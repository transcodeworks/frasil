//! The newcomer's snapshot (admission.md, "The newcomer's snapshot";
//! units.md, "The space snapshot").
//!
//! A member admitted "from now on" starts from a space snapshot under its
//! sender's scheme-2 signature:
//!
//! - **the base and its stubs:** the sender's heads, and a stub of every
//!   unit the newcomer will not hold in full that an event it will hold
//!   names as a parent;
//! - **body keys** of every space event the sender opened that the newcomer
//!   cannot open with the keys it will hold, its admitting event's past;
//! - **documents:** a stream entry per stream, naming a history-free
//!   stream snapshot object sealed under the current state, which holds the
//!   break.
//!
//! The newcomer judges only events after its base, and space events, which
//! it holds in full and opens with the handed body keys, provisionally.

use crate::at_rest::Batch;
use crate::device::Engine;
use crate::error::{Error, Result};
use frasil_adapter::Locator;
use frasil_events::{EventId, kind};
use frasil_keys::RotationSet;
use frasil_store::tables::{BodyKey, KeyKind as StoredKeyKind, KeyValue, LogKind, LogState};
use frasil_store::{Table, TableValue};
use frasil_units::compaction::{cover_set, covers};
use frasil_units::objects::{SealedObject, seal_object};
use frasil_units::snapshot::{LogEntry, SpaceSnapshot, StreamEntry, StreamSnapshot};
use frasil_units::{Stub, Unit};
use std::collections::BTreeSet;

/// A space snapshot and the stream snapshot objects it names.
#[derive(Debug, Clone)]
pub struct NewcomerSnapshot {
    /// The signed space snapshot.
    pub signed: Vec<u8>,
    /// The objects its stream entries name.
    pub objects: Vec<SealedObject>,
}

/// One part of an object as it travels: `ObjectChunks`'s fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPart {
    /// The object's locator.
    pub locator: Locator,
    /// The header's bytes, with the first chunk.
    pub header: Option<Vec<u8>>,
    /// The chunk's index.
    pub index: u64,
    /// The sealed chunk.
    pub chunk: Vec<u8>,
}

impl NewcomerSnapshot {
    /// Each object's parts, as `ObjectChunks` messages carry them.
    pub fn parts(&self) -> Vec<ObjectPart> {
        let mut out = Vec::new();
        for object in &self.objects {
            for chunk in &object.chunks {
                out.push(ObjectPart {
                    locator: object.locator,
                    header: (chunk.index == 0).then(|| object.header.clone()),
                    index: chunk.index,
                    chunk: chunk.sealed.clone(),
                });
            }
        }
        out
    }
}

impl Engine {
    /// The snapshot a newcomer admitted "from now on" by `admitting` starts
    /// from (admission.md, "The newcomer's snapshot"), at this device's
    /// current heads.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] while the device holds
    /// no current state, or when a document's adapter refuses its
    /// history-free export, as past the limits of what a replica loads.
    pub async fn newcomer_snapshot(
        &self,
        space: &EventId,
        admitting: EventId,
    ) -> Result<NewcomerSnapshot> {
        self.make_newcomer_snapshot(space, admitting, None).await
    }

    /// Makes a restored snapshot under exactly the state its welcome delivers.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn returning_member_snapshot(
        &self,
        space: &EventId,
        admitting: EventId,
        under: &RotationSet,
    ) -> Result<NewcomerSnapshot> {
        self.make_newcomer_snapshot(space, admitting, Some(under))
            .await
    }

    async fn make_newcomer_snapshot(
        &self,
        space: &EventId,
        admitting: EventId,
        under: Option<&RotationSet>,
    ) -> Result<NewcomerSnapshot> {
        // A lent document's operations reach a unit before the export.
        #[cfg(feature = "adapter-loro")]
        self.flush_lent_in(*space).await?;
        let state = self.lock().await;
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        // What a snapshot not yet attributed handed is not passed on under
        // this device's name (units.md, "The space snapshot", "Using it").
        if replica.snapshot_unconfirmed() {
            return Err(Error::NotAllowed(
                "the space snapshot this replica started from is not yet attributed",
            ));
        }
        let log = replica.log().ok_or(Error::UnknownSpace)?;
        let system = replica
            .system_stream()
            .ok_or(Error::NotAllowed("the genesis is not opened"))?;
        let mut base = log.heads();
        base.sort_unstable();
        base.truncate(frasil_units::limits::MAX_HEADS);
        let unit = |id: EventId| {
            log.event(id)
                .filter(|e| e.kind() == kind::UNIT)
                .and_then(|e| Unit::from_event(e.clone()).ok())
        };
        // Stubs: every unit an event names as a parent, and every unit of
        // the base; the newcomer holds no unit from before its base.
        let mut stubbed: BTreeSet<EventId> = BTreeSet::new();
        for event in log.events() {
            stubbed.extend(
                event
                    .parents()
                    .iter()
                    .copied()
                    .filter(|p| unit(*p).is_some()),
            );
        }
        stubbed.extend(base.iter().copied().filter(|h| unit(*h).is_some()));
        let stubs: Vec<Stub> = stubbed
            .into_iter()
            .filter_map(|id| {
                let event = log.event(id)?;
                Some(Stub {
                    id,
                    author: *event.author(),
                    seq: event.seq(),
                    height: log.height(id)?,
                    kind: kind::UNIT,
                    stream: unit(id).map(|u| u.body.stream),
                    cuts: frasil_events::Cuts::of(event),
                })
            })
            .collect();
        // Body keys of the space events from before the break.
        let body_keys: Vec<(EventId, [u8; 32])> = log
            .canonical()
            .into_iter()
            .filter(|id| *id != admitting && !log.precedes(admitting, *id))
            .filter(|id| log.event(*id).is_some_and(|e| e.kind() == kind::SPACE))
            .filter_map(|id| replica.body_key(&id).map(|key| (id, *key)))
            .collect();
        // Documents: history-free states under the current state (in a
        // restricted space, k_F and its reference).
        let (reference, key) = self.sealing_under(&state, space, under)?;
        let stream_of = |id: EventId| unit(id).map(|u| u.body.stream);
        let mut streams = Vec::new();
        let mut objects = Vec::new();
        for (stream, type_) in replica.streams() {
            if *stream == system {
                continue;
            }
            let Some(runtime) = replica.stream(stream) else {
                continue;
            };
            // The opening, so that the newcomer writes into the stream
            // before any unit of it reaches it.
            let Some(opening) = replica.opening_of(stream) else {
                continue;
            };
            let plaintext = StreamSnapshot {
                type_: type_.to_owned(),
                stream: *stream,
                history_free: true,
                state: runtime.export_history_free().ok_or(Error::NotAllowed(
                    "a document's adapter refuses its history-free export",
                ))?,
                moved: None,
            }
            .encode();
            let object = seal_object(space, &key, &reference, &plaintext).map_err(Error::class)?;
            let stream_covers = covers(log, stream_of, &base, stream);
            let excluded: Vec<EventId> = cover_set(log, stream_of, &stream_covers, stream)
                .into_iter()
                .filter(|id| {
                    !matches!(
                        replica.content_outcome(id),
                        Some(crate::adapters::ContentOutcome::Applied)
                    )
                })
                .collect();
            // ext-file-versions.md, 3.3 The supersession set: past the
            // limit the entry carries none, and old versions stay.
            let mut supersedes = runtime.export_supersedes();
            if supersedes.len() > frasil_units::limits::MAX_SUPERSESSIONS {
                supersedes.clear();
            }
            streams.push(StreamEntry {
                stream: *stream,
                opening,
                object: object.locator,
                key: reference.clone(),
                covers: stream_covers,
                excluded,
                supersedes,
            });
            objects.push(object);
        }
        let logs = grant_path_logs(&state, replica);
        let lists = named_lists(&state, replica, &logs, &base);
        // Keys 12 to 14: the checkpoint in effect at the base, its record's
        // object key and its cut chain; the newcomer holds the frame only
        // from it on (units.md, "The space snapshot").
        let checkpoint = snapshot_checkpoint(replica, log);
        let at_base = replica.lists_at_base(&base);
        let placed = lists
            .iter()
            .filter_map(|signed| frasil_events::decode(signed).ok())
            .map(|event| event.id())
            .filter(|id| at_base.contains(id))
            .collect();
        let snapshot = SpaceSnapshot {
            space: *space,
            sender: self.signer().signatory(),
            base,
            stubs,
            body_keys,
            lists,
            placed,
            logs,
            streams,
            proofs: Vec::new(),
            system_stream: system,
            checkpoint,
        };
        let signed = snapshot.sign(self.signer()).map_err(Error::class)?;
        Ok(NewcomerSnapshot { signed, objects })
    }

    /// Publishes `made`, the snapshot of a newcomer admitted "from now on"
    /// by `admitting` (admission.md, "The newcomer's snapshot"): the space
    /// snapshot as an object sealed under the admission's state, beside the
    /// stream snapshot objects it names, and a `frasil:body-keys` unit
    /// sealed under that state that carries the snapshot's body keys (the
    /// first 1,024) and lists every one of those objects, so that peers
    /// keep them. The device uploads the objects before the unit. Returns
    /// the snapshot's locator, which the welcome or the drop names, and the
    /// unit: once a peer holds it, the snapshot is there.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] without the
    /// admission's key, or for a snapshot with no body key; as
    /// [`Engine::write_system`].
    pub async fn publish_newcomer_snapshot(
        &self,
        space: &EventId,
        admitting: EventId,
        made: &NewcomerSnapshot,
    ) -> Result<(Locator, EventId)> {
        self.publish_snapshot_for(space, admitting, made, None)
            .await
    }

    /// Publishes a restored member's snapshot only while it remains a member.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn publish_returning_snapshot(
        &self,
        space: &EventId,
        admitting: EventId,
        made: &NewcomerSnapshot,
        recipient: frasil_crypto::device::DeviceId,
        under: &RotationSet,
    ) -> Result<(Locator, EventId)> {
        self.publish_snapshot_for(space, admitting, made, Some((recipient, under)))
            .await
    }

    async fn publish_snapshot_for(
        &self,
        space: &EventId,
        admitting: EventId,
        made: &NewcomerSnapshot,
        recipient: Option<(frasil_crypto::device::DeviceId, &RotationSet)>,
    ) -> Result<(Locator, EventId)> {
        // The device's own snapshot: its ML-DSA-65 half is not checked here.
        let snapshot = SpaceSnapshot::read(&made.signed, space, &())
            .map_err(Error::class)?
            .into_unverified();
        let mut pairs = snapshot.body_keys;
        pairs.truncate(frasil_units::limits::MAX_BODY_KEYS);
        if pairs.is_empty() {
            return Err(Error::NotAllowed("the snapshot carries no body key"));
        }
        let admission = RotationSet::single(admitting);
        let mut state = self.lock().await;
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        if let Some((recipient, under)) = recipient
            && (replica.level_of(&recipient).is_none()
                || replica.level_of(&self.device_id()) != Some(frasil_space::Level::Administer)
                || replica.current() != Some(under))
        {
            return Err(Error::NotAllowed(
                "a restored snapshot needs a current member, administrator, and delivered state",
            ));
        }
        let system = replica
            .system_stream()
            .ok_or(Error::NotAllowed("the genesis is not opened"))?;
        let (reference, key) = self
            .sealing_under(
                &state,
                space,
                Some(recipient.map_or(&admission, |(_, under)| under)),
            )
            .map_err(|_| Error::NotAllowed("the device lacks the admission's key"))?;
        let sealed = seal_object(space, &key, &reference, &made.signed).map_err(Error::class)?;
        let mut parts = crate::objects::parts_of(&sealed.locator, &sealed.bytes)?;
        let mut objects = vec![sealed.locator];
        for object in &made.objects {
            parts.extend(crate::objects::parts_of(&object.locator, &object.bytes)?);
            objects.push(object.locator);
        }
        Self::keep_parts_in(&mut state, *space, &parts.iter().collect::<Vec<_>>()).await?;
        let content = frasil_units::own::body_keys_content(&pairs);
        let unit = self
            .write_parts(
                &mut state,
                *space,
                system,
                None,
                frasil_units::types::BODY_KEYS,
                |_, _, _| {
                    Ok(crate::device::UnitParts {
                        content,
                        objects,
                        ..crate::device::UnitParts::default()
                    })
                },
            )
            .await?;
        Ok((sealed.locator, unit))
    }

    /// Takes a space snapshot as a newcomer (units.md, "The space
    /// snapshot", "Using it", steps 1 to 3 and the base), with the parts
    /// of the objects it names, before the space's events are placed.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `WrongSpace` or `BadSignature`;
    /// the store's.
    pub async fn adopt_snapshot(
        &self,
        space: EventId,
        signed: &[u8],
        parts: Vec<ObjectPart>,
    ) -> Result<()> {
        SpaceSnapshot::read(signed, &space, &()).map_err(Error::class)?;
        self.follow(space).await;
        let mut state = self.lock().await;
        let adopted = Self::adopt_in(&mut state, space, signed, parts).await?;
        // A snapshot that came as a message, not as an object, is kept as
        // one, so that the device finds its stream entries again when it
        // opens (at-rest.md, "Held objects": Frasil's own objects).
        if let Some(replica) = state.replicas.get_mut(&space) {
            replica.keep_snapshot_until_sealed(signed.to_vec());
        }
        self.adopt_granted(&mut state, adopted).await?;
        self.keep_adopted_snapshot(&mut state, space).await
    }

    /// Stores the space snapshot a replica adopted from a message, sealed
    /// as an object under the space's current state, once the device holds
    /// that state's key; until then the replica keeps it.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn keep_adopted_snapshot(
        &self,
        state: &mut crate::device::State,
        space: EventId,
    ) -> Result<()> {
        let Some(signed) = state
            .replicas
            .get(&space)
            .and_then(|replica| replica.snapshot_to_keep())
            .map(<[u8]>::to_vec)
        else {
            return Ok(());
        };
        let Ok((reference, key)) = self.sealing(state, &space) else {
            return Ok(());
        };
        let sealed = seal_object(&space, &key, &reference, &signed).map_err(Error::class)?;
        let parts = crate::objects::parts_of(&sealed.locator, &sealed.bytes)?;
        Self::keep_parts_in(state, space, &parts.iter().collect::<Vec<_>>()).await?;
        if let Some(replica) = state.replicas.get_mut(&space) {
            replica.snapshot_kept();
        }
        Ok(())
    }

    /// At open, finds the space snapshot a replica that started from one
    /// adopted, among the objects the store holds whole and no unit names,
    /// smallest first, and takes its stream entries and system stream
    /// again (units.md, "The space snapshot", "Using it", step 6): only the
    /// snapshot names how each stream's history-free state loads. Whether
    /// one was found.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn recover_snapshot(
        state: &mut crate::device::State,
        space: EventId,
    ) -> Result<bool> {
        let Some(replica) = state.replicas.get(&space) else {
            return Ok(false);
        };
        if !replica.has_base() {
            return Ok(false);
        }
        let named: BTreeSet<[u8; 32]> = crate::objects::named_objects(replica)
            .iter()
            .map(|locator| {
                let mut id = [0; 32];
                id.copy_from_slice(&locator[..32]);
                id
            })
            .collect();
        let candidates: Vec<[u8; 32]> = replica
            .unlocated_whole()
            .into_iter()
            .map(|(id, _)| id)
            .filter(|id| !named.contains(id))
            .collect();
        for id in candidates {
            let mut by_id = [0; 64];
            by_id[..32].copy_from_slice(&id);
            let Some((locator, bytes)) =
                crate::device::Engine::stored_located(state, &space, &by_id).await?
            else {
                continue;
            };
            let Some(replica) = state.replicas.get_mut(&space) else {
                return Ok(false);
            };
            let Ok(plaintext) = crate::objects::open_stored(replica, &space, &locator, &bytes)
            else {
                continue;
            };
            // Read again at load, as it was adopted: only what it hands is
            // used, and was used provisionally then.
            let Ok(read) = SpaceSnapshot::read(&plaintext, &space, &()) else {
                continue;
            };
            let snapshot = read.into_unverified();
            replica.set_system_stream(snapshot.system_stream);
            replica.set_base_lists(&snapshot.placed);
            replica.keep_stream_entries(snapshot.streams);
            return Ok(true);
        }
        Ok(false)
    }

    /// Takes what a space snapshot carries besides its space (admission.md,
    /// "The newcomer's snapshot"): the device lists of the persons its
    /// rosters name, and the logs along the grant path, each a log this
    /// device follows from then on, from the space events, storage events
    /// and anchors the snapshot carries, with their body keys and the stubs
    /// of the units they name. A log the device holds already is left as
    /// it is.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn adopt_granted(
        &self,
        state: &mut crate::device::State,
        adopted: Adopted,
    ) -> Result<()> {
        if !adopted.lists.is_empty() {
            self.keep_lists(state, adopted.lists).await?;
        }
        let reading = self.read_timeline(state).await?;
        for entry in adopted.logs {
            let granted = entry.space;
            if state.replicas.contains_key(&granted) {
                continue;
            }
            let events: Vec<frasil_events::Event> = entry
                .events
                .iter()
                .filter_map(|signed| crate::intake::read_event(signed).ok())
                .filter(|event| event.log_id() == granted)
                .collect();
            let cited: BTreeSet<EventId> = events
                .iter()
                .flat_map(|e| e.parents().iter().copied())
                .collect();
            let mut heads: Vec<EventId> = events
                .iter()
                .map(frasil_events::Event::id)
                .filter(|id| !cited.contains(id))
                .collect();
            heads.sort_unstable();
            heads.truncate(frasil_units::limits::MAX_HEADS);
            // A log along the grant path of a space kept in memory only is
            // kept in memory only too: it is part of what the device holds
            // of that space (ext-guests.md, "Nothing at rest").
            #[cfg(feature = "ext-guests")]
            if state.vault.is_memory_only(&adopted.space.0) && !state.vault.has_log(&granted.0) {
                state.vault.keep_in_memory(&granted.0).await?;
            }
            let mut replica = crate::replica::Replica::new(granted);
            #[cfg(feature = "partial-replicas")]
            if self.is_partial() {
                replica.make_partial();
            }
            replica.set_chunks_at_rest(!state.vault.is_memory_only(&granted.0));
            replica.set_base(heads.clone(), entry.stubs.clone());
            let ids: Vec<EventId> = events.iter().map(frasil_events::Event::id).collect();
            replica.place(events);
            replica.keep_bodies(&entry.body_keys);
            state.replicas.insert(granted, replica);
            state.outboxes.entry(granted).or_default();
            let mut batch = Batch::default();
            if !state.vault.has_log(&granted.0) {
                state
                    .vault
                    .add_log(&mut batch, &granted.0, LogKind::Space)?;
            }
            if !heads.is_empty() {
                let log_state = crate::device::log_state(&state.vault, &granted.0).await?;
                state.vault.put(
                    &mut batch,
                    &granted.0,
                    Table::State,
                    &[],
                    &TableValue::State(LogState {
                        erasing: None,
                        base_heads: Some(heads.iter().map(|id| id.0).collect()),
                        base_stubs: Some(
                            entry.stubs.iter().map(|s| s.to_value().encode()).collect(),
                        ),
                        ..log_state
                    }),
                )?;
            }
            for (id, key) in &entry.body_keys {
                put_body_key(&state.vault, &mut batch, &granted, id, key, adopted.sender)?;
            }
            state.vault.commit(batch).await?;
            Box::pin(self.settle_one(state, granted, ids, reading)).await?;
        }
        Ok(())
    }

    /// [`Engine::adopt_snapshot`], on the device's state, for a space it
    /// follows.
    pub(crate) async fn adopt_in(
        state: &mut crate::device::State,
        space: EventId,
        signed: &[u8],
        parts: Vec<ObjectPart>,
    ) -> Result<Adopted> {
        let read = SpaceSnapshot::read(signed, &space, &state.keys()).map_err(Error::class)?;
        let provisional = read.is_provisional();
        // Used provisionally either way (units.md, "The space snapshot",
        // "Using it"): the replica keeps the signed bytes of a provisional
        // one to verify again, and nothing it handed goes out under this
        // device's name until it is attributed.
        let snapshot = read.into_unverified();
        let adopted = Adopted {
            space,
            sender: snapshot.sender.device_id().0,
            logs: snapshot.logs.clone(),
            lists: snapshot.lists.clone(),
        };
        let crate::device::State {
            vault, replicas, ..
        } = state;
        let replica = replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        // Until the device holds keys that hash to the sender's `kc`, the
        // snapshot is provisional: its ML-DSA-65 half is checked again when
        // the device's keys grow (units.md, "The space snapshot", "Using
        // it", step 3).
        replica.set_provisional_snapshot(provisional.then(|| signed.to_vec()));
        // Its sender must reach the space once the view grants this
        // device; until then, nothing it handed goes out under this
        // device's name (units.md, "The space snapshot", "Using it").
        replica.set_snapshot_sender(Some(snapshot.sender.device_id()));
        replica.set_system_stream(snapshot.system_stream);
        replica.set_base(snapshot.base.clone(), snapshot.stubs.clone());
        replica.set_base_lists(&snapshot.placed);
        replica.keep_bodies(&snapshot.body_keys);
        replica.keep_stream_entries(snapshot.streams.clone());
        // A checkpoint in effect at the base: the newcomer starts from it,
        // and never fetches the frame before it (roster.md, 3.15.6).
        if let Some(checkpoint) = &snapshot.checkpoint
            && let Ok(envelopes) = checkpoint.kept_envelopes(&space)
        {
            replica.start_from_checkpoint(
                checkpoint.checkpoint,
                checkpoint.record_key,
                envelopes.into_values().collect(),
            );
        }
        replica.set_chunks_at_rest(!vault.is_memory_only(&space.0));
        for part in &parts {
            replica.keep_object(
                part.locator,
                part.header.clone(),
                Some((part.index, part.chunk.clone())),
            );
        }
        let mut batch = Batch::default();
        if !vault.has_log(&space.0) {
            vault.add_log(&mut batch, &space.0, LogKind::Space)?;
        }
        // The base and its stubs, with whatever else the record holds: a
        // claim begun in this log stays named until it is signed.
        let log_state = crate::device::log_state(vault, &space.0).await?;
        vault.put(
            &mut batch,
            &space.0,
            Table::State,
            &[],
            &TableValue::State(LogState {
                // A snapshot replaces the keyless residue's state; key 9
                // never shares a record with the replica's base.
                erasing: None,
                base_heads: Some(snapshot.base.iter().map(|id| id.0).collect()),
                base_stubs: Some(
                    snapshot
                        .stubs
                        .iter()
                        .map(|s| s.to_value().encode())
                        .collect(),
                ),
                // A newcomer that starts from a checkpoint commits key 7, its
                // kept checkpoint, before it judges anything after it
                // (at-rest.md, "Starting from a checkpoint").
                kept_checkpoint: snapshot
                    .checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.checkpoint.0)
                    .or(log_state.kept_checkpoint),
                ..log_state
            }),
        )?;
        // What the log keeps of its checkpoints, in records of their own
        // (at-rest.md, "Starting from a checkpoint").
        for (table, item, value) in replica.checkpoint_state().records() {
            vault.put(&mut batch, &space.0, table, &item, &value)?;
        }
        for (id, key) in &snapshot.body_keys {
            put_body_key(vault, &mut batch, &space, id, key, adopted.sender)?;
        }
        for part in &parts {
            let mut item = part.locator[..32].to_vec();
            if let Some(header) = &part.header {
                let mut header_item = item.clone();
                header_item.extend_from_slice(&0u32.to_be_bytes());
                vault.put(
                    &mut batch,
                    &space.0,
                    Table::Object,
                    &header_item,
                    &TableValue::Object(header.clone()),
                )?;
            }
            let index = crate::objects::chunk_part(part.index)?;
            item.extend_from_slice(&index.to_be_bytes());
            vault.put(
                &mut batch,
                &space.0,
                Table::Object,
                &item,
                &TableValue::Object(part.chunk.clone()),
            )?;
        }
        vault.commit(batch).await?;
        Ok(adopted)
    }

    /// Writes a `frasil:body-keys` unit in the system stream (units.md,
    /// "Frasil's own units"; admission.md, "Top-ups"): the body keys of
    /// these space events, which this device opened.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] when the device holds none of them; as
    /// [`Engine::write_system`].
    pub async fn publish_body_keys(&self, space: EventId, events: &[EventId]) -> Result<EventId> {
        let pairs: Vec<(EventId, [u8; 32])> = self
            .read(&space, |replica| {
                let mut pairs: Vec<(EventId, [u8; 32])> = events
                    .iter()
                    .filter_map(|id| replica.body_key(id).map(|key| (*id, *key)))
                    .collect();
                pairs.sort_unstable_by_key(|(id, _)| *id);
                pairs.dedup_by_key(|(id, _)| *id);
                pairs
            })
            .await?;
        if pairs.is_empty() {
            return Err(Error::NotAllowed(
                "the device holds none of these body keys",
            ));
        }
        let content = frasil_units::own::body_keys_content(&pairs);
        self.write_system(space, frasil_units::types::BODY_KEYS, content)
            .await
    }
}

/// What a space snapshot carries besides its space, for
/// [`Engine::adopt_granted`].
#[derive(Debug)]
pub(crate) struct Adopted {
    /// The space whose snapshot it is.
    #[cfg_attr(not(feature = "ext-guests"), allow(dead_code))]
    space: EventId,
    /// The snapshot's sender, which handed the body keys.
    sender: [u8; 32],
    /// The logs along the grant path.
    logs: Vec<LogEntry>,
    /// Signed device-list events.
    lists: Vec<Vec<u8>>,
}

/// The logs along a space's grant path that this device holds (admission.md,
/// "The newcomer's snapshot"): for every space it grants, transitively, its
/// space events and storage events, and the anchors among their parents, in
/// canonical order, with their body keys, and stubs of the units they name
/// as parents.
fn grant_path_logs(
    state: &crate::device::State,
    replica: &crate::replica::Replica,
) -> Vec<LogEntry> {
    let granted_by = |r: &crate::replica::Replica| -> Vec<EventId> {
        r.roster()
            .members_in()
            .filter(|(m, _)| m.kind == frasil_space::MemberType::Space)
            .map(|(m, _)| EventId(m.id))
            .collect()
    };
    let mut seen: BTreeSet<EventId> = BTreeSet::from([replica.space()]);
    let mut queue = granted_by(replica);
    let mut out = Vec::new();
    while let Some(granted) = queue.pop() {
        if !seen.insert(granted) {
            continue;
        }
        let Some(held) = state.replicas.get(&granted) else {
            continue;
        };
        let Some(log) = held.log() else {
            continue;
        };
        queue.extend(granted_by(held));
        let frame: BTreeSet<EventId> = log
            .canonical()
            .into_iter()
            .filter(|id| {
                log.event(*id)
                    .is_some_and(|e| matches!(e.kind(), kind::SPACE | kind::STORAGE))
            })
            .collect();
        let mut included = frame.clone();
        for id in &frame {
            if let Some(event) = log.event(*id) {
                included.extend(
                    event
                        .parents()
                        .iter()
                        .copied()
                        .filter(|p| log.event(*p).is_some_and(|e| e.kind() == kind::ANCHOR)),
                );
                if event.is_genesis() {
                    included.insert(*id);
                }
            }
        }
        let events: Vec<Vec<u8>> = log
            .canonical()
            .into_iter()
            .filter(|id| included.contains(id))
            .filter_map(|id| log.event(id).map(frasil_events::Event::signed))
            .collect();
        let mut stubbed: BTreeSet<EventId> = BTreeSet::new();
        for id in &included {
            if let Some(event) = log.event(*id) {
                stubbed.extend(
                    event
                        .parents()
                        .iter()
                        .copied()
                        .filter(|p| log.event(*p).is_some_and(|e| e.kind() == kind::UNIT)),
                );
            }
        }
        let stubs: Vec<Stub> = stubbed
            .into_iter()
            .filter_map(|id| {
                let event = log.event(id)?;
                let unit = Unit::from_event(event.clone()).ok()?;
                Some(Stub {
                    id,
                    author: *event.author(),
                    seq: event.seq(),
                    height: log.height(id)?,
                    kind: kind::UNIT,
                    stream: Some(unit.body.stream),
                    cuts: frasil_events::Cuts::of(event),
                })
            })
            .collect();
        let body_keys: Vec<(EventId, [u8; 32])> = frame
            .iter()
            .filter(|id| log.event(**id).is_some_and(|e| e.kind() == kind::SPACE))
            .filter_map(|id| held.body_key(id).map(|key| (*id, *key)))
            .collect();
        out.push(LogEntry {
            space: granted,
            events,
            stubs,
            body_keys,
            proofs: Vec::new(),
        });
    }
    out.sort_by_key(|entry| entry.space);
    out
}

/// Every event this device holds of the list of every person a roster of
/// the snapshot names (admission.md, "The newcomer's snapshot").
fn named_lists(
    state: &crate::device::State,
    replica: &crate::replica::Replica,
    logs: &[LogEntry],
    _base: &[EventId],
) -> Vec<Vec<u8>> {
    let mut persons: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut rosters = vec![replica];
    rosters.extend(logs.iter().filter_map(|e| state.replicas.get(&e.space)));
    for held in rosters {
        persons.extend(
            held.roster()
                .iter()
                .filter(|(m, _)| m.kind == frasil_space::MemberType::Person)
                .map(|(m, _)| m.id),
        );
    }
    let copied = replica.copied_list_events();
    persons
        .iter()
        .filter_map(|person| state.lists.get(person))
        .flat_map(|list| {
            let held = list.held();
            let mut seen = BTreeSet::new();
            copied
                .iter()
                .filter(|event| event.log_id().0 == list.person_id())
                .cloned()
                .chain(
                    list.signed_events()
                        .iter()
                        .filter_map(|signed| frasil_events::decode(signed).ok()),
                )
                .filter(|event| held.holds(event.id()))
                .filter(|event| seen.insert(event.id()))
                .map(|event| event.signed())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Puts a body key handed over as a `key` record of kind 3. A key a space
/// snapshot handed names its sender where at-rest.md's record names the
/// unit that handed it.
pub(crate) fn put_body_key(
    vault: &crate::at_rest::Vault,
    batch: &mut Batch,
    space: &EventId,
    event: &EventId,
    key: &[u8; 32],
    handed_by: [u8; 32],
) -> Result<()> {
    let mut item = vec![StoredKeyKind::BodyKey.code()];
    item.extend_from_slice(&event.0);
    vault.put(
        batch,
        &space.0,
        Table::Key,
        &item,
        &TableValue::Key(KeyValue::BodyKey(BodyKey {
            key: frasil_store::tables::Secret::new(*key),
            handed_by: Some(handed_by),
        })),
    )
}

/// Keys 12 to 14 of a space snapshot this replica sends (units.md, "The
/// space snapshot"): the last checkpoint in effect, its record's object
/// key, from the checkpoint's own content key or the one a snapshot handed
/// this device, and the envelopes of the checkpoints its cuts reach.
/// `None` with no checkpoint in effect, or while the replica lacks one of
/// them.
fn snapshot_checkpoint(
    replica: &crate::replica::Replica,
    log: &frasil_events::Log,
) -> Option<frasil_units::snapshot::SnapshotCheckpoint> {
    let facts = replica.checkpoint_facts();
    let checkpoint = facts.last()?;
    let part = facts.parts.get(&checkpoint)?;
    let content = replica
        .secrets_of(&checkpoint)
        .and_then(|secrets| secrets.content.clone());
    let key = match &content {
        Some(content) => frasil_admission::snapshot::RecordKeySource::Content(content),
        None => frasil_admission::snapshot::RecordKeySource::Object(
            replica.checkpoints.object_keys.get(&checkpoint)?,
        ),
    };
    frasil_admission::snapshot::snapshot_checkpoint(log, checkpoint, part, key)
}
