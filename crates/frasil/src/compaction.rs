//! Compaction at a device (units.md, "Snapshot units and stream snapshots",
//! "Compacting", "Checking, using and settling a snapshot").
//!
//! [`Engine::compact`] writes a snapshot unit of one stream:
//!
//! 1. **The cut** is the unit's parents, the device's heads; `covers` is
//!    each writer's stream frontier in their past.
//! 2. **The cover**, every unit of the stream past, valid or not. The
//!    adapter compacts the state built over the snapshot in use and the
//!    cover alone; every unit of the cover the state does not include is
//!    listed in `excluded`.
//! 3. **Boundary stubs:** each unit of the cover an event outside it names
//!    as a parent, the snapshot unit included, and the earlier snapshots'
//!    stubs still so named.
//! 4. **The stream snapshot object**, sealed under the current state and
//!    named by the unit, beside every object the state still references.
//!
//! A replica checks a snapshot unit whose stream past it holds: `covers`
//! must be exactly the writers' frontiers of that past (`BadCompaction`
//! otherwise, and the snapshot is never used). A replica that holds no unit
//! of a snapshot's cover, as when a peer collected them, places against the
//! unit's signed stubs and loads the snapshot's state in place of the
//! cover. Either uses a snapshot only while its unit is valid and its
//! stream's adapter accepted its content, a suggester's being refused.

use crate::device::{Engine, UnitParts};
use crate::error::{Error, Result};
use crate::objects::parts_of;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, kind};
use frasil_units::Unit;
use frasil_units::body::Compacts;
use frasil_units::compaction::{boundary_stubs, cover_set, covers};
use frasil_units::limits::MAX_SUPERSESSIONS;
use frasil_units::objects::seal_object;
use frasil_units::snapshot::StreamSnapshot;
use frasil_units::stream::StreamId;
use std::collections::BTreeSet;

impl Engine {
    /// Compacts a stream (units.md, "Compacting"): writes a snapshot unit
    /// whose cut is this device's heads, and keeps its stream snapshot
    /// object. Returns the snapshot unit.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a stream the device does not hold, or with
    /// nothing to cover, or while the space snapshot the replica started
    /// from is not yet attributed to a sender that reaches the space, whose
    /// state a compaction would sign under this device's name (units.md,
    /// "The space snapshot", "Using it"); as [`Engine::write_unit`].
    pub async fn compact(&self, space: EventId, stream: StreamId) -> Result<EventId> {
        let mut state = self.lock().await;
        let (reference, key) = self.sealing(&state, &space)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.snapshot_unconfirmed() {
            return Err(Error::NotAllowed(
                "the space snapshot this replica started from is not yet attributed",
            ));
        }
        let runtime = replica
            .stream(&stream)
            .ok_or(Error::NotAllowed("the device holds no such stream"))?;
        let type_ = runtime.adapter_type().to_owned();
        // The snapshot object is sealed and kept before the unit that
        // names it.
        let prepared = {
            let log = replica.log().ok_or(Error::UnknownSpace)?;
            let (_, prev) = Self::next(&state, &space, &self.device_id());
            let parents = replica.parents(prev);
            let stream_of = |id: EventId| stream_of(log, id);
            let pairs = covers(log, stream_of, &parents, &stream);
            if pairs.is_empty() {
                return Err(Error::NotAllowed("nothing to compact"));
            }
            let cover = cover_set(log, stream_of, &pairs, &stream);
            let cover_bytes: BTreeSet<[u8; 32]> = cover.iter().map(|id| id.0).collect();
            let compaction = runtime
                .compact(&cover_bytes)
                .ok_or(Error::NotAllowed("the adapter cannot compact this stream"))?;
            // adapter-loro.md, section 3.1: a state that the checks of
            // section 3.5 refuse is not written; the stream goes on by units.
            #[cfg(feature = "adapter-loro")]
            if type_ == frasil_adapter_loro::TYPE
                && frasil_adapter_loro::snapshot::check(&compaction.state).is_err()
            {
                return Err(Error::NotAllowed(
                    "the document's state is over the Loro adapter's snapshot limits",
                ));
            }
            let base = runtime.base_cover();
            let excluded: Vec<EventId> = cover
                .iter()
                .copied()
                .filter(|id| !compaction.included.contains(&id.0) && !base.contains(&id.0))
                .collect();
            // The stubs of earlier snapshot units in the cover.
            let earlier: Vec<frasil_units::Stub> = cover
                .iter()
                .filter_map(|id| log.event(*id))
                .filter_map(|event| Unit::from_event(event.clone()).ok())
                .filter_map(|unit| unit.body.compacts)
                .flat_map(|compacts| compacts.stubs)
                .collect();
            let stubs = boundary_stubs(log, &cover, &parents, &earlier);
            let plaintext = StreamSnapshot {
                type_: type_.clone(),
                stream,
                history_free: false,
                state: compaction.state.clone(),
                moved: None,
            }
            .encode();
            let object = seal_object(&space, &key, &reference, &plaintext).map_err(Error::class)?;
            let mut objects: Vec<_> = compaction.objects.iter().copied().collect();
            objects.push(object.locator);
            // Past the limit a unit carries none: an absent key 8 passes
            // (ext-file-versions.md, section 3.5), and old versions stay.
            let supersedes = if compaction.supersedes.len() > MAX_SUPERSESSIONS {
                Vec::new()
            } else {
                compaction.supersedes.clone()
            };
            (
                Compacts {
                    object: object.locator,
                    covers: pairs,
                    stubs,
                },
                compaction.metadata,
                excluded,
                objects,
                object,
                supersedes,
            )
        };
        let (compacts, metadata, excluded, objects, object, supersedes) = prepared;
        // The snapshot's object is kept in the unit's commit.
        let parts = parts_of(&object.locator, &object.bytes)?;
        let opening = state
            .replicas
            .get(&space)
            .and_then(|replica| replica.opening_of(&stream));
        self.write_parts(&mut state, space, stream, opening, &type_, |_, _, _| {
            Ok(UnitParts {
                content: metadata,
                objects,
                compacts: Some(compacts),
                supersedes,
                excluded,
                #[cfg(feature = "ext-restricted-spaces")]
                copied_from: None,
                stored: parts,
                records: Vec::new(),
            })
        })
        .await
    }
}

#[cfg(feature = "ext-file-versions")]
impl Engine {
    /// Compacts each Blobs stream that section 3.11 of ext-file-versions.md
    /// finds due, for a device that may write there. Returns the snapshot
    /// units written.
    pub async fn compact_versions(&self, interval: u64) -> Vec<EventId> {
        let due = {
            let mut state = self.lock().await;
            let Ok(now) = self.read_timeline(&mut state).await else {
                return Vec::new();
            };
            let mut due = Vec::new();
            for (space, replica) in &state.replicas {
                if replica.level_of(&self.device_id()) < Some(frasil_space::Level::Write) {
                    continue;
                }
                for stream in replica.supersession_streams() {
                    let first = replica.first_supersession(&stream);
                    if frasil_adapter_blobs::versions::compaction_due(
                        first.as_ref(),
                        &now,
                        interval,
                    ) {
                        due.push((*space, stream));
                    }
                }
            }
            due
        };
        let mut written = Vec::new();
        for (space, stream) in due {
            if let Ok(id) = self.compact(space, stream).await {
                written.push(id);
            }
        }
        written
    }
}

impl Engine {
    /// Settles, uses and collects the space's snapshots at this replica
    /// (units.md, "Checking, using and settling a snapshot", "Collecting"):
    /// a checked snapshot whose cover the replica holds is used once it is
    /// settled, stable or `gap_key_timeout` past its first sight, and then
    /// the units of its cover are collected from the store, except a
    /// refused unit of this device's own, a unit of a forked device, a
    /// unit still waiting in the outbox, a unit that an event outside the
    /// cover names as a parent while the replica holds no signed stub of
    /// it, and a unit that a space event outside the cover names as a
    /// parent ("Parents of space events"): the replica places that event
    /// only against the unit in full or a confirmed stub ("Confirming
    /// heights"). Returns the units collected.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn collect(&self, space: EventId) -> Result<Vec<EventId>> {
        let me = self.device_id();
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        if !state.replicas.contains_key(&space) {
            return Ok(Vec::new());
        }
        // A refresh first: the snapshots checked at the last one are judged
        // for stability at this one.
        self.settle_one(&mut state, space, Vec::new(), now).await?;
        let outbox: BTreeSet<EventId> = state
            .outboxes
            .get(&space)
            .map(|o| o.pending().map(|(_, id)| *id).collect())
            .unwrap_or_default();
        let Some(replica) = state.replicas.get_mut(&space) else {
            return Ok(Vec::new());
        };
        let timeout = replica.policy().gap_key_timeout;
        let settled = |replica: &crate::replica::Replica, id: &EventId| {
            let first = replica.first_sight(id).copied().unwrap_or(now);
            replica
                .status(id)
                .is_some_and(frasil_space::Status::is_valid)
                && !matches!(
                    replica.content_outcome(id),
                    Some(crate::adapters::ContentOutcome::Refused(_))
                )
                && frasil_units::decisions::settled(
                    replica.is_stable_snapshot(id),
                    &first,
                    &now,
                    timeout,
                )
        };
        // Settled checked snapshots are used in place of their cover.
        let ready: Vec<EventId> = replica
            .checked_snapshots()
            .copied()
            .filter(|id| settled(replica, id))
            .collect();
        for id in &ready {
            replica.use_checked_snapshot(*id);
        }
        // A snapshot object whose chunks are in the store is read back,
        // and its snapshot used then.
        if Self::fill_wanted(&mut state, &space).await? {
            let Some(replica) = state.replicas.get_mut(&space) else {
                return Ok(Vec::new());
            };
            for id in &ready {
                replica.use_checked_snapshot(*id);
            }
            replica.release_chunks();
        }
        let Some(replica) = state.replicas.get_mut(&space) else {
            return Ok(Vec::new());
        };
        let Some(log) = replica.log() else {
            return Ok(Vec::new());
        };
        let mut collected: BTreeSet<EventId> = BTreeSet::new();
        for snapshot in replica.used_snapshots().clone() {
            if !settled(replica, &snapshot) {
                continue;
            }
            let Some(unit) = log
                .event(snapshot)
                .and_then(|e| Unit::from_event(e.clone()).ok())
            else {
                continue;
            };
            let Some(compacts) = unit.body.compacts.as_ref() else {
                continue;
            };
            let stream = unit.body.stream;
            let cover: BTreeSet<EventId> =
                cover_set(log, |id| stream_of(log, id), &compacts.covers, &stream)
                    .into_iter()
                    .collect();
            let stubbed: BTreeSet<EventId> = compacts.stubs.iter().map(|s| s.id).collect();
            for id in &cover {
                let Some(event) = log.event(*id) else {
                    continue;
                };
                let refused = replica.status(id).is_some_and(|s| !s.is_valid());
                if (event.author() == &me && refused)
                    || replica.forked(event.author())
                    || outbox.contains(id)
                {
                    continue;
                }
                let named_outside = log
                    .events()
                    .filter(|other| !cover.contains(&other.id()) && other.parents().contains(id))
                    .map(frasil_events::Event::kind)
                    .collect::<BTreeSet<u8>>();
                if !named_outside.is_empty() && !stubbed.contains(id) && log.stub(*id).is_none() {
                    continue;
                }
                if named_outside.contains(&kind::SPACE) {
                    continue;
                }
                collected.insert(*id);
            }
        }
        if collected.is_empty() {
            return Ok(Vec::new());
        }
        let mut batch = crate::at_rest::Batch::default();
        for id in &collected {
            state
                .vault
                .delete(&mut batch, &space.0, frasil_store::Table::Event, &id.0);
        }
        state.vault.commit(batch).await?;
        Ok(collected.into_iter().collect())
    }

    /// Stores a restore that names each snapshot unit this replica reports
    /// `BadCompaction` for, or finds refused (units.md, "Checking, using
    /// and settling a snapshot"; peers.md, "Release and restore"): a writer
    /// request that cancels the snapshot's collection at every peer. Once
    /// for each snapshot. Returns the restores.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    pub async fn restore_compactions(&self, space: EventId) -> Result<Vec<EventId>> {
        let me = self.device_id();
        let mut state = self.lock().await;
        let due: Vec<EventId> = {
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(Vec::new());
            };
            if replica.level_of(&me) < Some(frasil_space::Level::Write) {
                return Ok(Vec::new());
            }
            let Some(log) = replica.log() else {
                return Ok(Vec::new());
            };
            // The snapshots this device has restored already.
            let restored: BTreeSet<[u8; 32]> = log
                .chain(&me)
                .into_iter()
                .filter_map(|id| log.event(id))
                .filter(|e| e.kind() == kind::STORAGE)
                // This device's own events.
                .filter_map(|e| frasil_peers::body::StorageBody::read(e.unverified_body()).ok())
                .filter_map(|body| match body {
                    frasil_peers::body::StorageBody::Restore(
                        frasil_peers::body::Restored::Snapshot(id),
                    ) => Some(id),
                    _ => None,
                })
                .collect();
            let refused_snapshots = log.events().filter(|e| {
                e.kind() == kind::UNIT
                    && Unit::from_event((*e).clone()).is_ok_and(|u| u.body.compacts.is_some())
                    && (replica.status(&e.id()).is_some_and(|s| {
                        s.class().is_some_and(|c| {
                            frasil_base::errors::Class::sort(c) == frasil_base::errors::Sort::Final
                        })
                    }) || matches!(
                        replica.content_outcome(&e.id()),
                        Some(crate::adapters::ContentOutcome::Refused(_))
                    ))
            });
            replica
                .bad_compactions()
                .iter()
                .copied()
                .chain(refused_snapshots.map(frasil_events::Event::id))
                .filter(|id| !restored.contains(&id.0))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let mut out = Vec::new();
        let restored = due.clone();
        for snapshot in due {
            Self::check_may_sign(&state, &space)?;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let (seq, prev) = Self::next(&state, &space, &me);
            let mut parents = replica.parents(prev);
            parents.extend(prev);
            parents.sort_unstable();
            parents.dedup();
            let cuts = replica.cuts_for(&parents)?;
            let event = frasil_events::Envelope {
                kind: kind::STORAGE,
                log: Some(space),
                ed: *self.signer().identity_key(),
                kc: *self.signer().kc(),
                seq,
                prev,
                parents,
                cuts,
                body: frasil_peers::body::StorageBody::Restore(
                    frasil_peers::body::Restored::Snapshot(snapshot.0),
                )
                .encode(),
                scheme: frasil_crypto::schemes::Scheme::Hybrid,
            };
            let signed = event.sign(self.signer());
            out.push(self.commit_own(&mut state, space, &signed, None).await?);
        }
        Self::offer_covers(&mut state, space, &restored).await?;
        Ok(out)
    }

    /// The cover of each restored snapshot returns at the peers (units.md,
    /// 3.6 "Checking"): the restore cancels its collection, and this device
    /// offers again, in its outbox, every unit of the cover it holds, so
    /// that a peer that collected them stores them again. Each leaves the
    /// outbox as an own event does, once a peer acknowledges it.
    async fn offer_covers(
        state: &mut crate::device::State,
        space: EventId,
        restored: &[EventId],
    ) -> Result<()> {
        let crate::device::State {
            vault,
            replicas,
            outboxes,
            ..
        } = state;
        let Some(log) = replicas.get(&space).and_then(|r| r.log()) else {
            return Ok(());
        };
        let mut offered: BTreeSet<EventId> = BTreeSet::new();
        for snapshot in restored {
            let Some(unit) = log
                .event(*snapshot)
                .and_then(|e| Unit::from_event(e.clone()).ok())
            else {
                continue;
            };
            let Some(compacts) = unit.body.compacts.as_ref() else {
                continue;
            };
            let stream = unit.body.stream;
            offered.extend(
                cover_set(log, |id| stream_of(log, id), &compacts.covers, &stream)
                    .into_iter()
                    .filter(|id| log.contains(*id)),
            );
        }
        if offered.is_empty() {
            return Ok(());
        }
        let outbox = outboxes.entry(space).or_default();
        let mut batch = crate::at_rest::Batch::default();
        for id in offered {
            let Some(event) = log.event(id) else {
                continue;
            };
            if outbox.holds(&id) {
                continue;
            }
            outbox.add(*event.author(), event.seq(), id);
            let mut item = event.author().0.to_vec();
            item.extend_from_slice(&event.seq().to_be_bytes());
            if vault.has_log(&space.0) {
                vault.put(
                    &mut batch,
                    &space.0,
                    frasil_store::Table::Outbox,
                    &item,
                    &frasil_store::TableValue::Outbox(id.0),
                )?;
            }
        }
        vault.commit(batch).await?;
        Ok(())
    }

    /// Checks a peer's `StreamHeads` for completeness (units.md, "Sync", by
    /// stream): every unit it names, and every unit reached from one by
    /// `stream_prev` back to the writer's pair in the latest snapshot's
    /// `covers`, that this device lacks, to ask for by ID; and whether the
    /// peer served less than this device holds: a writer it leaves out, or
    /// an older unit than one of that writer this device holds outside the
    /// past of the latest snapshot unit and has not just written
    /// (`Withheld`).
    pub async fn stream_heads_check(
        &self,
        space: EventId,
        stream: StreamId,
        latest: Option<EventId>,
        writers: &[frasil_units::messages::StreamWriter],
    ) -> (Vec<EventId>, bool) {
        let state = self.lock().await;
        let outbox: BTreeSet<EventId> = state
            .outboxes
            .get(&space)
            .map(|o| o.pending().map(|(_, id)| *id).collect())
            .unwrap_or_default();
        let Some(log) = state.replicas.get(&space).and_then(|r| r.log()) else {
            return (Vec::new(), false);
        };
        let unit_of = |id: EventId| {
            log.event(id)
                .and_then(|e| Unit::from_event(e.clone()).ok())
                .filter(|u| u.body.stream == stream)
        };
        let covers: Vec<frasil_units::body::Cover> = latest
            .and_then(unit_of)
            .and_then(|u| u.body.compacts.map(|c| c.covers))
            .unwrap_or_default();
        let mut missing = Vec::new();
        if let Some(latest) = latest
            && !log.contains(latest)
        {
            missing.push(latest);
        }
        for listed in writers {
            let floor = covers
                .iter()
                .find(|c| c.writer == listed.writer)
                .map(|c| c.unit);
            let mut next = Some(listed.unit);
            while let Some(id) = next {
                if Some(id) == floor {
                    break;
                }
                match unit_of(id) {
                    Some(unit) => next = unit.body.stream_prev,
                    None => {
                        if !log.contains(id) {
                            missing.push(id);
                        }
                        break;
                    }
                }
            }
        }
        // What this device holds of the stream after the latest snapshot,
        // by writer: its greatest `seq`, its own units not yet durable
        // aside. A unit in the past of the latest snapshot unit is in its
        // cover or before it, and a peer lists no writer for it; every
        // other unit counts, a covered writer's included (units.md, 3.14
        // "By stream").
        let before: BTreeSet<EventId> = latest
            .filter(|_| !covers.is_empty())
            .filter(|id| log.contains(*id))
            .map(|id| log.past(id))
            .unwrap_or_default();
        let mut held: std::collections::BTreeMap<DeviceId, u64> = std::collections::BTreeMap::new();
        for event in log.events() {
            if event.kind() != kind::UNIT
                || outbox.contains(&event.id())
                || before.contains(&event.id())
            {
                continue;
            }
            if unit_of(event.id()).is_some() {
                let seq = held.entry(*event.author()).or_default();
                *seq = (*seq).max(event.seq());
            }
        }
        let withheld = held.iter().any(|(writer, seq)| {
            writers
                .iter()
                .find(|w| &w.writer == writer)
                .is_none_or(|w| w.seq < *seq)
        });
        (missing, withheld)
    }
}

/// A placed unit's stream.
pub(crate) fn stream_of(log: &frasil_events::Log, id: EventId) -> Option<StreamId> {
    log.event(id)
        .filter(|event| event.kind() == kind::UNIT)
        .and_then(|event| Unit::from_event(event.clone()).ok())
        .map(|unit| unit.body.stream)
}

/// Checks a snapshot unit against the stream past the replica holds
/// (units.md, "Checking, using and settling a snapshot"): `covers` is
/// exactly the writers' stream frontiers of its parents' past, and each
/// stub matches the event it stands for. `None` when the replica does not
/// hold that past.
pub(crate) fn check(log: &frasil_events::Log, unit: &Unit, parents: &[EventId]) -> Option<bool> {
    let compacts = unit.body.compacts.as_ref()?;
    if parents.iter().any(|parent| log.event(*parent).is_none()) {
        return None;
    }
    // The whole past, every event of it held: a past the replica holds
    // only stubs of, as after it collected a cover, it does not check.
    let mut past: BTreeSet<EventId> = parents.iter().copied().collect();
    for parent in parents {
        past.extend(log.past(*parent));
    }
    if past.iter().any(|id| {
        log.event(*id)
            .is_none_or(|event| event.parents().iter().any(|p| log.event(*p).is_none()))
    }) {
        return None;
    }
    let stream = unit.body.stream;
    let expected = covers(log, |id| stream_of(log, id), parents, &stream);
    if expected != compacts.covers {
        return Some(false);
    }
    let stubs_match = compacts
        .stubs
        .iter()
        .all(|stub| frasil_units::compaction::check_stub(log, stub).is_ok());
    Some(stubs_match)
}

/// Seeds: no public call writes one but a document's move, so these tests
/// write it as a writer's engine would.
#[cfg(all(test, feature = "adapter-loro"))]
mod seed_tests {
    use super::*;
    use crate::advanced::{AdapterRegistry, Platform};
    use frasil_space::{HistoryMode, Level, MemberRef, Via};
    use frasil_units::stream::Opening;

    async fn device() -> Engine {
        Engine::create(
            Platform::memory(),
            &[7; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a device")
        .0
    }

    async fn grant(alice: &Engine, space: EventId, other: &Engine) {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }

    async fn write(engine: &Engine, space: EventId, doc: &Opening, words: &[&str]) {
        for word in words {
            engine
                .edit_document(space, doc, |d| {
                    let body = d.get_text("body");
                    body.insert(body.len_unicode(), word).unwrap();
                })
                .await
                .unwrap();
        }
    }

    async fn text(engine: &Engine, space: EventId, doc: &Opening) -> String {
        engine
            .document(&space, &doc.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string()
    }

    /// A seed of `doc`'s stream, empty `covers` and `stubs`, whose stream
    /// snapshot carries the state `writer` holds of `from`.
    async fn write_seed(writer: &Engine, space: EventId, doc: &Opening, from: &Opening) -> EventId {
        let mut state = writer.lock().await;
        let replica = state.replicas.get(&space).unwrap();
        let snapshot = replica
            .stream(&from.stream())
            .unwrap()
            .export_history_free()
            .expect("the document exports");
        let (reference, key) = writer.sealing(&state, &space).unwrap();
        let plaintext = StreamSnapshot {
            type_: doc.type_.clone(),
            stream: doc.stream(),
            history_free: true,
            state: snapshot,
            moved: None,
        }
        .encode();
        let object = seal_object(&space, &key, &reference, &plaintext).unwrap();
        let parts = parts_of(&object.locator, &object.bytes).unwrap();
        writer
            .write_parts(
                &mut state,
                space,
                doc.stream(),
                Some(doc.clone()),
                &doc.type_,
                |_, _, _| {
                    Ok(UnitParts {
                        objects: vec![object.locator],
                        compacts: Some(Compacts {
                            object: object.locator,
                            covers: Vec::new(),
                            stubs: Vec::new(),
                        }),
                        stored: parts,
                        ..UnitParts::default()
                    })
                },
            )
            .await
            .unwrap()
    }

    /// The locator of a snapshot unit's stream snapshot object.
    async fn seed_object(
        writer: &Engine,
        space: EventId,
        seed: EventId,
    ) -> frasil_adapter::Locator {
        writer
            .read(&space, |r| {
                r.event(seed)
                    .and_then(|e| Unit::from_event(e.clone()).ok())
                    .and_then(|u| u.body.compacts.map(|c| c.object))
            })
            .await
            .unwrap()
            .unwrap()
    }

    /// A seed is a snapshot unit, and a suggester writes none (units.md,
    /// 3.17 "`suggest`"): a suggester's seed of a new stream is valid and
    /// checks, its cover being empty, but its content is refused, so no
    /// replica loads its state (3.6 "Using").
    #[tokio::test]
    async fn a_suggesters_seed_is_not_used() {
        let alice = device().await;
        let carol = device().await;
        let space = alice.create_space().await.unwrap();
        grant(&alice, space, &carol).await;
        alice
            .set_suggester(space, MemberRef::device(carol.device_id()), true)
            .await
            .unwrap()
            .expect("Carol becomes a suggester");
        let other = alice.new_document().unwrap();
        write(&alice, space, &other, &["forged"]).await;
        carol.follow(space).await;
        carol
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
        // Carol starts a stream from a copy of another document's state.
        let fresh = carol.new_document().unwrap();
        let seed = write_seed(&carol, space, &fresh, &other).await;
        let locator = seed_object(&carol, space, seed).await;
        let stored = carol.stored_object(&space, &locator).await.unwrap();
        alice
            .receive_object(space, &locator, &stored)
            .await
            .unwrap();
        alice
            .ingest(space, carol.events(&space).await)
            .await
            .unwrap();
        let (status, outcome, used, bad) = alice
            .read(&space, |r| {
                (
                    r.status(&seed).copied(),
                    r.content_outcome(&seed),
                    r.used_snapshots().clone(),
                    r.bad_compactions().clone(),
                )
            })
            .await
            .unwrap();
        assert!(
            matches!(status, Some(frasil_space::Status::Valid(_))),
            "{status:?}"
        );
        assert!(
            matches!(
                outcome,
                Some(crate::adapters::ContentOutcome::Refused(
                    "CapabilityRefused"
                ))
            ),
            "{outcome:?}"
        );
        assert!(!bad.contains(&seed), "the seed checks: {bad:?}");
        assert!(!used.contains(&seed), "{used:?}");
        assert_eq!(text(&alice, space, &fresh).await, "");
    }

    /// A seed covers nothing, so its state stands in for no unit: a replica
    /// whose stream uses a snapshot with a non-empty cover keeps it when an
    /// accepted seed of the stream arrives (units.md, 3.6 "Using").
    #[tokio::test]
    async fn a_seed_does_not_replace_a_base_with_a_cover() {
        let alice = device().await;
        let bob = device().await;
        let dave = device().await;
        let space = alice.create_space().await.unwrap();
        grant(&alice, space, &bob).await;
        grant(&alice, space, &dave).await;
        let doc = alice.new_document().unwrap();
        let other = alice.new_document().unwrap();
        write(&alice, space, &other, &["forged"]).await;
        write(&alice, space, &doc, &["one", " two", " three"]).await;
        let cover: BTreeSet<EventId> = {
            let state = alice.lock().await;
            let replica = state.replicas.get(&space).unwrap();
            let log = replica.log().unwrap();
            log.events()
                .filter(|e| stream_of(log, e.id()) == Some(doc.stream()))
                .map(frasil_events::Event::id)
                .collect()
        };
        let snapshot = alice.compact(space, doc.stream()).await.unwrap();
        let locator = seed_object(&alice, space, snapshot).await;
        let stored = alice.stored_object(&space, &locator).await.unwrap();
        // Dave holds none of the cover: he uses the snapshot.
        let without_cover = |signed: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            signed
                .into_iter()
                .filter(|s| frasil_events::decode(s).is_ok_and(|e| !cover.contains(&e.id())))
                .collect()
        };
        dave.follow(space).await;
        dave.receive_object(space, &locator, &stored).await.unwrap();
        dave.ingest(space, without_cover(alice.events(&space).await))
            .await
            .unwrap();
        assert!(
            dave.read(&space, |r| r.used_snapshots().contains(&snapshot))
                .await
                .unwrap()
        );
        assert_eq!(text(&dave, space, &doc).await, "one two three");
        // Bob, a writer, seeds the stream with another document's state.
        bob.follow(space).await;
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let seed = write_seed(&bob, space, &doc, &other).await;
        let locator = seed_object(&bob, space, seed).await;
        let stored = bob.stored_object(&space, &locator).await.unwrap();
        dave.receive_object(space, &locator, &stored).await.unwrap();
        dave.ingest(space, without_cover(bob.events(&space).await))
            .await
            .unwrap();
        let (outcome, used, base) = dave
            .read(&space, |r| {
                (
                    r.content_outcome(&seed),
                    r.used_snapshots().clone(),
                    r.stream(&doc.stream()).map(|s| s.base_cover().len()),
                )
            })
            .await
            .unwrap();
        assert!(
            matches!(outcome, Some(crate::adapters::ContentOutcome::Applied)),
            "{outcome:?}"
        );
        assert!(
            used.contains(&snapshot) && !used.contains(&seed),
            "{used:?}"
        );
        assert!(base.is_some_and(|len| len > 0), "{base:?}");
        assert_eq!(text(&dave, space, &doc).await, "one two three");
    }
}
