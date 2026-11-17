//! Space files through the engine (ext-space-files.md, feature
//! `space-files`): a space exported to a file with a way in, a file
//! appended to, and a file imported by one of the roads in.
//!
//! - **Export** writes the way in, the snapshot of a history-free file,
//!   the frame's events whole and the included streams' units, the
//!   embedded objects, the sections, and the manifest last ("Export").
//! - **Append** writes the events outside the past of the last manifest's
//!   heads, the objects they name, and a new manifest ("Append").
//! - **Import** reads the file, checks its kind, and takes the road in:
//!   a member merges it as sync by another road; a claimant signs a
//!   successor as the invite key whose fragment the file carries, with
//!   its wrap taken from the invite entry's delivery in place of a drop
//!   ("The claim from a file"); a reader by keys holds the space as a
//!   replica with no grant ("Reading by keys"); otherwise `NoWayIn`.
//!
//! Every event, snapshot and object a file carries passes the checks a
//! peer's answers pass: the file claims nothing a replica believes without
//! the roster proving it.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::{Replica, RotationSecrets};
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::{EventId, kind};
use frasil_space::Level;
use frasil_space_file::file::{self, Read, Refusal, Writer};
use frasil_space_file::record::{History, Manifest, Record, Section, WayIn};
use frasil_space_file::way_in::{Fragment, WayInBody, open_way_in, seal_way_in_with};
use frasil_units::objects::Header;
use frasil_units::stream::StreamId;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// How many events one ingest takes.
const INGEST_BATCH: usize = 256;

/// Which objects an export embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Embed {
    /// Every object the device holds whose stored bytes fit, in locator
    /// order, within this many bytes in all.
    UpTo(u64),
    /// Every object the device holds.
    All,
    /// None, but a snapshot file's own stream snapshot objects.
    None,
}

impl Default for Embed {
    fn default() -> Self {
        Self::UpTo(32 * 1024 * 1024)
    }
}

/// One part of the way in an export writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WayInOption {
    /// The rotation secrets of every state the file's units name: a copy
    /// reads for as long as it exists.
    Keys,
    /// A fresh invite the device grants, whose fragment admits one
    /// claimant with nobody online, for `lifetime` seconds.
    Invite {
        /// `read` or `write`; `administer` is refused.
        level: Level,
        /// The invite's lifetime in seconds, 15 minutes to 7 days.
        lifetime: u64,
    },
}

/// What an export writes.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// The application's kind string for the space.
    pub kind: String,
    /// Full history, or from a space snapshot at the device's heads.
    pub history: History,
    /// The streams whose units the file holds; `None` for every stream.
    pub streams: Option<Vec<StreamId>>,
    /// Which objects to embed.
    pub objects: Embed,
    /// The way in.
    pub way_in: Vec<WayInOption>,
    /// The file key the way in is sealed under; `None` for the clear.
    pub seal: Option<Zeroizing<[u8; 32]>>,
    /// The application's sections.
    pub sections: Vec<Section>,
}

/// The road a file was imported by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Road {
    /// The device held the space as a member: the file was merged in.
    Member,
    /// The device held the space by keys alone, as a reader: the file was
    /// merged in, and it still has no grant.
    Rereading,
    /// A fragment of the file admits the device: the claim is prepared and
    /// waits for the person's consent, on which [`Engine::claim`] signs the
    /// successor; [`Engine::abandon_claim`] declines and keeps nothing.
    #[cfg(feature = "ext-invite-links")]
    Invited {
        /// What the person is shown.
        offer: crate::invite_links::ClaimOffer,
        /// The way in's label, if the exporter wrote one.
        label: Option<String>,
    },
    /// The device holds the space by the file's rotation secrets, with no
    /// grant.
    Reading,
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The space.
    pub space: EventId,
    /// The road in.
    pub road: Road,
    /// How many events the file carried that the device placed anew.
    pub placed: usize,
}

fn refused(refusal: Refusal) -> Error {
    match refusal {
        // A file of another revision (ext-space-files.md, "The
        // manifest").
        Refusal::Class(frasil_base::ErrorClass::RevisionMismatch) => Error::IncompatibleData,
        Refusal::Class(class) => Error::class(class),
        Refusal::NotASpaceFile => Error::Class("NotASpaceFile"),
    }
}

/// Whether an event is part of the frame: a space event, an anchor, a
/// storage event, or a unit of the system stream.
fn in_frame(replica: &Replica, event: &frasil_events::Event) -> bool {
    match event.kind() {
        kind::SPACE | kind::ANCHOR | kind::STORAGE => true,
        kind::UNIT => frasil_units::Unit::from_event(event.clone())
            .ok()
            .is_some_and(|unit| Some(unit.body.stream) == replica.system_stream()),
        _ => false,
    }
}

/// The signed events a file carries, in canonical order: the frame whole,
/// and the units of the included streams, outside `base` with a snapshot,
/// and outside `past` for an append. Also the locators those units name.
fn events_of(
    replica: &Replica,
    streams: Option<&[StreamId]>,
    skip: &BTreeSet<EventId>,
    units_since: Option<&BTreeSet<EventId>>,
) -> (Vec<Vec<u8>>, BTreeSet<Locator>) {
    let mut events = Vec::new();
    let mut named = BTreeSet::new();
    let Some(log) = replica.log() else {
        return (events, named);
    };
    for id in log.canonical() {
        let Some(event) = log.event(id) else {
            continue;
        };
        if skip.contains(&id) {
            continue;
        }
        let included = if in_frame(replica, event) {
            true
        } else if event.kind() == kind::UNIT {
            let Ok(unit) = frasil_units::Unit::from_event(event.clone()) else {
                continue;
            };
            let in_streams = streams.is_none_or(|s| s.contains(&unit.body.stream));
            let after_base = units_since.is_none_or(|base| !base.contains(&id));
            if in_streams && after_base {
                named.extend(unit.body.objects.iter().copied());
                true
            } else {
                false
            }
        } else {
            false
        };
        if included {
            if event.kind() == kind::UNIT
                && let Ok(unit) = frasil_units::Unit::from_event(event.clone())
            {
                named.extend(unit.body.objects.iter().copied());
            }
            events.push(event.signed());
        }
    }
    (events, named)
}

/// The past of a set of events, with the events themselves.
fn past_of(replica: &Replica, heads: &[EventId]) -> BTreeSet<EventId> {
    let mut out = BTreeSet::new();
    if let Some(log) = replica.log() {
        for head in heads {
            if log.contains(*head) {
                out.insert(*head);
                out.extend(log.past(*head));
            }
        }
    }
    out
}

/// The parts of an object's stored bytes, as records.
fn object_records(locator: &Locator, stored: &[u8]) -> Result<Vec<Record>> {
    let parts = crate::objects::parts_of(locator, stored)?;
    let mut out = Vec::with_capacity(parts.len() + 1);
    for part in parts {
        if let Some(header) = part.header {
            out.push(Record::ObjectHeader {
                locator: *locator,
                header,
            });
        }
        out.push(Record::ObjectChunk {
            locator: *locator,
            index: part.index,
            chunk: part.chunk,
        });
    }
    Ok(out)
}

/// The parts of the file's embedded objects, as a fetch carries them.
fn parts_of_read(read: &Read) -> Vec<ObjectPart> {
    let mut out = Vec::new();
    for (locator, object) in &read.objects {
        for (index, chunk) in &object.chunks {
            out.push(ObjectPart {
                locator: *locator,
                header: (*index == 0).then(|| object.header.clone()),
                index: *index,
                chunk: chunk.clone(),
            });
        }
    }
    out
}

impl Engine {
    /// Exports a space to a file (ext-space-files.md, "Export"): the file's
    /// bytes.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::Invalid`] for a kind that is not
    /// a kind string, or an invite at `administer`; [`Error::NotAllowed`]
    /// when the device holds no current state, which a snapshot or an
    /// invite needs; `TooLarge` for a section over a record's limit, or a
    /// way in of more than 64 rotation keys or 64 invites, which no reader
    /// would take (ext-space-files.md, 2.4 The way in); the store's.
    pub async fn export_space_file(
        &self,
        space: EventId,
        options: ExportOptions,
    ) -> Result<Vec<u8>> {
        if !frasil_space_file::record::is_kind(&options.kind) {
            return Err(Error::Invalid(
                "a kind string is 1 to 64 bytes without white space",
            ));
        }
        // Invites first: their entries are events the file carries.
        let mut fragments = Vec::new();
        for option in &options.way_in {
            if let WayInOption::Invite { level, lifetime } = option {
                fragments.push(
                    self.invite_for_file(space, *level, *lifetime, options.history)
                        .await?,
                );
            }
        }
        // The snapshot, at the device's heads.
        let mut snapshot = None;
        let mut snapshot_objects: Vec<(Locator, Vec<u8>)> = Vec::new();
        if options.history == History::FromSnapshot {
            let admitting = match fragments.first() {
                Some(fragment) => fragment.entry,
                None => self.newest_rotation(&space).await?,
            };
            let made = self.newcomer_snapshot(&space, admitting).await?;
            snapshot = Some(made.signed);
            snapshot_objects.extend(made.objects.into_iter().map(|o| (o.locator, o.bytes)));
        }
        // Under the lock: the events, the secrets, the heads.
        let (events, named, heads, secrets) = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let base = match &snapshot {
                Some(signed) => {
                    // The device's own snapshot: only its base is read.
                    let read = frasil_units::snapshot::SpaceSnapshot::read(signed, &space, &())
                        .map_err(Error::class)?;
                    Some(past_of(replica, &read.unverified().base))
                }
                None => None,
            };
            let (events, named) = events_of(
                replica,
                options.streams.as_deref(),
                &BTreeSet::new(),
                base.as_ref(),
            );
            let mut heads = replica.log().map(|log| log.heads()).unwrap_or_default();
            heads.sort_unstable();
            let secrets = if options.way_in.contains(&WayInOption::Keys) {
                rotation_keys(replica)
            } else {
                Vec::new()
            };
            (events, named, heads, secrets)
        };
        if heads.is_empty() {
            return Err(Error::UnknownSpace);
        }
        // The objects, each read with the lock released.
        let mut embedded: BTreeMap<Locator, Vec<u8>> = snapshot_objects.into_iter().collect();
        let mut budget = match options.objects {
            Embed::UpTo(bytes) => Some(bytes),
            Embed::All => None,
            Embed::None => Some(0),
        };
        for locator in named {
            if embedded.contains_key(&locator) {
                continue;
            }
            let Some(stored) = self.stored_object(&space, &locator).await else {
                continue;
            };
            let size = stored.len() as u64;
            if let Some(left) = budget {
                if size > left {
                    continue;
                }
                budget = Some(left - size);
            }
            embedded.insert(locator, stored);
        }
        // The file.
        let mut writer = Writer::new();
        let keyed = !secrets.is_empty() || !fragments.is_empty();
        if secrets.len() > frasil_space_file::way_in::MAX_ITEMS
            || fragments.len() > frasil_space_file::way_in::MAX_ITEMS
        {
            return Err(Error::Class("TooLarge"));
        }
        if keyed {
            let body = WayInBody {
                secrets,
                fragments,
                label: None,
            }
            .encode();
            let record = match &options.seal {
                Some(key) => {
                    let nonce = self.platform().nonce::<24>()?;
                    WayIn::Sealed(seal_way_in_with(key, &nonce, &body, &space))
                }
                None => WayIn::Clear(body),
            };
            writer.record(&Record::WayIn(record))?;
        }
        if let Some(signed) = snapshot {
            writer.record(&Record::Snapshot(signed))?;
        }
        for signed in events {
            writer.record(&Record::Event(signed))?;
        }
        for (locator, stored) in &embedded {
            for record in object_records(locator, stored)? {
                writer.record(&record)?;
            }
        }
        for section in &options.sections {
            writer.record(&Record::Section(section.clone()))?;
        }
        writer.record(&Record::Manifest(Manifest {
            space,
            kind: options.kind,
            heads,
            // Each stream once, ascending, whatever the caller gave.
            streams: options.streams.map(|mut s| {
                s.sort_unstable();
                s.dedup();
                s
            }),
            history: options.history,
            objects: embedded.keys().copied().collect(),
            exporter: self.device_id(),
            time: self.platform().clock.wall(),
        }))?;
        Ok(writer.finish())
    }

    /// Appends to a file what the device holds of the space since the
    /// file's last manifest (ext-space-files.md, "Append"): the file's
    /// bytes, grown.
    ///
    /// # Errors
    ///
    /// The file's classes; `OtherSpace` for a file of another space;
    /// [`Error::UnknownSpace`].
    pub async fn append_space_file(&self, space: EventId, data: &[u8]) -> Result<Vec<u8>> {
        let read = file::read(data).map_err(refused)?;
        if read.manifest.space != space {
            return Err(Error::class(frasil_space_file::SpaceFileClass::OtherSpace));
        }
        let (events, named, heads) = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let past = past_of(replica, &read.manifest.heads);
            let (events, named) = events_of(replica, read.first.streams.as_deref(), &past, None);
            let mut heads = replica.log().map(|log| log.heads()).unwrap_or_default();
            heads.sort_unstable();
            (events, named, heads)
        };
        let mut writer = Writer::appending(data, &read);
        for signed in events {
            writer.record(&Record::Event(signed))?;
        }
        let mut embedded: BTreeSet<Locator> = read.manifest.objects.iter().copied().collect();
        let mut budget = Embed::default();
        for locator in named {
            if embedded.contains(&locator) {
                continue;
            }
            let Some(stored) = self.stored_object(&space, &locator).await else {
                continue;
            };
            if let Embed::UpTo(left) = budget {
                let size = stored.len() as u64;
                if size > left {
                    continue;
                }
                budget = Embed::UpTo(left - size);
            }
            for record in object_records(&locator, &stored)? {
                writer.record(&record)?;
            }
            embedded.insert(locator);
        }
        writer.record(&Record::Manifest(Manifest {
            space,
            kind: read.first.kind.clone(),
            heads,
            streams: read.first.streams.clone(),
            history: read.first.history,
            objects: embedded.into_iter().collect(),
            exporter: read.first.exporter,
            time: self.platform().clock.wall(),
        }))?;
        Ok(writer.finish())
    }

    /// Imports a file (ext-space-files.md, "Import"): the road in.
    /// `kinds` are the kind strings the caller accepts.
    ///
    /// # Errors
    ///
    /// `NotASpaceFile`, `UnsupportedVersion`, `Malformed`, `TooLarge`
    /// (step 1); `WrongKind` (step 2); `Sealed` for a sealed way in
    /// without a key, `Decrypt` with the wrong one (step 4); a claim's
    /// classes (step 5); the first refusal's class when a reader's frame
    /// does not check through to the heads (step 6); `NoWayIn` (step 7);
    /// the store's.
    pub async fn import_space_file(
        &self,
        data: &[u8],
        kinds: &[&str],
        key: Option<&[u8; 32]>,
    ) -> Result<Imported> {
        Box::pin(self.import_space_file_inner(data, kinds, key)).await
    }

    async fn import_space_file_inner(
        &self,
        data: &[u8],
        kinds: &[&str],
        key: Option<&[u8; 32]>,
    ) -> Result<Imported> {
        // 1 and 2.
        let read = file::read(data).map_err(refused)?;
        let space = read.manifest.space;
        if !kinds.iter().any(|kind| *kind == read.manifest.kind) {
            return Err(Error::Class("WrongKind"));
        }
        // 3. Held already: as a member, or by keys alone. A space whose
        // claim waits for the person's consent is not held: the import
        // offers it again.
        if self.presentable_spaces().await.contains(&space) {
            let placed = Box::pin(self.take_in(space, &read, false)).await?;
            let me = self.device_id();
            let member = self
                .read(&space, |replica| replica.level_of(&me).is_some())
                .await
                .unwrap_or(false);
            return Ok(Imported {
                space,
                road: if member {
                    Road::Member
                } else {
                    Road::Rereading
                },
                placed,
            });
        }
        // 4. The way in.
        let body = match &read.way_in {
            None => return Err(Error::Class("NoWayIn")),
            Some(WayIn::Clear(body)) => Zeroizing::new(body.clone()),
            Some(WayIn::Sealed(sealed)) => {
                let key = key.ok_or(Error::Class("Sealed"))?;
                open_way_in(key, sealed, &space).map_err(Error::class)?
            }
        };
        let way_in = WayInBody::read(&body, &space).map_err(Error::class)?;
        // 5. A claimant: the first fragment that reads and passes the
        // claim's checks; one refused is skipped. The claim then waits for
        // the person's consent.
        #[cfg_attr(not(feature = "ext-invite-links"), allow(unused_mut))]
        let mut refused: Option<Error> = None;
        #[cfg(feature = "ext-invite-links")]
        for fragment in &way_in.fragments {
            match Box::pin(self.prepare_claim_from_file(space, fragment, &read)).await {
                Ok((offer, placed)) => {
                    return Ok(Imported {
                        space,
                        road: Road::Invited {
                            offer,
                            label: way_in.label.clone(),
                        },
                        placed,
                    });
                }
                Err(error @ Error::Class(_)) => refused = Some(error),
                Err(error) => return Err(error),
            }
        }
        // 6. A reader by keys.
        if !way_in.secrets.is_empty() {
            let placed = Box::pin(self.read_by_keys(space, &way_in.secrets, &read)).await?;
            return Ok(Imported {
                space,
                road: Road::Reading,
                placed,
            });
        }
        // 7: no way in, or none that worked.
        Err(refused.unwrap_or(Error::Class("NoWayIn")))
    }

    /// Steps 3, 5 and 6 share this: the snapshot used first when the
    /// device starts from it, then every event placed as a peer's, then
    /// every object kept. Returns how many events were placed.
    async fn take_in(&self, space: EventId, read: &Read, newcomer: bool) -> Result<usize> {
        if newcomer && let Some(signed) = &read.snapshot {
            self.adopt_snapshot(space, signed, parts_of_read(read))
                .await?;
        }
        let mut placed = 0;
        for batch in read.events.chunks(INGEST_BATCH) {
            let ingested = self.ingest(space, batch.to_vec()).await?;
            placed += ingested.placed.len();
        }
        for (locator, object) in &read.objects {
            let mut parts = Vec::new();
            for (index, chunk) in &object.chunks {
                parts.push(ObjectPart {
                    locator: *locator,
                    header: (*index == 0).then(|| object.header.clone()),
                    index: *index,
                    chunk: chunk.clone(),
                });
            }
            // An object the device holds already, or one whose parts do not
            // make a whole, changes nothing.
            let _ = self.keep_parts(space, &parts).await;
        }
        Ok(placed)
    }

    /// Reading by keys (ext-space-files.md, "Reading by keys"): each
    /// rotation secret is its rotation's, else `KeyMismatch`; the device
    /// holds the space as a replica with no grant, keeps the secrets, takes
    /// the file in, and keeps the space once its frame has checked through
    /// to the manifest's heads (`Pending` for a head the file does not
    /// reach); else forgets it all.
    async fn read_by_keys(
        &self,
        space: EventId,
        secrets: &[(EventId, Zeroizing<[u8; 32]>)],
        read: &Read,
    ) -> Result<usize> {
        // 1: each secret's read credential is the one its rotation's visible
        // key 11 names (keys.md, "Taking a key"); else KeyMismatch.
        let mut read_publics: BTreeMap<EventId, [u8; 32]> = BTreeMap::new();
        for signed in &read.events {
            if let Ok(event) = frasil_events::decode(signed)
                && event.kind() == kind::SPACE
                && let Some(visible) = crate::replica::visible(&event)
                && let Some(keys) = visible.rotation()
            {
                read_publics.insert(event.id(), keys.read);
            }
        }
        for (rotation, key) in secrets {
            let expected = read_publics.get(rotation);
            if expected != Some(&frasil_keys::derive::read_credential(key).public) {
                return Err(Error::Class("KeyMismatch"));
            }
        }
        self.follow(space).await;
        let keeping = self.keep_content_keys(space, secrets).await;
        let placed = match keeping {
            Ok(()) => self.take_in(space, read, true).await,
            Err(error) => Err(error),
        };
        let checked = match placed {
            Ok(placed) => self
                .frame_checks(space, &read.manifest.heads)
                .await
                .map(|()| placed),
            Err(error) => Err(error),
        };
        match checked {
            Ok(placed) => Ok(placed),
            Err(error) => {
                let _ = self.forget_space(&space).await;
                Err(error)
            }
        }
    }

    /// Whether every head of the manifest is placed and valid at the
    /// replica.
    async fn frame_checks(&self, space: EventId, heads: &[EventId]) -> Result<()> {
        let outcome = self
            .read(&space, |replica| {
                let log = replica.log()?;
                for head in heads {
                    if !log.contains(*head) {
                        return Some(Err(Error::Class("Pending")));
                    }
                    match replica.status(head) {
                        Some(status) if status.is_valid() => {}
                        Some(frasil_space::Status::Void { class, .. }) => {
                            return Some(Err(Error::class(*class)));
                        }
                        _ => return Some(Err(Error::Class("Pending"))),
                    }
                }
                Some(Ok(()))
            })
            .await?;
        outcome.ok_or(Error::Class("Pending"))?
    }

    /// Keeps rotation content keys the way in carries, as the device's
    /// `key` records, so that the space reads after a restart too.
    async fn keep_content_keys(
        &self,
        space: EventId,
        secrets: &[(EventId, Zeroizing<[u8; 32]>)],
    ) -> Result<()> {
        let mut state = self.lock().await;
        let mut batch = crate::at_rest::Batch::default();
        if !state.vault.has_log(&space.0) {
            state
                .vault
                .add_log(&mut batch, &space.0, frasil_store::tables::LogKind::Space)?;
        }
        for (rotation, key) in secrets {
            let found = RotationSecrets {
                content: Some(Zeroizing::new(**key)),
                upload: None,
                grant: None,
            };
            crate::device::put_rotation(&state.vault, &mut batch, &space, rotation, &found)?;
        }
        state.vault.commit(batch).await?;
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        for (rotation, key) in secrets {
            replica.keep_secrets(
                *rotation,
                RotationSecrets {
                    content: Some(Zeroizing::new(**key)),
                    upload: None,
                    grant: None,
                },
            );
        }
        Ok(())
    }

    /// The newest rotation of the space's current state, by height: what
    /// a snapshot for a reader by keys is taken for.
    async fn newest_rotation(&self, space: &EventId) -> Result<EventId> {
        self.read(space, |replica| {
            let held = Self::held_state(replica)?;
            let log = replica.log().ok_or(Error::UnknownSpace)?;
            held.state
                .ids()
                .iter()
                .copied()
                .max_by_key(|id| (log.height(*id).unwrap_or(0), *id))
                .ok_or(Error::NotAllowed("the device holds no current state"))
        })
        .await?
    }

    /// Grants a fresh invite for a file (ext-space-files.md, "Export",
    /// step 2): with history in a full file, from now on in a snapshot
    /// file. Returns its fragment.
    #[cfg(feature = "ext-invite-links")]
    async fn invite_for_file(
        &self,
        space: EventId,
        level: Level,
        lifetime: u64,
        history: History,
    ) -> Result<Fragment> {
        let mode = match history {
            History::Full => frasil_space::HistoryMode::WithHistory,
            History::FromSnapshot => frasil_space::HistoryMode::FromNowOn,
        };
        let made = self
            .make_invite(
                space,
                level,
                mode,
                crate::Claimant::Device,
                lifetime,
                Vec::new(),
            )
            .await?;
        // The file carries the drop's contents: no peer keeps a drop.
        self.drops_kept_at(made.entry, Vec::new()).await;
        let link = frasil_admission::ext_invite_links::read_fragment(&made.fragment)
            .map_err(Error::class)?;
        Ok(Fragment {
            secret: link.secret,
            entry: link.entry,
            space: link.space,
        })
    }

    /// Without invite links, a file carries no invite.
    #[cfg(not(feature = "ext-invite-links"))]
    #[allow(clippy::unused_async)]
    async fn invite_for_file(
        &self,
        _space: EventId,
        _level: Level,
        _lifetime: u64,
        _history: History,
    ) -> Result<Fragment> {
        Err(Error::Unsupported("ext-invite-links"))
    }

    /// The claim from a file (ext-space-files.md, "The claim from a
    /// file"): `K`'s wrap from the invite entry's delivery in place of the
    /// drop, the file's snapshot and events in place of fetching, then the
    /// claimant's checks, steps 5 to 9. The successor is signed on the
    /// person's consent, by [`Engine::claim`]. Returns the offer and how
    /// many events were placed; on a refusal the claim is abandoned and
    /// the space forgotten.
    #[cfg(feature = "ext-invite-links")]
    async fn prepare_claim_from_file(
        &self,
        space: EventId,
        fragment: &Fragment,
        read: &Read,
    ) -> Result<(crate::invite_links::ClaimOffer, usize)> {
        use crate::invite_links::ClaimStatus;
        use frasil_admission::ext_invite_links::{DropPlain, InviteKeys, Link};
        use frasil_keys::wraps::find_own_wrap;
        let keys = InviteKeys::derive(&fragment.secret);
        // 2. The invite entry is an event of the file, and its delivery
        // holds a wrap that opens for K.
        let entry = read
            .events
            .iter()
            .filter_map(|signed| frasil_events::decode(signed).ok())
            .find(|event| event.id() == fragment.entry)
            .ok_or(Error::Class("NoWrap"))?;
        let visible = crate::replica::visible(&entry).ok_or(Error::Class("NoWrap"))?;
        let mut plain = None;
        for delivery in &visible.deliveries {
            let Some(key_name) = &delivery.key_name else {
                continue;
            };
            if let Some((index, _)) = find_own_wrap(
                &delivery.wraps,
                &space.0,
                Some(key_name),
                delivery.grant_name.as_ref(),
                &keys.device_id(),
                &keys.xwing_seed,
            ) {
                plain = Some(DropPlain {
                    key_name: key_name.encode(),
                    grant_key_name: delivery
                        .grant_name
                        .as_ref()
                        .map(frasil_keys::KeyName::encode)
                        .unwrap_or_default(),
                    wrap: delivery.wraps[index].clone(),
                    peers: Vec::new(),
                    snapshot: None,
                });
                break;
            }
        }
        let plain = plain.ok_or(Error::Class("NoWrap"))?;
        let link = Link {
            secret: fragment.secret.clone(),
            entry: fragment.entry,
            space: fragment.space,
        };
        self.begin_claim_with(&link, &plain, false).await?;
        // 3 and 4: the file in place of fetching, then the claim's checks;
        // the successor waits for the person's consent (`Engine::claim`).
        let outcome = async {
            let placed = self.take_in(space, read, true).await?;
            match self.claim_status(&space).await? {
                ClaimStatus::Ready(offer) => Ok((offer, placed)),
                ClaimStatus::Claimed(_) => Err(Error::Class("InviteUsed")),
                ClaimStatus::Waiting => Err(Error::Class("NotInRoster")),
            }
        }
        .await;
        match outcome {
            Ok(ready) => Ok(ready),
            Err(error) => {
                let _ = self.abandon_claim(&space).await;
                Err(error)
            }
        }
    }
}

/// Every rotation's content key the replica holds, ascending by ID.
fn rotation_keys(replica: &Replica) -> Vec<(EventId, Zeroizing<[u8; 32]>)> {
    let Some(log) = replica.log() else {
        return Vec::new();
    };
    let mut out: Vec<(EventId, Zeroizing<[u8; 32]>)> = log
        .events()
        .filter(|event| event.kind() == kind::SPACE)
        .filter_map(|event| {
            let secrets = replica.secrets_of(&event.id())?;
            let content = secrets.content.as_ref()?;
            Some((event.id(), Zeroizing::new(**content)))
        })
        .collect();
    out.sort_by_key(|(id, _)| *id);
    out
}

/// A header's size, for a budget.
#[allow(dead_code)]
fn size_of(header: &[u8]) -> Option<u64> {
    Header::read(header).ok().map(|h| h.size)
}

#[allow(dead_code)]
fn _state_use(_: &State) {}
