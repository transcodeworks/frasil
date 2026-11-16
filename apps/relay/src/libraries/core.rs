//! The peer's procedures of ext-libraries.md, with the libraries under a
//! lock of their own and each space under its own:
//! `LibraryAttach` (3.3 Attaching), a create's or an import's genesis, the
//! checks before a store (3.4 Storing), the sweep of tickets used, a
//! space's usage for its ledger, deleting a space (3.5), and holds:
//! `HoldObject` (3.7), keeping a held object (3.8) and fetching one (3.9).

use super::{Ledger, Libraries, Record, Request, SpaceUsage, UsageRecord};
use crate::config::Settings;
use crate::records::Records;
use crate::space::{Space, object_bytes};
use crate::spaces::{Writing, blocking};
use crate::state::{Core, Grant, On, Outgoing, Reason, StoreAnswer, lock, refused};
use crate::util::log;
use crate::writer::made;
use frasil_base::time::Reading;
use frasil_events::{Event, EventId};
use frasil_libraries::{
    HoldObject, LibraryAttach, LibraryClass, LibraryId, PeerHolds, Purpose, TicketId,
};
use frasil_peers::body::{StorageBody, StorageType};
use frasil_peers::decisions::Execution;
use frasil_store::{Commit, StoreError};
use frasil_transport::messages::Accepted;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

/// Whether a store is one ext-libraries.md, 3.4 Storing, never refuses for
/// a library: a release, a restore or an erasure, which only lowers usage.
fn never_refused(event: &Event) -> bool {
    event.kind() == frasil_events::kind::STORAGE
        && StorageBody::read(event.unverified_body()).is_ok_and(|body| {
            matches!(
                body.storage_type(),
                StorageType::Release | StorageType::Restore | StorageType::Erase
            )
        })
}

/// A class as a reason code and its status.
fn reason(class: LibraryClass) -> Reason {
    (class.code().to_owned(), class.status().unwrap_or(400))
}

impl Libraries {
    /// What the peer keeps, from its records, under the peer's settings.
    ///
    /// # Errors
    ///
    /// If the records cannot be read.
    pub(crate) fn open(settings: &Settings, records: &Records) -> Result<Self, StoreError> {
        let rows = records.library_records()?;
        let decoded = rows.into_iter().filter_map(|(table, key, bytes)| {
            let record = Record::decode(table, &key, &bytes);
            if record.is_none() {
                log("a library record that does not read");
            }
            record
        });
        // ext-deposit-tokens.md's records are read only while it is on.
        let deposit = settings
            .extensions
            .deposit_tokens
            .then(|| settings.deposit_tokens.defaults());
        Ok(
            Self::from_records(settings.libraries.clone(), deposit, decoded)
                .with_erasure_timeout(settings.erasure_timeout),
        )
    }
}

/// A space's usage, as its library's ledger counts it (ext-libraries.md,
/// 2.5 What a peer keeps). `stored_bytes` is peers.md's usage without the
/// invite drops, which ext-invite-links.md adds.
pub(crate) fn space_usage(space: &Space) -> SpaceUsage {
    let released = space.released_streams();
    let in_released = |id: &EventId| {
        space
            .units
            .get(id)
            .is_some_and(|unit| released.contains(&unit.stream))
    };
    let mut usage = SpaceUsage {
        stored_bytes: space.usage,
        drops: space.drops,
        drop_bytes: space.drop_bytes,
        ..SpaceUsage::default()
    };
    for event in space.log.events().chain(space.log.pending()) {
        let id = event.id();
        let bytes = event.signed_len() as u64;
        if in_released(&id) {
            usage.released_bytes = usage.released_bytes.saturating_add(bytes);
        } else if space.covered.contains(&id) {
            usage.covered_bytes = usage.covered_bytes.saturating_add(bytes);
        }
    }
    for (locator, record) in &space.objects {
        let referencing: Vec<&EventId> = space
            .units
            .iter()
            .filter(|(_, unit)| unit.objects.contains(locator))
            .map(|(id, _)| id)
            .collect();
        if referencing.is_empty() {
            continue;
        }
        if referencing.iter().all(|id| in_released(id)) {
            usage.released_bytes = usage.released_bytes.saturating_add(object_bytes(record));
        } else if referencing
            .iter()
            .all(|id| in_released(id) || space.covered.contains(*id))
        {
            usage.covered_bytes = usage.covered_bytes.saturating_add(object_bytes(record));
        }
    }
    usage.erasing_bytes = erasing_bytes(space);
    usage.streams = space
        .streams
        .values()
        .filter(|units| !units.is_empty())
        .count() as u64;
    let last = space
        .sights
        .values()
        .chain(space.objects.values().map(|record| &record.last))
        .max_by_key(|reading| reading.timeline);
    usage.last_store = last.and_then(|reading| reading.wall);
    usage
}

/// A closed space's usage at rest, which its library's ledger reads without
/// opening it (ext-libraries.md, 2.5 What a peer keeps).
pub(crate) fn usage_record(space: &Space) -> Vec<u8> {
    let usage = space_usage(space);
    UsageRecord {
        stored_bytes: usage.stored_bytes,
        released_bytes: usage.released_bytes,
        covered_bytes: usage.covered_bytes,
        erasing_bytes: usage.erasing_bytes,
        streams: usage.streams,
        last_store: usage.last_store,
        unlisted: space
            .objects
            .iter()
            .filter(|(locator, record)| {
                record.complete
                    && !space
                        .units
                        .values()
                        .any(|unit| unit.objects.contains(*locator))
            })
            .map(|(locator, record)| (*locator, object_bytes(record)))
            .collect(),
    }
    .encode()
}

/// The bytes that count in usage and that erasures waiting at the peer
/// name: the space's whole usage while an erasure of it is neither void nor
/// carried out, since an erasure names the whole space (peers.md,
/// "Erasure").
fn erasing_bytes(space: &Space) -> u64 {
    for request in &space.requests {
        if space.executed.contains(request) || space.outcomes.get(request) == Some(&Execution::Void)
        {
            continue;
        }
        let Some(event) = space.log.event(*request) else {
            continue;
        };
        if StorageBody::read(event.unverified_body()) == Ok(StorageBody::Erase) {
            return space.usage;
        }
    }
    0
}

/// The connection and the peer, as `check_hold` reads them (ext-libraries.md,
/// 3.7 Registering a hold). The source is opened before.
struct HoldView<'v> {
    core: &'v Core,
    grants: &'v BTreeMap<EventId, Grant>,
}

impl PeerHolds for HoldView<'_> {
    fn store_right(&self, space: &[u8; 32]) -> bool {
        self.grants
            .get(&EventId(*space))
            .is_some_and(|grant| grant.rights.store)
    }

    fn fetch_right(&self, space: &[u8; 32]) -> bool {
        self.grants
            .get(&EventId(*space))
            .is_some_and(|grant| grant.rights.fetch)
    }

    fn vouches(&self, locator: &[u8; 64], access: &[u8; 32]) -> bool {
        lock(&self.core.libraries).vouches(locator, access)
    }

    fn holds_object(&self, source: &[u8; 32], locator: &[u8; 64]) -> bool {
        let source = EventId(*source);
        if self.core.tombstoned(&source) {
            return false;
        }
        self.core
            .peek(&source, |space| {
                space
                    .objects
                    .get(locator)
                    .is_some_and(|record| record.complete)
            })
            .unwrap_or(false)
    }

    fn same_library(&self, space: &[u8; 32], source: &[u8; 32]) -> bool {
        lock(&self.core.libraries).same_library(&EventId(*space), &EventId(*source))
    }
}

/// Bytes a space's writer holds in its library's quota while its store
/// is made; dropped, they are released. A store that is made has its bytes
/// in the space's `used_bytes` by then.
pub(crate) struct Reserved<'c> {
    core: &'c Core,
    space: EventId,
    bytes: u64,
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        let mut index = lock(&self.core.index);
        if let Some(held) = index.reserved.get_mut(&self.space) {
            *held = held.saturating_sub(self.bytes);
            if *held == 0 {
                index.reserved.remove(&self.space);
            }
        }
    }
}

/// A library commit submitted, and what to do if it fails.
pub(crate) type LibraryCommit =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StoreError>> + Send>>;

impl Core {
    /// A space's usage as its library's ledger counts it, with the holds it
    /// registered, from the space open.
    fn ledger_usage_of(&self, space: &Space) -> SpaceUsage {
        let mut usage = space_usage(space);
        let libraries = lock(&self.libraries);
        usage.holds = libraries.holds_of(&space.id);
        // The space's objects that no unit of it lists any more, which
        // holds keep (section 3.8).
        usage.held_bytes = space
            .objects
            .iter()
            .filter(|(locator, record)| {
                record.complete
                    && !space
                        .units
                        .values()
                        .any(|unit| unit.objects.contains(*locator))
                    && libraries.is_held(&space.id, locator)
            })
            .fold(0u64, |total, (_, record)| {
                total.saturating_add(object_bytes(record))
            });
        usage
    }

    /// A closed space's usage, as its library's ledger counts it, from its
    /// usage record, without opening it: `None` for a space that is open,
    /// that may hold something a sweep must judge, or whose record is not
    /// at rest. Blocking: it reads the records.
    fn closed_usage(&self, space: &EventId) -> Option<SpaceUsage> {
        if self.peek(space, |_| ()).is_some() || self.waiting(space) {
            return None;
        }
        let bytes = self.records.usage(space).ok()??;
        let record = UsageRecord::decode(&bytes)?;
        let unlisted = record.unlisted;
        let mut usage = SpaceUsage {
            stored_bytes: record.stored_bytes,
            released_bytes: record.released_bytes,
            covered_bytes: record.covered_bytes,
            erasing_bytes: record.erasing_bytes,
            streams: record.streams,
            last_store: record.last_store,
            ..SpaceUsage::default()
        };
        {
            let libraries = lock(&self.libraries);
            usage.holds = libraries.holds_of(space);
            usage.held_bytes = unlisted
                .iter()
                .filter(|(locator, _)| libraries.is_held(space, locator))
                .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes));
        }
        if self.settings.extensions.invite_links {
            let now = self.clock.now().timeline;
            let (drops, bytes) = lock(&self.drops).count(space.as_bytes(), now);
            usage.drops = drops;
            usage.drop_bytes = bytes;
        }
        Some(usage)
    }

    /// A library's ledger: each closed space's usage from its usage record,
    /// each other space opened in turn; `None` for a library the peer does
    /// not know.
    pub(crate) async fn ledger(&self, library: &LibraryId) -> Option<Ledger> {
        let members: Vec<EventId> = lock(&self.libraries).members(library).copied().collect();
        let mut usages = BTreeMap::new();
        for space in members {
            let closed = crate::spaces::blocking_here(|| self.closed_usage(&space));
            let usage = match closed {
                Some(usage) => usage,
                None => self
                    .read(space, |held| self.ledger_usage_of(held))
                    .await
                    .unwrap_or_default(),
            };
            usages.insert(space, usage);
        }
        let usage = |space: &EventId| usages.get(space).cloned().unwrap_or_default();
        let ledger = lock(&self.libraries).ledger(library, &usage)?;
        Some(self.window_passed(ledger))
    }

    /// [`Self::ledger`], for a caller that cannot await.
    pub(crate) fn ledger_blocking(&self, library: &LibraryId) -> Option<Ledger> {
        let members: Vec<EventId> = lock(&self.libraries).members(library).copied().collect();
        let usages: BTreeMap<EventId, SpaceUsage> = members
            .into_iter()
            .map(|space| {
                let usage = crate::spaces::blocking_here(|| self.closed_usage(&space))
                    .unwrap_or_else(|| {
                        self.read_blocking(space, |held| self.ledger_usage_of(held))
                            .unwrap_or_default()
                    });
                (space, usage)
            })
            .collect();
        let usage = |space: &EventId| usages.get(space).cloned().unwrap_or_default();
        let ledger = lock(&self.libraries).ledger(library, &usage)?;
        Some(self.window_passed(ledger))
    }

    /// `HoldObject` (ext-libraries.md, 3.7 Registering a hold), in order;
    /// then the hold is recorded, and `Accepted`.
    pub(crate) async fn hold_object(
        &self,
        on: &On,
        grants: &BTreeMap<EventId, Grant>,
        hold: &HoldObject,
    ) -> Outgoing {
        // The source open, for its objects.
        let _ = self.read(EventId(hold.source), |_| ()).await;
        let view = HoldView { core: self, grants };
        if let Err(class) = frasil_libraries::check_hold(hold, &on.binding, &view) {
            return refused(hold.request, class.code());
        }
        // A library being handed over takes no hold meanwhile (peers.md,
        // 3.1 Hosting a space, "Hand-over").
        if self.handing_over(&EventId(hold.space)) {
            return refused(hold.request, "busy");
        }
        let pending = {
            let mut libraries = lock(&self.libraries);
            let record = libraries.add_hold(
                EventId(hold.space),
                hold.locator,
                super::Hold {
                    source: hold.source,
                    access: hold.access,
                    at: on.now,
                },
            );
            record.map(|record| self.submit_libraries(vec![record], Vec::new()))
        };
        if let Some(pending) = pending
            && self.finish_libraries(pending).await.is_err()
        {
            return refused(hold.request, "busy");
        }
        Outgoing::Control(
            Accepted {
                request: hold.request,
            }
            .encode(),
        )
    }

    /// The space that stores the bytes of an object a space fetches: the
    /// space itself, or the source of a hold of it (ext-libraries.md, 3.9
    /// Fetching a held object).
    pub(crate) async fn held_source(&self, space: &EventId, locator: &[u8; 64]) -> Option<EventId> {
        let source = EventId(lock(&self.libraries).hold(space, locator)?.source);
        self.read(source, |held| held.objects.contains_key(locator))
            .await
            .unwrap_or(false)
            .then_some(source)
    }

    /// The copy a hold of a space points at, as the home its pieces are
    /// kept under and the object's record, complete (ext-libraries.md,
    /// 3.8 Keeping a held object).
    pub(crate) fn held_copy(
        &self,
        space: &EventId,
        locator: &[u8; 64],
    ) -> Option<(EventId, crate::records::ObjectRecord)> {
        let libraries = lock(&self.libraries);
        let (library, copy) = libraries.hold_copy(space, locator)?;
        let record = crate::records::ObjectRecord::decode(&copy.object).filter(|r| r.complete)?;
        Some((EventId(super::copy_home(library)), record))
    }

    /// The sweep of copies (ext-libraries.md, 3.8 Keeping a held object):
    /// a copy no hold points at, or whose source the peer erased, goes,
    /// with its pieces; in a cluster, each node sweeps the copies of the
    /// libraries whose shards it keeps. A copy a move under way may need
    /// stays. Returns the pieces to delete.
    pub(crate) async fn sweep_copies(&self) -> Vec<String> {
        let moving: BTreeSet<EventId> = lock(&self.moves).keys().copied().collect();
        let (pieces, pending) = {
            let mut libraries = lock(&self.libraries);
            let kept: BTreeSet<LibraryId> = libraries
                .copies()
                .keys()
                .map(|(library, _)| library.clone())
                .filter(|library| {
                    self.shards.as_ref().is_none_or(|shards| {
                        shards.keeps_shard(&crate::shards::library_shard(library.as_str()))
                    })
                })
                .collect();
            let mut gone = Vec::new();
            for library in kept {
                for locator in libraries.unheld_copies(&library, |source| self.tombstoned(source)) {
                    let involved = libraries
                        .copy(&library, &locator)
                        .is_some_and(|copy| moving.contains(&EventId(copy.source)))
                        || libraries
                            .holds()
                            .keys()
                            .any(|(holder, held)| *held == locator && moving.contains(holder));
                    if !involved {
                        gone.push((library.clone(), locator));
                    }
                }
            }
            if gone.is_empty() {
                return Vec::new();
            }
            let mut pieces = Vec::new();
            for (library, locator) in &gone {
                if let Some(record) = libraries
                    .copy(library, locator)
                    .and_then(|copy| crate::records::ObjectRecord::decode(&copy.object))
                {
                    let home = super::copy_home(library);
                    pieces.extend(
                        record
                            .pieces
                            .iter()
                            .map(|&piece| crate::objects::piece_key(&home, locator, piece)),
                    );
                }
            }
            let deletes = libraries.drop_copies(&gone);
            (pieces, self.submit_libraries(Vec::new(), deletes))
        };
        if self.finish_libraries(pending).await.is_err() {
            return Vec::new();
        }
        pieces
    }

    /// Whether a hold keeps a source's object from the source's own
    /// collection: a hold names it (ext-libraries.md, 3.8 Keeping a held
    /// object). An erasure of the source removes the source whole.
    pub(crate) fn kept_by_hold(&self, source: &Space, locator: &[u8; 64]) -> bool {
        lock(&self.libraries).is_held(&source.id, locator)
    }

    /// The sweep of holds (ext-libraries.md, 3.8 Keeping a held object):
    /// holds no longer live end, and objects that only ended holds kept
    /// are collected. A hold is live while its space stores a unit that
    /// lists its locator or, until one does, for `orphan_grace` from its
    /// registration; its space erased or deleted, it ends. Returns the
    /// object pieces to delete.
    ///
    /// In a cluster each node sweeps the holds of the spaces whose shards
    /// it keeps, and the sources it keeps: no node opens or writes a shard
    /// another keeps. A hold whose hosted space does not open now is judged
    /// at a later sweep.
    pub(crate) async fn sweep_holds(&self, now: Reading) -> Vec<String> {
        let held: Vec<(EventId, [u8; 64])> = lock(&self.libraries)
            .holds()
            .keys()
            .filter(|(space, _)| self.keeps_space(space))
            .copied()
            .collect();
        if held.is_empty() {
            return Vec::new();
        }
        let mut listed = BTreeSet::new();
        let mut unread = BTreeSet::new();
        for (space, locator) in &held {
            let file_versions = self.settings.extensions.file_versions;
            let (space_now, settings) = (self.space_now(space, now), self.sweep_settings(space));
            let lists = self
                .read(*space, |space| {
                    // A unit kept only as a parent of a space event
                    // references nothing (peers.md, "Collection").
                    let lists = space.units.iter().any(|(id, unit)| {
                        unit.objects.contains(locator) && !space.kept_as_parent(*id)
                    });
                    // ext-file-versions.md, 3.9: a reference to an old
                    // version goes with the version.
                    lists && !(file_versions && space.hold_ends(locator, space_now, &settings))
                })
                .await;
            match lists {
                Some(true) => {
                    listed.insert((*space, *locator));
                }
                Some(false) => {}
                None if self.hosts(space) => {
                    unread.insert((*space, *locator));
                }
                None => {}
            }
        }
        let (sources, pending) = {
            let mut libraries = lock(&self.libraries);
            let mut ended = libraries.ended_holds(
                &now,
                self.settings.orphan_grace,
                |space| self.hosts(space),
                |space, locator| listed.contains(&(*space, *locator)),
            );
            ended.retain(|key| held.contains(key) && !unread.contains(key));
            if ended.is_empty() {
                return Vec::new();
            }
            let sources: BTreeSet<(EventId, [u8; 64])> = ended
                .iter()
                .filter_map(|key| {
                    libraries
                        .holds()
                        .get(key)
                        .map(|hold| (EventId(hold.source), key.1))
                })
                .collect();
            let deletes = libraries.drop_holds(&ended);
            // The sources whose objects the ended holds kept sweep again:
            // an object no unit of its space lists any more and no other
            // hold names goes by peers.md's rules, now.
            let sources: BTreeSet<EventId> = sources
                .into_iter()
                .filter(|(source, locator)| !libraries.is_held(source, locator))
                .map(|(source, _)| source)
                .collect();
            (sources, self.submit_libraries(Vec::new(), deletes))
        };
        let _ = self.finish_libraries(pending).await;
        let mut pieces = Vec::new();
        for source in sources
            .into_iter()
            .filter(|source| self.keeps_space(source))
        {
            if let Ok(writing) = self.write(source).await {
                pieces.extend(self.sweep_space(&writing, now).await);
            }
        }
        pieces
    }

    /// Each hosted space's `used_bytes`, as last noted, with the bytes its
    /// writers hold for stores not yet made, for the library rules.
    pub(crate) fn used_bytes(&self, space: &EventId) -> u64 {
        let index = lock(&self.index);
        let used = index.used.get(space).copied().unwrap_or(0);
        used.saturating_add(index.reserved.get(space).copied().unwrap_or(0))
    }

    /// Opens each space of a space's library whose `used_bytes` the peer
    /// has not noted since it started, so that the library's quota counts
    /// them. Called holding no space's state.
    pub(crate) async fn know_library_usage(&self, space: &EventId) {
        let members: Vec<EventId> = {
            let libraries = lock(&self.libraries);
            match libraries.attachment(space) {
                Some(attachment) => libraries.members(&attachment.library).copied().collect(),
                None => return,
            }
        };
        self.know_usage(&members).await;
    }

    /// Opens each space of a library whose `used_bytes` the peer has not
    /// noted since it started, so that its quota counts them.
    pub(crate) async fn know_library_members(&self, library: &LibraryId) {
        let members: Vec<EventId> = lock(&self.libraries).members(library).copied().collect();
        self.know_usage(&members).await;
    }

    /// Opens each of `spaces` whose `used_bytes` is not noted.
    pub(crate) async fn know_usage(&self, spaces: &[EventId]) {
        let unknown: Vec<EventId> = {
            let index = lock(&self.index);
            spaces
                .iter()
                .filter(|space| index.hosted.contains(*space) && !index.used.contains_key(*space))
                .copied()
                .collect()
        };
        for space in unknown {
            // A closed space's usage record says it; another space opens.
            let closed = crate::spaces::blocking_here(|| self.closed_usage(&space));
            match closed {
                Some(usage) => {
                    lock(&self.index).used.insert(space, usage.used_bytes());
                }
                None => {
                    let _ = self.read(space, |_| ()).await;
                }
            }
        }
    }

    /// Submits library records to write, and others to delete, in one
    /// commit: under the libraries' lock, so that commits keep its order.
    pub(crate) fn submit_libraries(
        &self,
        puts: Vec<Record>,
        deletes: Vec<(u8, Vec<u8>)>,
    ) -> LibraryCommit {
        let puts = puts
            .iter()
            .map(|record| {
                let (table, key, bytes) = record.encode();
                (Records::library_address(table, &key), bytes)
            })
            .collect();
        let deletes = deletes
            .iter()
            .map(|(table, key)| Records::library_address(*table, key))
            .collect();
        Box::pin(self.writer.submit(Commit::new(puts, deletes)))
    }

    /// Awaits a library commit. If it fails, what the peer keeps is read
    /// again, so that memory matches the records.
    pub(crate) async fn finish_libraries(&self, pending: LibraryCommit) -> Result<(), StoreError> {
        let result = made(pending.await);
        if let Err(error) = &result {
            log(format_args!("a library record was not kept: {error}"));
            let records = self.records.clone();
            let settings = self.settings.clone();
            match blocking(move || Libraries::open(&settings, &records)).await {
                Ok(libraries) => *lock(&self.libraries) = libraries,
                Err(error) => log(format_args!("the library records were not read: {error}")),
            }
        }
        result
    }

    /// Writes library records, and deletes others, in one commit, blocking
    /// the caller, with the libraries' lock held. If the commit fails, what
    /// the peer keeps is read again.
    pub(crate) fn commit_libraries_blocking(
        &self,
        libraries: &mut Libraries,
        puts: Vec<Record>,
        deletes: Vec<(u8, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        let puts = puts
            .iter()
            .map(|record| {
                let (table, key, bytes) = record.encode();
                (Records::library_address(table, &key), bytes)
            })
            .collect();
        let deletes = deletes
            .iter()
            .map(|(table, key)| Records::library_address(*table, key))
            .collect();
        let result = crate::spaces::blocking_here(|| self.writer.commit_blocking(puts, deletes));
        if let Err(error) = &result {
            log(format_args!("a library record was not kept: {error}"));
            match crate::spaces::blocking_here(|| Libraries::open(&self.settings, &self.records)) {
                Ok(reread) => *libraries = reread,
                Err(error) => log(format_args!("the library records were not read: {error}")),
            }
        }
        result
    }

    /// `LibraryAttach` (ext-libraries.md, 3.3 Attaching), in order. A move
    /// is recorded at once; a create or an import is accepted, its ticket
    /// spent, and recorded when its genesis is stored on this connection.
    pub(crate) async fn library_attach(
        &self,
        on: &On,
        grants: &mut BTreeMap<EventId, Grant>,
        attach: &LibraryAttach,
    ) -> Outgoing {
        let space = EventId(attach.space);
        let request = Request {
            purpose: attach.purpose,
            space,
            signed: &attach.signed,
            wall: on.now.wall,
            hosted: self.hosts(&space),
            store_right: grants.get(&space).is_some_and(|grant| grant.rights.store),
        };
        // The spaces whose usage the check counts are known first: a first
        // check finds them, and the second decides.
        let unknown = Mutex::new(Vec::new());
        {
            let libraries = lock(&self.libraries);
            let usage = |id: &EventId| {
                if !lock(&self.index).used.contains_key(id) {
                    lock(&unknown).push(*id);
                }
                self.used_bytes(id)
            };
            let _ = libraries.check(&request, &usage);
        }
        let unknown = unknown.into_inner().unwrap_or_else(PoisonError::into_inner);
        self.know_usage(&unknown).await;
        let pending = {
            let mut libraries = lock(&self.libraries);
            let usage = |id: &EventId| self.used_bytes(id);
            let ticket = match libraries.check(&request, &usage) {
                Ok(ticket) => ticket,
                Err(class) => return refused(attach.request, class.code()),
            };
            let mut puts = libraries.spend(&ticket);
            let mut deletes = Vec::new();
            if attach.purpose == Purpose::Move {
                puts.extend(libraries.attach(space, &ticket.library, Some(ticket.id), on.now));
                deletes.extend(Libraries::cleared(&space));
            }
            (ticket, self.submit_libraries(puts, deletes))
        };
        let (ticket, pending) = pending;
        if self.finish_libraries(pending).await.is_err() {
            return refused(attach.request, "busy");
        }
        if attach.purpose != Purpose::Move {
            let grant = grants.entry(space).or_default();
            grant.library.pending = Some((attach.purpose, ticket.library, ticket.id, on.now));
        }
        Outgoing::Control(
            Accepted {
                request: attach.request,
            }
            .encode(),
        )
    }

    /// Attaches a space just created to a library.
    async fn attach_created(
        &self,
        space: EventId,
        library: &LibraryId,
        ticket: Option<TicketId>,
        at: Reading,
    ) {
        let pending = {
            let mut libraries = lock(&self.libraries);
            let puts = libraries.attach(space, library, ticket, at);
            let deletes = Libraries::cleared(&space).to_vec();
            self.submit_libraries(puts, deletes)
        };
        if self.finish_libraries(pending).await.is_err() {
            log("a space was created without its attachment");
        }
    }

    /// A genesis stored for a space the peer does not host: a create or an
    /// import this connection's `LibraryAttach` accepted; a create the
    /// operator's open library takes, while hosting is open; or
    /// `no_library`. An import's genesis adds its entry retired, source
    /// `import`, and starts the import (peers.md, "Hosting a space").
    pub(crate) async fn library_create(
        &self,
        writing: &Writing,
        grant: &mut Grant,
        event: Event,
        signed: &[u8],
        now: Reading,
    ) -> StoreAnswer {
        // A genesis of a space this peer handed over is refused `erased`,
        // but for an import, which ends its departure record (peers.md,
        // 3.1 Hosting a space, "Hand-over").
        let departed = event.is_genesis()
            && crate::spaces::blocking_here(|| self.departure_of(&writing.id)).is_some();
        let importing = matches!(grant.library.pending, Some((Purpose::Import, ..)));
        if departed && !importing {
            grant.library.lapse();
            return StoreAnswer::Refused(LibraryClass::Erased.code().into());
        }
        let Some((purpose, library, ticket, at)) = grant.library.pending.clone() else {
            return self.open_create(writing, event, signed, now).await;
        };
        // The first event stored must be the genesis (ext-libraries.md, 3.3
        // Attaching).
        if !event.is_genesis() {
            return StoreAnswer::Refused(LibraryClass::NotAuthorized.code().into());
        }
        let imported = purpose == Purpose::Import;
        // A genesis of a space the operator deleted is refused `erased` for
        // a create, and lapses it; an import of it may proceed (peers.md,
        // 3.2 Storing an event, step 3).
        if !imported && lock(&self.libraries).is_deleted(&writing.id) {
            grant.library.pending = None;
            return StoreAnswer::Refused(LibraryClass::Erased.code().into());
        }
        // A library being handed over takes no new space meanwhile.
        if lock(&self.libraries).handing().contains(&library) {
            return StoreAnswer::Refused("busy".into());
        }
        let shard = crate::shards::library_shard(library.as_str());
        let answer = self
            .create(writing, event, signed, now, shard, imported)
            .await;
        if let StoreAnswer::Acknowledge(space) = answer {
            grant.library.pending = None;
            grant.library.importing = imported;
            self.attach_created(space, &library, Some(ticket), at).await;
            if departed {
                self.end_departure(&space).await;
            }
        }
        answer
    }

    /// A create without a ticket: the operator's own hosting, by its open
    /// library while hosting is open; otherwise `no_library`, so that a
    /// closed peer hosts a space only once a ticket attached it
    /// (ext-libraries.md, 1 Overview).
    async fn open_create(
        &self,
        writing: &Writing,
        event: Event,
        signed: &[u8],
        now: Reading,
    ) -> StoreAnswer {
        let library = match self.settings.hosting {
            crate::config::Hosting::Open => self.settings.libraries.open_library.clone(),
            crate::config::Hosting::Closed => None,
        };
        let Some(library) = library else {
            return StoreAnswer::Refused(LibraryClass::NoLibrary.code().into());
        };
        if lock(&self.libraries).is_deleted(&writing.id) {
            return StoreAnswer::Refused(LibraryClass::Erased.code().into());
        }
        // The operator's open library is sharded by space.
        let shard = crate::shards::space_shard(writing.id.as_bytes());
        let answer = self.create(writing, event, signed, now, shard, false).await;
        if let StoreAnswer::Acknowledge(space) = answer {
            self.attach_created(space, &library, None, now).await;
        }
        answer
    }

    /// ext-libraries.md, 3.4 Storing, at peers.md's step "The space is
    /// hosted here", for an event. Releases, restores and erasures are
    /// never refused for a library.
    ///
    /// # Errors
    ///
    /// `no_library` or `library_closed`.
    pub(crate) fn library_hosts(&self, space: &EventId, event: &Event) -> Result<(), Reason> {
        if never_refused(event) {
            return Ok(());
        }
        let wall = self.clock.now().wall;
        lock(&self.libraries).hosts(space, wall).map_err(reason)
    }

    /// ext-libraries.md, 3.4 Storing, at peers.md's quota step, for an
    /// event: `adds` more bytes within the library's quota over all its
    /// spaces, held for the space until the returned reservation is
    /// dropped, so that writers of the library's other spaces count them
    /// meanwhile. Releases, restores and erasures are never refused for a
    /// library. The library's spaces' usage is known first
    /// ([`Self::know_library_usage`]).
    ///
    /// # Errors
    ///
    /// `quota_exceeded`, or `no_library`.
    pub(crate) fn library_reserve(
        &self,
        space: &EventId,
        event: &Event,
        adds: u64,
    ) -> Result<Reserved<'_>, Reason> {
        if never_refused(event) {
            return Ok(self.reserved(space, 0));
        }
        let libraries = lock(&self.libraries);
        self.reserve(&libraries, space, adds)
    }

    /// Both of ext-libraries.md's checks before a store, for an object,
    /// with its bytes held as [`Self::library_reserve`] holds an event's.
    /// The library's spaces' usage is known first.
    ///
    /// # Errors
    ///
    /// `no_library`, `library_closed` or `quota_exceeded`.
    pub(crate) fn library_admits(
        &self,
        space: &EventId,
        adds: u64,
    ) -> Result<Reserved<'_>, Reason> {
        let wall = self.clock.now().wall;
        let libraries = lock(&self.libraries);
        libraries.hosts(space, wall).map_err(reason)?;
        self.reserve(&libraries, space, adds)
    }

    /// ext-invite-links.md with ext-libraries: whether `adds` more bytes of
    /// a space's invite drops stay within its library's quota over all its
    /// spaces, the quota a drop's step 5 counts with peers.md's; with room,
    /// the bytes are held as [`Self::library_reserve`] holds an event's.
    pub(crate) fn library_room(&self, space: &EventId, adds: u64) -> Option<Reserved<'_>> {
        let libraries = lock(&self.libraries);
        self.reserve(&libraries, space, adds).ok()
    }

    /// Checks the quota and holds the bytes in one step, under the
    /// libraries' lock, which every such check takes.
    fn reserve(
        &self,
        libraries: &Libraries,
        space: &EventId,
        adds: u64,
    ) -> Result<Reserved<'_>, Reason> {
        let usage = |id: &EventId| self.used_bytes(id);
        libraries.quota(space, adds, &usage).map_err(reason)?;
        *lock(&self.index).reserved.entry(*space).or_default() += adds;
        Ok(self.reserved(space, adds))
    }

    fn reserved(&self, space: &EventId, bytes: u64) -> Reserved<'_> {
        Reserved {
            core: self,
            space: *space,
            bytes,
        }
    }

    /// The sweep: ticket IDs past their `not_after` and `ticket_skew` are
    /// forgotten, and erased spaces leave their libraries.
    pub(crate) async fn sweep_libraries(&self, now: Reading) {
        let pending = {
            let mut libraries = lock(&self.libraries);
            let mut deletes = match now.wall.or_else(crate::clock::wall_now) {
                Some(wall) => libraries.expire(wall),
                None => Vec::new(),
            };
            let gone: Vec<EventId> = libraries
                .attachments()
                .keys()
                .filter(|space| self.tombstoned(space))
                .copied()
                .collect();
            deletes.extend(libraries.drop_spaces(&gone));
            (!deletes.is_empty()).then(|| self.submit_libraries(Vec::new(), deletes))
        };
        if let Some(pending) = pending {
            let _ = self.finish_libraries(pending).await;
        }
    }

    /// ext-libraries.md, 3.5: deletes a space's events and objects at this
    /// peer and keeps its ID. Returns the object pieces to delete, or `None`
    /// for a space the peer does not host.
    ///
    /// # Errors
    ///
    /// If the records cannot be written.
    pub(crate) async fn delete_space(
        &self,
        space: EventId,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let writing = self.write(space).await?;
        let pieces: Vec<String> = {
            let state = writing.state();
            let Some(held) = &state.space else {
                return Ok(None);
            };
            held.objects
                .iter()
                .flat_map(|(locator, record)| {
                    record
                        .pieces
                        .iter()
                        .map(|&piece| crate::objects::piece_key(space.as_bytes(), locator, piece))
                })
                .collect()
        };
        let records = self.records.clone();
        let mut deletes = blocking(move || records.space_addresses(&space)).await?;
        let pending = {
            let mut libraries = lock(&self.libraries);
            let (record, library_deletes) = libraries.delete(&space);
            let (table, key, bytes) = record.encode();
            deletes.extend(
                library_deletes
                    .iter()
                    .map(|(table, key)| Records::library_address(*table, key)),
            );
            Box::pin(self.writer.submit(Commit::new(
                vec![(Records::library_address(table, &key), bytes)],
                deletes,
            ))) as LibraryCommit
        };
        self.finish_libraries(pending).await?;
        self.forget_space(&writing);
        lock(&self.transfers).retain(|_, transfer| transfer.space != space);
        lock(&self.uploads)
            .staging
            .retain(|(id, _), _| *id != space);
        Ok(Some(pieces))
    }
}
