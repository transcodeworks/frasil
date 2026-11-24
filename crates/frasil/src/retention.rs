//! What a device keeps of the blobs it stores (at-rest.md, "Retention").
//!
//! A blob's object on a device is kept, cached or absent. A kept object
//! stays until the application drops it. A cached one counts against the
//! device's budget of stored bytes, and the device drops whole cached
//! objects, the one read longest ago first, to stay within it. An object
//! the device stores with no `retention` record is kept, so a store
//! written before the table existed loses nothing.
//!
//! An object this device sealed is put: it stays as a kept one does while
//! no always-on peer is known to hold it, since this device may hold its
//! only copy, and becomes cached once a peer holds it and has acknowledged
//! a unit that names it. Whether a unit is durable says nothing of that: a
//! member's acknowledgement makes a unit durable in a space whose peer has
//! not been heard, and covers events alone.
//!
//! [`Engine::must_stay`] is the one place that says what the device never
//! drops by itself: Frasil's own objects, an object of a unit this device
//! signed that is not durable yet, an object a read or a fetch is using,
//! and a kept object. Eviction asks it for every candidate. A drop the
//! application asks for asks it too, and may take a kept object alone.
//! What a space's log and outbox say of it is kept from one pass to the
//! next, and only the events placed since are read.
//!
//! An object goes whole or not at all: its `retention` record and every
//! part are deleted in one commit, and the device then forgets what it
//! found out about the stored bytes, so that whatever it holds of the
//! object later is checked from the start (units.md, 3.3 Reading an
//! object).

#![cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]

use crate::at_rest::Batch;
use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::{Replica, object_id};
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_store::tables::{RETENTION_READ_STEP, Retention};
use frasil_store::{Table, TableValue};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

/// The budget of a device that names none: 256 MiB of stored bytes.
pub(crate) const DEFAULT_BLOB_CACHE: u64 = 256 << 20;

/// An object, by the space whose replica stores it and its object ID.
type Key = (EventId, [u8; 32]);

/// What the device notes of an object that has a `retention` record, or
/// would have one if its log were not kept in memory alone.
#[derive(Debug, Clone, Copy)]
struct Entry {
    retention: Retention,
    /// The stored bytes the device holds of it.
    bytes: u64,
    /// Its place among the reads since the device opened, which orders
    /// the objects read within one step of the record's last read.
    order: u64,
}

/// What the device knows of an object it put, while its record says so.
#[derive(Debug, Default)]
struct PutFacts {
    /// The units of this device that name it, once known: those written
    /// since the device opened, or all the log holds once it was read.
    units: Option<Vec<EventId>>,
    /// Whether an always-on peer was seen to hold the object whole.
    at_peer: bool,
}

/// Which stored objects are kept and which cached, with the bytes each
/// holds: built from the `retention` records when the device opens, and
/// kept as parts arrive and go.
#[derive(Debug, Default)]
pub(crate) struct Retained {
    entries: BTreeMap<Key, Entry>,
    /// The stored bytes of the cached objects.
    cached: u64,
    /// The reads counted since the device opened.
    reads: u64,
    /// What is known of the objects whose record says the device put them.
    puts: BTreeMap<Key, PutFacts>,
    /// Objects an always-on peer took before the unit that names them was
    /// written, which have no record yet.
    taken: BTreeSet<Key>,
    /// What must stay in each space, as its log and its outbox say.
    staying: BTreeMap<EventId, Staying>,
    /// How many events of logs were read to find what must stay.
    log_reads: std::sync::atomic::AtomicU64,
}

impl Retained {
    /// An object's retention, if it has a record.
    pub(crate) fn get(&self, key: &Key) -> Option<Retention> {
        self.entries.get(key).map(|entry| entry.retention)
    }

    /// Takes a record found at open, with the bytes the store holds.
    pub(crate) fn load(&mut self, space: EventId, id: [u8; 32], retention: Retention, bytes: u64) {
        self.set((space, id), retention, bytes);
    }

    fn set(&mut self, key: Key, retention: Retention, bytes: u64) {
        let puts = self.puts.remove(&key);
        self.remove(&key);
        if retention == Retention::Put {
            self.puts.insert(key, puts.unwrap_or_default());
        }
        if matches!(retention, Retention::Cached { .. }) {
            self.cached = self.cached.saturating_add(bytes);
        }
        self.reads += 1;
        self.entries.insert(
            key,
            Entry {
                retention,
                bytes,
                order: self.reads,
            },
        );
    }

    fn remove(&mut self, key: &Key) -> bool {
        self.puts.remove(key);
        let Some(entry) = self.entries.remove(key) else {
            return false;
        };
        if matches!(entry.retention, Retention::Cached { .. }) {
            self.cached = self.cached.saturating_sub(entry.bytes);
        }
        true
    }

    /// Notes the stored bytes the device now holds of an object.
    pub(crate) fn resize(&mut self, key: &Key, bytes: u64) {
        let Some(entry) = self.entries.get_mut(key) else {
            return;
        };
        if matches!(entry.retention, Retention::Cached { .. }) {
            self.cached = self
                .cached
                .saturating_sub(entry.bytes)
                .saturating_add(bytes);
        }
        entry.bytes = bytes;
    }

    /// Forgets an object the device no longer retains: the application
    /// holds its plaintext now.
    pub(crate) fn forget_object(&mut self, space: &EventId, id: &[u8; 32]) {
        self.remove(&(*space, *id));
    }

    /// Forgets a space the device no longer holds.
    pub(crate) fn forget_space(&mut self, space: &EventId) {
        let keys: Vec<Key> = self
            .entries
            .range((*space, [0; 32])..)
            .take_while(|((of, _), _)| of == space)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.remove(&key);
        }
        self.staying.remove(space);
    }

    /// How many events of logs were read to find what must stay.
    #[cfg(test)]
    pub(crate) fn log_reads(&self) -> u64 {
        self.log_reads.load(Ordering::Relaxed)
    }

    /// The cached objects, the one read longest ago first.
    fn oldest_first(&self) -> Vec<Key> {
        let mut cached: Vec<(u64, u64, Key)> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| match entry.retention {
                Retention::Cached { read } => Some((read, entry.order, *key)),
                Retention::Kept | Retention::Put => None,
            })
            .collect();
        cached.sort_unstable();
        cached.into_iter().map(|(_, _, key)| key).collect()
    }
}

/// The objects that reads are using, by how many use each.
#[derive(Debug, Default)]
pub(crate) struct Uses(Mutex<BTreeMap<Key, usize>>);

impl Uses {
    fn count(&self) -> std::sync::MutexGuard<'_, BTreeMap<Key, usize>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A use of an object: the device drops nothing of the object while one is
/// held.
#[derive(Debug)]
pub(crate) struct InUse {
    uses: Arc<Uses>,
    key: Key,
}

impl Drop for InUse {
    fn drop(&mut self) {
        let mut count = self.uses.count();
        if let Some(uses) = count.get_mut(&self.key) {
            *uses -= 1;
            if *uses == 0 {
                count.remove(&self.key);
            }
        }
    }
}

/// Why an object stays ([`Engine::must_stay`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stays {
    /// It is Frasil's own: the device reads it back from its store.
    Own,
    /// A unit this device signed names it, and is not durable yet.
    Pending,
    /// A read or a fetch is using it.
    InUse,
    /// It is kept: by its record, or for want of one; or this device put
    /// it and no always-on peer is known to hold it.
    Kept,
}

/// How a blob's object stands on a device ([`Engine::retention_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlobState {
    /// The device keeps it until the application drops it. A kept blob
    /// that is not whole here yet is fetched by the device itself. A blob
    /// this device put is kept until an always-on peer holds its bytes and
    /// has acknowledged the change that put it, and cached from then on.
    Kept,
    /// The device holds it within its cache's budget, and may drop it.
    Cached,
    /// The device holds nothing of it. A read fetches it.
    Absent,
}

/// What a device's blobs take, from
/// [`Device::blob_cache_usage`](crate::Device::blob_cache_usage), in stored
/// bytes: a blob's sealed chunks and its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobCacheUsage {
    /// The budget of the cache, as the device was opened with.
    pub budget: u64,
    /// The bytes of the cached blobs, whole or in part: within the budget
    /// but for a blob larger than it while a read holds it.
    pub cached: u64,
    /// The bytes of the blobs the device keeps, outside the budget.
    pub kept: u64,
}

/// Calls `found` with each of Frasil's own objects that a replica names
/// outside its log, until it answers `true`: the space snapshot a newcomer
/// awaits and the one it adopted and stores, the stream snapshot objects
/// not yet loaded, and the record objects of the checkpoints it opened
/// (roster.md, "The record object"). Whether one answered `true`.
fn any_own_beside_log(replica: &Replica, mut found: impl FnMut(&Locator) -> bool) -> bool {
    replica.awaited_snapshot().is_some_and(&mut found)
        || replica.adopted_snapshot().is_some_and(&mut found)
        || replica.pending_stream_objects().any(&mut found)
        || replica
            .checkpoint_facts()
            .parts
            .values()
            .any(|part| found(&part.locator))
}

/// The objects an event of a log makes Frasil's own: those that a snapshot
/// unit or a unit of the system stream names (units.md, "Frasil's own
/// units").
fn own_of_event(
    event: &frasil_events::Event,
    system: Option<&frasil_units::StreamId>,
) -> Vec<Locator> {
    if event.kind() != frasil_events::kind::UNIT {
        return Vec::new();
    }
    match frasil_units::Unit::from_event(event.clone()) {
        Ok(unit) if unit.body.compacts.is_some() || Some(&unit.body.stream) == system => {
            unit.body.objects.to_vec()
        }
        _ => Vec::new(),
    }
}

/// Whether an object is Frasil's own, by its ID: read by Frasil and never
/// by the application, stored sealed under every policy, and never
/// dropped. It reads the whole log: eviction asks [`Engine::must_stay`],
/// which keeps what the log says.
pub(crate) fn frasils_own(replica: &Replica, id: &[u8; 32]) -> bool {
    if any_own_beside_log(replica, |locator| locator[..32] == id[..]) {
        return true;
    }
    let system = replica.system_stream();
    replica.log().is_some_and(|log| {
        log.events().any(|event| {
            own_of_event(event, system.as_ref())
                .iter()
                .any(|locator| locator[..32] == id[..])
        })
    })
}

/// What must stay in a space besides what its records keep, as its log and
/// its outbox say: kept from one eviction pass to the next, and brought up
/// to date before each from what changed ([`Retained::refresh`]).
#[derive(Debug, Default)]
struct Staying {
    /// How many events the log had placed when it was last read, the last
    /// of them, the log's revision then, and the system stream.
    placed: usize,
    last: Option<EventId>,
    revision: u64,
    system: Option<frasil_units::StreamId>,
    /// The objects the log's units make Frasil's own.
    own: BTreeSet<[u8; 32]>,
    /// The events this device signed that are not durable yet, and the
    /// objects their units name.
    outbox: Vec<EventId>,
    pending: BTreeSet<[u8; 32]>,
}

impl Retained {
    /// Brings what must stay in a space up to date. The log is read whole
    /// the first time, and when it changed other than by placing events,
    /// or lost some: otherwise only the events placed since are read. The
    /// units of the outbox are read again when the outbox changed. An
    /// object once found stays in the set until the log is read whole
    /// again, so that a doubt keeps an object.
    fn refresh(
        &mut self,
        space: &EventId,
        replica: Option<&Replica>,
        outbox: Option<&crate::outbox::Outbox>,
    ) {
        let Some(log) = replica.and_then(Replica::log) else {
            self.staying.remove(space);
            return;
        };
        let staying = self.staying.entry(*space).or_default();
        let system = replica.and_then(Replica::system_stream);
        let placed = log.placed_since(0);
        let grown = staying.revision == log.revision()
            && staying.system == system
            && staying.placed <= placed.len()
            && staying
                .placed
                .checked_sub(1)
                .map_or(staying.last.is_none(), |at| {
                    placed.get(at) == staying.last.as_ref()
                });
        if !grown {
            staying.own.clear();
            staying.placed = 0;
        }
        let new = &placed[staying.placed..];
        self.log_reads
            .fetch_add(new.len() as u64, Ordering::Relaxed);
        for id in new {
            if let Some(event) = log.event(*id) {
                staying
                    .own
                    .extend(own_of_event(event, system.as_ref()).iter().map(object_id));
            }
        }
        staying.placed = placed.len();
        staying.last = placed.last().copied();
        staying.revision = log.revision();
        staying.system = system;
        // An event leaves the outbox when it becomes durable (units.md,
        // 3.13 "Durable").
        let outbox: Vec<EventId> = outbox
            .into_iter()
            .flat_map(crate::outbox::Outbox::pending)
            .map(|(_, id)| *id)
            .collect();
        if !grown || outbox != staying.outbox {
            staying.pending = outbox
                .iter()
                .filter_map(|id| log.event(*id))
                .filter(|event| event.kind() == frasil_events::kind::UNIT)
                .filter_map(|event| frasil_units::Unit::from_event(event.clone()).ok())
                .flat_map(|unit| unit.body.objects.to_vec())
                .map(|locator| object_id(&locator))
                .collect();
            staying.outbox = outbox;
        }
    }
}

#[cfg(all(test, feature = "adapter-blobs", feature = "adapter-loro"))]
mod tests;

impl Engine {
    /// Sets the budget of the blob cache, in stored bytes: what the device
    /// holds of the blobs it fetched to read, across all its spaces. Zero
    /// means that a read stores nothing once it ends.
    pub fn set_blob_cache(&self, bytes: u64) {
        self.blob_cache_cell().store(bytes, Ordering::SeqCst);
    }

    /// The budget of the blob cache, in stored bytes.
    pub fn blob_cache(&self) -> u64 {
        self.blob_cache_cell().load(Ordering::SeqCst)
    }

    /// Fetches every blob the device's spaces name, and keeps each: a full
    /// copy for use with no connection. Nothing is evicted meanwhile.
    pub fn keep_all_blobs(&self) {
        self.keep_all_blobs_cell().store(true, Ordering::SeqCst);
    }

    /// Whether the device fetches and keeps every blob.
    pub(crate) fn keeps_all_blobs(&self) -> bool {
        self.keep_all_blobs_cell().load(Ordering::SeqCst)
    }

    /// Uses an object: nothing of it is dropped until the use is dropped.
    /// A reader takes it before it looks whether the device holds the
    /// object, so that what it found stays.
    pub(crate) fn use_object(&self, space: EventId, locator: &Locator) -> InUse {
        let key = (space, object_id(locator));
        *self.uses().count().entry(key).or_insert(0) += 1;
        InUse {
            uses: self.uses().clone(),
            key,
        }
    }

    /// Whether a read uses an object, or a request for its chunks is
    /// still wanted ([`Engine::fetch_chunks`]).
    fn in_use(&self, space: &EventId, id: &[u8; 32]) -> bool {
        self.uses().count().contains_key(&(*space, *id))
            || self
                .fetches()
                .of(space)
                .iter()
                .any(|request| request.locator[..32] == id[..])
    }

    /// Why the device does not drop an object by itself, if it does not
    /// (at-rest.md, "Retention", what is never dropped): it is Frasil's
    /// own; a unit this device signed names it and is not durable yet; a
    /// read or a fetch is using it; or it is kept, by a record of state 1
    /// or 3 or for want of any record. `None` for a cached object none of
    /// these holds for, which is the only kind eviction takes.
    pub(crate) fn must_stay(
        &self,
        state: &mut State,
        space: &EventId,
        locator: &Locator,
    ) -> Option<Stays> {
        Self::refresh_staying(state, space);
        self.stays(state, space, &object_id(locator))
    }

    /// Brings what must stay in a space up to date with its log and its
    /// outbox: once before any number of [`stays`](Self::stays).
    fn refresh_staying(state: &mut State, space: &EventId) {
        state
            .retained
            .refresh(space, state.replicas.get(space), state.outboxes.get(space));
    }

    /// [`must_stay`](Self::must_stay), by what the space's log and outbox
    /// said when [`refresh_staying`](Self::refresh_staying) last read
    /// them. A space never read keeps everything.
    fn stays(&self, state: &State, space: &EventId, id: &[u8; 32]) -> Option<Stays> {
        let Some(staying) = state.retained.staying.get(space) else {
            return Some(Stays::Own);
        };
        let beside = state
            .replicas
            .get(space)
            .is_some_and(|replica| any_own_beside_log(replica, |locator| locator[..32] == id[..]));
        if beside || staying.own.contains(id) {
            return Some(Stays::Own);
        }
        if staying.pending.contains(id) {
            return Some(Stays::Pending);
        }
        if self.in_use(space, id) {
            return Some(Stays::InUse);
        }
        match state.retained.get(&(*space, *id)) {
            Some(Retention::Cached { .. }) if !self.keeps_all_blobs() => None,
            _ => Some(Stays::Kept),
        }
    }

    /// Whether a space has an always-on peer, as far as this device knows:
    /// one acknowledged its events since the device opened, one grants it
    /// the space on a connection now, or the device keeps a peer of the
    /// space at rest. It decides only whether the application may drop an
    /// object no peer holds yet, never whether the device may.
    async fn has_peer(&self, state: &mut State, space: &EventId) -> bool {
        if state.peered.contains(space) {
            return true;
        }
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        if self
            .syncing()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(of, _)| of == space)
        {
            return true;
        }
        // The `peers` record: the space's peers and its library's home
        // peer (at-rest.md, "Tables").
        matches!(
            state.vault.get(&space.0, Table::Peers, &[]).await,
            Ok(Some(TableValue::Peers(peers))) if !peers.hints.is_empty() || peers.home.is_some()
        )
    }

    /// Whether the device means to hold an object that another party
    /// sends parts of, so that a part is stored: it has a record; the
    /// device holds chunks of it, which with no record are kept; the
    /// device keeps every blob, or the application holds the space's
    /// objects; a request for its chunks is still wanted, or the
    /// application asked for it; or it is not an object the device fetches
    /// only when it is read, so that the device fetches it by itself, as
    /// it does Frasil's own. An object the device dropped, or meant to
    /// fetch for a read that gave up, is none of these.
    pub(crate) fn means_to_hold(&self, state: &State, space: &EventId, locator: &Locator) -> bool {
        let id = object_id(locator);
        if self.keeps_all_blobs()
            || self.is_held_space(state, space)
            || state.retained.get(&(*space, id)).is_some()
        {
            return true;
        }
        let Some(replica) = state.replicas.get(space) else {
            return true;
        };
        let holds = replica
            .object_locators(&id)
            .iter()
            .any(|locator| replica.holds_chunks(locator));
        if holds
            || state.held.asked_for(space, locator)
            || self
                .fetches()
                .of(space)
                .iter()
                .any(|request| request.locator[..32] == id[..])
        {
            return true;
        }
        !crate::objects::fetched_on_read(replica, locator)
    }

    /// Whether the space's objects have no retention on this device: the
    /// application holds them as files (at-rest.md, "Held objects").
    fn is_held_space(&self, state: &State, space: &EventId) -> bool {
        self.provider_of(state, space).is_some()
    }

    /// The last read to record for a read made now: the timeline's `T`,
    /// rounded down.
    fn read_now(&self, state: &mut State) -> u64 {
        let now = self.timeline_now(state);
        now - now % RETENTION_READ_STEP
    }

    /// Puts an object's retention in the state and, for a log the store
    /// keeps, in a record committed at once.
    async fn record(
        &self,
        state: &mut State,
        space: EventId,
        id: [u8; 32],
        retention: Retention,
    ) -> Result<()> {
        let mut batch = Batch::default();
        if state.vault.has_log(&space.0) {
            state.vault.put(
                &mut batch,
                &space.0,
                Table::Retention,
                &id,
                &TableValue::Retention(retention),
            )?;
        }
        state.vault.commit(batch).await?;
        let bytes = state
            .replicas
            .get(&space)
            .map_or(0, |replica| replica.object_bytes_stored(&id));
        state.retained.set((space, id), retention, bytes);
        Ok(())
    }

    /// Says how the device retains a blob's object it is about to fetch,
    /// before the first part arrives (at-rest.md, "Retention", recording):
    /// kept with `keep`, cached otherwise. An object the device holds
    /// parts of with no record is kept already and stays so; a cached one
    /// becomes kept with `keep`, and a kept one never becomes cached. In a
    /// space whose objects the application holds, nothing is recorded.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] to keep an object of
    /// a space kept in memory alone (ext-guests.md, "Nothing at rest");
    /// the store's.
    pub(crate) async fn retain(&self, space: EventId, locator: &Locator, keep: bool) -> Result<()> {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        if keep && state.vault.is_memory_only(&space.0) {
            return Err(Error::NotAllowed(
                "the space's grant asked for nothing at rest",
            ));
        }
        if self.is_held_space(&state, &space) {
            return Ok(());
        }
        let id = object_id(locator);
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let holds = replica.knows_object_id(&id);
        let retention = match (state.retained.get(&(space, id)), keep) {
            (Some(Retention::Kept), _)
            | (Some(Retention::Cached { .. } | Retention::Put), false) => return Ok(()),
            (_, true) => Retention::Kept,
            // Parts with no record: kept.
            (None, false) if holds || self.keeps_all_blobs() => return Ok(()),
            (None, false) => Retention::Cached {
                read: self.read_now(&mut state),
            },
        };
        self.record(&mut state, space, id, retention).await
    }

    /// Records that this device put an object, which `unit`, just written
    /// here, names: it stays until an always-on peer holds it (at-rest.md,
    /// "Retention", what is never dropped), whatever makes the unit
    /// durable. An object that has a record of another state keeps it.
    pub(crate) async fn retain_put(
        &self,
        state: &mut State,
        space: EventId,
        locator: &Locator,
        unit: EventId,
    ) -> Result<()> {
        let key = (space, object_id(locator));
        // Whether a peer took it before its unit was written.
        let taken = state.retained.taken.remove(&key);
        if self.is_held_space(state, &space) {
            return Ok(());
        }
        let first = match state.retained.get(&key) {
            Some(Retention::Put) => false,
            Some(_) => return Ok(()),
            None => {
                let stored = state.replicas.get(&space).is_some_and(|replica| {
                    replica.holds_chunks(locator) && !replica.is_held(locator)
                });
                if !stored {
                    return Ok(());
                }
                self.record(state, space, key.1, Retention::Put).await?;
                true
            }
        };
        let facts = state.retained.puts.entry(key).or_default();
        facts.at_peer |= taken;
        if first {
            facts.units = Some(vec![unit]);
        } else if let Some(units) = &mut facts.units {
            // The units of an earlier run are looked for when needed.
            units.push(unit);
        }
        Ok(())
    }

    /// Notes that the always-on peer `by` holds an object whole, by its
    /// own answer to an upload: an object this device put becomes cached
    /// once that peer has also acknowledged a unit that names it.
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn object_at_peer(
        &self,
        space: EventId,
        by: crate::outbox::Acknowledger,
        locator: &Locator,
    ) -> Result<()> {
        let mut state = self.lock().await;
        let key = (space, object_id(locator));
        match state.retained.get(&key) {
            Some(Retention::Put) => {
                state.retained.puts.entry(key).or_default().at_peer = true;
            }
            // Taken before its unit is written, by a put that holds it.
            None if self.in_use(&space, &key.1) => {
                state.retained.taken.insert(key);
                return Ok(());
            }
            _ => return Ok(()),
        }
        let heads = state
            .outboxes
            .get(&space)
            .and_then(|outbox| outbox.acknowledged(&by))
            .map(<[EventId]>::to_vec)
            .unwrap_or_default();
        self.settle_puts(&mut state, space, &heads).await
    }

    /// Makes cached each object of a space that this device put, that an
    /// always-on peer was seen to hold, and that a unit in the past of
    /// `heads` names, which a peer acknowledged: the peer holds the bytes
    /// and a unit that refers to them, so the device no longer holds the
    /// only copy.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn settle_puts(
        &self,
        state: &mut State,
        space: EventId,
        heads: &[EventId],
    ) -> Result<()> {
        let waiting: Vec<[u8; 32]> = state
            .retained
            .puts
            .range((space, [0; 32])..)
            .take_while(|((of, _), _)| *of == space)
            .filter(|(_, facts)| facts.at_peer)
            .map(|((_, id), _)| *id)
            .collect();
        if waiting.is_empty() {
            return Ok(());
        }
        let Some(log) = state.replicas.get(&space).and_then(Replica::log) else {
            return Ok(());
        };
        let covered = crate::outbox::past_of(log, heads);
        // The units that name an object put in an earlier run.
        let unknown: BTreeSet<[u8; 32]> = waiting
            .iter()
            .filter(|id| {
                state
                    .retained
                    .puts
                    .get(&(space, **id))
                    .is_some_and(|facts| facts.units.is_none())
            })
            .copied()
            .collect();
        let mut found: BTreeMap<[u8; 32], Vec<EventId>> = BTreeMap::new();
        if !unknown.is_empty() {
            for event in log.events() {
                if event.kind() != frasil_events::kind::UNIT {
                    continue;
                }
                let Ok(unit) = frasil_units::Unit::from_event(event.clone()) else {
                    continue;
                };
                for locator in unit.body.objects.iter() {
                    let id = object_id(locator);
                    if unknown.contains(&id) {
                        found.entry(id).or_default().push(event.id());
                    }
                }
            }
        }
        let mut settled = Vec::new();
        for id in waiting {
            let Some(facts) = state.retained.puts.get_mut(&(space, id)) else {
                continue;
            };
            let units = facts
                .units
                .get_or_insert_with(|| found.remove(&id).unwrap_or_default());
            if units.iter().any(|unit| covered.contains(unit)) {
                settled.push(id);
            }
        }
        for id in settled {
            let read = self.read_now(state);
            self.record(state, space, id, Retention::Cached { read })
                .await?;
        }
        Ok(())
    }

    /// Notes that a cached object was read: it is the last the device
    /// drops. Its record is put again when its last read, rounded down,
    /// changed.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn touch(&self, space: EventId, locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        let id = object_id(locator);
        let Some(Retention::Cached { read }) = state.retained.get(&(space, id)) else {
            return Ok(());
        };
        let now = self.read_now(&mut state);
        if now == read {
            // Its place among the reads alone.
            let bytes = state
                .retained
                .entries
                .get(&(space, id))
                .map_or(0, |entry| entry.bytes);
            state
                .retained
                .set((space, id), Retention::Cached { read }, bytes);
            return Ok(());
        }
        self.record(&mut state, space, id, Retention::Cached { read: now })
            .await
    }

    /// Notes the stored bytes the device now holds of objects, after parts
    /// of them were kept.
    pub(crate) fn resize_retained(state: &mut State, space: EventId, locators: &[Locator]) {
        let Some(replica) = state.replicas.get(&space) else {
            return;
        };
        for locator in locators {
            let id = object_id(locator);
            if state.retained.get(&(space, id)).is_some() {
                let bytes = replica.object_bytes_stored(&id);
                state.retained.resize(&(space, id), bytes);
            }
        }
    }

    /// Forgets what the device holds of an object, under every locator it
    /// knows it by, and deletes its parts' records, the header with the
    /// chunks, in one commit; with `record`, its `retention` record too,
    /// so that the device no longer means to hold it. What the device
    /// found out about the stored bytes goes with them. Whether it held
    /// anything of it, or a record.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_stored(
        &self,
        state: &mut State,
        space: EventId,
        id: &[u8; 32],
        record: bool,
    ) -> Result<bool> {
        let Some(replica) = state.replicas.get_mut(&space) else {
            return Ok(false);
        };
        let locators = replica.object_locators(id);
        let whole: Vec<Locator> = locators
            .iter()
            .filter(|locator| replica.holds_object(locator))
            .copied()
            .collect();
        let mut stored = None;
        for locator in &locators {
            if let Some(indices) = replica.forget_object(locator) {
                stored.get_or_insert_with(BTreeSet::new).extend(indices);
            }
        }
        let recorded = state.retained.get(&(space, *id)).is_some();
        if stored.is_none() && !(record && recorded) {
            return Ok(false);
        }
        let mut by_id = [0; 64];
        by_id[..32].copy_from_slice(id);
        let mut batch = Batch::default();
        if let Some(stored) = &stored {
            crate::objects::delete_object_records(&state.vault, &mut batch, &space, &by_id, stored);
        }
        if record {
            state
                .vault
                .delete(&mut batch, &space.0, Table::Retention, id);
        }
        state.vault.commit(batch).await?;
        if record {
            state.retained.remove(&(space, *id));
        } else {
            state.retained.resize(&(space, *id), 0);
        }
        self.forget_checks(&space, id);
        for locator in whole {
            self.dropped(space, locator);
        }
        Ok(true)
    }

    /// Drops cached objects, the one read longest ago first, until the
    /// cached bytes and `incoming` more fit the budget, or nothing more
    /// may go (at-rest.md, "Retention", when): never an object that
    /// [`must_stay`](Self::must_stay), nor one of `writing`, the objects
    /// the incoming bytes are parts of.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn evict_in(
        &self,
        state: &mut State,
        incoming: u64,
        writing: &BTreeSet<[u8; 32]>,
    ) -> Result<()> {
        let budget = self.blob_cache();
        let over = |state: &State| state.retained.cached.saturating_add(incoming) > budget;
        if self.keeps_all_blobs() || !over(state) {
            return Ok(());
        }
        // What must stay is brought up to date once for each space in a
        // pass; a drop changes neither a log nor an outbox.
        let mut read: BTreeSet<EventId> = BTreeSet::new();
        for (space, id) in state.retained.oldest_first() {
            if !over(state) {
                break;
            }
            if writing.contains(&id) {
                continue;
            }
            if read.insert(space) {
                Self::refresh_staying(state, &space);
            }
            if self.stays(state, &space, &id).is_some() {
                continue;
            }
            self.drop_stored(state, space, &id, true).await?;
        }
        Ok(())
    }

    /// [`evict_in`](Self::evict_in) with nothing more to come: at upkeep,
    /// and once a read ends.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn evict(&self) -> Result<()> {
        let mut state = self.lock().await;
        self.evict_in(&mut state, 0, &BTreeSet::new()).await
    }

    /// Drops what this device holds of a blob's object, kept or cached, so
    /// that it is absent: the device no longer means to hold it, and
    /// fetches it when it is read. Dropping an object the device holds
    /// nothing of changes nothing. A blob the application holds as a file
    /// is released ([`Engine::release_held`]).
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] while the object must stay: it is Frasil's
    /// own, a read or a fetch is using it, this device put it in a space
    /// with an always-on peer and no peer is known to hold it yet, or the
    /// device keeps every blob ([`Engine::keep_all_blobs`]) and would
    /// fetch it again at once; the store's and the provider's.
    pub async fn drop_local_object(&self, space: EventId, locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.is_held(locator) {
            drop(state);
            return self.release_held(&space, locator).await;
        }
        if self.keeps_all_blobs() {
            return Err(Error::NotAllowed(
                "this device keeps every blob, and would fetch it again",
            ));
        }
        match self.must_stay(&mut state, &space, locator) {
            Some(Stays::Own) => {
                return Err(Error::NotAllowed(
                    "the object is Frasil's own, and the device cannot run without it",
                ));
            }
            Some(Stays::InUse) => {
                return Err(Error::NotAllowed("a read or a fetch is using the blob"));
            }
            // With no always-on peer the unit may never be durable, and
            // the application decides.
            Some(Stays::Pending) => {
                if self.has_peer(&mut state, &space).await {
                    return Err(Error::NotAllowed(
                        "this device put the blob, and no peer holds it yet",
                    ));
                }
            }
            Some(Stays::Kept) | None => {}
        }
        // An object this device put that no peer is known to hold: the
        // peer of the space is about to take it. With no always-on peer
        // no party is bound to, and the application decides.
        if state.retained.get(&(space, object_id(locator))) == Some(Retention::Put)
            && self.has_peer(&mut state, &space).await
        {
            return Err(Error::NotAllowed(
                "this device put the blob, and no peer holds it yet",
            ));
        }
        self.drop_stored(&mut state, space, &object_id(locator), true)
            .await
            .map(drop)
    }

    /// Drops an object that a read fetched to store nowhere, if it is
    /// cached and nothing else uses it.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_if_cached(&self, space: EventId, locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        if self.must_stay(&mut state, &space, locator).is_some() {
            return Ok(());
        }
        self.drop_stored(&mut state, space, &object_id(locator), true)
            .await
            .map(drop)
    }

    /// Drops the record of a cached object a read meant to fetch and got
    /// nothing of.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_unfetched(&self, space: EventId, locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        let id = object_id(locator);
        let empty = state
            .replicas
            .get(&space)
            .is_none_or(|replica| replica.object_bytes_stored(&id) == 0);
        if !empty || self.must_stay(&mut state, &space, locator).is_some() {
            return Ok(());
        }
        self.drop_stored(&mut state, space, &id, true)
            .await
            .map(drop)
    }

    /// How a blob's object stands in a space on this device, and the
    /// stored bytes the device holds of it: for an object the application
    /// holds as a file, kept, with its stored length.
    pub(crate) async fn retention_of(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> (BlobState, u64) {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let Some(replica) = state.replicas.get(space) else {
            return (BlobState::Absent, 0);
        };
        if replica.is_held(locator) {
            let bytes = replica
                .object_bytes_held(locator)
                .map_or(0, |(held, _)| held);
            return (BlobState::Kept, bytes);
        }
        let id = object_id(locator);
        let bytes = replica.object_bytes_stored(&id);
        let holds = replica
            .object_locators(&id)
            .iter()
            .any(|locator| replica.holds_chunks(locator));
        match state.retained.get(&(*space, id)) {
            Some(Retention::Cached { .. }) if !self.keeps_all_blobs() => {
                if holds {
                    (BlobState::Cached, bytes)
                } else {
                    (BlobState::Absent, 0)
                }
            }
            Some(_) => (BlobState::Kept, if holds { bytes } else { 0 }),
            None if holds => (BlobState::Kept, bytes),
            None => (BlobState::Absent, 0),
        }
    }

    /// Whether the device means to hold an object of a blob stream whole
    /// without being asked again: it has a record of state 1 or 3, or the
    /// device holds chunks of it with no record, which are kept. Such an
    /// object is fetched by the device itself while it is not whole.
    pub(crate) fn keeps_object(state: &State, space: &EventId, locator: &Locator) -> bool {
        match state.retained.get(&(*space, object_id(locator))) {
            Some(Retention::Kept | Retention::Put) => true,
            Some(Retention::Cached { .. }) => false,
            None => state
                .replicas
                .get(space)
                .is_some_and(|replica| replica.holds_chunks(locator)),
        }
    }

    /// The budget of the blob cache, and the stored bytes of the blobs the
    /// device caches and keeps. Frasil's own objects count in neither, nor
    /// do blobs the application holds as files.
    pub async fn blob_cache_usage(&self) -> BlobCacheUsage {
        let mut state = self.lock().await;
        let spaces: Vec<EventId> = state.replicas.keys().copied().collect();
        let mut kept = 0u64;
        for space in &spaces {
            // Only what the space's log gained since it was last read.
            Self::refresh_staying(&mut state, space);
            let Some(replica) = state.replicas.get(space) else {
                continue;
            };
            for (id, bytes) in replica.stored_object_bytes() {
                let cached = matches!(
                    state.retained.get(&(*space, id)),
                    Some(Retention::Cached { .. })
                ) && !self.keeps_all_blobs();
                if !cached && self.stays(&state, space, &id) != Some(Stays::Own) {
                    kept = kept.saturating_add(bytes);
                }
            }
        }
        BlobCacheUsage {
            budget: self.blob_cache(),
            cached: if self.keeps_all_blobs() {
                0
            } else {
                state.retained.cached
            },
            kept,
        }
    }
}
