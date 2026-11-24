//! Reading an object the device does not hold whole (units.md, 3.3 Reading
//! an object; adapter-blobs.md, 3.5 Fetching).
//!
//! A reader that fetches by chunk uses a chunk once the steps that need
//! the header alone have passed (1 to 3, and 5) and that chunk's own have
//! (4 and 6): [`PartReader`] runs them, and hands out no plaintext before.
//! The steps that need the whole object, 0 and 7, run once the reader has
//! read every chunk. A [`PartReader`] that opens every chunk in order from
//! the first runs them as the bytes pass, hashing the stored bytes and the
//! plaintext, before it gives the last chunk; one that does not cannot,
//! and its object's whole-object steps run when the device holds the
//! object whole ([`Engine::verify_whole`]). Until then what was read may
//! later be refused (adapter-blobs.md, 4 Security considerations, "What a
//! reader shows before the whole-object checks").
//!
//! Each open reader has a [`Window`] on its object: the chunks it asks the
//! space's connections for, a request for each, and, for a reader that is
//! to store nothing, the sealed chunks that arrived for it, held in memory
//! and bounded by the reader. A chunk the device does not mean to store
//! is offered to the windows that asked for it and to nothing else, so no
//! party makes a window hold a chunk it did not ask for, nor more chunks
//! than its reader allows. The readers of an object hear when the device
//! keeps a part of it, and when a check of it fails
//! ([`Readers::refuse`]).
//!
//! A part that does not check as it arrives is its sender's fault while
//! nothing the device holds is in doubt: it is not kept, and another party
//! is asked ([`Engine::receive_part`]). The windows of an object say what
//! that takes: whether a chunk has opened under the header its readers
//! read by, and whether one has in a reader, whose bytes may then have
//! been given. Readers fail with what the device drops of an object only
//! in the second case; where no reader was given anything, they start
//! over under the header that arrives next. The reader of a reference
//! leaves the object's key with its window while it is open, so that the
//! chunks of a reference are opened as they arrive too.

#![cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::fetch::{Fetch, FetchEnd, FetchPriority};
use crate::replica::object_id;
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_units::objects::{ChunkReader, Header, ObjectKeys, Opening, check_chunk, chunk_count};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::watch;

/// An object, by the space a reader fetches it in and its object ID.
type Key = (EventId, [u8; 32]);

/// How many chunks an object's plaintext is cut into.
fn count_of(size: u64) -> u64 {
    chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64)
}

/// The open readers of the device's objects, and what was found out about
/// objects that failed their checks.
#[derive(Debug, Default)]
pub(crate) struct Readers {
    objects: Mutex<BTreeMap<Key, Arc<Watched>>>,
    /// The objects found not to be what their locators name, once their
    /// stored bytes hashed to the locator (units.md, 3.3, a fault at steps
    /// 1 to 7 that stands): by the space that opens them, with the class.
    /// The locator binds the bytes, so no fetch gives others.
    refused: Mutex<BTreeMap<(EventId, Locator), &'static str>>,
}

/// What the open readers of one object share.
#[derive(Debug)]
struct Watched {
    /// Counts what changed: a part kept, a chunk taken by a window, a
    /// refusal.
    changed: watch::Sender<u64>,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Counts the windows opened.
    next: u64,
    windows: BTreeMap<u64, Held>,
    /// The header that arrived with a chunk a window took, for an object
    /// the device stores nothing of.
    header: Option<Vec<u8>>,
    /// Whether a chunk has opened under the header the object's readers
    /// read by, the one above or the store's, as it arrived or in a
    /// reader: a holder of the object's key sealed a chunk under it.
    proved: bool,
    /// Whether a chunk has opened under that header in a reader, which
    /// may have given its bytes.
    given: bool,
    /// Counts the times what was held under a header nothing had opened
    /// under was let go: a reader that built on that header starts over.
    epoch: u64,
    /// Why the object was refused while it had readers, and whether a
    /// reader has reported it.
    refusal: Option<(&'static str, bool)>,
    /// Whether a reader is running the whole-object steps on the stored
    /// object.
    verifying: bool,
}

/// What the reader of a reference opens its object with: the reference's
/// source, which is the space in each chunk's associated data, and the
/// object's key (adapter-blobs.md, 3.5 Fetching). Formatted, it shows no
/// key.
#[derive(Clone)]
pub(crate) struct ObjectOpening {
    pub source: EventId,
    pub key: frasil_keys::derive::Secret,
}

impl core::fmt::Debug for ObjectOpening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectOpening")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// What one window holds.
#[derive(Debug, Default)]
struct Held {
    /// For a reference, what its reader opens the object with: what opens
    /// a chunk as it arrives where the space holds no key of the state
    /// the object's header names.
    opening: Option<ObjectOpening>,
    /// Whether chunks the device does not store are taken into memory.
    passing: bool,
    /// The most chunks it holds in memory.
    limit: usize,
    /// The chunks asked for and not arrived, each with its request and
    /// the priority it was asked at: one request for a run of chunks,
    /// which ends once none of them is wanted any more.
    wanted: BTreeMap<u64, (Arc<Fetch>, FetchPriority)>,
    /// The sealed chunks that arrived, of an object the device does not
    /// store.
    chunks: BTreeMap<u64, Arc<Vec<u8>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Watched {
    fn bump(&self) {
        self.changed
            .send_modify(|count| *count = count.wrapping_add(1));
    }
}

impl Readers {
    fn watched(&self, key: &Key) -> Option<Arc<Watched>> {
        lock(&self.objects).get(key).cloned()
    }

    /// Whether a reader that stores nothing has a window on the object.
    fn passing(&self, key: &Key) -> bool {
        self.watched(key).is_some_and(|watched| {
            lock(&watched.inner)
                .windows
                .values()
                .any(|held| held.passing)
        })
    }

    /// Whether a window that stores nothing still waits for this chunk.
    pub(crate) fn needs(&self, key: &Key, index: u64) -> bool {
        self.watched(key).is_some_and(|watched| {
            lock(&watched.inner)
                .windows
                .values()
                .any(|held| held.passing && held.wanted.contains_key(&index))
        })
    }

    /// The first chunk among `chunks` that a window that stores nothing
    /// still waits for.
    fn first_needed(&self, key: &Key, chunks: Range<u64>) -> Option<u64> {
        let watched = self.watched(key)?;
        let inner = lock(&watched.inner);
        inner
            .windows
            .values()
            .filter(|held| held.passing)
            .filter_map(|held| {
                held.wanted
                    .range(chunks.clone())
                    .next()
                    .map(|(index, _)| *index)
            })
            .min()
    }

    /// The header the windows of an object hold, of an object the device
    /// stores nothing of.
    pub(crate) fn header(&self, key: &Key) -> Option<Vec<u8>> {
        self.watched(key)
            .and_then(|watched| lock(&watched.inner).header.clone())
    }

    /// Whether a chunk has opened under the header the readers of an
    /// object read by, as it arrived or in a reader.
    pub(crate) fn proved(&self, key: &Key) -> bool {
        self.watched(key)
            .is_some_and(|watched| lock(&watched.inner).proved)
    }

    /// Notes that a chunk the device kept of an object opened as it
    /// arrived, under the header its readers read by.
    pub(crate) fn prove(&self, key: &Key) {
        if let Some(watched) = self.watched(key) {
            lock(&watched.inner).proved = true;
        }
    }

    /// What the open readers of a reference hold to open its object, of
    /// each.
    pub(crate) fn openings(&self, key: &Key) -> Vec<ObjectOpening> {
        self.watched(key)
            .map(|watched| {
                lock(&watched.inner)
                    .windows
                    .values()
                    .filter_map(|held| held.opening.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Offers a chunk the device does not store to the windows that asked
    /// for it: whether one took it. The caller has checked the part
    /// against the header it carries or the one held
    /// ([`Engine::receive_part`]); `opened` says its chunk opened there.
    /// A window takes a chunk only at an index it waits for, once, and
    /// never more than its limit.
    pub(crate) fn offer(&self, space: &EventId, part: &ObjectPart, opened: bool) -> bool {
        let Some(watched) = self.watched(&(*space, object_id(&part.locator))) else {
            return false;
        };
        let mut inner = lock(&watched.inner);
        let mut shared: Option<Arc<Vec<u8>>> = None;
        for held in inner.windows.values_mut().filter(|held| held.passing) {
            // The request ends with its chunk.
            if held.wanted.remove(&part.index).is_none() || held.chunks.len() >= held.limit {
                continue;
            }
            let chunk = shared.get_or_insert_with(|| Arc::new(part.chunk.clone()));
            held.chunks.insert(part.index, chunk.clone());
        }
        let taken = shared.is_some();
        if taken && inner.header.is_none() {
            inner.header.clone_from(&part.header);
        }
        inner.proved |= taken && opened;
        drop(inner);
        if taken {
            watched.bump();
        }
        taken
    }

    /// Refuses an object: each open reader of it fails with `class`, and
    /// what its windows held of it in memory goes. With `stands`, the
    /// fault is the object's own (units.md, 3.3: found at steps 1 to 7
    /// once step 0 passed), and a reader opened later fails at once.
    pub(crate) fn refuse(
        &self,
        space: &EventId,
        locator: &Locator,
        class: &'static str,
        stands: bool,
    ) {
        if stands {
            lock(&self.refused).insert((*space, *locator), class);
        }
        // A reader opened from now on starts afresh: the refusal is told
        // to those that were open.
        let key = (*space, object_id(locator));
        let Some(watched) = lock(&self.objects).remove(&key) else {
            return;
        };
        {
            let mut inner = lock(&watched.inner);
            inner.refusal.get_or_insert((class, false));
            inner.header = None;
            for held in inner.windows.values_mut() {
                held.chunks.clear();
                held.wanted.clear();
            }
        }
        watched.bump();
    }

    /// Lets go of what the windows of an object hold under a header no
    /// reader has opened a chunk under, the header with it: `false`, and
    /// nothing done, when one has, and may have given its bytes. The
    /// readers of the object that built on the header start over.
    pub(crate) fn disown(&self, key: &Key) -> bool {
        let Some(watched) = self.watched(key) else {
            return true;
        };
        {
            let mut inner = lock(&watched.inner);
            if inner.given {
                return false;
            }
            inner.header = None;
            inner.proved = false;
            inner.epoch += 1;
            for held in inner.windows.values_mut() {
                held.chunks.clear();
            }
        }
        watched.bump();
        true
    }

    /// Why an object was refused for good since the device opened.
    pub(crate) fn refused(&self, space: &EventId, locator: &Locator) -> Option<&'static str> {
        lock(&self.refused).get(&(*space, *locator)).copied()
    }

    /// Chunks of the object were kept in the store: no window waits for
    /// them any longer.
    pub(crate) fn kept(&self, space: &EventId, locator: &Locator, indices: &[u64]) {
        let key = (*space, object_id(locator));
        let Some(watched) = self.watched(&key) else {
            return;
        };
        for held in lock(&watched.inner).windows.values_mut() {
            for index in indices {
                held.wanted.remove(index);
            }
        }
        watched.bump();
    }
}

/// One reader's window on an object: the chunks it asks for and, when it
/// stores nothing, those that arrived for it, in memory. Dropping it ends
/// its requests and frees what it holds.
#[derive(Debug)]
pub(crate) struct Window {
    readers: Arc<Readers>,
    watched: Arc<Watched>,
    key: Key,
    locator: Locator,
    number: u64,
    passing: bool,
}

impl Window {
    /// Follows the object: the receiver changes when the device keeps a
    /// part of it, a window takes a chunk, or it is refused.
    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.watched.changed.subscribe()
    }

    /// Sets what the window wants. Each run of `runs` is asked for, at
    /// its priority, with one request for those of its chunks that the
    /// window neither holds nor has asked for at that priority or a more
    /// urgent one: a chunk asked for as read-ahead that a read comes to
    /// wait for gets a request of its own, ahead of everything else, and
    /// leaves the run it was in. The window holds in memory
    /// only chunks in `hold`, at most as many as `hold` names, and waits
    /// only for chunks in `hold`: what a seek leaves behind is dropped,
    /// and a request none of whose chunks is still waited for is
    /// cancelled.
    pub(crate) fn want(
        &self,
        engine: &Engine,
        runs: &[(Range<u64>, FetchPriority)],
        hold: Range<u64>,
    ) {
        let mut inner = lock(&self.watched.inner);
        let refused = inner.refusal.is_some();
        let Some(held) = inner.windows.get_mut(&self.number) else {
            return;
        };
        held.limit = usize::try_from(hold.end.saturating_sub(hold.start)).unwrap_or(usize::MAX);
        held.chunks.retain(|index, _| hold.contains(index));
        held.wanted.retain(|index, _| hold.contains(index));
        if refused {
            held.wanted.clear();
            return;
        }
        for (run, priority) in runs {
            let new: Vec<u64> = (run.start.max(hold.start)..run.end.min(hold.end))
                .filter(|index| {
                    !held.chunks.contains_key(index)
                        && held.wanted.get(index).is_none_or(|(_, at)| at > priority)
                })
                .collect();
            let (Some(first), Some(last)) = (new.first(), new.last()) else {
                continue;
            };
            let fetch = Arc::new(engine.fetches().add_for(
                self.key.0,
                self.locator,
                *first..last.saturating_add(1),
                *priority,
                !self.passing,
            ));
            for index in new {
                held.wanted.insert(index, (fetch.clone(), *priority));
            }
        }
    }

    /// Lets go of the requests the space's connections gave up
    /// ([`FetchEnd`]): their chunks are asked for again by the next
    /// [`want`](Self::want) that names them, with a request a connection
    /// made since, or one that left the chunks unserved, takes.
    pub(crate) fn renew(&self) {
        if let Some(held) = lock(&self.watched.inner).windows.get_mut(&self.number) {
            held.wanted.retain(|_, (fetch, _)| fetch.end().is_none());
        }
    }

    /// Cancels every request the window made: what it holds stays.
    pub(crate) fn cancel(&self) {
        if let Some(held) = lock(&self.watched.inner).windows.get_mut(&self.number) {
            held.wanted.clear();
        }
    }

    /// Of the chunks `chunks`, those the window holds in memory, and
    /// those it has asked for and still waits for, each with the
    /// priority it was asked at.
    pub(crate) fn state(
        &self,
        chunks: Range<u64>,
    ) -> (BTreeSet<u64>, BTreeMap<u64, FetchPriority>) {
        let inner = lock(&self.watched.inner);
        inner
            .windows
            .get(&self.number)
            .map(|held| {
                (
                    held.chunks
                        .range(chunks.clone())
                        .map(|(at, _)| *at)
                        .collect(),
                    held.wanted
                        .range(chunks.clone())
                        .map(|(at, (_, priority))| (*at, *priority))
                        .collect(),
                )
            })
            .unwrap_or_default()
    }

    /// A sealed chunk the window holds in memory.
    pub(crate) fn chunk(&self, index: u64) -> Option<Arc<Vec<u8>>> {
        lock(&self.watched.inner)
            .windows
            .get(&self.number)?
            .chunks
            .get(&index)
            .cloned()
    }

    /// Drops a chunk the window holds that did not open.
    pub(crate) fn discard(&self, index: u64) {
        if let Some(held) = lock(&self.watched.inner).windows.get_mut(&self.number) {
            held.chunks.remove(&index);
        }
    }

    /// The header that arrived with the chunks the windows took.
    pub(crate) fn header(&self) -> Option<Vec<u8>> {
        lock(&self.watched.inner).header.clone()
    }

    /// Notes that a chunk opened in this reader under the header the
    /// object's readers read by: its bytes may have been given.
    pub(crate) fn gave(&self) {
        let mut inner = lock(&self.watched.inner);
        inner.proved = true;
        inner.given = true;
    }

    /// Whether a chunk has opened in a reader of the object, this one or
    /// another, under the header they read by.
    pub(crate) fn given(&self) -> bool {
        lock(&self.watched.inner).given
    }

    /// How many times what was held under a header nothing had opened
    /// under was let go.
    pub(crate) fn epoch(&self) -> u64 {
        lock(&self.watched.inner).epoch
    }

    /// Lets go of the header the windows hold and of every chunk that
    /// arrived under it, unless a chunk has opened under it: nothing was
    /// given from them, and they are not known to be the object's.
    pub(crate) fn disown(&self) {
        self.readers.disown(&self.key);
    }

    /// A chunk the window holds in memory, if any: the last.
    pub(crate) fn any_chunk(&self) -> Option<u64> {
        lock(&self.watched.inner)
            .windows
            .get(&self.number)?
            .chunks
            .keys()
            .next_back()
            .copied()
    }

    /// Follows the end of the request for a chunk the window asked for.
    pub(crate) fn ends(&self, index: u64) -> Option<watch::Receiver<Option<FetchEnd>>> {
        lock(&self.watched.inner)
            .windows
            .get(&self.number)?
            .wanted
            .get(&index)
            .map(|(fetch, _)| fetch.follow_end())
    }

    /// The sealed bytes the window holds in memory, and how many requests
    /// it has made that are still wanted.
    pub(crate) fn holds(&self) -> (usize, usize) {
        let inner = lock(&self.watched.inner);
        inner.windows.get(&self.number).map_or((0, 0), |held| {
            (
                held.chunks.values().map(|chunk| chunk.len()).sum(),
                held.wanted.len(),
            )
        })
    }

    /// Why the object was refused while this reader was open, and whether
    /// this is the first reader to hear of it.
    pub(crate) fn refusal(&self) -> Option<(&'static str, bool)> {
        let mut inner = lock(&self.watched.inner);
        let (class, reported) = inner.refusal.as_mut()?;
        Some((*class, !std::mem::replace(reported, true)))
    }

    /// Takes the turn to run the whole-object steps on the stored object:
    /// `false` while another reader runs them.
    pub(crate) fn begin_verifying(&self) -> bool {
        !std::mem::replace(&mut lock(&self.watched.inner).verifying, true)
    }

    /// Gives the turn back.
    pub(crate) fn end_verifying(&self) {
        lock(&self.watched.inner).verifying = false;
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let mut objects = lock(&self.readers.objects);
        let empty = {
            let mut inner = lock(&self.watched.inner);
            inner.windows.remove(&self.number);
            inner.windows.is_empty()
        };
        if empty
            && objects
                .get(&self.key)
                .is_some_and(|watched| Arc::ptr_eq(watched, &self.watched))
        {
            objects.remove(&self.key);
        }
        drop(objects);
        // What follows the object hears that a reader went.
        self.watched.bump();
    }
}

/// What the device holds of an object a reader reads, in one of the
/// spaces that may store it ([`Engine::holding`]).
#[derive(Debug, Default)]
pub(crate) struct Holding {
    /// The header the replica holds, of a file the application holds
    /// too.
    pub header: Option<Vec<u8>>,
    /// The chunks it holds sealed, in memory or in the store, of those
    /// asked about.
    pub chunks: BTreeSet<u64>,
    /// Whether it holds the object whole, sealed.
    pub whole: bool,
    /// Whether the application holds the plaintext as a file.
    pub file: bool,
}

/// A fault a [`PartReader`] found at the whole-object steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WholeFault {
    /// Step 0: the bytes read are not the object's. Nothing is concluded
    /// about the object, which is fetched again.
    Bytes,
    /// Step 7, once step 0 passed: the object is not what its ID names.
    Object,
    /// A chunk the reader gave from memory came again as other bytes: at
    /// most one of the two is the object's, so step 0 cannot pass on what
    /// was given. Nothing is concluded about the object.
    Given,
}

/// An object's plaintext by chunk, any chunk first (units.md, 3.3 Reading
/// an object, by a reader that fetches by chunk): [`PartReader::new`] runs
/// steps 1 to 3 and 5 on the header, and [`PartReader::open`] steps 4 and
/// 6 on a chunk, before any byte of that chunk is returned. Chunks opened
/// in order from the first also count for the whole object: their stored
/// bytes are hashed for step 0 and their plaintext for step 7, and both
/// run before the last chunk is returned.
///
/// A chunk that was not read from what the device stores may be let go
/// and come again, from any party. The reader keeps the SHA-256 of each
/// such chunk's sealed bytes, 32 bytes a chunk, and a chunk opened again
/// at that place must be the same bytes: so the bytes the pass in order
/// hashed are the bytes returned, whatever was read before, between or
/// after ([`WholeFault::Given`]).
pub(crate) struct PartReader {
    locator: Locator,
    /// Opens any chunk.
    any: ChunkReader,
    /// The pass in order: the reader whose opens count for step 7, the
    /// hash of the stored bytes so far, and the next chunk it takes.
    pass: Option<(ChunkReader, frasil_crypto::primitives::Sha256Hasher, u64)>,
    /// Whether every chunk of the pass was read from what the device
    /// stores.
    stored: bool,
    /// Whether steps 0 to 7 have passed on what this reader read.
    whole: bool,
    /// The fault the pass ended with.
    fault: Option<WholeFault>,
    /// Whether a chunk has opened: the header is then one a holder of the
    /// object's key sealed a chunk under, and its size, which every
    /// chunk's associated data binds, is that holder's.
    opened: bool,
    /// The digest of the sealed bytes of each chunk returned that was not
    /// read from what the device stores.
    given: BTreeMap<u64, [u8; 32]>,
}

impl core::fmt::Debug for PartReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartReader")
            .field("whole", &self.whole)
            .finish_non_exhaustive()
    }
}

impl PartReader {
    /// Steps 1 to 3 on the header, then step 5 with `opening`. `opens` is
    /// the space that sealed the object.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `TooLarge`, `ObjectMismatch`,
    /// `Sealed`.
    pub(crate) fn new(
        header: &[u8],
        opens: &EventId,
        opening: Opening<'_>,
        locator: &Locator,
    ) -> Result<Self> {
        let reader = |opening| ChunkReader::new(header, opens, opening, locator);
        let (any, pass) = match opening {
            Opening::ContentKey(key) => (
                reader(Opening::ContentKey(key)),
                reader(Opening::ContentKey(key)),
            ),
            Opening::ObjectKey(key) => (
                reader(Opening::ObjectKey(key)),
                reader(Opening::ObjectKey(key)),
            ),
        };
        let hasher = frasil_units::objects::stored_bytes_hasher(header).map_err(Error::class)?;
        Ok(Self {
            locator: *locator,
            any: any.map_err(Error::class)?,
            pass: Some((pass.map_err(Error::class)?, hasher, 0)),
            stored: true,
            whole: false,
            fault: None,
            opened: false,
            given: BTreeMap::new(),
        })
    }

    /// Whether a chunk has opened under the header. Until one has, the
    /// header's size is only what the party that sent the header says:
    /// steps 1 to 3 bind the header's object ID to the locator and
    /// nothing else of it (units.md, 3.3 Reading an object).
    pub(crate) fn has_opened(&self) -> bool {
        self.opened
    }

    /// The plaintext's length, from the header.
    pub(crate) fn size(&self) -> u64 {
        self.any.size()
    }

    /// The object's chunk count.
    pub(crate) fn count(&self) -> u64 {
        self.any.count()
    }

    /// Whether every step of units.md, 3.3 has passed on what this reader
    /// read: it opened every chunk in order.
    pub(crate) fn is_whole(&self) -> bool {
        self.whole
    }

    /// Whether the chunks that passed were all read from what the device
    /// stores, so that what passed is the stored object.
    pub(crate) fn passed_stored(&self) -> bool {
        self.whole && self.stored
    }

    /// The fault the pass in order ended with.
    pub(crate) fn fault(&self) -> Option<WholeFault> {
        self.fault
    }

    /// Step 4 on one chunk's length, then step 6: its plaintext. `stored`
    /// says the sealed bytes were read from what the device stores. The
    /// chunk the pass in order takes next is hashed with it; the last one
    /// is returned only once step 0 passed on the stored bytes hashed and
    /// step 7 on the plaintext.
    ///
    /// # Errors
    ///
    /// `Malformed` for an index past the last chunk or a chunk of the
    /// wrong length; `Decrypt`; `ObjectMismatch` when the pass in order
    /// ends with a fault, or the chunk is not the one returned at that
    /// place before ([`fault`](Self::fault)).
    pub(crate) fn open(&mut self, index: u64, sealed: &[u8], stored: bool) -> Result<Vec<u8>> {
        // The chunk returned at this place before, from memory, is the
        // one that counts: other bytes are not returned, and not hashed.
        let digest = (!stored || self.given.contains_key(&index))
            .then(|| frasil_crypto::primitives::sha256(&[sealed]));
        if let Some(digest) = &digest
            && self.given.get(&index).is_some_and(|given| given != digest)
        {
            self.fault = Some(WholeFault::Given);
            self.whole = false;
            return Err(Error::Class("ObjectMismatch"));
        }
        let plain = self.open_checked(index, sealed, stored)?;
        if let Some(digest) = digest.filter(|_| !stored) {
            self.given.insert(index, digest);
        }
        Ok(plain)
    }

    /// [`open`](Self::open), once the chunk is known to be the one
    /// returned at its place before, if any was.
    fn open_checked(&mut self, index: u64, sealed: &[u8], stored: bool) -> Result<Vec<u8>> {
        let Some((pass, hasher, next)) = self.pass.as_mut().filter(|(_, _, next)| *next == index)
        else {
            let plain = self.any.open(index, sealed).map_err(Error::class)?;
            self.opened = true;
            return Ok(plain);
        };
        let plain = pass.open(index, sealed).map_err(Error::class)?;
        self.opened = true;
        hasher.update(sealed);
        *next += 1;
        self.stored &= stored;
        if *next < self.any.count() {
            return Ok(plain);
        }
        let Some((pass, hasher, _)) = self.pass.take() else {
            return Ok(plain);
        };
        // 0, which decides first.
        if hasher.finish() != self.locator[32..] {
            self.fault = Some(WholeFault::Bytes);
            return Err(Error::Class("ObjectMismatch"));
        }
        // 7.
        if let Err(fault) = pass.finish() {
            self.fault = Some(WholeFault::Object);
            return Err(Error::class(fault));
        }
        self.whole = true;
        Ok(plain)
    }
}

impl Engine {
    /// The open readers of the device's objects.
    pub(crate) fn readers(&self) -> &Arc<Readers> {
        self.shared_readers()
    }

    /// Opens a reader's window on an object of `space`. With `passing`,
    /// chunks of it the device does not store are taken into the window's
    /// memory, and the requests the window makes are not the store's.
    /// `opening` is what the reader of a reference opens the object with:
    /// chunks of the object are opened with it as they arrive, while the
    /// window is open.
    pub(crate) fn open_window(
        &self,
        space: EventId,
        locator: Locator,
        passing: bool,
        opening: Option<ObjectOpening>,
    ) -> Window {
        let readers = self.readers().clone();
        let key = (space, object_id(&locator));
        let (watched, number) = {
            let mut objects = lock(&readers.objects);
            let watched = objects
                .entry(key)
                .or_insert_with(|| {
                    Arc::new(Watched {
                        changed: watch::channel(0).0,
                        inner: Mutex::default(),
                    })
                })
                .clone();
            let number = {
                let mut inner = lock(&watched.inner);
                inner.next += 1;
                let number = inner.next;
                inner.windows.insert(
                    number,
                    Held {
                        opening,
                        passing,
                        ..Held::default()
                    },
                );
                number
            };
            (watched, number)
        };
        Window {
            readers,
            watched,
            key,
            locator,
            number,
            passing,
        }
    }

    /// Whether the chunks that arrive of an object go to the windows of
    /// readers that store nothing, and nowhere else: such a reader is
    /// open, and nothing makes the device mean to hold the object. It
    /// does when it keeps every blob, when the object has a `retention`
    /// record or chunks in the store, when a read that stores uses it or
    /// a request for the store names it, when the application asked for
    /// it or receives it through its provider, and when it is not a
    /// blob's, which the device fetches by itself.
    pub(crate) fn passes(&self, state: &State, space: &EventId, locator: &Locator) -> bool {
        let key = (*space, object_id(locator));
        if !self.readers().passing(&key)
            || self.keeps_all_blobs()
            || state.retained.get(&key).is_some()
            || self.wanted(&key).is_some()
            || state.held.asked_for(space, locator)
            || state.held.receive_at(space, locator).is_some()
            || self.fetches().stores(space, locator)
        {
            return false;
        }
        let Some(replica) = state.replicas.get(space) else {
            return false;
        };
        let holds = replica.is_held(locator)
            || replica.holds_chunks(locator)
            || replica
                .object_locators(&key.1)
                .iter()
                .any(|locator| replica.holds_chunks(locator));
        !holds && crate::objects::fetched_on_read(replica, locator)
    }

    /// Where a fetch of chunks for windows that store nothing starts: the
    /// header they hold, and the first chunk among `chunks` one of them
    /// still waits for. `None` when none does.
    pub(crate) fn window_fetch(
        &self,
        space: &EventId,
        locator: &Locator,
        chunks: Range<u64>,
    ) -> Option<(Option<Vec<u8>>, u64)> {
        let key = (*space, object_id(locator));
        let header = self.readers().header(&key);
        let end = header
            .as_deref()
            .and_then(|header| Header::read(header).ok())
            .map_or(chunks.end, |header| chunks.end.min(count_of(header.size)));
        let first = self.readers().first_needed(&key, chunks.start..end)?;
        Some((header, first))
    }

    /// What the device holds of an object in one space: its header, which
    /// of the chunks `chunks` it holds sealed, and whether it holds it
    /// whole or as a file of the application's.
    pub(crate) async fn holding(
        &self,
        space: &EventId,
        locator: &Locator,
        chunks: Range<u64>,
    ) -> Holding {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let Some(replica) = state.replicas.get(space) else {
            return Holding::default();
        };
        let header = replica.object_header(locator).map(<[u8]>::to_vec);
        if replica.is_held(locator) {
            return Holding {
                header,
                file: true,
                ..Holding::default()
            };
        }
        let end = header
            .as_deref()
            .and_then(|header| Header::read(header).ok())
            .map_or(chunks.end, |header| chunks.end.min(count_of(header.size)));
        Holding {
            chunks: (chunks.start..end)
                .filter(|index| replica.holds_sealed_chunk(locator, *index))
                .collect(),
            whole: replica.holds_object(locator),
            header,
            file: false,
        }
    }

    /// One sealed chunk of an object the device holds any part of, read
    /// without the device's lock, with the header held: `None` when the
    /// device does not hold the chunk sealed.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn held_part(
        &self,
        space: &EventId,
        locator: &Locator,
        index: u64,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let (header, memory, reader) = {
            let state = self.lock().await;
            let Some(replica) = state.replicas.get(space) else {
                return Ok(None);
            };
            if replica.is_held(locator) || !replica.holds_sealed_chunk(locator, index) {
                return Ok(None);
            }
            let Some(header) = replica.object_header(locator) else {
                return Ok(None);
            };
            (
                header.to_vec(),
                replica
                    .chunks_in_memory_in(locator, index..index.saturating_add(1))
                    .remove(&index),
                state.vault.object_parts(&space.0),
            )
        };
        if let Some(chunk) = memory {
            return Ok(Some((header, chunk)));
        }
        let Some(reader) = reader else {
            return Ok(None);
        };
        let part = crate::objects::chunk_part(index)?;
        let Some(opened) = reader.read(&locator[..32], &[part]).await? else {
            return Ok(None);
        };
        Ok(opened
            .into_iter()
            .next()
            .map(|chunk| (header, chunk.value().to_vec())))
    }

    /// The key that opens an object for a reader of `space`, as the
    /// header names it: the content key of the state the header names.
    pub(crate) async fn content_key_for(
        &self,
        space: &EventId,
        header: &[u8],
    ) -> Option<frasil_keys::derive::Secret> {
        let reference = Header::read(header).ok()?.key_reference;
        self.read(space, |replica| replica.object_key(&reference))
            .await
            .ok()
            .flatten()
            .map(|(key, _)| key)
    }

    /// Whether a sealed chunk the device holds of an object opens under
    /// the header it holds: that header is then one a holder of the
    /// object's key sealed chunks under, and a chunk another party sends
    /// that does not open under it is that chunk's fault, unless the
    /// sender holds another header.
    pub(crate) async fn holds_an_open_chunk(&self, space: &EventId, locator: &Locator) -> bool {
        let first = {
            let state = self.lock().await;
            state
                .replicas
                .get(space)
                .and_then(|replica| replica.object_stored(locator))
                .and_then(|stored| stored.first().copied())
        };
        let Some(first) = first else {
            return false;
        };
        let Ok(Some((header, chunk))) = self.held_part(space, locator, first).await else {
            return false;
        };
        let Ok(read) = Header::read(&header) else {
            return false;
        };
        let Some(key) = self.content_key_for(space, &header).await else {
            return false;
        };
        let object_key = ObjectKeys::of(&key).object_key(&read.object_id);
        check_chunk(space, &read, locator, first, &chunk, Some(&object_key)).is_ok()
    }

    /// Runs every step of units.md, 3.3 on an object the device holds
    /// whole and sealed, in one pass over the store a few chunks at a
    /// time, unless a read ran them since the object was last kept:
    /// `true` once they passed, `false` while the device does not hold it
    /// whole. An object that fails is refused: its open readers fail
    /// ([`Readers::refuse`]), and the device drops what it stores of it
    /// unless it keeps the object. One whose stored bytes hash to the
    /// locator and that fails a later step is not what its locator names,
    /// whoever sends it: it is refused for as long as the device is open.
    ///
    /// # Errors
    ///
    /// The object's classes; the store's.
    #[cfg(feature = "adapter-blobs")]
    pub(crate) async fn verify_whole(
        &self,
        space: &EventId,
        locator: &Locator,
        reference: Option<(EventId, [u8; 32])>,
    ) -> Result<bool> {
        let fault = match self.plain(space, locator, reference, 0..0).await {
            Ok(crate::objects::Plain::Chunks(_)) => return Ok(true),
            Ok(crate::objects::Plain::Held(_)) | Err(Error::Class("Missing" | "Sealed")) => {
                return Ok(false);
            }
            Err(Error::Class(class)) => class,
            Err(error) => return Err(error),
        };
        let mut holders = vec![*space];
        holders.extend(reference.map(|(source, _)| source));
        // Its bytes hash to the locator: the fault is the object's.
        let mut stands = false;
        for holder in &holders {
            stands |= self
                .read(holder, |replica| {
                    replica.holds_object(locator) && replica.is_checked(locator)
                })
                .await
                .unwrap_or(false);
        }
        self.refuse_read(space, &holders, locator, fault, stands)
            .await?;
        Err(Error::Class(fault))
    }

    /// Refuses an object a read found a fault in: its open readers fail
    /// with `class` ([`Readers::refuse`]), and what the device stores of
    /// it in `holders` is dropped. With `stands`, the fault is the
    /// object's own, whoever sends it: an object the device keeps then
    /// stays where it is, since fetching it again brings the same bytes,
    /// and a cached one goes with its record.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn refuse_read(
        &self,
        space: &EventId,
        holders: &[EventId],
        locator: &Locator,
        class: &'static str,
        stands: bool,
    ) -> Result<()> {
        self.readers().refuse(space, locator, class, stands);
        let mut state = self.lock().await;
        for holder in holders {
            if holder != space {
                self.readers().refuse(holder, locator, class, stands);
            }
            let kept = matches!(
                self.must_stay(&mut state, holder, locator),
                Some(
                    crate::retention::Stays::Own
                        | crate::retention::Stays::Pending
                        | crate::retention::Stays::Kept
                )
            );
            if !(stands && kept) {
                self.drop_stored(&mut state, *holder, &object_id(locator), stands && !kept)
                    .await?;
            }
        }
        Ok(())
    }

    /// Drops what the device stores of an object in `holders` under a
    /// header nothing has opened under: a chunk of it did not open for a
    /// reader, no reader gave anything of it, and so none fails. It is
    /// missing again, and fetched again; how the device retains it stays
    /// as it was.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_unopened(&self, holders: &[EventId], locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        for holder in holders {
            self.readers().disown(&(*holder, object_id(locator)));
            self.drop_stored(&mut state, *holder, &object_id(locator), false)
                .await?;
        }
        Ok(())
    }

    /// A chunk of an object the device holds sealed in one space, if any.
    pub(crate) async fn any_held_chunk(&self, space: &EventId, locator: &Locator) -> Option<u64> {
        self.read(space, |replica| replica.a_sealed_chunk(locator))
            .await
            .ok()
            .flatten()
    }

    /// Notes that a read in order of an object the device holds whole
    /// passed every step of units.md, 3.3 on the stored bytes: step 0, so
    /// that its chunks may be served, and with `step_7` the plaintext's
    /// ID.
    pub(crate) async fn passed_whole(&self, space: &EventId, locator: &Locator, step_7: bool) {
        let mut state = self.lock().await;
        let Some(replica) = state.replicas.get_mut(space) else {
            return;
        };
        if replica.holds_object(locator) && !replica.is_held(locator) {
            replica.mark_checked(locator);
            self.mark_verified(*space, *locator, step_7);
        }
    }
}

#[cfg(all(test, feature = "adapter-blobs"))]
mod tests;
