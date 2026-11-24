//! A reader over a blob that need not be whole on the device
//! (adapter-blobs.md, 3.5 Fetching; units.md, 3.3 Reading an object).
//!
//! [`Blobs::open_reader`] gives a [`BlobReader`]: it reads any range of a
//! blob, fetching the chunks that hold it from the peers and members
//! connected, and gives bytes as soon as their chunks are here and
//! checked. A media player backs its source with one: a seek fetches the
//! chunk it lands in and a few after it, not the blob.
//!
//! **What is checked, and when.** No byte is given before the header has
//! passed steps 1 to 3 and 5 of units.md, 3.3 and its chunk has passed
//! steps 4 and 6: the chunk opens under the object's key, at its own place
//! in its own object. The header's steps bind its object ID to the blob
//! and nothing else of it: its size is bound by each chunk's associated
//! data, so the reader gives no size and no end of the blob before a chunk
//! has opened under the header in that reader ([`BlobReader::size`]). The
//! two steps that need the whole object, 0 and 7,
//! cannot run on a part of it. [`BlobReader::verified`] says whether they
//! have: [`Verified::Chunks`] until then, and [`Verified::Whole`] after. A
//! reader that reads the blob in order from its first byte to its last
//! runs them as the bytes pass, before it gives the last chunk. One that
//! seeks cannot; its blob's checks run once the device holds the blob
//! whole in its store, which a reader that stores nothing never brings
//! about. Until [`Verified::Whole`], a member that holds the blob's key
//! can have served chunks that are not the blob's, and the blob may still
//! be refused: the reader then fails with `ObjectMismatch`, and
//! [`Event::ObjectRefused`] tells the application (adapter-blobs.md, 4
//! Security considerations).
//!
//! [`Verified::Whole`] is about the bytes the reader gave. A reader that
//! holds its chunks in memory lets go of those it leaves, and fetches a
//! chunk again when it is read again, from whichever party serves it. It
//! keeps the SHA-256 of each chunk it gave from memory, 32 bytes a chunk,
//! and takes at that place only the same bytes again: other bytes are not
//! given, the reader fails with `ObjectMismatch`, and the application is
//! told. So a reader that seeks back after it became whole stays whole,
//! and the pass in order counts the chunks that were given. A reader that
//! reads from the device's store reads the same stored chunk each time.
//!
//! **Where fetched chunks go.** As the [`Read`] says. By default into the
//! device's cache, as parts of a cached blob, and with
//! [`keep`](Read::keep) as parts of a kept one. With
//! [`uncached`](Read::uncached) into a window in memory that the reader
//! owns, and nothing reaches the store: the window holds the chunk the
//! reader stands in and the chunks read ahead of it, sealed, at most
//! `read_ahead + 1` chunks of 1,048,576 bytes each (9 MiB at the default
//! read-ahead of 8), beside one opened chunk and the header. A blob larger
//! than the whole cache budget, and any blob under a budget of zero, is
//! read that way too.

use super::retention::Reading;
use super::{BlobId, Blobs, Event, Read};
use crate::error::{Error, Result};
use crate::fetch::{FetchEnd, FetchPriority};
use crate::reading::{ObjectOpening, PartReader, WholeFault, Window};
use crate::retention::Want;
use frasil_adapter::Locator;
use frasil_adapter_blobs::Entry;
use frasil_events::EventId;
use frasil_keys::derive::Secret;
use frasil_units::limits::CHUNK_BYTES;
use frasil_units::objects::Opening;
use std::collections::BTreeSet;
use std::sync::{Arc, Weak};
use tokio::sync::watch;

/// How many chunks a reader fetches ahead of where it reads, unless it is
/// told otherwise ([`BlobReader::set_read_ahead`]).
pub const READ_AHEAD: u64 = 8;

/// The most chunks a reader fetches ahead.
pub const MAX_READ_AHEAD: u64 = 64;

/// How long a read waits with nothing of its blob arriving before it
/// gives up.
const STALL: std::time::Duration = std::time::Duration::from_secs(30);

/// How often a read that waits looks whether anything is still connected.
const POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Which steps of units.md, 3.3 Reading an object have passed on what a
/// [`BlobReader`] gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verified {
    /// The header's steps and each chunk's: every byte given comes from a
    /// chunk that opened under the blob's key at its own place. The
    /// whole-object steps have not run: the bytes may yet prove not to be
    /// the blob's, and the reader then fails with `ObjectMismatch`.
    Chunks,
    /// Every step: the bytes are the blob's.
    Whole,
}

/// A reader over one blob, from [`Blobs::open_reader`]. Dropping it ends
/// its fetches and frees what it holds; [`close`](Self::close) does the
/// same and waits until the device has looked at its cache. Formatted
/// for a log, it shows neither bytes of the blob nor a reference's object
/// key.
pub struct BlobReader {
    blobs: Blobs,
    id: BlobId,
    entry: Entry,
    /// The space the reader fetches in, and the spaces that may store the
    /// object: that one, and for a reference its source.
    space: EventId,
    holders: Vec<EventId>,
    /// For a reference, its source and the object's key.
    reference: Option<(EventId, Secret)>,
    /// Whether the reader fetches nothing.
    local: bool,
    /// Whether the application holds the blob as a file.
    file: bool,
    window: Window,
    reading: Option<Reading>,
    parts: Option<PartReader>,
    /// The chunk opened last, with its index.
    opened: Option<(u64, Vec<u8>)>,
    position: u64,
    read_ahead: u64,
    /// Whether the device holds the object whole, so that nothing is
    /// fetched.
    stored_whole: bool,
    /// Whether a chunk given came from the reader's window and not from
    /// the store.
    from_window: bool,
    /// Whether every step passed on what a held file's read gave.
    file_whole: bool,
    /// The class the reader failed with for good.
    failed: Option<&'static str>,
    /// Whether the last read failed because every connection of the
    /// space gave its chunk up, for bytes that failed their checks.
    gave_up: bool,
    /// The window's count of headers let go when `parts` was made
    /// ([`Window::epoch`]).
    epoch: u64,
    /// Held while the reader lives, for the task that follows the object.
    alive: Arc<()>,
}

impl core::fmt::Debug for BlobReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobReader")
            .field("id", &self.id)
            .field("space", &self.space)
            .field("position", &self.position)
            .field("read_ahead", &self.read_ahead)
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

/// Waits for a request's end.
async fn ended(ends: Option<watch::Receiver<Option<FetchEnd>>>) -> FetchEnd {
    let Some(mut ends) = ends else {
        return std::future::pending().await;
    };
    loop {
        if let Some(end) = *ends.borrow_and_update() {
            return end;
        }
        if ends.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Whether a blob of this size is read through memory under a budget: it
/// could not fit the cache.
fn streams_through(size: u64, budget: u64) -> bool {
    let chunks = frasil_units::objects::chunk_count(size, CHUNK_BYTES as u64);
    budget == 0 || size.saturating_add(chunks.saturating_mul(40)) > budget
}

impl Blobs {
    /// Opens a reader over a blob, which reads any range of it and fetches
    /// only the chunks it needs, as `read` says ([`Read`]): into the cache
    /// by default, kept with [`keep`](Read::keep), into the reader's own
    /// memory with [`uncached`](Read::uncached), and nothing with
    /// [`local`](Read::local), which reads only what the device holds.
    /// Nothing is fetched until the reader is read or asked its size.
    ///
    /// A blob the device holds, whole or in part, is read from the device
    /// whatever `read` says, and chunks fetched for a blob it holds part
    /// of join that part. A blob larger than the cache's whole budget, and
    /// any blob under a budget of zero, is read through the reader's
    /// memory as an [`uncached`](Read::uncached) read is. In a space whose
    /// blobs the application holds as files, a blob held as a file is read
    /// from the file, and one that is not is read through the reader's
    /// memory and becomes no file.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID;
    /// [`Error::NotAllowed`] for a read that [`keep`](Read::keep)s in a
    /// space this device keeps in memory alone; `ObjectMismatch` for a
    /// blob that failed its whole-object checks since the device opened;
    /// the store's.
    pub async fn open_reader(&self, id: BlobId, read: &Read) -> Result<BlobReader> {
        let entry = self.entry(id).await?;
        self.reader_of(id, entry, read).await
    }

    /// [`open_reader`](Self::open_reader) for an entry read already.
    pub(super) async fn reader_of(
        &self,
        id: BlobId,
        entry: Entry,
        read: &Read,
    ) -> Result<BlobReader> {
        let device = &self.space().device;
        let engine = device.engine().clone();
        let space = self.space().id().event();
        let locator = entry.object;
        if let Some(class) = engine.readers().refused(&space, &locator) {
            return Err(Error::Class(class));
        }
        let reference = entry
            .reference
            .as_ref()
            .map(|reference| (EventId(reference.source), Secret::new(reference.object_key)));
        let mut holders = vec![space];
        holders.extend(
            reference
                .as_ref()
                .map(|(source, _)| *source)
                .filter(|source| *source != space),
        );
        // Used before the device is asked what it holds, so that what it
        // answers stays.
        let mut uses: Vec<_> = holders
            .iter()
            .map(|holder| engine.use_object(*holder, &locator))
            .collect();
        let mut file = false;
        let mut whole = None;
        for holder in &holders {
            let holding = engine.holding(holder, &locator, 0..0).await;
            file |= holding.file;
            if holding.whole && whole.is_none() {
                whole = Some(*holder);
            }
        }
        let held_space = engine.object_policy(&space).await == crate::held::ObjectPolicy::Held;
        let mut local = false;
        let passing = if file {
            false
        } else if let Some(holder) = whole {
            if read.keeps() || !read.stores_nothing() {
                engine.retain(holder, &locator, read.keeps()).await?;
            }
            engine.touch(holder, &locator).await?;
            false
        } else if read.is_local() {
            local = true;
            false
        } else if held_space {
            true
        } else if read.keeps() {
            engine.retain(space, &locator, true).await?;
            false
        } else if read.stores_nothing() || streams_through(entry.size, engine.blob_cache()) {
            true
        } else {
            // Recorded as cached when its first part arrives.
            uses.push(engine.want_object(space, &locator, Want::Cache));
            false
        };
        let opening = reference.as_ref().map(|(source, key)| ObjectOpening {
            source: *source,
            key: key.clone(),
        });
        let window = engine.open_window(space, locator, passing, opening);
        let alive = Arc::new(());
        let reader = BlobReader {
            blobs: self.clone(),
            id,
            space,
            holders,
            reference,
            local,
            file,
            window,
            reading: Some(Reading::holding(self.clone(), uses)),
            parts: None,
            opened: None,
            position: 0,
            read_ahead: READ_AHEAD,
            stored_whole: false,
            from_window: false,
            file_whole: false,
            failed: None,
            gave_up: false,
            epoch: 0,
            alive,
            entry,
        };
        reader.follow_object();
        Ok(reader)
    }
}

/// What the task that follows a reader's object needs.
struct Following {
    blobs: Blobs,
    id: BlobId,
    space: EventId,
    locator: Locator,
    holders: Vec<EventId>,
    reference: Option<(EventId, Secret)>,
    window: Window,
    alive: Weak<()>,
}

impl Following {
    /// Follows the object while its reader lives: once the device holds
    /// it whole, every step of units.md, 3.3 runs on the stored object,
    /// and a refusal is told to the application.
    async fn run(self) {
        let engine = self.blobs.space().device.engine().clone();
        let mut changed = self.window.follow();
        loop {
            changed.borrow_and_update();
            if self.alive.strong_count() == 0 {
                return;
            }
            if let Some((_, first)) = self.window.refusal() {
                if first {
                    report(&self.blobs, self.id);
                }
                return;
            }
            let mut whole = false;
            for holder in &self.holders {
                whole |= engine.holding(holder, &self.locator, 0..0).await.whole;
            }
            if whole && self.window.begin_verifying() {
                let verified = engine
                    .verify_whole(&self.space, &self.locator, key_of(&self.reference))
                    .await;
                self.window.end_verifying();
                match verified {
                    // Refused: told at the next turn.
                    Err(Error::Class(_)) => continue,
                    Ok(true) | Err(_) => return,
                    Ok(false) => {}
                }
            }
            if changed.changed().await.is_err() {
                return;
            }
        }
    }
}

/// A reference's source and object key, for a call that takes them by
/// value.
fn key_of(reference: &Option<(EventId, Secret)>) -> Option<(EventId, [u8; 32])> {
    reference.as_ref().map(|(source, key)| (*source, **key))
}

/// Tells the application that a blob was refused while it was read.
fn report(blobs: &Blobs, id: BlobId) {
    blobs.space().device.report(Event::ObjectRefused {
        space: blobs.space().id(),
        stream: blobs.id(),
        blob: id,
    });
}

impl BlobReader {
    /// Starts the task that follows the object, where the device's tasks
    /// take one. Without it, a reader that does not read in order stays
    /// at [`Verified::Chunks`] unless another read ran every step on the
    /// stored blob.
    fn follow_object(&self) {
        let engine = self.blobs.space().device.engine();
        let following = Following {
            blobs: self.blobs.clone(),
            id: self.id,
            space: self.space,
            locator: self.entry.object,
            holders: self.holders.clone(),
            reference: self.reference.clone(),
            window: engine.open_window(self.space, self.entry.object, false, None),
            alive: Arc::downgrade(&self.alive),
        };
        let _ = self
            .blobs
            .space()
            .device
            .try_spawn(Box::pin(following.run()));
    }

    fn engine(&self) -> crate::device::Engine {
        self.blobs.space().device.engine().clone()
    }

    /// The blob's size, once the reader holds its header and a chunk has
    /// opened under it in this reader: `None` before the reader's first
    /// read or [`fetch_size`](Self::fetch_size), which opens one. The
    /// header's own checks bind only its object ID to the blob; its size
    /// is in the associated data of every chunk, so a chunk that opens
    /// under the header shows that a holder of the blob's key sealed under
    /// that size, and until one has the size is only what the party that
    /// sent the header says. The size the stream's entry shows is what its
    /// writer wrote; this one decides what is read.
    pub fn size(&self) -> Option<u64> {
        self.parts
            .as_ref()
            .filter(|parts| parts.has_opened() || self.file_whole)
            .map(PartReader::size)
    }

    /// The blob's size, once a chunk has opened under its header
    /// ([`size`](Self::size)): the chunk the reader stands in, or the
    /// blob's last when it stands past the end, fetched with the header
    /// when the device does not hold them. Of a blob the device holds
    /// part of, a reader that stands past the end opens a chunk held.
    ///
    /// # Errors
    ///
    /// As [`read_at`](Self::read_at).
    pub async fn fetch_size(&mut self) -> Result<u64> {
        self.check()?;
        self.gave_up = false;
        self.authenticate().await
    }

    /// Where the next [`read`](Self::read) reads.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Moves to `position`: the next [`read`](Self::read) reads there, and
    /// what was asked for and is neither there nor in the chunks after it
    /// is cancelled.
    pub fn seek(&mut self, position: u64) {
        self.position = position;
        if let Some(parts) = &self.parts {
            let index = position / CHUNK_BYTES as u64;
            let end = index
                .saturating_add(1)
                .saturating_add(self.read_ahead)
                .min(parts.count());
            self.window.want(&self.engine(), &[], index..end.max(index));
        }
    }

    /// How many chunks the reader fetches ahead of where it reads.
    pub fn read_ahead(&self) -> u64 {
        self.read_ahead
    }

    /// Sets how many chunks the reader fetches ahead of where it reads, at
    /// most [`MAX_READ_AHEAD`]: [`READ_AHEAD`] unless set. A reader that
    /// stores nothing holds one sealed chunk more than this in memory.
    pub fn set_read_ahead(&mut self, chunks: u64) {
        self.read_ahead = chunks.min(MAX_READ_AHEAD);
    }

    /// Which steps have passed on what the reader gave ([`Verified`]).
    /// [`Verified::Whole`] once the reader has read the blob in order from
    /// its first byte to its last, or once the device holds the blob whole
    /// in its store and every step ran on it there. A reader stays whole
    /// across seeks: a chunk it reads again from its own memory must be
    /// the bytes it gave at that place before, or the reader fails with
    /// `ObjectMismatch` and is whole no longer. One that reads from the
    /// store reads the same stored chunk each time.
    pub fn verified(&self) -> Verified {
        if self.failed.is_some() {
            return Verified::Chunks;
        }
        let engine = self.blobs.space().device.engine();
        let step_7 = self.reference.is_none();
        let whole = self.file_whole
            || self.parts.as_ref().is_some_and(PartReader::is_whole)
            || (!self.from_window
                && !self.file
                && self
                    .holders
                    .iter()
                    .any(|holder| engine.is_verified(holder, &self.entry.object, step_7)));
        if whole {
            Verified::Whole
        } else {
            Verified::Chunks
        }
    }

    /// How many sealed bytes the reader holds in memory, of chunks it
    /// fetched to store nothing: at most `(read_ahead + 1) × 1,048,576`.
    /// Beside them it keeps 32 bytes for each chunk it gave from memory,
    /// to know it again.
    pub fn window_bytes(&self) -> usize {
        self.window.holds().0
    }

    /// Reads at the reader's position, and moves past what was read:
    /// [`read_at`](Self::read_at) there.
    ///
    /// # Errors
    ///
    /// As [`read_at`](Self::read_at).
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.read_at(self.position, buf).await
    }

    /// Reads bytes of the blob from `offset` into `buf`, and returns how
    /// many: at least one unless `buf` is empty or `offset` is at or past
    /// the blob's end, and no more than the chunk `offset` lies in holds
    /// from there, so a read that spans chunks is read again from where
    /// this one ended. The chunk is fetched first when the device does not
    /// hold it, ahead of everything else asked of the space's connections,
    /// with the chunks after it behind. The reader's position moves past
    /// what was read.
    ///
    /// # Errors
    ///
    /// `Missing` while the device does not hold the chunk and the reader
    /// is [`local`](Read::local), or neither a peer nor a member is
    /// connected, or what is connected does not serve the blob for now;
    /// [`Error::Timeout`] when nothing the read waits for arrives for
    /// half a minute; `Decrypt` or `Malformed` for a chunk that does not
    /// open, and once every connection of the space gave the chunk up
    /// because what it was sent failed its checks; `Sealed` without the
    /// blob's key; the store's. After each of these the reader lives on,
    /// nothing of the failed chunk was given, and the read may be made
    /// again: it asks again, and a party connected since, or one that
    /// had not answered, serves it.
    ///
    /// `ObjectMismatch` when the blob was refused: it failed a
    /// whole-object check, or bytes this reader gave are in doubt
    /// ([`Event::ObjectRefused`]). The reader has then failed for good,
    /// and every later read fails the same way.
    pub async fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.check()?;
        if buf.is_empty() {
            return Ok(0);
        }
        let piece = self.piece_at(offset, buf.len()).await?;
        let read = piece.len();
        buf[..read].copy_from_slice(piece);
        Ok(read)
    }

    /// Ends the reader: its fetches stop, what it held in memory is freed,
    /// and the device looks at its cache, so that a blob it held beside
    /// the cache for this reader alone goes.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn close(mut self) -> Result<()> {
        match self.reading.take() {
            Some(reading) => reading.done().await,
            None => Ok(()),
        }
    }

    /// The bytes from `offset` to the end of its chunk, at most `most`:
    /// empty at or past the blob's end.
    pub(super) async fn piece_at(&mut self, offset: u64, most: usize) -> Result<&[u8]> {
        self.check()?;
        self.gave_up = false;
        self.position = offset;
        // No end of the blob before a chunk opened under its header. An
        // empty blob has one empty chunk, which this opens.
        let size = self.authenticate().await?;
        let chunk = CHUNK_BYTES as u64;
        if offset >= size {
            return Ok(&[]);
        }
        let index = offset / chunk;
        self.chunk(index).await?;
        let Some((_, plain)) = &self.opened else {
            return Err(Error::Class("Missing"));
        };
        let within = usize::try_from(offset - index * chunk).unwrap_or(usize::MAX);
        let rest = plain.get(within..).unwrap_or(&[]);
        let piece = &rest[..rest.len().min(most)];
        self.position = offset.saturating_add(piece.len() as u64);
        Ok(piece)
    }

    /// Makes the reader hold the header with a chunk opened under it, and
    /// returns the size the header names, which that chunk's associated
    /// data binds (units.md, 2.8 Objects): the chunk the reader stands
    /// in, or, when it stands past the end, a chunk the device holds or
    /// else the last.
    async fn authenticate(&mut self) -> Result<u64> {
        loop {
            self.header().await?;
            let Some(parts) = &self.parts else {
                continue;
            };
            let (size, count) = (parts.size(), parts.count());
            if parts.has_opened() || self.file_whole {
                return Ok(size);
            }
            let standing = self.position / CHUNK_BYTES as u64;
            let index = if standing < count {
                standing
            } else {
                let mut held = self.window.any_chunk();
                let engine = self.engine();
                for holder in &self.holders {
                    if held.is_none() {
                        held = engine.any_held_chunk(holder, &self.entry.object).await;
                    }
                }
                held.filter(|at| *at < count)
                    .unwrap_or(count.saturating_sub(1))
            };
            self.chunk(index).await?;
        }
    }

    /// A read's error as [`Blobs::get`], [`Blobs::get_stream`],
    /// [`Blobs::get_range`] and [`Blobs::content_hash`] give it: for a
    /// chunk that every connection of the space gave up because what it
    /// was sent failed its checks, `ObjectMismatch`, as for a blob fetched
    /// whole before it is read.
    fn of_blob(&self, error: Error) -> Error {
        if self.gave_up {
            Error::Class("ObjectMismatch")
        } else {
            error
        }
    }

    /// Fails if the reader failed for good, or its blob was refused.
    fn check(&mut self) -> Result<()> {
        if let Some((class, first)) = self.window.refusal() {
            if first {
                report(&self.blobs, self.id);
            }
            self.failed.get_or_insert(class);
            self.opened = None;
        }
        // The header the reader built on was let go, with nothing opened
        // under it: it starts over with the next one.
        if self.parts.as_ref().is_some_and(|parts| !parts.has_opened())
            && self.window.epoch() != self.epoch
        {
            self.parts = None;
        }
        match self.failed {
            Some(class) => Err(Error::Class(class)),
            None => Ok(()),
        }
    }

    /// Whether something is connected that could send the blob.
    fn reachable(&self) -> bool {
        self.blobs.can_fetch()
            || self
                .blobs
                .space()
                .device
                .engine()
                .fetches()
                .taken(&self.space)
    }

    /// Waits until the object changes, the request for `index` ends,
    /// nothing is connected any more that could send it, or nothing
    /// arrives for too long. A request the space's connections gave up
    /// fails the read with a class of its own, which is not the blob's
    /// refusal: `Decrypt` or `Malformed` where what they were sent failed
    /// its checks, `Missing` where they were sent nothing. The read made
    /// again asks again ([`Window::renew`]). The error comes with whether
    /// the connections gave the chunk up for bytes that failed their
    /// checks.
    async fn wait(
        &self,
        index: u64,
        changed: &mut watch::Receiver<u64>,
    ) -> std::result::Result<(), (Error, bool)> {
        let mut idle = std::time::Duration::ZERO;
        let ends = self.window.ends(index);
        let ended = ended(ends);
        tokio::pin!(ended);
        loop {
            if !self.reachable() {
                return Err((Error::Class("Missing"), false));
            }
            if idle >= STALL {
                return Err((Error::Timeout, false));
            }
            tokio::select! {
                changed = changed.changed() => {
                    return changed.map_err(|_| (Error::Class("Missing"), false));
                }
                end = &mut ended => {
                    return Err(match end {
                        FetchEnd::Refused => (Error::Class("Decrypt"), true),
                        FetchEnd::Malformed => (Error::Class("Malformed"), false),
                        FetchEnd::Unserved => (Error::Class("Missing"), false),
                    });
                }
                () = self.blobs.space().device.sleep(POLL) => idle += POLL,
            }
        }
    }

    /// Makes the reader hold the object's header, checked: steps 1 to 3
    /// and 5 of units.md, 3.3. Fetched with the chunk the reader stands
    /// in when the device does not hold it.
    async fn header(&mut self) -> Result<()> {
        if self.parts.is_some() {
            return Ok(());
        }
        let engine = self.engine();
        let locator = self.entry.object;
        let mut changed = self.window.follow();
        let mut renew = true;
        loop {
            changed.borrow_and_update();
            self.check()?;
            let mut header = None;
            for holder in &self.holders {
                let holding = engine.holding(holder, &locator, 0..0).await;
                self.file |= holding.file;
                header = header.or(holding.header);
            }
            if let Some(header) = header.or_else(|| self.window.header()) {
                let parts = match &self.reference {
                    None => {
                        let key = engine.content_key_for(&self.space, &header).await;
                        PartReader::new(
                            &header,
                            &self.space,
                            Opening::ContentKey(key.as_deref()),
                            &locator,
                        )
                    }
                    Some((source, key)) => {
                        PartReader::new(&header, source, Opening::ObjectKey(key), &locator)
                    }
                }?;
                self.epoch = self.window.epoch();
                self.parts = Some(parts);
                return Ok(());
            }
            if self.local || self.file {
                return Err(Error::Class("Missing"));
            }
            // The chunk the reader stands in, by the size the entry
            // shows: the header travels with it. A request that ended
            // before this read is made again, once.
            let last = self.entry.size.saturating_sub(1);
            let index = self.position.min(last) / CHUNK_BYTES as u64;
            if std::mem::take(&mut renew) {
                self.window.renew();
            }
            self.window.want(
                &engine,
                &[(index..index.saturating_add(1), FetchPriority::Position)],
                index..index.saturating_add(1).saturating_add(self.read_ahead),
            );
            if let Err((error, gave_up)) = self.wait(index, &mut changed).await {
                // The blob's refusal, if it came meanwhile, decides.
                self.check()?;
                self.gave_up = gave_up;
                return Err(error);
            }
        }
    }

    /// The sealed chunk at `index`, from what the device stores or from
    /// the reader's window, and whether it is the store's.
    async fn sealed(&self, index: u64) -> Result<Option<(Arc<Vec<u8>>, bool)>> {
        let engine = self.blobs.space().device.engine();
        for holder in &self.holders {
            if let Some((_, chunk)) = engine.held_part(holder, &self.entry.object, index).await? {
                return Ok(Some((Arc::new(chunk), true)));
            }
        }
        Ok(self.window.chunk(index).map(|chunk| (chunk, false)))
    }

    /// Asks for the chunk at `index`, when the reader has neither it nor
    /// asked for it, ahead of everything else; and, once fewer than half
    /// the chunks read ahead are here or on their way, for the rest of
    /// them in one run, behind it. Everything else is let go. A run takes
    /// one slice more than it has chunks on the HTTP routes, where a
    /// chunk spans two slices, so the chunks ahead are asked for several
    /// at a time and not one by one. With `renew`, the requests that the
    /// space's connections gave up are let go first, so that their chunks
    /// are asked for again: once for each read, which so makes at most
    /// one new request for the chunk it waits for.
    async fn slide(&mut self, index: u64, renew: bool) {
        if self.local || self.file || self.stored_whole {
            return;
        }
        if renew {
            self.window.renew();
        }
        let Some(count) = self.parts.as_ref().map(PartReader::count) else {
            return;
        };
        let engine = self.engine();
        let end = index
            .saturating_add(1)
            .saturating_add(self.read_ahead)
            .min(count);
        let hold = index..end.max(index);
        let mut here = BTreeSet::new();
        for holder in &self.holders {
            let holding = engine
                .holding(holder, &self.entry.object, hold.clone())
                .await;
            self.stored_whole |= holding.whole || holding.file;
            here.extend(holding.chunks);
        }
        if self.stored_whole {
            self.window.want(&engine, &[], hold);
            return;
        }
        let (held, asked) = self.window.state(hold.clone());
        here.extend(held);
        let coming = |at: &u64| here.contains(at) || asked.contains(at);
        let mut runs = Vec::new();
        if !coming(&index) && index < end {
            runs.push((index..index + 1, FetchPriority::Position));
        }
        // The chunks after it that are here or on their way, in a row.
        let after = index.saturating_add(1);
        let reached = (after..end).find(|at| !coming(at)).unwrap_or(end);
        if reached < end && reached - after < (self.read_ahead / 2).max(1) {
            let until = (reached..end).find(|at| coming(at)).unwrap_or(end);
            runs.push((reached..until, FetchPriority::ReadAhead));
        }
        self.window.want(&engine, &runs, hold);
    }

    /// Makes the chunk at `index` the one opened: steps 4 and 6 of
    /// units.md, 3.3 on it, and for the last chunk of a read in order
    /// steps 0 and 7 on the whole, before any of it is given.
    async fn chunk(&mut self, index: u64) -> Result<()> {
        if self.opened.as_ref().is_some_and(|(at, _)| *at == index) {
            return Ok(());
        }
        if self.file {
            return self.file_chunk(index).await;
        }
        let mut changed = self.window.follow();
        let mut renew = true;
        loop {
            changed.borrow_and_update();
            self.check()?;
            let Some((sealed, stored)) = self.sealed(index).await? else {
                if self.local {
                    return Err(Error::Class("Missing"));
                }
                self.slide(index, std::mem::take(&mut renew)).await;
                if let Err((error, gave_up)) = self.wait(index, &mut changed).await {
                    // The blob's refusal, if it came meanwhile, decides.
                    self.check()?;
                    self.gave_up = gave_up;
                    return Err(error);
                }
                continue;
            };
            let Some(parts) = self.parts.as_mut() else {
                // Let go meanwhile: read again under the next header.
                return Err(Error::Class("Missing"));
            };
            let proved = parts.has_opened();
            match parts.open(index, &sealed, stored) {
                Ok(plain) => {
                    if !proved {
                        self.window.gave();
                    }
                    self.from_window |= !stored;
                    self.opened = Some((index, plain));
                    self.passed().await;
                    self.slide(index, renew).await;
                    return Ok(());
                }
                Err(error) => return Err(self.fault(index, stored, error).await),
            }
        }
    }

    /// Notes at the device that a read in order of the stored object
    /// passed every step, so that no later read runs them again.
    async fn passed(&mut self) {
        if !self.parts.as_ref().is_some_and(PartReader::passed_stored) {
            return;
        }
        let engine = self.engine();
        for holder in &self.holders {
            engine
                .passed_whole(holder, &self.entry.object, self.reference.is_none())
                .await;
        }
    }

    /// What a chunk that did not open, or a whole-object step that
    /// failed, does to the reader and to what the device holds.
    async fn fault(&mut self, index: u64, stored: bool, error: Error) -> Error {
        let engine = self.engine();
        let locator = self.entry.object;
        match self.parts.as_ref().and_then(PartReader::fault) {
            // The object is not what its locator names.
            Some(WholeFault::Object) => {
                let class = error.class_name().unwrap_or("ObjectMismatch");
                let _ = engine
                    .refuse_read(&self.space, &self.holders, &locator, class, true)
                    .await;
            }
            // The bytes read are not the object's, or a chunk given came
            // again as other bytes: it is not received.
            Some(WholeFault::Bytes | WholeFault::Given) => {
                let _ = engine
                    .refuse_read(
                        &self.space,
                        &self.holders,
                        &locator,
                        "ObjectMismatch",
                        false,
                    )
                    .await;
            }
            // Nothing has opened under this header, here or in another
            // reader, so nothing was given under it: the header and what
            // came under it are not known to be the object's. They go, no
            // reader fails, and the next read fetches them again.
            None if !self.window.given() => {
                if stored {
                    let _ = engine.drop_unopened(&self.holders, &locator).await;
                } else {
                    self.window.disown();
                }
                self.parts = None;
            }
            // A chunk the store holds that does not open is not the
            // object's: what is held of it goes, and is fetched again.
            None if stored => {
                let _ = engine
                    .refuse_read(
                        &self.space,
                        &self.holders,
                        &locator,
                        "ObjectMismatch",
                        false,
                    )
                    .await;
            }
            None => self.window.discard(index),
        }
        let _ = self.check();
        error
    }

    /// A chunk of a blob the application holds as a file, read through
    /// the file with its ID checked (at-rest.md, "Held objects").
    async fn file_chunk(&mut self, index: u64) -> Result<()> {
        let engine = self.engine();
        let mut plain = engine
            .plain(
                &self.space,
                &self.entry.object,
                key_of(&self.reference),
                index..index.saturating_add(1),
            )
            .await?;
        let (at, chunk) = plain.next().await?.ok_or(Error::Class("Missing"))?;
        self.opened = Some((at, chunk));
        self.file_whole = true;
        Ok(())
    }
}

impl Blobs {
    /// A read of a blob the device does not hold whole, in order from its
    /// first byte, through a reader: each piece is given as its chunk
    /// passes its checks, and the last chunk's only once every step of
    /// units.md, 3.3 passed on the whole.
    pub(super) async fn read_through(
        &self,
        id: BlobId,
        entry: Entry,
        read: &Read,
    ) -> Result<Through> {
        Ok(Through {
            reader: self.reader_of(id, entry, read).await?,
            at: 0,
        })
    }

    /// `len` bytes of a blob from `offset`, through a reader that fetches
    /// the chunks of that range alone.
    pub(super) async fn range_through(
        &self,
        id: BlobId,
        entry: Entry,
        offset: u64,
        len: u64,
        read: &Read,
    ) -> Result<Vec<u8>> {
        let mut reader = self.reader_of(id, entry, read).await?;
        let chunk = CHUNK_BYTES as u64;
        reader.seek(offset);
        let read = async {
            reader.set_read_ahead(0);
            let size = reader.fetch_size().await?;
            let end = offset.saturating_add(len).min(size);
            let mut out = Vec::new();
            let mut at = offset;
            while at < end {
                // The chunks of the range after this one, and no other.
                let ahead = end.div_ceil(chunk).saturating_sub(at / chunk + 1);
                reader.set_read_ahead(ahead.min(READ_AHEAD));
                let most = usize::try_from(end - at).unwrap_or(usize::MAX);
                let piece = reader.piece_at(at, most).await?;
                if piece.is_empty() {
                    break;
                }
                at += piece.len() as u64;
                out.extend_from_slice(piece);
            }
            Ok(out)
        }
        .await;
        let read = read.map_err(|error| reader.of_blob(error));
        reader.close().await?;
        read
    }
}

/// A read of a blob in order through a reader ([`Blobs::read_through`]).
pub(super) struct Through {
    reader: BlobReader,
    at: u64,
}

impl Through {
    /// The next piece of the blob: `None` after its last byte, once every
    /// step passed on the whole.
    pub(super) async fn next(&mut self) -> Result<Option<&[u8]>> {
        let at = self.at;
        let read = self.reader.piece_at(at, usize::MAX).await.map(<[u8]>::len);
        let read = read.map_err(|error| self.reader.of_blob(error))?;
        if read == 0 {
            // A read in order ends with every step passed: one that did
            // not gives nothing more, as one that failed them.
            return if self.reader.verified() == Verified::Whole {
                Ok(None)
            } else {
                Err(Error::Class("ObjectMismatch"))
            };
        }
        self.at += read as u64;
        Ok(self.reader.opened.as_ref().map(|(index, plain)| {
            let within = usize::try_from(at - index * CHUNK_BYTES as u64).unwrap_or(0);
            &plain[within.min(plain.len())..]
        }))
    }

    /// Ends the read ([`BlobReader::close`]).
    pub(super) async fn close(self) -> Result<()> {
        self.reader.close().await
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
mod tests;
