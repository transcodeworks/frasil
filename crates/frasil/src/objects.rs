//! Objects at a device (units.md, "Objects", "Reading an object"; at-rest.md,
//! the `object` table).
//!
//! An object is sealed under the device's current state, deterministically,
//! so that equal plaintexts under one state have one locator. The device
//! keeps its header and sealed chunks as parts of the `object` table (part
//! 0 the header, part `i + 1` chunk `i`), and reads it whole under the
//! state its header names. A unit names the objects it uses by locator, and
//! a writer uploads each before the unit that names it.
//!
//! A Blobs reference (adapter-blobs.md, "References") names an object
//! another space of the library stores, with the object's own key: the
//! device opens it with that key alone, from wherever it holds the bytes,
//! and uploads nothing, since a peer holds it for the space
//! (ext-libraries.md, "Holds").

use crate::at_rest::{Batch, Vault};
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::replica::Replica;
use crate::snapshots::ObjectPart;
use crate::sync::SyncSession;
use frasil_adapter::Locator;
use frasil_base::collect::CollectMap;
use frasil_events::{EventId, kind};
use frasil_keys::derive::Secret;
use frasil_store::{Table, TableValue};
use frasil_units::messages::SyncMessage;
use frasil_units::objects::{
    ObjectKeys, Opening, Parts, check_chunk, check_stored, read_object, read_object_parts,
    read_object_with_key, seal_object,
};
use std::collections::{BTreeMap, BTreeSet};

/// The most bytes of parts that a blob's unit commits with it under the
/// device's lock; a larger object's parts are written before it, without
/// the lock.
#[cfg(feature = "adapter-blobs")]
const OWN_COMMIT_BYTES: usize = 4 << 20;

/// The bytes of object parts a commit made without the device's lock holds
/// at most, but for one part larger than that.
const PIECE_BYTES: usize = 8 << 20;

/// How many chunks a check of a whole object's digest reads at once.
const DIGEST_BATCH: u64 = 8;

/// What a stream snapshot's plaintext holds besides its adapter state, at
/// most: the type, the stream ID, the flags and a move record, framed
/// (units.md, "Stream snapshots"). Generous: it only bounds a fetch.
pub(crate) const STATE_FRAMING_BYTES: u64 = 4096;

/// The length of one slice of an object's stored bytes on the HTTP chunk
/// routes (transport.md, "Objects over HTTP"): one sealed chunk's length,
/// the plaintext chunk and its nonce and tag.
#[cfg(any(feature = "server", feature = "server-socket", test))]
pub(crate) const SLICE_BYTES: usize = frasil_units::limits::SEALED_CHUNK_BYTES;

/// An object fetched by slices of its stored bytes (transport.md, "Objects
/// over HTTP"), cut into its sealed chunks as the slices arrive (units.md,
/// "Objects"). Every chunk but the last is exactly one slice long, so
/// chunk `i` is the tail of slice `i` after `4 + len(header)` bytes and
/// the first `4 + len(header)` bytes of slice `i + 1`. The reader keeps
/// only the bytes of the chunk not yet whole, less than one slice, and a
/// fetch that holds the first `k` chunks starts at slice `k`.
#[cfg(any(feature = "server", feature = "server-socket", test))]
#[derive(Debug)]
pub(crate) struct SliceReader {
    locator: Locator,
    /// The header's bytes and what they name, once read from slice 0 or
    /// held.
    header: Option<SlicedHeader>,
    /// The next slice to fetch.
    next_slice: u64,
    /// The next chunk to cut.
    next_chunk: u64,
    /// The bytes received of the next chunk.
    pending: Vec<u8>,
    /// Whether the next slice begins with bytes before the next chunk:
    /// the header in slice 0, or the tail of a chunk held already in a
    /// resumed fetch's first slice.
    skip_prefix: bool,
}

/// What a [`SliceReader`] knows from the header.
#[cfg(any(feature = "server", feature = "server-socket", test))]
#[derive(Debug)]
struct SlicedHeader {
    bytes: Vec<u8>,
    size: u64,
    /// `n`, the object's chunk count.
    count: u64,
    /// `4 + len(header)`: where chunk 0 starts.
    prefix: usize,
    /// The object's stored length: `4 + len(header) + size + 40 · n`.
    stored: u64,
}

#[cfg(any(feature = "server", feature = "server-socket", test))]
impl SlicedHeader {
    /// Reads a header, as units.md, "Reading an object", steps 2 and 3,
    /// do, and the layout it gives the stored bytes.
    fn read(locator: &Locator, bytes: Vec<u8>) -> Result<Self> {
        let header = frasil_units::objects::Header::read(&bytes).map_err(Error::class)?;
        if header.object_id != locator[..32] {
            return Err(Error::Class("ObjectMismatch"));
        }
        let prefix = bytes
            .len()
            .checked_add(4)
            .ok_or(Error::Class("Malformed"))?;
        // The header and its length fit in slice 0, before chunk 0.
        if prefix > SLICE_BYTES {
            return Err(Error::Class("Malformed"));
        }
        let count = frasil_units::objects::chunk_count(
            header.size,
            frasil_units::limits::CHUNK_BYTES as u64,
        );
        let stored = (prefix as u64)
            .checked_add(header.size)
            .and_then(|length| length.checked_add(count.checked_mul(CHUNK_OVERHEAD as u64)?))
            .ok_or(Error::Class("TooLarge"))?;
        Ok(Self {
            bytes,
            size: header.size,
            count,
            prefix,
            stored,
        })
    }

    /// The sealed length of chunk `index`.
    fn chunk_length(&self, index: u64) -> usize {
        let plain = frasil_units::objects::plain_length(
            self.size,
            frasil_units::limits::CHUNK_BYTES as u64,
            index,
        );
        // At most one chunk of plaintext, which fits.
        usize::try_from(plain).unwrap_or(usize::MAX) + CHUNK_OVERHEAD
    }

    /// The length of slice `index`.
    fn slice_length(&self, index: u64) -> u64 {
        self.stored
            .saturating_sub(index.saturating_mul(SLICE_BYTES as u64))
            .min(SLICE_BYTES as u64)
    }
}

#[cfg(any(feature = "server", feature = "server-socket", test))]
impl SliceReader {
    /// A fetch of `locator`, resumed after the `leading` first chunks
    /// held under `header` when the device holds any, or from slice 0.
    pub(crate) fn start(locator: Locator, held: Option<(Vec<u8>, u64)>) -> Self {
        let resumed = held
            .filter(|(_, leading)| *leading > 0)
            .and_then(|(bytes, leading)| {
                let header = SlicedHeader::read(&locator, bytes).ok()?;
                (leading < header.count).then_some((header, leading))
            });
        match resumed {
            Some((header, leading)) => Self {
                locator,
                header: Some(header),
                next_slice: leading,
                next_chunk: leading,
                pending: Vec::new(),
                skip_prefix: true,
            },
            None => Self {
                locator,
                header: None,
                next_slice: 0,
                next_chunk: 0,
                pending: Vec::new(),
                skip_prefix: true,
            },
        }
    }

    /// The next slice to fetch, or `None` once every slice is taken.
    pub(crate) fn next_slice(&self) -> Option<u64> {
        match &self.header {
            Some(header) if self.next_chunk >= header.count => None,
            _ => Some(self.next_slice),
        }
    }

    /// The stored bytes taken so far, counting the chunks held before,
    /// and the stored length once the header is read: a fetch's progress.
    pub(crate) fn progress(&self) -> (u64, Option<u64>) {
        match &self.header {
            Some(header) => (
                self.next_slice
                    .saturating_mul(SLICE_BYTES as u64)
                    .min(header.stored),
                Some(header.stored),
            ),
            None => (0, None),
        }
    }

    /// Takes the next slice: the parts it completes, in order, each to be
    /// checked as it is kept (units.md, "Reading an object", step 6).
    /// Slice 0 gives the header (steps 1 to 3); each slice must be of the
    /// length the header gives (step 4).
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `TooLarge` or `ObjectMismatch`.
    pub(crate) fn take(&mut self, slice: &[u8]) -> Result<Vec<ObjectPart>> {
        let index = self.next_slice;
        let mut body = slice;
        if self.header.is_none() {
            // 1. At least 4 bytes, and the header's length fits.
            let length = body
                .get(..4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                .and_then(|length| usize::try_from(length).ok())
                .ok_or(Error::Class("Malformed"))?;
            let bytes = body
                .get(4..4usize.saturating_add(length))
                .ok_or(Error::Class("Malformed"))?;
            self.header = Some(SlicedHeader::read(&self.locator, bytes.to_vec())?);
        }
        let header = self.header.as_ref().ok_or(Error::Class("Malformed"))?;
        if body.len() as u64 != header.slice_length(index) {
            return Err(Error::Class("Malformed"));
        }
        if std::mem::take(&mut self.skip_prefix) {
            body = body.get(header.prefix..).ok_or(Error::Class("Malformed"))?;
        }
        self.next_slice += 1;
        // Each chunk's bytes are gathered in a buffer of its own length,
        // which becomes the part once full.
        let mut parts = Vec::new();
        while self.next_chunk < header.count && !body.is_empty() {
            let length = header.chunk_length(self.next_chunk);
            if self.pending.is_empty() {
                self.pending.reserve_exact(length);
            }
            let take = (length - self.pending.len()).min(body.len());
            self.pending.extend_from_slice(&body[..take]);
            body = &body[take..];
            if self.pending.len() < length {
                break;
            }
            parts.push(ObjectPart {
                locator: self.locator,
                header: (self.next_chunk == 0).then(|| header.bytes.clone()),
                index: self.next_chunk,
                chunk: std::mem::take(&mut self.pending),
            });
            self.next_chunk += 1;
        }
        // The last slice ends with the last chunk.
        if !body.is_empty() {
            return Err(Error::Class("Malformed"));
        }
        Ok(parts)
    }
}

/// What sealing adds to a chunk's plaintext: its nonce and tag (units.md,
/// "Objects").
#[cfg(any(feature = "server", feature = "server-socket", test))]
const CHUNK_OVERHEAD: usize = 40;

/// What became of a part another party sent ([`Engine::receive_part`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Received {
    /// Kept; the object is not whole yet.
    Kept,
    /// The object is whole: with this part, or already.
    Whole,
    /// Refused: what the device held of the object is dropped, and it is
    /// asked of another party.
    Refused,
}

/// Whether a part fits the object it names (units.md, "Reading an
/// object", steps 2 to 4 and 6, by chunk): a header that reads, is the
/// header held if one is, and names the locator's object ID; and a chunk
/// that [`check_chunk`] takes under it, opened under the object's key
/// when the replica holds the key of the state the header names.
fn fits_object(replica: &Replica, space: &EventId, part: &ObjectPart) -> bool {
    let held = replica.object_header(&part.locator);
    let bytes = match (part.header.as_deref(), held) {
        (Some(new), Some(held)) if new != held => return false,
        (Some(new), _) => new,
        (None, Some(held)) => held,
        (None, None) => return false,
    };
    let Ok(header) = frasil_units::objects::Header::read(bytes) else {
        return false;
    };
    let object_key = replica
        .object_key(&header.key_reference)
        .map(|(key, _)| ObjectKeys::of(&key).object_key(&header.object_id));
    check_chunk(
        space,
        &header,
        &part.locator,
        part.index,
        &part.chunk,
        object_key.as_deref(),
    )
    .is_ok()
}

/// Reads chunks of an object back from the `object` table, by index:
/// `None` when one is missing or does not open.
pub(crate) async fn read_chunks(
    vault: &Vault,
    space: &EventId,
    locator: &Locator,
    indices: &[u64],
) -> Result<Option<BTreeMap<u64, Vec<u8>>>> {
    if indices.is_empty() {
        return Ok(Some(BTreeMap::new()));
    }
    let Some(reader) = vault.object_parts(&space.0) else {
        return Ok(None);
    };
    let parts = chunk_parts(indices)?;
    Ok(reader.read(&locator[..32], &parts).await?.map(|opened| {
        indices
            .iter()
            .zip(opened)
            .map(|(index, part)| (*index, part.value().to_vec()))
            .collect_map()
    }))
}

/// Streams a checkpoint record from the store, one sealed part at a time.
pub(crate) async fn read_stored_records(
    vault: &Vault,
    replica: &mut crate::replica::Replica,
    space: &EventId,
    locator: &Locator,
) -> Result<bool> {
    let requests = replica.stored_record_requests(locator);
    if requests.is_empty() {
        return Ok(false);
    }
    let Some((header, _)) = replica.stored_parts(locator) else {
        return Ok(true);
    };
    for request in requests {
        // Held across the reads below, so kept off this future's frame.
        let mut reader = Box::new(frasil_units::record_reader::RecordObjectReader::new(
            &header,
            space,
            request.key(),
            &request.binding,
        ));
        let mut sink = Box::new(frasil_space::RecordStream::new(request.mode));
        let indices = replica.record_indices(locator, request.store_only);
        if request.store_only
            && (0..reader.chunk_count().unwrap_or(0))
                .any(|index| indices.binary_search(&index).is_err())
        {
            continue;
        }
        for index in indices {
            if !request.store_only
                && let Some(sealed) = replica.record_chunk(locator, index)
            {
                reader.feed(index, sealed, &mut *sink);
                continue;
            }
            let Some(chunks) = read_chunks(vault, space, locator, &[index]).await? else {
                break;
            };
            if let Some(sealed) = chunks.get(&index) {
                reader.feed(index, sealed, &mut *sink);
            }
        }
        let result =
            frasil_units::record::RecordRead::finish(*reader, *sink, &request.part, request.handed);
        replica.keep_record_read(request.id, result);
    }
    Ok(true)
}

/// The parts of the `object` table that hold chunks by these indices.
fn chunk_parts(indices: &[u64]) -> Result<Vec<u32>> {
    indices.iter().map(|index| chunk_part(*index)).collect()
}

/// The part of the `object` table that holds chunk `index`: `index + 1`,
/// part 0 being the header (at-rest.md, the `object` table). The addition
/// is checked, so that no index takes the header's part.
///
/// # Errors
///
/// `TooLarge` for an index whose part does not fit 32 bits.
pub(crate) fn chunk_part(index: u64) -> Result<u32> {
    index
        .checked_add(1)
        .and_then(|part| u32::try_from(part).ok())
        .ok_or(Error::Class("TooLarge"))
}

/// A chunk of an object being read: held in memory, or opened from the
/// store in its record's buffer.
enum Chunk {
    Memory(Vec<u8>),
    Stored(frasil_store::OpenedObject),
}

impl Chunk {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Memory(bytes) => bytes,
            Self::Stored(opened) => opened.value(),
        }
    }
}

/// What reading a located object whole takes, gathered under the device's
/// lock so that the reading itself does not hold it: its header, the
/// chunks in memory, a reader for those in the store, and the key its
/// header names.
struct ObjectRead {
    header: Vec<u8>,
    memory: BTreeMap<u64, Vec<u8>>,
    stored: Vec<u64>,
    reader: Option<crate::at_rest::ObjectParts>,
    key: Option<Secret>,
}

impl ObjectRead {
    /// `None` while the replica does not hold the object whole, sealed, by
    /// a known locator.
    fn of(state: &crate::device::State, space: &EventId, locator: &Locator) -> Option<Self> {
        Self::of_range(state, space, locator, 0..u64::MAX)
    }

    /// [`of`](Self::of), for the chunks in a range of indices alone.
    fn of_range(
        state: &crate::device::State,
        space: &EventId,
        locator: &Locator,
        range: core::ops::Range<u64>,
    ) -> Option<Self> {
        let replica = state.replicas.get(space)?;
        if !replica.is_located(locator) {
            return None;
        }
        let (header, stored) = replica.stored_parts(locator)?;
        let key = frasil_units::objects::Header::read(&header)
            .ok()
            .and_then(|read| replica.object_key(&read.key_reference))
            .map(|(key, _)| key);
        let mut memory = replica.chunks_in_memory(locator);
        memory.retain(|index, _| range.contains(index));
        let stored: Vec<u64> = stored
            .into_iter()
            .filter(|index| range.contains(index) && !memory.contains_key(index))
            .collect();
        Some(Self {
            header,
            memory,
            reader: state.vault.object_parts(&space.0),
            stored,
            key,
        })
    }

    /// Reads the chunks in the store: the header and the chunks asked for,
    /// by index. `None` when one is missing or does not open.
    async fn read(
        self,
        locator: &Locator,
    ) -> Result<Option<(Vec<u8>, BTreeMap<u64, Chunk>, Option<Secret>)>> {
        let mut chunks: BTreeMap<u64, Chunk> = self
            .memory
            .into_iter()
            .map(|(index, bytes)| (index, Chunk::Memory(bytes)))
            .collect_map();
        if !self.stored.is_empty() {
            let Some(reader) = &self.reader else {
                return Ok(None);
            };
            let parts = chunk_parts(&self.stored)?;
            let Some(opened) = reader.read(&locator[..32], &parts).await? else {
                return Ok(None);
            };
            chunks.extend(
                self.stored
                    .iter()
                    .zip(opened)
                    .map(|(index, part)| (*index, Chunk::Stored(part))),
            );
        }
        Ok(Some((self.header, chunks, self.key)))
    }

    /// The object's stored bytes, whole.
    async fn bytes(self, locator: &Locator) -> Result<Option<Vec<u8>>> {
        let Some((header, chunks, _)) = self.read(locator).await? else {
            return Ok(None);
        };
        if chunks.keys().copied().ne(0..chunks.len() as u64) {
            return Ok(None);
        }
        let slices: Vec<&[u8]> = chunks.values().map(Chunk::bytes).collect();
        Ok(Parts {
            header: &header,
            chunks: &slices,
        }
        .to_bytes())
    }

    /// Reads the chunks in the store, then opens the object (units.md,
    /// "Reading an object", steps 0 to 7) with `opening`, or with the key
    /// its header names. `None` when a chunk is missing or does not open.
    async fn open(
        self,
        space: &EventId,
        locator: &Locator,
        opening: Option<Opening<'_>>,
    ) -> Result<Option<Vec<u8>>> {
        let Some((header, chunks, key)) = self.read(locator).await? else {
            return Ok(None);
        };
        // Every chunk, in order, from 0.
        if chunks.keys().copied().ne(0..chunks.len() as u64) {
            return Ok(None);
        }
        let slices: Vec<&[u8]> = chunks.values().map(Chunk::bytes).collect();
        let bytes = slices.iter().map(|chunk| chunk.len()).sum();
        let parts = Parts {
            header: &header,
            chunks: &slices,
        };
        let opening = opening.unwrap_or(Opening::ContentKey(key.as_deref()));
        read_object_parts(
            parts,
            space,
            opening,
            locator,
            crate::parallel::for_bytes(bytes),
        )
        .map(Some)
        .map_err(Error::class)
    }
}

/// How many chunks a chunk-by-chunk read takes from the store at once.
#[cfg(feature = "adapter-blobs")]
const READ_BATCH: u64 = 8;

/// An object's plaintext, from [`Engine::plain`]: chunk by chunk from the
/// store, or whole where the device holds it otherwise.
#[cfg(feature = "adapter-blobs")]
pub(crate) enum Plain {
    /// Chunk by chunk.
    Chunks(Box<PlainChunks>),
    /// Whole: a held object, or one the replica keeps in memory.
    Whole(Vec<u8>),
}

/// An object's plaintext chunk by chunk (units.md, 3.3 Reading an object).
/// Its chunks are plaintext the reader hands to the application, as
/// [`Engine::object`] hands the whole: they are not zeroized, which would
/// cost a large read a sixth of its time.
/// Step 0 passed before the first chunk is given; each chunk opens (step
/// 6) before it is given; a read of every chunk runs step 7 before it
/// gives the last one.
#[cfg(feature = "adapter-blobs")]
pub(crate) struct PlainChunks {
    engine: Engine,
    /// The space whose replica stores the object.
    holder: EventId,
    locator: Locator,
    reader: Option<frasil_units::objects::ChunkReader>,
    /// The next chunk to read from the store, and one past the last.
    next: u64,
    end: u64,
    /// Whether the read covers every chunk, so that step 7 runs.
    whole: bool,
    opened: std::collections::VecDeque<(u64, Vec<u8>)>,
}

#[cfg(feature = "adapter-blobs")]
impl PlainChunks {
    /// The next chunk, by index, with its plaintext; `None` after the last
    /// one asked for.
    ///
    /// # Errors
    ///
    /// `Missing` when a chunk is gone from the store meanwhile; `Decrypt`,
    /// `Malformed`, `ObjectMismatch`.
    pub(crate) async fn next(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        loop {
            if let Some(chunk) = self.opened.pop_front() {
                return Ok(Some(chunk));
            }
            if self.next >= self.end {
                return Ok(None);
            }
            let batch = self.next..self.end.min(self.next + READ_BATCH);
            let chunks = self
                .engine
                .stored_chunks(&self.holder, &self.locator, batch.clone())
                .await?
                .ok_or(Error::Class("Missing"))?;
            let reader = self.reader.as_mut().ok_or(Error::Class("Missing"))?;
            let count = reader.count();
            let sealed: Vec<(u64, &[u8])> = chunks
                .iter()
                .map(|(index, chunk)| (*index, chunk.bytes()))
                .collect();
            let bytes = sealed.iter().map(|(_, chunk)| chunk.len()).sum();
            let plain = reader
                .open_many(&sealed, crate::parallel::for_bytes(bytes))
                .map_err(Error::class)?;
            self.opened
                .extend(sealed.iter().map(|(index, _)| *index).zip(plain));
            self.next = batch.end;
            // Step 7 before the last chunk is given.
            if self.whole && self.next >= count {
                if let Some(reader) = self.reader.take() {
                    reader.finish().map_err(Error::class)?;
                }
                self.engine.mark_verified(self.holder, self.locator);
            }
        }
    }
}

#[cfg(feature = "adapter-blobs")]
impl Engine {
    /// The chunks of a stored object in a range of indices, every one of
    /// them, read without the device's lock; `None` when one is missing.
    async fn stored_chunks(
        &self,
        space: &EventId,
        locator: &Locator,
        range: core::ops::Range<u64>,
    ) -> Result<Option<BTreeMap<u64, Chunk>>> {
        let read = {
            let state = self.lock().await;
            ObjectRead::of_range(&state, space, locator, range.clone())
        };
        let Some(read) = read else {
            return Ok(None);
        };
        let Some((_, chunks, _)) = read.read(locator).await? else {
            return Ok(None);
        };
        Ok(chunks.keys().copied().eq(range).then_some(chunks))
    }

    /// An object's plaintext, chunk by chunk where the store holds it,
    /// for the chunks in `chunks` (units.md, 3.3 Reading an object): the
    /// object of `space`, or for a reference the object of its source
    /// opened with its object key. A read of some chunks only opens the
    /// object whole once first, unless a read this session did, so that
    /// every step ran on it.
    ///
    /// # Errors
    ///
    /// `Missing` while the device does not hold it whole; the object's
    /// classes.
    pub(crate) async fn plain(
        &self,
        space: &EventId,
        locator: &Locator,
        reference: Option<(EventId, [u8; 32])>,
        chunks: core::ops::Range<u64>,
    ) -> Result<Plain> {
        if reference.is_none() {
            self.hold_named_blobs(*space).await?;
        }
        let mut holders = vec![*space];
        holders.extend(reference.map(|(source, _)| source));
        let found = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            holders.into_iter().find_map(|holder| {
                let replica = state.replicas.get(&holder)?;
                if replica.is_held(locator) {
                    return None;
                }
                let checked = replica.is_checked(locator);
                let read = ObjectRead::of_range(&state, &holder, locator, 0..0)?;
                Some((holder, read.header, read.key, checked))
            })
        };
        let whole = || async {
            let bytes = match &reference {
                None => self.object(space, locator).await?,
                Some((source, key)) => self.referenced_object(space, locator, source, key).await?,
            };
            Ok(Plain::Whole(bytes))
        };
        let Some((holder, header, key, checked)) = found else {
            return whole().await;
        };
        let Ok(size) = frasil_units::objects::Header::read(&header).map(|h| h.size) else {
            return whole().await;
        };
        let count =
            frasil_units::objects::chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64);
        // 0. The stored bytes hash to the locator, before any plaintext
        // goes out.
        if !checked {
            let mut digest = frasil_crypto::primitives::Sha256Hasher::new();
            let length = u32::try_from(header.len()).map_err(|_| Error::Class("Malformed"))?;
            digest.update(&length.to_be_bytes());
            digest.update(&header);
            let mut at = 0;
            while at < count {
                let batch = at..count.min(at + READ_BATCH);
                let Some(chunks) = self.stored_chunks(&holder, locator, batch.clone()).await?
                else {
                    return whole().await;
                };
                for chunk in chunks.values() {
                    digest.update(chunk.bytes());
                }
                at = batch.end;
            }
            if digest.finish() != locator[32..] {
                return Err(Error::Class("ObjectMismatch"));
            }
            if let Some(replica) = self.lock().await.replicas.get_mut(&holder) {
                replica.mark_checked(locator);
            }
        }
        let (opens, opening) = match &reference {
            None => (
                *space,
                frasil_units::objects::Opening::ContentKey(key.as_deref()),
            ),
            Some((source, object_key)) => (
                *source,
                frasil_units::objects::Opening::ObjectKey(object_key),
            ),
        };
        let reader = frasil_units::objects::ChunkReader::new(&header, &opens, opening, locator)
            .map_err(Error::class)?;
        let wanted = chunks.start.min(count)..chunks.end.min(count);
        let mut plain = PlainChunks {
            engine: self.clone(),
            holder,
            locator: *locator,
            reader: Some(reader),
            next: wanted.start,
            end: wanted.end,
            whole: wanted == (0..count),
            opened: std::collections::VecDeque::new(),
        };
        if !plain.whole && !self.is_verified(&holder, locator) {
            // Every step once, keeping the chunks asked for.
            let mut all = PlainChunks {
                next: 0,
                end: count,
                whole: true,
                ..plain
            };
            let mut kept = std::collections::VecDeque::new();
            while let Some((index, chunk)) = all.next().await? {
                if wanted.contains(&index) {
                    kept.push_back((index, chunk));
                }
            }
            plain = PlainChunks {
                reader: None,
                next: wanted.end,
                end: wanted.end,
                whole: false,
                opened: kept,
                ..all
            };
        }
        Ok(Plain::Chunks(Box::new(plain)))
    }
}

/// An object's stored bytes from its header and every chunk, in order.
fn assemble(header: &[u8], chunks: &BTreeMap<u64, Vec<u8>>) -> Option<Vec<u8>> {
    let size = frasil_units::objects::Header::read(header).ok()?.size;
    let count = frasil_units::objects::chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64);
    let mut out = u32::try_from(header.len()).ok()?.to_be_bytes().to_vec();
    out.extend_from_slice(header);
    for index in 0..count {
        out.extend_from_slice(chunks.get(&index)?);
    }
    Some(out)
}

/// Puts one part of an object in the `object` table.
pub(crate) fn put_part(
    vault: &Vault,
    batch: &mut Batch,
    space: &EventId,
    part: &ObjectPart,
) -> Result<()> {
    let mut item = part.locator[..32].to_vec();
    if let Some(header) = &part.header {
        let mut header_item = item.clone();
        header_item.extend_from_slice(&0u32.to_be_bytes());
        vault.put(
            batch,
            &space.0,
            Table::Object,
            &header_item,
            &TableValue::Object(header.clone()),
        )?;
    }
    let index = chunk_part(part.index)?;
    item.extend_from_slice(&index.to_be_bytes());
    vault.put(
        batch,
        &space.0,
        Table::Object,
        &item,
        &TableValue::Object(part.chunk.clone()),
    )
}

/// Deletes an object's records from the `object` table: its header, and
/// the chunks the store holds by these indices.
pub(crate) fn delete_object_records(
    vault: &Vault,
    batch: &mut Batch,
    space: &EventId,
    locator: &Locator,
    stored: &BTreeSet<u64>,
) {
    let id = &locator[..32];
    vault.delete(
        batch,
        &space.0,
        Table::Object,
        &[id, &0u32.to_be_bytes()].concat(),
    );
    for index in stored {
        if let Ok(part) = chunk_part(*index) {
            vault.delete(
                batch,
                &space.0,
                Table::Object,
                &[id, &part.to_be_bytes()].concat(),
            );
        }
    }
}

/// The parts of an object's stored bytes: its header with the first chunk.
pub(crate) fn parts_of(locator: &Locator, stored: &[u8]) -> Result<Vec<ObjectPart>> {
    let checked = check_stored(stored, locator).map_err(Error::class)?;
    let header = checked.header.encode();
    Ok(checked
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| ObjectPart {
            locator: *locator,
            header: (index == 0).then(|| header.clone()),
            index: index as u64,
            chunk: chunk.to_vec(),
        })
        .collect())
}

/// A held object's plaintext (units.md, "Reading an object", steps 0 to
/// 7), opened under the state its header names.
///
/// # Errors
///
/// `Missing` while the replica does not hold it whole; `Sealed` without
/// that state's key; the object's classes.
/// Opens an object's stored bytes under its own state, as a replica holds
/// its key: [`open_held`], for the space snapshot found at open.
pub(crate) fn open_stored(
    replica: &Replica,
    space: &EventId,
    locator: &Locator,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    open_held(replica, space, locator, bytes)
}

fn open_held(
    replica: &Replica,
    space: &EventId,
    locator: &Locator,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let checked = check_stored(bytes, locator).map_err(Error::class)?;
    let (key, _) = replica
        .object_key(&checked.header.key_reference)
        .ok_or(Error::Class("Sealed"))?;
    read_object(bytes, space, Some(&key), locator).map_err(Error::class)
}

/// The key of an object that a space's entry names by locator and key
/// reference (units.md, "Objects"): derived from the state's content key.
///
/// # Errors
///
/// `Sealed` without that state's key.
#[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
pub(crate) fn object_key_in(
    replica: &Replica,
    key_reference: &[u8],
    locator: &Locator,
) -> Result<[u8; 32]> {
    let (key, _) = replica
        .object_key(key_reference)
        .ok_or(Error::Class("Sealed"))?;
    let id: [u8; 32] = locator[..32]
        .try_into()
        .map_err(|_| Error::Class("Malformed"))?;
    Ok(*ObjectKeys::of(&key).object_key(&id))
}

/// The locators the units of a replica name, by their visible key 5.
pub(crate) fn named_objects(replica: &Replica) -> BTreeSet<Locator> {
    let mut out = BTreeSet::new();
    let Some(log) = replica.log() else {
        return out;
    };
    for event in log.events() {
        if event.kind() != kind::UNIT {
            continue;
        }
        if let Ok(unit) = frasil_units::Unit::from_event(event.clone()) {
            out.extend(unit.body.objects.iter().copied());
        }
    }
    out
}

/// The objects a blob stream's entries name, past and current, without the
/// snapshots of those streams, which are Frasil's own.
#[cfg(feature = "adapter-blobs")]
fn blob_objects(replica: &Replica) -> BTreeSet<Locator> {
    use frasil_units::runtime::Stream;
    let streams: BTreeSet<_> = replica
        .streams()
        .filter(|(_, adapter)| *adapter == frasil_adapter_blobs::TYPE)
        .map(|(id, _)| *id)
        .collect();
    let mut out: BTreeSet<Locator> = streams
        .iter()
        .filter_map(|id| replica.stream(id))
        .filter_map(|stream| {
            stream
                .as_any()
                .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()
        })
        .flat_map(|blobs| blobs.state().current().map(|(_, entry)| entry.object))
        .collect();
    if let Some(log) = replica.log() {
        out.extend(
            log.events()
                .filter(|event| event.kind() == kind::UNIT)
                .filter_map(|event| frasil_units::Unit::from_event(event.clone()).ok())
                .filter(|unit| unit.body.compacts.is_none() && streams.contains(&unit.body.stream))
                .flat_map(|unit| unit.body.objects.to_vec()),
        );
    }
    out
}

#[cfg(not(feature = "adapter-blobs"))]
fn blob_objects(_: &Replica) -> BTreeSet<Locator> {
    BTreeSet::new()
}

impl Engine {
    /// Seals an object under the space's current state and keeps it
    /// (units.md, "Objects"). Equal plaintexts under one state give one
    /// locator.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] while the device holds
    /// no current state; `TooLarge`; the store's.
    pub async fn put_object(&self, space: EventId, plaintext: &[u8]) -> Result<Locator> {
        Ok(self.put_object_with(space, plaintext).await?.0)
    }

    /// [`Engine::put_object`], with the key reference its header names.
    async fn put_object_with(
        &self,
        space: EventId,
        plaintext: &[u8],
    ) -> Result<(Locator, Vec<u8>)> {
        let (locator, reference, parts) = self.seal_parts(space, plaintext).await?;
        let parts: Vec<&ObjectPart> = parts.iter().collect();
        self.store_parts(space, &parts, true).await?;
        Ok((locator, reference))
    }

    /// Seals an object under the space's current state, outside the
    /// device's lock: its locator, key reference and parts.
    async fn seal_parts(
        &self,
        space: EventId,
        plaintext: &[u8],
    ) -> Result<(Locator, Vec<u8>, Vec<ObjectPart>)> {
        let (reference, key) = {
            let state = self.lock().await;
            self.sealing(&state, &space)?
        };
        let sealed = seal_object(&space, &key, &reference, plaintext).map_err(Error::class)?;
        let parts = parts_of(&sealed.locator, &sealed.bytes)?;
        Ok((sealed.locator, reference, parts))
    }

    /// Keeps parts of an object, as an upload or a fetch carries them, in
    /// one commit under the device's lock.
    pub(crate) async fn keep_parts_in(
        state: &mut crate::device::State,
        space: EventId,
        parts: &[&ObjectPart],
    ) -> Result<()> {
        let mut batch = Batch::default();
        if !state.vault.has_log(&space.0) {
            state
                .vault
                .add_log(&mut batch, &space.0, frasil_store::tables::LogKind::Space)?;
        }
        for part in parts {
            put_part(&state.vault, &mut batch, &space, part)?;
        }
        state.vault.commit(batch).await?;
        Self::note_parts(state, space, parts, false).await
    }

    /// Keeps parts of objects: sealed and committed without the device's
    /// lock while the store keeps the log, so that writes go on during a
    /// transfer, then noted under it; otherwise as
    /// [`keep_parts_in`](Self::keep_parts_in). `checked` says the parts are
    /// an object this device sealed, whose bytes hash to its locator.
    pub(crate) async fn store_parts(
        &self,
        space: EventId,
        parts: &[&ObjectPart],
        checked: bool,
    ) -> Result<()> {
        if parts.is_empty() {
            return Ok(());
        }
        let writer = {
            let mut state = self.lock().await;
            match state.vault.object_writer(&space.0) {
                Some(writer) => writer,
                None => return Self::keep_parts_in(&mut state, space, parts).await,
            }
        };
        let sealed = writer.seal(parts)?;
        let addresses: Vec<Vec<u8>> = sealed.iter().map(|(address, _)| address.clone()).collect();
        // In commits of a few chunks, so that a write that commits
        // meanwhile waits for one of them at most.
        let mut sealed = sealed.into_iter().peekable();
        while sealed.peek().is_some() {
            let mut bytes = 0;
            let mut piece = Vec::new();
            while let Some(next) = sealed.next_if(|_| bytes < PIECE_BYTES) {
                bytes += next.1.len();
                piece.push(next);
            }
            writer.commit(piece).await?;
        }
        let mut state = self.lock().await;
        if !writer.is_current(&state.vault) {
            // The log was forgotten or kept in memory meanwhile: what was
            // written is no one's.
            let _ = writer.forget(addresses).await;
            return Ok(());
        }
        Self::note_parts(&mut state, space, parts, checked).await
    }

    /// Notes parts of objects the store or memory now holds, and uses what
    /// they complete.
    async fn note_parts(
        state: &mut crate::device::State,
        space: EventId,
        parts: &[&ObjectPart],
        checked: bool,
    ) -> Result<()> {
        let at_rest = !state.vault.is_memory_only(&space.0);
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        replica.set_chunks_at_rest(at_rest);
        for part in parts {
            replica.keep_part(part);
        }
        if checked {
            for part in parts {
                replica.mark_checked(&part.locator);
            }
        }
        // A snapshot whose object was missing may now be used, read back
        // from the store.
        replica.take_snapshots();
        if Self::fill_wanted(state, &space).await?
            && let Some(replica) = state.replicas.get_mut(&space)
        {
            replica.take_snapshots();
            replica.release_chunks();
        }
        Ok(())
    }

    /// Keeps parts of an object another party sent. Once the newcomer's
    /// snapshot it awaits is whole, the device uses it; once a stream
    /// snapshot object it names is, the device loads that stream. An
    /// object these parts make whole is checked against its locator's
    /// digest first (units.md, "Reading an object", step 0): one that
    /// fails is dropped, and is missing again.
    #[cfg_attr(not(feature = "space-files"), allow(dead_code))]
    pub(crate) async fn keep_parts(&self, space: EventId, parts: &[ObjectPart]) -> Result<()> {
        Box::pin(self.keep_parts_with(space, parts, false))
            .await
            .map(drop)
    }

    /// [`keep_parts`](Self::keep_parts) for the parts of whole objects
    /// whose stored bytes were found to hash to their locators already
    /// ([`parts_of`]).
    pub(crate) async fn keep_checked_parts(
        &self,
        space: EventId,
        parts: &[ObjectPart],
    ) -> Result<()> {
        Box::pin(self.keep_parts_with(space, parts, true))
            .await
            .map(drop)
    }

    /// One part of an object another party sent, as sync carries it
    /// (units.md, "Sync", objects): checked as it arrives, then kept. Of
    /// an object the device holds whole, nothing is taken. A part is
    /// refused when it names no header the device can check it against,
    /// when its header differs from the one held, or when the chunk fails
    /// [`check_chunk`] under that header, opened under the object's key
    /// when the device holds it; once the object is whole, it is checked
    /// against its locator's digest, which needs no key. A refused part
    /// drops what the device held of the object, so that it is missing
    /// again and asked of another party.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    pub(crate) async fn receive_part(&self, space: EventId, part: ObjectPart) -> Result<Received> {
        let fits = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            if replica.holds_object(&part.locator) {
                return Ok(Received::Whole);
            }
            fits_object(replica, &space, &part)
        };
        if !fits {
            let mut state = self.lock().await;
            Self::drop_object(&mut state, space, &part.locator).await?;
            return Ok(Received::Refused);
        }
        // A state object whose header names more than its adapter loads is
        // fetched no further. Once the first chunk opened under the
        // object's key, the size is the writer's (it is in every chunk's
        // associated data), and the snapshot that names it has its verdict.
        if let Some(header) = &part.header
            && let Some(limit) = self.state_limit(&space, &part.locator).await
            && let Ok(read) = frasil_units::objects::Header::read(header)
            && read.size > limit
        {
            let mut state = self.lock().await;
            Self::drop_object(&mut state, space, &part.locator).await?;
            if let Some(replica) = state.replicas.get_mut(&space)
                && replica.object_key(&read.key_reference).is_some()
            {
                replica.refuse_oversized_state(part.locator);
            }
            return Ok(Received::Refused);
        }
        let locator = part.locator;
        let dropped =
            Box::pin(self.keep_parts_with(space, std::slice::from_ref(&part), false)).await?;
        if dropped.contains(&locator) {
            return Ok(Received::Refused);
        }
        let whole = self
            .read(&space, |replica| replica.holds_object(&locator))
            .await?;
        Ok(if whole {
            Received::Whole
        } else {
            Received::Kept
        })
    }

    /// Forgets an object the device held part of, and deletes its records:
    /// it is missing again.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_object(
        state: &mut crate::device::State,
        space: EventId,
        locator: &Locator,
    ) -> Result<()> {
        let Some(replica) = state.replicas.get_mut(&space) else {
            return Ok(());
        };
        let Some(stored) = replica.forget_object(locator) else {
            return Ok(());
        };
        let mut batch = Batch::default();
        delete_object_records(&state.vault, &mut batch, &space, locator, &stored);
        state.vault.commit(batch).await
    }

    /// Whether an object the replica holds whole, sealed, hashes to its
    /// locator (units.md, "Reading an object", step 0), read a few chunks
    /// at a time: `None` when it cannot be read.
    async fn whole_digest(
        state: &mut crate::device::State,
        space: &EventId,
        locator: &Locator,
    ) -> Result<Option<bool>> {
        let Some(replica) = state.replicas.get(space) else {
            return Ok(None);
        };
        let Some((header, _)) = replica.stored_parts(locator) else {
            return Ok(None);
        };
        let Ok(read) = frasil_units::objects::Header::read(&header) else {
            return Ok(Some(false));
        };
        let count =
            frasil_units::objects::chunk_count(read.size, frasil_units::limits::CHUNK_BYTES as u64);
        let memory = replica.chunks_in_memory(locator);
        let mut digest = frasil_crypto::primitives::Sha256Hasher::new();
        let length = u32::try_from(header.len()).map_err(|_| Error::Class("Malformed"))?;
        digest.update(&length.to_be_bytes());
        digest.update(&header);
        let mut at = 0;
        while at < count {
            let end = count.min(at.saturating_add(DIGEST_BATCH));
            let wanted: Vec<u64> = (at..end).filter(|i| !memory.contains_key(i)).collect();
            let Some(read) = read_chunks(&state.vault, space, locator, &wanted).await? else {
                return Ok(None);
            };
            for index in at..end {
                let Some(chunk) = memory.get(&index).or_else(|| read.get(&index)) else {
                    return Ok(None);
                };
                digest.update(chunk);
            }
            at = end;
        }
        Ok(Some(digest.finish() == locator[32..]))
    }

    /// [`keep_parts`](Self::keep_parts): the objects dropped because,
    /// whole, they did not hash to their locators.
    async fn keep_parts_with(
        &self,
        space: EventId,
        parts: &[ObjectPart],
        checked: bool,
    ) -> Result<BTreeSet<Locator>> {
        let sealed = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            // Under `held`, a blob's parts go through the provider instead
            // (at-rest.md, "Held objects", receiving).
            let (held, mut sealed): (Vec<&ObjectPart>, Vec<&ObjectPart>) = parts
                .iter()
                .partition(|part| self.receives_held(&state, &space, &part.locator));
            for part in held {
                if !self.receive_held_part(&mut state, space, part).await? {
                    sealed.push(part);
                }
            }
            sealed
        };
        // The chunks are sealed and written while the device goes on.
        self.store_parts(space, &sealed, checked).await?;
        let mut state = self.lock().await;
        // Each object these parts made whole hashes to its locator, or is
        // no one's: dropped before anything uses it.
        let mut dropped = BTreeSet::new();
        if !checked {
            let completed: BTreeSet<Locator> = {
                let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                parts
                    .iter()
                    .map(|part| part.locator)
                    .filter(|locator| {
                        replica.holds_object(locator)
                            && !replica.is_held(locator)
                            && !replica.is_checked(locator)
                    })
                    .collect()
            };
            for locator in completed {
                match Self::whole_digest(&mut state, &space, &locator).await? {
                    Some(true) => {
                        if let Some(replica) = state.replicas.get_mut(&space) {
                            replica.mark_checked(&locator);
                        }
                    }
                    Some(false) => {
                        Self::drop_object(&mut state, space, &locator).await?;
                        dropped.insert(locator);
                    }
                    None => {}
                }
            }
        }
        let (awaited, streams, records) = {
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            // Blob feeds hear of each object these parts made whole.
            let arrived: BTreeSet<Locator> = parts
                .iter()
                .map(|part| part.locator)
                .filter(|locator| replica.holds_object(locator))
                .collect();
            for locator in arrived {
                self.arrived(space, locator);
            }
            let whole = |locator: &Locator| {
                parts.iter().any(|p| p.locator == *locator)
                    && replica.holds_object(locator)
                    && !replica.is_held(locator)
            };
            (
                replica.awaited_snapshot().copied().filter(|l| whole(l)),
                replica.pending_stream_objects().any(whole),
                // A checkpoint's record object: the view is judged again
                // with it (roster.md, "The record object").
                replica
                    .checkpoint_facts()
                    .records_wanted()
                    .iter()
                    .any(whole),
            )
        };
        if let Some(locator) = awaited {
            let bytes = Self::stored_bytes(&mut state, &space, &locator).await?;
            // A newcomer to a restricted space learns its parent from the
            // snapshot's reference (ext-restricted-spaces.md).
            #[cfg(feature = "ext-restricted-spaces")]
            if let Some(reference) = bytes.as_ref().and_then(|bytes| {
                check_stored(bytes, &locator)
                    .ok()
                    .map(|checked| checked.header.key_reference.to_vec())
            }) {
                crate::restricted::learn_parent(&mut state, &space, &reference);
            }
            let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
            // Bytes that could not be read back leave the wait as it is.
            if let Some(bytes) = bytes {
                let signed = open_held(replica, &space, &locator, &bytes);
                replica.snapshot_taken();
                // Its bytes hash to the locator the welcome named, so one
                // that does not open or read is no snapshot: the newcomer
                // asks a member for one.
                if let Ok(signed) = signed
                    && let Ok(adopted) =
                        Self::adopt_in(&mut state, space, &signed, Vec::new()).await
                {
                    self.adopt_granted(&mut state, adopted).await?;
                }
            }
        }
        if awaited.is_some() || streams || records {
            let reading = self.read_timeline(&mut state).await?;
            Box::pin(self.settle_one(&mut state, space, Vec::new(), reading)).await?;
        }
        drop(state);
        // A blob whose entry is current now, stored sealed, is held.
        self.hold_named_blobs(space).await?;
        Ok(dropped)
    }

    /// Keeps an object another party handed over whole, by its stored
    /// bytes (units.md, "Reading an object", steps 0 to 4).
    ///
    /// # Errors
    ///
    /// `ObjectMismatch` or `Malformed`; the store's.
    pub async fn receive_object(
        &self,
        space: EventId,
        locator: &Locator,
        stored: &[u8],
    ) -> Result<()> {
        let parts = parts_of(locator, stored)?;
        self.keep_checked_parts(space, &parts).await
    }

    /// An object's stored bytes, once the device holds them whole: as the
    /// store keeps them, or sealed again from the plaintext the application
    /// holds (at-rest.md, "Held objects").
    pub async fn stored_object(&self, space: &EventId, locator: &Locator) -> Option<Vec<u8>> {
        if let Some(bytes) = self.sealed_object(space, locator).await {
            return Some(bytes);
        }
        self.held_bytes(space, locator).await
    }

    /// An object's stored bytes as the store keeps them, once whole.
    pub(crate) async fn sealed_object(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<Vec<u8>> {
        let read = {
            let mut state = self.lock().await;
            match ObjectRead::of(&state, space, locator) {
                Some(read) => read,
                None => {
                    return Self::stored_bytes(&mut state, space, locator)
                        .await
                        .ok()
                        .flatten();
                }
            }
        };
        // Read without the device's lock.
        read.bytes(locator).await.ok().flatten()
    }

    /// The parts of an object from chunk `first`, `count` of them, to serve
    /// to another party: the header with chunk 0. Once its stored bytes
    /// were found to hash to its locator, only those chunks are read,
    /// without the device's lock; until then, the object is read whole and
    /// checked first. `None` while the device does not hold it sealed.
    ///
    /// # Errors
    ///
    /// The object's classes when its bytes do not check
    /// ([`check_stored`]); the store's.
    pub(crate) async fn serve_parts(
        &self,
        space: &EventId,
        locator: &Locator,
        first: u64,
        count: u64,
    ) -> Result<Option<Vec<ObjectPart>>> {
        let range = first..first.saturating_add(count);
        let read = {
            let state = self.lock().await;
            state
                .replicas
                .get(space)
                .filter(|replica| replica.is_checked(locator))
                .and_then(|_| ObjectRead::of_range(&state, space, locator, range.clone()))
        };
        if let Some(read) = read {
            let Some((header, chunks, _)) = read.read(locator).await? else {
                return Ok(None);
            };
            return Ok(Some(
                chunks
                    .into_iter()
                    .map(|(index, chunk)| ObjectPart {
                        locator: *locator,
                        header: (index == 0).then(|| header.clone()),
                        index,
                        chunk: match chunk {
                            Chunk::Memory(bytes) => bytes,
                            Chunk::Stored(opened) => opened.value().to_vec(),
                        },
                    })
                    .collect(),
            ));
        }
        let Some(stored) = self.sealed_object(space, locator).await else {
            return Ok(None);
        };
        let parts = parts_of(locator, &stored)?;
        if let Some(replica) = self.lock().await.replicas.get_mut(space) {
            replica.mark_checked(locator);
        }
        Ok(Some(
            parts
                .into_iter()
                .filter(|part| range.contains(&part.index))
                .collect(),
        ))
    }

    /// An object's stored bytes, once the replica holds it whole: from
    /// memory, or read back from the store. An object found in the store at
    /// load gets its locator here, by hashing what was read; bytes that
    /// hash to another locator than the one asked for are not this object.
    pub(crate) async fn stored_bytes(
        state: &mut crate::device::State,
        space: &EventId,
        locator: &Locator,
    ) -> Result<Option<Vec<u8>>> {
        Ok(Self::stored_located(state, space, locator)
            .await?
            .filter(|(found, _)| found == locator)
            .map(|(_, bytes)| bytes))
    }

    /// [`stored_bytes`](Self::stored_bytes) of an object the store holds
    /// whole, by its ID alone where its locator is not known yet: its
    /// locator, found from its bytes, and the bytes.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn stored_located(
        state: &mut crate::device::State,
        space: &EventId,
        locator: &Locator,
    ) -> Result<Option<(Locator, Vec<u8>)>> {
        let Some(replica) = state.replicas.get(space) else {
            return Ok(None);
        };
        if let Some(bytes) = replica.object(locator) {
            return Ok(Some((*locator, bytes)));
        }
        let Some((header, stored)) = replica.stored_parts(locator) else {
            return Ok(None);
        };
        let mut chunks = replica.chunks_in_memory(locator);
        let unknown = !replica.is_located(locator);
        let missing: Vec<u64> = stored
            .into_iter()
            .filter(|index| !chunks.contains_key(index))
            .collect();
        let Some(read) = read_chunks(&state.vault, space, locator, &missing).await? else {
            return Ok(None);
        };
        chunks.extend(read);
        let Some(bytes) = assemble(&header, &chunks) else {
            return Ok(None);
        };
        if unknown {
            let mut found = [0; 64];
            found[..32].copy_from_slice(&locator[..32]);
            found[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&bytes]));
            let replica = state.replicas.get_mut(space).ok_or(Error::UnknownSpace)?;
            replica.locate(found);
            return Ok(Some((found, bytes)));
        }
        Ok(Some((*locator, bytes)))
    }

    /// Reads back into memory the objects a replica needed whose chunks
    /// are in the store: `true` if it needed any.
    pub(crate) async fn fill_wanted(
        state: &mut crate::device::State,
        space: &EventId,
    ) -> Result<bool> {
        let Some(replica) = state.replicas.get_mut(space) else {
            return Ok(false);
        };
        let wanted: Vec<(Locator, Vec<u64>)> = replica
            .take_wanted_at_rest()
            .into_iter()
            .filter_map(|locator| Some((locator, replica.stored_parts(&locator)?.1)))
            .collect();
        if wanted.is_empty() {
            return Ok(false);
        }
        for (locator, indices) in wanted {
            if let Some(replica) = state.replicas.get_mut(space)
                && Box::pin(read_stored_records(&state.vault, replica, space, &locator)).await?
            {
                continue;
            }
            if let Some(chunks) = read_chunks(&state.vault, space, &locator, &indices).await?
                && let Some(replica) = state.replicas.get_mut(space)
            {
                replica.fill_chunks(&locator, chunks);
            }
        }
        Ok(true)
    }

    /// Finds the locator of each object of a space the store holds whole
    /// whose locator is not yet known, by reading and hashing it.
    pub(crate) async fn locate_objects(
        state: &mut crate::device::State,
        space: &EventId,
    ) -> Result<()> {
        let ids = match state.replicas.get(space) {
            Some(replica) => replica.unlocated(),
            None => return Ok(()),
        };
        for id in ids {
            let mut locator = [0; 64];
            locator[..32].copy_from_slice(&id);
            // A record's signed checkpoint supplies its locator. Its streaming
            // read verifies that locator without a separate pass over the store.
            if state
                .replicas
                .get(space)
                .and_then(|replica| replica.object_header(&locator))
                .and_then(|header| frasil_units::objects::Header::read(header).ok())
                .is_some_and(|header| header.self_reference().is_some())
            {
                continue;
            }
            // Read with a locator of unknown hash: the object is located
            // under the one its bytes give.
            Self::stored_bytes(state, space, &locator).await?;
        }
        Ok(())
    }

    /// An object's plaintext (units.md, "Reading an object", steps 0 to 7),
    /// opened under the state its header names: see [`open_held`].
    ///
    /// # Errors
    ///
    /// `Missing` while the device does not hold it whole; `Sealed` without
    /// that state's key; the object's classes.
    pub async fn object(&self, space: &EventId, locator: &Locator) -> Result<Vec<u8>> {
        self.hold_named_blobs(*space).await?;
        let read = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
            if replica.is_held(locator) {
                None
            } else if let Some(read) = ObjectRead::of(&state, space, locator) {
                Some(read)
            } else {
                // Not whole, or found in the store with its locator not yet
                // known: read and located under the lock.
                let bytes = Self::stored_bytes(&mut state, space, locator)
                    .await?
                    .ok_or(Error::Class("Missing"))?;
                let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
                return open_held(replica, space, locator, &bytes);
            }
        };
        // The chunks are read and opened without the device's lock.
        if let Some(read) = read {
            return read
                .open(space, locator, None)
                .await?
                .ok_or(Error::Class("Missing"));
        }
        self.held_plaintext(space, locator)
            .await?
            .ok_or(Error::Class("Missing"))
    }

    /// A referenced object's plaintext (units.md, "Reading an object", by a
    /// reader that holds the object key): its bytes as this space or the
    /// source holds them, opened with the key and the source's ID.
    ///
    /// # Errors
    ///
    /// `Missing` while the device holds it in neither; the object's
    /// classes.
    pub async fn referenced_object(
        &self,
        space: &EventId,
        locator: &Locator,
        source: &EventId,
        object_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let read = {
            let mut state = self.lock().await;
            let mut found = None;
            for id in [space, source] {
                if let Some(read) = ObjectRead::of(&state, id, locator) {
                    found = Some(Ok(read));
                    break;
                }
                if let Some(bytes) = Self::stored_bytes(&mut state, id, locator).await? {
                    found = Some(Err(bytes));
                    break;
                }
            }
            found
        };
        match read {
            Some(Ok(read)) => {
                if let Some(plaintext) = read
                    .open(source, locator, Some(Opening::ObjectKey(object_key)))
                    .await?
                {
                    return Ok(plaintext);
                }
            }
            Some(Err(bytes)) => {
                return read_object_with_key(&bytes, source, object_key, locator)
                    .map_err(Error::class);
            }
            None => {}
        }
        // Held in this space, or in the source.
        for id in [space, source] {
            if let Some(plaintext) = self.held_plaintext(id, locator).await? {
                return Ok(plaintext);
            }
        }
        Err(Error::Class("Missing"))
    }

    /// The source and object key of a current reference entry of a space
    /// that names this locator, in any of its blob streams.
    #[cfg(feature = "adapter-blobs")]
    pub async fn reference_of(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<(EventId, [u8; 32])> {
        use frasil_units::runtime::Stream;
        let state = self.lock().await;
        let replica = state.replicas.get(space)?;
        replica
            .streams()
            .filter(|(_, adapter)| *adapter == frasil_adapter_blobs::TYPE)
            .filter_map(|(id, _)| {
                replica
                    .stream(id)?
                    .as_any()
                    .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()
            })
            .flat_map(|blobs| blobs.state().current())
            .filter(|(_, entry)| entry.object == *locator)
            .find_map(|(_, entry)| {
                entry
                    .reference
                    .as_ref()
                    .map(|reference| (EventId(reference.source), reference.object_key))
            })
    }

    /// The objects the space's units name that the device does not hold
    /// whole.
    pub async fn missing_objects(&self, space: &EventId) -> Vec<Locator> {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let Some(replica) = state.replicas.get(space) else {
            return Vec::new();
        };
        let mut named = named_objects(replica);
        // The newcomer's snapshot, and the stream snapshot objects it names
        // (admission.md, "The newcomer's snapshot").
        named.extend(replica.awaited_snapshot().copied());
        named.extend(replica.pending_stream_objects().copied());
        // The record objects of the checkpoints the replica cannot read yet
        // (roster.md, "The record object").
        named.extend(replica.checkpoint_facts().records_wanted());
        // The objects of the blob streams' current entries, references
        // among them, which a stream loaded from a snapshot names in no
        // unit the device holds.
        #[cfg(feature = "adapter-blobs")]
        named.extend(
            replica
                .streams()
                .filter(|(_, adapter)| *adapter == frasil_adapter_blobs::TYPE)
                .filter_map(|(id, _)| {
                    replica
                        .stream(id)?
                        .as_any()
                        .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_blobs::Blobs>>(
                        )
                })
                .flat_map(|blobs| blobs.state().current().map(|(_, entry)| entry.object)),
        );
        let on_demand = if self.objects_on_demand() {
            blob_objects(replica)
        } else {
            BTreeSet::new()
        };
        named
            .into_iter()
            .filter(|locator| !replica.holds_object(locator))
            .filter(|locator| !replica.is_oversized_state(locator))
            .filter(|locator| !on_demand.contains(locator) || state.held.asked_for(space, locator))
            .collect()
    }

    /// The largest plaintext a state object may name in its header, when
    /// `locator` is one this replica may load (a newcomer's stream entry,
    /// or a snapshot unit's object) and its adapter has a limit: the
    /// adapter's largest state, and the stream snapshot's framing around
    /// it (units.md, "Stream snapshots"). A fetch asks for its header
    /// first, and goes no further when the header names more.
    pub(crate) async fn state_limit(&self, space: &EventId, locator: &Locator) -> Option<u64> {
        let type_ = self
            .read(space, |replica| replica.state_object_type(locator))
            .await
            .ok()
            .flatten()?;
        self.registry()
            .max_state_bytes(&type_)
            .map(|max| max.saturating_add(STATE_FRAMING_BYTES))
    }

    /// Where a fetch of an object by slices resumes: the header the device
    /// holds of it, and how many of its first chunks it holds, in memory or
    /// in the store. `None` when it holds no chunk of it sealed, or holds
    /// it whole.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    pub(crate) async fn leading_chunks(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<(Vec<u8>, u64)> {
        let state = self.lock().await;
        let replica = state.replicas.get(space)?;
        if replica.holds_object(locator) || replica.is_held(locator) {
            return None;
        }
        let header = replica.object_header(locator)?.to_vec();
        let (held, _) = replica.object_progress(locator)?;
        if held == 0 {
            return None;
        }
        // The store's chunks, by the object's locator, or by its ID while
        // the locator is not known yet.
        let mut indices: BTreeSet<u64> = replica.stored_chunks_of(locator);
        if (indices.len() as u64) < held {
            indices.extend(replica.chunks_in_memory(locator).into_keys());
        }
        let leading = (0u64..).take_while(|index| indices.contains(index)).count() as u64;
        Some((header, leading))
    }

    /// Drops what the device held of an object a fetch found malformed:
    /// it is missing again.
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    pub(crate) async fn drop_fetched(&self, space: EventId, locator: &Locator) -> Result<()> {
        let mut state = self.lock().await;
        Self::drop_object(&mut state, space, locator).await
    }

    /// `ObjectHave` for every object of a space the device holds whole,
    /// which a member it admits may then ask it for (units.md, "Sync",
    /// objects): a newcomer that starts from a snapshot reaches objects
    /// written before its admission.
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) async fn whole_objects_have(&self, space: &EventId) -> Vec<SyncMessage> {
        // Each held object is checked against its provider first, and a
        // reference is never announced (at-rest.md, "Held objects").
        let announced = self.announce_held(space).await;
        {
            let mut state = self.lock().await;
            // An object whose bytes cannot be read is not announced.
            let _ = Self::locate_objects(&mut state, space).await;
        }
        let mut locators = self
            .read(space, |replica| {
                replica
                    .whole_objects()
                    .into_iter()
                    .filter(|l| !replica.is_held(l))
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();
        locators.extend(announced);
        locators.sort_unstable();
        locators.dedup();
        locators
            .chunks(frasil_units::limits::MAX_MESSAGE_ITEMS)
            .map(|chunk| SyncMessage {
                space: *space,
                message: frasil_units::messages::Message::ObjectHave {
                    locators: chunk.to_vec(),
                    counts: None,
                },
            })
            .collect()
    }

    /// `ObjectWant` for the objects a session's other side announced that
    /// the device now finds missing: a snapshot, a stream snapshot object
    /// or new units may name objects announced before.
    pub(crate) async fn want_announced(&self, session: &mut SyncSession) -> Vec<SyncMessage> {
        let space = session.space();
        {
            let state = self.lock().await;
            if let Some(replica) = state.replicas.get(&space) {
                session.forget_announced(|locator| replica.holds_object(locator));
            }
        }
        if session.announced().is_empty() {
            return Vec::new();
        }
        let wanted: Vec<Locator> = self
            .missing_objects(&space)
            .await
            .into_iter()
            .filter(|locator| session.announced().contains(locator))
            .collect();
        let mut out = Vec::new();
        for locator in wanted {
            out.extend(self.want_in(session, &space, locator).await);
        }
        out
    }

    /// `ObjectWant` for an object on a session: for a state object with a
    /// limit ([`state_limit`](Self::state_limit)), its first chunk alone,
    /// which carries the header; for any other, its first chunks.
    pub(crate) async fn want_in(
        &self,
        session: &mut SyncSession,
        space: &EventId,
        locator: Locator,
    ) -> Option<SyncMessage> {
        if self.state_limit(space, &locator).await.is_some() {
            session.want_object_header(locator)
        } else {
            session.want_object(locator)
        }
    }

    /// How much of an object the device holds: the chunks held, and their
    /// count once its header is held.
    #[cfg_attr(
        not(all(
            any(feature = "server", feature = "iroh", feature = "server-socket"),
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) async fn object_progress(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<(u64, Option<u64>)> {
        let state = self.lock().await;
        state.replicas.get(space)?.object_progress(locator)
    }

    /// Puts a blob in a `frasil:blobs` stream (adapter-blobs.md): the
    /// object, then a log unit that names it under a fresh handle. Returns
    /// the unit and the locator.
    ///
    /// # Errors
    ///
    /// As [`Engine::put_object`] and [`Engine::write_unit`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn put_blob(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        name: Option<&str>,
        plaintext: &[u8],
    ) -> Result<(EventId, Locator)> {
        let handle = self.platform().nonce::<16>()?;
        self.put_blob_under(space, stream, handle, name, plaintext)
            .await
    }

    /// [`Engine::put_blob`] under a handle the caller chose: a new blob, or
    /// a new version of the blob it names.
    ///
    /// # Errors
    ///
    /// As [`Engine::put_blob`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn put_blob_under(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        handle: [u8; 16],
        name: Option<&str>,
        plaintext: &[u8],
    ) -> Result<(EventId, Locator)> {
        use frasil_adapter_blobs::content::Op;
        use frasil_adapter_blobs::entry::Entry;
        // Under `held`, the bytes go through the provider's writer;
        // otherwise the object's parts are kept in the unit's commit.
        let (locator, key, mut stored) = match self.put_created(space, plaintext).await? {
            Some((locator, key)) => (locator, key, Vec::new()),
            None => self.seal_parts(space, plaintext).await?,
        };
        // A large object is written before its unit and without the
        // device's lock, so that other writes go on meanwhile; a small one
        // goes in the unit's commit.
        if stored.iter().map(|part| part.chunk.len()).sum::<usize>() >= OWN_COMMIT_BYTES {
            self.store_parts(space, &stored.iter().collect::<Vec<_>>(), true)
                .await?;
            stored.clear();
        }
        let entry = Entry {
            object: locator,
            key,
            size: plaintext.len() as u64,
            media_type: None,
            name: name.map(str::to_owned),
            reference: None,
        };
        let id = self
            .write_blob_op(
                space,
                stream,
                Op::put(handle, entry),
                vec![locator],
                &[],
                stored,
            )
            .await?;
        Ok((id, locator))
    }

    /// A blob's object, kept: under `held`, the bytes go through the
    /// provider's writer, and the file it made is put (at-rest.md, "Held
    /// objects"). Returns the locator and the key reference.
    #[cfg(feature = "adapter-blobs")]
    pub(crate) async fn blob_object(
        &self,
        space: EventId,
        plaintext: &[u8],
    ) -> Result<(Locator, Vec<u8>)> {
        match self.put_created(space, plaintext).await? {
            Some(put) => Ok(put),
            None => self.put_object_with(space, plaintext).await,
        }
    }

    /// Puts an entry in a `frasil:blobs` stream under a handle: a unit that
    /// names its object, which the device has uploaded or, for a reference,
    /// a peer holds for the space (adapter-blobs.md, "References").
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn put_entry(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        handle: [u8; 16],
        entry: frasil_adapter_blobs::Entry,
    ) -> Result<EventId> {
        self.put_version_entry(space, stream, handle, entry, &[])
            .await
    }

    /// [`Engine::put_entry`] as a new version of `parents`, the handles it
    /// was made from: with ext-file-versions.md, the unit supersedes each
    /// parent's entry the stream holds.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn put_version_entry(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        handle: [u8; 16],
        entry: frasil_adapter_blobs::Entry,
        parents: &[[u8; 16]],
    ) -> Result<EventId> {
        use frasil_adapter_blobs::content::Op;
        let locator = entry.object;
        self.write_blob_op(
            space,
            stream,
            Op::put(handle, entry),
            vec![locator],
            parents,
            Vec::new(),
        )
        .await
    }

    /// Removes a blob's entry from a `frasil:blobs` stream. A reference's
    /// hold ends once compaction drops its locator and the peer collects the
    /// units that listed it (ext-libraries.md, "Keeping a held object").
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn remove_blob(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        handle: [u8; 16],
    ) -> Result<EventId> {
        use frasil_adapter_blobs::content::Op;
        self.write_blob_op(
            space,
            stream,
            Op::remove(handle),
            Vec::new(),
            &[],
            Vec::new(),
        )
        .await
    }

    /// Writes one op of a `frasil:blobs` stream in a log unit of its own.
    #[cfg(feature = "adapter-blobs")]
    async fn write_blob_op(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        op: frasil_adapter_blobs::content::Op,
        objects: Vec<Locator>,
        parents: &[[u8; 16]],
        stored: Vec<ObjectPart>,
    ) -> Result<EventId> {
        use frasil_adapter_blobs::content::Change;
        let mut state = self.lock().await;
        let id = self
            .write_parts(
                &mut state,
                space,
                stream.stream(),
                Some(stream.clone()),
                &stream.type_.clone(),
                |replica, _, _| {
                    let blobs = replica.stream(&stream.stream()).and_then(|runtime| {
                        runtime
                            .as_any()
                            .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_blobs::Blobs>>()
                    });
                    let clock = blobs.map_or(1, |blobs| blobs.state().next_clock());
                    #[cfg(feature = "ext-file-versions")]
                    let supersedes = match (blobs, objects.first()) {
                        (Some(blobs), Some(successor)) => {
                            frasil_adapter_blobs::versions::supersessions_for(
                                blobs.state(),
                                parents,
                                *successor,
                            )
                        }
                        _ => Vec::new(),
                    };
                    #[cfg(not(feature = "ext-file-versions"))]
                    let supersedes = {
                        let _ = parents;
                        Vec::new()
                    };
                    Ok(crate::device::UnitParts {
                        content: Change::new(clock, vec![op]).encode(),
                        objects,
                        supersedes,
                        stored,
                        ..crate::device::UnitParts::default()
                    })
                },
            )
            .await?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::{SLICE_BYTES, SliceReader};
    use frasil_events::EventId;
    use frasil_keys::RotationSet;
    use frasil_units::limits::CHUNK_BYTES;
    use frasil_units::objects::{SealedObject, seal_object};

    /// An object of three and a half chunks, sealed.
    fn object() -> SealedObject {
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let plaintext: Vec<u8> = (0..CHUNK_BYTES * 7 / 2).map(|i| (i % 251) as u8).collect();
        seal_object(&EventId([1; 32]), &[2; 32], &reference, &plaintext).unwrap()
    }

    /// Takes every slice from where the reader stands: the chunks cut, by
    /// index, and the most bytes it held between slices.
    fn read_all(reader: &mut SliceReader, stored: &[u8]) -> (Vec<(u64, Vec<u8>)>, usize) {
        let mut parts = Vec::new();
        let mut most = 0;
        while let Some(index) = reader.next_slice() {
            let at = index as usize * SLICE_BYTES;
            let slice = &stored[at..(at + SLICE_BYTES).min(stored.len())];
            for part in reader.take(slice).unwrap() {
                assert_eq!(part.header.is_some(), part.index == 0);
                parts.push((part.index, part.chunk));
            }
            most = most.max(reader.pending.capacity());
        }
        (parts, most)
    }

    /// Slices cut into the object's sealed chunks, in order, holding at
    /// most one chunk's bytes between them.
    #[test]
    fn slices_are_cut_into_sealed_chunks() {
        let object = object();
        let mut reader = SliceReader::start(object.locator, None);
        let (parts, most) = read_all(&mut reader, &object.bytes);
        let chunks: Vec<(u64, Vec<u8>)> = object
            .chunks
            .iter()
            .map(|chunk| (chunk.index, chunk.sealed.clone()))
            .collect();
        assert_eq!(chunks.len(), 4);
        assert_eq!(parts, chunks);
        assert!(most <= SLICE_BYTES, "{most}");
        let stored = object.bytes.len() as u64;
        assert_eq!(reader.progress(), (stored, Some(stored)));
    }

    /// A fetch that holds the first chunks starts at the slice that ends
    /// the next one, and cuts the rest alone.
    #[test]
    fn a_fetch_resumes_after_the_leading_chunks_held() {
        let object = object();
        for leading in 1..4 {
            let mut reader =
                SliceReader::start(object.locator, Some((object.header.clone(), leading)));
            assert_eq!(reader.next_slice(), Some(leading));
            let (parts, _) = read_all(&mut reader, &object.bytes);
            let rest: Vec<(u64, Vec<u8>)> = object.chunks[leading as usize..]
                .iter()
                .map(|chunk| (chunk.index, chunk.sealed.clone()))
                .collect();
            assert_eq!(parts, rest);
        }
        // Whole, or holding nothing: from slice 0.
        let reader = SliceReader::start(object.locator, Some((object.header.clone(), 4)));
        assert_eq!(reader.next_slice(), Some(0));
        let reader = SliceReader::start(object.locator, Some((object.header.clone(), 0)));
        assert_eq!(reader.next_slice(), Some(0));
    }

    /// A slice of another length than the header gives, or a header of
    /// another object, is refused by class.
    #[test]
    fn a_slice_that_does_not_fit_is_refused() {
        let object = object();
        let mut reader = SliceReader::start(object.locator, None);
        let short = &object.bytes[..SLICE_BYTES - 1];
        assert_eq!(
            reader.take(short).unwrap_err().class_name(),
            Some("Malformed")
        );
        let mut other = object.locator;
        other[0] ^= 1;
        let mut reader = SliceReader::start(other, None);
        assert_eq!(
            reader
                .take(&object.bytes[..SLICE_BYTES])
                .unwrap_err()
                .class_name(),
            Some("ObjectMismatch")
        );
        let mut reader = SliceReader::start(object.locator, None);
        assert_eq!(
            reader.take(&[0, 0]).unwrap_err().class_name(),
            Some("Malformed")
        );
    }
}
