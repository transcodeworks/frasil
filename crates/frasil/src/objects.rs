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
pub(crate) const OWN_COMMIT_BYTES: usize = 4 << 20;

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

/// An object's chunks fetched by slices of its stored bytes
/// (transport.md, "Objects over HTTP"), cut into sealed chunks as the
/// slices arrive (units.md, "Objects"). Every chunk but the last is
/// exactly one slice long, so chunk `i` is the tail of slice `i` after
/// `4 + len(header)` bytes and the first `4 + len(header)` bytes of slice
/// `i + 1`. A fetch that holds the header starts at the slice of the
/// first chunk it wants; one that holds none takes slice 0 first, for the
/// header, and goes on from there. The reader keeps only the bytes of the
/// chunk not yet whole, less than one slice.
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
    /// The chunk the fetch ends before: at most the chunk count, once the
    /// header is read.
    end: u64,
    /// The bytes received of the next chunk.
    pending: Vec<u8>,
    /// Whether the next slice begins with bytes before the next chunk:
    /// the header in slice 0, or the tail of the chunk before.
    skip_prefix: bool,
    /// Whether the next part cut carries the header: the first of the
    /// fetch, and the first after each [`seek`](Self::seek), as the first
    /// chunk of an answer does on a stream (units.md, "Sync", objects).
    heads: bool,
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
    /// A fetch of the chunks `chunks` of `locator`, under the header the
    /// device holds of it, if any: from the slice of the first chunk
    /// wanted, or from slice 0 when no header is held.
    pub(crate) fn start(
        locator: Locator,
        header: Option<Vec<u8>>,
        chunks: core::ops::Range<u64>,
    ) -> Self {
        let header = header.and_then(|bytes| SlicedHeader::read(&locator, bytes).ok());
        let end = header
            .as_ref()
            .map_or(chunks.end, |header| chunks.end.min(header.count));
        Self {
            locator,
            next_slice: if header.is_some() { chunks.start } else { 0 },
            header,
            next_chunk: chunks.start,
            end,
            pending: Vec::new(),
            skip_prefix: true,
            heads: true,
        }
    }

    /// The next slice to fetch, or `None` once every chunk wanted is cut.
    pub(crate) fn next_slice(&self) -> Option<u64> {
        match &self.header {
            Some(_) if self.next_chunk >= self.end => None,
            _ => Some(self.next_slice),
        }
    }

    /// The next chunk the fetch cuts, or `None` once every chunk wanted
    /// is cut.
    pub(crate) fn next_chunk(&self) -> Option<u64> {
        (self.header.is_none() || self.next_chunk < self.end).then_some(self.next_chunk)
    }

    /// The header, when the chunks wanted all lie past the object's last
    /// chunk by it: the fetch then takes nothing more, and whoever asked
    /// for them asked by a size that is not the header's.
    pub(crate) fn beyond(&self) -> Option<&[u8]> {
        self.header
            .as_ref()
            .filter(|header| self.next_chunk >= header.count)
            .map(|header| header.bytes.as_slice())
    }

    /// Goes on at `chunk`, at or after the next one, leaving out the
    /// chunks between: the bytes received of the next chunk are dropped,
    /// and the fetch takes the slice `chunk` begins in.
    pub(crate) fn seek(&mut self, chunk: u64) {
        if chunk <= self.next_chunk {
            return;
        }
        self.next_chunk = chunk;
        self.pending = Vec::new();
        self.heads = true;
        if self.header.is_some() {
            self.next_slice = chunk;
            self.skip_prefix = true;
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
        let read = self.header.is_none();
        if read {
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
            let header = SlicedHeader::read(&self.locator, bytes.to_vec())?;
            self.end = self.end.min(header.count);
            self.header = Some(header);
        }
        let header = self.header.as_ref().ok_or(Error::Class("Malformed"))?;
        if body.len() as u64 != header.slice_length(index) {
            return Err(Error::Class("Malformed"));
        }
        if read && self.next_chunk > 0 {
            // Slice 0 was taken for the header alone: the fetch goes on at
            // the slice the first chunk wanted begins in.
            self.next_slice = self.next_chunk;
            return Ok(Vec::new());
        }
        if std::mem::take(&mut self.skip_prefix) {
            body = body.get(header.prefix..).ok_or(Error::Class("Malformed"))?;
        }
        self.next_slice += 1;
        // Each chunk's bytes are gathered in a buffer of its own length,
        // which becomes the part once full.
        let mut parts = Vec::new();
        while self.next_chunk < self.end && !body.is_empty() {
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
                header: std::mem::take(&mut self.heads).then(|| header.bytes.clone()),
                index: self.next_chunk,
                chunk: std::mem::take(&mut self.pending),
            });
            self.next_chunk += 1;
        }
        // The last slice ends with the last chunk; a fetch that ends
        // before it leaves the start of the next chunk.
        if self.next_chunk >= header.count && !body.is_empty() {
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
    /// Not kept: it carries no header and the device holds none of the
    /// object, so there is nothing to check it against. What the device
    /// holds of the object stays.
    Headerless,
    /// Not kept: the device takes the object in order through a provider
    /// (at-rest.md, "Held objects", receiving), and its receive did not
    /// take this chunk ([`HeldPart::Left`](crate::held::HeldPart::Left)).
    /// The chunk is asked for again.
    Left,
    /// Not kept, and no fault: the device does not mean to store it, and
    /// of the readers of its object that store nothing none waits for it
    /// any more. Another connection brought the chunk first. Nothing is
    /// asked for again because of it.
    Unwanted,
    /// Refused: the part opens under another header than the one the
    /// device holds, under which a chunk had opened too. At most one of
    /// the two is the object's: what the device held of it is dropped, and
    /// it is asked of another party. So too for an object that, whole,
    /// does not hash to its locator, and for a state object larger than
    /// its adapter loads.
    Refused,
    /// Not kept, and its sender's fault: the part does not check under
    /// the header it carries; or it carries none and does not check under
    /// the header the device holds, under which a chunk has opened
    /// ([`Engine::holds_an_open_chunk`], or in a reader); or it carries
    /// another header than that one, and nothing opens its chunk. What
    /// the device holds of the object stays, no reader of it fails, and
    /// the chunk is asked of another party (units.md, "Sync", objects). A
    /// sender whose stored bytes were read under the header held, and not
    /// its own, is judged again under its own
    /// ([`SliceTask`](crate::peer)).
    BadChunk,
    /// Not kept, and nobody's fault that the device can tell: nothing has
    /// opened under the header the device holds, and nothing opens the
    /// part either, which carries another header or none. One of the two
    /// is not the object's, and a party that holds no key can make
    /// either. What the device holds stays, its sender is not given up,
    /// and the chunk is asked for again: a chunk that opens decides,
    /// once the device holds a key that opens one. So too for a chunk
    /// that the device can open only with the object keys that entries
    /// carry, when none of them opens it: the chunk or such a key is
    /// wrong, and the readers that hold those keys fail their reads.
    Undecided,
}

/// What became of a chunk the other side of a session sent
/// ([`Engine::take_chunk`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Taken {
    /// Not kept: nobody wants it any more, it carries no header and the
    /// device holds none of its object, or the receive of its object
    /// through a provider did not take it.
    Dropped,
    /// Refused, with what the device held of its object.
    Refused,
    /// Kept; the object is not whole yet.
    Kept,
    /// The object is whole.
    Whole,
}

/// What became of parts the device was given to keep
/// ([`Engine::keep_parts`]).
struct KeptParts {
    /// The objects dropped because, whole, they did not hash to their
    /// locators.
    dropped: BTreeSet<Locator>,
    /// The parts not kept, by locator and chunk index: those no receive
    /// through a provider took,
    /// and those of objects the device no longer means to hold.
    left: BTreeSet<(Locator, u64)>,
    /// Of those, the parts of objects the device does not mean to hold.
    unmeant: BTreeSet<(Locator, u64)>,
}

/// What a part another party sent was asked for
/// ([`Engine::receive_part`]): looked at again where the device
/// decides whether it means to store the part, under its lock, so that a
/// part that was on its way when its request ended is not stored for
/// whoever uses the object by then.
#[derive(Clone, Copy)]
pub(crate) struct Asked<'a> {
    /// Whether what the part was asked for still wants it: the request
    /// was not cancelled, or a unit of the space names the object.
    pub wanted: &'a (dyn Fn() -> bool + Sync),
    /// Whether the part was asked for the store. One asked for a reader
    /// that stores nothing joins what the device holds of its object,
    /// and begins no cached object.
    pub stores: bool,
}

impl Asked<'_> {
    /// A part asked for the store, by something that still wants it.
    pub(crate) const STORE: Asked<'static> = Asked {
        wanted: &|| true,
        stores: true,
    };
}

/// Where parts the device is given to keep come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Another party sent them over a connection: stored only while the
    /// device means to hold their object ([`Engine::admit`]).
    Sent,
    /// The application gave them, as a space file's objects.
    Given,
    /// The parts of whole objects whose stored bytes were found to hash
    /// to their locators already.
    Checked,
}

/// Whether a part fits the object it names ([`fits_object`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fit {
    /// It fits, under the header it carries or the one held; `opened`
    /// says its chunk opened under the object's key.
    Fits { opened: bool },
    /// It carries no header, and none is held.
    Headerless,
    /// It does not check under the header it carries, whatever the device
    /// holds: its sender's fault.
    Bad,
    /// It carries no header, and does not check under the one the device
    /// holds: its sender's fault if a chunk has opened under that header,
    /// and else nothing says which of the two is not the object's.
    Unfit,
    /// It checks under the header it carries, which is not the one the
    /// device holds; `opened` says its chunk opened under it. At most one
    /// of the two headers is the object's.
    Other { opened: bool },
    /// It is a chunk of the object by its header, the one it carries or
    /// the one held, and the device holds no key of the state that header
    /// names: only the object keys that entries carry, which the open
    /// readers of references supplied, and none of them opens it. The
    /// chunk or one of those keys is not the object's, and nothing says
    /// which.
    Unjudged,
}

/// What a part's chunk is under one header ([`fits_object`]).
enum Check {
    /// It opens under the object's key.
    Opens,
    /// It is a chunk of the object by the header, and the device holds
    /// no key to open it with.
    Unopened,
    /// It is none of the object's by the header, or does not open under
    /// the key of the state the header names.
    Fails,
    /// It is a chunk of the object by the header, and opens under none
    /// of the object keys that entries carry, the only keys held.
    Unjudged,
}

/// Whether a part fits the object it names (units.md, "Reading an
/// object", steps 2 to 4 and 6, by chunk): a header that reads, is the
/// header held if one is, and names the locator's object ID; and a chunk
/// that [`check_chunk`] takes under it, opened under the object's key
/// when the replica holds the key of the state the header names, or an
/// open reader of a reference holds the object's key (`openings`). The
/// header held, `held`, is the replica's, the one a receive through a
/// provider holds while it runs (at-rest.md, "Held objects", receiving),
/// or the one the windows of readers that store nothing hold.
///
/// The key of the state the header names decides where the replica holds
/// it. An object key that an entry carries is its writer's word
/// (adapter-blobs.md, 4 Security considerations, "A reference hands one
/// key"): a chunk that opens under one is opened, and one that opens
/// under none of them is not judged ([`Fit::Unjudged`]).
fn fits_object(
    replica: &Replica,
    space: &EventId,
    part: &ObjectPart,
    held: Option<&[u8]>,
    openings: &[crate::reading::ObjectOpening],
) -> Fit {
    let checks = |bytes: &[u8]| -> Check {
        let Ok(header) = frasil_units::objects::Header::read(bytes) else {
            return Check::Fails;
        };
        let check = |of: &EventId, key: Option<&[u8; 32]>| {
            check_chunk(of, &header, &part.locator, part.index, &part.chunk, key).is_ok()
        };
        if let Some((key, _)) = replica.object_key(&header.key_reference) {
            let object_key = ObjectKeys::of(&key).object_key(&header.object_id);
            return if check(space, Some(&object_key)) {
                Check::Opens
            } else {
                Check::Fails
            };
        }
        // Steps 3 and 4 need no key.
        if !check(space, None) {
            return Check::Fails;
        }
        if openings.is_empty() {
            return Check::Unopened;
        }
        if openings
            .iter()
            .any(|opening| check(&opening.source, Some(&opening.key)))
        {
            Check::Opens
        } else {
            Check::Unjudged
        }
    };
    match (part.header.as_deref(), held) {
        (None, None) => Fit::Headerless,
        (Some(new), None) => match checks(new) {
            Check::Opens => Fit::Fits { opened: true },
            Check::Unopened => Fit::Fits { opened: false },
            Check::Fails => Fit::Bad,
            Check::Unjudged => Fit::Unjudged,
        },
        (Some(new), Some(held)) if new != held => match checks(new) {
            Check::Opens => Fit::Other { opened: true },
            Check::Unopened => Fit::Other { opened: false },
            Check::Fails => Fit::Bad,
            Check::Unjudged => Fit::Unjudged,
        },
        (carried, Some(held)) => match checks(held) {
            Check::Opens => Fit::Fits { opened: true },
            Check::Unopened => Fit::Fits { opened: false },
            Check::Fails if carried.is_some() => Fit::Bad,
            Check::Fails => Fit::Unfit,
            Check::Unjudged => Fit::Unjudged,
        },
    }
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
        state
            .replicas
            .get(space)?
            .is_located(locator)
            .then(|| Self::by_id(state, space, locator, range))
            .flatten()
    }

    /// [`of_range`](Self::of_range), for an object the store holds whole
    /// by its ID whether or not its locator is known yet: what it reads is
    /// the object's only once its bytes hash to the locator (units.md,
    /// "Reading an object", step 0).
    fn by_id(
        state: &crate::device::State,
        space: &EventId,
        locator: &Locator,
        range: core::ops::Range<u64>,
    ) -> Option<Self> {
        let replica = state.replicas.get(space)?;
        let (header, stored) = replica.stored_parts(locator)?;
        let key = frasil_units::objects::Header::read(&header)
            .ok()
            .and_then(|read| replica.object_key(&read.key_reference))
            .map(|(key, _)| key);
        let memory = replica.chunks_in_memory_in(locator, range.clone());
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

/// How many chunks a chunk-by-chunk read takes from the store at once: a
/// read holds about twice this many chunks, sealed and opened.
#[cfg(feature = "adapter-blobs")]
const READ_BATCH: u64 = 8;

/// An object's plaintext chunk by chunk, from [`Engine::plain`]: opened
/// from the store, or read from the file of an object the application
/// holds.
#[cfg(feature = "adapter-blobs")]
pub(crate) enum Plain {
    /// From the store.
    Chunks(Box<PlainChunks>),
    /// From the application's file (at-rest.md, "Held objects").
    Held(Box<crate::held::HeldChunks>),
}

#[cfg(feature = "adapter-blobs")]
impl Plain {
    /// The next chunk, by index, with its plaintext; `None` after the last
    /// one asked for.
    ///
    /// # Errors
    ///
    /// `Missing` when the store or the file no longer holds the object;
    /// `Decrypt`, `Malformed`, `ObjectMismatch`; the provider's.
    pub(crate) async fn next(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        match self {
            Self::Chunks(chunks) => chunks.next().await,
            Self::Held(chunks) => chunks.next().await,
        }
    }
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
    /// Whether the reader holds `k(S)`, so that step 7 is one of its steps.
    by_content_key: bool,
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
            drop(chunks);
            self.opened.extend(batch.clone().zip(plain));
            self.next = batch.end;
            // Step 7 before the last chunk is given.
            if self.whole && self.next >= count {
                if let Some(reader) = self.reader.take() {
                    reader.finish().map_err(Error::class)?;
                }
                self.engine
                    .mark_verified(self.holder, self.locator, self.by_content_key);
            }
        }
    }
}

/// What one pass over an object's stored chunks found (units.md, 3.3
/// Reading an object), from [`Engine::pass`].
#[cfg(feature = "adapter-blobs")]
struct Pass {
    /// The SHA-256 of the stored bytes, when the pass hashed them (step 0).
    digest: Option<[u8; 32]>,
    /// The first of steps 1 to 7 that failed, by the order of the steps.
    fault: Option<Error>,
    /// The reader, when the pass did not open the chunks: ready to open
    /// them from the first.
    reader: Option<frasil_units::objects::ChunkReader>,
    /// The plaintext of the chunks the pass was asked to keep, once every
    /// step it ran passed.
    kept: std::collections::VecDeque<(u64, Vec<u8>)>,
}

#[cfg(feature = "adapter-blobs")]
impl Engine {
    /// The chunks of a stored object in a range of indices, every one of
    /// them, read without the device's lock, by the object's ID; `None`
    /// when one is missing.
    async fn stored_chunks(
        &self,
        space: &EventId,
        locator: &Locator,
        range: core::ops::Range<u64>,
    ) -> Result<Option<BTreeMap<u64, Chunk>>> {
        let read = {
            let state = self.lock().await;
            ObjectRead::by_id(&state, space, locator, range.clone())
        };
        let Some(read) = read else {
            return Ok(None);
        };
        let Some((_, chunks, _)) = read.read(locator).await? else {
            return Ok(None);
        };
        Ok(chunks.keys().copied().eq(range).then_some(chunks))
    }

    /// One pass over every chunk of an object the store holds whole, a few
    /// chunks at a time, without the device's lock (units.md, 3.3 Reading
    /// an object): with `digest`, step 0's hash of the stored bytes; step 4
    /// on each chunk's length; with `open`, steps 6 and 7, keeping the
    /// plaintext of the chunks in `keep` and nothing else. `reader` is steps
    /// 1 to 3 and 5 on the header. A fault ends the opening, not the
    /// hashing, so that step 0 still decides first; the caller runs step 0
    /// on the digest. `None` when a chunk is missing from the store.
    #[allow(clippy::too_many_arguments)]
    async fn pass(
        &self,
        holder: &EventId,
        locator: &Locator,
        header: &[u8],
        size: u64,
        reader: Result<frasil_units::objects::ChunkReader>,
        digest: bool,
        open: bool,
        keep: core::ops::Range<u64>,
    ) -> Result<Option<Pass>> {
        use frasil_units::limits::{CHUNK_BYTES, NONCE_BYTES, TAG_BYTES};
        let count = frasil_units::objects::chunk_count(size, CHUNK_BYTES as u64);
        let mut hasher = if digest {
            let length = u32::try_from(header.len()).map_err(|_| Error::Class("Malformed"))?;
            let mut hasher = frasil_crypto::primitives::Sha256Hasher::new();
            hasher.update(&length.to_be_bytes());
            hasher.update(header);
            Some(hasher)
        } else {
            None
        };
        // Steps 1 to 3 fail before step 4, and step 5 after it.
        let (mut reader, header_fault, sealed_fault) = match reader {
            Ok(reader) => (Some(reader), None, None),
            Err(Error::Class("Sealed")) => (None, None, Some(Error::Class("Sealed"))),
            Err(fault) => (None, Some(fault), None),
        };
        let mut length_fault = None;
        let mut open_fault = None;
        let mut kept = std::collections::VecDeque::new();
        let mut at = 0;
        while at < count {
            // Without step 0 to run, a fault at steps 1 to 4 decides.
            if hasher.is_none() && (header_fault.is_some() || length_fault.is_some()) {
                break;
            }
            let batch = at..count.min(at + READ_BATCH);
            let Some(chunks) = self.stored_chunks(holder, locator, batch.clone()).await? else {
                return Ok(None);
            };
            for (index, chunk) in &chunks {
                let chunk = chunk.bytes();
                if let Some(hasher) = &mut hasher {
                    hasher.update(chunk);
                }
                let expected =
                    frasil_units::objects::plain_length(size, CHUNK_BYTES as u64, *index)
                        + (NONCE_BYTES + TAG_BYTES) as u64;
                if chunk.len() as u64 != expected {
                    length_fault.get_or_insert(Error::Class("Malformed"));
                }
            }
            let opening = open && length_fault.is_none() && open_fault.is_none();
            if let Some(reader) = reader.as_mut().filter(|_| opening) {
                let sealed: Vec<(u64, &[u8])> = chunks
                    .iter()
                    .map(|(index, chunk)| (*index, chunk.bytes()))
                    .collect();
                let bytes = sealed.iter().map(|(_, chunk)| chunk.len()).sum();
                match reader.open_many(&sealed, crate::parallel::for_bytes(bytes)) {
                    Ok(plain) => kept.extend(
                        batch
                            .clone()
                            .zip(plain)
                            .filter(|(index, _)| keep.contains(index)),
                    ),
                    Err(fault) => open_fault = Some(Error::class(fault)),
                }
            }
            at = batch.end;
        }
        let mut id_fault = None;
        if open
            && header_fault.is_none()
            && length_fault.is_none()
            && open_fault.is_none()
            && let Some(reader) = reader.take()
        {
            // 7.
            id_fault = reader.finish().err().map(Error::class);
        }
        let fault = header_fault
            .or(length_fault)
            .or(sealed_fault)
            .or(open_fault)
            .or(id_fault);
        if fault.is_some() {
            kept.clear();
        }
        Ok(Some(Pass {
            digest: hasher.map(frasil_crypto::primitives::Sha256Hasher::finish),
            fault,
            reader,
            kept,
        }))
    }

    /// An object's plaintext, chunk by chunk where the store holds it,
    /// for the chunks in `chunks` (units.md, 3.3 Reading an object): the
    /// object of `space`, or for a reference the object of its source
    /// opened with its object key. It holds a few chunks at a time, and
    /// the chunks of a range it keeps.
    ///
    /// Before it gives any plaintext, every step has passed on the whole
    /// object since the device opened: a read of every chunk runs them as
    /// it goes, step 0 first in a pass of its own when the stored bytes
    /// were not hashed yet; a read of some chunks runs them all in one
    /// pass over the store that keeps only the chunks asked for, unless a
    /// read this session already ran them.
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
                let located = replica.is_located(locator);
                let read = ObjectRead::by_id(&state, &holder, locator, 0..0)?;
                Some((holder, read.header, read.key, checked, located))
            })
        };
        let Some((holder, header, key, checked, located)) = found else {
            // An object the application holds, or none held whole.
            for holder in [Some(*space), reference.map(|(source, _)| source)]
                .into_iter()
                .flatten()
            {
                if let Some(held) = self.held_chunks(&holder, locator, chunks.clone()).await? {
                    return Ok(Plain::Held(Box::new(held)));
                }
            }
            return Err(Error::Class("Missing"));
        };
        // A whole object's header reads (`HeldObject::is_whole`).
        let size = frasil_units::objects::Header::read(&header)
            .map_err(Error::class)?
            .size;
        let count =
            frasil_units::objects::chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64);
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
        let by_content_key = reference.is_none();
        // 1 to 3, and 5.
        let reader = frasil_units::objects::ChunkReader::new(&header, &opens, opening, locator)
            .map_err(Error::class);
        let wanted = chunks.start.min(count)..chunks.end.min(count);
        let whole = wanted == (0..count);
        // Some chunks only: every step runs on the whole first, once.
        let open = !whole && !self.is_verified(&holder, locator, by_content_key);
        let mut plain = PlainChunks {
            engine: self.clone(),
            holder,
            locator: *locator,
            reader: None,
            next: wanted.start,
            end: wanted.end,
            whole,
            by_content_key,
            opened: std::collections::VecDeque::new(),
        };
        if checked && !open {
            plain.reader = Some(reader?);
            return Ok(Plain::Chunks(Box::new(plain)));
        }
        let pass = self
            .pass(
                &holder,
                locator,
                &header,
                size,
                reader,
                !checked,
                open,
                wanted.clone(),
            )
            .await?
            .ok_or(Error::Class("Missing"))?;
        // 0. The stored bytes hash to the locator, before any plaintext
        // goes out. Found in the store by its ID, an object is located by
        // its bytes, and bytes of another locator are not this object.
        if let Some(digest) = pass.digest {
            let mut found = *locator;
            found[32..].copy_from_slice(&digest);
            if let Some(replica) = self.lock().await.replicas.get_mut(&holder) {
                if !located {
                    replica.locate(found);
                }
                if found == *locator {
                    replica.mark_checked(locator);
                }
            }
            if found != *locator {
                return Err(Error::Class(if located {
                    "ObjectMismatch"
                } else {
                    "Missing"
                }));
            }
        }
        if let Some(fault) = pass.fault {
            return Err(fault);
        }
        if open {
            self.mark_verified(holder, *locator, by_content_key);
            plain.next = wanted.end;
            plain.opened = pass.kept;
        } else {
            plain.reader = pass.reader;
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

/// The objects a replica knows by name: those its units name, the
/// newcomer's snapshot it awaits and the stream snapshot objects that
/// names (admission.md, "The newcomer's snapshot"), and the record objects
/// of the checkpoints it cannot read yet (roster.md, "The record object").
fn named_to_replica(replica: &Replica) -> BTreeSet<Locator> {
    let mut named = named_objects(replica);
    named.extend(replica.awaited_snapshot().copied());
    named.extend(replica.pending_stream_objects().copied());
    named.extend(replica.checkpoint_facts().records_wanted());
    named
}

/// Whether an object is one the device fetches by itself whatever it
/// keeps of its blobs: the replica knows it by name, and no blob stream's
/// entry names it.
pub(crate) fn fetched_by_itself(replica: &Replica, locator: &Locator) -> bool {
    named_to_replica(replica).contains(locator) && !fetched_on_read(replica, locator)
}

/// The objects the device fetches by itself whatever it keeps of its
/// blobs ([`fetched_by_itself`]), by object ID.
pub(crate) fn fetched_by_itself_ids(replica: &Replica) -> BTreeSet<[u8; 32]> {
    let blobs = blob_objects(replica);
    named_to_replica(replica)
        .iter()
        .filter(|locator| !blobs.contains(*locator))
        .map(crate::replica::object_id)
        .collect()
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

/// Whether an object is one the device fetches only when the application
/// reads it: a blob stream's entry names it, so no fetch of the device's
/// own brings it.
pub(crate) fn fetched_on_read(replica: &Replica, locator: &Locator) -> bool {
    blob_objects(replica).contains(locator)
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
        self.mark_sealed(space, [&locator]).await;
        self.store_parts(space, &parts, true).await?;
        Ok((locator, reference))
    }

    /// Seals an object under the space's current state, outside the
    /// device's lock: its locator, key reference and parts.
    pub(crate) async fn seal_parts(
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
    pub(crate) async fn note_parts(
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
        let locators: Vec<Locator> = parts.iter().map(|part| part.locator).collect();
        Self::resize_retained(state, space, &locators);
        for locator in locators.iter().collect::<BTreeSet<_>>() {
            let indices: Vec<u64> = parts
                .iter()
                .filter(|part| part.locator == *locator)
                .map(|part| part.index)
                .collect();
            state.readers.kept(&space, locator, &indices);
        }
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
        Box::pin(self.keep_parts_with(space, parts, Source::Given, Asked::STORE))
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
        Box::pin(self.keep_parts_with(space, parts, Source::Checked, Asked::STORE))
            .await
            .map(drop)
    }

    /// One part of an object another party sent, as sync carries it
    /// (units.md, "Sync", objects): checked as it arrives, then kept. Of
    /// an object the device holds whole, nothing is taken. The chunk is
    /// checked with [`check_chunk`] under the header the part carries, or
    /// the one the device holds when it carries none, and opened under
    /// the object's key when the device holds it.
    ///
    /// A part that fits is kept. Of one that does not, by the header the
    /// device holds (none; one nothing has opened under; one a chunk has
    /// opened under, as it arrived, in a reader, or in the store):
    ///
    /// | Held | The part | It is | Dropped | Its sender |
    /// | --- | --- | --- | --- | --- |
    /// | none | carries no header | [`Received::Headerless`] | nothing | asked again |
    /// | any | fails under the header it carries | [`Received::BadChunk`] | nothing | given up |
    /// | opened | no header, fails under the one held | [`Received::BadChunk`] | nothing | given up |
    /// | opened | another header, nothing opens it | [`Received::BadChunk`] | nothing | given up |
    /// | opened | another header, opens | [`Received::Refused`] | what is held | given up |
    /// | not opened | another header, opens | kept | what was held | kept |
    /// | not opened | no header, fails under the one held | [`Received::Undecided`] | nothing | asked again |
    /// | not opened | another header, nothing opens it | [`Received::Undecided`] | nothing | asked again |
    /// | any | opens under no object key an entry carries, the only keys held | [`Received::Undecided`] | nothing | asked again |
    ///
    /// So a party that holds no key of the object makes the device drop
    /// nothing a chunk has opened under, and nothing it merely holds
    /// either: only a part that opens under another header does, which a
    /// holder of the key sealed. Where a chunk had opened under the
    /// header held, at most one of the two is the object's, and nothing
    /// says which: what is held goes, the object is missing again and
    /// asked of another party, and its whole-object checks decide once
    /// it is whole (adapter-blobs.md, 4 Security considerations). A
    /// reader of the object fails with what is dropped only when a chunk
    /// had opened in a reader, whose bytes are then in doubt
    /// ([`drop_object`](Self::drop_object)); where none had, the readers
    /// start over under the header that arrives next. Once the object is
    /// whole, it is checked against its locator's digest, which needs no
    /// key.
    ///
    /// `asked` says what the part was asked for ([`Asked`]): a part whose
    /// request ended while it was on its way is not stored, whoever uses
    /// its object by then, and one asked for a reader that stores nothing
    /// begins no cached object.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    pub(crate) async fn receive_part(
        &self,
        space: EventId,
        part: ObjectPart,
        asked: Asked<'_>,
    ) -> Result<Received> {
        let key = (space, crate::replica::object_id(&part.locator));
        let (fits, received) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            if replica.holds_object(&part.locator) {
                return Ok(Received::Whole);
            }
            // The header the replica holds, the one a receive through a
            // provider holds, or the one the windows of readers that
            // store nothing hold.
            let receive = state.held.receive_at(&space, &part.locator);
            // A receive through a provider opens each chunk it takes.
            let received = receive.as_ref().is_some_and(|(_, next)| *next > 0);
            let held = replica
                .object_header(&part.locator)
                .map(<[u8]>::to_vec)
                .or_else(|| receive.map(|(header, _)| header))
                .or_else(|| self.readers().header(&key));
            let openings = self.readers().openings(&key);
            let fits = fits_object(replica, &space, &part, held.as_deref(), &openings);
            (fits, received)
        };
        let opened = match fits {
            Fit::Fits { opened } => opened,
            Fit::Headerless => return Ok(Received::Headerless),
            // Asked of another party (units.md, "Sync", objects); what
            // is held stays.
            Fit::Bad => return Ok(Received::BadChunk),
            // The readers whose keys did not open it hear of it: their
            // reads fail as their entries' own, and nothing else changes.
            Fit::Unjudged => {
                self.readers().unopened(&key, part.index);
                return Ok(Received::Undecided);
            }
            Fit::Unfit | Fit::Other { .. } => {
                // Whether a chunk has opened under the header held: as
                // it arrived or in a reader, or a chunk of the store
                // does now.
                let proved = received
                    || self.readers().proved(&key)
                    || self.holds_an_open_chunk(&space, &part.locator).await;
                match (fits, proved) {
                    // A chunk opened under each header.
                    (Fit::Other { opened: true }, true) => {
                        let mut state = self.lock().await;
                        self.drop_object(&mut state, space, &part.locator).await?;
                        return Ok(Received::Refused);
                    }
                    // A chunk opened under the part's header and none
                    // under the one held, under which nothing was given:
                    // the part is the object's first.
                    (Fit::Other { opened: true }, false) => {
                        let mut state = self.lock().await;
                        self.drop_object(&mut state, space, &part.locator).await?;
                        true
                    }
                    // Nothing opens the part, and a chunk has opened
                    // under the header held.
                    (_, true) => return Ok(Received::BadChunk),
                    // Nothing has opened under either.
                    (_, false) => return Ok(Received::Undecided),
                }
            }
        };
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
            self.drop_object(&mut state, space, &part.locator).await?;
            if let Some(replica) = state.replicas.get_mut(&space)
                && replica.object_key(&read.key_reference).is_some()
            {
                replica.refuse_oversized_state(part.locator);
            }
            return Ok(Received::Refused);
        }
        let locator = part.locator;
        let kept =
            Box::pin(self.keep_parts_with(space, std::slice::from_ref(&part), Source::Sent, asked))
                .await?;
        if kept.dropped.contains(&locator) {
            return Ok(Received::Refused);
        }
        // Reported as kept only when it was: in the store, or in the
        // window of a reader that stores nothing and asked for it.
        if kept.left.contains(&(locator, part.index)) {
            return Ok(if self.readers().offer(&space, &part, opened) {
                Received::Kept
            } else if kept.unmeant.contains(&(locator, part.index)) && self.readers().passing(&key)
            {
                Received::Unwanted
            } else {
                Received::Left
            });
        }
        if opened {
            self.readers().prove(&key);
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

    /// [`receive_part`](Self::receive_part) for a part asked for the
    /// store, by something that still wants it.
    #[cfg(test)]
    pub(crate) async fn receive_sent(&self, space: EventId, part: ObjectPart) -> Result<Received> {
        self.receive_part(space, part, Asked::STORE).await
    }

    /// Forgets an object the device held part of because a check found
    /// that what is held is not the object's, and deletes its records: it
    /// is missing again. How the device retains the object stays as it
    /// was, so that what another party then sends of it is kept or cached
    /// as before. Its open readers fail if a chunk of it had opened in
    /// one of them: the bytes given are then not known to be the
    /// object's. Where none had, the readers gave nothing, and start over
    /// with what arrives next. Nothing is done to an object the device
    /// holds whole whose bytes hash to its locator
    /// ([`Dropping::Doubted`](crate::retention::Dropping)).
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn drop_object(
        &self,
        state: &mut crate::device::State,
        space: EventId,
        locator: &Locator,
    ) -> Result<()> {
        let id = crate::replica::object_id(locator);
        let doubted = crate::retention::Dropping::Doubted;
        if !self.may_drop(state, &space, &id, doubted) {
            return Ok(());
        }
        if !self.readers().disown(&(space, id)) {
            self.readers()
                .refuse(&space, locator, "ObjectMismatch", false);
        }
        self.drop_stored(state, space, &id, false, doubted)
            .await
            .map(drop)
    }

    /// Whether an object the replica holds whole, sealed, hashes to its
    /// locator (units.md, "Reading an object", step 0), read a few chunks
    /// at a time: `None` when it cannot be read.
    pub(crate) async fn whole_digest(
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
    /// whole, they did not hash to their locators, and the parts that
    /// were not kept.
    async fn keep_parts_with(
        &self,
        space: EventId,
        parts: &[ObjectPart],
        source: Source,
        asked: Asked<'_>,
    ) -> Result<KeptParts> {
        let checked = source == Source::Checked;
        let mut left = BTreeSet::new();
        let mut unmeant = BTreeSet::new();
        let (sealed, _writing) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            // Under `held`, a blob's parts go through the provider instead
            // (at-rest.md, "Held objects", receiving), unless chunks of
            // it are stored sealed already.
            let (held, mut sealed): (Vec<&ObjectPart>, Vec<&ObjectPart>) = parts
                .iter()
                .partition(|part| self.receives_held(&state, &space, &part.locator));
            for part in held {
                match self.receive_held_part(&mut state, space, part).await? {
                    crate::held::HeldPart::Taken => {}
                    crate::held::HeldPart::Sealed => sealed.push(part),
                    crate::held::HeldPart::Left => {
                        left.insert((part.locator, part.index));
                    }
                }
            }
            // A part another party sent is stored only while the device
            // means to hold its object: one that arrives after the device
            // dropped the object, as a slice asked for before a read gave
            // up does, would land with no record and count as kept
            // (at-rest.md, "Retention", recording).
            // An object a read fetches gets its record here, before its
            // first part is written. Parts the application gave, as a
            // space file's, are stored as they are: with no record, kept.
            if source == Source::Sent {
                let mut meant: BTreeMap<Locator, bool> = BTreeMap::new();
                let mut admitted = Vec::with_capacity(sealed.len());
                for part in sealed {
                    let means = match meant.get(&part.locator) {
                        Some(means) => *means,
                        None => {
                            // What asked for the part is looked at
                            // before and after the device says whether
                            // it means to hold the object: a request
                            // ends before its reader's use of the object
                            // does, so a part the device would store for
                            // a read that began since is seen here to
                            // have lost its own.
                            let header = part.header.as_deref();
                            let means = (asked.wanted)()
                                && self
                                    .admit(&mut state, space, &part.locator, header, asked.stores)
                                    .await?
                                && (asked.wanted)();
                            meant.insert(part.locator, means);
                            means
                        }
                    };
                    if means {
                        admitted.push(part);
                    } else {
                        left.insert((part.locator, part.index));
                        unmeant.insert((part.locator, part.index));
                    }
                }
                sealed = admitted;
            }
            // Taken under the lock that found the device means to hold
            // them, and held until the parts are noted: nothing drops an
            // object, its record or its earlier parts, while parts of it
            // are written outside the lock.
            let writing: Vec<crate::retention::InUse> = sealed
                .iter()
                .map(|part| part.locator)
                .collect::<BTreeSet<Locator>>()
                .iter()
                .map(|locator| self.use_object(space, locator))
                .collect();
            // Room for what goes to the cache, before it is written
            // (at-rest.md, "Retention", when). What is held beside the
            // cache counts against no budget, and makes nothing go; nor
            // does a chunk the device holds already, which adds nothing,
            // as when two connections fetch one object.
            let incoming: usize = {
                let replica = state.replicas.get(&space);
                sealed
                    .iter()
                    .filter(|part| {
                        state
                            .retained
                            .counts(&(space, crate::replica::object_id(&part.locator)))
                            && !replica.is_some_and(|replica| {
                                replica.holds_chunk(&part.locator, part.index)
                            })
                    })
                    .map(|part| part.chunk.len())
                    .sum()
            };
            if incoming > 0 {
                let writing = sealed
                    .iter()
                    .map(|part| crate::replica::object_id(&part.locator))
                    .collect();
                self.evict_in(&mut state, incoming as u64, &writing).await?;
            }
            (sealed, writing)
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
                        self.drop_object(&mut state, space, &locator).await?;
                        dropped.insert(locator);
                    }
                    None => {}
                }
            }
        }
        // Each object these parts made whole, past its checks.
        let arrived: BTreeSet<Locator> = {
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            parts
                .iter()
                .map(|part| part.locator)
                .filter(|locator| replica.holds_object(locator))
                .collect()
        };
        let (awaited, streams, records) = {
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            // Blob feeds hear of each.
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
        Ok(KeptParts {
            dropped,
            left,
            unmeant,
        })
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

    /// The plaintext length an object's header gives, once the replica
    /// holds the header: read from the header alone.
    #[cfg(feature = "adapter-blobs")]
    pub(crate) async fn object_size(&self, space: &EventId, locator: &Locator) -> Option<u64> {
        let header = self
            .read(space, |replica| {
                replica.object_header(locator).map(<[u8]>::to_vec)
            })
            .await
            .ok()??;
        frasil_units::objects::Header::read(&header)
            .ok()
            .map(|header| header.size)
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
    /// to another party: the header with chunk 0. Only those chunks are
    /// read, without the device's lock. Until its stored bytes were found
    /// to hash to its locator, they are hashed first, a few chunks at a
    /// time ([`check_whole`](Self::check_whole)). `None` while the device
    /// does not hold it sealed.
    ///
    /// # Errors
    ///
    /// `ObjectMismatch` when its bytes do not hash to its locator; the
    /// store's.
    pub(crate) async fn serve_parts(
        &self,
        space: &EventId,
        locator: &Locator,
        first: u64,
        count: u64,
    ) -> Result<Option<Vec<ObjectPart>>> {
        let range = first..first.saturating_add(count);
        let checked = {
            let state = self.lock().await;
            state
                .replicas
                .get(space)
                .is_some_and(|replica| replica.is_checked(locator))
        };
        if !checked {
            match self.check_whole(space, locator).await? {
                None => return Ok(None),
                Some(false) => return Err(Error::Class("ObjectMismatch")),
                Some(true) => {}
            }
            if let Some(replica) = self.lock().await.replicas.get_mut(space) {
                replica.mark_checked(locator);
            }
        }
        let read = {
            let state = self.lock().await;
            ObjectRead::of_range(&state, space, locator, range.clone())
        };
        let Some(read) = read else {
            return Ok(None);
        };
        let Some((header, chunks, _)) = read.read(locator).await? else {
            return Ok(None);
        };
        Ok(Some(
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

    /// The objects the space's units name that the device means to hold
    /// and does not hold whole: Frasil's own, and of its blobs those it
    /// keeps, or every one on a device that keeps every blob
    /// ([`Engine::keep_all_blobs`]).
    pub async fn missing_objects(&self, space: &EventId) -> Vec<Locator> {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let Some(replica) = state.replicas.get(space) else {
            return Vec::new();
        };
        #[cfg_attr(not(feature = "adapter-blobs"), allow(unused_mut))]
        let mut named = named_to_replica(replica);
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
        // A blob is fetched when it is read, unless the device keeps every
        // blob: of the blob streams' objects, only those it means to hold
        // whole are missing, the kept ones and those the application
        // started a fetch of. One it dropped is absent by its own choice.
        let on_read = if self.keeps_all_blobs() {
            BTreeSet::new()
        } else {
            blob_objects(replica)
        };
        named
            .into_iter()
            .filter(|locator| !replica.holds_object(locator))
            .filter(|locator| !replica.is_oversized_state(locator))
            .filter(|locator| {
                !on_read.contains(locator)
                    || state.held.asked_for(space, locator)
                    || Self::keeps_object(&state, space, locator)
            })
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

    /// Where a fetch of the chunks `chunks` of an object starts: the header
    /// the device holds of it, if any, and the first of those chunks it
    /// holds no copy of, in memory or in the store. `None` when there is
    /// nothing to fetch: it holds the object whole or each of those
    /// chunks, or the application holds the plaintext. An object the
    /// device receives through a provider is taken in order (at-rest.md,
    /// "Held objects", receiving): its fetch starts at chunk 0, or at the
    /// chunk the receive takes next, under the header the receive holds,
    /// and there is nothing to fetch once the receive is past `chunks`.
    #[cfg_attr(
        not(any(feature = "server", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn chunks_to_fetch(
        &self,
        space: &EventId,
        locator: &Locator,
        chunks: core::ops::Range<u64>,
    ) -> Option<(Option<Vec<u8>>, u64)> {
        let state = self.lock().await;
        let replica = state.replicas.get(space)?;
        if replica.holds_object(locator) || replica.is_held(locator) {
            return None;
        }
        // Fetched for readers that store nothing: the chunks their
        // windows still wait for, under the header they hold.
        if self.passes(&state, space, locator) {
            return self.window_fetch(space, locator, chunks);
        }
        if self.receives_in_order(&state, space, locator) {
            // In order from chunk 0, or from where the receive stands,
            // whichever chunks are asked for.
            let (header, next) = match state.held.receive_at(space, locator) {
                Some((header, next)) => (Some(header), next),
                None => (None, 0),
            };
            let count = header
                .as_deref()
                .or_else(|| replica.object_header(locator))
                .and_then(|header| frasil_units::objects::Header::read(header).ok())
                .map(|header| {
                    frasil_units::objects::chunk_count(
                        header.size,
                        frasil_units::limits::CHUNK_BYTES as u64,
                    )
                });
            let end = count.map_or(chunks.end, |count| chunks.end.min(count));
            return (chunks.start < end && next < end).then_some((header, next));
        }
        let Some(header) = replica.object_header(locator) else {
            return (!chunks.is_empty()).then_some((None, chunks.start));
        };
        // A chunk held that a reader could not open is fetched again
        // ([`Window::distrust`](crate::reading::Window::distrust)).
        let key = (*space, crate::replica::object_id(locator));
        let distrusted = self.readers().first_distrusted(&key, chunks.clone());
        let missing = replica.first_missing_chunk(locator, chunks);
        let first = match (missing, distrusted) {
            (Some(missing), Some(distrusted)) => missing.min(distrusted),
            (missing, distrusted) => missing.or(distrusted)?,
        };
        Some((Some(header.to_vec()), first))
    }

    /// How much of an object the device holds, in stored bytes: its
    /// header and each sealed chunk held, and the stored length once the
    /// header is held. A fetch's progress, whichever chunks came first.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn object_bytes_held(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<(u64, Option<u64>)> {
        let state = self.lock().await;
        // A receive through a provider keeps nothing at the replica until
        // it ends.
        if let Some((_, bytes)) = Self::receive_progress(&state, space, locator) {
            return Some((bytes.0, Some(bytes.1)));
        }
        state.replicas.get(space)?.object_bytes_held(locator)
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
            out.extend(self.want_in(session, locator).await);
        }
        out
    }

    /// `ObjectWant` for an object on a session, for the chunks the device
    /// lacks of it: for a state object with a limit
    /// ([`state_limit`](Self::state_limit)), its first chunk alone, which
    /// carries the header; for any other, its first chunks.
    pub(crate) async fn want_in(
        &self,
        session: &mut SyncSession,
        locator: Locator,
    ) -> Vec<SyncMessage> {
        self.want_chunks_in(
            session,
            locator,
            0..u64::MAX,
            crate::fetch::FetchPriority::Background,
        )
        .await
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
        if let Some((chunks, _)) = Self::receive_progress(&state, space, locator) {
            return Some((chunks.0, Some(chunks.1)));
        }
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
        // Sealed here and not yet named: nothing of it is dropped until
        // its unit is written, which holds it from then on.
        let _using = self.use_object(space, &locator);
        // A large object is written before its unit and without the
        // device's lock, so that other writes go on meanwhile; a small one
        // goes in the unit's commit.
        if stored.iter().map(|part| part.chunk.len()).sum::<usize>() >= OWN_COMMIT_BYTES {
            self.mark_sealed(space, [&locator]).await;
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
    pub(crate) async fn write_blob_op(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        op: frasil_adapter_blobs::content::Op,
        objects: Vec<Locator>,
        parents: &[[u8; 16]],
        stored: Vec<ObjectPart>,
    ) -> Result<EventId> {
        use frasil_adapter_blobs::content::Change;
        let named = objects.clone();
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
        // An object this device put stays until an always-on peer holds
        // it.
        for locator in &named {
            self.retain_put(&mut state, space, locator).await?;
        }
        Ok(id)
    }
}

#[cfg(all(test, feature = "adapter-blobs"))]
mod plain_tests;

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

    /// Sealed chunks, by index.
    type Chunks = Vec<(u64, Vec<u8>)>;

    /// Takes every slice from where the reader stands: the chunks cut, by
    /// index, the slices taken, and the most bytes it held between slices.
    /// The first part cut carries the header, and no other.
    fn read_all(reader: &mut SliceReader, stored: &[u8]) -> (Chunks, Vec<u64>, usize) {
        let mut parts = Vec::new();
        let mut slices = Vec::new();
        let mut most = 0;
        while let Some(index) = reader.next_slice() {
            let at = index as usize * SLICE_BYTES;
            let slice = &stored[at..(at + SLICE_BYTES).min(stored.len())];
            slices.push(index);
            for part in reader.take(slice).unwrap() {
                assert_eq!(part.header.is_some(), parts.is_empty());
                parts.push((part.index, part.chunk));
            }
            most = most.max(reader.pending.capacity());
        }
        (parts, slices, most)
    }

    /// The object's chunks in a range, by index.
    fn chunks_of(object: &SealedObject, range: core::ops::Range<usize>) -> Chunks {
        object.chunks[range]
            .iter()
            .map(|chunk| (chunk.index, chunk.sealed.clone()))
            .collect()
    }

    /// Slices cut into the object's sealed chunks, in order, holding at
    /// most one chunk's bytes between them.
    #[test]
    fn slices_are_cut_into_sealed_chunks() {
        let object = object();
        let mut reader = SliceReader::start(object.locator, None, 0..u64::MAX);
        let (parts, slices, most) = read_all(&mut reader, &object.bytes);
        assert_eq!(object.chunks.len(), 4);
        assert_eq!(parts, chunks_of(&object, 0..4));
        assert_eq!(slices, vec![0, 1, 2, 3]);
        assert!(most <= SLICE_BYTES, "{most}");
        assert_eq!(reader.next_chunk(), None);
    }

    /// A fetch that holds the header starts at the slice its first chunk
    /// begins in, whichever chunk that is, and takes one slice more than
    /// it cuts chunks, but for the last chunk, which ends its slice.
    #[test]
    fn a_fetch_starts_at_any_chunk_under_a_header_held() {
        let object = object();
        for first in 0..4usize {
            for end in first + 1..=4 {
                let mut reader = SliceReader::start(
                    object.locator,
                    Some(object.header.clone()),
                    first as u64..end as u64,
                );
                assert_eq!(reader.next_chunk(), Some(first as u64));
                let (parts, slices, most) = read_all(&mut reader, &object.bytes);
                assert_eq!(parts, chunks_of(&object, first..end), "{first}..{end}");
                let last = if end == 4 { 3 } else { end as u64 };
                assert_eq!(slices, (first as u64..=last).collect::<Vec<_>>());
                assert!(most <= SLICE_BYTES, "{most}");
            }
        }
        // To the end, however far the range reaches.
        let mut reader =
            SliceReader::start(object.locator, Some(object.header.clone()), 2..u64::MAX);
        let (parts, slices, _) = read_all(&mut reader, &object.bytes);
        assert_eq!(parts, chunks_of(&object, 2..4));
        assert_eq!(slices, vec![2, 3]);
        // Nothing wanted, or nothing left of the object: no slice.
        let reader = SliceReader::start(object.locator, Some(object.header.clone()), 4..9);
        assert_eq!(reader.next_slice(), None);
        let reader = SliceReader::start(object.locator, Some(object.header.clone()), 2..2);
        assert_eq!(reader.next_slice(), None);
    }

    /// A fetch that holds no header takes slice 0 first, for the header
    /// alone when it wants a later chunk, then the slices of its chunks.
    #[test]
    fn a_fetch_with_no_header_takes_slice_0_first() {
        let object = object();
        let mut reader = SliceReader::start(object.locator, None, 2..3);
        assert_eq!(reader.next_slice(), Some(0));
        assert_eq!(reader.next_chunk(), Some(2));
        let (parts, slices, _) = read_all(&mut reader, &object.bytes);
        assert_eq!(parts, chunks_of(&object, 2..3));
        assert_eq!(slices, vec![0, 2, 3]);
        // From chunk 0, slice 0 gives the header and the chunk's start.
        let mut reader = SliceReader::start(object.locator, None, 0..1);
        let (parts, slices, _) = read_all(&mut reader, &object.bytes);
        assert_eq!(parts, chunks_of(&object, 0..1));
        assert_eq!(slices, vec![0, 1]);
        // A range past the object's end, learnt from the header: no more.
        let mut reader = SliceReader::start(object.locator, None, 7..9);
        let (parts, slices, _) = read_all(&mut reader, &object.bytes);
        assert!(parts.is_empty());
        assert_eq!(slices, vec![0]);
        assert_eq!(reader.beyond(), Some(&object.header[..]));
        let within = SliceReader::start(object.locator, Some(object.header.clone()), 2..3);
        assert_eq!(within.beyond(), None);
        // A header held that does not read is not used.
        let reader = SliceReader::start(object.locator, Some(vec![1, 2, 3]), 2..3);
        assert_eq!(reader.next_slice(), Some(0));
    }

    /// A fetch leaves out chunks the device holds: it goes on at the slice
    /// the next chunk wanted begins in, and that chunk's part carries the
    /// header again.
    #[test]
    fn a_fetch_seeks_over_chunks_held() {
        let object = object();
        let slice = |index: usize| {
            let at = index * SLICE_BYTES;
            &object.bytes[at..(at + SLICE_BYTES).min(object.bytes.len())]
        };
        let mut reader =
            SliceReader::start(object.locator, Some(object.header.clone()), 0..u64::MAX);
        assert!(reader.take(slice(0)).unwrap().is_empty());
        let parts = reader.take(slice(1)).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            (parts[0].index, &parts[0].chunk),
            (0, &object.chunks[0].sealed)
        );
        assert!(parts[0].header.is_some());
        // Chunks 1 and 2 are held: the start of chunk 1 is dropped.
        assert_eq!(reader.next_chunk(), Some(1));
        reader.seek(3);
        assert_eq!(reader.next_slice(), Some(3));
        let parts = reader.take(slice(3)).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(
            (parts[0].index, &parts[0].chunk),
            (3, &object.chunks[3].sealed)
        );
        assert!(parts[0].header.is_some());
        assert_eq!(reader.next_slice(), None);
        // A seek to the next chunk, or back, changes nothing.
        let mut reader =
            SliceReader::start(object.locator, Some(object.header.clone()), 1..u64::MAX);
        reader.take(slice(1)).unwrap();
        reader.seek(1);
        reader.seek(0);
        let parts = reader.take(slice(2)).unwrap();
        assert_eq!(
            (parts[0].index, &parts[0].chunk),
            (1, &object.chunks[1].sealed)
        );
        // A seek before the header is read sets the first chunk wanted.
        let mut reader = SliceReader::start(object.locator, None, 0..u64::MAX);
        reader.seek(3);
        assert_eq!(reader.next_slice(), Some(0));
        assert!(reader.take(slice(0)).unwrap().is_empty());
        assert_eq!(reader.next_slice(), Some(3));
        assert_eq!(reader.take(slice(3)).unwrap().len(), 1);
    }

    /// A slice that ends the object with bytes after its last chunk is
    /// refused, and one of a fetch that ends before the last chunk is not.
    #[test]
    fn the_last_slice_ends_with_the_last_chunk() {
        let object = object();
        let mut longer = object.bytes[3 * SLICE_BYTES..].to_vec();
        longer.push(0);
        let mut reader =
            SliceReader::start(object.locator, Some(object.header.clone()), 3..u64::MAX);
        assert_eq!(
            reader.take(&longer).unwrap_err().class_name(),
            Some("Malformed")
        );
        let mut reader = SliceReader::start(object.locator, Some(object.header.clone()), 1..2);
        reader
            .take(&object.bytes[SLICE_BYTES..2 * SLICE_BYTES])
            .unwrap();
        let parts = reader
            .take(&object.bytes[2 * SLICE_BYTES..3 * SLICE_BYTES])
            .unwrap();
        assert_eq!(parts.len(), 1);
    }

    /// A slice of another length than the header gives, or a header of
    /// another object, is refused by class.
    #[test]
    fn a_slice_that_does_not_fit_is_refused() {
        let object = object();
        let mut reader = SliceReader::start(object.locator, None, 0..u64::MAX);
        let short = &object.bytes[..SLICE_BYTES - 1];
        assert_eq!(
            reader.take(short).unwrap_err().class_name(),
            Some("Malformed")
        );
        let mut other = object.locator;
        other[0] ^= 1;
        let mut reader = SliceReader::start(other, None, 0..u64::MAX);
        assert_eq!(
            reader
                .take(&object.bytes[..SLICE_BYTES])
                .unwrap_err()
                .class_name(),
            Some("ObjectMismatch")
        );
        let mut reader = SliceReader::start(object.locator, None, 0..u64::MAX);
        assert_eq!(
            reader.take(&[0, 0]).unwrap_err().class_name(),
            Some("Malformed")
        );
    }
}
