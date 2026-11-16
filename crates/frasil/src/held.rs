//! Held objects (at-rest.md, "Held objects"): a space's blobs kept by the
//! application as its own files, in place of their sealed chunks.
//!
//! Under the `held` policy Frasil keeps of an object its header and one
//! `held` record (the application's token for the plaintext, its size and
//! a change stamp), and no chunk records. Object sealing is deterministic
//! (units.md, "Objects"), so a device that holds the plaintext, the space
//! ID, the object ID and `k(S)` seals the chunks again byte for byte when
//! it serves them, and the other side cannot tell. The application gives an
//! [`ObjectProvider`] per space, or one for every space, on this device
//! alone: the policy is never synced and never stored.
//!
//! The procedures are functions over a provider, which the vectors drive:
//!
//! - [`put_with`] reads the file twice: once for the object ID, which is in
//!   every chunk's associated data, and once to seal the chunks, hash the
//!   digest and reach the locator.
//! - [`serve_with`] checks the token's size and stamp against the record,
//!   seals the chunks asked for, and, when it reads through from chunk 0 to
//!   the end, the object ID and the digest in the same pass. A difference
//!   is [`Served::NotHeld`]: the engine then withdraws the object, keeps
//!   the header, tells the application, and the object stays fetchable.
//! - [`Receiver`] writes the plaintext through the provider as the chunks
//!   open, in order, and checks the digest, and with `k(S)` the object ID,
//!   once every chunk is written.
//!
//! The engine commits the header and the `held` record after a put or a
//! receive, calls the provider's `forget` for each token when a space is
//! forgotten, and announces and serves held objects as it does stored ones.
//! The engine's state is never locked while the provider reads or writes
//! a file, except while chunks that arrive from a connection are written
//! through, one chunk at a time. Frasil's own objects, the space snapshot
//! and stream snapshots, are read by Frasil and never by the application,
//! so they stay sealed under every policy; every other object of the space
//! follows it. A reference's object (adapter-blobs.md, "References") is
//! held like any other once fetched, and never announced or served: with
//! the object key alone the device cannot seal its chunks again ("The
//! limit"). A store opened without a provider for a space with `held`
//! records treats them as not held until a provider is given, and deletes
//! nothing.
//!
//! The vectors lower the chunk size to show an object of several chunks;
//! the `_chunked` forms take it, and the others use `CHUNK_BYTES`.

use crate::at_rest::Batch;
use crate::client::SpaceId;
use crate::device::{Engine, Notice, State};
use crate::error::{Error, Result};
use crate::replica::Replica;
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_crypto::primitives::{HmacSha256, Sha256Hasher, xchacha20poly1305_open};
use frasil_events::EventId;
use frasil_store::store::{MaybeSend, MaybeSync};
use frasil_store::tables::{HeldRecord, MAX_HELD_STAMP, MAX_HELD_TOKEN};
use frasil_store::{BoxFuture, Table, TableValue};
use frasil_units::limits::{CHUNK_BYTES, NONCE_BYTES};
use frasil_units::objects::{Header, ObjectKeys, chunk_aad, chunk_count, plain_length, seal_chunk};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::Zeroizing;

/// What a provider reports of a token's plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStat {
    /// The plaintext's length.
    pub size: u64,
    /// The application's change stamp, 1 to 64 bytes, compared byte for
    /// byte and never interpreted: a modification time with an inode, a
    /// content hash, a version counter.
    pub stamp: Vec<u8>,
}

/// The application's object provider (at-rest.md, "Held objects"): where
/// the plaintexts of a space's held objects live, named by **tokens** the
/// application chooses, 1 to 1,024 bytes each: a path, a hash, an entry ID.
/// Tokens are not exclusive: two spaces may hold one file through one
/// token, and a `forget` from one says nothing about the other.
pub trait ObjectProvider: MaybeSend + MaybeSync {
    /// `stat(token)`: the plaintext's size and current stamp, or `None`
    /// when it is gone.
    fn stat<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Option<ObjectStat>>>;

    /// `open(token)`: a reader of the plaintext.
    fn open<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Box<dyn ObjectReader>>>;

    /// `create(space, object ID, size, hint)`: a place for a plaintext
    /// being received. `hint` is what the application passed to the call
    /// that caused the fetch, such as a path, and is empty when Frasil
    /// started it.
    fn create<'a>(
        &'a self,
        space: SpaceId,
        object_id: [u8; 32],
        size: u64,
        hint: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn ObjectWriter>>>;

    /// `forget(token)`: Frasil no longer needs the token. The application
    /// decides about the file; Frasil deletes nothing of the application's.
    fn forget<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<()>>;
}

/// A reader of a held plaintext.
pub trait ObjectReader: MaybeSend {
    /// Reads at `offset` into `buf`, as far as the plaintext goes: the
    /// number of bytes read, 0 at its end.
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>>;
}

/// A writer of a plaintext being received: it takes the plaintext in
/// order, then finishes with the token and stamp of the file it made, or
/// aborts, which deletes the partial file.
pub trait ObjectWriter: MaybeSend {
    /// Appends bytes.
    fn write<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    /// `finish()`: the file is whole; its token and stamp.
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(Vec<u8>, Vec<u8>)>>;

    /// `abort()`: the partial file goes.
    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<()>>;
}

/// A space's object policy on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectPolicy {
    /// The default: each object's sealed chunks are kept in the store.
    Sealed,
    /// The application holds each blob's plaintext through its provider,
    /// and the store keeps the header and the `held` record.
    Held,
}

/// A held object the device withdrew as not held: its file changed or is
/// gone (at-rest.md, "Held objects", serving). The application may put the
/// changed file as a new object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    /// The space.
    pub space: EventId,
    /// The object's ID.
    pub object_id: [u8; 32],
    /// The token the record named.
    pub token: Vec<u8>,
}

// ---------------------------------------------------------------------------
// The procedures, over a provider.

/// The object ID a locator names.
fn object_id(locator: &Locator) -> [u8; 32] {
    let mut id = [0; 32];
    id.copy_from_slice(&locator[..32]);
    id
}

/// A locator from an ID and a digest.
fn locator_of(id: &[u8; 32], digest: &[u8; 32]) -> Locator {
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(id);
    locator[32..].copy_from_slice(digest);
    locator
}

/// The item of an object's part 0 record.
fn header_item(id: &[u8; 32]) -> Vec<u8> {
    [&id[..], &0u32.to_be_bytes()].concat()
}

/// Reads exactly `length` bytes at `offset`, or fails `Changed`: the
/// plaintext is shorter than its record says.
async fn read_exact(reader: &mut dyn ObjectReader, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; length];
    let mut filled = 0;
    while filled < length {
        let read = reader
            .read_at(offset + filled as u64, &mut out[filled..])
            .await?;
        if read == 0 {
            return Err(Error::Class("Changed"));
        }
        filled += read;
    }
    Ok(out)
}

/// The length of chunk `index`'s plaintext, as a `usize`.
fn piece(size: u64, chunk: u64, index: u64) -> Result<usize> {
    usize::try_from(plain_length(size, chunk, index)).map_err(|_| Error::Class("TooLarge"))
}

/// Whether a stat is the record's size and stamp.
fn same_file(stat: Option<&ObjectStat>, record: &HeldRecord) -> bool {
    stat.is_some_and(|stat| stat.size == record.size && stat.stamp == record.stamp)
}

/// A token is 1 to 1,024 bytes (at-rest.md, "Tables").
fn check_token(token: &[u8]) -> Result<()> {
    if (1..=MAX_HELD_TOKEN).contains(&token.len()) {
        Ok(())
    } else {
        Err(Error::Invalid("a token is 1 to 1,024 bytes"))
    }
}

/// A stamp is 1 to 64 bytes (at-rest.md, "Tables").
fn check_stamp(stamp: &[u8]) -> Result<()> {
    if (1..=MAX_HELD_STAMP).contains(&stamp.len()) {
        Ok(())
    } else {
        Err(Error::Invalid("a stamp is 1 to 64 bytes"))
    }
}

/// The digest's start: `u32be(len(header)) || header`.
fn digest_of_header(header: &[u8]) -> Result<Sha256Hasher> {
    let mut digest = Sha256Hasher::new();
    let length = u32::try_from(header.len()).map_err(|_| Error::Class("TooLarge"))?;
    digest.update(&length.to_be_bytes());
    digest.update(header);
    Ok(digest)
}

/// A pass over a held plaintext, from chunk `first` to chunk `last − 1`:
/// the chunks sealed again, and, over what it read, the object ID and the
/// digest so far.
struct Pass {
    parts: Vec<ObjectPart>,
    id: HmacSha256,
    digest: Sha256Hasher,
}

#[allow(clippy::too_many_arguments)]
async fn seal_range(
    reader: &mut dyn ObjectReader,
    space: &EventId,
    keys: &ObjectKeys,
    header: &Header,
    header_bytes: &[u8],
    chunk: u64,
    first: u64,
    last: u64,
) -> Result<Pass> {
    let object_key = keys.object_key(&header.object_id);
    let mut id = HmacSha256::new(&*keys.id_key);
    let mut digest = digest_of_header(header_bytes)?;
    let mut parts = Vec::new();
    for index in first..last {
        let plain = read_exact(reader, index * chunk, piece(header.size, chunk, index)?).await?;
        let sealed = seal_chunk(
            space,
            keys,
            &object_key,
            &header.object_id,
            header.size,
            index,
            &plain,
        );
        id.update(&plain);
        digest.update(&sealed.sealed);
        parts.push(ObjectPart {
            locator: locator_of(&header.object_id, &[0; 32]),
            header: (index == 0).then(|| header_bytes.to_vec()),
            index,
            chunk: sealed.sealed,
        });
    }
    Ok(Pass { parts, id, digest })
}

/// What a held put yields: the object's locator, its header, its chunks
/// as sealed in the second pass, and the `held` record to commit with the
/// header.
#[derive(Debug, Clone)]
pub struct HeldPut {
    /// The locator.
    pub locator: Locator,
    /// The header's bytes.
    pub header: Vec<u8>,
    /// Each chunk, as the second pass sealed it, to upload or to keep.
    pub parts: Vec<ObjectPart>,
    /// The `held` record: the token, and the size and stamp of the first
    /// `stat`.
    pub record: HeldRecord,
}

/// `put_held(space, token)` (at-rest.md, "Held objects", putting), under
/// the state whose content key and key reference these are: `stat`; pass
/// one, the object ID over the plaintext; pass two, each chunk sealed and
/// hashed into the digest; `stat` again. The caller commits the header and
/// the record in one step.
///
/// # Errors
///
/// [`Error::Invalid`] for a token or a stamp outside the record's bounds;
/// `Changed` when the plaintext is gone, shorter or longer than `stat`
/// said, or changed between the passes; `TooLarge` over 2^40 bytes; the
/// provider's.
pub async fn put_with(
    provider: &dyn ObjectProvider,
    space: &EventId,
    content_key: &[u8; 32],
    key_reference: &[u8],
    token: &[u8],
) -> Result<HeldPut> {
    put_with_chunked(
        provider,
        space,
        content_key,
        key_reference,
        token,
        CHUNK_BYTES as u64,
    )
    .await
}

/// [`put_with`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`put_with`]; `Malformed` for a chunk size of 0.
pub async fn put_with_chunked(
    provider: &dyn ObjectProvider,
    space: &EventId,
    content_key: &[u8; 32],
    key_reference: &[u8],
    token: &[u8],
    chunk: u64,
) -> Result<HeldPut> {
    if chunk == 0 {
        return Err(Error::Class("Malformed"));
    }
    check_token(token)?;
    // 1. The size and the stamp.
    let stat = provider.stat(token).await?.ok_or(Error::Class("Changed"))?;
    check_stamp(&stat.stamp)?;
    if stat.size > frasil_units::limits::MAX_OBJECT_BYTES {
        return Err(Error::Class("TooLarge"));
    }
    let keys = ObjectKeys::of(content_key);
    // 2. Pass one: the object ID over the whole plaintext, which gives
    // exactly the size.
    let mut reader = provider.open(token).await?;
    let mut id = HmacSha256::new(&*keys.id_key);
    let mut offset = 0u64;
    let mut buffer = vec![0; 64 * 1024];
    while offset < stat.size {
        let read = reader.read_at(offset, &mut buffer).await?;
        if read == 0 {
            return Err(Error::Class("Changed"));
        }
        let left = usize::try_from(stat.size - offset).unwrap_or(usize::MAX);
        let take = read.min(left);
        id.update(&buffer[..take]);
        offset += take as u64;
    }
    let mut past_end = [0u8; 1];
    if reader.read_at(stat.size, &mut past_end).await? != 0 {
        return Err(Error::Class("Changed"));
    }
    let object_id = id.finish();
    // 3. Pass two: each chunk sealed and hashed into the digest.
    let header = Header {
        object_id,
        key_reference: key_reference.to_vec(),
        size: stat.size,
    };
    let header_bytes = header.encode();
    let count = chunk_count(stat.size, chunk);
    let pass = seal_range(
        reader.as_mut(),
        space,
        &keys,
        &header,
        &header_bytes,
        chunk,
        0,
        count,
    )
    .await?;
    if pass.id.finish() != object_id {
        return Err(Error::Class("Changed"));
    }
    let locator = locator_of(&object_id, &pass.digest.finish());
    // 4. The stamp again.
    if provider.stat(token).await?.as_ref() != Some(&stat) {
        return Err(Error::Class("Changed"));
    }
    // 5. What one commit stores.
    Ok(HeldPut {
        locator,
        header: header_bytes,
        parts: pass
            .parts
            .into_iter()
            .map(|part| ObjectPart { locator, ..part })
            .collect(),
        record: HeldRecord {
            token: token.to_vec(),
            size: stat.size,
            stamp: stat.stamp,
        },
    })
}

/// What a serve of a held object found.
#[derive(Debug, Clone)]
pub enum Served {
    /// The chunks asked for, sealed again, with the object's locator.
    Held {
        /// The locator: the one given, or the one a whole pass computed.
        locator: Locator,
        /// The chunks asked for.
        parts: Vec<ObjectPart>,
    },
    /// The file's size or stamp is not the record's, the plaintext is
    /// shorter than it says, or a whole pass found another ID or digest:
    /// the object is withdrawn.
    NotHeld,
}

/// The serve procedure (at-rest.md, "Held objects", serving) on a held
/// object whose header and record these are, under the state whose
/// content key this is: chunks `first` to `first + count − 1`, sealed
/// again from the plaintext. A serve from chunk 0 to the end also checks
/// the object ID and, with `locator` given, the digest; without a locator
/// the whole object is read and its locator computed.
///
/// # Errors
///
/// `Malformed` for a header that does not read; the provider's.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with(
    provider: &dyn ObjectProvider,
    space: &EventId,
    content_key: &[u8; 32],
    header_bytes: &[u8],
    record: &HeldRecord,
    locator: Option<Locator>,
    first: u64,
    count: u64,
) -> Result<Served> {
    serve_with_chunked(
        provider,
        space,
        content_key,
        header_bytes,
        record,
        locator,
        first,
        count,
        CHUNK_BYTES as u64,
    )
    .await
}

/// [`serve_with`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`serve_with`]; `Malformed` for a chunk size of 0.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_chunked(
    provider: &dyn ObjectProvider,
    space: &EventId,
    content_key: &[u8; 32],
    header_bytes: &[u8],
    record: &HeldRecord,
    locator: Option<Locator>,
    first: u64,
    count: u64,
    chunk: u64,
) -> Result<Served> {
    if chunk == 0 {
        return Err(Error::Class("Malformed"));
    }
    let header = Header::read(header_bytes).map_err(Error::class)?;
    let n = chunk_count(header.size, chunk);
    let (first, last) = match locator {
        Some(_) => (first.min(n), first.saturating_add(count).min(n)),
        None => (0, n),
    };
    let whole = first == 0 && last == n;
    // 1. The size and the stamp are the record's.
    if !same_file(provider.stat(&record.token).await?.as_ref(), record) {
        return Ok(Served::NotHeld);
    }
    // 2. Each chunk asked for.
    let keys = ObjectKeys::of(content_key);
    let mut reader = provider.open(&record.token).await?;
    let pass = match seal_range(
        reader.as_mut(),
        space,
        &keys,
        &header,
        header_bytes,
        chunk,
        first,
        last,
    )
    .await
    {
        Ok(pass) => pass,
        Err(Error::Class("Changed")) => return Ok(Served::NotHeld),
        Err(error) => return Err(error),
    };
    // 3. A whole pass checks the ID and the digest.
    let locator = if whole {
        let computed = locator_of(&header.object_id, &pass.digest.finish());
        if pass.id.finish() != header.object_id || locator.is_some_and(|known| known != computed) {
            return Ok(Served::NotHeld);
        }
        computed
    } else {
        locator.expect("a partial serve has a locator")
    };
    Ok(Served::Held {
        locator,
        parts: pass
            .parts
            .into_iter()
            .map(|part| ObjectPart { locator, ..part })
            .collect(),
    })
}

/// The key a receiver opens chunks with.
#[derive(Debug, Clone, Copy)]
pub enum ReceiveKey<'a> {
    /// `k(S)` of the object's state: the object ID is checked once the
    /// plaintext is written.
    State(&'a [u8; 32]),
    /// The object's own key alone, from a reference: only the digest is
    /// checked.
    Object(&'a [u8; 32]),
}

/// A receive in progress (at-rest.md, "Held objects", receiving): chunks
/// opened and written through the provider's writer in order, then the
/// checks of the whole, then the token and the stamp.
pub struct Receiver {
    writer: Box<dyn ObjectWriter>,
    header: Header,
    sealed_by: EventId,
    object_key: Zeroizing<[u8; 32]>,
    id: Option<HmacSha256>,
    digest: Sha256Hasher,
    chunk: u64,
    next: u64,
}

impl core::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receiver")
            .field("object", &self.header.object_id)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl Receiver {
    /// Step 1: once the header is held, a writer from `create`.
    /// `sealed_by` is the space whose ID each chunk's associated data
    /// names: the object's own space, or a reference's source. `space` is
    /// the space the object is received for.
    ///
    /// # Errors
    ///
    /// `Malformed` for a header that does not read; the provider's.
    pub async fn start(
        provider: &dyn ObjectProvider,
        space: EventId,
        sealed_by: EventId,
        header_bytes: &[u8],
        key: ReceiveKey<'_>,
        hint: &[u8],
    ) -> Result<Self> {
        Self::start_chunked(
            provider,
            space,
            sealed_by,
            header_bytes,
            key,
            hint,
            CHUNK_BYTES as u64,
        )
        .await
    }

    /// [`Receiver::start`] with another chunk size, as the vectors use.
    ///
    /// # Errors
    ///
    /// As [`Receiver::start`]; `Malformed` for a chunk size of 0.
    pub async fn start_chunked(
        provider: &dyn ObjectProvider,
        space: EventId,
        sealed_by: EventId,
        header_bytes: &[u8],
        key: ReceiveKey<'_>,
        hint: &[u8],
        chunk: u64,
    ) -> Result<Self> {
        if chunk == 0 {
            return Err(Error::Class("Malformed"));
        }
        let header = Header::read(header_bytes).map_err(Error::class)?;
        let (object_key, id) = match key {
            ReceiveKey::State(content_key) => {
                let keys = ObjectKeys::of(content_key);
                (
                    keys.object_key(&header.object_id),
                    Some(HmacSha256::new(&*keys.id_key)),
                )
            }
            ReceiveKey::Object(object_key) => (Zeroizing::new(*object_key), None),
        };
        let writer = provider
            .create(SpaceId::of(space), header.object_id, header.size, hint)
            .await?;
        Ok(Self {
            writer,
            header,
            sealed_by,
            object_key,
            id,
            digest: digest_of_header(header_bytes)?,
            chunk,
            next: 0,
        })
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The index of the next chunk to take.
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Whether every chunk is written.
    pub fn is_complete(&self) -> bool {
        self.next >= chunk_count(self.header.size, self.chunk)
    }

    /// Step 2: the next chunk, opened under the object key and written
    /// through. On an error the receiver is spent: the caller aborts it.
    ///
    /// # Errors
    ///
    /// `Decrypt` for a chunk that does not open at its place; `Malformed`
    /// for one of the wrong length; the writer's.
    pub async fn chunk(&mut self, sealed: &[u8]) -> Result<()> {
        let index = self.next;
        let (nonce, ciphertext) = sealed
            .split_at_checked(NONCE_BYTES)
            .ok_or(Error::Class("Malformed"))?;
        let nonce: &[u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Error::Class("Malformed"))?;
        let aad = chunk_aad(
            &self.sealed_by,
            &self.header.object_id,
            self.header.size,
            index,
        );
        let plain = xchacha20poly1305_open(&self.object_key, nonce, &aad, ciphertext)
            .map_err(|_| Error::Class("Decrypt"))?;
        if plain.len() != piece(self.header.size, self.chunk, index)? {
            return Err(Error::Class("Malformed"));
        }
        self.writer.write(&plain).await?;
        if let Some(id) = &mut self.id {
            id.update(&plain);
        }
        self.digest.update(sealed);
        self.next += 1;
        Ok(())
    }

    /// Steps 3 and 4: once every chunk is written, the digest is the
    /// locator's, and with `k(S)` the object ID is the header's; then
    /// `finish` gives the token and the stamp, as the `held` record to
    /// commit with the header. On a failure the writer is aborted; a token
    /// or stamp outside the record's bounds is forgotten through
    /// `provider`.
    ///
    /// # Errors
    ///
    /// `ObjectMismatch`; `Malformed` before every chunk is written;
    /// [`Error::Invalid`] for a token or stamp outside the bounds; the
    /// writer's.
    pub async fn finish(
        self,
        provider: &dyn ObjectProvider,
        locator: &Locator,
    ) -> Result<HeldRecord> {
        if !self.is_complete() {
            let _ = self.writer.abort().await;
            return Err(Error::Class("Malformed"));
        }
        let digest_ok = self.digest.finish()[..] == locator[32..];
        let id_ok = self
            .id
            .is_none_or(|id| id.finish() == self.header.object_id);
        if !digest_ok || !id_ok {
            let _ = self.writer.abort().await;
            return Err(Error::Class("ObjectMismatch"));
        }
        let (token, stamp) = self.writer.finish().await?;
        if let Err(error) = check_token(&token).and_then(|()| check_stamp(&stamp)) {
            let _ = provider.forget(&token).await;
            return Err(error);
        }
        Ok(HeldRecord {
            token,
            size: self.header.size,
            stamp,
        })
    }

    /// Ends the receive: the writer is aborted and the partial file goes.
    pub async fn abort(self) {
        let _ = self.writer.abort().await;
    }
}

// ---------------------------------------------------------------------------
// The engine's state.

/// The providers the application gave: one for every space, and one per
/// space, with the spaces set back to `sealed` over a device-wide one.
#[derive(Default)]
pub(crate) struct Providers {
    default: Option<Arc<dyn ObjectProvider>>,
    spaces: BTreeMap<EventId, Arc<dyn ObjectProvider>>,
    sealed: BTreeSet<EventId>,
    /// Whether the providers changed since the replicas last marked their
    /// held objects: a store's held records count as held only while a
    /// provider is given.
    changed: bool,
}

impl Providers {
    fn for_space(&self, space: &EventId) -> Option<Arc<dyn ObjectProvider>> {
        match self.spaces.get(space) {
            Some(provider) => Some(provider.clone()),
            None if self.sealed.contains(space) => None,
            None => self.default.clone(),
        }
    }
}

/// A held object as the device holds it.
#[derive(Debug, Clone)]
pub(crate) struct HeldEntry {
    /// The `held` record.
    pub record: HeldRecord,
    /// The header, from the `object` part 0 record.
    pub header: Vec<u8>,
    /// The locator, once known: from the put or the fetch, from a unit
    /// that names the ID, or from a pass over the plaintext.
    pub locator: Option<Locator>,
}

/// An object being received through a provider's writer, with the chunks
/// that arrived before one they follow.
struct Receiving {
    receiver: Receiver,
    waiting: BTreeMap<u64, Vec<u8>>,
}

/// The device's held objects, by space.
#[derive(Default)]
pub(crate) struct HeldObjects {
    /// Each space's held objects, by object ID.
    pub objects: BTreeMap<EventId, BTreeMap<[u8; 32], HeldEntry>>,
    /// Objects being received, by space and locator.
    receiving: BTreeMap<(EventId, Locator), Receiving>,
    /// Hints for fetches the application started, by space and locator.
    hints: BTreeMap<(EventId, Locator), Vec<u8>>,
}

impl HeldObjects {
    /// Whether the application started a fetch of the object.
    pub fn asked_for(&self, space: &EventId, locator: &Locator) -> bool {
        self.hints.contains_key(&(*space, *locator))
    }

    /// The held entry of an object, by ID.
    pub fn entry(&self, space: &EventId, id: &[u8; 32]) -> Option<&HeldEntry> {
        self.objects.get(space)?.get(id)
    }

    /// Whether the device holds an object, by locator.
    pub fn holds(&self, space: &EventId, locator: &Locator) -> bool {
        self.entry(space, &object_id(locator)).is_some()
    }

    /// Keeps a held object's entry.
    fn keep(&mut self, space: EventId, id: [u8; 32], entry: HeldEntry) {
        self.objects.entry(space).or_default().insert(id, entry);
    }

    /// Forgets a held object's entry.
    fn remove(&mut self, space: &EventId, id: &[u8; 32]) -> Option<HeldEntry> {
        self.objects.get_mut(space)?.remove(id)
    }

    /// Every held object of a space, with its token.
    pub fn tokens(&self, space: &EventId) -> Vec<Vec<u8>> {
        self.objects
            .get(space)
            .map(|objects| objects.values().map(|e| e.record.token.clone()).collect())
            .unwrap_or_default()
    }
}

/// The objects the blob streams' current entries name.
#[cfg(feature = "adapter-blobs")]
fn blob_locators(replica: &Replica) -> BTreeSet<Locator> {
    use frasil_units::runtime::Stream;
    replica
        .streams()
        .filter(|(_, adapter)| *adapter == frasil_adapter_blobs::TYPE)
        .filter_map(|(stream, _)| {
            replica
                .stream(stream)?
                .as_any()
                .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()
        })
        .flat_map(|blobs| blobs.state().current().map(|(_, entry)| entry.object))
        .collect()
}

#[cfg(not(feature = "adapter-blobs"))]
fn blob_locators(_: &Replica) -> BTreeSet<Locator> {
    BTreeSet::new()
}

/// The locator a blob stream's current entries give an object ID, if any.
fn blob_locator(replica: &Replica, id: &[u8; 32]) -> Option<Locator> {
    blob_locators(replica)
        .into_iter()
        .find(|l| l[..32] == id[..])
}

/// Whether a blob stream's current entry names the locator.
fn is_blob(replica: &Replica, locator: &Locator) -> bool {
    blob_locators(replica).contains(locator)
}

/// The source and object key of a reference entry that names the locator,
/// in any blob stream of the replica.
#[cfg(feature = "adapter-blobs")]
fn reference_in(replica: &Replica, locator: &Locator) -> Option<(EventId, [u8; 32])> {
    use frasil_units::runtime::Stream;
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

#[cfg(not(feature = "adapter-blobs"))]
fn reference_in(_: &Replica, _: &Locator) -> Option<(EventId, [u8; 32])> {
    None
}

/// Whether an object is Frasil's own, read by Frasil and never by the
/// application: the space snapshot a newcomer awaits, a stream snapshot
/// object not yet loaded, or an object a snapshot unit or a unit of the
/// system stream names, such as a `frasil:body-keys` unit that names a
/// newcomer's snapshot and its stream snapshot objects (units.md,
/// "Frasil's own units"). These stay sealed under every policy.
fn is_frasils_own(replica: &Replica, locator: &Locator) -> bool {
    if replica.awaited_snapshot() == Some(locator)
        || replica.pending_stream_objects().any(|l| l == locator)
    {
        return true;
    }
    let Some(log) = replica.log() else {
        return false;
    };
    let system = replica.system_stream();
    log.events()
        .filter(|event| event.kind() == frasil_events::kind::UNIT)
        .filter_map(|event| frasil_units::Unit::from_event(event.clone()).ok())
        .filter(|unit| unit.body.compacts.is_some() || Some(unit.body.stream) == system)
        .any(|unit| unit.body.objects.contains(locator))
}

/// A provider and the tokens to call `forget` for.
pub(crate) type Forgets = (Arc<dyn ObjectProvider>, Vec<Vec<u8>>);

/// What a held object is committed with: its header and its record.
fn commit_held(
    state: &mut State,
    batch: &mut Batch,
    space: &EventId,
    id: &[u8; 32],
    header: &[u8],
    record: &HeldRecord,
) -> Result<()> {
    if !state.vault.has_log(&space.0) {
        state
            .vault
            .add_log(batch, &space.0, frasil_store::tables::LogKind::Space)?;
    }
    state.vault.put(
        batch,
        &space.0,
        Table::Object,
        &header_item(id),
        &TableValue::Object(header.to_vec()),
    )?;
    state.vault.put(
        batch,
        &space.0,
        Table::Held,
        id,
        &TableValue::Held(record.clone()),
    )
}

/// Keeps a held entry in the state and marks it at the replica.
fn keep_held(state: &mut State, space: EventId, id: [u8; 32], entry: HeldEntry) {
    let (locator, header) = (entry.locator, entry.header.clone());
    state.held.keep(space, id, entry);
    if let (Some(locator), Some(replica)) = (locator, state.replicas.get_mut(&space)) {
        replica.keep_object(locator, Some(header), None);
        replica.mark_held(locator, true);
    }
}

impl Engine {
    // -- The policy

    /// The provider a space's objects are held through, if the space is
    /// held on this device: the space's own, or the device's, unless the
    /// space's grant carries `frasil.nothing-at-rest` (ext-guests.md), or
    /// the space was set back to `sealed`.
    pub(crate) fn provider_of(
        &self,
        state: &State,
        space: &EventId,
    ) -> Option<Arc<dyn ObjectProvider>> {
        if state.vault.is_memory_only(&space.0) {
            return None;
        }
        self.providers().for_space(space)
    }

    fn providers(&self) -> std::sync::MutexGuard<'_, Providers> {
        self.shared_providers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Holds every space's blobs through `provider`, now and from now on,
    /// unless a space is set otherwise with [`Engine::hold_objects`] or
    /// [`Engine::seal_objects`]. Blobs a space already stores sealed are
    /// written through the provider when [`Engine::hold_objects`] names
    /// the space.
    pub fn hold_all_objects(&self, provider: Arc<dyn ObjectProvider>) {
        let mut providers = self.providers();
        providers.default = Some(provider);
        providers.changed = true;
    }

    /// Marks the providers as changed: the replicas mark their held
    /// objects again at the next use.
    pub(crate) fn providers_changed(&self) {
        self.providers().changed = true;
    }

    /// A space's object policy on this device.
    pub async fn object_policy(&self, space: &EventId) -> ObjectPolicy {
        let state = self.lock().await;
        if self.provider_of(&state, space).is_some() {
            ObjectPolicy::Held
        } else {
            ObjectPolicy::Sealed
        }
    }

    /// Marks each space's held objects at its replica, once the providers
    /// changed: an object counts as held while its space has a provider,
    /// and as not held, fetchable like any other, without one (at-rest.md,
    /// "Held objects", the policy). Every use of held objects calls it.
    pub(crate) fn refresh_held(&self, state: &mut State) {
        if !std::mem::take(&mut self.providers().changed) {
            return;
        }
        let spaces: Vec<EventId> = state.held.objects.keys().copied().collect();
        for space in spaces {
            let provider = self.provider_of(state, &space);
            Self::resolve_held(state, &space, provider.is_some());
        }
    }

    /// Resolves the locators of a space's held objects from the units and
    /// blob entries that name their IDs, and marks them held, or not, at
    /// the replica.
    fn resolve_held(state: &mut State, space: &EventId, held: bool) {
        let Some(objects) = state.held.objects.get_mut(space) else {
            return;
        };
        let Some(replica) = state.replicas.get_mut(space) else {
            return;
        };
        let named = crate::objects::named_objects(replica);
        for (id, entry) in objects.iter_mut() {
            if entry.locator.is_none() {
                entry.locator = named
                    .iter()
                    .find(|l| l[..32] == id[..])
                    .copied()
                    .or_else(|| blob_locator(replica, id));
            }
            if let Some(locator) = entry.locator {
                if held {
                    replica.keep_object(locator, Some(entry.header.clone()), None);
                }
                replica.mark_held(locator, held);
            }
        }
    }

    /// Sets a space to `held` through `provider` (at-rest.md, "Held
    /// objects", changing the policy): each object the device holds whole
    /// but Frasil's own is written through the provider, and its chunk
    /// records go.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] when this device's
    /// grant carries `frasil.nothing-at-rest`; the provider's and the
    /// store's.
    pub async fn hold_objects(
        &self,
        space: EventId,
        provider: Arc<dyn ObjectProvider>,
    ) -> Result<()> {
        let candidates: Vec<Locator> = {
            let mut state = self.lock().await;
            if !state.replicas.contains_key(&space) {
                return Err(Error::UnknownSpace);
            }
            if state.vault.is_memory_only(&space.0) {
                return Err(Error::NotAllowed(
                    "the space's grant asked for nothing at rest",
                ));
            }
            {
                let mut providers = self.providers();
                providers.sealed.remove(&space);
                providers.spaces.insert(space, provider.clone());
                providers.changed = true;
            }
            self.refresh_held(&mut state);
            Self::locate_objects(&mut state, &space).await?;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            replica
                .whole_objects()
                .into_iter()
                .filter(|locator| {
                    // Only a blob: a snapshot the device has used is Frasil's
                    // own too, though nothing waits for it any more.
                    is_blob(replica, locator)
                        && !replica.is_held(locator)
                        && !is_frasils_own(replica, locator)
                        && !state.held.holds(&space, locator)
                })
                .collect()
        };
        // The local pass: each object the device stores sealed, read under
        // the lock and written through the provider outside it.
        for locator in candidates {
            if !self.hold_sealed(space, locator, &provider).await? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Holds one object the device stores sealed: its plaintext read under
    /// the lock, written through the provider outside it, then its `held`
    /// record committed and its chunk records deleted. `false` once the
    /// policy changed meanwhile, which ends the pass.
    async fn hold_sealed(
        &self,
        space: EventId,
        locator: Locator,
        provider: &Arc<dyn ObjectProvider>,
    ) -> Result<bool> {
        let (header, plaintext) = {
            let mut state = self.lock().await;
            let Some(bytes) = Self::stored_bytes(&mut state, &space, &locator).await? else {
                return Ok(true);
            };
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let checked =
                frasil_units::objects::check_stored(&bytes, &locator).map_err(Error::class)?;
            let header = checked.header.clone();
            let plaintext = match replica.object_key(&header.key_reference) {
                Some((key, _)) => {
                    frasil_units::objects::read_object(&bytes, &space, Some(&key), &locator)
                        .map_err(Error::class)?
                }
                None => {
                    let Some((source, object_key)) = reference_in(replica, &locator) else {
                        return Ok(true);
                    };
                    frasil_units::objects::read_object_with_key(
                        &bytes,
                        &source,
                        &object_key,
                        &locator,
                    )
                    .map_err(Error::class)?
                }
            };
            (header, plaintext)
        };
        let id = header.object_id;
        // A fetch the application asked for, whose key came after its chunks.
        let hint = {
            let state = self.lock().await;
            state.held.hints.get(&(space, locator)).cloned()
        };
        let mut writer = provider
            .create(
                SpaceId::of(space),
                id,
                header.size,
                hint.as_deref().unwrap_or_default(),
            )
            .await?;
        if let Err(error) = writer.write(&plaintext).await {
            let _ = writer.abort().await;
            return Err(error);
        }
        let (token, stamp) = writer.finish().await?;
        if let Err(error) = check_token(&token).and_then(|()| check_stamp(&stamp)) {
            let _ = provider.forget(&token).await;
            return Err(error);
        }
        let record = HeldRecord {
            token,
            size: header.size,
            stamp,
        };
        let mut state = self.lock().await;
        if !self
            .provider_of(&state, &space)
            .is_some_and(|current| Arc::ptr_eq(&current, provider))
        {
            // The policy changed during the write: the pass is over,
            // and this file is not kept.
            drop(state);
            provider.forget(&record.token).await?;
            return Ok(false);
        }
        if state.held.holds(&space, &locator) {
            // Held meanwhile, by a put or a fetch: this file is one too
            // many.
            drop(state);
            provider.forget(&record.token).await?;
            return Ok(true);
        }
        let count = chunk_count(header.size, CHUNK_BYTES as u64);
        let mut batch = Batch::default();
        state.vault.put(
            &mut batch,
            &space.0,
            Table::Held,
            &id,
            &TableValue::Held(record.clone()),
        )?;
        for index in 0..count {
            let part = crate::objects::chunk_part(index)?;
            state.vault.delete(
                &mut batch,
                &space.0,
                Table::Object,
                &[&id[..], &part.to_be_bytes()].concat(),
            );
        }
        if let Err(error) = state.vault.commit(batch).await {
            drop(state);
            let _ = provider.forget(&record.token).await;
            return Err(error);
        }
        state.held.hints.remove(&(space, locator));
        keep_held(
            &mut state,
            space,
            id,
            HeldEntry {
                record,
                header: header.encode(),
                locator: Some(locator),
            },
        );
        if let Some(replica) = state.replicas.get_mut(&space) {
            replica.drop_chunks(&locator);
        }
        Ok(true)
    }

    /// Holds each blob a current entry names that the device stores sealed,
    /// under `held`: the chunks of a blob arrived before the entry that
    /// names it, or the space was held with the blob stored. Runs with the
    /// state unlocked during the provider's writes.
    pub(crate) async fn hold_named_blobs(&self, space: EventId) -> Result<()> {
        let (provider, candidates) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let Some(provider) = self.provider_of(&state, &space) else {
                return Ok(());
            };
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(());
            };
            let candidates: Vec<Locator> = blob_locators(replica)
                .into_iter()
                .filter(|locator| {
                    replica.holds_object(locator)
                        && !replica.is_held(locator)
                        && !is_frasils_own(replica, locator)
                        && !state.held.holds(&space, locator)
                })
                .collect();
            (provider, candidates)
        };
        for locator in candidates {
            if !self.hold_sealed(space, locator, &provider).await? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Sets a space back to `sealed` (at-rest.md, "Held objects", changing
    /// the policy): each held object's chunks are sealed again from its
    /// plaintext and kept, its `held` record goes, and its token is
    /// forgotten. An object found not held is withdrawn, and stays
    /// fetchable.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the provider's and the store's.
    pub async fn seal_objects(&self, space: EventId) -> Result<()> {
        let (provider, ids) = {
            let mut state = self.lock().await;
            if !state.replicas.contains_key(&space) {
                return Err(Error::UnknownSpace);
            }
            self.refresh_held(&mut state);
            let provider = self.provider_of(&state, &space);
            {
                let mut providers = self.providers();
                providers.spaces.remove(&space);
                if providers.default.is_some() {
                    providers.sealed.insert(space);
                }
                providers.changed = true;
            }
            let ids: Vec<[u8; 32]> = state
                .held
                .objects
                .get(&space)
                .map(|objects| objects.keys().copied().collect())
                .unwrap_or_default();
            (provider, ids)
        };
        let Some(provider) = provider else {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            return Ok(());
        };
        for id in ids {
            let Some((locator, parts)) = self
                .serve_entry(&space, &id, provider.as_ref(), 0, u64::MAX)
                .await?
            else {
                // Withdrawn, or a reference: nothing to keep.
                continue;
            };
            let token = {
                let mut state = self.lock().await;
                let Some(entry) = state.held.remove(&space, &id) else {
                    continue;
                };
                let mut batch = Batch::default();
                for part in &parts {
                    crate::objects::put_part(&state.vault, &mut batch, &space, part)?;
                }
                state.vault.delete(&mut batch, &space.0, Table::Held, &id);
                state.vault.commit(batch).await?;
                let at_rest = !state.vault.is_memory_only(&space.0);
                if let Some(replica) = state.replicas.get_mut(&space) {
                    replica.set_chunks_at_rest(at_rest);
                    replica.mark_held(locator, false);
                    for part in parts {
                        replica.keep_object(locator, part.header, Some((part.index, part.chunk)));
                    }
                }
                entry.record.token
            };
            provider.forget(&token).await?;
        }
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        Ok(())
    }

    // -- Loading

    /// Keeps a held object loaded from the store: its record and its
    /// header, marked at the replica once a provider is given. A `held`
    /// record beside a chunk record is `Malformed`, and the chunk records
    /// win (at-rest.md, "Tables").
    pub(crate) fn load_held(
        state: &mut State,
        space: EventId,
        id: [u8; 32],
        record: HeldRecord,
        header: Vec<u8>,
    ) {
        state.held.keep(
            space,
            id,
            HeldEntry {
                record,
                header,
                locator: None,
            },
        );
    }

    // -- Putting

    /// Puts an object from the plaintext a token names with the space's
    /// provider, under the space's current state ([`put_with`]): under
    /// `held`, one commit of the header and the `held` record; under
    /// `sealed`, the chunks of the second pass are kept instead. An object
    /// the device holds already under another token keeps that token, and
    /// the provider is told to forget this one. Returns the locator and
    /// the key reference the header names.
    ///
    /// # Errors
    ///
    /// `Changed` when the plaintext is gone or changed while it was read;
    /// [`Error::Invalid`] for a token or stamp outside the bounds;
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] with no provider, or
    /// while the device holds no current state; `TooLarge`; the
    /// provider's and the store's.
    pub async fn put_held(&self, space: EventId, token: &[u8]) -> Result<(Locator, Vec<u8>)> {
        let (held, provider, reference, key) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let held = self.provider_of(&state, &space);
            let provider = match &held {
                Some(provider) => provider.clone(),
                None => self
                    .providers()
                    .default
                    .clone()
                    .ok_or(Error::NotAllowed("the device has no object provider"))?,
            };
            let (reference, key) = self.sealing(&state, &space)?;
            (held.is_some(), provider, reference, key)
        };
        let put = put_with(provider.as_ref(), &space, &key, &reference, token).await?;
        let mut state = self.lock().await;
        if !state.replicas.contains_key(&space) {
            return Err(Error::UnknownSpace);
        }
        // The policy may have changed during the passes: a space set back
        // to `sealed` keeps the chunks.
        let held = held && self.provider_of(&state, &space).is_some();
        if !held {
            // Under `sealed`: the chunks kept, as a put from memory keeps
            // them.
            Self::keep_parts_in(&mut state, space, &put.parts.iter().collect::<Vec<_>>()).await?;
            return Ok((put.locator, reference));
        }
        let id = object_id(&put.locator);
        if let Some(existing) = state.held.entry(&space, &id) {
            // Held already: one token suffices.
            let same = existing.record.token == put.record.token;
            drop(state);
            if !same {
                provider.forget(token).await?;
            }
            return Ok((put.locator, reference));
        }
        let mut batch = Batch::default();
        commit_held(
            &mut state,
            &mut batch,
            &space,
            &id,
            &put.header,
            &put.record,
        )?;
        state.vault.commit(batch).await?;
        keep_held(
            &mut state,
            space,
            id,
            HeldEntry {
                record: put.record,
                header: put.header,
                locator: Some(put.locator),
            },
        );
        Ok((put.locator, reference))
    }

    /// Writes a plaintext through the provider under `held` and puts the
    /// file it made: `Blobs::put` under that policy. A file the put does
    /// not keep, because the put fails or the object is held already, is
    /// forgotten. Returns `None` under `sealed`.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) async fn put_created(
        &self,
        space: EventId,
        plaintext: &[u8],
    ) -> Result<Option<(Locator, Vec<u8>)>> {
        let (provider, key) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let Some(provider) = self.provider_of(&state, &space) else {
                return Ok(None);
            };
            let (_, key) = self.sealing(&state, &space)?;
            (provider, key)
        };
        let id = ObjectKeys::of(&key).object_id(plaintext);
        let size = u64::try_from(plaintext.len()).map_err(|_| Error::Class("TooLarge"))?;
        let mut writer = provider.create(SpaceId::of(space), id, size, &[]).await?;
        if let Err(error) = writer.write(plaintext).await {
            let _ = writer.abort().await;
            return Err(error);
        }
        let (token, _) = writer.finish().await?;
        match self.put_held(space, &token).await {
            Ok(put) => Ok(Some(put)),
            Err(error) => {
                let _ = provider.forget(&token).await;
                Err(error)
            }
        }
    }

    // -- Serving

    /// Seals chunks `first` to `first + count − 1` of a held object again
    /// from its plaintext ([`serve_with`]): `None` when the object is not
    /// held here, or was found not held and withdrawn.
    ///
    /// # Errors
    ///
    /// The provider's and the store's.
    pub(crate) async fn serve_held(
        &self,
        space: EventId,
        locator: &Locator,
        first: u64,
        count: u64,
    ) -> Result<Option<Vec<ObjectPart>>> {
        let id = object_id(locator);
        let provider = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let Some(entry) = state.held.entry(&space, &id) else {
                return Ok(None);
            };
            if entry.locator.is_some_and(|known| known != *locator) {
                return Ok(None);
            }
            let Some(provider) = self.provider_of(&state, &space) else {
                return Ok(None);
            };
            provider
        };
        let served = self
            .serve_entry(&space, &id, provider.as_ref(), first, count)
            .await?;
        Ok(served.and_then(|(known, parts)| (known == *locator).then_some(parts)))
    }

    /// [`serve_with`] on a held object, the state locked only before and
    /// after the pass, with the withdrawal: the chunks and the locator, or
    /// `None` once the object was withdrawn, released meanwhile, or for a
    /// reference. `count` of `u64::MAX` is the whole object.
    async fn serve_entry(
        &self,
        space: &EventId,
        id: &[u8; 32],
        provider: &dyn ObjectProvider,
        first: u64,
        count: u64,
    ) -> Result<Option<(Locator, Vec<ObjectPart>)>> {
        let (entry, key) = {
            let state = self.lock().await;
            let Some(entry) = state.held.entry(space, id).cloned() else {
                return Ok(None);
            };
            let header = Header::read(&entry.header).map_err(Error::class)?;
            // A reference, or a state this device lacks: nothing to serve.
            let Some((key, _)) = state
                .replicas
                .get(space)
                .and_then(|r| r.object_key(&header.key_reference))
            else {
                return Ok(None);
            };
            (entry, key)
        };
        let served = serve_with(
            provider,
            space,
            &key,
            &entry.header,
            &entry.record,
            entry.locator,
            first,
            count,
        )
        .await?;
        let mut state = self.lock().await;
        // Withdrawn or released during the pass: the outcome is stale.
        if state
            .held
            .entry(space, id)
            .is_none_or(|current| current.record != entry.record)
        {
            return Ok(None);
        }
        match served {
            Served::NotHeld => {
                self.withdraw(&mut state, space, id).await?;
                Ok(None)
            }
            Served::Held { locator, parts } => {
                if entry.locator.is_none() {
                    if let Some(held) = state
                        .held
                        .objects
                        .get_mut(space)
                        .and_then(|o| o.get_mut(id))
                    {
                        held.locator = Some(locator);
                    }
                    if let Some(replica) = state.replicas.get_mut(space) {
                        replica.keep_object(locator, Some(entry.header.clone()), None);
                        replica.mark_held(locator, true);
                    }
                }
                Ok(Some((locator, parts)))
            }
        }
    }

    /// Withdraws a held object as not held: its `held` record goes, its
    /// header stays, the replica no longer announces it, and the
    /// application hears of it. `forget` is not called.
    async fn withdraw(&self, state: &mut State, space: &EventId, id: &[u8; 32]) -> Result<()> {
        let Some(entry) = state.held.remove(space, id) else {
            return Ok(());
        };
        let mut batch = Batch::default();
        state.vault.delete(&mut batch, &space.0, Table::Held, id);
        state.vault.commit(batch).await?;
        if let (Some(locator), Some(replica)) = (entry.locator, state.replicas.get_mut(space)) {
            replica.mark_held(locator, false);
        }
        self.mark_withdrawn(*space, *id);
        let _ = self.notices().send(Notice {
            space: *space,
            placed: Vec::new(),
            withdrawn: vec![Withdrawn {
                space: *space,
                object_id: *id,
                token: entry.record.token,
            }],
            wanted: Vec::new(),
        });
        Ok(())
    }

    /// The held objects of a space the device may announce: each checked
    /// against its provider, and withdrawn if it changed. A reference is
    /// never announced.
    pub(crate) async fn announce_held(&self, space: &EventId) -> Vec<Locator> {
        let _ = self.hold_named_blobs(*space).await;
        let (provider, entries) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let Some(provider) = self.provider_of(&state, space) else {
                return Vec::new();
            };
            Self::resolve_held(&mut state, space, true);
            let entries: Vec<([u8; 32], bool)> = state
                .held
                .objects
                .get(space)
                .map(|objects| {
                    objects
                        .iter()
                        .map(|(id, entry)| (*id, entry.locator.is_some()))
                        .collect()
                })
                .unwrap_or_default();
            (provider, entries)
        };
        let mut out = Vec::new();
        for (id, known) in entries {
            let count = if known { 0 } else { u64::MAX };
            if let Ok(Some((locator, _))) = self
                .serve_entry(space, &id, provider.as_ref(), 0, count)
                .await
            {
                out.push(locator);
            }
        }
        out
    }

    /// A held object's stored bytes, sealed again whole.
    pub(crate) async fn held_bytes(&self, space: &EventId, locator: &Locator) -> Option<Vec<u8>> {
        let parts = self.serve_held(*space, locator, 0, u64::MAX).await.ok()??;
        let header = parts.first()?.header.as_ref()?;
        let mut out = u32::try_from(header.len()).ok()?.to_be_bytes().to_vec();
        out.extend_from_slice(header);
        for part in &parts {
            out.extend_from_slice(&part.chunk);
        }
        Some(out)
    }

    // -- Reading

    /// A held object's entry, its provider and, with `k(S)`, its content
    /// key, if the object is held here: what a read starts from, under the
    /// lock.
    async fn held_for_read(
        &self,
        space: &EventId,
        id: &[u8; 32],
    ) -> Option<(
        HeldEntry,
        Arc<dyn ObjectProvider>,
        Option<Zeroizing<[u8; 32]>>,
    )> {
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        let entry = state.held.entry(space, id).cloned()?;
        let provider = self.provider_of(&state, space)?;
        let header = Header::read(&entry.header).ok()?;
        let key = state
            .replicas
            .get(space)
            .and_then(|r| r.object_key(&header.key_reference))
            .map(|(key, _)| key);
        Some((entry, provider, key))
    }

    /// Withdraws a held object after a read found its file changed, unless
    /// the entry changed meanwhile.
    async fn withdraw_if_same(
        &self,
        space: &EventId,
        id: &[u8; 32],
        record: &HeldRecord,
    ) -> Result<()> {
        let mut state = self.lock().await;
        if state
            .held
            .entry(space, id)
            .is_some_and(|current| current.record == *record)
        {
            self.withdraw(&mut state, space, id).await?;
        }
        Ok(())
    }

    /// A held object's plaintext, read through the provider with the object
    /// ID checked in the pass, or `None` when the object is not held here.
    /// A reference's plaintext is read as it is, under its stamp alone.
    ///
    /// # Errors
    ///
    /// `ObjectMismatch` when the plaintext is not the object's; the
    /// provider's.
    pub(crate) async fn held_plaintext(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Result<Option<Vec<u8>>> {
        let id = object_id(locator);
        let Some((entry, provider, key)) = self.held_for_read(space, &id).await else {
            return Ok(None);
        };
        let header = Header::read(&entry.header).map_err(Error::class)?;
        if !same_file(
            provider.stat(&entry.record.token).await?.as_ref(),
            &entry.record,
        ) {
            self.withdraw_if_same(space, &id, &entry.record).await?;
            return Ok(None);
        }
        let mut reader = provider.open(&entry.record.token).await?;
        let length = usize::try_from(header.size).map_err(|_| Error::Class("TooLarge"))?;
        let plaintext = match read_exact(reader.as_mut(), 0, length).await {
            Ok(plaintext) => plaintext,
            Err(Error::Class("Changed")) => {
                self.withdraw_if_same(space, &id, &entry.record).await?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if let Some(key) = key
            && ObjectKeys::of(&key).object_id(&plaintext) != header.object_id
        {
            self.withdraw_if_same(space, &id, &entry.record).await?;
            return Err(Error::Class("ObjectMismatch"));
        }
        Ok(Some(plaintext))
    }

    /// A held object's token, once its provider confirms its size and
    /// stamp: what `Blobs::materialise` returns.
    ///
    /// # Errors
    ///
    /// `Missing` while the object is not held here; the provider's.
    pub async fn held_token(&self, space: &EventId, locator: &Locator) -> Result<Vec<u8>> {
        self.hold_named_blobs(*space).await?;
        let id = object_id(locator);
        let Some((entry, provider, _)) = self.held_for_read(space, &id).await else {
            return Err(Error::Class("Missing"));
        };
        if !same_file(
            provider.stat(&entry.record.token).await?.as_ref(),
            &entry.record,
        ) {
            self.withdraw_if_same(space, &id, &entry.record).await?;
            return Err(Error::Class("Missing"));
        }
        Ok(entry.record.token)
    }

    /// Whether the store keeps a `held` record of an object, with or
    /// without a provider for its space: until one is given, the object is
    /// not served, yet its file may still be its copy (at-rest.md,
    /// "Held objects", the policy).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn keeps_held(&self, space: &EventId, locator: &Locator) -> bool {
        self.lock().await.held.holds(space, locator)
    }

    /// The `held` record of an object, if the device holds it: the space
    /// has a provider, and the record is in the store.
    pub async fn held_record(&self, space: &EventId, locator: &Locator) -> Option<HeldRecord> {
        let _ = self.hold_named_blobs(*space).await;
        let mut state = self.lock().await;
        self.refresh_held(&mut state);
        self.provider_of(&state, space)?;
        state
            .held
            .entry(space, &object_id(locator))
            .map(|entry| entry.record.clone())
    }

    /// Releases a held object: its `held` record goes and its token is
    /// forgotten; the object is `Missing` here until fetched again.
    ///
    /// # Errors
    ///
    /// `Missing` when the object is not held here; the provider's and the
    /// store's.
    pub async fn release_held(&self, space: &EventId, locator: &Locator) -> Result<()> {
        let id = object_id(locator);
        let (provider, token) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let provider = self.provider_of(&state, space);
            let Some(entry) = state.held.remove(space, &id) else {
                return Err(Error::Class("Missing"));
            };
            let mut batch = Batch::default();
            state.vault.delete(&mut batch, &space.0, Table::Held, &id);
            state.vault.commit(batch).await?;
            if let Some(replica) = state.replicas.get_mut(space) {
                replica.mark_held(*locator, false);
            }
            (provider, entry.record.token)
        };
        if let Some(provider) = provider {
            provider.forget(&token).await?;
        }
        Ok(())
    }

    /// Starts a fetch the application asked for: `hint` is what it passed,
    /// for the provider's `create`, and each member connection of the
    /// space asks the other side for the object. Peer connections fetch
    /// what the space's units name by themselves.
    pub async fn fetch_object(&self, space: EventId, locator: Locator, hint: Vec<u8>) {
        {
            let mut state = self.lock().await;
            state.held.hints.insert((space, locator), hint);
        }
        let _ = self.notices().send(Notice {
            space,
            placed: Vec::new(),
            withdrawn: Vec::new(),
            wanted: vec![locator],
        });
    }

    // -- Receiving

    /// Whether an arriving part of an object is received through the
    /// provider: the space is held, and a current blob entry names the
    /// object, or the application asked for it. An object whose chunks
    /// arrive before its entry is stored sealed, and held by
    /// [`Engine::hold_named_blobs`] once the entry is current.
    pub(crate) fn receives_held(&self, state: &State, space: &EventId, locator: &Locator) -> bool {
        if self.provider_of(state, space).is_none() {
            return false;
        }
        if state.held.receiving.contains_key(&(*space, *locator))
            || state.held.hints.contains_key(&(*space, *locator))
        {
            return true;
        }
        state
            .replicas
            .get(space)
            .is_some_and(|replica| !is_frasils_own(replica, locator) && is_blob(replica, locator))
    }

    /// Receives one part of an object through the provider, or `false`
    /// when the device lacks the key to open it yet, so that the part is
    /// stored sealed ([`Receiver`]): the header starts a receiver; each
    /// chunk, in order,
    /// is opened and written through; once every chunk is written, the
    /// checks of the whole run and the header and the `held` record are
    /// committed. A chunk that fails is the end of this receive: the
    /// writer is aborted, and the device asks again when the object is
    /// announced next. A file the commit does not keep is forgotten.
    pub(crate) async fn receive_held_part(
        &self,
        state: &mut State,
        space: EventId,
        part: &ObjectPart,
    ) -> Result<bool> {
        let locator = part.locator;
        let key = (space, locator);
        if state.held.holds(&space, &locator) {
            return Ok(true);
        }
        let Some(provider) = self.provider_of(state, &space) else {
            return Ok(true);
        };
        if !state.held.receiving.contains_key(&key) {
            let Some(header_bytes) = &part.header else {
                // A chunk before the header: it waits for the header's.
                return Ok(true);
            };
            let header = Header::read(header_bytes).map_err(Error::class)?;
            if header.object_id != locator[..32] {
                return Err(Error::Class("ObjectMismatch"));
            }
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let state_key = replica
                .object_key(&header.key_reference)
                .map(|(key, _)| key);
            let reference = reference_in(replica, &locator);
            let (sealed_by, receive_key) = match (&state_key, &reference) {
                (Some(key), _) => (space, ReceiveKey::State(key)),
                (None, Some((source, object_key))) => (*source, ReceiveKey::Object(object_key)),
                // No key yet: the part is stored sealed, and held once the
                // key arrives (`hold_named_blobs`).
                (None, None) => return Ok(false),
            };
            let hint = state.held.hints.get(&key).cloned().unwrap_or_default();
            let receiver = Receiver::start(
                provider.as_ref(),
                space,
                sealed_by,
                header_bytes,
                receive_key,
                &hint,
            )
            .await?;
            state.held.receiving.insert(
                key,
                Receiving {
                    receiver,
                    waiting: BTreeMap::new(),
                },
            );
        }
        let Some(receiving) = state.held.receiving.get_mut(&key) else {
            return Ok(true);
        };
        // Only a chunk of the object waits: its index below the header's
        // chunk count (units.md, "Reading an object", step 4).
        let count = chunk_count(receiving.receiver.header().size, CHUNK_BYTES as u64);
        if part.index >= receiving.receiver.next() && part.index < count {
            receiving.waiting.insert(part.index, part.chunk.clone());
        }
        while let Some(sealed) = receiving.waiting.remove(&receiving.receiver.next()) {
            if receiving.receiver.chunk(&sealed).await.is_err() {
                self.abort_receive(state, key).await?;
                return Ok(true);
            }
        }
        if !receiving.receiver.is_complete() {
            return Ok(true);
        }
        let Some(receiving) = state.held.receiving.remove(&key) else {
            return Ok(true);
        };
        state.held.hints.remove(&key);
        let header = receiving.receiver.header().encode();
        let id = receiving.receiver.header().object_id;
        let record = receiving
            .receiver
            .finish(provider.as_ref(), &locator)
            .await?;
        let mut batch = Batch::default();
        let committed = commit_held(state, &mut batch, &space, &id, &header, &record);
        let committed = match committed {
            Ok(()) => state.vault.commit(batch).await,
            Err(error) => Err(error),
        };
        if let Err(error) = committed {
            let _ = provider.forget(&record.token).await;
            return Err(error);
        }
        keep_held(
            state,
            space,
            id,
            HeldEntry {
                record,
                header,
                locator: Some(locator),
            },
        );
        if let Some(replica) = state.replicas.get_mut(&space) {
            replica.take_snapshots();
        }
        Ok(true)
    }

    /// Ends a receive whose chunk failed: the writer is aborted and the
    /// partial file goes. The device asks another party when the object is
    /// announced next.
    async fn abort_receive(&self, state: &mut State, key: (EventId, Locator)) -> Result<()> {
        if let Some(receiving) = state.held.receiving.remove(&key) {
            receiving.receiver.abort().await;
        }
        Ok(())
    }

    // -- Forgetting

    /// Drops a space's held objects from the state, and returns the
    /// provider and the tokens to call `forget` for, once the state is
    /// unlocked (at-rest.md, "Held objects", forgetting and collecting).
    pub(crate) fn take_held(&self, state: &mut State, space: &EventId) -> Option<Forgets> {
        let provider = self.provider_of(state, space);
        let tokens = state.held.tokens(space);
        state.held.objects.remove(space);
        state.held.receiving.retain(|(s, _), _| s != space);
        state.held.hints.retain(|(s, _), _| s != space);
        provider.map(|provider| (provider, tokens))
    }
}
