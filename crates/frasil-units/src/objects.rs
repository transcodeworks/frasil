//! Objects (units.md, section 2.8, "Objects", and section 3.3, "Reading an
//! object").
//!
//! ```text
//! object_id_key(S)    = HKDF(none, k(S), "frasil/object-id-key/v1")       keys.md
//! object_nonce_key(S) = HKDF(none, k(S), "frasil/object-nonce-key/v1")    keys.md
//! object_seal_key(S)  = HKDF(none, k(S), "frasil/object-seal-key/v1")
//!
//! object ID  = HMAC(object_id_key(S), plaintext)
//! object key = HMAC(object_seal_key(S), object ID)    the object's own key
//! digest     = SHA-256(object)                  over the stored bytes below
//! locator    = object ID (32) || digest (32)    64 bytes
//!
//! object    = u32be(len(header)) || header || chunk_0 || ... || chunk_(n−1)
//! header    = deterministic CBOR map {1: version, 1, 2: object ID,
//!             3: key reference of S, 4: size, the plaintext's length}
//! c         = 1,048,536
//! n         = max(1, ceil(size / c))
//! plain_i   = plaintext[i·c .. min((i + 1)·c, size)]
//! aad_i     = "frasil/object-chunk/v1" || field(space ID) || object ID
//!             || u64be(size) || u64be(i)
//! nonce_i   = HMAC(object_nonce_key(S), aad_i || plain_i)[0..24]
//! chunk_i   = nonce_i || XChaCha20-Poly1305(object key, nonce_i, plain_i, aad_i)
//! ```
//!
//! Sealing is deterministic, so equal plaintexts under one state have one
//! stored form and one locator. The synthetic nonce lets a writer that
//! resumes an upload seal any range again and get the same bytes. A chunk
//! opens only at its own place in its own object. The object key opens one
//! object: a reference entry of adapter-blobs.md carries it to readers of
//! another space, who read with [`read_object_with_key`].
//!
//! The vectors lower the chunk size to show an object of several chunks;
//! the `_chunked` forms take it, and the others use [`CHUNK_BYTES`].

use crate::body::KeyReference;
use crate::limits::{CHUNK_BYTES, MAX_OBJECT_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::{UnitClass, UnitError};
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_base::notation::field;
use frasil_crypto::labels::{OBJECT_CHUNK, OBJECT_SEAL_KEY};
use frasil_crypto::primitives::{
    HmacSha256, hkdf, hmac_sha256, sha256, xchacha20poly1305_open, xchacha20poly1305_open_into,
    xchacha20poly1305_seal,
};
use frasil_events::EventId;
use frasil_keys::derive::{object_id_key, object_nonce_key};
use frasil_keys::{KeyName, SelfRef};
use zeroize::Zeroizing;

/// The header's version.
pub const VERSION: u64 = 1;

/// A state's three object keys.
pub struct ObjectKeys {
    /// `object_id_key(S)`.
    pub id_key: Zeroizing<[u8; 32]>,
    /// `object_nonce_key(S)`.
    pub nonce_key: Zeroizing<[u8; 32]>,
    /// `object_seal_key(S)`.
    pub seal_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for ObjectKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ObjectKeys")
    }
}

impl ObjectKeys {
    /// The object keys of the state whose content key this is.
    pub fn of(content_key: &[u8; 32]) -> Self {
        Self {
            id_key: object_id_key(content_key),
            nonce_key: object_nonce_key(content_key),
            seal_key: hkdf(None, content_key, OBJECT_SEAL_KEY),
        }
    }

    /// `object ID = HMAC(object_id_key(S), plaintext)`.
    pub fn object_id(&self, plaintext: &[u8]) -> [u8; 32] {
        hmac_sha256(&*self.id_key, plaintext)
    }

    /// `object key = HMAC(object_seal_key(S), object ID)`: the key that
    /// opens that object alone.
    pub fn object_key(&self, object_id: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hmac_sha256(&*self.seal_key, object_id))
    }
}

/// `n = max(1, ceil(size / c))`.
pub fn chunk_count(size: u64, chunk: u64) -> u64 {
    size.div_ceil(chunk).max(1)
}

/// `aad_i = "frasil/object-chunk/v1" || field(space ID) || object ID ||
/// u64be(size) || u64be(i)`.
pub fn chunk_aad(space: &EventId, object_id: &[u8; 32], size: u64, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OBJECT_CHUNK.len() + 4 + 32 + 32 + 16);
    aad.extend_from_slice(OBJECT_CHUNK);
    aad.extend_from_slice(&field(&space.0));
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(&size.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// An object's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Key 2: the object ID.
    pub object_id: [u8; 32],
    /// Key 3: the key reference of the state it is sealed under.
    pub key_reference: Vec<u8>,
    /// Key 4: the plaintext's length.
    pub size: u64,
}

impl Header {
    /// The header's deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        Value::Map(Map::from([
            (1, Value::from(VERSION)),
            (2, Value::from(self.object_id)),
            (3, Value::from(self.key_reference.as_slice())),
            (4, Value::from(self.size)),
        ]))
        .encode()
    }

    /// Section 3.3, step 2: deterministic CBOR, a map with an unsigned key
    /// 1; key 1 is 1; keys 1 to 4 only; key 2 32 bytes; key 3 a key
    /// reference, or the self reference of a checkpoint's record object
    /// (roster.md, "The record object"); key 4 at most 2^40.
    ///
    /// A peer, and a holder that keeps objects for others, reads both
    /// forms: it cannot tell a record object from another. A reader of the
    /// plaintext takes the one form its object has ([`read_object`] a key
    /// reference, `read_record_object`
    /// a self reference).
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, the key reference's class, or
    /// `TooLarge`.
    pub fn read(data: &[u8]) -> Result<Self, UnitError> {
        Self::read_as(data, HeaderName::Either)
    }

    /// [`Header::read`] taking only the form `name` allows at key 3: a
    /// self reference where a key reference is wanted, or the other way
    /// round, is `Malformed`, at step 2.
    ///
    /// # Errors
    ///
    /// As [`Header::read`].
    pub fn read_as(data: &[u8], name: HeaderName) -> Result<Self, UnitError> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map.get(&1).ok_or(Malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.len() != 4 || !(1..=4).all(|key| map.contains_key(&key)) {
            return Err(ErrorClass::Malformed.into());
        }
        let object_id = map[&2].as_byte_array()?;
        let key_reference = map[&3].as_bytes()?.to_vec();
        let size = map[&4].as_unsigned()?;
        match (name, self_reference(&key_reference)?) {
            (HeaderName::Either | HeaderName::Record, Some(_)) => {}
            (HeaderName::Either | HeaderName::State, None) => {
                KeyReference::read(&key_reference)?;
            }
            _ => return Err(ErrorClass::Malformed.into()),
        }
        if size > MAX_OBJECT_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        Ok(Self {
            object_id,
            key_reference,
            size,
        })
    }
}

impl Header {
    /// The self reference key 3 holds, in a checkpoint's record object
    /// (roster.md, "The record object"); `None` for a key reference.
    pub fn self_reference(&self) -> Option<SelfRef> {
        self_reference(&self.key_reference).ok().flatten()
    }
}

/// The form an object header's key 3 takes (section 2.8; roster.md, "The
/// record object").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderName {
    /// A key reference: an object a unit names, sealed under a state of
    /// rotations that exist as events.
    State,
    /// A self reference alone: a checkpoint's record object, sealed under
    /// the checkpoint's own state, whose ID does not exist when it is
    /// sealed.
    Record,
    /// Either: what a peer and a holder of others' objects read.
    Either,
}

/// Key 3 as a self reference, when its first byte says it is one: exactly
/// the 41 bytes of `0x00 || author || u64be(seq)`, with nothing after.
fn self_reference(data: &[u8]) -> Result<Option<SelfRef>, UnitError> {
    if data.first() != Some(&0) {
        return Ok(None);
    }
    match KeyName::read(data, true)? {
        (KeyName::SelfRef(own), []) => Ok(Some(own)),
        _ => Err(ErrorClass::Malformed.into()),
    }
}

/// One sealed chunk, with its associated data and synthetic nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// Its index.
    pub index: u64,
    /// `aad_i`.
    pub aad: Vec<u8>,
    /// `nonce_i`.
    pub nonce: [u8; NONCE_BYTES],
    /// `chunk_i`: the nonce, then the ciphertext with its tag.
    pub sealed: Vec<u8>,
}

/// A sealed object and every intermediate value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedObject {
    /// The object ID.
    pub id: [u8; 32],
    /// The digest of the stored bytes.
    pub digest: [u8; 32],
    /// The locator: ID, then digest.
    pub locator: Locator,
    /// The header's bytes.
    pub header: Vec<u8>,
    /// The chunks.
    pub chunks: Vec<SealedChunk>,
    /// The stored bytes.
    pub bytes: Vec<u8>,
}

/// Seals an object under the state whose content key and key reference
/// these are, in chunks of 1,048,536 bytes. The result holds the sealed
/// chunks and the stored bytes, each about the plaintext's size, beside
/// the plaintext the caller holds.
///
/// # Errors
///
/// `TooLarge` for a plaintext of more than 2^40 bytes.
pub fn seal_object(
    space: &EventId,
    content_key: &[u8; 32],
    key_reference: &[u8],
    plaintext: &[u8],
) -> Result<SealedObject, ErrorClass> {
    seal_object_chunked(space, content_key, key_reference, plaintext, CHUNK_BYTES)
}

/// [`seal_object`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// `TooLarge` for a plaintext of more than 2^40 bytes; `Malformed` for a
/// chunk size of 0.
pub fn seal_object_chunked(
    space: &EventId,
    content_key: &[u8; 32],
    key_reference: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> Result<SealedObject, ErrorClass> {
    let size = u64::try_from(plaintext.len()).map_err(|_| ErrorClass::TooLarge)?;
    if size > MAX_OBJECT_BYTES {
        return Err(ErrorClass::TooLarge);
    }
    if chunk == 0 {
        return Err(ErrorClass::Malformed);
    }
    let keys = ObjectKeys::of(content_key);
    let id = keys.object_id(plaintext);
    let object_key = keys.object_key(&id);
    let header = Header {
        object_id: id,
        key_reference: key_reference.to_vec(),
        size,
    }
    .encode();
    let mut chunks = Vec::new();
    let pieces: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(chunk).collect()
    };
    for (index, plain) in (0u64..).zip(pieces) {
        chunks.push(seal_chunk(
            space,
            &keys,
            &object_key,
            &id,
            size,
            index,
            plain,
        ));
    }
    let header_length = u32::try_from(header.len()).map_err(|_| ErrorClass::TooLarge)?;
    let mut bytes = header_length.to_be_bytes().to_vec();
    bytes.extend_from_slice(&header);
    for chunk in &chunks {
        bytes.extend_from_slice(&chunk.sealed);
    }
    let digest = sha256(&[&bytes]);
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(&id);
    locator[32..].copy_from_slice(&digest);
    Ok(SealedObject {
        id,
        digest,
        locator,
        header,
        chunks,
        bytes,
    })
}

/// `chunk_i` from `plain_i` alone: its associated data, its synthetic nonce
/// and its sealed bytes. A chunk depends on nothing but `aad_i` and
/// `plain_i`, so a holder of the plaintext seals any chunk again and gets
/// the same bytes (at-rest.md, "Held objects").
pub fn seal_chunk(
    space: &EventId,
    keys: &ObjectKeys,
    object_key: &[u8; 32],
    object_id: &[u8; 32],
    size: u64,
    index: u64,
    plain: &[u8],
) -> SealedChunk {
    let aad = chunk_aad(space, object_id, size, index);
    let mut nonce_input = aad.clone();
    nonce_input.extend_from_slice(plain);
    let mut nonce = [0; NONCE_BYTES];
    nonce.copy_from_slice(&hmac_sha256(&*keys.nonce_key, &nonce_input)[..NONCE_BYTES]);
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&xchacha20poly1305_seal(object_key, &nonce, &aad, plain));
    SealedChunk {
        index,
        aad,
        nonce,
        sealed,
    }
}

/// The length of `plain_i`: `min(c, size − i·c)`, and 0 for the one chunk
/// of an empty object.
pub fn plain_length(size: u64, chunk: u64, index: u64) -> u64 {
    chunk.min(size.saturating_sub(index.saturating_mul(chunk)))
}

/// One chunk as a reader that fetches by chunk checks it on arrival
/// (section 3.3; section 3.14, "Objects"), against the header it holds or
/// that came with the chunk: the header's object ID is the locator's (step
/// 3); the index is below the chunk count, and the chunk has exactly the
/// length the header's size gives it (step 4); and, when the reader holds
/// the object key, it opens at its place (step 6). The index arithmetic is
/// checked.
///
/// # Errors
///
/// `ObjectMismatch` (step 3), `Malformed` (step 4), `Decrypt` (step 6).
pub fn check_chunk(
    space: &EventId,
    header: &Header,
    locator: &Locator,
    index: u64,
    sealed: &[u8],
    object_key: Option<&[u8; 32]>,
) -> Result<(), UnitError> {
    check_chunk_chunked(
        space,
        header,
        locator,
        index,
        sealed,
        object_key,
        CHUNK_BYTES,
    )
}

/// [`check_chunk`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`check_chunk`]; `Malformed` for a chunk size of 0.
pub fn check_chunk_chunked(
    space: &EventId,
    header: &Header,
    locator: &Locator,
    index: u64,
    sealed: &[u8],
    object_key: Option<&[u8; 32]>,
    chunk: usize,
) -> Result<(), UnitError> {
    // 3. The header's object ID is the locator's.
    if header.object_id != locator[..32] {
        return Err(UnitClass::ObjectMismatch.into());
    }
    // 4. A chunk of the object, of its length.
    let chunk = u64::try_from(chunk).map_err(|_| Malformed)?;
    if chunk == 0 || index >= chunk_count(header.size, chunk) {
        return Err(ErrorClass::Malformed.into());
    }
    let overhead = u64::try_from(NONCE_BYTES + TAG_BYTES).map_err(|_| Malformed)?;
    let expected = plain_length(header.size, chunk, index)
        .checked_add(overhead)
        .ok_or(Malformed)?;
    if u64::try_from(sealed.len()).map_err(|_| Malformed)? != expected {
        return Err(ErrorClass::Malformed.into());
    }
    // 6. It opens under the object key, at its place.
    if let Some(object_key) = object_key {
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let nonce: &[u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Malformed)?;
        let aad = chunk_aad(space, &header.object_id, header.size, index);
        xchacha20poly1305_open(object_key, nonce, &aad, ciphertext)?;
    }
    Ok(())
}

/// An object's stored bytes, split as section 3.3, steps 1 to 4, read them,
/// without any key: what a peer checks of an upload once it holds the
/// header and every chunk, after step 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject<'a> {
    /// The header.
    pub header: Header,
    /// Each chunk's sealed bytes.
    pub chunks: Vec<&'a [u8]>,
}

/// Section 3.3, steps 0 to 4: what a peer runs on an upload.
///
/// # Errors
///
/// `ObjectMismatch` (steps 0 and 3), `Malformed`, `UnsupportedVersion`,
/// the key reference's class or `TooLarge` (steps 1, 2 and 4).
pub fn check_stored<'a>(data: &'a [u8], locator: &Locator) -> Result<StoredObject<'a>, UnitError> {
    check_stored_chunked(data, locator, CHUNK_BYTES)
}

/// [`check_stored`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`check_stored`].
pub fn check_stored_chunked<'a>(
    data: &'a [u8],
    locator: &Locator,
    chunk: usize,
) -> Result<StoredObject<'a>, UnitError> {
    check_stored_as(data, locator, chunk, HeaderName::Either)
}

/// [`check_stored_chunked`] taking only the header form `name` allows
/// ([`Header::read_as`]).
///
/// # Errors
///
/// As [`check_stored`].
pub fn check_stored_as<'a>(
    data: &'a [u8],
    locator: &Locator,
    chunk: usize,
    name: HeaderName,
) -> Result<StoredObject<'a>, UnitError> {
    // 0. The digest.
    if sha256(&[data]) != locator[32..] {
        return Err(UnitClass::ObjectMismatch.into());
    }
    // 1. At least 4 bytes, and the header's length fits.
    let (length, rest) = data.split_first_chunk::<4>().ok_or(Malformed)?;
    let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| Malformed)?;
    if length > rest.len() {
        return Err(ErrorClass::Malformed.into());
    }
    let (header, rest) = rest.split_at(length);
    // 2. The header.
    let header = Header::read_as(header, name)?;
    // 3. The header's object ID is the locator's.
    if header.object_id != locator[..32] {
        return Err(UnitClass::ObjectMismatch.into());
    }
    // 4. Exactly n chunks of their lengths.
    let chunk = u64::try_from(chunk).map_err(|_| Malformed)?;
    if chunk == 0 {
        return Err(ErrorClass::Malformed.into());
    }
    let count = chunk_count(header.size, chunk);
    let overhead = u64::try_from(NONCE_BYTES + TAG_BYTES).map_err(|_| Malformed)?;
    let expected = header.size + count * overhead;
    if u64::try_from(rest.len()).map_err(|_| Malformed)? != expected {
        return Err(ErrorClass::Malformed.into());
    }
    let mut chunks = Vec::new();
    let mut at = rest;
    for index in 0..count {
        let plain = chunk.min(header.size - index * chunk);
        let length = usize::try_from(plain + overhead).map_err(|_| Malformed)?;
        let (piece, next) = at.split_at(length);
        chunks.push(piece);
        at = next;
    }
    Ok(StoredObject { header, chunks })
}

/// Section 3.3, steps 0 to 7, on a whole object: its plaintext.
/// `content_key` is `k(S)` of the state the header names, or `None` when
/// the reader does not hold it.
///
/// # Errors
///
/// As [`check_stored`]; then `Sealed` (step 5), `Decrypt` (step 6) and
/// `ObjectMismatch` (step 7).
pub fn read_object(
    data: &[u8],
    space: &EventId,
    content_key: Option<&[u8; 32]>,
    locator: &Locator,
) -> Result<Vec<u8>, UnitError> {
    read_object_chunked(data, space, content_key, locator, CHUNK_BYTES)
}

/// [`read_object`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`read_object`].
pub fn read_object_chunked(
    data: &[u8],
    space: &EventId,
    content_key: Option<&[u8; 32]>,
    locator: &Locator,
    chunk: usize,
) -> Result<Vec<u8>, UnitError> {
    let stored = check_stored_as(data, locator, chunk, HeaderName::State)?;
    // 5. The reader holds k(S).
    let content_key = content_key.ok_or(ErrorClass::Sealed)?;
    let keys = ObjectKeys::of(content_key);
    let header = &stored.header;
    // 6. Each chunk opens under the object key.
    let plaintext = open_chunks(&stored, space, &keys.object_key(&header.object_id))?;
    // 7. The whole plaintext's ID.
    if keys.object_id(&plaintext) != header.object_id {
        return Err(UnitClass::ObjectMismatch.into());
    }
    Ok(plaintext)
}

/// Section 3.3, steps 0 to 6, by a reader that holds the object key and not
/// `k(S)`, as a reference entry hands it (adapter-blobs.md): its plaintext.
/// `space` is the space that sealed the object, whose ID each chunk's
/// associated data names. Step 7 needs `k(S)` and is skipped: step 0 binds
/// the bytes to the locator, and step 6 to the key.
///
/// # Errors
///
/// As [`check_stored`]; then `Decrypt` (step 6).
pub fn read_object_with_key(
    data: &[u8],
    space: &EventId,
    object_key: &[u8; 32],
    locator: &Locator,
) -> Result<Vec<u8>, UnitError> {
    read_object_with_key_chunked(data, space, object_key, locator, CHUNK_BYTES)
}

/// [`read_object_with_key`] with another chunk size, as the vectors use.
///
/// # Errors
///
/// As [`read_object_with_key`].
pub fn read_object_with_key_chunked(
    data: &[u8],
    space: &EventId,
    object_key: &[u8; 32],
    locator: &Locator,
    chunk: usize,
) -> Result<Vec<u8>, UnitError> {
    let stored = check_stored_as(data, locator, chunk, HeaderName::State)?;
    open_chunks(&stored, space, object_key)
}

/// Section 3.3, step 6: every chunk opened under the object key, in order.
pub(crate) fn open_chunks(
    stored: &StoredObject<'_>,
    space: &EventId,
    object_key: &[u8; 32],
) -> Result<Vec<u8>, UnitError> {
    let header = &stored.header;
    let mut plaintext = Vec::new();
    for (index, sealed) in (0u64..).zip(&stored.chunks) {
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let nonce: &[u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Malformed)?;
        let aad = chunk_aad(space, &header.object_id, header.size, index);
        let plain = xchacha20poly1305_open(object_key, nonce, &aad, ciphertext)?;
        plaintext.extend_from_slice(&plain);
    }
    Ok(plaintext)
}

/// Work [`read_object_parts`] hands out: each task may run on any thread,
/// in any order.
pub type Task<'a> = Box<dyn FnOnce() + Send + 'a>;

/// Runs tasks and returns once each has run: one after another, or several
/// at once where the platform has threads.
pub trait Tasks {
    /// Runs every task.
    fn run<'a>(&self, tasks: Vec<Task<'a>>);
}

/// [`Tasks`] that runs each task in turn, on the calling thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct InTurn;

impl Tasks for InTurn {
    fn run<'a>(&self, tasks: Vec<Task<'a>>) {
        for task in tasks {
            task();
        }
    }
}

/// How a reader opens an object: with `k(S)` of the state its header names
/// (`None` when it does not hold it), or with the object key alone.
#[derive(Debug, Clone, Copy)]
pub enum Opening<'k> {
    /// [`read_object`]: steps 0 to 7.
    ContentKey(Option<&'k [u8; 32]>),
    /// [`read_object_with_key`]: steps 0 to 6.
    ObjectKey(&'k [u8; 32]),
}

/// An object's stored bytes in the parts a store keeps: the header, without
/// the length before it, and each chunk's sealed bytes, in order. They read
/// as `u32be(len(header)) || header || chunk_0 || ... || chunk_(n−1)`.
#[derive(Debug, Clone, Copy)]
pub struct Parts<'a> {
    /// The header.
    pub header: &'a [u8],
    /// Each chunk's sealed bytes.
    pub chunks: &'a [&'a [u8]],
}

impl Parts<'_> {
    /// The stored bytes, whole.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let length = u32::try_from(self.header.len()).ok()?;
        let total = 4 + self.header.len() + self.chunks.iter().map(|c| c.len()).sum::<usize>();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(self.header);
        for chunk in self.chunks {
            out.extend_from_slice(chunk);
        }
        Some(out)
    }

    /// Steps 1 to 4 on the parts, when each part is one of the chunks the
    /// header calls for: the header. `None` otherwise.
    fn layout(&self, locator: &Locator) -> Option<Header> {
        u32::try_from(self.header.len()).ok()?;
        let header = Header::read_as(self.header, HeaderName::State).ok()?;
        if header.object_id != locator[..32] {
            return None;
        }
        let chunk = CHUNK_BYTES as u64;
        let count = chunk_count(header.size, chunk);
        if u64::try_from(self.chunks.len()).ok()? != count {
            return None;
        }
        let overhead = (NONCE_BYTES + TAG_BYTES) as u64;
        for (index, sealed) in (0u64..).zip(self.chunks) {
            let plain = plain_length(header.size, chunk, index);
            if u64::try_from(sealed.len()).ok()? != plain + overhead {
                return None;
            }
        }
        Some(header)
    }
}

/// Section 3.3 on an object held in parts ([`Parts`]): what
/// [`read_object`] or [`read_object_with_key`] gives on the parts' bytes
/// whole, the same verdict in the same order, with no copy of them. Each
/// chunk's opening is a task, then step 0's digest and step 7's ID are two,
/// for `tasks` to run at once where it can; each chunk opens into its place
/// in the plaintext. A verdict is reported in the steps' order, whatever
/// order the work ran in.
///
/// # Errors
///
/// As [`read_object`] or [`read_object_with_key`].
pub fn read_object_parts(
    parts: Parts<'_>,
    space: &EventId,
    opening: Opening<'_>,
    locator: &Locator,
    tasks: &dyn Tasks,
) -> Result<Vec<u8>, UnitError> {
    // Parts that are not the header's chunks are read whole, so that each
    // step fails as it does on the bytes.
    let Some(header) = parts.layout(locator) else {
        let bytes = parts.to_bytes().ok_or(Malformed)?;
        return match opening {
            Opening::ContentKey(key) => read_object(&bytes, space, key, locator),
            Opening::ObjectKey(key) => read_object_with_key(&bytes, space, key, locator),
        };
    };
    let keys = match opening {
        Opening::ContentKey(Some(key)) => Some(ObjectKeys::of(key)),
        _ => None,
    };
    let object_key = match opening {
        Opening::ContentKey(Some(_)) => keys.as_ref().map(|k| k.object_key(&header.object_id)),
        Opening::ContentKey(None) => None,
        Opening::ObjectKey(key) => Some(Zeroizing::new(*key)),
    };
    let size = usize::try_from(header.size).map_err(|_| ErrorClass::TooLarge)?;
    let length = u32::try_from(parts.header.len())
        .map_err(|_| Malformed)?
        .to_be_bytes();
    let mut plaintext = Vec::new();
    let mut opened = Vec::new();
    // 6. Each chunk opens under the object key, into its place.
    if let Some(object_key) = &object_key {
        plaintext = vec![0; size];
        opened = vec![Ok(()); parts.chunks.len()];
        let places: Vec<&mut [u8]> = if size == 0 {
            vec![&mut []]
        } else {
            plaintext.chunks_mut(CHUNK_BYTES).collect()
        };
        let mut work: Vec<Task<'_>> = Vec::with_capacity(places.len());
        for (((index, sealed), place), result) in (0u64..)
            .zip(parts.chunks)
            .zip(places)
            .zip(opened.iter_mut())
        {
            let header = &header;
            work.push(Box::new(move || {
                *result = open_chunk_into(space, header, object_key, index, sealed, place);
            }));
        }
        tasks.run(work);
    }
    let opened: Result<(), UnitError> = opened.into_iter().collect();
    // 0. The digest, and 7. the plaintext's ID once every chunk opened, at
    // once.
    let mut digest = [0; 32];
    let mut id = None;
    {
        let digest = &mut digest;
        let mut work: Vec<Task<'_>> = vec![Box::new(move || {
            let mut pieces: Vec<&[u8]> = vec![&length, parts.header];
            pieces.extend_from_slice(parts.chunks);
            *digest = sha256(&pieces);
        })];
        if let (Some(keys), Ok(())) = (&keys, &opened) {
            let (id, plaintext) = (&mut id, &plaintext);
            work.push(Box::new(move || *id = Some(keys.object_id(plaintext))));
        }
        tasks.run(work);
    }
    if digest != locator[32..] {
        return Err(UnitClass::ObjectMismatch.into());
    }
    // 5.
    if object_key.is_none() {
        return Err(ErrorClass::Sealed.into());
    }
    opened?;
    // 7.
    if id.is_some_and(|id| id != header.object_id) {
        return Err(UnitClass::ObjectMismatch.into());
    }
    Ok(plaintext)
}

/// Section 3.3 chunk by chunk, for a reader that uses each chunk as it
/// opens it: "a reader verifies each chunk before it uses it". The caller
/// runs step 0 on the stored bytes whole first, or knows it passed.
/// [`ChunkReader::new`] runs steps 1 to 3 and 5 on the header,
/// [`ChunkReader::open`] steps 4 and 6 on one chunk, and
/// [`ChunkReader::finish`] step 7, with `k(S)`, once every chunk opened in
/// order.
pub struct ChunkReader {
    space: EventId,
    header: Header,
    object_key: Zeroizing<[u8; 32]>,
    /// Step 7's HMAC over the plaintext so far, with `k(S)` alone.
    id: Option<HmacSha256>,
    /// The next chunk step 7 takes, in order.
    next: u64,
}

impl core::fmt::Debug for ChunkReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkReader")
            .field("size", &self.header.size)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl ChunkReader {
    /// Steps 1 to 3 on the header, then step 5 with `opening`. `space` is
    /// the space that sealed the object.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `TooLarge`, `ObjectMismatch`,
    /// `Sealed`, as [`read_object`] reports them.
    pub fn new(
        header: &[u8],
        space: &EventId,
        opening: Opening<'_>,
        locator: &Locator,
    ) -> Result<Self, UnitError> {
        Self::new_as(header, space, opening, locator, HeaderName::State)
    }

    /// Steps 1 to 3 and 5, accepting the specified header name.
    ///
    /// # Errors
    ///
    /// As [`ChunkReader::new`].
    pub fn new_as(
        header: &[u8],
        space: &EventId,
        opening: Opening<'_>,
        locator: &Locator,
        name: HeaderName,
    ) -> Result<Self, UnitError> {
        // 1.
        u32::try_from(header.len()).map_err(|_| Malformed)?;
        // 2.
        let header = Header::read_as(header, name)?;
        // 3.
        if header.object_id != locator[..32] {
            return Err(UnitClass::ObjectMismatch.into());
        }
        // 5.
        let (object_key, id) = match opening {
            Opening::ContentKey(Some(key)) => {
                let keys = ObjectKeys::of(key);
                let id = HmacSha256::new(&*keys.id_key);
                (keys.object_key(&header.object_id), Some(id))
            }
            Opening::ContentKey(None) => return Err(ErrorClass::Sealed.into()),
            Opening::ObjectKey(key) => (Zeroizing::new(*key), None),
        };
        Ok(Self {
            space: *space,
            header,
            object_key,
            id,
            next: 0,
        })
    }

    /// The object's size in bytes.
    pub fn size(&self) -> u64 {
        self.header.size
    }

    /// Its number of chunks.
    pub fn count(&self) -> u64 {
        chunk_count(self.header.size, CHUNK_BYTES as u64)
    }

    /// Step 4 on one chunk's length, then step 6: its plaintext. Chunks
    /// opened in order from 0 also count for step 7.
    ///
    /// # Errors
    ///
    /// `Malformed` for an index past the last chunk or a chunk of the
    /// wrong length; `Decrypt`.
    pub fn open(&mut self, index: u64, sealed: &[u8]) -> Result<Vec<u8>, UnitError> {
        if index >= self.count() {
            return Err(ErrorClass::Malformed.into());
        }
        let plain = plain_length(self.header.size, CHUNK_BYTES as u64, index);
        if u64::try_from(sealed.len()).map_err(|_| Malformed)?
            != plain + (NONCE_BYTES + TAG_BYTES) as u64
        {
            return Err(ErrorClass::Malformed.into());
        }
        let mut out = vec![0; usize::try_from(plain).map_err(|_| ErrorClass::TooLarge)?];
        open_chunk_into(
            &self.space,
            &self.header,
            &self.object_key,
            index,
            sealed,
            &mut out,
        )?;
        if index == self.next {
            if let Some(id) = &mut self.id {
                id.update(&out);
            }
            self.next += 1;
        }
        Ok(out)
    }

    /// [`ChunkReader::open`] on several chunks, opened at once by `tasks`:
    /// their plaintexts, in the order given. Step 7 takes them in that
    /// order once they all opened.
    ///
    /// # Errors
    ///
    /// As [`ChunkReader::open`], for the first chunk that fails.
    pub fn open_many(
        &mut self,
        chunks: &[(u64, &[u8])],
        tasks: &dyn Tasks,
    ) -> Result<Vec<Vec<u8>>, UnitError> {
        let count = self.count();
        let mut out = Vec::with_capacity(chunks.len());
        for (index, sealed) in chunks {
            if *index >= count {
                return Err(ErrorClass::Malformed.into());
            }
            let plain = plain_length(self.header.size, CHUNK_BYTES as u64, *index);
            if u64::try_from(sealed.len()).map_err(|_| Malformed)?
                != plain + (NONCE_BYTES + TAG_BYTES) as u64
            {
                return Err(ErrorClass::Malformed.into());
            }
            out.push(vec![
                0;
                usize::try_from(plain)
                    .map_err(|_| ErrorClass::TooLarge)?
            ]);
        }
        let mut opened = vec![Ok(()); chunks.len()];
        {
            let (space, header, key) = (&self.space, &self.header, &*self.object_key);
            let work: Vec<Task<'_>> = chunks
                .iter()
                .zip(out.iter_mut())
                .zip(opened.iter_mut())
                .map(|(((index, sealed), place), result)| -> Task<'_> {
                    Box::new(move || {
                        *result = open_chunk_into(space, header, key, *index, sealed, place);
                    })
                })
                .collect();
            tasks.run(work);
        }
        opened.into_iter().collect::<Result<(), UnitError>>()?;
        for ((index, _), plain) in chunks.iter().zip(&out) {
            if *index == self.next {
                if let Some(id) = &mut self.id {
                    id.update(plain);
                }
                self.next += 1;
            }
        }
        Ok(out)
    }

    /// Step 7, with `k(S)`: the plaintext's ID is the header's. Every
    /// chunk must have opened in order.
    ///
    /// # Errors
    ///
    /// `Malformed` before every chunk opened in order; `ObjectMismatch`.
    pub fn finish(self) -> Result<(), UnitError> {
        if self.next != self.count() {
            return Err(ErrorClass::Malformed.into());
        }
        match self.id.map(HmacSha256::finish) {
            Some(id) if id != self.header.object_id => Err(UnitClass::ObjectMismatch.into()),
            _ => Ok(()),
        }
    }
}

/// Step 6 for one chunk: it opens under the object key into `out`, as long
/// as its plaintext.
fn open_chunk_into(
    space: &EventId,
    header: &Header,
    object_key: &[u8; 32],
    index: u64,
    sealed: &[u8],
    out: &mut [u8],
) -> Result<(), UnitError> {
    let (nonce, ciphertext) = sealed
        .split_first_chunk::<NONCE_BYTES>()
        .ok_or(ErrorClass::Decrypt)?;
    let aad = chunk_aad(space, &header.object_id, header.size, index);
    xchacha20poly1305_open_into(object_key, nonce, &aad, ciphertext, out)?;
    Ok(())
}

/// Starts the stored-byte digest with `u32be(len(header)) || header`.
///
/// # Errors
///
/// `Malformed` if the header length does not fit in four bytes.
pub fn stored_bytes_hasher(
    header: &[u8],
) -> Result<frasil_crypto::primitives::Sha256Hasher, UnitError> {
    let length = u32::try_from(header.len()).map_err(|_| Malformed)?;
    let mut hash = frasil_crypto::primitives::Sha256Hasher::new();
    hash.update(&length.to_be_bytes());
    hash.update(header);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_events::EventId;
    use frasil_keys::RotationSet;

    /// The parts a store keeps of stored bytes: the header and the chunks.
    fn split(bytes: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let header = bytes[4..4 + length].to_vec();
        let size = Header::read(&header).unwrap().size;
        let mut chunks = Vec::new();
        let mut at = 4 + length;
        for index in 0..chunk_count(size, CHUNK_BYTES as u64) {
            let length = plain_length(size, CHUNK_BYTES as u64, index) as usize + 40;
            chunks.push(bytes[at..at + length].to_vec());
            at += length;
        }
        (header, chunks)
    }

    /// Section 3.3, steps 3, 4 and 6, on one chunk received on its own.
    #[test]
    fn a_chunk_is_checked_against_its_header_on_arrival() {
        let space = EventId([1; 32]);
        let key = [2; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let big: Vec<u8> = (0..CHUNK_BYTES + 5).map(|i| i as u8).collect();
        let object = seal_object(&space, &key, &reference, &big).unwrap();
        let (header, chunks) = split(&object.bytes);
        let header = Header::read(&header).unwrap();
        let object_key = ObjectKeys::of(&key).object_key(&object.id);
        for (index, chunk) in (0u64..).zip(&chunks) {
            for held in [None, Some(&*object_key)] {
                assert_eq!(
                    check_chunk(&space, &header, &object.locator, index, chunk, held),
                    Ok(())
                );
            }
        }
        let check = |index: u64, chunk: &[u8], key: Option<&[u8; 32]>| {
            check_chunk(&space, &header, &object.locator, index, chunk, key)
        };
        // An index at or past the count, the greatest one included.
        for index in [2, u64::MAX] {
            assert_eq!(
                check(index, &chunks[1], None),
                Err(ErrorClass::Malformed.into())
            );
        }
        // A length the header does not give.
        assert_eq!(
            check(1, &chunks[0], None),
            Err(ErrorClass::Malformed.into())
        );
        assert_eq!(
            check(0, &chunks[1], None),
            Err(ErrorClass::Malformed.into())
        );
        assert_eq!(check(0, &[], None), Err(ErrorClass::Malformed.into()));
        // Junk of the right length opens only with the key held.
        let junk = vec![7; chunks[1].len()];
        assert_eq!(check(1, &junk, None), Ok(()));
        assert!(check(1, &junk, Some(&object_key)).is_err());
        // A chunk at another place does not open there.
        let mut swapped = chunks[0].clone();
        swapped.truncate(chunks[1].len());
        assert!(check(1, &swapped, Some(&object_key)).is_err());
        // Another locator's header.
        let mut other = object.locator;
        other[0] ^= 1;
        assert_eq!(
            check_chunk(&space, &header, &other, 0, &chunks[0], None),
            Err(UnitClass::ObjectMismatch.into())
        );
    }

    #[test]
    fn a_chunk_reader_reads_what_the_whole_read_gives() {
        let space = EventId([1; 32]);
        let key = [2; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let big: Vec<u8> = (0..CHUNK_BYTES * 2 + 5).map(|i| i as u8).collect();
        for plaintext in [&b""[..], b"x", &big] {
            let object = seal_object(&space, &key, &reference, plaintext).unwrap();
            let (header, chunks) = split(&object.bytes);
            let opening = Opening::ContentKey(Some(&key));
            let mut reader = ChunkReader::new(&header, &space, opening, &object.locator).unwrap();
            assert_eq!(reader.count(), chunks.len() as u64);
            assert_eq!(reader.size(), plaintext.len() as u64);
            let mut read = Vec::new();
            for (index, chunk) in (0u64..).zip(&chunks) {
                read.extend(reader.open(index, chunk).unwrap());
            }
            assert_eq!(read, plaintext);
            assert_eq!(reader.finish(), Ok(()));
            let mut many = ChunkReader::new(&header, &space, opening, &object.locator).unwrap();
            let parts: Vec<(u64, &[u8])> = (0u64..).zip(chunks.iter().map(Vec::as_slice)).collect();
            assert_eq!(many.open_many(&parts, &InTurn).unwrap().concat(), plaintext);
            assert_eq!(many.finish(), Ok(()));
            // With the object key alone, as a reference reads.
            let object_key = ObjectKeys::of(&key).object_key(&object.id);
            let mut reader = ChunkReader::new(
                &header,
                &space,
                Opening::ObjectKey(&object_key),
                &object.locator,
            )
            .unwrap();
            let last = chunks.len() as u64 - 1;
            assert_eq!(
                reader.open(last, &chunks[last as usize]).unwrap(),
                plaintext[(last as usize * CHUNK_BYTES).min(plaintext.len())..]
            );
            // Step 7 needs every chunk, in order.
            if last > 0 {
                assert!(reader.finish().is_err());
            }
            // Without the key: Sealed.
            assert_eq!(
                ChunkReader::new(&header, &space, Opening::ContentKey(None), &object.locator)
                    .unwrap_err(),
                ErrorClass::Sealed.into()
            );
            // Another locator's object: ObjectMismatch.
            let mut other = object.locator;
            other[0] ^= 1;
            assert_eq!(
                ChunkReader::new(&header, &space, opening, &other).unwrap_err(),
                UnitClass::ObjectMismatch.into()
            );
            // An altered chunk does not open; one of the wrong length is
            // Malformed.
            let mut reader = ChunkReader::new(&header, &space, opening, &object.locator).unwrap();
            let mut altered = chunks[0].clone();
            altered[30] ^= 1;
            assert_eq!(
                reader.open(0, &altered).unwrap_err(),
                ErrorClass::Decrypt.into()
            );
            assert_eq!(
                reader.open(0, &chunks[0][1..]).unwrap_err(),
                UnitError::from(Malformed)
            );
            assert_eq!(
                reader.open(last + 1, &chunks[0]).unwrap_err(),
                UnitError::from(Malformed)
            );
            // A chunk presented at another index does not open: each
            // chunk's associated data names its index.
            if chunks.len() > 2 {
                let mut reader =
                    ChunkReader::new(&header, &space, opening, &object.locator).unwrap();
                assert_eq!(
                    reader.open(0, &chunks[1]).unwrap_err(),
                    ErrorClass::Decrypt.into()
                );
                let parts: Vec<(u64, &[u8])> = vec![(0, &chunks[0]), (1, &chunks[0])];
                assert_eq!(
                    reader.open_many(&parts, &InTurn).unwrap_err(),
                    ErrorClass::Decrypt.into()
                );
            }
        }
    }

    #[test]
    fn parts_read_as_their_bytes_whole() {
        let space = EventId([1; 32]);
        let key = [2; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let big: Vec<u8> = (0..CHUNK_BYTES * 2 + 5).map(|i| i as u8).collect();
        for plaintext in [&b""[..], b"x", &big] {
            let object = seal_object(&space, &key, &reference, plaintext).unwrap();
            let (header, chunks) = split(&object.bytes);
            let object_key = ObjectKeys::of(&key).object_key(&object.id);
            let read = |header: &[u8], chunks: &[Vec<u8>], opening, locator: &Locator| {
                let chunks: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
                let parts = Parts {
                    header,
                    chunks: &chunks,
                };
                let bytes = parts.to_bytes().unwrap();
                let whole = match opening {
                    Opening::ContentKey(key) => read_object(&bytes, &space, key, locator),
                    Opening::ObjectKey(key) => read_object_with_key(&bytes, &space, key, locator),
                };
                let in_parts = read_object_parts(parts, &space, opening, locator, &InTurn);
                assert_eq!(in_parts, whole);
                in_parts
            };
            let openings = [
                Opening::ContentKey(Some(&key)),
                Opening::ContentKey(None),
                Opening::ContentKey(Some(&[9; 32])),
                Opening::ObjectKey(&object_key),
                Opening::ObjectKey(&[9; 32]),
            ];
            assert_eq!(
                read(&header, &chunks, openings[0], &object.locator),
                Ok(plaintext.to_vec())
            );
            for opening in openings {
                let _ = read(&header, &chunks, opening, &object.locator);
                // A chunk altered: the digest fails first.
                let mut altered = chunks.clone();
                let last = altered.len() - 1;
                altered[last][30] ^= 1;
                let _ = read(&header, &altered, opening, &object.locator);
                // Altered with the locator to match: the chunk fails.
                let mut locator = object.locator;
                let (header_b, altered_b) = (&header, &altered);
                let chunks: Vec<&[u8]> = altered_b.iter().map(Vec::as_slice).collect();
                let bytes = Parts {
                    header: header_b,
                    chunks: &chunks,
                }
                .to_bytes()
                .unwrap();
                locator[32..].copy_from_slice(&sha256(&[&bytes]));
                let _ = read(&header, &altered, opening, &locator);
                // Parts that are not the header's chunks, with the same
                // bytes whole.
                if chunks.len() > 1 {
                    let mut moved = altered.clone();
                    let byte = moved[1].remove(0);
                    moved[0].push(byte);
                    let _ = read(&header, &moved, opening, &locator);
                }
                let mut short = chunks.iter().map(|c| c.to_vec()).collect::<Vec<_>>();
                short.pop();
                let _ = read(&header, &short, opening, &object.locator);
                let _ = read(&header[1..], &altered, opening, &locator);
            }
        }
    }

    #[test]
    fn an_object_round_trips_and_dedupes() {
        let space = EventId([1; 32]);
        let key = [2; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        for plaintext in [&b""[..], b"x", &[7; 130]] {
            let object = seal_object_chunked(&space, &key, &reference, plaintext, 64).unwrap();
            let again = seal_object_chunked(&space, &key, &reference, plaintext, 64).unwrap();
            assert_eq!(object.locator, again.locator);
            assert_eq!(
                read_object_chunked(&object.bytes, &space, Some(&key), &object.locator, 64),
                Ok(plaintext.to_vec())
            );
            let object_key = ObjectKeys::of(&key).object_key(&object.id);
            assert_eq!(
                read_object_with_key_chunked(
                    &object.bytes,
                    &space,
                    &object_key,
                    &object.locator,
                    64
                ),
                Ok(plaintext.to_vec())
            );
        }
    }

    #[test]
    fn an_object_key_opens_its_object_alone() {
        let space = EventId([1; 32]);
        let key = [2; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let one = seal_object(&space, &key, &reference, b"one").unwrap();
        let two = seal_object(&space, &key, &reference, b"two").unwrap();
        let keys = ObjectKeys::of(&key);
        assert_eq!(
            read_object_with_key(&two.bytes, &space, &keys.object_key(&one.id), &two.locator),
            Err(ErrorClass::Decrypt.into())
        );
        assert_eq!(
            read_object_with_key(
                &one.bytes,
                &EventId([9; 32]),
                &keys.object_key(&one.id),
                &one.locator
            ),
            Err(ErrorClass::Decrypt.into()),
            "the chunks' associated data name the source"
        );
    }
}
