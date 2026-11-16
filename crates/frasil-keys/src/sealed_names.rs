//! Sealed names (keys.md, "Sealed names", sections 2.8 and 3.16).
//!
//! A sealed name is a name people chose, sealed under the metadata key of
//! one state and bound to its space, its state and the thing it names:
//!
//! ```text
//! padded = u16be(L) || name || zero bytes        padded_len(L) = ceil((L + 2) / 64) × 64
//! aad    = "frasil/name/v1" || space || field(reference) || u8(c) || field(id)
//! sealed = 0x01 || nonce (24) || XChaCha20-Poly1305(mk, nonce, padded, aad)
//! record = 0x01 || space (32) || field(reference) || sealed
//! ```
//!
//! A sealed name reveals only its 64-byte bucket.

use crate::KeyClass;
use crate::derive::{Secret, metadata_key};
use crate::limits::{MAX_DOCUMENT_ID_BYTES, MAX_NAME_BYTES};
use crate::names::RotationSet;
use frasil_base::ErrorClass;
use frasil_base::notation::{push_field, u16be};
use frasil_crypto::labels;
use frasil_crypto::primitives::{xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_crypto::sizes::{XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG};
use frasil_events::EventId;
use zeroize::Zeroizing;

/// The sealed name's and the record's version byte.
pub const NAME_VERSION: u8 = 0x01;
/// The padded plaintext is a multiple of this many bytes.
pub const BUCKET: usize = 64;
/// What sealing adds to the padded plaintext: the version, the nonce and
/// the tag.
pub const OVERHEAD: usize = 1 + XCHACHA20POLY1305_NONCE + XCHACHA20POLY1305_TAG;
/// The shortest record: the version, the space and the reference's length.
pub const MIN_RECORD_BYTES: usize = 1 + 32 + 4;

/// Kind code 1: the name of a space, this one or another whose name this
/// space keeps; its ID is that space's 32-byte ID.
pub const KIND_SPACE: u8 = 1;
/// Kind code 2: the name of a document in the space; its ID, 1 to 128
/// bytes, is its stream ID or the application's own.
pub const KIND_DOCUMENT: u8 = 2;

/// `padded_len(L) = ceil((L + 2) / 64) × 64`.
pub fn padded_len(length: usize) -> usize {
    (length + 2).div_ceil(BUCKET) * BUCKET
}

/// The associated data: `"frasil/name/v1" || space || field(reference) ||
/// u8(c) || field(id)`.
pub fn name_aad(space: &EventId, reference: &RotationSet, kind: u8, id: &[u8]) -> Vec<u8> {
    bound_aad(space, &reference.encode(), kind, id)
}

/// [`name_aad`] over a reference's bytes, whatever its form.
pub(crate) fn bound_aad(space: &EventId, reference: &[u8], kind: u8, id: &[u8]) -> Vec<u8> {
    let mut aad = labels::NAME.to_vec();
    aad.extend_from_slice(space.as_bytes());
    push_field(&mut aad, reference);
    aad.push(kind);
    push_field(&mut aad, id);
    aad
}

/// Step 1 of sealing and of opening: `c` is 1 or 2, and `id` follows its
/// kind's rule. The space is 32 bytes by its type.
fn check_kind(kind: u8, id: &[u8]) -> Result<(), KeyClass> {
    let fits = match kind {
        KIND_SPACE => id.len() == 32,
        KIND_DOCUMENT => (1..=MAX_DOCUMENT_ID_BYTES).contains(&id.len()),
        _ => false,
    };
    if fits {
        Ok(())
    } else {
        Err(ErrorClass::Malformed.into())
    }
}

/// The padded plaintext of a name, `u16be(L) || name || zero bytes`.
fn pad(name: &str) -> Result<Zeroizing<Vec<u8>>, KeyClass> {
    let length = u16::try_from(name.len())
        .ok()
        .filter(|&length| (1..=MAX_NAME_BYTES).contains(&usize::from(length)))
        .ok_or(KeyClass::InvalidName)?;
    let mut padded = Zeroizing::new(Vec::with_capacity(padded_len(name.len())));
    padded.extend_from_slice(&u16be(length));
    padded.extend_from_slice(name.as_bytes());
    padded.resize(padded_len(name.len()), 0);
    Ok(padded)
}

/// Seals a name, with the nonce given (keys.md, section 2.8): under
/// `metadata_key`, the metadata key of the state `reference` names, bound to
/// the space, that reference, the kind code and the ID.
///
/// # Errors
///
/// 1. `Malformed` for a kind other than 1 or 2, or an ID that breaks its
///    kind's rule.
/// 2. `InvalidName` for a name that is empty or longer than 1,022 bytes.
pub fn seal_name_with(
    metadata_key: &[u8; 32],
    space: &EventId,
    reference: &RotationSet,
    kind: u8,
    id: &[u8],
    name: &str,
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
) -> Result<Vec<u8>, KeyClass> {
    seal_bound(
        metadata_key,
        space,
        &reference.encode(),
        kind,
        id,
        name,
        nonce,
    )
}

/// [`seal_name_with`] over a reference's bytes, whatever its form.
pub(crate) fn seal_bound(
    metadata_key: &[u8; 32],
    space: &EventId,
    reference: &[u8],
    kind: u8,
    id: &[u8],
    name: &str,
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
) -> Result<Vec<u8>, KeyClass> {
    check_kind(kind, id)?;
    let padded = pad(name)?;
    let aad = bound_aad(space, reference, kind, id);
    let ciphertext = xchacha20poly1305_seal(metadata_key, nonce, &aad, &padded);
    let mut sealed = Vec::with_capacity(OVERHEAD + padded.len());
    sealed.push(NAME_VERSION);
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Opens a sealed name, in keys.md's order (section 3.16, "Opening").
///
/// # Errors
///
/// 1. `Malformed`: as sealing's step 1.
/// 2. `Malformed` for no byte; `UnsupportedVersion` for a version other
///    than `0x01`.
/// 3. `Malformed` unless `len(s) − 41` is above 0, a multiple of 64 and at
///    most 1,024.
/// 4. `Decrypt` unless it opens under the key and section 2.8's `aad`.
/// 5. `Malformed` unless the plaintext holds a length of 1 to 1,022, is
///    exactly `padded_len(L)` bytes, is zero after the name, and the name is
///    UTF-8. Every refusal after decryption is `Malformed`, so a caller
///    without the key learns only whether the tag verified.
pub fn open_name(
    metadata_key: &[u8; 32],
    space: &EventId,
    reference: &RotationSet,
    kind: u8,
    id: &[u8],
    sealed: &[u8],
) -> Result<String, KeyClass> {
    open_bound(metadata_key, space, &reference.encode(), kind, id, sealed)
}

/// [`open_name`] over a reference's bytes, whatever its form.
pub(crate) fn open_bound(
    metadata_key: &[u8; 32],
    space: &EventId,
    reference: &[u8],
    kind: u8,
    id: &[u8],
    sealed: &[u8],
) -> Result<String, KeyClass> {
    let malformed = || KeyClass::from(ErrorClass::Malformed);
    // 1.
    check_kind(kind, id)?;
    // 2.
    let (&version, rest) = sealed.split_first().ok_or_else(malformed)?;
    if version != NAME_VERSION {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    // 3.
    let body = sealed.len().saturating_sub(OVERHEAD);
    if body == 0 || !body.is_multiple_of(BUCKET) || body > padded_len(MAX_NAME_BYTES) {
        return Err(malformed());
    }
    // 4.
    let (nonce, ciphertext) = rest
        .split_first_chunk::<XCHACHA20POLY1305_NONCE>()
        .ok_or_else(malformed)?;
    let aad = bound_aad(space, reference, kind, id);
    let plaintext = xchacha20poly1305_open(metadata_key, nonce, &aad, ciphertext)?;
    // 5.
    let (length, padded) = plaintext.split_first_chunk::<2>().ok_or_else(malformed)?;
    let length = usize::from(u16::from_be_bytes(*length));
    if !(1..=MAX_NAME_BYTES).contains(&length) || plaintext.len() != padded_len(length) {
        return Err(malformed());
    }
    let (name, zeros) = padded.split_at(length);
    if zeros.iter().any(|&byte| byte != 0) {
        return Err(malformed());
    }
    String::from_utf8(name.to_vec()).map_err(|_| malformed())
}

/// A record: `0x01 || space (32) || field(reference) || sealed`.
pub fn encode_record(space: &EventId, reference: &RotationSet, sealed: &[u8]) -> Vec<u8> {
    let mut record = vec![NAME_VERSION];
    record.extend_from_slice(space.as_bytes());
    push_field(&mut record, &reference.encode());
    record.extend_from_slice(sealed);
    record
}

/// A record's parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record<'a> {
    /// The space whose name this is a record of.
    pub space: EventId,
    /// The state the name is sealed under.
    pub reference: RotationSet,
    /// The sealed name.
    pub sealed: &'a [u8],
}

pub(crate) fn record_space(record: &[u8]) -> Result<EventId, KeyClass> {
    let malformed = || KeyClass::from(ErrorClass::Malformed);
    // 1.
    let (&version, _) = record.split_first().ok_or_else(malformed)?;
    if version != NAME_VERSION {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    // 2.
    if record.len() < MIN_RECORD_BYTES {
        return Err(malformed());
    }
    Ok(EventId(record[1..33].try_into().map_err(|_| malformed())?))
}

fn record_reference(record: &[u8]) -> Result<(RotationSet, &[u8]), KeyClass> {
    let (reference, sealed) = record_reference_bytes(record)?;
    Ok((RotationSet::decode(reference)?, sealed))
}

/// A record's reference and sealed name, the reference unread: step 4's
/// length checks. The record holds at least 37 bytes.
pub(crate) fn record_reference_bytes(record: &[u8]) -> Result<(&[u8], &[u8]), KeyClass> {
    let malformed = || KeyClass::from(ErrorClass::Malformed);
    let length: [u8; 4] = record[33..MIN_RECORD_BYTES]
        .try_into()
        .map_err(|_| malformed())?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| malformed())?;
    let rest = &record[MIN_RECORD_BYTES..];
    if length == 0 || length > rest.len() {
        return Err(malformed());
    }
    Ok(rest.split_at(length))
}

impl<'a> Record<'a> {
    /// Reads a record's parts, steps 1, 2 and 4 of keys.md's "Reading a
    /// record", with no space to check against.
    ///
    /// # Errors
    ///
    /// `Malformed` for no byte; `UnsupportedVersion` for a version other
    /// than `0x01`; `Malformed` for fewer than 37 bytes, or a reference
    /// whose length is 0 or runs past the record's end; the reference's
    /// classes as a key reference.
    pub fn read(record: &'a [u8]) -> Result<Self, KeyClass> {
        let space = record_space(record)?;
        let (reference, sealed) = record_reference(record)?;
        Ok(Self {
            space,
            reference,
            sealed,
        })
    }
}

/// Reads a record in a space and opens its name, in keys.md's order
/// (section 3.16, "Reading a record"). `content_key_of` gives the content
/// key of a state the reader holds.
///
/// # Errors
///
/// 1. `Malformed` for no byte; `UnsupportedVersion` for a version other
///    than `0x01`.
/// 2. `Malformed` for fewer than 37 bytes.
/// 3. `Decrypt` for another space's record, whose reference is not read.
/// 4. `Malformed` for a reference whose length is 0 or does not fit, or the
///    reference's classes as a key reference.
/// 5. `MissingState` when the reader does not hold the content key of the
///    state it names: it may reach it later.
/// 6. [`open_name`]'s classes, under that state's metadata key.
pub fn open_record(
    record: &[u8],
    space: &EventId,
    content_key_of: impl FnOnce(&RotationSet) -> Option<Secret>,
    kind: u8,
    id: &[u8],
) -> Result<String, KeyClass> {
    // 1, 2.
    if record_space(record)? != *space {
        // 3.
        return Err(ErrorClass::Decrypt.into());
    }
    // 4.
    let (reference, sealed) = record_reference(record)?;
    // 5.
    let content_key = content_key_of(&reference).ok_or(KeyClass::MissingState)?;
    // 6.
    open_name(
        &metadata_key(&content_key),
        space,
        &reference,
        kind,
        id,
        sealed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(padded_len(1), 64);
        assert_eq!(padded_len(62), 64);
        assert_eq!(padded_len(63), 128);
        assert_eq!(padded_len(MAX_NAME_BYTES), 1024);
    }

    #[test]
    fn a_name_round_trips() {
        let space = EventId([1; 32]);
        let reference = RotationSet::single(EventId([2; 32]));
        let key = [3; 32];
        let sealed = seal_name_with(
            &key,
            &space,
            &reference,
            KIND_DOCUMENT,
            b"doc",
            "Été",
            &[4; 24],
        )
        .unwrap();
        assert_eq!(sealed.len(), 64 + OVERHEAD);
        assert_eq!(
            open_name(&key, &space, &reference, KIND_DOCUMENT, b"doc", &sealed).as_deref(),
            Ok("Été")
        );
        assert_eq!(
            open_name(&key, &space, &reference, KIND_DOCUMENT, b"other", &sealed),
            Err(ErrorClass::Decrypt.into())
        );
        let record = encode_record(&space, &reference, &sealed);
        let read = Record::read(&record).unwrap();
        assert_eq!((read.space, read.sealed), (space, &sealed[..]));
    }
}
