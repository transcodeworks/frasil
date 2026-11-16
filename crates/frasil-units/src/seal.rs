//! The seal (units.md, section 2.4, "The seal").
//!
//! ```text
//! unit_key(S) = HKDF(none, k(S), "frasil/unit-key/v1")
//! aad         = "frasil/unit/v1" || field(log) || author || u64be(seq)
//!               || stream || field(key reference)
//! body_key    = HKDF(none, unit_key(S), aad)
//! commitment  = HKDF(none, body_key, "frasil/unit-commitment/v1")
//! sealed      = nonce (24 random bytes) || commitment (32)
//!               || XChaCha20-Poly1305(body_key, nonce, inner, aad)
//! ```
//!
//! `log` and `seq` are the envelope's, and `author` the device ID its `ed`
//! and `kc` give (events.md, "The envelope"); `stream` and the key
//! reference are the visible body's. A sealed part therefore opens in one
//! unit only, and cannot be moved under another state. The body key opens
//! that one unit's sealed part and nothing else, so it can be handed to a
//! member that does not hold `k(S)`; the commitment binds the seal to one
//! body key, since XChaCha20-Poly1305 does not commit to its key. The seal
//! holds no signature: the envelope's signature covers the whole body.

use crate::limits::{COMMITMENT_BYTES, NONCE_BYTES};
use crate::stream::StreamId;
use frasil_base::ErrorClass;
use frasil_base::notation::field;
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels::{UNIT, UNIT_COMMITMENT, UNIT_KEY};
use frasil_crypto::primitives::{hkdf, xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_events::EventId;
use zeroize::Zeroizing;

/// `unit_key(S) = HKDF(none, k(S), "frasil/unit-key/v1")`.
pub fn unit_key(content_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, content_key, UNIT_KEY)
}

/// `aad = "frasil/unit/v1" || field(log) || author || u64be(seq) || stream
/// || field(key reference)`, `author` the unit's device ID.
pub fn unit_aad(
    log: &EventId,
    author: &DeviceId,
    seq: u64,
    stream: &StreamId,
    key_reference: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(UNIT.len() + 120 + key_reference.len());
    aad.extend_from_slice(UNIT);
    aad.extend_from_slice(&field(&log.0));
    aad.extend_from_slice(&author.0);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(stream);
    aad.extend_from_slice(&field(key_reference));
    aad
}

/// A unit's body key, `HKDF(none, unit_key(S), aad)`: it opens that unit's
/// sealed part and nothing else.
pub fn body_key(content_key: &[u8; 32], aad: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf(None, &*unit_key(content_key), aad)
}

/// A body key's commitment, `HKDF(none, body_key, "frasil/unit-commitment/v1")`.
pub fn commitment(body_key: &[u8; 32]) -> [u8; COMMITMENT_BYTES] {
    *hkdf(None, body_key, UNIT_COMMITMENT)
}

/// The commitment a seal carries, after its nonce; `None` for a seal too
/// short to carry one.
pub fn sealed_commitment(sealed: &[u8]) -> Option<&[u8; COMMITMENT_BYTES]> {
    sealed
        .get(NONCE_BYTES..NONCE_BYTES + COMMITMENT_BYTES)
        .and_then(|c| c.try_into().ok())
}

/// `sealed = nonce || commitment || XChaCha20-Poly1305(body_key, nonce,
/// inner, aad)`, with a nonce the caller drew from its random source.
pub fn seal_with(
    content_key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    inner: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let key = body_key(content_key, aad);
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&commitment(&key));
    sealed.extend_from_slice(&xchacha20poly1305_seal(&key, nonce, aad, inner));
    sealed
}

/// Opens a seal under `unit_key(S)`: its body key, checked against the
/// seal's commitment.
///
/// # Errors
///
/// `Decrypt` when the commitment does not match or the seal does not open;
/// the caller says whether that is `BadSeal` or `Sealed` (section 3.2,
/// step 14).
pub fn open(
    content_key: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    open_with_body_key(&body_key(content_key, aad), sealed, aad)
}

/// Opens a seal under a body key, checked against the seal's commitment.
///
/// # Errors
///
/// `Decrypt` when the commitment does not match or the seal does not open.
pub fn open_with_body_key(
    body_key: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    let committed = sealed_commitment(sealed).ok_or(ErrorClass::Decrypt)?;
    // A commitment is public: it is compared as it is.
    if commitment(body_key) != *committed {
        return Err(ErrorClass::Decrypt);
    }
    let nonce: &[u8; NONCE_BYTES] = sealed[..NONCE_BYTES]
        .try_into()
        .map_err(|_| ErrorClass::Decrypt)?;
    xchacha20poly1305_open(
        body_key,
        nonce,
        aad,
        &sealed[NONCE_BYTES + COMMITMENT_BYTES..],
    )
}

/// Whether a body key matches a seal's commitment.
pub fn commits_to(body_key: &[u8; 32], sealed: &[u8]) -> bool {
    sealed_commitment(sealed).is_some_and(|c| commitment(body_key) == *c)
}
