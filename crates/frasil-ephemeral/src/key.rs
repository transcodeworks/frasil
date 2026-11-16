//! The ephemeral key and the ephemeral slot handle (ext-ephemeral.md, "The
//! ephemeral key" and "The ephemeral slot handle").

use crate::limits::{EPHEMERAL_KEY, EPHEMERAL_SLOT, HANDLE_BYTES};
use frasil_base::notation::push_field;
use frasil_crypto::device::Signatory;
use frasil_crypto::primitives::{hkdf, hmac_sha256};
use zeroize::Zeroizing;

/// `ek(S) = HKDF(salt = none, ikm = k(S), info = "frasil/ephemeral-key/v1")`.
/// In a restricted space, `k(S)` is the restricted content key `k_F`.
pub fn ephemeral_key(content_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, content_key, EPHEMERAL_KEY)
}

/// `HMAC(ek(S), "frasil/ephemeral-slot/v1" || sender || field(name) ||
/// field(stream, or empty))[0..16]`, `sender` the inner map's 64-byte
/// `ed || kc`.
pub fn slot_handle(
    ephemeral_key: &[u8; 32],
    sender: &Signatory,
    name: &str,
    stream: Option<&[u8; 16]>,
) -> [u8; HANDLE_BYTES] {
    let mut message = Vec::with_capacity(EPHEMERAL_SLOT.len() + 64 + 4 + name.len() + 4 + 16);
    message.extend_from_slice(EPHEMERAL_SLOT);
    message.extend_from_slice(&sender.to_bytes());
    push_field(&mut message, name.as_bytes());
    push_field(&mut message, stream.map_or(&[][..], |s| &s[..]));
    let mac = hmac_sha256(ephemeral_key, &message);
    let mut handle = [0; HANDLE_BYTES];
    handle.copy_from_slice(&mac[..HANDLE_BYTES]);
    handle
}
