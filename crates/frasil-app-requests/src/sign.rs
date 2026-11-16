//! Signing (ext-app-requests.md, "Signing").
//!
//! A client builds the statement from the method, the URL's path and query
//! and the body bytes it is about to send, with the subject it is signed in
//! as, its person ID, the heads of its merged list and the audience of the
//! URL, and sets the six headers. Its HTTP transport sends them unchanged
//! and follows no redirect.
//!
//! A web server that forwards a browser's call to the verifier over a private
//! binding forwards the six values unchanged.

use crate::SIGNED_REQUEST_LIFETIME;
use crate::headers::SignedHeaders;
use crate::statement::{MAX_HEADS, NONCE_BYTES, Request, statement};
use frasil_base::ErrorClass;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::primitives::{ed25519_public, ed25519_sign};
use frasil_events::EventId;
use frasil_identity::DeviceList;

/// Signs a request with a list member's identity seed: the six header
/// values to send with it. `kc` is the member's keys commitment, which
/// `X-Frasil-Device` carries beside its Ed25519 key.
///
/// - `signed_at` is the signer's wall clock; `expires_at` is it plus
///   `signed_request_lifetime`.
/// - `nonce` is 16 fresh random bytes per request, which the caller draws
///   with `frasil_crypto::random_bytes`.
/// - `heads` are the heads of the signer's merged list, strictly ascending,
///   or none ([`heads_to_send`]).
///
/// # Errors
///
/// `Malformed` for an audience, subject, method, path, query or heads
/// outside its shape, or an expiry past 2^64 − 1: a signer refuses to sign
/// them.
pub fn sign(
    identity_seed: &[u8; 32],
    kc: &KeysCommitment,
    request: &Request<'_>,
    person_id: &[u8; 32],
    signed_at: u64,
    nonce: [u8; NONCE_BYTES],
    heads: &[EventId],
) -> Result<SignedHeaders, ErrorClass> {
    let signer = Signatory {
        ed: IdentityKey(ed25519_public(identity_seed)),
        kc: *kc,
    };
    let expires_at = signed_at
        .checked_add(SIGNED_REQUEST_LIFETIME)
        .ok_or(ErrorClass::Malformed)?;
    let message = statement(request, person_id, &signer, expires_at, &nonce, heads)?;
    Ok(SignedHeaders {
        signer,
        person_id: *person_id,
        expires_at,
        nonce,
        heads: heads.to_vec(),
        signature: ed25519_sign(identity_seed, &message),
    })
}

/// The heads a signer sends: those of its merged list, strictly ascending,
/// or none when there are more than 16.
pub fn heads_to_send(list: &DeviceList) -> Vec<EventId> {
    let mut heads = list.log().heads();
    heads.sort_unstable();
    heads.dedup();
    if heads.len() > MAX_HEADS {
        heads.clear();
    }
    heads
}
