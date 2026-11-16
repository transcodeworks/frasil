//! The possession statement and its proof (identity.md, "The possession
//! statement").
//!
//! The key an `add` names signs this statement under scheme 2, with its own
//! identity and ML-DSA-65 keys:
//!
//! ```text
//! statement =  "frasil/device-list/possession/v3"     32 bytes
//!           || field(person_id)                       4 + 32
//!           || field(adder)                           4 + 32
//!           || field(u8(kind))                        4 + 1
//!           || field(identity)                        4 + 32
//!           || field(mldsa)                           4 + 1,952
//!           || field(xwing)                           4 + 1,216, or 4 + 0 for an agent
//!           || field(u8(2))                           4 + 1: the scheme
//! ```
//!
//! `adder` is the device ID of the list member that signs the `add`, the
//! event's author: the device itself in the list's first event. `identity`,
//! `mldsa` and `xwing` are every key the added device ID commits to, so the
//! statement names that device ID too. A proof is
//! for one adder, so another list member that signs a copy of the `add` on
//! its own chain makes an `add` whose proof does not verify.
//!
//! A verifier computes the statement from the list it appends to, the
//! event's author and the keys the body names; it never reads one.

use crate::IdentityClass;
use crate::keys::Kind;
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey};
use frasil_crypto::labels::DEVICE_LIST_POSSESSION;
use frasil_crypto::schemes::{
    SCHEME_HYBRID, Scheme, Signed, Signer, ed25519_verify_strict, hybrid_ed25519_message,
    verify_mldsa_steps,
};
use frasil_crypto::sizes::{ED25519_SIGNATURE, MLDSA65_PUBLIC, SCHEME2_SIGNATURE, XWING_PUBLIC};

/// The statement's length for every kind but an agent.
pub const STATEMENT_BYTES: usize = 3326;

/// The statement's length for an agent, whose X-Wing field is empty.
pub const AGENT_STATEMENT_BYTES: usize = 2110;

/// A possession proof: a scheme-2 signature, 3,373 bytes.
pub const PROOF_BYTES: usize = SCHEME2_SIGNATURE;

/// The person ID a list's first event binds in its proof: 32 zero bytes,
/// since the person ID is that event's hash.
pub const FIRST_EVENT_PERSON: [u8; 32] = [0; 32];

/// The possession statement for an `add` of these keys as `kind` to the list
/// of `person_id` ([`FIRST_EVENT_PERSON`] in the list's first event), signed
/// by `adder`, the device ID of the list member that signs the `add`.
/// `xwing` is `None` for an agent, whose field is then empty.
pub fn statement(
    person_id: &[u8; 32],
    adder: &DeviceId,
    kind: Kind,
    identity: &IdentityKey,
    mldsa: &[u8; MLDSA65_PUBLIC],
    xwing: Option<&[u8; XWING_PUBLIC]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATEMENT_BYTES);
    out.extend_from_slice(DEVICE_LIST_POSSESSION);
    push_field(&mut out, person_id);
    push_field(&mut out, &adder.0);
    push_field(&mut out, &[kind.code()]);
    push_field(&mut out, &identity.0);
    push_field(&mut out, mldsa);
    push_field(&mut out, xwing.map_or(&[][..], |key| &key[..]));
    push_field(&mut out, &[SCHEME_HYBRID]);
    out
}

/// The proof of a statement: its scheme-2 signature by the named key's
/// identity and ML-DSA-65 keys, deterministic.
pub fn prove(signer: &Signer, statement: &[u8]) -> Vec<u8> {
    signer.sign(Scheme::Hybrid, statement)
}

/// Whether `proof` verifies over `statement`, both halves: the Ed25519 half
/// strictly under `identity`, and the ML-DSA-65 half under the ML-DSA-65 key
/// of `keys` (crypto.md, "Signature schemes", with the statement as `tbs`).
///
/// `identity` has passed `ed25519_valid` already.
///
/// # Errors
///
/// `BadPossession` if either half fails or the proof is not 3,373 bytes.
pub fn verify(
    identity: &IdentityKey,
    keys: &HybridKeys,
    statement: &[u8],
    proof: &[u8],
) -> Result<(), IdentityClass> {
    let bad = IdentityClass::Shared(ErrorClass::BadPossession);
    if proof.len() != PROOF_BYTES {
        return Err(bad);
    }
    let m_ed = hybrid_ed25519_message(identity, statement);
    if !ed25519_verify_strict(&identity.0, &m_ed, &proof[..ED25519_SIGNATURE]) {
        return Err(bad);
    }
    let signed = Signed {
        scheme: u64::from(SCHEME_HYBRID),
        ed: identity,
        kc: keys.commitment(),
        tbs: statement,
        signature: proof,
    };
    verify_mldsa_steps(&signed, Some(keys)).map_err(|_| bad)
}
