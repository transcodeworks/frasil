//! What derives from a state's secrets (keys.md, "Derivations"), and a
//! space event's body key and its commitment ("The space event's body").
//!
//! ```text
//! k(S) = k_R                                                    if S = {R}
//! info = "frasil/merge-key/v1" || field(space) || encode_set(S) if n >= 2
//! t_i  = HMAC(key = k_Ri, message = info)                       for each i, in order
//! k(S) = HKDF(salt = none, ikm = t_1 || ... || t_n, info)
//!
//! xwing_seed(G)   = HKDF(salt = none, ikm = g(G), info = "frasil/grant-key/v1")
//! commitment(R)   = SHA-256("frasil/grant-commitment/v1" || u8(break) || grant_public({R}))
//! read_seed(S)    = HKDF(salt = none, ikm = k(S), info = "frasil/read-credential/v1")
//! upload_seed(S)  = HKDF(salt = none, ikm = w(S), info = "frasil/upload-key/v1")
//!
//! aad        = "frasil/space-event/v1" || log || author || u64be(seq), author the device ID the envelope gives
//! body_key   = HKDF(salt = none, ikm = secret, info = aad)
//! commitment = HKDF(salt = none, ikm = body_key, info = "frasil/space-event-commitment/v1")
//! ```
//!
//! `k_R`, `k(S)`, `w(S)` and `g(G)` are used only as HMAC keys, as HKDF
//! input keying material and inside bundles: nothing here seals or signs
//! under them directly.

use crate::KeyClass;
use crate::names::RotationSet;
use frasil_base::ErrorClass;
use frasil_base::notation::{push_field, u64be};
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels;
use frasil_crypto::primitives::{ed25519_public, hkdf, hmac_sha256, sha256};
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_crypto::wrap::xwing_public;
use frasil_events::EventId;
use zeroize::Zeroizing;

/// A 32-byte secret, wiped when dropped.
pub type Secret = Zeroizing<[u8; 32]>;

/// Which secret of a state is merged: each has its own label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// The content key `k`, under `frasil/merge-key/v1`.
    Content,
    /// The upload seed `w`, under `frasil/merge-upload/v1`.
    Upload,
    /// The grant seed `g` of a grant state, under `frasil/merge-grant/v1`.
    Grant,
}

impl SecretKind {
    /// The merge's label.
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::Content => labels::MERGE_KEY,
            Self::Upload => labels::MERGE_UPLOAD,
            Self::Grant => labels::MERGE_GRANT,
        }
    }
}

/// A merge of two or more rotations' secrets, step by step. It holds
/// secrets, so it has no `PartialEq`: compare its fields in constant time.
#[derive(Clone)]
pub struct Merge {
    /// `label || field(space) || encode_set(S)`.
    pub info: Vec<u8>,
    /// `t_i = HMAC(k_Ri, info)`, in the state's canonical order.
    pub t: Zeroizing<Vec<[u8; 32]>>,
    /// `t_1 || ... || t_n`.
    pub ikm: Zeroizing<Vec<u8>>,
    /// The merged secret.
    pub secret: Secret,
}

impl core::fmt::Debug for Merge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Merge")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// A merge's `info`: `label || field(space) || encode_set(S)`.
pub fn merge_info(kind: SecretKind, space: &EventId, state: &RotationSet) -> Vec<u8> {
    let mut info = kind.label().to_vec();
    push_field(&mut info, space.as_bytes());
    state.encode_into(&mut info);
    info
}

/// Merges the secrets of a state of two or more rotations, given in the
/// state's canonical order.
///
/// # Errors
///
/// `Malformed` for a state of one rotation, or a count of inputs that is not
/// the state's.
pub fn merge(
    kind: SecretKind,
    space: &EventId,
    state: &RotationSet,
    inputs: &[[u8; 32]],
) -> Result<Merge, KeyClass> {
    if state.len() < 2 || inputs.len() != state.len() {
        return Err(ErrorClass::Malformed.into());
    }
    let info = merge_info(kind, space, state);
    let t: Zeroizing<Vec<[u8; 32]>> =
        Zeroizing::new(inputs.iter().map(|k| hmac_sha256(k, &info)).collect());
    let ikm = Zeroizing::new(t.concat());
    let secret = hkdf(None, &ikm, &info);
    Ok(Merge {
        info,
        t,
        ikm,
        secret,
    })
}

/// A state's secret of one kind: the rotation's own for a state of one, the
/// merge of its inputs otherwise. The inputs come in the state's canonical
/// order.
///
/// # Errors
///
/// `Malformed` for a count of inputs that is not the state's.
pub fn state_secret(
    kind: SecretKind,
    space: &EventId,
    state: &RotationSet,
    inputs: &[[u8; 32]],
) -> Result<Secret, KeyClass> {
    match inputs {
        [only] if state.len() == 1 => Ok(Zeroizing::new(*only)),
        _ => Ok(merge(kind, space, state, inputs)?.secret),
    }
}

/// The grant key: an X-Wing key pair from a grant state's seed. It holds
/// a secret, so it has no `PartialEq`.
#[derive(Clone)]
pub struct GrantKey {
    /// `xwing_seed(G) = HKDF(salt = none, ikm = g(G), info = "frasil/grant-key/v1")`.
    pub xwing_seed: Secret,
    /// `grant_public(G)`, the seed's X-Wing public key.
    pub public: Box<[u8; XWING_PUBLIC]>,
}

impl core::fmt::Debug for GrantKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrantKey").finish_non_exhaustive()
    }
}

impl GrantKey {
    /// The grant key of a grant state's seed `g(G)`.
    pub fn derive(grant_seed: &[u8; 32]) -> Self {
        let xwing_seed = hkdf(None, grant_seed, labels::GRANT_KEY);
        let public = Box::new(xwing_public(&xwing_seed));
        Self { xwing_seed, public }
    }

    /// The commitment a grant rotation of this key publishes.
    pub fn commitment(&self, is_break: bool) -> [u8; 32] {
        grant_commitment(&self.public, is_break)
    }
}

/// `SHA-256("frasil/grant-commitment/v1" || u8(break) || grant_public)`: the
/// commitment a grant rotation publishes in its visible key 3, and a notice
/// is checked against.
pub fn grant_commitment(public: &[u8; XWING_PUBLIC], is_break: bool) -> [u8; 32] {
    sha256(&[labels::GRANT_COMMITMENT, &[u8::from(is_break)], public])
}

/// An Ed25519 key pair derived from a state's secret. It holds a secret,
/// so it has no `PartialEq`.
#[derive(Clone)]
pub struct Credential {
    /// The Ed25519 seed.
    pub seed: Secret,
    /// The public key a peer learns.
    pub public: [u8; 32],
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

fn credential(secret: &[u8; 32], label: &[u8]) -> Credential {
    let seed = hkdf(None, secret, label);
    let public = ed25519_public(&seed);
    Credential { seed, public }
}

/// The read credential of a state, from its content key `k(S)`.
pub fn read_credential(content_key: &[u8; 32]) -> Credential {
    credential(content_key, labels::READ_CREDENTIAL)
}

/// The upload key of a state, from its upload seed `w(S)`.
pub fn upload_key(upload_seed: &[u8; 32]) -> Credential {
    credential(upload_seed, labels::UPLOAD_KEY)
}

/// `metadata_key(S)`, from the state's content key: the key names are
/// sealed under.
pub fn metadata_key(content_key: &[u8; 32]) -> Secret {
    hkdf(None, content_key, labels::SPACE_METADATA_KEY)
}

/// `object_id_key(S)`, from the state's content key.
pub fn object_id_key(content_key: &[u8; 32]) -> Secret {
    hkdf(None, content_key, labels::OBJECT_ID_KEY)
}

/// `object_nonce_key(S)`, from the state's content key.
pub fn object_nonce_key(content_key: &[u8; 32]) -> Secret {
    hkdf(None, content_key, labels::OBJECT_NONCE_KEY)
}

/// A space event's associated data, which is also its body key's `info`:
/// `"frasil/space-event/v1" || field(log) || author || u64be(seq)`.
pub fn body_aad(log: &[u8], author: &DeviceId, seq: u64) -> Vec<u8> {
    let mut aad = labels::SPACE_EVENT.to_vec();
    push_field(&mut aad, log);
    aad.extend_from_slice(&author.0);
    aad.extend_from_slice(&u64be(seq));
    aad
}

/// A space event's body key: `HKDF(salt = none, ikm = secret, info = aad)`.
/// `secret` is `k_R` in an event that rotates, and `k(S)` of the state
/// `sealed_under` names otherwise.
pub fn body_key(secret: &[u8; 32], log: &[u8], author: &DeviceId, seq: u64) -> Secret {
    hkdf(None, secret, &body_aad(log, author, seq))
}

/// The commitment to a body key, the visible key 14.
pub fn body_commitment(body_key: &[u8; 32]) -> [u8; 32] {
    *hkdf(None, body_key, labels::SPACE_EVENT_COMMITMENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_of_one_is_its_rotation() {
        let space = EventId([1; 32]);
        let state = RotationSet::single(EventId([2; 32]));
        let secret = state_secret(SecretKind::Content, &space, &state, &[[9; 32]]).unwrap();
        assert_eq!(*secret, [9; 32]);
        assert!(merge(SecretKind::Content, &space, &state, &[[9; 32]]).is_err());
    }

    #[test]
    fn a_merge_binds_its_kind_space_and_set() {
        let space = EventId([1; 32]);
        let state = RotationSet::new([EventId([2; 32]), EventId([3; 32])]).unwrap();
        let inputs = [[4; 32], [5; 32]];
        let content = state_secret(SecretKind::Content, &space, &state, &inputs).unwrap();
        let upload = state_secret(SecretKind::Upload, &space, &state, &inputs).unwrap();
        let elsewhere =
            state_secret(SecretKind::Content, &EventId([6; 32]), &state, &inputs).unwrap();
        assert_ne!(*content, *upload);
        assert_ne!(*content, *elsewhere);
        assert!(state_secret(SecretKind::Content, &space, &state, &inputs[..1]).is_err());
    }
}
