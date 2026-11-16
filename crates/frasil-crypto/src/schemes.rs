//! Signature schemes 0 and 2 (crypto.md, "Signature schemes", "Strict
//! Ed25519 verification", "Verifying a signature" and "Which structures
//! carry which scheme").
//!
//! | Code | Scheme | Used by |
//! |---|---|---|
//! | 0 | Ed25519, verified strictly | units, and structures verified once, at once |
//! | 1 | reserved | refused, `UnsupportedVersion` |
//! | 2 | Ed25519 and ML-DSA-65, both of which MUST verify | authority events and possession proofs |
//!
//! Scheme 0 signs `tbs`, the bytes the structure's document defines. Scheme
//! 2 signs the same `tbs`, with the scheme field set to 2:
//!
//! ```text
//! m_ed      = "frasil/hybrid-signature/ed25519/v1" || ed_public (32) || tbs
//! m_ml      = "frasil/hybrid-signature/mldsa/v1" || ed_public (32)
//!             || SHA-256(mldsa_public) (32) || tbs
//! signature = Ed25519-Sign(ed_seed, m_ed) || ML-DSA.Sign(mldsa_secret, m_ml, ctx = "")
//! ```
//!
//! The Ed25519 half needs only the signer's Ed25519 key, so a verifier
//! checks it before it looks anything up ([`verify_ed25519_steps`]); the
//! ML-DSA-65 half binds both keys, and is checked once the verifier holds,
//! from any source, keys whose commitment is the signer's `kc`
//! ([`verify_mldsa_steps`]). Both halves are always checked: nothing is
//! accepted on one half.

use crate::device::{DeviceId, HybridKeys, IdentityKey, KeysCommitment, Signatory};
use crate::keys::decode_ed25519;
use crate::labels::{HYBRID_SIGNATURE_ED25519, HYBRID_SIGNATURE_MLDSA};
use crate::mldsa65::{self, Mldsa65Key};
use crate::primitives::sha256;
use crate::sizes::{ED25519_SIGNATURE, MLDSA65_PUBLIC, SCHEME2_SIGNATURE, XWING_PUBLIC};
use curve25519_dalek::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use frasil_base::ErrorClass;

/// A signature scheme a structure names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scheme {
    /// Scheme 0: Ed25519, verified strictly.
    Ed25519,
    /// Scheme 2: Ed25519 and ML-DSA-65 over the same bytes, both required.
    Hybrid,
}

/// The code of scheme 0, Ed25519.
pub const SCHEME_ED25519: u8 = 0;
/// The reserved code 1: refused as `UnsupportedVersion`.
pub const SCHEME_RESERVED: u8 = 1;
/// The code of scheme 2, Ed25519 and ML-DSA-65.
pub const SCHEME_HYBRID: u8 = 2;

impl Scheme {
    /// The scheme's code, as structures carry it.
    pub const fn code(self) -> u8 {
        match self {
            Self::Ed25519 => SCHEME_ED25519,
            Self::Hybrid => SCHEME_HYBRID,
        }
    }

    /// The scheme a code names.
    ///
    /// # Errors
    ///
    /// `UnsupportedVersion` for the reserved code 1 and every code but 0 and
    /// 2: a verifier never guesses.
    pub fn from_code(code: u64) -> Result<Self, ErrorClass> {
        match code {
            0 => Ok(Self::Ed25519),
            2 => Ok(Self::Hybrid),
            _ => Err(ErrorClass::UnsupportedVersion),
        }
    }

    /// Bytes of a signature under this scheme: 64, or 3,373.
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::Ed25519 => ED25519_SIGNATURE,
            Self::Hybrid => SCHEME2_SIGNATURE,
        }
    }
}

/// The schemes an event kind may carry (crypto.md, "Which structures carry
/// which scheme"). A verifier takes them from the kind alone, before it opens
/// any body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KindPolicy {
    /// Kinds that decide authority: device-list events (1), space events
    /// (2), anchors (5) and storage events (6). Scheme 2 only, before and
    /// after the sunset.
    Authority,
    /// Units (4) and the ignorable kinds (64 to 127): scheme 0 or 2; after
    /// the classical sunset a scheme-0 event counts only if it is covered.
    Open,
    /// A kind from 7 to 63, not yet defined: it states its schemes when it
    /// is defined, and one that decides authority takes scheme 2 only.
    /// Until then a replica refuses it as `UnknownKind` (events.md), after
    /// the scheme checks; they let scheme 0 or 2 through, so that the
    /// refusal is that one.
    Undefined,
}

impl KindPolicy {
    /// The policy of an event kind.
    ///
    /// # Errors
    ///
    /// `Malformed` for kind 0, kind 3 (reserved, never assigned) and kinds
    /// from 128 (events.md, "Kinds").
    pub fn for_kind(kind: u64) -> Result<Self, ErrorClass> {
        match kind {
            1 | 2 | 5 | 6 => Ok(Self::Authority),
            4 | 64..=127 => Ok(Self::Open),
            7..=63 => Ok(Self::Undefined),
            _ => Err(ErrorClass::Malformed),
        }
    }

    /// The schemes a verifier accepts on such an event. They are the same
    /// before and after the sunset; after it, a scheme-0 event must also be
    /// covered ([`KindPolicy::scheme_0_only_if_covered`]).
    pub fn accepted(self) -> &'static [Scheme] {
        match self {
            Self::Authority => &[Scheme::Hybrid],
            Self::Open | Self::Undefined => &[Scheme::Ed25519, Scheme::Hybrid],
        }
    }

    /// Whether, after the sunset, a scheme-0 event of this kind is accepted
    /// only if it is covered.
    pub fn scheme_0_only_if_covered(self) -> bool {
        !matches!(self, Self::Authority)
    }

    /// The scheme an honest client signs such an event with, before or after
    /// the sunset: scheme 0 only for a unit or an ignorable kind before it.
    pub fn signing_scheme(self, sunset: bool) -> Scheme {
        match self {
            Self::Open if !sunset => Scheme::Ed25519,
            _ => Scheme::Hybrid,
        }
    }
}

/// `m_ed`, what the Ed25519 half of a scheme-2 signature signs:
/// `"frasil/hybrid-signature/ed25519/v1" || ed_public || tbs`.
pub fn hybrid_ed25519_message(ed_public: &IdentityKey, tbs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HYBRID_SIGNATURE_ED25519.len() + 32 + tbs.len());
    message.extend_from_slice(HYBRID_SIGNATURE_ED25519);
    message.extend_from_slice(&ed_public.0);
    message.extend_from_slice(tbs);
    message
}

/// `m_ml`, what the ML-DSA-65 half signs; it binds both keys:
/// `"frasil/hybrid-signature/mldsa/v1" || ed_public || SHA-256(mldsa_public) || tbs`.
pub fn hybrid_mldsa_message(
    ed_public: &IdentityKey,
    mldsa_public: &[u8; MLDSA65_PUBLIC],
    tbs: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(HYBRID_SIGNATURE_MLDSA.len() + 64 + tbs.len());
    message.extend_from_slice(HYBRID_SIGNATURE_MLDSA);
    message.extend_from_slice(&ed_public.0);
    message.extend_from_slice(&sha256(&[mldsa_public]));
    message.extend_from_slice(tbs);
    message
}

/// A holder of keys that signs under scheme 0 and scheme 2: an Ed25519 seed
/// and an ML-DSA-65 seed, each with its public key, and its X-Wing key or
/// none, with the keys commitment and device ID they give (crypto.md, "A
/// device's keys").
pub struct Signer {
    /// The expanded Ed25519 key, zeroized on drop.
    ed_key: ed25519_dalek::SigningKey,
    ed_public: IdentityKey,
    mldsa: Mldsa65Key,
    keys: HybridKeys,
    device_id: DeviceId,
}

impl Signer {
    /// The signer of these two seeds, with its X-Wing public key, or `None`
    /// for a holder that has none (a recovery agent, an administrator
    /// pseudonym).
    pub fn from_seeds(
        ed_seed: &[u8; 32],
        mldsa_seed: &[u8; 32],
        xwing_public: Option<&[u8; XWING_PUBLIC]>,
    ) -> Self {
        let ed_key = ed25519_dalek::SigningKey::from_bytes(ed_seed);
        let ed_public = IdentityKey(ed_key.verifying_key().to_bytes());
        let mldsa = Mldsa65Key::from_seed(mldsa_seed);
        let keys = HybridKeys::from_checked(
            Box::new(*mldsa.public()),
            xwing_public.map(|key| Box::new(*key)),
        );
        let device_id = crate::device::device_id(&ed_public, keys.commitment());
        Self {
            ed_public,
            ed_key,
            mldsa,
            keys,
            device_id,
        }
    }

    /// The Ed25519 identity key, `ed`.
    pub fn identity_key(&self) -> &IdentityKey {
        &self.ed_public
    }

    /// The ML-DSA-65 public key.
    pub fn mldsa_public(&self) -> &[u8; MLDSA65_PUBLIC] {
        self.mldsa.public()
    }

    /// The ML-DSA-65 and X-Wing keys that `kc` commits to.
    pub fn keys(&self) -> &HybridKeys {
        &self.keys
    }

    /// The keys commitment, `kc`.
    pub fn kc(&self) -> &KeysCommitment {
        self.keys.commitment()
    }

    /// The device ID.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// `ed || kc`, what a structure outside an envelope carries for its
    /// signer.
    pub fn signatory(&self) -> Signatory {
        Signatory {
            ed: self.ed_public,
            kc: *self.kc(),
        }
    }

    /// Signs `tbs` under `scheme`: `Ed25519-Sign(seed, tbs)` for scheme 0;
    /// for scheme 2, both halves, ML-DSA-65 deterministically (`rnd` of 32
    /// zero bytes), so that one structure has one signed encoding.
    pub fn sign(&self, scheme: Scheme, tbs: &[u8]) -> Vec<u8> {
        match scheme {
            Scheme::Ed25519 => self.ed_sign(tbs).to_vec(),
            Scheme::Hybrid => self.sign_hybrid_with_rnd(tbs, &[0; 32]),
        }
    }

    /// `Ed25519-Sign(seed, message)`, with the key expanded once.
    fn ed_sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.ed_key.sign(message).to_bytes()
    }

    /// A scheme-2 signature whose ML-DSA-65 half is hedged with the caller's
    /// `rnd`, for a signer that must hedge against fault attacks. A verifier
    /// accepts both.
    pub fn sign_hybrid_with_rnd(&self, tbs: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
        let m_ed = hybrid_ed25519_message(&self.ed_public, tbs);
        let m_ml = hybrid_mldsa_message(&self.ed_public, self.mldsa.public(), tbs);
        let mut signature = Vec::with_capacity(SCHEME2_SIGNATURE);
        signature.extend_from_slice(&self.ed_sign(&m_ed));
        signature.extend_from_slice(&self.mldsa.sign_with_rnd(&m_ml, rnd));
        signature
    }
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signer")
            .field("device_id", &self.device_id)
            .field("ed", &self.ed_public)
            .finish_non_exhaustive()
    }
}

/// Strict Ed25519 verification (crypto.md, "Strict Ed25519 verification"):
/// whether `signature` is valid for `message` under `public`, in order:
///
/// 1. it is 64 bytes, `R || S`;
/// 2. `S < ℓ`;
/// 3. `R` decodes as `ed25519_valid`, step 2, says, and re-encodes to the
///    same bytes;
/// 4. neither `R` nor `A` is of small order;
/// 5. `[S]B − [k]A`, encoded, equals `R`, with `k = SHA-512(R || A || M)`:
///    the equation without the cofactor.
///
/// `public` has passed `ed25519_valid` already, where it entered. The
/// caller turns `false` into `BadSignature`, or the class its document names
/// for its proofs.
pub fn ed25519_verify_strict(public: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    crate::counts::ed25519_verify();
    let Ok(signature) = <&[u8; ED25519_SIGNATURE]>::try_from(signature) else {
        return false;
    };
    let (r, s) = signature.split_at(32);
    let s: [u8; 32] = s.try_into().expect("S is 32 bytes");
    if bool::from(Scalar::from_canonical_bytes(s).is_none()) {
        return false;
    }
    let r: &[u8; 32] = r.try_into().expect("R is 32 bytes");
    let Some(r_point) = decode_ed25519(r) else {
        return false;
    };
    if r_point.compress().as_bytes() != r {
        return false;
    }
    let Some(a_point) = decode_ed25519(public) else {
        return false;
    };
    if r_point.is_small_order() || a_point.is_small_order() {
        return false;
    }
    // ed25519-dalek's verify_strict checks steps 2 and 4 again, and computes
    // step 5 as stated.
    VerifyingKey::from_bytes(public).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// A signed structure, as the verifier reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<'a> {
    /// The scheme code the structure names: 0 when a map leaves key 9 out.
    pub scheme: u64,
    /// The signer's Ed25519 key, which passed `ed25519_valid` where it
    /// entered.
    pub ed: &'a IdentityKey,
    /// The signer's keys commitment, which names the ML-DSA-65 key that
    /// verifies the scheme-2 half.
    pub kc: &'a KeysCommitment,
    /// The signed bytes the structure's document defines.
    pub tbs: &'a [u8],
    /// The signature.
    pub signature: &'a [u8],
}

/// What the verifier holds when it verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Held<'a> {
    /// Keys the verifier holds for the signer's `kc`, from any source
    /// (crypto.md, "Where a verifier takes an ML-DSA-65 key"), or `None`.
    /// They are used only if their commitment is the signer's `kc`.
    pub keys: Option<&'a HybridKeys>,
    /// Whether the verifier is past the classical sunset.
    pub sunset: bool,
    /// Whether an event the verifier accepted under scheme 2 covers this one
    /// (crypto.md, "Anchors and coverage"). It matters only after the sunset.
    pub covered: bool,
}

/// `verify(kind, scheme, ed, kc, tbs, signature, keys, sunset, covered)`,
/// every step in order (crypto.md, "Verifying a signature").
///
/// # Errors
///
/// In the document's order: `UnsupportedVersion`, `SchemeNotAllowed`,
/// `Malformed`, `BadSignature` (the Ed25519 half), `NoHybridKey` (pending),
/// `BadSignature` (the ML-DSA-65 half) and `Uncovered` (pending).
pub fn verify(policy: KindPolicy, signed: &Signed<'_>, held: &Held<'_>) -> Result<(), ErrorClass> {
    let scheme = verify_ed25519_steps(policy, signed)?;
    if scheme == Scheme::Hybrid {
        verify_mldsa_steps(signed, held.keys)?;
    }
    check_coverage(policy, scheme, held.sunset, held.covered)
}

/// Steps 1 to 4 of `verify`, which need only the structure: the scheme, the
/// kind's schemes, the length, and the Ed25519 signature (scheme 0) or the
/// Ed25519 half (scheme 2). Returns the scheme.
///
/// # Errors
///
/// `UnsupportedVersion`, `SchemeNotAllowed`, `Malformed` or `BadSignature`,
/// in that order.
pub fn verify_ed25519_steps(policy: KindPolicy, signed: &Signed<'_>) -> Result<Scheme, ErrorClass> {
    // 1. A scheme this verifier knows.
    let scheme = Scheme::from_code(signed.scheme)?;
    // 2. A scheme the kind may carry.
    if !policy.accepted().contains(&scheme) {
        return Err(ErrorClass::SchemeNotAllowed);
    }
    // 3. The signature's length for the scheme.
    if signed.signature.len() != scheme.signature_bytes() {
        return Err(ErrorClass::Malformed);
    }
    // 4. Ed25519, strictly, with the signer's Ed25519 key alone.
    let valid = match scheme {
        Scheme::Ed25519 => ed25519_verify_strict(&signed.ed.0, signed.tbs, signed.signature),
        Scheme::Hybrid => ed25519_verify_strict(
            &signed.ed.0,
            &hybrid_ed25519_message(signed.ed, signed.tbs),
            &signed.signature[..ED25519_SIGNATURE],
        ),
    };
    if valid {
        Ok(scheme)
    } else {
        Err(ErrorClass::BadSignature)
    }
}

/// Steps 5 and 6 of `verify`, for a scheme-2 structure whose steps 1 to 4
/// passed: the verifier holds keys whose commitment is the signer's `kc`,
/// and the ML-DSA-65 half verifies over `m_ml` under their ML-DSA-65 key,
/// with an empty context.
///
/// # Errors
///
/// `NoHybridKey` if no keys are given, or the ones given hash to another
/// `kc`; `BadSignature` if the half does not verify; `Malformed` for a
/// signature that is not 3,373 bytes.
pub fn verify_mldsa_steps(
    signed: &Signed<'_>,
    keys: Option<&HybridKeys>,
) -> Result<(), ErrorClass> {
    if signed.signature.len() != SCHEME2_SIGNATURE {
        return Err(ErrorClass::Malformed);
    }
    // 5. An ML-DSA-65 key that, with an X-Wing key or none, hashes to kc.
    let keys = keys
        .filter(|keys| keys.commitment() == signed.kc)
        .ok_or(ErrorClass::NoHybridKey)?;
    let mldsa_public = keys.mldsa();
    // 6. ML-DSA-65 over m_ml, with an empty context.
    let m_ml = hybrid_mldsa_message(signed.ed, mldsa_public, signed.tbs);
    if mldsa65::verify(mldsa_public, &m_ml, &signed.signature[ED25519_SIGNATURE..]) {
        Ok(())
    } else {
        Err(ErrorClass::BadSignature)
    }
}

/// Step 7 of `verify`: after the sunset, a scheme-0 event counts only if it
/// is covered.
///
/// # Errors
///
/// `Uncovered`, pending until a covering event arrives.
pub fn check_coverage(
    policy: KindPolicy,
    scheme: Scheme,
    sunset: bool,
    covered: bool,
) -> Result<(), ErrorClass> {
    if sunset && scheme == Scheme::Ed25519 && policy.scheme_0_only_if_covered() && !covered {
        return Err(ErrorClass::Uncovered);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::from_seeds(&[1; 32], &[2; 32], None)
    }

    #[test]
    fn scheme_codes() {
        assert_eq!(Scheme::from_code(0), Ok(Scheme::Ed25519));
        assert_eq!(Scheme::from_code(2), Ok(Scheme::Hybrid));
        for code in [1, 3, 255, u64::MAX] {
            assert_eq!(Scheme::from_code(code), Err(ErrorClass::UnsupportedVersion));
        }
        assert_eq!(Scheme::Hybrid.code(), 2);
        assert_eq!(Scheme::Hybrid.signature_bytes(), 3373);
    }

    #[test]
    fn kinds() {
        for kind in [0, 3, 128, u64::MAX] {
            assert_eq!(KindPolicy::for_kind(kind), Err(ErrorClass::Malformed));
        }
        assert_eq!(KindPolicy::for_kind(7), Ok(KindPolicy::Undefined));
        assert_eq!(KindPolicy::for_kind(63), Ok(KindPolicy::Undefined));
        assert_eq!(KindPolicy::for_kind(127), Ok(KindPolicy::Open));
    }

    #[test]
    fn both_schemes_round_trip_and_scheme_2_is_deterministic() {
        let signer = signer();
        let held = Held {
            keys: Some(signer.keys()),
            sunset: false,
            covered: false,
        };
        for scheme in [Scheme::Ed25519, Scheme::Hybrid] {
            let signature = signer.sign(scheme, b"tbs");
            assert_eq!(signature, signer.sign(scheme, b"tbs"));
            let signed = Signed {
                scheme: u64::from(scheme.code()),
                ed: signer.identity_key(),
                kc: signer.kc(),
                tbs: b"tbs",
                signature: &signature,
            };
            assert_eq!(verify(KindPolicy::Open, &signed, &held), Ok(()));
        }
    }

    #[test]
    fn a_hedged_signature_verifies() {
        let signer = signer();
        let signature = signer.sign_hybrid_with_rnd(b"tbs", &[5; 32]);
        assert_ne!(signature, signer.sign(Scheme::Hybrid, b"tbs"));
        let signed = Signed {
            scheme: 2,
            ed: signer.identity_key(),
            kc: signer.kc(),
            tbs: b"tbs",
            signature: &signature,
        };
        let held = Held {
            keys: Some(signer.keys()),
            ..Held::default()
        };
        assert_eq!(verify(KindPolicy::Authority, &signed, &held), Ok(()));
    }

    #[test]
    fn the_ed25519_half_fails_as_scheme_0() {
        let signer = signer();
        let signature = signer.sign(Scheme::Hybrid, b"tbs");
        assert!(!ed25519_verify_strict(
            &signer.identity_key().0,
            b"tbs",
            &signature[..64]
        ));
    }
}
