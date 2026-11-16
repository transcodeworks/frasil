//! ML-DSA-65 (FIPS 204), as Frasil uses it (crypto.md, "Primitives").
//!
//! - A key pair is `ML-DSA.KeyGen_internal(xi)` (Algorithm 6) from a 32-byte
//!   seed `xi`. The seed is what is kept; the expanded secret key is derived
//!   when used.
//! - Signing is pure ML-DSA (Algorithm 2), never HashML-DSA, with an empty
//!   context: `M' = 0x00 || 0x00 || M`. A signer signs deterministically,
//!   with `rnd` set to 32 zero bytes ([`Mldsa65Key::sign`]); the hedged
//!   variant takes a caller's `rnd` ([`Mldsa65Key::sign_with_rnd`]).
//! - Verifying is Algorithm 3 with an empty context ([`verify`]).
//!
//! The arithmetic is RustCrypto's `ml-dsa`.

use crate::sizes::{MLDSA65_PUBLIC, MLDSA65_SEED, MLDSA65_SIGNATURE};
use ml_dsa::{ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};

/// `M'` for pure ML-DSA with an empty context: `0x00 || 0x00 || message`
/// (FIPS 204, Algorithm 2, with `ctx` empty).
pub fn message_prime(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(message);
    out
}

/// An ML-DSA-65 signing key, expanded from its seed.
pub struct Mldsa65Key {
    expanded: Box<ExpandedSigningKey<MlDsa65>>,
    public: Box<[u8; MLDSA65_PUBLIC]>,
}

impl Mldsa65Key {
    /// `ML-DSA.KeyGen_internal(xi)` from the 32-byte seed `xi`.
    pub fn from_seed(xi: &[u8; MLDSA65_SEED]) -> Self {
        let expanded = Box::new(ExpandedSigningKey::<MlDsa65>::from_seed(&(*xi).into()));
        let mut public = Box::new([0; MLDSA65_PUBLIC]);
        public.copy_from_slice(expanded.verifying_key().encode().as_slice());
        Self { expanded, public }
    }

    /// The public key, 1,952 bytes.
    pub fn public(&self) -> &[u8; MLDSA65_PUBLIC] {
        &self.public
    }

    /// `ML-DSA.Sign(sk, message, ctx = "")`, deterministic: `rnd` is 32 zero
    /// bytes, so that one message has one signature.
    pub fn sign(&self, message: &[u8]) -> [u8; MLDSA65_SIGNATURE] {
        self.sign_with_rnd(message, &[0; 32])
    }

    /// `ML-DSA.Sign(sk, message, ctx = "")` with the caller's `rnd`: the
    /// hedged variant, for a signer that must hedge against fault attacks.
    pub fn sign_with_rnd(&self, message: &[u8], rnd: &[u8; 32]) -> [u8; MLDSA65_SIGNATURE] {
        crate::counts::mldsa65_sign();
        let signature = self
            .expanded
            .sign_internal(&[&[0, 0], message], &(*rnd).into());
        let mut out = [0; MLDSA65_SIGNATURE];
        out.copy_from_slice(signature.encode().as_slice());
        out
    }
}

impl core::fmt::Debug for Mldsa65Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mldsa65Key")
            .field("public", &format_args!("{:02x?}…", &self.public[..8]))
            .finish_non_exhaustive()
    }
}

/// The ML-DSA-65 public key of a 32-byte seed.
pub fn public_from_seed(xi: &[u8; MLDSA65_SEED]) -> Box<[u8; MLDSA65_PUBLIC]> {
    Mldsa65Key::from_seed(xi).public
}

/// `ML-DSA.Verify(pk, message, signature, ctx = "")`. False for a key or a
/// signature of another length, and for a signature whose encoding does not
/// decode (FIPS 204, Algorithm 27, its hint check).
pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    crate::counts::mldsa65_verify();
    let (Ok(public), Ok(signature)) = (
        <&[u8; MLDSA65_PUBLIC]>::try_from(public),
        <&[u8; MLDSA65_SIGNATURE]>::try_from(signature),
    ) else {
        return false;
    };
    let Ok(signature) = Signature::<MlDsa65>::try_from(signature.as_slice()) else {
        return false;
    };
    let key = VerifyingKey::<MlDsa65>::decode(&(*public).into());
    key.verify_with_context(message, &[], &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_is_deterministic_and_verifies() {
        let key = Mldsa65Key::from_seed(&[1; 32]);
        let signature = key.sign(b"message");
        assert_eq!(signature, key.sign(b"message"));
        assert!(verify(key.public(), b"message", &signature));
        assert!(!verify(key.public(), b"other", &signature));
        assert!(!verify(&key.public()[1..], b"message", &signature));
        assert!(!verify(key.public(), b"message", &signature[1..]));
        assert_eq!(*public_from_seed(&[1; 32]), *key.public());
    }

    #[test]
    fn the_hedged_variant_also_verifies() {
        let key = Mldsa65Key::from_seed(&[2; 32]);
        let hedged = key.sign_with_rnd(b"message", &[9; 32]);
        assert_ne!(hedged, key.sign(b"message"));
        assert!(verify(key.public(), b"message", &hedged));
    }

    #[test]
    fn a_signature_with_a_context_does_not_verify_without_it() {
        let key = Mldsa65Key::from_seed(&[3; 32]);
        let mut with_context = message_prime(b"message");
        with_context[1] = 1;
        with_context.insert(2, b'x');
        let signature = key
            .expanded
            .sign_internal(&[&with_context], &[0; 32].into())
            .encode();
        assert!(!verify(key.public(), b"message", signature.as_slice()));
    }
}
