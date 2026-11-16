//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's primitives, key checks, the X-Wing wrap and signature schemes.
//!
//! Specified by `docs/spec/crypto.md`, sections 2 (Formats) and
//! 3 (Procedures). Its vectors are `docs/spec/vectors/crypto.json`, all but
//! `coverage`.
//!
//! - [`primitives`]: SHA-256, HMAC-SHA256, HKDF-SHA256, XChaCha20-Poly1305
//!   and Ed25519 signing.
//! - [`mldsa65`]: ML-DSA-65 keys from a seed, pure signing with an empty
//!   context, and verifying.
//! - [`device`]: a device's keys commitment and device ID, and the types
//!   that keep an Ed25519 key, a keys commitment and a device ID apart.
//! - [`keys`]: the checks every public key passes where it enters.
//! - [`wrap`]: X-Wing keys, HPKE with X-Wing, and the X-Wing wrap.
//! - [`schemes`]: signature schemes 0 and 2, strict Ed25519 verification,
//!   and which event kinds carry which scheme.
//! - [`labels`]: the label registry.
//! - [`fixtures`]: the test fixtures' key derivations.
//! - [`sizes`]: the sizes of keys, signatures and AEAD parts.
//!
//! The crate does no IO and draws no randomness inside a procedure: every
//! function that needs random bytes takes them as an argument (a `_with`
//! form), so that vectors can drive it. A caller draws them with
//! [`random_bytes`], which refuses when the platform has no working source.
//! Errors are the shared error classes of `frasil-base`.

#[doc(hidden)]
pub mod counts;
pub mod device;
pub mod fixtures;
pub mod keys;
pub mod labels;
pub mod mldsa65;
pub mod primitives;
pub mod schemes;
pub mod wrap;

pub use frasil_base::ErrorClass;

/// The sizes of keys, signatures and AEAD parts, in bytes (crypto.md,
/// "Sizes").
pub mod sizes {
    /// An Ed25519 seed.
    pub const ED25519_SEED: usize = 32;
    /// An Ed25519 public key.
    pub const ED25519_PUBLIC: usize = 32;
    /// An Ed25519 signature.
    pub const ED25519_SIGNATURE: usize = 64;
    /// An X-Wing seed.
    pub const XWING_SEED: usize = 32;
    /// An X-Wing public key: the ML-KEM-768 encapsulation key (1,184) then
    /// the X25519 public key (32).
    pub const XWING_PUBLIC: usize = 1216;
    /// An X-Wing ciphertext, HPKE's `enc`: the ML-KEM-768 ciphertext (1,088)
    /// then the X25519 one (32).
    pub const XWING_ENC: usize = 1120;
    /// An ML-DSA-65 seed.
    pub const MLDSA65_SEED: usize = 32;
    /// An ML-DSA-65 public key.
    pub const MLDSA65_PUBLIC: usize = 1952;
    /// An ML-DSA-65 expanded secret key.
    pub const MLDSA65_SECRET_EXPANDED: usize = 4032;
    /// An ML-DSA-65 signature.
    pub const MLDSA65_SIGNATURE: usize = 3309;
    /// A scheme-2 signature: the Ed25519 half then the ML-DSA-65 half.
    pub const SCHEME2_SIGNATURE: usize = ED25519_SIGNATURE + MLDSA65_SIGNATURE;
    /// An XChaCha20-Poly1305 nonce.
    pub const XCHACHA20POLY1305_NONCE: usize = 24;
    /// An XChaCha20-Poly1305 tag.
    pub const XCHACHA20POLY1305_TAG: usize = 16;
}

/// The platform has no working source of randomness. An implementation
/// without one MUST refuse to generate keys, seal or wrap (crypto.md,
/// "Primitives").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRandomness;

impl core::fmt::Display for NoRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the platform has no working source of randomness")
    }
}

impl std::error::Error for NoRandomness {}

/// `N` bytes from the operating system's cryptographically secure source:
/// `getrandom`, which on `wasm32-unknown-unknown` is the JavaScript host's
/// `crypto.getRandomValues`.
///
/// # Errors
///
/// [`NoRandomness`] if the source fails or the host has none. Never weaker
/// bytes, and never a panic.
pub fn random_bytes<const N: usize>() -> Result<zeroize::Zeroizing<[u8; N]>, NoRandomness> {
    let mut bytes = zeroize::Zeroizing::new([0u8; N]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|_| NoRandomness)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn random_bytes_differ() {
        let first = super::random_bytes::<32>().unwrap();
        let second = super::random_bytes::<32>().unwrap();
        assert_ne!(*first, *second);
    }
}
