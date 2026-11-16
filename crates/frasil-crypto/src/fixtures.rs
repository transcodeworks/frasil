//! Test fixtures (crypto.md, "A device's keys").
//!
//! A device draws its three seeds, each independently, from its random
//! source, and MUST NOT derive one seed from another. Test fixtures are the
//! exception: they are built from an identity seed alone, so that vectors
//! and tests can name a device by one seed. Only tests use these
//! derivations.

use crate::device::{DeviceId, DeviceKeys, HybridKeys, IdentityKey};
use crate::labels::{DEVICE_HYBRID_SEED, DEVICE_MLDSA_SEED};
use crate::mldsa65;
use crate::primitives::{ed25519_public, sha256};
use crate::schemes::Signer;
use crate::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use crate::wrap::xwing_public;
use zeroize::Zeroizing;

/// A test fixture's X-Wing seed:
/// `SHA-256("frasil/device-hybrid-seed/v1" || identity seed)`.
pub fn fixture_xwing_seed(identity_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(sha256(&[DEVICE_HYBRID_SEED, identity_seed]))
}

/// A test fixture's ML-DSA-65 seed:
/// `SHA-256("frasil/device-mldsa-seed/v1" || identity seed)`.
pub fn fixture_mldsa_seed(identity_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(sha256(&[DEVICE_MLDSA_SEED, identity_seed]))
}

/// A test device's keys, built from its identity seed alone.
pub struct FixtureKeys {
    /// The identity seed.
    pub identity_seed: Zeroizing<[u8; 32]>,
    /// The Ed25519 identity key.
    pub identity: [u8; 32],
    /// The X-Wing seed, by [`fixture_xwing_seed`].
    pub xwing_seed: Zeroizing<[u8; 32]>,
    /// The X-Wing public key.
    pub xwing: Box<[u8; XWING_PUBLIC]>,
    /// The ML-DSA-65 seed, by [`fixture_mldsa_seed`].
    pub mldsa_seed: Zeroizing<[u8; 32]>,
    /// The ML-DSA-65 public key.
    pub mldsa_public: Box<[u8; MLDSA65_PUBLIC]>,
}

impl FixtureKeys {
    /// The device's three public keys.
    pub fn device_keys(&self) -> DeviceKeys {
        DeviceKeys {
            ed: IdentityKey(self.identity),
            keys: HybridKeys::from_checked(self.mldsa_public.clone(), Some(self.xwing.clone())),
        }
    }

    /// The device ID.
    pub fn device_id(&self) -> DeviceId {
        self.device_keys().device_id()
    }

    /// The device's signer.
    pub fn signer(&self) -> Signer {
        Signer::from_seeds(&self.identity_seed, &self.mldsa_seed, Some(&self.xwing))
    }
}

impl FixtureKeys {
    /// The keys of the test device whose identity seed this is.
    pub fn from_identity_seed(identity_seed: &[u8; 32]) -> Self {
        let xwing_seed = fixture_xwing_seed(identity_seed);
        let mldsa_seed = fixture_mldsa_seed(identity_seed);
        Self {
            identity_seed: Zeroizing::new(*identity_seed),
            identity: ed25519_public(identity_seed),
            xwing: Box::new(xwing_public(&xwing_seed)),
            xwing_seed,
            mldsa_public: mldsa65::public_from_seed(&mldsa_seed),
            mldsa_seed,
        }
    }
}

impl core::fmt::Debug for FixtureKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FixtureKeys")
            .field("identity", &format_args!("{:02x?}", self.identity))
            .finish_non_exhaustive()
    }
}
