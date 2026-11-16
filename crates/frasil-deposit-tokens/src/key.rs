//! Deposit keys and key IDs (ext-deposit-tokens.md, 2.2 Deposit keys).
//!
//! ```text
//! seed         = 32 random bytes, drawn by the peer for each key
//! (skS, pkS)   = DeriveKeyPair(seed, "frasil/deposit-key/v1")
//! public key   = SerializeElement(pkS)                                     32 bytes
//! key ID       = SHA-256("frasil/deposit-key/v1" || public key)            32 bytes
//! ```

use core::fmt;

use frasil_crypto::labels::DEPOSIT_KEY;
use frasil_crypto::primitives::sha256;
use frasil_crypto::{NoRandomness, random_bytes};
use voprf::VoprfServer;
use zeroize::Zeroizing;

use crate::suite::{self, ELEMENT_BYTES, Element, PROOF_BYTES, SCALAR_BYTES, Suite, SuiteError};

/// The bytes of a key ID.
pub const KEY_ID_BYTES: usize = 32;

/// The bytes of a deposit key's seed.
pub const SEED_BYTES: usize = 32;

/// A key ID: `SHA-256("frasil/deposit-key/v1" || public key)`.
pub type KeyId = [u8; KEY_ID_BYTES];

/// The key ID of a public key.
pub fn key_id(public: &[u8; ELEMENT_BYTES]) -> KeyId {
    sha256(&[DEPOSIT_KEY, public])
}

/// A key's role in a peer's key list (ext-deposit-tokens.md, 2.5 Messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// 1: the key the peer issues under.
    Issuing,
    /// 2: a key whose tokens the peer still accepts, and no longer issues
    /// under.
    Accepting,
}

impl Role {
    /// The role's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Issuing => 1,
            Self::Accepting => 2,
        }
    }

    /// The role of a code, 1 or 2.
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Issuing),
            2 => Some(Self::Accepting),
            _ => None,
        }
    }
}

/// A peer's deposit key: its seed, which it keeps until the key retires,
/// the VOPRF key `DeriveKeyPair` gives, the public key and the key ID. The
/// seed and the secret scalar are zeroized when the key is dropped.
#[derive(Clone)]
pub struct DepositKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    server: VoprfServer<Suite>,
    public: [u8; ELEMENT_BYTES],
    id: KeyId,
}

impl fmt::Debug for DepositKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DepositKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl DepositKey {
    /// The key of a seed.
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        // The info is the fixed label: DeriveKeyPair cannot refuse it, and
        // fails only after 256 zero scalars in a row.
        let server = suite::derive_key_pair(seed, DEPOSIT_KEY)
            .unwrap_or_else(|_| unreachable!("DeriveKeyPair refused a fixed info"));
        let public = suite::public_key(&server);
        Self {
            seed: Zeroizing::new(*seed),
            server,
            public,
            id: key_id(&public),
        }
    }

    /// A key from a seed the platform draws.
    ///
    /// # Errors
    ///
    /// [`NoRandomness`] when the platform has no working source.
    pub fn generate() -> Result<Self, NoRandomness> {
        Ok(Self::from_seed(&*random_bytes::<SEED_BYTES>()?))
    }

    /// The seed, which the peer keeps, sealed, until the key retires.
    pub fn seed(&self) -> &[u8; SEED_BYTES] {
        &self.seed
    }

    /// The public key, `SerializeElement(pkS)`.
    pub fn public(&self) -> &[u8; ELEMENT_BYTES] {
        &self.public
    }

    /// The key ID.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// The secret scalar `skS`, serialized: only for tests that compare it
    /// with a vector.
    pub fn secret(&self) -> Zeroizing<[u8; SCALAR_BYTES]> {
        let mut out = Zeroizing::new([0; SCALAR_BYTES]);
        // `VoprfServer` serializes as skS || pkS.
        out.copy_from_slice(&self.server.serialize()[..SCALAR_BYTES]);
        out
    }

    /// Evaluates a batch of blinded elements with one proof, its random
    /// scalar given (ext-deposit-tokens.md, 2.1 The VOPRF).
    ///
    /// # Errors
    ///
    /// As [`suite::evaluate_batch_with`].
    pub fn evaluate_batch_with(
        &self,
        blinded: &[[u8; ELEMENT_BYTES]],
        proof_scalar: &[u8; SCALAR_BYTES],
    ) -> Result<(Vec<[u8; ELEMENT_BYTES]>, [u8; PROOF_BYTES]), SuiteError> {
        suite::evaluate_batch_with(&self.server, blinded, proof_scalar)
    }

    /// `Evaluate(skS, input)`, the authenticator of a token's input.
    ///
    /// # Errors
    ///
    /// As [`suite::evaluate`].
    pub fn evaluate(
        &self,
        input: &[u8],
    ) -> Result<Zeroizing<[u8; suite::OUTPUT_BYTES]>, SuiteError> {
        suite::evaluate(&self.server, input)
    }

    /// Whether an authenticator equals `Evaluate(skS, input)`, compared in
    /// constant time.
    pub fn verify(&self, input: &[u8], authenticator: &[u8]) -> bool {
        suite::verify(&self.server, input, authenticator)
    }
}

/// A peer's key as a device holds it, after section 3.2's checks: its ID,
/// its public key and the element it decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerKey {
    /// The key ID.
    pub id: KeyId,
    /// The public key.
    pub public: [u8; ELEMENT_BYTES],
    /// The role the list gives it.
    pub role: Role,
    pub(crate) element: Element,
}

impl PeerKey {
    /// The element `pkS`.
    pub fn element(&self) -> Element {
        self.element
    }
}
