//! The credential proof (peers.md, "The credential proof").
//!
//! A device presents a credential in transport.md's `Present` message.
//! `presented` is that document's: the connection's `binding` (a hash of the
//! channel binding, both hellos' nonces and the purpose), the space, the
//! credential and its public half.
//!
//! ```text
//! presented = field(binding) || field(space) || u8(credential) || field(public)
//! proof     = Ed25519-Sign(seed, "frasil/storage-proof/v1" || presented)        64 bytes
//! ```
//!
//! The proof is scheme 0, verified once, at once. A peer keeps no nonce
//! store: a proof holds for its connection while the connection lasts.

use frasil_base::notation::push_field;
use frasil_crypto::labels::STORAGE_PROOF;
use frasil_crypto::primitives::ed25519_sign;
use frasil_crypto::schemes::ed25519_verify_strict;

/// Which credential a present proves (peers.md, "The credential proof").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Credential {
    /// 1: a read credential, the seed `read_seed(state)`.
    Read,
    /// 2: an upload key, the seed `upload_seed(state)`.
    Upload,
    /// 3: an administrator pseudonym, its Ed25519 seed.
    Pseudonym,
    /// 4: a fetch key, the fetch seed (identity.md).
    Fetch,
}

impl Credential {
    /// The credential's code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Upload => 2,
            Self::Pseudonym => 3,
            Self::Fetch => 4,
        }
    }

    /// The credential of a code, 1 to 4.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Read),
            2 => Some(Self::Upload),
            3 => Some(Self::Pseudonym),
            4 => Some(Self::Fetch),
            _ => None,
        }
    }
}

/// A connection's purpose (transport.md, "Presenting credentials").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// 1: space traffic, which presents read credentials, upload keys and
    /// fetch keys.
    SpaceTraffic,
    /// 2: administration, which presents one administrator pseudonym.
    Administration,
}

impl Purpose {
    /// The purpose's code.
    pub const fn code(self) -> u8 {
        match self {
            Self::SpaceTraffic => 1,
            Self::Administration => 2,
        }
    }

    /// Whether a connection of this purpose may present the credential.
    pub fn allows(self, credential: Credential) -> bool {
        match self {
            Self::SpaceTraffic => credential != Credential::Pseudonym,
            Self::Administration => credential == Credential::Pseudonym,
        }
    }
}

/// transport.md's `presented`:
/// `field(binding) || field(space) || u8(credential) || field(public)`.
pub fn presented(binding: &[u8; 32], space: &[u8; 32], credential: u8, public: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 4 + 32 + 1 + 4 + public.len());
    push_field(&mut out, binding);
    push_field(&mut out, space);
    out.push(credential);
    push_field(&mut out, public);
    out
}

/// What the proof signs: `"frasil/storage-proof/v1" || presented`.
pub fn proof_message(presented: &[u8]) -> Vec<u8> {
    [STORAGE_PROOF, presented].concat()
}

/// The proof of a credential's seed over a connection's `presented`.
pub fn prove(seed: &[u8; 32], presented: &[u8]) -> [u8; 64] {
    ed25519_sign(seed, &proof_message(presented))
}

/// Whether a proof verifies, strictly, under the credential's public half.
/// `public` passed `ed25519_valid` where it entered the peer.
pub fn verify(public: &[u8; 32], presented: &[u8], proof: &[u8]) -> bool {
    ed25519_verify_strict(public, &proof_message(presented), proof)
}
