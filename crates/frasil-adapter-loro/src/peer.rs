//! Peer IDs (adapter-loro.md, section 2.3, "Peer IDs").
//!
//! ```text
//! peer(space, stream, author, s) =
//!     (SHA-256("frasil/loro-peer/v1" || space || stream || author || u64be(s))[0..8]
//!      read as a big-endian unsigned integer) mod (2^64 − 1)
//! ```
//!
//! `author` is the writer's device ID (events.md, "The envelope"). The
//! reduction keeps the peer ID below 2^64 − 1, which Loro reserves.

use frasil_adapter::{Author, SpaceId, StreamId};
use frasil_crypto::labels::LORO_PEER;
use frasil_crypto::primitives::sha256;

/// A Loro peer ID.
pub type PeerId = loro::PeerID;

/// A peer ID with the values that give it, as the vectors list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerDerivation {
    /// The SHA-256 digest.
    pub digest: [u8; 32],
    /// Its first 8 bytes, read as a big-endian unsigned integer.
    pub first_8: u64,
    /// The peer ID: `first_8 mod (2^64 − 1)`.
    pub peer: PeerId,
}

/// Derives the peer ID of a writer's incarnation `s` in a stream.
pub fn derive(space: &SpaceId, stream: &StreamId, author: &Author, s: u64) -> PeerDerivation {
    let digest = sha256(&[LORO_PEER, space, stream, author, &s.to_be_bytes()]);
    let mut first = [0; 8];
    first.copy_from_slice(&digest[..8]);
    let first_8 = u64::from_be_bytes(first);
    PeerDerivation {
        digest,
        first_8,
        peer: first_8 % u64::MAX,
    }
}

/// `peer(space, stream, author, s)`.
pub fn peer(space: &SpaceId, stream: &StreamId, author: &Author, s: u64) -> PeerId {
    derive(space, stream, author, s).peer
}

/// One incarnation of one writer in one stream: what binds its peer ID
/// (adapter-loro.md, section 3.1, "Writing").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Incarnation {
    /// The space ID.
    pub space: SpaceId,
    /// The stream.
    pub stream: StreamId,
    /// The writer's device ID.
    pub author: Author,
    /// The incarnation: the `seq` of the unit that began it, at least 1.
    pub incarnation: u64,
}

impl Incarnation {
    /// The incarnation's peer ID.
    pub fn peer(&self) -> PeerId {
        peer(&self.space, &self.stream, &self.author, self.incarnation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reduction_keeps_the_reserved_peer_out() {
        let derived = derive(&[1; 32], &[2; 16], &[3; 32], 4);
        assert_eq!(derived.peer, derived.first_8 % u64::MAX);
        assert!(derived.peer < u64::MAX);
        assert_ne!(
            peer(&[1; 32], &[2; 16], &[3; 32], 4),
            peer(&[1; 32], &[2; 16], &[3; 32], 5)
        );
    }
}
