//! Objects at the peer (peers.md, "Objects"; units.md, "Objects";
//! transport.md, "The server binding").
//!
//! The peer stores an object by its locator, the object ID and the SHA-256
//! of its stored bytes:
//!
//! ```text
//! object = u32be(len(header)) || header || chunk_0 || ... || chunk_(n−1)
//! ```
//!
//! It keeps the stored bytes as **pieces** of 1,048,576 bytes, the server
//! binding's chunk route's unit: piece `i` is bytes `i·1,048,576` onward.
//! Piece 0 holds the header, from which the peer learns the stored length,
//! so it knows the last piece. Units.md's `ObjectChunks` and `ObjectWant`
//! name sealed chunks; the peer maps them onto the same bytes.

use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
use frasil_units::objects::{Header, chunk_count};

/// A piece's size: the server binding's largest body.
pub const PIECE_BYTES: usize = 1_048_576;

/// A nonce and a tag: what sealing adds to each chunk.
const CHUNK_OVERHEAD: u64 = (SEALED_CHUNK_BYTES - CHUNK_BYTES) as u64;

/// What piece 0 shows: the header's place and the stored length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    /// `4 + len(header)`: where chunk 0 starts.
    pub start: u64,
    /// The header's bytes.
    pub header: Vec<u8>,
    /// The stored object's length.
    pub total: u64,
    /// The count of sealed chunks.
    pub chunks: u64,
    /// The plaintext's length.
    pub size: u64,
}

impl Layout {
    /// Reads piece 0's front: the header's length, the header (units.md,
    /// "Reading an object", steps 1 to 3), and from its size the stored
    /// length.
    pub(crate) fn read(front: &[u8], locator: &[u8; 64]) -> Option<Self> {
        let (length, rest) = front.split_first_chunk::<4>()?;
        let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
        let header_bytes = rest.get(..length)?;
        let header = Header::read(header_bytes).ok()?;
        if header.object_id[..] != locator[..32] {
            return None;
        }
        let chunks = chunk_count(header.size, CHUNK_BYTES as u64);
        let start = 4 + length as u64;
        let total = start
            .checked_add(header.size)?
            .checked_add(chunks.checked_mul(CHUNK_OVERHEAD)?)?;
        Some(Self {
            start,
            header: header_bytes.to_vec(),
            total,
            chunks,
            size: header.size,
        })
    }

    /// How many pieces the stored object takes.
    #[cfg(test)]
    pub(crate) fn pieces(&self) -> u64 {
        pieces_of(self.total)
    }

    /// Sealed chunk `index`'s byte range in the stored object.
    pub(crate) fn chunk_range(&self, index: u64) -> Option<(u64, u64)> {
        if index >= self.chunks {
            return None;
        }
        let from = self.start + index * SEALED_CHUNK_BYTES as u64;
        let plain = (CHUNK_BYTES as u64).min(self.size - index * CHUNK_BYTES as u64);
        Some((from, from + plain + CHUNK_OVERHEAD))
    }

    /// The count of leading sealed chunks within the first `held` bytes.
    pub(crate) fn chunks_within(&self, held: u64) -> u64 {
        (0..self.chunks)
            .take_while(|&i| self.chunk_range(i).is_some_and(|(_, end)| end <= held))
            .count() as u64
    }
}

/// How many pieces a stored object of `total` bytes takes.
pub(crate) fn pieces_of(total: u64) -> u64 {
    total.div_ceil(PIECE_BYTES as u64).max(1)
}

/// The expected length of piece `index` of a stored object of `total`
/// bytes.
pub(crate) fn piece_length(total: u64, index: u64) -> Option<u64> {
    let from = index.checked_mul(PIECE_BYTES as u64)?;
    if from >= total && !(total == 0 && index == 0) {
        return None;
    }
    Some((total - from).min(PIECE_BYTES as u64))
}

/// The count of leading pieces held.
pub(crate) fn leading(pieces: &std::collections::BTreeSet<u64>) -> u64 {
    (0..).take_while(|i| pieces.contains(i)).count() as u64
}

/// A piece's key in the object store:
/// `<space hex>/<locator hex>/<index>`.
pub(crate) fn piece_key(space: &[u8; 32], locator: &[u8; 64], index: u64) -> String {
    use frasil_base::notation::hex::encode;
    format!("{}/{}/{index}", encode(space), encode(locator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_units::objects::Header;

    fn front(size: u64, id: [u8; 32]) -> Vec<u8> {
        let header = Header {
            object_id: id,
            key_reference: frasil_keys::RotationSet::single(frasil_events::EventId([1; 32]))
                .encode(),
            size,
        }
        .encode();
        let mut out = (header.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&header);
        out
    }

    #[test]
    fn a_layout_follows_the_object_format() {
        let mut locator = [0u8; 64];
        locator[..32].copy_from_slice(&[9; 32]);
        let small = Layout::read(&front(10, [9; 32]), &locator).unwrap();
        assert_eq!(small.chunks, 1);
        assert_eq!(small.total, small.start + 10 + 40);
        assert_eq!(small.pieces(), 1);
        assert_eq!(small.chunk_range(0), Some((small.start, small.total)));
        assert_eq!(small.chunks_within(small.total), 1);
        let empty = Layout::read(&front(0, [9; 32]), &locator).unwrap();
        assert_eq!(empty.chunks, 1);
        assert_eq!(empty.total, empty.start + 40);
        let big = Layout::read(&front(CHUNK_BYTES as u64 + 1, [9; 32]), &locator).unwrap();
        assert_eq!(big.chunks, 2);
        assert_eq!(big.pieces(), 2);
        assert_eq!(
            big.chunk_range(1).unwrap().1,
            big.total,
            "the last chunk ends the object"
        );
        assert!(Layout::read(&front(10, [8; 32]), &locator).is_none());
        assert_eq!(piece_length(PIECE_BYTES as u64 + 5, 1), Some(5));
        assert_eq!(piece_length(PIECE_BYTES as u64 + 5, 2), None);
    }

    #[test]
    fn a_checkpoints_record_object_lays_out_as_any_object() {
        // Its header names the checkpoint by a self reference (roster.md,
        // "The record object"): the peer reads either form.
        let own = frasil_keys::SelfRef::new(frasil_crypto::device::DeviceId([2; 32]), 7);
        let sealed = frasil_units::record::seal_record(
            &frasil_events::EventId([5; 32]),
            &[6; 32],
            own,
            &vec![1; CHUNK_BYTES + 3],
        )
        .unwrap();
        let bytes = &sealed.object.bytes;
        let layout = Layout::read(bytes, &sealed.binding.locator).unwrap();
        assert_eq!(layout.total, bytes.len() as u64);
        assert_eq!(layout.chunks, 2);
        assert_eq!(layout.size, sealed.binding.size);
    }
}
