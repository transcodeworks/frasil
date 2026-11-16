//! LZ4 frames as the pinned Loro's key-value store writes them
//! (adapter-loro.md, 3.5 Compaction and history-free export, "Loading a
//! state").
//!
//! `loro-kv-store` 1.17.0 compresses a block with `lz4_flex` 0.11.6's
//! `FrameEncoder::new`, the default frame: independent blocks, no block or
//! content checksum, no content size, no dictionary, one frame with its end
//! mark. It decompresses with `io::copy` from a `FrameDecoder`, into a
//! vector with no bound, and only then checks what it read; a block it
//! cannot decompress makes it panic when it reads the block lazily
//! (`Block::decode`, "validated SSTable block should decode").
//!
//! [`frame`] reads exactly the frames that encoder writes, as the decoder
//! reads them, and refuses anything the decoder would refuse. It counts
//! every byte before it writes it, so it never holds more than the limit it
//! is given.

/// A frame the screen refuses.
#[derive(Debug)]
pub(crate) struct Refused;

/// The frame's magic number, little-endian (`LZ4F_MAGIC_NUMBER`).
const MAGIC: [u8; 4] = 0x184D_2204u32.to_le_bytes();
/// The frame descriptor's flags as the default encoder writes them:
/// version 01 and independent blocks, nothing else (`FrameInfo::write`).
const FLAGS: u8 = 0b0110_0000;
/// A block size field whose high bit says the block is stored as it is.
const STORED: u32 = 0x8000_0000;
/// The shortest match (`MINMATCH`).
const MIN_MATCH: usize = 4;

/// Decompresses one LZ4 frame, appending what it holds to `out`, or only
/// counts it when `out` is `None`; returns its length. Refuses the frame
/// when `lz4_flex`'s `FrameDecoder` would fail on it, when it is not laid
/// out as `FrameEncoder::new` writes one, or when it holds more than
/// `limit` bytes.
pub(crate) fn frame(
    input: &[u8],
    out: Option<&mut Vec<u8>>,
    limit: usize,
) -> Result<usize, Refused> {
    // Magic, flags, block descriptor, header checksum.
    if input.len() < 7 || input[..4] != MAGIC || input[4] != FLAGS {
        return Err(Refused);
    }
    // `FrameInfo::read`: the reserved bits are 0, and the size code is 4
    // to 7 (64 KiB to 4 MiB).
    let descriptor = input[5];
    if descriptor & 0b1000_1111 != 0 || descriptor >> 4 < 4 {
        return Err(Refused);
    }
    let max_block = 1usize << (8 + 2 * usize::from(descriptor >> 4));
    // The header checksum: the second byte of xxHash32 of the flags and
    // the descriptor.
    if input[6] != (xxh32(&input[4..6], 0) >> 8) as u8 {
        return Err(Refused);
    }
    let mut out = Out {
        buf: out,
        len: 0,
        limit,
    };
    let mut rest = &input[7..];
    loop {
        let Some((size, after)) = rest.split_first_chunk::<4>() else {
            // `FrameDecoder` ends the frame silently where the bytes end
            // before an end mark; the encoder always writes one.
            return Err(Refused);
        };
        let size = u32::from_le_bytes(*size);
        rest = after;
        if size == 0 {
            // The end mark, then nothing: the encoder writes one frame.
            return if rest.is_empty() {
                Ok(out.len)
            } else {
                Err(Refused)
            };
        }
        let stored = size & STORED != 0;
        let len = (size & !STORED) as usize;
        if len > max_block || len > rest.len() {
            return Err(Refused);
        }
        let (data, after) = rest.split_at(len);
        rest = after;
        if stored {
            out.literals(data)?;
        } else {
            block(data, &mut out, max_block)?;
        }
    }
}

/// Where a frame decompresses to: a vector, or only a count.
struct Out<'a> {
    buf: Option<&'a mut Vec<u8>>,
    /// The bytes decompressed so far.
    len: usize,
    /// The most there may be.
    limit: usize,
}

impl Out<'_> {
    /// Takes `n` more bytes, within the limit.
    fn grow(&mut self, n: usize) -> Result<(), Refused> {
        match self.len.checked_add(n) {
            Some(len) if len <= self.limit => {
                self.len = len;
                Ok(())
            }
            _ => Err(Refused),
        }
    }

    fn literals(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        self.grow(bytes.len())?;
        if let Some(buf) = self.buf.as_deref_mut() {
            buf.extend_from_slice(bytes);
        }
        Ok(())
    }

    /// `length` bytes, each copied from `offset` before it.
    fn copy(&mut self, offset: usize, length: usize) -> Result<(), Refused> {
        self.grow(length)?;
        if let Some(buf) = self.buf.as_deref_mut() {
            // In runs of at most `offset` bytes, every one already there.
            let mut from = buf.len() - offset;
            let mut left = length;
            while left > 0 {
                let n = left.min(offset);
                buf.extend_from_within(from..from + n);
                from += n;
                left -= n;
            }
        }
        Ok(())
    }
}

/// One compressed block, as `decompress_internal` reads it without a
/// dictionary, into an output of `max_block` bytes: sequences of a token,
/// literals, an offset and a match, the last one literals only.
fn block(src: &[u8], out: &mut Out<'_>, max_block: usize) -> Result<(), Refused> {
    // What this block has decompressed to so far: the blocks are
    // independent, so a match reaches no further back.
    let mut produced = 0usize;
    let mut at = 0;
    // `read_integer`: a run of 255s and the byte that ends it, summed.
    let integer = |at: &mut usize| -> Result<usize, Refused> {
        let mut n = 0usize;
        loop {
            let byte = *src.get(*at).ok_or(Refused)?;
            *at += 1;
            n += usize::from(byte);
            if byte != 0xff {
                return Ok(n);
            }
        }
    };
    loop {
        let token = *src.get(at).ok_or(Refused)?;
        at += 1;
        let mut literals = usize::from(token >> 4);
        if literals == 15 {
            literals += integer(&mut at)?;
        }
        if literals > src.len() - at || produced + literals > max_block {
            return Err(Refused);
        }
        out.literals(&src[at..at + literals])?;
        produced += literals;
        at += literals;
        if at >= src.len() {
            return Ok(());
        }
        let offset = src.get(at..at + 2).ok_or(Refused)?;
        let offset = usize::from(u16::from_le_bytes([offset[0], offset[1]]));
        at += 2;
        // `OffsetZero`, and `OffsetOutOfBounds` before this block's start.
        if offset == 0 || offset > produced {
            return Err(Refused);
        }
        let mut length = MIN_MATCH + usize::from(token & 0x0f);
        if token & 0x0f == 0x0f {
            length += integer(&mut at)?;
        }
        if produced + length > max_block {
            return Err(Refused);
        }
        out.copy(offset, length)?;
        produced += length;
    }
}

/// xxHash32 of `input` with `seed`.
pub(crate) fn xxh32(input: &[u8], seed: u32) -> u32 {
    const P1: u32 = 0x9E37_79B1;
    const P2: u32 = 0x85EB_CA77;
    const P3: u32 = 0xC2B2_AE3D;
    const P4: u32 = 0x27D4_EB2F;
    const P5: u32 = 0x1656_67B1;
    let word = |bytes: &[u8]| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let round = |acc: u32, lane: u32| {
        acc.wrapping_add(lane.wrapping_mul(P2))
            .rotate_left(13)
            .wrapping_mul(P1)
    };
    let mut rest = input;
    let mut hash = if input.len() >= 16 {
        let mut lanes = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        while rest.len() >= 16 {
            for (i, lane) in lanes.iter_mut().enumerate() {
                *lane = round(*lane, word(&rest[4 * i..]));
            }
            rest = &rest[16..];
        }
        lanes[0]
            .rotate_left(1)
            .wrapping_add(lanes[1].rotate_left(7))
            .wrapping_add(lanes[2].rotate_left(12))
            .wrapping_add(lanes[3].rotate_left(18))
    } else {
        seed.wrapping_add(P5)
    };
    hash = hash.wrapping_add(input.len() as u32);
    while rest.len() >= 4 {
        hash = hash
            .wrapping_add(word(rest).wrapping_mul(P3))
            .rotate_left(17)
            .wrapping_mul(P4);
        rest = &rest[4..];
    }
    for byte in rest {
        hash = hash
            .wrapping_add(u32::from(*byte).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(P3);
    hash ^ (hash >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame of one compressed block, as the default encoder writes it
    /// for an input of up to 64 KiB.
    fn framed(block: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[FLAGS, 0x40]);
        out.push((xxh32(&[FLAGS, 0x40], 0) >> 8) as u8);
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(block);
        out.extend_from_slice(&[0; 4]);
        out
    }

    #[test]
    fn xxh32_matches_known_values() {
        assert_eq!(xxh32(b"", 0), 0x02CC_5D05);
        assert_eq!(xxh32(b"abc", 0), 0x32D1_53FF);
    }

    #[test]
    fn reads_literals_and_overlapping_matches() {
        // "ab", then a match of 6 at offset 2, then a literal "c".
        let block = [0x22, b'a', b'b', 2, 0, 0x10, b'c'];
        let mut out = Vec::new();
        assert_eq!(frame(&framed(&block), Some(&mut out), 1 << 20).unwrap(), 9);
        assert_eq!(out, b"ababababc");
    }

    #[test]
    fn refuses_what_the_decoder_refuses_or_the_limit_forbids() {
        // An offset of 0, and one before the block.
        for block in [[0x10, b'a', 0, 0, 0x00], [0x10, b'a', 2, 0, 0x00]] {
            assert!(frame(&framed(&block), None, 1 << 20).is_err());
        }
        // A match that ends the block: the last sequence is literals.
        assert!(frame(&framed(&[0x10, b'a', 1, 0]), None, 1 << 20).is_err());
        // A match of 4 + 15 + 255 * 200 bytes from 204: past a limit of
        // 1,000 bytes, and refused before it is written.
        let mut block = vec![0x1f, b'a', 1, 0];
        block.extend(std::iter::repeat_n(0xff, 200));
        block.extend_from_slice(&[0, 0x00]);
        let mut out = Vec::new();
        assert!(frame(&framed(&block), Some(&mut out), 1_000).is_err());
        assert!(out.len() <= 1_000);
        // The same block within a larger limit, counted, then written.
        let len = 1 + 4 + 15 + 255 * 200;
        assert_eq!(frame(&framed(&block), None, 1 << 20).unwrap(), len);
        let mut out = Vec::new();
        frame(&framed(&block), Some(&mut out), 1 << 20).unwrap();
        assert_eq!(out.len(), len);
        assert!(out.iter().all(|byte| *byte == b'a'));
        // A wrong header checksum, a missing end mark, bytes after it.
        let mut bad = framed(&[0x10, b'a']);
        bad[6] ^= 1;
        assert!(frame(&bad, None, 1 << 20).is_err());
        let whole = framed(&[0x10, b'a']);
        assert!(frame(&whole[..whole.len() - 4], None, 1 << 20).is_err());
        let mut longer = whole.clone();
        longer.push(0);
        assert!(frame(&longer, None, 1 << 20).is_err());
        frame(&whole, None, 1 << 20).unwrap();
    }
}
