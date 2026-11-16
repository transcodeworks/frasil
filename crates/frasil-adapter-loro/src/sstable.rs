//! The key-value tables of a snapshot, as the pinned Loro writes and reads
//! them (adapter-loro.md, 3.5 Compaction and history-free export, "Loading
//! a state").
//!
//! A fast snapshot holds its change store and its state stores each as
//! `loro-kv-store` 1.17.0's SSTable: the magic `LORO`, a schema version, the
//! blocks, a block index and the index's offset. `MemKvStore::import_all`
//! reads the index and checks each block's checksum (`SsTable::import_all`
//! with `validate_blocks` off), and decodes a block only when it is read,
//! where a block it cannot decode makes it panic (`Block::decode`). A block
//! is decompressed in full before its length is checked.
//!
//! [`table`] reads the index as `import_all` does, then every block as
//! `Block::try_decode` and `SsTable::validate_blocks` do, so that no block
//! Loro accepts at import fails when it is read, and hands each entry to the
//! caller. It counts what the blocks decompress to against an [`Inflate`]
//! budget before it holds it. It leaves the checksums to Loro, which refuses
//! a table whose checksum is wrong when it imports it.

use crate::lz4;

/// A table the screen refuses.
#[derive(Debug)]
pub(crate) struct Refused;

impl From<lz4::Refused> for Refused {
    fn from(_: lz4::Refused) -> Self {
        Refused
    }
}

type Result<T> = core::result::Result<T, Refused>;

/// The table's magic, `LORO`.
const MAGIC: &[u8; 4] = b"LORO";
/// The only schema version the pinned store reads.
const SCHEMA: u8 = 0;
/// The most blocks the pinned store's index names (`MAX_BLOCK_NUM`).
const MAX_BLOCKS: u32 = 10_000_000;
/// The least bytes of one index entry: offset, key length, block type.
const MIN_INDEX_ENTRY: usize = 4 + 2 + 1;
/// The most bytes a normal block decompresses to that the pinned store
/// reads: at most `u16::MAX` bytes of entries, then at most `u16::MAX`
/// offsets of two bytes and their count. A longer block is refused after
/// it is decompressed in full.
const MAX_NORMAL_BLOCK: usize = 0xffff + 2 * 0xffff + 2;

/// What the blocks of a snapshot's tables may decompress to, together.
#[derive(Debug)]
pub(crate) struct Inflate {
    /// The bytes decompressed so far.
    pub(crate) used: usize,
    /// The most they may come to.
    pub(crate) limit: usize,
}

/// How a block is stored (`CompressionType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    None,
    Lz4,
}

/// One entry of the block index (`BlockMeta`).
#[derive(Debug)]
struct Index<'a> {
    offset: usize,
    is_large: bool,
    compression: Compression,
    first_key: &'a [u8],
    last_key: Option<&'a [u8]>,
}

/// Reads a table as the pinned store reads it, handing each entry, key then
/// value, to `entry` in ascending order of key. An empty table holds no
/// entry, as `MemKvStore::import_all` reads it.
pub(crate) fn table(
    bytes: &[u8],
    inflate: &mut Inflate,
    mut entry: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    // `SsTable::import_all_with`: magic, schema, and the index's offset in
    // the last four bytes.
    if bytes.len() < 4 + 1 + 4 || bytes[..4] != MAGIC[..] || bytes[4] != SCHEMA {
        return Err(Refused);
    }
    let end = bytes.len() - 4;
    let index_offset = u32_at(bytes, end)? as usize;
    if index_offset >= end {
        return Err(Refused);
    }
    let index = index(&bytes[index_offset..end])?;
    // `validate_block_ranges`: at least one block, each inside the table
    // before the index, in order, and holding at least its checksum.
    if index.is_empty() {
        return Err(Refused);
    }
    let mut previous_last: Option<Vec<u8>> = None;
    for (i, block) in index.iter().enumerate() {
        let block_end = index.get(i + 1).map_or(index_offset, |next| next.offset);
        if block.offset < 4 + 1
            || block_end > index_offset
            || block.offset >= block_end
            || block_end - block.offset < 4
        {
            return Err(Refused);
        }
        // `Block::try_decode`: a block of an empty first key is refused.
        if block.first_key.is_empty() {
            return Err(Refused);
        }
        // The checksum is the block's last four bytes; Loro checks it.
        let stored = &bytes[block.offset..block_end - 4];
        let cap = if block.is_large {
            inflate.limit - inflate.used
        } else {
            MAX_NORMAL_BLOCK.min(inflate.limit - inflate.used)
        };
        let mut data = Vec::new();
        match block.compression {
            Compression::None => {
                if stored.len() > cap {
                    return Err(Refused);
                }
                data.extend_from_slice(stored);
            }
            Compression::Lz4 => {
                // Counted first, so that a frame past the limit is refused
                // before anything is held.
                let len = lz4::frame(stored, None, cap)?;
                data.reserve_exact(len);
                lz4::frame(stored, Some(&mut data), cap)?;
            }
        }
        inflate.used += data.len();
        let last = if block.is_large {
            // `LargeValueBlock`: one entry, its key the index's first key.
            // No export writes an empty value.
            if data.is_empty() || block.last_key.is_some() {
                return Err(Refused);
            }
            entry(block.first_key, &data)?;
            block.first_key.to_vec()
        } else {
            normal(&data, block.first_key, &mut entry)?
        };
        // `validate_blocks`: the index names the block's last key, the
        // first key is not after it, and the blocks are in ascending order.
        if block.last_key.unwrap_or(block.first_key) != last.as_slice()
            || block.first_key > last.as_slice()
            || previous_last
                .as_deref()
                .is_some_and(|previous| previous >= block.first_key)
        {
            return Err(Refused);
        }
        previous_last = Some(last);
    }
    Ok(())
}

/// The block index, `BlockMeta::decode_meta`: a count, the entries, and a
/// checksum, which Loro checks.
fn index(bytes: &[u8]) -> Result<Vec<Index<'_>>> {
    let count = u32_at(bytes, 0)?;
    let mut rest = &bytes[4..];
    // The count is checked against the bytes before anything is reserved
    // for it.
    let payload = rest.len().checked_sub(4).ok_or(Refused)?;
    if count > MAX_BLOCKS || count as usize * MIN_INDEX_ENTRY > payload {
        return Err(Refused);
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let offset = take_u32(&mut rest)? as usize;
        let first_len = take_u16(&mut rest)? as usize;
        let first_key = take(&mut rest, first_len)?;
        let kind = *take(&mut rest, 1)?.first().ok_or(Refused)?;
        let is_large = kind & 0x80 != 0;
        let compression = match kind & 0x7f {
            0 => Compression::None,
            1 => Compression::Lz4,
            _ => return Err(Refused),
        };
        let last_key = if is_large {
            None
        } else {
            let last_len = take_u16(&mut rest)? as usize;
            Some(take(&mut rest, last_len)?)
        };
        entries.push(Index {
            offset,
            is_large,
            compression,
            first_key,
            last_key,
        });
    }
    // The checksum, and nothing after it: the index is the table's last
    // part before its offset.
    if rest.len() != 4 {
        return Err(Refused);
    }
    Ok(entries)
}

/// A normal block, `NormalBlock::decode` and `validate_decoded_data`: its
/// entries, then an offset of two bytes for each, then their count. The
/// first entry is its value alone, under the index's first key; each other
/// is the length of the prefix it shares with the first key, the length of
/// the rest of its key, the rest of its key, and its value. Returns the
/// block's last key.
fn normal(
    data: &[u8],
    first_key: &[u8],
    entry: &mut impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    if data.len() < 2 {
        return Err(Refused);
    }
    let count = usize::from(u16::from_le_bytes([
        data[data.len() - 2],
        data[data.len() - 1],
    ]));
    let offsets_len = 2 * (count + 1);
    if count == 0 || data.len() < offsets_len {
        return Err(Refused);
    }
    let data_end = data.len() - offsets_len;
    if data_end > 0xffff {
        return Err(Refused);
    }
    let offsets: Vec<usize> = data[data_end..data.len() - 2]
        .chunks_exact(2)
        .map(|pair| usize::from(u16::from_le_bytes([pair[0], pair[1]])))
        .collect();
    let entries = &data[..data_end];
    if offsets[0] != 0 {
        return Err(Refused);
    }
    let mut previous_offset = 0;
    let mut previous_key: Vec<u8> = Vec::new();
    for (i, &offset) in offsets.iter().enumerate() {
        let offset_end = offsets.get(i + 1).copied().unwrap_or(data_end);
        if offset < previous_offset || offset > offset_end || offset_end > data_end {
            return Err(Refused);
        }
        let (key, value) = if i == 0 {
            (first_key.to_vec(), &entries[offset..offset_end])
        } else {
            let header_end = offset + 3;
            if header_end > offset_end {
                return Err(Refused);
            }
            let prefix = usize::from(entries[offset]);
            if prefix > first_key.len() {
                return Err(Refused);
            }
            let suffix = usize::from(u16::from_le_bytes([
                entries[offset + 1],
                entries[offset + 2],
            ]));
            let key_end = header_end + suffix;
            if key_end > offset_end {
                return Err(Refused);
            }
            let mut key = first_key[..prefix].to_vec();
            key.extend_from_slice(&entries[header_end..key_end]);
            (key, &entries[key_end..offset_end])
        };
        // Keys are not empty and strictly ascending; no export writes an
        // empty value.
        if key.is_empty() || (i > 0 && previous_key >= key) || value.is_empty() {
            return Err(Refused);
        }
        entry(&key, value)?;
        previous_offset = offset;
        previous_key = key;
    }
    Ok(previous_key)
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let word = bytes.get(at..at + 4).ok_or(Refused)?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if n > bytes.len() {
        return Err(Refused);
    }
    let (taken, rest) = bytes.split_at(n);
    *bytes = rest;
    Ok(taken)
}

fn take_u16(bytes: &mut &[u8]) -> Result<u16> {
    let pair = take(bytes, 2)?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

fn take_u32(bytes: &mut &[u8]) -> Result<u32> {
    let word = take(bytes, 4)?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}
