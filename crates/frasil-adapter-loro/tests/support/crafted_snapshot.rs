//! Snapshot exports crafted to reach the pinned Loro's snapshot decoder:
//! Loro's envelope with its checksum computed, around key-value tables
//! (`loro-kv-store`'s SSTable) written by hand with their checksums, whose
//! entries are taken from real exports or written by hand.

#![allow(dead_code)]

use super::crafted::{self, SEED, xxh32};
use frasil_adapter_loro::snapshot::{SnapshotState, snapshot_tables};
use loro::{ExportMode, LoroDoc};

/// Key-value entries of a table, in ascending order of key.
pub type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// The LZ4 frame magic, little-endian.
const LZ4_MAGIC: [u8; 4] = 0x184D_2204u32.to_le_bytes();
/// The frame flags the default encoder writes: version 01, independent
/// blocks.
const LZ4_FLAGS: u8 = 0x60;
/// The block descriptor of 4 MiB blocks.
pub const LZ4_4MIB: u8 = 0x70;

/// One block of a table, as it is stored.
#[derive(Debug, Clone)]
pub struct Block {
    /// The index's first key.
    pub first_key: Vec<u8>,
    /// The index's last key: `None` for a large block.
    pub last_key: Option<Vec<u8>>,
    /// Whether the block is LZ4-compressed.
    pub lz4: bool,
    /// The block's bytes before its checksum.
    pub stored: Vec<u8>,
}

/// The bytes of a normal block of `entries`, before compression: the first
/// entry's value, then each other entry with no prefix shared with the
/// first key, the offsets, and their count.
pub fn normal_block_data(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for (i, (key, value)) in entries.iter().enumerate() {
        offsets.push(data.len() as u16);
        if i > 0 {
            data.push(0);
            data.extend_from_slice(&(key.len() as u16).to_le_bytes());
            data.extend_from_slice(key);
        }
        data.extend_from_slice(value);
    }
    for offset in &offsets {
        data.extend_from_slice(&offset.to_le_bytes());
    }
    data.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
    data
}

/// A table of these blocks, with the block and index checksums computed.
pub fn table_of(blocks: &[Block]) -> Vec<u8> {
    let mut out = b"LORO".to_vec();
    out.push(0);
    let mut offsets = Vec::new();
    for block in blocks {
        offsets.push(out.len() as u32);
        out.extend_from_slice(&block.stored);
        out.extend_from_slice(&xxh32(&block.stored, SEED).to_le_bytes());
    }
    let index_offset = out.len() as u32;
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    let checked_from = out.len();
    for (block, offset) in blocks.iter().zip(offsets) {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&(block.first_key.len() as u16).to_le_bytes());
        out.extend_from_slice(&block.first_key);
        let large = block.last_key.is_none();
        out.push((u8::from(large) << 7) | u8::from(block.lz4));
        if let Some(last) = &block.last_key {
            out.extend_from_slice(&(last.len() as u16).to_le_bytes());
            out.extend_from_slice(last);
        }
    }
    let checksum = xxh32(&out[checked_from..], SEED);
    out.extend_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&index_offset.to_le_bytes());
    out
}

/// A table that holds each entry in a block of its own, stored as it is: a
/// normal block, or a large one for a value of more than 64 KiB.
pub fn table(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let blocks: Vec<Block> = entries
        .iter()
        .map(|(key, value)| {
            if value.len() > 0xff00 {
                Block {
                    first_key: key.clone(),
                    last_key: None,
                    lz4: false,
                    stored: value.clone(),
                }
            } else {
                Block {
                    first_key: key.clone(),
                    last_key: Some(key.clone()),
                    lz4: false,
                    stored: normal_block_data(&[(key.clone(), value.clone())]),
                }
            }
        })
        .collect();
    table_of(&blocks)
}

/// An LZ4 frame of these compressed blocks, with the block descriptor
/// `descriptor` and its header checksum computed.
pub fn lz4_frame(descriptor: u8, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = LZ4_MAGIC.to_vec();
    out.extend_from_slice(&[LZ4_FLAGS, descriptor]);
    out.push((xxh32(&[LZ4_FLAGS, descriptor], 0) >> 8) as u8);
    for block in blocks {
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&[0; 4]);
    out
}

/// An LZ4 block of `bytes` as literals alone.
pub fn lz4_literals(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if bytes.len() < 15 {
        out.push((bytes.len() as u8) << 4);
    } else {
        out.push(0xf0);
        let mut rest = bytes.len() - 15;
        while rest >= 255 {
            out.push(255);
            rest -= 255;
        }
        out.push(rest as u8);
    }
    out.extend_from_slice(bytes);
    out
}

/// An LZ4 block that decompresses to `len` bytes of `a` (at least 20), from
/// about `len / 255` bytes: one literal, then one match of the rest at
/// offset 1, then an empty last sequence.
pub fn lz4_run(len: usize) -> Vec<u8> {
    let mut out = vec![0x1f, b'a', 1, 0];
    let mut rest = len - 1 - 4 - 15;
    while rest >= 255 {
        out.push(255);
        rest -= 255;
    }
    out.push(rest as u8);
    out.push(0x00);
    out
}

/// Loro's envelope of a snapshot around three sections, with its checksum
/// computed.
pub fn snapshot(changes: &[u8], state: &[u8], shallow_root: &[u8]) -> Vec<u8> {
    let mut checked = vec![0, 3];
    for section in [changes, state, shallow_root] {
        checked.extend_from_slice(&(section.len() as u32).to_le_bytes());
        checked.extend_from_slice(section);
    }
    let mut main = b"loro".to_vec();
    main.extend_from_slice(&[0; 12]);
    main.extend_from_slice(&xxh32(&checked, SEED).to_le_bytes());
    main.extend_from_slice(&checked);
    main
}

/// A snapshot state with this `main` and no suggestion.
pub fn state(main: Vec<u8>) -> Vec<u8> {
    SnapshotState {
        main,
        suggestions: Vec::new(),
        dismissed: Vec::new(),
    }
    .encode()
}

/// The entries of a real export's three tables.
pub fn tables(main: &[u8]) -> [Entries; 3] {
    snapshot_tables(main).expect("a real export reads")
}

/// A snapshot of these tables, each entry in a block of its own; a state
/// store with no entry is written as no state store.
pub fn rebuilt(tables: &[Entries; 3]) -> Vec<u8> {
    let state = if tables[1].is_empty() {
        b"E".to_vec()
    } else {
        table(&tables[1])
    };
    snapshot(&table(&tables[0]), &state, &table(&tables[2]))
}

/// A document of peer `peer` with a text, a map, a list and a tree node.
pub fn small_doc(peer: u64) -> LoroDoc {
    let doc = LoroDoc::new();
    doc.set_peer_id(peer).unwrap();
    doc.get_text("text").insert(0, "hello world").unwrap();
    doc.get_text("text").mark(0..5, "bold", true).unwrap();
    doc.get_map("map").insert("k", 1).unwrap();
    doc.get_list("list").push("x").unwrap();
    doc.get_tree("tree").create(None).unwrap();
    doc.commit();
    doc
}

/// The tables of `small_doc`'s snapshot export.
pub fn small_tables(peer: u64) -> [Entries; 3] {
    tables(&small_doc(peer).export(ExportMode::Snapshot).unwrap())
}

/// The peer and first counter of a change block: the key the change store
/// files it under.
pub fn block_key(block: &crafted::Block) -> Vec<u8> {
    let header = &block.fields[crafted::HEADER];
    // One byte of peer count, then the peers, little-endian.
    let peer = u64::from_le_bytes(header[1..9].try_into().unwrap());
    let mut key = peer.to_be_bytes().to_vec();
    key.extend_from_slice(&(block.ints[0] as i32).to_be_bytes());
    key
}

/// A snapshot whose change store holds the change blocks of `blob`, an
/// updates blob, beside the version vector and frontiers of `small_doc`'s
/// export, and whose state stores are `small_doc`'s.
pub fn with_change_blocks(blob: &[u8]) -> Vec<u8> {
    let mut tables = small_tables(1);
    tables[0].retain(|(key, _)| key.len() != 12);
    for block in crafted::blocks(blob) {
        tables[0].push((block_key(&block), block.encode()));
    }
    tables[0].sort();
    tables[0].dedup_by(|a, b| a.0 == b.0);
    rebuilt(&tables)
}

/// A snapshot whose change store holds one large block under `vv`: an LZ4
/// frame of `blocks` blocks of 4 MiB each of `a`, from about 16 KiB each.
pub fn lz4_bomb(blocks: usize) -> Vec<u8> {
    let frame = lz4_frame(LZ4_4MIB, &vec![lz4_run(4 << 20); blocks]);
    let changes = table_of(&[Block {
        first_key: b"vv".to_vec(),
        last_key: None,
        lz4: true,
        stored: frame,
    }]);
    snapshot(&changes, b"E", &[])
}
