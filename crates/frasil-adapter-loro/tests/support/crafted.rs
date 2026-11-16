//! Updates blobs crafted to reach the pinned Loro's block decoder: Loro's
//! envelope with its checksum computed, around change blocks written by
//! hand.

#![allow(dead_code)]

/// The seed of the xxHash32 checksum of Loro's envelope: `"LORO"`.
pub const SEED: u32 = u32::from_le_bytes(*b"LORO");

/// xxHash32 of `input` with `seed`.
pub fn xxh32(input: &[u8], seed: u32) -> u32 {
    const P1: u32 = 0x9E37_79B1;
    const P2: u32 = 0x85EB_CA77;
    const P3: u32 = 0xC2B2_AE3D;
    const P4: u32 = 0x27D4_EB2F;
    const P5: u32 = 0x1656_67B1;
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes.try_into().unwrap());
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
                *lane = round(*lane, word(&rest[4 * i..4 * i + 4]));
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
            .wrapping_add(word(&rest[..4]).wrapping_mul(P3))
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

/// An unsigned LEB128 varint, as postcard and Loro's block lengths write it.
fn varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A change block of Loro's updates encoding: its counters and lamports,
/// `n_changes`, its change header and change metadata, and no operations.
fn block(n_changes: u32, header: &[u8], change_meta: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // counter_start, counter_len, lamport_start, lamport_len, n_changes.
    for value in [0, 1, 0, 1, n_changes] {
        varint(&mut out, u64::from(value));
    }
    for field in [header, change_meta] {
        varint(&mut out, field.len() as u64);
        out.extend_from_slice(field);
    }
    // cids, keys, positions, ops, delete_start_ids, values.
    out.extend_from_slice(&[0; 6]);
    out
}

/// Loro's envelope of an updates blob around these blocks, with its
/// checksum computed.
fn updates_blob(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for block in blocks {
        varint(&mut body, block.len() as u64);
        body.extend_from_slice(block);
    }
    seal(&body)
}

/// Loro's envelope of an updates blob around `body`, with its checksum
/// computed.
pub fn seal(body: &[u8]) -> Vec<u8> {
    let mut checked = vec![0, 4];
    checked.extend_from_slice(body);
    let mut blob = b"loro".to_vec();
    blob.extend_from_slice(&[0; 12]);
    blob.extend_from_slice(&xxh32(&checked, SEED).to_le_bytes());
    blob.extend_from_slice(&checked);
    blob
}

/// A change header of one peer, `peer`, and one change with no dependency
/// on itself, followed by `deps`: its dependency lengths and after.
fn header(peer: u64, deps: &[u8]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&peer.to_le_bytes());
    // The one change does not depend on the peer itself: a run of one
    // `false`.
    out.push(1);
    out.extend_from_slice(deps);
    out
}

/// A blob of `peer` whose one change claims `usize::MAX / 4` dependencies on other
/// peers: Loro reserves room for that many before it reads one.
pub fn too_many_dependencies(peer: u64) -> Vec<u8> {
    let mut deps = vec![2];
    varint(&mut deps, (usize::MAX / 4) as u64);
    updates_blob(&[block(1, &header(peer, &deps), &[])])
}

/// A blob of `peer` whose dependency counters end in the middle of a delta: a flag
/// bit that announces one, then nothing.
pub fn truncated_delta(peer: u64) -> Vec<u8> {
    let deps = [
        // Two dependencies on other peers, both on peer index 0.
        2, 2, 4, 0, // Their counters: head 5, then one bit, `1`, of a delta.
        1, 10, 1, 0x80,
    ];
    updates_blob(&[block(1, &header(peer, &deps), &[])])
}

/// A blob of `peer` that claims `u32::MAX` changes in a header of a few bytes.
pub fn too_many_changes(peer: u64) -> Vec<u8> {
    updates_blob(&[block(u32::MAX, &header(peer, &[2, 0]), &[])])
}

/// Every crafted blob of `peer`, by name.
pub fn all(peer: u64) -> [(&'static str, Vec<u8>); 3] {
    [
        ("too many dependencies", too_many_dependencies(peer)),
        ("truncated delta", truncated_delta(peer)),
        ("too many changes", too_many_changes(peer)),
    ]
}

/// The body of an updates blob whose change headers and metadata the pinned
/// Loro reads, so that it passes step 4, but whose operations make
/// `LoroDoc::import` panic: a style's end with no start before it
/// ("Unhandled checkout case").
const IMPORT_PANICS: &[&str] = &[
    "f4010018001e0425020700000000000000080000000000000006060604010006",
    "010601010202a080010002a3800e01fc8895af0d030008016d6d6d6d15040401",
    "0200020401000004040101000604010300080b016b0174016d016c0274721201",
    "020208000c0401800281800282800283804a0104100100060201050602010506",
    "02010506020f0c0003020104000304030400030605150105040b031005040b03",
    "1005040b031005040b0110100103060101030601010306010103060100380361",
    "62630300070103000005000103616263030107010301000b0101036162630302",
    "070103020011020103616263030307010303001703018d010008061a04230208",
    "0000000000000007000000000000000202020408010801010a03a280010c02a3",
    "800a01fc8895af0d030008000b0204010200000401040002050174026d6c0022",
    "0104060f0002010201020102080600090201040306090f090b090b090b090b02",
    "10011101030401020600040100060c0424020600100701030007010301070103",
    "0207010303",
];

/// An updates blob that passes step 4 and on whose import the pinned Loro
/// panics.
pub fn import_panics() -> Vec<u8> {
    let hex: String = IMPORT_PANICS.concat();
    let body: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    seal(&body)
}

/// The fields of a change block, in order after its five integers.
pub const HEADER: usize = 0;
/// The change metadata: timestamps and commit messages.
pub const CHANGE_META: usize = 1;
/// The container IDs.
pub const CIDS: usize = 2;
/// The key strings.
pub const KEYS: usize = 3;
/// The tree positions table.
pub const POSITIONS: usize = 4;
/// The operations table.
pub const OPS: usize = 5;
/// The deletion starts table.
pub const DELETE_START_IDS: usize = 6;
/// The operations' values.
pub const VALUES: usize = 7;

/// A change block of an updates blob: `counter_start`, `counter_len`,
/// `lamport_start`, `lamport_len` and `n_changes`, then eight byte strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The five integers.
    pub ints: [u64; 5],
    /// The eight byte strings, by the constants above.
    pub fields: [Vec<u8>; 8],
}

impl Block {
    /// The block's postcard bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for value in self.ints {
            varint(&mut out, value);
        }
        for field in &self.fields {
            varint(&mut out, field.len() as u64);
            out.extend_from_slice(field);
        }
        out
    }
}

/// Reads an unsigned varint from the front of `bytes`.
fn read_varint(bytes: &mut &[u8]) -> u128 {
    let mut out = 0u128;
    let mut shift = 0;
    loop {
        let (byte, rest) = bytes.split_first().unwrap();
        *bytes = rest;
        out |= u128::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return out;
        }
        shift += 7;
    }
}

/// Reads a length-prefixed byte string from the front of `bytes`.
fn read_bytes(bytes: &mut &[u8]) -> Vec<u8> {
    let len = read_varint(bytes) as usize;
    let (taken, rest) = bytes.split_at(len);
    *bytes = rest;
    taken.to_vec()
}

/// The change blocks of an updates blob.
pub fn blocks(blob: &[u8]) -> Vec<Block> {
    let mut body = &blob[22..];
    let mut out = Vec::new();
    while !body.is_empty() {
        let mut block: &[u8] = &read_bytes(&mut body);
        let ints = [(); 5].map(|_| read_varint(&mut block) as u64);
        let fields = [(); 8].map(|_| read_bytes(&mut block));
        out.push(Block { ints, fields });
    }
    out
}

/// An updates blob of these blocks, with its checksum computed.
pub fn blob_of(blocks: &[Block]) -> Vec<u8> {
    updates_blob(&blocks.iter().map(Block::encode).collect::<Vec<_>>())
}

/// The columns of a column table: a sequence of one field, a sequence of
/// byte strings.
pub fn columns(table: &[u8]) -> Vec<Vec<u8>> {
    let mut bytes = table;
    assert_eq!(read_varint(&mut bytes), 1);
    let n = read_varint(&mut bytes);
    (0..n).map(|_| read_bytes(&mut bytes)).collect()
}

/// A column table of these columns.
pub fn table(columns: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![1];
    varint(&mut out, columns.len() as u64);
    for column in columns {
        varint(&mut out, column.len() as u64);
        out.extend_from_slice(column);
    }
    out
}

/// A postcard zigzag varint of a signed integer.
pub fn signed(value: i128) -> Vec<u8> {
    let zigzag = ((value << 1) ^ (value >> 127)) as u128;
    let mut out = Vec::new();
    let mut rest = zigzag;
    while rest >= 0x80 {
        out.push(rest as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
    out
}

/// A postcard varint of an unsigned integer.
pub fn unsigned(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(&mut out, value);
    out
}

/// A run of `count` entries of one value, written as `value`'s bytes.
pub fn run(count: i64, value: &[u8]) -> Vec<u8> {
    let mut out = signed(count.into());
    out.extend_from_slice(value);
    out
}

/// Replaces block `index`'s field `field`.
pub fn with_field(blob: &[u8], index: usize, field: usize, bytes: Vec<u8>) -> Vec<u8> {
    let mut blocks = blocks(blob);
    blocks[index].fields[field] = bytes;
    blob_of(&blocks)
}

/// A one-change export of `peer` with a tree node: its positions table
/// holds one position.
pub fn with_tree(peer: u64) -> Vec<u8> {
    let doc = loro::LoroDoc::new();
    doc.set_peer_id(peer).unwrap();
    doc.get_tree("tree").create(None).unwrap();
    doc.commit();
    doc.export(loro::ExportMode::all_updates()).unwrap()
}

/// A blob whose positions table pairs one position with a run of `n`
/// common prefix lengths, which the pinned Loro expands in full before it
/// pairs them: `n` entries of a usize from a few bytes. Loro reads it.
pub fn long_prefix_column(peer: u64, n: i64) -> Vec<u8> {
    let blob = with_tree(peer);
    let positions = columns(&blocks(&blob)[0].fields[POSITIONS]);
    let rests = positions[1].clone();
    let prefixes = run(n, &unsigned(0));
    with_field(&blob, 0, POSITIONS, table(&[prefixes, rests]))
}

/// A blob whose positions table holds a position of `len` bytes, then `n`
/// more that repeat it whole: the pinned Loro builds each of them, `n *
/// len` bytes from about `n + len`. Loro reads it.
pub fn repeated_positions(peer: u64, n: u64, len: usize) -> Vec<u8> {
    let blob = with_tree(peer);
    let mut prefixes = run(1, &unsigned(0));
    prefixes.extend(run(n as i64, &unsigned(len as u64)));
    let mut rests = unsigned(n + 1);
    rests.extend(unsigned(len as u64));
    rests.extend(std::iter::repeat_n(0x80, len));
    rests.extend(std::iter::repeat_n(0, n as usize));
    with_field(&blob, 0, POSITIONS, table(&[prefixes, rests]))
}

/// A two-change export of `peer`: "abc" inserted, then its "b" deleted.
/// The second block's deletion starts table holds one deletion.
pub fn with_deletion(peer: u64) -> Vec<u8> {
    let doc = loro::LoroDoc::new();
    doc.set_peer_id(peer).unwrap();
    let text = doc.get_text("t");
    text.insert(0, "abc").unwrap();
    doc.commit();
    let from = doc.oplog_vv().get(&peer).copied().unwrap();
    text.delete(1, 1).unwrap();
    doc.commit();
    let end = doc.oplog_vv().get(&peer).copied().unwrap();
    doc.export(loro::ExportMode::updates_in_range(vec![loro::IdSpan::new(
        peer, from, end,
    )]))
    .unwrap()
}

/// A blob whose deletion starts table pairs its one deletion's peer index
/// with a run of `n`: the pinned Loro expands each column in full, then
/// pairs them, `n` entries of a usize from a few bytes. Loro reads it.
pub fn long_deletion_column(peer: u64, n: i64) -> Vec<u8> {
    let blob = with_deletion(peer);
    let mut starts = columns(&blocks(&blob)[0].fields[DELETE_START_IDS]);
    starts[0].extend(run(n - 1, &signed(0)));
    with_field(&blob, 0, DELETE_START_IDS, table(&starts))
}

/// A blob whose one deletion is of length 0. Loro's release build reads
/// it; its debug build stops at an assertion.
pub fn empty_deletion(peer: u64) -> Vec<u8> {
    let blob = with_deletion(peer);
    let mut starts = columns(&blocks(&blob)[0].fields[DELETE_START_IDS]);
    starts[2] = run(1, &signed(0));
    with_field(&blob, 0, DELETE_START_IDS, table(&starts))
}

/// A one-change blob of `peer` that sets key "k" of map "m" to an
/// integer, then deletes it `n` times: `n` operations that write no value
/// and whose columns repeat, so they take a few bytes whatever `n`. The
/// pinned Loro decodes every one.
pub fn many_deletions_of_a_key(peer: u64, n: u32) -> Vec<u8> {
    let doc = loro::LoroDoc::new();
    doc.set_peer_id(peer).unwrap();
    doc.get_map("m").insert("k", 1).unwrap();
    doc.commit();
    let blob = doc.export(loro::ExportMode::all_updates()).unwrap();
    let mut blocks = blocks(&blob);
    let block = &mut blocks[0];
    // Every column holds the one operation's entry, then repeats it: a run
    // of deltas of 0, or a run of the same value. The deletions write no
    // value: kind 8, DeleteOnce.
    let ops = columns(&block.fields[OPS]);
    let mut out = Vec::new();
    for (i, column) in ops.iter().enumerate() {
        let mut col = column.clone();
        match i {
            0 | 1 => col.extend(run(i64::from(n), &signed(0))),
            2 => col.extend(run(i64::from(n), &[8])),
            _ => col.extend(run(i64::from(n), &unsigned(1))),
        }
        out.push(col);
    }
    block.fields[OPS] = table(&out);
    // The change spans one counter and one Lamport timestamp per
    // operation.
    block.ints[1] += u64::from(n);
    block.ints[3] += u64::from(n);
    blob_of(&blocks)
}

/// A blob whose one value is a list that claims `len` elements and holds
/// none: the pinned Loro reserves room for them before it finds the bytes
/// end. Loro does not read it.
pub fn list_longer_than_its_bytes(peer: u64, len: u64) -> Vec<u8> {
    let doc = loro::LoroDoc::new();
    doc.set_peer_id(peer).unwrap();
    doc.get_map("m").insert("k", 1).unwrap();
    doc.commit();
    let blob = doc.export(loro::ExportMode::all_updates()).unwrap();
    let mut values = vec![7];
    values.extend(unsigned(len));
    with_field(&blob, 0, VALUES, values)
}

/// [`import_panics`] with its second block's deletion starts columns each
/// of the four entries Loro pairs from them: a blob laid out as an export
/// is, whose import still panics, at a style's end with no start before
/// it.
pub fn style_end_alone() -> Vec<u8> {
    let blob = import_panics();
    let mut starts = columns(&blocks(&blob)[1].fields[DELETE_START_IDS]);
    // Lengths 1, 2, 3, 4: a run of four deltas of 1.
    starts[2] = run(4, &signed(1));
    with_field(&blob, 1, DELETE_START_IDS, table(&starts))
}
