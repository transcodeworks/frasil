//! frasil-adapter-loro's checks of a snapshot state (adapter-loro.md, 3.5
//! Compaction and history-free export, "Loading a state") on snapshot
//! exports whose checksums are right, so that the bytes reach the pinned
//! Loro's snapshot decoder: Loro's envelope, with its checksum computed,
//! around a body of arbitrary bytes, around a change store or a state store
//! of arbitrary bytes, around a change store whose one block is arbitrary
//! bytes with its own checksum, or around a state store whose one
//! container state, of a map, a list, a text, a tree or a movable list,
//! is its header then arbitrary bytes: its value and its tables. The checks
//! and the load never panic, and a state the checks refuse never loads.
#![no_main]

use frasil_adapter_loro::State;
use frasil_adapter_loro::snapshot::{self, SnapshotState};
use libfuzzer_sys::fuzz_target;

/// The seed of the envelope's checksum: `"LORO"`.
const SEED: u32 = u32::from_le_bytes(*b"LORO");

/// xxHash32 of `input` with `seed`.
fn xxh32(input: &[u8], seed: u32) -> u32 {
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

/// A snapshot export around `body`, with its checksum computed.
fn snapshot_export(body: &[u8]) -> Vec<u8> {
    let mut checked = vec![0, 3];
    checked.extend_from_slice(body);
    let mut main = b"loro".to_vec();
    main.extend_from_slice(&[0; 12]);
    main.extend_from_slice(&xxh32(&checked, SEED).to_le_bytes());
    main.extend_from_slice(&checked);
    main
}

/// A snapshot body of three sections.
fn sections(changes: &[u8], state: &[u8], shallow_root: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for section in [changes, state, shallow_root] {
        body.extend_from_slice(&(section.len() as u32).to_le_bytes());
        body.extend_from_slice(section);
    }
    body
}

/// A key-value table of one normal block, stored as it is, that holds
/// `value` under `key`, with its checksums computed.
fn table(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut block = value.to_vec();
    block.extend_from_slice(&[0, 0, 1, 0]);
    let mut out = b"LORO".to_vec();
    out.push(0);
    out.extend_from_slice(&block);
    out.extend_from_slice(&xxh32(&block, SEED).to_le_bytes());
    let index = out.len() as u32;
    out.extend_from_slice(&1u32.to_le_bytes());
    let from = out.len();
    // The block's offset, its first key, a normal block stored as it is,
    // and its last key.
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key);
    out.push(0);
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key);
    let checksum = xxh32(&out[from..], SEED);
    out.extend_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out
}

fuzz_target!(|data: &[u8]| {
    let Some((shape, rest)) = data.split_first() else {
        return;
    };
    let body = match shape % 9 {
        0 => rest.to_vec(),
        1 => sections(rest, b"E", &[]),
        2 => sections(&[], rest, &[]),
        3 => {
            // A change block filed under the key of its first 12 bytes.
            let (key, value) = rest.split_at(rest.len().min(12));
            sections(&table(key, value), b"E", &[])
        }
        kind => {
            // The root container "c" of type `kind - 4`: its key, then its
            // state's header, its type, depth 1 and no parent, before the
            // arbitrary bytes.
            let kind = kind - 4;
            let key = [0x80 | kind, 1, b'c'];
            let mut state = vec![kind, 1, 0];
            state.extend_from_slice(rest);
            sections(&[], &table(&key, &state), &[])
        }
    };
    let state = SnapshotState {
        main: snapshot_export(&body),
        suggestions: Vec::new(),
        dismissed: Vec::new(),
    }
    .encode();
    let checked = snapshot::check(&state);
    let loaded = State::load(&state);
    if checked.is_err() {
        assert!(loaded.is_err(), "a state the checks refuse was loaded");
    }
});
