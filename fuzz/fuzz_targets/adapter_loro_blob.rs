//! frasil-adapter-loro's step 4 (adapter-loro.md, 3.2 The checks) on
//! updates blobs whose checksum is right, so that the bytes reach the
//! pinned Loro's block decoder: Loro's envelope, with its xxHash32
//! checksum computed, around a body of arbitrary bytes, or around one block
//! of them with its length. Reading the blob's metadata never panics, and a
//! unit that carries it is refused or read, whatever its verdict, without
//! panicking: a blob Loro does not read is never decoded.
#![no_main]

use frasil_adapter::{Adapter, Context, Role, StreamUnit};
use frasil_adapter_loro::{BlobMeta, Content, Loro, meta};
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

/// An updates blob around `body`, with its checksum computed.
fn updates_blob(body: &[u8]) -> Vec<u8> {
    let mut checked = vec![0, 4];
    checked.extend_from_slice(body);
    let mut blob = b"loro".to_vec();
    blob.extend_from_slice(&[0; 12]);
    blob.extend_from_slice(&xxh32(&checked, SEED).to_le_bytes());
    blob.extend_from_slice(&checked);
    blob
}

fuzz_target!(|data: &[u8]| {
    let Some((shape, rest)) = data.split_first() else {
        return;
    };
    let body = if shape & 1 == 0 {
        rest.to_vec()
    } else {
        // One block, after its LEB128 length.
        let mut body = Vec::new();
        let mut len = rest.len();
        while len >= 0x80 {
            body.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        body.push(len as u8);
        body.extend_from_slice(rest);
        body
    };
    let blob = updates_blob(&body);

    let read = BlobMeta::read(&blob);
    assert_eq!(read.is_some(), meta::import_blob_meta(&blob).is_some());

    // A unit that carries the blob, valid by the write rule and not.
    let loro = Loro::new();
    let content = Content::edit(1, blob.clone()).encode();
    let context = Context::new([1; 32], [2; 16], [3; 32], [4; 32], 1, 1, Role::Log);
    let decoded = loro.decode(&content, &context);
    for valid in [false, true] {
        let mut state = loro.empty();
        let unit = StreamUnit {
            context: context.clone(),
            content: content.clone(),
            valid,
        };
        loro.receive(&mut state, &unit);
    }
    if read.is_none() {
        assert!(decoded.is_err(), "a blob Loro does not read was decoded");
    }
});
