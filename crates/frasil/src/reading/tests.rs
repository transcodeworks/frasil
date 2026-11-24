//! Reading an object by chunk, any chunk first (units.md, 3.3 Reading an
//! object): what a chunk is bound to, and the whole-object steps of a
//! read in order.

use super::{PartReader, WholeFault};
use crate::error::Error;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_units::limits::CHUNK_BYTES;
use frasil_units::objects::{Header, ObjectKeys, Opening, SealedObject, seal_chunk, seal_object};

const SPACE: EventId = EventId([1; 32]);
const KEY: [u8; 32] = [2; 32];

fn reference() -> Vec<u8> {
    RotationSet::single(EventId([3; 32])).encode()
}

/// Three chunks and a bit, by a seed.
fn plaintext(seed: usize) -> Vec<u8> {
    (0..CHUNK_BYTES * 3 + 7)
        .map(|i| ((i + seed) % 251) as u8)
        .collect()
}

fn object(seed: usize) -> SealedObject {
    seal_object(&SPACE, &KEY, &reference(), &plaintext(seed)).unwrap()
}

fn reader(object: &SealedObject) -> PartReader {
    PartReader::new(
        &object.header,
        &SPACE,
        Opening::ContentKey(Some(&KEY)),
        &object.locator,
    )
    .unwrap()
}

fn class(result: Result<Vec<u8>, Error>) -> Option<&'static str> {
    result.unwrap_err().class_name()
}

/// Any chunk opens first, under the header alone, and gives its own
/// plaintext.
#[test]
fn any_chunk_opens_first() {
    let object = object(0);
    let plain = plaintext(0);
    for index in [2usize, 0, 3, 1] {
        let mut reader = reader(&object);
        let opened = reader
            .open(index as u64, &object.chunks[index].sealed, true)
            .unwrap();
        let from = index * CHUNK_BYTES;
        assert_eq!(opened, plain[from..(from + CHUNK_BYTES).min(plain.len())]);
        assert!(!reader.is_whole());
    }
    // The bytes given there before open again, from wherever.
    let mut again = self::reader(&object);
    again.open(1, &object.chunks[1].sealed, true).unwrap();
    again.open(1, &object.chunks[1].sealed, false).unwrap();
    assert_eq!(again.fault(), None);
}

/// A chunk opens only at its own place in its own object: one of another
/// object, and the object's own at another index, fail.
#[test]
fn a_chunk_is_bound_to_its_object_and_its_index() {
    let (object, other) = (object(0), object(1));
    let mut reader = reader(&object);
    // Another object's chunk, at the same index and of the same length.
    assert_eq!(
        class(reader.open(1, &other.chunks[1].sealed, true)),
        Some("Decrypt")
    );
    // Two chunks swapped.
    assert_eq!(
        class(reader.open(1, &object.chunks[2].sealed, true)),
        Some("Decrypt")
    );
    assert_eq!(
        class(reader.open(2, &object.chunks[1].sealed, true)),
        Some("Decrypt")
    );
    // Chunk 0 replayed as chunk 2.
    assert_eq!(
        class(reader.open(2, &object.chunks[0].sealed, true)),
        Some("Decrypt")
    );
    // The last chunk is shorter: at another place its length is wrong.
    assert_eq!(
        class(reader.open(0, &object.chunks[3].sealed, true)),
        Some("Malformed")
    );
    // Past the last chunk, and cut short.
    assert_eq!(
        class(reader.open(4, &object.chunks[0].sealed, true)),
        Some("Malformed")
    );
    let cut = &object.chunks[1].sealed[..CHUNK_BYTES];
    assert_eq!(class(reader.open(1, cut, true)), Some("Malformed"));
    // None of it counted: each opens at its place.
    for chunk in &object.chunks {
        reader.open(chunk.index, &chunk.sealed, true).unwrap();
    }
    assert!(reader.is_whole());
}

/// A header of another object does not pass, nor one that does not read,
/// and no key opens nothing.
#[test]
fn the_header_is_checked_before_any_chunk() {
    let (object, other) = (object(0), object(1));
    let new = |header: &[u8], opening, locator: &Locator| {
        PartReader::new(header, &SPACE, opening, locator)
            .unwrap_err()
            .class_name()
    };
    let key = Opening::ContentKey(Some(&KEY));
    assert_eq!(
        new(&other.header, key, &object.locator),
        Some("ObjectMismatch")
    );
    assert_eq!(new(&[1, 2, 3], key, &object.locator), Some("Malformed"));
    assert_eq!(
        new(&object.header, Opening::ContentKey(None), &object.locator),
        Some("Sealed")
    );
    // A size past the limit is refused where the header is read.
    let large = Header {
        object_id: object.locator[..32].try_into().unwrap(),
        key_reference: reference(),
        size: (1 << 40) + 1,
    }
    .encode();
    assert!(new(&large, key, &object.locator).is_some());
    // The size the reader reports is the header's.
    assert_eq!(reader(&object).size(), plaintext(0).len() as u64);
    assert_eq!(reader(&object).count(), 4);
}

/// A read in order runs steps 0 and 7 as the bytes pass, and is whole
/// after its last chunk; one out of order is not.
#[test]
fn a_read_in_order_runs_the_whole_object_steps() {
    let object = object(0);
    let mut in_order = reader(&object);
    for chunk in &object.chunks {
        assert!(!in_order.is_whole());
        in_order.open(chunk.index, &chunk.sealed, true).unwrap();
    }
    assert!(in_order.is_whole() && in_order.passed_stored());
    // A chunk read again afterwards opens, and changes nothing.
    in_order.open(1, &object.chunks[1].sealed, false).unwrap();
    assert!(in_order.is_whole() && in_order.passed_stored());

    // Out of order: every chunk opened, and the whole-object steps did
    // not run.
    let mut seeking = reader(&object);
    for index in [1usize, 0, 2, 3] {
        seeking
            .open(index as u64, &object.chunks[index].sealed, true)
            .unwrap();
    }
    assert!(!seeking.is_whole());
    // It goes on in order from where the pass stands, chunk 1.
    for index in [1usize, 2, 3] {
        seeking
            .open(index as u64, &object.chunks[index].sealed, true)
            .unwrap();
    }
    assert!(seeking.is_whole());

    // Chunks from a window are not the store's.
    let mut passing = reader(&object);
    for chunk in &object.chunks {
        passing
            .open(chunk.index, &chunk.sealed, chunk.index != 2)
            .unwrap();
    }
    assert!(passing.is_whole() && !passing.passed_stored());
}

/// Bytes that do not hash to the locator fail step 0 at the last chunk,
/// whose plaintext is not given.
#[test]
fn a_wrong_digest_fails_before_the_last_chunk_is_given() {
    let object = object(0);
    let mut locator = object.locator;
    locator[63] ^= 1;
    let mut reader = PartReader::new(
        &object.header,
        &SPACE,
        Opening::ContentKey(Some(&KEY)),
        &locator,
    )
    .unwrap();
    for chunk in &object.chunks[..3] {
        reader.open(chunk.index, &chunk.sealed, true).unwrap();
    }
    assert_eq!(
        class(reader.open(3, &object.chunks[3].sealed, true)),
        Some("ObjectMismatch")
    );
    assert_eq!(reader.fault(), Some(WholeFault::Bytes));
    assert!(!reader.is_whole());
}

/// An object whose header names another ID than its plaintext's fails
/// step 7 once step 0 passed: the fault is the object's.
#[test]
fn a_wrong_object_id_fails_once_the_digest_passed() {
    let plain = plaintext(0);
    let keys = ObjectKeys::of(&KEY);
    let id = [9; 32];
    let object_key = keys.object_key(&id);
    let size = plain.len() as u64;
    let header = Header {
        object_id: id,
        key_reference: reference(),
        size,
    }
    .encode();
    let chunks: Vec<Vec<u8>> = (0u64..)
        .zip(plain.chunks(CHUNK_BYTES))
        .map(|(index, plain)| {
            seal_chunk(&SPACE, &keys, &object_key, &id, size, index, plain).sealed
        })
        .collect();
    let mut bytes = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(&header);
    for chunk in &chunks {
        bytes.extend_from_slice(chunk);
    }
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(&id);
    locator[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&bytes]));

    let mut reader =
        PartReader::new(&header, &SPACE, Opening::ContentKey(Some(&KEY)), &locator).unwrap();
    for (index, chunk) in chunks.iter().enumerate().take(3) {
        reader.open(index as u64, chunk, true).unwrap();
    }
    assert_eq!(
        class(reader.open(3, &chunks[3], true)),
        Some("ObjectMismatch")
    );
    assert_eq!(reader.fault(), Some(WholeFault::Object));
    // A reader that holds the object key alone has no step 7: it is whole
    // once the digest passed.
    let mut by_key =
        PartReader::new(&header, &SPACE, Opening::ObjectKey(&object_key), &locator).unwrap();
    for (index, chunk) in chunks.iter().enumerate() {
        by_key.open(index as u64, chunk, true).unwrap();
    }
    assert!(by_key.is_whole());
}

/// An empty object has one empty chunk, and a read of it is whole.
#[test]
fn an_empty_object_is_read_whole_by_its_one_chunk() {
    let object = seal_object(&SPACE, &KEY, &reference(), &[]).unwrap();
    let mut reader = reader(&object);
    assert_eq!((reader.size(), reader.count()), (0, 1));
    assert!(
        reader
            .open(0, &object.chunks[0].sealed, true)
            .unwrap()
            .is_empty()
    );
    assert!(reader.is_whole());
}

/// A chunk returned from memory is known again by its sealed bytes: the
/// same bytes open again, and other bytes that a holder of the key sealed
/// at that place do not, wherever they are read from.
#[test]
fn a_chunk_given_from_memory_must_come_again_as_the_same_bytes() {
    let object = object(0);
    let keys = ObjectKeys::of(&KEY);
    let id: [u8; 32] = object.locator[..32].try_into().unwrap();
    let size = plaintext(0).len() as u64;
    let other = seal_chunk(
        &SPACE,
        &keys,
        &keys.object_key(&id),
        &id,
        size,
        1,
        &vec![9; CHUNK_BYTES],
    )
    .sealed;
    let mut reader = reader(&object);
    reader.open(1, &object.chunks[1].sealed, false).unwrap();
    reader.open(1, &object.chunks[1].sealed, false).unwrap();
    assert_eq!(reader.fault(), None);
    // From the store too, at a place given from memory.
    for stored in [false, true] {
        assert_eq!(
            class(reader.open(1, &other, stored)),
            Some("ObjectMismatch")
        );
        assert_eq!(reader.fault(), Some(WholeFault::Given));
    }
}

/// A chunk returned from what the device stores is known again by its
/// sealed bytes too: once the store let it go, other bytes that a holder
/// of the key sealed at that place are not returned, and the reader is
/// whole no longer.
#[test]
fn a_chunk_given_from_the_store_must_come_again_as_the_same_bytes() {
    let object = object(0);
    let keys = ObjectKeys::of(&KEY);
    let id: [u8; 32] = object.locator[..32].try_into().unwrap();
    let size = plaintext(0).len() as u64;
    let other = seal_chunk(
        &SPACE,
        &keys,
        &keys.object_key(&id),
        &id,
        size,
        1,
        &vec![9; CHUNK_BYTES],
    )
    .sealed;
    let mut reader = reader(&object);
    for (index, chunk) in object.chunks.iter().enumerate() {
        reader.open(index as u64, &chunk.sealed, true).unwrap();
    }
    assert!(reader.is_whole());
    for stored in [false, true] {
        assert_eq!(
            class(reader.open(1, &other, stored)),
            Some("ObjectMismatch")
        );
        assert_eq!(reader.fault(), Some(WholeFault::Given));
        assert!(!reader.is_whole());
    }
    // The bytes given there before open again, from wherever.
    let mut again = self::reader(&object);
    again.open(1, &object.chunks[1].sealed, true).unwrap();
    again.open(1, &object.chunks[1].sealed, false).unwrap();
    assert_eq!(again.fault(), None);
}
