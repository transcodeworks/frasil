//! Reading an object chunk by chunk and by range (units.md, 3.3 Reading an
//! object): the verdicts of a corrupted chunk, a wrong digest and a wrong
//! object ID, in the order of the steps, whatever chunks a read asks for.

use super::{Plain, parts_of};
use crate::advanced::{AdapterRegistry, Platform};
use crate::device::Engine;
use crate::error::Error;
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_units::limits::CHUNK_BYTES;
use frasil_units::objects::{Header, ObjectKeys, seal_chunk};

async fn device() -> (Engine, EventId) {
    let engine = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0;
    let space = engine.create_space().await.unwrap();
    (engine, space)
}

/// Three chunks and a bit of plaintext.
fn plaintext() -> Vec<u8> {
    (0..CHUNK_BYTES * 3 + 7).map(|i| (i % 251) as u8).collect()
}

/// An object sealed under the space's current state, as the device seals
/// it, with `id` in its header in place of its plaintext's ID when given,
/// and a byte of chunk `flip` changed when given: its header and chunks,
/// and the locator of those bytes.
async fn sealed(
    engine: &Engine,
    space: EventId,
    plaintext: &[u8],
    id: Option<[u8; 32]>,
    flip: Option<usize>,
) -> (Locator, Vec<u8>, Vec<Vec<u8>>) {
    let (reference, key) = {
        let state = engine.lock().await;
        engine.sealing(&state, &space).unwrap()
    };
    let keys = ObjectKeys::of(&key);
    let id = id.unwrap_or_else(|| keys.object_id(plaintext));
    let object_key = keys.object_key(&id);
    let size = plaintext.len() as u64;
    let header = Header {
        object_id: id,
        key_reference: reference,
        size,
    }
    .encode();
    let mut chunks: Vec<Vec<u8>> = (0u64..)
        .zip(plaintext.chunks(CHUNK_BYTES))
        .map(|(index, plain)| {
            seal_chunk(&space, &keys, &object_key, &id, size, index, plain).sealed
        })
        .collect();
    if let Some(index) = flip {
        let last = chunks[index].len() - 1;
        chunks[index][last] ^= 1;
    }
    let mut bytes = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(&header);
    for chunk in &chunks {
        bytes.extend_from_slice(chunk);
    }
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(&id);
    locator[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&bytes]));
    (locator, header, chunks)
}

/// Keeps an object's parts as they are, under `locator`, with no check:
/// what a store would hold had its bytes gone bad, or had a writer sealed
/// them so.
async fn keep(
    engine: &Engine,
    space: EventId,
    locator: Locator,
    header: Vec<u8>,
    chunks: Vec<Vec<u8>>,
) {
    let parts: Vec<ObjectPart> = (0u64..)
        .zip(chunks)
        .map(|(index, chunk)| ObjectPart {
            locator,
            header: (index == 0).then(|| header.clone()),
            index,
            chunk,
        })
        .collect();
    let parts: Vec<&ObjectPart> = parts.iter().collect();
    engine.store_parts(space, &parts, false).await.unwrap();
}

/// The plaintext of chunks `range`, or the first fault.
async fn read(
    engine: &Engine,
    space: EventId,
    locator: &Locator,
    range: core::ops::Range<u64>,
) -> Result<Vec<u8>, Error> {
    let mut chunks = engine.plain(&space, locator, None, range).await?;
    assert!(
        matches!(chunks, Plain::Chunks(_)),
        "a stored object reads from the store"
    );
    let mut out = Vec::new();
    while let Some((_, chunk)) = chunks.next().await? {
        out.extend(chunk);
    }
    Ok(out)
}

#[tokio::test]
async fn a_range_reads_the_chunks_it_covers_and_the_whole_reads_all() {
    let (engine, space) = device().await;
    let plaintext = plaintext();
    let (locator, header, chunks) = sealed(&engine, space, &plaintext, None, None).await;
    keep(&engine, space, locator, header, chunks).await;
    let c = CHUNK_BYTES;
    assert_eq!(
        read(&engine, space, &locator, 1..3).await.unwrap(),
        plaintext[c..3 * c]
    );
    assert_eq!(
        read(&engine, space, &locator, 2..3).await.unwrap(),
        plaintext[2 * c..3 * c]
    );
    assert_eq!(
        read(&engine, space, &locator, 0..u64::MAX).await.unwrap(),
        plaintext
    );
    assert_eq!(
        read(&engine, space, &locator, 3..9).await.unwrap(),
        plaintext[3 * c..]
    );
}

#[tokio::test]
async fn a_corrupted_chunk_is_decrypt_from_a_range_that_does_not_cover_it() {
    let (engine, space) = device().await;
    let (locator, header, chunks) = sealed(&engine, space, &plaintext(), None, Some(2)).await;
    keep(&engine, space, locator, header, chunks).await;
    for range in [0..1, 3..4, 0..u64::MAX] {
        assert_eq!(
            read(&engine, space, &locator, range.clone()).await,
            Err(Error::Class("Decrypt")),
            "{range:?}"
        );
    }
}

#[tokio::test]
async fn bytes_of_another_digest_are_object_mismatch_before_any_other_fault() {
    let (engine, space) = device().await;
    for flip in [None, Some(1)] {
        let (mut locator, header, chunks) = sealed(&engine, space, &plaintext(), None, flip).await;
        locator[63] ^= 1;
        keep(&engine, space, locator, header, chunks).await;
        for range in [0..1, 2..3, 0..u64::MAX] {
            assert_eq!(
                read(&engine, space, &locator, range.clone()).await,
                Err(Error::Class("ObjectMismatch")),
                "{flip:?} {range:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_plaintext_of_another_id_is_object_mismatch_after_every_chunk_opens() {
    let (engine, space) = device().await;
    let other = ObjectKeys::of(&[9; 32]).object_id(b"another plaintext");
    let (locator, header, chunks) = sealed(&engine, space, &plaintext(), Some(other), None).await;
    keep(&engine, space, locator, header, chunks).await;
    for range in [0..1, 1..2, 0..u64::MAX] {
        assert_eq!(
            read(&engine, space, &locator, range.clone()).await,
            Err(Error::Class("ObjectMismatch")),
            "{range:?}"
        );
    }
    // A chunk that does not open comes first (step 6 before step 7).
    let other = ObjectKeys::of(&[9; 32]).object_id(b"yet another plaintext");
    let (locator, header, chunks) =
        sealed(&engine, space, &plaintext(), Some(other), Some(3)).await;
    keep(&engine, space, locator, header, chunks).await;
    assert_eq!(
        read(&engine, space, &locator, 0..1).await,
        Err(Error::Class("Decrypt"))
    );
}

#[tokio::test]
async fn a_chunk_of_the_wrong_length_is_malformed_before_an_earlier_chunk_s_decrypt() {
    let (engine, space) = device().await;
    let (locator, header, mut chunks) = sealed(&engine, space, &plaintext(), None, Some(0)).await;
    chunks[3].push(0);
    // The locator of the bytes as kept.
    let mut bytes = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(&header);
    for chunk in &chunks {
        bytes.extend_from_slice(chunk);
    }
    let mut locator = locator;
    locator[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&bytes]));
    keep(&engine, space, locator, header, chunks).await;
    for range in [0..1, 1..2] {
        assert_eq!(
            read(&engine, space, &locator, range.clone()).await,
            Err(Error::Class("Malformed")),
            "{range:?}"
        );
    }
}

/// The parts the device keeps for an object it sealed read back alike.
#[tokio::test]
async fn an_object_kept_from_its_stored_bytes_reads_by_range() {
    let (engine, space) = device().await;
    let plaintext = plaintext();
    let (locator, header, chunks) = sealed(&engine, space, &plaintext, None, None).await;
    let mut bytes = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(&header);
    for chunk in &chunks {
        bytes.extend_from_slice(chunk);
    }
    engine
        .keep_checked_parts(space, &parts_of(&locator, &bytes).unwrap())
        .await
        .unwrap();
    assert_eq!(
        read(&engine, space, &locator, 1..2).await.unwrap(),
        plaintext[CHUNK_BYTES..2 * CHUNK_BYTES]
    );
}
