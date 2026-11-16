//! A device's arrivals, a blob's content hash, and a blob whose key has not
//! arrived, on devices with no peer. The durability feed, which needs a
//! peer's acknowledgements, is in
//! `tests/conformance/tests/client_durability_feed.rs`.
#![cfg(all(feature = "adapter-blobs", feature = "adapter-loro"))]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Arrival, BlobStatus, Device, Options, SpaceId, Storage};
use frasil_crypto::primitives::sha256;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use std::time::Duration;

async fn engine() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

/// Alice's space, with Bob granted at `history`; Bob follows it and holds
/// nothing of it yet.
async fn granted(alice: &Engine, bob: &Engine, history: HistoryMode) -> EventId {
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            history,
            Via::Code,
        )
        .await
        .unwrap();
    space
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arrivals_name_each_new_space_then_each_new_stream_once() {
    let alice_engine = engine().await;
    let bob_engine = engine().await;
    let alice = Device::from_engine(alice_engine.clone(), Options::new()).unwrap();
    let bob = Device::from_engine(bob_engine.clone(), Options::new()).unwrap();
    let mut arrivals = bob.arrivals().await;

    let space = granted(&alice_engine, &bob_engine, HistoryMode::WithHistory).await;
    let alices = alice.space(SpaceId::from_bytes(space.0)).await.unwrap();
    let note = alices.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    bob_engine.follow(space).await;
    carry(&alice_engine, &bob_engine, space).await;
    let id = SpaceId::from_bytes(space.0);
    let first = tokio::time::timeout(Duration::from_secs(10), arrivals.next())
        .await
        .unwrap();
    assert_eq!(first, Some(Arrival::Space(id)));
    let second = tokio::time::timeout(Duration::from_secs(10), arrivals.next())
        .await
        .unwrap();
    assert_eq!(
        second,
        Some(Arrival::Stream {
            space: id,
            stream: note.id()
        })
    );

    // A second stream arrives; the first is not named again.
    note.edit(|doc| doc.get_text("body").insert(5, "!"))
        .await
        .unwrap();
    let blobs = alices.create_blobs().unwrap();
    blobs.put(None, b"bytes").await.unwrap();
    carry(&alice_engine, &bob_engine, space).await;
    let third = tokio::time::timeout(Duration::from_secs(10), arrivals.next())
        .await
        .unwrap();
    assert_eq!(
        third,
        Some(Arrival::Stream {
            space: id,
            stream: blobs.id()
        })
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), arrivals.next())
            .await
            .is_err(),
        "nothing else arrived"
    );
}

#[tokio::test]
async fn a_blob_s_content_hash_is_the_sha256_of_its_bytes() {
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let small = blobs.put(Some("a.txt"), b"some content").await.unwrap();
    assert_eq!(
        blobs.content_hash(small).await.unwrap(),
        Some(sha256(&[b"some content"]))
    );
    // Larger than one chunk: hashed chunk by chunk.
    let large: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let id = blobs.put(None, &large).await.unwrap();
    assert_eq!(
        blobs.content_hash(id).await.unwrap(),
        Some(sha256(&[&large]))
    );
    // Equal content, equal hash.
    let again = blobs.put(Some("b.txt"), b"some content").await.unwrap();
    assert_eq!(
        blobs.content_hash(again).await.unwrap(),
        blobs.content_hash(small).await.unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_blob_with_its_keys_and_no_bytes_is_missing_not_keys_pending() {
    let alice_engine = engine().await;
    let bob_engine = engine().await;
    let alice = Device::from_engine(alice_engine.clone(), Options::new()).unwrap();
    let bob = Device::from_engine(bob_engine.clone(), Options::new()).unwrap();
    let space = granted(&alice_engine, &bob_engine, HistoryMode::WithHistory).await;
    let alices = alice.space(SpaceId::from_bytes(space.0)).await.unwrap();
    let blobs = alices.create_blobs().unwrap();
    let id = blobs.put(None, b"bytes").await.unwrap();
    assert_eq!(blobs.status(id).await.unwrap(), BlobStatus::Readable);
    // Bob holds the events and every key, and not the object's bytes.
    bob_engine.follow(space).await;
    carry(&alice_engine, &bob_engine, space).await;
    let bobs = bob.space(SpaceId::from_bytes(space.0)).await.unwrap();
    let bobs_blobs = bobs.blobs(blobs.id()).await.unwrap();
    assert_eq!(bobs_blobs.status(id).await.unwrap(), BlobStatus::Missing);
    assert_eq!(bobs_blobs.content_hash(id).await.unwrap(), None);
    // A blob the stream does not list, with nothing waiting for a key, is
    // still unknown.
    assert!(
        bobs_blobs
            .status(frasil::BlobId::from_bytes([9; 16]))
            .await
            .is_err()
    );
}
