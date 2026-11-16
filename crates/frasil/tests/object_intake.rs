//! Object chunks as a member receives them (units.md, "Reading an object";
//! "Sync", objects): each is checked as it arrives, only an object asked
//! for is taken, and one that fails leaves the object missing, asked of
//! another party.
#![cfg(feature = "adapter-blobs")]

use frasil::advanced::sync::SyncSession;
use frasil::advanced::{Acknowledger, AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::messages::{Message, SyncMessage};
use frasil_units::objects::Header;

async fn device() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

/// Alice and Bob, members of Alice's space with its history, and a blob
/// of two chunks Alice wrote.
struct Blob {
    alice: Engine,
    bob: Engine,
    space: EventId,
    locator: [u8; 64],
    plaintext: Vec<u8>,
}

async fn blob() -> Blob {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let files = alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    let plaintext = vec![9u8; frasil_units::limits::CHUNK_BYTES + 5];
    let (_, locator) = alice
        .put_blob(space, &files, Some("photo"), &plaintext)
        .await
        .unwrap();
    bob.follow(space).await;
    Blob {
        alice,
        bob,
        space,
        locator,
        plaintext,
    }
}

/// Syncs Bob with Alice on a new session pair, and returns Bob's session
/// and the `ObjectChunks` Alice answered his `ObjectWant` with, held back
/// from Bob.
async fn sync_holding_chunks(blob: &Blob) -> (SyncSession, Vec<SyncMessage>) {
    let Blob {
        alice, bob, space, ..
    } = blob;
    let mut bobs = SyncSession::new(*space);
    let mut alices = SyncSession::new(*space);
    let mut to_alice = bob.sync_start(&mut bobs).await.unwrap();
    let mut to_bob = alice.sync_start(&mut alices).await.unwrap();
    let mut chunks = Vec::new();
    for _ in 0..64 {
        if to_alice.is_empty() && to_bob.is_empty() {
            break;
        }
        for message in std::mem::take(&mut to_bob) {
            to_alice.extend(
                bob.sync_receive(
                    &mut bobs,
                    Acknowledger::Member(alice.device_id().0),
                    message,
                )
                .await
                .unwrap(),
            );
        }
        for message in std::mem::take(&mut to_alice) {
            for reply in alice
                .sync_receive(
                    &mut alices,
                    Acknowledger::Member(bob.device_id().0),
                    message,
                )
                .await
                .unwrap()
            {
                if matches!(reply.message, Message::ObjectChunks { .. }) {
                    chunks.push(reply);
                } else {
                    to_bob.push(reply);
                }
            }
        }
    }
    (bobs, chunks)
}

/// Carries messages both ways until neither side has more.
async fn pump(
    blob: &Blob,
    bobs: &mut SyncSession,
    alices: &mut SyncSession,
    first: Vec<SyncMessage>,
) {
    let Blob { alice, bob, .. } = blob;
    let mut to_alice = first;
    let mut to_bob = Vec::new();
    for _ in 0..64 {
        if to_alice.is_empty() && to_bob.is_empty() {
            return;
        }
        for message in std::mem::take(&mut to_alice) {
            to_bob.extend(
                alice
                    .sync_receive(alices, Acknowledger::Member(bob.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
        for message in std::mem::take(&mut to_bob) {
            to_alice.extend(
                bob.sync_receive(bobs, Acknowledger::Member(alice.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
    }
}

/// The object's header, as Alice stores it.
async fn header(blob: &Blob) -> Header {
    let stored = blob
        .alice
        .stored_object(&blob.space, &blob.locator)
        .await
        .unwrap();
    let length = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
    Header::read(&stored[4..4 + length]).unwrap()
}

fn chunks_message(
    space: EventId,
    locator: [u8; 64],
    header: Option<Vec<u8>>,
    index: u64,
    chunk: Vec<u8>,
) -> SyncMessage {
    SyncMessage {
        space,
        message: Message::ObjectChunks {
            locator,
            header,
            index,
            chunk,
        },
    }
}

/// Bob, who asked Alice for the blob on another session, fetches it there.
async fn fetch_elsewhere(blob: &Blob) {
    let mut bobs = SyncSession::new(blob.space);
    let mut alices = SyncSession::new(blob.space);
    let first = blob
        .bob
        .sync_want(&mut bobs, &[blob.locator])
        .await
        .unwrap();
    assert!(!first.is_empty(), "the object is asked for again");
    pump(blob, &mut bobs, &mut alices, first).await;
}

/// A header that claims a one-byte object, and one chunk of junk of that
/// length: the chunk does not open under the object's key, so the object
/// stays missing; it is not asked of the same side again, and another
/// party serves it whole.
#[tokio::test]
async fn a_chunk_that_does_not_open_leaves_the_object_missing() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
    assert!(bobs.is_fetching(&blob.locator));
    assert!(!held_back.is_empty());
    let mut junk = header(&blob).await;
    junk.size = 1;
    let replies = blob
        .bob
        .sync_receive(
            &mut bobs,
            Acknowledger::Member(blob.alice.device_id().0),
            chunks_message(
                blob.space,
                blob.locator,
                Some(junk.encode()),
                0,
                vec![0; 41],
            ),
        )
        .await
        .unwrap();
    assert!(
        !replies
            .iter()
            .any(|m| matches!(m.message, Message::ObjectWant { .. })),
        "{replies:?}"
    );
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
    assert!(blob.bob.object(&blob.space, &blob.locator).await.is_err());
    // The side that sent it is not asked again on this session, and what
    // it sends of the object now is not taken.
    assert!(!bobs.is_fetching(&blob.locator));
    for message in held_back {
        blob.bob
            .sync_receive(
                &mut bobs,
                Acknowledger::Member(blob.alice.device_id().0),
                message,
            )
            .await
            .unwrap();
    }
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
    // Another connection serves it, whole.
    fetch_elsewhere(&blob).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}

/// A chunk at index 2^64 − 1 is past the chunk count: refused, and it
/// takes no other part's place, the header's included.
#[tokio::test]
async fn a_chunk_past_the_count_is_refused() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
    let Message::ObjectChunks { header, chunk, .. } = held_back[0].message.clone() else {
        unreachable!()
    };
    assert!(header.is_some(), "chunk 0 carries the header");
    blob.bob
        .sync_receive(
            &mut bobs,
            Acknowledger::Member(blob.alice.device_id().0),
            chunks_message(blob.space, blob.locator, header, u64::MAX, chunk),
        )
        .await
        .unwrap();
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
    fetch_elsewhere(&blob).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}

/// A chunk of another length than the header gives its index is refused.
#[tokio::test]
async fn a_chunk_of_another_length_is_refused() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
    let Message::ObjectChunks { header, chunk, .. } = held_back[0].message.clone() else {
        unreachable!()
    };
    // Chunk 0 cut to the length of the last chunk, as the last chunk.
    let mut short = chunk;
    short.truncate(5 + 40);
    blob.bob
        .sync_receive(
            &mut bobs,
            Acknowledger::Member(blob.alice.device_id().0),
            chunks_message(blob.space, blob.locator, header.clone(), 1, short),
        )
        .await
        .unwrap();
    assert!(!bobs.is_fetching(&blob.locator));
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
    fetch_elsewhere(&blob).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}

/// Chunks of an object Bob did not ask for on a session are not taken,
/// however well they check.
#[tokio::test]
async fn chunks_not_asked_for_are_not_taken() {
    let blob = blob().await;
    let (_, held_back) = sync_holding_chunks(&blob).await;
    // Another session, on which Bob asked for nothing.
    let mut other = SyncSession::new(blob.space);
    for message in held_back {
        blob.bob
            .sync_receive(
                &mut other,
                Acknowledger::Member(blob.alice.device_id().0),
                message,
            )
            .await
            .unwrap();
    }
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
}

/// A header of the same object ID that differs from the one held is
/// refused, and does not replace it.
#[tokio::test]
async fn a_second_header_does_not_replace_the_first() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
    // The real chunk 0, with its header.
    blob.bob
        .sync_receive(
            &mut bobs,
            Acknowledger::Member(blob.alice.device_id().0),
            held_back[0].clone(),
        )
        .await
        .unwrap();
    assert!(bobs.is_fetching(&blob.locator));
    // Then a smaller header with a chunk of its length: refused, and with
    // it what Bob held of the object.
    let mut junk = header(&blob).await;
    junk.size = 1;
    blob.bob
        .sync_receive(
            &mut bobs,
            Acknowledger::Member(blob.alice.device_id().0),
            chunks_message(
                blob.space,
                blob.locator,
                Some(junk.encode()),
                0,
                vec![0; 41],
            ),
        )
        .await
        .unwrap();
    assert!(!bobs.is_fetching(&blob.locator));
    assert!(
        blob.bob
            .missing_objects(&blob.space)
            .await
            .contains(&blob.locator)
    );
    fetch_elsewhere(&blob).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}
