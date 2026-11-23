//! Object chunks as a member receives them (units.md, "Reading an object";
//! "Sync", objects): each is checked as it arrives, only an object asked
//! for is taken, and one that fails leaves the object missing, asked of
//! another party. A member serves a range of chunks from any index, the
//! first of each answer with the header; a chunk that arrives with no
//! header the device can check it against is not kept, and an answer
//! nobody wants any more is dropped as it arrives.
#![cfg(feature = "adapter-blobs")]

use frasil::advanced::sync::SyncSession;
use frasil::advanced::{Acknowledger, AdapterRegistry, Engine, FetchEnd, FetchPriority, Platform};
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
    // A reader that asked for its chunks hears that the side gave it up.
    let reader = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..1, FetchPriority::Position);
    assert_eq!(reader.end(), None);
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
    assert_eq!(reader.end(), Some(FetchEnd::Refused));
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

/// Bob, who fetches blobs only when asked, synced with Alice: he knows
/// the blob, which she announced, and holds nothing of it.
async fn synced_on_demand(blob: &Blob) -> (SyncSession, SyncSession) {
    blob.bob.fetch_objects_on_demand();
    let mut bobs = SyncSession::new(blob.space);
    let mut alices = SyncSession::new(blob.space);
    let first = blob.bob.sync_start(&mut bobs).await.unwrap();
    pump(blob, &mut bobs, &mut alices, first).await;
    assert!(bobs.announced().contains(&blob.locator));
    assert!(!bobs.is_fetching(&blob.locator));
    assert!(blob.bob.missing_objects(&blob.space).await.is_empty());
    (bobs, alices)
}

/// Whether Bob holds a chunk of the blob.
async fn holds(blob: &Blob, chunk: u64) -> bool {
    blob.bob
        .read(&blob.space, |replica| {
            replica.holds_chunk(&blob.locator, chunk)
        })
        .await
        .unwrap()
}

/// The `ObjectWant`s among messages, as first chunk and count.
fn wants(messages: &[SyncMessage]) -> Vec<(u64, u64)> {
    messages
        .iter()
        .filter_map(|message| match message.message {
            Message::ObjectWant { first, count, .. } => Some((first, count)),
            _ => None,
        })
        .collect()
}

/// A member is asked for a range of chunks from any first index, and the
/// first chunk of its answer carries the header, whichever index that is:
/// Bob, who holds nothing of the blob, keeps chunk 1 alone, then fetches
/// the rest and reads the blob.
#[tokio::test]
async fn a_member_serves_a_range_from_any_chunk_with_the_header() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let by_alice = Acknowledger::Member(blob.alice.device_id().0);
    let by_bob = Acknowledger::Member(blob.bob.device_id().0);

    // Chunk 1, at a reader's position.
    let fetch = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 1..2, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(1, 1)]);
    assert!(bobs.awaits_chunk(&blob.locator, 1));
    // Asked for once on the session.
    assert!(blob.bob.sync_fetches(&mut bobs).await.is_empty());
    let mut answers = Vec::new();
    for message in asked {
        answers.extend(
            blob.alice
                .sync_receive(&mut alices, by_bob, message)
                .await
                .unwrap(),
        );
    }
    assert_eq!(answers.len(), 1);
    let Message::ObjectChunks { header, index, .. } = &answers[0].message else {
        panic!("{answers:?}");
    };
    assert_eq!(*index, 1);
    assert!(
        header.is_some(),
        "the first chunk of an answer carries the header"
    );
    for message in answers {
        let replies = blob
            .bob
            .sync_receive(&mut bobs, by_alice, message)
            .await
            .unwrap();
        assert!(wants(&replies).is_empty(), "{replies:?}");
    }
    assert!(holds(&blob, 1).await);
    assert!(!holds(&blob, 0).await);
    assert!(!bobs.is_fetching(&blob.locator));
    assert!(blob.bob.object(&blob.space, &blob.locator).await.is_err());

    // The rest of the object: chunk 0 alone, since chunk 1 is held.
    let rest = blob.bob.fetch_chunks(
        blob.space,
        blob.locator,
        0..u64::MAX,
        FetchPriority::ReadAhead,
    );
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 1)]);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
    drop((fetch, rest));
}

/// Nothing on the wire cancels an `ObjectWant`: the answer to a request
/// cancelled meanwhile is dropped as it arrives, and nothing is kept.
#[tokio::test]
async fn an_answer_nobody_wants_any_more_is_dropped_as_it_arrives() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let fetch = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..2, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 2)]);
    let mut answers = Vec::new();
    for message in asked {
        answers.extend(
            blob.alice
                .sync_receive(
                    &mut alices,
                    Acknowledger::Member(blob.bob.device_id().0),
                    message,
                )
                .await
                .unwrap(),
        );
    }
    assert_eq!(answers.len(), 2);
    fetch.cancel();
    for message in answers {
        let replies = blob
            .bob
            .sync_receive(
                &mut bobs,
                Acknowledger::Member(blob.alice.device_id().0),
                message,
            )
            .await
            .unwrap();
        assert!(wants(&replies).is_empty(), "{replies:?}");
    }
    assert!(!holds(&blob, 0).await);
    assert!(!holds(&blob, 1).await);
    assert!(!bobs.is_fetching(&blob.locator));
    // A request cancelled before a session heard of it is never asked.
    assert!(blob.bob.sync_fetches(&mut bobs).await.is_empty());
}

/// A chunk that arrives with no header, while Bob holds none of the
/// object, cannot be checked: it is not kept, the side that sent it is
/// not refused, and what arrives after it is kept. The chunk is asked for
/// again, and its answer carries the header.
#[tokio::test]
async fn a_chunk_with_no_header_is_not_kept_and_refuses_nothing() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
    let by_alice = Acknowledger::Member(blob.alice.device_id().0);
    assert_eq!(held_back.len(), 2);
    let Message::ObjectChunks { header, index, .. } = &held_back[1].message else {
        unreachable!()
    };
    assert_eq!((header, *index), (&None, 1));

    // Chunk 1 first: no header came with it, and none is held.
    let replies = blob
        .bob
        .sync_receive(&mut bobs, by_alice, held_back[1].clone())
        .await
        .unwrap();
    assert!(wants(&replies).is_empty(), "{replies:?}");
    assert!(!holds(&blob, 1).await);
    assert!(bobs.is_fetching(&blob.locator), "Alice is still asked");
    assert!(!bobs.awaits_chunk(&blob.locator, 1));

    // Chunk 0, with the header: kept, and chunk 1 is asked for again.
    let replies = blob
        .bob
        .sync_receive(&mut bobs, by_alice, held_back[0].clone())
        .await
        .unwrap();
    assert!(holds(&blob, 0).await);
    assert_eq!(wants(&replies), vec![(1, 1)]);

    // The same chunk again, now that the header is held, would be kept
    // as it is; the answer to the new want carries the header anyway.
    let mut alices = SyncSession::new(blob.space);
    pump(&blob, &mut bobs, &mut alices, replies).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}

/// A chunk with no header changes nothing of what Bob holds of the
/// object: under the header held it is checked and kept as any other.
#[tokio::test]
async fn a_chunk_with_no_header_is_kept_under_the_header_held() {
    let blob = blob().await;
    let (mut bobs, held_back) = sync_holding_chunks(&blob).await;
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
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
}

/// A request that starts past the object's end, made while Bob holds no
/// header of it, gets no answer. It does not hold the object up: once
/// the wait for an answer is over, the chunks are given up and what the
/// session has yet to ask for is asked.
#[tokio::test]
async fn a_request_past_the_end_does_not_hold_up_the_object() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let by_bob = Acknowledger::Member(blob.bob.device_id().0);
    let past = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 10..20, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(10, 10)]);
    for message in asked {
        let answers = blob
            .alice
            .sync_receive(&mut alices, by_bob, message)
            .await
            .unwrap();
        assert!(answers.is_empty(), "nothing is past the end: {answers:?}");
    }
    assert!(bobs.awaits_chunk(&blob.locator, 10));

    // The whole object, behind the chunks awaited.
    let whole = blob.bob.fetch_chunks(
        blob.space,
        blob.locator,
        0..u64::MAX,
        FetchPriority::Background,
    );
    assert!(blob.bob.sync_fetches(&mut bobs).await.is_empty());
    let tick = std::time::Duration::from_secs(5);
    for _ in 0..5 {
        assert!(blob.bob.sync_waited(&mut bobs, tick).await.is_empty());
    }
    let asked = blob.bob.sync_waited(&mut bobs, tick).await;
    assert_eq!(wants(&asked), vec![(0, 64)]);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
    assert!(!bobs.is_fetching(&blob.locator));
    drop((past, whole));
}
