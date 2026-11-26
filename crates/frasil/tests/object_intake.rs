//! Object chunks as a member receives them (units.md, "Reading an object";
//! "Sync", objects): each is checked as it arrives, only an object asked
//! for is taken, and one that fails leaves the object missing, asked of
//! another party. A member serves a range of chunks from any index, the
//! first of each answer with the header; a chunk that arrives with no
//! header the device can check it against is not kept, and an answer
//! nobody wants any more is dropped as it arrives. Chunks that get no
//! answer are asked for again, a few times in a row, and a device that
//! holds its blobs as files keeps only a few chunks ahead of the one it
//! takes next.
#![cfg(feature = "adapter-blobs")]

#[path = "support/provider.rs"]
mod provider;

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
    blob_of(frasil_units::limits::CHUNK_BYTES + 5).await
}

/// With a Bob that fetches every blob the space names by itself, and
/// keeps each: without it, he fetches a blob when a request names it.
fn keeping_all(blob: Blob) -> Blob {
    blob.bob.keep_all_blobs();
    blob
}

/// [`blob`] with a blob of `size` bytes.
async fn blob_of(size: usize) -> Blob {
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
    let plaintext = vec![9u8; size];
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
    let blob = keeping_all(blob().await);
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
    let blob = keeping_all(blob().await);
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
    let blob = keeping_all(blob().await);
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
    let blob = keeping_all(blob().await);
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
    let blob = keeping_all(blob().await);
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

/// Bob, who fetches a blob when it is asked for, synced with Alice: he
/// knows the blob, which she announced, and holds nothing of it.
async fn synced_on_demand(blob: &Blob) -> (SyncSession, SyncSession) {
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

/// A member that announced an object holds it whether or not this device
/// does: Bob fetches the blob whole, drops it, and asks Alice for it
/// again on the same session, where she announced it once.
#[tokio::test]
async fn a_blob_dropped_is_asked_of_the_member_that_announced_it_again() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    for round in 0..3 {
        let fetch = blob.bob.fetch_chunks(
            blob.space,
            blob.locator,
            0..u64::MAX,
            FetchPriority::Position,
        );
        let asked = blob.bob.sync_fetches(&mut bobs).await;
        assert_eq!(
            wants(&asked).first().map(|want| want.0),
            Some(0),
            "round {round}"
        );
        pump(&blob, &mut bobs, &mut alices, asked).await;
        assert_eq!(
            blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
            blob.plaintext
        );
        drop(fetch);
        blob.bob
            .drop_local_object(blob.space, &blob.locator)
            .await
            .unwrap();
        assert!(!holds(&blob, 0).await && !holds(&blob, 1).await);
        // Bob serves nothing of what he dropped, and says he does not
        // hold it (units.md, "Sync", sources between members).
        let want = SyncMessage {
            space: blob.space,
            message: Message::ObjectWant {
                locator: blob.locator,
                first: 0,
                count: 2,
            },
        };
        let by_alice = Acknowledger::Member(blob.alice.device_id().0);
        let answers = blob
            .bob
            .sync_receive(&mut bobs, by_alice, want)
            .await
            .unwrap();
        let missing = SyncMessage {
            space: blob.space,
            message: Message::ObjectMissing {
                locators: vec![blob.locator],
            },
        };
        assert_eq!(answers, vec![missing], "round {round}");
    }
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
    let blob = keeping_all(blob().await);
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
    let blob = keeping_all(blob().await);
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
    // Two minutes, less the last five seconds.
    let tick = std::time::Duration::from_secs(5);
    for _ in 0..23 {
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

/// A member that never sends a header: each chunk it sends with none is
/// not kept and is asked for again, eight times in a row for the object
/// and then no more, which the request's holder hears; the side is not
/// refused.
#[tokio::test]
async fn a_member_that_never_sends_a_header_is_asked_again_eight_times() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let by_alice = Acknowledger::Member(blob.alice.device_id().0);
    let by_bob = Acknowledger::Member(blob.bob.device_id().0);
    let fetch = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..2, FetchPriority::Position);
    let mut asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 2)]);
    // Alice's answers, each with its header taken off.
    let mut asked_again = 0;
    for round in 0.. {
        assert!(round < 32, "asked without end");
        let mut answers = Vec::new();
        for message in std::mem::take(&mut asked) {
            answers.extend(
                blob.alice
                    .sync_receive(&mut alices, by_bob, message)
                    .await
                    .unwrap(),
            );
        }
        if answers.is_empty() {
            break;
        }
        for answer in answers {
            let Message::ObjectChunks { index, chunk, .. } = answer.message else {
                panic!("{answer:?}");
            };
            let headerless = chunks_message(blob.space, blob.locator, None, index, chunk);
            let replies = blob
                .bob
                .sync_receive(&mut bobs, by_alice, headerless)
                .await
                .unwrap();
            asked_again += wants(&replies).iter().map(|(_, count)| count).sum::<u64>();
            asked.extend(replies);
        }
    }
    assert_eq!(asked_again, 8);
    assert!(!bobs.is_fetching(&blob.locator));
    assert!(!holds(&blob, 0).await && !holds(&blob, 1).await);
    assert_eq!(
        fetch.end(),
        Some(FetchEnd::Unserved),
        "the holder hears, and the side is not refused"
    );

    // With its header, the side serves the object on the same session.
    let whole = blob.bob.fetch_chunks(
        blob.space,
        blob.locator,
        0..u64::MAX,
        FetchPriority::Position,
    );
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 64)]);
    assert_eq!(whole.end(), None);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
    drop((fetch, whole));
}

/// A side that answers nothing for an object, time after time, is asked
/// eight times more and then no further: the holder of the request hears
/// that it went unserved, and a request made afterwards is asked for on
/// the same session.
#[tokio::test]
async fn a_side_that_never_answers_ends_the_request_unserved() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let fetch = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..2, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 2)]);
    let tick = std::time::Duration::from_secs(5);
    let mut again = 0;
    for _ in 0..24 * 9 {
        assert_eq!(fetch.end(), None);
        let asked = blob.bob.sync_waited(&mut bobs, tick).await;
        if !asked.is_empty() {
            assert_eq!(wants(&asked), vec![(0, 2)]);
            again += 1;
        }
    }
    assert_eq!(again, 8);
    assert_eq!(fetch.end(), Some(FetchEnd::Unserved));
    assert!(!bobs.is_fetching(&blob.locator));

    let later = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..2, FetchPriority::Position);
    assert_eq!(later.end(), None);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 2)]);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
    drop((fetch, later));
}

/// Chunks whose answer does not come within the wait are given up and
/// asked for again on the same session: with one connection, the object
/// still arrives, and the request hears of no end.
#[tokio::test]
async fn chunks_given_up_are_asked_for_again_on_the_session() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let fetch = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..2, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 2)]);
    // The ask is lost: no answer comes.
    drop(asked);
    let tick = std::time::Duration::from_secs(5);
    let mut again = Vec::new();
    for _ in 0..120 {
        again = blob.bob.sync_waited(&mut bobs, tick).await;
        if !again.is_empty() {
            break;
        }
    }
    assert_eq!(wants(&again), vec![(0, 2)], "asked for again");
    assert!(bobs.awaits_chunk(&blob.locator, 0));
    pump(&blob, &mut bobs, &mut alices, again).await;
    assert_eq!(
        blob.bob.object(&blob.space, &blob.locator).await.unwrap(),
        blob.plaintext
    );
    assert_eq!(fetch.end(), None);
}

/// A blob of which a chunk is stored sealed, from before the device held
/// its blobs as files, takes its other chunks sealed too, whichever
/// arrives: what a fetch reports as kept is kept, and the blob is held
/// as a file once whole.
#[tokio::test]
async fn a_blob_with_a_chunk_stored_sealed_takes_the_rest_sealed() {
    let blob = blob().await;
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let first = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 0..1, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 1)]);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    assert!(holds(&blob, 0).await && !holds(&blob, 1).await);

    // From now on Bob holds his blobs as files.
    let files = provider::DirProvider::new(provider::temp_dir("intake-sealed-first"));
    blob.bob.hold_all_objects(files.clone());
    let rest = blob
        .bob
        .fetch_chunks(blob.space, blob.locator, 1..2, FetchPriority::Position);
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(1, 1)]);
    pump(&blob, &mut bobs, &mut alices, asked).await;
    let record = blob
        .bob
        .held_record(&blob.space, &blob.locator)
        .await
        .expect("whole, and held as a file");
    assert_eq!(files.read(&record.token), blob.plaintext);
    assert!(!bobs.is_fetching(&blob.locator));
    drop((first, rest));
}

/// A device that holds its blobs as files takes a blob in order
/// (at-rest.md, "Held objects", receiving), and keeps only a few chunks
/// that arrive ahead of the one it takes next: a member that withholds
/// one chunk and sends the rest leaves no more than those in memory. The
/// chunks further ahead are not kept and do not count as arrived: they
/// are asked for again once the receive reaches them.
#[tokio::test]
async fn chunks_far_ahead_of_a_receive_are_asked_for_again() {
    let blob = blob_of(11 * frasil_units::limits::CHUNK_BYTES + 5).await;
    let files = provider::DirProvider::new(provider::temp_dir("intake-far-ahead"));
    blob.bob.hold_all_objects(files.clone());
    let (mut bobs, mut alices) = synced_on_demand(&blob).await;
    let by_alice = Acknowledger::Member(blob.alice.device_id().0);
    let by_bob = Acknowledger::Member(blob.bob.device_id().0);
    let fetch = blob.bob.fetch_chunks(
        blob.space,
        blob.locator,
        0..u64::MAX,
        FetchPriority::Background,
    );
    let asked = blob.bob.sync_fetches(&mut bobs).await;
    assert_eq!(wants(&asked), vec![(0, 64)]);
    let mut answers = Vec::new();
    for message in asked {
        answers.extend(
            blob.alice
                .sync_receive(&mut alices, by_bob, message)
                .await
                .unwrap(),
        );
    }
    assert_eq!(answers.len(), 12);
    // Chunk 1 is withheld; chunks 2 to 11 arrive.
    let withheld = answers.remove(1);
    for answer in answers {
        let replies = blob
            .bob
            .sync_receive(&mut bobs, by_alice, answer)
            .await
            .unwrap();
        assert!(wants(&replies).is_empty(), "{replies:?}");
    }
    assert!(bobs.awaits_chunk(&blob.locator, 1));
    assert!(
        blob.bob
            .held_record(&blob.space, &blob.locator)
            .await
            .is_none()
    );

    // Chunk 1 arrives: the receive takes it and the eight chunks that
    // waited for it, and the last two are asked for again.
    let replies = blob
        .bob
        .sync_receive(&mut bobs, by_alice, withheld)
        .await
        .unwrap();
    assert_eq!(wants(&replies), vec![(10, 2)]);
    assert!(
        blob.bob
            .held_record(&blob.space, &blob.locator)
            .await
            .is_none()
    );
    pump(&blob, &mut bobs, &mut alices, replies).await;
    let record = blob
        .bob
        .held_record(&blob.space, &blob.locator)
        .await
        .expect("whole, and held as a file");
    assert_eq!(files.read(&record.token), blob.plaintext);
    assert_eq!(fetch.end(), None);
}
