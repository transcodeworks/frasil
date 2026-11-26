//! Which members a device counts as sources of an object, and for how
//! long (units.md, "Sync", sources between members): a member announces
//! an object in `ObjectHave` when it becomes whole there, and a member
//! asked for an object it does not hold whole answers `ObjectMissing`,
//! after which it is no source of it until it announces it again. An
//! announcement asks for nothing in return, and a session keeps a bounded
//! number of announcements of objects its replica does not know; past
//! the bound, it counts the member a source of every object. A read ends
//! once every member is done with it: one said it lacks the object, and
//! the others never announced it.
#![cfg(feature = "adapter-blobs")]

use frasil::advanced::sync::{MAX_UNKNOWN_ANNOUNCED, SyncSession};
use frasil::advanced::{Acknowledger, AdapterRegistry, Engine, FetchEnd, FetchPriority, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::limits::MAX_MESSAGE_ITEMS;
use frasil_units::messages::{FIRST_IGNORABLE, Message, SyncMessage};

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

/// Alice's space with a blob of two chunks she wrote, and Bob and Carol,
/// members with its history.
struct Space {
    alice: Engine,
    bob: Engine,
    carol: Engine,
    space: EventId,
    locator: [u8; 64],
    plaintext: Vec<u8>,
}

async fn space() -> Space {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for member in [&bob, &carol] {
        alice
            .grant_device(
                space,
                member.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let files = alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    let plaintext = vec![9u8; frasil_units::limits::CHUNK_BYTES + 5];
    let (_, locator) = alice
        .put_blob(space, &files, Some("photo"), &plaintext)
        .await
        .unwrap();
    bob.follow(space).await;
    carol.follow(space).await;
    Space {
        alice,
        bob,
        carol,
        space,
        locator,
        plaintext,
    }
}

/// One side of a session pair: the device and its session.
struct Side<'a> {
    device: &'a Engine,
    session: SyncSession,
}

/// A session pair between two devices of the space.
struct Pair<'a> {
    a: Side<'a>,
    b: Side<'a>,
    /// How many messages went either way.
    sent: usize,
}

impl<'a> Pair<'a> {
    fn new(space: EventId, a: &'a Engine, b: &'a Engine) -> Self {
        Self {
            a: Side {
                device: a,
                session: SyncSession::new(space),
            },
            b: Side {
                device: b,
                session: SyncSession::new(space),
            },
            sent: 0,
        }
    }

    /// Both sides open, and messages go both ways until neither has more;
    /// then each side's connection ticks.
    async fn sync(&mut self) {
        let to_b = self.a.device.sync_start(&mut self.a.session).await.unwrap();
        let to_a = self.b.device.sync_start(&mut self.b.session).await.unwrap();
        self.pump(to_b, to_a).await;
        self.tick().await;
    }

    /// Each side's connection ticks, announcing what became whole at it
    /// since its last tick, and the pair goes on until quiet: what either
    /// side announces with units after it is announced again when it
    /// becomes whole.
    async fn tick(&mut self) {
        let to_b = self.a.device.sync_announce(&mut self.a.session).await;
        let to_a = self.b.device.sync_announce(&mut self.b.session).await;
        self.pump(to_b, to_a).await;
    }

    /// Carries messages both ways until neither side has more.
    async fn pump(&mut self, mut to_b: Vec<SyncMessage>, mut to_a: Vec<SyncMessage>) {
        for _ in 0..64 {
            if to_a.is_empty() && to_b.is_empty() {
                return;
            }
            let (a, b) = (self.a.device, self.b.device);
            for message in std::mem::take(&mut to_b) {
                self.sent += 1;
                to_a.extend(receive(a, &mut self.b, message).await);
            }
            for message in std::mem::take(&mut to_a) {
                self.sent += 1;
                to_b.extend(receive(b, &mut self.a, message).await);
            }
        }
        panic!("the sides never went quiet");
    }

    /// Side `a` announces the objects that became whole at it, as its
    /// connection does on its next tick, and the pair goes on until quiet.
    async fn a_announces(&mut self, whole: &[[u8; 64]]) -> Vec<SyncMessage> {
        self.a.session.note_whole(whole);
        let have = self.a.device.sync_announce(&mut self.a.session).await;
        self.pump(have.clone(), Vec::new()).await;
        have
    }
}

/// `side` takes a message from `from`, and answers.
async fn receive(from: &Engine, side: &mut Side<'_>, message: SyncMessage) -> Vec<SyncMessage> {
    side.device
        .sync_receive(
            &mut side.session,
            Acknowledger::Member(from.device_id().0),
            message,
        )
        .await
        .unwrap()
}

fn missing(space: EventId, locators: Vec<[u8; 64]>) -> SyncMessage {
    SyncMessage {
        space,
        message: Message::ObjectMissing { locators },
    }
}

/// Fetches the blob whole on side `a` of a pair, from side `b`.
async fn fetch_whole(s: &Space, pair: &mut Pair<'_>) {
    let fetch =
        pair.a
            .device
            .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = pair.a.device.sync_fetches(&mut pair.a.session).await;
    assert!(!asked.is_empty(), "the blob is asked for");
    pair.pump(asked, Vec::new()).await;
    assert_eq!(
        pair.a.device.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    drop(fetch);
}

async fn holds(device: &Engine, s: &Space) -> bool {
    device
        .read(&s.space, |replica| replica.holds_object(&s.locator))
        .await
        .unwrap()
}

/// The device that put a blob and dropped it reads it back from the
/// member that fetched it whole on the same session: the member announced
/// it as it became whole there.
#[tokio::test]
async fn a_blob_put_and_dropped_is_read_back_from_the_member_that_fetched_it() {
    let s = space().await;
    // Bob, side a, fetches the blob from Alice.
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    fetch_whole(&s, &mut bob_alice).await;
    let have = bob_alice.a_announces(&[s.locator]).await;
    assert_eq!(have.len(), 1);
    assert!(bob_alice.b.session.announced().contains(&s.locator));

    // Alice drops it, and reads it from Bob.
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    assert!(!holds(&s.alice, &s).await);
    let fetch = s
        .alice
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.alice.sync_fetches(&mut bob_alice.b.session).await;
    assert!(!asked.is_empty(), "Alice asks Bob");
    bob_alice.pump(Vec::new(), asked).await;
    assert_eq!(
        s.alice.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    assert_eq!(fetch.end(), None);
}

/// After a put and a whole fetch, an announcement brings nothing back:
/// Alice, who holds the blob, asks for nothing and announces nothing, and
/// neither side has more to say.
#[tokio::test]
async fn an_announcement_of_an_object_held_asks_for_nothing() {
    let s = space().await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    fetch_whole(&s, &mut bob_alice).await;
    let before = bob_alice.sent;
    let have = bob_alice.a_announces(&[s.locator]).await;
    // One `ObjectHave`, and no answer to it.
    assert_eq!(have.len(), 1);
    assert_eq!(bob_alice.sent - before, 1);
    // Nothing more to announce on either side, and nothing to fetch.
    assert!(!bob_alice.a.session.has_announcements());
    assert!(!bob_alice.b.session.has_announcements());
    assert!(
        s.alice
            .sync_announce(&mut bob_alice.b.session)
            .await
            .is_empty()
    );
    assert!(
        s.alice
            .sync_fetches(&mut bob_alice.b.session)
            .await
            .is_empty()
    );
    assert!(
        s.bob
            .sync_fetches(&mut bob_alice.a.session)
            .await
            .is_empty()
    );
    let waited = std::time::Duration::from_secs(5);
    assert!(
        s.alice
            .sync_waited(&mut bob_alice.b.session, waited)
            .await
            .is_empty()
    );
    assert!(
        s.bob
            .sync_waited(&mut bob_alice.a.session, waited)
            .await
            .is_empty()
    );
}

/// Objects that become whole close together go in as few `ObjectHave`s as
/// the message's limit allows, and only those still held whole.
#[test]
fn objects_that_become_whole_together_are_announced_together() {
    let space = EventId([1; 32]);
    let mut session = SyncSession::new(space);
    let whole: Vec<[u8; 64]> = (0..10_000u32)
        .map(|i| {
            let mut locator = [0; 64];
            locator[..4].copy_from_slice(&i.to_be_bytes());
            locator
        })
        .collect();
    for locator in &whole {
        session.note_whole(&[*locator]);
    }
    // One of them was dropped again before the tick.
    let dropped = whole[17];
    let have = session.take_announcements(|locator| *locator != dropped);
    let sizes: Vec<usize> = have
        .iter()
        .map(|message| match &message.message {
            Message::ObjectHave { locators, counts } => {
                assert!(counts.is_none());
                assert!(!locators.contains(&dropped));
                locators.len()
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        sizes,
        vec![
            MAX_MESSAGE_ITEMS,
            MAX_MESSAGE_ITEMS,
            10_000 - 1 - 2 * MAX_MESSAGE_ITEMS
        ]
    );
    assert!(!session.has_announcements());
    assert!(session.take_announcements(|_| true).is_empty());
}

/// Three members: Alice and Carol hold the blob and announced it to Bob.
/// Alice drops it. Bob asks her first: she answers `ObjectMissing`, he no
/// longer counts her as a source and stops waiting on her, and his read
/// completes from Carol, on the same sessions and with no wait.
#[tokio::test]
async fn a_member_asked_for_what_it_dropped_says_so_and_another_serves() {
    let s = space().await;
    // Carol fetches the blob whole from Alice.
    let mut carol_alice = Pair::new(s.space, &s.carol, &s.alice);
    carol_alice.sync().await;
    fetch_whole(&s, &mut carol_alice).await;
    // Bob syncs with Alice, who announces the blob with the unit that
    // names it, and with Carol, who announces it as her connection does
    // once it admits him.
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    assert!(bob_alice.a.session.announced().contains(&s.locator));
    let mut carol_bob = Pair::new(s.space, &s.carol, &s.bob);
    carol_bob.sync().await;
    carol_bob.a_announces(&[s.locator]).await;
    assert!(carol_bob.b.session.announced().contains(&s.locator));
    // Both of Bob's sessions take his requests.
    assert!(
        s.bob
            .sync_fetches(&mut carol_bob.b.session)
            .await
            .is_empty()
    );
    assert!(
        s.bob
            .sync_fetches(&mut bob_alice.a.session)
            .await
            .is_empty()
    );

    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    // Bob asks Alice first.
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    let mut answers = Vec::new();
    for want in asked {
        answers.extend(receive(&s.bob, &mut bob_alice.b, want).await);
    }
    assert_eq!(answers, vec![missing(s.space, vec![s.locator])]);
    for answer in answers {
        assert!(receive(&s.alice, &mut bob_alice.a, answer).await.is_empty());
    }
    assert!(!bob_alice.a.session.announced().contains(&s.locator));
    assert!(!bob_alice.a.session.is_fetching(&s.locator));
    // Carol still will: the request goes on.
    assert_eq!(fetch.end(), None);

    let asked = s.bob.sync_fetches(&mut carol_bob.b.session).await;
    assert!(!asked.is_empty());
    carol_bob.pump(Vec::new(), asked).await;
    assert_eq!(
        s.bob.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    drop(fetch);

    // A later read does not ask Alice again on the session.
    s.bob.drop_local_object(s.space, &s.locator).await.unwrap();
    let later = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    assert!(
        s.bob
            .sync_fetches(&mut bob_alice.a.session)
            .await
            .is_empty()
    );
    let asked = s.bob.sync_fetches(&mut carol_bob.b.session).await;
    assert!(!asked.is_empty());
    carol_bob.pump(Vec::new(), asked).await;
    assert!(holds(&s.bob, &s).await);
    drop(later);
}

/// With one member, which says it no longer holds the blob, the read ends
/// at once: no wait for chunks that do not come.
#[tokio::test]
async fn a_read_no_member_will_serve_ends_when_the_member_says_so() {
    let s = space().await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    let mut answers = Vec::new();
    for want in asked {
        answers.extend(receive(&s.bob, &mut bob_alice.b, want).await);
    }
    assert_eq!(answers, vec![missing(s.space, vec![s.locator])]);
    for answer in answers {
        receive(&s.alice, &mut bob_alice.a, answer).await;
    }
    assert_eq!(fetch.end(), Some(FetchEnd::Unserved));
    assert!(!bob_alice.a.session.is_fetching(&s.locator));
}

/// A member that dropped a blob and holds it whole again is a source of it
/// again: Alice drops the blob and says so to Bob, fetches it back from
/// Carol, and announces it; Bob then reads it from her.
#[tokio::test]
async fn a_member_that_holds_a_blob_again_is_a_source_again() {
    let s = space().await;
    let mut carol_alice = Pair::new(s.space, &s.carol, &s.alice);
    carol_alice.sync().await;
    fetch_whole(&s, &mut carol_alice).await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;

    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    bob_alice.pump(asked, Vec::new()).await;
    assert!(!bob_alice.a.session.announced().contains(&s.locator));
    drop(fetch);

    // Alice reads it from Carol, who announces it to her, and it is whole
    // at Alice again: her connection with Bob announces it.
    carol_alice.a_announces(&[s.locator]).await;
    let fetch = s
        .alice
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.alice.sync_fetches(&mut carol_alice.b.session).await;
    assert!(!asked.is_empty());
    carol_alice.pump(Vec::new(), asked).await;
    assert!(holds(&s.alice, &s).await);
    drop(fetch);
    let mut alice_bob = Pair {
        a: bob_alice.b,
        b: bob_alice.a,
        sent: 0,
    };
    alice_bob.a_announces(&[s.locator]).await;
    assert!(alice_bob.b.session.announced().contains(&s.locator));

    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut alice_bob.b.session).await;
    assert!(!asked.is_empty(), "Bob asks Alice again");
    alice_bob.pump(Vec::new(), asked).await;
    assert_eq!(
        s.bob.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    assert_eq!(fetch.end(), None);
}

/// A member announces at most 65,536 objects the replica does not know
/// that a session keeps; every object the replica knows is kept whatever
/// came before it, and is asked for.
#[tokio::test]
async fn a_session_keeps_a_bounded_number_of_objects_it_does_not_know() {
    let s = space().await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    // A flood of junk from Alice's side, past the bound.
    let mut count = 0u32;
    let flood = MAX_UNKNOWN_ANNOUNCED / MAX_MESSAGE_ITEMS + 2;
    for _ in 0..flood {
        let locators: Vec<[u8; 64]> = (0..MAX_MESSAGE_ITEMS)
            .map(|_| {
                count += 1;
                let mut locator = [0xff; 64];
                locator[..4].copy_from_slice(&count.to_be_bytes());
                locator
            })
            .collect();
        let have = SyncMessage {
            space: s.space,
            message: Message::ObjectHave {
                locators,
                counts: None,
            },
        };
        receive(&s.alice, &mut bob_alice.a, have).await;
    }
    // The blob, which the replica knows, is still counted, and the junk
    // past the bound is not.
    let announced = bob_alice.a.session.announced();
    assert!(announced.contains(&s.locator));
    assert_eq!(announced.len(), MAX_UNKNOWN_ANNOUNCED + 1);

    // A blob put after the flood, announced with the unit that names it,
    // is kept and served.
    let files = s
        .alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    let later = vec![3u8; 100];
    let (unit, locator) = s
        .alice
        .put_blob(s.space, &files, Some("later"), &later)
        .await
        .unwrap();
    let offered = s
        .alice
        .sync_offer(&mut bob_alice.b.session, &[unit])
        .await
        .unwrap();
    bob_alice.pump(Vec::new(), offered).await;
    // Past the bound, Bob counts Alice a source of every object, and no
    // longer works out which ones his replica knows.
    assert!(bob_alice.a.session.is_source(&locator));
    let fetch = s
        .bob
        .fetch_chunks(s.space, locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    bob_alice.pump(asked, Vec::new()).await;
    assert_eq!(s.bob.object(&s.space, &locator).await.unwrap(), later);
    drop(fetch);
}

/// The bound at the session alone: objects the replica does not know
/// count toward it, those it knows do not, and one the other side says it
/// does not hold makes room again.
#[test]
fn the_bound_counts_only_objects_the_replica_does_not_know() {
    let mut session = SyncSession::new(EventId([1; 32]));
    let locator = |i: u32, tag: u8| {
        let mut locator = [tag; 64];
        locator[..4].copy_from_slice(&i.to_be_bytes());
        locator
    };
    let unknown: Vec<[u8; 64]> = (0..MAX_UNKNOWN_ANNOUNCED as u32 + 10)
        .map(|i| locator(i, 0))
        .collect();
    session.note_announced(&unknown);
    assert_eq!(session.announced().len(), MAX_UNKNOWN_ANNOUNCED);
    let known: Vec<[u8; 64]> = (0..10).map(|i| locator(i, 1)).collect();
    session.note_announced_with(&known, |_| true);
    assert_eq!(session.announced().len(), MAX_UNKNOWN_ANNOUNCED + 10);
    assert!(known.iter().all(|l| session.announced().contains(l)));
    let late = locator(u32::MAX, 2);
    session.note_announced(&[late]);
    assert!(!session.announced().contains(&late));
    // Past the bound, the other side is a possible source of every
    // object, announced or not.
    assert!(session.is_source(&late));
    assert!(session.is_source(&locator(7, 9)));
    assert!(session.has_sources());
}

/// Below the bound, the other side is a source only of what it announced.
#[test]
fn below_the_bound_a_member_is_a_source_only_of_what_it_announced() {
    let mut session = SyncSession::new(EventId([1; 32]));
    assert!(!session.has_sources());
    session.note_announced(&[[1; 64]]);
    assert!(session.is_source(&[1; 64]));
    assert!(!session.is_source(&[2; 64]));
}

/// A side that drops type 64, as a receiver that does not know it does
/// (units.md, 2.14), still gets the object. `ObjectMissing` is of an
/// ignorable type, sent between members only. Bob drops Alice's answer:
/// he goes on counting her as a source and awaiting the chunks, and his
/// request goes on. Alice holds the blob whole again and announces it in
/// `ObjectHave`; Bob gives up the chunks he awaited after the wait, asks
/// for them again, and Alice serves them.
#[tokio::test]
async fn a_side_that_drops_type_64_waits_and_asks_again() {
    let s = space().await;
    // Its type is in the ignorable range, between members only.
    let answer = missing(s.space, vec![s.locator]);
    assert!(answer.message.type_code() >= FIRST_IGNORABLE);
    assert!(answer.message.member_connections_only());

    let mut carol_alice = Pair::new(s.space, &s.carol, &s.alice);
    carol_alice.sync().await;
    fetch_whole(&s, &mut carol_alice).await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    let mut answers = Vec::new();
    for want in asked {
        answers.extend(receive(&s.bob, &mut bob_alice.b, want).await);
    }
    // What Bob keeps of Alice's answer when he drops type 64: nothing.
    assert_eq!(answers, vec![answer]);
    answers.retain(|message| message.message.type_code() < FIRST_IGNORABLE);
    assert!(answers.is_empty());
    assert!(bob_alice.a.session.is_fetching(&s.locator));
    assert!(bob_alice.a.session.announced().contains(&s.locator));
    assert_eq!(fetch.end(), None);

    // Alice fetches the blob back from Carol, and announces it whole.
    carol_alice.a_announces(&[s.locator]).await;
    let refetch = s
        .alice
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.alice.sync_fetches(&mut carol_alice.b.session).await;
    carol_alice.pump(Vec::new(), asked).await;
    assert!(holds(&s.alice, &s).await);
    drop(refetch);
    bob_alice.b.session.note_whole(&[s.locator]);
    let have = s.alice.sync_announce(&mut bob_alice.b.session).await;
    assert!(
        have.iter()
            .all(|message| matches!(message.message, Message::ObjectHave { .. }))
    );
    bob_alice.pump(Vec::new(), have).await;

    // Bob's chunks are given up after the wait, asked for again, and
    // served.
    let waited = s
        .bob
        .sync_waited(
            &mut bob_alice.a.session,
            std::time::Duration::from_secs(121),
        )
        .await;
    assert!(!waited.is_empty(), "the chunks are asked for again");
    bob_alice.pump(waited, Vec::new()).await;
    assert_eq!(
        s.bob.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    drop(fetch);
}

/// Two members, and neither will serve the blob: Alice, who announced it,
/// says she no longer holds it, and Carol never announced it. Bob's read
/// ends as soon as both connections are done with it, rather than after
/// the wait for chunks: Carol's, once it looks at the request, declines it
/// as one its member is no source of.
#[tokio::test]
async fn a_read_ends_when_one_member_says_missing_and_the_other_never_announced_it() {
    let s = space().await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    assert!(bob_alice.a.session.announced().contains(&s.locator));
    // Carol holds the space's units, not the blob: she announces nothing.
    let mut carol_bob = Pair::new(s.space, &s.carol, &s.bob);
    carol_bob.sync().await;
    assert!(!holds(&s.carol, &s).await);
    assert!(!carol_bob.b.session.is_source(&s.locator));
    // Both of Bob's sessions take his requests.
    for session in [&mut bob_alice.a.session, &mut carol_bob.b.session] {
        assert!(s.bob.sync_fetches(session).await.is_empty());
    }

    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    let mut answers = Vec::new();
    for want in asked {
        answers.extend(receive(&s.bob, &mut bob_alice.b, want).await);
    }
    assert_eq!(answers, vec![missing(s.space, vec![s.locator])]);
    for answer in answers {
        receive(&s.alice, &mut bob_alice.a, answer).await;
    }
    // Carol's connection has not looked at the request yet.
    assert_eq!(fetch.end(), None);
    // It does, as on the change of the device's requests: it asks Carol
    // for nothing, and the request ends.
    assert!(
        s.bob
            .sync_fetches(&mut carol_bob.b.session)
            .await
            .is_empty()
    );
    assert_eq!(fetch.end(), Some(FetchEnd::Unserved));
}

/// An `ObjectMissing` for an object the member was never asked for, and
/// never announced, changes nothing: Bob's request goes on.
#[tokio::test]
async fn object_missing_for_what_was_never_asked_changes_nothing() {
    let s = space().await;
    // Alice drops the blob before she meets Bob, so she does not announce
    // it, and Bob's request is not asked of her.
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    assert!(!bob_alice.a.session.is_source(&s.locator));
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    assert!(
        s.bob
            .sync_fetches(&mut bob_alice.a.session)
            .await
            .is_empty()
    );
    let answers = receive(
        &s.alice,
        &mut bob_alice.a,
        missing(s.space, vec![s.locator]),
    )
    .await;
    assert!(answers.is_empty());
    // Not left unserved on Bob's one connection: no end.
    assert_eq!(fetch.end(), None);
}

/// A member that said it lacks a blob, holds it whole again and announces
/// it is asked for the same request again, and is counted as serving it:
/// when Bob's other source, Carol, says she lacks the blob, the request
/// goes on, and Alice serves it.
#[tokio::test]
async fn a_member_asked_again_after_saying_missing_serves_the_same_request() {
    let s = space().await;
    let mut carol_alice = Pair::new(s.space, &s.carol, &s.alice);
    carol_alice.sync().await;
    fetch_whole(&s, &mut carol_alice).await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    let mut carol_bob = Pair::new(s.space, &s.carol, &s.bob);
    carol_bob.sync().await;
    carol_bob.a_announces(&[s.locator]).await;
    for session in [&mut bob_alice.a.session, &mut carol_bob.b.session] {
        assert!(s.bob.sync_fetches(session).await.is_empty());
    }

    // Alice drops the blob, and says so when Bob asks.
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    bob_alice.pump(asked, Vec::new()).await;
    assert!(!bob_alice.a.session.is_source(&s.locator));
    assert_eq!(fetch.end(), None);

    // She fetches it back from Carol, who announced it to her, and
    // announces it to Bob, who asks her again for the same request.
    carol_alice.a_announces(&[s.locator]).await;
    let refetch = s
        .alice
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.alice.sync_fetches(&mut carol_alice.b.session).await;
    carol_alice.pump(Vec::new(), asked).await;
    assert!(holds(&s.alice, &s).await);
    drop(refetch);
    bob_alice.b.session.note_whole(&[s.locator]);
    let mut wants = Vec::new();
    for have in s.alice.sync_announce(&mut bob_alice.b.session).await {
        wants.extend(receive(&s.alice, &mut bob_alice.a, have).await);
    }
    assert!(!wants.is_empty(), "Bob asks Alice again");

    // Carol says she lacks it: Alice still serves the request.
    let answers = receive(
        &s.carol,
        &mut carol_bob.b,
        missing(s.space, vec![s.locator]),
    )
    .await;
    assert!(answers.is_empty());
    assert_eq!(fetch.end(), None);
    bob_alice.pump(wants, Vec::new()).await;
    assert_eq!(
        s.bob.object(&s.space, &s.locator).await.unwrap(),
        s.plaintext
    );
    assert_eq!(fetch.end(), None);
}

/// Past the bound, a newcomer still reads what the member holds: Alice
/// floods Bob's session past the bound, then puts a blob whose unit
/// reaches Bob without its announcement. Bob asks Alice for it all the
/// same, and she serves it; once she says she lacks one, Bob asks her for
/// it no more.
#[tokio::test]
async fn past_the_bound_a_member_is_asked_for_every_object_the_replica_knows() {
    let s = space().await;
    let mut bob_alice = Pair::new(s.space, &s.bob, &s.alice);
    bob_alice.sync().await;
    let mut count = 0u32;
    for _ in 0..MAX_UNKNOWN_ANNOUNCED / MAX_MESSAGE_ITEMS + 1 {
        let locators: Vec<[u8; 64]> = (0..MAX_MESSAGE_ITEMS)
            .map(|_| {
                count += 1;
                let mut locator = [0xff; 64];
                locator[..4].copy_from_slice(&count.to_be_bytes());
                locator
            })
            .collect();
        let have = SyncMessage {
            space: s.space,
            message: Message::ObjectHave {
                locators,
                counts: None,
            },
        };
        receive(&s.alice, &mut bob_alice.a, have).await;
    }

    // A blob put now: its unit reaches Bob, and not its announcement.
    let files = s
        .alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    let later = vec![3u8; 100];
    let (unit, locator) = s
        .alice
        .put_blob(s.space, &files, Some("later"), &later)
        .await
        .unwrap();
    let mut offered = s
        .alice
        .sync_offer(&mut bob_alice.b.session, &[unit])
        .await
        .unwrap();
    offered.retain(|message| !matches!(message.message, Message::ObjectHave { .. }));
    bob_alice.pump(Vec::new(), offered).await;
    assert!(!bob_alice.a.session.announced().contains(&locator));
    assert!(bob_alice.a.session.is_source(&locator));
    let fetch = s
        .bob
        .fetch_chunks(s.space, locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty(), "Bob asks Alice");
    bob_alice.pump(asked, Vec::new()).await;
    assert_eq!(s.bob.object(&s.space, &locator).await.unwrap(), later);
    drop(fetch);

    // Alice dropped the first blob: asked, she says so, and is no longer
    // asked for it on the session.
    s.alice
        .drop_local_object(s.space, &s.locator)
        .await
        .unwrap();
    let fetch = s
        .bob
        .fetch_chunks(s.space, s.locator, 0..u64::MAX, FetchPriority::Position);
    let asked = s.bob.sync_fetches(&mut bob_alice.a.session).await;
    assert!(!asked.is_empty());
    bob_alice.pump(asked, Vec::new()).await;
    assert!(!bob_alice.a.session.is_source(&s.locator));
    assert_eq!(fetch.end(), Some(FetchEnd::Unserved));
}

/// A blob put while a session is open is announced once, with the unit
/// that names it, and not again on the connection's next tick, whichever
/// the device hears of first.
#[tokio::test]
async fn a_blob_put_is_announced_once() {
    let s = space().await;
    let mut alice_bob = Pair::new(s.space, &s.alice, &s.bob);
    alice_bob.sync().await;
    let files = s
        .alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    for (i, whole_first) in [false, true].into_iter().enumerate() {
        let (unit, locator) = s
            .alice
            .put_blob(s.space, &files, None, &[i as u8; 100])
            .await
            .unwrap();
        if whole_first {
            alice_bob.a.session.note_whole(&[locator]);
        }
        let offered = s
            .alice
            .sync_offer(&mut alice_bob.a.session, &[unit])
            .await
            .unwrap();
        let haves = offered
            .iter()
            .filter(|message| {
                matches!(&message.message, Message::ObjectHave { locators, .. } if locators.contains(&locator))
            })
            .count();
        assert_eq!(haves, 1, "with the unit");
        if !whole_first {
            alice_bob.a.session.note_whole(&[locator]);
        }
        assert!(
            s.alice
                .sync_announce(&mut alice_bob.a.session)
                .await
                .is_empty(),
            "not again on the tick"
        );
        alice_bob.pump(offered, Vec::new()).await;
        assert!(alice_bob.b.session.announced().contains(&locator));
    }
}
