//! Checkpoints with a peer on loopback (roster.md, 3.15 Checkpoints;
//! identity.md, 3.16 List checkpoints; peers.md, "Skeleton cuts" and
//! "Truncation"): a checkpoint that takes effect once every administrator
//! wrote after it; a device that forgets what came before it and keeps
//! syncing; a peer that truncates after `cut_retention` and then serves a
//! newcomer from the checkpoint; late work re-sent, re-signed or reported;
//! two concurrent checkpoints that settle on the smaller ID; and a person's
//! list checkpoint that drops a removed device from every space. Every
//! wait has a deadline, and nothing leaves the host.
//!
//! Each device proposes and forgets only when the scenario says so: its
//! policy is manual and keeps everything, and its upkeep still votes,
//! re-sends late edits and re-signs late removals by itself.

use frasil::advanced::platform::ManualClock;
use frasil::{
    CheckpointId, CheckpointPolicy, Device, Event, Events, LateChangeKind, Level, Options, Space,
    Storage,
};
use frasil_conformance::spawn_loopback;
use frasil_events::{EventId, kind};
use frasil_space::{HistoryMode, MemberRef, Via};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest one wait polls its condition.
const DEADLINE: Duration = Duration::from_secs(90);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// A device in memory whose checkpoint policy is manual and keeps
/// everything.
async fn device(key: u8) -> Device {
    let device = Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

/// [`device`], on a clock moved by hand: a device and a peer whose
/// timelines are moved on together agree on what has expired.
async fn device_at(key: u8, clock: &Arc<ManualClock>) -> Device {
    let device = Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().clock(clock.clone()),
    )
    .await
    .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

/// The system's wall clock, in seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// A space's ID as the engine names it.
fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// `by` grants `to` a level "with history", and hands `to` every event it
/// holds of the space, so that `to` holds the space before it connects.
/// Returns the grant.
async fn share(by: &Device, space: &Space, to: &Device, level: Level) -> EventId {
    let id = event_of(space);
    let grant = by
        .engine()
        .grant_device_at(
            id,
            to.engine().public_keys().clone(),
            level,
            (level == Level::Administer).then_some(255),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .expect("a grant");
    to.engine().follow(id).await;
    to.engine()
        .ingest(id, by.engine().events(&id).await)
        .await
        .expect("ingested");
    grant
}

/// Hands every event `from` holds of the space, and the objects `to`
/// lacks, to `to`, as a member connection would.
async fn hand(from: &Device, to: &Device, space: &EventId) {
    to.engine()
        .ingest(*space, from.engine().events(space).await)
        .await
        .expect("ingested");
    for locator in to.engine().missing_objects(space).await {
        if let Some(stored) = from.engine().stored_object(space, &locator).await {
            to.engine()
                .receive_object(*space, &locator, &stored)
                .await
                .expect("an object");
        }
    }
}

/// The checkpoint in effect at a device's replica of the space.
async fn in_effect(space: &Space) -> Option<CheckpointId> {
    space.checkpoints().await.ok()?.in_effect
}

/// The next event the stream gives that `wanted` accepts.
async fn next_matching(events: &mut Events, wanted: impl Fn(&Event) -> bool) -> Event {
    within(async {
        loop {
            let event = events.next().await.expect("the device is open");
            if wanted(&event) {
                return event;
            }
        }
    })
    .await
}

/// Writes `words` at the end of a document's body.
async fn append(document: &frasil::Document, words: &str) {
    document
        .edit(|doc| {
            let body = doc.get_text("body");
            body.insert(body.len_unicode(), words)
        })
        .await
        .expect("an edit");
}

/// Waits until the device's copy of a document reads `expected`.
async fn reads(space: &Space, document: &frasil::Document, expected: &str) {
    let id = document.id();
    until(|| async {
        match space.document(id).await {
            Ok(found) => found.text("body").await.is_ok_and(|text| text == expected),
            Err(_) => false,
        }
    })
    .await;
}

/// The last unit `device` signed in the space.
async fn last_unit(device: &Device, space: &EventId) -> EventId {
    let me = device.engine().device_id();
    device
        .engine()
        .events(space)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|event| event.kind() == kind::UNIT && *event.author() == me)
        .map(|event| event.id())
        .next_back()
        .expect("a unit of the device")
}

/// The name of an event's class at a device, `None` while valid or not
/// held.
async fn class_of(device: &Device, space: &EventId, event: &EventId) -> Option<&'static str> {
    device
        .engine()
        .read(space, |replica| replica.status(event).copied())
        .await
        .ok()
        .flatten()
        .and_then(|status| status.class())
        .map(|class| frasil_base::errors::Class::name(class))
}

/// Whether a member is in the space's roster at a device.
async fn is_in(device: &Device, space: &EventId, member: &Device) -> bool {
    let member = MemberRef::device(member.engine().device_id());
    device
        .engine()
        .read(space, |replica| replica.roster().is_in(&member))
        .await
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpoint_takes_effect_once_every_administrator_wrote_after_it() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    share(&alice, &space, &bob, Level::Administer).await;
    alice.connect(&peer.origin).await.unwrap();
    let mut events = alice.events();

    let c = within(space.propose_checkpoint()).await.unwrap();
    let status = space.checkpoints().await.unwrap();
    assert_eq!(status.in_effect, None);
    assert_eq!(status.pending.len(), 1);
    assert_eq!(status.pending[0].id, c);
    assert_eq!(
        status.pending[0].waiting_for,
        vec![bob.id()],
        "it waits for Bob alone: Alice voted by the checkpoint itself"
    );
    next_matching(&mut events, |event| {
        matches!(event, Event::CheckpointPending { checkpoint, waiting_for, .. }
            if *checkpoint == c && *waiting_for == vec![bob.id()])
    })
    .await;

    // Bob connects; his device writes after the checkpoint, by an anchor
    // if it has nothing else, and the checkpoint takes effect at both.
    bob.connect(&peer.origin).await.unwrap();
    let bobs_space = bob.space(space.id()).await.unwrap();
    until(|| async { in_effect(&bobs_space).await == Some(c) }).await;
    until(|| async { in_effect(&space).await == Some(c) }).await;
    next_matching(
        &mut events,
        |event| matches!(event, Event::CheckpointInEffect { checkpoint, .. } if *checkpoint == c),
    )
    .await;
    let status = space.checkpoints().await.unwrap();
    assert!(status.pending.is_empty());
    assert_eq!(status.epoch, 1);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_forgot_keeps_syncing() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let carol = device(3).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    append(&note, "one").await;
    share(&alice, &space, &carol, Level::Write).await;
    alice.connect(&peer.origin).await.unwrap();
    carol.connect(&peer.origin).await.unwrap();
    let carols_space = carol.space(space.id()).await.unwrap();
    reads(&carols_space, &note, "one").await;
    // Carol, a writer granted before the checkpoint, edits before it.
    let carols_note = carols_space.document(note.id()).await.unwrap();
    append(&carols_note, ", zero").await;
    reads(&space, &note, "one, zero").await;
    // Dave reads and keeps everything.
    let dave = device(4).await;
    share(&alice, &space, &dave, Level::Read).await;
    dave.connect(&peer.origin).await.unwrap();
    let daves_space = dave.space(space.id()).await.unwrap();

    // Alice administers alone: her checkpoint is in effect at once. She
    // forgets what came before it.
    let c = within(space.propose_checkpoint()).await.unwrap();
    assert_eq!(in_effect(&space).await, Some(c));
    // Her pseudonym votes for the checkpoint's cut, which the upkeep below
    // would otherwise sign beside forgetting. A device forgets nothing its
    // outbox still holds.
    let id = event_of(&space);
    alice.engine().acknowledge_checkpoint(id).await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let held = alice.engine().events(&id).await.len();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL);
    let work = alice.engine().maintain_checkpoints(id).await.unwrap();
    assert!(work.forgotten > 0, "the history before the checkpoint");
    assert!(alice.engine().events(&id).await.len() < held);
    let status = space.checkpoints().await.unwrap();
    assert!(status.forgot);
    assert_eq!(status.in_effect, Some(c));

    // Her document keeps Carol's edit from before the checkpoint.
    reads(&space, &note, "one, zero").await;
    // Both keep writing through the peer.
    append(&note, " two").await;
    reads(&carols_space, &note, "one, zero two").await;
    until(|| async { in_effect(&carols_space).await == Some(c) }).await;
    append(&carols_note, " three").await;
    reads(&space, &note, "one, zero two three").await;
    assert_eq!(carols_space.level().await, Some(Level::Write));
    // Alice shows what Dave, who kept everything, shows: the text and each
    // unit's verdict.
    reads(&daves_space, &note, "one, zero two three").await;
    let units: Vec<EventId> = alice
        .engine()
        .events(&id)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == kind::UNIT)
        .map(|event| event.id())
        .collect();
    for unit in &units {
        let verdict = |device: &Device| {
            let unit = *unit;
            let device = device.clone();
            async move {
                device
                    .engine()
                    .read(&id, |replica| replica.status(&unit).copied())
                    .await
                    .unwrap()
            }
        };
        assert_eq!(verdict(&alice).await, verdict(&dave).await, "{unit:?}");
    }

    alice.close().await.unwrap();
    carol.close().await.unwrap();
    dave.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_truncates_after_cut_retention_and_admits_a_newcomer_from_the_checkpoint() {
    let peer = spawn_loopback().await.unwrap();
    // Alice's clock moves on with the peer's, so that what one dates the
    // other reads alike.
    let alices_clock = Arc::new(ManualClock::new(1_000, Some(now())));
    let alice = device_at(1, &alices_clock).await;
    let dave = device(4).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    append(&note, "before").await;
    // A roster event before the checkpoint, which the peer may delete.
    let id = event_of(&space);
    let grant = alice
        .engine()
        .grant_device(
            id,
            dave.engine().public_keys().clone(),
            Level::Read,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    until(|| async { space.is_durable().await }).await;

    // Alice administers alone: her checkpoint is in effect at once, and its
    // cut at the peer once her pseudonym acknowledged it, which her
    // administration connection does when the peer reports it awaited.
    let c = within(space.propose_checkpoint()).await.unwrap();
    let checkpoint = *c.as_bytes();
    until(|| async { space.is_durable().await }).await;
    assert!(peer.peer.keeps(&id.0, &grant.0));

    // The peer truncates once the cut has been in effect for
    // cut_retention on its timeline. Each poll moves its clock on by that
    // much and sweeps.
    let advanced = std::sync::atomic::AtomicU64::new(0);
    until(|| async {
        peer.advance(frasil_peers::limits::CUT_RETENTION).await;
        alices_clock.advance(frasil_peers::limits::CUT_RETENTION);
        advanced.fetch_add(
            frasil_peers::limits::CUT_RETENTION,
            std::sync::atomic::Ordering::SeqCst,
        );
        !peer.peer.keeps(&id.0, &grant.0)
    })
    .await;
    // It keeps the genesis and the checkpoint, and serves its envelope.
    assert!(peer.peer.holds(&id.0, &id.0));
    assert!(peer.peer.holds(&id.0, &checkpoint));

    // A newcomer admitted from now on starts from the checkpoint: the peer
    // answers `Missing` for what it deleted. This relies on the client
    // taking a peer's `Missing` as a dropped parent when it starts from a
    // checkpoint, and keeping what it started from.
    let bobs_clock = Arc::new(ManualClock::new(
        1_000,
        Some(now() + advanced.load(std::sync::atomic::Ordering::SeqCst)),
    ));
    let bob = device_at(2, &bobs_clock).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(
        joining.text(),
        Level::Write,
        "Alice's laptop",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    assert_eq!(bobs_space.id(), space.id());
    reads(&bobs_space, &note, "before").await;
    until(|| async { in_effect(&bobs_space).await == Some(c) }).await;
    let bobs_note = bobs_space.document(note.id()).await.unwrap();
    append(&bobs_note, ", after").await;
    reads(&space, &note, "before, after").await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_checkpoint_twice_apart_from_their_peer_and_it_truncates_once_they_return() {
    // Alice and Bob administer, and their peer holds the space. Apart from
    // it, syncing only with each other, they checkpoint twice: each
    // checkpoint takes effect once both vote, and its skeleton cut once
    // both pseudonyms vote for it, which their acknowledgements carry from
    // one to the other (peers.md, "Skeleton cuts"). Back at the peer, it
    // stores what they did apart, takes the second cut into effect after
    // the first, and truncates under it after cut_retention.
    let peer = spawn_loopback().await.unwrap();
    let clock = Arc::new(ManualClock::new(1_000, Some(now())));
    let alice = device_at(1, &clock).await;
    let bob = device_at(2, &clock).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    share(&alice, &space, &bob, Level::Administer).await;
    bob.engine().enrol(&id).await.unwrap();
    hand(&bob, &alice, &id).await;
    let note = space.create_document().unwrap();
    append(&note, "before").await;
    let grant = alice
        .engine()
        .grant_device(
            id,
            device(4).await.engine().public_keys().clone(),
            Level::Read,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    hand(&alice, &bob, &id).await;
    let bobs_space = bob.space(space.id()).await.unwrap();
    let alices_link = alice.connect(&peer.origin).await.unwrap();
    let bobs_link = bob.connect(&peer.origin).await.unwrap();
    until(|| async { space.is_durable().await && bobs_space.is_durable().await }).await;
    alices_link.close();
    bobs_link.close();
    // A close is a command to the connection: it is apart only once both
    // connections have ended, or what follows may still reach the peer.
    until(|| async { !alices_link.status().connected && !bobs_link.status().connected }).await;

    // Apart: two checkpoints in a row.
    let mut chain = Vec::new();
    for epoch in 1..=2u64 {
        let c = within(space.propose_checkpoint()).await.unwrap();
        hand(&alice, &bob, &id).await;
        bob.engine().acknowledge_checkpoint(id).await.unwrap();
        hand(&bob, &alice, &id).await;
        alice.engine().acknowledge_checkpoint(id).await.unwrap();
        hand(&alice, &bob, &id).await;
        for at in [&space, &bobs_space] {
            let status = at.checkpoints().await.unwrap();
            assert_eq!(status.in_effect, Some(c));
            assert_eq!(status.epoch, epoch);
        }
        chain.push(c);
    }
    assert!(peer.peer.keeps(&id.0, &grant.0));
    // The peer saw none of it.
    assert!(!peer.peer.keeps(&id.0, chain[0].as_bytes()));

    // Back at the peer: it catches up, and truncates under the second cut
    // once it has been in effect for cut_retention.
    let _alices_link = alice.connect(&peer.origin).await.unwrap();
    let _bobs_link = bob.connect(&peer.origin).await.unwrap();
    until(|| async { space.is_durable().await && bobs_space.is_durable().await }).await;
    until(|| async {
        peer.advance(frasil_peers::limits::CUT_RETENTION).await;
        clock.advance(frasil_peers::limits::CUT_RETENTION);
        !peer.peer.keeps(&id.0, &grant.0)
    })
    .await;
    assert!(peer.peer.holds(&id.0, &id.0));
    assert!(peer.peer.holds(&id.0, chain[1].as_bytes()));
    reads(
        &bobs_space,
        &bobs_space.document(note.id()).await.unwrap(),
        "before",
    )
    .await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_edit_is_sent_again() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let carol = device(3).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    append(&note, "a").await;
    share(&alice, &space, &carol, Level::Write).await;
    alice.connect(&peer.origin).await.unwrap();

    // Carol edits offline while Alice checkpoints: her unit is concurrent
    // with the checkpoint.
    let id = event_of(&space);
    let carols_space = carol.space(space.id()).await.unwrap();
    let carols_note = carols_space.document(note.id()).await.unwrap();
    append(&carols_note, "b").await;
    let late = last_unit(&carol, &id).await;
    let c = within(space.propose_checkpoint()).await.unwrap();
    assert_eq!(in_effect(&space).await, Some(c));

    // Once connected, Carol holds the checkpoint, finds her unit late, and
    // sends the edit again after it, as a unit Alice holds valid. Its Loro
    // content repeats the late unit's, which step 6 of adapter-loro.md 3.2
    // does not count against it, so the edit is in the text at both.
    carol.connect(&peer.origin).await.unwrap();
    until(|| async { in_effect(&carols_space).await == Some(c) }).await;
    until(|| async { class_of(&alice, &id, &late).await == Some("Late") }).await;
    until(|| async {
        let again = last_unit(&carol, &id).await;
        again != late
            && alice
                .engine()
                .read(&id, |replica| {
                    replica
                        .status(&again)
                        .is_some_and(frasil_space::Status::is_valid)
                })
                .await
                .unwrap_or(false)
    })
    .await;
    reads(&space, &note, "ab").await;
    reads(&carols_space, &carols_note, "ab").await;

    alice.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// Alice and Bob administer, with Dave writing. Alice connects; Bob, still
/// offline, makes `change` while Alice checkpoints, then connects and votes
/// for her checkpoint, which makes his change late. With Bob's events from
/// before he connected.
async fn concurrent_with_a_checkpoint<F, Fut>(
    peer: &frasil_relay::testing::TestPeer,
    change: F,
) -> (Device, Device, Device, Space, Events)
where
    F: FnOnce(Device, Space, Device) -> Fut,
    Fut: Future<Output = ()>,
{
    concurrent_with_a_checkpoint_enrolled(peer, false, change).await
}

/// As [`concurrent_with_a_checkpoint`]. With `enrolled_first`, Bob enrols
/// his administrator pseudonym and Alice holds the enrolment before she
/// checkpoints, so her cut names it. Without it, Bob's enrolment is
/// concurrent with the checkpoint and its cut leaves it out.
async fn concurrent_with_a_checkpoint_enrolled<F, Fut>(
    peer: &frasil_relay::testing::TestPeer,
    enrolled_first: bool,
    change: F,
) -> (Device, Device, Device, Space, Events)
where
    F: FnOnce(Device, Space, Device) -> Fut,
    Fut: Future<Output = ()>,
{
    let alice = device(1).await;
    let bob = device(2).await;
    let dave = device(4).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    alice
        .engine()
        .grant_device(
            id,
            dave.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    share(&alice, &space, &bob, Level::Administer).await;
    if enrolled_first {
        bob.engine().enrol(&id).await.unwrap();
        hand(&bob, &alice, &id).await;
    }
    alice.connect(&peer.origin).await.unwrap();
    let bobs_space = bob.space(space.id()).await.unwrap();
    change(bob.clone(), bobs_space.clone(), dave.clone()).await;
    let c = within(space.propose_checkpoint()).await.unwrap();
    let events = bob.events();
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { in_effect(&bobs_space).await == Some(c) }).await;
    until(|| async { in_effect(&space).await == Some(c) }).await;
    (alice, bob, dave, space, events)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_removal_is_signed_again() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, dave, space, _) =
        concurrent_with_a_checkpoint(&peer, |_bob, bobs_space, dave| async move {
            bobs_space.remove(dave.id()).await.unwrap();
        })
        .await;
    // Bob's removal is late; his upkeep signs it again after the
    // checkpoint, and Dave is out at Alice too. Nothing is left listed.
    let id = event_of(&space);
    until(|| async { !is_in(&alice, &id, &dave).await }).await;
    until(|| async { !is_in(&bob, &id, &dave).await }).await;
    let bobs_space = bob.space(space.id()).await.unwrap();
    assert!(bobs_space.late_changes().await.unwrap().is_empty());

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    dave.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_grant_is_reported_to_its_administrator() {
    let peer = spawn_loopback().await.unwrap();
    let erin = device(5).await;
    let erin_keys = erin.engine().public_keys().clone();
    let (alice, bob, dave, space, mut events) =
        concurrent_with_a_checkpoint(&peer, |bob, bobs_space, _dave| async move {
            bob.engine()
                .grant_device(
                    event_of(&bobs_space),
                    erin_keys,
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap();
        })
        .await;
    // A grant is not made again by itself: it is reported, as an event and
    // by `late_changes`, and Erin is not a member at Alice.
    let late = next_matching(
        &mut events,
        |event| matches!(event, Event::Late { changes, .. } if !changes.is_empty()),
    )
    .await;
    let Event::Late { changes, .. } = late else {
        unreachable!()
    };
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, LateChangeKind::Grant);
    assert_eq!(changes[0].member, Some(erin.id()));
    let bobs_space = bob.space(space.id()).await.unwrap();
    assert_eq!(bobs_space.late_changes().await.unwrap(), changes);
    let id = event_of(&space);
    assert!(!is_in(&alice, &id, &erin).await);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    dave.close().await.unwrap();
    erin.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_concurrent_with_a_cut_does_not_hold_back_what_follows_it() {
    // Bob enrols his administrator pseudonym apart, concurrently with
    // Alice's checkpoint, whose cut leaves the enrolment out, and grants
    // Erin after it. Alice's checkpoint takes effect at the peer first: the
    // enrolment is late there, stored without effect and acknowledged, so
    // Bob's grant and his vote, which follow it, are placed, and the
    // checkpoint takes effect at Alice (peers.md, "Skeleton cuts", "Late
    // skeleton events"). Bob then enrols his slot again after the
    // checkpoint, under its secret, and signs a twin with the new
    // pseudonym: his grant of administer to Dave is valid at Alice.
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let dave = device(4).await;
    let erin = device(5).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    share(&alice, &space, &bob, Level::Administer).await;
    bob.engine().enrol(&id).await.unwrap();
    bob.engine()
        .grant_device(
            id,
            erin.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let c = within(space.propose_checkpoint()).await.unwrap();
    // The peer takes Alice's checkpoint, cut and all, before Bob arrives.
    alice.connect(&peer.origin).await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let bobs_space = bob.space(space.id()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { in_effect(&bobs_space).await == Some(c) }).await;
    until(|| async { bobs_space.is_durable().await }).await;
    until(|| async { in_effect(&space).await == Some(c) }).await;

    // Once the cut is in effect, Bob's upkeep enrols again; his twin then
    // signs with the new pseudonym.
    let grant = within(async {
        loop {
            let _ = bob.engine().maintain_checkpoints(id).await;
            match bob
                .engine()
                .grant_administrator(
                    id,
                    dave.engine().public_keys().clone(),
                    100,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
            {
                Ok(grant) => break grant,
                Err(frasil::Error::NotAllowed(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await;
    until(|| async { bobs_space.is_durable().await }).await;
    until(|| async {
        alice
            .engine()
            .read(&id, |replica| replica.status(&grant).copied())
            .await
            .ok()
            .flatten()
            .is_some_and(|status| status.is_valid())
    })
    .await;
    assert!(is_in(&alice, &id, &dave).await);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    dave.close().await.unwrap();
    erin.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_stable_checkpoints_settle_on_the_smaller_id() {
    // Alice founds the space at the top rank, Bob administers at rank 100,
    // and Rex is its recovery member. Apart, Alice demotes Bob, whom she
    // outranks, and checkpoints alone; Bob checkpoints, and Rex excuses
    // Alice from his checkpoint by marking her dormant after it. Two
    // concurrent checkpoints with the same predecessor (none) both take
    // effect (roster.md, 3.15.4, "Concurrent checkpoints that are both
    // stable"); once they meet at the peer, every replica keeps the one
    // with the smaller ID.
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let rex = device(3).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    alice
        .engine()
        .grant_administrator(
            id,
            bob.engine().public_keys().clone(),
            100,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    share(&alice, &space, &rex, Level::Write).await;
    space.make_recovery_member(rex.id()).await.unwrap();
    assert_eq!(space.recovery_members().await.unwrap(), vec![rex.id()]);
    for to in [&bob, &rex] {
        to.engine().follow(id).await;
        to.engine()
            .ingest(id, alice.engine().events(&id).await)
            .await
            .unwrap();
    }
    let bobs_space = bob.space(space.id()).await.unwrap();
    let rexs_space = rex.space(space.id()).await.unwrap();
    assert_eq!(bobs_space.my_rank().await.unwrap(), Some(100));

    space.set_level(bob.id(), Level::Write).await.unwrap();
    let a = within(space.propose_checkpoint()).await.unwrap();
    assert_eq!(in_effect(&space).await, Some(a));
    let b = within(bobs_space.propose_checkpoint()).await.unwrap();
    hand(&bob, &rex, &id).await;
    rexs_space.set_dormant(alice.id(), true).await.unwrap();
    hand(&rex, &bob, &id).await;
    until(|| async { in_effect(&bobs_space).await == Some(b) }).await;
    assert_ne!(a, b);
    let smaller = if a.as_bytes() < b.as_bytes() { a } else { b };

    bob.connect(&peer.origin).await.unwrap();
    rex.connect(&peer.origin).await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    until(|| async { in_effect(&space).await == Some(smaller) }).await;
    until(|| async { in_effect(&bobs_space).await == Some(smaller) }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    rex.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_checkpoint_that_drops_a_device_ends_its_access_in_every_space() {
    // The person's laptop and phone; the phone writes in a space of the
    // laptop's. The laptop takes the phone off the person's list, then
    // checkpoints the list: the record lists only the laptop, so the phone
    // has no path through the person in any space, for its units before
    // the checkpoint as after it (identity.md, 3.16, "Spaces").
    let peer = spawn_loopback().await.unwrap();
    let laptop = device(1).await;
    let person = laptop.make_person(&[1; 32]).await.unwrap();
    let space = laptop.create_space().await.unwrap();
    laptop.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    append(&note, "Hello").await;
    until(|| async { space.is_durable().await }).await;

    let phone = device(2).await;
    let joining =
        within(
            phone.join_person_via_peer(&peer.origin, person, "Phone", &[2; 32], |_, _| async {
                true
            }),
        )
        .await
        .unwrap();
    within(laptop.admit_device(joining.text(), "Laptop", |_, _| async { true }))
        .await
        .unwrap();
    within(joining.joined()).await.unwrap();
    let phones_space = phone.space(space.id()).await.unwrap();
    reads(&phones_space, &note, "Hello").await;
    let phones_note = phones_space.document(note.id()).await.unwrap();
    append(&phones_note, ", phone").await;
    reads(&space, &note, "Hello, phone").await;
    let id = event_of(&space);
    let unit = last_unit(&phone, &id).await;

    within(laptop.remove_device(phone.id())).await.unwrap();
    let c = within(laptop.propose_list_checkpoint()).await.unwrap();
    // The phone is revoked, so the checkpoint waits for no one.
    until(|| async { laptop.list_checkpoints_waiting().await.is_empty() }).await;
    let _ = c;

    // In every space of the laptop, the phone is no member, and its unit
    // from before the checkpoint has no path through the person. This
    // relies on the space reading the person's list checkpoint.
    let phone_id = phone.engine().device_id();
    for held in laptop.spaces().await {
        let held = event_of(&held);
        let level = laptop
            .engine()
            .read(&held, |replica| replica.level_of(&phone_id))
            .await
            .unwrap();
        assert_eq!(level, None);
    }
    until(|| async { class_of(&laptop, &id, &unit).await == Some("Dropped") }).await;

    laptop.close().await.unwrap();
    phone.close().await.unwrap();
    peer.shutdown().await;
}

/// A wide cut includes offline recovery administrators. Their slots stay
/// in the record and cut while the founder supplies the electorate's vote.
/// A new administrator then enrols after the peer discarded those grants.
async fn wide_checkpoint_truncates_and_enrols(slots: usize) {
    let started = std::time::Instant::now();
    let peer = spawn_loopback().await.unwrap();
    let clock = Arc::new(ManualClock::new(1_000, Some(now())));
    let alice = device_at(1, &clock).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    let mut first_grant = None;
    for start in (1..slots).step_by(32) {
        let changes = (start..slots.min(start + 32))
            .map(|index| {
                let mut seed = [0x91; 32];
                seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
                let keys = frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&seed);
                let mut change = frasil_space::Change::grant_administrator(
                    keys.device_keys(),
                    255,
                    HistoryMode::WithHistory,
                    Via::Code,
                );
                change.capabilities = Some(vec![frasil_space::Capability {
                    name: frasil_space::checkpoint::DORMANT.to_owned(),
                    mode: frasil_space::CapabilityMode::Extends,
                }]);
                change
            })
            .collect();
        let grant = alice.engine().sign_roster(id, changes).await.unwrap();
        first_grant.get_or_insert(grant);
    }
    alice.connect(&peer.origin).await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let checkpoint = within(space.propose_checkpoint()).await.unwrap();
    alice.engine().acknowledge_checkpoint(id).await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let cut = alice
        .engine()
        .events(&id)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .find_map(
            |event| match frasil_peers::body::StorageBody::read(event.unverified_body()) {
                Ok(frasil_peers::body::StorageBody::Cut(cut)) => Some(cut),
                _ => None,
            },
        )
        .expect("a stored cut");
    assert_eq!(cut.slots.len(), slots);
    assert_eq!(cut.standing.len(), slots);
    assert_eq!(
        cut.standing
            .iter()
            .filter(|entry| entry.dormant == 0)
            .count(),
        1
    );
    let first_grant = first_grant.unwrap();
    until(|| async {
        peer.advance(frasil_peers::limits::CUT_RETENTION).await;
        clock.advance(frasil_peers::limits::CUT_RETENTION);
        !peer.peer.keeps(&id.0, &first_grant.0)
    })
    .await;
    assert!(peer.peer.holds(&id.0, checkpoint.as_bytes()));

    let bob = device_at(2, &clock).await;
    let joining = within(bob.join_via_peer(&peer.origin, "New device", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit_administrator(
        joining.text(),
        254,
        HistoryMode::FromNowOn,
        "Founder",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    let joined = within(joining.joined()).await.unwrap();
    until(|| async { in_effect(&joined).await == Some(checkpoint) }).await;
    bob.engine().enrol(&id).await.unwrap();
    until(|| async { joined.is_durable().await }).await;
    let enrolment = bob
        .engine()
        .events(&id)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .find(|event| {
            matches!(
                frasil_peers::body::StorageBody::read(event.unverified_body()),
                Ok(frasil_peers::body::StorageBody::Enrol { .. })
            )
        });
    assert!(enrolment.is_some_and(|event| peer.peer.holds(&id.0, &event.id().0)));
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
    eprintln!(
        "{slots}-slot checkpoint, truncation and enrolment: {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_256_slot_space_checkpoints_truncates_and_enrols() {
    tokio::time::timeout(
        Duration::from_secs(60),
        wide_checkpoint_truncates_and_enrols(256),
    )
    .await
    .expect("a wide space completes within one minute");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "maximum-size checkpoint and enrolment exercise"]
async fn a_512_slot_space_checkpoints_truncates_and_enrols() {
    wide_checkpoint_truncates_and_enrols(512).await;
}
