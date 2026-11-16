//! Administrators' ranks with a peer on loopback (roster.md, 2.3 Changes,
//! "Ranks"; 3.6 Authority at the place; 3.5.2 duels; 3.15.4): a lower rank
//! cannot remove a higher one, and the peer's skeleton agrees; between
//! equal ranks the more senior wins a mutual removal; and a lower-rank
//! device's backdated takeover with a checkpoint never takes effect, while
//! the honest side's checkpoint does. Every wait has a deadline, and
//! nothing leaves the host.

use frasil::{CheckpointId, CheckpointPolicy, Device, Event, Level, Options, Space, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_space::{HistoryMode, MemberRef, Via};
use std::future::Future;
use std::time::Duration;

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

/// A device in memory that proposes and forgets only when told.
async fn device(key: u8) -> Device {
    let device = Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// `by` grants `to` administer at `rank` and hands `to` the space.
async fn administrator(by: &Device, space: &Space, to: &Device, rank: u8) {
    let id = event_of(space);
    by.engine()
        .grant_administrator(
            id,
            to.engine().public_keys().clone(),
            rank,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .expect("a grant");
    hand(by, to, &id).await;
}

/// Hands every event `from` holds of the space, and the objects `to`
/// lacks, to `to`, as a member connection would.
async fn hand(from: &Device, to: &Device, space: &EventId) {
    to.engine().follow(*space).await;
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
        .map(frasil_base::errors::Class::name)
}

async fn is_in(device: &Device, space: &EventId, member: &Device) -> bool {
    let member = MemberRef::device(member.engine().device_id());
    device
        .engine()
        .read(space, |replica| replica.roster().is_in(&member))
        .await
        .unwrap_or(false)
}

async fn in_effect(space: &Space) -> Option<CheckpointId> {
    space.checkpoints().await.ok()?.in_effect
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lower_rank_cannot_remove_a_higher_one() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    administrator(&alice, &space, &bob, 100).await;
    let bobs_space = bob.space(space.id()).await.unwrap();

    // Bob's client refuses before signing.
    assert!(matches!(
        bobs_space.remove(alice.id()).await,
        Err(frasil::Error::Class("HigherRank"))
    ));
    // A client that does not check signs it anyway: void at every replica.
    bob.engine().sign_without_rank_checks(true);
    let removal = bob
        .engine()
        .remove(id, MemberRef::device(alice.engine().device_id()))
        .await
        .unwrap();
    assert_eq!(class_of(&bob, &id, &removal).await, Some("HigherRank"));

    let mut events = alice.events();
    alice.connect(&peer.origin).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { class_of(&alice, &id, &removal).await == Some("HigherRank") }).await;
    assert!(is_in(&alice, &id, &alice).await);
    within(async {
        loop {
            match events.next().await.expect("the device is open") {
                Event::RankAttemptRefused { event, author, .. }
                    if *event.as_bytes() == removal.0 && author == bob.id() =>
                {
                    break;
                }
                _ => {}
            }
        }
    })
    .await;

    // The peer agrees: its skeleton keeps Alice's slot, so her checkpoint's
    // cut, signed in that slot, is stored and the checkpoint takes effect.
    let c = within(space.propose_checkpoint()).await.unwrap();
    until(|| async { space.is_durable().await }).await;
    until(|| async { in_effect(&space).await == Some(c) }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn between_equal_ranks_the_more_senior_wins_a_mutual_removal() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    administrator(&alice, &space, &bob, 255).await;
    let bobs_space = bob.space(space.id()).await.unwrap();

    // Apart, each removes the other. Alice, the founder, is the more senior.
    space.remove(bob.id()).await.unwrap();
    bobs_space.remove(alice.id()).await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { !is_in(&alice, &id, &bob).await && is_in(&alice, &id, &alice).await }).await;
    hand(&alice, &bob, &id).await;
    until(|| async { !is_in(&bob, &id, &bob).await && is_in(&bob, &id, &alice).await }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backdated_takeover_by_a_lower_rank_never_takes_effect() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    administrator(&alice, &space, &bob, 100).await;
    alice
        .engine()
        .grant_device(
            id,
            carol.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    hand(&alice, &carol, &id).await;
    let bobs_space = bob.space(space.id()).await.unwrap();
    let carols_space = carol.space(space.id()).await.unwrap();

    // Bob, a lower rank, signs from his view a removal of Alice and then a
    // checkpoint whose record he would administer alone.
    bob.engine().sign_without_rank_checks(true);
    let takeover = bob
        .engine()
        .remove(id, MemberRef::device(alice.engine().device_id()))
        .await
        .unwrap();
    let theirs = within(bobs_space.propose_checkpoint()).await.unwrap();
    // The removal is void, so his record keeps Alice, and the checkpoint
    // waits for her vote.
    assert_eq!(class_of(&bob, &id, &takeover).await, Some("HigherRank"));
    let waiting = bobs_space.checkpoints().await.unwrap();
    assert_eq!(waiting.in_effect, None);
    assert_eq!(waiting.pending[0].waiting_for, vec![alice.id()]);

    // Alice, honest, removes Bob and checkpoints.
    space.remove(bob.id()).await.unwrap();
    let ours = within(space.propose_checkpoint()).await.unwrap();
    assert_eq!(in_effect(&space).await, Some(ours));

    alice.connect(&peer.origin).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    carol.connect(&peer.origin).await.unwrap();
    until(|| async { in_effect(&carols_space).await == Some(ours) }).await;
    // Alice never votes for Bob's checkpoint, so it never takes effect. The
    // peer's skeleton refuses the twin of Bob's removal (HigherRank), so it
    // holds the removal and what follows it pending; a replica that holds
    // the removal finds it void.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for member in [&alice, &carol] {
        let held = member
            .engine()
            .read(&id, |replica| replica.status(&takeover).copied())
            .await
            .unwrap();
        assert!(!held.is_some_and(|status| status.is_valid()), "{held:?}");
    }
    assert_eq!(in_effect(&space).await, Some(ours));
    assert_eq!(in_effect(&carols_space).await, Some(ours));
    assert_ne!(in_effect(&space).await, Some(theirs));
    assert!(!is_in(&carol, &id, &bob).await);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}
