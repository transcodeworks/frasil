//! An administrator withholds its acknowledgements and votes while the
//! skeleton and the roster differ in its view (peers.md, 3.12, "Where the
//! peer and the roster differ"; 3.15): here a removal of a member that was
//! not yet an administrator at its place, concurrent with its raise to
//! administer, has no twin, so the skeleton keeps the slot the raise made
//! while the roster removes the member.

use crate::advanced::{AdapterRegistry, Engine, Platform};
use crate::checkpoints::CheckpointPolicy;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};

async fn device() -> Engine {
    let (device, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.follow(space).await;
    to.ingest(space, from.events(&space).await)
        .await
        .expect("ingested");
}

#[tokio::test]
async fn acknowledgements_wait_while_the_skeleton_and_the_roster_differ() {
    let alice = device().await;
    let carol = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device_at(
            space,
            carol.public_keys().clone(),
            Level::Administer,
            Some(255),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice
        .grant_device_at(
            space,
            bob.public_keys().clone(),
            Level::Write,
            None,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(&alice, &carol, space).await;
    // Apart: Alice raises Bob to administer, Carol removes Bob.
    alice
        .raise(space, MemberRef::device(bob.device_id()), 100)
        .await
        .unwrap();
    carol
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    carry(&carol, &alice, space).await;
    let (differs, bob_in) = alice
        .read(&space, |r| {
            (
                r.skeleton_differs(),
                r.roster().is_in(&MemberRef::device(bob.device_id())),
            )
        })
        .await
        .unwrap();
    assert!(!bob_in, "the removal stands in the roster");
    assert!(differs, "the skeleton keeps the slot the raise made");
    let head = alice.events(&space).await.len();
    assert!(
        alice
            .acknowledge_awaited(space, &[space])
            .await
            .unwrap()
            .is_none(),
        "no acknowledgement while they differ"
    );
    assert_eq!(alice.events(&space).await.len(), head);
}
