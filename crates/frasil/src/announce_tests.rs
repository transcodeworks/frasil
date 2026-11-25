//! The spaces a device announces on a local network (transport.md,
//! "Member announcements"): four an interval, each in turn, and none it
//! has left.

use crate::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use std::collections::BTreeSet;

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

/// What the device announces over `intervals` intervals, in order.
async fn announced(device: &Engine, intervals: usize) -> Vec<EventId> {
    let mut last = None;
    let mut out = Vec::new();
    for _ in 0..intervals {
        let states = device.announced_states(last.as_ref()).await;
        if let Some((space, _)) = states.last() {
            last = Some(*space);
        }
        out.extend(states.into_iter().map(|(space, _)| space));
    }
    out
}

#[tokio::test]
async fn a_device_announces_each_of_its_spaces_in_turn() {
    let device = device().await;
    let mut spaces = BTreeSet::new();
    for _ in 0..9 {
        spaces.insert(device.create_space().await.unwrap());
    }
    // Nine spaces, four an interval: each once in three intervals, in the
    // order of their IDs, then from the first again.
    let turn = announced(&device, 3).await;
    assert_eq!(turn.len(), 12);
    assert_eq!(turn[..9], spaces.iter().copied().collect::<Vec<_>>());
    assert_eq!(turn[9..], turn[..3]);
}

#[tokio::test]
async fn a_device_does_not_announce_a_space_it_has_left() {
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
    bob.follow(space).await;
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    assert_eq!(announced(&bob, 1).await, [space]);
    alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    // Until Bob hears of it, he announces the space as before.
    assert_eq!(announced(&bob, 1).await, [space]);
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    assert_eq!(announced(&bob, 1).await, []);
    assert_eq!(announced(&alice, 1).await, [space]);
}
