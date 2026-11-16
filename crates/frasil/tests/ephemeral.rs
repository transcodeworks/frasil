//! The ephemeral channel between two members over loopback QUIC: a message
//! and an ephemeral slot value, signed, sealed under the space's state and
//! checked at the receiver.
#![cfg(all(feature = "ephemeral", feature = "iroh"))]

use frasil::advanced::node::Node;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_transport::ticket::TicketKind;
use std::time::Duration;

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

async fn two_members() -> (Engine, Engine, EventId) {
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
    (alice, bob, space)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_exchange_ephemeral_messages_and_slots() {
    let (alice, bob, space) = two_members().await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    let mut received = bob.subscribe_ephemeral().await.unwrap();
    bob_node
        .dial(&alice_node.ticket(TicketKind::Member), vec![space])
        .await
        .unwrap();
    // The channel is lossy: Alice sends until Bob, admitted, takes one.
    let message = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            alice
                .send_ephemeral(space, "typing", None, b"alice", false)
                .await
                .unwrap();
            if let Ok(Ok(frame)) =
                tokio::time::timeout(Duration::from_millis(200), received.recv()).await
            {
                return frame;
            }
        }
    })
    .await
    .expect("a message within the deadline");
    assert_eq!(message.sender, alice.device_id());
    assert_eq!(message.name, "typing");
    assert_eq!(message.data, b"alice");
    assert!(!message.slot);

    let stream = [9; 16];
    alice
        .send_ephemeral(space, "cursor", Some(stream), b"12", true)
        .await
        .unwrap();
    let slot = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = received.recv().await.unwrap();
            if frame.slot {
                return frame;
            }
        }
    })
    .await
    .expect("a slot value");
    assert_eq!(slot.stream, Some(stream));
    assert_eq!(slot.data, b"12");
    alice_node.close().await;
    bob_node.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_only_command_needs_the_receivers_nonce() {
    let (alice, bob, space) = two_members().await;
    bob.set_fresh_only(["cue".to_owned()]);
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    let mut received = bob.subscribe_ephemeral().await.unwrap();
    bob_node
        .dial(&alice_node.ticket(TicketKind::Member), vec![space])
        .await
        .unwrap();
    // Alice sends until Bob takes one: a broadcast cue carries no fresh
    // entry, so Bob refuses it as Stale; a cue targeted at Bob carries his
    // nonce once Alice has his `frasil/nonce` slot, and he takes it.
    let cue = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            alice
                .send_ephemeral(space, "cue", None, b"broadcast", false)
                .await
                .unwrap();
            alice
                .send_ephemeral_to(space, "cue", &[bob.device_id()], b"targeted")
                .await
                .unwrap();
            if let Ok(Ok(frame)) =
                tokio::time::timeout(Duration::from_millis(200), received.recv()).await
                && frame.name == "cue"
            {
                return frame;
            }
        }
    })
    .await
    .expect("a cue within the deadline");
    assert_eq!(cue.data, b"targeted");
    alice_node.close().await;
    bob_node.close().await;
}
