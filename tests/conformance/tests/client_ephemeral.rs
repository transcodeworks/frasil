//! The ephemeral channel relayed through an always-on peer
//! (ext-ephemeral.md, "Relaying"): two devices that share a space and have
//! no member connection reach each other's frames through the peer, which
//! holds no key. Every wait has a deadline, and nothing leaves the host.
#![cfg(feature = "ephemeral")]

use frasil::{Device, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::{Options as PeerOptions, TestPeer, spawn_with};
use frasil_space::{HistoryMode, Level, Via};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

/// Alice and Bob, who share a space and meet only at `peer`, connected to
/// it.
async fn pair(peer: &TestPeer) -> (Device, Device, frasil_events::EventId) {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.engine().create_space().await.unwrap();
    // A direct grant: the devices meet only at the peer.
    alice
        .engine()
        .grant_device(
            space,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(space).await;
    bob.engine()
        .ingest(space, alice.engine().events(&space).await)
        .await
        .unwrap();
    alice.connect(&peer.origin).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    (alice, bob, space)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_relays_ephemeral_messages_and_slots() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space) = pair(&peer).await;
    let mut received = bob.engine().subscribe_ephemeral().await.unwrap();
    // The channel is lossy and the connections join it when granted:
    // Alice sends until Bob takes one through the peer.
    let message = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            alice
                .engine()
                .send_ephemeral(space, "typing", None, b"alice", false)
                .await
                .unwrap();
            if let Ok(Ok(frame)) =
                tokio::time::timeout(Duration::from_millis(200), received.recv()).await
                && frame.name == "typing"
            {
                return frame;
            }
        }
    })
    .await
    .expect("a relayed message within the deadline");
    assert_eq!(message.sender, alice.engine().device_id());
    assert_eq!(message.data, b"alice");

    // An ephemeral slot set before a device joins reaches it when it does:
    // the peer holds the latest value of each slot.
    alice
        .engine()
        .send_ephemeral(space, "cursor", Some([9; 16]), b"12", true)
        .await
        .unwrap();
    let slot = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let frame = received.recv().await.unwrap();
            if frame.slot && frame.name == "cursor" {
                return frame;
            }
        }
    })
    .await
    .expect("a relayed slot within the deadline");
    assert_eq!(slot.data, b"12");
    peer.shutdown().await;
}

/// A peer with ext-ephemeral off, as by default, relays nothing: the
/// devices' frames reach no one through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_the_extension_off_relays_nothing() {
    let peer = spawn_with(PeerOptions {
        settings: frasil_relay::Settings::open_core(),
        ..PeerOptions::default()
    })
    .await
    .unwrap();
    assert!(!peer.peer.extensions().ephemeral);
    let (alice, bob, space) = pair(&peer).await;
    let mut received = bob.engine().subscribe_ephemeral().await.unwrap();
    for _ in 0..25 {
        alice
            .engine()
            .send_ephemeral(space, "typing", None, b"alice", false)
            .await
            .unwrap();
        alice
            .engine()
            .send_ephemeral(space, "cursor", Some([9; 16]), b"12", true)
            .await
            .unwrap();
        let heard = tokio::time::timeout(Duration::from_millis(200), received.recv()).await;
        assert!(heard.is_err(), "a frame through a peer that relays none");
    }
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
