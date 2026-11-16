//! Administration connections (transport.md, section 3.10; peers.md,
//! "Administration connections"): a device stores its administrator
//! pseudonym's skeleton events at a peer only on a fresh connection that
//! presents that pseudonym, never on its space-traffic connection. Every
//! wait has a deadline, and nothing leaves the host.

use frasil::{Device, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_space::{HistoryMode, Via};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_is_stored_on_an_administration_connection() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.engine().create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    // Alice grants Bob's device `administer`: Bob enrols a fresh
    // pseudonym in the administrator slot, a skeleton event of his own.
    alice
        .engine()
        .grant_administrator(
            space,
            bob.engine().public_keys().clone(),
            255,
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
    let enrolment = bob.engine().enrol(&space).await.unwrap();
    assert!(enrolment.is_some() || !bob.engine().outbox(&space).await.is_empty());
    bob.connect(&peer.origin).await.unwrap();
    // His space-traffic connection withholds it; the upkeep stores it on an
    // administration connection, and the peer acknowledges it.
    tokio::time::timeout(Duration::from_secs(30), async {
        while !bob.engine().outbox(&space).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("every change of Bob durable at the peer");
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_erased_space_leaves_no_local_stream() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("durable within the deadline");
    assert_eq!(space.streams().await.unwrap().len(), 1);

    tokio::time::timeout(Duration::from_secs(60), space.erase())
        .await
        .expect("within the deadline")
        .unwrap();
    // The peer holds the erasure; the device holds nothing of the space.
    let event = frasil_events::EventId(*space.id().as_bytes());
    assert!(!alice.engine().spaces().await.contains(&event));
    assert!(alice.space(space.id()).await.is_err());
    assert!(space.streams().await.is_err());
    assert!(alice.engine().outbox(&event).await.is_empty());

    alice.close().await.unwrap();
    peer.shutdown().await;
}

/// A peer that executes the erasure before the device reads its
/// acknowledgement, as when another administration connection stored it,
/// refuses the device's next present `erased`: the peer erased the space,
/// and the device then drops it too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_erasure_executed_before_its_acknowledgement_is_read_leaves_the_device() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(3).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("durable within the deadline");

    let id = *space.id().as_bytes();
    let withholding = frasil_relay::testing::withhold_acknowledgements(id);
    tokio::time::timeout(Duration::from_secs(60), space.erase())
        .await
        .expect("within the deadline")
        .unwrap();
    // No acknowledgement reached the device; the peer erased the space.
    assert!(withholding.withheld() > 0);
    assert!(peer.peer.erased(&id));
    let event = frasil_events::EventId(id);
    assert!(!alice.engine().spaces().await.contains(&event));
    assert!(alice.space(space.id()).await.is_err());
    assert!(space.streams().await.is_err());
    assert!(alice.engine().outbox(&event).await.is_empty());

    alice.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_durable_returns_at_acknowledgement_or_at_its_deadline() {
    let alice = device(5).await;
    let bob = device(6).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    // No peer: the wait ends at its deadline, and the changes stay.
    let started = tokio::time::Instant::now();
    let refused = space.wait_durable(Duration::from_millis(200)).await;
    assert!(
        matches!(refused, Err(frasil::Error::Connection(_))),
        "{refused:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!space.is_durable().await);

    // With a peer, it returns once the peer acknowledged every change, a
    // change of who administers included.
    let peer = spawn_loopback().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    space.wait_durable(Duration::from_secs(30)).await.unwrap();
    assert!(space.is_durable().await);
    alice
        .engine()
        .grant_administrator(
            frasil_events::EventId(*space.id().as_bytes()),
            bob.engine().public_keys().clone(),
            255,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    space.wait_durable(Duration::from_secs(30)).await.unwrap();
    assert!(space.is_durable().await);
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_durable_alone_delivers_newly_created_spaces() {
    // Each new space needs its administrator skeleton at the peer before the
    // peer acknowledges its genesis, so only an administration connection
    // makes it durable; `wait_durable` drives that connection itself, with
    // no `flush` beside it.
    let peer = spawn_loopback().await.unwrap();
    let alice = device(7).await;
    alice.connect(&peer.origin).await.unwrap();
    for round in 0..12 {
        let space = alice.create_space().await.unwrap();
        let note = space.create_document().unwrap();
        note.edit(|doc| doc.get_text("body").insert(0, "Recovery sheet"))
            .await
            .unwrap();
        assert!(!space.is_durable().await, "round {round}");
        space
            .wait_durable(Duration::from_secs(15))
            .await
            .unwrap_or_else(|error| panic!("round {round}: {error}"));
        assert!(space.is_durable().await, "round {round}");
    }
    alice.close().await.unwrap();
    peer.shutdown().await;
}
