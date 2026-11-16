//! A space event whose parent a snapshot covers (units.md, 3.9 Placing
//! against stubs, "Confirming heights"; peers.md, "Collection"): Alice
//! writes a document, grants Carol, which names her last unit as a parent,
//! and compacts the document. The peer collects the cover. Bob, away all
//! the while, catches up from the peer alone: he places the grant against
//! the unit the peer kept for it, judges it, and reads the document from
//! the snapshot. Every wait has a deadline, and nothing leaves the host.

use frasil::advanced::Engine;
use frasil::{Device, Options, Storage};
use frasil_events::EventId;
use frasil_relay::testing::spawn_with;
use frasil_space::{HistoryMode, Level, Status, Via};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn text(engine: &Engine, space: &EventId, stream: &[u8; 16]) -> String {
    engine
        .document(space, stream)
        .await
        .map(|doc| doc.get_text("body").to_string())
        .unwrap_or_default()
}

async fn durable(engine: &Engine, space: &EventId) {
    tokio::time::timeout(DEADLINE, async {
        while !engine.outbox(space).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("durable at the peer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_event_on_a_collected_unit_is_placed_from_the_peer() {
    let peer = spawn_with(frasil_conformance::options()).await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let space = alice.engine().create_space().await.unwrap();
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

    // While Bob is away, Alice writes, grants Carol on top of her last
    // unit, and compacts: the grant names a unit of the cover.
    let doc = alice.engine().new_document().unwrap();
    let mut last = None;
    for word in ["one", " two", " three"] {
        last = Some(
            alice
                .engine()
                .edit_document(space, &doc, |d| {
                    let body = d.get_text("body");
                    body.insert(body.len_unicode(), word).unwrap();
                })
                .await
                .unwrap(),
        );
    }
    let last = last.unwrap();
    let grant = alice
        .engine()
        .grant_device(
            space,
            carol.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let parents = alice
        .engine()
        .read(&space, |r| r.event(grant).map(|e| e.parents().to_vec()))
        .await
        .unwrap()
        .unwrap();
    assert!(parents.contains(&last), "the grant names the last unit");
    alice.engine().compact(space, doc.stream()).await.unwrap();
    alice
        .engine()
        .edit_document(space, &doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), " four").unwrap();
        })
        .await
        .unwrap();
    durable(alice.engine(), &space).await;
    // The snapshot is stable at the peer, which collects its cover.
    peer.advance(8 * 86_400).await;

    // Bob comes back and syncs with the peer alone.
    bob.connect(&peer.origin).await.unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            let status = bob
                .engine()
                .read(&space, |r| r.status(&grant).copied())
                .await
                .unwrap();
            if matches!(status, Some(Status::Valid(_))) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Bob places and judges the grant");
    tokio::time::timeout(DEADLINE, async {
        while text(bob.engine(), &space, &doc.stream()).await != "one two three four" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Bob reads the document");
    peer.shutdown().await;
}
