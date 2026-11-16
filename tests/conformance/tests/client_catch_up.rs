//! Catch-up through a retired entry (transport.md, section 3.11; peers.md,
//! "Retirement and the cap", "Catch-up"): a device that missed rotations
//! while away holds only an older state, whose entry the peer has retired.
//! Its present is granted catch-up; it fetches what wraps the newer keys
//! for it, presents the newest state, and syncs again. Every wait has a
//! deadline, and nothing leaves the host.

use frasil::advanced::Engine;
use frasil::{Device, Options, Storage};
use frasil_relay::testing::spawn_with;
use frasil_space::{HistoryMode, Level, Via};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn text(engine: &Engine, space: &frasil_events::EventId, stream: &[u8; 16]) -> String {
    engine
        .document(space, stream)
        .await
        .map(|doc| doc.get_text("body").to_string())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_back_after_rotations_catches_up_through_a_retired_entry() {
    // A peer that keeps two live entries per space: older rotations' entries
    // retire as new ones are stored.
    let mut options = frasil_conformance::options();
    options.settings.credential_cap = 2;
    let peer = spawn_with(options).await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
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
    // While Bob is away, Alice rotates three times and writes.
    for _ in 0..3 {
        alice.engine().heal(space).await.unwrap();
    }
    let doc = alice.engine().new_document().unwrap();
    alice
        .engine()
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "while away").unwrap();
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !alice.engine().outbox(&space).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Alice's changes durable at the peer");
    // Bob comes back with only the state he left with.
    bob.connect(&peer.origin).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while text(bob.engine(), &space, &doc.stream()).await != "while away" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Bob catches up and reads Alice's note");
    peer.shutdown().await;
}
