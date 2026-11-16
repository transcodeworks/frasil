//! Pausing a space's sync with always-on peers, as for a suspended library:
//! while paused, the device neither stores nor fetches the space at the
//! peer, and the space stays readable and writable on the device; resumed,
//! it catches up both ways. Every wait has a deadline, and nothing leaves
//! the host.

use frasil::{Device, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_space::{HistoryMode, Level, Via};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    tokio::time::timeout(DEADLINE, async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("within the deadline");
}

async fn text(space: &frasil::Space, id: frasil::StreamId) -> Option<String> {
    match space.document(id).await {
        Ok(doc) => doc.text("body").await.ok(),
        Err(_) => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paused_space_neither_stores_nor_fetches_and_catches_up_on_resume() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    let event = frasil_events::EventId(*space.id().as_bytes());
    alice
        .engine()
        .grant_device(
            event,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(event).await;
    bob.engine()
        .ingest(event, alice.engine().events(&event).await)
        .await
        .unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "One"))
        .await
        .unwrap();
    alice.connect(&peer.origin).await.unwrap();
    space.wait_durable(DEADLINE).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let bobs = bob.space(space.id()).await.unwrap();
    until(|| async { text(&bobs, note.id()).await.as_deref() == Some("One") }).await;

    // Bob pauses the space: Alice's next change does not reach him, and
    // his own stays on his device, readable there.
    bobs.pause_sync();
    assert!(bobs.is_sync_paused());
    note.edit(|doc| doc.get_text("body").insert(3, " two"))
        .await
        .unwrap();
    space.wait_durable(DEADLINE).await.unwrap();
    let bobs_note = bobs.create_document().unwrap();
    bobs_note
        .edit(|doc| doc.get_text("body").insert(0, "Bob's"))
        .await
        .unwrap();
    assert!(
        bobs.wait_durable(Duration::from_secs(2)).await.is_err(),
        "nothing is stored while paused"
    );
    assert_eq!(text(&bobs, bobs_note.id()).await.as_deref(), Some("Bob's"));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        text(&bobs, note.id()).await.as_deref(),
        Some("One"),
        "nothing is fetched while paused"
    );
    assert_eq!(text(&space, bobs_note.id()).await, None);

    // Resumed, both catch up.
    bobs.resume_sync();
    assert!(!bobs.is_sync_paused());
    bobs.wait_durable(DEADLINE).await.unwrap();
    until(|| async { text(&bobs, note.id()).await.as_deref() == Some("One two") }).await;
    until(|| async { text(&space, bobs_note.id()).await.as_deref() == Some("Bob's") }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
