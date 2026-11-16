//! Releasing and restoring a stream from the high-level API, against a
//! live peer (peers.md, 3.18 Release and restore): the peer stops serving
//! a released document, the device writes nothing in it, and a restore
//! brings it back. Every wait has a deadline, and nothing leaves the host.

use frasil::{Device, Error, Options, Storage};
use frasil_conformance::spawn_loopback;
use std::time::Duration;

const DURABLE: Duration = Duration::from_secs(60);

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_is_released_at_the_peer_and_restored() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "draft"))
        .await
        .unwrap();
    let other = space.create_document().unwrap();
    other
        .edit(|doc| doc.get_text("body").insert(0, "other"))
        .await
        .unwrap();
    let table = space.create_records().unwrap();
    table
        .write(|t| {
            t.insert("t", b"k");
        })
        .await
        .unwrap();
    space.wait_durable(DURABLE).await.unwrap();
    let at_peer =
        |stream: frasil::StreamId| peer.peer.released(space.id().as_bytes(), stream.as_bytes());

    // Released: the peer stops serving it, and this device writes nothing
    // in it; what it holds stays readable here.
    note.release().await.unwrap();
    assert!(note.is_released().await.unwrap());
    space.wait_durable(DURABLE).await.unwrap();
    assert!(at_peer(note.id()));
    assert!(!at_peer(other.id()));
    assert_eq!(
        note.edit(|doc| doc.get_text("body").insert(0, "more "))
            .await
            .unwrap_err(),
        Error::Released
    );
    assert_eq!(note.text("body").await.unwrap(), "draft");
    // Releasing again signs nothing.
    let pending = space.pending_authored_changes().await;
    note.release().await.unwrap();
    assert_eq!(space.pending_authored_changes().await, pending);

    // Restored: served again, and written again.
    note.restore().await.unwrap();
    assert!(!note.is_released().await.unwrap());
    space.wait_durable(DURABLE).await.unwrap();
    assert!(!at_peer(note.id()));
    note.edit(|doc| doc.get_text("body").insert(0, "final "))
        .await
        .unwrap();
    space.wait_durable(DURABLE).await.unwrap();

    // Every document but the ones kept; tables stay.
    let released = space.release_documents(&[other.id()]).await.unwrap();
    assert_eq!(released, vec![note.id()]);
    space.wait_durable(DURABLE).await.unwrap();
    assert!(at_peer(note.id()));
    assert!(!at_peer(other.id()));
    assert!(!at_peer(table.id()));
    let rest = space.release_documents(&[]).await.unwrap();
    assert_eq!(rest, vec![other.id()]);
    space.wait_durable(DURABLE).await.unwrap();
    assert!(at_peer(other.id()));

    alice.close().await.unwrap();
    peer.shutdown().await;
}
