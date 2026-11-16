//! The client's `examples/shared_note.rs`, run whole against a peer on
//! loopback.

#[allow(dead_code)]
#[path = "../../../crates/frasil/examples/shared_note.rs"]
mod shared_note;

use frasil_conformance::spawn_loopback;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shared_note_example_runs() {
    let peer = spawn_loopback().await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(60), shared_note::run(&peer.origin))
        .await
        .expect("within the deadline")
        .unwrap();
    assert!(read.contains("Bob") && read.contains("world"));
    peer.shutdown().await;
}
