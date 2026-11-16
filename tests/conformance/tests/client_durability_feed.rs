//! A space-wide durability feed: `Space::observe_durable` says whether the
//! space has nothing unsent, and changes as the device writes and as the
//! peer acknowledges. Every wait has a deadline, and nothing leaves the
//! host.

use frasil::{Device, Options, Status, Storage};
use frasil_conformance::spawn_loopback;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn value_becomes(observed: &mut frasil::Observed<bool>, wanted: bool) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let now = observed.get();
            if now.status == Status::Ready && now.value.as_deref() == Some(&wanted) {
                return;
            }
            observed.changed().await.expect("the device is open");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("durable became {wanted} within the deadline"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_durability_feed_follows_writes_and_acknowledgements() {
    let peer = spawn_loopback().await.unwrap();
    let alice = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let mut durable = space.observe_durable();
    // Nothing has reached a peer yet.
    value_becomes(&mut durable, false).await;

    alice.connect(&peer.origin).await.unwrap();
    space.wait_durable(DEADLINE).await.unwrap();
    value_becomes(&mut durable, true).await;

    // A write the peer acknowledges leaves it true once acknowledged.
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    space.wait_durable(DEADLINE).await.unwrap();
    value_becomes(&mut durable, true).await;

    // Paused, a write stays unsent, and the feed says so.
    space.pause_sync();
    note.edit(|doc| doc.get_text("body").insert(5, "!"))
        .await
        .unwrap();
    value_becomes(&mut durable, false).await;
    space.resume_sync();
    value_becomes(&mut durable, true).await;

    alice.close().await.unwrap();
    peer.shutdown().await;
}
