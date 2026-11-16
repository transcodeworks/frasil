//! The peer with its records in shards: in a bucket, an event the peer
//! acknowledged is in the bucket before the acknowledgement, and another
//! node that takes the bucket up, on another machine with nothing in its
//! cache, serves what the first acknowledged, while the first stops
//! acknowledging anything; in a data directory, a restart serves the same.
//! Devices on both bindings, each in a space of its own, store at once.

mod common;

use common::{BINDINGS, Binding, DEADLINE, founder, within};
use frasil_conformance::history::History;
use frasil_events::EventId;
use frasil_relay::shards::Shards;
use frasil_relay::shards::bucket::{Bucket, BucketIo, MemoryBucket};
use frasil_relay::shards::fence::SingleNode;
use frasil_relay::testing::{Options, TestPeer, spawn_with};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// A directory of its own for this test run.
fn directory(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("frasil-peer-shards")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A node over a bucket, its working copies in `cache`. It reads the
/// bucket's `nodes/active` again every 50 ms.
fn node(bucket: &Arc<MemoryBucket>, cache: &std::path::Path) -> Arc<Shards> {
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let name = frasil_testkit::hex::encode(*frasil_crypto::random_bytes::<8>().unwrap());
    let fence = SingleNode::start_with(&io, &name, Duration::from_millis(50)).unwrap();
    Shards::bucket(io, cache, Arc::new(fence)).unwrap()
}

async fn peer_over(shards: Arc<Shards>) -> TestPeer {
    spawn_with(Options {
        shards: Some(shards),
        ..frasil_conformance::options()
    })
    .await
    .expect("a peer on loopback")
}

/// Both histories' spaces, each stored by its founder on one binding, at
/// once. Returns each space and the events acknowledged in it.
async fn store_both(peer: &TestPeer) -> Vec<(EventId, Vec<EventId>)> {
    let histories = [History::credentials(), History::skeleton()];
    let stores = histories.iter().zip(BINDINGS).map(|(history, binding)| {
        let history = history.clone();
        async move {
            let space = history.space();
            let mut device = founder(peer, binding, &history).await;
            let mut acked = vec![space];
            for name in &history.order[1..] {
                acked.extend(
                    device
                        .store(space, history.events(&[name.as_str()]), DEADLINE / 4)
                        .await,
                );
            }
            device.close().await;
            (space, acked)
        }
    });
    futures_util::future::join_all(stores).await
}

fn assert_keeps(peer: &TestPeer, stored: &[(EventId, Vec<EventId>)]) {
    for (space, acked) in stored {
        assert!(peer.peer.hosts(space.as_bytes()));
        for id in acked {
            assert!(
                peer.peer.keeps(space.as_bytes(), id.as_bytes()),
                "{id:?} was acknowledged and is in the bucket"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_acknowledged_event_is_in_the_bucket() {
    within(async {
        let bucket = Arc::new(MemoryBucket::new());
        // Every request to the bucket takes 5 ms.
        bucket.set_delay(Duration::from_millis(5));
        let first = directory("first");
        let peer = peer_over(node(&bucket, &first)).await;
        let stored = store_both(&peer).await;
        assert!(stored.iter().all(|(_, acked)| acked.len() > 2));
        // Another node, with nothing in its cache: it reads only what the
        // bucket holds.
        let second = directory("second");
        let other = peer_over(node(&bucket, &second)).await;
        assert_keeps(&other, &stored);
        other.shutdown().await;
        peer.shutdown().await;
    })
    .await;
}

/// A second node on the bucket takes it up, and the first, still running,
/// acknowledges nothing more: two writers never both acknowledge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_another_takes_over_from_refuses() {
    within(async {
        let bucket = Arc::new(MemoryBucket::new());
        let first = directory("taken-first");
        let shards = node(&bucket, &first);
        let peer = peer_over(shards.clone()).await;
        let history = History::credentials();
        let space = history.space();
        let half = history.order.len() / 2;
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        let mut acked = vec![space];
        for name in &history.order[1..half] {
            acked.extend(
                device
                    .store(space, history.events(&[name.as_str()]), DEADLINE / 4)
                    .await,
            );
        }
        assert!(acked.len() > 2);
        let second = directory("taken-second");
        let other = peer_over(node(&bucket, &second)).await;
        assert_keeps(&other, &[(space, acked.clone())]);
        // The first learns within a second or two that it is replaced.
        let fence = shards.fence().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while fence.may_write(0) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!fence.may_write(0), "the first node stops writing");
        // It refuses the rest of the history.
        let mut late = Vec::new();
        for name in &history.order[half..] {
            late.extend(
                device
                    .store(space, history.events(&[name.as_str()]), DEADLINE / 8)
                    .await,
            );
        }
        assert!(
            late.is_empty(),
            "nothing acknowledged after the takeover: {late:?}"
        );
        device.close().await;
        other.shutdown().await;
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_stops_cleanly_leaves_snapshots() {
    within(async {
        let bucket = Arc::new(MemoryBucket::new());
        let first = directory("clean");
        let shards = node(&bucket, &first);
        let peer = peer_over(shards.clone()).await;
        let stored = store_both(&peer).await;
        peer.shutdown().await;
        let closing = shards.clone();
        tokio::task::spawn_blocking(move || closing.close_all())
            .await
            .unwrap()
            .unwrap();
        drop(shards);
        let snapshots = bucket
            .keys()
            .iter()
            .filter(|key| key.contains("/snapshot-"))
            .count();
        assert!(snapshots > 0, "{:?}", bucket.keys());
        let second = directory("clean-again");
        let peer = peer_over(node(&bucket, &second)).await;
        assert_eq!(peer.peer.replays(), 0, "a start opens no space");
        assert_keeps(&peer, &stored);
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_data_directory_keeps_the_same_shards() {
    within(async {
        let dir = directory("local");
        let peer = peer_over(Shards::local(&dir).unwrap()).await;
        let stored = store_both(&peer).await;
        peer.shutdown().await;
        let peer = peer_over(Shards::local(&dir).unwrap()).await;
        assert_keeps(&peer, &stored);
        peer.shutdown().await;
    })
    .await;
}
