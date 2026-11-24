//! When a device lets go of a blob it put (at-rest.md, "Retention", an
//! object the device put): once an always-on peer that has acknowledged a
//! unit naming the blob answers, to a question put after that
//! acknowledgement, that it holds the bytes. An answer taken before the
//! unit reached the peer releases nothing, since the peer collects an
//! object no unit names (peers.md, "Objects"): the device asks again, and
//! a peer that lost the bytes takes them then. Over the iroh binding the
//! question after the acknowledgement is a request for one chunk. Every
//! wait has a deadline, and nothing leaves the host.

use frasil::advanced::peer::{PeerHandle, connect_iroh, connect_server};
use frasil::advanced::{AdapterRegistry, Engine, FetchPriority, Platform};
use frasil_conformance::{settings, spawn_loopback};
use frasil_events::EventId;
use frasil_relay::testing::TestPeer;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
}

async fn device(key: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn iroh(device: &Engine, peer: &TestPeer, space: EventId) -> PeerHandle {
    let info = peer.iroh.clone().expect("the peer listens on iroh");
    connect_iroh(
        device,
        info.endpoint,
        &info.addresses,
        &[],
        frasil_iroh::Config::loopback,
        vec![space],
    )
    .await
    .expect("an iroh connection")
}

fn bytes(length: u32) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

/// The peer answers that it holds an object before any unit names it, and
/// collects it as an orphan before the unit arrives, which it then stores
/// ahead of its object and acknowledges. The device holds the only copy:
/// it keeps the blob, uploads it again, and lets go of it only on the
/// answer to that upload, when the peer holds the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_the_peer_collected_before_its_unit_came_is_not_let_go() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let link = connect_server(&alice, &peer.origin, vec![space])
        .await
        .unwrap();
    until(|| async { alice.outbox(&space).await.is_empty() }).await;

    // The bytes reach the peer with no unit, while a request uses them.
    let content = bytes(300_000);
    let locator = alice.put_object(space, &content).await.unwrap();
    let using = alice.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    assert!(within(link.upload(space, locator)).await.unwrap());
    // No unit names them within the peer's grace: collected.
    peer.advance(settings().orphan_grace + 1).await;

    // The unit goes with no upload: the peer answered for the object on
    // this connection. It is stored ahead of its object.
    let stream = alice.new_stream("frasil:blobs").unwrap();
    let (_, named) = alice
        .put_blob(space, &stream, Some("a file"), &content)
        .await
        .unwrap();
    assert_eq!(named, locator);
    until(|| async { alice.outbox(&space).await.is_empty() }).await;
    drop(using);

    // The application may drop the blob once the device let go of it:
    // not before the peer holds the bytes again.
    until(|| async { alice.drop_local_object(space, &locator).await.is_ok() }).await;
    assert!(
        !alice
            .read(&space, |replica| replica.holds_chunk(&locator, 0))
            .await
            .unwrap()
    );
    let _fetching = alice.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    until(|| async {
        alice
            .read(&space, |replica| replica.holds_chunk(&locator, 0))
            .await
            .unwrap()
    })
    .await;
    drop(link);
}

/// Over the iroh binding, a blob this device put is uploaded before its
/// unit, and the peer's `ObjectHave` for that upload releases nothing.
/// Once the peer acknowledged the unit, the device asks it for one chunk
/// of the blob, and the chunk releases it: the blob is the cache's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_put_over_a_stream_is_let_go_once_the_peer_serves_a_chunk_of_it() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let stream = alice.new_stream("frasil:blobs").unwrap();
    // Three chunks, put before any connection: kept.
    let (_, locator) = alice
        .put_blob(space, &stream, Some("a file"), &bytes(2_500_000))
        .await
        .unwrap();
    let usage = alice.blob_cache_usage().await;
    assert!(usage.kept > 0 && usage.cached == 0, "{usage:?}");

    let link = iroh(&alice, &peer, space).await;
    until(|| async { alice.outbox(&space).await.is_empty() }).await;
    until(|| async {
        let usage = alice.blob_cache_usage().await;
        usage.cached > 0 && usage.kept == 0
    })
    .await;
    // The cache's: the application may drop it, and a fetch brings it
    // back from the peer.
    alice.drop_local_object(space, &locator).await.unwrap();
    let _fetching = alice.fetch_chunks(space, locator, 2..3, FetchPriority::Position);
    until(|| async {
        alice
            .read(&space, |replica| replica.holds_chunk(&locator, 2))
            .await
            .unwrap()
    })
    .await;
    drop(link);
}
