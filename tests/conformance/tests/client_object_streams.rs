//! A device that fetches an object's chunks from an always-on peer over
//! the iroh binding, by `ObjectWant` on the space's sync stream (units.md,
//! "Sync", objects): a range is asked for from any chunk, and the
//! connection reports an object while chunks of it are awaited, and no
//! longer. Every wait has a deadline, and nothing leaves the host.

use frasil::advanced::peer::{PeerHandle, connect_iroh, connect_server};
use frasil::advanced::{AdapterRegistry, Engine, FetchPriority, Platform};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_relay::testing::TestPeer;
use frasil_space::{HistoryMode, Level, Via};
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

/// Whether the device holds a chunk of the blob.
async fn holds(device: &Engine, space: &EventId, locator: &[u8; 64], chunk: u64) -> bool {
    device
        .read(space, |replica| replica.holds_chunk(locator, chunk))
        .await
        .unwrap()
}

/// Alice's space with Bob granted "with history", and a blob of five and
/// a half chunks durable at the peer. Bob fetches blobs only when asked.
async fn setup(peer: &TestPeer) -> (Engine, PeerHandle, Engine, EventId, [u8; 64], Vec<u8>) {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.follow(space).await;
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let alice_link = connect_server(&alice, &peer.origin, vec![space])
        .await
        .unwrap();
    let big: Vec<u8> = (0..5_770_000u32).map(|i| (i % 251) as u8).collect();
    let stream = alice.new_stream("frasil:blobs").unwrap();
    let (_, locator) = alice
        .put_blob(space, &stream, Some("big.bin"), &big)
        .await
        .unwrap();
    until(|| async { alice.outbox(&space).await.is_empty() }).await;
    bob.fetch_objects_on_demand();
    (alice, alice_link, bob, space, locator, big)
}

/// A range asked for on a stream is reported while its chunks are
/// awaited, and no longer once they are in, though the object is not
/// whole; the whole object is then fetched around the chunks held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_fetched_on_a_stream_is_reported_until_it_is_in() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, alice_link, bob, space, locator, big) = setup(&peer).await;
    let link = iroh(&bob, &peer, space).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!holds(&bob, &space, &locator, 0).await);

    let range = bob.fetch_chunks(space, locator, 1..3, FetchPriority::Position);
    until(|| async {
        holds(&bob, &space, &locator, 1).await && holds(&bob, &space, &locator, 2).await
    })
    .await;
    assert!(!holds(&bob, &space, &locator, 0).await);
    assert!(bob.object(&space, &locator).await.is_err());
    until(|| async { link.status().fetching.is_empty() }).await;

    let whole = bob.fetch_chunks(space, locator, 0..u64::MAX, FetchPriority::Background);
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    until(|| async { link.status().fetching.is_empty() }).await;
    drop((range, whole));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}
