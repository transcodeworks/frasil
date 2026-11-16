//! The peer with many spaces: an event the peer acknowledged is at rest in
//! SQLite before the acknowledgement, whatever happens to the peer after;
//! a restart opens no space until one is used; and a space closed and
//! opened again serves what it served. Devices on both bindings, each in a
//! space of its own, store at once.

mod common;

use common::{BINDINGS, Binding, DEADLINE, connect, founder, present_current, within};
use frasil_conformance::client::Credential;
use frasil_conformance::history::{self, History, object, stream};
use frasil_events::{EventId, Log, Placement};
use frasil_peers::body::StorageBody;
use frasil_relay::testing::{Options, START, TestPeer, spawn_with};
use frasil_store::{MemoryStore, SqliteStore, Store};
use frasil_transport::peer::Purpose;
use frasil_units::body::{Compacts, Cover, Stub};
use std::path::PathBuf;
use std::sync::Arc;

fn database(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("frasil-peer-scaling");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}-{}.sqlite", std::process::id()));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

async fn peer_over(store: Arc<dyn Store>) -> TestPeer {
    spawn_with(Options {
        store: Some(store),
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
            // One event a message, so that each waits for its own commit.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_acknowledged_event_is_at_rest() {
    within(async {
        let path = database("acknowledged");
        let peer = peer_over(Arc::new(SqliteStore::open(&path).unwrap())).await;
        let stored = store_both(&peer).await;
        assert!(stored.iter().all(|(_, acked)| acked.len() > 2));
        // Another peer over the same file, while the first still runs:
        // it reads only what SQLite made durable.
        let other = peer_over(Arc::new(SqliteStore::open(&path).unwrap())).await;
        for (space, acked) in &stored {
            assert!(other.peer.hosts(space.as_bytes()));
            for id in acked {
                assert!(
                    other.peer.keeps(space.as_bytes(), id.as_bytes()),
                    "{id:?} was acknowledged and is at rest"
                );
            }
        }
        other.shutdown().await;
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_opens_no_space_until_one_is_used() {
    within(async {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let peer = peer_over(store.clone()).await;
        let stored = store_both(&peer).await;
        peer.shutdown().await;
        let peer = peer_over(store).await;
        assert_eq!(peer.peer.replays(), 0, "a start opens no space");
        assert_eq!(peer.peer.open_spaces(), 0);
        for (space, _) in &stored {
            assert!(peer.peer.hosts(space.as_bytes()));
        }
        // A device presents in one space: that space alone opens, whatever
        // the present's answer.
        let history = History::credentials();
        let mut device = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        let genesis = &history.order[0];
        let _ = device
            .present(
                history.space(),
                Credential::Upload,
                &history.upload_seed(genesis),
            )
            .await;
        assert_eq!(peer.peer.replays(), 1);
        assert_eq!(peer.peer.open_spaces(), 1);
        device.close().await;
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_closed_and_opened_again_serves_as_before() {
    within(async {
        let peer = peer_over(Arc::new(MemoryStore::new())).await;
        let stored = store_both(&peer).await;
        let seen = |peer: &TestPeer| {
            stored
                .iter()
                .map(|(space, acked)| {
                    let space = space.as_bytes();
                    (
                        peer.peer.entries(space),
                        peer.peer.recovery_entries(space),
                        peer.peer.usage(space),
                        acked
                            .iter()
                            .map(|id| {
                                (
                                    peer.peer.holds(space, id.as_bytes()),
                                    peer.peer.keeps(space, id.as_bytes()),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let before = seen(&peer);
        let replays = peer.peer.replays();
        // The credentials space has nothing waiting and closes; the
        // skeleton's requests keep it open.
        assert_eq!(peer.peer.close_spaces().await, 1);
        assert_eq!(peer.peer.open_spaces(), 1);
        assert_eq!(seen(&peer), before);
        assert_eq!(peer.peer.replays(), replays + 1);
        peer.shutdown().await;
    })
    .await;
}

/// A local log of events, for the heights a stub carries.
fn log_of(events: &[Vec<u8>]) -> Log {
    let mut log: Option<Log> = None;
    for signed in events {
        let event = frasil_events::decode(signed).unwrap();
        match &mut log {
            None => log = Some(Log::new(event).unwrap()),
            Some(log) => {
                assert!(matches!(log.place(event).unwrap(), Placement::Placed(_)));
            }
        }
    }
    log.unwrap()
}

/// A collection whose cover spans a snapshot of the journal and the records
/// after it removes every unit it collects: none comes back when the
/// removal folds a new snapshot, nor when the space opens again from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_collection_across_a_snapshot_removes_all_it_collects() {
    within(async {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let peer = peer_over(store.clone()).await;
        let mut history = History::credentials();
        let space = history.space();
        let mut events: Vec<Vec<u8>> = history
            .order
            .iter()
            .filter(|name| *name != "W forks")
            .map(|name| history.signed(name))
            .collect();
        let notes = stream("collected");
        let base = "P0 asks to keep V's rotation live";
        events.push(history.unit("V", "V's first unit", notes, Vec::new(), None, &[base]));
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        device.store(space, events[1..].to_vec(), DEADLINE).await;
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut device, &history).await;
        let first = history.id("V's first unit");
        assert!(peer.peer.keeps(space.as_bytes(), first.as_bytes()));
        // The first unit goes into a snapshot; the rest follows it.
        assert!(peer.peer.fold_space(space.as_bytes()).await.unwrap());
        let mut more = vec![history.unit("V", "V's second unit", notes, Vec::new(), None, &[])];
        let second = history.id("V's second unit");
        let mut all = events.clone();
        all.extend(more.clone());
        let stub = frasil_units::compaction::stub_of(&log_of(&all), second).unwrap();
        let (_, locator) = object(history::object_id("snapshot"), 10, space);
        let compacts = Compacts {
            object: locator,
            covers: vec![Cover {
                writer: history.device_id("V"),
                unit: second,
            }],
            stubs: vec![Stub {
                stream: None,
                ..stub
            }],
        };
        more.push(history.unit(
            "P",
            "P's snapshot unit",
            notes,
            vec![locator],
            Some(compacts),
            &["V's second unit"],
        ));
        more.push(history.storage(
            "P0",
            "P0 acknowledges the snapshot unit",
            &StorageBody::Ack,
            &["P's snapshot unit"],
        ));
        device.store(space, more, DEADLINE).await;
        let snapshot = history.id("P's snapshot unit");
        peer.set_time(START).await;
        let keeps =
            |peer: &TestPeer, id: &EventId| peer.peer.keeps(space.as_bytes(), id.as_bytes());
        assert!(keeps(&peer, &snapshot));
        assert!(
            !keeps(&peer, &first),
            "the unit in the snapshot is collected"
        );
        assert!(!keeps(&peer, &second), "the unit after it is collected");
        // Opened again from its records, by another peer over them.
        let other = peer_over(store).await;
        assert!(keeps(&other, &snapshot));
        assert!(!keeps(&other, &first) && !keeps(&other, &second));
        other.shutdown().await;
        device.close().await;
        peer.shutdown().await;
    })
    .await;
}

/// A peer that stops closes each connection with `reconnect`, on both
/// bindings (transport.md, 3.10, "Reconnecting elsewhere").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopping_peer_asks_its_devices_to_reconnect() {
    within(async {
        let peer = peer_over(Arc::new(MemoryStore::new())).await;
        let mut ws = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        let mut iroh = connect(&peer, Binding::Iroh, Purpose::SpaceTraffic).await;
        let started = std::time::Instant::now();
        peer.peer
            .stop_connections(std::time::Duration::from_secs(30))
            .await;
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(ws.closed(DEADLINE).await, Some(Some(4017)));
        assert_eq!(iroh.closed(DEADLINE).await, Some(Some(17)));
        peer.shutdown().await;
    })
    .await;
}
