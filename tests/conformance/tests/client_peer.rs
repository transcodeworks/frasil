//! Devices and an always-on peer on loopback, over the server binding's
//! WebSocket and the iroh binding: creating a space at the peer, catching
//! up, a removal, a heal and its merge statement, a restore the device
//! detects, and work offline over the local network. Every wait has a
//! deadline, and nothing leaves the host.

use frasil::advanced::node::Node;
use frasil::advanced::peer::{PeerHandle, connect_iroh, connect_server};
use frasil::advanced::{AdapterRegistry, Continuity, Engine, Platform};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_iroh::lan::LanConfig;
use frasil_relay::testing::TestPeer;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_store::{Commit, DeviceBoundSlot, MemorySlot, MemoryStore, Store};
use frasil_transport::codes::Right;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// The longest one wait polls its condition: generous, since a full
/// workspace run on a loaded machine syncs over the local network and the
/// peer far more slowly than this file alone does.
const DEADLINE: Duration = Duration::from_secs(90);

async fn device() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

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

async fn text_of(device: &Engine, space: &EventId, stream: &[u8; 16]) -> Option<String> {
    device
        .document(space, stream)
        .await
        .ok()
        .map(|doc| doc.get_text("body").to_string())
}

async fn server(device: &Engine, peer: &TestPeer, space: EventId) -> PeerHandle {
    connect_server(device, &peer.origin, vec![space])
        .await
        .expect("a WebSocket connection")
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

/// Waits until the device's outbox of the space is empty: the peer has
/// acknowledged every event it signed there.
async fn durable(device: &Engine, space: &EventId) {
    until(|| async { device.outbox(space).await.is_empty() }).await;
}

/// A space of Alice's with Bob and Carol granted "with history", every
/// event carried by hand.
async fn three_members() -> (Engine, Engine, Engine, EventId) {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for other in [&bob, &carol] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    for other in [&bob, &carol] {
        other.follow(space).await;
        other
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
    }
    (alice, bob, carol, space)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_creates_its_space_at_the_peer_and_its_events_become_durable() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "kept").unwrap();
        })
        .await
        .unwrap();
    assert!(!alice.outbox(&space).await.is_empty());
    let link = server(&alice, &peer, space).await;
    durable(&alice, &space).await;
    let status = link.status();
    assert_eq!(status.created, vec![space]);
    let rights = &status.granted[&space];
    for right in [Right::Fetch, Right::Live, Right::Store] {
        assert!(rights.contains(&right), "{rights:?}");
    }
    // A new unit goes to the peer live, and becomes durable.
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(4, " live").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    assert!(link.status().refused_events.is_empty());
    link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_catches_up_from_the_peer_over_iroh() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, _carol, space) = three_members().await;
    let alice_link = server(&alice, &peer, space).await;
    // While Bob is away, Alice writes and rotates.
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "while you were away").unwrap();
        })
        .await
        .unwrap();
    let heal = alice.heal(space).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "after the heal: ").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    // Bob holds only the state from before the heal; its credential still
    // fetches, and the heal wraps the new key for him.
    let bob_link = iroh(&bob, &peer, space).await;
    until(|| async {
        text_of(&bob, &space, &doc.stream()).await.as_deref()
            == Some("after the heal: while you were away")
    })
    .await;
    assert!(bob.read(&space, |r| r.secrets_held(&heal)).await.unwrap());
    // Bob writes back; it reaches Alice live through the peer.
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "bob: ").unwrap();
    })
    .await
    .unwrap();
    durable(&bob, &space).await;
    until(|| async {
        text_of(&alice, &space, &doc.stream()).await.as_deref()
            == Some("bob: after the heal: while you were away")
    })
    .await;
    alice_link.close();
    bob_link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_fetches_but_reads_nothing_new() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, carol, space) = three_members().await;
    let links = [
        server(&alice, &peer, space).await,
        server(&bob, &peer, space).await,
        iroh(&carol, &peer, space).await,
    ];
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "for everyone").unwrap();
        })
        .await
        .unwrap();
    until(|| async {
        text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("for everyone")
    })
    .await;
    let removal = alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "without bob: ").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    until(|| async {
        text_of(&carol, &space, &doc.stream()).await.as_deref() == Some("without bob: for everyone")
    })
    .await;
    // Bob fetches the removal through the peer. He never receives its key;
    // its removal wrap hands him its body key alone, so he opens the
    // removal itself and nothing after it.
    until(|| async {
        bob.read(&space, |r| r.status(&removal).is_some())
            .await
            .unwrap()
    })
    .await;
    let held = bob
        .read(&space, |r| r.status(&removal).and_then(|s| s.class()))
        .await
        .unwrap();
    assert_eq!(held.map(frasil_base::errors::Class::name), None);
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        None
    );
    assert!(
        !bob.read(&space, |r| r.secrets_held(&removal))
            .await
            .unwrap()
    );
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        text_of(&bob, &space, &doc.stream()).await.as_deref(),
        Some("for everyone")
    );
    for link in links {
        link.close();
    }
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_heals_merge_and_a_writer_tells_the_peer_the_merged_state() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, carol, space) = three_members().await;
    // Bob and Carol heal concurrently, apart.
    let bob_heal = bob.heal(space).await.unwrap();
    let carol_heal = carol.heal(space).await.unwrap();
    let bob_link = server(&bob, &peer, space).await;
    let carol_link = iroh(&carol, &peer, space).await;
    durable(&bob, &space).await;
    durable(&carol, &space).await;
    // Each takes the other's heal from the peer: the current state merges
    // them, and a writer that holds both upload seeds publishes the merge
    // statement before it presents the merged state.
    let merged = until_merged(&bob, &space, bob_heal, carol_heal).await;
    until_merged(&carol, &space, bob_heal, carol_heal).await;
    until(|| async {
        [&bob_link, &carol_link]
            .iter()
            .any(|link| link.status().merges.contains(&(space, merged.clone())))
    })
    .await;
    for link in [&bob_link, &carol_link] {
        assert!(link.status().refused.is_empty(), "{:?}", link.status());
    }
    // A unit under the merged state is stored and acknowledged.
    let doc = bob.new_document().unwrap();
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "merged").unwrap();
    })
    .await
    .unwrap();
    durable(&bob, &space).await;
    let alice_link = server(&alice, &peer, space).await;
    until(|| async { text_of(&alice, &space, &doc.stream()).await.as_deref() == Some("merged") })
        .await;
    let current = alice.read(&space, |r| r.current().cloned()).await.unwrap();
    assert_eq!(current.as_ref(), Some(&merged));
    for link in [bob_link, carol_link, alice_link] {
        link.close();
    }
    peer.shutdown().await;
}

async fn until_merged(
    device: &Engine,
    space: &EventId,
    a: EventId,
    b: EventId,
) -> frasil_keys::RotationSet {
    within(async {
        loop {
            let current = device.read(space, |r| r.current().cloned()).await.unwrap();
            if let Some(state) = current
                && state.ids().contains(&a)
                && state.ids().contains(&b)
            {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_device_takes_its_own_events_from_the_peer_before_it_signs() {
    let peer = spawn_loopback().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[5; 32],
        registry.clone(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let link = server(&alice, &peer, space).await;
    durable(&alice, &space).await;
    let saved = store.scan(&[]).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    link.close();
    drop(alice);

    // The store comes back from the backup; the device finds the restore
    // by its mark, and signs nothing until a peer served its newer events.
    let restored = Arc::new(MemoryStore::new());
    assert!(
        restored
            .commit(&Commit::new(saved, Vec::new()))
            .await
            .unwrap()
    );
    let alice = Engine::open(Platform::new(restored, slot), &sealed, &[5; 32], registry)
        .await
        .unwrap();
    assert_eq!(alice.continuity().await, Continuity::Restored);
    assert!(!alice.may_sign(&space).await);
    let link = iroh(&alice, &peer, space).await;
    until(|| async { alice.may_sign(&space).await }).await;
    assert_eq!(
        text_of(&alice, &space, &doc.stream()).await.as_deref(),
        Some("one two")
    );
    // Its next unit follows its newest event: the peer stores it, no fork.
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(7, " three").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    assert!(link.status().forks.is_empty());
    link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_peer_refuses_a_forked_event_as_a_conflict() {
    let peer = spawn_loopback().await.unwrap();
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[5; 32],
        registry.clone(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let saved = store.scan(&[]).await.unwrap();
    let link = server(&alice, &peer, space).await;
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    link.close();
    drop(alice);

    // Restored and told wrongly that it is in sync, it signs its last
    // `seq` again; the peer keeps both as evidence and refuses the second.
    let restored = Arc::new(MemoryStore::new());
    assert!(
        restored
            .commit(&Commit::new(saved, Vec::new()))
            .await
            .unwrap()
    );
    let alice = Engine::open(Platform::new(restored, slot), &sealed, &[5; 32], registry)
        .await
        .unwrap();
    alice.synced(&space).await.unwrap();
    let forked = alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " other").unwrap();
        })
        .await
        .unwrap();
    let link = server(&alice, &peer, space).await;
    until(|| async { !link.status().forks.is_empty() }).await;
    assert_eq!(link.status().forks, vec![(space, forked)]);
    assert!(
        alice.outbox(&space).await.contains(&forked),
        "a refused event stays in the outbox"
    );
    link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_work_offline_over_the_local_network_then_the_peer_catches_up() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, _carol, space) = three_members().await;
    let alice_link = server(&alice, &peer, space).await;
    let bob_link = server(&bob, &peer, space).await;
    let doc = bob.new_document().unwrap();
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "online").unwrap();
    })
    .await
    .unwrap();
    durable(&alice, &space).await;
    durable(&bob, &space).await;
    alice_link.close();
    bob_link.close();
    // The peer is out of reach: Alice and Bob find each other on the local
    // network and sync there.
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    alice_node.discover(LanConfig::loopback_v4()).unwrap();
    bob_node.discover(LanConfig::loopback_v4()).unwrap();
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "offline, ").unwrap();
    })
    .await
    .unwrap();
    until(|| async {
        text_of(&alice, &space, &doc.stream()).await.as_deref() == Some("offline, online")
    })
    .await;
    // With a peer known in the space, a member's acknowledgement does not
    // make Bob's unit durable: it waits for a peer.
    assert!(!bob.outbox(&space).await.is_empty());
    // Back online, Alice relays Bob's unit to the peer; the peer's
    // acknowledgement reaches Bob when he connects.
    let alice_link = iroh(&alice, &peer, space).await;
    let bob_link = server(&bob, &peer, space).await;
    durable(&bob, &space).await;
    alice_node.close().await;
    bob_node.close().await;
    alice_link.close();
    bob_link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn objects_travel_over_http_slices_and_iroh_chunks() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, _carol, space) = three_members().await;
    let alice_link = server(&alice, &peer, space).await;
    let bob_link = iroh(&bob, &peer, space).await;
    // Three sealed chunks and three HTTP slices.
    let big: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
    let stream = alice.new_stream("frasil:blobs").unwrap();
    let (_, locator) = alice
        .put_blob(space, &stream, Some("big.bin"), &big)
        .await
        .unwrap();
    // The unit waits for its object's upload, then becomes durable.
    durable(&alice, &space).await;
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    // Bob uploads over iroh; Alice fetches over HTTP.
    let (_, small) = bob
        .put_blob(space, &stream, Some("note.txt"), b"from bob")
        .await
        .unwrap();
    durable(&bob, &space).await;
    until(|| async { alice.object(&space, &small).await.is_ok() }).await;
    assert_eq!(alice.object(&space, &small).await.unwrap(), b"from bob");
    alice_link.close();
    bob_link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newcomer_uses_a_snapshot_whose_cover_the_peer_collected() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, _bob, carol, space) = three_members().await;
    let alice_link = server(&alice, &peer, space).await;
    let doc = alice.new_document().unwrap();
    for word in ["one", " two", " three"] {
        alice
            .edit_document(space, &doc, |d| {
                let body = d.get_text("body");
                body.insert(body.len_unicode(), word).unwrap();
            })
            .await
            .unwrap();
    }
    // The stream's units so far: the snapshot's cover.
    let covered: Vec<EventId> = alice
        .events(&space)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter_map(|event| frasil_units::Unit::from_event(event).ok())
        .filter(|unit| unit.body.stream == doc.stream())
        .map(|unit| unit.id())
        .collect();
    assert_eq!(covered.len(), 3);
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), " four").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    // Closed, not only asked to close: a link still open would hand the
    // peer the cover again once it collected it, and Carol would read the
    // units rather than the snapshot.
    alice_link.close();
    until(|| async { alice_link.is_closed() }).await;
    // Past `erasure_timeout`, the peer collects the snapshot's cover: it
    // sweeps until it holds none of it, however slowly it saw the units.
    peer.advance(7 * 86_400 + 60).await;
    until(|| async {
        let held = covered.iter().any(|id| peer.peer.holds(&space.0, &id.0));
        if held {
            peer.advance(60).await;
        }
        !held
    })
    .await;

    let carol_link = iroh(&carol, &peer, space).await;
    until(|| async { carol_link.status().granted.contains_key(&space) }).await;
    carol_link.want_stream(space, doc.stream());
    until(|| async {
        text_of(&carol, &space, &doc.stream()).await.as_deref() == Some("one two three four")
    })
    .await;
    let used = carol
        .read(&space, |r| r.used_snapshots().clone())
        .await
        .unwrap();
    assert!(used.contains(&snapshot), "{used:?}");
    until(|| async {
        carol_link
            .status()
            .stream_heads
            .get(&(space, doc.stream()))
            .is_some_and(|(latest, _)| *latest == Some(snapshot))
    })
    .await;
    carol_link.close();
    peer.shutdown().await;
}

/// A device whose earlier events a member already acknowledged, so that
/// they are no longer in its outbox, connects to a peer that holds none of
/// them, then writes. The peer's `Heads` ask for everything: the events
/// that are ready go before the units held back for their object's upload,
/// never after them, so that the peer stores each after its parents and
/// acknowledges the new edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn units_held_back_for_an_upload_go_after_the_events_before_them() {
    use frasil::advanced::outbox::Acknowledger;
    let peer = spawn_loopback().await.unwrap();
    let alice = frasil::Device::open_with(
        frasil::Storage::Memory,
        &[61; 32],
        frasil::Options::new().loopback(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    let engine = alice.engine();
    // A unit that names an object, after the space's own events.
    let blobs = space.create_blobs().unwrap();
    blobs.put(Some("one"), b"one").await.unwrap();
    // A member acknowledges all of it, as a member that joined nearby
    // does: none of it is in the outbox any more.
    let heads: Vec<EventId> = engine
        .events(&id)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| event.id())
        .collect();
    engine
        .acknowledge(id, Acknowledger::Member([9; 32]), &heads)
        .await
        .unwrap();
    assert!(engine.outbox(&id).await.is_empty());
    alice.connect(&peer.origin).await.unwrap();
    blobs.put(Some("two"), b"two").await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !engine.outbox(&id).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("what was written after connecting is acknowledged by the peer");
    peer.shutdown().await;
}
