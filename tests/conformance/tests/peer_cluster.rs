//! Several nodes acting as one peer over one bucket (peers.md, 3.1 Hosting
//! a space, "One peer on several machines"), each a peer on loopback with
//! in-process links: three nodes form one cluster; a device on one node
//! edits a space another owns, and a device on a third sees it live; an
//! owner that dies hands its shards over after its lease and loses no
//! acknowledged event; an owner cut off from the others stops
//! acknowledging before its lease ends; and a node whose clock runs fast
//! or slow never writes after its lease by true time. Then the harder
//! cases: an owner cut off, replaced and joined again writes nothing it
//! opened before and serves what its successor stored; a node that left
//! cleanly is placed again when it starts; leases hold across a leader's
//! failover; two bootstraps on one bucket leave one cluster, and a claim
//! landing late stops the other; a write slowed to just under its timeout
//! still lands within the lease; a reader's subscription moves with its
//! space, with no delivery missed or repeated; an overloaded node moves a
//! few devices at a time; a drained node hands its shards over before its
//! devices reconnect; leases keep renewing while one node is down and
//! another rejoins; and a node restarted within its lease joins again.
//! With the extensions: two creates of one space through two shards keep
//! one, and a drop placed through one node is served by every node. And
//! answers larger than a frame of the links between nodes cross them
//! whole, beside other traffic, without closing a link.

mod common;

use common::{DEADLINE, present_current, within};
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{History, stream};
use frasil_events::EventId;
use frasil_relay::cluster::lease::Timing;
use frasil_relay::cluster::{Cluster, ClusterConfig, Listen, Wiring};
use frasil_relay::shards::bucket::{Bucket, BucketIo};
use frasil_relay::testing::cluster::{KEY, Node, SLOW_TIMING, TIMING, TestCluster};
use frasil_transport::codes::Right;
use frasil_transport::peer::Purpose;
use frasil_units::messages::Message as UnitMessage;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Long enough for a dead owner's lease to end and its shards to open
/// elsewhere.
const TAKEOVER: Duration = Duration::from_secs(15);

async fn cluster(seed: u64) -> TestCluster {
    TestCluster::start_with(3, TIMING, seed, frasil_conformance::settings())
        .await
        .expect("three nodes form a cluster")
}

/// The credentials history's events, but `W forks`, whose body is not a
/// unit's.
fn events(history: &History) -> Vec<Vec<u8>> {
    history
        .order
        .iter()
        .filter(|n| *n != "W forks")
        .map(|n| history.signed(n))
        .collect()
}

fn ids(events: &[Vec<u8>]) -> Vec<EventId> {
    events
        .iter()
        .map(|e| frasil_events::decode(e).unwrap().id())
        .collect()
}

/// A device on `node` that created the space from the genesis, holding its
/// upload key.
async fn founder_on(node: &Node, history: &History) -> PeerClient {
    let space = history.space();
    let mut device = PeerClient::ws(&node.peer, Purpose::SpaceTraffic).await;
    let acked = device
        .store(space, history.events(&[&history.order[0]]), DEADLINE)
        .await;
    assert_eq!(acked, vec![space], "the genesis creates the space");
    device
        .present(
            space,
            Credential::Upload,
            &history.upload_seed(&history.order[0]),
        )
        .await
        .expect("the genesis's upload key");
    device
}

/// A unit of V's, numbered, that the founder may store once the whole
/// credentials history is stored.
fn unit(history: &mut History, n: usize) -> Vec<u8> {
    history.unit(
        "V",
        &format!("V writes {n}"),
        stream("notes"),
        Vec::new(),
        None,
        &[],
    )
}

/// Every node other than `not`.
fn others(cluster: &TestCluster, not: usize) -> Vec<usize> {
    (0..cluster.nodes.len())
        .filter(|&n| n != not && cluster.nodes[n].is_some())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_form_one_cluster() {
    within(async {
        let cluster = cluster(1).await;
        let first = cluster.node(0).cluster.membership();
        assert_eq!(first.nodes.len(), 3);
        assert!(!first.cluster.is_empty());
        let mut leaders = Vec::new();
        for n in 0..3 {
            let node = cluster.node(n);
            let state = node.cluster.membership();
            assert_eq!((state.epoch, &state.cluster), (first.epoch, &first.cluster));
            let metrics = node.cluster.raft().metrics().borrow().clone();
            assert_eq!(
                metrics.membership_config.membership().voter_ids().count(),
                3
            );
            leaders.push(metrics.current_leader);
            assert!(node.cluster.serving(), "every node holds its lease");
        }
        assert!(leaders.iter().all(|l| l.is_some() && *l == leaders[0]));
        // Discovery lists every node's iroh endpoint key (transport.md,
        // 3.15).
        let url = format!("{}/.well-known/frasil", cluster.node(1).peer.origin);
        let document: serde_json::Value = frasil_conformance::http_client()
            .get(&url)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(document["iroh"]["endpoints"].as_array().unwrap().len(), 3);
        // A second bootstrap on the bucket is refused.
        let shared: Arc<dyn Bucket> = cluster.bucket.clone();
        let io = Arc::new(BucketIo::new(shared).unwrap());
        let net = Arc::new(frasil_relay::cluster::link::MemoryNet::new());
        let again = Cluster::start(
            ClusterConfig {
                key: KEY.into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: "elsewhere".into(),
                seeds: Vec::new(),
                capacity: 100,
                bootstrap: true,
                timing: TIMING,
                spaces_per_connection: frasil_relay::cluster::SPACES_PER_CONNECTION,
            },
            "00000000000077770000000000000000",
            None,
            io,
            Wiring {
                listen: Listen::Memory(net.listen("elsewhere")),
                net,
                faults: Arc::default(),
                clock: Arc::new(frasil_relay::cluster::lease::SystemLeaseClock::default()),
                raft: Arc::new(frasil_store::MemoryStore::new()),
            },
        )
        .await;
        let refused = again.expect_err("a bucket that names a cluster is not bootstrapped again");
        assert!(refused.0.contains("names cluster"), "{refused}");
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_on_one_node_edits_a_space_another_owns_and_a_third_sees_it() {
    within(async {
        let cluster = cluster(2).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        // The writer is on the node that owns the space once the owner is
        // gone, and the reader on the other.
        let shard = cluster.node(owner).shards.space_shard_of(space.as_bytes());
        let gone = cluster.node(owner).id;
        let placed: Vec<_> = cluster
            .node(owner)
            .cluster
            .membership()
            .placed()
            .into_iter()
            .filter(|(id, _)| *id != gone)
            .collect();
        let next = frasil_relay::cluster::placement::owner(&shard, &placed).unwrap();
        let a = cluster.index_of(next).unwrap();
        let b = others(&cluster, owner)
            .into_iter()
            .find(|&n| n != a)
            .unwrap();
        let mut writer = founder_on(cluster.node(a), &history).await;
        let stored = events(&history)[1..].to_vec();
        let acked = writer.store(space, stored.clone(), DEADLINE).await;
        assert_eq!(acked.len(), stored.len(), "every event is acknowledged");
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut writer, &history).await;
        // The owner keeps them; the gateway keeps none of its own.
        for id in ids(&stored) {
            assert!(
                cluster
                    .node(owner)
                    .peer
                    .peer
                    .holds(space.as_bytes(), id.as_bytes())
            );
            assert!(
                !cluster
                    .node(a)
                    .peer
                    .peer
                    .keeps(space.as_bytes(), id.as_bytes())
            );
        }
        // A reader on the third node subscribes through it.
        let mut reader = PeerClient::ws(&cluster.node(b).peer, Purpose::SpaceTraffic).await;
        let granted = reader
            .present(
                space,
                Credential::Read,
                &history.read_seed("V rotates, citing W's rotation"),
            )
            .await
            .expect("a live read credential at the owner, through the gateway");
        assert_eq!(granted.rights, vec![Right::Fetch, Right::Live]);
        reader
            .send_sync(
                space,
                UnitMessage::Subscribe {
                    streams: Vec::new(),
                },
            )
            .await;
        // The reader catches up as a device does once subscribed: it holds
        // everything stored so far.
        let _ = reader
            .exchange(
                space,
                UnitMessage::Heads {
                    heads: Vec::new(),
                    vector: None,
                    streams: Vec::new(),
                },
            )
            .await;
        let written = unit(&mut history, 0);
        assert!(writer.store_one(space, &written, DEADLINE).await);
        let delivered = reader
            .wait_for(DEADLINE, |message| {
                match PeerClient::unit_message(message, space) {
                    Some(UnitMessage::Events { events }) => Some(events),
                    _ => None,
                }
            })
            .await
            .expect("live delivery through the owner and the reader's gateway");
        assert_eq!(delivered, vec![written]);
        writer.close().await;
        reader.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A credentials request carried out at the space's owner ends what a
/// reader on another node held under the entry it retired: the owner keeps
/// the reader's grant and subscription, ends them, and asks the reader's
/// gateway to close its connection with `reconnect`. A reader that also
/// proved an entry the request keeps live goes on receiving (peers.md, 3.6
/// Retirement and the cap, "Connections").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retired_entry_ends_a_readers_live_delivery_through_its_gateway() {
    within(async {
        let cluster = cluster(41).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let gateway = others(&cluster, owner)[0];
        let mut writer = founder_on(cluster.node(owner), &history).await;
        let stored = events(&history)[1..].to_vec();
        let at = stored
            .iter()
            .position(|signed| {
                frasil_events::decode(signed).unwrap().id()
                    == history.id("P0 asks to keep the removal's entry live")
            })
            .unwrap();
        // Everything before P0's first request.
        let acked = writer.store(space, stored[..at].to_vec(), DEADLINE).await;
        assert_eq!(acked.len(), at);
        // Two readers through the gateway: one live by the genesis's read
        // credential alone, one by the removal's too.
        let mut readers = Vec::new();
        for rotations in [
            vec!["P creates the space"],
            vec!["P creates the space", "P removes W"],
        ] {
            let mut reader =
                PeerClient::ws(&cluster.node(gateway).peer, Purpose::SpaceTraffic).await;
            for rotation in rotations {
                let granted = reader
                    .present(space, Credential::Read, &history.read_seed(rotation))
                    .await
                    .expect("a live read credential at the owner, through the gateway");
                assert_eq!(granted.rights, vec![Right::Fetch, Right::Live]);
            }
            reader
                .send_sync(
                    space,
                    UnitMessage::Subscribe {
                        streams: Vec::new(),
                    },
                )
                .await;
            // The subscription travels before the next store.
            let _ = reader
                .exchange(
                    space,
                    UnitMessage::Heads {
                        heads: Vec::new(),
                        vector: None,
                        streams: Vec::new(),
                    },
                )
                .await;
            readers.push(reader);
        }
        let mut kept = readers.pop().unwrap();
        let mut ended = readers.pop().unwrap();
        // The request, stable at the owner as soon as it is stored: it
        // retires the genesis's entry and keeps the removal's.
        let request = vec![stored[at].clone()];
        assert_eq!(writer.store(space, request, DEADLINE).await.len(), 1);
        assert_eq!(
            ended.closed(DEADLINE).await,
            Some(Some(4017)),
            "the gateway closes the connection whose live delivery ended"
        );
        // The other reader is still delivered what is stored live, here by
        // a writer under the removal's entry.
        writer
            .present(
                space,
                Credential::Upload,
                &history.upload_seed("P removes W"),
            )
            .await
            .expect("the removal's upload key");
        let written = history.unit("P", "P writes", stream("notes"), Vec::new(), None, &[]);
        assert!(writer.store_one(space, &written, DEADLINE).await);
        let delivered = kept
            .wait_for(DEADLINE, |message| {
                match PeerClient::unit_message(message, space) {
                    Some(UnitMessage::Events { events }) if events.contains(&written) => Some(()),
                    _ => None,
                }
            })
            .await;
        assert!(
            delivered.is_some(),
            "live delivery under the removal's entry"
        );
        writer.close().await;
        kept.close().await;
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_dies_hands_its_shards_over_after_its_lease_and_loses_nothing() {
    within(async {
        let mut cluster = cluster(3).await;
        let history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let gateway = others(&cluster, owner)[0];
        let mut writer = founder_on(cluster.node(gateway), &history).await;
        let all = events(&history)[1..].to_vec();
        let half = all.len() / 2;
        let mut acked = vec![space];
        acked.extend(writer.store(space, all[..half].to_vec(), DEADLINE).await);
        assert_eq!(acked.len(), half + 1);
        let dead = cluster.node(owner).bucket.clone();
        let sent = cluster.node(owner).last_renewal_sent().unwrap();
        cluster.kill(owner).await;
        let lease_end = sent + TIMING.lease;
        // The device goes on through its gateway; the space is served
        // again once the dead owner's lease has ended.
        let rest = writer.store(space, all[half..].to_vec(), TAKEOVER).await;
        assert_eq!(rest.len(), all.len() - half, "the rest is acknowledged");
        acked.extend(rest);
        let heir = cluster.owner_of_space(space.as_bytes()).unwrap();
        assert_ne!(heir, owner);
        for id in &acked {
            assert!(
                cluster
                    .node(heir)
                    .peer
                    .peer
                    .keeps(space.as_bytes(), id.as_bytes()),
                "{id:?} was acknowledged and is kept"
            );
        }
        // The dead owner wrote nothing after its lease, and its heir wrote
        // the space's shard only after it.
        assert!(dead.writes().iter().all(|(at, _)| *at < lease_end));
        let shard = cluster.node(heir).shards.space_shard_of(space.as_bytes());
        let first = cluster
            .node(heir)
            .bucket
            .writes()
            .into_iter()
            .filter(|(_, key)| key.starts_with(&format!("{shard}/")))
            .map(|(at, _)| at)
            .min()
            .expect("the heir writes the shard");
        assert!(
            first >= lease_end,
            "the heir opens the shard after the lease"
        );
        writer.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// Stores units one at a time through `device` for as long as `for_`:
/// the true instant of each acknowledgement, and every unit sent.
async fn store_for(
    device: &mut PeerClient,
    history: &mut History,
    space: EventId,
    for_: Duration,
) -> (Vec<Instant>, Vec<Vec<u8>>) {
    let mut acks = Vec::new();
    let mut sent = Vec::new();
    let until = Instant::now() + for_;
    while Instant::now() < until {
        let written = unit(history, sent.len());
        sent.push(written.clone());
        if device
            .store_one(space, &written, Duration::from_millis(400))
            .await
        {
            acks.push(Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (acks, sent)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partitioned_owner_stops_acknowledging_before_its_lease_ends() {
    within(async {
        let cluster = cluster(4).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        // The device is on the owner itself, which its gateway is.
        let mut device = founder_on(cluster.node(owner), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            device.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut device, &history).await;
        cluster.isolate(owner);
        let (acks, sent) =
            store_for(&mut device, &mut history, space, Duration::from_secs(3)).await;
        let node = cluster.node(owner);
        let renewed = node.last_renewal_sent().unwrap();
        let own_end = node.lease_end().unwrap();
        assert!(own_end < renewed + TIMING.lease);
        assert!(
            acks.iter().all(|at| *at < own_end),
            "every acknowledgement after the cut came before the lease ended"
        );
        assert!(!node.cluster.serving(), "the owner no longer answers");
        // The others take the space up, with what was acknowledged: what
        // the owner acknowledged is acknowledged again, the rest stored.
        let gateway = others(&cluster, owner)[0];
        let mut other = PeerClient::ws(&cluster.node(gateway).peer, Purpose::SpaceTraffic).await;
        other
            .present(
                space,
                Credential::Upload,
                &history.upload_seed("V rotates, citing W's rotation"),
            )
            .await
            .expect("the current upload key at the space's new owner");
        let acked = other.store(space, sent.clone(), TAKEOVER).await;
        assert_eq!(acked.len(), sent.len(), "the new owner serves the space");
        device.close().await;
        other.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A wall clock stepped forward on a healthy owner ends its lease, which
/// the next renewal takes again: no shard is broken or opened again, and
/// the owner's device goes on storing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wall_clock_step_renews_the_lease_and_keeps_the_shards_open() {
    within(async {
        let cluster = cluster(31).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let mut device = founder_on(cluster.node(owner), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            device.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut device, &history).await;
        let node = cluster.node(owner);
        let open = node.shards.open_names();
        let opens = node.shards.opens();
        assert!(!open.is_empty());
        let granted = node.cluster.lease().grants().len();
        node.clock.step_wall(Duration::from_secs(30));
        // An attempt soon after sees the step, gives the lease up and renews
        // it; four renewals later it has surely ended, and others followed.
        let deadline = Instant::now() + DEADLINE;
        while node.cluster.lease().grants().len() < granted + 4 || !node.cluster.serving() {
            assert!(Instant::now() < deadline, "the lease is taken again");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for name in &open {
            assert!(node.shards.open_names().contains(name), "{name} stays open");
        }
        assert_eq!(node.shards.opens(), opens, "no shard opened again");
        let (acks, _) = store_for(&mut device, &mut history, space, Duration::from_secs(1)).await;
        assert!(!acks.is_empty(), "the device stores again");
        device.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A node whose lease clock runs at `rate` owns a space and is cut off
/// while it stores: no write it issues falls after its lease by true time.
async fn skewed_owner_never_writes_after_its_lease(seed: u64, rate: f64) {
    let cluster = cluster(seed).await;
    let mut history = History::credentials();
    let space = history.space();
    let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
    cluster.node(owner).clock.set_rate(rate);
    // A renewal at the new rate.
    tokio::time::sleep(TIMING.renew * 3).await;
    let mut device = founder_on(cluster.node(owner), &history).await;
    let all = events(&history)[1..].to_vec();
    assert_eq!(
        device.store(space, all.clone(), DEADLINE).await.len(),
        all.len()
    );
    // P0's first request retired the genesis's entry: the store right
    // goes on under the current state's upload key.
    present_current(&mut device, &history).await;
    let cut = Instant::now();
    cluster.isolate(owner);
    let (acks, _) = store_for(&mut device, &mut history, space, Duration::from_secs(3)).await;
    let node = cluster.node(owner);
    let sent = node.last_renewal_sent().unwrap();
    let end = sent + TIMING.lease;
    let writes: Vec<Instant> = node
        .bucket
        .writes()
        .into_iter()
        .map(|(at, _)| at)
        .filter(|at| *at >= cut)
        .collect();
    assert!(
        writes.iter().all(|at| *at < end),
        "a write after the lease by true time, at rate {rate}"
    );
    assert!(acks.iter().all(|at| *at < end));
    device.close().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_clock_runs_fast_never_stores_after_its_lease() {
    within(skewed_owner_never_writes_after_its_lease(5, 1.1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_clock_runs_slow_never_stores_after_its_lease() {
    within(skewed_owner_never_writes_after_its_lease(6, 0.9)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_voter_is_replaced_while_a_majority_remains() {
    within(async {
        let mut cluster = TestCluster::start_with(4, TIMING, 7, frasil_conformance::settings())
            .await
            .expect("four nodes form a cluster");
        let metrics = cluster.node(0).cluster.raft().metrics().borrow().clone();
        let voters: Vec<u64> = metrics.membership_config.membership().voter_ids().collect();
        assert_eq!(voters.len(), 3, "three of four nodes vote");
        let voter = cluster.index_of(voters[0]).unwrap();
        cluster.kill(voter).await;
        // Its lease ends, it is removed, and the learner votes in its place.
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        let survivor = others(&cluster, voter)[0];
        let metrics = cluster
            .node(survivor)
            .cluster
            .raft()
            .metrics()
            .borrow()
            .clone();
        let now: Vec<u64> = metrics.membership_config.membership().voter_ids().collect();
        assert_eq!(now.len(), 3);
        assert!(!now.contains(&voters[0]));
        cluster.shutdown().await;
    })
    .await;
}

/// A device on `node` holding the current upload key of the credentials
/// history's space.
async fn writer_on(node: &Node, history: &History) -> PeerClient {
    let mut device = PeerClient::ws(&node.peer, Purpose::SpaceTraffic).await;
    device
        .present(
            history.space(),
            Credential::Upload,
            &history.upload_seed("V rotates, citing W's rotation"),
        )
        .await
        .expect("the current upload key");
    device
}

/// Waits, up to `within`, for `done`.
async fn until(within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    done()
}

/// An owner cut off, replaced and joined again: it writes nothing it
/// opened before its absence, and what each owner acknowledged the next
/// one serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_cut_off_and_joined_again_writes_nothing_stale_and_loses_nothing() {
    within(async {
        let mut cluster = cluster(8).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let gateway = others(&cluster, owner)[0];
        let mut first = founder_on(cluster.node(owner), &history).await;
        let all = events(&history)[1..].to_vec();
        let mut acked: Vec<EventId> = vec![space];
        acked.extend(first.store(space, all.clone(), DEADLINE).await);
        assert_eq!(acked.len(), all.len() + 1);
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut first, &history).await;
        cluster.isolate(owner);
        let (_, sent) = store_for(&mut first, &mut history, space, Duration::from_secs(2)).await;
        // Another node takes the space up; the units go there.
        let mut other = writer_on(cluster.node(gateway), &history).await;
        let stored = other.store(space, sent.clone(), TAKEOVER).await;
        assert_eq!(stored.len(), sent.len());
        acked.extend(stored);
        assert_ne!(
            cluster
                .node(gateway)
                .cluster
                .owner_of_space(space.as_bytes()),
            Some(cluster.node(owner).id)
        );
        // The cut-off node comes back, is no member, and joins again.
        let joined = cluster.node(owner).cluster.lease().joined();
        let healed = Instant::now();
        cluster.faults.reconnect(cluster.node(owner).id);
        assert!(
            until(TAKEOVER, || {
                let node = cluster.node(owner);
                node.cluster.lease().joined() > joined && node.cluster.serving()
            })
            .await,
            "the node joins again"
        );
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        let more: Vec<Vec<u8>> = (0..3).map(|n| unit(&mut history, 900 + n)).collect();
        let stored = other.store(space, more.clone(), TAKEOVER).await;
        assert_eq!(stored.len(), more.len());
        acked.extend(stored);
        // Nothing the node opened before its absence was written since.
        let rejoined = cluster.node(owner).cluster.lease().joined();
        let shard = cluster.node(owner).shards.space_shard_of(space.as_bytes());
        let stale: Vec<String> = cluster
            .node(owner)
            .bucket
            .landed()
            .into_iter()
            .filter(|(at, key)| *at >= healed && key.starts_with(&format!("{shard}/log/")))
            .filter_map(|(_, key)| {
                let epoch: u64 = key.rsplit('/').next()?.split('-').next()?.parse().ok()?;
                (frasil_relay::cluster::lease::membership_epoch(epoch) < rejoined).then_some(key)
            })
            .collect();
        assert!(stale.is_empty(), "stale batches written: {stale:?}");
        // The next owner serves every acknowledged event.
        let now = cluster.owner_of_space(space.as_bytes()).unwrap();
        let rest = others(&cluster, now);
        let via = if rest.contains(&gateway) {
            gateway
        } else {
            rest[0]
        };
        cluster.kill(now).await;
        let mut last = writer_on(cluster.node(via), &history).await;
        let written = unit(&mut history, 999);
        assert!(last.store_one(space, &written, TAKEOVER).await);
        let heir = cluster.owner_of_space(space.as_bytes()).unwrap();
        for id in &acked {
            assert!(
                cluster
                    .node(heir)
                    .peer
                    .peer
                    .keeps(space.as_bytes(), id.as_bytes()),
                "{id:?} was acknowledged and is kept"
            );
        }
        first.close().await;
        other.close().await;
        last.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A node that left cleanly is placed again when it starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_left_is_placed_again_when_it_starts() {
    within(async {
        let mut cluster = cluster(9).await;
        let id = cluster.node(2).id;
        cluster.leave(2).await;
        assert!(
            until(TAKEOVER, || !cluster
                .node(0)
                .cluster
                .membership()
                .placed()
                .iter()
                .any(|(n, _)| *n == id))
            .await,
            "the node left"
        );
        cluster.restart(2).await.expect("the node starts again");
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        assert_eq!(cluster.node(2).id, id, "the same node, by its Raft state");
        assert!(
            cluster
                .node(0)
                .cluster
                .membership()
                .placed()
                .iter()
                .any(|(n, _)| *n == id)
        );
        assert!(cluster.node(2).cluster.serving());
        cluster.shutdown().await;
    })
    .await;
}

/// Leases hold across a leader's failover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_hold_across_a_leaders_failover() {
    within(async {
        let mut cluster = cluster(10).await;
        let leader_id = cluster
            .node(0)
            .cluster
            .raft()
            .metrics()
            .borrow()
            .current_leader
            .unwrap();
        let leader = cluster.index_of(leader_id).unwrap();
        let survivors: Vec<Arc<Cluster>> = others(&cluster, leader)
            .into_iter()
            .map(|n| cluster.node(n).cluster.clone())
            .collect();
        let watched = survivors.clone();
        let sampler = tokio::spawn(async move {
            let until = Instant::now() + Duration::from_secs(3);
            let mut lapses = 0;
            while Instant::now() < until {
                lapses += watched.iter().filter(|node| !node.serving()).count();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            lapses
        });
        cluster.kill(leader).await;
        assert_eq!(sampler.await.unwrap(), 0, "no survivor's lease lapsed");
        let next = survivors[0].raft().metrics().borrow().current_leader;
        assert!(next.is_some_and(|next| next != leader_id));
        cluster.shutdown().await;
    })
    .await;
}

/// Two nodes bootstrapping one bucket at once form one cluster at most; a
/// claim that lands later stops the cluster it replaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_bucket_names_one_cluster() {
    within(async {
        let cluster = cluster(11).await;
        let bootstrap = |n: u8| {
            let shared: Arc<dyn Bucket> = cluster.bucket.clone();
            let io = Arc::new(BucketIo::new(shared).unwrap());
            let net = Arc::new(frasil_relay::cluster::link::MemoryNet::new());
            let address = format!("racer-{n}");
            let wiring = Wiring {
                listen: Listen::Memory(net.listen(&address)),
                net,
                faults: Arc::default(),
                clock: Arc::new(frasil_relay::cluster::lease::SystemLeaseClock::default()),
                raft: Arc::new(frasil_store::MemoryStore::new()),
            };
            let config = ClusterConfig {
                key: KEY.into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: address,
                seeds: Vec::new(),
                capacity: 100,
                bootstrap: true,
                timing: TIMING,
                spaces_per_connection: frasil_relay::cluster::SPACES_PER_CONNECTION,
            };
            async move { Cluster::start(config, &format!("{n:032x}"), None, io, wiring).await }
        };
        // The bucket names the harness's cluster: neither racer forms one.
        let (a, b) = tokio::join!(bootstrap(1), bootstrap(2));
        assert!(a.is_err() && b.is_err());
        // A claim of another cluster lands late: every node stops.
        cluster
            .bucket
            .put(
                frasil_relay::cluster::CLUSTER_OBJECT,
                b"another node x".to_vec(),
            )
            .await
            .unwrap();
        let nodes: Vec<Arc<Cluster>> = (0..3).map(|n| cluster.node(n).cluster.clone()).collect();
        assert!(
            until(TIMING.lease * 2, || nodes
                .iter()
                .all(|node| node.fenced() && !node.serving()))
            .await,
            "every node of the replaced cluster stops"
        );
        cluster.shutdown().await;
    })
    .await;
}

/// A node whose start fails after it joined, here on a bucket that names
/// no cluster, leaves nothing behind: it is no member once its lease would
/// have ended, and the cluster places no shard on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_whose_start_fails_leaves_no_member_behind() {
    within(async {
        let cluster = cluster(19).await;
        let own: Arc<dyn Bucket> = Arc::new(frasil_relay::shards::bucket::MemoryBucket::new());
        let wiring = Wiring {
            listen: Listen::Memory(cluster.net.listen("stray")),
            net: cluster.net.clone(),
            faults: cluster.faults.clone(),
            clock: Arc::new(frasil_relay::cluster::lease::SystemLeaseClock::default()),
            raft: Arc::new(frasil_store::MemoryStore::new()),
        };
        let config = ClusterConfig {
            key: KEY.into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: "stray".into(),
            seeds: vec!["node-0".into()],
            capacity: 100,
            bootstrap: false,
            timing: TIMING,
            spaces_per_connection: frasil_relay::cluster::SPACES_PER_CONNECTION,
        };
        let io = Arc::new(BucketIo::new(own).unwrap());
        let started = Cluster::start(config, &format!("{:032x}", 0x57a), None, io, wiring).await;
        let error = started.expect_err("the bucket names no cluster");
        assert!(
            error.to_string().contains("the bucket names none"),
            "{error}"
        );
        let node = cluster.node(0).cluster.clone();
        assert!(
            until(TIMING.ended_after() * 4, || {
                let state = node.membership();
                state.nodes.len() == 3 && state.settled()
            })
            .await,
            "the node that failed to start is no member: {:?}",
            node.membership()
        );
        cluster.shutdown().await;
    })
    .await;
}

/// A single node that names itself the bucket's writer after the cluster
/// formed stops every node of the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_node_on_the_bucket_stops_the_cluster() {
    within(async {
        let cluster = cluster(20).await;
        let single = frasil_relay::shards::format::Active {
            epoch: 1,
            node: format!("{:032x}", 1),
            nonce: [1; 16],
        };
        cluster
            .bucket
            .put(frasil_relay::shards::fence::ACTIVE, single.encode())
            .await
            .unwrap();
        let nodes: Vec<Arc<Cluster>> = (0..3).map(|n| cluster.node(n).cluster.clone()).collect();
        assert!(
            until(TIMING.lease * 2, || nodes
                .iter()
                .all(|node| node.fenced() && !node.serving()))
            .await,
            "every node stops writing the bucket"
        );
        cluster.shutdown().await;
    })
    .await;
}

/// Two nodes bootstrapping one empty bucket at once: one cluster at most.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_bootstraps_at_once_form_one_cluster_at_most() {
    within(async {
        let bucket = Arc::new(frasil_relay::shards::bucket::MemoryBucket::new());
        let bootstrap = |n: u8, delay: Duration| {
            let shared: Arc<dyn Bucket> = bucket.clone();
            let io = Arc::new(BucketIo::new(shared).unwrap());
            let net = Arc::new(frasil_relay::cluster::link::MemoryNet::new());
            let address = format!("racer-{n}");
            let wiring = Wiring {
                listen: Listen::Memory(net.listen(&address)),
                net,
                faults: Arc::default(),
                clock: Arc::new(frasil_relay::cluster::lease::SystemLeaseClock::default()),
                raft: Arc::new(frasil_store::MemoryStore::new()),
            };
            let config = ClusterConfig {
                key: KEY.into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: address,
                seeds: Vec::new(),
                capacity: 100,
                bootstrap: true,
                timing: TIMING,
                spaces_per_connection: frasil_relay::cluster::SPACES_PER_CONNECTION,
            };
            async move {
                tokio::time::sleep(delay).await;
                Cluster::start(config, &format!("{n:032x}"), None, io, wiring).await
            }
        };
        let (a, b) = tokio::join!(
            bootstrap(1, Duration::ZERO),
            bootstrap(2, TIMING.put_timeout)
        );
        assert!(a.is_err() || b.is_err(), "one cluster at most is formed");
        for formed in [a, b].into_iter().flatten() {
            formed.stop().await;
        }
    })
    .await;
}

/// An owner cut off with its writes slowed to just under their timeout:
/// every write it issues lands before its lease ends by true time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_write_lands_within_the_lease() {
    within(async {
        let cluster = cluster(12).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let mut device = founder_on(cluster.node(owner), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            device.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut device, &history).await;
        cluster
            .node(owner)
            .bucket
            .set_delay(TIMING.put_timeout - Duration::from_millis(20));
        let cut = Instant::now();
        cluster.isolate(owner);
        let _ = store_for(&mut device, &mut history, space, Duration::from_secs(2)).await;
        let node = cluster.node(owner);
        let end = node.last_renewal_sent().unwrap() + TIMING.lease;
        let late: Vec<(Instant, String)> = node
            .bucket
            .landed()
            .into_iter()
            .filter(|(at, _)| *at >= cut && *at >= end)
            .collect();
        assert!(late.is_empty(), "writes landed after the lease: {late:?}");
        device.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A reader's subscription moves with its space: after the owner dies,
/// each unit stored reaches the reader once, and nothing earlier comes
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscription_moves_with_its_space_without_gaps_or_repeats() {
    within(async {
        let mut cluster = cluster(13).await;
        let mut history = History::credentials();
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        // The writer is on the node that owns the space once the owner is
        // gone, and the reader on the other.
        let shard = cluster.node(owner).shards.space_shard_of(space.as_bytes());
        let gone = cluster.node(owner).id;
        let placed: Vec<_> = cluster
            .node(owner)
            .cluster
            .membership()
            .placed()
            .into_iter()
            .filter(|(id, _)| *id != gone)
            .collect();
        let next = frasil_relay::cluster::placement::owner(&shard, &placed).unwrap();
        let a = cluster.index_of(next).unwrap();
        let b = others(&cluster, owner)
            .into_iter()
            .find(|&n| n != a)
            .unwrap();
        let mut writer = founder_on(cluster.node(a), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            writer.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        let mut reader = PeerClient::ws(&cluster.node(b).peer, Purpose::SpaceTraffic).await;
        reader
            .present(
                space,
                Credential::Read,
                &history.read_seed("V rotates, citing W's rotation"),
            )
            .await
            .expect("a live read credential");
        reader
            .send_sync(
                space,
                UnitMessage::Subscribe {
                    streams: Vec::new(),
                },
            )
            .await;
        // The reader catches up as a device does once subscribed: it holds
        // everything stored so far.
        let _ = reader
            .exchange(
                space,
                UnitMessage::Heads {
                    heads: Vec::new(),
                    vector: None,
                    streams: Vec::new(),
                },
            )
            .await;
        // A writer that holds a key live at any owner: a present made again
        // at the next owner is checked against the entries as they are.
        writer.close().await;
        let mut writer = writer_on(cluster.node(a), &history).await;
        // The reader's node reads the bucket slowly, so that it moves the
        // reader's subscription only after the new owner stored a unit.
        let slow = cluster.bucket_of(b);
        slow.set_delay(TIMING.put_timeout / 2);
        cluster.kill(owner).await;
        let first = unit(&mut history, 0);
        assert!(writer.store_one(space, &first, TAKEOVER).await);
        slow.set_delay(Duration::ZERO);
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        tokio::time::sleep(Duration::from_secs(1)).await;
        // The unit stored while the reader's gateway had not yet moved its
        // subscription reaches the reader as the gateway moves it.
        let mut delivered: Vec<EventId> = PeerClient::events_of(&reader.collect(space).await);
        let later: Vec<Vec<u8>> = (1..4).map(|n| unit(&mut history, n)).collect();
        for written in &later {
            assert!(writer.store_one(space, written, DEADLINE).await);
        }
        delivered.extend(PeerClient::events_of(&reader.collect(space).await));
        let mut stored = vec![first];
        stored.extend(later);
        assert_eq!(delivered, ids(&stored), "each unit once, in order");
        writer.close().await;
        reader.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A node holding more than its share of devices asks a few at a time to
/// reconnect elsewhere (transport.md, 3.10, "Reconnecting elsewhere").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_overloaded_node_moves_a_few_devices_at_a_time() {
    within(async {
        let mut cluster = TestCluster::start_with(2, TIMING, 14, frasil_conformance::settings())
            .await
            .expect("two nodes form a cluster");
        cluster.set_balancing(true);
        let mut devices = Vec::new();
        for _ in 0..12 {
            devices.push(PeerClient::ws(&cluster.node(0).peer, Purpose::SpaceTraffic).await);
        }
        let closed = |devices: &mut Vec<PeerClient>| {
            let devices = std::mem::take(devices);
            async move {
                let mut moved = 0;
                let mut kept = Vec::new();
                for mut device in devices {
                    match device.closed(Duration::from_millis(10)).await {
                        Some(Some(4017)) => moved += 1,
                        _ => kept.push(device),
                    }
                }
                (moved, kept)
            }
        };
        tokio::time::sleep(TIMING.lease.mul_f64(1.2)).await;
        let (early, kept) = closed(&mut devices).await;
        devices = kept;
        assert!(early <= 2, "{early} devices moved in the first lease");
        tokio::time::sleep(TIMING.lease * 4).await;
        let (later, kept) = closed(&mut devices).await;
        let moved = early + later;
        assert!(
            (2..=6).contains(&moved),
            "{moved} of 12 devices moved over five leases"
        );
        for device in kept {
            device.close().await;
        }
        cluster.shutdown().await;
    })
    .await;
}

/// The node that leads Raft, as node `n` knows it.
fn leader(cluster: &TestCluster, n: usize) -> Option<usize> {
    let id = cluster
        .node(n)
        .cluster
        .raft()
        .metrics()
        .borrow()
        .current_leader?;
    cluster.index_of(id)
}

/// A drained node that does not lead hands its shards over at once, with
/// no wait for its lease: the next owner serves the space while the
/// drained node's devices are still connected, and only then are they
/// closed with `reconnect`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drained_node_hands_its_shards_over_without_a_lease_wait() {
    within(async {
        let mut history = History::credentials();
        let space = history.space();
        // A cluster where the space's owner is not the leader.
        let mut seed = 15;
        let (mut cluster, owner) = loop {
            // A long lease, so that a takeover by the lease is told from a
            // slow store.
            let cluster =
                TestCluster::start_with(3, SLOW_TIMING, seed, frasil_conformance::settings())
                    .await
                    .expect("three nodes form a cluster");
            let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
            if leader(&cluster, owner) != Some(owner) {
                break (cluster, owner);
            }
            cluster.shutdown().await;
            seed += 100;
        };
        let gateway = others(&cluster, owner)[0];
        let mut on_owner = founder_on(cluster.node(owner), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            on_owner.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        let mut writer = writer_on(cluster.node(gateway), &history).await;
        let drained_id = cluster.node(owner).id;
        cluster.node(owner).cluster.hand_over().await;
        // Handed over once it returns: the drained node holds the space's
        // shard no more, and every node knows it unplaced, every member
        // having confirmed.
        let shards = &cluster.node(owner).shards;
        assert!(!shards.is_open(&shards.space_shard_of(space.as_bytes())));
        for n in others(&cluster, owner) {
            let state = cluster.node(n).cluster.membership();
            assert!(
                !state.nodes[&drained_id].placed,
                "node {n} knows it unplaced"
            );
            assert!(state.settled(), "node {n} sees every member confirm");
        }
        // The next owner holds the space already: no wait for a lease.
        let drained = Instant::now();
        let next = cluster.owner_of_space(space.as_bytes()).unwrap();
        assert_ne!(next, owner);
        let written = unit(&mut history, 0);
        assert!(writer.store_one(space, &written, DEADLINE).await);
        // Within a lease: a takeover by the lease would wait for the
        // drained node's lease to end, which it still renews.
        assert!(
            drained.elapsed() < SLOW_TIMING.lease,
            "the space was served again after {:?}",
            drained.elapsed()
        );
        assert_eq!(
            on_owner.closed(Duration::from_millis(50)).await,
            None,
            "the drained node's devices stay connected until its shards are handed over"
        );
        cluster.leave(owner).await;
        assert_eq!(on_owner.closed(DEADLINE).await, Some(Some(4017)));
        writer.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A node down while another, removed meanwhile, rejoins: no change of
/// Raft's voters waits on the node that is down, and every lease keeps
/// renewing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_down_while_another_rejoins_keeps_leases_renewing() {
    within(async {
        let mut cluster = TestCluster::start_with(5, TIMING, 16, frasil_conformance::settings())
            .await
            .expect("five nodes form a cluster");
        let lead = leader(&cluster, 0).expect("a leader");
        let rest = others(&cluster, lead);
        let (rejoining, down) = (rest[0], rest[1]);
        let rejoining_id = cluster.node(rejoining).id;
        cluster.kill(rejoining).await;
        let deadline = Instant::now() + TAKEOVER;
        while cluster
            .node(lead)
            .cluster
            .membership()
            .nodes
            .contains_key(&rejoining_id)
        {
            assert!(Instant::now() < deadline, "the dead node is removed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cluster.kill(down).await;
        cluster
            .restart(rejoining)
            .await
            .expect("the removed node rejoins while another is down");
        // For three leases, the down node's own lease ending among them,
        // every running node holds its lease.
        let watched = Instant::now();
        while watched.elapsed() < TIMING.lease * 3 {
            for n in 0..cluster.len() {
                if let Some(node) = &cluster.nodes[n] {
                    assert!(
                        node.cluster.serving(),
                        "node {n} lost its lease after {:?}",
                        watched.elapsed()
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        cluster
            .settle(TAKEOVER)
            .await
            .expect("the cluster settles without the down node");
        cluster.shutdown().await;
    })
    .await;
}

/// A node that crashes and starts again within its lease, its Raft store
/// intact, is still a member: it joins again as its new process under the
/// same ID, and Raft keeps replicating to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_restarted_within_its_lease_joins_again_and_serves() {
    within(async {
        // A long lease, so that a restart on a slow machine is still one
        // within it.
        let mut cluster =
            TestCluster::start_with(3, SLOW_TIMING, 17, frasil_conformance::settings())
                .await
                .expect("three nodes form a cluster");
        let lead = leader(&cluster, 0).expect("a leader");
        let restarted = others(&cluster, lead)[0];
        let id = cluster.node(restarted).id;
        let mut history = History::credentials();
        let space = history.space();
        let mut founder = founder_on(cluster.node(lead), &history).await;
        let all = events(&history)[1..].to_vec();
        assert_eq!(
            founder.store(space, all.clone(), DEADLINE).await.len(),
            all.len()
        );
        founder.close().await;
        let killed = Instant::now();
        cluster.kill(restarted).await;
        cluster
            .restart(restarted)
            .await
            .expect("the node starts again");
        assert_eq!(cluster.node(restarted).id, id, "the same ID");
        assert!(
            killed.elapsed() < SLOW_TIMING.ended_after(),
            "it started again within its lease"
        );
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        let mut writer = writer_on(cluster.node(restarted), &history).await;
        for n in 0..3 {
            let written = unit(&mut history, n);
            assert!(writer.store_one(space, &written, DEADLINE).await);
        }
        writer.close().await;
        for n in 0..3 {
            assert!(
                cluster.node(n).cluster.serving(),
                "node {n} holds its lease"
            );
        }
        cluster.shutdown().await;
    })
    .await;
}

/// The default timing holds a lease across a missed renewal.
#[test]
fn the_default_timing_is_sound() {
    assert_eq!(Timing::DEFAULT.check(), None);
    assert_eq!(TIMING.check(), None);
}

/// Two creates of one space through two shards that different nodes own
/// (peers.md, 3.1 Hosting a space, "One peer on several machines"): the
/// space index names it once, both genesis stores are acknowledged, and
/// every event either device then stores is at the one owner.
#[cfg(feature = "ext-libraries")]
mod racing_creates {
    use super::*;
    use frasil_libraries::{
        Issuer, LibraryAttach, LibraryId, Purpose as TicketPurpose, Ticket, TrustedIssuers,
    };
    use frasil_relay::Settings;
    use frasil_relay::libraries::LibrarySettings;

    fn issuer() -> Issuer {
        Issuer::from_seed(&[9; 32])
    }

    /// A library's shard name, as the peer makes it.
    fn shard(library: &str) -> String {
        let hex: String = library.bytes().map(|b| format!("{b:02x}")).collect();
        format!("libraries/{hex}")
    }

    fn ticket(library: &str, id: u8) -> Vec<u8> {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issuer = issuer();
        issuer.sign(&Ticket {
            library: LibraryId::new(library).unwrap(),
            id: [id; 16],
            purpose: TicketPurpose::Create,
            not_after: wall + 3600,
            issuer: *issuer.public(),
            tokens: None,
        })
    }

    /// A device on `node` whose create of the space by a ticket of
    /// `library` was accepted.
    async fn attached(node: &Node, space: EventId, library: &str, id: u8) -> PeerClient {
        let mut device = PeerClient::ws(&node.peer, Purpose::SpaceTraffic).await;
        let request = device.request();
        let message = LibraryAttach {
            request,
            space: *space.as_bytes(),
            purpose: TicketPurpose::Create,
            signed: ticket(library, id),
        }
        .encode();
        device
            .request_answer(request, &message)
            .await
            .expect("the create is accepted");
        device
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_creates_of_one_space_through_two_shards_keep_one() {
        within(async {
            let settings = Settings {
                libraries: LibrarySettings {
                    issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
                    ..LibrarySettings::default()
                },
                ..frasil_conformance::settings()
            };
            let cluster = TestCluster::start_with(3, TIMING, 7, settings)
                .await
                .expect("three nodes form a cluster");
            let mut history = History::credentials();
            let space = history.space();
            // Two libraries whose shards two different nodes own.
            let owner = |library: &str| {
                let id = cluster.node(0).cluster.owner(&shard(library)).unwrap();
                cluster.index_of(id).unwrap()
            };
            let first = "project:race-0".to_owned();
            let second = (1..64)
                .map(|n| format!("project:race-{n}"))
                .find(|name| owner(name) != owner(&first))
                .expect("two libraries owned by two nodes");
            let (x, y) = (owner(&first), owner(&second));
            let mut a = attached(cluster.node(x), space, &first, 1).await;
            let mut b = attached(cluster.node(y), space, &second, 2).await;
            // B's create reads an index that names nothing, then writes
            // slowly; A's, made meanwhile, is acknowledged and written in
            // before B's create ends.
            cluster.bucket_of(x).set_delay(Duration::from_millis(30));
            cluster.bucket_of(y).set_delay(Duration::from_millis(150));
            let genesis = history.signed(&history.order[0]);
            let slow = {
                let genesis = genesis.clone();
                tokio::spawn(async move {
                    let stored = b.store_one(space, &genesis, DEADLINE).await;
                    (b, stored)
                })
            };
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(a.store_one(space, &genesis, DEADLINE).await);
            let upload = history.upload_seed(&history.order[0]);
            let genesis_name = history.order[0].clone();
            let mut written = Vec::new();
            let write = |history: &mut History, n: usize| {
                history.unit(
                    &format!("writer {n}"),
                    &format!("writer {n} writes"),
                    stream("notes"),
                    Vec::new(),
                    None,
                    &[&genesis_name],
                )
            };
            a.present(space, Credential::Upload, &upload)
                .await
                .expect("the genesis's upload key");
            let one = write(&mut history, 0);
            assert!(a.store_one(space, &one, DEADLINE).await);
            written.push(one);
            let (mut b, stored) = slow.await.unwrap();
            for n in [x, y] {
                cluster.bucket_of(n).set_delay(Duration::ZERO);
            }
            assert!(stored, "both genesis stores are acknowledged");
            // B goes on in the one space the index names.
            b.present(space, Credential::Upload, &upload)
                .await
                .expect("the genesis's upload key, wherever the space is");
            let two = write(&mut history, 1);
            assert!(b.store_one(space, &two, DEADLINE).await);
            written.push(two);
            let shards = cluster.node(0).shards.clone();
            let placed = tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
                .await
                .unwrap()
                .unwrap()
                .expect("the index names the space");
            assert!(
                placed == shard(&first) || placed == shard(&second),
                "{placed}"
            );
            let at = cluster
                .index_of(cluster.node(0).cluster.owner(&placed).unwrap())
                .unwrap();
            // Every acknowledged event is at the owner the index names, and
            // no other node holds the space.
            for id in std::iter::once(space).chain(ids(&written)) {
                for n in 0..3 {
                    assert_eq!(
                        cluster
                            .node(n)
                            .peer
                            .peer
                            .holds(space.as_bytes(), id.as_bytes()),
                        n == at,
                        "node {n}, the index's owner {at}"
                    );
                }
            }
            a.close().await;
            b.close().await;
            cluster.shutdown().await;
        })
        .await;
    }
}

/// ext-invite-links.md: a drop placed through one node is served by every
/// node, over the WebSocket and the server binding, and gone from every
/// node once deleted.
#[cfg(feature = "ext-invite-links")]
mod drops {
    use super::*;
    use frasil_transport::ext_invite_links::{DropPut, MailboxDelete};
    use frasil_transport::frame::MessageType;
    use frasil_transport::mailbox::{Kind, MailboxGet, MailboxItems};

    /// The drop's items, by `MailboxGet` of kind 4 through `node`, and its
    /// status on that node's server binding.
    async fn served(node: &Node, address: [u8; 32]) -> (Vec<Vec<u8>>, u16) {
        let mut device = PeerClient::ws(&node.peer, Purpose::SpaceTraffic).await;
        let request = device.request();
        let message = MailboxGet {
            request,
            address,
            after: None,
            collector: None,
            kind: Kind::Drop,
        }
        .encode();
        let answer = device
            .request_answer(request, &message)
            .await
            .expect("MailboxItems")
            .expect("a message");
        assert_eq!(answer.kind, MessageType::MailboxItems);
        let items = MailboxItems::read(&answer)
            .unwrap()
            .items
            .into_iter()
            .map(|(_, item)| item)
            .collect();
        device.close().await;
        let url = format!(
            "{}{}",
            node.peer.origin,
            frasil_transport::peer::mailbox_path(4, &address)
        );
        let status = frasil_conformance::http_client()
            .get(url)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        (items, status)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_drop_placed_through_one_node_is_served_by_every_node() {
        within(async {
            let cluster = cluster(11).await;
            let history = History::credentials();
            let space = history.space();
            let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
            let placer = others(&cluster, owner)[0];
            let mut founder = founder_on(cluster.node(placer), &history).await;
            let address = [5; 32];
            let drop = vec![7; 64];
            let request = founder.request();
            let message = DropPut {
                request,
                address,
                drop: drop.clone(),
                space: *space.as_bytes(),
                lifetime: 3600,
            }
            .encode();
            founder
                .request_answer(request, &message)
                .await
                .expect("the drop is placed");
            for n in 0..3 {
                assert_eq!(
                    served(cluster.node(n), address).await,
                    (vec![drop.clone()], 200),
                    "node {n} serves the drop"
                );
            }
            let request = founder.request();
            let message = MailboxDelete {
                request,
                address,
                space: *space.as_bytes(),
            }
            .encode();
            founder
                .request_answer(request, &message)
                .await
                .expect("the drop is deleted");
            for n in 0..3 {
                let (items, _) = served(cluster.node(n), address).await;
                assert!(items.is_empty(), "node {n} serves no drop");
            }
            founder.close().await;
            cluster.shutdown().await;
        })
        .await;
    }

    /// ext-invite-links.md, a drop's checks, step 4: an address another
    /// space's drop holds, whichever node placed it, is refused
    /// `conflict`, and that drop stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_address_another_space_holds_is_refused_conflict() {
        within(async {
            let cluster = cluster(13).await;
            let history = History::credentials();
            let space = history.space();
            let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
            let placer = others(&cluster, owner)[0];
            let mut founder = founder_on(cluster.node(placer), &history).await;
            // Another space's drop at the address, as the node that keeps
            // that space wrote its locator: `{1: space}` under `a` and the
            // address.
            let address = [6; 32];
            let mut locator = vec![b'a'];
            locator.extend_from_slice(&address);
            let mut record = vec![0xa1, 0x01, 0x58, 0x20];
            record.extend_from_slice(&[9; 32]);
            let shards = cluster.node(owner).shards.clone();
            let written = tokio::task::spawn_blocking(move || {
                use frasil_store::Store;
                let commit = frasil_store::Commit::new(vec![(locator, record)], Vec::new());
                futures_util::FutureExt::now_or_never(shards.commit(&commit))
                    .expect("ready")
                    .expect("written")
            })
            .await
            .unwrap();
            assert!(written);
            let request = founder.request();
            let message = DropPut {
                request,
                address,
                drop: vec![7; 64],
                space: *space.as_bytes(),
                lifetime: 3600,
            }
            .encode();
            assert_eq!(
                founder
                    .request_answer(request, &message)
                    .await
                    .err()
                    .as_deref(),
                Some("conflict")
            );
            // The other space's locator stands.
            let shards = cluster.node(placer).shards.clone();
            let mut at = vec![b'a'];
            at.extend_from_slice(&address);
            let kept = tokio::task::spawn_blocking(move || {
                use frasil_store::Store;
                futures_util::FutureExt::now_or_never(shards.get(&at))
                    .expect("ready")
                    .expect("read")
            })
            .await
            .unwrap();
            assert_eq!(kept.map(|record| record[4..].to_vec()), Some(vec![9; 32]));
            founder.close().await;
            cluster.shutdown().await;
        })
        .await;
    }
}

/// Answers larger than one frame of the links between nodes: a reader
/// through a node that does not own its space catches up on more events,
/// and fetches a larger object, than one frame holds, while another
/// device's store crosses the same link; and a scan of a hashed shard
/// another node keeps reads more records than that.
mod large_answers {
    use super::*;
    use frasil_conformance::history::object;
    use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
    use std::collections::BTreeSet;

    /// The links between the nodes closed because a frame did not read,
    /// on every node.
    fn links_unread(cluster: &TestCluster) -> u64 {
        cluster
            .nodes
            .iter()
            .flatten()
            .map(|node| node.cluster.links().unread())
            .sum()
    }

    /// Renewals, and so Raft's heartbeats, far enough apart that one may
    /// wait behind a MiB being sealed and opened in a debug build; and
    /// writes of a MiB land within their timeout on a slow machine.
    const LARGE_TIMING: Timing = Timing {
        lease: Duration::from_secs(10),
        renew: Duration::from_secs(1),
        drift: 0.2,
        put_timeout: Duration::from_secs(1),
    };

    /// Three nodes on [`LARGE_TIMING`].
    async fn cluster(seed: u64) -> TestCluster {
        TestCluster::start_with(3, LARGE_TIMING, seed, frasil_conformance::settings())
            .await
            .expect("three nodes form a cluster")
    }

    /// A unit of V's of half a MiB, numbered.
    fn large_unit(history: &mut History, n: usize) -> Vec<u8> {
        history.unit_of(
            "V",
            &format!("V writes {n} at length"),
            stream("notes"),
            Vec::new(),
            None,
            &[],
            &vec![n as u8; 512 << 10],
        )
    }

    /// The founder, on a node that does not own the space, and a reader
    /// there with a read credential; and a device on each other node, so
    /// that no node holds enough more devices than the others to move one.
    async fn writer_and_reader(
        cluster: &TestCluster,
        history: &History,
    ) -> (PeerClient, PeerClient, Vec<PeerClient>) {
        let space = history.space();
        let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
        let gateway = others(cluster, owner)[0];
        let mut idle = Vec::new();
        for n in others(cluster, gateway) {
            idle.push(PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await);
        }
        let mut writer = founder_on(cluster.node(gateway), history).await;
        let stored = events(history)[1..].to_vec();
        let acked = writer.store(space, stored.clone(), DEADLINE).await;
        assert_eq!(acked.len(), stored.len(), "every event is acknowledged");
        // P0's first request retired the genesis's entry: the store right
        // goes on under the current state's upload key.
        present_current(&mut writer, history).await;
        let mut reader = PeerClient::ws(&cluster.node(gateway).peer, Purpose::SpaceTraffic).await;
        reader
            .present(
                space,
                Credential::Read,
                &history.read_seed("V rotates, citing W's rotation"),
            )
            .await
            .expect("a read credential at the owner, through the gateway");
        (writer, reader, idle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reader_through_another_node_catches_up_on_more_events_than_a_frame_holds() {
        within(async {
            let cluster = cluster(17).await;
            let mut history = History::credentials();
            let space = history.space();
            let (mut writer, mut reader, idle) = writer_and_reader(&cluster, &history).await;
            let mut written = Vec::new();
            for n in 0..20 {
                let unit = large_unit(&mut history, n);
                let answer = writer.store_answer(space, &unit, DEADLINE).await;
                assert_eq!(answer, Some(Ok(())), "unit {n} is stored");
                written.push(unit);
            }
            assert!(written.iter().map(Vec::len).sum::<usize>() > 9 << 20);
            let unread = links_unread(&cluster);
            reader
                .send_sync(
                    space,
                    UnitMessage::Heads {
                        heads: Vec::new(),
                        vector: None,
                        streams: Vec::new(),
                    },
                )
                .await;
            // Another device's store crosses the same link meanwhile.
            let after = unit(&mut history, 0);
            let catch_up = async {
                let mut missing: BTreeSet<EventId> = ids(&written).into_iter().collect();
                while !missing.is_empty() {
                    let Some(events) = reader
                        .wait_for(DEADLINE, |message| {
                            match PeerClient::unit_message(message, space) {
                                Some(UnitMessage::Events { events }) => Some(events),
                                _ => None,
                            }
                        })
                        .await
                    else {
                        break;
                    };
                    for id in ids(&events) {
                        missing.remove(&id);
                    }
                }
                missing.len()
            };
            let (missing, stored) =
                tokio::join!(catch_up, writer.store_one(space, &after, DEADLINE));
            assert_eq!(missing, 0, "every large unit reaches the reader");
            assert!(stored, "a store through the same link is acknowledged");
            // A link a starved machine leaves silent for two renewals is
            // closed and made again; none closes on a frame it cannot read.
            assert_eq!(
                links_unread(&cluster),
                unread,
                "no link between the nodes closed on a frame"
            );
            writer.close().await;
            reader.close().await;
            for device in idle {
                device.close().await;
            }
            cluster.shutdown().await;
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reader_through_another_node_fetches_an_object_larger_than_a_frame() {
        within(async {
            let cluster = cluster(19).await;
            let mut history = History::credentials();
            let space = history.space();
            let (mut writer, mut reader, idle) = writer_and_reader(&cluster, &history).await;
            // Nine sealed chunks: more than one frame of the links holds.
            const CHUNKS: usize = 9;
            let (stored, locator) = object(
                frasil_conformance::history::object_id("large"),
                (CHUNKS * CHUNK_BYTES) as u64,
                space,
            );
            let length = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
            let header = stored[4..4 + length].to_vec();
            let chunks: Vec<Vec<u8>> = stored[4 + length..]
                .chunks(SEALED_CHUNK_BYTES)
                .map(<[u8]>::to_vec)
                .collect();
            assert_eq!(chunks.len(), CHUNKS);
            for (index, chunk) in chunks.iter().enumerate() {
                writer
                    .send_sync(
                        space,
                        UnitMessage::ObjectChunks {
                            locator,
                            header: (index == 0).then(|| header.clone()),
                            index: index as u64,
                            chunk: chunk.clone(),
                        },
                    )
                    .await;
                let held = writer
                    .wait_for(DEADLINE, |message| {
                        match PeerClient::unit_message(message, space) {
                            Some(UnitMessage::ObjectHave { counts, .. }) => {
                                counts.map(|counts| counts[0])
                            }
                            _ => None,
                        }
                    })
                    .await;
                assert_eq!(held, Some(index as u64 + 1), "chunk {index} is stored");
            }
            let unread = links_unread(&cluster);
            reader
                .send_sync(
                    space,
                    UnitMessage::ObjectWant {
                        locator,
                        first: 0,
                        count: CHUNKS as u64,
                    },
                )
                .await;
            let after = unit(&mut history, 0);
            let fetch = async {
                let mut received = Vec::new();
                while received.len() < CHUNKS {
                    let Some(chunk) = reader
                        .wait_for(DEADLINE, |message| {
                            match PeerClient::unit_message(message, space) {
                                Some(UnitMessage::ObjectChunks { index, chunk, .. }) => {
                                    Some((index, chunk))
                                }
                                _ => None,
                            }
                        })
                        .await
                    else {
                        break;
                    };
                    received.push(chunk);
                }
                received
            };
            let (received, stored) = tokio::join!(fetch, writer.store_one(space, &after, DEADLINE));
            assert_eq!(received.len(), CHUNKS, "every chunk reaches the reader");
            for (index, chunk) in received {
                assert_eq!(chunk, chunks[index as usize], "chunk {index} as stored");
            }
            assert!(stored, "a store through the same link is acknowledged");
            // A link a starved machine leaves silent for two renewals is
            // closed and made again; none closes on a frame it cannot read.
            assert_eq!(
                links_unread(&cluster),
                unread,
                "no link between the nodes closed on a frame"
            );
            writer.close().await;
            reader.close().await;
            for device in idle {
                device.close().await;
            }
            cluster.shutdown().await;
        })
        .await;
    }

    /// A mailbox record, as the peer keeps one: `{1: sight, 2: item}`, of
    /// an item of 64 KiB or more.
    fn mailbox_record(item: &[u8]) -> Vec<u8> {
        assert!(item.len() > usize::from(u16::MAX));
        let mut record = vec![0xa2, 0x01, 0x00, 0x02, 0x5a];
        record.extend_from_slice(&(item.len() as u32).to_be_bytes());
        record.extend_from_slice(item);
        record
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_scan_of_a_shard_another_node_keeps_reads_more_than_a_frame() {
        use frasil_store::Store;
        within(async {
            let cluster = cluster(23).await;
            let address = [8; 32];
            let shard = frasil_relay::shards::Shards::address_shard("mailboxes", &address);
            let keeper = cluster
                .index_of(cluster.node(0).cluster.owner(&shard).unwrap())
                .unwrap();
            let asker = others(&cluster, keeper)[0];
            // Forty items of a quarter MiB each in one mailbox, written one
            // batch at a time from the node that does not keep it.
            let mut prefix = vec![b'm'];
            prefix.extend_from_slice(&address);
            for n in 0..40u8 {
                let mut at = prefix.clone();
                at.extend_from_slice(&[n; 16]);
                let record = mailbox_record(&vec![n; 256 << 10]);
                let shards = cluster.node(asker).shards.clone();
                let written = tokio::task::spawn_blocking(move || {
                    let commit = frasil_store::Commit::new(vec![(at, record)], Vec::new());
                    futures_util::FutureExt::now_or_never(shards.commit(&commit))
                        .expect("ready")
                        .expect("written")
                })
                .await
                .unwrap();
                assert!(written);
            }
            let unread = links_unread(&cluster);
            let shards = cluster.node(asker).shards.clone();
            let found = tokio::task::spawn_blocking(move || {
                futures_util::FutureExt::now_or_never(shards.scan(&prefix)).expect("ready")
            })
            .await
            .unwrap()
            .expect("the scan reads at the keeper");
            assert_eq!(found.len(), 40);
            assert!(found.iter().map(|(_, r)| r.len()).sum::<usize>() > 9 << 20);
            // A link a starved machine leaves silent for two renewals is
            // closed and made again; none closes on a frame it cannot read.
            assert_eq!(
                links_unread(&cluster),
                unread,
                "no link between the nodes closed on a frame"
            );
            cluster.shutdown().await;
        })
        .await;
    }
}
