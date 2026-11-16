//! The cluster under a seeded, randomized schedule of faults (peers.md, 3.1
//! Hosting a space, "One peer on several machines"): crashes and restarts,
//! partitions and heals, a node's bucket slowed or losing its answers,
//! clock rates within the drift margin, and planned drains, while a device
//! stores through a random node. Faults combine: a node down while another
//! is cut off, rejoins, drains or crashes, at most two of the five nodes
//! down or cut off at once, so that a majority still reaches itself. After
//! each step:
//!
//! - every shard write a node issued was issued before its lease, less a
//!   write's timeout, ended by both its clocks, under a renewal it was
//!   granted, and landed within a lease of that renewal's send, by true
//!   time (crate `frasil-relay`, module `cluster::lease`);
//! - no write of a node, and no batch the bucket answered as landed, which
//!   its shard may have acknowledged, landed after another node landed a
//!   manifest of that shard under a later epoch, which the later owner
//!   wrote only once it read what the earlier one acknowledged;
//!
//! and once everything heals, every acknowledged event is kept and the
//! space serves stores again.
//!
//! With ext-libraries the schedule also moves the space between libraries,
//! each its own shard (ext-libraries.md, 3.3 Attaching, Move), and hands
//! its library over to another peer and back (peers.md, 3.1 Hosting a
//! space, "Hand-over"). While it is handed over, the cluster answers
//! `moved` to a valid proof under a key the space held and `no_library` to
//! any other. Once everything heals, no move is under way, the owner of the
//! one shard the index names keeps every acknowledged event, no other node
//! holds the space, and the libraries' usage counts it once.
//!
//! A seed fixes the sequence of actions, not their outcomes: those depend
//! on when, by the wall clock, leases end, elections end and writes land,
//! so a run repeated under the same seed may take another course.
//!
//! `FRASIL_FAULT_SEEDS` sets how many seeds run (3 by default),
//! `FRASIL_FAULT_FIRST` the first of them (1 by default), and
//! `FRASIL_FAULT_STEPS` how many steps each (8 by default).

mod common;

#[cfg(feature = "ext-libraries")]
use common::DEADLINE;
use common::within;
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{History, stream};
use frasil_events::EventId;
use frasil_relay::testing::cluster::{TIMING, TestCluster};
use frasil_transport::peer::Purpose;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// The nodes of the cluster.
const NODES: usize = 5;

/// The most nodes down or cut off at once: a majority of five remains.
const UNAVAILABLE: usize = 2;

/// The time between a shard's check of its fence and its bucket's record
/// of the write, on a loaded machine.
const SCHEDULING: Duration = Duration::from_millis(25);

/// A seed's random draws: xorshift64*.
struct Draws(u64);

impl Draws {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// What a key of a shard's records is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    Log,
    Manifest,
    Snapshot,
}

/// Whether a key is of a shard's records: its log, manifests or
/// snapshots; and the shard, the record and the epoch it was written
/// under.
fn shard_write(key: &str) -> Option<(String, Record, u64)> {
    for (marker, record) in [
        ("/log/", Record::Log),
        ("/manifest-", Record::Manifest),
        ("/snapshot-", Record::Snapshot),
    ] {
        if let Some(at) = key.find(marker) {
            let rest = &key[at + marker.len()..];
            let epoch = rest.split('-').next()?.parse().ok()?;
            return Some((key[..at].to_owned(), record, epoch));
        }
    }
    None
}

/// A shard write that landed.
struct Landed {
    at: Instant,
    node: usize,
    record: Record,
    epoch: u64,
    key: String,
    answered: bool,
}

/// The invariants of writes (module documentation).
fn check_writes(cluster: &TestCluster, seed: u64) {
    let mut shards: BTreeMap<String, Vec<Landed>> = BTreeMap::new();
    for n in 0..cluster.len() {
        let grants = cluster.grants(n);
        let bucket = cluster.bucket_of(n);
        for (at, key) in bucket.writes() {
            if shard_write(&key).is_none() {
                continue;
            }
            let under = grants
                .iter()
                .rev()
                .find(|(sent, by)| *sent <= at && at < *by + SCHEDULING);
            assert!(
                under.is_some(),
                "seed {seed}: node {n} issued {key} with no lease to write under: {:?} after \
                 its last grant before, of {} grants",
                grants
                    .iter()
                    .rev()
                    .find(|(sent, _)| *sent <= at)
                    .map(|(sent, _)| at - *sent),
                grants.len()
            );
        }
        let answered: BTreeSet<String> = bucket.answered().into_iter().collect();
        let mut issued: BTreeMap<String, Vec<Instant>> = BTreeMap::new();
        for (at, key) in bucket.writes() {
            issued.entry(key).or_default().push(at);
        }
        for (at, key) in bucket.landed() {
            let Some((shard, record, epoch)) = shard_write(&key) else {
                continue;
            };
            // The renewal it was issued under: the last one sent before.
            let sent = issued
                .get(&key)
                .and_then(|times| times.iter().rev().find(|issue| **issue <= at))
                .and_then(|issue| {
                    grants
                        .iter()
                        .rev()
                        .map(|(sent, _)| *sent)
                        .find(|sent| sent <= issue)
                });
            assert!(
                sent.is_some_and(|sent| at < sent + TIMING.lease),
                "seed {seed}: node {n}'s {key} landed {:?} after the renewal it was issued \
                 under was sent, past a lease",
                sent.map(|sent| at - sent)
            );
            shards.entry(shard).or_default().push(Landed {
                at,
                node: n,
                record,
                epoch,
                answered: answered.contains(&key),
                key,
            });
        }
    }
    for (shard, mut landed) in shards {
        landed.sort_by_key(|write| write.at);
        // Each manifest, in the order they landed.
        let manifests: Vec<(Instant, usize, u64)> = landed
            .iter()
            .filter(|write| write.record == Record::Manifest)
            .map(|write| (write.at, write.node, write.epoch))
            .collect();
        for write in &landed {
            let Some((_, by, epoch)) = manifests.iter().find(|(at, node, epoch)| {
                *at < write.at && *node != write.node && *epoch > write.epoch
            }) else {
                continue;
            };
            let what = if write.record == Record::Log && write.answered {
                "acknowledged batch"
            } else {
                "write"
            };
            panic!(
                "seed {seed}: node {}'s {what} {} of {shard} landed after node {by} took the \
                 shard over under epoch {epoch}",
                write.node, write.key
            );
        }
    }
}

/// A device on a running node, holding the space's current upload key.
async fn writer(cluster: &TestCluster, n: usize, history: &History) -> PeerClient {
    let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
    let _ = device
        .present(
            history.space(),
            Credential::Upload,
            &history.upload_seed("V rotates, citing W's rotation"),
        )
        .await;
    device
}

/// Each running node's view, for a failure's report.
fn report(cluster: &TestCluster, seed: u64) {
    for n in 0..cluster.len() {
        if let Some(node) = &cluster.nodes[n] {
            let metrics = node.cluster.raft().metrics().borrow().clone();
            eprintln!(
                "seed {seed}: node {n} {:016x}: serving {}, Raft term {} leader {:?} \
                 voters {:?}, {:?}",
                node.id,
                node.cluster.serving(),
                metrics.current_term,
                metrics.current_leader,
                metrics
                    .membership_config
                    .membership()
                    .voter_ids()
                    .collect::<Vec<_>>(),
                node.cluster.membership()
            );
        }
    }
}

fn running(cluster: &TestCluster) -> Vec<usize> {
    (0..cluster.len())
        .filter(|&n| cluster.nodes[n].is_some())
        .collect()
}

async fn one_seed(seed: u64, steps: usize) {
    #[cfg(not(feature = "ext-libraries"))]
    let mut cluster =
        TestCluster::start_with(NODES, TIMING, 1000 + seed, frasil_conformance::settings())
            .await
            .expect("five nodes form a cluster");
    #[cfg(feature = "ext-libraries")]
    let mut cluster = TestCluster::start_with(NODES, TIMING, 1000 + seed, libraries::settings())
        .await
        .expect("five nodes form a cluster");
    #[cfg(feature = "ext-libraries")]
    let mut tickets = libraries::Tickets::new(seed);
    let mut draws = Draws(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut history = History::credentials();
    let space = history.space();
    // The space and its whole history, through the first node, each sent
    // again until it is acknowledged, as a device does: on a loaded
    // machine a lease may lapse even before any fault.
    let mut founder = PeerClient::ws(&cluster.node(0).peer, Purpose::SpaceTraffic).await;
    let genesis = history.order[0].clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut created = Vec::new();
    while created.is_empty() && Instant::now() < deadline {
        created = founder
            .store(space, history.events(&[&genesis]), Duration::from_secs(5))
            .await;
    }
    assert_eq!(created, vec![space], "seed {seed}: the space is created");
    founder
        .present(space, Credential::Upload, &history.upload_seed(&genesis))
        .await
        .expect("the genesis's upload key");
    let all: Vec<Vec<u8>> = history
        .order
        .iter()
        .filter(|n| *n != "W forks")
        .skip(1)
        .map(|n| history.signed(n))
        .collect();
    let mut acked: BTreeSet<EventId> = BTreeSet::new();
    acked.insert(space);
    // Stored whole once the upload key the writers present is live.
    let current = history.upload_seed("V rotates, citing W's rotation");
    loop {
        acked.extend(
            founder
                .store(space, all.clone(), Duration::from_secs(5))
                .await,
        );
        if founder
            .present(space, Credential::Upload, &current)
            .await
            .is_ok()
        {
            break;
        }
        // P0's first request, once stored, retires the genesis's entry and
        // keeps the removal's: the store right goes on under that one
        // (peers.md, 3.6 Retirement and the cap, "Connections").
        let _ = founder
            .present(
                space,
                Credential::Upload,
                &history.upload_seed("P removes W"),
            )
            .await;
        assert!(
            Instant::now() < deadline,
            "seed {seed}: the space's history is stored"
        );
    }
    founder.close().await;
    let mut waiting: Vec<Vec<u8>> = Vec::new();
    // The running nodes cut off from the others, until a heal.
    let mut isolated: BTreeSet<usize> = BTreeSet::new();
    for step in 0..steps {
        let live = running(&cluster);
        isolated.retain(|n| live.contains(n));
        let down = cluster.len() - live.len();
        let unavailable = down + isolated.len();
        let reachable: Vec<usize> = live
            .iter()
            .copied()
            .filter(|n| !isolated.contains(n))
            .collect();
        let action = draws.below(10);
        if std::env::var("FRASIL_FAULT_TRACE").is_ok() {
            eprintln!(
                "seed {seed} step {step}: action {action}, running {live:?}, cut off \
                 {isolated:?}"
            );
        }
        match action {
            // A crash: of any running node, or of one cut off already.
            0 => {
                let candidates: Vec<usize> = if unavailable < UNAVAILABLE {
                    live.clone()
                } else {
                    isolated.iter().copied().collect()
                };
                if !candidates.is_empty() {
                    let n = candidates[draws.below(candidates.len())];
                    cluster.kill(n).await;
                }
            }
            // A node that is down starts again, and rejoins.
            1 if down > 0 => {
                let stopped: Vec<usize> = (0..cluster.len())
                    .filter(|&n| cluster.nodes[n].is_none())
                    .collect();
                let n = stopped[draws.below(stopped.len())];
                let _ = cluster.restart(n).await;
            }
            2 if unavailable < UNAVAILABLE => {
                let n = reachable[draws.below(reachable.len())];
                cluster.isolate(n);
                isolated.insert(n);
            }
            3 => {
                cluster.faults.heal();
                isolated.clear();
            }
            4 => {
                let n = draws.below(cluster.len());
                let bucket = cluster.bucket_of(n);
                // Up to half again a write's timeout: a write that times
                // out still lands, late.
                let delay = TIMING.put_timeout.mul_f64(draws.below(150) as f64 / 100.0);
                bucket.set_delay(delay);
                bucket.set_lose_answers(draws.below(4) == 0);
            }
            5 => {
                let n = draws.below(cluster.len());
                let rate = 0.9 + draws.below(21) as f64 / 100.0;
                cluster.clock_of(n).set_rate(rate);
            }
            // A planned drain of a node that reaches the others.
            6 if unavailable < UNAVAILABLE => {
                let n = reachable[draws.below(reachable.len())];
                cluster.leave(n).await;
            }
            // A move of the space into another library, through a node
            // that reaches the others.
            #[cfg(feature = "ext-libraries")]
            7 if !reachable.is_empty() => {
                let n = reachable[draws.below(reachable.len())];
                let to = libraries::LIBRARIES[draws.below(libraries::LIBRARIES.len())];
                libraries::move_to(&cluster, n, &history, to, &mut tickets).await;
            }
            // The space's library handed over to another peer, and back.
            #[cfg(feature = "ext-libraries")]
            8 if !reachable.is_empty() => {
                libraries::hand_over_and_back(&cluster, &reachable, &history, seed).await;
            }
            _ => {}
        }
        // A device stores through a random running node: what waits, then
        // one unit more.
        let live = running(&cluster);
        if let Some(&n) = live.get(draws.below(live.len().max(1))) {
            waiting.push(history.unit(
                "V",
                &format!("V writes {seed}-{step}"),
                stream("notes"),
                Vec::new(),
                None,
                &[],
            ));
            let mut device = writer(&cluster, n, &history).await;
            let got = device
                .store(space, waiting.clone(), Duration::from_secs(3))
                .await;
            acked.extend(got);
            device.close().await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        check_writes(&cluster, seed);
    }
    // Everything heals: every node up, every link and bucket as it was.
    cluster.faults.heal();
    for n in 0..cluster.len() {
        let bucket = cluster.bucket_of(n);
        bucket.set_delay(Duration::ZERO);
        bucket.set_lose_answers(false);
        cluster.clock_of(n).set_rate(1.0);
        if cluster.nodes[n].is_none()
            && let Err(error) = cluster.restart(n).await
        {
            report(&cluster, seed);
            panic!("seed {seed}: node {n} starts again: {error}");
        }
    }
    if let Err(error) = cluster.settle(Duration::from_secs(60)).await {
        report(&cluster, seed);
        panic!("seed {seed}: the cluster settles after the faults: {error}");
    }
    // The space serves stores again, and keeps every acknowledged event.
    waiting.push(history.unit(
        "V",
        &format!("V writes {seed}-last"),
        stream("notes"),
        Vec::new(),
        None,
        &[],
    ));
    let mut device = writer(&cluster, 0, &history).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut done: BTreeSet<EventId> = BTreeSet::new();
    while done.len() < waiting.len() && Instant::now() < deadline {
        // As the nodes' maintenance does, which carries on a move a fault
        // left under way, and the space stores again.
        #[cfg(feature = "ext-libraries")]
        for n in running(&cluster) {
            cluster.node(n).peer.peer.sweep().await;
        }
        done.extend(
            device
                .store(space, waiting.clone(), Duration::from_secs(5))
                .await,
        );
    }
    assert_eq!(
        done.len(),
        waiting.len(),
        "seed {seed}: the space serves stores again"
    );
    acked.extend(done);
    device.close().await;
    #[cfg(feature = "ext-libraries")]
    let owner = libraries::settled(&cluster, &history, &acked, seed).await;
    #[cfg(not(feature = "ext-libraries"))]
    let owner = cluster.owner_of_space(space.as_bytes()).unwrap();
    for id in &acked {
        assert!(
            cluster
                .node(owner)
                .peer
                .peer
                .keeps(space.as_bytes(), id.as_bytes()),
            "seed {seed}: {id:?} was acknowledged and is lost"
        );
    }
    check_writes(&cluster, seed);
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cluster_keeps_its_invariants_under_random_faults() {
    let seeds = setting("FRASIL_FAULT_SEEDS", 3) as u64;
    let steps = setting("FRASIL_FAULT_STEPS", 8);
    let first = setting("FRASIL_FAULT_FIRST", 1) as u64;
    for seed in first..first + seeds {
        tokio::time::timeout(Duration::from_secs(300), one_seed(seed, steps))
            .await
            .unwrap_or_else(|_| panic!("seed {seed} ends in time"));
    }
    let _ = within(async {}).await;
}

/// The schedule's library steps (module documentation).
#[cfg(feature = "ext-libraries")]
mod libraries {
    use super::*;
    use frasil_libraries::{
        Issuer, LibraryAttach, LibraryId, Purpose as TicketPurpose, Ticket, TrustedIssuers,
    };
    use frasil_relay::Settings;
    use frasil_relay::libraries::{LibrarySettings, OperatorToken};
    use frasil_relay::shards::Shards;
    use frasil_relay::shards::bucket::{Bucket, BucketIo, MemoryBucket};
    use frasil_relay::shards::fence::SingleNode;
    use frasil_relay::testing::{OPEN_LIBRARY, Options, TestPeer, spawn_with};
    use std::sync::Arc;

    /// The libraries the space moves between, besides the open one it is
    /// created in.
    pub const LIBRARIES: [&str; 3] = ["project:faults-a", "project:faults-b", "project:faults-c"];

    const TOKEN: &str = "operator-token-of-the-fault-suite";

    fn issuer() -> Issuer {
        Issuer::from_seed(&[17; 32])
    }

    /// Tickets of one issuer, an operator token, and the open library that
    /// takes the space's create.
    pub fn settings() -> Settings {
        Settings {
            libraries: LibrarySettings {
                issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
                operator_token: Some(OperatorToken::new(TOKEN).unwrap()),
                open_library: LibraryId::new(OPEN_LIBRARY).ok(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        }
    }

    /// Ticket IDs, each used once.
    pub struct Tickets {
        seed: u64,
        next: u64,
    }

    impl Tickets {
        pub fn new(seed: u64) -> Self {
            Self { seed, next: 0 }
        }

        pub fn move_ticket(&mut self, library: &str) -> Vec<u8> {
            self.next += 1;
            let mut id = [0; 16];
            id[..8].copy_from_slice(&self.seed.to_be_bytes());
            id[8..].copy_from_slice(&self.next.to_be_bytes());
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let issuer = issuer();
            issuer.sign(&Ticket {
                library: LibraryId::new(library).unwrap(),
                id,
                purpose: TicketPurpose::Move,
                not_after: wall + 3600,
                issuer: *issuer.public(),
                tokens: None,
            })
        }
    }

    pub fn shard(library: &str) -> String {
        let hex: String = library.bytes().map(|b| format!("{b:02x}")).collect();
        format!("libraries/{hex}")
    }

    /// A move of the space into `to` through node `n`: its outcome may be
    /// anything under the faults.
    pub async fn move_to(
        cluster: &TestCluster,
        n: usize,
        history: &History,
        to: &str,
        tickets: &mut Tickets,
    ) {
        let mut device = writer(cluster, n, history).await;
        let request = device.request();
        let message = LibraryAttach {
            request,
            space: *history.space().as_bytes(),
            purpose: TicketPurpose::Move,
            signed: tickets.move_ticket(to),
        }
        .encode();
        let _ = device.request_answer(request, &message).await;
        device.close().await;
    }

    /// An operator route at `origin`: its status and body; 503 if no answer.
    async fn operator(
        origin: &str,
        library: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> (u16, Vec<u8>) {
        let client = frasil_conformance::http_client();
        let url = format!("{origin}/frasil/p1/libraries/{library}/{path}");
        let request = match body {
            Some(body) => client.post(url).body(body),
            None => client.get(url),
        };
        let sent = request
            .header("Authorization", format!("Bearer {TOKEN}"))
            .timeout(Duration::from_secs(20))
            .send()
            .await;
        match sent {
            Ok(response) => {
                let status = response.status().as_u16();
                (
                    status,
                    response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default(),
                )
            }
            Err(_) => (503, Vec::new()),
        }
    }

    /// A route tried through the nodes in turn until it answers other than
    /// 503, for 20 seconds at most.
    async fn through(
        cluster: &TestCluster,
        nodes: &[usize],
        library: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> (u16, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut turn = 0;
        loop {
            let live = running(cluster);
            let candidates: Vec<usize> =
                nodes.iter().copied().filter(|n| live.contains(n)).collect();
            if candidates.is_empty() {
                return (503, Vec::new());
            }
            let n = candidates[turn % candidates.len()];
            turn += 1;
            let answer = operator(&cluster.node(n).peer.origin, library, path, body.clone()).await;
            if answer.0 != 503 || Instant::now() >= deadline {
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// The library whose shard the index names for the space, if it names
    /// one of [`LIBRARIES`].
    async fn current(cluster: &TestCluster, space: EventId) -> Option<&'static str> {
        let n = *running(cluster).first()?;
        let shards = cluster.node(n).shards.clone();
        let placed = tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
            .await
            .ok()?
            .ok()??;
        LIBRARIES
            .iter()
            .copied()
            .find(|library| shard(library) == placed)
    }

    /// One node over a bucket of its own: the other peer.
    async fn other_peer(seed: u64) -> TestPeer {
        let bucket: Arc<dyn Bucket> = Arc::new(MemoryBucket::new());
        let io = Arc::new(BucketIo::new(bucket).unwrap());
        let name = format!("faults-other-{seed}");
        let fence = SingleNode::start_with(&io, &name, Duration::from_millis(50)).unwrap();
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("frasil-fault-handover")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let shards = Shards::bucket(io, dir, Arc::new(fence)).unwrap();
        spawn_with(Options {
            settings: settings(),
            shards: Some(shards),
            ..frasil_conformance::options()
        })
        .await
        .expect("a peer on loopback")
    }

    /// What a present of the space through node `n` is answered: `None`
    /// for granted.
    async fn presented(
        cluster: &TestCluster,
        n: usize,
        space: EventId,
        key: &[u8; 32],
    ) -> Option<String> {
        let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
        let answer = device.present(space, Credential::Upload, key).await.err();
        device.close().await;
        answer
    }

    /// What a present of the space through node `n` is answered when it
    /// names the upload key of `seed` with a proof made over another
    /// connection's binding, which does not verify on this one.
    async fn forged(
        cluster: &TestCluster,
        n: usize,
        space: EventId,
        seed: &[u8; 32],
    ) -> Option<String> {
        let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
        let request = device.request();
        let public = frasil_crypto::primitives::ed25519_public(seed);
        let elsewhere = frasil_peers::proof::presented(
            &[9; 32],
            space.as_bytes(),
            Credential::Upload.code(),
            &public,
        );
        let present = frasil_transport::messages::Present {
            request,
            space: *space.as_bytes(),
            credential: Credential::Upload.code().into(),
            public: public.to_vec(),
            proof: frasil_peers::proof::prove(seed, &elsewhere).to_vec(),
        }
        .encode();
        device.send_control(&present).await;
        let answer = device.answer(request).await.err();
        device.close().await;
        answer
    }

    /// The space's library, if it is one of [`LIBRARIES`], handed over to
    /// another peer and back, each operator step through the reachable
    /// nodes. A step the faults keep from answering resumes the library at
    /// the peer that still holds it, and the hand-over ends there.
    pub async fn hand_over_and_back(
        cluster: &TestCluster,
        reachable: &[usize],
        history: &History,
        seed: u64,
    ) {
        let space = history.space();
        let Some(library) = current(cluster, space).await else {
            return;
        };
        let (status, bundle) = through(
            cluster,
            reachable,
            library,
            "handover/export",
            Some(Vec::new()),
        )
        .await;
        if status != 200 {
            let _ = through(
                cluster,
                reachable,
                library,
                "handover/resume",
                Some(Vec::new()),
            )
            .await;
            return;
        }
        let other = other_peer(seed).await;
        let (status, _) = operator(&other.origin, library, "handover/import", Some(bundle)).await;
        if status != 200 {
            let _ = through(
                cluster,
                reachable,
                library,
                "handover/resume",
                Some(Vec::new()),
            )
            .await;
            other.shutdown().await;
            return;
        }
        let (status, _) = through(
            cluster,
            reachable,
            library,
            "handover/depart",
            Some(Vec::new()),
        )
        .await;
        let upload = history.upload_seed("V rotates, citing W's rotation");
        let live: Vec<usize> = reachable
            .iter()
            .copied()
            .filter(|n| running(cluster).contains(n))
            .collect();
        if status != 200 {
            // Not departed, or not known to be: the cluster keeps it.
            if live.first().is_some_and(|_| true) {
                let _ = through(
                    cluster,
                    reachable,
                    library,
                    "handover/resume",
                    Some(Vec::new()),
                )
                .await;
            }
            other.shutdown().await;
            return;
        }
        // Handed over: `moved` only to a valid proof under a key it held.
        if let Some(&n) = live.first() {
            assert_eq!(
                presented(cluster, n, space, &upload).await.as_deref(),
                Some("moved"),
                "seed {seed}: a valid proof learns the space moved"
            );
            assert_eq!(
                presented(cluster, n, space, &[42; 32]).await.as_deref(),
                Some("no_library"),
                "seed {seed}: any other proof learns nothing"
            );
            assert_eq!(
                forged(cluster, n, space, &upload).await.as_deref(),
                Some("no_library"),
                "seed {seed}: a key the space held, with a proof that does not \
                 verify, learns nothing"
            );
        }
        // And back.
        let (status, bundle) =
            operator(&other.origin, library, "handover/export", Some(Vec::new())).await;
        assert_eq!(
            status, 200,
            "seed {seed}: the other peer exports the library back"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, body) = through(
                cluster,
                reachable,
                library,
                "handover/import",
                Some(bundle.clone()),
            )
            .await;
            if status == 200 || status == 409 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "seed {seed}: the library is imported back: {status} {}",
                String::from_utf8_lossy(&body)
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let (status, _) =
            operator(&other.origin, library, "handover/depart", Some(Vec::new())).await;
        assert_eq!(
            status, 200,
            "seed {seed}: the other peer departs the library"
        );
        other.shutdown().await;
    }

    /// Once everything heals: no move under way, the index names one shard,
    /// and, judged on the first pass that finds so, no other node holds the
    /// space and the libraries count it once; then the owner keeps every
    /// acknowledged event, once it opens. Sweeps every node until the index
    /// settles, which carries a move left under way on. Returns the owner.
    pub async fn settled(
        cluster: &TestCluster,
        history: &History,
        acked: &BTreeSet<EventId>,
        seed: u64,
    ) -> usize {
        let space = history.space();
        let deadline = Instant::now() + Duration::from_secs(60);
        let (placed, owner) = loop {
            let live = running(cluster);
            for &n in &live {
                cluster.node(n).peer.peer.sweep().await;
            }
            let shards = cluster.node(live[0]).shards.clone();
            let placed = tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
                .await
                .unwrap()
                .ok()
                .flatten();
            let moving = cluster.node(live[0]).peer.peer.moving(space.as_bytes());
            if let Some(placed) = placed.clone()
                && !moving
                && let Some(owner) = cluster
                    .node(live[0])
                    .cluster
                    .owner(&placed)
                    .and_then(|id| cluster.index_of(id))
            {
                break (placed, owner);
            }
            if Instant::now() >= deadline {
                report(cluster, seed);
                panic!(
                    "seed {seed}: no move is under way and the index names the space: \
                     placed {placed:?}, moving {moving}"
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        let live = running(cluster);
        let doubled: Vec<usize> = live
            .iter()
            .copied()
            .filter(|n| *n != owner)
            .filter(|&n| {
                acked.iter().any(|id| {
                    cluster
                        .node(n)
                        .peer
                        .peer
                        .keeps(space.as_bytes(), id.as_bytes())
                })
            })
            .collect();
        assert!(
            doubled.is_empty(),
            "seed {seed}: nodes {doubled:?} hold the space the index places in {placed}"
        );
        // The open library shards its spaces by hash, apart from its own
        // shard, so its ledger's owner may not know them: the space counts
        // there by the index's placement. A route a node cannot answer yet
        // is asked again.
        let origin = &cluster.node(owner).peer.origin;
        let mut counted = u64::from(placed.starts_with("spaces/"));
        for library in LIBRARIES {
            let usage = loop {
                let (status, body) = operator(origin, library, "usage", None).await;
                match status {
                    200 => break serde_json::from_slice(&body).unwrap_or_default(),
                    404 => break serde_json::Value::Null,
                    _ if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    _ => panic!("seed {seed}: {library}'s usage is answered"),
                }
            };
            counted += usage["spaces"].as_u64().unwrap_or(0);
        }
        assert_eq!(
            counted, 1,
            "seed {seed}: the libraries count the space once"
        );
        loop {
            let kept = acked.iter().all(|id| {
                cluster
                    .node(owner)
                    .peer
                    .peer
                    .keeps(space.as_bytes(), id.as_bytes())
            });
            if kept {
                return owner;
            }
            if Instant::now() >= deadline {
                report(cluster, seed);
                panic!("seed {seed}: the owner of {placed} keeps every acknowledged event");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// A source cut off from the cluster in the middle of a move, as a fault
/// may leave it: its successor carries the move on, the cut-off source
/// sends no page more once its lease ended, and once the links heal the
/// space is in one shard, every acknowledged event kept, counted once.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_cut_off_mid_move_leaves_the_move_to_its_successor() {
    use frasil_libraries::{LibraryAttach, Purpose as TicketPurpose};
    use frasil_relay::testing::{MoveStep, hold_move};
    within(async {
        let seed = 77;
        let cluster = TestCluster::start_with(3, TIMING, 1000 + seed, libraries::settings())
            .await
            .expect("three nodes form a cluster");
        let mut history = History::credentials();
        let space = history.space();
        let mut founder = PeerClient::ws(&cluster.node(0).peer, Purpose::SpaceTraffic).await;
        let mut acked: BTreeSet<EventId> = founder
            .store(
                space,
                history.events(&[&history.order[0].clone()]),
                DEADLINE,
            )
            .await
            .into_iter()
            .collect();
        founder
            .present(
                space,
                Credential::Upload,
                &history.upload_seed(&history.order[0]),
            )
            .await
            .expect("the genesis's upload key");
        let rest: Vec<Vec<u8>> = history
            .order
            .iter()
            .filter(|n| *n != "W forks")
            .skip(1)
            .map(|n| history.signed(n))
            .collect();
        acked.extend(founder.store(space, rest, DEADLINE).await);
        founder.close().await;
        // The source owns the space's shard; the target library's shard is
        // another node's; the device's gateway is neither.
        let source = cluster.owner_of_space(space.as_bytes()).unwrap();
        let to = libraries::LIBRARIES
            .iter()
            .copied()
            .find(|library| {
                let id = cluster
                    .node(0)
                    .cluster
                    .owner(&libraries::shard(library))
                    .unwrap();
                cluster.index_of(id) != Some(source)
            })
            .expect("a library another node owns");
        let gateway = (0..3).find(|n| *n != source).unwrap();
        let hold = hold_move(*space.as_bytes(), to, MoveStep::LastPage);
        let mut device = writer(&cluster, gateway, &history).await;
        let moving = tokio::spawn(async move {
            let request = device.request();
            let message = LibraryAttach {
                request,
                space: *space.as_bytes(),
                purpose: TicketPurpose::Move,
                signed: libraries::Tickets::new(seed).move_ticket(to),
            }
            .encode();
            let _ = device.request_answer(request, &message).await;
            device.close().await;
        });
        tokio::time::timeout(Duration::from_secs(20), hold.reached())
            .await
            .expect("the move reaches its last page");
        cluster.isolate(source);
        // Its lease ends; then it is let go, and sends nothing more.
        let ended = cluster.node(source).lease_end().unwrap();
        while Instant::now() < ended + TIMING.lease {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        hold.release();
        let _ = tokio::time::timeout(Duration::from_secs(60), moving).await;
        cluster.faults.heal();
        cluster
            .settle(Duration::from_secs(60))
            .await
            .expect("the cluster settles once healed");
        let owner = libraries::settled(&cluster, &history, &acked, seed).await;
        let placed = {
            let shards = cluster.node(owner).shards.clone();
            tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        };
        assert!(
            placed == libraries::shard(to) || placed.starts_with("spaces/"),
            "{placed}"
        );
        // The index is settled; its owner may still be taking the space
        // up, so a refused store is tried again, with a fresh device, for a
        // while. A space that never takes stores fails here.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut attempt = 0;
        loop {
            let mut again = writer(&cluster, owner, &history).await;
            let unit = history.unit(
                "V",
                &format!("V writes once healed, attempt {attempt}"),
                stream("notes"),
                Vec::new(),
                None,
                &[],
            );
            let stored = again.store_one(space, &unit, DEADLINE).await;
            again.close().await;
            if stored {
                break;
            }
            assert!(Instant::now() < deadline, "the space stores again");
            attempt += 1;
            for n in running(&cluster) {
                cluster.node(n).peer.peer.sweep().await;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        cluster.shutdown().await;
    })
    .await;
}
