//! A peer on loopback, for end-to-end tests: memory records and objects by
//! default, a [`ManualClock`], the HTTP listener on `127.0.0.1` and the
//! iroh endpoint on IPv4 loopback with no relay, and, if asked, the
//! embedded iroh relay on loopback over plain HTTP. Nothing leaves the
//! machine.
//!
//! ```no_run
//! # async fn example() -> Result<(), frasil_relay::PeerError> {
//! let peer = frasil_relay::testing::spawn_loopback().await?;
//! // Dial `peer.connect_url` with the WebSocket subprotocol `frasil.p1`,
//! // or `peer.iroh.endpoint` at `peer.iroh.addresses` with ALPN
//! // `frasil/p1/peer`.
//! peer.shutdown().await;
//! # Ok(())
//! # }
//! ```

use crate::blobs::{Blobs, MemoryBlobs};
use crate::clock::ManualClock;
use crate::{IrohInfo, IrohRelay, IrohRelayConfig, Peer, PeerError, Running, Settings};
use frasil_store::{MemoryStore, Store};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// The timeline a test peer starts at, so that a test can step back.
pub const START: u64 = 1000;

/// With ext-libraries on, the open library of a test peer whose settings
/// leave libraries at their defaults: its creates need no ticket, as
/// without the extension.
pub const OPEN_LIBRARY: &str = "testing:open";

/// The key that seals a test peer's deposit keys at rest, unless its
/// settings name one (crate `deposit`).
pub const TEST_SEAL: [u8; 32] = [0x5e; 32];

/// A step of a move between libraries at which a test holds it (crate
/// `libraries`, module `moves`), to crash a node there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoveStep {
    /// At the source, once the move is recorded in the index.
    Recorded,
    /// At the source, before the last page goes to the target.
    LastPage,
    /// At the target, once the records are in its shard, before the index
    /// names it.
    Naming,
}

/// A move held at a step: [`MoveHold::reached`] once it gets there, and
/// [`MoveHold::release`] to let it go on.
#[derive(Debug, Default)]
pub struct MoveHold {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl MoveHold {
    /// Waits until the move reached the step.
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Lets the move go on.
    pub fn release(&self) {
        self.release.notify_one();
    }
}

type Holds =
    std::sync::Mutex<std::collections::HashMap<([u8; 32], String, MoveStep), Arc<MoveHold>>>;

fn move_holds() -> &'static Holds {
    static HOLDS: std::sync::OnceLock<Holds> = std::sync::OnceLock::new();
    HOLDS.get_or_init(Holds::default)
}

/// Holds the next move of `space` into `library` at `step`, once, on
/// whichever node of the process gets there.
pub fn hold_move(space: [u8; 32], library: &str, step: MoveStep) -> Arc<MoveHold> {
    let hold = Arc::new(MoveHold::default());
    move_holds()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((space, library.to_owned(), step), hold.clone());
    hold
}

/// A move of `space` into `library` at `step`: held there if a test asked.
pub(crate) async fn move_step(space: &[u8; 32], library: &str, step: MoveStep) {
    let hold = move_holds()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(*space, library.to_owned(), step));
    if let Some(hold) = hold {
        hold.reached.notify_one();
        hold.release.notified().await;
    }
}

/// The acknowledgements of events stored in a space that a test has the
/// peer withhold, as when the connection that stored them ends before the
/// device reads them: the events are stored and executed as ever.
#[derive(Debug, Default)]
pub struct AckWithholding {
    withheld: std::sync::atomic::AtomicUsize,
}

impl AckWithholding {
    /// How many acknowledgements were withheld.
    pub fn withheld(&self) -> usize {
        self.withheld.load(std::sync::atomic::Ordering::SeqCst)
    }
}

type Withholdings = std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<AckWithholding>>>;

fn withholdings() -> &'static Withholdings {
    static WITHHOLDINGS: std::sync::OnceLock<Withholdings> = std::sync::OnceLock::new();
    WITHHOLDINGS.get_or_init(Withholdings::default)
}

/// Has every peer of the process withhold its acknowledgements of the
/// events stored in `space` from now on.
pub fn withhold_acknowledgements(space: [u8; 32]) -> Arc<AckWithholding> {
    let withholding = Arc::new(AckWithholding::default());
    withholdings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(space, withholding.clone());
    withholding
}

/// Whether the acknowledgement of events stored in `space` is withheld.
pub(crate) fn acknowledgement_withheld(space: &[u8; 32]) -> bool {
    let withholdings = withholdings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(withholding) = withholdings.get(space) else {
        return false;
    };
    withholding
        .withheld
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    true
}

/// Makes each page of a move between libraries hold one record or copy,
/// in every node of the process, so that a test's small move spans
/// several pages.
pub fn move_one_row_per_page() {
    ONE_ROW_PER_PAGE.store(true, std::sync::atomic::Ordering::SeqCst);
}

static ONE_ROW_PER_PAGE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The bytes a page of a move holds at most: `normal`, unless a test asked
/// for one row per page.
pub(crate) fn move_page_bytes(normal: usize) -> usize {
    if ONE_ROW_PER_PAGE.load(std::sync::atomic::Ordering::SeqCst) {
        1
    } else {
        normal
    }
}

/// What a test peer runs with.
pub struct Options {
    /// The operator's settings: [`Settings::open_core`] by default, a core
    /// peer that hosts any space, which most tests start from.
    pub settings: Settings,
    /// The records; memory if none.
    pub store: Option<Arc<dyn Store>>,
    /// The records in shards, in place of [`Options::store`]: each space's
    /// sights on its shard's timeline, and the shards' maintenance on the
    /// writer's thread.
    pub shards: Option<Arc<crate::shards::Shards>>,
    /// The object store; memory if none.
    pub blobs: Option<Arc<dyn Blobs>>,
    /// The clock; a [`ManualClock`] at [`START`] if none.
    pub clock: Option<Arc<ManualClock>>,
    /// Whether to listen on the iroh binding.
    pub iroh: bool,
    /// The HTTP listener's address; `127.0.0.1` on a free port by default.
    pub listen: SocketAddr,
    /// Whether to run the embedded iroh relay, on `127.0.0.1` over plain
    /// HTTP; off by default. The discovery document names it unless
    /// [`Settings::relays`] names others.
    pub iroh_relay: bool,
    /// The cluster this peer is a node of, with [`Options::shards`].
    pub cluster: Option<Arc<crate::cluster::Cluster>>,
    /// The iroh endpoint's secret key; fresh if none.
    pub iroh_key: Option<[u8; 32]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            settings: Settings::open_core(),
            store: None,
            shards: None,
            blobs: None,
            clock: None,
            iroh: true,
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            iroh_relay: false,
            cluster: None,
            iroh_key: None,
        }
    }
}

/// A peer running on loopback.
#[derive(Debug)]
pub struct TestPeer {
    /// The service, to read its state.
    pub peer: Peer,
    /// Its clock.
    pub clock: Arc<ManualClock>,
    /// The HTTP listener.
    pub http: SocketAddr,
    /// The origin clients connect to: `http://127.0.0.1:<port>`.
    pub origin: String,
    /// The WebSocket route: `ws://127.0.0.1:<port>/frasil/p1/connect`.
    pub connect_url: String,
    /// The iroh endpoint, when it listens on one.
    pub iroh: Option<IrohInfo>,
    /// The embedded iroh relay's URL, `http://127.0.0.1:<port>`, when it
    /// runs.
    pub relay_url: Option<String>,
    running: Running,
    relay: Option<IrohRelay>,
}

/// Starts a peer on loopback with the default options.
///
/// # Errors
///
/// If a listener does not bind.
pub async fn spawn_loopback() -> Result<TestPeer, PeerError> {
    spawn_with(Options::default()).await
}

/// Starts a peer on loopback.
///
/// # Errors
///
/// If a listener does not bind, or the records cannot be read.
pub async fn spawn_with(options: Options) -> Result<TestPeer, PeerError> {
    let store = options
        .store
        .unwrap_or_else(|| Arc::new(MemoryStore::new()) as Arc<dyn Store>);
    let blobs = options
        .blobs
        .unwrap_or_else(|| Arc::new(MemoryBlobs::new()) as Arc<dyn Blobs>);
    let clock = options
        .clock
        .unwrap_or_else(|| Arc::new(ManualClock::new(START)));
    let iroh = if options.iroh {
        let key = match options.iroh_key {
            Some(key) => key,
            None => frasil_iroh::fresh_secret_key()?,
        };
        Some(frasil_iroh::Config::new(key, &[frasil_iroh::Alpn::Peer]).loopback())
    } else {
        None
    };
    let relay = if options.iroh_relay {
        let config = IrohRelayConfig {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls: None,
            quic: None,
        };
        Some(IrohRelay::spawn(&config).await?)
    } else {
        None
    };
    let mut settings = options.settings;
    // The discovery document names the embedded relay, unless the options
    // name relays of their own.
    if let Some(relay) = &relay
        && settings.relays.is_empty()
    {
        settings.relays = vec![relay.url()];
    }
    if settings.extensions.libraries
        && settings.libraries == crate::libraries::LibrarySettings::default()
    {
        settings.libraries.open_library = frasil_libraries::LibraryId::new(OPEN_LIBRARY).ok();
    }
    // ext-deposit-tokens: one sealing key for every test peer, so that a
    // peer started again on the same records opens the keys it sealed.
    if settings.deposit_tokens.seal.is_none() {
        settings.deposit_tokens.seal = Some(crate::deposit::SealKey::new(TEST_SEAL));
    }
    let running = match options.shards {
        Some(shards) => {
            let opened = clock.clone();
            let cluster = options.cluster;
            let peer = tokio::task::spawn_blocking(move || match cluster {
                Some(cluster) => Peer::open_clustered(settings, shards, cluster, blobs, opened),
                None => Peer::open_sharded(settings, shards, blobs, opened),
            })
            .await
            .map_err(|e| PeerError(format!("the peer did not open: {e}")))??;
            crate::serve(peer, options.listen, iroh, None).await?
        }
        None => {
            crate::start(
                settings,
                store,
                blobs,
                clock.clone(),
                options.listen,
                iroh,
                None,
            )
            .await?
        }
    };
    let http = running.http;
    Ok(TestPeer {
        peer: running.peer.clone(),
        clock,
        http,
        origin: format!("http://{http}"),
        connect_url: format!("ws://{http}{}", frasil_transport::peer::CONNECT_PATH),
        iroh: running.iroh.clone(),
        relay_url: relay.as_ref().map(IrohRelay::url),
        running,
        relay,
    })
}

impl TestPeer {
    /// Advances the peer's timeline, then sweeps.
    pub async fn advance(&self, seconds: u64) {
        self.clock.advance(seconds);
        self.peer.sweep().await;
    }

    /// Sets the peer's timeline, then sweeps.
    pub async fn set_time(&self, timeline: u64) {
        self.clock.set(timeline);
        self.peer.sweep().await;
    }

    /// Stops the peer.
    pub async fn shutdown(self) {
        self.running.shutdown().await;
        if let Some(relay) = self.relay {
            relay.shutdown().await;
        }
    }
}

pub mod cluster {
    //! Several nodes of one cluster in one process, for tests: each a peer
    //! on loopback, over one in-memory bucket and one store of objects,
    //! with in-process internal links. Each node has its own lease clock,
    //! whose rate a test sets; the links drop, delay and partition frames
    //! by a seed; and each node's view of the bucket delays, fails or loses
    //! its answers on its own, lands a write its node stopped waiting for,
    //! as an S3 PUT once sent does, and records when it issued each write
    //! and when each landed.

    use super::{Options, TestPeer, spawn_with};
    use crate::PeerError;
    use crate::blobs::{Blobs, MemoryBlobs};
    use crate::cluster::lease::{SkewedClock, Timing};
    use crate::cluster::link::{Faults, MemoryNet, NodeId};
    use crate::cluster::{Cluster, ClusterConfig, Listen, TimedBucket, Wiring};
    use crate::shards::Shards;
    use crate::shards::bucket::{Bucket, BucketError, BucketIo, MemoryBucket};
    use frasil_store::BoxFuture;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    /// Leases for tests: a second long, renewed every 100 ms, with a 20%
    /// margin and 200 ms writes.
    pub const TIMING: Timing = Timing {
        lease: Duration::from_secs(1),
        renew: Duration::from_millis(100),
        drift: 0.2,
        put_timeout: Duration::from_millis(200),
    };

    /// [`TIMING`] five times over, for a test that tells a lease's wait
    /// from the work around it by time: a lease of five seconds is far
    /// longer than a store on a slow machine.
    pub const SLOW_TIMING: Timing = Timing {
        lease: Duration::from_secs(5),
        renew: Duration::from_millis(500),
        drift: 0.2,
        put_timeout: Duration::from_secs(1),
    };

    /// One node's view of the shared bucket.
    pub struct NodeBucket {
        inner: Arc<dyn Bucket>,
        delay: Mutex<Duration>,
        down: Arc<AtomicBool>,
        lose: AtomicBool,
        land_late: AtomicBool,
        writes: Mutex<Vec<(Instant, String)>>,
        landed: Arc<Mutex<Vec<(Instant, String)>>>,
        answered: Mutex<Vec<String>>,
    }

    impl core::fmt::Debug for NodeBucket {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("NodeBucket").finish_non_exhaustive()
        }
    }

    impl NodeBucket {
        fn new(inner: Arc<dyn Bucket>) -> Self {
            Self {
                inner,
                delay: Mutex::new(Duration::ZERO),
                down: Arc::new(AtomicBool::new(false)),
                lose: AtomicBool::new(false),
                land_late: AtomicBool::new(true),
                writes: Mutex::new(Vec::new()),
                landed: Arc::new(Mutex::new(Vec::new())),
                answered: Mutex::new(Vec::new()),
            }
        }

        /// Delays every request of this node.
        pub fn set_delay(&self, delay: Duration) {
            *self.delay.lock().unwrap_or_else(PoisonError::into_inner) = delay;
        }

        /// Fails every request of this node, as a node that is gone.
        pub fn set_down(&self, down: bool) {
            self.down.store(down, Ordering::SeqCst);
        }

        /// Lands every write of this node and answers it as failed.
        pub fn set_lose_answers(&self, lose: bool) {
            self.lose.store(lose, Ordering::SeqCst);
        }

        /// Whether a write this node stopped waiting for, one that timed
        /// out, still lands once its delay has passed, as an S3 PUT once
        /// sent does: on by default.
        pub fn set_land_late(&self, land: bool) {
            self.land_late.store(land, Ordering::SeqCst);
        }

        /// When each write of this node landed in the bucket, by true time,
        /// and its key.
        pub fn landed(&self) -> Vec<(Instant, String)> {
            self.landed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The keys of this node's writes the bucket answered as landed:
        /// those a shard may have acknowledged.
        pub fn answered(&self) -> Vec<String> {
            self.answered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// When this node issued each write, by true time, and its key,
        /// whether the bucket took it or not.
        pub fn writes(&self) -> Vec<(Instant, String)> {
            self.writes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        async fn wait(&self) -> Result<(), BucketError> {
            let delay = *self.delay.lock().unwrap_or_else(PoisonError::into_inner);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if self.down.load(Ordering::SeqCst) {
                return Err(BucketError("this node's bucket is down".into()));
            }
            Ok(())
        }
    }

    impl Bucket for NodeBucket {
        fn put<'a>(
            &'a self,
            key: &'a str,
            bytes: Vec<u8>,
        ) -> BoxFuture<'a, Result<(), BucketError>> {
            Box::pin(async move {
                self.writes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((Instant::now(), key.to_owned()));
                let delay = *self.delay.lock().unwrap_or_else(PoisonError::into_inner);
                let land = {
                    let inner = self.inner.clone();
                    let down = self.down.clone();
                    let landed = self.landed.clone();
                    let key = key.to_owned();
                    async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if down.load(Ordering::SeqCst) {
                            return Err(BucketError("this node's bucket is down".into()));
                        }
                        inner.put(&key, bytes).await?;
                        landed
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((Instant::now(), key));
                        Ok(())
                    }
                };
                if self.land_late.load(Ordering::SeqCst) {
                    // A task of its own, which goes on if this future is
                    // dropped: the write lands though no one waits for it.
                    tokio::spawn(land)
                        .await
                        .unwrap_or_else(|_| Err(BucketError("the write's task ended".into())))?;
                } else {
                    land.await?;
                }
                if self.lose.load(Ordering::SeqCst) {
                    return Err(BucketError("the answer was lost".into()));
                }
                self.answered
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(key.to_owned());
                Ok(())
            })
        }

        fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BucketError>> {
            Box::pin(async move {
                self.wait().await?;
                self.inner.get(key).await
            })
        }

        fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, BucketError>> {
            Box::pin(async move {
                self.wait().await?;
                self.inner.list(prefix).await
            })
        }

        fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BucketError>> {
            Box::pin(async move {
                self.wait().await?;
                self.inner.delete(key).await
            })
        }
    }

    /// One node.
    #[derive(Debug)]
    pub struct Node {
        /// The peer on loopback, which devices connect to.
        pub peer: TestPeer,
        /// Its membership of the cluster.
        pub cluster: Arc<Cluster>,
        /// Its shards.
        pub shards: Arc<Shards>,
        /// Its view of the bucket.
        pub bucket: Arc<NodeBucket>,
        /// The clock its lease counts on.
        pub clock: Arc<SkewedClock>,
        /// Its ID.
        pub id: NodeId,
    }

    impl Node {
        /// The true instant this node's last lease ended or ends, by its
        /// own clock.
        pub fn lease_end(&self) -> Option<Instant> {
            let lease = self.cluster.lease();
            lease
                .last_sent()
                .map(|sent| self.clock.true_instant(sent + lease.timing().held()))
        }

        /// The true instant this node sent its last renewal that was
        /// committed: its lease ends, by true time, at most a lease later.
        pub fn last_renewal_sent(&self) -> Option<Instant> {
            self.cluster
                .lease()
                .last_sent()
                .map(|sent| self.clock.true_instant(sent))
        }
    }

    /// A cluster's nodes.
    #[derive(Debug)]
    pub struct TestCluster {
        /// The nodes, each none once stopped.
        pub nodes: Vec<Option<Node>>,
        /// The links' network.
        pub net: Arc<MemoryNet>,
        /// The links' faults.
        pub faults: Arc<Faults>,
        /// The bucket every node shares.
        pub bucket: Arc<MemoryBucket>,
        /// The objects every node shares.
        pub blobs: Arc<MemoryBlobs>,
        timing: Timing,
        dir: PathBuf,
        seed: u64,
        /// The operator's settings every node runs with.
        settings: crate::Settings,
        /// What each node keeps across a restart: its Raft store, its view
        /// of the bucket and its clock.
        parts: Vec<Parts>,
        /// Whether the nodes ask devices to reconnect elsewhere when one
        /// holds more than its share: off unless a test sets it, since a
        /// test's device does not reconnect, and a test may well put every
        /// device on one node.
        balancing: bool,
    }

    /// What a node keeps across a restart.
    #[derive(Debug, Clone)]
    struct Parts {
        raft: Arc<frasil_store::MemoryStore>,
        bucket: Arc<NodeBucket>,
        clock: Arc<SkewedClock>,
        /// Its earlier runs' renewals granted (`TestCluster::grants`).
        granted: Arc<Mutex<Vec<(Instant, Instant)>>>,
    }

    impl Drop for TestCluster {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The cluster key of tests.
    pub const KEY: [u8; 32] = [7; 32];

    impl TestCluster {
        /// Starts `count` nodes under `timing`, with node IDs drawn from
        /// `seed`: the first forms the cluster and the others join through
        /// it. Returns once every node is a member and the cluster is
        /// settled.
        ///
        /// # Errors
        ///
        /// If a node does not start.
        pub async fn start(count: usize, timing: Timing, seed: u64) -> Result<Self, PeerError> {
            Self::start_with(count, timing, seed, crate::Settings::open_core()).await
        }

        /// [`Self::start`], every node with the operator's `settings`.
        ///
        /// # Errors
        ///
        /// If a node does not start.
        pub async fn start_with(
            count: usize,
            timing: Timing,
            seed: u64,
            settings: crate::Settings,
        ) -> Result<Self, PeerError> {
            let dir = std::env::temp_dir().join(format!(
                "frasil-cluster-{seed}-{}",
                crate::util::hex(
                    &*frasil_crypto::random_bytes::<6>()
                        .map_err(|_| PeerError("no randomness".into()))?
                )
            ));
            let mut cluster = Self {
                nodes: Vec::new(),
                net: Arc::new(MemoryNet::new()),
                faults: Arc::new(Faults::new(seed)),
                bucket: Arc::new(MemoryBucket::new()),
                blobs: Arc::new(MemoryBlobs::new()),
                timing,
                dir,
                seed,
                settings,
                parts: Vec::new(),
                balancing: false,
            };
            for _ in 0..count {
                cluster.add().await?;
            }
            cluster.settle(Duration::from_secs(30)).await?;
            Ok(cluster)
        }

        /// Sets whether every node, and every node started later, asks
        /// devices to reconnect elsewhere when it holds more than its share
        /// (crate `cluster`, "Balance and draining"). Off unless set.
        pub fn set_balancing(&mut self, on: bool) {
            self.balancing = on;
            for node in self.nodes.iter().flatten() {
                node.cluster.set_balancing(on);
            }
        }

        /// The address of node `n`'s links.
        fn address(n: usize) -> String {
            format!("node-{n}")
        }

        /// Starts one more node, which joins through the first.
        ///
        /// # Errors
        ///
        /// If it does not start.
        pub async fn add(&mut self) -> Result<usize, PeerError> {
            let n = self.nodes.len();
            let raft = Arc::new(frasil_store::MemoryStore::new());
            // The node's ID derives from its name and this nonce: from the
            // seed, so that a run places shards as the last did.
            let nonce = (self.seed * 64 + n as u64).to_be_bytes().to_vec();
            let stored = futures_util::FutureExt::now_or_never(frasil_store::Store::commit(
                &*raft,
                &frasil_store::Commit::new(vec![(b"i".to_vec(), nonce)], Vec::new()),
            ));
            if !matches!(stored, Some(Ok(true))) {
                return Err(PeerError("the Raft store's nonce was not kept".into()));
            }
            let shared: Arc<dyn Bucket> = self.bucket.clone();
            self.parts.push(Parts {
                raft,
                bucket: Arc::new(NodeBucket::new(shared)),
                clock: Arc::new(SkewedClock::new(1.0)),
                granted: Arc::default(),
            });
            self.nodes.push(None);
            self.launch(n).await?;
            Ok(n)
        }

        /// Starts node `n` again, stopped by [`Self::kill`] or
        /// [`Self::leave`], with its Raft store, its cache and its view of
        /// the bucket, which is up again.
        ///
        /// # Errors
        ///
        /// If it does not start.
        pub async fn restart(&mut self, n: usize) -> Result<(), PeerError> {
            if self.nodes[n].is_some() {
                return Ok(());
            }
            let parts = self.parts[n].clone();
            parts.bucket.set_down(false);
            let raft: Arc<dyn frasil_store::Store> = parts.raft.clone();
            let nonce = crate::cluster::raft::nonce(&raft).map_err(PeerError)?;
            let name = Self::name(self.seed, n);
            self.faults
                .reconnect(crate::cluster::node_id(&name, &nonce));
            self.launch(n).await
        }

        fn name(seed: u64, n: usize) -> String {
            format!("{:016x}{:016x}", 0x1000 + seed * 64 + n as u64, n)
        }

        async fn launch(&mut self, n: usize) -> Result<(), PeerError> {
            let name = Self::name(self.seed, n);
            let parts = self.parts[n].clone();
            let timed: Arc<dyn Bucket> = Arc::new(TimedBucket::new(
                parts.bucket.clone(),
                self.timing.put_timeout,
            ));
            let io = Arc::new(BucketIo::new(timed).map_err(|e| PeerError(e.to_string()))?);
            let iroh_secret = frasil_iroh::fresh_secret_key()?;
            let config = ClusterConfig {
                key: KEY.into(),
                listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                advertise: Self::address(n),
                seeds: (0..self.parts.len())
                    .filter(|&other| other != n)
                    .map(Self::address)
                    .collect(),
                capacity: 100,
                bootstrap: n == 0,
                timing: self.timing,
                spaces_per_connection: crate::cluster::SPACES_PER_CONNECTION,
            };
            let wiring = Wiring {
                net: self.net.clone(),
                listen: Listen::Memory(self.net.listen(&Self::address(n))),
                faults: self.faults.clone(),
                clock: parts.clock.clone(),
                raft: parts.raft.clone(),
            };
            let iroh = frasil_crypto::primitives::ed25519_public(&iroh_secret);
            let member = Cluster::start(config, &name, Some(iroh), io.clone(), wiring).await?;
            // A node that fails to start stops, as its process would exit.
            let started = async {
                let cache = self.dir.join(format!("node-{n}"));
                let fence: Arc<dyn crate::shards::fence::Fence> = Arc::new(member.fence());
                let ownership: Arc<dyn crate::shards::fence::Ownership> = member.clone();
                let shards = tokio::task::spawn_blocking(move || {
                    Shards::clustered(io, cache, fence, ownership)
                })
                .await
                .map_err(|e| PeerError(e.to_string()))??;
                let blobs: Arc<dyn Blobs> = self.blobs.clone();
                let peer = spawn_with(Options {
                    settings: self.settings.clone(),
                    shards: Some(shards.clone()),
                    cluster: Some(member.clone()),
                    blobs: Some(blobs),
                    iroh_key: Some(iroh_secret),
                    ..Options::default()
                })
                .await?;
                Ok::<_, PeerError>((shards, peer))
            }
            .await;
            let (shards, peer) = match started {
                Ok(started) => started,
                Err(error) => {
                    member.stop().await;
                    self.keep_grants(n, &member);
                    return Err(error);
                }
            };
            member.set_balancing(self.balancing);
            let id = member.me();
            self.nodes[n] = Some(Node {
                peer,
                cluster: member,
                shards,
                bucket: parts.bucket,
                clock: parts.clock,
                id,
            });
            Ok(())
        }

        /// Stops node `n` cleanly, as `frasil-relay` does at SIGTERM: its
        /// shards handed over, its connections closed with `reconnect`, and
        /// the cluster left.
        pub async fn leave(&mut self, n: usize) {
            let Some(node) = self.nodes[n].take() else {
                return;
            };
            node.cluster.hand_over().await;
            node.peer.shutdown().await;
            let shards = node.shards.clone();
            let _ = tokio::task::spawn_blocking(move || shards.close_all()).await;
            node.cluster.leave().await;
            self.keep_grants(n, &node.cluster);
            self.net.close(&Self::address(n));
        }

        /// Each renewal node `n`, in any of its runs, was granted, by true
        /// time: when it was sent, and the last instant a write may be
        /// issued under it, `held` less a write's timeout later by both the
        /// node's clocks (crate `cluster`, module `lease`). A write issued
        /// under it lands within a lease of its send.
        pub fn grants(&self, n: usize) -> Vec<(Instant, Instant)> {
            let parts = &self.parts[n];
            let mut all = parts
                .granted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(node) = &self.nodes[n] {
                all.extend(Self::bounds(parts, &node.cluster));
            }
            all.sort();
            all
        }

        /// A run's renewals granted, as [`Self::grants`] gives them.
        fn bounds(parts: &Parts, cluster: &Cluster) -> Vec<(Instant, Instant)> {
            let lease = cluster.lease();
            let timing = lease.timing();
            let issue = timing.held().saturating_sub(timing.put_timeout);
            lease
                .grants()
                .into_iter()
                .map(|sent| {
                    let from = parts.clock.true_instant(sent);
                    // The wall clock counts true time.
                    let by = parts.clock.true_instant(sent + issue).min(from + issue);
                    (from, by)
                })
                .collect()
        }

        /// How many nodes were started.
        pub fn len(&self) -> usize {
            self.parts.len()
        }

        /// Whether no node was started.
        pub fn is_empty(&self) -> bool {
            self.parts.is_empty()
        }

        /// Keeps the grants of a run of node `n` once it stopped renewing.
        fn keep_grants(&self, n: usize, cluster: &Cluster) {
            let parts = &self.parts[n];
            let bounds = Self::bounds(parts, cluster);
            parts
                .granted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(bounds);
        }

        /// Node `n`'s view of the bucket, running or not.
        pub fn bucket_of(&self, n: usize) -> Arc<NodeBucket> {
            self.parts[n].bucket.clone()
        }

        /// Node `n`'s lease clock, running or not.
        pub fn clock_of(&self, n: usize) -> Arc<SkewedClock> {
            self.parts[n].clock.clone()
        }

        /// Node `n`, while it runs.
        pub fn node(&self, n: usize) -> &Node {
            self.nodes[n].as_ref().expect("the node runs")
        }

        /// The IDs of every node started.
        pub fn ids(&self) -> Vec<NodeId> {
            self.nodes.iter().flatten().map(|node| node.id).collect()
        }

        /// The index of a node by its ID.
        pub fn index_of(&self, id: NodeId) -> Option<usize> {
            self.nodes
                .iter()
                .position(|node| node.as_ref().is_some_and(|node| node.id == id))
        }

        /// The node that owns a space's shard, as the running nodes agree.
        pub fn owner_of_space(&self, space: &[u8; 32]) -> Option<usize> {
            let first = self.nodes.iter().flatten().next()?;
            self.index_of(first.cluster.owner_of_space(space)?)
        }

        /// Waits until every running node applied the same membership, every
        /// member confirmed its epoch, and the voters are as many as the
        /// members call for.
        ///
        /// # Errors
        ///
        /// If it does not settle in time.
        pub async fn settle(&self, within: Duration) -> Result<(), PeerError> {
            let deadline = Instant::now() + within;
            loop {
                let running: Vec<&Node> = self.nodes.iter().flatten().collect();
                let first = running[0].cluster.membership();
                let same = running.iter().all(|node| {
                    let state = node.cluster.membership();
                    state.epoch == first.epoch && state.settled()
                });
                let members = first.nodes.len();
                let wanted = match members {
                    0..=2 => 1,
                    3 | 4 => 3,
                    _ => 5,
                };
                let voters = running
                    .iter()
                    .map(|node| {
                        node.cluster
                            .raft()
                            .metrics()
                            .borrow()
                            .membership_config
                            .membership()
                            .voter_ids()
                            .count()
                    })
                    .max()
                    .unwrap_or(0);
                if same && members == running.len() && voters == wanted {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(PeerError(format!(
                        "the cluster did not settle: {members} members, {voters} voters"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// Cuts node `n` off from every other node: it keeps running, and
        /// its renewals fail.
        pub fn isolate(&self, n: usize) {
            let id = self.node(n).id;
            self.faults.isolate(id, &self.ids());
        }

        /// Stops node `n` as a crash does: its bucket fails, its links are
        /// cut, and it stops renewing and serving.
        pub async fn kill(&mut self, n: usize) {
            if self.nodes[n].is_none() {
                return;
            }
            self.isolate(n);
            let Some(node) = self.nodes[n].take() else {
                return;
            };
            node.bucket.set_down(true);
            node.cluster.stop().await;
            self.keep_grants(n, &node.cluster);
            self.net.close(&Self::address(n));
            node.peer.shutdown().await;
        }

        /// Stops every node.
        pub async fn shutdown(mut self) {
            for n in 0..self.nodes.len() {
                self.kill(n).await;
            }
        }
    }
}

/// What one connection showed the peer, as [`Watch`] records it: enough
/// for a test to say which credentials, collections, draws and deposits
/// travelled together (transport.md, 3.12 What a peer learns of a device;
/// ext-deposit-tokens.md, 3.6 Depositing with a token).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Shown {
    /// The remote end, as the peer names it for rates: the address on the
    /// server binding, the endpoint key on the iroh binding.
    pub source: String,
    /// Whether it came over the server binding's WebSocket.
    pub server: bool,
    /// Whether its WebSocket upgrade carried a cookie or `Authorization`.
    pub credentialed: bool,
    /// Each message's type, in order, from the `Hello` on.
    pub kinds: Vec<frasil_transport::frame::MessageType>,
    /// Each `Present`: the space and the credential's code.
    pub presented: Vec<([u8; 32], u64)>,
    /// Each `MailboxGet` that carried a collector's `ed || kc`: the address.
    pub collected: Vec<[u8; 32]>,
    /// Each deposit in a device mailbox: the address, and the nonce of the
    /// token it carried, if any.
    pub deposits: Vec<([u8; 32], Option<[u8; 32]>)>,
    /// Each `TokenRequest`: the space of a space draw, none for a grant
    /// draw.
    pub draws: Vec<Option<[u8; 32]>>,
}

/// What each connection showed the peer since a test began to watch
/// ([`Peer::watch`]), by the peer's own number for it.
#[derive(Debug, Default)]
pub struct Watch {
    links: std::sync::Mutex<std::collections::BTreeMap<u64, Shown>>,
    posts: std::sync::Mutex<Vec<Shown>>,
}

impl Watch {
    /// Every connection watched, in the order they opened.
    pub fn connections(&self) -> Vec<Shown> {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn opened(&self, link: u64, source: &str, server: bool, credentialed: bool) {
        self.with(link, |shown| {
            shown.source = source.to_owned();
            shown.server = server;
            shown.credentialed = credentialed;
        });
    }

    pub(crate) fn message(&self, link: u64, message: &frasil_transport::frame::Message) {
        use frasil_transport::frame::MessageType;
        let bytes = |key: u64| -> Option<[u8; 32]> { message.get(key)?.as_byte_array::<32>().ok() };
        let number = |key: u64| message.get(key).and_then(|v| v.as_unsigned().ok());
        self.with(link, |shown| {
            shown.kinds.push(message.kind);
            match message.kind {
                MessageType::Present => {
                    if let (Some(space), Some(credential)) = (bytes(2), number(3)) {
                        shown.presented.push((space, credential));
                    }
                }
                MessageType::MailboxGet if message.get(4).is_some() => {
                    if let Some(address) = bytes(2) {
                        shown.collected.push(address);
                    }
                }
                MessageType::MailboxPut if number(6) == Some(3) => {
                    if let Some(address) = bytes(2) {
                        let token = message.get(7).and_then(|token| token.as_bytes().ok());
                        shown.deposits.push((address, token.and_then(nonce)));
                    }
                }
                MessageType::TokenRequest => shown.draws.push(bytes(5)),
                _ => {}
            }
        });
    }

    /// A deposit by `POST`, a request of its own.
    pub(crate) fn posted(
        &self,
        source: &str,
        address: [u8; 32],
        token: Option<[u8; 32]>,
        credentialed: bool,
    ) {
        self.posts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Shown {
                source: source.to_owned(),
                server: true,
                credentialed,
                deposits: vec![(address, token)],
                ..Shown::default()
            });
    }

    /// Every deposit by `POST`, in order, each as a request of its own.
    pub fn posts(&self) -> Vec<Shown> {
        self.posts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The nonce of a token's header, `Frasil-Token <258 hex>`, if it reads.
    pub(crate) fn header_nonce(value: &str) -> Option<[u8; 32]> {
        let hex = value.strip_prefix("Frasil-Token ")?;
        let bytes: Option<Vec<u8>> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
            .collect();
        nonce(&bytes?)
    }

    fn with(&self, link: u64, f: impl FnOnce(&mut Shown)) {
        f(self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(link)
            .or_default());
    }
}

/// A token's nonce: its bytes 33 to 64 (ext-deposit-tokens.md, 2.4 Tokens).
fn nonce(token: &[u8]) -> Option<[u8; 32]> {
    token.get(33..65)?.try_into().ok()
}
