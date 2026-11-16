//! Several nodes in one region acting as one peer over one bucket
//! (peers.md, 3.1 Hosting a space, "One peer on several machines").
//!
//! Every node is a gateway for the devices connected to it and the owner
//! of the shards placed on it (crate `shards`). The nodes agree, through
//! Raft (module `raft`), on the membership, under a numbered epoch, and on
//! each node's lease (module `lease`): nothing else goes through Raft. Each
//! shard's owner is computed from the epoch's members (module `placement`).
//! The nodes reach each other over one authenticated, encrypted connection
//! per pair (module `link`), which carries Raft, the hashed shards' records
//! other nodes keep, and each space's traffic, forwarded from its gateway
//! to its owner (module `route`).
//!
//! # Membership and leases
//!
//! - Three or five nodes vote, chosen by the leader from the members; the
//!   others follow as learners. A voter whose lease ended is removed and
//!   replaced while a majority remains.
//! - Each node renews its lease every [`Timing::renew`], as the process
//!   that last joined under its ID: a renewal of another process, or of a
//!   node that is no member, is refused, and the node then breaks every
//!   shard it holds open and joins again. The leader removes a node it has
//!   not seen renew for `lease × (1 + drift)` by its own clock, counted
//!   from when it became leader at the earliest.
//! - At each new epoch a node waits for the opens under way, then gives up
//!   every open shard it no longer owns, with a last manifest and no fold,
//!   breaks every shard it opened before its latest join, and confirms the
//!   epoch through Raft, again with each renewal for as long as the
//!   membership shows it unconfirmed. A node opens a shard only once every
//!   member confirmed the epoch, and checks again as the open ends that it
//!   still owns it: a live node that lost the shard has given it up, and a
//!   node that is cut off is no member any more, which the leader decides
//!   only after its lease ended. So no two nodes write one shard, and the
//!   new owner reads the earlier owner's last acknowledged batch before it
//!   writes (crate `shards`, module `shard`, "Opening").
//! - A node answers for a shard it owned at its last reading of the state
//!   no one shard keeps at once, and for one it gained once it read that
//!   state again; only a shard's first open waits for every member to
//!   confirm.
//! - A renewal travels on the link to the leader, which sends the
//!   cluster's own traffic before its clients' (module `link`, "Two shares
//!   of a connection"). A link to the leader that goes dead is noticed and
//!   dialed again so that a renewal is granted again at most seven
//!   renewals after the last one granted was sent, within the lease less
//!   its drift margin, which `Timing::check` requires (module `link`, "A
//!   dead connection").
//!
//! # Balance and draining
//!
//! Every lease each node tells every member how many device connections it
//! holds. A node above the placed members' average by more than a tenth,
//! and at least one, asks some of its connections to reconnect elsewhere
//! (transport.md, 3.10, "Reconnecting elsewhere"): each lease at most its
//! excess and at most one in a hundred of its connections, at least one,
//! each at a random moment within the lease. So a new node fills over
//! minutes, and no lease moves more than a hundredth of a node's devices.
//! A node that drains for a planned stop first leaves the placement, hands
//! its shards over as an epoch does, with a last manifest each and no wait
//! for its lease, and only then closes its connections with `reconnect`.
//!
//! # Forming a cluster
//!
//! Exactly one node is started the first time with the bootstrap setting.
//! It refuses a bucket whose `cluster` object names a cluster; otherwise it
//! writes there a claim naming the new cluster, itself and its process,
//! and reads it back twice, a write's timeout and a renewal apart, before
//! it forms the cluster. Every other node joins through a seed address and
//! checks that the cluster it joined is the one its bucket names. Each node
//! also names its process in `nodes/<name>.run`.
//!
//! The store gives no conditional write, so this cannot exclude two nodes
//! bootstrapping one empty bucket at once with a claim that lands late.
//! What holds is this: every node reads `cluster`, `nodes/active` and its
//! own `nodes/<name>.run` again every half lease, on a task of its own
//! beside its renewals, and a node that finds another cluster named, a
//! single node named the bucket's writer, or another process under its
//! name, gives its lease up, breaks its shards and stops for good. So two
//! clusters, a cluster and a single node, or two processes of one node,
//! write one bucket at most until the next such reading after the later
//! claim lands, half a lease and a read's time, and the bucket names at
//! most one of them after. A reading that fails, or finds an object
//! missing, fences nothing. A single node refuses to start on a bucket
//! that names a cluster.
//!
//! # A node's ID
//!
//! A node's ID derives from its name in the bucket and the nonce its Raft
//! store was made with, so that a node whose Raft state was lost joins as
//! a new node rather than vote twice under one ID.

pub mod handshake;
pub mod json;
pub mod lease;
pub mod link;
pub mod placement;
pub mod raft;
pub(crate) mod route;
pub mod wire;

use crate::PeerError;
use crate::shards::Shards;
use crate::shards::bucket::{Bucket, BucketError, BucketIo};
use crate::shards::fence::Ownership;
use crate::util::log;
use frasil_store::{BoxFuture, StoreError};
use json::Join;
use lease::{Lease, LeaseClock, Stamp, Timing};
use link::{BoxStream, Faults, LinkError, Links, Net, NodeId};
use openraft::BasicNode;
use raft::{Applied, Command, Member, Membership};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};
use wire::{ShardAnswer, ShardOp, ShardRequest};

/// The bucket's object that names the cluster the bucket belongs to.
pub const CLUSTER_OBJECT: &str = "cluster";

/// The spaces one device connection may be granted in through a gateway,
/// by default: what one device syncs at once with room to spare. A gateway
/// keeps, per space granted, the presents it would make again (32 at
/// most), the last `Subscribe` (up to 4,096 streams) and the heads it would
/// catch up from (4,096 at most): about 260 KiB at most, so some 64 MiB
/// for a connection at this bound.
pub const SPACES_PER_CONNECTION: usize = 256;

/// Why a node refuses an all-zero cluster key.
pub const ZERO_KEY: &str = "the cluster key is all zeros: draw 32 random bytes for it";

/// How long a node remembers the batches of hashed shards it made for
/// other nodes, so that one sent again is made once.
const BATCHES_KEPT: Duration = Duration::from_secs(60);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A node's settings as a member of a cluster.
#[derive(Clone)]
pub struct ClusterConfig {
    /// The cluster key every node holds: the internal links' secret. It is
    /// zeroized when dropped, and never printed.
    pub key: zeroize::Zeroizing<[u8; 32]>,
    /// Where the internal links listen.
    pub listen: SocketAddr,
    /// The address other nodes reach the internal links at.
    pub advertise: String,
    /// Addresses of nodes to join through.
    pub seeds: Vec<String>,
    /// The node's weight in placement.
    pub capacity: u32,
    /// Whether this node forms the cluster, the first time it starts.
    pub bootstrap: bool,
    /// Leases.
    pub timing: Timing,
    /// The spaces one device connection may be granted in through this
    /// node as its gateway (module `route`); a present past that is
    /// refused `busy`. [`SPACES_PER_CONNECTION`] by default.
    pub spaces_per_connection: usize,
}

// The key is compared in constant time.
impl PartialEq for ClusterConfig {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.key.ct_eq(&*other.key))
            && self.listen == other.listen
            && self.advertise == other.advertise
            && self.seeds == other.seeds
            && self.capacity == other.capacity
            && self.bootstrap == other.bootstrap
            && self.timing == other.timing
            && self.spaces_per_connection == other.spaces_per_connection
    }
}

// The drift margin is a fraction the settings check, never NaN.
impl Eq for ClusterConfig {}

impl core::fmt::Debug for ClusterConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClusterConfig")
            .field("key", &"[redacted]")
            .field("listen", &self.listen)
            .field("advertise", &self.advertise)
            .field("seeds", &self.seeds)
            .field("capacity", &self.capacity)
            .field("bootstrap", &self.bootstrap)
            .field("timing", &self.timing)
            .field("spaces_per_connection", &self.spaces_per_connection)
            .finish()
    }
}

/// Where a node's internal links listen.
pub enum Listen {
    /// A TCP listener, bound already.
    Tcp(tokio::net::TcpListener),
    /// The streams of a [`link::MemoryNet`] listener, for tests.
    Memory(tokio::sync::mpsc::UnboundedReceiver<BoxStream>),
}

impl core::fmt::Debug for Listen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Tcp(_) => "Tcp",
            Self::Memory(_) => "Memory",
        })
    }
}

/// What a node runs over besides its settings: how it reaches other
/// nodes, the faults its links apply, the clock its lease counts on, and
/// where its Raft state is kept.
pub struct Wiring {
    /// How it dials other nodes.
    pub net: Arc<dyn Net>,
    /// Where it listens.
    pub listen: Listen,
    /// Faults on its links; none outside tests.
    pub faults: Arc<Faults>,
    /// The clock leases count on.
    pub clock: Arc<dyn LeaseClock>,
    /// Its Raft log, vote and snapshot.
    pub raft: Arc<dyn frasil_store::Store>,
}

impl core::fmt::Debug for Wiring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wiring").finish_non_exhaustive()
    }
}

/// A node's ID: from its name in the bucket and its Raft store's nonce.
pub fn node_id(name: &str, nonce: &[u8; 8]) -> NodeId {
    let digest = frasil_crypto::primitives::sha256(&[
        b"frasil-relay/node/v1\0",
        name.as_bytes(),
        &[0],
        nonce,
    ]);
    u64::from_be_bytes(digest[..8].try_into().unwrap_or_default()).max(1)
}

/// The bucket's object that names the process running a node.
pub fn run_object(name: &str) -> String {
    format!("nodes/{name}.run")
}

/// A node of a cluster.
pub struct Cluster {
    me: NodeId,
    name: String,
    run: u64,
    member: Mutex<Member>,
    config: ClusterConfig,
    links: Arc<Links>,
    raft: raft::Raft,
    store: raft::Store,
    lease: Arc<Lease>,
    bucket: Arc<BucketIo>,
    handle: tokio::runtime::Handle,
    /// When this node applied each node's last renewal, by its clock.
    renewed: Arc<Mutex<HashMap<NodeId, Duration>>>,
    leader_since: Mutex<Option<Duration>>,
    changing: Arc<AtomicBool>,
    shards: OnceLock<Arc<Shards>>,
    shared: OnceLock<Weak<crate::Shared>>,
    pub(crate) gateway: route::Gateway,
    pub(crate) owners: route::Owners,
    /// The last epoch this node handled and confirmed.
    handled: AtomicU64,
    /// The last epoch at which this node's peer read again what no one
    /// shard keeps.
    reloaded: AtomicU64,
    /// The placement at that reading: a shard this node owned then is one
    /// whose state its peer knows.
    answered: Mutex<Vec<(NodeId, u32)>>,
    /// Another cluster, or another process under this node's name, took
    /// over: the node serves nothing more.
    fenced: AtomicBool,
    /// The last batch number of a hashed shard sent to another node.
    batches: AtomicU64,
    /// The batches made here for other nodes, by key, and when; for a
    /// conditional one, whether it was made.
    made: Mutex<HashMap<(u64, u64), (Instant, bool)>>,
    /// Each node's device connections, as it last told, and when.
    loads: Mutex<HashMap<NodeId, (u64, Instant)>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    stopped: AtomicBool,
    /// Whether this node asks devices to reconnect elsewhere when it holds
    /// more than its share.
    balancing: AtomicBool,
    /// Whether this process formed or joined the cluster. The renewals
    /// wait for it: a restarted node's renewal sent before its start joins
    /// would find it no member and join a second time beside that join.
    joined: AtomicBool,
}

impl core::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cluster")
            .field("me", &format_args!("{:016x}", self.me))
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

/// Takes the peers' requests and notices.
struct Handler(Weak<Cluster>);

impl link::Handler for Handler {
    fn request(&self, from: NodeId, tag: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>> {
        let cluster = self.0.upgrade();
        Box::pin(async move {
            let Some(cluster) = cluster else {
                return Vec::new();
            };
            match tag {
                wire::RAFT_APPEND | wire::RAFT_VOTE | wire::RAFT_SNAPSHOT => {
                    raft::serve(&cluster.raft, tag, &body)
                        .await
                        .unwrap_or_default()
                }
                wire::PROPOSE => cluster.serve_propose(&body).await,
                wire::JOIN => cluster.serve_join(&body).await,
                wire::SHARD => cluster.serve_shard(&body).await.encode(),
                wire::FORWARD => cluster.serve_forward(from, &body).await.encode(),
                wire::FORWARD_NEXT => cluster.serve_forward_next(&body).await.encode(),
                wire::MAILBOX => cluster.serve_mailbox(&body).await.encode(),
                wire::PIECE => cluster.serve_piece(&body).await.encode(),
                // ext-libraries.md's, while it is on.
                wire::USAGE if cluster.libraries() => cluster.serve_usage(&body).await.encode(),
                wire::MOVE_IN if cluster.libraries() => cluster.serve_move_in(&body).await.encode(),
                wire::HANDOVER if cluster.libraries() => {
                    cluster.serve_handover(&body).await.encode()
                }
                wire::SETTINGS if cluster.libraries() => {
                    cluster.serve_settings(&body).await.encode()
                }
                _ => Vec::new(),
            }
        })
    }

    fn notice(&self, from: NodeId, tag: u8, body: Vec<u8>) {
        let Some(cluster) = self.0.upgrade() else {
            return;
        };
        match tag {
            wire::DELIVER => cluster.on_deliver(&body),
            wire::CLOSED => cluster.on_closed(from, &body),
            wire::LIVE => cluster.on_live(from, &body),
            wire::MOVED if cluster.libraries() => cluster.on_moved(&body),
            wire::LOAD => {
                if let Ok(bytes) = <[u8; 8]>::try_from(body.as_slice()) {
                    lock(&cluster.loads).insert(from, (u64::from_be_bytes(bytes), Instant::now()));
                }
            }
            _ => {}
        }
    }
}

/// Resets a flag when dropped, on every path.
struct Reset(Arc<AtomicBool>);

impl Drop for Reset {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Cluster {
    /// Starts a node of a cluster: its links and Raft; the cluster formed
    /// or joined, or joined again as this process; its lease and its
    /// renewals; and the tasks that follow the membership. Returns once
    /// this node is a placed member holding its lease, and every member
    /// confirmed the epoch.
    ///
    /// # Errors
    ///
    /// If the settings do not hold, Raft does not start, the bucket names
    /// another cluster, or no seed lets the node join within a minute.
    pub async fn start(
        config: ClusterConfig,
        name: &str,
        iroh: Option<[u8; 32]>,
        bucket: Arc<BucketIo>,
        wiring: Wiring,
    ) -> Result<Arc<Self>, PeerError> {
        if handshake::is_zero(&config.key) {
            return Err(PeerError(ZERO_KEY.into()));
        }
        if let Some(why) = config.timing.check() {
            return Err(PeerError(format!("the cluster's lease timing: {why}")));
        }
        let nonce = raft::nonce(&wiring.raft).map_err(PeerError)?;
        let me = node_id(name, &nonce);
        let links = Links::new(me, &config.key, wiring.net, wiring.faults);
        links.set_silent(config.timing.silent());
        let clock = wiring.clock;
        let renewed: Arc<Mutex<HashMap<NodeId, Duration>>> = Arc::default();
        let on_apply: raft::OnApply = {
            let renewed = renewed.clone();
            let clock = clock.clone();
            let links = links.clone();
            Arc::new(move |command: &Command, _: &Membership| match command {
                Command::Renew { node, .. } => {
                    lock(&renewed).insert(*node, clock.now());
                }
                Command::Join { node, member } => {
                    lock(&renewed).insert(*node, clock.now());
                    links.know(*node, &member.address);
                }
                _ => {}
            })
        };
        let store = raft::Store::open(wiring.raft, on_apply).map_err(PeerError)?;
        let raft_config = raft::config(config.timing.renew).map_err(PeerError)?;
        let (log_store, state_machine) = openraft::storage::Adaptor::new(store.clone());
        let raft = raft::Raft::new(
            me,
            Arc::new(raft_config),
            raft::Network::new(links.clone()),
            log_store,
            state_machine,
        )
        .await
        .map_err(|e| PeerError(format!("Raft: {e}")))?;
        let run = u64::from_be_bytes(
            *frasil_crypto::random_bytes::<8>()
                .map_err(|_| PeerError("no randomness for the node's run".into()))?,
        );
        let member = Member {
            name: name.to_owned(),
            address: config.advertise.clone(),
            capacity: config.capacity,
            iroh: iroh.map(|key| crate::util::hex(&key)),
            placed: true,
            confirmed: 0,
            run,
            joined: 0,
        };
        let cluster = Arc::new(Self {
            me,
            name: name.to_owned(),
            run,
            member: Mutex::new(member),
            lease: Arc::new(Lease::new(clock, config.timing)),
            config,
            links: links.clone(),
            raft,
            store,
            bucket,
            handle: tokio::runtime::Handle::current(),
            renewed,
            leader_since: Mutex::new(None),
            changing: Arc::new(AtomicBool::new(false)),
            shards: OnceLock::new(),
            shared: OnceLock::new(),
            gateway: route::Gateway::default(),
            owners: route::Owners::default(),
            handled: AtomicU64::new(0),
            reloaded: AtomicU64::new(0),
            answered: Mutex::new(Vec::new()),
            fenced: AtomicBool::new(false),
            batches: AtomicU64::new(0),
            made: Mutex::new(HashMap::new()),
            loads: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            balancing: AtomicBool::new(true),
            joined: AtomicBool::new(false),
        });
        links.set_handler(Arc::new(Handler(Arc::downgrade(&cluster))));
        let listener = match wiring.listen {
            Listen::Tcp(listener) => links.serve_tcp(listener),
            Listen::Memory(incoming) => links.serve_memory(incoming),
        };
        lock(&cluster.tasks).push(listener);
        // A start that fails at any step leaves nothing running: a node that
        // joined leaves the placement, and its renewals, Raft and links
        // stop, so that no shard is placed on a node that never opens it.
        if let Err(error) = cluster.clone().begin().await {
            cluster.abandon().await;
            return Err(error);
        }
        Ok(cluster)
    }

    /// [`Self::start`]'s steps once the node's links listen.
    async fn begin(self: Arc<Self>) -> Result<(), PeerError> {
        // This process runs the node from now on: an older one still
        // running under its name stops at its next reading.
        self.bucket
            .bucket()
            .put(
                &run_object(&self.name),
                crate::util::hex(&self.run.to_be_bytes()).into_bytes(),
            )
            .await
            .map_err(|e| PeerError(format!("the bucket: {e}")))?;
        let restarted = self.store.initialized();
        if !restarted {
            if self.config.bootstrap {
                self.bootstrap().await?;
            } else {
                self.join_cluster(Duration::from_secs(60)).await?;
            }
        } else {
            // A node that knows its cluster checks the bucket names it
            // before it joins again.
            self.check_named().await?;
            // Known members are dialed by the addresses the log keeps.
            for (node, member) in &self.store.membership().nodes {
                self.links.know(*node, &member.address);
            }
        }
        if !restarted {
            self.joined.store(true, Ordering::SeqCst);
        }
        self.spawn_tasks();
        if restarted {
            // Placed again as this process, after a clean stop or a crash.
            self.join_cluster(Duration::from_secs(60)).await?;
            self.joined.store(true, Ordering::SeqCst);
        }
        self.wait_member(Duration::from_secs(60)).await?;
        self.check_bucket().await?;
        // Read again from now on, once this node names itself the bucket's
        // writer.
        let cluster = self.clone();
        lock(&self.tasks).push(tokio::spawn(async move { cluster.bucket_loop().await }));
        Ok(())
    }

    /// Undoes a start that failed: the node leaves the placement if it was
    /// placed as this process, gives its lease up, and stops.
    async fn abandon(&self) {
        let placed = self
            .membership()
            .nodes
            .get(&self.me)
            .is_some_and(|member| member.run == self.run && member.placed);
        if placed {
            let left = self
                .propose_within(Command::Leave { node: self.me }, self.config.timing.renew)
                .await;
            if !matches!(left, Ok(ref applied) if applied.ok) {
                log("this node did not leave the placement as its start failed");
            }
        }
        self.lease.revoke();
        self.stop().await;
    }

    /// This node.
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// This process's run, drawn at its start.
    pub fn run(&self) -> u64 {
        self.run
    }

    /// The membership as this node last applied it.
    pub fn membership(&self) -> Arc<Membership> {
        self.store.membership()
    }

    /// The membership's epoch.
    pub fn epoch(&self) -> u64 {
        self.membership().epoch
    }

    /// This node's lease.
    pub fn lease(&self) -> &Arc<Lease> {
        &self.lease
    }

    /// The links to the other nodes.
    pub fn links(&self) -> &Arc<Links> {
        &self.links
    }

    /// Sets whether this node asks some of its devices to reconnect
    /// elsewhere when it holds more than its share (module documentation,
    /// "Balance and draining"); on unless set off. It still tells the
    /// others its load. A drain closes every connection all the same.
    pub fn set_balancing(&self, on: bool) {
        self.balancing.store(on, Ordering::SeqCst);
    }

    /// The Raft node, to read its metrics.
    pub fn raft(&self) -> &raft::Raft {
        &self.raft
    }

    /// Whether another cluster, or another process under this node's name,
    /// took over, so that this node serves nothing more.
    pub fn fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst) || self.lease.fenced()
    }

    /// The node's own timeline reading, kept on its disk beside its Raft
    /// log: in a cluster, each node's timeline is its own, and the hashed
    /// shards read it (crate `shards`, "Timelines").
    pub fn kept_reading(&self) -> Option<frasil_base::time::Reading> {
        use futures_util::FutureExt;
        self.store
            .disk()
            .get(b"t")
            .now_or_never()
            .and_then(Result::ok)
            .flatten()
            .and_then(|bytes| crate::shards::format::decode_reading(&bytes))
    }

    /// Keeps the node's own timeline reading on its disk.
    pub fn keep_reading(&self, reading: &frasil_base::time::Reading) {
        use futures_util::FutureExt;
        let commit = frasil_store::Commit::new(
            vec![(
                b"t".to_vec(),
                crate::shards::format::encode_reading(reading),
            )],
            Vec::new(),
        );
        if !matches!(
            self.store.disk().commit(&commit).now_or_never(),
            Some(Ok(true))
        ) {
            log("the node's timeline reading was not kept");
        }
    }

    /// Whether this node answers for its shards now: while its lease holds
    /// by both its clocks, less the drift margin.
    pub fn serving(&self) -> bool {
        !self.fenced() && self.lease.holds_for(Duration::ZERO)
    }

    /// Whether this node's peer answers for a shard now: while it serves,
    /// for a shard it owned when it last read what no one shard keeps, or
    /// any once it read that again at this epoch.
    pub(crate) fn answering(&self, shard: &str) -> bool {
        if !self.serving() || self.owner(shard) != Some(self.me) {
            return false;
        }
        self.reloaded.load(Ordering::SeqCst) >= self.epoch()
            || placement::owner(shard, &lock(&self.answered)) == Some(self.me)
    }

    /// Whether a shard is open here, or may open now.
    pub(crate) fn openable(&self, shard: &str) -> bool {
        self.shards
            .get()
            .is_some_and(|shards| shards.is_open(shard))
            || self.may_open(shard).is_ok()
    }

    /// The owner of a shard under the membership this node applied.
    pub fn owner(&self, shard: &str) -> Option<NodeId> {
        placement::owner(shard, &self.membership().placed())
    }

    /// The owner of a space's shard, as this node knows the shard.
    pub fn owner_of_space(&self, space: &[u8; 32]) -> Option<NodeId> {
        let shard = self.shards.get().map_or_else(
            || crate::shards::space_shard(space),
            |s| s.space_shard_of(space),
        );
        self.owner(&shard)
    }

    /// The fence this node's shards write under.
    pub fn fence(&self) -> lease::LeaseFence {
        lease::LeaseFence::new(self.lease.clone())
    }

    /// The node's shards, once they are open.
    pub fn attach_shards(&self, shards: Arc<Shards>) {
        let _ = self.shards.set(shards);
    }

    /// The peer this node serves, once it is open.
    pub(crate) fn attach_peer(&self, shared: &Arc<crate::Shared>) {
        let _ = self.shared.set(Arc::downgrade(shared));
        // The peer read everything as it opened.
        *lock(&self.answered) = self.membership().placed();
        self.reloaded
            .fetch_max(self.handled.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    pub(crate) fn peer(&self) -> Option<Arc<crate::Shared>> {
        self.shared.get().and_then(Weak::upgrade)
    }

    /// Whether this node's peer has ext-libraries on.
    fn libraries(&self) -> bool {
        self.peer()
            .is_some_and(|shared| shared.settings.extensions.libraries)
    }

    pub(crate) fn shards(&self) -> Option<&Arc<Shards>> {
        self.shards.get()
    }

    /// The iroh endpoint keys of the members that serve the iroh binding,
    /// in hex: discovery's `endpoints` (transport.md, 3.15 The server
    /// binding).
    pub fn iroh_endpoints(&self) -> Vec<String> {
        self.membership()
            .nodes
            .values()
            .filter_map(|member| member.iroh.clone())
            .collect()
    }

    /// Runs work on the cluster's runtime and waits for it, blocking this
    /// thread, which must not be one of the runtime's workers.
    fn block<T: Send + Default + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        self.handle.spawn(async move {
            let _ = tx.send(work.await);
        });
        rx.recv().unwrap_or_default()
    }

    // -- Forming and joining

    async fn bootstrap(&self) -> Result<(), PeerError> {
        let bucket = self.bucket.bucket();
        let failed = |e: BucketError| PeerError(format!("the bucket: {e}"));
        if let Some(named) = bucket.get(CLUSTER_OBJECT).await.map_err(failed)? {
            return Err(PeerError(format!(
                "the bucket names cluster {} already: start this node without the \
                 bootstrap setting, with a seed, to join it",
                claimed(&named)
            )));
        }
        let id = crate::util::hex(
            &*frasil_crypto::random_bytes::<16>()
                .map_err(|_| PeerError("no randomness for the cluster's ID".into()))?,
        );
        let claim = format!(
            "{id} {} {}",
            self.name,
            crate::util::hex(&self.run.to_be_bytes())
        )
        .into_bytes();
        bucket
            .put(CLUSTER_OBJECT, claim.clone())
            .await
            .map_err(failed)?;
        // Read back twice, a write's timeout and a renewal apart: another
        // claim sent at about the same time lands meanwhile.
        let settle = self.config.timing.put_timeout * 2 + self.config.timing.renew;
        for _ in 0..2 {
            tokio::time::sleep(settle).await;
            let back = bucket.get(CLUSTER_OBJECT).await.map_err(failed)?;
            if back.as_deref() != Some(claim.as_slice()) {
                return Err(PeerError(
                    "another node formed a cluster on this bucket at the same time".into(),
                ));
            }
        }
        let mut nodes = BTreeMap::new();
        nodes.insert(
            self.me,
            BasicNode {
                addr: self.config.advertise.clone(),
            },
        );
        self.raft
            .initialize(nodes)
            .await
            .map_err(|e| PeerError(format!("Raft: {e}")))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self
                .commit_here(Command::Init {
                    cluster: id.clone(),
                })
                .await
            {
                Ok(applied) if applied.ok => break,
                Ok(_) => return Err(PeerError("the cluster was named already".into())),
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(PeerError(format!("Raft: {error}"))),
            }
        }
        let member = lock(&self.member).clone();
        self.commit_here(Command::Join {
            node: self.me,
            member,
        })
        .await
        .map_err(|e| PeerError(format!("Raft: {e}")))?;
        log(format_args!("formed cluster {id}"));
        Ok(())
    }

    /// Joins as this process: through the leader, here if this node leads,
    /// or through a seed or a member it knows. A join of the same process,
    /// placed already, changes nothing.
    async fn join_cluster(&self, within: Duration) -> Result<(), PeerError> {
        let deadline = Instant::now() + within;
        let join = Join {
            node: self.me,
            member: lock(&self.member).clone(),
        };
        let request = serde_json::to_vec(&join).map_err(|e| PeerError(e.to_string()))?;
        let mut last = String::from("no seed");
        loop {
            match self.raft.current_leader().await {
                // A node that takes itself for the leader may lead no one, as
                // one removed while cut off: its own commit is bounded, and
                // then the seeds are asked.
                Some(leader) if leader == self.me => {
                    match tokio::time::timeout(
                        self.config.timing.renew * 4,
                        self.join_here(join.clone()),
                    )
                    .await
                    {
                        Ok(Ok(_)) => return Ok(()),
                        Ok(Err(why)) => last = why,
                        Err(_) => last = "this node leads no majority".into(),
                    }
                }
                Some(leader) => {
                    match self
                        .links
                        .call(leader, wire::JOIN, request.clone(), Duration::from_secs(5))
                        .await
                    {
                        Ok(answer) => {
                            match serde_json::from_slice::<Result<String, String>>(&answer) {
                                Ok(Ok(_)) => return Ok(()),
                                Ok(Err(why)) => last = why,
                                Err(e) => last = e.to_string(),
                            }
                        }
                        Err(error) => last = error.to_string(),
                    }
                }
                None => {}
            }
            let mut targets: Vec<String> = self.config.seeds.clone();
            targets.extend(
                self.membership()
                    .nodes
                    .iter()
                    .filter(|(id, _)| **id != self.me)
                    .map(|(_, m)| m.address.clone()),
            );
            for seed in targets {
                let peer = match self.links.dial(&seed).await {
                    Ok(peer) => peer,
                    Err(error) => {
                        last = error.to_string();
                        continue;
                    }
                };
                match self
                    .links
                    .call(peer, wire::JOIN, request.clone(), Duration::from_secs(10))
                    .await
                {
                    Ok(answer) => match serde_json::from_slice::<Result<String, String>>(&answer) {
                        Ok(Ok(cluster)) => {
                            log(format_args!("joined cluster {cluster} through {seed}"));
                            return Ok(());
                        }
                        Ok(Err(why)) => last = why,
                        Err(e) => last = e.to_string(),
                    },
                    Err(error) => last = error.to_string(),
                }
            }
            if Instant::now() >= deadline {
                return Err(PeerError(format!("this node did not join: {last}")));
            }
            tokio::time::sleep(self.config.timing.renew).await;
        }
    }

    /// Waits until this process is a placed member holding its lease, and
    /// every member confirmed the epoch.
    async fn wait_member(&self, within: Duration) -> Result<(), PeerError> {
        let deadline = Instant::now() + within;
        loop {
            let state = self.membership();
            let placed = state
                .nodes
                .get(&self.me)
                .is_some_and(|member| member.placed && member.run == self.run);
            let held = self.lease.holds_for(Duration::ZERO);
            let handled = self.handled.load(Ordering::SeqCst) >= state.epoch;
            if placed && held && handled && state.settled() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let unconfirmed: Vec<String> = state
                    .nodes
                    .iter()
                    .filter(|(_, member)| member.confirmed < state.epoch)
                    .map(|(node, _)| format!("{node:016x}"))
                    .collect();
                return Err(PeerError(format!(
                    "this node did not become a member holding a lease: placed {placed}, \
                     lease held {held}, epoch {} handled {handled}, members yet to confirm \
                     it {unconfirmed:?}",
                    state.epoch
                )));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Checks that the bucket names the cluster this node is a member of.
    async fn check_named(&self) -> Result<(), PeerError> {
        let cluster = self.membership().cluster.clone();
        let named = self
            .bucket
            .bucket()
            .get(CLUSTER_OBJECT)
            .await
            .map_err(|e| PeerError(format!("the bucket: {e}")))?;
        if named.as_deref().map(claimed).as_deref() != Some(cluster.as_str()) {
            return Err(PeerError(format!(
                "this node is a member of cluster {cluster}, and the bucket names {}",
                named.map_or_else(|| "none".into(), |n| claimed(&n))
            )));
        }
        Ok(())
    }

    /// This node's record in `nodes/active`: a cluster node's name there
    /// starts with [`active_prefix`].
    fn active(&self) -> crate::shards::format::Active {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.run.to_be_bytes());
        nonce[8..].copy_from_slice(&self.me.to_be_bytes());
        crate::shards::format::Active {
            epoch: 0,
            node: format!("{}{}", active_prefix(&self.membership().cluster), self.name),
            nonce,
        }
    }

    /// Checks that the bucket names the cluster this node is a member of,
    /// and names this process in `nodes/active`, so that a single node
    /// still running on the bucket stops writing (crate `shards`, module
    /// `fence`).
    async fn check_bucket(&self) -> Result<(), PeerError> {
        self.check_named().await?;
        self.bucket
            .bucket()
            .put(crate::shards::fence::ACTIVE, self.active().encode())
            .await
            .map_err(|e| PeerError(format!("the bucket: {e}")))
    }

    /// Reads `cluster`, `nodes/active` and this node's run object again
    /// every half lease, off the renewal path: another cluster named, a
    /// single node named as the bucket's writer, or another process under
    /// this node's name fences this node for good. A read that fails, or
    /// finds no object, fences nothing.
    async fn bucket_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.timing.held() / 2);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut absent = false;
        loop {
            interval.tick().await;
            if self.stopped.load(Ordering::SeqCst) || self.fenced() {
                return;
            }
            if let Some(why) = self.read_bucket(&mut absent).await {
                self.stop_for_good(why).await;
                return;
            }
        }
    }

    /// One reading of [`Self::bucket_loop`]: why the node is fenced, if it
    /// is. `absent` notes that a missing object was logged already.
    async fn read_bucket(&self, absent: &mut bool) -> Option<&'static str> {
        let bucket = self.bucket.bucket();
        let cluster = self.membership().cluster.clone();
        if cluster.is_empty() {
            return None;
        }
        let mut missing = Vec::new();
        match bucket.get(CLUSTER_OBJECT).await {
            Ok(Some(named)) if claimed(&named) != cluster => {
                return Some("the bucket names another cluster");
            }
            Ok(None) => missing.push(CLUSTER_OBJECT),
            _ => {}
        }
        match bucket.get(crate::shards::fence::ACTIVE).await {
            Ok(Some(bytes)) => {
                if crate::shards::format::Active::decode(&bytes)
                    .is_none_or(|active| !active.node.starts_with(&active_prefix(&cluster)))
                {
                    return Some("a single node writes this bucket now");
                }
            }
            Ok(None) => missing.push(crate::shards::fence::ACTIVE),
            Err(_) => {}
        }
        let ours = crate::util::hex(&self.run.to_be_bytes());
        match bucket.get(&run_object(&self.name)).await {
            Ok(Some(run)) if run != ours.as_bytes() => {
                return Some("another process runs this node now");
            }
            Ok(None) => missing.push("this node's run object"),
            _ => {}
        }
        if !missing.is_empty() && !*absent {
            log(format_args!(
                "the bucket holds no {}: this node keeps serving",
                missing.join(", ")
            ));
        }
        *absent = !missing.is_empty();
        None
    }

    /// Stops this node for good: its lease given up, its shards broken, its
    /// renewals and Raft stopped.
    async fn stop_for_good(&self, why: &str) {
        if self.fenced.swap(true, Ordering::SeqCst) {
            return;
        }
        log(format_args!("{why}: this node serves nothing more"));
        // For good: a renewal under way when this ran grants nothing after
        // it (module `lease`, "Fencing for good").
        self.lease.fence();
        self.break_all().await;
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.raft.shutdown().await;
    }

    /// Breaks every shard this node holds open, writing nothing, and takes
    /// their spaces out of memory.
    async fn break_all(&self) {
        let Some(shards) = self.shards.get().cloned() else {
            return;
        };
        let names = shards.open_names();
        let broken = shards.clone();
        let _ = tokio::task::spawn_blocking(move || {
            broken.barrier();
            for name in broken.open_names() {
                broken.discard(&name);
            }
        })
        .await;
        if let Some(shared) = self.peer() {
            shared.core.unload_shards(&names).await;
        }
    }

    // -- Proposals

    /// Commits a command through the leader: here, or by asking it, waiting
    /// a lease at most.
    ///
    /// # Errors
    ///
    /// If no leader commits it.
    pub async fn propose(&self, command: Command) -> Result<Applied, String> {
        self.propose_within(command, self.config.timing.lease).await
    }

    async fn propose_within(&self, command: Command, wait: Duration) -> Result<Applied, String> {
        let leader = self.raft.current_leader().await;
        let Some(leader) = leader.filter(|leader| *leader != self.me) else {
            return tokio::time::timeout(wait, self.commit_here(command))
                .await
                .unwrap_or_else(|_| Err("the commit timed out".into()));
        };
        let body = serde_json::to_vec(&command).map_err(|e| e.to_string())?;
        let answer = self
            .links
            .call(leader, wire::PROPOSE, body, wait)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice::<Result<Applied, String>>(&answer).map_err(|e| e.to_string())?
    }

    async fn commit_here(&self, command: Command) -> Result<Applied, String> {
        self.raft
            .client_write(command)
            .await
            .map(|response| response.data)
            .map_err(|e| e.to_string())
    }

    async fn serve_propose(&self, body: &[u8]) -> Vec<u8> {
        let answer: Result<Applied, String> = match serde_json::from_slice::<Command>(body) {
            Ok(command) => {
                tokio::time::timeout(self.config.timing.lease, self.commit_here(command))
                    .await
                    .unwrap_or_else(|_| Err("the commit timed out".into()))
            }
            Err(e) => Err(e.to_string()),
        };
        serde_json::to_vec(&answer).unwrap_or_default()
    }

    /// The leader's side of a join: the node a learner of Raft, then a
    /// member. The cluster's ID.
    async fn join_here(&self, join: Join) -> Result<String, String> {
        self.links.know(join.node, &join.member.address);
        let (mut known, voters) = {
            let metrics = self.raft.metrics().borrow().clone();
            let config = metrics.membership_config.membership();
            let known = config.nodes().any(|(id, _)| *id == join.node);
            let voters: BTreeSet<NodeId> = config.voter_ids().collect();
            (known, voters)
        };
        // A node that comes back after it was removed may still be a node of
        // Raft, with the replication progress of its earlier run: a learner
        // is taken out and added again, so that Raft learns its log afresh.
        // A voter's vote is withdrawn by the leader's duties, which change
        // the voters only to nodes that renew (`keep_voters`): the join
        // waits for it.
        if known && !self.membership().nodes.contains_key(&join.node) {
            if voters.contains(&join.node) {
                return Err("the node's earlier run is not out of Raft yet".into());
            }
            let bound = self.config.timing.lease * 2;
            let mut gone = BTreeSet::new();
            gone.insert(join.node);
            let removed = tokio::time::timeout(
                bound,
                self.raft
                    .change_membership(openraft::ChangeMembers::RemoveNodes(gone), true),
            )
            .await;
            if !matches!(removed, Ok(Ok(_))) {
                return Err("the node's earlier run is not out of Raft yet".into());
            }
            known = false;
        }
        if !known {
            self.raft
                .add_learner(
                    join.node,
                    BasicNode {
                        addr: join.member.address.clone(),
                    },
                    false,
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        self.commit_here(Command::Join {
            node: join.node,
            member: join.member,
        })
        .await?;
        Ok(self.membership().cluster.clone())
    }

    async fn serve_join(&self, body: &[u8]) -> Vec<u8> {
        let answer: Result<String, String> = async {
            let join: Join = serde_json::from_slice(body).map_err(|e| e.to_string())?;
            let leader = self.raft.current_leader().await;
            if leader != Some(self.me) {
                let Some(leader) = leader else {
                    return Err("no leader yet".to_owned());
                };
                let answer = self
                    .links
                    .call(leader, wire::JOIN, body.to_vec(), Duration::from_secs(10))
                    .await
                    .map_err(|e| e.to_string())?;
                return serde_json::from_slice::<Result<String, String>>(&answer)
                    .map_err(|e| e.to_string())?;
            }
            self.join_here(join).await
        }
        .await;
        serde_json::to_vec(&answer).unwrap_or_default()
    }

    // -- The tasks that follow the membership

    fn spawn_tasks(self: &Arc<Self>) {
        let mut tasks = lock(&self.tasks);
        let cluster = self.clone();
        tasks.push(tokio::spawn(async move { cluster.renew_loop().await }));
        let cluster = self.clone();
        tasks.push(tokio::spawn(async move { cluster.leader_loop().await }));
        let cluster = self.clone();
        tasks.push(tokio::spawn(async move { cluster.epoch_loop().await }));
        let cluster = self.clone();
        tasks.push(tokio::spawn(async move { cluster.live_loop().await }));
        let cluster = self.clone();
        tasks.push(tokio::spawn(async move { cluster.balance_loop().await }));
    }

    /// Renews the lease every [`Timing::renew`], each attempt waiting a
    /// renewal at most, once this process formed or joined the cluster. A
    /// node whose wall clock ran ahead of its monotonic clock, as after a
    /// pause or a step of the wall clock, gives its lease up first, and
    /// takes it again with the next renewal; one that is no member, or not
    /// as this process, gives its lease up, breaks its shards and joins
    /// again; and
    /// one whose renewals all failed for as long as the leader waits
    /// before it removes a node, as one cut off that may have been removed
    /// without hearing it, asks to join again through the others.
    async fn renew_loop(self: Arc<Self>) {
        let timing = self.config.timing;
        let mut interval = tokio::time::interval(timing.renew);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last: Option<Stamp> = None;
        let mut renewed = Instant::now();
        loop {
            interval.tick().await;
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            if !self.joined.load(Ordering::SeqCst) {
                renewed = Instant::now();
                continue;
            }
            if let Some(before) = last
                && self.lease.stalled_since(before)
            {
                // A step of the wall clock on a healthy node looks the same
                // as a pause, so the shards stay open: a node removed
                // meanwhile learns it from this renewal and breaks them
                // then, and its lease already ended by the wall clock.
                log("the wall clock ran ahead: this node gives its lease up");
                self.lease.revoke();
            }
            // The bucket's readings run on their own task (`bucket_loop`),
            // so a slow bucket never delays a renewal.
            if self.fenced() {
                return;
            }
            let sent = self.lease.stamp();
            let renewal = self
                .propose_within(
                    Command::Renew {
                        node: self.me,
                        run: self.run,
                    },
                    timing.renew,
                )
                .await;
            // Fenced while the renewal was under way: it holds nothing, and
            // the lease refuses it too (module `lease`, "Fencing for good").
            if self.fenced() {
                return;
            }
            match renewal {
                Ok(applied) if applied.ok => {
                    self.lease.set_epoch(applied.epoch);
                    self.lease.set_joined(applied.joined);
                    self.lease.grant(sent);
                    renewed = Instant::now();
                    self.confirm_again().await;
                }
                Ok(_) => {
                    log("this node is no member of the cluster as this process: it joins again");
                    self.lease.revoke();
                    self.break_all().await;
                    if let Err(error) = self.join_cluster(timing.lease).await {
                        log(format_args!("{error}"));
                    }
                }
                Err(_) if renewed.elapsed() >= timing.ended_after() => {
                    self.lease.revoke();
                    self.break_all().await;
                    if self.join_cluster(timing.lease).await.is_ok() {
                        renewed = Instant::now();
                    }
                }
                Err(_) => {}
            }
            // The next check for a pause counts from here, once this
            // attempt's waits are over: its margin is the drift of one
            // renewal's interval.
            last = Some(self.lease.stamp());
        }
    }

    /// Confirms again the epoch this node handled while the membership it
    /// applied shows it unconfirmed: a confirmation that found no leader
    /// for as long as [`Self::handle_epoch`] tries would otherwise keep the
    /// epoch from settling, and every shard's first open waiting, until the
    /// next epoch. A renewal just committed, so a leader is known.
    async fn confirm_again(&self) {
        let state = self.membership();
        let unconfirmed = state
            .nodes
            .get(&self.me)
            .is_some_and(|member| member.run == self.run && member.confirmed < state.epoch);
        if unconfirmed && self.handled.load(Ordering::SeqCst) >= state.epoch {
            let _ = self
                .propose_within(
                    Command::Confirm {
                        node: self.me,
                        epoch: state.epoch,
                    },
                    self.config.timing.renew,
                )
                .await;
        }
    }

    /// The leader's duties: removing nodes whose leases ended, and keeping
    /// three or five voters among the members.
    async fn leader_loop(self: Arc<Self>) {
        let timing = self.config.timing;
        let mut interval = tokio::time::interval(timing.renew);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            let metrics = self.raft.metrics().borrow().clone();
            if metrics.current_leader != Some(self.me)
                || metrics.state != openraft::ServerState::Leader
            {
                *lock(&self.leader_since) = None;
                continue;
            }
            let now = self.lease.clock().now();
            let since = *lock(&self.leader_since).get_or_insert(now);
            let state = self.membership();
            let ended: Vec<NodeId> = {
                let renewed = lock(&self.renewed);
                state
                    .nodes
                    .keys()
                    .filter(|&&node| node != self.me)
                    .filter(|node| {
                        let last = renewed.get(node).copied().unwrap_or(since).max(since);
                        now.saturating_sub(last) >= timing.ended_after()
                    })
                    .copied()
                    .collect()
            };
            for node in ended {
                log(format_args!(
                    "node {node:016x}'s lease has ended: it leaves the cluster"
                ));
                let removed =
                    tokio::time::timeout(timing.lease, self.commit_here(Command::Remove { node }))
                        .await;
                if let Ok(Err(error)) = removed {
                    log(format_args!("node {node:016x} was not removed: {error}"));
                }
            }
            self.keep_voters(&metrics);
        }
    }

    /// Makes three or five members voters, keeping those that vote, and
    /// every member a node of Raft; drops from Raft the nodes that are no
    /// members. One change at a time, each bounded by a few leases.
    ///
    /// Raft commits a change of voters under both the old voters and the
    /// new, with no check that the new can reach a majority. So the new
    /// voters are only nodes this one saw renew within the time after which
    /// a lease is taken as ended, as many as the members call for, and no
    /// change is made unless a majority of the old voters renewed so: no
    /// change waits on a node that is gone, which would stop every renewal
    /// until it came back.
    fn keep_voters(self: &Arc<Self>, metrics: &openraft::RaftMetrics<NodeId, BasicNode>) {
        if self.changing.load(Ordering::SeqCst) {
            return;
        }
        let state = self.membership();
        let config = metrics.membership_config.membership();
        let voters: BTreeSet<NodeId> = config.voter_ids().collect();
        let known: BTreeSet<NodeId> = config.nodes().map(|(id, _)| *id).collect();
        let fresh: BTreeSet<NodeId> = {
            let now = self.lease.clock().now();
            let ended = self.config.timing.ended_after();
            let renewed = lock(&self.renewed);
            known
                .iter()
                .chain(state.nodes.keys())
                .filter(|&&id| {
                    id == self.me
                        || renewed
                            .get(&id)
                            .is_some_and(|at| now.saturating_sub(*at) < ended)
                })
                .copied()
                .collect()
        };
        let target = match state.nodes.len() {
            0..=2 => 1,
            3 | 4 => 3,
            _ => 5,
        };
        let members: Vec<NodeId> = state
            .nodes
            .keys()
            .filter(|id| fresh.contains(id))
            .copied()
            .collect();
        let mut desired: Vec<NodeId> = members
            .iter()
            .filter(|id| voters.contains(id))
            .copied()
            .collect();
        for id in &members {
            if desired.len() >= target {
                break;
            }
            if !desired.contains(id) {
                desired.push(*id);
            }
        }
        desired.truncate(target);
        if !desired.contains(&self.me) && desired.len() == target && target > 0 {
            // The leader stays a voter while it leads.
            desired.pop();
            desired.push(self.me);
        }
        let desired: BTreeSet<NodeId> = desired.into_iter().collect();
        let voters_change = desired != voters
            && desired.len() == target
            && voters.iter().filter(|id| fresh.contains(id)).count() > voters.len() / 2;
        let learners: Vec<(NodeId, String)> = state
            .nodes
            .iter()
            .filter(|(id, _)| !known.contains(id))
            .map(|(id, m)| (*id, m.address.clone()))
            .collect();
        // A voter leaves Raft once its vote is withdrawn.
        let gone: BTreeSet<NodeId> = known
            .iter()
            .filter(|id| !state.nodes.contains_key(id) && !desired.contains(id))
            .filter(|id| voters_change || !voters.contains(id))
            .copied()
            .collect();
        if learners.is_empty() && !voters_change && gone.is_empty() {
            return;
        }
        self.changing.store(true, Ordering::SeqCst);
        let cluster = self.clone();
        let reset = Reset(self.changing.clone());
        let bound = self.config.timing.lease * 4;
        tokio::spawn(async move {
            let _reset = reset;
            for (id, addr) in learners {
                let added = tokio::time::timeout(
                    bound,
                    cluster.raft.add_learner(id, BasicNode { addr }, false),
                )
                .await;
                if !matches!(added, Ok(Ok(_))) {
                    log(format_args!("node {id:016x} did not become a learner"));
                }
            }
            if voters_change {
                let changed =
                    tokio::time::timeout(bound, cluster.raft.change_membership(desired, true))
                        .await;
                if !matches!(changed, Ok(Ok(_))) {
                    log("the voters did not change");
                }
            }
            if !gone.is_empty() {
                let removed = tokio::time::timeout(
                    bound,
                    cluster
                        .raft
                        .change_membership(openraft::ChangeMembers::RemoveNodes(gone), true),
                )
                .await;
                if !matches!(removed, Ok(Ok(_))) {
                    log("Raft kept nodes that left");
                }
            }
        });
    }

    /// Follows the membership: at each new epoch, gives up the shards this
    /// node no longer owns, breaks those it opened before its latest join,
    /// confirms the epoch, reads again what no one shard keeps, and moves
    /// its connections' spaces to their new owners.
    async fn epoch_loop(self: Arc<Self>) {
        let mut watch = self.store.watch();
        loop {
            let state = watch.borrow_and_update().clone();
            for (node, member) in &state.nodes {
                self.links.know(*node, &member.address);
            }
            self.lease.set_epoch(state.epoch);
            if state.epoch > self.handled.load(Ordering::SeqCst) {
                self.handle_epoch(&state).await;
            }
            if self.stopped.load(Ordering::SeqCst) || watch.changed().await.is_err() {
                return;
            }
        }
    }

    async fn handle_epoch(self: &Arc<Self>, state: &Membership) {
        let epoch = state.epoch;
        let member = state
            .nodes
            .get(&self.me)
            .filter(|member| member.run == self.run);
        let Some(member) = member else {
            // No member as this process: nothing it holds open is its own.
            self.break_all().await;
            self.handled.fetch_max(epoch, Ordering::SeqCst);
            return;
        };
        self.lease.set_joined(member.joined);
        let placed = state.placed();
        if let Some(shards) = self.shards.get().cloned() {
            let me = self.me;
            let lease = self.lease.clone();
            let classify = shards.clone();
            let mine = placed.clone();
            // Every open under way ends first, so that what it opened is
            // counted here.
            let sorted = tokio::task::spawn_blocking(move || {
                classify.barrier();
                let mut lost = Vec::new();
                let mut stale = Vec::new();
                for (name, opened) in classify.open_epochs() {
                    if opened.is_some_and(|opened| !lease.current(opened)) {
                        stale.push(name);
                    } else if placement::owner(&name, &mine) != Some(me) {
                        lost.push(name);
                    }
                }
                (lost, stale)
            })
            .await;
            let (lost, stale) = sorted.unwrap_or_default();
            if !lost.is_empty() || !stale.is_empty() {
                for name in &stale {
                    shards.discard(name);
                }
                if let Some(shared) = self.peer() {
                    let gone: Vec<String> = lost.iter().chain(&stale).cloned().collect();
                    shared.core.unload_shards(&gone).await;
                }
                self.owners.forget_lost(self);
                let released = shards.clone();
                let done = tokio::task::spawn_blocking(move || {
                    for name in lost {
                        if let Err(error) = released.release(&name) {
                            log(format_args!("{name} was given up uncleanly: {error}"));
                        }
                    }
                })
                .await;
                if done.is_err() {
                    log("a shard's release did not finish");
                }
            }
        }
        // Confirmed once given up; retried while the epoch stands, and
        // after with each renewal (`confirm_again`).
        let deadline = Instant::now() + self.config.timing.lease;
        while Instant::now() < deadline && self.epoch() == epoch {
            let confirmed = self
                .propose_within(
                    Command::Confirm {
                        node: self.me,
                        epoch,
                    },
                    self.config.timing.renew,
                )
                .await;
            if confirmed.is_ok() {
                break;
            }
            tokio::time::sleep(self.config.timing.renew / 4).await;
        }
        self.handled.fetch_max(epoch, Ordering::SeqCst);
        // Once every node gave up what it lost: what no one shard keeps read
        // again, the hashed shards this node gained opened, and the
        // gateways' spaces at their new owners.
        let cluster = self.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + cluster.config.timing.ended_after() * 4;
            while !cluster.membership().settled() && Instant::now() < deadline {
                if cluster.epoch() != epoch {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if cluster.epoch() != epoch {
                return;
            }
            if let Some(shared) = cluster.peer() {
                let core = shared.clone();
                let reloaded = tokio::task::spawn_blocking(move || core.core.reload_shared()).await;
                if let Ok(Err(error)) = reloaded {
                    log(format_args!("the shared state was not read again: {error}"));
                }
            }
            *lock(&cluster.answered) = placed;
            cluster.reloaded.fetch_max(epoch, Ordering::SeqCst);
            if let Some(shards) = cluster.shards.get().cloned() {
                let _ = tokio::task::spawn_blocking(move || shards.open_kept()).await;
            }
            // ext-deposit-tokens.md: the keeper of the keys' shard begins
            // the first key as it takes the shard up.
            if let Some(shared) = cluster.peer() {
                let now = shared.clock.now();
                let _ =
                    tokio::task::spawn_blocking(move || shared.core.begin_deposit_keys(now)).await;
            }
            cluster.gateway_reroute().await;
        });
    }

    /// Every lease: tells every member this node's device connections,
    /// and asks some to reconnect elsewhere when it holds more than its
    /// share (module documentation, "Balance and draining").
    async fn balance_loop(self: Arc<Self>) {
        let lease = self.config.timing.lease;
        let mut interval = tokio::time::interval(lease);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let Some(shared) = self.peer() else {
                continue;
            };
            let mine = shared.core.connections() as u64;
            let state = self.membership();
            for node in state.nodes.keys().filter(|node| **node != self.me) {
                let _ = self
                    .links
                    .notify(*node, wire::LOAD, mine.to_be_bytes().to_vec())
                    .await;
            }
            if !self.balancing.load(Ordering::SeqCst)
                || !state
                    .nodes
                    .get(&self.me)
                    .is_some_and(|member| member.placed)
            {
                continue;
            }
            let loads: Vec<u64> = {
                let loads = lock(&self.loads);
                state
                    .placed()
                    .iter()
                    .filter(|(node, _)| *node != self.me)
                    .filter_map(|(node, _)| loads.get(node))
                    .filter(|(_, at)| at.elapsed() < lease * 3)
                    .map(|(count, _)| *count)
                    .chain([mine])
                    .collect()
            };
            let count = excess(mine, &loads);
            for _ in 0..count {
                let shared = shared.clone();
                let wait = lease.mul_f64(jitter());
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    shared.core.reconnect_some(1);
                });
            }
        }
    }

    /// Hands this node's shards over for a planned stop: it leaves the
    /// placement, gives up its shards with a last manifest each, and
    /// confirms; the others open them at once. It still forwards for its
    /// devices meanwhile. Returns once this node handled the epoch its
    /// leave made and every member confirmed it, or after a lease.
    pub async fn hand_over(&self) {
        let deadline = Instant::now() + self.config.timing.lease;
        // The epoch the leave made, as the leader applied it: this node's
        // own view may not have reached it yet.
        let epoch = loop {
            match self
                .propose_within(Command::Leave { node: self.me }, self.config.timing.renew)
                .await
            {
                Ok(applied) if applied.ok => break Some(applied.epoch),
                Ok(_) => break None,
                Err(error) if Instant::now() >= deadline => {
                    log(format_args!(
                        "this node did not leave the cluster cleanly: {error}"
                    ));
                    break None;
                }
                Err(_) => tokio::time::sleep(self.config.timing.renew / 4).await,
            }
        };
        let Some(epoch) = epoch else {
            return;
        };
        while Instant::now() < deadline {
            let state = self.membership();
            if self.handled.load(Ordering::SeqCst) >= epoch
                && state.epoch >= epoch
                && state.settled()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        log("this node's shards were not all handed over within a lease");
    }

    /// Leaves the cluster: [`Self::hand_over`], then stops renewing. Its
    /// lease ends.
    pub async fn leave(&self) {
        self.hand_over().await;
        self.stop().await;
        self.lease.revoke();
    }

    /// Stops the node's tasks, Raft and links, as a crash does for the other
    /// nodes: its lease ends on its own.
    pub async fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
        let _ = self.raft.shutdown().await;
        self.links.close_all();
    }

    // -- The hashed shards other nodes keep

    /// Waits, blocking, for this node's view to reach `epoch`.
    fn wait_epoch(&self, epoch: u64, deadline: Instant) {
        while self.epoch() < epoch && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A read or a batch of a hashed shard, at its owner. A read tries
    /// again for five seconds at most; a batch is sent twice at most, under
    /// one key, which its owner makes once.
    ///
    /// The key is remembered only by the node that made the batch. An
    /// owner that answers "not mine" made nothing, so the batch goes to the
    /// next owner as it is. One whose answer was lost may have made it: the
    /// batch goes again only to that same node, which then answers from
    /// its memory, and is otherwise not known to be made. Sent to another
    /// owner, a plain batch made twice could overwrite a write made between
    /// the two, and a conditional one would be checked again against what
    /// its own first making left, and answer unmet.
    fn shard_call(&self, shard: &str, op: ShardOp) -> Result<ShardAnswer, StoreError> {
        let commit = matches!(op, ShardOp::Commit { .. } | ShardOp::CommitIf { .. });
        let wait = if commit {
            self.config.timing.put_timeout * 2 + Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        };
        let deadline = Instant::now()
            + if commit {
                wait * 2
            } else {
                Duration::from_secs(5)
            };
        let mut attempts = 0;
        // The node a batch went to whose answer was lost.
        let mut unanswered: Option<NodeId> = None;
        loop {
            attempts += 1;
            let last = Instant::now() >= deadline || (commit && attempts >= 2);
            let epoch = self.epoch();
            let Some(owner) = self.owner(shard) else {
                return Err(StoreError::new(format!("{shard}: no node owns it")));
            };
            if unanswered.is_some_and(|sent| sent != owner) {
                return Err(StoreError::new(format!(
                    "{shard}: the batch is not known to be made"
                )));
            }
            if owner == self.me {
                if self.shards.get().is_none() && !last {
                    // This node's own shards are still opening.
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                return self.local_shard(shard, op);
            }
            let body = ShardRequest {
                epoch,
                shard: shard.to_owned(),
                op: op.clone(),
            }
            .encode();
            let links = self.links.clone();
            let answer: Option<Result<Vec<u8>, (LinkError, bool)>> = self
                .block(async move { Some(links.call_sent(owner, wire::SHARD, body, wait).await) });
            let Some(answer) = answer else {
                return Err(StoreError::new("the cluster's runtime stopped"));
            };
            match answer {
                Ok(bytes) => match ShardAnswer::decode(&bytes) {
                    Some(ShardAnswer::NotMine(theirs)) if !last => {
                        if theirs > epoch {
                            self.wait_epoch(theirs, deadline.min(Instant::now() + wait));
                        } else {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                    Some(ShardAnswer::Failed(why)) if !commit && !last => {
                        log(format_args!("{shard}: {why}"));
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Some(ShardAnswer::NotMine(_)) => {
                        return Err(StoreError::new(format!("{shard}: no owner answered")));
                    }
                    Some(ShardAnswer::Failed(why)) => return Err(StoreError::new(why)),
                    Some(answer) => return Ok(answer),
                    None => {
                        return Err(StoreError::new(format!(
                            "{shard}: an answer that does not read"
                        )));
                    }
                },
                Err((error, _)) if error.is_too_large() => {
                    return Err(StoreError::new(format!("{shard}: {error}")));
                }
                Err((_, sent)) if !last => {
                    if commit && sent {
                        unanswered = Some(owner);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err((error, _)) => return Err(StoreError::new(format!("{shard}: {error}"))),
            }
        }
    }

    fn local_shard(&self, shard: &str, op: ShardOp) -> Result<ShardAnswer, StoreError> {
        let shards = self
            .shards
            .get()
            .ok_or_else(|| StoreError::new("the shards are not open yet"))?;
        Ok(match op {
            ShardOp::Get(address) => ShardAnswer::Found(shards.local_get(shard, &address)?),
            ShardOp::Scan(prefix) => ShardAnswer::Records(shards.local_scan(shard, &prefix)?),
            ShardOp::Commit { key, changes } => {
                if lock(&self.made).contains_key(&key) {
                    return Ok(ShardAnswer::Done);
                }
                shards.apply_remote(shard, changes)?;
                self.made_batch(key, true);
                ShardAnswer::Done
            }
            ShardOp::CommitIf {
                key,
                expect,
                changes,
            } => {
                let held = lock(&self.made).get(&key).map(|(_, held)| *held);
                let held = match held {
                    Some(held) => held,
                    None => {
                        let held = shards.apply_remote_if(shard, &expect, changes)?;
                        self.made_batch(key, held);
                        held
                    }
                };
                if held {
                    ShardAnswer::Done
                } else {
                    ShardAnswer::Unmet
                }
            }
        })
    }

    /// Remembers a batch made for another node, and whether it was made.
    fn made_batch(&self, key: (u64, u64), held: bool) {
        let mut made = lock(&self.made);
        made.retain(|_, (at, _)| at.elapsed() < BATCHES_KEPT);
        made.insert(key, (Instant::now(), held));
    }

    async fn serve_shard(self: &Arc<Self>, body: &[u8]) -> ShardAnswer {
        let Some(request) = ShardRequest::decode(body) else {
            return ShardAnswer::Failed("a request that does not read".into());
        };
        let epoch = self.epoch();
        if self.owner(&request.shard) != Some(self.me)
            || !self.serving()
            || self.shards.get().is_none()
            || !self.openable(&request.shard)
        {
            return ShardAnswer::NotMine(epoch);
        }
        let cluster = self.clone();
        tokio::task::spawn_blocking(move || {
            cluster
                .local_shard(&request.shard, request.op)
                .unwrap_or_else(|e| ShardAnswer::Failed(e.to_string()))
        })
        .await
        .unwrap_or_else(|e| ShardAnswer::Failed(e.to_string()))
    }
}

/// How many of a node's `mine` connections to move this lease, given every
/// placed node's count, `mine` among them: none unless it holds more than
/// the average by a tenth and at least one; then at most its excess, and at
/// most a hundredth of its connections, at least one.
pub fn excess(mine: u64, loads: &[u64]) -> u64 {
    if loads.is_empty() {
        return 0;
    }
    let average = loads.iter().sum::<u64>() / loads.len() as u64;
    if mine <= average + (average / 10).max(1) {
        return 0;
    }
    (mine - average).min((mine / 100).max(1))
}

/// A random fraction in [0, 1).
fn jitter() -> f64 {
    frasil_crypto::random_bytes::<8>()
        .map(|bytes| (u64::from_be_bytes(*bytes) >> 11) as f64 / (1u64 << 53) as f64)
        .unwrap_or(0.5)
}

/// How a cluster node's name in `nodes/active` starts: a name without it
/// is a single node's.
fn active_prefix(cluster: &str) -> String {
    format!("cluster-{cluster}-")
}

/// The cluster's ID a `cluster` object's claim names: its first word.
fn claimed(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

impl Ownership for Cluster {
    fn owns(&self, shard: &str) -> bool {
        self.owner(shard) == Some(self.me)
    }

    /// At once, never waiting: a caller that may not open the shard yet
    /// answers `busy`, and is asked again.
    fn may_open(&self, shard: &str) -> Result<(), StoreError> {
        if !self.owns(shard) {
            return Err(StoreError::new(format!("{shard}: not this node's shard")));
        }
        let state = self.membership();
        if state.settled()
            && self.handled.load(Ordering::SeqCst) >= state.epoch
            && !self.fenced()
            && self.lease.holds_for(self.config.timing.put_timeout)
        {
            Ok(())
        } else {
            Err(StoreError::new(format!(
                "{shard}: the nodes that kept it have not given it up yet"
            )))
        }
    }

    fn get(&self, shard: &str, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        match self.shard_call(shard, ShardOp::Get(address.to_vec()))? {
            ShardAnswer::Found(found) => Ok(found),
            _ => Err(StoreError::new(format!(
                "{shard}: an answer of another kind"
            ))),
        }
    }

    fn scan(&self, shard: &str, prefix: &[u8]) -> Result<frasil_store::store::Records, StoreError> {
        match self.shard_call(shard, ShardOp::Scan(prefix.to_vec()))? {
            ShardAnswer::Records(records) => Ok(records),
            _ => Err(StoreError::new(format!(
                "{shard}: an answer of another kind"
            ))),
        }
    }

    fn commit(
        &self,
        shard: &str,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StoreError> {
        let key = (self.run, self.batches.fetch_add(1, Ordering::SeqCst) + 1);
        match self.shard_call(shard, ShardOp::Commit { key, changes })? {
            ShardAnswer::Done => Ok(()),
            _ => Err(StoreError::new(format!(
                "{shard}: an answer of another kind"
            ))),
        }
    }

    fn commit_if(
        &self,
        shard: &str,
        expect: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<bool, StoreError> {
        let key = (self.run, self.batches.fetch_add(1, Ordering::SeqCst) + 1);
        let op = ShardOp::CommitIf {
            key,
            expect,
            changes,
        };
        match self.shard_call(shard, op)? {
            ShardAnswer::Done => Ok(true),
            ShardAnswer::Unmet => Ok(false),
            _ => Err(StoreError::new(format!(
                "{shard}: an answer of another kind"
            ))),
        }
    }
}

/// A bucket whose every request fails once it takes longer than its
/// timeout: a write that times out counts as failed, and a node issues
/// one only while its lease outlasts the timeout (module `lease`).
pub struct TimedBucket {
    inner: Arc<dyn Bucket>,
    put: Duration,
}

impl core::fmt::Debug for TimedBucket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TimedBucket")
            .field("put", &self.put)
            .finish_non_exhaustive()
    }
}

impl TimedBucket {
    /// `inner`, with writes timed out after `put`, and reads after twice
    /// that.
    pub fn new(inner: Arc<dyn Bucket>, put: Duration) -> Self {
        Self { inner, put }
    }
}

fn timed_out() -> BucketError {
    BucketError("the request timed out".into())
}

impl Bucket for TimedBucket {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            tokio::time::timeout(self.put, self.inner.put(key, bytes))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BucketError>> {
        Box::pin(async move {
            tokio::time::timeout(self.put * 2, self.inner.get(key))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, BucketError>> {
        Box::pin(async move {
            tokio::time::timeout(self.put * 2, self.inner.list(prefix))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            tokio::time::timeout(self.put * 2, self.inner.delete(key))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }

    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<(), BucketError>> {
        // A snapshot's upload is named by its manifest only once the
        // manifest is written, under the lease; it is bounded all the same,
        // so that no task waits on it for ever.
        Box::pin(async move {
            tokio::time::timeout(self.put * 30, self.inner.put_file(key, path))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }

    fn get_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<bool, BucketError>> {
        // A snapshot's download streams to the working copy's file, so a
        // large shard is never held whole in memory; bounded like its upload.
        Box::pin(async move {
            tokio::time::timeout(self.put * 30, self.inner.get_file(key, path))
                .await
                .unwrap_or_else(|_| Err(timed_out()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node refuses an all-zero cluster key before it starts anything.
    #[tokio::test]
    async fn an_all_zero_cluster_key_is_refused() {
        let net = Arc::new(link::MemoryNet::new());
        let bucket: Arc<dyn Bucket> = Arc::new(crate::shards::bucket::MemoryBucket::new());
        let io = Arc::new(BucketIo::new(bucket).expect("a bucket"));
        let config = ClusterConfig {
            key: zeroize::Zeroizing::new([0; 32]),
            listen: "127.0.0.1:0".parse().expect("an address"),
            advertise: "zero".into(),
            seeds: Vec::new(),
            capacity: 100,
            bootstrap: true,
            timing: Timing::DEFAULT,
            spaces_per_connection: SPACES_PER_CONNECTION,
        };
        let wiring = Wiring {
            net: net.clone(),
            listen: Listen::Memory(net.listen("zero")),
            faults: Arc::new(Faults::default()),
            clock: Arc::new(lease::SystemLeaseClock::default()),
            raft: Arc::new(frasil_store::MemoryStore::new()),
        };
        let refused = Cluster::start(config.clone(), "zero", None, io, wiring)
            .await
            .expect_err("an all-zero key is no secret");
        assert_eq!(refused.0, ZERO_KEY);
        assert!(
            !format!("{config:?}").contains("[0, 0"),
            "the key is never printed"
        );
    }
}
