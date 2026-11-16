//! The internal links: one connection between each pair of a region's
//! nodes, authenticated and encrypted under the cluster key, carrying
//! requests, their responses and notices in both directions (module `wire`).
//!
//! # The handshake
//!
//! Each end draws an X25519 key pair and 16 random bytes for the
//! connection:
//!
//! ```text
//! dialer   -> listener: "frasilc1" || e_d || n_d || u64 id_d
//! listener -> dialer:   e_l || n_l || u64 id_l || HMAC(psk, "listener" || th)
//! dialer   -> listener: HMAC(psk, "dialer" || th)
//!
//! psk = HKDF(salt "frasil-relay/cluster/v1", the cluster key, "link key")
//! th  = SHA-256 of every byte above before the first HMAC
//! prk = HKDF-Extract(psk, X25519(e, e_other))
//! keys: HKDF-Expand(prk, "dialer to listener" || th) and
//!       HKDF-Expand(prk, "listener to dialer" || th)
//! ```
//!
//! Only a holder of the cluster key computes either HMAC, so each end knows
//! the other holds it, and the ephemeral keys bind the connection's keys to
//! this connection alone: a recorded connection opens with no later
//! knowledge of the key. Each frame then is `u32 length || u64 counter ||
//! XChaCha20-Poly1305(key, counter, frame)`, counters from 1 in each
//! direction and checked in order. No plaintext mode exists. Module
//! `handshake` reads, writes and checks the three messages: each MAC is
//! compared in constant time, and the pre-shared key and the connection's
//! keys are zeroized when dropped. An all-zero cluster key is refused at
//! start-up.
//!
//! The node ID a handshake names is the dialer's or the listener's own
//! claim: the cluster key is the only credential, so any holder of it may
//! connect as any node.
//!
//! # Handshakes
//!
//! Inbound and outbound handshakes have budgets of their own, so that hosts
//! that connect to the cluster port never keep this node from dialing its
//! peers: at most [`HANDSHAKES_IN`] inbound at once, of which at most
//! [`HANDSHAKES_PER_SOURCE`] from one address, and [`HANDSHAKES_OUT`]
//! outbound, where more dialers wait. A refused or failed inbound
//! handshake is logged at most once every [`REFUSALS_LOGGED`], with the
//! count of those left out. Until its dialer's MAC checks, a stream holds
//! only the handshake's fixed buffers and its task.
//!
//! # One connection per pair
//!
//! A node dials a peer it has no live connection to. When a second
//! connection completes beside a live one, the one the lower node dialed
//! stays.
//!
//! # Two shares of a connection
//!
//! Each frame belongs to the cluster's own traffic or to its clients'
//! ([`Class`], by its tag). The cluster's own is Raft, proposals (the
//! lease renewals among them), joins, the hashed shards' reads and
//! commits, and the notices that follow the membership; the clients' is
//! what devices cause: forwarded messages and their deliveries, mailboxes,
//! object pieces, and the libraries' requests. Each share has a queue of
//! its own, and the writer sends the cluster's first, so that no amount of
//! client traffic delays a heartbeat or a renewal behind it by more than
//! the frame being written. The requests a node answers at once have
//! budgets of their own too: Raft, proposals and joins; shard reads and
//! commits; and the clients'.
//!
//! A full cluster queue means the connection is stuck: it is closed, and
//! dialed again. A full client queue never closes it: a request or a
//! notice waits for room, which slows the device whose message it carries,
//! and fails alone, as busy, if none comes in time ([`LinkError::Busy`]);
//! an answer waits as a piece of a large answer does, and is dropped if no
//! room comes, its asker timing out.
//!
//! # A dead connection
//!
//! A call that times out closes its connection, so that the next call
//! dials again, when nothing was received on the connection since its
//! request was queued, nor for the links' silence ([`Links::set_silent`],
//! twice a renewal in a cluster), and either its request was written or
//! the writer finished no frame for that long either. What is received
//! counts as it arrives, 64 KiB at a time, not once a frame is whole: a
//! connection busy carrying a large answer, which the writer makes
//! progress on, stays, however long the frame takes to cross.
//!
//! A node's connection to the leader carries a heartbeat at least every
//! quarter of a renewal, and its renewals, one every renewal, each waiting
//! a renewal at most. Say that connection goes dead at `t`:
//!
//! - The last renewal granted before `t` was sent after `t − 2 ×
//!   renewal`: the one sent a renewal before that was answered before `t`.
//! - A renewal sent at or after `t + silence − renewal` times out once the
//!   silence has passed and closes the connection: by `t + silence +
//!   renewal`.
//! - The next renewal goes at most a renewal later, on a new connection,
//!   and is answered within its own wait: by `t + silence + 3 × renewal`.
//!
//! So a renewal is granted again at most `silence + 5 × renewal`, seven
//! renewals, after the last one granted was sent, and module `lease`
//! refuses a timing whose lease, less its drift margin, does not outlast
//! that (`Timing::check`). With the default timing that is three and a half
//! seconds against the four a lease holds. A leader that is gone for good
//! is replaced by an election instead, which the same check counts.
//!
//! # Bounds
//!
//! Each share of a connection queues at most 4,096 frames and 32 MiB to
//! send. A node keeps at most 1,024 connections, and answers at most
//! [`IN_FLIGHT_RAFT`] Raft requests, proposals and joins, [`IN_FLIGHT_SHARD`]
//! shard requests and [`IN_FLIGHT`] client requests of one peer at once; a
//! request past its budget is answered as unknown, and its asker tries
//! again.
//!
//! # Large answers
//!
//! A request or a notice larger than a frame ([`MAX_FRAME`]) is refused
//! before it is sent, as an error of that call alone. An answer larger than
//! a piece goes in pieces of 1 MiB (module `wire`, [`PART`]), so that no
//! frame of an answer takes long to seal or to cross, each queued
//! only once its share's queue holds less than another piece, so that the
//! other frames pass between them; the asker puts the pieces together, and waits
//! for each piece as long as for an answer. An answer larger than
//! [`MAX_ANSWER`] is answered as too large. Neither closes the connection.
//!
//! # Faults
//!
//! [`Faults`], shared by the nodes of a test, drops, delays and partitions
//! frames before they are sealed, and refuses dials across a partition.

use super::handshake::{self, Hello, Keys, Reply};
use super::wire::{
    CLOSED, Frame, JOIN, LIVE, LOAD, MAX_FRAME, MOVED, NOTICE, PART, PARTS, PROPOSE, Part,
    RAFT_APPEND, RAFT_SNAPSHOT, RAFT_VOTE, REQUEST, RESPONSE, SHARD, TOO_LARGE, UNKNOWN,
    parts_length,
};
use frasil_crypto::primitives::{xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_store::BoxFuture;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// A node of the cluster.
pub type NodeId = u64;

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
/// The frames each share of a connection queues to send.
const QUEUE: usize = 4096;
/// The bytes of the frames the cluster's share of a connection queues to
/// send, at most: four frames of the largest size. A connection whose
/// cluster queue is full is stuck, and is closed and dialed again.
pub const CLUSTER_QUEUE_BYTES: usize = 32 << 20;
/// The bytes of the frames the clients' share of a connection queues to
/// send, at most. A frame that finds it full waits for room, and fails
/// alone if none comes; the connection stays.
pub const CLIENT_QUEUE_BYTES: usize = 32 << 20;
/// How long a client notice, such as a delivery to a gateway's device,
/// waits at most for room in its queue before it fails as busy.
pub const ROOM_WAIT: Duration = Duration::from_secs(2);
/// How long a connection has received nothing, at least, before a call
/// that times out closes it, until [`Links::set_silent`] sets it.
const SILENT: Duration = Duration::from_secs(1);
/// The inbound handshakes a node runs at once; a stream past that is
/// closed at once.
pub const HANDSHAKES_IN: usize = 32;
/// The inbound handshakes a node runs at once from one address.
pub const HANDSHAKES_PER_SOURCE: usize = 4;
/// The outbound handshakes a node runs at once; more dialers wait.
pub const HANDSHAKES_OUT: usize = 32;
/// How often, at most, a refused or failed inbound handshake is logged.
pub const REFUSALS_LOGGED: Duration = Duration::from_secs(10);
/// The connections a node keeps, one per peer.
const CONNECTIONS: usize = 1024;
/// The client requests of one peer a node answers at once; more are
/// answered as unknown, and the asker tries again.
pub const IN_FLIGHT: usize = 256;
/// The Raft requests, proposals and joins of one peer a node answers at
/// once: openraft keeps a few in flight to each peer, and every renewal is
/// one proposal.
pub const IN_FLIGHT_RAFT: usize = 64;
/// The shard reads and commits of one peer a node answers at once: each is
/// made by a thread of the asker's blocking pool.
pub const IN_FLIGHT_SHARD: usize = 256;
/// The bytes of a piece of a larger answer: small, so that the frames
/// queued behind one wait little, and a piece is sealed and crosses well
/// within the links' silence even on a slow machine.
const PART_BYTES: usize = 1 << 20;
/// The largest answer a link carries, in pieces; a larger one is answered
/// as too large. The asker holds an answer whole as its pieces arrive, so
/// this bounds what one call holds. An owner answers a forwarded message
/// in parts of at most `PART_BYTES` (module `route`, 8 MiB) past their
/// first message, which is at most units.md's message limit, and a
/// gateway asks for one part of a device connection's answer at a time:
/// this holds a part rounded up to whole pieces of 1 MiB, with room for
/// its framing, and is the most a device connection's forwarded answer
/// holds at its gateway. The crate's own tests use more, to carry the
/// large answers of their own.
pub const MAX_ANSWER: usize = if cfg!(test) { 24 << 20 } else { 16 << 20 };
/// How long a piece of an answer waits, at most, for room in the queue.
const PART_WAIT: Duration = Duration::from_secs(30);
/// What a frame adds to its body.
const FRAME_BYTES: usize = 10;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A byte stream a link runs over.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for T {}

/// A boxed [`Stream`].
pub type BoxStream = Box<dyn Stream>;

/// How a node reaches another's address.
pub trait Net: Send + Sync + 'static {
    /// Opens a stream to `address`.
    fn dial<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<BoxStream>>;
}

/// TCP.
#[derive(Debug, Default)]
pub struct TcpNet;

impl Net for TcpNet {
    fn dial<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream =
                tokio::time::timeout(HANDSHAKE_DEADLINE, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dial timed out"))??;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// Streams within one process, by address: the links of a test's nodes.
#[derive(Default)]
pub struct MemoryNet {
    listeners: Mutex<HashMap<String, mpsc::UnboundedSender<BoxStream>>>,
}

impl core::fmt::Debug for MemoryNet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryNet").finish_non_exhaustive()
    }
}

impl MemoryNet {
    /// A network with no listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Listens on `address`: the streams dialed to it.
    pub fn listen(&self, address: &str) -> mpsc::UnboundedReceiver<BoxStream> {
        let (tx, rx) = mpsc::unbounded_channel();
        lock(&self.listeners).insert(address.to_owned(), tx);
        rx
    }

    /// Stops listening on `address`.
    pub fn close(&self, address: &str) {
        lock(&self.listeners).remove(address);
    }
}

impl Net for MemoryNet {
    fn dial<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let listener = lock(&self.listeners).get(address).cloned();
            let Some(listener) = listener else {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "no listener",
                ));
            };
            let (near, far) = tokio::io::duplex(1 << 20);
            listener
                .send(Box::new(far))
                .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "no listener"))?;
            Ok(Box::new(near) as BoxStream)
        })
    }
}

/// Faults on the links: partitions between nodes, a delay of every frame,
/// and frames dropped at random, from a seed.
#[derive(Debug)]
pub struct Faults {
    blocked: Mutex<BTreeSet<(NodeId, NodeId)>>,
    delay: Mutex<Duration>,
    drop_per_mille: AtomicU64,
    seed: AtomicU64,
}

impl Default for Faults {
    fn default() -> Self {
        Self::new(1)
    }
}

impl Faults {
    /// No fault, drops drawn from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            blocked: Mutex::new(BTreeSet::new()),
            delay: Mutex::new(Duration::ZERO),
            drop_per_mille: AtomicU64::new(0),
            seed: AtomicU64::new(seed.max(1)),
        }
    }

    /// Cuts `a` and `b` apart, both ways.
    pub fn partition(&self, a: NodeId, b: NodeId) {
        let mut blocked = lock(&self.blocked);
        blocked.insert((a, b));
        blocked.insert((b, a));
    }

    /// Cuts `node` from every node in `others`.
    pub fn isolate(&self, node: NodeId, others: &[NodeId]) {
        for &other in others {
            if other != node {
                self.partition(node, other);
            }
        }
    }

    /// Ends every partition of `node`.
    pub fn reconnect(&self, node: NodeId) {
        lock(&self.blocked).retain(|(a, b)| *a != node && *b != node);
    }

    /// Ends every partition.
    pub fn heal(&self) {
        lock(&self.blocked).clear();
    }

    /// Delays every frame by `delay`.
    pub fn set_delay(&self, delay: Duration) {
        *lock(&self.delay) = delay;
    }

    /// Drops this many frames in a thousand.
    pub fn set_drops(&self, per_mille: u64) {
        self.drop_per_mille
            .store(per_mille.min(1000), Ordering::Relaxed);
    }

    /// Whether `from` reaches `to` now.
    pub fn reaches(&self, from: NodeId, to: NodeId) -> bool {
        !lock(&self.blocked).contains(&(from, to))
    }

    /// What happens to a frame from `from` to `to`: dropped (`None`), or
    /// sent after a delay.
    fn frame(&self, from: NodeId, to: NodeId) -> Option<Duration> {
        if !self.reaches(from, to) {
            return None;
        }
        let drops = self.drop_per_mille.load(Ordering::Relaxed);
        if drops > 0 {
            // xorshift64*, from the seed.
            let mut x = self.seed.load(Ordering::Relaxed);
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.seed.store(x, Ordering::Relaxed);
            if x.wrapping_mul(0x2545_f491_4f6c_dd1d) % 1000 < drops {
                return None;
            }
        }
        Some(*lock(&self.delay))
    }
}

/// Which share of a connection a frame goes in, by its tag (module
/// documentation, "Two shares of a connection").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The cluster's own traffic, sent first.
    Cluster,
    /// What devices cause.
    Client,
}

impl Class {
    /// The share a request, its answer or a notice of this tag goes in.
    pub fn of(tag: u8) -> Self {
        match tag {
            RAFT_APPEND | RAFT_VOTE | RAFT_SNAPSHOT | PROPOSE | JOIN | SHARD | CLOSED | LIVE
            | LOAD | MOVED => Self::Cluster,
            _ => Self::Client,
        }
    }
}

/// What a node does with what its peers send.
pub trait Handler: Send + Sync + 'static {
    /// A request; its answer's body.
    fn request(&self, from: NodeId, tag: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>>;
    /// A notice, taken in the order it arrived; it must not wait.
    fn notice(&self, from: NodeId, tag: u8, body: Vec<u8>);
}

/// A link failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// A request or a notice larger than a frame, refused before it was
    /// sent; or an answer larger than [`MAX_ANSWER`]. Sending it again does
    /// not change that.
    TooLarge,
    /// The clients' share of the connection stayed full for as long as the
    /// call or the notice could wait: it alone failed, and the connection
    /// stays. Sending it again later may succeed.
    Busy,
    /// Any other failure: the peer was not reached, did not answer in
    /// time, or the connection closed.
    Failed(String),
}

impl LinkError {
    /// [`Self::TooLarge`].
    pub fn too_large() -> Self {
        Self::TooLarge
    }

    /// [`Self::Failed`], with why.
    pub fn failed(why: impl Into<String>) -> Self {
        Self::Failed(why.into())
    }

    /// Whether the call failed for its size, which sending it again does
    /// not change.
    pub fn is_too_large(&self) -> bool {
        matches!(self, Self::TooLarge)
    }
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("larger than the link carries"),
            Self::Busy => f.write_str("the link's queue for clients is full"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for LinkError {}

fn nonce(counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// A frame queued to send, with the flag the writer raises once it wrote
/// it (or dropped it as a fault), for a call that waits on its request.
struct Item {
    bytes: Vec<u8>,
    class: Class,
    written: Option<Arc<AtomicBool>>,
}

/// One share of a connection's queue, bounded by [`QUEUE`] frames and its
/// bytes.
#[derive(Clone)]
struct Lane {
    tx: mpsc::Sender<Item>,
    /// The bytes queued, which the writer takes off as it sends.
    bytes: Arc<AtomicUsize>,
    limit: usize,
}

/// Why a frame was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unqueued {
    /// Its share's queue is full.
    Full,
    /// The connection closed.
    Closed,
}

/// A connection's queue of frames to send: the cluster's share and the
/// clients' (module documentation, "Two shares of a connection").
#[derive(Clone)]
struct Outbox {
    cluster: Lane,
    client: Lane,
    /// Told each time the writer takes a frame off.
    room: Arc<tokio::sync::Notify>,
    /// When the writer last finished with a frame: wrote it, or dropped it.
    wrote: Arc<Mutex<Instant>>,
}

impl Outbox {
    fn new() -> (Self, Queued) {
        let (cluster_tx, cluster_rx) = mpsc::channel(QUEUE);
        let (client_tx, client_rx) = mpsc::channel(QUEUE);
        let cluster = Lane {
            tx: cluster_tx,
            bytes: Arc::new(AtomicUsize::new(0)),
            limit: CLUSTER_QUEUE_BYTES,
        };
        let client = Lane {
            tx: client_tx,
            bytes: Arc::new(AtomicUsize::new(0)),
            limit: CLIENT_QUEUE_BYTES,
        };
        let room = Arc::new(tokio::sync::Notify::new());
        let wrote = Arc::new(Mutex::new(Instant::now()));
        (
            Self {
                cluster: cluster.clone(),
                client: client.clone(),
                room: room.clone(),
                wrote: wrote.clone(),
            },
            Queued {
                cluster_rx,
                client_rx,
                cluster: cluster.bytes,
                client: client.bytes,
                room,
                wrote,
            },
        )
    }

    fn lane(&self, class: Class) -> &Lane {
        match class {
            Class::Cluster => &self.cluster,
            Class::Client => &self.client,
        }
    }

    /// Queues an item in its share, at once, or gives it back with why
    /// not.
    fn offer(&self, item: Item) -> Result<(), (Unqueued, Item)> {
        let lane = self.lane(item.class);
        let length = item.bytes.len();
        let before = lane.bytes.fetch_add(length, Ordering::SeqCst);
        if before + length > lane.limit {
            lane.bytes.fetch_sub(length, Ordering::SeqCst);
            let why = if lane.tx.is_closed() {
                Unqueued::Closed
            } else {
                Unqueued::Full
            };
            return Err((why, item));
        }
        lane.tx.try_send(item).map_err(|error| {
            lane.bytes.fetch_sub(length, Ordering::SeqCst);
            match error {
                mpsc::error::TrySendError::Full(item) => (Unqueued::Full, item),
                mpsc::error::TrySendError::Closed(item) => (Unqueued::Closed, item),
            }
        })
    }

    /// Queues a frame in its share, at once.
    fn push(
        &self,
        class: Class,
        frame: Vec<u8>,
        written: Option<Arc<AtomicBool>>,
    ) -> Result<(), Unqueued> {
        self.offer(Item {
            bytes: frame,
            class,
            written,
        })
        .map_err(|(why, _)| why)
    }

    /// Queues a frame in its share once the share holds no more than
    /// `under` bytes with it, waiting until `deadline` at most.
    ///
    /// The wait holds no lock: it is woken as the writer takes a frame off
    /// (`room`, whose `notified` is taken before each check, so that a
    /// frame taken off between the check and the wait still wakes it), and
    /// every 100 ms to see the connection closed. Cancelled, it queued
    /// nothing.
    async fn push_within(
        &self,
        class: Class,
        frame: Vec<u8>,
        written: Option<Arc<AtomicBool>>,
        under: usize,
        deadline: Instant,
    ) -> Result<(), Unqueued> {
        let lane = self.lane(class);
        let mut item = Item {
            bytes: frame,
            class,
            written,
        };
        loop {
            let room = self.room.notified();
            if lane.bytes.load(Ordering::SeqCst) + item.bytes.len() <= under {
                match self.offer(item) {
                    Ok(()) => return Ok(()),
                    Err((Unqueued::Closed, _)) => return Err(Unqueued::Closed),
                    Err((Unqueued::Full, back)) => item = back,
                }
            }
            if lane.tx.is_closed() {
                return Err(Unqueued::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Unqueued::Full);
            }
            let _ =
                tokio::time::timeout((deadline - now).min(Duration::from_millis(100)), room).await;
        }
    }

    /// Queues a piece of a large answer once its share holds less than
    /// another piece, waiting [`PART_WAIT`] at most, so that other frames
    /// pass between the pieces.
    async fn push_paced(&self, class: Class, frame: Vec<u8>) -> Result<(), Unqueued> {
        let deadline = Instant::now() + PART_WAIT;
        self.push_within(class, frame, None, 2 * PART_BYTES + 64, deadline)
            .await
    }

    /// Whether the writer finished no frame for `silent`.
    fn stalled(&self, silent: Duration) -> bool {
        lock(&self.wrote).elapsed() >= silent
    }
}

/// The writer's end of an [`Outbox`].
struct Queued {
    cluster_rx: mpsc::Receiver<Item>,
    client_rx: mpsc::Receiver<Item>,
    cluster: Arc<AtomicUsize>,
    client: Arc<AtomicUsize>,
    room: Arc<tokio::sync::Notify>,
    wrote: Arc<Mutex<Instant>>,
}

impl Queued {
    /// The next frame to send, the cluster's first, taken off its share's
    /// bytes.
    async fn next(&mut self) -> Option<Item> {
        // `biased`: the cluster's queue is polled first each time, so that
        // no client frame goes while a cluster frame waits. A closed queue
        // yields none and leaves its branch for this pass; both closed end
        // the writer.
        let item = tokio::select! {
            biased;
            Some(item) = self.cluster_rx.recv() => item,
            Some(item) = self.client_rx.recv() => item,
            else => return None,
        };
        let bytes = match item.class {
            Class::Cluster => &self.cluster,
            Class::Client => &self.client,
        };
        bytes.fetch_sub(item.bytes.len(), Ordering::SeqCst);
        self.room.notify_waiters();
        Some(item)
    }

    /// The writer finished with a frame: sent it, or dropped it.
    fn finished(&self, item: &Item) {
        *lock(&self.wrote) = Instant::now();
        if let Some(written) = &item.written {
            written.store(true, Ordering::SeqCst);
        }
    }
}

/// A request sent, waiting for its answer.
struct Pending {
    tx: oneshot::Sender<Result<Frame, LinkError>>,
    /// The pieces of a large answer received so far, in order.
    parts: Vec<u8>,
    /// When the last piece arrived.
    heard: Option<Instant>,
}

/// One live connection.
struct Conn {
    peer: NodeId,
    dialer: NodeId,
    tx: Outbox,
    pending: Mutex<HashMap<u64, Pending>>,
    /// The peer's Raft requests, proposals and joins being answered.
    raft: Arc<tokio::sync::Semaphore>,
    /// The peer's shard requests being answered.
    shard: Arc<tokio::sync::Semaphore>,
    /// The peer's client requests being answered.
    client: Arc<tokio::sync::Semaphore>,
    next: AtomicU64,
    alive: AtomicBool,
    /// When bytes last arrived from the peer: a frame whole, or a step of
    /// one still arriving.
    received: Mutex<Instant>,
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl Conn {
    /// The budget a request of this tag is answered under.
    fn budget(&self, tag: u8) -> &Arc<tokio::sync::Semaphore> {
        match tag {
            RAFT_APPEND | RAFT_VOTE | RAFT_SNAPSHOT | PROPOSE | JOIN => &self.raft,
            SHARD => &self.shard,
            _ => &self.client,
        }
    }

    fn close(&self) {
        self.alive.store(false, Ordering::SeqCst);
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
        lock(&self.pending).clear();
    }
}

/// The inbound handshakes under way from each address.
type Sources = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// One address's place among the inbound handshakes under way, given back
/// when dropped.
struct SourceSlot {
    sources: Sources,
    source: IpAddr,
}

impl SourceSlot {
    /// A place for `source`, unless it holds [`HANDSHAKES_PER_SOURCE`]
    /// already.
    fn take(sources: &Sources, source: IpAddr) -> Option<Self> {
        let mut held = lock(sources);
        let count = held.entry(source).or_insert(0);
        if *count >= HANDSHAKES_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(Self {
            sources: sources.clone(),
            source,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut held = lock(&self.sources);
        if let Some(count) = held.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

/// When a refused or failed inbound handshake was last logged, and how
/// many were not logged since.
#[derive(Debug, Default)]
struct Refusals {
    logged: Option<Instant>,
    unlogged: u64,
}

/// A node's links to its peers.
pub struct Links {
    me: NodeId,
    psk: Zeroizing<[u8; 32]>,
    net: Arc<dyn Net>,
    faults: Arc<Faults>,
    handler: OnceLock<Arc<dyn Handler>>,
    conns: Mutex<HashMap<NodeId, Arc<Conn>>>,
    dialing: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    addresses: Mutex<HashMap<NodeId, String>>,
    /// The inbound handshakes' budget.
    inbound: Arc<tokio::sync::Semaphore>,
    /// The inbound handshakes under way, by address.
    sources: Sources,
    /// The outbound handshakes' budget.
    outbound: Arc<tokio::sync::Semaphore>,
    refusals: Mutex<Refusals>,
    /// How long a connection has received nothing, at least, before a call
    /// that times out closes it (module documentation, "A dead
    /// connection").
    silent: Mutex<Duration>,
    /// The connections started, dialed or accepted.
    started: AtomicU64,
    /// The connections closed because a frame received did not read.
    unread: AtomicU64,
    myself: Weak<Links>,
}

impl core::fmt::Debug for Links {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Links")
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl Links {
    /// The links of node `me` under the cluster key, over `net`.
    pub fn new(
        me: NodeId,
        cluster_key: &[u8; 32],
        net: Arc<dyn Net>,
        faults: Arc<Faults>,
    ) -> Arc<Self> {
        let psk = handshake::psk(cluster_key);
        Arc::new_cyclic(|myself| Self {
            me,
            psk,
            net,
            faults,
            handler: OnceLock::new(),
            conns: Mutex::new(HashMap::new()),
            dialing: Mutex::new(HashMap::new()),
            addresses: Mutex::new(HashMap::new()),
            inbound: Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_IN)),
            sources: Arc::default(),
            outbound: Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_OUT)),
            refusals: Mutex::default(),
            silent: Mutex::new(SILENT),
            started: AtomicU64::new(0),
            unread: AtomicU64::new(0),
            myself: myself.clone(),
        })
    }

    /// This node.
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// How many connections this node started, dialed or accepted: one
    /// per peer, and one more each time a connection closed and was made
    /// again.
    pub fn started(&self) -> u64 {
        self.started.load(Ordering::SeqCst)
    }

    /// How many connections this node closed because a frame it received
    /// did not read: a length out of bounds, a counter out of order, a
    /// frame that does not open or does not decode. A connection lost to
    /// silence or to its stream's end is not counted.
    pub fn unread(&self) -> u64 {
        self.unread.load(Ordering::SeqCst)
    }

    /// Sets how long a connection has received nothing, at least, before
    /// a call that times out closes it: twice a renewal in a cluster
    /// (module `lease`, `Timing::silent`).
    pub fn set_silent(&self, silent: Duration) {
        *lock(&self.silent) = silent;
    }

    /// The faults the links apply.
    pub fn faults(&self) -> &Arc<Faults> {
        &self.faults
    }

    /// Sets what takes the peers' requests and notices.
    pub fn set_handler(&self, handler: Arc<dyn Handler>) {
        let _ = self.handler.set(handler);
    }

    /// Notes where a peer listens.
    pub fn know(&self, node: NodeId, address: &str) {
        if node != self.me {
            lock(&self.addresses).insert(node, address.to_owned());
        }
    }

    /// Closes every connection.
    pub fn close_all(&self) {
        let conns: Vec<Arc<Conn>> = lock(&self.conns).drain().map(|(_, c)| c).collect();
        for conn in conns {
            conn.close();
        }
    }

    /// Logs a refused or failed inbound handshake, at most once every
    /// [`REFUSALS_LOGGED`]: whoever reaches the cluster port may cause
    /// them.
    fn refused(&self, why: core::fmt::Arguments<'_>) {
        let unlogged = {
            let mut refusals = lock(&self.refusals);
            if refusals
                .logged
                .is_some_and(|logged| logged.elapsed() < REFUSALS_LOGGED)
            {
                refusals.unlogged += 1;
                return;
            }
            refusals.logged = Some(Instant::now());
            std::mem::take(&mut refusals.unlogged)
        };
        if unlogged == 0 {
            crate::util::log(format_args!("a cluster link: {why}"));
        } else {
            crate::util::log(format_args!(
                "a cluster link: {why}; {unlogged} more refused or failed since the last such line"
            ));
        }
    }

    /// Takes a stream a peer dialed from `source`: the handshake as
    /// listener, then the connection. A stream past the inbound budget, or
    /// past its address's share of it, is closed at once. A stream with no
    /// address, as a [`MemoryNet`]'s, counts toward the budget alone.
    pub fn accept(&self, stream: BoxStream, source: Option<IpAddr>) {
        let Some(links) = self.myself.upgrade() else {
            return;
        };
        let slot = match source {
            Some(source) => match SourceSlot::take(&links.sources, source) {
                Some(slot) => Some(slot),
                None => {
                    links.refused(format_args!(
                        "refused: too many handshakes at once from {source}"
                    ));
                    return;
                }
            },
            None => None,
        };
        let Ok(permit) = links.inbound.clone().try_acquire_owned() else {
            links.refused(format_args!("refused: too many handshakes at once"));
            return;
        };
        if lock(&links.conns).len() >= CONNECTIONS {
            links.refused(format_args!("refused: too many connections"));
            return;
        }
        tokio::spawn(async move {
            // Both are held until the handshake ends, as it does within
            // its deadline: a stream that sends nothing holds them that
            // long at most.
            let _permit = permit;
            let _slot = slot;
            match tokio::time::timeout(HANDSHAKE_DEADLINE, links.clone().listen_handshake(stream))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => links.refused(format_args!("{error}")),
                Err(_) => links.refused(format_args!("the handshake timed out")),
            }
        });
    }

    /// Accepts on a TCP listener until the task is aborted.
    pub fn serve_tcp(
        self: &Arc<Self>,
        listener: tokio::net::TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        let links = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, from)) => {
                        let _ = stream.set_nodelay(true);
                        links.accept(Box::new(stream), Some(from.ip()));
                    }
                    Err(error) => {
                        crate::util::log(format_args!("the cluster listener: {error}"));
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Accepts the streams of a [`MemoryNet`] listener until it closes:
    /// streams of no address.
    pub fn serve_memory(
        self: &Arc<Self>,
        mut incoming: mpsc::UnboundedReceiver<BoxStream>,
    ) -> tokio::task::JoinHandle<()> {
        let links = self.clone();
        tokio::spawn(async move {
            while let Some(stream) = incoming.recv().await {
                links.accept(stream, None);
            }
        })
    }

    /// The listener's side: the dialer's [`handshake::HELLO`] bytes read
    /// into a fixed buffer, the answer, then the dialer's MAC into another;
    /// nothing else is read or kept before that MAC checks.
    async fn listen_handshake(self: Arc<Self>, mut stream: BoxStream) -> Result<(), LinkError> {
        let failed = |e: io::Error| LinkError::failed(e.to_string());
        let mut first = [0u8; handshake::HELLO];
        stream.read_exact(&mut first).await.map_err(failed)?;
        let Some(hello) = Hello::decode(&first) else {
            return Err(LinkError::failed("not a cluster link"));
        };
        if !self.faults.reaches(hello.node, self.me) {
            return Err(LinkError::failed("partitioned"));
        }
        let secret = x25519_dalek::StaticSecret::from(*random::<32>()?);
        let reply = Reply {
            public: *x25519_dalek::PublicKey::from(&secret).as_bytes(),
            nonce: *random::<16>()?,
            node: self.me,
        }
        .encode();
        let th = handshake::transcript(&first, &reply);
        let mut second = [0u8; handshake::REPLY];
        second[..handshake::REPLY_BODY].copy_from_slice(&reply);
        second[handshake::REPLY_BODY..].copy_from_slice(&handshake::mac(
            &self.psk,
            handshake::LISTENER,
            &th,
        ));
        stream.write_all(&second).await.map_err(failed)?;
        let mut mac = [0u8; handshake::FINISH];
        stream.read_exact(&mut mac).await.map_err(failed)?;
        if !handshake::verify(&self.psk, handshake::DIALER, &th, &mac) {
            return Err(LinkError::failed("a dialer without the cluster key"));
        }
        let keys = derive(&self.psk, &secret, &hello.public, &th, false)?;
        self.start(stream, hello.node, hello.node, keys);
        Ok(())
    }

    async fn dial_handshake(&self, address: &str) -> Result<(NodeId, BoxStream, Keys), LinkError> {
        let failed = |e: io::Error| LinkError::failed(format!("{address}: {e}"));
        let mut stream = self.net.dial(address).await.map_err(failed)?;
        let secret = x25519_dalek::StaticSecret::from(*random::<32>()?);
        let first = Hello {
            public: *x25519_dalek::PublicKey::from(&secret).as_bytes(),
            nonce: *random::<16>()?,
            node: self.me,
        }
        .encode();
        stream.write_all(&first).await.map_err(failed)?;
        let mut second = [0u8; handshake::REPLY];
        stream.read_exact(&mut second).await.map_err(failed)?;
        let (reply, mac) = Reply::decode(&second);
        let th = handshake::transcript(&first, &reply.encode());
        if !handshake::verify(&self.psk, handshake::LISTENER, &th, &mac) {
            return Err(LinkError::failed(format!(
                "{address}: a listener without the cluster key"
            )));
        }
        let ours = handshake::mac(&self.psk, handshake::DIALER, &th);
        stream.write_all(&ours).await.map_err(failed)?;
        let keys = derive(&self.psk, &secret, &reply.public, &th, true)?;
        Ok((reply.node, stream, keys))
    }

    /// Dials `address`, whose node it learns from the handshake.
    ///
    /// # Errors
    ///
    /// If the dial or the handshake fails.
    pub async fn dial(&self, address: &str) -> Result<NodeId, LinkError> {
        let gate = lock(&self.dialing)
            .entry(address.to_owned())
            .or_default()
            .clone();
        let _held = gate.lock().await;
        let _permit = self
            .outbound
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| LinkError::failed("the links are closed"))?;
        let (peer, stream, keys) =
            tokio::time::timeout(HANDSHAKE_DEADLINE, self.dial_handshake(address))
                .await
                .map_err(|_| LinkError::failed(format!("{address}: the handshake timed out")))??;
        if peer == self.me {
            return Err(LinkError::failed(format!("{address} is this node")));
        }
        if !self.faults.reaches(self.me, peer) {
            return Err(LinkError::failed("partitioned"));
        }
        self.know(peer, address);
        self.start(stream, peer, self.me, keys);
        Ok(peer)
    }

    /// Starts a connection's tasks, unless a live one the lower node
    /// dialed stays.
    fn start(&self, stream: BoxStream, peer: NodeId, dialer: NodeId, keys: Keys) {
        let lower = self.me.min(peer);
        {
            let conns = lock(&self.conns);
            if let Some(existing) = conns.get(&peer)
                && existing.alive.load(Ordering::SeqCst)
                && existing.dialer == lower
                && dialer != lower
            {
                return;
            }
        }
        self.started.fetch_add(1, Ordering::SeqCst);
        let (tx, queued) = Outbox::new();
        let conn = Arc::new(Conn {
            peer,
            dialer,
            tx,
            pending: Mutex::new(HashMap::new()),
            raft: Arc::new(tokio::sync::Semaphore::new(IN_FLIGHT_RAFT)),
            shard: Arc::new(tokio::sync::Semaphore::new(IN_FLIGHT_SHARD)),
            client: Arc::new(tokio::sync::Semaphore::new(IN_FLIGHT)),
            next: AtomicU64::new(1),
            alive: AtomicBool::new(true),
            received: Mutex::new(Instant::now()),
            tasks: Mutex::new(Vec::new()),
        });
        let (read, write) = tokio::io::split(stream);
        let writer = tokio::spawn(write_frames(
            write,
            queued,
            keys.send,
            self.faults.clone(),
            self.me,
            peer,
            Arc::downgrade(&conn),
        ));
        let reader = tokio::spawn(read_frames(
            read,
            keys.receive,
            self.myself.clone(),
            Arc::downgrade(&conn),
        ));
        lock(&conn.tasks).extend([writer.abort_handle(), reader.abort_handle()]);
        let old = lock(&self.conns).insert(peer, conn);
        if let Some(old) = old {
            old.close();
        }
    }

    fn live(&self, peer: NodeId) -> Option<Arc<Conn>> {
        lock(&self.conns)
            .get(&peer)
            .filter(|conn| conn.alive.load(Ordering::SeqCst))
            .cloned()
    }

    fn drop_conn(&self, conn: &Arc<Conn>) {
        conn.close();
        let mut conns = lock(&self.conns);
        if conns.get(&conn.peer).is_some_and(|c| Arc::ptr_eq(c, conn)) {
            conns.remove(&conn.peer);
        }
    }

    async fn conn(&self, peer: NodeId) -> Result<Arc<Conn>, LinkError> {
        if peer == self.me {
            return Err(LinkError::failed("a link to itself"));
        }
        if let Some(conn) = self.live(peer) {
            return Ok(conn);
        }
        if !self.faults.reaches(self.me, peer) {
            return Err(LinkError::failed("partitioned"));
        }
        let address = lock(&self.addresses).get(&peer).cloned();
        let Some(address) = address else {
            return Err(LinkError::failed(format!(
                "node {peer:016x} has no known address"
            )));
        };
        let reached = self.dial(&address).await?;
        if reached != peer {
            return Err(LinkError::failed(format!(
                "{address} is node {reached:016x}, not {peer:016x}"
            )));
        }
        self.live(peer)
            .ok_or_else(|| LinkError::failed("the connection closed"))
    }

    /// Asks `peer` and waits at most `wait` for its answer.
    ///
    /// # Errors
    ///
    /// If the peer cannot be reached, or does not answer in time.
    pub async fn call(
        &self,
        peer: NodeId,
        tag: u8,
        body: Vec<u8>,
        wait: Duration,
    ) -> Result<Vec<u8>, LinkError> {
        self.call_sent(peer, tag, body, wait)
            .await
            .map_err(|(error, _)| error)
    }

    /// [`Self::call`], telling of a failure whether the request was handed
    /// to the connection, so that `peer` may have acted on it.
    ///
    /// # Errors
    ///
    /// If the peer cannot be reached, or does not answer in time; and
    /// whether the request was sent.
    pub async fn call_sent(
        &self,
        peer: NodeId,
        tag: u8,
        body: Vec<u8>,
        wait: Duration,
    ) -> Result<Vec<u8>, (LinkError, bool)> {
        if FRAME_BYTES + body.len() > MAX_FRAME {
            return Err((LinkError::too_large(), false));
        }
        let asked = Instant::now();
        let class = Class::of(tag);
        let conn = self.conn(peer).await.map_err(|error| (error, false))?;
        let id = conn.next.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = oneshot::channel();
        lock(&conn.pending).insert(
            id,
            Pending {
                tx,
                parts: Vec::new(),
                heard: None,
            },
        );
        let frame = Frame {
            kind: REQUEST,
            id,
            tag,
            body,
        };
        let written = Arc::new(AtomicBool::new(false));
        // The cluster's share is queued at once, and a full one closes the
        // connection, which is stuck. The clients' waits for room for as
        // long as the call waits: the device whose message this carries
        // waits with it.
        let queued = match class {
            Class::Cluster => conn.tx.push(class, frame.encode(), Some(written.clone())),
            Class::Client => {
                conn.tx
                    .push_within(
                        class,
                        frame.encode(),
                        Some(written.clone()),
                        CLIENT_QUEUE_BYTES,
                        asked + wait,
                    )
                    .await
            }
        };
        if let Err(why) = queued {
            lock(&conn.pending).remove(&id);
            if why == Unqueued::Full && class == Class::Client {
                return Err((LinkError::Busy, false));
            }
            self.drop_conn(&conn);
            return Err((
                LinkError::failed("the connection closed, or its queue is full"),
                false,
            ));
        }
        let sent_at = Instant::now();
        // The answer is waited for until `wait` after the call, or `wait`
        // after its last piece.
        let mut until = asked + wait;
        let answer = loop {
            match tokio::time::timeout_at(until.into(), &mut rx).await {
                Ok(answer) => break Some(answer),
                Err(_) => {
                    let heard = lock(&conn.pending).get(&id).and_then(|p| p.heard);
                    match heard {
                        Some(heard) if heard + wait > until => until = heard + wait,
                        _ => break None,
                    }
                }
            }
        };
        match answer {
            Some(Ok(Ok(frame))) if frame.tag == UNKNOWN => Err((
                LinkError::failed("the peer does not know the request"),
                false,
            )),
            Some(Ok(Ok(frame))) if frame.tag == TOO_LARGE => Err((LinkError::too_large(), true)),
            Some(Ok(Ok(frame))) => Ok(frame.body),
            Some(Ok(Err(error))) => Err((error, true)),
            Some(Err(_)) => Err((LinkError::failed("the connection closed"), true)),
            None => {
                lock(&conn.pending).remove(&id);
                // Nothing came back since the request was queued, nor for
                // the silence, and the writer wrote the request or made no
                // progress for as long: the connection is taken as lost,
                // and the next call dials again (module documentation, "A
                // dead connection").
                let silent = *lock(&self.silent);
                let received = *lock(&conn.received);
                if received < sent_at
                    && received.elapsed() >= silent
                    && (written.load(Ordering::SeqCst) || conn.tx.stalled(silent))
                {
                    self.drop_conn(&conn);
                }
                Err((
                    LinkError::failed(format!("node {peer:016x} did not answer in time")),
                    true,
                ))
            }
        }
    }

    /// Sends `peer` a notice, in order after the others sent to it.
    ///
    /// # Errors
    ///
    /// If the peer cannot be reached.
    pub async fn notify(&self, peer: NodeId, tag: u8, body: Vec<u8>) -> Result<(), LinkError> {
        if FRAME_BYTES + body.len() > MAX_FRAME {
            return Err(LinkError::too_large());
        }
        let class = Class::of(tag);
        let conn = self.conn(peer).await?;
        let frame = Frame {
            kind: NOTICE,
            id: 0,
            tag,
            body,
        };
        // As a request's: a client notice waits for room, [`ROOM_WAIT`] at
        // most, and fails alone.
        let queued = match class {
            Class::Cluster => conn.tx.push(class, frame.encode(), None),
            Class::Client => {
                let deadline = Instant::now() + ROOM_WAIT;
                conn.tx
                    .push_within(class, frame.encode(), None, CLIENT_QUEUE_BYTES, deadline)
                    .await
            }
        };
        match queued {
            Ok(()) => Ok(()),
            Err(Unqueued::Full) if class == Class::Client => Err(LinkError::Busy),
            Err(_) => {
                self.drop_conn(&conn);
                Err(LinkError::failed(
                    "the connection closed, or its queue is full",
                ))
            }
        }
    }

    fn on_frame(&self, conn: &Arc<Conn>, frame: Frame) {
        *lock(&conn.received) = Instant::now();
        match frame.kind {
            RESPONSE => {
                let Some(pending) = lock(&conn.pending).remove(&frame.id) else {
                    return;
                };
                let answer = if frame.tag == PARTS {
                    // The pieces sent before are the answer, if they are
                    // all there.
                    match parts_length(&frame.body) {
                        Some(length) if length == pending.parts.len() as u64 => Ok(Frame {
                            body: pending.parts,
                            ..frame
                        }),
                        _ => Err(LinkError::failed("an answer arrived in part")),
                    }
                } else {
                    Ok(frame)
                };
                let _ = pending.tx.send(answer);
            }
            NOTICE if frame.tag == PART => {
                let mut pending = lock(&conn.pending);
                let Some(waiting) = pending.get_mut(&frame.id) else {
                    // An answer no longer waited for.
                    return;
                };
                let failed = match Part::decode(&frame.body) {
                    Some(part) if part.offset != waiting.parts.len() as u64 => {
                        Some(LinkError::failed("an answer arrived in part"))
                    }
                    Some(part) if waiting.parts.len() + part.bytes.len() > MAX_ANSWER => {
                        Some(LinkError::too_large())
                    }
                    Some(part) => {
                        waiting.parts.extend_from_slice(&part.bytes);
                        waiting.heard = Some(Instant::now());
                        None
                    }
                    None => Some(LinkError::failed("a piece of an answer that does not read")),
                };
                if let Some(error) = failed
                    && let Some(waiting) = pending.remove(&frame.id)
                {
                    let _ = waiting.tx.send(Err(error));
                }
            }
            NOTICE => {
                if let Some(handler) = self.handler.get() {
                    handler.notice(conn.peer, frame.tag, frame.body);
                }
            }
            _ => {
                let Some(handler) = self.handler.get().cloned() else {
                    return;
                };
                let tx = conn.tx.clone();
                let peer = conn.peer;
                let class = Class::of(frame.tag);
                // Each kind of request has a budget of its own, so that the
                // clients' never leave a Raft request, a renewal or a shard
                // commit unanswered.
                let Ok(permit) = conn.budget(frame.tag).clone().try_acquire_owned() else {
                    // Too many of the peer's requests of this kind at once.
                    let answer = Frame {
                        kind: RESPONSE,
                        id: frame.id,
                        tag: UNKNOWN,
                        body: Vec::new(),
                    };
                    // A full client queue drops the answer, and its asker
                    // times out; a full cluster queue is a stuck one.
                    match tx.push(class, answer.encode(), None) {
                        Ok(()) => {}
                        Err(Unqueued::Full) if class == Class::Client => {}
                        Err(_) => self.drop_conn(conn),
                    }
                    return;
                };
                let weak = Arc::downgrade(conn);
                let links = self.myself.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let body = handler.request(peer, frame.tag, frame.body).await;
                    let answered = answer(&tx, class, frame.id, frame.tag, body).await;
                    let stuck = match answered {
                        Ok(()) => false,
                        Err(Unqueued::Full) => class == Class::Cluster,
                        Err(Unqueued::Closed) => true,
                    };
                    if stuck && let (Some(links), Some(conn)) = (links.upgrade(), weak.upgrade()) {
                        links.drop_conn(&conn);
                    }
                });
            }
        }
    }
}

/// Queues the answer to request `id` in its share: in one frame, in pieces
/// when it is larger than a frame, or as too large when it is larger than
/// [`MAX_ANSWER`]. A cluster answer of one frame is queued at once; a
/// client answer of one frame waits for room as a piece does. Fails if its
/// share's queue stayed full, or the connection closed.
async fn answer(
    tx: &Outbox,
    class: Class,
    id: u64,
    tag: u8,
    body: Vec<u8>,
) -> Result<(), Unqueued> {
    let response = |tag, body| {
        Frame {
            kind: RESPONSE,
            id,
            tag,
            body,
        }
        .encode()
    };
    let single = |frame: Vec<u8>| async move {
        match class {
            Class::Cluster => tx.push(class, frame, None),
            Class::Client => {
                let deadline = Instant::now() + PART_WAIT;
                tx.push_within(class, frame, None, CLIENT_QUEUE_BYTES, deadline)
                    .await
            }
        }
    };
    if body.len() <= PART_BYTES {
        return single(response(tag, body)).await;
    }
    if body.len() > MAX_ANSWER {
        crate::util::log(format_args!(
            "an answer of {} bytes is larger than a cluster link carries",
            body.len()
        ));
        return single(response(TOO_LARGE, Vec::new())).await;
    }
    let mut offset = 0;
    for bytes in body.chunks(PART_BYTES) {
        let part = Frame {
            kind: NOTICE,
            id,
            tag: PART,
            body: Part {
                offset: offset as u64,
                bytes: bytes.to_vec(),
            }
            .encode(),
        };
        tx.push_paced(class, part.encode()).await?;
        offset += bytes.len();
    }
    tx.push_paced(
        class,
        response(PARTS, (body.len() as u64).to_be_bytes().to_vec()),
    )
    .await
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, LinkError> {
    frasil_crypto::random_bytes::<N>().map_err(|_| LinkError::failed("no randomness"))
}

/// The connection's keys from this end's ephemeral secret and the other
/// end's public key (module `handshake`, [`handshake::keys`]).
fn derive(
    psk: &[u8; 32],
    secret: &x25519_dalek::StaticSecret,
    other: &[u8; 32],
    th: &[u8; 32],
    dialer: bool,
) -> Result<Keys, LinkError> {
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*other));
    if !shared.was_contributory() {
        return Err(LinkError::failed("a low-order key"));
    }
    handshake::keys(psk, shared.as_bytes(), th, dialer).ok_or_else(|| LinkError::failed("keys"))
}

/// Seals and writes each frame, after the faults' delay or drop.
async fn write_frames(
    mut write: tokio::io::WriteHalf<BoxStream>,
    mut queued: Queued,
    key: Zeroizing<[u8; 32]>,
    faults: Arc<Faults>,
    me: NodeId,
    peer: NodeId,
    conn: Weak<Conn>,
) {
    let mut counter = 0u64;
    while let Some(item) = queued.next().await {
        let Some(delay) = faults.frame(me, peer) else {
            queued.finished(&item);
            continue;
        };
        let plain = &item.bytes;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        counter += 1;
        let sealed = xchacha20poly1305_seal(&key, &nonce(counter), &counter.to_be_bytes(), plain);
        let length = u32::try_from(8 + sealed.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(12 + sealed.len());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&sealed);
        if write.write_all(&out).await.is_err() {
            break;
        }
        queued.finished(&item);
    }
    if let Some(conn) = conn.upgrade() {
        conn.alive.store(false, Ordering::SeqCst);
    }
}

/// The bytes of a frame read at a time: each step that arrives counts as
/// hearing from the peer.
const READ_STEP: usize = 64 << 10;

/// Fills `buf` from the stream, a step at a time, noting after each step
/// that the peer was heard from: a peer whose large frame is still
/// arriving is not silent (module documentation, "A dead connection").
/// Whether `buf` was filled.
async fn read_heard(
    read: &mut tokio::io::ReadHalf<BoxStream>,
    buf: &mut [u8],
    conn: &Weak<Conn>,
) -> bool {
    for step in buf.chunks_mut(READ_STEP) {
        if read.read_exact(step).await.is_err() {
            return false;
        }
        if let Some(conn) = conn.upgrade() {
            *lock(&conn.received) = Instant::now();
        }
    }
    true
}

/// Reads, opens and hands on each frame, until the stream ends or a frame
/// does not open.
async fn read_frames(
    mut read: tokio::io::ReadHalf<BoxStream>,
    key: Zeroizing<[u8; 32]>,
    links: Weak<Links>,
    conn: Weak<Conn>,
) {
    let mut expected = 1u64;
    let mut unread = false;
    loop {
        let mut length = [0u8; 4];
        if read.read_exact(&mut length).await.is_err() {
            break;
        }
        let length = u32::from_be_bytes(length) as usize;
        if !(8 + 16..=MAX_FRAME + 8 + 16 + 64).contains(&length) {
            unread = true;
            break;
        }
        let mut sealed = vec![0u8; length];
        if !read_heard(&mut read, &mut sealed, &conn).await {
            break;
        }
        let counter = u64::from_be_bytes(sealed[..8].try_into().unwrap_or_default());
        if counter != expected {
            unread = true;
            break;
        }
        expected += 1;
        let Ok(plain) = xchacha20poly1305_open(&key, &nonce(counter), &sealed[..8], &sealed[8..])
        else {
            unread = true;
            break;
        };
        let Some(frame) = Frame::decode(&plain) else {
            unread = true;
            break;
        };
        let (Some(links), Some(conn)) = (links.upgrade(), conn.upgrade()) else {
            break;
        };
        links.on_frame(&conn, frame);
    }
    if let (Some(links), Some(conn)) = (links.upgrade(), conn.upgrade()) {
        if unread {
            links.unread.fetch_add(1, Ordering::SeqCst);
        }
        links.drop_conn(&conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::wire as wire_tag;

    struct Echo;

    impl Handler for Echo {
        fn request(&self, from: NodeId, tag: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>> {
            Box::pin(async move {
                let mut out = from.to_be_bytes().to_vec();
                out.push(tag);
                out.extend(body);
                out
            })
        }

        fn notice(&self, _: NodeId, _: u8, _: Vec<u8>) {}
    }

    fn pair(key_b: [u8; 32]) -> (Arc<Links>, Arc<Links>, Arc<Faults>) {
        let net = Arc::new(MemoryNet::new());
        let faults = Arc::new(Faults::new(7));
        let a = Links::new(1, &[5; 32], net.clone(), faults.clone());
        let b = Links::new(2, &key_b, net.clone(), faults.clone());
        a.set_handler(Arc::new(Echo));
        b.set_handler(Arc::new(Echo));
        b.serve_memory(net.listen("b"));
        a.serve_memory(net.listen("a"));
        a.know(2, "b");
        b.know(1, "a");
        (a, b, faults)
    }

    #[tokio::test]
    async fn a_call_is_answered_both_ways_over_one_connection() {
        let (a, b, _) = pair([5; 32]);
        let answer = a
            .call(2, 9, vec![1, 2], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(answer, [1u64.to_be_bytes().as_slice(), &[9, 1, 2]].concat());
        let back = b.call(1, 3, vec![], Duration::from_secs(2)).await.unwrap();
        assert_eq!(back, [2u64.to_be_bytes().as_slice(), &[3]].concat());
        assert_eq!(lock(&a.conns).len(), 1);
    }

    #[tokio::test]
    async fn a_node_without_the_key_is_refused() {
        let (a, _b, _) = pair([6; 32]);
        assert!(a.call(2, 9, vec![], Duration::from_secs(1)).await.is_err());
    }

    /// Streams from one address that never finish their handshake hold at
    /// most that address's share of the inbound budget, so another node
    /// still connects; and hosts that hold the whole inbound budget keep
    /// this node from no dial of its own.
    #[tokio::test]
    async fn a_handshake_flood_from_one_address_blocks_no_other() {
        let (a, b, _) = pair([5; 32]);
        let flooder: IpAddr = "192.0.2.1".parse().unwrap();
        let mut held = Vec::new();
        for _ in 0..HANDSHAKES_IN * 2 {
            let (near, far) = tokio::io::duplex(1024);
            b.accept(Box::new(far), Some(flooder));
            held.push(near);
        }
        assert_eq!(
            lock(&b.sources).get(&flooder).copied(),
            Some(HANDSHAKES_PER_SOURCE)
        );
        a.call(2, 9, vec![1], Duration::from_secs(2))
            .await
            .expect("another address connects");
        // Every inbound slot held, by addresses of their own.
        let (a, b, _) = pair([5; 32]);
        for n in 0..HANDSHAKES_IN {
            let (near, far) = tokio::io::duplex(1024);
            let source = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10 + n as u8));
            b.accept(Box::new(far), Some(source));
            held.push(near);
        }
        assert_eq!(b.inbound.available_permits(), 0);
        b.call(1, 9, vec![2], Duration::from_secs(2))
            .await
            .expect("this node still dials out");
        drop(a);
    }

    #[tokio::test]
    async fn a_partition_stops_calls_until_it_heals() {
        let (a, _b, faults) = pair([5; 32]);
        a.call(2, 1, vec![], Duration::from_secs(1)).await.unwrap();
        faults.partition(1, 2);
        assert!(
            a.call(2, 1, vec![], Duration::from_millis(200))
                .await
                .is_err()
        );
        faults.heal();
        a.call(2, 1, vec![], Duration::from_secs(1)).await.unwrap();
    }

    /// A slow link's cluster queue holds at most [`CLUSTER_QUEUE_BYTES`]:
    /// once it is full, the next frame closes the connection, long before
    /// [`QUEUE`] frames.
    #[tokio::test]
    async fn a_slow_links_cluster_queue_is_bounded_by_bytes() {
        let (a, _b, faults) = pair([5; 32]);
        a.call(2, 1, vec![], Duration::from_secs(1)).await.unwrap();
        faults.set_delay(Duration::from_secs(30));
        let body = vec![0u8; 7 << 20];
        let mut sent = 0;
        while a.notify(2, wire_tag::LIVE, body.clone()).await.is_ok() {
            sent += 1;
            assert!(sent <= QUEUE, "the queue never filled");
        }
        // Four frames of 7 MiB fit in 32 MiB, and the writer may hold one.
        let fit = CLUSTER_QUEUE_BYTES / (body.len() + FRAME_BYTES);
        assert!((fit..=fit + 1).contains(&sent), "{sent} frames queued");
        assert!(lock(&a.conns).is_empty(), "the full connection is closed");
    }

    /// A full client queue fails the one notice or call that found it
    /// full, as busy, and leaves the connection, and the cluster's share
    /// of it, as they were.
    #[tokio::test]
    async fn a_full_client_queue_does_not_reset_the_link() {
        let (a, _b, faults) = pair([5; 32]);
        a.call(2, 1, vec![], Duration::from_secs(1)).await.unwrap();
        let conn = a.live(2).unwrap();
        faults.set_delay(Duration::from_secs(30));
        let body = vec![0u8; 7 << 20];
        let mut sent = 0;
        let refused = loop {
            match a.notify(2, wire_tag::DELIVER, body.clone()).await {
                Ok(()) => sent += 1,
                Err(error) => break error,
            }
            assert!(sent <= QUEUE, "the queue never filled");
        };
        assert_eq!(refused, LinkError::Busy);
        let fit = CLIENT_QUEUE_BYTES / (body.len() + FRAME_BYTES);
        assert!((fit..=fit + 1).contains(&sent), "{sent} frames queued");
        let call = a
            .call_sent(
                2,
                wire_tag::FORWARD,
                body.clone(),
                Duration::from_millis(300),
            )
            .await
            .unwrap_err();
        assert_eq!(call, (LinkError::Busy, false), "nothing was sent");
        assert!(
            Arc::ptr_eq(&a.live(2).expect("the connection stays"), &conn),
            "the same connection"
        );
        a.notify(2, wire_tag::LIVE, vec![1])
            .await
            .expect("the cluster's share has room");
    }

    /// The writer takes the cluster's frames before the clients', in the
    /// order each share queued them.
    #[tokio::test]
    async fn the_clusters_frames_go_before_the_clients() {
        let (outbox, mut queued) = Outbox::new();
        for n in 0..3u8 {
            outbox.push(Class::Client, vec![n], None).unwrap();
        }
        outbox.push(Class::Cluster, vec![10], None).unwrap();
        outbox.push(Class::Cluster, vec![11], None).unwrap();
        let mut order = Vec::new();
        for _ in 0..5 {
            order.push(queued.next().await.unwrap().bytes[0]);
        }
        assert_eq!(order, vec![10, 11, 0, 1, 2]);
        assert_eq!(outbox.client.bytes.load(Ordering::SeqCst), 0);
    }

    /// Never answers a client request; answers the others at once.
    struct Stalling;

    impl Handler for Stalling {
        fn request(&self, _: NodeId, tag: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>> {
            Box::pin(async move {
                if Class::of(tag) == Class::Client {
                    std::future::pending::<()>().await;
                }
                body
            })
        }

        fn notice(&self, _: NodeId, _: u8, _: Vec<u8>) {}
    }

    /// Client requests that hold every client permit leave Raft requests,
    /// proposals, such as a lease's renewal, and shard requests answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raft_and_renewals_are_answered_while_clients_hold_their_share() {
        let net = Arc::new(MemoryNet::new());
        let faults = Arc::new(Faults::new(7));
        let a = Links::new(1, &[5; 32], net.clone(), faults.clone());
        let b = Links::new(2, &[5; 32], net.clone(), faults);
        a.set_handler(Arc::new(Echo));
        b.set_handler(Arc::new(Stalling));
        b.serve_memory(net.listen("b"));
        a.serve_memory(net.listen("a"));
        a.know(2, "b");
        b.know(1, "a");
        a.call(2, wire_tag::PROPOSE, vec![0], Duration::from_secs(2))
            .await
            .unwrap();
        let mut stalled = Vec::new();
        for n in 0..IN_FLIGHT {
            let a = a.clone();
            stalled.push(tokio::spawn(async move {
                a.call(2, wire_tag::FORWARD, vec![n as u8], Duration::from_secs(60))
                    .await
            }));
        }
        // Every client permit held. Waited for at the answering end, so
        // that no probe of ours takes one and times out.
        let held = b.live(1).expect("the connection");
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.client.available_permits() > 0 {
            assert!(Instant::now() < deadline, "the client permits never filled");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // One more client request is refused at once.
        let refused = a
            .call(2, wire_tag::FORWARD, vec![], Duration::from_secs(5))
            .await;
        assert!(
            matches!(&refused, Err(LinkError::Failed(why)) if why.contains("does not know")),
            "{refused:?}"
        );
        for tag in [
            wire_tag::PROPOSE,
            wire_tag::RAFT_APPEND,
            wire_tag::RAFT_VOTE,
            wire_tag::JOIN,
            wire_tag::SHARD,
        ] {
            let answer = a
                .call(2, tag, vec![tag], Duration::from_secs(2))
                .await
                .unwrap_or_else(|e| panic!("tag {tag} unanswered: {e}"));
            assert_eq!(answer, vec![tag]);
        }
        for task in stalled {
            task.abort();
        }
    }

    /// Answers tag 1 with as many bytes as its body's `u64` asks, each its
    /// offset modulo 251, and echoes any other.
    struct Sized;

    impl Handler for Sized {
        fn request(&self, _: NodeId, tag: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>> {
            Box::pin(async move {
                match (tag, <[u8; 8]>::try_from(body.as_slice())) {
                    (1, Ok(n)) => filler(u64::from_be_bytes(n) as usize),
                    _ => body,
                }
            })
        }

        fn notice(&self, _: NodeId, _: u8, _: Vec<u8>) {}
    }

    fn filler(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Two nodes connected, the second answering as [`Sized`].
    async fn sized_pair() -> (Arc<Links>, Arc<Links>) {
        let net = Arc::new(MemoryNet::new());
        let faults = Arc::new(Faults::new(7));
        let a = Links::new(1, &[5; 32], net.clone(), faults.clone());
        let b = Links::new(2, &[5; 32], net.clone(), faults);
        a.set_handler(Arc::new(Echo));
        b.set_handler(Arc::new(Sized));
        b.serve_memory(net.listen("b"));
        a.serve_memory(net.listen("a"));
        a.know(2, "b");
        b.know(1, "a");
        a.call(2, 9, vec![], Duration::from_secs(2)).await.unwrap();
        (a, b)
    }

    /// An answer of several frames arrives whole, over the connection it
    /// was asked on, while other calls on it are answered meanwhile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answer_larger_than_a_frame_arrives_in_pieces_beside_other_calls() {
        let (a, _b) = sized_pair().await;
        let conn = a.live(2).unwrap();
        let size = MAX_FRAME * 2 + 3;
        let large = a.call(
            2,
            1,
            (size as u64).to_be_bytes().to_vec(),
            Duration::from_secs(10),
        );
        let small = async {
            let mut answered = 0;
            for n in 0..20u8 {
                let back = a.call(2, 9, vec![n], Duration::from_secs(10)).await;
                assert_eq!(back.unwrap(), vec![n]);
                answered += 1;
            }
            answered
        };
        let (large, answered) = tokio::join!(large, small);
        assert_eq!(large.unwrap(), filler(size));
        assert_eq!(answered, 20);
        assert!(
            Arc::ptr_eq(&a.live(2).unwrap(), &conn),
            "the connection stayed"
        );
    }

    /// A request larger than a frame is refused before it is sent, and an
    /// answer larger than [`MAX_ANSWER`] is answered as too large: each an
    /// error of its call alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn what_is_larger_than_the_link_carries_fails_its_call_alone() {
        let (a, _b) = sized_pair().await;
        let conn = a.live(2).unwrap();
        let refused = a
            .call_sent(2, 9, vec![0; MAX_FRAME], Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(refused.0.is_too_large());
        assert!(!refused.1, "nothing was sent");
        assert!(
            a.notify(2, 9, vec![0; MAX_FRAME])
                .await
                .unwrap_err()
                .is_too_large()
        );
        let refused = a
            .call(
                2,
                1,
                (MAX_ANSWER as u64 + 1).to_be_bytes().to_vec(),
                Duration::from_secs(10),
            )
            .await
            .unwrap_err();
        assert!(refused.is_too_large());
        assert_eq!(
            a.call(2, 9, vec![1], Duration::from_secs(2)).await.unwrap(),
            vec![1]
        );
        assert!(
            Arc::ptr_eq(&a.live(2).unwrap(), &conn),
            "the connection stayed"
        );
    }

    /// Counts the requests it answers.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);

    impl Handler for Counting {
        fn request(&self, _: NodeId, _: u8, body: Vec<u8>) -> BoxFuture<'static, Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { body })
        }

        fn notice(&self, _: NodeId, _: u8, _: Vec<u8>) {}
    }

    /// A network whose dialer's bytes pass through a relay that, after the
    /// handshake, replays its first frame or flips a byte of it.
    struct Tampering {
        inner: MemoryNet,
        replay: bool,
    }

    impl Net for Tampering {
        fn dial<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let mut far = self.inner.dial(address).await?;
                let (near, mut relay) = tokio::io::duplex(1 << 16);
                let replay = self.replay;
                tokio::spawn(async move {
                    // The handshake, as it is: 64 bytes out, 88 back, 32 out.
                    let mut first = [0u8; 64];
                    let mut second = [0u8; 88];
                    let mut third = [0u8; 32];
                    if relay.read_exact(&mut first).await.is_err()
                        || far.write_all(&first).await.is_err()
                        || far.read_exact(&mut second).await.is_err()
                        || relay.write_all(&second).await.is_err()
                        || relay.read_exact(&mut third).await.is_err()
                        || far.write_all(&third).await.is_err()
                    {
                        return;
                    }
                    // The first frame.
                    let mut length = [0u8; 4];
                    if relay.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut frame = vec![0u8; u32::from_be_bytes(length) as usize];
                    if relay.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    let mut out = length.to_vec();
                    if replay {
                        out.extend_from_slice(&frame);
                        out.extend_from_slice(&length);
                        out.extend_from_slice(&frame);
                    } else {
                        let last = frame.len() - 1;
                        frame[last] ^= 1;
                        out.extend_from_slice(&frame);
                    }
                    let _ = far.write_all(&out).await;
                    let (mut back, mut forth) = tokio::io::split(far);
                    let (mut reader, mut writer) = tokio::io::split(relay);
                    let _ = tokio::join!(
                        tokio::io::copy(&mut reader, &mut forth),
                        tokio::io::copy(&mut back, &mut writer)
                    );
                });
                Ok(Box::new(near) as BoxStream)
            })
        }
    }

    async fn tampered(replay: bool) -> (Result<Vec<u8>, LinkError>, usize) {
        let net = Tampering {
            inner: MemoryNet::new(),
            replay,
        };
        let listening = net.inner.listen("b");
        let net = Arc::new(net);
        let faults = Arc::new(Faults::new(1));
        let a = Links::new(1, &[5; 32], net.clone(), faults.clone());
        let b = Links::new(2, &[5; 32], net, faults);
        let counting = Arc::new(Counting::default());
        b.set_handler(counting.clone());
        a.set_handler(Arc::new(Echo));
        b.serve_memory(listening);
        a.know(2, "b");
        let answer = a.call(2, 9, vec![7], Duration::from_millis(500)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        (answer, counting.0.load(Ordering::SeqCst))
    }

    /// A frame replayed on the wire is taken once, and closes the link.
    #[tokio::test]
    async fn a_replayed_frame_is_taken_once() {
        let (_, answered) = tampered(true).await;
        assert!(answered <= 1, "the request was answered {answered} times");
    }

    /// A frame altered on the wire is never taken.
    #[tokio::test]
    async fn a_tampered_frame_is_never_taken() {
        let (answer, answered) = tampered(false).await;
        assert!(answer.is_err());
        assert_eq!(answered, 0);
    }
}
