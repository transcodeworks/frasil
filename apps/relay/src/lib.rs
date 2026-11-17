//! Frasil's always-on peer service.
//!
//! Specified by `docs/spec/peers.md`, and by `docs/spec/transport.md`,
//! section 3.15 (The server binding) and section 3.16 (The iroh binding).
//!
//! A peer judges no event. It checks envelopes, Ed25519 signatures, visible
//! parts, sizes and rates, and decides only what it stores and serves: the
//! entries each rotation commits to and the rights a present grants
//! (peers.md, "Presenting a credential"), the administrator skeleton and
//! stability at the peer, and erasure, credentials requests, release and
//! collection, which wait for stability or `erasure_timeout`, and never
//! proceed while a skeleton cut concurrent with them can still take effect.
//! The skeleton starts from the last skeleton cut in effect at the peer,
//! which takes effect once each slot its standing entries wait for has
//! voted or is excused, and once a cut has been in effect for
//! `cut_retention` the peer truncates the history before its checkpoint,
//! keeping each stream's maximal releases and restores, answering `Missing`
//! for what it deleted and acknowledging it again unstored (peers.md,
//! "Skeleton cuts" and "Truncation").
//!
//! An event's author is its device ID, which the peer computes from the
//! envelope's `ed` and `kc` (events.md): the Ed25519 half of its signature
//! verifies under `ed` with no lookup, and chains, conflicts, attribution
//! and rates are keyed by the device ID, so one `ed` under two `kc` is two
//! authors. A device mailbox is addressed by device ID, and an
//! administrator pseudonym presents its device ID (peers.md, 2.2 The
//! credential proof).
//!
//! - [`Peer`] is the service: its state, opened from its records, and the
//!   handlers of both bindings. [`Peer::router`] serves the server binding
//!   (discovery, the WebSocket `frasil.p1`, objects over HTTP and
//!   mailboxes); [`Peer::listen_iroh`] accepts `frasil/p1/peer` on the iroh
//!   binding. [`run`] starts both from a [`Config`].
//! - [`IrohRelay`] is iroh's relay server, which [`run`] also starts when
//!   the [`Config`] names a listener for it: devices use it as their iroh
//!   relay.
//! - Events and every other record are kept through `frasil-store`'s
//!   `Store` (SQLite on a server); object chunks through [`blobs::Blobs`]
//!   (a directory, an S3-compatible bucket, or memory). Each space has
//!   locks of its own and opens on first use, from its snapshot and the
//!   journal after it; idle spaces close. Records are committed in groups
//!   by one writer thread, and an event is acknowledged only once its group
//!   is durable.
//! - [`testing`] starts a peer on loopback for end-to-end tests.
//! - Extensions: ext-ephemeral.md, ext-file-versions.md,
//!   ext-invite-links.md, ext-libraries.md and ext-deposit-tokens.md are all
//!   built in, and [`Settings::extensions`] turns each on
//!   (`FRASIL_EXTENSIONS`): ext-libraries.md and ext-deposit-tokens.md by
//!   default. With libraries on and no issuer named, the peer trusts its
//!   operator's own issuer ([`libraries::OperatorIssuer`]), and hosts no
//!   space until a ticket attaches it ([`Hosting::Closed`]); with deposit
//!   tokens on, the deposit keys' seeds are sealed under `deposit.key` in
//!   the data directory, or under a key derived from the cluster key.

pub mod blobs;
pub mod clock;
pub mod cluster;
pub mod config;
pub mod deposit;
mod device_mail;
mod drops;
mod iroh;
mod iroh_relay;
pub mod libraries;
mod limits;
mod objects;
mod records;
mod server;
mod session;
pub mod shards;
pub mod source;
mod space;
mod spaces;
mod state;
mod sync;
pub mod testing;
mod util;
mod writer;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{
    Config, ConfigError, ConnectionLimits, DeviceMailLimits, Extensions, GroupCommit, Hosting,
    IrohConfig, IrohRelayConfig, ObjectsConfig, Rates, RelayTls, S3Config, Settings, StoreConfig,
};
pub use frasil_peers::decisions::Execution;
pub use frasil_peers::entries::{Entry, EntryStatus, RecoveryEntry};
pub use iroh_relay::IrohRelay;

use crate::blobs::Blobs;
use crate::state::Core;
use frasil_events::EventId;
use frasil_store::{Store, StoreError};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The peer failed to start or to keep a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerError(pub String);

impl core::fmt::Display for PeerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PeerError {}

impl From<StoreError> for PeerError {
    fn from(error: StoreError) -> Self {
        Self(error.to_string())
    }
}

impl From<frasil_iroh::Error> for PeerError {
    fn from(error: frasil_iroh::Error) -> Self {
        Self(format!("iroh: {error}"))
    }
}

/// The iroh binding's endpoint, as the discovery document lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohInfo {
    /// The peer's stable endpoint key.
    pub endpoint: [u8; 32],
    /// The sockets it is bound to.
    pub addresses: Vec<SocketAddr>,
}

/// What every connection of the peer shares.
pub(crate) struct Shared {
    /// The peer's state, each part under its own lock.
    pub(crate) core: Core,
    pub(crate) blobs: Arc<dyn Blobs>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) settings: Settings,
    pub(crate) iroh: Mutex<Option<IrohInfo>>,
    /// What the peer asks of its connections as it stops.
    pub(crate) stop: tokio::sync::watch::Sender<Stop>,
    /// The cluster this node is a member of, if any (crate `cluster`).
    pub(crate) cluster: std::sync::OnceLock<Arc<cluster::Cluster>>,
    /// The timeline readings not kept in a row: the one write the peer
    /// makes whether or not a device does, so what shows that it writes.
    pub(crate) readings_unkept: AtomicU32,
    /// What each connection showed the peer, once a test asks to watch
    /// ([`Peer::watch`]); unset, nothing is recorded.
    pub(crate) watch: std::sync::OnceLock<Arc<testing::Watch>>,
    /// The connections open, under the operator's caps.
    pub(crate) connections: Arc<limits::Connections>,
}

/// The timeline readings not kept in a row at which the peer answers that
/// it does not write: one is a passing failure.
const READINGS_UNKEPT: u32 = 2;

impl Shared {
    /// Why the peer does not write now, if so, for its health answer.
    pub(crate) fn not_writing(&self) -> Option<&'static str> {
        let fence = self.core.shards.as_ref().and_then(|shards| shards.fence());
        fence.and_then(|fence| fence.stopped()).or_else(|| {
            (self.readings_unkept.load(Ordering::Relaxed) >= READINGS_UNKEPT)
                .then_some("the peer's writes are failing")
        })
    }
}

/// What the peer asks of its connections as it stops (transport.md, 3.10,
/// "Reconnecting elsewhere").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// It runs.
    Running,
    /// Close with `reconnect`, once no import is in progress and no create
    /// is pending on the connection.
    Reconnect,
    /// Drop the connection as a lost one, with no close code.
    Drop,
}

/// The peer service.
#[derive(Clone)]
pub struct Peer {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Peer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Peer").finish_non_exhaustive()
    }
}

impl Peer {
    /// Opens the peer over its records: what it hosts, its tombstones, its
    /// mailboxes and, with the extensions, its libraries and drops. No
    /// space is opened: each opens on first use. Blocking: call it outside
    /// the async runtime's workers.
    ///
    /// # Errors
    ///
    /// If a record cannot be read.
    pub fn open(
        settings: Settings,
        store: Arc<dyn Store>,
        blobs: Arc<dyn Blobs>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PeerError> {
        Self::open_with(settings, store, None, blobs, clock)
    }

    /// [`Peer::open`] over the peer's shards (crate `shards`): its records
    /// in them, each space's sights on its shard's timeline, and the shards'
    /// maintenance on the writer's thread. Blocking.
    ///
    /// # Errors
    ///
    /// If a record cannot be read.
    pub fn open_sharded(
        settings: Settings,
        shards: Arc<shards::Shards>,
        blobs: Arc<dyn Blobs>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PeerError> {
        shards.set_clock(clock.clone());
        let store: Arc<dyn Store> = shards.clone();
        Self::open_with(settings, store, Some(shards), blobs, clock)
    }

    /// [`Peer::open_sharded`] as a node of a cluster (crate `cluster`): its
    /// shards are those the cluster places on it, and its connections'
    /// spaces are served by their owners. Blocking.
    ///
    /// # Errors
    ///
    /// If a record cannot be read.
    pub fn open_clustered(
        settings: Settings,
        shards: Arc<shards::Shards>,
        cluster: Arc<cluster::Cluster>,
        blobs: Arc<dyn Blobs>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PeerError> {
        cluster.attach_shards(shards.clone());
        let peer = Self::open_sharded(settings, shards, blobs, clock)?;
        let _ = peer.shared.cluster.set(cluster.clone());
        cluster.attach_peer(&peer.shared);
        Ok(peer)
    }

    /// The cluster this node is a member of, if any.
    pub fn cluster(&self) -> Option<&Arc<cluster::Cluster>> {
        self.shared.cluster.get()
    }

    fn open_with(
        settings: Settings,
        store: Arc<dyn Store>,
        shards: Option<Arc<shards::Shards>>,
        blobs: Arc<dyn Blobs>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PeerError> {
        settings
            .extensions
            .check()
            .map_err(|error| PeerError(error.0))?;
        let core = Core::open_with(
            settings.clone(),
            records::Records::new(store),
            clock.clone(),
            shards,
        )?;
        let connections = limits::Connections::new(
            settings.connections.max_connections,
            settings.connections.max_connections_per_source,
        );
        Ok(Self {
            shared: Arc::new(Shared {
                connections,
                core,
                blobs,
                clock,
                settings,
                iroh: Mutex::new(None),
                stop: tokio::sync::watch::Sender::new(Stop::Running),
                cluster: std::sync::OnceLock::new(),
                readings_unkept: AtomicU32::new(0),
                watch: std::sync::OnceLock::new(),
            }),
        })
    }

    /// The server binding's routes (transport.md, "The server binding").
    pub fn router(&self) -> axum::Router {
        server::router(self.shared.clone())
    }

    /// Binds the iroh binding's endpoint and accepts `frasil/p1/peer` on it
    /// (transport.md, "The iroh binding"). The task ends when the endpoint
    /// closes.
    ///
    /// # Errors
    ///
    /// If the endpoint does not bind.
    pub async fn listen_iroh(
        &self,
        config: frasil_iroh::Config,
    ) -> Result<(frasil_iroh::Endpoint, tokio::task::JoinHandle<()>), PeerError> {
        let config = config.extensions(self.shared.settings.extensions.frames());
        let endpoint = frasil_iroh::Endpoint::bind(config).await?;
        *self
            .shared
            .iroh
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(IrohInfo {
            endpoint: endpoint.key(),
            addresses: endpoint.local_addresses(),
        });
        let task = tokio::spawn(iroh::accept(self.shared.clone(), endpoint.clone()));
        Ok((endpoint, task))
    }

    /// Judges and carries out what waits, now: erasures, credentials
    /// requests, releases, collections, pending events and orphaned objects
    /// past their timers, and mailboxes past their lifetimes.
    pub async fn sweep(&self) {
        let now = self.shared.clock.now();
        // ext-libraries.md: moves a crash left under way, carried on or
        // abandoned by the node that keeps their source shard.
        if self.shared.settings.extensions.libraries {
            libraries::moves::resume_moves(&self.shared).await;
        }
        let pieces = self.shared.core.sweep(now).await;
        for key in pieces {
            if let Err(error) = self.shared.blobs.delete(&key).await {
                util::log(format_args!("an object piece was not deleted: {error}"));
            }
        }
    }

    /// Sweeps every `every`, until the task is aborted.
    pub fn spawn_maintenance(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let peer = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            loop {
                interval.tick().await;
                peer.sweep().await;
            }
        })
    }

    /// The reading the peer keeps at rest: written at least once a minute
    /// and at shutdown (overview.md, "The local timeline").
    pub async fn keep_reading(&self) {
        let reading = self.shared.clock.now();
        if let Some(cluster) = self.shared.cluster.get() {
            cluster.keep_reading(&reading);
            return;
        }
        let put = records::Records::reading_put(&reading);
        match self.shared.core.writer.commit(vec![put], Vec::new()).await {
            Ok(_) => self.shared.readings_unkept.store(0, Ordering::Relaxed),
            Err(error) => {
                util::log(format_args!("the timeline reading was not kept: {error}"));
                self.shared.readings_unkept.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Closes every open space that may close now, idle or not: nothing
    /// waits in it and no connection is on it. Each folds its journal into
    /// a new snapshot first when the journal has grown. Returns how many
    /// closed.
    pub async fn close_spaces(&self) -> usize {
        self.shared.core.close_idle(true).await
    }

    /// Stops the peer's connections (transport.md, 3.10, "Reconnecting
    /// elsewhere"): each closes with `reconnect`, except one with an import
    /// in progress or a create pending, which closes so once that ends;
    /// after `drain`, those left are dropped, with no close code.
    pub async fn stop_connections(&self, drain: Duration) {
        let core = &self.shared.core;
        self.shared.stop.send_replace(Stop::Reconnect);
        let until = |wait: Duration| tokio::time::Instant::now() + wait;
        let deadline = until(drain);
        while core.connections() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.shared.stop.send_replace(Stop::Drop);
        let deadline = until(Duration::from_secs(1));
        while core.connections() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Folds a space's journal into a new snapshot now, as a close does
    /// once its journal has grown. Returns whether the peer hosts it.
    ///
    /// # Errors
    ///
    /// If the records cannot be read or written.
    pub async fn fold_space(&self, space: &[u8; 32]) -> Result<bool, PeerError> {
        let core = &self.shared.core;
        let writing = core.write(EventId(*space)).await?;
        if !writing.hosted() {
            return Ok(false);
        }
        core.fold(&writing, Default::default(), Vec::new(), Vec::new())
            .await?;
        Ok(true)
    }

    /// How many spaces are open in memory.
    pub fn open_spaces(&self) -> usize {
        self.shared.core.open_spaces()
    }

    /// Records, from now on, what each new connection shows the peer, for
    /// a test to read ([`testing::Watch`]). A peer nobody watches records
    /// nothing.
    pub fn watch(&self) -> Arc<testing::Watch> {
        self.shared
            .watch
            .get_or_init(|| Arc::new(testing::Watch::default()))
            .clone()
    }

    /// Forgets the deposit keys, at rest and in memory, as a peer whose
    /// records were lost would: the next use of a key begins a new one
    /// (ext-deposit-tokens.md, 3.9 Spent tokens and key rotation). For
    /// tests of a device that sees its issuing key replaced. Blocking.
    ///
    /// # Errors
    ///
    /// If the records cannot be written.
    pub fn forget_deposit_keys(&self) -> Result<(), PeerError> {
        self.shared
            .core
            .forget_deposit_keys()
            .map_err(|error| PeerError(format!("the deposit keys were not forgotten: {error}")))
    }

    /// The key ID of each spent-token record this node keeps
    /// (ext-deposit-tokens.md, 2.7 What a peer keeps). Blocking.
    ///
    /// # Errors
    ///
    /// If the records cannot be read.
    pub fn spent_tokens(&self) -> Result<Vec<[u8; 32]>, PeerError> {
        self.shared
            .core
            .spent_records()
            .map_err(|error| PeerError(format!("the spent tokens were not read: {error}")))
    }

    /// The extensions that are on.
    pub fn extensions(&self) -> Extensions {
        self.shared.settings.extensions
    }

    /// How many times the peer has opened or rebuilt a space from its
    /// records since it started.
    pub fn replays(&self) -> u64 {
        self.shared.core.replays.load(Ordering::Relaxed)
    }

    // -- What the operator and tests read

    /// Whether the peer hosts a space.
    pub fn hosts(&self, space: &[u8; 32]) -> bool {
        self.shared.core.hosts(&EventId(*space))
    }

    /// Whether the peer erased a space, and keeps its tombstone.
    pub fn erased(&self, space: &[u8; 32]) -> bool {
        self.shared.core.tombstoned(&EventId(*space))
    }

    /// A space's entries, in the order the peer added them.
    pub fn entries(&self, space: &[u8; 32]) -> Option<Vec<Entry>> {
        self.read(space, |held| held.entries.entries().to_vec())
    }

    /// A space's recovery entries.
    pub fn recovery_entries(&self, space: &[u8; 32]) -> Option<Vec<RecoveryEntry>> {
        self.read(space, |held| held.entries.recovery().to_vec())
    }

    /// ext-libraries.md: whether the space index records a move of a
    /// space into another shard under way (crate `libraries`, module
    /// `moves`), as read from the index now. Blocking.
    pub fn moving(&self, space: &[u8; 32]) -> bool {
        let address = records::Records::move_address(&EventId(*space));
        spaces::blocking_here(|| self.shared.core.records.get(&address))
            .is_ok_and(|record| record.is_some())
    }

    /// The last judgement of an erasure or a credentials request, or
    /// `Execute` once carried out.
    pub fn outcome(&self, space: &[u8; 32], request: &[u8; 32]) -> Option<Execution> {
        if self.shared.core.tombstoned(&EventId(*space)) {
            return Some(Execution::Execute);
        }
        let request = EventId(*request);
        self.read(space, |held| {
            if held.executed.contains(&request) {
                return Some(Execution::Execute);
            }
            held.outcomes.get(&request).copied()
        })
        .flatten()
    }

    /// Whether the peer holds an event and serves it as stored.
    pub fn holds(&self, space: &[u8; 32], event: &[u8; 32]) -> bool {
        self.read(space, |held| {
            let released = held.released_streams();
            held.servable(EventId(*event), &released)
        })
        .unwrap_or(false)
    }

    /// Whether the peer holds an event's bytes at all, served or not.
    pub fn keeps(&self, space: &[u8; 32], event: &[u8; 32]) -> bool {
        self.read(space, |held| {
            held.log.contains(EventId(*event)) || held.is_pending(EventId(*event))
        })
        .unwrap_or(false)
    }

    /// Whether a stream is released at the peer.
    pub fn released(&self, space: &[u8; 32], stream: &[u8; 16]) -> bool {
        self.read(space, |held| held.is_released(stream))
            .unwrap_or(false)
    }

    /// Whether the peer holds a complete object.
    pub fn holds_object(&self, space: &[u8; 32], locator: &[u8; 64]) -> bool {
        self.read(space, |held| {
            held.objects
                .get(locator)
                .is_some_and(|record| record.complete)
        })
        .unwrap_or(false)
    }

    /// A space's usage, in bytes (peers.md, "Quotas and rates").
    pub fn usage(&self, space: &[u8; 32]) -> Option<u64> {
        self.read(space, crate::space::Space::used)
    }

    /// Whether an event is stable at the peer now (peers.md, "Stability at
    /// the peer"), under its space's `erasure_timeout`, and whether a
    /// skeleton request is valid at the peer.
    pub fn stability(&self, space: &[u8; 32], event: &[u8; 32]) -> Option<(bool, bool)> {
        let now = self
            .shared
            .core
            .space_now(&EventId(*space), self.shared.clock.now());
        let timeout = self.shared.core.erasure_timeout(&EventId(*space));
        self.read(space, |held| {
            let skeleton = held.skeleton();
            let clock = frasil_peers::skeleton::Clock {
                first_sights: &held.sights,
                now,
                timeout,
            };
            (
                skeleton.is_stable(EventId(*event), Some(&clock)),
                skeleton.is_valid(EventId(*event)),
            )
        })
    }

    /// Reads a space, opening it if it is closed.
    fn read<T>(&self, space: &[u8; 32], f: impl FnOnce(&crate::space::Space) -> T) -> Option<T> {
        self.shared.core.read_blocking(EventId(*space), f)
    }
}

/// A peer started from a [`Config`].
#[derive(Debug)]
pub struct Running {
    /// The service.
    pub peer: Peer,
    /// The HTTP listener's address.
    pub http: SocketAddr,
    /// The iroh endpoint, if it listens on one.
    pub iroh: Option<IrohInfo>,
    endpoint: Option<frasil_iroh::Endpoint>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Stops the listeners and the maintenance, then the connections
    /// ([`Peer::stop_connections`], within `reconnect_drain`), keeps the
    /// timeline's reading, and closes the spaces that may close.
    pub async fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
        let drain = Duration::from_secs(self.peer.shared.settings.reconnect_drain);
        self.peer.stop_connections(drain).await;
        if let Some(endpoint) = &self.endpoint {
            endpoint.close().await;
        }
        self.peer.keep_reading().await;
        self.peer.close_spaces().await;
    }
}

/// Starts a peer: its HTTP listener, its iroh endpoint and its maintenance.
///
/// # Errors
///
/// If a listener does not bind, or a record cannot be read.
pub async fn start(
    settings: Settings,
    store: Arc<dyn Store>,
    blobs: Arc<dyn Blobs>,
    clock: Arc<dyn Clock>,
    listen: SocketAddr,
    iroh: Option<frasil_iroh::Config>,
    maintenance: Option<Duration>,
) -> Result<Running, PeerError> {
    let peer = tokio::task::spawn_blocking(move || Peer::open(settings, store, blobs, clock))
        .await
        .map_err(|e| PeerError(format!("the peer did not open: {e}")))??;
    serve(peer, listen, iroh, maintenance).await
}

/// Starts a peer opened already: its HTTP listener, its iroh endpoint and
/// its maintenance.
async fn serve(
    peer: Peer,
    listen: SocketAddr,
    iroh: Option<frasil_iroh::Config>,
    maintenance: Option<Duration>,
) -> Result<Running, PeerError> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| PeerError(format!("{listen}: {e}")))?;
    let http = listener
        .local_addr()
        .map_err(|e| PeerError(e.to_string()))?;
    let mut tasks = Vec::new();
    let mut endpoint = None;
    let mut info = None;
    if let Some(config) = iroh {
        let (bound, task) = peer.listen_iroh(config).await?;
        info = peer
            .shared
            .iroh
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        endpoint = Some(bound);
        tasks.push(task);
    }
    let app = peer
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    // Each connection under the caps, with its head's deadline and its
    // idle time; `tap_io` gives the remote address to the routes.
    let listener = {
        use axum::serve::ListenerExt;
        let shared = &peer.shared;
        limits::Listener::new(
            listener,
            shared.connections.clone(),
            &shared.settings.connections,
            shared.settings.trusted_proxies.clone(),
        )
        .tap_io(|_| {})
    };
    tasks.push(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            util::log(format_args!("the HTTP listener stopped: {error}"));
        }
    }));
    if let Some(every) = maintenance {
        tasks.push(peer.spawn_maintenance(every));
    }
    Ok(Running {
        peer,
        http,
        iroh: info,
        endpoint,
        tasks,
    })
}

/// Takes an exclusive advisory lock on `frasil.lock` in the data directory,
/// before anything else is written there or claimed in a bucket. Two peers
/// on one data directory would otherwise both acknowledge writes under one
/// epoch until the fence's next check. The lock lives as long as the
/// returned file and is released by the OS when the process ends.
fn lock_data_dir(dir: &std::path::Path) -> Result<std::fs::File, PeerError> {
    let path = dir.join("frasil.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| PeerError(format!("{}: {e}", path.display())))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(PeerError(format!(
            "the data directory {} is held by another frasil-relay on this machine \
             (lock file {}). Stop it, or give this peer its own FRASIL_DATA_DIR.",
            dir.display(),
            path.display()
        ))),
        Err(std::fs::TryLockError::Error(e)) => Err(PeerError(format!("{}: {e}", path.display()))),
    }
}

/// Runs the peer of a [`Config`] until SIGTERM or Ctrl-C: its records in
/// shards, in the data directory or a bucket; object chunks in the data
/// directory's `objects` or a bucket; the iroh endpoint's key in
/// `iroh.key`; with ext-libraries and no issuer named, the operator's own
/// issuer in `issuer.key` ([`operator_issuer`]) and the default library;
/// with ext-deposit-tokens, outside a cluster, the key that seals its
/// deposit keys in `deposit.key`.
///
/// # Errors
///
/// If the data directory, a store or a listener cannot be opened, or the
/// data directory holds a store of the single-file layout.
pub async fn run(config: Config) -> Result<(), PeerError> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| PeerError(format!("{}: {e}", config.data_dir.display())))?;
    // Held until `run` returns; the OS releases it if the process dies.
    let _data_lock = lock_data_dir(&config.data_dir)?;
    let single = config.data_dir.join("peer.sqlite");
    if single.exists() {
        return Err(PeerError(format!(
            "{} is a store of the single-file layout, which this peer does not read: \
             it keeps its records in shards. Move the data directory aside, or delete \
             peer.sqlite with its -wal and -shm files, and start again.",
            single.display()
        )));
    }
    let (shards, cluster) = match &config.cluster {
        Some(cluster) => {
            let (shards, cluster) = join_cluster(&config, cluster).await?;
            (shards, Some(cluster))
        }
        None => {
            let store = config.store.clone();
            let shards = tokio::task::spawn_blocking(move || open_shards(&store))
                .await
                .map_err(|e| PeerError(format!("the store did not open: {e}")))??;
            (shards, None)
        }
    };
    let blobs: Arc<dyn Blobs> = match &config.objects {
        ObjectsConfig::Files(path) => {
            Arc::new(blobs::FileBlobs::open(path).map_err(|e| PeerError(e.to_string()))?)
        }
        ObjectsConfig::S3(s3) => {
            Arc::new(blobs::S3Blobs::open(s3).map_err(|e| PeerError(e.to_string()))?)
        }
    };
    let kept = match &cluster {
        Some(cluster) => cluster.kept_reading(),
        None => {
            let records = records::Records::new(shards.clone());
            tokio::task::spawn_blocking(move || records.kept_reading())
                .await
                .map_err(|e| PeerError(format!("the store did not open: {e}")))??
        }
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::start(kept));
    util::log(format_args!(
        "extensions on: {}",
        config.settings.extensions
    ));
    let relay = match &config.iroh_relay {
        Some(relay) => {
            let relay = IrohRelay::spawn(relay).await?;
            util::log(format_args!("iroh relay at {}", relay.url()));
            if let Some(quic) = relay.quic_addr() {
                util::log(format_args!("QUIC address discovery on {quic}"));
            }
            Some(relay)
        }
        None => None,
    };
    let iroh = match &config.iroh {
        Some(iroh) => {
            let key = iroh_key(&config.data_dir)?;
            Some(
                frasil_iroh::Config::new(key, &[frasil_iroh::Alpn::Peer])
                    .bind([iroh.bind])
                    .relays(config.settings.relays.clone()),
            )
        }
        None => None,
    };
    let mut settings = config.settings.clone();
    // ext-libraries.md: with no issuer named, the operator's own signs
    // the tickets, and is the one the peer trusts.
    if settings.extensions.libraries && settings.libraries.issuers.is_empty() {
        settings.libraries.use_operator(operator_issuer(&config)?);
    }
    // ext-deposit-tokens.md: the deposit keys' seeds are sealed at rest,
    // under a key of the data directory, or in a cluster one every node
    // derives from the cluster key.
    if settings.extensions.deposit_tokens && settings.deposit_tokens.seal.is_none() {
        settings.deposit_tokens.seal = Some(match &config.cluster {
            Some(cluster) => deposit::SealKey::from_cluster_key(&cluster.key),
            None => deposit_seal_key(&config.data_dir)?,
        });
    }
    let opened = shards.clone();
    let member = cluster.clone();
    let peer = tokio::task::spawn_blocking(move || match member {
        Some(cluster) => Peer::open_clustered(settings, opened, cluster, blobs, clock),
        None => Peer::open_sharded(settings, opened, blobs, clock),
    })
    .await
    .map_err(|e| PeerError(format!("the peer did not open: {e}")))??;
    // The default library, recorded once at the first start; in a cluster
    // its first ticket creates it (ext-libraries.md, 3.2).
    if cluster.is_none() {
        let opened = peer.clone();
        let default = tokio::task::spawn_blocking(move || opened.ensure_default_library())
            .await
            .map_err(|e| PeerError(format!("the default library was not kept: {e}")))??;
        if let Some(library) = default {
            util::log(format_args!("the default library is {library}"));
        }
    }
    let running = serve(peer, config.listen, iroh, Some(Duration::from_secs(60))).await?;
    util::log(format_args!("listening on {}", running.http));
    if let Some(info) = &running.iroh {
        util::log(format_args!(
            "iroh endpoint {} on {:?}",
            util::hex(&info.endpoint),
            info.addresses
        ));
    }
    let keeper = {
        let peer = running.peer.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                peer.keep_reading().await;
            }
        })
    };
    shutdown_signal().await;
    keeper.abort();
    // A planned stop: the shards go to the other nodes first, while this
    // node still forwards for its devices, then the devices reconnect.
    if let Some(cluster) = &cluster {
        cluster.hand_over().await;
    }
    running.shutdown().await;
    // Every shard folds or keeps its reading, once the writer has made the
    // last commit.
    let closed = tokio::task::spawn_blocking(move || shards.close_all()).await;
    if let Ok(Err(error)) | Err(error) = closed.map_err(|e| StoreError::new(e.to_string())) {
        util::log(format_args!("a shard did not close cleanly: {error}"));
    }
    // The other nodes take its shards up at once.
    if let Some(cluster) = cluster {
        cluster.leave().await;
    }
    if let Some(relay) = relay {
        relay.shutdown().await;
    }
    Ok(())
}

/// Starts this node of a cluster and its shards: the bucket's requests
/// timed out after the write timeout, the internal links on their TCP
/// listener, and Raft's state in the data directory's `raft.sqlite`.
async fn join_cluster(
    config: &Config,
    settings: &cluster::ClusterConfig,
) -> Result<(Arc<shards::Shards>, Arc<cluster::Cluster>), PeerError> {
    let StoreConfig::Bucket {
        s3,
        prefix,
        cache,
        node,
        ..
    } = &config.store
    else {
        return Err(PeerError("a cluster keeps its records in a bucket".into()));
    };
    let failed = |e: shards::bucket::BucketError| PeerError(e.to_string());
    let bucket = shards::bucket::S3Bucket::open(s3, prefix).map_err(failed)?;
    let timed = cluster::TimedBucket::new(Arc::new(bucket), settings.timing.put_timeout);
    let io = Arc::new(shards::bucket::BucketIo::new(Arc::new(timed)).map_err(failed)?);
    let name = node_name(node)?;
    let iroh = match &config.iroh {
        Some(_) => Some(frasil_crypto::primitives::ed25519_public(&iroh_key(
            &config.data_dir,
        )?)),
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(settings.listen)
        .await
        .map_err(|e| PeerError(format!("{}: {e}", settings.listen)))?;
    let path = config.data_dir.join("raft.sqlite");
    let raft: Arc<dyn Store> = tokio::task::spawn_blocking(move || {
        frasil_store::SqliteStore::open_with(&path, 1, frasil_store::Durability::Full)
    })
    .await
    .map_err(|e| PeerError(format!("the Raft store did not open: {e}")))?
    .map(|store| Arc::new(store) as Arc<dyn Store>)?;
    let wiring = cluster::Wiring {
        net: Arc::new(cluster::link::TcpNet),
        listen: cluster::Listen::Tcp(listener),
        faults: Arc::new(cluster::link::Faults::default()),
        clock: Arc::new(cluster::lease::SystemLeaseClock::default()),
        raft,
    };
    let member = cluster::Cluster::start(settings.clone(), &name, iroh, io.clone(), wiring).await?;
    util::log(format_args!(
        "node {:016x} of the cluster at epoch {}",
        member.me(),
        member.epoch()
    ));
    let fence: Arc<dyn shards::fence::Fence> = Arc::new(member.fence());
    let ownership: Arc<dyn shards::fence::Ownership> = member.clone();
    let cache = cache.clone();
    let shards =
        tokio::task::spawn_blocking(move || shards::Shards::clustered(io, cache, fence, ownership))
            .await
            .map_err(|e| PeerError(format!("the store did not open: {e}")))??;
    member.attach_shards(shards.clone());
    Ok((shards, member))
}

/// The shards a [`StoreConfig`] names: in a directory, or in a bucket under
/// this node's epoch. Blocking.
fn open_shards(store: &StoreConfig) -> Result<Arc<shards::Shards>, PeerError> {
    match store {
        StoreConfig::Directory(dir) => Ok(shards::Shards::local(dir)?),
        StoreConfig::Bucket {
            s3,
            prefix,
            cache,
            node,
            fence_every,
        } => {
            let failed = |e: shards::bucket::BucketError| PeerError(e.to_string());
            let bucket = shards::bucket::S3Bucket::open(s3, prefix).map_err(failed)?;
            let io = Arc::new(shards::bucket::BucketIo::new(Arc::new(bucket)).map_err(failed)?);
            let name = node_name(node)?;
            refuse_cluster_bucket(&io)?;
            let fence =
                shards::fence::SingleNode::start_with(&io, &name, *fence_every).map_err(failed)?;
            Ok(shards::Shards::bucket(io, cache, Arc::new(fence))?)
        }
    }
}

/// Refuses a bucket that names a cluster, for a peer started without the
/// cluster's settings: it would write shards the cluster's nodes own.
/// Blocking.
fn refuse_cluster_bucket(io: &Arc<shards::bucket::BucketIo>) -> Result<(), PeerError> {
    let bucket = io.bucket();
    let named = io
        .block(async move { bucket.get(cluster::CLUSTER_OBJECT).await })
        .map_err(|e| PeerError(e.to_string()))?;
    match named {
        Some(claim) => Err(PeerError(format!(
            "the bucket belongs to cluster {}: start this peer with the cluster's \
             settings to join it, or give it a bucket of its own",
            String::from_utf8_lossy(&claim)
                .split_whitespace()
                .next()
                .unwrap_or_default()
        ))),
        None => Ok(()),
    }
}

/// This node's name in the bucket, kept in a file: 16 random bytes in hex.
fn node_name(path: &std::path::Path) -> Result<String, PeerError> {
    match std::fs::read_to_string(path) {
        Ok(name) => {
            let name = name.trim().to_owned();
            if name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(name)
            } else {
                Err(PeerError(format!(
                    "{} is not a node's name",
                    path.display()
                )))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let bytes = frasil_crypto::random_bytes::<16>()
                .map_err(|_| PeerError("no randomness for the node's name".into()))?;
            let name = util::hex(&*bytes);
            std::fs::write(path, &name)
                .map_err(|e| PeerError(format!("{}: {e}", path.display())))?;
            Ok(name)
        }
        Err(e) => Err(PeerError(format!("{}: {e}", path.display()))),
    }
}

/// ext-libraries.md: the operator's own issuer (crate `libraries`,
/// `operator`): in a cluster derived from the cluster key, so that every
/// node has the same; otherwise kept in the data directory as `issuer.key`,
/// 32 random bytes written at the first start with mode 0600, as
/// `iroh.key` is. `frasil-relay ticket` reads it the same way.
///
/// # Errors
///
/// If `issuer.key` cannot be read or written, or is not 32 bytes.
pub fn operator_issuer(config: &Config) -> Result<libraries::OperatorIssuer, PeerError> {
    if let Some(cluster) = &config.cluster {
        return Ok(libraries::OperatorIssuer::from_cluster_key(&cluster.key));
    }
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| PeerError(format!("{}: {e}", config.data_dir.display())))?;
    let seed = zeroize::Zeroizing::new(kept_secret(&config.data_dir, "issuer.key", || {
        frasil_crypto::random_bytes::<32>()
            .map(|bytes| *bytes)
            .map_err(|_| PeerError("no randomness for issuer.key".into()))
    })?);
    Ok(libraries::OperatorIssuer::from_seed(*seed))
}

/// The peer's stable iroh endpoint key, kept in the data directory.
fn iroh_key(dir: &std::path::Path) -> Result<[u8; 32], PeerError> {
    kept_secret(dir, "iroh.key", || Ok(frasil_iroh::fresh_secret_key()?))
}

/// ext-deposit-tokens.md: the key that seals the deposit keys' seeds at
/// rest (crate `deposit`), kept in the data directory as `iroh.key` is.
fn deposit_seal_key(dir: &std::path::Path) -> Result<deposit::SealKey, PeerError> {
    kept_secret(dir, "deposit.key", || {
        frasil_crypto::random_bytes::<32>()
            .map(|bytes| *bytes)
            .map_err(|_| PeerError("no randomness for deposit.key".into()))
    })
    .map(deposit::SealKey::new)
}

/// A 32-byte secret kept in a file of the data directory that only the
/// peer's user reads, made by `fresh` the first time.
fn kept_secret(
    dir: &std::path::Path,
    name: &str,
    fresh: impl FnOnce() -> Result<[u8; 32], PeerError>,
) -> Result<[u8; 32], PeerError> {
    let path = dir.join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| PeerError(format!("{} is not 32 bytes", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = fresh()?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .map_err(|e| PeerError(format!("{}: {e}", path.display())))?;
            std::io::Write::write_all(&mut file, &key)
                .and_then(|()| file.sync_all())
                .map_err(|e| PeerError(e.to_string()))?;
            Ok(key)
        }
        Err(e) => Err(PeerError(e.to_string())),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shards::bucket::{Bucket, BucketIo, MemoryBucket};

    /// A second start on a locked data directory is refused, and succeeds
    /// once the first lock is dropped.
    #[test]
    fn a_data_directory_has_one_peer() {
        let dir = std::env::temp_dir().join(format!("frasil-lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = lock_data_dir(&dir).unwrap();
        let err = lock_data_dir(&dir).unwrap_err().to_string();
        assert!(err.contains(&dir.display().to_string()), "{err}");
        assert!(err.contains("held by another frasil-relay"), "{err}");
        drop(first);
        drop(lock_data_dir(&dir).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A peer started without the cluster's settings refuses a bucket that
    /// names a cluster, and takes one that names none.
    #[test]
    fn a_single_node_refuses_a_clusters_bucket() {
        let bucket = Arc::new(MemoryBucket::new());
        let shared: Arc<dyn Bucket> = bucket.clone();
        let io = Arc::new(BucketIo::new(shared).unwrap());
        assert!(refuse_cluster_bucket(&io).is_ok());
        let claim = bucket.clone();
        io.block(async move {
            claim
                .put(cluster::CLUSTER_OBJECT, b"c0ffee node run".to_vec())
                .await
        })
        .unwrap();
        let error = refuse_cluster_bucket(&io).unwrap_err();
        assert!(error.0.contains("cluster c0ffee"), "{error}");
    }

    /// `/healthz`, as a health check reads it: the status and the body.
    async fn health(http: SocketAddr) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(http).await.unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: peer\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        let status = answer.split(' ').nth(1).unwrap().parse().unwrap();
        (status, answer.rsplit("\r\n").next().unwrap().to_owned())
    }

    /// What a Docker health check sees of a peer on a bucket: `ok` while it
    /// writes, 503 once it cannot, and `ok` again when a lapse ends.
    #[tokio::test(flavor = "multi_thread")]
    async fn health_shows_a_peer_that_cannot_write() {
        let dir = std::env::temp_dir().join(format!(
            "frasil-relay-health-{}",
            util::hex(&*frasil_crypto::random_bytes::<8>().unwrap())
        ));
        let bucket = Arc::new(MemoryBucket::new());
        let shared: Arc<dyn Bucket> = bucket.clone();
        let io = Arc::new(BucketIo::new(shared).unwrap());
        let every = Duration::from_secs(10);
        let fence = Arc::new(shards::fence::SingleNode::start_with(&io, "a", every).unwrap());
        let held: Arc<dyn shards::fence::Fence> = fence.clone();
        let shards = shards::Shards::bucket(io.clone(), dir.join("cache"), held).unwrap();
        let blobs: Arc<dyn Blobs> = Arc::new(blobs::FileBlobs::open(dir.join("objects")).unwrap());
        let clock: Arc<dyn Clock> = Arc::new(clock::ManualClock::new(1000));
        let peer = Peer::open_sharded(Settings::open_core(), shards, blobs, clock).unwrap();
        let running = serve(peer.clone(), "127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        let ok = (200, "ok".to_owned());
        peer.keep_reading().await;
        assert_eq!(health(running.http).await, ok);

        // Reads refused: writes go on until the lapse, and stop after it.
        bucket.refuse_reads(true);
        fence.refresh_now();
        assert_eq!(health(running.http).await, ok);
        fence.unconfirmed_for(shards::fence::lapse_after(every));
        let (status, why) = health(running.http).await;
        assert_eq!(status, 503, "{why}");
        assert!(why.contains("could not confirm"), "{why}");
        bucket.refuse_reads(false);
        fence.refresh_now();
        assert_eq!(health(running.http).await, ok);

        // Writes failing, with the records reading well: one failure
        // passes, two in a row do not, and a kept reading ends it.
        bucket.fail_puts("log/", 2);
        peer.keep_reading().await;
        assert_eq!(health(running.http).await, ok);
        peer.keep_reading().await;
        let (status, why) = health(running.http).await;
        assert_eq!(status, 503, "{why}");
        assert!(why.contains("writes are failing"), "{why}");
        peer.keep_reading().await;
        assert_eq!(health(running.http).await, ok);

        // Replaced: for good.
        drop(shards::fence::SingleNode::start_with(&io, "b", every).unwrap());
        fence.refresh_now();
        let (status, why) = health(running.http).await;
        assert_eq!(status, 503, "{why}");
        assert!(why.contains("another node"), "{why}");
        running.shutdown().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
