//! A device's connections on the iroh binding: its member endpoint, the
//! connections it accepts and dials, local discovery and nearby pairing
//! (transport.md, "The iroh binding").
//!
//! A [`Node`] binds a member endpoint under a random key, never one of the
//! device's own keys, and accepts member and nearby connections on it. Each
//! member connection runs [`run_member`]. With local discovery on, the
//! node announces each open space every 2 seconds under its current state
//! (`lan_key(S)`), and dials every candidate an announcement it opens
//! gives; the member handshake decides everything. A node also keeps
//! where it reached each member, and dials those members again when the
//! device opens again (transport.md, "Reconnecting"), and dials each
//! member another member's `Addresses` lists, with or without local
//! discovery (transport.md, "The iroh binding", member addresses).

use crate::at_rest::Batch;
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::links::Learned;
use crate::member::run_member_with;
use frasil_admission::Offer;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_iroh::lan::{KEEP, LanConfig, LanSocket, next_announcement, open_member};
use frasil_iroh::{Alpn, Config, Connection, Endpoint};
use frasil_store::{Table, TableValue};
use frasil_transport::addresses::{CROSS_DIAL_WAIT_SECONDS, for_guest};
use frasil_transport::lan::MAX_CANDIDATES;
use frasil_transport::roster::{Path, Standing};
use frasil_transport::ticket::{Ticket, TicketKind};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The most spaces a device announces on a local network (transport.md,
/// "Member announcements").
const ANNOUNCED_SPACES: usize = 4;

/// How often a node dials again the members it keeps tickets of that it is
/// not connected to, after the device opens, and for how many rounds:
/// 5 minutes in all.
const RECONNECT_EVERY: Duration = Duration::from_secs(10);
const RECONNECT_ROUNDS: usize = 30;

/// A pairing the node hosts: the space, the offer, and the person's
/// confirmation of the code.
type Confirm = Box<dyn FnOnce(String, String) -> frasil_store::BoxFuture<'static, bool> + Send>;

struct Hosting {
    space: EventId,
    offer: Offer,
    display: String,
    confirm: Confirm,
    done: tokio::sync::oneshot::Sender<Result<EventId>>,
}

/// A nearby exchange its caller runs on the next nearby connection, such as
/// a person's new device's admission (admission.md, "A person's new
/// device", "Over a direct connection").
pub(crate) type NearbyHost =
    Box<dyn FnOnce(Node, Connection) -> frasil_store::BoxFuture<'static, ()> + Send>;

/// A setup the node awaits: the device's setup state, and where the
/// outcome goes.
struct AwaitingSetup {
    headless: frasil_admission::setup::HeadlessDevice,
    done: tokio::sync::oneshot::Sender<Result<crate::pairing::Provisioned>>,
}

/// A running member connection: the other side's endpoint key, and where
/// further spaces to attach on it go.
type Running = ([u8; 32], mpsc::UnboundedSender<EventId>);

/// A dial: an endpoint key, and the addresses and relays it is dialed at.
type Dial = ([u8; 32], Vec<SocketAddr>, Vec<String>);

struct Shared {
    device: Engine,
    endpoint: Endpoint,
    /// What the member endpoint bound with: the pairing endpoints bind
    /// beside it, on the same networks and relays.
    config: Config,
    hosting: Mutex<Option<Hosting>>,
    nearby: Mutex<Option<NearbyHost>>,
    setup: Mutex<Option<AwaitingSetup>>,
    /// The member connections running, by number: the other side's
    /// endpoint key, and where further spaces to attach go.
    connections: Mutex<BTreeMap<u64, Running>>,
    next_connection: AtomicU64,
    /// The dials under way: each endpoint key with the addresses and
    /// relays it is dialed at.
    dialing: Mutex<BTreeSet<Dial>>,
    discovering: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// A device's member endpoint and its connections.
#[derive(Clone)]
pub struct Node {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("endpoint", &self.shared.endpoint.key())
            .finish_non_exhaustive()
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

fn failed(error: impl core::fmt::Display) -> Error {
    Error::Connection(error.to_string())
}

impl Node {
    /// Binds a member endpoint for a device under a fresh key, accepting
    /// member and nearby connections, with `config` naming its sockets and
    /// relays; `config`'s own key is replaced.
    ///
    /// # Errors
    ///
    /// The binding's.
    pub async fn bind(device: Engine, config: impl FnOnce(Config) -> Config) -> Result<Self> {
        #[cfg(not(feature = "ext-next-endpoints"))]
        let key = device.platform().nonce::<32>()?;
        // A rotation takes the key announced as next (ext-next-endpoints.md,
        // "Rotating"), and the endpoint reads `NextEndpoint`.
        #[cfg(feature = "ext-next-endpoints")]
        let key = *device.rotate_member_endpoint().await?;
        let config = config(Config::new(key, &[Alpn::Member, Alpn::Nearby]));
        #[cfg(feature = "ext-next-endpoints")]
        let config = config.extensions(frasil_transport::frame::Extensions {
            next_endpoints: true,
            ..frasil_transport::frame::Extensions::NONE
        });
        let endpoint = Endpoint::bind(config.clone()).await.map_err(failed)?;
        let node = Self {
            shared: Arc::new(Shared {
                device,
                endpoint,
                config,
                hosting: Mutex::new(None),
                nearby: Mutex::new(None),
                setup: Mutex::new(None),
                connections: Mutex::new(BTreeMap::new()),
                next_connection: AtomicU64::new(0),
                dialing: Mutex::new(BTreeSet::new()),
                discovering: AtomicBool::new(false),
                tasks: Mutex::new(Vec::new()),
            }),
        };
        let accepting = node.clone();
        node.spawn(async move { accepting.accept_loop().await });
        let (dialer, learned) = mpsc::unbounded_channel();
        node.shared.device.links().set_dialer(dialer);
        let dialing = node.clone();
        node.spawn(async move { dialing.dial_learned(learned).await });
        Ok(node)
    }

    /// Dials each ticket another member's `Addresses` lists, attaching its
    /// space (transport.md, "The iroh binding", member addresses): the
    /// device's links hold each, at most 128, each for 10 seconds, and send
    /// an endpoint key for a space once while they hold it. Of two members
    /// that learn of each other at once, the one with the greater endpoint
    /// key waits 1 second, and then attaches on the connection the other
    /// dialed, if one formed.
    async fn dial_learned(&self, mut learned: mpsc::UnboundedReceiver<Learned>) {
        while let Some(Learned { space, ticket }) = learned.recv().await {
            let key = ticket.endpoint;
            if key == self.key() {
                continue;
            }
            let (addresses, relays) = dial_paths(&ticket);
            if self.key() > key && !self.connected_to(&key) {
                let node = self.clone();
                self.spawn(async move {
                    tokio::time::sleep(Duration::from_secs(CROSS_DIAL_WAIT_SECONDS)).await;
                    node.dial_once(key, addresses, relays, vec![space]);
                });
            } else {
                self.dial_once(key, addresses, relays, vec![space]);
            }
        }
    }

    /// Binds on IPv4 loopback alone, with no relay.
    ///
    /// # Errors
    ///
    /// The binding's.
    pub async fn loopback(device: Engine) -> Result<Self> {
        Self::bind(device, Config::loopback).await
    }

    /// The device.
    pub fn device(&self) -> &Engine {
        &self.shared.device
    }

    /// The member endpoint key.
    pub fn key(&self) -> [u8; 32] {
        self.shared.endpoint.key()
    }

    /// Registers the endpoint with further home relays, which its tickets
    /// name from then on.
    ///
    /// # Errors
    ///
    /// The binding's, for a relay URL that does not parse.
    pub async fn add_relays(&self, relays: &[String]) -> Result<()> {
        self.shared
            .endpoint
            .add_relays(relays)
            .await
            .map_err(failed)
    }

    /// A ticket of this endpoint: `Member` to dial it with the member ALPN,
    /// `Nearby` for pairing.
    pub fn ticket(&self, kind: TicketKind) -> Ticket {
        self.shared.endpoint.ticket(kind)
    }

    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let handle = tokio::spawn(task);
        self.shared
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(handle);
    }

    async fn accept_loop(&self) {
        while let Some(accepted) = self.shared.endpoint.accept().await {
            let Ok(connection) = accepted else {
                continue;
            };
            match connection.alpn() {
                Alpn::Member => {
                    let node = self.clone();
                    self.spawn(async move { node.serve(connection, Vec::new()).await });
                }
                Alpn::Nearby => {
                    // A device awaiting setup takes the administrator that
                    // dials it.
                    let setup = self
                        .shared
                        .setup
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    if let Some(setup) = setup {
                        let node = self.clone();
                        self.spawn(async move { node.provision(connection, setup).await });
                        continue;
                    }
                    let nearby = self
                        .shared
                        .nearby
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    if let Some(run) = nearby {
                        self.spawn(run(self.clone(), connection));
                        continue;
                    }
                    let hosting = self
                        .shared
                        .hosting
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    match hosting {
                        Some(hosting) => {
                            let node = self.clone();
                            self.spawn(async move { node.host(connection, hosting).await });
                        }
                        None => connection.close(frasil_transport::Code::Done),
                    }
                }
                Alpn::Peer => connection.close(frasil_transport::Code::PurposeViolation),
            }
        }
    }

    async fn serve(&self, connection: Connection, spaces: Vec<EventId>) {
        let peer = connection.peer();
        let number = self.shared.next_connection.fetch_add(1, Ordering::Relaxed);
        let (further, receiver) = mpsc::unbounded_channel();
        self.shared
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(number, (peer, further));
        let _ = run_member_with(
            self.shared.device.clone(),
            connection,
            spaces,
            Some(receiver),
        )
        .await;
        self.shared
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&number);
    }

    /// Attaches a space on every member connection with an endpoint key.
    /// `false` when the node holds none.
    fn attach_on(&self, key: &[u8; 32], space: EventId) -> bool {
        let connections = self
            .shared
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut any = false;
        for (peer, further) in connections.values() {
            if peer == key {
                any = true;
                let _ = further.send(space);
            }
        }
        any
    }

    /// Dials an endpoint key in the background, once at a time at the same
    /// addresses and relays, attaching these spaces; or attaches them on
    /// the connection the node holds with it already. A dial at other
    /// paths goes ahead beside one under way, so that a key dialed where
    /// it no longer listens, such as a member's announced key at its
    /// earlier addresses (ext-next-endpoints.md, "Reconnecting"), does not
    /// hold back a dial where it does.
    fn dial_once(
        &self,
        key: [u8; 32],
        addresses: Vec<SocketAddr>,
        relays: Vec<String>,
        spaces: Vec<EventId>,
    ) {
        if key == self.key() {
            return;
        }
        if self.connected_to(&key) {
            for space in spaces {
                self.attach_on(&key, space);
            }
            return;
        }
        let dial: Dial = (key, addresses, relays);
        if !self
            .shared
            .dialing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(dial.clone())
        {
            return;
        }
        let node = self.clone();
        self.spawn(async move {
            let (_, addresses, relays) = &dial;
            let dialed = node
                .shared
                .endpoint
                .connect(&key, addresses, relays, Alpn::Member)
                .await;
            node.shared
                .dialing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&dial);
            if let Ok(connection) = dialed {
                node.serve(connection, spaces).await;
            }
        });
    }

    async fn host(&self, connection: Connection, hosting: Hosting) {
        let ticket = self.ticket(TicketKind::Member);
        let pairing = crate::pairing::host_pairing(
            &self.shared.device,
            &connection,
            hosting.space,
            hosting.offer,
            &hosting.display,
            &ticket,
            hosting.confirm,
        );
        let result = within_pairing_deadline(&connection, pairing).await;
        let _ = hosting.done.send(result);
    }

    async fn provision(&self, connection: Connection, mut setup: AwaitingSetup) {
        let setting_up =
            crate::pairing::serve_setup(&self.shared.device, &connection, &mut setup.headless);
        let result = within_pairing_deadline(&connection, setting_up).await;
        // A connection that ended before an Offer bound the device, or whose
        // Offer's MAC failed, changes nothing: the device awaits the next
        // administrator (admission.md, 3.8 Setup).
        if result.is_err()
            && matches!(
                setup.headless.state(),
                frasil_admission::setup::SetupState::Waiting
            )
        {
            connection.close(frasil_transport::Code::Done);
            let mut slot = self
                .shared
                .setup
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if slot.is_none() {
                *slot = Some(setup);
                return;
            }
            drop(slot);
            let _ = setup.done.send(result);
            return;
        }
        let result = match result {
            Ok(provisioned) => self
                .dial(&provisioned.ticket, vec![provisioned.space])
                .await
                .map(|()| provisioned),
            Err(error) => Err(error),
        };
        let _ = setup.done.send(result);
    }

    /// Awaits setup by a setup code (admission.md, "Setup"), for a device
    /// with no display: makes a setup secret, a request ID and an
    /// ephemeral X-Wing key, and returns the setup code's text to print or
    /// show, with a receiver of the outcome. The first administrator that
    /// dials this node's nearby ticket runs setup; once provisioned, the
    /// device dials the member ticket it was handed.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a display text that does not read;
    /// [`Error::NoRandomness`].
    pub fn await_setup(
        &self,
        display: &str,
    ) -> Result<(
        String,
        tokio::sync::oneshot::Receiver<Result<crate::pairing::Provisioned>>,
    )> {
        let device = &self.shared.device;
        let platform = device.platform();
        let headless = frasil_admission::setup::HeadlessDevice::new_with(
            device.signer(),
            display,
            frasil_admission::setup::SetupDraw {
                secret: platform.draw()?,
                request: platform.nonce()?,
                eph_seed: platform.draw()?,
            },
        )
        .map_err(Error::class)?;
        let text = headless.setup_code().text();
        let (done, receiver) = tokio::sync::oneshot::channel();
        *self
            .shared
            .setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(AwaitingSetup { headless, done });
        Ok((text, receiver))
    }

    /// Sets up a device by its setup code (admission.md, "Setup"): dials
    /// its nearby ticket from a fresh endpoint key, checks its Hello
    /// against the scanned code, and grants it `offer` in `space`. Returns
    /// the admitting event.
    ///
    /// # Errors
    ///
    /// `SetupMismatch` and admission.md's classes; the connection's
    /// failure.
    pub async fn set_up(
        &self,
        nearby: &Ticket,
        setup_code: &str,
        space: EventId,
        offer: Offer,
        display: &str,
    ) -> Result<EventId> {
        let scanned = frasil_admission::setup::SetupCode::read(setup_code).map_err(Error::class)?;
        let dialer = self.pairing_endpoint().await?;
        let connection = dialer.dial(nearby).await.map_err(failed)?;
        let ticket = self.ticket(TicketKind::Member);
        let result = crate::pairing::administer_setup(
            &self.shared.device,
            &connection,
            space,
            offer,
            &scanned,
            display,
            &ticket,
        )
        .await;
        dialer.close().await;
        result
    }

    /// Hosts the next nearby pairing: the first newcomer that connects with
    /// the nearby ALPN runs the exchange for `space`, and is granted
    /// `offer` once `confirm` approves the code. Returns a receiver of the
    /// admitting event.
    pub fn host_pairing<F>(
        &self,
        space: EventId,
        offer: Offer,
        display: &str,
        confirm: impl FnOnce(String, String) -> F + Send + 'static,
    ) -> tokio::sync::oneshot::Receiver<Result<EventId>>
    where
        F: std::future::Future<Output = bool> + Send + 'static,
    {
        let (done, receiver) = tokio::sync::oneshot::channel();
        // One pairing at a time: this one replaces any other.
        self.shared
            .nearby
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        *self
            .shared
            .hosting
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Hosting {
            space,
            offer,
            display: display.to_owned(),
            confirm: Box::new(move |code, newcomer| Box::pin(confirm(code, newcomer))),
            done,
        });
        receiver
    }

    /// Hosts the next nearby exchange with `run`, which takes the node and
    /// the connection the first newcomer dials; it replaces any pairing
    /// hosted before.
    pub(crate) fn host_nearby(&self, run: NearbyHost) {
        self.shared
            .hosting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        *self
            .shared
            .nearby
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(run);
    }

    /// Joins a space through a host's nearby ticket, then dials the member
    /// ticket the host handed over and keeps that member connection.
    ///
    /// # Errors
    ///
    /// admission.md's classes; the connection's failure.
    pub async fn join<F>(
        &self,
        nearby: &Ticket,
        display: &str,
        confirm: impl FnOnce(String, String) -> F,
    ) -> Result<crate::pairing::Joined>
    where
        F: std::future::Future<Output = bool>,
    {
        let pairing = self.pairing_endpoint().await?;
        let connection = pairing.dial(nearby).await.map_err(failed)?;
        let joined =
            crate::pairing::join_nearby(&self.shared.device, &connection, display, confirm).await;
        pairing.close().await;
        let joined = joined?;
        self.dial(&joined.ticket, vec![joined.space]).await?;
        Ok(joined)
    }

    /// An endpoint for one pairing session, under a fresh key
    /// (transport.md, "Endpoint keys"), bound beside the member endpoint:
    /// on its networks, and with its relays, so that it reaches a host
    /// through a relay when no direct path does.
    async fn pairing_endpoint(&self) -> Result<Endpoint> {
        let key = self.shared.device.platform().nonce::<32>()?;
        let config = self
            .shared
            .config
            .beside(key, &[])
            .relays(self.shared.endpoint.relays());
        Endpoint::bind(config).await.map_err(failed)
    }

    /// Dials a member ticket and keeps the member connection, attaching
    /// these spaces.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn dial(&self, ticket: &Ticket, spaces: Vec<EventId>) -> Result<()> {
        let connection = self.shared.endpoint.dial(ticket).await.map_err(failed)?;
        let node = self.clone();
        self.spawn(async move { node.serve(connection, spaces).await });
        Ok(())
    }

    /// Whether the node holds a member connection with an endpoint key.
    pub fn connected_to(&self, key: &[u8; 32]) -> bool {
        self.shared
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .any(|(peer, _)| peer == key)
    }

    /// Dials each member the device keeps a ticket of and is not connected
    /// to, attaching the spaces that keep it (transport.md,
    /// "Reconnecting"); attaches them on a connection it holds already.
    pub async fn reconnect(&self) {
        let Ok(kept) = self.shared.device.remembered_endpoints().await else {
            return;
        };
        let mut by_key: BTreeMap<[u8; 32], (Ticket, Vec<EventId>)> = BTreeMap::new();
        for (space, ticket) in kept {
            by_key
                .entry(ticket.endpoint)
                .or_insert_with(|| (ticket, Vec::new()))
                .1
                .push(space);
        }
        for (key, (ticket, spaces)) in by_key {
            let (addresses, relays) = dial_paths(&ticket);
            self.dial_once(key, addresses, relays, spaces);
        }
    }

    /// Dials the members the device keeps tickets of now, and again every
    /// 10 seconds for 5 minutes while one does not answer
    /// ([`Node::reconnect`]).
    pub fn keep_reconnecting(&self) {
        let node = self.clone();
        self.spawn(async move {
            for _ in 0..RECONNECT_ROUNDS {
                node.reconnect().await;
                tokio::time::sleep(RECONNECT_EVERY).await;
            }
        });
    }

    /// Switches local discovery on (transport.md, "Member announcements"):
    /// announces up to 4 open spaces every 2 seconds, with jitter, and
    /// dials each candidate an announcement it opens gives.
    ///
    /// # Errors
    ///
    /// The local-network socket's.
    pub fn discover(&self, config: LanConfig) -> Result<()> {
        if self.shared.discovering.load(Ordering::SeqCst) {
            return Ok(());
        }
        let socket = Arc::new(LanSocket::bind(config).map_err(failed)?);
        if self.shared.discovering.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let port = self
            .shared
            .endpoint
            .local_addresses()
            .first()
            .map(SocketAddr::port)
            .ok_or_else(|| Error::Connection("the endpoint has no socket".into()))?;
        let announcer = self.clone();
        let announcing = socket.clone();
        self.spawn(async move {
            loop {
                let states = announcer
                    .shared
                    .device
                    .announced_states(ANNOUNCED_SPACES)
                    .await;
                for (_, secret) in &states {
                    let _ = announcing.announce(secret, &announcer.key(), port).await;
                }
                let wait = next_announcement().unwrap_or(std::time::Duration::from_secs(2));
                tokio::time::sleep(wait).await;
            }
        });
        let listener = self.clone();
        self.spawn(async move {
            // The candidates kept, by endpoint key, address and space: at
            // most 128, each for 10 seconds (transport.md, 3.16). A packet
            // that names one already kept, such as a replay, dials nothing,
            // and none is kept past the bound, so announcements start at
            // most 128 dials every 10 seconds.
            type Candidate = ([u8; 32], SocketAddr, EventId);
            let mut candidates: Vec<(Candidate, Instant)> = Vec::new();
            loop {
                let Ok((packet, source)) = socket.receive().await else {
                    continue;
                };
                let open = listener.shared.device.listened_states().await;
                for (space, secrets) in open {
                    let Ok(candidate) = open_member(&packet, source, &secrets) else {
                        continue;
                    };
                    if candidate.endpoint == listener.key() {
                        continue;
                    }
                    let now = Instant::now();
                    candidates.retain(|(_, seen)| now.saturating_duration_since(*seen) < KEEP);
                    let kept = (candidate.endpoint, candidate.address, space);
                    if candidates.len() >= MAX_CANDIDATES
                        || candidates.iter().any(|(other, _)| *other == kept)
                    {
                        continue;
                    }
                    candidates.push((kept, now));
                    // A member already connected attaches the space on
                    // that connection.
                    listener.dial_once(
                        candidate.endpoint,
                        vec![candidate.address],
                        Vec::new(),
                        vec![space],
                    );
                }
            }
        });
        Ok(())
    }

    /// Runs every space's heals and cascades ([`Engine::maintain_all`])
    /// every `rotation_step`, while the node lives (keys.md, "The rank and
    /// the delay").
    pub fn keep_maintaining(&self) {
        let node = self.clone();
        self.spawn(async move {
            let step = std::time::Duration::from_secs(crate::maintenance::rotation_step().max(1));
            loop {
                let _ = node.shared.device.maintain_all().await;
                tokio::time::sleep(step).await;
            }
        });
    }

    /// Closes the endpoint and every connection on it, and stops the
    /// node's announcements, dials and upkeep.
    pub async fn close(&self) {
        let tasks: Vec<JoinHandle<()>> = self
            .shared
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        for task in tasks {
            task.abort();
        }
        self.shared.endpoint.close().await;
    }
}

/// A ticket's direct addresses and relays, as the endpoint dials them.
fn dial_paths(ticket: &Ticket) -> (Vec<SocketAddr>, Vec<String>) {
    let addresses = ticket
        .addresses
        .iter()
        .map(|address| match *address {
            frasil_transport::ticket::Address::V4(ip, port) => {
                SocketAddr::from((std::net::Ipv4Addr::from(ip), port))
            }
            frasil_transport::ticket::Address::V6(ip, port) => {
                SocketAddr::from((std::net::Ipv6Addr::from(ip), port))
            }
        })
        .collect();
    (addresses, ticket.relays.clone())
}

impl Engine {
    /// Keeps the member ticket at which this device reached a member of a
    /// space, in the space's `endpoint` table (transport.md,
    /// "Reconnecting"; at-rest.md, "Tables"), unless it keeps it already.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn remember_endpoint(
        &self,
        space: &EventId,
        member: &DeviceId,
        ticket: &Ticket,
    ) -> Result<()> {
        let value = TableValue::Endpoint(ticket.cbor());
        let mut state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(());
        }
        let kept = state.vault.scan(&space.0, Table::Endpoint).await?;
        if kept
            .iter()
            .any(|(item, kept)| item[..] == member.0[..] && *kept == value)
        {
            return Ok(());
        }
        let mut batch = Batch::default();
        state
            .vault
            .put(&mut batch, &space.0, Table::Endpoint, &member.0, &value)?;
        state.vault.commit(batch).await?;
        drop(state);
        self.links().changed();
        Ok(())
    }

    /// The member tickets the device keeps in a space's `endpoint` table,
    /// by member: each at which it last reached that member, and never one
    /// it only learned from another member (transport.md, "Reconnecting"
    /// and "The iroh binding", member addresses).
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn kept_endpoints(&self, space: &EventId) -> Result<Vec<(DeviceId, Ticket)>> {
        let state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (item, value) in state.vault.scan(&space.0, Table::Endpoint).await? {
            if let (TableValue::Endpoint(bytes), Ok(member)) =
                (value, <[u8; 32]>::try_from(&item[..]).map(DeviceId))
                && let Ok(ticket) = Ticket::read_cbor(&bytes)
                && ticket.kind == TicketKind::Member
            {
                out.push((member, ticket));
            }
        }
        Ok(out)
    }

    /// The learned tickets the device holds now for a space, with the
    /// member each names: those other members' `Addresses` listed that it
    /// dialed, at most 128, each for 10 seconds. None of them is kept at
    /// rest; one is kept only once a dial to it is admitted (transport.md,
    /// "The iroh binding", member addresses, "Keeping").
    pub fn learned_tickets(&self, space: &EventId) -> Vec<(DeviceId, Ticket)> {
        self.links().held(space, Instant::now())
    }

    /// What this device lists in an `Addresses` to `recipient` for a
    /// space (transport.md, "The iroh binding", member addresses): first
    /// each member an admitted attach of the space reaches, at the ticket
    /// its connection reaches it at, then each member it keeps a ticket of;
    /// never the recipient or this device, and only devices that reach the
    /// space in its current view. To a guest, each ticket keeps only its
    /// local-network addresses and no relay, and one left with no address
    /// is left out ("Sending to a guest").
    pub(crate) async fn address_list(
        &self,
        space: &EventId,
        recipient: &DeviceId,
    ) -> Vec<(DeviceId, Ticket)> {
        let me = self.device_id();
        let guest = matches!(
            self.standing(space, recipient).await,
            Standing::Reaches(Path::Guest)
        );
        let reached = self.links().reached(space);
        let kept = self.kept_endpoints(space).await.unwrap_or_default();
        let others: Vec<(DeviceId, Ticket)> = kept
            .into_iter()
            .filter(|(member, _)| !reached.contains_key(member))
            .collect();
        let mut listed = Vec::new();
        for (member, ticket) in reached.into_iter().chain(others) {
            if member == *recipient || member == me {
                continue;
            }
            if !matches!(self.standing(space, &member).await, Standing::Reaches(_)) {
                continue;
            }
            if !guest {
                listed.push((member, ticket));
            } else if let Some(ticket) = for_guest(&ticket) {
                listed.push((member, ticket));
            }
        }
        listed
    }

    /// The member tickets the device keeps, by space, of members still in
    /// each space; the tickets of members whose membership ended are
    /// deleted (transport.md, "Reconnecting"). With
    /// `ext-next-endpoints`, each kept ticket is followed by its announced
    /// ticket, when the member announced another key, and a membership
    /// that ended also deletes the key announced and withdraws this
    /// device's own (ext-next-endpoints.md, "Reconnecting", "Announcing").
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn remembered_endpoints(&self) -> Result<Vec<(EventId, Ticket)>> {
        let mut kept = Vec::new();
        {
            let state = self.lock().await;
            let spaces: Vec<EventId> = state.replicas.keys().copied().collect();
            for space in spaces {
                for (item, value) in state.vault.scan(&space.0, Table::Endpoint).await? {
                    if let (TableValue::Endpoint(bytes), Ok(member)) =
                        (value, <[u8; 32]>::try_from(&item[..]).map(DeviceId))
                    {
                        kept.push((space, member, bytes));
                    }
                }
            }
        }
        let mut out = Vec::new();
        let mut ended = Vec::new();
        for (space, member, bytes) in kept {
            match self.standing(&space, &member).await {
                Standing::Ended(_) | Standing::Forked => ended.push((space, member)),
                _ => {
                    if let Ok(ticket) = Ticket::read_cbor(&bytes)
                        && ticket.kind == TicketKind::Member
                    {
                        // Only for a member not reached in the space now,
                        // so that a key not yet taken is not asked for again
                        // and again.
                        #[cfg(feature = "ext-next-endpoints")]
                        let announced = if self.links().reaches(&space, &member) {
                            None
                        } else {
                            self.announced(&space, &member).await?
                        }
                        .and_then(|key| {
                            frasil_transport::ext_next_endpoints::announced_ticket(&ticket, &key)
                        });
                        out.push((space, ticket));
                        #[cfg(feature = "ext-next-endpoints")]
                        out.extend(announced.map(|ticket| (space, ticket)));
                    }
                }
            }
        }
        if !ended.is_empty() {
            let mut state = self.lock().await;
            let mut batch = Batch::default();
            for (space, member) in &ended {
                state
                    .vault
                    .delete(&mut batch, &space.0, Table::Endpoint, &member.0);
                #[cfg(feature = "ext-next-endpoints")]
                state
                    .vault
                    .delete(&mut batch, &space.0, Table::Announced, &member.0);
            }
            state.vault.commit(batch).await?;
            drop(state);
            self.links().changed();
            #[cfg(feature = "ext-next-endpoints")]
            self.withdraw_next_endpoint().await?;
        }
        Ok(out)
    }
}

/// Runs one nearby pairing within `pairing_deadline` (transport.md, 3.16);
/// past it the connection closes `timeout`.
async fn within_pairing_deadline<T>(
    connection: &Connection,
    pairing: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(frasil_iroh::PAIRING_DEADLINE, pairing).await {
        Ok(result) => result,
        Err(_) => {
            connection.close(frasil_transport::Code::Timeout);
            Err(Error::Class("Timeout"))
        }
    }
}
