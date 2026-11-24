//! Device-to-peer connections (transport.md, sections 3.10 to 3.12, 3.15
//! and 3.16; peers.md, "Presenting a credential").
//!
//! A device reaches an always-on peer over the server binding's WebSocket
//! ([`connect_server`]), over a WebSocket the application supplies, such
//! as a browser's ([`socket::connect_socket`]), or over the iroh binding's
//! `frasil/p1/peer` ([`connect_iroh`]). Either way the connection runs, for
//! space traffic:
//!
//! 1. **The handshake.** The peer sends `PeerHello`; the device checks its
//!    protocol and revision and answers `Hello` with a fresh nonce and
//!    purpose 1. The connection's `binding` follows from the channel, both
//!    nonces and the purpose. The device never sends its keys or its
//!    device ID.
//! 2. **Presents.** For each space, the read credential of its current
//!    state, and the upload key when it writes, each proved over the
//!    binding. A merged state the peer has no entry for is first told to
//!    it by a merge statement, signed with every input's upload seed; a
//!    device that cannot sign one presents its inputs' credentials. A space
//!    the peer does not host is created by storing its genesis first.
//!    Whenever the device's current state changes, it presents again.
//! 3. **Sync**, once granted: units.md's sync in `Sync` messages scoped by
//!    the space, on one sync stream per space over iroh, on the WebSocket
//!    otherwise; `Subscribe` for live delivery under the live right; the
//!    device's new events as they are placed. The peer's `Ack` makes the
//!    device's events durable.
//! 4. **Refused events.** An `EventRefused` names one event the peer did
//!    not acknowledge: it stays in the outbox, not durable at this peer.
//!    `rate_limited` is retried later; `conflict` is a fork, reported.

use crate::device::Engine;
use crate::error::{Error, Result};
use crate::outbox::Acknowledger;
use crate::replica::Replica;
use crate::sync::SyncSession;
use frasil_adapter::Locator;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{read_credential, upload_key};
use frasil_peers::merge::MergeStatement;
use frasil_store::BoxFuture;
use frasil_store::store::MaybeSend;
use frasil_transport::Channel;
use frasil_transport::codes::Right;
use frasil_transport::frame::{ConnectionKind, Message, MessageType};
use frasil_transport::messages::{Accepted, EventRefused, Granted, Merge, Refused, Scope, Sync};
use frasil_transport::peer::{Credential, DeviceSide, Purpose};
use frasil_units::messages::{Message as UnitMessage, Received, StreamWriter, SyncMessage};
use frasil_units::stream::StreamId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

/// How long a device waits for the peer's `PeerHello`.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// How long a device waits before it offers again an event refused with
/// `rate_limited`.
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// How long a connection the device closes stays open for a
/// `LibraryAttach` it sent: its answer, and the acknowledgement of the
/// genesis that follows a create.
#[cfg(feature = "ext-libraries")]
const ATTACH_DRAIN: Duration = Duration::from_secs(5);

/// The longest wait before a refused read credential is presented again
/// (transport.md, "Presenting credentials").
const PRESENT_RETRY_MAX: Duration = Duration::from_secs(30);

/// The first wait before a refused read credential is presented again:
/// `present_retry`.
fn present_retry() -> Duration {
    Duration::from_secs(
        frasil_base::time::Timer::PresentRetry
            .spec()
            .default
            .unwrap_or(1),
    )
}

/// What a peer connection has done, for the application to show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerStatus {
    /// The rights granted, by space.
    pub granted: BTreeMap<EventId, BTreeSet<Right>>,
    /// Requests refused: the space and the reason code.
    pub refused: Vec<(EventId, String)>,
    /// Events refused: the space, the event and the reason code. The event
    /// stays in the outbox.
    pub refused_events: Vec<(EventId, EventId, String)>,
    /// Forks the peer reported (`conflict`): the space and the event, each
    /// once, however often the peer refused the event.
    pub forks: Vec<(EventId, EventId)>,
    /// Fetch keys the peer registered as recovery entries, by space
    /// (peers.md, "Presenting a credential", recovery entries).
    pub registered: BTreeSet<(EventId, [u8; 32])>,
    /// Spaces in which the device has held every head the peer sent under
    /// the fetch right: it fetched all the peer served, at least once.
    pub caught_up: BTreeSet<EventId>,
    /// Spaces this connection created at the peer.
    pub created: Vec<EventId>,
    /// Merged states the peer accepted a merge statement of.
    pub merges: Vec<(EventId, RotationSet)>,
    /// The peer's index of each stream asked for by `StreamWant`: its
    /// latest snapshot unit and each writer's latest unit.
    pub stream_heads: BTreeMap<(EventId, StreamId), (Option<EventId>, Vec<StreamWriter>)>,
    /// Streams whose `StreamHeads` named less than this device holds
    /// (`Withheld`, units.md, "Sync", by stream).
    pub withheld: BTreeSet<(EventId, StreamId)>,
    /// Loss detected against this peer, by space and class (units.md,
    /// 3.13 "Detected loss"): `Withheld` or `RolledBack`.
    pub lost: BTreeSet<(EventId, crate::outbox::LossClass)>,
    /// Objects being fetched on this connection: the stored bytes the
    /// device holds of each so far, whichever chunks came first, and the
    /// stored length once known. An object is here from the first of its
    /// bytes the device holds, while a fetch of it runs by slices or
    /// chunks of it are awaited on a stream, and no longer.
    pub fetching: BTreeMap<Locator, (u64, Option<u64>)>,
    /// Holds the peer accepted (ext-libraries.md, 3.7 Registering a
    /// hold): the holding space and the object's locator.
    pub held: BTreeSet<(EventId, Locator)>,
    /// Why the connection ended, once it has.
    pub closed: Option<String>,
    /// Whether the connection is waiting to connect again, or connecting
    /// again, after the peer closed it with `reconnect` (transport.md,
    /// "Reconnecting elsewhere").
    pub reconnecting: bool,
    /// How many times the connection has connected again after a
    /// `reconnect` close.
    pub reconnects: u64,
    /// How many attempts to connect again it has made, those that failed
    /// among them.
    pub reconnect_attempts: u64,
    /// The latest attempt's bound of the random wait, and the wait drawn
    /// under it.
    pub reconnect_wait: Option<(Duration, Duration)>,
}

impl PeerStatus {
    /// Notes a fork the peer reported. The same event offered again, on
    /// the grant and again in answer to the peer's `Heads` (units.md,
    /// "Sync", the exchange), is refused again; it is one fork.
    fn note_fork(&mut self, space: EventId, event: EventId) {
        if !self.forks.contains(&(space, event)) {
            self.forks.push((space, event));
        }
    }
}

/// A running device-to-peer connection.
#[derive(Debug)]
pub struct PeerHandle {
    status: Arc<Mutex<PeerStatus>>,
    commands: mpsc::UnboundedSender<Command>,
    by: Acknowledger,
    /// Set once the connection is to close, so that an upload in progress
    /// stops before its next slice rather than when it ends.
    closing: Arc<AtomicBool>,
}

impl PeerHandle {
    /// What the connection has done so far.
    pub fn status(&self) -> PeerStatus {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The acknowledger this peer's acknowledgements are kept under.
    pub fn acknowledger(&self) -> Acknowledger {
        self.by
    }

    /// Presents a further space on this connection; the peer then links
    /// the spaces of the connection (transport.md, section 3.11).
    pub fn attach(&self, space: EventId) {
        let _ = self.commands.send(Command::Attach(space));
    }

    /// Offers the space's events not yet durable at this peer again: after
    /// an administration connection stored the twins they cite.
    pub fn reoffer(&self, space: EventId) {
        let _ = self.commands.send(Command::Reoffer(space));
    }

    /// Syncs a space again once its pause ended: offers its heads, as at
    /// the start, and fetches what it lacks.
    pub(crate) fn resume(&self, space: EventId) {
        let _ = self.commands.send(Command::Resume(space));
    }

    /// Presents a further space on this connection only to find out
    /// whether the peer hosts it: a peer that does not is never asked to
    /// create it, and its `no_library` is reported as other refusals are
    /// (peers.md, "Refusal codes": `moved`, the device finds the space's
    /// new peer).
    pub fn seek(&self, space: EventId) {
        let _ = self.commands.send(Command::Seek(space));
    }

    /// Uploads an object before any unit names it. The answer is whether
    /// the peer holds it whole, by its own acknowledgement.
    pub fn upload(&self, space: EventId, locator: Locator) -> tokio::sync::oneshot::Receiver<bool> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let _ = self.commands.send(Command::Upload(space, locator, reply));
        answer
    }

    /// Fetches again the objects the space needs that the device lacks:
    /// the newcomer's snapshot it awaits, above all, which may reach the
    /// peer after the welcome or the drop that names it.
    pub fn fetch(&self, space: EventId) {
        let _ = self.commands.send(Command::Fetch(space));
    }

    /// Uploads again the objects this device put in a space that no peer
    /// is known to hold and no unit waiting to be sent names, so that the
    /// peer answers whether it holds each (at-rest.md, "Retention", an
    /// object the device put). A device calls it at its upkeep.
    pub fn offer_puts(&self, space: EventId) {
        let _ = self.commands.send(Command::OfferPuts(space));
    }

    /// Asks the peer for a stream's units from its latest snapshot
    /// (units.md, "Sync", by stream): the peer answers `StreamHeads`, then
    /// the snapshot unit and the units after its cover.
    pub fn want_stream(&self, space: EventId, stream: StreamId) {
        let _ = self.commands.send(Command::WantStream(space, stream));
    }

    /// Closes the connection. An object upload in progress stops before
    /// its next slice; the next connection goes on from what the peer
    /// holds.
    pub fn close(&self) {
        self.closing.store(true, Ordering::Release);
        let _ = self.commands.send(Command::Close);
    }

    /// Attaches a space to a library with the ticket the device holds for
    /// it (ext-libraries.md, 3.3 Attaching): a create or an import before
    /// the genesis is stored, a move of a space the peer hosts.
    #[cfg(feature = "ext-libraries")]
    pub fn library(&self, space: EventId) {
        let _ = self.commands.send(Command::Library(space));
    }

    /// Registers a hold of an object for a space (ext-libraries.md, 3.7
    /// Registering a hold), once the connection holds the space's store
    /// right; the answer goes to [`holds`]' waiters.
    #[cfg(feature = "ext-libraries")]
    pub(crate) fn hold(&self, ask: holds::HoldAsk) {
        let _ = self.commands.send(Command::Hold(ask));
    }

    /// Sends a mailbox message and waits for its answer: the items of a
    /// `MailboxGet`, none for a put or a delete the peer accepted, or the
    /// code of a refusal. An invite drop's placement or delete waits until
    /// the connection holds the space's store right.
    pub(crate) async fn mailbox(&self, ask: MailboxAsk) -> MailboxAnswer {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if self.commands.send(Command::Mailbox(ask, reply)).is_err() {
            return Err(CONNECTION_ENDED.into());
        }
        answer
            .await
            .unwrap_or_else(|_| Err(CONNECTION_ENDED.into()))
    }
}

/// A mailbox message to a peer (transport.md, "Mailboxes").
#[derive(Debug, Clone)]
pub(crate) enum MailboxAsk {
    /// `MailboxPut` of an exchange mailbox, kind 1 (admission.md,
    /// "Exchange mailboxes").
    Exchange {
        /// The mailbox's address.
        address: [u8; 32],
        /// The admission message.
        item: Vec<u8>,
    },
    /// `MailboxGet` of an exchange mailbox, after an item ID. This
    /// device's own device mailbox is never collected on a connection that
    /// presents its spaces: only on a [`Bare`] one ([`Bare::collect_own`];
    /// transport.md, 3.12 What a peer learns of a device).
    Collect {
        /// The mailbox's address.
        address: [u8; 32],
        /// The last item ID collected.
        after: Option<[u8; 16]>,
    },
    /// `MailboxPut` of kind 4, an invite drop, under the space's store
    /// right (ext-invite-links.md, "The drop and its messages").
    #[cfg(feature = "ext-invite-links")]
    DropPut {
        /// The space.
        space: EventId,
        /// The drop's address.
        address: [u8; 32],
        /// The drop.
        drop: Vec<u8>,
        /// Its lifetime, in seconds.
        lifetime: u64,
    },
    /// `MailboxDelete`, under the entry the drop was placed under.
    #[cfg(feature = "ext-invite-links")]
    DropDelete {
        /// The space.
        space: EventId,
        /// The drop's address.
        address: [u8; 32],
        /// The state whose upload key the connection presents first, when
        /// the device holds it: the drop's, which a rotation since may
        /// have left behind.
        under: Option<RotationSet>,
    },
    /// `MailboxGet` of kind 4: anyone may fetch a drop; it never sends
    /// `after`.
    #[cfg(feature = "ext-invite-links")]
    DropGet {
        /// The drop's address.
        address: [u8; 32],
    },
}

/// A mailbox message's answer when the connection ended before it came:
/// the peer may have closed it over the message.
pub(crate) const CONNECTION_ENDED: &str = "the connection ended";

/// A mailbox's items, each with its 16-byte ID, or the code of a refusal.
pub(crate) type MailboxAnswer = std::result::Result<Vec<([u8; 16], Vec<u8>)>, String>;

/// Where a mailbox message's answer goes.
type MailboxReply = tokio::sync::oneshot::Sender<MailboxAnswer>;

impl MailboxAsk {
    /// The space whose store right it needs, if any.
    fn needs_store(&self) -> Option<EventId> {
        match self {
            #[cfg(feature = "ext-invite-links")]
            Self::DropPut { space, .. } | Self::DropDelete { space, .. } => Some(*space),
            _ => None,
        }
    }

    /// The message, under request number `request`. None of these carries
    /// the device's keys or is signed with them.
    fn encode(&self, request: u64) -> Vec<u8> {
        use frasil_transport::mailbox::{Kind, MailboxGet, MailboxPut};
        match self {
            Self::Exchange { address, item } => MailboxPut {
                request,
                address: *address,
                item: item.clone(),
                kind: Kind::Exchange,
            }
            .encode(),
            Self::Collect { address, after } => MailboxGet {
                request,
                address: *address,
                after: *after,
                collector: None,
                kind: Kind::Exchange,
            }
            .encode(),
            #[cfg(feature = "ext-invite-links")]
            Self::DropPut {
                space,
                address,
                drop,
                lifetime,
            } => frasil_transport::ext_invite_links::DropPut {
                request,
                address: *address,
                drop: drop.clone(),
                space: space.0,
                lifetime: *lifetime,
            }
            .encode(),
            #[cfg(feature = "ext-invite-links")]
            Self::DropDelete { space, address, .. } => {
                frasil_transport::ext_invite_links::MailboxDelete {
                    request,
                    address: *address,
                    space: space.0,
                }
                .encode()
            }
            #[cfg(feature = "ext-invite-links")]
            Self::DropGet { address } => MailboxGet {
                request,
                address: *address,
                after: None,
                collector: None,
                kind: Kind::Drop,
            }
            .encode(),
        }
    }
}

impl PeerHandle {
    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.status().closed.is_some()
    }
}

enum Command {
    Attach(EventId),
    Reoffer(EventId),
    Resume(EventId),
    Seek(EventId),
    Fetch(EventId),
    /// Uploads again the objects this device put that no peer is known to
    /// hold.
    OfferPuts(EventId),
    Upload(EventId, Locator, tokio::sync::oneshot::Sender<bool>),
    WantStream(EventId, StreamId),
    Mailbox(MailboxAsk, MailboxReply),
    #[cfg(feature = "ext-libraries")]
    Library(EventId),
    #[cfg(feature = "ext-libraries")]
    Hold(holds::HoldAsk),
    Close,
}

/// Something a reader received, or a timer fired.
enum Incoming {
    Control(Message),
    Sync(EventId, Vec<u8>),
    Retry(EventId, EventId),
    /// The wait before presenting a refused state again is over.
    Present(EventId),
    /// `withholding_grace` has passed since the peer first answered
    /// `Missing` for a head statement's heads: ask it again.
    Restated(EventId),
    /// The transport was lost, with no close code of section 2.5.
    Closed(String),
    /// The peer closed the transport with a close code of section 2.5
    /// other than `reconnect`: the connection ends with it.
    Refused(String),
    /// The peer closed the connection with `reconnect` (transport.md,
    /// "Reconnecting elsewhere").
    Reconnect,
    /// A fetch by slices that ran beside the connection ended.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    Fetched(Fetched),
    /// The wait of a request whose fetch stopped is over: it is tried
    /// again.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    Again(crate::fetch::Request),
}

/// How a transport ended.
enum Ended {
    /// The device ended it, or failed itself.
    Stopped(String),
    /// It was lost, with no close code.
    Closed(String),
    /// The peer closed it with a close code other than `reconnect`.
    Refused(String),
    /// The peer closed it with `reconnect`.
    Reconnect,
}

/// Why a fresh transport's handshake did not complete.
enum Unopened {
    /// The transport was lost or never opened: an attempt that failed
    /// (transport.md, "Reconnecting elsewhere").
    Lost(Error),
    /// The peer closed it with a close code other than `reconnect`, or
    /// its `PeerHello` was refused: the connection ends.
    Refused(String),
}

impl From<Unopened> for Error {
    fn from(unopened: Unopened) -> Self {
        match unopened {
            Unopened::Lost(error) => error,
            Unopened::Refused(why) if is_other_revision(&why) => Error::OtherRevision,
            Unopened::Refused(why) => Error::Connection(why),
        }
    }
}

/// Whether a refusal's reason is the other end's revision: a
/// `PeerHello` this device refused as `RevisionMismatch`, or a close with
/// `revision_mismatch` (transport.md, "Close codes").
pub(crate) fn is_other_revision(why: &str) -> bool {
    why.contains("RevisionMismatch") || why.contains("revision_mismatch")
}

/// What a fresh transport gives: its wire, its channel, and the channel its
/// readers fill.
struct Opened {
    wire: Wire,
    channel: Channel,
    tx: mpsc::UnboundedSender<Incoming>,
    rx: mpsc::UnboundedReceiver<Incoming>,
    /// Set once the transport's readers end.
    ended: Arc<AtomicBool>,
}

/// Opens the transport again, to the same peer, after a `reconnect` close:
/// on the server binding through the same origin, on the iroh binding by
/// the same endpoint key (transport.md, "Reconnecting elsewhere").
/// [`Error::Unsupported`] when it cannot.
#[cfg(not(target_arch = "wasm32"))]
type Redial = Arc<dyn Fn() -> BoxFuture<'static, Result<Opened>> + Send + std::marker::Sync>;
/// [`Redial`] on `wasm32`, whose futures and sockets stay on one thread.
#[cfg(target_arch = "wasm32")]
type Redial = Arc<dyn Fn() -> BoxFuture<'static, Result<Opened>>>;

/// The first bound of the random wait before connecting again:
/// `reconnect_wait`.
fn reconnect_wait() -> Duration {
    Duration::from_secs(
        frasil_base::time::Timer::ReconnectWait
            .spec()
            .default
            .unwrap_or(5),
    )
}

/// The bound after an attempt that failed: doubled, to at most
/// `reconnect_wait_cap`.
fn reconnect_bound_after(bound: Duration) -> Duration {
    let cap = Duration::from_secs(
        frasil_base::time::Timer::ReconnectWaitCap
            .spec()
            .default
            .unwrap_or(60),
    );
    bound.saturating_mul(2).min(cap)
}

/// A wait uniform from 0 to `bound`, to the millisecond, from 8 random
/// bytes (transport.md, "Reconnecting elsewhere").
fn reconnect_wait_with(bound: Duration, random: [u8; 8]) -> Duration {
    let most = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(u64::from_be_bytes(random) % most.saturating_add(1))
}

/// How long a connection whose write failed waits for its reader to say
/// why the transport ended.
const READER_SETTLE: Duration = Duration::from_secs(1);

/// The reason code of a space the peer handed over (peers.md, "Refusal
/// codes").
fn moved_code() -> &'static str {
    frasil_peers::Code::Moved.name()
}

/// A request of the connection, by its number.
#[derive(Debug, Clone)]
enum Request {
    /// A present of a state's credential.
    Present {
        space: EventId,
        credential: Credential,
        state: RotationSet,
    },
    /// A merge statement of a state.
    Merge { space: EventId, state: RotationSet },
    /// A present of a fetch key, by a device that holds no state of the
    /// space (identity.md, "Recovery").
    Fetch { space: EventId },
    /// A `RegisterRecoveryEntry` of a fetch key.
    Register { space: EventId, key: [u8; 32] },
    /// A `LibraryAttach` (ext-libraries.md, 2.3 LibraryAttach).
    #[cfg(feature = "ext-libraries")]
    Library {
        space: EventId,
        purpose: frasil_libraries::Purpose,
        /// The signed ticket, sent again on the next transport if this one
        /// ends before the answer.
        signed: Vec<u8>,
    },
    /// A `HoldObject` (ext-libraries.md, 2.8 HoldObject).
    #[cfg(feature = "ext-libraries")]
    Hold(holds::HoldAsk),
}

/// One space on the connection.
struct Attached {
    session: SyncSession,
    rights: BTreeSet<Right>,
    /// The newest state whose read credential the peer granted.
    granted_state: Option<RotationSet>,
    /// States whose read credential is presented and not yet answered.
    pending: BTreeSet<RotationSet>,
    /// States the peer refused since it last acknowledged an event: it
    /// may hold no entry for them yet.
    tried: BTreeSet<RotationSet>,
    /// Whether sync has started.
    started: bool,
    /// Whether `Subscribe` was sent.
    subscribed: bool,
    /// At a partial replica, the streams the last `Subscribe` named
    /// (units.md, "Sync messages", `Subscribe` key 2).
    streams: Option<BTreeSet<StreamId>>,
    /// Whether the outbox was offered under the store right.
    offered_outbox: bool,
    /// Whether the objects this device put that no peer is known to hold
    /// were offered on this transport (at-rest.md, "Retention").
    offered_puts: bool,
    /// Whether this connection is creating the space at the peer.
    creating: bool,
    /// Merged states a merge statement was sent for.
    merged: BTreeSet<RotationSet>,
    /// States whose inputs' credentials were presented instead.
    inputs: BTreeSet<RotationSet>,
    /// Transfer tokens of the server binding: for fetching, for storing.
    fetch_token: Option<[u8; 32]>,
    store_token: Option<[u8; 32]>,
    /// Objects the peer holds whole, by its answer.
    uploaded: BTreeSet<Locator>,
    /// Objects being uploaded.
    uploading: BTreeSet<Locator>,
    /// Who waits to learn that the peer holds an object.
    upload_answers: BTreeMap<Locator, Vec<tokio::sync::oneshot::Sender<bool>>>,
    /// Units held back until the objects they name are uploaded (units.md,
    /// "What a writer does", item 7).
    deferred: Vec<(Vec<u8>, BTreeSet<Locator>)>,
    /// Objects the space's units name that are being fetched by slices,
    /// or wait to be.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    fetching: BTreeSet<Locator>,
    /// Objects whose slices from this peer failed their checks: not asked
    /// of it again on this connection (units.md, "Sync", objects). On a
    /// stream, the space's session keeps them.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    refused: BTreeSet<Locator>,
    /// States whose upload key was presented.
    uploads: BTreeSet<RotationSet>,
    /// Whether a fetch key was presented, for a space whose state the
    /// device does not hold yet.
    fetch_key: bool,
    /// Fetch keys sent in `RegisterRecoveryEntry`.
    registering: BTreeSet<[u8; 32]>,
    /// Whether the peer sent `Heads` since the connection held the fetch
    /// right: until then the heads it last sent may be catch-up's.
    heads_under_fetch: bool,
    /// The wait before the next present again of a refused state, once one
    /// was refused; doubled at each refusal.
    present_wait: Option<Duration>,
    /// Whether a present again is scheduled.
    present_scheduled: bool,
}

/// Where the connection's messages go.
enum Wire {
    #[cfg(feature = "server")]
    Server(server::Sink, server::Http),
    #[cfg(feature = "iroh")]
    Iroh(iroh::Wire),
    /// A socket the application supplies, and the peer's origin.
    #[cfg(feature = "server-socket")]
    Socket(Arc<dyn socket::ServerSocket>, String),
}

impl Wire {
    async fn control(&mut self, message: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "server")]
            Self::Server(sink, _) => sink.send(message).await,
            #[cfg(feature = "iroh")]
            Self::Iroh(wire) => wire.control(message).await,
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, _) => socket.send(message).await.map_err(Error::Connection),
        }
    }

    /// An `Ephemeral`: lossy, as a datagram on the iroh binding.
    #[cfg_attr(not(feature = "ephemeral"), allow(dead_code))]
    async fn ephemeral(&mut self, message: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "server")]
            Self::Server(sink, _) => sink.send(message).await,
            #[cfg(feature = "iroh")]
            Self::Iroh(wire) => wire.ephemeral(message).await,
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, _) => socket.send(message).await.map_err(Error::Connection),
        }
    }

    // The server binding scopes each message itself; only iroh opens a
    // stream per space.
    #[cfg_attr(not(feature = "iroh"), allow(unused_variables))]
    async fn sync(
        &mut self,
        space: EventId,
        message: &[u8],
        incoming: &mpsc::UnboundedSender<Incoming>,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "server")]
            Self::Server(sink, _) => sink.send(message).await,
            #[cfg(feature = "iroh")]
            Self::Iroh(wire) => wire.sync(space, message, incoming).await,
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, _) => socket.send(message).await.map_err(Error::Connection),
        }
    }

    /// Whether objects are fetched by slices over the HTTP chunk routes
    /// (transport.md, "Objects over HTTP"), and not by `ObjectWant`.
    fn by_slices(&self) -> bool {
        match self {
            #[cfg(feature = "server")]
            Self::Server(..) => true,
            #[cfg(feature = "iroh")]
            Self::Iroh(_) => false,
            #[cfg(feature = "server-socket")]
            Self::Socket(..) => true,
        }
    }

    /// The HTTP chunk routes of the binding, for a fetch that runs beside
    /// the connection.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    fn slice_routes(&self) -> Option<SliceRoutes> {
        match self {
            #[cfg(feature = "server")]
            Self::Server(_, http) => Some(SliceRoutes::Server(http.clone())),
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, origin) => {
                Some(SliceRoutes::Socket(socket.clone(), origin.clone()))
            }
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    fn close(&mut self) {
        match self {
            #[cfg(feature = "server")]
            Self::Server(sink, _) => sink.close(),
            #[cfg(feature = "iroh")]
            Self::Iroh(wire) => wire.close(),
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, _) => socket.close(),
        }
    }
}

/// Where a connection's tasks and timers run: tokio's runtime for the
/// bindings this crate opens itself; the application's for a socket it
/// supplies.
#[derive(Clone)]
enum Runtime {
    #[cfg(any(feature = "server", feature = "iroh"))]
    Tokio,
    #[cfg(feature = "server-socket")]
    Supplied(Arc<dyn socket::ServerSocket>),
}

impl Runtime {
    fn spawn(&self, task: impl std::future::Future<Output = ()> + MaybeSend + 'static) {
        match self {
            #[cfg(any(feature = "server", feature = "iroh"))]
            Self::Tokio => {
                tokio::spawn(task);
            }
            #[cfg(feature = "server-socket")]
            Self::Supplied(socket) => socket.spawn(Box::pin(task)),
        }
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        match self {
            #[cfg(any(feature = "server", feature = "iroh"))]
            Self::Tokio => Box::pin(tokio::time::sleep(duration)),
            #[cfg(feature = "server-socket")]
            Self::Supplied(socket) => socket.sleep(duration),
        }
    }
}

/// The connect route's URL for a peer's origin (transport.md, section
/// 3.15): `wss://` for HTTPS, `ws://` for HTTP to a loopback host only.
///
/// An origin is a scheme, a host and an optional port, and nothing else:
/// no user information, no path but an empty one or `/`, no query and no
/// fragment. The loopback exception compares the host the origin parses
/// to, not its text.
///
/// # Errors
///
/// [`Error::NotAllowed`] for any other origin.
#[cfg(any(feature = "server", feature = "server-socket"))]
pub fn connect_url(origin: &str) -> Result<String> {
    let path = frasil_transport::peer::CONNECT_PATH;
    let (secure, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(Error::NotAllowed("a peer's origin must be HTTPS"));
    };
    let (host, port) = parse_authority(rest.strip_suffix('/').unwrap_or(rest)).ok_or(
        Error::NotAllowed("a peer's origin is a scheme, a host and a port"),
    )?;
    let authority = match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    if secure {
        return Ok(format!("wss://{authority}{path}"));
    }
    if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]" {
        return Ok(format!("ws://{authority}{path}"));
    }
    Err(Error::NotAllowed("a peer's origin must be HTTPS"))
}

/// An origin's authority, `host[:port]`, as its host and port: `None` for
/// user information, a path, a query or a fragment, an empty host, a host
/// of other characters than a DNS name's or an IPv4 address's, a bracketed
/// host that is not an IPv6 address, or a port that is not 1 to 5 digits
/// of at most 65,535.
#[cfg(any(feature = "server", feature = "server-socket"))]
fn parse_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, rest) = authority.split_at(end + 1);
        let inner = &host[1..host.len() - 1];
        inner.parse::<core::net::Ipv6Addr>().ok()?;
        match rest {
            "" => (host, None),
            _ => (host, Some(rest.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let name_ok = host.starts_with('[')
        || (!host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')));
    if !name_ok {
        return None;
    }
    let port = match port {
        None => None,
        Some(digits) => {
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            Some(digits.parse::<u16>().ok()?)
        }
    };
    Some((host, port))
}

/// The acknowledger a server binding's peer is kept under: the
/// connection's `channel` (transport.md, "Whose acknowledgement"), which
/// only the origin's holder can answer to.
#[cfg(any(feature = "server", feature = "server-socket", feature = "iroh"))]
fn origin_acknowledger(origin: &str) -> Acknowledger {
    Acknowledger::Peer(frasil_transport::peer::server_channel(origin))
}

/// Reads one message of a device-to-peer connection, of the class its type
/// travels in: the server binding carries every class on one WebSocket.
#[cfg(any(feature = "server", feature = "server-socket"))]
fn read(bytes: &[u8]) -> std::result::Result<Option<Message>, String> {
    use frasil_transport::frame::{Extensions, StreamClass};
    let class = match frasil_base::cbor::decode(bytes)
        .ok()
        .and_then(|value| value.as_map().ok().and_then(|map| map.get(&0).cloned()))
        .and_then(|code| code.as_unsigned().ok())
        .and_then(MessageType::from_code)
    {
        Some(MessageType::Sync | MessageType::Open | MessageType::AdapterSync) => StreamClass::Sync,
        Some(MessageType::Ephemeral) => StreamClass::Ephemeral,
        _ => StreamClass::Control,
    };
    // A device reads deposit tokens' answers only on the connections of
    // its own it opens for them ([`Bare`]); it sends their requests nowhere
    // else, so a peer sends them nowhere else.
    let extensions = Extensions {
        deposit_tokens: cfg!(feature = "ext-deposit-tokens"),
        ..Extensions::NONE
    };
    frasil_transport::frame::read_message(bytes, class, ConnectionKind::DeviceToPeer, extensions)
        .map_err(|class| format!("{class:?}"))
}

/// What a WebSocket close code of section 2.5 means for the connection:
/// 4017, `reconnect`, opens it again; any other ends it (transport.md,
/// "Reconnecting elsewhere"). `None` for a close code of no section 2.5
/// code, which is a lost transport.
#[cfg(any(feature = "server", feature = "server-socket"))]
fn coded_close(code: u16) -> Option<Incoming> {
    match frasil_transport::Code::from_websocket(code)? {
        frasil_transport::Code::Reconnect => Some(Incoming::Reconnect),
        other => Some(Incoming::Refused(format!(
            "closed by the peer: {}",
            other.name()
        ))),
    }
}

/// Sorts a received message into what the driver takes.
fn sort(message: Message) -> Option<Incoming> {
    if message.kind == MessageType::Sync {
        let sync = Sync::read(&message, ConnectionKind::DeviceToPeer).ok()?;
        let Scope::Space(space) = sync.scope else {
            return None;
        };
        return Some(Incoming::Sync(EventId(space), sync.message));
    }
    Some(Incoming::Control(message))
}

/// How long an administration connection runs at most.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const ADMINISTRATION_DEADLINE: Duration = Duration::from_secs(20);

/// Stores this device's own skeleton events of a space at a peer over a
/// fresh administration connection on the server binding (transport.md,
/// section 3.10; peers.md, "Administration connections"): one present, of
/// the device's newest administrator pseudonym for the space, then only
/// that pseudonym's skeleton events and acknowledgements, and closed once
/// the peer has acknowledged them and its awaiting report is answered.
/// Returns whether anything was stored.
///
/// # Errors
///
/// [`Error::Connection`] when the connection or the present fails.
#[cfg(feature = "server")]
pub async fn administer_server(device: &Engine, origin: &str, space: EventId) -> Result<bool> {
    let (sink, http, incoming_tx, incoming_rx, _) = server::open(origin).await?;
    let channel = frasil_transport::peer::server_channel(origin);
    let by = origin_acknowledger(origin);
    let mut wire = Wire::Server(sink, http);
    let done = administer(
        device,
        &mut wire,
        &Runtime::Tokio,
        &channel,
        by,
        incoming_tx,
        incoming_rx,
        space,
    )
    .await;
    wire.close();
    done
}

/// [`administer_server`] over the iroh binding, from a fresh endpoint key.
///
/// # Errors
///
/// [`Error::Connection`] when the dial, the handshake or the present fails.
#[cfg(feature = "iroh")]
pub async fn administer_iroh(
    device: &Engine,
    peer: [u8; 32],
    addresses: &[std::net::SocketAddr],
    relays: &[String],
    config: impl FnOnce(frasil_iroh::Config) -> frasil_iroh::Config,
    space: EventId,
) -> Result<bool> {
    let (iroh_wire, channel, incoming_tx, incoming_rx, _) =
        iroh::open(peer, addresses, relays, config).await?;
    let mut wire = Wire::Iroh(iroh_wire);
    let done = administer(
        device,
        &mut wire,
        &Runtime::Tokio,
        &channel,
        Acknowledger::Peer(peer),
        incoming_tx,
        incoming_rx,
        space,
    )
    .await;
    wire.close();
    done
}

/// The next message of an administration connection, within its deadline,
/// on the connection's timers.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
async fn receive(
    incoming: &mut mpsc::UnboundedReceiver<Incoming>,
    runtime: &Runtime,
) -> Result<Incoming> {
    let deadline = runtime.sleep(ADMINISTRATION_DEADLINE);
    tokio::select! {
        message = incoming.recv() => match message {
            Some(Incoming::Closed(why) | Incoming::Refused(why)) => Err(Error::Connection(why)),
            // An administration connection is opened again whenever the
            // device has skeleton events to store; this one ends.
            Some(Incoming::Reconnect) => Err(Error::Connection("closed by the peer: reconnect".into())),
            Some(message) => Ok(message),
            None => Err(Error::Connection("ended".into())),
        },
        () = deadline => Err(Error::Timeout),
    }
}

/// How often an administration connection looks again at what it waits
/// for when no message arrives.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const ADMINISTRATION_RECHECK: Duration = Duration::from_millis(100);

/// The device's own skeleton events of a space not yet acknowledged by a
/// peer.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
async fn pending_ids(device: &Engine, space: &EventId) -> Vec<EventId> {
    device
        .administration(space, |_| Vec::new())
        .await
        .map(|(_, _, pending)| {
            pending
                .iter()
                .filter_map(|signed| frasil_events::decode(signed).ok())
                .map(|event| event.id())
                .collect()
        })
        .unwrap_or_default()
}

/// The start of the error of an administration connection whose present
/// the peer refused; the peer's reason code follows it.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const ADMINISTRATOR_REFUSED: &str = "the peer refused the administrator pseudonym";

/// Whether an administration connection ended because the peer refused
/// its present `erased`: the peer holds the space's tombstone, so it
/// executed an erasure of the space and keeps nothing of it (peers.md,
/// "Erasure").
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub(crate) fn refused_as_erased(error: &Error) -> bool {
    matches!(error, Error::Connection(why)
        if why.strip_prefix(ADMINISTRATOR_REFUSED) == Some(": erased"))
}

/// One administration connection's flow, after the transport opened.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
#[allow(clippy::too_many_arguments)]
async fn administer(
    device: &Engine,
    wire: &mut Wire,
    runtime: &Runtime,
    channel: &Channel,
    by: Acknowledger,
    incoming_tx: mpsc::UnboundedSender<Incoming>,
    mut incoming: mpsc::UnboundedReceiver<Incoming>,
    space: EventId,
) -> Result<bool> {
    // The handshake, with the administration purpose.
    let hello = match receive(&mut incoming, runtime).await? {
        Incoming::Control(message) => message,
        _ => return Err(Error::Connection("no PeerHello".into())),
    };
    let nonce = device.platform().nonce::<32>()?;
    let side = DeviceSide::answer_with(channel, &hello, nonce, Purpose::Administration)
        .map_err(|closed| Error::Connection(format!("{:?}", closed.class)))?;
    wire.control(&side.hello).await?;
    // One present: the newest pseudonym, proved over the binding.
    let credential = Credential::Pseudonym.code();
    let Some((public, proof, pending)) = device
        .administration(&space, |public| {
            frasil_peers::proof::presented(&side.binding, &space.0, credential, public)
        })
        .await
    else {
        return Ok(false);
    };
    wire.control(
        &frasil_transport::messages::Present {
            request: 1,
            space: space.0,
            credential: credential.into(),
            public: public.to_vec(),
            proof: proof.to_vec(),
        }
        .encode(),
    )
    .await?;
    let send_events = |events: Vec<Vec<u8>>| {
        events
            .into_iter()
            .map(|signed| {
                Sync {
                    scope: Scope::Space(space.0),
                    message: SyncMessage {
                        space,
                        message: UnitMessage::Events {
                            events: vec![signed],
                        },
                    }
                    .encode(),
                }
                .encode()
            })
            .collect::<Vec<_>>()
    };
    let mut granted = false;
    let mut answered = false;
    let mut stored = false;
    let sent: BTreeSet<EventId> = pending
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| event.id())
        .collect();
    // The whole connection ends within its deadline, whatever the peer
    // sends meanwhile: while a skeleton cut awaits votes, the peer's
    // awaiting reports would keep it open, and the device opens another
    // when it has skeleton events to store.
    let deadline = runtime.sleep(ADMINISTRATION_DEADLINE);
    tokio::pin!(deadline);
    loop {
        // The device may hold another administration connection for the
        // space (a flush beside its own), and the peer acknowledges an event
        // on the connection that stored it: what this one waits for can be
        // settled without a message here, so it looks again now and then.
        let next = tokio::select! {
            next = receive(&mut incoming, runtime) => Some(next?),
            () = &mut deadline => return Ok(stored),
            () = runtime.sleep(ADMINISTRATION_RECHECK) => None,
        };
        let Some(next) = next else {
            if granted && answered && pending_ids(device, &space).await.is_empty() {
                return Ok(stored);
            }
            continue;
        };
        match next {
            Incoming::Control(message) => match message.kind {
                MessageType::EventRefused
                    if EventRefused::read(&message)
                        .is_ok_and(|refused| refused.code == "extension_required") =>
                {
                    return Err(Error::Class("extension_required"));
                }
                MessageType::EventRefused if device.erasing().await.contains(&space) => {
                    let refused = EventRefused::read(&message).map_err(Error::class)?;
                    return Err(Error::Connection(format!(
                        "erasure store refused: {}",
                        refused.code
                    )));
                }
                MessageType::ErasureLate => {
                    let answer = frasil_transport::messages::ErasureLate::read(&message)
                        .map_err(Error::class)?;
                    if device.erasing().await.contains(&space) {
                        device.receive_erasure_late(space, answer).await?;
                        return Ok(stored);
                    }
                }
                MessageType::Granted => {
                    granted = true;
                    stored = !pending.is_empty();
                    for message in send_events(pending.clone()) {
                        wire.sync(space, &message, &incoming_tx).await?;
                    }
                }
                MessageType::Refused => {
                    let code = Refused::read(&message)
                        .map_or_else(|_| "unreadable".to_owned(), |refused| refused.code);
                    return Err(Error::Connection(format!(
                        "{ADMINISTRATOR_REFUSED}: {code}"
                    )));
                }
                // The awaiting report: the requests and snapshots not yet
                // stable at the peer that this slot has not acknowledged.
                MessageType::Awaiting => {
                    // A residue has no checkpoint record or space keys and
                    // cannot vote. Its only store is its retained erasure.
                    if device.erasing().await.contains(&space) {
                        answered = true;
                        continue;
                    }
                    let Ok(awaiting) = frasil_transport::messages::Awaiting::read(&message) else {
                        continue;
                    };
                    let ids: Vec<EventId> = awaiting.ids.into_iter().map(EventId).collect();
                    if let Some(ack) = device.acknowledge_awaited(space, &ids).await? {
                        for message in send_events(vec![ack]) {
                            wire.sync(space, &message, &incoming_tx).await?;
                        }
                    } else {
                        answered = true;
                    }
                }
                _ => {}
            },
            Incoming::Sync(scope, bytes) if scope == space => {
                if let Ok(frasil_units::messages::Received::Message(SyncMessage {
                    message: UnitMessage::Ack { heads },
                    ..
                })) = SyncMessage::read(&bytes)
                {
                    device.acknowledge(space, by, &heads).await?;
                }
            }
            _ => {}
        }
        let left = pending_ids(device, &space).await;
        if granted && left.is_empty() && answered {
            return Ok(stored);
        }
        // A skeleton event signed since the connection opened, such as a
        // checkpoint's cut, goes on the next one, after what it needs
        // (the cut's record object) reached the peer.
        if granted && left.iter().any(|id| !sent.contains(id)) {
            return Ok(stored);
        }
    }
}

/// A connection of the device's own to a peer that presents nothing: a
/// fresh transport, as an administration connection is opened (transport.md,
/// 3.10 Connection purposes: a new transport session, no TLS session
/// resumption, no cookie, and on the iroh binding a fresh endpoint key),
/// with purpose 1 and no `Present`, bearer token or grant. A device asks a
/// peer's deposit keys, and deposits in device mailboxes, on such
/// connections, each a fresh one, and nothing on them carries the
/// device's Ed25519 key, `kc` or device ID (ext-deposit-tokens.md, 3.2 and
/// 3.6; transport.md, "A sender keeps what was refused"). It collects its
/// own device mailbox on one too, which then carries collections alone
/// ([`Bare::collect_own`]; transport.md, 3.12 What a peer learns of a
/// device). It carries one request at a time and is closed when dropped.
pub struct Bare {
    wire: Wire,
    side: DeviceSide,
    rx: mpsc::UnboundedReceiver<Incoming>,
    runtime: Runtime,
    request: u64,
    /// Set once the transport's readers end.
    ended: Arc<AtomicBool>,
}

impl core::fmt::Debug for Bare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bare")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl Drop for Bare {
    fn drop(&mut self) {
        self.wire.close();
    }
}

/// How long a [`Bare`] connection waits for one answer.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub(crate) const BARE_ANSWER: Duration = Duration::from_secs(20);

impl Bare {
    /// The handshake on a fresh transport, with purpose 1.
    async fn open(device: &Engine, opened: Opened, runtime: Runtime) -> Result<Self> {
        match handshake(device, opened, &runtime).await {
            Ok(Some(dialed)) => Ok(Self {
                wire: dialed.wire,
                side: dialed.side,
                rx: dialed.rx,
                runtime,
                request: 0,
                ended: dialed.ended,
            }),
            Ok(None) => Err(Error::Connection("closed by the peer: reconnect".into())),
            Err(unopened) => Err(unopened.into()),
        }
    }

    /// The services the peer's `PeerHello` lists.
    #[cfg_attr(not(feature = "ext-deposit-tokens"), allow(dead_code))]
    pub(crate) fn services(&self) -> Vec<frasil_transport::codes::Service> {
        self.side.peer_hello.services()
    }

    /// The next request number.
    pub(crate) fn next_request(&mut self) -> u64 {
        self.request += 1;
        self.request
    }

    /// Sends a control message and waits, within [`BARE_ANSWER`], for the
    /// control message that answers `request`: the message whose key 1 it
    /// is.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the transport ends; [`Error::Timeout`].
    pub(crate) async fn ask(&mut self, message: &[u8], request: u64) -> Result<Message> {
        self.wire.control(message).await?;
        let deadline = self.runtime.sleep(BARE_ANSWER);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                incoming = self.rx.recv() => match incoming {
                    Some(Incoming::Control(answer))
                        if answer.get(1).and_then(|v| v.as_unsigned().ok()) == Some(request) =>
                    {
                        return Ok(answer);
                    }
                    Some(Incoming::Closed(why) | Incoming::Refused(why)) => {
                        return Err(Error::Connection(why));
                    }
                    Some(Incoming::Reconnect) => {
                        return Err(Error::Connection("closed by the peer: reconnect".into()));
                    }
                    Some(_) => {}
                    None => return Err(Error::Connection(CONNECTION_ENDED.into())),
                },
                () = &mut deadline => return Err(Error::Timeout),
            }
        }
    }

    /// Presents the upload key of the space's current state, and nothing
    /// else, proved over the connection's binding (transport.md, 3.11
    /// Presenting credentials), for a space draw (ext-deposit-tokens.md,
    /// 3.1.2 Drawing as a writer of a space). True once the peer grants
    /// the store right; false when the device holds no upload key of the
    /// space or the peer refuses it.
    ///
    /// # Errors
    ///
    /// As [`ask`](Self::ask).
    #[cfg(feature = "ext-deposit-tokens")]
    pub(crate) async fn present_upload(&mut self, device: &Engine, space: EventId) -> Result<bool> {
        let me = device.device_id();
        let upload = device
            .read(&space, |replica| {
                let state = replica.current()?.clone();
                credentials(replica, &me, &state, false).and_then(|(_, upload)| upload)
            })
            .await
            .ok()
            .flatten();
        let Some(upload) = upload else {
            return Ok(false);
        };
        let request = self.next_request();
        let message = self
            .side
            .present(request, &space.0, Credential::Upload, &upload);
        let answer = self.ask(&message, request).await?;
        Ok(answer.kind == MessageType::Granted
            && Granted::read(&answer).is_ok_and(|granted| granted.rights.contains(&Right::Store)))
    }

    /// Sends a mailbox message and reads its answer: `Ok` for `Accepted`,
    /// the reason code of a `Refused`.
    ///
    /// # Errors
    ///
    /// As [`ask`](Self::ask); [`Error::Connection`] for an answer of
    /// another type.
    pub(crate) async fn put(
        &mut self,
        message: &[u8],
        request: u64,
    ) -> Result<std::result::Result<(), String>> {
        let answer = self.ask(message, request).await?;
        match answer.kind {
            MessageType::Accepted => Ok(Ok(())),
            MessageType::Refused => Refused::read(&answer)
                .map(|refused| Err(refused.code))
                .map_err(|class| Error::Connection(format!("{class:?}"))),
            other => Err(Error::Connection(format!("an answer of type {other:?}"))),
        }
    }

    /// Whether the transport still runs: false once the peer closed it or
    /// it was lost.
    pub(crate) fn is_open(&self) -> bool {
        !self.ended.load(Ordering::Acquire)
    }

    /// Collects this device's own device mailbox after the item `after`,
    /// signed with its identity key over this connection's binding
    /// (transport.md, "Collecting a device mailbox"): the items, or the
    /// reason code of a `Refused`. A connection that collects carries
    /// nothing else (transport.md, 3.12 What a peer learns of a device):
    /// the caller keeps it for collections alone.
    ///
    /// # Errors
    ///
    /// As [`ask`](Self::ask); [`Error::Connection`] for an answer of
    /// another type.
    pub(crate) async fn collect_own(
        &mut self,
        device: &Engine,
        after: Option<[u8; 16]>,
    ) -> Result<MailboxAnswer> {
        let request = self.next_request();
        let message = {
            let seed = zeroize::Zeroizing::new(device.keys().identity_seed_bytes());
            frasil_transport::mailbox::collect(
                request,
                &seed,
                device.signer().kc(),
                &self.side.binding,
                after,
            )
        };
        let answer = self.ask(&message, request).await?;
        match answer.kind {
            MessageType::MailboxItems => frasil_transport::mailbox::MailboxItems::read(&answer)
                .map(|items| Ok(items.items))
                .map_err(|class| Error::Connection(format!("{class:?}"))),
            MessageType::Refused => Refused::read(&answer)
                .map(|refused| Err(refused.code))
                .map_err(|class| Error::Connection(format!("{class:?}"))),
            other => Err(Error::Connection(format!("an answer of type {other:?}"))),
        }
    }
}

/// A [`Bare`] connection over the server binding's WebSocket: a new
/// WebSocket of its own, with no cookie.
///
/// # Errors
///
/// [`Error::Connection`] when the WebSocket does not open or the handshake
/// fails.
#[cfg(feature = "server")]
pub async fn bare_server(device: &Engine, origin: &str) -> Result<Bare> {
    let (sink, http, tx, rx, ended) = server::open(origin).await?;
    let opened = Opened {
        wire: Wire::Server(sink, http),
        channel: frasil_transport::peer::server_channel(origin),
        tx,
        rx,
        ended,
    };
    Bare::open(device, opened, Runtime::Tokio).await
}

/// A [`Bare`] connection over the iroh binding, from a fresh endpoint key.
/// Its receivers read ext-deposit-tokens.md's answers, types 41 and 43,
/// in a build with that feature, whatever `config` sets.
///
/// # Errors
///
/// [`Error::Connection`] when the dial or the handshake fails.
#[cfg(feature = "iroh")]
pub async fn bare_iroh(
    device: &Engine,
    peer: [u8; 32],
    addresses: &[std::net::SocketAddr],
    relays: &[String],
    config: impl FnOnce(frasil_iroh::Config) -> frasil_iroh::Config,
) -> Result<Bare> {
    let config = |base| {
        config(base).extensions(frasil_transport::frame::Extensions {
            deposit_tokens: cfg!(feature = "ext-deposit-tokens"),
            ..frasil_transport::frame::Extensions::NONE
        })
    };
    let (wire, channel, tx, rx, ended) = iroh::open(peer, addresses, relays, config).await?;
    let opened = Opened {
        wire: Wire::Iroh(wire),
        channel,
        tx,
        rx,
        ended,
    };
    Bare::open(device, opened, Runtime::Tokio).await
}

/// Connects to a peer over the server binding (transport.md, section
/// 3.15): `origin` is the peer's origin, such as
/// `https://peer.example.org`; plain `http` only to a loopback host. The
/// connection presents `spaces` and runs until it closes. When the peer
/// closes it with `reconnect`, it connects again through the same origin
/// (transport.md, "Reconnecting elsewhere").
///
/// # Errors
///
/// [`Error::Connection`] when the WebSocket does not open, the peer does
/// not echo the subprotocol, or the handshake fails.
#[cfg(feature = "server")]
pub async fn connect_server(
    device: &Engine,
    origin: &str,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    let by = origin_acknowledger(origin);
    let origin = origin.to_owned();
    let redial: Redial = Arc::new(move || {
        let origin = origin.clone();
        Box::pin(async move {
            let (sink, http, tx, rx, ended) = server::open(&origin).await?;
            Ok(Opened {
                wire: Wire::Server(sink, http),
                channel: frasil_transport::peer::server_channel(&origin),
                tx,
                rx,
                ended,
            })
        })
    });
    let opened = redial().await?;
    start(
        device.clone(),
        opened,
        Runtime::Tokio,
        by,
        Some(redial),
        spaces,
    )
    .await
}

/// Connects to a peer over the iroh binding's `frasil/p1/peer`
/// (transport.md, section 3.16), from a fresh endpoint key: the peer's
/// stable endpoint key, its addresses and relays. `config` shapes the
/// fresh endpoint, such as [`frasil_iroh::Config::loopback`]. When the
/// peer closes the connection with `reconnect`, it dials the same endpoint
/// key again, from a fresh endpoint key (transport.md, "Reconnecting
/// elsewhere"). Acknowledgements are kept under that key: one taken from
/// no discovery, such as a peer ticket's (section 3.12).
///
/// # Errors
///
/// [`Error::Connection`] when the dial or the handshake fails.
#[cfg(feature = "iroh")]
pub async fn connect_iroh(
    device: &Engine,
    peer: [u8; 32],
    addresses: &[std::net::SocketAddr],
    relays: &[String],
    config: impl Fn(frasil_iroh::Config) -> frasil_iroh::Config + Send + std::marker::Sync + 'static,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    let endpoints = vec![(peer, addresses.to_vec())];
    connect_iroh_keys(
        device,
        endpoints,
        relays,
        config,
        Acknowledger::Peer(peer),
        spaces,
    )
    .await
}

/// Connects to the peer at `origin` over the iroh binding, by the endpoint
/// keys its discovery lists, `endpoint` and `endpoints` of its `iroh`
/// ([`discovery_endpoints`]), each with the addresses to dial it at, if
/// any (transport.md, "The server binding"). Every key is the origin's
/// peer, so acknowledgements are kept under the origin, whichever of its
/// machines answers (section 3.12). The device dials the keys in turn: the
/// first that connects; after a `reconnect` close, or an attempt that
/// fails, the next one (transport.md, "Reconnecting elsewhere").
///
/// # Errors
///
/// [`Error::Invalid`] for no key; [`Error::Connection`] when no key's dial
/// and handshake succeed.
#[cfg(feature = "iroh")]
pub async fn connect_iroh_origin(
    device: &Engine,
    origin: &str,
    endpoints: &[([u8; 32], Vec<std::net::SocketAddr>)],
    relays: &[String],
    config: impl Fn(frasil_iroh::Config) -> frasil_iroh::Config + Send + std::marker::Sync + 'static,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    if endpoints.is_empty() {
        return Err(Error::Invalid("no endpoint key"));
    }
    connect_iroh_keys(
        device,
        endpoints.to_vec(),
        relays,
        config,
        origin_acknowledger(origin),
        spaces,
    )
    .await
}

/// The endpoint keys of a peer's discovery document, the body of
/// `GET /.well-known/frasil`: `iroh.endpoint` first, then each other key
/// of `iroh.endpoints`, at most 256 (transport.md, "The server binding").
/// None for a document without `iroh`, or one that does not read.
#[cfg(feature = "server")]
pub fn discovery_endpoints(document: &[u8]) -> Vec<[u8; 32]> {
    fn key(value: &serde_json::Value) -> Option<[u8; 32]> {
        let text = value.as_str()?;
        if text.len() != 64 {
            return None;
        }
        let mut key = [0; 32];
        for (byte, pair) in key.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(key)
    }
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(document) else {
        return Vec::new();
    };
    let Some(iroh) = document.get("iroh") else {
        return Vec::new();
    };
    let mut keys: Vec<[u8; 32]> = iroh.get("endpoint").and_then(key).into_iter().collect();
    let listed = iroh
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for listed in listed.iter().filter_map(key) {
        if keys.len() < 256 && !keys.contains(&listed) {
            keys.push(listed);
        }
    }
    keys
}

/// Connects over the iroh binding by any of `endpoints`, in turn, keeping
/// acknowledgements under `by`.
#[cfg(feature = "iroh")]
async fn connect_iroh_keys(
    device: &Engine,
    endpoints: Vec<([u8; 32], Vec<std::net::SocketAddr>)>,
    relays: &[String],
    config: impl Fn(frasil_iroh::Config) -> frasil_iroh::Config + Send + std::marker::Sync + 'static,
    by: Acknowledger,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    let count = endpoints.len();
    let (endpoints, relays, config) = (Arc::new(endpoints), relays.to_vec(), Arc::new(config));
    // Each dial takes the next key: after a `reconnect` close, or a key
    // that failed, another of the peer's machines.
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let redial: Redial = Arc::new(move || {
        let (endpoints, relays, config) = (endpoints.clone(), relays.clone(), config.clone());
        let at = next.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Box::pin(async move {
            let (peer, addresses) = &endpoints[at];
            let (wire, channel, tx, rx, ended) =
                iroh::open(*peer, addresses, &relays, |fresh| config(fresh)).await?;
            Ok(Opened {
                wire: Wire::Iroh(wire),
                channel,
                tx,
                rx,
                ended,
            })
        })
    });
    let mut opened = redial().await;
    for _ in 1..count {
        if opened.is_ok() {
            break;
        }
        opened = redial().await;
    }
    start(
        device.clone(),
        opened?,
        Runtime::Tokio,
        by,
        Some(redial),
        spaces,
    )
    .await
}

/// A transport whose handshake completed.
struct Dialed {
    wire: Wire,
    side: DeviceSide,
    tx: mpsc::UnboundedSender<Incoming>,
    rx: mpsc::UnboundedReceiver<Incoming>,
    ended: Arc<AtomicBool>,
}

/// The device's side of the handshake on a fresh transport: the peer's
/// `PeerHello`, answered by `Hello` with purpose 1. `None` when the peer
/// closes the transport with `reconnect` first.
async fn handshake(
    device: &Engine,
    opened: Opened,
    runtime: &Runtime,
) -> std::result::Result<Option<Dialed>, Unopened> {
    let Opened {
        mut wire,
        channel,
        tx,
        mut rx,
        ended,
    } = opened;
    let deadline = runtime.sleep(HELLO_DEADLINE);
    let hello = tokio::select! {
        message = rx.recv() => match message {
            Some(Incoming::Control(message)) => message,
            Some(Incoming::Closed(why)) => return Err(Unopened::Lost(Error::Connection(why))),
            Some(Incoming::Refused(why)) => return Err(Unopened::Refused(why)),
            Some(Incoming::Reconnect) => return Ok(None),
            _ => return Err(Unopened::Refused("no PeerHello".into())),
        },
        () = deadline => {
            return Err(Unopened::Lost(Error::Connection(
                "the PeerHello did not come".into(),
            )));
        }
    };
    let nonce = device
        .platform()
        .nonce::<32>()
        .map_err(|error| Unopened::Refused(error.to_string()))?;
    // A `PeerHello` of another version or revision ends the connection:
    // connecting again would only meet it again.
    let side = DeviceSide::answer_with(&channel, &hello, nonce, Purpose::SpaceTraffic)
        .map_err(|closed| Unopened::Refused(format!("{:?}", closed.class)))?;
    if let Err(error) = wire.control(&side.hello).await {
        return match reader_end(&mut rx, runtime).await {
            Some(Ended::Reconnect) => Ok(None),
            Some(Ended::Refused(why)) => Err(Unopened::Refused(why)),
            _ => Err(Unopened::Lost(error)),
        };
    }
    Ok(Some(Dialed {
        wire,
        side,
        tx,
        rx,
        ended,
    }))
}

/// Once a write failed: how the transport's reader says it ended, the
/// peer's `reconnect` among the reasons; `None` when it does not say so
/// within [`READER_SETTLE`].
async fn reader_end(
    incoming: &mut mpsc::UnboundedReceiver<Incoming>,
    runtime: &Runtime,
) -> Option<Ended> {
    let mut settle = runtime.sleep(READER_SETTLE);
    loop {
        tokio::select! {
            message = incoming.recv() => match message {
                Some(Incoming::Reconnect) => return Some(Ended::Reconnect),
                Some(Incoming::Closed(why)) => return Some(Ended::Closed(why)),
                Some(Incoming::Refused(why)) => return Some(Ended::Refused(why)),
                Some(_) => {}
                None => return None,
            },
            () = &mut settle => return None,
        }
    }
}

fn lock(status: &Mutex<PeerStatus>) -> std::sync::MutexGuard<'_, PeerStatus> {
    status.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Connects again after a `reconnect` close (transport.md, "Reconnecting
/// elsewhere"): waits a random time from 0 to `bound`, then opens a fresh
/// transport to the same peer and runs its handshake, doubling the bound
/// after each attempt that fails, to at most `reconnect_wait_cap`. Returns
/// the transport and the bound of the wait before it, or why the connection
/// ends instead. Commands taken meanwhile are held.
async fn dial_again(
    device: &Engine,
    runtime: &Runtime,
    redial: &Redial,
    status: &Mutex<PeerStatus>,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    held: &mut VecDeque<Command>,
    mut bound: Duration,
) -> std::result::Result<(Dialed, Duration), String> {
    loop {
        let random = device
            .platform()
            .nonce::<8>()
            .map_err(|error| error.to_string())?;
        let wait = reconnect_wait_with(bound, random);
        lock(status).reconnect_wait = Some((bound, wait));
        if or_close(runtime.sleep(wait), commands, held)
            .await
            .is_none()
        {
            return Err("closed by the device".into());
        }
        lock(status).reconnect_attempts += 1;
        let attempt = async {
            match redial().await {
                Ok(opened) => handshake(device, opened, runtime).await,
                Err(Error::Unsupported(why)) => Err(Unopened::Refused(format!(
                    "closed by the peer: reconnect ({why})"
                ))),
                Err(error) => Err(Unopened::Lost(error)),
            }
        };
        match or_close(attempt, commands, held).await {
            None => return Err("closed by the device".into()),
            Some(Ok(Some(dialed))) => return Ok((dialed, bound)),
            // Only a `reconnect` close, or a transport lost or never
            // opened, is an attempt that failed; any other close code, or
            // a refused `PeerHello`, ends the connection.
            Some(Err(Unopened::Refused(why))) => return Err(why),
            Some(Ok(None) | Err(Unopened::Lost(_))) => bound = reconnect_bound_after(bound),
        }
    }
}

/// Runs the handshake, then spawns the connection's driver. A first
/// transport the peer closes with `reconnect` is followed as any other
/// (transport.md, "Reconnecting elsewhere"): the connection starts
/// reconnecting.
async fn start(
    device: Engine,
    opened: Opened,
    runtime: Runtime,
    by: Acknowledger,
    redial: Option<Redial>,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    let status = Arc::new(Mutex::new(PeerStatus::default()));
    let (commands, mut commands_rx) = mpsc::unbounded_channel();
    // Each space is presented first, on whichever transport the connection
    // opens.
    let mut held: VecDeque<Command> = spaces.into_iter().map(Command::Attach).collect();
    let first = handshake(&device, opened, &runtime).await?;
    let closing = Arc::new(AtomicBool::new(false));
    let handle = PeerHandle {
        status: status.clone(),
        commands,
        by,
        closing: closing.clone(),
    };
    let spawner = runtime.clone();
    match first {
        Some(dialed) => {
            let (mut driver, rx) = Driver::new(device, dialed, runtime, by, redial, status, held);
            driver.closing = closing;
            spawner.spawn(driver.serve_to_end(rx, commands_rx));
        }
        None => {
            let Some(redial) = redial else {
                return Err(Error::Connection("closed by the peer: reconnect".into()));
            };
            lock(&status).reconnecting = true;
            spawner.spawn(async move {
                let dialed = dial_again(
                    &device,
                    &runtime,
                    &redial,
                    &status,
                    &mut commands_rx,
                    &mut held,
                    reconnect_wait(),
                )
                .await;
                match dialed {
                    Ok((dialed, bound)) => {
                        {
                            let mut status = lock(&status);
                            status.reconnecting = false;
                            status.reconnects += 1;
                        }
                        let (mut driver, rx) =
                            Driver::new(device, dialed, runtime, by, Some(redial), status, held);
                        driver.reconnected = true;
                        driver.last_bound = Some(bound);
                        driver.closing = closing;
                        driver.serve_to_end(rx, commands_rx).await;
                    }
                    Err(why) => {
                        let mut status = lock(&status);
                        status.reconnecting = false;
                        status.closed = Some(why);
                    }
                }
            });
        }
    }
    Ok(handle)
}

/// Runs `future` while taking the device's commands: `None` when the
/// device closes the connection meanwhile. Every other command is held, to
/// be carried out on the next transport.
async fn or_close<T>(
    future: impl std::future::Future<Output = T>,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    held: &mut VecDeque<Command>,
) -> Option<T> {
    let mut future = std::pin::pin!(future);
    loop {
        tokio::select! {
            out = &mut future => return Some(out),
            command = commands.recv() => match command {
                Some(Command::Close) | None => return None,
                Some(command) => held.push_back(command),
            },
        }
    }
}

struct Driver {
    device: Engine,
    wire: Wire,
    runtime: Runtime,
    side: DeviceSide,
    by: Acknowledger,
    incoming: mpsc::UnboundedSender<Incoming>,
    /// Whether the transport's readers have ended.
    ended: Arc<AtomicBool>,
    /// Whether the connection is to close: [`PeerHandle::close`].
    closing: Arc<AtomicBool>,
    next_request: u64,
    requests: BTreeMap<u64, Request>,
    spaces: BTreeMap<EventId, Attached>,
    status: Arc<Mutex<PeerStatus>>,
    mailboxes: Mailboxes,
    /// Holds waiting to be sent (ext-libraries.md, 3.7 Registering a hold).
    #[cfg(feature = "ext-libraries")]
    holds: Vec<holds::HoldAsk>,
    /// Spaces whose `LibraryAttach` was in flight when a transport ended:
    /// sent again once the next one holds the store right.
    #[cfg(feature = "ext-libraries")]
    library_again: BTreeSet<EventId>,
    /// Spaces whose create or import the peer accepted on this transport,
    /// until it acknowledges their genesis: the pending create lapses,
    /// with its ticket used, when the connection closes before
    /// (ext-libraries.md, 3.3 Attaching).
    #[cfg(feature = "ext-libraries")]
    library_creating: BTreeSet<EventId>,
    /// How the transport opens again after a `reconnect` close, where it
    /// can.
    redial: Option<Redial>,
    /// Whether the transport was opened again after a `reconnect` close.
    reconnected: bool,
    /// Whether the peer sent a `Granted` or an acknowledgement on this
    /// transport.
    progressed: bool,
    /// The bound of the wait before the latest attempt to connect again.
    last_bound: Option<Duration>,
    /// Spaces the peer refused `moved`: never presented on this connection
    /// again.
    moved: BTreeSet<EventId>,
    /// Spaces presented only to find out whether the peer hosts them
    /// ([`PeerHandle::seek`]).
    seeking: BTreeSet<EventId>,
    /// Commands to carry out first on the transport: each space's present,
    /// then what the device asked while the connection opened.
    held: VecDeque<Command>,
    /// The fetches by slices of this transport: those that wait, and how
    /// many run.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    fetches: SliceFetches,
    /// The device's requests for chunks taken on this transport, by their
    /// numbers ([`Engine::fetch_chunks`]).
    ///
    /// [`Engine::fetch_chunks`]: crate::device::Engine::fetch_chunks
    requested: BTreeSet<u64>,
    /// How many times in a row a request's fetch stopped on this
    /// transport with nothing kept, by the request's number: the wait
    /// before it is tried again grows with it.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    stopped: BTreeMap<u64, u32>,
    /// The device's number for the current transport, which names what it
    /// delivered on the ephemeral channel (ext-ephemeral.md, "Relaying").
    #[cfg(feature = "ephemeral")]
    ephemeral_connection: u64,
}

/// Mailbox messages in flight, and those waiting for a space's store
/// right.
#[derive(Default)]
struct Mailboxes {
    answers: BTreeMap<u64, MailboxReply>,
    waiting: Vec<(EventId, MailboxAsk, MailboxReply)>,
}

impl Driver {
    fn new(
        device: Engine,
        dialed: Dialed,
        runtime: Runtime,
        by: Acknowledger,
        redial: Option<Redial>,
        status: Arc<Mutex<PeerStatus>>,
        held: VecDeque<Command>,
    ) -> (Self, mpsc::UnboundedReceiver<Incoming>) {
        let Dialed {
            wire,
            side,
            tx,
            rx,
            ended,
        } = dialed;
        let driver = Self {
            device,
            wire,
            runtime,
            side,
            by,
            incoming: tx,
            ended,
            closing: Arc::new(AtomicBool::new(false)),
            next_request: 1,
            requests: BTreeMap::new(),
            spaces: BTreeMap::new(),
            status,
            mailboxes: Mailboxes::default(),
            #[cfg(feature = "ext-libraries")]
            holds: Vec::new(),
            #[cfg(feature = "ext-libraries")]
            library_again: BTreeSet::new(),
            #[cfg(feature = "ext-libraries")]
            library_creating: BTreeSet::new(),
            redial,
            reconnected: false,
            progressed: false,
            last_bound: None,
            moved: BTreeSet::new(),
            seeking: BTreeSet::new(),
            held,
            #[cfg(any(feature = "server", feature = "server-socket"))]
            fetches: SliceFetches::default(),
            requested: BTreeSet::new(),
            #[cfg(any(feature = "server", feature = "server-socket"))]
            stopped: BTreeMap::new(),
            #[cfg(feature = "ephemeral")]
            ephemeral_connection: crate::ephemeral::ephemeral_connection(),
        };
        (driver, rx)
    }

    fn status(&self) -> std::sync::MutexGuard<'_, PeerStatus> {
        lock(&self.status)
    }

    /// Whether the transport has ended, so that nothing more goes over it.
    fn transport_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    /// Runs the connection to its end, and records why it ended.
    async fn serve_to_end(
        mut self,
        incoming: mpsc::UnboundedReceiver<Incoming>,
        commands: mpsc::UnboundedReceiver<Command>,
    ) {
        let why = self.serve(incoming, commands).await;
        // The fetches that run beside the connection end with it.
        #[cfg(any(feature = "server", feature = "server-socket"))]
        self.fetches.stop.cancel();
        self.wire.close();
        if let Acknowledger::Peer(by) = self.by {
            self.device.peer_gone(by);
        }
        // A `LibraryAttach` this connection never saw answered: its ticket
        // stays with the device, for another connection to send.
        #[cfg(feature = "ext-libraries")]
        for request in std::mem::take(&mut self.requests).into_values() {
            if let Request::Library { space, signed, .. } = request {
                library::hand_back(self.device.device_id(), space, signed);
            }
        }
        let mut status = self.status();
        status.reconnecting = false;
        status.closed = Some(why);
    }

    /// Runs the connection over each transport it opens, until it ends for
    /// good; returns why.
    async fn serve(
        &mut self,
        mut incoming: mpsc::UnboundedReceiver<Incoming>,
        mut commands: mpsc::UnboundedReceiver<Command>,
    ) -> String {
        let mut notices = self.device.subscribe();
        loop {
            let ended = self.run(&mut incoming, &mut commands, &mut notices).await;
            // The ephemeral slot values this transport delivered go with it
            // (ext-ephemeral.md, "Relaying"); the next one has a new number.
            #[cfg(feature = "ephemeral")]
            {
                self.device
                    .ephemeral_closed(self.ephemeral_connection)
                    .await;
                self.ephemeral_connection = crate::ephemeral::ephemeral_connection();
            }
            match ended {
                // A close code other than `reconnect` ends the connection,
                // on any transport (transport.md, "Reconnecting
                // elsewhere").
                Ended::Stopped(why) | Ended::Refused(why) => return why,
                // A transport opened again that is lost before any
                // `Granted` or acknowledgement is an attempt that failed.
                Ended::Closed(why) if !self.reconnected || self.progressed => return why,
                Ended::Closed(_) | Ended::Reconnect => {}
            }
            self.wire.close();
            match self.reconnect(&mut commands).await {
                Ok(fresh) => {
                    incoming = fresh;
                    notices = self.device.subscribe();
                }
                Err(why) => return why,
            }
        }
    }

    /// One transport's traffic, until it ends.
    async fn run(
        &mut self,
        incoming: &mut mpsc::UnboundedReceiver<Incoming>,
        commands: &mut mpsc::UnboundedReceiver<Command>,
        notices: &mut broadcast::Receiver<crate::device::Notice>,
    ) -> Ended {
        // Each space's present, then the commands taken while the
        // connection opened.
        while let Some(command) = self.held.pop_front() {
            if let Err(error) = self.on_command(command).await {
                return self.failed(error, incoming).await;
            }
        }
        // This device's own ephemeral frames, relayed through the peer
        // (ext-ephemeral.md, "Relaying").
        #[cfg(feature = "ephemeral")]
        let mut ephemeral = self.device.ephemeral_outgoing().await.ok();
        // Set once the device closed the connection while a
        // `LibraryAttach` was under way: the connection ends when that
        // is done, or at this deadline.
        #[cfg_attr(not(feature = "ext-libraries"), allow(unused_mut))]
        let mut closing: Option<BoxFuture<'static, ()>> = None;
        // The device's requests for chunks, as they are made and end.
        let mut requests = self.device.fetches().follow();
        // How long chunks asked for on a stream have been awaited, every
        // few seconds.
        let mut waited = self.runtime.sleep(crate::fetch::AWAIT_TICK);
        loop {
            if closing.is_some() && !self.attaching() {
                return Ended::Stopped("closed by the device".into());
            }
            let overdue = async {
                match closing.as_mut() {
                    Some(deadline) => deadline.await,
                    None => std::future::pending().await,
                }
            };
            #[cfg(feature = "ephemeral")]
            let frame = async {
                match ephemeral.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            };
            #[cfg(not(feature = "ephemeral"))]
            let frame =
                std::future::pending::<Result<(EventId, Vec<u8>), broadcast::error::RecvError>>();
            let requested = async {
                if requests.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            };
            let step = tokio::select! {
                frame = frame => match frame {
                    Ok((space, outer)) => self.send_ephemeral(space, outer).await,
                    Err(_) => Ok(()),
                },
                message = incoming.recv() => match message {
                    Some(Incoming::Closed(why)) => return Ended::Closed(why),
                    Some(Incoming::Refused(why)) => return Ended::Refused(why),
                    Some(Incoming::Reconnect) => return Ended::Reconnect,
                    None => return Ended::Closed("ended".into()),
                    Some(message) => self.on_incoming(message).await,
                },
                command = commands.recv() => match command {
                    // A create the peer accepted lapses, with its ticket
                    // used, when the connection closes before the genesis
                    // is stored (ext-libraries.md, 3.3 Attaching): the
                    // connection stays open for it.
                    Some(Command::Close) if self.attaching() => {
                        #[cfg(feature = "ext-libraries")]
                        if closing.is_none() {
                            closing = Some(self.runtime.sleep(ATTACH_DRAIN));
                        }
                        Ok(())
                    }
                    Some(Command::Close) | None => {
                        return Ended::Stopped("closed by the device".into());
                    }
                    Some(command) => self.on_command(command).await,
                },
                () = overdue => return Ended::Stopped("closed by the device".into()),
                () = requested => self.on_requests().await,
                () = &mut waited => {
                    waited = self.runtime.sleep(crate::fetch::AWAIT_TICK);
                    self.on_waited().await
                }
                notice = notices.recv() => match notice {
                    Ok(notice) => self.on_placed(notice.space, &notice.placed).await,
                    Err(broadcast::error::RecvError::Lagged(_)) => self.resync().await,
                    Err(broadcast::error::RecvError::Closed) => {
                        return Ended::Stopped("the device ended".into());
                    }
                },
            };
            if let Err(error) = step {
                return self.failed(error, incoming).await;
            }
        }
    }

    async fn on_command(&mut self, command: Command) -> Result<()> {
        // A paused space is neither stored nor fetched: its commands wait
        // for the resume, which offers and fetches everything again.
        let paused = match &command {
            Command::Reoffer(space) | Command::Fetch(space) | Command::WantStream(space, _) => {
                Some(*space)
            }
            Command::Upload(space, ..) => Some(*space),
            _ => None,
        }
        .is_some_and(|space| self.paused(&space));
        if paused {
            if let Command::Upload(_, _, reply) = command {
                let _ = reply.send(false);
            }
            return Ok(());
        }
        match command {
            Command::Attach(space) => self.attach(space).await,
            Command::Reoffer(space) => self.reoffer(space).await,
            Command::Resume(space) => self.resume(space).await,
            Command::Seek(space) => {
                self.seeking.insert(space);
                self.attach(space).await
            }
            Command::Fetch(space) => self.fetch_missing(space).await,
            Command::OfferPuts(space) => self.offer_puts(space, false).await,
            Command::Upload(space, locator, reply) => {
                self.upload_answering(space, locator, reply).await
            }
            Command::WantStream(space, stream) => self.want_stream(space, stream).await,
            Command::Mailbox(ask, reply) => self.mailbox(ask, reply).await,
            #[cfg(feature = "ext-libraries")]
            Command::Library(space) => self.library(space).await,
            #[cfg(feature = "ext-libraries")]
            Command::Hold(ask) => self.hold(ask).await,
            Command::Close => Ok(()),
        }
    }

    /// A step failed. A write fails once the transport has ended, and its
    /// reader then says why; any other failure is the device's own.
    async fn failed(
        &mut self,
        error: Error,
        incoming: &mut mpsc::UnboundedReceiver<Incoming>,
    ) -> Ended {
        if !matches!(error, Error::Connection(_)) {
            return Ended::Stopped(error.to_string());
        }
        reader_end(incoming, &self.runtime)
            .await
            .unwrap_or_else(|| Ended::Closed(error.to_string()))
    }

    /// After a `reconnect` close, or a transport opened again that ended
    /// before any `Granted` or acknowledgement (transport.md,
    /// "Reconnecting elsewhere"): the first wait's bound is
    /// `reconnect_wait`, or, after an attempt that failed, the last bound
    /// doubled. On the new transport the device presents every space again,
    /// since a proof holds only for its connection, and offers again each
    /// event the peer has not acknowledged once the store right is granted.
    /// Returns the new transport's messages, or why the connection ends
    /// instead.
    async fn reconnect(
        &mut self,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) -> std::result::Result<mpsc::UnboundedReceiver<Incoming>, String> {
        let Some(redial) = self.redial.clone() else {
            return Err("closed by the peer: reconnect".into());
        };
        let bound = match self.last_bound {
            Some(last) if !self.progressed => reconnect_bound_after(last),
            _ => reconnect_wait(),
        };
        // Every space of the transport that ended; one the peer refused
        // `moved` is no longer among them.
        let mut held: VecDeque<Command> =
            self.spaces.keys().copied().map(Command::Attach).collect();
        held.extend(self.held.drain(..));
        self.drop_transport();
        {
            let mut status = self.status();
            status.reconnecting = true;
            status.granted.clear();
            status.fetching.clear();
        }
        let (dialed, bound) = dial_again(
            &self.device,
            &self.runtime,
            &redial,
            &self.status,
            commands,
            &mut held,
            bound,
        )
        .await?;
        let Dialed {
            wire,
            side,
            tx,
            rx,
            ended,
        } = dialed;
        self.wire = wire;
        self.side = side;
        self.incoming = tx;
        self.ended = ended;
        self.held = held;
        self.last_bound = Some(bound);
        self.reconnected = true;
        self.progressed = false;
        let mut status = self.status();
        status.reconnecting = false;
        status.reconnects += 1;
        Ok(rx)
    }

    /// Whether a `LibraryAttach` is under way on this transport: sent and
    /// not answered, or a create or an import accepted whose genesis the
    /// peer has not acknowledged.
    fn attaching(&self) -> bool {
        #[cfg(feature = "ext-libraries")]
        {
            !self.library_creating.is_empty()
                || self
                    .requests
                    .values()
                    .any(|request| matches!(request, Request::Library { .. }))
        }
        #[cfg(not(feature = "ext-libraries"))]
        false
    }

    /// Forgets what belonged to the transport that ended: its spaces'
    /// state and its requests, none of which will be answered. A mailbox
    /// message's caller learns that the connection ended; a queued hold
    /// goes again, and so does a `LibraryAttach`, with its ticket.
    fn drop_transport(&mut self) {
        let requests = std::mem::take(&mut self.requests);
        #[cfg(feature = "ext-libraries")]
        for request in requests.into_values() {
            match request {
                Request::Hold(ask) => {
                    if !self.holds.contains(&ask) {
                        self.holds.push(ask);
                    }
                }
                Request::Library { space, signed, .. } => {
                    library::restore(self.device.device_id(), space, signed);
                    self.library_again.insert(space);
                }
                _ => {}
            }
        }
        #[cfg(not(feature = "ext-libraries"))]
        drop(requests);
        #[cfg(feature = "ext-libraries")]
        self.library_creating.clear();
        self.mailboxes.answers.clear();
        self.spaces.clear();
        // The fetches of the transport stop before their next slice, and
        // the next transport takes the device's requests again.
        #[cfg(any(feature = "server", feature = "server-socket"))]
        {
            self.fetches.stop.cancel();
            self.fetches = SliceFetches::default();
            self.stopped.clear();
        }
        self.requested.clear();
    }

    /// The peer handed the space over (peers.md, "Hosting a space"): it is
    /// reported `moved`, as other refusals are, and never presented on this
    /// connection again. What waited for it there is answered `moved`.
    fn moved(&mut self, space: EventId) {
        let code = moved_code().to_owned();
        self.moved.insert(space);
        self.spaces.remove(&space);
        {
            let mut status = self.status();
            status.granted.remove(&space);
            if !status.refused.contains(&(space, code.clone())) {
                status.refused.push((space, code.clone()));
            }
        }
        let (gone, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.mailboxes.waiting)
            .into_iter()
            .partition(|(s, ..)| *s == space);
        self.mailboxes.waiting = waiting;
        for (_, _, reply) in gone {
            let _ = reply.send(Err(code.clone()));
        }
        #[cfg(feature = "ext-libraries")]
        {
            let device = self.device.device_id();
            let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.holds)
                .into_iter()
                .partition(|ask| ask.space == space);
            self.holds = kept;
            for ask in gone {
                holds::answer(device, &ask, Err(code.clone()));
            }
        }
    }

    /// A request refused `moved`: its space is the one handed over.
    fn refused_moved(&mut self, request: Request) {
        let space = match request {
            Request::Present { space, .. }
            | Request::Merge { space, .. }
            | Request::Fetch { space }
            | Request::Register { space, .. } => space,
            #[cfg(feature = "ext-libraries")]
            Request::Library { space, .. } => {
                library::answer(self.device.device_id(), space, Err(moved_code().to_owned()));
                space
            }
            #[cfg(feature = "ext-libraries")]
            Request::Hold(ask) => {
                holds::answer(self.device.device_id(), &ask, Err(moved_code().to_owned()));
                ask.space
            }
        };
        self.moved(space);
    }

    fn request(&mut self, request: Request) -> u64 {
        let number = self.next_request;
        self.next_request += 1;
        self.requests.insert(number, request);
        number
    }

    /// Offers every event of the space not yet durable again, under the
    /// store right: an event whose parent the peer lacked, such as a
    /// roster event whose twin an administration connection has stored
    /// since, is acknowledged once offered again.
    async fn reoffer(&mut self, space: EventId) -> Result<()> {
        if self.device.residue_only(&space).await {
            return Ok(());
        }
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if !attached.rights.contains(&Right::Store) {
            return Ok(());
        }
        let outbox = self.device.outbox(&space).await;
        if outbox.is_empty() {
            return Ok(());
        }
        attached.session.forget(&outbox);
        let messages = self
            .device
            .sync_offer(&mut attached.session, &outbox)
            .await?;
        self.send_sync(space, messages).await
    }

    async fn attach(&mut self, space: EventId) -> Result<()> {
        if self.spaces.contains_key(&space) || self.moved.contains(&space) {
            return Ok(());
        }
        let mut session = SyncSession::new(space);
        session.set_acknowledges(false);
        // This device's own skeleton events go on administration
        // connections only (peers.md, "Administration connections").
        session.withhold(self.device.own_skeleton(&space).await);
        self.spaces.insert(
            space,
            Attached {
                session,
                rights: BTreeSet::new(),
                granted_state: None,
                pending: BTreeSet::new(),
                tried: BTreeSet::new(),
                started: false,
                subscribed: false,
                streams: None,
                offered_outbox: false,
                offered_puts: false,
                creating: false,
                merged: BTreeSet::new(),
                inputs: BTreeSet::new(),
                fetch_token: None,
                store_token: None,
                uploaded: BTreeSet::new(),
                uploading: BTreeSet::new(),
                upload_answers: BTreeMap::new(),
                deferred: Vec::new(),
                #[cfg(any(feature = "server", feature = "server-socket"))]
                fetching: BTreeSet::new(),
                #[cfg(any(feature = "server", feature = "server-socket"))]
                refused: BTreeSet::new(),
                uploads: BTreeSet::new(),
                fetch_key: false,
                registering: BTreeSet::new(),
                heads_under_fetch: false,
                present_wait: None,
                present_scheduled: false,
            },
        );
        self.present_current(space).await
    }

    /// Sends this device's ephemeral frame of a space whose `live` right the
    /// connection holds (ext-ephemeral.md, "Sending").
    #[cfg_attr(not(feature = "ephemeral"), allow(clippy::unused_async))]
    async fn send_ephemeral(&mut self, space: EventId, outer: Vec<u8>) -> Result<()> {
        let live = self
            .spaces
            .get(&space)
            .is_some_and(|attached| attached.rights.contains(&Right::Live));
        if !live {
            return Ok(());
        }
        let message = frasil_transport::messages::Ephemeral {
            scope: Scope::Space(space.0),
            frame: outer,
            origin: None,
        }
        .encode();
        self.wire.ephemeral(&message).await
    }

    /// Sends a mailbox message now, or once the connection holds the store
    /// right it needs.
    async fn mailbox(&mut self, ask: MailboxAsk, reply: MailboxReply) -> Result<()> {
        if let Some(space) = ask.needs_store() {
            if self.moved.contains(&space) {
                let _ = reply.send(Err(moved_code().to_owned()));
                return Ok(());
            }
            let stores = self
                .spaces
                .get(&space)
                .is_some_and(|attached| attached.rights.contains(&Right::Store));
            if !stores {
                self.mailboxes.waiting.push((space, ask, reply));
                return self.attach(space).await;
            }
        }
        // A peer deletes a drop only on a connection that proved the entry
        // it was placed under, and the heal after a claim moves the
        // connection on: it proves the drop's state's upload key first,
        // and its current one after (ext-invite-links.md, "Making an
        // invite and keeping drops" and "Administering devices").
        #[cfg(feature = "ext-invite-links")]
        let restore = match &ask {
            MailboxAsk::DropDelete {
                space,
                under: Some(state),
                ..
            } => {
                self.present_upload(*space, state.clone()).await?;
                Some(*space)
            }
            _ => None,
        };
        let number = self.next_request;
        self.next_request += 1;
        self.mailboxes.answers.insert(number, reply);
        let message = ask.encode(number);
        self.wire.control(&message).await?;
        #[cfg(feature = "ext-invite-links")]
        if let Some(space) = restore {
            let current = self
                .device
                .read(&space, |replica| replica.current().cloned())
                .await?;
            if let Some(current) = current {
                self.present_upload(space, current).await?;
            }
        }
        Ok(())
    }

    /// Proves a state's upload key on this connection, when the device
    /// writes and holds it.
    #[cfg(feature = "ext-invite-links")]
    async fn present_upload(&mut self, space: EventId, state: RotationSet) -> Result<()> {
        let me = self.device.device_id();
        let publishes = self.publishes_claim(&space).await;
        let upload = self
            .device
            .read(&space, |replica| {
                credentials(replica, &me, &state, publishes).and_then(|(_, upload)| upload)
            })
            .await?;
        match upload {
            Some(upload) => {
                self.present(space, Credential::Upload, state, &upload)
                    .await
            }
            None => Ok(()),
        }
    }

    /// Sends the mailbox messages that waited for a space's store right.
    async fn mailboxes_after_store(&mut self, space: EventId) -> Result<()> {
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.mailboxes.waiting)
            .into_iter()
            .partition(|(s, ..)| *s == space);
        self.mailboxes.waiting = waiting;
        for (_, ask, reply) in ready {
            self.mailbox(ask, reply).await?;
        }
        Ok(())
    }

    /// Answers a mailbox message: `true` when `request` was one.
    fn mailbox_answered(&mut self, request: u64, answer: MailboxAnswer) -> bool {
        match self.mailboxes.answers.remove(&request) {
            Some(reply) => {
                let _ = reply.send(answer);
                true
            }
            None => false,
        }
    }

    /// Presents the read credential of the space's current state, and its
    /// upload key when the device writes, unless the peer granted it, is
    /// answering it, or refused it since it last acknowledged an event.
    async fn present_current(&mut self, space: EventId) -> Result<()> {
        let state = self
            .device
            .read(&space, |replica| replica.current().cloned())
            .await?;
        match state {
            Some(state) => self.present_state(space, state).await,
            None => self.present_fetch_key(space).await,
        }
    }

    /// Presents a fetch key for a space whose state the device does not
    /// hold, while it recovers: the peer grants catch-up, whose space
    /// events hold the wraps it opens (identity.md, "Recovery", step 1;
    /// transport.md, "Presenting credentials").
    async fn present_fetch_key(&mut self, space: EventId) -> Result<()> {
        let presented = self
            .spaces
            .get(&space)
            .is_none_or(|attached| attached.fetch_key);
        if presented {
            return Ok(());
        }
        let Some(seed) = self.device.fetch_seed(&space).await else {
            return Ok(());
        };
        if let Some(attached) = self.spaces.get_mut(&space) {
            attached.fetch_key = true;
            attached
                .session
                .set_serving(frasil_transport::roster::Serving::Nothing);
        }
        let number = self.request(Request::Fetch { space });
        let message = self
            .side
            .present(number, &space.0, Credential::Fetch, &seed);
        self.wire.control(&message).await
    }

    /// Registers at the peer, as recovery entries, the fetch keys the
    /// personal space records for each space whose store right the
    /// connection holds, that it has not sent yet (identity.md, "Adding
    /// list members": a device registers every entry whose list member is
    /// active at each peer it uses). `None` checks every such space.
    async fn register_entries(&mut self, only: Option<EventId>) -> Result<()> {
        let spaces: Vec<EventId> = self
            .spaces
            .iter()
            .filter(|(space, attached)| {
                only.is_none_or(|o| o == **space) && attached.rights.contains(&Right::Store)
            })
            .map(|(space, _)| *space)
            .collect();
        if spaces.is_empty() {
            return Ok(());
        }
        let entries = self.device.recovery_entries().await;
        for space in spaces {
            let keys = entries
                .iter()
                .filter(|(s, _)| *s == space)
                .map(|(_, key)| *key);
            for key in keys {
                let Some(attached) = self.spaces.get_mut(&space) else {
                    continue;
                };
                if !attached.registering.insert(key) {
                    continue;
                }
                let number = self.request(Request::Register { space, key });
                let message = frasil_transport::messages::RegisterRecoveryEntry {
                    request: number,
                    space: space.0,
                    fetch_key: key,
                }
                .encode();
                self.wire.control(&message).await?;
            }
        }
        Ok(())
    }

    /// Presents a state's read credential, and its upload key when the
    /// device writes and holds it.
    async fn present_state(&mut self, space: EventId, state: RotationSet) -> Result<()> {
        let me = self.device.device_id();
        let publishes = self.publishes_claim(&space).await;
        let Some((read, upload)) = self
            .device
            .read(&space, |replica| {
                credentials(replica, &me, &state, publishes)
            })
            .await?
        else {
            return Ok(());
        };
        // A claimant whose successor is not durable, holding no upload key
        // of this state, stores under the state its invite key held
        // (ext-invite-links.md, "Claiming", step 11).
        let claim = match &upload {
            None if publishes => self.claim_upload(&space).await,
            _ => None,
        };
        let upload = upload.map(|seed| (state.clone(), seed)).or(claim);
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if attached.pending.contains(&state) || attached.tried.contains(&state) {
            return Ok(());
        }
        if attached.granted_state.as_ref() == Some(&state) {
            // A device that came to write at a granted state presents its
            // upload key then.
            if let Some((under, upload)) = upload
                && !attached.rights.contains(&Right::Store)
                && attached.uploads.insert(under.clone())
            {
                attached
                    .session
                    .set_serving(frasil_transport::roster::Serving::Everything);
                self.present(space, Credential::Upload, under, &upload)
                    .await?;
            }
            return Ok(());
        }
        attached.pending.insert(state.clone());
        attached.session.set_serving(if upload.is_some() {
            frasil_transport::roster::Serving::Everything
        } else {
            frasil_transport::roster::Serving::Nothing
        });
        if let Some((under, _)) = &upload {
            attached.uploads.insert(under.clone());
        }
        self.present(space, Credential::Read, state, &read).await?;
        if let Some((under, upload)) = upload {
            self.present(space, Credential::Upload, under, &upload)
                .await?;
        }
        Ok(())
    }

    /// The state a claimant's successor is sealed under, and its upload
    /// key, while the successor is not durable.
    #[cfg_attr(not(feature = "ext-invite-links"), allow(clippy::unused_async))]
    async fn claim_upload(&self, space: &EventId) -> Option<(RotationSet, [u8; 32])> {
        #[cfg(feature = "ext-invite-links")]
        {
            self.device.claim_upload(space).await
        }
        #[cfg(not(feature = "ext-invite-links"))]
        {
            let _ = space;
            None
        }
    }

    /// Whether the device publishes a successor of its own in the space
    /// (ext-invite-links.md, "Claiming", step 11).
    #[cfg_attr(not(feature = "ext-invite-links"), allow(clippy::unused_async))]
    async fn publishes_claim(&self, space: &EventId) -> bool {
        #[cfg(feature = "ext-invite-links")]
        {
            self.device.publishes_claim(space).await
        }
        #[cfg(not(feature = "ext-invite-links"))]
        {
            let _ = space;
            false
        }
    }

    /// After the peer refused a state it may not hold yet: presents the
    /// device's current state again after a wait, from `present_retry`,
    /// doubling to 30 seconds, while the connection holds no grant at it
    /// (transport.md, "Presenting credentials"). Another member may store
    /// its entry meanwhile.
    async fn present_later(&mut self, space: EventId) -> Result<()> {
        let current = self
            .device
            .read(&space, |replica| replica.current().cloned())
            .await?;
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if attached.present_scheduled || (current.is_some() && attached.granted_state == current) {
            return Ok(());
        }
        let wait = attached.present_wait.unwrap_or_else(present_retry);
        attached.present_wait = Some((wait * 2).min(PRESENT_RETRY_MAX));
        attached.present_scheduled = true;
        let incoming = self.incoming.clone();
        let sleep = self.runtime.sleep(wait);
        self.runtime.spawn(async move {
            sleep.await;
            let _ = incoming.send(Incoming::Present(space));
        });
        Ok(())
    }

    /// After the peer refused a state it may not hold yet: the newest
    /// valid rotation the device holds that it has not tried, so that the
    /// device can store the newer rotations under a state the peer knows.
    async fn present_older(&mut self, space: EventId) -> Result<()> {
        let Some(attached) = self.spaces.get(&space) else {
            return Ok(());
        };
        if attached.granted_state.is_some() || !attached.pending.is_empty() {
            return Ok(());
        }
        let skip: BTreeSet<RotationSet> = attached.tried.clone();
        let older = self
            .device
            .read(&space, |replica| {
                let log = replica.log()?;
                log.canonical()
                    .into_iter()
                    .rev()
                    .filter(|id| {
                        replica
                            .status(id)
                            .is_some_and(frasil_space::Status::is_valid)
                            && replica.event(*id).is_some_and(crate::replica::rotates)
                            && replica.secrets_of(id).is_some_and(|s| s.content.is_some())
                    })
                    .map(RotationSet::single)
                    .find(|state| !skip.contains(state))
            })
            .await?;
        match older {
            Some(state) => self.present_state(space, state).await,
            None => Ok(()),
        }
    }

    async fn present(
        &mut self,
        space: EventId,
        credential: Credential,
        state: RotationSet,
        seed: &[u8; 32],
    ) -> Result<()> {
        let number = self.request(Request::Present {
            space,
            credential,
            state,
        });
        let message = self.side.present(number, &space.0, credential, seed);
        self.wire.control(&message).await
    }

    async fn on_incoming(&mut self, incoming: Incoming) -> Result<()> {
        match incoming {
            Incoming::Control(message) => self.on_control(message).await,
            // What a peer sends for a paused space is not taken.
            Incoming::Sync(space, _)
                if self.paused(&space) || self.device.residue_only(&space).await =>
            {
                Ok(())
            }
            Incoming::Sync(space, bytes) => self.on_sync(space, &bytes).await,
            Incoming::Retry(space, event) => {
                let Some(attached) = self.spaces.get_mut(&space) else {
                    return Ok(());
                };
                attached.session.forget(&[event]);
                let messages = self
                    .device
                    .sync_offer(&mut attached.session, &[event])
                    .await?;
                self.send_sync(space, messages).await
            }
            Incoming::Present(space) => {
                let Some(attached) = self.spaces.get_mut(&space) else {
                    return Ok(());
                };
                attached.present_scheduled = false;
                // Refused states may have entries at the peer by now, and
                // the space may be there.
                attached.tried.clear();
                attached.creating = false;
                self.present_current(space).await
            }
            Incoming::Restated(space) => {
                let Some(attached) = self.spaces.get_mut(&space) else {
                    return Ok(());
                };
                let messages = self
                    .device
                    .sync_restated(&mut attached.session, self.by)
                    .await?;
                self.send_raw(space, messages).await
            }
            Incoming::Closed(_) | Incoming::Refused(_) | Incoming::Reconnect => Ok(()),
            #[cfg(any(feature = "server", feature = "server-socket"))]
            Incoming::Fetched(fetched) => self.on_fetched(fetched).await,
            #[cfg(any(feature = "server", feature = "server-socket"))]
            Incoming::Again(request) => {
                self.on_again(request).await;
                Ok(())
            }
        }
    }

    async fn on_control(&mut self, message: Message) -> Result<()> {
        match message.kind {
            MessageType::Granted => {
                let Ok(granted) = Granted::read(&message) else {
                    return Ok(());
                };
                self.progressed = true;
                let (space, credential, state) = match self.requests.remove(&granted.request) {
                    Some(Request::Present {
                        space,
                        credential,
                        state,
                    }) => (space, credential, Some(state)),
                    Some(Request::Fetch { space }) => (space, Credential::Fetch, None),
                    _ => return Ok(()),
                };
                // Objects whose upload found no store token yet: the units
                // held back behind them go once they are at the peer.
                let mut to_upload = BTreeSet::new();
                if let Some(attached) = self.spaces.get_mut(&space) {
                    if let Some(token) = granted.transfer_token {
                        if granted.rights.contains(&Right::Store) {
                            attached.store_token = Some(token);
                            to_upload = attached
                                .deferred
                                .iter()
                                .flat_map(|(_, waiting)| waiting.iter().copied())
                                .filter(|locator| !attached.uploading.contains(locator))
                                .collect();
                        }
                        if granted.rights.contains(&Right::Fetch)
                            || granted.rights.contains(&Right::CatchUp)
                        {
                            attached.fetch_token = Some(token);
                        }
                    }
                    if credential == Credential::Read
                        && let Some(state) = state
                    {
                        attached.pending.remove(&state);
                        attached.granted_state = Some(state);
                        attached.present_wait = None;
                    }
                }
                for locator in to_upload {
                    self.upload(space, locator).await?;
                }
                self.on_granted(space, granted.rights).await?;
                self.fetch_missing(space).await
            }
            MessageType::Refused => {
                let Ok(refused) = Refused::read(&message) else {
                    return Ok(());
                };
                if self.mailbox_answered(refused.request, Err(refused.code.clone())) {
                    return Ok(());
                }
                let Some(request) = self.requests.remove(&refused.request) else {
                    return Ok(());
                };
                self.on_refused(request, refused.code).await
            }
            MessageType::Accepted => {
                let Ok(accepted) = Accepted::read(&message) else {
                    return Ok(());
                };
                if self.mailbox_answered(accepted.request, Ok(Vec::new())) {
                    return Ok(());
                }
                let request = self.requests.remove(&accepted.request);
                #[cfg(feature = "ext-libraries")]
                if let Some(Request::Library { space, purpose, .. }) = request {
                    return self.library_accepted(space, purpose).await;
                }
                #[cfg(feature = "ext-libraries")]
                if let Some(Request::Hold(ask)) = request {
                    return self.hold_accepted(ask).await;
                }
                if let Some(Request::Register { space, key }) = request {
                    self.status().registered.insert((space, key));
                    return Ok(());
                }
                if let Some(Request::Merge { space, state }) = request {
                    self.status().merges.push((space, state));
                    // The merge entry is live: present the merged state.
                    if let Some(attached) = self.spaces.get_mut(&space) {
                        attached.tried.clear();
                    }
                    self.present_current(space).await?;
                }
                Ok(())
            }
            MessageType::EventRefused => {
                let Ok(refused) = EventRefused::read(&message) else {
                    return Ok(());
                };
                self.on_event_refused(refused);
                Ok(())
            }
            // A frame the peer relays (ext-ephemeral.md, "Relaying"): taken
            // as from any member; one that fails is dropped.
            #[cfg(feature = "ephemeral")]
            MessageType::Ephemeral => {
                if let Ok(frame) = frasil_transport::messages::Ephemeral::read(
                    &message,
                    ConnectionKind::DeviceToPeer,
                ) && let Scope::Space(space) = frame.scope
                {
                    let delivery = frasil_ephemeral::replay::Delivery {
                        connection: self.ephemeral_connection,
                        origin: frame.origin,
                    };
                    let _ = self
                        .device
                        .receive_ephemeral(EventId(space), &frame.frame, delivery)
                        .await;
                }
                Ok(())
            }
            // The peer names an origin gone: the ephemeral slot values it
            // delivered with it are dropped (ext-ephemeral.md, "Relaying").
            #[cfg(feature = "ephemeral")]
            MessageType::Gone => {
                if let Ok(gone) =
                    frasil_transport::messages::Gone::read(&message, ConnectionKind::DeviceToPeer)
                    && let Scope::Space(space) = gone.scope
                {
                    self.device
                        .ephemeral_gone(EventId(space), self.ephemeral_connection, gone.origin)
                        .await;
                }
                Ok(())
            }
            MessageType::MailboxItems => {
                if let Ok(items) = frasil_transport::mailbox::MailboxItems::read(&message) {
                    self.mailbox_answered(items.request, Ok(items.items));
                }
                Ok(())
            }
            // Nothing else concerns space traffic.
            _ => Ok(()),
        }
    }

    async fn on_granted(&mut self, space: EventId, rights: Vec<Right>) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        // Catch-up gave way to fetch: the device presented the newer state
        // that catch-up brought it (transport.md, "Presenting
        // credentials"), and syncs again with everything in reach.
        let caught_up = !attached.rights.contains(&Right::Fetch)
            && attached.rights.contains(&Right::CatchUp)
            && rights.contains(&Right::Fetch);
        attached.rights.extend(rights.iter().copied());
        if caught_up {
            attached.started = false;
            attached.offered_outbox = false;
        }
        let all = attached.rights.clone();
        self.status().granted.insert(space, all.clone());
        let mut messages = Vec::new();
        let fetches = all.contains(&Right::Fetch) || all.contains(&Right::CatchUp);
        let stores = all.contains(&Right::Store);
        // A newcomer admitted "from now on" places no event before its
        // snapshot (admission.md, "The newcomer's snapshot"): it fetches
        // the snapshot first, then syncs.
        let awaits = self
            .device
            .read(&space, |replica| {
                replica.awaited_snapshot().is_some() || replica.wants_snapshot()
            })
            .await
            .unwrap_or(false);
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if awaits {
            return Ok(());
        }
        if all.contains(&Right::Live) && !attached.subscribed {
            attached.subscribed = true;
            // The channel through the peer starts: this device's receiver
            // nonce and its live ephemeral slots (ext-ephemeral.md).
            #[cfg(feature = "ephemeral")]
            {
                let _ = self.device.start_receiving(space).await;
                let _ = self.device.republish_slots(space, true).await;
            }
            // A partial replica subscribes to its frame and its streams.
            let held = self
                .device
                .read(&space, |replica| {
                    replica.held_streams().map(|held| {
                        let mut streams = held.clone();
                        streams.extend(replica.system_stream());
                        streams
                    })
                })
                .await
                .ok()
                .flatten();
            let Some(attached) = self.spaces.get_mut(&space) else {
                return Ok(());
            };
            attached.streams = held.clone();
            messages.push(SyncMessage {
                space,
                message: UnitMessage::Subscribe {
                    streams: held.map(|h| h.into_iter().collect()).unwrap_or_default(),
                },
            });
        }
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if !attached.started && (fetches || stores) {
            attached.started = true;
            messages.extend(self.device.sync_start(&mut attached.session).await?);
        }
        if stores && self.mailboxes.waiting.iter().any(|(s, ..)| *s == space) {
            self.mailboxes_after_store(space).await?;
        }
        if stores {
            self.register_entries(Some(space)).await?;
        }
        // A `LibraryAttach` the transport before did not see answered goes
        // again; a create or an import sent it already, before its genesis.
        #[cfg(feature = "ext-libraries")]
        if stores && self.library_again.remove(&space) {
            self.send_library_attach(space).await?;
        }
        #[cfg(feature = "ext-libraries")]
        self.send_holds().await?;
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if stores && !attached.offered_outbox {
            // Every event not yet durable is offered again on every
            // connection; the peer acknowledges an identical retry.
            attached.offered_outbox = true;
            let outbox = self.device.outbox(&space).await;
            attached.session.forget(&outbox);
            messages.extend(
                self.device
                    .sync_offer(&mut attached.session, &outbox)
                    .await?,
            );
        }
        self.send_sync(space, messages).await?;
        let offers = self
            .spaces
            .get_mut(&space)
            .is_some_and(|attached| stores && !std::mem::replace(&mut attached.offered_puts, true));
        if offers {
            self.offer_puts(space, true).await?;
        }
        Ok(())
    }

    /// Uploads again the objects this device put in a space whose record
    /// still says that no peer is known to hold them, and that no unit of
    /// the outbox names: the peer answers whether it holds each, and the
    /// device releases those it holds and has acknowledged a unit of
    /// (at-rest.md, "Retention", an object the device put). It is the
    /// upload a writer makes before a unit, and no other message.
    async fn offer_puts(&mut self, space: EventId, connected: bool) -> Result<()> {
        let stores = self
            .spaces
            .get(&space)
            .is_some_and(|attached| attached.rights.contains(&Right::Store));
        if !stores || self.paused(&space) || self.transport_ended() {
            return Ok(());
        }
        for locator in self.device.puts_to_offer(space, self.by, connected).await {
            let Some(attached) = self.spaces.get_mut(&space) else {
                return Ok(());
            };
            if attached.uploading.contains(&locator) {
                continue;
            }
            // What an earlier upload on this connection left is asked
            // again: the peer may have collected the object since.
            attached.uploaded.remove(&locator);
            self.upload(space, locator).await?;
        }
        Ok(())
    }

    async fn on_refused(&mut self, request: Request, code: String) -> Result<()> {
        if code == moved_code() {
            self.refused_moved(request);
            return Ok(());
        }
        match request {
            Request::Present {
                space,
                credential,
                state,
            } => {
                // A peer that erased the space answers `erased` from then
                // on; what the device's view says of that erasure is told
                // to the application (peers.md, "The administrator's
                // duties").
                if code == "erased" {
                    self.device.note_erased_at_peer(space);
                }
                if credential == Credential::Read
                    && let Some(attached) = self.spaces.get_mut(&space)
                {
                    attached.pending.remove(&state);
                    attached.tried.insert(state.clone());
                }
                if code == "no_library" && self.seeking.contains(&space) {
                    let mut status = self.status();
                    if !status.refused.contains(&(space, code.clone())) {
                        status.refused.push((space, code));
                    }
                    return Ok(());
                }
                if code == "no_library" {
                    // Another device may create the space at the peer
                    // first, and this genesis then grants nothing: present
                    // again later.
                    self.create(space).await?;
                    return self.present_later(space).await;
                }
                if credential != Credential::Read {
                    return Ok(());
                }
                if code == "credential_refused" {
                    if state.len() > 1 {
                        self.merged_refused(space, credential, state).await?;
                    }
                    self.present_older(space).await?;
                    return self.present_later(space).await;
                }
                self.status().refused.push((space, code));
                Ok(())
            }
            Request::Merge { space, state } => {
                self.status().refused.push((space, code));
                self.present_inputs(space, state).await
            }
            // A fetch key the peer holds no live recovery entry of: the
            // recovery fails with the peer's refusal (identity.md,
            // "Recovery", step 1). Nothing is created.
            Request::Fetch { space } => {
                self.status().refused.push((space, code));
                Ok(())
            }
            Request::Register { space, key } => {
                if let Some(attached) = self.spaces.get_mut(&space) {
                    attached.registering.remove(&key);
                }
                self.status().refused.push((space, code));
                Ok(())
            }
            #[cfg(feature = "ext-libraries")]
            Request::Library { space, .. } => {
                if let Some(attached) = self.spaces.get_mut(&space) {
                    attached.creating = false;
                }
                library::answer(self.device.device_id(), space, Err(code.clone()));
                self.status().refused.push((space, code));
                Ok(())
            }
            #[cfg(feature = "ext-libraries")]
            Request::Hold(ask) => self.hold_refused(ask, code).await,
        }
    }

    /// The peer does not host the space: store its genesis, which creates
    /// it (peers.md, "Hosting a space"), then present again.
    async fn create(&mut self, space: EventId) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if attached.creating {
            return Ok(());
        }
        attached.creating = true;
        // ext-libraries.md, 3.3 Attaching: a ticket the device holds for
        // the space goes first; the genesis follows its `Accepted`.
        #[cfg(feature = "ext-libraries")]
        if self.send_library_attach(space).await? {
            return Ok(());
        }
        self.send_genesis(space).await
    }

    /// Stores the space's genesis at the peer, which creates it there.
    async fn send_genesis(&mut self, space: EventId) -> Result<()> {
        let genesis = self
            .device
            .read(&space, |replica| {
                replica.event(space).map(frasil_events::Event::signed)
            })
            .await?;
        let Some(genesis) = genesis else {
            return Ok(());
        };
        self.send_sync(
            space,
            vec![SyncMessage {
                space,
                message: UnitMessage::Events {
                    events: vec![genesis],
                },
            }],
        )
        .await
    }

    /// A merged state the peer holds no entry for: a writer that holds
    /// every input's upload seed tells it the merged credentials; otherwise
    /// the device presents its inputs' credentials (peers.md, "Merge
    /// statements").
    async fn merged_refused(
        &mut self,
        space: EventId,
        credential: Credential,
        state: RotationSet,
    ) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if attached.merged.contains(&state) || credential != Credential::Read {
            return Ok(());
        }
        let statement = self
            .device
            .read(&space, |replica| merge_statement(replica, &space, &state))
            .await?;
        match statement {
            Some(statement) => {
                attached.merged.insert(state.clone());
                let number = self.request(Request::Merge { space, state });
                let message = Merge {
                    request: number,
                    statement: statement.encode(),
                }
                .encode()
                .map_err(Error::class)?;
                self.wire.control(&message).await
            }
            None => self.present_inputs(space, state).await,
        }
    }

    /// Presents the credentials of each input of a merged state the device
    /// holds.
    async fn present_inputs(&mut self, space: EventId, state: RotationSet) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if !attached.inputs.insert(state.clone()) {
            return Ok(());
        }
        let me = self.device.device_id();
        let inputs = self
            .device
            .read(&space, |replica| {
                state
                    .ids()
                    .iter()
                    .filter_map(|id| {
                        let secrets = replica.secrets_of(id)?;
                        let read = read_credential(secrets.content.as_ref()?).seed;
                        let upload = replica
                            .uploads(&me)
                            .then(|| secrets.upload.as_ref().map(|w| upload_key(w).seed))
                            .flatten();
                        Some((*id, read, upload))
                    })
                    .collect::<Vec<_>>()
            })
            .await?;
        for (id, read, upload) in inputs {
            let single = RotationSet::single(id);
            self.present(space, Credential::Read, single.clone(), &read)
                .await?;
            if let Some(upload) = upload {
                self.present(space, Credential::Upload, single, &upload)
                    .await?;
            }
        }
        Ok(())
    }

    fn on_event_refused(&mut self, refused: EventRefused) {
        let space = EventId(refused.space);
        let event = EventId(refused.event);
        // A genesis refused: the pending create lapsed.
        #[cfg(feature = "ext-libraries")]
        self.library_creating.remove(&space);
        // An event of a space handed over since the connection was granted
        // in it (peers.md, "Hosting a space").
        if refused.code == moved_code() {
            self.moved(space);
        }
        match refused.code.as_str() {
            "rate_limited" => {
                let incoming = self.incoming.clone();
                let wait = self.runtime.sleep(RETRY_AFTER);
                self.runtime.spawn(async move {
                    wait.await;
                    let _ = incoming.send(Incoming::Retry(space, event));
                });
            }
            "conflict" => self.status().note_fork(space, event),
            _ => {}
        }
        self.status()
            .refused_events
            .push((space, event, refused.code));
    }

    async fn on_sync(&mut self, space: EventId, bytes: &[u8]) -> Result<()> {
        let Ok(Received::Message(message)) = SyncMessage::read(bytes) else {
            return Ok(());
        };
        if message.space != space {
            return Ok(());
        }
        // What the peer is known to hold: what it sends, lists as its heads
        // or acknowledges (peers.md, "The administrator's duties": votes
        // wait for each reached peer to hold a checkpoint's cut).
        if let Acknowledger::Peer(by) = self.by {
            let held: Vec<EventId> = match &message.message {
                UnitMessage::Heads { heads, .. } | UnitMessage::Ack { heads } => heads.clone(),
                UnitMessage::Events { events } => events
                    .iter()
                    .filter_map(|signed| frasil_events::decode(signed).ok())
                    .map(|event| event.id())
                    .collect(),
                _ => Vec::new(),
            };
            self.device.peer_holds(space, by, &held);
        }
        match message.message {
            UnitMessage::ObjectHave { locators, counts } => {
                // An object's acknowledgement (transport.md, 3.12).
                self.progressed = true;
                return self.on_object_have(space, locators, counts).await;
            }
            UnitMessage::ObjectChunks {
                locator,
                header,
                index,
                chunk,
            } => {
                return self
                    .on_object_chunk(space, locator, header, index, chunk)
                    .await;
            }
            UnitMessage::StreamHeads {
                stream,
                latest_snapshot,
                writers,
            } => {
                // Completeness: the peer's gaps asked for by ID, and a
                // peer that serves less than this device holds reported.
                let (missing, withheld) = self
                    .device
                    .stream_heads_check(space, stream, latest_snapshot, &writers)
                    .await;
                {
                    let mut status = self.status();
                    status
                        .stream_heads
                        .insert((space, stream), (latest_snapshot, writers));
                    if withheld {
                        status.withheld.insert((space, stream));
                        status
                            .lost
                            .insert((space, crate::outbox::LossClass::Withheld));
                    }
                }
                if withheld {
                    self.device.report_loss(crate::outbox::Loss {
                        space,
                        by: self.by,
                        class: crate::outbox::LossClass::Withheld,
                        events: Vec::new(),
                    });
                }
                if !missing.is_empty() {
                    self.send_raw(
                        space,
                        vec![SyncMessage {
                            space,
                            message: UnitMessage::Want {
                                ids: missing,
                                ranges: Vec::new(),
                                kinds: Vec::new(),
                                streams: Vec::new(),
                            },
                        }],
                    )
                    .await?;
                }
                return Ok(());
            }
            _ => {}
        }
        let acknowledged = matches!(message.message, UnitMessage::Ack { .. });
        self.progressed |= acknowledged;
        let heads = matches!(message.message, UnitMessage::Heads { .. });
        let created = match &message.message {
            UnitMessage::Ack { heads } => heads.contains(&space),
            _ => false,
        };
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if heads && attached.rights.contains(&Right::Fetch) {
            attached.heads_under_fetch = true;
        }
        // A peer lists less to a connection without the fetch right: only
        // under it do its `Heads` show its whole state (units.md, 3.13
        // "Detected loss").
        attached
            .session
            .set_judges(attached.rights.contains(&Right::Fetch));
        let messages = self
            .device
            .sync_receive(&mut attached.session, self.by, message)
            .await?;
        if attached.session.take_stated_missing() {
            // The peer may not have received a statement's heads yet:
            // asked again once `withholding_grace` has passed (units.md,
            // 3.13 "Head statements").
            let incoming = self.incoming.clone();
            let grace = Duration::from_secs(crate::statements::withholding_grace() + 1);
            let sleep = self.runtime.sleep(grace);
            self.runtime.spawn(async move {
                sleep.await;
                let _ = incoming.send(Incoming::Restated(space));
            });
        }
        let lost = self.device.lost_by(&self.by);
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lost
            .extend(lost);
        if attached.heads_under_fetch
            && self
                .device
                .read(&space, |replica| attached.session.caught_up(replica))
                .await
                .unwrap_or(false)
        {
            self.status
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .caught_up
                .insert(space);
        }
        if acknowledged {
            // The peer may hold entries it lacked: try again.
            attached.tried.clear();
        }
        #[cfg(feature = "ext-libraries")]
        if created {
            self.library_creating.remove(&space);
        }
        if created && attached.creating {
            attached.creating = false;
            self.status().created.push(space);
        }
        self.send_sync(space, messages).await?;
        self.present_current(space).await?;
        self.fetch_missing(space).await
    }

    async fn on_placed(&mut self, space: EventId, placed: &[EventId]) -> Result<()> {
        self.follow_streams(space).await?;
        let own = self.device.own_skeleton(&space).await;
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        attached.session.withhold(own);
        if attached.started {
            let messages = self
                .device
                .sync_offer(&mut attached.session, placed)
                .await?;
            self.send_sync(space, messages).await?;
        }
        // A new recovery entry in the personal space is registered at once.
        if self.device.personal_space().await == Some(space) {
            self.register_entries(None).await?;
        }
        self.present_current(space).await
    }

    /// At a partial replica, the streams it opened since it last
    /// subscribed: each is asked for by `StreamWant`, and `Subscribe` names
    /// them all again (units.md, "Sync", by stream; "Partial replicas").
    async fn follow_streams(&mut self, space: EventId) -> Result<()> {
        let Some(subscribed) = self
            .spaces
            .get(&space)
            .and_then(|attached| attached.streams.clone())
        else {
            return Ok(());
        };
        let held = self
            .device
            .read(&space, |replica| {
                replica.held_streams().map(|held| {
                    let mut streams = held.clone();
                    streams.extend(replica.system_stream());
                    streams
                })
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let new: Vec<StreamId> = held.difference(&subscribed).copied().collect();
        if new.is_empty() {
            return Ok(());
        }
        if let Some(attached) = self.spaces.get_mut(&space) {
            attached.streams = Some(held.clone());
        }
        self.send_raw(
            space,
            vec![SyncMessage {
                space,
                message: UnitMessage::Subscribe {
                    streams: held.into_iter().collect(),
                },
            }],
        )
        .await?;
        for stream in new {
            self.want_stream(space, stream).await?;
        }
        Ok(())
    }

    /// Whether the application paused the space's sync with peers.
    fn paused(&self, space: &EventId) -> bool {
        self.device.links().is_paused(space)
    }

    /// A pause ended: the space's heads are offered again, as at the start,
    /// and what it lacks is fetched, so it catches up.
    async fn resume(&mut self, space: EventId) -> Result<()> {
        if self.device.residue_only(&space).await {
            return Ok(());
        }
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if attached.started {
            let messages = self.device.sync_start(&mut attached.session).await?;
            self.send_sync(space, messages).await?;
        }
        self.fetch_missing(space).await
    }

    /// After missing notices: offer every space's heads again.
    async fn resync(&mut self) -> Result<()> {
        let spaces: Vec<EventId> = self.spaces.keys().copied().collect();
        for space in spaces {
            if self.device.residue_only(&space).await {
                continue;
            }
            let Some(attached) = self.spaces.get_mut(&space) else {
                continue;
            };
            if !attached.started {
                continue;
            }
            let messages = self.device.sync_start(&mut attached.session).await?;
            self.send_sync(space, messages).await?;
        }
        Ok(())
    }

    async fn send_sync(&mut self, space: EventId, messages: Vec<SyncMessage>) -> Result<()> {
        let mut out = Vec::new();
        for message in messages {
            match message.message {
                UnitMessage::Events { events } => {
                    let ready = self.hold_back(space, events).await?;
                    if !ready.is_empty() {
                        out.push(SyncMessage {
                            space,
                            message: UnitMessage::Events { events: ready },
                        });
                    }
                }
                other => out.push(SyncMessage {
                    space,
                    message: other,
                }),
            }
        }
        self.send_raw(space, out).await
    }

    async fn send_raw(&mut self, space: EventId, messages: Vec<SyncMessage>) -> Result<()> {
        // A paused space sends nothing: no store, no fetch.
        if self.paused(&space) {
            return Ok(());
        }
        for message in messages {
            // units.md's messages for members only never go to a peer.
            if message.message.member_connections_only() {
                continue;
            }
            let wrapped = Sync {
                scope: Scope::Space(space.0),
                message: message.encode(),
            }
            .encode();
            self.wire.sync(space, &wrapped, &self.incoming).await?;
        }
        Ok(())
    }
}

/// The locators a signed event names, if it is a unit.
fn named(signed: &[u8]) -> BTreeSet<Locator> {
    let Ok(event) = frasil_events::decode(signed) else {
        return BTreeSet::new();
    };
    // A skeleton cut names its checkpoint's record object, which its author
    // uploads before the cut and the checkpoint reach the peer (roster.md,
    // "The record object"; peers.md, "Skeleton cuts").
    if event.kind() == frasil_events::kind::STORAGE {
        return frasil_peers::body::StorageBody::read(event.unverified_body())
            .ok()
            .and_then(|body| body.cut().map(|cut| cut.record))
            .into_iter()
            .collect();
    }
    frasil_units::Unit::from_event(event)
        .ok()
        .map(|unit| unit.body.objects.iter().copied().collect())
        .unwrap_or_default()
}

/// Why an upload over the HTTP chunk routes stopped.
#[cfg(any(feature = "server", feature = "server-socket"))]
enum Stopped {
    /// The transfer failed or the peer refused a slice: what it said.
    Refused(String),
    /// The device no longer holds a chunk it was to send.
    Gone,
    /// The connection is closing: the next one goes on from what the peer
    /// holds.
    Closing,
}

impl Driver {
    /// Splits events into those ready to send and units held back until
    /// the objects they name are at the peer, whose uploads it starts. An
    /// event after a held-back one waits behind it, so that the peer
    /// receives each event after its parents: one whose parent it lacks
    /// it neither stores nor refuses.
    async fn hold_back(&mut self, space: EventId, events: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let mut ready = Vec::new();
        let mut uploads = BTreeSet::new();
        {
            let Some(attached) = self.spaces.get_mut(&space) else {
                return Ok(events);
            };
            for signed in events {
                let waiting: BTreeSet<Locator> = named(&signed)
                    .into_iter()
                    .filter(|locator| !attached.uploaded.contains(locator))
                    .collect();
                if waiting.is_empty() && attached.deferred.is_empty() {
                    ready.push(signed);
                } else {
                    uploads.extend(
                        waiting
                            .iter()
                            .filter(|locator| !attached.uploading.contains(*locator))
                            .copied(),
                    );
                    attached.deferred.push((signed, waiting));
                }
            }
        }
        // What is ready goes first: an upload that completes at once sends
        // the units held back behind it, which may be children of these.
        if !uploads.is_empty() && !ready.is_empty() {
            self.send_raw(
                space,
                vec![SyncMessage {
                    space,
                    message: UnitMessage::Events {
                        events: std::mem::take(&mut ready),
                    },
                }],
            )
            .await?;
        }
        for locator in uploads {
            self.upload(space, locator).await?;
        }
        Ok(ready)
    }

    /// Uploads an object: over HTTP on the server binding, in `ObjectChunks`
    /// on an object stream over iroh (transport.md, section 3.15; units.md,
    /// "Sync", objects).
    async fn upload(&mut self, space: EventId, locator: Locator) -> Result<()> {
        // A reference's object is the source's, which a peer holds for the
        // space: the device registers a hold instead (adapter-blobs.md,
        // "References").
        #[cfg(all(feature = "ext-libraries", feature = "adapter-blobs"))]
        if let Some((source, object_key)) = self.device.reference_of(&space, &locator).await {
            return self
                .hold(holds::HoldAsk {
                    space,
                    source,
                    locator,
                    object_key,
                })
                .await;
        }
        // Read a chunk at a time as it is sent, never whole.
        let Some(source) = self.device.object_upload(&space, &locator).await else {
            return self.no_copy(space, locator).await;
        };
        if self.transport_ended() {
            // The next transport uploads it, under its own token.
            return Ok(());
        }
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        attached.uploading.insert(locator);
        match &mut self.wire {
            #[cfg(feature = "server")]
            Wire::Server(_, http) => {
                let Some(token) = attached.store_token else {
                    attached.uploading.remove(&locator);
                    return Ok(());
                };
                match http
                    .put_object(&token, &space, &locator, source, &self.closing)
                    .await
                {
                    Ok(()) => self.uploaded(space, locator).await,
                    Err(Stopped::Closing) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        Ok(())
                    }
                    Err(Stopped::Gone) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        self.no_copy(space, locator).await
                    }
                    Err(Stopped::Refused(code)) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        // A transfer of a transport that ended was no
                        // refusal.
                        if !self.transport_ended() {
                            self.status().refused.push((space, code));
                        }
                        Ok(())
                    }
                }
            }
            #[cfg(feature = "server-socket")]
            Wire::Socket(socket, origin) => {
                let Some(token) = attached.store_token else {
                    attached.uploading.remove(&locator);
                    return Ok(());
                };
                let put = socket::put_object(
                    socket.as_ref(),
                    origin,
                    &token,
                    &space,
                    &locator,
                    source,
                    &self.closing,
                )
                .await;
                match put {
                    Ok(()) => self.uploaded(space, locator).await,
                    Err(Stopped::Closing) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        Ok(())
                    }
                    Err(Stopped::Gone) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        self.no_copy(space, locator).await
                    }
                    Err(Stopped::Refused(code)) => {
                        if let Some(attached) = self.spaces.get_mut(&space) {
                            attached.uploading.remove(&locator);
                        }
                        // A transfer of a transport that ended was no
                        // refusal.
                        if !self.transport_ended() {
                            self.status().refused.push((space, code));
                        }
                        Ok(())
                    }
                }
            }
            #[cfg(feature = "iroh")]
            Wire::Iroh(wire) => {
                let encode = |part: crate::snapshots::ObjectPart| {
                    Sync {
                        scope: Scope::Space(space.0),
                        message: SyncMessage {
                            space,
                            message: UnitMessage::ObjectChunks {
                                locator,
                                header: part.header,
                                index: part.index,
                                chunk: part.chunk,
                            },
                        }
                        .encode(),
                    }
                    .encode()
                };
                // The peer answers `ObjectHave` on the space's sync stream,
                // which must be open.
                wire.ensure_sync(space, &self.incoming).await?;
                if wire.object(space, source, encode).await? {
                    return Ok(());
                }
                if let Some(attached) = self.spaces.get_mut(&space) {
                    attached.uploading.remove(&locator);
                }
                self.no_copy(space, locator).await
            }
        }
    }

    /// An object to upload of which this device holds no copy it can give,
    /// or no longer does part way through.
    async fn no_copy(&mut self, space: EventId, locator: Locator) -> Result<()> {
        // A held file not served while its space has no provider may
        // still be the object's copy: the unit waits for it.
        if self.transport_ended() || self.device.keeps_held(&space, &locator).await {
            return Ok(());
        }
        // An object this device holds no copy of, such as a held one whose
        // file was saved over: its units go without it (units.md, 3.4 What
        // a writer does, item 7), and a device that holds it uploads it
        // when it offers them.
        self.release(space, locator).await
    }

    /// Uploads an object, then answers whether the peer holds it. What an
    /// earlier upload on this connection left is asked again: the peer may
    /// have collected the object since. An upload that does not start, or
    /// that the peer refuses, answers no; one that waits for `ObjectHave`
    /// answers then, or the answer is dropped with the connection.
    async fn upload_answering(
        &mut self,
        space: EventId,
        locator: Locator,
        reply: tokio::sync::oneshot::Sender<bool>,
    ) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            let _ = reply.send(false);
            return Ok(());
        };
        attached
            .upload_answers
            .entry(locator)
            .or_default()
            .push(reply);
        attached.uploaded.remove(&locator);
        if !attached.uploading.contains(&locator) {
            self.upload(space, locator).await?;
        }
        if let Some(attached) = self.spaces.get_mut(&space)
            && !attached.uploading.contains(&locator)
            && !attached.uploaded.contains(&locator)
        {
            for reply in attached.upload_answers.remove(&locator).unwrap_or_default() {
                let _ = reply.send(false);
            }
        }
        Ok(())
    }

    /// An object is at the peer: send the units that waited for it.
    async fn uploaded(&mut self, space: EventId, locator: Locator) -> Result<()> {
        // A hold that waited for its source's upload may go now.
        #[cfg(feature = "ext-libraries")]
        self.send_holds().await?;
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        attached.uploading.remove(&locator);
        attached.uploaded.insert(locator);
        // An object this device put has another holder now.
        self.device.object_at_peer(space, self.by, &locator).await?;
        for reply in attached.upload_answers.remove(&locator).unwrap_or_default() {
            let _ = reply.send(true);
        }
        self.release(space, locator).await
    }

    /// Sends the units that waited for an object and wait for nothing else:
    /// once it is at the peer, or once this device finds it holds no copy.
    /// The latter is not taken as at the peer, so a later unit that names
    /// it asks again whether this device holds it. Events go in the order
    /// they were held back: one that waits for nothing more still waits
    /// behind an earlier one that does, since it may be its child.
    async fn release(&mut self, space: EventId, locator: Locator) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        let mut ready = Vec::new();
        let mut still = Vec::new();
        for (signed, mut waiting) in std::mem::take(&mut attached.deferred) {
            waiting.remove(&locator);
            if waiting.is_empty() && still.is_empty() {
                ready.push(signed);
            } else {
                still.push((signed, waiting));
            }
        }
        attached.deferred = still;
        if ready.is_empty() {
            return Ok(());
        }
        self.send_raw(
            space,
            vec![SyncMessage {
                space,
                message: UnitMessage::Events { events: ready },
            }],
        )
        .await
    }

    async fn on_object_have(
        &mut self,
        space: EventId,
        locators: Vec<Locator>,
        counts: Option<Vec<u64>>,
    ) -> Result<()> {
        let counts = counts.unwrap_or_default();
        for (i, locator) in locators.into_iter().enumerate() {
            let Some(held) = counts.get(i).copied() else {
                continue;
            };
            // Whole here, by the header's chunk count.
            let Some((have, Some(total))) = self.device.object_progress(&space, &locator).await
            else {
                continue;
            };
            if have >= total && held >= total {
                self.uploaded(space, locator).await?;
            }
        }
        Ok(())
    }

    /// A chunk the peer sent in answer to an `ObjectWant` of this
    /// connection: checked as it arrives (units.md, "Sync", objects), and
    /// kept if it is still wanted. A chunk that fails drops what the
    /// device held of the object, which is no longer asked of this peer.
    async fn on_object_chunk(
        &mut self,
        space: EventId,
        locator: Locator,
        header: Option<Vec<u8>>,
        index: u64,
        chunk: Vec<u8>,
    ) -> Result<()> {
        use crate::objects::Taken;
        let Some(attached) = self.spaces.get_mut(&space) else {
            return Ok(());
        };
        if !attached.session.is_fetching(&locator) {
            return Ok(());
        }
        let part = crate::snapshots::ObjectPart {
            locator,
            header,
            index,
            chunk,
        };
        let (taken, wants) = self.device.take_chunk(&mut attached.session, part).await?;
        // The fetch's progress, while chunks of the object are awaited or
        // yet to ask for: the stored bytes held of it.
        let fetching = attached.session.is_fetching(&locator);
        let held = match taken {
            Taken::Kept | Taken::Dropped if fetching => {
                self.device.object_bytes_held(&space, &locator).await
            }
            _ => None,
        };
        {
            let mut status = self.status();
            match held {
                Some(held) => status.fetching.insert(locator, held),
                None => status.fetching.remove(&locator),
            };
        }
        // The next chunks, once every chunk asked for is in.
        self.send_raw(space, wants).await?;
        // Whole now: every chunk kept, or the plaintext with the application.
        if taken == Taken::Whole {
            return self.start_after_snapshot(space).await;
        }
        Ok(())
    }

    /// Sends `StreamWant` for a stream, with each writer's frontier the
    /// device holds, from the latest snapshot.
    async fn want_stream(&mut self, space: EventId, stream: StreamId) -> Result<()> {
        let held = self
            .device
            .read(&space, |replica| {
                replica.log().map(|log| {
                    frasil_units::compaction::covers(
                        log,
                        |id| crate::compaction::stream_of(log, id),
                        &log.heads(),
                        &stream,
                    )
                })
            })
            .await?
            .unwrap_or_default();
        self.send_raw(
            space,
            vec![SyncMessage {
                space,
                message: UnitMessage::StreamWant {
                    stream,
                    held,
                    from_snapshot: true,
                },
            }],
        )
        .await
    }

    /// Fetches the objects the space's units name that the device lacks,
    /// and the chunks the device was asked for: by slices over HTTP on
    /// the server binding, each on a task beside the connection, and by
    /// `ObjectWant` over iroh. The connection goes on meanwhile.
    async fn fetch_missing(&mut self, space: EventId) -> Result<()> {
        if !self.fetches(&space) {
            return Ok(());
        }
        let missing = self.device.missing_objects(&space).await;
        for locator in missing {
            // The next transport fetches the rest, under its own token.
            if self.transport_ended() {
                return Ok(());
            }
            if self.wire.by_slices() {
                #[cfg(any(feature = "server", feature = "server-socket"))]
                self.queue_object(space, locator);
            } else {
                // A state object's header comes first: it must name no
                // more than the adapter loads before the rest is asked
                // for.
                let Some(attached) = self.spaces.get_mut(&space) else {
                    return Ok(());
                };
                let wants = self.device.want_in(&mut attached.session, locator).await;
                self.send_raw(space, wants).await?;
            }
        }
        self.take_requests(space).await?;
        #[cfg(any(feature = "server", feature = "server-socket"))]
        self.pump().await;
        self.start_after_snapshot(space).await
    }

    /// Whether the connection fetches a space's objects now: it holds the
    /// fetch or the catch-up right, and the space is not paused.
    fn fetches(&self, space: &EventId) -> bool {
        !self.paused(space)
            && self.spaces.get(space).is_some_and(|attached| {
                attached.rights.contains(&Right::Fetch) || attached.rights.contains(&Right::CatchUp)
            })
    }

    /// Takes the requests for chunks made of the device for a space
    /// ([`Engine::fetch_chunks`]) that this transport has not taken yet.
    ///
    /// [`Engine::fetch_chunks`]: crate::device::Engine::fetch_chunks
    async fn take_requests(&mut self, space: EventId) -> Result<()> {
        if !self.fetches(&space) || self.transport_ended() {
            return Ok(());
        }
        if !self.wire.by_slices() {
            let Some(attached) = self.spaces.get_mut(&space) else {
                return Ok(());
            };
            let wants = self
                .device
                .want_requests(&mut attached.session, false)
                .await;
            return self.send_raw(space, wants).await;
        }
        // The connection takes the space's requests once it may fetch.
        #[cfg(any(feature = "server", feature = "server-socket"))]
        if let Some(attached) = self.spaces.get_mut(&space)
            && attached.fetch_token.is_some()
        {
            attached.session.taker(self.device.fetches());
        }
        // A request for an object refused on this connection is left: its
        // holder heard why when it made it, unless another connection
        // will try.
        #[cfg(any(feature = "server", feature = "server-socket"))]
        for request in self.device.fetches().of(&space) {
            let served = self.spaces.get(&space).is_some_and(|attached| {
                attached.fetch_token.is_some() && !attached.refused.contains(&request.locator)
            });
            if served && self.requested.insert(request.id) {
                self.fetches.queue.push(request);
            }
        }
        Ok(())
    }

    /// The device's requests for chunks changed: each space takes those
    /// made since, and the fetches that wait start.
    async fn on_requests(&mut self) -> Result<()> {
        let live = self.device.fetches().clone();
        self.requested.retain(|id| live.is_live(*id));
        #[cfg(any(feature = "server", feature = "server-socket"))]
        self.stopped.retain(|id, _| live.is_live(*id));
        let spaces: Vec<EventId> = self.spaces.keys().copied().collect();
        for space in spaces {
            self.take_requests(space).await?;
        }
        #[cfg(any(feature = "server", feature = "server-socket"))]
        self.pump().await;
        Ok(())
    }

    /// A few seconds passed: on a stream, each space gives up the chunks
    /// it awaited too long with no answer and asks for what it has yet
    /// to ask for (units.md, "Sync", objects), and an object none of
    /// whose chunks is awaited any longer is no longer reported.
    async fn on_waited(&mut self) -> Result<()> {
        if self.wire.by_slices() || self.transport_ended() {
            return Ok(());
        }
        let spaces: Vec<EventId> = self.spaces.keys().copied().collect();
        for space in spaces {
            if self.paused(&space) {
                continue;
            }
            let Some(attached) = self.spaces.get_mut(&space) else {
                continue;
            };
            let wants = self
                .device
                .sync_waited(&mut attached.session, crate::fetch::AWAIT_TICK)
                .await;
            self.send_raw(space, wants).await?;
        }
        let spaces = &self.spaces;
        lock(&self.status).fetching.retain(|locator, _| {
            spaces
                .values()
                .any(|attached| attached.session.is_fetching(locator))
        });
        Ok(())
    }

    /// Syncs a space whose start waited for the newcomer's snapshot, once
    /// the device took it.
    async fn start_after_snapshot(&mut self, space: EventId) -> Result<()> {
        let waiting = self
            .spaces
            .get(&space)
            .is_some_and(|attached| !attached.started && !attached.rights.is_empty());
        if waiting {
            self.on_granted(space, Vec::new()).await?;
        }
        Ok(())
    }
}

/// A state's read seed, and its upload seed when the device writes and
/// holds it.
fn credentials(
    replica: &Replica,
    me: &DeviceId,
    state: &RotationSet,
    publishes_claim: bool,
) -> Option<([u8; 32], Option<[u8; 32]>)> {
    let (content, _) = replica.state_key(state)?;
    let read = *read_credential(&content).seed;
    let upload = (publishes_claim || replica.uploads(me))
        .then(|| replica.state_upload(state))
        .flatten()
        .map(|seed| *upload_key(&seed).seed);
    Some((read, upload))
}

/// A merge statement of a merged state, when the device holds its key and
/// every input's upload seed.
fn merge_statement(
    replica: &Replica,
    space: &EventId,
    state: &RotationSet,
) -> Option<MergeStatement> {
    let (content, _) = replica.state_key(state)?;
    let upload = replica.state_upload(state)?;
    let seeds: Vec<[u8; 32]> = state
        .ids()
        .iter()
        .map(|id| {
            replica
                .secrets_of(id)
                .and_then(|s| s.upload.as_ref())
                .map(|w| *upload_key(w).seed)
        })
        .collect::<Option<_>>()?;
    Some(MergeStatement::sign(
        *space,
        state.clone(),
        read_credential(&content).public,
        upload_key(&upload).public,
        &seeds,
    ))
}

/// How a fetch by slices ended.
#[cfg(any(feature = "server", feature = "server-socket"))]
enum SliceFetch {
    /// Every slice taken, or every chunk wanted held already.
    Done,
    /// The peer lacks it, the transfer was cut, or the transport or the
    /// space's sync stopped: what is kept stays, and a later fetch takes
    /// the rest.
    Stopped,
    /// The request was cancelled: the fetch stopped before its next slice.
    Cancelled,
    /// It gave way to a more urgent request: it waits again, and goes on
    /// from what the device holds by then.
    GaveWay,
    /// A chunk failed its check, and the device dropped what it held.
    Refused,
    /// A slice did not read as the header gives it, and the device
    /// dropped what it held.
    Malformed,
    /// The device could not keep a part.
    Failed(Error),
}

/// A fetch by slices that ended.
#[cfg(any(feature = "server", feature = "server-socket"))]
struct Fetched {
    /// The request it served: the device's, or, with number 0, an object
    /// the space's units name.
    request: crate::fetch::Request,
    /// The transport's number for the fetch.
    serial: u64,
    ended: SliceFetch,
    /// Whether it kept a chunk itself.
    kept: bool,
}

/// A fetch by slices that runs.
#[cfg(any(feature = "server", feature = "server-socket"))]
struct Running {
    space: EventId,
    locator: Locator,
    priority: crate::fetch::FetchPriority,
    /// Signalled when a more urgent request waits for its place.
    gives_way: crate::fetch::Cancel,
    /// Signalled when another fetch of the object found the peer's bytes
    /// wrong: the object is no longer asked of this peer.
    refused: crate::fetch::Cancel,
}

/// The slices that the fetches of one transport share, by space, locator
/// and slice index.
#[cfg(any(feature = "server", feature = "server-socket"))]
type SharedSlices = crate::fetch::Slices<(EventId, Locator, u64), Vec<u8>>;

/// The fetches by slices of one transport.
#[cfg(any(feature = "server", feature = "server-socket"))]
#[derive(Default)]
struct SliceFetches {
    /// Those that wait for a task, most urgent first.
    queue: crate::fetch::Queue,
    /// Those that run, each one slice request at a time, by the numbers
    /// the transport gave them.
    running: BTreeMap<u64, Running>,
    /// Counts the fetches started.
    started: u64,
    /// The slices they share.
    slices: Arc<SharedSlices>,
    /// Signalled when the transport ends: each stops before its next
    /// slice.
    stop: crate::fetch::Cancel,
}

/// The slices a fetch is about to take: the next one and the one after,
/// which a fetch of the neighbouring chunks takes too
/// ([`Slices`](crate::fetch::Slices)).
#[cfg(any(feature = "server", feature = "server-socket"))]
struct Claims {
    slices: Arc<SharedSlices>,
    space: EventId,
    locator: Locator,
    claimed: BTreeSet<u64>,
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl Claims {
    fn new(slices: Arc<SharedSlices>, space: EventId, locator: Locator) -> Self {
        Self {
            slices,
            space,
            locator,
            claimed: BTreeSet::new(),
        }
    }

    /// Claims `slice` and the one after, and releases every other.
    fn window(&mut self, slice: u64) {
        let wanted = [slice, slice.saturating_add(1)];
        for index in wanted {
            if self.claimed.insert(index) {
                self.slices.claim((self.space, self.locator, index));
            }
        }
        let taken: Vec<u64> = self
            .claimed
            .iter()
            .copied()
            .filter(|index| !wanted.contains(index))
            .collect();
        for index in taken {
            self.claimed.remove(&index);
            self.slices.release(&(self.space, self.locator, index));
        }
    }
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl Drop for Claims {
    fn drop(&mut self) {
        for index in &self.claimed {
            self.slices.release(&(self.space, self.locator, *index));
        }
    }
}

/// Why a slice did not arrive.
#[cfg(any(feature = "server", feature = "server-socket"))]
enum NoSlice {
    /// The peer lacks the object.
    Lacking,
    /// The request failed: what it said.
    Failed(#[allow(dead_code)] String),
}

/// The HTTP chunk routes of a transport (transport.md, "Objects over
/// HTTP"), for a fetch that runs beside the connection.
#[cfg(any(feature = "server", feature = "server-socket"))]
#[derive(Clone)]
enum SliceRoutes {
    #[cfg(feature = "server")]
    Server(server::Http),
    #[cfg(feature = "server-socket")]
    Socket(Arc<dyn socket::ServerSocket>, String),
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl SliceRoutes {
    /// One slice of an object's stored bytes from the peer. `abort` is
    /// signalled when the answer is no longer wanted.
    async fn get(
        &self,
        token: &[u8; 32],
        space: &EventId,
        locator: &Locator,
        index: u64,
        abort: &crate::fetch::Cancel,
    ) -> std::result::Result<Vec<u8>, NoSlice> {
        let slice = match self {
            // Dropping the request ends its transfer.
            #[cfg(feature = "server")]
            Self::Server(http) => http.get_slice(token, space, locator, index).await,
            #[cfg(feature = "server-socket")]
            Self::Socket(socket, origin) => {
                socket::get_slice(socket.as_ref(), origin, token, space, locator, index, abort)
                    .await
            }
        };
        #[cfg(not(feature = "server-socket"))]
        let _ = abort;
        match slice {
            Ok(Some(slice)) => Ok(slice),
            Ok(None) => Err(NoSlice::Lacking),
            Err(why) => Err(NoSlice::Failed(why)),
        }
    }
}

/// One fetch of chunks of an object by slices of its stored bytes, on a
/// task beside the connection: one slice at a time, from the slice of
/// the first chunk the device lacks, leaving out the chunks it holds.
/// Each sealed chunk is cut out once its slices arrived, checked and
/// kept as a part on a stream is ([`Engine::receive_part`]): partial
/// objects stay in the store, and the object, once whole, is checked
/// against its locator's digest (units.md, "Reading an object", step 0).
/// The fetch holds the slice being read and the bytes of one chunk.
///
/// [`Engine::receive_part`]: crate::device::Engine::receive_part
#[cfg(any(feature = "server", feature = "server-socket"))]
struct SliceTask {
    device: Engine,
    routes: SliceRoutes,
    token: [u8; 32],
    request: crate::fetch::Request,
    /// The header the device held when the fetch was planned, and the
    /// first chunk it lacked.
    header: Option<Vec<u8>>,
    first: u64,
    slices: Arc<SharedSlices>,
    claims: Claims,
    /// Signalled when the transport ends.
    stop: crate::fetch::Cancel,
    /// Signalled when a more urgent request waits for this fetch's place.
    gives_way: crate::fetch::Cancel,
    /// Signalled when another fetch of the object found the peer's bytes
    /// wrong.
    refused: crate::fetch::Cancel,
    /// Set once the transport's readers end.
    ended: Arc<AtomicBool>,
    /// Set once the connection is to close.
    closing: Arc<AtomicBool>,
    status: Arc<Mutex<PeerStatus>>,
    /// Whether this fetch kept a chunk: its own progress, whatever other
    /// fetches of the object kept meanwhile.
    kept: bool,
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl SliceTask {
    async fn run(&mut self) -> SliceFetch {
        use crate::objects::{Received, SliceReader};
        let (space, locator) = (self.request.space, self.request.locator);
        let end = self.request.chunks.end;
        let mut reader = SliceReader::start(locator, self.header.take(), self.first..end);
        loop {
            if self.request.cancel.is_cancelled() {
                return SliceFetch::Cancelled;
            }
            if self.gives_way.is_cancelled() {
                return SliceFetch::GaveWay;
            }
            if self.stop.is_cancelled()
                || self.refused.is_cancelled()
                || self.ended.load(Ordering::Acquire)
                || self.closing.load(Ordering::Acquire)
                || self.device.links().is_paused(&space)
            {
                return SliceFetch::Stopped;
            }
            // Chunks that arrived meanwhile, in another fetch or from
            // another party, are left out.
            if let Some(next) = reader.next_chunk() {
                match self
                    .device
                    .chunks_to_fetch(&space, &locator, next..end)
                    .await
                {
                    Some((_, lacked)) => reader.seek(lacked),
                    None => return SliceFetch::Done,
                }
            }
            let Some(index) = reader.next_slice() else {
                return SliceFetch::Done;
            };
            self.claims.window(index);
            let abort = crate::fetch::Cancel::new();
            let key = (space, locator, index);
            let slice = tokio::select! {
                slice = self.slices.get(
                    &key,
                    self.routes.get(&self.token, &space, &locator, index, &abort),
                ) => slice,
                () = self.request.cancel.cancelled() => {
                    abort.cancel();
                    return SliceFetch::Cancelled;
                }
                () = self.stop.cancelled() => {
                    abort.cancel();
                    return SliceFetch::Stopped;
                }
                () = self.refused.cancelled() => {
                    abort.cancel();
                    return SliceFetch::Stopped;
                }
                // What a reader waits for goes first: the slice under way
                // is given up, and asked for again later.
                () = self.gives_way.cancelled() => {
                    abort.cancel();
                    return SliceFetch::GaveWay;
                }
            };
            let Ok(slice) = slice else {
                return SliceFetch::Stopped;
            };
            let Ok(parts) = reader.take(&slice) else {
                return match self.device.drop_fetched(space, &locator).await {
                    Ok(()) => SliceFetch::Malformed,
                    Err(error) => SliceFetch::Failed(error),
                };
            };
            drop(slice);
            for part in parts {
                // Cancelled while the slice was on its way: none of its
                // parts is stored for this request.
                if self.request.cancel.is_cancelled() {
                    return SliceFetch::Cancelled;
                }
                match self.device.receive_part(space, part).await {
                    Ok(Received::Kept) => self.kept = true,
                    Ok(Received::Whole) => return SliceFetch::Done,
                    Ok(Received::Refused) => return SliceFetch::Refused,
                    // What the device held of the object went meanwhile,
                    // or the receive of it through a provider does not
                    // take this chunk: a later fetch starts from where
                    // the device stands then.
                    Ok(Received::Headerless | Received::Left) => return SliceFetch::Stopped,
                    Err(error) => return SliceFetch::Failed(error),
                }
            }
            // The fetch's progress: the stored bytes held of the object.
            if let Some(held) = self.device.object_bytes_held(&space, &locator).await {
                lock(&self.status).fetching.insert(locator, held);
            }
        }
    }
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl Driver {
    /// Queues a fetch of an object the space's units name, whole, behind
    /// what readers wait for, unless it waits or runs already.
    fn queue_object(&mut self, space: EventId, locator: Locator) {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return;
        };
        if attached.fetch_token.is_none()
            || attached.refused.contains(&locator)
            || !attached.fetching.insert(locator)
        {
            return;
        }
        self.fetches
            .queue
            .push(crate::fetch::Request::of_units(space, locator));
    }

    /// Starts the fetches that wait, most urgent first, each on a task of
    /// its own, while fewer than [`SLICES_AT_ONCE`] run: the connection
    /// goes on reading messages, and hears of each as it ends. When as
    /// many run as may, and a request waits that is more urgent than one
    /// of them, the least urgent gives way.
    ///
    /// [`SLICES_AT_ONCE`]: crate::fetch::SLICES_AT_ONCE
    async fn pump(&mut self) {
        loop {
            if self.fetches.running.len() >= crate::fetch::SLICES_AT_ONCE {
                self.give_way();
                return;
            }
            let Some(request) = self.fetches.queue.pop() else {
                return;
            };
            let (space, locator) = (request.space, request.locator);
            let token = self
                .spaces
                .get(&space)
                .filter(|attached| !attached.refused.contains(&locator))
                .and_then(|attached| attached.fetch_token);
            let routes = self.wire.slice_routes();
            let (Some(token), Some(routes)) = (token, routes) else {
                self.unserved(&request);
                continue;
            };
            if self.transport_ended() || self.paused(&space) {
                self.unserved(&request);
                continue;
            }
            // Where it starts, as the device stands now.
            let Some((header, first)) = self
                .device
                .chunks_to_fetch(&space, &locator, request.chunks.clone())
                .await
            else {
                // Nothing of it is lacking.
                if let Some(attached) = self.spaces.get_mut(&space)
                    && request.id == 0
                {
                    attached.fetching.remove(&locator);
                }
                continue;
            };
            // What the device holds of it already is the fetch's progress
            // from its start.
            if let Some(held) = self.device.object_bytes_held(&space, &locator).await {
                self.status().fetching.insert(locator, held);
            }
            // Its first slices are claimed before it runs, so that a fetch
            // of the neighbouring chunks started beside it shares them.
            let mut claims = Claims::new(self.fetches.slices.clone(), space, locator);
            claims.window(if header.is_some() { first } else { 0 });
            let gives_way = crate::fetch::Cancel::new();
            let refused = crate::fetch::Cancel::new();
            self.fetches.started += 1;
            let serial = self.fetches.started;
            self.fetches.running.insert(
                serial,
                Running {
                    space,
                    locator,
                    priority: request.priority,
                    gives_way: gives_way.clone(),
                    refused: refused.clone(),
                },
            );
            let mut task = SliceTask {
                device: self.device.clone(),
                routes,
                token,
                request,
                header,
                first,
                slices: self.fetches.slices.clone(),
                claims,
                stop: self.fetches.stop.clone(),
                gives_way,
                refused,
                ended: self.ended.clone(),
                closing: self.closing.clone(),
                status: self.status.clone(),
                kept: false,
            };
            let incoming = self.incoming.clone();
            self.runtime.spawn(async move {
                let ended = task.run().await;
                let _ = incoming.send(Incoming::Fetched(Fetched {
                    request: task.request,
                    serial,
                    ended,
                    kept: task.kept,
                }));
            });
        }
    }

    /// Makes room for a request that waits and is more urgent than a
    /// fetch that runs: the least urgent of those, and the last started
    /// among them, stops and waits again. One at a time: the next gives
    /// way once this one is heard of.
    fn give_way(&mut self) {
        let Some(waiting) = self.fetches.queue.most_urgent() else {
            return;
        };
        let running = &self.fetches.running;
        if running.values().any(|fetch| fetch.gives_way.is_cancelled()) {
            return;
        }
        if let Some(least) = running.values().max_by_key(|fetch| fetch.priority)
            && least.priority > waiting
        {
            least.gives_way.cancel();
        }
    }

    /// A fetch that did not run: an object the space's units name is
    /// queued again when the space next fetches, and so is a request of
    /// the device.
    fn unserved(&mut self, request: &crate::fetch::Request) {
        if request.id == 0 {
            if let Some(attached) = self.spaces.get_mut(&request.space) {
                attached.fetching.remove(&request.locator);
            }
        } else {
            self.requested.remove(&request.id);
        }
    }

    /// A fetch ended: the next one that waits starts. One that gave way
    /// waits again at once. A request of the device whose fetch stopped,
    /// because its transfer was cut or the peer lacks the object for
    /// now, is tried again after a wait ([`again_after`]). One whose
    /// slices the peer sent wrong is given up for good: the object is not
    /// asked of this peer again on this connection, the other fetches of
    /// it that run stop, and whoever asked for its chunks, or asks later,
    /// hears why once no other connection of the space will try.
    ///
    /// [`again_after`]: crate::fetch::again_after
    async fn on_fetched(&mut self, fetched: Fetched) -> Result<()> {
        let Fetched {
            request,
            serial,
            ended,
            kept,
        } = fetched;
        self.fetches.running.remove(&serial);
        let (space, locator, id) = (request.space, request.locator, request.id);
        // The object's progress stays while another fetch of it runs.
        let fetching = |fetches: &SliceFetches| {
            fetches
                .running
                .values()
                .any(|fetch| fetch.space == space && fetch.locator == locator)
        };
        if !fetching(&self.fetches) {
            self.status().fetching.remove(&locator);
        }
        if matches!(ended, SliceFetch::GaveWay) {
            // It waits again, behind the request it gave way to.
            self.fetches.queue.push(request);
            self.pump().await;
            return Ok(());
        }
        let given_up = match ended {
            SliceFetch::Refused => Some(crate::fetch::FetchEnd::Refused),
            SliceFetch::Malformed => Some(crate::fetch::FetchEnd::Malformed),
            _ => None,
        };
        if let Some(attached) = self.spaces.get_mut(&space) {
            if id == 0 {
                attached.fetching.remove(&locator);
            }
            // Not asked of this peer again on this connection: who asked
            // for its chunks hears why, now and from then on, unless
            // another connection of the space will try.
            if let Some(end) = given_up {
                attached.refused.insert(locator);
                attached
                    .session
                    .taker(self.device.fetches())
                    .give_up(&locator, end);
            }
        }
        if given_up.is_some() {
            for fetch in self.fetches.running.values() {
                if fetch.space == space && fetch.locator == locator {
                    fetch.refused.cancel();
                }
            }
        }
        if id != 0 && matches!(ended, SliceFetch::Stopped) {
            let served = self
                .spaces
                .get(&space)
                .is_some_and(|attached| !attached.refused.contains(&locator));
            if served && !request.cancel.is_cancelled() {
                self.again(request, kept);
            } else {
                self.requested.remove(&id);
            }
        } else if id != 0 {
            self.stopped.remove(&id);
        }
        self.pump().await;
        match ended {
            SliceFetch::Failed(error) => Err(error),
            _ => self.start_after_snapshot(space).await,
        }
    }

    /// Tries a request whose fetch stopped again, after a wait that grows
    /// while its fetches keep nothing: `kept` says whether this one kept
    /// a chunk itself, which starts the wait over, whatever another fetch
    /// or connection kept of the object meanwhile. The request stays
    /// taken meanwhile, so that it is queued once.
    fn again(&mut self, request: crate::fetch::Request, kept: bool) {
        let stopped = self.stopped.entry(request.id).or_default();
        if kept {
            *stopped = 0;
        }
        let wait = self.runtime.sleep(crate::fetch::again_after(*stopped));
        *stopped = stopped.saturating_add(1);
        let incoming = self.incoming.clone();
        self.runtime.spawn(async move {
            wait.await;
            let _ = incoming.send(Incoming::Again(request));
        });
    }

    /// The wait of a request whose fetch stopped is over: it is queued
    /// again, unless it was cancelled meanwhile.
    async fn on_again(&mut self, request: crate::fetch::Request) {
        if request.cancel.is_cancelled() || !self.requested.contains(&request.id) {
            self.requested.remove(&request.id);
            return;
        }
        self.fetches.queue.push(request);
        self.pump().await;
    }
}

#[cfg(feature = "ext-libraries")]
impl Driver {
    /// Attaches a space to a library with the ticket the device holds for
    /// it: a space the peer does not host yet is created (or imported)
    /// with it; one it hosts is moved.
    async fn library(&mut self, space: EventId) -> Result<()> {
        let Some(attached) = self.spaces.get_mut(&space) else {
            return self.attach(space).await;
        };
        if attached.rights.is_empty() {
            attached.creating = false;
            return self.create(space).await;
        }
        self.send_library_attach(space).await.map(|_| ())
    }

    /// Sends `LibraryAttach` with the device's ticket for the space, to a
    /// peer that lists service 5; whether it was sent.
    async fn send_library_attach(&mut self, space: EventId) -> Result<bool> {
        use frasil_transport::codes::Service;
        if !self.side.peer_hello.services().contains(&Service::Library) {
            return Ok(false);
        }
        let creating = self
            .spaces
            .get(&space)
            .is_some_and(|attached| attached.creating);
        let Some((purpose, signed)) = library::take(self.device.device_id(), space, creating)
        else {
            return Ok(false);
        };
        let request = self.request(Request::Library {
            space,
            purpose,
            signed: signed.clone(),
        });
        let message = frasil_libraries::LibraryAttach {
            request,
            space: space.0,
            purpose,
            signed,
        }
        .encode();
        self.wire.control(&message).await?;
        Ok(true)
    }

    /// The peer accepted a `LibraryAttach`: a create or an import stores
    /// the genesis now; a move lets the space store again.
    async fn library_accepted(
        &mut self,
        space: EventId,
        purpose: frasil_libraries::Purpose,
    ) -> Result<()> {
        library::answer(self.device.device_id(), space, Ok(()));
        if purpose == frasil_libraries::Purpose::Move {
            if let Some(attached) = self.spaces.get_mut(&space) {
                attached.tried.clear();
                attached.offered_outbox = false;
            }
            return self.on_granted(space, Vec::new()).await;
        }
        self.library_creating.insert(space);
        self.send_genesis(space).await
    }
}

/// The library tickets a device holds (ext-libraries.md): its default
/// ticket for the next space it creates at a peer, and each space's own,
/// until a connection sends it. The tickets are opaque but for their
/// purpose, which `LibraryAttach` repeats.
#[cfg(feature = "ext-libraries")]
pub(crate) mod library {
    use frasil_crypto::device::DeviceId;
    use frasil_events::EventId;
    use frasil_libraries::{Purpose, SignedTicket};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Mutex, PoisonError};
    use tokio::sync::oneshot;

    /// A peer's answer to a `LibraryAttach`: accepted, or the code of its
    /// refusal.
    pub(crate) type Answer = std::result::Result<(), String>;

    #[derive(Default)]
    struct Book {
        default: Option<Vec<u8>>,
        spaces: BTreeMap<EventId, Vec<u8>>,
        handed_back: BTreeSet<EventId>,
        waiters: BTreeMap<EventId, Vec<oneshot::Sender<Answer>>>,
    }

    /// Each device's tickets, by its device ID.
    static BOOKS: Mutex<BTreeMap<DeviceId, Book>> = Mutex::new(BTreeMap::new());

    fn with<T>(device: DeviceId, f: impl FnOnce(&mut Book) -> T) -> T {
        let mut books = BOOKS.lock().unwrap_or_else(PoisonError::into_inner);
        f(books.entry(device).or_default())
    }

    /// A signed ticket's purpose; `None` for bytes that are no ticket.
    pub(crate) fn purpose_of(signed: &[u8]) -> Option<Purpose> {
        SignedTicket::decode(signed)
            .ok()
            .map(|signed| signed.ticket.purpose)
    }

    /// Keeps the device's default ticket, for the next space it creates at
    /// a peer that holds none of its own.
    pub(crate) fn set_default(device: DeviceId, signed: Vec<u8>) {
        with(device, |book| book.default = Some(signed));
    }

    /// Keeps a space's ticket; the receiver hears the first peer's answer.
    pub(crate) fn hold(
        device: DeviceId,
        space: EventId,
        signed: Vec<u8>,
    ) -> oneshot::Receiver<Answer> {
        let (reply, answer) = oneshot::channel();
        with(device, |book| {
            book.spaces.insert(space, signed);
            book.handed_back.remove(&space);
            book.waiters.entry(space).or_default().push(reply);
        });
        answer
    }

    /// Takes the ticket to send for a space: its own, or, for a create,
    /// the device's default create ticket.
    pub(crate) fn take(
        device: DeviceId,
        space: EventId,
        creating: bool,
    ) -> Option<(Purpose, Vec<u8>)> {
        with(device, |book| {
            if let Some(signed) = book.spaces.remove(&space) {
                book.handed_back.remove(&space);
                return purpose_of(&signed).map(|purpose| (purpose, signed));
            }
            if !creating {
                return None;
            }
            let signed = book.default.take()?;
            if purpose_of(&signed) == Some(Purpose::Create) {
                Some((Purpose::Create, signed))
            } else {
                book.default = Some(signed);
                None
            }
        })
    }

    /// Keeps again a space's ticket whose `LibraryAttach` got no answer,
    /// unless the device holds a newer one; its waiters wait on.
    pub(crate) fn restore(device: DeviceId, space: EventId, signed: Vec<u8>) {
        with(device, |book| {
            book.spaces.entry(space).or_insert(signed);
        });
    }

    /// Keeps again a space's ticket whose connection closed before the
    /// peer answered its `LibraryAttach`, as [`restore`] does, and marks
    /// it handed back: another connection is to send it.
    pub(crate) fn hand_back(device: DeviceId, space: EventId, signed: Vec<u8>) {
        with(device, |book| {
            book.spaces.entry(space).or_insert(signed);
            book.handed_back.insert(space);
        });
    }

    /// Whether a closed connection handed the space's ticket back, and no
    /// connection has taken it since.
    pub(crate) fn handed_back(device: DeviceId, space: EventId) -> bool {
        with(device, |book| book.handed_back.contains(&space))
    }

    /// Hands a peer's answer to whoever waits on the space's ticket.
    pub(crate) fn answer(device: DeviceId, space: EventId, answer: Answer) {
        let waiters = with(device, |book| {
            book.waiters.remove(&space).unwrap_or_default()
        });
        for waiter in waiters {
            let _ = waiter.send(answer.clone());
        }
    }
}

#[cfg(feature = "server")]
mod server {
    //! The server binding's WebSocket (transport.md, section 3.15).

    use super::{AtomicBool, Incoming, Ordering, Stopped, coded_close, connect_url, read, sort};
    use crate::error::{Error, Result};
    use crate::object_upload::{ObjectUpload, UploadSlices, held_of};
    use frasil_adapter::Locator;
    use frasil_events::EventId;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    /// The subprotocol of the connect route.
    const SUBPROTOCOL: &str = "frasil.p1";

    type Socket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    pub(super) struct Sink {
        sink: futures_util::stream::SplitSink<Socket, WsMessage>,
    }

    impl Sink {
        pub(super) async fn send(&mut self, message: &[u8]) -> Result<()> {
            self.sink
                .send(WsMessage::Binary(message.to_vec().into()))
                .await
                .map_err(|error| Error::Connection(error.to_string()))
        }

        pub(super) fn close(&mut self) {
            // Dropping the sink with the reader ends the WebSocket.
        }
    }

    /// The server binding's HTTP routes for object chunks.
    #[derive(Clone)]
    pub(super) struct Http {
        client: reqwest::Client,
        origin: String,
    }

    /// The size of one slice of a stored object on the chunk routes.
    const SLICE: usize = frasil_transport::frame::OBJECT_CHUNK_BYTES;

    impl Http {
        fn url(&self, space: &EventId, locator: &Locator, index: usize) -> String {
            format!(
                "{}{}",
                self.origin,
                frasil_transport::peer::chunk_path(&space.0, locator, index as u64)
            )
        }

        /// Uploads an object's stored bytes, slice by slice as its chunks
        /// are read; each is stored durably when the peer answers 201, or
        /// held already at 200.
        pub(super) async fn put_object(
            &self,
            token: &[u8; 32],
            space: &EventId,
            locator: &Locator,
            upload: ObjectUpload,
            closing: &AtomicBool,
        ) -> std::result::Result<(), Stopped> {
            let authorization = frasil_transport::peer::transfer_authorization(token);
            let mut slices = UploadSlices::new(upload, SLICE).map_err(|_| Stopped::Gone)?;
            while let Some((index, slice)) = slices.next().await.map_err(|_| Stopped::Gone)? {
                if closing.load(Ordering::Acquire) {
                    return Err(Stopped::Closing);
                }
                let index =
                    usize::try_from(index).map_err(|error| Stopped::Refused(error.to_string()))?;
                let response = self
                    .client
                    .put(self.url(space, locator, index))
                    .header("Authorization", &authorization)
                    .header("Content-Type", "application/octet-stream")
                    .body(slice)
                    .send()
                    .await
                    .map_err(|error| Stopped::Refused(error.to_string()))?;
                let status = response.status().as_u16();
                if status != 200 && status != 201 {
                    return Err(Stopped::Refused(format!("object upload: {status}")));
                }
                // The peer may hold more than this slice already, as when
                // an upload is resumed after a reopen: it goes on from
                // there.
                if let Some(held) = response.bytes().await.ok().and_then(|body| held_of(&body)) {
                    slices.resume(held);
                }
            }
            Ok(())
        }

        /// Fetches one slice of an object's stored bytes. `None` when the
        /// peer lacks it.
        pub(super) async fn get_slice(
            &self,
            token: &[u8; 32],
            space: &EventId,
            locator: &Locator,
            index: u64,
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            let authorization = frasil_transport::peer::transfer_authorization(token);
            let index = usize::try_from(index).map_err(|error| error.to_string())?;
            let response = self
                .client
                .get(self.url(space, locator, index))
                .header("Authorization", &authorization)
                .send()
                .await
                .map_err(|error| error.to_string())?;
            match response.status().as_u16() {
                200 => {}
                404 => return Ok(None),
                status => return Err(format!("object fetch: {status}")),
            }
            let body = response.bytes().await.map_err(|error| error.to_string())?;
            if body.len() > SLICE {
                return Err("an oversized slice".into());
            }
            Ok(Some(body.to_vec()))
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) async fn open(
        origin: &str,
    ) -> Result<(
        Sink,
        Http,
        mpsc::UnboundedSender<Incoming>,
        mpsc::UnboundedReceiver<Incoming>,
        Arc<AtomicBool>,
    )> {
        let url = connect_url(origin)?;
        let mut request = url
            .into_client_request()
            .map_err(|error| Error::Connection(error.to_string()))?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(SUBPROTOCOL),
        );
        let (socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|error| Error::Connection(error.to_string()))?;
        let echoed = response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .is_some_and(|value| value.as_bytes() == SUBPROTOCOL.as_bytes());
        if !echoed {
            return Err(Error::Connection(
                "the peer did not echo the subprotocol".into(),
            ));
        }
        let (sink, mut stream) = socket.split();
        let (tx, rx) = mpsc::unbounded_channel();
        let reader = tx.clone();
        let ended = Arc::new(AtomicBool::new(false));
        let ending = ended.clone();
        tokio::spawn(async move {
            let why = loop {
                match stream.next().await {
                    Some(Ok(WsMessage::Binary(bytes))) => match read(&bytes) {
                        Ok(Some(message)) => {
                            if let Some(incoming) = sort(message) {
                                let _ = reader.send(incoming);
                            }
                        }
                        Ok(None) => {}
                        Err(class) => break format!("a message that does not read: {class}"),
                    },
                    Some(Ok(WsMessage::Text(_))) => break "a text message".to_owned(),
                    Some(Ok(WsMessage::Close(frame))) => {
                        let code = frame.map_or(1000, |f| u16::from(f.code));
                        // transport.md, "Reconnecting elsewhere": 4017 is no
                        // error, and any other code of section 2.5 ends the
                        // connection.
                        if let Some(incoming) = coded_close(code) {
                            ending.store(true, Ordering::Release);
                            let _ = reader.send(incoming);
                            return;
                        }
                        break format!("closed by the peer: {code}");
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => break error.to_string(),
                    None => break "the WebSocket ended".to_owned(),
                }
            };
            ending.store(true, Ordering::Release);
            let _ = reader.send(Incoming::Closed(why));
        });
        // reqwest takes its TLS provider from the process default, and ring is
        // the only provider linked. An application that installed one keeps it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| Error::Connection(error.to_string()))?;
        Ok((
            Sink { sink },
            Http {
                client,
                origin: origin.trim_end_matches('/').to_owned(),
            },
            tx,
            rx,
            ended,
        ))
    }
}

#[cfg(feature = "iroh")]
mod iroh {
    //! The iroh binding's `frasil/p1/peer` (transport.md, section 3.16).

    use super::{AtomicBool, Incoming, Ordering, sort};
    use crate::error::{Error, Result};
    use frasil_events::EventId;
    use frasil_iroh::{Alpn, Config, Connection, Endpoint, FrameReceiver, FrameSender};
    use frasil_transport::Channel;
    use frasil_transport::messages::Scope;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn failed(error: impl core::fmt::Display) -> Error {
        Error::Connection(error.to_string())
    }

    pub(super) struct Wire {
        _endpoint: Endpoint,
        connection: Arc<Connection>,
        control: FrameSender,
        syncs: BTreeMap<EventId, FrameSender>,
        /// Set once a reader ends.
        ended: Arc<AtomicBool>,
    }

    fn read_into(
        mut receiver: FrameReceiver,
        tx: mpsc::UnboundedSender<Incoming>,
        ended: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            let why = loop {
                match receiver.receive().await {
                    Ok(Some(message)) => {
                        if let Some(incoming) = sort(message) {
                            let _ = tx.send(incoming);
                        }
                    }
                    Ok(None) => break "the stream ended".to_owned(),
                    // transport.md, "Reconnecting elsewhere": application
                    // close 17 is no error.
                    Err(error) if error.code() == Some(frasil_transport::Code::Reconnect) => {
                        ended.store(true, Ordering::Release);
                        let _ = tx.send(Incoming::Reconnect);
                        return;
                    }
                    // Any other code the peer closed with ends the
                    // connection.
                    Err(frasil_iroh::Error::ClosedByPeer(number)) => {
                        ended.store(true, Ordering::Release);
                        let name = frasil_transport::Code::from_number(number)
                            .map_or_else(|| number.to_string(), |code| code.name().to_owned());
                        let _ = tx.send(Incoming::Refused(format!("closed by the peer: {name}")));
                        return;
                    }
                    Err(error) => break error.to_string(),
                }
            };
            ended.store(true, Ordering::Release);
            let _ = tx.send(Incoming::Closed(why));
        });
    }

    /// Reads an object stream: its messages, until it ends, which ends
    /// nothing else.
    fn read_objects(mut receiver: FrameReceiver, tx: mpsc::UnboundedSender<Incoming>) {
        tokio::spawn(async move {
            while let Ok(Some(message)) = receiver.receive().await {
                if let Some(incoming) = sort(message) {
                    let _ = tx.send(incoming);
                }
            }
        });
    }

    impl Wire {
        pub(super) async fn control(&mut self, message: &[u8]) -> Result<()> {
            self.control.send(message).await.map_err(failed)
        }

        /// One `Ephemeral`, lossy: a frame the path cannot carry is
        /// dropped.
        pub(super) async fn ephemeral(&mut self, message: &[u8]) -> Result<()> {
            let _ = self.connection.send_lossy(message).await;
            Ok(())
        }

        pub(super) async fn sync(
            &mut self,
            space: EventId,
            message: &[u8],
            incoming: &mpsc::UnboundedSender<Incoming>,
        ) -> Result<()> {
            self.ensure_sync(space, incoming).await?;
            let sender = self.syncs.get_mut(&space).ok_or(Error::UnknownSpace)?;
            sender.send(message).await.map_err(failed)
        }

        /// One object transfer, on an object stream of its own.
        /// Sends an object's chunks on an object stream of its own, each
        /// encoded as it is read: `false` when the device no longer holds
        /// a chunk part way, and the stream ends there.
        pub(super) async fn object(
            &mut self,
            space: EventId,
            mut upload: crate::object_upload::ObjectUpload,
            encode: impl Fn(crate::snapshots::ObjectPart) -> Vec<u8>,
        ) -> Result<bool> {
            let mut sender = self
                .connection
                .open_object(Scope::Space(space.0))
                .await
                .map_err(failed)?;
            loop {
                match upload.next_part().await {
                    Ok(Some(part)) => sender.send(&encode(part)).await.map_err(failed)?,
                    Ok(None) => break,
                    Err(_) => {
                        let _ = sender.finish();
                        return Ok(false);
                    }
                }
            }
            sender.finish().map_err(failed)?;
            Ok(true)
        }

        pub(super) async fn ensure_sync(
            &mut self,
            space: EventId,
            incoming: &mpsc::UnboundedSender<Incoming>,
        ) -> Result<()> {
            if !self.syncs.contains_key(&space) {
                // One sync stream per space, opened by the device.
                let (sender, receiver) = self
                    .connection
                    .open_sync(Scope::Space(space.0))
                    .await
                    .map_err(failed)?;
                read_into(receiver, incoming.clone(), self.ended.clone());
                self.syncs.insert(space, sender);
            }
            Ok(())
        }

        pub(super) fn close(&mut self) {
            self.connection.close(frasil_transport::Code::Done);
        }
    }

    pub(super) async fn open(
        peer: [u8; 32],
        addresses: &[std::net::SocketAddr],
        relays: &[String],
        config: impl FnOnce(Config) -> Config,
    ) -> Result<(
        Wire,
        Channel,
        mpsc::UnboundedSender<Incoming>,
        mpsc::UnboundedReceiver<Incoming>,
        Arc<AtomicBool>,
    )> {
        // A fresh endpoint key per connection.
        let key = frasil_iroh::fresh_secret_key().map_err(failed)?;
        let endpoint = Endpoint::bind(config(Config::new(key, &[Alpn::Peer])))
            .await
            .map_err(failed)?;
        let connection = endpoint
            .connect(&peer, addresses, relays, Alpn::Peer)
            .await
            .map_err(failed)?;
        // The peer opens the control stream and writes PeerHello on it.
        let (control, receiver) = connection.accept_control().await.map_err(failed)?;
        let channel = connection.channel();
        let (tx, rx) = mpsc::unbounded_channel();
        let ended = Arc::new(AtomicBool::new(false));
        read_into(receiver, tx.clone(), ended.clone());
        let connection = Arc::new(connection);
        // Streams the peer opens: object transfers that answer `ObjectWant`.
        // Frames the peer relays as datagrams (ext-ephemeral.md).
        let datagrams = connection.clone();
        let frames = tx.clone();
        tokio::spawn(async move {
            while let Ok(message) = datagrams.receive_datagram().await {
                if frames.send(Incoming::Control(message)).is_err() {
                    return;
                }
            }
        });
        let accepting = connection.clone();
        let streams = tx.clone();
        let ending = ended.clone();
        tokio::spawn(async move {
            while let Ok(stream) = accepting.accept_stream().await {
                match stream {
                    frasil_iroh::Stream::Object { receiver, .. } => {
                        read_objects(receiver, streams.clone());
                    }
                    // Frames the peer relays (ext-ephemeral.md).
                    frasil_iroh::Stream::Ephemeral { receiver } => {
                        read_into(receiver, streams.clone(), ending.clone());
                    }
                    frasil_iroh::Stream::Sync { .. } => {}
                }
            }
        });
        Ok((
            Wire {
                _endpoint: endpoint,
                connection,
                control,
                syncs: BTreeMap::new(),
                ended: ended.clone(),
            },
            channel,
            tx,
            rx,
            ended,
        ))
    }
}

#[cfg(feature = "server-socket")]
pub mod socket {
    //! The server binding over a WebSocket and HTTP that the application
    //! supplies (transport.md, section 3.15), where this crate opens no
    //! socket of its own and tokio has no runtime: in a browser, through
    //! `frasil-wasm`.
    //!
    //! The application opens a WebSocket to [`connect_url`](super::connect_url)
    //! with subprotocol `frasil.p1`, closes it unless the peer echoes the
    //! subprotocol, and hands it to [`connect_socket`] as a
    //! [`ServerSocket`]. The connection then runs as over the native
    //! WebSocket, its tasks and timers on the socket's own.

    use super::{
        AtomicBool, Incoming, Opened, Ordering, PeerHandle, Redial, Runtime, Stopped, Wire,
        administer, coded_close, origin_acknowledger, read, sort, start,
    };
    use crate::device::Engine;
    use crate::error::{Error, Result};
    pub use crate::fetch::Cancel;
    use crate::object_upload::{ObjectUpload, UploadSlices, held_of};
    use frasil_adapter::Locator;
    use frasil_events::EventId;
    use frasil_store::BoxFuture;
    use frasil_store::store::{MaybeSend, MaybeSync};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// One connection's WebSocket and HTTP, as the application supplies
    /// them, with the tasks and timers the connection runs on.
    pub trait ServerSocket: MaybeSend + MaybeSync {
        /// Sends one binary message on the WebSocket.
        fn send<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<(), String>>;

        /// The next binary message the WebSocket received, or why it
        /// ended: closed by either end, failed, or a text message, which
        /// ends it with 1003. Once it has ended, every later call says so.
        fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, String>>;

        /// Closes the WebSocket.
        fn close(&self);

        /// One HTTP request to `url`, with `Authorization: authorization`
        /// and, for a body, `Content-Type: application/octet-stream`: the
        /// status and the body. It follows no redirect, returning a 3xx as
        /// it is; it never retries; it fails only when no response arrived.
        ///
        /// `abort` is signalled when the answer is no longer wanted, as
        /// when a fetch is cancelled: the request then ends its transfer,
        /// as `fetch` does for an `AbortSignal`, and may fail. The future
        /// may also be dropped before it is ready, which means the same.
        fn request<'a>(
            &'a self,
            method: &'a str,
            url: &'a str,
            authorization: &'a str,
            body: Option<&'a [u8]>,
            abort: &'a Cancel,
        ) -> BoxFuture<'a, Result<(u16, Vec<u8>), String>>;

        /// Runs a task in the background, to its end.
        fn spawn(&self, task: BoxFuture<'static, ()>);

        /// A future that is ready once `duration` has passed.
        fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;

        /// The close code of the peer's close, once the WebSocket has
        /// ended with one. A connection the peer closed with 4017,
        /// `reconnect`, opens again (transport.md, "Reconnecting
        /// elsewhere"); without the code, it ends.
        fn close_code(&self) -> Option<u16> {
            None
        }

        /// Opens a new socket to the same connect route, as the first was
        /// opened, for a connection the peer closed with `reconnect`;
        /// `None` where the application opens no other.
        #[allow(clippy::type_complexity)]
        fn reopen(&self) -> Option<BoxFuture<'static, Result<Arc<dyn ServerSocket>, String>>> {
            None
        }
    }

    /// Connects to a peer over a socket the application opened to the
    /// connect route of `origin`, such as `https://peer.example.org`, and
    /// presents `spaces`. The connection runs until it closes. When the
    /// peer closes it with `reconnect`, it goes on over the socket that
    /// [`ServerSocket::reopen`] opens, where the application opens one.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`](crate::Error::Connection) when the handshake
    /// fails.
    pub async fn connect_socket(
        device: &Engine,
        origin: &str,
        socket: Arc<dyn ServerSocket>,
        spaces: Vec<EventId>,
    ) -> Result<PeerHandle> {
        let origin = origin.trim_end_matches('/').to_owned();
        let runtime = Runtime::Supplied(socket.clone());
        let by = origin_acknowledger(&origin);
        let first = opened(socket.clone(), &origin);
        let redial: Redial = Arc::new(move || {
            let reopen = socket.reopen();
            let origin = origin.clone();
            Box::pin(async move {
                let Some(reopen) = reopen else {
                    return Err(Error::Unsupported("the socket does not open again"));
                };
                let socket = reopen.await.map_err(Error::Connection)?;
                Ok(opened(socket, &origin))
            })
        });
        start(device.clone(), first, runtime, by, Some(redial), spaces).await
    }

    /// A connection's transport over `socket`, read on its own tasks.
    fn opened(socket: Arc<dyn ServerSocket>, origin: &str) -> Opened {
        let (tx, rx, _, ended) = reading(&socket);
        Opened {
            wire: Wire::Socket(socket, origin.to_owned()),
            channel: frasil_transport::peer::server_channel(origin),
            tx,
            rx,
            ended,
        }
    }

    /// A [`Bare`](super::Bare) connection over a socket the application
    /// opened to the connect route of `origin` for it alone: a new
    /// WebSocket, as for an administration connection.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`](crate::Error::Connection) when the handshake
    /// fails.
    pub async fn bare_socket(
        device: &Engine,
        origin: &str,
        socket: Arc<dyn ServerSocket>,
    ) -> Result<super::Bare> {
        let origin = origin.trim_end_matches('/').to_owned();
        let runtime = Runtime::Supplied(socket.clone());
        super::Bare::open(device, opened(socket, &origin), runtime).await
    }

    /// Stores this device's own skeleton events of `space` at a peer over
    /// a socket the application opened to the connect route of `origin`
    /// for this alone: an administration connection (peers.md,
    /// "Administration connections"), as
    /// [`administer_server`](super::administer_server) opens natively. The
    /// socket is closed once the peer has acknowledged them. Returns
    /// whether anything was stored.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`](crate::Error::Connection) when the handshake
    /// or the present fails; [`Error::Timeout`](crate::Error::Timeout).
    pub async fn administer_socket(
        device: &Engine,
        origin: &str,
        socket: Arc<dyn ServerSocket>,
        space: EventId,
    ) -> Result<bool> {
        let (tx, rx, runtime, _) = reading(&socket);
        let origin = origin.trim_end_matches('/').to_owned();
        let channel = frasil_transport::peer::server_channel(&origin);
        let by = origin_acknowledger(&origin);
        let mut wire = Wire::Socket(socket, origin);
        let done = administer(device, &mut wire, &runtime, &channel, by, tx, rx, space).await;
        wire.close();
        done
    }

    /// The socket's messages, read on its own tasks into the connection's
    /// channel, and the flag its reader sets when it ends.
    fn reading(
        socket: &Arc<dyn ServerSocket>,
    ) -> (
        mpsc::UnboundedSender<Incoming>,
        mpsc::UnboundedReceiver<Incoming>,
        Runtime,
        Arc<AtomicBool>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let runtime = Runtime::Supplied(socket.clone());
        let reader = tx.clone();
        let receiving = socket.clone();
        let ended = Arc::new(AtomicBool::new(false));
        let ending = ended.clone();
        runtime.spawn(async move {
            let why = loop {
                match receiving.receive().await {
                    Ok(bytes) => match read(&bytes) {
                        Ok(Some(message)) => {
                            if let Some(incoming) = sort(message) {
                                let _ = reader.send(incoming);
                            }
                        }
                        Ok(None) => {}
                        Err(class) => break format!("a message that does not read: {class}"),
                    },
                    // transport.md, "Reconnecting elsewhere": 4017 is no
                    // error, and any other code of section 2.5 ends the
                    // connection.
                    Err(why) => {
                        if let Some(incoming) = receiving.close_code().and_then(coded_close) {
                            ending.store(true, Ordering::Release);
                            let _ = reader.send(incoming);
                            return;
                        }
                        break why;
                    }
                }
            };
            ending.store(true, Ordering::Release);
            let _ = reader.send(Incoming::Closed(why));
        });
        (tx, rx, runtime, ended)
    }

    /// The size of one slice of a stored object on the chunk routes.
    const SLICE: usize = frasil_transport::frame::OBJECT_CHUNK_BYTES;

    fn url(origin: &str, space: &EventId, locator: &Locator, index: usize) -> String {
        format!(
            "{origin}{}",
            frasil_transport::peer::chunk_path(&space.0, locator, index as u64)
        )
    }

    /// Uploads an object's stored bytes, slice by slice as its chunks are
    /// read; each is stored durably when the peer answers 201, or held
    /// already at 200.
    pub(super) async fn put_object(
        socket: &dyn ServerSocket,
        origin: &str,
        token: &[u8; 32],
        space: &EventId,
        locator: &Locator,
        upload: ObjectUpload,
        closing: &AtomicBool,
    ) -> std::result::Result<(), Stopped> {
        let authorization = frasil_transport::peer::transfer_authorization(token);
        let mut slices = UploadSlices::new(upload, SLICE).map_err(|_| Stopped::Gone)?;
        // An upload stops between slices, never part way through one.
        let never = Cancel::new();
        while let Some((index, slice)) = slices.next().await.map_err(|_| Stopped::Gone)? {
            if closing.load(Ordering::Acquire) {
                return Err(Stopped::Closing);
            }
            let index =
                usize::try_from(index).map_err(|error| Stopped::Refused(error.to_string()))?;
            let (status, body) = socket
                .request(
                    "PUT",
                    &url(origin, space, locator, index),
                    &authorization,
                    Some(&slice),
                    &never,
                )
                .await
                .map_err(Stopped::Refused)?;
            if status != 200 && status != 201 {
                return Err(Stopped::Refused(format!("object upload: {status}")));
            }
            // As over HTTP: the upload goes on from what the peer holds.
            if let Some(held) = held_of(&body) {
                slices.resume(held);
            }
        }
        Ok(())
    }

    /// Fetches one slice of an object's stored bytes. `None` when the peer
    /// lacks it. `abort` is signalled when the slice is no longer wanted.
    pub(super) async fn get_slice(
        socket: &dyn ServerSocket,
        origin: &str,
        token: &[u8; 32],
        space: &EventId,
        locator: &Locator,
        index: u64,
        abort: &Cancel,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        let authorization = frasil_transport::peer::transfer_authorization(token);
        let index = usize::try_from(index).map_err(|error| error.to_string())?;
        let (status, body) = socket
            .request(
                "GET",
                &url(origin, space, locator, index),
                &authorization,
                None,
                abort,
            )
            .await?;
        match status {
            200 => {}
            404 => return Ok(None),
            status => return Err(format!("object fetch: {status}")),
        }
        if body.len() > SLICE {
            return Err("an oversized slice".into());
        }
        Ok(Some(body))
    }
}

#[cfg(all(test, any(feature = "server", feature = "server-socket")))]
mod tests {
    use super::read;

    /// An event the peer refuses as a `conflict` each time it is offered
    /// is one fork; a second event is another.
    #[test]
    fn a_fork_refused_twice_is_reported_once() {
        use super::{EventId, PeerStatus};
        let space = EventId([1; 32]);
        let mut status = PeerStatus::default();
        status.note_fork(space, EventId([2; 32]));
        status.note_fork(space, EventId([2; 32]));
        status.note_fork(space, EventId([3; 32]));
        assert_eq!(
            status.forks,
            vec![(space, EventId([2; 32])), (space, EventId([3; 32]))]
        );
    }
    use frasil_transport::frame::MessageType;
    use frasil_transport::messages::{Gone, Scope};

    /// A relaying peer's `Gone` travels as control (transport.md, "Stream
    /// classes"): the device reads it, and the connection goes on.
    #[test]
    fn a_gone_from_the_peer_reads() {
        let gone = Gone {
            scope: Scope::Space([7; 32]),
            origin: [1; 8],
        }
        .encode();
        let message = read(&gone).expect("it reads").expect("a known type");
        assert_eq!(message.kind, MessageType::Gone);
    }

    /// transport.md, "The server binding": HTTPS, or HTTP to a loopback
    /// host; the host is the one the origin parses to.
    #[test]
    fn the_connect_route_takes_origins_alone() {
        use super::connect_url;
        let path = frasil_transport::peer::CONNECT_PATH;
        for (origin, expected) in [
            ("https://peer.example", format!("wss://peer.example{path}")),
            ("https://peer.example/", format!("wss://peer.example{path}")),
            (
                "https://peer.example:8443",
                format!("wss://peer.example:8443{path}"),
            ),
            (
                "http://localhost:8080",
                format!("ws://localhost:8080{path}"),
            ),
            ("http://127.0.0.1:1", format!("ws://127.0.0.1:1{path}")),
            ("http://[::1]:9", format!("ws://[::1]:9{path}")),
            ("http://[::1]", format!("ws://[::1]{path}")),
        ] {
            assert_eq!(connect_url(origin).ok(), Some(expected), "{origin}");
        }
        for origin in [
            // User information before the host the loopback test reads.
            "http://localhost:1@evil.example",
            "http://localhost@evil.example",
            "http://127.0.0.1:80@evil.example:80",
            "http://[::1]:1@evil.example",
            "https://user:pass@peer.example",
            "https://peer.example@evil.example",
            // Paths, queries and fragments.
            "http://localhost:1/evil",
            "https://peer.example/path",
            "https://peer.example?x=1",
            "https://peer.example#frag",
            "http://localhost:1#@evil.example",
            "http://localhost:1?@evil.example",
            "http://localhost:1\\@evil.example",
            // Not loopback, or no host, or a bad port.
            "http://evil.example",
            "http://localhost.evil.example:1",
            "http://127.0.0.1.evil.example",
            "http://",
            "https://",
            "https://:443",
            "http://localhost:",
            "http://localhost:65536",
            "http://localhost:1:2",
            "http://[::1",
            "http://[evil.example]:1",
            "http://[::1]x",
            "ftp://localhost",
            "localhost:1",
        ] {
            assert!(connect_url(origin).is_err(), "{origin}");
        }
    }

    /// transport.md, "Reconnecting elsewhere": the first bound is
    /// `reconnect_wait`, doubled after each attempt that fails, to at most
    /// `reconnect_wait_cap`; the wait is uniform from 0 to the bound.
    #[test]
    fn the_reconnect_waits_follow_the_backoff() {
        use super::{reconnect_bound_after, reconnect_wait, reconnect_wait_with};
        use std::time::Duration;
        let mut bound = reconnect_wait();
        assert_eq!(bound, Duration::from_secs(5));
        let mut bounds = Vec::new();
        for _ in 0..6 {
            bound = reconnect_bound_after(bound);
            bounds.push(bound.as_secs());
        }
        assert_eq!(bounds, [10, 20, 40, 60, 60, 60]);
        let five = Duration::from_secs(5);
        assert_eq!(reconnect_wait_with(five, [0; 8]), Duration::ZERO);
        assert_eq!(
            reconnect_wait_with(five, 5000_u64.to_be_bytes()),
            Duration::from_secs(5)
        );
        assert_eq!(
            reconnect_wait_with(five, 5001_u64.to_be_bytes()),
            Duration::ZERO
        );
        assert!(reconnect_wait_with(five, [0xff; 8]) <= five);
    }
}

#[cfg(feature = "ext-libraries")]
impl Driver {
    /// Queues a hold, then sends what may go.
    async fn hold(&mut self, ask: holds::HoldAsk) -> Result<()> {
        use frasil_transport::codes::Service;
        if !self.side.peer_hello.services().contains(&Service::Library) {
            // A peer that keeps no libraries holds nothing: there is
            // nothing to wait for here.
            holds::answer(self.device.device_id(), &ask, Ok(()));
            return Ok(());
        }
        if self.moved.contains(&ask.space) {
            holds::answer(self.device.device_id(), &ask, Err(moved_code().to_owned()));
            return Ok(());
        }
        let in_flight = self
            .requests
            .values()
            .any(|request| matches!(request, Request::Hold(other) if *other == ask));
        if !in_flight && !self.holds.contains(&ask) {
            self.holds.push(ask);
        }
        self.send_holds().await
    }

    /// Sends each queued `HoldObject` (ext-libraries.md, 2.8 HoldObject)
    /// whose time has come: the connection holds the store right for its
    /// space and, when it presents the source too, the fetch right for it;
    /// and the source's object is not still on its way up from this device.
    async fn send_holds(&mut self) -> Result<()> {
        let mut ready = Vec::new();
        let mut waiting = Vec::new();
        for ask in std::mem::take(&mut self.holds) {
            let stores = self
                .spaces
                .get(&ask.space)
                .is_some_and(|attached| attached.rights.contains(&Right::Store));
            let source = self.spaces.get(&ask.source);
            let reads_source = source.is_none_or(|attached| {
                attached.rights.contains(&Right::Fetch)
                    && !attached.uploading.contains(&ask.locator)
                    && !attached
                        .deferred
                        .iter()
                        .any(|(_, waiting)| waiting.contains(&ask.locator))
            });
            if stores && reads_source {
                ready.push(ask);
            } else {
                waiting.push(ask);
            }
        }
        self.holds = waiting;
        for ask in ready {
            let request = self.request(Request::Hold(ask.clone()));
            let message = frasil_libraries::HoldObject::prove(
                request,
                &self.side.binding,
                ask.space.0,
                ask.source.0,
                ask.locator,
                &ask.object_key,
            )
            .encode();
            self.wire.control(&message).await?;
        }
        Ok(())
    }

    /// The peer holds the object for the space: the units that name it go.
    async fn hold_accepted(&mut self, ask: holds::HoldAsk) -> Result<()> {
        holds::answer(self.device.device_id(), &ask, Ok(()));
        self.status().held.insert((ask.space, ask.locator));
        self.uploaded(ask.space, ask.locator).await
    }

    /// A refused hold. One of an object the source has not yet stored at
    /// the peer, while this device uploads it, waits for that upload;
    /// another is the application's.
    async fn hold_refused(&mut self, ask: holds::HoldAsk, code: String) -> Result<()> {
        let uploading = code == "unknown_object"
            && self
                .device
                .stored_object(&ask.source, &ask.locator)
                .await
                .is_some()
            && self
                .spaces
                .get(&ask.source)
                .is_some_and(|attached| !attached.uploaded.contains(&ask.locator));
        if uploading {
            self.holds.push(ask);
            return Ok(());
        }
        holds::answer(self.device.device_id(), &ask, Err(code.clone()));
        self.status().refused.push((ask.space, code));
        Ok(())
    }
}

/// Holds a device asks of its peers (ext-libraries.md, "Holds"), and who
/// waits for their answers.
#[cfg(feature = "ext-libraries")]
pub(crate) mod holds {
    use frasil_adapter::Locator;
    use frasil_crypto::device::DeviceId;
    use frasil_events::EventId;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, PoisonError};
    use tokio::sync::oneshot;

    /// A peer's answer to a `HoldObject`: accepted, or the code of its
    /// refusal.
    pub(crate) type Answer = std::result::Result<(), String>;

    /// A hold to register: the holding space, the source that stores the
    /// object, its locator and its key.
    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct HoldAsk {
        pub space: EventId,
        pub source: EventId,
        pub locator: Locator,
        pub object_key: [u8; 32],
    }

    impl core::fmt::Debug for HoldAsk {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("HoldAsk")
                .field("space", &self.space)
                .field("source", &self.source)
                .finish_non_exhaustive()
        }
    }

    type Key = (DeviceId, EventId, Locator);
    type Waiters = BTreeMap<Key, Vec<oneshot::Sender<Answer>>>;

    /// Who waits for each device's holds, by its device ID.
    static WAITERS: Mutex<Waiters> = Mutex::new(BTreeMap::new());

    /// The receiver hears the first peer's answer to a hold.
    pub(crate) fn wait(
        device: DeviceId,
        space: EventId,
        locator: Locator,
    ) -> oneshot::Receiver<Answer> {
        let (reply, answer) = oneshot::channel();
        WAITERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((device, space, locator))
            .or_default()
            .push(reply);
        answer
    }

    /// Hands a peer's answer to whoever waits on the hold.
    pub(crate) fn answer(device: DeviceId, ask: &HoldAsk, answer: Answer) {
        let waiters = WAITERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(device, ask.space, ask.locator))
            .unwrap_or_default();
        for waiter in waiters {
            let _ = waiter.send(answer.clone());
        }
    }
}
