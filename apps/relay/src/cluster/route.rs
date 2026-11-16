//! Every node is a gateway: a device connects to any node, and its
//! gateway forwards each space's traffic to the owner of the space's
//! shard, whose answers come back the same way.
//!
//! - **At the gateway** a connection keeps a route per space it holds a
//!   grant in at the space's owner, and nothing for any other space
//!   ("Before a grant", below). A route keeps the shard it routes to, the
//!   owner it reached, and the presents granted and the subscription, so
//!   that when the epoch moves the space to another owner the gateway
//!   presents the same proofs there again, with the same transfer tokens,
//!   and subscribes again. A proof holds for its connection's `binding`,
//!   which the owner checks it against, so it holds at any owner.
//!   Subscriptions are live only, so the gateway also notes, per space,
//!   the events the connection is known to hold (those it sent, those
//!   delivered to it, and the heads it announced), and after presenting
//!   and subscribing at a new owner it sends there `Heads` naming them:
//!   what the new owner stored before the connection reached it comes
//!   back as `Events`, and reaches the device once, beside the live
//!   deliveries.
//! - **At the owner** each forwarded connection, named by its gateway, the
//!   gateway's run and the connection's number, has a
//!   [`SpaceSession`](crate::session::SpaceSession): its grants, its
//!   catch-up, its subscriptions and its imports, kept as a connection of
//!   the owner's own is. What the owner sends it on its own, deliveries,
//!   `Awaiting` and relayed ephemeral frames, goes to its gateway in order,
//!   which hands it to the device; so does an ask to reconnect once an
//!   entry's retirement or the space's erasure ended its live delivery
//!   there, which the gateway carries out on the device's connection. The owner forgets it when the gateway
//!   reports the connection closed, or once a newer run of the gateway
//!   speaks.
//! - An owner that does not own the space's shard at its epoch, or not
//!   yet, answers "not mine" with its epoch, and the gateway tries again
//!   once its own view has moved on, for as long as a takeover takes.
//! - A gateway forwards one message of a device connection at a time, as
//!   the connection hands them over: what one device connection has in
//!   flight between the nodes is that message and one part of its answer
//!   ("Answers in parts", below), at most `MAX_ANSWER` (module `link`).
//!   What an owner sends a forwarded connection on its own waits at the
//!   owner within the operator's `queued_bytes`, as on a connection of its
//!   own, while its link to the gateway takes it.
//! - A mailbox's deposits and collections go to the node that keeps its
//!   shard, and an object piece over HTTP to the owner of its space, which
//!   keeps the transfer tokens its grants carry.
//!
//! # Before a grant
//!
//! Until the owner granted a `Present` of a connection in a space, the
//! gateway keeps nothing for the connection in that space, and forwards
//! only what may lead to a grant: a `Present`, a create's or an import's
//! `LibraryAttach` and genesis, and a deposit-token draw, whose own checks
//! come before its right's. It answers the rest itself, with what the
//! owner answers a connection that holds no grant there, decided in one
//! place for both (`session::without_grant`): a request with
//! `credential_refused`, or `not_authorized` for a hold; each event with
//! `EventRefused` and `not_authorized`, or `purpose_violation` on an
//! administration connection; and anything else with nothing. A device presents
//! before it syncs (`frasil`'s peer connections), and the gateway takes a
//! connection's messages one at a time, so a message sent right after a
//! present is taken once the present is answered, under its grant: nothing
//! an honest device sends is dropped.
//!
//! An owner that refuses a connection's present, and holds no other grant
//! for it, forgets the connection at once. A gateway keeps routes for one
//! connection in at most `ClusterConfig::spaces_per_connection` spaces,
//! and refuses a present past that `busy`. It remembers for a few seconds
//! ([`UNKNOWN_FOR`]) a space its index named no shard for, so that the
//! index's shard is read once for it in that time, and a space whose owner
//! refused a present `no_library` and handed nothing over, so that a
//! present for it is refused here meanwhile, without reaching the owner. A
//! create through this gateway forgets both at once.
//!
//! # Answers in parts
//!
//! An owner answers a forwarded message as it answers one of its own
//! connections: what it answers at once, then the answers it serves in
//! batches (units.md, "Sync"). It sends the gateway the first part of that,
//! messages in order up to [`PART_BYTES`], and keeps the rest for the
//! connection; an object transfer larger than a part is divided into
//! transfers that each fit, each chunk being a message of its own. The
//! gateway sends the device what came and, once it is sent, asks for the
//! next part ([`wire::ForwardNext`]), before it takes the device's next
//! message, as a connection of the owner's own is served before its next
//! message is read: so the device receives the same messages in the same
//! order (transport.md, 3.7 Order on a connection; 3.9), and one part of a
//! connection's answer at a time crosses the link. An owner forgets what
//! is left when the connection's next message comes, or it leaves the
//! space there; a gateway whose route moved asks no more, and the device
//! asks again at its next head exchange.

use super::Cluster;
use super::link::NodeId;
use super::wire::{
    self, Closed, Deliver, Forward, ForwardAnswer, LinkName, MailboxAnswer, MailboxRequest, Out,
    Piece, PieceAnswer,
};
use crate::Shared;
use crate::session::{Failure, SpaceSession, WithoutGrant, without_grant};
use crate::state::{Items, Outgoing, Reason};
use crate::util::log;
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_peers::proof::Purpose;
use frasil_transport::Closed as Close;
use frasil_transport::codes::Code;
use frasil_transport::frame::{Message, MessageType};
use frasil_transport::mailbox::Kind;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a gateway waits for an owner to answer one message.
const FORWARD_WAIT: Duration = Duration::from_secs(30);
/// The presents a gateway keeps per space to present again elsewhere.
const REPLAYS: usize = 32;
/// How long a gateway remembers that its index named no shard for a
/// space, or that an owner found a space unknown (module documentation,
/// "Before a grant"). The crate's own tests use less.
const UNKNOWN_FOR: Duration = if cfg!(test) {
    Duration::from_millis(500)
} else {
    Duration::from_secs(5)
};
/// How many such spaces a gateway remembers at once: past that, the
/// lapsed are forgotten, and a new one is not remembered while none lapsed.
const UNKNOWN_KEPT: usize = 4096;
/// The most bytes of messages one answer of an owner to a gateway carries,
/// past its first message (module documentation, "Answers in parts"): a
/// few of a sync answer's batches, or eight chunks of an object, each at
/// most units.md's message limit. Module `link`'s `MAX_ANSWER` holds it.
/// The crate's own tests take each message as a part of its own, so that
/// every answer of more than one crosses in parts.
pub(crate) const PART_BYTES: usize = if cfg!(test) { 1 } else { 8 << 20 };
// A part, with a message of units.md's limit and the framing of its
// messages, fits the largest answer a link carries.
const _: () = assert!(PART_BYTES + (2 << 20) <= super::link::MAX_ANSWER);

/// What a gateway answers a device's message of a space.
#[derive(Debug, Default)]
pub(crate) struct Forwarded {
    /// What to send at once.
    pub out: Vec<Outgoing>,
    /// Whether more of the answer is left at the owner
    /// ([`Cluster::forward_next`]).
    pub more: bool,
    /// Whether the connection holds a grant in the space now, as its owner
    /// answered; `None` when no owner answered.
    pub holds: Option<bool>,
}

impl Forwarded {
    /// An answer made at the gateway, which changes no grant.
    fn here(out: Vec<Outgoing>) -> Self {
        Self {
            out,
            more: false,
            holds: None,
        }
    }
}

/// Why an owner's answer to a forwarded message did not come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unanswered {
    /// The owner could not be reached, or did not answer in time: it may
    /// be asked again.
    Unreached,
    /// The message or its answer is larger than the links carry: asking
    /// again cannot change that.
    TooLarge,
}

/// A device's connection, as its gateway forwards it.
#[derive(Debug, Clone)]
pub(crate) struct Connection {
    pub link: u64,
    pub binding: [u8; 32],
    pub purpose: Purpose,
    pub server: bool,
    pub source: String,
}

/// Where one space of a connection goes.
#[derive(Debug, Clone)]
struct Route {
    shard: String,
    /// Whether the index named the shard, so that the route stands.
    hosted: bool,
    owner: Option<NodeId>,
    /// The presents to make again at another owner, with their tokens.
    replay: Vec<(Vec<u8>, Option<[u8; 32]>)>,
    /// The last `Subscribe`.
    subscribe: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Routes {
    connection: Option<Connection>,
    spaces: BTreeMap<[u8; 32], Route>,
}

/// The gateway's connections and their routes.
#[derive(Debug, Default)]
pub(crate) struct Gateway {
    /// Each connection's routes: a connection is here once an owner
    /// granted it something.
    links: Mutex<HashMap<u64, Arc<tokio::sync::Mutex<Routes>>>>,
    /// Each connection's spaces with an import or a pending create.
    holding: Mutex<BTreeSet<(u64, [u8; 32])>>,
    /// What each connection is known to hold of each space it has a route
    /// for: made with the route, gone with it.
    held: Mutex<HashMap<(u64, [u8; 32]), Held>>,
    /// Spaces the index named no shard for lately.
    unindexed: Lapsing,
    /// Spaces an owner found unknown lately.
    unknown: Lapsing,
}

/// Spaces remembered for [`UNKNOWN_FOR`], at most [`UNKNOWN_KEPT`] at once.
#[derive(Debug, Default)]
struct Lapsing(Mutex<HashMap<[u8; 32], Instant>>);

impl Lapsing {
    /// Whether `space` is remembered still.
    fn holds(&self, space: &[u8; 32]) -> bool {
        let mut kept = lock(&self.0);
        match kept.get(space) {
            Some(until) if Instant::now() < *until => true,
            Some(_) => {
                kept.remove(space);
                false
            }
            None => false,
        }
    }

    /// Remembers `space` for [`UNKNOWN_FOR`].
    fn note(&self, space: [u8; 32]) {
        let now = Instant::now();
        let mut kept = lock(&self.0);
        if kept.len() >= UNKNOWN_KEPT {
            kept.retain(|_, until| now < *until);
        }
        if kept.len() < UNKNOWN_KEPT {
            kept.insert(space, now + UNKNOWN_FOR);
        }
    }

    /// Forgets `space`.
    fn forget(&self, space: &[u8; 32]) {
        lock(&self.0).remove(space);
    }
}

/// The events delivered to a connection lately, which a delivery passes
/// over once more.
const RECENT: usize = 1024;

/// What a gateway knows a connection holds of a space: heads whose pasts
/// it holds, and the events delivered to it lately.
#[derive(Debug, Default)]
struct Held {
    heads: BTreeSet<EventId>,
    /// Until when the events delivered are counted, while the connection
    /// moves to a new owner in the space.
    moving: Option<Instant>,
    recent: VecDeque<EventId>,
    seen: HashSet<EventId>,
}

impl Held {
    /// Whether the connection is moving to a new owner in the space; once
    /// it is not, the events counted are forgotten.
    fn moving(&mut self) -> bool {
        if self.moving.is_some_and(|until| Instant::now() < until) {
            return true;
        }
        self.moving = None;
        self.recent.clear();
        self.seen.clear();
        false
    }

    /// The connection holds `id`, and so its parents: whether `id` is not
    /// among the events delivered while it moves, which `delivered` then
    /// counts it among.
    fn note(&mut self, id: EventId, parents: &[EventId], delivered: bool) -> bool {
        for parent in parents {
            self.heads.remove(parent);
        }
        self.add_head(id);
        if !delivered || !self.moving() {
            return true;
        }
        if !self.seen.insert(id) {
            return false;
        }
        self.recent.push_back(id);
        if self.recent.len() > RECENT
            && let Some(old) = self.recent.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }

    /// A head the connection announced or received. Past the limit of one
    /// message, the first are forgotten: what their pasts held is then
    /// sent again, never left out.
    fn add_head(&mut self, id: EventId) {
        self.heads.insert(id);
        while self.heads.len() > frasil_units::limits::MAX_MESSAGE_ITEMS {
            self.heads.pop_first();
        }
    }
}

/// The units.md message of a `Sync` message, as either side encodes it.
fn unit_of(bytes: &[u8]) -> Option<frasil_units::messages::Message> {
    use frasil_transport::frame::ConnectionKind;
    use frasil_transport::messages::Sync;
    use frasil_units::messages::{Received, SyncMessage};
    let message = crate::server::read(bytes, crate::Extensions::NONE)
        .ok()
        .flatten()?;
    if message.kind != MessageType::Sync {
        return None;
    }
    let wrapper = Sync::read(&message, ConnectionKind::DeviceToPeer).ok()?;
    match SyncMessage::read(&wrapper.message).ok()? {
        Received::Message(unit) => Some(unit.message),
        _ => None,
    }
}

/// The ID and parents of each signed event that reads.
fn ids_of(events: &[Vec<u8>]) -> Vec<(EventId, Vec<EventId>)> {
    events
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| (event.id(), event.parents().to_vec()))
        .collect()
}

/// A connection forwarded here.
struct Owned {
    space: SpaceSession,
    seen: BTreeSet<[u8; 32]>,
    forward: tokio::task::JoinHandle<()>,
    /// Taken out of [`Owners::sessions`]: a forward that finds it so asks
    /// for the connection again.
    retired: bool,
    /// What is left of the answer to the connection's last forwarded
    /// message, for its gateway to ask for in parts.
    pending: Option<Pending>,
}

/// What is left of an answer to a forwarded message: messages made
/// already, then answers served in batches.
struct Pending {
    space: [u8; 32],
    ready: VecDeque<Outgoing>,
    answers: VecDeque<crate::sync::Answer>,
}

impl Owned {
    /// The next part of the answer pending in `space`: its messages, in
    /// order, as many as fit [`PART_BYTES`] and at least one; and whether
    /// more is left. An answer of another space, or none, has nothing left.
    async fn part(&mut self, space: [u8; 32]) -> (Vec<Out>, bool) {
        let Some(mut pending) = self.pending.take().filter(|p| p.space == space) else {
            return (Vec::new(), false);
        };
        let mut out = Vec::new();
        let mut bytes = 0usize;
        loop {
            let next = match pending.ready.pop_front() {
                Some(next) => next,
                None => match pending.answers.front_mut() {
                    Some(answer) => match self.space.next_batch(answer).await {
                        Some(next) => next,
                        None => {
                            pending.answers.pop_front();
                            continue;
                        }
                    },
                    None => break,
                },
            };
            let size = crate::state::queued_size(&next);
            if !out.is_empty() && bytes.saturating_add(size) > PART_BYTES {
                pending.ready.push_front(next);
                break;
            }
            bytes = bytes.saturating_add(size);
            out.extend(to_wire(next));
        }
        let more = !(pending.ready.is_empty() && pending.answers.is_empty());
        if more {
            self.pending = Some(pending);
        }
        (out, more)
    }
}

/// An answer's messages, with each object transfer larger than
/// [`PART_BYTES`] divided into transfers that each fit: each chunk travels
/// in an `ObjectChunks` of its own (units.md, "Sync"), so the device takes
/// them as it takes one transfer.
fn in_parts(out: Vec<Outgoing>) -> VecDeque<Outgoing> {
    let mut parts = VecDeque::with_capacity(out.len());
    for message in out {
        let Outgoing::Object(space, messages) = message else {
            parts.push_back(message);
            continue;
        };
        let mut group: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        for chunk in messages {
            if !group.is_empty() && bytes.saturating_add(chunk.len()) > PART_BYTES {
                parts.push_back(Outgoing::Object(space, std::mem::take(&mut group)));
                bytes = 0;
            }
            bytes = bytes.saturating_add(chunk.len());
            group.push(chunk);
        }
        if !group.is_empty() {
            parts.push_back(Outgoing::Object(space, group));
        }
    }
    parts
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.forward.abort();
        self.space.shared.core.unlink(self.space.link);
    }
}

/// The connections gateways forward to this owner.
#[derive(Default)]
pub(crate) struct Owners {
    sessions: Mutex<HashMap<LinkName, Arc<tokio::sync::Mutex<Owned>>>>,
    /// How many forwarded messages this owner took up, for tests.
    served: AtomicU64,
    /// When each connection's gateway last named it, by a forward or in
    /// its digest of live connections.
    heard: Mutex<HashMap<LinkName, Instant>>,
}

impl core::fmt::Debug for Owners {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Owners")
            .field("sessions", &lock(&self.sessions).len())
            .finish()
    }
}

fn purpose_of(code: u8) -> Purpose {
    if code == Purpose::Administration.code() {
        Purpose::Administration
    } else {
        Purpose::SpaceTraffic
    }
}

fn to_wire(out: Outgoing) -> Option<Out> {
    Some(match out {
        Outgoing::Control(bytes) => Out::Control(bytes),
        Outgoing::Sync(space, bytes) => Out::Sync(*space.as_bytes(), bytes),
        Outgoing::Object(space, messages) => Out::Object(*space.as_bytes(), messages),
        Outgoing::Ephemeral(bytes) => Out::Ephemeral(bytes),
        // An owner never moves a forwarded connection's load; it asks only
        // when the connection's live delivery ended here, and the gateway
        // closes its own connection.
        Outgoing::Reconnect => Out::Reconnect,
    })
}

fn from_wire(out: Out) -> Option<Outgoing> {
    Some(match out {
        Out::Control(bytes) => Outgoing::Control(bytes),
        Out::Sync(space, bytes) => Outgoing::Sync(EventId(space), bytes),
        Out::Object(space, messages) => Outgoing::Object(EventId(space), messages),
        // Made only by a node with ext-ephemeral on.
        Out::Ephemeral(bytes) => Outgoing::Ephemeral(bytes),
        Out::Reconnect => Outgoing::Reconnect,
    })
}

fn close_of(number: u64) -> Close {
    let code = Code::from_number(number).unwrap_or(Code::Malformed);
    Close {
        code,
        class: code
            .class()
            .unwrap_or_else(|| frasil_base::ErrorClass::Malformed.into()),
    }
}

/// Whether a message is a `Sync` carrying `Subscribe`.
fn is_subscribe(message: &Message) -> bool {
    use frasil_transport::frame::ConnectionKind;
    use frasil_transport::messages::Sync;
    use frasil_units::messages::{Message as Unit, Received, SyncMessage};
    message.kind == MessageType::Sync
        && Sync::read(message, ConnectionKind::DeviceToPeer)
            .ok()
            .and_then(|wrapper| SyncMessage::read(&wrapper.message).ok())
            .is_some_and(|read| matches!(read, Received::Message(m) if matches!(m.message, Unit::Subscribe { .. })))
}

/// What a gateway answers a message no owner took: `busy` for a request,
/// each event refused `busy` so that the device sends it again, nothing
/// for the rest.
fn busy(message: &Message) -> Vec<Outgoing> {
    use frasil_transport::frame::ConnectionKind;
    use frasil_transport::messages::{EventRefused, Sync};
    use frasil_units::messages::{Message as Unit, Received, SyncMessage};
    if let Some(request) = message.get(1).and_then(|v| v.as_unsigned().ok())
        && message.kind != MessageType::Sync
        && message.kind != MessageType::Ephemeral
    {
        return vec![crate::state::refused(request, "busy")];
    }
    let Ok(wrapper) = Sync::read(message, ConnectionKind::DeviceToPeer) else {
        return Vec::new();
    };
    let frasil_transport::messages::Scope::Space(space) = wrapper.scope else {
        return Vec::new();
    };
    let Ok(Received::Message(unit)) = SyncMessage::read(&wrapper.message) else {
        return Vec::new();
    };
    let Unit::Events { events } = unit.message else {
        return Vec::new();
    };
    events
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| {
            Outgoing::Control(
                EventRefused {
                    space,
                    event: *event.id().as_bytes(),
                    code: "busy".into(),
                }
                .encode(),
            )
        })
        .collect()
}

/// The message of a control `Out`, read as the device reads it.
fn control_of(bytes: &[u8]) -> Option<Message> {
    crate::server::read(bytes, crate::Extensions::NONE)
        .ok()
        .flatten()
}

/// Whether an owner's answer grants a present: it holds a `Granted`.
fn grants_present(out: &[Out]) -> bool {
    out.iter().any(|out| {
        matches!(out, Out::Control(bytes)
            if control_of(bytes).is_some_and(|message| message.kind == MessageType::Granted))
    })
}

/// Whether a present's answer is a refusal `no_library`.
fn refused_no_library(out: &[Outgoing]) -> bool {
    out.iter().any(|out| {
        matches!(out, Outgoing::Control(bytes)
            if control_of(bytes)
                .filter(|message| message.kind == MessageType::Refused)
                .and_then(|message| frasil_transport::messages::Refused::read(&message).ok())
                .is_some_and(|refused| refused.code == frasil_peers::Code::NoLibrary.name()))
    })
}

impl Cluster {
    /// How long a gateway keeps trying an owner: long enough for a dead
    /// owner's lease to end and its shard to open elsewhere.
    fn takeover(&self) -> Duration {
        self.config.timing.ended_after() * 2 + Duration::from_secs(2)
    }

    /// The shard of a space: the one the index names, else the hint (a
    /// ticket's library), else the space's hashed shard. Whether the index
    /// named it.
    async fn resolve(&self, space: [u8; 32], hint: Option<String>) -> (String, bool) {
        let Some(shards) = self.shards().cloned() else {
            return (crate::shards::space_shard(&space), false);
        };
        let located = tokio::task::spawn_blocking(move || shards.locate(&space))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        match located {
            Some(shard) => (shard, true),
            None => (
                hint.unwrap_or_else(|| crate::shards::space_shard(&space)),
                false,
            ),
        }
    }

    /// [`Self::resolve`], reading the index whatever memory notes: for a
    /// space that may have moved into another shard.
    async fn resolve_fresh(&self, space: [u8; 32], hint: String) -> (String, bool) {
        self.gateway.unindexed.forget(&space);
        let Some(shards) = self.shards().cloned() else {
            return (hint, false);
        };
        let located = tokio::task::spawn_blocking(move || shards.locate_fresh(&space))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        match located {
            Some(shard) => (shard, true),
            None => (hint, false),
        }
    }

    /// [`Self::resolve`] at a gateway: a space the index named no shard
    /// for lately is not looked up again (module documentation, "Before a
    /// grant"). An owner never takes this: a gateway that routes a space
    /// to the wrong shard is answered "not mine", and reads the index again
    /// ([`Self::resolve_fresh`]).
    async fn resolve_at_gateway(&self, space: [u8; 32], hint: Option<String>) -> (String, bool) {
        let fallback =
            |hint: Option<String>| hint.unwrap_or_else(|| crate::shards::space_shard(&space));
        let Some(shards) = self.shards().cloned() else {
            return (crate::shards::space_shard(&space), false);
        };
        if self.gateway.unindexed.holds(&space) {
            return (fallback(hint), false);
        }
        let located = tokio::task::spawn_blocking(move || shards.locate(&space)).await;
        match located {
            Ok(Ok(Some(shard))) => (shard, true),
            Ok(Ok(None)) => {
                self.gateway.unindexed.note(space);
                (fallback(hint), false)
            }
            // A failed read is not remembered.
            _ => (fallback(hint), false),
        }
    }

    /// The spaces a connection holds routes for.
    async fn routed(&self, link: u64) -> usize {
        let routes = lock(&self.gateway.links).get(&link).cloned();
        match routes {
            Some(routes) => routes.lock().await.spaces.len(),
            None => 0,
        }
    }

    /// Forwards a device's message of a space to the space's owner, here
    /// or on another node: the answer to send, and whether more of it is
    /// left at the owner, for [`Self::forward_next`]; or the failure that
    /// closes the connection. A space the connection holds no grant in
    /// goes by [`Self::forward_ungranted`].
    pub(crate) async fn forward(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        hint: Option<String>,
        message: &Message,
        token: Option<[u8; 32]>,
    ) -> Result<Forwarded, Failure> {
        let routes = lock(&self.gateway.links).get(&connection.link).cloned();
        if let Some(routes) = routes {
            // Held for the whole forward, as a reroute holds it, so that
            // the route changes in one order. The device's own messages
            // come one at a time.
            let mut routes = routes.lock().await;
            if routes.spaces.contains_key(&space) {
                return self
                    .forward_routed(&mut routes, connection, space, hint, message, token)
                    .await;
            }
        }
        self.forward_ungranted(connection, space, hint, message, token)
            .await
    }

    /// The next part of the answer to a connection's last message of a
    /// space, from the owner that answered it (module documentation,
    /// "Answers in parts"): its messages, and whether more is left. Nothing
    /// is left once the connection's route there went, or the owner could
    /// not be reached: the device asks again at its next head exchange.
    pub(crate) async fn forward_next(
        self: &Arc<Self>,
        link: u64,
        space: [u8; 32],
    ) -> (Vec<Outgoing>, bool) {
        let routes = lock(&self.gateway.links).get(&link).cloned();
        let Some(routes) = routes else {
            return (Vec::new(), false);
        };
        // Held as a forward holds it, so that no reroute moves the route
        // meanwhile.
        let routes = routes.lock().await;
        let Some(owner) = routes.spaces.get(&space).and_then(|route| route.owner) else {
            return (Vec::new(), false);
        };
        match self.next_part(owner, link, space).await {
            Some((out, more)) => (
                out.into_iter()
                    .filter_map(|out| self.note_out(link, out, false))
                    .filter_map(from_wire)
                    .collect(),
                more,
            ),
            None => (Vec::new(), false),
        }
    }

    /// Asks `owner` for the next part of an answer it serves in parts.
    async fn next_part(
        self: &Arc<Self>,
        owner: NodeId,
        link: u64,
        space: [u8; 32],
    ) -> Option<(Vec<Out>, bool)> {
        let next = wire::ForwardNext {
            link: LinkName {
                node: self.me,
                run: self.run,
                link,
            },
            space,
        };
        let answer = if owner == self.me {
            self.serve_forward_next_local(next).await
        } else {
            let body = self
                .links
                .call(owner, wire::FORWARD_NEXT, next.encode(), FORWARD_WAIT)
                .await
                .ok()?;
            ForwardAnswer::decode(&body)?
        };
        match answer {
            ForwardAnswer::Answered { out, more, .. } => Some((out, more)),
            ForwardAnswer::NotMine(_) => None,
        }
    }

    /// A message of a space the connection holds no grant in (module
    /// documentation, "Before a grant"): answered here, or forwarded with
    /// nothing kept unless the owner grants something.
    async fn forward_ungranted(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        hint: Option<String>,
        message: &Message,
        token: Option<[u8; 32]>,
    ) -> Result<Forwarded, Failure> {
        let create = match without_grant(message, &space, connection.purpose)? {
            WithoutGrant::Answer(out) => return Ok(Forwarded::here(out)),
            WithoutGrant::Goes { create } => create,
        };
        let cap = self.config.spaces_per_connection;
        let present = (message.kind == MessageType::Present)
            .then(|| frasil_transport::messages::Present::read(message).ok())
            .flatten();
        if let Some(present) = &present {
            if self.gateway.unknown.holds(&space) {
                return Ok(Forwarded::here(vec![crate::state::refused(
                    present.request,
                    frasil_peers::Code::NoLibrary.name(),
                )]));
            }
            if self.routed(connection.link).await >= cap {
                return Ok(Forwarded::here(vec![crate::state::refused(
                    present.request,
                    "busy",
                )]));
            }
        }
        if create {
            self.gateway.unknown.forget(&space);
            self.gateway.unindexed.forget(&space);
        }
        let (mut shard, mut hosted) = self.resolve_at_gateway(space, hint).await;
        let Some((owner, answer)) = self
            .send_ungranted(
                connection,
                space,
                &mut shard,
                &mut hosted,
                &message.bytes,
                token,
            )
            .await
        else {
            return Ok(Forwarded::here(busy(message)));
        };
        let ForwardAnswer::Answered {
            out,
            close,
            holding,
            granted,
            unknown,
            more,
        } = answer
        else {
            return Ok(Forwarded::here(busy(message)));
        };
        if unknown && present.is_some() {
            self.gateway.unknown.note(space);
        }
        let mut kept = false;
        if granted {
            let routes = lock(&self.gateway.links)
                .entry(connection.link)
                .or_default()
                .clone();
            let mut routes = routes.lock().await;
            routes.connection.get_or_insert_with(|| connection.clone());
            if routes.spaces.len() < cap || routes.spaces.contains_key(&space) {
                let replay = present
                    .as_ref()
                    .filter(|_| grants_present(&out))
                    .map(|_| (message.bytes.clone(), token));
                let route = routes.spaces.entry(space).or_insert_with(|| Route {
                    shard: shard.clone(),
                    hosted,
                    owner: Some(owner),
                    replay: Vec::new(),
                    subscribe: None,
                });
                route.replay.extend(replay);
                lock(&self.gateway.held)
                    .entry((connection.link, space))
                    .or_default();
                kept = true;
            } else {
                // Granted past the cap, as by a create's `LibraryAttach`:
                // the owner forgets the space on this connection, and the
                // device is answered busy.
                self.leave_owner(connection.link, space, owner).await;
                return Ok(Forwarded {
                    out: match &present {
                        Some(present) => vec![crate::state::refused(present.request, "busy")],
                        None => busy(message),
                    },
                    more: false,
                    holds: Some(false),
                });
            }
        }
        {
            let mut held = lock(&self.gateway.holding);
            if holding && kept {
                held.insert((connection.link, space));
            } else {
                held.remove(&(connection.link, space));
            }
        }
        if let Some(code) = close {
            return Err(close_of(code));
        }
        // What is left at the owner is reached by the route alone.
        Ok(Forwarded {
            out: out
                .into_iter()
                .filter_map(|out| self.note_out(connection.link, out, false))
                .filter_map(from_wire)
                .collect(),
            more: more && kept,
            holds: Some(kept),
        })
    }

    /// Tells `owner` that a connection of this gateway left `space` there.
    async fn leave_owner(&self, link: u64, space: [u8; 32], owner: NodeId) {
        let name = LinkName {
            node: self.me,
            run: self.run,
            link,
        };
        if owner == self.me {
            self.owners.closed(name, Some(space));
        } else {
            let body = Closed {
                link: name,
                space: Some(space),
            }
            .encode();
            let _ = self.links.notify(owner, wire::CLOSED, body).await;
        }
    }

    /// A message of a space the connection holds a route for.
    async fn forward_routed(
        self: &Arc<Self>,
        routes: &mut Routes,
        connection: &Connection,
        space: [u8; 32],
        hint: Option<String>,
        message: &Message,
        token: Option<[u8; 32]>,
    ) -> Result<Forwarded, Failure> {
        routes.connection.get_or_insert_with(|| connection.clone());
        let (shard, hosted) = match routes.spaces.get(&space) {
            Some(route) if route.hosted && hint.is_none() => (route.shard.clone(), true),
            Some(route) => {
                self.resolve_at_gateway(space, hint.or(Some(route.shard.clone())))
                    .await
            }
            None => return Ok(Forwarded::here(busy(message))),
        };
        self.note_sent(connection.link, space, &message.bytes);
        let Some(route) = routes.spaces.get_mut(&space) else {
            return Ok(Forwarded::here(busy(message)));
        };
        route.shard = shard;
        route.hosted = hosted;
        let Some(answer) = self
            .send(connection, space, route, &message.bytes, token)
            .await
        else {
            return Ok(Forwarded::here(busy(message)));
        };
        let ForwardAnswer::Answered {
            out,
            close,
            holding,
            granted,
            more,
            ..
        } = answer
        else {
            return Ok(Forwarded::here(busy(message)));
        };
        // Only a present granted is made again at another owner: one
        // refused leaves nothing.
        if message.kind == MessageType::Present {
            if grants_present(&out) {
                if route.replay.len() >= REPLAYS {
                    route.replay.remove(0);
                }
                route.replay.push((message.bytes.clone(), token));
            }
        } else if is_subscribe(message) {
            route.subscribe = Some(message.bytes.clone());
        }
        {
            let mut held = lock(&self.gateway.holding);
            if holding {
                held.insert((connection.link, space));
            } else {
                held.remove(&(connection.link, space));
            }
        }
        let out: Vec<Outgoing> = out
            .into_iter()
            .filter_map(|out| self.note_out(connection.link, out, false))
            .filter_map(from_wire)
            .collect();
        // The owner holds no grant for the connection in the space any
        // more, as when the entries it proved retired (peers.md, 3.6
        // Retirement and the cap, "Connections"): the gateway keeps
        // nothing for it there either, and the owner forgets the space on
        // the connection.
        if !granted {
            let owner = routes.spaces.remove(&space).and_then(|route| route.owner);
            lock(&self.gateway.held).remove(&(connection.link, space));
            lock(&self.gateway.holding).remove(&(connection.link, space));
            if let Some(owner) = owner {
                self.leave_owner(connection.link, space, owner).await;
            }
        }
        if let Some(code) = close {
            return Err(close_of(code));
        }
        Ok(Forwarded {
            out,
            more: more && granted,
            holds: Some(granted),
        })
    }

    /// Notes what a device sends in a space: the events it stores and the
    /// heads it announces, which it holds.
    fn note_sent(&self, link: u64, space: [u8; 32], bytes: &[u8]) {
        use frasil_units::messages::Message as Unit;
        let (events, heads) = match unit_of(bytes) {
            Some(Unit::Events { events }) => (ids_of(&events), Vec::new()),
            Some(Unit::Heads { heads, .. }) => (Vec::new(), heads),
            _ => return,
        };
        // Only for a space with a route, which made its entry.
        let mut held = lock(&self.gateway.held);
        let Some(entry) = held.get_mut(&(link, space)) else {
            return;
        };
        for (id, parents) in events {
            entry.note(id, &parents, false);
        }
        for head in heads {
            entry.add_head(head);
        }
    }

    /// Notes the events that go to a connection, which it then holds.
    /// With `once`, while the connection moves to a new owner, an event
    /// delivered already is passed over, and nothing goes if nothing is
    /// left.
    fn note_out(&self, link: u64, out: Out, once: bool) -> Option<Out> {
        use frasil_units::messages::Message as Unit;
        let Out::Sync(space, bytes) = &out else {
            return Some(out);
        };
        let Some(Unit::Events { events }) = unit_of(bytes) else {
            return Some(out);
        };
        let space = *space;
        let count = events.len();
        let mut kept = Vec::with_capacity(count);
        {
            let mut held = lock(&self.gateway.held);
            // A connection with no route in the space is told nothing
            // through it, and nothing is noted for it.
            let Some(entry) = held.get_mut(&(link, space)) else {
                return Some(out);
            };
            for signed in events {
                let new = match frasil_events::decode(&signed) {
                    Ok(event) => entry.note(event.id(), event.parents(), true),
                    Err(_) => true,
                };
                if new || !once {
                    kept.push(signed);
                }
            }
        }
        if kept.len() == count {
            Some(out)
        } else if kept.is_empty() {
            None
        } else {
            Some(Out::Sync(
                space,
                crate::state::sync(EventId(space), Unit::Events { events: kept }),
            ))
        }
    }

    /// Sends one message of a space to its owner until an owner answers
    /// it, for as long as a takeover takes. An owner the connection has not
    /// reached in the space before is first given what the connection
    /// presented and subscribed there, and the one before told to forget
    /// it. A message or an answer larger than the links carry is sent once.
    async fn send(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        route: &mut Route,
        bytes: &[u8],
        token: Option<[u8; 32]>,
    ) -> Option<ForwardAnswer> {
        let deadline = Instant::now() + self.takeover();
        loop {
            let owner = self.owner(&route.shard)?;
            if route.owner != Some(owner)
                && self.rehome(connection, space, route, owner, deadline).await
                || route.owner == Some(owner)
            {
                match self
                    .send_once(
                        owner,
                        connection,
                        space,
                        &route.shard,
                        bytes,
                        token,
                        deadline,
                    )
                    .await
                {
                    Ok(answer @ ForwardAnswer::Answered { .. }) => return Some(answer),
                    Err(Unanswered::TooLarge) => {
                        log(
                            "a forwarded message or its answer is larger than a cluster link carries",
                        );
                        return None;
                    }
                    Ok(ForwardAnswer::NotMine(theirs)) if theirs > self.epoch() => {
                        let until = Instant::now() + Duration::from_secs(1);
                        while self.epoch() < theirs && Instant::now() < until {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    }
                    Ok(ForwardAnswer::NotMine(_)) => {
                        // The same view, and not the owner's: the index may
                        // name the space's shard now, after a move.
                        let (shard, hosted) = self.resolve_fresh(space, route.shard.clone()).await;
                        if hosted && shard != route.shard {
                            route.shard = shard;
                            route.hosted = true;
                        }
                        tokio::time::sleep(self.config.timing.renew / 10).await;
                    }
                    _ => tokio::time::sleep(self.config.timing.renew / 10).await,
                }
            } else {
                tokio::time::sleep(self.config.timing.renew / 10).await;
            }
            if Instant::now() >= deadline {
                return None;
            }
        }
    }

    /// Sends one message of a space the connection holds no grant in to the
    /// space's owner until an owner answers it, for as long as a takeover
    /// takes, keeping nothing: the owner that answered, and its answer.
    /// The shard is the one the index names once an owner answered "not
    /// mine" from the same view.
    async fn send_ungranted(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        shard: &mut String,
        hosted: &mut bool,
        bytes: &[u8],
        token: Option<[u8; 32]>,
    ) -> Option<(NodeId, ForwardAnswer)> {
        let deadline = Instant::now() + self.takeover();
        loop {
            let owner = self.owner(shard)?;
            match self
                .send_once(owner, connection, space, shard, bytes, token, deadline)
                .await
            {
                Ok(answer @ ForwardAnswer::Answered { .. }) => return Some((owner, answer)),
                Err(Unanswered::TooLarge) => {
                    log("a forwarded message or its answer is larger than a cluster link carries");
                    return None;
                }
                Ok(ForwardAnswer::NotMine(theirs)) if theirs > self.epoch() => {
                    let until = Instant::now() + Duration::from_secs(1);
                    while self.epoch() < theirs && Instant::now() < until {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                Ok(ForwardAnswer::NotMine(_)) => {
                    let (fresh, indexed) = self.resolve_fresh(space, shard.clone()).await;
                    if indexed && fresh != *shard {
                        *shard = fresh;
                        *hosted = true;
                    }
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                Err(Unanswered::Unreached) => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
        }
    }

    /// Presents and subscribes again at `owner` what the connection did in
    /// the space at its owner before, and tells that one to forget it.
    /// Whether the new owner took every message.
    async fn rehome(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        route: &mut Route,
        owner: NodeId,
        deadline: Instant,
    ) -> bool {
        // Moving from an owner it subscribed at: what the new owner sends
        // live from now on is counted, so that the catch-up below passes
        // over it, and the catch-up's events are passed over as they come
        // live.
        let catch_up = route.owner.is_some() && route.subscribe.is_some();
        if catch_up {
            lock(&self.gateway.held)
                .entry((connection.link, space))
                .or_default()
                .moving = Some(Instant::now() + self.takeover());
        }
        let again: Vec<(Vec<u8>, Option<[u8; 32]>)> = route
            .replay
            .iter()
            .cloned()
            .chain(route.subscribe.clone().map(|bytes| (bytes, None)))
            .collect();
        for (bytes, token) in again {
            let answer = self
                .send_once(
                    owner,
                    connection,
                    space,
                    &route.shard,
                    &bytes,
                    token,
                    deadline,
                )
                .await;
            if !matches!(answer, Ok(ForwardAnswer::Answered { .. })) {
                return false;
            }
        }
        if catch_up
            && !self
                .catch_up(connection, space, route, owner, deadline)
                .await
        {
            return false;
        }
        let name = LinkName {
            node: self.me,
            run: self.run,
            link: connection.link,
        };
        if let Some(old) = route.owner.replace(owner) {
            if old == self.me {
                self.owners.closed(name, Some(space));
            } else {
                let body = Closed {
                    link: name,
                    space: Some(space),
                }
                .encode();
                let _ = self.links.notify(old, wire::CLOSED, body).await;
            }
        }
        true
    }

    /// After a subscription moved to `owner`: `Heads` sent there naming
    /// what the connection is known to hold, and the events it answers
    /// with handed to the device, those delivered live meanwhile passed
    /// over. So what the new owner stored before the subscription reached
    /// it reaches the device too. Whether the owner answered.
    async fn catch_up(
        self: &Arc<Self>,
        connection: &Connection,
        space: [u8; 32],
        route: &Route,
        owner: NodeId,
        deadline: Instant,
    ) -> bool {
        use frasil_units::messages::Message as Unit;
        let heads: Vec<EventId> = lock(&self.gateway.held)
            .get(&(connection.link, space))
            .map(|held| held.heads.iter().copied().collect())
            .unwrap_or_default();
        if heads.is_empty() {
            // Nothing is known to be held: no basis to send from.
            return true;
        }
        let streams = match route.subscribe.as_deref().and_then(unit_of) {
            Some(Unit::Subscribe { streams }) => streams,
            _ => Vec::new(),
        };
        let bytes = crate::state::sync(
            EventId(space),
            Unit::Heads {
                heads,
                vector: None,
                streams,
            },
        );
        let answer = self
            .send_once(
                owner,
                connection,
                space,
                &route.shard,
                &bytes,
                None,
                deadline,
            )
            .await;
        let (mut out, mut more) = match answer {
            Ok(ForwardAnswer::Answered { out, more, .. }) => (out, more),
            Err(Unanswered::TooLarge) => {
                // Asking again cannot help: the move goes on without the
                // catch-up.
                log("a catch-up through the gateway is larger than a cluster link carries");
                return true;
            }
            _ => return false,
        };
        let Some(shared) = self.peer() else {
            return true;
        };
        // The owner answers in parts: each is asked for once the one
        // before is queued for the device, and none once its queue is full.
        loop {
            for out in out {
                // Only the events: the owner's own heads answer no question
                // of the device's.
                if !matches!(&out, Out::Sync(_, bytes) if matches!(unit_of(bytes), Some(Unit::Events { .. })))
                {
                    continue;
                }
                if let Some(out) = self
                    .note_out(connection.link, out, true)
                    .and_then(from_wire)
                    && !shared.core.send_to(connection.link, out)
                {
                    log(
                        "a catch-up through the gateway was dropped: the connection's queue is full",
                    );
                    return true;
                }
            }
            if !more {
                return true;
            }
            match self.next_part(owner, connection.link, space).await {
                Some(next) => (out, more) = next,
                None => return true,
            }
        }
    }

    /// Sends one message to one owner: its answer, or why none came.
    #[allow(clippy::too_many_arguments)]
    async fn send_once(
        self: &Arc<Self>,
        owner: NodeId,
        connection: &Connection,
        space: [u8; 32],
        shard: &str,
        bytes: &[u8],
        token: Option<[u8; 32]>,
        deadline: Instant,
    ) -> Result<ForwardAnswer, Unanswered> {
        let forward = Forward {
            link: LinkName {
                node: self.me,
                run: self.run,
                link: connection.link,
            },
            binding: connection.binding,
            purpose: connection.purpose.code(),
            server: connection.server,
            source: connection.source.clone(),
            token,
            epoch: self.epoch(),
            space,
            shard: shard.to_owned(),
            message: bytes.to_vec(),
        };
        if owner == self.me {
            return Ok(self.serve_forward_local(self.me, forward).await);
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(100), FORWARD_WAIT);
        match self
            .links
            .call(owner, wire::FORWARD, forward.encode(), wait)
            .await
        {
            Ok(body) => ForwardAnswer::decode(&body).ok_or(Unanswered::Unreached),
            Err(error) if error.is_too_large() => Err(Unanswered::TooLarge),
            Err(_) => Err(Unanswered::Unreached),
        }
    }

    /// The owner's side of a forwarded message.
    pub(crate) async fn serve_forward(
        self: &Arc<Self>,
        from: NodeId,
        body: &[u8],
    ) -> ForwardAnswer {
        match Forward::decode(body) {
            Some(forward) => self.serve_forward_local(from, forward).await,
            None => ForwardAnswer::Answered {
                out: Vec::new(),
                close: Some(Code::Malformed.number()),
                holding: false,
                granted: false,
                unknown: false,
                more: false,
            },
        }
    }

    /// The owner's side of a gateway's ask for the next part of an answer.
    pub(crate) async fn serve_forward_next(&self, body: &[u8]) -> ForwardAnswer {
        let Some(next) = wire::ForwardNext::decode(body) else {
            return ForwardAnswer::NotMine(self.epoch());
        };
        self.serve_forward_next_local(next).await
    }

    /// The next part of the answer an owner serves a connection in parts
    /// (module documentation, "Answers in parts"): nothing once the
    /// connection or the space left this owner.
    async fn serve_forward_next_local(&self, next: wire::ForwardNext) -> ForwardAnswer {
        let nothing = ForwardAnswer::Answered {
            out: Vec::new(),
            close: None,
            holding: false,
            granted: true,
            unknown: false,
            more: false,
        };
        let Some(handle) = lock(&self.owners.sessions).get(&next.link).cloned() else {
            return nothing;
        };
        let mut session = handle.lock().await;
        if session.retired || !session.seen.contains(&next.space) {
            return nothing;
        }
        self.owners.heard(next.link);
        let (out, more) = session.part(next.space).await;
        let space = EventId(next.space);
        ForwardAnswer::Answered {
            out,
            close: None,
            holding: session.space.holding_space(&space),
            granted: session
                .space
                .grants
                .get(&space)
                .is_some_and(crate::state::Grant::holds),
            unknown: false,
            more,
        }
    }

    async fn serve_forward_local(
        self: &Arc<Self>,
        from: NodeId,
        forward: Forward,
    ) -> ForwardAnswer {
        let epoch = self.epoch();
        let Some(shared) = self.peer() else {
            return ForwardAnswer::NotMine(epoch);
        };
        // The owner names the space's shard itself; the gateway's name
        // serves only for a space the index names nowhere, as a ticket's
        // library does for a create. It answers only while its lease
        // holds, and for a shard it may open.
        let (mut shard, _) = self
            .resolve(forward.space, Some(forward.shard.clone()))
            .await;
        // Memory may predate a move into the shard the gateway names.
        if shard != forward.shard && self.answering(&forward.shard) {
            shard = self
                .resolve_fresh(forward.space, forward.shard.clone())
                .await
                .0;
        }
        if !self.answering(&shard) || !self.openable(&shard) {
            return ForwardAnswer::NotMine(epoch);
        }
        self.owners.served.fetch_add(1, Ordering::Relaxed);
        self.owners.heard(forward.link);
        // A connection retired between taking it out of the map and locking
        // it is asked for again: the map holds a live one, or makes one.
        let (handle, mut session) = loop {
            let handle = self.owners.session(self, from, &forward, &shared);
            let session = handle.clone().lock_owned().await;
            if !session.retired {
                break (handle, session);
            }
        };
        // The gateway asks for the next message's answer only once it took
        // the last one whole: what is left of it was given up.
        session.pending = None;
        if session.seen.insert(forward.space) {
            let core = shared.clone();
            let space = EventId(forward.space);
            let refreshed =
                tokio::task::spawn_blocking(move || core.core.refresh_space(&space)).await;
            if !matches!(refreshed, Ok(Ok(()))) {
                session.seen.remove(&forward.space);
                self.owners
                    .retire_unless_granted(forward.link, &handle, &mut session);
                return ForwardAnswer::NotMine(epoch);
            }
        }
        let space = EventId(forward.space);
        let message = match crate::server::read(&forward.message, shared.settings.extensions) {
            Ok(Some(message)) => message,
            read => {
                let close = read.err().map(|class| Close::of(class).code.number());
                let granted = session
                    .space
                    .grants
                    .get(&space)
                    .is_some_and(crate::state::Grant::holds);
                self.owners
                    .retire_unless_granted(forward.link, &handle, &mut session);
                return ForwardAnswer::Answered {
                    out: Vec::new(),
                    close,
                    holding: false,
                    granted,
                    unknown: false,
                    more: false,
                };
            }
        };
        // The answer goes in parts, each at most `PART_BYTES` past its
        // first message: the first now, the rest as the gateway asks.
        let mut answers = Vec::new();
        let answer = session
            .space
            .handle_with(&message, forward.token, &mut answers)
            .await;
        let holding = session.space.holding_space(&space);
        let granted = session
            .space
            .grants
            .get(&space)
            .is_some_and(crate::state::Grant::holds);
        // A present refused `no_library` for a space no departure names:
        // the peer knows nothing of it (`Core::present`, `unhosted`), and
        // the gateway may say so itself for a while.
        let unknown = message.kind == MessageType::Present
            && !granted
            && matches!(&answer, Ok(out) if refused_no_library(out))
            && {
                let core = shared.clone();
                tokio::task::spawn_blocking(move || core.core.departure_of(&space).is_none())
                    .await
                    .unwrap_or(false)
            };
        // Nothing granted on the connection here: nothing of it is kept.
        self.owners
            .retire_unless_granted(forward.link, &handle, &mut session);
        match answer {
            Ok(out) => {
                let (out, more) = if session.retired {
                    (out.into_iter().filter_map(to_wire).collect(), false)
                } else {
                    session.pending = Some(Pending {
                        space: forward.space,
                        ready: in_parts(out),
                        answers: answers.into(),
                    });
                    session.part(forward.space).await
                };
                ForwardAnswer::Answered {
                    out,
                    close: None,
                    holding,
                    granted,
                    unknown,
                    more,
                }
            }
            Err(closed) => ForwardAnswer::Answered {
                out: Vec::new(),
                close: Some(closed.code.number()),
                holding,
                granted,
                unknown: false,
                more: false,
            },
        }
    }

    /// What an owner sends a connection of this gateway.
    pub(crate) fn on_deliver(&self, body: &[u8]) {
        let Some(deliver) = Deliver::decode(body) else {
            return;
        };
        self.deliver_here(deliver.link, deliver.out);
    }

    fn deliver_here(&self, link: LinkName, out: Out) {
        if link.node != self.me || link.run != self.run {
            return;
        }
        let Some(shared) = self.peer() else {
            return;
        };
        if let Some(out) = self.note_out(link.link, out, true).and_then(from_wire)
            && !shared.core.send_to(link.link, out)
        {
            log("a delivery through the gateway was dropped: the connection's queue is full");
        }
    }

    /// A gateway's connection closed, or left a space here.
    pub(crate) fn on_closed(self: &Arc<Self>, from: NodeId, body: &[u8]) {
        let Some(closed) = Closed::decode(body) else {
            return;
        };
        if closed.link.node != from {
            return;
        }
        self.owners.closed(closed.link, closed.space);
    }

    /// A device's connection to this gateway closed: each owner it reached
    /// forgets it.
    pub(crate) fn closed(self: &Arc<Self>, link: u64) {
        let Some(routes) = lock(&self.gateway.links).remove(&link) else {
            return;
        };
        lock(&self.gateway.holding).retain(|(held, _)| *held != link);
        lock(&self.gateway.held).retain(|(held, _), _| *held != link);
        let cluster = self.clone();
        tokio::spawn(async move {
            let routes = routes.lock().await;
            let owners: BTreeSet<NodeId> = routes
                .spaces
                .values()
                .filter_map(|route| route.owner)
                .collect();
            let name = LinkName {
                node: cluster.me,
                run: cluster.run,
                link,
            };
            for owner in owners {
                if owner == cluster.me {
                    cluster.owners.closed(name, None);
                } else {
                    let body = Closed {
                        link: name,
                        space: None,
                    }
                    .encode();
                    let _ = cluster.links.notify(owner, wire::CLOSED, body).await;
                }
            }
        });
    }

    /// Whether an import is in progress or a create pending on a
    /// connection, at any owner.
    pub(crate) fn holding(&self, link: u64) -> bool {
        lock(&self.gateway.holding)
            .iter()
            .any(|(held, _)| *held == link)
    }

    /// After an epoch: each connection's spaces whose owner changed are
    /// presented and subscribed again at the new owner, and the old owner
    /// told to forget them.
    pub(crate) async fn gateway_reroute(self: &Arc<Self>) {
        let all: Vec<Arc<tokio::sync::Mutex<Routes>>> =
            lock(&self.gateway.links).values().cloned().collect();
        for routes in all {
            let cluster = self.clone();
            tokio::spawn(async move {
                let mut routes = routes.lock().await;
                let Some(connection) = routes.connection.clone() else {
                    return;
                };
                // An owner that does not answer yet, as one still opening
                // the shard, is asked again until the takeover's end: the
                // device may send nothing more that would move it.
                let deadline = Instant::now() + cluster.takeover();
                for (space, route) in &mut routes.spaces {
                    while let Some(owner) = cluster.owner(&route.shard) {
                        if route.owner == Some(owner)
                            || cluster
                                .rehome(&connection, *space, route, owner, deadline)
                                .await
                            || Instant::now() >= deadline
                        {
                            break;
                        }
                        tokio::time::sleep(cluster.config.timing.renew / 10).await;
                    }
                }
            });
        }
    }

    /// Every lease: tells each owner this gateway's connections that reach
    /// it, and forgets the forwarded connections no gateway named for three
    /// leases.
    pub(crate) async fn live_loop(self: Arc<Self>) {
        let lease = self.config.timing.lease;
        let mut interval = tokio::time::interval(lease);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let all: Vec<(u64, Arc<tokio::sync::Mutex<Routes>>)> = lock(&self.gateway.links)
                .iter()
                .map(|(link, routes)| (*link, routes.clone()))
                .collect();
            let mut by_owner: BTreeMap<NodeId, Vec<u64>> = BTreeMap::new();
            for (link, routes) in all {
                let Ok(routes) = routes.try_lock() else {
                    // Busy forwarding, which names it anyway.
                    continue;
                };
                for owner in routes.spaces.values().filter_map(|route| route.owner) {
                    let links = by_owner.entry(owner).or_default();
                    if !links.contains(&link) {
                        links.push(link);
                    }
                }
            }
            for (owner, links) in by_owner {
                if owner == self.me {
                    self.owners.live(self.me, self.run, &links);
                } else {
                    let body = wire::Live {
                        run: self.run,
                        links,
                    }
                    .encode();
                    let _ = self.links.notify(owner, wire::LIVE, body).await;
                }
            }
            self.owners.expire(lease * 3);
        }
    }

    /// A gateway's digest of its live connections.
    pub(crate) fn on_live(&self, from: NodeId, body: &[u8]) {
        if let Some(live) = wire::Live::decode(body) {
            self.owners.live(from, live.run, &live.links);
        }
    }

    // -- Mailboxes

    async fn mailbox_remote(
        self: &Arc<Self>,
        family: &str,
        address: &[u8; 32],
        request: MailboxRequest,
    ) -> Result<MailboxAnswer, Reason> {
        let shard = crate::shards::Shards::address_shard(family, address);
        self.mailbox_at(&shard, request).await
    }

    /// A mailbox request at the owner of `shard`, for as long as a
    /// takeover takes.
    async fn mailbox_at(
        self: &Arc<Self>,
        shard: &str,
        request: MailboxRequest,
    ) -> Result<MailboxAnswer, Reason> {
        let deadline = Instant::now() + self.takeover();
        loop {
            let owner = self.owner(shard).ok_or(("busy".to_owned(), 503))?;
            let answer = if owner == self.me {
                Some(self.serve_mailbox_request(request.clone()).await)
            } else {
                self.links
                    .call(owner, wire::MAILBOX, request.encode(), FORWARD_WAIT)
                    .await
                    .ok()
                    .and_then(|body| MailboxAnswer::decode(&body))
            };
            match answer {
                Some(MailboxAnswer::NotMine(_)) | None if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                Some(MailboxAnswer::NotMine(_)) | None => return Err(("busy".into(), 503)),
                Some(MailboxAnswer::Refused(code, status)) => return Err((code, status)),
                Some(answer) => return Ok(answer),
            }
        }
    }

    pub(crate) async fn serve_mailbox(self: &Arc<Self>, body: &[u8]) -> MailboxAnswer {
        match MailboxRequest::decode(body) {
            Some(request) => self.serve_mailbox_request(request).await,
            None => MailboxAnswer::Refused("malformed".into(), 400),
        }
    }

    async fn serve_mailbox_request(self: &Arc<Self>, request: MailboxRequest) -> MailboxAnswer {
        let epoch = self.epoch();
        let Some(shared) = self.peer() else {
            return MailboxAnswer::NotMine(epoch);
        };
        let core = &shared.core;
        let now = shared.clock.now();
        let (kind, address) = match &request {
            MailboxRequest::Put { kind, address, .. }
            | MailboxRequest::Get { kind, address, .. } => (*kind, *address),
            MailboxRequest::TokenPut { address, .. } => (Kind::Device.code(), *address),
        };
        let Some(kind) = Kind::from_code(u64::from(kind)) else {
            return MailboxAnswer::Refused("malformed".into(), 400);
        };
        if kind == Kind::Drop && shared.settings.extensions.invite_links {
            return self.serve_drop(&shared, request, now).await;
        }
        let Some(family) = family_of(kind) else {
            return MailboxAnswer::Refused("not_found".into(), 404);
        };
        let shard = crate::shards::Shards::address_shard(family, &address);
        if !core.keeps_address(family, &address)
            || !self.answering(&shard)
            || !self.openable(&shard)
        {
            return MailboxAnswer::NotMine(epoch);
        }
        match request {
            // ext-deposit-tokens.md, 3.7 Redeeming, at the mailbox's keeper.
            MailboxRequest::TokenPut { .. } if !shared.settings.extensions.deposit_tokens => {
                MailboxAnswer::Refused("malformed".into(), 400)
            }
            MailboxRequest::TokenPut {
                address,
                item,
                token,
                ..
            } => {
                let deposit = frasil_deposit_tokens::Token::from_bytes(&token).map(|token| {
                    frasil_deposit_tokens::TokenDeposit {
                        request: None,
                        address,
                        item,
                        token,
                    }
                });
                let answer = match deposit {
                    Ok(deposit) => core.token_put(&deposit, now).await,
                    Err(class) => Err(class),
                };
                match answer {
                    Ok(id) => MailboxAnswer::Put(id),
                    Err(class) => {
                        let (code, status) = crate::deposit::reason(class);
                        MailboxAnswer::Refused(code, status)
                    }
                }
            }
            MailboxRequest::Put { item, source, .. } => {
                match core.mailbox_put(kind, &address, &item, &source, now).await {
                    Ok(id) => MailboxAnswer::Put(id),
                    Err((code, status)) => MailboxAnswer::Refused(code, status),
                }
            }
            MailboxRequest::Get {
                after, collector, ..
            } => {
                let collector = collector
                    .as_ref()
                    .map(|(key, signature, binding)| (key, signature.as_slice(), binding));
                match core.mailbox_get(kind, &address, after.as_ref(), collector, now) {
                    Ok(items) => MailboxAnswer::Items(items),
                    Err((code, status)) => MailboxAnswer::Refused(code, status),
                }
            }
        }
    }

    /// ext-invite-links.md: the space a drop at `address` was placed for,
    /// as its locator at rest names it.
    async fn drop_space(&self, address: &[u8; 32]) -> Result<Option<[u8; 32]>, Reason> {
        let Some(shared) = self.peer() else {
            return Err(("busy".into(), 503));
        };
        let address = crate::records::Records::drop_locator_address(address);
        let found = tokio::task::spawn_blocking(move || shared.core.records.get(&address)).await;
        match found {
            Ok(Ok(record)) => Ok(record
                .as_deref()
                .and_then(crate::records::Records::drop_locator_space)),
            _ => Err(("busy".into(), 503)),
        }
    }

    /// ext-invite-links.md: a collection of a drop, at the node that
    /// answers for the space it was placed for, which keeps it (crate
    /// `drops`). None is held where no locator names a space.
    async fn drop_get(
        self: &Arc<Self>,
        address: &[u8; 32],
        after: Option<[u8; 16]>,
    ) -> Result<Items, Reason> {
        let Some(space) = self.drop_space(address).await? else {
            return Ok(Vec::new());
        };
        let (shard, _) = self.resolve(space, None).await;
        let request = MailboxRequest::Get {
            epoch: self.epoch(),
            kind: Kind::Drop.code(),
            address: *address,
            after,
            collector: None,
        };
        match self.mailbox_at(&shard, request).await? {
            MailboxAnswer::Items(items) => Ok(items),
            _ => Err(("busy".into(), 503)),
        }
    }

    /// The owner's side of a drop's collection: served while this node
    /// answers for the drop's space. A drop is placed only over the
    /// WebSocket, at its space's owner.
    async fn serve_drop(
        self: &Arc<Self>,
        shared: &Arc<Shared>,
        request: MailboxRequest,
        now: Reading,
    ) -> MailboxAnswer {
        let epoch = self.epoch();
        let MailboxRequest::Get { address, after, .. } = request else {
            let (code, status) = frasil_transport::ext_invite_links::POST_REFUSED;
            return MailboxAnswer::Refused(code.into(), status);
        };
        let space = match self.drop_space(&address).await {
            Ok(Some(space)) => space,
            Ok(None) => return MailboxAnswer::Items(Vec::new()),
            Err(_) => return MailboxAnswer::NotMine(epoch),
        };
        let (shard, _) = self.resolve(space, None).await;
        if !self.answering(&shard) {
            return MailboxAnswer::NotMine(epoch);
        }
        match shared
            .core
            .mailbox_get(Kind::Drop, &address, after.as_ref(), None, now)
        {
            Ok(items) => MailboxAnswer::Items(items),
            Err((code, status)) => MailboxAnswer::Refused(code, status),
        }
    }

    // -- Object pieces over HTTP

    /// An object piece at the owner of its space: the HTTP status, whether
    /// the body is JSON, and the body.
    pub(crate) async fn piece(self: &Arc<Self>, piece: Piece) -> (u16, bool, Vec<u8>) {
        let (shard, _) = self.resolve(piece.space, None).await;
        let deadline = Instant::now() + self.takeover();
        loop {
            let Some(owner) = self.owner(&shard) else {
                return (503, true, br#"{"code":"busy"}"#.to_vec());
            };
            let answer = if owner == self.me {
                Some(self.serve_piece_request(piece.clone()).await)
            } else {
                self.links
                    .call(owner, wire::PIECE, piece.encode(), FORWARD_WAIT)
                    .await
                    .ok()
                    .and_then(|body| PieceAnswer::decode(&body))
            };
            match answer {
                Some(PieceAnswer::Answered { status, json, body }) => return (status, json, body),
                _ if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                _ => return (503, true, br#"{"code":"busy"}"#.to_vec()),
            }
        }
    }

    pub(crate) async fn serve_piece(self: &Arc<Self>, body: &[u8]) -> PieceAnswer {
        match Piece::decode(body) {
            Some(piece) => self.serve_piece_request(piece).await,
            None => PieceAnswer::Answered {
                status: 400,
                json: true,
                body: br#"{"code":"malformed"}"#.to_vec(),
            },
        }
    }

    async fn serve_piece_request(self: &Arc<Self>, piece: Piece) -> PieceAnswer {
        let epoch = self.epoch();
        let (shard, _) = self.resolve(piece.space, None).await;
        if !self.answering(&shard) || !self.openable(&shard) {
            return PieceAnswer::NotMine(epoch);
        }
        let Some(shared) = self.peer() else {
            return PieceAnswer::NotMine(epoch);
        };
        let (status, json, body) = crate::server::piece_here(&shared, &piece).await;
        PieceAnswer::Answered { status, json, body }
    }
}

impl Cluster {
    /// ext-libraries.md: a library's usage as the operator route answers
    /// it, at the owner of the library's shard, which keeps its ledger:
    /// the HTTP status and the JSON body.
    pub(crate) async fn usage(
        self: &Arc<Self>,
        library: &frasil_libraries::LibraryId,
    ) -> (u16, Vec<u8>) {
        let shard = crate::shards::library_shard(library.as_str());
        let deadline = Instant::now() + self.takeover();
        loop {
            let answer = match self.owner(&shard) {
                Some(owner) if owner == self.me => {
                    Some(self.serve_usage(library.as_str().as_bytes()).await)
                }
                Some(owner) => self
                    .links
                    .call(
                        owner,
                        wire::USAGE,
                        library.as_str().as_bytes().to_vec(),
                        FORWARD_WAIT,
                    )
                    .await
                    .ok()
                    .and_then(|body| PieceAnswer::decode(&body)),
                None => None,
            };
            match answer {
                Some(PieceAnswer::Answered { status, body, .. }) => return (status, body),
                _ if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                _ => return (503, br#"{"code":"busy"}"#.to_vec()),
            }
        }
    }

    /// ext-libraries.md, 3.3 Attaching, Move: a page of a moving space's
    /// records, at the owner of the shard it moves into, here or on another
    /// node (crate `libraries`, module `moves`); tried for as long as a
    /// takeover takes. None if no owner answered.
    pub(crate) async fn move_in(
        self: &Arc<Self>,
        target: &str,
        page: wire::MoveIn,
    ) -> Option<wire::MoveAnswer> {
        use wire::MoveAnswer;
        let deadline = Instant::now() + self.takeover();
        loop {
            let mut page = page.clone();
            page.epoch = self.epoch();
            let answer = match self.owner(target) {
                Some(owner) if owner == self.me => Some(self.serve_move_in_here(page).await),
                Some(owner) => self
                    .links
                    .call(owner, wire::MOVE_IN, page.encode(), FORWARD_WAIT)
                    .await
                    .ok()
                    .and_then(|body| MoveAnswer::decode(&body)),
                None => None,
            };
            match answer {
                Some(MoveAnswer::NotMine(_)) | None if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                Some(MoveAnswer::NotMine(_)) => return None,
                answer => return answer,
            }
        }
    }

    pub(crate) async fn serve_move_in(self: &Arc<Self>, body: &[u8]) -> wire::MoveAnswer {
        match wire::MoveIn::decode(body) {
            Some(page) => self.serve_move_in_here(page).await,
            None => wire::MoveAnswer::Refused("malformed".into()),
        }
    }

    /// A page, at this node: only while it answers for the target shard.
    async fn serve_move_in_here(self: &Arc<Self>, page: wire::MoveIn) -> wire::MoveAnswer {
        let epoch = self.epoch();
        let Some(shared) = self.peer() else {
            return wire::MoveAnswer::NotMine(epoch);
        };
        let Some(intent) = crate::records::MoveRecord::decode(&page.intent) else {
            return wire::MoveAnswer::Refused("malformed".into());
        };
        if !self.answering(&intent.target) || !self.openable(&intent.target) {
            return wire::MoveAnswer::NotMine(epoch);
        }
        match crate::libraries::moves::move_in(&shared, page).await {
            wire::MoveAnswer::NotMine(_) => wire::MoveAnswer::NotMine(epoch),
            answer => answer,
        }
    }

    /// A space's records moved into another shard: every member told, and
    /// this gateway's connections routed there.
    pub(crate) async fn moved(self: &Arc<Self>, space: EventId, shard: &str) {
        let body = wire::Moved {
            space: *space.as_bytes(),
            shard: shard.to_owned(),
        }
        .encode();
        let others: Vec<NodeId> = self
            .membership()
            .nodes
            .keys()
            .filter(|node| **node != self.me)
            .copied()
            .collect();
        for node in others {
            let _ = self.links.notify(node, wire::MOVED, body.clone()).await;
        }
        self.reroute_space(space, shard);
    }

    /// Another node moved a space's records into another shard.
    pub(crate) fn on_moved(self: &Arc<Self>, body: &[u8]) {
        let Some(moved) = wire::Moved::decode(body) else {
            return;
        };
        let cluster = self.clone();
        tokio::spawn(async move {
            let space = EventId(moved.space);
            if let Some(shared) = cluster.peer() {
                crate::libraries::moves::moved_elsewhere(&shared, space, moved.shard.clone()).await;
            }
            cluster.reroute_space(space, &moved.shard);
        });
    }

    /// Routes this gateway's connections in a space to the shard it moved
    /// into, presenting and subscribing again at its owner, each on a task
    /// of its own.
    fn reroute_space(self: &Arc<Self>, space: EventId, shard: &str) {
        let all: Vec<Arc<tokio::sync::Mutex<Routes>>> =
            lock(&self.gateway.links).values().cloned().collect();
        for routes in all {
            let cluster = self.clone();
            let shard = shard.to_owned();
            tokio::spawn(async move {
                let mut routes = routes.lock().await;
                let Some(connection) = routes.connection.clone() else {
                    return;
                };
                let Some(route) = routes.spaces.get_mut(space.as_bytes()) else {
                    return;
                };
                route.shard = shard;
                route.hosted = true;
                let Some(owner) = cluster.owner(&route.shard) else {
                    return;
                };
                if route.owner != Some(owner) {
                    let deadline = Instant::now() + cluster.takeover();
                    cluster
                        .rehome(&connection, *space.as_bytes(), route, owner, deadline)
                        .await;
                }
            });
        }
    }

    pub(crate) async fn serve_usage(self: &Arc<Self>, body: &[u8]) -> PieceAnswer {
        let epoch = self.epoch();
        let Some(library) = std::str::from_utf8(body)
            .ok()
            .and_then(|id| frasil_libraries::LibraryId::new(id).ok())
        else {
            return PieceAnswer::Answered {
                status: 400,
                json: true,
                body: br#"{"code":"malformed"}"#.to_vec(),
            };
        };
        let shard = crate::shards::library_shard(library.as_str());
        let Some(shared) = self.peer() else {
            return PieceAnswer::NotMine(epoch);
        };
        if !self.answering(&shard) {
            return PieceAnswer::NotMine(epoch);
        }
        let (status, body) = match crate::libraries::library_usage(&shared, &library).await {
            Some(usage) => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "library": library.as_str(),
                    "used_bytes": usage.used_bytes,
                    "quota_bytes": usage.quota_bytes,
                    "spaces": usage.spaces,
                }))
                .unwrap_or_default(),
            ),
            None => (404, br#"{"code":"not_found"}"#.to_vec()),
        };
        PieceAnswer::Answered {
            status,
            json: true,
            body,
        }
    }

    /// ext-libraries.md, 2.4 Settings: a library's settings read, or set
    /// with the settings route's JSON body, at the owner of the library's
    /// shard, which keeps them: the HTTP status and the JSON body.
    pub(crate) async fn settings(
        self: &Arc<Self>,
        library: &frasil_libraries::LibraryId,
        change: Option<Vec<u8>>,
    ) -> (u16, Vec<u8>) {
        let shard = crate::shards::library_shard(library.as_str());
        let request = wire::SettingsRequest {
            library: library.as_str().to_owned(),
            change,
        };
        let deadline = Instant::now() + self.takeover();
        loop {
            let answer = match self.owner(&shard) {
                Some(owner) if owner == self.me => Some(self.serve_settings_request(&request)),
                Some(owner) => self
                    .links
                    .call(owner, wire::SETTINGS, request.encode(), FORWARD_WAIT)
                    .await
                    .ok()
                    .and_then(|body| PieceAnswer::decode(&body)),
                None => None,
            };
            match answer {
                Some(PieceAnswer::Answered { status, body, .. }) => return (status, body),
                _ if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                _ => return (503, br#"{"code":"busy"}"#.to_vec()),
            }
        }
    }

    pub(crate) async fn serve_settings(self: &Arc<Self>, body: &[u8]) -> PieceAnswer {
        match wire::SettingsRequest::decode(body) {
            Some(request) => self.serve_settings_request(&request),
            None => PieceAnswer::Answered {
                status: 400,
                json: true,
                body: br#"{"code":"malformed"}"#.to_vec(),
            },
        }
    }

    fn serve_settings_request(self: &Arc<Self>, request: &wire::SettingsRequest) -> PieceAnswer {
        let epoch = self.epoch();
        let Ok(library) = frasil_libraries::LibraryId::new(&request.library) else {
            return PieceAnswer::Answered {
                status: 400,
                json: true,
                body: br#"{"code":"malformed"}"#.to_vec(),
            };
        };
        let shard = crate::shards::library_shard(library.as_str());
        let Some(shared) = self.peer() else {
            return PieceAnswer::NotMine(epoch);
        };
        if !self.answering(&shard) {
            return PieceAnswer::NotMine(epoch);
        }
        let (status, body) =
            crate::libraries::library_settings(&shared, &library, request.change.as_deref());
        PieceAnswer::Answered {
            status,
            json: true,
            body,
        }
    }

    /// A step of a library's hand-over (crate `libraries`, module
    /// `handover`) at the owner of the library's shard: the HTTP status,
    /// whether the body is JSON, and the body.
    pub(crate) async fn handover(
        self: &Arc<Self>,
        step: u8,
        library: &frasil_libraries::LibraryId,
        after: &[u8],
        reading: Option<Reading>,
        rows: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> (u16, bool, Vec<u8>) {
        let shard = crate::shards::library_shard(library.as_str());
        let mut request = wire::HandoverRequest {
            epoch: self.epoch(),
            step,
            library: library.as_str().to_owned(),
            after: after.to_vec(),
            reading: reading
                .map(|reading| crate::libraries::bundle::reading_value(&reading).encode())
                .unwrap_or_default(),
            rows,
        };
        let deadline = Instant::now() + self.takeover();
        loop {
            request.epoch = self.epoch();
            let answer = match self.owner(&shard) {
                Some(owner) if owner == self.me => {
                    Some(self.serve_handover_request(&request).await)
                }
                Some(owner) => self
                    .links
                    .call(owner, wire::HANDOVER, request.encode(), FORWARD_WAIT)
                    .await
                    .ok()
                    .and_then(|body| PieceAnswer::decode(&body)),
                None => None,
            };
            match answer {
                Some(PieceAnswer::Answered { status, json, body }) => return (status, json, body),
                _ if Instant::now() < deadline => {
                    tokio::time::sleep(self.config.timing.renew / 10).await;
                }
                _ => return (503, true, br#"{"code":"busy"}"#.to_vec()),
            }
        }
    }

    pub(crate) async fn serve_handover(self: &Arc<Self>, body: &[u8]) -> PieceAnswer {
        match wire::HandoverRequest::decode(body) {
            Some(request) => self.serve_handover_request(&request).await,
            None => PieceAnswer::Answered {
                status: 400,
                json: true,
                body: br#"{"code":"malformed"}"#.to_vec(),
            },
        }
    }

    async fn serve_handover_request(
        self: &Arc<Self>,
        request: &wire::HandoverRequest,
    ) -> PieceAnswer {
        let epoch = self.epoch();
        let malformed = || PieceAnswer::Answered {
            status: 400,
            json: true,
            body: br#"{"code":"malformed"}"#.to_vec(),
        };
        let Ok(library) = frasil_libraries::LibraryId::new(&request.library) else {
            return malformed();
        };
        let reading = if request.reading.is_empty() {
            None
        } else {
            match frasil_base::cbor::decode(&request.reading)
                .ok()
                .and_then(|value| crate::libraries::bundle::read_reading(&value))
            {
                Some(reading) => Some(reading),
                None => return malformed(),
            }
        };
        let shard = crate::shards::library_shard(library.as_str());
        let Some(shared) = self.peer() else {
            return PieceAnswer::NotMine(epoch);
        };
        if !self.answering(&shard) || !self.openable(&shard) {
            return PieceAnswer::NotMine(epoch);
        }
        let (status, json, body) = crate::libraries::handover::step_here(
            &shared,
            request.step,
            &library,
            &request.after,
            reading,
            request.rows.clone(),
        )
        .await;
        PieceAnswer::Answered { status, json, body }
    }
}

/// The hashed family of a mailbox kind kept at rest: exchange and device
/// mailboxes. A drop is served by the owner of its space (crate `drops`).
fn family_of(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Exchange => Some("exchange"),
        Kind::Device => Some("mailboxes"),
        _ => None,
    }
}

/// A deposit, at the node that keeps the mailbox. A deposit in a device
/// mailbox counts first toward its source's rate at the node it reaches,
/// once, wherever the mailbox is kept; the node that keeps the mailbox
/// applies the caps (crate `device_mail`).
pub(crate) async fn mailbox_put(
    shared: &Arc<Shared>,
    kind: Kind,
    address: &[u8; 32],
    item: &[u8],
    source: &str,
    now: Reading,
) -> Result<[u8; 16], Reason> {
    if kind == Kind::Device && !shared.core.admit_deposit(source, now) {
        return Err(("rate_limited".into(), 429));
    }
    if let Some(cluster) = shared.cluster.get()
        && let Some(family) = family_of(kind)
        && !shared.core.keeps_address(family, address)
    {
        let request = MailboxRequest::Put {
            epoch: cluster.epoch(),
            kind: kind.code(),
            address: *address,
            item: item.to_vec(),
            source: source.to_owned(),
        };
        return match cluster.mailbox_remote(family, address, request).await? {
            MailboxAnswer::Put(id) => Ok(id),
            _ => Err(("busy".into(), 503)),
        };
    }
    shared
        .core
        .mailbox_put(kind, address, item, source, now)
        .await
}

/// ext-deposit-tokens.md, 3.7 Redeeming: a token deposit, at the node that
/// keeps its mailbox. It counts toward no rate of anonymous deposits; a
/// source that had `refused_per_minute` tokens refused in the last minute
/// is refused `rate_limited` until the minute passes (section 3.7: "A peer
/// MAY limit refused tokens per source").
pub(crate) async fn token_put(
    shared: &Arc<Shared>,
    deposit: frasil_deposit_tokens::TokenDeposit,
    source: &str,
    now: Reading,
) -> Result<[u8; 16], Reason> {
    let limit = shared.settings.deposit_tokens.refused_per_minute;
    if !lock(&shared.core.refused_tokens).below(source, now.timeline, limit) {
        return Err(("rate_limited".into(), 429));
    }
    let answer = match shared.cluster.get() {
        Some(cluster) if !shared.core.keeps_address("mailboxes", &deposit.address) => {
            let request = MailboxRequest::TokenPut {
                epoch: cluster.epoch(),
                address: deposit.address,
                item: deposit.item.clone(),
                token: deposit.token.as_bytes().to_vec(),
            };
            match cluster
                .mailbox_remote("mailboxes", &deposit.address, request)
                .await
            {
                Ok(MailboxAnswer::Put(id)) => Ok(id),
                Ok(_) => Err(("busy".into(), 503)),
                Err(refused) => Err(refused),
            }
        }
        _ => shared
            .core
            .token_put(&deposit, now)
            .await
            .map_err(crate::deposit::reason),
    };
    if let Err((code, _)) = &answer
        && matches!(
            code.as_str(),
            "token_refused" | "token_expired" | "token_spent" | "unsupported_version"
        )
    {
        lock(&shared.core.refused_tokens).admit(source, now.timeline, usize::MAX);
    }
    answer
}

/// A collection, at the node that keeps the mailbox.
pub(crate) async fn mailbox_get(
    shared: &Arc<Shared>,
    kind: Kind,
    address: &[u8; 32],
    after: Option<[u8; 16]>,
    collector: Option<([u8; 64], Vec<u8>, [u8; 32])>,
    now: Reading,
) -> Result<Items, Reason> {
    if kind == Kind::Drop
        && shared.settings.extensions.invite_links
        && let Some(cluster) = shared.cluster.get()
    {
        return cluster.drop_get(address, after).await;
    }
    if let Some(cluster) = shared.cluster.get()
        && let Some(family) = family_of(kind)
        && !shared.core.keeps_address(family, address)
    {
        let request = MailboxRequest::Get {
            epoch: cluster.epoch(),
            kind: kind.code(),
            address: *address,
            after,
            collector,
        };
        return match cluster.mailbox_remote(family, address, request).await? {
            MailboxAnswer::Items(items) => Ok(items),
            _ => Err(("busy".into(), 503)),
        };
    }
    let collector = collector
        .as_ref()
        .map(|(key, signature, binding)| (key, signature.as_slice(), binding));
    shared
        .core
        .mailbox_get(kind, address, after.as_ref(), collector, now)
}

impl Owners {
    /// How many connections forwarded here have part of an answer left,
    /// for tests.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        let sessions: Vec<_> = lock(&self.sessions).values().cloned().collect();
        sessions
            .iter()
            .filter(|session| {
                session
                    .try_lock()
                    .map_or(true, |session| session.pending.is_some())
            })
            .count()
    }

    /// Notes that a connection's gateway named it.
    fn heard(&self, name: LinkName) {
        lock(&self.heard).insert(name, Instant::now());
    }

    /// A gateway's digest of its live connections that reach this owner:
    /// they are heard, and its connections of other runs go.
    fn live(&self, from: NodeId, run: u64, links: &[u64]) {
        let now = Instant::now();
        {
            let mut heard = lock(&self.heard);
            for &link in links {
                heard.insert(
                    LinkName {
                        node: from,
                        run,
                        link,
                    },
                    now,
                );
            }
        }
        lock(&self.sessions).retain(|name, _| name.node != from || name.run == run);
    }

    /// Forgets the connections no gateway named for `quiet`: their gateway
    /// is gone, or could not tell this owner they closed.
    fn expire(&self, quiet: Duration) {
        let mut heard = lock(&self.heard);
        heard.retain(|_, at| at.elapsed() < quiet);
        lock(&self.sessions).retain(|name, _| heard.contains_key(name));
    }

    /// The connection a forward names, made the first time.
    fn session(
        &self,
        cluster: &Arc<Cluster>,
        from: NodeId,
        forward: &Forward,
        shared: &Arc<Shared>,
    ) -> Arc<tokio::sync::Mutex<Owned>> {
        lock(&self.heard).insert(forward.link, Instant::now());
        let mut sessions = lock(&self.sessions);
        // A gateway started again names none of its old connections.
        sessions.retain(|name, _| name.node != forward.link.node || name.run == forward.link.run);
        sessions
            .entry(forward.link)
            .or_insert_with(|| {
                let (tx, mut rx) = tokio::sync::mpsc::channel(crate::session::QUEUE);
                let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let link = shared.core.link_forwarded(tx, queued.clone());
                let name = forward.link;
                let weak: Weak<Cluster> = Arc::downgrade(cluster);
                let task = tokio::spawn(async move {
                    while let Some(out) = rx.recv().await {
                        crate::state::dequeued(&queued, &out);
                        let Some(cluster) = weak.upgrade() else {
                            return;
                        };
                        let Some(out) = to_wire(out) else {
                            continue;
                        };
                        if from == cluster.me {
                            cluster.deliver_here(name, out);
                        } else {
                            let body = Deliver { link: name, out }.encode();
                            let _ = cluster.links.notify(from, wire::DELIVER, body).await;
                        }
                    }
                });
                Arc::new(tokio::sync::Mutex::new(Owned {
                    space: SpaceSession {
                        shared: shared.clone(),
                        link,
                        binding: forward.binding,
                        purpose: purpose_of(forward.purpose),
                        grants: BTreeMap::new(),
                    },
                    seen: BTreeSet::new(),
                    forward: task,
                    retired: false,
                    pending: None,
                }))
            })
            .clone()
    }

    /// Forgets a connection that holds no grant here, as one whose only
    /// present was refused: its session, with what the core keeps of it,
    /// and when it was heard. `session` is `handle`'s, locked.
    ///
    /// The session's lock is held throughout, and the maps' are taken
    /// inside it, never the other way round, as everywhere: so no forward
    /// on the connection runs on it meanwhile. One that took `handle` out
    /// of the map before and waits for its lock finds it retired, and asks
    /// the map again, which then makes a new one. `heard` is locked before
    /// `sessions`, as [`Self::expire`] does, and both are held while the
    /// connection goes, so that no session made after loses its entry.
    fn retire_unless_granted(
        &self,
        name: LinkName,
        handle: &Arc<tokio::sync::Mutex<Owned>>,
        session: &mut Owned,
    ) {
        if session
            .space
            .grants
            .values()
            .any(crate::state::Grant::holds)
        {
            return;
        }
        session.retired = true;
        let mut heard = lock(&self.heard);
        let mut sessions = lock(&self.sessions);
        if sessions
            .get(&name)
            .is_some_and(|kept| Arc::ptr_eq(kept, handle))
        {
            // The connection's `Owned` drops here only if no other forward
            // holds it; one that does finds it retired.
            sessions.remove(&name);
            heard.remove(&name);
        }
    }

    /// A gateway's connection closed, or left one space here.
    fn closed(&self, name: LinkName, space: Option<[u8; 32]>) {
        match space {
            None => {
                lock(&self.sessions).remove(&name);
            }
            Some(space) => {
                let Some(session) = lock(&self.sessions).get(&name).cloned() else {
                    return;
                };
                tokio::spawn(async move {
                    let mut session = session.lock().await;
                    session.seen.remove(&space);
                    session.space.leave(&EventId(space));
                });
            }
        }
    }

    /// After an epoch: every connection leaves here the spaces whose
    /// shards this node no longer owns, and the connections of gateways
    /// that are no members go.
    pub(crate) fn forget_lost(&self, cluster: &Arc<Cluster>) {
        let members = cluster.membership();
        let sessions: Vec<(LinkName, Arc<tokio::sync::Mutex<Owned>>)> = {
            let mut sessions = lock(&self.sessions);
            sessions.retain(|name, _| members.nodes.contains_key(&name.node));
            sessions.iter().map(|(n, s)| (*n, s.clone())).collect()
        };
        let Some(shards) = cluster.shards().cloned() else {
            return;
        };
        for (_, session) in sessions {
            let cluster = cluster.clone();
            let shards = shards.clone();
            tokio::spawn(async move {
                let mut session = session.lock().await;
                let lost: Vec<[u8; 32]> = session
                    .seen
                    .iter()
                    .filter(|space| {
                        cluster.owner(&shards.space_shard_of(space)) != Some(cluster.me)
                    })
                    .copied()
                    .collect();
                for space in lost {
                    session.seen.remove(&space);
                    session.space.leave(&EventId(space));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An owner's ask that a forwarded connection reconnect, once its live
    /// delivery ended there (peers.md, 3.6 Retirement and the cap,
    /// "Connections"), crosses to the gateway, which closes the device's
    /// connection as its own.
    #[test]
    fn an_ask_to_reconnect_crosses_to_the_gateway() {
        let out = to_wire(Outgoing::Reconnect).expect("it crosses");
        assert_eq!(out, Out::Reconnect);
        let deliver = Deliver {
            link: LinkName {
                node: 1,
                run: 2,
                link: 3,
            },
            out,
        };
        let read = Deliver::decode(&deliver.encode()).expect("it reads");
        assert_eq!(from_wire(read.out), Some(Outgoing::Reconnect));
    }

    /// An object transfer larger than a part of a forwarded answer is
    /// divided into transfers that each fit, its chunks in order; the
    /// messages around it stay as they are.
    #[test]
    fn a_large_object_transfer_crosses_in_parts() {
        let space = EventId([5; 32]);
        let chunks: Vec<Vec<u8>> = (0..64u8)
            .map(|n| vec![n; frasil_units::limits::MAX_MESSAGE_BYTES])
            .collect();
        let parts = in_parts(vec![
            Outgoing::Control(vec![1]),
            Outgoing::Object(space, chunks.clone()),
            Outgoing::Sync(space, vec![2]),
        ]);
        assert_eq!(parts.front(), Some(&Outgoing::Control(vec![1])));
        assert_eq!(parts.back(), Some(&Outgoing::Sync(space, vec![2])));
        let mut again = Vec::new();
        for part in parts.iter().skip(1).take(parts.len() - 2) {
            let Outgoing::Object(of, messages) = part else {
                panic!("an object transfer");
            };
            assert_eq!(*of, space);
            assert!(crate::state::queued_size(part) <= PART_BYTES || messages.len() == 1);
            again.extend(messages.iter().cloned());
        }
        assert!(parts.len() > 3, "divided");
        assert_eq!(again, chunks, "every chunk, in order");
    }

    /// A message as a device sends it.
    fn message(bytes: &[u8]) -> Message {
        crate::server::read(bytes, crate::Extensions::NONE)
            .expect("it reads")
            .expect("a message")
    }

    /// The reason code of a refusal.
    fn refused_code(out: &[Outgoing]) -> Option<String> {
        match out {
            [Outgoing::Control(bytes)] => {
                frasil_transport::messages::Refused::read(&message(bytes))
                    .ok()
                    .map(|refused| refused.code)
            }
            _ => None,
        }
    }

    /// A stranger's present for a space the peer does not host, and its
    /// `Subscribe` and `Heads` there, leave no route, no heads and no
    /// session behind: the present reaches the owner once, and is refused
    /// at the gateway after that until the time it is remembered passes;
    /// the rest never reaches it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_strangers_messages_for_unknown_spaces_leave_no_route_state() {
        use crate::testing::cluster::{TIMING, TestCluster};
        use frasil_units::messages::Message as Unit;
        let cluster = TestCluster::start(2, TIMING, 0x65)
            .await
            .expect("two nodes form a cluster");
        let gateway = cluster.node(0).cluster.clone();
        let served = || -> u64 {
            cluster
                .nodes
                .iter()
                .flatten()
                .map(|node| node.cluster.owners.served.load(Ordering::SeqCst))
                .sum()
        };
        let connection = Connection {
            link: 1 << 40,
            binding: [7; 32],
            purpose: Purpose::SpaceTraffic,
            server: false,
            source: "192.0.2.1".into(),
        };
        let space = [0x65; 32];
        let present = |request: u64| {
            message(
                &frasil_transport::messages::Present {
                    request,
                    space,
                    credential: 1,
                    public: vec![1; 32],
                    proof: vec![2; 64],
                }
                .encode(),
            )
        };
        let before = served();
        for request in 1..=5 {
            let out = gateway
                .forward(&connection, space, None, &present(request), None)
                .await
                .expect("answered")
                .out;
            assert_eq!(refused_code(&out).as_deref(), Some("no_library"));
        }
        assert_eq!(served() - before, 1, "the owner was reached once");
        let subscribe = message(&crate::state::sync(
            EventId(space),
            Unit::Subscribe {
                streams: Vec::new(),
            },
        ));
        let heads = message(&crate::state::sync(
            EventId(space),
            Unit::Heads {
                heads: (0..frasil_units::limits::MAX_MESSAGE_ITEMS)
                    .map(|n| {
                        let mut id = [0u8; 32];
                        id[..8].copy_from_slice(&(n as u64).to_be_bytes());
                        EventId(id)
                    })
                    .collect(),
                vector: None,
                streams: Vec::new(),
            },
        ));
        for other in [&subscribe, &heads] {
            let out = gateway
                .forward(&connection, space, None, other, None)
                .await
                .expect("answered")
                .out;
            assert!(out.is_empty());
        }
        assert_eq!(served() - before, 1, "nothing else reached an owner");
        assert!(lock(&gateway.gateway.links).is_empty(), "no route");
        assert!(lock(&gateway.gateway.held).is_empty(), "no heads");
        assert!(!gateway.holding(connection.link));
        for node in cluster.nodes.iter().flatten() {
            assert!(
                lock(&node.cluster.owners.sessions).is_empty(),
                "the refused present left no session at its owner"
            );
        }
        // Once the time passes, the next present reaches the owner again.
        tokio::time::sleep(UNKNOWN_FOR + Duration::from_millis(100)).await;
        let out = gateway
            .forward(&connection, space, None, &present(6), None)
            .await
            .expect("answered")
            .out;
        assert_eq!(refused_code(&out).as_deref(), Some("no_library"));
        assert_eq!(served() - before, 2);
        assert!(lock(&gateway.gateway.links).is_empty(), "no route");
        cluster.shutdown().await;
    }

    /// A request of a space the connection holds no grant in is refused at
    /// the gateway, an event of it is refused `not_authorized`, and only a
    /// genesis of the space goes on, as a create.
    #[test]
    fn what_a_connection_with_no_grant_sends_is_answered_at_the_gateway() {
        let space = [3; 32];
        let merge = message(
            &frasil_transport::messages::Merge {
                request: 4,
                // An empty map: a `Merge` carries a map.
                statement: vec![0xa0],
            }
            .encode()
            .expect("a merge"),
        );
        match without_grant(&merge, &space, Purpose::SpaceTraffic) {
            Ok(WithoutGrant::Answer(out)) => {
                assert_eq!(refused_code(&out).as_deref(), Some("credential_refused"));
            }
            _ => panic!("a request is answered at the gateway"),
        }
        let present = message(
            &frasil_transport::messages::Present {
                request: 1,
                space,
                credential: 1,
                public: vec![1; 32],
                proof: vec![2; 64],
            }
            .encode(),
        );
        assert!(matches!(
            without_grant(&present, &space, Purpose::SpaceTraffic),
            Ok(WithoutGrant::Goes { create: false })
        ));
        let elsewhere = message(&crate::state::sync(
            EventId([4; 32]),
            frasil_units::messages::Message::Subscribe {
                streams: Vec::new(),
            },
        ));
        assert!(
            without_grant(&elsewhere, &space, Purpose::SpaceTraffic).is_err(),
            "another space's unit"
        );
        // A genesis goes on as a create, except on an administration
        // connection, where it is refused as the owner refuses it.
        let events = crate::session::tests::history();
        let genesis = &events[0].1;
        let created = crate::session::tests::id_of(genesis);
        let store = message(&crate::state::sync(
            created,
            frasil_units::messages::Message::Events {
                events: vec![genesis.clone()],
            },
        ));
        assert!(matches!(
            without_grant(&store, created.as_bytes(), Purpose::SpaceTraffic),
            Ok(WithoutGrant::Goes { create: true })
        ));
        match without_grant(&store, created.as_bytes(), Purpose::Administration) {
            Ok(WithoutGrant::Answer(out)) => {
                let [Outgoing::Control(bytes)] = out.as_slice() else {
                    panic!("one refusal");
                };
                let refused =
                    frasil_transport::messages::EventRefused::read(&message(bytes)).expect("read");
                assert_eq!(refused.code, "purpose_violation");
            }
            _ => panic!("answered at the gateway"),
        }
        // A hold is refused by the class its procedure checks first.
        let hold =
            frasil_libraries::HoldObject::prove(3, &[1; 32], space, [2; 32], [4; 64], &[5; 32]);
        let libraries = crate::Extensions {
            libraries: true,
            ..crate::Extensions::NONE
        };
        let hold = crate::server::read(&hold.encode(), libraries)
            .expect("it reads")
            .expect("a message");
        match without_grant(&hold, &space, Purpose::SpaceTraffic) {
            Ok(WithoutGrant::Answer(out)) => {
                assert_eq!(refused_code(&out).as_deref(), Some("not_authorized"));
            }
            _ => panic!("answered at the gateway"),
        }
    }

    /// The heads follow the events a connection holds, and while it moves
    /// an event delivered twice goes once.
    #[test]
    fn held_events_keep_heads_and_pass_over_repeats_while_moving() {
        let (a, b, c) = (EventId([1; 32]), EventId([2; 32]), EventId([3; 32]));
        let mut held = Held::default();
        assert!(held.note(a, &[], true));
        assert!(held.note(b, &[a], true));
        assert!(held.note(b, &[a], true), "not moving: nothing is counted");
        assert_eq!(held.heads.iter().copied().collect::<Vec<_>>(), vec![b]);
        held.moving = Some(Instant::now() + Duration::from_secs(60));
        assert!(held.note(c, &[b], true));
        assert!(!held.note(c, &[b], true), "a repeat while moving");
        assert!(
            held.note(c, &[b], false),
            "what the device sent is no delivery"
        );
        assert_eq!(held.heads.iter().copied().collect::<Vec<_>>(), vec![c]);
        held.moving = Some(Instant::now());
        assert!(held.note(c, &[b], true), "the move is over");
        assert!(held.seen.is_empty());
    }
}
