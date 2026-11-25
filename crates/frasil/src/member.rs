//! Member connections over the iroh binding (transport.md, sections 3.2 to
//! 3.9 and 3.16).
//!
//! [`run_member`] drives one side of one `frasil/p1/member` connection
//! until it closes:
//!
//! 1. **The handshake**, by `frasil-transport`'s [`MemberSession`] on the
//!    control stream: the dialer offers the states it holds of a space,
//!    the responder matches them against its candidates, both bind their
//!    Ed25519 keys and keys commitments with `Identify`, which give each
//!    side's device ID, and each runs the roster check on that device ID
//!    against its own current view, which admits, detaches or starts probation.
//!    Further spaces attach on the same connection: once the other device
//!    has identified itself, each side offers every other space it holds
//!    that the other device reaches in its own view, and again as its
//!    spaces and their rosters change (transport.md, "Further attaches").
//! 2. **Sync** on each attach's sync stream, opened by the attach's
//!    initiator: [`SyncSession`] behind the device, every message a
//!    `Sync` frame scoped by the attach. A side serves nothing before it
//!    admits the other, and only catch-up during probation.
//! 3. **Live delivery and the re-check**: every event the device places
//!    in an attached space goes to the other side, space events first, and
//!    every change of the device's view runs the roster check again, which
//!    detaches a device that is out.
//! 4. **Objects**: once a side admits the other for a space, it announces
//!    the objects it holds whole in `ObjectHave`, and the other asks for
//!    those it lacks; answers travel on object streams, one per transfer
//!    (units.md, "Sync", objects).
//! 5. **Welcomes**: a welcome waiting for the other device, such as one for
//!    a space that grants its person, goes over as an item of its device
//!    mailbox; the other side follows the space and attaches it on the
//!    same connection (admission.md, "Welcomes"; transport.md,
//!    "Mailboxes").
//! 6. **Member addresses**: once both sides admitted each other for a
//!    space, each tells the other where the space's other members are, in
//!    `Addresses`, and dials the members the other lists (transport.md,
//!    "The iroh binding", member addresses).
//! 7. **Next endpoints**, with `ext-next-endpoints`: on the same attaches,
//!    each side tells the other the member endpoint key it takes at its
//!    next rotation, in `NextEndpoint`, and keeps the one the other sends
//!    (ext-next-endpoints.md, "Announcing" and "Receiving").

use crate::device::{Engine, Notice};
use crate::error::{Error, Result};
use crate::outbox::Acknowledger;
use crate::sync::SyncSession;
use frasil_admission::welcome::Welcome;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_iroh::{Connection, FrameReceiver, FrameSender, Role, Stream};
use frasil_keys::RotationSet;
use frasil_transport::addresses::{Addresses, Known, Outcome, Receiver, judge};
use frasil_transport::frame::{ConnectionKind, Message, MessageType};
use frasil_transport::mailbox::{self, Kind as MailboxKind, MailboxPut};
use frasil_transport::member::OFFER_TAGS;
use frasil_transport::messages::{Scope, Sync};
use frasil_transport::roster::{Probation, SELF_REMOVED, Serving, Standing, Verdict, check};
use frasil_transport::session::{Event, MemberSession};
use frasil_transport::ticket::Ticket;
use frasil_transport::{Closed, Code};
use frasil_units::messages::Message as UnitMessage;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

/// What a session's attach holds: the space and the proof state.
type Attached = (EventId, RotationSet);

/// Something one of the connection's readers received.
enum Incoming {
    /// A message of the control stream, or its end.
    Control(std::result::Result<Option<Message>, frasil_iroh::Error>),
    /// A stream the other side opened.
    Stream(std::result::Result<Stream, frasil_iroh::Error>),
    /// A message of an attach's sync stream, or its end.
    Sync(
        u32,
        std::result::Result<Option<Message>, frasil_iroh::Error>,
    ),
    /// An `Ephemeral` message, from a datagram or an ephemeral stream.
    #[cfg_attr(not(feature = "ephemeral"), allow(dead_code))]
    Ephemeral(Message),
}

/// Frames this device sends on the ephemeral channel, by space.
#[cfg(feature = "ephemeral")]
type Outgoing = broadcast::Receiver<(EventId, Vec<u8>)>;
#[cfg(not(feature = "ephemeral"))]
type Outgoing = ();

async fn outgoing_next(outgoing: &mut Outgoing) -> (EventId, Vec<u8>) {
    #[cfg(feature = "ephemeral")]
    loop {
        match outgoing.recv().await {
            Ok(frame) => return frame,
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(feature = "ephemeral"))]
    {
        let () = *outgoing;
        std::future::pending().await
    }
}

/// Reads `Ephemeral` messages from the connection's datagrams.
#[cfg(feature = "ephemeral")]
fn spawn_datagrams(connection: Arc<Connection>, incoming: mpsc::UnboundedSender<Incoming>) {
    tokio::spawn(async move {
        while let Ok(message) = connection.receive_datagram().await {
            if incoming.send(Incoming::Ephemeral(message)).is_err() {
                return;
            }
        }
    });
}

/// The channel starts on an attach both sides have sent `Admit` for: this
/// device's receiver nonce, and its live ephemeral slots for the other side
/// (ext-ephemeral.md, "Sending", "Freshness across restarts").
#[cfg(feature = "ephemeral")]
async fn start_ephemeral(device: &Engine, space: EventId) {
    let _ = device.start_receiving(space).await;
    let _ = device.republish_slots(space, true).await;
}

/// Reads an ephemeral stream's `Ephemeral` messages.
#[cfg(feature = "ephemeral")]
fn spawn_ephemeral(mut receiver: FrameReceiver, incoming: mpsc::UnboundedSender<Incoming>) {
    tokio::spawn(async move {
        while let Ok(Some(message)) = receiver.receive().await {
            if incoming.send(Incoming::Ephemeral(message)).is_err() {
                return;
            }
        }
    });
}

/// This side's view of the other device on one attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    /// The roster check has not run.
    Pending,
    /// The other device is in probation since this instant.
    Probation(Probation),
    /// This side admitted the other.
    Admitted,
}

/// The most messages of a sync stream an attach keeps until this side's
/// roster check has run.
const EARLY_MESSAGES: usize = 16;
/// The most bytes those messages hold together: room for heads, a head
/// statement and what the device has, and not for a part of an object,
/// which a device that never identifies itself could otherwise have every
/// attach hold.
const EARLY_BYTES: usize = 64 * 1024;

/// One attach of the connection.
struct Attach {
    space: EventId,
    sync: SyncSession,
    sender: Option<FrameSender>,
    queued: Vec<Vec<u8>>,
    /// What the sync stream carried before this side's roster check ran,
    /// taken once it has. The control stream and the sync stream are read
    /// apart, so the other side's first messages can come before its
    /// `Identify` is read.
    early: Vec<Message>,
    local: Local,
    started: bool,
    offers: usize,
    /// When this side last sent its head statement, and its heads then.
    stated: Option<(Instant, Vec<EventId>)>,
    /// The other side sent `Admit` for the attach.
    remote_admitted: bool,
    /// What this side last listed in `Addresses` on the attach.
    shared: Shared,
    /// The next key this side last announced on the attach.
    #[cfg(feature = "ext-next-endpoints")]
    announced: Option<[u8; 32]>,
}

/// What a side last listed in `Addresses` on an attach.
#[derive(Default)]
struct Shared {
    /// The links' version the list was last made at.
    version: Option<u64>,
    /// When the last `Addresses` went.
    at: Option<Instant>,
    /// What it listed.
    sent: Vec<(DeviceId, Ticket)>,
}

impl Attach {
    fn new(space: EventId, offers: usize) -> Self {
        Self {
            space,
            sync: SyncSession::new(space),
            sender: None,
            queued: Vec::new(),
            early: Vec::new(),
            local: Local::Pending,
            started: false,
            offers,
            stated: None,
            remote_admitted: false,
            shared: Shared::default(),
            #[cfg(feature = "ext-next-endpoints")]
            announced: None,
        }
    }
}

/// One side of one member connection.
struct Driver {
    device: Engine,
    connection: Arc<Connection>,
    session: MemberSession<Attached>,
    control: FrameSender,
    attaches: BTreeMap<u32, Attach>,
    /// Spaces this side still means to attach, after attach 0.
    to_offer: Vec<EventId>,
    /// The spaces the other side refused or detached on this connection:
    /// this side does not offer them again of its own accord. The other
    /// side offers one once its own view admits it.
    declined: BTreeSet<EventId>,
    /// The device's spaces or their rosters may have changed since this
    /// side last looked for spaces it shares with the other device.
    shared_due: bool,
    incoming: mpsc::UnboundedSender<Incoming>,
    opened: Instant,
    started: Instant,
    /// The spaces whose welcomes this connection handed over.
    handed: BTreeSet<EventId>,
    /// The admitted attaches the device's links count, with their spaces.
    counted: BTreeMap<u32, (EventId, Option<DeviceId>)>,
    /// The admitted attaches whose member the links count as reached, with
    /// their tokens.
    reached: BTreeMap<u32, u64>,
    /// The device's number for this connection, which names what it
    /// delivered on the ephemeral channel (ext-ephemeral.md, "Relaying").
    #[cfg(feature = "ephemeral")]
    ephemeral_connection: u64,
}

/// Further spaces to attach on a connection, as its node learns of them,
/// such as from a local announcement (transport.md, "Member
/// announcements").
pub type Further = mpsc::UnboundedReceiver<EventId>;

/// Of a sync message from a device this side has not admitted for the
/// attach, what it takes: during probation the verifier fetches from the
/// device and judges what it receives by its own rules (transport.md, "The
/// roster check"), so it takes the device's `Heads`, `Want` and `Events`,
/// and of a `Missing` the IDs it names. Everything else rests on trust in
/// the sender and waits for `Admit`: an `Ack`, which counts toward
/// durability (units.md, "Heads, acknowledgements and durability"); object
/// chunks and announcements; a space snapshot; and the stubs' carriers of
/// a `Missing`.
fn taken_before_admission(
    message: frasil_units::messages::SyncMessage,
) -> Option<frasil_units::messages::SyncMessage> {
    match message.message {
        UnitMessage::Heads { .. } | UnitMessage::Want { .. } | UnitMessage::Events { .. } => {
            Some(message)
        }
        UnitMessage::Missing { ids, .. } if !ids.is_empty() => {
            Some(frasil_units::messages::SyncMessage {
                space: message.space,
                message: UnitMessage::Missing {
                    ids,
                    carried: Vec::new(),
                },
            })
        }
        _ => None,
    }
}

async fn further_next(further: &mut Option<Further>) -> EventId {
    if let Some(receiver) = further {
        if let Some(space) = receiver.recv().await {
            return space;
        }
        *further = None;
    }
    std::future::pending().await
}

impl Drop for Driver {
    fn drop(&mut self) {
        let mut links = self.device.links();
        for (space, remote) in self.counted.values() {
            links.detach(space, *remote);
        }
        for token in self.reached.values() {
            links.unreach(*token);
        }
    }
}

fn random<const N: usize>(device: &Engine) -> Result<[u8; N]> {
    device.platform().nonce::<N>()
}

fn fillers(device: &Engine) -> Result<[[u8; 32]; OFFER_TAGS]> {
    let mut out = [[0u8; 32]; OFFER_TAGS];
    for filler in &mut out {
        *filler = random(device)?;
    }
    Ok(out)
}

fn connection_error(error: impl core::fmt::Display) -> Error {
    Error::Connection(error.to_string())
}

/// Runs one side of a member connection until it closes. The dialer
/// attaches `spaces` in turn, the first as attach 0; the listener answers,
/// and may attach `spaces` too once attach 0 is proved. Once the other
/// device has identified itself, each side attaches too every other space
/// the device shares with it ([`Engine::spaces_shared_with`]).
///
/// # Errors
///
/// The connection's failure, or a refusal that ends it.
pub async fn run_member(
    device: Engine,
    connection: Connection,
    spaces: Vec<EventId>,
) -> Result<()> {
    run_member_with(device, connection, spaces, None).await
}

/// [`run_member`], attaching too each space `further` names while the
/// connection runs.
///
/// # Errors
///
/// As [`run_member`].
pub async fn run_member_with(
    device: Engine,
    connection: Connection,
    spaces: Vec<EventId>,
    mut further: Option<Further>,
) -> Result<()> {
    let connection = Arc::new(connection);
    let identity_seed = device.identity_seed();
    let session: MemberSession<Attached> = connection
        .member_session(&identity_seed, *device.signer().kc())
        .map_err(connection_error)?;
    let (control, receiver) = connection.control().await.map_err(connection_error)?;
    let (incoming, mut inbox) = mpsc::unbounded_channel();
    spawn_control(receiver, incoming.clone());
    spawn_streams(connection.clone(), incoming.clone());
    #[cfg(feature = "ephemeral")]
    spawn_datagrams(connection.clone(), incoming.clone());
    #[cfg(feature = "ephemeral")]
    let mut outgoing: Outgoing = device.ephemeral_outgoing().await?;
    #[cfg(not(feature = "ephemeral"))]
    let mut outgoing: Outgoing = ();
    let mut driver = Driver {
        device: device.clone(),
        connection,
        session,
        control,
        attaches: BTreeMap::new(),
        to_offer: spaces,
        declined: BTreeSet::new(),
        shared_due: false,
        incoming,
        opened: Instant::now(),
        started: Instant::now(),
        handed: BTreeSet::new(),
        counted: BTreeMap::new(),
        reached: BTreeMap::new(),
        #[cfg(feature = "ephemeral")]
        ephemeral_connection: crate::ephemeral::ephemeral_connection(),
    };
    let ended = drive(&mut driver, &mut inbox, &mut outgoing, &mut further).await;
    // The ephemeral slot values this connection delivered go with it
    // (ext-ephemeral.md, "Relaying").
    #[cfg(feature = "ephemeral")]
    device.ephemeral_closed(driver.ephemeral_connection).await;
    ended
}

/// A member connection's traffic, until it closes.
async fn drive(
    driver: &mut Driver,
    inbox: &mut mpsc::UnboundedReceiver<Incoming>,
    outgoing: &mut Outgoing,
    further: &mut Option<Further>,
) -> Result<()> {
    let device = driver.device.clone();
    let mut notices = device.subscribe();
    if driver.connection.role() == Role::Dialer {
        driver.offer_next().await?;
    }
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    // How long chunks asked for have been awaited, every few seconds.
    let mut waited = tokio::time::interval(crate::fetch::AWAIT_TICK);
    waited.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    waited.reset();
    // The device's requests for chunks of objects, as they are made.
    let mut requests = device.fetches().follow();
    loop {
        let requested = async {
            if requests.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            () = requested => driver.on_requests().await?,
            incoming = inbox.recv() => {
                let Some(incoming) = incoming else { return Ok(()) };
                if !driver.on_incoming(incoming).await? {
                    return Ok(());
                }
            }
            notice = notices.recv() => match notice {
                Ok(notice) => driver.on_notice(notice).await?,
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    driver.shared_due = true;
                    driver.resync().await?;
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            _ = tick.tick() => {
                if !driver.on_tick().await? {
                    return Ok(());
                }
            }
            _ = waited.tick() => driver.on_waited().await?,
            (space, frame) = outgoing_next(outgoing) => {
                driver.send_ephemeral(space, frame).await;
            }
            space = further_next(further) => driver.attach_further(space).await?,
        }
    }
}

fn spawn_control(mut receiver: FrameReceiver, incoming: mpsc::UnboundedSender<Incoming>) {
    tokio::spawn(async move {
        loop {
            let message = receiver.receive().await;
            let end = !matches!(message, Ok(Some(_)));
            if incoming.send(Incoming::Control(message)).is_err() || end {
                return;
            }
        }
    });
}

fn spawn_streams(connection: Arc<Connection>, incoming: mpsc::UnboundedSender<Incoming>) {
    tokio::spawn(async move {
        loop {
            let stream = connection.accept_stream().await;
            let end = stream.is_err();
            if incoming.send(Incoming::Stream(stream)).is_err() || end {
                return;
            }
        }
    });
}

fn spawn_sync(attach: u32, mut receiver: FrameReceiver, incoming: mpsc::UnboundedSender<Incoming>) {
    tokio::spawn(async move {
        loop {
            let message = receiver.receive().await;
            let end = !matches!(message, Ok(Some(_)));
            if incoming.send(Incoming::Sync(attach, message)).is_err() || end {
                return;
            }
        }
    });
}

impl Driver {
    /// Offers the next space this side means to attach.
    async fn offer_next(&mut self) -> Result<()> {
        let mut deferred = Vec::new();
        let offered = self.offer_one(&mut deferred).await;
        // A restricted space waits for its parent's attach.
        self.to_offer.extend(deferred);
        offered
    }

    /// Whether this connection may carry a space: a restricted space only
    /// once its parent is attached on it (ext-restricted-spaces.md,
    /// "Keys of a restricted space", connections).
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(unused_variables))]
    async fn may_attach(&self, space: &EventId) -> bool {
        #[cfg(feature = "ext-restricted-spaces")]
        if let Some(parent) = self
            .device
            .read(space, crate::replica::Replica::restricted_parent)
            .await
            .ok()
            .flatten()
        {
            let attached = self
                .attaches
                .keys()
                .any(|n| self.session.state(*n).is_some_and(|(s, _)| *s == parent));
            return frasil_transport::ext_restricted_spaces::may_attach(attached);
        }
        true
    }

    async fn offer_one(&mut self, deferred: &mut Vec<EventId>) -> Result<()> {
        while let Some(space) = self.to_offer.first().copied() {
            self.to_offer.remove(0);
            // The other side attached it meanwhile.
            if self.carries(&space) {
                continue;
            }
            if !self.may_attach(&space).await {
                deferred.push(space);
                continue;
            }
            let states = self.device.offered_states(&space).await;
            if states.is_empty() {
                continue;
            }
            let offered = self.session.offer_with(
                states.into_iter().map(|(state, key)| (state, *key)),
                random(&self.device)?,
                &fillers(&self.device)?,
            );
            let (attach, events) = match offered {
                Ok(offered) => offered,
                // The session has no attach number left: the connection
                // keeps what it carries and offers no more.
                Err(frasil_transport::TransportClass::AttachLimit) => {
                    self.to_offer.clear();
                    return Ok(());
                }
                Err(class) => return Err(Error::class(class)),
            };
            self.attaches.insert(attach, Attach::new(space, 1));
            self.handle(events).await?;
            return Ok(());
        }
        Ok(())
    }

    /// Whether an attach of the connection carries a space, or an offer of
    /// this side's for it awaits its answer.
    fn carries(&self, space: &EventId) -> bool {
        self.attaches.values().any(|a| a.space == *space)
    }

    /// The spaces this side leaves out of its candidates for an offer of
    /// the other side's (transport.md, "Further attaches"): each space an
    /// attach of the connection carries, and each space this side is
    /// offering for the first time under a lower attach number. Of two
    /// offers of one space sent at the same moment, the one with the lower
    /// number is then answered and the other refused.
    fn taken(&self, offer: u32) -> BTreeSet<EventId> {
        let role = self.connection.role();
        self.attaches
            .iter()
            .filter(|(attach, state)| {
                self.session.state(**attach).is_some()
                    || (frasil_transport::member::Role::of_attach(**attach) == role
                        && **attach < offer
                        && state.offers == 1)
            })
            .map(|(_, state)| state.space)
            .collect()
    }

    /// Whether an offer of this side's awaits its answer. This side offers
    /// one space at a time, so that a restricted space follows its parent.
    fn offering(&self) -> bool {
        let role = self.connection.role();
        self.attaches.keys().any(|attach| {
            frasil_transport::member::Role::of_attach(*attach) == role
                && self.session.state(*attach).is_none()
        })
    }

    /// Means to attach every space this device shares with the other
    /// device, in its own current view, that the connection does not carry
    /// yet (transport.md, "Further attaches"): each space it holds that the
    /// other device reaches. A space the other device does not reach in
    /// this view is never offered, and neither is one the other side
    /// refused or detached on this connection. Nothing before the other
    /// side's `Identify` has verified.
    async fn offer_shared(&mut self) -> Result<()> {
        self.shared_due = false;
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        for space in self.device.spaces_shared_with(&remote).await {
            if !self.declined.contains(&space)
                && !self.to_offer.contains(&space)
                && !self.carries(&space)
            {
                self.to_offer.push(space);
            }
        }
        if !self.to_offer.is_empty() && !self.offering() {
            self.offer_next().await?;
        }
        Ok(())
    }

    /// Attaches a further space the device holds, unless the connection
    /// carries it or means to (transport.md, "Further attaches"). The
    /// listener offers once attach 0 is proved.
    async fn attach_further(&mut self, space: EventId) -> Result<()> {
        let attaching = self.to_offer.contains(&space) || self.carries(&space);
        if attaching
            || self.declined.contains(&space)
            || self.device.offered_states(&space).await.is_empty()
        {
            return Ok(());
        }
        self.to_offer.push(space);
        if self.connection.role() == Role::Dialer || self.session.state(0).is_some() {
            self.offer_next().await?;
        }
        Ok(())
    }

    /// Takes what a reader received. `false` once the connection is over.
    async fn on_incoming(&mut self, incoming: Incoming) -> Result<bool> {
        match incoming {
            Incoming::Control(Ok(Some(message))) => match self.session.receive(&message) {
                Ok(events) => self.handle(events).await,
                Err(closed) => {
                    self.connection.close(closed.code);
                    Ok(false)
                }
            },
            Incoming::Control(_) => Ok(false),
            Incoming::Stream(Ok(Stream::Sync {
                scope: Scope::Attach(attach),
                sender,
                receiver,
            })) => {
                let Ok(attach) = u32::try_from(attach) else {
                    self.connection.close(Code::Malformed);
                    return Ok(false);
                };
                spawn_sync(attach, receiver, self.incoming.clone());
                if let Some(state) = self.attaches.get_mut(&attach) {
                    state.sender = Some(sender);
                    self.flush(attach).await?;
                }
                Ok(true)
            }
            #[cfg(feature = "ephemeral")]
            Incoming::Stream(Ok(Stream::Ephemeral { receiver })) => {
                spawn_ephemeral(receiver, self.incoming.clone());
                Ok(true)
            }
            // One object transfer: its `Sync` messages go to the attach.
            Incoming::Stream(Ok(Stream::Object {
                scope: Scope::Attach(attach),
                receiver,
            })) => {
                let Ok(attach) = u32::try_from(attach) else {
                    self.connection.close(Code::Malformed);
                    return Ok(false);
                };
                spawn_sync(attach, receiver, self.incoming.clone());
                Ok(true)
            }
            Incoming::Stream(Ok(_)) => Ok(true),
            Incoming::Ephemeral(message) => {
                self.on_ephemeral(&message).await;
                Ok(true)
            }
            Incoming::Stream(Err(_)) => Ok(true),
            Incoming::Sync(attach, Ok(Some(message))) => {
                self.on_sync(attach, &message).await?;
                Ok(true)
            }
            Incoming::Sync(_, _) => Ok(true),
        }
    }

    async fn handle(&mut self, events: Vec<Event>) -> Result<bool> {
        let mut pending = events;
        while !pending.is_empty() {
            for event in std::mem::take(&mut pending) {
                match event {
                    Event::Send(message) => {
                        self.control
                            .send(&message)
                            .await
                            .map_err(connection_error)?;
                    }
                    Event::OfferReceived { attach } => {
                        // A space is attached once on a connection.
                        let taken = self.taken(attach);
                        let candidates = self.device.candidate_states().await;
                        let events = self
                            .session
                            .respond_with(
                                attach,
                                candidates
                                    .into_iter()
                                    .filter(|((space, _), _)| !taken.contains(space))
                                    .map(|(state, key)| (state, *key)),
                                random(&self.device)?,
                            )
                            .map_err(Error::class)?;
                        pending.extend(events);
                    }
                    Event::Proved { attach } => pending.extend(self.on_proved(attach).await?),
                    Event::Refused {
                        attach, may_retry, ..
                    } => {
                        // The other side's offer of the space, sent at the
                        // same moment, attached it: this offer is no longer
                        // wanted (transport.md, "Further attaches").
                        let space = self.attaches.get(&attach).map(|state| state.space);
                        let crossed = space.is_some_and(|space| {
                            self.attaches
                                .iter()
                                .any(|(other, state)| *other != attach && state.space == space)
                        });
                        if crossed {
                            self.remove_attach(attach);
                            let events = self
                                .session
                                .detach(attach, Code::Done)
                                .map_err(Error::class)?;
                            pending.extend(events);
                            Box::pin(self.offer_next()).await?;
                        } else if !self.retry(attach, may_retry).await? {
                            if let Some(space) = space {
                                self.declined.insert(space);
                            }
                            self.remove_attach(attach);
                            if attach == 0 {
                                self.connection.close(Code::Done);
                                return Ok(false);
                            }
                            // The next space in turn.
                            if frasil_transport::member::Role::of_attach(attach)
                                == self.connection.role()
                            {
                                Box::pin(self.offer_next()).await?;
                            }
                        }
                    }
                    Event::Identified { .. } => {
                        self.hand_welcomes().await?;
                        // The dialer offers the spaces it shares with the
                        // other device at once, and the listener at its
                        // next tick, which offers what the dialer's view
                        // left out: both at once would offer each space
                        // twice, for one of the two to be refused.
                        if self.connection.role() == Role::Dialer {
                            Box::pin(self.offer_shared()).await?;
                        } else {
                            self.shared_due = true;
                        }
                    }
                    Event::CheckRoster { attach, device } => {
                        pending.extend(self.check(attach, &device).await?);
                    }
                    Event::Admitted { attach } => {
                        #[cfg_attr(not(feature = "ephemeral"), allow(unused_variables))]
                        let both = self.attaches.get_mut(&attach).and_then(|state| {
                            state.remote_admitted = true;
                            (state.local == Local::Admitted).then_some(state.space)
                        });
                        #[cfg(feature = "ephemeral")]
                        if let Some(space) = both {
                            start_ephemeral(&self.device, space).await;
                        }
                        self.share(attach).await?;
                    }
                    Event::Detached { attach, .. } => {
                        let space = self.attaches.get(&attach).map(|state| state.space);
                        self.remove_attach(attach);
                        // Unless another attach still carries the space.
                        if let Some(space) = space
                            && !self.carries(&space)
                        {
                            self.declined.insert(space);
                        }
                    }
                    Event::Close(code) => {
                        self.connection.close(code);
                        return Ok(false);
                    }
                    Event::Other(message) if message.kind == MessageType::MailboxPut => {
                        self.on_mailbox_put(&message).await?;
                    }
                    Event::Other(message) if message.kind == MessageType::Addresses => {
                        if !self.on_addresses(&message).await? {
                            return Ok(false);
                        }
                    }
                    #[cfg(feature = "ext-next-endpoints")]
                    Event::Other(message) if message.kind == MessageType::NextEndpoint => {
                        if !self.on_next_endpoint(&message).await? {
                            return Ok(false);
                        }
                    }
                    Event::Other(_) => {}
                }
            }
        }
        Ok(true)
    }

    /// After a refusal: offer again with the states this side holds, while
    /// it may.
    async fn retry(&mut self, attach: u32, may_retry: bool) -> Result<bool> {
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(false);
        };
        if !may_retry || state.offers >= 4 {
            return Ok(false);
        }
        state.offers += 1;
        let space = state.space;
        let states = self.device.offered_states(&space).await;
        let events = self
            .session
            .retry_with(
                attach,
                states.into_iter().map(|(state, key)| (state, *key)),
                random(&self.device)?,
                &fillers(&self.device)?,
            )
            .map_err(Error::class)?;
        Box::pin(self.handle(events)).await
    }

    /// An attach is proved: the space is fixed. Its initiator opens the
    /// attach's sync stream.
    async fn on_proved(&mut self, attach: u32) -> Result<Vec<Event>> {
        let Some((space, _)) = self.session.state(attach).cloned() else {
            return Ok(Vec::new());
        };
        let entry = self
            .attaches
            .entry(attach)
            .or_insert_with(|| Attach::new(space, 0));
        entry.space = space;
        entry.sync = SyncSession::new(space);
        // Being made: it takes the space's requests once it has started.
        entry.sync.expect(self.device.fetches());
        let own = frasil_transport::member::Role::of_attach(attach) == self.connection.role();
        if own {
            let (sender, receiver) = self
                .connection
                .open_sync(Scope::Attach(attach.into()))
                .await
                .map_err(connection_error)?;
            spawn_sync(attach, receiver, self.incoming.clone());
            if let Some(state) = self.attaches.get_mut(&attach) {
                state.sender = Some(sender);
            }
            self.flush(attach).await?;
        }
        // The next space is offered once this side's last attach is
        // proved, so that a restricted space follows its parent.
        if attach == 0 || own {
            Box::pin(self.offer_next()).await?;
        } else {
            // A restricted space of this side's may follow the parent the
            // other side attached.
            self.shared_due = true;
        }
        Ok(Vec::new())
    }

    /// The roster check (transport.md, "The roster check"), and what
    /// follows from its outcome.
    async fn check(&mut self, attach: u32, device: &DeviceId) -> Result<Vec<Event>> {
        let Some(space) = self.attaches.get(&attach).map(|a| a.space) else {
            return Ok(Vec::new());
        };
        let standing = self.device.standing(&space, device).await;
        let now = self.opened.elapsed().as_secs();
        let verdict = match self.attaches.get(&attach).map(|a| a.local) {
            Some(Local::Probation(probation)) => match probation.decide(standing, now) {
                Some(verdict) => verdict,
                None => return Ok(Vec::new()),
            },
            _ => check(standing),
        };
        self.apply(attach, verdict).await
    }

    async fn apply(&mut self, attach: u32, verdict: Verdict) -> Result<Vec<Event>> {
        let now = self.opened.elapsed().as_secs();
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(Vec::new());
        };
        let changed = !matches!(
            (state.local, verdict),
            (Local::Admitted, Verdict::Admit) | (Local::Probation(_), Verdict::Probation)
        );
        if !changed {
            return Ok(Vec::new());
        }
        let events = self
            .session
            .verdict(attach, verdict)
            .map_err(Error::class)?;
        match verdict {
            Verdict::Admit => {
                state.local = Local::Admitted;
                state.sync.set_serving(Serving::Everything);
                // A device admitted here may reach other spaces through
                // this one.
                self.shared_due = true;
                // The channel starts once both sides have sent `Admit`;
                // the other side takes no frame before its own.
                #[cfg(feature = "ephemeral")]
                if state.remote_admitted {
                    let space = state.space;
                    start_ephemeral(&self.device, space).await;
                }
            }
            Verdict::Probation => {
                state.local = Local::Probation(Probation::start(now));
                state.sync.set_serving(Serving::CatchUp);
            }
            Verdict::Detach(code) => {
                // A member this side admitted, and so told its next key,
                // whose membership ended: that key is withdrawn
                // (ext-next-endpoints.md, "Announcing").
                #[cfg(feature = "ext-next-endpoints")]
                if state.local == Local::Admitted && code == Code::MembershipEnded {
                    self.device.withdraw_next_endpoint().await?;
                }
                #[cfg(not(feature = "ext-next-endpoints"))]
                let _ = code;
                self.remove_attach(attach);
                return Ok(events);
            }
        }
        let start = !state.started;
        state.started = true;
        if start {
            let messages = self.device.sync_start(&mut state.sync).await?;
            self.queue(attach, messages).await?;
        }
        match verdict {
            Verdict::Admit => self.admitted(attach).await?,
            _ => self.uncount(attach),
        }
        self.state_heads(attach).await?;
        // What the sync stream carried before this outcome.
        let early = self
            .attaches
            .get_mut(&attach)
            .map(|state| std::mem::take(&mut state.early))
            .unwrap_or_default();
        for message in &early {
            self.on_sync(attach, message).await?;
        }
        Ok(events)
    }

    /// This side admitted the other for an attach: the links count it, a
    /// welcome of its space no longer waits for the other device, and the
    /// objects this side holds whole are announced (units.md, "Sync",
    /// objects).
    async fn admitted(&mut self, attach: u32) -> Result<()> {
        let Some(space) = self.attaches.get(&attach).map(|a| a.space) else {
            return Ok(());
        };
        let remote = self.session.remote_device().copied();
        if self.counted.insert(attach, (space, remote)).is_some() {
            return Ok(());
        }
        {
            let mut links = self.device.links();
            links.attach(space, remote);
            if let Some(remote) = self.session.remote_device() {
                links.delivered(remote, &space);
            }
        }
        // Where the other device is, for dialing it again after a restart
        // (transport.md, "Reconnecting"), and for member addresses.
        if let Some(remote) = self.session.remote_device().copied()
            && let Some(ticket) = self
                .connection
                .remote_ticket(frasil_transport::ticket::TicketKind::Member)
        {
            let _ = self
                .device
                .remember_endpoint(&space, &remote, &ticket)
                .await;
            let token = self.device.links().reach(space, remote, ticket);
            if let Some(old) = self.reached.insert(attach, token) {
                self.device.links().unreach(old);
            }
        }
        self.share(attach).await?;
        let have = self.device.whole_objects_have(&space).await;
        self.queue(attach, have).await
    }

    /// The links stop counting an attach.
    fn uncount(&mut self, attach: u32) {
        if let Some((space, remote)) = self.counted.remove(&attach) {
            self.device.links().detach(&space, remote);
        }
        if let Some(token) = self.reached.remove(&attach) {
            self.device.links().unreach(token);
        }
    }

    /// Sends the other side this side's `Addresses` for an attach both
    /// sides admitted, when what it would list changed since it last
    /// listed, at most once per `gossip_interval`, and never an empty list
    /// (transport.md, "The iroh binding", member addresses).
    async fn share(&mut self, attach: u32) -> Result<()> {
        #[cfg(feature = "ext-next-endpoints")]
        self.announce(attach).await?;
        let version = self.device.links().version();
        let Some(state) = self.attaches.get(&attach) else {
            return Ok(());
        };
        if state.local != Local::Admitted || !state.remote_admitted {
            return Ok(());
        }
        let shared = &state.shared;
        if shared.version == Some(version)
            || shared
                .at
                .is_some_and(|at| at.elapsed() < crate::statements::gossip_interval())
        {
            return Ok(());
        }
        let space = state.space;
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        let listed = self.device.address_list(&space, &remote).await;
        let message = Addresses::fitting(attach.into(), listed);
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        state.shared.version = Some(version);
        let Some(message) = message else {
            return Ok(());
        };
        if message.entries == state.shared.sent {
            return Ok(());
        }
        state.shared.at = Some(Instant::now());
        state.shared.sent.clone_from(&message.entries);
        self.control
            .send(&message.encode())
            .await
            .map_err(connection_error)
    }

    /// An `Addresses` from the other side (transport.md, "The iroh
    /// binding", member addresses): one that does not read closes the
    /// connection; one on an attach both sides have not admitted is
    /// dropped; each entry the receiver's checks pass is held among the
    /// learned tickets and dialed, and never written to the `endpoint`
    /// table: it is kept only once a dial to it is admitted
    /// ("Reconnecting"). `false` once the connection is over.
    async fn on_addresses(&mut self, message: &Message) -> Result<bool> {
        // 1 and 2.
        let addresses = match Addresses::read(message) {
            Ok(addresses) => addresses,
            Err(class) => {
                self.connection.close(Closed::of(class).code);
                return Ok(false);
            }
        };
        // 3.
        let Some(state) = u32::try_from(addresses.attach)
            .ok()
            .and_then(|attach| self.attaches.get(&attach))
        else {
            return Ok(true);
        };
        if state.local != Local::Admitted || !state.remote_admitted {
            return Ok(true);
        }
        let space = state.space;
        let Some(sender) = self.session.remote_device().copied() else {
            return Ok(true);
        };
        let receiver = Receiver {
            device: self.device.device_id(),
            sender,
            endpoint: self.connection.local(),
        };
        // 4 to 7, for each entry in order.
        for (member, ticket) in addresses.entries {
            let reaches = matches!(
                self.device.standing(&space, &member).await,
                Standing::Reaches(_)
            );
            let known = Known {
                reaches,
                attached: self.device.links().reaches(&space, &member),
            };
            if judge(&receiver, &member, &ticket, known) == Outcome::Dial {
                self.device
                    .links()
                    .learned(space, member, ticket, Instant::now());
            }
        }
        Ok(true)
    }

    /// Tells the other side this side's next member endpoint key on an
    /// attach both sides admitted, once per key (ext-next-endpoints.md,
    /// "Announcing").
    #[cfg(feature = "ext-next-endpoints")]
    async fn announce(&mut self, attach: u32) -> Result<()> {
        let Some(key) = self.device.next_endpoint_key() else {
            return Ok(());
        };
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        if state.local != Local::Admitted || !state.remote_admitted || state.announced == Some(key)
        {
            return Ok(());
        }
        state.announced = Some(key);
        let message = frasil_transport::ext_next_endpoints::NextEndpoint {
            attach: attach.into(),
            key,
        };
        self.control
            .send(&message.encode())
            .await
            .map_err(connection_error)
    }

    /// A `NextEndpoint` from the other side (ext-next-endpoints.md,
    /// "Receiving"): one that does not read closes the connection; one on
    /// an attach both sides have not admitted, or naming the key the other
    /// side is at, is dropped; otherwise it is kept beside the ticket this
    /// side keeps of the other. `false` once the connection is over.
    #[cfg(feature = "ext-next-endpoints")]
    async fn on_next_endpoint(&mut self, message: &Message) -> Result<bool> {
        use frasil_transport::ext_next_endpoints::{NextEndpoint, Outcome, judge};
        // 1 and 2.
        let announced = match NextEndpoint::read(message, ConnectionKind::Member) {
            Ok(announced) => announced,
            Err(class) => {
                self.connection.close(Closed::of(class).code);
                return Ok(false);
            }
        };
        // 3 and 4.
        let Some(state) = u32::try_from(announced.attach)
            .ok()
            .and_then(|attach| self.attaches.get(&attach))
        else {
            return Ok(true);
        };
        let admitted = state.local == Local::Admitted && state.remote_admitted;
        let space = state.space;
        if judge(&announced, admitted, &self.connection.peer()) != Outcome::Kept {
            return Ok(true);
        }
        // 5.
        if let Some(sender) = self.session.remote_device().copied() {
            self.device
                .remember_announced(&space, &sender, announced.key)
                .await?;
        }
        Ok(true)
    }

    /// An attach is over.
    fn remove_attach(&mut self, attach: u32) {
        self.attaches.remove(&attach);
        self.uncount(attach);
    }

    /// Hands the other device the welcomes waiting for it, each once on
    /// this connection, as items of its device mailbox (transport.md,
    /// "Mailboxes"), once its `Identify` has verified.
    async fn hand_welcomes(&mut self) -> Result<()> {
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        let waiting = self.device.links().welcomes_for(&remote);
        for welcome in waiting {
            if !self.handed.insert(welcome.space) {
                continue;
            }
            let put = MailboxPut {
                request: 0,
                address: mailbox::address(MailboxKind::Device, &remote.0),
                item: welcome.sealed,
                kind: MailboxKind::Device,
            };
            self.control
                .send(&put.encode())
                .await
                .map_err(connection_error)?;
        }
        Ok(())
    }

    /// An item of this device's own mailbox, handed over by the other
    /// device. A welcome its signer hands over makes this device follow
    /// the space and attach it on this connection: the roster decides the
    /// rest (admission.md, "Welcomes"). Anything else is dropped.
    async fn on_mailbox_put(&mut self, message: &Message) -> Result<()> {
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        let me = self.device.device_id();
        let Ok(Some(put)) = MailboxPut::read(message, self.connection.extensions()) else {
            return Ok(());
        };
        if put.kind != MailboxKind::Device
            || put.address != mailbox::address(MailboxKind::Device, &me.0)
        {
            return Ok(());
        }
        let Ok(welcome) = Welcome::open(&put.item, &me, self.device.xwing_seed()) else {
            return Ok(());
        };
        if welcome.approver != remote {
            return Ok(());
        }
        let space = EventId(welcome.space);
        let held = self
            .device
            .read(&space, |replica| replica.log().is_some())
            .await
            .unwrap_or(false);
        let attaching =
            self.to_offer.contains(&space) || self.attaches.values().any(|a| a.space == space);
        if held || attaching || self.device.begin_welcomed(&welcome).await.is_err() {
            return Ok(());
        }
        self.to_offer.push(space);
        Box::pin(self.offer_next()).await
    }

    /// Sends units.md's messages on an attach's sync stream, or keeps them
    /// until the stream is open.
    async fn queue(
        &mut self,
        attach: u32,
        messages: Vec<frasil_units::messages::SyncMessage>,
    ) -> Result<()> {
        // Chunks that answer `ObjectWant` travel on an object stream of
        // their own; a snapshot's follow its `SnapshotOffer` on the sync
        // stream, so that the receiver knows their objects.
        let offers = messages
            .iter()
            .any(|m| matches!(m.message, UnitMessage::SnapshotOffer { .. }));
        let (chunks, messages): (Vec<_>, Vec<_>) = if offers {
            (Vec::new(), messages)
        } else {
            messages
                .into_iter()
                .partition(|m| matches!(m.message, UnitMessage::ObjectChunks { .. }))
        };
        if !chunks.is_empty() {
            self.send_object(attach, chunks);
        }
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        for message in messages {
            state.queued.push(
                Sync {
                    scope: Scope::Attach(attach.into()),
                    message: message.encode(),
                }
                .encode(),
            );
        }
        self.flush(attach).await
    }

    /// One object transfer, on an object stream the sender opens
    /// (transport.md, "Sync, head statements, list events and adapter
    /// sync"), sent beside the driver so that sync does not wait for it.
    fn send_object(&self, attach: u32, chunks: Vec<frasil_units::messages::SyncMessage>) {
        let connection = self.connection.clone();
        tokio::spawn(async move {
            let scope = Scope::Attach(attach.into());
            let Ok(mut sender) = connection.open_object(scope).await else {
                return;
            };
            for chunk in chunks {
                let frame = Sync {
                    scope,
                    message: chunk.encode(),
                }
                .encode();
                if sender.send(&frame).await.is_err() {
                    return;
                }
            }
            let _ = sender.finish();
        });
    }

    async fn flush(&mut self, attach: u32) -> Result<()> {
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        let Some(sender) = state.sender.as_mut() else {
            return Ok(());
        };
        for message in std::mem::take(&mut state.queued) {
            sender.send(&message).await.map_err(connection_error)?;
        }
        Ok(())
    }

    /// A message of an attach's sync stream.
    async fn on_sync(&mut self, attach: u32, message: &Message) -> Result<()> {
        if message.kind != MessageType::Sync {
            return Ok(());
        }
        let Ok(sync) = Sync::read(message, ConnectionKind::Member) else {
            self.connection.close(Code::Malformed);
            return Ok(());
        };
        if sync.scope != Scope::Attach(attach.into()) {
            self.connection.close(Code::Malformed);
            return Ok(());
        }
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        // Before the roster check: kept, and taken by its outcome's rule.
        if state.local == Local::Pending {
            let held: usize = state.early.iter().map(|early| early.bytes.len()).sum();
            if state.early.len() < EARLY_MESSAGES
                && held.saturating_add(message.bytes.len()) <= EARLY_BYTES
            {
                state.early.push(message.clone());
            }
            return Ok(());
        }
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        let Ok(Some(units_message)) = crate::intake::read_sync(&sync.message) else {
            return Ok(());
        };
        // The space a message names is the attach's (transport.md, "Sync,
        // head statements, list events and adapter sync").
        if units_message.space != state.space {
            self.connection.close(Code::Malformed);
            return Ok(());
        }
        if let frasil_units::messages::Message::Statement { statements } = &units_message.message {
            // Statements are gossip: taken from an admitted attach only.
            // The heads of the other device's statements this device lacks
            // are asked of it first (units.md, 3.13 "Head statements").
            if state.local == Local::Admitted {
                let space = state.space;
                self.device.take_statements(&space, statements).await?;
                let wants = self.device.sync_stated(&mut state.sync, &remote).await?;
                return self.queue(attach, wants).await;
            }
            return Ok(());
        }
        // Before this side admits the other, it takes only what it fetches
        // from a device in probation (transport.md, "The roster check"):
        // nothing that acts on trust in the sender, such as an
        // acknowledgement, an object or a snapshot.
        let units_message = if state.local == Local::Admitted {
            units_message
        } else {
            let Some(taken) = taken_before_admission(units_message) else {
                return Ok(());
            };
            taken
        };
        if let Local::Probation(probation) = &mut state.local
            && let frasil_units::messages::Message::Events { events } = &units_message.message
        {
            probation.received(events.len() as u64);
        }
        let replies = self
            .device
            .sync_receive(
                &mut state.sync,
                Acknowledger::Member(remote.0),
                units_message,
            )
            .await?;
        self.queue(attach, replies).await
    }

    /// The device placed events: live delivery to each attach of the
    /// space, and the re-check.
    async fn on_notice(&mut self, notice: Notice) -> Result<()> {
        self.hand_welcomes().await?;
        // Events of a space the connection does not carry, as when the
        // device joins a space or admits the other device to one: the next
        // tick looks again for spaces it shares with the other device.
        if !notice.placed.is_empty() && !self.carries(&notice.space) {
            self.shared_due = true;
        }
        let attaches: Vec<u32> = self
            .attaches
            .iter()
            .filter(|(_, a)| a.space == notice.space)
            .map(|(n, _)| *n)
            .collect();
        for attach in attaches {
            self.recheck(attach).await?;
            let Some(state) = self.attaches.get_mut(&attach) else {
                continue;
            };
            if !state.started {
                continue;
            }
            let mut messages = self
                .device
                .sync_offer(&mut state.sync, &notice.placed)
                .await?;
            if !notice.wanted.is_empty() {
                messages.extend(
                    self.device
                        .sync_want(&mut state.sync, &notice.wanted)
                        .await?,
                );
            }
            self.queue(attach, messages).await?;
            self.state_heads(attach).await?;
        }
        Ok(())
    }

    /// The device's requests for chunks changed: each attach asks the
    /// other side for those of its space made since, of objects it
    /// announced (units.md, "Sync", objects).
    async fn on_requests(&mut self) -> Result<()> {
        let attaches: Vec<u32> = self
            .attaches
            .iter()
            .filter(|(_, a)| a.started)
            .map(|(n, _)| *n)
            .collect();
        for attach in attaches {
            let Some(state) = self.attaches.get_mut(&attach) else {
                continue;
            };
            let wants = self.device.want_requests(&mut state.sync, true).await;
            self.queue(attach, wants).await?;
        }
        Ok(())
    }

    /// A few seconds passed: each attach gives up the chunks it awaited
    /// too long with no answer, and asks for what it has yet to ask for
    /// (units.md, "Sync", objects).
    async fn on_waited(&mut self) -> Result<()> {
        let attaches: Vec<u32> = self
            .attaches
            .iter()
            .filter(|(_, a)| a.started)
            .map(|(n, _)| *n)
            .collect();
        for attach in attaches {
            let Some(state) = self.attaches.get_mut(&attach) else {
                continue;
            };
            let wants = self
                .device
                .sync_waited(&mut state.sync, crate::fetch::AWAIT_TICK)
                .await;
            self.queue(attach, wants).await?;
        }
        Ok(())
    }

    /// Sends an outer frame on every admitted attach of its space, lossy
    /// (transport.md, "Priority and the lossy channel"). A frame that does
    /// not go is dropped.
    async fn send_ephemeral(&mut self, space: EventId, frame: Vec<u8>) {
        let attaches: Vec<u32> = self
            .attaches
            .iter()
            .filter(|(_, a)| a.space == space && a.local == Local::Admitted)
            .map(|(n, _)| *n)
            .collect();
        for attach in attaches {
            let message = frasil_transport::messages::Ephemeral {
                scope: Scope::Attach(attach.into()),
                frame: frame.clone(),
                origin: None,
            }
            .encode();
            let _ = self.connection.send_lossy(&message).await;
        }
    }

    /// An `Ephemeral` message from the other device: taken on an admitted
    /// attach only, and dropped when the receiver's checks refuse it.
    #[cfg_attr(not(feature = "ephemeral"), allow(clippy::unused_async))]
    async fn on_ephemeral(&mut self, message: &Message) {
        let Ok(ephemeral) =
            frasil_transport::messages::Ephemeral::read(message, ConnectionKind::Member)
        else {
            return;
        };
        let Scope::Attach(attach) = ephemeral.scope else {
            return;
        };
        let Some(state) = u32::try_from(attach)
            .ok()
            .and_then(|attach| self.attaches.get(&attach))
        else {
            return;
        };
        #[cfg(feature = "ephemeral")]
        if state.local == Local::Admitted {
            let space = state.space;
            let delivery = frasil_ephemeral::replay::Delivery {
                connection: self.ephemeral_connection,
                origin: None,
            };
            let _ = self
                .device
                .receive_ephemeral(space, &ephemeral.frame, delivery)
                .await;
        }
        #[cfg(not(feature = "ephemeral"))]
        let _ = (state, ephemeral.frame);
    }

    /// Sends this device's head statement on an admitted attach when its
    /// heads changed since the last one, at most once per
    /// `gossip_interval`.
    async fn state_heads(&mut self, attach: u32) -> Result<()> {
        let Some(state) = self.attaches.get(&attach) else {
            return Ok(());
        };
        if state.local != Local::Admitted || !state.started {
            return Ok(());
        }
        let space = state.space;
        let Ok((signed, heads)) = self.device.head_statement(&space).await else {
            return Ok(());
        };
        let Some(state) = self.attaches.get_mut(&attach) else {
            return Ok(());
        };
        let due = match &state.stated {
            None => true,
            Some((at, last)) => {
                *last != heads && at.elapsed() >= crate::statements::gossip_interval()
            }
        };
        if !due {
            return Ok(());
        }
        state.stated = Some((Instant::now(), heads));
        self.queue(
            attach,
            vec![frasil_units::messages::SyncMessage {
                space,
                message: frasil_units::messages::Message::Statement {
                    statements: vec![signed],
                },
            }],
        )
        .await
    }

    /// The re-check (transport.md, "Order on a connection, and the
    /// re-check"): a device now out is detached at once; a device that
    /// learns it was removed itself detaches every attach of the space.
    async fn recheck(&mut self, attach: u32) -> Result<()> {
        let Some(space) = self.attaches.get(&attach).map(|a| a.space) else {
            return Ok(());
        };
        // An attach not proved yet takes its verdict once proved.
        if self.session.state(attach).is_none() {
            return Ok(());
        }
        let me = self.device.device_id();
        if matches!(
            self.device.standing(&space, &me).await,
            Standing::Ended(_) | Standing::Forked
        ) {
            let events = self.apply(attach, SELF_REMOVED).await?;
            self.handle(events).await?;
            return Ok(());
        }
        let Some(remote) = self.session.remote_device().copied() else {
            return Ok(());
        };
        let events = self.check(attach, &remote).await?;
        self.handle(events).await?;
        Ok(())
    }

    /// After a lagged notice stream: offer each attach everything.
    async fn resync(&mut self) -> Result<()> {
        let attaches: Vec<u32> = self.attaches.keys().copied().collect();
        for attach in attaches {
            let Some(state) = self.attaches.get_mut(&attach) else {
                continue;
            };
            if !state.started {
                continue;
            }
            let messages = self.device.sync_start(&mut state.sync).await?;
            self.queue(attach, messages).await?;
        }
        Ok(())
    }

    /// `handshake_deadline`, and probation's bound. `false` once the
    /// connection is over.
    async fn on_tick(&mut self) -> Result<bool> {
        if let Some(closed) = self.session.deadline(self.started.elapsed().as_secs()) {
            self.connection.close(closed.code);
            return Ok(false);
        }
        let probations: Vec<u32> = self
            .attaches
            .iter()
            .filter(|(_, a)| matches!(a.local, Local::Probation(_)))
            .map(|(n, _)| *n)
            .collect();
        for attach in probations {
            self.recheck(attach).await?;
        }
        let admitted: Vec<u32> = self.attaches.keys().copied().collect();
        for attach in admitted {
            self.state_heads(attach).await?;
            self.share(attach).await?;
        }
        self.hand_welcomes().await?;
        if self.shared_due {
            self.offer_shared().await?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::taken_before_admission;
    use frasil_events::EventId;
    use frasil_units::messages::{Message, SyncMessage};

    fn taken(message: Message) -> Option<Message> {
        taken_before_admission(SyncMessage {
            space: EventId([1; 32]),
            message,
        })
        .map(|taken| taken.message)
    }

    /// transport.md, "The roster check": before it admits the other side,
    /// a side takes what it fetches, and nothing that rests on trust in
    /// the sender.
    #[test]
    fn a_side_not_admitted_is_heard_only_for_what_it_fetches() {
        let id = EventId([2; 32]);
        for message in [
            Message::Heads {
                heads: vec![id],
                vector: None,
                streams: Vec::new(),
            },
            Message::Want {
                ids: vec![id],
                ranges: Vec::new(),
                kinds: Vec::new(),
                streams: Vec::new(),
            },
            Message::Events {
                events: vec![vec![0]],
            },
        ] {
            assert_eq!(taken(message.clone()), Some(message));
        }
        // An acknowledgement does not count toward durability, and no
        // object or snapshot is kept.
        for message in [
            Message::Ack { heads: vec![id] },
            Message::ObjectChunks {
                locator: [3; 64],
                header: Some(vec![1]),
                index: 0,
                chunk: vec![0; 40],
            },
            Message::ObjectHave {
                locators: vec![[3; 64]],
                counts: None,
            },
            Message::SnapshotOffer {
                snapshot: vec![1, 2, 3],
            },
            Message::Missing {
                ids: Vec::new(),
                carried: vec![(id, EventId([4; 32]))],
            },
        ] {
            assert_eq!(taken(message), None);
        }
        // A `Missing` keeps its IDs, without the carriers it names.
        assert_eq!(
            taken(Message::Missing {
                ids: vec![id],
                carried: vec![(id, EventId([4; 32]))],
            }),
            Some(Message::Missing {
                ids: vec![id],
                carried: Vec::new(),
            })
        );
    }
}
