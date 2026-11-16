//! A device-to-peer connection, whichever binding carries it
//! (transport.md, "The device-to-peer handshake", "Presenting credentials",
//! "Mailboxes"; units.md, "Sync").
//!
//! A [`Session`] takes each message the binding read and answers with what
//! to send. The binding opens the connection, sends the `PeerHello` the
//! session made, and carries [`Outgoing`] messages: on the WebSocket all of
//! them; on iroh, control messages on the control stream and `Sync`
//! messages on the space's sync stream or an object stream.

use crate::Shared;
use crate::objects::{Layout, PIECE_BYTES, leading, piece_key};
use crate::records::ObjectRecord;
use crate::space::Locator;
use crate::state::{Bucket, Grant, Outgoing, StoreAnswer, Window, lock, refused, sync};
use crate::sync::{Answer, Reply, View};
use crate::util::log;
use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_peers::proof::Purpose;
use frasil_transport::codes::Service;
use frasil_transport::frame::{ConnectionKind, Message, MessageType};
use frasil_transport::mailbox::{Kind, MailboxGet, MailboxItems, MailboxPut};
use frasil_transport::messages::{
    Accepted, EventRefused, Merge, RegisterRecoveryEntry, Scope, Sync,
};
use frasil_transport::peer::{Checked, Limits, PeerSide};
use frasil_transport::{Channel, Closed};
use frasil_units::messages::{Message as UnitMessage, Received, SyncMessage};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::mpsc;

/// The services this peer lists: live delivery, storage and mailboxes,
/// and, with ext-libraries on, its service 5, `library`, and with
/// ext-deposit-tokens on, its service 6, `deposit`.
pub(crate) fn services(extensions: &crate::Extensions) -> Vec<Service> {
    let mut services = vec![Service::Relay, Service::Store, Service::Mailbox];
    if extensions.libraries {
        services.push(Service::Library);
    }
    if extensions.deposit_tokens {
        services.push(Service::Deposit);
    }
    services
}

/// How many messages a connection's queue holds before live delivery to it
/// is dropped: 1,024 for its sync deliveries and control messages, and room
/// for the ephemeral frames queued beside them, which never take more
/// ([`crate::state::offer`]). Its bytes are bounded too, by the operator's
/// `queued_bytes`.
pub(crate) const QUEUE: usize = 1024 + crate::state::EPHEMERAL_QUEUED;

/// A device-to-peer connection: its handshake, its presents' rate, and its
/// messages, each space's handled by a [`SpaceSession`] here or, in a
/// cluster, at the node that owns the space (crate `cluster`, module
/// `route`).
pub(crate) struct Session {
    shared: Arc<Shared>,
    link: u64,
    side: PeerSide,
    binding: Option<[u8; 32]>,
    purpose: Option<Purpose>,
    /// The server binding: grants carry transfer tokens.
    server: bool,
    presents: Window,
    /// The rate of its `Ephemeral` frames (ext-ephemeral.md, 3.7 Relaying).
    ephemeral: Bucket,
    source: String,
    /// Each space's state on this connection, when it is kept here.
    spaces: Option<SpaceSession>,
    /// The spaces a present or an attach of this connection was granted
    /// in, here or at their owners.
    granted: BTreeSet<[u8; 32]>,
    /// The rate of its messages naming a space it holds no grant in,
    /// presents aside.
    ungranted: Window,
    /// The answers it is served in batches or in parts, in order.
    answers: std::collections::VecDeque<Served>,
    /// The bytes queued for it by other procedures, not yet taken.
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

/// A failure of the session: the connection closes with this code.
pub(crate) type Failure = Closed;

/// An answer a connection is served after what it is answered at once.
enum Served {
    /// Served here in batches.
    Here(Answer),
    /// Left at the owner of a space, in a cluster, which serves it in
    /// parts (crate `cluster`, module `route`): what came of it and is not
    /// sent yet, and whether more is left there.
    Owner {
        space: [u8; 32],
        ready: std::collections::VecDeque<Outgoing>,
        more: bool,
    },
}

fn malformed() -> Failure {
    Closed::of(ErrorClass::Malformed)
}

/// What a connection's spaces hold where the spaces are kept: each space's
/// grant, and the connection as other procedures reach it. On one node it
/// is the session's own; in a cluster, the owner of a space keeps one for
/// each connection a gateway forwards it (crate `cluster`, module `route`).
pub(crate) struct SpaceSession {
    pub(crate) shared: Arc<Shared>,
    /// The connection's number at the core of this node: deliveries to it
    /// reach the device, here or through its gateway.
    pub(crate) link: u64,
    pub(crate) binding: [u8; 32],
    pub(crate) purpose: Purpose,
    pub(crate) grants: BTreeMap<EventId, Grant>,
}

/// The space a message of space traffic is about, and, for a create or an
/// import that a ticket attaches, the shard of the ticket's library: what
/// a gateway routes it by. None for a message of no one space, or one that
/// does not read.
pub(crate) fn space_of(
    message: &Message,
    extensions: &crate::Extensions,
) -> Option<([u8; 32], Option<String>)> {
    let space = match message.kind {
        MessageType::Present => {
            frasil_transport::messages::Present::read(message)
                .ok()?
                .space
        }
        MessageType::Merge => {
            let merge = Merge::read(message).ok()?;
            *frasil_peers::merge::MergeStatement::read(&merge.statement)
                .ok()?
                .space
                .as_bytes()
        }
        MessageType::RegisterRecoveryEntry => RegisterRecoveryEntry::read(message).ok()?.space,
        MessageType::Sync => match Sync::read(message, ConnectionKind::DeviceToPeer)
            .ok()?
            .scope
        {
            Scope::Space(space) => space,
            _ => return None,
        },
        MessageType::Ephemeral if extensions.ephemeral => {
            match frasil_transport::messages::Ephemeral::read(message, ConnectionKind::DeviceToPeer)
                .ok()?
                .scope
            {
                Scope::Space(space) => space,
                _ => return None,
            }
        }
        MessageType::MailboxPut if extensions.invite_links => {
            frasil_transport::ext_invite_links::DropPut::read(message)
                .ok()?
                .space
        }
        MessageType::MailboxDelete if extensions.invite_links => {
            frasil_transport::ext_invite_links::MailboxDelete::read(message)
                .ok()?
                .space
        }
        MessageType::HoldObject if extensions.libraries => {
            frasil_libraries::HoldObject::read(&message.map).ok()?.space
        }
        // ext-deposit-tokens.md: a space draw is the space's traffic, at
        // the node whose grants hold its store right; a grant draw is no
        // one space's.
        MessageType::TokenRequest if extensions.deposit_tokens => {
            message.get(5)?.as_byte_array::<32>().ok()?
        }
        MessageType::LibraryAttach if extensions.libraries => {
            use frasil_libraries::ticket::Purpose as Attach;
            let attach = frasil_libraries::attach::LibraryAttach::read(&message.map).ok()?;
            let library = match attach.purpose {
                Attach::Create | Attach::Import => {
                    frasil_libraries::ticket::SignedTicket::decode(&attach.signed)
                        .ok()
                        .map(|signed| crate::shards::library_shard(signed.ticket.library.as_str()))
                }
                // `LibraryAttach` never carries purpose 4, a deposit grant.
                Attach::Move | Attach::Deposit => None,
            };
            return Some((attach.space, library));
        }
        _ => return None,
    };
    Some((space, None))
}

impl Session {
    /// A new connection over `channel`: the session, its `PeerHello`, and
    /// the queue of what other procedures send on it. `source` names the
    /// remote end for rate limits.
    pub(crate) fn start(
        shared: Arc<Shared>,
        channel: Channel,
        server: bool,
        source: String,
    ) -> Result<(Self, Vec<u8>, mpsc::Receiver<Outgoing>), Failure> {
        let nonce = *frasil_crypto::random_bytes::<32>().map_err(|_| malformed())?;
        let limits = Limits {
            max_streams_per_space: shared.settings.max_streams_per_space,
            ..Limits::PROTOCOL
        };
        let (side, hello) = PeerSide::start_with(
            channel,
            nonce,
            &services(&shared.settings.extensions),
            &limits,
        );
        let (tx, rx) = mpsc::channel(QUEUE);
        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let link = shared.core.link_bounded(tx, queued.clone());
        if let Some(watch) = shared.watch.get() {
            watch.opened(link, &source, server, false);
        }
        Ok((
            Self {
                shared,
                link,
                side,
                binding: None,
                purpose: None,
                server,
                presents: Window::default(),
                ephemeral: Bucket::default(),
                source,
                spaces: None,
                granted: BTreeSet::new(),
                ungranted: Window::default(),
                answers: Default::default(),
                queued,
            },
            hello,
            rx,
        ))
    }

    /// Records, where a test watches, that the connection's WebSocket
    /// upgrade carried a cookie or `Authorization`.
    pub(crate) fn credentialed(&self) {
        if let Some(watch) = self.shared.watch.get() {
            watch.opened(self.link, &self.source, self.server, true);
        }
    }

    /// The binding took a message off the connection's queue to send it.
    pub(crate) fn dequeued(&self, out: &Outgoing) {
        crate::state::dequeued(&self.queued, out);
    }

    /// Whether a present of the connection was granted, or an attach
    /// accepted, in any space.
    pub(crate) fn holds_grant(&self) -> bool {
        !self.granted.is_empty()
    }

    /// Whether the device's `Hello` has arrived.
    pub(crate) fn opened(&self) -> bool {
        self.binding.is_some()
    }

    /// Whether the connection may be closed with `reconnect` now: no import
    /// is in progress on it, and no create is pending (transport.md, 3.10,
    /// "Reconnecting elsewhere"), here or at the owner of a space it
    /// reaches.
    pub(crate) fn may_reconnect(&self) -> bool {
        if let Some(cluster) = self.shared.cluster.get()
            && cluster.holding(self.link)
        {
            return false;
        }
        self.spaces.as_ref().is_none_or(|spaces| !spaces.holding())
    }

    /// The connection declined an ask to reconnect elsewhere, as an import
    /// or a create held it: it may be asked again.
    pub(crate) fn declined_reconnect(&self) {
        self.shared.core.reconnect_declined(self.link);
    }

    /// One message the binding read, of any stream.
    ///
    /// # Errors
    ///
    /// A failure that closes the connection, with its code.
    pub(crate) async fn on_message(&mut self, message: &Message) -> Result<Vec<Outgoing>, Failure> {
        if let Some(watch) = self.shared.watch.get() {
            watch.message(self.link, message);
        }
        if message.kind == MessageType::Hello {
            let binding = self.side.on_hello(message)?;
            self.binding = Some(binding);
            self.purpose = self.side.purpose();
            self.spaces = Some(SpaceSession {
                shared: self.shared.clone(),
                link: self.link,
                binding,
                purpose: self.purpose.unwrap_or(Purpose::SpaceTraffic),
                grants: BTreeMap::new(),
            });
            return Ok(Vec::new());
        }
        let Some(binding) = self.binding else {
            return Err(malformed());
        };
        let checked = self.side.on_message(message)?;
        let now = self.shared.clock.now();
        let mut token = None;
        match message.kind {
            MessageType::Present => match checked {
                Checked::Present(present) => {
                    let limit = self.shared.settings.rates.presents_per_minute;
                    if !self.presents.admit(now.timeline, 60, limit) {
                        return Ok(vec![refused(present.request, "rate_limited")]);
                    }
                    if self.server {
                        token =
                            Some(*frasil_crypto::random_bytes::<32>().map_err(|_| malformed())?);
                    }
                }
                Checked::Refuse(bytes) => return Ok(vec![Outgoing::Control(bytes)]),
                Checked::Pass => return Err(malformed()),
            },
            MessageType::MailboxPut => {
                // ext-invite-links.md's drops are a space's traffic.
                let extensions = self.shared.settings.extensions.frames();
                let put = MailboxPut::read(message, extensions)?;
                // ext-deposit-tokens.md, 3.7 Redeeming: kind 3 with key 7.
                if put.is_none()
                    && extensions.deposit_tokens
                    && message.get(6).and_then(|v| v.as_unsigned().ok()) == Some(3)
                {
                    return self.token_put(message, now).await;
                }
                if let Some(put) = put {
                    let answer = crate::cluster::route::mailbox_put(
                        &self.shared,
                        put.kind,
                        &put.address,
                        &put.item,
                        &self.source,
                        now,
                    )
                    .await;
                    return Ok(vec![match answer {
                        Ok(_) => Outgoing::Control(
                            Accepted {
                                request: put.request,
                            }
                            .encode(),
                        ),
                        Err((reason, _)) => refused(put.request, &reason),
                    }]);
                }
            }
            MessageType::MailboxGet => {
                let get = MailboxGet::read(message)?;
                // ext-invite-links.md: mailbox kind 4 reads only while the
                // extension is on.
                if get.kind == Kind::Drop && !self.shared.settings.extensions.invite_links {
                    return Err(malformed());
                }
                let collector = get
                    .collector
                    .as_ref()
                    .map(|(signer, signature)| (signer.to_bytes(), signature.clone(), binding));
                let answer = crate::cluster::route::mailbox_get(
                    &self.shared,
                    get.kind,
                    &get.address,
                    get.after,
                    collector,
                    now,
                )
                .await;
                return Ok(vec![match answer {
                    Ok(items) => Outgoing::Control(
                        MailboxItems {
                            request: get.request,
                            items,
                        }
                        .encode(),
                    ),
                    Err((reason, _)) => refused(get.request, &reason),
                }]);
            }
            MessageType::Gone | MessageType::AdapterSync | MessageType::Open => {
                return Ok(Vec::new());
            }
            // ext-ephemeral.md, 3.7 Relaying: past the connection's rate, a
            // frame is dropped unread, as the lossy channel drops any.
            MessageType::Ephemeral
                if self.shared.settings.extensions.ephemeral
                    && !self.ephemeral.admit(
                        std::time::Instant::now(),
                        self.shared.settings.rates.ephemeral_frames_per_second,
                    ) =>
            {
                return Ok(Vec::new());
            }
            // ext-deposit-tokens.md, 3.2 Learning a peer's keys. Without
            // the extension the connection closed on the unknown type.
            MessageType::TokenKeysGet if self.shared.settings.extensions.deposit_tokens => {
                return Ok(vec![self.shared.core.token_keys(&message.map, now)?]);
            }
            _ => {}
        }
        let named = space_of(message, &self.shared.settings.extensions);
        // A message naming a space the connection holds no grant in costs
        // the peer before any credential is proved: past the connection's
        // rate it is refused `rate_limited`, unread further. Presents have
        // their own rate, and ephemeral frames theirs.
        if let Some((space, _)) = &named
            && !matches!(message.kind, MessageType::Present | MessageType::Ephemeral)
            && !self.granted.contains(space)
        {
            let limit = self.shared.settings.connections.ungranted_per_minute;
            if !self.ungranted.admit(now.timeline, 60, limit) {
                return Ok(refused_each(
                    message,
                    frasil_peers::Code::RateLimited.name(),
                ));
            }
        }
        // A space's traffic: in a cluster, at the space's owner.
        let (answer, holds) = if let Some(cluster) = self.shared.cluster.get().cloned()
            && let Some((space, shard)) = named.clone()
        {
            let link = crate::cluster::route::Connection {
                link: self.link,
                binding,
                purpose: self.purpose.unwrap_or(Purpose::SpaceTraffic),
                server: self.server,
                source: self.source.clone(),
            };
            let forwarded = cluster.forward(&link, space, shard, message, token).await?;
            if forwarded.more {
                self.answers.push_back(Served::Owner {
                    space,
                    ready: Default::default(),
                    more: true,
                });
            }
            (forwarded.out, forwarded.holds)
        } else {
            let Some(spaces) = self.spaces.as_mut() else {
                return Err(malformed());
            };
            let mut answers = Vec::new();
            let answer = spaces.handle_with(message, token, &mut answers).await?;
            self.answers.extend(answers.into_iter().map(Served::Here));
            let holds = named.as_ref().map(|(space, _)| {
                spaces
                    .grants
                    .get(&EventId(*space))
                    .is_some_and(Grant::holds)
            });
            (answer, holds)
        };
        // A space the connection holds a grant in, here or at its owner, is
        // exempt from the rate of messages for spaces it holds none in,
        // and keeps an idle connection open; once its rights ended with its
        // entries, it is a stranger there again (peers.md, 3.6 Retirement
        // and the cap, "Connections").
        if let Some((space, _)) = named {
            match holds {
                Some(true) => {
                    self.granted.insert(space);
                }
                Some(false) => {
                    self.granted.remove(&space);
                }
                None => {}
            }
        }
        Ok(answer)
    }
}

impl Session {
    /// A `MailboxPut` of kind 3 with key 7 (ext-deposit-tokens.md, 3.7
    /// Redeeming): `Accepted` or `Refused`, at the node that keeps the
    /// mailbox. It counts toward no rate of anonymous deposits.
    async fn token_put(
        &self,
        message: &Message,
        now: frasil_base::time::Reading,
    ) -> Result<Vec<Outgoing>, Failure> {
        let request = message
            .get(1)
            .and_then(|v| v.as_unsigned().ok())
            .ok_or_else(malformed)?;
        let answer = match frasil_deposit_tokens::TokenDeposit::read_put(&message.map) {
            Ok(deposit) => {
                crate::cluster::route::token_put(&self.shared, deposit, &self.source, now).await
            }
            Err(class) => Err(crate::deposit::reason(class)),
        };
        Ok(vec![match answer {
            Ok(_) => Outgoing::Control(Accepted { request }.encode()),
            Err((reason, _)) => refused(request, &reason),
        }])
    }
}

impl SpaceSession {
    /// Whether an import is in progress or a create pending in any space
    /// (transport.md, 3.10, "Reconnecting elsewhere").
    pub(crate) fn holding(&self) -> bool {
        self.grants
            .values()
            .any(|grant| grant.library.in_progress())
    }

    /// Whether an import is in progress or a create pending in one space.
    pub(crate) fn holding_space(&self, space: &EventId) -> bool {
        self.grants
            .get(space)
            .is_some_and(|grant| grant.library.in_progress())
    }

    /// The next part of an answer served in batches: a batch of its events,
    /// read with the space's state held only while it is read, then what
    /// follows them; `None` once it is all served. An answer whose
    /// connection may fetch nothing now, an entry retired since, serves no
    /// more events.
    pub(crate) async fn next_batch(&mut self, answer: &mut Answer) -> Option<Outgoing> {
        let space = answer.space;
        let Some(grant) = self.grants.get_mut(&space) else {
            answer.end_events();
            return answer
                .next_after()
                .map(|message| Outgoing::Sync(space, message));
        };
        self.shared.core.rejudge(space, grant).await;
        if !(grant.rights.fetch || grant.rights.catch_up) {
            answer.end_events();
        }
        let batch = if answer.done() {
            None
        } else {
            self.shared
                .core
                .read(space, |held| answer.batch(held))
                .await
                .flatten()
        };
        match batch {
            Some((message, ids)) => {
                // Under catch-up, the parents of what was served may be
                // fetched by ID.
                if !grant.rights.fetch {
                    grant.served.extend(ids);
                }
                Some(Outgoing::Sync(space, message))
            }
            None => {
                answer.end_events();
                answer
                    .next_after()
                    .map(|message| Outgoing::Sync(space, message))
            }
        }
    }

    /// One message of a space's traffic, checked already by the connection
    /// (transport.md, 3.10, steps 1 to 7): what it is answered at once,
    /// with what it is served in batches left in `answers`, for
    /// [`Self::next_batch`] to serve as the connection takes it. `token` is
    /// the transfer token a `Present` grants on the server binding.
    ///
    /// # Errors
    ///
    /// A failure that closes the connection, with its code.
    pub(crate) async fn handle_with(
        &mut self,
        message: &Message,
        token: Option<[u8; 32]>,
        answers: &mut Vec<Answer>,
    ) -> Result<Vec<Outgoing>, Failure> {
        let now = self.shared.clock.now();
        let binding = self.binding;
        let extensions = self.shared.settings.extensions;
        // A space handed over to another peer since this connection was
        // granted in it: each later request or event is refused `moved`
        // (peers.md, 3.1 Hosting a space, "Hand-over").
        let space = (message.kind != MessageType::Present)
            .then(|| space_of(message, &self.shared.settings.extensions))
            .flatten()
            .map(|(space, _)| EventId(space));
        if let Some(space) = space
            && self.grants.get(&space).is_some_and(Grant::proved)
            && !self.shared.core.hosts(&space)
            && self.shared.core.departure_of(&space).is_some()
        {
            return Ok(refused_each(message, frasil_peers::Code::Moved.name()));
        }
        // What an entry's retirement or the space's erasure ended since the
        // grant was last judged is gone before this message uses it
        // (peers.md, 3.6 Retirement and the cap, "Connections"): it is
        // answered as one with no right.
        if let Some(space) = space
            && let Some(grant) = self.grants.get_mut(&space)
        {
            self.shared.core.rejudge(space, grant).await;
        }
        // A space the connection holds no grant in: answered as a gateway
        // in a cluster answers it, unless it may lead to a grant.
        if let Some(space) = space
            && !self.grants.contains_key(&space)
            && let WithoutGrant::Answer(out) =
                without_grant(message, space.as_bytes(), self.purpose)?
        {
            return Ok(out);
        }
        match message.kind {
            MessageType::Present => {
                let Ok(present) = frasil_transport::messages::Present::read(message) else {
                    let request = message
                        .get(1)
                        .and_then(|v| v.as_unsigned().ok())
                        .ok_or_else(malformed)?;
                    return Ok(vec![refused(request, "credential_refused")]);
                };
                let on = crate::state::On {
                    link: self.link,
                    binding,
                    purpose: self.purpose,
                    now,
                };
                let answer = self
                    .shared
                    .core
                    .present(&on, &mut self.grants, &present, token)
                    .await;
                Ok(vec![answer])
            }
            MessageType::Merge => {
                let merge = Merge::read(message)?;
                Ok(vec![
                    self.shared
                        .core
                        .merge(&self.grants, merge.request, &merge.statement, now)
                        .await,
                ])
            }
            MessageType::RegisterRecoveryEntry => {
                let register = RegisterRecoveryEntry::read(message)?;
                Ok(vec![
                    self.shared
                        .core
                        .register(
                            &self.grants,
                            register.request,
                            EventId(register.space),
                            register.fetch_key,
                        )
                        .await,
                ])
            }
            // ext-invite-links.md: a drop, mailbox kind 4.
            MessageType::MailboxPut if extensions.invite_links => {
                let put = frasil_transport::ext_invite_links::DropPut::read(message)?;
                Ok(vec![
                    self.shared.core.drop_put(&self.grants, &put, now).await,
                ])
            }
            MessageType::Sync => self.on_sync(message, answers).await,
            // ext-invite-links.md: the placer removes its drop.
            MessageType::MailboxDelete if extensions.invite_links => {
                let delete = frasil_transport::ext_invite_links::MailboxDelete::read(message)?;
                Ok(vec![
                    self.shared
                        .core
                        .drop_delete(&self.grants, &delete, now)
                        .await,
                ])
            }
            // ext-deposit-tokens.md, 3.4 Issuing: a grant draw, or a space
            // draw by the store right this connection holds here.
            MessageType::TokenRequest if extensions.deposit_tokens => Ok(vec![
                self.shared
                    .core
                    .token_request(&self.grants, &message.map, now)
                    .await?,
            ]),
            // ext-libraries.md, 3.7 Registering a hold.
            MessageType::HoldObject if extensions.libraries => {
                let hold =
                    frasil_libraries::HoldObject::read(&message.map).map_err(|_| malformed())?;
                let on = crate::state::On {
                    link: self.link,
                    binding,
                    purpose: self.purpose,
                    now,
                };
                Ok(vec![
                    self.shared.core.hold_object(&on, &self.grants, &hold).await,
                ])
            }
            MessageType::LibraryAttach if extensions.libraries => {
                let attach = frasil_libraries::attach::LibraryAttach::read(&message.map)
                    .map_err(|_| malformed())?;
                let on = crate::state::On {
                    link: self.link,
                    binding,
                    purpose: self.purpose,
                    now,
                };
                // A move into a library kept in another shard moves the
                // space's records (crate `libraries`, module `moves`).
                let answer = if attach.purpose == frasil_libraries::Purpose::Move {
                    crate::libraries::moves::library_move(
                        &self.shared,
                        &on,
                        &mut self.grants,
                        &attach,
                    )
                    .await
                } else {
                    self.shared
                        .core
                        .library_attach(&on, &mut self.grants, &attach)
                        .await
                };
                Ok(vec![answer])
            }
            // The ephemeral channel (ext-ephemeral.md, "Relaying"): a frame
            // of a space this connection holds the live right for goes to
            // the channel's other connections.
            MessageType::Ephemeral if extensions.ephemeral => {
                let frame = frasil_transport::messages::Ephemeral::read(
                    message,
                    ConnectionKind::DeviceToPeer,
                )?;
                if let frasil_transport::messages::Scope::Space(space) = frame.scope
                    && frame.origin.is_none()
                    && self
                        .grants
                        .get(&EventId(space))
                        .is_some_and(|grant| grant.rights.live)
                {
                    self.shared
                        .core
                        .ephemeral_frame(self.link, EventId(space), &frame.frame);
                }
                Ok(Vec::new())
            }
            // A peer without the ephemeral channel on drops its messages and
            // never relays them. A device sends no `Gone`. Adapter sync
            // travels between members only.
            MessageType::Ephemeral => Ok(Vec::new()),
            MessageType::Gone | MessageType::AdapterSync | MessageType::Open => Ok(Vec::new()),
            _ => Err(malformed()),
        }
    }

    /// The space's grant ends here: the connection leaves it at this node.
    pub(crate) fn leave(&mut self, space: &EventId) {
        self.grants.remove(space);
        self.shared.core.leave_space(self.link, *space);
    }

    /// A `Sync` message: units.md's sync, within the space's rights
    /// (transport.md, section 3.10, step 8). A message the space holds no
    /// right for is dropped, as is one whose own shape is malformed. An
    /// answer served in batches goes to `answers`.
    async fn on_sync(
        &mut self,
        message: &Message,
        answers: &mut Vec<Answer>,
    ) -> Result<Vec<Outgoing>, Failure> {
        let wrapper = Sync::read(message, ConnectionKind::DeviceToPeer)?;
        let Scope::Space(scope) = wrapper.scope else {
            return Err(malformed());
        };
        let space = EventId(scope);
        let unit = match SyncMessage::read(&wrapper.message) {
            Ok(Received::Message(unit)) => unit,
            Ok(Received::Ignored { .. }) | Err(_) => return Ok(Vec::new()),
        };
        if unit.space != space {
            return Err(malformed());
        }
        let now = self.shared.clock.now();
        let administration = self.purpose == Purpose::Administration;
        if administration && !matches!(unit.message, UnitMessage::Events { .. }) {
            // An administration connection carries only its pseudonym's
            // skeleton events and acknowledgements.
            return Ok(Vec::new());
        }
        // A space the connection holds no grant in gets none from its
        // messages: what they may do, they do under no right, and the peer
        // keeps nothing of the connection for it.
        let mut none = Grant::default();
        let grant = match self.grants.get_mut(&space) {
            Some(grant) => grant,
            None => &mut none,
        };
        // An administration connection stores only its pseudonym's skeleton
        // events, in the space it presented the pseudonym for: before that
        // present, or in another space, an event is outside its purpose,
        // a create included (transport.md, 3.10, the purposes).
        if administration && grant.pseudonym.is_none() {
            return Ok(refused_each(message, "purpose_violation"));
        }
        let may_fetch = grant.rights.fetch || grant.rights.catch_up;
        let messages: Vec<Vec<u8>> = match unit.message {
            UnitMessage::Events { events } => {
                // Each event is acknowledged, held pending, or answered by
                // `EventRefused` with its reason code (transport.md,
                // section 3.10): events carry no request number.
                let mut acknowledged = Vec::new();
                let mut out = Vec::new();
                let core = &self.shared.core;
                for signed in events {
                    let reason = match core.store(self.link, grant, space, &signed, now).await {
                        StoreAnswer::Acknowledge(id) | StoreAnswer::Elsewhere(id) => {
                            acknowledged.push(id);
                            if administration
                                && let Some(answer) = core.erasure_late(space, id).await
                            {
                                out.push(Outgoing::Control(answer));
                            }
                            continue;
                        }
                        StoreAnswer::Held(None) => continue,
                        StoreAnswer::Held(Some(code)) => code.to_owned(),
                        StoreAnswer::Refused(reason) => reason,
                    };
                    // An event whose ID does not read has none to name.
                    let Ok(event) = frasil_events::decode(&signed) else {
                        log(format_args!("an event that does not read: {reason}"));
                        continue;
                    };
                    out.push(Outgoing::Control(
                        EventRefused {
                            space: scope,
                            event: *event.id().as_bytes(),
                            code: reason,
                        }
                        .encode(),
                    ));
                }
                if !acknowledged.is_empty()
                    && !crate::testing::acknowledgement_withheld(space.as_bytes())
                {
                    acknowledged.truncate(frasil_units::limits::MAX_MESSAGE_ITEMS);
                    out.push(Outgoing::Sync(
                        space,
                        sync(
                            space,
                            UnitMessage::Ack {
                                heads: acknowledged,
                            },
                        ),
                    ));
                }
                return Ok(out);
            }
            UnitMessage::Subscribe { streams } => {
                if grant.rights.live {
                    let streams = (!streams.is_empty()).then_some(streams);
                    let core = &self.shared.core;
                    core.subscribe(self.link, space, streams);
                    // The first `Subscribe` joins the ephemeral channel.
                    if self.shared.settings.extensions.ephemeral {
                        core.ephemeral_join(self.link, space);
                    }
                }
                Vec::new()
            }
            // Nothing is read for a connection that may fetch nothing.
            UnitMessage::Heads { .. }
            | UnitMessage::Want { .. }
            | UnitMessage::StreamWant { .. }
            | UnitMessage::PathWant { .. }
                if !may_fetch =>
            {
                Vec::new()
            }
            UnitMessage::Heads {
                heads,
                vector,
                streams,
            } => {
                let reply = self
                    .shared
                    .core
                    .read(space, |held| {
                        View::new(held, grant).on_heads(&heads, vector.as_deref(), &streams)
                    })
                    .await;
                take(reply, answers)
            }
            UnitMessage::Want {
                ids,
                ranges,
                kinds,
                streams,
            } => {
                let reply = self
                    .shared
                    .core
                    .read(space, |held| {
                        View::new(held, grant).on_want(&ids, &ranges, &kinds, &streams)
                    })
                    .await;
                take(reply, answers)
            }
            UnitMessage::StreamWant {
                stream,
                held,
                from_snapshot,
            } => {
                let reply = self
                    .shared
                    .core
                    .read(space, |space_held| {
                        View::new(space_held, grant).on_stream_want(&stream, &held, from_snapshot)
                    })
                    .await;
                take(reply, answers)
            }
            UnitMessage::PathWant { from, to } => {
                let reply = self
                    .shared
                    .core
                    .read(space, |held| View::new(held, grant).on_path_want(from, to))
                    .await;
                take(reply, answers)
            }
            UnitMessage::ObjectWant {
                locator,
                first,
                count,
            } => {
                if !grant.rights.fetch {
                    return Ok(Vec::new());
                }
                let chunks = object_chunks(&self.shared, space, locator, first, count).await;
                return Ok(if chunks.is_empty() {
                    Vec::new()
                } else {
                    vec![Outgoing::Object(space, chunks)]
                });
            }
            UnitMessage::ObjectChunks {
                locator,
                header,
                index,
                chunk,
            } => {
                if !grant.rights.store {
                    return Ok(Vec::new());
                }
                let entry = grant.upload;
                let held = upload_chunk(
                    &self.shared,
                    self.link,
                    space,
                    locator,
                    header,
                    index,
                    chunk,
                    entry,
                )
                .await;
                vec![sync(
                    space,
                    UnitMessage::ObjectHave {
                        locators: vec![locator],
                        counts: Some(vec![held]),
                    },
                )]
            }
            UnitMessage::ObjectHave { locators, .. } => {
                if !(grant.rights.store || grant.rights.fetch) {
                    return Ok(Vec::new());
                }
                let mut counts: Vec<u64> = Vec::with_capacity(locators.len());
                for locator in &locators {
                    let home = self.shared.core.object_home(&space, locator).await;
                    counts.push(held_chunks(&self.shared, home, locator).await);
                }
                vec![sync(
                    space,
                    UnitMessage::ObjectHave {
                        locators,
                        counts: Some(counts),
                    },
                )]
            }
            _ => Vec::new(),
        };
        Ok(messages
            .into_iter()
            .map(|message| Outgoing::Sync(space, message))
            .collect())
    }
}

impl Session {
    /// The next part of an answer the peer serves in batches, if one is
    /// under way: the binding sends it before it reads the connection's
    /// next message. In a cluster, the owner of the space serves it in
    /// parts, each asked for once the one before is sent: so the order of
    /// what the device receives is the one it would be on the owner's own
    /// connection (transport.md, 3.7 Order on a connection), and one part
    /// at a time is in flight between the nodes.
    pub(crate) async fn next_answer(&mut self) -> Option<Outgoing> {
        while let Some(served) = self.answers.front_mut() {
            match served {
                Served::Here(answer) => {
                    let spaces = self.spaces.as_mut()?;
                    if let Some(next) = spaces.next_batch(answer).await {
                        return Some(next);
                    }
                }
                Served::Owner { space, ready, more } => {
                    if let Some(next) = ready.pop_front() {
                        return Some(next);
                    }
                    if *more && let Some(cluster) = self.shared.cluster.get().cloned() {
                        let (part, left) = cluster.forward_next(self.link, *space).await;
                        ready.extend(part);
                        *more = left;
                        continue;
                    }
                }
            }
            self.answers.pop_front();
        }
        None
    }
}

/// What a sync request is answered at once; its answer in batches goes to
/// `answers`.
fn take(reply: Option<Reply>, answers: &mut Vec<Answer>) -> Vec<Vec<u8>> {
    let Some(reply) = reply else {
        return Vec::new();
    };
    answers.extend(reply.answer.filter(|answer| !answer.done()));
    reply.now
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shared.core.unlink(self.link);
        if let Some(cluster) = self.shared.cluster.get() {
            cluster.closed(self.link);
        }
    }
}

/// The count of leading sealed chunks the peer holds of an object: all of
/// a complete one; otherwise those within its leading pieces and the tail
/// an upload on a sync stream has staged.
async fn held_chunks(shared: &Shared, space: EventId, locator: &Locator) -> u64 {
    let core = &shared.core;
    let record = core
        .read(space, |held| held.objects.get(locator).cloned())
        .await
        .flatten();
    if record.as_ref().is_some_and(|record| record.complete) {
        // A complete object's upload is over: its layout is piece 0's.
        return match core.layout(space, locator) {
            Some(layout) => layout.chunks,
            None => front_layout(shared, space, locator)
                .await
                .map_or(0, |layout| layout.chunks),
        };
    }
    let Some(layout) = core.layout(space, locator) else {
        return 0;
    };
    // The leading bytes held: the leading pieces, then the staged tail.
    let pieces = record.map_or(0, |record| leading(&record.pieces));
    let staged = lock(&core.uploads)
        .staging
        .get(&(space, *locator))
        .map_or(0, |staged| staged.bytes.len() as u64);
    layout.chunks_within(pieces * PIECE_BYTES as u64 + staged)
}

/// An object's layout as its stored piece 0 shows it.
async fn front_layout(shared: &Shared, space: EventId, locator: &Locator) -> Option<Layout> {
    let key = piece_key(space.as_bytes(), locator, 0);
    let front = shared.blobs.get(&key).await.ok().flatten()?;
    Layout::read(&front, locator)
}

/// What storing one piece did (transport.md, "The server binding", the
/// chunk route's answers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PieceOutcome {
    /// Stored durably: 201 with the count of leading pieces held.
    Stored(u64),
    /// An identical piece already held: 200.
    Identical(u64),
}

/// A message refused whole with `code`: a request by `Refused`, each event
/// a `Sync` carries by `EventRefused`; nothing for the rest, which is
/// dropped. As for a message of a space handed over to another peer,
/// `moved`.
fn refused_each(message: &Message, code: &str) -> Vec<Outgoing> {
    use frasil_transport::messages::EventRefused;
    use frasil_units::messages::{Message as Unit, Received};
    if message.kind != MessageType::Sync {
        return match message.get(1).and_then(|v| v.as_unsigned().ok()) {
            Some(request) if message.kind != MessageType::Ephemeral => {
                vec![refused(request, code)]
            }
            _ => Vec::new(),
        };
    }
    let Ok(wrapper) = Sync::read(message, ConnectionKind::DeviceToPeer) else {
        return Vec::new();
    };
    let Scope::Space(space) = wrapper.scope else {
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
                    code: code.into(),
                }
                .encode(),
            )
        })
        .collect()
}

/// What becomes of a message of a space the connection holds no grant in
/// (crate `cluster`, module `route`, "Before a grant").
pub(crate) enum WithoutGrant {
    /// It may lead to a grant, or its procedure checks more before the
    /// right: it goes on to the space's procedures, at the owner. With
    /// `create`, it may create the space there.
    Goes {
        /// Whether it may create the space.
        create: bool,
    },
    /// Its answer, which nothing the peer keeps decides.
    Answer(Vec<Outgoing>),
}

/// What a message of `space` is answered on a connection that holds no
/// grant there, at the space's owner and at a gateway alike, so that the
/// two answer code for code: a `Present` goes on (peers.md, 3.7 Presenting
/// a credential), as do a `LibraryAttach` and an `Events` carrying the
/// space's genesis, which may create or import it (peers.md, 3.1 Hosting a
/// space; ext-libraries.md), and a deposit-token draw, whose form is
/// checked before its store right (ext-deposit-tokens.md, 3.4 Issuing).
/// Every other request needs a right the connection lacks:
/// `credential_refused`, or `not_authorized` for a hold, the class its
/// procedure checks first (ext-libraries.md, 3.7 Registering a hold); a
/// drop's put and delete name the entry the connection proved, which is
/// none (ext-invite-links.md, 3.1). Each event is refused
/// `not_authorized` (peers.md, 3.7, step 2 of storing), or, on an
/// administration connection, which stores only its pseudonym's skeleton
/// events, `purpose_violation` (transport.md, 3.10, the purposes); one
/// that does not read is answered nothing, and one of another log
/// `malformed`. Every other unit, and an ephemeral frame, takes a right
/// the connection lacks, and is answered nothing.
///
/// # Errors
///
/// The failure the connection closes with: a request with no request
/// number, or a `Sync` whose unit names another space.
pub(crate) fn without_grant(
    message: &Message,
    space: &[u8; 32],
    purpose: Purpose,
) -> Result<WithoutGrant, Failure> {
    match message.kind {
        MessageType::Present | MessageType::TokenRequest => {
            Ok(WithoutGrant::Goes { create: false })
        }
        MessageType::LibraryAttach => Ok(WithoutGrant::Goes { create: true }),
        MessageType::Ephemeral | MessageType::Gone | MessageType::Open => {
            Ok(WithoutGrant::Answer(Vec::new()))
        }
        MessageType::Sync => {
            let wrapper = Sync::read(message, ConnectionKind::DeviceToPeer)?;
            let unit = match SyncMessage::read(&wrapper.message) {
                Ok(Received::Message(unit)) => unit,
                Ok(Received::Ignored { .. }) | Err(_) => {
                    return Ok(WithoutGrant::Answer(Vec::new()));
                }
            };
            if unit.space.as_bytes() != space {
                return Err(malformed());
            }
            let UnitMessage::Events { events } = unit.message else {
                return Ok(WithoutGrant::Answer(Vec::new()));
            };
            if purpose == Purpose::Administration {
                return Ok(WithoutGrant::Answer(refused_each(
                    message,
                    "purpose_violation",
                )));
            }
            let read: Vec<frasil_events::Event> = events
                .iter()
                .filter_map(|signed| frasil_events::decode(signed).ok())
                .collect();
            // A genesis creates the space: the device stores it before it
            // presents (peers.md, 3.1 Hosting a space).
            if read
                .iter()
                .any(|event| event.is_genesis() && event.id().as_bytes() == space)
            {
                return Ok(WithoutGrant::Goes { create: true });
            }
            Ok(WithoutGrant::Answer(
                read.iter()
                    .map(|event| {
                        let code = if event.log_id().as_bytes() == space {
                            frasil_peers::Code::NotAuthorized.name()
                        } else {
                            "malformed"
                        };
                        Outgoing::Control(
                            EventRefused {
                                space: *space,
                                event: *event.id().as_bytes(),
                                code: code.into(),
                            }
                            .encode(),
                        )
                    })
                    .collect(),
            ))
        }
        kind => {
            let request = message
                .get(1)
                .and_then(|value| value.as_unsigned().ok())
                .ok_or_else(malformed)?;
            let code = if kind == MessageType::HoldObject {
                frasil_peers::Code::NotAuthorized.name()
            } else {
                frasil_peers::Code::CredentialRefused.name()
            };
            Ok(WithoutGrant::Answer(vec![refused(request, code)]))
        }
    }
}

/// Stores one piece of an object (peers.md, "Objects"): checks it, writes
/// it to the object store, indexes it, and once the last piece completes
/// the object, checks the whole object's digest.
///
/// Before piece 0 the peer does not know the object's stored length, and
/// takes any whole piece at any index, so that pieces may arrive in any
/// order. Piece 0 fixes the length: a piece held at an index past it, or
/// held whole where the object's piece there is shorter, is deleted then,
/// and no longer counts toward the quota. Each piece's bytes are held in
/// the space's quota from its check until it is indexed, so that parallel
/// uploads never pass the quota together (peers.md, 3.20 Quotas and
/// rates).
///
/// # Errors
///
/// A reason code and its status: `erased` (410), `no_library` (507),
/// `too_large` (413), `malformed` (400), `conflict` (409),
/// `quota_exceeded` (507), `object_mismatch` (422).
pub(crate) async fn store_piece(
    shared: &Arc<Shared>,
    space: EventId,
    locator: Locator,
    index: u64,
    bytes: Vec<u8>,
    entry: Option<[u8; 32]>,
) -> Result<PieceOutcome, crate::state::Reason> {
    let key = piece_key(space.as_bytes(), &locator, index);
    let core = &shared.core;
    let now = core.space_now(&space, shared.clock.now());
    if let Some(refusal) = core.object_refusal(&space) {
        return Err(refusal);
    }
    if bytes.len() > PIECE_BYTES {
        return Err(("too_large".to_owned(), 413));
    }
    // ext-libraries.md, "Storing": the space's library's usage known.
    let libraries = shared.settings.extensions.libraries;
    if libraries {
        core.know_library_usage(&space).await;
    }
    let checked = core
        .read(space, |held| {
            let record = held.objects.get(&locator).cloned().unwrap_or(ObjectRecord {
                pieces: Default::default(),
                total: None,
                complete: false,
                last: now,
                referenced: false,
                entry,
            });
            let existing = record.pieces.contains(&index);
            // A piece held already, or a complete object, adds nothing.
            let adds = if existing || record.complete {
                0
            } else {
                bytes.len() as u64
            };
            // The bytes are held in the quota until the piece is indexed.
            let hold = if adds > 0 {
                Some(core.hold_piece(held, adds)?)
            } else {
                None
            };
            // ext-libraries.md, "Storing": the space's library, open, with
            // room.
            let reserved = if libraries {
                Some(core.library_admits(&space, adds)?)
            } else {
                None
            };
            Ok((existing, record, hold, reserved))
        })
        .await
        .unwrap_or_else(|| Err((frasil_peers::Code::NoLibrary.name().into(), 507)));
    let (existing, mut record, _hold, _reserved) = checked?;
    if existing || record.complete {
        let held = shared.blobs.get(&key).await.map_err(busy)?;
        return match held {
            Some(held) if held == bytes => Ok(PieceOutcome::Identical(leading(&record.pieces))),
            Some(_) => Err(("conflict".into(), 409)),
            None if record.complete => Err(("conflict".into(), 409)),
            None => Err(("busy".into(), 503)),
        };
    }
    if index == 0 {
        let layout = Layout::read(&bytes, &locator).ok_or_else(|| ("malformed".to_owned(), 400))?;
        record.total = Some(layout.total);
        core.keep_layout(space, locator, &layout);
    }
    let length = bytes.len() as u64;
    if let Some(total) = record.total {
        match crate::objects::piece_length(total, index) {
            Some(expected) if expected == length => {}
            _ => return Err(("malformed".into(), 400)),
        }
    } else if bytes.len() != PIECE_BYTES {
        // Before piece 0, only a whole piece can be placed.
        return Err(("malformed".into(), 400));
    }
    shared.blobs.put(&key, bytes).await.map_err(busy)?;
    let total = record.total;
    let indexed = core
        .update_object(space, locator, |current| {
            let mut current = current.cloned().unwrap_or(record);
            // Whether this piece 0 fixes the length now: before it, only
            // whole pieces were taken.
            let fixing = current.total.is_none() && total.is_some();
            if fixing {
                current.total = total;
            }
            // Checked again against the length as it is now: piece 0 may
            // have fixed it since this piece was checked.
            let fits = match current.total {
                Some(total) => crate::objects::piece_length(total, index) == Some(length),
                None => length == PIECE_BYTES as u64,
            };
            if !fits {
                return Err(("malformed".into(), 400));
            }
            current.pieces.insert(index);
            current.last = now;
            current.entry = current.entry.or(entry);
            // Piece 0 fixes the stored length: what was held past it goes.
            let strays: Vec<u64> = match current.total {
                Some(total) if fixing => current
                    .pieces
                    .iter()
                    .copied()
                    .filter(|&held| {
                        held != 0
                            && crate::objects::piece_length(total, held) != Some(PIECE_BYTES as u64)
                    })
                    .collect(),
                _ => Vec::new(),
            };
            for stray in &strays {
                current.pieces.remove(stray);
            }
            let held = leading(&current.pieces);
            let done = current
                .total
                .is_some_and(|total| held >= crate::objects::pieces_of(total));
            let answer = (held, done.then(|| current.clone()), strays);
            Ok((Some(current), answer))
        })
        .await;
    let (held, done, strays) = match indexed {
        Ok(indexed) => indexed,
        Err(refusal) => {
            if refusal.1 == 400 {
                let _ = shared.blobs.delete(&key).await;
            }
            return Err(refusal);
        }
    };
    for stray in strays {
        let _ = shared
            .blobs
            .delete(&piece_key(space.as_bytes(), &locator, stray))
            .await;
    }
    let Some(mut current) = done else {
        return Ok(PieceOutcome::Stored(held));
    };
    // The last piece: the stored object must hash to the locator's digest.
    let pieces = current.total.map_or(1, crate::objects::pieces_of);
    let mut digest = sha2::Sha256::default();
    for piece in 0..pieces {
        let key = piece_key(space.as_bytes(), &locator, piece);
        match shared.blobs.get(&key).await.map_err(busy)? {
            Some(bytes) => sha2::Digest::update(&mut digest, &bytes),
            None => return Err(("busy".into(), 503)),
        }
    }
    let digest: [u8; 32] = sha2::Digest::finalize(digest).into();
    core.upload_done(&space, &locator);
    if digest[..] != locator[32..] {
        for piece in &current.pieces {
            let _ = shared
                .blobs
                .delete(&piece_key(space.as_bytes(), &locator, *piece))
                .await;
        }
        let _ = core.update_object(space, locator, |_| Ok((None, ()))).await;
        return Err(("object_mismatch".into(), 422));
    }
    current.complete = true;
    core.update_object(space, locator, |_| Ok((Some(current), ())))
        .await?;
    Ok(PieceOutcome::Stored(held))
}

fn busy(error: crate::blobs::BlobError) -> crate::state::Reason {
    log(format_args!("{error}"));
    ("busy".into(), 503)
}

/// `ObjectWant`: each sealed chunk asked for, in its own `ObjectChunks`
/// (units.md, "Sync", objects).
async fn object_chunks(
    shared: &Arc<Shared>,
    space: EventId,
    locator: Locator,
    first: u64,
    count: u64,
) -> Vec<Vec<u8>> {
    // A held object's bytes are its source's (ext-libraries.md, 3.9
    // Fetching a held object); the chunks travel under the asking scope.
    let (home, record) = match shared.core.object_fetchable(&space, &locator).await {
        Ok(found) => found,
        Err(_) => return Vec::new(),
    };
    let Some(total) = record.total else {
        return Vec::new();
    };
    let mut pieces: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let read = |index: u64| {
        let shared = shared.clone();
        async move {
            shared
                .blobs
                .get(&piece_key(home.as_bytes(), &locator, index))
                .await
                .ok()
                .flatten()
        }
    };
    let Some(front) = read(0).await else {
        return Vec::new();
    };
    let Some(layout) = Layout::read(&front, &locator) else {
        return Vec::new();
    };
    pieces.insert(0, front);
    let mut out = Vec::new();
    for index in first..first.saturating_add(count.min(64)) {
        let Some((from, to)) = layout.chunk_range(index) else {
            break;
        };
        if to > total {
            break;
        }
        let mut chunk = Vec::with_capacity((to - from) as usize);
        let mut at = from;
        while at < to {
            let piece = at / PIECE_BYTES as u64;
            if let std::collections::btree_map::Entry::Vacant(slot) = pieces.entry(piece) {
                match read(piece).await {
                    Some(bytes) => {
                        slot.insert(bytes);
                    }
                    None => return out,
                }
            }
            let bytes = &pieces[&piece];
            let offset = (at - piece * PIECE_BYTES as u64) as usize;
            let end = ((to - piece * PIECE_BYTES as u64) as usize).min(bytes.len());
            if offset >= end {
                return out;
            }
            chunk.extend_from_slice(&bytes[offset..end]);
            at += (end - offset) as u64;
        }
        out.push(sync(
            space,
            UnitMessage::ObjectChunks {
                locator,
                header: (index == first).then(|| layout.header.clone()),
                index,
                chunk,
            },
        ));
    }
    out
}

/// Learns an object's layout from its piece 0, or from an upload's header.
async fn learn_layout(
    shared: &Arc<Shared>,
    space: EventId,
    locator: Locator,
    header: Option<&[u8]>,
) {
    if shared.core.layout(space, &locator).is_some() {
        return;
    }
    let key = piece_key(space.as_bytes(), &locator, 0);
    let front = match shared.blobs.get(&key).await {
        Ok(Some(front)) => Some(front),
        _ => header.map(|header| {
            let mut front = (header.len() as u32).to_be_bytes().to_vec();
            front.extend_from_slice(header);
            front
        }),
    };
    if let Some(layout) = front.and_then(|front| Layout::read(&front, &locator)) {
        shared.core.keep_layout(space, locator, &layout);
    }
}

/// `ObjectChunks` as an upload on a sync or object stream: the header, then
/// sealed chunks in order. The peer appends each to the stored bytes it
/// holds and writes whole pieces as they fill; a chunk out of order is
/// dropped, and the answer's count tells the uploader where to resume
/// (units.md, "Sync", objects). Returns the count of leading chunks held.
///
/// What it stages counts toward the space's quota, belongs to the
/// connection `link`, which stages at most `staged_objects` objects at
/// once, and goes when the object completes, when the connection closes,
/// or `orphan_grace` after its last chunk.
#[allow(clippy::too_many_arguments)]
async fn upload_chunk(
    shared: &Arc<Shared>,
    link: u64,
    space: EventId,
    locator: Locator,
    header: Option<Vec<u8>>,
    index: u64,
    chunk: Vec<u8>,
    entry: Option<[u8; 32]>,
) -> u64 {
    let core = &shared.core;
    let Some((record, used)) = core
        .read(space, |held| {
            (held.objects.get(&locator).cloned(), held.used())
        })
        .await
    else {
        return 0;
    };
    if record.as_ref().is_some_and(|record| record.complete) {
        return held_chunks(shared, space, &locator).await;
    }
    learn_layout(shared, space, locator, header.as_deref()).await;
    let Some(layout) = core.layout(space, &locator) else {
        return 0;
    };
    let pieces = record.as_ref().map_or(0, |record| leading(&record.pieces));
    let now = shared.clock.now().timeline;
    let flush = {
        let mut uploads = lock(&core.uploads);
        let key = (space, locator);
        let staged_len = uploads
            .staging
            .get(&key)
            .map_or(0, |staged| staged.bytes.len());
        // A first upload's staged bytes begin with the header's length and
        // the header.
        let front = if pieces == 0 && staged_len == 0 {
            4 + layout.header.len()
        } else {
            0
        };
        let held = pieces * PIECE_BYTES as u64 + (staged_len + front) as u64;
        let expected = layout.chunks_within(held);
        // The chunk is the next one; after a resume it may begin inside
        // the last piece held, whose bytes it repeats.
        let fits = layout
            .chunk_range(index)
            .filter(|&(from, to)| from <= held && held < to && to - from == chunk.len() as u64);
        let Some((from, _)) = fits.filter(|_| index == expected) else {
            return expected;
        };
        let adds = (front + chunk.len() - (held - from) as usize) as u64;
        // A connection stages at most `staged_objects` objects at once.
        if !uploads.staging.contains_key(&key) {
            let staging = uploads
                .staging
                .values()
                .filter(|staged| staged.link == link)
                .count();
            if staging >= shared.settings.connections.staged_objects {
                return expected;
            }
        }
        // Staged bytes count toward the space's quota (peers.md, 3.20).
        if used
            .saturating_add(uploads.held(&space))
            .saturating_add(adds)
            > shared.settings.space_quota
        {
            return expected;
        }
        let staged = uploads.staging.entry(key).or_default();
        staged.link = link;
        staged.last = now;
        if front > 0 {
            staged
                .bytes
                .extend_from_slice(&(layout.header.len() as u32).to_be_bytes());
            staged.bytes.extend_from_slice(&layout.header);
        }
        staged
            .bytes
            .extend_from_slice(&chunk[(held - from) as usize..]);
        let held = pieces * PIECE_BYTES as u64 + staged.bytes.len() as u64;
        let mut ready = Vec::new();
        let mut piece = pieces;
        while staged.bytes.len() >= PIECE_BYTES
            || (held == layout.total && !staged.bytes.is_empty())
        {
            let take = staged.bytes.len().min(PIECE_BYTES);
            ready.push((piece, staged.bytes.drain(..take).collect::<Vec<u8>>()));
            piece += 1;
        }
        ready
    };
    for (piece, bytes) in flush {
        if let Err((reason, _)) = store_piece(shared, space, locator, piece, bytes, entry).await {
            log(format_args!("an object piece was refused: {reason}"));
            core.upload_done(&space, &locator);
            return 0;
        }
    }
    held_chunks(shared, space, &locator).await
}

#[cfg(test)]
pub(crate) mod tests;
