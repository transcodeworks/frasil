//! The peer's state and its procedures, independent of any binding.
//!
//! [`Core`] holds what the peer hosts, each space behind locks of its own
//! and opened on first use (crate `spaces`), the tombstones of erased
//! spaces, the mailboxes, the connections other procedures reach (for live
//! delivery and `Awaiting`), and the transfer tokens of the server binding,
//! each under a lock of its own. Its methods run whole procedures of
//! peers.md and transport.md. A procedure that changes a space holds the
//! space for writing until its records are durable (crate `writer`) and
//! applied, so procedures on different spaces run in parallel and share
//! their commits' syncs. What needs the object store's IO is split around
//! them by the caller.

use crate::clock::{Clock, wall_now};
use crate::config::{Hosting, Settings};
use crate::device_mail::{Caps, Claim, DeviceMail, Held};
use crate::records::{ObjectRecord, Op, Records};
use crate::space::{self, Locator, Removal, Rules, Space, Stored};
use crate::spaces::{Index, Writing, blocking};
use crate::util::log;
use crate::writer::{Writer, made};
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_events::{Event, EventId, kind};
use frasil_peers::Code;
use frasil_peers::entries::{
    Connection, Entries, EntryStatus, Present as EntryPresent, Refusal, Rights, Storer, may_store,
};
use frasil_peers::proof::{Credential, Purpose};
use frasil_store::{Commit, StoreError};
use frasil_transport::codes::Right;
use frasil_transport::mailbox::{self, Kind};
use frasil_transport::messages::{Accepted, Awaiting, Granted, Present, Refused, Scope, Sync};
use frasil_units::messages::{Message as UnitMessage, SyncMessage};
use frasil_units::stream::StreamId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use tokio::sync::mpsc;

/// What a connection sends, in the order it is queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outgoing {
    /// A control message.
    Control(Vec<u8>),
    /// A `Sync` message, on the space's sync stream.
    Sync(EventId, Vec<u8>),
    /// `Sync` messages carrying one object transfer, on an object stream
    /// of its own where the binding has them.
    Object(EventId, Vec<Vec<u8>>),
    /// An `Ephemeral` or `Gone` the peer relays (ext-ephemeral.md): lossy,
    /// as a datagram where the binding has them.
    Ephemeral(Vec<u8>),
    /// Close the connection with `reconnect` once no import is in progress
    /// and no create pending on it (transport.md, 3.10, "Reconnecting
    /// elsewhere"): the cluster moves load between its machines, or the
    /// connection's live delivery of a space ended with the entries that
    /// granted it (peers.md, 3.6 Retirement and the cap, "Connections").
    /// Never sent to a device as such.
    Reconnect,
}

/// A connection, as other procedures reach it.
#[derive(Debug)]
struct Link {
    tx: mpsc::Sender<Outgoing>,
    /// The spaces it subscribed to.
    subscriptions: BTreeSet<EventId>,
    /// An administration connection's space and pseudonym, by device ID.
    admin: Option<(EventId, DeviceId)>,
    /// Whether a gateway forwards it here (crate `cluster`): not one of
    /// this node's own connections.
    forwarded: bool,
    /// The last `Awaiting` sent.
    awaiting: Option<Vec<EventId>>,
    /// Whether this administration connection was told of a held cut.
    extension_notified: bool,
    /// Whether it was asked to reconnect elsewhere and has not declined.
    asked: bool,
    /// Per space, the read keys whose presents granted it the live right:
    /// its live delivery stands while one of them is a live entry's
    /// (peers.md, 3.6 Retirement and the cap, "Connections").
    live: BTreeMap<EventId, BTreeSet<[u8; 32]>>,
    /// The bytes queued for it and not yet taken by its binding, and the
    /// most it may hold.
    queued: Arc<AtomicUsize>,
    cap: usize,
}

impl Link {
    /// Queues a message, as [`offer`] does, unless its bytes would take
    /// the connection's queue past its cap: false if it is not queued.
    fn offer(&self, out: Outgoing) -> bool {
        let size = queued_size(&out);
        if size > 0 && self.queued.load(Ordering::SeqCst).saturating_add(size) > self.cap {
            return false;
        }
        if !offer(&self.tx, out) {
            return false;
        }
        self.queued.fetch_add(size, Ordering::SeqCst);
        true
    }
}

/// The bytes a queued message holds.
pub(crate) fn queued_size(out: &Outgoing) -> usize {
    match out {
        Outgoing::Control(bytes) | Outgoing::Sync(_, bytes) | Outgoing::Ephemeral(bytes) => {
            bytes.len()
        }
        Outgoing::Object(_, messages) => messages.iter().map(Vec::len).sum(),
        Outgoing::Reconnect => 0,
    }
}

/// Notes that a connection's binding took a message off its queue.
pub(crate) fn dequeued(queued: &AtomicUsize, out: &Outgoing) {
    let size = queued_size(out);
    let _ = queued.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
        Some(held.saturating_sub(size))
    });
}

/// The connections, and who listens to each space.
#[derive(Debug, Default)]
struct Links {
    next: u64,
    links: BTreeMap<u64, Link>,
    /// The connection the next ask to reconnect elsewhere starts from.
    ask_from: u64,
    /// Live delivery, per space: each connection's whole space, or its
    /// streams.
    subscribers: BTreeMap<EventId, BTreeMap<u64, Option<Vec<StreamId>>>>,
    /// Each space's administration connections.
    admins: BTreeMap<EventId, BTreeSet<u64>>,
}

impl Links {
    /// [`Core::reconnect_some`].
    fn ask_reconnect(&mut self, count: usize) -> usize {
        let from = self.ask_from;
        let order: Vec<u64> = self
            .links
            .range(from..)
            .chain(self.links.range(..from))
            .filter(|(_, link)| !link.forwarded && !link.asked)
            .map(|(id, _)| *id)
            .collect();
        let mut asked = 0;
        for id in order {
            if asked >= count {
                break;
            }
            let Some(link) = self.links.get_mut(&id) else {
                continue;
            };
            if link.offer(Outgoing::Reconnect) {
                link.asked = true;
                asked += 1;
                self.ask_from = id + 1;
            }
        }
        asked
    }
}

/// What a connection's presents for one space were granted, and what the
/// store right and catch-up track on it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Grant {
    /// The rights granted.
    pub rights: Rights,
    /// The administrator pseudonym, by device ID, an administration
    /// present proved, or names while [`Self::provisional`].
    pub pseudonym: Option<DeviceId>,
    /// The pseudonym was not enrolled yet: its enrolment must be the first
    /// event the connection stores, and the present's proof verifies under
    /// that enrolment's `ed` (peers.md, 3.7 Presenting a credential, steps
    /// 3 and 4).
    pub provisional: Option<Deferred>,
    /// Whether the connection has stored an event of the space.
    pub stored_any: bool,
    /// The upload key of the entry the connection proved, for attribution.
    pub upload: Option<[u8; 32]>,
    /// Under catch-up: the events served, whose parents it may fetch by ID.
    pub served: BTreeSet<EventId>,
    /// Under catch-up: the stream it names as the space's system stream.
    pub system_stream: Option<StreamId>,
    /// ext-libraries.md: the connection's create or import of the space,
    /// accepted by `LibraryAttach` and not yet over.
    pub library: crate::libraries::Attaching,
    /// Each credential the connection's presents proved, with what it
    /// grants: [`Self::rights`] is their union. A proof holds while its
    /// entry is live (peers.md, 2.2 The credential proof).
    pub proofs: Vec<Proved>,
    /// The core's count of retirements when the rights were last judged
    /// ([`Core::rejudge`]).
    pub judged: u64,
}

/// A credential a connection proved for a space, and what it grants now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Proved {
    /// The credential.
    pub credential: Credential,
    /// Its public half: the entry's key, or the pseudonym's device ID.
    pub public: [u8; 32],
    /// What it grants now.
    pub rights: Rights,
}

impl Grant {
    /// Whether the grant holds anything: a right, an administrator
    /// pseudonym, or an import or a create under way. One whose rights
    /// ended with its entries holds nothing, and the connection is a
    /// stranger in the space again.
    pub(crate) fn holds(&self) -> bool {
        self.rights != Rights::default()
            || self.pseudonym.is_some()
            || self.provisional.is_some()
            || self.library.in_progress()
    }

    /// Takes the rights each proof grants now, by `standing`: [`Self::rights`]
    /// becomes their union, and the upload key that attributes stores one
    /// whose entry still grants the store right (peers.md, 3.6 Retirement
    /// and the cap, "Connections"). A grant with no proof keeps its rights.
    fn judge(&mut self, standing: impl Fn(Credential, &[u8; 32]) -> Rights, judged: u64) {
        self.judged = judged;
        if self.proofs.is_empty() {
            return;
        }
        let mut rights = Rights::default();
        for proof in &mut self.proofs {
            proof.rights = standing(proof.credential, &proof.public);
            rights = rights.union(proof.rights);
        }
        self.rights = rights;
        let stores = |public: &[u8; 32]| {
            self.proofs.iter().any(|proof| {
                proof.credential == Credential::Upload
                    && proof.public == *public
                    && proof.rights.store
            })
        };
        if !self.upload.is_some_and(|upload| stores(&upload)) {
            self.upload = self
                .proofs
                .iter()
                .rev()
                .find(|proof| proof.credential == Credential::Upload && proof.rights.store)
                .map(|proof| proof.public);
        }
    }

    /// Whether the connection proved a credential of the space: a proof
    /// that verified, whatever it grants now. A pseudonym granted
    /// provisionally, whose proof waits for its enrolment, proved nothing
    /// yet (peers.md, 3.7 Presenting a credential). Only such a connection
    /// learns, by `moved`, that the space was handed over (peers.md, 3.1
    /// Hosting a space, "Hand-over").
    pub(crate) fn proved(&self) -> bool {
        self.proofs
            .iter()
            .any(|proof| proof.credential != Credential::Pseudonym || self.provisional.is_none())
    }

    /// Notes a credential a present proved; one proved again replaces it.
    fn prove(&mut self, credential: Credential, public: [u8; 32], rights: Rights) {
        self.proofs
            .retain(|proof| !(proof.credential == credential && proof.public == public));
        self.proofs.push(Proved {
            credential,
            public,
            rights,
        });
    }
}

/// A credential 3 present whose pseudonym the peer does not know yet: what
/// its proof signs and the proof, checked when the pseudonym's enrolment
/// arrives, under the `ed` of its envelope (peers.md, 3.7 Presenting a
/// credential, step 4).
#[derive(Debug, Clone)]
pub(crate) struct Deferred {
    /// transport.md's `presented` of the present.
    presented: Vec<u8>,
    /// The proof.
    proof: Vec<u8>,
}

impl Deferred {
    /// Whether the proof verifies strictly under `ed`.
    fn verifies(&self, ed: &IdentityKey) -> bool {
        frasil_peers::proof::verify(&ed.0, &self.presented, &self.proof)
    }
}

/// The connection a request arrives on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct On {
    /// The connection's number.
    pub link: u64,
    /// Its `binding`.
    pub binding: [u8; 32],
    /// Its purpose.
    pub purpose: Purpose,
    /// Now, on the peer's timeline.
    pub now: Reading,
}

/// A refusal of an HTTP or mailbox request: a reason code and its status.
pub(crate) type Reason = (String, u16);

/// Mailbox items: each item's ID and the item.
pub(crate) type Items = Vec<([u8; 16], Vec<u8>)>;

/// A transfer token's grant (transport.md, "The server binding"): the
/// present's credential, by which it stands while its entry is live
/// (peers.md, 3.6 Retirement and the cap, "Connections").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Transfer {
    pub link: u64,
    pub space: EventId,
    pub rights: Rights,
    pub credential: Credential,
    pub public: [u8; 32],
}

/// What a store answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreAnswer {
    /// Acknowledge this event by its ID.
    Acknowledge(EventId),
    /// Stored, or held, without an acknowledgement: pending, or `conflict`,
    /// which `EventRefused` carries.
    Held(Option<&'static str>),
    /// Refused, with its reason.
    Refused(String),
    /// A genesis whose create another shard of the peer made first: the
    /// same event, stored there, so acknowledged, and nothing of the
    /// create here is kept (peers.md, 3.1 Hosting a space, "One peer on
    /// several machines").
    Elsewhere(EventId),
}

/// A refusal of a request that travels as a reason code.
pub(crate) fn refused(request: u64, reason: &str) -> Outgoing {
    Outgoing::Control(
        Refused {
            request,
            code: reason.to_owned(),
        }
        .encode(),
    )
}

/// A rate window: the timeline readings of the events it counts.
#[derive(Debug, Default, Clone)]
pub(crate) struct Window(VecDeque<u64>);

impl Window {
    /// Counts one at `now` if fewer than `limit` fall within `span` seconds
    /// before it.
    pub(crate) fn admit(&mut self, now: u64, span: u64, limit: usize) -> bool {
        if !self.room(now, span, limit) {
            return false;
        }
        self.count(now);
        true
    }

    /// Whether fewer than `limit` fall within `span` seconds before `now`;
    /// counts nothing.
    pub(crate) fn room(&mut self, now: u64, span: u64, limit: usize) -> bool {
        while self
            .0
            .front()
            .is_some_and(|&t| now.saturating_sub(t) >= span)
        {
            self.0.pop_front();
        }
        self.0.len() < limit
    }

    /// Counts one at `now`.
    pub(crate) fn count(&mut self, now: u64) {
        self.0.push_back(now);
    }

    /// Whether it counts nothing within `span` seconds before `now`.
    pub(crate) fn idle(&self, now: u64, span: u64) -> bool {
        self.0.iter().all(|&t| now.saturating_sub(t) >= span)
    }
}

/// A rate per second over a monotonic clock, with a burst of one second's
/// worth: a connection's `Ephemeral` frames (ext-ephemeral.md, 3.7
/// Relaying, "applies its own rate limits per connection"). It holds two
/// words, whatever the rate.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Bucket {
    /// The frames it may still take now, in thousandths.
    thousandths: u64,
    /// When it last counted.
    last: Option<std::time::Instant>,
}

impl Bucket {
    /// Takes one at `now` if the rate allows it.
    pub(crate) fn admit(&mut self, now: std::time::Instant, per_second: usize) -> bool {
        let per_second = per_second as u64;
        let full = per_second.saturating_mul(1000);
        let held = match self.last {
            None => full,
            Some(last) => {
                let millis = u64::try_from(now.saturating_duration_since(last).as_millis())
                    .unwrap_or(u64::MAX);
                self.thousandths
                    .saturating_add(millis.saturating_mul(per_second))
                    .min(full)
            }
        };
        self.last = Some(now);
        if held >= 1000 {
            self.thousandths = held - 1000;
            true
        } else {
            self.thousandths = held;
            false
        }
    }
}

/// The most ephemeral frames queued for one connection at once: a sender's
/// queue (ext-ephemeral.md, 2.1 Labels and limits). Past it the frame is
/// dropped, so that ephemeral traffic never takes the room of another
/// message.
pub(crate) const EPHEMERAL_QUEUED: usize = frasil_ephemeral::limits::SEND_QUEUE;

/// Queues a message for a connection, as a delivery does: false if the
/// queue is full, or, for an ephemeral frame, if it already holds
/// [`EPHEMERAL_QUEUED`] messages. A connection's queue holds
/// [`EPHEMERAL_QUEUED`] more than its other traffic needs, so an ephemeral
/// flood never drops another member's sync delivery (transport.md, 3.8
/// Priority and the lossy channel).
pub(crate) fn offer(tx: &mpsc::Sender<Outgoing>, out: Outgoing) -> bool {
    if matches!(out, Outgoing::Ephemeral(_))
        && tx.max_capacity() - tx.capacity() >= EPHEMERAL_QUEUED
    {
        return false;
    }
    tx.try_send(out).is_ok()
}

/// The ephemeral channels (ext-ephemeral.md, "Relaying"): each space's,
/// while a connection is on it, and the spaces each connection is on, so
/// that a close walks only the channels the connection was on.
#[derive(Default)]
struct Relays {
    channels: BTreeMap<EventId, frasil_ephemeral::relay::Relay<u64>>,
    joined: BTreeMap<u64, BTreeSet<EventId>>,
}

impl Relays {
    /// The channel of a space, made when a connection first comes on it.
    fn channel(&mut self, space: EventId) -> &mut frasil_ephemeral::relay::Relay<u64> {
        self.channels
            .entry(space)
            .or_insert_with(|| frasil_ephemeral::relay::Relay::new(*space.as_bytes()))
    }

    /// Notes that a connection is on a space's channel, if it is.
    fn note(&mut self, link: u64, space: EventId) {
        if self
            .channels
            .get(&space)
            .is_some_and(|relay| relay.origin(&link).is_some())
        {
            self.joined.entry(link).or_default().insert(space);
        }
    }

    /// A connection leaves a space's channel; the channel goes once no
    /// connection is on it.
    fn leave(&mut self, link: u64, space: EventId) -> Vec<frasil_ephemeral::relay::Relayed<u64>> {
        if let Some(spaces) = self.joined.get_mut(&link) {
            spaces.remove(&space);
            if spaces.is_empty() {
                self.joined.remove(&link);
            }
        }
        let Some(relay) = self.channels.get_mut(&space) else {
            return Vec::new();
        };
        let out = relay.leave(&link);
        if relay.is_empty() {
            self.channels.remove(&space);
        }
        out
    }
}

/// The mailboxes (transport.md, "Mailboxes").
struct Mail {
    exchange: frasil_admission::mailbox::ExchangeMailboxes<String>,
    exchange_requests: BTreeMap<[u8; 32], [u8; 16]>,
    /// The kinds of message each exchange mailbox holds at rest.
    exchange_kinds: BTreeMap<[u8; 32], BTreeSet<u8>>,
    /// The device mailboxes' index; their items stay in the records.
    devices: DeviceMail,
    next_item: u128,
    /// Counts the changes made in memory, so that a reading of the records
    /// replaces memory only if none was made meanwhile.
    changes: u64,
}

impl Mail {
    /// The mailboxes as their records hold them: with `shards`, the device
    /// mailboxes of the shards this node keeps, which are the only ones it
    /// decides for, each item counted in its shard's part, each part under
    /// `caps`; and the claims, as at the reading `now`, under the
    /// operator's `mailbox_retention`. Blocking.
    fn read(
        records: &Records,
        shards: Option<&crate::shards::Shards>,
        caps: Caps,
        now: u64,
        retention: u64,
    ) -> Result<Self, StoreError> {
        let mut mail = Mail {
            exchange: Default::default(),
            exchange_requests: BTreeMap::new(),
            exchange_kinds: BTreeMap::new(),
            devices: DeviceMail::new(caps),
            next_item: 1,
            changes: 0,
        };
        let scan = |prefix: &[u8]| match shards {
            // With shards, only the mailboxes this node keeps.
            Some(shards) => shards.scan_kept_mailboxes(prefix),
            None => records.scan(prefix),
        };
        for first in 0..=u8::MAX {
            let found = scan(&Records::mailbox_prefix(first))?;
            for (address, id, kept, len) in Records::mailbox_items(found)? {
                let part = mail_part(shards.is_some(), &address);
                let held = Held {
                    id,
                    len,
                    sight: kept.sight,
                    paid: kept.paid,
                    unclaimed: kept.unclaimed,
                };
                mail.devices.load(&part, address, held);
                mail.next_item = mail.next_item.max(u128::from_be_bytes(id) + 1);
            }
        }
        for (address, last, since) in Records::claims(scan(&[crate::records::CLAIM])?) {
            let part = mail_part(shards.is_some(), &address);
            mail.devices
                .load_claim(&part, address, Claim { last, since }, now, retention);
        }
        for (address, wall, source, message) in records.exchange_messages()? {
            let Ok(read) = frasil_admission::message::read_message(&message) else {
                continue;
            };
            if crate::source::exchange_put(&mut mail.exchange, &source, &message, wall).is_ok() {
                mail.exchange_requests.insert(address, read.request);
                mail.exchange_kinds
                    .entry(address)
                    .or_default()
                    .insert(read.kind.code());
            }
        }
        Ok(mail)
    }
}

/// Object uploads in progress (peers.md, 3.8 Objects): what an upload
/// holds in memory between its chunks, each part freed when the object
/// completes, when the connection that staged it closes, or `orphan_grace`
/// after its last use, as an upload left incomplete is collected.
#[derive(Debug, Default)]
pub(crate) struct Uploads {
    /// Sealed chunks uploaded in order on a sync or object stream, not yet
    /// a whole piece, with the connection that sent them. They count
    /// toward their space's quota.
    pub staging: BTreeMap<(EventId, Locator), Staged>,
    /// The front of each object being uploaded, its header's length and
    /// its header, once known, with its last use.
    layouts: BTreeMap<(EventId, Locator), (Vec<u8>, u64)>,
    /// Per space, the bytes of pieces being written and not yet indexed:
    /// a store counts them toward the quota with what is stored, so that
    /// parallel uploads never pass it together.
    writing: BTreeMap<EventId, u64>,
}

/// An upload's sealed chunks not yet a whole piece.
#[derive(Debug, Default)]
pub(crate) struct Staged {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The connection that sent them.
    pub link: u64,
    /// The peer's timeline at their last chunk.
    pub last: u64,
}

impl Uploads {
    /// The bytes staged for a space: they count toward its quota.
    pub(crate) fn staged_bytes(&self, space: &EventId) -> u64 {
        self.staging
            .range((*space, [0; 64])..)
            .take_while(|((id, _), _)| id == space)
            .map(|(_, staged)| staged.bytes.len() as u64)
            .sum()
    }

    /// What a space's uploads hold apart from its usage: bytes staged and
    /// pieces being written.
    pub(crate) fn held(&self, space: &EventId) -> u64 {
        self.staged_bytes(space)
            .saturating_add(self.writing.get(space).copied().unwrap_or(0))
    }

    /// Forgets an upload: its staged bytes and its layout.
    pub(crate) fn forget(&mut self, space: &EventId, locator: &Locator) {
        self.staging.remove(&(*space, *locator));
        self.layouts.remove(&(*space, *locator));
    }
}

/// Bytes of a piece being written, held in its space's quota until the
/// piece is indexed or refused.
pub(crate) struct PieceHold<'a> {
    core: &'a Core,
    space: EventId,
    bytes: u64,
}

impl Drop for PieceHold<'_> {
    fn drop(&mut self) {
        let mut uploads = lock(&self.core.uploads);
        if let Some(held) = uploads.writing.get_mut(&self.space) {
            *held = held.saturating_sub(self.bytes);
            if *held == 0 {
                uploads.writing.remove(&self.space);
            }
        }
    }
}

/// The part a device mailbox's items count in (crate `device_mail`): its
/// shard when the records are in shards, else the one part `""`.
fn mail_part(sharded: bool, address: &[u8; 32]) -> String {
    if sharded {
        crate::shards::Shards::address_shard("mailboxes", address)
    } else {
        String::new()
    }
}

/// What each part of the device mailboxes may hold: the operator's caps,
/// and with ext-deposit-tokens the token budget, each split evenly among
/// the parts, so that the parts together never pass them, whichever node
/// decides for each (ext-deposit-tokens.md, 3.10 In a cluster). With the
/// extension off, the token budget holds nothing: no deposit is paid.
fn mail_caps(settings: &Settings, sharded: bool) -> Caps {
    use frasil_transport::caps::Cap;
    let parts = if sharded { crate::shards::HASHED } else { 1 } as u64;
    let split = |items: u64, bytes: u64| Cap {
        items: (items / parts).max(1),
        bytes: (bytes / parts).max(1),
    };
    let limits = settings.device_mail;
    let budget = settings.deposit_tokens.budget;
    Caps {
        anonymous: split(limits.items as u64, limits.bytes as u64),
        tokens: if settings.extensions.deposit_tokens {
            split(budget.items, budget.bytes)
        } else {
            Cap { items: 0, bytes: 0 }
        },
    }
}

/// How often, at most, a claimed mailbox's last collection is written
/// again, in seconds.
const CLAIM_KEPT_EVERY: u64 = 3_600;

/// Which entries and recovery entries of a space are live, by position.
/// The peer only ever adds to them, so a retirement shows as one live
/// before and retired after. An erasure, which removes the recovery
/// entries, reaches connections on its own ([`Core::retired`] with no
/// entries).
struct Liveness(Vec<bool>, Vec<bool>);

impl Liveness {
    fn of(entries: &Entries) -> Self {
        Self(
            entries.entries().iter().map(|e| e.is_live()).collect(),
            entries
                .recovery()
                .iter()
                .map(|e| e.status == EntryStatus::Live)
                .collect(),
        )
    }

    /// Whether an entry or a recovery entry live before is retired in
    /// `entries`.
    fn retired_in(&self, entries: &Entries) -> bool {
        self.0
            .iter()
            .zip(entries.entries())
            .any(|(&was, e)| was && !e.is_live())
            || self
                .1
                .iter()
                .zip(entries.recovery())
                .any(|(&was, e)| was && e.status != EntryStatus::Live)
    }
}

/// Locks a mutex; a panic elsewhere while it was held leaves its value as
/// it was.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The peer's state.
pub(crate) struct Core {
    pub settings: Settings,
    pub records: Records,
    pub writer: Writer,
    pub clock: Arc<dyn Clock>,
    /// What the peer hosts, and the slots of the spaces in use.
    pub(crate) index: Mutex<Index>,
    tombstones: RwLock<BTreeMap<EventId, Vec<u8>>>,
    /// The departure records of the spaces handed over to another peer
    /// (peers.md, 3.1 Hosting a space, "Hand-over").
    pub(crate) departures: RwLock<BTreeMap<EventId, crate::records::Departure>>,
    /// The libraries handed over lately, with how many spaces left.
    pub(crate) departed: Mutex<BTreeMap<frasil_libraries::LibraryId, usize>>,
    /// ext-libraries.md: the moves of spaces into other shards under way.
    pub(crate) moves: Mutex<BTreeMap<EventId, crate::records::MoveRecord>>,
    /// ext-libraries.md: the changes memory took to `moves` while the
    /// index's moves are read again.
    pub(crate) move_changes: Mutex<crate::libraries::moves::MoveChanges>,
    /// ext-libraries.md: the spaces moving into shards this node keeps.
    pub(crate) arrivals: Mutex<crate::libraries::moves::Arrivals>,
    links: Mutex<Links>,
    pub transfers: Mutex<BTreeMap<[u8; 32], Transfer>>,
    /// Counts the times an entry retired or a space was erased here, so
    /// that each grant is judged again before its next use
    /// ([`Self::rejudge`]).
    retirements: AtomicU64,
    mail: Mutex<Mail>,
    /// The device-mailbox deposits each source made lately.
    deposits: Mutex<crate::device_mail::Deposits>,
    /// ext-deposit-tokens.md: the tokens each source had refused lately.
    pub(crate) refused_tokens: Mutex<crate::device_mail::Deposits>,
    /// ext-deposit-tokens.md: the deposit keys (crate `deposit`).
    pub(crate) deposit_keys: crate::deposit::Keys,
    pub uploads: Mutex<Uploads>,
    /// ext-libraries.md: libraries, attachments and the tickets used.
    pub libraries: Mutex<crate::libraries::Libraries>,
    /// ext-invite-links.md: the invite drops.
    pub drops: Mutex<crate::drops::Drops>,
    /// ext-ephemeral.md: each space's ephemeral channel, while a connection
    /// is on it, and the channels each connection is on.
    relays: Mutex<Relays>,
    /// How many times a space was rebuilt from its records.
    pub replays: AtomicU64,
    /// The shards the records are kept in, when they are.
    pub(crate) shards: Option<Arc<crate::shards::Shards>>,
}

impl core::fmt::Debug for Core {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core")
            .field("hosted", &lock(&self.index).hosted.len())
            .field("open", &self.open_spaces())
            .finish_non_exhaustive()
    }
}

impl Core {
    /// The peer's state from its records: the space index, tombstones,
    /// mailboxes and, with the extensions, libraries and drops. No space is
    /// opened. Blocking: it reads the records.
    #[cfg(test)]
    pub(crate) fn open(
        settings: Settings,
        records: Records,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        Self::open_with(settings, records, clock, None)
    }

    /// [`Self::open`] over the peer's shards, whose timelines its spaces
    /// read and whose maintenance its writer runs between groups.
    pub(crate) fn open_with(
        settings: Settings,
        records: Records,
        clock: Arc<dyn Clock>,
        shards: Option<Arc<crate::shards::Shards>>,
    ) -> Result<Self, StoreError> {
        let maintain = shards.clone().map(|shards| {
            shards.set_idle_close(settings.idle_close);
            Arc::new(move || shards.maintain()) as crate::writer::Maintain
        });
        records.check_revision()?;
        let writer = Writer::spawn_with(records.store(), settings.group_commit, maintain)?;
        let index = Index::new(records.hosted_spaces()?, records.waiting_spaces()?);
        let tombstones = records.tombstones()?.into_iter().collect();
        let departures = records.departures()?.into_iter().collect();
        // An extension that is off reads none of its records: its state
        // stays empty, as in a peer without it.
        let extensions = settings.extensions;
        let moves = if extensions.libraries {
            records.moves()?.into_iter().collect()
        } else {
            BTreeMap::new()
        };
        let libraries = if extensions.libraries {
            crate::libraries::Libraries::open(&settings, &records)?
        } else {
            crate::libraries::Libraries::new(settings.libraries.clone())
        };
        let drops = if extensions.invite_links {
            crate::drops::Drops::open(&records)?
        } else {
            crate::drops::Drops::default()
        };
        let deposit_keys = crate::deposit::Keys::new(&settings.deposit_tokens);
        let caps = mail_caps(&settings, shards.is_some());
        let mail = Mail::read(
            &records,
            shards.as_deref(),
            caps,
            clock.now().timeline,
            settings.mailbox_retention,
        )?;
        Ok(Self {
            settings,
            records,
            writer,
            clock,
            index: Mutex::new(index),
            tombstones: RwLock::new(tombstones),
            departures: RwLock::new(departures),
            departed: Mutex::new(BTreeMap::new()),
            moves: Mutex::new(moves),
            move_changes: Mutex::new(crate::libraries::moves::MoveChanges::default()),
            arrivals: Mutex::new(crate::libraries::moves::Arrivals::default()),
            links: Mutex::new(Links {
                next: 1,
                ..Links::default()
            }),
            transfers: Mutex::new(BTreeMap::new()),
            retirements: AtomicU64::new(0),
            mail: Mutex::new(mail),
            deposits: Mutex::new(crate::device_mail::Deposits::default()),
            refused_tokens: Mutex::new(crate::device_mail::Deposits::default()),
            deposit_keys,
            uploads: Mutex::new(Uploads::default()),
            libraries: Mutex::new(libraries),
            drops: Mutex::new(drops),
            relays: Mutex::new(Relays::default()),
            replays: AtomicU64::new(0),
            shards,
        })
    }

    /// The reading of a space's shard's timeline at the node's reading
    /// `now` (overview.md, 6.7 Clocks of a replicated peer): every sight the
    /// peer records for the space, and every timer it judges against them,
    /// is on that timeline. The node's own when the records are in no
    /// shards. A space that moved in from another shard keeps its own
    /// timeline: its reading at the move, plus the shard's advance since.
    pub(crate) fn space_now(&self, space: &EventId, now: Reading) -> Reading {
        let Some(shards) = &self.shards else {
            return now;
        };
        let address = Records::journal_address(space, 0);
        let mut reading = match shards.reading_open(&address, now) {
            Some(reading) => reading,
            None => match crate::spaces::blocking_here(|| shards.reading(&address, now)) {
                Ok(reading) => reading,
                Err(error) => {
                    log(format_args!("a shard's timeline was not read: {error}"));
                    return now;
                }
            },
        };
        if let Some((shard_at, space_at)) =
            crate::spaces::blocking_here(|| shards.space_offset(space.as_bytes()))
        {
            reading.timeline = reading
                .timeline
                .saturating_sub(shard_at)
                .saturating_add(space_at);
        }
        reading
    }

    /// The reading of a shard's timeline at the node's reading `now`, by
    /// the shard's name: for a space about to be placed in it.
    pub(crate) fn shard_now(&self, shard: &str, now: Reading) -> Reading {
        let Some(shards) = &self.shards else {
            return now;
        };
        match crate::spaces::blocking_here(|| shards.reading_of(shard, now)) {
            Ok(reading) => reading,
            Err(error) => {
                log(format_args!("a shard's timeline was not read: {error}"));
                now
            }
        }
    }

    /// A space's `erasure_timeout`, T: with ext-libraries, its library's
    /// when it is attached to one; otherwise the peer's.
    pub(crate) fn erasure_timeout(&self, space_id: &EventId) -> u64 {
        if let Some(timeout) = lock(&self.libraries).erasure_timeout(space_id) {
            return timeout;
        }
        self.settings.erasure_timeout
    }

    /// Whether the peer erased a space and keeps its tombstone.
    pub(crate) fn tombstoned(&self, space_id: &EventId) -> bool {
        self.tombstones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(space_id)
    }

    /// The settings a space's sweep judges under: with ext-libraries, its
    /// library's T.
    pub(crate) fn sweep_settings(&self, space_id: &EventId) -> Settings {
        let mut settings = self.settings.clone();
        if let Some(timeout) = lock(&self.libraries).erasure_timeout(space_id) {
            settings.erasure_timeout = timeout;
        }
        settings
    }

    // -- Connections

    /// Registers a connection; returns its number. Its queue is bounded by
    /// its messages alone.
    #[cfg(test)]
    pub(crate) fn link(&self, tx: mpsc::Sender<Outgoing>) -> u64 {
        self.link_with(tx, false, Arc::default(), usize::MAX)
    }

    /// Registers a connection whose queue holds at most `queued_bytes` of
    /// messages: `queued` counts them, and its binding takes off what it
    /// sends ([`dequeued`]).
    pub(crate) fn link_bounded(&self, tx: mpsc::Sender<Outgoing>, queued: Arc<AtomicUsize>) -> u64 {
        let cap = self.settings.connections.queued_bytes;
        self.link_with(tx, false, queued, cap)
    }

    /// Registers a connection a gateway forwards here, in a cluster: what
    /// this node sends it on its own waits here for its link to the
    /// gateway, bounded as a connection's own queue is, by `queued_bytes`;
    /// `queued` counts it, and what carries it to the gateway takes off
    /// what it took ([`dequeued`]).
    pub(crate) fn link_forwarded(
        &self,
        tx: mpsc::Sender<Outgoing>,
        queued: Arc<AtomicUsize>,
    ) -> u64 {
        let cap = self.settings.connections.queued_bytes;
        self.link_with(tx, true, queued, cap)
    }

    fn link_with(
        &self,
        tx: mpsc::Sender<Outgoing>,
        forwarded: bool,
        queued: Arc<AtomicUsize>,
        cap: usize,
    ) -> u64 {
        let mut links = lock(&self.links);
        let id = links.next;
        links.next += 1;
        links.links.insert(
            id,
            Link {
                tx,
                subscriptions: BTreeSet::new(),
                admin: None,
                awaiting: None,
                extension_notified: false,
                forwarded,
                asked: false,
                live: BTreeMap::new(),
                queued,
                cap,
            },
        );
        id
    }

    /// Forgets a connection and its transfer tokens.
    pub(crate) fn unlink(&self, link: u64) {
        // Its ephemeral frames dropped, and `Gone` to the others: on the
        // channels it was on, and no other.
        {
            let spaces = lock(&self.relays).joined.remove(&link).unwrap_or_default();
            for space in spaces {
                self.ephemeral_leave(link, space);
            }
        }
        {
            let mut links = lock(&self.links);
            if let Some(gone) = links.links.remove(&link) {
                for space in gone.subscriptions {
                    if let Some(subscribers) = links.subscribers.get_mut(&space) {
                        subscribers.remove(&link);
                        if subscribers.is_empty() {
                            links.subscribers.remove(&space);
                        }
                    }
                }
                if let Some((space, _)) = gone.admin
                    && let Some(admins) = links.admins.get_mut(&space)
                {
                    admins.remove(&link);
                    if admins.is_empty() {
                        links.admins.remove(&space);
                    }
                }
            }
        }
        lock(&self.transfers).retain(|_, transfer| transfer.link != link);
        // What its uploads staged goes with it (peers.md, 3.8 Objects: an
        // upload left incomplete is collected).
        lock(&self.uploads)
            .staging
            .retain(|_, staged| staged.link != link);
    }

    /// Asks up to `count` of this node's own connections to reconnect
    /// elsewhere; returns how many were asked. Each ask starts after the
    /// last connection asked, and passes over those asked already until
    /// they decline or close, so that a connection held by an import or a
    /// create stalls no one.
    pub(crate) fn reconnect_some(&self, count: usize) -> usize {
        lock(&self.links).ask_reconnect(count)
    }

    /// A connection asked to reconnect elsewhere declined, as an import or
    /// a create held it: it may be asked again.
    pub(crate) fn reconnect_declined(&self, link: u64) {
        if let Some(entry) = lock(&self.links).links.get_mut(&link) {
            entry.asked = false;
        }
    }

    /// How many of this node's own connections are open.
    pub(crate) fn connections(&self) -> usize {
        lock(&self.links)
            .links
            .values()
            .filter(|link| !link.forwarded)
            .count()
    }

    /// Whether a connection or an upload is on a space, so that it stays
    /// open.
    pub(crate) fn in_use(&self, space_id: &EventId) -> bool {
        {
            let links = lock(&self.links);
            if links.subscribers.contains_key(space_id) || links.admins.contains_key(space_id) {
                return true;
            }
        }
        if lock(&self.relays).channels.contains_key(space_id) {
            return true;
        }
        lock(&self.uploads).staged_bytes(space_id) > 0
    }

    /// How many administration connections a space has.
    fn admin_connections(&self, space_id: &EventId) -> usize {
        lock(&self.links)
            .admins
            .get(space_id)
            .map_or(0, BTreeSet::len)
    }

    /// Makes a connection an administration connection of a space.
    fn admin(&self, link: u64, space_id: EventId, pseudonym: DeviceId) {
        let mut links = lock(&self.links);
        let Some(entry) = links.links.get_mut(&link) else {
            return;
        };
        let before = entry.admin.replace((space_id, pseudonym));
        if let Some((old, _)) = before
            && old != space_id
            && let Some(admins) = links.admins.get_mut(&old)
        {
            admins.remove(&link);
            if admins.is_empty() {
                links.admins.remove(&old);
            }
        }
        links.admins.entry(space_id).or_default().insert(link);
    }

    // -- Retirement reaching connections

    /// Notes that a present of the read key `public` granted a connection
    /// the live right in a space.
    fn note_live(&self, link: u64, space_id: EventId, public: [u8; 32]) {
        if let Some(entry) = lock(&self.links).links.get_mut(&link) {
            entry.live.entry(space_id).or_default().insert(public);
        }
    }

    /// Judges a grant again before its next use if an entry retired or a
    /// space was erased here since it was last judged: each proof keeps
    /// what a present of it would be granted now (peers.md, 2.2 The
    /// credential proof; 3.6 Retirement and the cap, "Connections"). A
    /// space no longer hosted here, but not erased, leaves it as it is:
    /// a hand-over answers `moved`.
    pub(crate) async fn rejudge(&self, space_id: EventId, grant: &mut Grant) {
        // Read before the entries: a retirement after it is judged again.
        let judged = self.retirements.load(Ordering::SeqCst);
        if grant.judged == judged {
            return;
        }
        if grant.proofs.is_empty() {
            grant.judged = judged;
            return;
        }
        if self.tombstoned(&space_id) {
            grant.judge(|_, _| Rights::default(), judged);
            return;
        }
        let proofs: Vec<(Credential, [u8; 32])> = grant
            .proofs
            .iter()
            .map(|proof| (proof.credential, proof.public))
            .collect();
        let standing = self
            .read(space_id, |space| {
                proofs
                    .iter()
                    .map(|(credential, public)| {
                        (
                            (*credential, *public),
                            space.entries.standing(*credential, public),
                        )
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .await;
        if let Some(standing) = standing {
            grant.judge(
                |credential, public| {
                    standing
                        .get(&(credential, *public))
                        .copied()
                        .unwrap_or_default()
                },
                judged,
            );
        } else if self.tombstoned(&space_id) {
            grant.judge(|_, _| Rights::default(), judged);
        }
    }

    /// An entry or a recovery entry of a space retired, or, with no
    /// `entries`, the space was erased: what open connections hold under
    /// it ends at once (peers.md, 3.6 Retirement and the cap,
    /// "Connections"). Each grant is judged again before its next use; a
    /// transfer token whose present no longer grants what it carried stops;
    /// a connection that no live entry it proved grants the live right
    /// leaves the space's live delivery and its ephemeral channel, and one
    /// that was subscribed is asked to reconnect, which its binding does
    /// unless an import or a create holds it (transport.md, 3.10
    /// "Reconnecting elsewhere"). In a cluster this runs at the space's
    /// owner, which keeps the grants, tokens and subscriptions of the
    /// connections gateways forward to it; a forwarded connection's ask goes
    /// to its gateway, which closes the device's connection.
    pub(crate) fn retired(&self, space_id: EventId, entries: Option<&Entries>) {
        self.retirements.fetch_add(1, Ordering::SeqCst);
        let standing = |credential: Credential, public: &[u8; 32]| {
            entries.map_or_else(Rights::default, |entries| {
                entries.standing(credential, public)
            })
        };
        lock(&self.transfers).retain(|_, transfer| {
            transfer.space != space_id
                || standing(transfer.credential, &transfer.public) == transfer.rights
        });
        let ended: Vec<u64> = {
            let mut links = lock(&self.links);
            let mut ended = Vec::new();
            for (&number, link) in &mut links.links {
                let Some(keys) = link.live.get_mut(&space_id) else {
                    continue;
                };
                keys.retain(|key| standing(Credential::Read, key).live);
                if !keys.is_empty() {
                    continue;
                }
                link.live.remove(&space_id);
                if link.subscriptions.remove(&space_id) {
                    // `Subscribe` names no request that a `Refused` could
                    // answer: the connection is asked to reconnect.
                    let _ = link.offer(Outgoing::Reconnect);
                }
                ended.push(number);
            }
            if let Some(subscribers) = links.subscribers.get_mut(&space_id) {
                for number in &ended {
                    subscribers.remove(number);
                }
                if subscribers.is_empty() {
                    links.subscribers.remove(&space_id);
                }
            }
            ended
        };
        for number in ended {
            self.ephemeral_leave(number, space_id);
        }
    }

    /// Whether a connection is subscribed to a space's live delivery.
    #[cfg(test)]
    pub(crate) fn subscribed(&self, link: u64, space_id: &EventId) -> bool {
        lock(&self.links)
            .subscribers
            .get(space_id)
            .is_some_and(|subscribers| subscribers.contains_key(&link))
    }

    // -- Presenting a credential

    /// peers.md, "Presenting a credential", on a `Present` that
    /// transport.md's steps 6 and 7 let through. Answers `Granted` or
    /// `Refused`; on the server binding the grant carries a transfer token.
    pub(crate) async fn present(
        &self,
        on: &On,
        grants: &mut BTreeMap<EventId, Grant>,
        present: &Present,
        transfer_token: Option<[u8; 32]>,
    ) -> Outgoing {
        let On {
            link,
            binding,
            purpose,
            now,
        } = *on;
        let binding = &binding;
        let request = present.request;
        let space_id = EventId(present.space);
        let Ok(public) = <[u8; 32]>::try_from(present.public.as_slice()) else {
            return refused(request, "credential_refused");
        };
        // Whether this connection is the space's import in progress
        // (peers.md, "Hosting a space"); imports are ext-libraries.md's.
        let importing = grants
            .get(&space_id)
            .is_some_and(|grant| grant.library.importing());
        // 2. The space is hosted here and not erased. A space not hosted
        // is answered with no slot of it made.
        if self.tombstoned(&space_id) {
            return refused(request, Code::Erased.name());
        }
        if !self.hosts(&space_id) {
            return refused(request, self.unhosted(space_id, present, &public, binding));
        }
        let writing = match self.write(space_id).await {
            Ok(writing) => writing,
            Err(error) => {
                log(format_args!("a space did not open: {error}"));
                return refused(request, "busy");
            }
        };
        // Again with the space held: an erasure ends with the space's gate.
        if self.tombstoned(&space_id) {
            return refused(request, Code::Erased.name());
        }
        let pseudonym = present.credential == u64::from(Credential::Pseudonym.code());
        // The present is judged on a copy of the entries, which replaces
        // them once what it changed is at rest.
        let (rights, deferred, op, entries) = {
            let state = writing.state();
            let Some(space) = state.space.as_ref() else {
                return refused(request, self.unhosted(space_id, present, &public, binding));
            };
            // Credential 3 names a pseudonym by device ID; its proof
            // verifies under the `ed` of the root or enrolment the peer
            // accepted for it (peers.md, 2.2 The credential proof).
            let ed = if pseudonym {
                space.pseudonym_ed(&DeviceId(public))
            } else {
                None
            };
            // Step 3: a pseudonym the peer does not know yet may still enrol
            // as the first event this connection stores. Steps 1 and 2 hold
            // here; step 4 waits for that enrolment, whose `ed` the proof
            // verifies under.
            if pseudonym && ed.is_none() {
                if !purpose.allows(Credential::Pseudonym) {
                    return refused(request, "purpose_violation");
                }
                let presented = frasil_peers::proof::presented(
                    binding,
                    space_id.as_bytes(),
                    Credential::Pseudonym.code(),
                    &public,
                );
                let deferred = Deferred {
                    presented,
                    proof: present.proof.clone(),
                };
                (Rights::ERASE, Some(deferred), None, None)
            } else {
                // The entries' proved marks and statuses, which a present
                // may change.
                let find = |entries: &frasil_peers::entries::Entries| {
                    entries
                        .entries()
                        .iter()
                        .filter(|e| match present.credential {
                            1 => e.read == public,
                            2 => e.upload == public,
                            _ => false,
                        })
                        .map(|e| (e.proved, e.is_live()))
                        .collect::<Vec<_>>()
                };
                let mut entries = space.entries.clone();
                let before = find(&entries);
                let entry_present = EntryPresent {
                    credential: present.credential,
                    space: space_id,
                    public,
                    proof: &present.proof,
                };
                let connection = Connection {
                    binding: *binding,
                    purpose,
                    importing,
                };
                let rights = match entries.present(&entry_present, &connection, ed.as_ref()) {
                    Ok(rights) => rights,
                    Err(Refusal::PurposeViolation) => return refused(request, "purpose_violation"),
                    Err(Refusal::Code(code)) => return refused(request, code.name()),
                    Err(Refusal::Class(_)) => return refused(request, "credential_refused"),
                };
                // A present that changed an entry is kept, so that a replay
                // makes the same change.
                let after = find(&entries);
                let op = (!before.is_empty() && before != after).then(|| Op::Proved {
                    credential: u8::try_from(present.credential).unwrap_or(0),
                    public,
                    binding: *binding,
                    proof: present.proof.clone(),
                    importing,
                });
                (rights, None, op, Some(entries))
            }
        };
        // A space's administration connections are bounded: past the
        // operator's limit, a further pseudonym's present is refused `busy`
        // (transport.md, 2.5 Codes), its proof checked first.
        if pseudonym
            && self.admin_connections(&space_id)
                >= self.settings.connections.admin_connections_per_space
        {
            return refused(request, "busy");
        }
        if let Some(op) = op
            && let Err(error) = self.journal(&writing, vec![op]).await
        {
            log(format_args!("a present was not kept: {error}"));
            return refused(request, "busy");
        }
        // Read before the entries: a retirement after it is judged again.
        let judged = self.retirements.load(Ordering::SeqCst);
        let credential = Credential::from_code(present.credential).unwrap_or(Credential::Read);
        let grant = grants.entry(space_id).or_default();
        grant.prove(credential, public, rights);
        {
            let mut state = writing.state();
            if let Some(space) = state.space.as_mut() {
                if let Some(entries) = entries {
                    space.entries = entries;
                }
                // Every proof of the connection's is judged by the entries
                // as they are now (peers.md, 2.2 The credential proof).
                grant.judge(
                    |credential, key| space.entries.standing(credential, key),
                    judged,
                );
            }
        }
        if rights.live {
            self.note_live(link, space_id, public);
        }
        if pseudonym {
            grant.pseudonym = Some(DeviceId(public));
            // A provisional pseudonym administers once its enrolment is
            // stored and its proof verified.
            if deferred.is_none() {
                self.admin(link, space_id, DeviceId(public));
            }
            grant.provisional = deferred;
        }
        if credential == Credential::Upload && rights.store {
            grant.upload = Some(public);
        }
        if let Some(token) = transfer_token {
            lock(&self.transfers).insert(
                token,
                Transfer {
                    link,
                    space: space_id,
                    rights,
                    credential,
                    public,
                },
            );
        }
        let answer = Outgoing::Control(
            Granted {
                request,
                rights: Right::of(rights),
                transfer_token,
            }
            .encode(),
        );
        if pseudonym {
            let state = writing.state();
            if let Some(space) = &state.space {
                self.send_awaiting(space, now);
            }
        }
        answer
    }

    // -- Merge statements and recovery entries

    /// `Merge`, on a connection that proved a live upload entry of its space
    /// (peers.md, "Merge statements").
    pub(crate) async fn merge(
        &self,
        grants: &BTreeMap<EventId, Grant>,
        request: u64,
        statement: &[u8],
        now: Reading,
    ) -> Outgoing {
        let Ok(read) = frasil_peers::merge::MergeStatement::read(statement) else {
            return refused(request, "malformed");
        };
        let space_id = read.space;
        if !grants.get(&space_id).is_some_and(|g| g.rights.store) {
            return refused(request, "credential_refused");
        }
        let Ok(writing) = self.write(space_id).await else {
            return refused(request, "busy");
        };
        let entries = {
            let mut state = writing.state();
            let limit = self.settings.rates.merges_per_hour;
            if !state.merges.admit(now.timeline, 3600, limit) {
                return refused(request, Code::RateLimited.name());
            }
            let Some(space) = state.space.as_ref() else {
                return refused(request, Code::NoLibrary.name());
            };
            let mut entries = space.entries.clone();
            if let Err(class) = entries.merge(&space.log, &space_id, statement) {
                return refused(request, &space::reason(Refusal::Class(class)));
            }
            entries
        };
        // A merge entry past `merge_per_state` or the cap retires another
        // (peers.md, 3.6 Retirement and the cap).
        let retiring = {
            let state = writing.state();
            state
                .space
                .as_ref()
                .is_some_and(|space| Liveness::of(&space.entries).retired_in(&entries))
        };
        let op = Op::Merge {
            statement: statement.to_vec(),
        };
        let answer = self.journal_then(&writing, op, entries, request).await;
        if retiring && let Some(space) = writing.state().space.as_ref() {
            self.retired(space_id, Some(&space.entries));
        }
        answer
    }

    /// `RegisterRecoveryEntry` (peers.md, "Presenting a credential",
    /// recovery entries).
    pub(crate) async fn register(
        &self,
        grants: &BTreeMap<EventId, Grant>,
        request: u64,
        space_id: EventId,
        key: [u8; 32],
    ) -> Outgoing {
        let rights = grants.get(&space_id).map(|g| g.rights).unwrap_or_default();
        // The store right first: a connection without it opens nothing.
        if !rights.store {
            return refused(request, Code::CredentialRefused.name());
        }
        let Ok(writing) = self.write(space_id).await else {
            return refused(request, "busy");
        };
        let entries = {
            let state = writing.state();
            let Some(space) = state.space.as_ref() else {
                return refused(request, "credential_refused");
            };
            let mut entries = space.entries.clone();
            if let Err(refusal) = entries.register(&key, rights) {
                return refused(request, &space::reason(refusal));
            }
            entries
        };
        self.journal_then(&writing, Op::Register { key }, entries, request)
            .await
    }

    /// Journals a record that changes a space's entries, then, once it is
    /// at rest, takes `entries` as the space's: `Accepted`, or `busy` with
    /// nothing changed.
    async fn journal_then(
        &self,
        writing: &Writing,
        op: Op,
        entries: frasil_peers::entries::Entries,
        request: u64,
    ) -> Outgoing {
        if self.journal(writing, vec![op]).await.is_err() {
            return refused(request, "busy");
        }
        if let Some(space) = writing.state().space.as_mut() {
            space.entries = entries;
        }
        Outgoing::Control(Accepted { request }.encode())
    }

    /// peers.md, 3.7 Presenting a credential, step 2, for a space the peer
    /// does not host and has not erased: the proof is verified whatever the
    /// peer keeps, so that the answer costs the same for every such space.
    /// `moved` answers only a proof that verifies under a public half the
    /// space's departure record keeps (peers.md, 3.1 Hosting a space);
    /// anything else `no_library`.
    fn unhosted(
        &self,
        space_id: EventId,
        present: &Present,
        public: &[u8; 32],
        binding: &[u8; 32],
    ) -> &'static str {
        let credential = u8::try_from(present.credential).unwrap_or(0);
        let presented =
            frasil_peers::proof::presented(binding, space_id.as_bytes(), credential, public);
        // Credential 3's proof verifies under the Ed25519 key the record
        // keeps for the pseudonym whose device ID `public` is; with none
        // kept, under `public`, as every other proof for a space never
        // hosted.
        let departure = self.departure_of(&space_id);
        let key = match &departure {
            Some(departure) if credential == Credential::Pseudonym.code() => {
                departure.pseudonym(public).unwrap_or(*public)
            }
            _ => *public,
        };
        let verified = frasil_peers::proof::verify(&key, &presented, &present.proof);
        if verified && departure.is_some_and(|departure| departure.keeps(credential, public)) {
            Code::Moved.name()
        } else {
            Code::NoLibrary.name()
        }
    }

    /// Whether the peer handed a space over, as its departure record says:
    /// memory first, then, in a cluster, where another node may have
    /// written it, the index. Blocking.
    pub(crate) fn departure_of(&self, space: &EventId) -> Option<crate::records::Departure> {
        if let Some(departure) = self
            .departures
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(space)
        {
            return Some(departure.clone());
        }
        if !self
            .shards
            .as_ref()
            .is_some_and(|shards| shards.clustered_now())
        {
            return None;
        }
        let address = Records::departure_address(space);
        crate::spaces::blocking_here(|| self.records.get(&address))
            .ok()
            .flatten()
            .and_then(|record| crate::records::Departure::decode(&record))
    }

    /// Appends records, already applied, to a space's journal.
    async fn journal(&self, writing: &Writing, ops: Vec<Op>) -> Result<(), StoreError> {
        let (puts, index) = {
            let state = writing.state();
            let Some(space) = state.space.as_ref() else {
                return Ok(());
            };
            let mut puts = Vec::new();
            let mut index = space.next_index;
            for op in &ops {
                puts.push((Records::journal_address(&writing.id, index), op.encode()));
                index += 1;
            }
            (puts, index)
        };
        self.commit_space(writing, puts, Vec::new()).await?;
        if let Some(space) = writing.state().space.as_mut() {
            space.next_index = index;
        }
        Ok(())
    }

    /// Reads the late-erasure answer from the durable skeleton.
    pub(crate) async fn erasure_late(&self, space: EventId, id: EventId) -> Option<Vec<u8>> {
        let writing = self.write(space).await.ok()?;
        let answer = writing
            .state()
            .space
            .as_ref()?
            .erasure_late(id)
            .map(|answer| answer.encode());
        self.let_go(writing);
        answer
    }

    // -- Storing an event

    /// peers.md, "Storing an event", in order, on an event a connection
    /// sends in the space `space_id`. Answers once the event is durable.
    pub(crate) async fn store(
        &self,
        link: u64,
        grant: &mut Grant,
        space_id: EventId,
        signed: &[u8],
        now: Reading,
    ) -> StoreAnswer {
        // 1. events.md's envelope and size checks, and the Ed25519 half.
        let event = match frasil_events::decode(signed) {
            Ok(event) => event,
            Err(class) => {
                use frasil_base::errors::Class;
                return StoreAnswer::Refused(class.wire_name().to_owned());
            }
        };
        if event.log_id() != space_id {
            return StoreAnswer::Refused("malformed".into());
        }
        let id = event.id();
        let libraries = self.settings.extensions.libraries;
        // 2, first as the index says now: a connection that may not store
        // in the space is refused before the space is opened, or a slot of
        // it made. Step 2 runs again with the space held.
        {
            let hosted = self.hosts(&space_id);
            let storer = Storer {
                rights: grant.rights,
                creating: !hosted,
                // Judged on a copy: the store's own judgement below is the
                // one that ends an import.
                importing: libraries
                    && grant.library.clone().importing_store(&grant.rights, hosted),
                pseudonym: grant.pseudonym,
            };
            if let Err(class) = may_store(&event, &storer) {
                return StoreAnswer::Refused(space::reason(Refusal::Class(class)));
            }
        }
        let writing = match self.write(space_id).await {
            Ok(writing) => writing,
            Err(error) => {
                log(format_args!("a space did not open: {error}"));
                return StoreAnswer::Refused("busy".into());
            }
        };
        // Read with the space held: an erasure ends with the space's gate.
        let tombstoned = self.tombstoned(&space_id);
        let hosted = writing.hosted();
        // An import in progress stores the log it imports, and ends at the
        // importer's first store under the store right (peers.md, "Hosting
        // a space").
        let importing = libraries && grant.library.importing_store(&grant.rights, hosted);
        // 2. The connection may store in this space.
        let storer = Storer {
            rights: grant.rights,
            // A genesis of an erased space passes as a create, and step 3
            // refuses it as erased (peers.md, "Erasure").
            creating: !hosted,
            importing,
            pseudonym: grant.pseudonym,
        };
        if let Err(class) = may_store(&event, &storer) {
            return StoreAnswer::Refused(space::reason(Refusal::Class(class)));
        }
        // A provisional pseudonym's connection stores its enrolment first,
        // and the present's proof verifies under that enrolment's `ed`
        // (peers.md, 3.7 Presenting a credential, steps 3 and 4).
        if let Some(deferred) = &grant.provisional {
            let enrols = matches!(
                frasil_peers::body::StorageBody::read(event.unverified_body()),
                Ok(frasil_peers::body::StorageBody::Enrol { .. })
            );
            if grant.stored_any
                || !enrols
                || grant.pseudonym != Some(*event.author())
                || !deferred.verifies(event.ed())
            {
                return StoreAnswer::Refused(Code::NotAuthorized.name().into());
            }
        }
        // 3. The space is hosted here and not erased. A create or an import
        // whose genesis is refused lapses (ext-libraries.md, 3.3
        // Attaching).
        if tombstoned {
            if event.is_genesis() {
                grant.library.lapse();
            }
            return StoreAnswer::Refused(Code::Erased.name().into());
        }
        if !hosted {
            let answer = if libraries {
                self.library_create(&writing, grant, event, signed, now)
                    .await
            } else {
                self.create(
                    &writing,
                    event,
                    signed,
                    now,
                    crate::shards::space_shard(space_id.as_bytes()),
                    false,
                )
                .await
            };
            // A create refused leaves no slot behind.
            self.let_go(writing);
            return answer;
        }
        // ext-libraries.md, "Storing": the space is attached to an open
        // library, with room in its quota over all its spaces.
        if libraries {
            if let Err((reason, _)) = self.library_hosts(&space_id, &event) {
                return StoreAnswer::Refused(reason);
            }
            self.know_library_usage(&space_id).await;
        }
        let settings = &self.settings;
        let sight = self.space_now(&space_id, now);
        let mut reserved = None;
        let (puts, index, op) = {
            let mut state = writing.state();
            let op = {
                let space = state.held();
                if let Some(retry) = space.retry(id) {
                    if frasil_peers::body::StorageBody::read(event.unverified_body()).is_err_and(
                        |class| class.shared() == Some(frasil_base::ErrorClass::ExtensionRequired),
                    ) {
                        return StoreAnswer::Held(Some(Code::ExtensionRequired.name()));
                    }
                    // The enrolment of a provisional pseudonym, stored
                    // already: once the peer accepted it, the pseudonym
                    // administers.
                    if grant.provisional.is_some()
                        && space.pseudonym_ed(event.author()) == Some(*event.ed())
                    {
                        grant.provisional = None;
                        self.admin(link, space_id, *event.author());
                    }
                    return match retry {
                        Stored::Retry { acknowledge: true } => StoreAnswer::Acknowledge(id),
                        // A fork's second event, sent again, is answered
                        // again.
                        _ if space.conflicts.contains(&id) => {
                            StoreAnswer::Held(Some(Code::Conflict.name()))
                        }
                        _ => StoreAnswer::Held(None),
                    };
                }
                // 4 to 6. An import stores its log whole, writer requests
                // too, before its importer holds any right (peers.md, 3.1
                // Hosting a space, "Import"; 3.2, step 2).
                let rights = if importing {
                    frasil_peers::entries::Rights::STORE_AND_RELEASE
                } else {
                    grant.rights
                };
                match space.admit(&event, signed, &rights, settings, sight, grant.upload) {
                    Ok(op) => op,
                    Err(refusal) => return StoreAnswer::Refused(space::reason(refusal)),
                }
            };
            // ext-libraries.md, "Storing": the library's quota over all its
            // spaces, the event's bytes held for it until it is durable.
            if libraries {
                reserved = match self.library_reserve(&space_id, &event, signed.len() as u64) {
                    Ok(reserved) => Some(reserved),
                    Err((reason, _)) => return StoreAnswer::Refused(reason),
                };
            }
            // Rates, per author per space and, apart, per entry: the entry
            // whose upload key the connection proved (peers.md, 3.20 Quotas
            // and rates). An import's stores count toward no rate: the
            // quota and the import's end bound them.
            let (span, limit) = match event.kind() {
                _ if importing => (0, usize::MAX),
                kind::SPACE => (3600, settings.rates.space_events_per_hour),
                kind::STORAGE => (3600, settings.rates.storage_events_per_hour),
                _ => (0, usize::MAX),
            };
            if span > 0 {
                let at = now.timeline;
                let by_author = (*event.author(), event.kind());
                let by_entry = grant.upload.map(|upload| (upload, event.kind()));
                let author_room = state
                    .rates
                    .entry(by_author)
                    .or_default()
                    .room(at, span, limit);
                let entry_room = by_entry.is_none_or(|key| {
                    state
                        .entry_rates
                        .entry(key)
                        .or_default()
                        .room(at, span, limit)
                });
                if !(author_room && entry_room) {
                    return StoreAnswer::Refused(Code::RateLimited.name().into());
                }
                state.rates.entry(by_author).or_default().count(at);
                if let Some(key) = by_entry {
                    state.entry_rates.entry(key).or_default().count(at);
                }
            }
            let space = state.held();
            // peers.md, "What a peer checks before it stores a skeleton
            // event".
            let checked = match space.check_skeleton(&event) {
                Ok(checked) => checked,
                Err(refusal) => return StoreAnswer::Refused(space::reason(refusal)),
            };
            // The provisional pseudonym's enrolment, accepted.
            if grant.provisional.is_some() && checked.enrols != grant.pseudonym {
                return StoreAnswer::Refused(Code::NotAuthorized.name().into());
            }
            // peers.md, "Skeleton cuts", what a late enrolment opens: a
            // connection that presents a late pseudonym, or whose
            // provisional pseudonym's enrolment is late, may store only that
            // pseudonym's late skeleton events, each with no effect.
            if let Some(pseudonym) = grant.pseudonym {
                let late_connection = space.is_late_pseudonym(&pseudonym)
                    || (grant.provisional.is_some() && checked.late);
                if late_connection && !(checked.late && *event.author() == pseudonym) {
                    return StoreAnswer::Refused(Code::NotAuthorized.name().into());
                }
            }
            // 7. Store.
            let index = space.next_index;
            let mut puts = vec![(Records::journal_address(&space_id, index), op.encode())];
            if importing {
                puts.push((
                    Records::journal_address(&space_id, index + 1),
                    Op::Imported { event: id }.encode(),
                ));
            }
            (puts, index, op)
        };
        // Durable before anything else sees it.
        if let Err(error) = self.commit_space(&writing, puts, Vec::new()).await {
            log(format_args!("a store was not kept: {error}"));
            return StoreAnswer::Refused("busy".into());
        }
        grant.stored_any = true;
        if grant.provisional.take().is_some() {
            self.admin(link, space_id, *event.author());
        }
        let outcome = {
            let mut state = writing.state();
            let space = state.held();
            if importing {
                space.imported.insert(id);
                space.next_index = index + 2;
            }
            // A rotation past the cap, or evidence of a fork, retires
            // entries (peers.md, 3.4 and 3.6).
            let before = Liveness::of(&space.entries);
            let placed = space.apply(index, &op, Some(event.clone()));
            if before.retired_in(&space.entries) {
                self.retired(space_id, Some(&space.entries));
            }
            space.refresh();
            let outcome = space.outcome(id, placed.clone());
            self.deliver(space, &placed, link, id);
            self.note(space);
            outcome
        };
        drop(reserved);
        if matches!(event.kind(), kind::STORAGE | kind::UNIT) {
            self.sweep_space(&writing, now).await;
        }
        if let Some(space) = &writing.state().space {
            self.send_awaiting(space, now);
        }
        if event.kind() == kind::STORAGE
            && frasil_peers::body::StorageBody::read(event.unverified_body()).is_err_and(|class| {
                class.shared() == Some(frasil_base::ErrorClass::ExtensionRequired)
            })
        {
            return StoreAnswer::Held(Some(Code::ExtensionRequired.name()));
        }
        match outcome {
            Stored::Placed(_) => StoreAnswer::Acknowledge(id),
            Stored::Conflict(_) => StoreAnswer::Held(Some(Code::Conflict.name())),
            Stored::Pending | Stored::Retry { .. } => StoreAnswer::Held(None),
        }
    }

    /// peers.md, "Hosting a space": a create, by the space's genesis; with
    /// ext-libraries.md, also an import's genesis.
    /// `shard` is the shard that keeps the space's records from then on.
    pub(crate) async fn create(
        &self,
        writing: &Writing,
        genesis: Event,
        signed: &[u8],
        now: Reading,
        shard: String,
        imported: bool,
    ) -> StoreAnswer {
        // The genesis's sight is on the timeline of the shard that keeps
        // the space from now on (overview.md, 6.7).
        let now = self.shard_now(&shard, now);
        // A core peer's policy; with ext-libraries.md, a ticket or the open
        // library decided it before.
        if self.settings.hosting == Hosting::Closed && !self.settings.extensions.libraries {
            return StoreAnswer::Refused(Code::NoLibrary.name().into());
        }
        let id = genesis.id();
        if let Err(class) = frasil_keys::body::VisiblePart::read(
            genesis.unverified_body(),
            genesis.author(),
            genesis.seq(),
        ) {
            return StoreAnswer::Refused(space::reason(Refusal::Class(class.into())));
        }
        let mut space = match Space::create(genesis.clone(), Rules::of(&self.settings)) {
            Ok(space) => space,
            Err(refusal) => return StoreAnswer::Refused(space::reason(refusal)),
        };
        let op = Op::Event {
            signed: signed.to_vec(),
            sight: now,
            entry: None,
        };
        #[allow(unused_mut)]
        let mut journal = vec![(Records::journal_address(&id, 0), op.encode())];
        // An import's genesis adds its entry retired, source `import`.
        if imported {
            journal.push((
                Records::journal_address(&id, 1),
                Op::Imported { event: id }.encode(),
            ));
            space.imported.insert(id);
            space.next_index = 2;
        }
        let tail: u64 = journal
            .iter()
            .map(|(address, record)| (address.len() + record.len()) as u64)
            .sum();
        let mut puts = journal;
        puts.push((Records::hosted_address(&id), Records::hosted_record(&shard)));
        // The index names the space once: of two creates of one space
        // through two shards, the index's shard keeps the first, and the
        // other's records are collected from its shard (crate `shards`,
        // "Commits across shards").
        let expect = vec![(Records::hosted_address(&id), None)];
        match self
            .commit_space_if(writing, puts, Vec::new(), expect)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                // An import needs the space new to the peer (ext-libraries.md,
                // 3.3 Attaching).
                if imported {
                    return StoreAnswer::Refused(
                        frasil_libraries::LibraryClass::SpaceExists.code().into(),
                    );
                }
                return self.created_elsewhere(id);
            }
            Err(error) => {
                log(format_args!("a create was not kept: {error}"));
                return StoreAnswer::Refused("busy".into());
            }
        }
        // The genesis is placed by `Space::create`; its record adds the
        // genesis's entry.
        space.apply_genesis_record(0, &op);
        space.refresh();
        self.install_created(writing, space, tail);
        StoreAnswer::Acknowledge(id)
    }

    /// A create another shard made first: the peer hosts the space there,
    /// and this node notes where.
    fn created_elsewhere(&self, id: EventId) -> StoreAnswer {
        if let Some(shards) = &self.shards
            && let Err(error) = crate::spaces::blocking_here(|| shards.locate_fresh(id.as_bytes()))
        {
            log(format_args!("a space's placement was not read: {error}"));
        }
        lock(&self.index).hosted.insert(id);
        StoreAnswer::Elsewhere(id)
    }

    /// Sends newly stored events to the connections subscribed to them
    /// (units.md, 3.14 Sync): the event `sent` to every other connection,
    /// and the pending events it released to every connection, the
    /// sender's too, which did not send them.
    fn deliver(&self, space: &Space, placed: &[EventId], from: u64, sent: EventId) {
        let released = space.released_streams();
        let events: Vec<&Event> = placed
            .iter()
            .filter(|&&id| space.servable(id, &released))
            .filter_map(|&id| space.log.event(id))
            .collect();
        if events.is_empty() {
            return;
        }
        let links = lock(&self.links);
        let Some(subscribers) = links.subscribers.get(&space.id) else {
            return;
        };
        for (&number, filter) in subscribers {
            let Some(link) = links.links.get(&number) else {
                continue;
            };
            let chosen: Vec<Vec<u8>> = events
                .iter()
                .filter(|event| number != from || event.id() != sent)
                .filter(|event| match (filter, space.units.get(&event.id())) {
                    (None, _) | (Some(_), None) => true,
                    (Some(streams), Some(unit)) => streams.contains(&unit.stream),
                })
                .map(|event| event.signed())
                .collect();
            for message in crate::sync::events_messages(space.id, chosen) {
                if !link.offer(Outgoing::Sync(space.id, message)) {
                    log("a live delivery was dropped: the connection's queue is full");
                }
            }
        }
    }

    /// A connection joins a space's ephemeral channel (ext-ephemeral.md,
    /// "Relaying"), with its first `Subscribe` or `Ephemeral` there; it is
    /// sent the ephemeral slot frames held, with their origins.
    pub(crate) fn ephemeral_join(&self, link: u64, space: EventId) {
        let Ok(origin) = frasil_crypto::random_bytes::<8>() else {
            return;
        };
        let mut relays = lock(&self.relays);
        let out = relays.channel(space).join_with(link, *origin);
        relays.note(link, space);
        self.send_relayed(space, out);
    }

    /// A frame a connection with the space's `live` right sent: forwarded
    /// to every other connection on the channel, with its origin. A frame
    /// whose outer map does not read is dropped.
    pub(crate) fn ephemeral_frame(&self, link: u64, space: EventId, outer: &[u8]) {
        let Ok(origin) = frasil_crypto::random_bytes::<8>() else {
            return;
        };
        let mut relays = lock(&self.relays);
        match relays.channel(space).frame_with(link, outer, *origin) {
            Ok(out) => {
                relays.note(link, space);
                self.send_relayed(space, out);
            }
            Err(_) => {
                if relays
                    .channels
                    .get(&space)
                    .is_some_and(|relay| relay.is_empty())
                {
                    relays.channels.remove(&space);
                }
            }
        }
    }

    /// A connection leaves a space's channel: closed, or without its
    /// `live` right. The channel goes once no connection is on it.
    pub(crate) fn ephemeral_leave(&self, link: u64, space: EventId) {
        let mut relays = lock(&self.relays);
        let out = relays.leave(link, space);
        self.send_relayed(space, out);
    }

    fn send_relayed(&self, space: EventId, out: Vec<frasil_ephemeral::relay::Relayed<u64>>) {
        let links = lock(&self.links);
        for relayed in out {
            let Some(link) = links.links.get(relayed.to()) else {
                continue;
            };
            // Lossy: a queue under pressure drops the frame, never another
            // message (`offer`). `Gone` is of the control class, which the
            // iroh binding's ephemeral path does not carry (transport.md, 2.3
            // Frames and stream classes).
            let message = relayed.message(space.as_bytes());
            let out = match relayed {
                frasil_ephemeral::relay::Relayed::Gone { .. } => Outgoing::Control(message),
                frasil_ephemeral::relay::Relayed::Frame { .. } => Outgoing::Ephemeral(message),
            };
            let _ = link.offer(out);
        }
    }

    /// Live delivery for a connection (units.md's `Subscribe`).
    pub(crate) fn subscribe(&self, link: u64, space: EventId, streams: Option<Vec<StreamId>>) {
        let mut links = lock(&self.links);
        let Some(entry) = links.links.get_mut(&link) else {
            return;
        };
        entry.subscriptions.insert(space);
        links
            .subscribers
            .entry(space)
            .or_default()
            .insert(link, streams);
    }

    /// Sends `Awaiting` to each administration connection of a space whose
    /// list changed (transport.md, "Presenting credentials"). The skeleton
    /// is resolved once for all of them, outside the connections' lock.
    fn send_awaiting(&self, space: &Space, now: Reading) {
        let admins: Vec<(u64, DeviceId)> = {
            let links = lock(&self.links);
            let Some(admins) = links.admins.get(&space.id) else {
                return;
            };
            admins
                .iter()
                .filter_map(|number| {
                    let (admin_space, pseudonym) = links.links.get(number)?.admin?;
                    (admin_space == space.id).then_some((*number, pseudonym))
                })
                .collect()
        };
        if admins.is_empty() {
            return;
        }
        let now = self.space_now(&space.id, now);
        // ext-libraries.md, "Settings": a library's T applies to its spaces.
        let timeout = self.erasure_timeout(&space.id);
        let lists: BTreeMap<DeviceId, Vec<EventId>> = {
            let skeleton = space.skeleton();
            let before = space.waiting_before(&skeleton);
            space.awaiting_lists(
                &skeleton,
                before.as_ref(),
                admins
                    .iter()
                    .map(|(_, pseudonym)| *pseudonym)
                    .collect::<BTreeSet<_>>(),
                now,
                timeout,
            )
        };
        // The held cuts the space keeps, from its index: no event's body is
        // read again for each report.
        let held_cut = space
            .held_cuts
            .iter()
            .copied()
            .find(|&id| space.log.event(id).is_some());
        let mut links = lock(&self.links);
        for (number, pseudonym) in admins {
            let Some(link) = links.links.get_mut(&number) else {
                continue;
            };
            if let Some(cut) = held_cut
                && !link.extension_notified
            {
                let message = frasil_transport::messages::EventRefused {
                    space: space.id.0,
                    event: cut.0,
                    code: Code::ExtensionRequired.name().to_owned(),
                }
                .encode();
                if link.offer(Outgoing::Control(message)) {
                    link.extension_notified = true;
                }
            }
            let Some(ids) = lists.get(&pseudonym) else {
                continue;
            };
            if link.awaiting.as_ref() == Some(ids) {
                continue;
            }
            let message = Awaiting {
                space: *space.id.as_bytes(),
                ids: ids.iter().map(|id| *id.as_bytes()).collect(),
            }
            .encode();
            if link.offer(Outgoing::Control(message)) {
                link.awaiting = Some(ids.clone());
            }
        }
    }

    // -- The sweep

    /// Judges and carries out what waits in every space that may hold
    /// something to judge (peers.md, "Erasure" to "Collection", and
    /// "Objects"), then closes the spaces idle long enough. Returns the
    /// object pieces to delete.
    pub(crate) async fn sweep(&self, now: Reading) -> Vec<String> {
        let mut pieces = Vec::new();
        for id in self.to_sweep() {
            if !self.keeps_space(&id) {
                continue;
            }
            let writing = match self.write(id).await {
                Ok(writing) => writing,
                Err(error) => {
                    log(format_args!("a space did not open for its sweep: {error}"));
                    continue;
                }
            };
            pieces.extend(self.sweep_space(&writing, now).await);
            if let Some(space) = &writing.state().space {
                self.send_awaiting(space, now);
            }
        }
        self.sweep_uploads(now.timeline);
        self.sweep_mailboxes(now).await;
        if self.settings.extensions.deposit_tokens {
            self.sweep_deposit_tokens(now).await;
        }
        // In a cluster, each node sweeps the drops and holds of the spaces
        // it keeps, and one node what belongs to no shard it can name.
        if self.settings.extensions.invite_links {
            self.sweep_drops(now).await;
        }
        if self.settings.extensions.libraries {
            if self.sweeps_shared() {
                self.sweep_libraries(now).await;
            }
            pieces.extend(self.sweep_holds(now).await);
            pieces.extend(self.sweep_copies().await);
        }
        self.close_idle(false).await;
        pieces
    }

    /// The sweep of one space, held for writing. Returns the object pieces
    /// to delete.
    pub(crate) async fn sweep_space(&self, writing: &Writing, now: Reading) -> Vec<String> {
        let now = self.space_now(&writing.id, now);
        let settings = self.sweep_settings(&writing.id);
        let removal = {
            let mut state = writing.state();
            let Some(space) = state.space.as_mut() else {
                return Vec::new();
            };
            if !space.waits() {
                return Vec::new();
            }
            // A credentials request carried out retires entries (peers.md,
            // 3.17 Credentials requests).
            let before = Liveness::of(&space.entries);
            let removal = space.sweep(now, &settings);
            if removal.is_empty() {
                space.refresh();
                self.note(space);
                return Vec::new();
            }
            (removal, before.retired_in(&space.entries))
        };
        let (removal, retiring) = removal;
        let pieces = match self.remove(writing, removal).await {
            Ok(pieces) => pieces,
            Err(error) => {
                log(format_args!("a sweep was not kept: {error}"));
                Vec::new()
            }
        };
        if retiring && let Some(space) = writing.state().space.as_ref() {
            self.retired(writing.id, Some(&space.entries));
        }
        pieces
    }

    /// Makes a sweep's removal at rest, then rebuilds the space from its
    /// records. Returns the object pieces to delete.
    pub(crate) async fn remove(
        &self,
        writing: &Writing,
        removal: Removal,
    ) -> Result<Vec<String>, StoreError> {
        // Unsettled until the space is rebuilt: a writer dropped meanwhile
        // leaves it to open from its records.
        writing.unsettle();
        let removed = self.removing(writing, removal).await;
        writing.settled();
        removed
    }

    async fn removing(
        &self,
        writing: &Writing,
        #[allow(unused_mut)] mut removal: Removal,
    ) -> Result<Vec<String>, StoreError> {
        let space_id = writing.id;
        // ext-libraries.md, 3.8 Keeping a held object: collection, a
        // reclaimed release and orphan_grace leave an object a hold keeps.
        if self.settings.extensions.libraries && removal.erase_space.is_none() {
            let state = writing.state();
            if let Some(space) = &state.space {
                removal
                    .objects
                    .retain(|locator| !self.kept_by_hold(space, locator));
            }
        }
        let piece_keys = |locator: &Locator, record: &ObjectRecord| -> Vec<String> {
            record
                .pieces
                .iter()
                .map(|&piece| crate::objects::piece_key(space_id.as_bytes(), locator, piece))
                .collect()
        };
        if let Some(erasure) = removal.erase_space {
            // The space's erasure: a tombstone, and nothing else.
            let pieces: Vec<String> = {
                let state = writing.state();
                state.space.as_ref().map_or_else(Vec::new, |space| {
                    space
                        .objects
                        .iter()
                        .flat_map(|(locator, record)| piece_keys(locator, record))
                        .collect()
                })
            };
            let records = self.records.clone();
            let deletes = blocking(move || records.space_addresses(&space_id)).await?;
            self.writer
                .commit(
                    vec![(Records::tombstone_address(&space_id), erasure.clone())],
                    deletes,
                )
                .await?;
            self.forget_space(writing);
            if self.settings.extensions.invite_links {
                self.erase_drops(&space_id);
            }
            self.tombstones
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(space_id, erasure);
            // Every right held in the space ends, its transfer tokens too
            // (peers.md, 3.6 Retirement and the cap, "Connections").
            self.retired(space_id, None);
            return Ok(pieces);
        }
        let through = self.through(writing);
        let (puts, deletes, folded, pieces, index, written) = {
            let state = writing.state();
            let Some(space) = &state.space else {
                return Ok(Vec::new());
            };
            let mut puts = Vec::new();
            let mut deletes = Vec::new();
            let mut written = Vec::new();
            let mut index = space.next_index;
            for op in removal
                .ops
                .iter()
                .cloned()
                .chain(removal.stubs.iter().map(|stub| Op::Stub(*stub)))
            {
                puts.push((Records::journal_address(&space_id, index), op.encode()));
                written.push((index, op));
                index += 1;
            }
            // A removed event's record in the journal goes. If the
            // snapshot holds one, a new snapshot leaves out every removed
            // record, those of the journal after it too.
            let mut removed = BTreeSet::new();
            for id in &removal.events {
                if let Some(&at) = space.journal_of.get(id) {
                    deletes.push(Records::journal_address(&space_id, at));
                    removed.insert(at);
                }
            }
            let folded = if removed.iter().any(|&at| at < through) {
                removed
            } else {
                BTreeSet::new()
            };
            let mut pieces = Vec::new();
            for locator in &removal.objects {
                if let Some(record) = space.objects.get(locator) {
                    pieces.extend(piece_keys(locator, record));
                }
                deletes.push(Records::object_address(&space_id, locator));
            }
            (puts, deletes, folded, pieces, index, written)
        };
        if folded.is_empty() {
            self.commit_space(writing, puts, deletes).await?;
        } else {
            self.fold(writing, folded, puts, deletes).await?;
        }
        if removal.events.is_empty() && removal.objects.is_empty() && removal.stubs.is_empty() {
            // Only records of requests carried out: nothing to rebuild.
            let mut state = writing.state();
            if let Some(space) = state.space.as_mut() {
                // Their effects are made; the records join the journal the
                // space keeps.
                space.ops.extend(written);
                space.next_index = index;
                space.refresh();
                self.note(space);
            }
            return Ok(pieces);
        }
        if let Err(error) = self.rebuild(writing).await {
            log(format_args!("a space was not rebuilt: {error}"));
            writing.unload();
        }
        {
            let mut uploads = lock(&self.uploads);
            for locator in &removal.objects {
                uploads.forget(&space_id, locator);
            }
        }
        Ok(pieces)
    }

    // -- Mailboxes (transport.md, "Mailboxes")

    /// The part a device mailbox's items count in: its shard, or every
    /// mailbox's one part when the records are in no shards.
    pub(crate) fn mail_part(&self, address: &[u8; 32]) -> String {
        mail_part(self.shards.is_some(), address)
    }

    /// Counts a device-mailbox deposit from `source`: false once it made
    /// the operator's `deposits_per_minute` in the last minute
    /// (transport.md, 3.14 Mailboxes: deposits are "subject to the peer's
    /// rate limits").
    pub(crate) fn admit_deposit(&self, source: &str, now: Reading) -> bool {
        lock(&self.deposits).admit(
            source,
            now.timeline,
            self.settings.device_mail.deposits_per_minute,
        )
    }

    /// A deposit: the item's ID, once it is durable.
    pub(crate) async fn mailbox_put(
        &self,
        kind: Kind,
        address: &[u8; 32],
        item: &[u8],
        source: &str,
        now: Reading,
    ) -> Result<[u8; 16], Reason> {
        if item.len() > frasil_transport::frame::MAILBOX_ITEM_BYTES {
            return Err(("too_large".into(), 413));
        }
        match kind {
            Kind::Exchange => {
                let read = frasil_admission::message::read_message(item).map_err(admission)?;
                let request = read.request;
                if frasil_admission::mailbox::exchange_address(&request) != *address {
                    return Err(("malformed".into(), 400));
                }
                let wall = now.wall.or_else(wall_now).unwrap_or(0);
                let kind = read.kind.code();
                // Kept at rest, so that the mailbox outlives a restart and
                // its shard can be kept by another machine.
                let pending = {
                    let mut mail = lock(&self.mail);
                    crate::source::exchange_put(&mut mail.exchange, source, item, wall)
                        .map_err(admission)?;
                    mail.exchange_requests.insert(*address, request);
                    mail.exchange_kinds
                        .entry(*address)
                        .or_default()
                        .insert(kind);
                    mail.changes += 1;
                    self.writer.submit(Commit::new(
                        vec![(
                            Records::exchange_address(address, kind),
                            Records::exchange_record(wall, source, item),
                        )],
                        Vec::new(),
                    ))
                };
                made(pending.await).map_err(|_| ("busy".to_owned(), 503))?;
                let mut id = [0u8; 16];
                id[15] = kind;
                Ok(id)
            }
            Kind::Device => self.device_put(address, item, false, now).await,
            // ext-invite-links.md: a drop is placed only over the WebSocket.
            Kind::Drop if self.settings.extensions.invite_links => {
                let (code, status) = frasil_transport::ext_invite_links::POST_REFUSED;
                Err((code.into(), status))
            }
            Kind::Drop => Err(("not_found".into(), 404)),
            Kind::Person => Err(("not_found".into(), 404)),
        }
    }

    /// Whether a token deposit of `len` bytes into a device mailbox has
    /// room (ext-deposit-tokens.md, 3.7 Redeeming, step 7), changing
    /// nothing.
    pub(crate) fn device_room(&self, address: &[u8; 32], len: usize, now: Reading) -> bool {
        let part = self.mail_part(address);
        lock(&self.mail).devices.room(
            &part,
            address,
            len,
            true,
            now.timeline,
            self.settings.mailbox_retention,
        )
    }

    /// The items of a device mailbox, as memory keeps them.
    #[cfg(test)]
    pub(crate) fn mail_items_for_test(&self, address: &[u8; 32]) -> Vec<Held> {
        lock(&self.mail)
            .devices
            .items(&self.mail_part(address), address)
    }

    /// A collection of a device mailbox that passed the checks.
    #[cfg(test)]
    pub(crate) fn claim_for_test(&self, address: &[u8; 32], now: Reading) {
        let part = self.mail_part(address);
        let mut mail = lock(&self.mail);
        self.record_collection(&mut mail, &part, address, now);
    }

    /// A deposit in a device mailbox, a token paying for it or not
    /// (crate `device_mail`): the item's ID, once it and its evictions are
    /// durable.
    pub(crate) async fn device_put(
        &self,
        address: &[u8; 32],
        item: &[u8],
        paid: bool,
        now: Reading,
    ) -> Result<[u8; 16], Reason> {
        let part = self.mail_part(address);
        let retention = self.settings.mailbox_retention;
        let (id, pending) = {
            let mut guard = lock(&self.mail);
            let mail = &mut *guard;
            let id = mail.next_item.to_be_bytes();
            let evicted = mail
                .devices
                .deposit(
                    &part,
                    *address,
                    id,
                    item.len(),
                    paid,
                    now.timeline,
                    retention,
                )
                .map_err(|_| ("busy".to_owned(), 503))?;
            let unclaimed = !mail.devices.is_claimed(address, now.timeline, retention);
            mail.next_item += 1;
            let deletes: Vec<Vec<u8>> = evicted
                .iter()
                .map(|(at, old)| Records::mailbox_address(at, old))
                .collect();
            mail.changes += 1;
            let kept = crate::records::MailboxItem {
                sight: now.timeline,
                paid,
                unclaimed,
            };
            // Submitted in the mailboxes' order.
            let pending = self.writer.submit(Commit::new(
                vec![(
                    Records::mailbox_address(address, &id),
                    Records::mailbox_record(kept, item),
                )],
                deletes,
            ));
            (id, pending)
        };
        if made(pending.await).is_err() {
            // Not kept: memory forgets it too.
            let mut mail = lock(&self.mail);
            if mail.devices.remove(&part, address, &id) {
                mail.changes += 1;
            }
            return Err(("busy".to_owned(), 503));
        }
        Ok(id)
    }

    /// A collection: the items after `after`, oldest first. A device
    /// mailbox is collected only by its device's signature over the
    /// connection's `binding`, with the device's `ed || kc`, whose device
    /// ID the address hashes (transport.md, 3.14 Collecting a device
    /// mailbox).
    pub(crate) fn mailbox_get(
        &self,
        kind: Kind,
        address: &[u8; 32],
        after: Option<&[u8; 16]>,
        collector: Option<(&[u8; 64], &[u8], &[u8; 32])>,
        now: Reading,
    ) -> Result<Items, Reason> {
        match kind {
            Kind::Exchange => {
                let wall = now.wall.or_else(wall_now).unwrap_or(0);
                let mut mail = lock(&self.mail);
                mail.exchange.sweep(wall);
                let Some(request) = mail.exchange_requests.get(address).copied() else {
                    return Ok(Vec::new());
                };
                let Some((messages, _)) = mail.exchange.read(&request) else {
                    return Ok(Vec::new());
                };
                let mut out = Vec::new();
                for message in messages {
                    let Ok(read) = frasil_admission::message::read_message(message) else {
                        continue;
                    };
                    let mut id = [0u8; 16];
                    id[15] = read.kind.code();
                    if after.is_some_and(|after| id <= *after) {
                        continue;
                    }
                    out.push((id, message.to_vec()));
                }
                Ok(out)
            }
            Kind::Device => {
                let Some((key, signature, binding)) = collector else {
                    return Err(("credential_refused".into(), 403));
                };
                let checked =
                    mailbox::check_collect(address, key, signature, binding).map_err(|class| {
                        let code = class.code().map_or("malformed", |code| code.name());
                        let status = frasil_transport::codes::reason_status(code).unwrap_or(400);
                        (code.to_owned(), status)
                    })?;
                self.device_items(&checked, after, now)
            }
            // ext-invite-links.md: a drop, served to anyone who names it.
            Kind::Drop if self.settings.extensions.invite_links => {
                Ok(self.drop_items(address, after, now))
            }
            Kind::Drop => Err(("not_found".into(), 404)),
            Kind::Person => Err(("not_found".into(), 404)),
        }
    }

    /// A device mailbox's items after `after`, for a collection that
    /// passed transport.md's checks, which only
    /// [`mailbox::check_collect`] makes: the mailbox is claimed from it,
    /// and its items are read from the records.
    fn device_items(
        &self,
        checked: &mailbox::CheckedCollection,
        after: Option<&[u8; 16]>,
        now: Reading,
    ) -> Result<Items, Reason> {
        let address = checked.address();
        let part = self.mail_part(address);
        let held = {
            let mut mail = lock(&self.mail);
            self.record_collection(&mut mail, &part, address, now);
            mail.devices.after(&part, address, after)
        };
        // Read from the records. An item whose deposit is not yet durable
        // ends the answer, so that a collector reading after a later ID
        // does not pass it by.
        crate::spaces::blocking_here(|| {
            let mut items = Vec::with_capacity(held.len());
            for held in held {
                match self.records.mailbox_item(address, &held.id) {
                    Ok(Some(item)) => items.push((held.id, item)),
                    Ok(None) => break,
                    Err(error) => {
                        log(format_args!("a mailbox item was not read: {error}"));
                        return Err(("busy".to_owned(), 503));
                    }
                }
            }
            Ok(items)
        })
    }

    /// Records a collection that passed the checks (transport.md, "Claimed
    /// device mailboxes"): the mailbox is claimed from it. Its claim is
    /// written as it begins, and then at most once an hour, so that it
    /// survives a restart within an hour of its last collection; it is
    /// not awaited, and the writer keeps its order.
    fn record_collection(&self, mail: &mut Mail, part: &str, address: &[u8; 32], now: Reading) {
        let before = mail.devices.claim(address);
        let (claim, began) = mail.devices.collect(
            part,
            *address,
            now.timeline,
            self.settings.mailbox_retention,
        );
        let stale =
            before.is_none_or(|old| claim.last.saturating_sub(old.last) >= CLAIM_KEPT_EVERY);
        if began || stale {
            mail.changes += 1;
            drop(self.writer.submit(Commit::new(
                vec![(
                    Records::claim_address(address),
                    Records::claim_record(claim.last, claim.since),
                )],
                Vec::new(),
            )));
        }
    }

    /// Drops device-mailbox items no longer kept (transport.md, "Claimed
    /// device mailboxes": `mailbox_retention`, or `uncollected_retention`
    /// for an item that came while its mailbox was not claimed and was not
    /// collected by then), the claims that lapsed, and exchange mailboxes
    /// past their lifetime.
    async fn sweep_mailboxes(&self, now: Reading) {
        let retention = self.settings.mailbox_retention;
        lock(&self.deposits).prune(now.timeline);
        lock(&self.refused_tokens).prune(now.timeline);
        let pending = {
            let mut guard = lock(&self.mail);
            let mail = &mut *guard;
            let mut deletes = Vec::new();
            let keeps = |address: &[u8; 32]| self.keeps_address("mailboxes", address);
            let old = mail.devices.expired(
                keeps,
                now.timeline,
                retention,
                self.settings.uncollected_retention,
            );
            for (address, id) in old {
                mail.devices
                    .remove(&self.mail_part(&address), &address, &id);
                deletes.push(Records::mailbox_address(&address, &id));
            }
            let lapsed = mail.devices.lapse(
                |address| (keeps(address), self.mail_part(address)),
                now.timeline,
                retention,
            );
            deletes.extend(lapsed.iter().map(Records::claim_address));
            if let Some(wall) = now.wall.or_else(wall_now) {
                mail.exchange.sweep(wall);
            }
            // An exchange mailbox past its lifetime: its messages at rest go.
            let gone: Vec<[u8; 32]> = mail
                .exchange_requests
                .iter()
                .filter(|(address, _)| self.keeps_address("exchange", address))
                .filter(|(_, request)| mail.exchange.read(request).is_none())
                .map(|(address, _)| *address)
                .collect();
            for address in gone {
                mail.exchange_requests.remove(&address);
                for kind in mail.exchange_kinds.remove(&address).unwrap_or_default() {
                    deletes.push(Records::exchange_address(&address, kind));
                }
            }
            if !deletes.is_empty() {
                mail.changes += 1;
            }
            (!deletes.is_empty()).then(|| self.writer.submit(Commit::new(Vec::new(), deletes)))
        };
        if let Some(pending) = pending
            && let Err(error) = made(pending.await)
        {
            log(format_args!("a mailbox sweep was not kept: {error}"));
        }
    }

    // -- Objects

    /// Why an object route of a space is refused before its rights: the
    /// space erased, or not hosted (peers.md, "Objects").
    pub(crate) fn object_refusal(&self, space_id: &EventId) -> Option<Reason> {
        if self.tombstoned(space_id) {
            return Some((Code::Erased.name().into(), 410));
        }
        (!self.hosts(space_id)).then(|| (Code::NoLibrary.name().into(), 507))
    }

    /// Updates, or forgets, an object's index entry at rest and in memory,
    /// as `change` decides from the entry held: the new entry, or `None` to
    /// forget it, and what to answer.
    ///
    /// # Errors
    ///
    /// `change`'s refusal; `busy` if the records cannot be written;
    /// `no_library` for a space the peer no longer hosts.
    pub(crate) async fn update_object<T>(
        &self,
        space_id: EventId,
        locator: Locator,
        change: impl FnOnce(Option<&ObjectRecord>) -> Result<(Option<ObjectRecord>, T), Reason>,
    ) -> Result<T, Reason> {
        let busy = || ("busy".to_owned(), 503);
        let writing = self.write(space_id).await.map_err(|_| busy())?;
        let (record, answer) = {
            let state = writing.state();
            let Some(space) = &state.space else {
                return Err((Code::NoLibrary.name().into(), 507));
            };
            change(space.objects.get(&locator))?
        };
        let address = Records::object_address(&space_id, &locator);
        let (puts, deletes) = match &record {
            Some(record) => (vec![(address, record.encode())], Vec::new()),
            None => (Vec::new(), vec![address]),
        };
        self.commit_space(&writing, puts, deletes)
            .await
            .map_err(|_| busy())?;
        let mut state = writing.state();
        if let Some(space) = state.space.as_mut() {
            match record {
                Some(mut record) => {
                    if record.complete
                        && space
                            .units
                            .values()
                            .any(|unit| unit.objects.contains(&locator))
                    {
                        record.referenced = true;
                    }
                    space.objects.insert(locator, record);
                }
                None => {
                    space.objects.remove(&locator);
                }
            }
            space.refresh();
            self.note(space);
        }
        Ok(answer)
    }

    /// The space whose stored bytes an object route of a space reads: the
    /// space itself, or, for an object a hold of the space names, the
    /// hold's source (ext-libraries.md, 3.9 Fetching a held object).
    pub(crate) async fn object_home(&self, space_id: &EventId, locator: &Locator) -> EventId {
        if self.settings.extensions.libraries
            && !self
                .read(*space_id, |space| space.objects.contains_key(locator))
                .await
                .unwrap_or(false)
            && let Some(source) = self.held_source(space_id, locator).await
        {
            return source;
        }
        *space_id
    }

    /// Whether an object may be fetched: complete, and not only referenced
    /// by units of released streams. Returns the space whose stored bytes
    /// hold it, as [`Self::object_home`] finds it, and its record.
    pub(crate) async fn object_fetchable(
        &self,
        space_id: &EventId,
        locator: &Locator,
    ) -> Result<(EventId, ObjectRecord), Reason> {
        if let Some(refusal) = self.object_refusal(space_id) {
            return Err(refusal);
        }
        // A hold that points at a copy is served from it (ext-libraries.md,
        // 3.9 Fetching a held object).
        let copied = if !self.settings.extensions.libraries
            || self
                .read(*space_id, |space| space.objects.contains_key(locator))
                .await
                .unwrap_or(false)
        {
            None
        } else {
            self.held_copy(space_id, locator)
        };
        let (home, record) = match copied {
            Some(copied) => copied,
            None => {
                let home = self.object_home(space_id, locator).await;
                match self
                    .read(home, |held| {
                        held.objects.get(locator).filter(|r| r.complete).cloned()
                    })
                    .await
                    .flatten()
                {
                    Some(record) => (home, record),
                    None => return Err(("not_found".into(), 404)),
                }
            }
        };
        self.read(*space_id, |space| {
            let released = space.released_streams();
            let referencing: Vec<&crate::space::UnitIndex> = space
                .units
                .values()
                .filter(|unit| unit.objects.contains(locator))
                .collect();
            if !referencing.is_empty()
                && referencing
                    .iter()
                    .all(|unit| released.contains(&unit.stream))
            {
                return Err((Code::Released.name().into(), 410));
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|| Err((Code::NoLibrary.name().into(), 507)))?;
        Ok((home, record))
    }

    /// The layout of an object being uploaded, once its header is known.
    pub(crate) fn layout(
        &self,
        space: EventId,
        locator: &Locator,
    ) -> Option<crate::objects::Layout> {
        let now = self.clock.now().timeline;
        let mut uploads = lock(&self.uploads);
        let (front, last) = uploads.layouts.get_mut(&(space, *locator))?;
        *last = now;
        crate::objects::Layout::read(front, locator)
    }

    /// Keeps the layout of an object being uploaded, until the object
    /// completes, its upload is collected, or `orphan_grace` passes with no
    /// use of it.
    pub(crate) fn keep_layout(
        &self,
        space: EventId,
        locator: Locator,
        layout: &crate::objects::Layout,
    ) {
        let mut front = (layout.header.len() as u32).to_be_bytes().to_vec();
        front.extend_from_slice(&layout.header);
        let now = self.clock.now().timeline;
        lock(&self.uploads)
            .layouts
            .insert((space, locator), (front, now));
    }

    /// Checks that `bytes` more of a piece stay within a space's quota with
    /// what it stores, what its uploads stage and the pieces being written,
    /// and holds them until the returned hold drops. Called with the space's
    /// state held, which every such check holds, so that two uploads never
    /// pass the quota together (peers.md, 3.20 Quotas and rates).
    pub(crate) fn hold_piece(&self, space: &Space, bytes: u64) -> Result<PieceHold<'_>, Reason> {
        let mut uploads = lock(&self.uploads);
        let total = space
            .used()
            .saturating_add(uploads.held(&space.id))
            .saturating_add(bytes);
        if total > self.settings.space_quota {
            return Err((Code::QuotaExceeded.name().into(), 507));
        }
        *uploads.writing.entry(space.id).or_default() += bytes;
        Ok(PieceHold {
            core: self,
            space: space.id,
            bytes,
        })
    }

    /// An object completed, or was refused whole: its upload's staged bytes
    /// and layout go.
    pub(crate) fn upload_done(&self, space: &EventId, locator: &Locator) {
        lock(&self.uploads).forget(space, locator);
    }

    /// Drops the staged bytes and layouts of uploads unused for
    /// `orphan_grace` (peers.md, 3.8 Objects, "Orphans": an upload left
    /// incomplete is collected).
    fn sweep_uploads(&self, now: u64) {
        let grace = self.settings.orphan_grace;
        let stale = |last: u64| now.saturating_sub(last) >= grace;
        let mut uploads = lock(&self.uploads);
        uploads.staging.retain(|_, staged| !stale(staged.last));
        uploads.layouts.retain(|_, (_, last)| !stale(*last));
    }
}

/// An admission class as a reason code and status.
/// In a cluster (crate `cluster`): what the node keeps of the state that
/// belongs to no one shard is read again as shards move, and the node sweeps
/// only what it keeps.
impl Core {
    /// Whether this node keeps a space's shard: always on one node.
    pub(crate) fn keeps_space(&self, space: &EventId) -> bool {
        self.shards
            .as_ref()
            .is_none_or(|shards| shards.keeps_space(space.as_bytes()))
    }

    /// Whether this node keeps the shard of a mailbox's address, of the
    /// family `mailboxes`, `exchange` or `drops`.
    pub(crate) fn keeps_address(&self, family: &str, address: &[u8; 32]) -> bool {
        self.shards
            .as_ref()
            .is_none_or(|shards| shards.keeps_address(family, address))
    }

    /// Whether this node runs the sweeps of state that belongs to no shard
    /// it can name, such as tickets past their lifetime: on one node; in a
    /// cluster, the owner of the first index shard alone.
    pub(crate) fn sweeps_shared(&self) -> bool {
        self.keeps_address("index", &[0; 32])
    }

    /// Sends a connection something, as a delivery would: false if it is
    /// gone or its queue is full.
    pub(crate) fn send_to(&self, link: u64, out: Outgoing) -> bool {
        lock(&self.links)
            .links
            .get(&link)
            .is_some_and(|entry| entry.offer(out))
    }

    /// A connection stops reaching a space here: its live delivery and its
    /// administration of the space end.
    pub(crate) fn leave_space(&self, link: u64, space: EventId) {
        self.ephemeral_leave(link, space);
        let mut links = lock(&self.links);
        if let Some(entry) = links.links.get_mut(&link) {
            entry.subscriptions.remove(&space);
            entry.live.remove(&space);
            if entry.admin.is_some_and(|(admin, _)| admin == space) {
                entry.admin = None;
            }
        }
        if let Some(subscribers) = links.subscribers.get_mut(&space) {
            subscribers.remove(&link);
            if subscribers.is_empty() {
                links.subscribers.remove(&space);
            }
        }
        if let Some(admins) = links.admins.get_mut(&space) {
            admins.remove(&link);
            if admins.is_empty() {
                links.admins.remove(&space);
            }
        }
    }

    /// Reads what the index keeps of one space again: whether it is
    /// hosted, waits, or is erased, and in which shard. Blocking.
    pub(crate) fn refresh_space(&self, space: &EventId) -> Result<(), StoreError> {
        let hosted = self.records.get(&Records::hosted_address(space))?.is_some();
        let waits = self.records.get(&Records::waits_address(space))?.is_some();
        let tombstone = self.records.get(&Records::tombstone_address(space))?;
        if let Some(shards) = &self.shards {
            shards.locate(space.as_bytes())?;
        }
        {
            let mut index = lock(&self.index);
            if hosted {
                index.hosted.insert(*space);
            } else {
                index.hosted.remove(space);
            }
            if waits && hosted {
                index.waiting.insert(*space);
            }
        }
        let mut tombstones = self
            .tombstones
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match tombstone {
            Some(record) => {
                tombstones.insert(*space, record);
            }
            None => {
                tombstones.remove(space);
            }
        }
        Ok(())
    }

    /// Reads again what memory keeps of the state no one shard holds: the
    /// spaces hosted and waiting, the tombstones, the mailboxes and, with
    /// the extensions, the libraries and drops; and the index's
    /// placements. As shards move between nodes, so that a node that takes
    /// a shard up knows what other nodes wrote for it. Blocking.
    ///
    /// A space created, erased or forgotten here while the records are
    /// read stays as that change left it: the reading may predate it.
    pub(crate) fn reload_shared(&self) -> Result<(), StoreError> {
        if let Some(shards) = &self.shards {
            shards.reload_placements()?;
        }
        let hosted_before = lock(&self.index).hosted.clone();
        let tombstones_before: BTreeSet<EventId> = self
            .tombstones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        let departures_before: BTreeSet<EventId> = self
            .departures
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        let hosted = self.records.hosted_spaces()?;
        let waiting = self.records.waiting_spaces()?;
        let tombstones: BTreeMap<EventId, Vec<u8>> =
            self.records.tombstones()?.into_iter().collect();
        let departures: BTreeMap<EventId, crate::records::Departure> =
            self.records.departures()?.into_iter().collect();
        let extensions = self.settings.extensions;
        // A move memory takes or lets go of while the index is read stays
        // as that change left it (crate `libraries`, module `moves`).
        if extensions.libraries {
            let since = self.moves_reading();
            match self.records.moves() {
                Ok(read) => self.moves_read(since, Some(read.into_iter().collect())),
                Err(error) => {
                    self.moves_read(since, None);
                    return Err(error);
                }
            }
        } else {
            lock(&self.moves).clear();
        }
        {
            let mut index = lock(&self.index);
            let mut hosted = hosted;
            for space in index.hosted.difference(&hosted_before) {
                hosted.insert(*space);
            }
            for space in hosted_before.difference(&index.hosted) {
                hosted.remove(space);
            }
            index.waiting = waiting.intersection(&hosted).copied().collect();
            index.hosted = hosted;
        }
        {
            let mut held = self
                .tombstones
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let mut tombstones = tombstones;
            for (space, record) in held.iter() {
                if !tombstones_before.contains(space) {
                    tombstones.insert(*space, record.clone());
                }
            }
            for space in &tombstones_before {
                if !held.contains_key(space) {
                    tombstones.remove(space);
                }
            }
            *held = tombstones;
        }
        self.reload_mail()?;
        {
            // A hand-over's departure taken here, or ended by an import,
            // while the records were read stays as that change left it.
            let mut held = self
                .departures
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let mut departures = departures;
            for (space, departure) in held.iter() {
                if !departures_before.contains(space) {
                    departures.insert(*space, departure.clone());
                }
            }
            for space in &departures_before {
                if !held.contains_key(space) {
                    departures.remove(space);
                }
            }
            *held = departures;
        }
        if extensions.libraries {
            self.reload_libraries()?;
        }
        if extensions.invite_links {
            self.reload_drops()?;
        }
        Ok(())
    }

    /// The mailboxes read again, for [`Self::reload_shared`]: taken only if
    /// memory did not change meanwhile, once every commit submitted before
    /// the reading was made, and tried again otherwise, as
    /// `reload_libraries` does. Blocking.
    fn reload_mail(&self) -> Result<(), StoreError> {
        for _ in 0..4 {
            let before = lock(&self.mail).changes;
            self.writer.barrier_blocking()?;
            let mut read = Mail::read(
                &self.records,
                self.shards.as_deref(),
                mail_caps(&self.settings, self.shards.is_some()),
                self.clock.now().timeline,
                self.settings.mailbox_retention,
            )?;
            let mut held = lock(&self.mail);
            if held.changes == before {
                read.next_item = read.next_item.max(held.next_item);
                read.changes = before;
                *held = read;
                return Ok(());
            }
        }
        log("the mailboxes changed as they were read again: memory keeps its own");
        Ok(())
    }

    /// ext-invite-links.md: the drops read again, for
    /// [`Self::reload_shared`], as [`Self::reload_mail`] reads the
    /// mailboxes. Blocking.
    fn reload_drops(&self) -> Result<(), StoreError> {
        for _ in 0..4 {
            let before = lock(&self.drops).changes;
            self.writer.barrier_blocking()?;
            let mut read = crate::drops::Drops::open(&self.records)?;
            let mut held = lock(&self.drops);
            if held.changes == before {
                read.changes = before;
                *held = read;
                return Ok(());
            }
        }
        log("the drops changed as they were read again: memory keeps its own");
        Ok(())
    }

    /// ext-libraries.md, 2.5 What a peer keeps: the libraries read again,
    /// for [`Self::reload_shared`]. A change made here as they are read,
    /// such as a create's attachment, is held in memory before its record
    /// is at rest: the reading is taken only if memory did not change
    /// meanwhile, once every commit submitted before it was made, and is
    /// tried again otherwise. Blocking.
    fn reload_libraries(&self) -> Result<(), StoreError> {
        for _ in 0..4 {
            let before = lock(&self.libraries).clone();
            self.writer.barrier_blocking()?;
            let read = crate::libraries::Libraries::open(&self.settings, &self.records)?;
            let mut held = lock(&self.libraries);
            if *held == before {
                *held = read;
                return Ok(());
            }
        }
        log("the libraries changed as they were read again: memory keeps its own");
        Ok(())
    }
}

fn admission(class: frasil_admission::AdmissionClass) -> Reason {
    let (reason, status) = class.reason().unwrap_or(("malformed", 400));
    (reason.to_owned(), status)
}

/// A `Sync` message of a space's units.md message.
pub(crate) fn sync(space: EventId, message: UnitMessage) -> Vec<u8> {
    Sync {
        scope: Scope::Space(*space.as_bytes()),
        message: SyncMessage { space, message }.encode(),
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::{Link, Links, Outgoing};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Asks to reconnect elsewhere go round the connections, pass over one
    /// asked already until it declines, and never reach a forwarded one.
    #[test]
    fn asks_to_reconnect_go_round_and_pass_over_those_asked() {
        let mut links = Links::default();
        let mut queues = Vec::new();
        for id in 0..4 {
            let (tx, rx) = mpsc::channel(8);
            links.links.insert(
                id,
                Link {
                    tx,
                    subscriptions: BTreeSet::new(),
                    admin: None,
                    forwarded: id == 3,
                    awaiting: None,
                    extension_notified: false,
                    asked: false,
                    live: Default::default(),
                    queued: Arc::default(),
                    cap: usize::MAX,
                },
            );
            queues.push(rx);
        }
        let asked = |links: &mut Links, queues: &mut Vec<mpsc::Receiver<Outgoing>>| {
            assert_eq!(links.ask_reconnect(1), 1);
            queues
                .iter_mut()
                .position(|queue| queue.try_recv() == Ok(Outgoing::Reconnect))
        };
        assert_eq!(asked(&mut links, &mut queues), Some(0));
        assert_eq!(asked(&mut links, &mut queues), Some(1));
        // Connection 0 is held by an import, and declines.
        if let Some(link) = links.links.get_mut(&0) {
            link.asked = false;
        }
        assert_eq!(asked(&mut links, &mut queues), Some(2));
        assert_eq!(asked(&mut links, &mut queues), Some(0));
        // Every own connection is asked and has not declined.
        assert_eq!(links.ask_reconnect(1), 0);
    }
}

#[cfg(test)]
mod retirement_tests;

#[cfg(test)]
mod truncation_tests;

/// The ephemeral channel at the peer (ext-ephemeral.md, 3.7 Relaying): a
/// connection's rate, its queue under a flood, and a close.
#[cfg(test)]
mod ephemeral_tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::session::QUEUE;
    use frasil_store::MemoryStore;
    use std::time::{Duration, Instant};

    const SPACE: EventId = EventId([3; 32]);

    fn core() -> Core {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(crate::testing::START));
        let settings = Settings {
            extensions: crate::Extensions {
                ephemeral: true,
                ..crate::Extensions::NONE
            },
            ..Settings::open_core()
        };
        Core::open(settings, Records::new(Arc::new(MemoryStore::new())), clock).unwrap()
    }

    /// An outer frame of `space` that reads by steps 1 and 2, as the peer
    /// checks it; the peer holds no key to open it.
    fn frame(space: EventId, n: u8) -> Vec<u8> {
        frasil_ephemeral::Outer {
            kind: frasil_ephemeral::Kind::Message,
            space: *space.as_bytes(),
            reference: vec![1; 33],
            handle: None,
            sealed: vec![n; frasil_ephemeral::limits::MIN_SEALED_BYTES],
        }
        .encode()
    }

    /// A connection with a queue of the peer's size.
    fn connect(core: &Core) -> (u64, mpsc::Receiver<Outgoing>) {
        let (tx, rx) = mpsc::channel(QUEUE);
        (core.link(tx), rx)
    }

    /// What a connection's queue holds: its ephemeral frames, and the rest.
    fn drain(rx: &mut mpsc::Receiver<Outgoing>) -> (usize, Vec<Outgoing>) {
        let mut ephemeral = 0;
        let mut rest = Vec::new();
        while let Ok(out) = rx.try_recv() {
            match out {
                Outgoing::Ephemeral(_) => ephemeral += 1,
                other => rest.push(other),
            }
        }
        (ephemeral, rest)
    }

    #[test]
    fn a_connection_sends_at_its_rate_with_a_burst_of_one_second() {
        let start = Instant::now();
        let mut bucket = Bucket::default();
        assert!((0..10).all(|_| bucket.admit(start, 10)));
        assert!(!bucket.admit(start, 10));
        // A tenth of a second earns one frame.
        let soon = start + Duration::from_millis(100);
        assert!(bucket.admit(soon, 10));
        assert!(!bucket.admit(soon, 10));
        // A long quiet earns no more than one second's burst.
        let later = start + Duration::from_secs(60);
        assert_eq!((0..20).filter(|_| bucket.admit(later, 10)).count(), 10);
    }

    #[test]
    fn ephemeral_frames_take_at_most_a_senders_queue() {
        let (tx, mut rx) = mpsc::channel(EPHEMERAL_QUEUED + 2);
        let taken = (0..100)
            .filter(|_| offer(&tx, Outgoing::Ephemeral(vec![1])))
            .count();
        assert_eq!(taken, EPHEMERAL_QUEUED);
        // The room left is for other messages.
        assert!(offer(&tx, Outgoing::Control(vec![2])));
        assert!(offer(&tx, Outgoing::Sync(SPACE, vec![3])));
        assert!(!offer(&tx, Outgoing::Control(vec![4])));
        let (ephemeral, rest) = drain(&mut rx);
        assert_eq!((ephemeral, rest.len()), (EPHEMERAL_QUEUED, 2));
    }

    #[test]
    fn sync_deliveries_survive_an_ephemeral_flood() {
        let core = core();
        let (flooder, _flooder_rx) = connect(&core);
        let (member, mut member_rx) = connect(&core);
        core.ephemeral_join(member, SPACE);
        for n in 0..5_000u32 {
            core.ephemeral_frame(flooder, SPACE, &frame(SPACE, n.to_be_bytes()[3]));
        }
        // Every one of the 1,024 deliveries a queue held before still
        // fits beside the flood.
        for n in 0..1024u32 {
            assert!(
                core.send_to(member, Outgoing::Sync(SPACE, n.to_be_bytes().to_vec())),
                "delivery {n}"
            );
        }
        let (ephemeral, rest) = drain(&mut member_rx);
        assert_eq!(ephemeral, EPHEMERAL_QUEUED);
        assert_eq!(rest.len(), 1024);
        assert!(rest.iter().all(|out| matches!(out, Outgoing::Sync(..))));
    }

    #[test]
    fn a_close_walks_only_the_channels_the_connection_was_on() {
        let core = core();
        let other = EventId([4; 32]);
        let third = EventId([5; 32]);
        let (closing, _closing_rx) = connect(&core);
        let (member, mut member_rx) = connect(&core);
        let (elsewhere, mut elsewhere_rx) = connect(&core);
        core.ephemeral_join(closing, SPACE);
        core.ephemeral_frame(closing, other, &frame(other, 1));
        core.ephemeral_join(member, SPACE);
        core.ephemeral_join(elsewhere, third);
        {
            let relays = lock(&core.relays);
            assert_eq!(
                relays.joined.get(&closing),
                Some(&BTreeSet::from([SPACE, other]))
            );
            assert_eq!(relays.channels.len(), 3);
        }
        drain(&mut member_rx);
        core.unlink(closing);
        // `Gone` to the member on its one shared channel; nothing to the
        // connection on another space's.
        let (_, rest) = drain(&mut member_rx);
        assert_eq!(rest.len(), 1);
        assert!(matches!(rest[0], Outgoing::Control(_)));
        assert!(drain(&mut elsewhere_rx).1.is_empty());
        let relays = lock(&core.relays);
        assert!(!relays.joined.contains_key(&closing));
        // The channel only it was on is gone; the others stay.
        assert!(!relays.channels.contains_key(&other));
        assert!(relays.channels.contains_key(&SPACE));
        assert!(relays.channels.contains_key(&third));
    }
}
