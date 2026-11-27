//! What a device's member connections share: the welcomes waiting for
//! their recipient, as the device keeps them at rest (admission.md, 3.10
//! Welcomes, "A welcome that waits"; transport.md, "Mailboxes"), the
//! spaces that member connections
//! serve, admitted on some attach, and the members they reach and the
//! tickets other members listed, for member addresses (transport.md, "The
//! iroh binding", member addresses).

use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_transport::addresses::{LEARNED_SECONDS, LEARNED_TICKETS};
use frasil_transport::ticket::Ticket;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The most welcomes a device keeps waiting; past it, the oldest go.
pub(crate) const WAITING: usize = 256;

/// How long a welcome waits at most, on the device's timeline from when it
/// was kept: `welcome_retention` (overview.md, "Every timer"), the longest
/// a peer keeps a mailbox item.
pub(crate) const WELCOME_RETENTION: u64 = 30 * 24 * 3600;

/// How long after its latest deposit at a peer a waiting welcome is
/// deposited there again: `welcome_redeposit` (overview.md, "Every
/// timer"), under the 72 hours a peer keeps by default an item of a
/// mailbox its device has not collected (`uncollected_retention`).
pub(crate) const WELCOME_REDEPOSIT: u64 = 48 * 3600;

/// A welcome sealed to its recipient.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) struct Waiting {
    /// The recipient's device ID.
    pub recipient: DeviceId,
    /// The space it admits the recipient to.
    pub space: EventId,
    /// The event that admits it.
    pub event: EventId,
    /// The sealed welcome (admission.md, "The welcome").
    pub sealed: Vec<u8>,
    /// The timeline's `T` at which the device kept it.
    pub since: u64,
    /// The peers, by origin, it was deposited at in the recipient's
    /// device mailbox, ascending, each with the timeline's `T` of the
    /// latest deposit there: as its `welcome` record names them.
    pub deposited: Vec<(String, u64)>,
    /// The peers, by origin, that refused its deposit for good, each with
    /// the timeline's `T` of the deposit: kept in memory only, so that a
    /// restart deposits there again.
    pub refused: Vec<(String, u64)>,
}

#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
impl Waiting {
    /// Whether it is due at the peer at `origin` at `now`: deposited and
    /// refused there never, or `WELCOME_REDEPOSIT` or longer before.
    fn due_at(&self, origin: &str, now: u64) -> bool {
        self.deposited
            .iter()
            .chain(&self.refused)
            .filter(|(peer, _)| peer == origin)
            .all(|(_, at)| now.saturating_sub(*at) >= WELCOME_REDEPOSIT)
    }

    /// The same welcome as `other`: the same recipient, space, event and
    /// sealed bytes.
    pub(crate) fn same(&self, other: &Waiting) -> bool {
        (self.recipient, self.space, self.event) == (other.recipient, other.space, other.event)
            && self.sealed == other.sealed
    }

    /// Deposited at the peer at `origin` at `at`: named there with that
    /// `T`, and refused there no longer.
    pub(crate) fn deposit_at(&mut self, origin: &str, at: u64) {
        self.refused.retain(|(peer, _)| peer != origin);
        match self
            .deposited
            .binary_search_by(|(peer, _)| peer.as_str().cmp(origin))
        {
            Ok(index) => self.deposited[index].1 = at,
            Err(index) => self.deposited.insert(index, (origin.to_owned(), at)),
        }
    }

    /// Refused for good at the peer at `origin` at `at`: named there no
    /// longer, and held in memory to be deposited again later.
    pub(crate) fn refused_at(&mut self, origin: &str, at: u64) {
        self.deposited.retain(|(peer, _)| peer != origin);
        self.refused.retain(|(peer, _)| peer != origin);
        self.refused.push((origin.to_owned(), at));
    }
}

/// A peer's origin as a `deposit` record names it: its URL with no
/// trailing slash.
pub(crate) fn origin(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// A member ticket an `Addresses` listed, for the node to dial with the
/// space attached.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
pub(crate) struct Learned {
    /// The space to attach.
    pub space: EventId,
    /// Where to dial.
    pub ticket: Ticket,
}

/// A member an admitted attach reaches, at the ticket its connection
/// reaches it at.
#[derive(Debug, Clone)]
struct Reached {
    space: EventId,
    member: DeviceId,
    ticket: Ticket,
}

/// A learned ticket: one another member's `Addresses` listed, held in
/// memory for a while and never kept at rest (transport.md, "The iroh
/// binding", member addresses, "Keeping").
#[derive(Debug, Clone)]
struct Held {
    space: EventId,
    member: DeviceId,
    ticket: Ticket,
    at: Instant,
}

/// What the device's member connections share.
#[derive(Debug, Default)]
#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
pub(crate) struct Links {
    /// Welcomes not yet known to have arrived, oldest first, as their
    /// `welcome` records hold them.
    welcomes: Vec<Waiting>,
    /// For each space, the admitted attaches that serve it.
    attached: BTreeMap<EventId, usize>,
    /// For each space and member, the admitted attaches with that member.
    members: BTreeMap<(EventId, DeviceId), usize>,
    /// The members admitted attaches reach, by a token of the attach.
    reached: BTreeMap<u64, Reached>,
    next_reached: u64,
    /// Changes whenever what member addresses list may have changed.
    version: u64,
    /// Where learned tickets go: the node's dialer.
    dialer: Option<mpsc::UnboundedSender<Learned>>,
    /// The learned tickets, oldest first: at most 128, each for 10
    /// seconds.
    held: Vec<Held>,
    /// The spaces whose sync with always-on peers the application paused.
    paused: std::collections::BTreeSet<EventId>,
    /// The key this device announces as its next member endpoint key
    /// (ext-next-endpoints.md), once its member endpoint has bound.
    #[cfg(feature = "ext-next-endpoints")]
    next_endpoint: Option<[u8; 32]>,
}

#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
impl Links {
    /// Keeps a welcome until a member connection with its recipient hands
    /// it over and the recipient attaches the space, in place of one for
    /// the same recipient and space. Returns the welcomes the bound
    /// passes, the oldest first, which wait no longer.
    pub(crate) fn wait(&mut self, welcome: Waiting) -> Vec<Waiting> {
        self.welcomes
            .retain(|w| (w.recipient, w.space) != (welcome.recipient, welcome.space));
        let at = self.welcomes.partition_point(|w| w.since <= welcome.since);
        self.welcomes.insert(at, welcome);
        let over = self.welcomes.len().saturating_sub(WAITING);
        self.welcomes.drain(..over).collect()
    }

    /// The welcomes kept `WELCOME_RETENTION` or longer before `now`, on
    /// the device's timeline, which wait no longer.
    pub(crate) fn expire_welcomes(&mut self, now: u64) -> Vec<Waiting> {
        let (old, young) = std::mem::take(&mut self.welcomes)
            .into_iter()
            .partition(|w| now.saturating_sub(w.since) >= WELCOME_RETENTION);
        self.welcomes = young;
        old
    }

    /// The welcomes of a space the device forgets: none of them waits.
    pub(crate) fn forget_welcomes(&mut self, space: &EventId) {
        self.welcomes.retain(|w| w.space != *space);
    }

    /// The welcomes due at the peer at `url` at `now`, on the device's
    /// timeline: never deposited there, or last deposited or refused
    /// there `WELCOME_REDEPOSIT` or longer before. A `T` past `now`, as
    /// after a timeline that started again, is not due until `now` passes
    /// it by that much.
    pub(crate) fn to_deposit(&self, url: &str, now: u64) -> Vec<Waiting> {
        let url = origin(url);
        self.welcomes
            .iter()
            .filter(|w| w.due_at(url, now))
            .cloned()
            .collect()
    }

    /// Every waiting welcome, oldest first.
    pub(crate) fn waiting_welcomes(&self) -> Vec<Waiting> {
        self.welcomes.clone()
    }

    /// The welcome for a recipient and space, as it waits now.
    pub(crate) fn waiting(&self, recipient: &DeviceId, space: &EventId) -> Option<Waiting> {
        self.welcomes
            .iter()
            .find(|w| (w.recipient, w.space) == (*recipient, *space))
            .cloned()
    }

    /// The waiting welcome that is the same as `welcome`, to change.
    pub(crate) fn same_mut(&mut self, welcome: &Waiting) -> Option<&mut Waiting> {
        self.welcomes.iter_mut().find(|w| w.same(welcome))
    }

    /// The waiting welcome a deposit of `item` at the device mailbox
    /// `address` carries, where `address_of` gives a recipient's address.
    pub(crate) fn carried(
        &self,
        address: &[u8; 32],
        item: &[u8],
        address_of: impl Fn(&DeviceId) -> [u8; 32],
    ) -> Option<Waiting> {
        self.welcomes
            .iter()
            .find(|w| w.sealed == item && address_of(&w.recipient) == *address)
            .cloned()
    }

    /// The welcomes waiting for a recipient.
    pub(crate) fn welcomes_for(&self, recipient: &DeviceId) -> Vec<Waiting> {
        self.welcomes
            .iter()
            .filter(|w| w.recipient == *recipient)
            .cloned()
            .collect()
    }

    /// The recipient holds the space, or the space's roster no longer
    /// reaches it: its welcome no longer waits. Whether one waited.
    pub(crate) fn delivered(&mut self, recipient: &DeviceId, space: &EventId) -> bool {
        let before = self.welcomes.len();
        self.welcomes
            .retain(|w| (w.recipient, w.space) != (*recipient, *space));
        self.welcomes.len() != before
    }

    /// An attach admitted for a space, with the member on the other side
    /// if it identified itself.
    pub(crate) fn attach(&mut self, space: EventId, member: Option<DeviceId>) {
        *self.attached.entry(space).or_default() += 1;
        if let Some(member) = member {
            *self.members.entry((space, member)).or_default() += 1;
        }
    }

    /// An admitted attach of a space ended.
    pub(crate) fn detach(&mut self, space: &EventId, member: Option<DeviceId>) {
        if let Some(count) = self.attached.get_mut(space) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.attached.remove(space);
            }
        }
        if let Some(member) = member
            && let Some(count) = self.members.get_mut(&(*space, member))
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.members.remove(&(*space, member));
            }
        }
    }

    /// The members an admitted attach of a space connects this device to
    /// now, by device ID.
    pub(crate) fn connected(&self, space: &EventId) -> Vec<DeviceId> {
        self.members
            .range((*space, DeviceId([0; 32]))..=(*space, DeviceId([0xff; 32])))
            .map(|((_, member), _)| *member)
            .collect()
    }

    /// The admitted attaches of a space with a member.
    pub(crate) fn attaches_with(&self, space: &EventId, member: &DeviceId) -> usize {
        self.members.get(&(*space, *member)).copied().unwrap_or(0)
    }

    /// Whether some member connection serves the space.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn attached(&self, space: &EventId) -> bool {
        self.attached.contains_key(space)
    }

    /// An admitted attach of a space reaches a member at a ticket. Returns
    /// the token that [`Links::unreach`] ends it by.
    pub(crate) fn reach(&mut self, space: EventId, member: DeviceId, ticket: Ticket) -> u64 {
        let token = self.next_reached;
        self.next_reached += 1;
        self.reached.insert(
            token,
            Reached {
                space,
                member,
                ticket,
            },
        );
        self.changed();
        token
    }

    /// The attach of a token reaches its member no longer.
    pub(crate) fn unreach(&mut self, token: u64) {
        if self.reached.remove(&token).is_some() {
            self.changed();
        }
    }

    /// The members admitted attaches of a space reach, each once, by
    /// device ID, at the ticket the latest of its attaches reaches it at.
    pub(crate) fn reached(&self, space: &EventId) -> BTreeMap<DeviceId, Ticket> {
        self.reached
            .values()
            .filter(|r| r.space == *space)
            .map(|r| (r.member, r.ticket.clone()))
            .collect()
    }

    /// Whether an admitted attach of a space reaches a member.
    pub(crate) fn reaches(&self, space: &EventId, member: &DeviceId) -> bool {
        self.reached
            .values()
            .any(|r| r.space == *space && r.member == *member)
    }

    /// What member addresses list may have changed: a member reached or
    /// no longer, or a ticket kept.
    pub(crate) fn changed(&mut self) {
        self.version = self.version.wrapping_add(1);
    }

    /// The version of what member addresses list.
    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    /// Pauses a space's sync with always-on peers: whether it was running.
    pub(crate) fn pause(&mut self, space: EventId) -> bool {
        self.paused.insert(space)
    }

    /// Resumes a space's sync with always-on peers: whether it was paused.
    pub(crate) fn resume(&mut self, space: &EventId) -> bool {
        self.paused.remove(space)
    }

    /// Whether the space's sync with always-on peers is paused.
    pub(crate) fn is_paused(&self, space: &EventId) -> bool {
        self.paused.contains(space)
    }

    /// The key this device announces as its next member endpoint key.
    #[cfg(feature = "ext-next-endpoints")]
    pub(crate) fn next_endpoint(&self) -> Option<[u8; 32]> {
        self.next_endpoint
    }

    /// Announces another next key from now on.
    #[cfg(feature = "ext-next-endpoints")]
    pub(crate) fn set_next_endpoint(&mut self, key: [u8; 32]) {
        self.next_endpoint = Some(key);
    }

    /// Where learned tickets go from now on.
    pub(crate) fn set_dialer(&mut self, dialer: mpsc::UnboundedSender<Learned>) {
        self.dialer = Some(dialer);
    }

    /// A ticket an `Addresses` listed of a member of a space, at step 7:
    /// held among the learned tickets, at most 128, each for 10 seconds,
    /// and sent to the dialer, unless a ticket of its endpoint key for the
    /// space is held already, and so was dialed (transport.md, "The iroh
    /// binding", member addresses, "Dialing"). It is never kept at rest.
    pub(crate) fn learned(
        &mut self,
        space: EventId,
        member: DeviceId,
        ticket: Ticket,
        now: Instant,
    ) {
        self.expire(now);
        if self
            .held
            .iter()
            .any(|h| h.space == space && h.ticket.endpoint == ticket.endpoint)
        {
            return;
        }
        self.held.push(Held {
            space,
            member,
            ticket: ticket.clone(),
            at: now,
        });
        if self.held.len() > LEARNED_TICKETS {
            let over = self.held.len() - LEARNED_TICKETS;
            self.held.drain(..over);
        }
        if let Some(dialer) = &self.dialer {
            let _ = dialer.send(Learned { space, ticket });
        }
    }

    /// The learned tickets held for a space at `now`, oldest first, with
    /// the member each names.
    pub(crate) fn held(&mut self, space: &EventId, now: Instant) -> Vec<(DeviceId, Ticket)> {
        self.expire(now);
        self.held
            .iter()
            .filter(|h| h.space == *space)
            .map(|h| (h.member, h.ticket.clone()))
            .collect()
    }

    /// Lets go of the learned tickets held for 10 seconds.
    fn expire(&mut self, now: Instant) {
        let keep = Duration::from_secs(LEARNED_SECONDS);
        self.held
            .retain(|h| now.saturating_duration_since(h.at) < keep);
    }
}
