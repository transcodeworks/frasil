//! What a device's member connections share: the welcomes waiting for a
//! member connection with their recipient (admission.md, "Welcomes";
//! transport.md, "Mailboxes"), the spaces that member connections
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
const WAITING: usize = 256;

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
    /// The peers, by URL, that hold it in the recipient's device mailbox.
    pub deposited: Vec<String>,
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
    /// Welcomes not yet known to have arrived, oldest first.
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
    /// it over and the recipient attaches the space.
    pub(crate) fn wait(&mut self, welcome: Waiting) {
        self.welcomes
            .retain(|w| (w.recipient, w.space) != (welcome.recipient, welcome.space));
        self.welcomes.push(welcome);
        if self.welcomes.len() > WAITING {
            let over = self.welcomes.len() - WAITING;
            self.welcomes.drain(..over);
        }
    }

    /// The welcomes the peer at `url` does not hold yet.
    pub(crate) fn to_deposit(&self, url: &str) -> Vec<Waiting> {
        self.welcomes
            .iter()
            .filter(|w| !w.deposited.iter().any(|at| at == url))
            .cloned()
            .collect()
    }

    /// The peer at `url` holds a welcome in its recipient's device mailbox.
    pub(crate) fn deposited(&mut self, recipient: &DeviceId, space: &EventId, url: &str) {
        for welcome in &mut self.welcomes {
            if (welcome.recipient, welcome.space) == (*recipient, *space)
                && !welcome.deposited.iter().any(|at| at == url)
            {
                welcome.deposited.push(url.to_owned());
            }
        }
    }

    /// The welcomes waiting for a recipient.
    pub(crate) fn welcomes_for(&self, recipient: &DeviceId) -> Vec<Waiting> {
        self.welcomes
            .iter()
            .filter(|w| w.recipient == *recipient)
            .cloned()
            .collect()
    }

    /// The recipient holds the space: its welcome no longer waits.
    pub(crate) fn delivered(&mut self, recipient: &DeviceId, space: &EventId) {
        self.welcomes
            .retain(|w| (w.recipient, w.space) != (*recipient, *space));
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
