//! Baseline sync (units.md, "Sync"), sans-IO, over one replica.
//!
//! **The exchange.**
//!
//! 1. Each side sends `Heads`. A side that holds every head the other sent
//!    computes exactly what the other lacks, every event it holds outside
//!    the past of those heads, and sends them in `Events`, in canonical
//!    order, space events first (transport.md, "Order on a connection").
//! 2. A side that lacks some of the other's heads asks for them by `Want`
//!    with IDs.
//! 3. Each side places what arrives. An event that stays pending names
//!    parents to ask for by ID.
//! 4. A side asked for an event it does not hold says so in `Missing`.
//! 5. Once it has stored what it received durably, a side sends `Ack`.
//!
//! A [`SyncSession`] is one side of this for one space on one connection.
//! It turns what arrives into [`Action`]s; the device places events, stores
//! them and sends what the session asks.

use crate::fetch::{Asks, CHUNKS_PER_WANT, Requests, Taker, Want};
use crate::replica::Replica;
use frasil_adapter::Locator;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, Log, kind};
use frasil_transport::roster::Serving;
use frasil_units::limits::{MAX_MESSAGE_BYTES, MAX_MESSAGE_ITEMS};
use frasil_units::messages::{Message, SyncMessage, VectorEntry};
use frasil_units::stream::StreamId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The room a message keeps for its own keys, beside its events.
const MESSAGE_OVERHEAD: usize = 64;

/// What the device does for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this message.
    Send(SyncMessage),
    /// Place and store these signed events, then call
    /// [`SyncSession::stored`].
    Ingest(Vec<Vec<u8>>),
    /// The other side acknowledged these heads: every event in their past
    /// is durable there (units.md, "Heads, acknowledgements and
    /// durability").
    Acknowledged(Vec<EventId>),
    /// A `Missing` named these IDs: the other side does not hold them,
    /// which may show it lost what it acknowledged, or, for a head
    /// statement's heads, withholding or a junk statement (units.md, 3.13).
    Missing(Vec<EventId>),
    /// `ObjectWant` from a side this one serves: answer each chunk asked
    /// for in its own `ObjectChunks` (units.md, "Sync", objects).
    ServeObject {
        /// The object.
        locator: Locator,
        /// The first chunk asked for.
        first: u64,
        /// How many.
        count: u64,
    },
    /// `ObjectChunks`: a chunk to keep, if the device lacks its object,
    /// then ask for the next ones.
    ObjectChunk(crate::snapshots::ObjectPart),
    /// `ObjectHave`: objects the other side holds, which the device may
    /// ask it for.
    ObjectsHeld(Vec<Locator>),
    /// `SnapshotWant` from a member this side serves: answer with a space
    /// snapshot and the objects it names.
    SnapshotWanted,
    /// `SnapshotOffer`: a space snapshot, which a device waiting for one
    /// uses before it places the space's events.
    SnapshotOffered(Vec<u8>),
    /// A `Missing` named units that carry stubs of events this side asked
    /// for, as pairs `[ID, unit ID]`: the device asks for each carrier and
    /// places against its stubs (units.md, "Sync", step 4), then calls
    /// [`SyncSession::stored`].
    Carried(Vec<(EventId, EventId)>),
    /// A `Path` arrived: a partial replica witnesses its events if it
    /// checks (units.md, "Partial replicas"), then calls
    /// [`SyncSession::stored`].
    Path {
        /// The event the path starts beneath.
        from: EventId,
        /// The event the path reaches.
        to: EventId,
        /// The signed events of the path.
        events: Vec<Vec<u8>>,
    },
}

/// Where a session is with a space snapshot this side asked of the other
/// (units.md, `SnapshotWant`; admission.md, "The newcomer's snapshot").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotAsk {
    /// This side sent no `SnapshotWant` on the session: an offer is not
    /// taken.
    NotAsked,
    /// This side sent `SnapshotWant`: one offer is taken.
    Asked,
    /// An offer from the other side was adopted: the chunks of the objects
    /// it names follow unasked.
    Adopted,
}

/// One side of baseline sync for one space on one connection.
#[derive(Debug, Clone)]
pub struct SyncSession {
    space: EventId,
    /// The other side's heads, as it last sent them.
    theirs: Option<Vec<EventId>>,
    /// The vector it last sent with them.
    their_vector: Option<Vec<VectorEntry>>,
    /// Whether the state its last `Heads` show was judged whole for
    /// detected loss (units.md, 3.13 "Detected loss").
    judged: bool,
    /// Whether its `Heads` show its whole state, so that detected loss
    /// reads them: toward a peer, only under the fetch right, since one
    /// that may not fetch is listed less.
    judges: bool,
    /// Head statements' heads asked for on this session.
    stated: BTreeSet<EventId>,
    /// Whether the other side answered `Missing` for a statement's head
    /// for the first time since [`SyncSession::take_stated_missing`].
    stated_missing: bool,
    /// Events this side has sent on this session, or knows the other holds.
    known: BTreeSet<EventId>,
    /// IDs asked for and not yet received.
    asked: BTreeSet<EventId>,
    /// `Path`s asked for, with the replica's heads when they were: asked
    /// again only once the heads move.
    paths: BTreeMap<(EventId, EventId), Vec<EventId>>,
    /// What this side may serve the other.
    serving: Serving,
    /// The chunks of objects asked for by `ObjectWant` and not yet
    /// arrived, and those yet to ask.
    asks: Asks,
    /// The device's requests for chunks taken on this session, by their
    /// numbers.
    requested: BTreeSet<u64>,
    /// The session's place among the connections that take the device's
    /// requests, from the first time it takes them or gives an object
    /// up; copies of the session share it.
    taker: Option<Arc<Taker>>,
    /// Objects the other side announced in `ObjectHave` that this side did
    /// not hold whole then: asked for once the device finds them missing.
    announced: BTreeSet<Locator>,
    /// Objects whose chunks from the other side failed their checks: not
    /// asked of it again on this session (units.md, "Sync", objects).
    refused: BTreeSet<Locator>,
    /// Where this side is with a space snapshot asked of the other.
    snapshot: SnapshotAsk,
    /// The streams a partial replica's `Heads` named: of units, only
    /// theirs are sent in answer.
    their_streams: Option<Vec<StreamId>>,
    /// Events this side never sends on this session: on a space-traffic
    /// connection, this device's own skeleton events (peers.md,
    /// "Administration connections").
    withheld: BTreeSet<EventId>,
    /// Whether this side acknowledges what it stores: toward a member, not
    /// toward a peer.
    acknowledges: bool,
}

impl SyncSession {
    /// A session for a space, serving everything.
    pub fn new(space: EventId) -> Self {
        Self {
            space,
            theirs: None,
            their_vector: None,
            judged: false,
            judges: true,
            stated: BTreeSet::new(),
            stated_missing: false,
            known: BTreeSet::new(),
            asked: BTreeSet::new(),
            paths: BTreeMap::new(),
            serving: Serving::Everything,
            asks: Asks::default(),
            requested: BTreeSet::new(),
            taker: None,
            announced: BTreeSet::new(),
            refused: BTreeSet::new(),
            snapshot: SnapshotAsk::NotAsked,
            their_streams: None,
            withheld: BTreeSet::new(),
            acknowledges: true,
        }
    }

    /// Sets whether this side sends `Ack` once it stored what arrived: a
    /// device acknowledges to members, never to a peer.
    pub fn set_acknowledges(&mut self, acknowledges: bool) {
        self.acknowledges = acknowledges;
    }

    /// Sets whether the other side's `Heads` show its whole state, which
    /// detected loss reads (units.md, 3.13 "Detected loss").
    pub fn set_judges(&mut self, judges: bool) {
        self.judges = judges;
    }

    /// The state the other side's last `Heads` show, not yet judged
    /// whole, when detected loss reads it.
    pub fn unjudged(&self) -> Option<crate::outbox::Served> {
        if !self.judges || self.judged {
            return None;
        }
        Some(crate::outbox::Served {
            heads: self.theirs.clone()?,
            vector: self.their_vector.clone(),
        })
    }

    /// The state the other side's last `Heads` show was judged whole.
    pub fn mark_judged(&mut self) {
        self.judged = true;
    }

    /// `Want` for head statements' heads not yet asked for on this
    /// session (units.md, 3.13 "Head statements").
    pub fn ask_stated(&mut self, ids: Vec<EventId>) -> Vec<Action> {
        let ids: Vec<EventId> = ids
            .into_iter()
            .filter(|id| self.stated.insert(*id))
            .collect();
        self.want(ids)
    }

    /// `Want` again for head statements' heads asked for on this session
    /// before, once `withholding_grace` has passed since the other side's
    /// first `Missing` for them (units.md, 3.13 "Head statements").
    pub fn ask_stated_again(&mut self, ids: Vec<EventId>) -> Vec<Action> {
        for id in &ids {
            self.stated.remove(id);
        }
        self.ask_stated(ids)
    }

    /// Notes that the other side answered `Missing` for a statement's
    /// head for the first time.
    pub fn note_stated_missing(&mut self) {
        self.stated_missing = true;
    }

    /// Whether the other side answered `Missing` for a statement's head
    /// for the first time since the last call: the connection then asks
    /// again after `withholding_grace`.
    pub fn take_stated_missing(&mut self) -> bool {
        std::mem::take(&mut self.stated_missing)
    }

    /// Forgets that the other side was sent these events, so that they are
    /// offered again: an event the other side refused for now.
    pub fn forget(&mut self, ids: &[EventId]) {
        for id in ids {
            self.known.remove(id);
        }
    }

    /// Whether this side acknowledges what it stores: a session with a
    /// member.
    pub fn acknowledges(&self) -> bool {
        self.acknowledges
    }

    /// `ObjectWant` for the first chunks of an object the other side holds,
    /// unless it is asked for already.
    pub fn want_object(&mut self, locator: Locator) -> Option<SyncMessage> {
        self.want_first(locator, CHUNKS_PER_WANT)
    }

    /// `ObjectWant` for the first chunk alone, which carries the header,
    /// of an object the other side holds, unless it is asked for already:
    /// a state object, whose header must name no more than its adapter
    /// loads before the rest is asked for.
    pub fn want_object_header(&mut self, locator: Locator) -> Option<SyncMessage> {
        self.want_first(locator, 1)
    }

    fn want_first(&mut self, locator: Locator, count: u64) -> Option<SyncMessage> {
        if self.asks.has(&locator) {
            return None;
        }
        self.want_chunks(locator, 0..u64::MAX, false, count, None, |_| false)
            .into_iter()
            .next()
    }

    /// `ObjectWant`s for the chunks `chunks` of an object the other side
    /// holds, from any first index (units.md, "Sync", objects), unless it
    /// refused the object on this session. `count` is the object's chunk
    /// count when the device holds its header, and `skip` says which
    /// chunks are not to be asked for: those the device holds, and those
    /// nobody wants any more. With `at_once`, the first chunks are asked
    /// for now, at most 64, beside whatever is awaited; the rest goes
    /// `batch` chunks at a time, the first batch now when nothing is
    /// awaited, and each of the others once the one before arrived.
    pub(crate) fn want_chunks(
        &mut self,
        locator: Locator,
        chunks: core::ops::Range<u64>,
        at_once: bool,
        batch: u64,
        count: Option<u64>,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<SyncMessage> {
        if self.refused.contains(&locator) {
            return Vec::new();
        }
        let wants = self.asks.want(locator, chunks, at_once, batch, count, skip);
        self.wants(locator, wants)
    }

    fn wants(&self, locator: Locator, wants: Vec<Want>) -> Vec<SyncMessage> {
        wants
            .into_iter()
            .map(|(first, count)| SyncMessage {
                space: self.space,
                message: Message::ObjectWant {
                    locator,
                    first,
                    count,
                },
            })
            .collect()
    }

    /// Whether this side asked the other for chunks of an object on this
    /// session that have not all arrived, or has more of it to ask for.
    pub fn is_fetching(&self, locator: &Locator) -> bool {
        self.asks.has(locator)
    }

    /// Whether this side asked the other for this chunk on this session,
    /// and it has not arrived.
    pub fn awaits_chunk(&self, locator: &Locator, index: u64) -> bool {
        self.asks.awaits(locator, index)
    }

    /// A chunk of an object from the other side failed its checks: the
    /// object is not asked of it again on this session, and another party
    /// is asked (units.md, "Sync", objects).
    pub fn refuse_object(&mut self, locator: Locator) {
        self.asks.forget(&locator);
        self.announced.remove(&locator);
        self.refused.insert(locator);
    }

    /// Notes a request for chunks the device made: `true` the first time
    /// this session hears of it.
    pub(crate) fn take_request(&mut self, id: u64) -> bool {
        self.requested.insert(id)
    }

    /// The session's place among the connections that take the requests
    /// made of the device ([`Requests::attach`]), taken the first time
    /// this is called: through it the session says which objects it asks
    /// the other side for no further.
    pub(crate) fn taker(&mut self, requests: &Arc<Requests>) -> &Taker {
        let space = self.space;
        self.taker
            .get_or_insert_with(|| Arc::new(requests.attach(space)))
    }

    /// Forgets the device's requests that ended.
    pub(crate) fn keep_requests(&mut self, live: &BTreeSet<u64>) {
        self.requested.retain(|id| live.contains(id));
    }

    /// Where this session is with a space snapshot asked of the other side.
    pub(crate) fn snapshot_ask(&self) -> SnapshotAsk {
        self.snapshot
    }

    /// Notes where this session is with a space snapshot.
    pub(crate) fn set_snapshot_ask(&mut self, ask: SnapshotAsk) {
        self.snapshot = ask;
    }

    /// Keeps objects the other side announced in `ObjectHave`, which this
    /// side may ask it for (units.md, "Sync", objects).
    pub fn note_announced(&mut self, locators: &[Locator]) {
        self.announced.extend(
            locators
                .iter()
                .copied()
                .filter(|locator| !self.refused.contains(locator)),
        );
    }

    /// The objects the other side announced that this side has not yet
    /// been found to hold whole.
    pub fn announced(&self) -> &BTreeSet<Locator> {
        &self.announced
    }

    /// Forgets announced objects this side now holds whole.
    pub fn forget_announced(&mut self, held: impl Fn(&Locator) -> bool) {
        self.announced.retain(|locator| !held(locator));
    }

    /// After a chunk of an object asked for arrived: `ObjectWant`s for the
    /// next chunks once every chunk awaited is in, and the object is not
    /// yet whole. `count` is the object's chunk count, once its header is
    /// known, and `skip` says which chunks are not to be asked for.
    pub(crate) fn chunk_arrived(
        &mut self,
        locator: Locator,
        index: u64,
        count: Option<u64>,
        whole: bool,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<SyncMessage> {
        if whole {
            self.asks.forget(&locator);
            return Vec::new();
        }
        let (_, wants) = self.asks.arrived(&locator, index, count, skip);
        self.wants(locator, wants)
    }

    /// A chunk asked for arrived and was not kept, for want of a header:
    /// it is asked for again, in an answer of its own, whose first chunk
    /// carries the header (units.md, "Sync", objects).
    pub(crate) fn chunk_again(
        &mut self,
        locator: Locator,
        index: u64,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<SyncMessage> {
        let wants = self.asks.again(&locator, index, skip);
        self.wants(locator, wants)
    }

    /// The objects with chunks asked for and not yet arrived, or yet to
    /// ask for.
    pub(crate) fn fetching(&self) -> Vec<Locator> {
        self.asks.objects()
    }

    /// Time passed with no chunk of an object arriving: chunks past the
    /// end of an object whose header is held by now are awaited no
    /// longer, those that got no answer for too long are given up, and
    /// the `ObjectWant`s for what is yet to ask for follow.
    pub(crate) fn chunks_waited(
        &mut self,
        locator: Locator,
        elapsed: std::time::Duration,
        count: Option<u64>,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<SyncMessage> {
        let wants = self.asks.waited(&locator, elapsed, count, skip);
        self.wants(locator, wants)
    }

    /// Withholds these events from the other side: this device's own
    /// skeleton events, which travel only on administration connections
    /// (peers.md, "Administration connections").
    pub fn withhold(&mut self, events: BTreeSet<EventId>) {
        self.withheld = events;
    }

    /// The space.
    pub fn space(&self) -> EventId {
        self.space
    }

    /// Sets what this side may serve: nothing before it admits the other,
    /// catch-up during probation (transport.md, "The roster check").
    pub fn set_serving(&mut self, serving: Serving) {
        self.serving = serving;
    }

    /// Whether this side holds every head the other last sent: it is caught
    /// up with the other, as far as the other told.
    pub fn caught_up(&self, replica: &Replica) -> bool {
        self.theirs
            .as_ref()
            .is_some_and(|heads| heads.iter().all(|id| replica.holds(*id)))
    }

    /// The `Heads` this side opens with: its heads and its vector.
    pub fn start(&self, replica: &Replica) -> Vec<Action> {
        vec![Action::Send(SyncMessage {
            space: self.space,
            message: heads(replica),
        })]
    }

    /// Takes one sync message of this space.
    pub fn receive(&mut self, replica: &Replica, message: SyncMessage) -> Vec<Action> {
        if message.space != self.space {
            return Vec::new();
        }
        match message.message {
            Message::Heads {
                heads,
                vector,
                streams,
            } => {
                self.their_streams = (!streams.is_empty()).then_some(streams);
                self.their_vector = vector;
                self.judged = false;
                self.on_heads(replica, heads)
            }
            Message::Want { ids, ranges, .. } => {
                let mut wanted: Vec<EventId> = ids;
                if let Some(log) = replica.log() {
                    for range in ranges {
                        for id in log.chain(&range.author) {
                            let seq = log.event(id).map_or(0, |e| e.seq());
                            if (range.first..=range.last).contains(&seq) {
                                wanted.push(id);
                            }
                        }
                    }
                }
                self.answer(replica, wanted)
            }
            Message::Events { events } => {
                for signed in &events {
                    if let Ok(event) = frasil_events::decode(signed) {
                        self.asked.remove(&event.id());
                        self.known.insert(event.id());
                    }
                }
                vec![Action::Ingest(events)]
            }
            Message::Missing { ids, carried } => {
                for id in &ids {
                    self.asked.remove(id);
                }
                let mut actions = Vec::new();
                if !ids.is_empty() {
                    actions.push(Action::Missing(ids));
                }
                if !carried.is_empty() {
                    actions.push(Action::Carried(carried));
                }
                actions
            }
            Message::Ack { heads } => {
                self.known.extend(heads.iter().copied());
                vec![Action::Acknowledged(heads)]
            }
            Message::ObjectWant {
                locator,
                first,
                count,
            } if self.serving == Serving::Everything => vec![Action::ServeObject {
                locator,
                first,
                count,
            }],
            Message::ObjectChunks {
                locator,
                header,
                index,
                chunk,
            } => vec![Action::ObjectChunk(crate::snapshots::ObjectPart {
                locator,
                header,
                index,
                chunk,
            })],
            Message::ObjectHave { locators, .. } => vec![Action::ObjectsHeld(locators)],
            Message::SnapshotWant { .. } if self.serving == Serving::Everything => {
                vec![Action::SnapshotWanted]
            }
            Message::SnapshotOffer { snapshot } => vec![Action::SnapshotOffered(snapshot)],
            // Live delivery is the device's to keep: every new event goes
            // to each session (`offer`).
            Message::Subscribe { .. } => Vec::new(),
            #[cfg(feature = "partial-replicas")]
            Message::Path { from, to, events } => vec![Action::Path { from, to, events }],
            #[cfg(feature = "partial-replicas")]
            Message::PathWant { from, to } => vec![self.path(replica, from, to)],
            _ => Vec::new(),
        }
    }

    fn on_heads(&mut self, replica: &Replica, heads: Vec<EventId>) -> Vec<Action> {
        self.known.extend(heads.iter().copied());
        self.theirs = Some(heads.clone());
        let mut actions = Vec::new();
        let lacking: Vec<EventId> = heads
            .iter()
            .copied()
            .filter(|id| !replica.holds(*id))
            .collect();
        if lacking.is_empty() {
            // Every event outside the past of their heads.
            let missing = self.narrowed(replica, after(replica, &heads));
            actions.extend(self.events(replica, missing));
        } else {
            actions.extend(self.want(lacking));
            // Send what they surely lack: everything outside the past of
            // the heads this side holds of theirs.
            let held: Vec<EventId> = heads
                .iter()
                .copied()
                .filter(|id| replica.holds(*id))
                .collect();
            let missing = self.narrowed(replica, after(replica, &held));
            actions.extend(self.events(replica, missing));
        }
        actions.extend(self.ask_peer_stated(replica));
        actions
    }

    /// Toward a peer, `Want` for the head statements' heads asked of their
    /// authors and still lacking (units.md, 3.13 "Head statements").
    fn ask_peer_stated(&mut self, replica: &Replica) -> Vec<Action> {
        if self.acknowledges {
            return Vec::new();
        }
        self.ask_stated(replica.stated_asked_lacking())
    }

    fn want(&mut self, ids: Vec<EventId>) -> Vec<Action> {
        let ids: Vec<EventId> = ids
            .into_iter()
            .filter(|id| self.asked.insert(*id))
            .collect();
        ids.chunks(MAX_MESSAGE_ITEMS)
            .map(|chunk| {
                Action::Send(SyncMessage {
                    space: self.space,
                    message: Message::Want {
                        ids: chunk.to_vec(),
                        ranges: Vec::new(),
                        kinds: Vec::new(),
                        streams: Vec::new(),
                    },
                })
            })
            .collect()
    }

    fn answer(&mut self, replica: &Replica, wanted: Vec<EventId>) -> Vec<Action> {
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for id in wanted {
            match replica.event(id) {
                Some(_) if self.may_serve(replica, id) => found.push(id),
                _ => missing.push(id),
            }
        }
        let mut actions = self.events(replica, found);
        if !missing.is_empty() {
            for chunk in missing.chunks(MAX_MESSAGE_ITEMS) {
                actions.push(Action::Send(SyncMessage {
                    space: self.space,
                    message: Message::Missing {
                        ids: chunk.to_vec(),
                        carried: Vec::new(),
                    },
                }));
            }
        }
        actions
    }

    /// After the device placed and stored what arrived: `Want` for every
    /// parent still missing, and at a partial replica for what it fetches
    /// to learn heights, `PathWant` for the orders its pending units wait
    /// on (units.md, "Partial replicas"), and `Ack` of its heads.
    pub fn stored(&mut self, replica: &Replica) -> Vec<Action> {
        let wanted: Vec<EventId> = replica
            .wanted()
            .into_iter()
            .filter(|id| !replica.holds(*id))
            .collect();
        let mut actions = self.want(wanted);
        actions.extend(self.ask_peer_stated(replica));
        let heads = replica.heads();
        for &(from, to) in replica.paths_wanted() {
            if self.paths.get(&(from, to)) == Some(&heads) {
                continue;
            }
            self.paths.insert((from, to), heads.clone());
            actions.push(Action::Send(SyncMessage {
                space: self.space,
                message: Message::PathWant { from, to },
            }));
        }
        let heads = replica.heads();
        if self.acknowledges && !heads.is_empty() {
            for chunk in heads.chunks(MAX_MESSAGE_ITEMS) {
                actions.push(Action::Send(SyncMessage {
                    space: self.space,
                    message: Message::Ack {
                        heads: chunk.to_vec(),
                    },
                }));
            }
        }
        actions
    }

    /// `PathWant`: a path of placed events from `from` down to `to`, the
    /// first a parent of `from`, the last with `to` among its parents;
    /// empty when this side knows none.
    #[cfg(feature = "partial-replicas")]
    fn path(&self, replica: &Replica, from: EventId, to: EventId) -> Action {
        let mut events = Vec::new();
        if let Some(log) = replica.log()
            && let Some(start) = log.event(from)
            && !start.parents().contains(&to)
            && self.may_serve(replica, from)
        {
            // Breadth first from `from`'s parents to an event that has
            // `to` among its parents.
            let mut previous: BTreeMap<EventId, EventId> = BTreeMap::new();
            let mut queue: std::collections::VecDeque<EventId> = start
                .parents()
                .iter()
                .copied()
                .filter(|p| log.contains(*p))
                .collect();
            let mut seen: BTreeSet<EventId> = queue.iter().copied().collect();
            let mut end = None;
            while let Some(id) = queue.pop_front() {
                let Some(event) = log.event(id) else {
                    continue;
                };
                if event.parents().contains(&to) {
                    end = Some(id);
                    break;
                }
                for &parent in event.parents() {
                    if log.contains(parent) && seen.insert(parent) {
                        previous.insert(parent, id);
                        queue.push_back(parent);
                    }
                }
            }
            if let Some(mut id) = end {
                let mut ids = vec![id];
                while let Some(&before) = previous.get(&id) {
                    ids.push(before);
                    id = before;
                }
                ids.reverse();
                if ids.iter().all(|id| self.may_serve(replica, *id)) {
                    ids.truncate(MAX_MESSAGE_ITEMS);
                    events = ids
                        .iter()
                        .filter_map(|id| log.event(*id).map(frasil_events::Event::signed))
                        .collect();
                }
            }
        }
        Action::Send(SyncMessage {
            space: self.space,
            message: Message::Path { from, to, events },
        })
    }

    /// Live delivery: new events of this space the other has not been
    /// sent, space events first.
    pub fn offer(&mut self, replica: &Replica, ids: &[EventId]) -> Vec<Action> {
        let ids: Vec<EventId> = ids
            .iter()
            .copied()
            .filter(|id| !self.known.contains(id))
            .collect();
        let ids = self.narrowed(replica, ids);
        self.events(replica, ids)
    }

    /// Of these events, those the other side's `Heads` ask for: at a
    /// partial replica's, units of the streams it named only (units.md,
    /// "Sync", the exchange, step 1).
    fn narrowed(&self, replica: &Replica, ids: Vec<EventId>) -> Vec<EventId> {
        let Some(streams) = &self.their_streams else {
            return ids;
        };
        ids.into_iter()
            .filter(|id| {
                replica.event(*id).is_none_or(|event| {
                    if event.kind() != kind::UNIT {
                        return true;
                    }
                    frasil_units::Unit::from_event(event.clone()).is_ok_and(|unit| {
                        frasil_units::messages::sent_after_heads(
                            Some(&unit.body.stream),
                            streams,
                            replica.system_stream().as_ref(),
                        )
                    })
                })
            })
            .collect()
    }

    fn may_serve(&self, replica: &Replica, id: EventId) -> bool {
        match self.serving {
            Serving::Everything => true,
            Serving::Nothing => false,
            // Catch-up: space events, storage events, anchors, and the
            // units of the system stream (peers.md, "Catch-up").
            Serving::CatchUp => replica.event(id).is_some_and(|event| match event.kind() {
                kind::SPACE | kind::STORAGE | kind::ANCHOR => true,
                kind::UNIT => frasil_units::Unit::from_event(event.clone())
                    .is_ok_and(|unit| Some(unit.body.stream) == replica.system_stream()),
                _ => false,
            }),
        }
    }

    /// `Events` messages for these IDs, in canonical order with space
    /// events first, each within the message limits.
    fn events(&mut self, replica: &Replica, ids: Vec<EventId>) -> Vec<Action> {
        let Some(log) = replica.log() else {
            // Before the genesis, only what is staged.
            return Vec::new();
        };
        let ids: Vec<EventId> = ordered(log, ids)
            .into_iter()
            .filter(|id| self.may_serve(replica, *id))
            .filter(|id| !self.withheld.contains(id))
            .collect();
        let mut actions = Vec::new();
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut size = MESSAGE_OVERHEAD;
        for id in ids {
            let Some(event) = replica.event(id) else {
                continue;
            };
            let signed = event.signed();
            let cost = signed.len() + 8;
            if !batch.is_empty()
                && (size + cost > MAX_MESSAGE_BYTES || batch.len() == MAX_MESSAGE_ITEMS)
            {
                actions.push(self.events_message(std::mem::take(&mut batch)));
                size = MESSAGE_OVERHEAD;
            }
            size += cost;
            batch.push(signed);
            self.known.insert(id);
        }
        if !batch.is_empty() {
            actions.push(self.events_message(batch));
        }
        actions
    }

    fn events_message(&self, events: Vec<Vec<u8>>) -> Action {
        Action::Send(SyncMessage {
            space: self.space,
            message: Message::Events { events },
        })
    }
}

/// The replica's `Heads`: its heads and its vector, and at a partial
/// replica its system stream and the streams it holds, so that the other
/// side sends it no other stream (units.md, "Partial replicas").
pub fn heads(replica: &Replica) -> Message {
    let heads = replica.heads();
    let vector = replica.log().map(vector);
    let streams = replica
        .held_streams()
        .map(|held| {
            let mut streams: Vec<StreamId> = held.iter().copied().collect();
            streams.extend(replica.system_stream());
            streams.sort_unstable();
            streams.dedup();
            streams.truncate(MAX_MESSAGE_ITEMS);
            streams
        })
        .unwrap_or_default();
    Message::Heads {
        heads: heads.into_iter().take(MAX_MESSAGE_ITEMS).collect(),
        vector,
        streams,
    }
}

/// Per author, the greatest `seq` held and that event's ID.
pub fn vector(log: &Log) -> Vec<VectorEntry> {
    let mut authors: BTreeSet<DeviceId> = BTreeSet::new();
    for event in log.events() {
        authors.insert(*event.author());
    }
    let mut out: Vec<VectorEntry> = authors
        .into_iter()
        .filter_map(|author| {
            let id = log.latest(&author)?;
            let seq = log.event(id)?.seq();
            Some(VectorEntry { author, seq, id })
        })
        .collect();
    out.sort();
    out.truncate(MAX_MESSAGE_ITEMS);
    out
}

/// Every event the replica holds outside the past of `heads`, which it
/// holds.
fn after(replica: &Replica, heads: &[EventId]) -> Vec<EventId> {
    let Some(log) = replica.log() else {
        return Vec::new();
    };
    let mut theirs: BTreeSet<EventId> = BTreeSet::new();
    for head in heads {
        if log.contains(*head) {
            theirs.extend(log.past(*head));
            theirs.insert(*head);
        }
    }
    log.canonical()
        .into_iter()
        .filter(|id| !theirs.contains(id))
        .collect()
}

/// IDs in canonical order, space events first, each after its parents
/// among them.
fn ordered(log: &Log, ids: Vec<EventId>) -> Vec<EventId> {
    let wanted: BTreeSet<EventId> = ids.into_iter().collect();
    let canonical: Vec<EventId> = log
        .canonical()
        .into_iter()
        .filter(|id| wanted.contains(id))
        .collect();
    let (space, other): (Vec<EventId>, Vec<EventId>) = canonical
        .into_iter()
        .partition(|id| log.event(*id).is_some_and(|e| e.kind() == kind::SPACE));
    // A space event whose parents among these are not all space events
    // keeps its canonical place after them, so it can be placed on arrival.
    let space_set: BTreeSet<EventId> = space.iter().copied().collect();
    let mut first = Vec::new();
    let mut rest = Vec::new();
    let mut deferred: BTreeSet<EventId> = BTreeSet::new();
    for id in &space {
        let event = log.event(*id).expect("placed");
        let blocked = event
            .parents()
            .iter()
            .any(|p| (wanted.contains(p) && !space_set.contains(p)) || deferred.contains(p));
        if blocked {
            deferred.insert(*id);
        } else {
            first.push(*id);
        }
    }
    let mut remaining: Vec<EventId> = log
        .canonical()
        .into_iter()
        .filter(|id| other.contains(id) || deferred.contains(id))
        .collect();
    rest.append(&mut remaining);
    first.extend(rest);
    first
}
