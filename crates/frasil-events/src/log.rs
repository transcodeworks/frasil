//! A log's placed events, and their order (events.md, "Placement and
//! order", "Members that start from a base").
//!
//! ```text
//! place(event, log), in order:
//!   1. The event's log ID is the log's ID.                        else WrongLog
//!   2. No parent is an event of another log.                      else WrongLog
//!   3. Each parent is placed in this log, or stands as an
//!      authenticated stub that counts for the event (units.md).   else Pending, and fetch it
//! ```
//!
//! A parent the replica **dropped** ([`Log::mark_dropped`]) counts as
//! present for step 3: it is in the past of the replica's kept checkpoint
//! (roster.md, 3.15.6 Forgetting, and starting from a checkpoint), and the
//! replica never fetches it again. An event that cites it may be cited in
//! turn ([`Log::citable`]). It adds nothing to the event's height, unless
//! the replica held it and kept its height ([`Log::mark_dropped_at`]):
//! a parent of an event the replica keeps of the checkpoint's past, which
//! keeps the height and canonical order it was judged at (events.md,
//! "Placement and order"). A dropped `prev` is not checked against its
//! chain again.
//!
//! # Stubs
//!
//! A stub counts only from a signed source the replica has judged (units.md,
//! 3.9 Placing against stubs, "Where stubs come from"). The log keeps, for
//! each stub, whether its height is **confirmed** ("Confirming heights"): a
//! space event is placed against a stub only once it is, and until then
//! waits for the parent, which [`Log::wanted`] names. A pending snapshot
//! unit's own stubs may place it, **provisionally**
//! ([`Log::add_provisional_stubs`]): the replica judges the unit, then keeps
//! them ([`Log::accept_provisional`]) or takes them back with every event
//! placed on them ([`Log::retract_provisional`]). When a stubbed event
//! arrives in full, the heights of the events placed on its stub are
//! computed again from the event.
//!
//! - The **past** of an event is its parents, their parents, and so on. `a`
//!   is **before** `b` when `a` is in the past of `b`; they are
//!   **concurrent** when they differ and neither is before the other.
//! - A **view** is a set of placed events closed under parents. The
//!   **heads** of a view are its events in no other event's past.
//! - The **height** of a genesis is 0, and of another event one more than
//!   the greatest height of its parents; a stubbed parent's height is the
//!   stub's.
//! - **Canonical order** sorts by height, then by event ID as a byte string,
//!   smallest first. It extends the causal order.
//!
//! A [`Log`] also keeps each placed event's [`SignatureState`]: a scheme-0
//! event verified at decoding, a scheme-2 event once its ML-DSA-65 half
//! verifies ([`Log::verify_hybrid`]). Only verified events count as
//! evidence of a fork, or root coverage. [`Log::event`] gives any placed
//! event as an [`Event`], whose body it does not open;
//! [`Log::verified`] gives a placed event as a [`VerifiedEvent`] only once
//! its signature verified in full, so that what applies or judges an event
//! reads it from there (events.md, 3.3 The ML-DSA-65 half: a `NoHybridKey`
//! event "is kept, never applied and never cited").
//!
//! # Partial replicas
//!
//! A partial replica (units.md, "Partial replicas") holds the space's frame
//! and the streams it opens. A parent outside them is **witnessed** once the
//! replica has fetched it and checked its envelope, signature and ID
//! ([`Log::witness`]); an event is placed once each parent is placed,
//! stubbed or witnessed. A witness is never placed: it is in no view, has
//! no chain and is never cited, and the replica fetches its own parents
//! only to learn a height. A `Path` that checks witnesses its events
//! ([`Log::add_path`]).
//!
//! **Proven order** follows the parents of placed and witnessed events: `a`
//! is proven before `b` when such a chain leads from `b` down to `a`. It is
//! the log's order, [`Log::precedes`] ([`Log::proves_before`] names it so);
//! on a log with no witness it is causal order.
//!
//! **Heights** (units.md, "Partial replicas", "Heights"). A replica knows
//! an event's height when it holds the event's whole past, placed, stubbed
//! or witnessed ([`Log::is_height_exact`]). Where a witness's parents are
//! not all held, the log takes one more than the greatest height among
//! those it holds, or 1, as a lower bound, and every height resting on it
//! is a lower bound too. The log revises them as parents arrive, so a
//! height never falls below a held parent's: canonical order extends proven
//! order. [`Log::heights_wanted`] names the parents to fetch, by ID, to
//! learn a height.

use crate::EventClass;
use crate::cuts::Cuts;
use crate::decode::{Event, VerifiedEvent};
use crate::envelope::EventId;
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, HybridKeys, KeySource};
use std::collections::{BTreeMap, BTreeSet};

/// Where a placed event's signature stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureState {
    /// Scheme 0 verified strictly, or both halves of scheme 2.
    Verified,
    /// Scheme 2, its Ed25519 half verified, waiting for keys that hash to
    /// its `kc` (`NoHybridKey`, pending).
    NoHybridKey,
    /// Scheme 2, its ML-DSA-65 half refused under the author's key. Another
    /// copy of the event, with another signature, may replace this one.
    BadSignature,
}

/// A stub (units.md, "Stubs"): an event whose bytes the replica does not
/// hold, from a signed source, which placement accepts as a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stub {
    /// The event's ID.
    pub id: EventId,
    /// The event's author.
    pub author: DeviceId,
    /// The event's `seq`.
    pub seq: u64,
    /// The event's height.
    pub height: u64,
    /// The event's kind.
    pub kind: u8,
    /// The cuts the event declares (events.md, 3.11 Cuts), which a stub of
    /// an event that declares any carries as its last element; a parent
    /// held as a stub contributes them to its children's cuts.
    pub cuts: Cuts,
}

/// What [`Log::place`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// The event is placed, and so is every pending event it released: their
    /// IDs, in the order placed.
    Placed(Vec<EventId>),
    /// The event is pending (`Pending`) until these parents are placed or
    /// stubbed. The replica fetches them, from the event's author first.
    Pending(Vec<EventId>),
    /// The event is already placed or pending. The log keeps the copy it
    /// has, unless that copy's signature was refused and this one replaces
    /// it.
    Known,
}

#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) event: Event,
    pub(crate) height: u64,
    /// The height is the one a full replica computes: no witness is in the
    /// event's held past.
    pub(crate) exact: bool,
    pub(crate) signature: SignatureState,
    /// The event, when `signature` is [`SignatureState::Verified`].
    pub(crate) verified: Option<VerifiedEvent>,
    pub(crate) children: Vec<EventId>,
}

impl Node {
    /// Sets the signature's state, and the verified event with it.
    pub(crate) fn set_signature(&mut self, state: SignatureState, verified: Option<VerifiedEvent>) {
        debug_assert_eq!(state == SignatureState::Verified, verified.is_some());
        self.signature = state;
        self.verified = verified;
    }
}

/// A witnessed event and its height, a lower bound unless `exact`.
#[derive(Debug, Clone)]
pub(crate) struct Witness {
    pub(crate) event: Event,
    pub(crate) height: u64,
    /// Every parent is held, with an exact height.
    pub(crate) exact: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Waiting {
    pub(crate) event: Event,
    pub(crate) missing: BTreeSet<EventId>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StubEntry {
    pub(crate) stub: Stub,
    /// Two stubs disagree for this ID: it no longer counts for placement
    /// (units.md, "Placing against stubs").
    pub(crate) disputed: bool,
    /// Its height is confirmed: a space event may rest on it (units.md,
    /// "Confirming heights").
    pub(crate) confirmed: bool,
    /// The pending snapshot unit whose own stubs gave it, until the replica
    /// judges that unit.
    pub(crate) provisional: Option<EventId>,
}

/// The initial state of a decoded event's signature, and the event as
/// verified when it is scheme 0.
pub(crate) fn initial_state(event: &Event) -> (SignatureState, Option<VerifiedEvent>) {
    match event.verified_scheme_0() {
        Some(verified) => (SignatureState::Verified, Some(verified)),
        None => (SignatureState::NoHybridKey, None),
    }
}

/// The events of one log a replica has placed, and those pending on a
/// parent.
#[derive(Debug, Clone)]
pub struct Log {
    pub(crate) id: EventId,
    pub(crate) nodes: BTreeMap<EventId, Node>,
    /// Canonical order: `(height, ID)`.
    pub(crate) order: BTreeSet<(u64, EventId)>,
    pub(crate) heads: BTreeSet<EventId>,
    /// Each author's events: `(seq, ID)`.
    pub(crate) chains: BTreeMap<DeviceId, BTreeSet<(u64, EventId)>>,
    pub(crate) stubs: BTreeMap<EventId, StubEntry>,
    /// Each ID that is stubbed or witnessed and not placed, and the placed
    /// events that name it as a parent: the children it takes when it is
    /// placed.
    pub(crate) on_unplaced: BTreeMap<EventId, BTreeSet<EventId>>,
    /// Witnessed events (units.md, "Partial replicas").
    pub(crate) witnesses: BTreeMap<EventId, Witness>,
    /// A witness was ever added: order follows witnesses, and does not
    /// prune by height.
    pub(crate) witnessed: bool,
    /// Once a witness was added: each ID, held or not, and the placed and
    /// witnessed events that name it as a parent, whose heights to revise
    /// when it arrives or rises. Events placed before any witness have
    /// final heights.
    pub(crate) dependents: BTreeMap<EventId, BTreeSet<EventId>>,
    pub(crate) pending: BTreeMap<EventId, Waiting>,
    /// A missing parent, and the pending events that wait for it.
    pub(crate) waiters: BTreeMap<EventId, BTreeSet<EventId>>,
    /// Every event placed, in the order placed.
    pub(crate) placed: Vec<EventId>,
    /// The placed events that are not units, in canonical order: the few a
    /// reader of the space's frame looks for among them all.
    pub(crate) frame: BTreeSet<(u64, EventId)>,
    /// How many times the log changed other than by placing an event.
    pub(crate) revision: u64,
    /// The ML-DSA-65 verdicts reached under each event's author's keys
    /// ([`Log::verify_hybrid_remembered`]).
    pub(crate) verdicts: HybridVerdicts,
    /// The envelopes of checkpoints kept beyond the events placed and
    /// witnessed, by ID ([`Log::keep_envelope`]).
    pub(crate) kept: BTreeMap<EventId, Event>,
    /// The IDs of the events the replica dropped when it forgot the past of
    /// its kept checkpoint ([`Log::mark_dropped`]).
    pub(crate) dropped: BTreeSet<EventId>,
    /// The heights the replica kept of dropped events, each a parent of an
    /// event it keeps of its kept checkpoint's past
    /// ([`Log::mark_dropped_at`]).
    pub(crate) dropped_heights: BTreeMap<EventId, u64>,
}

/// The outcome of an ML-DSA-65 half checked under the keys that hash to its
/// event's `kc`, by event ID and the SHA-256 of the signature: what
/// [`Log::verify_hybrid_remembered`] gives again without verifying again.
///
/// The outcome is a function of these alone. The event ID hashes the map,
/// which holds `ed`, `kc`, the scheme and everything `tbs` signs (events.md,
/// 2.5 What is signed, and the event ID); the signature is the rest; and
/// one ML-DSA-65 key hashes to a `kc` (roster.md, 3.4.2 An author's keys).
/// So whichever source gave the keys, and whichever view asks, a check under
/// matching keys gives the same outcome. A check with no matching keys is
/// `NoHybridKey` and is never kept: it depends on the keys held.
///
/// The verdicts are kept in memory only, shared by the log's clones, and a
/// log read back from rest starts with none.
#[derive(Clone, Default)]
pub(crate) struct HybridVerdicts(std::sync::Arc<std::sync::Mutex<Verdicts>>);

/// The outcomes, by event ID and the SHA-256 of the signature.
type Verdicts = BTreeMap<(EventId, [u8; 32]), Result<(), EventClass>>;

impl HybridVerdicts {
    fn lock(&self) -> std::sync::MutexGuard<'_, Verdicts> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The events before one event of a log, from [`Log::ancestry`].
#[derive(Debug, Clone)]
pub struct Ancestry<'a> {
    log: &'a Log,
    /// Every ID a parent link from the event reaches through held events:
    /// placed and witnessed events, and the parents they name, held or not.
    ids: BTreeSet<EventId>,
}

impl Ancestry<'_> {
    /// [`Log::precedes`]`(earlier, later)` for the `later` this ancestry is
    /// of: `earlier` has a height and a chain of parents through held
    /// events leads from `later` to it. Heights only shorten the walk
    /// there: along a parent link they fall, except at a partial replica,
    /// which walks without them.
    pub fn includes(&self, earlier: EventId) -> bool {
        self.ids.contains(&earlier) && self.log.height(earlier).is_some()
    }
}

/// Shows nothing of what is remembered: a log that remembers more is the
/// same log.
impl std::fmt::Debug for HybridVerdicts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridVerdicts").finish_non_exhaustive()
    }
}

std::thread_local! {
    /// How many walks [`Log::precedes`] made on this thread.
    static WALKS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// How many walks of the log [`Log::precedes`] has made on this thread:
/// what a caller that answers causal order from precomputed pasts saves,
/// for tests and measurements.
#[doc(hidden)]
pub fn precedes_walks() -> u64 {
    WALKS.with(core::cell::Cell::get)
}

impl Log {
    /// The log a genesis starts: its ID is the genesis's.
    ///
    /// # Errors
    ///
    /// `WrongLog` if the event is not a genesis.
    pub fn new(genesis: Event) -> Result<Self, EventClass> {
        if !genesis.is_genesis() {
            return Err(EventClass::WrongLog);
        }
        let id = genesis.id();
        let mut log = Self {
            id,
            nodes: BTreeMap::new(),
            order: BTreeSet::new(),
            heads: BTreeSet::new(),
            chains: BTreeMap::new(),
            stubs: BTreeMap::new(),
            on_unplaced: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            witnessed: false,
            dependents: BTreeMap::new(),
            pending: BTreeMap::new(),
            waiters: BTreeMap::new(),
            placed: Vec::new(),
            frame: BTreeSet::new(),
            revision: 0,
            verdicts: HybridVerdicts::default(),
            kept: BTreeMap::new(),
            dropped: BTreeSet::new(),
            dropped_heights: BTreeMap::new(),
        };
        log.insert(genesis);
        Ok(log)
    }

    /// The log's ID: its genesis's event ID.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// The genesis.
    pub fn genesis(&self) -> &Event {
        &self.nodes[&self.id].event
    }

    /// How many events are placed.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Always `false`: a log holds at least its genesis.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether the event is placed.
    pub fn contains(&self, id: EventId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// A placed event.
    pub fn event(&self, id: EventId) -> Option<&Event> {
        self.nodes.get(&id).map(|node| &node.event)
    }

    /// A placed event whose signature verified in full: scheme 0, or both
    /// halves of scheme 2. `None` for an event not placed, or `NoHybridKey`
    /// or `BadSignature` (events.md, 3.3 The ML-DSA-65 half).
    pub fn verified(&self, id: EventId) -> Option<&VerifiedEvent> {
        self.nodes.get(&id).and_then(|node| node.verified.as_ref())
    }

    /// Every placed event whose signature verified in full, in canonical
    /// order.
    pub fn verified_events(&self) -> impl Iterator<Item = &VerifiedEvent> {
        self.order
            .iter()
            .filter_map(|(_, id)| self.nodes[id].verified.as_ref())
    }

    /// A placed event's signature state.
    pub fn signature_state(&self, id: EventId) -> Option<SignatureState> {
        self.nodes.get(&id).map(|node| node.signature)
    }

    /// Whether a placed event's signature verified in full.
    pub fn is_verified(&self, id: EventId) -> bool {
        self.signature_state(id) == Some(SignatureState::Verified)
    }

    /// `place(event, log)`, treating no parent as another log's. See
    /// [`place_checked`](Log::place_checked).
    ///
    /// # Errors
    ///
    /// `WrongLog` if the event is of another log.
    pub fn place(&mut self, event: Event) -> Result<Placement, EventClass> {
        self.place_checked(event, |_| false)
    }

    /// `place(event, log)`, in order: the event's log ID is this log's
    /// (`WrongLog`); no parent is an event of another log, which
    /// `of_another_log` tells from the logs the replica follows
    /// (`WrongLog`); and each parent is placed or stubbed, else the event is
    /// pending. A partial replica's witnessed parents count as placed here
    /// (units.md, "Partial replicas"), and so do the parents the replica
    /// dropped ([`mark_dropped`](Log::mark_dropped)).
    ///
    /// A replica keeps the first copy of an event whose signature it
    /// verified and treats every other copy as that event: a copy of a
    /// placed event replaces it only if the placed copy's ML-DSA-65 half was
    /// refused.
    ///
    /// # Errors
    ///
    /// `WrongLog`.
    pub fn place_checked(
        &mut self,
        event: Event,
        of_another_log: impl Fn(EventId) -> bool,
    ) -> Result<Placement, EventClass> {
        // 1. The event's log ID is the log's ID.
        if event.log_id() != self.id {
            return Err(EventClass::WrongLog);
        }
        // 2. No parent is an event of another log.
        if event.parents().iter().any(|&parent| of_another_log(parent)) {
            return Err(EventClass::WrongLog);
        }
        let id = event.id();
        if let Some(node) = self.nodes.get_mut(&id) {
            if node.signature == SignatureState::BadSignature
                && node.event.signature() != event.signature()
            {
                let (state, verified) = initial_state(&event);
                node.set_signature(state, verified);
                node.event = event;
                self.revision += 1;
            }
            return Ok(Placement::Known);
        }
        if self.pending.contains_key(&id) {
            return Ok(Placement::Known);
        }
        // 3. Each parent placed, or stubbed; or, at a partial replica,
        // witnessed. A space event rests only on a confirmed stub.
        let missing: BTreeSet<EventId> = event
            .parents()
            .iter()
            .copied()
            .filter(|&parent| !self.counts_for(parent, event.kind()))
            .collect();
        if !missing.is_empty() {
            for &parent in &missing {
                self.waiters.entry(parent).or_default().insert(id);
            }
            let wanted = missing.iter().copied().collect();
            self.pending.insert(id, Waiting { event, missing });
            return Ok(Placement::Pending(wanted));
        }
        self.insert(event);
        let mut placed = vec![id];
        self.release(id, &mut placed);
        Ok(Placement::Placed(placed))
    }

    /// Witnesses an event outside a partial replica's frame and streams
    /// (units.md, "Partial replicas"): the caller fetched it and decoded it
    /// ([`decode`](crate::decode())), which checked its envelope and
    /// signature, and its ID is the one asked for. Places the pending
    /// events it releases, returning their IDs in the order placed. The
    /// replica fetches a witness's own parents only to learn a height
    /// ([`heights_wanted`](Log::heights_wanted)); each one witnessed revises
    /// the heights resting on it.
    ///
    /// A placed event, or one witnessed already, changes nothing.
    ///
    /// # Errors
    ///
    /// `WrongLog` if the event is of another log.
    pub fn witness(&mut self, event: Event) -> Result<Vec<EventId>, EventClass> {
        if event.log_id() != self.id {
            return Err(EventClass::WrongLog);
        }
        let id = event.id();
        if self.nodes.contains_key(&id) || self.witnesses.contains_key(&id) {
            return Ok(Vec::new());
        }
        let (height, exact) = self.measure(&event);
        self.witnessed = true;
        self.revision += 1;
        self.register(&event);
        self.undrop(id);
        self.witnesses.insert(
            id,
            Witness {
                event,
                height,
                exact,
            },
        );
        self.refresh(id);
        let mut placed = Vec::new();
        self.release(id, &mut placed);
        Ok(placed)
    }

    /// A `Path` (units.md, "Sync messages"): `path`'s first event is a
    /// parent of `from`, each next a parent of the one before, and the last
    /// has `to` among its parents. `from` must be placed or witnessed. A
    /// path that checks witnesses each of its events not placed already
    /// ([`witness`](Log::witness)) and returns the pending events that
    /// released; one that does not check returns `None` and changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// `WrongLog` if an event of the path is of another log.
    pub fn add_path(
        &mut self,
        from: EventId,
        to: EventId,
        path: Vec<Event>,
    ) -> Result<Option<Vec<EventId>>, EventClass> {
        let Some(start) = self.held_event(from) else {
            return Ok(None);
        };
        if !check_path(&path, start, to) {
            return Ok(None);
        }
        if path.iter().any(|event| event.log_id() != self.id) {
            return Err(EventClass::WrongLog);
        }
        let mut placed = Vec::new();
        for event in path {
            placed.extend(self.witness(event)?);
        }
        Ok(Some(placed))
    }

    /// A witnessed event that is not placed.
    pub fn witnessed(&self, id: EventId) -> Option<&Event> {
        self.witnesses
            .get(&id)
            .filter(|_| !self.nodes.contains_key(&id))
            .map(|witness| &witness.event)
    }

    /// How many events were ever placed: a mark for
    /// [`placed_since`](Log::placed_since).
    pub fn placed_count(&self) -> usize {
        self.placed.len()
    }

    /// The events placed since a mark, in the order placed: each after
    /// its placed parents.
    pub fn placed_since(&self, mark: usize) -> &[EventId] {
        self.placed.get(mark..).unwrap_or_default()
    }

    /// How many times the log changed other than by placing an event: a
    /// copy that replaced a placed one, a stub, a witness, a signature
    /// checked. A reader that saw the same revision and the same events
    /// sees the same log, plus what was placed since.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether a witness was ever added: the past then follows witnessed
    /// events too ([`precedes`](Log::precedes)).
    pub fn has_witnesses(&self) -> bool {
        self.witnessed
    }

    /// The witnessed events that are not placed, by ID.
    pub fn witnesses(&self) -> impl Iterator<Item = &Event> {
        self.witnesses
            .iter()
            .filter(|(id, _)| !self.nodes.contains_key(id))
            .map(|(_, witness)| &witness.event)
    }

    /// Adds a stub from a signed source (units.md, "Placing against
    /// stubs"), its height confirmed, and places the pending events it
    /// releases, returning their IDs in the order placed.
    ///
    /// A stub of an event already placed changes nothing: the replica uses
    /// the event (units.md compares the two). A second stub for one ID that
    /// disagrees with the first disputes it: from then on it releases no
    /// event, until the event itself is placed.
    pub fn add_stub(&mut self, stub: Stub) -> Vec<EventId> {
        self.add_entry(stub, true, None)
    }

    /// Adds a stub as [`add_stub`](Log::add_stub) does, its height not yet
    /// confirmed (units.md, "Confirming heights"): units are placed against
    /// it, and a space event that names it waits until
    /// [`confirm_stub`](Log::confirm_stub) or the event itself.
    pub fn add_stub_unconfirmed(&mut self, stub: Stub) -> Vec<EventId> {
        self.add_entry(stub, false, None)
    }

    /// Confirms a stub's height (units.md, "Confirming heights"), and
    /// places the space events that waited for it, returning their IDs in
    /// the order placed. A stub not held, or disputed, changes nothing.
    pub fn confirm_stub(&mut self, id: EventId) -> Vec<EventId> {
        let mut placed = Vec::new();
        if let Some(entry) = self.stubs.get_mut(&id)
            && !entry.confirmed
            && !entry.disputed
        {
            entry.confirmed = true;
            self.revision += 1;
            if !self.nodes.contains_key(&id) {
                self.release(id, &mut placed);
            }
        }
        placed
    }

    /// Confirms every stub whose event the log holds in full, pending on a
    /// parent, with the stub's author, `seq`, kind and cuts (units.md,
    /// "Confirming heights"), and places the space events that waited for
    /// it, returning their IDs in the order placed.
    pub fn confirm_held(&mut self) -> Vec<EventId> {
        let held: Vec<EventId> = self
            .stubs
            .iter()
            .filter(|(_, entry)| !entry.confirmed && self.held_in_full(&entry.stub))
            .map(|(id, _)| *id)
            .collect();
        let mut placed = Vec::new();
        for id in held {
            placed.extend(self.confirm_stub(id));
        }
        placed
    }

    /// Whether the log holds a stub's event in full, pending on a parent,
    /// with the stub's author, `seq` and kind, and the cuts the stub
    /// carries the event's own: a stub whose cuts differ is `BadStub`
    /// (units.md, "Placing against stubs"), and confirms nothing.
    fn held_in_full(&self, stub: &Stub) -> bool {
        self.pending.get(&stub.id).is_some_and(|waiting| {
            waiting.event.author() == &stub.author
                && waiting.event.seq() == stub.seq
                && waiting.event.kind() == stub.kind
                && waiting.event.cuts() == stub.cuts.as_slice()
        })
    }

    /// Whether a stub is held, not disputed, and its height confirmed.
    pub fn is_stub_confirmed(&self, id: EventId) -> bool {
        self.stubs
            .get(&id)
            .is_some_and(|entry| entry.confirmed && !entry.disputed)
    }

    fn add_entry(&mut self, stub: Stub, confirmed: bool, source: Option<EventId>) -> Vec<EventId> {
        if self.nodes.contains_key(&stub.id) {
            return Vec::new();
        }
        match self.stubs.get_mut(&stub.id) {
            Some(entry) => {
                if entry.stub != stub {
                    if !entry.disputed {
                        entry.disputed = true;
                        self.revision += 1;
                    }
                    return Vec::new();
                }
                // The same stub from a judged source: it no longer rests
                // on the provisional one.
                if source.is_none() && entry.provisional.is_some() {
                    entry.provisional = None;
                    self.revision += 1;
                }
                if confirmed {
                    return self.confirm_stub(stub.id);
                }
                Vec::new()
            }
            None => {
                self.revision += 1;
                let confirmed = confirmed || self.held_in_full(&stub);
                self.stubs.insert(
                    stub.id,
                    StubEntry {
                        stub,
                        disputed: false,
                        confirmed,
                        provisional: source,
                    },
                );
                self.refresh(stub.id);
                let mut placed = Vec::new();
                self.release(stub.id, &mut placed);
                placed
            }
        }
    }

    /// Places a pending snapshot unit against its own stubs, provisionally
    /// (units.md, "Where stubs come from"): only when `stubs` hold a stub
    /// of every parent that the unit's pending past lacks, none of them
    /// held already and none named by a space event of that past. Those
    /// stubs are added, unconfirmed, and the events they release placed;
    /// returns their IDs in the order placed, the unit among them. `None`,
    /// and nothing changes, otherwise.
    ///
    /// The stubs stay the unit's until the replica keeps them
    /// ([`accept_provisional`](Log::accept_provisional)) or takes them back
    /// ([`retract_provisional`](Log::retract_provisional)).
    pub fn add_provisional_stubs(
        &mut self,
        source: EventId,
        stubs: &[Stub],
    ) -> Option<Vec<EventId>> {
        if !self.pending.contains_key(&source) {
            return None;
        }
        // The unit's pending past, and the parents it lacks that are not
        // pending themselves.
        let by_id: BTreeMap<EventId, &Stub> =
            stubs.iter().map(|stub| (stub.id, stub)).collect_map();
        let mut seen = BTreeSet::from([source]);
        let mut stack = vec![source];
        let mut lacking = BTreeSet::new();
        while let Some(current) = stack.pop() {
            let Some(waiting) = self.pending.get(&current) else {
                continue;
            };
            let space_event = waiting.event.kind() == crate::kind::SPACE;
            for &parent in &waiting.missing {
                match by_id.get(&parent) {
                    // A stub of the unit's own stands for the parent; a
                    // space event rests on it only if it is confirmed by
                    // the event held in full.
                    Some(stub) if !self.stubs.contains_key(&parent) => {
                        if space_event && !self.held_in_full(stub) {
                            return None;
                        }
                        lacking.insert(parent);
                    }
                    _ if self.pending.contains_key(&parent) => {
                        if seen.insert(parent) {
                            stack.push(parent);
                        }
                    }
                    _ => return None,
                }
            }
        }
        let mut placed = Vec::new();
        for id in lacking {
            placed.extend(self.add_entry(*by_id[&id], false, Some(source)));
        }
        if !self.nodes.contains_key(&source) {
            self.retract_provisional(source);
            return None;
        }
        Some(placed)
    }

    /// Keeps the envelope of a checkpoint beyond the events the log places
    /// and witnesses (events.md, 3.11 Cuts, "Ordering needs envelopes"): a
    /// replica keeps the envelope of every checkpoint its kept checkpoint's
    /// cuts reach after it forgets the events around them (roster.md,
    /// 3.15.6 Forgetting, and starting from a checkpoint), and a newcomer
    /// keeps those a space snapshot hands it (units.md, "The space
    /// snapshot", key 14). The cuts check reads them to order checkpoints;
    /// a kept envelope is never placed, cited or judged here. Returns
    /// whether it was not kept already.
    ///
    /// The caller decoded the event, which checked its envelope and its
    /// Ed25519 signature or half.
    ///
    /// # Errors
    ///
    /// `WrongLog` for an event of another log; `Malformed` for an event
    /// that cannot be a checkpoint (a space event other than a genesis).
    pub fn keep_envelope(&mut self, event: Event) -> Result<bool, EventClass> {
        if event.log_id() != self.id {
            return Err(EventClass::WrongLog);
        }
        if !crate::cuts::may_be_checkpoint(&event) {
            return Err(ErrorClass::Malformed.into());
        }
        let id = event.id();
        if self.kept.contains_key(&id) {
            return Ok(false);
        }
        self.undrop(id);
        self.kept.insert(id, event);
        self.revision += 1;
        Ok(true)
    }

    /// The kept envelope of a checkpoint, if the log keeps it
    /// ([`keep_envelope`](Log::keep_envelope)).
    pub fn kept_envelope_of(&self, id: EventId) -> Option<&Event> {
        self.kept.get(&id)
    }

    /// Every kept checkpoint envelope, by ID.
    pub fn kept_envelopes(&self) -> impl Iterator<Item = &Event> {
        self.kept.values()
    }

    /// Stops keeping a checkpoint's envelope, once no cut the replica
    /// still orders reaches it. Returns it.
    pub fn drop_kept_envelope(&mut self, id: EventId) -> Option<Event> {
        let event = self.kept.remove(&id)?;
        self.revision += 1;
        Some(event)
    }

    /// Records that the replica dropped this event: it forgot the past of
    /// its kept checkpoint and keeps the ID alone (roster.md, 3.15.6
    /// Forgetting, and starting from a checkpoint), or, as a newcomer, a
    /// peer answered `Missing` for a parent outside the world it fetched.
    /// The cuts check counts such a parent as contributing nothing and
    /// never waits for it (events.md, 3.11 Cuts), and placement counts it
    /// as present. An event the log places, witnesses or keeps the envelope
    /// of is not dropped: the caller first lets go of it. Returns whether
    /// it was not recorded already.
    ///
    /// Events already pending on it stay pending until
    /// [`release_dropped`](Log::release_dropped), or use
    /// [`drop_parent`](Log::drop_parent), which does both.
    pub fn mark_dropped(&mut self, id: EventId) -> bool {
        if self.nodes.contains_key(&id)
            || self.witnesses.contains_key(&id)
            || self.kept.contains_key(&id)
            || !self.dropped.insert(id)
        {
            return false;
        }
        self.revision += 1;
        true
    }

    /// Records that the replica dropped this event, as
    /// [`mark_dropped`](Log::mark_dropped) does, and keeps its height, from
    /// 1: the replica held it, and it is a parent of an event the replica
    /// keeps of its kept checkpoint's past (events.md, "Placement and
    /// order"; at-rest.md, the `dropped` table, key 3). An event placed on
    /// it counts the height as a placed parent's would, so that it keeps
    /// the height it was judged at; the heights of events already placed
    /// on it are computed again. Returns whether anything changed: the
    /// event was not dropped, or not at this height. An event the log
    /// places, witnesses or keeps the envelope of, and a height of 0,
    /// change nothing.
    pub fn mark_dropped_at(&mut self, id: EventId, height: u64) -> bool {
        if height == 0
            || self.nodes.contains_key(&id)
            || self.witnesses.contains_key(&id)
            || self.kept.contains_key(&id)
        {
            return false;
        }
        let new = self.dropped.insert(id);
        if self.dropped_heights.insert(id, height) == Some(height) && !new {
            return false;
        }
        self.revision += 1;
        // The events placed on it count its height now.
        let children: Vec<EventId> = self
            .on_unplaced
            .get(&id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        for child in children {
            let Some((height, exact)) = self.held_event(child).map(|e| self.measure(e)) else {
                continue;
            };
            if self.set_height(child, height, exact) {
                self.refresh(child);
            }
        }
        true
    }

    /// The height the replica kept of a dropped event
    /// ([`mark_dropped_at`](Log::mark_dropped_at)); `None` for one dropped
    /// without it, which adds nothing to a height, and for an event not
    /// dropped.
    pub fn dropped_height(&self, id: EventId) -> Option<u64> {
        self.dropped_heights.get(&id).copied()
    }

    /// Marks the event dropped at its height
    /// ([`mark_dropped_at`](Log::mark_dropped_at)) and places the pending
    /// events that waited only for it, and what those release in turn, as
    /// [`drop_parent`](Log::drop_parent) does: what a replica that forgot
    /// places its kept events on after a restart. Returns the events
    /// placed, in the order placed.
    pub fn drop_parent_at(&mut self, id: EventId, height: u64) -> Vec<EventId> {
        self.mark_dropped_at(id, height);
        self.release_dropped(id)
    }

    /// Marks the event dropped ([`mark_dropped`](Log::mark_dropped)) and
    /// places the pending events that waited only for it, and what those
    /// release in turn: a newcomer answered `Missing` for a parent in its
    /// checkpoint's past places what rests on it without a stand-in stub.
    /// Returns the events placed, in the order placed; none when the event
    /// is placed, witnessed or kept as an envelope.
    pub fn drop_parent(&mut self, id: EventId) -> Vec<EventId> {
        self.mark_dropped(id);
        self.release_dropped(id)
    }

    /// Places the pending events that waited only for a dropped event, and
    /// what those release in turn. Returns their IDs in the order placed;
    /// none when the event is not dropped.
    pub fn release_dropped(&mut self, id: EventId) -> Vec<EventId> {
        let mut placed = Vec::new();
        if self.dropped.contains(&id) {
            self.release(id, &mut placed);
        }
        placed
    }

    /// Whether the replica dropped this event ([`Log::mark_dropped`]).
    pub fn is_dropped(&self, id: EventId) -> bool {
        self.dropped.contains(&id)
    }

    /// The IDs of the events the replica dropped, ascending.
    pub fn dropped_ids(&self) -> impl Iterator<Item = EventId> + '_ {
        self.dropped.iter().copied()
    }

    /// The event is held again: it is no longer dropped.
    fn undrop(&mut self, id: EventId) {
        self.dropped.remove(&id);
        self.dropped_heights.remove(&id);
    }

    /// Whether an event is pending on a parent.
    pub fn is_pending(&self, id: EventId) -> bool {
        self.pending.contains_key(&id)
    }

    /// Whether any stub is provisional.
    pub fn has_provisional(&self) -> bool {
        self.stubs.values().any(|entry| entry.provisional.is_some())
    }

    /// The IDs of the provisional stubs: events known only through a unit
    /// the replica has yet to judge, which it still fetches.
    pub fn provisional_stubs(&self) -> impl Iterator<Item = EventId> + '_ {
        self.stubs
            .iter()
            .filter(|(_, entry)| entry.provisional.is_some())
            .map(|(id, _)| *id)
    }

    /// The pending snapshot units whose own stubs placed events
    /// provisionally, and which the replica has yet to judge.
    pub fn provisional_sources(&self) -> BTreeSet<EventId> {
        self.stubs
            .values()
            .filter_map(|entry| entry.provisional)
            .collect()
    }

    /// The placed events that rest on a provisional stub: each has one in
    /// its past. A replica holds them out of its view until it judges the
    /// stubs' unit.
    pub fn resting_on_provisional(&self) -> BTreeSet<EventId> {
        let ids: Vec<EventId> = self
            .stubs
            .iter()
            .filter(|(_, entry)| entry.provisional.is_some())
            .map(|(id, _)| *id)
            .collect();
        self.resting_on(ids)
    }

    /// Keeps the stubs a snapshot unit placed provisionally: the replica
    /// judged it valid (units.md, "Where stubs come from").
    pub fn accept_provisional(&mut self, source: EventId) {
        for entry in self.stubs.values_mut() {
            if entry.provisional == Some(source) {
                entry.provisional = None;
                self.revision += 1;
            }
        }
    }

    /// Takes back the stubs a snapshot unit placed provisionally, the
    /// replica having judged it not valid (units.md, "Where stubs come
    /// from"): every event placed on them is pending again. Returns those
    /// events.
    pub fn retract_provisional(&mut self, source: EventId) -> Vec<EventId> {
        let ids: Vec<EventId> = self
            .stubs
            .iter()
            .filter(|(_, entry)| entry.provisional == Some(source))
            .map(|(id, _)| *id)
            .collect();
        if ids.is_empty() {
            return Vec::new();
        }
        let gone = self.resting_on(ids.iter().copied());
        for id in &ids {
            self.stubs.remove(id);
            self.on_unplaced.remove(id);
        }
        self.revision += 1;
        self.unplace(&gone);
        gone.into_iter().collect()
    }

    /// The stub held for an ID, if any and not disputed.
    pub fn stub(&self, id: EventId) -> Option<&Stub> {
        self.stubs
            .get(&id)
            .filter(|entry| !entry.disputed)
            .map(|entry| &entry.stub)
    }

    /// Every stub held and not disputed.
    pub fn stubs(&self) -> impl Iterator<Item = &Stub> {
        self.stubs
            .values()
            .filter(|entry| !entry.disputed)
            .map(|entry| &entry.stub)
    }

    /// The events pending on a parent, by ID.
    pub fn pending(&self) -> impl Iterator<Item = &Event> {
        self.pending.values().map(|waiting| &waiting.event)
    }

    /// An event pending on a parent, by its ID.
    pub fn pending_event(&self, id: EventId) -> Option<&Event> {
        self.pending.get(&id).map(|waiting| &waiting.event)
    }

    /// How many events are pending on a parent.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drops an event pending on a parent: the log no longer holds it, and
    /// no longer waits on its missing parents for it. A pending event that
    /// waited on it waits on, and names it among [`wanted`](Log::wanted),
    /// so that it is fetched again. Returns the event dropped.
    pub fn drop_pending(&mut self, id: EventId) -> Option<Event> {
        let waiting = self.pending.remove(&id)?;
        for parent in &waiting.missing {
            if let Some(children) = self.waiters.get_mut(parent) {
                children.remove(&id);
                if children.is_empty() {
                    self.waiters.remove(parent);
                }
            }
        }
        Some(waiting.event)
    }

    /// Every parent the pending events wait for, which the replica fetches.
    pub fn wanted(&self) -> Vec<EventId> {
        self.waiters.keys().copied().collect()
    }

    /// The ML-DSA-65 half of a placed scheme-2 event (events.md, "The
    /// ML-DSA-65 half"), under keys from any source, used only if they hash
    /// to the event's `kc`. Its state becomes [`SignatureState::Verified`]
    /// or [`SignatureState::BadSignature`], or stays
    /// [`SignatureState::NoHybridKey`]. An event verified already passes.
    /// Returns the event verified, as [`Log::verified`] gives it from then
    /// on.
    ///
    /// # Errors
    ///
    /// `Pending` if the event is not placed; otherwise as
    /// [`Event::verify_hybrid`].
    pub fn verify_hybrid(
        &mut self,
        id: EventId,
        keys: Option<&HybridKeys>,
    ) -> Result<VerifiedEvent, EventClass> {
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or(EventClass::Shared(ErrorClass::Pending))?;
        if let Some(verified) = &node.verified {
            return Ok(verified.clone());
        }
        let outcome = node.event.verify_hybrid(keys);
        self.revision += 1;
        match &outcome {
            Ok(verified) => node.set_signature(SignatureState::Verified, Some(verified.clone())),
            Err(EventClass::Shared(ErrorClass::NoHybridKey)) => {
                node.set_signature(SignatureState::NoHybridKey, None);
            }
            Err(_) => node.set_signature(SignatureState::BadSignature, None),
        }
        outcome
    }

    /// A copy of the log that remembers no verdict
    /// ([`verify_hybrid_remembered`](Self::verify_hybrid_remembered)) and
    /// shares none with this one: for a check from scratch.
    pub fn forgetting_verdicts(&self) -> Self {
        Self {
            verdicts: HybridVerdicts::default(),
            ..self.clone()
        }
    }

    /// [`Event::verify_hybrid`] for an event of this log, under keys from
    /// any source, without verifying again a half this log already
    /// verified, or one already checked under keys that hash to the event's
    /// `kc` with the same signature. Keys that hash to another `kc`, or none,
    /// give `NoHybridKey` as they do there, whatever was checked before:
    /// the memo is read only once matching keys are given, so every caller
    /// gets the outcome [`Event::verify_hybrid`] gives it. The log's own
    /// signature states are left as they are.
    ///
    /// # Errors
    ///
    /// As [`Event::verify_hybrid`].
    pub fn verify_hybrid_remembered(
        &self,
        event: &Event,
        keys: Option<&HybridKeys>,
    ) -> Result<VerifiedEvent, EventClass> {
        if let Some(verified) = self.verified(event.id())
            && verified.signature() == event.signature()
        {
            return Ok(verified.clone());
        }
        if event.scheme() != frasil_crypto::schemes::Scheme::Hybrid {
            return event.verify_hybrid(keys);
        }
        let Some(keys) = keys.filter(|keys| keys.commitment() == event.kc()) else {
            return event.verify_hybrid(keys);
        };
        let key = (
            event.id(),
            frasil_crypto::primitives::sha256(&[event.signature()]),
        );
        if let Some(outcome) = self.verdicts.lock().get(&key).copied() {
            return outcome.map(|()| VerifiedEvent::from_rest(event.clone()));
        }
        let outcome = event.verify_hybrid(Some(keys));
        self.verdicts
            .lock()
            .insert(key, outcome.as_ref().map(|_| ()).map_err(|class| *class));
        outcome
    }

    /// Runs [`verify_hybrid`](Self::verify_hybrid) on every placed event
    /// still [`SignatureState::NoHybridKey`], with the keys `source` holds
    /// for its `kc`: what a replica does whenever its keys grow. Returns the
    /// events whose state changed, in canonical order.
    pub fn verify_pending_hybrid(&mut self, source: &(impl KeySource + ?Sized)) -> Vec<EventId> {
        let waiting: Vec<EventId> = self
            .order
            .iter()
            .map(|(_, id)| *id)
            .filter(|id| self.nodes[id].signature == SignatureState::NoHybridKey)
            .collect();
        let mut changed = Vec::new();
        for id in waiting {
            let keys = source.hybrid_keys(self.nodes[&id].event.kc());
            if keys.is_none() {
                continue;
            }
            let _ = self.verify_hybrid(id, keys.as_ref());
            if self.nodes[&id].signature != SignatureState::NoHybridKey {
                changed.push(id);
            }
        }
        changed
    }

    // -- Order

    /// The height of a placed event, or of a stub that is not disputed, or
    /// of a witness; at a partial replica, a lower bound unless
    /// [`is_height_exact`](Log::is_height_exact) (units.md, "Partial
    /// replicas", "Heights").
    pub fn height(&self, id: EventId) -> Option<u64> {
        match self.nodes.get(&id) {
            Some(node) => Some(node.height),
            None => self
                .stub(id)
                .map(|stub| stub.height)
                .or_else(|| self.witnesses.get(&id).map(|witness| witness.height)),
        }
    }

    /// Whether the replica knows an event's height: the event is a stub, or
    /// it holds the event's whole past, placed, stubbed or witnessed, so the
    /// height is the one a full replica computes (units.md, "Partial
    /// replicas", "Heights"). On a log with no witness every held height is
    /// known.
    pub fn is_height_exact(&self, id: EventId) -> bool {
        match self.nodes.get(&id) {
            Some(node) => node.exact,
            None => {
                self.stub(id).is_some()
                    || self.witnesses.get(&id).is_some_and(|witness| witness.exact)
            }
        }
    }

    /// What to fetch, by ID, to learn the heights of `ids` (units.md,
    /// "Partial replicas", "Heights"): each parent the log does not hold of
    /// an event in their held pasts whose height it does not know. The
    /// replica witnesses each one fetched ([`witness`](Log::witness)), or
    /// places it, and asks again until nothing is wanted. Empty when every
    /// height is known.
    pub fn heights_wanted(&self, ids: impl IntoIterator<Item = EventId>) -> Vec<EventId> {
        let mut wanted = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut stack: Vec<EventId> = ids.into_iter().collect();
        while let Some(current) = stack.pop() {
            if !seen.insert(current) || self.is_height_exact(current) {
                continue;
            }
            let Some(event) = self.held_event(current) else {
                continue;
            };
            for &parent in event.parents() {
                if self.height(parent).is_some() {
                    stack.push(parent);
                } else if !self.dropped.contains(&parent) {
                    wanted.insert(parent);
                }
            }
        }
        wanted.into_iter().collect()
    }

    /// Whether `earlier` is in the past of `later`: before it, never the
    /// event itself. The past reaches back as far as the log holds events:
    /// a stubbed parent is in it, and what lies before a stub is not. At a
    /// partial replica it follows witnessed events too: it is proven order
    /// (units.md, "Partial replicas", "Proven order").
    pub fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        let (Some(floor), Some(top)) = (self.height(earlier), self.height(later)) else {
            return false;
        };
        if floor >= top && !self.witnessed {
            return false;
        }
        WALKS.with(|walks| walks.set(walks.get().saturating_add(1)));
        let mut seen = BTreeSet::new();
        let mut stack = vec![later];
        while let Some(current) = stack.pop() {
            let Some(event) = self.held_event(current) else {
                continue;
            };
            for &parent in event.parents() {
                if parent == earlier {
                    return true;
                }
                // An event at or below `earlier`'s height cannot have it in
                // its past.
                if (self.witnessed || self.height(parent).is_some_and(|h| h > floor))
                    && seen.insert(parent)
                {
                    stack.push(parent);
                }
            }
        }
        false
    }

    /// Everything [`precedes`](Log::precedes) finds before `later`, found
    /// in one walk: for a caller that asks about many events before one.
    /// [`Ancestry::includes`] answers as [`precedes`](Log::precedes) does.
    pub fn ancestry(&self, later: EventId) -> Ancestry<'_> {
        let mut ids = BTreeSet::new();
        if self.height(later).is_some() {
            let mut stack = vec![later];
            while let Some(current) = stack.pop() {
                let Some(event) = self.held_event(current) else {
                    continue;
                };
                for &parent in event.parents() {
                    if ids.insert(parent) {
                        stack.push(parent);
                    }
                }
            }
        }
        Ancestry { log: self, ids }
    }

    /// Whether `earlier` is proven before `later` (units.md, "Partial
    /// replicas", "Proven order"): a chain of parents leads from `later`
    /// down to `earlier` through placed and witnessed events, as a `Path`
    /// that checks does. Never the event itself. It is
    /// [`precedes`](Log::precedes), which a full replica reads as causal
    /// order.
    pub fn proves_before(&self, earlier: EventId, later: EventId) -> bool {
        self.precedes(earlier, later)
    }

    /// The proven past of a placed or witnessed event: the placed and
    /// witnessed events a chain of parents reaches from it, without the
    /// event (units.md, "Partial replicas", "Proven order").
    pub fn proven_past(&self, id: EventId) -> BTreeSet<EventId> {
        let mut past = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            let Some(event) = self.held_event(current) else {
                continue;
            };
            for &parent in event.parents() {
                if self.held_event(parent).is_some() && past.insert(parent) {
                    stack.push(parent);
                }
            }
        }
        past
    }

    /// Whether `a` and `b` are concurrent: different, and neither before the
    /// other.
    pub fn concurrent(&self, a: EventId, b: EventId) -> bool {
        a != b && !self.precedes(a, b) && !self.precedes(b, a)
    }

    /// The past of a placed event: its placed ancestors, without the event.
    pub fn past(&self, id: EventId) -> BTreeSet<EventId> {
        let mut past = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            let Some(node) = self.nodes.get(&current) else {
                continue;
            };
            for &parent in node.event.parents() {
                if self.nodes.contains_key(&parent) && past.insert(parent) {
                    stack.push(parent);
                }
            }
        }
        past
    }

    /// Whether a set of placed events is a view: closed under parents
    /// (stubbed, witnessed and dropped parents count as held).
    pub fn is_closed(&self, view: &BTreeSet<EventId>) -> bool {
        view.iter().all(|id| {
            self.nodes.get(id).is_some_and(|node| {
                node.event.parents().iter().all(|parent| {
                    view.contains(parent)
                        || self.stub(*parent).is_some()
                        || self.witnessed(*parent).is_some()
                        || self.dropped.contains(parent)
                })
            })
        })
    }

    /// The heads of the log: placed events in no other event's past, by ID.
    pub fn heads(&self) -> Vec<EventId> {
        self.heads.iter().copied().collect()
    }

    /// The heads of a view, by ID. The view should be closed under parents;
    /// IDs it holds that are not placed are ignored.
    pub fn heads_in(&self, view: &BTreeSet<EventId>) -> Vec<EventId> {
        view.iter()
            .copied()
            .filter(|id| {
                self.nodes
                    .get(id)
                    .is_some_and(|node| !node.children.iter().any(|child| view.contains(child)))
            })
            .collect()
    }

    /// Every placed event, in canonical order.
    pub fn canonical(&self) -> Vec<EventId> {
        self.order.iter().map(|&(_, id)| id).collect()
    }

    /// The placed events of a view, in canonical order.
    pub fn canonical_in(&self, view: &BTreeSet<EventId>) -> Vec<EventId> {
        let mut out: Vec<(u64, EventId)> = view
            .iter()
            .filter_map(|&id| self.nodes.get(&id).map(|node| (node.height, id)))
            .collect();
        out.sort_unstable();
        out.into_iter().map(|(_, id)| id).collect()
    }

    /// Every placed event that is not a unit, in canonical order: space
    /// events, anchors, storage events and ignorable kinds.
    pub fn frame_events(&self) -> impl Iterator<Item = &Event> {
        self.frame.iter().map(|(_, id)| &self.nodes[id].event)
    }

    /// An author's placed events in this log, newest first: by `seq`, then
    /// ID, descending.
    pub fn chain_rev(&self, author: &DeviceId) -> impl Iterator<Item = EventId> + '_ {
        self.chains
            .get(author)
            .into_iter()
            .flat_map(|chain| chain.iter().rev())
            .map(|&(_, id)| id)
    }

    /// Every placed event, in canonical order.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.order.iter().map(|(_, id)| &self.nodes[id].event)
    }

    // -- Chains

    /// An author's placed events at one `seq`, by ID.
    pub fn chain_at(&self, author: &DeviceId, seq: u64) -> impl Iterator<Item = EventId> + '_ {
        self.chains
            .get(author)
            .into_iter()
            .flat_map(move |chain| {
                chain.range((seq, EventId([0; 32]))..=(seq, EventId([0xff; 32])))
            })
            .map(|&(_, id)| id)
    }

    /// An author's placed events in this log, by `seq`, then ID.
    pub fn chain(&self, author: &DeviceId) -> Vec<EventId> {
        self.chains
            .get(author)
            .map(|chain| chain.iter().map(|&(_, id)| id).collect())
            .unwrap_or_default()
    }

    /// An author's latest placed event: the greatest `seq`, then the
    /// greatest ID. A device continues its chain from it (events.md,
    /// "Restored devices sync before writing").
    pub fn latest(&self, author: &DeviceId) -> Option<EventId> {
        self.chains
            .get(author)
            .and_then(|chain| chain.last())
            .map(|&(_, id)| id)
    }

    /// The `seq` and `prev` of an author's next event in this log: one more
    /// than its latest event's `seq`, naming that event; or `seq` 1 and no
    /// `prev`. A device that may have lost events it signed fetches its own
    /// latest event before it asks (events.md, "Restored devices sync before
    /// writing").
    pub fn next_in_chain(&self, author: &DeviceId) -> (u64, Option<EventId>) {
        match self.latest(author) {
            Some(id) => (self.nodes[&id].event.seq().saturating_add(1), Some(id)),
            None => (1, None),
        }
    }

    // -- What a device cites

    /// The view a device may cite from (events.md, "Accepted in full, and
    /// what is cited"): every placed event that `accepted` holds accepted in
    /// full and judged by its kind's rules, and whose whole past is too. An
    /// event the replica holds as pending, `NoHybridKey`, `Sealed`,
    /// `BadSeal` or `ExtensionRequired`, and everything after one, is left
    /// out. A stubbed or dropped parent counts as accepted, and so, at a partial
    /// replica, does a witnessed one (units.md, "Partial replicas",
    /// "Citing"). The heads of this view ([`heads_in`](Log::heads_in)) are
    /// what the device cites as parents.
    pub fn citable(&self, accepted: impl Fn(&Event) -> bool) -> BTreeSet<EventId> {
        let mut view = BTreeSet::new();
        for &(_, id) in &self.order {
            let event = &self.nodes[&id].event;
            let past_citable = event.parents().iter().all(|parent| {
                view.contains(parent)
                    || (!self.nodes.contains_key(parent)
                        && (self.stub(*parent).is_some()
                            || self.witnesses.contains_key(parent)
                            || self.dropped.contains(parent)))
            });
            if past_citable && accepted(event) {
                view.insert(id);
            }
        }
        view
    }

    // -- Internals

    /// An event's height from the parents the log holds, and whether it is
    /// exact: every parent held, with an exact height. With no parent held
    /// it is 1, a witness's lower bound; a genesis is inserted at 0.
    fn measure(&self, event: &Event) -> (u64, bool) {
        let mut highest = None;
        let mut exact = true;
        for &parent in event.parents() {
            // A dropped parent is outside the kept checkpoint's world, where
            // a parent outside counts for nothing (roster.md, 3.15.5,
            // "Heights"), unless the replica kept its height: a parent of an
            // event it keeps of the checkpoint's past, which keeps its
            // height (events.md, "Placement and order").
            if self.height(parent).is_none() && self.dropped.contains(&parent) {
                if let Some(&height) = self.dropped_heights.get(&parent) {
                    highest = highest.max(Some(height));
                }
                continue;
            }
            match self.height(parent) {
                Some(height) => highest = highest.max(Some(height)),
                None => exact = false,
            }
            exact &= self.is_height_exact(parent);
        }
        let height = highest.map_or(1, |height: u64| height.saturating_add(1));
        (height, exact)
    }

    /// Records the event as a dependent of each of its parents.
    fn register(&mut self, event: &Event) {
        let id = event.id();
        for &parent in event.parents() {
            self.dependents.entry(parent).or_default().insert(id);
        }
    }

    /// Revises the heights resting on `from`, which arrived or changed,
    /// and on each event revised in turn.
    fn refresh(&mut self, from: EventId) {
        let mut queue = vec![from];
        while let Some(current) = queue.pop() {
            let mut dependents = self.dependents.get(&current).cloned().unwrap_or_default();
            if let Some(node) = self.nodes.get(&current) {
                dependents.extend(node.children.iter().copied());
            }
            for dependent in dependents {
                let Some((height, exact)) = self.held_event(dependent).map(|e| self.measure(e))
                else {
                    continue;
                };
                if self.set_height(dependent, height, exact) {
                    queue.push(dependent);
                }
            }
        }
    }

    /// Sets a placed or witnessed event's height, keeping canonical order.
    /// Returns whether anything changed.
    fn set_height(&mut self, id: EventId, height: u64, exact: bool) -> bool {
        if let Some(node) = self.nodes.get_mut(&id) {
            if (node.height, node.exact) == (height, exact) {
                return false;
            }
            if node.height != height {
                self.order.remove(&(node.height, id));
                self.order.insert((height, id));
                if self.frame.remove(&(node.height, id)) {
                    self.frame.insert((height, id));
                }
            }
            node.height = height;
            node.exact = exact;
            return true;
        }
        if let Some(witness) = self.witnesses.get_mut(&id) {
            if (witness.height, witness.exact) == (height, exact) {
                return false;
            }
            witness.height = height;
            witness.exact = exact;
            return true;
        }
        false
    }

    /// A placed event, or a witnessed one.
    fn held_event(&self, id: EventId) -> Option<&Event> {
        self.nodes
            .get(&id)
            .map(|node| &node.event)
            .or_else(|| self.witnesses.get(&id).map(|witness| &witness.event))
    }

    fn insert(&mut self, event: Event) {
        let (height, exact) = if event.is_genesis() {
            (0, true)
        } else {
            self.measure(&event)
        };
        let id = event.id();
        self.undrop(id);
        if self.witnessed {
            self.register(&event);
        }
        for parent in event.parents() {
            self.heads.remove(parent);
            match self.nodes.get_mut(parent) {
                Some(node) => node.children.push(id),
                None => {
                    self.on_unplaced.entry(*parent).or_default().insert(id);
                }
            }
        }
        // An event that arrives after events placed on its stub or its
        // witness takes them as children: it is no head, and their heights
        // are computed again from its own.
        let children: Vec<EventId> = self
            .on_unplaced
            .remove(&id)
            .map(|set| set.into_iter().collect())
            .unwrap_or_default();
        if children.is_empty() {
            self.heads.insert(id);
        }
        // Held in full, it no longer rests on a provisional stub.
        if self
            .stubs
            .get(&id)
            .is_some_and(|entry| entry.provisional.is_some())
        {
            self.stubs.remove(&id);
        }
        self.witnesses.remove(&id);
        self.order.insert((height, id));
        self.placed.push(id);
        if event.kind() != crate::kind::UNIT {
            self.frame.insert((height, id));
        }
        self.chains
            .entry(*event.author())
            .or_default()
            .insert((event.seq(), id));
        let (signature, verified) = initial_state(&event);
        self.nodes.insert(
            id,
            Node {
                signature,
                verified,
                event,
                height,
                exact,
                children,
            },
        );
        self.refresh(id);
    }

    /// Places every pending event that waited only for `arrived`, and what
    /// those release in turn.
    fn release(&mut self, arrived: EventId, placed: &mut Vec<EventId>) {
        let mut queue = vec![arrived];
        while let Some(parent) = queue.pop() {
            let Some(children) = self.waiters.remove(&parent) else {
                continue;
            };
            let mut still = BTreeSet::new();
            for child in children {
                // A space event waits on until a stub is confirmed.
                let Some(child_kind) = self.pending.get(&child).map(|w| w.event.kind()) else {
                    continue;
                };
                if !self.counts_for(parent, child_kind) {
                    still.insert(child);
                    continue;
                }
                let ready = self.pending.get_mut(&child).is_some_and(|waiting| {
                    waiting.missing.remove(&parent);
                    waiting.missing.is_empty()
                });
                if ready {
                    let waiting = self.pending.remove(&child).expect("pending");
                    self.insert(waiting.event);
                    placed.push(child);
                    queue.push(child);
                }
            }
            if !still.is_empty() {
                self.waiters.entry(parent).or_default().extend(still);
            }
        }
    }

    /// Whether `parent` counts for placing an event of `kind`: it is
    /// placed, witnessed or dropped, or stubbed and not disputed, and for a
    /// space event its stub is confirmed (units.md, "Confirming heights").
    fn counts_for(&self, parent: EventId, kind: u8) -> bool {
        if self.nodes.contains_key(&parent)
            || self.witnesses.contains_key(&parent)
            || self.dropped.contains(&parent)
        {
            return true;
        }
        self.stubs
            .get(&parent)
            .is_some_and(|entry| !entry.disputed && (kind != crate::kind::SPACE || entry.confirmed))
    }

    /// The placed events with one of `ids` in their past.
    fn resting_on(&self, ids: impl IntoIterator<Item = EventId>) -> BTreeSet<EventId> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<EventId> = ids.into_iter().collect();
        while let Some(current) = stack.pop() {
            let children: Vec<EventId> = match self.nodes.get(&current) {
                Some(node) => node.children.clone(),
                None => self
                    .on_unplaced
                    .get(&current)
                    .map(|set| set.iter().copied().collect())
                    .unwrap_or_default(),
            };
            for child in children {
                if self.nodes.contains_key(&child) && out.insert(child) {
                    stack.push(child);
                }
            }
        }
        out
    }

    /// Takes placed events out of the log and holds them pending on the
    /// parents they now lack. `gone` holds every placed event resting on
    /// any one of it.
    fn unplace(&mut self, gone: &BTreeSet<EventId>) {
        let mut events = Vec::new();
        for id in gone {
            let Some(node) = self.nodes.remove(id) else {
                continue;
            };
            self.order.remove(&(node.height, *id));
            self.frame.remove(&(node.height, *id));
            self.heads.remove(id);
            if let Some(chain) = self.chains.get_mut(node.event.author()) {
                chain.remove(&(node.event.seq(), *id));
                if chain.is_empty() {
                    self.chains.remove(node.event.author());
                }
            }
            for parent in node.event.parents() {
                if let Some(set) = self.on_unplaced.get_mut(parent) {
                    set.remove(id);
                    if set.is_empty() {
                        self.on_unplaced.remove(parent);
                    }
                }
                if let Some(set) = self.dependents.get_mut(parent) {
                    set.remove(id);
                }
            }
            events.push(node.event);
        }
        self.placed.retain(|id| !gone.contains(id));
        for event in &events {
            for parent in event.parents() {
                if let Some(node) = self.nodes.get_mut(parent) {
                    node.children.retain(|child| !gone.contains(child));
                    if node.children.is_empty() {
                        self.heads.insert(*parent);
                    }
                }
            }
        }
        for event in events {
            let id = event.id();
            let missing: BTreeSet<EventId> = event
                .parents()
                .iter()
                .copied()
                .filter(|&parent| !self.counts_for(parent, event.kind()))
                .collect();
            for &parent in &missing {
                self.waiters.entry(parent).or_default().insert(id);
            }
            self.pending.insert(id, Waiting { event, missing });
        }
        for id in gone {
            self.refresh(*id);
        }
        self.revision += 1;
    }
}

/// Whether a `Path` checks (units.md, "Sync messages"): its first event is
/// a parent of `from`, each next a parent of the one before, and the last
/// has `to` among its parents. An empty path never checks.
pub fn check_path(path: &[Event], from: &Event, to: EventId) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    if !from.parents().contains(&first.id()) {
        return false;
    }
    let mut previous = first;
    for event in rest {
        if !previous.parents().contains(&event.id()) {
            return false;
        }
        previous = event;
    }
    previous.parents().contains(&to)
}
