//! The merge (identity.md, "Checks at the event's place" and "The merge"),
//! through `frasil-resolve`'s resolution procedure (roster.md, "The
//! resolution procedure").
//!
//! - **Contested** events: the list events other than the first that pass
//!   "Checking a list event alone", steps 1 to 6 ([`Resolve::check`]) and 7
//!   ([`Resolve::forked`]), which a self-revocation survives.
//! - **Authority:** "Checks at the event's place", at the state of the first
//!   event and the valid list events of the event's past.
//! - **Attacks:** a valid list event `x` attacks a concurrent list event `e`
//!   when `x` revokes `e`'s author and `e` is not a self-revocation
//!   (`RevokedConcurrently`); when `x` revokes the list member `e` confirms
//!   (`TargetRevokedConcurrently`); or when both are adds that name one
//!   Ed25519, X-Wing or ML-DSA-65 key without naming the same device ID and
//!   kind, and `x` comes first in canonical order (`AlreadyListed`).
//! - **Mutual pairs, by rank:** when both revoke, their authors differ and
//!   each names the other's author, `x`'s attack on `e` does not count when
//!   `e`'s author ranks at least as high as `x`'s, each rank at its own
//!   event's place.
//! - **The pick:** the smallest `(rank of its author at its place, seniority
//!   of its author, height, event ID)`, a list member's seniority being the
//!   smallest `(height(add), SHA-256("frasil/device-list/seniority/v1" ||
//!   person ID || device ID), add's ID)` over its valid adds in the place.
//!
//! The **merged list** is the first event and the valid contested events;
//! its state is "The state of a list at a place" over all of them. A list
//! member that forked is not active in it from its fork point on.

use crate::IdentityClass;
use crate::body::{Action, ListBody, MAX_LIST_EVENTS};
use crate::entries::{Holder, RecoveryEntry};
use crate::keys::{Kind, MemberKeys, PublicKeys, Rank};
use crate::links::ListView;
use crate::list::DeviceList;
use crate::passkey::{PasskeyMember, UserHandle};
use crate::state::{Member, Rootedness};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, KeysCommitment};
use frasil_crypto::labels::DEVICE_LIST_SENIORITY;
use frasil_crypto::primitives::sha256;
use frasil_events::{Event, EventId, Evidence, EvidenceKind, ForkPoints};
use frasil_resolve::{How, Resolve, Verdict, View, resolve};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// The list members at a place, by device ID.
pub(crate) type State = BTreeMap<DeviceId, Member>;

/// A set of positions in an order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Bits(Vec<u64>);

impl Bits {
    pub(crate) fn new(n: usize) -> Self {
        Self(vec![0; n.div_ceil(64)])
    }

    pub(crate) fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    pub(crate) fn remove(&mut self, i: usize) {
        self.0[i / 64] &= !(1 << (i % 64));
    }

    pub(crate) fn contains(&self, i: usize) -> bool {
        self.0
            .get(i / 64)
            .is_some_and(|word| word >> (i % 64) & 1 == 1)
    }

    pub(crate) fn union_with(&mut self, other: &Bits) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }

    pub(crate) fn intersection(&self, other: &Bits) -> Bits {
        Bits(self.0.iter().zip(&other.0).map(|(a, b)| a & b).collect())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.iter().map(|word| word.count_ones() as usize).sum()
    }

    pub(crate) fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(w, &word)| {
            (0..64)
                .filter(move |b| word >> b & 1 == 1)
                .map(move |b| w * 64 + b)
        })
    }
}

/// A list member's seniority: `(epoch, height(add), SHA-256(label || person
/// ID || device ID), add's ID)`, the smallest over its valid adds. The
/// epoch is that of the world the add was judged in: 0 before any list
/// checkpoint, so that a list with none sorts by the rest alone.
pub(crate) type Seniority = (u64, u64, [u8; 32], EventId);

/// The pick's key: `(rank, seniority of the author, height, event ID)`.
type PickKey = (Rank, Option<Seniority>, u64, EventId);

/// What a merge reads its events from: a list that holds its whole log, or
/// one that holds a list checkpoint and what follows it
/// ([`crate::kept::KeptList`]).
pub(crate) trait Source {
    /// The person ID.
    fn person_id(&self) -> [u8; 32];
    /// A placed event: one the holder judges.
    fn event(&self, id: EventId) -> Option<&Event>;
    /// The body of a placed event, or of an event kept alone, that passed
    /// "Checking a list event alone", steps 2 to 6.
    fn body(&self, id: EventId) -> Option<&ListBody>;
    /// The class of a placed event that failed steps 2 to 7.
    fn check_alone(&self, id: EventId) -> Option<IdentityClass>;
    /// Every placed event, parents before children.
    fn canonical(&self) -> Vec<EventId>;
}

impl Source for DeviceList {
    fn person_id(&self) -> [u8; 32] {
        DeviceList::person_id(self)
    }

    fn event(&self, id: EventId) -> Option<&Event> {
        self.log().event(id)
    }

    fn body(&self, id: EventId) -> Option<&ListBody> {
        DeviceList::body(self, id)
    }

    fn check_alone(&self, id: EventId) -> Option<IdentityClass> {
        DeviceList::check_alone(self, id)
    }

    fn canonical(&self) -> Vec<EventId> {
        self.log().canonical()
    }
}

/// The log a merge resolves: a root (the list's first event, or a list
/// checkpoint) and events, each linked only to its parents among them, its
/// height counted from the root at 0 (identity.md, "List checkpoints",
/// "The world after it"). Over a whole list it is the list's own log.
#[derive(Debug, Clone)]
pub(crate) struct Frame {
    /// The root, then the events in canonical order within the frame.
    pub(crate) order: Vec<EventId>,
    pub(crate) position: BTreeMap<EventId, usize>,
    pub(crate) heights: Vec<u64>,
    /// `past[i]`: the positions of the events in `order[i]`'s past.
    pub(crate) past: Vec<Bits>,
}

impl Frame {
    /// The frame of `root` and the placed events `member` accepts, read in
    /// `topological` order (parents first).
    pub(crate) fn new(
        src: &dyn Source,
        topological: &[EventId],
        root: EventId,
        member: impl Fn(EventId) -> bool,
    ) -> Self {
        let mut height: BTreeMap<EventId, u64> = BTreeMap::from([(root, 0)]);
        for &id in topological {
            if id == root || !member(id) {
                continue;
            }
            let Some(event) = src.event(id) else {
                continue;
            };
            let h = event
                .parents()
                .iter()
                .filter_map(|p| height.get(p))
                .max()
                .map_or(1, |h| h + 1);
            height.insert(id, h);
        }
        let mut order: Vec<(u64, EventId)> = height.iter().map(|(&id, &h)| (h, id)).collect();
        order.sort_unstable();
        let order: Vec<EventId> = order.into_iter().map(|(_, id)| id).collect();
        let n = order.len();
        let position: BTreeMap<EventId, usize> = order
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect_map();
        let mut past: Vec<Bits> = Vec::with_capacity(n);
        for (i, &id) in order.iter().enumerate() {
            let mut bits = Bits::new(n);
            if i > 0 {
                for parent in src.event(id).expect("placed").parents() {
                    if let Some(&p) = position.get(parent) {
                        bits.insert(p);
                        let parent_past = past[p].clone();
                        bits.union_with(&parent_past);
                    }
                }
            }
            past.push(bits);
        }
        let heights = order.iter().map(|id| height[id]).collect();
        Self {
            order,
            position,
            heights,
            past,
        }
    }

    /// The evidence of every fork among the frame's events that `counted`
    /// accepts: every duplicate, then every skip whose `prev` is in the
    /// frame and counted (events.md, "Chains and evidence of a fork"). A
    /// `prev` outside the frame is not checked.
    pub(crate) fn evidence(
        &self,
        src: &dyn Source,
        counted: impl Fn(EventId) -> bool,
    ) -> Vec<Evidence> {
        let ids: Vec<EventId> = self
            .order
            .iter()
            .copied()
            .filter(|&id| counted(id))
            .collect();
        let mut slots: BTreeMap<(DeviceId, u64), Vec<EventId>> = BTreeMap::new();
        for &id in &ids {
            let event = src.event(id).expect("placed");
            slots
                .entry((*event.author(), event.seq()))
                .or_default()
                .push(id);
        }
        let mut out = Vec::new();
        for ((author, seq), mut slot) in slots {
            slot.sort_unstable();
            for (i, &first) in slot.iter().enumerate() {
                for &second in &slot[i + 1..] {
                    out.push(Evidence {
                        kind: EvidenceKind::Duplicate,
                        author,
                        seq,
                        first,
                        second,
                        fork_seq: seq,
                    });
                }
            }
        }
        for &id in &ids {
            let event = src.event(id).expect("placed");
            let Some(prev) = event.prev() else {
                continue;
            };
            if !self.position.contains_key(&prev) || !counted(prev) {
                continue;
            }
            let previous = src.event(prev).expect("placed");
            let own = previous.author() == event.author();
            if own && previous.seq().checked_add(1) == Some(event.seq()) {
                continue;
            }
            let fork_seq = if own {
                event.seq().min(previous.seq().saturating_add(1))
            } else {
                event.seq()
            };
            out.push(Evidence {
                kind: EvidenceKind::Skip,
                author: *event.author(),
                seq: event.seq(),
                first: id,
                second: prev,
                fork_seq,
            });
        }
        out
    }
}

/// A list checkpoint standing as a frame's root: its record's members are
/// list members from the start (identity.md, "List checkpoints", "The world
/// after it").
#[derive(Debug, Clone)]
pub(crate) struct Base {
    /// The checkpoint's epoch: the epoch of the adds judged after it.
    pub(crate) epoch: u64,
    /// The record's members, each with the `add` its entry names as its
    /// only add, its root, agent and confirmation.
    pub(crate) members: State,
    /// Each record member's seniority, as the record gives it.
    pub(crate) seniority: BTreeMap<DeviceId, Seniority>,
    /// The record's fork points and tips: an author's events after the
    /// checkpoint at or below its tip, or at or after its fork point, are
    /// forked there.
    pub(crate) forks: BTreeMap<DeviceId, u64>,
    pub(crate) tips: BTreeMap<DeviceId, u64>,
}

/// Verdicts decided before the merge (a list checkpoint's own, and
/// `BadCuts` and `MixedCut`), by event.
pub(crate) type Presets = BTreeMap<EventId, Result<(), IdentityClass>>;

/// The keys commitments the adds of a frame name: the adds among its events
/// and, in a world, the adds its base's record names.
pub(crate) type Named = BTreeSet<KeysCommitment>;

/// The keys commitments the adds of a frame name (identity.md, "List
/// checkpoints", "Keys in the world"): each `add` among the frame's events
/// that passed steps 2 to 6, valid or not, and in a world the `add` each
/// record member's entry names.
pub(crate) fn frame_named(src: &dyn Source, frame: &Frame, base: Option<&Base>) -> Named {
    let record_adds = base
        .into_iter()
        .flat_map(|b| b.members.values().map(|m| m.adds[0]));
    record_adds
        .chain(frame.order.iter().copied())
        .filter_map(|id| src.body(id))
        .filter(|b| b.action == Action::Add)
        .filter_map(ListBody::keys)
        .map(|keys| *keys.hybrid().commitment())
        .collect()
}

/// Whether a class of "Checking a list event alone" is step 7's, the
/// signature's.
pub(crate) fn is_signature_class(class: IdentityClass) -> bool {
    matches!(
        class,
        IdentityClass::Shared(ErrorClass::NoHybridKey | ErrorClass::BadSignature)
    )
}

/// "Checking a list event alone", steps 2 to 7, for an event of a frame.
/// In a list checkpoint's world (`named` given) step 7 takes keys only from
/// the adds `named` lists, the record's and the world's own: an event whose
/// author none of them names is `UntrustedSigner`, final (identity.md,
/// "List checkpoints", "Keys in the world"). Keys are found by their hash,
/// so an event whose keys commitment one of them names verifies as it does
/// under any source.
pub(crate) fn alone_in(
    src: &dyn Source,
    named: Option<&Named>,
    id: EventId,
) -> Option<IdentityClass> {
    let class = src.check_alone(id);
    let Some(named) = named else {
        return class;
    };
    if class.is_some_and(|c| !is_signature_class(c)) {
        return class;
    }
    match src.event(id) {
        Some(event) if !named.contains(event.kc()) => Some(IdentityClass::UntrustedSigner),
        _ => class,
    }
}

/// The list's rules, read by the resolution procedure.
struct Judge<'a> {
    src: &'a dyn Source,
    person_id: [u8; 32],
    frame: &'a Frame,
    forks: ForkPoints,
    base: Option<&'a Base>,
    /// The epoch of the adds the frame judges.
    epoch: u64,
    /// The positions of the events valid before the merge.
    preset_valid: Bits,
    /// In a world, the keys its adds name (see [`alone_in`]).
    named: Option<&'a Named>,
    /// The state at each place, by the place's positions.
    states: RefCell<BTreeMap<Bits, Rc<State>>>,
}

impl<'a> Judge<'a> {
    fn author(&self, id: EventId) -> &DeviceId {
        self.src.event(id).expect("placed").author()
    }

    fn body(&self, id: EventId) -> Option<&ListBody> {
        self.src.body(id)
    }

    fn order_key(&self, id: EventId) -> (u64, EventId) {
        (self.frame.heights[self.frame.position[&id]], id)
    }

    /// The place of a contested event under the procedure's statuses: the
    /// root, the events valid before the merge and the valid contested
    /// events of its past.
    fn place(&self, event: EventId, view: &View<'_, Self>) -> Bits {
        let i = self.frame.position[&event];
        let mut bits = self.frame.past[i].intersection(&self.preset_valid);
        bits.insert(0);
        for id in view.place(event) {
            bits.insert(self.frame.position[&id]);
        }
        bits
    }

    /// The state of the list at a place (identity.md, "The state of a list
    /// at a place"), starting from the base's members in a world.
    fn state(&self, place: &Bits) -> Rc<State> {
        if let Some(state) = self.states.borrow().get(place) {
            return Rc::clone(state);
        }
        let mut members = self.base.map(|b| b.members.clone()).unwrap_or_default();
        for i in place.ones() {
            let id = self.frame.order[i];
            if let Some(body) = self.body(id).filter(|b| b.action == Action::Add) {
                members
                    .entry(body.device)
                    .and_modify(|m| m.adds.push(id))
                    .or_insert_with(|| Member::new(body.kind, body.device, id));
            }
        }
        for i in place.ones() {
            let id = self.frame.order[i];
            let Some(body) = self.body(id) else {
                continue;
            };
            match body.action {
                Action::Add => {
                    let (root, agent) = if i == 0 {
                        (Rootedness::None, None)
                    } else {
                        self.rooting(id, &place.intersection(&self.frame.past[i]))
                    };
                    let root = if body.kind == Kind::PasskeyMember {
                        root.max(Rootedness::Passkey)
                    } else {
                        root
                    };
                    let member = members.get_mut(&body.device).expect("named");
                    if root == Rootedness::Agent {
                        member.agent_adds.push(id);
                    }
                    member.root = member.root.max(root);
                    if member.agent.is_none() {
                        member.agent = agent;
                    }
                }
                // An event a trial holds valid may name no list member of
                // the place: it applies nothing.
                Action::Revoke => {
                    if let Some(member) = members.get_mut(&body.device) {
                        member.revoked_by.push(id);
                    }
                }
                Action::Confirm => {
                    if let Some(member) = members.get_mut(&body.device) {
                        member.confirmed_by.push(id);
                    }
                }
                // A checkpoint is judged on its own past, and an ack changes
                // nothing.
                Action::Checkpoint | Action::Ack => {}
            }
        }
        let state = Rc::new(members);
        self.states
            .borrow_mut()
            .insert(place.clone(), Rc::clone(&state));
        state
    }

    /// How an `add` roots the list member it adds, from its author's state
    /// at the add's own place, and the agent it is rooted in. An author
    /// missing from that place, which only a trial of the agreement step can
    /// give, roots it in an agent: rootedness fails closed.
    fn rooting(&self, add: EventId, place: &Bits) -> (Rootedness, Option<DeviceId>) {
        let state = self.state(place);
        let Some(signer) = state.get(self.author(add)) else {
            return (Rootedness::Agent, None);
        };
        if signer.kind == Kind::RecoveryAgent {
            (Rootedness::Agent, Some(signer.device))
        } else if signer.rooted() == Rootedness::Agent {
            (Rootedness::Agent, signer.agent)
        } else {
            (signer.rooted(), None)
        }
    }

    /// Whether an `add` names a list member's device ID, or one of its
    /// Ed25519, X-Wing or ML-DSA-65 keys.
    fn shares_a_key(&self, member: &Member, add: &ListBody) -> bool {
        let Some(named) = self.body(member.adds[0]).and_then(|b| b.added.as_ref()) else {
            return false;
        };
        let Some(added) = add.added.as_ref() else {
            return false;
        };
        member.device == add.device
            || named.identity == added.identity
            || named.mldsa == added.mldsa
            || (added.xwing.is_some() && named.xwing == added.xwing)
    }

    /// "Checks at the event's place", in order, at the state `place` gives.
    fn checks(&self, event: EventId, place: &Bits) -> Result<(), IdentityClass> {
        let state = self.state(place);
        let author = self.author(event);
        let body = self.body(event).expect("contested events have bodies");
        let full = || {
            // The place, the root included, and the event itself: in a
            // world, the checkpoint and the valid events after it.
            if place.len() + 1 > MAX_LIST_EVENTS {
                Err(IdentityClass::Shared(ErrorClass::Full))
            } else {
                Ok(())
            }
        };
        // 1. The author is an active list member.
        let signer = match state.get(author) {
            Some(signer) if signer.active() => signer,
            _ => return Err(IdentityClass::UntrustedSigner),
        };
        // 2. An agent signs only an add of a device, or a revoke of itself.
        if signer.kind == Kind::RecoveryAgent
            && !((body.action == Action::Add && body.kind == Kind::Device)
                || (body.action == Action::Revoke && body.device == *author))
        {
            return Err(IdentityClass::AgentLimited);
        }
        match body.action {
            // An ack is valid when its author is active at its place.
            Action::Ack => return full(),
            // A checkpoint is judged on its own past before the merge.
            Action::Checkpoint => return Err(IdentityClass::UntrustedSigner),
            _ => {}
        }
        if body.action == Action::Add {
            // 3. An agent is added only by a device or a recovery key that
            // is not rooted; no list member has any key the add names.
            if body.kind == Kind::RecoveryAgent
                && !(matches!(signer.kind, Kind::Device | Kind::RecoveryKey)
                    && signer.rooted() == Rootedness::None)
            {
                return Err(IdentityClass::UntrustedSigner);
            }
            if state.values().any(|m| self.shares_a_key(m, body)) {
                return Err(IdentityClass::AlreadyListed);
            }
            return full();
        }
        // 4. A confirm's author is a device that is not rooted.
        if body.action == Action::Confirm
            && (signer.kind != Kind::Device || signer.rooted() != Rootedness::None)
        {
            return Err(IdentityClass::UntrustedSigner);
        }
        // 5. The named list member is active, of that kind.
        let named = match state.get(&body.device) {
            Some(named) if named.active() && named.kind == body.kind => named,
            _ => return Err(IdentityClass::NotListed),
        };
        if body.action == Action::Revoke {
            // 6. A rooted author revokes a recovery key only when it revokes
            // itself; an author rooted in an agent, other than an agent,
            // revokes only list members rooted in the same agent; and some
            // other active list member is not an agent.
            if named.kind == Kind::RecoveryKey
                && signer.rooted() != Rootedness::None
                && body.device != *author
            {
                return Err(IdentityClass::RecoveryKeyProtected);
            }
            if signer.rooted() == Rootedness::Agent
                && signer.kind != Kind::RecoveryAgent
                && !(named.rooted() == Rootedness::Agent && named.agent == signer.agent)
            {
                return Err(IdentityClass::AgentLimited);
            }
            let others = state.iter().any(|(device, other)| {
                *device != body.device && other.active() && other.kind != Kind::RecoveryAgent
            });
            if !others {
                return Err(IdentityClass::LastMember);
            }
            return full();
        }
        // 7. A confirm names a rooted device or recovery key.
        if !matches!(named.kind, Kind::Device | Kind::RecoveryKey)
            || named.rooted() == Rootedness::None
        {
            return Err(IdentityClass::NotPending);
        }
        // 8. At most 4,096 valid list events in its place.
        full()
    }

    fn self_revocation(&self, event: EventId) -> bool {
        self.body(event)
            .is_some_and(|b| b.action == Action::Revoke && b.device == *self.author(event))
    }

    /// Whether two revokes by different authors each name the other's
    /// author.
    fn mutual_pair(&self, x: EventId, e: EventId) -> bool {
        let (Some(bx), Some(be)) = (self.body(x), self.body(e)) else {
            return false;
        };
        let (ax, ae) = (self.author(x), self.author(e));
        bx.action == Action::Revoke
            && be.action == Action::Revoke
            && ax != ae
            && bx.device == *ae
            && be.device == *ax
    }

    /// The rank of an event's author at its place. An author missing there,
    /// which only a trial can give, ranks lowest.
    fn rank_at(&self, event: EventId, view: &View<'_, Self>) -> Rank {
        self.state(&self.place(event, view))
            .get(self.author(event))
            .map_or(Rank::Agent, Member::rank)
    }

    /// A list member's seniority: the smallest over its adds of `(epoch,
    /// height, hash, add)`, an add outside the frame (a record member's)
    /// taking the seniority the record gives.
    fn seniority(&self, member: &Member) -> Option<Seniority> {
        let hash = sha256(&[DEVICE_LIST_SENIORITY, &self.person_id, &member.device.0]);
        member
            .adds
            .iter()
            .filter_map(|&add| match self.frame.position.get(&add) {
                Some(_) => Some((self.epoch, self.order_key(add).0, hash, add)),
                None => self
                    .base
                    .and_then(|b| b.seniority.get(&member.device))
                    .copied(),
            })
            .min()
    }
}

impl Resolve for Judge<'_> {
    type Id = EventId;
    type Class = IdentityClass;
    type PickKey = PickKey;

    fn height(&self, event: EventId) -> u64 {
        self.order_key(event).0
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        match (
            self.frame.position.get(&earlier),
            self.frame.position.get(&later),
        ) {
            (Some(&a), Some(&b)) => self.frame.past[b].contains(a),
            _ => false,
        }
    }

    /// Steps 1 to 7 of "Checking a list event alone"; in a world, under
    /// the world's keys only.
    fn check(&self, event: EventId) -> Result<(), IdentityClass> {
        alone_in(self.src, self.named, event).map_or(Ok(()), Err)
    }

    /// Step 7: the author's fork point is at or below `seq`.
    fn forked(&self, event: EventId) -> Option<IdentityClass> {
        let event = self.src.event(event)?;
        self.forks
            .is_void(event)
            .then_some(IdentityClass::Shared(ErrorClass::Forked))
    }

    /// A `revoke` that names its own author: never attacked, and it survives
    /// its author's fork.
    fn self_lowering(&self, event: EventId) -> bool {
        self.self_revocation(event)
    }

    fn authority(&self, event: EventId, view: &View<'_, Self>) -> Result<(), IdentityClass> {
        self.checks(event, &self.place(event, view))
    }

    fn attack(&self, x: EventId, e: EventId) -> Option<IdentityClass> {
        let (bx, be) = (self.body(x)?, self.body(e)?);
        if bx.action == Action::Revoke {
            if bx.device == *self.author(e) && !self.self_revocation(e) {
                return Some(IdentityClass::RevokedConcurrently);
            }
            if be.action == Action::Confirm && be.device == bx.device {
                return Some(IdentityClass::TargetRevokedConcurrently);
            }
        }
        if let (Some(ax), Some(ae)) = (&bx.added, &be.added) {
            let same = bx.kind == be.kind && bx.device == be.device;
            let overlap = ax.identity == ae.identity
                || ax.mldsa == ae.mldsa
                || (ax.xwing.is_some() && ax.xwing == ae.xwing);
            if !same && overlap && self.order_key(x) < self.order_key(e) {
                return Some(IdentityClass::AlreadyListed);
            }
        }
        None
    }

    /// A mutual pair's attack is dropped when `e`'s author ranks at least as
    /// high as `x`'s; it is not known until both pasts are decided.
    fn attack_counts(&self, x: EventId, e: EventId, view: &View<'_, Self>) -> Option<bool> {
        if !self.mutual_pair(x, e) {
            return Some(true);
        }
        if !(view.past_decided(x) && view.past_decided(e)) {
            return None;
        }
        Some(self.rank_at(e, view) > self.rank_at(x, view))
    }

    fn pick_key(&self, event: EventId, view: &View<'_, Self>) -> PickKey {
        let state = self.state(&self.place(event, view));
        let author = state.get(self.author(event));
        (
            author.map_or(Rank::Agent, Member::rank),
            author.and_then(|member| self.seniority(member)),
            self.height(event),
            event,
        )
    }
}

/// A person's merged list: every placed event's verdict, and the state of
/// the list over the first event and the valid list events. With a list
/// checkpoint in effect, the state is that of the checkpoint's world
/// (identity.md, "List checkpoints").
#[derive(Debug, Clone)]
pub struct MergedList {
    person_id: [u8; 32],
    /// Every placed event, in canonical order, with its verdict. The first
    /// event is valid by [`How::Rules`].
    verdicts: Vec<(EventId, Verdict<EventId, IdentityClass>)>,
    members: State,
    keys: BTreeMap<DeviceId, PublicKeys>,
    forks: ForkPoints,
    /// For each list member that forked, the canonically later event of the
    /// evidence that fixes its fork point.
    fork_ends: BTreeMap<DeviceId, EventId>,
    /// What the list checkpoints held give: the chain in effect, whom each
    /// valid one waits for, and each active member's seniority.
    pub(crate) checkpoints: crate::checkpoint::Checkpoints,
    /// Each list member's seniority at the merged state.
    seniority: BTreeMap<DeviceId, Seniority>,
}

/// A valid `revoke` of a frame, read at its place (identity.md, "List
/// checkpoints", "Effect"): what heard devices and contested checkpoints
/// read.
#[derive(Debug, Clone)]
pub(crate) struct Revocation {
    /// The `revoke`.
    pub(crate) id: EventId,
    /// Its author.
    pub(crate) by: DeviceId,
    /// The list member it names.
    pub(crate) target: DeviceId,
    /// Whether the target is, at its place, a device that is not rooted,
    /// or confirmed: one a checkpoint waits for.
    pub(crate) waited: bool,
    /// Whether its author outranks the target at its place.
    pub(crate) outranks: bool,
    /// The target's seniority at its place.
    pub(crate) seniority: Option<Seniority>,
}

/// What a merge of one frame gives, before a [`MergedList`] gathers frames.
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub(crate) merged: MergedList,
    /// Each list member's seniority at the merged state.
    pub(crate) seniority: BTreeMap<DeviceId, Seniority>,
    /// The frame's events, the root first.
    pub(crate) view: Vec<EventId>,
    /// The keys commitments the frame's adds name ([`frame_named`]).
    pub(crate) named: Named,
    /// The frame's valid `revoke`s, in canonical order.
    pub(crate) revocations: Vec<Revocation>,
}

/// Merges one frame: resolves its events, the root valid, with `presets`
/// decided before the merge, and computes the state over the valid ones.
/// With a `base`, the frame is a list checkpoint's world, whose events take
/// keys only from `named` ([`alone_in`]); `evidence` was gathered under the
/// same rule.
pub(crate) fn merge_frame(
    src: &dyn Source,
    frame: &Frame,
    base: Option<&Base>,
    presets: &Presets,
    evidence: Vec<Evidence>,
    named: Named,
) -> Outcome {
    let world_keys = base.is_some().then_some(&named);
    let mut points: BTreeMap<DeviceId, u64> = ForkPoints::from_evidence(&evidence)
        .iter()
        .map(|(author, point)| (*author, point))
        .collect_map();
    let mut lower = |author: DeviceId, seq: u64| {
        points
            .entry(author)
            .and_modify(|point| *point = (*point).min(seq))
            .or_insert(seq);
    };
    if let Some(base) = base {
        for (&author, &seq) in &base.forks {
            lower(author, seq);
        }
        for &id in &frame.order[1..] {
            let event = src.event(id).expect("placed");
            if base
                .tips
                .get(event.author())
                .is_some_and(|&tip| event.seq() <= tip)
            {
                lower(*event.author(), event.seq());
            }
        }
    }
    let forks = ForkPoints::from_points(points);
    // An event that fails alone keeps that verdict, before any preset.
    let presets: Presets = presets
        .iter()
        .filter(|(id, _)| {
            frame.position.contains_key(id) && alone_in(src, world_keys, **id).is_none()
        })
        .map(|(id, verdict)| (*id, *verdict))
        .collect_map();
    let mut preset_valid = Bits::new(frame.order.len());
    for (id, verdict) in &presets {
        if verdict.is_ok() {
            preset_valid.insert(frame.position[id]);
        }
    }
    let judge = Judge {
        src,
        person_id: src.person_id(),
        frame,
        forks: forks.clone(),
        base,
        epoch: base.map_or(0, |b| b.epoch),
        preset_valid: preset_valid.clone(),
        named: world_keys,
        states: RefCell::new(BTreeMap::new()),
    };
    let contested = frame.order[1..]
        .iter()
        .copied()
        .filter(|id| !presets.contains_key(id));
    let resolution = resolve(&judge, contested);
    let mut valid = preset_valid;
    valid.insert(0);
    for id in resolution.valid() {
        valid.insert(frame.position[&id]);
    }
    let members = (*judge.state(&valid)).clone();
    let keys = members
        .iter()
        .filter_map(|(device, member)| {
            let keys = judge.body(member.adds[0])?.keys()?;
            Some((*device, keys))
        })
        .collect_map();
    let seniority: BTreeMap<DeviceId, Seniority> = members
        .values()
        .filter_map(|m| Some((m.device, judge.seniority(m)?)))
        .collect_map();
    // Each valid revoke read at its place: the target's standing and
    // seniority there, and whether its author outranks it (identity.md,
    // "List checkpoints", "Effect").
    let mut revocations = Vec::new();
    for i in valid.ones().filter(|&i| i != 0) {
        let id = frame.order[i];
        let Some(body) = judge.body(id).filter(|b| b.action == Action::Revoke) else {
            continue;
        };
        let mut place = frame.past[i].intersection(&valid);
        place.insert(0);
        let state = judge.state(&place);
        let Some(target) = state.get(&body.device) else {
            continue;
        };
        let by = *judge.author(id);
        let rank_key = |m: &Member| (m.rank(), judge.seniority(m));
        let target_key = rank_key(target);
        let outranks = state.get(&by).is_some_and(|a| {
            let key = rank_key(a);
            key.1.is_some() && target_key.1.is_some() && key < target_key
        });
        revocations.push(Revocation {
            id,
            by,
            target: body.device,
            waited: target.kind == Kind::Device && target.rooted() == Rootedness::None,
            outranks,
            seniority: target_key.1,
        });
    }
    let mut verdicts = vec![(frame.order[0], Verdict::Valid(How::Rules))];
    for &id in &frame.order[1..] {
        let verdict = match presets.get(&id) {
            Some(Ok(())) => Verdict::Valid(How::Rules),
            Some(Err(class)) => Verdict::Void {
                class: *class,
                by: None,
            },
            None => *resolution.verdict(id).expect("resolved"),
        };
        verdicts.push((id, verdict));
    }
    // The end of a fork: of the evidence that fixes the fork point, the
    // one whose canonically later event comes first.
    let mut fork_ends = BTreeMap::new();
    for (author, point) in forks.iter() {
        let end = evidence
            .iter()
            .filter(|item| item.author == *author && item.fork_seq == point)
            .map(|item| {
                judge
                    .order_key(item.first)
                    .max(judge.order_key(item.second))
            })
            .min();
        if let Some((_, end)) = end {
            fork_ends.insert(*author, end);
        }
    }
    Outcome {
        merged: MergedList {
            person_id: src.person_id(),
            verdicts,
            members,
            keys,
            forks,
            fork_ends,
            checkpoints: crate::checkpoint::Checkpoints::default(),
            seniority: seniority.clone(),
        },
        seniority,
        view: frame.order.clone(),
        named,
        revocations,
    }
}

impl DeviceList {
    /// Merges the list (identity.md, "The merge"): resolves its placed
    /// events and computes the state of the merged list. With list
    /// checkpoints among them, it judges them and the events around them
    /// first (identity.md, "List checkpoints"): with one in effect, events
    /// in its past keep the verdicts of that past alone, events after it
    /// are judged in its world, and every other event is `Late`.
    pub fn merge(&self) -> MergedList {
        if !crate::checkpoint::declares_checkpoints(self) {
            return self.merge_plain();
        }
        crate::checkpoint::merge_with_checkpoints(self, None)
    }

    /// The merge through the procedure for list checkpoints, whether or
    /// not the list holds one: for tests, which check that a list with none
    /// merges alike either way.
    #[doc(hidden)]
    pub fn merge_through_checkpoints(&self) -> MergedList {
        crate::checkpoint::merge_with_checkpoints(self, None)
    }

    /// The merge of a list that holds no list checkpoint and whose events
    /// follow none: the resolution of every placed event.
    fn merge_plain(&self) -> MergedList {
        let order = self.log().canonical();
        let frame = Frame::new(self, &order, self.first(), |_| true);
        // No frame here is a world, so no event's keys are restricted.
        merge_frame(
            self,
            &frame,
            None,
            &Presets::new(),
            self.evidence(),
            Named::new(),
        )
        .merged
    }
}

impl DeviceList {
    /// `add_passkey_member` (identity.md, "Adding list members"), in order:
    /// two evaluations of the PRF derive the same keys; no list member of
    /// the merged list has any of them; the passkey member signs its
    /// possession proof, with `signer` as adder; and `signer`, an active
    /// list member, signs the
    /// `add` on its own chain. Returns the signed `add`, not yet inserted,
    /// and the passkey member. Both outputs and every derived secret are
    /// zeroised on failure.
    ///
    /// # Errors
    ///
    /// `passkey_keys`'s classes and `UnstablePrf`; `AlreadyListed`; then
    /// `UntrustedSigner` for a signer that is not an active list member.
    pub fn add_passkey_member(
        &self,
        first: &[u8],
        second: &[u8],
        signer: &MemberKeys,
    ) -> Result<(Vec<u8>, PasskeyMember), IdentityClass> {
        let person = self.person_id();
        let member = PasskeyMember::enrol(&person, first, second)?;
        let public = member.member().public(Kind::PasskeyMember);
        let merged = self.merge();
        let device = public.device_id();
        let listed = merged.keys.iter().any(|(listed, keys)| {
            *listed == device
                || keys.identity == public.identity
                || keys.mldsa == public.mldsa
                || (keys.xwing.is_some() && keys.xwing == public.xwing)
        });
        if listed {
            return Err(IdentityClass::AlreadyListed);
        }
        if merged.active(signer.device_id()).is_none() {
            return Err(IdentityClass::UntrustedSigner);
        }
        let proof =
            member
                .member()
                .prove_possession(&person, signer.device_id(), Kind::PasskeyMember);
        let body = ListBody::add(Kind::PasskeyMember, &public, proof);
        Ok((self.sign(&body, signer.signer()), member))
    }
}

impl MergedList {
    /// A merged list gathered from the verdicts of several frames and the
    /// state of the last one.
    /// Holds pending every placed event `held` accepts: a holder that holds
    /// a rival of its kept checkpoint judges none of them (identity.md,
    /// "List checkpoints", "A rival").
    pub(crate) fn hold_pending(&mut self, held: impl Fn(EventId) -> bool) {
        for (id, verdict) in &mut self.verdicts {
            if held(*id) {
                *verdict = Verdict::Void {
                    class: IdentityClass::Shared(ErrorClass::Pending),
                    by: None,
                };
            }
        }
    }

    pub(crate) fn gathered(
        last: MergedList,
        verdicts: Vec<(EventId, Verdict<EventId, IdentityClass>)>,
        checkpoints: crate::checkpoint::Checkpoints,
    ) -> Self {
        Self {
            verdicts,
            checkpoints,
            ..last
        }
    }

    /// Whether list member `a` outranks list member `b` at the merged
    /// state (identity.md, "List checkpoints", "Effect"): a higher rank, or
    /// the same rank and the smaller seniority. `false` when either is no
    /// list member there.
    pub fn outranks(&self, a: &DeviceId, b: &DeviceId) -> bool {
        let key = |d: &DeviceId| {
            let member = self.members.get(d)?;
            Some((member.rank(), *self.seniority.get(d)?))
        };
        matches!((key(a), key(b)), (Some(x), Some(y)) if x < y)
    }

    /// The person ID.
    pub fn person_id(&self) -> &[u8; 32] {
        &self.person_id
    }

    /// Every placed event, in canonical order, with its verdict.
    pub fn verdicts(&self) -> impl Iterator<Item = (EventId, &Verdict<EventId, IdentityClass>)> {
        self.verdicts.iter().map(|(id, verdict)| (*id, verdict))
    }

    /// A placed event's verdict, or `None` for an event that is not placed.
    pub fn verdict(&self, event: EventId) -> Option<&Verdict<EventId, IdentityClass>> {
        self.verdicts
            .iter()
            .find(|(id, _)| *id == event)
            .map(|(_, verdict)| verdict)
    }

    /// Whether a placed event is valid.
    pub fn is_valid(&self, event: EventId) -> bool {
        self.verdict(event).is_some_and(Verdict::is_valid)
    }

    /// The valid events, the first included, in canonical order.
    pub fn valid(&self) -> impl Iterator<Item = EventId> + '_ {
        self.verdicts()
            .filter(|(_, verdict)| verdict.is_valid())
            .map(|(id, _)| id)
    }

    /// Every list member a valid `add` names, revoked or not, by device ID.
    pub fn members(&self) -> &BTreeMap<DeviceId, Member> {
        &self.members
    }

    /// The list member of a device ID, revoked or not.
    pub fn member(&self, device: &DeviceId) -> Option<&Member> {
        self.members.get(device)
    }

    /// The keys of a list member: those its device ID commits to.
    pub fn keys(&self, device: &DeviceId) -> Option<&PublicKeys> {
        self.keys.get(device)
    }

    /// A list member's fork point, if it forked.
    pub fn fork_point(&self, device: &DeviceId) -> Option<u64> {
        self.forks.fork_point(device)
    }

    /// Each list member's fork point.
    pub fn forks(&self) -> &ForkPoints {
        &self.forks
    }

    /// The active list member of a device ID: not revoked, and not forked.
    pub fn active(&self, device: &DeviceId) -> Option<&Member> {
        self.members
            .get(device)
            .filter(|m| m.active() && self.forks.fork_point(device).is_none())
    }

    /// The active list members, by device ID.
    pub fn active_members(&self) -> impl Iterator<Item = &Member> {
        self.members
            .values()
            .filter(|m| self.active(&m.device).is_some())
    }

    /// Whether the list is **dead**: no active list member. No list member
    /// can sign, and nothing vouches for any key.
    pub fn is_dead(&self) -> bool {
        self.active_members().next().is_none()
    }

    /// Whether a list member is **waiting**: rooted in an agent, and not an
    /// agent.
    pub fn is_waiting(&self, device: &DeviceId) -> bool {
        self.members.get(device).is_some_and(Member::waiting)
    }

    /// The **recipients** under a person grant (identity.md, "What a list
    /// vouches for"): each active list member that is a device, a passkey
    /// member or a recovery key, has not forked, and is not waiting. An
    /// agent receives nothing. By device ID.
    pub fn recipients(&self) -> Vec<DeviceId> {
        self.recipients_with(|_| false)
    }

    /// The recipients, with a hook that decides whether a waiting list
    /// member is vouched for: ext-recovery-agent.md's waiting period. In core
    /// protocol 1 a waiting list member waits until a `confirm` clears it,
    /// which [`MergedList::recipients`] gives.
    pub fn recipients_with(&self, vouch_waiting: impl Fn(&Member) -> bool) -> Vec<DeviceId> {
        self.active_members()
            .filter(|m| m.kind != Kind::RecoveryAgent)
            .filter(|m| !m.waiting() || vouch_waiting(m))
            .map(|m| m.device)
            .collect()
    }

    /// The **writers**: each device or passkey member that a valid `add`
    /// names, revoked or not, with its first `add`. A revocation or a fork
    /// ends its path in a space only once a writer of the space responds
    /// ([`MergedList::ends`]). A recovery key and an agent never write.
    pub fn writers(&self) -> BTreeMap<DeviceId, EventId> {
        self.members
            .values()
            .filter(|m| matches!(m.kind, Kind::Device | Kind::PasskeyMember))
            .map(|m| (m.device, m.adds[0]))
            .collect_map()
    }

    /// The events that end a list member's path through the person: its
    /// valid revocations, by ID, and for a fork the canonically later event
    /// of the evidence that fixes its fork point.
    pub fn ends(&self, device: &DeviceId) -> Vec<EventId> {
        let mut out = self
            .members
            .get(device)
            .map(|m| m.revoked_by.clone())
            .unwrap_or_default();
        out.sort_unstable();
        out.extend(self.fork_ends.get(device));
        out
    }

    /// Whether the merged list holds an active agent: a space whose policy
    /// forbids agents wraps nothing for the person's devices.
    pub fn holds_active_agent(&self) -> bool {
        self.active_members().any(|m| m.kind == Kind::RecoveryAgent)
    }

    /// Whether these keys are an active list member of the merged list, of
    /// this kind, with exactly these keys (identity.md, "Recovery", step 4;
    /// "Using a passkey member", step 4).
    ///
    /// # Errors
    ///
    /// `NotOnList`.
    pub fn check_on_list(&self, kind: Kind, keys: &PublicKeys) -> Result<(), IdentityClass> {
        let device = keys.device_id();
        let listed = self
            .active(&device)
            .is_some_and(|m| m.kind == kind && self.keys.get(&device) == Some(keys));
        if listed {
            Ok(())
        } else {
            Err(IdentityClass::NotOnList)
        }
    }

    /// Steps 2 and 4 of `use_passkey_member` (identity.md, "Using a passkey
    /// member"): derive the passkey member from the PRF output under
    /// `person_id`, then check that the merged list is that person's and
    /// that the member is an active passkey member of it. Step 1 is
    /// [`read_user_handle`]; step 3, fetching the personal space, is the
    /// client's. Every derived secret is zeroised on failure.
    ///
    /// # Errors
    ///
    /// `InvalidPrfOutput`, then `NotOnList`.
    pub fn use_passkey_member(
        &self,
        person_id: &[u8; 32],
        output: &[u8],
    ) -> Result<PasskeyMember, IdentityClass> {
        let member = PasskeyMember::derive(person_id, output)?;
        if *person_id != self.person_id {
            return Err(IdentityClass::NotOnList);
        }
        self.check_on_list(
            Kind::PasskeyMember,
            &member.member().public(Kind::PasskeyMember),
        )?;
        Ok(member)
    }

    /// Whether a recovery entry counts: an entry of the personal space whose
    /// member is not an active passkey member or recovery key of the merged
    /// list is ignored (identity.md, "Fetch keys and recovery entries").
    pub fn entry_counts(&self, entry: &RecoveryEntry) -> bool {
        match &entry.holder {
            Holder::Member(member) => self
                .active(member)
                .is_some_and(|m| matches!(m.kind, Kind::PasskeyMember | Kind::RecoveryKey)),
            Holder::Seed(_) => true,
        }
    }
}

/// Step 1 of `use_passkey_member` (identity.md, "Using a passkey member"):
/// the user handle is 64 bytes, the person ID then the personal space ID,
/// and a client that already holds the person's list checks that the person
/// ID is its own.
///
/// # Errors
///
/// `Malformed`, then `WrongPerson`.
pub fn read_user_handle(
    handle: &[u8],
    held: Option<&MergedList>,
) -> Result<UserHandle, IdentityClass> {
    let handle = UserHandle::parse(handle)?;
    if held.is_some_and(|list| list.person_id != handle.person_id) {
        return Err(IdentityClass::WrongPerson);
    }
    Ok(handle)
}

/// What "Checking an account link" reads of the merged list: active list
/// members, forked ones left out, and every list member a valid `add` ever
/// named.
impl ListView for MergedList {
    fn person_id(&self) -> &[u8; 32] {
        &self.person_id
    }

    fn active_kind(&self, device: &DeviceId) -> Option<Kind> {
        self.active(device).map(|m| m.kind)
    }

    fn listed_kind(&self, device: &DeviceId) -> Option<Kind> {
        self.members.get(device).map(|m| m.kind)
    }
}
