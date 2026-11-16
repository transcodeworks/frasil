//! List checkpoints (identity.md, "List checkpoints"): a person's list
//! fixed at a point that every active device agreed on, after which a holder
//! of the list keeps only the list's first event, the checkpoint, the adds
//! its record names and what follows. The rules are roster.md's
//! "Checkpoints" read for a list:
//!
//! - **Following.** Body key 8 (`follows`) declares the list checkpoints an
//!   event follows: exactly the maximal checkpoints, under "at or before",
//!   among its parents that are checkpoints and those its parents declare
//!   (events.md, "Cuts", read for a list). An event whose `follows` differ
//!   is void (`BadCuts`). An event **follows** checkpoint `c` when its
//!   declarations reach `c`.
//! - **Validity.** A checkpoint is judged on its own past alone, never
//!   attacked and attacking nothing, in order: (1) the event alone, its
//!   record read (`Malformed`, `UnsupportedVersion`), and its `follows`
//!   (`BadCuts`); (2) its predecessor: without one, no checkpoint its
//!   `follows` reach is valid (`BadCheckpoint`); with one, roster.md's rules
//!   (`BadCheckpoint`, `CheckpointPending`); (3) its signature under the
//!   keys of the adds of its past (`BadSignature`, and `UntrustedSigner`
//!   for an author no such add names); (4) its author's fork point
//!   (`Forked`); (5) its author an active device or recovery key that is not
//!   rooted (`UntrustedSigner`); (6) its record equal, byte for byte, to the
//!   record of its past (`BadCheckpoint`).
//! - **Effect.** A list member **outranks** another at a place when its
//!   rank there is higher, or the same and its seniority the smaller tuple.
//!   A device is **heard** by the checkpoint when a valid `revoke` of its
//!   window named it while it was a device that is not rooted, or
//!   confirmed; the record does not list it; and no such `revoke` was
//!   signed by itself or by a member that outranks it. The record lists
//!   heard devices (key 7), by the `add` that gives their keys. The
//!   electorate is every device of the record that is not rooted, a
//!   confirmed one included, and every heard device, but those **excused**
//!   for good: a device with evidence of its fork in the checkpoint's world;
//!   one that revokes itself after the checkpoint; and one a `revoke` after
//!   the checkpoint names, whatever its verdict, signed by a device or
//!   recovery key of the record that may sign a checkpoint and that
//!   outranks it, when that `revoke` counts as its author's vote. A heard
//!   device's events are checked under its `add`. A device votes by any list
//!   event of it after the checkpoint that is judged, whose signature
//!   verifies, whose `follows` are correct and reach no list checkpoint
//!   concurrent with it, an `ack` when it has nothing else to sign.
//!   Recovery keys, passkey members, agents and members rooted in them that
//!   no `confirm` cleared are not waited for. Excuses and votes only
//!   accumulate, so effect only grows. A checkpoint takes effect once every
//!   member of its electorate voted; among those that follow the current
//!   one and name it as predecessor, the smallest ID takes effect, and so
//!   on: the **chain in effect**. Two such checkpoints both stable need
//!   electorates with no device in common; validity is final and stability
//!   only grows, so a holder's chain moves, as events arrive, only to a
//!   smaller ID, and the events after the one it replaced (not after the
//!   new one) become late.
//! - **A rival.** A holder that forgot under its kept checkpoint cannot
//!   judge a concurrent checkpoint that could replace one of its chain: it
//!   holds such a rival, and while it does, the kept checkpoint and every
//!   event after it are `Pending` ([`crate::kept::KeptList::merge`]).
//! - **Late and mixed.** With a chain in effect, events in the first
//!   checkpoint's past keep the verdicts of that past alone; events after
//!   each checkpoint are judged in its **world**; every other event is void
//!   (`Late`). An event after a checkpoint with a parent other than its
//!   `prev` that is neither the checkpoint nor after it is void
//!   (`MixedCut`).
//! - **The world** of a checkpoint is identity.md's merge over a log whose
//!   root is the checkpoint and whose events are those after it, each
//!   linked only to its parents among them: each record member is a list
//!   member from the start, with its `add`'s keys and kind, its root, agent,
//!   confirmation, seniority and rooting add; heights count from the
//!   checkpoint; an author's events at or below its tip, or at or after its
//!   recorded fork point, are forked; the 4,096 bound counts the checkpoint
//!   and the valid events after it. Its events take keys only from the adds
//!   the record names and the world's own adds: an author none of them
//!   names is `UntrustedSigner`.
//! - **Following.** A parent the holder forgot contributes nothing to an
//!   event's `follows`: it is in the kept checkpoint's past, which another
//!   parent already reaches.
//!
//! The procedure here is the reference's (`list_checkpoints.py`), over the
//! events a holder holds: a whole list ([`crate::DeviceList`]), or a list
//! that forgot ([`crate::kept::KeptList`]), whose kept checkpoint is valid
//! without its past and which reads only what it keeps.

use crate::IdentityClass;
use crate::body::{Action, ListBody};
use crate::keys::Kind;
use crate::keys::Rank;
use crate::merge::{
    Base, Bits, Frame, MergedList, Named, Outcome, Presets, Seniority, Source, alone_in,
    frame_named, is_signature_class, merge_frame,
};
use crate::record::{ListRecord, RecordMember, RecordSeniority};
use crate::state::{Member, Rootedness};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, KeysCommitment};
use frasil_crypto::labels::DEVICE_LIST_SENIORITY;
use frasil_crypto::primitives::sha256;
use frasil_events::EventId;
use frasil_resolve::{How, Verdict};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// What the list checkpoints a holder holds give, beside the verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checkpoints {
    /// The chain in effect, oldest first; for a list that forgot, starting
    /// at its kept checkpoint.
    pub chain: Vec<EventId>,
    /// Each list checkpoint held, with its verdict on its own past
    /// (identity.md, "List checkpoints", "Who signs, and validity").
    pub validity: BTreeMap<EventId, Result<(), IdentityClass>>,
    /// For each valid checkpoint that is not in effect, the members of its
    /// electorate that have not voted, each with the last event of it the
    /// holder holds: whom the checkpoint waits for.
    pub waiting: BTreeMap<EventId, Vec<(DeviceId, Option<EventId>)>>,
    /// For each valid checkpoint, its electorate over the events held after
    /// it: the devices it waits for, less those excused.
    pub electorates: BTreeMap<EventId, BTreeSet<DeviceId>>,
    /// For each valid checkpoint, the devices that voted for it over the
    /// events held after it: its author, and each device with an event
    /// after it that counts as a vote.
    pub votes: BTreeMap<EventId, BTreeSet<DeviceId>>,
    /// The list events before the checkpoint in effect that the holder
    /// holds, keeps alone or dropped when it forgot: a space's ref to one
    /// resolves (roster.md, 3.15.8 Other logs and extensions). Empty with
    /// no checkpoint in effect.
    pub before: BTreeSet<EventId>,
    /// For a holder that forgot, the rivals of its kept checkpoint it holds
    /// (identity.md, "List checkpoints", "A rival"): while any is held, the
    /// kept checkpoint and every event after it are `Pending`.
    pub rivals: BTreeSet<EventId>,
    /// For each list checkpoint held whose record reads, the devices it
    /// hears (identity.md, "List checkpoints", "Effect"), by the `add`s its
    /// record names that the holder holds.
    pub heard: BTreeMap<EventId, BTreeSet<DeviceId>>,
}

/// How many valid list events since the last list checkpoint in effect, or
/// since the list's first event, make a device propose a list checkpoint
/// (identity.md, "List checkpoints", "Clients"). A device may propose more
/// often.
pub const PROPOSAL_THRESHOLD: usize = 1_024;

/// Why a device never cites or votes for a list checkpoint that is not in
/// effect in its view (identity.md, "List checkpoints", "Clients"; roster.md,
/// 3.15.7, contested checkpoints). It tells the person, until the
/// checkpoint takes effect without it, the person has it revoke itself, or
/// the `revoke` is void in its view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contest {
    /// The checkpoint's record hears the device: revoked there only by
    /// members it outranks.
    Heard,
    /// The device's view holds a valid `revoke`, concurrent with the
    /// checkpoint, that names the checkpoint's author or a device its
    /// record keeps, signed by a member that outranks its target.
    Revoked {
        /// The `revoke`.
        revoke: EventId,
        /// The device it names.
        target: DeviceId,
    },
}

/// Whether any placed event of the list is a list checkpoint or declares
/// that it follows one. A list with neither merges exactly as one with no
/// checkpoint rules.
pub(crate) fn declares_checkpoints(src: &dyn Source) -> bool {
    src.canonical().into_iter().any(|id| {
        src.body(id)
            .is_some_and(|b| b.action == Action::Checkpoint || !b.follows.is_empty())
    })
}

/// A verdict on one list checkpoint.
type Validity = Result<(), IdentityClass>;

/// The verdicts over a view, the chain in effect there, and the last frame.
#[derive(Debug, Clone)]
struct Judgment {
    verdicts: BTreeMap<EventId, Verdict<EventId, IdentityClass>>,
    chain: Vec<EventId>,
    last: Rc<Outcome>,
}

#[derive(Default)]
struct Memo {
    reach: BTreeMap<EventId, Rc<BTreeSet<EventId>>>,
    records: BTreeMap<EventId, Rc<ListRecord>>,
    validity: BTreeMap<EventId, Validity>,
    frames: BTreeMap<(EventId, Bits), Rc<Frame>>,
    /// Merged frames: plain ones (`false`) by root and view, worlds
    /// (`true`) by checkpoint and view.
    outcomes: BTreeMap<(EventId, Bits, bool), Rc<Outcome>>,
    stable: BTreeMap<(EventId, Bits), bool>,
    judgments: BTreeMap<(Bits, Option<EventId>), Rc<Judgment>>,
}

/// The procedure over the events one holder holds.
pub(crate) struct Ctx<'a> {
    src: &'a dyn Source,
    /// The list's first event, or for a holder that forgot its kept
    /// checkpoint: the root of every plain frame.
    root: EventId,
    /// For a holder that forgot, its kept checkpoint, valid without its
    /// past.
    kept: Option<EventId>,
    /// Every placed event, parents first, and its position.
    ids: Vec<EventId>,
    index: BTreeMap<EventId, usize>,
    /// Each placed event's past among the placed events.
    anc: Vec<Bits>,
    memo: RefCell<Memo>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(src: &'a dyn Source, root: EventId, kept: Option<EventId>) -> Self {
        let ids = src.canonical();
        let n = ids.len();
        let index: BTreeMap<EventId, usize> =
            ids.iter().enumerate().map(|(i, &id)| (id, i)).collect_map();
        let mut anc: Vec<Bits> = Vec::with_capacity(n);
        for &id in &ids {
            let mut bits = Bits::new(n);
            for parent in src.event(id).expect("placed").parents() {
                if let Some(&p) = index.get(parent) {
                    bits.insert(p);
                    let parent_past = anc[p].clone();
                    bits.union_with(&parent_past);
                }
            }
            anc.push(bits);
        }
        Self {
            src,
            root,
            kept,
            ids,
            index,
            anc,
            memo: RefCell::new(Memo::default()),
        }
    }

    // -- Sets of placed events

    fn empty(&self) -> Bits {
        Bits::new(self.ids.len())
    }

    fn all(&self) -> Bits {
        let mut bits = self.empty();
        for i in 0..self.ids.len() {
            bits.insert(i);
        }
        bits
    }

    fn set(&self, ids: impl IntoIterator<Item = EventId>) -> Bits {
        let mut bits = self.empty();
        for id in ids {
            if let Some(&i) = self.index.get(&id) {
                bits.insert(i);
            }
        }
        bits
    }

    fn members<'s>(&'s self, set: &'s Bits) -> impl Iterator<Item = EventId> + 's {
        set.ones().map(|i| self.ids[i])
    }

    fn filter(&self, set: &Bits, keep: impl Fn(EventId) -> bool) -> Bits {
        let mut out = self.empty();
        for i in set.ones() {
            if keep(self.ids[i]) {
                out.insert(i);
            }
        }
        out
    }

    fn contains(&self, set: &Bits, id: EventId) -> bool {
        self.index.get(&id).is_some_and(|&i| set.contains(i))
    }

    /// An event's past among the placed events.
    fn past(&self, id: EventId) -> Bits {
        self.index
            .get(&id)
            .map_or_else(|| self.empty(), |&i| self.anc[i].clone())
    }

    /// An event's past among the placed events, as IDs.
    pub(crate) fn past_ids(&self, id: EventId) -> BTreeSet<EventId> {
        self.members(&self.past(id)).collect()
    }

    // -- Bodies and declarations

    fn body(&self, id: EventId) -> Option<&'a ListBody> {
        self.src.body(id)
    }

    pub(crate) fn is_checkpoint(&self, id: EventId) -> bool {
        self.body(id)
            .is_some_and(|b| b.action == Action::Checkpoint)
    }

    fn record(&self, id: EventId) -> Option<Rc<ListRecord>> {
        if let Some(record) = self.memo.borrow().records.get(&id) {
            return Some(Rc::clone(record));
        }
        let record = Rc::new(self.body(id)?.list_record()?);
        self.memo
            .borrow_mut()
            .records
            .insert(id, Rc::clone(&record));
        Some(record)
    }

    fn previous(&self, id: EventId) -> Option<EventId> {
        self.record(id).and_then(|r| r.previous)
    }

    fn follows_of(&self, id: EventId) -> &'a [EventId] {
        self.body(id).map_or(&[], |b| &b.follows[..])
    }

    /// The checkpoints an event's `follows` reach: its declarations and,
    /// for each whose body the holder holds, what that one's reach.
    pub(crate) fn reach(&self, id: EventId) -> Rc<BTreeSet<EventId>> {
        if let Some(reach) = self.memo.borrow().reach.get(&id) {
            return Rc::clone(reach);
        }
        let mut out = BTreeSet::new();
        for &c in self.follows_of(id) {
            out.insert(c);
            if self.body(c).is_some() {
                out.extend(self.reach(c).iter().copied());
            }
        }
        let out = Rc::new(out);
        self.memo.borrow_mut().reach.insert(id, Rc::clone(&out));
        out
    }

    /// Checkpoint `x` is at or before checkpoint `y`.
    pub(crate) fn below(&self, x: EventId, y: EventId) -> bool {
        x == y || self.reach(y).contains(&x)
    }

    pub(crate) fn concurrent(&self, x: EventId, y: EventId) -> bool {
        !self.below(x, y) && !self.below(y, x)
    }

    /// An event follows checkpoint `c`: its declarations reach `c`.
    pub(crate) fn follows(&self, id: EventId, c: EventId) -> bool {
        self.reach(id).contains(&c)
    }

    /// The maximal checkpoints, under at or before, among `found`.
    fn maximal(&self, found: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        found
            .iter()
            .copied()
            .filter(|&x| !found.iter().any(|&y| x != y && self.below(x, y)))
            .collect()
    }

    /// The `follows` an event with these parents declares: the maximal
    /// checkpoints among the parents that are checkpoints and the
    /// checkpoints the parents declare.
    pub(crate) fn expected_follows(&self, parents: &[EventId]) -> BTreeSet<EventId> {
        let mut found = BTreeSet::new();
        for &p in parents {
            if self.is_checkpoint(p) {
                found.insert(p);
            }
            found.extend(self.follows_of(p).iter().copied());
        }
        self.maximal(&found)
    }

    /// Whether the holder reads an event: one it placed, or one it keeps
    /// alone or as the list's first.
    fn readable(&self, id: EventId) -> bool {
        self.src.event(id).is_some() || self.body(id).is_some()
    }

    /// Whether an event's `follows` differ from what its parents give
    /// (`BadCuts`). The list's first event declares none. A parent the
    /// holder forgot is in its kept checkpoint's past, so all it could add
    /// is at or before that checkpoint, which a parent after it already
    /// reaches: it contributes nothing, and the check never waits for it
    /// (identity.md, "List checkpoints", "Following").
    pub(crate) fn bad_follows(&self, id: EventId) -> bool {
        let Some(event) = self.src.event(id) else {
            return false;
        };
        if event.is_genesis() {
            return false;
        }
        let declared: BTreeSet<EventId> = self.follows_of(id).iter().copied().collect();
        let read: Vec<EventId> = event
            .parents()
            .iter()
            .copied()
            .filter(|&p| self.readable(p))
            .collect();
        declared != self.expected_follows(&read)
    }

    fn author(&self, id: EventId) -> DeviceId {
        *self.src.event(id).expect("placed").author()
    }

    // -- Frames

    fn frame(&self, root: EventId, members: &Bits) -> Rc<Frame> {
        let key = (root, members.clone());
        if let Some(frame) = self.memo.borrow().frames.get(&key) {
            return Rc::clone(frame);
        }
        let frame = Rc::new(Frame::new(self.src, &self.ids, root, |id| {
            self.contains(members, id)
        }));
        self.memo.borrow_mut().frames.insert(key, Rc::clone(&frame));
        frame
    }

    /// An event's past in the world of `root` over `members`: through
    /// parents among them only.
    fn world_past(&self, root: EventId, members: &Bits, id: EventId) -> Bits {
        let frame = self.frame(root, members);
        let Some(&i) = frame.position.get(&id) else {
            return self.empty();
        };
        self.set(frame.past[i].ones().map(|p| frame.order[p]))
    }

    /// The verdicts decided before the merge of a frame without a base:
    /// `BadCuts`, and each checkpoint's verdict on its own past.
    fn presets_outside(&self, view: &Bits) -> Presets {
        let mut presets = Presets::new();
        for id in self.members(view) {
            if id == self.root || self.src.event(id).is_some_and(|e| e.is_genesis()) {
                continue;
            }
            if self.bad_follows(id) {
                presets.insert(id, Err(IdentityClass::BadCuts));
            } else if self.is_checkpoint(id) {
                presets.insert(id, self.validity(id));
            }
        }
        presets
    }

    fn evidence_of(&self, frame: &Frame) -> Vec<frasil_events::Evidence> {
        frame.evidence(self.src, |id| self.src.check_alone(id).is_none())
    }

    /// The merge of a view with no checkpoint in effect, rooted at the
    /// list's first event.
    fn plain(&self, view: &Bits) -> Rc<Outcome> {
        let key = (self.root, view.clone(), false);
        if let Some(outcome) = self.memo.borrow().outcomes.get(&key) {
            return Rc::clone(outcome);
        }
        let members = self.filter(view, |id| id != self.root);
        let frame = self.frame(self.root, &members);
        let presets = self.presets_outside(view);
        let named = frame_named(self.src, &frame, None);
        let outcome = Rc::new(merge_frame(
            self.src,
            &frame,
            None,
            &presets,
            self.evidence_of(&frame),
            named,
        ));
        self.memo
            .borrow_mut()
            .outcomes
            .insert(key, Rc::clone(&outcome));
        outcome
    }

    /// The record's members as a frame's base.
    fn base(&self, c: EventId) -> Base {
        let record = self.record(c).expect("a checkpoint's record");
        let person = self.src.person_id();
        let mut base = Base {
            epoch: record.epoch,
            members: BTreeMap::new(),
            seniority: BTreeMap::new(),
            forks: record.forks.iter().copied().collect_map(),
            tips: record.tips.iter().map(|(d, s, _)| (*d, *s)).collect_map(),
        };
        for entry in &record.members {
            let Some(body) = self.body(entry.add).filter(|b| b.action == Action::Add) else {
                continue;
            };
            let mut member = Member::new(body.kind, body.device, entry.add);
            member.root = entry.root;
            member.agent = entry.agent;
            if entry.confirmed {
                // The confirms are in the checkpoint's past: the checkpoint
                // stands for them.
                member.confirmed_by.push(c);
            }
            // The add that rooted it in an agent, which every holder keeps:
            // a verifier counts the waiting period from its first sight, and
            // the veto traces through its author.
            member.agent_adds = entry.rooting.into_iter().collect();
            let hash = sha256(&[DEVICE_LIST_SENIORITY, &person, &body.device.0]);
            base.seniority.insert(
                body.device,
                (
                    entry.seniority.epoch,
                    entry.seniority.height,
                    hash,
                    entry.seniority.add,
                ),
            );
            base.members.insert(body.device, member);
        }
        base
    }

    /// The world of checkpoint `c` over `view`: `c` and the events of
    /// `view` after it.
    fn world(&self, c: EventId, view: &Bits) -> Rc<Outcome> {
        let mut view = self.filter(view, |id| id == c || self.follows(id, c));
        if let Some(&i) = self.index.get(&c) {
            view.insert(i);
        }
        let key = (c, view.clone(), true);
        if let Some(outcome) = self.memo.borrow().outcomes.get(&key) {
            return Rc::clone(outcome);
        }
        let members = self.filter(&view, |id| id != c);
        let frame = self.frame(c, &members);
        let mut presets = Presets::new();
        for &id in &frame.order[1..] {
            let event = self.src.event(id).expect("placed");
            if self.bad_follows(id) {
                presets.insert(id, Err(IdentityClass::BadCuts));
            } else if event
                .parents()
                .iter()
                .any(|&p| Some(p) != event.prev() && p != c && !self.follows(p, c))
            {
                presets.insert(id, Err(IdentityClass::MixedCut));
            } else if self.is_checkpoint(id) {
                presets.insert(id, self.validity(id));
            }
        }
        let base = self.base(c);
        // Keys only from the record's adds and the world's own.
        let named = frame_named(self.src, &frame, Some(&base));
        let evidence = frame.evidence(self.src, |id| {
            alone_in(self.src, Some(&named), id).is_none()
        });
        let outcome = Rc::new(merge_frame(
            self.src,
            &frame,
            Some(&base),
            &presets,
            evidence,
            named,
        ));
        self.memo
            .borrow_mut()
            .outcomes
            .insert(key, Rc::clone(&outcome));
        outcome
    }

    // -- A checkpoint's validity

    /// A checkpoint's verdict on its own past (identity.md, "List
    /// checkpoints", "Validity").
    pub(crate) fn validity(&self, c: EventId) -> Validity {
        if self.kept == Some(c) {
            return Ok(());
        }
        if let Some(&verdict) = self.memo.borrow().validity.get(&c) {
            return verdict;
        }
        // Held while it is judged: a checkpoint never waits on itself.
        self.memo
            .borrow_mut()
            .validity
            .insert(c, Err(IdentityClass::Shared(ErrorClass::Pending)));
        let verdict = self.judge_validity(c);
        self.memo.borrow_mut().validity.insert(c, verdict);
        verdict
    }

    fn judge_validity(&self, c: EventId) -> Validity {
        // 1. The event alone (section 3.1, steps 1 to 6, its record read),
        // and its follows.
        if let Some(class) = self.src.check_alone(c).filter(|&k| !is_signature_class(k)) {
            return Err(class);
        }
        if self.bad_follows(c) {
            return Err(IdentityClass::BadCuts);
        }
        let record = self
            .record(c)
            .ok_or(IdentityClass::Shared(ErrorClass::Malformed))?;
        let previous = record.previous;
        // The checkpoints its follows reach, the kept one first: a holder
        // that forgot decides from it alone.
        let mut reached: Vec<EventId> = self
            .reach(c)
            .iter()
            .copied()
            .filter(|&x| self.is_checkpoint(x))
            .collect();
        reached.sort_unstable_by_key(|&x| (Some(x) != self.kept, x));
        let list = match previous {
            None => {
                // 2. Without a predecessor: no checkpoint its follows reach
                // is valid.
                if reached.iter().any(|&x| self.validity(x).is_ok()) {
                    return Err(IdentityClass::BadCheckpoint);
                }
                if self.kept.is_some() {
                    // A holder that forgot judges only its kept checkpoint
                    // and the events after it; this one follows none and is
                    // late there, so it is never judged.
                    return Err(IdentityClass::CheckpointPending);
                }
                self.plain(&self.past(c))
            }
            Some(p) => {
                // 2. With a predecessor p: p is a checkpoint its follows
                // reach, and every checkpoint they reach is at or before p,
                // or after it;
                if !self.is_checkpoint(p)
                    || !reached.contains(&p)
                    || reached.iter().any(|&x| self.concurrent(x, p))
                {
                    return Err(IdentityClass::BadCheckpoint);
                }
                // none they reach after p is valid;
                if reached
                    .iter()
                    .any(|&x| x != p && self.below(p, x) && self.validity(x).is_ok())
                {
                    return Err(IdentityClass::CheckpointPending);
                }
                // p is valid;
                if self.validity(p).is_err() {
                    return Err(IdentityClass::BadCheckpoint);
                }
                // p is in effect in the view of p and the events after p in
                // its past, which holds no other valid checkpoint. Its past
                // there: p and the events after p that it reaches through
                // events after p.
                let mut pool = if self.kept.is_some() {
                    self.all()
                } else {
                    self.past(c)
                };
                if let Some(&i) = self.index.get(&c) {
                    pool.insert(i);
                }
                let members = self.filter(&pool, |id| self.follows(id, p));
                let mut held = self.world_past(p, &members, c);
                if let Some(&i) = self.index.get(&p) {
                    held.insert(i);
                }
                if let Some(&i) = self.index.get(&c) {
                    held.remove(i);
                }
                if self
                    .members(&held)
                    .any(|id| id != p && self.is_checkpoint(id) && self.validity(id).is_ok())
                {
                    return Err(IdentityClass::CheckpointPending);
                }
                if !self.stable(p, &held) {
                    return Err(IdentityClass::CheckpointPending);
                }
                self.world(p, &held)
            }
        };
        // 3. Its signature, under the keys of the adds of its past: with p,
        // those p's record names and the adds after p; without, every add
        // of its past. An author no such add names is no list member there.
        self.signature(c, &list.named)?;
        // 4. Its author's fork point there is above its seq.
        let event = self.src.event(c).expect("placed");
        if list.merged.forks().is_void(event) {
            return Err(IdentityClass::Shared(ErrorClass::Forked));
        }
        // 5. Its author is an active device or recovery key there that is
        // not rooted; a confirm clears a device's rootedness.
        let signs = list.merged.member(event.author()).is_some_and(|m| {
            m.active()
                && matches!(m.kind, Kind::Device | Kind::RecoveryKey)
                && m.rooted() == Rootedness::None
        });
        if !signs {
            return Err(IdentityClass::UntrustedSigner);
        }
        // 6. Its record equals, byte for byte, the record of its past.
        let derived = self.record_of(&list, previous);
        if self.body(c).and_then(|b| b.record.as_deref()) != Some(&derived.encode()[..]) {
            return Err(IdentityClass::BadCheckpoint);
        }
        Ok(())
    }

    /// Step 3 of a checkpoint's validity: its signature verifies under the
    /// keys `named` lists, found by their hash. The holder verified it
    /// already under whatever keys hash to its keys commitment, so the
    /// verdict is that one when an add of the past names those keys, and
    /// `UntrustedSigner` when none does.
    fn signature(&self, c: EventId, named: &Named) -> Validity {
        let event = self.src.event(c).expect("placed");
        if !named.contains(event.kc()) {
            return Err(IdentityClass::UntrustedSigner);
        }
        match self.src.check_alone(c) {
            Some(class) if is_signature_class(class) => Err(class),
            _ => Ok(()),
        }
    }

    /// The record of a frame's merged list: identity.md, "List
    /// checkpoints", over the list of a checkpoint's past.
    pub(crate) fn record_of(&self, list: &Outcome, previous: Option<EventId>) -> ListRecord {
        let mut tips: BTreeMap<DeviceId, (u64, EventId)> = BTreeMap::new();
        let epoch = match previous.and_then(|p| self.record(p)) {
            Some(record) => {
                for (device, seq, id) in &record.tips {
                    tips.insert(*device, (*seq, *id));
                }
                record.epoch + 1
            }
            None => 1,
        };
        let mut view = list.view.clone();
        view.sort_unstable();
        for id in view {
            let event = self.src.event(id).expect("placed");
            if event.seq() > tips.get(event.author()).map_or(0, |t| t.0) {
                tips.insert(*event.author(), (event.seq(), id));
            }
        }
        let active: BTreeMap<DeviceId, &Member> = list
            .merged
            .active_members()
            .map(|m| (m.device, m))
            .collect_map();
        let members = active
            .values()
            .map(|m| {
                let s = list.seniority[&m.device];
                RecordMember {
                    add: m.adds[0],
                    root: m.root,
                    agent: m.agent,
                    confirmed: m.confirmed(),
                    seniority: RecordSeniority {
                        epoch: s.0,
                        height: s.1,
                        add: s.3,
                    },
                    rooting: m.agent_adds.first().copied(),
                }
            })
            .collect();
        // The heard devices (identity.md, "List checkpoints", "Effect"):
        // each device a valid revoke of the window named while it was a
        // device that is not rooted, or confirmed, that is not active, and
        // that no such revoke signed by itself or by a member that outranks
        // it named; with its smallest seniority at those revokes, by its
        // earliest valid add.
        let mut found: BTreeMap<DeviceId, (bool, Seniority)> = BTreeMap::new();
        for r in list.revocations.iter().filter(|r| r.waited) {
            let Some(seniority) = r.seniority else {
                continue;
            };
            let excusing = r.by == r.target || r.outranks;
            found
                .entry(r.target)
                .and_modify(|(excused, s)| {
                    *excused |= excusing;
                    *s = (*s).min(seniority);
                })
                .or_insert((excusing, seniority));
        }
        let mut heard: Vec<(EventId, RecordSeniority)> = found
            .into_iter()
            .filter(|(device, (excused, _))| !excused && !active.contains_key(device))
            .filter_map(|(device, (_, s))| {
                let add = *list.merged.member(&device)?.adds.first()?;
                Some((
                    add,
                    RecordSeniority {
                        epoch: s.0,
                        height: s.1,
                        add: s.3,
                    },
                ))
            })
            .collect();
        heard.sort_by_key(|(add, _)| *add);
        ListRecord {
            epoch,
            previous,
            heard,
            members,
            tips: tips
                .into_iter()
                .filter(|(device, _)| active.contains_key(device))
                .map(|(device, (seq, id))| (device, seq, id))
                .collect(),
            forks: list
                .merged
                .forks()
                .iter()
                .map(|(device, seq)| (*device, seq))
                .collect(),
        }
    }

    // -- Votes and effect

    /// Whether event `id` of `c`'s world counts toward `c`'s effect: judged
    /// (not held), its signature verified under the world's keys, its
    /// follows correct, and reaching no list checkpoint concurrent with `c`.
    fn counts(
        &self,
        c: EventId,
        world: &Outcome,
        id: EventId,
        verdict: &Verdict<EventId, IdentityClass>,
    ) -> bool {
        let held_back = matches!(
            verdict,
            Verdict::Void {
                class: IdentityClass::Shared(ErrorClass::Pending | ErrorClass::NoHybridKey),
                ..
            }
        );
        !held_back
            && alone_in(self.src, Some(&world.named), id).is_none()
            && !self.bad_follows(id)
            && !self
                .reach(id)
                .iter()
                .any(|&x| self.is_checkpoint(x) && self.concurrent(x, c))
    }

    /// The devices `c`'s record hears (key 7), each with its seniority as
    /// the merge sorts by it and the keys commitment of the `add` that
    /// gives its keys, under which its events are checked.
    fn heard_of(&self, c: EventId) -> BTreeMap<DeviceId, (Seniority, KeysCommitment)> {
        let Some(record) = self.record(c) else {
            return BTreeMap::new();
        };
        let person = self.src.person_id();
        record
            .heard
            .iter()
            .filter_map(|(add, s)| {
                let body = self.body(*add).filter(|b| b.action == Action::Add)?;
                let keys = body.keys()?;
                let hash = sha256(&[DEVICE_LIST_SENIORITY, &person, &body.device.0]);
                Some((
                    body.device,
                    (
                        (s.epoch, s.height, hash, s.add),
                        *keys.hybrid().commitment(),
                    ),
                ))
            })
            .collect_map()
    }

    /// Whether event `id`, whose author `c` hears, is signed under the
    /// keys of the `add` the record names for it: the world names no key
    /// for it, so it is `UntrustedSigner` there, and its signature verified
    /// under the keys the holder holds.
    fn signed_as_heard(
        &self,
        world: &Outcome,
        heard: &BTreeMap<DeviceId, (Seniority, KeysCommitment)>,
        id: EventId,
    ) -> bool {
        let Some(event) = self.src.event(id) else {
            return false;
        };
        heard
            .get(event.author())
            .is_some_and(|(_, kc)| kc == event.kc())
            && alone_in(self.src, Some(&world.named), id) == Some(IdentityClass::UntrustedSigner)
            && self.src.check_alone(id).is_none()
    }

    /// The devices `c` waits for over `held` (identity.md, "List
    /// checkpoints", "Effect"): every device of the record that is not
    /// rooted, a confirmed one included, and every device it hears, but
    /// those excused, which only grows as events arrive: one with evidence
    /// of its fork in `c`'s world; one that revokes itself after `c` (a
    /// heard device's `revoke` checked under its add); and one a `revoke`
    /// after `c` names, whatever its verdict, signed by a device or
    /// recovery key of the record that may sign a checkpoint and that
    /// outranks it, when that `revoke` counts as its author's vote. A heard
    /// device ranks as a device that is not rooted, with the seniority the
    /// record gives it. A `revoke` that a later merge voids still excuses:
    /// otherwise its target would return to the electorate and `c` could
    /// leave effect. A device excuses nobody it does not outrank, `c`'s
    /// author included: else a revoked device could sign `c` on a view
    /// before its revocation and revoke every other device.
    ///
    /// This is the one place the electorate is computed.
    fn electorate(&self, c: EventId, held: &Bits) -> BTreeSet<DeviceId> {
        let world = self.world(c, held);
        let Some(record) = self.record(c) else {
            return BTreeSet::new();
        };
        let mut named = BTreeSet::new();
        let mut signers = BTreeSet::new();
        for entry in &record.members {
            let Some(body) = self.body(entry.add) else {
                continue;
            };
            let unrooted = entry.root == Rootedness::None || entry.confirmed;
            if body.kind == Kind::Device && unrooted {
                named.insert(body.device);
            }
            if matches!(body.kind, Kind::Device | Kind::RecoveryKey) && unrooted {
                signers.insert(body.device);
            }
        }
        let heard = self.heard_of(c);
        named.extend(heard.keys().copied());
        let mut excused: BTreeSet<DeviceId> = world
            .merged
            .forks()
            .iter()
            .map(|(device, _)| *device)
            .filter(|device| named.contains(device))
            .collect();
        let members = world.merged.members();
        let key = |d: &DeviceId| -> Option<(Rank, Seniority)> {
            Some((members.get(d)?.rank(), *world.seniority.get(d)?))
        };
        for (id, verdict) in world.merged.verdicts().skip(1) {
            let Some(body) = self.body(id).filter(|b| b.action == Action::Revoke) else {
                continue;
            };
            let target = body.device;
            if !named.contains(&target) {
                continue;
            }
            let author = self.author(id);
            if author == target {
                // It revokes itself: it accepts.
                if self.counts(c, &world, id, verdict) || self.signed_as_heard(&world, &heard, id) {
                    excused.insert(target);
                }
                continue;
            }
            if !signers.contains(&author) || !self.counts(c, &world, id, verdict) {
                continue;
            }
            let outranks = match heard.get(&target) {
                Some((seniority, _)) => {
                    key(&author).is_some_and(|k| k < (Rank::Device, *seniority))
                }
                None => matches!((key(&author), key(&target)), (Some(a), Some(b)) if a < b),
            };
            if outranks {
                excused.insert(target);
            }
        }
        named.retain(|device| !excused.contains(device));
        named
    }

    /// The devices that voted for `c` over `held`: its author, each author
    /// of an event after it that counts ([`Ctx::counts`]), and each device
    /// `c` hears whose event after it is signed under the keys of its add,
    /// with correct `follows` that reach no list checkpoint concurrent with
    /// `c`.
    fn votes(&self, c: EventId, held: &Bits) -> BTreeSet<DeviceId> {
        let world = self.world(c, held);
        let heard = self.heard_of(c);
        let mut out = BTreeSet::from([self.author(c)]);
        for (id, verdict) in world.merged.verdicts().skip(1) {
            if self.counts(c, &world, id, verdict)
                || (self.signed_as_heard(&world, &heard, id)
                    && !self.bad_follows(id)
                    && !self
                        .reach(id)
                        .iter()
                        .any(|&x| self.is_checkpoint(x) && self.concurrent(x, c)))
            {
                out.insert(self.author(id));
            }
        }
        out
    }

    /// Every member of the electorate voted.
    fn stable(&self, c: EventId, held: &Bits) -> bool {
        let mut held = held.clone();
        if let Some(&i) = self.index.get(&c) {
            held.insert(i);
        }
        let key = (c, held.clone());
        if let Some(&stable) = self.memo.borrow().stable.get(&key) {
            return stable;
        }
        let votes = self.votes(c, &held);
        let stable = self.electorate(c, &held).is_subset(&votes);
        self.memo.borrow_mut().stable.insert(key, stable);
        stable
    }

    /// The members of `c`'s electorate that have not voted over `held`.
    fn not_voted(&self, c: EventId, held: &Bits) -> BTreeSet<DeviceId> {
        let mut held = held.clone();
        if let Some(&i) = self.index.get(&c) {
            held.insert(i);
        }
        let votes = self.votes(c, &held);
        self.electorate(c, &held)
            .into_iter()
            .filter(|d| !votes.contains(d))
            .collect()
    }

    /// The events of `held` that are `c` or after it.
    fn after(&self, c: EventId, held: &Bits) -> Bits {
        self.filter(held, |id| id == c || self.follows(id, c))
    }

    /// The chain in effect over `held`, from `base`.
    fn effective_chain(&self, held: &Bits, base: Option<EventId>) -> Vec<EventId> {
        let mut chain: Vec<EventId> = base.into_iter().collect();
        let mut current = base;
        loop {
            let next = self
                .members(held)
                .filter(|&id| self.is_checkpoint(id) && Some(id) != current)
                .filter(|&id| self.previous(id) == current)
                .filter(|&id| current.is_none_or(|cur| self.follows(id, cur)))
                .filter(|&id| self.validity(id).is_ok())
                .filter(|&id| self.stable(id, &self.after(id, held)))
                .min();
            let Some(next) = next else {
                return chain;
            };
            chain.push(next);
            current = Some(next);
        }
    }

    /// The verdicts over `held` (identity.md, "List checkpoints"; roster.md,
    /// 3.15.5, "Verdicts").
    fn judge(&self, held: &Bits, base: Option<EventId>) -> Rc<Judgment> {
        let key = (held.clone(), base);
        if let Some(judgment) = self.memo.borrow().judgments.get(&key) {
            return Rc::clone(judgment);
        }
        let chain = self.effective_chain(held, base);
        let judgment = if chain.is_empty() {
            let last = self.plain(held);
            Judgment {
                verdicts: last.merged.verdicts().map(|(id, v)| (id, *v)).collect_map(),
                chain,
                last,
            }
        } else {
            let mut verdicts = BTreeMap::new();
            if base.is_none() {
                let past = self.judge(&self.past(chain[0]), None);
                verdicts.extend(past.verdicts.iter().map(|(id, v)| (*id, *v)));
            }
            for pair in chain.windows(2) {
                let (a, b) = (pair[0], pair[1]);
                let members = self.filter(held, |id| id != a && self.follows(id, a));
                let mut view = self.world_past(a, &members, b);
                if let Some(&i) = self.index.get(&b) {
                    view.insert(i);
                }
                let world = self.world(a, &view);
                verdicts.extend(world.merged.verdicts().skip(1).map(|(id, v)| (id, *v)));
                verdicts.insert(a, Verdict::Valid(How::Rules));
            }
            let last_id = *chain.last().expect("a chain");
            let last = self.world(last_id, &self.after(last_id, held));
            verdicts.extend(last.merged.verdicts().skip(1).map(|(id, v)| (id, *v)));
            verdicts.insert(last_id, Verdict::Valid(How::Rules));
            for id in self.members(held) {
                verdicts.entry(id).or_insert(Verdict::Void {
                    class: IdentityClass::Late,
                    by: None,
                });
            }
            Judgment {
                verdicts,
                chain,
                last,
            }
        };
        let judgment = Rc::new(judgment);
        self.memo
            .borrow_mut()
            .judgments
            .insert(key, Rc::clone(&judgment));
        judgment
    }

    // -- What clients read

    /// The merged list over every placed event.
    pub(crate) fn merged(&self) -> MergedList {
        let held = self.all();
        let judgment = self.judge(&held, self.kept);
        let verdicts = self
            .ids
            .iter()
            .map(|&id| {
                let verdict = judgment
                    .verdicts
                    .get(&id)
                    .copied()
                    .unwrap_or(Verdict::Void {
                        class: IdentityClass::Late,
                        by: None,
                    });
                (id, verdict)
            })
            .collect();
        let mut checkpoints = Checkpoints {
            chain: judgment.chain.clone(),
            before: judgment
                .chain
                .last()
                .map(|&last| self.past_ids(last))
                .unwrap_or_default(),
            ..Checkpoints::default()
        };
        for id in self
            .ids
            .iter()
            .copied()
            .filter(|&id| self.is_checkpoint(id))
        {
            // A holder that forgot judges its kept checkpoint and those
            // after it; one that is late there is never judged.
            if self
                .kept
                .is_some_and(|kept| id != kept && !self.follows(id, kept))
            {
                continue;
            }
            if let Some(record) = self.record(id) {
                let heard = record
                    .heard
                    .iter()
                    .filter_map(|(add, _)| self.body(*add).map(|b| b.device))
                    .collect();
                checkpoints.heard.insert(id, heard);
            }
            let validity = self.validity(id);
            checkpoints.validity.insert(id, validity);
            if validity.is_err() {
                continue;
            }
            let mut after = self.after(id, &held);
            if let Some(&i) = self.index.get(&id) {
                after.insert(i);
            }
            checkpoints
                .electorates
                .insert(id, self.electorate(id, &after));
            checkpoints.votes.insert(id, self.votes(id, &after));
            if judgment.chain.contains(&id) {
                continue;
            }
            let waiting = self
                .not_voted(id, &self.after(id, &held))
                .into_iter()
                .map(|device| (device, self.last_of(&device)))
                .collect();
            checkpoints.waiting.insert(id, waiting);
        }
        MergedList::gathered(judgment.last.merged.clone(), verdicts, checkpoints)
    }

    /// The last placed event of an author: its greatest `seq`, the
    /// smaller ID on a tie.
    fn last_of(&self, device: &DeviceId) -> Option<EventId> {
        self.ids
            .iter()
            .copied()
            .filter(|&id| self.author(id) == *device)
            .max_by_key(|&id| {
                (
                    self.src.event(id).expect("placed").seq(),
                    std::cmp::Reverse(id),
                )
            })
    }

    /// The checkpoint a device signing on `parents` follows, the chain in
    /// effect and the record a checkpoint signed on them carries
    /// (identity.md, "List checkpoints"; list_checkpoints.py's
    /// `make_checkpoint`).
    pub(crate) fn record_for(&self, parents: &[EventId]) -> (ListRecord, Rc<Outcome>) {
        self.record_naming(parents, None)
    }

    /// The record a checkpoint signed on `parents` carries when it names
    /// `previous` as predecessor (`Some(None)` for none), its list that
    /// predecessor's world over its past, or its whole past without one;
    /// with `None`, the chain in effect over that past names it
    /// (list_checkpoints.py's `make_checkpoint`, a dishonest device's
    /// choice included).
    pub(crate) fn record_naming(
        &self,
        parents: &[EventId],
        previous: Option<Option<EventId>>,
    ) -> (ListRecord, Rc<Outcome>) {
        let mut past = self.empty();
        for &q in parents {
            past.union_with(&self.past(q));
            if let Some(&i) = self.index.get(&q) {
                past.insert(i);
            }
        }
        let judgment = self.judge(&past, self.kept);
        let previous = previous.unwrap_or_else(|| judgment.chain.last().copied());
        let list = match previous {
            None if judgment.chain.is_empty() => Rc::clone(&judgment.last),
            None => self.plain(&past),
            Some(p) => {
                let members = self.filter(&past, |id| id != p && self.follows(id, p));
                let mut held = self.set([p]);
                for &q in parents {
                    if q == p || self.follows(q, p) {
                        held.union_with(&self.world_past(p, &members, q));
                        if let Some(&i) = self.index.get(&q) {
                            held.insert(i);
                        }
                    }
                }
                self.world(p, &held)
            }
        };
        (self.record_of(&list, previous), list)
    }

    /// The checkpoint a device follows in its view (roster.md, 3.15.7,
    /// "Following"): the latest valid checkpoint whose chain it is on, the
    /// one in effect, or a valid one waiting for votes whose predecessor is
    /// in effect and that the device does not contest, the one its own
    /// events already follow first, else the smallest ID.
    pub(crate) fn to_follow(
        &self,
        merged: &MergedList,
        own_last: Option<EventId>,
        contested: &BTreeSet<EventId>,
    ) -> Option<EventId> {
        let current = merged.checkpoints.chain.last().copied();
        let mut waiting = self.waiting_on_chain(merged);
        waiting.retain(|c| !contested.contains(c));
        if waiting.is_empty() {
            return current;
        }
        let own = own_last.map(|last| self.reach(last));
        waiting
            .iter()
            .copied()
            .find(|c| {
                own.as_ref()
                    .is_some_and(|reach| reach.contains(c) || own_last == Some(*c))
            })
            .or_else(|| waiting.first().copied())
    }

    /// The valid checkpoints that wait for votes on the chain in effect:
    /// not in effect, naming the latest in effect as predecessor and
    /// following it, ascending by ID.
    pub(crate) fn waiting_on_chain(&self, merged: &MergedList) -> Vec<EventId> {
        let current = merged.checkpoints.chain.last().copied();
        merged
            .checkpoints
            .validity
            .iter()
            .filter(|(id, v)| v.is_ok() && !merged.checkpoints.chain.contains(id))
            .map(|(id, _)| *id)
            .filter(|&id| self.previous(id) == current)
            .filter(|&id| current.is_none_or(|cur| self.follows(id, cur)))
            .collect()
    }

    /// Whether `device`, whose view is every event the holder holds, never
    /// cites or votes for list checkpoint `c` (identity.md, "List
    /// checkpoints", "Clients"), and why: `c`'s record hears it, or the view
    /// holds a valid `revoke` concurrent with `c` naming `c`'s author or a
    /// device its record keeps, signed by a member that outranks its target
    /// at its place.
    pub(crate) fn contest(&self, device: &DeviceId, c: EventId) -> Option<Contest> {
        let record = self.record(c)?;
        if record
            .heard
            .iter()
            .any(|(add, _)| self.body(*add).is_some_and(|b| b.device == *device))
        {
            return Some(Contest::Heard);
        }
        let all = self.all();
        let rivals: BTreeSet<EventId> = self
            .members(&all)
            .filter(|&x| self.causally_concurrent(x, c))
            .collect();
        if rivals.is_empty() {
            return None;
        }
        let mut kept: BTreeSet<DeviceId> = record
            .members
            .iter()
            .filter_map(|m| self.body(m.add).map(|b| b.device))
            .collect();
        kept.insert(self.author(c));
        let list = match self.kept {
            Some(k) => self.world(k, &self.after(k, &all)),
            None => self.plain(&all),
        };
        list.revocations
            .iter()
            .find(|r| rivals.contains(&r.id) && kept.contains(&r.target) && r.outranks)
            .map(|r| Contest::Revoked {
                revoke: r.id,
                target: r.target,
            })
    }

    /// The list checkpoints held, not in effect in `merged`, that `device`
    /// contests ([`Ctx::contest`]).
    pub(crate) fn contested(&self, merged: &MergedList, device: &DeviceId) -> BTreeSet<EventId> {
        self.ids
            .iter()
            .copied()
            .filter(|&x| self.is_checkpoint(x) && !merged.checkpoints.chain.contains(&x))
            .filter(|&x| self.contest(device, x).is_some())
            .collect()
    }

    /// Whether `earlier` is in the past of `later` among the placed events.
    pub(crate) fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.contains(&self.past(later), earlier)
    }

    /// Whether `x` is concurrent with checkpoint `c` in causal order.
    pub(crate) fn causally_concurrent(&self, x: EventId, c: EventId) -> bool {
        x != c && !self.contains(&self.past(c), x) && !self.contains(&self.past(x), c)
    }

    /// Whether the kept checkpoint is in effect over what the holder holds
    /// after it: every member of its electorate voted.
    pub(crate) fn kept_stable(&self) -> bool {
        match self.kept {
            Some(kept) => self.stable(kept, &self.after(kept, &self.all())),
            None => true,
        }
    }
}

/// Merges a list with list checkpoints among its events (identity.md,
/// "List checkpoints"): a whole list, or with `kept` one that forgot.
pub(crate) fn merge_with_checkpoints(src: &dyn Source, kept: Option<EventId>) -> MergedList {
    let root = kept.unwrap_or_else(|| src.canonical()[0]);
    Ctx::new(src, root, kept).merged()
}

impl MergedList {
    /// The list checkpoints in effect, oldest first (identity.md, "List
    /// checkpoints", "Effect"): empty when none is. For a list that forgot,
    /// the chain starts at its kept checkpoint.
    pub fn chain(&self) -> &[EventId] {
        &self.checkpoints.chain
    }

    /// The latest list checkpoint in effect, if any.
    pub fn in_effect(&self) -> Option<EventId> {
        self.checkpoints.chain.last().copied()
    }

    /// Each list checkpoint held, with its verdict on its own past.
    pub fn checkpoint_validity(&self) -> &BTreeMap<EventId, Result<(), IdentityClass>> {
        &self.checkpoints.validity
    }

    /// Whom a valid list checkpoint that is not in effect waits for: the
    /// members of its electorate that have not voted, each with the last
    /// event of it the list holds. `None` for a checkpoint that is not
    /// valid, in effect, or not held. An application shows them, and a
    /// device of the person may revoke one that will not return.
    pub fn waiting_for(&self, checkpoint: EventId) -> Option<&[(DeviceId, Option<EventId>)]> {
        self.checkpoints.waiting.get(&checkpoint).map(Vec::as_slice)
    }

    /// The electorate of a valid list checkpoint over the events the list
    /// holds after it (identity.md, "List checkpoints", "Effect"): every
    /// device of its record that is not rooted, a confirmed one included,
    /// less those excused. `None` for a checkpoint that is not valid or not
    /// held.
    pub fn electorate(&self, checkpoint: EventId) -> Option<&BTreeSet<DeviceId>> {
        self.checkpoints.electorates.get(&checkpoint)
    }

    /// The devices a list checkpoint's record hears (identity.md, "List
    /// checkpoints", "Effect"): revoked in its window only by members they
    /// outrank. They are in its electorate, and a device never votes for a
    /// checkpoint that hears it. `None` for a checkpoint not held or not
    /// judged.
    pub fn heard(&self, checkpoint: EventId) -> Option<&BTreeSet<DeviceId>> {
        self.checkpoints.heard.get(&checkpoint)
    }

    /// The valid list events since the latest list checkpoint in effect,
    /// or since the list's first event with none in effect, which the
    /// first event and the checkpoint do not count.
    pub fn valid_since_checkpoint(&self) -> usize {
        let last = self.in_effect();
        self.valid()
            .enumerate()
            .filter(|&(n, id)| {
                Some(id) != last
                    && !self.checkpoints.before.contains(&id)
                    && (last.is_some() || n > 0)
            })
            .count()
    }

    /// Whether a device proposes a list checkpoint by count: the valid list
    /// events since the latest in effect reach [`PROPOSAL_THRESHOLD`]
    /// (identity.md, "List checkpoints", "Clients"). It proposes only when
    /// no list checkpoint waits for votes in its view and the record fits.
    pub fn proposal_due(&self) -> bool {
        self.valid_since_checkpoint() >= PROPOSAL_THRESHOLD
    }

    /// The devices that voted for a valid list checkpoint over the events
    /// the list holds after it: its author, and each device with an event
    /// after it that counts (identity.md, "List checkpoints", "Effect"), a
    /// heard device's checked under its add. `None` for a checkpoint that
    /// is not valid or not held.
    pub fn voted(&self, checkpoint: EventId) -> Option<&BTreeSet<DeviceId>> {
        self.checkpoints.votes.get(&checkpoint)
    }

    /// Every valid list checkpoint that is not in effect, with whom it
    /// waits for.
    pub fn pending_checkpoints(
        &self,
    ) -> impl Iterator<Item = (EventId, &[(DeviceId, Option<EventId>)])> {
        self.checkpoints
            .waiting
            .iter()
            .map(|(id, waiting)| (*id, waiting.as_slice()))
    }

    /// The events that are `Late`: neither in the past of the list
    /// checkpoint in effect nor after it.
    pub fn late(&self) -> impl Iterator<Item = EventId> + '_ {
        self.verdicts().filter_map(|(id, verdict)| {
            matches!(
                verdict,
                Verdict::Void {
                    class: IdentityClass::Late,
                    ..
                }
            )
            .then_some(id)
        })
    }

    /// The list events before the checkpoint in effect that the holder
    /// holds, keeps alone or dropped when it forgot (roster.md, 3.15.8
    /// Other logs and extensions): a space's ref to one resolves, whether
    /// the holder kept the list whole or forgot it. Empty with no list
    /// checkpoint in effect.
    pub fn before_checkpoint(&self) -> &BTreeSet<EventId> {
        &self.checkpoints.before
    }

    /// Whether a space's ref to a list event resolves because the event is
    /// before the list checkpoint in effect ([`Self::before_checkpoint`]).
    pub fn resolves_before_checkpoint(&self, event: EventId) -> bool {
        self.checkpoints.before.contains(&event)
    }

    /// The rivals of the kept checkpoint a holder that forgot holds
    /// (identity.md, "List checkpoints", "A rival"): list checkpoints
    /// concurrent with it that could take the place of one of its chain,
    /// which only the forgotten past tells. While any is held, the kept
    /// checkpoint and every list event after it are `Pending`; the holder
    /// settles once it gets the rival's past or a sealed copy of the
    /// rival's chain. Empty for a whole list.
    pub fn rivals(&self) -> &BTreeSet<EventId> {
        &self.checkpoints.rivals
    }

    /// The list checkpoint in effect that ends the path of a device it does
    /// not list (identity.md, "List checkpoints", "Spaces"; roster.md,
    /// 3.15.8): the latest in effect, when the merged list holds no list
    /// member of this device ID. `None` with no list checkpoint in effect,
    /// or for a list member.
    pub fn unlisted_end(&self, device: &DeviceId) -> Option<EventId> {
        if self.member(device).is_some() {
            return None;
        }
        self.in_effect()
    }
}

/// What a device does with its own list events that became `Late`
/// (identity.md, "List checkpoints", "Late and mixed"): it re-signs, after
/// the checkpoint, each of its late revocations whose list member is still
/// active, and lists its late adds and confirms for the person to decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LateWork {
    /// The revocations to sign again, as bodies.
    pub resign: Vec<ListBody>,
    /// The late adds and confirms, for the person to decide.
    pub listed: Vec<EventId>,
}

/// The late work of `device` in a list whose events `src` holds.
pub(crate) fn late_work(src: &dyn Source, merged: &MergedList, device: &DeviceId) -> LateWork {
    let mut work = LateWork::default();
    for id in merged.late() {
        let Some(event) = src.event(id) else {
            continue;
        };
        if event.author() != device {
            continue;
        }
        let Some(body) = src.body(id) else {
            continue;
        };
        match body.action {
            Action::Revoke => {
                let needed = merged
                    .active(&body.device)
                    .is_some_and(|m| m.kind == body.kind);
                if needed && !work.resign.iter().any(|b| b.device == body.device) {
                    work.resign.push(ListBody::revoke(body.kind, body.device));
                }
            }
            Action::Add | Action::Confirm => work.listed.push(id),
            Action::Checkpoint | Action::Ack => {}
        }
    }
    work
}

/// The parents and `follows` of the next event a device signs, and for a
/// proposal the record it carries.
pub(crate) struct Plan {
    pub(crate) parents: Vec<EventId>,
    pub(crate) follows: Vec<EventId>,
    pub(crate) record: Option<Result<ListRecord, IdentityClass>>,
}

/// Whether a device signs a proposal next, and whether it heeds the
/// clients' rule that it proposes only when no list checkpoint waits for
/// votes in its view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Propose {
    /// It signs no checkpoint.
    No,
    /// It proposes as a client does.
    AsClient,
    /// It proposes even while another checkpoint waits for votes: for
    /// tests that build competing checkpoints.
    Anyway,
    /// It proposes as a dishonest device would: citing every head it may
    /// cite, fencing nothing, and naming `previous` as predecessor
    /// (`Some(None)` for none, `None` for the latest in effect in its
    /// past), whether or not it may sign one: for tests.
    Unfenced {
        /// The predecessor it names.
        previous: Option<Option<EventId>>,
    },
}

/// What a device that signs next cites (identity.md, "List checkpoints";
/// roster.md, 3.15.7, "Following"): `prev` and the heads of `citable`, at
/// most 16, leaving out every event concurrent with the list checkpoint it
/// follows, so that its event is after that checkpoint and none is
/// `MixedCut`; and the `follows` those parents give. With a proposal, the
/// record of a checkpoint signed on those parents, if `signer` may sign
/// one: an active device or recovery key that is not rooted and has not
/// forked; as a client, only when no list checkpoint waits for votes
/// (`CheckpointPending`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan(
    src: &dyn Source,
    root: EventId,
    kept: Option<EventId>,
    prev: Option<EventId>,
    mut citable: BTreeSet<EventId>,
    heads: &dyn Fn(&BTreeSet<EventId>) -> Vec<EventId>,
    signer: &DeviceId,
    propose: Propose,
) -> Plan {
    let declares = kept.is_some() || declares_checkpoints(src);
    if !declares && propose == Propose::No {
        // No list checkpoint is held and no event follows one: nothing to
        // fence, and the parents declare nothing.
        let mut parents: Vec<EventId> = prev.into_iter().collect();
        parents.extend(
            heads(&citable)
                .into_iter()
                .filter(|&head| Some(head) != prev),
        );
        parents.truncate(frasil_events::kind::MAX_DEVICE_LIST_PARENTS);
        return Plan {
            parents,
            follows: Vec::new(),
            record: None,
        };
    }
    let ctx = Ctx::new(src, root, kept);
    let mut waits = false;
    let unfenced = matches!(propose, Propose::Unfenced { .. });
    if declares && !unfenced {
        let merged = ctx.merged();
        // A contested checkpoint, and every event after it, is never
        // cited: citing it would vote for it (identity.md, "List
        // checkpoints", "Clients").
        let contested = ctx.contested(&merged, signer);
        citable
            .retain(|&x| !contested.contains(&x) && !contested.iter().any(|&b| ctx.precedes(b, x)));
        if let Some(c) = ctx.to_follow(&merged, prev, &contested) {
            citable.retain(|&x| !ctx.causally_concurrent(x, c));
        }
        waits = ctx
            .waiting_on_chain(&merged)
            .iter()
            .any(|c| !contested.contains(c));
    }
    let mut parents: Vec<EventId> = prev.into_iter().collect();
    parents.extend(
        heads(&citable)
            .into_iter()
            .filter(|&head| Some(head) != prev),
    );
    parents.truncate(frasil_events::kind::MAX_DEVICE_LIST_PARENTS);
    let follows = ctx.expected_follows(&parents).into_iter().collect();
    let record = (propose != Propose::No).then(|| {
        if let Propose::Unfenced { previous } = propose {
            return Ok(ctx.record_naming(&parents, previous).0);
        }
        let (record, list) = ctx.record_for(&parents);
        let signs = list.merged.active(signer).is_some_and(|m| {
            matches!(m.kind, Kind::Device | Kind::RecoveryKey) && m.rooted() == Rootedness::None
        });
        if !signs {
            Err(IdentityClass::UntrustedSigner)
        } else if waits && propose == Propose::AsClient {
            Err(IdentityClass::CheckpointPending)
        } else {
            Ok(record)
        }
    });
    Plan {
        parents,
        follows,
        record,
    }
}
