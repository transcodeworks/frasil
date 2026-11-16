//! What a holder of a person's list keeps when it forgets (identity.md,
//! "List checkpoints", "Forgetting"), and the list it judges from there.
//!
//! With a list checkpoint in effect, a holder of the list may forget every
//! list event in its past. It keeps the **kept checkpoint**, the latest in
//! effect, and every event after it, which it judges; and, as events alone,
//! which it never judges:
//!
//! - the list's first event, whose hash the person ID is;
//! - the `add` and the `rooting` add each member entry of the record names:
//!   the first gives the member's kind and keys, the second starts
//!   ext-recovery-agent.md's waiting period and names, by its author, whom
//!   the veto traces through; and the `add` each heard device's entry
//!   names, whose keys its votes are checked under;
//! - the list checkpoints the kept checkpoint's `follows` reach, so that it
//!   orders any checkpoint an event reaches;
//! - every late event, so that it reads the `follows` of a late `prev` and
//!   the checkpoints they reach.
//!
//! It never asks for what it forgot, and judges only from what it keeps. A
//! [`KeptList`] holds exactly that, with the IDs of the events it dropped:
//! a parent among them contributes nothing to an event's `follows`, and an
//! event after the checkpoint that cites one other than its `prev` is
//! `MixedCut`. The checkpoint is valid without its past, the events after
//! it are judged in its world, and every other event it is given is `Late`.
//!
//! An event is placed once each parent other than its `prev` is the kept
//! checkpoint, a placed event, an event kept alone, a dropped one or a
//! chain tip the kept checkpoint's record names; until then it is pending,
//! and the holder fetches the parent. Its `prev` may be an event the holder
//! forgot: a device whose own last event is late continues its chain after
//! the checkpoint, and a `prev` outside the checkpoint's world is not
//! checked.
//!
//! A sealed list copy ([`KeptList::signed_events`]) carries the list's first
//! event, the checkpoint, the adds and rooting adds its record names, the
//! checkpoints its `follows` reach, the late events the holder kept and the
//! events after it; beside it travel the IDs of the list events the holder
//! forgot ([`KeptList::forgotten`]), which a `frasil:system` snapshot state
//! carries in key 5 (units.md, 2.12). A newcomer that starts from the copy
//! ([`KeptList::from_sealed_copy`]) takes its dropped IDs from there, since
//! list events travel only inside sealed copies and no peer serves one.
//!
//! A **rival** of the kept checkpoint (identity.md, "List checkpoints", "A
//! rival") is a list checkpoint concurrent with it that could take the
//! place of one of its chain, which only the forgotten past tells: while
//! the holder holds one, the kept checkpoint and every event after it are
//! `Pending` ([`KeptList::merge`]).

use crate::IdentityClass;
use crate::body::{Action, ListBody, check_body};
use crate::checkpoint::{self, Ctx, LateWork, Propose};
use crate::list::{DeviceList, Refusal};
use crate::merge::{Frame, MergedList, Source};
use crate::record::ListRecord;
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, KeyRing, KeySource};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{
    Envelope, Event, EventClass, EventId, Evidence, ForkPoints, Placement, decode,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// A person's list held from a list checkpoint on: the list's first event,
/// the kept checkpoint, the events kept alone and the events after it.
#[derive(Debug, Clone)]
pub struct KeptList {
    person_id: [u8; 32],
    first: Event,
    checkpoint: EventId,
    record: ListRecord,
    /// Placed events, the kept checkpoint first, with their height counted
    /// from it.
    placed: BTreeMap<EventId, (Event, u64)>,
    order: BTreeSet<(u64, EventId)>,
    /// Events kept alone: read for their bodies, never judged.
    alone: BTreeMap<EventId, Event>,
    /// Bodies that passed steps 2 to 6: of the first event, the events kept
    /// alone and the placed events.
    bodies: BTreeMap<EventId, ListBody>,
    /// Placed events that failed steps 2 to 7, with the class.
    refused: BTreeMap<EventId, IdentityClass>,
    /// Placed events whose author's keys are not held (`NoHybridKey`).
    unverified: BTreeSet<EventId>,
    /// Events waiting for a parent.
    pending: BTreeMap<EventId, Event>,
    keys: KeyRing,
    /// The IDs of the events the holder dropped when it forgot.
    dropped: BTreeSet<EventId>,
}

impl KeptList {
    /// The list a holder keeps, from signed events: the list's first event,
    /// the kept checkpoint, the events kept alone (at least the `add` and
    /// the `rooting` add each record member names) and the events after the
    /// checkpoint, in any order; `dropped` names the events it forgot, empty
    /// for a list built from a sealed copy.
    ///
    /// The caller takes the checkpoint as kept: one it judged in effect on
    /// its whole past, or one a snapshot names and that is in effect over
    /// what it holds after it ([`KeptList::is_in_effect`]).
    ///
    /// # Errors
    ///
    /// The first event's classes, as [`DeviceList::new`]; for the
    /// checkpoint or an event kept alone, events.md's decoding, `WrongLog`
    /// for an event of another list, and `Malformed` for a checkpoint
    /// whose body is not one.
    pub fn new<'a>(
        first: &[u8],
        checkpoint: &[u8],
        alone: impl IntoIterator<Item = &'a [u8]>,
        after: impl IntoIterator<Item = &'a [u8]>,
        dropped: impl IntoIterator<Item = EventId>,
    ) -> Result<Self, Refusal> {
        let alone = alone
            .into_iter()
            .map(decode)
            .collect::<Result<Vec<Event>, EventClass>>()?;
        let dropped = dropped.into_iter().collect();
        let mut list = Self::from_events(decode(first)?, decode(checkpoint)?, alone, dropped)?;
        for signed in after {
            list.insert(signed)?;
        }
        Ok(list)
    }

    /// The list a newcomer holds from a sealed list copy (identity.md,
    /// "List checkpoints", "Spaces"): `copy` as [`KeptList::signed_events`]
    /// writes it, the list's first event, then the kept checkpoint, then
    /// the rest in any order; `forgotten` the IDs of the list events its
    /// writer forgot, as a `frasil:system` snapshot state's key 5 carries
    /// them (units.md, 2.12). An event of the copy whose `follows` reach
    /// the checkpoint is placed after it; every other one is kept alone.
    ///
    /// # Errors
    ///
    /// As [`KeptList::new`]; `Malformed` for a copy of fewer than two
    /// events.
    pub fn from_sealed_copy<'a>(
        copy: impl IntoIterator<Item = &'a [u8]>,
        forgotten: impl IntoIterator<Item = EventId>,
    ) -> Result<Self, Refusal> {
        let mut copy = copy.into_iter();
        let (Some(first), Some(checkpoint)) = (copy.next(), copy.next()) else {
            return Err(IdentityClass::Shared(ErrorClass::Malformed).into());
        };
        let start = decode(first)?;
        let person = start.id().0;
        let c = decode(checkpoint)?.id();
        let rest = copy
            .map(|signed| Ok((signed, decode(signed)?)))
            .collect::<Result<Vec<(&[u8], Event)>, EventClass>>()?;
        let follows: BTreeMap<EventId, Vec<EventId>> = rest
            .iter()
            .filter_map(|(_, event)| {
                check_body(event.unverified_body(), event.author(), Some(&person))
                    .ok()
                    .map(|body| (event.id(), body.follows))
            })
            .collect_map();
        let after = |id: EventId| -> bool {
            let mut seen = BTreeSet::new();
            let mut stack: Vec<EventId> = follows.get(&id).cloned().unwrap_or_default();
            while let Some(x) = stack.pop() {
                if x == c {
                    return true;
                }
                if seen.insert(x) {
                    stack.extend(follows.get(&x).into_iter().flatten().copied());
                }
            }
            false
        };
        let (placed, alone): (Vec<_>, Vec<_>) =
            rest.into_iter().partition(|(_, event)| after(event.id()));
        Self::new(
            first,
            checkpoint,
            alone.into_iter().map(|(signed, _)| signed),
            placed.into_iter().map(|(signed, _)| signed),
            forgotten,
        )
    }

    fn from_events(
        first: Event,
        checkpoint: Event,
        alone: Vec<Event>,
        dropped: BTreeSet<EventId>,
    ) -> Result<Self, Refusal> {
        let start = DeviceList::from_first(first.clone())?;
        let person_id = start.person_id();
        let first_body = start.body(start.first()).expect("the first event").clone();
        let own = |event: &Event| -> Result<(), Refusal> {
            if event.kind() != DEVICE_LIST {
                return Err(IdentityClass::Shared(ErrorClass::Malformed).into());
            }
            if event.log() != Some(EventId(person_id)) {
                return Err(EventClass::WrongLog.into());
            }
            Ok(())
        };
        own(&checkpoint)?;
        let body = check_body(
            checkpoint.unverified_body(),
            checkpoint.author(),
            Some(&person_id),
        )?;
        let record = body
            .list_record()
            .filter(|_| body.action == Action::Checkpoint)
            .ok_or(IdentityClass::Shared(ErrorClass::Malformed))?;
        let c = checkpoint.id();
        let mut list = Self {
            person_id,
            first: first.clone(),
            checkpoint: c,
            record,
            placed: BTreeMap::from([(c, (checkpoint, 0))]),
            order: BTreeSet::from([(0, c)]),
            alone: BTreeMap::new(),
            bodies: BTreeMap::from([(first.id(), first_body), (c, body)]),
            refused: BTreeMap::new(),
            unverified: BTreeSet::from([c]),
            pending: BTreeMap::new(),
            keys: KeyRing::new(),
            dropped,
        };
        for event in alone {
            // The first event names no log (its hash is the person ID), and
            // the checkpoint is placed already: neither is kept alone.
            let id = event.id();
            if id == c || id == first.id() {
                continue;
            }
            own(&event)?;
            if let Ok(body) = check_body(event.unverified_body(), event.author(), Some(&person_id))
            {
                list.bodies.insert(id, body);
            }
            list.alone.insert(id, event);
        }
        list.verify_signatures();
        Ok(list)
    }

    /// The person ID.
    pub fn person_id(&self) -> [u8; 32] {
        self.person_id
    }

    /// The list's first event.
    pub fn first(&self) -> &Event {
        &self.first
    }

    /// The kept checkpoint.
    pub fn checkpoint(&self) -> EventId {
        self.checkpoint
    }

    /// The kept checkpoint's record.
    pub fn record(&self) -> &ListRecord {
        &self.record
    }

    /// The events kept alone, by ID.
    pub fn alone(&self) -> &BTreeMap<EventId, Event> {
        &self.alone
    }

    /// The IDs of the events the holder dropped when it forgot: a ref to
    /// one counts as resolved, and a parent among them contributes nothing.
    pub fn dropped(&self) -> &BTreeSet<EventId> {
        &self.dropped
    }

    /// The IDs of the list events the holder forgot, strictly ascending:
    /// what travels beside its sealed copy, in a `frasil:system` snapshot
    /// state's key 5 (units.md, 2.12; identity.md, "List checkpoints",
    /// "Spaces"), so that a newcomer tells a forgotten parent from one it
    /// has not received.
    pub fn forgotten(&self) -> Vec<EventId> {
        self.dropped.iter().copied().collect()
    }

    /// The late events kept alone, ascending by ID: every event kept alone
    /// that [`KeptList::carried`] does not name. A sealed copy carries them
    /// too.
    pub fn late_kept(&self) -> Vec<EventId> {
        let carried: BTreeSet<EventId> = self.carried().into_iter().collect();
        self.alone
            .keys()
            .copied()
            .filter(|id| !carried.contains(id))
            .collect()
    }

    /// The events kept alone that a sealed copy carries, ascending by ID:
    /// the `add` and the `rooting` add each record member names, the `add`
    /// each heard device's entry names, and the
    /// list checkpoints the kept checkpoint's `follows` reach. The others
    /// kept alone are late events.
    pub fn carried(&self) -> Vec<EventId> {
        let mut out: BTreeSet<EventId> = self
            .record
            .members
            .iter()
            .flat_map(|m| [Some(m.add), m.rooting])
            .flatten()
            .chain(self.record.heard.iter().map(|(add, _)| *add))
            .collect();
        let mut stack: Vec<EventId> = self
            .bodies
            .get(&self.checkpoint)
            .map(|b| b.follows.clone())
            .unwrap_or_default();
        while let Some(c) = stack.pop() {
            if out.insert(c) {
                stack.extend(
                    self.bodies
                        .get(&c)
                        .map(|b| b.follows.clone())
                        .unwrap_or_default(),
                );
            }
        }
        out.into_iter()
            .filter(|id| self.alone.contains_key(id))
            .collect()
    }

    /// An event the list holds, placed, kept alone or as its first.
    pub fn any_event(&self, id: EventId) -> Option<&Event> {
        self.event(id)
            .or_else(|| self.alone.get(&id))
            .or_else(|| (id == self.first.id()).then_some(&self.first))
    }

    /// Whether `earlier` is in the past of `later`, through the parents of
    /// the events the list placed.
    pub fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<EventId> = self
            .event(later)
            .map(|e| e.parents().to_vec())
            .unwrap_or_default();
        while let Some(id) = stack.pop() {
            if id == earlier {
                return true;
            }
            if seen.insert(id)
                && let Some(event) = self.event(id)
            {
                stack.extend(event.parents().iter().copied());
            }
        }
        false
    }

    /// The placed events, the kept checkpoint first, in canonical order
    /// from it.
    pub fn canonical(&self) -> Vec<EventId> {
        self.order.iter().map(|(_, id)| *id).collect()
    }

    /// A placed event.
    pub fn event(&self, id: EventId) -> Option<&Event> {
        self.placed.get(&id).map(|(event, _)| event)
    }

    /// Whether the list holds an event, placed, kept alone or as its first
    /// event.
    pub fn contains(&self, id: EventId) -> bool {
        self.placed.contains_key(&id) || self.alone.contains_key(&id) || id == self.first.id()
    }

    /// The body of a placed event, an event kept alone or the first event,
    /// that passed "Checking a list event alone", steps 2 to 6.
    pub fn body(&self, id: EventId) -> Option<&ListBody> {
        self.bodies.get(&id)
    }

    /// The class of a placed event that failed one of steps 2 to 7, or
    /// `None` if it passed them all.
    pub fn check_alone(&self, id: EventId) -> Option<IdentityClass> {
        if let Some(&class) = self.refused.get(&id) {
            return Some(class);
        }
        if self.unverified.contains(&id) {
            return Some(IdentityClass::Shared(ErrorClass::NoHybridKey));
        }
        None
    }

    /// The keys every `add` the list holds names, by their hashes.
    pub fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// Places a signed event, or holds it pending until its parents are
    /// held.
    ///
    /// # Errors
    ///
    /// As [`KeptList::insert_event`], after events.md's decoding.
    pub fn insert(&mut self, signed: &[u8]) -> Result<Placement, Refusal> {
        self.insert_event(decode(signed)?)
    }

    /// Places a decoded event once each parent other than its `prev` is the
    /// kept checkpoint, a placed event, an event kept alone or a tip the
    /// record names, then runs steps 2 to 7 on it and on every pending
    /// event it releases.
    ///
    /// # Errors
    ///
    /// `Malformed` for an event that is not a device-list event; `WrongLog`
    /// for an event of another list.
    pub fn insert_event(&mut self, event: Event) -> Result<Placement, Refusal> {
        if event.kind() != DEVICE_LIST {
            return Err(IdentityClass::Shared(ErrorClass::Malformed).into());
        }
        if event.log() != Some(EventId(self.person_id)) {
            return Err(EventClass::WrongLog.into());
        }
        let id = event.id();
        if self.contains(id) || self.pending.contains_key(&id) {
            return Ok(Placement::Known);
        }
        let missing = self.missing(&event);
        if !missing.is_empty() {
            self.pending.insert(id, event);
            return Ok(Placement::Pending(missing));
        }
        let mut placed = vec![id];
        self.place(event);
        loop {
            let ready: Vec<EventId> = self
                .pending
                .iter()
                .filter(|(_, e)| self.missing(e).is_empty())
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                break;
            }
            for id in ready {
                let event = self.pending.remove(&id).expect("pending");
                self.place(event);
                placed.push(id);
            }
        }
        self.verify_signatures();
        Ok(Placement::Placed(placed))
    }

    /// The parents of an event, other than its `prev`, that the list does
    /// not hold.
    fn missing(&self, event: &Event) -> Vec<EventId> {
        event
            .parents()
            .iter()
            .copied()
            .filter(|&p| Some(p) != event.prev())
            .filter(|&p| {
                !self.contains(p)
                    && !self.dropped.contains(&p)
                    && !self.record.tips.iter().any(|t| t.2 == p)
            })
            .collect()
    }

    fn place(&mut self, event: Event) {
        let id = event.id();
        match check_body(
            event.unverified_body(),
            event.author(),
            Some(&self.person_id),
        ) {
            Ok(body) => {
                self.bodies.insert(id, body);
            }
            Err(class) => {
                self.refused.insert(id, class);
            }
        }
        self.unverified.insert(id);
        self.placed.insert(id, (event, 0));
        self.heights();
    }

    /// Each placed event's height, counted from the kept checkpoint
    /// through placed parents only: a `prev` placed after its child raises
    /// the child's.
    fn heights(&mut self) {
        let mut heights: BTreeMap<EventId, u64> = BTreeMap::from([(self.checkpoint, 0)]);
        let ids: Vec<EventId> = self.placed.keys().copied().collect();
        for id in ids {
            let mut stack = vec![id];
            while let Some(&top) = stack.last() {
                if heights.contains_key(&top) {
                    stack.pop();
                    continue;
                }
                let parents: Vec<EventId> = self.placed[&top]
                    .0
                    .parents()
                    .iter()
                    .copied()
                    .filter(|p| self.placed.contains_key(p))
                    .collect();
                let waiting: Vec<EventId> = parents
                    .iter()
                    .copied()
                    .filter(|p| !heights.contains_key(p))
                    .collect();
                if waiting.is_empty() {
                    let h = parents
                        .iter()
                        .map(|p| heights[p])
                        .max()
                        .map_or(1, |h| h + 1);
                    heights.insert(top, h);
                    stack.pop();
                } else {
                    stack.extend(waiting);
                }
            }
        }
        self.order = heights.iter().map(|(id, h)| (*h, *id)).collect();
        for (id, (_, height)) in &mut self.placed {
            *height = heights[id];
        }
    }

    /// Step 7 for every placed event whose author's keys were not held,
    /// under the keys the list's adds name.
    fn verify_signatures(&mut self) {
        let named: Vec<_> = self
            .bodies
            .values()
            .filter_map(ListBody::keys)
            .map(|keys| keys.device_keys())
            .collect();
        for device in named {
            self.keys.add_device(device);
        }
        let keys = self.keys.clone();
        self.verify_with(&keys);
    }

    /// Step 7 again, for every placed event still waiting for its author's
    /// keys, under the list's own keys and those `source` holds. Returns the
    /// events whose signature state changed.
    pub fn verify_with(&mut self, source: &(impl KeySource + ?Sized)) -> Vec<EventId> {
        let waiting: Vec<EventId> = self.unverified.iter().copied().collect();
        let mut changed = Vec::new();
        for id in waiting {
            let event = &self.placed[&id].0;
            let keys = self
                .keys
                .hybrid_keys(event.kc())
                .or_else(|| source.hybrid_keys(event.kc()));
            let Some(keys) = keys else {
                continue;
            };
            self.unverified.remove(&id);
            if event.verify_hybrid(Some(&keys)).is_err() {
                self.refused
                    .entry(id)
                    .or_insert(IdentityClass::Shared(ErrorClass::BadSignature));
            }
            changed.push(id);
        }
        changed
    }

    /// Merges the list from its kept checkpoint (identity.md, "List
    /// checkpoints"): the checkpoint is valid, the events after it are
    /// judged in its world, and every other placed event is `Late`. While
    /// the holder holds a rival of the kept checkpoint
    /// ([`MergedList::rivals`]), the checkpoint and every event after it
    /// are `Pending` instead. Refs to the events before the checkpoint in
    /// effect resolve ([`MergedList::before_checkpoint`]): the forgotten
    /// ones, those kept alone in its past and the first event.
    pub fn merge(&self) -> MergedList {
        let mut merged = checkpoint::merge_with_checkpoints(self, Some(self.checkpoint));
        let before = &mut merged.checkpoints.before;
        before.extend(self.dropped.iter().copied());
        before.extend(self.carried());
        before.insert(self.first.id());
        let rivals = self.rivals();
        if !rivals.is_empty() {
            let ctx = Ctx::new(self, self.checkpoint, Some(self.checkpoint));
            let kept = self.checkpoint;
            merged.hold_pending(|id| id == kept || ctx.follows(id, kept));
        }
        merged.checkpoints.rivals = rivals;
        merged
    }

    /// The rivals of the kept checkpoint `c` among what the holder holds
    /// (identity.md, "List checkpoints", "A rival"; roster.md, 3.15.6): a
    /// list checkpoint `x` concurrent with `c` that names `c`'s predecessor,
    /// one `c`'s `follows` reach, or none; whose ID is smaller than that of
    /// a checkpoint of `c`'s chain it could replace (`c`, or one `c`
    /// reaches after the one `x` names, any for none); whose `follows` are
    /// correct; and that is stable in what the holder holds after it, its
    /// votes checked under the keys of the adds its record names and of the
    /// adds after it. One whose record names an add the holder does not
    /// hold counts as a rival: the holder cannot work out its stability.
    /// Each is judged apart, so that it leaves no verdict behind.
    fn rivals(&self) -> BTreeSet<EventId> {
        let base = self.checkpoint;
        let ctx = Ctx::new(self, base, Some(base));
        let previous = self.record.previous;
        let reached = ctx.reach(base);
        let pool: Vec<EventId> = self
            .placed
            .keys()
            .chain(self.alone.keys())
            .copied()
            .collect();
        let mut out = BTreeSet::new();
        for &x in &pool {
            if x == base || !ctx.is_checkpoint(x) || !ctx.concurrent(x, base) {
                continue;
            }
            let Some(record) = self.body(x).and_then(ListBody::list_record) else {
                continue;
            };
            let mut replaceable = vec![base];
            match record.previous {
                None => replaceable.extend(reached.iter().copied()),
                Some(q) if Some(q) == previous || reached.contains(&q) => replaceable.extend(
                    reached
                        .iter()
                        .copied()
                        .filter(|&y| y != q && ctx.below(q, y)),
                ),
                Some(_) => continue,
            }
            if !replaceable.iter().any(|&y| x < y) {
                continue;
            }
            let after: BTreeSet<EventId> = pool
                .iter()
                .copied()
                .filter(|&y| y == x || ctx.follows(y, x))
                .collect();
            let apart = Apart::new(self, x, &after);
            let actx = Ctx::new(&apart, x, Some(x));
            if actx.bad_follows(x) {
                continue;
            }
            if !record.members.iter().all(|m| self.contains(m.add)) || actx.kept_stable() {
                out.insert(x);
            }
        }
        out
    }

    /// Whether `device`, whose view is what this list holds, contests list
    /// checkpoint `checkpoint`, and why (identity.md, "List checkpoints",
    /// "Clients"): it never cites or votes for one, and tells the person.
    /// A checkpoint in effect is not contested.
    pub fn contest(&self, device: &DeviceId, checkpoint: EventId) -> Option<checkpoint::Contest> {
        let ctx = Ctx::new(self, self.checkpoint, Some(self.checkpoint));
        if checkpoint == self.checkpoint || ctx.follows(self.checkpoint, checkpoint) {
            return None;
        }
        let merged = self.merge();
        if merged.chain().contains(&checkpoint) {
            return None;
        }
        ctx.contest(device, checkpoint)
    }

    /// Whether the kept checkpoint is in effect over what the list holds
    /// after it: every member of its electorate voted. A newcomer takes a
    /// checkpoint a snapshot names as kept only once it is.
    pub fn is_in_effect(&self) -> bool {
        Ctx::new(self, self.checkpoint, Some(self.checkpoint)).kept_stable()
    }

    /// The evidence of every fork among the placed events that passed
    /// steps 2 to 7.
    pub fn evidence(&self) -> Vec<Evidence> {
        let frame = Frame::new(self, &self.canonical(), self.checkpoint, |_| true);
        frame.evidence(self, |id| self.check_alone(id).is_none())
    }

    /// Each author's fork point among the placed events.
    pub fn fork_points(&self) -> ForkPoints {
        ForkPoints::from_evidence(&self.evidence())
    }

    /// The list's sealed copy (identity.md, "Sealed list copies", "List
    /// checkpoints", "Spaces"), as signed bytes: its first event, the kept
    /// checkpoint, the events kept alone that its record names and its
    /// `follows` reach ([`KeptList::carried`]), the late events it kept
    /// ([`KeptList::late_kept`]), and the events after the checkpoint. The
    /// IDs of what it forgot travel beside it ([`KeptList::forgotten`]);
    /// [`KeptList::from_sealed_copy`] reads both back.
    pub fn signed_events(&self) -> Vec<Vec<u8>> {
        let mut out = vec![self.first.signed()];
        out.extend(
            self.order
                .iter()
                .take(1)
                .map(|(_, id)| self.placed[id].0.signed()),
        );
        out.extend(self.carried().iter().map(|id| self.alone[id].signed()));
        out.extend(self.late_kept().iter().map(|id| self.alone[id].signed()));
        out.extend(
            self.order
                .iter()
                .skip(1)
                .map(|(_, id)| self.placed[id].0.signed()),
        );
        out
    }

    /// The `seq` and `prev` of `author`'s next event: after the larger of
    /// its latest event the list holds and its tip in the kept
    /// checkpoint's record (roster.md, 3.15.7, "A device offline across a
    /// checkpoint"). A device also keeps its own chain tip at rest, which
    /// may be later still.
    pub fn next_in_chain(&self, author: &DeviceId) -> (u64, Option<EventId>) {
        let held = self
            .placed
            .values()
            .map(|(event, _)| event)
            .chain(self.alone.values())
            .chain([&self.first])
            .filter(|e| e.author() == author)
            .map(|e| (e.seq(), e.id()));
        let tip = self
            .record
            .tips
            .iter()
            .filter(|t| t.0 == *author)
            .map(|t| (t.1, t.2));
        match held
            .chain(tip)
            .max_by_key(|(seq, id)| (*seq, std::cmp::Reverse(*id)))
        {
            Some((seq, id)) => (seq.saturating_add(1), Some(id)),
            None => (1, None),
        }
    }

    /// The placed events a device may cite: those that passed steps 2 to 7
    /// and whose placed parents may be cited.
    fn citable(&self) -> BTreeSet<EventId> {
        let mut view = BTreeSet::new();
        for &(_, id) in &self.order {
            let event = &self.placed[&id].0;
            let past = event
                .parents()
                .iter()
                .all(|p| view.contains(p) || !self.placed.contains_key(p));
            if past && self.check_alone(id).is_none() {
                view.insert(id);
            }
        }
        view
    }

    /// The events of `view` that no other event of `view` names as a
    /// parent.
    fn heads_in(&self, view: &BTreeSet<EventId>) -> Vec<EventId> {
        let cited: BTreeSet<EventId> = view
            .iter()
            .flat_map(|id| self.placed[id].0.parents().iter().copied())
            .collect();
        view.iter()
            .copied()
            .filter(|id| !cited.contains(id))
            .collect()
    }

    fn plan(&self, signer: &DeviceId, propose: Propose) -> checkpoint::Plan {
        let (_, prev) = self.next_in_chain(signer);
        checkpoint::plan(
            self,
            self.checkpoint,
            Some(self.checkpoint),
            prev,
            self.citable(),
            &|view| self.heads_in(view),
            signer,
            propose,
        )
    }

    fn sign_on(&self, body: ListBody, signer: &Signer, parents: Vec<EventId>) -> Vec<u8> {
        let (seq, prev) = self.next_in_chain(signer.device_id());
        Envelope {
            kind: DEVICE_LIST,
            log: Some(EventId(self.person_id)),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(signer)
    }

    /// The signed list event `signer` makes next with `body`, as
    /// [`DeviceList::sign`] makes it. The event is not inserted.
    pub fn sign(&self, body: &ListBody, signer: &Signer) -> Vec<u8> {
        let plan = self.plan(signer.device_id(), Propose::No);
        self.sign_on(
            body.clone().with_follows(plan.follows),
            signer,
            plan.parents,
        )
    }

    /// An `ack` signed by `signer`.
    pub fn ack(&self, signer: &Signer) -> Vec<u8> {
        self.sign(&ListBody::ack(), signer)
    }

    /// A list checkpoint signed by `signer`, as
    /// [`DeviceList::propose_checkpoint`] makes it.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::propose_checkpoint`].
    pub fn propose_checkpoint(&self, signer: &Signer) -> Result<Vec<u8>, IdentityClass> {
        self.propose_with(signer, Propose::AsClient)
    }

    /// A list checkpoint signed as [`DeviceList::propose_checkpoint_anyway`]
    /// signs it: for tests that build competing checkpoints.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::propose_checkpoint_anyway`].
    #[doc(hidden)]
    pub fn propose_checkpoint_anyway(&self, signer: &Signer) -> Result<Vec<u8>, IdentityClass> {
        self.propose_with(signer, Propose::Anyway)
    }

    fn propose_with(&self, signer: &Signer, propose: Propose) -> Result<Vec<u8>, IdentityClass> {
        let plan = self.plan(signer.device_id(), propose);
        let record = plan.record.expect("a proposal")?;
        let body = ListBody::checkpoint(&record).with_follows(plan.follows);
        let signed = self.sign_on(body, signer, plan.parents);
        if signed.len() > frasil_events::kind::limits(DEVICE_LIST).bytes {
            return Err(IdentityClass::Shared(ErrorClass::TooLarge));
        }
        Ok(signed)
    }

    /// What `device` does with its own list events that became `Late`.
    pub fn late_work(&self, merged: &MergedList, device: &DeviceId) -> LateWork {
        checkpoint::late_work(self, merged, device)
    }

    /// The list a holder keeps when the chain in effect has moved past this
    /// list's kept checkpoint: `None` when it has not. It keeps the late
    /// events it already kept.
    pub fn forget(&self, merged: &MergedList) -> Option<KeptList> {
        let ctx = Ctx::new(self, self.checkpoint, Some(self.checkpoint));
        let carried: BTreeSet<EventId> = self.carried().into_iter().collect();
        let late: BTreeSet<EventId> = self
            .alone
            .keys()
            .copied()
            .filter(|id| !carried.contains(id))
            .collect();
        let known: BTreeSet<EventId> = self
            .placed
            .keys()
            .chain(self.alone.keys())
            .chain(&self.dropped)
            .copied()
            .collect();
        let parts = parts(
            self,
            &ctx,
            Some(merged),
            merged.in_effect()?,
            Some(self.checkpoint),
            &late,
            &known,
        )?;
        build(self.first.clone(), parts, |id| self.any_event(id).cloned())
    }
}

impl Source for KeptList {
    fn person_id(&self) -> [u8; 32] {
        self.person_id
    }

    fn event(&self, id: EventId) -> Option<&Event> {
        KeptList::event(self, id)
    }

    fn body(&self, id: EventId) -> Option<&ListBody> {
        KeptList::body(self, id)
    }

    fn check_alone(&self, id: EventId) -> Option<IdentityClass> {
        KeptList::check_alone(self, id)
    }

    fn canonical(&self) -> Vec<EventId> {
        KeptList::canonical(self)
    }
}

/// What a holder keeps under the latest list checkpoint in effect.
struct Parts {
    checkpoint: EventId,
    alone: BTreeSet<EventId>,
    after: Vec<EventId>,
    dropped: BTreeSet<EventId>,
}

/// What a holder of the events `src` places keeps under `c`, one of the
/// chain in effect (identity.md, "List checkpoints", "Forgetting"): `c` and
/// the events after it; alone, the adds and rooting adds `c`'s record
/// names (a heard device's add too), the checkpoints `c`'s `follows` reach, every placed event neither
/// in `c`'s past nor after it, and `late`; and the IDs of the rest of
/// `known` as dropped.
fn parts(
    src: &dyn Source,
    ctx: &Ctx<'_>,
    merged: Option<&MergedList>,
    c: EventId,
    kept: Option<EventId>,
    late: &BTreeSet<EventId>,
    known: &BTreeSet<EventId>,
) -> Option<Parts> {
    if Some(c) == kept || merged.is_some_and(|m| !m.chain().contains(&c)) || !ctx.is_checkpoint(c) {
        return None;
    }
    let record = src.body(c)?.list_record()?;
    let after: Vec<EventId> = src
        .canonical()
        .into_iter()
        .filter(|&id| ctx.follows(id, c))
        .collect();
    let held: BTreeSet<EventId> = after.iter().copied().chain([c]).collect();
    let past = ctx.past_ids(c);
    let mut alone: BTreeSet<EventId> = record
        .members
        .iter()
        .flat_map(|m| [Some(m.add), m.rooting])
        .flatten()
        .chain(record.heard.iter().map(|(add, _)| *add))
        .collect();
    alone.extend(
        ctx.reach(c)
            .iter()
            .copied()
            .filter(|&x| src.event(x).is_some() || src.body(x).is_some()),
    );
    alone.extend(
        src.canonical()
            .into_iter()
            .filter(|id| !held.contains(id) && !past.contains(id)),
    );
    alone.extend(late.iter().copied());
    let dropped = known
        .iter()
        .copied()
        .filter(|id| !held.contains(id) && !alone.contains(id))
        .collect();
    Some(Parts {
        checkpoint: c,
        alone,
        after,
        dropped,
    })
}

fn build(first: Event, parts: Parts, any: impl Fn(EventId) -> Option<Event>) -> Option<KeptList> {
    let checkpoint = any(parts.checkpoint)?;
    let first_id = first.id();
    let alone: Vec<Event> = parts.alone.iter().filter_map(|&id| any(id)).collect();
    let dropped = parts
        .dropped
        .into_iter()
        .filter(|&id| id != first_id)
        .collect();
    let mut list = KeptList::from_events(first, checkpoint, alone, dropped).ok()?;
    for id in parts.after {
        let event = any(id)?;
        list.insert_event(event).ok()?;
    }
    Some(list)
}

impl DeviceList {
    /// What a holder keeps when it forgets (identity.md, "List
    /// checkpoints", "Forgetting"), given this list's merge: a
    /// [`KeptList`] under the latest list checkpoint in effect, or `None`
    /// when none is. The holder may then drop every other event of the
    /// list, and never asks for them again.
    pub fn forget(&self, merged: &MergedList) -> Option<KeptList> {
        self.forget_at(merged, merged.in_effect()?)
    }

    /// What a holder keeps when it forgets under `checkpoint`, one of the
    /// chain in effect in `merged`; `None` for another event.
    pub fn forget_at(&self, merged: &MergedList, checkpoint: EventId) -> Option<KeptList> {
        self.forget_with(Some(merged), checkpoint)
    }

    /// What a holder keeps when it forgets under `checkpoint`, a list
    /// checkpoint of the list, whether or not it is in effect over every
    /// event the list holds: a holder that forgot under a checkpoint in
    /// effect in its view, which a concurrent checkpoint with a smaller ID
    /// replaced since (identity.md, "List checkpoints", "A rival"). For
    /// tests that build such a holder. `None` for an event that is no list
    /// checkpoint of the list.
    #[doc(hidden)]
    pub fn forget_under(&self, checkpoint: EventId) -> Option<KeptList> {
        self.forget_with(None, checkpoint)
    }

    fn forget_with(&self, merged: Option<&MergedList>, checkpoint: EventId) -> Option<KeptList> {
        let ctx = Ctx::new(self, self.first(), None);
        let known: BTreeSet<EventId> = self.log().canonical().into_iter().collect();
        let parts = parts(
            self,
            &ctx,
            merged,
            checkpoint,
            None,
            &BTreeSet::new(),
            &known,
        )?;
        build(self.log().genesis().clone(), parts, |id| {
            self.log().event(id).cloned()
        })
    }
}

/// What a holder that forgot holds after a candidate rival `x`, as a list
/// of its own rooted at `x`: `x` and the events after it, placed or kept
/// alone, read with every body the holder holds. An event kept alone, never
/// judged, has its signature checked here under the keys the holder holds.
struct Apart<'a> {
    list: &'a KeptList,
    order: Vec<EventId>,
    members: BTreeSet<EventId>,
    checked: RefCell<BTreeMap<EventId, Option<IdentityClass>>>,
}

impl<'a> Apart<'a> {
    fn new(list: &'a KeptList, root: EventId, members: &BTreeSet<EventId>) -> Self {
        // Parents first: heights through parents among the members.
        let mut height: BTreeMap<EventId, u64> = BTreeMap::new();
        let parents = |id: EventId| -> Vec<EventId> {
            list.any_event(id)
                .map(|e| {
                    e.parents()
                        .iter()
                        .copied()
                        .filter(|p| members.contains(p))
                        .collect()
                })
                .unwrap_or_default()
        };
        for &id in members {
            let mut stack = vec![id];
            while let Some(&top) = stack.last() {
                if height.contains_key(&top) {
                    stack.pop();
                    continue;
                }
                let ps = parents(top);
                let waiting: Vec<EventId> = ps
                    .iter()
                    .copied()
                    .filter(|p| !height.contains_key(p) && !stack.contains(p))
                    .collect();
                if waiting.is_empty() {
                    let h = ps
                        .iter()
                        .filter_map(|p| height.get(p))
                        .max()
                        .map_or(if top == root { 0 } else { 1 }, |h| h + 1);
                    height.insert(top, h);
                    stack.pop();
                } else {
                    stack.extend(waiting);
                }
            }
        }
        let mut order: Vec<(u64, EventId)> = height.into_iter().map(|(id, h)| (h, id)).collect();
        order.sort_unstable();
        Self {
            list,
            order: order.into_iter().map(|(_, id)| id).collect(),
            members: members.clone(),
            checked: RefCell::new(BTreeMap::new()),
        }
    }
}

impl Source for Apart<'_> {
    fn person_id(&self) -> [u8; 32] {
        self.list.person_id
    }

    fn event(&self, id: EventId) -> Option<&Event> {
        if !self.members.contains(&id) {
            return None;
        }
        self.list.any_event(id)
    }

    fn body(&self, id: EventId) -> Option<&ListBody> {
        self.list.body(id)
    }

    fn check_alone(&self, id: EventId) -> Option<IdentityClass> {
        if self.list.placed.contains_key(&id) {
            return self.list.check_alone(id);
        }
        if let Some(class) = self.checked.borrow().get(&id) {
            return *class;
        }
        let event = self.list.alone.get(&id)?;
        let class = if self.list.body(id).is_none() {
            Some(IdentityClass::Shared(ErrorClass::Malformed))
        } else {
            match self.list.keys.hybrid_keys(event.kc()) {
                None => Some(IdentityClass::Shared(ErrorClass::NoHybridKey)),
                Some(keys) => event
                    .verify_hybrid(Some(&keys))
                    .err()
                    .map(|_| IdentityClass::Shared(ErrorClass::BadSignature)),
            }
        };
        self.checked.borrow_mut().insert(id, class);
        class
    }

    fn canonical(&self) -> Vec<EventId> {
        self.order.clone()
    }
}
