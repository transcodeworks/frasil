//! Keys after a checkpoint (keys.md, "Keys after a checkpoint").
//!
//! A checkpoint (roster.md, "Checkpoints") is a roster event that rotates:
//! keys.md's checks against the event and its place take it as they take a
//! genesis ([`EventKind::Checkpoint`](crate::context::EventKind)). It is a
//! grant rotation unless its author does not propagate or the space is
//! restricted, and it is no break. Its author links back to the current
//! state of its view where the gate allows, records gaps otherwise, and
//! delivers the new state, `k_c`, in its own delivery (key names
//! `self_ref`, as every rotation's) to the members of its record.
//!
//! **The record object** is sealed under `k_c` and its header names the
//! checkpoint by its self reference, since the checkpoint's ID does not
//! exist when the record is sealed (roster.md, "The record object"). Once
//! the checkpoint exists that name is the state `{c}`, whose secret is
//! `k_c`: [`record_reference`] and [`record_state`]. The object's ID key,
//! nonce key and seal key derive from `k({c}) = k_c` as for any object
//! (units.md, "Objects"), and the record's **object key**, which a space
//! snapshot hands a newcomer (units.md, "The space snapshot", key 13), is
//! that object's own key; `frasil-units` derives it.
//!
//! **The key graph rooted at a checkpoint.** Once the checkpoint `c` is in
//! effect, its world (roster.md, "The world after a checkpoint") is the key
//! graph's too: the rotations counted are `c` and the valid rotations after
//! it ([`counts`], [`world_state`], [`seal_against_checkpoint`]), so the
//! current state, the heal test ([`counts_artifact`]), entitlement to
//! states after it and the link gate ([`gate_breaks`]) read nothing before
//! it. A state before it is reached only through links and gap keys made
//! under it or after it:
//!
//! - a member with a "with history" grant after the checkpoint, or a space
//!   principal with a "with history" notice after it whose space the record
//!   gives no floor, is entitled to every state before it
//!   ([`entitled_before`]);
//! - a break before the checkpoint never blocks a link after it
//!   ([`gate_breaks`]);
//! - a device tries a delivery of an event after the checkpoint that names
//!   states before it whose rotations it neither holds nor can fetch, when
//!   it is entitled to them ([`tries`]); a key it takes for a rotation whose
//!   event it does not hold is provisional ([`provisional`]), compared slot
//!   by slot once it holds that rotation's visible part.
//!
//! **Forgetting.** A replica that forgets the events before its kept
//! checkpoint keeps the keys of the states its retained units, objects,
//! names and kept events are sealed under, and, for each, who is entitled to
//! it: [`plan_forgetting`] and [`KeptState`].
//!
//! # What this module takes as inputs
//!
//! The roster, the world's resolution and which checkpoint is in effect are
//! `frasil-space`'s. This module reads them through [`Rooted`], which says
//! where an event stands against the kept checkpoint, and through plain
//! arguments: the valid rotations, the causal order, and the entitlement a
//! replica that holds the past computes before it forgets. [`Sides`] is a
//! ready [`Rooted`] for a replica that classified the events it holds.
//!
//! # Readings taken where the text leaves a choice
//!
//! - A space event after the checkpoint sealed under a state with a rotation
//!   that is not the checkpoint or after it, in its past, is `StaleSeal`
//!   ([`seal_against_checkpoint`]): no rotation outside the world is
//!   counted, and the checkpoint follows every rotation before it.
//! - Entitlement to a state before the checkpoint from a member's own past
//!   ([`KeptState`]) is for a replica that still holds that past: a replica
//!   that forgot it passes none and counts a record member as entitled to
//!   no state before the checkpoint.

use crate::KeyClass;
use crate::links::LinkKind;
use crate::names::{KeyName, RotationSet, SelfRef};
use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};

// -- Where an event stands

/// Where an event stands against the checkpoint a key graph is rooted at
/// (roster.md, "What follows a checkpoint").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// In the checkpoint's past: held, or forgotten and known to have been.
    Before,
    /// The checkpoint itself, which stands as the world's genesis.
    Root,
    /// After it: its cuts reach the checkpoint.
    After,
    /// Late: neither in its past nor after it, so void.
    Late,
    /// The replica cannot tell: it holds neither the event nor a note of
    /// where it stood. A newcomer that started from the checkpoint knows
    /// nothing before it.
    Unknown,
}

impl Side {
    /// Where an event the replica holds stands: the checkpoint itself; after
    /// it when its cuts reach it (`follows`); before it when it is in its
    /// causal past (`in_past`); late otherwise.
    pub fn of_held(is_checkpoint: bool, follows: bool, in_past: bool) -> Self {
        if is_checkpoint {
            Self::Root
        } else if follows {
            Self::After
        } else if in_past {
            Self::Before
        } else {
            Self::Late
        }
    }

    /// Whether it is an event of the checkpoint's world: the checkpoint or
    /// an event after it.
    pub fn in_world(self) -> bool {
        matches!(self, Self::Root | Self::After)
    }
}

/// What a key graph rooted at a checkpoint in effect reads of the log: the
/// checkpoint, and where each event stands against it. `frasil-space`
/// decides which checkpoint is in effect and which events follow it.
pub trait Rooted {
    /// The checkpoint the key graph is rooted at: the last of the chain in
    /// effect, or the replica's kept checkpoint.
    fn checkpoint(&self) -> EventId;

    /// Where an event stands against it.
    fn side(&self, id: &EventId) -> Side;
}

/// A [`Rooted`] from sets: the checkpoint, the events after it, and the
/// events before it and late that the replica holds or noted when it forgot
/// them. Every other ID is [`Side::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sides {
    checkpoint: EventId,
    sides: BTreeMap<EventId, Side>,
}

impl Sides {
    /// Sides of a replica that knows only the checkpoint.
    pub fn new(checkpoint: EventId) -> Self {
        Self {
            checkpoint,
            sides: BTreeMap::new(),
        }
    }

    /// Sides of the events a replica holds, from their cuts and their causal
    /// order: `follows(e)` when `e`'s cuts reach the checkpoint, and
    /// `precedes(a, b)` when `a` is in `b`'s past.
    pub fn classify(
        checkpoint: EventId,
        events: impl IntoIterator<Item = EventId>,
        follows: impl Fn(&EventId) -> bool,
        precedes: impl Fn(&EventId, &EventId) -> bool,
    ) -> Self {
        let mut out = Self::new(checkpoint);
        for id in events {
            if id == checkpoint {
                continue;
            }
            let side = Side::of_held(false, follows(&id), precedes(&id, &checkpoint));
            out.sides.insert(id, side);
        }
        out
    }

    /// Notes where an event stands; the checkpoint itself is always
    /// [`Side::Root`]. A replica that forgets an event may note it as
    /// [`Side::Before`] or [`Side::Late`] first.
    pub fn insert(&mut self, id: EventId, side: Side) {
        if id != self.checkpoint {
            self.sides.insert(id, side);
        }
    }

    /// The events of the world: the checkpoint and the events after it.
    pub fn world(&self) -> BTreeSet<EventId> {
        let mut out: BTreeSet<EventId> = self
            .sides
            .iter()
            .filter(|(_, side)| **side == Side::After)
            .map(|(id, _)| *id)
            .collect();
        out.insert(self.checkpoint);
        out
    }

    /// What a replica that forgets keeps of these sides: the checkpoint, the
    /// events after it, and a note of each event before it that `keep_note`
    /// names (those its kept keys are of). Late events and the rest of the
    /// past become [`Side::Unknown`].
    pub fn forgetting(&self, keep_note: impl Fn(&EventId) -> bool) -> Self {
        let sides = self
            .sides
            .iter()
            .filter(|(id, side)| match side {
                Side::After => true,
                Side::Before => keep_note(id),
                _ => false,
            })
            .map(|(id, side)| (*id, *side))
            .collect();
        Self {
            checkpoint: self.checkpoint,
            sides,
        }
    }
}

impl Rooted for Sides {
    fn checkpoint(&self) -> EventId {
        self.checkpoint
    }

    fn side(&self, id: &EventId) -> Side {
        if *id == self.checkpoint {
            return Side::Root;
        }
        self.sides.get(id).copied().unwrap_or(Side::Unknown)
    }
}

// -- The record object

/// The key reference a record object's header carries: its checkpoint's
/// self reference, `0x00 || author || u64be(seq)` (roster.md, "The record
/// object"), since the checkpoint's ID does not exist when the record is
/// sealed.
pub fn record_reference(author: DeviceId, seq: u64) -> KeyName {
    KeyName::SelfRef(SelfRef::new(author, seq))
}

/// The state a record object is sealed under, from its header's key
/// reference and its checkpoint: the checkpoint's self reference names `{c}`,
/// whose secret is the checkpoint's own content key `k_c`. Every member that
/// holds `k_c` opens the record; a newcomer opens it with the object key a
/// snapshot hands it instead.
///
/// # Errors
///
/// That class of reading a key name (keys.md, "Reading key names"), a self
/// reference allowed; then `Malformed` for any name but the checkpoint's
/// self reference. The locator binds that very object, so the caller holds
/// the checkpoint as roster.md says of a record that does not read
/// (`BadCheckpoint`).
pub fn record_state(
    header_reference: &[u8],
    author: DeviceId,
    seq: u64,
    checkpoint: EventId,
) -> Result<RotationSet, KeyClass> {
    match KeyName::decode(header_reference, true)? {
        KeyName::SelfRef(own) if own == SelfRef::new(author, seq) => {
            Ok(RotationSet::single(checkpoint))
        }
        _ => Err(ErrorClass::Malformed.into()),
    }
}

// -- The world's rotations and its current state

/// Whether a rotation counts in the key graph rooted at the checkpoint: the
/// checkpoint and the rotations after it (keys.md, "Keys after a
/// checkpoint").
pub fn counts<R: Rooted + ?Sized>(rooted: &R, id: &EventId) -> bool {
    rooted.side(id).in_world()
}

/// The current state of the world: among the valid rotations, those that
/// count ([`counts`]) and that no other counted rotation follows. `None`
/// when none counts, or when more than 64 do (a collapse is overdue).
///
/// With the checkpoint in effect, every valid event is in its past or after
/// it, and the checkpoint follows every rotation in its past, so a replica
/// that holds everything and one that forgot the past find the same state.
pub fn world_state<R: Rooted + ?Sized>(
    rooted: &R,
    valid_rotations: impl IntoIterator<Item = EventId>,
    precedes: impl Fn(&EventId, &EventId) -> bool,
) -> Option<RotationSet> {
    let counted: Vec<EventId> = valid_rotations
        .into_iter()
        .filter(|id| counts(rooted, id))
        .collect();
    let maximal = counted
        .iter()
        .copied()
        .filter(|r| !counted.iter().any(|o| precedes(r, o)));
    RotationSet::new(maximal).ok()
}

/// How keys.md's `StaleSeal` reads a space event after the checkpoint that
/// does not rotate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SealPlace {
    /// Its `sealed_under` names a rotation outside the world, or one of the
    /// world that is not in the event's past: stale. The checkpoint, a
    /// counted rotation in its place, follows every rotation before it.
    Stale,
    /// Every rotation of `sealed_under` is the checkpoint or a rotation
    /// after it in the event's past: the world's own check decides.
    World,
}

/// keys.md's `StaleSeal` for a space event after the checkpoint (keys.md,
/// "Checks against the event and its place", step 2, with the rotations
/// counted those of "Keys after a checkpoint"). `in_past(r)` says whether
/// rotation `r` is in the event's past. A replica decides it from the
/// visible `sealed_under` and the world alone, so one that forgot the past
/// and one that kept it agree, whichever keys each kept.
pub fn seal_against_checkpoint<R: Rooted + ?Sized>(
    rooted: &R,
    sealed_under: &RotationSet,
    in_past: impl Fn(&EventId) -> bool,
) -> SealPlace {
    let checkpoint = rooted.checkpoint();
    let in_world = sealed_under
        .ids()
        .iter()
        .all(|r| *r == checkpoint || (rooted.side(r) == Side::After && in_past(r)));
    if in_world {
        SealPlace::World
    } else {
        SealPlace::Stale
    }
}

// -- The heal test and the link gate

/// Whether an event's key artifacts (wraps, space wraps, links, gap records
/// and its author as a rotation's) count in the heal test of the world
/// (keys.md, "Keys after a checkpoint"): those of the checkpoint and the
/// events after it alone. Those of late events and of events before the
/// checkpoint count for nothing, whether a replica kept them or not: none
/// of them has a rotation of the world in its past, so none reaches a state
/// of the world, and a replica that dropped them decides as one that kept
/// them.
pub fn counts_artifact(side: Side) -> bool {
    side.in_world()
}

/// The breaks that the link gate's condition 2 counts for a link under a
/// state of the world (keys.md, "Entitlement and the link gate"; "Keys
/// after a checkpoint"): breaks after the checkpoint, and breaks the replica
/// cannot place. A break before the checkpoint precedes every rotation of
/// the world, so it never blocks a link to one; and its grantee holds a
/// state of the world only as a member of the record or through a grant
/// after it, which condition 1 counts, or as a holder the heal test counts.
/// A late break is void, and its grantee was never wrapped a state of the
/// world.
pub fn gate_breaks<R: Rooted + ?Sized>(
    rooted: &R,
    breaks: impl IntoIterator<Item = EventId>,
) -> Vec<EventId> {
    breaks
        .into_iter()
        .filter(|b| matches!(rooted.side(b), Side::After | Side::Unknown))
        .collect()
}

// -- Entitlement to states before the checkpoint

/// What a replica rooted at a checkpoint knows of a member after it, for
/// [`entitled_before`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MemberAfter {
    /// A valid "with history" grant of the member after the checkpoint (for
    /// the grant graph, one without `session`), or for a space principal a
    /// valid "with history" notice of it after the checkpoint.
    pub with_history_after: bool,
    /// The member is still in with the state its record entry gives it: no
    /// valid change after the checkpoint removed it.
    pub in_from_record: bool,
    /// The member is a space principal whose space the record gives a
    /// floor: it is entitled to no state before the checkpoint, whatever
    /// notice admits it after it.
    pub floor: bool,
}

/// A state before the checkpoint that a replica keeps the key of, with the
/// members entitled to it as the replica judged them on the whole past
/// before it forgot (keys.md, "Entitlement and the link gate").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptState<M> {
    /// Content or grant.
    pub kind: LinkKind,
    /// The state.
    pub state: RotationSet,
    /// Members entitled to it for good: in the roster of its place (rule
    /// 1), entitled to each of its rotations (rule 2), or holding a valid
    /// "with history" grant that its rotations precede (rule 3).
    pub entitled: BTreeSet<M>,
    /// Members entitled to it only through a "with history" grant
    /// concurrent with its rotation that was in force at the checkpoint:
    /// entitled while they stay in with the state the record gives them.
    pub while_in: BTreeSet<M>,
}

impl<M: Ord> KeptState<M> {
    /// A kept state nobody is entitled to yet.
    pub fn new(kind: LinkKind, state: RotationSet) -> Self {
        Self {
            kind,
            state,
            entitled: BTreeSet::new(),
            while_in: BTreeSet::new(),
        }
    }
}

/// Whether `member` is entitled to `state`, a state before the checkpoint,
/// in a key graph rooted at it (keys.md, "Keys after a checkpoint"):
///
/// 1. a space principal whose space the record gives a floor is not;
/// 2. a valid "with history" grant of the member after the checkpoint, or
///    a valid "with history" notice of a principal, entitles it to every
///    state before it, since each precedes it;
/// 3. otherwise, at a replica that still holds the past, as it judges it
///    there ([`KeptState`]): for good, or while the member stays in with
///    its record entry's state;
/// 4. otherwise it is not entitled: a replica that forgot the past passes
///    no judgement, and counts a member of the record as entitled to none.
///
/// `None` when `state` is no state before the checkpoint: a rotation of it
/// is the checkpoint or after it, and the world's own rules decide. A state
/// with a late rotation is entitled only through a kept judgement: a "with
/// history" grant after the checkpoint need not follow a late rotation. A
/// rotation the replica cannot place ([`Side::Unknown`]) counts as before
/// it here, since a newcomer that started from the checkpoint can place
/// none.
pub fn entitled_before<R: Rooted + ?Sized, M: Ord>(
    rooted: &R,
    state: &RotationSet,
    member: &M,
    after: MemberAfter,
    kept: Option<&KeptState<M>>,
) -> Option<bool> {
    let sides: Vec<Side> = state.ids().iter().map(|r| rooted.side(r)).collect();
    if sides.iter().any(|side| side.in_world()) {
        return None;
    }
    if after.floor {
        return Some(false);
    }
    let before = |side: &Side| matches!(side, Side::Before | Side::Unknown);
    if after.with_history_after && sides.iter().all(before) {
        return Some(true);
    }
    let kept = kept.filter(|kept| kept.state == *state);
    Some(kept.is_some_and(|kept| {
        kept.entitled.contains(member) || (after.in_from_record && kept.while_in.contains(member))
    }))
}

// -- Trial decryption and taking keys

/// Whether a device tries a delivery's wraps in a key graph rooted at a
/// checkpoint (keys.md, "Trial decryption"; "Keys after a checkpoint"):
/// every rotation its names name is an event of the log it holds, or, for a
/// delivery of the checkpoint or an event after it (`carrier`), one it
/// neither holds nor can fetch (`fetchable`) that may stand before the
/// checkpoint ([`Side::Before`], or [`Side::Unknown`] at a replica that
/// never held the past); and it lacks a state the delivery names and is
/// entitled to it. It never tries for a late rotation, and waits for a
/// rotation it can still fetch. A self reference names the carrying event,
/// which the device holds. What it takes from such a delivery is
/// provisional ([`provisional`]); a device tries such a delivery once. With
/// no checkpoint, `frasil-space`'s trial-decryption rule applies unchanged.
pub fn tries<R: Rooted + ?Sized>(
    rooted: &R,
    carrier: &EventId,
    names: &[&KeyName],
    holds_event: impl Fn(&EventId) -> bool,
    fetchable: impl Fn(&EventId) -> bool,
    holds: impl Fn(&KeyName) -> bool,
    entitled: impl Fn(&KeyName) -> bool,
) -> bool {
    let after = rooted.side(carrier).in_world();
    let known = |id: &EventId| {
        holds_event(id)
            || (after && !fetchable(id) && matches!(rooted.side(id), Side::Before | Side::Unknown))
    };
    let all_known = names.iter().all(|name| match name.as_set() {
        Some(set) => set.ids().iter().all(known),
        None => true,
    });
    all_known && names.iter().any(|name| !holds(name) && entitled(name))
}

/// Whether a key received for `state` is provisional (keys.md, "Taking a
/// key"): a merged state received whole, as always; and, after a checkpoint,
/// a state with a rotation whose event the replica does not hold, a rotation
/// before it that it forgot or never held. Such a key has no visible part
/// to be checked against slot by slot; it is used as a provisional key is,
/// and a space event or unit it fails to open is held, never `BadSeal`.
pub fn provisional(state: &RotationSet, holds_event: impl Fn(&EventId) -> bool) -> bool {
    state.len() > 1 || state.ids().iter().any(|r| !holds_event(r))
}

// -- Forgetting

/// What a replica keeps of the key graph when it forgets the events before
/// its kept checkpoint (roster.md, "Forgetting, and starting from a
/// checkpoint"; keys.md, "Keys after a checkpoint").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetPlan<M> {
    /// The states before the checkpoint whose keys it keeps, because a
    /// retained unit, object, name or kept event is sealed under them, with
    /// who is entitled to each, so that it can still deliver them as gap
    /// keys (keys.md, "Deliveries", items 2 and 5).
    pub keep: Vec<KeptState<M>>,
    /// The states before the checkpoint it needs and lacks the key of. What
    /// is sealed under them stays held until a member that holds the key
    /// delivers it; a replica may keep the events whose deliveries could give
    /// it until then.
    pub missing: Vec<(LinkKind, RotationSet)>,
    /// Grant rotations before the checkpoint whose grant seeds it keeps:
    /// a space that grants this one seals its space wraps to the grant key
    /// of the rotation its notice names, which may stand before this
    /// space's checkpoint, until it notices a later one (keys.md, "Notices
    /// and space principals").
    pub grant_rotations: Vec<EventId>,
}

/// What a replica that holds the whole past keeps when it forgets it:
///
/// - `sealed_under`: every state its retained units, objects, sealed names
///   and kept events are sealed under (content);
/// - `noticed`: this space's grant rotations that the valid notices of the
///   spaces that grant it name, as it holds their logs;
/// - `holds(kind, state)`: whether it holds that key;
/// - `entitlement(kind, state)`: the members entitled to the state for good
///   and those entitled while they stay in ([`KeptState`]), as keys.md's
///   rules decide over the whole past.
///
/// Only states with a rotation outside the world are kept here: the keys
/// of the world are kept with its events.
pub fn plan_forgetting<R: Rooted + ?Sized, M: Ord + Clone>(
    rooted: &R,
    sealed_under: impl IntoIterator<Item = RotationSet>,
    noticed: impl IntoIterator<Item = EventId>,
    holds: impl Fn(LinkKind, &RotationSet) -> bool,
    entitlement: impl Fn(LinkKind, &RotationSet) -> (BTreeSet<M>, BTreeSet<M>),
) -> ForgetPlan<M> {
    let needed: BTreeSet<RotationSet> = sealed_under
        .into_iter()
        .filter(|state| state.ids().iter().any(|r| !counts(rooted, r)))
        .collect();
    let mut keep = Vec::new();
    let mut missing = Vec::new();
    for state in needed {
        if holds(LinkKind::Content, &state) {
            let (entitled, while_in) = entitlement(LinkKind::Content, &state);
            keep.push(KeptState {
                kind: LinkKind::Content,
                state,
                entitled,
                while_in,
            });
        } else {
            missing.push((LinkKind::Content, state));
        }
    }
    let grant_rotations: BTreeSet<EventId> = noticed
        .into_iter()
        .filter(|r| !counts(rooted, r))
        .filter(|r| holds(LinkKind::Grant, &RotationSet::single(*r)))
        .collect();
    ForgetPlan {
        keep,
        missing,
        grant_rotations: grant_rotations.into_iter().collect(),
    }
}

/// The grant rotations before the checkpoint whose grant seeds a replica
/// that forgot still keeps (keys.md, "Keys after a checkpoint", What is
/// kept): of those it kept ([`ForgetPlan::grant_rotations`]), each that a
/// space principal in force names, as the replica now holds the logs of the
/// spaces that grant this one (`named`). It drops the others: once no
/// principal in force names a rotation, no space seals a space wrap to its
/// grant key again.
pub fn grant_seeds_kept(kept: &[EventId], named: impl Fn(&EventId) -> bool) -> Vec<EventId> {
    kept.iter().copied().filter(|r| named(r)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> EventId {
        EventId([n; 32])
    }

    #[test]
    fn sides_of_held_events() {
        assert_eq!(Side::of_held(true, false, false), Side::Root);
        assert_eq!(Side::of_held(false, true, false), Side::After);
        assert_eq!(Side::of_held(false, false, true), Side::Before);
        assert_eq!(Side::of_held(false, false, false), Side::Late);
        assert!(Side::Root.in_world() && Side::After.in_world());
        assert!(!Side::Before.in_world() && !Side::Late.in_world());
    }

    #[test]
    fn the_record_is_sealed_under_the_checkpoints_own_state() {
        let author = DeviceId([7; 32]);
        let name = record_reference(author, 9);
        assert!(name.is_self_ref());
        let bytes = name.encode();
        assert_eq!(
            record_state(&bytes, author, 9, id(3)),
            Ok(RotationSet::single(id(3)))
        );
        // Another seq, another author, or a rotation set is not the
        // checkpoint's own name.
        let malformed = Err(KeyClass::from(ErrorClass::Malformed));
        assert_eq!(record_state(&bytes, author, 8, id(3)), malformed);
        assert_eq!(record_state(&bytes, DeviceId([8; 32]), 9, id(3)), malformed);
        let set = RotationSet::single(id(3)).encode();
        assert_eq!(record_state(&set, author, 9, id(3)), malformed);
        assert!(record_state(&[], author, 9, id(3)).is_err());
    }

    #[test]
    fn a_kept_judgement_entitles_while_its_member_stays_in() {
        let mut sides = Sides::new(id(10));
        sides.insert(id(1), Side::Before);
        let state = RotationSet::single(id(1));
        let mut kept = KeptState::new(LinkKind::Content, state.clone());
        kept.entitled.insert("a");
        kept.while_in.insert("b");
        let stays = MemberAfter {
            with_history_after: false,
            in_from_record: true,
            floor: false,
        };
        let left = MemberAfter::default();
        assert_eq!(
            entitled_before(&sides, &state, &"a", left, Some(&kept)),
            Some(true)
        );
        assert_eq!(
            entitled_before(&sides, &state, &"b", stays, Some(&kept)),
            Some(true)
        );
        assert_eq!(
            entitled_before(&sides, &state, &"b", left, Some(&kept)),
            Some(false)
        );
        assert_eq!(
            entitled_before(&sides, &state, &"c", stays, Some(&kept)),
            Some(false)
        );
        // A kept judgement of another state says nothing of this one.
        let other = KeptState {
            state: RotationSet::single(id(2)),
            ..kept.clone()
        };
        assert_eq!(
            entitled_before(&sides, &state, &"a", left, Some(&other)),
            Some(false)
        );
        // A principal whose space has a floor is entitled to none.
        let floored = MemberAfter {
            with_history_after: true,
            in_from_record: true,
            floor: true,
        };
        assert_eq!(
            entitled_before(&sides, &state, &"a", floored, Some(&kept)),
            Some(false)
        );
        // The checkpoint's own state is the world's question.
        let root = RotationSet::single(id(10));
        assert_eq!(
            entitled_before(&sides, &root, &"a", left, Some(&kept)),
            None
        );
    }

    #[test]
    fn provisional_keys() {
        let held = |r: &EventId| *r == id(1);
        assert!(!provisional(&RotationSet::single(id(1)), held));
        assert!(provisional(&RotationSet::single(id(2)), held));
        assert!(provisional(
            &RotationSet::new([id(1), id(3)]).unwrap(),
            |_| true
        ));
        assert!(provisional(
            &RotationSet::new([id(1), id(3)]).unwrap(),
            held
        ));
    }

    #[test]
    fn grant_seeds_stay_while_a_principal_names_them() {
        let kept = [id(1), id(2), id(3)];
        assert_eq!(grant_seeds_kept(&kept, |r| *r != id(2)), vec![id(1), id(3)]);
        assert!(grant_seeds_kept(&kept, |_| false).is_empty());
    }
}
