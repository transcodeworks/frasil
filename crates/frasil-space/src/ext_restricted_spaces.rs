//! Restricted spaces and carve-outs in the roster and the key graph
//! (ext-restricted-spaces.md, feature `ext-restricted-spaces`).
//!
//! A restricted space F names its parent P in its descriptor (kind 1). This
//! module fills in the hooks roster.md and keys.md reserve for it:
//!
//! - **The parent** ("The parent of a restricted space"): a replica judges
//!   F only once it holds P's genesis, as a space among the other logs;
//!   until then every event of F is `Pending`, and under a restricted
//!   parent every event of F is `RestrictedParent` ([`parent_verdict`]).
//! - **Membership** ("Membership of a restricted space"): F's effective
//!   membership is its own, keeping only devices that also reach P, each at
//!   the lower of its two levels, propagating only if it propagates in
//!   both ([`narrow`]). Authority over F's roster is F's alone.
//! - **Writes**: P is on every path into F. A device writes in F only while
//!   it reaches P at `write`, and every end of its paths in P ends each of
//!   its paths in F.
//! - **Keys** ("Keys of a restricted space"): F rotates by keys.md's rules
//!   applied to its membership before P narrows it, never for a change of
//!   P ([`rotation`]). A device outside P receives nothing of F, and an
//!   outside holder of F's key counts in its heal test only inside P.
//! - **Mirrors** ("Mirroring P's removals", "Carve-out administration and
//!   the guest"): which of F's or a carve-out's administrator devices
//!   mirror a roster event of P, by rank ([`mirror_candidates`]), and when
//!   a candidate drops its mirror ([`mirror_landed`]).
//! - **The carve-out** ("Creating a carve-out"): the level each member of
//!   P has in it through its grant of P ([`carve_out_levels`]). A carve-out
//!   is otherwise an ordinary space.
//!
//! The restricted key reference and F's sealed names are `frasil-keys'`;
//! the move record, late writes and their re-application `frasil-units'`;
//! F's member key `frasil-transport`'s, each under the same feature.

use crate::across::{GrantedSpace, OtherLogs};
use crate::graph::{self, Reach, SpaceGrants, Verdicts};
use crate::keygraph::rank::{delay, rank_order};
use crate::member::{Level, MemberRef};
use crate::policy::{Descriptor, DescriptorKind};
use crate::{RosterClass, Space, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_events::{EventId, Ref};
use std::collections::BTreeMap;

frasil_base::error_classes! {
    /// ext-restricted-spaces.md's own classes ("Error classes"), with every
    /// shared class.
    pub enum RestrictedClass {
        /// A restricted space whose parent is restricted.
        RestrictedParent = "restricted_parent", Final;
    }
}

impl RestrictedClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

impl From<RestrictedClass> for RosterClass {
    fn from(class: RestrictedClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Restricted(class),
        }
    }
}

// ---------------------------------------------------------------------------
// The parent of a restricted space (section 3.1).

/// The verdict a restricted space's parent gives every event of the space,
/// genesis included: `None` when the roster decides. `parent_kind` gives
/// the kind of a space whose genesis this replica holds.
///
/// ```text
/// 1. Not a restricted space.                     the roster decides
/// 2. The replica holds P's genesis.              else Pending
/// 3. P's descriptor is not kind 1.               else RestrictedParent (final)
/// ```
pub fn parent_verdict(
    descriptor: &Descriptor,
    parent_kind: impl FnOnce(&EventId) -> Option<DescriptorKind>,
) -> Option<RosterClass> {
    if descriptor.kind != DescriptorKind::Restricted {
        return None;
    }
    let parent = EventId(descriptor.parent?);
    match parent_kind(&parent) {
        None => Some(ErrorClass::Pending.into()),
        Some(DescriptorKind::Restricted) => Some(RestrictedClass::RestrictedParent.into()),
        Some(_) => None,
    }
}

/// The parent of a space among the other logs: the space it names, held
/// beside the spaces it grants.
fn parent_of<'a>(descriptor: &Descriptor, others: &OtherLogs<'a>) -> Option<&'a dyn GrantedSpace> {
    others.space(&EventId(descriptor.parent?))
}

/// [`parent_verdict`] for a space whose parent, if this replica holds it,
/// is among `others`: a replica that cannot judge the genesis cannot use
/// the space.
///
/// # Errors
///
/// `Pending` or `RestrictedParent`.
pub(crate) fn check_parent(
    descriptor: &Descriptor,
    others: &OtherLogs<'_>,
) -> Result<(), RosterClass> {
    let held = parent_of(descriptor, others);
    match parent_verdict(descriptor, |_| {
        held.map(|p| {
            if p.is_restricted() {
                DescriptorKind::Restricted
            } else {
                DescriptorKind::Space
            }
        })
    }) {
        Some(class) => Err(class),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Membership of a restricted space (section 3.3), over grants in force.

/// One device's reach narrowed by its reach of the parent: the lower of the
/// two levels, propagating only if it propagates in both; capabilities and
/// depths, propagating ones included, are the restricted space's own.
fn narrow_reach(own: Reach, parent: &Reach) -> Reach {
    let propagating_level = match (own.propagating_level, parent.propagating_level) {
        (Some(a), Some(b)) => Some(a.min(b)),
        _ => None,
    };
    Reach {
        level: own.level.min(parent.level),
        propagates: propagating_level.is_some(),
        propagating_level,
        ..own
    }
}

/// F's effective membership from its own and P's: only the devices that
/// reach both ("Effective membership").
pub fn narrow(
    own: BTreeMap<[u8; 32], Reach>,
    parent: &BTreeMap<[u8; 32], Reach>,
) -> BTreeMap<[u8; 32], Reach> {
    own.into_iter()
        .filter_map(|(device, reach)| {
            parent
                .get(&device)
                .map(|there| (device, narrow_reach(reach, there)))
        })
        .collect()
}

/// A restricted space's membership by its own grants, before its parent's
/// narrows it: what decides whether it rotates.
///
/// # Errors
///
/// [`graph::effective`]'s classes.
pub fn own_membership(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
    verdicts: &Verdicts,
) -> Result<BTreeMap<[u8; 32], Reach>, SpaceClass> {
    graph::own_within(spaces, persons, space, verdicts, &mut Vec::new())
}

/// [`graph::effective`] of a restricted space: its own membership narrowed
/// by its parent's. A restricted space under a restricted parent, whose
/// every event is `RestrictedParent`, has no member.
///
/// # Errors
///
/// [`graph::effective`]'s; `UnknownSpace` while this replica does not hold
/// the parent's roster, on which the membership waits.
pub(crate) fn restricted_membership(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
    verdicts: &Verdicts,
    stack: &mut Vec<EventId>,
) -> Result<BTreeMap<[u8; 32], Reach>, SpaceClass> {
    let parent = spaces
        .get(&space)
        .and_then(|s| s.parent)
        .ok_or(SpaceClass::Shared(ErrorClass::Malformed))?;
    let held = spaces.get(&parent).ok_or(SpaceClass::UnknownSpace)?;
    if held.kind == DescriptorKind::Restricted || stack.contains(&parent) {
        return Ok(BTreeMap::new());
    }
    let own = graph::own_within(spaces, persons, space, verdicts, stack)?;
    stack.push(space);
    let there = graph::own_within(spaces, persons, parent, verdicts, stack);
    stack.pop();
    Ok(narrow(own, &there?))
}

// ---------------------------------------------------------------------------
// A resolved restricted space: membership and paths through its parent.

/// The parent of a resolved restricted space among its other logs; `None`
/// for any other space, and `Some(None)` while the parent is not held.
fn held_parent<'a>(space: &Space<'a>) -> Option<Option<&'a dyn GrantedSpace>> {
    let descriptor = &space.screened().genesis().descriptor;
    (descriptor.kind == DescriptorKind::Restricted)
        .then(|| parent_of(descriptor, space.options().others))
}

/// Narrows a resolved restricted space's effective membership by its
/// parent's, as [`narrow`] does: nothing while the parent is not held.
pub(crate) fn narrow_by_parent(
    space: &Space<'_>,
    own: BTreeMap<[u8; 32], (Level, Option<Level>)>,
    _depth: usize,
    _seen: &[EventId],
) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
    let Some(parent) = held_parent(space) else {
        return own;
    };
    let Some(parent) = parent else {
        return BTreeMap::new();
    };
    let there = parent.effective(0, &[]);
    // Each level the lower of the two; a propagating level only where both
    // propagate, as `Option`'s order puts `None` lowest.
    own.into_iter()
        .filter_map(|(device, (level, propagating))| {
            there
                .get(&device)
                .map(|&(l, p)| (device, (level.min(l), propagating.min(p))))
        })
        .collect_map()
}

/// Whether a device reaches a resolved restricted space's parent at
/// `write`: at its merged roster or at the place of any of its valid roster
/// events, as a writer of a granted space does until a response to the end
/// of its path. `None` while the parent is not held; `Some(true)` for any
/// other space.
fn writes_in_parent(space: &Space<'_>, device: &[u8; 32]) -> Option<bool> {
    let Some(parent) = held_parent(space) else {
        return Some(true);
    };
    let parent = parent?;
    Some(
        parent.propagating_writers().contains(device)
            || parent
                .effective(0, &[])
                .get(device)
                .is_some_and(|&(level, _)| level >= Level::Write),
    )
}

/// The write rule's paths in a restricted space: P is on every path into
/// F. A device that does not reach P at `write` has none; while P is not
/// held, no path can be judged.
pub(crate) fn through_parent(
    space: &Space<'_>,
    device: &[u8; 32],
    paths: Vec<MemberRef>,
    unknown: bool,
) -> (Vec<MemberRef>, bool) {
    match writes_in_parent(space, device) {
        Some(true) => (paths, unknown),
        Some(false) => (Vec::new(), unknown),
        None => (Vec::new(), true),
    }
}

/// The ends of a device's paths in P, which end each of its paths in a
/// restricted space F: an event of F whose refs name one is a response.
pub(crate) fn parent_ends(space: &Space<'_>, device: &[u8; 32]) -> Vec<Ref> {
    held_parent(space)
        .flatten()
        .map(|parent| parent.ends(device))
        .unwrap_or_default()
}

/// Whether a device of a resolved space receives its wraps: in a restricted
/// space, only a device that reaches the parent, since its effective
/// membership keeps no other. Any device of another space.
pub(crate) fn receives(space: &Space<'_>, device: &[u8; 32]) -> bool {
    match held_parent(space) {
        None => true,
        Some(parent) => parent.is_some_and(|parent| parent.effective(0, &[]).contains_key(device)),
    }
}

/// The heal test of a restricted space ("Keys of a restricted space"): an
/// outside holder counts only inside P's merged roster, since a device
/// outside P cannot derive `k_P` of P's current state and P's own heal test
/// covers it. Every outside holder counts in another space.
pub(crate) fn counts_outside(space: &Space<'_>, device: &[u8; 32]) -> bool {
    match held_parent(space) {
        None => true,
        Some(parent) => parent.is_some_and(|parent| parent.effective(0, &[]).contains_key(device)),
    }
}

// ---------------------------------------------------------------------------
// When a restricted space rotates (section 3.4).

/// Whether a restricted space rotates after a change, by keys.md's rules
/// applied to its membership before its parent narrows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rotation {
    /// It loses these devices, ascending: a removal in F, a revocation in
    /// the list of a person F grants, or a loss in a space F grants.
    Loses(Vec<[u8; 32]>),
    /// It lowers these devices from `write` or above to `read`, ascending.
    Lowers(Vec<[u8; 32]>),
    /// Nothing it reaches is lost or lowered; a change of P alone never
    /// rotates F, since P's next key already denies a removed device F's
    /// next key.
    KeepsItsKey,
}

/// [`Rotation`] from F's own membership before and after a change
/// ([`own_membership`]).
pub fn rotation(before: &BTreeMap<[u8; 32], Reach>, after: &BTreeMap<[u8; 32], Reach>) -> Rotation {
    let lost: Vec<[u8; 32]> = before
        .keys()
        .filter(|d| !after.contains_key(*d))
        .copied()
        .collect();
    if !lost.is_empty() {
        return Rotation::Loses(lost);
    }
    let lowered: Vec<[u8; 32]> = before
        .iter()
        .filter(|(d, old)| {
            old.level >= Level::Write && after.get(*d).is_some_and(|new| new.level < Level::Write)
        })
        .map(|(d, _)| *d)
        .collect();
    if lowered.is_empty() {
        Rotation::KeepsItsKey
    } else {
        Rotation::Lowers(lowered)
    }
}

// ---------------------------------------------------------------------------
// Carve-outs (sections 3.5 and 3.6).

/// The level each member of P has in a carve-out through the carve-out's
/// grant of P at `grant_level`: the lower of that level, its level in P
/// over the paths that propagate, and `write`. A guest of P, which does not
/// propagate there, gains nothing. Administering the carve-out comes only
/// from its own grants.
pub fn carve_out_levels(
    parent_members: &BTreeMap<[u8; 32], Reach>,
    grant_level: Level,
) -> BTreeMap<[u8; 32], Level> {
    parent_members
        .iter()
        .filter_map(|(device, reach)| {
            reach
                .propagating_level
                .map(|there| (*device, grant_level.min(there).min(Level::Write)))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Mirrors of the parent's changes (sections 3.3 and 3.6).

/// A candidate to mirror an event of P: its device ID, its position by
/// rank, and its delay in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// The device's device ID.
    pub device: [u8; 32],
    /// Its position among the candidates, from 0.
    pub position: u64,
    /// Its rank delay, `min(position, rotation_rank_cap) × rotation_step`.
    pub delay: u64,
}

/// The candidates that mirror a valid roster event of P in a restricted
/// space or a carve-out `space`, by keys.md's rank with P's event ID as the
/// trigger: the space's administrator devices that reach P. The first, once
/// its delay has passed, removes the member P removed (for F), or grants or
/// removes the administrator P granted or ended (for a carve-out), with
/// P's event in the refs.
pub fn mirror_candidates(
    space: &EventId,
    trigger: &EventId,
    administrators: &[[u8; 32]],
    rotation_step: u64,
) -> Vec<Candidate> {
    ranked(space, trigger, administrators, rotation_step)
}

/// Devices in keys.md's rank order in `space` for `trigger`, each with its
/// position and delay ("The rank and the delay").
pub fn ranked(
    space: &EventId,
    trigger: &EventId,
    devices: &[[u8; 32]],
    rotation_step: u64,
) -> Vec<Candidate> {
    rank_order(space.as_bytes(), trigger.as_bytes(), devices)
        .into_iter()
        .zip(0u64..)
        .map(|(device, position)| Candidate {
            device,
            position,
            delay: delay(position, rotation_step),
        })
        .collect()
}

/// Whether a candidate drops its mirror of `trigger`, an event of P: it
/// holds a valid roster event of the space whose refs name it.
pub fn mirror_landed<'r>(
    valid_roster_refs: impl IntoIterator<Item = &'r [Ref]>,
    trigger: &Ref,
) -> bool {
    valid_roster_refs
        .into_iter()
        .any(|refs| refs.contains(trigger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn reach(level: Level, propagates: bool) -> Reach {
        Reach {
            level,
            propagates,
            propagating_level: propagates.then_some(level),
            extends: BTreeSet::new(),
            narrows: BTreeSet::new(),
            depth: 1,
            propagating_narrows: BTreeSet::new(),
            propagating_depth: if propagates { 1 } else { 0 },
        }
    }

    #[test]
    fn the_parent_decides_first() {
        let restricted = Descriptor {
            kind: DescriptorKind::Restricted,
            parent: Some([1; 32]),
            application: None,
        };
        assert_eq!(parent_verdict(&Descriptor::ORDINARY, |_| None), None);
        assert_eq!(
            parent_verdict(&restricted, |_| None),
            Some(ErrorClass::Pending.into())
        );
        assert_eq!(
            parent_verdict(&restricted, |_| Some(DescriptorKind::Restricted)),
            Some(RestrictedClass::RestrictedParent.into())
        );
        assert_eq!(
            parent_verdict(&restricted, |_| Some(DescriptorKind::CarveOut)),
            None
        );
    }

    #[test]
    fn narrowing_keeps_the_lower_level_and_both_propagations() {
        let own = BTreeMap::from([
            ([1; 32], reach(Level::Administer, true)),
            ([2; 32], reach(Level::Write, true)),
            ([3; 32], reach(Level::Write, true)),
        ]);
        let parent = BTreeMap::from([
            ([1; 32], reach(Level::Read, true)),
            ([2; 32], reach(Level::Write, false)),
        ]);
        let narrowed = narrow(own, &parent);
        assert_eq!(narrowed.len(), 2);
        assert_eq!(narrowed[&[1; 32]].level, Level::Read);
        assert!(!narrowed[&[2; 32]].propagates);
    }

    #[test]
    fn a_lowering_to_read_rotates() {
        let before = BTreeMap::from([([1; 32], reach(Level::Write, true))]);
        let after = BTreeMap::from([([1; 32], reach(Level::Read, true))]);
        assert_eq!(rotation(&before, &after), Rotation::Lowers(vec![[1; 32]]));
        assert_eq!(rotation(&before, &before), Rotation::KeepsItsKey);
        assert_eq!(
            rotation(&before, &BTreeMap::new()),
            Rotation::Loses(vec![[1; 32]])
        );
    }
}
