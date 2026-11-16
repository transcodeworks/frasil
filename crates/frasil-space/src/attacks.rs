//! Attacks (roster.md, "Attacks").
//!
//! An event is **self-lowering** ([`self_lowering`]) when each of its
//! changes names its author's own device member and removes it or lowers
//! only its level below `administer`. It is never attacked, and survives
//! its author's chain penalty.
//!
//! Roster event `x`, if valid, **attacks** roster event `e` when `x` and `e`
//! are concurrent, `e` is not self-lowering, and:
//!
//! - **(a)** `x` removes `e`'s author's member (`RemovedConcurrently`);
//! - **(b)** `x` demotes `e`'s author's device member below `administer`
//!   (`DemotedConcurrently`);
//! - **(c)** `x` removes a member that `e` grants or changes
//!   (`TargetRemovedConcurrently`);
//! - **(d)** reserved for ext-invite-links.md, whose successors a core
//!   implementation holds; with that extension it never holds, and a
//!   successor's author member is its invite key.
//!
//! The relation reads only the two events and their concurrency, never the
//! roster, so every replica computes it alike.
//!
//! An attack **counts** unless a duel drops it. `x` and `e` **lower each
//! other** ([`lower_each_other`]) when each attacks the other through (a)
//! or (b) and their authors differ. Under duel policy 0:
//!
//! - **Mutual pairs** ([`mutual`]): two events that lower each other with
//!   one change each. The attack of `x` on `e` counts exactly when `x`'s
//!   author outranks `e`'s author, each at its own event's place: the
//!   higher rank, then the more senior. That reads the roster, so the
//!   resolution applies it ([`crate::resolution`]), once both pasts are
//!   decided.
//! - **A lone change is spared by an event of several** ([`spared`]): when
//!   `e` has one change and its partner more, the partner's attack on `e`
//!   does not count; the event of several falls to its partner.
//! - **Neither undoes its partner's authority** ([`Shields`]): no attack of
//!   `e` through (a), (b) or (c) counts against an event of `x`'s
//!   **support** ([`support`]) that `x`'s author did not sign.
//!
//! The last two rules read only the contested events and their causal
//! order, never a status, so they depend on no outcome.

pub use crate::state::self_lowering;

use crate::change::{Change, Op};
use crate::member::{Level, MemberRef};
use crate::{RosterClass, SpaceClass};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use std::collections::BTreeSet;

/// A roster event as the attack relation reads it: its author and its
/// changes.
#[derive(Debug, Clone, Copy)]
pub struct Side<'a> {
    /// The author's device ID.
    pub author: &'a DeviceId,
    /// Its changes.
    pub changes: &'a [Change],
}

impl Side<'_> {
    /// The member whose authority the event uses: its author's device
    /// member; with ext-invite-links.md, a successor's invite key.
    pub(crate) fn author_member(&self) -> MemberRef {
        author_member(self.author, self.changes)
    }
}

/// The member whose authority a roster event by `author` with these
/// changes uses: the author's device member; with ext-invite-links.md, for
/// a successor, the invite key that signs it.
pub(crate) fn author_member(author: &DeviceId, changes: &[Change]) -> MemberRef {
    crate::ext::successor_author(&author.0, changes).unwrap_or(MemberRef::device(*author))
}

/// Whether a change grants or changes its member, for attack (c): a grant
/// or a change; with ext-invite-links.md, also a successor, which grants its
/// claimant.
fn targets(change: &Change) -> bool {
    matches!(change.op, Op::Grant | Op::Change) || crate::ext::is_succeed(change)
}

/// Whether `x`, if valid, attacks `e`, and with which class. `concurrent`
/// says whether the two events are concurrent.
pub fn attack(x: Side<'_>, e: Side<'_>, concurrent: bool) -> Option<RosterClass> {
    if !concurrent || self_lowering(&e.author.0, e.changes) {
        return None;
    }
    let author = Some(e.author_member());
    for change in x.changes.iter().filter(|c| c.member == author) {
        // (a)
        if change.op == Op::Remove {
            return Some(SpaceClass::RemovedConcurrently.into());
        }
        // (b)
        if change.op == Op::Change && change.level.is_some_and(|l| l < Level::Administer) {
            return Some(SpaceClass::DemotedConcurrently.into());
        }
    }
    // (c)
    let removed: Vec<MemberRef> = x
        .changes
        .iter()
        .filter(|c| c.op == Op::Remove)
        .filter_map(|c| c.member)
        .collect();
    let mut targets = e
        .changes
        .iter()
        .filter(|c| targets(c))
        .filter_map(|c| c.member);
    if targets.any(|m| removed.contains(&m)) {
        return Some(SpaceClass::TargetRemovedConcurrently.into());
    }
    None
}

/// Whether an attack is (a) or (b): one that lowers the attacked event's
/// author.
fn lowers_author(class: Option<RosterClass>) -> bool {
    class.is_some_and(|class| {
        class == SpaceClass::RemovedConcurrently.into()
            || class == SpaceClass::DemotedConcurrently.into()
    })
}

/// Whether `x` and `e` **lower each other**: their authors differ, and each
/// attacks the other through (a) or (b). Neither may be self-lowering, as
/// [`attack`] already requires of the event attacked.
pub fn lower_each_other(x: Side<'_>, e: Side<'_>, concurrent: bool) -> bool {
    x.author != e.author
        && lowers_author(attack(x, e, concurrent))
        && lowers_author(attack(e, x, concurrent))
}

/// Whether `x` and `e` are a **mutual pair**: they lower each other with one
/// change each. Only the outranking author's lowering counts.
pub fn mutual(x: Side<'_>, e: Side<'_>, concurrent: bool) -> bool {
    x.changes.len() == 1 && e.changes.len() == 1 && lower_each_other(x, e, concurrent)
}

/// Whether `x`'s attack on `e` does not count because `e` is spared by its
/// partner: they lower each other, and `e` has one change.
pub fn spared(x: Side<'_>, e: Side<'_>, concurrent: bool) -> bool {
    e.changes.len() == 1 && lower_each_other(x, e, concurrent)
}

/// The **support** of `x` among `contested`: the events in its past that
/// grant or change its author's member, with the support of each of them.
/// `precedes(a, b)` says whether `a` is in `b`'s past.
pub fn support<'a>(
    x: EventId,
    contested: &[EventId],
    precedes: impl Fn(EventId, EventId) -> bool,
    side: impl Fn(EventId) -> Side<'a>,
) -> BTreeSet<EventId> {
    let mut out = BTreeSet::new();
    let mut todo = vec![x];
    while let Some(s) = todo.pop() {
        let member = side(s).author_member();
        for &p in contested {
            if !out.contains(&p)
                && precedes(p, s)
                && side(p)
                    .changes
                    .iter()
                    .any(|c| targets(c) && c.member == Some(member))
            {
                out.insert(p);
                todo.push(p);
            }
        }
    }
    out
}

/// The attacks no duel lets undo a partner's authority: `(e, g)` for each
/// event `g` of the support of an event `x` that lowers each other with
/// `e`, where `x`'s author did not sign `g`. They are dropped through (a),
/// (b) and (c) ([`Shields::drops`]).
#[derive(Debug, Clone, Default)]
pub struct Shields(BTreeSet<(EventId, EventId)>);

impl Shields {
    /// The shields among the contested events. `concurrent(a, b)` says
    /// whether two events are concurrent, `precedes(a, b)` whether `a` is
    /// in `b`'s past.
    pub fn new<'a>(
        contested: &[EventId],
        concurrent: impl Fn(EventId, EventId) -> bool,
        precedes: impl Fn(EventId, EventId) -> bool,
        side: impl Fn(EventId) -> Side<'a> + Copy,
    ) -> Self {
        let mut out = BTreeSet::new();
        for &x in contested {
            let partners: Vec<EventId> = contested
                .iter()
                .copied()
                .filter(|&e| lower_each_other(side(x), side(e), concurrent(x, e)))
                .collect();
            if partners.is_empty() {
                continue;
            }
            let author = side(x).author;
            for g in support(x, contested, &precedes, side) {
                if side(g).author != author {
                    out.extend(partners.iter().map(|&e| (e, g)));
                }
            }
        }
        Self(out)
    }

    /// Whether the attack of `attacker` on `event`, of class `class`, is
    /// dropped: it is through (a), (b) or (c), and `event` is in the support
    /// of a partner of `attacker` that did not sign it.
    pub fn drops(&self, attacker: EventId, event: EventId, class: RosterClass) -> bool {
        let shieldable = [
            RosterClass::from(SpaceClass::RemovedConcurrently),
            SpaceClass::DemotedConcurrently.into(),
            SpaceClass::TargetRemovedConcurrently.into(),
        ];
        shieldable.contains(&class) && self.0.contains(&(attacker, event))
    }
}

/// Whether the attack of `x` on `e`, of class `class`, counts (section
/// 3.5.2), for a pair that is not mutual: `e` is not spared by its
/// partner, and no shield drops it. A mutual pair's attack counts by rank
/// and seniority, which the resolution reads at the events' places.
pub fn counts(
    (x, x_side): (EventId, Side<'_>),
    (e, e_side): (EventId, Side<'_>),
    concurrent: bool,
    class: RosterClass,
    shields: &Shields,
) -> bool {
    !spared(x_side, e_side, concurrent) && !shields.drops(x, e, class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn side<'a>(author: &'a DeviceId, changes: &'a [Change]) -> Side<'a> {
        Side { author, changes }
    }

    #[test]
    fn removals_and_demotions_of_each_other_are_a_mutual_pair() {
        let (p, q) = (DeviceId([1; 32]), DeviceId([2; 32]));
        let p_removes_q = [Change::remove(MemberRef::device(q))];
        let q_demotes_p = [Change::set_level(MemberRef::device(p), Level::Write)];
        let (x, e) = (side(&p, &p_removes_q), side(&q, &q_demotes_p));
        assert_eq!(
            attack(x, e, true),
            Some(SpaceClass::RemovedConcurrently.into())
        );
        assert_eq!(
            attack(e, x, true),
            Some(SpaceClass::DemotedConcurrently.into())
        );
        assert!(mutual(x, e, true));
        assert!(!mutual(x, e, false));
        assert_eq!(attack(x, e, false), None);
    }

    #[test]
    fn a_batch_is_never_spared_by_its_partner() {
        let (p, q, n) = (DeviceId([1; 32]), DeviceId([2; 32]), DeviceId([3; 32]));
        let p_removes_q = [Change::remove(MemberRef::device(q))];
        let q_removes_p_and_n = [
            Change::remove(MemberRef::device(p)),
            Change::remove(MemberRef::device(n)),
        ];
        let (x, e) = (side(&p, &p_removes_q), side(&q, &q_removes_p_and_n));
        assert!(lower_each_other(x, e, true));
        assert!(!mutual(x, e, true));
        assert!(!spared(x, e, true), "the batch falls to its partner");
        assert!(spared(e, x, true), "the single removal is spared");
    }

    /// F raises P (`g`), P removes Q (`x`), and Q, concurrently with both,
    /// removes P (`e`): `e`'s attack (c) on the raise does not count. P's
    /// own concurrent raise of A (`a`) stays attacked.
    #[test]
    fn a_duel_does_not_undo_its_partners_authority() {
        let (f, p, q, a) = (
            DeviceId([1; 32]),
            DeviceId([2; 32]),
            DeviceId([3; 32]),
            DeviceId([4; 32]),
        );
        let ids = [EventId([10; 32]), EventId([11; 32]), EventId([12; 32])];
        let [g, x, e] = ids;
        let pa = EventId([13; 32]);
        let raise_p = [Change::set_level(MemberRef::device(p), Level::Administer)];
        let remove_q = [Change::remove(MemberRef::device(q))];
        let remove_p = [Change::remove(MemberRef::device(p))];
        let raise_a = [Change::set_level(MemberRef::device(a), Level::Administer)];
        let side_of = |id: EventId| match id {
            _ if id == g => side(&f, &raise_p),
            _ if id == x => side(&p, &remove_q),
            _ if id == e => side(&q, &remove_p),
            _ => side(&p, &raise_a),
        };
        // g precedes x and pa; e is concurrent with all three.
        let precedes = |a: EventId, b: EventId| a == g && (b == x || b == pa);
        let concurrent = |a: EventId, b: EventId| a != b && !precedes(a, b) && !precedes(b, a);
        let contested = [g, x, e, pa];
        assert_eq!(
            support(x, &contested, precedes, side_of),
            BTreeSet::from([g])
        );
        let shields = Shields::new(&contested, concurrent, precedes, side_of);
        let c = SpaceClass::TargetRemovedConcurrently.into();
        assert!(shields.drops(e, g, c));
        assert!(!counts((e, side_of(e)), (g, side_of(g)), true, c, &shields));
        let removed = SpaceClass::RemovedConcurrently.into();
        assert!(counts(
            (e, side_of(e)),
            (pa, side_of(pa)),
            true,
            removed,
            &shields
        ));
        assert!(!counts(
            (e, side_of(e)),
            (x, side_of(x)),
            true,
            removed,
            &shields
        ));
    }

    #[test]
    fn a_self_lowering_event_is_never_attacked() {
        let (p, q) = (DeviceId([1; 32]), DeviceId([2; 32]));
        let p_removes_q = [Change::remove(MemberRef::device(q))];
        let q_leaves = [Change::remove(MemberRef::device(q))];
        let (x, e) = (side(&p, &p_removes_q), side(&q, &q_leaves));
        assert_eq!(attack(x, e, true), None);
        assert!(!mutual(x, e, true));
    }

    #[test]
    fn a_removal_beats_a_grant_or_change_of_its_target() {
        let (p, q, h) = (DeviceId([1; 32]), DeviceId([2; 32]), DeviceId([3; 32]));
        let removes = [Change::remove(MemberRef::device(h))];
        let promotes = [Change::set_level(MemberRef::device(h), Level::Administer)];
        assert_eq!(
            attack(side(&p, &removes), side(&q, &promotes), true),
            Some(SpaceClass::TargetRemovedConcurrently.into())
        );
        assert_eq!(attack(side(&q, &promotes), side(&p, &removes), true), None);
    }
}
