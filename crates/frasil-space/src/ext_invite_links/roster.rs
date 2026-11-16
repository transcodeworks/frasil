//! Invites in the roster and raced claims (ext-invite-links.md, "Invites in
//! the roster" and "Raced claims").
//!
//! **Member state.** `K` is out at any place that holds a valid successor
//! it signed. A valid successor is a grant of its claimant: it gives the
//! invite's state at the successor's place (level, capabilities, label,
//! history, session), `via` 1, a device claimant's keys, and the
//! successor's seniority.
//!
//! **Authority.** A grant of `[3, K]` is also `InviteUsed` when an event of
//! its place names `[3, K]` or `K` signed a successor there. A removal of
//! `[3, K]` is also allowed when `K` is out only by valid successors: the
//! **close**. In a checkpoint's world ("Across a checkpoint") the checkpoint
//! counts as a successor of every key its record shows not open, and as the
//! valid successor that put out a key it shows claimed. For a successor `e` by `K`, with `S` the roster at its place,
//! these replace roster.md's steps 1 to 3:
//!
//! ```text
//! 1. No successor signed by K, valid or void, is in e's past.            else InviteUsed
//! 2. [3, K] is in S.                                                     else NotAnInvite
//! 3. The claimant's type is the invite's claims.                         else ClaimMismatch
//! 4. The claimant is not in S.                                           else AlreadyMember
//! ```
//!
//! then `Full`, `StaleSeal`, the race rule's `ClaimRaced`, and keys.md's
//! checks against the event and its place.
//!
//! **Raced claims.** A successor of `K` races every other successor of `K`
//! concurrent with it that passes roster.md's "The event alone", valid or
//! void. A close is any valid removal of `[3, K]`. A racing successor is
//! void (`ClaimRaced`) unless every successor it races is concurrent with a
//! valid close of its key. Resolution runs:
//!
//! ```text
//! forced = {}
//! repeat:
//!   resolve, with each successor in forced failing its authority as ClaimRaced
//!   more = the valid successors that race a successor concurrent
//!          with no valid close of their key
//!   if more ⊆ forced: stop
//!   forced = forced ∪ more
//! ```

use super::InviteClass;
use super::change::{CLAIMS_DEVICE, CLAIMS_PERSON, invite_member};
use crate::change::{Change, Op};
use crate::member::{MemberRef, MemberType, Via};
use crate::resolution::Judge;
use crate::space::Space;
use crate::state::{
    MemberState, Places, Roster, RosterEvents, Seniority, Standing, seniority_hash,
};
use crate::{RosterClass, SpaceClass};
use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_resolve::Resolution;
use std::collections::{BTreeMap, BTreeSet};

/// Whether a roster event's changes make it a successor: its change is op 4.
pub fn is_successor(changes: &[Change]) -> bool {
    crate::ext::is_successor(changes)
}

/// A successor's claimant: the member its op-4 change names.
pub fn claimant(changes: &[Change]) -> Option<MemberRef> {
    changes
        .iter()
        .find(|c| c.op == Op::Succeed)
        .and_then(|c| c.member)
}

/// The invite grant of `K` among a member's grants in force, the first in
/// canonical order, as `(event, change)`.
pub fn invite_grant_of<'c, E: RosterEvents>(
    events: &'c E,
    grants: &BTreeSet<EventId>,
    key: &[u8; 32],
) -> Option<(EventId, &'c Change)> {
    let member = invite_member(*key);
    let mut ordered: Vec<EventId> = grants.iter().copied().collect();
    ordered.sort_unstable_by_key(|&g| (events.height(g), g));
    ordered.into_iter().find_map(|g| {
        events
            .changes(g)
            .iter()
            .find(|c| c.op == Op::Grant && c.member == Some(member))
            .map(|c| (g, c))
    })
}

/// "Member state": each invite key with a valid successor at `place` is out,
/// removed by the first such successor in canonical order, unless already
/// out.
pub(crate) fn put_out_invites<E: RosterEvents>(
    events: &E,
    place: &BTreeSet<EventId>,
    members: &mut BTreeMap<MemberRef, Standing>,
) {
    let mut ordered: Vec<EventId> = place.iter().copied().collect();
    ordered.sort_unstable_by_key(|&e| (events.height(e), e));
    for event in ordered {
        if !is_successor(events.changes(event)) {
            continue;
        }
        let key = invite_member(events.author(event));
        if !matches!(members.get(&key), Some(Standing::Out { .. })) {
            members.insert(
                key,
                Standing::Out {
                    removed_by: vec![event],
                },
            );
        }
    }
}

/// "Member state": the state a valid successor gives its claimant at a
/// place: the invite's state at the successor's place, `via` 1, a device
/// claimant's keys, and the successor's seniority. `None` if the invite key
/// is not in there.
pub(crate) fn successor_state<E: RosterEvents>(
    places: &Places<'_, E>,
    member: MemberRef,
    event: EventId,
    change: &Change,
    place: &BTreeSet<EventId>,
) -> Option<MemberState> {
    let events = places.events();
    let at = places.roster(&places.place_of(event, place));
    let invite = at.state(&invite_member(events.author(event)))?;
    let height = events.height(event);
    Some(MemberState {
        level: invite.level,
        capabilities: invite.capabilities.clone(),
        label: invite.label.clone(),
        history: invite.history,
        via: Via::Link,
        session: invite.session,
        replaces: None,
        grants: BTreeSet::from([event]),
        seniority: Seniority {
            epoch: events.epoch(),
            height,
            hash: seniority_hash(&events.space(), &member.id),
            grant: event,
        },
        keys: if member.kind == MemberType::Device {
            change.keys.clone()
        } else {
            None
        },
        source: (height, event),
        expires_at: invite.session.and(invite.expires_at),
        rank: None,
    })
}

/// Whether an event of `place` names `[3, K]`, or `K` signed a successor
/// there.
fn invite_named(judge: &Judge<'_>, key: &[u8; 32], place: &BTreeSet<EventId>) -> bool {
    let member = invite_member(*key);
    place.iter().any(|&p| {
        let changes = judge.changes(p);
        changes.iter().any(|c| c.member == Some(member))
            || (is_successor(changes) && judge.author(p).0 == *key)
    })
}

/// "Authority": a change of an invite key at an administrator's event, in
/// place of roster.md's step 2 for it. A grant: not named at the place
/// (`InviteUsed`), not in (`AlreadyMember`). A removal: the key in, or out
/// only by valid successors (the close); else `NoSuchMember`. `None` for a
/// change of any other member.
pub(crate) fn invite_change_authority(
    judge: &Judge<'_>,
    change: &Change,
    roster: &Roster,
    place: &BTreeSet<EventId>,
) -> Option<Result<(), RosterClass>> {
    let member = change.member.filter(|m| m.kind == MemberType::Invite)?;
    Some(match change.op {
        Op::Grant if invite_named(judge, &member.id, place) => Err(InviteClass::InviteUsed.into()),
        Op::Grant if roster.is_in(&member) => Err(SpaceClass::AlreadyMember.into()),
        Op::Grant => Ok(()),
        Op::Remove => match roster.standing(&member) {
            Some(Standing::In(_)) => Ok(()),
            Some(Standing::Out { removed_by })
                if !removed_by.is_empty()
                    && removed_by.iter().all(|&r| {
                        is_successor(judge.changes(r))
                            || judge.world.is_some_and(|world| world.root == r)
                    }) =>
            {
                Ok(())
            }
            _ => Err(SpaceClass::NoSuchMember.into()),
        },
        _ => return None,
    })
}

/// "Authority" for a successor at its place, in place of roster.md's steps
/// 1 to 3, then `Full`, `StaleSeal`, the race rule and keys.md's checks
/// against the event and its place. `None` for any other event.
pub(crate) fn successor_authority(
    judge: &Judge<'_>,
    event: EventId,
    place: &BTreeSet<EventId>,
) -> Option<Result<(), RosterClass>> {
    let changes = judge.changes(event);
    if !is_successor(changes) {
        return None;
    }
    Some(authority(judge, event, changes, place))
}

/// "Authority", step 1: a successor signed by the same invite key, valid
/// or void, is in the successor's past.
fn used(judge: &Judge<'_>, event: EventId) -> bool {
    let key = judge.author(event).0;
    // In a checkpoint's world the checkpoint counts as a successor of
    // every invite key whose recorded status is not open
    // ("Across a checkpoint").
    if judge.world.is_some_and(|world| world.used.contains(&key)) {
        return true;
    }
    judge.screened.events().iter().any(|&p| {
        judge.author(p).0 == key && is_successor(judge.changes(p)) && judge.precedes_fast(p, event)
    })
}

/// "Standing": the class of a successor no grant of whose invite key is in
/// its past, void before the procedure: `InviteUsed` when it fails step 1,
/// otherwise `NotAnInvite`, since `[3, K]` is in no roster at its place.
pub(crate) fn without_standing(judge: &Judge<'_>, event: EventId) -> RosterClass {
    if used(judge, event) {
        InviteClass::InviteUsed.into()
    } else {
        InviteClass::NotAnInvite.into()
    }
}

fn authority(
    judge: &Judge<'_>,
    event: EventId,
    changes: &[Change],
    place: &BTreeSet<EventId>,
) -> Result<(), RosterClass> {
    let key = judge.author(event).0;
    let roster = judge.places.roster(place);
    // 1.
    if used(judge, event) {
        return Err(InviteClass::InviteUsed.into());
    }
    // 2.
    let Some(invite) = roster.state(&invite_member(key)) else {
        return Err(InviteClass::NotAnInvite.into());
    };
    // 3.
    let claimant = claimant(changes).ok_or_else(|| RosterClass::from(ErrorClass::Malformed))?;
    let claims = invite_grant_of(judge.places.events(), &invite.grants, &key)
        .and_then(|(_, grant)| grant.claims);
    let matches = match claims {
        Some(CLAIMS_DEVICE) => claimant.kind == MemberType::Device,
        Some(CLAIMS_PERSON) => claimant.kind == MemberType::Person,
        _ => false,
    };
    if !matches {
        return Err(InviteClass::ClaimMismatch.into());
    }
    // 4.
    if roster.is_in(&claimant) {
        return Err(SpaceClass::AlreadyMember.into());
    }
    if place.len() + 1 > judge.limits.max_roster_events {
        return Err(ErrorClass::Full.into());
    }
    if judge.stale(event, place) {
        return Err(frasil_keys::KeyClass::StaleSeal.into());
    }
    if judge.forced.contains(&event) {
        return Err(InviteClass::ClaimRaced.into());
    }
    judge.place_checks(event, place, &roster)
}

/// "Raced claims": the resolution of the offered roster events with the
/// race rule's forced successors, and those successors.
pub(crate) fn resolve_racing(
    space: &Space<'_>,
    offered: &[EventId],
) -> (Resolution<EventId, RosterClass>, BTreeSet<EventId>) {
    let log = space.log();
    let author = |e: EventId| log.event(e).map(|ev| ev.author().0).unwrap_or_default();
    let changes = |e: EventId| space.opened(e).map_or(&[][..], |o| o.changes());
    let mut forced: BTreeSet<EventId> = BTreeSet::new();
    loop {
        let resolution = space.with_judge_forcing(&forced, |judge| {
            frasil_resolve::resolve(judge, offered.iter().copied())
        });
        let contested = resolution.contested();
        // Every offered successor races, valid or void, contested or void
        // for want of standing ("Raced claims").
        let successors: Vec<EventId> = offered
            .iter()
            .copied()
            .filter(|&e| is_successor(changes(e)))
            .collect();
        let mut more = BTreeSet::new();
        for &i in &successors {
            if !resolution.is_valid(i) {
                continue;
            }
            let key = author(i);
            let racing: Vec<EventId> = successors
                .iter()
                .copied()
                .filter(|&j| j != i && author(j) == key && log.concurrent(i, j))
                .collect();
            if racing.is_empty() {
                continue;
            }
            let closes: Vec<EventId> = contested
                .iter()
                .copied()
                .filter(|&x| {
                    resolution.is_valid(x)
                        && changes(x)
                            .iter()
                            .any(|c| c.op == Op::Remove && c.member == Some(invite_member(key)))
                })
                .collect();
            let shielded = racing
                .iter()
                .all(|&j| closes.iter().any(|&x| log.concurrent(j, x)));
            if !shielded {
                more.insert(i);
            }
        }
        if more.is_subset(&forced) {
            return (resolution, forced);
        }
        forced.extend(more);
    }
}

/// The events that void a successor void as `ClaimRaced`: the successors of
/// its key concurrent with it, in canonical order. `None` for any other
/// class.
pub(crate) fn racers(
    space: &Space<'_>,
    event: EventId,
    class: RosterClass,
) -> Option<Vec<EventId>> {
    if class != InviteClass::ClaimRaced.into() {
        return None;
    }
    let log = space.log();
    let key = *log.event(event)?.author();
    let racing: BTreeSet<EventId> = space
        .view()
        .iter()
        .copied()
        .filter(|&j| {
            j != event
                && log.event(j).is_some_and(|e| *e.author() == key)
                && space.opened(j).is_some_and(|o| is_successor(o.changes()))
                && log.concurrent(event, j)
        })
        .collect();
    Some(log.canonical_in(&racing))
}
