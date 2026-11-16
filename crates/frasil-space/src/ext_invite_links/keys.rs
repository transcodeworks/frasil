//! Invite keys in the key graph (ext-invite-links.md, "Keys").
//!
//! - **Receipt.** `K` is a wrap recipient while `[3, K]` is in and `K`
//!   counts as inside, under its grant's X-Wing key, with `K` as the
//!   recipient device ID. Once it counts as outside it receives no wrap,
//!   though it stays in the roster until a removal.
//! - **Inside.** `K` in force is inside. A valid successor puts it out, a
//!   valid removal with no valid successor revokes it, and a successor of
//!   `K` void as `ClaimRaced` leaves it out of the wrap recipients: in each
//!   case it counts as outside, and since it holds the state the invite
//!   delivered, a writer heals. The claimant is inside as a member of its
//!   own, wrapped for under its own keys.
//! - **Entitlement**, rule 4: the claimant of a valid successor is entitled
//!   to every state its invite key is entitled to; for the grant graph, only
//!   for an invite without `session`, which the invite key's own
//!   entitlement already says.
//!
//! The key graph reads a successor through [`EventFacts`]'s `successor`:
//! its invite key and its claimant, as the view names them.
//!
//! [`EventFacts`]: crate::keygraph::EventFacts

use super::InviteClass;
use crate::change::Change;
use crate::keygraph::graph::{KeyGraph, Member, Roster};
use crate::keygraph::{History, Kind};
use crate::member::MemberRef;
use crate::space::Space;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use std::collections::BTreeSet;

/// A successor, as the key graph reads it: the invite key that signs it
/// and the claimant it grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Succession<M> {
    /// The invite key's member, `[3, K]`.
    pub invite: M,
    /// The claimant.
    pub claimant: M,
}

/// The succession of a roster event by `author` with these changes, if it
/// is a successor.
pub(crate) fn succession(author: &[u8; 32], changes: &[Change]) -> Option<Succession<MemberRef>> {
    let claimant = super::claimant(changes).filter(|_| super::is_successor(changes))?;
    Some(Succession {
        invite: super::invite_member(*author),
        claimant,
    })
}

/// Whether a successor of a resolved space is void as `ClaimRaced`.
pub(crate) fn void_as_raced(space: &Space<'_>, successor: EventId) -> bool {
    space
        .status(successor)
        .and_then(|s| s.class())
        .is_some_and(|class| class == InviteClass::ClaimRaced.into())
}

/// The invite keys a raced claim counts as outside: those with a successor
/// of the view that is not valid and void as `ClaimRaced`, and in a
/// checkpoint's world those its record shows raced.
fn raced<H: History>(graph: &KeyGraph<'_, H>) -> BTreeSet<H::Member> {
    let recorded = graph.history().record_raced();
    graph
        .events()
        .iter()
        .filter(|e| !graph.valid().contains(e))
        .filter_map(|&e| {
            let succession = graph.history().facts(e).successor.as_ref()?;
            graph
                .history()
                .void_as_raced(e)
                .then(|| succession.invite.clone())
        })
        .chain(recorded)
        .collect()
}

/// The members that receive wraps and count towards the inside: the merged
/// roster, less the invite keys a raced claim counts as outside.
pub(crate) fn receiving<H: History>(
    graph: &KeyGraph<'_, H>,
    mut members: Roster<H::Member>,
) -> Roster<H::Member> {
    let raced = raced(graph);
    members.retain(|m, _| !matches!(m, Member::Roster(r) if raced.contains(r)));
    members
}

/// Rule 4: whether `member` is the claimant of a valid successor of
/// `valid` whose invite key is entitled to `state`.
pub(crate) fn claimant_entitled<H: History>(
    graph: &KeyGraph<'_, H>,
    valid: &BTreeSet<EventId>,
    member: &Member<H::Member>,
    state: &RotationSet,
    kind: Kind,
) -> bool {
    let Member::Roster(m) = member else {
        return false;
    };
    valid.iter().any(|&e| {
        graph
            .history()
            .facts(e)
            .successor
            .as_ref()
            .is_some_and(|s| {
                s.claimant == *m
                    && s.invite != *m
                    && graph.entitled_in(valid, &Member::Roster(s.invite.clone()), state, kind)
            })
    })
}
