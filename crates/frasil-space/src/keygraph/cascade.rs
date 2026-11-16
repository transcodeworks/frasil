//! Cascades (keys.md, "Cascades"): which spaces rotate after a change, and
//! who rotates.
//!
//! A **change** to space C is a roster event of C, a device list's
//! revocation of a device C reaches through a person, or a cascaded
//! rotation of C. After it, every other space X is compared before and
//! after, by its effective membership:
//!
//! - **X loses a device:** X rotates, with a grant rotation, which
//!   cascades in turn.
//! - **X loses nothing:** X keeps its key. (A member's level in X that
//!   drops to `read` through C loses no device: X keeps its key, and the
//!   write rule refuses the device's units.)
//! - **C admitted a member that propagates, "from now on":** every space C
//!   reaches through grants, transitively, breaks.
//! - **C healed its grant key:** every space C reaches through grants,
//!   transitively, rotates.
//! - **A guest leaves C:** C rotates its content key only, and nothing C
//!   reaches rotates, since a guest reaches no other space.

use crate::SpaceClass;
use crate::graph::{GrantTarget, SpaceGrants, Verdicts, edge_verdicts, effective};
use crate::member::Level;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};

/// What kind of change C made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeKind {
    /// A roster event or a device list's revocation that may lose devices.
    Removal,
    /// An admission "from now on" of a member that propagates.
    Break,
    /// A heal of C's grant key.
    GrantHeal,
}

/// A space's verdict after a change.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Cascade {
    /// It rotates, with a grant rotation; after a removal, the devices it
    /// loses, by device ID, ascending.
    Rotates(Vec<[u8; 32]>),
    /// It loses nothing and keeps its key.
    KeepsItsKey,
    /// It breaks: C admitted a member "from now on" and reaches it.
    Breaks,
    /// C's break or grant heal does not reach it.
    NotReached,
}

/// The spaces whose grants reach `changed`, transitively, through edges
/// that count: nearest first, each once.
pub fn reached_by(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    verdicts: &Verdicts,
    changed: EventId,
) -> Vec<EventId> {
    let mut out: Vec<EventId> = Vec::new();
    let mut frontier = vec![changed];
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for &x in &frontier {
            for (&s, space) in spaces {
                let grants_x = space.grants.iter().any(|g| {
                    g.target == GrantTarget::Space(x)
                        && verdicts
                            .iter()
                            .any(|(e, v)| e.event == g.event && e.from == s && v.is_ok())
                });
                if grants_x && s != changed && !out.contains(&s) {
                    out.push(s);
                    next.push(s);
                }
            }
        }
        frontier = next;
    }
    out
}

/// The devices of each space whose effective membership reaches it,
/// before or after a change.
fn members(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
) -> Result<BTreeSet<[u8; 32]>, SpaceClass> {
    let verdicts = edge_verdicts(spaces);
    #[cfg(feature = "ext-restricted-spaces")]
    if spaces
        .get(&space)
        .is_some_and(|s| s.kind == crate::DescriptorKind::Restricted)
    {
        // ext-restricted-spaces.md, "Keys of a restricted space": by its
        // membership before its parent's narrows it.
        return Ok(crate::ext_restricted_spaces::own_membership(
            spaces, persons, space, &verdicts,
        )?
        .into_keys()
        .collect());
    }
    Ok(effective(spaces, persons, space, &verdicts)?
        .into_keys()
        .collect())
}

/// Each space's verdict after a change to `changed` (`None` for a device
/// list's revocation, which is no space), from the spaces' grants and the
/// persons' lists before and after it.
///
/// # Errors
///
/// [`effective`]'s classes.
pub fn cascade(
    before: &BTreeMap<EventId, SpaceGrants>,
    after: &BTreeMap<EventId, SpaceGrants>,
    persons_before: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    persons_after: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    changed: Option<EventId>,
    change: ChangeKind,
) -> Result<BTreeMap<EventId, Cascade>, SpaceClass> {
    let mut out = BTreeMap::new();
    let reached = match (change, changed) {
        (ChangeKind::Removal, _) | (_, None) => Vec::new(),
        (_, Some(c)) => reached_by(after, &edge_verdicts(after), c),
    };
    for &space in after.keys() {
        if Some(space) == changed {
            continue;
        }
        let verdict = match change {
            ChangeKind::Break | ChangeKind::GrantHeal if !reached.contains(&space) => {
                Cascade::NotReached
            }
            ChangeKind::Break => Cascade::Breaks,
            ChangeKind::GrantHeal => Cascade::Rotates(Vec::new()),
            ChangeKind::Removal => {
                let old = members(before, persons_before, space)?;
                let new = members(after, persons_after, space)?;
                let lost: Vec<[u8; 32]> = old.difference(&new).copied().collect();
                if lost.is_empty() {
                    Cascade::KeepsItsKey
                } else {
                    Cascade::Rotates(lost)
                }
            }
        };
        out.insert(space, verdict);
    }
    Ok(out)
}

/// The candidates for X's cascaded rotation after a change in a space C
/// that X grants: X's writer devices that propagate there and are
/// propagating members of C after the change. Each waits its rank delay
/// with the change's event ID as the trigger.
///
/// # Errors
///
/// [`effective`]'s classes.
pub fn cascade_candidates(
    after: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    x: EventId,
    c: EventId,
) -> Result<Vec<[u8; 32]>, SpaceClass> {
    let verdicts = edge_verdicts(after);
    let in_x = effective(after, persons, x, &verdicts)?;
    let in_c = effective(after, persons, c, &verdicts)?;
    Ok(in_x
        .into_iter()
        .filter(|(d, r)| {
            r.propagates && r.level >= Level::Write && in_c.get(d).is_some_and(|t| t.propagates)
        })
        .map(|(d, _)| d)
        .collect())
}
