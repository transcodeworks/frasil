//! Grants of spaces and effective membership (roster.md, "Grants of spaces
//! and effective membership"), as pure functions over the grants in force
//! that the caller gives for each space whose roster it holds.
//!
//! **The grant graph.** An edge `X → Y` for each grant of space Y in force
//! in the roster of X. Which edges **count**, in order:
//!
//! 1. An edge to a space whose roster is not held is `UnknownSpace`; to a
//!    restricted space, `GrantOfRestricted`; to a space whose descriptor a
//!    later document defines, `GrantOfReserved`, at every implementation;
//!    from a space to itself, `GrantCycle`. None takes part in what
//!    follows.
//! 2. **Cycles.** While some counted edges lie on a cycle, the one among
//!    them with the highest granting space ID stops counting
//!    (`GrantCycle`). Ties fall to the granted space's ID, then to the
//!    grant's event ID.
//! 3. **Depth.** The remaining edges are taken from the roots of the graph
//!    down: nearest a root first, by the longest chain of counted edges
//!    above the granting space, then by lower granting space ID. Each is
//!    kept unless the longest chain of kept edges ending at X, plus the
//!    longest starting at Y, would pass 8 spaces (`GrantTooDeep`).
//!
//! An edge that does not count delivers nothing. These verdicts refuse no
//! event.
//!
//! **Effective membership** of space X: every device that reaches X, with
//! a level, whether it propagates there, and its capabilities, through a
//! device grant, a person grant (every device the person's list vouches
//! for) or a counted space grant (every device that reaches the granted
//! space and propagates there, at the lowest of the grant's level, its
//! level there over the paths that propagate, and `write`).

use crate::member::{Capability, CapabilityMode, Level};
use crate::policy::DescriptorKind;
use crate::{SpaceClass, ext};
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};

/// The most spaces on a chain of counted grants.
pub const MAX_GRANT_DEPTH: usize = 8;

/// Whom a grant in force admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GrantTarget {
    /// A device, by its device ID.
    Device([u8; 32]),
    /// A person, by its person ID.
    Person([u8; 32]),
    /// A space, by its space ID.
    Space(EventId),
}

/// A grant in force in a space's roster, as the space's resolved roster
/// gives it: one per grant in force, with its member's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantInForce {
    /// The grant's event ID.
    pub event: EventId,
    /// Whom it admits.
    pub target: GrantTarget,
    /// The member's level.
    pub level: Level,
    /// Whether the grant carries `session`: a guest, which does not
    /// propagate.
    pub session: bool,
    /// The member's capabilities.
    pub capabilities: Vec<Capability>,
}

/// One space's grants in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceGrants {
    /// Its kind, from its descriptor.
    pub kind: DescriptorKind,
    /// Its parent, from its descriptor: present exactly for a restricted
    /// space and a carve-out.
    pub parent: Option<EventId>,
    /// Its grants in force.
    pub grants: Vec<GrantInForce>,
}

/// An edge `from → to` of the grant graph, by the grant that makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Edge {
    /// The granting space, X.
    pub from: EventId,
    /// The granted space, Y.
    pub to: EventId,
    /// The grant's event ID.
    pub event: EventId,
}

impl Edge {
    /// The order in which cycles drop edges, highest first: the granting
    /// space's ID, then the granted space's, then the grant's event ID.
    fn rank(&self) -> (EventId, EventId, EventId) {
        (self.from, self.to, self.event)
    }
}

/// Every edge's verdict: `Ok` when it counts, else `UnknownSpace`,
/// `GrantOfRestricted`, `GrantOfReserved`, `GrantCycle` or `GrantTooDeep`.
pub type Verdicts = BTreeMap<Edge, Result<(), SpaceClass>>;

/// The grant graph's rules, in the module's order, over the spaces whose
/// rosters this replica holds, by space ID.
pub fn edge_verdicts(spaces: &BTreeMap<EventId, SpaceGrants>) -> Verdicts {
    let mut verdicts = Verdicts::new();
    let mut live: Vec<Edge> = Vec::new();
    // 1.
    for (&from, space) in spaces {
        for grant in &space.grants {
            let GrantTarget::Space(to) = grant.target else {
                continue;
            };
            let edge = Edge {
                from,
                to,
                event: grant.event,
            };
            let verdict = match spaces.get(&to) {
                None => Err(SpaceClass::UnknownSpace),
                Some(target)
                    if matches!(
                        target.kind,
                        DescriptorKind::Restricted | DescriptorKind::Reserved(1)
                    ) =>
                {
                    Err(SpaceClass::GrantOfRestricted)
                }
                Some(target) if target.kind.is_reserved() => Err(SpaceClass::GrantOfReserved),
                Some(_) if to == from => Err(SpaceClass::GrantCycle),
                Some(_) => {
                    live.push(edge);
                    continue;
                }
            };
            verdicts.insert(edge, verdict);
        }
    }
    // 2.
    loop {
        // What each space reaches over the live edges, found once a round
        // for every edge that starts there.
        let mut reached: BTreeMap<EventId, BTreeSet<EventId>> = BTreeMap::new();
        let mut on_cycle: Option<Edge> = None;
        for edge in &live {
            let from_to = reached
                .entry(edge.to)
                .or_insert_with(|| reachable(&live, edge.to));
            if from_to.contains(&edge.from) && on_cycle.is_none_or(|e| edge.rank() > e.rank()) {
                on_cycle = Some(*edge);
            }
        }
        let Some(drop) = on_cycle else {
            break;
        };
        live.retain(|edge| *edge != drop);
        verdicts.insert(drop, Err(SpaceClass::GrantCycle));
    }
    // 3.
    let acyclic = live;
    let mut above = BTreeMap::new();
    let mut ordered = acyclic.clone();
    ordered.sort_by_key(|edge| (longest_above(&acyclic, edge.from, &mut above), edge.rank()));
    let mut kept: Vec<Edge> = Vec::new();
    for edge in ordered {
        let up = 1 + longest_above(&kept, edge.from, &mut BTreeMap::new());
        let down = 1 + longest_below(&kept, edge.to, &mut BTreeMap::new());
        if up + down > MAX_GRANT_DEPTH {
            verdicts.insert(edge, Err(SpaceClass::GrantTooDeep));
        } else {
            kept.push(edge);
            verdicts.insert(edge, Ok(()));
        }
    }
    verdicts
}

/// The spaces a path of edges leads to from `from`, `from` included.
fn reachable(edges: &[Edge], from: EventId) -> BTreeSet<EventId> {
    let mut next: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    for edge in edges {
        next.entry(edge.from).or_default().push(edge.to);
    }
    let mut seen = BTreeSet::new();
    let mut todo = vec![from];
    while let Some(at) = todo.pop() {
        if seen.insert(at) {
            todo.extend(next.get(&at).into_iter().flatten().copied());
        }
    }
    seen
}

/// The longest chain of edges ending at `space`, in edges. The edges are
/// acyclic.
fn longest_above(edges: &[Edge], space: EventId, memo: &mut BTreeMap<EventId, usize>) -> usize {
    if let Some(&hit) = memo.get(&space) {
        return hit;
    }
    let parents: Vec<EventId> = edges
        .iter()
        .filter(|e| e.to == space)
        .map(|e| e.from)
        .collect();
    let out = parents
        .into_iter()
        .map(|p| longest_above(edges, p, memo) + 1)
        .max()
        .unwrap_or(0);
    memo.insert(space, out);
    out
}

/// The longest chain of edges starting at `space`, in edges.
fn longest_below(edges: &[Edge], space: EventId, memo: &mut BTreeMap<EventId, usize>) -> usize {
    if let Some(&hit) = memo.get(&space) {
        return hit;
    }
    let children: Vec<EventId> = edges
        .iter()
        .filter(|e| e.from == space)
        .map(|e| e.to)
        .collect();
    let out = children
        .into_iter()
        .map(|c| longest_below(edges, c, memo) + 1)
        .max()
        .unwrap_or(0);
    memo.insert(space, out);
    out
}

/// How a device reaches a space: its effective grant there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    /// The highest level over its paths.
    pub level: Level,
    /// Whether some path propagates.
    pub propagates: bool,
    /// Its level over the paths that propagate, if any does: what a space
    /// that grants this one passes on.
    pub propagating_level: Option<Level>,
    /// The extending capabilities every path at its level carries.
    pub extends: BTreeSet<String>,
    /// The narrowing capabilities any path at its level carries.
    pub narrows: BTreeSet<String>,
    /// The fewest spaces on a path at its level, this one counted: 1 for a
    /// grant in this space's own roster.
    pub depth: usize,
    /// The narrowing capabilities any propagating path at
    /// `propagating_level` carries: with that level, what a space that
    /// grants this one passes on. A path that does not propagate adds none,
    /// even when it is the strongest.
    pub propagating_narrows: BTreeSet<String>,
    /// The fewest spaces on a propagating path at `propagating_level`; 0
    /// when none propagates.
    pub propagating_depth: usize,
}

/// One path by which a device reaches a space.
pub(crate) struct Path {
    pub(crate) level: Level,
    pub(crate) propagates: bool,
    pub(crate) extends: BTreeSet<String>,
    pub(crate) narrows: BTreeSet<String>,
    pub(crate) depth: usize,
}

fn split(capabilities: &[Capability]) -> (BTreeSet<String>, BTreeSet<String>) {
    let of = |mode| {
        capabilities
            .iter()
            .filter(|c| c.mode == mode)
            .map(|c| c.name.clone())
            .collect()
    };
    (of(CapabilityMode::Extends), of(CapabilityMode::Narrows))
}

/// Effective membership of `space`: every device that reaches it, by
/// device ID. `persons` gives the devices each person's list vouches
/// for; a person whose list is not held gives none here (the write rule
/// holds such a path as one that cannot be judged). `verdicts` are
/// [`edge_verdicts`] over the same spaces.
///
/// # Errors
///
/// `ExtensionRequired` for a restricted space, whose membership
/// ext-restricted-spaces.md narrows by its parent's, and for a space whose
/// descriptor a later document defines; `UnknownSpace` for a space not
/// given.
pub fn effective(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
    verdicts: &Verdicts,
) -> Result<BTreeMap<[u8; 32], Reach>, SpaceClass> {
    effective_within(spaces, persons, space, verdicts, &mut Vec::new())
}

fn effective_within(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
    verdicts: &Verdicts,
    stack: &mut Vec<EventId>,
) -> Result<BTreeMap<[u8; 32], Reach>, SpaceClass> {
    let grants = spaces.get(&space).ok_or(SpaceClass::UnknownSpace)?;
    if grants.kind == DescriptorKind::Restricted {
        return ext::restricted_membership(spaces, persons, space, verdicts, stack);
    }
    // A space whose descriptor a later document defines is held whole.
    if grants.kind.is_reserved() {
        return Err(frasil_base::ErrorClass::ExtensionRequired.into());
    }
    own_within(spaces, persons, space, verdicts, stack)
}

/// Effective membership of `space` by its own grants, as an ordinary
/// space's: before ext-restricted-spaces.md narrows a restricted space's by
/// its parent's.
pub(crate) fn own_within(
    spaces: &BTreeMap<EventId, SpaceGrants>,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    space: EventId,
    verdicts: &Verdicts,
    stack: &mut Vec<EventId>,
) -> Result<BTreeMap<[u8; 32], Reach>, SpaceClass> {
    let grants = spaces.get(&space).ok_or(SpaceClass::UnknownSpace)?;
    let mut paths: BTreeMap<[u8; 32], Vec<Path>> = BTreeMap::new();
    stack.push(space);
    for grant in &grants.grants {
        let (extends, narrows) = split(&grant.capabilities);
        match grant.target {
            GrantTarget::Device(device) => paths.entry(device).or_default().push(Path {
                level: grant.level,
                propagates: !grant.session,
                extends,
                narrows,
                depth: 1,
            }),
            GrantTarget::Person(person) => {
                for &device in persons.get(&person).into_iter().flatten() {
                    paths.entry(device).or_default().push(Path {
                        level: grant.level,
                        propagates: true,
                        extends: extends.clone(),
                        narrows: narrows.clone(),
                        depth: 1,
                    });
                }
            }
            GrantTarget::Space(to) => {
                let edge = Edge {
                    from: space,
                    to,
                    event: grant.event,
                };
                if verdicts.get(&edge) != Some(&Ok(())) || stack.contains(&to) {
                    continue;
                }
                let inner = effective_within(spaces, persons, to, verdicts, stack)?;
                for (device, reach) in inner {
                    // A guest of the granted space gains nothing here, and a
                    // device passes on only what its propagating paths there
                    // give (roster.md, 3.3).
                    let Some(there) = reach.propagating_level else {
                        continue;
                    };
                    // administer never flows; an extending capability comes
                    // only from this space's own grant, a narrowing one from
                    // any on the path.
                    paths.entry(device).or_default().push(Path {
                        level: grant.level.min(there).min(Level::Write),
                        propagates: true,
                        extends: extends.clone(),
                        narrows: narrows.union(&reach.propagating_narrows).cloned().collect(),
                        depth: reach.propagating_depth + 1,
                    });
                }
            }
        }
    }
    stack.pop();
    Ok(paths
        .into_iter()
        .filter_map(|(device, paths)| combine(&paths).map(|reach| (device, reach)))
        .collect())
}

/// The reach of a member over paths given as their level and the
/// capabilities their grants carry, none propagating, each at depth 1: what
/// [`combine`] makes of them. `None` for no path.
pub fn meet_of_paths(paths: &[(Level, Vec<Capability>)]) -> Option<Reach> {
    let paths: Vec<Path> = paths
        .iter()
        .map(|(level, capabilities)| {
            let (extends, narrows) = split(capabilities);
            Path {
                level: *level,
                propagates: false,
                extends,
                narrows,
                depth: 1,
            }
        })
        .collect();
    combine(&paths)
}

/// A reach's capabilities as the adapter reads them: its extending ones
/// and its narrowing ones, strictly ascending by name and then mode, so a
/// name the meet keeps in both modes appears twice.
pub fn capabilities_of(reach: &Reach) -> Vec<Capability> {
    let mut out: Vec<Capability> = reach
        .extends
        .iter()
        .map(|name| (name, CapabilityMode::Extends))
        .chain(
            reach
                .narrows
                .iter()
                .map(|name| (name, CapabilityMode::Narrows)),
        )
        .map(|(name, mode)| Capability {
            name: name.clone(),
            mode,
        })
        .collect();
    out.sort_by(|a, b| (a.name.as_bytes(), a.mode.code()).cmp(&(b.name.as_bytes(), b.mode.code())));
    out
}

/// The highest level over every path; over the paths at that level, the
/// least depth, an extending capability only if every one carries it, and a
/// narrowing one if any does. The paths that propagate are merged alike,
/// apart (roster.md, 3.3): their highest level, and over those at it the
/// narrowing capabilities of any and the least depth. Each is a maximum,
/// a minimum, an intersection or a union, so the order of `paths` changes
/// nothing.
pub(crate) fn combine(paths: &[Path]) -> Option<Reach> {
    let level = paths.iter().map(|p| p.level).max()?;
    let strongest: Vec<&Path> = paths.iter().filter(|p| p.level == level).collect();
    let extends = strongest
        .iter()
        .map(|p| p.extends.clone())
        .reduce(|a, b| a.intersection(&b).cloned().collect())
        .unwrap_or_default();
    let narrows = strongest
        .iter()
        .flat_map(|p| p.narrows.iter().cloned())
        .collect();
    let propagating_level = paths.iter().filter(|p| p.propagates).map(|p| p.level).max();
    let propagating: Vec<&Path> = paths
        .iter()
        .filter(|p| p.propagates && Some(p.level) == propagating_level)
        .collect();
    Some(Reach {
        level,
        propagates: propagating_level.is_some(),
        propagating_level,
        extends,
        narrows,
        depth: strongest.iter().map(|p| p.depth).min()?,
        propagating_narrows: propagating
            .iter()
            .flat_map(|p| p.narrows.iter().cloned())
            .collect(),
        propagating_depth: propagating.iter().map(|p| p.depth).min().unwrap_or(0),
    })
}
