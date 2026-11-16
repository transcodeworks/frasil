//! The past of a kept checkpoint (units.md, "The past of a kept
//! checkpoint"; roster.md, 3.15.6 Forgetting, and starting from a
//! checkpoint): what a replica freezes of each unit of that past it keeps
//! before it forgets the rest.
//!
//! A unit's verdict and context are a function of its place, which a
//! replica that forgets no longer holds. Before it forgets, it freezes, for
//! each unit it keeps: its verdict, the capabilities its author held at its
//! place, the path that admitted it, and the events that void it
//! ([`FrozenUnit`]). From then on it hands the unit to its adapter with the
//! frozen capabilities, never with what the checkpoint's record or any later
//! place gives its author, so it shows what a replica that kept everything
//! shows, whatever became of the author before the checkpoint
//! (`frasil_units::frozen` reads a unit back from them; at-rest.md keeps
//! them in the `event` record's keys 6 to 8).
//!
//! - [`Space::freeze_unit`] gives them for a unit at its own place, in the
//!   resolution that judged it.
//! - [`Checkpointed::frozen_units`] gives them for every unit of a
//!   checkpoint's past, each read in the view that judged it: the past of
//!   the first checkpoint of the chain, resolved alone, for a unit of that
//!   past; the world of the checkpoint before for a unit between two
//!   checkpoints of the chain.

use super::Checkpointed;
use crate::across::AuthorReach;
use crate::member::{Capability, MemberRef};
use crate::space::{Checkpointing, Space, Status};
use frasil_events::{EventId, kind};
use std::collections::{BTreeMap, BTreeSet};

/// The most paths a unit's attribution names (roster.md, 3.11).
pub const MAX_ATTRIBUTION: usize = 64;

/// What a replica freezes of a unit of its kept checkpoint's past (units.md,
/// "The past of a kept checkpoint").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenUnit {
    /// Its verdict by the write rule, as the replica that judged it shows
    /// it: valid, or void with its class (`NotAWriter`, `RefusedByRemoval`,
    /// `Pending` for one held as waiting, `Late`).
    pub status: Status,
    /// How its author reached the space at its place, with the capabilities
    /// of its strongest path (units.md, 3.17 "Capability checks"); `None`
    /// for a unit with no place in the view that judged it, one late under
    /// an earlier checkpoint, whose verdict is all that is frozen.
    pub reach: Option<AuthorReach>,
    /// For a unit valid by the write rule, its attribution at its place
    /// (roster.md, 3.11, "Attribution"): the step-2 paths at its place, each
    /// with its label in the roster there when it has one, by type then ID,
    /// at most [`MAX_ATTRIBUTION`]; `None` for a unit the write rule voids,
    /// attributed to no member, and for one no path reached.
    pub attribution: Option<Vec<(MemberRef, Option<String>)>>,
    /// For a void unit, the events that void it (roster.md, 3.14, "The
    /// events that void an event"), ascending.
    pub voided_by: Vec<EventId>,
}

impl FrozenUnit {
    /// The capabilities its author held at its place, as the adapter reads
    /// them: the meet over its paths at its highest level there (roster.md,
    /// section 3.3), strictly ascending by name and then mode, a name kept in
    /// both modes where the meet keeps both: extended on every path and
    /// narrowed on some. What the `event` record's key 6 keeps. None where no
    /// path reached it.
    pub fn capabilities(&self) -> Vec<Capability> {
        let Some(AuthorReach::Reached(reach)) = &self.reach else {
            return Vec::new();
        };
        crate::graph::capabilities_of(reach)
    }
}

impl Space<'_> {
    /// The attribution of unit `u`, valid by the write rule (roster.md,
    /// 3.11, "Attribution"): the step-2 paths at its place, each with its
    /// label in the roster at the unit's place, by type then ID, at most
    /// [`MAX_ATTRIBUTION`]. `None` when no path is left, or for an event
    /// that is no valid unit of this view.
    pub fn attribution(&self, u: EventId) -> Option<Vec<(MemberRef, Option<String>)>> {
        if self.log().event(u)?.kind() != kind::UNIT || !self.status(u)?.is_valid() {
            return None;
        }
        let event = self.log().event(u)?;
        let roster = self.roster_at(&self.place_of(u));
        let (mut paths, _) =
            self.paths_at_event(&event.author().0, &roster, crate::Level::Write, u);
        let unrevoked: Vec<_> = paths
            .iter()
            .copied()
            .filter(|path| {
                let placed = std::cell::OnceCell::new();
                path.kind != crate::MemberType::Person
                    || self.options.others.list(&path.id).is_none_or(|list| {
                        !list.merged().member(event.author()).is_some_and(|member| {
                            member.revoked_by.iter().any(|end| {
                                placed
                                    .get_or_init(|| {
                                        self.options
                                            .units
                                            .list_events_at(self.log(), u)
                                            .unwrap_or_default()
                                    })
                                    .iter()
                                    .any(|copy| end == copy)
                            })
                        })
                    })
            })
            .collect();
        if !unrevoked.is_empty() {
            paths = unrevoked;
        }
        if paths.is_empty() {
            return None;
        }
        paths.sort_unstable_by_key(|path| (path.kind.code(), path.id));
        paths.dedup();
        paths.truncate(MAX_ATTRIBUTION);
        let roster = self.roster_at(&self.place_of(u));
        Some(
            paths
                .into_iter()
                .map(|path| {
                    let label = roster.state(&path).and_then(|state| state.label.clone());
                    (path, label)
                })
                .collect(),
        )
    }

    /// What a replica freezes of unit `u` at its own place in this
    /// resolution, the one that judged it (units.md, "The past of a kept
    /// checkpoint"): its verdict, its author's reach at its place, the path
    /// that admitted it and the events that void it. `None` for an event
    /// that is no unit of this view.
    pub fn freeze_unit(&self, u: EventId) -> Option<FrozenUnit> {
        let event = self.log().event(u)?;
        if event.kind() != kind::UNIT {
            return None;
        }
        let status = *self.status(u)?;
        let reach = self.author_reach(u);
        let attribution = match status.is_valid() {
            true => self.attribution(u),
            false => None,
        };
        let mut voided_by = match status.is_valid() {
            true => Vec::new(),
            false => self.voiders(u),
        };
        voided_by.sort_unstable();
        voided_by.dedup();
        Some(FrozenUnit {
            status,
            reach: Some(reach),
            attribution,
            voided_by,
        })
    }
}

impl Checkpointed<'_> {
    /// What a replica that holds `held` freezes when it forgets the past of
    /// checkpoint `c` of its chain in effect (units.md, "The past of a kept
    /// checkpoint"): for each unit of `c`'s past it holds, its verdict as
    /// [`Self::judge`] gives it, and its context read in the view that
    /// judged it, the past of the first checkpoint of the chain whose past
    /// holds it ([`Space::freeze_unit`]). A unit late under an earlier
    /// checkpoint of the chain has no place in that view: its verdict alone
    /// is frozen. At a replica that forgot, the units of its kept
    /// checkpoint's past were frozen already, and are left out. Empty when
    /// `c` is not in the chain over `held`.
    pub fn frozen_units(
        &self,
        held: &BTreeSet<EventId>,
        c: EventId,
    ) -> BTreeMap<EventId, FrozenUnit> {
        let judged = self.judge(held);
        let Some(position) = judged.chain.iter().position(|&x| x == c) else {
            return BTreeMap::new();
        };
        let chain = &judged.chain[..=position];
        let log = self.log();
        let mut by_view: BTreeMap<usize, Vec<EventId>> = BTreeMap::new();
        for &u in held {
            if log.event(u).is_none_or(|event| event.kind() != kind::UNIT) {
                continue;
            }
            if let Some(i) = chain.iter().position(|&k| log.precedes(u, k)) {
                by_view.entry(i).or_default().push(u);
            }
        }
        let mut out = BTreeMap::new();
        for (i, units) in by_view {
            // At a replica that forgot, the chain starts at its kept
            // checkpoint, whose past it froze when it forgot.
            if i == 0 && self.kept.is_some() {
                continue;
            }
            let found = match i {
                0 => self.freeze_in_past(chain[0], &units),
                _ => self.freeze_in_world(chain[i - 1], chain[i], &units),
            };
            for u in units {
                let Some(&status) = judged.statuses.get(&u) else {
                    continue;
                };
                let frozen = match found.get(&u) {
                    Some(frozen) if frozen.status == status => frozen.clone(),
                    // Late under the checkpoint before, it has no place in
                    // the world that judged it.
                    _ => FrozenUnit {
                        status,
                        reach: None,
                        attribution: None,
                        voided_by: Vec::new(),
                    },
                };
                out.insert(u, frozen);
            }
        }
        out
    }

    /// The units among `units` frozen in the past of the first checkpoint
    /// of the chain, `first`, resolved with no checkpoint in effect.
    fn freeze_in_past(&self, first: EventId, units: &[EventId]) -> BTreeMap<EventId, FrozenUnit> {
        let view = self.log().past(first);
        let presets = self.presets_outside(&view);
        match Space::resolve_checkpointed(
            self.log(),
            Some(&view),
            self.inputs.options,
            Checkpointing {
                presets,
                world: None,
            },
        ) {
            Ok(space) => units
                .iter()
                .filter_map(|&u| Some((u, space.freeze_unit(u)?)))
                .collect(),
            Err(_) => BTreeMap::new(),
        }
    }

    /// The units among `units` frozen in `a`'s world over the past of `b`,
    /// the checkpoint after `a` in the chain.
    fn freeze_in_world(
        &self,
        a: EventId,
        b: EventId,
        units: &[EventId],
    ) -> BTreeMap<EventId, FrozenUnit> {
        let Ok(view) = self.past_in_world(a, b) else {
            return BTreeMap::new();
        };
        let members: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&id| id == a || self.follows(id, a) == Ok(true))
            .collect();
        let (Ok(world), Some(record)) = (
            crate::WorldLog::new(self.log(), a, &members),
            self.record(a),
        ) else {
            return BTreeMap::new();
        };
        let presets = self.presets_in_world(&world, a, &members);
        let skeleton = match self.inputs.options.twins {
            crate::Twins::Skeleton => self.world_skeleton(a, &members),
            crate::Twins::Assumed => None,
        };
        match world.resolve_with_skeleton(self.inputs.options, &record, presets, skeleton) {
            Ok(space) => units
                .iter()
                .filter_map(|&u| Some((u, space.freeze_unit(u)?)))
                .collect(),
            Err(_) => BTreeMap::new(),
        }
    }
}
