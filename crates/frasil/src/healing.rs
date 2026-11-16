//! The heal test as a replica computes it (keys.md, "Healing").
//!
//! A replica reads the key artifacts of its view, each with the devices it
//! was made for:
//!
//! - **Bundle wraps:** every member knows from the roster at a delivery's
//!   place which devices it wrapped for: the devices of the roster's
//!   members at that place, and for a grant state only members whose grant
//!   propagates. A device its person's list revoked since, or whose chain
//!   forked since, still holds what was wrapped for it unless the
//!   delivery's past holds the response to that end or the fork; a waiting
//!   list member, or a person's device where an active agent is forbidden,
//!   holds nothing (identity.md, "Kinds of list member").
//! - **Space wraps:** a wrap to each device of each space principal of the
//!   roster at that place.
//! - **Links and gap records,** from the sealed parts it opened.
//!
//! With them, `frasil-space`'s heal test runs over each graph, and the
//! candidates that may heal it are kept for the device's rank delay
//! (keys.md, "The rank and the delay"). When no content heal is due, the
//! same holdings give the content deliveries the view calls for (keys.md,
//! "Deliveries"): the current state to inside devices that lack it, and
//! every other state a member is entitled to and lacks.

use frasil_events::Log;
use frasil_keys::{KeyName, RotationSet};
use frasil_space::Space;
use frasil_space::keygraph::{
    Artifact, Heal, Holdings, KeyGraph, Kind, Member, SpaceHistory, entitled_lacking,
    heal_candidates, heal_due,
};
use std::collections::BTreeMap;

/// A heal the view calls for in one graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealDue {
    /// Content or grant.
    pub kind: Kind,
    /// The state to heal, the current state of that graph: its
    /// `encode_set` is the trigger.
    pub state: RotationSet,
    /// Why the test fired.
    pub reason: Heal,
    /// The devices that may heal it.
    pub candidates: Vec<[u8; 32]>,
}

/// Inside devices that derive a content state the view calls for from
/// what the view holds (keys.md, "Deliveries"). The first completion is the
/// current state: a member admitted "from now on" whose break merged with a
/// rotation concurrent with it, for one, holds the break's key and not the
/// other's. The second is every other state a member is entitled to: that
/// member holds the merged state whole only if it received it while it was
/// current, and the events sealed under it stay `Sealed` at it until it
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lacking {
    /// The state: its `encode_set` is the trigger.
    pub state: RotationSet,
    /// The devices that lack it.
    pub devices: Vec<[u8; 32]>,
    /// The devices that may deliver it: the writer devices, less those.
    pub candidates: Vec<[u8; 32]>,
}

/// What a resolved view calls for of its keys.
#[derive(Debug, Default)]
pub(crate) struct Called {
    /// The heals, content first.
    pub heals: Vec<HealDue>,
    /// When no content heal is due, the inside devices that lack the
    /// current content state.
    pub lacking: Option<Lacking>,
    /// When no content heal is due, each other content state inside
    /// devices are entitled to and lack, in ascending order of state.
    pub entitled: Vec<Lacking>,
}

/// The heals a resolved view calls for, content first; and, when no content
/// heal is due, the content states inside devices lack.
pub(crate) fn heals(
    space: &Space<'_>,
    log: &Log,
    graph: &KeyGraph<'_, SpaceHistory<'_, '_>>,
) -> Called {
    let artifacts = artifacts(space, log, graph);
    let mut out = Vec::new();
    let mut lacking = None;
    let mut entitled = Vec::new();
    for kind in [Kind::Content, Kind::Grant] {
        let holdings = Holdings::new(graph, &artifacts, kind);
        let Some(reason) = heal_due(graph, &holdings, kind) else {
            if kind == Kind::Content {
                lacking = lacking_current(graph, &holdings);
                entitled = lacking_entitled(graph, &holdings);
            }
            continue;
        };
        let Some(state) = graph.current(kind) else {
            continue;
        };
        out.push(HealDue {
            kind,
            state,
            reason,
            candidates: heal_candidates(graph, kind),
        });
    }
    Called {
        heals: out,
        lacking,
        entitled,
    }
}

/// "Deliveries", item 2, for the content graph, over the states of several
/// rotations an event is sealed under: each such state other than the
/// current one that a member is entitled to, with the inside devices it
/// receives wraps on that derive no such state. Keys that wait for
/// stability are held back. Single rotations are left out: a claimant
/// opens the wraps its invite key received (ext-invite-links.md, "Keys",
/// receipt), which the holdings count as the invite key's alone, so every
/// rotation made while a claim travelled would go to the claimant again.
fn lacking_entitled(
    graph: &KeyGraph<'_, SpaceHistory<'_, '_>>,
    holdings: &Holdings<[u8; 32]>,
) -> Vec<Lacking> {
    let inside = graph.inside(Kind::Content);
    let mut by_state: BTreeMap<RotationSet, Vec<[u8; 32]>> = BTreeMap::new();
    for (state, device, pending) in entitled_lacking(graph, holdings, Kind::Content, false, true) {
        if !pending && inside.contains(&device) {
            by_state.entry(state).or_default().push(device);
        }
    }
    if by_state.is_empty() {
        return Vec::new();
    }
    let writers = heal_candidates(graph, Kind::Content);
    by_state
        .into_iter()
        .map(|(state, mut devices)| {
            devices.sort_unstable();
            devices.dedup();
            let candidates = writers
                .iter()
                .filter(|d| devices.binary_search(d).is_err())
                .copied()
                .collect();
            Lacking {
                state,
                devices,
                candidates,
            }
        })
        .collect()
}

/// The devices the merged roster's members receive wraps on, inside, that
/// derive no current content state.
fn lacking_current(
    graph: &KeyGraph<'_, SpaceHistory<'_, '_>>,
    holdings: &Holdings<[u8; 32]>,
) -> Option<Lacking> {
    let state = graph.current(Kind::Content)?;
    let inside = graph.inside(Kind::Content);
    let mut devices: Vec<[u8; 32]> = graph
        .members(Kind::Content)
        .keys()
        .filter(|member| matches!(member, Member::Roster(_)))
        .flat_map(|member| graph.wrap_devices(member))
        .filter(|d| inside.contains(d) && !holdings.reaches(std::iter::once(d), &state))
        .collect();
    devices.sort_unstable();
    devices.dedup();
    if devices.is_empty() {
        return None;
    }
    let candidates = heal_candidates(graph, Kind::Content)
        .into_iter()
        .filter(|d| devices.binary_search(d).is_err())
        .collect();
    Some(Lacking {
        state,
        devices,
        candidates,
    })
}

/// The key artifacts of a view, with the devices each was made for.
fn artifacts(
    space: &Space<'_>,
    log: &Log,
    graph: &KeyGraph<'_, SpaceHistory<'_, '_>>,
) -> Vec<Artifact<[u8; 32]>> {
    let mut out = Vec::new();
    for &id in space.view() {
        let Some(event) = log.event(id) else {
            continue;
        };
        let Some(visible) = crate::replica::visible(event) else {
            continue;
        };
        let name = |key: &KeyName| match key {
            KeyName::Set(set) => set.clone(),
            KeyName::SelfRef(_) => RotationSet::single(id),
        };
        if !visible.deliveries.is_empty() {
            let place = graph.place(graph.valid(), &RotationSet::single(id));
            let roster = graph.roster_at(&place);
            for delivery in &visible.deliveries {
                for (kind, state) in [
                    (Kind::Content, delivery.key_name.as_ref()),
                    (Kind::Grant, delivery.grant_name.as_ref()),
                ] {
                    let Some(state) = state.map(name) else {
                        continue;
                    };
                    for (member, membership) in roster.iter() {
                        if kind == Kind::Grant && membership.session {
                            continue;
                        }
                        let wrapped = match member {
                            Member::Roster(_) => !delivery.wraps.is_empty(),
                            Member::Principal(_) => !delivery.space_wraps.is_empty(),
                        };
                        if !wrapped {
                            continue;
                        }
                        // The devices wrapped for: a device revoked or forked
                        // since still holds what it received, and one the
                        // roster's member does not wrap for (a waiting list
                        // member, or a person's device where an active agent
                        // is forbidden) received nothing.
                        let current = graph.devices(member);
                        let receiving = graph.wrap_devices(member);
                        for device in graph
                            .wrapped_for(member, id)
                            .into_iter()
                            .filter(|d| receiving.contains(d) || !current.contains(d))
                        {
                            out.push(Artifact::Wrap {
                                kind,
                                state: state.clone(),
                                device,
                            });
                        }
                    }
                }
            }
        }
        let Some(opened) = space.opened(id) else {
            continue;
        };
        for link in &opened.inner.links {
            out.push(Artifact::Link {
                kind: link.kind,
                under: name(&link.under),
                reaches: link.reaches.clone(),
            });
        }
        for gap in &opened.inner.gaps {
            out.push(Artifact::Gap {
                kind: gap.kind,
                state: gap.state.clone(),
            });
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The trigger a heal of `state` ranks by: its `encode_set`.
pub(crate) fn trigger(state: &RotationSet) -> Vec<u8> {
    state.encode()
}
