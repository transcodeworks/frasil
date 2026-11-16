//! Deliveries (keys.md, "Deliveries"): the completions a view calls for,
//! each with the first device present that can make it.
//!
//! 1. The current state, to every inside device and space principal that
//!    lacks it.
//! 2. Every state a member is entitled to and lacks: every rotation of the
//!    view and every state an event is sealed under, a unit's or a space
//!    event's. Keys waiting for stability are held back.
//! 3. The inputs of a merge: for each rotation of a current state of
//!    several, a link from the current state where the gate allows, and
//!    otherwise a gap record and wraps.
//! 4. Void keys: for each void rotation, and each state a unit names that
//!    includes one, a link from the current state where the gate allows,
//!    and otherwise a gap and wraps.
//! 5. Gap keys, to every member entitled to them.
//!
//! When the heal test fires, the heal comes first: no link hangs under the
//! condemned state. A device can make a delivery when it is a member of
//! the graph's merged roster, writes, and derives what it delivers.

use super::Kind;
use super::graph::KeyGraph;
use super::holdings::{Artifact, Heal, Holdings, heal_due};
use super::view::{History, Role};
use crate::member::Level;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use std::collections::{BTreeMap, BTreeSet};

/// Why a wrap is called for: the item of "Deliveries" that first asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Why {
    /// Item 1: the current state.
    Current,
    /// Item 2: a state the member is entitled to and lacks.
    Entitled,
    /// Item 3: an input of the current merge the gate keeps from a link.
    MergeInput,
    /// Item 4: a void key the gate keeps from a link.
    Void,
    /// Item 5: a gap key.
    Gap,
}

impl Why {
    /// The item's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Entitled => "entitled",
            Self::MergeInput => "merge input",
            Self::Void => "void",
            Self::Gap => "gap",
        }
    }
}

/// A wrap the view calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWrap<D> {
    /// The state.
    pub state: RotationSet,
    /// The device it is for.
    pub device: D,
    /// The first device present that can make it, if any.
    pub by: Option<D>,
    /// Why.
    pub why: Why,
}

/// A link the view calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLink<D> {
    /// The state it hangs under.
    pub under: RotationSet,
    /// The state it reaches.
    pub reaches: RotationSet,
    /// The first device present that derives both, if any.
    pub by: Option<D>,
}

/// The deliveries a view calls for in one graph, each list in ascending
/// order of its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<D> {
    /// The graph.
    pub kind: Kind,
    /// Wraps, by state then device.
    pub wraps: Vec<PlannedWrap<D>>,
    /// Links, by the state they hang under then the state they reach.
    pub links: Vec<PlannedLink<D>>,
    /// New gap records.
    pub gaps: Vec<RotationSet>,
    /// Keys held back while they wait for stability, with the device each
    /// waits for.
    pub waiting: Vec<(RotationSet, D)>,
    /// The heal test.
    pub heal: Option<Heal>,
}

/// The deliveries the view calls for in one graph, given its artifacts and
/// the devices present (`room`). After `gap_key_timeout` (`timed_out`)
/// nothing waits for stability.
pub fn plan<H: History>(
    graph: &KeyGraph<'_, H>,
    artifacts: &[Artifact<H::Device>],
    kind: Kind,
    room: &[H::Device],
    timed_out: bool,
) -> Plan<H::Device> {
    let holdings = Holdings::new(graph, artifacts, kind);
    let current = graph.current(kind);
    let now = graph.receiving(kind);
    let content_now = graph.receiving(Kind::Content);
    let mut room: Vec<H::Device> = room.to_vec();
    room.sort();
    room.dedup();
    let publishers: Vec<H::Device> = room
        .into_iter()
        .filter(|d| {
            graph.device_level(d, &now).is_some()
                && graph.device_level(d, &content_now) >= Some(Level::Write)
        })
        .collect();
    let heal = heal_due(graph, &holdings, kind);
    let reach: BTreeMap<H::Device, BTreeSet<RotationSet>> = publishers
        .iter()
        .map(|p| (p.clone(), holdings.reach(std::iter::once(p))))
        .collect();
    let first = |states: &[&RotationSet]| -> Option<H::Device> {
        publishers
            .iter()
            .find(|p| states.iter().all(|s| reach[*p].contains(*s)))
            .cloned()
    };
    let held: BTreeSet<&Artifact<H::Device>> = artifacts.iter().collect();
    let mut wraps: Wraps<H::Device> = BTreeMap::new();
    let mut links: BTreeMap<(RotationSet, RotationSet), Option<H::Device>> = BTreeMap::new();
    let mut gaps: BTreeSet<RotationSet> = BTreeSet::new();
    let mut waiting: BTreeSet<(RotationSet, H::Device)> = BTreeSet::new();

    let give = |wraps: &mut BTreeMap<_, _>, k: &RotationSet, d: &H::Device, why: Why| {
        let key = (k.clone(), d.clone());
        if wraps.contains_key(&key) || holdings.reaches(std::iter::once(d), k) {
            return;
        }
        wraps.insert(key, (first(&[k]), why));
    };
    let link_or_wrap = |wraps: &mut BTreeMap<_, _>,
                        links: &mut BTreeMap<_, _>,
                        gaps: &mut BTreeSet<RotationSet>,
                        under: &RotationSet,
                        k: &RotationSet,
                        why: Why| {
        if heal.is_some() {
            return;
        }
        if graph.gate(under, k, kind, timed_out) {
            let link = Artifact::Link {
                kind,
                under: under.clone(),
                reaches: k.clone(),
            };
            if !held.contains(&link) {
                links.insert((under.clone(), k.clone()), first(&[under, k]));
            }
            return;
        }
        let gap = Artifact::Gap {
            kind,
            state: k.clone(),
        };
        if !held.contains(&gap) {
            gaps.insert(k.clone());
        }
        for m in now.keys() {
            if graph.entitled_now(m, k, kind, timed_out) && graph.may_wrap(m, k) {
                for d in graph.wrap_devices(m) {
                    give(wraps, k, &d, why);
                }
            }
        }
    };

    // 1.
    if let Some(current) = &current {
        for m in now.keys().filter(|m| graph.may_wrap(m, current)) {
            for d in graph.wrap_devices(m) {
                give(&mut wraps, current, &d, Why::Current);
            }
        }
    }
    // 2.
    for (k, d, pending) in entitled_lacking(graph, &holdings, kind, timed_out, false) {
        if pending {
            waiting.insert((k, d));
        } else {
            give(&mut wraps, &k, &d, Why::Entitled);
        }
    }
    // 3.
    if let Some(current) = current.as_ref().filter(|c| c.len() > 1) {
        for &i in current.ids() {
            let input = RotationSet::single(i);
            link_or_wrap(
                &mut wraps,
                &mut links,
                &mut gaps,
                current,
                &input,
                Why::MergeInput,
            );
        }
    }
    // 4.
    let mut void: BTreeSet<RotationSet> = graph
        .events()
        .iter()
        .copied()
        .filter(|&i| graph.is_rotation(i, kind) && !graph.valid().contains(&i))
        .map(RotationSet::single)
        .collect();
    if kind == Kind::Content {
        void.extend(
            unit_references(graph)
                .into_iter()
                .filter(|r| r.len() > 1 && r.ids().iter().any(|x| !graph.valid().contains(x))),
        );
    }
    if let Some(current) = &current {
        void.remove(current);
        for k in &void {
            link_or_wrap(&mut wraps, &mut links, &mut gaps, current, k, Why::Void);
        }
    }
    // 5.
    let all_gaps: BTreeSet<RotationSet> = holdings.gaps().iter().chain(&gaps).cloned().collect();
    for m in now.keys() {
        for k in &all_gaps {
            if graph.entitled_now(m, k, kind, timed_out) && graph.may_wrap(m, k) {
                for d in graph.wrap_devices(m) {
                    give(&mut wraps, k, &d, Why::Gap);
                }
            }
        }
    }
    Plan {
        kind,
        wraps: wraps
            .into_iter()
            .map(|((state, device), (by, why))| PlannedWrap {
                state,
                device,
                by,
                why,
            })
            .collect(),
        links: links
            .into_iter()
            .map(|((under, reaches), by)| PlannedLink { under, reaches, by })
            .collect(),
        gaps: gaps.into_iter().collect(),
        waiting: waiting.into_iter().collect(),
        heal,
    }
}

/// "Deliveries", item 2: each state other than the current one that a
/// member is entitled to, every rotation of the view and every state an
/// event is sealed under, with each device the member receives wraps on
/// that does not derive it, and whether the key waits for stability
/// there. With `merged_only`, only the states of several rotations an
/// event is sealed under. In ascending order of state, then device.
pub fn entitled_lacking<H: History>(
    graph: &KeyGraph<'_, H>,
    holdings: &Holdings<H::Device>,
    kind: Kind,
    timed_out: bool,
    merged_only: bool,
) -> Vec<(RotationSet, H::Device, bool)> {
    let current = graph.current(kind);
    let now = graph.receiving(kind);
    let mut keys: BTreeSet<RotationSet> = if merged_only {
        BTreeSet::new()
    } else {
        graph
            .events()
            .iter()
            .copied()
            .filter(|&i| graph.is_rotation(i, kind))
            .map(RotationSet::single)
            .collect()
    };
    if kind == Kind::Content {
        keys.extend(
            sealed_states(graph)
                .into_iter()
                .filter(|state| !merged_only || state.len() > 1),
        );
    }
    let mut out = BTreeSet::new();
    for m in now.keys() {
        let devices = graph.wrap_devices(m);
        for k in &keys {
            if Some(k) == current.as_ref() {
                continue;
            }
            // Entitlement is the costlier test: only for a key some device
            // of the member lacks.
            let lacking: Vec<&H::Device> = devices
                .iter()
                .filter(|d| !holdings.reaches(std::iter::once(*d), k))
                .collect();
            if lacking.is_empty() || !graph.entitled(m, k, kind) || !graph.may_wrap(m, k) {
                continue;
            }
            let pending = graph.restored_pending(m, k, kind, timed_out);
            for d in lacking {
                out.insert((k.clone(), d.clone(), pending));
            }
        }
    }
    out.into_iter().collect()
}

/// The wraps called for, by state and device: who can make each, and why.
type Wraps<D> = BTreeMap<(RotationSet, D), (Option<D>, Why)>;

/// The states the view's units name.
fn unit_references<H: History>(graph: &KeyGraph<'_, H>) -> BTreeSet<RotationSet> {
    graph
        .events()
        .iter()
        .filter_map(|&i| {
            let facts = graph.facts(i);
            (facts.role == Role::Unit)
                .then(|| facts.key_reference.clone())
                .flatten()
        })
        .collect()
}

/// The states the view's units and space events are sealed under.
fn sealed_states<H: History>(graph: &KeyGraph<'_, H>) -> BTreeSet<RotationSet> {
    graph
        .events()
        .iter()
        .filter_map(|&i| graph.facts(i).key_reference.clone())
        .collect()
}

/// Whom a rotation's own delivery wraps for in one graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDelivery<D> {
    /// The devices that receive a bundle wrap, ascending: every device of
    /// every member of the merged roster, and the author's own device.
    pub devices: Vec<D>,
    /// The space principals in force, each sealed one space wrap.
    pub principals: Vec<super::graph::Principal>,
}

/// The recipients of a rotation's own delivery in one graph, over the
/// merged roster of a view that holds the rotation (keys.md,
/// "Deliveries"). The delivery MUST include a wrap for the author's own
/// device, so that a device restored from an older backup recovers the
/// rotation's secrets from the log; for the grant graph, only when the
/// author propagates, since a guest never receives a grant seed. Space
/// principals receive space wraps.
pub fn own_delivery<H: History>(
    graph: &KeyGraph<'_, H>,
    author: &H::Device,
    kind: Kind,
) -> OwnDelivery<H::Device> {
    let members = graph.receiving(kind);
    let content = graph.receiving(Kind::Content);
    let mut devices: BTreeSet<H::Device> = BTreeSet::new();
    let mut principals = Vec::new();
    for member in members.keys() {
        match member {
            super::graph::Member::Principal(p) => principals.push(*p),
            super::graph::Member::Roster(_) => devices.extend(graph.wrap_devices(member)),
        }
    }
    if kind == Kind::Content || !graph.device_session(author, &content) {
        devices.insert(author.clone());
    }
    OwnDelivery {
        devices: devices.into_iter().collect(),
        principals,
    }
}

/// The recipients of a checkpoint's own delivery in one graph (keys.md,
/// "Keys after a checkpoint"; roster.md, "The checkpoint record"), over the
/// key graph of the view its author signs it on, its past:
///
/// - a wrap for every device inside at that past, as [`KeyGraph::inside`]
///   counts it: the devices of the merged roster's members that this
///   replica wraps for, never a revoked or forked device, nor an invite key
///   whose claim was raced or made, which count as outside;
/// - a space wrap for every space principal in force there whose notice its
///   record keeps (`kept`, for instance [`record_principals`]), the
///   principals its world will have, while this replica holds that space's
///   log;
/// - the author's own device, as for every rotation (keys.md,
///   "Deliveries"); a checkpoint's author is an administrator of its past,
///   so it is inside already.
///
/// For the grant graph, only members whose grant propagates receive it. A
/// checkpoint in a restricted space is no grant rotation, so its delivery
/// has no grant graph part. No holder outside the inside of its past derives
/// the checkpoint's state, so the checkpoint heals.
pub fn checkpoint_delivery<H: History>(
    graph: &KeyGraph<'_, H>,
    author: &H::Device,
    kind: Kind,
    kept: impl Fn(&super::graph::Principal) -> bool,
) -> OwnDelivery<H::Device> {
    let members = graph.receiving(kind);
    let mut devices: BTreeSet<H::Device> = BTreeSet::new();
    let mut principals = Vec::new();
    for member in members.keys() {
        match member {
            super::graph::Member::Principal(p) => {
                if kept(p) && graph.may_wrap(member, &RotationSet::single(p.rotation)) {
                    principals.push(*p);
                }
            }
            super::graph::Member::Roster(_) => devices.extend(graph.wrap_devices(member)),
        }
    }
    let content = graph.receiving(Kind::Content);
    if graph.device_level(author, &content).is_some()
        && (kind == Kind::Content || !graph.device_session(author, &content))
    {
        devices.insert(author.clone());
    }
    OwnDelivery {
        devices: devices.into_iter().collect(),
        principals,
    }
}

/// The space principals a checkpoint record keeps: for each space member
/// entry, the principal of each recorded notice (roster.md, "The checkpoint
/// record", key 18). [`checkpoint_delivery`] space-wraps to these alone.
pub fn record_principals(record: &crate::Record) -> BTreeSet<super::graph::Principal> {
    record
        .members
        .iter()
        .filter(|entry| entry.member.kind == crate::MemberType::Space)
        .flat_map(|entry| {
            entry
                .notices
                .iter()
                .map(move |notice| super::graph::Principal {
                    space: EventId(entry.member.id),
                    rotation: notice.rotation,
                })
        })
        .collect()
}
