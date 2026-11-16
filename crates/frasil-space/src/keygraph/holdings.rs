//! What a set of devices derives, and the heal test (keys.md, "Healing").
//!
//! **What a set of devices derives,** from the wraps, space wraps, links,
//! gap records and rotation authors a view holds, for one graph:
//!
//! 1. A device holds every state a bundle wrap it opens carries, and every
//!    rotation it authored.
//! 2. The devices of a space principal hold every state a space wrap to it
//!    carries.
//! 3. Repeat until nothing changes: a link under a held state gives the
//!    state it reaches; a merged state named anywhere in the view is held
//!    when all its rotations are.
//!
//! A set of devices derives the union of their holdings.

use super::Kind;
use super::graph::KeyGraph;
use super::view::History;
use frasil_keys::RotationSet;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// A key artifact a view holds, with the device it was made for. A space
/// wrap counts as a wrap to each device of its principal that the
/// wrapper's roster names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Artifact<D> {
    /// A bundle wrap of a state, for a device.
    Wrap {
        /// Content or grant.
        kind: Kind,
        /// The state it carries.
        state: RotationSet,
        /// The device it was made for.
        device: D,
    },
    /// A link from the state it hangs under to the state it reaches.
    Link {
        /// Content or grant.
        kind: Kind,
        /// The state it hangs under, `U`.
        under: RotationSet,
        /// The state it reaches, `B`.
        reaches: RotationSet,
    },
    /// A gap record: the state is a gap key.
    Gap {
        /// Content or grant.
        kind: Kind,
        /// The state.
        state: RotationSet,
    },
}

impl<D> Artifact<D> {
    /// The graph it belongs to.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Wrap { kind, .. } | Self::Link { kind, .. } | Self::Gap { kind, .. } => *kind,
        }
    }
}

/// Why the heal test fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Heal {
    /// The holders outside the inside together derive the current state.
    Outside,
    /// No inside device derives the current state.
    Unreachable,
}

impl Heal {
    /// The reason's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Outside => "outside",
            Self::Unreachable => "unreachable",
        }
    }
}

/// What each device of a view derives in one graph.
#[derive(Debug)]
pub struct Holdings<D: Ord + Clone> {
    wraps: BTreeMap<D, BTreeSet<RotationSet>>,
    links: BTreeMap<RotationSet, BTreeSet<RotationSet>>,
    gaps: BTreeSet<RotationSet>,
    merged: BTreeSet<RotationSet>,
    authored: BTreeMap<D, BTreeSet<RotationSet>>,
    cache: RefCell<BTreeMap<BTreeSet<D>, BTreeSet<RotationSet>>>,
}

impl<D: Ord + Clone> Holdings<D> {
    /// The holdings of a view's artifacts of one graph. The merged states
    /// named anywhere in the view are those of its artifacts, the states its
    /// units and space events are sealed under (content only) and its
    /// current state.
    pub fn new<H: History<Device = D>>(
        graph: &KeyGraph<'_, H>,
        artifacts: &[Artifact<D>],
        kind: Kind,
    ) -> Self {
        let mut wraps: BTreeMap<D, BTreeSet<RotationSet>> = BTreeMap::new();
        let mut links: BTreeMap<RotationSet, BTreeSet<RotationSet>> = BTreeMap::new();
        let mut gaps = BTreeSet::new();
        let mut merged = BTreeSet::new();
        let mut name = |state: &RotationSet| {
            if state.len() > 1 {
                merged.insert(state.clone());
            }
        };
        for artifact in artifacts.iter().filter(|a| a.kind() == kind) {
            match artifact {
                Artifact::Wrap { state, device, .. } => {
                    wraps
                        .entry(device.clone())
                        .or_default()
                        .insert(state.clone());
                    name(state);
                }
                Artifact::Link { under, reaches, .. } => {
                    links
                        .entry(under.clone())
                        .or_default()
                        .insert(reaches.clone());
                    name(under);
                    name(reaches);
                }
                Artifact::Gap { state, .. } => {
                    gaps.insert(state.clone());
                    name(state);
                }
            }
        }
        if kind == Kind::Content {
            for &i in graph.events() {
                if let Some(reference) = &graph.facts(i).key_reference {
                    name(reference);
                }
            }
        }
        if let Some(current) = graph.current(kind) {
            name(&current);
        }
        let mut authored: BTreeMap<D, BTreeSet<RotationSet>> = BTreeMap::new();
        for &i in graph.events() {
            if graph.is_rotation(i, kind) {
                authored
                    .entry(graph.facts(i).author.clone())
                    .or_default()
                    .insert(RotationSet::single(i));
            }
        }
        Self {
            wraps,
            links,
            gaps,
            merged,
            authored,
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    /// Every holder: each device a wrap was made for, and each rotation's
    /// author.
    pub fn holders(&self) -> BTreeSet<D> {
        self.wraps
            .keys()
            .chain(self.authored.keys())
            .cloned()
            .collect()
    }

    /// The states the view holds gap records for.
    pub fn gaps(&self) -> &BTreeSet<RotationSet> {
        &self.gaps
    }

    /// Every state a set of devices derives together.
    pub fn reach<'d>(&self, devices: impl IntoIterator<Item = &'d D>) -> BTreeSet<RotationSet>
    where
        D: 'd,
    {
        let devices: BTreeSet<D> = devices.into_iter().cloned().collect();
        if let Some(hit) = self.cache.borrow().get(&devices) {
            return hit.clone();
        }
        let mut held: BTreeSet<RotationSet> = BTreeSet::new();
        for d in &devices {
            held.extend(self.wraps.get(d).into_iter().flatten().cloned());
            held.extend(self.authored.get(d).into_iter().flatten().cloned());
        }
        let mut todo: Vec<RotationSet> = held.iter().cloned().collect();
        loop {
            while let Some(k) = todo.pop() {
                for r in self.links.get(&k).into_iter().flatten() {
                    if held.insert(r.clone()) {
                        todo.push(r.clone());
                    }
                }
            }
            let new: Vec<RotationSet> = self
                .merged
                .iter()
                .filter(|s| {
                    !held.contains(*s)
                        && s.ids()
                            .iter()
                            .all(|&i| held.contains(&RotationSet::single(i)))
                })
                .cloned()
                .collect();
            if new.is_empty() {
                break;
            }
            for s in new {
                held.insert(s.clone());
                todo.push(s);
            }
        }
        self.cache.borrow_mut().insert(devices, held.clone());
        held
    }

    /// Whether a set of devices derives a state.
    pub fn reaches<'d>(&self, devices: impl IntoIterator<Item = &'d D>, state: &RotationSet) -> bool
    where
        D: 'd,
    {
        self.reach(devices).contains(state)
    }
}

/// The heal test of one graph (keys.md, "Healing"): it fires when the
/// holders outside the inside together derive the current state
/// (`Outside`), or when no inside device derives it (`Unreachable`).
/// Forked devices, the devices of a principal no longer inside and, for the
/// grant graph, members whose grant does not propagate count as outside. A
/// replica that does not hold a principal's space's log counts its devices
/// as neither.
pub fn heal_due<H: History>(
    graph: &KeyGraph<'_, H>,
    holdings: &Holdings<H::Device>,
    kind: Kind,
) -> Option<Heal> {
    let current = graph.current(kind)?;
    let inside = graph.inside(kind);
    let neither = graph.neither(kind);
    let outside: Vec<H::Device> = holdings
        .holders()
        .into_iter()
        .filter(|d| !inside.contains(d) && !neither.contains(d))
        .collect();
    #[cfg(feature = "ext-restricted-spaces")]
    let outside: Vec<H::Device> = outside
        .into_iter()
        .filter(|d| graph.history().counts_outside(d))
        .collect();
    if !outside.is_empty() && holdings.reaches(&outside, &current) {
        return Some(Heal::Outside);
    }
    if !inside.is_empty()
        && !inside
            .iter()
            .any(|d| holdings.reaches(std::iter::once(d), &current))
    {
        return Some(Heal::Unreachable);
    }
    None
}

/// The devices that may heal a graph, by the merged roster: for the
/// content key, every writer device, a guest included; for the grant key,
/// every writer device whose grant propagates (keys.md, "Healing"). They
/// are the candidates the rank orders, with the healed state's
/// `encode_set` as the trigger.
pub fn heal_candidates<H: History>(graph: &KeyGraph<'_, H>, kind: Kind) -> Vec<H::Device> {
    let content = graph.receiving(Kind::Content);
    let members = graph.receiving(kind);
    let mut out: BTreeSet<H::Device> = BTreeSet::new();
    for member in members.keys() {
        for device in graph.devices(member) {
            let writes = graph.device_level(&device, &content) >= Some(crate::member::Level::Write);
            let propagates = kind == Kind::Content || !graph.device_session(&device, &content);
            if writes && propagates {
                out.insert(device);
            }
        }
    }
    out.into_iter().collect()
}
