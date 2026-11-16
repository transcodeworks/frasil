//! Retention (ext-file-versions.md, sections 3.6 to 3.9): a peer's listings,
//! heads and depth, and whether it keeps an object.
//!
//! [`Listings`] is a space's stored units as a peer reads them, those
//! neither replaced nor released. It holds no bytes and no clock: the caller
//! gives each unit's first sight and whether it is stable at the peer.

use frasil_base::time::{Reading, lower};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A unit's event ID.
pub type UnitId = [u8; 32];
/// An object's locator.
pub type Locator = [u8; 64];

/// A supersession as a peer reads it (units.md, section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Named {
    /// The object that replaces.
    pub successor: Locator,
    /// The unit named as listing the predecessor; `None` in a snapshot
    /// unit, whose supersessions name its own listings.
    pub listing: Option<UnitId>,
    /// The object replaced.
    pub predecessor: Locator,
}

/// A stored unit, neither replaced nor released, as a peer reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitView {
    /// Its stream.
    pub stream: [u8; 16],
    /// Its `objects`.
    pub objects: Vec<Locator>,
    /// Its `supersedes`.
    pub supersedes: Vec<Named>,
    /// The peer's first sight of it.
    pub seen: Reading,
    /// Whether it is a snapshot unit.
    pub snapshot: bool,
    /// Whether it is stable at the peer.
    pub stable: bool,
    /// Whether it is fork evidence: it lists, and supersedes nothing.
    pub evidence: bool,
    /// For a snapshot unit: `since` of its own listings, fixed when the
    /// peer stored it (section 3.6).
    pub since: BTreeMap<Locator, Reading>,
}

/// A space's settings for section 3.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `max_file_versions`.
    pub max_file_versions: u64,
    /// `file_version_retention`, in seconds.
    pub file_version_retention: u64,
    /// T, the space's `erasure_timeout`, in seconds.
    pub erasure_timeout: u64,
}

/// What section 3.8 decides of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retain {
    /// Step 1: it has no listing, and peers.md decides.
    Peers,
    /// Keep it, by step 2, 3, 4 or 7.
    Keep(u8),
    /// Collect it, by step 5 or 6.
    Collect(u8),
}

/// A listing: a unit and a locator in its `objects`.
pub type Listing = (UnitId, Locator);

/// The stored units of a space, with what sections 3.6 and 3.7 derive.
#[derive(Debug, Clone, Default)]
pub struct Listings {
    units: BTreeMap<UnitId, UnitView>,
    /// Each superseded listing, with the units that supersede it and their
    /// successors.
    superseders: BTreeMap<Listing, Vec<(UnitId, Locator)>>,
    /// Every listing of each object.
    of_object: BTreeMap<Locator, Vec<UnitId>>,
    heads: BTreeSet<Locator>,
    depth: BTreeMap<Locator, u64>,
}

impl Listings {
    /// Derives the listings of these units.
    pub fn new(units: BTreeMap<UnitId, UnitView>) -> Self {
        let mut superseders: BTreeMap<Listing, Vec<(UnitId, Locator)>> = BTreeMap::new();
        let mut of_object: BTreeMap<Locator, Vec<UnitId>> = BTreeMap::new();
        for (id, unit) in &units {
            for object in &unit.objects {
                of_object.entry(*object).or_default().push(*id);
            }
            if unit.evidence {
                continue;
            }
            for named in &unit.supersedes {
                let listing = if unit.snapshot {
                    *id
                } else {
                    match named.listing {
                        Some(listing) => listing,
                        None => continue,
                    }
                };
                let holds = units.get(&listing).is_some_and(|target| {
                    target.stream == unit.stream && target.objects.contains(&named.predecessor)
                });
                if holds {
                    superseders
                        .entry((listing, named.predecessor))
                        .or_default()
                        .push((*id, named.successor));
                }
            }
        }
        let heads: BTreeSet<Locator> = of_object
            .iter()
            .filter(|(object, listed)| {
                listed
                    .iter()
                    .any(|id| !superseders.contains_key(&(*id, **object)))
            })
            .map(|(object, _)| *object)
            .collect();
        // Section 3.7: an edge from S to P for each superseded listing of P
        // with successor S; depth is the shortest path from any head.
        let mut edges: BTreeMap<Locator, BTreeSet<Locator>> = BTreeMap::new();
        for ((_, predecessor), found) in &superseders {
            for (_, successor) in found {
                edges.entry(*successor).or_default().insert(*predecessor);
            }
        }
        let mut depth: BTreeMap<Locator, u64> = heads.iter().map(|head| (*head, 0)).collect();
        let mut queue: VecDeque<Locator> = heads.iter().copied().collect();
        while let Some(object) = queue.pop_front() {
            let next = depth[&object] + 1;
            for predecessor in edges.get(&object).into_iter().flatten() {
                if !depth.contains_key(predecessor) {
                    depth.insert(*predecessor, next);
                    queue.push_back(*predecessor);
                }
            }
        }
        Self {
            units,
            superseders,
            of_object,
            heads,
            depth,
        }
    }

    /// The stored units.
    pub fn units(&self) -> &BTreeMap<UnitId, UnitView> {
        &self.units
    }

    /// The objects with a listing.
    pub fn objects(&self) -> impl Iterator<Item = &Locator> {
        self.of_object.keys()
    }

    /// The units that supersede a listing, each with its successor.
    pub fn superseders(&self, listing: &Listing) -> &[(UnitId, Locator)] {
        self.superseders.get(listing).map_or(&[], Vec::as_slice)
    }

    /// `since(U, O)`: the peer's first sight of the earliest unit that
    /// supersedes the listing, or what a snapshot unit fixed for its own
    /// listing; `None` when it is not superseded.
    pub fn since(&self, listing: &Listing) -> Option<Reading> {
        let found = self.superseders.get(listing)?;
        let unit = self.units.get(&listing.0)?;
        if unit.snapshot
            && let Some(since) = unit.since.get(&listing.1)
        {
            return Some(*since);
        }
        found
            .iter()
            .filter_map(|(id, _)| self.units.get(id).map(|unit| unit.seen))
            .min_by_key(|reading| reading.timeline)
    }

    /// The heads: objects with a listing that is not superseded.
    pub fn heads(&self) -> &BTreeSet<Locator> {
        &self.heads
    }

    /// `depth(O)`, or `None` when there is no path from a head.
    pub fn depth(&self, object: &Locator) -> Option<u64> {
        self.depth.get(object).copied()
    }

    /// `since` for a snapshot unit's listing of `object` (section 3.6), as
    /// the peer stores the snapshot unit, with these the units of its cover
    /// that list it. The latest of theirs if all are superseded; otherwise
    /// the snapshot unit's first sight.
    pub fn inherited_since(&self, cover: &[UnitId], object: &Locator, seen: Reading) -> Reading {
        let listings: Vec<Listing> = cover
            .iter()
            .filter(|id| {
                self.units
                    .get(*id)
                    .is_some_and(|unit| unit.objects.contains(object))
            })
            .map(|id| (*id, *object))
            .collect();
        let sinces: Option<Vec<Reading>> =
            listings.iter().map(|listing| self.since(listing)).collect();
        match sinces {
            Some(sinces) => sinces
                .into_iter()
                .max_by_key(|reading| reading.timeline)
                .unwrap_or(seen),
            None => seen,
        }
    }

    /// Section 3.8, `retain`, in order. `held` is whether a live hold names
    /// the object; a hold's own question passes `false`.
    pub fn retain(&self, object: &Locator, now: &Reading, limits: &Limits, held: bool) -> Retain {
        let Some(listed) = self.of_object.get(object) else {
            return Retain::Peers;
        };
        if held {
            return Retain::Keep(2);
        }
        if self.heads.contains(object) {
            return Retain::Keep(3);
        }
        let settled = |id: &UnitId| {
            self.units
                .get(id)
                .is_some_and(|unit| unit.stable || lower(&unit.seen, now) >= limits.erasure_timeout)
        };
        let waits = listed.iter().any(|id| {
            !self
                .superseders(&(*id, *object))
                .iter()
                .any(|(unit, _)| settled(unit))
        });
        if waits {
            return Retain::Keep(4);
        }
        match self.depth(object) {
            None => return Retain::Collect(5),
            Some(depth) if depth >= limits.max_file_versions => return Retain::Collect(5),
            Some(_) => {}
        }
        let since = listed
            .iter()
            .filter_map(|id| self.since(&(*id, *object)))
            .max_by_key(|reading| reading.timeline);
        match since {
            Some(since) if lower(&since, now) >= limits.file_version_retention => {
                Retain::Collect(6)
            }
            _ => Retain::Keep(7),
        }
    }
}
