//! Supersessions at a Blobs replica (ext-file-versions.md): what a writer
//! derives from the stream's stamps, the checks of section 3.2, the
//! supersession set of section 3.3, and the pairs a compactor lists and a
//! replica compares (sections 3.4 and 3.5).

use crate::content::Handle;
use crate::state::State;
use frasil_adapter::{EventId, Locator, Supersession};
use frasil_base::time::{Reading, Timer, lower};
use std::collections::{BTreeMap, BTreeSet};

/// A supersession section 3.2 refused: reported and ignored, while the
/// content and the unit's verdict stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Report {
    /// The log unit that carries it, or `None` for a snapshot unit's.
    pub unit: Option<EventId>,
    /// The supersession.
    pub supersession: Supersession,
}

/// The reports a state keeps. A writer of the stream can make more, each
/// the same class, and one is enough to tell.
const MAX_REPORTS: usize = 256;

/// The supersession set Σ of a stream (section 3.3), with what section 3.2
/// refused. `(listing, predecessor) → successor` triples, so that apply is
/// commutative and idempotent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Versions {
    set: BTreeSet<(EventId, Locator, Locator)>,
    reports: BTreeSet<Report>,
}

impl Versions {
    /// The triples of Σ, as `(listing, predecessor, successor)`.
    pub fn set(&self) -> &BTreeSet<(EventId, Locator, Locator)> {
        &self.set
    }

    /// The supersessions section 3.2 refused.
    pub fn reports(&self) -> &BTreeSet<Report> {
        &self.reports
    }

    fn report(&mut self, unit: Option<EventId>, supersession: Supersession) {
        if self.reports.len() < MAX_REPORTS {
            self.reports.insert(Report { unit, supersession });
        }
    }

    /// Apply: each supersession of an accepted log unit whose successor is
    /// the locator of a put of the unit.
    pub(crate) fn apply(
        &mut self,
        unit: EventId,
        supersedes: &[Supersession],
        puts: &BTreeSet<Locator>,
    ) {
        for supersession in supersedes {
            match supersession.listing {
                Some(listing) if puts.contains(&supersession.successor) => {
                    self.set
                        .insert((listing, supersession.predecessor, supersession.successor));
                }
                _ => self.report(Some(unit), *supersession),
            }
        }
    }
}

/// Section 3.1: the supersessions of a put of `successor` made from
/// `parents`, one per parent whose entry `state` holds, strictly ascending.
/// A parent absent or removed gets none. Each listing is the unit that put
/// the entry, as its stamp says.
pub fn supersessions_for(
    state: &State,
    parents: &[Handle],
    successor: Locator,
) -> Vec<Supersession> {
    let found: BTreeSet<Supersession> = parents
        .iter()
        .filter_map(|parent| state.slots().get(parent))
        .filter_map(|slot| {
            slot.entry.as_ref().map(|entry| Supersession {
                successor,
                listing: Some(slot.stamp.event_id),
                predecessor: entry.object,
            })
        })
        .collect();
    found.into_iter().collect()
}

impl State {
    /// The stream's supersession set.
    pub fn versions(&self) -> &Versions {
        self.versions_ref()
    }

    /// Load (section 3.3): each `[S, P]` of the snapshot unit whose `S` and
    /// `P` are locators of current entries adds `(event ID, P) → S` for each
    /// entry of locator `P`.
    pub fn load_supersedes(&mut self, supersedes: &[Supersession]) {
        let current: Vec<(EventId, Locator)> = self
            .slots()
            .values()
            .filter_map(|slot| {
                let entry = slot.entry.as_ref()?;
                Some((slot.stamp.event_id, entry.object))
            })
            .collect();
        let known = |locator: &Locator| current.iter().any(|(_, object)| object == locator);
        for supersession in supersedes {
            if !known(&supersession.successor) || !known(&supersession.predecessor) {
                self.versions_mut().report(None, *supersession);
                continue;
            }
            for (listing, object) in &current {
                if *object == supersession.predecessor {
                    self.versions_mut().set.insert((
                        *listing,
                        supersession.predecessor,
                        supersession.successor,
                    ));
                }
            }
        }
    }

    /// Each superseded current entry, by handle, with its successors: the
    /// locators of current entries other than it (section 3.3).
    pub fn superseded(&self) -> BTreeMap<Handle, BTreeSet<Locator>> {
        let mut out = BTreeMap::new();
        for (handle, entry) in self.current() {
            let Some(slot) = self.slots().get(handle) else {
                continue;
            };
            let others: BTreeSet<Locator> = self
                .current()
                .filter(|(other, _)| *other != handle)
                .map(|(_, other)| other.object)
                .collect();
            let successors: BTreeSet<Locator> = self
                .versions()
                .set
                .iter()
                .filter(|(listing, predecessor, successor)| {
                    *listing == slot.stamp.event_id
                        && *predecessor == entry.object
                        && others.contains(successor)
                })
                .map(|(_, _, successor)| *successor)
                .collect();
            if !successors.is_empty() {
                out.insert(*handle, successors);
            }
        }
        out
    }

    /// Section 3.4: `[S, P]` for each locator `P` every current entry of
    /// which is superseded and no open suggestion's put names, and each `S`
    /// that Σ gives for one of those entries. Strictly ascending.
    pub fn snapshot_supersedes(&self) -> Vec<Supersession> {
        let superseded = self.superseded();
        let suggested = self.suggestion_objects();
        let mut by_locator: BTreeMap<Locator, Vec<Handle>> = BTreeMap::new();
        for (handle, entry) in self.current() {
            by_locator.entry(entry.object).or_default().push(*handle);
        }
        let mut pairs = BTreeSet::new();
        for (predecessor, handles) in by_locator {
            if suggested.contains(&predecessor)
                || !handles.iter().all(|handle| superseded.contains_key(handle))
            {
                continue;
            }
            for successor in handles.iter().flat_map(|handle| &superseded[handle]) {
                pairs.insert(Supersession {
                    successor: *successor,
                    listing: None,
                    predecessor,
                });
            }
        }
        pairs.into_iter().collect()
    }
}

/// Section 3.5: whether a snapshot unit's key 8 passes against the replica's
/// own derivation. A key 8 that is absent passes.
pub fn supersedes_hold(derived: &[Supersession], listed: &[Supersession]) -> bool {
    listed.is_empty() || listed == derived
}

/// Section 3.11: whether a client compacts a stream now. `first` is its
/// first sight of the earliest unit since the last snapshot that carries a
/// supersession, or `None` when no such unit is held.
pub fn compaction_due(first: Option<&Reading>, now: &Reading, interval: u64) -> bool {
    first.is_some_and(|first| lower(first, now) >= interval)
}

/// `version_compaction_interval`'s default.
pub fn default_compaction_interval() -> u64 {
    Timer::VersionCompactionInterval
        .spec()
        .default
        .unwrap_or_default()
}
