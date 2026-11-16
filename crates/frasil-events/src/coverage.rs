//! Anchors and coverage (crypto.md, "Anchors and coverage" and "The
//! classical sunset").
//!
//! - An event `E` is **covered** for a verifier when an event it accepted
//!   under scheme 2 names `E` by hash, directly or through a chain of
//!   hashes. Only an envelope's `prev` and `parents` count; refs never do,
//!   and coverage does not depend on the keys a verifier holds. The schemes
//!   of the events between do not matter: coverage vouches for an event's
//!   content, which its ID hashes, not for its signature.
//! - An **anchor** is an event of kind 5 under scheme 2 with an empty body,
//!   whose parents are the heads its author holds in the log, `prev` among
//!   them. Decoding checks its shape; it changes no state.
//! - Before the sunset every event whose signature verifies is accepted.
//!   From it, a scheme-0 event is accepted only if it is covered, or the
//!   verifier held it from before its own sunset; otherwise it is
//!   `Uncovered`, pending until a covering event arrives.

use crate::envelope::EventId;
use crate::log::Log;
use frasil_base::ErrorClass;
use frasil_crypto::schemes::Scheme;
use std::collections::{BTreeMap, BTreeSet};

/// An event as coverage reads it: its ID, its scheme, and the events its
/// envelope names by hash (its `prev` and its parents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEvent<I> {
    /// The event.
    pub id: I,
    /// Its signature scheme.
    pub scheme: Scheme,
    /// The events its envelope names: `prev` and `parents`.
    pub names: Vec<I>,
}

/// Everything reachable from `roots` through `names`, the roots included.
fn reach<I: Ord + Clone>(roots: Vec<I>, names: impl Fn(&I) -> Vec<I>) -> BTreeSet<I> {
    let mut reached = BTreeSet::new();
    let mut stack = roots;
    while let Some(current) = stack.pop() {
        if reached.insert(current.clone()) {
            stack.extend(names(&current));
        }
    }
    reached
}

/// Which of a verifier's events it accepts, given events whose signatures
/// verify: every one before the sunset; after it, every scheme-2 event, and
/// a scheme-0 event that an accepted scheme-2 event reaches or that the
/// verifier held from before its sunset. The others are `Uncovered`.
///
/// Names of events not among `events` are not followed.
pub fn coverage<I: Ord + Clone>(
    events: &[CoverageEvent<I>],
    sunset: bool,
    held_before_sunset: &BTreeSet<I>,
) -> BTreeMap<I, Result<(), ErrorClass>> {
    let by_id: BTreeMap<&I, &CoverageEvent<I>> =
        events.iter().map(|event| (&event.id, event)).collect();
    let reached = if sunset {
        reach(
            events
                .iter()
                .filter(|event| event.scheme == Scheme::Hybrid)
                .map(|event| event.id.clone())
                .collect(),
            |id| {
                by_id
                    .get(id)
                    .map(|event| {
                        event
                            .names
                            .iter()
                            .filter(|name| by_id.contains_key(name))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default()
            },
        )
    } else {
        BTreeSet::new()
    };
    events
        .iter()
        .map(|event| {
            let accepted = !sunset
                || event.scheme == Scheme::Hybrid
                || reached.contains(&event.id)
                || held_before_sunset.contains(&event.id);
            let verdict = if accepted {
                Ok(())
            } else {
                Err(ErrorClass::Uncovered)
            };
            (event.id.clone(), verdict)
        })
        .collect()
}

impl Log {
    /// The placed events that are covered: every scheme-2 event whose
    /// signature verified in full, and every placed event one of them
    /// reaches through parents (`prev` is among them), whatever the
    /// signatures between.
    pub fn covered(&self) -> BTreeSet<EventId> {
        let roots = self
            .verified_events()
            .filter(|event| event.scheme() == Scheme::Hybrid)
            .map(|event| event.id())
            .collect();
        reach(roots, |id| {
            self.event(*id)
                .map(|event| {
                    event
                        .parents()
                        .iter()
                        .copied()
                        .filter(|&parent| self.contains(parent))
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    /// Whether the verifier accepts each placed event whose signature
    /// verified in full ([`coverage()`] over the log): after the sunset, a
    /// scheme-0 event that is not covered and was not held from before the
    /// verifier's sunset is `Uncovered`.
    pub fn coverage(
        &self,
        sunset: bool,
        held_before_sunset: &BTreeSet<EventId>,
    ) -> BTreeMap<EventId, Result<(), ErrorClass>> {
        let covered = if sunset {
            self.covered()
        } else {
            BTreeSet::new()
        };
        self.verified_events()
            .map(|event| {
                let id = event.id();
                let accepted = !sunset
                    || event.scheme() == Scheme::Hybrid
                    || covered.contains(&id)
                    || held_before_sunset.contains(&id);
                let verdict = if accepted {
                    Ok(())
                } else {
                    Err(ErrorClass::Uncovered)
                };
                (id, verdict)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        id: &'static str,
        scheme: Scheme,
        names: &[&'static str],
    ) -> CoverageEvent<&'static str> {
        CoverageEvent {
            id,
            scheme,
            names: names.to_vec(),
        }
    }

    #[test]
    fn a_forged_branch_stays_out_after_the_sunset() {
        let events = [
            event("u1", Scheme::Ed25519, &[]),
            event("A", Scheme::Hybrid, &["u1"]),
            event("f", Scheme::Ed25519, &["u1"]),
        ];
        let after = coverage(&events, true, &BTreeSet::new());
        assert_eq!(after["u1"], Ok(()));
        assert_eq!(after["A"], Ok(()));
        assert_eq!(after["f"], Err(ErrorClass::Uncovered));
        let before = coverage(&events, false, &BTreeSet::new());
        assert!(before.values().all(Result::is_ok));
    }
}
