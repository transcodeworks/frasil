//! The logical clock, its floor and admission, and the stamp
//! (adapter-records.md, sections 3.1 and 3.3). adapter-blobs.md uses them
//! as they are.
//!
//! ```text
//! admit(counted changesets H, base max_clock b):
//!   A = {}; floor = b
//!   repeat until nothing changes:
//!     add to A every c in H with clock(c) <= floor + 1
//!     floor = max(b, the clocks of A)
//!   return A, floor
//! ```
//!
//! The admitted set is a least fixed point, so it depends on the changesets
//! held, never on their order. [`Clock`] computes it incrementally: as `H`
//! grows, `A` only grows, so admitting the smallest waiting clock while it
//! is at most `floor + 1` reaches the same fixed point.

use frasil_adapter::{Author, EventId};
use std::collections::{BTreeMap, BTreeSet};

/// A changeset's stamp: its clock, then its author, then its event ID,
/// compared in that order, author and ID byte by byte (adapter-records.md,
/// section 3.3). The derived order is that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stamp {
    /// The changeset's clock.
    pub clock: u64,
    /// The unit's author.
    pub author: Author,
    /// The unit's event ID, which breaks the one remaining tie: two
    /// changesets of one writer at one clock.
    pub event_id: EventId,
}

/// The admission of counted changesets over a base (adapter-records.md,
/// section 3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Clock {
    base: u64,
    floor: u64,
    counted: BTreeMap<EventId, u64>,
    waiting: BTreeSet<(u64, EventId)>,
}

impl Clock {
    /// A clock over a base snapshot's `max_clock`, or 0 without one.
    pub fn new(base: u64) -> Self {
        Self {
            base,
            floor: base,
            counted: BTreeMap::new(),
            waiting: BTreeSet::new(),
        }
    }

    /// The base snapshot's `max_clock`.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The floor: the greatest of the base and the admitted clocks.
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// A writer's clock: its floor plus one, over the changesets it holds
    /// and its base. A changeset held but not admitted does not count.
    pub fn next_clock(&self) -> u64 {
        self.floor.saturating_add(1)
    }

    /// Counts one changeset that passes the content's format checks,
    /// whatever its verdict. Returns the changesets admitted by it, in the
    /// order admitted, possibly itself. Counting a changeset twice changes
    /// nothing.
    pub fn count(&mut self, event_id: EventId, clock: u64) -> Vec<EventId> {
        if self.counted.contains_key(&event_id) {
            return Vec::new();
        }
        self.counted.insert(event_id, clock);
        self.waiting.insert((clock, event_id));
        let mut admitted = Vec::new();
        while let Some(&(clock, event_id)) = self.waiting.first() {
            if clock > self.floor.saturating_add(1) {
                break;
            }
            self.waiting.pop_first();
            self.floor = self.floor.max(clock);
            admitted.push(event_id);
        }
        admitted
    }

    /// Whether a changeset is counted.
    pub fn is_counted(&self, event_id: &EventId) -> bool {
        self.counted.contains_key(event_id)
    }

    /// Whether a changeset is counted and admitted.
    pub fn is_admitted(&self, event_id: &EventId) -> bool {
        self.counted
            .get(event_id)
            .is_some_and(|clock| !self.waiting.contains(&(*clock, *event_id)))
    }

    /// The counted changesets not yet admitted (`ClockAhead`), by clock.
    pub fn waiting(&self) -> impl Iterator<Item = &EventId> {
        self.waiting.iter().map(|(_, event_id)| event_id)
    }
}

/// `admit(H, b)`: the admitted set and the floor of the counted changesets
/// `H`, given as event IDs and clocks, over the base `b`.
pub fn admit(
    counted: impl IntoIterator<Item = (EventId, u64)>,
    base: u64,
) -> (BTreeSet<EventId>, u64) {
    let mut clock = Clock::new(base);
    let mut admitted = BTreeSet::new();
    for (event_id, value) in counted {
        admitted.extend(clock.count(event_id, value));
    }
    (admitted, clock.floor())
}

/// Admission with the accepted changesets that wait for it: the clock, and
/// an item per accepted changeset counted but not yet admitted. Records and
/// Blobs keep their accepted units here until they are admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission<T> {
    clock: Clock,
    held: BTreeMap<EventId, T>,
}

impl<T> Admission<T> {
    /// Admission over a base snapshot's `max_clock`, or 0.
    pub fn new(base: u64) -> Self {
        Self {
            clock: Clock::new(base),
            held: BTreeMap::new(),
        }
    }

    /// The clock.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// Counts a changeset whatever its verdict. Returns the accepted
    /// changesets it admits, ready to apply.
    pub fn count(&mut self, event_id: EventId, clock: u64) -> Vec<(EventId, T)> {
        let admitted = self.clock.count(event_id, clock);
        admitted
            .into_iter()
            .filter_map(|id| self.held.remove(&id).map(|item| (id, item)))
            .collect()
    }

    /// Counts an accepted changeset and returns what is ready to apply: it,
    /// if it is admitted, and the accepted changesets it admits. If it is
    /// not admitted, it is held until it is.
    pub fn submit(&mut self, event_id: EventId, clock: u64, item: T) -> Vec<(EventId, T)> {
        let mut ready = self.count(event_id, clock);
        if self.clock.is_admitted(&event_id) {
            ready.push((event_id, item));
        } else {
            self.held.entry(event_id).or_insert(item);
        }
        ready
    }

    /// Whether an accepted changeset waits for admission (`ClockAhead`).
    pub fn is_held(&self, event_id: &EventId) -> bool {
        self.held.contains_key(event_id)
    }

    /// The accepted changesets that wait for admission, by event ID.
    pub fn held(&self) -> impl Iterator<Item = &EventId> {
        self.held.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> EventId {
        [n; 32]
    }

    #[test]
    fn admission_is_a_least_fixed_point_in_any_order() {
        let counted = [(id(1), 1), (id(2), 2), (id(3), 9), (id(4), 3), (id(5), 2)];
        let (admitted, floor) = admit(counted, 0);
        assert_eq!(floor, 3);
        assert_eq!(admitted, BTreeSet::from([id(1), id(2), id(4), id(5)]));
        let reversed: Vec<_> = counted.iter().rev().copied().collect();
        assert_eq!(admit(reversed, 0), (admitted, floor));
    }

    #[test]
    fn the_base_supports_clocks_above_it() {
        let (admitted, floor) = admit([(id(1), 6), (id(2), 8)], 5);
        assert_eq!((admitted, floor), (BTreeSet::from([id(1)]), 6));
        let (admitted, floor) = admit([(id(1), 2)], 5);
        assert_eq!((admitted, floor), (BTreeSet::from([id(1)]), 5));
    }

    #[test]
    fn a_waiting_clock_does_not_count_for_the_next() {
        let mut clock = Clock::new(0);
        assert_eq!(clock.count(id(1), 9), Vec::<EventId>::new());
        assert_eq!(clock.next_clock(), 1);
        assert_eq!(clock.count(id(2), 1), vec![id(2)]);
        assert!(clock.is_admitted(&id(2)) && !clock.is_admitted(&id(1)));
        assert!(clock.is_counted(&id(1)));
        assert_eq!(clock.waiting().collect::<Vec<_>>(), [&id(1)]);
        assert_eq!(clock.next_clock(), 2);
        assert_eq!(clock.count(id(2), 1), Vec::<EventId>::new());
    }

    #[test]
    fn held_changesets_are_released_when_admitted() {
        let mut admission = Admission::new(0);
        assert!(admission.submit(id(3), 3, "c").is_empty());
        assert!(admission.is_held(&id(3)));
        assert!(admission.count(id(1), 1).is_empty());
        let ready = admission.submit(id(2), 2, "b");
        assert_eq!(ready, vec![(id(3), "c"), (id(2), "b")]);
        assert_eq!(admission.held().count(), 0);
        assert_eq!(admission.clock().floor(), 3);
        assert_eq!(admission.clock().base(), 0);
    }

    #[test]
    fn stamps_compare_by_clock_then_author_then_id() {
        let a = Stamp {
            clock: 2,
            author: [9; 32],
            event_id: [9; 32],
        };
        let b = Stamp {
            clock: 3,
            author: [0; 32],
            event_id: [0; 32],
        };
        let c = Stamp {
            clock: 3,
            author: [0; 32],
            event_id: [1; 32],
        };
        assert!(a < b && b < c);
    }
}
