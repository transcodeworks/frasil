//! What a log sees of the procedure's statuses while it judges an event.

use crate::engine::Contest;
use crate::{How, Resolve};

/// A contested event's standing while the procedure runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing<Id, C> {
    /// Not yet decided.
    Undecided,
    /// Decided valid, by the step [`How`] says.
    Valid(How),
    /// Decided void: by its authority, with that class, or by an attack,
    /// with the attack's class and the attacker.
    Void {
        /// The class.
        class: C,
        /// The attacker, for an attack.
        by: Option<Id>,
    },
    /// Decided void by the agreement step (roster.md, 3.7, step 3). Its
    /// class is named when the procedure ends.
    AgreedVoid,
    /// Valid (`true`) or void (`false`) under the assignment the agreement
    /// step is trying. Never seen outside that step.
    Trial(bool),
}

impl<Id, C> Standing<Id, C> {
    /// Valid, decided or under a trial.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::Trial(true))
    }

    /// Void, decided or under a trial.
    pub fn is_void(&self) -> bool {
        matches!(
            self,
            Self::Void { .. } | Self::AgreedVoid | Self::Trial(false)
        )
    }

    /// Decided, or assigned by a trial: anything but
    /// [`Undecided`](Standing::Undecided).
    pub fn is_assigned(&self) -> bool {
        !matches!(self, Self::Undecided)
    }
}

/// The procedure's statuses, as a log reads them to judge an event at its
/// place.
///
/// Only contested events have a standing. The others are not the
/// procedure's: those that failed the screen are void, and whatever the log
/// holds valid without contest (a genesis, a first list event, a root) it
/// adds to a place itself.
pub struct View<'a, L: Resolve> {
    pub(crate) log: &'a L,
    pub(crate) contest: &'a Contest<L::Id>,
    pub(crate) slots: &'a [Standing<L::Id, L::Class>],
}

impl<L: Resolve> View<'_, L> {
    /// The contested events, in canonical order.
    pub fn contested(&self) -> &[L::Id] {
        &self.contest.ids
    }

    /// Whether the event is contested.
    pub fn is_contested(&self, event: L::Id) -> bool {
        self.contest.index.contains_key(&event)
    }

    /// The event's standing, or `None` for an event that is not contested.
    pub fn standing(&self, event: L::Id) -> Option<Standing<L::Id, L::Class>> {
        self.contest.index.get(&event).map(|&i| self.slots[i])
    }

    /// Whether the event is contested and valid, decided or under a trial.
    pub fn is_valid(&self, event: L::Id) -> bool {
        self.standing(event).is_some_and(|s| s.is_valid())
    }

    /// The event's **place**, as far as the procedure decides it: the
    /// contested events in its past that are valid, decided or under a
    /// trial, in canonical order.
    pub fn place(&self, event: L::Id) -> Vec<L::Id> {
        match self.contest.index.get(&event) {
            Some(&e) => self.contest.past[e]
                .iter()
                .filter(|&p| self.slots[p].is_valid())
                .map(|p| self.contest.ids[p])
                .collect(),
            None => self
                .contest
                .ids
                .iter()
                .zip(self.slots)
                .filter(|(id, s)| s.is_valid() && self.log.precedes(**id, event))
                .map(|(id, _)| *id)
                .collect(),
        }
    }

    /// Whether every contested event in the event's past has a standing:
    /// decided, or assigned by a trial.
    pub fn past_decided(&self, event: L::Id) -> bool {
        match self.contest.index.get(&event) {
            Some(&e) => self.contest.past[e]
                .iter()
                .all(|p| self.slots[p].is_assigned()),
            None => self
                .contest
                .ids
                .iter()
                .zip(self.slots)
                .all(|(id, s)| s.is_assigned() || !self.log.precedes(*id, event)),
        }
    }

    /// Whether two events are concurrent: different, and neither in the
    /// other's past.
    pub fn concurrent(&self, a: L::Id, b: L::Id) -> bool {
        a != b && !self.log.precedes(a, b) && !self.log.precedes(b, a)
    }
}
