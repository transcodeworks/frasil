//! What the procedure decides.

use std::collections::BTreeMap;

/// The step that made an event valid (roster.md, 3.7 The resolution
/// procedure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum How {
    /// Step 1, propagation: its authority holds and nothing that counts
    /// attacks it. The vectors write this "valid".
    Rules,
    /// Step 3, agreement: valid in every allowed assignment. The vectors
    /// write this "valid (agreed)".
    Agreed,
    /// Step 4, the seniority pick. The vectors write this "valid
    /// (seniority)".
    Seniority,
}

/// An event's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict<Id, C> {
    /// The event is valid.
    Valid(How),
    /// The event is void.
    Void {
        /// Its class: from the screen, its authority, or the attack that
        /// voids it.
        class: C,
        /// The attacker, when an attack voids it. The vectors write this
        /// "`class` by `attacker`".
        by: Option<Id>,
    },
}

impl<Id, C> Verdict<Id, C> {
    /// Whether the event is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    /// The class of a void event.
    pub fn class(&self) -> Option<&C> {
        match self {
            Self::Valid(_) => None,
            Self::Void { class, .. } => Some(class),
        }
    }
}

/// The verdict of every event [`resolve`](crate::resolve) was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution<Id, C> {
    /// Every event, in canonical order, with its verdict.
    pub(crate) verdicts: Vec<(Id, Verdict<Id, C>)>,
    /// Each event's position in `verdicts`.
    pub(crate) index: BTreeMap<Id, usize>,
    /// The contested events, in canonical order.
    pub(crate) contested: Vec<Id>,
}

impl<Id: Copy + Ord, C> Resolution<Id, C> {
    /// The event's verdict, or `None` for an event the procedure was not
    /// given.
    pub fn verdict(&self, event: Id) -> Option<&Verdict<Id, C>> {
        self.index.get(&event).map(|&i| &self.verdicts[i].1)
    }

    /// Whether the event was given and is valid.
    pub fn is_valid(&self, event: Id) -> bool {
        self.verdict(event).is_some_and(Verdict::is_valid)
    }

    /// Every event with its verdict, in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (Id, &Verdict<Id, C>)> {
        self.verdicts.iter().map(|(id, verdict)| (*id, verdict))
    }

    /// The valid events, in canonical order.
    pub fn valid(&self) -> impl Iterator<Item = Id> + '_ {
        self.iter()
            .filter(|(_, verdict)| verdict.is_valid())
            .map(|(id, _)| id)
    }

    /// The contested events, those that passed the screen, in canonical
    /// order.
    pub fn contested(&self) -> &[Id] {
        &self.contested
    }

    /// The number of events the procedure was given, without repeats.
    pub fn len(&self) -> usize {
        self.verdicts.len()
    }

    /// Whether the procedure was given no event.
    pub fn is_empty(&self) -> bool {
        self.verdicts.is_empty()
    }
}
