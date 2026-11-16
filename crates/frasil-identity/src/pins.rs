//! Pins (identity.md, "Pins").
//!
//! A **pin** is the set of a list's events that a client has verified and
//! applied. It only grows. When a peer offers a state of the list:
//!
//! - if the state lacks a pinned event, the client keeps its own events and
//!   reports `RolledBack`: the peer withholds or rolls back;
//! - otherwise, if it holds new evidence of a fork, the client merges it as
//!   usual and reports `ForkDetected` with the evidence: a list member of
//!   the person equivocated, and the person can revoke it;
//! - otherwise the state **advances**.
//!
//! A pin of a list that forgot keeps the kept checkpoint and what follows
//! it (identity.md, "List checkpoints", "Pins"): [`Pin::forget`] drops the
//! rest, and a list that offers less than a pinned checkpoint and its
//! successors is `RolledBack`.

use crate::IdentityClass;
use crate::kept::KeptList;
use crate::list::DeviceList;
use frasil_events::{EventId, Evidence, ForkPoints};
use std::collections::BTreeSet;

/// What an offered state of a list does to a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// The state holds every pinned event and no new evidence of a fork.
    Advances,
    /// The state lacks a pinned event: the client keeps its own events.
    RolledBack,
    /// The state holds new evidence that a list member forked: the client
    /// merges it as usual, and reports this evidence.
    ForkDetected(Vec<Evidence>),
}

impl PinCheck {
    /// The report's class: `RolledBack` or `ForkDetected`, or `None` when
    /// the state advances.
    pub fn class(&self) -> Option<IdentityClass> {
        match self {
            PinCheck::Advances => None,
            PinCheck::RolledBack => Some(IdentityClass::RolledBack),
            PinCheck::ForkDetected(_) => Some(IdentityClass::ForkDetected),
        }
    }
}

/// A pin: the list events a client verified and applied, and the fork
/// points they show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    events: BTreeSet<EventId>,
    forks: ForkPoints,
}

impl Pin {
    /// The pin of every event a list holds placed.
    pub fn of(list: &DeviceList) -> Self {
        Self {
            events: list.log().canonical().into_iter().collect(),
            forks: list.fork_points(),
        }
    }

    /// The pinned events.
    pub fn events(&self) -> &BTreeSet<EventId> {
        &self.events
    }

    /// What an offered state of the list does to the pin.
    pub fn check(&self, offered: &DeviceList) -> PinCheck {
        if self.events.iter().any(|&id| !offered.log().contains(id)) {
            return PinCheck::RolledBack;
        }
        let forks = offered.fork_points();
        if forks == self.forks {
            return PinCheck::Advances;
        }
        let new = offered
            .evidence()
            .into_iter()
            .filter(|item| self.forks.fork_point(&item.author) != forks.fork_point(&item.author))
            .collect();
        PinCheck::ForkDetected(new)
    }

    /// Grows the pin to every event `list` holds placed, after the client
    /// verified and applied them. A pin only grows.
    pub fn advance(&mut self, list: &DeviceList) {
        self.events.extend(list.log().canonical());
        self.forks = list.fork_points();
    }

    /// The pin of every event a list that forgot holds placed: its kept
    /// checkpoint and the events after it.
    pub fn of_kept(list: &KeptList) -> Self {
        Self {
            events: list.canonical().into_iter().collect(),
            forks: list.fork_points(),
        }
    }

    /// Forgets with the list: keeps only the pinned events `kept` still
    /// holds placed, its kept checkpoint and what follows it.
    pub fn forget(&mut self, kept: &KeptList) {
        self.events.retain(|id| kept.event(*id).is_some());
        self.events.insert(kept.checkpoint());
        self.forks = kept.fork_points();
    }

    /// What an offered state of a list that forgot does to the pin: a
    /// state that lacks a pinned event, the pinned checkpoint or one of its
    /// successors included, is `RolledBack`.
    pub fn check_kept(&self, offered: &KeptList) -> PinCheck {
        if self.events.iter().any(|&id| offered.event(id).is_none()) {
            return PinCheck::RolledBack;
        }
        let forks = offered.fork_points();
        if forks == self.forks {
            return PinCheck::Advances;
        }
        let new = offered
            .evidence()
            .into_iter()
            .filter(|item| self.forks.fork_point(&item.author) != forks.fork_point(&item.author))
            .collect();
        PinCheck::ForkDetected(new)
    }

    /// Grows the pin to every event a list that forgot holds placed.
    pub fn advance_kept(&mut self, list: &KeptList) {
        self.events.extend(list.canonical());
        self.forks = list.fork_points();
    }
}
