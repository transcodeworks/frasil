//! The roster check and probation (transport.md, sections 3.5 "The roster
//! check" and 3.7 "Order on a connection, and the re-check").
//!
//! For each attach, each side checks the other's device against its own
//! current view of the space. The view is the caller's (roster.md and
//! identity.md decide it); this module turns where the device stands in it
//! into the attach's outcome, and bounds probation.

use crate::Code;

/// How a device reaches a space it reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Path {
    /// Through a device grant.
    DeviceGrant,
    /// Through a device grant with its session set: a guest.
    Guest,
    /// Through a person grant whose list, as the verifier holds it, vouches
    /// for the device.
    PersonGrant,
    /// Through a granted space it reaches.
    GrantedSpace,
}

/// How a named device reaches the space no longer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ended {
    /// It was removed.
    Removed,
    /// It was revoked from its list.
    Revoked,
    /// It is gone from a granted space.
    GoneFromGrantedSpace,
}

/// The other device, in the verifier's own current view of the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// It reaches the space at any level. A verifier that has not received
    /// a removal still finds the removed device here.
    Reaches(Path),
    /// It has a fork point in the space's log.
    Forked,
    /// It was named, and reaches the space no longer.
    Ended(Ended),
    /// It is named nowhere in the view: its grant is in an event the
    /// verifier lacks.
    NamedNowhere,
    /// It reaches the space only through a log the verifier does not hold.
    OnlyThroughUnheldLog,
}

/// The roster check's outcome for an attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The attach is admitted: send `Admit`.
    Admit,
    /// The attach is detached with this code: `forked`,
    /// `membership_ended` or `unknown_member`.
    Detach(Code),
    /// The device is in probation.
    Probation,
}

/// Section 3.5's table: the outcome for a device's standing.
pub fn check(standing: Standing) -> Verdict {
    match standing {
        Standing::Reaches(_) => Verdict::Admit,
        Standing::Forked => Verdict::Detach(Code::Forked),
        Standing::Ended(_) => Verdict::Detach(Code::MembershipEnded),
        Standing::NamedNowhere | Standing::OnlyThroughUnheldLog => Verdict::Probation,
    }
}

/// The re-check (section 3.7): whenever the verifier's view of a space
/// changes, it runs the check again for every device attached for that
/// space. A device now out is detached at once; one whose path now needs a
/// log the verifier does not hold enters probation.
pub fn recheck(standing: Standing) -> Verdict {
    check(standing)
}

/// What a device that learns that it was removed itself does with every
/// attach of that space.
pub const SELF_REMOVED: Verdict = Verdict::Detach(Code::MembershipEnded);

/// Probation's bound in time, `probation`: 30 seconds.
pub const PROBATION_SECONDS: u64 = 30;
/// Probation's bound in events received from the device: 4,096.
pub const PROBATION_EVENTS: u64 = 4_096;

/// One device's probation on one attach. Times are the caller's monotonic
/// clock, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probation {
    started: u64,
    events: u64,
}

impl Probation {
    /// Probation that starts now.
    pub fn start(now: u64) -> Self {
        Self {
            started: now,
            events: 0,
        }
    }

    /// Counts events received from the device during probation.
    pub fn received(&mut self, events: u64) {
        self.events = self.events.saturating_add(events);
    }

    /// Whether probation is spent: 30 seconds or 4,096 events.
    pub fn spent(&self, now: u64) -> bool {
        now.saturating_sub(self.started) >= PROBATION_SECONDS || self.events >= PROBATION_EVENTS
    }

    /// Probation ends at the first of: the device is in (`Admit`); it is
    /// out (`Detach` as the check says); probation is spent (`Detach`,
    /// `unknown_member`). `None` while it goes on.
    pub fn decide(&self, standing: Standing, now: u64) -> Option<Verdict> {
        match check(standing) {
            Verdict::Probation if self.spent(now) => Some(Verdict::Detach(Code::UnknownMember)),
            Verdict::Probation => None,
            verdict => Some(verdict),
        }
    }
}

/// What a side may serve the other on an attach (section 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Serving {
    /// Nothing: the side has not admitted the other: no unit, object,
    /// ephemeral frame or head statement.
    Nothing,
    /// Probation: only what peers.md serves under catch-up: space events,
    /// storage events, by ID any parent of an event already served, and the
    /// units of the system stream.
    CatchUp,
    /// Everything: the side admitted the other.
    Everything,
}
