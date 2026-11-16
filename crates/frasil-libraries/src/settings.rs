//! A library's and a peer's settings (ext-libraries.md, 2.4 Settings), and
//! the limits of tickets in time.
//!
//! | Setting | Scope | Default | Range | Set by |
//! |---|---|---|---|---|
//! | `quota` | a library | the operator's default for the ID's kind, or none | bytes, or none | the operator, or the issuer |
//! | `erasure_timeout` (T) | a library | 7 days | 1 hour to 90 days | the same |
//! | `state` | a library | `open` | `open` or `suspended` | the same |
//! | `open_until` | a library | none | an instant, or none | the same |
//! | trusted issuers | the peer | none | at most 16 Ed25519 keys | the operator |
//! | `detached_grace` | the peer | 30 days | 1 to 365 days | the operator |
//!
//! The durations are overview.md's timers; [`frasil_base::time::Timer`]
//! holds the same values, and the tests check that they agree.

use core::fmt;

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

/// `ticket_lifetime`: the issuer sets `not_after` at most this long after it
/// signs (ext-libraries.md, 3.1 Getting a ticket). 24 hours.
pub const TICKET_LIFETIME: u64 = DAY;

/// `ticket_skew`: the wall-clock skew `check_expiry` allows a ticket. 60
/// seconds.
pub const TICKET_SKEW: u64 = 60;

/// The most issuers a peer trusts.
pub const MAX_ISSUERS: usize = 16;

/// A library's `erasure_timeout` (T) by default: 7 days.
pub const ERASURE_TIMEOUT_DEFAULT: u64 = 7 * DAY;

/// The range of a library's `erasure_timeout`: 1 hour to 90 days.
pub const ERASURE_TIMEOUT_RANGE: (u64, u64) = (HOUR, 90 * DAY);

/// A peer's `detached_grace` by default: 30 days.
pub const DETACHED_GRACE_DEFAULT: u64 = 30 * DAY;

/// The range of a peer's `detached_grace`: 1 to 365 days.
pub const DETACHED_GRACE_RANGE: (u64, u64) = (DAY, 365 * DAY);

/// A library's `state`. A library the peer does not yet know is created at
/// its first ticket, open (ext-libraries.md, 3.2 Checking a ticket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LibraryState {
    /// The library accepts stores for its spaces, and tickets.
    #[default]
    Open,
    /// The library accepts no store for any of its spaces and no ticket
    /// (`LibraryClosed`).
    Suspended,
}

impl LibraryState {
    /// The state's name: `open` or `suspended`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Suspended => "suspended",
        }
    }

    /// The state of a name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "open" => Some(Self::Open),
            "suspended" => Some(Self::Suspended),
            _ => None,
        }
    }
}

impl fmt::Display for LibraryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a library's `erasure_timeout` is within its range.
pub fn erasure_timeout_allowed(seconds: u64) -> bool {
    (ERASURE_TIMEOUT_RANGE.0..=ERASURE_TIMEOUT_RANGE.1).contains(&seconds)
}

/// Whether a peer's `detached_grace` is within its range.
pub fn detached_grace_allowed(seconds: u64) -> bool {
    (DETACHED_GRACE_RANGE.0..=DETACHED_GRACE_RANGE.1).contains(&seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::time::Timer;

    #[test]
    fn the_timer_table_agrees() {
        let lifetime = Timer::TicketLifetime.spec();
        assert_eq!(lifetime.maximum, Some(TICKET_LIFETIME));
        let skew = Timer::TicketSkew.spec();
        assert_eq!(
            (skew.default, skew.minimum, skew.maximum),
            (Some(TICKET_SKEW), Some(TICKET_SKEW), Some(TICKET_SKEW))
        );
        let t = Timer::ErasureTimeout.spec();
        assert_eq!(
            (t.default, t.minimum, t.maximum),
            (
                Some(ERASURE_TIMEOUT_DEFAULT),
                Some(ERASURE_TIMEOUT_RANGE.0),
                Some(ERASURE_TIMEOUT_RANGE.1)
            )
        );
        let grace = Timer::DetachedGrace.spec();
        assert_eq!(
            (grace.default, grace.minimum, grace.maximum),
            (
                Some(DETACHED_GRACE_DEFAULT),
                Some(DETACHED_GRACE_RANGE.0),
                Some(DETACHED_GRACE_RANGE.1)
            )
        );
        for seconds in [0, HOUR - 1, HOUR, 90 * DAY, 90 * DAY + 1] {
            assert_eq!(erasure_timeout_allowed(seconds), t.allows(seconds));
        }
        for seconds in [0, DAY - 1, DAY, 365 * DAY, 365 * DAY + 1] {
            assert_eq!(detached_grace_allowed(seconds), grace.allows(seconds));
        }
    }

    #[test]
    fn states_have_names() {
        for state in [LibraryState::Open, LibraryState::Suspended] {
            assert_eq!(LibraryState::from_name(state.name()), Some(state));
        }
        assert_eq!(LibraryState::default(), LibraryState::Open);
    }
}
