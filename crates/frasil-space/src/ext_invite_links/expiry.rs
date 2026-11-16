//! Expiry and the administering devices' acts (ext-invite-links.md,
//! "Claiming", step 10, and "Administering devices").
//!
//! ```text
//! invite_expiry(expires_at, first_sight, now), in order:
//!   1. Its wall clock is known and now.W >= expires_at.            Revoke
//!   2. lower(first_sight, now) >= 604,800.                         Revoke
//!   3. Otherwise.                                                  Open
//! ```
//!
//! `first_sight` is this device's first sight of the invite entry, so step
//! 2 enforces the maximum without trusting `expires_at`. Each act's delay is
//! keys.md's rank delay over the space's administering devices in this
//! device's view: the close after a successor, with the successor's ID as
//! the trigger, which the inviter's client makes at once; the revocation
//! at expiry and after a raced claim, with the invite entry's ID as the
//! trigger.

use crate::keygraph::rank::{delay, rank_order};
use frasil_base::ErrorClass;
use frasil_base::time::{Reading, check_expiry, lower};
use frasil_events::EventId;

/// `link_lifetime`'s minimum, 15 minutes (overview.md, "Every timer"):
/// the shortest lifetime the inviter's client signs.
pub const LINK_LIFETIME_MIN: u64 = 900;

/// `link_lifetime`'s maximum, 7 days (overview.md, "Every timer"): the
/// furthest `expires_at` a claimant accepts, and how long an administering
/// device keeps an invite open from its first sight of it.
pub const LINK_LIFETIME_MAX: u64 = 604_800;

/// `link_skew` (overview.md, "Every timer"): the claimant's allowance for
/// the inviter's clock.
pub const LINK_SKEW: u64 = 60;

/// `invite_expiry`'s decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InviteExpiry {
    /// The invite stays open.
    Open,
    /// An administering device revokes the invite key.
    Revoke,
}

impl InviteExpiry {
    /// The decision's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Revoke => "Revoke",
        }
    }
}

/// `invite_expiry(expires_at, first_sight, now)`, for an invite with no
/// valid successor and no valid removal.
pub fn invite_expiry(expires_at: u64, first_sight: &Reading, now: &Reading) -> InviteExpiry {
    if now.wall.is_some_and(|wall| wall >= expires_at)
        || lower(first_sight, now) >= LINK_LIFETIME_MAX
    {
        InviteExpiry::Revoke
    } else {
        InviteExpiry::Open
    }
}

/// "Claiming", step 10: `check_expiry(expires_at, the claimant's wall
/// clock, 604,800, link_skew)`. An unknown wall clock is `Expired`.
///
/// # Errors
///
/// `Expired`, or `Malformed` for an `expires_at` beyond the furthest.
pub fn check_claim_expiry(expires_at: u64, now_wall: Option<u64>) -> Result<(), ErrorClass> {
    check_expiry(expires_at, now_wall, LINK_LIFETIME_MAX, LINK_SKEW)
}

/// The delay, in seconds, before `device` makes an act whose trigger is
/// `trigger` (a successor's ID for the close, the invite entry's for a
/// revocation), over the space's administering devices; `at_once` for the
/// inviter's client closing its own invite. `None` for a device that does
/// not administer.
pub fn act_delay(
    space: &EventId,
    trigger: &EventId,
    administering: &[[u8; 32]],
    device: &[u8; 32],
    at_once: bool,
    rotation_step: u64,
) -> Option<u64> {
    let order = rank_order(space.as_bytes(), trigger.as_bytes(), administering);
    let position = order.iter().position(|d| d == device)?;
    Some(if at_once {
        0
    } else {
        delay(position as u64, rotation_step)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(timeline: u64, wall: Option<u64>) -> Reading {
        Reading {
            timeline,
            wall,
            run: 1,
        }
    }

    #[test]
    fn expiry_follows_the_wall_clock_then_the_maximum() {
        let seen = reading(0, Some(100));
        assert_eq!(
            invite_expiry(200, &seen, &reading(50, Some(150))),
            InviteExpiry::Open
        );
        assert_eq!(
            invite_expiry(200, &seen, &reading(100, Some(200))),
            InviteExpiry::Revoke
        );
        assert_eq!(
            invite_expiry(u64::MAX, &reading(0, None), &reading(604_800, None)),
            InviteExpiry::Revoke
        );
        assert_eq!(check_claim_expiry(100, None), Err(ErrorClass::Expired));
        assert_eq!(check_claim_expiry(100 + 604_860, Some(100)), Ok(()));
        assert_eq!(
            check_claim_expiry(101 + 604_860, Some(100)),
            Err(ErrorClass::Malformed)
        );
    }
}
