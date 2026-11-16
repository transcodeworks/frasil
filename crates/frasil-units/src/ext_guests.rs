//! The writer's decision (ext-guests.md, "The writer's decision", feature
//! `ext-guests`).
//!
//! Before it seals anything in the space, a device decides, in order:
//!
//! ```text
//! 1. It has sent a leave request for its membership.                    Left
//! 2. A grant of it in force carries expires_at, and for the earliest,
//!    check_expiry(expires_at, its wall clock, 2,592,000, session_skew)
//!    (overview.md, section 6.6) does not pass.                          SessionEnded
//! 3. bounded_window is set, and upper(followed, now) >= bounded_window. WindowElapsed
//! 4. online_freshness is set, and no completed sync is recorded, or
//!    upper(last_sync, now) >= online_freshness.                         NotOnline
//! 5. Otherwise.                                                         MayWrite
//! ```
//!
//! A device that may not write seals nothing under the space's keys: no
//! unit, system units included, no key event, no roster event and no
//! ephemeral message. It still reads, syncs, receives and signs anchors.
//! No replica refuses an event for this: the decision binds the writer
//! alone.
//!
//! Under a bounded window a device keeps others able to follow it with
//! anchors ("Heartbeats"):
//!
//! ```text
//! heartbeat(last_signed, last_heartbeat, now, window, unanswered), in order:
//!   1. lower(last_heartbeat, now) < window / 2.                         Wait
//!   2. upper(last_signed, now) >= window / 2, or unanswered.             Heartbeat
//!   3. Otherwise.                                                        Wait
//! ```
//!
//! `followed` is `frasil_space::ext_guests::followed`; the earliest
//! `expires_at`, `frasil_space::ext_guests::earliest_expiry`.

use frasil_base::time::{Reading, lower, upper};
use frasil_space::Policy;
use frasil_space::ext_guests::{GuestClass, check_session_expiry};

/// What the writer's decision reads of this device and the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterState {
    /// It has sent a leave request for its membership.
    pub left: bool,
    /// The earliest `expires_at` of its grants in force, if any carries
    /// one.
    pub session_expires_at: Option<u64>,
    /// The space policy's `bounded_window` (key 3), `None` when off.
    pub bounded_window: Option<u64>,
    /// The space policy's `online_freshness` (key 4), `None` when off.
    pub online_freshness: Option<u64>,
    /// Its first sight of its own admission.
    pub admitted: Reading,
    /// Its reading when it signed its newest event another member follows,
    /// if any is followed.
    pub followed: Option<Reading>,
    /// Its reading at its last completed sync, `state` key 3 at rest.
    pub last_sync: Option<Reading>,
}

impl WriterState {
    /// A member admitted at `admitted`, under the space's policy, that has
    /// not left, with no session expiry, no followed event and no sync.
    pub fn new(policy: &Policy, admitted: Reading) -> Self {
        Self {
            left: false,
            session_expires_at: None,
            bounded_window: policy.bounded_window,
            online_freshness: policy.online_freshness,
            admitted,
            followed: None,
            last_sync: None,
        }
    }
}

/// The writer's decision, in order: `Ok` for `MayWrite`.
///
/// # Errors
///
/// `Left`, `SessionEnded`, `WindowElapsed` or `NotOnline`, each a report.
pub fn may_seal(state: &WriterState, now: &Reading) -> Result<(), GuestClass> {
    // 1.
    if state.left {
        return Err(GuestClass::Left);
    }
    // 2.
    if let Some(expires_at) = state.session_expires_at
        && check_session_expiry(expires_at, now.wall).is_err()
    {
        return Err(GuestClass::SessionEnded);
    }
    // 3.
    if let Some(window) = state.bounded_window {
        let followed = state.followed.unwrap_or(state.admitted);
        if upper(&followed, now).at_least(window) {
            return Err(GuestClass::WindowElapsed);
        }
    }
    // 4.
    if let Some(freshness) = state.online_freshness {
        let fresh = state
            .last_sync
            .is_some_and(|synced| !upper(&synced, now).at_least(freshness));
        if !fresh {
            return Err(GuestClass::NotOnline);
        }
    }
    Ok(())
}

/// The heartbeat decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Heartbeat {
    /// Sign an anchor now.
    Heartbeat,
    /// Not yet.
    Wait,
}

impl Heartbeat {
    /// The decision's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Heartbeat => "Heartbeat",
            Self::Wait => "Wait",
        }
    }
}

/// `heartbeat(last_signed, last_heartbeat, now, window, unanswered)`, under
/// a bounded window of `window` seconds. `unanswered` holds when the device
/// holds another member's anchor that none of its own events follows.
pub fn heartbeat(
    last_signed: &Reading,
    last_heartbeat: Option<&Reading>,
    now: &Reading,
    window: u64,
    unanswered: bool,
) -> Heartbeat {
    let half = window / 2;
    // 1.
    if last_heartbeat.is_some_and(|beat| lower(beat, now) < half) {
        return Heartbeat::Wait;
    }
    // 2.
    if upper(last_signed, now).at_least(half) || unanswered {
        return Heartbeat::Heartbeat;
    }
    // 3.
    Heartbeat::Wait
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(timeline: u64, wall: Option<u64>, run: u64) -> Reading {
        Reading {
            timeline,
            wall,
            run,
        }
    }

    #[test]
    fn the_steps_run_in_order() {
        let mut state = WriterState::new(&Policy::default(), r(0, Some(100), 1));
        assert_eq!(may_seal(&state, &r(10, Some(110), 1)), Ok(()));
        state.online_freshness = Some(300);
        assert_eq!(
            may_seal(&state, &r(10, Some(110), 1)),
            Err(GuestClass::NotOnline)
        );
        state.bounded_window = Some(3600);
        assert_eq!(
            may_seal(&state, &r(5, None, 2)),
            Err(GuestClass::WindowElapsed)
        );
        state.session_expires_at = Some(50);
        assert_eq!(
            may_seal(&state, &r(10, Some(110), 1)),
            Err(GuestClass::SessionEnded)
        );
        state.left = true;
        assert_eq!(
            may_seal(&state, &r(10, Some(110), 1)),
            Err(GuestClass::Left)
        );
    }

    #[test]
    fn heartbeats_do_not_answer_each_other() {
        let start = r(0, Some(0), 1);
        let now = r(1000, Some(1000), 1);
        assert_eq!(
            heartbeat(&start, Some(&r(900, Some(900), 1)), &now, 3600, true),
            Heartbeat::Wait
        );
        assert_eq!(
            heartbeat(&start, None, &now, 3600, true),
            Heartbeat::Heartbeat
        );
        assert_eq!(heartbeat(&start, None, &now, 3600, false), Heartbeat::Wait);
    }
}
