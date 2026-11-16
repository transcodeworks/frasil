//! The peer's timeline (overview.md, "The local timeline").
//!
//! A peer keeps its own timeline and uses it only for its own storage and
//! decisions: first sights, `erasure_timeout`, `release_retention`,
//! `orphan_grace`, the mailboxes' lifetimes and its rates. Its wall clock
//! serves only what overview.md compares with a wall clock, such as an
//! exchange mailbox's `expires_at`.
//!
//! [`SystemClock`] follows the monotonic clock while the peer runs and
//! resumes from the reading the peer keeps at rest. [`ManualClock`] is set
//! by hand, for tests.

use frasil_base::time::{Reading, Timeline};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A source of readings of the peer's timeline.
pub trait Clock: Send + Sync {
    /// Reads the timeline now.
    fn now(&self) -> Reading;
}

/// The wall clock, in seconds since 1970, if the system knows it.
pub fn wall_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// The timeline over the system's monotonic and wall clocks.
#[derive(Debug)]
pub struct SystemClock {
    timeline: Mutex<Timeline>,
    started: Instant,
}

impl SystemClock {
    /// Starts the timeline from the reading kept at rest, or from none at
    /// the peer's first start.
    pub fn start(kept: Option<Reading>) -> Self {
        Self {
            timeline: Mutex::new(Timeline::start(kept, wall_now(), 0)),
            started: Instant::now(),
        }
    }

    /// The last reading, for the peer to keep at rest.
    pub fn kept(&self) -> Reading {
        self.timeline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .kept()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Reading {
        let mono = self.started.elapsed().as_secs();
        self.timeline
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(mono, wall_now())
    }
}

/// A timeline set by hand: its value is the timeline's, and its wall clock
/// is a fixed base plus the timeline.
#[derive(Debug)]
pub struct ManualClock {
    timeline: AtomicU64,
    wall_base: Option<u64>,
}

impl ManualClock {
    /// A clock at `timeline`, whose wall clock is the system's now minus
    /// `timeline`, so that it starts at the real wall time.
    pub fn new(timeline: u64) -> Self {
        Self {
            timeline: AtomicU64::new(timeline),
            wall_base: wall_now().map(|wall| wall.saturating_sub(timeline)),
        }
    }

    /// Sets the timeline.
    pub fn set(&self, timeline: u64) {
        self.timeline.store(timeline, Ordering::SeqCst);
    }

    /// Advances the timeline by `seconds`.
    pub fn advance(&self, seconds: u64) {
        self.timeline.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Reading {
        let timeline = self.timeline.load(Ordering::SeqCst);
        Reading {
            timeline,
            wall: self.wall_base.map(|base| base.saturating_add(timeline)),
            run: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_clock_moves_only_by_hand() {
        let clock = ManualClock::new(1000);
        assert_eq!(clock.now().timeline, 1000);
        clock.advance(5);
        assert_eq!(clock.now().timeline, 1005);
        clock.set(7);
        assert_eq!(clock.now().timeline, 7);
    }

    #[test]
    fn the_system_clock_resumes_from_its_kept_reading() {
        let kept = Reading {
            timeline: 500,
            wall: None,
            run: 3,
        };
        let clock = SystemClock::start(Some(kept));
        let now = clock.now();
        assert!(now.timeline >= 500);
        assert_eq!(now.run, 4);
    }
}
