//! Node leases, and the [`Fence`] a node of a cluster writes its shards
//! under.
//!
//! A node renews its lease through Raft every [`Timing::renew`]. It reads
//! its monotonic clock before it sends the renewal, and once the renewal is
//! committed it holds its lease until that reading plus [`Timing::lease`]
//! less the drift margin, `lease × (1 − drift)`, by the same clock. Every
//! other node, the leader among them, counts the lease from the moment it
//! applied the renewal, which comes after the send, until `lease × (1 +
//! drift)` by its own clock. So with every clock's rate within `drift` of
//! true time, a node's lease ends, by true time, before
//! `send + lease`, and every other node sees it ended only after that.
//!
//! A node issues a write only while its lease outlasts the write's timeout,
//! [`Timing::put_timeout`], and the bucket's wrapper (crate `cluster`,
//! `TimedBucket`) fails a write that takes longer. So every write that
//! returns in time returned before the lease ended.
//!
//! # Clocks that stop
//!
//! A monotonic clock may stop while the machine is suspended, or while a
//! virtual machine is paused, and true time goes on. So a lease is also
//! counted on the wall clock from the same renewal, and it holds only while
//! both counts say it does: a node that wakes from a pause finds its lease
//! ended by the wall clock even where its monotonic clock missed the pause.
//! A wall clock stepped forward only shortens a lease; one stepped back
//! leaves the monotonic count to end it. Each renewal also compares the two
//! clocks' advance since the previous attempt ended, and a node whose wall
//! clock ran ahead of its monotonic clock by more than the drift margin of
//! that interval, and the drift margin of a lease more, takes itself as
//! paused: it gives its lease up before it renews again. A step of the wall
//! clock looks the same, so it keeps its open shards: if it was removed
//! while it was paused, the renewal finds it no member, and it breaks them
//! then. The assumption that remains is that the wall clock keeps counting
//! through a pause.
//!
//! # Epochs
//!
//! A shard opens under `epoch << 24`, or one above the epoch it was opened
//! under before if that is greater: the high bits name the membership epoch
//! the node opened it under. A node writes a shard only if that membership
//! epoch is no earlier than the epoch of its own latest join, so a node that
//! was removed and joined again writes nothing it opened before its
//! absence, when another node may have owned the shard meanwhile.
//!
//! # Fencing for good
//!
//! A node that finds another cluster, a single node or another process of
//! its own name writing its bucket fences its lease for good
//! ([`Lease::fence`]): the lease ends, and no renewal granted after, not
//! even one whose answer was on its way, holds it again, so the node never
//! writes a shard again.

use crate::shards::fence::Fence;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The bits of a shard's epoch below the membership epoch.
pub const EPOCH_SHIFT: u32 = 24;

/// The membership epoch a shard epoch names.
pub fn membership_epoch(shard_epoch: u64) -> u64 {
    shard_epoch >> EPOCH_SHIFT
}

/// A monotonic clock a lease is counted on: the time since some origin;
/// and the wall clock beside it.
pub trait LeaseClock: Send + Sync + core::fmt::Debug {
    /// The time since the clock's origin.
    fn now(&self) -> Duration;

    /// The wall clock: the time since the Unix epoch.
    fn wall(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

/// When a renewal was sent, by both clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// By the monotonic clock.
    pub mono: Duration,
    /// By the wall clock.
    pub wall: Duration,
}

/// The process's monotonic clock.
#[derive(Debug)]
pub struct SystemLeaseClock {
    origin: Instant,
}

impl Default for SystemLeaseClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl LeaseClock for SystemLeaseClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A clock that runs at `rate` times true time, for tests: 1.1 runs 10%
/// fast. Its rate may change as it runs.
#[derive(Debug)]
pub struct SkewedClock {
    /// Each run at one rate: its true start, its own reading then, its
    /// rate.
    runs: Mutex<Vec<(Instant, Duration, f64)>>,
    /// How far the wall clock was stepped forward.
    stepped: Mutex<Duration>,
}

impl SkewedClock {
    /// A clock from now, at `rate`.
    pub fn new(rate: f64) -> Self {
        Self {
            runs: Mutex::new(vec![(Instant::now(), Duration::ZERO, rate)]),
            stepped: Mutex::new(Duration::ZERO),
        }
    }

    /// Steps the wall clock forward by `by`, as a time service may, while
    /// the monotonic clock goes on.
    pub fn step_wall(&self, by: Duration) {
        *self.stepped.lock().unwrap_or_else(PoisonError::into_inner) += by;
    }

    /// Runs at `rate` from now on.
    pub fn set_rate(&self, rate: f64) {
        let own = self.now();
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((Instant::now(), own, rate));
    }

    /// The true instant at which this clock read, or reads, `reading`.
    pub fn true_instant(&self, reading: Duration) -> Instant {
        let runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, own, rate) = runs
            .iter()
            .rev()
            .find(|(_, own, _)| *own <= reading)
            .copied()
            .unwrap_or(runs[0]);
        start + (reading - own.min(reading)).div_f64(rate)
    }
}

impl LeaseClock for SkewedClock {
    fn now(&self) -> Duration {
        let runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, own, rate) = runs[runs.len() - 1];
        own + start.elapsed().mul_f64(rate)
    }

    fn wall(&self) -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            + *self.stepped.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How long leases last, and how often they are renewed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Timing {
    /// A lease's length.
    pub lease: Duration,
    /// How often a node renews.
    pub renew: Duration,
    /// The most any clock's rate may stray from true time, as a fraction.
    pub drift: f64,
    /// The longest a write to the bucket may take before it counts as
    /// failed.
    pub put_timeout: Duration,
}

impl Timing {
    /// Five-second leases renewed every half second, with a 20% margin for
    /// clock rates and a second for each write. A lease, less its margin,
    /// is four seconds: a renewal missed, a leader's election of at most
    /// three renewals, a renewal more to commit, and a write.
    pub const DEFAULT: Self = Self {
        lease: Duration::from_secs(5),
        renew: Duration::from_millis(500),
        drift: 0.2,
        put_timeout: Duration::from_secs(1),
    };

    /// How long a node holds its lease after it sent the renewal, by its
    /// own clock.
    ///
    /// At the drift bound itself, this and [`Self::ended_after`] both come
    /// to exactly `lease` of true time: a node whose clock runs slowest
    /// holds its lease until `send + lease`, and one whose clock runs
    /// fastest sees it end only then. What separates two owners is the
    /// write's timeout: a write is issued only while the lease outlasts
    /// [`Self::put_timeout`] by the writer's clock, so even the slowest
    /// clock's last write returns by `send + lease − put_timeout × drift /
    /// (1 − drift)` of true time, and the next owner opens a shard only
    /// after the lease ended, a removal and an epoch through Raft later.
    pub fn held(&self) -> Duration {
        self.lease.mul_f64(1.0 - self.drift)
    }

    /// How long another node waits after it applied a renewal before it
    /// takes the lease as ended, by its own clock.
    pub fn ended_after(&self) -> Duration {
        self.lease.mul_f64(1.0 + self.drift)
    }

    /// The longest a follower waits for its leader before it calls an
    /// election: three renewals (module `raft`, `config`).
    pub fn election(&self) -> Duration {
        self.renew * 3
    }

    /// How long a node's link to another has received nothing, at least,
    /// before a call that times out closes it: two renewals, eight
    /// heartbeats (module `link`, "A dead connection").
    pub fn silent(&self) -> Duration {
        self.renew * 2
    }

    /// How much more than the drift margin of the interval between two
    /// renewal attempts the wall clock may run ahead of the monotonic clock
    /// before the node takes itself as paused.
    pub fn stall(&self) -> Duration {
        self.lease.mul_f64(self.drift)
    }

    /// Why the timing cannot hold a lease across a leader's failover, or
    /// across a link to the leader that went dead: none if it can. A
    /// lease, less its margin, must outlast a renewal missed, an election,
    /// a renewal to commit after it, and a write; and a dead link's
    /// silence and the five renewals around it (module `link`, "A dead
    /// connection").
    pub fn check(&self) -> Option<&'static str> {
        if !(0.0..0.5).contains(&self.drift) {
            return Some("the drift margin is not 0 to 50%");
        }
        if self.renew.is_zero() || self.put_timeout.is_zero() {
            return Some("the renewal and the write timeout are not positive");
        }
        if self.renew * 2 + self.election() + self.put_timeout >= self.held() {
            return Some(
                "a lease, less its drift margin, does not outlast two renewals, an election \
                 and a write",
            );
        }
        if self.silent() + self.renew * 5 >= self.held() {
            return Some(
                "a lease, less its drift margin, does not outlast seven renewals: a link to the \
                 leader that went dead, and the renewal after it",
            );
        }
        None
    }
}

impl Default for Timing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// This node's lease: until when it holds it, by its monotonic clock and
/// by the wall clock.
#[derive(Debug)]
pub struct Lease {
    clock: Arc<dyn LeaseClock>,
    timing: Timing,
    until: Mutex<Option<Stamp>>,
    /// When the last renewal granted was sent, given up or not.
    last: Mutex<Option<Stamp>>,
    /// When each renewal granted was sent, by the monotonic clock: the
    /// last hundred thousand, for tests that check writes against them.
    grants: Mutex<Vec<Duration>>,
    /// The membership epoch the shards open under (crate `cluster`).
    epoch: Mutex<u64>,
    /// The epoch of this node's latest join: it writes no shard it opened
    /// under an earlier one.
    joined: Mutex<u64>,
    /// Fenced for good: no renewal holds the lease again. Set, and read by
    /// [`Self::grant`], under the lock of `until`, so that a grant and the
    /// fence never interleave.
    fenced: AtomicBool,
}

impl Lease {
    /// No lease yet.
    pub fn new(clock: Arc<dyn LeaseClock>, timing: Timing) -> Self {
        Self {
            clock,
            timing,
            until: Mutex::new(None),
            last: Mutex::new(None),
            grants: Mutex::new(Vec::new()),
            epoch: Mutex::new(0),
            joined: Mutex::new(0),
            fenced: AtomicBool::new(false),
        }
    }

    /// The clock the lease is counted on.
    pub fn clock(&self) -> &Arc<dyn LeaseClock> {
        &self.clock
    }

    /// The timing.
    pub fn timing(&self) -> Timing {
        self.timing
    }

    /// Now, by both clocks.
    pub fn stamp(&self) -> Stamp {
        Stamp {
            mono: self.clock.now(),
            wall: self.clock.wall(),
        }
    }

    /// A renewal sent at `sent` was committed. Nothing, once the lease is
    /// fenced for good.
    pub fn grant(&self, sent: Stamp) {
        if self.fenced() {
            return;
        }
        let held = self.timing.held();
        let until = Stamp {
            mono: sent.mono + held,
            wall: sent.wall + held,
        };
        {
            let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
            if grants.len() >= 100_000 {
                grants.remove(0);
            }
            grants.push(sent.mono);
        }
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            if last.is_none_or(|before| before.mono < sent.mono) {
                *last = Some(sent);
            }
        }
        let mut kept = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        // Read again under the lock the fence takes: a fence that came
        // after the check above ends the lease after this grant, or this
        // grant sees it.
        if self.fenced() {
            return;
        }
        *kept = Some(match *kept {
            Some(before) if before.mono >= until.mono => before,
            _ => until,
        });
    }

    /// Gives the lease up at once: the node is leaving, learned it is no
    /// member, or was paused.
    pub fn revoke(&self) {
        *self.until.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Gives the lease up for good: another cluster, a single node or
    /// another process of this node's name writes its bucket. No renewal
    /// granted after holds it again.
    pub fn fence(&self) {
        let mut until = self.until.lock().unwrap_or_else(PoisonError::into_inner);
        self.fenced.store(true, Ordering::SeqCst);
        *until = None;
    }

    /// Whether the lease is fenced for good.
    pub fn fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst)
    }

    /// When each renewal granted was sent, by the monotonic clock.
    pub fn grants(&self) -> Vec<Duration> {
        self.grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// When the last renewal granted was sent, by the monotonic clock,
    /// whether the lease was given up since or not.
    pub fn last_sent(&self) -> Option<Duration> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map(|sent| sent.mono)
    }

    /// Until when the lease is held, by the monotonic clock.
    pub fn until(&self) -> Option<Duration> {
        self.until
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map(|until| until.mono)
    }

    /// Whether the lease is held for at least `margin` more, by both
    /// clocks.
    pub fn holds_for(&self, margin: Duration) -> bool {
        let Some(until) = *self.until.lock().unwrap_or_else(PoisonError::into_inner) else {
            return false;
        };
        if self.fenced() {
            return false;
        }
        self.clock.now() + margin < until.mono && self.clock.wall() + margin < until.wall
    }

    /// Whether the wall clock ran ahead of the monotonic clock since
    /// `before` by more than the drift margin of the time between and
    /// [`Timing::stall`] more: the node was paused.
    pub fn stalled_since(&self, before: Stamp) -> bool {
        let now = self.stamp();
        let mono = now.mono.saturating_sub(before.mono);
        let wall = now.wall.saturating_sub(before.wall);
        wall > mono.mul_f64(1.0 + self.timing.drift) + self.timing.stall()
    }

    /// Notes the membership epoch shards open under.
    pub fn set_epoch(&self, epoch: u64) {
        let mut held = self.epoch.lock().unwrap_or_else(PoisonError::into_inner);
        *held = (*held).max(epoch);
    }

    /// The membership epoch.
    pub fn epoch(&self) -> u64 {
        *self.epoch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes the epoch of this node's latest join.
    pub fn set_joined(&self, epoch: u64) {
        let mut held = self.joined.lock().unwrap_or_else(PoisonError::into_inner);
        *held = (*held).max(epoch);
    }

    /// The epoch of this node's latest join.
    pub fn joined(&self) -> u64 {
        *self.joined.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a shard opened under `shard_epoch` may still be written: it
    /// was opened at or after this node's latest join.
    pub fn current(&self, shard_epoch: u64) -> bool {
        membership_epoch(shard_epoch) >= self.joined()
    }
}

/// The fence of a node of a cluster: a shard opens under an epoch whose
/// high bits are the membership's, above every earlier one the shard was
/// opened under, and the node writes only while its lease outlasts a
/// write's timeout, a shard it opened since its latest join, and never once
/// its lease is fenced for good.
#[derive(Debug)]
pub struct LeaseFence {
    lease: Arc<Lease>,
}

impl LeaseFence {
    /// The fence over a node's lease.
    pub fn new(lease: Arc<Lease>) -> Self {
        Self { lease }
    }
}

impl Fence for LeaseFence {
    fn open_epoch(&self, previous: Option<u64>) -> u64 {
        let epoch = self.lease.epoch() << EPOCH_SHIFT;
        previous.map_or(epoch, |previous| epoch.max(previous + 1))
    }

    fn may_write(&self, epoch: u64) -> bool {
        !self.lease.fenced()
            && self.lease.current(epoch)
            && self.lease.holds_for(self.lease.timing.put_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock the test sets.
    #[derive(Debug, Default)]
    struct Fixed(Mutex<Duration>);

    impl LeaseClock for Fixed {
        fn now(&self) -> Duration {
            *self.0.lock().unwrap()
        }

        fn wall(&self) -> Duration {
            *self.0.lock().unwrap()
        }
    }

    #[test]
    fn a_lease_ends_its_margin_before_others_see_it_end() {
        let timing = Timing {
            lease: Duration::from_secs(5),
            renew: Duration::from_millis(500),
            drift: 0.2,
            put_timeout: Duration::from_millis(900),
        };
        assert_eq!(timing.check(), None);
        assert_eq!(timing.held(), Duration::from_secs(4));
        assert_eq!(timing.ended_after(), Duration::from_secs(6));
        let clock = Arc::new(Fixed::default());
        let lease = Arc::new(Lease::new(clock.clone(), timing));
        let fence = LeaseFence::new(lease.clone());
        assert!(!fence.may_write(1), "no lease before a renewal");
        *clock.0.lock().unwrap() = Duration::from_secs(10);
        lease.grant(lease.stamp());
        assert!(fence.may_write(1));
        // A write is issued only while the lease outlasts its timeout.
        *clock.0.lock().unwrap() = Duration::from_millis(13_000);
        assert!(fence.may_write(1));
        *clock.0.lock().unwrap() = Duration::from_millis(13_200);
        assert!(!fence.may_write(1));
        // A late answer to an older renewal never shortens the lease.
        lease.grant(Stamp {
            mono: Duration::from_secs(9),
            wall: Duration::from_secs(9),
        });
        assert_eq!(lease.until(), Some(Duration::from_secs(14)));
    }

    /// A dead link to the leader is noticed, and a renewal granted again,
    /// before the lease ends: a timing that holds across a failover but
    /// not across that is refused.
    #[test]
    fn a_lease_outlasts_a_dead_links_notice() {
        let timing = Timing {
            lease: Duration::from_secs(5),
            renew: Duration::from_millis(600),
            drift: 0.2,
            put_timeout: Duration::from_millis(900),
        };
        assert!(timing.renew * 2 + timing.election() + timing.put_timeout < timing.held());
        assert!(timing.check().is_some());
        for timing in [Timing::DEFAULT, crate::testing::cluster::TIMING] {
            assert_eq!(timing.check(), None);
            assert!(timing.silent() + timing.renew * 5 < timing.held());
        }
    }

    #[test]
    fn shards_open_under_the_membership_epoch_and_above_any_earlier() {
        let lease = Arc::new(Lease::new(
            Arc::new(SystemLeaseClock::default()),
            Timing::DEFAULT,
        ));
        lease.set_epoch(4);
        let fence = LeaseFence::new(lease.clone());
        let four = 4 << EPOCH_SHIFT;
        assert_eq!(fence.open_epoch(None), four);
        assert_eq!(fence.open_epoch(Some(2)), four);
        assert_eq!(fence.open_epoch(Some(four)), four + 1);
        assert_eq!(membership_epoch(four + 1), 4);
        lease.set_epoch(3);
        assert_eq!(lease.epoch(), 4, "an epoch never goes back");
    }

    /// A node removed and joined again writes nothing it opened before.
    #[test]
    fn a_shard_opened_before_the_latest_join_is_not_written() {
        let clock = Arc::new(Fixed::default());
        let lease = Arc::new(Lease::new(clock, Timing::DEFAULT));
        lease.grant(lease.stamp());
        let fence = LeaseFence::new(lease.clone());
        assert!(fence.may_write(3 << EPOCH_SHIFT));
        lease.set_joined(5);
        assert!(!fence.may_write(3 << EPOCH_SHIFT));
        assert!(fence.may_write(5 << EPOCH_SHIFT));
    }

    /// A node fenced for good writes no shard again: its lease ends, and a
    /// renewal granted after, such as one whose answer was on its way as
    /// the node was fenced, holds nothing.
    #[test]
    fn a_fenced_lease_holds_nothing_and_a_late_renewal_grants_nothing() {
        let clock = Arc::new(Fixed::default());
        let lease = Arc::new(Lease::new(clock.clone(), Timing::DEFAULT));
        let fence = LeaseFence::new(lease.clone());
        let sent = lease.stamp();
        lease.grant(sent);
        assert!(fence.may_write(0));
        lease.fence();
        assert!(lease.fenced());
        assert!(!fence.may_write(0));
        assert!(!lease.holds_for(Duration::ZERO));
        // The renewal sent before the fence is answered after it.
        lease.grant(sent);
        lease.grant(lease.stamp());
        assert_eq!(lease.until(), None);
        assert!(!lease.holds_for(Duration::ZERO));
        assert!(!fence.may_write(0));
    }

    /// A pause the monotonic clock misses ends the lease by the wall clock.
    #[test]
    fn a_pause_the_monotonic_clock_misses_ends_the_lease() {
        #[derive(Debug, Default)]
        struct Paused {
            mono: Mutex<Duration>,
            wall: Mutex<Duration>,
        }
        impl LeaseClock for Paused {
            fn now(&self) -> Duration {
                *self.mono.lock().unwrap()
            }
            fn wall(&self) -> Duration {
                *self.wall.lock().unwrap()
            }
        }
        let clock = Arc::new(Paused::default());
        let lease = Lease::new(clock.clone(), Timing::DEFAULT);
        let before = lease.stamp();
        lease.grant(before);
        assert!(lease.holds_for(Duration::ZERO));
        // Ten seconds of true time pass while the monotonic clock is still.
        *clock.wall.lock().unwrap() = Duration::from_secs(10);
        assert!(!lease.holds_for(Duration::ZERO));
        assert!(lease.stalled_since(before));
    }

    /// At exactly the drift bound, a lease ends by true time when the
    /// others see it end, and the write timeout keeps every write's return
    /// strictly before that (`Timing::held`).
    #[test]
    fn writes_return_before_the_lease_ends_at_the_drift_bound() {
        let timing = Timing::DEFAULT;
        let (slow, fast) = (1.0 - timing.drift, 1.0 + timing.drift);
        let lease = timing.lease.as_secs_f64();
        let held_true = timing.held().as_secs_f64() / slow;
        let seen_true = timing.ended_after().as_secs_f64() / fast;
        assert!((held_true - lease).abs() < 1e-9, "{held_true}");
        assert!((seen_true - lease).abs() < 1e-9, "{seen_true}");
        // The last write is issued `put_timeout` before the lease ends by
        // the slow clock, and takes at most `put_timeout` of true time.
        let put = timing.put_timeout.as_secs_f64();
        let last_return = (timing.held().as_secs_f64() - put) / slow + put;
        let margin = put * timing.drift / (1.0 - timing.drift);
        assert!((lease - last_return - margin).abs() < 1e-9);
        assert!(last_return < seen_true, "{last_return} < {seen_true}");
        // Every rate within the bound leaves at least that margin.
        for rate in [slow, 0.9, 1.0, 1.1, fast] {
            let returns = (timing.held().as_secs_f64() - put) / rate + put;
            assert!(lease - returns >= margin - 1e-9, "rate {rate}");
        }
    }

    /// Every clock within the drift margin: a node's last write starts, by
    /// true time, before its renewal's send plus the lease, and the others
    /// see the lease end only after that.
    #[test]
    fn skewed_clocks_keep_writes_within_the_true_lease() {
        let timing = Timing::DEFAULT;
        for rate in [0.85, 0.9, 1.0, 1.1, 1.15] {
            // The node's own clock: `held` of its time is this much true
            // time.
            let held_true = timing.held().div_f64(rate);
            assert!(held_true < timing.lease, "rate {rate}");
            // Another node's clock at the other extreme waits this long.
            for other in [0.85, 1.15] {
                let seen_true = timing.ended_after().div_f64(other);
                assert!(seen_true > timing.lease, "rates {rate} and {other}");
            }
        }
    }
}
