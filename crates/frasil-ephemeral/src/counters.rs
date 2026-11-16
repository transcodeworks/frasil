//! A device's epoch and its counters (ext-ephemeral.md, "Epoch, counter and
//! replay").
//!
//! - **The epoch** is a 64-bit number per device, in at-rest.md's `epoch`
//!   table. A device that starts sending after its process starts reads
//!   `e`, commits `e + 1`, and uses `e + 1` in every space until its next
//!   start. After a restore, or with no epoch record, it takes instead its
//!   stored epoch (0 if none) plus 2^32 plus a random number below 2^32.
//! - **The counter** is per space: 1 at the start of each epoch, then one
//!   more for each ephemeral message and ephemeral slot value the device
//!   sends there.
//!
//! The caller commits [`Counters::epoch`] to the `epoch` table before the
//! first frame of the run goes out.

use crate::limits::EPOCH_RESTORE_STEP;
use std::collections::HashMap;

/// One run of a device's sending: its epoch, and its counter in each space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    epoch: u64,
    counters: HashMap<[u8; 32], u64>,
}

impl Counters {
    /// A start: reads the stored epoch `e` and runs with `e + 1`, which the
    /// caller commits. `None` if `e` is 2^64 − 1, so no epoch is left.
    pub fn start(stored: u64) -> Option<Self> {
        Some(Self::at(stored.checked_add(1)?))
    }

    /// A start after a restore, or with no epoch record (`stored` is
    /// `None`): the stored epoch (0 if none) plus 2^32 plus `random`, a
    /// random number below 2^32 the caller draws. `None` if that passes
    /// 2^64 − 1.
    pub fn restore_with(stored: Option<u64>, random: u32) -> Option<Self> {
        let epoch = stored
            .unwrap_or(0)
            .checked_add(EPOCH_RESTORE_STEP)?
            .checked_add(u64::from(random))?;
        Some(Self::at(epoch))
    }

    fn at(epoch: u64) -> Self {
        Self {
            epoch,
            counters: HashMap::new(),
        }
    }

    /// The run's epoch, which the caller commits to the `epoch` table.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The `(epoch, counter)` of the next ephemeral message or ephemeral
    /// slot value the device sends in `space`: counter 1 first in each
    /// space. `None` once the space's counter has reached 2^64 − 1; the
    /// device then sends nothing there until its next start.
    pub fn next(&mut self, space: &[u8; 32]) -> Option<(u64, u64)> {
        let counter = self.counters.entry(*space).or_insert(0);
        *counter = counter.checked_add(1)?;
        Some((self.epoch, *counter))
    }
}
