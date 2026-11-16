//! A peer's deposit keys and their rotation (ext-deposit-tokens.md, 2.2
//! Deposit keys, and 3.9 Spent tokens and key rotation).
//!
//! - A key issues while the upper estimate of the time since the reading at
//!   which it began, on the keys' shard's timeline, is less than
//!   `token_period`, and is accepting only while it is less than twice
//!   that. It then retires: the peer deletes its seed and every
//!   spent-token record under its key ID.
//! - When a key stops issuing, the peer begins the next at once, at that
//!   reading, and retires the key before it if that one has not yet
//!   retired, so that at most two keys live.
//! - A peer whose estimate is unbounded, after a restart with no known wall
//!   clock, retires both keys and begins a new one.
//!
//! [`KeyShard`] is the keys' shard's state; [`KeyShard::advance_with`] is
//! one transition, with the next key's seed given. The spent-token records
//! are the peer's; [`Rotation::retired`] names the key IDs whose records
//! it deletes.

use frasil_base::time::{Elapsed, Reading, upper};
use frasil_crypto::{NoRandomness, random_bytes};

use crate::errors::{TokenClass, malformed};
use crate::key::{DepositKey, KeyId, Role, SEED_BYTES};
use crate::messages::KeyEntry;
use crate::settings::TOKEN_PERIOD_RANGE;

/// A live key: the key and the reading at which it began to issue.
#[derive(Debug, Clone)]
pub struct LiveKey {
    /// The key.
    pub key: DepositKey,
    /// The reading at which it began, on the keys' shard's timeline.
    pub began: Reading,
}

/// What one transition did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rotation {
    /// The keys that retired, whose seeds and spent-token records the peer
    /// deletes.
    pub retired: Vec<KeyId>,
    /// The key that began, if one did.
    pub begun: Option<KeyId>,
}

/// The keys' shard: at most two live keys, the issuing key first.
#[derive(Debug, Clone)]
pub struct KeyShard {
    period: u64,
    keys: Vec<LiveKey>,
}

impl KeyShard {
    /// No key yet, under a `token_period` of 1 to 30 days.
    ///
    /// # Errors
    ///
    /// `Malformed` for a period outside the range.
    pub fn new(period: u64) -> Result<Self, TokenClass> {
        if !(TOKEN_PERIOD_RANGE.0..=TOKEN_PERIOD_RANGE.1).contains(&period) {
            return Err(malformed());
        }
        Ok(Self {
            period,
            keys: Vec::new(),
        })
    }

    /// A shard kept at rest: its live keys, the issuing key first. At most
    /// two are kept; any after them are not.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn from_keys(period: u64, keys: Vec<LiveKey>) -> Result<Self, TokenClass> {
        let mut shard = Self::new(period)?;
        shard.keys = keys;
        shard.keys.truncate(2);
        Ok(shard)
    }

    /// `token_period`.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// The live keys, the issuing key first.
    pub fn live_keys(&self) -> &[LiveKey] {
        &self.keys
    }

    /// The issuing key, if a key has begun.
    pub fn issuing(&self) -> Option<&DepositKey> {
        self.keys.first().map(|live| &live.key)
    }

    /// The live key of an ID.
    pub fn live(&self, id: &KeyId) -> Option<&DepositKey> {
        self.keys
            .iter()
            .map(|live| &live.key)
            .find(|key| key.id() == id)
    }

    /// The live keys with their roles, as `TokenKeys` and discovery list
    /// them.
    pub fn entries(&self) -> Vec<KeyEntry> {
        self.keys
            .iter()
            .enumerate()
            .map(|(index, live)| KeyEntry {
                key_id: *live.key.id(),
                public: *live.key.public(),
                role: if index == 0 {
                    Role::Issuing
                } else {
                    Role::Accepting
                },
            })
            .collect()
    }

    /// Begins a key from `seed` at `now`: it issues, the key that issued
    /// before accepts only, and any key before that retires.
    pub fn begin_with(&mut self, seed: &[u8; SEED_BYTES], now: Reading) -> Rotation {
        let key = DepositKey::from_seed(seed);
        let begun = *key.id();
        self.keys.insert(0, LiveKey { key, began: now });
        let retired = self.keys.split_off(2.min(self.keys.len()));
        Rotation {
            retired: retired.iter().map(|live| *live.key.id()).collect(),
            begun: Some(begun),
        }
    }

    /// The rotation at reading `now`, beginning a key from `next_seed` when
    /// one is due; with no key yet, the first begins.
    pub fn advance_with(&mut self, now: Reading, next_seed: &[u8; SEED_BYTES]) -> Rotation {
        let Some(first) = self.keys.first() else {
            return self.begin_with(next_seed, now);
        };
        let elapsed = upper(&first.began, &now);
        let mut retired = Vec::new();
        let Elapsed::Seconds(issuing) = elapsed else {
            retired.extend(self.keys.drain(..).map(|live| *live.key.id()));
            let mut rotation = self.begin_with(next_seed, now);
            rotation.retired.splice(0..0, retired);
            return rotation;
        };
        let twice = self.period.saturating_mul(2);
        let mut index = 1;
        while index < self.keys.len() {
            if upper(&self.keys[index].began, &now).at_least(twice) {
                retired.push(*self.keys.remove(index).key.id());
            } else {
                index += 1;
            }
        }
        if issuing < self.period {
            return Rotation {
                retired,
                begun: None,
            };
        }
        if issuing >= twice {
            retired.push(*self.keys.remove(0).key.id());
        }
        let mut rotation = self.begin_with(next_seed, now);
        retired.append(&mut rotation.retired);
        rotation.retired = retired;
        rotation
    }

    /// [`advance_with`](Self::advance_with), the next seed drawn from the
    /// platform only when a key begins.
    ///
    /// # Errors
    ///
    /// [`NoRandomness`] when a key is due and the platform has no working
    /// source; nothing changes then.
    pub fn advance(&mut self, now: Reading) -> Result<Rotation, NoRandomness> {
        let due = match self.keys.first() {
            None => true,
            Some(first) => upper(&first.began, &now).at_least(self.period),
        };
        if !due {
            return Ok(self.advance_with(now, &[0; SEED_BYTES]));
        }
        let seed = random_bytes::<SEED_BYTES>()?;
        Ok(self.advance_with(now, &seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn at(day: u64, wall: Option<u64>, run: u64) -> Reading {
        Reading {
            timeline: day * DAY,
            wall,
            run,
        }
    }

    #[test]
    fn a_period_out_of_range_is_refused() {
        assert!(KeyShard::new(DAY - 1).is_err());
        assert!(KeyShard::new(30 * DAY + 1).is_err());
        assert!(KeyShard::new(DAY).is_ok());
    }

    #[test]
    fn keys_issue_for_one_period_and_accept_for_the_next() {
        let mut shard = KeyShard::new(7 * DAY).unwrap();
        let first = shard.advance_with(at(0, None, 1), &[1; 32]);
        assert!(first.retired.is_empty());
        let k1 = first.begun.unwrap();
        // A second before the period: nothing.
        let mut early = at(7, None, 1);
        early.timeline -= 1;
        assert_eq!(shard.advance_with(early, &[2; 32]), Rotation::default());
        // At the period: the second key begins, the first accepts.
        let second = shard.advance_with(at(7, None, 1), &[2; 32]);
        let k2 = second.begun.unwrap();
        assert!(second.retired.is_empty());
        assert_eq!(shard.issuing().unwrap().id(), &k2);
        assert!(shard.live(&k1).is_some());
        // Two periods from the first key's start: it retires, a third
        // begins.
        let third = shard.advance_with(at(14, None, 1), &[3; 32]);
        assert_eq!(third.retired, vec![k1]);
        assert_eq!(shard.live_keys().len(), 2);
        // After a long gap both stop at once: the issuing key retires too.
        let gap = shard.advance_with(at(40, None, 1), &[4; 32]);
        assert_eq!(gap.retired.len(), 2);
        assert_eq!(shard.live_keys().len(), 1);
        // A restart with no wall clock: unbounded, both retire.
        shard.advance_with(at(47, None, 1), &[5; 32]);
        assert_eq!(shard.live_keys().len(), 2);
        let restart = shard.advance_with(at(48, None, 2), &[6; 32]);
        assert_eq!(restart.retired.len(), 2);
        assert_eq!(shard.live_keys().len(), 1);
    }

    #[test]
    fn a_wall_clock_ahead_stops_a_key_early() {
        let mut shard = KeyShard::new(7 * DAY).unwrap();
        shard.advance_with(at(0, Some(1_000), 1), &[1; 32]);
        let moved = shard.advance_with(at(1, Some(1_000 + 7 * DAY), 1), &[2; 32]);
        assert!(moved.begun.is_some());
    }
}
