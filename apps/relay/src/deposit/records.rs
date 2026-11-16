//! What a peer keeps of deposit tokens at rest (ext-deposit-tokens.md, 2.7
//! What a peer keeps), besides a library's window and the grants it used,
//! which are the libraries' records:
//!
//! | Record | Address | Record |
//! |---|---|---|
//! | a deposit key | `q`, its key ID | `{1: sealed seed, 2: role, 3: began}` |
//! | a spent token | `p`, its nonce, its key ID | `{1: deposit, 2: item ID}`, or while its deposit is undecided `{1: deposit, 3: mailbox address, 4: reserved}` |
//!
//! - The sealed seed is 24 bytes of nonce, then the seed sealed under the
//!   peer's sealing key with XChaCha20-Poly1305, its key ID as associated
//!   data: 72 bytes (crate `deposit`).
//! - The role is 1, issuing, or 2, accepting only. `began` is the reading
//!   of the keys' shard's timeline at which the key began to issue,
//!   `{1: timeline, 2: run, 3: wall?}`.
//! - `deposit` is `SHA-256(address || item)` of the deposit the token paid
//!   for, and the item ID the one the peer assigned it. A reservation names
//!   the mailbox the deposit went to and the reading of the token's shard's
//!   timeline at which it was made (ext-deposit-tokens.md, 3.10 In a
//!   cluster).
//!
//! Every record is deterministic CBOR and reads only in its one encoding.
//! This file reads no clock and does no IO.

use frasil_base::cbor::{self, Map, Value};
use frasil_base::time::Reading;

/// The bytes of a sealed seed: a 24-byte nonce, the 32-byte seed and the
/// 16-byte tag.
pub const SEALED_BYTES: usize = 24 + 32 + 16;

/// A deposit key as the peer keeps it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The seed, sealed.
    pub sealed: Vec<u8>,
    /// Its role: 1 issuing, 2 accepting only.
    pub role: u8,
    /// The reading at which it began to issue.
    pub began: Reading,
}

impl core::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("role", &self.role)
            .field("began", &self.began)
            .finish_non_exhaustive()
    }
}

fn reading_value(reading: &Reading) -> Value {
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(reading.timeline));
    map.insert(2, Value::Unsigned(reading.run));
    if let Some(wall) = reading.wall {
        map.insert(3, Value::Unsigned(wall));
    }
    Value::Map(map)
}

fn read_reading(value: &Value) -> Option<Reading> {
    let map = value.as_map().ok()?;
    if !map.keys().all(|key| (1..=3).contains(key)) {
        return None;
    }
    Some(Reading {
        timeline: map.get(&1)?.as_unsigned().ok()?,
        run: map.get(&2)?.as_unsigned().ok()?,
        wall: match map.get(&3) {
            Some(value) => Some(value.as_unsigned().ok()?),
            None => None,
        },
    })
}

impl KeyRecord {
    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(self.sealed.as_slice()));
        map.insert(2, Value::Unsigned(u64::from(self.role)));
        map.insert(3, reading_value(&self.began));
        Value::Map(map).encode()
    }

    /// A key record, if `bytes` are one in its one encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 3 {
            return None;
        }
        let sealed = map.get(&1)?.as_bytes().ok()?;
        let role = map.get(&2)?.as_unsigned().ok()?;
        if sealed.len() != SEALED_BYTES || !(1..=2).contains(&role) {
            return None;
        }
        let record = Self {
            sealed: sealed.to_vec(),
            role: u8::try_from(role).ok()?,
            began: read_reading(map.get(&3)?)?,
        };
        (record.encode() == bytes).then_some(record)
    }
}

/// A spent token's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentState {
    /// Spent by a deposit the peer kept.
    Spent {
        /// `SHA-256(address || item)` of the deposit.
        deposit: [u8; 32],
        /// The item ID the peer assigned it.
        item: [u8; 16],
    },
    /// Reserved for a deposit whose item is not yet known to be kept.
    Reserved {
        /// `SHA-256(address || item)` of the deposit.
        deposit: [u8; 32],
        /// The mailbox the item goes to.
        address: [u8; 32],
        /// The reading of the token's shard's timeline, in seconds, at the
        /// reservation.
        at: u64,
    },
}

impl SpentState {
    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        match self {
            Self::Spent { deposit, item } => {
                map.insert(1, Value::from(*deposit));
                map.insert(2, Value::from(item.as_slice()));
            }
            Self::Reserved {
                deposit,
                address,
                at,
            } => {
                map.insert(1, Value::from(*deposit));
                map.insert(3, Value::from(*address));
                map.insert(4, Value::Unsigned(*at));
            }
        }
        Value::Map(map).encode()
    }

    /// A spent token's record, if `bytes` are one in its one encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        let deposit = map.get(&1)?.as_byte_array::<32>().ok()?;
        let state = match map.len() {
            2 => Self::Spent {
                deposit,
                item: map.get(&2)?.as_byte_array::<16>().ok()?,
            },
            3 => Self::Reserved {
                deposit,
                address: map.get(&3)?.as_byte_array::<32>().ok()?,
                at: map.get(&4)?.as_unsigned().ok()?,
            },
            _ => return None,
        };
        (state.encode() == bytes).then_some(state)
    }

    /// The deposit it is for.
    pub fn deposit(&self) -> [u8; 32] {
        match self {
            Self::Spent { deposit, .. } | Self::Reserved { deposit, .. } => *deposit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_read_back_and_odd_ones_do_not() {
        let key = KeyRecord {
            sealed: vec![7; SEALED_BYTES],
            role: 2,
            began: Reading {
                timeline: 10,
                run: 3,
                wall: Some(1_792_000_000),
            },
        };
        assert_eq!(KeyRecord::decode(&key.encode()), Some(key.clone()));
        let mut short = key.clone();
        short.sealed.pop();
        assert_eq!(KeyRecord::decode(&short.encode()), None);
        let mut role = key;
        role.role = 3;
        assert_eq!(KeyRecord::decode(&role.encode()), None);
        for state in [
            SpentState::Spent {
                deposit: [1; 32],
                item: [2; 16],
            },
            SpentState::Reserved {
                deposit: [1; 32],
                address: [3; 32],
                at: 99,
            },
        ] {
            assert_eq!(SpentState::decode(&state.encode()), Some(state));
        }
        // Keys 2 and 3 together, or a deposit of 31 bytes.
        assert_eq!(SpentState::decode(&[0xa2, 1, 0x40, 2, 0x40]), None);
        let mut map = Map::new();
        map.insert(1, Value::from(&[0u8; 31][..]));
        map.insert(2, Value::from(&[0u8; 16][..]));
        assert_eq!(SpentState::decode(&Value::Map(map).encode()), None);
    }
}
