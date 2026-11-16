//! A peer's invite drops (ext-invite-links.md, "Making an invite and keeping
//! drops", feature `ext-invite-links`).
//!
//! A peer, on `MailboxPut` of kind 4, in order:
//!
//! ```text
//! 1. Keys 2 and 4 are 32 bytes; key 5 is 1 to 604,800.            else Malformed
//! 2. The drop is at most 65,536 bytes.                            else TooLarge
//! 3. The connection holds the store right for key 4's space.      else CredentialRefused
//! 4. No drop is held at the address.                              else Conflict
//! 5. The space stays within its quota.                            else QuotaExceeded
//! ```
//!
//! Steps 1 and 2 read the message (`frasil-transport`); [`DropStore`] runs
//! steps 3 to 5. It keeps the drop for its lifetime plus 60 seconds of the
//! peer's own timeline, counts it in the space's usage meanwhile (peers.md,
//! "Quotas and rates"), and serves it to anyone who names the address. It
//! records the upload entry the drop was placed under; `MailboxDelete`
//! removes the drop only on a connection that proved that entry (else
//! `CredentialRefused`; `NotFound` if none).
//!
//! The store reads no clock: each call takes the peer's timeline, in
//! seconds.

use crate::Code;
use std::collections::BTreeMap;

/// The most bytes of a drop.
pub const DROP_MAX_BYTES: usize = 65_536;
/// The longest lifetime a drop may ask for, 7 days, in seconds.
pub const DROP_LIFETIME_MAX: u64 = 604_800;
/// What a peer keeps a drop beyond its lifetime, in seconds of its own
/// timeline.
pub const DROP_GRACE: u64 = 60;

/// A drop to place: the fields of a `MailboxPut` of kind 4 whose shape
/// steps 1 and 2 checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacedDrop<'a> {
    /// Key 2: the drop's address.
    pub address: [u8; 32],
    /// Key 4: the space ID.
    pub space: [u8; 32],
    /// Key 3: the drop.
    pub drop: &'a [u8],
    /// Key 5: its lifetime, in seconds, 1 to 604,800.
    pub lifetime: u64,
}

/// A drop a peer holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDrop {
    /// The space it was placed for.
    pub space: [u8; 32],
    /// The upload entry whose store right placed it.
    pub entry: [u8; 32],
    /// The drop.
    pub drop: Vec<u8>,
    /// The peer's timeline, in seconds, at which it goes.
    pub until: u64,
}

/// What a peer answers a drop's `MailboxPut` or `MailboxDelete` with, when
/// it does not accept it: `CredentialRefused`, `Conflict` or
/// `QuotaExceeded` (peers.md's codes), or `NotFound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropRefusal {
    /// One of peers.md's refusal codes.
    Code(Code),
    /// `not_found`: no drop is held at the address.
    NotFound,
}

impl DropRefusal {
    /// The code's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Self::Code(code) => code.name(),
            Self::NotFound => "not_found",
        }
    }
}

/// A peer's invite drops, by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropStore {
    drops: BTreeMap<[u8; 32], HeldDrop>,
}

impl DropStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets the drops whose time is up at `now`.
    pub fn expire(&mut self, now: u64) {
        self.drops.retain(|_, drop| drop.until > now);
    }

    /// Steps 3 to 5 for a `MailboxPut` of kind 4 whose shape steps 1 and 2
    /// checked: `entry` is the upload entry whose store right the connection
    /// holds for `space`, if any; `quota_left` the bytes the space may
    /// still use. Stored, it counts in the space's usage until it goes.
    ///
    /// # Errors
    ///
    /// `CredentialRefused`, `Conflict` or `QuotaExceeded`.
    pub fn put(
        &mut self,
        placed: &PlacedDrop<'_>,
        entry: Option<[u8; 32]>,
        quota_left: u64,
        now: u64,
    ) -> Result<(), DropRefusal> {
        let PlacedDrop {
            address,
            space,
            drop,
            lifetime,
        } = *placed;
        self.expire(now);
        // 3.
        let Some(entry) = entry else {
            return Err(DropRefusal::Code(Code::CredentialRefused));
        };
        // 4.
        if self.drops.contains_key(&address) {
            return Err(DropRefusal::Code(Code::Conflict));
        }
        // 5.
        if u64::try_from(drop.len()).unwrap_or(u64::MAX) > quota_left {
            return Err(DropRefusal::Code(Code::QuotaExceeded));
        }
        self.drops.insert(
            address,
            HeldDrop {
                space,
                entry,
                drop: drop.to_vec(),
                until: now
                    .saturating_add(lifetime.min(DROP_LIFETIME_MAX))
                    .saturating_add(DROP_GRACE),
            },
        );
        Ok(())
    }

    /// `MailboxDelete`: removes the drop at `address` of `space` only on a
    /// connection that proved the entry it was placed under.
    ///
    /// # Errors
    ///
    /// `NotFound` if no drop is held there; `CredentialRefused` for no
    /// entry, another entry or another space.
    pub fn delete(
        &mut self,
        address: &[u8; 32],
        space: &[u8; 32],
        entry: Option<&[u8; 32]>,
        now: u64,
    ) -> Result<(), DropRefusal> {
        self.expire(now);
        let held = self.drops.get(address).ok_or(DropRefusal::NotFound)?;
        if entry != Some(&held.entry) || held.space != *space {
            return Err(DropRefusal::Code(Code::CredentialRefused));
        }
        self.drops.remove(address);
        Ok(())
    }

    /// The drop held at an address, served to anyone who names it.
    pub fn get(&self, address: &[u8; 32], now: u64) -> Option<&[u8]> {
        self.drops
            .get(address)
            .filter(|drop| drop.until > now)
            .map(|drop| drop.drop.as_slice())
    }

    /// The bytes of the drops a space holds at `now`, which count in its
    /// usage.
    pub fn usage(&self, space: &[u8; 32], now: u64) -> u64 {
        self.drops
            .values()
            .filter(|drop| drop.space == *space && drop.until > now)
            .map(|drop| u64::try_from(drop.drop.len()).unwrap_or(u64::MAX))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drop_lives_its_lifetime_and_60_seconds() {
        let mut store = DropStore::new();
        let (address, space, entry) = ([1; 32], [2; 32], [3; 32]);
        let placed = |drop: &'static [u8]| PlacedDrop {
            address,
            space,
            drop,
            lifetime: 100,
        };
        assert_eq!(store.put(&placed(b"drop"), Some(entry), 4, 0), Ok(()));
        assert_eq!(store.usage(&space, 10), 4);
        assert_eq!(store.get(&address, 159), Some(&b"drop"[..]));
        assert_eq!(store.get(&address, 160), None);
        assert_eq!(store.put(&placed(b"again"), Some(entry), 5, 160), Ok(()));
        assert_eq!(
            store.put(&placed(b"over"), Some(entry), 0, 160),
            Err(DropRefusal::Code(Code::Conflict))
        );
        assert_eq!(
            store.delete(&address, &[9; 32], Some(&entry), 161),
            Err(DropRefusal::Code(Code::CredentialRefused))
        );
        assert_eq!(store.delete(&address, &space, Some(&entry), 161), Ok(()));
        assert_eq!(
            store.delete(&address, &space, Some(&entry), 161),
            Err(DropRefusal::NotFound)
        );
    }
}
