//! The peer's caps over its device mailboxes, and how long it keeps their
//! items (transport.md, 3.14 Mailboxes: "Claimed device mailboxes" and "The
//! peer's caps").
//!
//! A device mailbox is **claimed** from its device's first collection that
//! passes the checks, [`check_collect`](crate::mailbox::check_collect)'s,
//! until `mailbox_retention` passes on the peer's timeline with no further
//! collection. A collection names the device by its `ed || kc`, and the
//! mailbox's address hashes the device ID they give, so a key holder that
//! shares the device's Ed25519 key under another `kc` claims another
//! mailbox. An item received while its mailbox was not
//! claimed is kept at most `uncollected_retention` from its deposit, unless
//! the mailbox is claimed by then; otherwise for `mailbox_retention`.
//!
//! Besides each mailbox's cap of 64 items and 4 MiB, a peer may cap what
//! all its device mailboxes hold together. A deposit past its mailbox's cap
//! evicts that mailbox's oldest items. One past the peer's cap then evicts,
//! oldest first, items of mailboxes that are not claimed, unless its own is
//! not claimed; if room is still lacking it is refused `busy`, and evicts
//! nothing. It never evicts an item of a claimed mailbox for another
//! mailbox's deposit.
//!
//! [`PeerMailboxes`] holds what these rules read: each mailbox's claim and
//! its items' IDs and sizes, in deposit order. A peer that keeps its
//! mailboxes elsewhere applies the same rules to its own records. Readings
//! are seconds on the peer's timeline; the module reads no clock.

use std::collections::BTreeMap;

use crate::TransportClass;
use crate::frame::MAILBOX_ITEM_BYTES;
use crate::mailbox::{DEVICE_MAILBOX_BYTES, DEVICE_MAILBOX_ITEMS};

/// Whether a device mailbox is claimed at `now`, given its last collection
/// that passed the checks at or before `now`, if any.
pub fn claimed(last_collection: Option<u64>, now: u64, mailbox_retention: u64) -> bool {
    last_collection.is_some_and(|at| at <= now && now - at < mailbox_retention)
}

/// Whether an item deposited at `deposited` is still kept at `now`.
/// `claimed_at_deposit` says whether its mailbox was claimed when it came;
/// `first_collection_after` is the mailbox's first collection at or after
/// the deposit, if any.
pub fn item_kept(
    deposited: u64,
    claimed_at_deposit: bool,
    first_collection_after: Option<u64>,
    now: u64,
    mailbox_retention: u64,
    uncollected_retention: u64,
) -> bool {
    let claimed_by_then = claimed_at_deposit
        || first_collection_after
            .is_some_and(|at| at >= deposited && at - deposited < uncollected_retention);
    let kept_for = if claimed_by_then {
        mailbox_retention
    } else {
        uncollected_retention
    };
    now.saturating_sub(deposited) < kept_for
}

/// A cap in items and in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cap {
    /// The most items.
    pub items: u64,
    /// The most bytes.
    pub bytes: u64,
}

impl Cap {
    /// No cap.
    pub const NONE: Self = Self {
        items: u64::MAX,
        bytes: u64::MAX,
    };

    fn holds(self, items: u64, bytes: u64) -> bool {
        items <= self.items && bytes <= self.bytes
    }
}

/// One device mailbox as the caps see it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mailbox {
    /// Whether its device has claimed it.
    pub claimed: bool,
    /// Its items' IDs and sizes, oldest first.
    pub items: Vec<([u8; 16], u64)>,
}

/// A deposit the caps took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposited {
    /// The ID the peer assigned the item.
    pub id: [u8; 16],
    /// The items evicted for it, in ID order.
    pub evicted: Vec<[u8; 16]>,
}

/// A peer's device mailboxes under its caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMailboxes {
    cap: Cap,
    mailboxes: BTreeMap<[u8; 32], Mailbox>,
    next: u128,
}

impl PeerMailboxes {
    /// No mailbox yet, under the peer's cap; item IDs count from `first`.
    pub fn new(cap: Cap, first: u128) -> Self {
        Self {
            cap,
            mailboxes: BTreeMap::new(),
            next: first,
        }
    }

    /// The mailbox at an address, created empty and unclaimed.
    pub fn mailbox(&mut self, address: [u8; 32]) -> &mut Mailbox {
        self.mailboxes.entry(address).or_default()
    }

    /// Every mailbox, by address.
    pub fn mailboxes(&self) -> &BTreeMap<[u8; 32], Mailbox> {
        &self.mailboxes
    }

    /// The items a deposit of `bytes` into the mailbox at `address` would
    /// evict, in ID order, without changing anything.
    ///
    /// # Errors
    ///
    /// `TooLarge` for an item over 262,144 bytes; `Busy` where the peer's
    /// cap leaves no room.
    pub fn plan(&self, address: &[u8; 32], bytes: u64) -> Result<Vec<[u8; 16]>, TransportClass> {
        if bytes > MAILBOX_ITEM_BYTES as u64 {
            return Err(frasil_base::ErrorClass::TooLarge.into());
        }
        let empty = Mailbox::default();
        let own = self.mailboxes.get(address).unwrap_or(&empty);
        let mut mine: Vec<([u8; 16], u64)> = own.items.clone();
        let mut evicted = Vec::new();
        let mailbox_cap = Cap {
            items: DEVICE_MAILBOX_ITEMS as u64,
            bytes: DEVICE_MAILBOX_BYTES as u64,
        };
        while !mine.is_empty() && !mailbox_cap.holds(mine.len() as u64 + 1, total(&mine) + bytes) {
            evicted.push(mine.remove(0).0);
        }
        let mut others: Vec<([u8; 16], u64, bool)> = self
            .mailboxes
            .iter()
            .filter(|(at, _)| *at != address)
            .flat_map(|(_, mailbox)| {
                mailbox
                    .items
                    .iter()
                    .map(move |&(id, size)| (id, size, mailbox.claimed))
            })
            .collect();
        others.sort_unstable();
        let mut count = mine.len() as u64 + others.len() as u64 + 1;
        let mut held = total(&mine) + others.iter().map(|o| o.1).sum::<u64>() + bytes;
        if !self.cap.holds(count, held) {
            if !own.claimed {
                return Err(TransportClass::Busy);
            }
            for &(id, size, claimed) in &others {
                if self.cap.holds(count, held) {
                    break;
                }
                if !claimed {
                    evicted.push(id);
                    count -= 1;
                    held -= size;
                }
            }
            if !self.cap.holds(count, held) {
                return Err(TransportClass::Busy);
            }
        }
        evicted.sort_unstable();
        Ok(evicted)
    }

    /// Deposits an item of `bytes` into the mailbox at `address`: the
    /// evictions of [`plan`](Self::plan), then the item under the next ID.
    ///
    /// # Errors
    ///
    /// As [`plan`](Self::plan); a refused deposit changes nothing.
    pub fn deposit(&mut self, address: [u8; 32], bytes: u64) -> Result<Deposited, TransportClass> {
        let evicted = self.plan(&address, bytes)?;
        for mailbox in self.mailboxes.values_mut() {
            mailbox.items.retain(|(id, _)| !evicted.contains(id));
        }
        let id = self.next.to_be_bytes();
        self.next += 1;
        self.mailbox(address).items.push((id, bytes));
        Ok(Deposited { id, evicted })
    }
}

fn total(items: &[([u8; 16], u64)]) -> u64 {
    items.iter().map(|item| item.1).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mailbox_at_its_own_cap_evicts_its_oldest() {
        let mut peer = PeerMailboxes::new(Cap::NONE, 1);
        let at = [1; 32];
        for _ in 0..DEVICE_MAILBOX_ITEMS {
            peer.deposit(at, 10).unwrap();
        }
        let next = peer.deposit(at, 10).unwrap();
        assert_eq!(next.evicted, vec![1u128.to_be_bytes()]);
        assert_eq!(
            peer.plan(&at, MAILBOX_ITEM_BYTES as u64 + 1),
            Err(frasil_base::ErrorClass::TooLarge.into())
        );
    }

    #[test]
    fn a_claim_lapses_after_the_retention() {
        assert!(!claimed(None, 5, 10));
        assert!(claimed(Some(0), 9, 10));
        assert!(!claimed(Some(0), 10, 10));
        assert!(!claimed(Some(6), 5, 10));
        assert!(item_kept(0, false, None, 4, 10, 5));
        assert!(!item_kept(0, false, None, 5, 10, 5));
        assert!(item_kept(0, false, Some(4), 9, 10, 5));
        assert!(!item_kept(0, false, Some(5), 5, 10, 5));
    }
}
