//! The token budget (ext-deposit-tokens.md, 3.8 The token budget).
//!
//! A peer that implements this extension keeps two budgets over its device
//! mailboxes, each a number of items and of bytes: the **anonymous
//! budget**, transport.md's peer's cap, and the **token budget**. A token
//! deposit counts only in the token budget, every other deposit only in
//! the anonymous one.
//!
//! - Within one mailbox, both kinds share transport.md's cap of 64 items
//!   and 4 MiB. A token deposit past it evicts the mailbox's oldest
//!   anonymous items first, then its oldest token items. An anonymous
//!   deposit past it evicts the mailbox's oldest anonymous items only; one
//!   that would have to evict a token item is refused `busy`.
//! - Across the peer, a deposit that would pass its budget first evicts,
//!   oldest first, items of its own kind in mailboxes that are not claimed,
//!   unless its own mailbox is not claimed; if room is still lacking, it is
//!   refused `busy`. Neither budget takes room from the other.
//! - A deposit refused `busy` evicts nothing.
//!
//! [`Mailboxes`] holds what these rules read: each mailbox's claim and its
//! items' IDs, sizes and kinds, in deposit order.

use std::collections::BTreeMap;

use frasil_transport::caps::Cap;
use frasil_transport::frame::MAILBOX_ITEM_BYTES;
use frasil_transport::mailbox::{DEVICE_MAILBOX_BYTES, DEVICE_MAILBOX_ITEMS};

use crate::errors::TokenClass;

/// One item a device mailbox holds, as the budgets count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Held {
    /// The ID the peer assigned, in deposit order.
    pub id: [u8; 16],
    /// Its bytes.
    pub bytes: u64,
    /// Whether a token paid for it.
    pub paid: bool,
}

/// One device mailbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mailbox {
    /// Whether its device has claimed it (transport.md, "Claimed device
    /// mailboxes").
    pub claimed: bool,
    /// Its items, oldest first.
    pub items: Vec<Held>,
}

/// A deposit the budgets took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The ID the peer assigned the item.
    pub id: [u8; 16],
    /// The items evicted for it, in ID order.
    pub evicted: Vec<[u8; 16]>,
}

/// A peer's device mailboxes under the anonymous budget and the token
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailboxes {
    anonymous: Cap,
    tokens: Cap,
    mailboxes: BTreeMap<[u8; 32], Mailbox>,
    next: u128,
}

impl Mailboxes {
    /// No mailbox yet, under these budgets; item IDs count from `first`.
    pub fn new(anonymous: Cap, tokens: Cap, first: u128) -> Self {
        Self {
            anonymous,
            tokens,
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

    /// Sets whether a mailbox is claimed. A mailbox left empty and not
    /// claimed is forgotten.
    pub fn set_claimed(&mut self, address: &[u8; 32], claimed: bool) {
        if claimed {
            self.mailbox(*address).claimed = true;
        } else if let Some(mailbox) = self.mailboxes.get_mut(address) {
            mailbox.claimed = false;
            if mailbox.items.is_empty() {
                self.mailboxes.remove(address);
            }
        }
    }

    /// Takes an item out of a mailbox: one collected past its retention,
    /// or one whose deposit was not kept. A mailbox left empty and not
    /// claimed is forgotten.
    pub fn remove(&mut self, address: &[u8; 32], id: &[u8; 16]) -> Option<Held> {
        let mailbox = self.mailboxes.get_mut(address)?;
        let at = mailbox.items.iter().position(|item| item.id == *id)?;
        let held = mailbox.items.remove(at);
        if mailbox.items.is_empty() && !mailbox.claimed {
            self.mailboxes.remove(address);
        }
        Some(held)
    }

    /// Keeps an item under an ID the peer assigned, whatever the budgets,
    /// as its records hold it: its mailbox's items stay in ID order.
    pub fn load(&mut self, address: [u8; 32], held: Held) {
        let items = &mut self.mailbox(address).items;
        let at = items.partition_point(|item| item.id < held.id);
        items.insert(at, held);
    }

    /// The items a deposit of `bytes` into the mailbox at `address` would
    /// evict, in ID order, without changing anything. `paid` says whether
    /// a token pays for it.
    ///
    /// # Errors
    ///
    /// `TooLarge` for an item over 262,144 bytes; `Busy` where the rules
    /// leave no room.
    pub fn plan(
        &self,
        address: &[u8; 32],
        bytes: u64,
        paid: bool,
    ) -> Result<Vec<[u8; 16]>, TokenClass> {
        if bytes > MAILBOX_ITEM_BYTES as u64 {
            return Err(frasil_base::ErrorClass::TooLarge.into());
        }
        let empty = Mailbox::default();
        let own = self.mailboxes.get(address).unwrap_or(&empty);
        let mut mine = own.items.clone();
        let mut evicted = Vec::new();
        // Within the mailbox.
        let fits = |items: &[Held]| {
            items.len() < DEVICE_MAILBOX_ITEMS
                && items.iter().map(|i| i.bytes).sum::<u64>() + bytes <= DEVICE_MAILBOX_BYTES as u64
        };
        while !fits(&mine) {
            let victim = mine
                .iter()
                .position(|item| !item.paid)
                .or_else(|| paid.then_some(0).filter(|_| !mine.is_empty()));
            let Some(victim) = victim else {
                return Err(TokenClass::Busy);
            };
            evicted.push(mine.remove(victim).id);
        }
        // Across the peer, in this deposit's own budget.
        let cap = if paid { self.tokens } else { self.anonymous };
        let others = || {
            self.mailboxes
                .iter()
                .filter(move |(at, _)| *at != address)
                .flat_map(move |(_, mailbox)| {
                    mailbox
                        .items
                        .iter()
                        .filter(move |item| item.paid == paid)
                        .map(move |item| (*item, mailbox.claimed))
                })
        };
        let same = mine.iter().filter(|item| item.paid == paid);
        let (mut count, mut held) = others().fold(
            (
                same.clone().count() as u64 + 1,
                same.map(|i| i.bytes).sum::<u64>().saturating_add(bytes),
            ),
            |(count, held), (item, _)| (count + 1, held.saturating_add(item.bytes)),
        );
        let holds = |count: u64, held: u64| count <= cap.items && held <= cap.bytes;
        if !holds(count, held) {
            if !own.claimed {
                return Err(TokenClass::Busy);
            }
            // Only a deposit past its budget reads the others in order.
            let mut others: Vec<(Held, bool)> = others().collect();
            others.sort_unstable();
            for (item, claimed) in &others {
                if holds(count, held) {
                    break;
                }
                if !claimed {
                    evicted.push(item.id);
                    count -= 1;
                    held -= item.bytes;
                }
            }
            if !holds(count, held) {
                return Err(TokenClass::Busy);
            }
        }
        evicted.sort_unstable();
        Ok(evicted)
    }

    /// Whether a token deposit has room: section 3.7, step 7.
    pub fn room(&self, address: &[u8; 32], bytes: u64) -> bool {
        self.plan(address, bytes, true).is_ok()
    }

    /// Keeps a deposit: the evictions of [`plan`](Self::plan), then the
    /// item under the next ID.
    ///
    /// # Errors
    ///
    /// As [`plan`](Self::plan); a refused deposit changes nothing.
    pub fn deposit(
        &mut self,
        address: [u8; 32],
        bytes: u64,
        paid: bool,
    ) -> Result<Kept, TokenClass> {
        let evicted = self.plan(&address, bytes, paid)?;
        for mailbox in self.mailboxes.values_mut() {
            mailbox.items.retain(|item| !evicted.contains(&item.id));
        }
        let id = self.next.to_be_bytes();
        self.next += 1;
        self.mailbox(address).items.push(Held { id, bytes, paid });
        Ok(Kept { id, evicted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_budget_takes_room_from_the_other() {
        let one = Cap {
            items: 1,
            bytes: 1 << 20,
        };
        let mut boxes = Mailboxes::new(one, one, 1);
        let (a, b) = ([1; 32], [2; 32]);
        boxes.mailbox(a).claimed = true;
        boxes.deposit(b, 10, false).unwrap();
        boxes.deposit(b, 10, true).unwrap();
        // A's anonymous deposit evicts B's anonymous item, never its token
        // item; A's token deposit evicts B's token item.
        let anonymous = boxes.deposit(a, 10, false).unwrap();
        assert_eq!(anonymous.evicted, vec![1u128.to_be_bytes()]);
        let paid = boxes.deposit(a, 10, true).unwrap();
        assert_eq!(paid.evicted, vec![2u128.to_be_bytes()]);
        // B is not claimed: its deposits evict nothing elsewhere.
        assert_eq!(boxes.deposit(b, 10, true), Err(TokenClass::Busy));
        assert_eq!(boxes.deposit(b, 10, false), Err(TokenClass::Busy));
        assert!(!boxes.room(&b, 10));
    }
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn a_mailbox_at_64_items_evicts_anonymous_items_first() {
        let mut boxes = Mailboxes::new(Cap::NONE, Cap::NONE, 1);
        let at = [3; 32];
        boxes.deposit(at, 10, true).unwrap();
        for _ in 1..DEVICE_MAILBOX_ITEMS {
            boxes.deposit(at, 10, false).unwrap();
        }
        // The oldest item is a token item; a token deposit evicts the
        // oldest anonymous one, the second.
        let kept = boxes.deposit(at, 10, true).unwrap();
        assert_eq!(kept.evicted, vec![2u128.to_be_bytes()]);
        // Fill with token items: an anonymous deposit then evicts the
        // anonymous items left, then is refused.
        let mut boxes = Mailboxes::new(Cap::NONE, Cap::NONE, 1);
        for _ in 0..DEVICE_MAILBOX_ITEMS {
            boxes.deposit(at, 10, true).unwrap();
        }
        assert_eq!(boxes.deposit(at, 10, false), Err(TokenClass::Busy));
        assert_eq!(boxes.mailboxes()[&at].items.len(), DEVICE_MAILBOX_ITEMS);
        // A token deposit evicts the oldest token item.
        let kept = boxes.deposit(at, 10, true).unwrap();
        assert_eq!(kept.evicted, vec![1u128.to_be_bytes()]);
        assert_eq!(
            boxes.plan(&at, MAILBOX_ITEM_BYTES as u64 + 1, true),
            Err(frasil_base::ErrorClass::TooLarge.into())
        );
    }
}
