//! What memory keeps of the device mailboxes (transport.md, 2.7 Mailboxes
//! and 3.14 Mailboxes): each item's ID, length, deposit's sight, whether a
//! token paid for it and whether its mailbox was claimed when it came, and
//! each mailbox's claim. The items themselves stay in the records and are
//! read when a device collects them, so the peer's memory does not grow
//! with what the mailboxes hold, nor does its start read every item into
//! memory.
//!
//! Anyone deposits, with no credential, "subject to the peer's rate
//! limits". The rules a deposit is kept or refused by are
//! `frasil_deposit_tokens::budget`'s, which this module holds per part:
//!
//! - Each mailbox holds at most 64 items and 4 MiB. A deposit past either
//!   evicts the mailbox's oldest items: for a token deposit, its anonymous
//!   items first, then its token items; for an anonymous deposit, its
//!   anonymous items only, and one that would have to evict a token item
//!   is refused `busy` (ext-deposit-tokens.md, 3.8 The token budget).
//! - Every mailbox of a part together holds at most the part's share of
//!   the anonymous budget, the operator's caps
//!   ([`crate::config::DeviceMailLimits`]), and of the token budget
//!   (crate `deposit`). A deposit that would pass its budget first evicts,
//!   oldest first, items of its own kind in mailboxes that are not
//!   claimed, unless its own mailbox is not claimed; if room is still
//!   lacking it is refused `busy` and evicts nothing (transport.md, "The
//!   peer's caps"). Neither budget takes room from the other.
//! - A mailbox is claimed from its device's first collection that passes
//!   the checks until `mailbox_retention` passes with no further one; an
//!   item that came while it was not claimed is kept `uncollected_retention`
//!   unless the mailbox is claimed by then (transport.md, "Claimed device
//!   mailboxes"); `frasil_transport::caps` judges both.
//!
//! So a stranger who fills the peer delays new deposits in claimed
//! mailboxes until retention frees room, never pushes out mail in a
//! mailbox its device collects from, and loses first what it put where
//! nobody collects.

use crate::state::Window;
use frasil_deposit_tokens::budget::{Held as Budgeted, Mailboxes};
use frasil_transport::caps::{Cap, claimed, item_kept};
use frasil_transport::mailbox::ITEMS_BYTES;
use std::collections::BTreeMap;

/// An item, as memory keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Held {
    /// The ID the peer assigned, in deposit order.
    pub id: [u8; 16],
    /// The item's length in bytes.
    pub len: usize,
    /// Its deposit's sight on the timeline.
    pub sight: u64,
    /// Whether a token paid for it (ext-deposit-tokens.md).
    pub paid: bool,
    /// Whether its mailbox was not claimed when it came.
    pub unclaimed: bool,
}

/// A device mailbox's claim: its last collection that passed the checks,
/// and the collection the claim began with, on the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Claim {
    /// The last collection.
    pub last: u64,
    /// The first collection of the claim the mailbox holds now.
    pub since: u64,
}

/// What each part of the device mailboxes may hold: its share of the
/// anonymous budget and of the token budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Caps {
    /// The anonymous budget's share.
    pub anonymous: Cap,
    /// The token budget's share.
    pub tokens: Cap,
}

/// An item named by its mailbox's address and its ID.
pub(crate) type Item = ([u8; 32], [u8; 16]);

/// A deposit refused: the rules leave no room for it, and it evicted
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Full;

/// What memory keeps of one item besides the budgets' view of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kept {
    address: [u8; 32],
    sight: u64,
    unclaimed: bool,
}

/// The device mailboxes, by part, and their claims. A part is the share of
/// mailboxes one node decides for: a mailbox shard, or every mailbox when
/// the records are in no shards.
#[derive(Debug, Clone)]
pub(crate) struct DeviceMail {
    caps: Caps,
    parts: BTreeMap<String, Mailboxes>,
    items: BTreeMap<[u8; 16], Kept>,
    claims: BTreeMap<[u8; 32], Claim>,
}

impl DeviceMail {
    /// No mailbox yet, each part under `caps`.
    pub(crate) fn new(caps: Caps) -> Self {
        Self {
            caps,
            parts: BTreeMap::new(),
            items: BTreeMap::new(),
            claims: BTreeMap::new(),
        }
    }

    fn part(&mut self, part: &str) -> &mut Mailboxes {
        let caps = self.caps;
        self.parts
            .entry(part.to_owned())
            .or_insert_with(|| Mailboxes::new(caps.anonymous, caps.tokens, 0))
    }

    /// Whether a mailbox is claimed at `now`.
    pub(crate) fn is_claimed(&self, address: &[u8; 32], now: u64, retention: u64) -> bool {
        self.claims
            .get(address)
            .is_some_and(|claim| claimed(Some(claim.last), now, retention))
    }

    /// A mailbox's claim, as last recorded.
    pub(crate) fn claim(&self, address: &[u8; 32]) -> Option<Claim> {
        self.claims.get(address).copied()
    }

    /// The items of a mailbox, oldest first.
    pub(crate) fn items(&self, part: &str, address: &[u8; 32]) -> Vec<Held> {
        let Some(mailbox) = self
            .parts
            .get(part)
            .and_then(|mailboxes| mailboxes.mailboxes().get(address))
        else {
            return Vec::new();
        };
        mailbox
            .items
            .iter()
            .filter_map(|item| {
                let kept = self.items.get(&item.id)?;
                Some(Held {
                    id: item.id,
                    len: usize::try_from(item.bytes).unwrap_or(usize::MAX),
                    sight: kept.sight,
                    paid: item.paid,
                    unclaimed: kept.unclaimed,
                })
            })
            .collect()
    }

    /// The items after an ID, oldest first, at most 262,144 bytes of them
    /// (transport.md, 2.7 Mailboxes).
    pub(crate) fn after(
        &self,
        part: &str,
        address: &[u8; 32],
        after: Option<&[u8; 16]>,
    ) -> Vec<Held> {
        let mut out = Vec::new();
        let mut total = 0;
        for held in self.items(part, address) {
            if after.is_some_and(|after| held.id <= *after) {
                continue;
            }
            if total + held.len > ITEMS_BYTES {
                break;
            }
            total += held.len;
            out.push(held);
        }
        out
    }

    /// Keeps an item read from the records, whatever the budgets.
    pub(crate) fn load(&mut self, part: &str, address: [u8; 32], held: Held) {
        self.part(part).load(
            address,
            Budgeted {
                id: held.id,
                bytes: held.len as u64,
                paid: held.paid,
            },
        );
        self.items.insert(
            held.id,
            Kept {
                address,
                sight: held.sight,
                unclaimed: held.unclaimed,
            },
        );
    }

    /// Keeps a claim read from the records.
    pub(crate) fn load_claim(
        &mut self,
        part: &str,
        address: [u8; 32],
        claim: Claim,
        now: u64,
        retention: u64,
    ) {
        self.claims.insert(address, claim);
        if claimed(Some(claim.last), now, retention) {
            self.part(part).set_claimed(&address, true);
        }
    }

    /// Whether a deposit of `len` bytes into a mailbox has room, a token
    /// paying for it or not, without changing anything: for
    /// ext-deposit-tokens.md, 3.7 Redeeming, step 7.
    pub(crate) fn room(
        &mut self,
        part: &str,
        address: &[u8; 32],
        len: usize,
        paid: bool,
        now: u64,
        retention: u64,
    ) -> bool {
        let claimed = self.is_claimed(address, now, retention);
        let mailboxes = self.part(part);
        if claimed {
            mailboxes.set_claimed(address, true);
        }
        mailboxes.plan(address, len as u64, paid).is_ok()
    }

    /// A deposit under the ID `id` at the sight `now`, a token paying for
    /// it or not: the items the rules evict for it, each with its
    /// mailbox's address.
    ///
    /// # Errors
    ///
    /// [`Full`] where the rules leave no room; nothing changes then.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deposit(
        &mut self,
        part: &str,
        address: [u8; 32],
        id: [u8; 16],
        len: usize,
        paid: bool,
        now: u64,
        retention: u64,
    ) -> Result<Vec<Item>, Full> {
        let claimed = self.is_claimed(&address, now, retention);
        let mailboxes = self.part(part);
        mailboxes.set_claimed(&address, claimed);
        let planned = mailboxes
            .plan(&address, len as u64, paid)
            .map_err(|_| Full)?;
        let mut evicted = Vec::with_capacity(planned.len());
        for old in planned {
            if let Some(kept) = self.items.remove(&old) {
                self.part(part).remove(&kept.address, &old);
                evicted.push((kept.address, old));
            }
        }
        self.load(
            part,
            address,
            Held {
                id,
                len,
                sight: now,
                paid,
                unclaimed: !claimed,
            },
        );
        Ok(evicted)
    }

    /// Forgets an item: one swept, or one whose deposit was not kept.
    pub(crate) fn remove(&mut self, part: &str, address: &[u8; 32], id: &[u8; 16]) -> bool {
        if self.items.remove(id).is_none() {
            return false;
        }
        self.part(part).remove(address, id);
        true
    }

    /// A collection that passed the checks, at `now`: the mailbox's claim
    /// after it, and whether the claim began with it.
    pub(crate) fn collect(
        &mut self,
        part: &str,
        address: [u8; 32],
        now: u64,
        retention: u64,
    ) -> (Claim, bool) {
        let held = self.is_claimed(&address, now, retention);
        let since = match self.claims.get(&address) {
            Some(claim) if held => claim.since,
            _ => now,
        };
        let claim = Claim { last: now, since };
        self.claims.insert(address, claim);
        self.part(part).set_claimed(&address, true);
        (claim, !held)
    }

    /// The items no longer kept at `now`, in the mailboxes `keeps` names:
    /// each mailbox's address and the item's ID (transport.md, "Claimed
    /// device mailboxes").
    pub(crate) fn expired(
        &self,
        keeps: impl Fn(&[u8; 32]) -> bool,
        now: u64,
        retention: u64,
        uncollected: u64,
    ) -> Vec<([u8; 32], [u8; 16])> {
        self.items
            .iter()
            .filter(|(_, kept)| keeps(&kept.address))
            .filter(|(_, kept)| {
                let since = self
                    .claims
                    .get(&kept.address)
                    .map(|claim| claim.since)
                    .filter(|since| *since >= kept.sight);
                !item_kept(
                    kept.sight,
                    !kept.unclaimed,
                    since,
                    now,
                    retention,
                    uncollected,
                )
            })
            .map(|(id, kept)| (kept.address, *id))
            .collect()
    }

    /// The claims that lapsed by `now`, in the mailboxes `keeps` names:
    /// their mailboxes are no longer claimed, and are forgotten. Returns
    /// their addresses.
    pub(crate) fn lapse(
        &mut self,
        keeps: impl Fn(&[u8; 32]) -> (bool, String),
        now: u64,
        retention: u64,
    ) -> Vec<[u8; 32]> {
        let lapsed: Vec<([u8; 32], String)> = self
            .claims
            .iter()
            .filter(|(_, claim)| !claimed(Some(claim.last), now, retention))
            .filter_map(|(address, _)| {
                let (kept, part) = keeps(address);
                kept.then_some((*address, part))
            })
            .collect();
        for (address, part) in &lapsed {
            self.claims.remove(address);
            self.part(part).set_claimed(address, false);
        }
        lapsed.into_iter().map(|(address, _)| address).collect()
    }

    /// The items each kind holds in a part: anonymous, then token items,
    /// each as a count and bytes.
    #[cfg(test)]
    pub(crate) fn held(&self, part: &str) -> [(u64, u64); 2] {
        let mut out = [(0, 0); 2];
        if let Some(mailboxes) = self.parts.get(part) {
            for item in mailboxes.mailboxes().values().flat_map(|m| &m.items) {
                let at = &mut out[usize::from(item.paid)];
                at.0 += 1;
                at.1 += item.bytes;
            }
        }
        out
    }
}

/// How many sources' windows are kept before those idle for a minute are
/// dropped.
const PRUNE_AT: usize = 4096;

/// What each source did in the last minute: the deposits it made, or the
/// tokens it had refused.
#[derive(Debug, Default)]
pub(crate) struct Deposits {
    windows: BTreeMap<String, Window>,
}

impl Deposits {
    /// Counts a deposit from `source` at `now`, on the timeline, unless it
    /// already made `limit` in the minute before. A deposit with no source
    /// (crate `source`, [`crate::source::NONE`]) is under no rate per
    /// source: only the caps bound it.
    pub(crate) fn admit(&mut self, source: &str, now: u64, limit: usize) -> bool {
        if source == crate::source::NONE {
            return true;
        }
        if self.windows.len() >= PRUNE_AT && !self.windows.contains_key(source) {
            self.prune(now);
        }
        self.windows
            .entry(source.to_owned())
            .or_default()
            .admit(now, 60, limit)
    }

    /// Whether `source` made fewer than `limit` in the minute before `now`,
    /// counting nothing.
    pub(crate) fn below(&self, source: &str, now: u64, limit: usize) -> bool {
        if source == crate::source::NONE {
            return true;
        }
        self.windows
            .get(source)
            .is_none_or(|window| window.clone().admit(now, 60, limit))
    }

    /// Drops the windows of sources that made no deposit in the last
    /// minute.
    pub(crate) fn prune(&mut self, now: u64) {
        self.windows.retain(|_, window| !window.idle(now, 60));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    const RETENTION: u64 = 30 * DAY;
    const UNCOLLECTED: u64 = 3 * DAY;

    fn id(n: u8) -> [u8; 16] {
        let mut id = [0; 16];
        id[15] = n;
        id
    }

    fn mail(items: u64, bytes: u64) -> DeviceMail {
        DeviceMail::new(Caps {
            anonymous: Cap { items, bytes },
            tokens: Cap { items, bytes },
        })
    }

    fn put(
        mail: &mut DeviceMail,
        address: u8,
        n: u8,
        len: usize,
        paid: bool,
    ) -> Result<Vec<u8>, Full> {
        mail.deposit("p", [address; 32], id(n), len, paid, 0, RETENTION)
            .map(|evicted| evicted.iter().map(|(_, id)| id[15]).collect())
    }

    #[test]
    fn a_full_part_refuses_an_unclaimed_mailbox_and_keeps_what_it_holds() {
        let mut mail = mail(2, 1000);
        assert!(put(&mut mail, 1, 1, 10, false).is_ok());
        assert!(put(&mut mail, 2, 2, 10, false).is_ok());
        // Neither mailbox is claimed: a third is refused, and evicts
        // nothing.
        assert_eq!(put(&mut mail, 3, 3, 10, false), Err(Full));
        assert_eq!(mail.held("p")[0], (2, 20));
        // Another part has room of its own.
        assert!(
            mail.deposit("q", [3; 32], id(3), 10, false, 0, RETENTION)
                .is_ok()
        );
        // Room again once an item goes.
        assert!(mail.remove("p", &[1; 32], &id(1)));
        assert!(mail.items("p", &[1; 32]).is_empty());
        assert!(put(&mut mail, 4, 4, 10, false).is_ok());
    }

    #[test]
    fn a_claimed_mailbox_takes_room_from_unclaimed_ones_never_from_claimed() {
        let mut mail = mail(2, 1000);
        put(&mut mail, 1, 1, 10, false).unwrap();
        mail.collect("p", [2; 32], 0, RETENTION);
        put(&mut mail, 2, 2, 10, false).unwrap();
        // Mailbox 3's device collected: its deposit evicts mailbox 1's
        // item, oldest first, and never mailbox 2's, which is claimed.
        mail.collect("p", [3; 32], 0, RETENTION);
        assert_eq!(put(&mut mail, 3, 3, 10, false), Ok(vec![1]));
        assert_eq!(put(&mut mail, 3, 4, 10, false), Err(Full));
        assert_eq!(mail.items("p", &[2; 32]).len(), 1);
    }

    #[test]
    fn the_token_budget_is_apart_from_the_anonymous_one() {
        let mut mail = DeviceMail::new(Caps {
            anonymous: Cap {
                items: 1,
                bytes: 1000,
            },
            tokens: Cap {
                items: 2,
                bytes: 1000,
            },
        });
        put(&mut mail, 1, 1, 10, false).unwrap();
        assert_eq!(put(&mut mail, 2, 2, 10, false), Err(Full));
        // A token deposit is never refused for the anonymous budget.
        assert_eq!(put(&mut mail, 2, 3, 10, true), Ok(vec![]));
        assert_eq!(put(&mut mail, 2, 4, 10, true), Ok(vec![]));
        assert_eq!(put(&mut mail, 2, 5, 10, true), Err(Full));
        assert_eq!(mail.held("p"), [(1, 10), (2, 20)]);
        assert!(!mail.room("p", &[2; 32], 10, true, 0, RETENTION));
        assert!(!mail.room("p", &[1; 32], 10, false, 0, RETENTION));
    }

    #[test]
    fn a_full_mailbox_evicts_its_own_oldest_anonymous_items() {
        let mut mail = mail(u64::MAX, u64::MAX);
        put(&mut mail, 1, 0, 10, true).unwrap();
        for n in 1..64u8 {
            assert_eq!(put(&mut mail, 1, n, 10, false), Ok(vec![]));
        }
        // A 65th item evicts the oldest anonymous one, not the token item.
        assert_eq!(put(&mut mail, 1, 64, 10, false), Ok(vec![1]));
        assert_eq!(mail.items("p", &[1; 32]).len(), 64);
        // 16 items of the largest size fill its 4 MiB.
        let len = frasil_transport::frame::MAILBOX_ITEM_BYTES;
        let mut big = self::mail(u64::MAX, u64::MAX);
        for n in 0..16u8 {
            put(&mut big, 1, n, len, false).unwrap();
        }
        assert_eq!(put(&mut big, 1, 16, 1, false), Ok(vec![0]));
    }

    #[test]
    fn an_unclaimed_mailbox_keeps_its_items_uncollected_retention() {
        let mut mail = mail(u64::MAX, u64::MAX);
        put(&mut mail, 1, 1, 10, false).unwrap();
        mail.collect("p", [2; 32], 0, RETENTION);
        put(&mut mail, 2, 2, 10, false).unwrap();
        put(&mut mail, 3, 3, 10, false).unwrap();
        // Mailbox 3's device collects a day later: its item is kept
        // mailbox_retention from then on.
        mail.collect("p", [3; 32], DAY, RETENTION);
        let ids =
            |list: Vec<([u8; 32], [u8; 16])>| list.iter().map(|(_, id)| id[15]).collect::<Vec<_>>();
        assert_eq!(
            ids(mail.expired(|_| true, UNCOLLECTED - 1, RETENTION, UNCOLLECTED)),
            Vec::<u8>::new()
        );
        assert_eq!(
            ids(mail.expired(|_| true, UNCOLLECTED, RETENTION, UNCOLLECTED)),
            vec![1]
        );
        assert_eq!(
            ids(mail.expired(|_| true, RETENTION, RETENTION, UNCOLLECTED)),
            vec![1, 2, 3]
        );
        // A claim lapses once mailbox_retention passes with no collection.
        assert!(mail.is_claimed(&[3; 32], DAY + RETENTION - 1, RETENTION));
        let lapsed = mail.lapse(|_| (true, "p".to_owned()), DAY + RETENTION, RETENTION);
        assert_eq!(lapsed, vec![[2; 32], [3; 32]]);
        assert!(!mail.is_claimed(&[3; 32], DAY + RETENTION, RETENTION));
    }

    #[test]
    fn after_reads_in_order_within_one_message() {
        let mut mail = mail(u64::MAX, u64::MAX);
        for n in 1..=3u8 {
            put(&mut mail, 1, n, ITEMS_BYTES / 2, false).unwrap();
        }
        let ids = |items: Vec<Held>| items.iter().map(|h| h.id[15]).collect::<Vec<_>>();
        assert_eq!(ids(mail.after("p", &[1; 32], None)), vec![1, 2]);
        assert_eq!(ids(mail.after("p", &[1; 32], Some(&id(2)))), vec![3]);
    }

    #[test]
    fn a_source_is_limited_per_minute_and_forgotten_when_idle() {
        let mut deposits = Deposits::default();
        assert!(deposits.admit("a", 100, 2));
        assert!(deposits.admit("a", 110, 2));
        assert!(!deposits.below("a", 115, 2));
        assert!(!deposits.admit("a", 120, 2));
        assert!(deposits.admit("b", 120, 2));
        assert!(deposits.admit("a", 160, 2));
        deposits.prune(300);
        assert_eq!(deposits.len(), 0);
        assert!(deposits.below("a", 300, 2));
        // No source: no rate, and nothing kept.
        for at in 0..10 {
            assert!(deposits.admit(crate::source::NONE, 400 + at, 2));
        }
        assert!(deposits.below(crate::source::NONE, 410, 2));
        assert_eq!(deposits.len(), 0);
    }
}
