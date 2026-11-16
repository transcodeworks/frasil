//! Invite drops at the peer (ext-invite-links.md, "The drop and its
//! messages", "Making an invite and keeping drops"), feature
//! `ext-invite-links`.
//!
//! A `MailboxPut` of kind 4 places a drop, in order:
//!
//! ```text
//! 1. Keys 2 and 4 are 32 bytes; key 5 is 1 to 604,800.            else Malformed
//! 2. The drop is at most 65,536 bytes.                            else TooLarge
//! 3. The connection holds the store right for key 4's space.      else CredentialRefused
//! 4. No drop is held at the address.                              else Conflict
//! 5. The space stays within its quota.                            else QuotaExceeded
//! ```
//!
//! `frasil-transport` reads steps 1 and 2, and `frasil-peers`' drop store
//! runs steps 3 to 5. The peer keeps each drop for its lifetime plus 60
//! seconds of its own timeline, at rest so that a restart keeps it, counts
//! it in its space's usage meanwhile, and serves it to anyone who names the
//! address: as the one item of `MailboxItems`, and on the server binding at
//! `GET /frasil/p1/mailbox/4/{address}`. `MailboxDelete` removes a drop only
//! on a connection that proved the upload entry it was placed under. A
//! space's erasure removes its drops.
//!
//! A drop is placed, kept in memory, swept and served by the node that
//! answers for its space. Beside its record, the drop's address alone names
//! its space at rest, so that a collection by address at any node of a
//! cluster finds the node that serves it (crate `cluster`, module `route`).

use crate::records::{KeptDrop, Records};
use crate::space::Space;
use crate::state::{Core, Grant, Items, Outgoing, lock, refused};
use crate::util::log;
use crate::writer::made;
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_peers::ext_invite_links::{DROP_GRACE, DROP_LIFETIME_MAX, DropStore, PlacedDrop};
use frasil_store::{Commit, StoreError};
use frasil_transport::ext_invite_links::{DropPut, MailboxDelete};
use frasil_transport::messages::Accepted;
use std::collections::BTreeMap;

/// The item ID a drop carries in `MailboxItems` and on the server binding
/// (ext-invite-links.md, "The drop and its messages"): 16 zero bytes, since
/// a drop is its mailbox's one item. A request that gives `after` receives
/// none.
pub(crate) const DROP_ITEM: [u8; 16] = [0; 16];

/// The peer's invite drops: `frasil-peers`' store, which decides and
/// serves, and what the peer keeps of each drop at rest.
#[derive(Debug, Default)]
pub(crate) struct Drops {
    store: DropStore,
    kept: BTreeMap<[u8; 32], KeptDrop>,
    /// Counts the changes made in memory, so that a reading of the records
    /// replaces memory only if none was made meanwhile.
    pub(crate) changes: u64,
}

/// When a kept drop goes, on the peer's timeline.
fn until(kept: &KeptDrop) -> u64 {
    kept.placed
        .saturating_add(kept.lifetime.min(DROP_LIFETIME_MAX))
        .saturating_add(DROP_GRACE)
}

impl Drops {
    /// The drops kept at rest, each placed again as it was.
    pub(crate) fn open(records: &Records) -> Result<Self, StoreError> {
        let mut drops = Self::default();
        for kept in records.drops()? {
            let placed = PlacedDrop {
                address: kept.address,
                space: kept.space,
                drop: &kept.drop,
                lifetime: kept.lifetime,
            };
            if drops
                .store
                .put(&placed, Some(kept.entry), u64::MAX, kept.placed)
                .is_ok()
            {
                drops.kept.insert(kept.address, kept);
            }
        }
        Ok(drops)
    }

    /// The drops a space holds at `now`, and their bytes.
    pub(crate) fn count(&self, space: &[u8; 32], now: u64) -> (u64, u64) {
        let held = self
            .kept
            .values()
            .filter(|kept| kept.space == *space && until(kept) > now)
            .count() as u64;
        (held, self.store.usage(space, now))
    }
}

impl Core {
    /// Sets a space's count of drops and their bytes, which its usage
    /// counts.
    pub(crate) fn count_drops(&self, space: &mut Space, now: u64) {
        let (drops, bytes) = lock(&self.drops).count(space.id.as_bytes(), now);
        space.drops = drops;
        space.drop_bytes = bytes;
    }

    /// A `MailboxPut` of kind 4, whose shape steps 1 and 2 checked: steps 3
    /// to 5, then the drop kept at rest.
    pub(crate) async fn drop_put(
        &self,
        grants: &BTreeMap<EventId, Grant>,
        put: &DropPut,
        now: Reading,
    ) -> Outgoing {
        let space_id = EventId(put.space);
        let Ok(writing) = self.write(space_id).await else {
            return refused(put.request, "busy");
        };
        // 3. The store right, and the entry the connection proved.
        let entry = grants
            .get(&space_id)
            .filter(|grant| grant.rights.store)
            .and_then(|grant| grant.upload)
            .filter(|_| writing.hosted());
        // 5. Room in the space's quota, and with ext-libraries in its
        // library's.
        let libraries = self.settings.extensions.libraries;
        if libraries {
            self.know_library_usage(&space_id).await;
        }
        let quota_left = writing.state().space.as_ref().map_or(0, |held| {
            self.settings.space_quota.saturating_sub(held.used())
        });
        let room = libraries
            .then(|| self.library_room(&space_id, put.drop.len() as u64))
            .flatten();
        let quota_left = if !libraries || room.is_some() {
            quota_left
        } else {
            0
        };
        let pending = {
            let mut drops = lock(&self.drops);
            let answer = drops
                .store
                .put(&put.placed(), entry, quota_left, now.timeline);
            let (Ok(()), Some(entry)) = (answer, entry) else {
                let code = answer.err().map_or("credential_refused", |r| r.name());
                return refused(put.request, code);
            };
            let kept = KeptDrop {
                space: put.space,
                address: put.address,
                entry,
                placed: now.timeline,
                lifetime: put.lifetime,
                drop: put.drop.clone(),
            };
            // 4. No drop is held at the address, by any space: its locator
            // is absent, checked where the address's shard is kept, so a
            // drop another node holds is not taken over.
            let locator = Records::drop_locator_address(&put.address);
            let pending = self.writer.submit(
                Commit::new(
                    vec![
                        (
                            Records::drop_address(&put.space, &put.address),
                            Records::drop_record(&kept),
                        ),
                        (locator.clone(), Records::drop_locator_record(&put.space)),
                    ],
                    Vec::new(),
                )
                .expecting(&locator, None),
            );
            drops.kept.insert(put.address, kept);
            drops.changes += 1;
            (pending, entry)
        };
        let (pending, entry) = pending;
        let outcome = pending.await;
        let held_elsewhere = matches!(outcome, Ok(false));
        if let Err(error) = made(outcome) {
            if !held_elsewhere {
                log(format_args!("a drop was not kept: {error}"));
            }
            let mut drops = lock(&self.drops);
            drops.kept.remove(&put.address);
            drops.changes += 1;
            let _ = drops
                .store
                .delete(&put.address, &put.space, Some(&entry), now.timeline);
            return refused(
                put.request,
                if held_elsewhere {
                    frasil_peers::Code::Conflict.name()
                } else {
                    "busy"
                },
            );
        }
        if let Some(space) = writing.state().space.as_mut() {
            self.count_drops(space, now.timeline);
            self.note(space);
        }
        Outgoing::Control(
            Accepted {
                request: put.request,
            }
            .encode(),
        )
    }

    /// `MailboxDelete`: the drop removed, on a connection that proved the
    /// entry it was placed under (else `credential_refused`; `not_found`
    /// if none is held).
    pub(crate) async fn drop_delete(
        &self,
        grants: &BTreeMap<EventId, Grant>,
        delete: &MailboxDelete,
        now: Reading,
    ) -> Outgoing {
        let space_id = EventId(delete.space);
        let entry = grants.get(&space_id).and_then(|grant| grant.upload);
        let Ok(writing) = self.write(space_id).await else {
            return refused(delete.request, "busy");
        };
        let pending = {
            let mut drops = lock(&self.drops);
            let answer =
                drops
                    .store
                    .delete(&delete.address, &delete.space, entry.as_ref(), now.timeline);
            if let Err(refusal) = answer {
                return refused(delete.request, refusal.name());
            }
            drops.kept.remove(&delete.address);
            drops.changes += 1;
            self.writer.submit(Commit::new(
                Vec::new(),
                vec![
                    Records::drop_address(&delete.space, &delete.address),
                    Records::drop_locator_address(&delete.address),
                ],
            ))
        };
        if let Err(error) = made(pending.await) {
            log(format_args!("a drop's deletion was not kept: {error}"));
        }
        if let Some(space) = writing.state().space.as_mut() {
            self.count_drops(space, now.timeline);
            self.note(space);
        }
        Outgoing::Control(
            Accepted {
                request: delete.request,
            }
            .encode(),
        )
    }

    /// Forgets the drops past their time, and counts each open space's
    /// drops again. Only the drops of the spaces this node keeps go at rest
    /// too: another node places, sweeps and serves the others.
    pub(crate) async fn sweep_drops(&self, now: Reading) {
        let now = now.timeline;
        let pending = {
            let mut drops = lock(&self.drops);
            drops.store.expire(now);
            let gone: Vec<KeptDrop> = drops
                .kept
                .values()
                .filter(|kept| until(kept) <= now)
                .cloned()
                .collect();
            for kept in &gone {
                drops.kept.remove(&kept.address);
            }
            if !gone.is_empty() {
                drops.changes += 1;
            }
            let deletes: Vec<Vec<u8>> = gone
                .iter()
                .filter(|kept| self.keeps_space(&EventId(kept.space)))
                .flat_map(|kept| {
                    [
                        Records::drop_address(&kept.space, &kept.address),
                        Records::drop_locator_address(&kept.address),
                    ]
                })
                .collect();
            (!deletes.is_empty()).then(|| self.writer.submit(Commit::new(Vec::new(), deletes)))
        };
        if let Some(pending) = pending
            && let Err(error) = made(pending.await)
        {
            log(format_args!("a drop sweep was not kept: {error}"));
        }
        self.each_open(|space| {
            self.count_drops(space, now);
            self.note(space);
        });
    }

    /// A space's erasure: its drops go with it. Their records are among the
    /// space's addresses at rest.
    pub(crate) fn erase_drops(&self, space: &EventId) {
        let mut drops = lock(&self.drops);
        let gone: Vec<KeptDrop> = drops
            .kept
            .values()
            .filter(|kept| kept.space == *space.as_bytes())
            .cloned()
            .collect();
        if !gone.is_empty() {
            drops.changes += 1;
        }
        for kept in gone {
            drops.kept.remove(&kept.address);
            let _ = drops
                .store
                .delete(&kept.address, &kept.space, Some(&kept.entry), 0);
        }
    }

    /// The drop at an address, for anyone who names it: its one item, or
    /// none.
    pub(crate) fn drop_items(
        &self,
        address: &[u8; 32],
        after: Option<&[u8; 16]>,
        now: Reading,
    ) -> Items {
        match lock(&self.drops).store.get(address, now.timeline) {
            Some(drop) if after.is_none() => vec![(DROP_ITEM, drop.to_vec())],
            _ => Vec::new(),
        }
    }
}
