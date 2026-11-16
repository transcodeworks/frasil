//! Requests across a checkpoint at a replica (peers.md, 3.16 Erasure, 3.17
//! Credentials requests, 3.18 Release and restore; units.md, 3.12 Release,
//! restore and erasure at a replica; roster.md, 3.15.7, "Work concurrent
//! with a checkpoint").
//!
//! - **Where an event stands** against the chain in effect of a view
//!   ([`Checkpointed::placement`]): in the last checkpoint's past, after it,
//!   or late under some checkpoint of the chain, though a later
//!   checkpoint's past holds it. What a client reads to count releases and
//!   restores: a late one counts for nothing, and every one kept of the
//!   past is before every event after the kept checkpoint
//!   ([`Checkpointed::precedes`]; `frasil_units::release`).
//! - **Undecided checkpoints** ([`Checkpointed::undecided`]): the valid
//!   checkpoints not in effect that can still take effect in a view, of a
//!   later epoch than the chain's last, or of the epoch of a checkpoint of
//!   the chain whose ID is larger, which they could replace (section
//!   3.15.4). A replica drops nothing for an erasure while it holds one
//!   concurrent with it ([`Checkpointed::request_state`]), as a peer waits.
//! - **Late requests** ([`Checkpointed::late_requests`]): a device's own
//!   erasures, credentials requests, releases and restores that the chain
//!   in effect makes late, under any of its checkpoints, which its client
//!   signs again after the checkpoint and reports to the application.

use super::Checkpointed;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, kind};
use frasil_peers::body::{StorageBody, StorageType};
use std::collections::BTreeSet;

/// Where an event a replica holds stands against the chain in effect of
/// its view (roster.md, 3.15.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Placement {
    /// No checkpoint is in effect: every event counts as it is.
    Unchecked,
    /// In the past of the last checkpoint of the chain, or that checkpoint.
    Past,
    /// After it: its cuts reach it.
    After,
    /// Late under some checkpoint of the chain: neither in its past, nor
    /// it, nor after it. Void, even where a later checkpoint's past holds
    /// it.
    Late,
    /// Whether it follows the checkpoint waits for envelopes: held, never
    /// late.
    Pending,
}

/// A request's state at a replica against the checkpoints of its view, as
/// peers.md's steps 0 and 1 of an erasure read it at a peer (section 3.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Late under a checkpoint of the chain in effect: void, and its author
    /// signs it again after the checkpoint.
    Late,
    /// Concurrent with a checkpoint that can still take effect: the
    /// replica drops nothing for it, whatever its stability or the time
    /// it has held it.
    Wait,
    /// Neither: stability or the timeout decides it.
    Free,
}

/// A device's request that the chain in effect makes late (roster.md,
/// 3.15.7, "Work concurrent with a checkpoint").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LateRequest {
    /// The request.
    pub event: EventId,
    /// Its type: an erasure, a credentials request, a release or a
    /// restore.
    pub kind: StorageType,
}

/// Whether a storage type is one a late request of which its author signs
/// again: an erasure, a credentials request, a release or a restore.
fn signed_again(kind: StorageType) -> bool {
    matches!(
        kind,
        StorageType::Erase | StorageType::Credentials | StorageType::Release | StorageType::Restore
    )
}

impl Checkpointed<'_> {
    /// Where event `x` of the events `held` stands against the chain in
    /// effect over `held` (roster.md, 3.15.1): late when it is late under
    /// any checkpoint of the chain, neither in that checkpoint's past, nor
    /// it, nor after it, though a later checkpoint's past holds it (peers.md,
    /// 3.18; units.md, 3.12, "After a checkpoint"); else in the last
    /// checkpoint's past (that checkpoint included), or after it. A replica
    /// that forgot places each event it kept of its kept checkpoint's past
    /// ([`Self::set_kept_past`]) there, `Past`, which its log, without the
    /// order of what it dropped, cannot show.
    pub fn placement(&self, held: &BTreeSet<EventId>, x: EventId) -> Placement {
        let judged = self.judge(held);
        self.placement_in(&judged.chain, x)
    }

    fn placement_in(&self, chain: &[EventId], x: EventId) -> Placement {
        let Some(&last) = chain.last() else {
            return Placement::Unchecked;
        };
        if self.kept_past.contains(&x) {
            return Placement::Past;
        }
        let log = self.log();
        let mut pending = false;
        for &k in chain {
            if x == k || log.precedes(x, k) {
                continue;
            }
            match self.follows(x, k) {
                Ok(true) => {}
                Ok(false) => return Placement::Late,
                Err(_) => pending = true,
            }
        }
        if pending {
            Placement::Pending
        } else if x == last || log.precedes(x, last) {
            Placement::Past
        } else {
            Placement::After
        }
    }

    /// Takes the events a replica that forgot keeps of its kept
    /// checkpoint's past (roster.md, 3.15.6, "What must be kept"): units,
    /// and the releases and restores it kept, found before it dropped
    /// anything. Its log no longer orders them against what follows the
    /// checkpoint; [`Self::placement`] places them in that past and
    /// [`Self::precedes`] orders each before every event after the
    /// checkpoint. Nothing at a replica that kept everything.
    pub fn set_kept_past(&mut self, ids: impl IntoIterator<Item = EventId>) {
        if self.kept.is_some() {
            self.kept_past = ids.into_iter().collect();
        }
    }

    /// Whether event `a` precedes event `b` at this replica: its log's
    /// order, and at a replica that forgot, every event it kept of its kept
    /// checkpoint's past ([`Self::set_kept_past`]) before the checkpoint
    /// and every event that follows it, as a replica that kept everything
    /// finds them ordered (units.md, 3.12, "After a checkpoint"). Two kept
    /// events of that past are ordered by the log alone.
    pub fn precedes(&self, a: EventId, b: EventId) -> bool {
        if self.log().precedes(a, b) {
            return true;
        }
        let Some(kept) = &self.kept else {
            return false;
        };
        self.kept_past.contains(&a)
            && !self.kept_past.contains(&b)
            && (b == kept.checkpoint || self.follows_known(b, kept.checkpoint))
    }

    /// The valid checkpoints of `held` not in effect over it that can still
    /// take effect (peers.md, 3.16, "Undecided cuts", as a replica reads its
    /// own chain): of an epoch later than the last of the chain in effect
    /// (any, without one), or of the epoch of a checkpoint of the chain
    /// whose ID is larger, which it could replace (roster.md, 3.15.4): the
    /// peers crate's [`frasil_peers::cut::can_still_take_effect`], the test
    /// a peer reads of its cuts, over this replica's chain. A
    /// checkpoint the replica holds for its record (`Sealed`,
    /// `ExtensionRequired`) or whose validity it cannot judge yet is none.
    pub fn undecided(&self, held: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let chain = self.judge(held).chain.clone();
        let epoch = |c: EventId| self.record(c).map(|record| record.epoch);
        let in_effect: Vec<(u64, EventId)> =
            chain.iter().filter_map(|&c| Some((epoch(c)?, c))).collect();
        held.iter()
            .copied()
            .filter(|&k| !chain.contains(&k) && self.is_checkpoint(k))
            .filter(|&k| self.validity(k).is_valid())
            .filter(|&k| {
                epoch(k).is_some_and(|e| frasil_peers::cut::can_still_take_effect(e, k, &in_effect))
            })
            .collect()
    }

    /// The state of request `x` among the events `held` (peers.md, 3.16,
    /// steps 0 and 1, as a replica reads them): `Late` when it is late under
    /// any checkpoint of the chain in effect, though a later checkpoint's
    /// past holds it; `Wait` while it is concurrent with a checkpoint
    /// of [`Self::undecided`], neither in its past, nor it, nor after it;
    /// `Free` otherwise. A replica never drops a space's data for an erasure
    /// that waits, and drops none for a late one, which is void; one whose
    /// following of a checkpoint waits for envelopes counts as concurrent
    /// with it.
    pub fn request_state(&self, held: &BTreeSet<EventId>, x: EventId) -> RequestState {
        if self.placement(held, x) == Placement::Late {
            return RequestState::Late;
        }
        let log = self.log();
        let waits = self
            .undecided(held)
            .into_iter()
            .any(|k| x != k && !log.precedes(x, k) && self.follows(x, k) != Ok(true));
        match waits {
            true => RequestState::Wait,
            false => RequestState::Free,
        }
    }

    /// The erasures, credentials requests, releases and restores among the
    /// events `held` signed by one of `authors` (a device and its
    /// pseudonyms) that the chain in effect over `held` makes late, under
    /// any of its checkpoints ([`Self::placement`]): what
    /// the device's client signs again after the checkpoint, naming for
    /// credentials the current state of its view, and tells the
    /// application it signed again (roster.md, 3.15.7, "Work concurrent
    /// with a checkpoint"; peers.md, 3.15). In canonical order.
    pub fn late_requests(
        &self,
        held: &BTreeSet<EventId>,
        authors: &BTreeSet<DeviceId>,
    ) -> Vec<LateRequest> {
        let judged = self.judge(held);
        if judged.chain.is_empty() {
            return Vec::new();
        }
        let log = self.log();
        log.canonical_in(held)
            .into_iter()
            .filter_map(|id| {
                let event = log.event(id)?;
                if event.kind() != kind::STORAGE || !authors.contains(event.author()) {
                    return None;
                }
                let kind = StorageBody::read(event.unverified_body())
                    .ok()?
                    .storage_type();
                (signed_again(kind) && self.placement_in(&judged.chain, id) == Placement::Late)
                    .then_some(LateRequest { event: id, kind })
            })
            .collect()
    }
}
