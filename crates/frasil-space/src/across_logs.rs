//! Spaces across list checkpoints (roster.md, 3.15.8 Other logs and
//! extensions; identity.md, "List checkpoints", "Spaces").
//!
//! A space reads a person's list as the replica holds it: the whole list
//! ([`DeviceList`]), or, when the replica forgot the list's earlier events,
//! from the list's kept checkpoint on ([`KeptList`]), a sealed list copy
//! included. Either way the space reads the merged list, and with a list
//! checkpoint in effect the merged list is that checkpoint's world: its
//! record's members and what follows.
//!
//! A list checkpoint in effect ends at once, in every space, the path of
//! every device it does not list, as if each space had responded to its
//! end: such a device is no writer of the merged list
//! ([`HeldList::writers`](crate::HeldList::writers)), so the write rule
//! finds no path through the person for it, and no space waits for a
//! response or needs the list event that ended it.
//! [`HeldList::unlisted_end`] names the checkpoint that ended it. A replica
//! that kept the whole list and one that forgot it agree, since neither
//! reads the device's `add` any longer: an `add` in the checkpoint's past
//! names a device only if the record lists it ([`ListHolding::names`]).
//! The device loses its path for its events before the checkpoint as for
//! those after it (roster.md, 3.15.8, "What an unlisted device loses"): its
//! units, anchors and writer requests are `Dropped`, and so are its key
//! events whose signature the replica can check; one whose keys the replica
//! no longer holds, the list's `add` that carried them forgotten, stays
//! `NoHybridKey`, held and never judged. A space's ref to a list event
//! before the list checkpoint resolves, held or forgotten
//! ([`ListHolding::holds`]; a newcomer from a sealed copy takes the
//! forgotten IDs from the copy). With no list checkpoint in effect nothing
//! changes: a revoked device's path ends once a writer of the space
//! responds.

use crate::across::HeldList;
use frasil_crypto::device::{DeviceId, KeyRing};
use frasil_events::EventId;
use frasil_identity::body::Action;
use frasil_identity::{DeviceList, KeptList, MergedList};
use std::collections::BTreeSet;

/// A person's list as a replica holds it.
#[derive(Debug, Clone)]
pub(crate) enum ListHolding {
    /// Every event of the list.
    Whole(DeviceList),
    /// The list from its kept checkpoint on.
    Kept(KeptList),
}

impl ListHolding {
    /// The merged list (identity.md, "The merge", "List checkpoints").
    pub(crate) fn merge(&self) -> MergedList {
        match self {
            Self::Whole(list) => list.merge(),
            Self::Kept(list) => list.merge(),
        }
    }

    /// The person ID.
    pub(crate) fn person_id(&self) -> [u8; 32] {
        match self {
            Self::Whole(list) => list.person_id(),
            Self::Kept(list) => list.person_id(),
        }
    }

    /// Whether a ref to an event of the list resolves: an event the replica
    /// holds, or, for a list that forgot, one it dropped, as its own
    /// forgetting or a sealed copy's forgotten IDs name them (roster.md,
    /// 3.15.8: a ref to a list event before the list checkpoint resolves,
    /// held or forgotten).
    pub(crate) fn holds(&self, event: EventId) -> bool {
        match self {
            Self::Whole(list) => list.log().contains(event),
            Self::Kept(list) => list.contains(event) || list.dropped().contains(&event),
        }
    }

    /// Whether `earlier` is in the past of `later`, in the list as held.
    pub(crate) fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        match self {
            Self::Whole(list) => list.log().precedes(earlier, later),
            Self::Kept(list) => {
                list.precedes(earlier, later)
                    || (list.dropped().contains(&earlier)
                        && (later == list.checkpoint() || list.precedes(list.checkpoint(), later)))
            }
        }
    }

    /// The keys every `add` the replica holds of the list carries.
    pub(crate) fn keys(&self) -> &KeyRing {
        match self {
            Self::Whole(list) => list.keys(),
            Self::Kept(list) => list.keys(),
        }
    }

    /// Whether an `add` the replica holds of the list names a device, valid
    /// or not. With a list checkpoint in effect, only the adds a holder that
    /// forgot still reads count, so that it and one that kept the whole
    /// list agree on whom a record names: the adds of the checkpoint's
    /// world and the late ones, and, from its past, a device the merged
    /// list lists.
    pub(crate) fn names(&self, device: &DeviceId, merged: &MergedList) -> bool {
        let adds = |body: Option<&frasil_identity::body::ListBody>| {
            body.is_some_and(|body| body.action == Action::Add && body.device == *device)
        };
        let Some(c) = merged.in_effect() else {
            return match self {
                Self::Whole(list) => list
                    .log()
                    .canonical()
                    .into_iter()
                    .any(|id| adds(list.body(id))),
                Self::Kept(list) => list
                    .canonical()
                    .into_iter()
                    .chain(list.alone().keys().copied())
                    .chain([list.first().id()])
                    .any(|id| adds(list.body(id))),
            };
        };
        if merged.member(device).is_some() {
            return true;
        }
        match self {
            Self::Whole(list) => {
                let past = list.log().past(c);
                list.log()
                    .canonical()
                    .into_iter()
                    .filter(|id| *id != c && !past.contains(id))
                    .any(|id| adds(list.body(id)))
            }
            Self::Kept(list) => {
                let carried: BTreeSet<EventId> = list.carried().into_iter().collect();
                list.canonical()
                    .into_iter()
                    .chain(list.alone().keys().copied())
                    .filter(|id| *id != c && !carried.contains(id))
                    .any(|id| adds(list.body(id)))
            }
        }
    }
}

impl HeldList {
    /// A list the replica holds from its kept checkpoint on, or a sealed
    /// list copy of one (identity.md, "List checkpoints", "Forgetting",
    /// "Spaces"), merged.
    pub fn kept(list: KeptList) -> Self {
        Self::holding(ListHolding::Kept(list))
    }

    /// The list from its kept checkpoint on, when the replica holds it so.
    pub fn kept_list(&self) -> Option<&KeptList> {
        match &self.list {
            ListHolding::Kept(list) => Some(list),
            ListHolding::Whole(_) => None,
        }
    }

    /// The list checkpoint in effect that ended `device`'s path through the
    /// person at once (roster.md, 3.15.8): the latest in effect, when the
    /// merged list does not list the device. `None` with no list checkpoint
    /// in effect, or for a device the merged list lists. Such a device is
    /// no writer, so no space finds a path through the person for it.
    pub fn unlisted_end(&self, device: &[u8; 32]) -> Option<EventId> {
        self.merged().unlisted_end(&DeviceId(*device))
    }
}
