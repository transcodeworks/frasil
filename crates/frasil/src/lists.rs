//! A person's device list as this device holds it (identity.md, "List
//! checkpoints", "Forgetting"; roster.md, 3.15.8 Other logs and
//! extensions).
//!
//! A device holds a list whole until a list checkpoint is in effect and its
//! policy forgets; from then on it holds the list from that checkpoint on
//! ([`KeptList`]): the list's first event, the kept checkpoint, the adds and
//! rooting adds its record names, the checkpoints its `follows` reach, the
//! late events and what follows, with the IDs of what it dropped. Every
//! reader goes through [`PersonList`]: spaces read it as a
//! [`frasil_space::HeldList`], sending reads its merged list and keys, and
//! sealed list copies carry what it holds.

use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, KeyRing, KeySource};
use frasil_crypto::schemes::Signer;
use frasil_events::{Event, EventId, Placement};
use frasil_identity::body::{Action, ListBody};
use frasil_identity::checkpoint::LateWork;
use frasil_identity::list::Refusal;
use frasil_identity::{DeviceList, IdentityClass, KeptList, MergedList};
use std::collections::BTreeSet;

/// A person's device list as this device holds it.
#[derive(Debug, Clone)]
pub(crate) enum PersonList {
    /// Every event of the list.
    Whole(DeviceList),
    /// The list from its kept checkpoint on, after the device forgot what
    /// came before it, or as a sealed copy carried it.
    Kept(KeptList),
}

impl From<DeviceList> for PersonList {
    fn from(list: DeviceList) -> Self {
        Self::Whole(list)
    }
}

impl PersonList {
    /// The person ID.
    #[cfg_attr(not(feature = "ext-recovery-agent"), allow(dead_code))]
    pub fn person_id(&self) -> [u8; 32] {
        match self {
            Self::Whole(list) => list.person_id(),
            Self::Kept(list) => list.person_id(),
        }
    }

    /// The whole list, when the device holds it so.
    pub fn whole(&self) -> Option<&DeviceList> {
        match self {
            Self::Whole(list) => Some(list),
            Self::Kept(_) => None,
        }
    }

    /// The list from its kept checkpoint on, when the device holds it so.
    pub fn kept(&self) -> Option<&KeptList> {
        match self {
            Self::Kept(list) => Some(list),
            Self::Whole(_) => None,
        }
    }

    /// The merged list (identity.md, "The merge", "List checkpoints").
    pub fn merge(&self) -> MergedList {
        match self {
            Self::Whole(list) => list.merge(),
            Self::Kept(list) => list.merge(),
        }
    }

    /// The list as a space reads it.
    pub fn held(&self) -> frasil_space::HeldList {
        match self {
            Self::Whole(list) => frasil_space::HeldList::new(list.clone()),
            Self::Kept(list) => frasil_space::HeldList::kept(list.clone()),
        }
    }

    /// The keys every `add` the device holds of the list carries.
    pub fn keys(&self) -> &KeyRing {
        match self {
            Self::Whole(list) => list.keys(),
            Self::Kept(list) => list.keys(),
        }
    }

    /// The body of an event the device holds that passed the checks alone.
    pub fn body(&self, id: EventId) -> Option<&ListBody> {
        match self {
            Self::Whole(list) => list.body(id),
            Self::Kept(list) => list.body(id),
        }
    }

    /// An event the device holds, placed (or, for a kept list, kept alone
    /// or its first event).
    #[cfg_attr(not(feature = "ext-recovery-agent"), allow(dead_code))]
    pub fn event(&self, id: EventId) -> Option<&Event> {
        match self {
            Self::Whole(list) => list.log().event(id),
            Self::Kept(list) => list.any_event(id),
        }
    }

    /// Whether the device holds an event of the list or dropped it when it
    /// forgot: an event it never needs again.
    pub fn has_seen(&self, id: EventId) -> bool {
        match self {
            Self::Whole(list) => list.log().contains(id),
            Self::Kept(list) => list.contains(id) || list.dropped().contains(&id),
        }
    }

    /// Whether `earlier` is in the past of `later`.
    pub fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        match self {
            Self::Whole(list) => list.log().precedes(earlier, later),
            Self::Kept(list) => list.precedes(earlier, later),
        }
    }

    /// The events the device judges, in canonical order: every event of a
    /// whole list, or the kept checkpoint and what follows it.
    pub fn canonical(&self) -> Vec<EventId> {
        match self {
            Self::Whole(list) => list.log().canonical(),
            Self::Kept(list) => list.canonical(),
        }
    }

    /// How many events the device holds of the list.
    pub fn len(&self) -> usize {
        match self {
            Self::Whole(list) => list.log().len(),
            Self::Kept(list) => list.canonical().len() + list.alone().len() + 1,
        }
    }

    /// The heads of what the device holds of the list: its placed events
    /// no other placed event cites.
    pub fn heads(&self) -> Vec<EventId> {
        match self {
            Self::Whole(list) => list.log().heads(),
            Self::Kept(list) => {
                let placed = list.canonical();
                let cited: BTreeSet<EventId> = placed
                    .iter()
                    .filter_map(|id| list.event(*id))
                    .flat_map(|event| event.parents().iter().copied())
                    .collect();
                placed
                    .into_iter()
                    .filter(|id| !cited.contains(id))
                    .collect()
            }
        }
    }

    /// A number that changes whenever the device takes an event of the
    /// list or forgets some.
    pub fn revision(&self) -> (u64, u64) {
        match self {
            Self::Whole(list) => (list.log().placed_count() as u64, list.log().revision()),
            Self::Kept(list) => (self.len() as u64, list.dropped().len() as u64 | 1 << 63),
        }
    }

    /// ext-recovery-agent.md's veto of `device` ([`DeviceList::veto`],
    /// [`KeptList::veto`]).
    #[cfg(feature = "ext-recovery-agent")]
    pub fn veto(&self, merged: &MergedList, device: &DeviceId, with_agent: bool) -> Vec<ListBody> {
        match self {
            Self::Whole(list) => list.veto(merged, device, with_agent),
            Self::Kept(list) => list.veto(merged, device, with_agent),
        }
    }

    /// An `add` with the events of its past the device holds, signed: what
    /// a space needs to judge it. For a list held from a kept checkpoint
    /// on, every event the device holds.
    #[cfg(feature = "ext-recovery-agent")]
    pub fn with_past(&self, add: EventId) -> Vec<Vec<u8>> {
        match self {
            Self::Whole(list) => list.with_past(add),
            Self::Kept(list) if list.contains(add) => list.signed_events(),
            Self::Kept(_) => Vec::new(),
        }
    }

    /// Takes a signed event of the list.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::insert`] or [`KeptList::insert`].
    pub fn insert(&mut self, signed: &[u8]) -> Result<Placement, Refusal> {
        match self {
            Self::Whole(list) => list.insert(signed),
            Self::Kept(list) => list.insert(signed),
        }
    }

    /// Takes a decoded event of the list.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::insert_event`] or [`KeptList::insert_event`].
    pub fn insert_event(&mut self, event: Event) -> Result<Placement, Refusal> {
        match self {
            Self::Whole(list) => list.insert_event(event),
            Self::Kept(list) => {
                // An event the device forgot is never taken again.
                if list.dropped().contains(&event.id()) {
                    return Ok(Placement::Known);
                }
                list.insert_event(event)
            }
        }
    }

    /// Checks again the events that wait for keys, under `source` too.
    pub fn verify_with(&mut self, source: &(impl KeySource + ?Sized)) -> Vec<EventId> {
        match self {
            Self::Whole(list) => list.verify_with(source),
            Self::Kept(list) => list.verify_with(source),
        }
    }

    /// The signed events a sealed list copy carries (identity.md, "Sealed
    /// list copies"): every event of a whole list, or what a kept list
    /// holds.
    pub fn signed_events(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Whole(list) => list.signed_events(),
            Self::Kept(list) => list.signed_events(),
        }
    }

    /// Signs a list event with this body as this device's next.
    pub fn sign(&self, body: &ListBody, signer: &Signer) -> Vec<u8> {
        match self {
            Self::Whole(list) => list.sign(body, signer),
            Self::Kept(list) => list.sign(body, signer),
        }
    }

    /// Signs an `ack` (action 4).
    pub fn ack(&self, signer: &Signer) -> Vec<u8> {
        match self {
            Self::Whole(list) => list.ack(signer),
            Self::Kept(list) => list.ack(signer),
        }
    }

    /// Signs a list checkpoint (action 3) of what the device holds.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::propose_checkpoint`].
    pub fn propose_checkpoint(&self, signer: &Signer) -> Result<Vec<u8>, IdentityClass> {
        match self {
            Self::Whole(list) => list.propose_checkpoint(signer),
            Self::Kept(list) => list.propose_checkpoint(signer),
        }
    }

    /// What `device` does with its own list events that became `Late`.
    pub fn late_work(&self, merged: &MergedList, device: &DeviceId) -> LateWork {
        match self {
            Self::Whole(list) => list.late_work(merged, device),
            Self::Kept(list) => list.late_work(merged, device),
        }
    }

    /// Whether `device` contests list checkpoint `checkpoint`, and why
    /// (identity.md, "List checkpoints", "Clients"): it never cites or
    /// votes for one.
    pub fn contest(
        &self,
        device: &DeviceId,
        checkpoint: EventId,
    ) -> Option<frasil_identity::Contest> {
        match self {
            Self::Whole(list) => list.contest(device, checkpoint),
            Self::Kept(list) => list.contest(device, checkpoint),
        }
    }

    /// The list the device keeps when it forgets under the latest list
    /// checkpoint in effect (identity.md, "List checkpoints",
    /// "Forgetting"), with the IDs of the events it drops; `None` when no
    /// list checkpoint is in effect, the device keeps it already, or a
    /// rival is held.
    pub fn forget(&self, merged: &MergedList) -> Option<(KeptList, Vec<EventId>)> {
        let c = merged.in_effect()?;
        if !rivals(self, merged).is_empty() {
            return None;
        }
        // Never while a concurrent valid checkpoint with a smaller ID is
        // pending: the chain may still move to it.
        if merged
            .pending_checkpoints()
            .any(|(x, _)| x < c && !self.precedes(x, c) && !self.precedes(c, x))
        {
            return None;
        }
        let kept = match self {
            Self::Whole(list) => list.forget(merged)?,
            Self::Kept(list) => {
                if list.checkpoint() == c {
                    return None;
                }
                list.forget(merged)?
            }
        };
        let before: BTreeSet<EventId> = self.all_ids();
        let after: BTreeSet<EventId> = {
            let mut ids: BTreeSet<EventId> = kept.canonical().into_iter().collect();
            ids.extend(kept.alone().keys().copied());
            ids.insert(kept.first().id());
            ids
        };
        let dropped = before.difference(&after).copied().collect();
        Some((kept, dropped))
    }

    /// Every event ID the device holds of the list.
    fn all_ids(&self) -> BTreeSet<EventId> {
        match self {
            Self::Whole(list) => list.log().canonical().into_iter().collect(),
            Self::Kept(list) => {
                let mut ids: BTreeSet<EventId> = list.canonical().into_iter().collect();
                ids.extend(list.alone().keys().copied());
                ids.insert(list.first().id());
                ids
            }
        }
    }
}

/// A person's list from its events: whole when every event places, else
/// from a list checkpoint on (a sealed list copy of a holder that forgot,
/// or what this device kept at rest after it forgot; identity.md, "List
/// checkpoints", "Forgetting"). `checkpoint` names the kept checkpoint when
/// the device knows it; otherwise it is the latest checkpoint among the
/// events that is in effect over what follows it. `dropped` names the
/// events the device forgot, empty for a copy another holder sent. `None`
/// without the list's first event, or when the events make neither.
pub(crate) fn from_events(
    events: &[Event],
    checkpoint: Option<EventId>,
    dropped: &[EventId],
) -> Option<PersonList> {
    let first = events.iter().find(|event| event.is_genesis())?.clone();
    if checkpoint.is_none() {
        let mut whole = DeviceList::from_first(first.clone()).ok()?;
        for event in events {
            if event.id() != first.id() {
                let _ = whole.insert_event(event.clone());
            }
        }
        let checkpoints = events.iter().any(is_checkpoint);
        if whole.log().pending().next().is_none() || !checkpoints {
            return Some(PersonList::Whole(whole));
        }
    }
    let by_id: std::collections::BTreeMap<EventId, &Event> =
        events.iter().map(|event| (event.id(), event)).collect_map();
    let reaches = |from: EventId, to: EventId| {
        let mut todo = vec![from];
        let mut seen = BTreeSet::new();
        while let Some(id) = todo.pop() {
            if id == to {
                return true;
            }
            if seen.insert(id)
                && let Some(event) = by_id.get(&id)
            {
                todo.extend(event.parents().iter().copied());
            }
        }
        false
    };
    let mut candidates: Vec<EventId> = match checkpoint {
        Some(c) => vec![c],
        None => events
            .iter()
            .filter(|event| is_checkpoint(event))
            .map(Event::id)
            .collect(),
    };
    // The latest first: one that follows more checkpoints comes earlier.
    let all = candidates.clone();
    candidates.sort_by_key(|&c| core::cmp::Reverse(candidates_reached(&all, c, &reaches)));
    for c in candidates {
        let Some(kept_checkpoint) = by_id.get(&c) else {
            continue;
        };
        // In a sealed copy's order: the first event, the checkpoint, the
        // rest (identity.md, "List checkpoints", "Forgetting").
        let mut copy = vec![first.signed(), kept_checkpoint.signed()];
        copy.extend(
            events
                .iter()
                .filter(|event| event.id() != first.id() && event.id() != c)
                .map(Event::signed),
        );
        let Ok(kept) =
            KeptList::from_sealed_copy(copy.iter().map(Vec::as_slice), dropped.iter().copied())
        else {
            continue;
        };
        if checkpoint.is_some() || kept.is_in_effect() {
            return Some(PersonList::Kept(kept));
        }
    }
    None
}

/// How many of `candidates` `c` follows.
fn candidates_reached(
    candidates: &[EventId],
    c: EventId,
    reaches: &impl Fn(EventId, EventId) -> bool,
) -> usize {
    candidates
        .iter()
        .filter(|&&other| other != c && reaches(c, other))
        .count()
}

/// Whether a list event is a list checkpoint (action 3), read from its body
/// alone.
fn is_checkpoint(event: &Event) -> bool {
    ListBody::decode(event.unverified_body()).is_ok_and(|body| body.action == Action::Checkpoint)
}

impl PersonList {
    /// A whole list that holds events pending on parents it will never get,
    /// because they came in a sealed copy of a holder that forgot, taken
    /// from that copy's checkpoint on instead; any other list as it is.
    pub fn settled(self) -> Self {
        let Self::Whole(list) = &self else {
            return self;
        };
        if list.log().pending().next().is_none() {
            return self;
        }
        let events: Vec<Event> = list
            .log()
            .events()
            .chain(list.log().pending())
            .cloned()
            .collect();
        match from_events(&events, None, &[]) {
            Some(kept @ Self::Kept(_)) => kept,
            _ => self,
        }
    }
}

/// Whether the device holds the list from a kept checkpoint on.
pub(crate) fn is_kept(list: &PersonList) -> bool {
    matches!(list, PersonList::Kept(_))
}

/// The rivals of a kept list's checkpoint (identity.md, "List
/// checkpoints", "A rival"): while one is held the device does not forget
/// again and reports it. Empty for a whole list.
pub(crate) fn rivals(_list: &PersonList, merged: &MergedList) -> Vec<EventId> {
    merged.rivals().iter().copied().collect()
}
