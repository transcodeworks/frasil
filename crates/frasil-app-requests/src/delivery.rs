//! List deliveries and the lists a verifier holds (ext-app-requests.md, "The
//! list delivery", "List deliveries", "Who signs").
//!
//! ```text
//! list delivery = deterministic CBOR map {1: 1, 2: array of 1 to 4,096
//!                 signed device-list events (bytes)}
//! ```
//!
//! It is the body of a signed `PUT /frasil/p1/device-list` at the verifier's
//! origin, with `Content-Type: application/cbor`. A list event verifies from
//! the person's first event, whose event ID is the person ID, and every
//! `add` carries its key's possession proof, so the verifier takes list
//! events from whoever delivers them and trusts only their signatures.
//!
//! **Placing** a list delivery, in order:
//!
//! 1. The body is the map above. Else `BadListDelivery`.
//! 2. Each event passes events.md's decoding, is of kind 1, and is the
//!    person's: its `log` is `person_id`, or it is a first event whose event
//!    ID is `person_id`. Else `BadListDelivery`, and nothing of the list
//!    delivery is placed.
//! 3. A verifier that holds none of the person's events needs the first
//!    event in the list delivery, and places nothing without it. A first
//!    event that fails identity.md's check of a first event is
//!    `BadListDelivery`.
//! 4. Each event is placed after its parents. One whose parents are missing
//!    waits for a later list delivery.
//! 5. The verifier records its first sight of each event it places.
//!
//! The placed events are the verifier's pin of the person ([`Pin`]): they
//! only grow. A list delivery that brings new evidence of a fork is merged
//! as usual, and the verifier reports `ForkDetected`.

use crate::AppRequestClass;
use crate::state::VerifierState;
use frasil_base::cbor::{self, Reader};
use frasil_crypto::device::DeviceId;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Event, EventId, Evidence, decode};
use frasil_identity::body::MAX_LIST_EVENTS;
use frasil_identity::{DeviceList, Kind, MergedList, Pin, PinCheck};
use std::collections::{BTreeMap, BTreeSet};

/// The list delivery map's version, key 1.
pub const DELIVERY_VERSION: u64 = 1;
/// The list delivery route's method.
pub const DELIVERY_METHOD: &str = "PUT";
/// The list delivery route's path.
pub const DELIVERY_PATH: &str = "/frasil/p1/device-list";
/// The list delivery's content type.
pub const DELIVERY_CONTENT_TYPE: &str = "application/cbor";
/// The status the verifier answers once a list delivery is accepted.
pub const DELIVERY_STATUS: u16 = 204;
/// The most events a list delivery holds, and the most events of one person
/// a verifier holds.
pub const MAX_DELIVERY_EVENTS: usize = MAX_LIST_EVENTS;

/// The list delivery of these signed list events.
pub fn encode_delivery<E: AsRef<[u8]>>(events: &[E]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::map_head(&mut out, 2);
    cbor::unsigned(&mut out, 1);
    cbor::unsigned(&mut out, DELIVERY_VERSION);
    cbor::unsigned(&mut out, 2);
    cbor::array_head(&mut out, events.len());
    for event in events {
        cbor::bytes(&mut out, event.as_ref());
    }
    out
}

/// The signed events of a list delivery: step 1 of placing it.
///
/// # Errors
///
/// `BadListDelivery` for a body that is not the deterministic CBOR map
/// `{1: 1, 2: [1 to 4,096 byte strings]}`.
pub fn read_delivery(body: &[u8]) -> Result<Vec<&[u8]>, AppRequestClass> {
    read(body).map_err(|_| AppRequestClass::BadListDelivery)
}

fn read(body: &[u8]) -> Result<Vec<&[u8]>, cbor::Malformed> {
    let mut reader = Reader::new(body);
    if reader.map_len()? != 2 {
        return Err(cbor::Malformed);
    }
    reader.key(1)?;
    if reader.unsigned()? != DELIVERY_VERSION {
        return Err(cbor::Malformed);
    }
    reader.key(2)?;
    let count = reader.array_len()?;
    if !(1..=MAX_DELIVERY_EVENTS).contains(&count) {
        return Err(cbor::Malformed);
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        events.push(reader.bytes()?);
    }
    reader.finish()?;
    Ok(events)
}

/// Whether a request is to the list delivery route.
pub fn is_delivery(method: &str, path: &str) -> bool {
    method == DELIVERY_METHOD && path == DELIVERY_PATH
}

/// What placing a list delivery did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Placed {
    /// How many events it placed that were not placed before.
    pub placed: usize,
    /// identity.md's `ForkDetected`: the new evidence that a list member
    /// forked, which the person can act on by revoking it. Empty when the
    /// list delivery brought none.
    pub fork_detected: Vec<Evidence>,
}

/// The list a verifier holds of a person: the list events it placed, which
/// only grow, the merge over them, and its first sight of each.
#[derive(Debug, Clone)]
pub struct HeldList {
    list: DeviceList,
    merged: MergedList,
    first_seen: BTreeMap<EventId, u64>,
}

impl HeldList {
    /// The list a verified first event starts, first seen at `now`.
    ///
    /// # Errors
    ///
    /// `BadListDelivery` for a first event that fails identity.md's check of
    /// a first event.
    pub fn new(first: Event, now: u64) -> Result<Self, AppRequestClass> {
        let id = first.id();
        let list = DeviceList::from_first(first).map_err(|_| AppRequestClass::BadListDelivery)?;
        let merged = list.merge();
        Ok(Self {
            list,
            merged,
            first_seen: BTreeMap::from([(id, now)]),
        })
    }

    /// A list kept durably, from [`HeldList::events`]: each placed event's
    /// signed bytes and the verifier's first sight of it.
    ///
    /// # Errors
    ///
    /// `BadListDelivery` if an event does not decode as a list event of one
    /// person, or the first event is missing or fails its check.
    pub fn restore<'a>(
        events: impl IntoIterator<Item = (&'a [u8], u64)>,
    ) -> Result<Self, AppRequestClass> {
        let bad = AppRequestClass::BadListDelivery;
        let mut decoded = Vec::new();
        let mut seen = BTreeMap::new();
        for (signed, first_seen) in events {
            let event = decode(signed).map_err(|_| bad)?;
            seen.insert(event.id(), first_seen);
            decoded.push(event);
        }
        let first = decoded.iter().find(|e| e.is_genesis()).ok_or(bad)?.clone();
        let person = first.id();
        if decoded
            .iter()
            .any(|e| e.kind() != DEVICE_LIST || e.log_id() != person)
        {
            return Err(bad);
        }
        let mut held = Self::new(first, seen[&person])?;
        for event in decoded {
            let _ = held.list.insert_event(event);
        }
        held.first_seen = held
            .list
            .log()
            .canonical()
            .into_iter()
            .map(|id| (id, seen[&id]))
            .collect();
        held.merged = held.list.merge();
        Ok(held)
    }

    /// The person ID.
    pub fn person_id(&self) -> [u8; 32] {
        self.list.person_id()
    }

    /// The list's placed and pending events.
    pub fn list(&self) -> &DeviceList {
        &self.list
    }

    /// identity.md's merge over the placed events.
    pub fn merged(&self) -> &MergedList {
        &self.merged
    }

    /// Whether the event is placed.
    pub fn holds(&self, id: EventId) -> bool {
        self.list.log().contains(id)
    }

    /// The verifier's first sight of a placed event.
    pub fn first_seen(&self, id: EventId) -> Option<u64> {
        self.first_seen.get(&id).copied()
    }

    /// Each placed event's signed bytes and first sight, in canonical order:
    /// what a verifier keeps durably, and gives back to
    /// [`HeldList::restore`].
    pub fn events(&self) -> Vec<(Vec<u8>, u64)> {
        self.list
            .log()
            .canonical()
            .into_iter()
            .filter_map(|id| {
                let event = self.list.log().event(id)?;
                Some((event.signed(), self.first_seen.get(&id).copied()?))
            })
            .collect()
    }

    /// "Who signs": the kind of `device` if it is a signer of the merged
    /// list at `now`, an active device or passkey member that has not forked
    /// and is not waiting.
    ///
    /// - A list member rooted in a passkey signs while it is active.
    /// - A waiting list member does not sign. With `agent_waiting_period`,
    ///   as a verifier that implements ext-recovery-agent.md, it signs once
    ///   that long has passed since the verifier's first sight of its `add`;
    ///   with `None`, it waits for a `confirm`.
    /// - A recovery key and a recovery agent never sign.
    /// - A revoked list member, and one that forked, never sign.
    pub fn signer(
        &self,
        device: &DeviceId,
        now: u64,
        agent_waiting_period: Option<u64>,
    ) -> Option<Kind> {
        let member = self.merged.active(device)?;
        if !matches!(member.kind, Kind::Device | Kind::PasskeyMember) {
            return None;
        }
        if member.waiting() {
            let period = agent_waiting_period?;
            let seen = self.first_seen(*member.adds.first()?)?;
            if now.saturating_sub(seen) < period {
                return None;
            }
        }
        Some(member.kind)
    }

    /// The events of a list delivery not yet placed or pending, and whether
    /// holding them would bring the person past 4,096 events.
    fn would_overflow(&self, events: &[Event]) -> bool {
        let log = self.list.log();
        let pending: BTreeSet<EventId> = log.pending().map(Event::id).collect();
        let new: BTreeSet<EventId> = events
            .iter()
            .map(Event::id)
            .filter(|&id| !log.contains(id) && !pending.contains(&id))
            .collect();
        log.len() + pending.len() + new.len() > MAX_DELIVERY_EVENTS
    }

    /// Steps 4 and 5 of placing, on events that passed steps 1 to 3.
    fn place(&mut self, events: Vec<Event>, now: u64) -> Placed {
        let pin = Pin::of(&self.list);
        let before = self.list.log().len();
        for event in events {
            // Every event is a device-list event of this person (step 2), so
            // the list never refuses one before placing it.
            let _ = self.list.insert_event(event);
        }
        let placed = self.list.log().len() - before;
        for id in self.list.log().canonical() {
            self.first_seen.entry(id).or_insert(now);
        }
        if placed > 0 {
            self.merged = self.list.merge();
        }
        let fork_detected = match pin.check(&self.list) {
            PinCheck::ForkDetected(evidence) => evidence,
            PinCheck::Advances | PinCheck::RolledBack => Vec::new(),
        };
        Placed {
            placed,
            fork_detected,
        }
    }
}

/// Places a list delivery's body for `person_id` in the verifier's state:
/// every step of placing.
///
/// # Errors
///
/// `BadListDelivery`; also for a list delivery that would bring the events
/// held of the person past 4,096, which a verifier may refuse.
pub fn place_delivery<S: VerifierState + ?Sized>(
    state: &mut S,
    person_id: &[u8; 32],
    body: &[u8],
    now: u64,
) -> Result<Placed, AppRequestClass> {
    let events = read_delivery(body)?;
    place_events(state, person_id, &events, now)
}

/// Places signed list events of `person_id` in the verifier's state: steps 2
/// to 5 of placing a list delivery.
///
/// # Errors
///
/// As [`place_delivery`].
pub fn place_events<S: VerifierState + ?Sized, E: AsRef<[u8]>>(
    state: &mut S,
    person_id: &[u8; 32],
    signed: &[E],
    now: u64,
) -> Result<Placed, AppRequestClass> {
    let bad = AppRequestClass::BadListDelivery;
    let mut events = Vec::with_capacity(signed.len());
    for signed in signed {
        let event = decode(signed.as_ref()).map_err(|_| bad)?;
        if event.kind() != DEVICE_LIST || event.log_id().0 != *person_id {
            return Err(bad);
        }
        events.push(event);
    }
    if let Some(held) = state.list_mut(person_id) {
        if held.would_overflow(&events) {
            return Err(bad);
        }
        return Ok(held.place(events, now));
    }
    let Some(first) = events.iter().find(|e| e.is_genesis()) else {
        return Ok(Placed::default());
    };
    let mut held = HeldList::new(first.clone(), now)?;
    if held.would_overflow(&events) {
        return Err(bad);
    }
    let mut placed = held.place(events, now);
    placed.placed += 1;
    state.insert_list(held);
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliveries_read_back() {
        let events: [&[u8]; 2] = [b"a", b"bc"];
        let body = encode_delivery(&events);
        assert_eq!(read_delivery(&body), Ok(events.to_vec()));
        let empty: [&[u8]; 0] = [];
        let bad = Err(AppRequestClass::BadListDelivery);
        assert_eq!(read_delivery(&encode_delivery(&empty)), bad);
        assert_eq!(read_delivery(b"\xa1\x01\x01"), bad);
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(read_delivery(&trailing), bad);
        let mut version = body;
        version[2] = 2;
        assert_eq!(read_delivery(&version), bad);
    }
}
