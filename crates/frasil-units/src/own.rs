//! Frasil's own units (units.md, sections 2.12 and 3.11), and a read-only
//! person's list events.
//!
//! Each is a unit of the system stream whose content is deterministic CBOR:
//!
//! | Type | Content |
//! |---|---|
//! | `frasil:list` | an array of 1 to 16 signed device-list events, each a byte string, of one or more persons |
//! | `frasil:body-keys` | an array of 1 to 1,024 pairs `[event ID, body key]`, bytes(32) each, strictly ascending by event ID |
//! | `frasil:recovery-entry` | one recovery entry (identity.md) |
//!
//! A `frasil:system` unit is a snapshot unit of the system stream, whose
//! snapshot state is [`SystemState`].

use crate::limits::{MAX_BODY_KEYS, MAX_LIST_EVENTS};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, kind};
use frasil_identity::IdentityClass;
use frasil_identity::body::check_body;
use frasil_identity::entries::{Holder, RecoveryEntry};

/// The content name of a read-only person's list events in a device mailbox
/// item (transport.md).
pub const LIST_EVENTS_CONTENT_NAME: &str = "frasil/list-events";

/// A body key: an event ID and the key that opens its body (keys.md).
pub type BodyKey = (EventId, [u8; 32]);

fn byte_strings(events: &[Vec<u8>]) -> Value {
    Value::Array(events.iter().map(|e| Value::from(e.as_slice())).collect())
}

/// Reads 1 to 16 byte strings.
fn read_list_events(value: &Value) -> Result<Vec<Vec<u8>>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_LIST_EVENTS {
        return Err(Malformed);
    }
    items
        .iter()
        .map(|item| item.as_bytes().map(<[u8]>::to_vec))
        .collect()
}

/// A `frasil:list` unit's content: 1 to 16 signed device-list events.
pub fn list_copy_content(events: &[Vec<u8>]) -> Vec<u8> {
    byte_strings(events).encode()
}

/// Reads a `frasil:list` unit's content: an array of 1 to 16 byte strings
/// (`Malformed`, which refuses the content). Each event is then checked as
/// a device-list event; one that does not decode, or is of another kind, is
/// dropped from the copy, and the unit stays valid (section 3.11). The
/// events kept are placed in their persons' logs, which check them further.
///
/// # Errors
///
/// `Malformed`.
pub fn read_list_copy(content: &[u8]) -> Result<Vec<Event>, Malformed> {
    let events = read_list_events(&cbor::decode(content)?)?;
    Ok(events
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|event| event.kind() == kind::DEVICE_LIST)
        .collect())
}

fn body_key_pairs(pairs: &[BodyKey]) -> Value {
    let mut pairs = pairs.to_vec();
    pairs.sort_unstable_by_key(|(id, _)| *id);
    Value::Array(
        pairs
            .into_iter()
            .map(|(id, key)| Value::Array(vec![Value::from(id.0), Value::from(key)]))
            .collect(),
    )
}

/// Reads pairs `[event ID, body key]`, bytes(32) each, strictly ascending by
/// event ID, at most `limit`.
///
/// # Errors
///
/// `Malformed`.
pub fn read_body_key_pairs(value: &Value, limit: usize) -> Result<Vec<BodyKey>, Malformed> {
    let items = value.as_array()?;
    if items.len() > limit {
        return Err(Malformed);
    }
    let mut pairs: Vec<BodyKey> = Vec::with_capacity(items.len());
    for item in items {
        let [id, key] = item.as_array()? else {
            return Err(Malformed);
        };
        let pair = (EventId(id.as_byte_array()?), key.as_byte_array()?);
        if pairs.last().is_some_and(|last| last.0 >= pair.0) {
            return Err(Malformed);
        }
        pairs.push(pair);
    }
    Ok(pairs)
}

/// A `frasil:body-keys` unit's content: 1 to 1,024 pairs, ascending by event
/// ID. An event ID may name an event of any log.
pub fn body_keys_content(pairs: &[BodyKey]) -> Vec<u8> {
    body_key_pairs(pairs).encode()
}

/// Reads a `frasil:body-keys` unit's content. Each key is checked against
/// its event's commitment before use (keys.md).
///
/// # Errors
///
/// `Malformed`.
pub fn read_body_keys(content: &[u8]) -> Result<Vec<BodyKey>, Malformed> {
    let pairs = read_body_key_pairs(&cbor::decode(content)?, MAX_BODY_KEYS)?;
    if pairs.is_empty() {
        return Err(Malformed);
    }
    Ok(pairs)
}

/// Why a `frasil:recovery-entry` unit's entry is ignored; the unit stays
/// valid either way (section 3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryIgnored {
    /// It fails identity.md's checks, with this class.
    Invalid(IdentityClass),
    /// Its list member is not active.
    MemberNotActive,
}

/// Reads a `frasil:recovery-entry` unit's content by identity.md's checks.
/// An entry that fails, or whose list member is not active, is ignored.
///
/// # Errors
///
/// Why it is ignored.
pub fn read_recovery_entry(
    content: &[u8],
    personal_space: &[u8; 32],
    active: impl Fn(&DeviceId) -> bool,
) -> Result<RecoveryEntry, EntryIgnored> {
    let entry = RecoveryEntry::read(content, personal_space).map_err(EntryIgnored::Invalid)?;
    if let Holder::Member(member) = &entry.holder
        && !active(member)
    {
        return Err(EntryIgnored::MemberNotActive);
    }
    Ok(entry)
}

/// A `frasil:system` unit's snapshot state (section 2.12).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemState {
    /// Key 1: every device-list event its cover's list copies carry, each
    /// once; written ascending by event ID.
    pub lists: Vec<Vec<u8>>,
    /// Key 2: the body keys its cover's units carry. Key 3 is reserved.
    pub body_keys: Vec<BodyKey>,
    /// Key 4: every recovery entry its cover's `frasil:recovery-entry`
    /// units carry, each once; written ascending by encoding, and left out
    /// when there are none.
    pub entries: Vec<Vec<u8>>,
    /// Key 5: for each person whose list key 1 carries from a list
    /// checkpoint on, the IDs of the list events its writer forgot
    /// (identity.md, "List checkpoints", Forgetting and Spaces), so that a
    /// member that starts from the state tells a forgotten parent from one
    /// it has not received. Written ascending by person ID, each person's
    /// IDs ascending and each once; a person with none is left out, and
    /// the key with them when none is left.
    pub forgotten: Vec<(EventId, Vec<EventId>)>,
}

/// Key 5 as written: persons ascending, each person's IDs ascending and
/// each once, persons with none left out.
fn forgotten_pairs(forgotten: &[(EventId, Vec<EventId>)]) -> Vec<(EventId, Vec<EventId>)> {
    let mut by_person: std::collections::BTreeMap<EventId, std::collections::BTreeSet<EventId>> =
        std::collections::BTreeMap::new();
    for (person, ids) in forgotten {
        by_person
            .entry(*person)
            .or_default()
            .extend(ids.iter().copied());
    }
    by_person
        .into_iter()
        .filter(|(_, ids)| !ids.is_empty())
        .map(|(person, ids)| (person, ids.into_iter().collect()))
        .collect()
}

/// Reads key 5: 1 or more pairs `[person ID, forgotten]`, strictly
/// ascending by person ID, `forgotten` 1 or more event IDs, bytes(32) each,
/// strictly ascending.
fn read_forgotten(value: &Value) -> Result<Vec<(EventId, Vec<EventId>)>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(Malformed);
    }
    let mut out: Vec<(EventId, Vec<EventId>)> = Vec::with_capacity(items.len());
    for item in items {
        let [person, ids] = item.as_array()? else {
            return Err(Malformed);
        };
        let person = EventId(person.as_byte_array()?);
        if out.last().is_some_and(|(last, _)| *last >= person) {
            return Err(Malformed);
        }
        let ids = ids
            .as_array()?
            .iter()
            .map(|id| id.as_byte_array().map(EventId))
            .collect::<Result<Vec<_>, _>>()?;
        if ids.is_empty() || !ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(Malformed);
        }
        out.push((person, ids));
    }
    Ok(out)
}

impl SystemState {
    /// The state's deterministic encoding.
    ///
    /// # Errors
    ///
    /// `Malformed` if a list event does not decode, whose ID orders key 1.
    pub fn encode(&self) -> Result<Vec<u8>, ErrorClass> {
        let mut lists: Vec<(EventId, &Vec<u8>)> = self
            .lists
            .iter()
            .map(|signed| Ok((frasil_events::decode(signed)?.id(), signed)))
            .collect::<Result<_, frasil_events::EventClass>>()
            .map_err(|_| ErrorClass::Malformed)?;
        lists.sort_unstable_by_key(|(id, _)| *id);
        lists.dedup_by_key(|(id, _)| *id);
        let mut map = Map::from([
            (
                1,
                Value::Array(
                    lists
                        .into_iter()
                        .map(|(_, signed)| Value::from(signed.as_slice()))
                        .collect(),
                ),
            ),
            (2, body_key_pairs(&self.body_keys)),
        ]);
        if !self.entries.is_empty() {
            let mut entries = self.entries.clone();
            entries.sort_unstable();
            entries.dedup();
            map.insert(4, byte_strings(&entries));
        }
        let forgotten = forgotten_pairs(&self.forgotten);
        if !forgotten.is_empty() {
            map.insert(
                5,
                Value::Array(
                    forgotten
                        .into_iter()
                        .map(|(person, ids)| {
                            Value::Array(vec![
                                Value::from(person.0),
                                Value::Array(ids.into_iter().map(|id| Value::from(id.0)).collect()),
                            ])
                        })
                        .collect(),
                ),
            );
        }
        Ok(Value::Map(map).encode())
    }

    /// Reads a `frasil:system` snapshot state.
    ///
    /// # Errors
    ///
    /// `Malformed` for keys other than 1, 2, 4 and 5 (key 3 is reserved), a
    /// missing key 1 or 2, an order not strictly ascending, a list event
    /// that does not decode, an empty key 4 or 5, or a person in key 5 with
    /// no event ID.
    pub fn read(data: &[u8]) -> Result<Self, Malformed> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        if map.keys().any(|key| ![1, 2, 4, 5].contains(key))
            || !(1..=2).all(|k| map.contains_key(&k))
        {
            return Err(Malformed);
        }
        let lists: Vec<Vec<u8>> = map[&1]
            .as_array()?
            .iter()
            .map(|item| item.as_bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let ids = lists
            .iter()
            .map(|signed| frasil_events::decode(signed).map(|event| event.id()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Malformed)?;
        if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(Malformed);
        }
        let body_keys = read_body_key_pairs(&map[&2], usize::MAX)?;
        let entries: Vec<Vec<u8>> = match map.get(&4) {
            Some(value) => value
                .as_array()?
                .iter()
                .map(|item| item.as_bytes().map(<[u8]>::to_vec))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        if map.contains_key(&4)
            && (entries.is_empty() || !entries.windows(2).all(|pair| pair[0] < pair[1]))
        {
            return Err(Malformed);
        }
        let forgotten = match map.get(&5) {
            Some(value) => read_forgotten(value)?,
            None => Vec::new(),
        };
        Ok(Self {
            lists,
            body_keys,
            entries,
            forgotten,
        })
    }
}

/// A read-only person's list events, as a device-mailbox item's body with
/// content name `frasil/list-events`: `{1: space ID, 2: 1 to 16 signed
/// device-list events}` (section 3.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEventsBody {
    /// The space.
    pub space: EventId,
    /// The signed device-list events.
    pub events: Vec<Vec<u8>>,
}

impl ListEventsBody {
    /// The body's deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        Value::Map(Map::from([
            (1, Value::from(self.space.0)),
            (2, byte_strings(&self.events)),
        ]))
        .encode()
    }

    /// Reads a `frasil/list-events` body.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, Malformed> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        if map.len() != 2 || !map.contains_key(&1) || !map.contains_key(&2) {
            return Err(Malformed);
        }
        Ok(Self {
            space: EventId(map[&1].as_byte_array()?),
            events: read_list_events(&map[&2])?,
        })
    }
}

/// Why a writer drops a list event handed to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// It does not decode as an event, or fails identity.md's checks of its
    /// body, with this class.
    Invalid(IdentityClass),
    /// It is not a device-list event.
    NotAListEvent,
    /// It is of a person the space's roster never named.
    PersonNotNamed,
}

/// What a writer does with one list event handed to it (section 3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forwarding {
    /// Its view lacks it: it forwards it in a `frasil:list` unit.
    Forward(EventId),
    /// The system stream holds it already.
    AlreadyHeld(EventId),
    /// It drops it, and nothing else.
    Dropped(Option<EventId>, Dropped),
}

/// The person a device-list event belongs to: the list's first event's ID,
/// which every later list event carries as its log (identity.md).
pub fn person_of(event: &Event) -> EventId {
    event.log_id()
}

/// What a writer does with list events handed to it, by `ListEvents` or a
/// device-mailbox item: it checks each as a list event of a person the
/// space's roster names, now or before (`named`), and forwards it in a
/// `frasil:list` unit if its view lacks it (`held` says what the system
/// stream holds). An event that fails is dropped, and nothing else.
pub fn forward_list_events(
    events: &[Vec<u8>],
    named: impl Fn(&EventId) -> bool,
    held: impl Fn(&EventId) -> bool,
) -> Vec<Forwarding> {
    events
        .iter()
        .map(|signed| {
            let event = match frasil_events::decode(signed) {
                Ok(event) => event,
                Err(class) => {
                    let class = class.shared().unwrap_or(ErrorClass::Malformed);
                    return Forwarding::Dropped(None, Dropped::Invalid(class.into()));
                }
            };
            let id = event.id();
            if event.kind() != kind::DEVICE_LIST {
                return Forwarding::Dropped(Some(id), Dropped::NotAListEvent);
            }
            let person = event.log().map(|log| log.0);
            // The body's shape, checked alone before forwarding: the list
            // that places the event checks its signature.
            if let Err(class) = check_body(event.unverified_body(), event.author(), person.as_ref())
            {
                return Forwarding::Dropped(Some(id), Dropped::Invalid(class));
            }
            if !named(&person_of(&event)) {
                Forwarding::Dropped(Some(id), Dropped::PersonNotNamed)
            } else if held(&id) {
                Forwarding::AlreadyHeld(id)
            } else {
                Forwarding::Forward(id)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_keys_are_one_to_1024_ascending_pairs() {
        let pairs = [(EventId([2; 32]), [9; 32]), (EventId([1; 32]), [8; 32])];
        let content = body_keys_content(&pairs);
        assert_eq!(
            read_body_keys(&content),
            Ok(vec![
                (EventId([1; 32]), [8; 32]),
                (EventId([2; 32]), [9; 32])
            ])
        );
        assert_eq!(read_body_keys(&body_keys_content(&[])), Err(Malformed));
    }

    #[test]
    fn a_system_state_keeps_each_entry_once() {
        let entry = cbor::Value::Map(Map::from([(0, Value::from(1u64))])).encode();
        let state = SystemState {
            entries: vec![entry.clone(), entry.clone()],
            ..SystemState::default()
        };
        let bytes = state.encode().unwrap();
        let read = SystemState::read(&bytes).unwrap();
        assert_eq!(read.entries, vec![entry]);
        let empty = SystemState::default().encode().unwrap();
        assert_eq!(cbor::decode(&empty).unwrap().as_map().unwrap().len(), 2);
        // Key 3 is reserved.
        let mut with_three = cbor::decode(&empty).unwrap().as_map().unwrap().clone();
        with_three.insert(3, Value::Array(Vec::new()));
        assert_eq!(
            SystemState::read(&Value::Map(with_three).encode()),
            Err(Malformed)
        );
    }

    #[test]
    fn key_5_names_forgotten_list_events_per_person() {
        let (a, b) = (EventId([2; 32]), EventId([1; 32]));
        let (x, y) = (EventId([9; 32]), EventId([3; 32]));
        let state = SystemState {
            forgotten: vec![(a, vec![x, y, x]), (b, vec![y]), (EventId([7; 32]), vec![])],
            ..SystemState::default()
        };
        let bytes = state.encode().unwrap();
        let read = SystemState::read(&bytes).unwrap();
        assert_eq!(read.forgotten, vec![(b, vec![y]), (a, vec![y, x])]);
        assert_eq!(read.encode().unwrap(), bytes);
        let base = |five: Value| {
            Value::Map(Map::from([
                (1, Value::Array(Vec::new())),
                (2, Value::Array(Vec::new())),
                (5, five),
            ]))
            .encode()
        };
        let pair = |person: EventId, ids: &[EventId]| {
            Value::Array(vec![
                Value::from(person.0),
                Value::Array(ids.iter().map(|id| Value::from(id.0)).collect()),
            ])
        };
        // An empty key 5, a person with none, persons or IDs out of order,
        // and an ID that is not 32 bytes are each Malformed.
        for bad in [
            Value::Array(Vec::new()),
            Value::Array(vec![pair(a, &[])]),
            Value::Array(vec![pair(a, &[y]), pair(b, &[y])]),
            Value::Array(vec![pair(a, &[y]), pair(a, &[x])]),
            Value::Array(vec![pair(a, &[x, y])]),
            Value::Array(vec![pair(a, &[y, y])]),
            Value::Array(vec![Value::Array(vec![
                Value::from(a.0),
                Value::Array(vec![Value::from(&[1u8; 31][..])]),
            ])]),
        ] {
            assert_eq!(SystemState::read(&base(bad)), Err(Malformed));
        }
        assert!(SystemState::read(&base(Value::Array(vec![pair(b, &[y, x])]))).is_ok());
        // Without any, the key is left out.
        let none = SystemState::default().encode().unwrap();
        assert!(
            !cbor::decode(&none)
                .unwrap()
                .as_map()
                .unwrap()
                .contains_key(&5)
        );
    }

    #[test]
    fn a_list_events_body_holds_one_to_16_events() {
        let body = ListEventsBody {
            space: EventId([1; 32]),
            events: vec![b"e".to_vec()],
        };
        assert_eq!(ListEventsBody::read(&body.encode()), Ok(body));
        let empty = ListEventsBody {
            space: EventId([1; 32]),
            events: Vec::new(),
        };
        assert_eq!(ListEventsBody::read(&empty.encode()), Err(Malformed));
        assert_eq!(
            forward_list_events(&[b"not an event".to_vec()], |_| true, |_| false),
            vec![Forwarding::Dropped(
                None,
                Dropped::Invalid(ErrorClass::Malformed.into())
            )]
        );
    }
}
