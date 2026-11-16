//! A Blobs stream's state: each handle's entry, or none, with its stamp,
//! the suggestion layer and the clock (adapter-blobs.md, sections 3.2 and
//! 3.3), and the snapshot state, byte for byte (section 2.2).

use crate::content::{Change, HANDLE_BYTES, Handle, VERSION};
use crate::entry::Entry;
use crate::versions::Versions;
use frasil_adapter::{Author, EventId, Locator, Supersession};
use frasil_adapter_records::{Admission, Layer, Stamp, Suggestion, read};
use frasil_base::cbor::{self, Map, Value};
use frasil_base::errors::ErrorClass;
use std::collections::{BTreeMap, BTreeSet};

/// One handle's slot: its entry, or `None` once removed, and the stamp of
/// the unit that set it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Slot {
    /// The current entry, or `None` for a removed handle.
    pub entry: Option<Entry>,
    /// The stamp of the unit that put or removed it.
    pub stamp: Stamp,
}

/// An accepted unit that waits for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Its author.
    pub author: Author,
    /// Its content.
    pub change: Change,
    /// The supersessions its body carries.
    pub supersedes: Vec<Supersession>,
}

/// A Blobs stream's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    entries: BTreeMap<Handle, Slot>,
    layer: Layer,
    admission: Admission<Pending>,
    included: BTreeSet<EventId>,
    versions: Versions,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// A stream's state before any unit, over no base.
    pub fn new() -> Self {
        Self::with_base(0)
    }

    fn with_base(max_clock: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            layer: Layer::new(),
            admission: Admission::new(max_clock),
            included: BTreeSet::new(),
            versions: Versions::default(),
        }
    }

    pub(crate) fn versions_ref(&self) -> &Versions {
        &self.versions
    }

    pub(crate) fn versions_mut(&mut self) -> &mut Versions {
        &mut self.versions
    }

    /// Every handle written, removed ones included.
    pub fn slots(&self) -> &BTreeMap<Handle, Slot> {
        &self.entries
    }

    /// A handle's current entry, if it has one.
    pub fn entry(&self, handle: &Handle) -> Option<&Entry> {
        self.entries.get(handle)?.entry.as_ref()
    }

    /// The current entries, by handle.
    pub fn current(&self) -> impl Iterator<Item = (&Handle, &Entry)> {
        self.entries
            .iter()
            .filter_map(|(handle, slot)| slot.entry.as_ref().map(|entry| (handle, entry)))
    }

    /// The suggestion layer.
    pub fn layer(&self) -> &Layer {
        &self.layer
    }

    /// The floor: the snapshot's `max_clock`.
    pub fn max_clock(&self) -> u64 {
        self.admission.clock().floor()
    }

    /// The clock a writer sets on its next unit.
    pub fn next_clock(&self) -> u64 {
        self.admission.clock().next_clock()
    }

    /// The admission of counted units.
    pub fn admission(&self) -> &Admission<Pending> {
        &self.admission
    }

    /// The units applied since the state was loaded or created.
    pub fn included(&self) -> &BTreeSet<EventId> {
        &self.included
    }

    /// The locators a snapshot unit lists besides its snapshot object:
    /// every current entry's, and every put's in an open suggestion
    /// (adapter-blobs.md, section 3.4, "Compaction").
    pub fn objects(&self) -> BTreeSet<Locator> {
        let mut objects: BTreeSet<Locator> =
            self.current().map(|(_, entry)| entry.object).collect();
        objects.extend(self.suggestion_objects());
        objects
    }

    /// The locators the puts of open suggestions name.
    pub(crate) fn suggestion_objects(&self) -> BTreeSet<Locator> {
        self.layer
            .open()
            .values()
            .filter_map(|suggestion| Change::read(&suggestion.content).ok())
            .flat_map(|change| change.objects())
            .collect()
    }

    /// Counts a unit whatever its verdict, and applies the accepted units
    /// it admits.
    pub fn count(&mut self, event_id: EventId, clock: u64) {
        for (id, pending) in self.admission.count(event_id, clock) {
            self.apply_admitted(id, &pending);
        }
    }

    /// Hands over an accepted unit. Returns whether it is applied; if not,
    /// it waits for admission (`ClockAhead`).
    pub fn submit(&mut self, event_id: EventId, author: Author, change: &Change) -> bool {
        self.submit_with(event_id, author, change, &[])
    }

    /// [`submit`](Self::submit), with the supersessions the unit's body
    /// carries.
    pub fn submit_with(
        &mut self,
        event_id: EventId,
        author: Author,
        change: &Change,
        supersedes: &[Supersession],
    ) -> bool {
        let pending = Pending {
            author,
            change: change.clone(),
            supersedes: supersedes.to_vec(),
        };
        for (id, pending) in self.admission.submit(event_id, change.clock, pending) {
            self.apply_admitted(id, &pending);
        }
        !self.admission.is_held(&event_id)
    }

    /// Apply, for an admitted unit that is accepted (adapter-blobs.md,
    /// sections 3.2 and 3.3): each handle whose stamp is less than the
    /// unit's, or that has none, takes the op's entry or nothing.
    fn apply_admitted(&mut self, event_id: EventId, pending: &Pending) {
        let (author, change) = (pending.author, &pending.change);
        self.included.insert(event_id);
        if !pending.supersedes.is_empty() {
            let puts = change
                .ops
                .iter()
                .filter_map(|op| op.entry.as_ref().map(|entry| entry.object))
                .collect();
            self.versions.apply(event_id, &pending.supersedes, &puts);
        }
        if change.keys.suggestion {
            let suggestion = Suggestion {
                author,
                content: change.encode(),
            };
            self.layer.suggest(event_id, suggestion);
            return;
        }
        for target in change.keys.targets() {
            self.layer.close(*target);
        }
        let stamp = Stamp {
            clock: change.clock,
            author,
            event_id,
        };
        for op in &change.ops {
            let newer = self
                .entries
                .get(&op.handle)
                .is_none_or(|slot| stamp > slot.stamp);
            if newer {
                let slot = Slot {
                    entry: op.entry.clone(),
                    stamp,
                };
                self.entries.insert(op.handle, slot);
            }
        }
    }

    /// The snapshot state (adapter-blobs.md, section 2.2, "The snapshot
    /// state"). History-free, it is the same map without key 4 and without
    /// removed handles.
    pub fn to_bytes(&self, history_free: bool) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .filter(|(_, slot)| !history_free || slot.entry.is_some())
            .map(|(handle, slot)| {
                let entry = match &slot.entry {
                    Some(entry) => entry.to_value(),
                    None => Value::Array(Vec::new()),
                };
                Value::Array(vec![
                    Value::from(*handle),
                    entry,
                    Value::Unsigned(slot.stamp.clock),
                    Value::from(slot.stamp.author),
                    Value::from(slot.stamp.event_id),
                ])
            })
            .collect();
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.max_clock()));
        map.insert(3, Value::Array(entries));
        if !history_free && let Some(suggestions) = self.layer.to_value() {
            map.insert(4, suggestions);
        }
        Value::Map(map).encode()
    }

    /// Loads a snapshot state. A state that does not decode as
    /// adapter-blobs.md, section 2.2, "The snapshot state", is `Malformed`.
    /// Entries are strictly ascending by handle, and key 4, when present, holds
    /// 1 or more suggestions, so that each state has one encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorClass> {
        let Value::Map(map) = cbor::decode(bytes)? else {
            return Err(ErrorClass::Malformed);
        };
        read::keys(&map, &[1, 2, 3], &[1, 2, 3, 4])?;
        if map[&1] != Value::Unsigned(VERSION) {
            return Err(ErrorClass::Malformed);
        }
        let mut state = Self::with_base(map[&2].as_unsigned()?);
        let mut previous: Option<Handle> = None;
        for row in map[&3].as_array()? {
            let [handle, entry, clock, author, event_id] = row.as_array()? else {
                return Err(ErrorClass::Malformed);
            };
            let handle = handle.as_byte_array::<HANDLE_BYTES>()?;
            if previous.is_some_and(|previous| previous >= handle) {
                return Err(ErrorClass::Malformed);
            }
            previous = Some(handle);
            let entry = match entry {
                Value::Array(items) if items.is_empty() => None,
                other => Some(Entry::read(other)?),
            };
            let stamp = Stamp {
                clock: clock.as_unsigned()?,
                author: author.as_byte_array::<32>()?,
                event_id: event_id.as_byte_array::<32>()?,
            };
            state.entries.insert(handle, Slot { entry, stamp });
        }
        state.layer = Layer::from_value(map.get(&4), |content| {
            Change::read(content).is_ok_and(|change| change.keys.suggestion)
        })?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::Op;
    use frasil_adapter_records::SuggestionKeys;

    fn entry(object: u8) -> Entry {
        let mut key = vec![1];
        key.extend([9; 32]);
        Entry {
            object: [object; 64],
            key,
            size: 3,
            media_type: Some("image/png".to_owned()),
            name: None,
            reference: None,
        }
    }

    #[test]
    fn a_remove_moves_the_stamp_and_a_later_put_wins() {
        let mut state = State::new();
        state.submit(
            [1; 32],
            [1; 32],
            &Change::new(1, vec![Op::put([1; 16], entry(1))]),
        );
        state.submit([2; 32], [1; 32], &Change::new(2, vec![Op::remove([1; 16])]));
        assert!(state.entry(&[1; 16]).is_none());
        // An older put does not bring it back.
        state.submit(
            [3; 32],
            [2; 32],
            &Change::new(1, vec![Op::put([1; 16], entry(2))]),
        );
        assert!(state.entry(&[1; 16]).is_none());
        state.submit(
            [4; 32],
            [2; 32],
            &Change::new(3, vec![Op::put([1; 16], entry(3))]),
        );
        assert_eq!(state.entry(&[1; 16]), Some(&entry(3)));
        let bytes = state.to_bytes(false);
        assert_eq!(State::from_bytes(&bytes).unwrap().to_bytes(false), bytes);
    }

    #[test]
    fn open_suggestions_keep_their_objects_referenced() {
        let mut state = State::new();
        let suggestion = Change {
            clock: 1,
            ops: vec![Op::put([2; 16], entry(8))],
            keys: SuggestionKeys {
                suggestion: true,
                ..SuggestionKeys::default()
            },
        };
        state.submit([5; 32], [1; 32], &suggestion);
        state.submit(
            [6; 32],
            [1; 32],
            &Change::new(1, vec![Op::put([1; 16], entry(7))]),
        );
        state.submit([7; 32], [1; 32], &Change::new(2, vec![Op::remove([3; 16])]));
        assert_eq!(state.objects(), BTreeSet::from([[7; 64], [8; 64]]));
        let full = state.to_bytes(false);
        let loaded = State::from_bytes(&full).unwrap();
        assert_eq!(loaded.objects(), state.objects());
        let free = State::from_bytes(&state.to_bytes(true)).unwrap();
        assert_eq!(free.objects(), BTreeSet::from([[7; 64]]));
        assert_eq!(free.slots().len(), 1);
    }

    #[test]
    fn refuses_a_state_that_does_not_decode() {
        let row = |handle: u8| {
            Value::Array(vec![
                Value::from([handle; 16]),
                Value::Array(vec![]),
                Value::Unsigned(1),
                Value::from([1u8; 32]),
                Value::from([2u8; 32]),
            ])
        };
        let state = |rows: Vec<Value>, extra: Option<(u64, Value)>| {
            let mut map = Map::new();
            map.insert(1, Value::Unsigned(1));
            map.insert(2, Value::Unsigned(1));
            map.insert(3, Value::Array(rows));
            if let Some((key, value)) = extra {
                map.insert(key, value);
            }
            Value::Map(map).encode()
        };
        assert!(State::from_bytes(&state(vec![row(1), row(2)], None)).is_ok());
        for bad in [
            state(vec![row(2), row(1)], None),
            state(vec![row(1), row(1)], None),
            state(vec![], Some((4, Value::Array(vec![])))),
            state(vec![], Some((5, Value::Unsigned(0)))),
        ] {
            assert_eq!(State::from_bytes(&bad), Err(ErrorClass::Malformed));
        }
    }
}
