//! A Blobs unit's content (adapter-blobs.md, section 2.1, "Content"), and the
//! format checks of section 3.1, steps 1 and 2.

use crate::entry::{Entry, KeyForm};
use frasil_adapter::{Locator, Role};
use frasil_adapter_records::{SuggestionKeys, read};
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeSet;

/// The content version this document defines.
pub const VERSION: u64 = 1;
/// The most ops one unit holds.
pub const MAX_OPS: usize = 1024;
/// A handle's length.
pub const HANDLE_BYTES: usize = 16;

/// A handle: 16 random bytes, drawn by the writer that first puts it.
pub type Handle = [u8; HANDLE_BYTES];

/// One op: `[handle]`, a remove, or `[handle, entry]`, a put.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Op {
    /// The handle.
    pub handle: Handle,
    /// The entry put, or `None` for a remove.
    pub entry: Option<Entry>,
}

impl Op {
    /// A put.
    pub fn put(handle: Handle, entry: Entry) -> Self {
        Self {
            handle,
            entry: Some(entry),
        }
    }

    /// A remove: a put of nothing.
    pub fn remove(handle: Handle) -> Self {
        Self {
            handle,
            entry: None,
        }
    }

    fn to_value(&self) -> Value {
        let mut items = vec![Value::from(self.handle)];
        items.extend(self.entry.as_ref().map(Entry::to_value));
        Value::Array(items)
    }

    fn read(value: &Value, form: Option<KeyForm>) -> Result<Self, ErrorClass> {
        match value.as_array()? {
            [handle] => Ok(Self::remove(handle.as_byte_array()?)),
            [handle, entry] => {
                let handle = handle.as_byte_array()?;
                let entry = match form {
                    Some(form) => Entry::read_as(entry, form)?,
                    None => Entry::read(entry)?,
                };
                Ok(Self::put(handle, entry))
            }
            _ => Err(ErrorClass::Malformed),
        }
    }
}

/// A log unit's content: a clock, ops and keys 4 to 6.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change {
    /// Key 2: the logical clock, at least 1.
    pub clock: u64,
    /// Key 3: 1 to 1,024 ops, no two naming the same handle.
    pub ops: Vec<Op>,
    /// Keys 4 to 6, as adapter-records.md, section 2.2, "Changesets", says.
    pub keys: SuggestionKeys,
}

impl Change {
    /// A plain unit of these ops.
    pub fn new(clock: u64, ops: Vec<Op>) -> Self {
        Self {
            clock,
            ops,
            keys: SuggestionKeys::default(),
        }
    }

    /// The content's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.clock));
        map.insert(3, Value::Array(self.ops.iter().map(Op::to_value).collect()));
        self.keys.write(&mut map);
        Value::Map(map).encode()
    }

    /// The locators its puts name, which its unit lists in `objects`.
    pub fn objects(&self) -> BTreeSet<Locator> {
        self.ops
            .iter()
            .filter_map(|op| op.entry.as_ref().map(|entry| entry.object))
            .collect()
    }

    /// Reads a log unit's content already checked, its key references in
    /// either form.
    pub fn read(content: &[u8]) -> Result<Self, ErrorClass> {
        Self::read_in(content, None)
    }

    /// Reads a log unit's content: adapter-blobs.md, section 3.1, "The checks",
    /// steps 1 and 2, its key references in its space's `form`. Step 3, the
    /// objects check, is [`check_objects`](Self::check_objects).
    pub fn read_as(content: &[u8], form: KeyForm) -> Result<Self, ErrorClass> {
        Self::read_in(content, Some(form))
    }

    fn read_in(content: &[u8], form: Option<KeyForm>) -> Result<Self, ErrorClass> {
        // Step 1.
        let map = read::versioned_map(content, VERSION)?;
        // Step 2.
        read::keys(&map, &[1, 2, 3], &[1, 2, 3, 4, 5, 6])?;
        let clock = map[&2].as_unsigned()?;
        if clock < 1 {
            return Err(ErrorClass::Malformed);
        }
        let keys = SuggestionKeys::read(&map)?;
        let items = read::array_of(&map[&3], 1, MAX_OPS)?;
        let mut ops = Vec::with_capacity(items.len());
        let mut handles = BTreeSet::new();
        for item in items {
            let op = Op::read(item, form)?;
            if !handles.insert(op.handle) {
                return Err(ErrorClass::Malformed);
            }
            ops.push(op);
        }
        Ok(Self { clock, ops, keys })
    }

    /// Step 3: every put's locator is in the unit's `objects`. Else
    /// `ObjectNotListed`, which the caller names.
    pub fn check_objects(&self, objects: &[Locator]) -> bool {
        self.ops
            .iter()
            .filter_map(|op| op.entry.as_ref())
            .all(|entry| objects.contains(&entry.object))
    }
}

/// A unit's decoded content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Content {
    /// A log unit's content.
    Change(Change),
    /// A snapshot unit's content, which is empty.
    Snapshot,
}

impl Content {
    /// The content's bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Change(change) => change.encode(),
            Self::Snapshot => Vec::new(),
        }
    }

    /// Reads a unit's content by its role, already checked, its key
    /// references in either form. A snapshot unit's content is empty.
    pub fn read(content: &[u8], role: Role) -> Result<Self, ErrorClass> {
        Self::read_in(content, role, None)
    }

    /// Reads a unit's content by its role: adapter-blobs.md, section 3.1, "The
    /// checks", steps 1 and 2, its key references in its space's `form`. A
    /// snapshot unit's content is empty.
    pub fn read_as(content: &[u8], role: Role, form: KeyForm) -> Result<Self, ErrorClass> {
        Self::read_in(content, role, Some(form))
    }

    fn read_in(content: &[u8], role: Role, form: Option<KeyForm>) -> Result<Self, ErrorClass> {
        match role {
            Role::Snapshot if content.is_empty() => Ok(Self::Snapshot),
            Role::Snapshot => Err(ErrorClass::Malformed),
            Role::Log => Change::read_in(content, form).map(Self::Change),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(object: u8) -> Entry {
        let mut key = vec![1];
        key.extend([9; 32]);
        Entry {
            object: [object; 64],
            key,
            size: 3,
            media_type: None,
            name: None,
            reference: None,
        }
    }

    #[test]
    fn a_change_round_trips_and_names_its_objects() {
        let change = Change::new(2, vec![Op::put([1; 16], entry(5)), Op::remove([2; 16])]);
        let content = change.encode();
        assert_eq!(Change::read(&content), Ok(change.clone()));
        assert_eq!(change.objects(), BTreeSet::from([[5; 64]]));
        assert!(change.check_objects(&[[5; 64]]));
        assert!(!change.check_objects(&[]));
        assert_eq!(
            Content::read(&content, Role::Log),
            Ok(Content::Change(change))
        );
        assert_eq!(Content::read(&[], Role::Snapshot), Ok(Content::Snapshot));
        assert_eq!(
            Content::read(&content, Role::Snapshot),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn refuses_what_section_2_1_forbids() {
        let too_many: Vec<Op> = (0..=1024u16)
            .map(|n| {
                let mut handle = [0; 16];
                handle[..2].copy_from_slice(&n.to_be_bytes());
                Op::remove(handle)
            })
            .collect();
        for content in [
            Change::new(1, vec![]).encode(),
            Change::new(0, vec![Op::remove([1; 16])]).encode(),
            Change::new(1, vec![Op::remove([1; 16]), Op::put([1; 16], entry(1))]).encode(),
            Change::new(1, too_many).encode(),
        ] {
            assert_eq!(Change::read(&content), Err(ErrorClass::Malformed));
        }
    }
}
