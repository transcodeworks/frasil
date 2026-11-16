//! The data model and changesets (adapter-records.md, sections 2.1 and
//! 2.2), and the format checks of section 3.2, steps 1 to 3.

use crate::read;
use crate::suggestions::SuggestionKeys;
use frasil_adapter::Role;
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeSet;

/// The content version this document defines.
pub const VERSION: u64 = 1;
/// The most ops one changeset holds.
pub const MAX_OPS: usize = 65_536;
/// A table's name: 1 to 255 bytes of text.
pub const TABLE_BYTES: (usize, usize) = (1, 255);
/// A row's key: 1 to 1,024 bytes.
pub const KEY_BYTES: (usize, usize) = (1, 1024);
/// A column's name: 0 to 255 bytes of text. The empty column is the row's
/// marker.
pub const COLUMN_BYTES: (usize, usize) = (0, 255);
/// The marker column.
pub const MARKER: &str = "";
/// How many levels a value's item may nest (adapter-records.md, section
/// 2.1). In a changeset the item sits at depth 4, and in a snapshot state at
/// depth 8, so every state fits [`MAX_DEPTH`](frasil_base::cbor::MAX_DEPTH).
pub const VALUE_DEPTH: usize = 8;

/// One op: `[table, key, column, value]`, which sets one cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Op {
    /// The table.
    pub table: String,
    /// The row's key.
    pub key: Vec<u8>,
    /// The column; the empty column is the row's marker.
    pub column: String,
    /// The value: `None` for `[]`, cleared; `Some(v)` for `[v]`.
    pub value: Option<Value>,
}

impl Op {
    /// Writes a cell's value.
    pub fn set(
        table: impl Into<String>,
        key: impl Into<Vec<u8>>,
        column: impl Into<String>,
        value: Value,
    ) -> Self {
        Self {
            table: table.into(),
            key: key.into(),
            column: column.into(),
            value: Some(value),
        }
    }

    /// Clears a cell.
    pub fn clear(
        table: impl Into<String>,
        key: impl Into<Vec<u8>>,
        column: impl Into<String>,
    ) -> Self {
        Self {
            table: table.into(),
            key: key.into(),
            column: column.into(),
            value: None,
        }
    }

    /// Inserts a row: its marker `[1]` (adapter-records.md, section 3.3, "Merge
    /// and rebuild", "Rows").
    pub fn insert_row(table: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self::set(table, key, MARKER, Value::Unsigned(1))
    }

    /// Deletes a row: its marker `[]`.
    pub fn delete_row(table: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self::clear(table, key, MARKER)
    }

    /// Whether the op sets the row's marker.
    pub fn is_marker(&self) -> bool {
        self.column == MARKER
    }

    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::from(self.table.as_str()),
            Value::from(self.key.clone()),
            Value::from(self.column.as_str()),
            value_to_cbor(&self.value),
        ])
    }

    fn read(value: &Value) -> Result<Self, ErrorClass> {
        let [table, key, column, cell] = value.as_array()? else {
            return Err(ErrorClass::Malformed);
        };
        let op = Self {
            table: read::text_of(table, TABLE_BYTES.0, TABLE_BYTES.1)?.to_owned(),
            key: read::bytes_of(key, KEY_BYTES.0, KEY_BYTES.1)?.to_vec(),
            column: read::text_of(column, COLUMN_BYTES.0, COLUMN_BYTES.1)?.to_owned(),
            value: read_value(cell)?,
        };
        check_marker(&op.column, &op.value)?;
        Ok(op)
    }
}

/// A value as written: `[]` for `None`, `[v]` for `Some(v)`.
pub fn value_to_cbor(value: &Option<Value>) -> Value {
    Value::Array(value.iter().cloned().collect())
}

/// Reads a value: `[]` or `[v]`, an array of one CBOR item of the
/// deterministic subset that nests at most [`VALUE_DEPTH`] levels
/// (adapter-records.md, section 2.1, "The data model").
pub fn read_value(value: &Value) -> Result<Option<Value>, ErrorClass> {
    match value.as_array()? {
        [] => Ok(None),
        [item] if nesting(item) <= VALUE_DEPTH => Ok(Some(item.clone())),
        _ => Err(ErrorClass::Malformed),
    }
}

/// How many levels an item nests: 0 for a scalar or an empty array or map,
/// else one more than its deepest item. A map's keys are unsigned, so only
/// its values count. A decoded item nests at most [`MAX_DEPTH`](frasil_base::cbor::MAX_DEPTH)
/// levels, which bounds the recursion.
pub fn nesting(value: &Value) -> usize {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| nesting(item) + 1)
            .max()
            .unwrap_or(0),
        Value::Map(map) => map
            .values()
            .map(|item| nesting(item) + 1)
            .max()
            .unwrap_or(0),
        _ => 0,
    }
}

/// A marker's value is `[1]` or `[]`.
pub fn check_marker(column: &str, value: &Option<Value>) -> Result<(), ErrorClass> {
    match (column == MARKER, value) {
        (false, _) | (true, None | Some(Value::Unsigned(1))) => Ok(()),
        (true, Some(_)) => Err(ErrorClass::Malformed),
    }
}

/// A changeset: the content of one log unit, one transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Changeset {
    /// Key 2: the logical clock, at least 1.
    pub clock: u64,
    /// Key 3: 1 to 65,536 ops, no two naming the same cell.
    pub ops: Vec<Op>,
    /// Keys 4 to 6.
    pub keys: SuggestionKeys,
    /// Key 7: the writer's wall clock when it wrote, in seconds since
    /// 1970-01-01T00:00:00Z. Its claim, which no replica checks
    /// (adapter-records.md, section 2.2).
    pub time: Option<u64>,
}

impl Changeset {
    /// A plain changeset of these ops.
    pub fn new(clock: u64, ops: Vec<Op>) -> Self {
        Self {
            clock,
            ops,
            keys: SuggestionKeys::default(),
            time: None,
        }
    }

    /// The changeset's content.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.clock));
        map.insert(3, Value::Array(self.ops.iter().map(Op::to_value).collect()));
        self.keys.write(&mut map);
        if let Some(time) = self.time {
            map.insert(7, Value::Unsigned(time));
        }
        Value::Map(map).encode()
    }

    /// Reads a log unit's content: adapter-records.md, section 3.2, "The
    /// checks", steps 1 to 3.
    pub fn read(content: &[u8]) -> Result<Self, ErrorClass> {
        // Step 1.
        let map = read::versioned_records_map(content, VERSION)?;
        // Step 2.
        read::keys(&map, &[1, 2, 3], &[1, 2, 3, 4, 5, 6, 7])?;
        let clock = map[&2].as_unsigned()?;
        if clock < 1 {
            return Err(ErrorClass::Malformed);
        }
        let time = map.get(&7).map(Value::as_unsigned).transpose()?;
        let items = read::array_of(&map[&3], 1, MAX_OPS)?;
        let mut ops = Vec::with_capacity(items.len());
        let mut cells = BTreeSet::new();
        for item in items {
            let op = Op::read(item)?;
            if !cells.insert((op.table.clone(), op.key.clone(), op.column.clone())) {
                return Err(ErrorClass::Malformed);
            }
            ops.push(op);
        }
        // Step 3, with the rest of keys 4 to 6.
        let keys = SuggestionKeys::read(&map)?;
        Ok(Self {
            clock,
            ops,
            keys,
            time,
        })
    }
}

/// A unit's decoded content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Content {
    /// A log unit's changeset.
    Changeset(Changeset),
    /// A snapshot unit's content, which is empty.
    Snapshot,
}

impl Content {
    /// The content's bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Changeset(changeset) => changeset.encode(),
            Self::Snapshot => Vec::new(),
        }
    }

    /// Reads a unit's content by its role: adapter-records.md, section 3.2,
    /// "The checks", steps 1 to 3. A snapshot unit's content is empty; a log
    /// unit's is a changeset.
    pub fn read(content: &[u8], role: Role) -> Result<Self, ErrorClass> {
        match role {
            Role::Snapshot if content.is_empty() => Ok(Self::Snapshot),
            Role::Snapshot => Err(ErrorClass::Malformed),
            Role::Log => Changeset::read(content).map(Self::Changeset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changeset_round_trips() {
        let changeset = Changeset {
            clock: 3,
            ops: vec![
                Op::insert_row("t", b"k".to_vec()),
                Op::set("t", b"k".to_vec(), "c", Value::from("v")),
                Op::clear("t", b"k".to_vec(), "d"),
            ],
            keys: SuggestionKeys {
                dismisses: vec![[1; 32]],
                ..SuggestionKeys::default()
            },
            time: None,
        };
        let content = changeset.encode();
        assert_eq!(Changeset::read(&content), Ok(changeset.clone()));
        assert_eq!(
            Content::read(&content, Role::Log),
            Ok(Content::Changeset(changeset))
        );
        assert!(Op::delete_row("t", b"k".to_vec()).is_marker());
    }

    #[test]
    fn a_snapshot_unit_is_empty_and_a_log_unit_is_not() {
        assert_eq!(Content::read(&[], Role::Snapshot), Ok(Content::Snapshot));
        assert_eq!(Content::Snapshot.encode(), Vec::<u8>::new());
        let content = Changeset::new(1, vec![Op::insert_row("t", b"k".to_vec())]).encode();
        assert_eq!(
            Content::read(&content, Role::Snapshot),
            Err(ErrorClass::Malformed)
        );
        assert_eq!(Content::read(&[], Role::Log), Err(ErrorClass::Malformed));
    }

    #[test]
    fn refuses_what_sections_2_1_and_2_2_forbid() {
        let ok = |ops: Vec<Op>| Changeset::new(1, ops).encode();
        let long = "x".repeat(256);
        for (name, content) in [
            ("no ops", ok(vec![])),
            (
                "an empty table",
                ok(vec![Op::insert_row("", b"k".to_vec())]),
            ),
            (
                "a long table",
                ok(vec![Op::insert_row(long.clone(), b"k".to_vec())]),
            ),
            ("an empty key", ok(vec![Op::insert_row("t", Vec::new())])),
            ("a long key", ok(vec![Op::insert_row("t", vec![0; 1025])])),
            (
                "a long column",
                ok(vec![Op::set("t", b"k".to_vec(), long, Value::Unsigned(0))]),
            ),
            (
                "a marker of text",
                ok(vec![Op::set("t", b"k".to_vec(), "", Value::from("1"))]),
            ),
            (
                "a cell twice",
                ok(vec![
                    Op::insert_row("t", b"k".to_vec()),
                    Op::delete_row("t", b"k".to_vec()),
                ]),
            ),
        ] {
            assert_eq!(
                Changeset::read(&content),
                Err(ErrorClass::Malformed),
                "{name}"
            );
        }
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(1));
        map.insert(2, Value::Unsigned(1));
        map.insert(
            3,
            Value::Array(vec![Op::insert_row("t", b"k".to_vec()).to_value()]),
        );
        // Key 7, the time, is unsigned; key 8 is unknown.
        map.insert(7, Value::from("now"));
        assert_eq!(
            Changeset::read(&Value::Map(map.clone()).encode()),
            Err(ErrorClass::Malformed)
        );
        map.insert(7, Value::Unsigned(1));
        assert_eq!(
            Changeset::read(&Value::Map(map.clone()).encode()).map(|c| c.time),
            Ok(Some(1))
        );
        map.insert(8, Value::Unsigned(1));
        assert_eq!(
            Changeset::read(&Value::Map(map.clone()).encode()),
            Err(ErrorClass::Malformed)
        );
        map.remove(&8);
        map.remove(&7);
        map.remove(&2);
        assert_eq!(
            Changeset::read(&Value::Map(map).encode()),
            Err(ErrorClass::Malformed)
        );
        let max = Changeset::new(
            1,
            vec![Op::set(
                "t".repeat(255),
                vec![0; 1024],
                "c".repeat(255),
                Value::Unsigned(0),
            )],
        );
        assert!(Changeset::read(&max.encode()).is_ok());
    }
}
