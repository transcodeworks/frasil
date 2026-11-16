//! A Records stream's state: the cells with their stamps, the suggestion
//! layer and the clock (adapter-records.md, sections 3.3 and 3.4), and the
//! snapshot state, byte for byte (section 2.3).

use crate::changeset::{
    COLUMN_BYTES, Changeset, KEY_BYTES, MARKER, TABLE_BYTES, VERSION, check_marker, read_value,
    value_to_cbor,
};
use crate::clock::{Admission, Stamp};
use crate::read;
use crate::suggestions::{Layer, Suggestion};
use frasil_adapter::{Author, EventId};
use frasil_base::cbor::{self, Map, Value};
use frasil_base::collect::CollectMap;
use frasil_base::errors::ErrorClass;
use std::collections::{BTreeMap, BTreeSet};

/// One cell: its value and the stamp of the changeset that set it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    /// The value: `None` when cleared.
    pub value: Option<Value>,
    /// The stamp of the changeset that wrote it.
    pub stamp: Stamp,
    /// The time that changeset claims (adapter-records.md, section 2.2,
    /// key 7): the writer's word, never checked.
    pub time: Option<u64>,
}

/// A table's rows: each row's cells by column, by key.
pub type Rows = BTreeMap<Vec<u8>, BTreeMap<String, Cell>>;

/// The visible rows of each table: rows whose marker holds `[1]`, with
/// their other columns' values, cleared ones as `None`.
pub type Visible = BTreeMap<String, BTreeMap<Vec<u8>, BTreeMap<String, Option<Value>>>>;

/// An accepted changeset that waits for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Its author.
    pub author: Author,
    /// The changeset.
    pub changeset: Changeset,
}

/// A Records stream's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    tables: BTreeMap<String, Rows>,
    layer: Layer,
    admission: Admission<Pending>,
    included: BTreeSet<EventId>,
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
            tables: BTreeMap::new(),
            layer: Layer::new(),
            admission: Admission::new(max_clock),
            included: BTreeSet::new(),
        }
    }

    /// The tables, with every cell written, cleared or not.
    pub fn tables(&self) -> &BTreeMap<String, Rows> {
        &self.tables
    }

    /// One cell, if it has been written.
    pub fn cell(&self, table: &str, key: &[u8], column: &str) -> Option<&Cell> {
        self.tables.get(table)?.get(key)?.get(column)
    }

    /// A row's last change: its cell with the greatest stamp, the marker
    /// included (adapter-records.md, section 2.3), if any cell of the row
    /// has been written.
    pub fn last_change(&self, table: &str, key: &[u8]) -> Option<&Cell> {
        self.tables
            .get(table)?
            .get(key)?
            .values()
            .max_by_key(|cell| cell.stamp)
    }

    /// The visible rows: those whose marker holds `[1]` (adapter-records.md,
    /// section 2.1), with their other columns.
    pub fn rows(&self) -> Visible {
        let mut visible = Visible::new();
        for (table, rows) in &self.tables {
            for (key, cells) in rows {
                let exists = cells
                    .get(MARKER)
                    .is_some_and(|marker| marker.value == Some(Value::Unsigned(1)));
                if exists {
                    let columns = cells
                        .iter()
                        .filter(|(column, _)| column.as_str() != MARKER)
                        .map(|(column, cell)| (column.clone(), cell.value.clone()))
                        .collect_map();
                    visible
                        .entry(table.clone())
                        .or_default()
                        .insert(key.clone(), columns);
                }
            }
        }
        visible
    }

    /// The suggestion layer.
    pub fn layer(&self) -> &Layer {
        &self.layer
    }

    /// The floor over the base and the admitted changesets: the snapshot's
    /// `max_clock`.
    pub fn max_clock(&self) -> u64 {
        self.admission.clock().floor()
    }

    /// The clock a writer sets on its next changeset: its floor plus one,
    /// over admitted changesets only (adapter-records.md, section 3.1, "A
    /// writer's clock").
    pub fn next_clock(&self) -> u64 {
        self.admission.clock().next_clock()
    }

    /// The admission of counted changesets.
    pub fn admission(&self) -> &Admission<Pending> {
        &self.admission
    }

    /// The units applied since the state was loaded or created.
    pub fn included(&self) -> &BTreeSet<EventId> {
        &self.included
    }

    /// Counts a changeset whatever its verdict, and applies the accepted
    /// changesets it admits.
    pub fn count(&mut self, event_id: EventId, clock: u64) {
        for (id, pending) in self.admission.count(event_id, clock) {
            self.apply_admitted(id, pending.author, &pending.changeset);
        }
    }

    /// Hands over an accepted changeset. Returns whether it is applied; if
    /// not, it waits for admission (`ClockAhead`).
    pub fn submit(&mut self, event_id: EventId, author: Author, changeset: &Changeset) -> bool {
        let pending = Pending {
            author,
            changeset: changeset.clone(),
        };
        let ready = self.admission.submit(event_id, changeset.clock, pending);
        for (id, pending) in ready {
            self.apply_admitted(id, pending.author, &pending.changeset);
        }
        !self.admission.is_held(&event_id)
    }

    /// Apply, for an admitted changeset of an accepted unit
    /// (adapter-records.md, sections 3.3 and 3.4). Commutative and
    /// idempotent.
    fn apply_admitted(&mut self, event_id: EventId, author: Author, changeset: &Changeset) {
        self.included.insert(event_id);
        if changeset.keys.suggestion {
            let suggestion = Suggestion {
                author,
                content: changeset.encode(),
            };
            self.layer.suggest(event_id, suggestion);
            return;
        }
        for target in changeset.keys.targets() {
            self.layer.close(*target);
        }
        let stamp = Stamp {
            clock: changeset.clock,
            author,
            event_id,
        };
        for op in &changeset.ops {
            let cells = self
                .tables
                .entry(op.table.clone())
                .or_default()
                .entry(op.key.clone())
                .or_default();
            let newer = cells.get(&op.column).is_none_or(|cell| stamp > cell.stamp);
            if newer {
                let cell = Cell {
                    value: op.value.clone(),
                    stamp,
                    time: changeset.time,
                };
                cells.insert(op.column.clone(), cell);
            }
        }
    }

    /// The snapshot state (adapter-records.md, section 2.3, "The snapshot
    /// state"); history-free, it is the same map without key 4.
    pub fn to_bytes(&self, history_free: bool) -> Vec<u8> {
        let tables = self
            .tables
            .iter()
            .map(|(table, rows)| {
                let rows = rows
                    .iter()
                    .map(|(key, cells)| {
                        let cells = cells
                            .iter()
                            .map(|(column, cell)| {
                                let mut items = vec![
                                    Value::from(column.as_str()),
                                    value_to_cbor(&cell.value),
                                    Value::Unsigned(cell.stamp.clock),
                                    Value::from(cell.stamp.author),
                                    Value::from(cell.stamp.event_id),
                                ];
                                items.extend(cell.time.map(Value::Unsigned));
                                Value::Array(items)
                            })
                            .collect();
                        Value::Array(vec![Value::from(key.clone()), Value::Array(cells)])
                    })
                    .collect();
                Value::Array(vec![Value::from(table.as_str()), Value::Array(rows)])
            })
            .collect();
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.max_clock()));
        map.insert(3, Value::Array(tables));
        if !history_free && let Some(suggestions) = self.layer.to_value() {
            map.insert(4, suggestions);
        }
        Value::Map(map).encode()
    }

    /// Loads a snapshot state. A state that does not decode as
    /// adapter-records.md, section 2.3, "The snapshot state", is `Malformed`.
    /// Besides the format's rules, every array is strictly ascending and none
    /// is empty but `tables`, so that each state has one encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorClass> {
        // A value's item sits at depth 8 and nests at most VALUE_DEPTH
        // levels, so every state a valid cover produces fits the global
        // limit.
        let Value::Map(map) = cbor::decode_records(bytes)? else {
            return Err(ErrorClass::Malformed);
        };
        read::keys(&map, &[1, 2, 3], &[1, 2, 3, 4])?;
        if map[&1] != Value::Unsigned(VERSION) {
            return Err(ErrorClass::Malformed);
        }
        let mut state = Self::with_base(map[&2].as_unsigned()?);
        let mut previous_table: Option<&str> = None;
        for entry in map[&3].as_array()? {
            let [table, rows] = entry.as_array()? else {
                return Err(ErrorClass::Malformed);
            };
            let table = read::text_of(table, TABLE_BYTES.0, TABLE_BYTES.1)?;
            if previous_table.is_some_and(|previous| previous >= table) {
                return Err(ErrorClass::Malformed);
            }
            previous_table = Some(table);
            state.tables.insert(table.to_owned(), read_rows(rows)?);
        }
        state.layer = Layer::from_value(map.get(&4), |content| {
            Changeset::read(content).is_ok_and(|changeset| changeset.keys.suggestion)
        })?;
        Ok(state)
    }
}

fn read_rows(value: &Value) -> Result<Rows, ErrorClass> {
    let mut rows = Rows::new();
    let mut previous_key: Option<&[u8]> = None;
    for entry in read::array_of(value, 1, usize::MAX)? {
        let [key, cells] = entry.as_array()? else {
            return Err(ErrorClass::Malformed);
        };
        let key = read::bytes_of(key, KEY_BYTES.0, KEY_BYTES.1)?;
        if previous_key.is_some_and(|previous| previous >= key) {
            return Err(ErrorClass::Malformed);
        }
        previous_key = Some(key);
        rows.insert(key.to_vec(), read_cells(cells)?);
    }
    Ok(rows)
}

fn read_cells(value: &Value) -> Result<BTreeMap<String, Cell>, ErrorClass> {
    let mut cells = BTreeMap::new();
    let mut previous_column: Option<&str> = None;
    for entry in read::array_of(value, 1, usize::MAX)? {
        let (column, value, clock, author, event_id, time) = match entry.as_array()? {
            [column, value, clock, author, event_id] => {
                (column, value, clock, author, event_id, None)
            }
            [column, value, clock, author, event_id, time] => (
                column,
                value,
                clock,
                author,
                event_id,
                Some(time.as_unsigned()?),
            ),
            _ => return Err(ErrorClass::Malformed),
        };
        let column = read::text_of(column, COLUMN_BYTES.0, COLUMN_BYTES.1)?;
        if previous_column.is_some_and(|previous| previous >= column) {
            return Err(ErrorClass::Malformed);
        }
        previous_column = Some(column);
        let value = read_value(value)?;
        check_marker(column, &value)?;
        let stamp = Stamp {
            clock: clock.as_unsigned()?,
            author: author.as_byte_array::<32>()?,
            event_id: event_id.as_byte_array::<32>()?,
        };
        cells.insert(column.to_owned(), Cell { value, stamp, time });
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changeset::{Op, VALUE_DEPTH};
    use crate::suggestions::SuggestionKeys;

    fn id(n: u8) -> EventId {
        [n; 32]
    }

    fn changeset(clock: u64, ops: Vec<Op>) -> Changeset {
        Changeset::new(clock, ops)
    }

    #[test]
    fn the_greater_stamp_holds_each_cell_in_any_order() {
        let one = changeset(1, vec![Op::insert_row("t", b"r".to_vec())]);
        let two = changeset(2, vec![Op::set("t", b"r".to_vec(), "c", Value::from("a"))]);
        let tie = changeset(2, vec![Op::set("t", b"r".to_vec(), "c", Value::from("b"))]);
        let units = [
            (id(1), [1; 32], &one),
            (id(2), [2; 32], &two),
            (id(3), [3; 32], &tie),
        ];
        let mut states = Vec::new();
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
            let mut state = State::new();
            for index in order {
                let (event_id, author, changeset) = units[index];
                state.submit(event_id, author, changeset);
                // Idempotent.
                state.submit(event_id, author, changeset);
            }
            states.push(state.to_bytes(false));
        }
        assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
        let state = State::from_bytes(&states[0]).unwrap();
        let cell = state.cell("t", b"r", "c").unwrap();
        assert_eq!(cell.value, Some(Value::from("b")));
        assert_eq!(cell.stamp.author, [3; 32]);
        assert_eq!(state.to_bytes(false), states[0]);
    }

    #[test]
    fn a_deleted_row_keeps_its_cells_for_a_later_insertion() {
        let mut state = State::new();
        let insert = changeset(
            1,
            vec![
                Op::insert_row("t", b"r".to_vec()),
                Op::set("t", b"r".to_vec(), "c", Value::Unsigned(5)),
            ],
        );
        state.submit(id(1), [1; 32], &insert);
        state.submit(
            id(2),
            [1; 32],
            &changeset(2, vec![Op::delete_row("t", b"r".to_vec())]),
        );
        assert!(state.rows().is_empty());
        state.submit(
            id(3),
            [1; 32],
            &changeset(3, vec![Op::insert_row("t", b"r".to_vec())]),
        );
        let rows = state.rows();
        assert_eq!(rows["t"][&b"r".to_vec()]["c"], Some(Value::Unsigned(5)));
    }

    #[test]
    fn a_clock_ahead_waits_and_a_count_releases_it() {
        let mut state = State::new();
        let ahead = changeset(
            3,
            vec![Op::set("t", b"r".to_vec(), "c", Value::Unsigned(1))],
        );
        assert!(!state.submit(id(3), [1; 32], &ahead));
        assert_eq!(state.next_clock(), 1);
        state.count(id(1), 1);
        assert!(state.cell("t", b"r", "c").is_none());
        state.count(id(2), 2);
        assert!(state.cell("t", b"r", "c").is_some());
        assert_eq!(state.max_clock(), 3);
        assert_eq!(state.included(), &BTreeSet::from([id(3)]));
    }

    #[test]
    fn suggestions_and_the_history_free_export() {
        let mut state = State::new();
        let suggestion = Changeset {
            clock: 1,
            ops: vec![Op::insert_row("t", b"r".to_vec())],
            keys: SuggestionKeys {
                suggestion: true,
                ..SuggestionKeys::default()
            },
            time: None,
        };
        state.submit(id(9), [1; 32], &suggestion);
        assert!(state.rows().is_empty());
        assert!(state.layer().is_open(&id(9)));
        let full = state.to_bytes(false);
        let free = state.to_bytes(true);
        assert_ne!(full, free);
        assert_eq!(State::from_bytes(&full).unwrap().to_bytes(false), full);
        assert!(!State::from_bytes(&free).unwrap().layer().is_open(&id(9)));
    }

    #[test]
    fn refuses_a_state_that_does_not_decode() {
        let row =
            |cells: Vec<Value>| Value::Array(vec![Value::from(b"r".to_vec()), Value::Array(cells)]);
        let cell = |column: &str, value: Value| {
            Value::Array(vec![
                Value::from(column),
                value,
                Value::Unsigned(1),
                Value::from([1u8; 32]),
                Value::from([2u8; 32]),
            ])
        };
        let state = |tables: Vec<Value>| {
            let mut map = Map::new();
            map.insert(1, Value::Unsigned(1));
            map.insert(2, Value::Unsigned(1));
            map.insert(3, Value::Array(tables));
            Value::Map(map).encode()
        };
        let table = |name: &str, rows: Vec<Value>| {
            Value::Array(vec![Value::from(name), Value::Array(rows)])
        };
        let one = Value::Array(vec![Value::Unsigned(1)]);
        let good = state(vec![table("t", vec![row(vec![cell("", one.clone())])])]);
        assert!(State::from_bytes(&good).is_ok());
        assert!(State::from_bytes(&state(vec![])).is_ok());
        for bad in [
            state(vec![table("t", vec![])]),
            state(vec![table("t", vec![row(vec![])])]),
            state(vec![table("", vec![row(vec![cell("c", one.clone())])])]),
            state(vec![
                table("u", vec![row(vec![cell("c", one.clone())])]),
                table("t", vec![row(vec![cell("c", one.clone())])]),
            ]),
            state(vec![table(
                "t",
                vec![row(vec![cell("c", one.clone()), cell("c", one.clone())])],
            )]),
            state(vec![table(
                "t",
                vec![row(vec![cell("", Value::Array(vec![Value::Unsigned(2)]))])],
            )]),
        ] {
            assert_eq!(State::from_bytes(&bad), Err(ErrorClass::Malformed));
        }
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(2));
        map.insert(2, Value::Unsigned(1));
        map.insert(3, Value::Array(vec![]));
        assert!(State::from_bytes(&Value::Map(map).encode()).is_err());
    }

    #[test]
    fn a_nested_value_fits_the_state() {
        // A value item nested to its own limit, in arrays and in maps.
        for wrap in [
            (|v: Value| Value::Array(vec![v])) as fn(Value) -> Value,
            |v: Value| Value::Map(Map::from([(0, v)])),
        ] {
            let mut nested = Value::Unsigned(1);
            for _ in 0..VALUE_DEPTH {
                nested = wrap(nested);
            }
            let content =
                changeset(1, vec![Op::set("t", b"r".to_vec(), "c", nested.clone())]).encode();
            let read = Changeset::read(&content).unwrap();
            let mut state = State::new();
            state.submit(id(1), [1; 32], &read);
            let bytes = state.to_bytes(false);
            assert_eq!(State::from_bytes(&bytes).unwrap().to_bytes(false), bytes);
            // One level more is refused in the changeset.
            let deeper = changeset(1, vec![Op::set("t", b"r".to_vec(), "c", wrap(nested))]);
            assert_eq!(
                Changeset::read(&deeper.encode()),
                Err(ErrorClass::Malformed)
            );
        }
    }
}
