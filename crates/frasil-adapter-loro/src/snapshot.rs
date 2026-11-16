//! The snapshot state's framing (adapter-loro.md, section 2.4, "The
//! snapshot state").
//!
//! The `state` of a stream snapshot object (units.md, section 2.9) is a
//! deterministic CBOR map:
//!
//! | Key | Name | Value |
//! |---|---|---|
//! | 1 | `version` | 1 |
//! | 2 | `main` | bytes: `LoroDoc::export(ExportMode::Snapshot)` of the main document; when history-free, `ExportMode::ShallowSnapshot` at its current frontiers |
//! | 3 | `suggestions` | optional: array of `[unit ID, author, incarnation, blob]`, strictly ascending by unit ID: the open suggestions |
//! | 4 | `dismissed` | optional: as key 3, for the dismissed suggestions; never in a history-free state |
//!
//! This module reads and writes the framing, and [`check`] runs the checks
//! of section 3.5, "Loading a state", that come before Loro reads `main`;
//! what Loro makes of `main` and each `blob` is
//! [`State::load`](crate::State)'s.

use crate::content::VERSION;
use crate::{meta::BlobMeta, screen};
use frasil_adapter::{Author, EventId};
use frasil_base::cbor::{self, Map, Value};
use frasil_base::errors::ErrorClass;

/// The most bytes a snapshot state holds (adapter-loro.md, 3.5,
/// "Loading a state"): what a replica holds whole and decodes.
pub const MAX_STATE_BYTES: usize = 1 << 28;

/// The checks of section 3.5, "Loading a state", that come before the
/// pinned Loro reads the state: its size, its framing, its `main` read as
/// the pinned Loro reads it and within the section's limits, and each
/// suggestion's blob passing step 4 of section 3.2. A state they refuse is
/// `Malformed`, and a compactor does not write it (section 3.1).
pub fn check(bytes: &[u8]) -> Result<SnapshotState, ErrorClass> {
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let state = SnapshotState::read(bytes)?;
    if !screen::snapshot(&state.main) {
        return Err(ErrorClass::Malformed);
    }
    let blobs_pass = state
        .suggestions
        .iter()
        .chain(&state.dismissed)
        .all(|row| BlobMeta::read(&row.blob).is_some_and(|meta| meta.is_updates()));
    if !blobs_pass {
        return Err(ErrorClass::Malformed);
    }
    Ok(state)
}

/// The entries, key then value, of the change store, the state store and
/// the shallow root's state store of a snapshot export, as the pinned Loro
/// reads its tables; `None` when they do not read. Not part of the
/// adapter's interface: tests and fuzz targets build snapshots from the
/// entries of real ones.
#[doc(hidden)]
#[allow(clippy::type_complexity)]
pub fn snapshot_tables(main: &[u8]) -> Option<[Vec<(Vec<u8>, Vec<u8>)>; 3]> {
    screen::tables(main)
}

/// One suggestion of the snapshot state's key 3 or 4.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LayerRow {
    /// The suggestion's unit ID.
    pub unit: EventId,
    /// Its author.
    pub author: Author,
    /// Its incarnation: its own `seq`.
    pub incarnation: u64,
    /// Its blob, as the unit carries it.
    pub blob: Vec<u8>,
}

impl LayerRow {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::from(self.unit),
            Value::from(self.author),
            Value::Unsigned(self.incarnation),
            Value::from(self.blob.clone()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ErrorClass> {
        let [unit, author, incarnation, blob] = value.as_array()? else {
            return Err(ErrorClass::Malformed);
        };
        let incarnation = incarnation.as_unsigned()?;
        if incarnation < 1 {
            return Err(ErrorClass::Malformed);
        }
        Ok(Self {
            unit: unit.as_byte_array::<32>()?,
            author: author.as_byte_array::<32>()?,
            incarnation,
            blob: blob.as_bytes()?.to_vec(),
        })
    }
}

/// A snapshot state, framed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnapshotState {
    /// Key 2: the main document's export.
    pub main: Vec<u8>,
    /// Key 3: the open suggestions, strictly ascending by unit ID.
    pub suggestions: Vec<LayerRow>,
    /// Key 4: the dismissed suggestions, strictly ascending by unit ID.
    pub dismissed: Vec<LayerRow>,
}

impl SnapshotState {
    /// The state's one deterministic encoding. Keys 3 and 4 are left out
    /// when empty; rows are written in ascending order of unit ID.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::from(self.main.clone()));
        for (key, rows) in [(3, &self.suggestions), (4, &self.dismissed)] {
            if !rows.is_empty() {
                let mut rows = rows.clone();
                rows.sort();
                map.insert(
                    key,
                    Value::Array(rows.iter().map(LayerRow::to_value).collect()),
                );
            }
        }
        Value::Map(map).encode()
    }

    /// Reads a state's framing. Anything that does not decode as section
    /// 2.4 frames it is `Malformed`, a version other than 1 included, and so
    /// is a unit ID in both key 3 and key 4.
    pub fn read(bytes: &[u8]) -> Result<Self, ErrorClass> {
        let Value::Map(map) = cbor::decode(bytes)? else {
            return Err(ErrorClass::Malformed);
        };
        let rules = cbor::KeyRules {
            required: &[1, 2],
            optional: &[3, 4],
            unknown: cbor::UnknownKeys::Malformed,
        };
        rules.check(&map)?;
        if map[&1].as_unsigned()? != VERSION {
            return Err(ErrorClass::Malformed);
        }
        let main = map[&2].as_bytes()?.to_vec();
        let suggestions = read_rows(map.get(&3))?;
        let dismissed = read_rows(map.get(&4))?;
        let both = suggestions.iter().any(|row| {
            dismissed
                .binary_search_by(|other| other.unit.cmp(&row.unit))
                .is_ok()
        });
        if both {
            return Err(ErrorClass::Malformed);
        }
        Ok(Self {
            main,
            suggestions,
            dismissed,
        })
    }
}

fn read_rows(value: Option<&Value>) -> Result<Vec<LayerRow>, ErrorClass> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(ErrorClass::Malformed);
    }
    let rows = items
        .iter()
        .map(LayerRow::from_value)
        .collect::<Result<Vec<_>, _>>()?;
    if !rows.windows(2).all(|pair| pair[0].unit < pair[1].unit) {
        return Err(ErrorClass::Malformed);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(unit: u8) -> LayerRow {
        LayerRow {
            unit: [unit; 32],
            author: [9; 32],
            incarnation: 4,
            blob: vec![unit],
        }
    }

    #[test]
    fn round_trips_and_sorts_its_rows() {
        let state = SnapshotState {
            main: b"main".to_vec(),
            suggestions: vec![row(2), row(1)],
            dismissed: vec![row(3)],
        };
        let read = SnapshotState::read(&state.encode()).unwrap();
        assert_eq!(read.suggestions, vec![row(1), row(2)]);
        assert_eq!(read.dismissed, vec![row(3)]);
        assert_eq!(read.encode(), state.encode());
        let bare = SnapshotState {
            main: Vec::new(),
            suggestions: Vec::new(),
            dismissed: Vec::new(),
        };
        assert_eq!(SnapshotState::read(&bare.encode()), Ok(bare));
    }

    #[test]
    fn refuses_what_section_2_4_forbids() {
        let encode =
            |entries: Vec<(u64, Value)>| Value::Map(entries.into_iter().collect()).encode();
        let rows = |r: Vec<LayerRow>| Value::Array(r.iter().map(LayerRow::to_value).collect());
        let main = (2, Value::from(b"m".to_vec()));
        let one = (1, Value::Unsigned(1));
        for bad in [
            encode(vec![one.clone()]),
            encode(vec![(1, Value::Unsigned(2)), main.clone()]),
            encode(vec![one.clone(), main.clone(), (3, Value::Array(vec![]))]),
            encode(vec![
                one.clone(),
                main.clone(),
                (3, rows(vec![row(2), row(1)])),
            ]),
            encode(vec![
                one.clone(),
                main.clone(),
                (3, rows(vec![row(1), row(1)])),
            ]),
            encode(vec![
                one.clone(),
                main.clone(),
                (3, rows(vec![row(1)])),
                (4, rows(vec![row(1)])),
            ]),
            encode(vec![one.clone(), main.clone(), (5, Value::Unsigned(0))]),
            encode(vec![
                one.clone(),
                main.clone(),
                (
                    3,
                    Value::Array(vec![Value::Array(vec![Value::from([1u8; 32])])]),
                ),
            ]),
            encode(vec![
                one.clone(),
                main,
                (
                    4,
                    Value::Array(vec![Value::Array(vec![
                        Value::from([1u8; 32]),
                        Value::from([2u8; 32]),
                        Value::Unsigned(0),
                        Value::from(vec![1u8]),
                    ])]),
                ),
            ]),
            Vec::new(),
        ] {
            assert_eq!(
                SnapshotState::read(&bad),
                Err(ErrorClass::Malformed),
                "{bad:02x?}"
            );
        }
    }
}
