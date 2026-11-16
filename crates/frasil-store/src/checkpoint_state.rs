//! What a log keeps of its checkpoints beside `state` key 7 (at-rest.md,
//! "Forgetting before a checkpoint", "Starting from a checkpoint" and
//! "Lists after a list checkpoint"; roster.md, 3.15.6 Forgetting).
//!
//! A device that forgot a log's past, or started a space from a checkpoint
//! a snapshot named, needs three things again when it reopens the log, each
//! in records of its own:
//!
//! - **record keys**: the record object key of a checkpoint, a `key` record
//!   of kind 5 named by the checkpoint's event ID, without which the kept
//!   checkpoint's record cannot be read again;
//! - **dropped events**: a `dropped` record for every event it dropped,
//!   with its envelope's kind and, for a parent of an event it keeps of the
//!   kept checkpoint's past, its height; and for every parent a peer answered
//!   `Missing` for at a newcomer, so that such a parent contributes nothing
//!   and is never waited for or fetched again;
//! - **events kept alone**: `event` records in state 6, never judged: in a
//!   space, the envelopes of the checkpoints its kept checkpoint's cuts
//!   reach, which order every later cut.
//!
//! [`CheckpointState`] gathers them for a log ([`CheckpointState::take`])
//! and gives the records that hold them ([`CheckpointState::records`]).
//!
//! The same commit also writes keys 6 to 8 of the `event` record of each
//! unit of the forgotten past that the log keeps
//! ([`crate::tables::Frozen`]), and keeps the `key` records of kind 1 of
//! every rotation whose state seals a unit, object or name the log keeps,
//! though it drops the rotation event ([`rotation_keys_dropped`]): those
//! secrets were checked against the rotation's commitments while the device
//! held the event, so after a restart a kept unit sealed under that state
//! opens without it, and a device takes such a record's secrets as checked
//! ([`kept_rotation_key`]).

use crate::tables::{
    DroppedOrigin, EventRecord, EventState, FLAG_VERIFIED, KeyKind, KeyValue, RecordKey, Secret,
    Table, TableValue,
};
use frasil_base::cbor::{self, Value};
use frasil_keys::RotationSet;
use std::collections::BTreeSet;

/// An event a log holds no more: its ID and why (the `dropped` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Dropped {
    /// The event's ID.
    pub id: [u8; 32],
    /// Dropped by this device, with its kind, or answered `Missing`.
    pub origin: DroppedOrigin,
}

/// What a log keeps of its checkpoints beside `state` key 7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointState {
    /// Record object keys a space snapshot handed over, by checkpoint,
    /// strictly ascending: `key` records of kind 5, source 2.
    pub record_keys: Vec<([u8; 32], Secret)>,
    /// The events the device dropped or a peer answered `Missing` for,
    /// strictly ascending by ID: `dropped` records.
    pub dropped: Vec<Dropped>,
    /// The kept checkpoint envelopes, signed: `event` records in state 6.
    pub kept_envelopes: Vec<Vec<u8>>,
}

impl core::hash::Hash for CheckpointState {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // The keys are secret: only the checkpoints they open are hashed.
        for (checkpoint, _) in &self.record_keys {
            checkpoint.hash(state);
        }
        self.dropped.hash(state);
        self.kept_envelopes.hash(state);
    }
}

/// The event ID of a signed event, `[event, signature]`: the hash of its
/// event bytes, as the `event` table names it.
fn signed_id(signed: &[u8]) -> Option<[u8; 32]> {
    let Ok(Value::Array(outer)) = cbor::decode(signed) else {
        return None;
    };
    match outer.as_slice() {
        [Value::Bytes(event), Value::Bytes(_)] => Some(frasil_events::envelope::event_id(event).0),
        _ => None,
    }
}

impl CheckpointState {
    /// Whether it holds nothing.
    pub fn is_empty(&self) -> bool {
        self.record_keys.is_empty() && self.dropped.is_empty() && self.kept_envelopes.is_empty()
    }

    /// The IDs of the dropped events, ascending.
    pub fn dropped_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.dropped.iter().map(|dropped| dropped.id)
    }

    /// Takes one of a log's records into the aggregate, if it is one of
    /// these: a `key` record of kind 5 handed by a snapshot, a `dropped`
    /// record, or an `event` record in state 6. Returns whether it took it.
    /// [`normalize`](Self::normalize) once every record is taken.
    pub fn take(&mut self, table: Table, item: &[u8], value: &TableValue) -> bool {
        match (table, value) {
            (Table::Key, TableValue::Key(KeyValue::RecordKey(record))) => {
                match item.split_first() {
                    Some((&kind, rest)) if kind == KeyKind::RecordKey.code() && record.handed => {
                        let Ok(checkpoint) = <[u8; 32]>::try_from(rest) else {
                            return false;
                        };
                        self.record_keys.push((checkpoint, record.key.clone()));
                        true
                    }
                    _ => false,
                }
            }
            (Table::Dropped, TableValue::Dropped(origin)) => {
                let Ok(id) = <[u8; 32]>::try_from(item) else {
                    return false;
                };
                self.dropped.push(Dropped {
                    id,
                    origin: *origin,
                });
                true
            }
            (Table::Event, TableValue::Event(record)) if record.state == EventState::KeptAlone => {
                self.kept_envelopes.push(record.signed.clone());
                true
            }
            _ => false,
        }
    }

    /// Sorts the record keys and dropped events by ID, one of each.
    pub fn normalize(&mut self) {
        self.record_keys.sort_by_key(|(checkpoint, _)| *checkpoint);
        self.record_keys.dedup_by_key(|(checkpoint, _)| *checkpoint);
        self.dropped.sort_by_key(|dropped| dropped.id);
        self.dropped.dedup_by_key(|dropped| dropped.id);
    }

    /// The records that hold it: `(table, item, value)`. A record key is
    /// one a snapshot handed (source 2); a kept envelope an `event` record
    /// in state 6 with its signatures verified. Puts these where no record
    /// of the same address holds something else: an event kept alone never
    /// replaces a judged one (at-rest.md, "The head, events and keys").
    pub fn records(&self) -> Vec<(Table, Vec<u8>, TableValue)> {
        let mut out = Vec::new();
        for (checkpoint, key) in &self.record_keys {
            let mut item = vec![KeyKind::RecordKey.code()];
            item.extend_from_slice(checkpoint);
            out.push((
                Table::Key,
                item,
                TableValue::Key(KeyValue::RecordKey(RecordKey {
                    key: key.clone(),
                    handed: true,
                })),
            ));
        }
        for dropped in &self.dropped {
            out.push((
                Table::Dropped,
                dropped.id.to_vec(),
                TableValue::Dropped(dropped.origin),
            ));
        }
        for signed in &self.kept_envelopes {
            let Some(id) = signed_id(signed) else {
                continue;
            };
            out.push((
                Table::Event,
                id.to_vec(),
                TableValue::Event(EventRecord {
                    signed: signed.clone(),
                    state: EventState::KeptAlone,
                    flags: FLAG_VERIFIED,
                    class: None,
                    first_sight: None,
                    frozen: None,
                }),
            ));
        }
        out
    }

    /// What this holds that `held` does not: the records to add to a log
    /// whose records give `held`.
    pub fn beyond(&self, held: &CheckpointState) -> CheckpointState {
        CheckpointState {
            record_keys: self
                .record_keys
                .iter()
                .filter(|(c, _)| !held.record_keys.iter().any(|(h, _)| h == c))
                .cloned()
                .collect(),
            dropped: self
                .dropped
                .iter()
                .filter(|d| !held.dropped.iter().any(|h| h.id == d.id))
                .copied()
                .collect(),
            kept_envelopes: self
                .kept_envelopes
                .iter()
                .filter(|e| !held.kept_envelopes.contains(e))
                .cloned()
                .collect(),
        }
    }
}

/// The rotations whose `key` records of kind 1 a forgetting deletes
/// (at-rest.md, "Forgetting before a checkpoint"), of `held`, the rotations
/// the log holds such a record for: each one it drops (`dropped` names its
/// event) that no state of `sealing` holds, `sealing` being the states that
/// seal a unit, object or name the log keeps. Every other one is kept,
/// a dropped rotation's included, so that what is sealed under its states
/// opens after a restart. Ascending.
pub fn rotation_keys_dropped<'s>(
    held: impl IntoIterator<Item = [u8; 32]>,
    dropped: &BTreeSet<[u8; 32]>,
    sealing: impl IntoIterator<Item = &'s RotationSet>,
) -> BTreeSet<[u8; 32]> {
    let sealing: BTreeSet<[u8; 32]> = sealing
        .into_iter()
        .flat_map(|state| state.ids().iter().map(|id| id.0))
        .collect();
    held.into_iter()
        .filter(|rotation| dropped.contains(rotation) && !sealing.contains(rotation))
        .collect()
}

/// Whether a `key` record of a log is one of kind 1 that the log keeps for a
/// rotation it dropped (at-rest.md, "Forgetting before a checkpoint"): its
/// item is the kind byte 1 and a rotation ID that `dropped` names. Its
/// secrets were checked against the rotation's commitments when the device
/// held the event, which it no longer does: the device takes them as they
/// are, for the states that seal what it kept, and never checks them again.
pub fn kept_rotation_key(item: &[u8], dropped: &BTreeSet<[u8; 32]>) -> bool {
    match item.split_first() {
        Some((&kind, rest)) if kind == KeyKind::Rotation.code() => {
            <[u8; 32]>::try_from(rest).is_ok_and(|rotation| dropped.contains(&rotation))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forgetting_keeps_the_rotation_keys_of_what_it_keeps() {
        let id = |n: u8| frasil_events::EventId([n; 32]);
        // Rotations 1 and 2 are dropped; a kept unit is sealed under {1, 3}.
        let dropped = BTreeSet::from([[1; 32], [2; 32]]);
        let sealing = [RotationSet::new([id(1), id(3)]).unwrap()];
        let held = [[1; 32], [2; 32], [3; 32], [4; 32]];
        assert_eq!(
            rotation_keys_dropped(held, &dropped, &sealing),
            BTreeSet::from([[2; 32]])
        );
        assert_eq!(
            rotation_keys_dropped(held, &dropped, &[]),
            BTreeSet::from([[1; 32], [2; 32]])
        );
        let item = |kind: u8, n: u8| [&[kind][..], &[n; 32]].concat();
        assert!(kept_rotation_key(&item(1, 1), &dropped));
        assert!(!kept_rotation_key(&item(1, 3), &dropped));
        assert!(!kept_rotation_key(&item(3, 1), &dropped));
        assert!(!kept_rotation_key(&[1, 1, 1], &dropped));
    }

    #[test]
    fn a_checkpoint_state_reads_back_from_its_records() {
        let state = CheckpointState {
            record_keys: vec![
                ([1; 32], Secret::new([7; 32])),
                ([2; 32], Secret::new([8; 32])),
            ],
            dropped: vec![
                Dropped {
                    id: [3; 32],
                    origin: DroppedOrigin::Held {
                        kind: 1,
                        height: None,
                    },
                },
                Dropped {
                    id: [4; 32],
                    origin: DroppedOrigin::Missing,
                },
                Dropped {
                    id: [5; 32],
                    origin: DroppedOrigin::Held {
                        kind: 2,
                        height: Some(11),
                    },
                },
            ],
            kept_envelopes: Vec::new(),
        };
        let mut back = CheckpointState::default();
        for (table, item, value) in state.records() {
            let encoded = value.encode();
            let read = TableValue::read(table, &item, &encoded, Some(&[0; 32]))
                .expect("a record reads back");
            assert!(back.take(table, &item, &read));
        }
        back.normalize();
        assert_eq!(back, state);
        assert!(back.beyond(&state).is_empty());
    }

    #[test]
    fn a_dropped_record_carries_a_kind_exactly_with_origin_1() {
        let read = |value: &[u8]| TableValue::read(Table::Dropped, &[5; 32], value, None);
        let encode = |pairs: &[(u64, u64)]| {
            Value::Map(
                pairs
                    .iter()
                    .map(|&(k, v)| (k, Value::Unsigned(v)))
                    .collect(),
            )
            .encode()
        };
        assert!(read(&encode(&[(1, 1), (2, 3)])).is_ok());
        assert!(read(&encode(&[(1, 2)])).is_ok());
        assert!(read(&encode(&[(1, 1)])).is_err());
        assert!(read(&encode(&[(1, 2), (2, 3)])).is_err());
        assert!(read(&encode(&[(1, 3)])).is_err());
        assert!(read(&encode(&[(1, 1), (2, 256)])).is_err());
        // Key 3, a height from 1, with origin 1 alone.
        assert!(read(&encode(&[(1, 1), (2, 2), (3, 41)])).is_ok());
        assert!(read(&encode(&[(1, 1), (2, 2), (3, 0)])).is_err());
        assert!(read(&encode(&[(1, 2), (3, 41)])).is_err());
        assert!(read(&encode(&[(1, 1), (3, 41)])).is_err());
        // The earlier `[author, seq, height]` is no height.
        let mut map = frasil_base::cbor::Map::new();
        map.insert(1, Value::Unsigned(1));
        map.insert(2, Value::Unsigned(2));
        map.insert(
            3,
            Value::Array(vec![
                Value::from([9u8; 32]),
                Value::from(4u64),
                Value::from(11u64),
            ]),
        );
        assert!(read(&Value::Map(map).encode()).is_err());
    }
}
