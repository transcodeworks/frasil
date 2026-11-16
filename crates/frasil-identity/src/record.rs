//! The list record a list checkpoint carries (identity.md, "List
//! checkpoints").
//!
//! A list checkpoint's `record` (body key 9) is a deterministic CBOR map:
//!
//! | Key | Field | Value |
//! |---|---|---|
//! | 1 | `version` | 1 |
//! | 2 | `epoch` | 1 for a checkpoint whose past has none in effect; otherwise one more than its predecessor's |
//! | 3 | `previous` | bytes(32): the list checkpoint in effect in its past; present exactly when `epoch` > 1 |
//! | 4 | `members` | one entry per active list member of its past, strictly ascending by device ID: `[add, root, agent, confirmed, seniority, rooting]` |
//! | 5 | `tips` | `[device, seq, event ID]` for each active member that signed in its past, strictly ascending |
//! | 6 | `forks` | `[device, seq]` for each author forked there, strictly ascending |
//! | 7 | `heard` | `[add, seniority]` for each device the checkpoint hears, strictly ascending by `add`; present exactly when there are some |
//!
//! A member entry's `agent` and `rooting` are 32 bytes exactly when `root`
//! is 2 (rooted in an agent), and empty bytes otherwise: `rooting` names the
//! first valid `add` there, in canonical order, that rooted the member in an
//! agent, from whose first sight a verifier counts ext-recovery-agent.md's
//! waiting period and through whose author the veto traces.
//!
//! A member's keys and kind are those of the `add` its entry names, which
//! every holder of the list keeps, with each `rooting` add. The record names
//! no key itself. At the widest encodings a member entry with its tip takes
//! at most about 165 bytes, about 200 for a member rooted in an agent, so a
//! list event's 16,384 bytes hold at least 70 active members none of which
//! is rooted in an agent, and at least 51 when every one is.
//!
//! Reading a record, in order (identity.md, "List checkpoints", "Reading a
//! record"): deterministic CBOR, a map with an unsigned key 1
//! (`Malformed`); key 1 is 1 (`UnsupportedVersion`); exactly the keys
//! above, with their types and orders, `previous` present exactly when
//! `epoch` > 1, `heard` absent or not empty, each member entry of six
//! elements with `agent` and `rooting` as above (`Malformed`). The members' order is by the device
//! IDs their `add`s name, which a reader learns from those `add`s, so
//! reading checks it only when the record is compared with the one a holder
//! derives.
//!
//! A **heard** device (identity.md, "List checkpoints", "Effect") is one a
//! valid `revoke` of the checkpoint's window named while it was a device
//! that is not rooted, or confirmed, that the record does not list, and
//! that no such `revoke` signed by itself or by a member that outranks it
//! named. Its entry names the event ID of its earliest valid `add` there,
//! whose keys its votes are checked under, and its seniority as a member
//! entry's.

use crate::IdentityClass;
use crate::state::Rootedness;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;

/// The list record's version, key 1.
pub const RECORD_VERSION: u64 = 1;

/// A member's seniority as the record carries it: `[epoch, height, add]`,
/// the epoch of the world its most senior `add` was judged in (0 before any
/// list checkpoint), that `add`'s height there and its event ID. The hash
/// the merge's seniority sorts by between height and ID is
/// `SHA-256("frasil/device-list/seniority/v1" || person ID || device ID)`,
/// which every holder computes again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordSeniority {
    /// The epoch of the world the `add` was judged in.
    pub epoch: u64,
    /// The `add`'s height in that world.
    pub height: u64,
    /// The `add`'s event ID.
    pub add: EventId,
}

/// One active list member of a list checkpoint's past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMember {
    /// The event ID of the member's earliest valid `add` there: its kind and
    /// keys are that `add`'s.
    pub add: EventId,
    /// The most rooted of its `add`s, before its kind and any `confirm`
    /// count (identity.md, "The state of a list at a place").
    pub root: Rootedness,
    /// The agent it is rooted in: present exactly when `root` is
    /// [`Rootedness::Agent`].
    pub agent: Option<DeviceId>,
    /// Whether a `confirm` named it.
    pub confirmed: bool,
    /// Its seniority.
    pub seniority: RecordSeniority,
    /// The first valid `add` there, in canonical order, that rooted it in
    /// an agent: present exactly when `root` is [`Rootedness::Agent`].
    pub rooting: Option<EventId>,
}

/// A list checkpoint's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRecord {
    /// The checkpoint's epoch.
    pub epoch: u64,
    /// Its predecessor, present exactly when `epoch` > 1.
    pub previous: Option<EventId>,
    /// One entry per active list member, ascending by device ID.
    pub members: Vec<RecordMember>,
    /// Each active member's greatest `seq` in the past and that event,
    /// ascending by device ID.
    pub tips: Vec<(DeviceId, u64, EventId)>,
    /// Each author's fork point in the past, ascending by device ID.
    pub forks: Vec<(DeviceId, u64)>,
    /// Key 7: the devices the checkpoint hears, each by its earliest valid
    /// `add` there and with its seniority, strictly ascending by `add`.
    pub heard: Vec<(EventId, RecordSeniority)>,
}

fn rootedness_code(root: Rootedness) -> u64 {
    match root {
        Rootedness::None => 0,
        Rootedness::Passkey => 1,
        Rootedness::Agent => 2,
    }
}

fn rootedness_of(code: u64) -> Option<Rootedness> {
    match code {
        0 => Some(Rootedness::None),
        1 => Some(Rootedness::Passkey),
        2 => Some(Rootedness::Agent),
        _ => None,
    }
}

impl ListRecord {
    /// The record's one encoding. The members are written in the order
    /// held, which a record derived by [`crate::checkpoint`] sorts by device
    /// ID.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(RECORD_VERSION));
        map.insert(2, Value::Unsigned(self.epoch));
        if let Some(previous) = self.previous {
            map.insert(3, Value::from(previous.0));
        }
        map.insert(
            4,
            Value::Array(
                self.members
                    .iter()
                    .map(|m| {
                        Value::Array(vec![
                            Value::from(m.add.0),
                            Value::Unsigned(rootedness_code(m.root)),
                            match m.agent {
                                Some(agent) => Value::from(agent.0),
                                None => Value::Bytes(Vec::new()),
                            },
                            Value::Unsigned(u64::from(m.confirmed)),
                            seniority_value(&m.seniority),
                            match m.rooting {
                                Some(add) => Value::from(add.0),
                                None => Value::Bytes(Vec::new()),
                            },
                        ])
                    })
                    .collect(),
            ),
        );
        map.insert(
            5,
            Value::Array(
                self.tips
                    .iter()
                    .map(|(device, seq, id)| {
                        Value::Array(vec![
                            Value::from(device.0),
                            Value::Unsigned(*seq),
                            Value::from(id.0),
                        ])
                    })
                    .collect(),
            ),
        );
        map.insert(
            6,
            Value::Array(
                self.forks
                    .iter()
                    .map(|(device, seq)| {
                        Value::Array(vec![Value::from(device.0), Value::Unsigned(*seq)])
                    })
                    .collect(),
            ),
        );
        if !self.heard.is_empty() {
            map.insert(
                7,
                Value::Array(
                    self.heard
                        .iter()
                        .map(|(add, s)| Value::Array(vec![Value::from(add.0), seniority_value(s)]))
                        .collect(),
                ),
            );
        }
        Value::Map(map).encode()
    }

    /// Reads a record, in order: deterministic CBOR, a map with an unsigned
    /// key 1; version 1; exactly its keys, with their types and orders,
    /// `heard` absent or not empty and strictly ascending by `add`, and
    /// each member entry of six elements, its `agent` and `rooting` present
    /// exactly when it is rooted in an agent.
    ///
    /// # Errors
    ///
    /// `Malformed`, then `UnsupportedVersion`, then `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, IdentityClass> {
        let malformed = IdentityClass::Shared(ErrorClass::Malformed);
        let value = cbor::decode(data).map_err(|_| malformed)?;
        let map = value.as_map().map_err(|_| malformed)?;
        let version = map
            .get(&1)
            .and_then(|v| v.as_unsigned().ok())
            .ok_or(malformed)?;
        if version != RECORD_VERSION {
            return Err(IdentityClass::Shared(ErrorClass::UnsupportedVersion));
        }
        read_fields(map).map_err(|_| malformed)
    }

    /// The tip the record names for a device, if any: its `seq`.
    pub fn tip(&self, device: &DeviceId) -> Option<u64> {
        self.tips
            .iter()
            .find(|(d, _, _)| d == device)
            .map(|(_, seq, _)| *seq)
    }
}

fn seniority_value(s: &RecordSeniority) -> Value {
    Value::Array(vec![
        Value::Unsigned(s.epoch),
        Value::Unsigned(s.height),
        Value::from(s.add.0),
    ])
}

fn read_seniority(value: &Value) -> Result<RecordSeniority, cbor::Malformed> {
    let seniority = value.as_array()?;
    if seniority.len() != 3 {
        return Err(cbor::Malformed);
    }
    Ok(RecordSeniority {
        epoch: seniority[0].as_unsigned()?,
        height: seniority[1].as_unsigned()?,
        add: EventId(seniority[2].as_byte_array()?),
    })
}

fn read_fields(map: &Map) -> Result<ListRecord, cbor::Malformed> {
    if [1, 2, 4, 5, 6].iter().any(|k| !map.contains_key(k))
        || map.keys().any(|k| !(1..=7).contains(k))
    {
        return Err(cbor::Malformed);
    }
    let epoch = map[&2].as_unsigned()?;
    if epoch < 1 || map.contains_key(&3) != (epoch > 1) {
        return Err(cbor::Malformed);
    }
    let previous = match map.get(&3) {
        Some(value) => Some(EventId(value.as_byte_array()?)),
        None => None,
    };
    let mut members = Vec::new();
    for entry in map[&4].as_array()? {
        let entry = entry.as_array()?;
        if entry.len() != 6 {
            return Err(cbor::Malformed);
        }
        let add = EventId(entry[0].as_byte_array()?);
        let root = rootedness_of(entry[1].as_unsigned()?).ok_or(cbor::Malformed)?;
        let agent = match entry[2].as_bytes()? {
            [] => None,
            bytes => Some(DeviceId(bytes.try_into().map_err(|_| cbor::Malformed)?)),
        };
        let confirmed = match entry[3].as_unsigned()? {
            0 => false,
            1 => true,
            _ => return Err(cbor::Malformed),
        };
        let seniority = read_seniority(&entry[4])?;
        let rooting = match entry[5].as_bytes()? {
            [] => None,
            bytes => Some(EventId(bytes.try_into().map_err(|_| cbor::Malformed)?)),
        };
        let in_agent = root == Rootedness::Agent;
        if agent.is_some() != in_agent || rooting.is_some() != in_agent {
            return Err(cbor::Malformed);
        }
        members.push(RecordMember {
            add,
            root,
            agent,
            confirmed,
            seniority,
            rooting,
        });
    }
    let mut tips = Vec::new();
    for row in map[&5].as_array()? {
        let row = row.as_array()?;
        if row.len() != 3 {
            return Err(cbor::Malformed);
        }
        let seq = row[1].as_unsigned()?;
        if seq < 1 {
            return Err(cbor::Malformed);
        }
        tips.push((
            DeviceId(row[0].as_byte_array()?),
            seq,
            EventId(row[2].as_byte_array()?),
        ));
    }
    let mut forks = Vec::new();
    for row in map[&6].as_array()? {
        let row = row.as_array()?;
        if row.len() != 2 {
            return Err(cbor::Malformed);
        }
        let seq = row[1].as_unsigned()?;
        if seq < 1 {
            return Err(cbor::Malformed);
        }
        forks.push((DeviceId(row[0].as_byte_array()?), seq));
    }
    let mut heard = Vec::new();
    if let Some(rows) = map.get(&7) {
        let rows = rows.as_array()?;
        if rows.is_empty() {
            return Err(cbor::Malformed);
        }
        for row in rows {
            let row = row.as_array()?;
            if row.len() != 2 {
                return Err(cbor::Malformed);
            }
            heard.push((EventId(row[0].as_byte_array()?), read_seniority(&row[1])?));
        }
    }
    let ascending = tips.windows(2).all(|w| w[0].0 < w[1].0)
        && forks.windows(2).all(|w| w[0].0 < w[1].0)
        && heard.windows(2).all(|w| w[0].0 < w[1].0);
    if !ascending {
        return Err(cbor::Malformed);
    }
    Ok(ListRecord {
        epoch,
        previous,
        members,
        tips,
        forks,
        heard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ListRecord {
        ListRecord {
            epoch: 2,
            previous: Some(EventId([7; 32])),
            members: vec![RecordMember {
                add: EventId([1; 32]),
                root: Rootedness::Agent,
                agent: Some(DeviceId([2; 32])),
                confirmed: true,
                seniority: RecordSeniority {
                    epoch: 1,
                    height: 3,
                    add: EventId([1; 32]),
                },
                rooting: Some(EventId([4; 32])),
            }],
            tips: vec![(DeviceId([3; 32]), 4, EventId([5; 32]))],
            forks: vec![(DeviceId([6; 32]), 2)],
            heard: vec![(
                EventId([8; 32]),
                RecordSeniority {
                    epoch: 0,
                    height: 2,
                    add: EventId([8; 32]),
                },
            )],
        }
    }

    #[test]
    fn a_record_round_trips() {
        let bytes = record().encode();
        assert_eq!(ListRecord::read(&bytes).unwrap(), record());
        assert_eq!(ListRecord::read(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn reading_refuses_in_order() {
        let malformed = IdentityClass::Shared(ErrorClass::Malformed);
        let encode = |f: &dyn Fn(&mut Map)| {
            let Value::Map(mut map) = cbor::decode(&record().encode()).unwrap() else {
                unreachable!()
            };
            f(&mut map);
            Value::Map(map).encode()
        };
        assert_eq!(ListRecord::read(b"\x80"), Err(malformed));
        assert_eq!(
            ListRecord::read(&encode(&|m| {
                m.insert(1, Value::Unsigned(2));
            })),
            Err(IdentityClass::Shared(ErrorClass::UnsupportedVersion))
        );
        fn entry(m: &mut Map, f: impl Fn(&mut Vec<Value>)) {
            let Value::Array(members) = &m[&4] else {
                unreachable!()
            };
            let Value::Array(mut first) = members[0].clone() else {
                unreachable!()
            };
            f(&mut first);
            m.insert(4, Value::Array(vec![Value::Array(first)]));
        }
        let five = |m: &mut Map| {
            entry(m, |e| {
                e.pop();
            })
        };
        let no_rooting = |m: &mut Map| entry(m, |e| e[5] = Value::Bytes(Vec::new()));
        let no_agent = |m: &mut Map| entry(m, |e| e[2] = Value::Bytes(Vec::new()));
        let unrooted = |m: &mut Map| entry(m, |e| e[1] = Value::Unsigned(0));
        let changes: [&dyn Fn(&mut Map); 12] = [
            &five,
            &no_rooting,
            &no_agent,
            &unrooted,
            &|m| {
                m.remove(&3);
            },
            &|m| {
                m.insert(2, Value::Unsigned(1));
            },
            &|m| {
                m.insert(8, Value::Unsigned(0));
            },
            &|m| {
                m.insert(7, Value::Array(Vec::new()));
            },
            &|m| {
                let Value::Array(rows) = &m[&7] else {
                    unreachable!()
                };
                m.insert(7, Value::Array(vec![rows[0].clone(), rows[0].clone()]));
            },
            &|m| {
                m.insert(6, Value::Array(vec![Value::Unsigned(0)]));
            },
            &|m| {
                let row = Value::Array(vec![Value::from([6u8; 32]), Value::Unsigned(2)]);
                m.insert(6, Value::Array(vec![row.clone(), row]));
            },
            &|m| {
                m.insert(4, Value::Unsigned(0));
            },
        ];
        for change in changes {
            assert_eq!(ListRecord::read(&encode(change)), Err(malformed));
        }
    }
}
