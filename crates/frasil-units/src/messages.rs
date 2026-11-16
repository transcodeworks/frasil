//! The sync messages (units.md, section 2.14, "Sync messages", and section
//! 3.14, "Sync").
//!
//! Each message is a deterministic CBOR map of at most 1,052,672 bytes. Key
//! 0 is its type and key 1 the space ID (bytes(32)); the other keys are the
//! type's. Arrays of IDs are strictly ascending. A sender splits what does
//! not fit over several messages. Types 18 to 63 are reserved and must be
//! understood (`UnknownMessage`); types from 64 are ignorable.
//!
//! A receiver refuses a message that breaks its type's shape as
//! `Malformed`, and drops it.

use crate::UnitError;
use crate::body::{Cover, covers_value, read_covers};
use crate::ids::{event_ids, ids_value, read_ids};
use crate::limits::{
    LOCATOR_BYTES, MAX_CHUNKS_WANTED, MAX_COVERS, MAX_LIST_EVENTS, MAX_MESSAGE_BYTES,
    MAX_MESSAGE_ITEMS, MAX_STATEMENTS_PER_MESSAGE, MIN_SEAL_BYTES, SEALED_CHUNK_BYTES,
};
use crate::stream::{self, StreamId};
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;

/// The first ignorable message type.
pub const FIRST_IGNORABLE: u64 = 64;

/// A vector entry of `Heads`: an author's greatest `seq` held and that
/// event's ID (section 3.13, "Heads and vectors").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VectorEntry {
    /// The author's device ID.
    pub author: DeviceId,
    /// Its greatest `seq` held, at least 1.
    pub seq: u64,
    /// That event's ID.
    pub id: EventId,
}

/// A range of `Want`: an author's events from `first` to `last` `seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Range {
    /// The author's device ID.
    pub author: DeviceId,
    /// The first `seq`, at least 1.
    pub first: u64,
    /// The last `seq`, at least `first`.
    pub last: u64,
}

/// A writer of `StreamHeads`: its latest unit in the stream, and that
/// unit's `seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamWriter {
    /// The writer's device ID.
    pub writer: DeviceId,
    /// Its latest unit.
    pub unit: EventId,
    /// That unit's `seq`, at least 1.
    pub seq: u64,
}

/// One sync message's own keys, by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Type 1: the sender's state.
    Heads {
        /// Key 2: 0 to 4,096 heads.
        heads: Vec<EventId>,
        /// Key 3: optional, the vector, ascending by author, then ID.
        vector: Option<Vec<VectorEntry>>,
        /// Key 4: a partial replica's streams; none for a full replica. The
        /// answer sends units of the system stream and of these streams
        /// only, beside space events, anchors and storage events.
        streams: Vec<StreamId>,
    },
    /// Type 2: events asked for, by ID or by author and `seq`; at least one
    /// of IDs and ranges.
    Want {
        /// Key 2: 1 to 4,096 IDs, or none.
        ids: Vec<EventId>,
        /// Key 3: 1 to 4,096 ranges, ascending by author, or none.
        ranges: Vec<Range>,
        /// Key 4: kinds, 1 to 127, that narrow ranges; none for all.
        kinds: Vec<u8>,
        /// Key 5: streams that narrow units; none for all.
        streams: Vec<StreamId>,
    },
    /// Type 3: 1 to 4,096 signed events, each after its parents.
    Events {
        /// Key 2.
        events: Vec<Vec<u8>>,
    },
    /// Type 4: answers a `Want` the sender cannot fill.
    Missing {
        /// Key 2: IDs not held, or none.
        ids: Vec<EventId>,
        /// Key 3: pairs `[ID, unit ID]`: a collected unit, and the snapshot
        /// unit that carries its stub; or none.
        carried: Vec<(EventId, EventId)>,
    },
    /// Type 5: an acknowledgement (section 3.13).
    Ack {
        /// Key 2: 1 to 4,096 heads.
        heads: Vec<EventId>,
    },
    /// Type 6: a peer's index of one stream.
    StreamHeads {
        /// Key 2: the stream.
        stream: StreamId,
        /// Key 3: the latest snapshot unit.
        latest_snapshot: Option<EventId>,
        /// Key 4: each writer's latest unit, ascending by writer.
        writers: Vec<StreamWriter>,
    },
    /// Type 7: asks for a stream's units the sender lacks.
    StreamWant {
        /// Key 2: the stream.
        stream: StreamId,
        /// Key 3: pairs `[writer, unit ID]` the sender holds, possibly none.
        held: Vec<Cover>,
        /// Key 4: start from the latest snapshot.
        from_snapshot: bool,
    },
    /// Type 8: asks for chunks, each answered in its own `ObjectChunks`.
    ObjectWant {
        /// Key 2: the locator.
        locator: Locator,
        /// Key 3: the first chunk's index.
        first: u64,
        /// Key 4: how many, 1 to 64.
        count: u64,
    },
    /// Type 9: a chunk, as an upload or an answer.
    ObjectChunks {
        /// Key 2: the locator.
        locator: Locator,
        /// Key 3: the object's header bytes.
        header: Option<Vec<u8>>,
        /// Key 4: the chunk's index.
        index: u64,
        /// Key 5: one sealed chunk.
        chunk: Vec<u8>,
    },
    /// Type 10: the objects the sender holds.
    ObjectHave {
        /// Key 2: 1 to 4,096 locators.
        locators: Vec<Locator>,
        /// Key 3: for each, the count of leading chunks held.
        counts: Option<Vec<u64>>,
    },
    /// Type 11: asks for a path from one event down to another.
    PathWant {
        /// Key 2: from.
        from: EventId,
        /// Key 3: to.
        to: EventId,
    },
    /// Type 12: the first a parent of `from`, each next a parent of the one
    /// before, the last with `to` among its parents; empty when the sender
    /// knows none.
    Path {
        /// Key 2: from.
        from: EventId,
        /// Key 3: to.
        to: EventId,
        /// Key 4: 0 to 4,096 signed events.
        events: Vec<Vec<u8>>,
    },
    /// Type 13: live delivery: the whole space; or space events, anchors,
    /// storage events, the system stream and these streams.
    Subscribe {
        /// Key 2: the streams, or none for the whole space.
        streams: Vec<StreamId>,
    },
    /// Type 14: gossip of head statements; member connections only.
    Statement {
        /// Key 2: 1 to 64 signed head statements.
        statements: Vec<Vec<u8>>,
    },
    /// Type 15: asks a member for history-free stream snapshots; member
    /// connections only.
    SnapshotWant {
        /// Key 2: 1 to 4,096 streams.
        streams: Vec<StreamId>,
    },
    /// Type 16: a space snapshot whose `streams` hold the entries asked
    /// for; member connections only.
    SnapshotOffer {
        /// Key 2: the signed space snapshot.
        snapshot: Vec<u8>,
    },
    /// Type 17: a read-only person's list events handed to a writer
    /// (section 3.11); member connections only.
    ListEvents {
        /// Key 2: 1 to 16 signed device-list events.
        events: Vec<Vec<u8>>,
    },
}

impl Message {
    /// The message's type.
    pub fn type_code(&self) -> u64 {
        match self {
            Self::Heads { .. } => 1,
            Self::Want { .. } => 2,
            Self::Events { .. } => 3,
            Self::Missing { .. } => 4,
            Self::Ack { .. } => 5,
            Self::StreamHeads { .. } => 6,
            Self::StreamWant { .. } => 7,
            Self::ObjectWant { .. } => 8,
            Self::ObjectChunks { .. } => 9,
            Self::ObjectHave { .. } => 10,
            Self::PathWant { .. } => 11,
            Self::Path { .. } => 12,
            Self::Subscribe { .. } => 13,
            Self::Statement { .. } => 14,
            Self::SnapshotWant { .. } => 15,
            Self::SnapshotOffer { .. } => 16,
            Self::ListEvents { .. } => 17,
        }
    }

    /// The message's name.
    pub fn name(&self) -> &'static str {
        name(self.type_code()).unwrap_or("")
    }

    /// Whether the message travels on member connections only.
    pub fn member_connections_only(&self) -> bool {
        (14..=17).contains(&self.type_code())
    }
}

/// The name of a message type from 1 to 17.
pub fn name(type_code: u64) -> Option<&'static str> {
    const NAMES: [&str; 17] = [
        "Heads",
        "Want",
        "Events",
        "Missing",
        "Ack",
        "StreamHeads",
        "StreamWant",
        "ObjectWant",
        "ObjectChunks",
        "ObjectHave",
        "PathWant",
        "Path",
        "Subscribe",
        "Statement",
        "SnapshotWant",
        "SnapshotOffer",
        "ListEvents",
    ];
    let index = usize::try_from(type_code.checked_sub(1)?).ok()?;
    NAMES.get(index).copied()
}

/// A sync message: the space its frame names, and its own keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncMessage {
    /// Key 1: the space ID.
    pub space: EventId,
    /// The type and its keys.
    pub message: Message,
}

/// What a receiver makes of a sync message's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A message of a type from 1 to 17.
    Message(SyncMessage),
    /// A message of an ignorable type, from 64.
    Ignored {
        /// Its type.
        type_code: u64,
    },
}

fn streams_value(streams: &[StreamId]) -> Value {
    let mut streams = streams.to_vec();
    streams.sort_unstable();
    streams.dedup();
    Value::Array(streams.into_iter().map(Value::from).collect())
}

fn byte_strings(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| Value::from(b.as_slice())).collect())
}

impl SyncMessage {
    /// The message's deterministic encoding. ID arrays are written
    /// ascending, each once.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::from([
            (0, Value::from(self.message.type_code())),
            (1, Value::from(self.space.0)),
        ]);
        match &self.message {
            Message::Heads {
                heads,
                vector,
                streams,
            } => {
                map.insert(2, ids_value(heads));
                if !streams.is_empty() {
                    map.insert(4, streams_value(streams));
                }
                if let Some(vector) = vector {
                    let mut vector = vector.clone();
                    vector.sort_unstable_by_key(|entry| (entry.author, entry.id));
                    map.insert(
                        3,
                        Value::Array(
                            vector
                                .into_iter()
                                .map(|entry| {
                                    Value::Array(vec![
                                        Value::from(entry.author.0),
                                        Value::from(entry.seq),
                                        Value::from(entry.id.0),
                                    ])
                                })
                                .collect(),
                        ),
                    );
                }
            }
            Message::Want {
                ids,
                ranges,
                kinds,
                streams,
            } => {
                if !ids.is_empty() {
                    map.insert(2, ids_value(ids));
                }
                if !ranges.is_empty() {
                    let mut ranges = ranges.clone();
                    ranges.sort_unstable();
                    map.insert(
                        3,
                        Value::Array(
                            ranges
                                .into_iter()
                                .map(|range| {
                                    Value::Array(vec![
                                        Value::from(range.author.0),
                                        Value::from(range.first),
                                        Value::from(range.last),
                                    ])
                                })
                                .collect(),
                        ),
                    );
                }
                if !kinds.is_empty() {
                    let mut kinds = kinds.clone();
                    kinds.sort_unstable();
                    kinds.dedup();
                    map.insert(
                        4,
                        Value::Array(
                            kinds
                                .into_iter()
                                .map(|k| Value::from(u64::from(k)))
                                .collect(),
                        ),
                    );
                }
                if !streams.is_empty() {
                    map.insert(5, streams_value(streams));
                }
            }
            Message::Events { events } | Message::ListEvents { events } => {
                map.insert(2, byte_strings(events));
            }
            Message::Missing { ids, carried } => {
                if !ids.is_empty() {
                    map.insert(2, ids_value(ids));
                }
                if !carried.is_empty() {
                    let mut carried = carried.clone();
                    carried.sort_unstable();
                    map.insert(
                        3,
                        Value::Array(
                            carried
                                .into_iter()
                                .map(|(id, unit)| {
                                    Value::Array(vec![Value::from(id.0), Value::from(unit.0)])
                                })
                                .collect(),
                        ),
                    );
                }
            }
            Message::Ack { heads } => {
                map.insert(2, ids_value(heads));
            }
            Message::StreamHeads {
                stream,
                latest_snapshot,
                writers,
            } => {
                map.insert(2, Value::from(*stream));
                if let Some(latest) = latest_snapshot {
                    map.insert(3, Value::from(latest.0));
                }
                let mut writers = writers.clone();
                writers.sort_unstable();
                map.insert(
                    4,
                    Value::Array(
                        writers
                            .into_iter()
                            .map(|w| {
                                Value::Array(vec![
                                    Value::from(w.writer.0),
                                    Value::from(w.unit.0),
                                    Value::from(w.seq),
                                ])
                            })
                            .collect(),
                    ),
                );
            }
            Message::StreamWant {
                stream,
                held,
                from_snapshot,
            } => {
                map.insert(2, Value::from(*stream));
                map.insert(3, covers_value(held));
                if *from_snapshot {
                    map.insert(4, Value::from(1u64));
                }
            }
            Message::ObjectWant {
                locator,
                first,
                count,
            } => {
                map.insert(2, Value::from(*locator));
                map.insert(3, Value::from(*first));
                map.insert(4, Value::from(*count));
            }
            Message::ObjectChunks {
                locator,
                header,
                index,
                chunk,
            } => {
                map.insert(2, Value::from(*locator));
                if let Some(header) = header {
                    map.insert(3, Value::from(header.as_slice()));
                }
                map.insert(4, Value::from(*index));
                map.insert(5, Value::from(chunk.as_slice()));
            }
            Message::ObjectHave { locators, counts } => {
                map.insert(
                    2,
                    Value::Array(locators.iter().map(|l| Value::from(*l)).collect()),
                );
                if let Some(counts) = counts {
                    map.insert(
                        3,
                        Value::Array(counts.iter().map(|c| Value::from(*c)).collect()),
                    );
                }
            }
            Message::PathWant { from, to } => {
                map.insert(2, Value::from(from.0));
                map.insert(3, Value::from(to.0));
            }
            Message::Path { from, to, events } => {
                map.insert(2, Value::from(from.0));
                map.insert(3, Value::from(to.0));
                map.insert(4, byte_strings(events));
            }
            Message::Subscribe { streams } => {
                if !streams.is_empty() {
                    map.insert(2, streams_value(streams));
                }
            }
            Message::Statement { statements } => {
                map.insert(2, byte_strings(statements));
            }
            Message::SnapshotWant { streams } => {
                map.insert(2, streams_value(streams));
            }
            Message::SnapshotOffer { snapshot } => {
                map.insert(2, Value::from(snapshot.as_slice()));
            }
        }
        Value::Map(map).encode()
    }

    /// Reads a sync message: at most 1,052,672 bytes (`TooLarge`);
    /// deterministic CBOR, a map with an unsigned key 0 and a 32-byte key 1
    /// (`Malformed`); a type from 64 is ignored; a type this side does not
    /// know is `UnknownMessage`; then the type's keys and shape
    /// (`Malformed`).
    ///
    /// # Errors
    ///
    /// `TooLarge`, `Malformed` or `UnknownMessage`.
    pub fn read(data: &[u8]) -> Result<Received, UnitError> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let type_code = map.get(&0).ok_or(Malformed)?.as_unsigned()?;
        let space = EventId(map.get(&1).ok_or(Malformed)?.as_byte_array()?);
        if type_code >= FIRST_IGNORABLE {
            return Ok(Received::Ignored { type_code });
        }
        if name(type_code).is_none() {
            return Err(ErrorClass::UnknownMessage.into());
        }
        let (allowed, required): (&[u64], &[u64]) = match type_code {
            1 => (&[2, 3, 4], &[2]),
            2 => (&[2, 3, 4, 5], &[]),
            4 => (&[2, 3], &[]),
            6 => (&[2, 3, 4], &[2, 4]),
            7 => (&[2, 3, 4], &[2, 3]),
            8 => (&[2, 3, 4], &[2, 3, 4]),
            9 => (&[2, 3, 4, 5], &[2, 4, 5]),
            10 => (&[2, 3], &[2]),
            11 => (&[2, 3], &[2, 3]),
            12 => (&[2, 3, 4], &[2, 3, 4]),
            13 => (&[2], &[]),
            _ => (&[2], &[2]),
        };
        if map.keys().any(|key| *key > 1 && !allowed.contains(key))
            || !required.iter().all(|key| map.contains_key(key))
        {
            return Err(ErrorClass::Malformed.into());
        }
        let message = read_keys(type_code, map)?;
        Ok(Received::Message(Self { space, message }))
    }
}

fn read_bytes_array(value: &Value, lo: usize, hi: usize) -> Result<Vec<Vec<u8>>, Malformed> {
    let items = value.as_array()?;
    if items.len() < lo || items.len() > hi {
        return Err(Malformed);
    }
    items
        .iter()
        .map(|item| item.as_bytes().map(<[u8]>::to_vec))
        .collect()
}

fn read_stream(value: &Value) -> Result<StreamId, Malformed> {
    let bytes = value.as_bytes()?;
    if !stream::is_valid(bytes) {
        return Err(Malformed);
    }
    bytes.try_into().map_err(|_| Malformed)
}

/// Reads a triple's items: a 32-byte first element, then two more.
fn triples(value: &Value, hi: usize) -> Result<Vec<(&Value, &Value, &Value)>, Malformed> {
    let items = value.as_array()?;
    if items.len() > hi {
        return Err(Malformed);
    }
    items
        .iter()
        .map(|item| match item.as_array()? {
            [a, b, c] => {
                a.as_byte_array::<32>()?;
                Ok((a, b, c))
            }
            _ => Err(Malformed),
        })
        .collect()
}

fn read_keys(type_code: u64, map: &Map) -> Result<Message, Malformed> {
    Ok(match type_code {
        1 => {
            let heads = event_ids(&map[&2], 0, MAX_MESSAGE_ITEMS)?;
            let vector = match map.get(&3) {
                Some(value) => {
                    let mut vector: Vec<VectorEntry> = Vec::new();
                    for (author, seq, id) in triples(value, MAX_MESSAGE_ITEMS)? {
                        let entry = VectorEntry {
                            author: DeviceId(author.as_byte_array()?),
                            seq: seq.as_unsigned()?,
                            id: EventId(id.as_byte_array()?),
                        };
                        if entry.seq == 0
                            || vector.last().is_some_and(|last| {
                                (last.author, last.id) >= (entry.author, entry.id)
                            })
                        {
                            return Err(Malformed);
                        }
                        vector.push(entry);
                    }
                    Some(vector)
                }
                None => None,
            };
            let streams = match map.get(&4) {
                Some(value) => read_ids::<16>(value, 1, MAX_MESSAGE_ITEMS)?,
                None => Vec::new(),
            };
            Message::Heads {
                heads,
                vector,
                streams,
            }
        }
        2 => {
            if !map.contains_key(&2) && !map.contains_key(&3) {
                return Err(Malformed);
            }
            let ids = match map.get(&2) {
                Some(value) => event_ids(value, 1, MAX_MESSAGE_ITEMS)?,
                None => Vec::new(),
            };
            let ranges = match map.get(&3) {
                Some(value) => {
                    let mut ranges: Vec<Range> = Vec::new();
                    for (author, first, last) in triples(value, MAX_MESSAGE_ITEMS)? {
                        let range = Range {
                            author: DeviceId(author.as_byte_array()?),
                            first: first.as_unsigned()?,
                            last: last.as_unsigned()?,
                        };
                        if range.first == 0
                            || range.first > range.last
                            || ranges
                                .last()
                                .is_some_and(|prev| prev.author >= range.author)
                        {
                            return Err(Malformed);
                        }
                        ranges.push(range);
                    }
                    if ranges.is_empty() {
                        return Err(Malformed);
                    }
                    ranges
                }
                None => Vec::new(),
            };
            let kinds = match map.get(&4) {
                Some(value) => {
                    let items = value.as_array()?;
                    let kinds = items
                        .iter()
                        .map(|item| {
                            let kind = item.as_unsigned()?;
                            if !(1..=127).contains(&kind) {
                                return Err(Malformed);
                            }
                            u8::try_from(kind).map_err(|_| Malformed)
                        })
                        .collect::<Result<Vec<u8>, _>>()?;
                    if kinds.is_empty() || !kinds.windows(2).all(|pair| pair[0] < pair[1]) {
                        return Err(Malformed);
                    }
                    kinds
                }
                None => Vec::new(),
            };
            let streams = match map.get(&5) {
                Some(value) => read_ids::<16>(value, 1, MAX_MESSAGE_ITEMS)?,
                None => Vec::new(),
            };
            Message::Want {
                ids,
                ranges,
                kinds,
                streams,
            }
        }
        3 => Message::Events {
            events: read_bytes_array(&map[&2], 1, MAX_MESSAGE_ITEMS)?,
        },
        4 => {
            let ids = match map.get(&2) {
                Some(value) => event_ids(value, 1, MAX_MESSAGE_ITEMS)?,
                None => Vec::new(),
            };
            let carried = match map.get(&3) {
                Some(value) => {
                    let items = value.as_array()?;
                    if items.is_empty() || items.len() > MAX_MESSAGE_ITEMS {
                        return Err(Malformed);
                    }
                    let mut carried: Vec<(EventId, EventId)> = Vec::new();
                    for item in items {
                        let [id, unit] = item.as_array()? else {
                            return Err(Malformed);
                        };
                        let pair = (EventId(id.as_byte_array()?), EventId(unit.as_byte_array()?));
                        if carried.last().is_some_and(|last| last.0 >= pair.0) {
                            return Err(Malformed);
                        }
                        carried.push(pair);
                    }
                    carried
                }
                None => Vec::new(),
            };
            Message::Missing { ids, carried }
        }
        5 => Message::Ack {
            heads: event_ids(&map[&2], 1, MAX_MESSAGE_ITEMS)?,
        },
        6 => {
            let stream = read_stream(&map[&2])?;
            let latest_snapshot = match map.get(&3) {
                Some(value) => Some(EventId(value.as_byte_array()?)),
                None => None,
            };
            let mut writers: Vec<StreamWriter> = Vec::new();
            for (writer, unit, seq) in triples(&map[&4], MAX_COVERS)? {
                let entry = StreamWriter {
                    writer: DeviceId(writer.as_byte_array()?),
                    unit: EventId(unit.as_byte_array()?),
                    seq: seq.as_unsigned()?,
                };
                if entry.seq == 0
                    || writers
                        .last()
                        .is_some_and(|last| last.writer >= entry.writer)
                {
                    return Err(Malformed);
                }
                writers.push(entry);
            }
            Message::StreamHeads {
                stream,
                latest_snapshot,
                writers,
            }
        }
        7 => {
            let stream = read_stream(&map[&2])?;
            let held = read_covers(&map[&3])?;
            let from_snapshot = match map.get(&4) {
                Some(value) if value.as_unsigned()? == 1 => true,
                Some(_) => return Err(Malformed),
                None => false,
            };
            Message::StreamWant {
                stream,
                held,
                from_snapshot,
            }
        }
        8 => {
            let locator = map[&2].as_byte_array::<LOCATOR_BYTES>()?;
            let first = map[&3].as_unsigned()?;
            let count = map[&4].as_unsigned()?;
            if !(1..=MAX_CHUNKS_WANTED).contains(&count) {
                return Err(Malformed);
            }
            Message::ObjectWant {
                locator,
                first,
                count,
            }
        }
        9 => {
            let locator = map[&2].as_byte_array::<LOCATOR_BYTES>()?;
            let index = map[&4].as_unsigned()?;
            let chunk = map[&5].as_bytes()?;
            if !(MIN_SEAL_BYTES..=SEALED_CHUNK_BYTES).contains(&chunk.len()) {
                return Err(Malformed);
            }
            let header = match map.get(&3) {
                Some(value) => Some(value.as_bytes()?.to_vec()),
                None => None,
            };
            Message::ObjectChunks {
                locator,
                header,
                index,
                chunk: chunk.to_vec(),
            }
        }
        10 => {
            let locators = read_ids::<LOCATOR_BYTES>(&map[&2], 1, MAX_MESSAGE_ITEMS)?;
            let counts = match map.get(&3) {
                Some(value) => {
                    let counts = value
                        .as_array()?
                        .iter()
                        .map(Value::as_unsigned)
                        .collect::<Result<Vec<_>, _>>()?;
                    if counts.len() != locators.len() {
                        return Err(Malformed);
                    }
                    Some(counts)
                }
                None => None,
            };
            Message::ObjectHave { locators, counts }
        }
        11 => Message::PathWant {
            from: EventId(map[&2].as_byte_array()?),
            to: EventId(map[&3].as_byte_array()?),
        },
        12 => Message::Path {
            from: EventId(map[&2].as_byte_array()?),
            to: EventId(map[&3].as_byte_array()?),
            events: read_bytes_array(&map[&4], 0, MAX_MESSAGE_ITEMS)?,
        },
        13 => Message::Subscribe {
            streams: match map.get(&2) {
                Some(value) => read_ids::<16>(value, 1, MAX_MESSAGE_ITEMS)?,
                None => Vec::new(),
            },
        },
        14 => Message::Statement {
            statements: read_bytes_array(&map[&2], 1, MAX_STATEMENTS_PER_MESSAGE)?,
        },
        15 => Message::SnapshotWant {
            streams: read_ids::<16>(&map[&2], 1, MAX_MESSAGE_ITEMS)?,
        },
        16 => Message::SnapshotOffer {
            snapshot: map[&2].as_bytes()?.to_vec(),
        },
        17 => Message::ListEvents {
            events: read_bytes_array(&map[&2], 1, MAX_LIST_EVENTS)?,
        },
        _ => return Err(Malformed),
    })
}

/// Whether an event the other side lacks is sent in answer to its `Heads`
/// (section 3.14, the exchange, step 1): with key 4, a partial replica's
/// `Heads`, only space events, anchors, storage events, the system stream's
/// units and units of the streams key 4 names. `stream` is a unit's stream,
/// `None` for another kind; `system` the space's system stream, where the
/// answering side knows it.
pub fn sent_after_heads(
    stream: Option<&StreamId>,
    streams: &[StreamId],
    system: Option<&StreamId>,
) -> bool {
    match stream {
        None => true,
        Some(stream) => streams.is_empty() || streams.contains(stream) || system == Some(stream),
    }
}

/// Whether a `Path` checks (units.md, "Sync messages").
pub use frasil_events::check_path;
