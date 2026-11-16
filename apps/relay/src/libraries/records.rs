//! What a peer keeps of its libraries, at rest (ext-libraries.md, 2.5 What
//! a peer keeps, and 2.4 Settings).
//!
//! Each record is one row of one table, under the peer's library prefix:
//!
//! | Table | Key | Record |
//! |---|---|---|
//! | `L` | the library ID's UTF-8 | `{1: quota?, 2: erasure_timeout, 3: state, 4: open_until?, 5: deposit_allowance?, 6: space_share?}` |
//! | `S` | a space ID | `{1: library, 2: ticket ID?, 3: reading}`: its attachment |
//! | `T` | a ticket ID | `{1: not_after}`: a ticket that attached a space |
//! | `D` | a space ID | `{}`: a space whose data the operator deleted |
//! | `X` | a space ID | `{1: reading}`: a space detached from its library |
//! | `H` | a space ID, then a locator | `{1: source, 2: access key, 3: reading}`: a hold |
//! | `C` | a locator, then the library ID's UTF-8 | `{1: source, 2: object record, 3: bytes, 4: reading}`: a copy |
//! | `O` | the library ID's UTF-8 | `{1: [space ID]}`: a library being handed over to another peer, whose spaces take no store, and the spaces its shard kept as it froze, ascending |
//! | `W` | the library ID's UTF-8 | `{1: start, 2: drawn, 3: [[space ID, drawn]]}`: ext-deposit-tokens.md's allowance window, its start on the library's timeline, the tokens drawn in it, and each space's share drawn, ascending, none of them 0 |
//! | `G` | SHA-256 of the library ID's UTF-8, then a grant ID | `{1: not_after}`: a deposit grant used, beside its library's window |
//!
//! Keys 5 and 6 of `L` and the tables `W` and `G` are ext-deposit-tokens.md's
//! (2.7 What a peer keeps). A library record kept before they existed has
//! neither key, and its library takes the operator's defaults.
//!
//! A reading is `{1: timeline, 2: run, 3: wall?}`. Every record is
//! deterministic CBOR, so a record read and written again is the same
//! bytes. This file reads no clock and does no IO.

use frasil_base::cbor::{self, Map, Value};
use frasil_base::time::Reading;
use frasil_libraries::ticket::TICKET_ID_BYTES;
use frasil_libraries::{LibraryId, LibraryState, TicketId};

/// A library's settings (ext-libraries.md, 2.4 Settings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Library {
    /// `quota`: the bytes its spaces may use together, or none.
    pub quota: Option<u64>,
    /// `erasure_timeout`, T, for every space billed to it.
    pub erasure_timeout: u64,
    /// `state`: open or suspended.
    pub state: LibraryState,
    /// `open_until`: the wall-clock instant, in seconds since 1970, from
    /// which the library is suspended whatever its `state`; none by default.
    pub open_until: Option<u64>,
    /// ext-deposit-tokens.md's `deposit_allowance`, 0 to 65,536 tokens per
    /// window; none for the operator's default.
    pub deposit_allowance: Option<u64>,
    /// ext-deposit-tokens.md's `space_share`, 0 to `deposit_allowance`;
    /// none for the operator's default.
    pub space_share: Option<u64>,
}

impl Library {
    /// The library's state at the wall clock `wall` (ext-libraries.md, 2.4
    /// Settings): suspended by its `state`, or once `open_until` is set and
    /// the wall clock is at or past it, or not known.
    pub fn state_at(&self, wall: Option<u64>) -> LibraryState {
        match (self.state, self.open_until) {
            (LibraryState::Suspended, _) => LibraryState::Suspended,
            (LibraryState::Open, Some(until)) if wall.is_none_or(|wall| wall >= until) => {
                LibraryState::Suspended
            }
            (LibraryState::Open, _) => LibraryState::Open,
        }
    }
}

/// A space's attachment (ext-libraries.md, 2.5 What a peer keeps): its
/// library, the ticket ID that attached it, and the peer's reading when the
/// attachment took effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The library the space is billed to.
    pub library: LibraryId,
    /// The ticket that attached it; none for a create the operator's open
    /// library took without a ticket.
    pub ticket: Option<TicketId>,
    /// The peer's reading when the attachment took effect.
    pub at: Reading,
}

/// A hold (ext-libraries.md, 3.7 Registering a hold): the source space
/// that stores the object, the access key the hold was registered with,
/// and the peer's reading at its registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    /// The space that stores the object.
    pub source: [u8; 32],
    /// The object's access key, as the hold proved it.
    pub access: [u8; 32],
    /// The peer's reading at the registration.
    pub at: Reading,
}

/// A copy of a held object in a library (ext-libraries.md, 3.8 Keeping a
/// held object): the source space it was copied from, the object's index
/// record as the source kept it, its stored bytes, and the peer's reading
/// when it was made. Its pieces are kept under the library's copy home
/// (crate `libraries`, `copy_home`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    /// The space that stores the object.
    pub source: [u8; 32],
    /// The object's index record (crate `records`, `ObjectRecord`).
    pub object: Vec<u8>,
    /// Its stored bytes, which count in its library's `used_bytes` and
    /// `held_bytes`.
    pub bytes: u64,
    /// The peer's reading when it was made.
    pub at: Reading,
}

/// A library's allowance window (ext-deposit-tokens.md, 2.6 Settings and
/// 2.7 What a peer keeps): its start, on the library's timeline, the
/// tokens drawn in it, and the tokens each space's writers drew in it by
/// space draws, by space ID, ascending.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    /// The reading of the library's timeline, in seconds, at which it
    /// opened.
    pub start: u64,
    /// The tokens drawn in it, by grant draws and space draws alike.
    pub drawn: u64,
    /// Each space's share drawn, by space ID, ascending; none of them 0.
    pub spaces: Vec<([u8; 32], u64)>,
}

/// The most a token count of a window may be: `deposit_allowance`'s
/// greatest value.
pub const MAX_ALLOWANCE: u64 = 65_536;

/// One record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A library's settings.
    Library(LibraryId, Library),
    /// A space's attachment.
    Attachment([u8; 32], Attachment),
    /// A ticket ID that attached a space, with its `not_after`.
    Ticket(TicketId, u64),
    /// A space the operator deleted.
    Deleted([u8; 32]),
    /// A space detached from its library, at a reading.
    Detached([u8; 32], Reading),
    /// A hold, named by its holding space and the object's locator.
    Hold([u8; 32], [u8; 64], Hold),
    /// A copy, named by the object's locator and its library.
    Copy([u8; 64], LibraryId, Copy),
    /// A library being handed over to another peer (peers.md, 3.1 Hosting
    /// a space, "Hand-over"): its spaces take no store until the hand-over
    /// ends or is called off; with the spaces its shard kept as it froze,
    /// ascending, which the hand-over carries.
    HandingOver(LibraryId, Vec<[u8; 32]>),
    /// ext-deposit-tokens.md: a library's allowance window.
    Window(LibraryId, Window),
    /// ext-deposit-tokens.md: a deposit grant used, by the SHA-256 of its
    /// library's ID and its ID, with its `not_after`.
    Grant([u8; 32], TicketId, u64),
}

/// The table of library settings.
pub const LIBRARY: u8 = b'L';
/// The table of attachments.
pub const ATTACHMENT: u8 = b'S';
/// The table of ticket IDs used.
pub const TICKET: u8 = b'T';
/// The table of deleted spaces.
pub const DELETED: u8 = b'D';
/// The table of detached spaces.
pub const DETACHED: u8 = b'X';
/// The table of holds.
pub const HOLD: u8 = b'H';
/// The table of copies.
pub const COPY: u8 = b'C';
/// The table of libraries being handed over.
pub const HANDING_OVER: u8 = b'O';
/// ext-deposit-tokens.md: the table of allowance windows.
pub const WINDOW: u8 = b'W';
/// ext-deposit-tokens.md: the table of deposit grants used.
pub const GRANT: u8 = b'G';

/// A deposit grant's key: the SHA-256 of its library's ID, so that it is
/// kept beside the library's window, then its ID.
pub fn grant_key(library: &LibraryId, id: &TicketId) -> Vec<u8> {
    [&library_hash(library)[..], &id[..]].concat()
}

/// The SHA-256 of a library ID's UTF-8.
pub fn library_hash(library: &LibraryId) -> [u8; 32] {
    frasil_crypto::primitives::sha256(&[library.as_str().as_bytes()])
}

/// A hold's key: its holding space, then the locator.
pub fn hold_key(space: &[u8; 32], locator: &[u8; 64]) -> Vec<u8> {
    [&space[..], &locator[..]].concat()
}

fn reading_value(reading: &Reading) -> Value {
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(reading.timeline));
    map.insert(2, Value::Unsigned(reading.run));
    if let Some(wall) = reading.wall {
        map.insert(3, Value::Unsigned(wall));
    }
    Value::Map(map)
}

fn read_reading(value: &Value) -> Option<Reading> {
    let map = value.as_map().ok()?;
    if !map.keys().all(|key| (1..=3).contains(key)) {
        return None;
    }
    Some(Reading {
        timeline: map.get(&1)?.as_unsigned().ok()?,
        run: map.get(&2)?.as_unsigned().ok()?,
        wall: match map.get(&3) {
            Some(value) => Some(value.as_unsigned().ok()?),
            None => None,
        },
    })
}

fn state_code(state: LibraryState) -> u64 {
    match state {
        LibraryState::Open => 0,
        LibraryState::Suspended => 1,
    }
}

/// A map of exactly these keys, each present.
fn exactly(map: &Map, keys: &[u64]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(key))
}

impl Record {
    /// The record's table, key and bytes.
    pub fn encode(&self) -> (u8, Vec<u8>, Vec<u8>) {
        let mut map = Map::new();
        let (table, key) = match self {
            Self::Library(id, library) => {
                if let Some(quota) = library.quota {
                    map.insert(1, Value::Unsigned(quota));
                }
                map.insert(2, Value::Unsigned(library.erasure_timeout));
                map.insert(3, Value::Unsigned(state_code(library.state)));
                if let Some(until) = library.open_until {
                    map.insert(4, Value::Unsigned(until));
                }
                if let Some(allowance) = library.deposit_allowance {
                    map.insert(5, Value::Unsigned(allowance));
                }
                if let Some(share) = library.space_share {
                    map.insert(6, Value::Unsigned(share));
                }
                (LIBRARY, id.as_str().as_bytes().to_vec())
            }
            Self::Attachment(space, attachment) => {
                map.insert(1, Value::from(attachment.library.as_str()));
                if let Some(ticket) = attachment.ticket {
                    map.insert(2, Value::from(ticket.as_slice()));
                }
                map.insert(3, reading_value(&attachment.at));
                (ATTACHMENT, space.to_vec())
            }
            Self::Ticket(id, not_after) => {
                map.insert(1, Value::Unsigned(*not_after));
                (TICKET, id.to_vec())
            }
            Self::Deleted(space) => (DELETED, space.to_vec()),
            Self::Detached(space, at) => {
                map.insert(1, reading_value(at));
                (DETACHED, space.to_vec())
            }
            Self::Hold(space, locator, hold) => {
                map.insert(1, Value::from(hold.source));
                map.insert(2, Value::from(hold.access));
                map.insert(3, reading_value(&hold.at));
                (HOLD, hold_key(space, locator))
            }
            Self::Copy(locator, library, copy) => {
                map.insert(1, Value::from(copy.source));
                map.insert(2, Value::from(copy.object.as_slice()));
                map.insert(3, Value::Unsigned(copy.bytes));
                map.insert(4, reading_value(&copy.at));
                (COPY, [&locator[..], library.as_str().as_bytes()].concat())
            }
            Self::HandingOver(library, spaces) => {
                map.insert(
                    1,
                    Value::Array(spaces.iter().map(|space| Value::from(*space)).collect()),
                );
                (HANDING_OVER, library.as_str().as_bytes().to_vec())
            }
            Self::Window(library, window) => {
                map.insert(1, Value::Unsigned(window.start));
                map.insert(2, Value::Unsigned(window.drawn));
                map.insert(
                    3,
                    Value::Array(
                        window
                            .spaces
                            .iter()
                            .map(|(space, drawn)| {
                                Value::Array(vec![Value::from(*space), Value::Unsigned(*drawn)])
                            })
                            .collect(),
                    ),
                );
                (WINDOW, library.as_str().as_bytes().to_vec())
            }
            Self::Grant(hash, id, not_after) => {
                map.insert(1, Value::Unsigned(*not_after));
                (GRANT, [&hash[..], &id[..]].concat())
            }
        };
        (table, key, Value::Map(map).encode())
    }

    /// Reads a record of a table, by its key and bytes; `None` for one that
    /// does not read.
    pub fn decode(table: u8, key: &[u8], bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        let space = || <[u8; 32]>::try_from(key).ok();
        Some(match table {
            LIBRARY => {
                let id = LibraryId::new(core::str::from_utf8(key).ok()?).ok()?;
                let quota = match map.get(&1) {
                    Some(value) => Some(value.as_unsigned().ok()?),
                    None => None,
                };
                let optional = |key: u64| match map.get(&key) {
                    Some(value) => value.as_unsigned().ok().map(Some),
                    None => Some(None),
                };
                let open_until = optional(4)?;
                let deposit_allowance = optional(5)?;
                let space_share = optional(6)?;
                if !map.keys().all(|key| (1..=6).contains(key))
                    || !map.contains_key(&2)
                    || !map.contains_key(&3)
                    || deposit_allowance.is_some_and(|a| a > MAX_ALLOWANCE)
                    || space_share.is_some_and(|s| s > deposit_allowance.unwrap_or(MAX_ALLOWANCE))
                {
                    return None;
                }
                let state = match map.get(&3)?.as_unsigned().ok()? {
                    0 => LibraryState::Open,
                    1 => LibraryState::Suspended,
                    _ => return None,
                };
                Self::Library(
                    id,
                    Library {
                        quota,
                        erasure_timeout: map.get(&2)?.as_unsigned().ok()?,
                        state,
                        open_until,
                        deposit_allowance,
                        space_share,
                    },
                )
            }
            ATTACHMENT => {
                let ticket = match map.get(&2) {
                    Some(value) => Some(value.as_byte_array::<TICKET_ID_BYTES>().ok()?),
                    None => None,
                };
                if !exactly(
                    map,
                    if ticket.is_some() {
                        &[1, 2, 3]
                    } else {
                        &[1, 3]
                    },
                ) {
                    return None;
                }
                Self::Attachment(
                    space()?,
                    Attachment {
                        library: LibraryId::new(map.get(&1)?.as_text().ok()?).ok()?,
                        ticket,
                        at: read_reading(map.get(&3)?)?,
                    },
                )
            }
            TICKET => {
                if !exactly(map, &[1]) {
                    return None;
                }
                Self::Ticket(
                    TicketId::try_from(key).ok()?,
                    map.get(&1)?.as_unsigned().ok()?,
                )
            }
            DELETED => {
                if !map.is_empty() {
                    return None;
                }
                Self::Deleted(space()?)
            }
            DETACHED => {
                if !exactly(map, &[1]) {
                    return None;
                }
                Self::Detached(space()?, read_reading(map.get(&1)?)?)
            }
            HOLD => {
                if !exactly(map, &[1, 2, 3]) || key.len() != 96 {
                    return None;
                }
                Self::Hold(
                    key[..32].try_into().ok()?,
                    key[32..].try_into().ok()?,
                    Hold {
                        source: map.get(&1)?.as_byte_array::<32>().ok()?,
                        access: map.get(&2)?.as_byte_array::<32>().ok()?,
                        at: read_reading(map.get(&3)?)?,
                    },
                )
            }
            HANDING_OVER => {
                if !exactly(map, &[1]) {
                    return None;
                }
                let mut spaces: Vec<[u8; 32]> = Vec::new();
                for item in map.get(&1)?.as_array().ok()? {
                    let space = item.as_byte_array::<32>().ok()?;
                    if spaces.last().is_some_and(|last| *last >= space) {
                        return None;
                    }
                    spaces.push(space);
                }
                Self::HandingOver(
                    LibraryId::new(core::str::from_utf8(key).ok()?).ok()?,
                    spaces,
                )
            }
            WINDOW => {
                if !exactly(map, &[1, 2, 3]) {
                    return None;
                }
                let drawn = map.get(&2)?.as_unsigned().ok()?;
                let mut spaces: Vec<([u8; 32], u64)> = Vec::new();
                for pair in map.get(&3)?.as_array().ok()? {
                    let [space, count] = pair.as_array().ok()? else {
                        return None;
                    };
                    let space = space.as_byte_array::<32>().ok()?;
                    let count = count.as_unsigned().ok()?;
                    if count == 0
                        || count > drawn
                        || spaces.last().is_some_and(|(last, _)| *last >= space)
                    {
                        return None;
                    }
                    spaces.push((space, count));
                }
                if drawn > MAX_ALLOWANCE {
                    return None;
                }
                Self::Window(
                    LibraryId::new(core::str::from_utf8(key).ok()?).ok()?,
                    Window {
                        start: map.get(&1)?.as_unsigned().ok()?,
                        drawn,
                        spaces,
                    },
                )
            }
            GRANT => {
                if !exactly(map, &[1]) || key.len() != 32 + TICKET_ID_BYTES {
                    return None;
                }
                Self::Grant(
                    key[..32].try_into().ok()?,
                    key[32..].try_into().ok()?,
                    map.get(&1)?.as_unsigned().ok()?,
                )
            }
            COPY => {
                if !exactly(map, &[1, 2, 3, 4]) || key.len() <= 64 {
                    return None;
                }
                Self::Copy(
                    key[..64].try_into().ok()?,
                    LibraryId::new(core::str::from_utf8(&key[64..]).ok()?).ok()?,
                    Copy {
                        source: map.get(&1)?.as_byte_array::<32>().ok()?,
                        object: map.get(&2)?.as_bytes().ok()?.to_vec(),
                        bytes: map.get(&3)?.as_unsigned().ok()?,
                        at: read_reading(map.get(&4)?)?,
                    },
                )
            }
            _ => return None,
        })
    }
}

/// A closed space's usage at rest, which its library's ledger reads without
/// opening it (section 2.5): its usage numbers but those that holds and
/// drops change while it is closed, and its complete objects that no unit
/// of it lists, which holds may keep, with their bytes.
///
/// ```text
/// usage = {1: stored_bytes, 2: released_bytes, 3: covered_bytes,
///          4: erasing_bytes, 5: streams, 6: last_store?,
///          7: [* [locator, bytes]]}
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageRecord {
    /// `stored_bytes`, without invite drops.
    pub stored_bytes: u64,
    /// Released and not reclaimed.
    pub released_bytes: u64,
    /// Covered and not collected.
    pub covered_bytes: u64,
    /// Named by erasures that wait.
    pub erasing_bytes: u64,
    /// Its streams.
    pub streams: u64,
    /// The wall-clock instant of its last store, if known.
    pub last_store: Option<u64>,
    /// Its complete objects that no unit of it lists, ascending, and their
    /// bytes.
    pub unlisted: Vec<([u8; 64], u64)>,
}

impl UsageRecord {
    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(self.stored_bytes));
        map.insert(2, Value::Unsigned(self.released_bytes));
        map.insert(3, Value::Unsigned(self.covered_bytes));
        map.insert(4, Value::Unsigned(self.erasing_bytes));
        map.insert(5, Value::Unsigned(self.streams));
        if let Some(instant) = self.last_store {
            map.insert(6, Value::Unsigned(instant));
        }
        map.insert(
            7,
            Value::Array(
                self.unlisted
                    .iter()
                    .map(|(locator, bytes)| {
                        Value::Array(vec![
                            Value::from(locator.as_slice()),
                            Value::Unsigned(*bytes),
                        ])
                    })
                    .collect(),
            ),
        );
        Value::Map(map).encode()
    }

    /// A usage record, if `bytes` are one in its one encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        let optional = usize::from(map.contains_key(&6));
        if map.len() != 6 + optional {
            return None;
        }
        let uint = |key: u64| map.get(&key)?.as_unsigned().ok();
        let unlisted = map
            .get(&7)?
            .as_array()
            .ok()?
            .iter()
            .map(|pair| match pair.as_array().ok()? {
                [locator, bytes] => Some((
                    locator.as_byte_array::<64>().ok()?,
                    bytes.as_unsigned().ok()?,
                )),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if unlisted.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return None;
        }
        let record = Self {
            stored_bytes: uint(1)?,
            released_bytes: uint(2)?,
            covered_bytes: uint(3)?,
            erasing_bytes: uint(4)?,
            streams: uint(5)?,
            last_store: match map.get(&6) {
                Some(value) => Some(value.as_unsigned().ok()?),
                None => None,
            },
            unlisted,
        };
        (record.encode() == bytes).then_some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(timeline: u64, wall: Option<u64>) -> Reading {
        Reading {
            timeline,
            wall,
            run: 2,
        }
    }

    #[test]
    fn every_record_reads_back() {
        let library = LibraryId::new("project:7c1f").unwrap();
        let records = [
            Record::Library(
                library.clone(),
                Library {
                    quota: Some(1000),
                    erasure_timeout: 3600,
                    state: LibraryState::Suspended,
                    open_until: None,
                    deposit_allowance: None,
                    space_share: None,
                },
            ),
            Record::Library(
                library.clone(),
                Library {
                    quota: None,
                    erasure_timeout: 7 * 86_400,
                    state: LibraryState::Open,
                    open_until: None,
                    deposit_allowance: None,
                    space_share: None,
                },
            ),
            Record::Library(
                library.clone(),
                Library {
                    quota: Some(5),
                    erasure_timeout: 7 * 86_400,
                    state: LibraryState::Open,
                    open_until: Some(1_792_000_000),
                    deposit_allowance: None,
                    space_share: None,
                },
            ),
            Record::Library(
                library.clone(),
                Library {
                    quota: None,
                    erasure_timeout: 7 * 86_400,
                    state: LibraryState::Open,
                    open_until: Some(1_792_000_000),
                    deposit_allowance: None,
                    space_share: None,
                },
            ),
            Record::Attachment(
                [1; 32],
                Attachment {
                    library: library.clone(),
                    ticket: Some([2; 16]),
                    at: reading(10, Some(1_792_000_000)),
                },
            ),
            Record::Attachment(
                [1; 32],
                Attachment {
                    library: library.clone(),
                    ticket: None,
                    at: reading(11, None),
                },
            ),
            Record::Ticket([3; 16], 1_792_003_600),
            Record::Library(
                library.clone(),
                Library {
                    quota: None,
                    erasure_timeout: 3600,
                    state: LibraryState::Open,
                    open_until: None,
                    deposit_allowance: Some(100),
                    space_share: Some(0),
                },
            ),
            Record::Window(
                library.clone(),
                Window {
                    start: 86_400,
                    drawn: 20,
                    spaces: vec![([1; 32], 4), ([2; 32], 16)],
                },
            ),
            Record::Window(library.clone(), Window::default()),
            Record::Grant(library_hash(&library), [9; 16], 1_792_003_600),
            Record::Deleted([4; 32]),
            Record::Detached([5; 32], reading(12, None)),
            Record::Hold(
                [6; 32],
                [7; 64],
                Hold {
                    source: [8; 32],
                    access: [9; 32],
                    at: reading(13, Some(1_792_000_100)),
                },
            ),
        ];
        for record in records {
            let (table, key, bytes) = record.encode();
            assert_eq!(Record::decode(table, &key, &bytes), Some(record));
            assert_eq!(cbor::decode(&bytes).unwrap().encode(), bytes);
        }
    }

    #[test]
    fn odd_records_do_not_read() {
        assert_eq!(Record::decode(TICKET, &[0; 15], &[0xa1, 1, 1]), None);
        assert_eq!(Record::decode(DELETED, &[0; 32], &[0xa1, 1, 1]), None);
        assert_eq!(Record::decode(b'?', &[0; 32], &[0xa0]), None);
        // A library ID holding a control character.
        assert_eq!(Record::decode(LIBRARY, b"a\x07", &[0xa2, 2, 1, 3, 0]), None);
        assert!(Record::decode(LIBRARY, b"a", &[0xa2, 2, 1, 3, 0]).is_some());
        assert_eq!(Record::decode(LIBRARY, b"a", &[0xa2, 2, 1, 3, 2]), None);
        // A record kept before open_until reads as before; one with it
        // reads; one with a key past it does not.
        assert!(Record::decode(LIBRARY, b"a", &[0xa3, 2, 1, 3, 0, 4, 9]).is_some());
        assert_eq!(
            Record::decode(LIBRARY, b"a", &[0xa3, 2, 1, 3, 0, 7, 9]),
            None
        );
    }

    #[test]
    fn deposit_records_read_strictly() {
        let window = |spaces: &[([u8; 32], u64)], drawn: u64| {
            Record::Window(
                LibraryId::new("a").unwrap(),
                Window {
                    start: 1,
                    drawn,
                    spaces: spaces.to_vec(),
                },
            )
            .encode()
        };
        // Spaces out of order, twice, with 0, or past the window's count.
        for (spaces, drawn) in [
            (vec![([2; 32], 1), ([1; 32], 1)], 2),
            (vec![([1; 32], 1), ([1; 32], 1)], 2),
            (vec![([1; 32], 0)], 2),
            (vec![([1; 32], 3)], 2),
            (vec![], MAX_ALLOWANCE + 1),
        ] {
            let (table, key, bytes) = window(&spaces, drawn);
            assert_eq!(Record::decode(table, &key, &bytes), None, "{spaces:?}");
        }
        // A share past the allowance, an allowance past its range, and a
        // key past 6.
        for bytes in [
            &[0xa4, 2, 1, 3, 0, 5, 4, 6, 5][..],
            &[0xa3, 2, 1, 3, 0, 0x05, 0x1a, 0, 1, 0, 1],
            &[0xa3, 2, 1, 3, 0, 7, 1],
        ] {
            assert_eq!(Record::decode(LIBRARY, b"a", bytes), None, "{bytes:?}");
        }
        assert!(Record::decode(LIBRARY, b"a", &[0xa4, 2, 1, 3, 0, 5, 4, 6, 4]).is_some());
        // A grant's key is a hash and an ID.
        assert_eq!(Record::decode(GRANT, &[0; 47], &[0xa1, 1, 1]), None);
        assert!(Record::decode(GRANT, &[0; 48], &[0xa1, 1, 1]).is_some());
    }

    #[test]
    fn open_until_suspends_from_its_instant() {
        let mut library = Library {
            quota: None,
            erasure_timeout: 3600,
            state: LibraryState::Open,
            open_until: None,
            deposit_allowance: None,
            space_share: None,
        };
        assert_eq!(library.state_at(None), LibraryState::Open);
        library.open_until = Some(100);
        assert_eq!(library.state_at(Some(99)), LibraryState::Open);
        assert_eq!(library.state_at(Some(100)), LibraryState::Suspended);
        assert_eq!(library.state_at(None), LibraryState::Suspended);
        library.state = LibraryState::Suspended;
        assert_eq!(library.state_at(Some(0)), LibraryState::Suspended);
    }
}
