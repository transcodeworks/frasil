//! A library's hand-over bundle, as one peer exports it and another
//! imports it (peers.md, 3.1 Hosting a space, "Hand-over"; ext-libraries.md,
//! 3.10 The home peer). It holds the library as it stands: the space
//! index's records of its spaces and of the library, the last reading of
//! the shard's timeline, its shard's records, and the object pieces of its
//! spaces and copies.
//!
//! A bundle is a stream of items, each `u32 length || CBOR`, so that
//! neither peer holds it whole: the header, then the shard's records a
//! page at a time, then each piece, then the end.
//!
//! ```text
//! header = {1: 3, 2: library ID (text),
//!           3: reading {1: timeline, 2: run, 3: wall?},
//!           4: [* [address, record]]}   the space index's records
//! item   = [1, [* [address, record]]]   a page of the shard's records
//!        / [2, key (text), bytes]       an object piece
//!        / [0]                          the end
//! ```
//!
//! Each list of records is in ascending order with no repeat, and so are
//! the shard's records and the pieces' keys across their items. A stream
//! that stops before its end is not a bundle. Its records are the peer's
//! own (crate `records`), and pass between peers of one operator only.
//! This file reads no clock and does no IO.

use frasil_base::cbor::{self, Map, Value};
use frasil_base::time::Reading;

/// The bundle's version. Version 3's records name devices by device ID
/// (crate `records`); a bundle of an earlier version, whose records name
/// them by Ed25519 key, does not read.
pub const VERSION: u64 = 3;

/// The largest item a bundle holds, its length prefix aside: well above a
/// page of records or a piece.
pub const MAX_ITEM: usize = 64 << 20;

/// One record: its address and its bytes.
pub type Row = (Vec<u8>, Vec<u8>);

/// A bundle's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The library ID.
    pub library: String,
    /// The last reading of the shard's timeline.
    pub reading: Reading,
    /// The space index's records.
    pub index: Vec<Row>,
}

/// An item after the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A page of the shard's records.
    Records(Vec<Row>),
    /// An object piece: its key and its bytes.
    Piece(String, Vec<u8>),
    /// The end of the bundle.
    End,
}

/// A reading as a map.
pub fn reading_value(reading: &Reading) -> Value {
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(reading.timeline));
    map.insert(2, Value::Unsigned(reading.run));
    if let Some(wall) = reading.wall {
        map.insert(3, Value::Unsigned(wall));
    }
    Value::Map(map)
}

/// A reading from its map: exactly its keys.
pub fn read_reading(value: &Value) -> Option<Reading> {
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

/// Records as a list of pairs.
pub fn rows_value(rows: &[Row]) -> Value {
    Value::Array(
        rows.iter()
            .map(|(address, record)| {
                Value::Array(vec![
                    Value::from(address.as_slice()),
                    Value::from(record.as_slice()),
                ])
            })
            .collect(),
    )
}

/// Records from a list of pairs, in ascending order with no repeat.
pub fn read_rows(value: &Value) -> Option<Vec<Row>> {
    let mut rows: Vec<Row> = Vec::new();
    for item in value.as_array().ok()? {
        let [address, record] = item.as_array().ok()? else {
            return None;
        };
        let address = address.as_bytes().ok()?.to_vec();
        if rows.last().is_some_and(|(last, _)| *last >= address) {
            return None;
        }
        rows.push((address, record.as_bytes().ok()?.to_vec()));
    }
    Some(rows)
}

/// An item's bytes with their length prefix.
fn framed(value: &Value) -> Vec<u8> {
    let body = value.encode();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

impl Header {
    /// The header's bytes, with their length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Text(self.library.clone()));
        map.insert(3, reading_value(&self.reading));
        map.insert(4, rows_value(&self.index));
        framed(&Value::Map(map))
    }

    /// Reads a header from its bytes, without their length prefix: exactly
    /// its keys, of this version.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 4 || !map.keys().all(|key| (1..=4).contains(key)) {
            return None;
        }
        if map.get(&1)?.as_unsigned().ok()? != VERSION {
            return None;
        }
        Some(Self {
            library: map.get(&2)?.as_text().ok()?.to_owned(),
            reading: read_reading(map.get(&3)?)?,
            index: read_rows(map.get(&4)?)?,
        })
    }
}

impl Item {
    /// The item's bytes, with their length prefix.
    pub fn encode(&self) -> Vec<u8> {
        framed(&match self {
            Self::Records(rows) => Value::Array(vec![Value::Unsigned(1), rows_value(rows)]),
            Self::Piece(key, bytes) => Value::Array(vec![
                Value::Unsigned(2),
                Value::Text(key.clone()),
                Value::from(bytes.as_slice()),
            ]),
            Self::End => Value::Array(vec![Value::Unsigned(0)]),
        })
    }

    /// Reads an item from its bytes, without their length prefix.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let parts = value.as_array().ok()?;
        match (parts.first()?.as_unsigned().ok()?, parts.len()) {
            (0, 1) => Some(Self::End),
            (1, 2) => Some(Self::Records(read_rows(&parts[1])?)),
            (2, 3) => Some(Self::Piece(
                parts[1].as_text().ok()?.to_owned(),
                parts[2].as_bytes().ok()?.to_vec(),
            )),
            _ => None,
        }
    }
}

/// Splits a bundle's bytes into its items as they arrive: [`Self::push`]
/// what came, then [`Self::take`] each whole item, without its length
/// prefix.
#[derive(Debug, Default)]
pub struct Items {
    held: Vec<u8>,
}

impl Items {
    /// Takes bytes that came.
    pub fn push(&mut self, bytes: &[u8]) {
        self.held.extend_from_slice(bytes);
    }

    /// The next whole item, if it came; `Err` for a length past
    /// [`MAX_ITEM`].
    #[allow(clippy::result_unit_err)]
    pub fn take(&mut self) -> Result<Option<Vec<u8>>, ()> {
        let Some(prefix) = self.held.get(..4) else {
            return Ok(None);
        };
        let length = u32::from_be_bytes(prefix.try_into().map_err(|_| ())?) as usize;
        if length > MAX_ITEM {
            return Err(());
        }
        if self.held.len() < 4 + length {
            return Ok(None);
        }
        let item = self.held[4..4 + length].to_vec();
        self.held.drain(..4 + length);
        Ok(Some(item))
    }

    /// Whether bytes of an item that has not come whole are held.
    pub fn partial(&self) -> bool {
        !self.held.is_empty()
    }
}

/// One page of a shard's records, as the shard's owner hands it out:
/// `{1: [* [address, record]], 2: 1 if more follow, else 0}`.
pub fn encode_page(rows: &[Row], more: bool) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(1, rows_value(rows));
    map.insert(2, Value::Unsigned(u64::from(more)));
    Value::Map(map).encode()
}

/// Reads a page.
pub fn decode_page(bytes: &[u8]) -> Option<(Vec<Row>, bool)> {
    let value = cbor::decode(bytes).ok()?;
    let map = value.as_map().ok()?;
    if map.len() != 2 {
        return None;
    }
    let more = match map.get(&2)?.as_unsigned().ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some((read_rows(map.get(&1)?)?, more))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_streams_and_reads_back() {
        let header = Header {
            library: "project:a".into(),
            reading: Reading {
                timeline: 7,
                wall: Some(9),
                run: 2,
            },
            index: vec![(vec![4, 5], vec![6])],
        };
        let items = [
            Item::Records(vec![(vec![1], vec![2]), (vec![3], vec![])]),
            Item::Piece("a/b/0".into(), vec![7]),
            Item::End,
        ];
        let mut bytes = header.encode();
        for item in &items {
            bytes.extend(item.encode());
        }
        // In pieces of 3 bytes, as a body may come.
        let mut split = Items::default();
        let mut read = Vec::new();
        for chunk in bytes.chunks(3) {
            split.push(chunk);
            while let Some(item) = split.take().unwrap() {
                read.push(item);
            }
        }
        assert!(!split.partial());
        assert_eq!(Header::decode(&read[0]), Some(header));
        let rest: Vec<Item> = read[1..].iter().map(|b| Item::decode(b).unwrap()).collect();
        assert_eq!(rest, items);
        assert_eq!(
            Item::decode(&Item::Records(vec![(vec![3], vec![]), (vec![1], vec![])]).encode()[4..]),
            None
        );
        let page = encode_page(&[(vec![1], vec![2])], true);
        assert_eq!(decode_page(&page), Some((vec![(vec![1], vec![2])], true)));
    }

    #[test]
    fn an_item_past_the_limit_is_refused() {
        let mut split = Items::default();
        split.push(&(MAX_ITEM as u32 + 1).to_be_bytes());
        assert!(split.take().is_err());
    }
}
