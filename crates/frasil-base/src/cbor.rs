//! Deterministic CBOR (overview.md, "Deterministic CBOR").
//!
//! Frasil's own structures use RFC 8949's core deterministic encoding
//! (section 4.2.1), restricted to:
//! - unsigned integers, 0 to 2^64 − 1;
//! - byte strings and UTF-8 text strings;
//! - arrays;
//! - maps whose keys are unsigned integers in ascending order;
//!
//! all with definite lengths and shortest heads. No negative integers,
//! floats, simple values or tags.
//!
//! adapter-records.md's **records subset** widens it for a cell's value:
//! negative integers, `false` and `true`, and binary64 floats, always 8
//! bytes and never a NaN. Only [`decode_records`] accepts them; [`decode`]
//! refuses them as before.
//!
//! [`decode`] accepts exactly one encoding: it decodes, refuses anything
//! outside the subset, re-encodes and compares byte for byte. Any difference,
//! or any byte after the top-level item, is [`Malformed`]. It allocates
//! nothing for a count before checking that the input can hold that many
//! items, so a forged count cannot make it allocate more than the input's
//! length.
//!
//! Each document names the keys each map allows and requires; [`KeyRules`]
//! checks them, with an unknown key `Malformed` unless the document says it
//! is ignored. A document's own count bounds are checked with [`Reader`]'s
//! [`array_len`](Reader::array_len) and [`map_len`](Reader::map_len), or on
//! the decoded [`Value`], before anything is allocated for the items.

use std::collections::BTreeMap;
use std::fmt;

/// Major type 0, an unsigned integer.
pub const UNSIGNED: u8 = 0;
/// Major type 1, a negative integer: the records subset only.
pub const NEGATIVE: u8 = 1;
/// The simple value `false`.
const FALSE: u8 = 0xf4;
/// The simple value `true`.
const TRUE: u8 = 0xf5;
/// The head of a binary64 float.
const FLOAT64: u8 = 0xfb;
/// Major type 2, a byte string.
pub const BYTES: u8 = 2;
/// Major type 3, a UTF-8 text string.
pub const TEXT: u8 = 3;
/// Major type 4, an array.
pub const ARRAY: u8 = 4;
/// Major type 5, a map.
pub const MAP: u8 = 5;

/// The deepest nesting [`decode`] accepts (overview.md, section 5.3,
/// "Deterministic CBOR"): the top-level item is at depth 0, each item of an
/// array and each key and value of a map is one deeper, and an item deeper
/// than this is `Malformed`. It also bounds the decoder's recursion.
pub const MAX_DEPTH: usize = 16;

/// The bytes are not the one deterministic encoding of a value of the
/// subset, or not the shape expected. Converts into
/// [`ErrorClass::Malformed`](crate::errors::ErrorClass::Malformed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Malformed;

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed")
    }
}

impl std::error::Error for Malformed {}

/// A map of the subset: unsigned keys, kept in ascending order.
pub type Map = BTreeMap<u64, Value>;

/// One value of the subset, or of the records subset.
#[derive(Debug, Clone)]
pub enum Value {
    /// An unsigned integer.
    Unsigned(u64),
    /// A negative integer, `-1 - n` for `Negative(n)`: from -1 to -2^64.
    /// The records subset only.
    Negative(u64),
    /// `false` or `true`. The records subset only.
    Bool(bool),
    /// A binary64 float, never a NaN, compared by its bits, so `0.0` and
    /// `-0.0` differ. The records subset only.
    Float(f64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map with unsigned keys.
    Map(Map),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsigned(a), Self::Unsigned(b)) | (Self::Negative(a), Self::Negative(b)) => {
                a == b
            }
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::Text(a), Self::Text(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Map(a), Self::Map(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Unsigned(value) | Self::Negative(value) => value.hash(state),
            Self::Bool(value) => value.hash(state),
            Self::Float(value) => value.to_bits().hash(state),
            Self::Bytes(value) => value.hash(state),
            Self::Text(value) => value.hash(state),
            Self::Array(items) => items.hash(state),
            Self::Map(map) => map.hash(state),
        }
    }
}

impl Value {
    /// The value's major type.
    pub fn major(&self) -> u8 {
        match self {
            Self::Unsigned(_) => UNSIGNED,
            Self::Negative(_) => NEGATIVE,
            Self::Bool(_) | Self::Float(_) => 7,
            Self::Bytes(_) => BYTES,
            Self::Text(_) => TEXT,
            Self::Array(_) => ARRAY,
            Self::Map(_) => MAP,
        }
    }

    /// The value's one deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Appends the value's one deterministic encoding.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Unsigned(value) => unsigned(out, *value),
            Self::Negative(value) => head(out, NEGATIVE, *value),
            Self::Bool(value) => out.push(if *value { TRUE } else { FALSE }),
            Self::Float(value) => {
                out.push(FLOAT64);
                out.extend_from_slice(&value.to_bits().to_be_bytes());
            }
            Self::Bytes(value) => bytes(out, value),
            Self::Text(value) => text(out, value),
            Self::Array(items) => {
                array_head(out, items.len());
                for item in items {
                    item.encode_into(out);
                }
            }
            Self::Map(map) => {
                map_head(out, map.len());
                for (key, value) in map {
                    unsigned(out, *key);
                    value.encode_into(out);
                }
            }
        }
    }

    /// The unsigned integer, or `Malformed`.
    pub fn as_unsigned(&self) -> Result<u64, Malformed> {
        match self {
            Self::Unsigned(value) => Ok(*value),
            _ => Err(Malformed),
        }
    }

    /// The byte string, or `Malformed`.
    pub fn as_bytes(&self) -> Result<&[u8], Malformed> {
        match self {
            Self::Bytes(value) => Ok(value),
            _ => Err(Malformed),
        }
    }

    /// A byte string of exactly `N` bytes, or `Malformed`.
    pub fn as_byte_array<const N: usize>(&self) -> Result<[u8; N], Malformed> {
        self.as_bytes()?.try_into().map_err(|_| Malformed)
    }

    /// A signed integer in `i64`'s range, unsigned or negative, or
    /// `Malformed`.
    pub fn as_i64(&self) -> Result<i64, Malformed> {
        match self {
            Self::Unsigned(value) => i64::try_from(*value).map_err(|_| Malformed),
            Self::Negative(value) => i64::try_from(*value).map(|n| -1 - n).map_err(|_| Malformed),
            _ => Err(Malformed),
        }
    }

    /// The boolean, or `Malformed`.
    pub fn as_bool(&self) -> Result<bool, Malformed> {
        match self {
            Self::Bool(value) => Ok(*value),
            _ => Err(Malformed),
        }
    }

    /// The float, or `Malformed`.
    pub fn as_f64(&self) -> Result<f64, Malformed> {
        match self {
            Self::Float(value) => Ok(*value),
            _ => Err(Malformed),
        }
    }

    /// Whether the value, or an item inside it, is outside the subset of
    /// Frasil's own structures: of the records subset only.
    pub fn is_records_only(&self) -> bool {
        match self {
            Self::Negative(_) | Self::Bool(_) | Self::Float(_) => true,
            Self::Array(items) => items.iter().any(Self::is_records_only),
            Self::Map(map) => map.values().any(Self::is_records_only),
            Self::Unsigned(_) | Self::Bytes(_) | Self::Text(_) => false,
        }
    }

    /// The text string, or `Malformed`.
    pub fn as_text(&self) -> Result<&str, Malformed> {
        match self {
            Self::Text(value) => Ok(value),
            _ => Err(Malformed),
        }
    }

    /// The array's items, or `Malformed`.
    pub fn as_array(&self) -> Result<&[Value], Malformed> {
        match self {
            Self::Array(items) => Ok(items),
            _ => Err(Malformed),
        }
    }

    /// The map, or `Malformed`.
    pub fn as_map(&self) -> Result<&Map, Malformed> {
        match self {
            Self::Map(map) => Ok(map),
            _ => Err(Malformed),
        }
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<i64> for Value {
    /// An unsigned integer from zero up, a negative one below.
    fn from(value: i64) -> Self {
        match u64::try_from(value) {
            Ok(value) => Self::Unsigned(value),
            // -1 - n = value, so n = !value as two's complement.
            Err(_) => Self::Negative(!value as u64),
        }
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::from(i64::from(value))
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<f64> for Value {
    /// A float. A NaN has no encoding in the records subset: a changeset
    /// that carries one is refused when it is written.
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(value: [u8; N]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Self::Array(items)
    }
}

impl From<Map> for Value {
    fn from(map: Map) -> Self {
        Self::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Encoding.

/// Appends a head of `major` type carrying `value`, in shortest form.
pub fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if let Ok(small) = u8::try_from(value) {
        if small < 24 {
            out.push(major | small);
        } else {
            out.extend_from_slice(&[major | 24, small]);
        }
    } else if let Ok(value) = u16::try_from(value) {
        out.push(major | 25);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(major | 26);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// A length as a head's value. Every length a `Vec` or slice can have fits.
fn length(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// Appends an unsigned integer.
pub fn unsigned(out: &mut Vec<u8>, value: u64) {
    head(out, UNSIGNED, value);
}

/// Appends a byte string.
pub fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, BYTES, length(value.len()));
    out.extend_from_slice(value);
}

/// Appends a text string.
pub fn text(out: &mut Vec<u8>, value: &str) {
    head(out, TEXT, length(value.len()));
    out.extend_from_slice(value.as_bytes());
}

/// Appends the head of an array of `count` items; the items follow.
pub fn array_head(out: &mut Vec<u8>, count: usize) {
    head(out, ARRAY, length(count));
}

/// Appends the head of a map of `count` entries; each key, in ascending
/// order, then its value, follow.
pub fn map_head(out: &mut Vec<u8>, count: usize) {
    head(out, MAP, length(count));
}

// ---------------------------------------------------------------------------
// Decoding.

/// Decodes exactly one deterministic CBOR item filling all of `data`, nested
/// at most [`MAX_DEPTH`] deep.
pub fn decode(data: &[u8]) -> Result<Value, Malformed> {
    decode_with_depth(data, MAX_DEPTH)
}

/// [`decode`] with another nesting limit.
pub fn decode_with_depth(data: &[u8], max_depth: usize) -> Result<Value, Malformed> {
    decode_in(data, max_depth, false)
}

/// [`decode`] in adapter-records.md's records subset, which also holds
/// negative integers, `false`, `true` and binary64 floats that are not a
/// NaN, each with one encoding.
pub fn decode_records(data: &[u8]) -> Result<Value, Malformed> {
    decode_in(data, MAX_DEPTH, true)
}

fn decode_in(data: &[u8], max_depth: usize, records: bool) -> Result<Value, Malformed> {
    let mut reader = Reader::new(data);
    reader.records = records;
    let value = reader.item(0, max_depth)?;
    reader.finish()?;
    // Re-encode and compare: the one accepted encoding.
    if value.encode() != data {
        return Err(Malformed);
    }
    Ok(value)
}

/// Reads deterministic CBOR one item at a time from the front of a slice.
///
/// Every head it reads must be in shortest form with a definite length. A
/// decoder built on it reads a map's keys in the order its document fixes,
/// so the bytes it accepts are the one encoding of what it read; it calls
/// [`finish`](Reader::finish) at the end to refuse trailing bytes.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    /// Whether [`Reader::value`] reads the records subset.
    records: bool,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            records: false,
        }
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }

    /// Whether every byte was read.
    pub fn is_finished(&self) -> bool {
        self.data.is_empty()
    }

    /// `Malformed` if any byte is left after the top-level item.
    pub fn finish(&self) -> Result<(), Malformed> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    /// Takes the next `count` bytes.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Malformed> {
        if self.data.len() < count {
            return Err(Malformed);
        }
        let (taken, rest) = self.data.split_at(count);
        self.data = rest;
        Ok(taken)
    }

    /// The major type of the next item, without reading it.
    pub fn peek_major(&self) -> Option<u8> {
        self.data.first().map(|initial| initial >> 5)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        self.take(N)?.try_into().map_err(|_| Malformed)
    }

    /// Reads one head, of any major type: the major type and the value.
    /// Refuses a head that is not in shortest form, an indefinite length and
    /// the reserved additional information 28 to 30.
    fn any_head(&mut self) -> Result<(u8, u64), Malformed> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let (value, minimum) = match initial & 31 {
            small @ 0..=23 => return Ok((major, u64::from(small))),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.take_array()?), 0x1_0000_0000),
            _ => return Err(Malformed),
        };
        if value < minimum {
            return Err(Malformed);
        }
        Ok((major, value))
    }

    /// Reads one head of the expected major type and returns its value.
    pub fn head(&mut self, major: u8) -> Result<u64, Malformed> {
        match self.any_head()? {
            (found, value) if found == major => Ok(value),
            _ => Err(Malformed),
        }
    }

    /// Reads an unsigned integer.
    pub fn unsigned(&mut self) -> Result<u64, Malformed> {
        self.head(UNSIGNED)
    }

    /// Reads the next map key, which must be `expected`.
    pub fn key(&mut self, expected: u64) -> Result<(), Malformed> {
        if self.unsigned()? != expected {
            return Err(Malformed);
        }
        Ok(())
    }

    /// Whether the next item is the map key `expected`, consuming it if so:
    /// for a key a map may leave out. Anything else is left for the caller.
    pub fn optional_key(&mut self, expected: u64) -> bool {
        let mut probe = self.clone();
        if probe.unsigned() == Ok(expected) {
            self.data = probe.data;
            true
        } else {
            false
        }
    }

    /// The value of a length head as a count, checked against the bytes
    /// left: each of `count × per_item` items takes at least one byte.
    fn count(&mut self, major: u8, per_item: usize) -> Result<usize, Malformed> {
        let count = usize::try_from(self.head(major)?).map_err(|_| Malformed)?;
        match count.checked_mul(per_item) {
            Some(needed) if needed <= self.data.len() => Ok(count),
            _ => Err(Malformed),
        }
    }

    /// Reads a byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8], Malformed> {
        let length = self.count(BYTES, 1)?;
        self.take(length)
    }

    /// Reads a byte string of exactly `N` bytes.
    pub fn byte_array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        self.bytes()?.try_into().map_err(|_| Malformed)
    }

    /// Reads a UTF-8 text string.
    pub fn text(&mut self) -> Result<&'a str, Malformed> {
        let length = self.count(TEXT, 1)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| Malformed)
    }

    /// Reads an array's head and returns its count, after checking that the
    /// bytes left can hold that many items. A caller checks its document's
    /// bound on the count before it allocates for the items.
    pub fn array_len(&mut self) -> Result<usize, Malformed> {
        self.count(ARRAY, 1)
    }

    /// Reads a map's head and returns its count of entries, after checking
    /// that the bytes left can hold that many keys and values.
    pub fn map_len(&mut self) -> Result<usize, Malformed> {
        self.count(MAP, 2)
    }

    /// Reads one whole item of the subset, nested at most [`MAX_DEPTH`]
    /// deep, with its map keys ascending and distinct.
    pub fn value(&mut self) -> Result<Value, Malformed> {
        self.item(0, MAX_DEPTH)
    }

    fn item(&mut self, depth: usize, max_depth: usize) -> Result<Value, Malformed> {
        if depth > max_depth {
            return Err(Malformed);
        }
        // The records subset's simple values and floats, whose heads are
        // not counts.
        if self.records && self.data.first().is_some_and(|b| b >> 5 == 7) {
            return match self.take(1)?[0] {
                FALSE => Ok(Value::Bool(false)),
                TRUE => Ok(Value::Bool(true)),
                FLOAT64 => {
                    let value = f64::from_bits(u64::from_be_bytes(self.take_array()?));
                    if value.is_nan() {
                        return Err(Malformed);
                    }
                    Ok(Value::Float(value))
                }
                _ => Err(Malformed),
            };
        }
        let (major, value) = self.any_head()?;
        let count = || usize::try_from(value).map_err(|_| Malformed);
        match major {
            UNSIGNED => Ok(Value::Unsigned(value)),
            NEGATIVE if self.records => Ok(Value::Negative(value)),
            BYTES => Ok(Value::Bytes(self.take(count()?)?.to_vec())),
            TEXT => {
                let raw = self.take(count()?)?;
                let text = std::str::from_utf8(raw).map_err(|_| Malformed)?;
                Ok(Value::Text(text.to_owned()))
            }
            ARRAY => {
                let count = count()?;
                // Each item takes at least one byte: check before allocating.
                if count > self.data.len() {
                    return Err(Malformed);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth + 1, max_depth)?);
                }
                Ok(Value::Array(items))
            }
            MAP => {
                let count = count()?;
                if count > self.data.len() / 2 {
                    return Err(Malformed);
                }
                let mut map = Map::new();
                let mut last = None;
                for _ in 0..count {
                    if depth + 1 > max_depth {
                        return Err(Malformed);
                    }
                    // Keys are unsigned, ascending and distinct.
                    let key = self.unsigned()?;
                    if last.is_some_and(|last| key <= last) {
                        return Err(Malformed);
                    }
                    last = Some(key);
                    map.insert(key, self.item(depth + 1, max_depth)?);
                }
                Ok(Value::Map(map))
            }
            // Negative integers, tags, floats and simple values.
            _ => Err(Malformed),
        }
    }
}

// ---------------------------------------------------------------------------
// Map keys.

/// What a map does with a key its document does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKeys {
    /// An unknown key is `Malformed`: the rule unless the document says
    /// otherwise.
    Malformed,
    /// The document says an unknown key is ignored.
    Ignored,
}

/// The keys a document allows and requires in one map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRules<'k> {
    /// Keys that must be present.
    pub required: &'k [u64],
    /// Keys that may be present.
    pub optional: &'k [u64],
    /// What an unknown key is.
    pub unknown: UnknownKeys,
}

impl KeyRules<'_> {
    /// Checks that every required key is present and, unless unknown keys
    /// are ignored, that every key present is required or optional.
    pub fn check(&self, map: &Map) -> Result<(), Malformed> {
        if !self.required.iter().all(|key| map.contains_key(key)) {
            return Err(Malformed);
        }
        if self.unknown == UnknownKeys::Malformed
            && !map
                .keys()
                .all(|key| self.required.contains(key) || self.optional.contains(key))
        {
            return Err(Malformed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notation::hex;

    fn enc(value: &Value) -> String {
        hex::encode(value.encode())
    }

    fn dec(text: &str) -> Result<Value, Malformed> {
        decode(&hex::decode(text).unwrap())
    }

    #[test]
    fn heads_are_shortest() {
        for (value, expected) in [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (u64::from(u32::MAX), "1affffffff"),
            (1 << 32, "1b0000000100000000"),
            (u64::MAX, "1bffffffffffffffff"),
        ] {
            assert_eq!(enc(&Value::Unsigned(value)), expected);
            assert_eq!(dec(expected), Ok(Value::Unsigned(value)));
        }
    }

    #[test]
    fn round_trips_the_reference_values() {
        let mut map = Map::new();
        map.insert(0, Value::Unsigned(1));
        map.insert(5, Value::from(&b"a"[..]));
        for value in [
            Value::Unsigned(0),
            Value::Unsigned(1 << 32),
            Value::from(Vec::<u8>::new()),
            Value::from(vec![b'x'; 300]),
            Value::from("é"),
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Array(vec![Value::Unsigned(2)]),
            ]),
            Value::Map(map),
        ] {
            let bytes = value.encode();
            assert_eq!(decode(&bytes), Ok(value));
        }
        assert_eq!(
            enc(&Value::Map(Map::from([
                (5, Value::from(&b"a"[..])),
                (0, Value::Unsigned(1))
            ]))),
            "a20001054161"
        );
    }

    #[test]
    fn refuses_the_reference_encodings() {
        for bad in [
            "1801",       // a non-shortest head
            "190010",     // a non-shortest head
            "a201000000", // keys not ascending
            "9fff",       // an indefinite length
            "20",         // a negative integer
            "0000",       // a trailing byte
            "f5",         // a simple value
            "c000",       // a tag
        ] {
            assert_eq!(dec(bad), Err(Malformed), "{bad}");
        }
    }

    #[test]
    fn refuses_outside_the_subset() {
        for bad in [
            "",                   // nothing
            "18",                 // a truncated head
            "1c",                 // reserved additional information
            "5f",                 // an indefinite byte string
            "bf",                 // an indefinite map
            "f97e00",             // a float
            "62c328",             // invalid UTF-8
            "42ff",               // a byte string longer than the input
            "a10000a0",           // a trailing item
            "a1410000",           // a byte-string key
            "a2010001",           // a map missing a value
            "a200000000",         // a key twice
            "9b0000000100000000", // a count longer than the input
            "bb0000000100000000", // a map count longer than the input
            "7b7fffffffffffffff", // a length beyond the address space
        ] {
            assert_eq!(dec(bad), Err(Malformed), "{bad}");
        }
    }

    #[test]
    fn bounds_nesting() {
        let mut value = Value::Unsigned(0);
        for _ in 0..MAX_DEPTH {
            value = Value::Array(vec![value]);
        }
        let bytes = value.encode();
        assert_eq!(decode(&bytes), Ok(value.clone()));
        let deeper = Value::Array(vec![value]).encode();
        assert_eq!(decode(&deeper), Err(Malformed));
        assert!(decode_with_depth(&deeper, MAX_DEPTH + 1).is_ok());
        // A map's keys and values sit one level down.
        let mut map = Value::Unsigned(0);
        for _ in 0..=MAX_DEPTH {
            map = Value::Map(Map::from([(0, map)]));
        }
        assert_eq!(decode(&map.encode()), Err(Malformed));
        assert_eq!(decode(&[0xa0]), Ok(Value::Map(Map::new())));
    }

    /// The fuzz target's property over every input of up to two bytes: what
    /// decode accepts is the encoding of what it returns, and the reader
    /// agrees with it.
    #[test]
    fn accepts_one_encoding_of_every_short_input() {
        let mut inputs = vec![vec![]];
        inputs.extend((0..=255u8).map(|a| vec![a]));
        inputs.extend((0..=0xffffu16).map(|ab| ab.to_be_bytes().to_vec()));
        let mut accepted = 0;
        for data in inputs {
            let decoded = decode(&data);
            if let Ok(value) = &decoded {
                assert_eq!(value.encode(), data);
                accepted += 1;
            }
            let mut reader = Reader::new(&data);
            let streamed = reader.value();
            if reader.is_finished() {
                assert_eq!(streamed, decoded, "{data:?}");
            }
        }
        // 0x00..=0x17, 0x18 0x18..=0xff, 0x40, 0x60, 0x80, 0xa0, 0x41 x,
        // 0x61 x for ASCII x, and 0x81 then a one-byte item.
        assert_eq!(accepted, 24 + 232 + 4 + 256 + 128 + 24 + 4);
    }

    #[test]
    fn reader_reads_fixed_shapes() {
        // {1: 7, 3: h'0102', 4: "hi", 5: [1, 2]}
        let data = hex::decode("a40107034201020462686905820102").unwrap();
        let mut reader = Reader::new(&data);
        assert_eq!(reader.map_len(), Ok(4));
        reader.key(1).unwrap();
        assert_eq!(reader.unsigned(), Ok(7));
        assert!(!reader.optional_key(2));
        assert!(reader.optional_key(3));
        assert_eq!(reader.byte_array::<2>(), Ok([1, 2]));
        reader.key(4).unwrap();
        assert_eq!(reader.text(), Ok("hi"));
        reader.key(5).unwrap();
        assert_eq!(reader.peek_major(), Some(ARRAY));
        assert_eq!(
            reader.value(),
            Ok(Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]))
        );
        assert_eq!(reader.finish(), Ok(()));

        let mut short = Reader::new(&[0x83, 0x01]);
        assert_eq!(short.array_len(), Err(Malformed));
        let mut wrong = Reader::new(&[0x41, 0x00]);
        assert_eq!(wrong.unsigned(), Err(Malformed));
        let mut trailing = Reader::new(&[0x01, 0x02]);
        assert_eq!(trailing.unsigned(), Ok(1));
        assert_eq!(trailing.finish(), Err(Malformed));
    }

    #[test]
    fn key_rules() {
        let map = Map::from([
            (1, Value::Unsigned(1)),
            (3, Value::Unsigned(3)),
            (9, Value::Unsigned(9)),
        ]);
        let strict = KeyRules {
            required: &[1, 3],
            optional: &[9],
            unknown: UnknownKeys::Malformed,
        };
        assert_eq!(strict.check(&map), Ok(()));
        let missing = KeyRules {
            required: &[1, 2],
            ..strict
        };
        assert_eq!(missing.check(&map), Err(Malformed));
        let narrower = KeyRules {
            optional: &[],
            ..strict
        };
        assert_eq!(narrower.check(&map), Err(Malformed));
        let ignoring = KeyRules {
            unknown: UnknownKeys::Ignored,
            ..narrower
        };
        assert_eq!(ignoring.check(&map), Ok(()));
    }

    #[test]
    fn accessors() {
        let value = Value::from([1u8, 2, 3]);
        assert_eq!(value.as_byte_array::<3>(), Ok([1, 2, 3]));
        assert_eq!(value.as_byte_array::<2>(), Err(Malformed));
        assert_eq!(value.as_unsigned(), Err(Malformed));
        assert_eq!(Value::from(4u64).as_unsigned(), Ok(4));
        assert_eq!(Value::from("x").as_text(), Ok("x"));
        assert!(Value::from(Map::new()).as_map().is_ok());
        assert!(Value::from(Vec::<Value>::new()).as_array().is_ok());
        assert_eq!(Value::from(String::from("x")).major(), TEXT);
    }
}
