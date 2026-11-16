//! Column types: how a field's value is a Records cell, and how the cache
//! holds it in SQL.
//!
//! Records cells are CBOR values with unsigned integers, byte strings,
//! text, arrays and maps. A column type maps onto them so that every
//! writer, in any language, reads the same:
//!
//! | Type | Cell | SQL |
//! | --- | --- | --- |
//! | `i64` | native signed integer | `INTEGER` |
//! | `f64` | native binary64 float | `REAL` |
//! | `bool` | native boolean | `INTEGER` 0 or 1 |
//! | `String` | text | `TEXT` |
//! | `Vec<u8>` | bytes | `BLOB` |
//! | [`Time`] | as `i64`, milliseconds since 1970-01-01T00:00:00Z | `INTEGER` |
//! | [`Ref<T>`] | the row key's bytes | `TEXT`, the key in lowercase hexadecimal |
//! | [`RichText`] | a Loro document's stream ID, 16 bytes | `TEXT`, the document's plain text |
//! | `Option<C>` | `C`'s cell, or no cell | `C`'s, or `NULL` |

use crate::index::error::{Error, Result};
use crate::index::sql::SqlValue;
use crate::{StreamId, Value};
use serde::Serialize;
use std::marker::PhantomData;

/// What a column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ColumnKind {
    /// A signed 64-bit integer.
    Integer,
    /// A 64-bit float.
    Real,
    /// A boolean.
    Bool,
    /// UTF-8 text.
    Text,
    /// Bytes.
    Bytes,
    /// A time, in milliseconds since the Unix epoch.
    Time,
    /// A row key of another table.
    Ref,
    /// A Loro document of the row's space, cached as its plain text.
    RichText,
}

impl ColumnKind {
    /// The column's SQLite type.
    pub const fn sql_type(self) -> &'static str {
        match self {
            Self::Integer | Self::Bool | Self::Time => "INTEGER",
            Self::Real => "REAL",
            Self::Text | Self::Ref | Self::RichText => "TEXT",
            Self::Bytes => "BLOB",
        }
    }

    /// A cell as this column holds it in SQL; `None` when it does not read
    /// as this kind. A rich-text cell reads as its document's ID, which the
    /// index replaces with the document's text.
    pub fn to_sql(self, cell: &Value) -> Option<SqlValue> {
        Some(match self {
            Self::Integer | Self::Time => SqlValue::Integer(int_of(cell)?),
            Self::Real => SqlValue::Real(real_of(cell)?),
            Self::Bool => SqlValue::Integer(i64::from(bool_of(cell)?)),
            Self::Text => match cell {
                Value::Text(text) => SqlValue::Text(text.clone()),
                _ => return None,
            },
            Self::Bytes => match cell {
                Value::Bytes(bytes) => SqlValue::Blob(bytes.clone()),
                _ => return None,
            },
            Self::Ref => match cell {
                Value::Bytes(bytes) => SqlValue::Text(hex(bytes)),
                _ => return None,
            },
            Self::RichText => match cell {
                Value::Bytes(bytes) if bytes.len() == 16 => SqlValue::Text(hex(bytes)),
                _ => return None,
            },
        })
    }
}

/// What a write does to one cell.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// Sets it.
    Set(Value),
    /// Clears it.
    Clear,
    /// Leaves it as it is.
    Keep,
}

/// A type a table's field may have: its kind, its cell and its SQL value.
/// The types in this module's table implement it.
pub trait Column: Sized {
    /// What the column holds.
    const KIND: ColumnKind;
    /// Whether it may be absent: `Option<C>`.
    const NULLABLE: bool = false;
    /// The table its keys name, for a [`Ref`].
    const REFERENCES: Option<&'static str> = None;

    /// The value as a cell.
    fn to_cell(&self) -> Cell;

    /// The value from the cache's SQL value.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] when the SQL value is not of this type.
    fn from_sql(value: &SqlValue) -> Result<Self>;
}

fn mismatch(expected: &'static str) -> Error {
    Error::Decode {
        table: String::new(),
        column: String::new(),
        expected,
    }
}

impl Column for i64 {
    const KIND: ColumnKind = ColumnKind::Integer;

    fn to_cell(&self) -> Cell {
        Cell::Set(int_cell(*self))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Integer(n) => Ok(*n),
            _ => Err(mismatch("an integer")),
        }
    }
}

impl Column for f64 {
    const KIND: ColumnKind = ColumnKind::Real;

    fn to_cell(&self) -> Cell {
        Cell::Set(Value::from(*self))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Real(x) => Ok(*x),
            SqlValue::Integer(n) => Ok(*n as f64),
            _ => Err(mismatch("a number")),
        }
    }
}

impl Column for bool {
    const KIND: ColumnKind = ColumnKind::Bool;

    fn to_cell(&self) -> Cell {
        Cell::Set(Value::from(*self))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Integer(0) => Ok(false),
            SqlValue::Integer(1) => Ok(true),
            _ => Err(mismatch("0 or 1")),
        }
    }
}

impl Column for String {
    const KIND: ColumnKind = ColumnKind::Text;

    fn to_cell(&self) -> Cell {
        Cell::Set(Value::Text(self.clone()))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Text(text) => Ok(text.clone()),
            _ => Err(mismatch("text")),
        }
    }
}

impl Column for Vec<u8> {
    const KIND: ColumnKind = ColumnKind::Bytes;

    fn to_cell(&self) -> Cell {
        Cell::Set(Value::Bytes(self.clone()))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Blob(bytes) => Ok(bytes.clone()),
            _ => Err(mismatch("bytes")),
        }
    }
}

impl<C: Column> Column for Option<C> {
    const KIND: ColumnKind = C::KIND;
    const NULLABLE: bool = true;
    const REFERENCES: Option<&'static str> = C::REFERENCES;

    fn to_cell(&self) -> Cell {
        match self {
            Some(value) => value.to_cell(),
            None => Cell::Clear,
        }
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Null => Ok(None),
            value => C::from_sql(value).map(Some),
        }
    }
}

/// A time: milliseconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(i64);

impl Time {
    /// The time this many milliseconds after the Unix epoch.
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Now, by this device's wall clock.
    pub fn now() -> Self {
        Self(crate::index::platform::now_millis())
    }
}

impl Column for Time {
    const KIND: ColumnKind = ColumnKind::Time;

    fn to_cell(&self) -> Cell {
        Cell::Set(int_cell(self.0))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        i64::from_sql(value).map(Self)
    }
}

/// The key of a row of table `T`. Keys are random and global, so a
/// reference names its row whichever space holds it, and joins work across
/// spaces. The keys [`Writer::insert`](crate::index::Writer::insert) makes are 16
/// random bytes.
pub struct Ref<T> {
    key: Vec<u8>,
    table: PhantomData<fn() -> T>,
}

impl<T> Ref<T> {
    /// The reference of a row key.
    pub fn from_key(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            table: PhantomData,
        }
    }

    /// A new random key.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    pub fn random() -> Result<Self> {
        let mut key = [0u8; 16];
        getrandom::fill(&mut key).map_err(|_| Error::NoRandomness)?;
        Ok(Self::from_key(key.to_vec()))
    }

    /// The reference of a key in lowercase hexadecimal, as SQL holds it.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] when it is not hexadecimal.
    pub fn from_hex(text: &str) -> Result<Self> {
        unhex(text)
            .map(Self::from_key)
            .ok_or_else(|| mismatch("a key in hexadecimal"))
    }

    /// The key's bytes.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The key in lowercase hexadecimal, as SQL holds it.
    pub fn hex(&self) -> String {
        hex(&self.key)
    }
}

impl<T> Clone for Ref<T> {
    fn clone(&self) -> Self {
        Self::from_key(self.key.clone())
    }
}

impl<T> PartialEq for Ref<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<T> Eq for Ref<T> {}

impl<T> PartialOrd for Ref<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Ref<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

impl<T> core::hash::Hash for Ref<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl<T> core::fmt::Debug for Ref<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ref({})", self.hex())
    }
}

impl<T> core::fmt::Display for Ref<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl<T: crate::index::Table> Column for Ref<T> {
    const KIND: ColumnKind = ColumnKind::Ref;
    const REFERENCES: Option<&'static str> = Some(T::SCHEMA.name);

    fn to_cell(&self) -> Cell {
        Cell::Set(Value::Bytes(self.key.clone()))
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Text(text) => Self::from_hex(text),
            _ => Err(mismatch("a key in hexadecimal")),
        }
    }
}

/// Rich text: a Loro document of the row's space, which the cache holds as
/// the plain text of its [`RichText::CONTAINER`] text container. A value
/// read back from the cache holds that text and no document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichText {
    document: Option<StreamId>,
    text: String,
}

impl RichText {
    /// The document's text container that the cache reads.
    pub const CONTAINER: &'static str = "text";

    /// Rich text in this document.
    pub fn new(document: StreamId) -> Self {
        Self {
            document: Some(document),
            text: String::new(),
        }
    }

    /// The document, when the value names one.
    pub fn document(&self) -> Option<StreamId> {
        self.document
    }

    /// The plain text, as the cache holds it.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl Column for RichText {
    const KIND: ColumnKind = ColumnKind::RichText;

    /// The document's ID; a value read from the cache, which names no
    /// document, leaves the cell as it is.
    fn to_cell(&self) -> Cell {
        match self.document {
            Some(document) => Cell::Set(Value::Bytes(document.as_bytes().to_vec())),
            None => Cell::Keep,
        }
    }

    fn from_sql(value: &SqlValue) -> Result<Self> {
        match value {
            SqlValue::Text(text) => Ok(Self {
                document: None,
                text: text.clone(),
            }),
            _ => Err(mismatch("text")),
        }
    }
}

/// An integer's cell.
pub(crate) fn int_cell(n: i64) -> Value {
    Value::from(n)
}

/// An integer cell's value.
pub(crate) fn int_of(cell: &Value) -> Option<i64> {
    match cell {
        Value::Unsigned(_) | Value::Negative(_) => cell.as_i64().ok(),
        _ => None,
    }
}

fn real_of(cell: &Value) -> Option<f64> {
    match cell {
        Value::Float(value) => Some(*value),
        _ => None,
    }
}

fn bool_of(cell: &Value) -> Option<bool> {
    match cell {
        Value::Bool(value) => Some(*value),
        _ => None,
    }
}

/// Bytes in lowercase hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hexadecimal's bytes.
pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_through_cells() {
        for n in [0, 1, -1, 42, -42, i64::MAX, i64::MIN] {
            assert_eq!(int_of(&int_cell(n)), Some(n), "{n}");
        }
        assert_eq!(int_cell(-1), Value::Negative(0));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&bytes), "0001abff");
        assert_eq!(unhex("0001abff").as_deref(), Some(&bytes[..]));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }
}

#[cfg(test)]
mod scalar_tests {
    use super::*;
    #[test]
    fn scalar_decoders_accept_native_values_only() {
        assert_eq!(int_of(&Value::from(-17i64)), Some(-17));
        assert_eq!(real_of(&Value::Float(1.5)), Some(1.5));
        assert_eq!(bool_of(&Value::Bool(true)), Some(true));
        assert_eq!(int_of(&Value::Array(vec![Value::Unsigned(16)])), None);
        assert_eq!(real_of(&Value::Bytes(1.5f64.to_be_bytes().to_vec())), None);
        assert_eq!(bool_of(&Value::Unsigned(1)), None);
    }
}
