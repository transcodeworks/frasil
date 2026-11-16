//! Values and rows as queries return them.

use crate::index::error::{Error, Result};
use serde::Serialize;
use std::sync::Arc;

/// A SQLite value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SqlValue {
    /// `NULL`.
    Null,
    /// An integer.
    Integer(i64),
    /// A float.
    Real(f64),
    /// Text.
    Text(String),
    /// A blob.
    Blob(Vec<u8>),
}

impl From<i64> for SqlValue {
    fn from(n: i64) -> Self {
        Self::Integer(n)
    }
}

impl From<f64> for SqlValue {
    fn from(x: f64) -> Self {
        Self::Real(x)
    }
}

impl From<bool> for SqlValue {
    fn from(b: bool) -> Self {
        Self::Integer(i64::from(b))
    }
}

impl From<&str> for SqlValue {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for SqlValue {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<Vec<u8>> for SqlValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Blob(bytes)
    }
}

impl From<crate::index::Time> for SqlValue {
    fn from(time: crate::index::Time) -> Self {
        Self::Integer(time.as_millis())
    }
}

impl<T> From<&crate::index::Ref<T>> for SqlValue {
    fn from(key: &crate::index::Ref<T>) -> Self {
        Self::Text(key.hex())
    }
}

impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

impl rusqlite::ToSql for SqlValue {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        Ok(ToSqlOutput::Borrowed(match self {
            Self::Null => ValueRef::Null,
            Self::Integer(n) => ValueRef::Integer(*n),
            Self::Real(x) => ValueRef::Real(*x),
            Self::Text(text) => ValueRef::Text(text.as_bytes()),
            Self::Blob(bytes) => ValueRef::Blob(bytes),
        }))
    }
}

impl SqlValue {
    pub(crate) fn of(value: rusqlite::types::ValueRef<'_>) -> Self {
        use rusqlite::types::ValueRef;
        match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(n) => Self::Integer(n),
            ValueRef::Real(x) => Self::Real(x),
            ValueRef::Text(text) => Self::Text(String::from_utf8_lossy(text).into_owned()),
            ValueRef::Blob(bytes) => Self::Blob(bytes.to_vec()),
        }
    }
}

/// One row of a query's result.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    columns: Arc<[String]>,
    values: Vec<SqlValue>,
}

impl Row {
    pub(crate) fn new(columns: Arc<[String]>, values: Vec<SqlValue>) -> Self {
        Self { columns, values }
    }

    /// The value of a column, by name.
    ///
    /// # Errors
    ///
    /// [`Error::NoColumn`] when the result has none of this name.
    pub fn get(&self, column: &str) -> Result<&SqlValue> {
        self.columns
            .iter()
            .position(|c| c == column)
            .map(|i| &self.values[i])
            .ok_or_else(|| Error::NoColumn(column.to_owned()))
    }

    /// The columns' names, in the result's order.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// The values, in the result's order.
    pub fn values(&self) -> &[SqlValue] {
        &self.values
    }
}

impl Serialize for Row {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (column, value) in self.columns.iter().zip(&self.values) {
            map.serialize_entry(column, value)?;
        }
        map.end()
    }
}
