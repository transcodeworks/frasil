//! What `#[derive(Table)]` implements.

use crate::index::column::Cell;
use crate::index::error::Result;
use crate::index::schema::TableSchema;
use crate::index::sql::Row;

/// A struct that is one table of the index. Derive it with
/// `#[derive(Table)]`.
pub trait Table: Sized + 'static {
    /// The table's schema.
    const SCHEMA: TableSchema;

    /// The row's cells, by column, for a Records write.
    fn cells(&self) -> Vec<(&'static str, Cell)>;

    /// The struct from a row of the cache.
    ///
    /// # Errors
    ///
    /// [`Error::NoColumn`](crate::index::Error::NoColumn) or
    /// [`Error::Decode`](crate::index::Error::Decode) when the row is not one of
    /// this table.
    fn from_row(row: &Row) -> Result<Self>;
}
