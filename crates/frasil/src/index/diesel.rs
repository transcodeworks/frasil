//! Typed Diesel queries over the cache (feature `index-diesel`). Each derived
//! table also has a Diesel `table!` module named after it, with the
//! built-in columns first: `i64` and [`Time`](crate::index::Time) are `BigInt`,
//! `f64` is `Double`, `bool` is `Bool`, `String`, [`Ref`](crate::index::Ref)
//! and [`RichText`](crate::index::RichText) are `Text`, `Vec<u8>` is `Binary`,
//! and `Option` is `Nullable`. The crate that derives a table depends on
//! `diesel` itself, at the version `frasil` uses.

use crate::index::cache::Index;
use crate::index::error::{Error, Result};
use ::diesel::{Connection, RunQueryDsl, SqliteConnection};

impl Index {
    /// Runs `f` with a Diesel connection to the cache: opened read-only,
    /// under the cache's key, with `query_only` on, so that every write
    /// fails. The connection is made on first use and kept.
    ///
    /// # Errors
    ///
    /// [`Error::Sql`] when the connection does not open.
    pub fn diesel<R>(&self, f: impl FnOnce(&mut SqliteConnection) -> R) -> Result<R> {
        let mut slot = self
            .inner_diesel()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            let store = self.store();
            let mut connection = SqliteConnection::establish(&store.location.diesel_url())
                .map_err(|error| Error::Sql(error.to_string()))?;
            let setup = |c: &mut SqliteConnection| -> ::diesel::QueryResult<()> {
                ::diesel::sql_query(store.key.as_str()).execute(c)?;
                ::diesel::sql_query("PRAGMA query_only = ON").execute(c)?;
                ::diesel::sql_query("SELECT count(*) FROM sqlite_master").execute(c)?;
                Ok(())
            };
            setup(&mut connection).map_err(|error| Error::Sql(error.to_string()))?;
            *slot = Some(connection);
        }
        Ok(f(slot.as_mut().expect("the connection is made")))
    }
}
