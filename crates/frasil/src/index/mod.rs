//! The index (feature `index`): a typed, local SQLite cache over many
//! spaces.
//!
//! An application describes its tables as plain structs. Each names the
//! kind of space that feeds it; every space of that kind this device can
//! read puts its rows in the table, and joins work across spaces because
//! row keys are random and global. The cache is a rebuildable copy of the
//! device's replicas: the application writes through Records, and queries
//! the cache with SQL, typed rows, live queries or Diesel.
//!
//! ```ignore
//! use frasil::index::{Index, Ref, Schema, Table, Time, Writer, create_space};
//!
//! #[derive(Table)]
//! #[table(source = "shared")]
//! struct List { title: String }
//!
//! #[derive(Table)]
//! #[table(source = "personal")]
//! struct Item { list: Ref<List>, at: Time, done: bool, note: Option<String> }
//!
//! let schema = Schema::new().table::<List>().table::<Item>();
//! let index = Index::open(&device, dir.join("index.db"), schema).await?;
//! let shared = create_space(&device, "shared").await?;
//! let list = shared.insert(&List { title: "Errands".into() }).await?;
//! let mine = create_space(&device, "personal").await?;
//! mine.insert(&Item { list, at: Time::now(), done: false, note: None }).await?;
//! index.sync().await?;
//! let rows = index.query(
//!     "SELECT l.title, count(*) AS n FROM item i JOIN list l ON l._key = i.list GROUP BY l._key",
//!     &[],
//! )?;
//! ```
//!
//! # Tables
//!
//! `#[derive(Table)]` makes a struct one table: its typed Records writes
//! ([`Writer`]), its SQLite DDL ([`TableSchema::ddl`]), a Diesel `table!`
//! with the `index-diesel` feature, and its part of the JSON manifest
//! ([`Schema::manifest`]) from which another language reads the same
//! schema. The [`column`](mod@column) module says how each field type is a Records
//! cell and a SQL value.
//!
//! Every table has the built-in columns `_space` (the space's ID),
//! `_key` (the row's key, in hexadecimal), `_author` (the person, or
//! device, that last changed the row) and `_changed_at` (when, by the
//! writer's clock, in milliseconds). A table that holds suggestions, with
//! `#[table(suggestions)]`, also has `_suggested` (1 for a row as an open
//! suggestion would make it) and `_suggestion` (that suggestion's ID, empty
//! for merged rows). The `_spaces` table lists each space that feeds the
//! index: `id`, `kind`, `synced_at` and `owner`, the person or device that
//! made it.
//!
//! # Sources
//!
//! A space's kind is set when it is made, with [`create_space`], and kept
//! in its descriptor. A space with no kind feeds nothing. A space this
//! device no longer reads, or no longer holds, leaves every table.
//!
//! # The cache
//!
//! The index alone writes the cache. [`Index::query`] runs on a connection
//! opened read-only, with `query_only` on and an authorizer that allows
//! reads alone, so a write fails rather than drifting from the replicas.
//! [`Index::watch`] runs a query again each time the index changes a table
//! it reads, the authorizer also recording which tables those are;
//! [`Watch::distinct`] gives its rows only when they differ from the last.
//! [`Index::table_changes`] names each table as the index changes it.
//!
//! [`Index::refresh`] updates one space, while [`Index::sync`] scans all held
//! spaces. [`Index::try_refresh`] skips immediately if another refresh is busy;
//! a caller using it must retry or run [`Index::follow`] to finish projection.
//!
//! The file is encrypted at rest under a key derived from the device's
//! application key, using `Device::derive_key`: SQLCipher on native targets, SQLite3 Multiple Ciphers in its
//! SQLCipher scheme on wasm32. The schema's version is a hash of its
//! manifest; a cache of another version, or one that does not open under
//! the key, is rebuilt from the device's replicas, with no network.
//!
//! # Limits
//!
//! - A space counts as readable while this device is a member of it at some
//!   level ([`crate::Space::level`]). A device that a space removed keeps
//!   its level until its replica learns of the removal, so its rows stay
//!   until then; a space it no longer holds leaves at the next
//!   [`Index::sync`].
//! - [`Index::refresh`] and [`Index::sync`] read a whole space again, rows
//!   and history, and write a table only when its rows differ.
//!   [`Index::follow`] refreshes only the rows a Records write touched, and
//!   a whole space after any other change of it: who may read it, a
//!   snapshot, or a document that a rich text column shows.
//! - `_changed_at` comes from `Records::last_change`: the writer's claimed
//!   wall time, with second precision expressed in milliseconds. It is not
//!   verified, and old changes without a time remain unknown.
//!
//! # Platforms
//!
//! Native targets (macOS, iOS, Android, Linux, Windows) open the cache in a
//! file with [`Index::open`]. Apple targets build SQLCipher on
//! CommonCrypto; the others need the `index-vendored-openssl` feature, or an
//! OpenSSL that `OPENSSL_DIR` names. On wasm32-unknown-unknown,
//! `Index::open_in_browser` keeps it in the origin-private file system
//! through the OPFS SyncAccessHandle pool VFS, in a dedicated worker.
//!
//! # Features
//!
//! - `index`: this module.
//! - `index-diesel`: a Diesel `table!` per table, and `Index::diesel`.
//! - `index-vendored-openssl`: SQLCipher's crypto from a vendored OpenSSL,
//!   on native targets only; wasm32 does not build with it.
//!
//! The derive macro comes from `frasil-index-derive`, an internal crate
//! that `frasil` re-exports here as [`Table`](macro@Table); depend on
//! `frasil` alone.

mod cache;
pub mod column;
#[cfg(feature = "index-diesel")]
pub mod diesel;
mod error;
mod platform;
mod schema;
mod sql;
mod store;
mod table;
mod watch;
mod write;

pub use crate::Value;
pub use cache::{Dangling, Index, Stored};
pub use column::{Cell, Column, ColumnKind, Ref, RichText, Time};
pub use error::{Error, Result};
/// `#[derive(Table)]`: see [`Table`] and the crate's documentation.
pub use frasil_index_derive::Table;
pub use schema::{BUILT_IN, ColumnSchema, SPACES_TABLE, Schema, TableSchema};
pub use sql::{Row, SqlValue};
pub use table::Table;
pub use watch::{TableChanges, Watch};
pub use write::{Batch, Writer, create_space};
