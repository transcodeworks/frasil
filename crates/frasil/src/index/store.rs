//! The SQLite file: encrypted at rest, written by the index alone, read
//! through a connection that refuses writes.
//!
//! Native targets build SQLite as SQLCipher, and wasm32 builds it as
//! SQLite3 Multiple Ciphers in its SQLCipher scheme; both take the same
//! raw 256-bit key (`PRAGMA key = "x'…'"`), so no password hashing runs.
//! Frasil derives the key under the index's application purpose.

use crate::index::error::{Error, Result};
use crate::index::sql::{Row, SqlValue};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// Where the file is.
pub(crate) enum Location {
    /// A file on disk.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    File(std::path::PathBuf),
    /// A file in the browser's origin-private file system, through the
    /// OPFS SyncAccessHandle pool VFS.
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    Opfs {
        /// The file's name in the pool.
        name: String,
        /// The name of the pool's VFS under SQLite3 Multiple Ciphers.
        vfs: String,
        /// The pool.
        pool: sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil,
    },
}

/// The name SQLite3 Multiple Ciphers gives its encrypting layer over the
/// VFS called `pool`.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn cipher_vfs(pool: &str) -> String {
    format!("multipleciphers-{pool}")
}

impl Location {
    fn open(&self, flags: OpenFlags) -> rusqlite::Result<Connection> {
        match self {
            #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
            Self::File(path) => Connection::open_with_flags(path, flags),
            #[cfg(all(target_family = "wasm", target_os = "unknown"))]
            Self::Opfs { name, vfs, .. } => {
                Connection::open_with_flags_and_vfs(name, flags, vfs.as_str())
            }
        }
    }

    /// Deletes the file: the cache is rebuilt from the replicas.
    fn delete(&self) -> Result<()> {
        match self {
            #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
            Self::File(path) => {
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    let mut name = path.clone().into_os_string();
                    name.push(suffix);
                    match std::fs::remove_file(&name) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(Error::Sql(error.to_string())),
                    }
                }
                Ok(())
            }
            #[cfg(all(target_family = "wasm", target_os = "unknown"))]
            Self::Opfs { name, pool, .. } => {
                use sqlite_wasm_rs::vfs::VfsFilesManager;
                pool.remove(name)
                    .map(drop)
                    .map_err(|error| Error::Sql(format!("{error:?}")))
            }
        }
    }

    /// The file as a Diesel URL, read-only.
    #[cfg(feature = "index-diesel")]
    pub(crate) fn diesel_url(&self) -> String {
        match self {
            #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
            Self::File(path) => format!("file:{}?mode=ro", uri_path(&path.to_string_lossy())),
            #[cfg(all(target_family = "wasm", target_os = "unknown"))]
            Self::Opfs { name, vfs, .. } => {
                format!("file:{}?mode=ro&vfs={vfs}", uri_path(name))
            }
        }
    }
}

/// A path within a `file:` URI: `%`, `?` and `#` escaped.
#[cfg(feature = "index-diesel")]
fn uri_path(path: &str) -> String {
    path.replace('%', "%25")
        .replace('?', "%3f")
        .replace('#', "%23")
}

/// Formats Frasil's derived application key for SQLCipher.
pub(crate) fn key_pragma(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "PRAGMA key = \"x'{}'\";",
        Zeroizing::new(crate::index::column::hex(key)).as_str()
    ))
}

/// The two connections.
pub(crate) struct Store {
    pub(crate) location: Location,
    pub(crate) key: Zeroizing<String>,
    writer: Mutex<Connection>,
    reader: Mutex<Connection>,
    /// The tables the statement being prepared on the reader reads.
    reads: Arc<Mutex<BTreeSet<String>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Store {
    /// Opens the file, or makes it. A file that does not open under the
    /// key, or is no database, is deleted and made again: it is a cache.
    pub(crate) fn open(location: Location, key: Zeroizing<String>) -> Result<Self> {
        let writer = match open_writer(&location, &key) {
            Ok(writer) => writer,
            Err(_) => {
                location.delete()?;
                open_writer(&location, &key)?
            }
        };
        let reads = Arc::new(Mutex::new(BTreeSet::new()));
        let reader = open_reader(&location, &key, reads.clone())?;
        Ok(Self {
            location,
            key,
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            reads,
        })
    }

    /// Opens the reading connection again, after the schema changed: a
    /// statement it prepared before would expand `*` to the old columns.
    pub(crate) fn reopen_reader(&self) -> Result<()> {
        let reader = open_reader(&self.location, &self.key, self.reads.clone())?;
        *lock(&self.reader) = reader;
        Ok(())
    }

    /// Checkpoints the write-ahead log into the file and truncates it, so
    /// that its frames, which may hold rows deleted since, leave the file
    /// system's view of the cache. The browser's journal is no write-ahead
    /// log, and `secure_delete` already overwrote the rows there.
    pub(crate) fn scrub(&self) -> Result<()> {
        #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
        lock(&self.writer).query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    /// Runs `f` on the writing connection.
    pub(crate) fn write<R>(&self, f: impl FnOnce(&mut Connection) -> Result<R>) -> Result<R> {
        f(&mut lock(&self.writer))
    }

    /// The tables a query reads, as the reading connection prepares it.
    pub(crate) fn reads(&self, sql: &str) -> Result<BTreeSet<String>> {
        let reader = lock(&self.reader);
        lock(&self.reads).clear();
        let prepared = reader.prepare(sql);
        let tables = std::mem::take(&mut *lock(&self.reads));
        if !prepared?.readonly() {
            return Err(Error::Sql("the query connection only reads".into()));
        }
        Ok(tables)
    }

    /// Runs a query on the reading connection: its rows, and the tables it
    /// reads.
    pub(crate) fn query(
        &self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<(Vec<Row>, BTreeSet<String>)> {
        let reader = lock(&self.reader);
        lock(&self.reads).clear();
        let prepared = reader.prepare(sql);
        let tables = std::mem::take(&mut *lock(&self.reads));
        let mut statement = prepared?;
        if !statement.readonly() {
            return Err(Error::Sql("the query connection only reads".into()));
        }
        let columns: Arc<[String]> = statement.column_names().map(str::to_owned).collect();
        let width = columns.len();
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let values = (0..width)
                .map(|i| row.get_ref(i).map(SqlValue::of))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out.push(Row::new(columns.clone(), values));
        }
        Ok((out, tables))
    }
}

fn keyed(location: &Location, flags: OpenFlags, key: &str) -> Result<Connection> {
    let connection = location.open(flags)?;
    connection.execute_batch(key)?;
    // The first read checks the key: a wrong one reads no database.
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    Ok(connection)
}

fn open_writer(location: &Location, key: &str) -> Result<Connection> {
    let connection = keyed(
        location,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        key,
    )?;
    // Readers alongside the writer, where the platform has shared memory;
    // the browser's pool VFS has none and keeps its default journal.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    connection.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
    // A cache: a commit lost to a power cut is read again from the
    // replicas.
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    // A deleted row's bytes are overwritten, not left in free pages.
    connection.pragma_update(None, "secure_delete", true)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS \"_meta\" (\"name\" TEXT PRIMARY KEY NOT NULL, \"value\" TEXT NOT NULL);",
    )?;
    Ok(connection)
}

/// The reading connection: opened read-only, `query_only`, and with an
/// authorizer that allows reads alone and records the tables each
/// statement reads.
fn open_reader(
    location: &Location,
    key: &str,
    reads: Arc<Mutex<BTreeSet<String>>>,
) -> Result<Connection> {
    let mut connection = keyed(
        location,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        key,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    connection.authorizer(Some(move |context: AuthContext<'_>| match context.action {
        AuthAction::Read { table_name, .. } => {
            lock(&reads).insert(table_name.to_owned());
            Authorization::Allow
        }
        AuthAction::Select | AuthAction::Function { .. } | AuthAction::Recursive => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }))?;
    Ok(connection)
}
