//! A [`Store`] in a SQLite database (feature `sqlite`): the only part of the
//! crate that does IO.
//!
//! The database is in WAL mode with `synchronous=FULL` and full fsyncs, so
//! a commit is durable when it returns, and SQLite's recovery discards an
//! incomplete transaction when the database is opened again. The filesystem
//! must honour its fsync calls: use a local filesystem, not a network one.
//! A database that is only a working copy of records kept elsewhere opens
//! with [`Durability::Cache`] instead: `synchronous=NORMAL`, so a crash may
//! lose its last commits, never its consistency.
//!
//! One connection writes. [`Store::commit_all`] makes a batch of commits in
//! one of its transactions, so the writers of a batch share one fsync. Reads
//! of a database in a file take connections of their own, read-only, from a
//! small pool: in WAL mode a reader sees every transaction committed before
//! its statement began, and neither waits for the writer nor holds it up. A
//! database in memory reads on its one connection.
//!
//! One table holds every record, by address, `WITHOUT ROWID`, so a scan of a
//! prefix is one range of the primary key in address order (SQLite compares
//! blobs bytewise).
//!
//! The futures do their blocking work when first polled. Run them outside
//! an async executor's threads, or on a thread of their own.

use crate::store::{BoxFuture, Commit, Records, Store, StoreError};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// The schema's version, SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 1;

/// The read-only connections of a database in a file.
pub const READERS: usize = 4;

/// How durable a commit is when it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    /// `synchronous=FULL` with full fsyncs: the database is the copy of
    /// record.
    #[default]
    Full,
    /// `synchronous=NORMAL`: the database is a working copy, and a crash may
    /// lose the commits since the last checkpoint's sync.
    Cache,
}

/// A [`Store`] in a SQLite database.
#[derive(Debug)]
pub struct SqliteStore {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    next: AtomicUsize,
}

fn failed(error: rusqlite::Error) -> StoreError {
    StoreError::new(format!("sqlite: {error}"))
}

/// The first byte string after every string that starts with `prefix`, or
/// `None` if there is none (an empty prefix, or one of 0xff bytes only).
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

fn lock(connection: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    connection.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Makes one commit inside a transaction: `false`, and nothing written, if
/// an expectation does not hold.
fn apply(transaction: &Transaction<'_>, commit: &Commit) -> rusqlite::Result<bool> {
    for (address, expected) in &commit.expect {
        let held: Option<Vec<u8>> = transaction
            .prepare_cached("SELECT record FROM records WHERE address = ?1")?
            .query_row(params![address], |row| row.get(0))
            .optional()?;
        if held.as_ref() != expected.as_ref() {
            return Ok(false);
        }
    }
    let mut delete = transaction.prepare_cached("DELETE FROM records WHERE address = ?1")?;
    for address in &commit.deletes {
        delete.execute(params![address])?;
    }
    let mut put = transaction.prepare_cached(
        "INSERT INTO records (address, record) VALUES (?1, ?2)
         ON CONFLICT (address) DO UPDATE SET record = excluded.record",
    )?;
    for (address, record) in &commit.puts {
        put.execute(params![address, record])?;
    }
    Ok(true)
}

impl SqliteStore {
    /// Opens the database at `path`, making it if there is none, with
    /// [`READERS`] read-only connections.
    ///
    /// # Errors
    ///
    /// If SQLite cannot open it, or it holds a schema of another version.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_readers(path, READERS)
    }

    /// Opens the database at `path` with `readers` read-only connections;
    /// with none, reads take the writer's connection.
    ///
    /// # Errors
    ///
    /// If SQLite cannot open it, or it holds a schema of another version.
    pub fn open_with_readers(path: impl AsRef<Path>, readers: usize) -> Result<Self, StoreError> {
        Self::open_with(path, readers, Durability::Full)
    }

    /// Opens the database at `path` with `readers` read-only connections
    /// and a [`Durability`].
    ///
    /// # Errors
    ///
    /// If SQLite cannot open it, or it holds a schema of another version.
    pub fn open_with(
        path: impl AsRef<Path>,
        readers: usize,
        durability: Durability,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let mut store = Self::setup(Connection::open(path).map_err(failed)?, durability)?;
        for _ in 0..readers {
            let reader = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(failed)?;
            reader
                .busy_timeout(Duration::from_secs(5))
                .map_err(failed)?;
            store.readers.push(Mutex::new(reader));
        }
        Ok(store)
    }

    /// A database in memory, for tests: it is lost when dropped.
    ///
    /// # Errors
    ///
    /// If SQLite cannot make it.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::setup(
            Connection::open_in_memory().map_err(failed)?,
            Durability::Full,
        )
    }

    fn setup(mut connection: Connection, durability: Durability) -> Result<Self, StoreError> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(failed)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(failed)?;
        let synchronous = match durability {
            Durability::Full => "FULL",
            Durability::Cache => "NORMAL",
        };
        connection
            .pragma_update(None, "synchronous", synchronous)
            .map_err(failed)?;
        connection
            .pragma_update(None, "fullfsync", true)
            .map_err(failed)?;
        connection
            .pragma_update(None, "checkpoint_fullfsync", true)
            .map_err(failed)?;
        // A deleted record's bytes are overwritten in the file, not left in
        // its free pages (at-rest.md, "Forgetting a log, and re-keying").
        connection
            .pragma_update(None, "secure_delete", true)
            .map_err(failed)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let version: i64 = transaction
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(failed)?;
        match version {
            0 => transaction
                .execute_batch(
                    "CREATE TABLE records (
                        address BLOB PRIMARY KEY NOT NULL,
                        record BLOB NOT NULL
                    ) WITHOUT ROWID;
                    PRAGMA user_version = 1;",
                )
                .map_err(failed)?,
            SCHEMA_VERSION => {}
            _ => return Err(StoreError::new("sqlite: a store schema of another version")),
        }
        transaction.commit().map_err(failed)?;
        Ok(Self {
            writer: Mutex::new(connection),
            readers: Vec::new(),
            next: AtomicUsize::new(0),
        })
    }

    /// Runs a read on a reader: the first free one, else the next in turn.
    fn read<T>(
        &self,
        action: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        if self.readers.is_empty() {
            return action(&lock(&self.writer)).map_err(failed);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let count = self.readers.len();
        for offset in 0..count {
            if let Ok(reader) = self.readers[(start + offset) % count].try_lock() {
                return action(&reader).map_err(failed);
            }
        }
        action(&lock(&self.readers[start % count])).map_err(failed)
    }

    /// [`Store::get`], blocking the calling thread.
    ///
    /// # Errors
    ///
    /// When SQLite fails.
    pub fn get_now(&self, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.read(|connection| {
            connection
                .prepare_cached("SELECT record FROM records WHERE address = ?1")?
                .query_row(params![address], |row| row.get(0))
                .optional()
        })
    }

    /// [`Store::get_many`], blocking the calling thread. Several records
    /// are read at once, a share on each read-only connection, each on a
    /// thread of its own: a large record's pages are read one after
    /// another.
    ///
    /// # Errors
    ///
    /// When SQLite fails.
    pub fn get_many_now(&self, addresses: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        fn get_all(
            connection: &Connection,
            addresses: &[Vec<u8>],
        ) -> rusqlite::Result<Vec<Option<Vec<u8>>>> {
            let mut statement =
                connection.prepare_cached("SELECT record FROM records WHERE address = ?1")?;
            addresses
                .iter()
                .map(|address| {
                    statement
                        .query_row(params![address], |row| row.get(0))
                        .optional()
                })
                .collect()
        }
        let shares = self.readers.len().min(addresses.len());
        if shares <= 1 {
            return self.read(|connection| get_all(connection, addresses));
        }
        let size = addresses.len().div_ceil(shares);
        std::thread::scope(|scope| {
            let reads: Vec<_> = addresses
                .chunks(size)
                .zip(&self.readers)
                .map(|(share, reader)| {
                    scope.spawn(move || get_all(&lock(reader), share).map_err(failed))
                })
                .collect();
            let mut out = Vec::with_capacity(addresses.len());
            for read in reads {
                out.extend(
                    read.join()
                        .map_err(|_| StoreError::new("sqlite: a read failed"))??,
                );
            }
            Ok(out)
        })
    }

    /// [`Store::scan`], blocking the calling thread.
    ///
    /// # Errors
    ///
    /// When SQLite fails.
    pub fn scan_now(&self, prefix: &[u8]) -> Result<Records, StoreError> {
        self.read(|connection| {
            let row = |row: &rusqlite::Row<'_>| Ok((row.get(0)?, row.get(1)?));
            match prefix_end(prefix) {
                Some(end) => connection
                    .prepare_cached(
                        "SELECT address, record FROM records
                         WHERE address >= ?1 AND address < ?2 ORDER BY address",
                    )?
                    .query_map(params![prefix, end], row)?
                    .collect(),
                None => connection
                    .prepare_cached(
                        "SELECT address, record FROM records
                         WHERE address >= ?1 ORDER BY address",
                    )?
                    .query_map(params![prefix], row)?
                    .collect(),
            }
        })
    }

    /// [`Store::scan_sizes`], blocking the calling thread.
    ///
    /// # Errors
    ///
    /// When SQLite fails.
    pub fn scan_sizes_now(&self, prefix: &[u8]) -> Result<crate::store::Sizes, StoreError> {
        self.read(|connection| {
            let row = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get(0)?,
                    usize::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                ))
            };
            match prefix_end(prefix) {
                Some(end) => connection
                    .prepare_cached(
                        "SELECT address, length(record) FROM records
                         WHERE address >= ?1 AND address < ?2 ORDER BY address",
                    )?
                    .query_map(params![prefix, end], row)?
                    .collect(),
                None => connection
                    .prepare_cached(
                        "SELECT address, length(record) FROM records
                         WHERE address >= ?1 ORDER BY address",
                    )?
                    .query_map(params![prefix], row)?
                    .collect(),
            }
        })
    }

    /// Writes a copy of the whole database to a new file at `path`
    /// (SQLite's `VACUUM INTO`): a consistent copy of the database as of one
    /// commit. On a database with readers it runs on a reader, so commits go
    /// on meanwhile.
    ///
    /// # Errors
    ///
    /// If SQLite cannot write it, or a file is already at `path`.
    pub fn copy_into(&self, path: impl AsRef<Path>) -> Result<(), StoreError> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| StoreError::new("sqlite: a path that is not UTF-8"))?
            .to_owned();
        self.read(|connection| {
            connection
                .execute("VACUUM INTO ?1", params![path])
                .map(|_| ())
        })
    }

    /// The record at `address` in the database file at `path`, read without
    /// changing the file: for a copy [`Self::copy_into`] made.
    ///
    /// # Errors
    ///
    /// If SQLite cannot open the file or read it.
    pub fn read_file(
        path: impl AsRef<Path>,
        address: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(failed)?;
        connection
            .query_row(
                "SELECT record FROM records WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .optional()
            .map_err(failed)
    }

    /// The first address after `after`, in address order, if any.
    ///
    /// # Errors
    ///
    /// If SQLite cannot read it.
    pub fn next_address(&self, after: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.read(|connection| {
            connection
                .prepare_cached(
                    "SELECT address FROM records WHERE address > ?1 ORDER BY address LIMIT 1",
                )?
                .query_row(params![after], |row| row.get(0))
                .optional()
        })
    }

    /// [`Store::scrub`], blocking the calling thread: the write-ahead log
    /// is checkpointed into the file and truncated, so that its frames,
    /// which may still hold deleted records, leave the file system's view
    /// of the store. Deleted records' pages are already overwritten, since
    /// the store deletes with `secure_delete`.
    ///
    /// # Errors
    ///
    /// When SQLite fails.
    pub fn scrub_now(&self) -> Result<(), StoreError> {
        let connection = lock(&self.writer);
        connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .map_err(failed)
    }

    /// [`Store::commit_all`], blocking the calling thread: the commits in
    /// one transaction of the writer, with one fsync.
    ///
    /// # Errors
    ///
    /// When SQLite fails; then none of the commits is made.
    pub fn commit_now(&self, commits: &[Commit]) -> Result<Vec<bool>, StoreError> {
        let mut connection = lock(&self.writer);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let made = commits
            .iter()
            .map(|commit| apply(&transaction, commit))
            .collect::<rusqlite::Result<Vec<bool>>>()
            .map_err(failed)?;
        transaction.commit().map_err(failed)?;
        Ok(made)
    }
}

impl Store for SqliteStore {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move { self.get_now(address) })
    }

    fn get_many<'a>(
        &'a self,
        addresses: &'a [Vec<u8>],
    ) -> BoxFuture<'a, Result<Vec<Option<Vec<u8>>>, StoreError>> {
        Box::pin(async move { self.get_many_now(addresses) })
    }

    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Records, StoreError>> {
        Box::pin(async move { self.scan_now(prefix) })
    }

    fn scan_sizes<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> BoxFuture<'a, Result<crate::store::Sizes, StoreError>> {
        Box::pin(async move { self.scan_sizes_now(prefix) })
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            self.commit_now(std::slice::from_ref(commit))
                .map(|made| made[0])
        })
    }

    fn scrub(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move { self.scrub_now() })
    }

    fn commit_all<'a>(
        &'a self,
        commits: &'a [Commit],
    ) -> BoxFuture<'a, Result<Vec<bool>, StoreError>> {
        Box::pin(async move {
            if commits.is_empty() {
                return Ok(Vec::new());
            }
            self.commit_now(commits)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::prefix_end;

    #[test]
    fn prefix_ends() {
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(&[0xff, 0xff]), None);
        assert_eq!(prefix_end(&[1, 0xff]), Some(vec![2]));
        assert_eq!(prefix_end(&[1, 2]), Some(vec![1, 3]));
    }
}
