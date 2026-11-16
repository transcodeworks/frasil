//! The index: reads each source space's replica into the cache, and
//! answers queries over it.

use crate::index::column::{ColumnKind, Ref, RichText, Time, hex};
use crate::index::error::{Error, Result};
use crate::index::schema::{SPACES_TABLE, Schema, TableSchema};
use crate::index::sql::{Row, SqlValue};
use crate::index::store::{Location, Store, key_pragma};
use crate::index::table::Table;
use crate::index::watch::{TableChanges, Watch};
use crate::index::write::kinded;
use crate::{
    Change, Detail, Device, Effect, Kind, MemberId, Records, ReviewChange, Row as Cells, Space,
    SpaceId, StreamId, Value,
};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::broadcast;

/// The refreshes [`Index::follow`] has still to run: whole spaces, and
/// rows of tables by space.
#[derive(Default)]
struct Pending {
    whole: BTreeSet<SpaceId>,
    rows: BTreeMap<SpaceId, BTreeMap<String, BTreeSet<Vec<u8>>>>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.whole.is_empty() && self.rows.is_empty()
    }
}

/// A typed, local cache of the tables that spaces' Records hold.
///
/// Every space this device can read whose kind is a table's source feeds
/// that table; a space it can no longer read, or no longer holds, leaves
/// it. A space the device keeps nothing of at rest
/// ([`Space::keeps_nothing_at_rest`]) feeds no table: its rows would reach
/// the cache's file, so queries never see them (ext-guests.md, "Nothing at
/// rest"). The cache is a SQLite file, encrypted at rest, that the index alone
/// writes: queries run on a connection that refuses writes, and the
/// application writes through Records ([`Writer`](crate::index::Writer)). It
/// holds merged state, and open suggestions only in tables that ask for
/// them.
///
/// An index is a cheap handle: clones share one cache.
#[derive(Clone)]
pub struct Index {
    inner: Arc<Inner>,
}

struct Inner {
    device: Device,
    schema: Schema,
    revision: std::sync::atomic::AtomicU64,
    metadata_write_failed: Mutex<BTreeSet<String>>,
    store: Store,
    /// The tables each refresh changed.
    changed: broadcast::Sender<Arc<BTreeSet<String>>>,
    /// One refresh at a time.
    refreshing: tokio::sync::Mutex<()>,
    /// What each space's table held at its last write, by digest.
    reads: Mutex<BTreeMap<String, u64>>,
    digests: Mutex<HashMap<(String, &'static str), [u8; 32]>>,
    #[cfg(feature = "index-diesel")]
    diesel: Mutex<Option<::diesel::SqliteConnection>>,
}

impl core::fmt::Debug for Index {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Index")
            .field("tables", &self.inner.schema.tables().len())
            .finish_non_exhaustive()
    }
}

/// A row of a typed table, with the columns every table has.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Stored<T> {
    /// The space that holds it.
    pub space: SpaceId,
    /// Its key.
    pub key: Ref<T>,
    /// Who last changed it: the person of the device that did, or the
    /// device when it reached the space directly.
    pub author: Option<MemberId>,
    /// The writer's claimed wall time from `Records::last_change`, with
    /// second precision expressed in milliseconds.
    pub changed_at: Option<Time>,
    /// The open suggestion it shows, for a table that holds suggestions.
    pub suggestion: Option<String>,
    /// Its columns.
    pub row: T,
}

/// A reference to a row that the cache does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dangling {
    /// The table of the referring row.
    pub table: &'static str,
    /// Its column.
    pub column: &'static str,
    /// Its space.
    pub space: String,
    /// Its key, in hexadecimal.
    pub key: String,
    /// The table referred to.
    pub target: &'static str,
    /// The key referred to, in hexadecimal.
    pub missing: String,
}

/// A table's rows, by key and suggestion, as SQL values in the table's
/// column order.
type Rows = BTreeMap<(Vec<u8>, String), Vec<SqlValue>>;

/// A space as its replica holds it.
struct Read {
    kind: String,
    owner: Option<String>,
    /// Each fed table's rows.
    tables: BTreeMap<&'static str, Rows>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

impl Index {
    /// Opens the cache in a file, or makes it, and brings it up to date
    /// from the device's replicas. Frasil derives its encryption key with
    /// the index's application purpose. A cache of another
    /// schema version, or one that does not open under the key, is
    /// rebuilt, from the replicas alone.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`] when the schema does not hold together; SQLite's;
    /// Frasil's.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    pub async fn open(
        device: &Device,
        path: impl AsRef<std::path::Path>,
        schema: Schema,
    ) -> Result<Self> {
        schema.check()?;
        let store = Store::open(
            Location::File(path.as_ref().to_path_buf()),
            key_pragma(&*device.derive_key("frasil-index/cache/v1").await?),
        )?;
        Self::start(device, store, schema).await
    }

    /// Opens the cache in the browser's origin-private file system, under
    /// `name`, as [`Index::open`] does in a file. It runs in a dedicated
    /// worker, where OPFS gives synchronous access handles.
    ///
    /// # Errors
    ///
    /// As [`Index::open`]; [`Error::Sql`] when the OPFS pool does not
    /// install.
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    pub async fn open_in_browser(device: &Device, name: &str, schema: Schema) -> Result<Self> {
        use sqlite_wasm_vfs::sahpool::{OpfsSAHPoolCfgBuilder, install};
        schema.check()?;
        // One pool for each name, in a directory and under a VFS name of its
        // own: a pool keeps one directory, and a VFS name one pool.
        let pool_name = format!("frasil-index-{}", hex(&Sha256::digest(name.as_bytes())));
        let config = OpfsSAHPoolCfgBuilder::new()
            .vfs_name(&pool_name)
            .directory(&format!(".{pool_name}"))
            .build();
        let pool = install::<sqlite_wasm_rs::WasmOsCallback>(&config, false)
            .await
            .map_err(|error| Error::Sql(format!("OPFS: {error:?}")))?;
        let location = Location::Opfs {
            name: format!("/{name}"),
            vfs: crate::index::store::cipher_vfs(&pool_name),
            pool,
        };
        let store = Store::open(
            location,
            key_pragma(&*device.derive_key("frasil-index/cache/v1").await?),
        )?;
        Self::start(device, store, schema).await
    }

    async fn start(device: &Device, store: Store, schema: Schema) -> Result<Self> {
        let version = schema.version();
        let stored: Option<String> = store.write(|c| {
            Ok(c.query_row(
                "SELECT \"value\" FROM \"_meta\" WHERE \"name\" = 'schema'",
                [],
                |row| row.get(0),
            )
            .optional()?)
        })?;
        let index = Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                schema,
                revision: std::sync::atomic::AtomicU64::new(0),
                metadata_write_failed: Mutex::new(BTreeSet::new()),
                store,
                changed: broadcast::channel(64).0,
                refreshing: tokio::sync::Mutex::new(()),
                reads: Mutex::new(BTreeMap::new()),
                digests: Mutex::new(HashMap::new()),
                #[cfg(feature = "index-diesel")]
                diesel: Mutex::new(None),
            }),
        };
        if stored.as_deref() != Some(version.as_str()) {
            index.reset()?;
        }
        index.sync().await?;
        Ok(index)
    }

    /// Atomically read and replace opaque device-local metadata under the cache lock.
    /// The callback and durable commit use an immediate SQLite transaction, serializing
    /// with other handles as well as users of this index. `None`
    /// retains the existing value. Metadata never enters replicas or query revisions.
    pub fn update_local_metadata<R>(
        &self,
        name: &str,
        update: impl FnOnce(Option<&str>) -> Result<(Option<String>, R)>,
    ) -> Result<R> {
        let result = self.inner.store.write(|c| {
            let transaction = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let previous: Option<String> = transaction.query_row(
                "SELECT value FROM _meta WHERE name = ?1", [name], |row| row.get(0),
            ).optional()?;
            let (next, result) = update(previous.as_deref())?;
            let mut persisted = false;
            if let Some(next) = next
                && (previous.as_ref() != Some(&next)
                    || lock(&self.inner.metadata_write_failed).contains(name))
            {
                transaction.execute("INSERT INTO _meta (name, value) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET value = excluded.value", [name, &next])?;
                persisted = true;
            }
            transaction.commit()?;
            Ok((result, persisted))
        });
        let mut failed = lock(&self.inner.metadata_write_failed);
        match &result {
            Err(_) => {
                failed.insert(name.into());
            }
            Ok((_, true)) => {
                failed.remove(name);
            }
            Ok((_, false)) => {}
        }
        result.map(|(result, _)| result)
    }

    /// Read an opaque device-local metadata value. Read failures remain errors.
    pub fn local_metadata(&self, name: &str) -> Result<Option<String>> {
        self.inner.store.write(|c| {
            Ok(
                c.query_row("SELECT value FROM _meta WHERE name = ?1", [name], |row| {
                    row.get(0)
                })
                .optional()?,
            )
        })
    }

    /// Monotonic cache revision, incremented only when refreshed tables change.
    pub fn revision(&self) -> u64 {
        self.inner
            .revision
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// The schema.
    pub fn schema(&self) -> &Schema {
        &self.inner.schema
    }

    /// The device.
    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    #[cfg_attr(not(feature = "index-diesel"), allow(dead_code))]
    pub(crate) fn store(&self) -> &Store {
        &self.inner.store
    }

    #[cfg(feature = "index-diesel")]
    pub(crate) fn inner_diesel(&self) -> &Mutex<Option<::diesel::SqliteConnection>> {
        &self.inner.diesel
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<BTreeSet<String>>> {
        self.inner.changed.subscribe()
    }

    /// Runs a query: its rows, with their columns by name.
    ///
    /// # Errors
    ///
    /// [`Error::Sql`] when it does not prepare or run, or would write.
    pub fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.inner.store.query(sql, params).map(|(rows, _)| rows)
    }

    /// The tables the index changes from now on, as it changes them.
    pub fn table_changes(&self) -> TableChanges {
        let mut tables: BTreeSet<String> = self
            .inner
            .schema
            .tables()
            .iter()
            .map(|table| table.name.to_owned())
            .collect();
        tables.insert(SPACES_TABLE.to_owned());
        TableChanges::new(tables, self.subscribe())
    }

    /// A live query: [`Watch::next`] gives its rows now, then again each
    /// time the index changes a table it reads.
    ///
    /// # Errors
    ///
    /// As [`Index::query`].
    pub fn watch(&self, sql: impl Into<String>, params: Vec<SqlValue>) -> Result<Watch> {
        let sql = sql.into();
        let receiver = self.subscribe();
        let tables = self.inner.store.reads(&sql)?;
        Ok(Watch::new(self.clone(), sql, params, tables, receiver))
    }

    /// Runs a query whose rows are of table `T`, with its built-in
    /// columns: `SELECT * FROM <table> …`.
    ///
    /// # Errors
    ///
    /// As [`Index::query`]; [`Error::Decode`] or [`Error::NoColumn`] for a
    /// row that is not one of `T`.
    pub fn query_as<T: Table>(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Stored<T>>> {
        self.query(sql, params)?.iter().map(stored::<T>).collect()
    }

    /// Every merged row of table `T`.
    ///
    /// # Errors
    ///
    /// As [`Index::query_as`].
    pub fn all<T: Table>(&self) -> Result<Vec<Stored<T>>> {
        let filter = if T::SCHEMA.suggestions {
            " WHERE \"_suggested\" = 0"
        } else {
            ""
        };
        self.query_as(
            &format!("SELECT * FROM {}{filter}", quoted(T::SCHEMA.name)),
            &[],
        )
    }

    /// The references, in merged rows, to rows the cache does not hold: a
    /// row deleted, in a space this device does not read, or not yet
    /// synced.
    ///
    /// # Errors
    ///
    /// SQLite's.
    pub fn dangling(&self) -> Result<Vec<Dangling>> {
        let schema = &self.inner.schema;
        let mut out = Vec::new();
        for table in schema.tables() {
            for column in table.columns {
                let Some(target) = column.references.and_then(|t| schema.get(t)) else {
                    continue;
                };
                let merged = |t: &TableSchema, alias: &str| {
                    if t.suggestions {
                        format!(" AND {alias}.\"_suggested\" = 0")
                    } else {
                        String::new()
                    }
                };
                let sql = format!(
                    "SELECT s.\"_space\", s.\"_key\", s.{c} FROM {t} AS s \
                     LEFT JOIN {r} AS r ON r.\"_key\" = s.{c}{rm} \
                     WHERE s.{c} IS NOT NULL AND r.\"_key\" IS NULL{sm} \
                     ORDER BY s.\"_space\", s.\"_key\"",
                    c = quoted(column.name),
                    t = quoted(table.name),
                    r = quoted(target.name),
                    rm = merged(target, "r"),
                    sm = merged(table, "s"),
                );
                for row in self.query(&sql, &[])? {
                    let text = |i: usize| match &row.values()[i] {
                        SqlValue::Text(text) => text.clone(),
                        _ => String::new(),
                    };
                    out.push(Dangling {
                        table: table.name,
                        column: column.name,
                        space: text(0),
                        key: text(1),
                        target: target.name,
                        missing: text(2),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Brings the whole cache up to date: every space the device holds is
    /// read again, and spaces it no longer holds leave.
    ///
    /// # Errors
    ///
    /// SQLite's; Frasil's.
    pub async fn sync(&self) -> Result<()> {
        let _refreshing = self.inner.refreshing.lock().await;
        let mut held = BTreeSet::new();
        for space in self.inner.device.spaces().await {
            let id = space.id().to_string();
            let read = self.read_space(&space).await?;
            self.apply(&id, read)?;
            held.insert(id);
        }
        let known = self.known_spaces()?;
        for id in known.difference(&held) {
            self.apply(id, None)?;
        }
        Ok(())
    }

    /// Brings one space up to date: its rows are read again, or leave when
    /// the device no longer reads it.
    ///
    /// # Errors
    ///
    /// As [`Index::sync`].
    pub async fn refresh(&self, space: SpaceId) -> Result<()> {
        let _refreshing = self.inner.refreshing.lock().await;
        self.refresh_space(space).await
    }

    /// Refresh one authored row after a local write, retaining unrelated cached rows.
    /// Reads the merged public Records value and metadata; never trusts a caller's row payload.
    pub async fn refresh_row<T: Table>(&self, space: SpaceId, key: &Ref<T>) -> Result<()> {
        let _refreshing = self.inner.refreshing.lock().await;
        self.refresh_keys(space, T::SCHEMA.name, &[key.key().to_vec()])
            .await
    }

    /// Refreshes some rows of one table of a space from its Records, and
    /// leaves the others; the whole space when the table holds
    /// suggestions or the cache does not hold the space yet. Called with
    /// the refresh lock held.
    async fn refresh_keys(&self, space: SpaceId, table: &str, keys: &[Vec<u8>]) -> Result<()> {
        let Some(table) = self.inner.schema.get(table).copied() else {
            return Ok(());
        };
        if table.suggestions || !self.known_spaces()?.contains(&space.to_string()) {
            return self.refresh_space(space).await;
        }
        let source = match self.inner.device.space(space).await {
            Ok(source) => source,
            Err(crate::Error::UnknownSpace) => return self.refresh_space(space).await,
            Err(error) => return Err(error.into()),
        };
        if source.keeps_nothing_at_rest().await {
            return self.refresh_space(space).await;
        }
        let kinded: Vec<Records> = kinded(&source)
            .await?
            .into_iter()
            .filter(|(_, kind)| kind == table.source)
            .map(|(records, _)| records)
            .collect();
        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            let mut values = None;
            for records in &kinded {
                let Some(found) = records.row_with_metadata(table.name, key).await? else {
                    continue;
                };
                let metadata = metadata(&found.last_change);
                values = self
                    .values(&source, &table, key, &found.row, metadata, None)
                    .await;
            }
            rows.push((hex(key), values));
        }
        let id = space.to_string();
        self.inner.store.write(|c| {
            let tx = c.transaction()?;
            {
                let columns = table.sql_columns();
                let mut insert = tx.prepare(&format!(
                    "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
                    quoted(table.name),
                    columns
                        .iter()
                        .map(|c| quoted(c))
                        .collect::<Vec<_>>()
                        .join(","),
                    (1..=columns.len())
                        .map(|n| format!("?{n}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ))?;
                let mut delete = tx.prepare(&format!(
                    "DELETE FROM {} WHERE \"_space\" = ?1 AND \"_key\" = ?2",
                    quoted(table.name)
                ))?;
                for (key, values) in &rows {
                    match values {
                        Some(values) => insert.execute(rusqlite::params_from_iter(values))?,
                        None => delete.execute(rusqlite::params![id, key])?,
                    };
                }
            }
            tx.execute(
                "UPDATE _spaces SET synced_at = ?2 WHERE id = ?1",
                rusqlite::params![id, Time::now().as_millis()],
            )?;
            tx.commit()?;
            Ok(())
        })?;
        let slot = (id, table.name);
        lock(&self.inner.digests).remove(&slot);
        self.inner
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        let _ = self.inner.changed.send(Arc::new(BTreeSet::from([
            table.name.to_owned(),
            SPACES_TABLE.to_owned(),
        ])));
        Ok(())
    }

    /// Refreshes one space if no other refresh or sync is in progress.
    ///
    /// Returns `false` immediately when busy, without changing the cache. The
    /// caller may retry later or leave the pending change to [`Index::follow`].
    /// Once admitted, reading this space still awaits local replica storage.
    ///
    /// # Errors
    ///
    /// As [`Index::refresh`].
    pub async fn try_refresh(&self, space: SpaceId) -> Result<bool> {
        let Ok(_refreshing) = self.inner.refreshing.try_lock() else {
            return Ok(false);
        };
        self.refresh_space(space).await?;
        Ok(true)
    }

    async fn refresh_space(&self, space: SpaceId) -> Result<()> {
        let read = match self.inner.device.space(space).await {
            Ok(space) => self.read_space(&space).await?,
            Err(crate::Error::UnknownSpace) => None,
            Err(error) => return Err(error.into()),
        };
        self.apply(&space.to_string(), read)
    }

    /// Follows the device: brings the cache up to date with
    /// [`Index::sync`], then keeps it so until the device sends no more.
    /// A write to rows of a Records table refreshes those rows alone; any
    /// other change, such as one of who may read a space, refreshes its
    /// whole space. Changes that arrive while a refresh runs are taken
    /// together. A refresh that fails is retried with backoff, and the
    /// others go on; [`Index::follow_with`] hears of each failure. Run it in
    /// a task of its own.
    ///
    /// # Errors
    ///
    /// None: it returns once the device is gone.
    pub async fn follow(&self) -> Result<()> {
        self.follow_with(|_| {}).await
    }

    /// [`Index::follow`], telling `on_error` of each refresh that failed
    /// before it is retried.
    ///
    /// # Errors
    ///
    /// None: it returns once the device is gone.
    pub async fn follow_with(&self, mut on_error: impl FnMut(&Error)) -> Result<()> {
        use tokio::sync::broadcast::error::{RecvError, TryRecvError};
        const FIRST: std::time::Duration = std::time::Duration::from_millis(100);
        const LONGEST: std::time::Duration = std::time::Duration::from_secs(30);
        let device = &self.inner.device;
        let mut notices = device.engine().subscribe();
        let mut pending = Pending::default();
        let mut synced = false;
        let mut backoff = FIRST;
        let mut gone = false;
        while !gone {
            if pending.is_empty() && synced {
                match notices.recv().await {
                    Ok(notice) => self.gather(&mut pending, &notice).await,
                    Err(RecvError::Lagged(_)) => synced = false,
                    Err(RecvError::Closed) => return Ok(()),
                }
            }
            // What else came meanwhile goes in the same refresh.
            loop {
                match notices.try_recv() {
                    Ok(notice) => self.gather(&mut pending, &notice).await,
                    Err(TryRecvError::Lagged(_)) => synced = false,
                    Err(TryRecvError::Closed) => {
                        gone = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            let failed = if synced {
                self.refresh_pending(&mut pending, &mut on_error).await
            } else {
                match self.sync().await {
                    Ok(()) => {
                        synced = true;
                        pending = Pending::default();
                        false
                    }
                    Err(error) => {
                        on_error(&error);
                        true
                    }
                }
            };
            if failed {
                device.sleep(backoff).await;
                backoff = (backoff * 2).min(LONGEST);
            } else {
                backoff = FIRST;
            }
        }
        Ok(())
    }

    /// Adds what a notice changed to the refreshes pending.
    async fn gather(&self, pending: &mut Pending, notice: &crate::device::Notice) {
        if notice.placed.is_empty() {
            return;
        }
        let space = SpaceId::of(notice.space);
        let engine = self.inner.device.engine();
        let me = engine.device_id();
        let touched = engine
            .read(&notice.space, |replica| {
                crate::client::touched(replica, &me, &notice.placed)
            })
            .await;
        let (rows, others) = match touched {
            Ok(crate::client::Touched::Streams { rows, others }) => (rows, others),
            Ok(crate::client::Touched::All) | Err(_) => {
                pending.whole.insert(space);
                return;
            }
        };
        // A Loro document's text shows in rich text columns.
        let rich = self.inner.schema.tables().iter().any(|table| {
            table
                .columns
                .iter()
                .any(|column| column.kind == ColumnKind::RichText)
        });
        if others && rich {
            pending.whole.insert(space);
            return;
        }
        for change in rows.into_values().flatten() {
            match change {
                crate::RecordChange::Rows { table, keys, .. } => {
                    if self.inner.schema.get(&table).is_some() {
                        pending
                            .rows
                            .entry(space)
                            .or_default()
                            .entry(table)
                            .or_default()
                            .extend(keys);
                    }
                }
                _ => {
                    pending.whole.insert(space);
                    return;
                }
            }
        }
    }

    /// Runs the refreshes pending; those that fail stay pending, whole.
    /// Whether any failed.
    async fn refresh_pending(
        &self,
        pending: &mut Pending,
        on_error: &mut impl FnMut(&Error),
    ) -> bool {
        let _refreshing = self.inner.refreshing.lock().await;
        let work = std::mem::take(pending);
        let mut failed = false;
        for space in &work.whole {
            if let Err(error) = self.refresh_space(*space).await {
                on_error(&error);
                pending.whole.insert(*space);
                failed = true;
            }
        }
        for (space, tables) in work.rows {
            if work.whole.contains(&space) {
                continue;
            }
            for (table, keys) in tables {
                let keys: Vec<Vec<u8>> = keys.into_iter().collect();
                if let Err(error) = self.refresh_keys(space, &table, &keys).await {
                    on_error(&error);
                    pending.whole.insert(space);
                    failed = true;
                    break;
                }
            }
        }
        failed
    }

    /// Drops the cache's tables, makes them again, and reads every space
    /// again from the device's replicas.
    ///
    /// # Errors
    ///
    /// As [`Index::sync`].
    pub async fn rebuild(&self) -> Result<()> {
        {
            let _refreshing = self.inner.refreshing.lock().await;
            self.reset()?;
        }
        self.sync().await
    }

    /// Drops every table and makes the schema's, at its version.
    fn reset(&self) -> Result<()> {
        let schema = &self.inner.schema;
        let version = schema.version();
        let dropped = self.inner.store.write(|c| {
            let tx = c.transaction()?;
            let tables: Vec<String> = tx
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' \
                     AND name <> '_meta' AND name NOT LIKE 'sqlite_%'",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            for table in &tables {
                tx.execute_batch(&format!("DROP TABLE {};", quoted(table)))?;
            }
            tx.execute_batch(&schema.ddl())?;
            tx.execute(
                "INSERT INTO \"_meta\" (\"name\", \"value\") VALUES ('schema', ?1) \
                 ON CONFLICT (\"name\") DO UPDATE SET \"value\" = excluded.\"value\"",
                [&version],
            )?;
            tx.commit()?;
            Ok(tables)
        })?;
        self.inner.store.reopen_reader()?;
        #[cfg(feature = "index-diesel")]
        lock(&self.inner.diesel).take();
        lock(&self.inner.digests).clear();
        let mut changed: BTreeSet<String> = dropped.into_iter().collect();
        changed.extend(schema.tables().iter().map(|t| t.name.to_owned()));
        changed.insert(SPACES_TABLE.to_owned());
        self.inner
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        let _ = self.inner.changed.send(Arc::new(changed));
        Ok(())
    }

    /// The spaces the cache holds rows of.
    fn known_spaces(&self) -> Result<BTreeSet<String>> {
        let mut sql = format!("SELECT \"id\" FROM {}", quoted(SPACES_TABLE));
        for table in self.inner.schema.tables() {
            sql.push_str(&format!(
                " UNION SELECT \"_space\" FROM {}",
                quoted(table.name)
            ));
        }
        self.inner.store.write(|c| {
            Ok(c.prepare(&sql)?
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Number of full replica reads per space since this index was opened, for diagnostics and budgets.
    pub fn full_refresh_counts(&self) -> BTreeMap<String, u64> {
        lock(&self.inner.reads).clone()
    }

    /// Read a complete public replica, including author provenance.
    async fn read_space(&self, space: &Space) -> Result<Option<Read>> {
        *lock(&self.inner.reads)
            .entry(space.id().to_string())
            .or_default() += 1;
        // A space kept in memory only writes nothing to the cache's file.
        if space.level().await.is_none() || space.keeps_nothing_at_rest().await {
            return Ok(None);
        }
        let kinded = kinded(space).await?;
        let Some(kind) = space.kind().await? else {
            return Ok(None);
        };
        let tables: Vec<TableSchema> = self.inner.schema.fed_by(&kind).copied().collect();
        let mut read = Read {
            kind: kind.clone(),
            owner: None,
            tables: BTreeMap::new(),
        };
        for (records, _) in kinded.iter().filter(|(_, k)| *k == kind) {
            let history = match records.history().await {
                Ok(history) => history,
                Err(crate::Error::UnknownStream) => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            let owner = owner(&history);
            read.owner = read.owner.or(owner);
            for table in &tables {
                let with = match records.rows_with_metadata(table.name).await {
                    Ok(rows) => rows,
                    Err(crate::Error::UnknownStream) => BTreeMap::new(),
                    Err(error) => return Err(error.into()),
                };
                let out = read.tables.entry(table.name).or_default();
                let mut rows = BTreeMap::new();
                for (key, found) in with {
                    if let Some(values) = self
                        .values(
                            space,
                            table,
                            &key,
                            &found.row,
                            metadata(&found.last_change),
                            None,
                        )
                        .await
                    {
                        out.insert((key.clone(), String::new()), values);
                    }
                    rows.insert(key, found.row);
                }
                if table.suggestions {
                    for (key, suggestion, author, cells) in
                        suggested(records, table.name, &rows).await?
                    {
                        if let Some(values) = self
                            .values(
                                space,
                                table,
                                &key,
                                &cells,
                                (
                                    Some(author),
                                    history
                                        .iter()
                                        .find(|c| c.id.to_string() == suggestion)
                                        .and_then(|c| c.time)
                                        .and_then(|t| i64::try_from(t).ok())
                                        .and_then(|t| t.checked_mul(1000)),
                                ),
                                Some(&suggestion),
                            )
                            .await
                        {
                            out.insert((key, suggestion), values);
                        }
                    }
                }
            }
        }
        Ok(Some(read))
    }

    /// A row's SQL values, in its table's column order; `None` when a cell
    /// the table needs is absent or does not read as its column's kind.
    async fn values(
        &self,
        space: &Space,
        table: &TableSchema,
        key: &[u8],
        cells: &Cells,
        metadata: (Option<String>, Option<i64>),
        suggestion: Option<&str>,
    ) -> Option<Vec<SqlValue>> {
        let mut values = vec![
            SqlValue::Text(space.id().to_string()),
            SqlValue::Text(hex(key)),
            metadata.0.map_or(SqlValue::Null, SqlValue::Text),
            metadata.1.map_or(SqlValue::Null, SqlValue::Integer),
        ];
        if table.suggestions {
            values.push(SqlValue::Integer(i64::from(suggestion.is_some())));
            values.push(SqlValue::Text(suggestion.unwrap_or_default().to_owned()));
        }
        for column in table.columns {
            let value = match cells.get(column.name).map(|cell| column.kind.to_sql(cell)) {
                Some(Some(value)) => value,
                _ if column.nullable => SqlValue::Null,
                _ => return None,
            };
            let value = match (column.kind, value) {
                (ColumnKind::RichText, SqlValue::Text(id)) => {
                    SqlValue::Text(plain_text(space, &id).await)
                }
                (_, value) => value,
            };
            values.push(value);
        }
        Some(values)
    }

    /// Writes what a space holds, or removes it, in one transaction, and
    /// tells live queries which tables changed.
    fn apply(&self, id: &str, read: Option<Read>) -> Result<()> {
        let schema = &self.inner.schema;
        let mut digests = lock(&self.inner.digests);
        let mut changed = BTreeSet::new();
        self.inner.store.write(|c| {
            let tx = c.transaction()?;
            for table in schema.tables() {
                let empty = BTreeMap::new();
                let rows = read
                    .as_ref()
                    .and_then(|read| read.tables.get(table.name))
                    .unwrap_or(&empty);
                let digest = digest(rows);
                let slot = (id.to_owned(), table.name);
                if read.is_some() && digests.get(&slot) == Some(&digest) {
                    continue;
                }
                let deleted = tx.execute(
                    &format!("DELETE FROM {} WHERE \"_space\" = ?1", quoted(table.name)),
                    [id],
                )?;
                let columns = table.sql_columns();
                let mut insert = tx.prepare(&format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    quoted(table.name),
                    columns
                        .iter()
                        .map(|c| quoted(c))
                        .collect::<Vec<_>>()
                        .join(", "),
                    (1..=columns.len())
                        .map(|i| format!("?{i}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))?;
                for values in rows.values() {
                    insert.execute(rusqlite::params_from_iter(values))?;
                }
                if deleted > 0 || !rows.is_empty() {
                    changed.insert(table.name.to_owned());
                }
                if read.is_some() {
                    digests.insert(slot, digest);
                } else {
                    digests.remove(&slot);
                }
            }
            let spaces = quoted(SPACES_TABLE);
            let touched = match &read {
                Some(read) => tx.execute(
                    &format!(
                        "INSERT INTO {spaces} (\"id\", \"kind\", \"synced_at\", \"owner\") \
                         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (\"id\") DO UPDATE SET \
                         \"kind\" = excluded.\"kind\", \"synced_at\" = excluded.\"synced_at\", \
                         \"owner\" = excluded.\"owner\" WHERE \
                         \"kind\" IS NOT excluded.\"kind\" OR \
                         \"owner\" IS NOT excluded.\"owner\" OR ?5"
                    ),
                    rusqlite::params![
                        id,
                        read.kind,
                        Time::now().as_millis(),
                        read.owner,
                        !changed.is_empty()
                    ],
                )?,
                None => tx.execute(&format!("DELETE FROM {spaces} WHERE \"id\" = ?1"), [id])?,
            };
            if touched > 0 {
                changed.insert(SPACES_TABLE.to_owned());
            }
            tx.commit()?;
            Ok(())
        })?;
        drop(digests);
        // A space that leaves leaves nothing of its rows in the file.
        if read.is_none() && !changed.is_empty() {
            self.inner.store.scrub()?;
        }
        if !changed.is_empty() {
            self.inner
                .revision
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            let _ = self.inner.changed.send(Arc::new(changed));
        }
        Ok(())
    }
}

/// A row's `_author` and `_changed_at`: who made its last change, the
/// person at the change's place or else the device, and the writer's
/// claimed time in milliseconds.
fn metadata(last: &crate::LastChange) -> (Option<String>, Option<i64>) {
    let time = last
        .time
        .and_then(|t| i64::try_from(t).ok())
        .and_then(|t| t.checked_mul(1000));
    (Some(last.who().to_string()), time)
}

/// Who first inserted a row of the space: the person of the device, or the
/// device when it reached the space directly, in the space's canonical
/// order.
fn owner(history: &[Change]) -> Option<String> {
    history
        .iter()
        .filter(|change| {
            change.effect == Effect::Applied
                && matches!(change.kind, Kind::Edit | Kind::Review { .. })
        })
        .find_map(|change| {
            let Detail::Records(rows) = &change.detail else {
                return None;
            };
            rows.iter().any(|row| row.inserted).then(|| {
                change
                    .author
                    .person
                    .unwrap_or(change.author.device)
                    .to_string()
            })
        })
}

/// The rows each open suggestion shows in a table: its key, the
/// suggestion's ID, its author, and the row's cells with the suggestion's
/// over them. A suggestion that deletes a row shows nothing.
async fn suggested(
    records: &Records,
    table: &str,
    rows: &BTreeMap<Vec<u8>, Cells>,
) -> Result<Vec<(Vec<u8>, String, String, Cells)>> {
    let mut out = Vec::new();
    for suggestion in records.suggestions().await? {
        let review = records.review(suggestion.id).await?;
        let mut changed: BTreeMap<Vec<u8>, Vec<(String, Option<Value>)>> = BTreeMap::new();
        for change in review.changes {
            if let ReviewChange::Cell {
                table: t,
                key,
                column,
                to,
                ..
            } = change
                && t == table
            {
                changed.entry(key).or_default().push((column, to));
            }
        }
        for (key, cells) in changed {
            let mut row = rows.get(&key).cloned().unwrap_or_default();
            let mut deleted = false;
            for (column, to) in cells {
                match (column.is_empty(), to) {
                    // The row's marker: cleared, the row is deleted.
                    (true, None) => deleted = true,
                    (true, Some(_)) => deleted = false,
                    (false, Some(value)) => {
                        row.insert(column, value);
                    }
                    (false, None) => {
                        row.remove(&column);
                    }
                }
            }
            if !deleted {
                out.push((
                    key,
                    suggestion.id.to_string(),
                    review.author.to_string(),
                    row,
                ));
            }
        }
    }
    Ok(out)
}

/// A rich-text cell's plain text: its document's text container, empty
/// while this device does not hold the document.
async fn plain_text(space: &Space, id: &str) -> String {
    let Ok(id) = id.parse::<StreamId>() else {
        return String::new();
    };
    match space.document(id).await {
        Ok(document) => document.text(RichText::CONTAINER).await.unwrap_or_default(),
        Err(_) => String::new(),
    }
}

fn digest(rows: &Rows) -> [u8; 32] {
    let rows: Vec<&Vec<SqlValue>> = rows.values().collect();
    Sha256::digest(
        serde_json::to_vec(&rows)
            .expect("rows serialise")
            .as_slice(),
    )
    .into()
}

fn stored<T: Table>(row: &Row) -> Result<Stored<T>> {
    let text = |column: &str| -> Result<Option<String>> {
        Ok(match row.get(column)? {
            SqlValue::Text(text) => Some(text.clone()),
            _ => None,
        })
    };
    let decode = |column: &'static str, expected: &'static str| Error::Decode {
        table: T::SCHEMA.name.to_owned(),
        column: column.to_owned(),
        expected,
    };
    let space = text("_space")?
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| decode("_space", "a space ID"))?;
    let key = text("_key")?
        .and_then(|key| Ref::from_hex(&key).ok())
        .ok_or_else(|| decode("_key", "a key in hexadecimal"))?;
    let author = text("_author")?.and_then(|id| id.parse().ok());
    let changed_at = match row.get("_changed_at")? {
        SqlValue::Integer(ms) => Some(Time::from_millis(*ms)),
        _ => None,
    };
    let suggestion = if T::SCHEMA.suggestions {
        text("_suggestion")?.filter(|s| !s.is_empty())
    } else {
        None
    };
    Ok(Stored {
        space,
        key,
        author,
        changed_at,
        suggestion,
        row: T::from_row(row)?,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_refresh_skips_an_active_sync_and_can_retry() {
        let device = Device::open_with(
            crate::Storage::Memory,
            &[111; 32],
            crate::Options::new().loopback(),
        )
        .await
        .unwrap();
        device.make_person(&[111; 32]).await.unwrap();
        let writer = crate::index::create_space(&device, "shared").await.unwrap();
        let space = writer.space().id();
        let path =
            std::env::temp_dir().join(format!("index-try-refresh-{}.db", std::process::id()));
        let index = Index::open(&device, &path, Schema::new()).await.unwrap();
        let syncing = index.inner.refreshing.lock().await;
        let refreshed =
            tokio::time::timeout(std::time::Duration::from_secs(1), index.try_refresh(space))
                .await
                .expect("a busy cache must not wait for sync")
                .unwrap();
        assert!(!refreshed);
        drop(syncing);
        assert!(index.try_refresh(space).await.unwrap());
        drop(index);
        device.close().await.unwrap();
        let _ = std::fs::remove_file(path);
    }
}
