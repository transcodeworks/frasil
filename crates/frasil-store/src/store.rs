//! What the application provides (at-rest.md, "What the application
//! provides"): the [`Store`], from addresses to records, and the
//! [`DeviceBoundSlot`] that holds the mark. Both have a version in memory
//! here; the SQLite store is `crate::sqlite`'s.
//!
//! A store decides nothing. It holds only Frasil's records, which nothing
//! opens without the unlocked device, and Frasil writes nothing else. It
//! compares and writes atomically: each [`Store::commit`] is one atomic,
//! durable step, and may be made conditional on what some addresses hold,
//! so two processes or tabs of one device never both advance the head from
//! the same state.
//!
//! Every method returns a [`BoxFuture`], because a browser's storage
//! answers asynchronously. [`Store::commit_all`] lets a store make the
//! commits of several writers in one step. The futures of the stores in this crate are
//! ready when first polled.

use crate::keys::{Address, StoreKeys};
use crate::tables::Table;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};

/// `Send` on native targets; nothing on `wasm32`, where futures that await
/// JavaScript promises cannot be sent between threads.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}
/// `Send` on native targets; nothing on `wasm32`, where futures that await
/// JavaScript promises cannot be sent between threads.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Sync` on native targets; nothing on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}
/// `Sync` on native targets; nothing on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// A boxed future, `Send` on native targets and not on `wasm32`, which
/// keeps the traits usable as trait objects.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// A boxed future, `Send` on native targets and not on `wasm32`, which
/// keeps the traits usable as trait objects.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Records with their addresses, in address order: what
/// [`Store::scan`] returns.
pub type Records = Vec<(Vec<u8>, Vec<u8>)>;

/// Addresses and the lengths of their records, in address order.
pub type Sizes = Vec<(Vec<u8>, usize)>;

/// A store or slot failed: its medium did, not a record. The message is the
/// backend's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
}

impl StoreError {
    /// A failure described by `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

/// One commit: `commit(puts, deletes)`, made only if every expectation
/// holds.
///
/// The commit removes `deletes` then writes `puts`, so an address in both
/// ends up put; a delete of an address the store does not hold is nothing.
/// With no expectation it is at-rest.md's commit as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Commit {
    /// Addresses and what each must hold for the commit to be made: the
    /// record, or `None` for nothing. This is how a device keeps its head
    /// from being advanced twice from one state.
    pub expect: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// Records to write, by address.
    pub puts: Vec<(Vec<u8>, Vec<u8>)>,
    /// Addresses to delete.
    pub deletes: Vec<Vec<u8>>,
}

impl Commit {
    /// A commit of puts and deletes, with no expectation.
    pub fn new(puts: Vec<(Vec<u8>, Vec<u8>)>, deletes: Vec<Vec<u8>>) -> Self {
        Self {
            expect: Vec::new(),
            puts,
            deletes,
        }
    }

    /// Adds an expectation: the address holds exactly `record`, or nothing.
    pub fn expecting(mut self, address: &[u8], record: Option<&[u8]>) -> Self {
        self.expect
            .push((address.to_vec(), record.map(<[u8]>::to_vec)));
        self
    }
}

/// The store: addresses to records (at-rest.md, "What the application
/// provides").
///
/// The application supplies it: a database on native targets (the crate's
/// SQLite store), IndexedDB in a browser. A store is read only by the device
/// that wrote it; data moves to another device by sync, never by copying a
/// store.
pub trait Store: MaybeSend + MaybeSync {
    /// `get(address)`: the record at an address, or `None`.
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>>;

    /// The record at each of several addresses, in their order: what a
    /// reader that wants many records at once asks for. By default,
    /// [`get`](Store::get) for each; a store that can read them in one step
    /// overrides it.
    fn get_many<'a>(
        &'a self,
        addresses: &'a [Vec<u8>],
    ) -> BoxFuture<'a, Result<Vec<Option<Vec<u8>>>, StoreError>> {
        Box::pin(async move {
            let mut out = Vec::with_capacity(addresses.len());
            for address in addresses {
                out.push(self.get(address).await?);
            }
            Ok(out)
        })
    }

    /// `scan(prefix)`: every address that starts with `prefix`, and its
    /// record, in address order (bytewise).
    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Records, StoreError>>;

    /// Every address that starts with `prefix`, and the length of its
    /// record, in address order: what a reader that opens only some records
    /// asks for. By default, [`scan`](Store::scan)'s records' lengths; a
    /// store that can answer without reading the records overrides it.
    fn scan_sizes<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Sizes, StoreError>> {
        Box::pin(async move {
            Ok(self
                .scan(prefix)
                .await?
                .into_iter()
                .map(|(address, record)| (address, record.len()))
                .collect())
        })
    }

    /// `commit(puts, deletes)`: if every expectation holds, delete then put,
    /// atomically and durably when the future completes, and return `true`;
    /// otherwise change nothing and return `false`. Compare and write must
    /// be one step (one database transaction, one IndexedDB transaction).
    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>>;

    /// Removes, where the store can, what its file still holds of records
    /// deleted before: after a log is forgotten, so that no record of it
    /// stays on the medium in a form the file system shows (at-rest.md,
    /// "Forgetting a log, and re-keying"). The crate's SQLite store
    /// truncates its write-ahead log. By default, nothing: a store that
    /// cannot, such as IndexedDB, leaves deleted records to its own
    /// compaction.
    fn scrub(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    /// Several commits, in order: each is made if its expectations hold
    /// against what the commits before it left, and the answer says, per
    /// commit, whether it was made.
    ///
    /// A store that can make them one atomic, durable step (one database
    /// transaction and one sync, one object in a bucket) overrides this, so
    /// that writers who commit at once share that step; then, if the step
    /// fails, none of them is made. By default each commit is its own step,
    /// and the first that fails ends the batch.
    fn commit_all<'a>(
        &'a self,
        commits: &'a [Commit],
    ) -> BoxFuture<'a, Result<Vec<bool>, StoreError>> {
        Box::pin(async move {
            let mut made = Vec::with_capacity(commits.len());
            for commit in commits {
                made.push(self.commit(commit).await?);
            }
            Ok(made)
        })
    }
}

/// The device-bound slot (at-rest.md, "What the application provides"):
/// the 65-byte mark, durable, in a place no backup restores, such as a
/// keychain item bound to the device and left out of backups.
pub trait DeviceBoundSlot: MaybeSend + MaybeSync {
    /// `read()`: the slot's bytes, or `None` if it holds none.
    fn read(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, StoreError>>;

    /// `write(bytes)`, durable when the future completes.
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// A [`Store`] in memory: records last as long as this value. For tests,
/// and for a log kept in memory only.
#[derive(Debug, Default)]
pub struct MemoryStore {
    records: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, action: impl FnOnce(&mut BTreeMap<Vec<u8>, Vec<u8>>) -> T) -> T {
        let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut records)
    }

    /// How many records it holds.
    pub fn len(&self) -> usize {
        self.with(|records| records.len())
    }

    /// Whether it holds no record.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Applies a commit to an ordered map, if its expectations hold.
pub(crate) fn apply(records: &mut BTreeMap<Vec<u8>, Vec<u8>>, commit: &Commit) -> bool {
    let holds = commit
        .expect
        .iter()
        .all(|(address, expected)| records.get(address) == expected.as_ref());
    if !holds {
        return false;
    }
    for address in &commit.deletes {
        records.remove(address);
    }
    for (address, record) in &commit.puts {
        records.insert(address.clone(), record.clone());
    }
    true
}

impl Store for MemoryStore {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        let record = self.with(|records| records.get(address).cloned());
        Box::pin(async move { Ok(record) })
    }

    fn get_many<'a>(
        &'a self,
        addresses: &'a [Vec<u8>],
    ) -> BoxFuture<'a, Result<Vec<Option<Vec<u8>>>, StoreError>> {
        let found = self.with(|records| {
            addresses
                .iter()
                .map(|address| records.get(address).cloned())
                .collect()
        });
        Box::pin(async move { Ok(found) })
    }

    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Records, StoreError>> {
        let found = self.with(|records| {
            records
                .range(prefix.to_vec()..)
                .take_while(|(address, _)| address.starts_with(prefix))
                .map(|(address, record)| (address.clone(), record.clone()))
                .collect()
        });
        Box::pin(async move { Ok(found) })
    }

    fn scan_sizes<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Sizes, StoreError>> {
        let found = self.with(|records| {
            records
                .range(prefix.to_vec()..)
                .take_while(|(address, _)| address.starts_with(prefix))
                .map(|(address, record)| (address.clone(), record.len()))
                .collect()
        });
        Box::pin(async move { Ok(found) })
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        let made = self.with(|records| apply(records, commit));
        Box::pin(async move { Ok(made) })
    }

    fn commit_all<'a>(
        &'a self,
        commits: &'a [Commit],
    ) -> BoxFuture<'a, Result<Vec<bool>, StoreError>> {
        let made = self.with(|records| {
            commits
                .iter()
                .map(|commit| apply(records, commit))
                .collect()
        });
        Box::pin(async move { Ok(made) })
    }
}

/// A [`DeviceBoundSlot`] in memory. For tests: a slot in memory is lost
/// with the process, so every start would count as a restore.
#[derive(Debug, Default)]
pub struct MemorySlot {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl MemorySlot {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DeviceBoundSlot for MemorySlot {
    fn read(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, StoreError>> {
        let bytes = self
            .bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Box::pin(async move { Ok(bytes) })
    }

    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, Result<(), StoreError>> {
        *self.bytes.lock().unwrap_or_else(PoisonError::into_inner) = Some(bytes.to_vec());
        Box::pin(async { Ok(()) })
    }
}

/// Forgets a log (at-rest.md, "Forgetting a log, and re-keying"): deletes
/// its `log` record in one commit, then the log's other records by their
/// scope prefix. From then on no record of the log that the medium still
/// holds can be opened, even with the unlock key.
///
/// # Errors
///
/// The store's.
pub async fn forget_log<S: Store + ?Sized>(
    store: &S,
    keys: &StoreKeys,
    log_id: &[u8; 32],
) -> Result<(), StoreError> {
    let log_record: Address = keys
        .address(Table::Log, log_id)
        .expect("the log table is device-wide");
    store
        .commit(&Commit::new(Vec::new(), vec![log_record.to_vec()]))
        .await?;
    let scope = keys.scope_tag(log_id);
    let records = store.scan(&scope).await?;
    if !records.is_empty() {
        let deletes = records.into_iter().map(|(address, _)| address).collect();
        store.commit(&Commit::new(Vec::new(), deletes)).await?;
    }
    // What the file still holds of the deleted records goes too.
    store.scrub().await
}
