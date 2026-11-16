//! The device's store at rest (at-rest.md): the head, the logs' keys, sealed
//! records, and the rules for committing.
//!
//! [`Vault`] is the client's side of `frasil-store`: it seals and opens
//! records under the store secret and each log's key, keeps the head, and
//! commits as at-rest.md, "Committing" says:
//!
//! - **One commit, one step.** An event the device signs, its `outbox`
//!   record, its tip and any secret drawn for it go in one [`Batch`].
//! - **Mark before commit.** Before a commit that holds an event a signer
//!   of this device signed, the device writes the mark for
//!   `generation + 1` to the device-bound slot, then commits with the head
//!   at `generation + 1` (restore mode `device-bound` only).
//! - **A precondition.** Every commit that advances the head names the head
//!   record it read, so two processes of one device never advance it from
//!   the same state.
//!
//! [`Vault::open`] runs `continuity` at every open of the store, and
//! records a restore as "After a restore", step 1, says.

use crate::error::{Error, Result};
use crate::intake::{continuity, open_mark, open_record};
use crate::platform::Platform;
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_store::tables::{LogKind, LogRecord, Secret};
use frasil_store::{
    Commit, Continuity, Head, LogKeys, OpenedObject, Store, StoreKeys, Table, TableValue, Tip,
    after_restore, open_object_record, seal_mark_with, seal_record_with,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The 16 zero bytes of the device-wide scope.
const DEVICE_SCOPE: [u8; 16] = [0; 16];

/// Records to commit in one step, with the tips they move.
#[derive(Debug, Default)]
pub(crate) struct Batch {
    /// Sealed records, by address.
    pub puts: Vec<(Vec<u8>, Vec<u8>)>,
    /// Addresses to delete.
    pub deletes: Vec<Vec<u8>>,
    /// Tips to set in the head.
    pub tips: Vec<Tip>,
    /// Whether the batch holds an event a signer of this device signed: the generation moves, behind a mark.
    pub signs: bool,
    /// Logs synced since a restore (at-rest.md, "After a restore", step 2).
    pub synced: Vec<[u8; 32]>,
}

impl Batch {
    /// Whether the batch changes nothing.
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty()
            && self.deletes.is_empty()
            && self.tips.is_empty()
            && self.synced.is_empty()
    }
}

/// Reads parts of a log's objects from the `object` table, apart from the
/// [`Vault`] it came from: what reading a blob needs while the device goes
/// on.
pub(crate) struct ObjectParts {
    store: Arc<dyn Store>,
    keys: StoreKeys,
    log: LogKeys,
}

impl ObjectParts {
    /// Reads and opens parts of an object by ID, in one read of the store:
    /// part 0 is the header, part `i + 1` chunk `i`. `None` when one is
    /// missing or does not open (at-rest.md, "Opening a record"). The
    /// records open at once where the platform has threads.
    pub async fn read(&self, id: &[u8], parts: &[u32]) -> Result<Option<Vec<OpenedObject>>> {
        let mut addresses = Vec::with_capacity(parts.len());
        for part in parts {
            let item = [id, &part.to_be_bytes()].concat();
            match self.log.address(Table::Object, &item) {
                Some(address) => addresses.push(address.to_vec()),
                None => return Ok(None),
            }
        }
        let records = self.store.get_many(&addresses).await?;
        let bytes = records.iter().flatten().map(Vec::len).sum();
        let (store_keys, log_keys) = (&self.keys, &self.log);
        let opened = crate::parallel::map(
            addresses.iter().zip(records).collect(),
            bytes,
            |(address, record)| open_object_record(store_keys, log_keys, address, record?).ok(),
        );
        Ok(opened.into_iter().collect())
    }
}

/// Seals and commits parts of a log's objects apart from the [`Vault`] it
/// came from, so that a transfer does not hold the device while its chunks
/// are sealed and written. A commit of object parts alone moves no tip and
/// does not advance the head (at-rest.md, "Committing").
pub(crate) struct ObjectWriter {
    platform: Platform,
    keys: StoreKeys,
    log: LogKeys,
}

impl ObjectWriter {
    /// Seals parts of objects as `object` records, at once where the
    /// platform has threads: their addresses and records.
    pub fn seal(&self, parts: &[&crate::snapshots::ObjectPart]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut items = Vec::new();
        for part in parts {
            let id = &part.locator[..32];
            if let Some(header) = &part.header {
                items.push(([id, &0u32.to_be_bytes()].concat(), header.as_slice()));
            }
            let index = crate::objects::chunk_part(part.index)?;
            items.push(([id, &index.to_be_bytes()].concat(), part.chunk.as_slice()));
        }
        let mut nonces = Vec::with_capacity(items.len());
        for _ in &items {
            nonces.push(self.platform.nonce::<24>()?);
        }
        let bytes = items.iter().map(|(_, value)| value.len()).sum();
        let (store_keys, log_keys) = (&self.keys, &self.log);
        crate::parallel::map(
            items.into_iter().zip(nonces).collect(),
            bytes,
            |((item, value), nonce)| {
                seal_record_with(
                    store_keys,
                    Some(log_keys),
                    Table::Object,
                    &item,
                    value,
                    &nonce,
                )
                .map(|sealed| (sealed.address.to_vec(), sealed.record))
                .map_err(Error::class)
            },
        )
        .into_iter()
        .collect()
    }

    /// Commits sealed records on their own.
    pub async fn commit(&self, puts: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        if puts.is_empty() {
            return Ok(());
        }
        if !self
            .platform
            .store
            .commit(&Commit::new(puts, Vec::new()))
            .await?
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Deletes records this writer committed, best effort.
    pub async fn forget(&self, addresses: Vec<Vec<u8>>) -> Result<()> {
        self.platform
            .store
            .commit(&Commit::new(Vec::new(), addresses))
            .await?;
        Ok(())
    }

    /// Whether the vault still keeps the log under the keys this writer
    /// sealed with.
    pub fn is_current(&self, vault: &Vault) -> bool {
        vault
            .logs
            .get(self.log.id())
            .is_some_and(|(_, keys)| *keys == self.log)
            && !vault.is_memory_only(self.log.id())
    }
}

/// The device's store, unlocked.
pub(crate) struct Vault {
    platform: Platform,
    keys: StoreKeys,
    device: DeviceId,
    head: Head,
    /// The head record as the store holds it: the precondition of the next
    /// commit that advances the head.
    head_record: Option<Vec<u8>>,
    logs: BTreeMap<[u8; 32], (LogKind, LogKeys)>,
    continuity: Continuity,
    /// Logs kept in memory only (ext-guests.md, "Nothing at rest"): none of
    /// their records, and no tip of them, reach the store.
    #[cfg(feature = "ext-guests")]
    memory_only: std::collections::BTreeSet<[u8; 32]>,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("device", &self.device)
            .field("generation", &self.head.generation)
            .field("logs", &self.logs.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Makes the store of a new device: its head, at generation 1, and the
    /// mark, before the device first signs (at-rest.md, "Continuity").
    pub async fn create(
        platform: Platform,
        store_secret: &[u8; 32],
        device: DeviceId,
    ) -> Result<Self> {
        let keys = StoreKeys::new(store_secret);
        let head = Head::new(platform.nonce::<16>()?);
        let mut vault = Self {
            platform,
            keys,
            device,
            head,
            head_record: None,
            logs: BTreeMap::new(),
            continuity: Continuity::Current,
            #[cfg(feature = "ext-guests")]
            memory_only: std::collections::BTreeSet::new(),
        };
        if let Some(existing) = vault.read_head().await? {
            // Keys that open with a head already: another store under the
            // same keys. Refuse to overwrite it.
            let _ = existing;
            return Err(Error::Conflict);
        }
        vault.write_mark(vault.head.generation).await?;
        let mut batch = Batch::default();
        vault.put_head(&mut batch)?;
        vault.commit_raw(batch, None).await?;
        Ok(vault)
    }

    /// Opens the store of an existing device, runs `continuity` and, on a
    /// restore, records it (at-rest.md, "After a restore", step 1).
    pub async fn open(
        platform: Platform,
        store_secret: &[u8; 32],
        device: DeviceId,
    ) -> Result<Self> {
        let keys = StoreKeys::new(store_secret);
        let mut vault = Self {
            platform,
            keys,
            device,
            head: Head::new([0; 16]),
            head_record: None,
            logs: BTreeMap::new(),
            continuity: Continuity::Current,
            #[cfg(feature = "ext-guests")]
            memory_only: std::collections::BTreeSet::new(),
        };
        let head = vault.read_head().await?;
        // A store made under another revision is refused whole,
        // before continuity reads it or anything is written (at-rest.md,
        // "Continuity").
        if let Some(head) = &head
            && head.check_revision().is_err()
        {
            return Err(Error::IncompatibleData);
        }
        let mark = match &vault.platform.slot {
            Some(slot) => slot.read().await?,
            None => None,
        };
        let found = continuity(
            &vault.keys,
            &vault.device,
            vault.platform.restore_mode,
            head.as_ref(),
            mark.as_deref(),
        );
        vault.continuity = found;
        match (found, head) {
            (Continuity::Current, Some(head)) => vault.head = head,
            (_, head) => {
                // A lost store has no head: a new head under a new store
                // ID, at generation 0 before the restore is recorded.
                let head = match head {
                    Some(head) => head,
                    None => {
                        let mut fresh = Head::new(vault.platform.nonce::<16>()?);
                        fresh.generation = 0;
                        fresh
                    }
                };
                let mark_generation = mark
                    .as_deref()
                    .and_then(|mark| open_mark(&vault.keys, &vault.device, mark).ok())
                    .map(|(_, generation)| generation);
                vault.head = after_restore(&head, mark_generation);
                vault.write_mark(vault.head.generation).await?;
                let mut batch = Batch::default();
                vault.put_head(&mut batch)?;
                vault.commit_raw(batch, None).await?;
            }
        }
        vault.load_logs().await?;
        Ok(vault)
    }

    /// What `continuity` found when the store was opened.
    pub fn continuity(&self) -> Continuity {
        self.continuity
    }

    /// The head as the device holds it.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// The logs the device keeps, with their kinds.
    pub fn logs(&self) -> impl Iterator<Item = (&[u8; 32], LogKind)> {
        self.logs.iter().map(|(id, (kind, _))| (id, *kind))
    }

    /// `app_key(K, purpose)` (at-rest.md, "Application keys"): under the
    /// store secret for `None`, under a log's key otherwise; `None` for a
    /// log the store does not hold.
    pub fn app_key(
        &self,
        log: Option<&[u8; 32]>,
        purpose: &[u8],
    ) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        match log {
            None => Some(self.keys.app_key(purpose)),
            Some(log) => self.logs.get(log).map(|(_, keys)| keys.app_key(purpose)),
        }
    }

    /// Whether the device keeps a log.
    pub fn has_log(&self, log: &[u8; 32]) -> bool {
        self.logs.contains_key(log)
    }

    async fn read_head(&self) -> Result<Option<Head>> {
        let address = self
            .keys
            .address(Table::Head, &[])
            .expect("the head is device-wide");
        let Some(record) = self.platform.store.get(&address).await? else {
            return Ok(None);
        };
        match open_record(&self.keys, None, &address, &record) {
            Ok(opened) => match opened.value {
                TableValue::Head(head) => Ok(Some(head)),
                _ => Ok(None),
            },
            // A record that does not open is treated as missing.
            Err(_) => Ok(None),
        }
    }

    async fn load_logs(&mut self) -> Result<()> {
        let records = self.platform.store.scan(&DEVICE_SCOPE).await?;
        let head_address = self.keys.address(Table::Head, &[]).expect("device-wide");
        for (address, record) in records {
            if address == head_address.to_vec() {
                self.head_record = Some(record);
                continue;
            }
            if address.get(16) != Some(&Table::Log.code()) {
                continue;
            }
            let Ok(opened) = open_record(&self.keys, None, &address, &record) else {
                continue;
            };
            let (TableValue::Log(log), Ok(id)) =
                (opened.value, <[u8; 32]>::try_from(&opened.item[..]))
            else {
                continue;
            };
            let keys = self.keys.log(&id, log.log_key.expose());
            self.logs.insert(id, (log.kind, keys));
        }
        Ok(())
    }

    /// The mark for a generation, written to the device-bound slot in mode
    /// `device-bound`.
    async fn write_mark(&self, generation: u64) -> Result<()> {
        if !self.platform.restore_mode.writes_mark() {
            return Ok(());
        }
        let Some(slot) = &self.platform.slot else {
            return Ok(());
        };
        let mark = seal_mark_with(
            &self.keys,
            &self.device,
            &self.head.store_id,
            generation,
            &self.platform.nonce::<24>()?,
        );
        slot.write(&mark).await?;
        Ok(())
    }

    fn put_head(&self, batch: &mut Batch) -> Result<()> {
        let value = TableValue::Head(self.head.clone()).encode();
        let (address, record) = self.seal(None, Table::Head, &[], &value)?;
        batch.puts.push((address, record));
        Ok(())
    }

    /// Seals a record: `log` names the log of a log's table.
    pub fn seal(
        &self,
        log: Option<&[u8; 32]>,
        table: Table,
        item: &[u8],
        value: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let log_keys = match log {
            Some(id) => Some(&self.logs.get(id).ok_or(Error::UnknownSpace)?.1),
            None => None,
        };
        let sealed = seal_record_with(
            &self.keys,
            log_keys,
            table,
            item,
            value,
            &self.platform.nonce::<24>()?,
        )
        .map_err(Error::class)?;
        Ok((sealed.address.to_vec(), sealed.record))
    }

    /// Keeps a log in memory only from now on, and forgets what the store
    /// holds of it (ext-guests.md, "Nothing at rest"; at-rest.md, "A
    /// memory-only log").
    #[cfg(feature = "ext-guests")]
    pub async fn keep_in_memory(&mut self, log: &[u8; 32]) -> Result<()> {
        if self.memory_only.insert(*log) {
            self.forget(log).await?;
        }
        Ok(())
    }

    /// Whether a log is kept in memory only.
    pub fn is_memory_only(&self, log: &[u8; 32]) -> bool {
        #[cfg(feature = "ext-guests")]
        return self.memory_only.contains(log);
        #[cfg(not(feature = "ext-guests"))]
        {
            let _ = log;
            false
        }
    }

    /// Seals a record of a log's table into a batch. A memory-only log's
    /// records are left out.
    pub fn put(
        &self,
        batch: &mut Batch,
        log: &[u8; 32],
        table: Table,
        item: &[u8],
        value: &TableValue,
    ) -> Result<()> {
        if self.is_memory_only(log) {
            return Ok(());
        }
        let (address, record) = self.seal(Some(log), table, item, &value.encode())?;
        batch.puts.push((address, record));
        Ok(())
    }

    /// The address of a record of a log's table.
    pub fn address(&self, log: &[u8; 32], table: Table, item: &[u8]) -> Option<Vec<u8>> {
        let (_, keys) = self.logs.get(log)?;
        keys.address(table, item).map(|address| address.to_vec())
    }

    /// Deletes a record of a log's table in a batch.
    pub fn delete(&self, batch: &mut Batch, log: &[u8; 32], table: Table, item: &[u8]) {
        if let Some(address) = self.address(log, table, item) {
            batch.deletes.push(address);
        }
    }

    /// Starts keeping a log: draws its key and puts its `log` record in the
    /// batch (at-rest.md, "Keys, addresses and records").
    pub fn add_log(&mut self, batch: &mut Batch, log: &[u8; 32], kind: LogKind) -> Result<()> {
        if self.logs.contains_key(log) || self.is_memory_only(log) {
            return Ok(());
        }
        let log_key = self.platform.draw::<32>()?;
        let value = TableValue::Log(LogRecord {
            kind,
            log_key: Secret::new(*log_key),
        })
        .encode();
        let (address, record) = self.seal(None, Table::Log, log, &value)?;
        batch.puts.push((address, record));
        let keys = self.keys.log(log, &log_key);
        self.logs.insert(*log, (kind, keys));
        Ok(())
    }

    /// Every record of a log's table that opens, with its item. A record
    /// that does not open is treated as missing (at-rest.md, "Opening a
    /// record").
    pub async fn scan(&self, log: &[u8; 32], table: Table) -> Result<Vec<(Vec<u8>, TableValue)>> {
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(Vec::new());
        };
        // An address is the log's scope tag, the table's code and the
        // item's tag: one table's records are one range.
        let mut prefix = keys.scope_tag().to_vec();
        prefix.push(table.code());
        let records = self.platform.store.scan(&prefix).await?;
        // Opened at once where there are threads.
        let bytes = records.iter().map(|(_, record)| record.len()).sum();
        let store_keys = &self.keys;
        Ok(crate::parallel::map(records, bytes, |(address, record)| {
            open_record(store_keys, Some(keys), &address, &record)
                .ok()
                .map(|opened| (opened.item, opened.value))
        })
        .into_iter()
        .flatten()
        .collect())
    }

    /// [`scan`](Self::scan), each record read with `read` as it opens, in
    /// batches, at once where there are threads: a record's bytes go once
    /// read, so a large table is never held twice. `work` is what each
    /// record counts for against [`crate::parallel::PARALLEL_BYTES`].
    pub async fn scan_reading<R: Send>(
        &self,
        log: &[u8; 32],
        table: Table,
        work: usize,
        read: impl Fn(Vec<u8>, TableValue) -> Option<R> + Sync,
    ) -> Result<Vec<R>> {
        const BATCH: usize = 1024;
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(Vec::new());
        };
        let mut prefix = keys.scope_tag().to_vec();
        prefix.push(table.code());
        let mut records = self.platform.store.scan(&prefix).await?.into_iter();
        let mut out = Vec::new();
        loop {
            let batch: Vec<(Vec<u8>, Vec<u8>)> = records.by_ref().take(BATCH).collect();
            if batch.is_empty() {
                break;
            }
            let store_keys = &self.keys;
            let reads = crate::parallel::map(batch, BATCH * work, |(address, record)| {
                let opened = open_record(store_keys, Some(keys), &address, &record).ok()?;
                drop(record);
                read(opened.item, opened.value)
            });
            out.extend(reads.into_iter().flatten());
        }
        Ok(out)
    }

    /// The addresses of a log's table's records and the lengths of the
    /// records, without reading them.
    pub async fn scan_sizes(&self, log: &[u8; 32], table: Table) -> Result<frasil_store::Sizes> {
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(Vec::new());
        };
        let mut prefix = keys.scope_tag().to_vec();
        prefix.push(table.code());
        Ok(self.platform.store.scan_sizes(&prefix).await?)
    }

    /// A writer of a log's objects that needs no hold on the vault: none
    /// for a log not kept yet, or kept in memory only.
    pub fn object_writer(&self, log: &[u8; 32]) -> Option<ObjectWriter> {
        if self.is_memory_only(log) {
            return None;
        }
        let (_, keys) = self.logs.get(log)?;
        Some(ObjectWriter {
            platform: self.platform.clone(),
            keys: self.keys.clone(),
            log: keys.clone(),
        })
    }

    /// A reader of a log's objects that needs no hold on the vault: the
    /// store and the keys as they are now.
    pub fn object_parts(&self, log: &[u8; 32]) -> Option<ObjectParts> {
        let (_, keys) = self.logs.get(log)?;
        Some(ObjectParts {
            store: Arc::clone(&self.platform.store),
            keys: self.keys.clone(),
            log: keys.clone(),
        })
    }

    /// Reads and opens the record of a log at an address: its item and
    /// value, or none when it is missing or does not open.
    pub async fn get_at(
        &self,
        log: &[u8; 32],
        address: &[u8],
    ) -> Result<Option<(Vec<u8>, TableValue)>> {
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(None);
        };
        let Some(record) = self.platform.store.get(address).await? else {
            return Ok(None);
        };
        Ok(open_record(&self.keys, Some(keys), address, &record)
            .ok()
            .map(|opened| (opened.item, opened.value)))
    }

    /// Reads one record of a log's table, by its item: none when it is
    /// missing or does not open.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub async fn get(
        &self,
        log: &[u8; 32],
        table: Table,
        item: &[u8],
    ) -> Result<Option<TableValue>> {
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(None);
        };
        let Some(address) = keys.address(table, item) else {
            return Ok(None);
        };
        let Some(record) = self.platform.store.get(&address).await? else {
            return Ok(None);
        };
        Ok(open_record(&self.keys, Some(keys), &address, &record)
            .ok()
            .map(|opened| opened.value))
    }

    /// Reads one device-wide record.
    pub async fn get_device(&self, table: Table) -> Result<Option<TableValue>> {
        let Some(address) = self.keys.address(table, &[]) else {
            return Ok(None);
        };
        let Some(record) = self.platform.store.get(&address).await? else {
            return Ok(None);
        };
        Ok(open_record(&self.keys, None, &address, &record)
            .ok()
            .map(|opened| opened.value))
    }

    /// The address of an item of a device-wide table.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub fn device_address(&self, table: Table, item: &[u8]) -> Option<Vec<u8>> {
        self.keys
            .address(table, item)
            .map(|address| address.to_vec())
    }

    /// Every record of a device-wide table that opens, with its item. A
    /// record that does not open is treated as missing (at-rest.md,
    /// "Opening a record").
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub async fn scan_device(&self, table: Table) -> Result<Vec<(Vec<u8>, TableValue)>> {
        let mut prefix = vec![0; 16];
        prefix.push(table.code());
        let records = self.platform.store.scan(&prefix).await?;
        Ok(records
            .into_iter()
            .filter_map(|(address, record)| {
                open_record(&self.keys, None, &address, &record)
                    .ok()
                    .map(|opened| (opened.item, opened.value))
            })
            .collect())
    }

    /// Reads one record of a device-wide table, by its item.
    #[cfg_attr(
        not(all(
            feature = "ext-deposit-tokens",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        )),
        allow(dead_code)
    )]
    pub async fn get_device_item(&self, table: Table, item: &[u8]) -> Result<Option<TableValue>> {
        let Some(address) = self.device_address(table, item) else {
            return Ok(None);
        };
        let Some(record) = self.platform.store.get(&address).await? else {
            return Ok(None);
        };
        Ok(open_record(&self.keys, None, &address, &record)
            .ok()
            .map(|opened| opened.value))
    }

    /// Seals a record of a device-wide table into a batch.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub fn put_device(
        &self,
        batch: &mut Batch,
        table: Table,
        item: &[u8],
        value: &TableValue,
    ) -> Result<()> {
        let (address, record) = self.seal(None, table, item, &value.encode())?;
        batch.puts.push((address, record));
        Ok(())
    }

    /// Deletes a record of a device-wide table in a batch.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub fn delete_device(&self, batch: &mut Batch, table: Table, item: &[u8]) {
        if let Some(address) = self.device_address(table, item) {
            batch.deletes.push(address);
        }
    }

    /// Puts the reading the device keeps in `timeline` (overview.md, "The
    /// local timeline"), in a commit of its own.
    pub async fn keep_reading(&mut self, reading: &Reading) -> Result<()> {
        let mut batch = Batch::default();
        self.keep_reading_in(&mut batch, reading)?;
        self.commit(batch).await
    }

    /// Keeps a reading of the timeline at rest in a batch.
    pub fn keep_reading_in(&self, batch: &mut Batch, reading: &Reading) -> Result<()> {
        let value = TableValue::Timeline(*reading).encode();
        let (address, record) = self.seal(None, Table::Timeline, &[], &value)?;
        batch.puts.push((address, record));
        Ok(())
    }

    /// Commits a batch as one atomic step. A batch that moves a tip or
    /// signs advances the head; one that signs writes the mark first.
    pub async fn commit(&mut self, mut batch: Batch) -> Result<()> {
        if batch.is_empty() && !batch.signs {
            return Ok(());
        }
        let advances = batch.signs || !batch.tips.is_empty() || !batch.synced.is_empty();
        if !advances {
            return self.commit_raw(batch, None).await;
        }
        let mut head = self.head.clone();
        // A memory-only log has no tip in the head.
        for tip in batch.tips.iter().filter(|t| !self.is_memory_only(&t.log)) {
            head.set_tip(*tip).map_err(Error::class)?;
        }
        for log in &batch.synced {
            head.add_synced(log);
        }
        if batch.signs {
            head.generation = head.generation.saturating_add(1);
            // Mark before commit.
            self.write_mark(head.generation).await?;
        }
        let expected = self.head_record.clone();
        let previous = std::mem::replace(&mut self.head, head);
        if let Err(error) = self.put_head(&mut batch) {
            self.head = previous;
            return Err(error);
        }
        match self.commit_raw(batch, Some(expected)).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.head = previous;
                Err(error)
            }
        }
    }

    /// One store commit. With `expect`, the head record must be the one
    /// named (or none); the new head record becomes the next precondition.
    async fn commit_raw(&mut self, batch: Batch, expect: Option<Option<Vec<u8>>>) -> Result<()> {
        let head_address = self
            .keys
            .address(Table::Head, &[])
            .expect("device-wide")
            .to_vec();
        let new_head = batch
            .puts
            .iter()
            .find(|(address, _)| *address == head_address)
            .map(|(_, record)| record.clone());
        let mut commit = Commit::new(batch.puts, batch.deletes);
        if let Some(expected) = expect {
            commit = commit.expecting(&head_address, expected.as_deref());
        }
        if !self.platform.store.commit(&commit).await? {
            return Err(Error::Conflict);
        }
        if let Some(record) = new_head {
            self.head_record = Some(record);
        }
        Ok(())
    }

    /// Drops a log for the device's own erasure of it (at-rest.md, 3.4, "A
    /// device's own erasure"): one commit deletes every record of the log
    /// but those of the tables in `keep` and the `records` named, and the
    /// store then removes what its file still holds of them. The `log`
    /// record, device-wide, stays, so what is kept still opens. The same
    /// commit replaces `state` with the residue's administering devices.
    pub async fn forget_all_but(
        &self,
        log: &[u8; 32],
        keep: &[Table],
        records: &[(Table, Vec<u8>)],
        state: &frasil_store::tables::LogState,
    ) -> Result<()> {
        let Some((_, keys)) = self.logs.get(log) else {
            return Ok(());
        };
        let scope = keys.scope_tag().to_vec();
        let kept: Vec<u8> = keep.iter().map(|table| table.code()).collect();
        let kept_records: Vec<Vec<u8>> = records
            .iter()
            .filter_map(|(table, item)| keys.address(*table, item).map(|a| a.to_vec()))
            .collect();
        let deletes: Vec<Vec<u8>> = self
            .platform
            .store
            .scan(&scope)
            .await?
            .into_iter()
            .map(|(address, _)| address)
            .filter(|address| {
                address
                    .get(scope.len())
                    .is_none_or(|code| !kept.contains(code))
                    && !kept_records.contains(address)
            })
            .collect();
        let mut batch = Batch::default();
        self.put(
            &mut batch,
            log,
            Table::State,
            &[],
            &TableValue::State(state.clone()),
        )?;
        self.platform
            .store
            .commit(&frasil_store::Commit::new(batch.puts, deletes))
            .await?;
        self.platform.store.scrub().await?;
        Ok(())
    }

    /// Forgets a log (at-rest.md, "Forgetting a log, and re-keying").
    pub async fn forget(&mut self, log: &[u8; 32]) -> Result<()> {
        frasil_store::forget_log(self.platform.store.as_ref(), &self.keys, log).await?;
        self.logs.remove(log);
        Ok(())
    }
}
