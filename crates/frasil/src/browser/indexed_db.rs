//! The at-rest store in IndexedDB (at-rest.md, "What the application
//! provides"), in a page or a worker.
//!
//! The database has two object stores, as `@frasil/client`'s
//! `IndexedDbStore` lays them out, so either opens the other's database:
//!
//! - `records`: each record under its address, a binary key, which
//!   IndexedDB orders bytewise as a scan must;
//! - `keys`: the device's sealed keys under `"device"`.
//!
//! Each commit is one `readwrite` transaction with strict durability,
//! which the browser serialises across the tabs and workers of the origin,
//! so two of them never both advance the device's head from one state.
//! The expectations are read and the writes issued inside the
//! transaction's own callbacks, so it never commits half-way.

use super::message_of;
use crate::client::KeepKeys;
use frasil_store::store::Records;
use frasil_store::{BoxFuture, Commit, Store, StoreError};
use js_sys::{Array, ArrayBuffer, Promise, Reflect, Uint8Array};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    IdbDatabase, IdbFactory, IdbKeyRange, IdbObjectStore, IdbOpenDbRequest, IdbRequest,
    IdbTransaction, IdbTransactionMode,
};

/// The database's version: the one `@frasil/client` opens.
const VERSION: u32 = 2;

/// The object store of the records.
const RECORDS: &str = "records";

/// The object store of the sealed device keys, under [`SEALED`].
const KEYS: &str = "keys";
const SEALED: &str = "device";

fn failed(what: &str, cause: impl Into<String>) -> StoreError {
    StoreError::new(format!("IndexedDB could not {what}: {}", cause.into()))
}

fn thrown(what: &str) -> impl Fn(JsValue) -> StoreError + '_ {
    move |error| failed(what, message_of(&error))
}

/// The global scope's `indexedDB`: a page's or a worker's.
fn factory() -> Result<IdbFactory, StoreError> {
    Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
        .ok()
        .and_then(|value| value.dyn_into::<IdbFactory>().ok())
        .ok_or_else(|| failed("open", "IndexedDB is not available here"))
}

/// Waits for a request to succeed, then gives its result.
async fn result_of(request: &IdbRequest, what: &str) -> Result<JsValue, StoreError> {
    let settled = Promise::new(&mut |resolve, reject| {
        request.set_onsuccess(Some(&resolve));
        request.set_onerror(Some(&reject));
    });
    JsFuture::from(settled).await.map_err(|_| {
        let cause = request
            .error()
            .ok()
            .flatten()
            .map_or_else(|| "the request failed".to_owned(), |e| e.message());
        failed(what, cause)
    })?;
    request.result().map_err(thrown(what))
}

/// Waits for a transaction to commit.
async fn committed(transaction: &IdbTransaction, what: &str) -> Result<(), StoreError> {
    let settled = Promise::new(&mut |resolve, reject| {
        transaction.set_oncomplete(Some(&resolve));
        transaction.set_onabort(Some(&reject));
    });
    JsFuture::from(settled).await.map(drop).map_err(|_| {
        let error = transaction.error();
        let cause = error
            .as_ref()
            .map_or_else(|| "the transaction aborted".to_owned(), |e| e.message());
        // The browser refused the write past the origin's quota: nothing
        // was written, and the device makes room in its cache.
        if error.is_some_and(|e| e.name() == "QuotaExceededError") {
            StoreError::full(format!("IndexedDB could not {what}: {cause}"))
        } else {
            failed(what, cause)
        }
    })
}

/// An address as an IndexedDB key: a binary key, in a buffer of its own.
fn key_of(address: &[u8]) -> JsValue {
    Uint8Array::from(address).buffer().into()
}

/// Bytes kept as a `Uint8Array` or an `ArrayBuffer`.
fn bytes_of(value: &JsValue, what: &str) -> Result<Vec<u8>, StoreError> {
    if let Some(array) = value.dyn_ref::<Uint8Array>() {
        return Ok(array.to_vec());
    }
    if let Some(buffer) = value.dyn_ref::<ArrayBuffer>() {
        return Ok(Uint8Array::new(buffer).to_vec());
    }
    Err(failed(what, "it holds something other than bytes"))
}

/// The first address after every address that starts with `prefix`, if
/// there is one.
fn after(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// The device's store in an IndexedDB database of its own, with its sealed
/// keys beside the records. A device in a browser opens it with
/// [`Storage::indexed_db`](crate::Storage::indexed_db); it is public for
/// an application that builds the [`Platform`](crate::advanced::Platform)
/// itself.
pub struct IndexedDbStore {
    db: IdbDatabase,
}

impl core::fmt::Debug for IndexedDbStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexedDbStore")
            .field("name", &self.db.name())
            .finish()
    }
}

impl Drop for IndexedDbStore {
    fn drop(&mut self) {
        self.db.close();
    }
}

impl IndexedDbStore {
    /// Opens the database `name`, or creates it.
    ///
    /// # Errors
    ///
    /// When IndexedDB is not available, or refuses.
    pub async fn open(name: &str) -> Result<Self, StoreError> {
        let request: IdbOpenDbRequest = factory()?
            .open_with_u32(name, VERSION)
            .map_err(thrown("open"))?;
        let upgrading = request.clone();
        let upgrade = Closure::<dyn FnMut()>::new(move || {
            let Ok(db) = upgrading
                .result()
                .map(JsCast::unchecked_into::<IdbDatabase>)
            else {
                return;
            };
            let names = db.object_store_names();
            for name in [RECORDS, KEYS] {
                if !names.contains(name) {
                    let _ = db.create_object_store(name);
                }
            }
        });
        request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
        let db = result_of(&request, "open").await?;
        request.set_onupgradeneeded(None);
        drop(upgrade);
        let db: IdbDatabase = db.unchecked_into();
        // Another tab or worker that upgrades the database closes this one.
        let closing = db.clone();
        let on_version = Closure::<dyn FnMut()>::new(move || closing.close());
        db.set_onversionchange(Some(on_version.as_ref().unchecked_ref()));
        on_version.forget();
        Ok(Self { db })
    }

    /// Deletes the database `name` and every record in it. Drop every
    /// store and device opened on it first.
    ///
    /// # Errors
    ///
    /// When IndexedDB is not available, or refuses.
    pub async fn delete_database(name: &str) -> Result<(), StoreError> {
        let request = factory()?
            .delete_database(name)
            .map_err(thrown("delete its database"))?;
        result_of(&request, "delete its database").await.map(drop)
    }

    fn transaction(
        &self,
        of: &str,
        mode: IdbTransactionMode,
        what: &str,
    ) -> Result<(IdbTransaction, IdbObjectStore), StoreError> {
        // `{ durability: "strict" }`, which a browser that does not know it
        // ignores.
        let options = js_sys::Object::new();
        Reflect::set(&options, &"durability".into(), &"strict".into()).map_err(thrown(what))?;
        let mode = match mode {
            IdbTransactionMode::Readwrite => "readwrite",
            _ => "readonly",
        };
        let open = Reflect::get(&self.db, &"transaction".into())
            .and_then(|method| method.dyn_into::<js_sys::Function>())
            .map_err(thrown(what))?;
        let transaction: IdbTransaction = open
            .call3(&self.db, &of.into(), &mode.into(), &options)
            .map_err(thrown(what))?
            .unchecked_into();
        let store = transaction.object_store(of).map_err(thrown(what))?;
        Ok((transaction, store))
    }

    /// The device's sealed keys; `None` before a device is made here.
    ///
    /// # Errors
    ///
    /// When IndexedDB refuses.
    pub async fn load_sealed_keys(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let what = "read the device's keys";
        let (_, keys) = self.transaction(KEYS, IdbTransactionMode::Readonly, what)?;
        let request = keys.get(&JsValue::from_str(SEALED)).map_err(thrown(what))?;
        let value = result_of(&request, what).await?;
        if value.is_undefined() {
            return Ok(None);
        }
        bytes_of(&value, what).map(Some)
    }

    /// Keeps the device's sealed keys, durably, in place of any.
    ///
    /// # Errors
    ///
    /// When IndexedDB refuses.
    pub async fn save_sealed_keys(&self, sealed: &[u8]) -> Result<(), StoreError> {
        let what = "keep the device's keys";
        let (transaction, keys) = self.transaction(KEYS, IdbTransactionMode::Readwrite, what)?;
        keys.put_with_key(&Uint8Array::from(sealed), &JsValue::from_str(SEALED))
            .map_err(thrown(what))?;
        committed(&transaction, what).await
    }
}

impl KeepKeys for IndexedDbStore {
    fn keep<'a>(&'a self, sealed: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        Box::pin(async move {
            self.save_sealed_keys(sealed)
                .await
                .map_err(|error| crate::Error::Store(error.to_string()))
        })
    }
}

/// What a commit's callbacks share inside its transaction.
struct Committing {
    records: IdbObjectStore,
    commit: Commit,
    pending: Cell<usize>,
    holds: Cell<bool>,
    written: Cell<bool>,
    failed: RefCell<Option<String>>,
}

impl Committing {
    /// Once every expectation is read: the writes, if every one held.
    fn write(&self) {
        if !self.holds.get() {
            return;
        }
        let result = (|| {
            for address in &self.commit.deletes {
                self.records.delete(&key_of(address))?;
            }
            for (address, record) in &self.commit.puts {
                self.records
                    .put_with_key(&Uint8Array::from(record.as_slice()), &key_of(address))?;
            }
            Ok::<(), JsValue>(())
        })();
        match result {
            Ok(()) => self.written.set(true),
            Err(error) => *self.failed.borrow_mut() = Some(message_of(&error)),
        }
    }
}

impl Store for IndexedDbStore {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            let what = "read a record";
            let (_, records) = self.transaction(RECORDS, IdbTransactionMode::Readonly, what)?;
            let request = records.get(&key_of(address)).map_err(thrown(what))?;
            let value = result_of(&request, what).await?;
            if value.is_undefined() {
                return Ok(None);
            }
            bytes_of(&value, what).map(Some)
        })
    }

    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Records, StoreError>> {
        Box::pin(async move {
            let what = "scan its records";
            let (_, records) = self.transaction(RECORDS, IdbTransactionMode::Readonly, what)?;
            let range = if prefix.is_empty() {
                None
            } else {
                Some(
                    match after(prefix) {
                        Some(end) => IdbKeyRange::bound_with_lower_open_and_upper_open(
                            &key_of(prefix),
                            &key_of(&end),
                            false,
                            true,
                        ),
                        None => IdbKeyRange::lower_bound(&key_of(prefix)),
                    }
                    .map_err(thrown(what))?,
                )
            };
            // Both requests list the range in key order, issued together in
            // one transaction.
            let (keys, values) = match &range {
                Some(range) => (
                    records.get_all_keys_with_key(range),
                    records.get_all_with_key(range),
                ),
                None => (records.get_all_keys(), records.get_all()),
            };
            let keys = keys.map_err(thrown(what))?;
            let values = values.map_err(thrown(what))?;
            let keys: Array = result_of(&keys, what).await?.unchecked_into();
            let values: Array = result_of(&values, what).await?.unchecked_into();
            if keys.length() != values.length() {
                return Err(failed(what, "its keys and values differ in number"));
            }
            let mut found = Vec::with_capacity(keys.length() as usize);
            for (key, value) in keys.iter().zip(values.iter()) {
                found.push((bytes_of(&key, what)?, bytes_of(&value, what)?));
            }
            // The order the store must keep, kept whatever IndexedDB gives.
            found.retain(|(address, _)| address.starts_with(prefix));
            found.sort();
            Ok(found)
        })
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let what = "commit";
            let (transaction, records) =
                self.transaction(RECORDS, IdbTransactionMode::Readwrite, what)?;
            let state = Rc::new(Committing {
                records: records.clone(),
                commit: commit.clone(),
                pending: Cell::new(commit.expect.len()),
                holds: Cell::new(true),
                written: Cell::new(false),
                failed: RefCell::new(None),
            });
            // Each expectation is read and compared in its own callback; the
            // last one writes, while the transaction is still active.
            let mut callbacks = Vec::with_capacity(commit.expect.len());
            if commit.expect.is_empty() {
                state.write();
            }
            for (address, expected) in &commit.expect {
                let request = records.get(&key_of(address)).map_err(thrown(what))?;
                let reading = request.clone();
                let shared = state.clone();
                let expected = expected.clone();
                let callback = Closure::<dyn FnMut()>::new(move || {
                    let held = reading
                        .result()
                        .ok()
                        .filter(|value| !value.is_undefined())
                        .and_then(|value| bytes_of(&value, "commit").ok());
                    if held != expected {
                        shared.holds.set(false);
                    }
                    let left = shared.pending.get().saturating_sub(1);
                    shared.pending.set(left);
                    if left == 0 {
                        shared.write();
                    }
                });
                request.set_onsuccess(Some(callback.as_ref().unchecked_ref()));
                callbacks.push(callback);
            }
            committed(&transaction, what).await?;
            drop(callbacks);
            if let Some(cause) = state.failed.borrow_mut().take() {
                return Err(failed(what, cause));
            }
            Ok(state.holds.get() && state.written.get())
        })
    }
}
