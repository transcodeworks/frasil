//! What a device runs on in a browser (at-rest.md, "What the application
//! provides"; overview.md, "Clocks").
//!
//! - **The store** is a JavaScript object the application supplies, with
//!   three methods, each returning a value or a promise of one:
//!   - `get(address)`: the record at an address (`Uint8Array`), or
//!     `undefined`;
//!   - `scan(prefix)`: every `[address, record]` pair whose address starts
//!     with `prefix`, in bytewise address order;
//!   - `commit({ expect, puts, deletes })`: if every `[address, record]`
//!     of `expect` holds (`record` `null` for nothing), deletes then puts
//!     in one atomic, durable step and answers `true`; otherwise changes
//!     nothing and answers `false`.
//!
//!   The package's `IndexedDbStore` is one, with every commit one IndexedDB
//!   transaction. A store that throws or rejects fails as `store`. Its
//!   `saveSealedKeys(sealed)` keeps the device's keys when `makePerson`
//!   seals them again ([`JsKeys`]).
//! - **The restore mode** is `never-restored` by default: a browser has no
//!   place that no backup restores, and at-rest.md lets an application
//!   state that its browser storage is never restored. `none` makes every
//!   start count as a restore.
//! - **The clocks** are the browser's: `performance.now()` for the
//!   monotonic clock, and `Date.now()` for the wall clock, which counts as
//!   known unless the application says otherwise.
//! - **Randomness** is `crypto.getRandomValues`, through `frasil-crypto`.

use crate::convert::{bytes, bytes_in, field};
use frasil::advanced::{KeepKeys, OsRandom, Platform, RestoreMode};
use frasil::browser::BrowserClock;
use frasil_store::store::Records;
use frasil_store::{BoxFuture, Commit, Store, StoreError};
use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use std::sync::Arc;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

pub(crate) use frasil::browser::message_of;

/// Calls `object[name](...args)` and waits for its value, which may be a
/// promise.
async fn call(object: &JsValue, name: &str, args: &[JsValue]) -> Result<JsValue, String> {
    let method = Reflect::get(object, &JsValue::from_str(name)).map_err(|e| message_of(&e))?;
    let method = method
        .dyn_into::<Function>()
        .map_err(|_| format!("the store has no method `{name}`"))?;
    let arguments: Array = args.iter().collect();
    let value = method
        .apply(object, &arguments)
        .map_err(|e| message_of(&e))?;
    JsFuture::from(Promise::resolve(&value))
        .await
        .map_err(|e| message_of(&e))
}

/// Where the device's sealed keys are kept: the application store's
/// `saveSealedKeys(sealed)`, in place of those kept before.
pub(crate) struct JsKeys {
    object: JsValue,
}

impl JsKeys {
    /// The keys kept through the store `object`.
    pub(crate) fn new(object: JsValue) -> Self {
        Self { object }
    }
}

impl KeepKeys for JsKeys {
    fn keep<'a>(&'a self, sealed: &'a [u8]) -> BoxFuture<'a, frasil::Result<()>> {
        Box::pin(async move {
            call(&self.object, "saveSealedKeys", &[bytes(sealed)])
                .await
                .map(drop)
                .map_err(frasil::Error::Store)
        })
    }
}

/// The store the application supplies from JavaScript.
pub struct JsStore {
    object: JsValue,
}

impl JsStore {
    /// The store `object`, whose methods are checked when first called.
    pub fn new(object: JsValue) -> Self {
        Self { object }
    }
}

fn failed(message: String) -> StoreError {
    StoreError::new(message)
}

fn pairs(value: &JsValue) -> Result<Records, StoreError> {
    let array = value
        .dyn_ref::<Array>()
        .ok_or_else(|| failed("scan answered something other than an array".into()))?;
    array
        .iter()
        .map(|pair| {
            let address = bytes_in(&Reflect::get_u32(&pair, 0).unwrap_or_default());
            let record = bytes_in(&Reflect::get_u32(&pair, 1).unwrap_or_default());
            address
                .zip(record)
                .ok_or_else(|| failed("scan answered a pair that is not two Uint8Arrays".into()))
        })
        .collect()
}

fn pair(address: &[u8], record: Option<&[u8]>) -> JsValue {
    Array::of2(&bytes(address), &record.map_or(JsValue::NULL, bytes)).into()
}

impl Store for JsStore {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async move {
            let value = call(&self.object, "get", &[bytes(address)])
                .await
                .map_err(failed)?;
            if value.is_undefined() || value.is_null() {
                return Ok(None);
            }
            bytes_in(&value)
                .map(Some)
                .ok_or_else(|| failed("get answered something other than a Uint8Array".into()))
        })
    }

    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Records, StoreError>> {
        Box::pin(async move {
            let value = call(&self.object, "scan", &[bytes(prefix)])
                .await
                .map_err(failed)?;
            let mut found = pairs(&value)?;
            // The order the store must keep, kept whatever it answers.
            found.retain(|(address, _)| address.starts_with(prefix));
            found.sort();
            Ok(found)
        })
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let expect: Array = commit
                .expect
                .iter()
                .map(|(address, record)| pair(address, record.as_deref()))
                .collect();
            let puts: Array = commit
                .puts
                .iter()
                .map(|(address, record)| pair(address, Some(record)))
                .collect();
            let deletes: Array = commit
                .deletes
                .iter()
                .map(|address| JsValue::from(Uint8Array::from(address.as_slice())))
                .collect();
            let argument = crate::convert::Obj::new()
                .set("expect", expect)
                .set("puts", puts)
                .set("deletes", deletes)
                .build();
            let value = call(&self.object, "commit", &[argument])
                .await
                .map_err(failed)?;
            value
                .as_bool()
                .ok_or_else(|| failed("commit answered something other than a boolean".into()))
        })
    }
}

/// The device's platform over the application's store, from its options:
/// `restoreMode` (`"never-restored"`, the default, or `"none"`) and
/// `wallClockKnown` (default `true`).
pub(crate) fn platform(store: JsValue, options: &JsValue) -> Result<Platform, JsValue> {
    let option = |key: &str| {
        if options.is_object() {
            field(options, key)
        } else {
            Ok(JsValue::UNDEFINED)
        }
    };
    let restore_mode = match option("restoreMode")?.as_string().as_deref() {
        None | Some("never-restored") => RestoreMode::NeverRestored,
        Some("none") => RestoreMode::None,
        Some(_) => {
            return Err(crate::error::invalid(
                "restoreMode is \"never-restored\" or \"none\": a browser has no device-bound slot.",
            ));
        }
    };
    let wall_known = option("wallClockKnown")?.as_bool().unwrap_or(true);
    if !store.is_object() {
        return Err(crate::error::invalid(
            "the store is an object with get, scan and commit.",
        ));
    }
    // A browser runs this module on one thread: the Arcs only satisfy the
    // platform's types.
    #[allow(clippy::arc_with_non_send_sync)]
    let store: Arc<dyn Store> = Arc::new(JsStore::new(store));
    Ok(Platform {
        store,
        slot: None,
        restore_mode,
        clock: Arc::new(BrowserClock::new(wall_known)),
        random: Arc::new(OsRandom),
        streams_only: false,
    })
}
