//! A device in a browser or a web worker, for a Rust application compiled
//! to `wasm32-unknown-unknown` with the `browser` feature.
//!
//! A device opens as it does natively, and takes the browser's tasks,
//! timers, clocks and connections by default:
//!
//! ```ignore
//! use frasil::{Device, Storage};
//!
//! let device = Device::open(Storage::indexed_db("my-app-frasil"), &unlock_key).await?;
//! let space = device.create_space().await?;
//! device.connect("https://peer.example.org").await?;
//! ```
//!
//! - [`Storage::indexed_db`](crate::Storage::indexed_db) keeps the store
//!   and the sealed device keys in an IndexedDB database of their own
//!   ([`IndexedDbStore`]), the layout `@frasil/client`'s `IndexedDbStore`
//!   uses. [`Storage::Memory`](crate::Storage::Memory) keeps nothing.
//! - A browser has no place that no backup restores, so the store's restore
//!   mode is `never-restored` (at-rest.md, "Continuity").
//! - Background work runs on the event loop ([`BrowserTasks`]), timers on
//!   `setTimeout`, and the clocks are `performance.now()` and `Date.now()`
//!   ([`BrowserClock`]).
//! - [`Device::connect`](crate::Device::connect) opens the server binding
//!   over the browser's `WebSocket` and `fetch` ([`BrowserConnect`]); a
//!   browser has no member connections or local discovery.
//!
//! Everything here runs on the thread that opened the device: a page's
//! main thread or one worker's.

mod clock;
mod indexed_db;
mod socket;

pub use clock::BrowserClock;
pub use indexed_db::IndexedDbStore;
pub use socket::{BrowserConnect, BrowserSocket, BrowserTasks, open as open_socket, sleep};

use crate::platform::{OsRandom, Platform};
use frasil_store::{RestoreMode, Store};
use std::sync::Arc;
use wasm_bindgen::{JsCast, JsValue};

/// The message of what JavaScript threw or rejected with.
pub fn message_of(thrown: &JsValue) -> String {
    if let Some(error) = thrown.dyn_ref::<js_sys::Error>() {
        return String::from(error.message());
    }
    if let Some(error) = thrown.dyn_ref::<web_sys::DomException>() {
        return error.message();
    }
    thrown
        .as_string()
        .unwrap_or_else(|| "a JavaScript value that is not an Error".into())
}

/// A browser device's platform over `store`: no device-bound slot, restore
/// mode `never-restored`, the browser's clocks with the wall clock known,
/// and `crypto.getRandomValues`.
pub fn platform(store: Arc<dyn Store>) -> Platform {
    Platform {
        store,
        slot: None,
        restore_mode: RestoreMode::NeverRestored,
        clock: Arc::new(BrowserClock::default()),
        random: Arc::new(OsRandom),
        streams_only: false,
    }
}
