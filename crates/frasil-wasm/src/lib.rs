//! Frasil's client for browsers, through wasm-bindgen.
//!
//! Specified by every core document; `docs/spec/overview.md`, section 7
//! (Conformance), lists them. It binds the server binding of
//! `docs/spec/transport.md`, section 3.15 (The server binding), over the
//! browser's WebSocket and `fetch`.
//!
//! It adapts types and decides nothing: each class wraps the `frasil`
//! type of its name, each method converts its arguments from JavaScript's
//! shapes, calls `frasil`, and converts the result or the error back. The
//! npm package in `packages/frasil` builds this crate with `wasm-bindgen`
//! and puts a TypeScript layer on it; applications use that package, not
//! this crate's generated code.
//!
//! - [`device`]: `frasil::Device`, running its upkeep on the browser's
//!   event loop, and the engine's direct grant, which the TypeScript layer
//!   gathers under `device.advanced`.
//! - [`space`], [`streams`], [`peer`] and [`events`]: `frasil::Space`; its
//!   `Document`, `Records` and `Blobs`; `frasil::Peer`; `frasil::Events`.
//!   Asynchronous methods return promises; each clones its `frasil` handle
//!   into its future, so no future borrows a JavaScript object.
//! - [`platform`]: what the device runs on in a browser: the store the
//!   application supplies from JavaScript (IndexedDB, in the package), the
//!   browser's clocks, and `crypto.getRandomValues` (at-rest.md, "What the
//!   application provides"; overview.md, "Clocks").
//! - [`socket`]: the server binding's WebSocket and object routes over the
//!   browser's `WebSocket` and `fetch`, with tasks and timers on the
//!   browser's event loop.
//! - [`error`]: errors thrown as a JavaScript `Error` named `FrasilError`,
//!   with a stable `code`, the specification's `class` where a check
//!   failed (overview.md, "Error classes"), and `whatToDo`.
//! - [`panic`]: the panic hook.
//! - [`requests`]: signed application requests, verified by a server.
//!
//! Admission by code (admission.md, "Nearby pairing") needs a nearby
//! connection, which a browser does not have: this build has no
//! `Space::invite`. A browser joins through an exchange mailbox at a peer
//! (`Device::join_via_peer`, `Space::admit`) or an invite link
//! (`Space::invite_link`, `Device::join`).
//!
//! On any target but `wasm32-unknown-unknown` the crate is empty.
//!
//! A panic in WebAssembly traps and takes the module, and every key it
//! holds, with it. This crate therefore writes no code that can panic, and
//! Clippy enforces it.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod callback;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod checkpoints;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod convert;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod device;
#[allow(unused)]
pub mod drive;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod error;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod events;
#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "index"))]
pub mod index;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod panic;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod peer;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod platform;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod reads;
#[allow(unused)]
pub mod references;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod requests;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod space;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod space_file;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod streams;

/// A promise for `future`, which owns everything it uses.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn promise(
    future: impl std::future::Future<Output = Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>>
    + 'static,
) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(future)
}
