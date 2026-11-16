//! What happens when Rust panics.
//!
//! On `wasm32-unknown-unknown` a panic aborts: the module traps with
//! `RuntimeError: unreachable`, and its state (every key it holds, every
//! lock it had taken) stays as it was. A synchronous call throws that error
//! to its caller. An asynchronous one traps in a microtask, so its promise
//! never settles.
//!
//! The hook installed at start logs the panic's message and location to the
//! console, then tells the listener registered with [`on_panic`], which the
//! TypeScript layer uses to reject every call in flight and refuse later
//! ones.

use std::cell::RefCell;
use std::panic::PanicHookInfo;

use js_sys::Function;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

thread_local! {
    static LISTENER: RefCell<Option<Function>> = const { RefCell::new(None) };
}

fn hook(info: &PanicHookInfo<'_>) {
    let message = format!("Frasil: {info}");
    console_error(&message);
    LISTENER.with(|listener| {
        if let Ok(listener) = listener.try_borrow()
            && let Some(listener) = listener.as_ref()
        {
            let _ = listener.call1(&JsValue::NULL, &JsValue::from_str(&message));
        }
    });
}

/// Installs the panic hook when the module is instantiated.
#[wasm_bindgen(start)]
pub fn start() {
    std::panic::set_hook(Box::new(hook));
}

/// Calls `listener(message)` when Rust panics, just before the module
/// traps. One listener at a time; a later call replaces it. The listener
/// must not call into this module.
#[wasm_bindgen(js_name = onPanic)]
pub fn on_panic(listener: Function) {
    LISTENER.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = Some(listener);
        }
    });
}
