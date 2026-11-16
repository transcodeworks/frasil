//! The browser's clocks (overview.md, "Clocks"): `performance.now()` for
//! the monotonic clock, and `Date.now()` for the wall clock.

use crate::platform::Clock;
use js_sys::{Function, Reflect};
use wasm_bindgen::{JsCast, JsValue};

/// The browser's clocks: `performance.now()`, counted from when the clock
/// was made, and `Date.now()`, which counts as known unless the
/// application says otherwise. A device in a browser takes it by default.
#[derive(Debug, Clone, Copy)]
pub struct BrowserClock {
    origin: f64,
    wall_known: bool,
}

/// `performance.now()` in milliseconds, or `Date.now()` where the global
/// scope has no `performance`.
fn performance_now() -> f64 {
    let global = js_sys::global();
    Reflect::get(&global, &JsValue::from_str("performance"))
        .ok()
        .filter(|performance| performance.is_object())
        .and_then(|performance| {
            let now = Reflect::get(&performance, &JsValue::from_str("now")).ok()?;
            now.dyn_into::<Function>()
                .ok()?
                .call0(&performance)
                .ok()?
                .as_f64()
        })
        .unwrap_or_else(js_sys::Date::now)
}

impl BrowserClock {
    /// The clocks, with the monotonic clock counted from now and the wall
    /// clock known or not as `wall_known` says.
    pub fn new(wall_known: bool) -> Self {
        Self {
            origin: performance_now(),
            wall_known,
        }
    }
}

impl Default for BrowserClock {
    /// The clocks, with the wall clock known.
    fn default() -> Self {
        Self::new(true)
    }
}

impl Clock for BrowserClock {
    fn monotonic(&self) -> u64 {
        let elapsed = (performance_now() - self.origin) / 1000.0;
        if elapsed.is_finite() && elapsed > 0.0 {
            elapsed as u64
        } else {
            0
        }
    }

    fn wall(&self) -> Option<u64> {
        let seconds = js_sys::Date::now() / 1000.0;
        (self.wall_known && seconds.is_finite() && seconds > 0.0).then_some(seconds as u64)
    }
}
