//! JavaScript functions that `frasil` calls back: a person's confirmation
//! of an admission code, and progress reports.

use js_sys::{Function, Promise};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

/// Asks `function` whether the person saw `code` on both screens, with the
/// other device's `name`, and waits for its answer: a `boolean`, or a
/// promise of one, so that the page can wait for the person's click. Only
/// `true` confirms; a function that throws or rejects, or answers anything
/// else, declines.
pub(crate) async fn confirm(function: Function, code: String, name: String) -> bool {
    let Ok(answer) = function.call2(
        &JsValue::NULL,
        &JsValue::from_str(&code),
        &JsValue::from_str(&name),
    ) else {
        return false;
    };
    JsFuture::from(Promise::resolve(&answer))
        .await
        .ok()
        .and_then(|answer| answer.as_bool())
        == Some(true)
}

/// A progress report to `function`, if given: `(done, total)`, `total`
/// `undefined` when unknown. What the function throws is ignored.
pub(crate) fn progress(function: Option<Function>) -> impl FnMut(u64, Option<u64>) {
    move |done: u64, total: Option<u64>| {
        if let Some(function) = &function {
            #[allow(clippy::cast_precision_loss)]
            let total = total.map_or(JsValue::UNDEFINED, |total| JsValue::from_f64(total as f64));
            #[allow(clippy::cast_precision_loss)]
            let _ = function.call2(&JsValue::NULL, &JsValue::from_f64(done as f64), &total);
        }
    }
}
