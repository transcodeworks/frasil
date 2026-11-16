//! A device in a dedicated web worker, through the `browser` feature
//! (`frasil::browser`). Runs under wasm-bindgen-test in a headless browser:
//! `scripts/check-browser.sh`.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[path = "browser_common/mod.rs"]
mod common;

#[wasm_bindgen_test]
async fn a_device_keeps_its_spaces_in_indexed_db() {
    common::a_device_keeps_its_spaces_in_indexed_db().await;
}

#[wasm_bindgen_test]
async fn a_device_opens_in_memory() {
    common::a_device_opens_in_memory().await;
}

#[wasm_bindgen_test]
async fn sheet_recovery_keeps_the_person() {
    common::recovery_keeps_the_person(false).await;
}
#[wasm_bindgen_test]
async fn passkey_recovery_keeps_the_person() {
    common::recovery_keeps_the_person(true).await;
}
