//! Deposit tokens in a browser page (ext-deposit-tokens.md): a device
//! handed a grant draws a batch over the browser's own WebSocket, on a
//! connection of its own, and pays with one token for a deposit, against
//! the live peer `scripts/check-browser.sh` starts with the extension on and
//! the issuer below trusted. Runs under wasm-bindgen-test in a headless
//! browser.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use frasil::advanced::ManualClock;
use frasil::{Device, Options, Storage};
use frasil_libraries::{Issuer, LibraryId};
use std::sync::Arc;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The peer `scripts/check-browser.sh` starts with deposit tokens on.
const PEER: &str = "http://127.0.0.1:18788";

/// The seed of the issuer that peer trusts (`FRASIL_LIBRARY_ISSUERS`).
const ISSUER: [u8; 32] = [0x1d; 32];

#[wasm_bindgen_test]
async fn a_browser_draws_tokens_and_pays_for_a_deposit() {
    let wall = (js_sys::Date::now() / 1000.0) as u64;
    let clock = Arc::new(ManualClock::new(1_000, Some(wall)));
    let device = Device::open_with(
        Storage::Memory,
        &[0x19; 32],
        Options::new().clock(clock.clone()),
    )
    .await
    .unwrap();
    let grant = Issuer::from_seed(&ISSUER)
        .issue_grant_with(
            &LibraryId::new("personal:browser").unwrap(),
            16,
            wall,
            wall + 3_600,
            [1; 16],
        )
        .unwrap();
    device.give_deposit_grant(PEER, grant);
    // A draw comes at a random moment in the next hour, never at once.
    device.deposit_upkeep().await;
    assert_eq!(device.deposit_tokens(PEER).await.held, 0);
    clock.advance(3_601);
    device.deposit_upkeep().await;
    let tokens = device.deposit_tokens(PEER).await;
    assert_eq!(tokens.held, 16, "{tokens:?}");
    assert!(!tokens.grant);
    // A deposit pays with one, and the peer takes it.
    device
        .deposit_item(PEER, device.id(), b"a sealed welcome".to_vec())
        .await
        .unwrap();
    assert_eq!(device.deposit_tokens(PEER).await.held, 15);
    assert_eq!(device.waiting_deposits().await, 0);
}
