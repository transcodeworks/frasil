//! frasil-relay's deposit-token records at rest on arbitrary bytes
//! (ext-deposit-tokens.md, 2.7 What a peer keeps): a deposit key's record
//! and a spent token's, spent or reserved. No reader panics, and a record
//! that reads is in its one encoding, so it writes back to the same bytes.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/deposit/records.rs"]
mod records;

use libfuzzer_sys::fuzz_target;
use records::{KeyRecord, SEALED_BYTES, SpentState};

fuzz_target!(|data: &[u8]| {
    if let Some(key) = KeyRecord::decode(data) {
        assert_eq!(key.encode(), data, "a second encoding of a key record");
        assert_eq!(key.sealed.len(), SEALED_BYTES);
        assert!((1..=2).contains(&key.role));
    }
    if let Some(state) = SpentState::decode(data) {
        assert_eq!(state.encode(), data, "a second encoding of a spent token");
    }
});
