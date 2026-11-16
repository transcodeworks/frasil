//! frasil-deposit-tokens' `TokenKeysGet` reader on arbitrary bytes
//! (ext-deposit-tokens.md, 2.5 Messages). It never panics, and what it
//! accepts is the one encoding of what it returns.
#![no_main]

use frasil_deposit_tokens::TokenKeysGet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = TokenKeysGet::decode(data) {
        assert_eq!(message.encode(), data, "a second encoding of TokenKeysGet");
    }
});
