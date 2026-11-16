//! frasil-deposit-tokens' reader of the server binding's `Authorization:
//! Frasil-Token` value on arbitrary text (ext-deposit-tokens.md, 2.5
//! Messages, "The server binding", and 3.7 Redeeming, step 1). It never
//! panics, refuses only with `Malformed`, and what it accepts is the one
//! spelling of the token it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_deposit_tokens::{Token, TokenClass};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    match Token::from_header(text) {
        Ok(token) => assert_eq!(token.header().as_str(), text),
        Err(class) => assert_eq!(class, TokenClass::Shared(ErrorClass::Malformed)),
    }
});
