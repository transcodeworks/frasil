//! frasil-deposit-tokens' `TokenIssue` reader and a device's finishing of
//! a batch on arbitrary bytes (ext-deposit-tokens.md, 2.5 Messages and 3.5
//! Finishing issuance). They never panic; finishing refuses only with
//! `Malformed` or `BadProof`; it finishes at most the tokens sent; and
//! what the reader accepts is the one encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_deposit_tokens::{Batch, DepositKey, KeyList, TokenClass, TokenIssue};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn batch() -> &'static Batch {
    static BATCH: OnceLock<Batch> = OnceLock::new();
    BATCH.get_or_init(|| {
        let key = DepositKey::from_seed(&[7; 32]);
        let list = KeyList::check(&[(key.id().as_slice(), key.public().as_slice(), 1)]).unwrap();
        let draws = [([1; 32], [2; 32]), ([3; 32], [4; 32]), ([5; 32], [6; 32])];
        Batch::new_with(list.issuing(), &draws).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(issue) = TokenIssue::decode(data, 1, 3) {
        assert_eq!(issue.encode(), data, "a second encoding of TokenIssue");
    }
    match batch().finish_bytes(data, 1) {
        Ok(tokens) => assert!(!tokens.is_empty() && tokens.len() <= 3),
        Err(class) => assert!(
            matches!(
                class,
                TokenClass::Shared(ErrorClass::Malformed) | TokenClass::BadProof
            ),
            "{class:?}"
        ),
    }
});
