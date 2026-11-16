//! frasil-deposit-tokens' reader of `MailboxPut` with key 7, and a peer's
//! checks of a deposit paid with a token, on arbitrary bytes
//! (ext-deposit-tokens.md, 2.5 Messages and 3.7 Redeeming). They never
//! panic; what the reader accepts is the one encoding of what it returns;
//! the checks refuse only with their steps' classes; and nothing passes
//! them that the peer's key did not evaluate.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::time::Reading;
use frasil_deposit_tokens::budget::Mailboxes;
use frasil_deposit_tokens::rotation::LiveKey;
use frasil_deposit_tokens::settings::TOKEN_PERIOD;
use frasil_deposit_tokens::{
    DepositKey, KeyId, KeyShard, Redemption, SpentRecord, SpentTokens, TokenClass, TokenDeposit,
    TokenPut, redeem,
};
use frasil_transport::caps::Cap;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Every token whose nonce starts with an odd byte is spent by a deposit
/// of nothing.
struct Spent;

impl SpentTokens for Spent {
    fn spent(&self, _: &KeyId, nonce: &[u8; 32]) -> Option<SpentRecord> {
        (nonce[0] & 1 == 1).then_some(SpentRecord {
            deposit: [0; 32],
            item: [0; 16],
        })
    }
}

fn keys() -> &'static KeyShard {
    static KEYS: OnceLock<KeyShard> = OnceLock::new();
    KEYS.get_or_init(|| {
        let began = Reading {
            timeline: 0,
            wall: None,
            run: 1,
        };
        let key = DepositKey::from_seed(&[7; 32]);
        KeyShard::from_keys(TOKEN_PERIOD, vec![LiveKey { key, began }]).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let read = TokenPut::decode(data);
    if let Ok(put) = &read {
        assert_eq!(
            put.encode(),
            data,
            "a second encoding of MailboxPut with key 7"
        );
    }
    let Ok(value) = frasil_base::cbor::decode(data) else {
        return;
    };
    let Ok(map) = value.as_map() else {
        return;
    };
    let deposit = match TokenDeposit::read_put(map) {
        Ok(deposit) => deposit,
        Err(class) => {
            assert_eq!(class, TokenClass::Shared(ErrorClass::Malformed));
            return;
        }
    };
    let budget = Mailboxes::new(
        Cap::NONE,
        Cap {
            items: 4,
            bytes: 4_096,
        },
        1,
    );
    match redeem(&deposit, keys(), &Spent, &budget) {
        Ok(_) => {
            let key = keys().issuing().unwrap();
            let token = &deposit.token;
            assert_eq!(&token.key_id(), key.id());
            assert_eq!(
                key.evaluate(&token.input()).unwrap().as_slice(),
                token.authenticator()
            );
            if let Ok(Redemption::Repeat { .. }) = redeem(&deposit, keys(), &Spent, &budget) {
                assert_eq!(token.nonce()[0] & 1, 1);
            }
        }
        Err(class) => assert!(
            matches!(
                class,
                TokenClass::Shared(ErrorClass::UnsupportedVersion | ErrorClass::TooLarge)
                    | TokenClass::TokenExpired
                    | TokenClass::TokenRefused
                    | TokenClass::TokenSpent
                    | TokenClass::Busy
            ),
            "{class:?}"
        ),
    }
});
