//! frasil-deposit-tokens' `TokenKeys` reader and a device's checks of a key
//! list on arbitrary bytes (ext-deposit-tokens.md, 2.5 Messages and 3.2
//! Learning a peer's keys). It never panics; it refuses only with the
//! steps' classes; what it accepts is one or two keys, exactly one issuing,
//! each its own key ID's, in the one encoding; and a device's history of
//! such lists never panics either.
#![no_main]

use frasil_base::ErrorClass;
use frasil_deposit_tokens::key::key_id;
use frasil_deposit_tokens::messages::KeyEntry;
use frasil_deposit_tokens::{KeyHistory, KeyList, Role, TokenClass, TokenKeys};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&request, bytes)) = data.split_first() else {
        return;
    };
    match KeyList::decode(bytes, u64::from(request)) {
        Ok(list) => {
            let keys = list.keys();
            assert!(!keys.is_empty() && keys.len() <= 2);
            assert_eq!(keys.iter().filter(|k| k.role == Role::Issuing).count(), 1);
            for key in keys {
                assert_eq!(key_id(&key.public), key.id);
            }
            let again = TokenKeys {
                request: u64::from(request),
                keys: keys
                    .iter()
                    .map(|k| KeyEntry {
                        key_id: k.id,
                        public: k.public,
                        role: k.role,
                    })
                    .collect(),
            };
            assert_eq!(again.encode(), bytes, "a second encoding of TokenKeys");
            let mut history = KeyHistory::new();
            let _ = history.observe(&list, u64::from(request));
            let _ = history.observe(&list, u64::from(request) * 3_600);
        }
        Err(class) => assert!(
            matches!(
                class,
                TokenClass::Shared(ErrorClass::Malformed | ErrorClass::InvalidKey)
            ),
            "{class:?}"
        ),
    }
});
