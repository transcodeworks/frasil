//! frasil-store's `held` record reader on arbitrary bytes (at-rest.md,
//! "Tables", "Held objects"): the value as `TableValue::read` reads it, and
//! a sealed record of the table at an address. It never panics; it refuses
//! only as `Malformed`; a value it accepts has exactly one encoding, the one
//! it read, and keeps to the token, size and stamp limits.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::notation::hex;
use frasil_store::record::open_record;
use frasil_store::tables::{MAX_HELD_STAMP, MAX_HELD_TOKEN, MAX_OBJECT_SIZE, Table, TableValue};
use frasil_store::{LogKeys, StoreKeys};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The store secret, space and log key of at-rest.json's browser, so that
/// the vectors' held records seed the corpus and open.
const STORE_SECRET: &str = "579fb11a557bf5499250e601ec1bc7cc7ac54d6b00d0e5a79e253c3a5790922b";
const SPACE: &str = "a993aa80d5e4a7f9177435e93d152ca2174671491e81a30c2ca3ab05daeed353";
const LOG_KEY: &str = "05a0a94b15771688f66604ccb184660255a06896faadc2a55b9c3c21ba815bbc";

fn keys() -> &'static (StoreKeys, LogKeys) {
    static KEYS: OnceLock<(StoreKeys, LogKeys)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let array = |text| hex::decode_array::<32>(text).expect("32 bytes of hex");
        let store = StoreKeys::new(&array(STORE_SECRET));
        let log = store.log(&array(SPACE), &array(LOG_KEY));
        (store, log)
    })
}

fuzz_target!(|data: &[u8]| {
    let (store, log) = keys();

    // The value under a fixed item: the first 32 bytes are the object ID.
    if let Some((item, value)) = data.split_at_checked(32) {
        match TableValue::read(Table::Held, item, value, Some(log.id())) {
            Ok(TableValue::Held(held)) => {
                assert!((1..=MAX_HELD_TOKEN).contains(&held.token.len()));
                assert!(held.size <= MAX_OBJECT_SIZE);
                assert!((1..=MAX_HELD_STAMP).contains(&held.stamp.len()));
                assert_eq!(
                    TableValue::Held(held).encode().as_slice(),
                    value,
                    "one encoding"
                );
            }
            Ok(other) => panic!("a held value read as {other:?}"),
            Err(class) => assert_eq!(class, ErrorClass::Malformed),
        }
    }

    // A record at a held address: the item tag is the record's, so the
    // first 16 bytes name the address's item tag and the rest is the record.
    if let Some((tag, record)) = data.split_at_checked(16) {
        let mut address = log.scope_tag().to_vec();
        address.push(Table::Held.code());
        address.extend_from_slice(tag);
        match open_record(store, Some(log), &address, record) {
            Ok(opened) => {
                assert_eq!(opened.table, Table::Held);
                assert_eq!(opened.item.len(), 32);
                assert!(matches!(opened.value, TableValue::Held(_)));
            }
            Err(class) => assert!(matches!(
                class,
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
            )),
        }
    }
});
