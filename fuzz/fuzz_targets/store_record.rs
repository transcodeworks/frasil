//! frasil-store's record readers on arbitrary bytes (at-rest.md, "Tables",
//! "Opening a record"). They never panic; they refuse only as the document
//! says; a value a table's reader accepts has exactly one encoding, the one
//! it read; and a record opens only if its address, item and value read.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::notation::{hex, split_field};
use frasil_store::record::open_record;
use frasil_store::tables::{Scope, Table, TableValue, check_item};
use frasil_store::{LogKeys, StoreKeys};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The store secret, space and log key of at-rest.json's browser, so that
/// the vectors' records seed the corpus and open.
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

    // A table's item and value: u8(table) || field(item) || value.
    if let Some((&code, rest)) = data.split_first()
        && let Some(table) = Table::from_code(code)
        && let Ok((item, value)) = split_field(rest)
    {
        let named = (table.scope() == Scope::Log).then_some(log.id());
        match TableValue::read(table, item, value, named) {
            Ok(read) => {
                assert_eq!(read.table(), table);
                assert_eq!(read.encode().as_slice(), value, "one encoding");
                assert_eq!(check_item(table, item), Ok(()));
            }
            Err(class) => assert_eq!(class, ErrorClass::Malformed),
        }
    }

    // A record at an address: the first 33 bytes, then the record, under
    // the device scope and under the log.
    let (address, record) = data.split_at(data.len().min(33));
    for scope in [None, Some(log)] {
        match open_record(store, scope, address, record) {
            Ok(opened) => {
                assert_eq!(address.len(), 33);
                assert_eq!(Some(opened.table), Table::from_code(address[16]));
                let named = scope.map(LogKeys::id);
                let again =
                    TableValue::read(opened.table, &opened.item, &opened.value.encode(), named);
                assert_eq!(again.as_ref(), Ok(&opened.value));
            }
            Err(class) => assert!(matches!(
                class,
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
            )),
        }
    }
});
