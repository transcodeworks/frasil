//! frasil-store's mark reader on arbitrary bytes (at-rest.md, "The mark",
//! "Continuity"). It never panics; it refuses only as `Malformed`,
//! `UnsupportedVersion` or `Decrypt`; and continuity, which never fails,
//! finds a store current only from a mark that opens to the head's store ID
//! and generation, or in mode `never-restored`.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_store::continuity::{MARK_BYTES, open_mark};
use frasil_store::{Continuity, Head, RestoreMode, StoreKeys, continuity};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const DEVICE: DeviceId = DeviceId([2; 32]);

fn keys() -> &'static StoreKeys {
    static KEYS: OnceLock<StoreKeys> = OnceLock::new();
    KEYS.get_or_init(|| StoreKeys::new(&[1; 32]))
}

fuzz_target!(|data: &[u8]| {
    let opened = open_mark(keys(), &DEVICE, data);
    match &opened {
        Ok(_) => {
            assert_eq!(data.len(), MARK_BYTES);
            assert_eq!(data[0], 1);
        }
        Err(class) => assert!(matches!(
            class,
            ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
        )),
    }
    let mut head = Head::new([4; 16]);
    head.generation = 2;
    for mode in [
        RestoreMode::DeviceBound,
        RestoreMode::NeverRestored,
        RestoreMode::None,
    ] {
        let found = continuity(keys(), &DEVICE, mode, Some(&head), Some(data));
        let current = match mode {
            RestoreMode::NeverRestored => true,
            RestoreMode::None => false,
            RestoreMode::DeviceBound => opened == Ok((head.store_id, head.generation)),
        };
        assert_eq!(found == Continuity::Current, current);
        assert_eq!(
            continuity(keys(), &DEVICE, mode, None, Some(data)),
            Continuity::Restored
        );
    }
});
