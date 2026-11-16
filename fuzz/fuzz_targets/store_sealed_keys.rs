//! frasil-store's sealed device keys reader on arbitrary bytes (at-rest.md,
//! "Sealed device keys", "Sealing and opening the device keys"). It never
//! panics; it refuses only with the classes of open_device_keys, in its
//! order; a blob whose header does not read never opens; and a plaintext
//! that reads has exactly one layout.
#![no_main]

use frasil_base::ErrorClass;
use frasil_store::StoreClass;
use frasil_store::device_keys::{
    DeviceKeys, KeyKind, SEALED_DEVICE_KEYS_BYTES, open_device_keys, read_header,
};
use libfuzzer_sys::fuzz_target;

/// A fixed unlock key, so that a blob the fuzzer finds can open.
const UNLOCK_KEY: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let header = read_header(data);
    match &header {
        Ok(header) => {
            assert_eq!(data.len(), SEALED_DEVICE_KEYS_BYTES);
            assert_eq!(data[0], 1);
            assert_eq!(header.to_bytes()[..], data[..66]);
        }
        Err(class) => assert!(matches!(
            class,
            ErrorClass::Malformed | ErrorClass::UnsupportedVersion
        )),
    }
    let person = header.map_or([0; 32], |header| header.person_id);
    for kind in [KeyKind::PasskeyUnlock, KeyKind::UnlockKey] {
        match open_device_keys(data, kind, &UNLOCK_KEY, &person, None) {
            Ok(keys) => {
                let header = header.expect("an opened blob's header reads");
                assert_eq!(header.kind, kind);
                assert_eq!(keys.device_id(), header.device_id);
            }
            Err(StoreClass::Shared(class)) => {
                assert!(matches!(
                    class,
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
                ));
            }
            Err(StoreClass::WrongKeyKind) => {
                assert!(header.is_ok_and(|header| header.kind != kind));
            }
            Err(other) => panic!("open_device_keys refused as {other:?}"),
        }
    }

    match DeviceKeys::from_plaintext(data) {
        Ok(keys) => assert_eq!(&keys.plaintext()[..], data),
        Err(class) => assert!(matches!(
            class,
            ErrorClass::Malformed | ErrorClass::UnsupportedVersion
        )),
    }
});
