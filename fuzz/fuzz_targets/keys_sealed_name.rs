//! frasil-keys' sealed name readers on arbitrary bytes (keys.md, "Sealed
//! names"): the bytes as a sealed name, as a record, and as a name sealed
//! then opened. They never panic; they refuse only with their document's
//! classes; what they accept is the one encoding of what they return; and
//! a name sealed opens to itself.
#![no_main]

use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_keys::derive::{Secret, metadata_key};
use frasil_keys::sealed_names::{
    KIND_DOCUMENT, KIND_SPACE, Record, encode_record, open_name, open_record, seal_name_with,
};
use frasil_keys::{KeyClass, RotationSet};
use libfuzzer_sys::fuzz_target;

const SPACE: EventId = EventId([1; 32]);
const CONTENT_KEY: [u8; 32] = [2; 32];

fn reference() -> RotationSet {
    RotationSet::single(EventId([3; 32]))
}

fn allowed(class: KeyClass) -> bool {
    matches!(
        class,
        KeyClass::TooManyRotations
            | KeyClass::MissingState
            | KeyClass::InvalidName
            | KeyClass::Shared(
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
            )
    )
}

fuzz_target!(|data: &[u8]| {
    let mk = metadata_key(&CONTENT_KEY);
    let (kind, rest) = data.split_first().map_or((0, data), |(&k, r)| (k % 4, r));
    let id: &[u8] = if kind == KIND_SPACE { &[4; 32] } else { b"doc" };

    // The bytes as a sealed name: only the tag can let one through.
    if let Err(class) = open_name(&mk, &SPACE, &reference(), kind, id, rest) {
        assert!(allowed(class), "{class:?}");
    }

    // The bytes as a record.
    match Record::read(data) {
        Ok(record) => {
            assert_eq!(
                encode_record(&record.space, &record.reference, record.sealed),
                data,
                "a second encoding of a record"
            );
        }
        Err(class) => assert!(allowed(class), "{class:?}"),
    }
    let key_of = |state: &RotationSet| (*state == reference()).then(|| Secret::new(CONTENT_KEY));
    if let Err(class) = open_record(data, &SPACE, key_of, KIND_DOCUMENT, b"doc") {
        assert!(allowed(class), "{class:?}");
    }

    // The bytes as a name to seal.
    if let Ok(name) = std::str::from_utf8(rest) {
        match seal_name_with(&mk, &SPACE, &reference(), kind, id, name, &[5; 24]) {
            Ok(sealed) => {
                assert_eq!(sealed.len() % 64, 41);
                let opened = open_name(&mk, &SPACE, &reference(), kind, id, &sealed);
                assert_eq!(opened.as_deref(), Ok(name));
                let record = encode_record(&SPACE, &reference(), &sealed);
                let opened = open_record(&record, &SPACE, key_of, kind, id);
                assert_eq!(opened.as_deref(), Ok(name));
            }
            Err(class) => assert!(
                matches!(
                    class,
                    KeyClass::InvalidName | KeyClass::Shared(ErrorClass::Malformed)
                ),
                "{class:?}"
            ),
        }
    }
});
