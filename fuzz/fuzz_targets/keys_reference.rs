//! frasil-keys' readers of key names and the formats built on them, on
//! arbitrary bytes (keys.md, "Rotations and states", "Reading key names,
//! bundles, wraps and links" and "Reading a unit's key reference"): the
//! bytes as a key name, a key reference, a link, a gap record, a bundle and
//! a wrap's layout. They never panic; they refuse only with their
//! documents' classes; and what they accept is the one encoding of what
//! they return.
#![no_main]

use frasil_base::ErrorClass;
use frasil_keys::bundle::Bundle;
use frasil_keys::links::{GapRecord, Link};
use frasil_keys::reference::read_key_reference;
use frasil_keys::wraps::read_wrap;
use frasil_keys::{KeyClass, KeyName, RotationSet};
use libfuzzer_sys::fuzz_target;

fn allowed(class: KeyClass) -> bool {
    matches!(
        class,
        KeyClass::TooManyRotations
            | KeyClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
    )
}

fn check<T>(result: Result<T, KeyClass>, encode: impl FnOnce(&T) -> Vec<u8>, data: &[u8]) {
    match result {
        Ok(value) => assert_eq!(encode(&value), data, "a second encoding"),
        Err(class) => assert!(allowed(class), "{class:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    for allow_self in [false, true] {
        match KeyName::read(data, allow_self) {
            Ok((name, rest)) => {
                assert!(allow_self || !name.is_self_ref());
                let encoded = name.encode();
                assert_eq!(&data[..encoded.len()], &encoded[..]);
                assert_eq!(encoded.len() + rest.len(), data.len());
                if let KeyName::Set(set) = &name {
                    assert!((1..=64).contains(&set.len()));
                    assert!(set.ids().windows(2).all(|pair| pair[0] < pair[1]));
                }
            }
            Err(class) => assert!(allowed(class), "{class:?}"),
        }
    }
    check(RotationSet::decode(data), RotationSet::encode, data);
    check(read_key_reference(data), RotationSet::encode, data);
    check(Link::read(data), Link::encode, data);
    check(GapRecord::read(data), GapRecord::encode, data);
    check(Bundle::read(data), |bundle| bundle.encode().to_vec(), data);
    if let Err(class) = read_wrap(data) {
        assert!(allowed(class), "{class:?}");
    }
});
