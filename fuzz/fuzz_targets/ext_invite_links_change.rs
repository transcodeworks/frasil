//! frasil-space's change reader with ext-invite-links.md on arbitrary CBOR
//! (ext-invite-links.md, "The invite grant and the successor"; roster.md,
//! "Changes"): the invite grant, its removal and the successor read as that
//! document says. It never panics; it refuses only with the classes a
//! change can fail with, never `ExtensionRequired`; and what it accepts is
//! the one encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor;
use frasil_space::{Change, Limits, SpaceClass};
use libfuzzer_sys::fuzz_target;

const SPACE: [u8; 32] = [9; 32];

fuzz_target!(|data: &[u8]| {
    let Ok(value) = cbor::decode(data) else {
        return;
    };
    for space in [None, Some(&SPACE)] {
        match Change::read(&value, space, &Limits::PROTOCOL) {
            Ok(change) => assert_eq!(change.to_value().encode(), data, "a second encoding"),
            Err(class) => {
                let allowed = match class {
                    SpaceClass::Shared(shared) => matches!(
                        shared,
                        ErrorClass::Malformed
                            | ErrorClass::UnsupportedVersion
                            | ErrorClass::InvalidKey
                            | ErrorClass::BadPossession
                    ),
                    SpaceClass::AdministerNotDevice => true,
                    _ => false,
                };
                assert!(allowed, "{class:?}");
            }
        }
    }
});
