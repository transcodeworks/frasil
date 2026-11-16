//! frasil-keys' readers of a restricted space's key reference on arbitrary
//! input (ext-restricted-spaces.md, "The restricted key reference" and
//! "Reading a restricted key reference"): the bytes as a reference, as the
//! plaintext of a sealed parent state, and as a record of the space's
//! names. They never panic; each refuses only with its document's classes;
//! and what a reader accepts is the one encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::primitives::xchacha20poly1305_seal;
use frasil_events::EventId;
use frasil_keys::ext_restricted_spaces::{
    RestrictedReference, open_restricted_record, parent_reference_aad, parent_reference_key,
};
use frasil_keys::{KeyClass, RotationSet};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const SPACE: EventId = EventId([3; 32]);
const SECRET: [u8; 32] = [5; 32];
const NONCE: [u8; 24] = [6; 24];

fn shape(class: KeyClass) -> bool {
    matches!(
        class,
        KeyClass::TooManyRotations
            | KeyClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
    )
}

fuzz_target!(|data: &[u8]| {
    // The bytes as a reference: read, then opened under a fixed secret.
    match RestrictedReference::read(data) {
        Ok(reference) => {
            assert_eq!(reference.encode(), data, "a second encoding");
            assert!((1..=64).contains(&reference.parent_rotations()));
            if let Err(class) = reference.open(&SPACE, &SECRET) {
                assert!(
                    matches!(
                        class,
                        KeyClass::Shared(ErrorClass::Decrypt | ErrorClass::Malformed)
                    ),
                    "{class:?}"
                );
            }
        }
        Err(class) => assert!(shape(class), "{class:?}"),
    }
    // The bytes as a sealed parent state's plaintext.
    let own = RotationSet::single(EventId([1; 32]));
    let sealed = xchacha20poly1305_seal(
        &parent_reference_key(&SECRET),
        &NONCE,
        &parent_reference_aad(&SPACE, &own),
        data,
    );
    let reference = RestrictedReference {
        own,
        nonce: NONCE,
        sealed,
    };
    match reference.open(&SPACE, &SECRET) {
        Ok(parent) => assert_eq!(parent.encode(), data, "a second encoding"),
        Err(class) => assert_eq!(class, KeyClass::Shared(ErrorClass::Malformed)),
    }
    // The bytes as a record of the space's names.
    let opened =
        open_restricted_record(data, &SPACE, |_| Some(Zeroizing::new(SECRET)), 2, &[7; 16]);
    if let Err(class) = opened {
        assert!(
            shape(class) || matches!(class, KeyClass::Shared(ErrorClass::Decrypt)),
            "{class:?}"
        );
    }
});
