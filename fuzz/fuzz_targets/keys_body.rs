//! frasil-keys' space event body readers on arbitrary bytes (keys.md, "The
//! space event's body" and "Checking a space event's body"): the bytes as a
//! visible part, as a sealed part's plaintext against a body that rotates
//! and one that does not, and as a plaintext sealed and opened under a body
//! key. They never panic; they refuse only with their documents' classes;
//! and what they accept is the one encoding of what they return.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::body::{Delivery, Inner, RotationKeys, Seal, VisiblePart};
use frasil_keys::derive::{body_commitment, body_key};
use frasil_keys::{KeyClass, KeyName, RotationSet, SelfRef};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const AUTHOR: DeviceId = DeviceId([7; 32]);
const SEQ: u64 = 5;
const LOG: &[u8] = &[9; 32];

fn own() -> SelfRef {
    SelfRef::new(AUTHOR, SEQ)
}

fn key() -> [u8; 32] {
    *body_key(&[1; 32], LOG, &AUTHOR, SEQ)
}

/// A body that rotates, whose own delivery names a grant state, and one
/// that does not rotate.
fn bodies() -> &'static [VisiblePart; 2] {
    static BODIES: OnceLock<[VisiblePart; 2]> = OnceLock::new();
    BODIES.get_or_init(|| {
        let mut wrap = vec![0x01, 0x64, 0x7a];
        wrap.resize(1236, 0);
        let own = KeyName::SelfRef(own());
        let commitment = body_commitment(&key());
        [
            VisiblePart {
                seal: Seal::Rotation(RotationKeys {
                    grant_commitment: [2; 32],
                    read: [3; 32],
                    upload: [4; 32],
                }),
                deliveries: vec![Delivery {
                    key_name: Some(own.clone()),
                    grant_name: Some(own),
                    wraps: vec![wrap],
                    space_wraps: Vec::new(),
                }],
                sealed: vec![0; 41],
                nonce: None,
                commitment,
                twin: None,
            },
            VisiblePart {
                seal: Seal::Under(RotationSet::single(EventId([5; 32]))),
                deliveries: Vec::new(),
                sealed: vec![0; 41],
                nonce: None,
                commitment,
                twin: None,
            },
        ]
    })
}

fn allowed(class: KeyClass) -> bool {
    matches!(
        class,
        KeyClass::TooManyRotations
            | KeyClass::Shared(
                ErrorClass::Malformed
                    | ErrorClass::UnsupportedVersion
                    | ErrorClass::InvalidKey
                    | ErrorClass::TooLarge
            )
    )
}

fuzz_target!(|data: &[u8]| {
    match VisiblePart::read(data, &AUTHOR, SEQ) {
        Ok(visible) => {
            assert_eq!(visible.encode(), data, "a second encoding of a body");
            assert!(visible.deliveries.len() <= 64 && visible.wrap_count() <= 768);
            assert_eq!(visible.rotates(), visible.sealed_under().is_none());
            if let Err(class) = visible.open(&key(), LOG, &AUTHOR, SEQ) {
                assert!(
                    allowed(class) || class == ErrorClass::BadSeal.into(),
                    "{class:?}"
                );
            }
        }
        Err(class) => assert!(
            allowed(class) && class != ErrorClass::TooLarge.into(),
            "{class:?}"
        ),
    }

    for visible in bodies() {
        let read = Inner::read(data, visible, &own());
        match &read {
            Ok(inner) => {
                assert_eq!(inner.encode(), data, "a second encoding of a sealed part");
                assert!(visible.rotates() || (inner.grant.is_none() && !inner.is_break));
                assert!(inner.refs.len() <= 64);
            }
            Err(class) => assert!(allowed(*class), "{class:?}"),
        }
        // Sealed under the body key, the bytes open to the same verdict.
        let inner_bytes = data.to_vec();
        let sealed = {
            let ciphertext = frasil_crypto::primitives::xchacha20poly1305_seal(
                &key(),
                &[6; 24],
                &frasil_keys::derive::body_aad(LOG, &AUTHOR, SEQ),
                &inner_bytes,
            );
            [&[6; 24][..], &ciphertext].concat()
        };
        let carrying = VisiblePart {
            sealed,
            ..visible.clone()
        };
        assert_eq!(carrying.open(&key(), LOG, &AUTHOR, SEQ), read);
    }
});
