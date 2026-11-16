//! frasil-units' unit readers on arbitrary bytes (units.md, "The visible
//! body", "The sealed part", "Frasil's own units", "Snapshot units and
//! stream snapshots" and "Reading an object"): the bytes as a signed unit,
//! a visible body, a sealed part of a log unit and of a snapshot unit, the
//! content of Frasil's own units, a stream snapshot's plaintext and a stored
//! object. They never panic; they refuse only with their documents'
//! classes; and what they accept is the one encoding of what they return.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_crypto::primitives::sha256;
use frasil_units::body::Body;
use frasil_units::inner::Inner;
use frasil_units::objects::check_stored_chunked;
use frasil_units::own::{ListEventsBody, SystemState, read_body_keys, read_list_copy};
use frasil_units::snapshot::StreamSnapshot;
use frasil_units::unit::Unit;
use frasil_units::{UnitError, types};
use libfuzzer_sys::fuzz_target;

const STREAM: [u8; 16] = [1; 16];
const SYSTEM: [u8; 16] = [2; 16];

fn shared(class: UnitError, allowed: &[ErrorClass]) -> bool {
    class
        .shared()
        .is_some_and(|shared| allowed.contains(&shared))
}

fuzz_target!(|data: &[u8]| {
    match Body::read(data) {
        Ok(body) => {
            assert_eq!(body.encode(), data, "a second encoding of a body");
            assert!(body.sealed.len() >= 40 && body.objects.len() <= 4096);
        }
        Err(class) => assert!(
            shared(
                class,
                &[ErrorClass::Malformed, ErrorClass::UnsupportedVersion]
            ) || class.name() == "TooManyRotations",
            "{class:?}"
        ),
    }

    for (snapshot, system) in [(false, Some(&SYSTEM)), (true, Some(&STREAM)), (false, None)] {
        match Inner::read(data, snapshot, &STREAM, system) {
            Ok(inner) => {
                assert_eq!(inner.encode(), data, "a second encoding of a sealed part");
                assert!(types::is_valid(&inner.type_));
                assert!(snapshot || inner.excluded.is_empty());
                assert!(inner.resubmits.is_none() || inner.copied_from.is_none());
                assert!(inner.refs.len() <= 64);
            }
            Err(class) => assert!(
                shared(class, &[ErrorClass::Malformed, ErrorClass::TooLarge]),
                "{class:?}"
            ),
        }
    }

    if let Err(class) = Unit::check_at_peer(data) {
        assert!(!class.name().is_empty());
    }

    let _ = read_list_copy(data);
    let _ = read_body_keys(data);
    if let Ok(state) = SystemState::read(data) {
        assert_eq!(state.encode().as_deref(), Ok(data), "a second system state");
    }
    if let Ok(body) = ListEventsBody::read(data) {
        assert_eq!(body.encode(), data, "a second list-events body");
    }
    match StreamSnapshot::read(data, &STREAM, types::RECORDS) {
        Ok(snapshot) => assert_eq!(snapshot.encode(), data, "a second stream snapshot"),
        Err(class) => assert!(
            shared(
                class,
                &[ErrorClass::Malformed, ErrorClass::UnsupportedVersion]
            ),
            "{class:?}"
        ),
    }

    // As stored bytes under their own digest, with small chunks.
    let mut locator = [0; 64];
    locator[32..].copy_from_slice(&sha256(&[data]));
    if let Ok(stored) = check_stored_chunked(data, &locator, 64) {
        assert!(stored.header.size <= 1 << 40);
    }
});
