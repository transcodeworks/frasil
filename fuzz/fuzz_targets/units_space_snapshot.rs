//! frasil-units' space snapshot readers on arbitrary bytes (units.md, "The
//! space snapshot", "Using it", steps 1 to 3): the bytes as a snapshot's
//! map and as a signed snapshot. They never panic; they refuse only with
//! the classes of those steps; and what they accept is the one encoding of
//! what they return.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_units::snapshot::SpaceSnapshot;
use libfuzzer_sys::fuzz_target;

const SPACE: EventId = EventId([3; 32]);

fuzz_target!(|data: &[u8]| {
    match SpaceSnapshot::decode(data) {
        Ok(snapshot) => {
            assert_eq!(
                snapshot.encode().as_deref(),
                Ok(data),
                "a second encoding of a snapshot"
            );
            assert!((1..=256).contains(&snapshot.base.len()));
            assert!(snapshot.stubs.iter().all(|stub| stub.stream.is_some()));
        }
        Err(class) => assert!(
            matches!(
                class.shared(),
                Some(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
            ),
            "{class:?}"
        ),
    }
    match SpaceSnapshot::read(data, &SPACE, &()) {
        Ok(read) => assert!(read.is_provisional() && read.unverified().space == SPACE),
        Err(class) => assert!(
            matches!(
                class.shared(),
                Some(
                    ErrorClass::Malformed
                        | ErrorClass::UnsupportedVersion
                        | ErrorClass::BadSignature
                )
            ) || class.name() == "WrongSpace",
            "{class:?}"
        ),
    }
});
