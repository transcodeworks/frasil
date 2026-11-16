//! frasil-ephemeral's outer frame reader on arbitrary bytes (ext-ephemeral.md,
//! "The outer frame" and "Receiving", steps 1 and 2), with a relay on top
//! ("Relaying"). It never panics; it refuses only with `TooLarge`,
//! `Malformed` or `UnsupportedVersion`; and what it accepts is the one
//! encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_ephemeral::relay::Relay;
use frasil_ephemeral::{EphemeralClass, Outer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The scope: the frame's own space where it names one, so that the
    // reader goes past the space check.
    let scope: [u8; 32] = match cbor::decode(data) {
        Ok(Value::Map(map)) => map
            .get(&3)
            .and_then(|space| space.as_byte_array().ok())
            .unwrap_or([0; 32]),
        _ => [0; 32],
    };
    match Outer::read(data, &scope) {
        Ok(frame) => {
            assert_eq!(frame.encode(), data, "a second encoding");
            assert_eq!(frame.space, scope);
            assert_eq!(
                frame.handle.is_some(),
                frame.kind == frasil_ephemeral::Kind::Slot
            );
        }
        Err(class) => assert!(
            matches!(
                class,
                EphemeralClass::Shared(
                    ErrorClass::TooLarge | ErrorClass::Malformed | ErrorClass::UnsupportedVersion
                )
            ),
            "{class:?}"
        ),
    }
    // A relay checks the same steps, and forwards to the other connection.
    let mut relay: Relay<u8> = Relay::new(scope);
    relay.join_with(0, [0; 8]);
    let relayed = relay.frame_with(1, data, [1; 8]);
    assert_eq!(relayed.is_ok(), Outer::read(data, &scope).is_ok());
    if let Ok(sent) = relayed {
        assert_eq!(sent.len(), 1);
        // A late joiner receives the frame only if it is an ephemeral slot.
        let slot = Outer::read(data, &scope).is_ok_and(|frame| frame.handle.is_some());
        assert_eq!(relay.join_with(2, [2; 8]).len(), usize::from(slot));
    }
});
