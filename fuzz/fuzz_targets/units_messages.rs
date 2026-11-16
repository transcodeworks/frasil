//! frasil-units' sync message reader on arbitrary bytes (units.md, "Sync
//! messages" and "Sync"). It never panics; it refuses only with
//! `TooLarge`, `Malformed` or `UnknownMessage`; it ignores types from 64;
//! and what it accepts is the one encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_units::messages::{FIRST_IGNORABLE, Received, SyncMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match SyncMessage::read(data) {
        Ok(Received::Message(message)) => {
            assert_eq!(message.encode(), data, "a second encoding of a message");
            assert!((1..=17).contains(&message.message.type_code()));
            assert_eq!(
                SyncMessage::read(&message.encode()),
                Ok(Received::Message(message))
            );
        }
        Ok(Received::Ignored { type_code }) => assert!(type_code >= FIRST_IGNORABLE),
        Err(class) => assert!(
            matches!(
                class.shared(),
                Some(ErrorClass::TooLarge | ErrorClass::Malformed | ErrorClass::UnknownMessage)
            ),
            "{class:?}"
        ),
    }
});
