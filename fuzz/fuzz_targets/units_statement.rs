//! frasil-units' head statement reader on arbitrary bytes (units.md, "Head
//! statements"): the bytes as a signed statement, and as a statement's map
//! under a signature that does not verify, which reaches the map's reader
//! before the signature. It never panics, and refuses only with the classes
//! a receiver checks, in order.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor::Value;
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_units::statement::HeadStatement;
use libfuzzer_sys::fuzz_target;

const SPACE: EventId = EventId([3; 32]);

fuzz_target!(|data: &[u8]| {
    let unsigned = Value::Array(vec![Value::from(data), Value::from([0u8; 64])]).encode();
    match HeadStatement::read(&unsigned, &SPACE, |_| true) {
        Ok(_) => panic!("a zero signature verifies"),
        Err(class) => assert!(
            matches!(
                class.shared(),
                Some(
                    ErrorClass::TooLarge
                        | ErrorClass::Malformed
                        | ErrorClass::UnsupportedVersion
                        | ErrorClass::BadSignature
                )
            ),
            "{class:?}"
        ),
    }
    match HeadStatement::read(data, &SPACE, |_| true) {
        Ok(statement) => assert_eq!(statement.space, SPACE),
        Err(class) => assert!(
            matches!(
                class.shared(),
                Some(
                    ErrorClass::TooLarge
                        | ErrorClass::Malformed
                        | ErrorClass::UnsupportedVersion
                        | ErrorClass::BadSignature
                        | ErrorClass::InvalidKey
                )
            ) || class.name() == "WrongSpace",
            "{class:?}"
        ),
    }
});
