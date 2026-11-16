//! frasil-identity's device-list body decoder and its checks on arbitrary
//! bytes (identity.md, "The device-list event" and "Checking a list event
//! alone", steps 2 to 5). They never panic; what the decoder accepts is the
//! one encoding of what it returns; and the checks refuse only with their
//! classes, in their order.
#![no_main]

use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_identity::body::{ListBody, check_body};
use libfuzzer_sys::fuzz_target;

const AUTHOR: DeviceId = DeviceId([9; 32]);
const PERSON: [u8; 32] = [1; 32];

fuzz_target!(|data: &[u8]| {
    let decoded = ListBody::decode(data);
    if let Ok(body) = &decoded {
        assert_eq!(body.encode(), data, "a second encoding of a body");
        assert_eq!(body.keys().is_some(), body.added.is_some());
    }
    for person in [None, Some(&PERSON)] {
        match check_body(data, &AUTHOR, person) {
            Ok(body) => assert_eq!(Some(&body), decoded.as_ref().ok()),
            Err(class) => {
                assert!(matches!(
                    class.name(),
                    "Malformed" | "BadGenesis" | "InvalidKey" | "NotCommitted" | "BadPossession"
                ));
                assert_eq!(class.name() == "Malformed", decoded.is_err());
                assert!(class.name() != "BadGenesis" || person.is_none());
            }
        }
    }
});
