//! frasil-transport's reader of `NextEndpoint` on arbitrary payloads
//! (ext-next-endpoints.md, "Receiving", steps 1 and 2), at a member that
//! implements the extension. It never panics; it refuses only with
//! `Malformed`, `TooLarge` or `InvalidKey`; and what it accepts is the one
//! encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::TransportClass;
use frasil_transport::ext_next_endpoints::NextEndpoint;
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let extensions = Extensions {
        next_endpoints: true,
        ..Extensions::NONE
    };
    let Ok(Some(message)) = read_message(
        data,
        StreamClass::Control,
        ConnectionKind::Member,
        extensions,
    ) else {
        return;
    };
    match NextEndpoint::read(&message, ConnectionKind::Member) {
        Ok(next) => assert_eq!(next.encode(), data, "a second encoding"),
        Err(class) => assert!(
            matches!(
                class,
                TransportClass::Shared(
                    ErrorClass::Malformed | ErrorClass::TooLarge | ErrorClass::InvalidKey
                )
            ),
            "{class:?}"
        ),
    }
});
