//! frasil-transport's ticket reader and base64url decoder on arbitrary
//! text (transport.md, 2.8 Tickets). They never panic; the reader refuses
//! only with `Malformed` or `InvalidKey`; and what either accepts is the one
//! encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::TransportClass;
use frasil_transport::ticket::{MAX_BYTES, PREFIX, Ticket, base64url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(raw) = base64url::decode(text) {
        assert_eq!(base64url::encode(&raw), text, "a second base64url encoding");
    }
    match Ticket::read(text) {
        Ok(ticket) => {
            assert!(ticket.cbor().len() <= MAX_BYTES);
            assert_eq!(ticket.encode().as_deref(), Ok(text), "a second encoding");
            assert!(text.starts_with(PREFIX));
        }
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::Shared(ErrorClass::Malformed | ErrorClass::InvalidKey)
            ),
            "{error:?}"
        ),
    }
    // The CBOR alone, under the prefix.
    let wrapped = format!("{PREFIX}{}", base64url::encode(data));
    if let Ok(ticket) = Ticket::read(&wrapped) {
        assert_eq!(ticket.cbor(), data);
    }
});
