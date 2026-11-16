//! frasil-transport's `Addresses` reader on arbitrary bytes (transport.md,
//! 3.16 The iroh binding, member addresses). It never panics; it refuses
//! only with `Malformed`, `InvalidKey`, `TooLarge` or `UnknownMessage`;
//! what it accepts is the one encoding of what it returns, lists each
//! device ID once and only member tickets, and is what a sender would
//! send of the same list.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::TransportClass;
use frasil_transport::addresses::{Addresses, MAX_ENTRIES};
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::ticket::TicketKind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let message = match read_message(
        data,
        StreamClass::Control,
        ConnectionKind::Member,
        Extensions::NONE,
    ) {
        Ok(Some(message)) => message,
        Ok(None) => return,
        Err(error) => {
            assert!(
                matches!(
                    error,
                    TransportClass::Shared(
                        ErrorClass::Malformed | ErrorClass::TooLarge | ErrorClass::UnknownMessage
                    )
                ),
                "{error:?}"
            );
            return;
        }
    };
    match Addresses::read(&message) {
        Ok(addresses) => {
            assert_eq!(addresses.encode(), data, "a second encoding");
            assert!(addresses.entries.len() <= MAX_ENTRIES);
            for (n, (device, ticket)) in addresses.entries.iter().enumerate() {
                assert_eq!(ticket.kind, TicketKind::Member);
                assert!(addresses.entries[..n].iter().all(|(k, _)| k != device));
            }
            assert_eq!(
                Addresses::fitting(addresses.attach, addresses.entries.clone()).as_ref(),
                (!addresses.entries.is_empty()).then_some(&addresses)
            );
        }
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::Shared(ErrorClass::Malformed | ErrorClass::InvalidKey)
            ),
            "{error:?}"
        ),
    }
});
