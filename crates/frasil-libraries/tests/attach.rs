//! `ext-libraries.json`'s `library_attach`: a `LibraryAttach` message for
//! each purpose, as it travels (ext-libraries.md, 2.3 LibraryAttach), byte
//! for byte, carrying the tickets of `tickets`.

use frasil_base::notation::field;
use frasil_libraries::{LIBRARY_ATTACH, LibraryAttach, Purpose, SignedTicket};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    purpose: u64,
    name: String,
    request: u64,
    space: String,
    signed: String,
    message: String,
    frame: String,
}

#[derive(Deserialize)]
struct TicketRow {
    signed: String,
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

#[test]
fn library_attach_messages_are_byte_for_byte() {
    let rows: Vec<Row> = vectors::family("ext-libraries.json", "library_attach");
    let tickets: Vec<TicketRow> = vectors::family("ext-libraries.json", "tickets");
    assert_eq!(rows.len(), 3);
    for (row, ticket) in rows.iter().zip(&tickets) {
        let purpose = Purpose::from_code(row.purpose).unwrap();
        assert_eq!(purpose.name(), row.name);
        // The message carries the ticket of `tickets` with its purpose.
        assert_eq!(row.signed, ticket.signed);
        let signed = SignedTicket::decode(&unhex(&row.signed)).unwrap();
        assert_eq!(signed.ticket.purpose, purpose);
        let message = LibraryAttach {
            request: row.request,
            space: unhex(&row.space).try_into().unwrap(),
            purpose,
            signed: unhex(&row.signed),
        };
        let bytes = message.encode();
        assert_eq!(hex::encode(&bytes), row.message, "{}", row.name);
        assert_eq!(hex::encode(field(&bytes)), row.frame, "{}", row.name);
        assert_eq!(LibraryAttach::decode(&bytes), Ok(message));
        assert_eq!(
            frasil_base::cbor::decode(&bytes).unwrap().as_map().unwrap()[&0]
                .as_unsigned()
                .unwrap(),
            LIBRARY_ATTACH
        );
    }
}
