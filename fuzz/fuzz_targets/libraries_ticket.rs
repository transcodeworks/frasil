//! frasil-libraries' ticket readers and `check_ticket` on arbitrary bytes
//! (ext-libraries.md, 2.2 The library ticket, and 3.2 Checking a ticket).
//! They never panic; what they accept is the one encoding of what they
//! return; `check_ticket` refuses only with its steps' classes; and nothing
//! passes it that the trusted issuer did not sign.
#![no_main]

use frasil_base::ErrorClass;
use frasil_libraries::ticket::MAX_TICKET_BYTES;
use frasil_libraries::{
    Issuer, LibraryClass, LibraryId, LibraryState, PeerRecords, Purpose, SignedTicket, Ticket,
    TicketId, TrustedIssuers, check_ticket,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn issuer() -> &'static (Issuer, TrustedIssuers) {
    static ISSUER: OnceLock<(Issuer, TrustedIssuers)> = OnceLock::new();
    ISSUER.get_or_init(|| {
        let issuer = Issuer::from_seed(&[1; 32]);
        let trusted = TrustedIssuers::new([*issuer.public()]).unwrap();
        (issuer, trusted)
    })
}

/// A peer that has used every ID whose first byte is odd, and whose
/// libraries starting with `s` are suspended.
struct Records;

impl PeerRecords for Records {
    fn ticket_used(&self, id: &TicketId) -> bool {
        id[0] & 1 == 1
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        library
            .as_str()
            .starts_with('s')
            .then_some(LibraryState::Suspended)
    }
}

fuzz_target!(|data: &[u8]| {
    let (issuer, trusted) = issuer();

    if let Ok(ticket) = Ticket::decode(data) {
        assert_eq!(ticket.encode(), data, "a second encoding of a ticket");
        assert!(LibraryId::is_valid(ticket.library.as_str()));
    }

    let read = SignedTicket::decode(data);
    if let Ok(signed) = &read {
        assert!(data.len() <= MAX_TICKET_BYTES);
        assert_eq!(
            signed.encode(),
            data,
            "a second encoding of a signed ticket"
        );
        assert_eq!(signed.ticket.encode(), signed.ticket_bytes);
    }

    // The first byte picks the purpose and the wall clock; the rest is the
    // signed ticket.
    let Some((&pick, signed)) = data.split_first() else {
        return;
    };
    let purpose = Purpose::ALL[usize::from(pick % 3)];
    let now = (pick & 0x80 == 0).then_some(u64::from(pick & 0x7c) << 24);
    match check_ticket(signed, purpose, now, trusted, &Records) {
        Ok(ticket) => {
            // Ed25519 is deterministic: only the issuer's own signature of
            // these bytes passes.
            let read = SignedTicket::decode(signed).unwrap();
            assert_eq!(read.ticket, ticket);
            assert_eq!(issuer.sign_bytes(&read.ticket_bytes), signed);
            assert_eq!(ticket.purpose, purpose);
            assert!(!Records.ticket_used(&ticket.id));
        }
        Err(class) => {
            assert!(matches!(
                class,
                LibraryClass::Shared(ErrorClass::Malformed)
                    | LibraryClass::TicketRefused
                    | LibraryClass::TicketExpired
                    | LibraryClass::TicketUsed
                    | LibraryClass::LibraryClosed
            ));
            // Step 1 alone agrees with check_ticket on what it refuses.
            assert_eq!(
                SignedTicket::decode(signed).is_err(),
                class == LibraryClass::Shared(ErrorClass::Malformed)
            );
        }
    }
});
