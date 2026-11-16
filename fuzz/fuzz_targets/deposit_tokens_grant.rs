//! frasil-libraries' ticket readers where the peer implements deposit
//! tokens, on arbitrary bytes (ext-deposit-tokens.md, 2.3 The deposit
//! grant, and ext-libraries.md, 3.2 Checking a ticket, step 1). They never
//! panic; what they accept is the one encoding of what they return; key 7
//! is present exactly for purpose 4, with 1 to 256 tokens; and a reading
//! as a core peer accepts nothing of purpose 4.
#![no_main]

use frasil_libraries::ticket::MAX_GRANT_TOKENS;
use frasil_libraries::{Purpose, SignedTicket, Ticket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(ticket) = Ticket::decode_with_grants(data, true) {
        assert_eq!(ticket.encode(), data, "a second encoding of a ticket");
        assert_eq!(ticket.tokens.is_some(), ticket.purpose == Purpose::Deposit);
        if let Some(tokens) = ticket.tokens {
            assert!((1..=MAX_GRANT_TOKENS).contains(&tokens));
        }
    }
    if let Ok(ticket) = Ticket::decode(data) {
        assert_ne!(ticket.purpose, Purpose::Deposit);
        assert_eq!(ticket.tokens, None);
    }
    if let Ok(signed) = SignedTicket::decode_with_grants(data, true) {
        assert_eq!(
            signed.encode(),
            data,
            "a second encoding of a signed ticket"
        );
        assert_eq!(signed.ticket.encode(), signed.ticket_bytes);
    }
});
