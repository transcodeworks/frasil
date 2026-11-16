//! frasil-libraries' ticket link reader on arbitrary text: a link that
//! reads writes back to the same text, its origin and its ticket as read.
//! The reader never panics.
#![no_main]

use frasil_libraries::TicketLink;
use frasil_libraries::ticket::MAX_TICKET_BYTES;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(link) = TicketLink::parse(text) {
        assert!(!link.ticket().is_empty() && link.ticket().len() <= MAX_TICKET_BYTES);
        let written = link.to_string();
        assert_eq!(written, text.trim());
        assert_eq!(TicketLink::parse(&written), Ok(link));
    }
});
