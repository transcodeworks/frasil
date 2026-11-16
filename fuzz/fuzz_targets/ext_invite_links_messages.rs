//! frasil-transport's readers of the invite drop's messages on arbitrary
//! payloads (ext-invite-links.md, "The drop and its messages"): a
//! `MailboxPut` of kind 4, `MailboxDelete`, and `MailboxGet` of kind 4, at a
//! peer that implements the extension. They never panic; each refuses only
//! with `Malformed` or `TooLarge`; and what each accepts is the one encoding
//! of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::TransportClass;
use frasil_transport::ext_invite_links::{DropPut, MailboxDelete};
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::mailbox::MailboxGet;
use libfuzzer_sys::fuzz_target;

fn refused(class: TransportClass) {
    assert!(
        matches!(
            class,
            TransportClass::Shared(ErrorClass::Malformed | ErrorClass::TooLarge)
        ),
        "{class:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let extensions = Extensions {
        invite_links: true,
        ..Extensions::NONE
    };
    let Ok(Some(message)) = read_message(
        data,
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        extensions,
    ) else {
        return;
    };
    match DropPut::read(&message) {
        Ok(put) => assert_eq!(put.encode(), data, "a second encoding"),
        Err(class) => refused(class),
    }
    match MailboxDelete::read(&message) {
        Ok(delete) => assert_eq!(delete.encode(), data, "a second encoding"),
        Err(class) => refused(class),
    }
    match MailboxGet::read(&message) {
        Ok(get) => assert_eq!(get.encode(), data, "a second encoding"),
        Err(class) => refused(class),
    }
});
