//! frasil-admission's invite-link readers on arbitrary input
//! (ext-invite-links.md, "The secret, its keys and the link" and "The drop
//! and its messages"): the fragment, and the drop, both sealed under a
//! fixed secret and opened as the input's own plaintext. They never panic;
//! each refuses only with its document's classes; and what either accepts
//! is the one encoding of what it returns.
#![no_main]

use frasil_admission::ext_invite_links::{link_fragment, open_drop, read_fragment, seal_drop_with};
use frasil_base::ErrorClass;
use libfuzzer_sys::fuzz_target;

const SECRET: [u8; 32] = [5; 32];
const NONCE: [u8; 24] = [6; 24];

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        match read_fragment(text) {
            Ok(link) => assert_eq!(
                link_fragment(&link.secret, &link.entry, &link.space),
                text,
                "a second fragment"
            ),
            Err(class) => assert!(
                matches!(
                    class,
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion
                ),
                "{class:?}"
            ),
        }
    }
    // The bytes as a drop: never opened, only refused.
    match open_drop(&SECRET, data) {
        Ok(_) => {}
        Err(class) => assert!(
            matches!(class, ErrorClass::Malformed | ErrorClass::Decrypt),
            "{class:?}"
        ),
    }
    // The bytes as a drop's plaintext.
    let drop = seal_drop_with(&SECRET, data, &NONCE);
    match open_drop(&SECRET, &drop) {
        Ok(plain) => assert_eq!(plain.encode(), data, "a second encoding"),
        Err(class) => assert!(
            matches!(
                class,
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion
            ),
            "{class:?}"
        ),
    }
});
