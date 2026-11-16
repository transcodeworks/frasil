//! frasil-space-file's way-in readers on arbitrary input
//! (ext-space-files.md, "The way in"): the body, an invite fragment, and
//! the sealed form under a fixed file key, opened as the input's own
//! plaintext. They never panic; each refuses only with the document's
//! classes; and what either accepts is the one encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_space_file::way_in::{Fragment, WayInBody, open_way_in, seal_way_in_with};
use libfuzzer_sys::fuzz_target;

const SPACE: EventId = EventId([7; 32]);
const FILE_KEY: [u8; 32] = [5; 32];
const NONCE: [u8; 24] = [6; 24];

fn body_class(class: ErrorClass) {
    assert!(
        matches!(
            class,
            ErrorClass::Malformed | ErrorClass::UnsupportedVersion
        ),
        "{class:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    match WayInBody::read(data, &SPACE) {
        Ok(body) => assert_eq!(body.encode(), data, "a second encoding"),
        Err(class) => body_class(class),
    }
    match Fragment::read(data) {
        Ok(fragment) => assert_eq!(fragment.encode(), data, "a second fragment"),
        Err(class) => assert!(
            matches!(
                class,
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion
            ),
            "{class:?}"
        ),
    }
    // The bytes as a sealed way in: never opened, only refused.
    match open_way_in(&FILE_KEY, data, &SPACE) {
        Ok(_) => {}
        Err(class) => assert!(
            matches!(class, ErrorClass::Malformed | ErrorClass::Decrypt),
            "{class:?}"
        ),
    }
    // The bytes as a way in's plaintext, sealed then opened.
    let sealed = seal_way_in_with(&FILE_KEY, &NONCE, data, &SPACE);
    let opened = open_way_in(&FILE_KEY, &sealed, &SPACE).expect("what was sealed opens");
    assert_eq!(&opened[..], data, "the plaintext");
});
