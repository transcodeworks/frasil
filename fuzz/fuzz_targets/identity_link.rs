//! frasil-identity's account link, unlink and user handle readers on
//! arbitrary bytes (identity.md, "Account links" and "Passkey members").
//! They never panic, and what they accept is the one encoding of what they
//! return.
#![no_main]

use frasil_identity::links::{AccountLink, Unlink};
use frasil_identity::passkey::UserHandle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(link) = AccountLink::decode(data) {
        assert_eq!(link.encode(), data, "a second encoding of a link");
        if let Ok(verified) = AccountLink::verify(data) {
            assert_eq!(verified, link);
        }
    } else {
        assert!(AccountLink::verify(data).is_err());
    }
    if let Ok(unlink) = Unlink::decode(data) {
        assert_eq!(unlink.encode(), data, "a second encoding of an unlink");
        let _ = unlink.verifies();
    }
    if let Ok(handle) = UserHandle::parse(data) {
        assert_eq!(handle.to_bytes()[..], data[..]);
    }
});
