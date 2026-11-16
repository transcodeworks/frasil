//! frasil-libraries' `LibraryAttach` reader on arbitrary bytes
//! (ext-libraries.md, 2.3 LibraryAttach). It never panics; what it accepts
//! is the one encoding of what it returns; and it reads the map transport's
//! framing hands it the same way.
#![no_main]

use frasil_base::cbor;
use frasil_libraries::{LIBRARY_ATTACH, LibraryAttach};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let read = LibraryAttach::decode(data);
    if let Ok(message) = &read {
        assert_eq!(message.encode(), data, "a second encoding of LibraryAttach");
    }
    if let Ok(value) = cbor::decode(data)
        && let Ok(map) = value.as_map()
    {
        assert_eq!(LibraryAttach::read(map), read);
        if read.is_ok() {
            assert_eq!(map[&0].as_unsigned().ok(), Some(LIBRARY_ATTACH));
            assert_eq!(map.len(), 5);
        }
    }
});
