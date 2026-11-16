//! frasil-peers' entries at rest (`Entries::decode_state`) on arbitrary
//! bytes. The reader does not panic, and what it accepts is the one encoding
//! of what it returns.
#![no_main]

use frasil_peers::entries::Entries;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(entries) = Entries::decode_state(data) {
        assert_eq!(entries.encode_state(), data, "a second encoding of entries");
        let _ = entries.live().count();
    }
});
