//! frasil-identity's recovery entry reader on arbitrary bytes (identity.md,
//! "Fetch keys and recovery entries"), for the personal space and another
//! space. It never panics, and what it accepts is the one encoding of what
//! it returns.
#![no_main]

use frasil_identity::entries::RecoveryEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut personal = [0u8; 32];
    // A personal space the input can name: the bytes after a map's key 1.
    if let Some(at) = data.windows(3).position(|w| w == [0x01, 0x58, 0x20])
        && let Some(space) = data.get(at + 3..at + 35)
    {
        personal.copy_from_slice(space);
    }
    for space in [personal, [0xff; 32]] {
        if let Ok(entry) = RecoveryEntry::read(data, &space) {
            assert_eq!(entry.encode(), data, "a second encoding of an entry");
        }
    }
});
