//! frasil-identity's list checkpoint record on arbitrary bytes
//! (identity.md, "List checkpoints"). The reader never panics, and what it
//! accepts it writes in an encoding that reads back and writes the same
//! bytes again.
#![no_main]

use frasil_identity::ListRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = ListRecord::read(data) {
        let again = record.encode();
        let read = ListRecord::read(&again).expect("its own encoding reads");
        assert_eq!(read.encode(), again);
    }
});
