//! frasil-relay's space snapshot, a space's decoded state at rest, on
//! arbitrary bytes. The reader does not panic; what it accepts is the one
//! encoding of what it returns, its journal records below its `through`. A
//! version-2 snapshot is read too and written as this version, so its
//! second encoding is compared after another reading.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/records.rs"]
mod records;

use libfuzzer_sys::fuzz_target;
use records::Snapshot;

fuzz_target!(|data: &[u8]| {
    if let Some(snapshot) = Snapshot::decode(data) {
        let encoded = snapshot.encode();
        if data.get(1) == Some(&2) {
            let again = Snapshot::decode(&encoded).map(|snapshot| snapshot.encode());
            assert_eq!(again, Some(encoded), "a version-2 snapshot, written again");
        } else {
            assert_eq!(encoded, data, "a second encoding of a snapshot");
        }
        assert!(
            snapshot
                .ops
                .iter()
                .all(|(index, _)| *index < snapshot.through)
        );
        assert!(
            snapshot
                .held
                .iter()
                .all(|held| held.index < snapshot.through)
        );
    }
});
