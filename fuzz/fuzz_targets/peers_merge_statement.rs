//! frasil-peers' merge statement reader on arbitrary bytes (peers.md, "The
//! merge statement" and "Merge statements", steps 1 and 2). It never panics;
//! it refuses only with its document's classes; and what it accepts is the
//! one encoding of what it returns, with one signature per rotation of a
//! state of 2 to 64.
#![no_main]

use frasil_base::ErrorClass;
use frasil_peers::PeersClass;
use frasil_peers::limits::{MAX_MERGE_ROTATIONS, MIN_MERGE_ROTATIONS};
use frasil_peers::merge::MergeStatement;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match MergeStatement::read(data) {
        Ok(statement) => {
            assert_eq!(statement.encode(), data, "a second encoding of a statement");
            assert!((MIN_MERGE_ROTATIONS..=MAX_MERGE_ROTATIONS).contains(&statement.state.len()));
            assert_eq!(statement.signatures.len(), statement.state.len());
            assert_eq!(MergeStatement::read(&statement.encode()), Ok(statement));
        }
        Err(class) => assert!(
            matches!(
                class,
                PeersClass::Shared(
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::InvalidKey
                )
            ),
            "{class:?}"
        ),
    }
});
