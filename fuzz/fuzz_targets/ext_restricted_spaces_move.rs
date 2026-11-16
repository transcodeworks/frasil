//! frasil-units' reader of a move record on arbitrary input
//! (ext-restricted-spaces.md, "The move record" and "Moved documents"),
//! whether a move unit's content, an index pointer or a stream snapshot's
//! `moved`. It never panics; it refuses only with `Malformed` or
//! `UnsupportedVersion`; and what it accepts is the one encoding of what it
//! returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_units::UnitError;
use frasil_units::ext_restricted_spaces::{MoveRecord, move_unit, moved_by_snapshot};
use frasil_units::types;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match MoveRecord::read(data) {
        Ok(record) => {
            assert_eq!(record.encode(), data, "a second encoding");
            assert!(record.to_stream.iter().any(|&b| b != 0));
            assert!(
                record
                    .name
                    .as_ref()
                    .is_none_or(|n| (1..=1022).contains(&n.len()))
            );
            assert_eq!(moved_by_snapshot(Some(data)), Some(record));
        }
        Err(class) => {
            assert!(
                matches!(
                    class.shared(),
                    Some(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
                ),
                "{class:?}"
            );
            assert!(matches!(
                move_unit(types::MOVE, data),
                Some(Err(UnitError::Units(_)))
            ));
        }
    }
});
