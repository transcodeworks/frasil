//! frasil-space-file's record reader on arbitrary input (ext-space-files.md,
//! "Records"): a record body's type, and the record read from it. It never
//! panics; it refuses only with the document's classes; and what it accepts
//! is the one encoding of what it returns, except an ignorable record, whose
//! body is skipped.
#![no_main]

use frasil_base::ErrorClass;
use frasil_space_file::record::Record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let type_of = Record::type_of(data);
    match Record::read(data) {
        Ok(record) => {
            assert_eq!(type_of, Ok(record.type_code()), "the type read first");
            if !matches!(record, Record::Ignored(_)) {
                let framed = record.encode().expect("what was read fits");
                assert_eq!(&framed[4..], data, "a second encoding");
            }
        }
        Err(class) => assert!(
            matches!(
                class,
                ErrorClass::Malformed
                    | ErrorClass::UnsupportedVersion
                    | ErrorClass::RevisionMismatch
                    | ErrorClass::TooLarge
            ),
            "{class:?}"
        ),
    }
});
