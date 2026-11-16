//! frasil-space-file's file reader and sniffer on arbitrary input
//! (ext-space-files.md, "The file", "Sniff"): both walk the records by
//! their lengths, neither panics, each refuses only with the document's
//! classes, and a file that reads sniffs as the same space and kind.
#![no_main]

use frasil_base::ErrorClass;
use frasil_space_file::file::{Refusal, read, sniff};
use libfuzzer_sys::fuzz_target;

fn allowed(refusal: &Refusal) -> bool {
    match refusal {
        Refusal::NotASpaceFile => true,
        Refusal::Class(class) => matches!(
            class,
            ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::TooLarge
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let sniffed = sniff(data);
    match read(data) {
        Ok(file) => {
            assert!(
                file.whole <= data.len(),
                "the whole part is within the file"
            );
            let sniffed = sniffed.as_ref().expect("a file that reads sniffs");
            assert_eq!(sniffed.manifest.space, file.manifest.space, "one space");
            assert_eq!(sniffed.manifest.kind, file.manifest.kind, "one kind");
            assert_eq!(
                sniffed.way_in.is_some(),
                file.way_in.is_some(),
                "the way in's presence"
            );
        }
        Err(refusal) => assert!(allowed(&refusal), "{refusal:?}"),
    }
    if let Err(refusal) = &sniffed {
        assert!(allowed(refusal), "{refusal:?}");
    }
});
