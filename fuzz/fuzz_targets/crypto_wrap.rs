//! frasil-crypto's wrap reader and opener on arbitrary bytes (crypto.md,
//! "Opening a wrap"). They never panic; the reader refuses only as
//! `Malformed` or `UnsupportedVersion`, in the document's order, and splits
//! what it accepts into the header, `enc` and the ciphertext; and a wrap
//! opens only if its layout reads.
#![no_main]

use frasil_crypto::ErrorClass;
use frasil_crypto::wrap::{self, WrapLength, WrapUse};
use libfuzzer_sys::fuzz_target;

/// A fixed recipient, so that a wrap the fuzzer finds can open.
const SEED: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let lengths = WrapUse::ALL
        .iter()
        .map(|use_| use_.length())
        .chain([WrapLength::AtLeast(0), WrapLength::Exactly(data.len())]);
    for length in lengths {
        match wrap::read_wrap(data, length) {
            Ok(parts) => {
                assert_eq!(data[0], wrap::WRAP_VERSION);
                assert_eq!(u16::from_be_bytes([data[1], data[2]]), wrap::SUITE_XWING);
                assert!(length.admits(data.len()));
                assert_eq!(parts.enc.len(), 1120);
                assert_eq!(
                    wrap::WRAP_HEADER + parts.enc.len() + parts.ciphertext.len(),
                    data.len()
                );
                assert!(parts.ciphertext.len() >= wrap::HPKE_TAG);
            }
            Err(ErrorClass::UnsupportedVersion) => {
                assert!(
                    data[0] != wrap::WRAP_VERSION
                        || (data.len() >= 3
                            && u16::from_be_bytes([data[1], data[2]]) != wrap::SUITE_XWING)
                );
            }
            Err(ErrorClass::Malformed) => {}
            Err(other) => panic!("read_wrap refused as {other:?}"),
        }
        let opened = wrap::open_wrap(data, &SEED, b"info", length);
        if let Err(class) = &opened {
            assert!(matches!(
                class,
                ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
            ));
        }
        if wrap::read_wrap(data, length).is_err() {
            assert!(opened.is_err());
        }
    }
});
