//! frasil-base's deterministic CBOR decoder on arbitrary bytes. It never
//! panics; what it accepts is the one encoding of the value it returns; the
//! streaming reader accepts the same items; and a value's encoding decodes
//! to itself.
#![no_main]

use frasil_base::cbor::{self, Reader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = cbor::decode(data);
    if let Ok(value) = &decoded {
        assert_eq!(value.encode(), data, "decode accepts a second encoding");
    }

    // The streaming reader reads the same first item; with nothing after
    // it, it agrees with decode.
    let mut reader = Reader::new(data);
    let streamed = reader.value();
    if reader.is_finished() {
        assert_eq!(streamed, decoded, "the reader and decode disagree");
    }
    if let Ok(value) = streamed {
        let encoded = value.encode();
        assert_eq!(cbor::decode(&encoded), Ok(value));
        assert!(
            data.starts_with(&encoded),
            "the reader took another encoding"
        );
    }
});
