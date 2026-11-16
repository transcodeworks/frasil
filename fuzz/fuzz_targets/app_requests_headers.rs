//! frasil-app-requests' header reader on arbitrary header values
//! (ext-app-requests.md, "Headers"; "Verifying", step 3). It never panics,
//! and every value it accepts has one spelling: what it read writes back as
//! the exact bytes received.
//!
//! The input is lines split at `\n`. A line's first byte picks a header (its
//! value modulo 7, where 6 is a header of another name) and, by its top bit,
//! whether the name arrives in lower case; the rest of the line is the value.
#![no_main]

use frasil_app_requests::headers::read_heads;
use frasil_app_requests::{Header, Received, ReceivedHeaders, SignedHeaders};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut names = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let Some((&pick, value)) = line.split_first() else {
            continue;
        };
        let name = match Header::ALL.get(usize::from(pick & 0x7f) % 7) {
            Some(header) => header.name().to_string(),
            None => "Content-Type".to_string(),
        };
        let name = if pick & 0x80 != 0 {
            name.to_ascii_lowercase()
        } else {
            name
        };
        names.push((name, value));
    }
    let received =
        ReceivedHeaders::from_pairs(names.iter().map(|(name, value)| (name.as_str(), *value)));
    if let Ok(signed) = SignedHeaders::read(&received) {
        for header in Header::ALL {
            let written = signed.value(header);
            match received.get(header) {
                Received::Once(value) => {
                    assert_eq!(written.as_deref().map(str::as_bytes), Some(value));
                }
                Received::Absent => assert_eq!(written, None, "{}", header.name()),
                Received::Repeated => panic!("a repeated header was read"),
            }
        }
    }
    if let Some(heads) = read_heads(data) {
        let written: Vec<String> = heads
            .iter()
            .map(|id| frasil_base::notation::hex::encode(id.0))
            .collect();
        assert_eq!(written.join(",").as_bytes(), data);
    }
});
