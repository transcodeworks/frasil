//! frasil-relay's hand-over bundle and its pages of shard records on
//! arbitrary bytes (crate `libraries`, module `bundle`): the readers never
//! panic, a header, an item or a page read and written again reads back as
//! the same, and the bytes split into items without a panic.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/libraries/bundle.rs"]
mod bundle;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(read) = bundle::Header::decode(data) {
        assert_eq!(bundle::Header::decode(&read.encode()[4..]), Some(read));
    }
    if let Some(read) = bundle::Item::decode(data) {
        assert_eq!(bundle::Item::decode(&read.encode()[4..]), Some(read));
    }
    if let Some((rows, more)) = bundle::decode_page(data) {
        assert_eq!(
            bundle::decode_page(&bundle::encode_page(&rows, more)),
            Some((rows, more))
        );
    }
    let mut items = bundle::Items::default();
    items.push(data);
    while let Ok(Some(_)) = items.take() {}
});
