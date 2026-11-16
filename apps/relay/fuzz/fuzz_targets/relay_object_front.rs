//! frasil-relay's reading of an object's front on arbitrary bytes: the
//! first 64 bytes are a locator, the rest piece 0 (units.md, "Objects";
//! transport.md, "The server binding"). It never panics, and what it
//! accepts lays out the stored object's sealed chunks end to end.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/objects.rs"]
mod objects;

use libfuzzer_sys::fuzz_target;
use objects::{Layout, pieces_of};

fuzz_target!(|data: &[u8]| {
    let Some((locator, front)) = data.split_first_chunk::<64>() else {
        return;
    };
    let Some(layout) = Layout::read(front, locator) else {
        return;
    };
    assert!(layout.start >= 4 && layout.total >= layout.start);
    assert!(layout.chunks >= 1);
    assert!(pieces_of(layout.total) >= 1);
    let first = layout.chunk_range(0).expect("chunk 0");
    assert_eq!(first.0, layout.start);
    let last = layout
        .chunk_range(layout.chunks - 1)
        .expect("the last chunk");
    assert_eq!(last.1, layout.total, "the last chunk ends the object");
    assert!(layout.chunk_range(layout.chunks).is_none());
    if layout.chunks >= 2 {
        let second = layout.chunk_range(1).expect("chunk 1");
        assert_eq!(first.1, second.0, "chunks follow each other");
    }
    if layout.chunks <= 64 {
        assert_eq!(layout.chunks_within(layout.total), layout.chunks);
    }
    assert_eq!(layout.chunks_within(layout.start), 0);
});
