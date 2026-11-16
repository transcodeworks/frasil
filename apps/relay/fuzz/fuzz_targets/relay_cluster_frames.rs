//! frasil-relay's internal-link frames between a cluster's nodes, once
//! opened, on arbitrary bytes (crate `cluster`, module `wire`): a frame
//! that reads is written again as the same bytes, and its body, of every
//! kind and tag this peer reads, reads back as what it wrote. The reader
//! never panics. The first two bytes also pick a kind and a tag for the
//! rest, so that every body's reader sees arbitrary bytes.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/cluster/wire.rs"]
mod wire;

use libfuzzer_sys::fuzz_target;

const KINDS: [u8; 3] = [wire::REQUEST, wire::RESPONSE, wire::NOTICE];

fuzz_target!(|data: &[u8]| {
    if let Some(frame) = wire::Frame::decode(data) {
        assert_eq!(frame.encode(), data, "a second encoding of a frame");
        let _ = wire::round_trip(frame.kind, frame.tag, &frame.body);
    }
    let [kind, tag, body @ ..] = data else {
        return;
    };
    let kind = KINDS[usize::from(*kind) % KINDS.len()];
    let _ = wire::round_trip(kind, *tag % 22, body);
});
