//! frasil-relay's internal-link bodies that travel as JSON, on arbitrary
//! bytes (crate `cluster`, module `json`): Raft's `AppendEntries`, `Vote`
//! and `InstallSnapshot` and their answers, a command proposed to the
//! leader and its answer, and a join and its answer. A body that reads is
//! written again, and reads back as what was written. The reader never
//! panics. The first byte picks the body and whether it is a request's or
//! an answer's.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/cluster/wire.rs"]
mod wire;

#[allow(dead_code)]
#[path = "../../src/cluster/json.rs"]
mod json;

use libfuzzer_sys::fuzz_target;

const TAGS: [u8; 5] = [
    wire::RAFT_APPEND,
    wire::RAFT_VOTE,
    wire::RAFT_SNAPSHOT,
    wire::PROPOSE,
    wire::JOIN,
];

fuzz_target!(|data: &[u8]| {
    let [pick, body @ ..] = data else {
        return;
    };
    let tag = TAGS[usize::from(*pick >> 1) % TAGS.len()];
    let _ = json::round_trip(pick & 1 == 0, tag, body);
});
