//! frasil-adapter-loro's decoders on arbitrary bytes: a unit's content, as
//! a log unit and as a snapshot unit, a blob's metadata, and a stream
//! snapshot's state. They never panic; what they accept is the one encoding
//! of what they return; and a state that loads compacts and exports to
//! states that load.
#![no_main]

use frasil_adapter::{Adapter, Context, Role};
use frasil_adapter_loro::{BlobMeta, Content, Loro, SnapshotState, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let loro = Loro::new();
    for role in [Role::Log, Role::Snapshot] {
        let context = Context::new([1; 32], [2; 16], [3; 32], [4; 32], 9, 9, role);
        if let Ok(change) = loro.decode(data, &context) {
            assert_eq!(loro.encode(&change), data, "a second encoding of content");
            // Applying it twice, and counting it, changes nothing more.
            let mut once = loro.empty();
            loro.count(&mut once, &context, data);
            loro.apply(&mut once, &context, &change);
            let mut twice = loro.empty();
            loro.apply(&mut twice, &context, &change);
            loro.count(&mut twice, &context, data);
            loro.apply(&mut twice, &context, &change);
            assert!(once.matches(&twice));
        }
    }
    if let Ok(content) = Content::read(data) {
        assert_eq!(content.encode(), data);
    }
    let _ = BlobMeta::read(data);
    if let Ok(framed) = SnapshotState::read(data) {
        assert_eq!(framed.encode(), data, "a second encoding of a state");
    }
    if let Ok(state) = State::load(data) {
        let compacted = loro.compact(&state).state;
        let reloaded = State::load(&compacted).expect("a compacted state loads");
        assert!(reloaded.matches(&state));
        // An export the checks refuse is refused; any other loads.
        if let Ok(free) = loro.export_history_free(&state) {
            let loaded = State::load(&free).expect("a history-free export loads");
            assert_eq!(loaded.doc().oplog_vv(), state.doc().oplog_vv());
        }
    }
});
