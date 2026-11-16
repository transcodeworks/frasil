//! frasil-adapter-blobs' decoders on arbitrary bytes: a unit's content, as
//! a log unit with and without its objects listed and as a snapshot unit,
//! an entry's key reference, and a stream snapshot's state. They never
//! panic, and what they accept is the one encoding of what they return.
#![no_main]

use frasil_adapter::{Adapter, Context, Role};
use frasil_adapter_blobs::entry::read_rotation_set;
use frasil_adapter_blobs::{Blobs, Change, Content, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let blobs = Blobs::new();
    let _ = read_rotation_set(data);
    let listed: Vec<_> = Change::read(data)
        .map(|change| change.objects().into_iter().collect())
        .unwrap_or_default();
    for (role, objects) in [
        (Role::Log, Vec::new()),
        (Role::Log, listed),
        (Role::Snapshot, Vec::new()),
    ] {
        let context =
            Context::new([1; 32], [2; 16], [3; 32], [4; 32], 1, 1, role).with_objects(objects);
        if let Ok(change) = blobs.decode(data, &context) {
            assert_eq!(blobs.encode(&change), data, "a second encoding of content");
            let mut once = blobs.empty();
            blobs.apply(&mut once, &context, &change);
            let mut twice = once.clone();
            blobs.count(&mut twice, &context, data);
            blobs.apply(&mut twice, &context, &change);
            assert_eq!(once.to_bytes(false), twice.to_bytes(false));
            if let Content::Change(change) = &change {
                assert!(change.objects().iter().all(|o| context.objects.contains(o)));
            }
        }
    }
    if let Ok(state) = State::from_bytes(data) {
        assert_eq!(state.to_bytes(false), data, "a second encoding of a state");
        let free = state.to_bytes(true);
        let reloaded = State::from_bytes(&free).expect("a history-free export loads");
        assert_eq!(reloaded.to_bytes(false), free);
    }
});
