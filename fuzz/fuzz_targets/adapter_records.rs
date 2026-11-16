//! frasil-adapter-records' decoders on arbitrary bytes: a unit's content,
//! as a log unit and as a snapshot unit, and a stream snapshot's state.
//! They never panic; what they accept is the one encoding of what they
//! return; and a state that loads takes accepted changesets in any order.
#![no_main]

use frasil_adapter::{Adapter, Context, Role};
use frasil_adapter_records::{Changeset, Content, Records, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let records = Records::new();
    for role in [Role::Log, Role::Snapshot] {
        let context = Context::new([1; 32], [2; 16], [3; 32], [4; 32], 1, 1, role);
        if let Ok(change) = records.decode(data, &context) {
            assert_eq!(
                records.encode(&change),
                data,
                "a second encoding of content"
            );
            // Applying it twice, and counting it, changes nothing more.
            let mut once = records.empty();
            records.apply(&mut once, &context, &change);
            let mut twice = once.clone();
            records.count(&mut twice, &context, data);
            records.apply(&mut twice, &context, &change);
            assert_eq!(once.to_bytes(false), twice.to_bytes(false));
        }
    }
    if let Ok(changeset) = Changeset::read(data) {
        assert_eq!(Content::Changeset(changeset).encode(), data);
    }
    if let Ok(state) = State::from_bytes(data) {
        assert_eq!(state.to_bytes(false), data, "a second encoding of a state");
        let free = state.to_bytes(true);
        let reloaded = State::from_bytes(&free).expect("a history-free export loads");
        assert_eq!(reloaded.to_bytes(false), free);
    }
});
