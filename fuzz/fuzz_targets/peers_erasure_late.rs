//! Keyless late-erasure checks on arbitrary signed envelopes.
#![no_main]
use frasil_events::EventId;
use frasil_peers::body::SlotId;
use frasil_peers::erasure::{LateErasure, check_late};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let Some((&standing, envelopes)) = data.split_first() else {
        return;
    };
    let Some((checkpoint, cut)) = envelopes.split_first_chunk::<32>() else {
        return;
    };
    let checkpoint = EventId(*checkpoint);
    let space = EventId([0; 32]);
    let erasure = EventId([1; 32]);
    let slot = SlotId::new([2; 32], 0, EventId([3; 32]));
    let _ = check_late(
        space,
        erasure,
        slot,
        LateErasure {
            space,
            erasure,
            cut,
            checkpoint,
            standing,
        },
    );
});
