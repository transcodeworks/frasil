//! frasil-events' log state at rest and fork points (crate `state`) on
//! arbitrary bytes. Neither reader panics; what they accept is the one
//! encoding of what they return; and a log read from a state answers its
//! causal questions without panicking.
#![no_main]

use frasil_events::{ForkPoints, Log};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(log) = Log::decode_state(data) {
        assert_eq!(log.encode_state(), data, "a second encoding of a log state");
        let order = log.canonical();
        assert_eq!(order.len(), log.len());
        let _ = log.heads();
        let _ = log.wanted();
        if let (Some(first), Some(last)) = (order.first(), order.last()) {
            let _ = log.precedes(*first, *last);
            let _ = log.past(*last);
        }
        let _ = log.fork_points(|_| true);
        // Cuts read back as decoding allows them, and their reach and
        // check never panic.
        for event in log.events() {
            assert!(event.cuts().len() <= frasil_events::MAX_CUTS);
            assert!(event.cuts().windows(2).all(|pair| pair[0] < pair[1]));
            assert!(!event.is_genesis() || event.cuts().is_empty());
            let _ = log.cuts_reach(event.id());
            let _ = log.check_cuts(&frasil_events::NoCheckpoints, event);
        }
    }
    if let Some(points) = ForkPoints::decode(data) {
        assert_eq!(points.encode(), data, "a second encoding of fork points");
    }
});
