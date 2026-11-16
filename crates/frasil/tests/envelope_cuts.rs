//! The envelope's cuts, key 7 (events.md, 2.1 The envelope, 3.1 Decoding
//! an event): any envelope with up to four cuts, given in any order and
//! with repeats, encodes to one map that decodes to the same fields, cuts
//! strictly ascending, and signs to an event with the same ID.
#![cfg(not(target_arch = "wasm32"))]

use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::envelope::{Envelope, EventId, KEY_CUTS};
use frasil_events::{EventClass, MAX_CUTS, decode, kind};
use proptest::prelude::*;
use std::sync::OnceLock;

fn signer() -> &'static Signer {
    static SIGNER: OnceLock<Signer> = OnceLock::new();
    SIGNER.get_or_init(|| Signer::from_seeds(&[5; 32], &[6; 32], None))
}

fn envelope(cuts: Vec<EventId>, parents: Vec<EventId>, seq: u64, body: Vec<u8>) -> Envelope {
    let signer = signer();
    Envelope {
        kind: kind::UNIT,
        log: Some(EventId([0x11; 32])),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev: (seq > 1).then(|| parents[0]),
        parents,
        cuts,
        body,
        scheme: Scheme::Ed25519,
    }
}

fn ids(max: usize) -> impl Strategy<Value = Vec<EventId>> {
    prop::collection::vec(any::<[u8; 32]>().prop_map(EventId), 0..=max)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn cuts_round_trip(
        cuts in ids(MAX_CUTS),
        repeat in any::<bool>(),
        parents in ids(4),
        first in any::<[u8; 32]>(),
        seq in 1u64..1_000,
        body in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut parents = parents;
        parents.insert(0, EventId(first));
        let mut given = cuts.clone();
        given.reverse();
        if repeat && !given.is_empty() {
            given.push(given[0]);
        }
        let mut canonical = cuts;
        canonical.sort();
        canonical.dedup();
        let shuffled = envelope(given, parents.clone(), seq, body.clone());
        let sorted = envelope(canonical.clone(), parents, seq, body);
        // One map, whatever the order and repeats given.
        prop_assert_eq!(shuffled.encode(), sorted.encode());
        prop_assert_eq!(shuffled.id(), sorted.id());
        // Key 7 is present exactly when there is a cut.
        let map = frasil_base::cbor::decode(&sorted.encode()).unwrap();
        prop_assert_eq!(
            map.as_map().unwrap().contains_key(&KEY_CUTS),
            !canonical.is_empty()
        );
        let signed = shuffled.sign(signer());
        let event = decode(&signed).unwrap();
        prop_assert_eq!(event.cuts(), canonical.as_slice());
        prop_assert_eq!(event.id(), sorted.id());
        prop_assert_eq!(event.signed(), signed);
        let verified = event.verified_scheme_0().unwrap();
        let mut parents = sorted.parents.clone();
        parents.sort();
        parents.dedup();
        let expected = Envelope { parents, ..sorted };
        prop_assert_eq!(verified.envelope(), &expected);
        prop_assert_eq!(verified.envelope().encode(), event.event_bytes());
    }

    #[test]
    fn more_than_four_cuts_are_malformed(cuts in prop::collection::vec(any::<[u8; 32]>(), 5..9)) {
        let mut cuts: Vec<EventId> = cuts.into_iter().map(EventId).collect();
        cuts.sort();
        cuts.dedup();
        prop_assume!(cuts.len() > MAX_CUTS);
        let signed = envelope(cuts, vec![EventId([0x22; 32])], 1, vec![]).sign(signer());
        prop_assert_eq!(decode(&signed), Err(EventClass::from(frasil_base::ErrorClass::Malformed)));
    }
}
