//! frasil-events' decoders on arbitrary bytes (events.md, "Decoding an
//! event", "Refs" and "Verifying a proof"): the bytes as a signed event, as
//! an event's map signed by a fixed signer (so that the checks after the
//! signature's length are reached), as an equivocation proof and as refs.
//! They never panic; they refuse only with their documents' classes; and
//! what they accept is the one encoding of what they return. An accepted
//! event's cuts (key 7) are 1 to 4 strictly ascending IDs, or none, and
//! none in a genesis; checked against the event's own envelope as its only
//! held event, they never panic either.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_crypto::device::KeyRing;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::cuts::{self, CutsCheck, NoCheckpoints};
use frasil_events::envelope::{self, event_id};
use frasil_events::refs::{decode_refs_bytes, encode_refs};
use frasil_events::{EventClass, Log, MAX_CUTS, decode, verify_proof};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn signer() -> &'static Signer {
    static SIGNER: OnceLock<Signer> = OnceLock::new();
    SIGNER.get_or_init(|| Signer::from_seeds(&[1; 32], &[2; 32], None))
}

/// The fixed signer's keys, by their hash.
fn ring() -> KeyRing {
    let mut ring = KeyRing::new();
    ring.add_keys(signer().keys().clone());
    ring
}

fn check_signed(signed: &[u8]) {
    match decode(signed) {
        Ok(event) => {
            // One encoding: the signed bytes, the map and the ID.
            assert_eq!(event.signed(), signed);
            assert_eq!(event.signed_len(), signed.len());
            assert_eq!(event.id(), event_id(event.event_bytes()));
            assert_eq!(event.tbs(), envelope::tbs(event.event_bytes()));
            // The fixed signer's keys verify only an event under its kc.
            let verdict = event.verify_hybrid(Some(signer().keys()));
            // A verified event gives its fields, whose encoding is the map.
            if let Ok(verified) = &verdict {
                assert_eq!(verified.envelope().encode(), event.event_bytes());
                assert_eq!(verified.event(), &event);
            }
            assert_eq!(
                event.verified_scheme_0().is_some(),
                event.scheme() == Scheme::Ed25519
            );
            assert!(
                event.scheme() == Scheme::Ed25519
                    || verdict.is_ok()
                    || verdict == Err(ErrorClass::BadSignature.into())
                    || (verdict == Err(ErrorClass::NoHybridKey.into())
                        && event.kc() != signer().kc())
            );
            // A log starts from a genesis, and from nothing else.
            assert_eq!(Log::new(event.clone()).is_ok(), event.is_genesis());
            // Cuts: at most four, strictly ascending, none in a genesis.
            let cut_ids = event.cuts();
            assert!(cut_ids.len() <= MAX_CUTS);
            assert!(cut_ids.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(!event.is_genesis() || cut_ids.is_empty());
            // Read with its own envelope as the only one held: a parent
            // not held keeps the check pending, and nothing panics.
            let held = BTreeMap::from([(event.id(), event.clone())]);
            match cuts::reach(&held, cut_ids) {
                Ok(reached) => assert!(cut_ids.iter().all(|cut| reached.contains(cut))),
                // A cut whose envelope is not held waits for it.
                Err(missing) => assert!(missing.iter().all(|cut| cut_ids.contains(cut))),
            }
            let check = cuts::check(&held, &NoCheckpoints, &event);
            if event.is_genesis() {
                assert_eq!(check, CutsCheck::Correct);
            } else {
                assert_eq!(check, CutsCheck::Pending(event.parents().to_vec()));
            }
        }
        Err(class) => assert!(
            matches!(
                class,
                EventClass::UnknownKind
                    | EventClass::Shared(
                        ErrorClass::TooLarge
                            | ErrorClass::Malformed
                            | ErrorClass::UnsupportedVersion
                            | ErrorClass::SchemeNotAllowed
                            | ErrorClass::InvalidKey
                            | ErrorClass::BadSignature
                    )
            ),
            "{class:?}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    check_signed(data);

    // The bytes as an event's map, signed by the fixed signer: scheme 2 when
    // the map says so, scheme 0 otherwise.
    let scheme = match cbor::decode(data) {
        Ok(Value::Map(map)) if map.get(&9) == Some(&Value::Unsigned(2)) => Scheme::Hybrid,
        _ => Scheme::Ed25519,
    };
    let signature = signer().sign(scheme, &envelope::tbs(data));
    check_signed(&envelope::assemble(data, &signature));

    match verify_proof(data, &ring()) {
        Ok(shown) => {
            assert_eq!(shown.author, *shown.first.author());
            assert_eq!(shown.log, shown.first.log_id());
            assert!(shown.fork_seq >= 1 && shown.fork_seq <= shown.first.seq());
        }
        Err(class) => assert!(!matches!(class, EventClass::WrongLog)),
    }

    if let Ok(refs) = decode_refs_bytes(data) {
        assert_eq!(encode_refs(&refs), data, "a second encoding of refs");
    }
});
