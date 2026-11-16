//! frasil-peers' storage event body reader on arbitrary bytes (peers.md,
//! "Storage events"). It never panics; it refuses only with its document's
//! classes; and what it accepts is the one encoding of what it returns,
//! within the type's bounds.
#![no_main]

use frasil_base::ErrorClass;
use frasil_peers::PeersClass;
use frasil_peers::body::{ChangeEffect, StorageBody};
use frasil_peers::limits::{MAX_CUT_SLOTS, MAX_GRANTS, MAX_KEEP, MAX_LIVE_NAMED};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match StorageBody::read(data) {
        Ok(body) => {
            assert_eq!(body.encode(), data, "a second encoding of a body");
            match &body {
                StorageBody::Change {
                    effect: ChangeEffect::Grants(grants),
                    ..
                } => assert!((1..=MAX_GRANTS).contains(&grants.len())),
                // A cut carries at most 64 slot entries.
                StorageBody::Cut(cut) => assert!(cut.slots.len() <= MAX_CUT_SLOTS),
                // An erasure names the whole space, and nothing narrower.
                StorageBody::Erase => assert_eq!(data, [0xa3, 1, 1, 2, 5, 3, 1]),
                StorageBody::Credentials { live, recovery } => {
                    assert!(live.is_some() || recovery.is_some());
                    assert!(
                        live.as_ref()
                            .is_none_or(|l| (1..=MAX_LIVE_NAMED).contains(&l.len()))
                    );
                    assert!(recovery.as_ref().is_none_or(|k| k.len() <= MAX_KEEP));
                }
                _ => {}
            }
            // A slot reference names its maker beside `[c, index]`.
            if let Some(slot) = body.lowered() {
                assert!(usize::from(slot.reference.index) < MAX_GRANTS);
            }
            assert_eq!(StorageBody::read(&body.encode()), Ok(body));
        }
        Err(class) => assert!(
            matches!(
                class,
                PeersClass::Shared(
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::InvalidKey
                )
            ),
            "{class:?}"
        ),
    }
});
