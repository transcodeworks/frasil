//! frasil-ephemeral's inner map reader and Frasil's names on arbitrary bytes
//! (ext-ephemeral.md, "The inner map", "Frasil's names" and "Receiving",
//! steps 7 and 11). They never panic; the reader refuses only with
//! `Malformed` or `UnsupportedVersion`; and what it accepts is the one
//! encoding of what it returns.
#![no_main]

use frasil_base::ErrorClass;
use frasil_ephemeral::inner::{Inner, adapter_ok, name_ok};
use frasil_ephemeral::names::{check_reserved, list_events_ok};
use frasil_ephemeral::{EphemeralClass, Kind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let space = [7; 32];
    let _ = list_events_ok(data, &space);
    match Inner::read(data) {
        Ok(inner) => {
            assert_eq!(inner.encode(), data, "a second encoding");
            assert!(name_ok(&inner.name));
            assert!(inner.adapter.as_deref().is_none_or(adapter_ok));
            assert!(inner.kind == Kind::Message || inner.targets.is_none());
            assert!(inner.fresh.is_none() || inner.targets.is_some());
            if let Err(class) = check_reserved(&inner, &space, |_| true) {
                assert!(
                    matches!(
                        class,
                        EphemeralClass::UnknownName | EphemeralClass::Shared(ErrorClass::Malformed)
                    ),
                    "{class:?}"
                );
            }
        }
        Err(class) => assert!(
            matches!(
                class,
                EphemeralClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
            ),
            "{class:?}"
        ),
    }
});
