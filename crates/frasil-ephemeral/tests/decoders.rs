//! The decoders' properties that the fuzz targets check
//! (`fuzz/fuzz_targets/ephemeral_*.rs`), run here over every byte string of
//! ext-ephemeral.json and mutations of each: no decoder panics, each refuses
//! only with its steps' classes, and what one accepts is the one encoding of
//! what it returns.

use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_ephemeral::frame::{pad, read_core, unpad};
use frasil_ephemeral::inner::{Inner, adapter_ok, name_ok};
use frasil_ephemeral::names::{check_reserved, list_events_ok};
use frasil_ephemeral::receive::read_restricted_reference;
use frasil_ephemeral::{EphemeralClass, Outer};
use serde_json::Value as Json;

fn strings(value: &Json, out: &mut Vec<Vec<u8>>) {
    match value {
        Json::String(text) => {
            if let Ok(bytes) = frasil_testkit::hex::decode(text)
                && !bytes.is_empty()
            {
                out.push(bytes);
            }
        }
        Json::Array(items) => items.iter().for_each(|i| strings(i, out)),
        Json::Object(map) => map.values().for_each(|i| strings(i, out)),
        _ => {}
    }
}

/// Every byte string of the file, then for each: every truncation at a
/// sixteenth of its length, and one bit flipped at each sixteenth.
fn inputs() -> Vec<Vec<u8>> {
    let file = frasil_testkit::vectors::VectorFile::load("ext-ephemeral.json").unwrap();
    let mut seeds = Vec::new();
    for (_, family) in file.families() {
        strings(family, &mut seeds);
    }
    let mut out = Vec::new();
    for seed in seeds {
        for i in 0..16 {
            let at = seed.len() * i / 16;
            out.push(seed[..at].to_vec());
            let mut flipped = seed.clone();
            flipped[at] ^= 1 << (i % 8);
            out.push(flipped);
        }
        out.push(seed);
    }
    out
}

fn outer_property(data: &[u8]) {
    let scope: [u8; 32] = match cbor::decode(data) {
        Ok(Value::Map(map)) => map
            .get(&3)
            .and_then(|space| space.as_byte_array().ok())
            .unwrap_or([0; 32]),
        _ => [0; 32],
    };
    match Outer::read(data, &scope) {
        Ok(frame) => assert_eq!(frame.encode(), data),
        Err(class) => assert!(
            matches!(
                class,
                EphemeralClass::Shared(
                    ErrorClass::TooLarge | ErrorClass::Malformed | ErrorClass::UnsupportedVersion
                )
            ),
            "{class:?}"
        ),
    }
}

fn inner_property(data: &[u8]) {
    let space = [7; 32];
    let _ = list_events_ok(data, &space);
    match Inner::read(data) {
        Ok(inner) => {
            assert_eq!(inner.encode(), data);
            assert!(name_ok(&inner.name));
            assert!(inner.adapter.as_deref().is_none_or(adapter_ok));
            let _ = check_reserved(&inner, &space, |_| true);
        }
        Err(class) => assert!(
            matches!(
                class,
                EphemeralClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
            ),
            "{class:?}"
        ),
    }
}

fn plaintext_property(data: &[u8]) {
    if let Ok(core) = unpad(data) {
        assert_eq!(pad(core).as_deref(), Ok(data));
        let _ = read_core(core);
    }
    if let Err(class) = read_restricted_reference(data) {
        assert!(
            matches!(
                class,
                EphemeralClass::TooManyRotations | EphemeralClass::Shared(ErrorClass::Malformed)
            ),
            "{class:?}"
        );
    }
}

#[test]
fn decoders_hold_their_properties() {
    let inputs = inputs();
    assert!(inputs.len() > 1000);
    let mut accepted = [0; 3];
    for data in &inputs {
        outer_property(data);
        inner_property(data);
        plaintext_property(data);
        accepted[0] +=
            usize::from(Outer::read(data, &[0; 32]).is_ok() || cbor::decode(data).is_ok());
        accepted[1] += usize::from(Inner::read(data).is_ok());
        accepted[2] += usize::from(unpad(data).is_ok());
    }
    // The seeds themselves are read.
    assert!(accepted.iter().all(|&n| n > 0), "{accepted:?}");
}
