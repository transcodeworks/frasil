//! The decoders' properties that the fuzz targets check (`fuzz/fuzz_targets/
//! units_*.rs`), run here over every byte string of units.json and
//! mutations of each: no decoder panics, and what one accepts is the one
//! encoding of what it returns.

mod common;

use common::*;
use frasil_crypto::primitives::sha256;
use frasil_units::body::Body;
use frasil_units::inner::Inner;
use frasil_units::messages::{Received, SyncMessage};
use frasil_units::objects::check_stored_chunked;
use frasil_units::own::{ListEventsBody, SystemState};
use frasil_units::snapshot::{SpaceSnapshot, StreamSnapshot};
use frasil_units::statement::HeadStatement;
use frasil_units::types;
use frasil_units::unit::Unit;
use serde_json::Value as Json;

const STREAM: [u8; 16] = [1; 16];

fn strings(value: &Json, out: &mut Vec<Vec<u8>>) {
    match value {
        Json::String(text) => {
            if let Ok(bytes) = frasil_testkit::hex::decode(text)
                && !bytes.is_empty()
            {
                out.push(bytes);
            }
        }
        Json::Array(items) => items.iter().for_each(|item| strings(item, out)),
        Json::Object(map) => map.values().for_each(|item| strings(item, out)),
        _ => {}
    }
}

/// Each byte string, and its unit's or message's inner byte strings, with
/// a few mutations: truncated, a byte flipped, a byte appended.
fn inputs() -> Vec<Vec<u8>> {
    let file = frasil_testkit::vectors::VectorFile::load(FILE).unwrap();
    let mut out = Vec::new();
    for (_, value) in file.families() {
        strings(value, &mut out);
    }
    let mut more = Vec::new();
    for bytes in &out {
        if bytes.len() > 4096 {
            continue;
        }
        more.push(bytes[..bytes.len() / 2].to_vec());
        for at in [0, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            more.push(flipped);
        }
        let mut longer = bytes.clone();
        longer.push(0);
        more.push(longer);
    }
    out.extend(more);
    out
}

fn check(data: &[u8]) {
    if let Ok(body) = Body::read(data) {
        assert_eq!(body.encode(), data);
    }
    for snapshot in [false, true] {
        if let Ok(inner) = Inner::read(data, snapshot, &STREAM, None) {
            assert_eq!(inner.encode(), data);
        }
    }
    if let Ok(unit) = Unit::check_at_peer(data) {
        assert_eq!(unit.body.encode(), unit.event.unverified_body());
    }
    if let Ok(state) = SystemState::read(data) {
        assert_eq!(state.encode().as_deref(), Ok(data));
    }
    if let Ok(body) = ListEventsBody::read(data) {
        assert_eq!(body.encode(), data);
    }
    if let Ok(snapshot) = StreamSnapshot::read(data, &STREAM, types::RECORDS) {
        assert_eq!(snapshot.encode(), data);
    }
    let mut locator = [0; 64];
    locator[32..].copy_from_slice(&sha256(&[data]));
    let _ = check_stored_chunked(data, &locator, 64);
    match SyncMessage::read(data) {
        Ok(Received::Message(message)) => assert_eq!(message.encode(), data),
        Ok(Received::Ignored { type_code }) => assert!(type_code >= 64),
        Err(_) => {}
    }
    let _ = HeadStatement::read(data, &space(), |_| true);
    if let Ok(snapshot) = SpaceSnapshot::decode(data) {
        assert_eq!(snapshot.encode().as_deref(), Ok(data));
    }
    let _ = SpaceSnapshot::read(data, &space(), &());
}

#[test]
fn decoders_accept_one_encoding_and_never_panic() {
    let inputs = inputs();
    assert!(inputs.len() > 500);
    for data in &inputs {
        check(data);
        // The CBOR byte strings inside each input, such as a snapshot's map
        // inside its signed array, or a unit's body inside its event.
        if let Ok(value) = frasil_base::cbor::decode(data) {
            let mut inner = Vec::new();
            collect(&value, &mut inner);
            for bytes in inner {
                check(&bytes);
            }
        }
    }
}

fn collect(value: &frasil_base::cbor::Value, out: &mut Vec<Vec<u8>>) {
    use frasil_base::cbor::Value;
    match value {
        Value::Bytes(bytes) if bytes.len() > 1 => out.push(bytes.clone()),
        Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
        Value::Map(map) => map.values().for_each(|item| collect(item, out)),
        _ => {}
    }
}
