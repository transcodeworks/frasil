//! Deterministic CBOR against encodings other documents' vectors hold. These
//! families belong to `frasil-events`; this file checks only that the
//! decoder takes their bytes, and claims nothing.

use frasil_base::cbor::{self, Malformed, Value};
use frasil_testkit::{hex, vectors::VectorFile};

#[test]
fn signed_events_decode_and_re_encode() {
    let file = VectorFile::load("events.json").unwrap();
    let encodings = file.family("encodings").unwrap().as_array().unwrap();
    assert!(!encodings.is_empty());
    for case in encodings {
        let signed = hex::from_value(&case["signed"]).unwrap();
        let event = hex::from_value(&case["event"]).unwrap();
        let outer = cbor::decode(&signed).unwrap();
        let [Value::Bytes(inner), Value::Bytes(_signature)] = outer.as_array().unwrap() else {
            panic!("{}: not two byte strings", case["name"]);
        };
        assert_eq!(inner, &event);
        let fields = cbor::decode(&event).unwrap();
        assert!(fields.as_map().is_ok());
        assert_eq!(fields.encode(), event);
        assert_eq!(outer.encode(), signed);
    }
}

#[test]
fn encoding_faults_are_malformed() {
    let file = VectorFile::load("events.json").unwrap();
    let refusals = file.family("refusals").unwrap().as_array().unwrap();
    let mut seen = 0;
    for case in refusals {
        let name = case["name"].as_str().unwrap();
        if name == "a trailing byte" || name == "a non-shortest head on the outer array" {
            let signed = hex::from_value(&case["signed"]).unwrap();
            assert_eq!(cbor::decode(&signed), Err(Malformed), "{name}");
            seen += 1;
        }
    }
    assert_eq!(seen, 2);
}
