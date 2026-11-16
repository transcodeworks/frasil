//! `keys.json`: `sealed_names` (keys.md, sections 2.8 and 3.16).

use frasil_events::EventId;
use frasil_keys::derive::{Secret, SecretKind, metadata_key, state_secret};
use frasil_keys::sealed_names::{
    KIND_DOCUMENT, KIND_SPACE, Record, encode_record, name_aad, open_name, open_record, padded_len,
    seal_name_with,
};
use frasil_keys::{KeyClass, RotationSet};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde_json::Value as Json;
use std::collections::BTreeMap;

const FILE: &str = "keys.json";

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().unwrap()).unwrap()
}

fn id(value: &Json) -> EventId {
    EventId(array(value))
}

fn class(value: &Json) -> KeyClass {
    KeyClass::from_name(value.as_str().unwrap()).unwrap()
}

fn kind_code(kind: &Json) -> u8 {
    match kind.as_str().unwrap() {
        "space" => KIND_SPACE,
        "document" => KIND_DOCUMENT,
        "kind 5" => 5,
        other => panic!("{other}"),
    }
}

#[test]
fn sealed_names() {
    let f: Json = vectors::family(FILE, "sealed_names");
    let labels = f["labels"].as_object().unwrap();
    for label in [
        frasil_crypto::labels::NAME,
        frasil_crypto::labels::SPACE_METADATA_KEY,
    ] {
        let text = std::str::from_utf8(label).unwrap();
        assert_eq!(labels[text], hex::encode(label));
    }
    assert_eq!(f["kinds"]["space"], KIND_SPACE);
    assert_eq!(f["kinds"]["document"], KIND_DOCUMENT);
    let space = id(&f["space"]);

    // The states, by key reference: their content and metadata keys.
    let mut states: BTreeMap<String, (RotationSet, [u8; 32], [u8; 32])> = BTreeMap::new();
    for state in f["states"].as_array().unwrap() {
        let set = RotationSet::new(state["rotations"].as_array().unwrap().iter().map(id)).unwrap();
        assert_eq!(set.encode(), bytes(&state["key_reference"]));
        let content = array::<32>(&state["content_key"]);
        if let Some(inputs) = state["content_key_inputs"].as_array() {
            let inputs: Vec<[u8; 32]> = inputs.iter().map(array).collect();
            let merged = state_secret(SecretKind::Content, &space, &set, &inputs).unwrap();
            assert_eq!(*merged, content);
        }
        let mk = *metadata_key(&content);
        assert_eq!(mk, array::<32>(&state["metadata_key"]));
        states.insert(
            state["state"].as_str().unwrap().to_owned(),
            (set, content, mk),
        );
    }
    let content_key_of = |reference: &RotationSet| {
        states
            .values()
            .find(|(set, _, _)| set == reference)
            .map(|(_, content, _)| Secret::new(*content))
    };

    for case in f["sealed"].as_array().unwrap() {
        let title = case["name"].as_str().unwrap();
        assert_eq!(id(&case["space"]), space);
        let (reference, _, mk) = &states[case["state"].as_str().unwrap()];
        let kind = kind_code(&case["kind"]);
        assert_eq!(case["kind_code"], kind);
        let item = bytes(&case["id"]);
        let name = String::from_utf8(bytes(&case["name_bytes"])).unwrap();

        let mut padded = (name.len() as u16).to_be_bytes().to_vec();
        padded.extend_from_slice(name.as_bytes());
        padded.resize(padded_len(name.len()), 0);
        assert_eq!(padded, bytes(&case["padded"]), "{title}");
        assert_eq!(
            name_aad(&space, reference, kind, &item),
            bytes(&case["aad"]),
            "{title}"
        );

        let sealed = seal_name_with(
            mk,
            &space,
            reference,
            kind,
            &item,
            &name,
            &array(&case["nonce"]),
        )
        .unwrap();
        assert_eq!(sealed, bytes(&case["sealed"]), "{title}");
        assert_eq!(
            open_name(mk, &space, reference, kind, &item, &sealed).as_deref(),
            Ok(name.as_str())
        );

        let record = encode_record(&space, reference, &sealed);
        assert_eq!(record, bytes(&case["record"]), "{title}");
        let read = Record::read(&record).unwrap();
        assert_eq!(
            (read.space, &read.reference, read.sealed),
            (space, reference, &sealed[..])
        );
        assert_eq!(
            open_record(&record, &space, content_key_of, kind, &item).as_deref(),
            Ok(name.as_str())
        );
    }

    for case in f["refusals"].as_array().unwrap() {
        let title = case["name"].as_str().unwrap();
        let kind = kind_code(&case["kind"]);
        let item = bytes(&case["id"]);
        let in_space = id(&case["space"]);
        let result = match case["operation"].as_str().unwrap() {
            "open" => open_name(
                &array(&case["metadata_key"]),
                &in_space,
                &RotationSet::decode(&bytes(&case["key_reference"])).unwrap(),
                kind,
                &item,
                &bytes(&case["sealed"]),
            )
            .map(|_| ()),
            "seal" => {
                let (reference, _, mk) = &states["A+B"];
                let name = String::from_utf8(bytes(&case["name_bytes"])).unwrap();
                seal_name_with(mk, &in_space, reference, kind, &item, &name, &[0; 24]).map(|_| ())
            }
            other => panic!("{other}"),
        };
        assert_eq!(result, Err(class(&case["error"])), "{title}");
    }

    for case in f["record_refusals"].as_array().unwrap() {
        let result = open_record(
            &bytes(&case["record"]),
            &id(&case["space"]),
            content_key_of,
            kind_code(&case["kind"]),
            &bytes(&case["id"]),
        );
        assert_eq!(result, Err(class(&case["error"])), "{}", case["name"]);
    }
}
