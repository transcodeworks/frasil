//! ext-restricted-spaces.json's key families, with feature
//! `ext-restricted-spaces`:
//!
//! - `restricted_keys` (sections 2.2 and 2.3): F's own secrets merged, P's
//!   content key, `k_F` with its info and PRK, F's read credential and
//!   upload key, and the sealed key reference;
//! - `reference_refusals` (section 3.2): a parent state that does not open,
//!   and two references whose parts do not read;
//! - `restricted_space_event`: a rotation of F sealed under its own `f_R`;
//! - `restricted_names`: a document's name sealed in F, and a record of F
//!   whose reference is a plain set.

#![cfg(feature = "ext-restricted-spaces")]

use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::{
    SecretKind, body_commitment, body_key, metadata_key, read_credential, state_secret, upload_key,
};
use frasil_keys::ext_restricted_spaces::{
    RestrictedReference, check_restricted_states, encode_restricted_record, open_restricted_record,
    parent_reference_key, read_restricted_reference, restricted_key, restricted_name_aad,
    seal_restricted_name_with,
};
use frasil_keys::links::{Link, LinkKind};
use frasil_keys::reference::{Lookup, RotationLog};
use frasil_keys::sealed_names::{KIND_DOCUMENT, padded_len};
use frasil_keys::{KeyClass, KeyName, RotationSet};
use frasil_testkit::hex;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const FILE: &str = "ext-restricted-spaces.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().unwrap()).unwrap()
}

fn id(value: &Json) -> EventId {
    EventId(array(value))
}

/// A rotation of F or P, by name: its ID and its two secrets.
struct Rotation {
    id: EventId,
    content: [u8; 32],
    upload: [u8; 32],
}

/// A log in which every ID given is a rotation, concurrent with the others.
struct Rotations(Vec<EventId>);

impl RotationLog for Rotations {
    fn lookup(&self, id: &EventId) -> Lookup {
        if self.0.contains(id) {
            Lookup::Rotation
        } else {
            Lookup::Missing
        }
    }

    fn precedes(&self, _earlier: &EventId, _later: &EventId) -> bool {
        false
    }
}

/// The state of these rotations, and its merged content and upload
/// secrets.
fn state(
    space: &EventId,
    names: &Json,
    rotations: &BTreeMap<String, Rotation>,
) -> (RotationSet, [u8; 32], [u8; 32]) {
    let mut chosen: Vec<&Rotation> = names
        .as_array()
        .unwrap()
        .iter()
        .map(|n| &rotations[n.as_str().unwrap()])
        .collect();
    chosen.sort_by_key(|r| r.id);
    let set = RotationSet::new(chosen.iter().map(|r| r.id)).unwrap();
    let merge = |kind, of: fn(&Rotation) -> [u8; 32]| {
        let inputs: Vec<[u8; 32]> = chosen.iter().map(|r| of(r)).collect();
        *state_secret(kind, space, &set, &inputs).unwrap()
    };
    let content = merge(SecretKind::Content, |r| r.content);
    let upload = merge(SecretKind::Upload, |r| r.upload);
    (set, content, upload)
}

fn rotations(f: &Json) -> BTreeMap<String, Rotation> {
    f["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_owned(),
                Rotation {
                    id: id(&r["id"]),
                    content: array(&r["content"]),
                    upload: array(&r["upload"]),
                },
            )
        })
        .collect()
}

#[test]
fn restricted_keys() {
    let f = family("restricted_keys");
    let space = id(&f["space"]);
    let parent = id(&f["parent"]);
    let rotations = rotations(&f);
    let cases = f["keys"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let (own, own_secret, own_upload) = state(&space, &case["own_state"], &rotations);
        let (parent_state, parent_key, _) = state(&parent, &case["parent_state"], &rotations);
        assert_eq!(own_secret, array(&case["own_secret"]));
        assert_eq!(own_upload, array(&case["own_upload_seed"]));
        assert_eq!(parent_key, array(&case["parent_key"]));
        let key = restricted_key(&space, &parent, &own_secret, &parent_key);
        assert_eq!(key.info, bytes(&case["info"]));
        assert_eq!(*key.prk, array(&case["prk"]));
        assert_eq!(*key.key, array(&case["key"]));
        // F's read credential and upload key derive from its own secrets.
        assert_eq!(
            read_credential(&own_secret).public,
            array(&case["read_credential"])
        );
        assert_eq!(upload_key(&own_upload).public, array(&case["upload_key"]));
        assert_eq!(
            *parent_reference_key(&own_secret),
            array(&case["parent_reference_key"])
        );
        // The reference, byte for byte, and read back in every step.
        let reference = RestrictedReference::seal_with(
            &space,
            &own,
            &parent_state,
            &own_secret,
            &array(&case["reference_nonce"]),
        );
        let encoded = bytes(&case["key_reference"]);
        assert_eq!(reference.encode(), encoded);
        assert_eq!(
            encoded.len(),
            42 + 32 * (own.len() + parent_state.len()),
            "section 2.3's size"
        );
        let read = read_restricted_reference(
            &encoded,
            &space,
            |s| (*s == own).then(|| Zeroizing::new(own_secret)),
            &Rotations(own.ids().to_vec()),
            &Rotations(parent_state.ids().to_vec()),
        );
        assert_eq!(read, Ok((own.clone(), parent_state.clone())));
        // Step 3: a reader without f(S_F); step 6: a parent rotation not
        // yet held.
        assert_eq!(
            read_restricted_reference(
                &encoded,
                &space,
                |_| None,
                &Rotations(Vec::new()),
                &Rotations(Vec::new())
            )
            .map_err(Class::name),
            Err("Sealed")
        );
        assert_eq!(
            check_restricted_states(
                &own,
                &parent_state,
                &Rotations(own.ids().to_vec()),
                &Rotations(Vec::new())
            )
            .map_err(Class::name),
            Err("Pending")
        );
    }
}

#[test]
fn reference_refusals() {
    let space = id(&family("restricted_keys")["space"]);
    let cases = family("reference_refusals");
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let reference = bytes(&case["reference"]);
        let got = RestrictedReference::read(&reference).and_then(|read| {
            let secret: [u8; 32] = array(&case["own_secret"]);
            read.open(&space, &secret)
        });
        assert_eq!(
            got.map_err(Class::name),
            Err(case["error"].as_str().unwrap()),
            "{name}"
        );
    }
}

#[test]
fn restricted_space_event() {
    let keys = family("restricted_keys");
    let space = id(&keys["space"]);
    let rotations = rotations(&keys);
    let f = family("restricted_space_event");
    let author = frasil_crypto::device::DeviceId(array(&f["author"]));
    let seq = f["seq"].as_u64().unwrap();
    let secret: [u8; 32] = array(&f["secret"]);
    let f2 = &rotations["F2"];
    assert_eq!(secret, f2.content, "F's rotation seals under its own f_R");
    let key = body_key(&secret, space.as_bytes(), &author, seq);
    assert_eq!(*key, array(&f["body_key"]));
    assert_eq!(body_commitment(&key), array(&f["commitment"]));
    // The payload: a rotation of F's own secrets, linked back to F1, and no
    // grant rotation.
    let visible = VisiblePart::read(&bytes(&f["payload"]), &author, seq).unwrap();
    let rotation = visible.rotation().unwrap();
    assert_eq!(rotation.read, read_credential(&f2.content).public);
    assert_eq!(rotation.upload, upload_key(&f2.upload).public);
    let inner = visible.open(&key, space.as_bytes(), &author, seq).unwrap();
    assert!(!inner.grant_rotation());
    assert_eq!(inner.links.len(), 1);
    let link = &inner.links[0];
    let f1 = &rotations["F1"];
    assert_eq!(link.kind, LinkKind::Content);
    assert_eq!(link.reaches, RotationSet::single(f1.id));
    let opened = Link::open(
        &link.encode(),
        LinkKind::Content,
        space.as_bytes(),
        &link.under,
        &link.reaches,
        &secret,
    )
    .unwrap();
    assert_eq!(*opened, f1.content);
    assert!(matches!(link.under, KeyName::SelfRef(_)));
}

#[test]
fn restricted_names() {
    let f = family("restricted_names");
    let space = id(&f["space"]);
    let parent = id(&f["parent"]);
    let state = &f["state"];
    let own = RotationSet::new(state["rotations"].as_array().unwrap().iter().map(id)).unwrap();
    let own_secret: [u8; 32] = array(&state["own_secret"]);
    let parent_key: [u8; 32] = array(&state["parent_content_key"]);
    let k_f = restricted_key(&space, &parent, &own_secret, &parent_key);
    assert_eq!(*k_f.key, array(&state["content_key"]));
    let mk = metadata_key(&k_f.key);
    assert_eq!(*mk, array(&state["metadata_key"]));
    // The reference names keys.json's state A+B of the parent.
    let reference = RestrictedReference::read(&bytes(&state["key_reference"])).unwrap();
    assert_eq!(reference.own, own);
    let parent_state = reference.open(&space, &own_secret).unwrap();
    let a_b = frasil_testkit::vectors::family::<Json>("keys.json", "sealed_names")["states"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["state"] == state["parent_state"])
        .map(|s| RotationSet::new(s["rotations"].as_array().unwrap().iter().map(id)).unwrap())
        .unwrap();
    assert_eq!(parent_state, a_b);

    let sealed = &f["sealed"];
    assert_eq!(sealed["kind"], "document");
    let doc = bytes(&sealed["id"]);
    let name = String::from_utf8(bytes(&sealed["name_bytes"])).unwrap();
    assert_eq!(bytes(&sealed["padded"]).len(), padded_len(name.len()));
    assert_eq!(
        restricted_name_aad(&space, &reference, KIND_DOCUMENT, &doc),
        bytes(&sealed["aad"])
    );
    let out = seal_restricted_name_with(
        &mk,
        &space,
        &reference,
        KIND_DOCUMENT,
        &doc,
        &name,
        &array(&sealed["nonce"]),
    )
    .unwrap();
    assert_eq!(out, bytes(&sealed["sealed"]));
    let record = encode_restricted_record(&space, &reference, &out);
    assert_eq!(record, bytes(&sealed["record"]));
    // Step 5 needs f(S_F) and k_P(S_P).
    let key_for = |r: &RestrictedReference| {
        let opened = r.open(&space, &own_secret).ok()?;
        (r.own == own && opened == a_b).then(|| k_f.key.clone())
    };
    assert_eq!(
        open_restricted_record(&record, &space, key_for, KIND_DOCUMENT, &doc),
        Ok(name)
    );
    assert_eq!(
        open_restricted_record(&record, &space, |_| None, KIND_DOCUMENT, &doc),
        Err(KeyClass::MissingState)
    );
    for case in f["refusals"].as_array().unwrap() {
        let got = open_restricted_record(
            &bytes(&case["record"]),
            &space,
            key_for,
            KIND_DOCUMENT,
            &doc,
        );
        assert_eq!(
            got.map_err(Class::name),
            Err(case["error"].as_str().unwrap()),
            "{}",
            case["name"]
        );
    }
}
