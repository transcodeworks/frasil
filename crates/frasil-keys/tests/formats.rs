//! `keys.json`: `labels`, `parameters`, `rotation_sets`, `derivations`,
//! `bundles`, `bundle_wraps`, `space_wraps`, `removal_wraps` and `links` (keys.md, sections
//! 2.1 to 2.5, 2.9 and 3.1).

use frasil_base::time::Timer;
use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment, device_id};
use frasil_crypto::primitives::{ed25519_public, hkdf_extract};
use frasil_crypto::wrap::{SUITE_XWING, xwing_public};
use frasil_events::EventId;
use frasil_keys::bundle::{Bundle, Level, Slots, bundle_contents};
use frasil_keys::derive::{
    GrantKey, SecretKind, body_aad, body_commitment, body_key, merge, metadata_key, object_id_key,
    object_nonce_key, read_credential, state_secret, upload_key,
};
use frasil_keys::limits::*;
use frasil_keys::links::{GapRecord, Link, LinkKind, link_aad, link_info, link_key};
use frasil_keys::reference::read_key_reference;
use frasil_keys::wraps::{
    bundle_wrap_info, find_own_wrap, find_removal_wrap, open_bundle_wrap, open_removal_wrap,
    open_space_wrap, removal_plaintext, removal_wrap_info, seal_bundle_wrap_with,
    seal_removal_wrap_with, seal_space_wrap_with, space_wrap_info,
};
use frasil_keys::{KeyClass, KeyName, LABELS, RotationSet, SelfRef};
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

/// A delivery's key name as the vectors write it: empty for none.
fn name(value: &Json) -> Option<KeyName> {
    let bytes = bytes(value);
    (!bytes.is_empty()).then(|| KeyName::decode(&bytes, true).unwrap())
}

fn set(value: &Json) -> RotationSet {
    RotationSet::decode(&bytes(value)).unwrap()
}

fn kind(value: &Json) -> LinkKind {
    match value {
        Json::String(text) if text == "content" => LinkKind::Content,
        Json::String(text) if text == "grant" => LinkKind::Grant,
        Json::Number(code) => LinkKind::from_code(code.as_u64().unwrap() as u8).unwrap(),
        other => panic!("not a link kind: {other}"),
    }
}

// ---------------------------------------------------------------------------
// labels, parameters

#[test]
fn labels() {
    let labels: BTreeMap<String, String> = vectors::family(FILE, "labels");
    assert_eq!(labels.len(), LABELS.len());
    for (text, encoded) in &labels {
        assert_eq!(hex::encode(text.as_bytes()), *encoded);
        assert!(LABELS.contains(&text.as_bytes()), "{text}");
    }
}

#[test]
fn parameters() {
    let p: Json = vectors::family(FILE, "parameters");
    let expected = [
        ("max_rotations", MAX_ROTATIONS),
        ("collapse_above", COLLAPSE_ABOVE),
        ("max_deliveries_per_event", MAX_DELIVERIES_PER_EVENT),
        ("max_wraps_per_event", MAX_WRAPS_PER_EVENT),
        ("max_refs_per_event", MAX_REFS_PER_EVENT),
        ("max_name_bytes", MAX_NAME_BYTES),
        ("max_document_id_bytes", MAX_DOCUMENT_ID_BYTES),
        ("max_breaks_per_space", MAX_BREAKS_PER_SPACE),
        ("cascade_warning", CASCADE_WARNING),
        ("self_reference_bytes", SELF_REFERENCE_BYTES),
        ("bundle_bytes", BUNDLE_BYTES),
        ("grant_public_key_bytes", GRANT_PUBLIC_KEY_BYTES),
        ("wrap_bytes", WRAP_BYTES),
        (
            "link_bytes_between_single_rotations",
            LINK_BYTES_BETWEEN_SINGLE_ROTATIONS,
        ),
    ];
    for (key, value) in expected {
        assert_eq!(p[key], value, "{key}");
    }
    assert_eq!(p["suite"], SUITE_XWING);
    assert_eq!(
        p["rotation_rank_cap"].as_u64(),
        Timer::RotationRankCap.spec().default
    );
    assert_eq!(p.as_object().unwrap().len(), expected.len() + 2);
}

// ---------------------------------------------------------------------------
// rotation_sets

#[test]
fn rotation_sets() {
    let f: Json = vectors::family(FILE, "rotation_sets");
    for case in f["sets"].as_array().unwrap() {
        let ids = case["ids"].as_array().unwrap().iter().map(id);
        let state = RotationSet::new(ids).unwrap();
        let encoding = bytes(&case["encoding"]);
        assert_eq!(state.encode(), encoding, "{}", case["name"]);
        assert_eq!(RotationSet::decode(&encoding), Ok(state.clone()));
        assert_eq!(read_key_reference(&encoding), Ok(state));
    }
    let own = &f["self_reference"];
    let reference = SelfRef::new(
        DeviceId(array(&own["author"])),
        own["seq"].as_u64().unwrap(),
    );
    let encoding = bytes(&own["encoding"]);
    assert_eq!(reference.encode().to_vec(), encoding);
    assert_eq!(
        KeyName::decode(&encoding, true),
        Ok(KeyName::SelfRef(reference))
    );
    for case in f["collapse"].as_array().unwrap() {
        let size = case["size"].as_u64().unwrap() as usize;
        // `size` distinct IDs, ascending.
        let ids: Vec<EventId> = (0..size)
            .map(|i| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                EventId(bytes)
            })
            .collect();
        let mut encoding = vec![size as u8];
        for id in &ids {
            encoding.extend_from_slice(id.as_bytes());
        }
        let read = read_key_reference(&encoding);
        assert_eq!(read.is_ok(), case["unit_may_name_it"], "{size}");
        match read {
            Ok(state) => assert_eq!(state.collapse_due(), case["collapse_due"], "{size}"),
            Err(error) => {
                assert_eq!(error, KeyClass::TooManyRotations);
                assert_eq!(case["collapse_due"], true);
            }
        }
    }
    for case in f["refusals"].as_array().unwrap() {
        let encoding = bytes(&case["encoding"]);
        let result = if case["self_allowed"] == true {
            KeyName::decode(&encoding, true).map(|_| ())
        } else {
            RotationSet::decode(&encoding).map(|_| ())
        };
        assert_eq!(result, Err(class(&case["error"])), "{}", case["name"]);
    }
}

// ---------------------------------------------------------------------------
// derivations

/// The rotations' secrets by ID, from `derivations`.
fn rotation_secrets(f: &Json) -> BTreeMap<EventId, [[u8; 32]; 3]> {
    f["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                id(&r["id"]),
                [
                    array(&r["content"]),
                    array(&r["upload"]),
                    array(&r["grant"]),
                ],
            )
        })
        .collect()
}

#[test]
fn derivations() {
    let f: Json = vectors::family(FILE, "derivations");
    let space = id(&f["space"]);
    let secrets = rotation_secrets(&f);
    let kinds = [
        ("content", SecretKind::Content),
        ("upload", SecretKind::Upload),
        ("grant", SecretKind::Grant),
    ];
    let mut content_of_ab = None;
    for case in f["states"].as_array().unwrap() {
        let state = RotationSet::new(case["ids"].as_array().unwrap().iter().map(id)).unwrap();
        let ids: Vec<EventId> = case["ids"].as_array().unwrap().iter().map(id).collect();
        assert_eq!(
            state.ids(),
            &ids[..],
            "the vectors list the canonical order"
        );
        let mut derived = Vec::new();
        for (index, (key, kind)) in kinds.into_iter().enumerate() {
            let inputs: Vec<[u8; 32]> = ids.iter().map(|i| secrets[i][index]).collect();
            let expected = &case[key];
            let secret = state_secret(kind, &space, &state, &inputs).unwrap();
            assert_eq!(*secret, array::<32>(&expected["secret"]), "{key}");
            if state.len() > 1 {
                let m = merge(kind, &space, &state, &inputs).unwrap();
                assert_eq!(m.info, bytes(&expected["info"]));
                let t: Vec<[u8; 32]> = expected["t"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(array)
                    .collect();
                assert_eq!(*m.t, t);
                assert_eq!(*m.ikm, bytes(&expected["ikm"]));
            }
            derived.push(*secret);
        }
        let [k, w, g] = [derived[0], derived[1], derived[2]];
        if state.len() == 2 {
            content_of_ab = Some((state.clone(), ids.clone()));
        }

        let gk = &case["grant_key"];
        assert_eq!(bytes(&gk["info"]), frasil_crypto::labels::GRANT_KEY);
        let grant = GrantKey::derive(&g);
        assert_eq!(*grant.xwing_seed, array::<32>(&gk["xwing_seed"]));
        assert_eq!(grant.public.to_vec(), bytes(&gk["public"]));
        assert_eq!(grant.commitment(false), array::<32>(&gk["commitment"]));
        assert_eq!(
            grant.commitment(true),
            array::<32>(&gk["commitment_at_a_break"])
        );

        for (key, credential, label) in [
            (
                "read_credential",
                read_credential(&k),
                frasil_crypto::labels::READ_CREDENTIAL,
            ),
            (
                "upload_key",
                upload_key(&w),
                frasil_crypto::labels::UPLOAD_KEY,
            ),
        ] {
            assert_eq!(bytes(&case[key]["info"]), label);
            assert_eq!(*credential.seed, array::<32>(&case[key]["seed"]), "{key}");
            assert_eq!(
                credential.public,
                array::<32>(&case[key]["public"]),
                "{key}"
            );
        }
        for (key, derived, label) in [
            (
                "metadata_key",
                metadata_key(&k),
                frasil_crypto::labels::SPACE_METADATA_KEY,
            ),
            (
                "object_id_key",
                object_id_key(&k),
                frasil_crypto::labels::OBJECT_ID_KEY,
            ),
            (
                "object_nonce_key",
                object_nonce_key(&k),
                frasil_crypto::labels::OBJECT_NONCE_KEY,
            ),
        ] {
            assert_eq!(bytes(&case[key]["info"]), label);
            assert_eq!(*derived, array::<32>(&case[key]["key"]), "{key}");
        }

        let bk = &case["body_key"];
        let author = DeviceId(array::<32>(&bk["author"]));
        let seq = bk["seq"].as_u64().unwrap();
        assert_eq!(body_aad(space.as_bytes(), &author, seq), bytes(&bk["info"]));
        let key = body_key(&k, space.as_bytes(), &author, seq);
        assert_eq!(*key, array::<32>(&bk["key"]));
        assert_eq!(body_commitment(&key), array::<32>(&bk["commitment"]));
    }

    // {A, B} merged in another space differs.
    let (ab, ids) = content_of_ab.unwrap();
    let inputs: Vec<[u8; 32]> = ids.iter().map(|i| secrets[i][0]).collect();
    let other = state_secret(SecretKind::Content, &id(&f["other_space"]), &ab, &inputs).unwrap();
    assert_eq!(*other, array::<32>(&f["other_space_content_key_of_A_B"]));
}

// ---------------------------------------------------------------------------
// bundles

#[test]
fn bundles() {
    let f: Json = vectors::family(FILE, "bundles");
    for case in f["shapes"].as_array().unwrap() {
        let encoded = bytes(&case["bundle"]);
        let bundle = Bundle::read(&encoded).unwrap();
        assert_eq!(bundle.encode().to_vec(), encoded, "{}", case["name"]);
        let again = Bundle::new(
            bundle.content().copied(),
            bundle.upload().copied(),
            bundle.grant().copied(),
        )
        .unwrap();
        assert_eq!(again, bundle);
    }
    for case in f["refusals"].as_array().unwrap() {
        assert_eq!(
            Bundle::read(&bytes(&case["bundle"])),
            Err(class(&case["error"])),
            "{}",
            case["name"]
        );
    }
    for case in f["who_gets_what"].as_array().unwrap() {
        let level = match case["level"].as_str().unwrap() {
            "read" => Level::Read,
            "write" => Level::Write,
            "administer" => Level::Administer,
            other => panic!("{other}"),
        };
        let slots = bundle_contents(level, case["propagates"].as_bool().unwrap());
        let listed: Vec<&str> = case["bundle"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        let expected = Slots {
            content: listed.contains(&"content"),
            upload: listed.contains(&"upload"),
            grant: listed.contains(&"grant"),
        };
        assert_eq!(slots, expected, "{}", case["recipient"]);
    }
}

// ---------------------------------------------------------------------------
// bundle_wraps

struct Device {
    identity: [u8; 32],
    device_id: DeviceId,
    xwing_seed: [u8; 32],
    xwing: Vec<u8>,
}

fn devices(f: &Json) -> BTreeMap<String, Device> {
    f["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let identity_seed = array::<32>(&d["identity_seed"]);
            let xwing_seed = array::<32>(&d["hybrid_seed"]);
            let device = Device {
                identity: array(&d["identity"]),
                device_id: DeviceId(array(&d["device_id"])),
                xwing_seed,
                xwing: bytes(&d["hybrid"]),
            };
            assert_eq!(ed25519_public(&identity_seed), device.identity);
            assert_eq!(
                device_id(
                    &IdentityKey(device.identity),
                    &KeysCommitment(array(&d["kc"]))
                ),
                device.device_id
            );
            assert_eq!(xwing_public(&xwing_seed).to_vec(), device.xwing);
            (d["name"].as_str().unwrap().to_owned(), device)
        })
        .collect()
}

#[test]
fn bundle_wraps() {
    let f: Json = vectors::family(FILE, "bundle_wraps");
    let log = bytes(&f["log"]);
    let devices = devices(&f);
    for case in f["wraps"].as_array().unwrap() {
        let recipient = &devices[case["recipient"].as_str().unwrap()];
        let key_name = name(&case["key_name"]);
        let grant_name = name(&case["grant_name"]);
        let bundle = Bundle::read(&bytes(&case["bundle"])).unwrap();
        let info = bundle_wrap_info(
            &log,
            key_name.as_ref(),
            grant_name.as_ref(),
            &recipient.device_id,
        );
        assert_eq!(info, bytes(&case["info"]), "{}", case["name"]);
        let wrap = seal_bundle_wrap_with(
            &log,
            key_name.as_ref(),
            grant_name.as_ref(),
            &recipient.device_id,
            &recipient.xwing,
            &bundle,
            &array(&case["encapsulation_randomness"]),
        )
        .unwrap();
        assert_eq!(wrap, bytes(&case["wrap"]), "{}", case["name"]);
        assert_eq!(wrap[3..1123], bytes(&case["enc"])[..]);
        assert_eq!(wrap[1123..], bytes(&case["sealed"])[..]);
        let opened = open_bundle_wrap(
            &wrap,
            &log,
            key_name.as_ref(),
            grant_name.as_ref(),
            &recipient.device_id,
            &recipient.xwing_seed,
        );
        assert_eq!(opened, Ok(bundle), "{}", case["name"]);
    }

    let trial = &f["trial_decryption"];
    let delivery: Vec<Vec<u8>> = trial["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let opener = &devices[trial["opener"].as_str().unwrap()];
    let first = &f["wraps"][0];
    let found = find_own_wrap(
        &delivery,
        &log,
        name(&first["key_name"]).as_ref(),
        name(&first["grant_name"]).as_ref(),
        &opener.device_id,
        &opener.xwing_seed,
    );
    assert_eq!(
        found.map(|(index, _)| index as u64),
        trial["found_at"].as_u64()
    );

    for case in f["refusals"].as_array().unwrap() {
        let opener = &devices[case["opener"].as_str().unwrap()];
        let result = open_bundle_wrap(
            &bytes(&case["wrap"]),
            &log,
            name(&case["key_name"]).as_ref(),
            name(&case["grant_name"]).as_ref(),
            &opener.device_id,
            &opener.xwing_seed,
        );
        assert_eq!(result, Err(class(&case["error"])), "{}", case["name"]);
    }
}

// ---------------------------------------------------------------------------
// removal_wraps

#[test]
fn removal_wraps() {
    let f: Json = vectors::family(FILE, "removal_wraps");
    let log = bytes(&f["log"]);
    let devices = devices(&f);
    let own = name(&f["key_name"]).unwrap();
    let grant = name(&f["grant_name"]);
    let author = &devices[f["author"].as_str().unwrap()];
    let seq = f["seq"].as_u64().unwrap();
    assert_eq!(own, KeyName::SelfRef(SelfRef::new(author.device_id, seq)));
    let key = body_key(
        &array(&f["rotation_content_key"]),
        &log,
        &author.device_id,
        seq,
    );
    assert_eq!(*key, array::<32>(&f["body_key"]));
    let commitment: [u8; 32] = array(&f["commitment"]);
    assert_eq!(body_commitment(&key), commitment);

    let case = &f["removal_wrap"];
    let recipient = &devices[case["recipient"].as_str().unwrap()];
    let info = removal_wrap_info(&log, &own, grant.as_ref(), &recipient.device_id);
    assert_eq!(info, bytes(&case["info"]));
    assert_eq!(removal_plaintext(&key).to_vec(), bytes(&case["plaintext"]));
    let wrap = seal_removal_wrap_with(
        &log,
        &own,
        grant.as_ref(),
        &recipient.device_id,
        &recipient.xwing,
        &key,
        &array(&case["encapsulation_randomness"]),
    )
    .unwrap();
    assert_eq!(wrap, bytes(&case["wrap"]));
    assert_eq!(wrap[3..1123], bytes(&case["enc"])[..]);
    assert_eq!(wrap[1123..], bytes(&case["sealed"])[..]);
    let opened = open_removal_wrap(
        &wrap,
        &log,
        &own,
        grant.as_ref(),
        &recipient.device_id,
        &recipient.xwing_seed,
        &commitment,
    )
    .unwrap();
    assert_eq!(*opened, *key);

    let trial = &f["trial_decryption"];
    let delivery: Vec<Vec<u8>> = trial["delivery"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let removed = &devices[trial["removed"]["opener"].as_str().unwrap()];
    let found = find_removal_wrap(
        &delivery,
        &log,
        &own,
        grant.as_ref(),
        &removed.device_id,
        &removed.xwing_seed,
        &commitment,
    );
    assert_eq!(
        found.map(|(index, _)| index as u64),
        trial["removed"]["found_at"].as_u64()
    );
    assert!(
        find_own_wrap(
            &delivery,
            &log,
            Some(&own),
            grant.as_ref(),
            &removed.device_id,
            &removed.xwing_seed
        )
        .is_none()
    );
    let remaining = &devices[trial["remaining"]["opener"].as_str().unwrap()];
    let found = find_own_wrap(
        &delivery,
        &log,
        Some(&own),
        grant.as_ref(),
        &remaining.device_id,
        &remaining.xwing_seed,
    );
    assert_eq!(
        found.map(|(index, _)| index as u64),
        trial["remaining"]["found_at"].as_u64()
    );

    for case in f["refusals"].as_array().unwrap() {
        let opener = &devices[case["opener"].as_str().unwrap()];
        let data = bytes(&case["wrap"]);
        let error = match case["as"].as_str().unwrap() {
            "bundle wrap" => open_bundle_wrap(
                &data,
                &log,
                Some(&own),
                grant.as_ref(),
                &opener.device_id,
                &opener.xwing_seed,
            )
            .err(),
            "removal wrap" => open_removal_wrap(
                &data,
                &log,
                &own,
                grant.as_ref(),
                &opener.device_id,
                &opener.xwing_seed,
                &commitment,
            )
            .err(),
            other => panic!("not a wrap: {other}"),
        };
        assert_eq!(error, Some(class(&case["error"])), "{}", case["name"]);
    }
}

// ---------------------------------------------------------------------------
// space_wraps

#[test]
fn space_wraps() {
    let f: Json = vectors::family(FILE, "space_wraps");
    let log = bytes(&f["log"]);
    let state = name(&f["key_name"]);
    let grantee = id(&f["grantee"]);
    let rotation = id(&f["grantee_rotation"]);
    let grant = GrantKey::derive(&array(&f["grantee_grant_seed"]));
    let gk = &f["grantee_grant_key"];
    assert_eq!(bytes(&gk["info"]), frasil_crypto::labels::GRANT_KEY);
    assert_eq!(*grant.xwing_seed, array::<32>(&gk["xwing_seed"]));
    assert_eq!(grant.public.to_vec(), bytes(&gk["public"]));
    for case in f["wraps"].as_array().unwrap() {
        let bundle = Bundle::read(&bytes(&case["bundle"])).unwrap();
        let info = space_wrap_info(&log, state.as_ref(), state.as_ref(), &grantee, &rotation);
        assert_eq!(info, bytes(&case["info"]), "{}", case["name"]);
        let wrap = seal_space_wrap_with(
            &log,
            state.as_ref(),
            state.as_ref(),
            &grantee,
            &rotation,
            &grant.public[..],
            &bundle,
            &array(&case["encapsulation_randomness"]),
        )
        .unwrap();
        assert_eq!(wrap, bytes(&case["wrap"]), "{}", case["name"]);
        assert_eq!(wrap[3..1123], bytes(&case["enc"])[..]);
        assert_eq!(wrap[1123..], bytes(&case["sealed"])[..]);
        let opened = open_space_wrap(
            &wrap,
            &log,
            state.as_ref(),
            state.as_ref(),
            &grantee,
            &rotation,
            &grant.xwing_seed,
        );
        assert_eq!(opened, Ok(bundle));
    }
    for case in f["refusals"].as_array().unwrap() {
        let result = open_space_wrap(
            &bytes(&case["wrap"]),
            &log,
            state.as_ref(),
            state.as_ref(),
            &id(&case["grantee"]),
            &id(&case["grantee_rotation"]),
            &array(&case["grant_xwing_seed"]),
        );
        assert_eq!(result, Err(class(&case["error"])), "{}", case["name"]);
    }
}

// ---------------------------------------------------------------------------
// links

#[test]
fn links() {
    let f: Json = vectors::family(FILE, "links");
    let log = bytes(&f["log"]);
    for case in f["links"].as_array().unwrap() {
        let kind = kind(&case["kind"]);
        let under = name(&case["under"]).unwrap();
        let reaches = set(&case["reaches"]);
        let under_secret = array::<32>(&case["under_secret"]);
        let reached = array::<32>(&case["reached_secret"]);
        assert_eq!(
            link_info(kind, &log, &under, &reaches),
            bytes(&case["info"])
        );
        assert_eq!(
            *hkdf_extract(&[0; 32], &under_secret),
            array::<32>(&case["prk"])
        );
        assert_eq!(
            *link_key(kind, &log, &under, &reaches, &under_secret),
            array::<32>(&case["link_key"])
        );
        assert_eq!(link_aad(kind, &log, &under, &reaches), bytes(&case["aad"]));
        let link = Link::seal_with(
            kind,
            &log,
            under.clone(),
            reaches.clone(),
            &under_secret,
            &reached,
            &array(&case["nonce"]),
        )
        .unwrap();
        let encoded = bytes(&case["link"]);
        assert_eq!(link.encode(), encoded, "{}", case["name"]);
        assert_eq!(Link::read(&encoded), Ok(link));
        let opened = Link::open(&encoded, kind, &log, &under, &reaches, &under_secret).unwrap();
        assert_eq!(*opened, reached);
    }
    for case in f["refusals"].as_array().unwrap() {
        let link = bytes(&case["link"]);
        let under = name(&case["under"]).unwrap();
        // An opener looks only for a state it can name; a link that reaches
        // a self reference is refused before what it looks for is compared.
        let result = match RotationSet::decode(&bytes(&case["reaches"])) {
            Ok(reaches) => Link::open(
                &link,
                kind(&case["kind"]),
                &log,
                &under,
                &reaches,
                &array(&case["under_secret"]),
            )
            .map(|_| ()),
            Err(_) => Link::read(&link).map(|_| ()),
        };
        assert_eq!(result, Err(class(&case["error"])), "{}", case["name"]);
    }
    for case in f["gaps"].as_array().unwrap() {
        let record = bytes(&case["record"]);
        let gap = GapRecord::read(&record).unwrap();
        assert_eq!(gap.encode(), record, "{}", case["name"]);
    }
    for case in f["gap_refusals"].as_array().unwrap() {
        assert_eq!(
            GapRecord::read(&bytes(&case["record"])),
            Err(class(&case["error"])),
            "{}",
            case["name"]
        );
    }
}
