//! `peers.json`: `parameters`, `proofs`, `merge_statement`, `skeleton` and
//! `erase_bodies` (peers.md, sections 2.1 to 2.6, 3.2, 3.5, 3.7, 3.10 to
//! 3.13 and 3.16).

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::schemes::Scheme;
use frasil_events::{EventId, ForkPoints};
use frasil_keys::RotationSet;
use frasil_keys::derive::{read_credential, upload_key};
use frasil_peers::body::{
    ChangeEffect, EntryName, GrantMap, Restored, SlotId, SlotRef, StorageBody, StorageType,
};
use frasil_peers::decisions::is_released;
use frasil_peers::derive::{
    SlotKeys, binding_key, enrol_statement, grant_map_with, open_token, root_statement,
    seal_binding_with, token_info, twin_commitment, twin_secret,
};
use frasil_peers::entries::{Entries, Rights, Source, Storer, may_store};
use frasil_peers::limits::*;
use frasil_peers::merge::MergeStatement;
use frasil_peers::skeleton::Skeleton;
use frasil_peers::twins::TwinChecks;
use frasil_peers::{Code, PeersClass};
use serde_json::Value as Json;
use std::collections::BTreeMap;

const PREFIX: &str = "storage";

#[test]
fn parameters() {
    let p = family("parameters");
    assert_eq!(
        p["max_file_versions"]["default"].as_u64(),
        Some(MAX_FILE_VERSIONS)
    );
    assert_eq!(
        p["max_file_versions"]["range"],
        serde_json::json!([MAX_FILE_VERSIONS_RANGE.0, MAX_FILE_VERSIONS_RANGE.1])
    );
    assert_eq!(p["max_storage_event"], MAX_STORAGE_EVENT);
    assert_eq!(p["max_grants"], MAX_GRANTS);
    assert!(p.get("max_named").is_none());
    assert_eq!(p["max_live_named"], MAX_LIVE_NAMED);
    assert_eq!(p["max_keep"], MAX_KEEP);
    assert_eq!(p["max_recovery_entries"], MAX_RECOVERY_ENTRIES);
    assert_eq!(
        p["merge_rotations"],
        serde_json::json!([MIN_MERGE_ROTATIONS, MAX_MERGE_ROTATIONS])
    );
    assert_eq!(p["max_skeleton_place"], MAX_SKELETON_PLACE);
    assert_eq!(p["max_planted"], MAX_PLANTED);
    assert_eq!(p["credential_cap"], CREDENTIAL_CAP);
    assert_eq!(
        p["credential_cap_range"],
        serde_json::json!([MIN_CREDENTIAL_CAP, MAX_CREDENTIAL_CAP])
    );
    assert_eq!(p["merge_per_state"], MERGE_PER_STATE);
    assert_eq!(p["pending_cap"], PENDING_CAP);
    assert_eq!(p["sealed_token_bytes"], SEALED_TOKEN_BYTES);
    assert_eq!(p["binding_bytes"], BINDING_BYTES);
    let types: BTreeMap<String, Json> = StorageType::ALL
        .into_iter()
        .map(|t| (t.code().to_string(), Json::from(t.name())))
        .collect();
    assert_eq!(p["types"], serde_json::to_value(types).unwrap());
    let codes: BTreeMap<&str, u16> = Code::ALL
        .into_iter()
        .map(|c| (c.name(), c.status()))
        .collect();
    assert_eq!(p["codes"], serde_json::to_value(codes).unwrap());
    assert_eq!(p["max_cut_slots"], MAX_CUT_SLOTS);
    assert_eq!(p["max_standing"], MAX_STANDING);
    assert_eq!(p["reserved_cut_key"], RESERVED_CUT_KEY);

    // The largest body of each type the limits allow, with a scheme-2
    // signature and the reference's generous envelope (64 bytes of `ed` and
    // `kc`, three IDs and 256 parents), under the limit.
    let envelope = SIGNATURE_BYTES + 64 + 32 * 3 + 256 * 35;
    let slot = SlotId::new([0; 32], 63, EventId([0; 32]));
    let wide = RotationSet::new((1..=64u8).map(|i| EventId([i; 32]))).unwrap();
    let be = |i: u64, n: usize| {
        let mut out = vec![0u8; n];
        out[n - 8..].copy_from_slice(&i.to_be_bytes());
        out
    };
    let bodies: Vec<(&str, StorageBody)> = vec![
        (
            "root",
            StorageBody::Root {
                twin: [0; 32],
                mldsa: vec![0; MLDSA_BYTES],
                duel_policy: 0,
                founder_mldsa: vec![0; MLDSA_BYTES],
                founder_signature: vec![0; SIGNATURE_BYTES],
                founder_xwing: vec![0; frasil_crypto::sizes::XWING_PUBLIC],
            },
        ),
        (
            "change, 64 grants",
            StorageBody::Change {
                twin: [0; 32],
                salt: [0; 32],
                effect: ChangeEffect::Grants(vec![
                    GrantMap {
                        slot_ed: [0; 32],
                        slot_mldsa_hash: [0; 32],
                        token: vec![0; SEALED_TOKEN_BYTES],
                        rank: MAX_RANK,
                    };
                    64
                ]),
            },
        ),
        (
            "enrol",
            StorageBody::Enrol {
                slot,
                mldsa: vec![0; MLDSA_BYTES],
                slot_mldsa: vec![0; MLDSA_BYTES],
                authorization: vec![0; SIGNATURE_BYTES],
                binding: vec![0; BINDING_BYTES],
            },
        ),
        ("disown", StorageBody::Disown { slot }),
        ("ack", StorageBody::Ack),
        ("erase", StorageBody::Erase),
        (
            "credentials, 64 states of 64 rotations and 64 fetch keys",
            StorageBody::Credentials {
                live: Some(
                    (0..64)
                        .map(|i| EntryName {
                            state: wide.clone(),
                            read: be(i, 32).try_into().unwrap(),
                        })
                        .collect(),
                ),
                recovery: Some((64..128).map(|i| be(i, 32).try_into().unwrap()).collect()),
            },
        ),
        ("release", StorageBody::Release { stream: [0; 16] }),
        ("restore", StorageBody::Restore(Restored::Snapshot([0; 32]))),
    ];
    let largest = p["largest_events"].as_object().unwrap();
    assert_eq!(largest.len(), bodies.len());
    for (name, body) in bodies {
        let size = body.encode().len() + envelope;
        assert_eq!(largest[name], size, "{name}");
        assert!(size <= MAX_STORAGE_EVENT, "{name}");
    }
}

fn rights_of(value: &Json) -> Rights {
    let mut rights = Rights::default();
    for name in value.as_array().unwrap() {
        match text(name) {
            "fetch" => rights.fetch = true,
            "live" => rights.live = true,
            "catch-up" => rights.catch_up = true,
            "store" => rights.store = true,
            "release" => rights.release = true,
            "erase" => rights.erase = true,
            other => panic!("right {other}"),
        }
    }
    assert_eq!(Json::from(rights.names()), *value);
    rights
}

#[test]
fn proofs() {
    let history = History::of(&family("skeleton")["events"]);
    let log = &history.log;
    let space = log.id();
    let skeleton = Skeleton::new(log, None);
    let mut entries = Entries::default();
    let none = ForkPoints::default();
    let retired = history.id("P creates the space");
    for rotation in [retired, history.id("W rotates")] {
        assert!(
            entries
                .add_rotation(log, rotation, Source::Rotation, &none)
                .unwrap()
        );
    }
    let genesis_entry = entries.entries()[0].name();
    assert!(entries.retire(&genesis_entry));
    let p = family("proofs");
    check_presents(&mut entries, space, &p["cases"], |public| {
        skeleton
            .pseudonym_keys(&frasil_crypto::device::DeviceId(*public))
            .map(|keys| keys.ed)
    });

    let p0 = pseudonym_id(PREFIX, "P0");
    for case in p["stores"].as_array().unwrap() {
        let name = text(&case["name"]);
        let event = log.event(history.id(text(&case["event"]))).unwrap();
        let rights = rights_of(&case["rights"]);
        let storer = Storer {
            rights,
            creating: name.contains("a create"),
            importing: false,
            pseudonym: rights.erase.then_some(p0),
        };
        let result = may_store(event, &storer);
        assert_eq!(outcome(result), text(&case["verdict"]), "{name}");
        let code = result.err().and_then(PeersClass::code).map(Code::name);
        assert_eq!(
            code,
            case.get("code").and_then(Json::as_str),
            "{name}: code"
        );
    }
}

#[test]
fn merge_statement() {
    let m = family("merge_statement");
    let space = MergeSpace::new();
    let k: [u8; 32] = array(&m["content_key"]);
    let w: [u8; 32] = array(&m["upload_seed"]);
    assert_eq!(read_credential(&k).public, array::<32>(&m["read"]));
    assert_eq!(upload_key(&w).public, array::<32>(&m["upload"]));
    let accepted = MergeStatement::read(&hex(&m["cases"][0]["statement"])).unwrap();
    assert_eq!(accepted.message(), hex(&m["message"]));
    assert_eq!(accepted.encode(), hex(&m["cases"][0]["statement"]));
    let names: Vec<&str> = accepted
        .state
        .ids()
        .iter()
        .map(|&id| space.name(id))
        .collect();
    assert_eq!(Json::from(names), m["state"]);
    for case in m["cases"].as_array().unwrap() {
        let name = text(&case["name"]);
        let mut entries = space.entries(CREDENTIAL_CAP);
        let result = entries.merge(&space, &space.genesis, &hex(&case["statement"]));
        assert_eq!(outcome(result), text(&case["verdict"]), "{name}");
        assert_eq!(
            entries.entries().len(),
            4 + usize::from(result.is_ok()),
            "{name}"
        );
    }
}

#[test]
fn skeleton() {
    let s = family("skeleton");
    let history = History::of(&s["events"]);
    let log = &history.log;
    let space = log.id();
    let skeleton = Skeleton::new(log, None);
    check_summary("skeleton", &skeleton, &history, &s["peer"]);

    // Every storage body reads and is its one encoding.
    for id in log.canonical() {
        let event = log.event(id).unwrap();
        if event.kind() == frasil_events::kind::STORAGE {
            let body = StorageBody::read(event.unverified_body()).unwrap();
            assert_eq!(
                body.encode(),
                event.unverified_body(),
                "{}",
                history.name(id)
            );
        }
    }

    // Each roster event names its twin in visible key 15.
    for (r, twin) in s["names"].as_object().unwrap() {
        assert_eq!(
            skeleton.named_by(history.id(text(twin))),
            Some(history.id(r)),
            "{r}"
        );
    }

    // The twins' derivations.
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        ("P grants A administer", grants(PREFIX, &["A"])),
        ("P removes A", lowers(PREFIX, &["A"])),
        ("P grants B administer", grants(PREFIX, &["B"])),
    ];
    let facts = Facts::new(PREFIX, &history, &["P", "A", "B", "W"], &roster);
    for (r, twin) in s["twins"].as_object().unwrap() {
        let id = history.id(r);
        let event = log.event(id).unwrap();
        let body_key: [u8; 32] = array(&twin["body_key"]);
        assert_eq!(facts.body_keys[&id], body_key, "{r}: body key");
        let secret = twin_secret(&body_key);
        assert_eq!(*secret, array::<32>(&twin["twin_secret"]), "{r}");
        let salt = hex(&twin["salt"]);
        if id == log.id() {
            assert!(salt.is_empty(), "the root carries no salt");
        } else {
            let Some(StorageBody::Change { salt: carried, .. }) =
                frasil_peers::skeleton::named_twin(event).and_then(|t| skeleton.body_of(t))
            else {
                panic!("{r}: its twin")
            };
            assert_eq!(salt, carried.to_vec(), "{r}: the twin's salt");
        }
        let c = twin_commitment(event.author(), event.seq(), &secret, &salt);
        assert_eq!(c, array::<32>(&twin["c"]), "{r}");
        assert_eq!(
            *binding_key(&secret),
            array::<32>(&twin["binding_key"]),
            "{r}"
        );
    }

    // The replica's checks: each twin and the root pass; each pseudonym is
    // bound to its device.
    let checks = TwinChecks::new(&skeleton, &facts);
    for (r, twin) in s["twins"].as_object().unwrap() {
        let verdict = match checks.check(history.id(r)) {
            Ok(()) => "valid".to_string(),
            Err(failure) => failure.class().name().to_string(),
        };
        assert_eq!(verdict, text(&twin["replica"]), "{r}");
    }
    assert_eq!(
        bindings_json(&checks, PREFIX, &["P", "A", "B", "W", "P0", "A1"]),
        s["bindings"]
    );

    // The slot token: the grantee opens it, and its keys are the grant
    // map's; sealed again, it is the same bytes.
    let t = &s["token"];
    let twin_a = history.id(text(&t["twin"]));
    let c_a: [u8; 32] = array(&s["twins"]["P grants A administer"]["c"]);
    let slot_a = SlotRef::new(c_a, 0);
    let grant = skeleton.body_of(twin_a).unwrap().grants()[0].clone();
    assert!(!skeleton.repeats(twin_a));
    assert_eq!(grant.token, hex(&t["sealed_token"]));
    let a = device(PREFIX, "A");
    assert_eq!(token_info(&space, slot_a, &a), hex(&t["info"]));
    let xwing_a =
        *frasil_crypto::fixtures::fixture_xwing_seed(&example(&format!("{PREFIX}/A/ed25519")));
    let token = open_token(&grant, &space, slot_a, &a, &xwing_a).unwrap();
    assert_eq!(*token, array::<32>(&t["token"]));
    let keys = SlotKeys::from_token(&token);
    assert_eq!(*keys.ed_seed, array::<32>(&t["slot_ed_seed"]));
    assert_eq!(*keys.mldsa_seed, array::<32>(&t["slot_mldsa_seed"]));
    assert_eq!(*keys.ed_public(), array::<32>(&t["slot_ed"]));
    assert_eq!(keys.mldsa_hash(), array::<32>(&t["slot_mldsa_hash"]));
    let eseed: [u8; 64] = [
        example("P grants A administer/eseed/0/a"),
        example("P grants A administer/eseed/0/b"),
    ]
    .concat()
    .try_into()
    .unwrap();
    let xwing_public = frasil_crypto::wrap::xwing_public(&xwing_a);
    // P grants A administer at the top rank.
    assert_eq!(grant.rank, MAX_RANK);
    assert_eq!(
        grant_map_with(&space, slot_a, &a, &xwing_public, &token, &eseed, MAX_RANK).unwrap(),
        grant
    );
    // Another grantee's token, or a damaged one, is BadToken.
    let b = device(PREFIX, "B");
    assert_eq!(
        outcome(open_token(&grant, &space, slot_a, &b, &xwing_a)),
        "BadToken"
    );
    let damaged = GrantMap {
        token: grant.token[..SEALED_TOKEN_BYTES - 1].to_vec(),
        ..grant.clone()
    };
    assert_eq!(
        outcome(open_token(&damaged, &space, slot_a, &a, &xwing_a)),
        "BadToken"
    );

    // The enrolment's authorization and binding, signed and sealed again.
    let enrol = history.id("A1: enrols");
    let Some(StorageBody::Enrol {
        slot,
        mldsa,
        authorization,
        binding,
        ..
    }) = skeleton.body_of(enrol)
    else {
        panic!("an enrolment")
    };
    assert_eq!(*slot, SlotId::new(c_a, 0, twin_a));
    let a1 = pseudonym(PREFIX, "A1");
    assert_eq!(mldsa.as_slice(), a1.mldsa_public());
    let statement = enrol_statement(&space, slot_a, a1.device_id());
    assert_eq!(&keys.signer.sign(Scheme::Hybrid, &statement), authorization);
    let secret = twin_secret(&array(&s["twins"]["P grants A administer"]["body_key"]));
    let nonce: [u8; 24] = example("A1: enrols/binding-nonce")[..24]
        .try_into()
        .unwrap();
    let sealed = seal_binding_with(
        &secret,
        &space,
        slot_a,
        a1.device_id(),
        &signer(PREFIX, "A"),
        &nonce,
    );
    assert_eq!(&sealed, binding);

    // The root's founder signature, signed again.
    let root = skeleton.root().unwrap();
    let Some(StorageBody::Root {
        founder_signature, ..
    }) = skeleton.body_of(root)
    else {
        panic!("a root")
    };
    let p0 = pseudonym(PREFIX, "P0");
    let statement = root_statement(&space, p0.device_id());
    assert_eq!(
        &signer(PREFIX, "P").sign(Scheme::Hybrid, &statement),
        founder_signature
    );
    assert_eq!(
        ed25519_public(&example("storage/P0/ed25519")),
        p0.identity_key().0
    );

    // Whether the notes stream is released before and after the restore.
    let notes: [u8; 16] = example("storage/stream/notes")[..16].try_into().unwrap();
    let restore = history.id("W restores the notes stream");
    let requests = skeleton.writer_requests();
    let before = requests.iter().filter(|(id, _)| *id != restore).copied();
    assert_eq!(
        is_released(log, before, &notes),
        s["released_before_restore"]["notes"]
    );
    assert_eq!(
        is_released(log, requests.iter().copied(), &notes),
        s["released_after_restore"]["notes"]
    );
}

#[test]
fn bodies_refuse_in_order() {
    let ack = StorageBody::Ack.encode();
    assert_eq!(outcome(StorageBody::read(&ack)), "accepted");
    // Version 2 is unsupported; an unknown type, an extra key, or a key 0
    // is malformed.
    let mut v2 = ack.clone();
    v2[2] = 0x02;
    assert_eq!(outcome(StorageBody::read(&v2)), "UnsupportedVersion");
    let mut unknown = ack.clone();
    unknown[4] = 0x08;
    assert_eq!(outcome(StorageBody::read(&unknown)), "Malformed");
    // Type 7 is a cut, whose keys an acknowledgement's body lacks.
    unknown[4] = 0x07;
    assert_eq!(outcome(StorageBody::read(&unknown)), "Malformed");
    let extra = [0xa3, 0x00, 0x00, 0x01, 0x01, 0x02, 0x04];
    assert_eq!(outcome(StorageBody::read(&extra)), "Malformed");
    // A release of the all-zero stream is malformed (units.md).
    let zero = StorageBody::Release { stream: [0; 16] }.encode();
    assert_eq!(outcome(StorageBody::read(&zero)), "Malformed");
    // Structure before keys: a change whose first grant's key is invalid
    // and whose second grant is malformed is Malformed.
    let grant = GrantMap {
        slot_ed: [0; 32],
        slot_mldsa_hash: [0; 32],
        token: vec![0; SEALED_TOKEN_BYTES],
        rank: MAX_RANK,
    };
    let short = GrantMap {
        token: vec![0; 1],
        ..grant.clone()
    };
    let both = StorageBody::Change {
        twin: [0; 32],
        salt: [0; 32],
        effect: ChangeEffect::Grants(vec![grant.clone(), short]),
    };
    assert_eq!(outcome(StorageBody::read(&both.encode())), "Malformed");
    let invalid = StorageBody::Change {
        twin: [0; 32],
        salt: [0; 32],
        effect: ChangeEffect::Grants(vec![grant]),
    };
    assert_eq!(outcome(StorageBody::read(&invalid.encode())), "InvalidKey");
    // A grant map's rank, key 4, is required and at most 255: a missing
    // rank, one of 256, or one that is no unsigned integer is Malformed,
    // ahead of the invalid key.
    let ranked = |rank: Option<frasil_base::cbor::Value>| {
        let frasil_base::cbor::Value::Map(mut body) =
            frasil_base::cbor::decode(&invalid.encode()).unwrap()
        else {
            panic!("a map")
        };
        let Some(frasil_base::cbor::Value::Array(grants)) = body.get_mut(&4) else {
            panic!("the grants")
        };
        let frasil_base::cbor::Value::Map(map) = &mut grants[0] else {
            panic!("a grant map")
        };
        match rank {
            Some(rank) => map.insert(4, rank),
            None => map.remove(&4),
        };
        frasil_base::cbor::Value::Map(body).encode()
    };
    for (name, rank) in [
        ("missing", None),
        ("256", Some(frasil_base::cbor::Value::Unsigned(256))),
        ("bytes", Some(frasil_base::cbor::Value::Bytes(vec![1]))),
    ] {
        assert_eq!(
            outcome(StorageBody::read(&ranked(rank))),
            "Malformed",
            "a rank {name}"
        );
    }
    let low = ranked(Some(frasil_base::cbor::Value::Unsigned(0)));
    assert_eq!(outcome(StorageBody::read(&low)), "InvalidKey");
    // A slot reference of two elements, `[c, index]`, and a change without
    // a salt are Malformed (peers.md, "Storage events").
    use frasil_base::cbor::Value;
    let mut disown = std::collections::BTreeMap::new();
    disown.insert(1u64, Value::Unsigned(1));
    disown.insert(2, Value::Unsigned(3));
    disown.insert(
        3,
        Value::Array(vec![Value::from([7u8; 32]), Value::Unsigned(0)]),
    );
    let two = Value::Map(disown.clone()).encode();
    assert_eq!(outcome(StorageBody::read(&two)), "Malformed");
    disown.insert(
        3,
        Value::Array(vec![
            Value::from([7u8; 32]),
            Value::Unsigned(0),
            Value::from([9u8; 32]),
        ]),
    );
    let three = Value::Map(disown).encode();
    assert_eq!(
        StorageBody::read(&three).unwrap(),
        StorageBody::Disown {
            slot: SlotId::new([7; 32], 0, EventId([9; 32]))
        }
    );
    let lower = StorageBody::Change {
        twin: [0; 32],
        salt: [0; 32],
        effect: ChangeEffect::Lower(SlotId::new([7; 32], 0, EventId([9; 32]))),
    }
    .encode();
    let Value::Map(mut unsalted) = frasil_base::cbor::decode(&lower).unwrap() else {
        panic!("a map")
    };
    unsalted.remove(&6);
    assert_eq!(
        outcome(StorageBody::read(&Value::Map(unsalted).encode())),
        "Malformed"
    );
    // A root with a reserved duel policy is malformed.
    let root = StorageBody::Root {
        twin: [0; 32],
        mldsa: vec![0; MLDSA_BYTES],
        duel_policy: 1,
        founder_mldsa: vec![0; MLDSA_BYTES],
        founder_signature: vec![0; SIGNATURE_BYTES],
        founder_xwing: vec![0; frasil_crypto::sizes::XWING_PUBLIC],
    };
    assert_eq!(outcome(StorageBody::read(&root.encode())), "Malformed");
    // An erasure of the space names nothing else.
    let mut space = std::collections::BTreeMap::new();
    space.insert(1u64, frasil_base::cbor::Value::Unsigned(1));
    space.insert(2, frasil_base::cbor::Value::Unsigned(5));
    space.insert(3, frasil_base::cbor::Value::Unsigned(1));
    let erase = frasil_base::cbor::Value::Map(space.clone()).encode();
    assert_eq!(StorageBody::read(&erase).unwrap(), StorageBody::Erase);
    space.insert(
        5,
        frasil_base::cbor::Value::Array(vec![frasil_base::cbor::Value::from([1u8; 32])]),
    );
    let both = frasil_base::cbor::Value::Map(space).encode();
    assert_eq!(outcome(StorageBody::read(&both)), "Malformed");
}

/// `erase_bodies` (peers.md, "Storage events" and "Erasure"): an erasure
/// names the whole space; keys 4 and 5 are reserved, so a body that names
/// a stream or an object, with or without key 3, is `Malformed`.
#[test]
fn erase_bodies() {
    let cases = family("erase_bodies");
    let cases = cases.as_array().unwrap();
    assert!(cases.len() >= 2);
    for case in cases {
        let body = hex(&case["body"]);
        let result = StorageBody::read(&body);
        assert_eq!(
            outcome(result.clone()),
            text(&case["verdict"]),
            "{}",
            case["name"]
        );
        if let Ok(read) = result {
            assert_eq!(read, StorageBody::Erase, "{}", case["name"]);
            assert_eq!(read.encode(), body, "{}", case["name"]);
        }
    }
    // A stream named alone, the case a peer must refuse.
    let stream = cases
        .iter()
        .find(|case| text(&case["name"]) == "a stream")
        .expect("a body naming a stream");
    assert_eq!(text(&stream["verdict"]), "Malformed");
}
