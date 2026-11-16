//! `keys.json`: `space_event_bodies`, `visible_refusals`, `sealed_refusals`
//! and `context_refusals` (keys.md, sections 2.6, 3.2 and 3.3).

use frasil_base::ErrorClass;
use frasil_base::cbor;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey, device_id};
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::wrap::xwing_public;
use frasil_events::{EventId, decode};
use frasil_keys::body::{Delivery, GrantSlot, Inner, Seal, VisiblePart};
use frasil_keys::context::{Context, EventKind, Facts, check_context};
use frasil_keys::derive::{
    GrantKey, SecretKind, body_aad, body_commitment, body_key, grant_commitment, read_credential,
    state_secret, upload_key,
};
use frasil_keys::links::LinkKind;
use frasil_keys::wraps::find_own_wrap;
use frasil_keys::{KeyClass, KeyName, RotationSet, SelfRef};
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

/// The state `{A, B}` of `derivations`, with its content key and grant seed,
/// and `A`'s secrets: the "previous" state the bodies link back to.
struct Previous {
    state: RotationSet,
    content: [u8; 32],
    grant: [u8; 32],
    a: RotationSet,
    a_content: [u8; 32],
    a_grant: [u8; 32],
}

fn previous() -> Previous {
    let f: Json = vectors::family(FILE, "derivations");
    let space = id(&f["space"]);
    let rotations = f["rotations"].as_array().unwrap();
    let by_name = |name: &str| rotations.iter().find(|r| r["name"] == name).unwrap();
    let (a, b) = (by_name("A"), by_name("B"));
    let state = RotationSet::new([id(&a["id"]), id(&b["id"])]).unwrap();
    let inputs = |key: &str| -> Vec<[u8; 32]> {
        state
            .ids()
            .iter()
            .map(|i| {
                let r = rotations.iter().find(|r| id(&r["id"]) == *i).unwrap();
                array(&r[key])
            })
            .collect()
    };
    let content = *state_secret(SecretKind::Content, &space, &state, &inputs("content")).unwrap();
    let grant = *state_secret(SecretKind::Grant, &space, &state, &inputs("grant")).unwrap();
    Previous {
        state,
        content,
        grant,
        a: RotationSet::single(id(&a["id"])),
        a_content: array(&a["content"]),
        a_grant: array(&a["grant"]),
    }
}

/// A context from the vectors' flags. `refs` is the vectors' name for
/// `responds`; an absent `notice_covers` answers the notice question yes.
fn context(flags: &Json) -> Context {
    let event = match flags["event"].as_str().unwrap() {
        "genesis" => EventKind::Genesis,
        "roster" => EventKind::Roster,
        "key" => EventKind::Key,
        other => panic!("{other}"),
    };
    let flag = |key: &str| flags[key].as_bool().unwrap_or(false);
    for key in flags.as_object().unwrap().keys() {
        assert!(
            [
                "event",
                "removes",
                "removes_self",
                "removes_propagating",
                "lowers_to_read",
                "lowers_self",
                "admits_from_now_on",
                "admits_propagating",
                "author_propagates",
                "refs",
                "restricted",
                "sealed_under_stale",
                "refs_granted",
                "notice_covers",
            ]
            .contains(&key.as_str()),
            "an unknown flag {key}"
        );
    }
    Context {
        event,
        removes: flag("removes"),
        removes_self: flag("removes_self"),
        removes_propagating: flag("removes_propagating"),
        lowers_to_read: flag("lowers_to_read"),
        lowers_self: flag("lowers_self"),
        admits_from_now_on: flag("admits_from_now_on"),
        admits_propagating: flag("admits_propagating"),
        author_propagates: flag("author_propagates"),
        responds: flag("refs"),
        restricted: flag("restricted"),
        sealed_under_stale: flag("sealed_under_stale"),
        refs_granted: flag("refs_granted"),
        notice_covers: Some(flags["notice_covers"].as_bool().unwrap_or(true)),
    }
}

struct Device {
    device_id: DeviceId,
    xwing: Vec<u8>,
    xwing_seed: [u8; 32],
}

fn devices(f: &Json) -> Vec<Device> {
    f["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let xwing_seed = array::<32>(&d["hybrid_seed"]);
            assert_eq!(xwing_public(&xwing_seed).to_vec(), bytes(&d["hybrid"]));
            let identity = IdentityKey(array(&d["identity"]));
            assert_eq!(ed25519_public(&array(&d["identity_seed"])), identity.0);
            let device = DeviceId(array(&d["device_id"]));
            assert_eq!(
                device_id(
                    &identity,
                    &frasil_crypto::device::KeysCommitment(array(&d["kc"]))
                ),
                device
            );
            Device {
                device_id: device,
                xwing: bytes(&d["hybrid"]),
                xwing_seed,
            }
        })
        .collect()
}

/// The visible part's keys, in order.
fn visible_keys(body: &[u8]) -> Vec<u64> {
    cbor::decode(body)
        .unwrap()
        .as_map()
        .unwrap()
        .keys()
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------
// space_event_bodies

#[test]
fn space_event_bodies() {
    let f: Json = vectors::family(FILE, "space_event_bodies");
    let log = bytes(&f["log"]);
    let devices = devices(&f);
    let prev = previous();

    let new = &f["new_rotation_secrets"];
    let (k_r, w_r, g_r) = (
        array::<32>(&new["content"]),
        array::<32>(&new["upload"]),
        array::<32>(&new["grant"]),
    );
    let commits = &f["commitments_of_new_rotation"];
    assert_eq!(read_credential(&k_r).public, array::<32>(&commits["read"]));
    assert_eq!(upload_key(&w_r).public, array::<32>(&commits["upload"]));
    assert_eq!(
        GrantKey::derive(&g_r).commitment(false),
        array::<32>(&commits["grant"])
    );

    let team = &f["team"];
    let team_space = id(&team["space"]);
    let team_public: [u8; 1216] = array(&team["grant_public"]);
    let mut team_rotations = BTreeMap::new();
    for (title, rotation) in team["rotations"].as_object().unwrap() {
        let commitment = array::<32>(&rotation["grant_commitment"]);
        assert_eq!(
            grant_commitment(&team_public, title == "break"),
            commitment,
            "{title}"
        );
        team_rotations.insert(id(&rotation["id"]), commitment);
    }

    for case in f["bodies"].as_array().unwrap() {
        let title = case["name"].as_str().unwrap();
        let author = DeviceId(array::<32>(&case["author"]));
        let seq = case["seq"].as_u64().unwrap();
        let own = SelfRef::new(author, seq);
        let body = bytes(&case["body"]);
        assert_eq!(body, bytes(&case["payload"]), "{title}");

        // The carrying event: a space event signed under scheme 2.
        let event = decode(&bytes(&case["event"]["signed"])).unwrap();
        assert_eq!(
            u64::from(event.kind()),
            case["event"]["kind"].as_u64().unwrap()
        );
        assert_eq!(event.id(), id(&case["event"]["event_id"]));
        assert_eq!((event.author(), event.seq()), (&author, seq));
        assert_eq!(event.unverified_body(), &body[..]);
        let mldsa = bytes(&case["event"]["author_mldsa"]);
        let xwing = &devices
            .iter()
            .find(|d| d.device_id == author)
            .expect("the author is a device of the vectors")
            .xwing;
        let keys = HybridKeys::new(&mldsa, Some(xwing)).unwrap();
        assert!(event.verify_hybrid(Some(&keys)).is_ok());

        // The visible part, and its one encoding.
        let visible = VisiblePart::read(&body, &author, seq).unwrap();
        assert_eq!(visible.encode(), body, "{title}");

        // The sealed part, opened under the body key of its secret, and
        // sealed again with its own nonce.
        let secret = array::<32>(&case["seal_secret"]);
        let key = body_key(&secret, &log, &author, seq);
        assert_eq!(body_commitment(&key), visible.commitment);
        let inner = visible.open(&key, &log, &author, seq).unwrap();
        let nonce: [u8; 24] = visible.sealed[..24].try_into().unwrap();
        assert_eq!(
            inner.seal_with(&key, &log, &author, seq, &nonce),
            visible.sealed
        );

        let summary = &case["summary"];
        assert_eq!(visible.rotates(), summary["rotates"], "{title}");
        assert_eq!(inner.grant_rotation(), summary["grant_rotation"]);
        assert_eq!(inner.is_break, summary["break"]);
        assert_eq!(visible.deliveries.len(), summary["deliveries"]);
        let wraps: usize = visible.deliveries.iter().map(|d| d.wraps.len()).sum();
        let space_wraps: usize = visible.deliveries.iter().map(|d| d.space_wraps.len()).sum();
        assert_eq!(wraps, summary["wraps"]);
        assert_eq!(space_wraps, summary["space_wraps"]);
        assert_eq!(inner.links.len(), summary["links"]);
        assert_eq!(inner.gaps.len(), summary["gaps"]);
        assert_eq!(inner.notices.len(), summary["notices"]);

        let refs: Vec<(EventId, EventId)> = inner.refs.iter().map(|r| (r.log, r.id)).collect();
        let expected: Vec<(EventId, EventId)> = case["refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (id(&pair[0]), id(&pair[1])))
            .collect();
        assert_eq!(refs, expected, "{title}");

        // Against its place: the notice covers the response when it names a
        // rotation the refs name.
        let mut place = context(&case["context"]);
        place.responds = inner.responds();
        place.notice_covers = Some(
            inner
                .notices
                .iter()
                .any(|n| refs.iter().any(|(_, r)| *r == n.rotation)),
        );
        assert_eq!(
            check_context(Some(Facts::of(&visible, &inner)), &place),
            Ok(()),
            "{title}"
        );
        // Each notice names a team rotation whose commitment its key and
        // break match.
        for notice in &inner.notices {
            assert_eq!(notice.space, team_space);
            assert_eq!(
                grant_commitment(&notice.public, notice.from_now_on),
                team_rotations[&notice.rotation],
                "{title}"
            );
        }
        // A guest's heal names the grant state its own delivery's grant
        // slots carry.
        if !inner.grant_rotation() && visible.rotates() {
            assert_eq!(inner.grant, Some(GrantSlot::State(prev.state.clone())));
        }

        // Every bundle wrap opens for one of the devices, and its slots
        // match what the delivery names.
        for delivery in &visible.deliveries {
            check_wraps(
                delivery,
                &devices,
                &log,
                &own,
                &visible,
                inner.is_break,
                &prev,
            );
        }
        // Every link opens and reaches the secret it names.
        for link in &inner.links {
            let (under_secret, reached) = match (&link.under, link.kind) {
                (KeyName::SelfRef(_), LinkKind::Content) => (k_r, prev.content),
                (KeyName::SelfRef(_), LinkKind::Grant) => (g_r, prev.grant),
                (KeyName::Set(under), LinkKind::Content) => {
                    assert_eq!(*under, prev.state);
                    assert_eq!(link.reaches, prev.a);
                    (prev.content, prev.a_content)
                }
                (KeyName::Set(_), LinkKind::Grant) => (prev.grant, prev.a_grant),
            };
            assert_eq!(*link.open_read(&log, &under_secret).unwrap(), reached);
        }
    }

    // A self-removal: it does not rotate, is sealed under the current state,
    // which it names, and need not rotate.
    let removal = &f["self_removal"];
    let event = decode(&bytes(&removal["event"]["signed"])).unwrap();
    assert_eq!(event.id(), id(&removal["event"]["event_id"]));
    let body = bytes(&removal["body"]);
    assert_eq!(event.unverified_body(), &body[..]);
    let visible = VisiblePart::read(&body, event.author(), event.seq()).unwrap();
    assert_eq!(visible.encode(), body);
    assert_eq!(visible.sealed_under(), Some(&prev.state));
    let inner = visible
        .open_with_secret(&prev.content, &log, event.author(), event.seq())
        .unwrap();
    assert!(inner.roster.is_some());
    // The vector checks the context as an event that carries no opened
    // body, as the reference does.
    let place = context(&removal["context"]);
    assert!(place.removes_self && !place.removes_propagating);
    assert_eq!(check_context(None, &place), Ok(()));

    shapes(&f["shapes"]);
}

fn check_wraps(
    delivery: &Delivery,
    devices: &[Device],
    log: &[u8],
    own: &SelfRef,
    visible: &VisiblePart,
    is_break: bool,
    prev: &Previous,
) {
    let opened: Vec<_> = devices
        .iter()
        .filter_map(|d| {
            find_own_wrap(
                &delivery.wraps,
                log,
                delivery.key_name.as_ref(),
                delivery.grant_name.as_ref(),
                &d.device_id,
                &d.xwing_seed,
            )
        })
        .collect();
    assert_eq!(opened.len(), delivery.wraps.len());
    for (_, bundle) in opened {
        match &delivery.key_name {
            // The own delivery: each slot matches the rotation's commitments.
            Some(KeyName::SelfRef(found)) => {
                assert_eq!(found, own);
                let keys = visible.rotation().unwrap();
                assert_eq!(read_credential(bundle.content().unwrap()).public, keys.read);
                if let Some(upload) = bundle.upload() {
                    assert_eq!(upload_key(upload).public, keys.upload);
                }
                if let Some(grant) = bundle.grant() {
                    assert_eq!(
                        GrantKey::derive(grant).commitment(is_break),
                        keys.grant_commitment
                    );
                }
            }
            Some(KeyName::Set(state)) => {
                assert_eq!(*state, prev.state);
                assert_eq!(bundle.content(), Some(&prev.content));
                assert_eq!(bundle.grant(), Some(&prev.grant));
            }
            None => panic!("a delivery of a grant state alone"),
        }
    }
}

/// `space_event_bodies.shapes`: roster.md's history, whose space events
/// read and whose listed bodies open under their body keys.
fn shapes(f: &Json) {
    let mut events = BTreeMap::new();
    for item in f["history"].as_array().unwrap() {
        let event = decode(&bytes(&item["signed"])).unwrap();
        assert_eq!(event.id(), id(&item["id"]));
        if event.kind() == frasil_events::kind::SPACE {
            let visible =
                VisiblePart::read(event.unverified_body(), event.author(), event.seq()).unwrap();
            assert_eq!(
                visible.encode(),
                event.unverified_body(),
                "{}",
                item["name"]
            );
            assert_eq!(visible.nonce.is_some(), event.is_genesis());
        }
        events.insert(item["name"].as_str().unwrap().to_owned(), event);
    }
    for (title, shape) in f["events"].as_object().unwrap() {
        let event = &events[shape["event"].as_str().unwrap()];
        let body = event.unverified_body();
        let keys: Vec<u64> = shape["visible_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_u64().unwrap())
            .collect();
        assert_eq!(visible_keys(body), keys, "{title}");
        assert_eq!(body.len() as u64, shape["body_bytes"].as_u64().unwrap());
        let visible = VisiblePart::read(body, event.author(), event.seq()).unwrap();
        assert_eq!(
            visible.sealed.len() as u64,
            shape["sealed_bytes"].as_u64().unwrap()
        );
        let key = array::<32>(&shape["body_key"]);
        assert_eq!(body_commitment(&key), array::<32>(&shape["commitment"]));
        assert_eq!(visible.commitment, array::<32>(&shape["commitment"]));
        let log = event.log_id();
        let inner = visible.open(&key, log.as_bytes(), event.author(), event.seq());
        assert!(inner.is_ok(), "{title}: {inner:?}");
    }

    let derived = &f["body_key"];
    let event = &events[derived["event"].as_str().unwrap()];
    let log = bytes(&derived["log"]);
    assert_eq!(event.log_id().as_bytes()[..], log[..]);
    let author = DeviceId(array::<32>(&derived["author"]));
    let seq = derived["seq"].as_u64().unwrap();
    assert_eq!((event.author(), event.seq()), (&author, seq));
    let named = RotationSet::new(
        derived["sealed_under"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| events[name.as_str().unwrap()].id()),
    )
    .unwrap();
    let visible = VisiblePart::read(event.unverified_body(), &author, seq).unwrap();
    assert_eq!(visible.seal, Seal::Under(named));
    assert_eq!(body_aad(&log, &author, seq), bytes(&derived["info"]));
    let key = body_key(&array(&derived["state_content_key"]), &log, &author, seq);
    assert_eq!(*key, array::<32>(&derived["body_key"]));
    assert_eq!(body_commitment(&key), array::<32>(&derived["commitment"]));

    // The genesis binds its nonce in place of its log.
    let genesis = &f["genesis_body_key"];
    let nonce = array::<16>(&genesis["nonce"]);
    let author = DeviceId(array::<32>(&genesis["author"]));
    let seq = genesis["seq"].as_u64().unwrap();
    assert_eq!(body_aad(&nonce, &author, seq), bytes(&genesis["info"]));
    let key = body_key(&array(&genesis["content_key"]), &nonce, &author, seq);
    assert_eq!(*key, array::<32>(&genesis["body_key"]));
    let event = events.values().find(|e| e.is_genesis()).unwrap();
    assert_eq!((event.author(), event.seq()), (&author, seq));
    let visible = VisiblePart::read(event.unverified_body(), &author, seq).unwrap();
    assert_eq!(visible.nonce, Some(nonce));
    let inner = visible.open(&key, &nonce, &author, seq).unwrap();
    assert!(inner.grant_rotation() && inner.roster.is_some());
}

// ---------------------------------------------------------------------------
// visible_refusals, sealed_refusals

#[test]
fn visible_refusals() {
    let cases: Vec<Json> = vectors::family(FILE, "visible_refusals");
    assert_eq!(cases.len(), 24);
    for case in &cases {
        let result = VisiblePart::read(
            &bytes(&case["payload"]),
            &DeviceId(array(&case["author"])),
            case["seq"].as_u64().unwrap(),
        );
        assert_eq!(
            result.err(),
            Some(class(&case["error"])),
            "{}",
            case["name"]
        );
    }
}

/// Step 5: with keys 8 and 14 present, a read credential or an upload key
/// that is not a valid Ed25519 key is `InvalidKey`; a short one is
/// `Malformed` first.
#[test]
fn invalid_rotation_keys() {
    let valid = read_credential(&[1; 32]).public;
    let body = |read: [u8; 32], upload: [u8; 32]| {
        VisiblePart {
            seal: Seal::Rotation(frasil_keys::body::RotationKeys {
                grant_commitment: [2; 32],
                read,
                upload,
            }),
            deliveries: Vec::new(),
            sealed: vec![0; 41],
            nonce: None,
            commitment: [3; 32],
            twin: None,
        }
        .encode()
    };
    let read = |body: Vec<u8>| VisiblePart::read(&body, &DeviceId([7; 32]), 5).map(|_| ());
    assert_eq!(read(body(valid, valid)), Ok(()));
    let invalid_key = Err(KeyClass::from(ErrorClass::InvalidKey));
    assert_eq!(read(body([0; 32], valid)), invalid_key);
    assert_eq!(read(body(valid, [0; 32])), invalid_key);
    // A 31-byte commitment beside an invalid key: sizes come first.
    let mut short = cbor::decode(&body([0; 32], valid)).unwrap();
    if let cbor::Value::Map(map) = &mut short {
        map.insert(14, cbor::Value::from([3u8; 31]));
    }
    assert_eq!(
        read(short.encode()),
        Err(KeyClass::from(ErrorClass::Malformed))
    );
}

#[test]
fn sealed_refusals() {
    let f: Json = vectors::family(FILE, "space_event_bodies");
    let log = bytes(&f["log"]);
    let cases: Vec<Json> = vectors::family(FILE, "sealed_refusals");
    assert_eq!(cases.len(), 13);
    for case in &cases {
        let author = DeviceId(array::<32>(&case["author"]));
        let seq = case["seq"].as_u64().unwrap();
        let visible = VisiblePart::read(&bytes(&case["payload"]), &author, seq).unwrap();
        let result = visible.open_with_secret(&array(&case["opened_with"]), &log, &author, seq);
        assert_eq!(
            result.err(),
            Some(class(&case["error"])),
            "{}",
            case["name"]
        );
    }
}

// ---------------------------------------------------------------------------
// context_refusals

fn facts(opened: &Json) -> Option<Facts> {
    (!opened.is_null()).then(|| Facts {
        rotates: opened["rotates"].as_bool().unwrap(),
        is_break: opened["break"].as_bool().unwrap(),
        grant_rotation: opened["grant_rotation"].as_bool().unwrap_or(false),
    })
}

#[test]
fn context_refusals() {
    let f: Json = vectors::family(FILE, "context_refusals");
    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 15);
    for case in refused {
        assert_eq!(
            check_context(facts(&case["opened"]), &context(&case["context"])),
            Err(class(&case["error"])),
            "{}",
            case["name"]
        );
    }
    for case in f["accepted"].as_array().unwrap() {
        assert_eq!(case["result"], "accepted");
        assert_eq!(
            check_context(facts(&case["opened"]), &context(&case["context"])),
            Ok(()),
            "{}",
            case["name"]
        );
    }
}

// ---------------------------------------------------------------------------
// The caps on deliveries and wraps, as `taking_keys.caps` states them (that
// family is the key graph's; these are the visible part's checks).

#[test]
fn caps_on_deliveries_and_wraps() {
    let author = DeviceId([7; 32]);
    let state = RotationSet::single(EventId([9; 32]));
    let mut dummy = vec![0x01, 0x64, 0x7a];
    dummy.resize(1236, 0);
    let body = |deliveries: Vec<Delivery>| {
        VisiblePart {
            seal: Seal::Under(state.clone()),
            deliveries,
            sealed: vec![0; 41],
            nonce: None,
            commitment: [0; 32],
            twin: None,
        }
        .encode()
    };
    let delivery = |wraps: usize, space_wraps: usize| Delivery {
        key_name: Some(KeyName::Set(state.clone())),
        grant_name: None,
        wraps: vec![dummy.clone(); wraps],
        space_wraps: vec![dummy.clone(); space_wraps],
    };
    let read =
        |deliveries| VisiblePart::read(&body(deliveries), &author, 5).map(|v| v.wrap_count());
    assert_eq!(read(vec![delivery(765, 3)]), Ok(768));
    let malformed = Err(KeyClass::from(ErrorClass::Malformed));
    assert_eq!(read(vec![delivery(769, 0)]), malformed);
    assert_eq!(read(vec![delivery(1, 0); 64]), Ok(64));
    assert_eq!(read(vec![delivery(1, 0); 65]), malformed);
}

#[test]
fn a_body_round_trips() {
    let author = DeviceId([7; 32]);
    let state = RotationSet::single(EventId([9; 32]));
    let inner = Inner {
        refs: vec![frasil_events::Ref {
            log: EventId([1; 32]),
            id: EventId([2; 32]),
        }],
        padding: Some(3),
        ..Inner::default()
    };
    let key = body_key(&[4; 32], b"log", &author, 5);
    let visible = VisiblePart {
        seal: Seal::Under(state),
        deliveries: Vec::new(),
        sealed: inner.seal_with(&key, b"log", &author, 5, &[6; 24]),
        nonce: None,
        commitment: body_commitment(&key),
        twin: Some([8; 32]),
    };
    let read = VisiblePart::read(&visible.encode(), &author, 5).unwrap();
    assert_eq!(read, visible);
    assert_eq!(read.open(&key, b"log", &author, 5), Ok(inner));
    assert_eq!(
        read.open(&key, b"log", &author, 6),
        Err(ErrorClass::BadSeal.into())
    );
}
