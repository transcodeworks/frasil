//! `units.json`: `fixtures`, `parameters`, `units`, `list_events`,
//! `unit_refusals`, `handed_body_keys`, `stream_types`, `system_stream`,
//! `objects` and `object_refusals` (units.md, sections 2.1 to 2.8, 2.12,
//! 3.1 to 3.3 and 3.11).

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels::STREAM_ID;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::EventId;
use frasil_testkit::hex;
use frasil_units::body::KeyReference;
use frasil_units::inner::Inner;
use frasil_units::limits::*;
use frasil_units::messages::{Message, Received, SyncMessage};
use frasil_units::objects::{
    ObjectKeys, read_object_chunked, read_object_with_key_chunked, seal_object_chunked,
};
use frasil_units::own::{
    Dropped, EntryIgnored, Forwarding, ListEventsBody, forward_list_events, read_body_keys,
    read_list_copy, read_recovery_entry,
};
use frasil_units::seal::{body_key, commitment, unit_key};
use frasil_units::stream::{Opening, check_stream, content_check, stream_id};
use frasil_units::types::{self, FRASIL_TYPES, SYSTEM_TYPES};
use frasil_units::unit::{Draft, Unit};
use frasil_units::{StreamId, UnitError};
use serde_json::Value as Json;
use std::collections::BTreeMap;

fn class_name(result: Result<impl Sized, UnitError>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(class) => class.name(),
    }
}

fn has_adapter(type_: &str) -> bool {
    FRASIL_TYPES.contains(&type_)
}

/// The genesis of the vectors' space and its ID.
fn genesis() -> (Vec<u8>, EventId) {
    let fixtures = family("fixtures");
    (
        bytes(&fixtures["genesis"]["signed"]),
        id(&fixtures["genesis"]["id"]),
    )
}

// ---------------------------------------------------------------------------
// fixtures, parameters, system_stream

#[test]
fn fixtures() {
    let fixtures = family("fixtures");
    assert_eq!(array::<32>(&fixtures["space"]), space().0);
    let (signed, gid) = genesis();
    let genesis = frasil_events::decode(&signed).unwrap();
    assert_eq!(genesis.id(), gid);
    assert_eq!(genesis.author(), signer("A").device_id());
    for name in ["A", "B", "C"] {
        assert_eq!(
            array::<32>(&fixtures["devices"][name]),
            signer(name).device_id().0
        );
    }
    for name in ["A", "B"] {
        assert_eq!(id(&fixtures["rotations"][name]), rotation(name).0);
    }
    let person = frasil_events::decode(&bytes(&fixtures["person"]["first_event"])).unwrap();
    assert_eq!(person.id(), id(&fixtures["person"]["id"]));
    assert_eq!(
        person.author(),
        signer_of_seed(&example("units/person/Q/ed25519")).device_id()
    );
}

#[test]
fn parameters() {
    let p = family("parameters");
    let n = |key: &str| p[key].as_u64().unwrap();
    let pair = |key: &str| (p[key][0].as_u64().unwrap(), p[key][1].as_u64().unwrap());
    assert_eq!(n("max_unit_bytes"), MAX_UNIT_BYTES as u64);
    assert_eq!(n("max_locators"), MAX_LOCATORS as u64);
    assert_eq!(n("max_covers"), MAX_COVERS as u64);
    assert_eq!(n("max_stubs"), MAX_STUBS as u64);
    assert_eq!(n("max_excluded"), MAX_EXCLUDED as u64);
    assert_eq!(
        pair("adapter_type_bytes"),
        (MIN_TYPE_BYTES as u64, MAX_TYPE_BYTES as u64)
    );
    assert_eq!(
        pair("adapter_type_octets"),
        (u64::from(MIN_TYPE_OCTET), u64::from(MAX_TYPE_OCTET))
    );
    assert_eq!(pair("list_events_per_copy"), (1, MAX_LIST_EVENTS as u64));
    assert_eq!(pair("body_keys_per_unit"), (1, MAX_BODY_KEYS as u64));
    assert_eq!(n("max_object_bytes"), MAX_OBJECT_BYTES);
    assert_eq!(n("chunk_bytes"), CHUNK_BYTES as u64);
    assert_eq!(n("sealed_chunk_bytes"), SEALED_CHUNK_BYTES as u64);
    assert_eq!(CHUNK_BYTES + NONCE_BYTES + TAG_BYTES, SEALED_CHUNK_BYTES);
    assert_eq!(pair("heads_per_statement"), (1, MAX_HEADS as u64));
    assert_eq!(n("max_statement_bytes"), MAX_STATEMENT_BYTES as u64);
    assert_eq!(n("max_message_items"), MAX_MESSAGE_ITEMS as u64);
    assert_eq!(n("max_message_bytes"), MAX_MESSAGE_BYTES as u64);
    let streams = &p["max_streams_per_space"];
    assert_eq!(streams["min"].as_u64(), Some(max_streams_per_space::MIN));
    assert_eq!(streams["max"].as_u64(), Some(max_streams_per_space::MAX));
    assert_eq!(
        streams["default"].as_u64(),
        Some(max_streams_per_space::DEFAULT)
    );
    let names = |key: &str| -> Vec<String> {
        p[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(names("frasil_types"), FRASIL_TYPES);
    assert_eq!(names("system_types"), SYSTEM_TYPES);
}

#[test]
fn system_stream() {
    let f = family("system_stream");
    assert_eq!(array::<16>(&f["stream"]), system());
    assert!(frasil_units::stream::is_valid(&system()));
}

// ---------------------------------------------------------------------------
// units

/// The signers of the vectors' units, by device ID.
fn signers() -> BTreeMap<DeviceId, Signer> {
    let mut signers: BTreeMap<DeviceId, Signer> = ["A", "B", "C"]
        .iter()
        .map(|name| {
            let signer = signer(name);
            (*signer.device_id(), signer)
        })
        .collect();
    let person = signer_of_seed(&example("units/person/Q/ed25519"));
    signers.insert(*person.device_id(), person);
    signers
}

#[test]
fn units() {
    let cases = family("units");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 9);
    let signers = signers();
    let person = family("fixtures")["person"].clone();
    let plain_id = id(&cases[0]["id"]);
    for case in cases {
        let name = text(&case["name"]);
        let key: [u8; 32] = array(&case["state_key"]);
        let system = match case.get("personal_system_stream") {
            Some(stream) => array::<16>(stream),
            None => system(),
        };
        assert_eq!(*unit_key(&key), array::<32>(&case["unit_key"]), "{name}");
        let signed = bytes(&case["signed"]);
        let unit = Unit::check_at_peer(&signed).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(unit.id(), id(&case["id"]), "{name}");
        assert_eq!(unit.event.event_bytes(), bytes(&case["event"]), "{name}");
        assert_eq!(unit.event.unverified_body(), bytes(&case["body"]), "{name}");
        assert_eq!(unit.body.encode(), bytes(&case["body"]), "{name}");
        assert_eq!(unit.body.key, bytes(&case["key_reference"]), "{name}");
        assert_eq!(unit.body.sealed, bytes(&case["sealed"]), "{name}");
        assert_eq!(unit.body.sealed[..24], bytes(&case["nonce"]), "{name}");
        assert_eq!(unit.aad(), bytes(&case["aad"]), "{name}");
        let body = body_key(&key, &unit.aad());
        assert_eq!(*body, array::<32>(&case["body_key"]), "{name}");
        assert_eq!(
            commitment(&body),
            array::<32>(&case["commitment"]),
            "{name}"
        );
        assert_eq!(unit.body.sealed[24..56], commitment(&body), "{name}");

        // The member's steps 13 and 14, then step 16's content check.
        let inner = unit
            .open_with(&key, false, Some(&system))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(inner.encode(), bytes(&case["inner"]), "{name}");
        let verdict = content_check(
            &unit.body.stream,
            &system,
            &inner.type_,
            inner.opening.as_ref(),
            has_adapter,
        );
        assert_eq!(class_name(verdict), text(&case["content_check"]), "{name}");

        // Written again from its parts: the same bytes.
        let event = &unit.event;
        let draft = Draft {
            log: event.log_id(),
            seq: event.seq(),
            prev: event.prev(),
            parents: event.parents().to_vec(),
            scheme: event.scheme(),
            stream: unit.body.stream,
            key_reference: unit.body.key.clone(),
            stream_prev: unit.body.stream_prev,
            objects: unit.body.objects.clone(),
            compacts: unit.body.compacts.clone(),
            supersedes: Vec::new(),
        };
        assert_eq!(draft.scheme, Scheme::Ed25519);
        let written = draft.write_with(
            &signers[event.author()],
            &key,
            &inner.encode(),
            &array(&case["nonce"]),
        );
        assert_eq!(written.signed, signed, "{name}");
        assert_eq!(written.aad, bytes(&case["aad"]), "{name}");
        assert_eq!(written.id, unit.id(), "{name}");
        // Declaring the cuts its envelope carries writes it again too, and
        // other cuts land in the envelope with the rest unchanged.
        let again = draft.write_with_cuts(
            &signers[event.author()],
            &key,
            &inner.encode(),
            &array(&case["nonce"]),
            event.cuts(),
        );
        assert_eq!(again.signed, signed, "{name}");
        let cut = frasil_events::EventId([7; 32]);
        let with_cut = draft.write_with_cuts(
            &signers[event.author()],
            &key,
            &inner.encode(),
            &array(&case["nonce"]),
            &[cut],
        );
        let decoded = frasil_events::decode(&with_cut.signed).unwrap();
        assert_eq!(decoded.cuts(), &[cut], "{name}");
        assert_eq!(decoded.unverified_body(), event.unverified_body(), "{name}");

        match name {
            "a unit naming two objects" => {
                // The unit names them in ascending order.
                let mut locators: Vec<Vec<u8>> = case["locators"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(bytes)
                    .collect();
                locators.sort_unstable();
                let objects: Vec<Vec<u8>> = unit.body.objects.iter().map(|o| o.to_vec()).collect();
                assert_eq!(objects, locators);
            }
            "a list copy carrying a device-list genesis" => {
                assert_eq!(inner.type_, types::LIST);
                let events = read_list_copy(&inner.content).unwrap();
                let ids: Vec<EventId> = events.iter().map(|e| e.id()).collect();
                assert_eq!(ids, vec![id(&case["list_event_id"])]);
                assert_eq!(ids, vec![id(&person["id"])]);
            }
            "a body-keys unit" => {
                assert_eq!(read_body_keys(&inner.content).unwrap().len(), 2);
                assert!(unit.body.stream_prev.is_some());
            }
            "a move unit with padding" => {
                assert_eq!(inner.type_, types::MOVE);
                assert_eq!(inner.padding, Some(3));
            }
            "a re-submission with refs" => {
                assert_eq!(inner.resubmits, Some(plain_id));
                assert_eq!(inner.refs.len(), 1);
            }
            "a unit under a merged state" => {
                // Derived in the space of the units' log, the genesis's ID.
                let log = id(&family("fixtures")["genesis"]["id"]);
                assert_eq!(key, state_key_in(&log, &["A", "B"]));
                assert_eq!(unit.body.key, key_reference(&["A", "B"]));
            }
            "a unit of a restricted space" => {
                assert!(matches!(
                    unit.body.reference,
                    KeyReference::Restricted { .. }
                ));
                assert_eq!(unit.space(), id(&case["restricted_space"]));
            }
            "a recovery-entry unit of a personal space" => {
                assert_eq!(inner.type_, types::RECOVERY_ENTRY);
                assert_eq!(inner.content, bytes(&case["entry"]));
                let personal: [u8; 32] = array(&case["personal_space"]);
                assert_eq!(unit.space().0, personal);
                let member = DeviceId(array(&case["recovery_key"]["device_id"]));
                let entry =
                    read_recovery_entry(&inner.content, &personal, |m| *m == member).unwrap();
                assert_eq!(entry.key, array::<32>(&case["recovery_key"]["fetch_key"]));
                assert_eq!(
                    read_recovery_entry(&inner.content, &personal, |_| false).err(),
                    Some(EntryIgnored::MemberNotActive)
                );
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// list_events

#[test]
fn list_events() {
    let f = family("list_events");
    assert_eq!(
        text(&f["content_name"]),
        frasil_units::own::LIST_EVENTS_CONTENT_NAME
    );
    let space_id = id(&f["space"]);
    assert_eq!(space_id, space());
    let persons: Vec<EventId> = f["roster_persons"]
        .as_array()
        .unwrap()
        .iter()
        .map(id)
        .collect();
    let named = |person: &EventId| persons.contains(person);

    let events: Vec<Vec<u8>> = f["body"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let body = ListEventsBody {
        space: space_id,
        events: events.clone(),
    };
    assert_eq!(body.encode(), bytes(&f["body"]["bytes"]));
    assert_eq!(ListEventsBody::read(&bytes(&f["body"]["bytes"])), Ok(body));
    let decisions = forward_list_events(&events, named, |_| false);
    check_decisions(&decisions, &f["body"]["decisions"]);

    let message = SyncMessage {
        space: space_id,
        message: Message::ListEvents { events },
    };
    assert_eq!(message.encode(), bytes(&f["message"]["bytes"]));
    assert_eq!(
        f["message"]["type"].as_u64(),
        Some(message.message.type_code())
    );
    assert_eq!(text(&f["message"]["name"]), message.message.name());
    assert_eq!(
        SyncMessage::read(&bytes(&f["message"]["bytes"])),
        Ok(Received::Message(message))
    );

    let dropped = &f["dropped"];
    let read = ListEventsBody::read(&bytes(&dropped["bytes"])).unwrap();
    let expected: Vec<Vec<u8>> = dropped["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    assert_eq!(read.events, expected);
    let decisions = forward_list_events(&read.events, named, |_| false);
    check_decisions(&decisions, &dropped["decisions"]);
    assert_eq!(
        decisions[1],
        Forwarding::Dropped(
            Some(id(&dropped["unnamed_person"])),
            Dropped::PersonNotNamed
        )
    );
    // An event the system stream holds already is not forwarded again.
    let held = forward_list_events(&read.events[..1], named, |_| true);
    assert!(matches!(held[0], Forwarding::AlreadyHeld(_)));
}

fn check_decisions(decisions: &[Forwarding], expected: &Json) {
    let expected = expected.as_array().unwrap();
    assert_eq!(decisions.len(), expected.len());
    for (decision, row) in decisions.iter().zip(expected) {
        let (event, text_) = match decision {
            Forwarding::Forward(id) => (Some(*id), "forwarded in a frasil:list unit"),
            Forwarding::AlreadyHeld(id) => (Some(*id), "already in the system stream"),
            Forwarding::Dropped(id, _) => (*id, "dropped"),
        };
        assert_eq!(text_, text(&row["decision"]));
        assert_eq!(event, Some(id(&row["id"])));
        if let Forwarding::Dropped(_, Dropped::PersonNotNamed) = decision {
            assert_eq!(
                text(&row["reason"]),
                "of a person the space's roster never named"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// handed_body_keys

#[test]
fn handed_body_keys() {
    let t = family("handed_body_keys");
    let unit = Unit::check_at_peer(&bytes(&t["signed"])).unwrap();
    // A member that holds no state key opens the unit under its body key.
    let key = zeroize::Zeroizing::new(array::<32>(&t["body_key"]));
    let inner = unit
        .open_handed(std::slice::from_ref(&key), Some(&system()))
        .unwrap();
    assert_eq!(inner.type_, text(&t["opened"]["type"]));
    assert_eq!(inner.content, bytes(&t["opened"]["content"]));
    // A key that misses the commitment holds it.
    let wrong = zeroize::Zeroizing::new(array::<32>(&t["wrong_key"]));
    let refused = unit.open_handed(&[wrong], Some(&system())).unwrap_err();
    assert_eq!(
        class_name(Err::<(), _>(refused)),
        text(&t["wrong_key_class"])
    );
    // And the body key a member derives from the state is the same.
    assert_eq!(*body_key(&state_key(&["A"]), &unit.aad()), *key);
}

// ---------------------------------------------------------------------------
// unit_refusals

/// Sections 3.1 and 3.2, steps 1 to 14, under `key`.
fn judge(signed: &[u8], key: &[u8; 32]) -> Result<Inner, UnitError> {
    Unit::check_at_peer(signed)?.open_with(key, false, Some(&system()))
}

#[test]
fn unit_refusals() {
    let rows = family("unit_refusals");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 30);
    let key = state_key(&["A"]);
    for row in rows {
        let name = text(&row["name"]);
        let expected = text(&row["class"]);
        if name == "a unit over 1,048,576 bytes" {
            // Built again from the reference's inputs: its length is given.
            let (_, gid) = genesis();
            let loro = Opening::with_salt(types::LORO, salt("L"));
            let inner = Inner::new(types::LORO, vec![0; MAX_UNIT_BYTES]).with_opening(loro.clone());
            // The vectors' units are of the log the genesis starts.
            let draft = Draft {
                log: gid,
                seq: 2,
                prev: Some(gid),
                parents: vec![gid],
                scheme: Scheme::Ed25519,
                stream: loro.stream(),
                key_reference: key_reference(&["A"]),
                stream_prev: None,
                objects: Vec::new(),
                compacts: None,
                supersedes: Vec::new(),
            };
            let written = draft.write_with(&signer("A"), &key, &inner.encode(), &nonce("big"));
            assert_eq!(
                written.signed.len() as u64,
                row["signed_length"].as_u64().unwrap()
            );
            assert_eq!(class_name(judge(&written.signed, &key)), expected);
            continue;
        }
        let with_key = if name == "a seal opened under another state's key" {
            state_key(&["B"])
        } else {
            key
        };
        assert_eq!(
            class_name(judge(&bytes(&row["signed"]), &with_key)),
            expected,
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// stream_types

#[test]
fn stream_types() {
    let f = family("stream_types");
    assert_eq!(bytes(&f["label"]), STREAM_ID);
    for row in f["streams"].as_array().unwrap() {
        assert_eq!(
            stream_id(text(&row["type"]), &array(&row["salt"])),
            array::<16>(&row["stream"])
        );
    }
    let key = state_key(&["A"]);
    for case in f["cases"].as_array().unwrap() {
        let name = text(&case["case"]);
        let stream: StreamId = array(&case["stream"]);
        let opening = Opening::with_salt(
            text(&case["opening"]["type"]),
            array(&case["opening"]["salt"]),
        );
        assert_eq!(
            opening.stream(),
            array::<16>(&case["opening"]["hashes_to"]),
            "{name}"
        );
        let unit = Unit::check_at_peer(&bytes(&case["signed"])).unwrap();
        assert_eq!(unit.body.stream, stream);
        let inner = unit.open_with(&key, false, Some(&system())).unwrap();
        assert_eq!(inner.type_, text(&case["type"]), "{name}");
        assert_eq!(inner.opening.as_ref(), Some(&opening), "{name}");
        let verdict = check_stream(&stream, &opening, &inner.type_);
        let verdict = verdict.map_err(UnitError::from);
        assert_eq!(class_name(verdict), text(&case["verdict"]), "{name}");
        // The same verdict through step 16's content check.
        let checked = content_check(
            &stream,
            &system(),
            &inner.type_,
            Some(&opening),
            has_adapter,
        );
        assert_eq!(class_name(checked), text(&case["verdict"]), "{name}");
    }
}

// ---------------------------------------------------------------------------
// objects, object_refusals

#[test]
fn objects() {
    let f = family("objects");
    assert_eq!(f["chunk_bytes"].as_u64(), Some(CHUNK_BYTES as u64));
    let key = state_key(&["A"]);
    let reference = key_reference(&["A"]);
    let keys = ObjectKeys::of(&key);
    for case in f["cases"].as_array().unwrap() {
        let name = text(&case["name"]);
        let chunk = case["chunk_bytes"].as_u64().unwrap() as usize;
        assert_eq!(*keys.id_key, array::<32>(&case["keys"]["id_key"]));
        assert_eq!(*keys.nonce_key, array::<32>(&case["keys"]["nonce_key"]));
        assert_eq!(*keys.seal_key, array::<32>(&case["keys"]["seal_key"]));
        let plaintext = bytes(&case["plaintext"]);
        let object = seal_object_chunked(&space(), &key, &reference, &plaintext, chunk).unwrap();
        assert_eq!(object.id, array::<32>(&case["id"]), "{name}");
        assert_eq!(object.digest, array::<32>(&case["digest"]), "{name}");
        assert_eq!(object.locator.to_vec(), bytes(&case["locator"]), "{name}");
        let object_key = keys.object_key(&object.id);
        assert_eq!(*object_key, array::<32>(&case["object_key"]), "{name}");
        assert_eq!(
            read_object_with_key_chunked(
                &object.bytes,
                &space(),
                &object_key,
                &object.locator,
                chunk
            ),
            Ok(plaintext.clone()),
            "{name}"
        );
        assert_eq!(object.header, bytes(&case["header"]), "{name}");
        assert_eq!(object.bytes, bytes(&case["bytes"]), "{name}");
        let chunks = case["chunks"].as_array().unwrap();
        assert_eq!(object.chunks.len(), chunks.len(), "{name}");
        for (sealed, row) in object.chunks.iter().zip(chunks) {
            assert_eq!(Some(sealed.index), row["index"].as_u64());
            assert_eq!(sealed.aad, bytes(&row["aad"]));
            assert_eq!(sealed.nonce.to_vec(), bytes(&row["nonce"]));
            assert_eq!(sealed.sealed, bytes(&row["sealed"]));
        }
        assert_eq!(
            read_object_chunked(&object.bytes, &space(), Some(&key), &object.locator, chunk),
            Ok(plaintext)
        );
    }
}

#[test]
fn object_refusals() {
    let rows = family("object_refusals");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 9);
    let key = state_key(&["A"]);
    for row in rows {
        let name = text(&row["name"]);
        let chunk = row["chunk_bytes"].as_u64().unwrap() as usize;
        let locator: [u8; 64] = array(&row["locator"]);
        let held = (name != "a state this reader lacks").then_some(&key);
        let read = read_object_chunked(&bytes(&row["bytes"]), &space(), held, &locator, chunk);
        assert_eq!(class_name(read), text(&row["class"]), "{name}");
    }
}

#[test]
fn hex_round_trips() {
    // The vectors' hex is lowercase, as the testkit writes it.
    assert_eq!(
        hex::encode(system()),
        text(&family("system_stream")["stream"])
    );
}

// ---------------------------------------------------------------------------
// supersessions

#[test]
fn supersessions() {
    let f = family("supersessions");
    for name in ["log_unit", "snapshot_unit"] {
        let case = &f[name];
        let unit = Unit::check_at_peer(&bytes(&case["signed"])).unwrap();
        assert_eq!(unit.id(), id(&case["id"]), "{name}");
        assert_eq!(unit.body.encode(), bytes(&case["body"]), "{name}");
        let shown: Vec<Vec<Vec<u8>>> = unit
            .body
            .supersedes
            .iter()
            .map(|s| {
                let mut parts = vec![s.successor.to_vec()];
                parts.extend(s.listing.map(|listing| listing.to_vec()));
                parts.push(s.predecessor.to_vec());
                parts
            })
            .collect();
        let expected: Vec<Vec<Vec<u8>>> = case["supersedes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_array().unwrap().iter().map(bytes).collect())
            .collect();
        assert_eq!(shown, expected, "{name}");
    }
    for case in f["refusals"].as_array().unwrap() {
        let refused = class_name(Unit::check_at_peer(&bytes(&case["signed"])));
        assert_eq!(refused, text(&case["class"]), "{}", text(&case["name"]));
    }
}
