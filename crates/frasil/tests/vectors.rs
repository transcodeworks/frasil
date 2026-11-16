//! The conformance runner: the core vector files replayed through the
//! client's own readers (`frasil::advanced::intake`), the ones every byte another
//! party or the store hands the device goes through first.
//!
//! The protocol crates claim these families and pass them on their own;
//! the client claims none. This runner shows that what the client runs on
//! its intake reaches the same values, verdicts and classes:
//!
//! - events.json: `encodings`, `refusals`;
//! - units.json: `units`, `unit_refusals`, `messages`;
//! - transport.json: `framing`;
//! - at-rest.json: `sealed_device_keys`, `sealed_device_keys_refusals`,
//!   `records`, `record_refusals`, `mark`, `continuity`.

use frasil::advanced::intake::{
    Framed, continuity, open_device_keys, open_mark, open_record, read_event, read_frame,
    read_sync, read_unit, verify_hybrid,
};
use frasil_crypto::device::{DeviceId, KeyRing};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::Signer;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_store::device_keys::KeyKind;
use frasil_store::{Continuity, Head, RestoreMode, StoreKeys};
use frasil_testkit::hex;
use frasil_transport::frame::{ConnectionKind, StreamClass};
use serde_json::Value as Json;
use std::collections::BTreeMap;

fn family(file: &str, name: &str) -> Json {
    frasil_testkit::vectors::family(file, name)
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

fn rows(value: &Json) -> &Vec<Json> {
    value.as_array().expect("an array")
}

fn outcome<T>(result: Result<T, &'static str>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(class) => class,
    }
}

// -- events.json

#[test]
fn events_encodings_and_refusals() {
    for row in rows(&family("events.json", "encodings")) {
        let event = read_event(&bytes(&row["signed"]))
            .unwrap_or_else(|class| panic!("{}: {class}", text(&row["name"])));
        assert_eq!(
            event.id().0,
            array::<32>(&row["id"]),
            "{}",
            text(&row["name"])
        );
        assert_eq!(event.author().0, array::<32>(&row["author"]));
        assert_eq!(event.seq(), row["seq"].as_u64().unwrap());
        assert_eq!(u64::from(event.kind()), row["kind"].as_u64().unwrap());
        assert_eq!(event.event_bytes(), bytes(&row["event"]));
    }
    // The ML-DSA-65 half runs with the founder's keys held, the author of
    // every scheme-2 case, except where the case names others: keys from
    // any source, used only where they hash to the event's `kc`.
    let seeds = family("events.json", "parameters")["identity_seeds"].clone();
    let signer = |name: &str| {
        let seed: [u8; 32] = array(&seeds[name]);
        FixtureKeys::from_identity_seed(&seed).signer()
    };
    let (founder, writer) = (signer("founder"), signer("writer"));
    let ring = |signers: &[&Signer]| {
        let mut ring = KeyRing::new();
        for signer in signers {
            ring.add_keys(signer.keys().clone());
        }
        ring
    };
    let refusals = family("events.json", "refusals");
    for row in rows(&refusals) {
        let name = text(&row["name"]);
        let keys = if name.contains("author's keys are not held") {
            ring(&[&writer])
        } else if name.contains("another device's key, under this device's ed and kc") {
            ring(&[&founder, &writer])
        } else {
            ring(&[&founder])
        };
        assert_eq!(
            outcome(read_event(&bytes(&row["signed"])).and_then(|e| verify_hybrid(&e, &keys))),
            text(&row["error"]),
            "{}",
            text(&row["name"])
        );
    }
}

// -- units.json

/// `example(name)`: SHA-256 of `"frasil spec example/" || name`.
fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The content key of state `{name}` of the unit vectors.
fn state_key(name: &str) -> [u8; 32] {
    let space = EventId(example("units/space"));
    let rotation = EventId(example(&format!("units/rotation/{name}")));
    let key = example(&format!("units/rotation/{name}/content"));
    *state_secret(
        SecretKind::Content,
        &space,
        &RotationSet::single(rotation),
        &[key],
    )
    .unwrap()
}

fn system_stream() -> [u8; 16] {
    let digest = sha256(&[b"units/system-stream (stands for 16 random bytes)"]);
    digest[..16].try_into().unwrap()
}

#[test]
fn units_and_unit_refusals() {
    let system = system_stream();
    for row in rows(&family("units.json", "units")) {
        let key: [u8; 32] = array(&row["state_key"]);
        // A personal space's unit is of its own system stream.
        let system: [u8; 16] = match row.get("personal_system_stream") {
            Some(stream) => array(stream),
            None => system,
        };
        let inner = read_unit(&bytes(&row["signed"]), &key, false, Some(&system))
            .unwrap_or_else(|class| panic!("{}: {class}", text(&row["name"])));
        assert_eq!(
            inner.encode(),
            bytes(&row["inner"]),
            "{}",
            text(&row["name"])
        );
    }
    let key = state_key("A");
    let mut judged = 0;
    for row in rows(&family("units.json", "unit_refusals")) {
        // The one unit over the limit is given by its length alone.
        let Some(signed) = row.get("signed") else {
            continue;
        };
        let name = text(&row["name"]);
        let key = if name == "a seal opened under another state's key" {
            state_key("B")
        } else {
            key
        };
        assert_eq!(
            outcome(read_unit(&bytes(signed), &key, false, Some(&system))),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
        judged += 1;
    }
    assert_eq!(judged, 29);
}

#[test]
fn sync_messages() {
    let messages = family("units.json", "messages");
    for row in rows(&messages["cases"]) {
        let message = read_sync(&bytes(&row["bytes"]))
            .unwrap_or_else(|class| panic!("{}: {class}", text(&row["name"])))
            .expect("a known type");
        assert_eq!(message.message.type_code(), row["type"].as_u64().unwrap());
        assert_eq!(
            message.message.member_connections_only(),
            row["member_connections_only"].as_bool().unwrap()
        );
        assert_eq!(
            message.encode(),
            bytes(&row["bytes"]),
            "{}",
            text(&row["name"])
        );
    }
    assert_eq!(read_sync(&bytes(&messages["ignorable"]["bytes"])), Ok(None));
    for row in rows(&messages["refusals"]) {
        assert_eq!(
            outcome(read_sync(&bytes(&row["bytes"]))),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
    }
}

// -- transport.json

fn class_of(name: &str) -> StreamClass {
    StreamClass::from_name(name).unwrap_or_else(|| panic!("a stream class: {name}"))
}

fn connection_of(name: &str) -> ConnectionKind {
    match name {
        "member" => ConnectionKind::Member,
        "peer" => ConnectionKind::DeviceToPeer,
        "nearby" => ConnectionKind::Nearby,
        other => panic!("a connection: {other}"),
    }
}

#[test]
fn framing() {
    let framing = family("transport.json", "framing");
    for row in rows(&framing["examples"]) {
        let read = read_frame(
            &bytes(&row["frame"]),
            class_of(text(&row["stream"])),
            connection_of(text(&row["connection"])),
        );
        assert!(
            matches!(read, Ok(Framed::Message(_))),
            "{}: {read:?}",
            text(&row["description"])
        );
    }
    for row in rows(&framing["caps"]) {
        let prefix = bytes(&row["prefix"]);
        let read = read_frame(
            &prefix,
            class_of(text(&row["stream"])),
            ConnectionKind::Member,
        );
        let expected = text(&row["result"]);
        match read {
            Ok(Framed::ReadOn) => assert_eq!(expected, "read on"),
            Err(class) => assert_eq!(class, expected),
            other => panic!("a prefix alone reads on or is refused: {other:?}"),
        }
    }
    for row in rows(&framing["refused"]) {
        let read = read_frame(
            &bytes(&row["frame"]),
            class_of(text(&row["stream"])),
            connection_of(text(&row["connection"])),
        );
        assert_eq!(
            outcome(read),
            text(&row["error"]),
            "{}",
            text(&row["description"])
        );
    }
    for row in rows(&framing["dropped"]) {
        let read = read_frame(
            &bytes(&row["frame"]),
            class_of(text(&row["stream"])),
            connection_of(text(&row["connection"])),
        );
        assert_eq!(read, Ok(Framed::Dropped), "{}", text(&row["description"]));
    }
}

// -- at-rest.json

fn store_secret() -> [u8; 32] {
    array(&family("at-rest.json", "device")["keys"]["store_secret"])
}

fn device_id() -> DeviceId {
    DeviceId(array(&family("at-rest.json", "device")["device_id"]))
}

fn key_kind(value: &Json) -> KeyKind {
    KeyKind::from_code(u8::try_from(value.as_u64().unwrap()).unwrap()).unwrap()
}

#[test]
fn sealed_device_keys() {
    for row in rows(&family("at-rest.json", "sealed_device_keys")) {
        let sealed = bytes(&row["sealed"]);
        let keys = open_device_keys(
            &sealed,
            key_kind(&row["key_kind"]),
            &array(&row["key"]),
            &array(&row["person_id"]),
            None,
        )
        .unwrap_or_else(|class| panic!("{}: {class}", text(&row["name"])));
        assert_eq!(keys.device_id().0, array::<32>(&row["device_id"]));
        assert_eq!(keys.plaintext()[..], bytes(&row["plaintext"])[..]);
    }
    for row in rows(&family("at-rest.json", "sealed_device_keys_refusals")) {
        let sealed = bytes(&row["sealed"]);
        // A caller that does not check the person names the header's.
        let person: [u8; 32] = match row["expected_person"].as_str() {
            Some(_) => array(&row["expected_person"]),
            None => sealed[34..66].try_into().unwrap(),
        };
        let device: Option<DeviceId> = row["expected_device"]
            .as_str()
            .map(|_| DeviceId(array(&row["expected_device"])));
        assert_eq!(
            outcome(open_device_keys(
                &sealed,
                key_kind(&row["key_kind"]),
                &array(&row["key"]),
                &person,
                device.as_ref(),
            )),
            text(&row["error"]),
            "{}",
            text(&row["name"])
        );
    }
}

#[test]
fn records_and_refusals() {
    let store = StoreKeys::new(&store_secret());
    let records = family("at-rest.json", "records");
    // Each log's key, from its `log` record.
    let mut log_keys: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    for row in rows(&records) {
        if text(&row["table_name"]) == "log" {
            log_keys.insert(array(&row["item"]), array(&row["opened"]["log_key"]));
        }
    }
    for row in rows(&records) {
        let log = row["log"].as_str().map(|_| {
            let id: [u8; 32] = array(&row["log"]);
            store.log(&id, &log_keys[&id])
        });
        let opened = open_record(
            &store,
            log.as_ref(),
            &bytes(&row["address"]),
            &bytes(&row["record"]),
        )
        .unwrap_or_else(|class| panic!("{}: {class}", text(&row["name"])));
        assert_eq!(
            u64::from(opened.table.code()),
            row["table"].as_u64().unwrap()
        );
        assert_eq!(opened.item, bytes(&row["item"]), "{}", text(&row["name"]));
        assert_eq!(
            *opened.value.encode(),
            bytes(&row["value"]),
            "{}",
            text(&row["name"])
        );
    }
    for row in rows(&family("at-rest.json", "record_refusals")) {
        let log = row["log"].as_str().map(|_| {
            let id: [u8; 32] = array(&row["log"]);
            let key: [u8; 32] = match row["log_key"].as_str() {
                Some(_) => array(&row["log_key"]),
                None => [0; 32],
            };
            store.log(&id, &key)
        });
        assert_eq!(
            outcome(open_record(
                &store,
                log.as_ref(),
                &bytes(&row["address"]),
                &bytes(&row["record"])
            )),
            text(&row["error"]),
            "{}",
            text(&row["name"])
        );
    }
}

#[test]
fn mark_and_continuity() {
    let store = StoreKeys::new(&store_secret());
    let mark = family("at-rest.json", "mark");
    assert_eq!(
        open_mark(
            &store,
            &DeviceId(array(&mark["device_id"])),
            &bytes(&mark["mark"])
        ),
        Ok((
            array(&mark["store_id"]),
            mark["generation"].as_u64().unwrap()
        ))
    );
    for row in rows(&mark["refusals"]) {
        assert_eq!(
            outcome(open_mark(
                &store,
                &DeviceId(array(&row["device_id"])),
                &bytes(&row["mark"])
            )),
            text(&row["error"]),
            "{}",
            text(&row["name"])
        );
    }
    for row in rows(&family("at-rest.json", "continuity")) {
        let mode = RestoreMode::from_name(text(&row["mode"])).unwrap();
        let head = row["head_generation"].as_u64().map(|generation| Head {
            generation,
            ..Head::new(array(&row["head_store_id"]))
        });
        let slot = row["mark"].as_str().map(|_| bytes(&row["mark"]));
        let found = continuity(&store, &device_id(), mode, head.as_ref(), slot.as_deref());
        let expected = match text(&row["outcome"]) {
            "Current" => Continuity::Current,
            _ => Continuity::Restored,
        };
        assert_eq!(found, expected, "{}", text(&row["name"]));
    }
}
