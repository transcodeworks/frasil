//! `units.json`: `stream_snapshot`, `space_snapshot`, `head_statements`
//! and `messages` (units.md, sections 2.9, 2.11, 2.13, 2.14, 3.10, 3.13 and
//! 3.14).

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_crypto::device::KeyRing;
use frasil_crypto::labels::{HEAD_STATEMENT, SPACE_SNAPSHOT};
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::schemes::Signer;
use frasil_events::{EventId, verify_proof};
use frasil_units::UnitError;
use frasil_units::messages::{Received, SyncMessage, check_path};
use frasil_units::objects::{read_object, seal_object};
use frasil_units::snapshot::{SpaceSnapshot, StreamSnapshot};
use frasil_units::statement::HeadStatement;
use frasil_units::types;

fn class_name(result: Result<impl Sized, UnitError>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(class) => class.name(),
    }
}

#[test]
fn stream_snapshot() {
    let f = family("stream_snapshot");
    let type_ = text(&f["type"]);
    assert_eq!(type_, types::RECORDS);
    let stream: [u8; 16] = array(&f["stream"]);
    let snapshot = StreamSnapshot {
        type_: type_.to_owned(),
        stream,
        history_free: true,
        state: b"records state".to_vec(),
        moved: None,
    };
    let plaintext = bytes(&f["plaintext"]);
    assert_eq!(snapshot.encode(), plaintext);
    assert_eq!(
        StreamSnapshot::read(&plaintext, &stream, type_),
        Ok(snapshot)
    );

    let key = state_key(&["A"]);
    let object = seal_object(&space(), &key, &key_reference(&["A"]), &plaintext).unwrap();
    assert_eq!(object.id, array::<32>(&f["object_id"]));
    assert_eq!(object.locator.to_vec(), bytes(&f["locator"]));
    assert_eq!(object.bytes, bytes(&f["object"]));
    assert_eq!(
        read_object(&object.bytes, &space(), Some(&key), &object.locator),
        Ok(plaintext)
    );

    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 4);
    for row in refusals {
        let read = StreamSnapshot::read(&bytes(&row["plaintext"]), &stream, type_);
        assert_eq!(
            class_name(read),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
    }
}

#[test]
fn space_snapshot() {
    let f = family("space_snapshot");
    let space_id = id(&f["space"]);
    let sender = signer("A");
    assert_eq!(array::<64>(&f["sender"]), sender.signatory().to_bytes());
    assert_eq!(array::<32>(&f["sender_device_id"]), sender.device_id().0);
    assert_eq!(bytes(&f["sender_mldsa"]), sender.mldsa_public().to_vec());
    assert_eq!(
        bytes(&f["sender_xwing"]),
        sender.keys().xwing().unwrap().to_vec()
    );
    assert_eq!(bytes(&f["tbs_prefix"]), SPACE_SNAPSHOT);
    let signed = bytes(&f["signed"]);
    let ring_of = |signer: &Signer| {
        let mut ring = KeyRing::new();
        ring.add_keys(signer.keys().clone());
        ring
    };
    let senders = ring_of(&sender);

    let read = SpaceSnapshot::read(&signed, &space_id, &senders).unwrap();
    let outcome = |provisional: bool| {
        if provisional {
            "provisional"
        } else {
            "accepted"
        }
    };
    let snapshot = read
        .clone()
        .verified()
        .expect("verified under the sender's keys");
    let outcomes = f["outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 3);
    for row in outcomes {
        let held = text(&row["keys_held"]);
        let keys = if held.starts_with("the sender's") {
            senders.clone()
        } else if held.starts_with("another device's") {
            ring_of(&signer("C"))
        } else {
            assert_eq!(held, "none");
            KeyRing::new()
        };
        let read = SpaceSnapshot::read(&signed, &space_id, &keys).unwrap();
        assert_eq!(outcome(read.is_provisional()), text(&row["outcome"]));
        assert_eq!(read.unverified(), &snapshot);
        // A provisional snapshot never passes for a verified one.
        assert_eq!(read.clone().verified().is_none(), read.is_provisional());
    }

    // The map and the signature, written again.
    assert_eq!(snapshot.encode().unwrap(), bytes(&f["snapshot"]));
    assert_eq!(snapshot.sign(&sender).unwrap(), signed);
    assert_eq!(snapshot.system_stream, array::<16>(&f["system_stream"]));
    assert_eq!(snapshot.lists, vec![bytes(&f["list_event"])]);
    assert_eq!(snapshot.streams.len(), 1);
    assert!(snapshot.streams.iter().all(
        |entry| entry.opening.type_ == types::RECORDS && entry.opening.stream() == entry.stream
    ));

    // The equivocation proof, verified once its events are placed.
    let proof = &f["proof"];
    assert_eq!(snapshot.proofs, vec![bytes(&proof["bytes"])]);
    let shown = verify_proof(&bytes(&proof["bytes"]), &()).unwrap();
    assert_eq!(shown.author.0, array::<32>(&proof["author"]));
    assert_eq!(
        shown.author.0,
        array::<32>(&proof["verify_proof"]["author"])
    );
    assert_eq!(
        Some(shown.fork_seq),
        proof["verify_proof"]["fork_seq"].as_u64()
    );
    assert_eq!(shown.log, id(&proof["verify_proof"]["log"]));
    let events: Vec<EventId> = proof["events"].as_array().unwrap().iter().map(id).collect();
    assert_eq!(events, vec![shown.first.id(), shown.second.id()]);

    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 5);
    for row in refusals {
        let read = SpaceSnapshot::read(&bytes(&row["signed"]), &id(&row["space"]), &senders);
        assert_eq!(
            class_name(read),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
    }
}

#[test]
fn head_statements() {
    let f = family("head_statements");
    let space_id = id(&f["space"]);
    let seed: [u8; 32] = array(&f["seed"]);
    let b = signer("B");
    let device = *b.device_id();
    assert_eq!(ed25519_public(&seed), b.identity_key().0);
    assert_eq!(b.signatory().to_bytes(), array::<64>(&f["device"]));
    assert_eq!(device.0, array::<32>(&f["device_id"]));
    assert_eq!(seed, example("units/device/B"));
    assert_eq!(bytes(&f["tbs_prefix"]), HEAD_STATEMENT);
    let signed = bytes(&f["signed"]);
    let statement = HeadStatement::read(&signed, &space_id, |d| *d == device).unwrap();
    assert_eq!(statement.encode(), bytes(&f["statement"]));
    assert_eq!(statement.streams.len(), 1);
    assert_eq!(statement.sign(&seed), signed);
    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 5);
    for row in refusals {
        let name = text(&row["name"]);
        let member = name != "a device that is not a member";
        let read = HeadStatement::read(&bytes(&row["signed"]), &space_id, |d| {
            member && *d == device
        });
        assert_eq!(class_name(read), text(&row["class"]), "{name}");
    }
}

#[test]
fn messages() {
    let f = family("messages");
    let cases = f["cases"].as_array().unwrap();
    // Types 1 to 17, and type 64, the ignorable type the text defines.
    assert_eq!(cases.len(), 18);
    for (code, case) in (1u64..=17).chain([64]).zip(cases) {
        let data = bytes(&case["bytes"]);
        let Ok(Received::Message(message)) = SyncMessage::read(&data) else {
            panic!("{} does not read", text(&case["name"]));
        };
        assert_eq!(message.space, space());
        assert_eq!(message.message.type_code(), code);
        assert_eq!(case["type"].as_u64(), Some(code));
        assert_eq!(message.message.name(), text(&case["name"]));
        assert_eq!(
            Some(message.message.member_connections_only()),
            case["member_connections_only"].as_bool()
        );
        assert_eq!(message.encode(), data, "{}", text(&case["name"]));
    }
    // A partial replica's `Heads` name its streams, and narrow the answer.
    let partial = &f["partial_heads"];
    let Ok(Received::Message(message)) = SyncMessage::read(&bytes(&partial["bytes"])) else {
        panic!("a partial replica's Heads do not read");
    };
    let named: Vec<[u8; 16]> = partial["streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| bytes(s).try_into().unwrap())
        .collect();
    let frasil_units::messages::Message::Heads { streams, .. } = &message.message else {
        panic!("not Heads");
    };
    assert_eq!(streams, &named);
    assert_eq!(message.encode(), bytes(&partial["bytes"]));
    let system: [u8; 16] = bytes(&partial["system_stream"]).try_into().unwrap();
    let other = [0xee; 16];
    let expected: Vec<bool> = partial["sends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["sent"].as_bool().unwrap())
        .collect();
    let got: Vec<bool> = [None, None, Some(&system), Some(&named[0]), Some(&other)]
        .into_iter()
        .map(|stream| frasil_units::messages::sent_after_heads(stream, streams, Some(&system)))
        .collect();
    assert_eq!(got, expected);
    let ignorable = &f["ignorable"];
    assert_eq!(text(&ignorable["outcome"]), "ignored");
    assert_eq!(
        SyncMessage::read(&bytes(&ignorable["bytes"])),
        Ok(Received::Ignored {
            type_code: ignorable["type"].as_u64().unwrap()
        })
    );
    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 8);
    for row in refusals {
        let read = SyncMessage::read(&bytes(&row["bytes"]));
        assert_eq!(
            class_name(read),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
    }

    // A Path that checks: from the unit naming two objects down to the
    // genesis.
    let path = &f["path"];
    let units = family("units");
    let from = units
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == path["from"])
        .map(|case| frasil_events::decode(&bytes(&case["signed"])).unwrap())
        .expect("the path's first event is a unit of the vectors");
    let events: Vec<_> = path["signed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|signed| frasil_events::decode(&bytes(signed)).unwrap())
        .collect();
    let ids: Vec<EventId> = path["events"].as_array().unwrap().iter().map(id).collect();
    assert_eq!(events.iter().map(|e| e.id()).collect::<Vec<_>>(), ids);
    assert_eq!(
        check_path(&events, &from, id(&path["to"])),
        path["checks"].as_bool().unwrap()
    );
    assert!(!check_path(&events, &from, from.id()));
    assert!(!check_path(&[], &from, id(&path["to"])));
}
