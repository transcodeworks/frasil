//! units.md's parts of checkpoints: stubs that carry cuts (section 2.10),
//! the space snapshot's keys 12 to 14 (sections 2.11 and 3.10), stubs
//! checked against their events (section 3.9), a checkpoint's record object
//! (section 3.3), late units (roster.md, 3.15.1 What follows a checkpoint)
//! and `StaleSeal` after a checkpoint (section 3.2, step 12).
//!
//! `units.json`'s `record_objects`, `stubs_with_cuts` and
//! `snapshot_checkpoint` families are read here; the other tests build
//! their events with the vectors' signers.

mod common;

use common::*;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_crypto::device::KeyRing;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::envelope::Envelope;
use frasil_events::{Cuts, Event, EventId, Log, Placement, decode, kind};
use frasil_units::compaction::{check_stub, stub_of};
use frasil_units::inner::Inner;
use frasil_units::late::{self, LateUnit, Standing};
use frasil_units::snapshot::{SnapshotCheckpoint, SpaceSnapshot};
use frasil_units::{Stub, UnitClass};

/// A signed event of `kind` in `log`, by `signer`.
fn event(
    signer: &Signer,
    kind: u8,
    log: EventId,
    seq: u64,
    prev: Option<EventId>,
    parents: &[EventId],
    cuts: &[EventId],
) -> Event {
    let mut parents = parents.to_vec();
    parents.extend(prev);
    parents.sort();
    parents.dedup();
    let envelope = Envelope {
        kind,
        log: Some(log),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents,
        cuts: cuts.to_vec(),
        body: format!("{kind} {seq}").into_bytes(),
        scheme: if kind == kind::UNIT {
            Scheme::Ed25519
        } else {
            Scheme::Hybrid
        },
    };
    decode(&envelope.sign(signer)).unwrap()
}

fn genesis(signer: &Signer) -> Event {
    let envelope = Envelope {
        kind: kind::SPACE,
        log: None,
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq: 1,
        prev: None,
        parents: Vec::new(),
        cuts: Vec::new(),
        body: b"genesis".to_vec(),
        scheme: Scheme::Hybrid,
    };
    decode(&envelope.sign(signer)).unwrap()
}

/// A chain of three checkpoints by A, each following the one before:
///
/// ```text
/// g <- c1 <- c2 (cuts [c1]) <- c3 (cuts [c2])
/// ```
struct Chain {
    g: Event,
    c1: Event,
    c2: Event,
    c3: Event,
}

fn chain() -> Chain {
    let a = signer("A");
    let g = genesis(&a);
    let log = g.id();
    let c1 = event(&a, kind::SPACE, log, 2, Some(g.id()), &[], &[]);
    let c2 = event(&a, kind::SPACE, log, 3, Some(c1.id()), &[], &[c1.id()]);
    let c3 = event(&a, kind::SPACE, log, 4, Some(c2.id()), &[], &[c2.id()]);
    Chain { g, c1, c2, c3 }
}

/// The vectors' space snapshot, moved to the chain's space.
fn snapshot_of(space: EventId) -> SpaceSnapshot {
    let f = family("space_snapshot");
    let mut snapshot = SpaceSnapshot::decode(&bytes(&f["snapshot"])).unwrap();
    assert_eq!(snapshot.checkpoint, None);
    snapshot.space = space;
    snapshot
}

#[test]
fn a_space_snapshot_names_the_checkpoint_its_record_key_and_its_cut_chain() {
    let h = chain();
    let space = h.g.id();
    let mut snapshot = snapshot_of(space);
    let start = SnapshotCheckpoint {
        checkpoint: h.c3.id(),
        record_key: [0x33; 32],
        // Given in any order; written ascending by event ID.
        cut_chain: vec![h.c2.signed(), h.c1.signed()],
    };
    snapshot.checkpoint = Some(start.clone());
    let encoded = snapshot.encode().unwrap();
    let decoded = SpaceSnapshot::decode(&encoded).unwrap();
    let back = decoded.checkpoint.clone().unwrap();
    assert_eq!(back.checkpoint, h.c3.id());
    assert_eq!(back.record_key, [0x33; 32]);
    let mut ascending = vec![(h.c1.id(), h.c1.signed()), (h.c2.id(), h.c2.signed())];
    ascending.sort();
    assert_eq!(
        back.cut_chain,
        ascending.into_iter().map(|(_, s)| s).collect::<Vec<_>>()
    );
    // What it decodes to encodes to the same bytes.
    assert_eq!(decoded.encode().unwrap(), encoded);
    // Signed and read: the keys survive the signature.
    let sender = signer("A");
    let signed = snapshot.sign(&sender).unwrap();
    let mut ring = KeyRing::new();
    ring.add_keys(sender.keys().clone());
    let read = SpaceSnapshot::read(&signed, &space, &ring)
        .unwrap()
        .verified()
        .unwrap();
    assert_eq!(read.checkpoint, decoded.checkpoint);

    // The newcomer keeps the chain's envelopes, and they order c3's cuts.
    let kept = back.kept_envelopes(&space).unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(back.lacking(&space, &h.c3), Ok(Vec::new()));
    let mut log = Log::new(h.g.clone()).unwrap();
    for event in kept.into_values() {
        assert!(log.keep_envelope(event).unwrap());
    }
    assert!(matches!(log.place(h.c3.clone()), Ok(Placement::Pending(_))));
    // c3 waits for its parent c2 to be placed, but its cuts' reach is
    // read from the kept envelopes.
    assert_eq!(
        frasil_events::cuts::reach(&log, h.c3.cuts()),
        Ok([h.c1.id(), h.c2.id()].into_iter().collect())
    );

    // A chain that lacks c1 names it; one of another space, or a unit, is
    // Malformed; another checkpoint than key 12's is Malformed.
    let short = SnapshotCheckpoint {
        cut_chain: vec![h.c2.signed()],
        ..start.clone()
    };
    assert_eq!(short.lacking(&space, &h.c3), Ok(vec![h.c1.id()]));
    assert_eq!(
        start.kept_envelopes(&EventId([1; 32])),
        Err(ErrorClass::Malformed)
    );
    assert_eq!(start.lacking(&space, &h.c2), Err(ErrorClass::Malformed));
    let unit = event(&signer("B"), kind::UNIT, space, 1, None, &[space], &[]);
    let with_unit = SnapshotCheckpoint {
        cut_chain: vec![unit.signed()],
        ..start.clone()
    };
    assert_eq!(with_unit.kept_envelopes(&space), Err(ErrorClass::Malformed));
    // The genesis is no checkpoint either.
    let with_genesis = SnapshotCheckpoint {
        cut_chain: vec![h.g.signed()],
        ..start
    };
    assert_eq!(
        with_genesis.kept_envelopes(&space),
        Err(ErrorClass::Malformed)
    );
}

#[test]
fn a_checkpoint_with_an_empty_cut_chain_writes_key_14_empty() {
    let h = chain();
    let mut snapshot = snapshot_of(h.g.id());
    snapshot.checkpoint = Some(SnapshotCheckpoint {
        checkpoint: h.c1.id(),
        record_key: [0x44; 32],
        cut_chain: Vec::new(),
    });
    let encoded = snapshot.encode().unwrap();
    let value = cbor::decode(&encoded).unwrap();
    let map = value.as_map().unwrap();
    assert_eq!(map.get(&14), Some(&Value::Array(Vec::new())));
    assert_eq!(SpaceSnapshot::decode(&encoded).unwrap(), snapshot);
    // Key 14 may be absent with key 12: the chain is then empty.
    let mut map = map.clone();
    map.remove(&14);
    let without = Value::Map(map).encode();
    assert_eq!(
        SpaceSnapshot::decode(&without).unwrap().checkpoint,
        snapshot.checkpoint
    );
}

#[test]
fn keys_12_to_14_refusals() {
    let h = chain();
    let snapshot = snapshot_of(h.g.id());
    let base = cbor::decode(&snapshot.encode().unwrap()).unwrap();
    let with = |entries: Vec<(u64, Value)>| {
        let mut map = base.as_map().unwrap().clone();
        for (key, value) in entries {
            map.insert(key, value);
        }
        Value::Map(map).encode()
    };
    let id = |event: &Event| Value::from(event.id().0);
    let signed = |event: &Event| Value::from(event.signed().as_slice());
    let key = Value::from([0x55u8; 32]);
    let mut descending = [h.c1.clone(), h.c2.clone()];
    descending.sort_by_key(|event| std::cmp::Reverse(event.id()));
    let cases: Vec<(&str, Vec<(u64, Value)>)> = vec![
        ("key 13 without key 12", vec![(13, key.clone())]),
        (
            "key 14 without key 12",
            vec![(14, Value::Array(Vec::new()))],
        ),
        ("key 12 without key 13", vec![(12, id(&h.c3))]),
        (
            "a checkpoint of 31 bytes",
            vec![(12, Value::from([1u8; 31])), (13, key.clone())],
        ),
        (
            "a record key of 31 bytes",
            vec![(12, id(&h.c3)), (13, Value::from([1u8; 31]))],
        ),
        (
            "a cut chain that is not an array",
            vec![(12, id(&h.c3)), (13, key.clone()), (14, Value::from(1u64))],
        ),
        (
            "a cut chain entry that is no event",
            vec![
                (12, id(&h.c3)),
                (13, key.clone()),
                (14, Value::Array(vec![Value::from(&b"junk"[..])])),
            ],
        ),
        (
            "a cut chain out of order",
            vec![
                (12, id(&h.c3)),
                (13, key.clone()),
                (14, Value::Array(descending.iter().map(signed).collect())),
            ],
        ),
        (
            "a cut chain entry twice",
            vec![
                (12, id(&h.c3)),
                (13, key.clone()),
                (14, Value::Array(vec![signed(&h.c1), signed(&h.c1)])),
            ],
        ),
        ("key 15", vec![(15, Value::from(1u64))]),
    ];
    for (name, entries) in cases {
        assert_eq!(
            SpaceSnapshot::decode(&with(entries)),
            Err(ErrorClass::Malformed.into()),
            "{name}"
        );
    }
}

#[test]
fn a_space_snapshot_carries_stubs_with_their_cuts_seventh() {
    let h = chain();
    let mut snapshot = snapshot_of(h.g.id());
    let stream = [9; 16];
    let stub = Stub {
        id: EventId([0xab; 32]),
        author: *signer("B").device_id(),
        seq: 2,
        height: 3,
        kind: kind::UNIT,
        stream: Some(stream),
        cuts: Cuts::new(&[h.c1.id()]).unwrap(),
    };
    snapshot.stubs = vec![stub];
    let encoded = snapshot.encode().unwrap();
    let decoded = SpaceSnapshot::decode(&encoded).unwrap();
    assert_eq!(decoded.stubs, vec![stub]);
    let value = cbor::decode(&encoded).unwrap();
    let stubs = value.as_map().unwrap()[&5].as_array().unwrap();
    assert_eq!(stubs[0].as_array().unwrap().len(), 7);
    // A stub with cuts and no stream has six elements, which a space
    // snapshot refuses.
    snapshot.stubs = vec![Stub {
        stream: None,
        ..stub
    }];
    assert_eq!(
        SpaceSnapshot::decode(&snapshot.encode().unwrap()),
        Err(ErrorClass::Malformed.into())
    );
}

/// A unit after a checkpoint, a unit in its past and a late unit:
///
/// ```text
/// g <- p (B, unit) <- c (A, checkpoint) <- after (B, cuts [c])
/// g <- late (C, unit, no cuts)
/// ```
struct Around {
    log: Log,
    c: Event,
    p: Event,
    after: Event,
    late: Event,
}

fn around() -> Around {
    let (a, b, c_) = (signer("A"), signer("B"), signer("C"));
    let g = genesis(&a);
    let log_id = g.id();
    let p = event(&b, kind::UNIT, log_id, 1, None, &[log_id], &[]);
    let c = event(&a, kind::SPACE, log_id, 2, Some(log_id), &[p.id()], &[]);
    let after = event(
        &b,
        kind::UNIT,
        log_id,
        2,
        Some(p.id()),
        &[c.id()],
        &[c.id()],
    );
    let late = event(&c_, kind::UNIT, log_id, 1, None, &[log_id], &[]);
    let mut log = Log::new(g).unwrap();
    for event in [&p, &c, &after, &late] {
        assert!(matches!(
            log.place(event.clone()).unwrap(),
            Placement::Placed(_)
        ));
    }
    Around {
        log,
        c,
        p,
        after,
        late,
    }
}

#[test]
fn a_unit_concurrent_with_the_checkpoint_in_effect_is_late() {
    let h = around();
    let c = h.c.id();
    assert_eq!(late::standing(&h.log, c, c), Ok(Standing::Checkpoint));
    assert_eq!(late::standing(&h.log, c, h.p.id()), Ok(Standing::Past));
    assert_eq!(late::standing(&h.log, c, h.after.id()), Ok(Standing::After));
    assert_eq!(late::standing(&h.log, c, h.late.id()), Ok(Standing::Late));
    assert_eq!(
        late::late_units(&h.log, c),
        vec![LateUnit {
            unit: h.late.id(),
            refused_by: c,
        }]
    );
    // Its class is roster.md's `Late`, final.
    let class = LateUnit::class();
    assert_eq!(frasil_base::errors::Class::name(class), late::LATE);
    assert_eq!(frasil_units::UnitError::from_name(late::LATE), Some(class));
    assert_eq!(
        frasil_base::errors::Class::sort(class),
        frasil_base::errors::Sort::Final
    );
}

#[test]
fn a_writer_resubmits_its_own_late_units_in_canonical_order() {
    let h = around();
    let c = h.c.id();
    let late_units = late::late_units(&h.log, c);
    let writer = *signer("C").device_id();
    assert_eq!(
        late::resubmission_order(&h.log, &writer, &late_units),
        vec![h.late.id()]
    );
    assert!(late::resubmission_order(&h.log, signer("B").device_id(), &late_units).is_empty());
    let original = Inner::new("frasil:records", b"content".to_vec());
    let again = late::resubmission(&original, h.late.id(), false).unwrap();
    assert_eq!(again.type_, original.type_);
    assert_eq!(again.content, original.content);
    assert_eq!(again.resubmits, Some(h.late.id()));
    assert_eq!(again.copied_from, None);
    // A snapshot unit is not re-submitted.
    assert_eq!(late::resubmission(&original, h.late.id(), true), None);
}

#[test]
fn a_stub_whose_cuts_differ_from_its_events_is_a_bad_stub() {
    let h = around();
    let stub = stub_of(&h.log, h.after.id()).unwrap();
    assert_eq!(stub.cuts.as_slice(), &[h.c.id()]);
    assert_eq!(check_stub(&h.log, &stub), Ok(()));
    let without = Stub {
        cuts: Cuts::NONE,
        ..stub
    };
    assert_eq!(check_stub(&h.log, &without), Err(UnitClass::BadStub));
    // The stub as frasil-events places against carries the cuts.
    assert_eq!(stub.event_stub().cuts, stub.cuts);
    // A stub of an event that declares none carries none.
    assert!(stub_of(&h.log, h.late.id()).unwrap().cuts.is_empty());
}

#[test]
fn the_roster_vector_record_object_reads_for_the_roster() {
    // roster.json's `checkpoints`: the record object the checkpoint names,
    // sealed under its own content key, reads as the record it binds.
    let case: serde_json::Value = frasil_testkit::vectors::family("roster.json", "checkpoints");
    let vector = &case["checkpoint"];
    let space = decode(&bytes(&case["events"][0]["signed"])).unwrap().id();
    let name = text(&vector["name"]);
    let checkpoint = case["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| text(&e["name"]) == name)
        .map(|e| id(&e["id"]))
        .unwrap();
    let part = frasil_space::CheckpointPart {
        epoch: vector["epoch"].as_u64().unwrap(),
        digest: array(&vector["digest"]),
        size: vector["size"].as_u64().unwrap(),
        locator: array(&vector["locator"]),
    };
    let objects = std::collections::BTreeMap::from([(part.locator, bytes(&vector["object"]))]);
    let mut keys = frasil_space::Keyring::default();
    let k_r = example(&format!(
        "{}/{name}/content-key",
        text(&case["history_prefix"])
    ));
    keys.rotations
        .insert(checkpoint, zeroize::Zeroizing::new(k_r));
    let none = std::collections::BTreeMap::new();
    let envelopes: std::collections::BTreeMap<EventId, Event> = case["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| decode(&bytes(&e["signed"])).unwrap())
        .map(|event| (event.id(), event))
        .collect();
    let held = frasil_units::record::oracle::OracleRecords {
        space,
        envelopes: &envelopes,
        objects: &objects,
        keys: &keys,
        object_keys: &none,
    };
    use frasil_space::{RecordObject, RecordObjects};
    assert_eq!(
        held.record_object(checkpoint, &part),
        RecordObject::Read(std::sync::Arc::new(
            frasil_space::Record::read_object(&bytes(&vector["record"]), &part).unwrap(),
        ))
    );
    // A newcomer opens it with the object key a snapshot hands it.
    let handed = std::collections::BTreeMap::from([(
        checkpoint,
        frasil_units::record::record_object_key(&k_r, &part.locator),
    )]);
    let empty = frasil_space::Keyring::default();
    let newcomer = frasil_units::record::oracle::OracleRecords {
        keys: &empty,
        object_keys: &handed,
        ..held
    };
    assert_eq!(
        newcomer.record_object(checkpoint, &part),
        RecordObject::Read(std::sync::Arc::new(
            frasil_space::Record::read_object(&bytes(&vector["record"]), &part).unwrap(),
        ))
    );
}

fn self_ref_of(value: &serde_json::Value) -> frasil_keys::SelfRef {
    let raw = bytes(value);
    assert_eq!(raw.len(), 41);
    assert_eq!(raw[0], 0);
    frasil_keys::SelfRef::new(
        frasil_crypto::device::DeviceId(raw[1..33].try_into().unwrap()),
        u64::from_be_bytes(raw[33..].try_into().unwrap()),
    )
}

#[test]
fn record_objects() {
    use frasil_units::objects::{Header, check_stored, read_object};
    use frasil_units::record::{
        RecordBinding, RecordError, RecordKey, read_record_object, record_digest,
        record_object_key, seal_record,
    };
    let f = family("record_objects");
    let space_id = id(&f["space"]);
    assert_eq!(space_id, space());
    let own = self_ref_of(&f["self_ref"]);
    assert_eq!(own.author.0, array::<32>(&f["author"]));
    assert_eq!(Some(own.seq), f["seq"].as_u64());
    assert_eq!(own.encode().to_vec(), bytes(&f["self_ref"]));
    let content_key: [u8; 32] = array(&f["content_key"]);
    let plaintext = bytes(&f["plaintext"]);
    let object = bytes(&f["object"]);
    let locator: [u8; 64] = array(&f["locator"]);

    // Sealed again, byte for byte, with its header the self reference.
    let sealed = seal_record(&space_id, &content_key, own, &plaintext).unwrap();
    assert_eq!(sealed.object.header, bytes(&f["header"]));
    assert_eq!(sealed.object.bytes, object);
    assert_eq!(sealed.binding.locator, locator);
    assert_eq!(sealed.binding.checkpoint, own);
    assert_eq!(
        Header::read(&sealed.object.header)
            .unwrap()
            .self_reference(),
        Some(own)
    );
    let object_key = record_object_key(&content_key, &locator);
    assert_eq!(*object_key, array::<32>(&f["object_key"]));

    // Accepted: a member with the checkpoint's content key, a newcomer with
    // the object key alone, a peer's steps 0 to 4.
    assert_eq!(f["accepted"].as_array().unwrap().len(), 3);
    let binding = RecordBinding {
        checkpoint: own,
        locator,
        size: plaintext.len() as u64,
        digest: record_digest(&plaintext),
    };
    assert_eq!(binding, sealed.binding);
    assert_eq!(
        read_record_object(
            &object,
            &space_id,
            Some(RecordKey::Checkpoint(&content_key)),
            &binding
        ),
        Ok(plaintext.clone())
    );
    assert_eq!(
        read_record_object(
            &object,
            &space_id,
            Some(RecordKey::Object(&object_key)),
            &binding
        ),
        Ok(plaintext.clone())
    );
    assert!(check_stored(&object, &locator).is_ok());

    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 5);
    for row in refusals {
        let name = text(&row["name"]);
        let data = bytes(&row["object"]);
        let want: [u8; 64] = array(&row["locator"]);
        let got = match text(&row["reader"]) {
            "record" => {
                let binding = RecordBinding {
                    checkpoint: self_ref_of(&row["self_ref"]),
                    locator: want,
                    size: plaintext.len() as u64,
                    digest: record_digest(&plaintext),
                };
                match read_record_object(
                    &data,
                    &space_id,
                    Some(RecordKey::Checkpoint(&content_key)),
                    &binding,
                ) {
                    Ok(_) => "accepted",
                    Err(RecordError::BadCheckpoint) => "BadCheckpoint",
                    Err(RecordError::Object(class)) => class_name::<()>(Err(class)),
                }
            }
            "member" => class_name(read_object(&data, &space_id, Some(&content_key), &want)),
            reader => {
                assert_eq!(reader, "peer");
                class_name(check_stored(&data, &want))
            }
        };
        assert_eq!(got, text(&row["class"]), "{name}");
    }
}

fn class_name<T>(result: Result<T, frasil_units::UnitError>) -> &'static str {
    use frasil_base::errors::Class;
    match result {
        Ok(_) => "accepted",
        Err(class) => class.name(),
    }
}

#[test]
fn stubs_with_cuts() {
    use frasil_units::body::{read_compaction_stubs, read_snapshot_stubs};
    use frasil_units::compaction::compare_stub;
    let f = family("stubs_with_cuts");
    let unit = decode(&bytes(&f["unit"])).unwrap();
    assert_eq!(unit.id(), id(&f["unit_id"]));
    let cuts: Vec<EventId> = f["cuts"].as_array().unwrap().iter().map(id).collect();
    assert_eq!(unit.cuts(), cuts.as_slice());

    let reading = f["reading"].as_array().unwrap();
    assert_eq!(reading.len(), 11);
    for row in reading {
        let name = text(&row["name"]);
        let stub = cbor::decode(&bytes(&row["stub"])).unwrap();
        let list = Value::Array(vec![stub.clone()]);
        let read = match text(&row["container"]) {
            "snapshot unit" => read_compaction_stubs(&list),
            container => {
                assert_eq!(container, "space snapshot");
                read_snapshot_stubs(&list)
            }
        };
        let got = match &read {
            Ok(_) => "accepted",
            Err(_) => "Malformed",
        };
        assert_eq!(got, text(&row["class"]), "{name}");
        // What reads writes back to the same bytes.
        if let Ok(stubs) = read {
            assert_eq!(stubs[0].to_value(), stub, "{name}");
        }
    }

    let comparing = f["comparing"].as_array().unwrap();
    assert_eq!(comparing.len(), 5);
    for row in comparing {
        let name = text(&row["name"]);
        let stub = Stub::read(&cbor::decode(&bytes(&row["stub"])).unwrap()).unwrap();
        let height = row["height"].as_u64().unwrap();
        let got = match compare_stub(&stub, &unit, height) {
            Ok(()) => "match",
            Err(class) => {
                assert_eq!(class, UnitClass::BadStub);
                "BadStub"
            }
        };
        assert_eq!(got, text(&row["verdict"]), "{name}");
    }
}

#[test]
fn snapshot_checkpoint() {
    let f = family("snapshot_checkpoint");
    let space_id = id(&f["space"]);
    let sender = signer("A");
    assert_eq!(array::<64>(&f["sender"]), sender.signatory().to_bytes());
    let mut senders = KeyRing::new();
    senders.add_keys(sender.keys().clone());
    let signed = bytes(&f["signed"]);
    let read = SpaceSnapshot::read(&signed, &space_id, &senders).unwrap();
    assert!(!read.is_provisional());
    assert_eq!(text(&f["outcome"]), "accepted");
    let snapshot = read.verified().unwrap();
    assert_eq!(
        snapshot.placed,
        f["placed"]
            .as_array()
            .unwrap()
            .iter()
            .map(id)
            .collect::<Vec<_>>()
    );
    let checkpoint = snapshot.checkpoint.clone().expect("keys 12 to 14");
    assert_eq!(checkpoint.checkpoint, id(&f["checkpoint"]));
    assert_eq!(checkpoint.record_key, array::<32>(&f["record_key"]));
    let chain: Vec<EventId> = f["cut_chain"].as_array().unwrap().iter().map(id).collect();
    let kept = checkpoint.kept_envelopes(&space_id).unwrap();
    assert_eq!(kept.keys().copied().collect::<Vec<_>>(), chain);
    // Written again, byte for byte.
    assert_eq!(snapshot.sign(&sender).unwrap(), signed);
    // Key 15 is written strictly ascending whatever order the writer
    // gives it, so that every reader takes it.
    let mut shuffled = snapshot.clone();
    shuffled.placed.reverse();
    shuffled.placed.extend(snapshot.placed.first().copied());
    assert_eq!(shuffled.sign(&sender).unwrap(), signed);

    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 8);
    for row in refusals {
        let read = SpaceSnapshot::read(&bytes(&row["signed"]), &space_id, &senders);
        assert_eq!(
            class_name(read),
            text(&row["class"]),
            "{}",
            text(&row["name"])
        );
    }
}

#[test]
fn a_late_unit_with_copied_from_is_resubmitted_with_it_and_without_resubmits() {
    let h = around();
    let mut original = Inner::new("frasil:records", b"content".to_vec());
    let copied = frasil_units::inner::CopiedFrom {
        space: EventId([0x51; 32]),
        event: EventId([0x52; 32]),
    };
    original.copied_from = Some(copied);
    let again = late::resubmission(&original, h.late.id(), false).unwrap();
    assert_eq!(again.copied_from, Some(copied));
    assert_eq!(again.resubmits, None);
    assert_eq!(again.content, original.content);
}

#[test]
fn a_unit_after_the_checkpoint_sealed_outside_its_world_is_stale_seal() {
    use frasil_keys::{KeyClass, RotationSet};
    use frasil_units::KeyReference;
    use frasil_units::unit::world_seal;
    let mut h = around();
    let c = h.c.id();
    let log_id = h.log.id();
    // A rotation after the checkpoint, and a unit that has it in its past.
    let d = event(&signer("A"), kind::SPACE, log_id, 3, Some(c), &[], &[c]);
    let after2 = event(
        &signer("B"),
        kind::UNIT,
        log_id,
        3,
        Some(h.after.id()),
        &[d.id()],
        &[c],
    );
    for event in [&d, &after2] {
        assert!(matches!(
            h.log.place(event.clone()).unwrap(),
            Placement::Placed(_)
        ));
    }
    let set = |ids: &[EventId]| KeyReference::Set(RotationSet::new(ids.to_vec()).unwrap());
    let stale = Err(KeyClass::StaleSeal.into());
    // The checkpoint itself, and a rotation after it in the unit's past.
    assert_eq!(world_seal(&h.log, c, &h.after, &set(&[c])), Ok(()));
    assert_eq!(world_seal(&h.log, c, &after2, &set(&[d.id()])), Ok(()));
    // A rotation after it that is not in the unit's past.
    assert_eq!(world_seal(&h.log, c, &h.after, &set(&[d.id()])), stale);
    // A state before the checkpoint, or one the replica does not hold.
    let g = h.log.id();
    assert_eq!(world_seal(&h.log, c, &h.after, &set(&[g])), stale);
    assert_eq!(world_seal(&h.log, c, &after2, &set(&[g, d.id()])), stale);
    assert_eq!(
        world_seal(&h.log, c, &h.after, &set(&[EventId([0x77; 32])])),
        stale
    );
    // A unit that does not follow the checkpoint is not this check's.
    assert_eq!(world_seal(&h.log, c, &h.late, &set(&[g])), Ok(()));
    assert_eq!(world_seal(&h.log, c, &h.p, &set(&[g])), Ok(()));
}

#[test]
fn a_newcomer_fetches_the_genesis_the_cut_chain_and_the_cuts_enrolments() {
    let h = chain();
    let space = h.g.id();
    let start = SnapshotCheckpoint {
        checkpoint: h.c3.id(),
        record_key: [0x33; 32],
        cut_chain: vec![h.c2.signed()],
    };
    let enrolment = EventId([0x0e; 32]);
    let nothing = |_: &EventId| false;
    // Before it holds the checkpoint: the genesis, the checkpoint and the
    // enrolments.
    let mut want = vec![space, h.c3.id(), enrolment];
    want.sort();
    assert_eq!(start.fetches(&space, None, &[enrolment], nothing), Ok(want));
    // With it: what key 14 lacks below it, and what it does not hold.
    let mut want = vec![space, h.c1.id(), enrolment];
    want.sort();
    assert_eq!(
        start.fetches(&space, Some(&h.c3), &[enrolment], nothing),
        Ok(want)
    );
    let held = |id: &EventId| *id == space || *id == enrolment;
    assert_eq!(
        start.fetches(&space, Some(&h.c3), &[enrolment], held),
        Ok(vec![h.c1.id()])
    );
}

#[test]
fn the_sealed_copy_system_state_names_the_forgotten_list_events() {
    // identity.json's `list_checkpoints`, `sealed_copy`: the frasil:system
    // snapshot state that carries a list from its checkpoint on, with key
    // 5, the IDs of the list events its writer forgot (units.md, 2.12).
    let case: serde_json::Value =
        frasil_testkit::vectors::family("identity.json", "list_checkpoints");
    let events = case["events"].as_array().unwrap();
    let by_name = |name: &str| {
        events
            .iter()
            .find(|e| text(&e["name"]) == name)
            .map(|e| id(&e["id"]))
            .unwrap_or_else(|| panic!("no event {name}"))
    };
    let person = id(&events[0]["id"]);
    let copy = &case["sealed_copy"];
    let mut forgotten: Vec<EventId> = copy["forgotten"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| by_name(text(name)))
        .collect();
    forgotten.sort();
    let mut carried: Vec<EventId> = copy["carries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| by_name(text(name)))
        .collect();
    carried.sort();
    let state_bytes = bytes(&copy["system_state"]);
    let state = frasil_units::own::SystemState::read(&state_bytes).unwrap();
    assert_eq!(state.forgotten, vec![(person, forgotten)]);
    let listed: Vec<EventId> = state
        .lists
        .iter()
        .map(|signed| decode(signed).unwrap().id())
        .collect();
    assert_eq!(listed, carried);
    assert!(state.body_keys.is_empty() && state.entries.is_empty());
    // The writer's encoding is the vector's, byte for byte.
    assert_eq!(state.encode().unwrap(), state_bytes);
}

#[test]
fn a_newcomer_fetches_the_cut_its_checkpoint_names_then_the_cuts_enrolments() {
    // peers.json's `skeleton_cuts`: P's checkpoint names its skeleton cut
    // as its twin, and the cut's slots name P0's root and A1's enrolment.
    let case: serde_json::Value = frasil_testkit::vectors::family("peers.json", "skeleton_cuts");
    let event = |name: &str| {
        case["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| text(&e["name"]) == name)
            .map(|e| decode(&bytes(&e["signed"])).unwrap())
            .unwrap_or_else(|| panic!("no event {name}"))
    };
    let space = event("P creates the space").id();
    let checkpoint = event("P checkpoints");
    let cut = event("P0: cut of P checkpoints");
    let mut enrolments = vec![event("P0: root").id(), event("A1 enrols").id()];
    enrolments.sort();
    assert_eq!(frasil_units::snapshot::twin_of(&checkpoint), Some(cut.id()));
    assert_eq!(
        frasil_units::snapshot::cut_enrolments(&cut),
        Some(enrolments.clone())
    );
    assert_eq!(frasil_units::snapshot::cut_enrolments(&checkpoint), None);
    let start = SnapshotCheckpoint {
        checkpoint: checkpoint.id(),
        record_key: [0x44; 32],
        cut_chain: Vec::new(),
    };
    let nothing = |_: &EventId| false;
    // Before the checkpoint: the genesis and the checkpoint.
    let mut want = vec![space, checkpoint.id()];
    want.sort();
    assert_eq!(start.fetches_through(&space, None, None, nothing), Ok(want));
    // With it: the cut it names.
    let mut want = vec![space, cut.id()];
    want.sort();
    assert_eq!(
        start.fetches_through(&space, Some(&checkpoint), None, nothing),
        Ok(want)
    );
    // With the cut: the roots and enrolments its slots name.
    let mut want = enrolments.clone();
    want.push(space);
    want.sort();
    assert_eq!(
        start.fetches_through(&space, Some(&checkpoint), Some(&cut), nothing),
        Ok(want)
    );
    let held = |id: &EventId| *id == space || enrolments.contains(id);
    assert_eq!(
        start.fetches_through(&space, Some(&checkpoint), Some(&cut), held),
        Ok(Vec::new())
    );
    // Another event given as the cut, or a cut without the checkpoint.
    assert_eq!(
        start.fetches_through(&space, Some(&checkpoint), Some(&checkpoint), nothing),
        Err(ErrorClass::Malformed)
    );
    assert_eq!(
        start.fetches_through(&space, None, Some(&cut), nothing),
        Err(ErrorClass::Malformed)
    );
}

fn compare_record_stream(
    data: &[u8],
    space: &EventId,
    key: Option<frasil_units::record::RecordKey<'_>>,
    binding: &frasil_units::record::RecordBinding,
    chunk: usize,
) -> frasil_units::RecordObjectOutcome {
    use frasil_units::objects::{Header, plain_length};
    use frasil_units::{RecordObjectOutcome, RecordObjectReader};
    struct Collect(Vec<u8>);
    impl frasil_space::record_stream::RecordSink for Collect {
        fn feed(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }
    let oracle = frasil_units::record::read_record_object_chunked(data, space, key, binding, chunk);
    let n = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    let header = &data[4..4 + n];
    let mut reader = RecordObjectReader::new_chunked(header, space, key, binding, chunk);
    let mut sink = Collect(Vec::new());
    let mut rest = &data[4 + n..];
    let size = Header::read(header).ok().map(|h| h.size);
    let mut index = 0;
    while !rest.is_empty() {
        let length = size
            .map(|s| plain_length(s, chunk as u64, index) as usize + 40)
            .unwrap_or(rest.len())
            .min(rest.len());
        reader.feed(index, &rest[..length], &mut sink);
        rest = &rest[length..];
        index += 1;
    }
    let got = reader.finish();
    let expected = if frasil_crypto::primitives::sha256(&[data]) != binding.locator[32..] {
        RecordObjectOutcome::NotTheObject
    } else {
        match oracle {
            Ok(plain) => {
                assert_eq!(sink.0, plain);
                RecordObjectOutcome::Opened
            }
            Err(error) => RecordObjectOutcome::Refused(error),
        }
    };
    assert_eq!(got, expected);
    got
}

#[test]
fn record_stream_matches_record_object_vectors() {
    use frasil_units::limits::CHUNK_BYTES;
    use frasil_units::record::{RecordBinding, RecordKey, record_digest};
    let f = family("record_objects");
    let space = id(&f["space"]);
    let key = array::<32>(&f["content_key"]);
    let object_key = array::<32>(&f["object_key"]);
    let binding = RecordBinding {
        checkpoint: self_ref_of(&f["self_ref"]),
        locator: array(&f["locator"]),
        size: bytes(&f["plaintext"]).len() as u64,
        digest: record_digest(&bytes(&f["plaintext"])),
    };
    for opening in [
        None,
        Some(RecordKey::Checkpoint(&key)),
        Some(RecordKey::Object(&object_key)),
    ] {
        compare_record_stream(&bytes(&f["object"]), &space, opening, &binding, CHUNK_BYTES);
    }
    for row in f["refusals"].as_array().unwrap() {
        let binding = RecordBinding {
            checkpoint: if row["self_ref"].is_null() {
                binding.checkpoint
            } else {
                self_ref_of(&row["self_ref"])
            },
            locator: array(&row["locator"]),
            ..binding
        };
        compare_record_stream(
            &bytes(&row["object"]),
            &space,
            Some(RecordKey::Checkpoint(&key)),
            &binding,
            CHUNK_BYTES,
        );
    }
    let roster: serde_json::Value = frasil_testkit::vectors::family("roster.json", "checkpoints");
    let order = &roster["record_object_order"];
    let space = id(&order["space"]);
    let key = array::<32>(&order["content_key"]);
    for row in order["cases"].as_array().unwrap() {
        let binding = RecordBinding {
            checkpoint: self_ref_of(&order["self_reference"]),
            locator: array(&row["locator"]),
            size: row["size"].as_u64().unwrap(),
            digest: array(&row["digest"]),
        };
        for chunk in [CHUNK_BYTES, row["chunk"].as_u64().unwrap() as usize] {
            for opening in [None, Some(RecordKey::Checkpoint(&key))] {
                let got =
                    compare_record_stream(&bytes(&row["object"]), &space, opening, &binding, chunk);
                if text(&row["name"]).contains("cut at a chunk boundary") {
                    assert_eq!(got, frasil_units::RecordObjectOutcome::NotTheObject);
                }
            }
        }
    }
}

#[test]
fn record_stream_checks_later_lengths_before_earlier_opening_faults() {
    use frasil_units::record::{RecordKey, seal_record_chunked};
    use frasil_units::{RecordObjectOutcome, RecordObjectReader};
    struct Discard;
    impl frasil_space::record_stream::RecordSink for Discard {
        fn feed(&mut self, _: &[u8]) {}
    }
    let space = EventId([1; 32]);
    let key = [2; 32];
    let own = frasil_keys::SelfRef::new(frasil_crypto::device::DeviceId([3; 32]), 1);
    let sealed = seal_record_chunked(&space, &key, own, &[7; 513], 256).unwrap();
    let mut chunks: Vec<Vec<u8>> = sealed
        .object
        .chunks
        .iter()
        .map(|c| c.sealed.clone())
        .collect();
    chunks[0][30] ^= 1;
    chunks[2].push(0);
    let mut binding = sealed.binding;
    let mut hash = frasil_units::objects::stored_bytes_hasher(&sealed.object.header).unwrap();
    for chunk in &chunks {
        hash.update(chunk);
    }
    binding.locator[32..].copy_from_slice(&hash.finish());
    for opening in [None, Some(RecordKey::Checkpoint(&key))] {
        let mut reader =
            RecordObjectReader::new_chunked(&sealed.object.header, &space, opening, &binding, 256);
        for (index, chunk) in chunks.iter().enumerate() {
            reader.feed(index as u64, chunk, &mut Discard);
        }
        assert_eq!(
            reader.finish(),
            RecordObjectOutcome::Refused(frasil_units::record::RecordError::Object(
                ErrorClass::Malformed.into()
            ))
        );
    }
    // Missing chunks fetch again even when the digest binds that prefix.
    let mut hash = frasil_units::objects::stored_bytes_hasher(&sealed.object.header).unwrap();
    hash.update(&chunks[0]);
    binding.locator[32..].copy_from_slice(&hash.finish());
    let mut reader =
        RecordObjectReader::new_chunked(&sealed.object.header, &space, None, &binding, 256);
    reader.feed(0, &chunks[0], &mut Discard);
    assert_eq!(reader.finish(), RecordObjectOutcome::NotTheObject);
}

/// Complete object and record verdicts, including faults deferred by the sink.
#[test]
fn streamed_record_verdicts_follow_object_order() {
    use frasil_space::{CheckpointPart, RecordMode, RecordObject, RecordStream};
    use frasil_units::objects::{Header, plain_length};
    use frasil_units::record::{RecordBinding, RecordKey, RecordRead};
    let vectors: serde_json::Value = frasil_testkit::vectors::family("roster.json", "checkpoints");
    let order = &vectors["record_object_order"];
    let space = id(&order["space"]);
    let key = array::<32>(&order["content_key"]);
    for row in order["cases"].as_array().unwrap() {
        let binding = RecordBinding {
            checkpoint: self_ref_of(&order["self_reference"]),
            locator: array(&row["locator"]),
            size: row["size"].as_u64().unwrap(),
            digest: array(&row["digest"]),
        };
        let part = CheckpointPart {
            epoch: 1,
            locator: binding.locator,
            size: binding.size,
            digest: binding.digest,
        };
        let data = bytes(&row["object"]);
        let chunk = row["chunk"].as_u64().unwrap() as usize;
        for mode in [RecordMode::Build, RecordMode::Summary] {
            let read = |data: &[u8]| {
                let n = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
                let header = &data[4..4 + n];
                let size = Header::read(header).unwrap().size;
                let mut reader = frasil_units::RecordObjectReader::new_chunked(
                    header,
                    &space,
                    Some(RecordKey::Checkpoint(&key)),
                    &binding,
                    chunk,
                );
                let mut sink = RecordStream::new(mode);
                let mut rest = &data[4 + n..];
                let mut index = 0;
                while !rest.is_empty() {
                    let length =
                        (plain_length(size, chunk as u64, index) as usize + 40).min(rest.len());
                    reader.feed(index, &rest[..length], &mut sink);
                    rest = &rest[length..];
                    index += 1;
                }
                RecordRead::finish(reader, sink, &part, false).outcome
            };
            let result = read(&data);
            match text(&row["class"]) {
                "ExtensionRequired" => assert!(matches!(result, RecordObject::Extension(_))),
                "ObjectMismatch" if text(&row["name"]).contains("cut at a chunk boundary") => {
                    assert_eq!(result, RecordObject::Missing)
                }
                _ => assert_eq!(result, RecordObject::Refused),
            }
            let mut flipped = data.clone();
            *flipped.last_mut().unwrap() ^= 1;
            assert_eq!(read(&flipped), RecordObject::Missing);
        }
    }
}
