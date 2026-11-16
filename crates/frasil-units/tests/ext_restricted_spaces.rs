//! ext-restricted-spaces.json's families of units, with feature
//! `ext-restricted-spaces`:
//!
//! - `move_records`, `move_record_refusals` (sections 2.4 and 3.7): two
//!   records read and written, and six refused;
//! - `late_writes` (section 3.7): a stream with a move unit and late
//!   writes, which units are late, which of them their authors re-apply,
//!   and a re-applied unit with its `copied_from`.
//!
//! It also reads `restricted_keys`, which `frasil-keys` claims, to check a
//! restricted space's unit keys (section 3.2, in place of keys.md's
//! "Reading a unit's key reference").

#![cfg(feature = "ext-restricted-spaces")]

use frasil_adapter::{Adapter, Context, Role, Writer};
use frasil_adapter_records::{Records, State};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::reference::{Lookup, RotationLog};
use frasil_space::Keyring;
use frasil_testkit::hex;
use frasil_units::body::KeyReference;
use frasil_units::ext_restricted_spaces::{
    MoveRecord, RestrictedKeys, late_writes, move_unit, moved_by_snapshot, reapplication_landed,
    reapplied, reapplier,
};
use frasil_units::inner::Inner;
use frasil_units::stream::{Opening, stream_id};
use frasil_units::types;
use frasil_units::unit::UnitKeys;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
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

fn text(value: &Json) -> &str {
    value.as_str().unwrap()
}

#[test]
fn move_records() {
    for case in family("move_records").as_array().unwrap() {
        let record = bytes(&case["record"]);
        let read = MoveRecord::read(&record).unwrap();
        assert_eq!(read.encode(), record, "{}", case["name"]);
        assert_eq!(
            read.name.is_some(),
            text(&case["name"]) == "with a cached name"
        );
        // The same map as a pointer, and in a stream snapshot's `moved`.
        assert_eq!(moved_by_snapshot(Some(&record)), Some(read.clone()));
        assert_eq!(move_unit(types::MOVE, &record), Some(Ok(read)));
    }
}

#[test]
fn move_record_refusals() {
    let cases = family("move_record_refusals");
    assert_eq!(cases.as_array().unwrap().len(), 6);
    for case in cases.as_array().unwrap() {
        let record = bytes(&case["record"]);
        let name = text(&case["name"]);
        let got = MoveRecord::read(&record).map_err(Class::name);
        assert_eq!(got, Err(text(&case["class"])), "{name}");
        // A move unit whose record fails is a content refusal, and a
        // snapshot whose `moved` fails shows no move.
        assert!(matches!(move_unit(types::MOVE, &record), Some(Err(_))));
        assert_eq!(moved_by_snapshot(Some(&record)), None);
    }
}

#[test]
fn late_writes_and_their_reapplication() {
    let f = family("late_writes");
    let original = &f["original"];
    let new = &f["new"];
    assert_eq!(text(&original["type"]), types::RECORDS);
    let p_space = EventId(array(&original["space"]));
    let n_space = EventId(array(&new["space"]));
    let p_opening = Opening::with_salt(types::RECORDS, array(&original["salt"]));
    let n_opening = Opening::with_salt(types::RECORDS, array(&new["salt"]));
    assert_eq!(p_opening.stream(), array(&original["stream"]));
    assert_eq!(n_opening.stream(), array(&new["stream"]));
    assert_eq!(
        stream_id(types::RECORDS, &array(&new["salt"])),
        array(&new["stream"])
    );

    // The move record points at the new stream.
    let record = MoveRecord::read(&bytes(&f["move_record"])).unwrap();
    assert_eq!(record.to_space, n_space);
    assert_eq!(record.to_stream, n_opening.stream());

    let devices: BTreeMap<&str, DeviceId> = f["devices"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, key)| (name.as_str(), DeviceId(array(key))))
        .collect();
    let name_of = |key: &DeviceId| {
        devices
            .iter()
            .find(|(_, k)| *k == key)
            .map(|(n, _)| *n)
            .unwrap()
    };

    // The stream's units, their sealed parts and their causal order.
    let mut ids: Vec<EventId> = Vec::new();
    let mut names: BTreeMap<EventId, &str> = BTreeMap::new();
    let mut authors: BTreeMap<EventId, DeviceId> = BTreeMap::new();
    let mut parents: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    let mut moves = BTreeSet::new();
    let mut inners: BTreeMap<EventId, Inner> = BTreeMap::new();
    for unit in f["units"].as_array().unwrap() {
        let id = EventId(array(&unit["id"]));
        ids.push(id);
        names.insert(id, text(&unit["name"]));
        authors.insert(id, devices[text(&unit["author"])]);
        parents.insert(
            id,
            unit["parents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| EventId(array(p)))
                .collect(),
        );
        let stream = p_opening.stream();
        let inner = Inner::read(&bytes(&unit["inner"]), false, &stream, None).unwrap();
        assert_eq!(inner.opening.as_ref(), Some(&p_opening));
        if let Some(found) = move_unit(&inner.type_, &inner.content) {
            assert_eq!(found, Ok(record.clone()), "the move unit's record");
            moves.insert(id);
        }
        inners.insert(id, inner);
    }
    assert_eq!(moves.len(), 1);
    let precedes = |a: &EventId, b: &EventId| {
        let mut todo = parents[b].clone();
        let mut seen = BTreeSet::new();
        while let Some(x) = todo.pop() {
            if x == *a {
                return true;
            }
            if seen.insert(x) {
                todo.extend(parents[&x].iter().copied());
            }
        }
        false
    };
    let late = late_writes(&ids, &moves, precedes);
    let late_names: Vec<&str> = late.iter().map(|id| names[id]).collect();
    let want: Vec<&str> = f["late"].as_array().unwrap().iter().map(text).collect();
    assert_eq!(late_names, want);
    for unit in f["units"].as_array().unwrap() {
        let id = EventId(array(&unit["id"]));
        assert_eq!(late.contains(&id), unit["late"].as_bool().unwrap());
    }

    // Who re-applies each late write: its author, if it writes in N, and
    // no other device.
    let writers: Vec<DeviceId> = f["writers_of_N"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| devices[text(name)])
        .collect();
    let by_name: BTreeMap<&str, EventId> = names.iter().map(|(id, n)| (*n, *id)).collect();
    let cases = f["reapply"].as_array().unwrap();
    assert_eq!(cases.len(), late.len());
    for case in cases {
        let late_write = by_name[text(&case["late_write"])];
        assert!(late.contains(&late_write));
        let author = authors[&late_write];
        assert_eq!(name_of(&author), text(&case["author"]));
        let got = reapplier(&author, &writers);
        assert_eq!(got.as_ref().map(name_of), case["reapplied_by"].as_str());
    }

    // B re-applies its own late write: the Records adapter's `reapply`,
    // under B's own clock in the new stream, with `copied_from`.
    let done = &f["reapplied"];
    let u3 = EventId(array(&done["copied_from"][1]));
    assert_eq!(names[&u3], text(&done["late_write"]));
    assert_eq!(EventId(array(&done["copied_from"][0])), p_space);
    let records = Records::new();
    let context = Context::new(
        p_space.0,
        p_opening.stream(),
        u3.0,
        authors[&u3].0,
        1,
        1,
        Role::Log,
    );
    let change = records.decode(&inners[&u3].content, &context).unwrap();
    let b = devices[text(&done["by"])];
    let writer = Writer {
        space: n_space.0,
        stream: n_opening.stream(),
        author: b.0,
        seq: 1,
    };
    let content = records
        .reapply(&State::new(), &context, &change, &State::new(), &writer)
        .unwrap();
    assert_eq!(content, bytes(&done["content"]));
    let inner = reapplied(n_opening.clone(), content, p_space, u3);
    assert_eq!(inner.encode(), bytes(&done["inner"]));
    let read = Inner::read(&bytes(&done["inner"]), false, &n_opening.stream(), None).unwrap();
    assert_eq!(read, inner);
    // A device that holds it drops its own re-application of u3.
    assert!(reapplication_landed([&read], &p_space, &u3));
    assert!(!reapplication_landed([&read], &p_space, &EventId([0; 32])));
}

/// A log in which every rotation of the vectors is a rotation, each
/// concurrent with the others.
struct Rotations(BTreeSet<EventId>);

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

#[test]
fn a_restricted_spaces_unit_keys() {
    let f = family("restricted_keys");
    let space = EventId(array(&f["space"]));
    let parent = EventId(array(&f["parent"]));
    let mut own = Keyring::default();
    let mut parent_keys = Keyring::default();
    let mut own_ids = BTreeSet::new();
    let mut parent_ids = BTreeSet::new();
    for rotation in f["rotations"].as_array().unwrap() {
        let id = EventId(array(&rotation["id"]));
        let key = Zeroizing::new(array(&rotation["content"]));
        if text(&rotation["name"]).starts_with('F') {
            own.rotations.insert(id, key);
            own_ids.insert(id);
        } else {
            parent_keys.rotations.insert(id, key);
            parent_ids.insert(id);
        }
    }
    let own_log = Rotations(own_ids);
    let parent_log = Rotations(parent_ids);
    let keys = RestrictedKeys {
        parent,
        own: &own,
        own_log: &own_log,
        parent_keys: &parent_keys,
        parent_log: &parent_log,
    };
    for case in f["keys"].as_array().unwrap() {
        let reference = KeyReference::read(&bytes(&case["key_reference"])).unwrap();
        assert!(matches!(reference, KeyReference::Restricted { .. }));
        let key = keys.key(&space, &reference).unwrap();
        assert_eq!(*key.key, array::<32>(&case["key"]));
        assert!(!key.provisional);
    }
    // In a restricted space, a plain rotation set is Malformed; a reader
    // without P's keys holds the unit Sealed.
    let plain = KeyReference::Set(frasil_keys::RotationSet::single(parent));
    assert_eq!(
        keys.key(&space, &plain).map_err(Class::name).err(),
        Some("Malformed")
    );
    let without = RestrictedKeys {
        parent_keys: &Keyring::default(),
        ..keys
    };
    let reference = KeyReference::read(&bytes(&f["keys"][0]["key_reference"])).unwrap();
    assert_eq!(
        without.key(&space, &reference).map_err(Class::name).err(),
        Some("Sealed")
    );
}
