//! `ext-file-versions.json`: what a writer and a replica do with
//! supersessions, as `claims.txt` lists them.

#![cfg(feature = "ext-file-versions")]

use frasil_adapter::{Adapter, Context, EventId, Locator, Role, StreamUnit, Supersession};
use frasil_adapter_blobs::versions::{
    compaction_due, default_compaction_interval, supersedes_hold, supersessions_for,
};
use frasil_adapter_blobs::{Blobs, BlobsClass, Handle, State};
use frasil_base::errors::Class;
use frasil_base::time::{Reading, Timer};
use frasil_testkit::{hex, vectors};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const FILE: &str = "ext-file-versions.json";
const SPACE: [u8; 32] = [0x5a; 32];
const STREAM: [u8; 16] = [0x57; 16];

fn locator(value: &Value) -> Locator {
    hex::decode_array(value.as_str().unwrap()).unwrap()
}

fn event(value: &Value) -> EventId {
    hex::decode_array(value.as_str().unwrap()).unwrap()
}

fn handle(value: &str) -> Handle {
    hex::decode_array(value).unwrap()
}

fn supersession(value: &Value) -> Supersession {
    match value.as_array().unwrap().as_slice() {
        [successor, predecessor] => Supersession {
            successor: locator(successor),
            listing: None,
            predecessor: locator(predecessor),
        },
        [successor, listing, predecessor] => Supersession {
            successor: locator(successor),
            listing: Some(event(listing)),
            predecessor: locator(predecessor),
        },
        other => panic!("not a supersession: {other:?}"),
    }
}

fn supersessions(value: &Value) -> Vec<Supersession> {
    value.as_array().unwrap().iter().map(supersession).collect()
}

fn shown(supersession: &Supersession) -> Value {
    let mut out = vec![hex::encode(supersession.successor)];
    out.extend(supersession.listing.map(hex::encode));
    out.push(hex::encode(supersession.predecessor));
    json!(out)
}

fn shown_all(items: &[Supersession]) -> Value {
    json!(items.iter().map(shown).collect::<Vec<_>>())
}

fn sigma(state: &State) -> Value {
    json!(
        state
            .versions()
            .set()
            .iter()
            .map(|(listing, predecessor, successor)| {
                [
                    hex::encode(listing),
                    hex::encode(predecessor),
                    hex::encode(successor),
                ]
            })
            .collect::<Vec<_>>()
    )
}

fn superseded(state: &State) -> Value {
    let map: BTreeMap<String, Vec<String>> = state
        .superseded()
        .iter()
        .map(|(entry, successors)| {
            (
                hex::encode(entry),
                successors.iter().map(hex::encode).collect(),
            )
        })
        .collect();
    json!(map)
}

/// The stream's units by name, with their authors.
fn units() -> Vec<(String, StreamUnit)> {
    let family: Value = vectors::family(FILE, "writer");
    family["units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let author = family["devices"][row["author"].as_str().unwrap()].clone();
            (row["name"].as_str().unwrap().to_owned(), unit(row, &author))
        })
        .collect()
}

fn unit(row: &Value, author: &Value) -> StreamUnit {
    let objects: Vec<Locator> = row["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(locator)
        .collect();
    let context = Context::new(
        SPACE,
        STREAM,
        event(&row["id"]),
        event(author),
        1,
        1,
        Role::Log,
    )
    .with_objects(objects)
    .with_supersedes(supersessions(&row["supersedes"]));
    StreamUnit {
        context,
        content: hex::decode(row["content"].as_str().unwrap()).unwrap(),
        valid: true,
    }
}

fn applied(order: impl IntoIterator<Item = StreamUnit>) -> State {
    let units: Vec<StreamUnit> = order.into_iter().collect();
    Blobs::new().rebuild(None, &units).unwrap()
}

fn all() -> State {
    applied(units().into_iter().map(|(_, unit)| unit))
}

#[test]
fn parameters() {
    let p: Value = vectors::family(FILE, "parameters");
    assert_eq!(p["max_supersessions"], 4096);
    assert_eq!(p["classes"], json!([BlobsClass::BadSupersession.name()]),);
    let settings = [
        ("file_version_retention", Timer::FileVersionRetention),
        (
            "version_compaction_interval",
            Timer::VersionCompactionInterval,
        ),
    ];
    for (name, timer) in settings {
        let spec = timer.spec();
        assert_eq!(p[name]["default"].as_u64(), spec.default, "{name}");
        assert_eq!(p[name]["min"].as_u64(), spec.minimum, "{name}");
        assert_eq!(p[name]["max"].as_u64(), spec.maximum, "{name}");
    }
    assert_eq!(
        p["version_compaction_interval"]["default"].as_u64(),
        Some(default_compaction_interval())
    );
}

#[test]
fn writer() {
    let family: Value = vectors::family(FILE, "writer");
    let handles = family["handles"].as_object().unwrap();
    let mut state = State::new();
    let blobs = Blobs::new();
    for row in family["units"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        if let Some(parents) = row.get("parents") {
            let parents: Vec<Handle> = parents
                .as_array()
                .unwrap()
                .iter()
                .map(|parent| handle(handles[parent.as_str().unwrap()].as_str().unwrap()))
                .collect();
            let successor = locator(&family["objects"][row["object"].as_str().unwrap()]);
            let derived = supersessions_for(&state, &parents, successor);
            assert_eq!(shown_all(&derived), row["supersedes"], "{name}");
        }
        let author = family["devices"][row["author"].as_str().unwrap()].clone();
        blobs.receive(&mut state, &unit(row, &author));
    }
}

#[test]
fn replica_checks() {
    let cases: Vec<Value> = vectors::family(FILE, "replica_checks");
    let blobs = Blobs::new();
    let author = json!(hex::encode([1u8; 32]));
    for case in &cases {
        let what = case["name"].as_str().unwrap();
        let state = if case.get("state").is_some() {
            let bytes = hex::decode(case["state"].as_str().unwrap()).unwrap();
            let mut state = blobs.load(&bytes).unwrap();
            blobs.load_supersedes(&mut state, &supersessions(&case["supersedes"]));
            state
        } else {
            let id = case["reports"][0]["unit"].clone();
            let mut row = case.clone();
            row["id"] = id;
            applied([unit(&row, &author)])
        };
        let reports = state.versions().reports();
        assert_eq!(reports.len(), case["reports"].as_array().unwrap().len());
        for (report, expected) in reports.iter().zip(case["reports"].as_array().unwrap()) {
            assert_eq!(
                shown(&report.supersession),
                expected["supersession"],
                "{what}"
            );
            assert_eq!(expected["class"], BlobsClass::BadSupersession.name());
            match report.unit {
                Some(id) => assert_eq!(json!(hex::encode(id)), expected["unit"], "{what}"),
                None => assert_eq!(expected["unit"], "snapshot", "{what}"),
            }
        }
        let entries: Vec<String> = state.current().map(|(h, _)| hex::encode(h)).collect();
        assert_eq!(json!(entries), case["entries_after"], "{what}");
        assert_eq!(sigma(&state), case["supersession_set"], "{what}");
    }
}

#[test]
fn supersession_set() {
    let family: Value = vectors::family(FILE, "supersession_set");
    let by_name: BTreeMap<String, StreamUnit> = units().into_iter().collect();
    let mut states = Vec::new();
    for order in family["orders"].as_array().unwrap() {
        let state = applied(
            order
                .as_array()
                .unwrap()
                .iter()
                .map(|name| by_name[name.as_str().unwrap()].clone()),
        );
        assert_eq!(sigma(&state), family["after_all"]["supersession_set"]);
        assert_eq!(superseded(&state), family["after_all"]["superseded"]);
        states.push(state.to_bytes(false));
    }
    assert!(states.windows(2).all(|pair| pair[0] == pair[1]));
    // A successor's handle removed: what it replaced is a head again.
    let author = vectors::family::<Value>(FILE, "writer")["devices"]["A"].clone();
    let removal = unit(&family["after_removal"]["removed"], &author);
    let state = applied(units().into_iter().map(|(_, unit)| unit).chain([removal]));
    assert_eq!(sigma(&state), family["after_removal"]["supersession_set"]);
    assert_eq!(superseded(&state), family["after_removal"]["superseded"]);
}

#[test]
fn compaction() {
    let family: Value = vectors::family(FILE, "compaction");
    let first = &family["first"];
    let blobs = Blobs::new();
    let state = all();
    let compaction = blobs.compact(&state);
    assert_eq!(shown_all(&compaction.supersedes), first["supersedes"]);
    let objects: Vec<String> = compaction.objects.iter().map(hex::encode).collect();
    assert_eq!(json!(objects), first["objects"]);
    assert_eq!(superseded(&state), first["superseded"]);
    assert_eq!(
        hex::encode(&compaction.state),
        first["state"].as_str().unwrap()
    );

    // A second compaction, over a cover that starts from the first.
    let second = &family["second"];
    let mut loaded = blobs.load(&compaction.state).unwrap();
    blobs.load_supersedes(&mut loaded, &compaction.supersedes);
    assert_eq!(sigma(&loaded), second["loaded_supersession_set"]);
    let row = &second["unit"];
    let author = vectors::family::<Value>(FILE, "writer")["devices"]["B"].clone();
    blobs.receive(&mut loaded, &unit(row, &author));
    assert_eq!(superseded(&loaded), second["superseded"]);
    assert_eq!(
        shown_all(&blobs.compact(&loaded).supersedes),
        second["supersedes"]
    );
}

#[test]
fn compaction_checks() {
    let cases: Vec<Value> = vectors::family(FILE, "compaction_checks");
    for case in &cases {
        let what = case["name"].as_str().unwrap();
        let derived = supersessions(&case["derived"]);
        let (listed, absent) = if case["listed"].is_null() {
            (Vec::new(), true)
        } else {
            let mut listed = supersessions(&case["listed"]);
            listed.sort_unstable();
            (listed, false)
        };
        let outcome = match (supersedes_hold(&derived, &listed), absent) {
            (true, true) => "accepted, nothing loaded",
            (true, false) => "accepted",
            (false, _) => "BadCompaction",
        };
        assert_eq!(case["outcome"], outcome, "{what}");
    }
}

fn reading(value: &Value) -> Option<Reading> {
    value.is_object().then(|| Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    })
}

#[test]
fn cadence() {
    let cases: Vec<Value> = vectors::family(FILE, "cadence");
    for case in &cases {
        let first = reading(&case["first"]);
        let now = reading(&case["now"]).unwrap();
        let due = compaction_due(first.as_ref(), &now, case["interval"].as_u64().unwrap());
        let outcome = if due { "Compact" } else { "Wait" };
        assert_eq!(case["outcome"], outcome, "{}", case["name"]);
    }
}
