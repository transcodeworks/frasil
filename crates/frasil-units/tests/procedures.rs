//! `units.json`: `compaction`, `stub_confirmation`, `statement_outcomes`,
//! `settled` and `partial_replica` (units.md, sections 3.5, 3.6, 3.9, 3.13
//! and 3.15).

mod common;

use common::*;
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, Placement};
use frasil_units::body::{Compacts, Cover, Stub};
use frasil_units::compaction::{boundary_stubs, check_stub, cover_set, covers};
use frasil_units::decisions::{
    PartialVerdict, StatementOutcome, StubDecision, confirm_stub, partial_verdict, settled,
    statement_outcome,
};
use frasil_units::unit::Unit;
use frasil_units::{StreamId, UnitClass};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

fn stub(value: &Json) -> Stub {
    let items = value.as_array().unwrap();
    Stub {
        id: id(&items[0]),
        author: DeviceId(array(&items[1])),
        seq: items[2].as_u64().unwrap(),
        height: items[3].as_u64().unwrap(),
        kind: items[4].as_u64().unwrap() as u8,
        stream: items.get(5).map(array::<16>),
        // The vectors' stubs are of events that declare no cuts.
        cuts: frasil_events::Cuts::NONE,
    }
}

/// A log of the genesis and these events, each placed.
fn log_of(genesis: &Event, events: &[&Event]) -> Log {
    let mut log = Log::new(genesis.clone()).unwrap();
    for event in events {
        assert!(matches!(
            log.place((*event).clone()).unwrap(),
            Placement::Placed(_)
        ));
    }
    log
}

#[test]
fn compaction() {
    let f = family("compaction");
    let rows = f["events"].as_array().unwrap();
    let mut events: BTreeMap<String, Event> = BTreeMap::new();
    let mut names: BTreeMap<EventId, String> = BTreeMap::new();
    let mut streams: BTreeMap<EventId, StreamId> = BTreeMap::new();
    let mut order = Vec::new();
    for row in rows {
        let name = text(&row["name"]).to_owned();
        let event = frasil_events::decode(&bytes(&row["signed"])).unwrap();
        assert_eq!(event.id(), id(&row["id"]));
        if let Some(stream) = row["stream"].as_str() {
            let unit = Unit::from_event(event.clone()).unwrap();
            assert_eq!(hex_of(&unit.body.stream), stream);
            streams.insert(event.id(), unit.body.stream);
        }
        names.insert(event.id(), name.clone());
        order.push(name.clone());
        events.insert(name, event);
    }
    let by_name = |name: &str| events[name].id();
    let stream_of = |id: EventId| streams.get(&id).copied();
    let genesis = &events["g"];

    // A full replica's heights and canonical order.
    let all: Vec<&Event> = order[1..].iter().map(|n| &events[n]).collect();
    let full = log_of(genesis, &all);
    for row in rows {
        assert_eq!(
            full.height(id(&row["id"])),
            row["height"].as_u64(),
            "{}",
            text(&row["name"])
        );
    }
    let canonical: Vec<&str> = f["canonical_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    let computed: Vec<&str> = full.canonical().iter().map(|i| names[i].as_str()).collect();
    assert_eq!(computed, canonical);

    // The snapshot unit s by C in stream X, citing b2 and its own c1,
    // computed over the log before it.
    let s = &f["snapshot_unit"];
    let snapshot = Unit::check_at_peer(&bytes(&s["signed"])).unwrap();
    assert_eq!(snapshot.id(), by_name("s"));
    let stream = snapshot.body.stream;
    let parents: Vec<EventId> = s["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| by_name(text(n)))
        .collect();
    let mut sorted = parents.clone();
    sorted.sort_unstable();
    assert_eq!(snapshot.event.parents(), sorted);
    let before: Vec<&Event> = ["a1", "b1", "c1", "a2", "b2", "b3"]
        .iter()
        .map(|n| &events[*n])
        .collect();
    let log = log_of(genesis, &before);
    let declared = covers(&log, stream_of, &parents, &stream);
    let expected: Vec<Cover> = s["covers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| Cover {
            writer: DeviceId(array(&pair["writer"])),
            unit: by_name(text(&pair["unit"])),
        })
        .collect();
    assert_eq!(declared, expected);
    let cover = cover_set(&log, stream_of, &declared, &stream);
    let expected_cover: BTreeSet<EventId> = s["cover"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| by_name(text(n)))
        .collect();
    assert_eq!(cover, expected_cover);
    let stubs = boundary_stubs(&log, &cover, &parents, &[]);
    let expected_stubs: Vec<Stub> = s["stubs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| stub(&row["stub"]))
        .collect();
    let mut sorted_stubs = expected_stubs.clone();
    sorted_stubs.sort_unstable_by_key(|stub| stub.id);
    assert_eq!(stubs, sorted_stubs);
    for row in s["stubs"].as_array().unwrap() {
        assert_eq!(stub(&row["stub"]).id, by_name(text(&row["event"])));
    }

    // The declaration s carries is the one computed.
    let compacts = Compacts {
        object: array(&s["object"]),
        covers: declared.clone(),
        stubs: stubs.clone(),
    };
    assert_eq!(compacts.encode(), bytes(&s["compacts"]));
    assert_eq!(snapshot.body.compacts.as_ref(), Some(&compacts));
    assert!(snapshot.body.objects.contains(&compacts.object));
    let inner = snapshot
        .open_with(&state_key(&["A"]), false, Some(&system()))
        .unwrap();
    let excluded: Vec<EventId> = s["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| by_name(text(n)))
        .collect();
    assert_eq!(inner.excluded, excluded);
    // The stubs match the events they stand for at a full replica.
    for stub in &stubs {
        assert_eq!(check_stub(&full, stub), Ok(()));
    }
    let lied = Stub {
        height: 900,
        ..stubs[0]
    };
    assert_eq!(check_stub(&full, &lied), Err(UnitClass::BadStub));

    // A newcomer that holds g, s, the Y units and a3, and s's stubs for the
    // cover, places them at the full replica's heights; without the stubs
    // they stay pending.
    let newcomer = &f["newcomer"];
    let holds: Vec<&str> = newcomer["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(holds[0], "g");
    let held: Vec<&Event> = holds[1..].iter().map(|n| &events[*n]).collect();

    let mut without = Log::new(genesis.clone()).unwrap();
    for event in &held {
        without.place((*event).clone()).unwrap();
    }
    let mut pending: Vec<&str> = without.pending().map(|e| names[&e.id()].as_str()).collect();
    pending.sort_unstable();
    let expected_pending: Vec<&str> = newcomer["pending_without_stubs"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(pending, expected_pending);

    let mut with = Log::new(genesis.clone()).unwrap();
    for stub in &stubs {
        with.add_stub(stub.event_stub());
    }
    for event in &held {
        with.place((*event).clone()).unwrap();
    }
    assert_eq!(with.pending().count(), 0);
    for (name, height) in newcomer["heights_with_stubs"].as_object().unwrap() {
        assert_eq!(with.height(by_name(name)), height.as_u64(), "{name}");
        assert_eq!(full.height(by_name(name)), height.as_u64(), "{name}");
    }
    assert_eq!(newcomer["agrees_with_full_replica"].as_bool(), Some(true));
}

fn hex_of(bytes: &[u8]) -> String {
    frasil_testkit::hex::encode(bytes)
}

#[test]
fn stub_confirmation() {
    let rows = family("stub_confirmation");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let sources: Vec<(String, Stub)> = row["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| (text(&source[0]).to_owned(), stub(&source[1])))
            .collect();
        let decision = confirm_stub(row["held_in_full"].as_bool().unwrap(), &sources);
        let expected = match decision {
            StubDecision::HeldInFull => "placed: held in full",
            StubDecision::TwoSignersAgree => "placed: two signers agree",
            StubDecision::OneSigner => "pending: one signer",
            StubDecision::StubsDisagree => "pending: stubs disagree",
        };
        assert_eq!(expected, text(&row["decision"]), "{}", text(&row["case"]));
        assert_eq!(decision.placed(), expected.starts_with("placed"));
    }
}

#[test]
fn statement_outcomes() {
    for row in family("statement_outcomes").as_array().unwrap() {
        let missing_for = match (row["first_missing"].as_u64(), row["last_missing"].as_u64()) {
            (Some(first), Some(last)) => last - first,
            _ => 0,
        };
        let outcome = statement_outcome(
            row["peer_serves"].as_bool().unwrap(),
            row["author_supplies"].as_bool().unwrap(),
            row["peer_acknowledged"].as_bool().unwrap(),
            missing_for,
            row["withholding_grace"].as_u64().unwrap(),
        );
        let expected = match outcome {
            StatementOutcome::Consistent => "consistent",
            StatementOutcome::WithheldByPeer => "Withheld, against the peer",
            StatementOutcome::NotReported => "not reported",
            StatementOutcome::BadStatement => "BadStatement, against the statement's author",
        };
        assert_eq!(expected, text(&row["outcome"]));
    }
}

#[test]
fn settled_snapshots() {
    let rows = family("settled");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let reading = |t: u64| Reading {
        timeline: t,
        wall: None,
        run: 1,
    };
    for row in rows {
        let outcome = settled(
            row["stable"].as_bool().unwrap(),
            &reading(row["first_sight"].as_u64().unwrap()),
            &reading(row["now"].as_u64().unwrap()),
            row["gap_key_timeout"].as_u64().unwrap(),
        );
        let expected = if outcome { "Settled" } else { "Unsettled" };
        assert_eq!(expected, text(&row["outcome"]), "{row}");
    }
}

#[test]
fn partial_replica() {
    let rows = family("partial_replica");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        // Its inputs: whether r is proven in u's past, and whether a Path
        // proves u before r.
        let case = text(&row["case"]);
        let r_in_past = row["r_in_u_past_proven"].as_bool().unwrap();
        let u_before = row["u_before_r_proven"].as_bool().unwrap();
        let verdict = match partial_verdict(r_in_past, u_before) {
            PartialVerdict::NotAWriter => "NotAWriter",
            PartialVerdict::Valid => "valid",
            PartialVerdict::Pending => "Pending: order not proven",
        };
        assert_eq!(verdict, text(&row["partial_replica"]), "{case}");
        // A partial replica never applies a unit a full replica refuses.
        let full = text(&row["full_replica"]);
        assert!(verdict != "valid" || full == "valid", "{case}");
    }
}
