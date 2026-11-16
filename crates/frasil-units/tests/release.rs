//! units.md, 3.12, "After a checkpoint", over peers.json's
//! `skeleton_cuts` `release_order`: P restores stream x, anchors, then
//! releases it, the release reaching the restore only through the anchor,
//! and checkpoints. A replica that forgot keeps the release alone, the
//! maximal request, and finds x released as one that kept everything does;
//! had it kept both without the anchor between them, it would read them as
//! concurrent and the restore would win.

mod common;

use common::text;
use frasil_events::{EventId, Log, decode};
use frasil_peers::body::StorageBody;
use frasil_space::Placement;
use frasil_units::late::{self, Standing};
use frasil_units::release::{Request, kept_requests, released};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

fn scenario() -> Json {
    let family: Json = frasil_testkit::vectors::family("peers.json", "skeleton_cuts");
    family["release_order"].clone()
}

/// The history's log, and its events' IDs by name.
fn history(case: &Json) -> (Log, BTreeMap<String, EventId>) {
    let mut log: Option<Log> = None;
    let mut names = BTreeMap::new();
    for event in case["events"].as_array().unwrap() {
        let decoded = decode(&common::bytes(&event["signed"])).expect("the event decodes");
        names.insert(text(&event["name"]).to_owned(), decoded.id());
        match &mut log {
            None => log = Some(Log::new(decoded).expect("a genesis")),
            Some(log) => {
                log.place(decoded).expect("placed");
            }
        }
    }
    (log.expect("a history"), names)
}

fn placement(log: &Log, c: EventId, id: EventId) -> Placement {
    match late::standing(log, c, id) {
        Ok(Standing::Past | Standing::Checkpoint) => Placement::Past,
        Ok(Standing::After) => Placement::After,
        Ok(Standing::Late) => Placement::Late,
        Err(_) => Placement::Pending,
    }
}

#[test]
fn a_replica_that_forgot_keeps_the_maximal_requests_and_agrees() {
    let case = scenario();
    let (log, names) = history(&case);
    let c = names["P checkpoints"];
    let restore = names["P restores x"];
    let release = names["P releases x, after its restore"];
    let bodies: BTreeMap<EventId, StorageBody> = log
        .canonical()
        .into_iter()
        .filter_map(|id| {
            let body = StorageBody::read(log.event(id)?.unverified_body()).ok()?;
            matches!(body, StorageBody::Release { .. } | StorageBody::Restore(_))
                .then_some((id, body))
        })
        .collect();
    assert_eq!(bodies.len(), 2, "the restore and the release");
    let stream = match &bodies[&release] {
        StorageBody::Release { stream } => *stream,
        other => panic!("{other:?}"),
    };
    let want = &case["released"];

    // A replica that kept everything: both in the checkpoint's past, in the
    // order the log gives.
    let all: Vec<Request<'_>> = bodies
        .iter()
        .map(|(&id, body)| Request {
            id,
            body,
            placement: placement(&log, c, id),
            valid: true,
        })
        .collect();
    assert!(all.iter().all(|r| r.placement == Placement::Past));
    let precedes = |a, b| log.precedes(a, b);
    assert_eq!(
        released(&all, &stream, precedes),
        want["kept everything"].as_bool().unwrap()
    );

    // What it keeps when it forgets, found before it drops anything: the
    // release alone, as a peer that truncated holds it.
    let past = log.past(c);
    let kept = kept_requests(
        bodies
            .iter()
            .filter(|(id, _)| past.contains(id))
            .map(|(&id, body)| (id, body)),
        precedes,
    );
    assert_eq!(kept, BTreeSet::from([release]));
    let holds: BTreeSet<EventId> = case["truncated_holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| names[text(n)])
        .collect();
    assert!(holds.contains(&release) && !holds.contains(&restore));

    // A replica that forgot reads no order among what it kept.
    let forgot: Vec<Request<'_>> = all
        .iter()
        .copied()
        .filter(|r| kept.contains(&r.id))
        .collect();
    let unordered = |_, _| false;
    assert_eq!(
        released(&forgot, &stream, unordered),
        want["a replica that forgot"].as_bool().unwrap()
    );
    // Keeping both without the anchor between them would read them as
    // concurrent, and the restore win.
    assert_eq!(
        released(&all, &stream, unordered),
        want["kept every request, ordered from what it holds"]
            .as_bool()
            .unwrap()
    );
}
