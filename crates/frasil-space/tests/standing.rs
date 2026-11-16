//! The replica's side of peers.json's `skeleton_cuts` (peers.md, "Storage
//! events", "Skeleton cuts" and "Erasure"; roster.md, 3.15.2 step 9, 3.15.4
//! and 3.15.7): the standing entries a checkpoint's record gives its cut
//! (`cut`, `absent_administrator`), whether the checkpoint takes effect at a
//! replica once a member that outranks the absent administrator excuses it,
//! and an erasure concurrent with a checkpoint that waits while it can still
//! take effect and is late once it does (`concurrent_request`).
//!
//! A replica that checks twins judges each checkpoint with its skeleton,
//! step 9 comparing the cut's standing entries with the record's; the
//! votes and excuses are read with twins assumed and the record's slots
//! handed in, and with twins checked.

mod common;

use common::space::{Fixture, StandIn};
use common::text;
use frasil_base::errors::Class as _;
use frasil_events::EventId;
use frasil_peers::cut::read_cut;
use frasil_space::checkpoint::StandingEntry;
use frasil_space::{
    CheckpointInputs, Checkpointed, Checkpointing, KeyEventChecks, Limits, Options, OtherLogs,
    RequestState, SlotEntry, Space, Status, Twins, Valid,
};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

fn family() -> Json {
    frasil_testkit::vectors::family("peers.json", "skeleton_cuts")
}

fn options<'a>(fixture: &'a Fixture, others: &'a OtherLogs<'a>, twins: Twins) -> Options<'a> {
    Options {
        keys: &fixture.keys,
        limits: Limits::PROTOCOL,
        others,
        units: &StandIn,
        twins,
        key_checks: KeyEventChecks::Context,
        notices: None,
    }
}

/// The administrator slots of the skeleton of `checkpoint`'s past, as a
/// resolution that checks twins reads them: what its record names in key
/// 13.
fn slots_of(
    fixture: &Fixture,
    others: &OtherLogs<'_>,
    checkpoint: EventId,
) -> BTreeMap<frasil_space::DeviceId, SlotEntry> {
    let mut view = fixture.log.past(checkpoint);
    view.insert(checkpoint);
    Space::resolve_checkpointed(
        &fixture.log,
        Some(&view),
        options(fixture, others, Twins::Skeleton),
        Checkpointing {
            presets: BTreeMap::from([(checkpoint, Status::Valid(Valid::Checkpoint))]),
            world: None,
        },
    )
    .expect("the past resolves")
    .administrator_slots()
}

/// The standing entries of a cut as the vectors write them: `[c, index,
/// maker's name, order, dormant]`.
fn named_standing(
    fixture: &Fixture,
    entries: &[StandingEntry],
) -> BTreeSet<(String, u64, String, u64, u64)> {
    entries
        .iter()
        .map(|entry| {
            (
                frasil_testkit::hex::encode(entry.slot.reference.commitment),
                u64::from(entry.slot.reference.index),
                fixture.event_names[&entry.slot.maker].clone(),
                entry.order,
                entry.dormant,
            )
        })
        .collect()
}

fn vector_standing(standing: &Json) -> BTreeSet<(String, u64, String, u64, u64)> {
    standing
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let e = entry.as_array().unwrap();
            (
                e[0].as_str().unwrap().to_owned(),
                e[1].as_u64().unwrap(),
                e[2].as_str().unwrap().to_owned(),
                e[3].as_u64().unwrap(),
                e[4].as_u64().unwrap(),
            )
        })
        .collect()
}

/// The standing entries the record of the checkpoint's past gives, by a
/// replica that checks twins, are its cut's key 8 byte for byte.
#[test]
fn a_cuts_standing_entries_are_those_its_record_gives() {
    let case = family();
    let fixture = Fixture::new(text(&case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let vector = &case["cut"];
    let cut = fixture.id(text(vector, "name"));
    let checkpoint = fixture.id(text(vector, "checkpoint"));
    let event = fixture.log.event(cut).unwrap();
    assert_eq!(
        frasil_testkit::hex::encode(event.unverified_body()),
        text(vector, "body")
    );
    let carried = read_cut(event).expect("the cut reads").standing;
    let objects = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let judge = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let derived = judge
        .standing_for(&fixture.log.past(checkpoint))
        .expect("the standing of its past");
    assert_eq!(derived, carried);
    // The founder's slot first, then A's, each voting.
    assert_eq!(
        derived
            .iter()
            .map(|e| (e.order, e.dormant))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([(1, 0), (2, 0)])
    );
}

/// `absent_administrator`: four administrators of one rank, ordered by
/// seniority; the one that never returns is excused at a replica only by
/// a senior's removal.
#[test]
fn absent_administrator() {
    let case = family();
    let mut failures = Vec::new();
    for (name, scenario) in case["absent_administrator"].as_object().unwrap() {
        let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
        let others = OtherLogs::none();
        let checkpoint = fixture.id("P checkpoints");
        let cut = fixture.id("P0: cut of P checkpoints");
        let past = fixture.log.past(checkpoint);
        let none = BTreeMap::<EventId, Vec<u8>>::new();
        let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
        let checking = Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options: options(&fixture, &others, Twins::Skeleton),
                objects: &none,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        );
        let derived = checking
            .standing_for(&past)
            .expect("the standing of its past");
        let want = vector_standing(&scenario["standing"]);
        if named_standing(&fixture, &derived) != want {
            failures.push(format!("{name}: derived standing"));
        }
        let carried = read_cut(fixture.log.event(cut).unwrap())
            .expect("the cut reads")
            .standing;
        if carried != derived {
            failures.push(format!("{name}: the cut's key 8"));
        }
        // The replica: the record of the past, its slots handed in.
        let slots = slots_of(&fixture, &others, checkpoint);
        let record = checking.record_for(&past).expect("the record of its past");
        let objects = BTreeMap::from([(checkpoint, record.encode())]);
        let replica = Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options: options(&fixture, &others, Twins::Assumed),
                objects: &objects,
                envelopes: &envelopes,
                slots: Some(&slots),
            },
            None,
        );
        assert_eq!(
            replica.validity(checkpoint),
            Status::Valid(Valid::Checkpoint),
            "{name}"
        );
        let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
        let in_effect = replica.judge(&all).chain.contains(&checkpoint);
        let want = scenario["checkpoint_in_effect_at_a_replica"]
            .as_bool()
            .unwrap();
        if in_effect != want {
            failures.push(format!("{name}: in effect {in_effect}, not {want}"));
        }
        // A replica that checks twins: step 9 holds the cut's standing
        // entries to the record's, and the verdict is the same.
        let skeleton = Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options: options(&fixture, &others, Twins::Skeleton),
                objects: &objects,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        );
        if skeleton.validity(checkpoint) != Status::Valid(Valid::Checkpoint) {
            failures.push(format!(
                "{name}: with twins checked, {:?}",
                skeleton.validity(checkpoint)
            ));
        }
        if skeleton.judge(&all).chain.contains(&checkpoint) != want {
            failures.push(format!("{name}: with twins checked, in effect"));
        }
        // The cut is in effect at the peer's rule over the same events as the
        // vector says.
        let at_peer = skeleton.cut_in_effect(&all, cut);
        if at_peer != scenario["cut_in_effect_at_the_peer"].as_bool().unwrap() {
            failures.push(format!("{name}: the cut in effect {at_peer}"));
        }
        // No checkpoint can still take effect once it has, and none is
        // concurrent with it.
        let undecided = replica.undecided(&all);
        if in_effect && !undecided.is_empty() {
            failures.push(format!("{name}: undecided {undecided:?}"));
        }
        if !in_effect && undecided != BTreeSet::from([checkpoint]) {
            failures.push(format!("{name}: the checkpoint can still take effect"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `concurrent_request`: an erasure concurrent with a checkpoint waits at a
/// replica while the checkpoint can still take effect, is late once it
/// does, and its author signs it again after the checkpoint; the new one is
/// free. The late one is listed for its author's pseudonym.
#[test]
fn an_erasure_concurrent_with_a_checkpoint() {
    let case = family();
    let scenario = &case["concurrent_request"];
    let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
    let others = OtherLogs::none();
    let checkpoint = fixture.id("P checkpoints, without the erasure");
    let erasure = fixture.id("A1 asks for erasure, apart");
    let again = fixture.id("A1 asks for erasure again, after the checkpoint");
    let names: Vec<&str> = scenario["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| text(e, "name"))
        .collect();
    let up_to = |last: &str| -> BTreeSet<EventId> {
        let n = names.iter().position(|&n| n == last).unwrap();
        names[..=n].iter().map(|n| fixture.id(n)).collect()
    };
    let views = [
        (
            "the peer holds the erasure and the cut",
            up_to("P checkpoints, without the erasure"),
        ),
        ("the cut in effect", up_to("A1 votes")),
        ("signed again", up_to(names[names.len() - 1])),
    ];
    let none = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let past = fixture.log.past(checkpoint);
    let record = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &none,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    )
    .record_for(&past)
    .expect("the record of its past");
    let slots = slots_of(&fixture, &others, checkpoint);
    let objects = BTreeMap::from([(checkpoint, record.encode())]);
    let replica = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Assumed),
            objects: &objects,
            envelopes: &envelopes,
            slots: Some(&slots),
        },
        None,
    );
    let show = |state: RequestState| match state {
        RequestState::Late => "Late",
        RequestState::Wait => "Wait",
        RequestState::Free => "Free",
    };
    let mut failures = Vec::new();
    for (name, view) in &views {
        let want = &scenario["states"][*name];
        let got = show(replica.request_state(view, erasure));
        if got != text(want, "erasure") {
            failures.push(format!("{name}: the erasure {got}"));
        }
        if view.contains(&again) {
            let got = show(replica.request_state(view, again));
            if got != text(want, "again") {
                failures.push(format!("{name}: signed again {got}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    // Its author lists the late one, and not the one signed again.
    let all = &views[2].1;
    let author = *fixture.log.event(erasure).unwrap().author();
    let late = replica.late_requests(all, &BTreeSet::from([author]));
    assert_eq!(
        late.iter().map(|l| l.event).collect::<Vec<_>>(),
        vec![erasure]
    );
    assert_eq!(late[0].kind, frasil_peers::body::StorageType::Erase);
    assert!(
        replica
            .late_requests(&views[0].1, &BTreeSet::from([author]))
            .is_empty(),
        "nothing is late before the checkpoint takes effect"
    );
}

/// A replica that checks twins over a scenario's log, with the record
/// objects of `checkpoints`, each the record of its past naming the last
/// checkpoint in effect there, derived in order.
fn with_records(fixture: &Fixture, checkpoints: &[EventId]) -> BTreeMap<EventId, Vec<u8>> {
    let others = OtherLogs::none();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let mut objects = BTreeMap::new();
    for &c in checkpoints {
        let record = Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options: options(fixture, &others, Twins::Skeleton),
                objects: &objects,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        )
        .record_for(&fixture.log.past(c))
        .expect("the record of its past");
        objects.insert(c, record.encode());
    }
    objects
}

/// `late_then_past` (peers.md, "Release and restore"; units.md, 3.12): a
/// release late under the first checkpoint, in the second one's past
/// through its author's chain, counts for nothing under the second: its
/// verdict stays `Late`, its author lists it to sign again, and the stream
/// is not released, at a replica that kept everything and at one that
/// forgot under the second, which keeps no request of that past.
#[test]
fn a_request_late_under_a_checkpoint_stays_late_under_the_next() {
    let case = family();
    let scenario = &case["late_then_past"];
    let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
    let others = OtherLogs::none();
    let c1 = fixture.id("C1: P checkpoints (1)");
    let c2 = fixture.id("A checkpoints (C2)");
    let release = fixture.id("A releases x, apart");
    assert!(
        fixture.log.precedes(release, c2),
        "in the second one's past"
    );
    let objects = with_records(&fixture, &[c1, c2]);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let replica = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = replica.judge(&all);
    assert_eq!(judged.chain, vec![c1, c2]);
    assert_eq!(
        judged.statuses[&release].class().map(|c| c.name()),
        Some("Late")
    );
    assert_eq!(
        replica.placement(&all, release),
        frasil_space::Placement::Late
    );
    assert_eq!(replica.request_state(&all, release), RequestState::Late);
    let author = *fixture.log.event(release).unwrap().author();
    let late = replica.late_requests(&all, &BTreeSet::from([author]));
    assert_eq!(
        late.iter().map(|l| l.event).collect::<Vec<_>>(),
        vec![release]
    );
    let body = frasil_peers::body::StorageBody::read(
        fixture.log.event(release).unwrap().unverified_body(),
    )
    .unwrap();
    let frasil_peers::body::StorageBody::Release { stream } = body else {
        panic!("a release");
    };
    let want = &scenario["released"];
    let requests = [frasil_units::release::Request {
        id: release,
        body: &body,
        placement: replica.placement(&all, release),
        valid: false,
    }];
    let kept_everything =
        frasil_units::release::released(&requests, &stream, |a, b| replica.precedes(a, b));
    assert_eq!(kept_everything, want["kept everything"].as_bool().unwrap());
    // A replica that forgets under the second keeps no request of its past
    // that is late under the first.
    let kept = frasil_units::release::kept_requests(
        [(release, &body)]
            .into_iter()
            .filter(|(id, _)| replica.placement(&all, *id) != frasil_space::Placement::Late),
        |a, b| fixture.log.precedes(a, b),
    );
    assert!(kept.is_empty());
    assert!(!frasil_units::release::released(&[], &stream, |_, _| false));
    assert_eq!(want["truncated"].as_bool(), Some(false));
}

/// `no_slot` (peers.md, "Storage events"): B administers in the roster but
/// the skeleton holds no slot for it. The cut's standing entries are P's and
/// A's, ordered 1 and 2 with no gap, those the record gives, and a replica
/// finds the checkpoint valid.
#[test]
fn an_administrator_without_a_slot_has_no_entry() {
    let case = family();
    let scenario = &case["no_slot"];
    let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
    let others = OtherLogs::none();
    let checkpoint = fixture.id("P checkpoints, B without a slot");
    let cut = fixture.id("P0: cut of P checkpoints, B without a slot");
    let objects = with_records(&fixture, &[checkpoint]);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let replica = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let derived = replica
        .standing_for(&fixture.log.past(checkpoint))
        .expect("the standing of its past");
    assert_eq!(
        named_standing(&fixture, &derived),
        vector_standing(&scenario["standing"])
    );
    let carried = read_cut(fixture.log.event(cut).unwrap())
        .expect("the cut reads")
        .standing;
    assert_eq!(derived, carried);
    assert_eq!(text(scenario, "checkpoint"), "checkpoint");
    assert_eq!(
        replica.validity(checkpoint),
        Status::Valid(Valid::Checkpoint)
    );
}

/// `heard_vote` (peers.md, "Skeleton cuts"): B removes A, its senior, so P's
/// first checkpoint hears A, whose standing entry names its out slot with
/// A1's enrolment, those the record gives; A does not vote and P, its senior,
/// removes it again after the checkpoint, which excuses it; both cuts take
/// effect by the peer's rule over what a replica holds, and both checkpoints
/// by the replicas' own, as the vector's chains say.
#[test]
fn a_heard_member_is_excused_through_its_out_slot() {
    let case = family();
    let scenario = &case["heard_vote"];
    let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
    let others = OtherLogs::none();
    let c1 = fixture.id("P checkpoints (1)");
    let c2 = fixture.id("P checkpoints (2)");
    let cut = fixture.id("P0: cut of P checkpoints (1)");
    let objects = with_records(&fixture, &[c1, c2]);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let replica = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let derived = replica
        .standing_for(&fixture.log.past(c1))
        .expect("the standing of its past");
    let carried = read_cut(fixture.log.event(cut).unwrap())
        .expect("the cut reads")
        .standing;
    assert_eq!(derived, carried, "the record's standing is the cut's");
    let heard: Vec<EventId> = derived.iter().filter_map(|e| e.pseudonym).collect();
    assert_eq!(heard, vec![fixture.id("A1 enrols")], "A's out slot");
    assert_eq!(
        replica.validity(c1),
        Status::Valid(Valid::Checkpoint),
        "the first checkpoint"
    );
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    for name in scenario["chain"].as_array().unwrap() {
        let cut = fixture.id(name.as_str().unwrap());
        assert!(replica.cut_in_effect(&all, cut), "{name}");
    }
    // A replica's own chain: A, heard, votes nothing, and P's removal after
    // the first checkpoint, void at replicas, excuses it there too.
    let chain: Vec<String> = replica
        .judge(&all)
        .chain
        .iter()
        .map(|c| fixture.event_names[c].clone())
        .collect();
    let want: Vec<String> = scenario["replica_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(chain, want, "both checkpoints in effect at a replica");
}

/// `detached` (peers.md, "Skeleton cuts"; roster.md, 3.15.2, step 7): a
/// checkpoint names its cut without citing it; a replica finds it `BadTwin`
/// from its own parents.
#[test]
fn a_checkpoint_that_does_not_cite_its_cut_is_bad_twin() {
    let case = family();
    let scenario = &case["detached"];
    let fixture = Fixture::new(text(scenario, "history_prefix"), &scenario["events"]);
    let others = OtherLogs::none();
    let checkpoint = fixture.id("P checkpoints, naming a cut it does not cite");
    let objects = with_records(&fixture, &[checkpoint]);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let replica = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others, Twins::Skeleton),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let got = match replica.validity(checkpoint) {
        Status::Valid(_) => "valid".to_owned(),
        Status::Void { class, .. } => class.name().to_owned(),
    };
    assert_eq!(got, text(scenario, "checkpoint"));
    // Judged on the checkpoint's past, which does not hold the cut.
    let mut past = fixture.log.past(checkpoint);
    past.insert(checkpoint);
    assert_eq!(
        Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options: options(&fixture, &others, Twins::Skeleton),
                objects: &objects,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        )
        .judge(&past)
        .statuses[&checkpoint]
            .class()
            .map(|c| c.name()),
        Some("BadTwin")
    );
}
