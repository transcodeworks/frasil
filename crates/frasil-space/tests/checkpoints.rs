//! roster.json's `checkpoints` (roster.md, "Checkpoints", "The checkpoint
//! record" and "Rules this replica lacks"): a checkpoint by the founder, an
//! administrator's grant concurrent with it (late once the administrator
//! votes), a unit and a removal after it; the record byte for byte, its
//! digest and its fields read back; the verdicts of a replica that holds
//! everything and of one that holds only the checkpoint and what follows
//! it, which agree; and a roster part of type 3 that holds itself, a
//! concurrent grant and everything after both (`freeze`).

mod common;

#[path = "support/summary.rs"]
mod summary;

use common::space::{Fixture, StandIn};
use common::{array, bytes, family, text};
use frasil_base::errors::Class;
use frasil_events::{EventId, Log, Stub};
use frasil_keys::checkpoint::{Rooted, Side};
use frasil_space::checkpoint_record::digest;
use frasil_space::keygraph::{History, Kind as KeyKind, SpaceHistory};
use frasil_space::{
    CheckpointInputs, Checkpointed, Kept, KeyEventChecks, Limits, Options, OtherLogs, Record,
    ScreenedLog, Space, Status, Twins, Valid,
};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn show(status: &Status) -> String {
    match status {
        Status::Valid(_) => "valid".into(),
        Status::Void { class, .. } => class.name().to_owned(),
    }
}

fn options<'a>(fixture: &'a Fixture, others: &'a OtherLogs<'a>) -> Options<'a> {
    Options {
        keys: &fixture.keys,
        limits: Limits::PROTOCOL,
        others,
        units: &StandIn,
        twins: Twins::Assumed,
        key_checks: KeyEventChecks::Context,
        notices: None,
    }
}

/// The log of a replica that keeps only `held` (and the genesis): every
/// parent it forgot stands as a stub.
fn forgetting_log(full: &Log, held: &BTreeSet<EventId>) -> Log {
    let mut log = Log::new(full.genesis().clone()).unwrap();
    let mut order: Vec<(u64, EventId)> = held
        .iter()
        .map(|&id| (full.height(id).unwrap(), id))
        .collect();
    order.sort_unstable();
    for &(_, id) in &order {
        let event = full.event(id).unwrap();
        for &parent in event.parents() {
            if parent == full.id() || held.contains(&parent) || log.stub(parent).is_some() {
                continue;
            }
            let forgotten = full.event(parent).unwrap();
            log.add_stub(Stub {
                id: parent,
                author: *forgotten.author(),
                seq: forgotten.seq(),
                height: full.height(parent).unwrap(),
                kind: forgotten.kind(),
                cuts: frasil_events::cuts::Cuts::of(forgotten),
            });
        }
        log.place(event.clone()).unwrap();
    }
    log
}

#[test]
fn checkpoints() {
    let case = family("checkpoints");
    let prefix = text(&case, "history_prefix");
    let fixture = Fixture::new(prefix, &case["events"]);
    let others = OtherLogs::none();

    // The roster part binds the record by its size and digest, and the
    // object by its locator.
    let vector = &case["checkpoint"];
    let checkpoint = fixture.id(text(vector, "name"));
    let plaintext = bytes(vector, "record");
    let screened = ScreenedLog::screen(&fixture.log, &fixture.keys, &Limits::PROTOCOL, &others)
        .expect("the genesis opens");
    let part = screened
        .opened(checkpoint)
        .and_then(|opened| opened.checkpoint())
        .expect("a checkpoint")
        .clone();
    assert_eq!(part.digest, array::<32>(vector, "digest"));
    assert_eq!(digest(&plaintext), part.digest);
    assert_eq!(part.size, vector["size"].as_u64().unwrap());
    assert_eq!(part.size, plaintext.len() as u64);
    assert_eq!(part.locator.to_vec(), bytes(vector, "locator"));
    assert_eq!(part.epoch, vector["epoch"].as_u64().unwrap());

    // The record reads back in its one encoding, with the fields the vector
    // gives.
    let record = Arc::new(Record::read_object(&plaintext, &part).expect("the record matches"));
    assert_eq!(record.encode(), plaintext);
    let read = &case["record_read"];
    assert_eq!(record.epoch, read["epoch"].as_u64().unwrap());
    assert_eq!(record.previous, None);
    let members = read["members"].as_array().unwrap();
    assert_eq!(record.members.len(), members.len());
    for (entry, want) in record.members.iter().zip(members) {
        let member = want["member"].as_array().unwrap();
        assert_eq!(entry.member.kind.code(), member[0].as_u64().unwrap());
        assert_eq!(
            frasil_testkit::hex::encode(entry.member.id),
            member[1].as_str().unwrap()
        );
        assert_eq!(entry.level.code(), want["level"].as_u64().unwrap());
        assert_eq!(entry.history.code(), want["history"].as_u64().unwrap());
        let seniority = want["seniority"].as_array().unwrap();
        assert_eq!(entry.seniority.0, seniority[0].as_u64().unwrap());
        assert_eq!(entry.seniority.1, seniority[1].as_u64().unwrap());
        assert_eq!(
            frasil_testkit::hex::encode(entry.seniority.2.0),
            seniority[2].as_str().unwrap()
        );
        assert!(entry.keys.is_some(), "a device member carries its keys");
    }
    let tips: BTreeMap<String, Json> = record
        .tips
        .iter()
        .map(|(author, (seq, id))| {
            (
                frasil_testkit::hex::encode(author.0),
                serde_json::json!([seq, frasil_testkit::hex::encode(id.0)]),
            )
        })
        .collect();
    assert_eq!(
        serde_json::to_value(tips).unwrap(),
        read["tips"],
        "the record's tips"
    );
    assert_eq!(
        record.forks.len(),
        read["forks"].as_object().unwrap().len(),
        "the record's forks"
    );

    // A replica that holds everything.
    let objects: BTreeMap<EventId, Vec<u8>> = BTreeMap::from([(checkpoint, plaintext.clone())]);
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &objects,
        envelopes: &BTreeMap::<EventId, frasil_events::Event>::new(),
        slots: None,
    };
    let full = Checkpointed::new(inputs, None);
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);
    let summaries = summary::Summaries::new(&objects);
    let streamed = Checkpointed::new(
        CheckpointInputs {
            objects: &summaries,
            ..inputs
        },
        None,
    );
    summary::same(&judged, &streamed.judge(&all));
    let effective: Vec<String> = judged
        .chain
        .iter()
        .map(|id| fixture.event_names[id].clone())
        .collect();
    let want: Vec<String> = case["full"]["effective"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(effective, want, "the chain in effect");
    assert_eq!(full.validity(checkpoint), Status::Valid(Valid::Checkpoint));
    let mut failures = Vec::new();
    for (name, want) in case["full"]["verdicts"].as_object().unwrap() {
        let got = show(&judged.statuses[&fixture.id(name)]);
        if got != want.as_str().unwrap() {
            failures.push(format!("full: {name}: {got}, not {want}"));
        }
    }
    // Before the administrator votes, the checkpoint waits for it, and its
    // offline grant stands.
    let vote = fixture.id("A votes");
    let before: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|&id| id != vote && !fixture.log.precedes(vote, id))
        .collect();
    let before_vote = before.clone();
    let early = full.judge(&before);
    assert!(early.chain.is_empty(), "not in effect before the vote");
    assert!(early.statuses[&fixture.id("A grants X, offline")].is_valid());
    let waiting = full.waiting_for(checkpoint, &before);
    assert_eq!(waiting.len(), 1, "it waits for one administrator");
    assert_eq!(
        waiting[0].device.0,
        fixture.log.event(vote).unwrap().author().0
    );
    assert!(full.waiting_for(checkpoint, &all).is_empty());

    // A replica that holds only the checkpoint and what follows it agrees.
    let holds: BTreeSet<EventId> = case["forgot"]["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    let forgetting = forgetting_log(&fixture.log, &holds);
    // The envelopes of the parents it forgot: what the stubs it keeps carry
    // of them for the cuts check (events.md, "Cuts", "A parent held as a
    // stub").
    let kept_envelopes: BTreeMap<EventId, frasil_events::Event> = holds
        .iter()
        .flat_map(|&id| fixture.log.event(id).unwrap().parents().to_vec())
        .filter(|parent| !holds.contains(parent))
        .map(|parent| (parent, fixture.log.event(parent).unwrap().clone()))
        .collect();
    let inputs = CheckpointInputs {
        log: &forgetting,
        envelopes: &kept_envelopes,
        ..inputs
    };
    let forgot = Checkpointed::new(
        inputs,
        Some(Kept {
            checkpoint,
            record: Arc::clone(&record),
        }),
    );
    let mut held = holds.clone();
    held.insert(forgetting.id());
    assert!(Arc::ptr_eq(&record, &forgot.record(checkpoint).unwrap()));
    let mut seeded = Checkpointed::new(inputs, None);
    seeded.seed_records([(checkpoint, Arc::clone(&record))]);
    assert!(Arc::ptr_eq(&record, &seeded.record(checkpoint).unwrap()));
    let judged_forgot = forgot.judge(&held);
    assert_eq!(judged_forgot.chain, vec![checkpoint]);
    for (name, want) in case["forgot"]["verdicts"].as_object().unwrap() {
        let id = fixture.id(name);
        let got = show(&judged_forgot.statuses[&id]);
        if got != want.as_str().unwrap() {
            failures.push(format!("forgot: {name}: {got}, not {want}"));
        }
        if judged_forgot.statuses[&id] != judged.statuses[&id] {
            failures.push(format!("forgot and full differ on {name}"));
        }
    }
    assert_eq!(judged_forgot.roster, judged.roster, "one roster");

    // The key graph rooted at the checkpoint (keys.md, "Keys after a
    // checkpoint"): the same at both replicas, the checkpoint standing as
    // its genesis and the space's genesis taking no part.
    let full_world = full.key_world(&all).expect("a chain in effect");
    let forgot_world = forgot.key_world(&held).expect("a chain in effect");
    assert_eq!(full_world.checkpoint(), checkpoint);
    assert_eq!(forgot_world.checkpoint(), checkpoint);
    let full_space = full_world.resolve(options(&fixture, &others)).unwrap();
    let forgot_space = forgot_world.resolve(options(&fixture, &others)).unwrap();
    let full_keys = SpaceHistory::new(&full_space);
    let forgot_keys = SpaceHistory::new(&forgot_space);
    let (a, b) = (full_keys.key_graph(), forgot_keys.key_graph());
    assert_eq!(History::genesis(&full_keys), checkpoint);
    assert!(!a.events().contains(&fixture.log.id()));
    assert_eq!(a.events(), b.events(), "the world's events");
    assert_eq!(a.valid(), b.valid(), "the world's valid set");
    for kind in [KeyKind::Content, KeyKind::Grant] {
        let current = a.current(kind).expect("a current state");
        assert_eq!(Some(current.clone()), b.current(kind), "{kind:?}");
        assert!(
            current
                .ids()
                .iter()
                .all(|&r| r == checkpoint || fixture.log.precedes(checkpoint, r)),
            "{kind:?}: the current state counts the world's rotations alone"
        );
    }
    // Where events stand, for the rules rooted at it.
    let sides = full.sides(&all).unwrap();
    assert_eq!(sides.side(&checkpoint), Side::Root);
    assert_eq!(sides.side(&fixture.id("A grants X, offline")), Side::Late);
    assert_eq!(sides.side(&fixture.log.id()), Side::Before);
    // A state before it: the world entitles nobody it does not grant with
    // history after it; a kept judgement does.
    let before = frasil_keys::RotationSet::single(fixture.log.id());
    let founder = *full_space
        .world()
        .unwrap()
        .states
        .keys()
        .next()
        .expect("a member of the record");
    let valid: BTreeSet<EventId> = a.valid().clone();
    assert_eq!(
        full_keys.entitled_before(&valid, &founder, &before, None),
        Some(false)
    );
    let mut kept = frasil_keys::checkpoint::KeptState::new(KeyKind::Content, before.clone());
    kept.while_in.insert(founder);
    assert_eq!(
        full_keys.entitled_before(&valid, &founder, &before, Some(&kept)),
        Some(true)
    );
    let root = frasil_keys::RotationSet::single(checkpoint);
    assert_eq!(
        full_keys.entitled_before(&valid, &founder, &root, None),
        None
    );
    // Forgetting keeps the keys of the states before it its retained data
    // is sealed under.
    let plan = frasil_keys::checkpoint::plan_forgetting(
        &sides,
        [before.clone(), root.clone()],
        [],
        |_, state| *state == before,
        |_, _| (BTreeSet::from([founder]), BTreeSet::new()),
    );
    assert_eq!(plan.keep.len(), 1);
    assert_eq!(plan.keep[0].state, before);
    assert!(plan.missing.is_empty());
    // With no chain in effect, no world: the key graph reads the view as
    // it always did.
    assert!(full.key_world(&before_vote).is_none());

    // Without the record object, the checkpoint is held with what follows
    // it, and the rest is judged as if it had not arrived.
    let none: BTreeMap<EventId, Vec<u8>> = BTreeMap::new();
    let lacking = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            objects: &none,
            ..inputs
        },
        None,
    );
    let without = lacking.judge(&all);
    assert_eq!(
        show(&without.statuses[&checkpoint]),
        "Sealed",
        "a checkpoint whose record is missing is held"
    );
    for &id in &all {
        if fixture.log.precedes(checkpoint, id) {
            let got = show(&without.statuses[&id]);
            if got != "Pending" && got != "Sealed" {
                failures.push(format!("lacking: {id:?} after the checkpoint is {got}"));
            }
        }
    }
    let received: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|&id| id != checkpoint && !fixture.log.precedes(checkpoint, id))
        .collect();
    let reference = full.judge(&received);
    for &id in &received {
        if without.statuses[&id] != reference.statuses[&id] {
            failures.push(format!(
                "lacking: {} differs from a replica that never received it",
                fixture.event_names[&id]
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_tampered_record_is_void() {
    let case = family("checkpoints");
    let prefix = text(&case, "history_prefix");
    let fixture = Fixture::new(prefix, &case["events"]);
    let others = OtherLogs::none();
    let checkpoint = fixture.id(text(&case["checkpoint"], "name"));
    // A record object that does not match the digest is BadCheckpoint.
    let mut wrong = bytes(&case["checkpoint"], "record");
    let last = wrong.len() - 1;
    wrong[last] ^= 1;
    let objects: BTreeMap<EventId, Vec<u8>> = BTreeMap::from([(checkpoint, wrong)]);
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &objects,
        envelopes: &BTreeMap::<EventId, frasil_events::Event>::new(),
        slots: None,
    };
    let judge = Checkpointed::new(inputs, None);
    assert_eq!(show(&judge.validity(checkpoint)), "BadCheckpoint");
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    assert!(judge.judge(&all).chain.is_empty(), "it never takes effect");
}

#[test]
fn freeze() {
    let case = &family("checkpoints")["freeze"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let space = Space::resolve(&fixture.log, None, options(&fixture, &others)).unwrap();
    let mut failures = Vec::new();
    for (name, want) in case["verdicts"].as_object().unwrap() {
        let got = show(space.status(fixture.id(name)).unwrap());
        if got != want.as_str().unwrap() {
            failures.push(format!("{name}: {got}, not {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    // A replica that lacks the rule signs nothing more in the log.
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let objects = BTreeMap::<EventId, Vec<u8>>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &objects,
        envelopes: &BTreeMap::<EventId, frasil_events::Event>::new(),
        slots: None,
    };
    assert!(
        Checkpointed::new(inputs, None)
            .judge(&all)
            .needs_later_rules
    );
}

#[test]
fn a_checkpoints_cut_checks_against_its_record_at_a_replica_that_checks_twins() {
    // peers.json's `skeleton_cuts`: P grants A administer, A's pseudonym
    // enrols, and P checkpoints, its pseudonym signing the cut first.
    let case: Json = frasil_testkit::vectors::family("peers.json", "skeleton_cuts");
    let prefix = text(&case, "history_prefix");
    let mut fixture = Fixture::new(prefix, &case["events"]);
    fixture.name_device("P");
    fixture.name_device("A");
    let others = OtherLogs::none();
    let checking = Options {
        twins: Twins::Skeleton,
        ..options(&fixture, &others)
    };
    let checkpoint = fixture.id("P checkpoints");
    let past = fixture.log.past(checkpoint);
    let mut view = past.clone();
    view.insert(checkpoint);
    let space = Space::resolve_checkpointed(
        &fixture.log,
        Some(&view),
        checking,
        frasil_space::Checkpointing {
            presets: BTreeMap::from([(checkpoint, Status::Valid(Valid::Checkpoint))]),
            world: None,
        },
    )
    .unwrap();
    // The skeleton's administrator slots: P's, made by the root, and A's,
    // made by the twin of P's grant, each with its pseudonym enrolled.
    let slots = space.administrator_slots();
    assert_eq!(slots.len(), 2);
    let device = |name: &str| frasil_space::DeviceId(fixture.device_key(name));
    assert_eq!(slots[&device("P")].maker, fixture.id("P0: root"));
    assert_eq!(
        slots[&device("A")].maker,
        fixture.id("P0: twin of P grants A administer")
    );
    assert!(slots.values().all(|slot| slot.pseudonym.len() == 32));

    // The record of its past, with those slots, passes the twin check.
    let objects = BTreeMap::<EventId, Vec<u8>>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: checking,
        objects: &objects,
        envelopes: &BTreeMap::<EventId, frasil_events::Event>::new(),
        slots: None,
    };
    let judge = Checkpointed::new(inputs, None);
    let record = judge.record_for(&past).expect("the record of its past");
    let administrators = frasil_space::checkpoint::record_slots(&record);
    assert_eq!(administrators.len(), 2);
    assert!(administrators.iter().all(Option::is_some));
    let standing = judge.standing_for(&past).expect("the standing of its past");
    assert_eq!(
        space.check_checkpoint_twin(checkpoint, &record, &standing),
        Ok(())
    );
    // Standing entries other than the record's fail it (`BadTwin`).
    let mut swapped = standing.clone();
    swapped[0].order = swapped.len() as u64 + 1;
    assert_eq!(
        space.check_checkpoint_twin(checkpoint, &record, &swapped),
        Err(frasil_peers::PeersClass::BadTwin.into())
    );
    // With its record object, the checkpoint passes its validity in order:
    // its twin, the skeleton cut, by peers.md's checks of a cut (step 7);
    // its record (step 8); the cut against the record (step 9).
    let sealed: BTreeMap<EventId, Vec<u8>> = BTreeMap::from([(checkpoint, record.encode())]);
    let with_object = Checkpointed::new(
        CheckpointInputs {
            objects: &sealed,
            ..inputs
        },
        None,
    );
    assert_eq!(
        with_object.validity(checkpoint),
        Status::Valid(Valid::Checkpoint)
    );
    // A record whose administrator names a slot the cut lacks fails it
    // (`BadTwin`).
    let mut moved = record.clone();
    let slot = moved
        .members
        .iter_mut()
        .find_map(|entry| entry.slot.as_mut())
        .expect("a slot entry");
    slot.index = (slot.index + 1) % 64;
    assert_eq!(
        space.check_checkpoint_twin(checkpoint, &moved, &standing),
        Err(frasil_peers::PeersClass::BadTwin.into())
    );
    // One whose administrators carry no slot entry names no slot of the
    // cut, which step 9 lets pass: it differs from the record of the past,
    // which step 8 refuses first.
    let mut bare = record.clone();
    for entry in &mut bare.members {
        entry.slot = None;
    }
    assert_eq!(
        space.check_checkpoint_twin(checkpoint, &bare, &standing),
        Ok(())
    );
    // A replica that does not check twins names no slot, and passes.
    let assumed = Space::resolve_checkpointed(
        &fixture.log,
        Some(&view),
        options(&fixture, &others),
        frasil_space::Checkpointing {
            presets: BTreeMap::from([(checkpoint, Status::Valid(Valid::Checkpoint))]),
            world: None,
        },
    )
    .unwrap();
    assert!(assumed.administrator_slots().is_empty());
    assert_eq!(
        assumed.check_checkpoint_twin(checkpoint, &bare, &standing),
        Ok(())
    );
}

/// roster.md, "The checkpoint record", reading in order: each refused
/// record with its class.
#[test]
fn record_refusals() {
    let case = family("checkpoints");
    let mut failures = Vec::new();
    for refusal in case["record_refusals"].as_array().unwrap() {
        let name = text(refusal, "name");
        let got = Record::read(&bytes(refusal, "record"))
            .map(|_| "accepted")
            .unwrap_or_else(|class| frasil_space::RosterClass::from(class).name());
        if got != text(refusal, "error") {
            failures.push(format!("{name}: {got}, not {}", text(refusal, "error")));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `extension_required` (roster.md, "The checkpoint record", step 3, and
/// "Reserved record keys"): for a record key 9, a member-entry key 22 and a
/// member type 4, a checkpoint whose record uses it. The record is the one
/// of the checkpoint's past with the vector's change, which its digest
/// binds. A replica that lacks the documents holds the checkpoint as
/// `ExtensionRequired` with the anchor after it, has no chain, never reads
/// the record (so never votes for or cites it), needs a later version, and
/// a newcomer refuses to start from it.
#[test]
fn a_record_of_a_later_document_holds_its_checkpoint() {
    use frasil_base::cbor::{self, Value};
    let cases = &family("checkpoints")["extension_required"];
    let others = OtherLogs::none();
    let mut failures = Vec::new();
    for (name, case) in cases.as_object().unwrap() {
        let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
        let checkpoint = fixture.id("P checkpoints, its record using a later document's key");
        let none = BTreeMap::<EventId, Vec<u8>>::new();
        let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
        let inputs = CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others),
            objects: &none,
            envelopes: &envelopes,
            slots: None,
        };
        // The record of the checkpoint's past, changed as the vector says.
        let past = fixture.log.past(checkpoint);
        let derived = Checkpointed::new(inputs, None)
            .record_for(&past)
            .expect("the record of the past")
            .encode();
        let mut value = cbor::decode(&derived).unwrap();
        let Value::Map(record) = &mut value else {
            panic!("a record is a map");
        };
        match name.as_str() {
            "a record key 9" => {
                record.insert(9, Value::Unsigned(1));
            }
            "a member-entry key 22" => {
                let Some(Value::Array(members)) = record.get_mut(&4) else {
                    panic!("members");
                };
                let Some(Value::Map(entry)) = members.first_mut() else {
                    panic!("a member entry");
                };
                entry.insert(22, Value::Unsigned(1));
            }
            "a member of type 4" => {
                let Some(Value::Array(members)) = record.get_mut(&4) else {
                    panic!("members");
                };
                let mut entry = cbor::Map::new();
                entry.insert(
                    1,
                    Value::Array(vec![Value::Unsigned(4), Value::Bytes(vec![0; 32])]),
                );
                members.push(Value::Map(entry));
            }
            other => panic!("case {other}"),
        }
        let plaintext = value.encode();
        let screened = ScreenedLog::screen(&fixture.log, &fixture.keys, &Limits::PROTOCOL, &others)
            .expect("the genesis opens");
        let part = screened
            .opened(checkpoint)
            .and_then(|opened| opened.checkpoint())
            .expect("a checkpoint")
            .clone();
        assert_eq!(digest(&plaintext), part.digest, "{name}: the record");
        assert_eq!(
            frasil_space::checkpoint_record::read_link(&plaintext),
            Some((part.epoch, None)),
            "{name}"
        );
        // A newcomer handed the record refuses to start from it.
        let newcomer = match Record::read_object(&plaintext, &part) {
            Ok(_) => "starts".to_owned(),
            Err(class) => format!("refused: {}", class.name()),
        };
        if newcomer != text(case, "newcomer") {
            failures.push(format!("{name}: newcomer {newcomer}"));
        }
        let objects = BTreeMap::from([(checkpoint, plaintext)]);
        let judge = Checkpointed::new(
            CheckpointInputs {
                objects: &objects,
                ..inputs
            },
            None,
        );
        assert!(judge.extension_required(checkpoint), "{name}");
        assert!(judge.record(checkpoint).is_none(), "{name}: never read");
        assert_eq!(
            show(&judge.validity(checkpoint)),
            "ExtensionRequired",
            "{name}"
        );
        let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
        let judged = judge.judge(&all);
        compare(
            &fixture,
            name,
            &judged.statuses,
            &case["verdicts"],
            &mut failures,
        );
        compare_chain(
            &fixture,
            name,
            &judged.chain,
            &case["effective"],
            &mut failures,
        );
        assert!(judged.needs_later_rules, "{name}: needs a later version");
        // Nothing reads it as a rival where nothing is kept.
        assert!(judge.rivals(&all).is_empty());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `extension_rival` (roster.md, 3.15.2, "A record held for a later
/// document's key", and 3.15.6, "A rival"): a writer's checkpoint whose
/// record uses key 9, concurrent with the founder's, which takes effect. A
/// replica that holds the writer's past judges the steps that read no
/// record: the writer administers nothing, so its checkpoint is
/// `NotAnAdministrator`, final, and late beside the founder's; the replica
/// needs no later version. One that forgot under the founder's checkpoint
/// cannot: the writer's, whose ID is smaller and whose keys 2 and 3 name no
/// predecessor, is a rival that counts as stable, and it holds every event.
#[test]
fn a_writers_checkpoint_of_a_later_document_is_void_where_its_past_is_held() {
    use frasil_base::cbor::{self, Value};
    let case = &family("checkpoints")["extension_rival"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let writer = fixture.id("W checkpoints, its record using a later document's key");
    let founder = fixture.id("P checkpoints (C)");
    assert!(writer < founder, "the writer's has the smaller ID");
    let none = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &none,
        envelopes: &envelopes,
        slots: None,
    };
    let deriving = Checkpointed::new(inputs, None);
    // The writer's record: that of its past, with record key 9.
    let derived = deriving
        .record_for(&fixture.log.past(writer))
        .expect("the record of the writer's past")
        .encode();
    let mut value = cbor::decode(&derived).unwrap();
    let Value::Map(map) = &mut value else {
        panic!("a record is a map");
    };
    map.insert(9, Value::Unsigned(1));
    let held_record = value.encode();
    let record = deriving
        .record_for(&fixture.log.past(founder))
        .expect("the record of the founder's past");
    let screened = ScreenedLog::screen(&fixture.log, &fixture.keys, &Limits::PROTOCOL, &others)
        .expect("the genesis opens");
    for (c, plaintext) in [(writer, &held_record), (founder, &record.encode())] {
        let part = screened
            .opened(c)
            .and_then(|opened| opened.checkpoint())
            .expect("a checkpoint");
        assert_eq!(digest(plaintext), part.digest, "the record object");
    }
    let objects = BTreeMap::from([(writer, held_record), (founder, record.encode())]);
    let inputs = CheckpointInputs {
        objects: &objects,
        ..inputs
    };
    let mut failures = Vec::new();

    // A replica that kept everything.
    let full = Checkpointed::new(inputs, None);
    assert_eq!(show(&full.validity(writer)), "NotAnAdministrator");
    assert!(!full.extension_required(writer), "settled, not held");
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);
    let summaries = summary::Summaries::new(&objects);
    let streamed = Checkpointed::new(
        CheckpointInputs {
            objects: &summaries,
            ..inputs
        },
        None,
    );
    summary::same(&judged, &streamed.judge(&all));
    assert_eq!(judged.chain, vec![founder]);
    compare(
        &fixture,
        "kept",
        &judged.statuses,
        &case["kept"],
        &mut failures,
    );
    assert!(!judged.needs_later_rules, "a void checkpoint holds nothing");

    // A replica that forgot under the founder's checkpoint: the genesis, the
    // checkpoint and the writer's, which is late, whole.
    let holds = BTreeSet::from([founder, writer]);
    let forgetting = forgetting_log(&fixture.log, &holds);
    let kept_envelopes: BTreeMap<EventId, frasil_events::Event> = holds
        .iter()
        .flat_map(|&id| fixture.log.event(id).unwrap().parents().to_vec())
        .filter(|parent| !holds.contains(parent))
        .map(|parent| (parent, fixture.log.event(parent).unwrap().clone()))
        .collect();
    let forgot = Checkpointed::new(
        CheckpointInputs {
            log: &forgetting,
            envelopes: &kept_envelopes,
            ..inputs
        },
        Some(Kept {
            checkpoint: founder,
            record: record.into(),
        }),
    );
    let mut held = holds.clone();
    held.insert(forgetting.id());
    assert!(forgot.extension_required(writer), "its past is gone");
    let rivals: Vec<String> = forgot
        .rivals(&held)
        .iter()
        .map(|id| fixture.event_names[id].clone())
        .collect();
    let want: Vec<String> = case["forgot"]["rivals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(rivals, want, "the rivals");
    let judged = forgot.judge(&held);
    compare(
        &fixture,
        "forgot",
        &judged.statuses,
        &case["forgot"]["verdicts"],
        &mut failures,
    );
    assert!(judged.needs_later_rules);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `extension_after_predecessor` (roster.md, 3.15.2, "A record held for a
/// later document's key"): after a first checkpoint in effect, a writer and
/// an administrator each sign a checkpoint whose record names it as
/// predecessor and uses record key 9. Steps 2 to 6 run with the predecessor
/// the record's keys 2 and 3 name: the writer's is `NotAnAdministrator`,
/// final and not held; the administrator's passes them and stays held as
/// `ExtensionRequired`. A replica that forgot under the first holds both.
#[test]
fn held_records_after_a_predecessor_run_every_step_that_reads_no_record() {
    use frasil_base::cbor::{self, Value};
    let case = &family("checkpoints")["extension_after_predecessor"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let c1 = fixture.id("P checkpoints (C1)");
    let writer = fixture.id("W checkpoints after C1, its record using key 9");
    let admin = fixture.id("A checkpoints after C1, its record using key 9");
    let none = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &none,
        envelopes: &envelopes,
        slots: None,
    };
    let deriving = Checkpointed::new(inputs, None);
    let first = deriving
        .record_for(&fixture.log.past(c1))
        .expect("the record of C1's past");
    let first_only = BTreeMap::from([(c1, first.encode())]);
    let deriving = Checkpointed::new(
        CheckpointInputs {
            objects: &first_only,
            ..inputs
        },
        None,
    );
    // Each record: that of its past naming C1, with record key 9.
    let held = |c: EventId| {
        let derived = deriving
            .record_naming(&fixture.log.past(c), Some(c1))
            .expect("the record of its past")
            .encode();
        let mut value = cbor::decode(&derived).unwrap();
        let Value::Map(map) = &mut value else {
            panic!("a record is a map");
        };
        map.insert(9, Value::Unsigned(1));
        value.encode()
    };
    let objects = BTreeMap::from([
        (c1, first.encode()),
        (writer, held(writer)),
        (admin, held(admin)),
    ]);
    let screened = ScreenedLog::screen(&fixture.log, &fixture.keys, &Limits::PROTOCOL, &others)
        .expect("the genesis opens");
    for (c, plaintext) in &objects {
        let part = screened
            .opened(*c)
            .and_then(|opened| opened.checkpoint())
            .expect("a checkpoint");
        assert_eq!(digest(plaintext), part.digest, "the record object");
        if *c != c1 {
            assert_eq!(
                frasil_space::checkpoint_record::read_link(plaintext),
                Some((part.epoch, Some(c1)))
            );
        }
    }
    let inputs = CheckpointInputs {
        objects: &objects,
        ..inputs
    };
    let mut failures = Vec::new();
    let full = Checkpointed::new(inputs, None);
    for (name, want) in case["verdicts"].as_object().unwrap() {
        let got = show(&full.validity(fixture.id(name)));
        if got != want.as_str().unwrap() {
            failures.push(format!("validity: {name}: {got}, not {want}"));
        }
    }
    assert!(!full.extension_required(writer), "settled, not held");
    assert!(full.extension_required(admin), "held");
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    assert_eq!(judged.chain, vec![c1]);
    compare(
        &fixture,
        "kept everything",
        &judged.statuses,
        &case["statuses"],
        &mut failures,
    );
    assert!(judged.needs_later_rules, "the administrator's is held");

    // A replica that forgot under C1 cannot run the steps: it holds both.
    let after: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|&id| id == c1 || full.follows(id, c1) == Ok(true))
        .collect();
    let forgetting = forgetting_log(&fixture.log, &after);
    let forgot = Checkpointed::new(
        CheckpointInputs {
            log: &forgetting,
            ..inputs
        },
        Some(Kept {
            checkpoint: c1,
            record: first.into(),
        }),
    );
    for c in [writer, admin] {
        assert!(forgot.extension_required(c), "its past is gone");
        assert_eq!(show(&forgot.validity(c)), "ExtensionRequired");
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `frozen_content` (units.md, "The past of a kept checkpoint"): P grants
/// C write with `suggest` narrowing, D read and E write; each writes a unit,
/// then P lowers C to read, raises D to write and removes E, and
/// checkpoints. What a replica that forgets under the checkpoint freezes of
/// each unit is its verdict and its author's capabilities at its place, as
/// the vector gives them, never the record's standing, which differs for
/// each; read back as `frasil_units` hands a unit to its adapter, C's edit
/// applies as a suggester's, D's stays refused and E's applies.
#[test]
fn a_forgetting_replica_freezes_each_units_verdict_and_context() {
    let case = &family("checkpoints")["frozen_content"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let c = fixture.id("P checkpoints");
    let none = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, &others),
        objects: &none,
        envelopes: &envelopes,
        slots: None,
    };
    let record = Checkpointed::new(inputs, None)
        .record_for(&fixture.log.past(c))
        .expect("the record of its past");
    let objects = BTreeMap::from([(c, record.encode())]);
    let judge = Checkpointed::new(
        CheckpointInputs {
            objects: &objects,
            ..inputs
        },
        None,
    );
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    assert_eq!(judge.judge(&all).chain, vec![c]);
    let frozen = judge.frozen_units(&all, c);
    // The roster now, whose labels attribution never reads.
    let now = frasil_space::Space::resolve(&fixture.log, None, options(&fixture, &others))
        .expect("the whole view");
    let context_json = |level: u64, capabilities: Vec<(String, u64)>| {
        serde_json::json!([
            level,
            capabilities
                .into_iter()
                .map(|(name, mode)| serde_json::json!([name, mode]))
                .collect::<Vec<_>>()
        ])
    };
    let mut failures = Vec::new();
    let units = case["units"].as_object().unwrap();
    assert_eq!(frozen.len(), units.len(), "every unit of the past");
    for (name, want) in units {
        let unit = fixture.id(name);
        let got = &frozen[&unit];
        if show(&got.status) != text(want, "verdict") {
            failures.push(format!("{name}: {}", show(&got.status)));
        }
        let Some(frasil_space::across::AuthorReach::Reached(reach)) = &got.reach else {
            failures.push(format!("{name}: no reach {:?}", got.reach));
            continue;
        };
        let pairs: Vec<(String, u64)> = got
            .capabilities()
            .into_iter()
            .map(|c| (c.name, c.mode.code()))
            .collect();
        let context = context_json(reach.level.code(), pairs);
        if context != want["context"] {
            failures.push(format!("{name}: context {context}"));
        }
        // The record's standing of its author, which a replica that forgot
        // must not read for it, differs.
        let author = *fixture.log.event(unit).unwrap().author();
        let standing = record
            .entry(&frasil_space::MemberRef::device(author))
            .map(|entry| {
                context_json(
                    entry.level.code(),
                    entry
                        .capabilities
                        .iter()
                        .map(|c| (c.name.clone(), c.mode.code()))
                        .collect(),
                )
            })
            .unwrap_or_else(|| serde_json::json!([]));
        assert_eq!(standing, want["record_standing"], "{name}");
        assert_ne!(standing, context, "{name}");
        // Read back as a replica that forgot reads it.
        let kept = frasil_units::frozen::Frozen::of(got, None);
        assert_eq!(kept.applies(), got.status.is_valid(), "{name}");
        let back = frasil_units::frozen::Frozen::from_parts(
            kept.applies(),
            kept.verdict.as_ref().err().map(String::as_str),
            &kept.capability_pairs(),
            &kept.attribution_entries(),
            &kept.voided_by.iter().map(|id| id.0).collect::<Vec<_>>(),
        );
        assert_eq!(back.as_ref(), Some(&kept), "{name}");
        // Its attribution with the labels of its place, never the current
        // label, and the events that void it.
        let attribution = got.attribution.as_ref().map(|paths| {
            paths
                .iter()
                .map(|(member, label)| {
                    let mut entry = vec![
                        serde_json::json!(member.kind.code()),
                        serde_json::json!(fixture.member_name(member)),
                    ];
                    entry.extend(label.iter().map(|label| serde_json::json!(label)));
                    serde_json::Value::Array(entry)
                })
                .collect::<Vec<_>>()
        });
        if serde_json::json!(attribution) != want["attribution"] {
            failures.push(format!("{name}: attribution {attribution:?}"));
        }
        let current = now
            .roster()
            .state(&frasil_space::MemberRef::device(author))
            .and_then(|state| state.label.clone())
            .map(|label| serde_json::json!(label))
            .unwrap_or(serde_json::Value::Null);
        assert_eq!(current, want["current_label"], "{name}: the current label");
        let voided_by: Vec<String> = got
            .voided_by
            .iter()
            .map(|id| fixture.name_of(*id))
            .collect();
        assert_eq!(serde_json::json!(voided_by), want["voided_by"], "{name}");
        assert!(
            kept.attribution.is_empty() || kept.voided_by.is_empty(),
            "{name}"
        );
        match name.as_str() {
            "C writes" => {
                assert!(kept.capabilities.is_suggester(), "C wrote as a suggester");
                assert_eq!(
                    kept.attribution
                        .iter()
                        .map(|(member, _)| *member)
                        .collect::<Vec<_>>(),
                    vec![frasil_space::MemberRef::device(author)]
                );
            }
            "D writes" => assert!(!kept.applies(), "a reader's edit stays refused"),
            "E writes" => assert!(kept.applies(), "a removed writer's edit stays"),
            other => panic!("{other}"),
        }
    }
    // Two paths at one level, one extending a capability and the other
    // extending and narrowing it: the meet keeps both modes, which key 6
    // holds and the adapter reads.
    let two = &case["two_paths"];
    let paths: Vec<(frasil_space::Level, Vec<frasil_space::Capability>)> = two["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| {
            let level = frasil_space::Level::from_code(path[0].as_u64().unwrap()).unwrap();
            let capabilities = path[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| frasil_space::Capability {
                    name: pair[0].as_str().unwrap().to_owned(),
                    mode: frasil_space::CapabilityMode::from_code(pair[1].as_u64().unwrap())
                        .unwrap(),
                })
                .collect();
            (level, capabilities)
        })
        .collect();
    let reach = frasil_space::graph::meet_of_paths(&paths).expect("a path");
    let pairs: Vec<(String, u64)> = frasil_space::graph::capabilities_of(&reach)
        .into_iter()
        .map(|c| (c.name, c.mode.code()))
        .collect();
    assert_eq!(
        context_json(reach.level.code(), pairs.clone()),
        two["frozen"]
    );
    let kept = frasil_units::frozen::Frozen::from_parts(true, None, &pairs, &[], &[])
        .expect("both modes read back");
    assert_eq!(kept.capability_pairs(), pairs, "kept in both modes");
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A record's derivation reads back byte for byte: the record of the
/// checkpoint's past at a replica that holds it is the vector's.
#[test]
fn the_record_of_the_past_is_the_vectors() {
    let case = family("checkpoints");
    let fixture = Fixture::new(text(&case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let checkpoint = fixture.id(text(&case["checkpoint"], "name"));
    let objects = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let judge = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let record = judge
        .record_for(&fixture.log.past(checkpoint))
        .expect("the record of its past");
    assert_eq!(record.encode(), bytes(&case["checkpoint"], "record"));
}

/// The record entries a scenario names, as the vectors write them.
fn entry_json(entry: &frasil_space::MemberEntry) -> Json {
    let mut out = serde_json::Map::new();
    out.insert(
        "member".into(),
        serde_json::json!([
            entry.member.kind.code(),
            frasil_testkit::hex::encode(entry.member.id)
        ]),
    );
    if let Some(claims) = entry.claims {
        out.insert("claims".into(), claims.into());
    }
    if let Some(expires_at) = entry.expires_at {
        out.insert("expires_at".into(), expires_at.into());
    }
    if let Some(invite) = entry.invite {
        out.insert("invite".into(), invite.code().into());
    }
    if let Some(claimant) = entry.claimant {
        out.insert(
            "claimant".into(),
            serde_json::json!([
                claimant.kind.code(),
                frasil_testkit::hex::encode(claimant.id)
            ]),
        );
    }
    if entry.floor {
        out.insert("floor".into(), 1.into());
    }
    if !entry.named.is_empty() {
        let named: Vec<String> = entry
            .named
            .iter()
            .map(|id| frasil_testkit::hex::encode(id.0))
            .collect();
        out.insert("named".into(), named.into());
    }
    if !entry.notices.is_empty() {
        let notices: Vec<Json> = entry
            .notices
            .iter()
            .map(|n| {
                serde_json::json!({
                    "author": frasil_testkit::hex::encode(n.author.0),
                    "break": u64::from(n.from_now_on),
                    "rotation": frasil_testkit::hex::encode(n.rotation.0),
                })
            })
            .collect();
        out.insert("notices".into(), notices.into());
    }
    Json::Object(out)
}

/// One scenario of roster.json's `checkpoints`: the record read back and
/// derived byte for byte, the entries it names, and the verdicts of a
/// replica that holds everything and of one that forgot, which agree.
fn scenario(case: &Json, others: &OtherLogs<'_>) -> Vec<String> {
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let checkpoint = fixture.id(text(case, "checkpoint"));
    let plaintext = bytes(case, "record");
    let mut failures = Vec::new();
    let record = Arc::new(Record::read(&plaintext).expect("the record reads"));
    assert_eq!(record.encode(), plaintext, "its one encoding");
    let wanted = case["entries"].as_array().unwrap();
    for want in wanted {
        let member = want["member"].as_array().unwrap();
        let id = frasil_testkit::hex::decode_array::<32>(member[1].as_str().unwrap()).unwrap();
        match record.members.iter().find(|e| e.member.id == id) {
            Some(entry) if entry_json(entry) == *want => {}
            Some(entry) => failures.push(format!("entry {}, not {want}", entry_json(entry))),
            None => failures.push(format!("no entry {want}")),
        }
    }
    let objects: BTreeMap<EventId, Vec<u8>> = BTreeMap::from([(checkpoint, plaintext.clone())]);
    let none = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: options(&fixture, others),
        objects: &objects,
        envelopes: &none,
        slots: None,
    };
    let full = Checkpointed::new(inputs, None);
    // An administrator votes for it: its record, space entries included, is
    // the one this replica derives.
    if full.record_agrees(checkpoint) != Some(true) {
        failures.push("the record does not agree with the derived one".into());
    }
    // The record of the checkpoint's past is the vector's, byte for byte.
    match full.record_for(&fixture.log.past(checkpoint)) {
        Some(derived) if derived.encode() == plaintext => {}
        Some(derived) => failures.push(format!(
            "derived record differs: {:?}",
            derived.members.iter().map(entry_json).collect::<Vec<_>>()
        )),
        None => failures.push("no record derived".into()),
    }
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    let effective: Vec<String> = judged
        .chain
        .iter()
        .map(|id| fixture.event_names[id].clone())
        .collect();
    let want: Vec<String> = case["full"]["effective"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    if effective != want {
        failures.push(format!("chain {effective:?}, not {want:?}"));
    }
    for (name, want) in case["full"]["verdicts"].as_object().unwrap() {
        let got = show(&judged.statuses[&fixture.id(name)]);
        if got != want.as_str().unwrap() {
            failures.push(format!("full: {name}: {got}, not {want}"));
        }
    }
    let holds: BTreeSet<EventId> = case["forgot"]["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    let forgetting = forgetting_log(&fixture.log, &holds);
    let kept_envelopes: BTreeMap<EventId, frasil_events::Event> = holds
        .iter()
        .flat_map(|&id| fixture.log.event(id).unwrap().parents().to_vec())
        .filter(|parent| !holds.contains(parent))
        .map(|parent| (parent, fixture.log.event(parent).unwrap().clone()))
        .collect();
    let forgot = Checkpointed::new(
        CheckpointInputs {
            log: &forgetting,
            envelopes: &kept_envelopes,
            ..inputs
        },
        Some(Kept {
            checkpoint,
            record: Arc::clone(&record),
        }),
    );
    let mut held = holds.clone();
    held.insert(forgetting.id());
    let judged_forgot = forgot.judge(&held);
    for (name, want) in case["forgot"]["verdicts"].as_object().unwrap() {
        let id = fixture.id(name);
        let got = show(&judged_forgot.statuses[&id]);
        if got != want.as_str().unwrap() {
            failures.push(format!("forgot: {name}: {got}, not {want}"));
        }
    }
    if judged_forgot.roster != judged.roster {
        failures.push("the replicas' rosters differ".into());
    }
    failures
}

/// roster.json's `checkpoints.raced` (ext-invite-links.md, "Across a
/// checkpoint"): two claims race before the checkpoint, so its record shows
/// the invite key raced; a claim after it is `InviteUsed` at a replica that
/// holds everything and at one that forgot, and a revocation of the key is
/// valid.
#[cfg(feature = "ext-invite-links")]
#[test]
fn a_raced_invite_across_a_checkpoint() {
    let case = &family("checkpoints")["raced"];
    let failures = scenario(case, &OtherLogs::none());
    assert!(failures.is_empty(), "{failures:#?}");
}

/// roster.json's `checkpoints.granted` (roster.md, "Other logs and
/// extensions"): the record keeps the granted team's notice, its floor and
/// the rotation the response named; after the checkpoint a team device
/// writes through the team, and the principal of the response stays in
/// force at both replicas.
#[test]
fn a_granted_space_across_a_checkpoint() {
    let case = &family("checkpoints")["granted"];
    let team = Fixture::new(text(case, "team_prefix"), &case["team"]);
    let none = OtherLogs::none();
    let team_space = team.resolve(None, &team.keys, &none).unwrap();
    let others = OtherLogs::none().with_space(&team_space);
    let mut failures = scenario(case, &others);

    // The principals of the world, from the record's notices.
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let checkpoint = fixture.id(text(case, "checkpoint"));
    let objects: BTreeMap<EventId, Vec<u8>> = BTreeMap::from([(checkpoint, bytes(case, "record"))]);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let full = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: options(&fixture, &others),
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let world = full.key_world(&all).expect("a chain in effect");
    let space = world.resolve(options(&fixture, &others)).unwrap();
    let history = SpaceHistory::new(&space);
    let graph = history.key_graph();
    let got: BTreeSet<(String, String)> = graph
        .members(KeyKind::Content)
        .keys()
        .filter_map(|m| match m {
            frasil_space::keygraph::Member::Principal(p) => Some((
                frasil_testkit::hex::encode(p.space.0),
                team.event_names[&p.rotation].clone(),
            )),
            _ => None,
        })
        .collect();
    let want: BTreeSet<(String, String)> = case["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let p = p.as_array().unwrap();
            (
                p[0].as_str().unwrap().to_owned(),
                p[1].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    if got != want {
        failures.push(format!("principals {got:?}, not {want:?}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------
// roster.json's `checkpoints.adversarial`.

/// The record objects of a history's checkpoints, as their authors sealed
/// them: the vectors carry the events alone, so each checkpoint's record
/// is derived from its past ([`Checkpointed::record_naming`]), naming the
/// predecessor (none, or a checkpoint of its past) whose record matches its
/// roster part's digest. A checkpoint none matches has no object.
fn derived_objects(fixture: &Fixture, options: Options<'_>) -> BTreeMap<EventId, Vec<u8>> {
    let screened = ScreenedLog::screen(
        &fixture.log,
        &fixture.keys,
        &Limits::PROTOCOL,
        options.others,
    )
    .expect("the genesis opens");
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let mut objects: BTreeMap<EventId, Vec<u8>> = BTreeMap::new();
    for id in fixture.log.canonical() {
        let Some(part) = screened
            .opened(id)
            .and_then(|opened| opened.checkpoint())
            .cloned()
        else {
            continue;
        };
        let found = {
            let judge = Checkpointed::new(
                CheckpointInputs {
                    log: &fixture.log,
                    options,
                    objects: &objects,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            );
            let past = fixture.log.past(id);
            let mut candidates = vec![None];
            candidates.extend(
                past.iter()
                    .copied()
                    .filter(|&x| judge.is_checkpoint(x))
                    .map(Some),
            );
            candidates.into_iter().find_map(|previous| {
                let plain = judge.record_naming(&past, previous)?.encode();
                (digest(&plain) == part.digest).then_some(plain)
            })
        };
        if let Some(plain) = found {
            objects.insert(id, plain);
        }
    }
    objects
}

/// The verdicts of a replica that kept `kept` and holds `holds`, the
/// genesis and the stubs of what it forgot (roster.md, 3.15.6): it keeps
/// the envelopes of the parents it forgot and of the checkpoints the kept
/// one's cuts reach.
fn forgotten<'a>(
    fixture: &Fixture,
    inputs: CheckpointInputs<'a>,
    kept: EventId,
    holds: &BTreeSet<EventId>,
    run: impl FnOnce(&Checkpointed<'_>, &BTreeSet<EventId>),
) {
    let full = Checkpointed::new(inputs, None);
    let reached = full.reach(kept).unwrap_or_default();
    let forgetting = forgetting_log(&fixture.log, holds);
    let kept_envelopes: BTreeMap<EventId, frasil_events::Event> = holds
        .iter()
        .flat_map(|&id| fixture.log.event(id).unwrap().parents().to_vec())
        .chain(reached)
        .filter(|id| !holds.contains(id) && *id != fixture.log.id())
        .map(|id| (id, fixture.log.event(id).unwrap().clone()))
        .collect();
    let record = full.record(kept).expect("the kept checkpoint's record");
    let forgot = Checkpointed::new(
        CheckpointInputs {
            log: &forgetting,
            envelopes: &kept_envelopes,
            ..inputs
        },
        Some(Kept {
            checkpoint: kept,
            record,
        }),
    );
    let mut held = holds.clone();
    held.insert(forgetting.id());
    run(&forgot, &held);
}

/// The names of a vector's list of events.
fn names(fixture: &Fixture, list: &Json) -> BTreeSet<EventId> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect()
}

/// Each of `verdicts` against what `statuses` holds.
fn compare(
    fixture: &Fixture,
    label: &str,
    statuses: &BTreeMap<EventId, Status>,
    verdicts: &Json,
    failures: &mut Vec<String>,
) {
    for (name, want) in verdicts.as_object().unwrap() {
        let got = statuses
            .get(&fixture.id(name))
            .map_or_else(|| "none".to_owned(), show);
        if got != want.as_str().unwrap() {
            failures.push(format!("{label}: {name}: {got}, not {want}"));
        }
    }
}

/// The chain a vector names, against a judged one.
fn compare_chain(
    fixture: &Fixture,
    label: &str,
    chain: &[EventId],
    want: &Json,
    failures: &mut Vec<String>,
) {
    let got: Vec<String> = chain
        .iter()
        .map(|id| fixture.event_names[id].clone())
        .collect();
    let want: Vec<String> = want
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    if got != want {
        failures.push(format!("{label}: chain {got:?}, not {want:?}"));
    }
}

/// `stale_predecessor` (roster.md, 3.15.2): X and Y name K1 as predecessor
/// while their cuts reach K2, valid and after K1: `CheckpointPending` at a
/// replica that kept everything and at one that kept K2 and holds K1 as an
/// envelope alone.
#[test]
fn a_checkpoint_naming_a_forgotten_predecessor_is_checkpoint_pending() {
    let case = &family("checkpoints")["adversarial"]["stale_predecessor"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options,
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let mut failures = Vec::new();
    let full = Checkpointed::new(inputs, None);
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    compare_chain(
        &fixture,
        "full",
        &judged.chain,
        &case["full"]["effective"],
        &mut failures,
    );
    compare(
        &fixture,
        "full",
        &judged.statuses,
        &case["full"]["verdicts"],
        &mut failures,
    );
    let kept = fixture.id("P checkpoints again (K2)");
    let holds = names(&fixture, &case["forgot"]["holds"]);
    forgotten(&fixture, inputs, kept, &holds, |forgot, held| {
        let judged = forgot.judge(held);
        compare(
            &fixture,
            "forgot",
            &judged.statuses,
            &case["forgot"]["verdicts"],
            &mut failures,
        );
        assert!(forgot.rivals(held).is_empty(), "no rival");
    });
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `backdated` (roster.md, 3.15.4, "Not by its author"): A's checkpoint,
/// signed on a view before its removal, waits for P, since A's removal of
/// P after it excuses no one from A's own checkpoint; P's removal of A
/// stands.
#[test]
fn a_backdated_checkpoints_author_excuses_no_one() {
    let case = &family("checkpoints")["adversarial"]["backdated"];
    let mut fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    fixture.name_device("P");
    let others = OtherLogs::none();
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let full = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options,
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let mut failures = Vec::new();
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    compare_chain(
        &fixture,
        "full",
        &judged.chain,
        &case["full"]["effective"],
        &mut failures,
    );
    compare(
        &fixture,
        "full",
        &judged.statuses,
        &case["full"]["verdicts"],
        &mut failures,
    );
    let x = fixture.id("A checkpoints on its old view (X)");
    let waiting: Vec<[u8; 32]> = full
        .waiting_for(x, &all)
        .into_iter()
        .map(|w| w.device.0)
        .collect();
    let want: Vec<[u8; 32]> = case["waiting_for"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.device_key(n.as_str().unwrap()))
        .collect();
    if waiting != want {
        failures.push("X waits for another set than P".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `disjoint` (roster.md, 3.15.4, "Concurrent checkpoints that are both
/// stable", and 3.15.6, "A rival"): two electorates with no device in
/// common; the smaller ID takes effect at a replica that holds both; one
/// that forgot under the other holds the smaller as a rival and every
/// event pending; one that forgot under the smaller judges the other late.
#[test]
fn disjoint_electorates_settle_on_the_smaller_id_and_a_rival_holds_everything() {
    let case = &family("checkpoints")["adversarial"]["disjoint"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options,
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let mut failures = Vec::new();
    let full = Checkpointed::new(inputs, None);
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    compare_chain(
        &fixture,
        "full",
        &judged.chain,
        &case["full"]["effective"],
        &mut failures,
    );
    compare(
        &fixture,
        "full",
        &judged.statuses,
        &case["full"]["verdicts"],
        &mut failures,
    );
    assert!(
        full.rivals(&all).is_empty(),
        "a replica that kept everything holds no rival"
    );
    let (c1, c2) = (
        fixture.id("P checkpoints (c1)"),
        fixture.id("A checkpoints concurrently (c2)"),
    );
    let (win, lose) = (c1.min(c2), c1.max(c2));
    assert_eq!(judged.chain, vec![win], "the smaller ID wins");
    for (key, expect_rival) in [("forgot_under_loser", true), ("forgot_under_winner", false)] {
        let view = &case[key];
        let kept = fixture.id(text(view, "kept"));
        let holds = names(&fixture, &view["holds"]);
        forgotten(&fixture, inputs, kept, &holds, |forgot, held| {
            let rivals = forgot.rivals(held);
            match expect_rival {
                true => {
                    if rivals != BTreeSet::from([win]) {
                        failures.push(format!("{key}: rivals {rivals:?}, not the winner"));
                    }
                }
                false => {
                    if !rivals.is_empty() {
                        failures.push(format!("{key}: a rival held"));
                    }
                }
            }
            let judged = forgot.judge(held);
            compare(
                &fixture,
                key,
                &judged.statuses,
                &view["verdicts"],
                &mut failures,
            );
        });
        assert_ne!(kept, if expect_rival { win } else { lose });
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `takeover_junior`, `takeover_colluding`, `takeover_senior`,
/// `takeover_recovery` and `takeover_lower` (roster.md, section 4, "A
/// backdated checkpoint", and 3.15.4, heard members): the members each
/// checkpoint hears, whom it waits for, the chain in effect and every
/// verdict. A junior's or a lower rank's backdated checkpoint waits for
/// good and the honest one takes effect; a thief holding the most senior
/// device wins; the recovery member excuses a lost senior device.
#[test]
fn backdated_takeovers_hear_their_victims() {
    for kind in ["junior", "colluding", "senior", "recovery", "lower"] {
        let case = &family("checkpoints")["adversarial"][format!("takeover_{kind}").as_str()];
        let mut fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
        for name in ["P", "Q", "A", "B", "R"] {
            fixture.name_device(name);
        }
        let others = OtherLogs::none();
        let options = options(&fixture, &others);
        let objects = derived_objects(&fixture, options);
        let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
        let full = Checkpointed::new(
            CheckpointInputs {
                log: &fixture.log,
                options,
                objects: &objects,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        );
        let mut failures = Vec::new();
        let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
        let judged = full.judge(&all);

        compare_chain(
            &fixture,
            kind,
            &judged.chain,
            &case["full"]["effective"],
            &mut failures,
        );
        compare(
            &fixture,
            kind,
            &judged.statuses,
            &case["full"]["verdicts"],
            &mut failures,
        );
        let devices = |list: &Json| -> BTreeSet<[u8; 32]> {
            list.as_array()
                .unwrap()
                .iter()
                .map(|n| fixture.device_key(n.as_str().unwrap()))
                .collect()
        };
        for (name, want) in case["heard"].as_object().unwrap() {
            let c = fixture.id(name);
            let got: BTreeSet<[u8; 32]> = full.heard(c).keys().map(|d| d.0).collect();
            if got != devices(want) {
                failures.push(format!("{kind}: {name} hears another set"));
            }
        }
        for (name, want) in case["waiting_for"].as_object().unwrap() {
            let c = fixture.id(name);
            let got: BTreeSet<[u8; 32]> = full
                .waiting_for(c, &all)
                .into_iter()
                .map(|w| w.device.0)
                .collect();
            if got != devices(want) {
                failures.push(format!("{kind}: {name} waits for another set"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }
}

/// `step_6` (roster.md, 3.15.2, "Step 6"): a guest's checkpoint is
/// `NotAnAdministrator` before keys.md is read, and a checkpoint that is
/// no grant rotation in a space that is not restricted is
/// `GrantKeyRequired`.
#[cfg(feature = "ext-guests")]
#[test]
fn a_guests_checkpoint_and_one_without_a_grant_rotation_are_refused() {
    let case = &family("checkpoints")["adversarial"]["step_6"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let judge = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options,
            objects: &objects,
            envelopes: &envelopes,
            slots: None,
        },
        None,
    );
    let mut failures = Vec::new();
    for (name, want) in case["verdicts"].as_object().unwrap() {
        let got = show(&judge.validity(fixture.id(name)));
        if got != want.as_str().unwrap() {
            failures.push(format!("{name}: {got}, not {want}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `guest` (roster.md, "Other logs and extensions", guests): the record
/// keeps a guest's session and `expires_at`; the guest writes after the
/// checkpoint and its session ends by removal, alike at a replica that
/// kept everything and one that forgot.
#[cfg(feature = "ext-guests")]
#[test]
fn a_guest_across_a_checkpoint() {
    let case = &family("checkpoints")["adversarial"]["guest"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let others = OtherLogs::none();
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let checkpoint = fixture.id("P checkpoints");
    let mut failures = Vec::new();
    if objects.get(&checkpoint) != Some(&bytes(case, "record")) {
        failures.push("the record of its past is not the vector's".into());
    }
    let record = Record::read(&bytes(case, "record")).expect("the record reads");
    assert!(
        record
            .members
            .iter()
            .any(|entry| entry.session.is_some() && entry.expires_at == Some(2_000_000_000)),
        "the guest's session and expiry"
    );
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options,
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let full = Checkpointed::new(inputs, None);
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    compare_chain(
        &fixture,
        "full",
        &judged.chain,
        &case["full"]["effective"],
        &mut failures,
    );
    compare(
        &fixture,
        "full",
        &judged.statuses,
        &case["full"]["verdicts"],
        &mut failures,
    );
    let holds = names(&fixture, &case["forgot"]["holds"]);
    forgotten(&fixture, inputs, checkpoint, &holds, |forgot, held| {
        let got = forgot.judge(held);
        compare(
            &fixture,
            "forgot",
            &got.statuses,
            &case["forgot"]["verdicts"],
            &mut failures,
        );
        if got.roster != judged.roster {
            failures.push("the replicas' rosters differ".into());
        }
    });
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `granted_checkpoint` (roster.md, "Other logs and extensions"): the
/// granted team checkpoints, as a grant rotation of it; the granting space
/// responds by delivery, noticing it; its principal is in force whether
/// the team is held whole or from its checkpoint on, and the space's
/// replicas agree.
#[test]
fn a_granted_spaces_own_checkpoint() {
    let case = &family("checkpoints")["adversarial"]["granted_checkpoint"];
    let team = Fixture::new(text(case, "team_prefix"), &case["team"]);
    // The team as a replica that holds it whole reads it: its checkpoint
    // in effect, the space its world resolves.
    let none = OtherLogs::none();
    let team_options = options(&team, &none);
    let team_objects = derived_objects(&team, team_options);
    let team_envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let team_judge = Checkpointed::new(
        CheckpointInputs {
            log: &team.log,
            options: team_options,
            objects: &team_objects,
            envelopes: &team_envelopes,
            slots: None,
        },
        None,
    );
    let team_all: BTreeSet<EventId> = team.log.canonical().into_iter().collect();
    let team_world = team_judge
        .key_world(&team_all)
        .expect("the team's checkpoint in effect");
    let team_space = team_world.resolve(team_options).unwrap();
    let others = OtherLogs::none().with_space(&team_space);
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let options = options(&fixture, &others);
    let objects = derived_objects(&fixture, options);
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options,
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let mut failures = Vec::new();
    let full = Checkpointed::new(inputs, None);
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let judged = full.judge(&all);

    compare(
        &fixture,
        "full",
        &judged.statuses,
        &case["full"]["verdicts"],
        &mut failures,
    );
    let checkpoint = fixture.id("P checkpoints");
    let holds = names(&fixture, &case["forgot"]["holds"]);
    forgotten(&fixture, inputs, checkpoint, &holds, |forgot, held| {
        let got = forgot.judge(held);
        compare(
            &fixture,
            "forgot",
            &got.statuses,
            &case["forgot"]["verdicts"],
            &mut failures,
        );
    });
    // The principal of the response, in the world's key graph.
    let world = full.key_world(&all).expect("a chain in effect");
    let space = world.resolve(options).unwrap();
    let history = SpaceHistory::new(&space);
    let got: BTreeSet<(String, String)> = history
        .key_graph()
        .members(KeyKind::Content)
        .keys()
        .filter_map(|m| match m {
            frasil_space::keygraph::Member::Principal(p) => Some((
                frasil_testkit::hex::encode(p.space.0),
                team.event_names[&p.rotation].clone(),
            )),
            _ => None,
        })
        .collect();
    let want: BTreeSet<(String, String)> = case["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let p = p.as_array().unwrap();
            (
                p[0].as_str().unwrap().to_owned(),
                p[1].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    if got != want {
        failures.push(format!("principals {got:?}, not {want:?}"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Signs an event onto a fixture's log and names it: the history's own
/// signers, the cuts its parents reach (events.md, 3.11 Cuts).
#[allow(clippy::too_many_arguments)]
fn sign_onto(
    fixture: &mut Fixture,
    name: &str,
    signer: &frasil_crypto::schemes::Signer,
    event_kind: u8,
    seq: u64,
    prev: Option<EventId>,
    parents: Vec<EventId>,
    checkpoints: &BTreeSet<EventId>,
    body: Vec<u8>,
) -> EventId {
    let cuts = frasil_events::cuts::expected(&fixture.log, checkpoints, &parents)
        .expect("the parents' cuts are known");
    let scheme = if event_kind == frasil_events::kind::UNIT {
        frasil_crypto::schemes::Scheme::Ed25519
    } else {
        frasil_crypto::schemes::Scheme::Hybrid
    };
    let signed = frasil_events::Envelope {
        kind: event_kind,
        log: Some(fixture.log.id()),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents,
        cuts,
        body,
        scheme,
    }
    .sign(signer);
    let event = frasil_events::decode(&signed).expect("the event decodes");
    let id = event.id();
    fixture.log.place(event).expect("placed");
    fixture.event_names.insert(id, name.to_owned());
    id
}

/// roster.md, 3.15.5 The world after a checkpoint, Skeleton: once a
/// checkpoint takes effect at a replica that checks twins, the skeleton it
/// reads restarts at the checkpoint's cut, the cut's slots mapped to
/// devices by the record's `slot` entries. peers.json's `skeleton_cuts`
/// history, with A's vote (a unit after the checkpoint, so that the
/// checkpoint takes effect) and P's grant of `administer` to B after its
/// removal of A, each roster event with its twin signed by P's pseudonym
/// P0 after the cut: the removal of an administrator and the grant of a
/// new one after the checkpoint pass their twin checks, at a replica that
/// kept everything and at one that forgot under the checkpoint (keeping
/// the cut and the root and enrolment it names).
#[test]
fn administrators_added_and_removed_after_a_checkpoint_pass_their_twin_checks() {
    use frasil_crypto::fixtures::FixtureKeys;
    use frasil_keys::body::{Inner, RotationKeys, Seal, VisiblePart};
    use frasil_keys::derive::{body_commitment, body_key, read_credential, upload_key};
    use frasil_peers::body::{ChangeEffect, SlotRef, StorageBody};
    use frasil_peers::derive::{grant_map_with, twin_commitment, twin_secret};
    use frasil_space::part::{RosterPart, Update};
    use frasil_space::{Change, HistoryMode, Via};

    let case: Json = frasil_testkit::vectors::family("peers.json", "skeleton_cuts");
    let prefix = text(&case, "history_prefix").to_owned();
    let mut fixture = Fixture::new(&prefix, &case["events"]);
    fixture.name_device("P");
    fixture.name_device("A");
    let signer = |name: &str| {
        FixtureKeys::from_identity_seed(&common::example(&format!("{prefix}/{name}/ed25519")))
            .signer()
    };
    let pseudonym = |name: &str| {
        let seed = common::example(&format!("{prefix}/{name}/ed25519"));
        frasil_crypto::schemes::Signer::from_seeds(
            &seed,
            &frasil_crypto::fixtures::fixture_mldsa_seed(&seed),
            None,
        )
    };
    let space = fixture.log.id();
    let checkpoint = fixture.id("P checkpoints");
    let cut = fixture.id("P0: cut of P checkpoints");
    let removal = fixture.id("P removes A");
    let checkpoints = BTreeSet::from([checkpoint]);

    // A votes for the checkpoint by a unit after it.
    let vote = sign_onto(
        &mut fixture,
        "A votes",
        &signer("A"),
        frasil_events::kind::UNIT,
        1,
        None,
        vec![checkpoint],
        &checkpoints,
        b"unit: A votes".to_vec(),
    );

    // P grants B administer after its removal of A, with its twin by P0.
    let p = signer("P");
    let p_device = *p.device_id();
    let b = signer("B");
    let b_keys = frasil_space::DeviceKeys {
        ed: *b.identity_key(),
        keys: b.keys().clone(),
    };
    let label = format!("{prefix}/P grants B administer after the checkpoint");
    let content = common::example(&format!("{label}/content-key"));
    let seq = fixture.log.event(removal).unwrap().seq() + 1;
    let key = body_key(&content, &space.0, &p_device, seq);
    let salt = common::example(&format!("{label}/salt"));
    let c = twin_commitment(&p_device, seq, &twin_secret(&key), &salt);
    let grant = grant_map_with(
        &space,
        SlotRef::new(c, 0),
        b.device_id(),
        b.keys().xwing().expect("B has an X-Wing key"),
        &common::example(&format!("{label}/token")),
        &[0x5a; 64],
        frasil_peers::limits::MAX_RANK,
    )
    .expect("a grant map");
    let acknowledged = fixture.id("P0 acknowledges the removal");
    let p0 = pseudonym("P0");
    let p0_seq = fixture.log.event(acknowledged).unwrap().seq() + 1;
    let twin = sign_onto(
        &mut fixture,
        "P0: twin of P grants B administer",
        &p0,
        frasil_events::kind::STORAGE,
        p0_seq,
        Some(acknowledged),
        vec![acknowledged],
        &checkpoints,
        StorageBody::Change {
            twin: c,
            salt,
            effect: ChangeEffect::Grants(vec![grant]),
        }
        .encode(),
    );
    let part = RosterPart::Update(Update {
        changes: vec![Change::grant_administrator(
            b_keys,
            255,
            HistoryMode::WithHistory,
            Via::Code,
        )],
    })
    .encode();
    let inner = Inner {
        roster: Some(part),
        ..Inner::default()
    };
    let rotation = RotationKeys {
        grant_commitment: common::example(&format!("{label}/grant-commitment")),
        read: read_credential(&content).public,
        upload: upload_key(&common::example(&format!("{label}/upload"))).public,
    };
    let body = VisiblePart {
        seal: Seal::Rotation(rotation),
        deliveries: Vec::new(),
        sealed: inner.seal_with(&key, &space.0, &p_device, seq, &[0x6e; 24]),
        nonce: None,
        commitment: body_commitment(&key),
        twin: Some(twin.0),
    }
    .encode();
    let granted = sign_onto(
        &mut fixture,
        "P grants B administer",
        &p,
        frasil_events::kind::SPACE,
        seq,
        Some(removal),
        vec![removal, twin],
        &checkpoints,
        body,
    );
    fixture
        .keys
        .rotations
        .insert(granted, zeroize::Zeroizing::new(content));

    // The record object, as the existing twin check derives it.
    let others = OtherLogs::none();
    let checking = Options {
        twins: Twins::Skeleton,
        ..options(&fixture, &others)
    };
    let none = BTreeMap::<EventId, Vec<u8>>::new();
    let no_envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let past = fixture.log.past(checkpoint);
    let record = Checkpointed::new(
        CheckpointInputs {
            log: &fixture.log,
            options: checking,
            objects: &none,
            envelopes: &no_envelopes,
            slots: None,
        },
        None,
    )
    .record_for(&past)
    .expect("the record of its past");
    let objects = BTreeMap::from([(checkpoint, record.encode())]);
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: checking,
        objects: &objects,
        envelopes: &no_envelopes,
        slots: None,
    };
    let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
    let after: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|&id| id != checkpoint && fixture.log.precedes(checkpoint, id))
        .collect();
    let expect = |label: &str, judged: &frasil_space::Judged| {
        assert_eq!(judged.chain, vec![checkpoint], "{label}: the chain");
        // A's vote is concurrent with its removal, so the unit is refused;
        // it still votes, as any event of A after the checkpoint does.
        for (id, what, verdict) in [
            (vote, "A's vote", "RefusedByRemoval"),
            (removal, "the removal of A", "valid"),
            (granted, "the grant of B", "valid"),
        ] {
            assert_eq!(
                judged.statuses.get(&id).map(show).as_deref(),
                Some(verdict),
                "{label}: {what}"
            );
        }
        assert!(
            !judged.roster.is_administrator(&fixture.device_key("A")),
            "{label}: A is removed"
        );
        assert!(
            judged.roster.is_administrator(&b.device_id().0),
            "{label}: B administers"
        );
    };

    // A replica that kept everything.
    let full = Checkpointed::new(inputs, None);
    expect("kept everything", &full.judge(&all));

    // A replica that forgot under the checkpoint, keeping its cut and the
    // root and enrolment the cut names.
    let mut holds = after.clone();
    holds.extend([
        checkpoint,
        cut,
        fixture.id("P0: root"),
        fixture.id("A1 enrols"),
    ]);
    forgotten(&fixture, inputs, checkpoint, &holds, |forgot, held| {
        expect("forgot under the checkpoint", &forgot.judge(held));
    });
}

#[test]
fn a_reserved_cut_holds_the_checkpoint_at_a_full_replica() {
    let case = &frasil_testkit::vectors::family::<Json>("peers.json", "skeleton_cuts")["held_cut"];
    let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
    let checkpoint = fixture.id(text(&case["replica"], "checkpoint_event"));
    let after = fixture.id(text(&case["replica"], "after_event"));
    let others = OtherLogs::none();
    let objects = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: Options {
            twins: Twins::Skeleton,
            ..options(&fixture, &others)
        },
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let record = Checkpointed::new(inputs, None)
        .record_for(&fixture.log.past(checkpoint))
        .unwrap();
    let objects = BTreeMap::from([(checkpoint, record.encode())]);
    let full = Checkpointed::new(
        CheckpointInputs {
            objects: &objects,
            ..inputs
        },
        None,
    );
    assert!(full.extension_required(checkpoint));
    assert_eq!(show(&full.validity(checkpoint)), "ExtensionRequired");
    let all = fixture.log.canonical().into_iter().collect();
    assert_eq!(
        show(&full.judge(&all).statuses[&after]),
        "ExtensionRequired"
    );
}

#[test]
fn a_reserved_cut_after_a_retained_predecessor_is_held_at_both_replicas() {
    use frasil_base::cbor::{self, Value};
    use frasil_crypto::fixtures::{FixtureKeys, fixture_mldsa_seed};
    use frasil_crypto::schemes::Signer;
    let case =
        &frasil_testkit::vectors::family::<Json>("peers.json", "skeleton_cuts")["heard_vote"];
    let prefix = text(case, "history_prefix");
    let fixture = Fixture::new(prefix, &case["events"]);
    let first = fixture.id("P checkpoints (1)");
    let original_second = fixture.id("P checkpoints (2)");
    let original_cut = fixture.id("P0: cut of P checkpoints (2)");
    let others = OtherLogs::none();
    let empty = BTreeMap::<EventId, Vec<u8>>::new();
    let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
    let checking = Options {
        twins: Twins::Skeleton,
        ..options(&fixture, &others)
    };
    let inputs = CheckpointInputs {
        log: &fixture.log,
        options: checking,
        objects: &empty,
        envelopes: &envelopes,
        slots: None,
    };
    let record = Checkpointed::new(inputs, None)
        .record_for(&fixture.log.past(first))
        .unwrap();
    let first_object = BTreeMap::from([(first, record.encode())]);
    let original = Checkpointed::new(
        CheckpointInputs {
            objects: &first_object,
            ..inputs
        },
        None,
    );
    let second_record = original
        .record_naming(&fixture.log.past(original_second), Some(first))
        .unwrap();
    let originals = BTreeMap::from([
        (first, record.encode()),
        (original_second, second_record.encode()),
    ]);
    let original = Checkpointed::new(
        CheckpointInputs {
            objects: &originals,
            ..inputs
        },
        None,
    );
    assert_eq!(
        original
            .judge(&fixture.log.canonical().into_iter().collect())
            .chain,
        vec![first, original_second]
    );

    // Preserve the checkpoint's self reference, sealed part and record;
    // only its cut's reserved key and the visible reference to that cut change.
    let seed = common::example(&format!("{prefix}/P0/ed25519"));
    let pseudonym = Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), None);
    let founder =
        FixtureKeys::from_identity_seed(&common::example(&format!("{prefix}/P/ed25519"))).signer();
    let unsigned = |event: &frasil_events::Event| frasil_events::Envelope {
        kind: event.kind(),
        log: event.log(),
        ed: *event.ed(),
        kc: *event.kc(),
        seq: event.seq(),
        prev: event.prev(),
        parents: event.parents().to_vec(),
        cuts: event.cuts().to_vec(),
        body: event.unverified_body().to_vec(),
        scheme: event.scheme(),
    };
    let mut cut = unsigned(fixture.log.event(original_cut).unwrap());
    let Value::Map(mut body) = cbor::decode(&cut.body).unwrap() else {
        panic!("map")
    };
    body.insert(9, Value::Unsigned(1));
    cut.body = Value::Map(body).encode();
    let cut = frasil_events::decode(&cut.sign(&pseudonym)).unwrap();
    let mut checkpoint = unsigned(fixture.log.event(original_second).unwrap());
    for parent in &mut checkpoint.parents {
        if *parent == original_cut {
            *parent = cut.id();
        }
    }
    checkpoint.parents.sort_unstable();
    let Value::Map(mut body) = cbor::decode(&checkpoint.body).unwrap() else {
        panic!("map")
    };
    body.insert(15, Value::Bytes(cut.id().0.to_vec()));
    checkpoint.body = Value::Map(body).encode();
    let checkpoint = frasil_events::decode(&checkpoint.sign(&founder)).unwrap();
    let second = checkpoint.id();
    let mut log = Log::new(fixture.log.genesis().clone()).unwrap();
    for (_, event) in fixture.events.iter().skip(1) {
        let next = if event.id() == original_cut {
            &cut
        } else if event.id() == original_second {
            &checkpoint
        } else {
            event
        };
        log.place(next.clone()).unwrap();
        if event.id() == original_second {
            break;
        }
    }
    let mut keys = fixture.keys.clone();
    keys.rotations
        .insert(second, keys.rotations[&original_second].clone());
    let objects = BTreeMap::from([(first, record.encode()), (second, second_record.encode())]);
    let inputs = CheckpointInputs {
        log: &log,
        options: Options {
            keys: &keys,
            ..checking
        },
        objects: &objects,
        envelopes: &envelopes,
        slots: None,
    };
    let full = Checkpointed::new(inputs, None);
    assert!(full.extension_required(second));
    let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
    assert_eq!(full.judge(&all).chain, vec![first]);
    assert_eq!(show(&full.validity(second)), "ExtensionRequired");

    let first_cut = fixture.id("P0: cut of P checkpoints (1)");
    let past = log.past(first);
    let mut retained: BTreeSet<EventId> = all
        .difference(&past)
        .copied()
        .chain(frasil_peers::cut::always_kept(&log, first_cut))
        .collect();
    retained.remove(&log.id());
    let forgotten = forgetting_log(&log, &retained);
    let forgot = Checkpointed::new(
        CheckpointInputs {
            log: &forgotten,
            ..inputs
        },
        Some(Kept {
            checkpoint: first,
            record: record.into(),
        }),
    );
    retained.insert(log.id());
    assert!(forgot.extension_required(second));
    assert_eq!(show(&forgot.validity(second)), "ExtensionRequired");
    assert!(forgot.judge(&retained).needs_later_rules);
    assert!(
        forgot.rivals(&retained).is_empty(),
        "the held successor is no rival of its predecessor"
    );
}

fn compare_stream(bytes: &[u8], chunk: usize) {
    use frasil_base::ErrorClass;
    use frasil_space::{ReadRecord, RecordFault, RecordMode, RecordSink, RecordStream};
    let oracle = Record::read(bytes);
    for mode in [RecordMode::Build, RecordMode::Summary] {
        let mut stream = RecordStream::new(mode);
        for part in bytes.chunks(chunk) {
            stream.feed(part);
        }
        match (stream.finish(), &oracle) {
            (Ok(ReadRecord::Built(record)), Ok(want)) => assert_eq!(&record, want),
            (Ok(ReadRecord::Summary(summary)), Ok(want)) => {
                assert_eq!(summary.epoch, want.epoch);
                assert_eq!(summary.previous, want.previous);
                assert_eq!(
                    summary.compared_digest,
                    frasil_crypto::primitives::sha256(&[&want.compared().encode()])
                );
                assert_eq!(summary.compared_digest, want.compared_digest());
                assert_eq!(want.record_digest(), digest(&want.encode()));
                assert_eq!(want.clone().with_space_fields(&summary.space_fields), *want);
            }
            (Err(RecordFault::Class(got)), Err(want)) => assert_eq!(&got, want),
            (Err(RecordFault::Extension(link)), Err(want)) => {
                assert_eq!(*want, ErrorClass::ExtensionRequired.into());
                assert_eq!(link, frasil_space::checkpoint_record::read_link(bytes));
            }
            _ => panic!("stream and whole record disagree"),
        }
    }
}

#[test]
fn streamed_record_vectors() {
    let case = family("checkpoints");
    let mut records = vec![bytes(&case["checkpoint"], "record")];
    records.extend(
        case["record_refusals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| bytes(r, "record")),
    );
    for record in records {
        for chunk in [1, 7, 256, record.len().max(1)] {
            compare_stream(&record, chunk);
        }
    }
}

#[test]
fn streamed_two_thousand_members() {
    use frasil_space::{MemberRef, MemberType};
    let case = family("checkpoints");
    let mut record = Record::read(&bytes(&case["checkpoint"], "record")).unwrap();
    let mut template = record.members[0].clone();
    template.member = MemberRef::person([0; 32]);
    template.level = frasil_space::Level::Write;
    template.rank = None;
    template.keys = None;
    template.slot = None;
    template.session = None;
    template.expires_at = None;
    template.claims = None;
    template.invite = None;
    template.claimant = None;
    template.notices.clear();
    template.floor = false;
    template.named.clear();
    assert_eq!(template.member.kind, MemberType::Person);
    record.members = (0..2000u64)
        .map(|i| {
            let mut entry = template.clone();
            entry.member.id[..8].copy_from_slice(&i.to_be_bytes());
            entry
        })
        .collect();
    let encoded = record.encode();
    assert!(Record::read(&encoded).is_ok());
    for chunk in [1, 7, 256, encoded.len()] {
        compare_stream(&encoded, chunk);
    }
}

#[test]
fn push_reader_matches_small_cbor_cases() {
    use frasil_base::{cbor, cbor_stream::PushReader};
    let cases: &[&[u8]] = &[
        &[0],
        &[0x18, 24],
        &[0x18, 0],
        &[0x9f, 0xff],
        &[0x43, 1, 2, 3],
        &[0x43, 1, 2],
        &[0x19, 1, 0],
        &[0x19, 1],
        &[0x61, 0xff],
        &[0x20],
        &[0xf4],
        &[0x81, 0x81, 0],
        &[0x80],
        &[0, 0],
        &[],
    ];
    for &data in cases {
        for depth in [0, 1, cbor::MAX_DEPTH] {
            for chunk in [1, 2, data.len().max(1)] {
                let mut reader = PushReader::new(depth);
                let mut failed = false;
                for part in data.chunks(chunk) {
                    reader.push(part);
                    loop {
                        match reader.next() {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                }
                assert_eq!(
                    !failed && reader.finish().is_ok(),
                    cbor::decode_with_depth(data, depth).is_ok(),
                    "{data:?}, depth {depth}, chunk {chunk}"
                );
            }
        }
    }
}

/// Strings beyond the schema's lengths and arrays beyond its counts, in
/// every place a record holds them, read as the whole record does.
#[test]
fn streamed_records_beyond_the_schemas_bounds() {
    use frasil_base::cbor::{Map, Value};
    let case = family("checkpoints");
    let encoded = bytes(&case["checkpoint"], "record");
    let Value::Map(root) = frasil_base::cbor::decode(&encoded).unwrap() else {
        panic!("a record is a map");
    };
    let long_bytes = || Value::Bytes(vec![9; 5000]);
    let long_text = || Value::Text("é".repeat(2600));
    let many = |n: usize, item: Value| Value::Array(vec![item; n]);
    let policy =
        |pairs: Vec<(u64, Value)>| Value::Bytes(Value::Map(pairs.into_iter().collect()).encode());
    let mut variants: Vec<Map> = Vec::new();
    let mut with = |edit: &dyn Fn(&mut Map)| {
        let mut map = root.clone();
        edit(&mut map);
        variants.push(map);
    };
    // The policy: another version, version 1, not a map, key 1 missing or
    // not an integer, each holding a long string.
    with(&|m| {
        m.insert(5, policy(vec![(1, Value::Unsigned(2)), (2, long_bytes())]));
    });
    with(&|m| {
        m.insert(5, policy(vec![(0, long_text()), (1, Value::Unsigned(3))]));
    });
    with(&|m| {
        m.insert(5, policy(vec![(1, Value::Unsigned(1)), (2, long_bytes())]));
    });
    with(&|m| {
        m.insert(5, policy(vec![(2, long_bytes())]));
    });
    with(&|m| {
        m.insert(5, policy(vec![(1, long_bytes())]));
    });
    with(&|m| {
        m.insert(5, Value::Bytes(Value::Array(vec![long_bytes()]).encode()));
    });
    with(&|m| {
        let mut bad = policy(vec![(1, Value::Unsigned(2)), (2, long_bytes())]);
        if let Value::Bytes(b) = &mut bad {
            b.push(0);
        }
        m.insert(5, bad);
    });
    // Root keys: `previous` long, a later document's key long.
    with(&|m| {
        m.insert(3, long_bytes());
    });
    with(&|m| {
        m.insert(12, long_text());
    });
    with(&|m| {
        m.insert(12, many(5000, Value::Unsigned(0)));
    });
    // Rows of tips, forks and heard members beyond their counts.
    with(&|m| {
        m.insert(6, many(2, many(4000, Value::Unsigned(1))));
    });
    with(&|m| {
        m.insert(
            7,
            many(2, Value::Array(vec![long_bytes(), Value::Unsigned(1)])),
        );
    });
    with(&|m| {
        m.insert(8, many(1, many(7, long_bytes())));
    });
    // Member entries: each key long, or beyond its count, and a later
    // document's key or member type alongside.
    type Edit<'a> = Box<dyn Fn(&mut Map) + 'a>;
    let entry_edits: Vec<Edit<'_>> = vec![
        Box::new(|e| {
            e.insert(4, long_text());
        }),
        Box::new(|e| {
            e.insert(
                3,
                many(
                    40,
                    Value::Array(vec![Value::Text("a".into()), Value::Unsigned(0)]),
                ),
            );
        }),
        Box::new(|e| {
            e.insert(20, many(3000, Value::Unsigned(0)));
        }),
        Box::new(|e| {
            e.insert(18, many(3000, many(4, Value::Unsigned(0))));
        }),
        Box::new(|e| {
            e.insert(13, many(4, long_bytes()));
        }),
        Box::new(|e| {
            e.insert(9, many(5, Value::Unsigned(1)));
        }),
        Box::new(|e| {
            e.insert(25, long_bytes());
        }),
        Box::new(|e| {
            e.insert(25, many(5000, Value::Unsigned(0)));
        }),
        Box::new(|e| {
            e.insert(
                1,
                Value::Array(vec![Value::Unsigned(7), long_bytes(), Value::Unsigned(0)]),
            );
        }),
        Box::new(|e| {
            e.insert(1, Value::Array(vec![Value::Unsigned(1), long_bytes()]));
        }),
    ];
    for edit in &entry_edits {
        for at in [0, usize::MAX] {
            with(&|m| {
                let Some(Value::Array(members)) = m.get_mut(&4) else {
                    panic!("members");
                };
                let at = at.min(members.len() - 1);
                if let Value::Map(entry) = &mut members[at] {
                    edit(entry);
                }
            });
        }
    }
    let mut seen = BTreeSet::new();
    for map in variants {
        let data = Value::Map(map).encode();
        seen.insert(format!("{:?}", Record::read(&data).err()));
        for chunk in [1, 977, data.len()] {
            compare_stream(&data, chunk);
        }
    }
    // Each class a long item can leave the record with is reached.
    assert_eq!(seen.len(), 3, "{seen:?}");
}
