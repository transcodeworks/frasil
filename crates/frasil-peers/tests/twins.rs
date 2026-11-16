//! `peers.json`: `twin_checks` (peers.md, section 3.13, "What replicas
//! check").
//!
//! Every case gives its history and its prefix; the twin checks replay on
//! each through [`TwinChecks`], with the roster's facts the test derives as
//! the reference's builder does. The cases that give the roster event and
//! its twin are also checked from those bytes alone, deriving `c(R)`, in
//! the order of the checks.

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, decode};
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::{body_key, read_credential};
use frasil_peers::PeersClass;
use frasil_peers::body::{SlotId, StorageBody};
use frasil_peers::cut::{RecordSlot, entry_pseudonym};
use frasil_peers::derive::{twin_commitment, twin_secret};
use frasil_peers::skeleton::{Skeleton, named_twin};
use frasil_peers::twins::{BadTwin, TwinChecks, TwinFailure};
use serde_json::Value as Json;
use std::collections::BTreeSet;

/// `c(R)` of a rotating roster event of the reference's builder, from its
/// content key `<prefix>/<label>/content-key`, its space, author and seq,
/// under `salt`.
fn commitment(
    prefix: &str,
    label: &str,
    space: &EventId,
    author: &DeviceId,
    seq: u64,
    salt: &[u8; 32],
) -> [u8; 32] {
    let secret = example(&format!("{prefix}/{label}/content-key"));
    let key = body_key(&secret, space.as_bytes(), author, seq);
    twin_commitment(author, seq, &twin_secret(&key), salt)
}

fn change(event: &Event) -> StorageBody {
    let body = StorageBody::read(event.unverified_body()).unwrap();
    assert!(matches!(body, StorageBody::Change { .. }));
    body
}

fn twin_of(body: &StorageBody) -> [u8; 32] {
    match body {
        StorageBody::Change { twin, .. } => *twin,
        _ => unreachable!(),
    }
}

fn salt_of(body: &StorageBody) -> [u8; 32] {
    match body {
        StorageBody::Change { salt, .. } => *salt,
        _ => unreachable!(),
    }
}

/// A case that gives the roster event `P grants B administer` and its twin:
/// the first of the checks the bytes show that fails.
fn case_with_bytes(case: &Json) -> Option<BadTwin> {
    const PREFIX: &str = "storage/replica";
    let r = decode(&hex(&case["roster_event"])).unwrap();
    let s = decode(&hex(&case["twin"])).unwrap();
    let visible = VisiblePart::read(r.unverified_body(), r.author(), r.seq()).unwrap();
    let secret = example(&format!("{PREFIX}/P grants B administer/content-key"));
    assert_eq!(
        visible.rotation().unwrap().read,
        read_credential(&secret).public
    );
    assert_eq!(r.author(), &device(PREFIX, "P"));
    // R names the twin and cites it.
    assert_eq!(named_twin(&r), Some(s.id()));
    assert!(r.parents().contains(&s.id()));
    let body = change(&s);
    let c = commitment(
        PREFIX,
        "P grants B administer",
        &r.log_id(),
        r.author(),
        r.seq(),
        &salt_of(&body),
    );
    // 3. twin = c(R) under its own salt.
    if twin_of(&body) != c {
        return Some(BadTwin::Commitment);
    }
    // 4. Its author is P's pseudonym, P0, enrolled in P's administrator slot.
    if s.author() != &pseudonym_id(PREFIX, "P0") {
        return Some(BadTwin::Author);
    }
    // 6. One grant, for B.
    if body.grants().len() != 1 {
        return Some(BadTwin::Grants);
    }
    None
}

fn reason(value: &Json) -> Option<&str> {
    value.as_str()
}

#[test]
fn twins_against_their_roster_events() {
    let t = family("twin_checks");
    for name in ["passes", "wrong_grants", "another_administrators_pseudonym"] {
        let case = &t[name];
        let found = case_with_bytes(case);
        let verdict = if found.is_some() { "BadTwin" } else { "valid" };
        assert_eq!(verdict, text(&case["verdict"]), "{name}");
        assert_eq!(found.map(BadTwin::name), reason(&case["reason"]), "{name}");
    }
}

/// The verdict a case gives, as the twin checks return it. A roster event
/// that names no twin is roster.md's `TwinRequired`, which the twin checks
/// find as `names no twin`.
fn expected(case: &Json) -> Result<(), TwinFailure> {
    match text(&case["verdict"]) {
        "valid" => Ok(()),
        "NoTwin" => Err(TwinFailure::NoTwin),
        "TwinRequired" => Err(TwinFailure::BadTwin(BadTwin::NamesNoTwin)),
        "BadTwin" => {
            let reason = reason(&case["reason"]).expect("a reason");
            let found = [
                BadTwin::NamesNoTwin,
                BadTwin::Root,
                BadTwin::NotAChange,
                BadTwin::Commitment,
                BadTwin::Author,
                BadTwin::Forked,
                BadTwin::Grants,
                BadTwin::Ranks,
                BadTwin::Parents,
                BadTwin::CiteTogether,
                BadTwin::Record,
            ]
            .into_iter()
            .find(|b| b.name() == reason)
            .unwrap_or_else(|| panic!("a reason {reason}"));
            Err(TwinFailure::BadTwin(found))
        }
        other => panic!("a verdict {other}"),
    }
}

/// The twin checks of a case's last administrator grant, replayed from its
/// history over `view` (every event when `None`). P founds the space and
/// grants A, then B, administer, each the twin's only grantee.
fn replay(case: &Json, view: Option<&BTreeSet<EventId>>) -> Result<(), TwinFailure> {
    let prefix = text(&case["prefix"]);
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, view);
    if let Some(peer) = case.get("peer").filter(|_| view.is_none()) {
        check_summary(prefix, &skeleton, &history, peer);
    }
    let mut roster = vec![("P creates the space", grants(prefix, &["P"]))];
    for (name, device) in [
        ("P grants A administer", "A"),
        ("P grants B administer", "B"),
    ] {
        if history.ids.contains_key(name) {
            roster.push((name, grants(prefix, &[device])));
        }
    }
    let target = history.id(roster.last().expect("a grant").0);
    let mut facts = Facts::new(prefix, &history, &["P", "A", "B"], &roster);
    facts.administrators = vec![device(prefix, "P"), device(prefix, "A")];
    TwinChecks::new(&skeleton, &facts).check(target)
}

#[test]
fn every_case_replays_from_its_history() {
    let t = family("twin_checks");
    for name in [
        "passes",
        "wrong_grants",
        "another_administrators_pseudonym",
        "parent_not_a_skeleton_event",
        "names_no_twin",
        "unnamed_change_with_its_commitment",
        "forked_pseudonym",
    ] {
        let case = &t[name];
        assert_eq!(replay(case, None), expected(case), "{name}");
    }
    // A roster event that names a twin it does not cite: pending over the
    // view without the twin, void (step 7) once the twin is held.
    let missing = &t["twin_not_cited"];
    let history = History::of(&missing["events"]);
    let holds: BTreeSet<EventId> = missing["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| history.id(text(n)))
        .collect();
    assert_eq!(replay(missing, Some(&holds)), expected(missing));
    assert_eq!(
        replay(missing, None),
        Err(TwinFailure::BadTwin(BadTwin::Parents))
    );
    assert_eq!(
        reason(&missing["reason_with_the_twin"]),
        Some(BadTwin::Parents.name())
    );
}

#[test]
fn a_twin_whose_parent_is_not_a_skeleton_event() {
    const PREFIX: &str = "storage/replica-parents";
    let case = &family("twin_checks")["parent_not_a_skeleton_event"];
    let s = decode(&hex(&case["twin"])).unwrap();
    let body = change(&s);
    // P's roster event follows its genesis, its grant to A and its unit.
    let c = commitment(
        PREFIX,
        "P grants B administer",
        &s.log_id(),
        &device(PREFIX, "P"),
        4,
        &salt_of(&body),
    );
    // Steps 3 to 6 hold: the commitment, P0's authorship, one grant. The
    // twin cites a unit as well as the skeleton's heads: step 7 fails.
    assert_eq!(twin_of(&body), c);
    assert_eq!(s.author(), &pseudonym_id(PREFIX, "P0"));
    assert_eq!(body.grants().len(), 1);
    assert!(s.parents().len() >= 2);
    assert_eq!(text(&case["verdict"]), PeersClass::BadTwin.name());
    assert_eq!(reason(&case["reason"]), Some(BadTwin::Parents.name()));
}

#[test]
fn verdicts_without_bytes() {
    let t = family("twin_checks");
    // A roster event that names a twin it does not cite: pending while the
    // twin is not held, void (step 7) once it is.
    let missing = &t["twin_not_cited"];
    assert_eq!(text(&missing["verdict"]), PeersClass::NoTwin.name());
    assert_eq!(text(&missing["roster_event"]), PeersClass::NoTwin.name());
    assert_eq!(text(&missing["with_the_twin"]), PeersClass::BadTwin.name());
    assert_eq!(
        reason(&missing["reason_with_the_twin"]),
        Some(BadTwin::Parents.name())
    );
    // A twin by a pseudonym forked at it: step 5.
    let forked = &t["forked_pseudonym"];
    assert_eq!(text(&forked["verdict"]), PeersClass::BadTwin.name());
    assert_eq!(reason(&forked["reason"]), Some(BadTwin::Forked.name()));
    // A roster event that names no twin is roster.md's TwinRequired.
    assert_eq!(text(&t["names_no_twin"]["verdict"]), "TwinRequired");
}

#[test]
fn a_junk_change_with_a_roster_events_commitment() {
    const PREFIX: &str = "storage/replica-junk";
    let case = &family("twin_checks")["unnamed_change_with_its_commitment"];
    let junk = decode(&hex(&case["junk"])).unwrap();
    let body = change(&junk);
    // A1 copies the commitment and salt of P's twin of its third roster
    // event, lowering P's administrator slot. No event names it, so the
    // peer never applies it, and the roster event's own twin passes.
    let c = commitment(
        PREFIX,
        "P grants B administer",
        &junk.log_id(),
        &device(PREFIX, "P"),
        3,
        &salt_of(&body),
    );
    assert_eq!(twin_of(&body), c);
    assert_eq!(junk.author(), &pseudonym_id(PREFIX, "A1"));
    assert!(body.lowered().is_some());
    assert_eq!(text(&case["verdict"]), "valid");
    let statuses = case["peer"]["events"].as_object().unwrap();
    assert_eq!(
        statuses["A1: a junk change with the commitment of P's twin"],
        PeersClass::Unnamed.name()
    );
}

#[test]
fn a_foreign_enrolment_and_a_planted_administrator_slot() {
    const PREFIX: &str = "storage/replica-foreign";
    let case = &family("twin_checks")["foreign_enrolment_and_planted_administrator_slot"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("foreign", &skeleton, &history, &case["peer"]);
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        ("P grants A administer", grants(PREFIX, &["A"])),
    ];
    let mut facts = Facts::new(PREFIX, &history, &["P", "A", "Q"], &roster);
    facts.administrators = vec![device(PREFIX, "P"), device(PREFIX, "A")];
    let checks = TwinChecks::new(&skeleton, &facts);
    for (r, _) in &roster {
        assert_eq!(checks.check(history.id(r)), Ok(()), "{r}");
    }
    assert_eq!(
        bindings_json(&checks, PREFIX, &["P", "A", "Q", "P0", "X"]),
        case["bindings"]
    );
    assert_eq!(slots_json(&checks.planted(), &history), case["planted"]);
    assert_eq!(
        case["planted"][0][0],
        frasil_testkit::hex::encode(example("storage/planted"))
    );
    for (name, justified) in case["justified"].as_object().unwrap() {
        assert_eq!(
            Json::from(checks.justified(history.id(name))),
            *justified,
            "{name}"
        );
    }
    // A's administrator slot is justified by the foreign enrolment alone:
    // A is an administrator in the roster, and the slot is not planted.
    let slot_a = SlotId::new(
        checks
            .commitment(history.id("P grants A administer"))
            .unwrap()
            .1
            .expect("a twin"),
        0,
        history.id("P0: twin of P grants A administer"),
    );
    assert!(!checks.planted().contains(&slot_a));
    assert_eq!(
        checks.slot_device(slot_a),
        Some(device(PREFIX, "A")),
        "the device of A's administrator slot"
    );
}

/// A root whose founder keys are not the ones the genesis's `kc` commits
/// to: the peer refuses it (`NotCommitted`), and a replica judges the
/// genesis `BadTwin`.
#[test]
fn a_root_whose_founder_keys_are_not_committed() {
    let case = &family("twin_checks")["root_founder_keys_not_committed"];
    let prefix = text(&case["prefix"]);
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    let root = decode(&hex(&case["root"])).unwrap();
    let Some(StorageBody::Root {
        founder_mldsa,
        founder_xwing,
        ..
    }) = skeleton.body_of(root.id())
    else {
        panic!("a root")
    };
    assert_eq!(*founder_mldsa, hex(&case["founder_keys_named"]["mldsa"]));
    assert_eq!(*founder_xwing, hex(&case["founder_keys_named"]["xwing"]));
    let status = skeleton.status(root.id()).expect("a status");
    assert_eq!(status_text(status, &history), text(&case["peer"]));
    assert!(skeleton.root().is_none());
    let roster = [("P creates the space", grants(prefix, &["P"]))];
    let facts = Facts::new(prefix, &history, &["P"], &roster);
    let verdict = TwinChecks::new(&skeleton, &facts).check(history.log.id());
    assert_eq!(verdict, Err(TwinFailure::BadTwin(BadTwin::Root)));
    assert_eq!(verdict.unwrap_err().class().name(), text(&case["replica"]));
}

#[test]
fn a_checkpoints_twin_is_its_cut_checked_against_the_record() {
    // peers.json's `skeleton_cuts`: P checkpoints, its pseudonym signing the
    // cut first (roster.md, 3.15.8, "Twins and the skeleton").
    let case = frasil_testkit::vectors::family::<Json>("peers.json", "skeleton_cuts");
    let prefix = text(&case["history_prefix"]);
    let history = History::of(&case["events"]);
    let checkpoint = history.id("P checkpoints");
    let cut_id = history.id("P0: cut of P checkpoints");
    let mut view: BTreeSet<EventId> = history.log.past(checkpoint);
    view.insert(checkpoint);
    let skeleton = Skeleton::new(&history.log, Some(&view));
    let roster = vec![
        ("P creates the space", grants(prefix, &["P"])),
        ("P grants A administer", grants(prefix, &["A"])),
        ("P checkpoints", Default::default()),
    ];
    let mut facts = Facts::new(prefix, &history, &["P", "A"], &roster);
    facts.administrators = vec![device(prefix, "P"), device(prefix, "A")];
    let checks = TwinChecks::new(&skeleton, &facts);
    let Some(StorageBody::Cut(cut)) = skeleton.body_of(cut_id).cloned() else {
        panic!("the cut");
    };
    // The record's administrators, each with its slot and pseudonym.
    let record: Vec<Option<RecordSlot>> = cut
        .slots
        .iter()
        .map(|entry| {
            Some(RecordSlot {
                slot: entry.slot,
                pseudonym: entry_pseudonym(&history.log, entry),
            })
        })
        .collect();
    assert_eq!(record.len(), 2);
    assert_eq!(checks.check_checkpoint(checkpoint, &record), Ok(()));
    // As a change's twin, a cut is not one.
    assert_eq!(
        checks.check(checkpoint),
        Err(TwinFailure::BadTwin(BadTwin::NotAChange))
    );
    // A slot of the cut no `slot` entry names, and an administrator without
    // a slot, pass: such slots map to no device (peers.md, "Skeleton
    // cuts").
    assert_eq!(checks.check_checkpoint(checkpoint, &record[..1]), Ok(()));
    let mut none = record.clone();
    none.push(None);
    assert_eq!(checks.check_checkpoint(checkpoint, &none), Ok(()));
    // A record entry that names another pseudonym, or a slot the cut lacks.
    let bad = TwinFailure::BadTwin(BadTwin::Record);
    let mut other = record.clone();
    other[1] = Some(RecordSlot {
        pseudonym: Some(device(prefix, "A")),
        ..other[1].unwrap()
    });
    assert_eq!(checks.check_checkpoint(checkpoint, &other), Err(bad));
    let mut absent = record.clone();
    absent[0] = Some(RecordSlot {
        slot: frasil_peers::body::SlotId::new([0; 32], 0, EventId([0; 32])),
        ..absent[0].unwrap()
    });
    assert_eq!(checks.check_checkpoint(checkpoint, &absent), Err(bad));
    // The standing entries the record gives: the cut's own pass; another
    // order, another dormant value, or one entry more or less, do not.
    assert_eq!(
        checks.check_checkpoint_standing(checkpoint, &record, &cut.standing),
        Ok(())
    );
    let mut reordered = cut.standing.clone();
    reordered.reverse();
    assert_eq!(
        checks.check_checkpoint_standing(checkpoint, &record, &reordered),
        Ok(())
    );
    let mut other_order = cut.standing.clone();
    let (first, second) = (other_order[0].order, other_order[1].order);
    other_order[0].order = second;
    other_order[1].order = first;
    let mut dormant = cut.standing.clone();
    dormant[0].dormant = 1;
    for standing in [&other_order[..], &dormant[..], &cut.standing[..1]] {
        assert_eq!(
            checks.check_checkpoint_standing(checkpoint, &record, standing),
            Err(bad)
        );
    }
    // Without the cut, the checkpoint waits for it.
    let mut without = view.clone();
    without.remove(&cut_id);
    without.remove(&checkpoint);
    let held = Skeleton::new(&history.log, Some(&without));
    assert_eq!(
        TwinChecks::new(&held, &facts).check_checkpoint(checkpoint, &record),
        Err(TwinFailure::NoTwin)
    );
}
