//! `peers.json`: `resolution` and `stability` (peers.md, sections 3.12,
//! "The skeleton's resolution", and 3.14, "Stability at the peer").

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_peers::PeersClass;
use frasil_peers::skeleton::{Clock, Skeleton};
use frasil_peers::twins::{BadTwin, TwinChecks, TwinFailure};
use serde_json::Value as Json;
use std::collections::BTreeMap;

/// T, `erasure_timeout`, in the vectors: seven days.
const T: u64 = 7 * 24 * 3600;

/// Whether `target` is stable without a clock, within T of the lowerings'
/// first sights at 100, and at T.
fn stable_three_ways(skeleton: &Skeleton<'_>, target: EventId, lowerings: &[EventId]) -> [bool; 3] {
    let sights: BTreeMap<EventId, Reading> = lowerings.iter().map(|&x| (x, reading(100))).collect();
    let within = Clock {
        first_sights: &sights,
        now: reading(100 + T - 1),
        timeout: T,
    };
    let after = Clock {
        now: reading(100 + T),
        ..within
    };
    [
        skeleton.is_stable(target, None),
        skeleton.is_stable(target, Some(&within)),
        skeleton.is_stable(target, Some(&after)),
    ]
}

/// A mutual lowering of equal ranks: only the more senior author's
/// lowering, the root's slot's, stands, and the other author's concurrent
/// erasure is void.
#[test]
fn mutual_lowering() {
    let case = &family("resolution")["mutual_lowering"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("mutual lowering", &skeleton, &history, &case["peer"]);
    let root = skeleton.root().expect("a root");
    let survivors = skeleton.administrators();
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].maker, root);
}

/// Ranks (peers.md, "The skeleton's resolution"): a slot of rank 10 that
/// lowers one of rank 20 is `HigherRank`, as its roster event is at
/// replicas, and every administrator stays. Replicas check each twin
/// grant's rank against the rank its roster grant gives.
#[test]
fn ranks() {
    const PREFIX: &str = "storage/ranks";
    let case = &family("resolution")["ranks"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("ranks", &skeleton, &history, &case["peer"]);
    let removal = history.id("A1: twin of A, rank 10, removes B, rank 20");
    assert_eq!(
        skeleton.status(removal).map(|s| status_text(s, &history)),
        Some("HigherRank".to_string())
    );
    let rank_of = |name: &str| {
        let maker = history.id(name);
        let slot = skeleton
            .administrators()
            .into_iter()
            .find(|slot| slot.maker == maker)
            .expect("an administrator slot");
        skeleton.rank(slot)
    };
    assert_eq!(rank_of("P0: root"), frasil_peers::limits::MAX_RANK);
    assert_eq!(rank_of("P0: twin of P grants A administer at rank 10"), 10);
    assert_eq!(rank_of("P0: twin of P grants B administer at rank 20"), 20);

    // The twin checks: each grant's rank is the one its roster grant gives.
    let grant_a = "P grants A administer at rank 10";
    let grant_b = "P grants B administer at rank 20";
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        (grant_a, grants(PREFIX, &["A"])),
        (grant_b, grants(PREFIX, &["B"])),
        ("A, rank 10, removes B, rank 20", lowers(PREFIX, &["B"])),
    ];
    let mut facts = Facts::new(PREFIX, &history, &["P", "A", "B"], &roster);
    facts.ranks.insert(history.id(grant_a), vec![10]);
    facts.ranks.insert(history.id(grant_b), vec![20]);
    let checks = TwinChecks::new(&skeleton, &facts);
    for (name, _) in &roster {
        assert_eq!(checks.check(history.id(name)), Ok(()), "{name}");
    }
    // A roster grant of another rank than its twin's grant map: BadTwin.
    facts.ranks.insert(history.id(grant_a), vec![20]);
    let checks = TwinChecks::new(&skeleton, &facts);
    assert_eq!(
        checks.check(history.id(grant_a)),
        Err(TwinFailure::BadTwin(BadTwin::Ranks))
    );
}

/// A lowering backdated before its partner's enrolment does not undo the
/// enrolment: the enrolment stands, and of the two lowerings, of equal
/// ranks, the more senior author's (the root's slot), as the roster's
/// does, in whatever order the events arrive.
#[test]
fn late_enrolment() {
    let case = &family("resolution")["late_enrolment"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("late enrolment", &skeleton, &history, &case["peer"]);
    let rows = case["events"].as_array().unwrap();
    let (genesis, rest) = rows.split_first().unwrap();
    let decoded = |row: &Json| frasil_events::decode(&hex(&row["signed"])).unwrap();
    for turn in 0..rest.len() {
        // Each rotation of the reversed order: events arrive before their
        // parents, and the log holds them until the parents come.
        let mut order: Vec<&Json> = rest.iter().rev().collect();
        order.rotate_left(turn);
        let mut log = frasil_events::Log::new(decoded(genesis)).unwrap();
        for row in order {
            log.place(decoded(row)).unwrap();
        }
        assert_eq!(log.placed_count(), rows.len(), "every event placed");
        let arrived = History {
            log,
            names: history.names.clone(),
            ids: history.ids.clone(),
        };
        let skeleton = Skeleton::new(&arrived.log, None);
        check_summary(
            &format!("late enrolment, arrival order {turn}"),
            &skeleton,
            &arrived,
            &case["peer"],
        );
    }
}

#[test]
fn concurrent_enrolments() {
    const PREFIX: &str = "storage/enrolments";
    let case = &family("resolution")["concurrent_enrolments"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("concurrent enrolments", &skeleton, &history, &case["peer"]);
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        ("P grants A administer", grants(PREFIX, &["A"])),
    ];
    let facts = Facts::new(PREFIX, &history, &["P", "A"], &roster);
    let checks = TwinChecks::new(&skeleton, &facts);
    assert_eq!(
        bindings_json(&checks, PREFIX, &["P", "A", "P0", "A1", "X"]),
        case["bindings"]
    );
}

#[test]
fn disown_attack() {
    let case = &family("resolution")["disown_attack"];
    let history = History::of(&case["events"]);
    let response = [
        "P removes A, concurrently with A1's disowns",
        "P0: twin of P removes A, concurrently with A1's disowns",
    ];
    let before = history.view_without(&response);
    let skeleton = Skeleton::new(&history.log, Some(&before));
    check_summary(
        "before the response",
        &skeleton,
        &history,
        &case["peer_before_response"],
    );
    assert_eq!(
        slots_json(&skeleton.administrators(), &history),
        case["merged_administrators"]
    );
    assert_eq!(
        slots_json(&skeleton.stability_set(None), &history),
        case["stability_set"]
    );
    let erase = history.id("A1 erases the space");
    let disowns = [
        history.id("A1 disowns P's administrator slot"),
        history.id("A1 disowns B's administrator slot"),
    ];
    assert_eq!(
        Json::from(skeleton.acknowledged(erase, &skeleton.administrators())),
        case["erase_stable_without_the_rule"]
    );
    let [stable, within, after] = stable_three_ways(&skeleton, erase, &disowns);
    assert_eq!(Json::from(stable), case["erase_stable"]);
    assert_eq!(Json::from(within), case["erase_stable_within_T"]);
    assert_eq!(Json::from(after), case["erase_stable_after_T"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary(
        "after the response",
        &skeleton,
        &history,
        &case["peer_after_response"],
    );
}

#[test]
fn lowers_named_by_key_events() {
    let case = &family("resolution")["lowers_named_by_key_events"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("key events", &skeleton, &history, &case["peer"]);
    let lowers = [
        history.id("A1: a change lowering P's administrator slot"),
        history.id("A1: a change lowering B's administrator slot"),
    ];
    assert_eq!(
        Json::from(lowers.iter().all(|&x| skeleton.is_valid(x))),
        case["lowers_applied"]
    );
    let erase = history.id("A1 erases the space");
    assert_eq!(
        Json::from(skeleton.acknowledged(erase, &skeleton.administrators())),
        case["erase_stable_without_the_rule"]
    );
    let [stable, within, after] = stable_three_ways(&skeleton, erase, &lowers);
    assert_eq!(Json::from(stable), case["erase_stable"]);
    assert_eq!(Json::from(within), case["erase_stable_within_T"]);
    assert_eq!(Json::from(after), case["erase_stable_after_T"]);
}

#[test]
fn removal_cost() {
    let case = &family("resolution")["removal_cost"];
    let history = History::of(&case["events"]);
    let before = history.view_without(&["A1 acknowledges its removal"]);
    let skeleton = Skeleton::new(&history.log, Some(&before));
    let erase = history.id("P0 erases the space");
    let lowering = history.id("P0: twin of P removes A");
    let [stable, within, after] = stable_three_ways(&skeleton, erase, &[lowering]);
    assert_eq!(Json::from(stable), case["erase_stable"]);
    assert_eq!(Json::from(within), case["erase_stable_within_T"]);
    assert_eq!(Json::from(after), case["erase_stable_after_T"]);
    let acknowledged = Skeleton::new(&history.log, None);
    assert_eq!(
        Json::from(acknowledged.is_stable(erase, None)),
        case["erase_stable_once_A_acknowledges"]
    );
}

#[test]
fn repeated_commitment() {
    let case = &family("resolution")["repeated_commitment"];
    let history = History::of(&case["events"]);
    let erase = history.id("A1 erases the space");
    let p0 = "P0 acknowledges the erasure";
    let b1 = "B1 acknowledges the erasure";
    let disown = "P0 disowns the copy of B's administrator slot";
    let skeleton = Skeleton::new(&history.log, Some(&history.view_without(&[p0])));
    check_summary(
        "before the acknowledgements",
        &skeleton,
        &history,
        &case["peer_before_acknowledgements"],
    );
    assert_eq!(
        slots_json(&skeleton.stability_set(None), &history),
        case["stability_set"]
    );
    assert_eq!(Json::from(skeleton.is_valid(erase)), case["erase_valid"]);
    assert_eq!(
        Json::from(skeleton.is_stable(erase, None)),
        case["erase_stable"]
    );
    let skeleton = Skeleton::new(&history.log, Some(&history.view_without(&[b1])));
    assert_eq!(
        Json::from(skeleton.is_stable(erase, None)),
        case["erase_stable_once_P0_acknowledges"]
    );
    let skeleton = Skeleton::new(&history.log, Some(&history.view_without(&[disown])));
    assert_eq!(
        Json::from(skeleton.is_stable(erase, None)),
        case["erase_stable_once_B1_acknowledges"]
    );
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("after the disown", &skeleton, &history, &case["peer"]);
    assert_eq!(
        slots_json(skeleton.lowers(history.id(disown)), &history),
        case["disown_lowers"]
    );
}

#[test]
fn stability() {
    let s = family("stability");
    assert_eq!(s["timeout"], T);
    let history = History::of(&family("skeleton")["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    let removal = history.id("P0: twin of P removes A");
    let seen = s["first_sight_of_the_removal"].as_u64().unwrap();
    assert_eq!(seen, 100);
    for (name, expected) in s["requests"].as_object().unwrap() {
        let id = history.id(name);
        let [stable, within, after] = stable_three_ways(&skeleton, id, &[removal]);
        let found = serde_json::json!({
            "valid": skeleton.is_valid(id),
            "stable": stable,
            "stable_within_T": within,
            "stable_after_T": after,
        });
        assert_eq!(&found, expected, "{name}");
    }
    let before_b = history.view_without(&["P grants B administer"]);
    let earlier = Skeleton::new(&history.log, Some(&before_b));
    for (name, expected) in s["before_b"].as_object().unwrap() {
        assert_eq!(
            Json::from(earlier.is_stable(history.id(name), None)),
            *expected,
            "{name}"
        );
    }
}

/// A copy of B's twin, its grant map whole, after the grant: B1 enrols B's
/// administrator slot with the copy in its past, and a disown of the copy
/// is justified and lowers it alone.
#[test]
fn grant_map_copy() {
    const PREFIX: &str = "storage/grant-map-copy";
    let case = &family("resolution")["grant_map_copy"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("grant-map copy", &skeleton, &history, &case["peer"]);
    let copy = history.id("A1: a copy of B's twin, its grant map whole");
    let enrol = history.id("B1: enrols, the copy in its past");
    assert!(history.log.precedes(copy, enrol));
    assert_eq!(Json::from(skeleton.repeats(copy)), case["copy_repeats"]);
    let b1 = pseudonym_id(PREFIX, "B1");
    assert_eq!(
        slots_json(&[skeleton.slot_of(&b1).expect("enrolled")], &history),
        case["enrolled"]
    );
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        ("P grants A administer", grants(PREFIX, &["A"])),
        ("P grants B administer", grants(PREFIX, &["B"])),
    ];
    let mut facts = Facts::new(PREFIX, &history, &["P", "A", "B"], &roster);
    facts.administrators = vec![
        device(PREFIX, "P"),
        device(PREFIX, "A"),
        device(PREFIX, "B"),
    ];
    let checks = TwinChecks::new(&skeleton, &facts);
    for (r, _) in &roster {
        assert_eq!(checks.check(history.id(r)), Ok(()), "{r}");
    }
    assert_eq!(slots_json(&checks.planted(), &history), case["planted"]);
    for (name, justified) in case["justified"].as_object().unwrap() {
        let id = history.id(name);
        assert_eq!(Json::from(checks.justified(id)), *justified, "{name}");
        assert_eq!(
            slots_json(skeleton.lowers(id), &history),
            case["disown_lowers"]
        );
    }
    assert_eq!(
        bindings_json(&checks, PREFIX, &["P", "A", "B", "P0", "A1", "B1"]),
        case["bindings"]
    );
}

/// A lower of a copy of the root's commitment lowers the copy alone: the
/// founder's administrator slot stays in, enrolled to P0.
#[test]
fn lower_of_a_copy() {
    let case = &family("resolution")["lower_of_a_copy"];
    let history = History::of(&case["events"]);
    let lower = history.id("P0: a change lowering the copy");
    let before = history.view_without(&["P0: a change lowering the copy"]);
    let earlier = Skeleton::new(&history.log, Some(&before));
    assert_eq!(
        slots_json(&earlier.administrators(), &history),
        case["administrators_before"]
    );
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("lower of a copy", &skeleton, &history, &case["peer"]);
    assert_eq!(slots_json(skeleton.lowers(lower), &history), case["lowers"]);
    let root = skeleton.root().expect("a root");
    let founder = skeleton
        .slot_of(history.log.event(root).unwrap().author())
        .expect("the founder's slot");
    assert_eq!(slots_json(&[founder], &history), case["founder"]);
    assert!(skeleton.merged()[&founder].is_in);
}

/// A disown and a lower whose slot reference names a maker that did not
/// make that administrator slot are `UnknownAdministratorSlot`; a slot
/// reference of two elements is `Malformed`. Each in whatever order the
/// events arrive.
#[test]
fn unknown_makers() {
    let case = &family("resolution")["unknown_makers"];
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("unknown makers", &skeleton, &history, &case["peer"]);
    for (name, status) in case["peer"]["events"].as_object().unwrap() {
        if status == "UnknownAdministratorSlot" || status == "Malformed" {
            let Some(frasil_peers::skeleton::Status::Void { class, .. }) =
                skeleton.status(history.id(name))
            else {
                panic!("{name}: void");
            };
            assert!(frasil_peers::skeleton::refused_at_store(class), "{name}");
        }
    }
}

/// peers.md, "Limits": copies of A's commitment, one after another, reach
/// 256 planted administrator slots; the next copy with a grant is
/// `PlantedSlotsFull`, a copy that lowers still applies, and P's grant of B
/// with the copies in its past repeats nothing, applies, passes at
/// replicas, and B1 enrols. Step 6 reads only a copy's past, so a copy's
/// verdict is the same at a peer that holds no more than that past and the
/// space events naming the changes in it: those make the changes applied,
/// and so make the administrator slots a lower names (step 5).
#[test]
fn planted_limit() {
    const PREFIX: &str = "storage/planted-limit";
    let case = &family("resolution")["planted_limit"];
    assert_eq!(case["limit"], frasil_peers::limits::MAX_PLANTED);
    let history = History::of(&case["events"]);
    let skeleton = Skeleton::new(&history.log, None);
    check_summary("planted limit", &skeleton, &history, &case["peer"]);
    let repeats: Vec<Json> = history
        .log
        .canonical()
        .into_iter()
        .filter(|&id| skeleton.repeats(id))
        .map(|id| Json::from(history.name(id)))
        .collect();
    assert_eq!(Json::from(repeats), case["repeats"]);
    // Each copy's verdict is the same over the view that ends with it: its
    // past, and the space events that name the changes in it with their
    // past. A slot reference names an administrator slot only an applied
    // change made (peers.md, "Storage events"), and the space event that
    // applies a change lies outside the past of a skeleton event.
    let statuses = case["peer"]["events"].as_object().unwrap();
    for (name, status) in statuses {
        if !name.starts_with("A1: copy") {
            continue;
        }
        let id = history.id(name);
        let canonical = history.log.canonical();
        let past: std::collections::BTreeSet<EventId> = canonical
            .iter()
            .copied()
            .filter(|&x| history.log.precedes(x, id))
            .collect();
        let naming: Vec<EventId> = canonical
            .iter()
            .copied()
            .filter(|&x| {
                let event = history.log.event(x).expect("placed");
                frasil_peers::skeleton::named_twin(event).is_some_and(|twin| past.contains(&twin))
            })
            .collect();
        let mut view: std::collections::BTreeSet<EventId> = canonical
            .iter()
            .copied()
            .filter(|&x| {
                past.contains(&x) || naming.iter().any(|&k| k == x || history.log.precedes(x, k))
            })
            .collect();
        view.insert(id);
        let alone = Skeleton::new(&history.log, Some(&view));
        let found = status_text(alone.status(id).expect("a status"), &history);
        // A copy is Unnamed until the key event naming it is in the view.
        if found != PeersClass::Unnamed.name() {
            assert_eq!(&Json::from(found), status, "{name}");
        }
    }
    let grant = "P grants B administer, the copies in its past";
    let roster = [
        ("P creates the space", grants(PREFIX, &["P"])),
        ("P grants A administer", grants(PREFIX, &["A"])),
        (grant, grants(PREFIX, &["B"])),
    ];
    let facts = Facts::new(PREFIX, &history, &["P", "A", "B"], &roster);
    let checks = TwinChecks::new(&skeleton, &facts);
    let verdict = match checks.check(history.id(grant)) {
        Ok(()) => "valid".to_string(),
        Err(failure) => failure.class().name().to_string(),
    };
    assert_eq!(Json::from(verdict), case["replica"][grant]);
}
