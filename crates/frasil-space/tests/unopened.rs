//! roster.json's `unopened_events` (roster.md, "Space events a replica
//! cannot open"): a member admitted "from now on" judging the space with
//! and without the body keys a snapshot carries; an author that seals under
//! a key of its own; and a merged state's key received whole.

mod common;

use common::space::{Fixture, differences, prefix_at};
use common::{array, example, family, text};
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{Secret, body_key};
use frasil_space::{Keyring, OtherLogs, Space};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

fn secret(bytes: [u8; 32]) -> Secret {
    Zeroizing::new(bytes)
}

/// Keys by event name, as the vector gives them, each checked against the
/// keyring the history's prefix derives when `check` holds it.
fn keys_named(
    fixture: &Fixture,
    keys: &Json,
    check: Option<&Keyring>,
) -> BTreeMap<EventId, [u8; 32]> {
    keys.as_object()
        .unwrap()
        .keys()
        .map(|n| {
            let id = fixture.id(n);
            let key: [u8; 32] = array(keys, n);
            if let Some(keyring) = check {
                assert_eq!(keyring.rotations.get(&id).map(|k| **k), Some(key), "{n}");
            }
            (id, key)
        })
        .collect()
}

fn secrets(keys: &BTreeMap<EventId, [u8; 32]>) -> BTreeMap<EventId, Secret> {
    keys.iter().map(|(id, k)| (*id, secret(*k))).collect()
}

/// Checks the body keys the vector gives against those a replica holding
/// every rotation key opens.
fn check_body_keys(fixture: &Fixture, keys: &BTreeMap<EventId, [u8; 32]>) {
    let others = OtherLogs::none();
    for (&id, key) in keys {
        assert_eq!(
            opened_body_key(fixture, &others, &fixture_name(fixture, id)),
            *key,
            "{}",
            fixture_name(fixture, id)
        );
    }
}

/// An event's body key, as a replica holding every rotation key opens it.
fn opened_body_key(fixture: &Fixture, others: &OtherLogs<'_>, name: &str) -> [u8; 32] {
    let space = fixture.resolve(None, &fixture.keys, others).unwrap();
    *space.opened(fixture.id(name)).unwrap().body_key
}

fn check(
    fixture: &Fixture,
    keys: &Keyring,
    expected: &Json,
    label: &str,
    failures: &mut Vec<String>,
) {
    let others = OtherLogs::none();
    match fixture.resolve(None, keys, &others) {
        Ok(space) => {
            failures.extend(differences(fixture, &space, expected, false, label));
            if let Some(provisional) = expected.get("provisional") {
                let want: Vec<&str> = provisional
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_str().unwrap())
                    .collect();
                // The vectors list them by event ID.
                let mut ids = space.provisional();
                ids.sort_unstable();
                let got: Vec<String> = ids
                    .into_iter()
                    .map(|id| fixture_name(fixture, id))
                    .collect();
                if got != want {
                    failures.push(format!("{label}: provisional {got:?}, want {want:?}"));
                }
            }
        }
        Err(class) => failures.push(format!("{label}: unusable, {class:?}")),
    }
}

fn fixture_name(fixture: &Fixture, id: EventId) -> String {
    fixture.event_names[&id].clone()
}

#[test]
fn late_joiner() {
    let f = family("unopened_events");
    let late = &f["late_joiner"];
    let fixture = Fixture::new(
        &prefix_at(&["unopened_events", "late_joiner"]),
        &late["history"],
    );
    let held = keys_named(&fixture, &late["rotation_keys"], Some(&fixture.keys));
    let holds: BTreeSet<EventId> = late["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    assert_eq!(
        holds,
        held.keys().copied().collect(),
        "every rotation the newcomer holds"
    );
    let held = secrets(&held);
    let snapshot = keys_named(&fixture, &late["snapshot"], None);
    check_body_keys(&fixture, &snapshot);
    let others = OtherLogs::none();
    let views = &late["views"];
    let mut failures = Vec::new();

    // Without body keys, the genesis is Sealed: the space is unusable.
    let keys = Keyring {
        rotations: held.clone(),
        ..Keyring::default()
    };
    let outcome = fixture.resolve(None, &keys, &others).map(|_| ());
    assert_eq!(
        outcome.map_err(frasil_base::Class::name),
        Err(text(views, "without body keys"))
    );

    let at_grant: Vec<EventId> = late["snapshot_at_grant"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    let bodies = |ids: &[EventId], wrong: Option<(EventId, [u8; 32])>| -> Keyring {
        let mut bodies: BTreeMap<EventId, Vec<Secret>> = ids
            .iter()
            .map(|id| (*id, vec![secret(snapshot[id])]))
            .collect();
        if let Some((id, key)) = wrong {
            bodies.insert(id, vec![secret(key)]);
        }
        Keyring {
            rotations: held.clone(),
            bodies,
            ..Keyring::default()
        }
    };
    check(
        &fixture,
        &bodies(&at_grant, None),
        &views["with body keys for the grant's past"],
        "with body keys for the grant's past",
        &mut failures,
    );
    let everything: Vec<EventId> = snapshot.keys().copied().collect();
    check(
        &fixture,
        &bodies(&everything, None),
        &views["with body keys for everything it cannot open"],
        "with body keys for everything it cannot open",
        &mut failures,
    );
    let wrong_key: [u8; 32] = array(late, "wrong_body_key");
    assert_eq!(wrong_key, example(&format!("{}/wrong", fixture.prefix)));
    let wrong = (fixture.id("P forbids recovery agents"), wrong_key);
    check(
        &fixture,
        &bodies(&everything, Some(wrong)),
        &views["with a wrong body key for the policy change"],
        "with a wrong body key for the policy change",
        &mut failures,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn wrong_seal() {
    let f = family("unopened_events");
    let split = &f["wrong_seal"];
    let mut fixture = Fixture::new(
        &prefix_at(&["unopened_events", "wrong_seal"]),
        &split["history"],
    );
    fixture.name_device("N");
    let bad = fixture.id(text(split, "event"));
    let derived: [u8; 32] = array(split, "derived_body_key");
    let actual: [u8; 32] = array(split, "author_body_key");
    // The author's key is the secret the author sealed under.
    let author_secret: [u8; 32] = array(split, "author_secret");
    let event = fixture.log.event(bad).unwrap();
    let own = body_key(
        &author_secret,
        fixture.log.id().as_bytes(),
        event.author(),
        event.seq(),
    );
    assert_eq!(*own, actual);
    let views = &split["views"];
    let mut failures = Vec::new();
    check(
        &fixture,
        &fixture.keys,
        &views["member"],
        "member",
        &mut failures,
    );
    // The newcomer holds the rotations from its grant on, and the body keys
    // of what it cannot open with them.
    let newcomer = &split["newcomer"];
    let held = keys_named(&fixture, &newcomer["rotation_keys"], Some(&fixture.keys));
    let holds: BTreeSet<EventId> = newcomer["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    assert_eq!(holds, held.keys().copied().collect());
    let held = secrets(&held);
    let snapshot = keys_named(&fixture, &newcomer["snapshot"], None);
    check_body_keys(&fixture, &snapshot);
    let keyring = |handed: Vec<[u8; 32]>| {
        let mut bodies: BTreeMap<EventId, Vec<Secret>> = snapshot
            .iter()
            .map(|(id, k)| (*id, vec![secret(*k)]))
            .collect();
        bodies.insert(bad, handed.into_iter().map(secret).collect());
        Keyring {
            rotations: held.clone(),
            bodies,
            ..Keyring::default()
        }
    };
    for (view, handed) in [
        ("newcomer handed the author's key", vec![actual]),
        ("newcomer handed both keys", vec![actual, derived]),
        ("newcomer handed the derived key", vec![derived]),
    ] {
        check(
            &fixture,
            &keyring(handed),
            &views[view],
            view,
            &mut failures,
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn whole_merged_key() {
    let f = family("unopened_events");
    let whole = &f["whole_merged_key"];
    let fixture = Fixture::new(
        &prefix_at(&["unopened_events", "whole_merged_key"]),
        &whole["history"],
    );
    let merged: Vec<EventId> = whole["merged_state"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| fixture.id(n.as_str().unwrap()))
        .collect();
    let state = RotationSet::new(merged.iter().copied()).unwrap();
    let others = OtherLogs::none();
    // The replica holds every rotation key but the merged ones, and the
    // merged heals' body keys.
    let rotations = keys_named(&fixture, &whole["rotation_keys"], Some(&fixture.keys));
    let expected: BTreeSet<EventId> = fixture
        .keys
        .rotations
        .keys()
        .copied()
        .filter(|id| !merged.contains(id))
        .collect();
    assert_eq!(rotations.keys().copied().collect::<BTreeSet<_>>(), expected);
    let rotations = secrets(&rotations);
    let body_keys = keys_named(&fixture, &whole["body_keys"], None);
    assert_eq!(body_keys.keys().copied().collect::<Vec<_>>(), {
        let mut m = merged.clone();
        m.sort();
        m
    });
    check_body_keys(&fixture, &body_keys);
    let bodies: BTreeMap<EventId, Vec<Secret>> = body_keys
        .iter()
        .map(|(id, k)| (*id, vec![secret(*k)]))
        .collect();
    let views = &whole["views"];
    let mut failures = Vec::new();
    for (view, key) in [
        (
            "the merged key received whole",
            array::<32>(whole, "merged_key"),
        ),
        ("a wrong merged key received whole", [0; 32]),
    ] {
        let keys = Keyring {
            rotations: rotations.clone(),
            bodies: bodies.clone(),
            states: BTreeMap::from([(state.clone(), secret(key))]),
        };
        check(&fixture, &keys, &views[view], view, &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // A replica that holds every rotation key opens nothing provisionally.
    let space: Space<'_> = fixture.resolve(None, &fixture.keys, &others).unwrap();
    assert!(space.provisional().is_empty());
}
