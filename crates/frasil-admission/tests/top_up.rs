//! admission.json's `top_up` family (admission.md, sections 3.11 and 3.12):
//! the body keys a newcomer's snapshot carries, a delivery, a rotation and
//! a delivery under it, each concurrent with an admission from now on and
//! held until its body key is topped up, and the writers' rank for the
//! first top-up.

mod common;

use common::history::History;
use common::*;
use frasil_admission::snapshot::{snapshot_body_keys, top_up_rank, top_up_set};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Keyring, Level, OtherLogs, Via};
use serde_json::{Map, Value as Json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

fn named_keys(r: &History, keys: &BTreeMap<EventId, Zeroizing<[u8; 32]>>) -> Json {
    Json::Object(
        keys.iter()
            .map(|(id, key)| (r.names[id].clone(), Json::from(h(&key[..]))))
            .collect::<Map<String, Json>>(),
    )
}

fn events(map: BTreeMap<String, String>) -> Json {
    Json::Object(map.into_iter().map(|(k, v)| (k, Json::from(v))).collect())
}

#[test]
fn top_up() {
    let t = family("top_up");
    let prefix = "admission/records";
    let mut r = History::new("A", prefix);
    let w = r.device("W");
    let grant_w = Change::grant_device(
        r.device_keys("W"),
        Level::Write,
        HistoryMode::WithHistory,
        Via::Code,
    );
    let gw = r.rotate("A", vec![grant_w], "A grants W write");
    r.sync(&["A", "W"]);
    let mut admit_n = Change::grant_device(
        r.device_keys("N"),
        Level::Write,
        HistoryMode::FromNowOn,
        Via::Code,
    );
    admit_n.session = Some(example16("admission/records/session"));
    let adm = r.admit(
        "A",
        vec![admit_n],
        "A admits N from now on",
        true,
        &[r.recipient("N", true)],
    );
    let x = r.deliver("W", "W delivers, concurrent with the admission");
    assert_eq!(r.names[&x], text(&t["concurrent_event"]));
    assert!(r.log.concurrent(x, adm));
    // A rotation concurrent with the break, and a delivery under it: its
    // state is from before the break, since none of its rotations is the
    // break or follows it.
    let heal = r.heal("W", "W rotates, concurrent with the admission");
    let y = r.deliver("W", "W delivers under its concurrent rotation");
    assert!(r.log.concurrent(heal, adm));
    assert!(r.log.concurrent(y, adm));
    assert!(r.log.precedes(gw, adm));

    // What the snapshot carries for N, which holds the admission's key.
    let others = OtherLogs::default();
    let all = r.keyring();
    let held = BTreeSet::from([adm]);
    let mut pre_view = r.log.past(adm);
    pre_view.insert(adm);
    let snap = {
        let pre = r.resolve(Some(&pre_view), &all, &others);
        snapshot_body_keys(&pre, &held)
    };
    assert_eq!(named_keys(&r, &snap), t["snapshot_body_keys"]);

    // Before the top-up, the concurrent delivery is held.
    let keyring = |bodies: &BTreeMap<EventId, Zeroizing<[u8; 32]>>| {
        let mut keys = Keyring::default();
        keys.rotations.insert(adm, Zeroizing::new(r.krot[&adm]));
        for (id, key) in bodies {
            keys.bodies.insert(*id, vec![key.clone()]);
        }
        keys
    };
    let before_keys = keyring(&snap);
    let before = r.resolve(None, &before_keys, &others);
    assert_eq!(events(r.events(&before)), t["before_the_top_up"]);

    // The top-up: the body keys a writer that opened them publishes.
    let full = r.resolve(None, &all, &others);
    let extra: BTreeMap<EventId, Zeroizing<[u8; 32]>> = snapshot_body_keys(&full, &held)
        .into_iter()
        .filter(|(id, _)| !snap.contains_key(id))
        .collect();
    assert_eq!(named_keys(&r, &extra), t["top_up_body_keys"]);
    assert_eq!(
        top_up_set(&full, adm),
        extra.keys().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(top_up_set(&full, adm), BTreeSet::from([x, heal, y]));
    let mut writers = vec![r.device("A"), w];
    writers.sort_unstable();
    let rank: Vec<Json> = top_up_rank(&r.id(), &x, &writers)
        .into_iter()
        .map(|d| Json::from(if d == w { "W" } else { "A" }))
        .collect();
    assert_eq!(Json::Array(rank), t["top_up_rank"]);

    // After it, every event is valid.
    let mut all_bodies = snap.clone();
    all_bodies.extend(extra);
    let after_keys = keyring(&all_bodies);
    let after = r.resolve(None, &after_keys, &others);
    assert_eq!(events(r.events(&after)), t["after_the_top_up"]);
}
