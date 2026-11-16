//! `ext-file-versions.json`: a peer's listings, heads and depth, and
//! retention (ext-file-versions.md, sections 3.6 to 3.9). The vectors give
//! what a peer stored, and the reference's own scenarios are built again
//! here from the same unit and object names.

#![cfg(feature = "ext-file-versions")]

use frasil_base::time::Reading;
use frasil_crypto::primitives::sha256;
use frasil_peers::retention::{Limits, Listings, Locator, Named, Retain, UnitId, UnitView};
use frasil_testkit::{hex, vectors};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "ext-file-versions.json";
const X: [u8; 16] = [7; 16];

fn reading(timeline: u64) -> Reading {
    Reading {
        timeline,
        wall: None,
        run: 1,
    }
}

/// The reference's `loc`: a locator named by a label.
fn loc(name: &str) -> Locator {
    let tag = format!("versions/object/{name}");
    let mut out = [0; 64];
    out[..32].copy_from_slice(&sha256(&[tag.as_bytes()]));
    out[32..].copy_from_slice(&sha256(&[format!("{tag}/digest").as_bytes()]));
    out
}

/// The reference's `uid`.
fn uid(name: &str) -> UnitId {
    sha256(&[format!("versions/unit/{name}").as_bytes()])
}

fn log(successor: Locator, listing: UnitId, predecessor: Locator) -> Named {
    Named {
        successor,
        listing: Some(listing),
        predecessor,
    }
}

fn unit(objects: Vec<Locator>, supersedes: Vec<Named>, seen: u64) -> UnitView {
    UnitView {
        stream: X,
        objects,
        supersedes,
        seen: reading(seen),
        snapshot: false,
        stable: true,
        evidence: false,
        since: BTreeMap::new(),
    }
}

fn head_list(listings: &Listings) -> Value {
    let heads: Vec<String> = listings.heads().iter().map(hex::encode).collect();
    json!(heads)
}

fn locator(value: &Value) -> Locator {
    hex::decode_array(value.as_str().unwrap()).unwrap()
}

fn named(value: &Value) -> Named {
    match value.as_array().unwrap().as_slice() {
        [successor, predecessor] => Named {
            successor: locator(successor),
            listing: None,
            predecessor: locator(predecessor),
        },
        [successor, listing, predecessor] => log(
            locator(successor),
            hex::decode_array(listing.as_str().unwrap()).unwrap(),
            locator(predecessor),
        ),
        other => panic!("not a supersession: {other:?}"),
    }
}

#[test]
fn listings() {
    let family: Value = vectors::family(FILE, "listings");
    let mut units = BTreeMap::new();
    let mut names = BTreeMap::new();
    for row in family["units"].as_array().unwrap() {
        let id: UnitId = hex::decode_array(row["id"].as_str().unwrap()).unwrap();
        names.insert(id, row["name"].as_str().unwrap().to_owned());
        if row["released"] == true {
            continue;
        }
        units.insert(
            id,
            UnitView {
                stream: hex::decode_array(row["stream"].as_str().unwrap()).unwrap(),
                objects: row["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(locator)
                    .collect(),
                supersedes: row["supersedes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(named)
                    .collect(),
                seen: reading(row["seen"].as_u64().unwrap()),
                snapshot: false,
                stable: true,
                evidence: row["evidence"] == true,
                since: BTreeMap::new(),
            },
        );
    }
    let listings = Listings::new(units);
    let mut rows = Vec::new();
    for (id, name) in &names {
        let Some(unit) = listings.units().get(id) else {
            continue;
        };
        for object in &unit.objects {
            let mut by: Vec<&str> = listings
                .superseders(&(*id, *object))
                .iter()
                .map(|(unit, _)| names[unit].as_str())
                .collect();
            by.sort_unstable();
            let since = listings.since(&(*id, *object)).map(|r| r.timeline);
            rows.push(json!({
                "unit": name,
                "object": hex::encode(object),
                "superseded_by": by,
                "since": since,
            }));
        }
    }
    let key = |row: &Value| row["unit"].as_str().unwrap().to_owned();
    rows.sort_by_key(key);
    let mut expected = family["listings"].as_array().unwrap().clone();
    expected.sort_by_key(key);
    assert_eq!(rows, expected);
    assert_eq!(head_list(&listings), family["heads"]);
}

#[test]
fn after_compaction() {
    let family: Value = vectors::family(FILE, "after_compaction");
    let (o1, o2, o3) = (loc("A1"), loc("A2"), loc("A3"));
    let (a1, a2, a3) = (uid("a1"), uid("a2"), uid("a3"));
    let mut units = BTreeMap::from([
        (a1, unit(vec![o1], vec![], 100)),
        (a2, unit(vec![o2], vec![log(o2, a1, o1)], 200)),
        (a3, unit(vec![o3], vec![log(o3, a2, o2)], 300)),
    ]);
    let before = Listings::new(units.clone());
    let inherited = family["inherited"].clone();
    for row in inherited["cover"].as_array().unwrap() {
        let (id, object) = match row["unit"].as_str().unwrap() {
            "a1" => (a1, o1),
            _ => (a2, o2),
        };
        assert_eq!(
            before.since(&(id, object)).map(|r| r.timeline),
            row["since"].as_u64()
        );
    }
    let cover = [a1, a2, a3];
    let since = BTreeMap::from([
        (o1, before.inherited_since(&cover, &o1, reading(400))),
        (o2, before.inherited_since(&cover, &o2, reading(400))),
    ]);
    let snapshot = UnitView {
        snapshot: true,
        since,
        ..unit(
            vec![o1, o2, o3],
            inherited["snapshot"]["supersedes"]
                .as_array()
                .unwrap()
                .iter()
                .map(named)
                .collect(),
            400,
        )
    };
    let s = uid("s");
    units.clear();
    units.insert(s, snapshot);
    let after = Listings::new(units);
    assert_eq!(
        after.since(&(s, o1)).map(|r| r.timeline),
        inherited["since"]["O1"].as_u64()
    );
    assert_eq!(
        after.since(&(s, o2)).map(|r| r.timeline),
        inherited["since"]["O2"].as_u64()
    );
    assert_eq!(head_list(&after), inherited["heads"]);

    // A listing of the cover that was never superseded: the snapshot's own
    // first sight.
    let (oa, ob) = (loc("B1"), loc("B2"));
    let (b1, b2) = (uid("b1"), uid("b2"));
    let cover = Listings::new(BTreeMap::from([
        (b1, unit(vec![oa], vec![], 100)),
        (b2, unit(vec![ob], vec![log(ob, uid("lost"), oa)], 200)),
    ]));
    let seen = family["reset"]["snapshot_seen"].as_u64().unwrap();
    assert_eq!(
        Some(
            cover
                .inherited_since(&[b1, b2], &oa, reading(seen))
                .timeline
        ),
        family["reset"]["since"]["B1"].as_u64()
    );
}

fn depth_of(listings: &Listings, cases: &[(&str, Locator)]) -> Value {
    let map: BTreeMap<&str, Option<u64>> = cases
        .iter()
        .map(|(name, object)| (*name, listings.depth(object)))
        .collect();
    json!(map)
}

/// A chain of seven versions, each superseding the one before.
fn chain(seen: impl Fn(usize) -> u64) -> (Vec<Locator>, BTreeMap<UnitId, UnitView>) {
    let objects: Vec<Locator> = (0..7).map(|i| loc(&format!("V{i}"))).collect();
    let mut units = BTreeMap::new();
    units.insert(uid("v0"), unit(vec![objects[0]], vec![], seen(0)));
    for i in 1..7 {
        let supersedes = vec![log(objects[i], uid(&format!("v{}", i - 1)), objects[i - 1])];
        units.insert(
            uid(&format!("v{i}")),
            unit(vec![objects[i]], supersedes, seen(i)),
        );
    }
    (objects, units)
}

#[test]
fn heads_and_depth() {
    let family: Value = vectors::family(FILE, "heads_and_depth");

    let (objects, units) = chain(|i| 1000 * i as u64);
    let listings = Listings::new(units);
    let names: Vec<String> = (0..7).map(|i| format!("V{i}")).collect();
    let cases: Vec<(&str, Locator)> = names
        .iter()
        .zip(&objects)
        .map(|(name, object)| (name.as_str(), *object))
        .collect();
    assert_eq!(head_list(&listings), family["chain"]["heads"]);
    assert_eq!(depth_of(&listings, &cases), family["chain"]["depth"]);

    let (oa, ob, oc, od) = (loc("Ba"), loc("Bb"), loc("Bc"), loc("Bd"));
    let (ba, bb, bc) = (uid("ba"), uid("bb"), uid("bc"));
    let mut units = BTreeMap::from([
        (ba, unit(vec![oa], vec![], 0)),
        (bb, unit(vec![ob], vec![log(ob, ba, oa)], 100)),
        (bc, unit(vec![oc], vec![log(oc, ba, oa)], 110)),
    ]);
    let open = Listings::new(units.clone());
    assert_eq!(head_list(&open), family["branch"]["open"]["heads"]);
    assert_eq!(
        depth_of(&open, &[("Ba", oa), ("Bb", ob), ("Bc", oc)]),
        family["branch"]["open"]["depth"]
    );
    units.insert(
        uid("bd"),
        unit(vec![od], vec![log(od, bb, ob), log(od, bc, oc)], 200),
    );
    let resolved = Listings::new(units);
    assert_eq!(head_list(&resolved), family["branch"]["resolved"]["heads"]);
    assert_eq!(
        depth_of(&resolved, &[("Ba", oa), ("Bb", ob), ("Bc", oc), ("Bd", od)]),
        family["branch"]["resolved"]["depth"]
    );

    let (orr, oh1, oh2) = (loc("Rr"), loc("Rh1"), loc("Rh2"));
    let (rr, rh1, rh2) = (uid("rr"), uid("rh1"), uid("rh2"));
    let restored = Listings::new(BTreeMap::from([
        (rr, unit(vec![orr], vec![], 0)),
        (rh1, unit(vec![oh1], vec![log(oh1, rr, orr)], 100)),
        (rh2, unit(vec![oh2], vec![log(oh2, rh1, oh1)], 200)),
        (uid("rr2"), unit(vec![orr], vec![log(orr, rh2, oh2)], 300)),
    ]));
    assert_eq!(head_list(&restored), family["restored"]["heads"]);
    assert_eq!(
        depth_of(&restored, &[("Rr", orr), ("Rh1", oh1), ("Rh2", oh2)]),
        family["restored"]["depth"]
    );

    let (ox, oy) = (loc("Dx"), loc("Dy"));
    let dx = uid("dx");
    let same = Listings::new(BTreeMap::from([
        (dx, unit(vec![ox], vec![], 0)),
        (uid("dy"), unit(vec![oy], vec![log(oy, dx, ox)], 100)),
        (uid("dz"), unit(vec![ox], vec![], 150)),
    ]));
    assert_eq!(head_list(&same), family["same_bytes"]["heads"]);
    assert_eq!(
        depth_of(&same, &[("Dx", ox), ("Dy", oy)]),
        family["same_bytes"]["depth"]
    );

    let (op, oq) = (loc("Cp"), loc("Cq"));
    let (cp, cq) = (uid("cp"), uid("cq"));
    let headless = Listings::new(BTreeMap::from([
        (cp, unit(vec![op], vec![log(op, cq, oq)], 0)),
        (cq, unit(vec![oq], vec![log(oq, cp, op)], 100)),
    ]));
    assert_eq!(head_list(&headless), family["headless"]["heads"]);
    assert_eq!(
        depth_of(&headless, &[("Cp", op), ("Cq", oq)]),
        family["headless"]["depth"]
    );
    // Without a head nothing is kept by step 3, and step 5 collects.
    let limits = Limits {
        max_file_versions: 5,
        file_version_retention: 0,
        erasure_timeout: 0,
    };
    assert_eq!(
        headless.retain(&op, &reading(1000), &limits, false),
        Retain::Collect(5)
    );
}

fn shown(outcome: Retain) -> (&'static str, u8) {
    match outcome {
        Retain::Peers => ("peers.md decides", 1),
        Retain::Keep(step) => ("Keep", step),
        Retain::Collect(step) => ("Collect", step),
    }
}

#[test]
fn decisions() {
    let family: Value = vectors::family(FILE, "decisions");
    let p = &family["parameters"];
    let limits = Limits {
        max_file_versions: p["max_file_versions"].as_u64().unwrap(),
        file_version_retention: p["file_version_retention"].as_u64().unwrap(),
        erasure_timeout: p["erasure_timeout"].as_u64().unwrap(),
    };
    let seen: Vec<u64> = family["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["seen"].as_u64().unwrap())
        .collect();
    for case in family["cases"].as_array().unwrap() {
        let what = case["name"].as_str().unwrap();
        let (_, mut units) = chain(|i| seen[i]);
        for unit in units.values_mut() {
            unit.stable = case["stable"] == true;
        }
        let listings = Listings::new(units);
        let object = case["object"]
            .as_str()
            .map_or_else(|| loc("none"), |text| hex::decode_array(text).unwrap());
        let now = reading(case["now"].as_u64().unwrap());
        let outcome = listings.retain(&object, &now, &limits, case["hold"] == true);
        let (name, step) = shown(outcome);
        assert_eq!(case["outcome"], name, "{what}");
        assert_eq!(case["step"], step, "{what}");
        if case["object"].is_string() {
            assert_eq!(listings.depth(&object), case["depth"].as_u64(), "{what}");
        }
    }
}

#[test]
fn holds() {
    let family: Value = vectors::family(FILE, "holds");
    let limits = Limits {
        max_file_versions: 5,
        file_version_retention: 3 * 86_400,
        erasure_timeout: 7 * 86_400,
    };
    let mut ids = BTreeSet::new();
    let units: BTreeMap<UnitId, UnitView> = family["holding_space_units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let id = uid(row["name"].as_str().unwrap());
            ids.insert(id);
            let view = unit(
                row["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(locator)
                    .collect(),
                row["supersedes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(named)
                    .collect(),
                row["seen"].as_u64().unwrap(),
            );
            (id, view)
        })
        .collect();
    let listings = Listings::new(units);
    for case in family["cases"].as_array().unwrap() {
        let what = case["name"].as_str().unwrap();
        let now = reading(case["now"].as_u64().unwrap());
        let outcome = listings.retain(&locator(&case["object"]), &now, &limits, false);
        let (name, step) = shown(outcome);
        assert_eq!(case["retain"], name, "{what}");
        assert_eq!(case["step"], step, "{what}");
        assert_eq!(
            case["hold_live"] == true,
            !matches!(outcome, Retain::Collect(_)),
            "{what}"
        );
    }
}
