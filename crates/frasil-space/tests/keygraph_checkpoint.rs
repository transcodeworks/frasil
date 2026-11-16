//! keys.json's `checkpoint_worlds` (keys.md, section 3.17 "Keys after a
//! checkpoint"): the key graph rooted at a checkpoint, read by a replica
//! that holds only the checkpoint and the events after it.
//!
//! Each history's checkpoint names the checkpoint the view is rooted at
//! (`world_of`); [`model::Model`] stands the checkpoint as the genesis, its
//! record granting its members there. The key graph computes the merged
//! roster, the inside, the current states, the heal tests, the deliveries
//! a room calls for, entitlement to states before the checkpoint, and the
//! stated reach queries, from the world alone.

mod common;
mod model;

use frasil_keys::RotationSet;
use frasil_space::keygraph::{Holdings, Kind, Member, plan};
use model::Model;
use serde_json::{Value as Json, json};

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn kind_of(name: &str) -> Kind {
    match name {
        "content" => Kind::Content,
        "grant" => Kind::Grant,
        other => panic!("{other}"),
    }
}

fn check(model: &Model, checkpoint: &Json, label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |what: &str, got: Json, want: &Json| {
        if got != *want {
            out.push(format!("{label}: {what}\n  got  {got}\n  want {want}"));
        }
    };
    let graph = model.key_graph();
    // The merged roster.
    let roster: serde_json::Map<String, Json> = graph
        .members(Kind::Content)
        .iter()
        .map(|(m, s)| {
            (
                model.member_name(m),
                json!({"level": model::level_name(s.level), "session": s.session}),
            )
        })
        .collect();
    check("roster", Json::Object(roster), &checkpoint["roster"]);
    // The inside: the record's members, a raced invite key outside, and
    // the recorded principals inside where the replica holds their
    // space's log.
    let inside = json!({
        "content": graph.inside(Kind::Content).into_iter().collect::<Vec<_>>(),
        "grant": graph.inside(Kind::Grant).into_iter().collect::<Vec<_>>(),
    });
    check("inside", inside, &checkpoint["inside"]);
    // The current states: the checkpoint and the rotations after it.
    let current = json!({
        "content": graph.current(Kind::Content).map(|s| model.state_name(&s)),
        "grant": graph.current(Kind::Grant).map(|s| model.state_name(&s)),
    });
    check("current", current, &checkpoint["current"]);
    // The deliveries each graph calls for, and the heal test, from the
    // artifacts of the checkpoint and the events after it alone.
    let room: Vec<String> = checkpoint["room"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_owned())
        .collect();
    let artifacts = model.artifacts(&checkpoint["artifacts"]);
    let mut heal = serde_json::Map::new();
    for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
        let p = plan(&graph, &artifacts, kind, &room, false);
        let by = |d: &Option<String>| d.clone().unwrap_or_else(|| "nobody in the room".into());
        let wraps: Vec<String> = p
            .wraps
            .iter()
            .map(|w| {
                format!(
                    "{} to {} by {} ({})",
                    model.state_name(&w.state),
                    w.device,
                    by(&w.by),
                    w.why.name()
                )
            })
            .collect();
        let links: Vec<String> = p
            .links
            .iter()
            .map(|l| {
                format!(
                    "{} > {} by {}",
                    model.state_name(&l.under),
                    model.state_name(&l.reaches),
                    by(&l.by)
                )
            })
            .collect();
        let gaps: Vec<String> = p.gaps.iter().map(|g| model.state_name(g)).collect();
        let waiting: Vec<String> = p
            .waiting
            .iter()
            .map(|(k, d)| format!("{} to {d}", model.state_name(k)))
            .collect();
        let healing = p.heal.map(|h| h.name());
        heal.insert(key.into(), json!(healing));
        let got = json!({
            "wraps": wraps, "links": links, "gaps": gaps, "waiting": waiting,
            "heal": healing,
        });
        check(&format!("plan {key}"), got, &checkpoint["plan"][key]);
    }
    check("heal", Json::Object(heal), &checkpoint["heal"]);
    // Entitlement to states before the checkpoint, at a replica that holds
    // only the world.
    for query in checkpoint["entitlement_before"].as_array().unwrap() {
        let name = text(query, "member");
        let member = match name.split_once('@') {
            Some(_) => graph
                .members(Kind::Content)
                .into_keys()
                .find(|m| model.member_name(m) == name)
                .unwrap_or_else(|| panic!("{label}: no principal {name}")),
            None => Member::Roster(name.to_owned()),
        };
        let state: RotationSet = model.state(text(query, "state"));
        let got = graph.entitled(&member, &state, kind_of(text(query, "kind")));
        check(
            &format!("entitlement before {query}"),
            Json::Bool(got),
            &query["entitled"],
        );
    }
    // The stated reach queries.
    for query in checkpoint["reaches"].as_array().unwrap() {
        let kind = kind_of(text(query, "kind"));
        let devices: Vec<String> = query["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect();
        let state = model.state(text(query, "state"));
        let holdings = Holdings::new(&graph, &artifacts, kind);
        check(
            &format!("reaches {query}"),
            Json::Bool(holdings.reaches(&devices, &state)),
            &query["result"],
        );
    }
    out
}

#[test]
fn checkpoint_worlds() {
    let mut failures = Vec::new();
    let histories: Json = frasil_testkit::vectors::family("keys.json", "checkpoint_worlds");
    for history in histories.as_array().unwrap() {
        let name = text(history, "name");
        // A raced invite key needs ext-invite-links.md's rules.
        #[cfg(not(feature = "ext-invite-links"))]
        if name.contains("invite") {
            continue;
        }
        for checkpoint in history["checkpoints"].as_array().unwrap() {
            let model = Model::new(history, checkpoint);
            let label = format!("{name} / {}", text(checkpoint, "name"));
            assert_eq!(
                model.key_graph().events().len(),
                checkpoint["events"].as_array().unwrap().len(),
                "{label}: the world's events"
            );
            failures.extend(check(&model, checkpoint, &label));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// keys.md, "Keys after a checkpoint": a checkpoint's own delivery wraps
/// for the inside of its past and, by space wrap, for the principals its
/// record keeps; never for a raced invite key. Read at the root of each
/// history's world, where the inside is the record's, it is among the wraps
/// of the checkpoint the vectors hold, and covers every device the record's
/// members and principals have.
#[test]
fn a_checkpoints_own_delivery() {
    let histories: Json = frasil_testkit::vectors::family("keys.json", "checkpoint_worlds");
    let mut seen = 0;
    for history in histories.as_array().unwrap() {
        let name = text(history, "name");
        #[cfg(not(feature = "ext-invite-links"))]
        if name.contains("invite") {
            continue;
        }
        // A checkpoint that wrapped for a raced invite key is the dishonest
        // case: its wraps are not the delivery this function plans.
        if name.contains("wrapped for") {
            continue;
        }
        let first = &history["checkpoints"][0];
        let root = text(first, "world_of");
        let mut at_root = first.clone();
        at_root["events"] = json!([root]);
        at_root["valid"] = json!([root]);
        let model = Model::new(history, &at_root);
        let graph = model.key_graph();
        let author = text(first, "view_of").to_owned();
        for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
            let delivery =
                frasil_space::keygraph::checkpoint_delivery(&graph, &author, kind, |_| true);
            let mut devices: std::collections::BTreeSet<String> =
                delivery.devices.iter().cloned().collect();
            for p in &delivery.principals {
                devices.extend(graph.devices(&Member::Principal(*p)));
            }
            let wrapped: std::collections::BTreeSet<String> = first["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|a| a.as_str()?.strip_prefix(&format!("wrap {key} {root} to ")))
                .map(str::to_owned)
                .collect();
            assert!(devices.contains(&author), "{name} {key}: the author");
            assert!(
                devices.is_subset(&wrapped),
                "{name} {key}: planned {devices:?}, the checkpoint wrapped {wrapped:?}"
            );
            assert!(
                !devices.contains("I1"),
                "{name} {key}: a raced invite key is outside"
            );
            assert_eq!(
                devices,
                graph
                    .inside(kind)
                    .into_iter()
                    .chain([author.clone()])
                    .collect(),
                "{name} {key}: the inside at the root"
            );
        }
        seen += 1;
    }
    assert!(seen >= 5, "the histories read: {seen}");
}

/// keys.json's `checkpoint_worlds` holds the mixed rotation: an event
/// after the checkpoint that also cites a late rotation is void
/// (`MixedCut`), held in the world's view but no rotation of it.
#[test]
fn the_mixed_rotation_is_no_rotation_of_the_world() {
    let histories: Json = frasil_testkit::vectors::family("keys.json", "checkpoint_worlds");
    let history = histories
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == "a mixed rotation across a checkpoint")
        .expect("the mixed rotation history");
    let checkpoint = &history["checkpoints"][0];
    let model = Model::new(history, checkpoint);
    let graph = model.key_graph();
    let x = model.state("X");
    let c = model.state("C");
    assert!(graph.events().contains(&x.ids()[0]));
    assert!(!graph.valid().contains(&x.ids()[0]));
    assert_eq!(graph.current(Kind::Content), Some(c));
}
