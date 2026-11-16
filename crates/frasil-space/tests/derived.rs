//! roster.json's `stability` and `refused_unit` (roster.md, "What replicas
//! derive"): a removal before and after every administrator has signed
//! after it, and how long a replica keeps a refused unit's content.

mod common;

use common::space::{Fixture, prefix_at};
use common::{family, text};
use frasil_base::time::Reading;
use frasil_space::{OtherLogs, Retention, refused_unit};
use serde_json::Value as Json;

fn reading(value: &Json) -> Reading {
    Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    }
}

fn outcome(retention: Retention) -> &'static str {
    match retention {
        Retention::Keep => "Keep",
        Retention::MayDrop => "MayDrop",
    }
}

#[test]
fn stability() {
    let f = family("stability");
    let mut fixture = Fixture::new(&prefix_at(&["stability"]), &f["events"]);
    for name in ["P", "Q", "M"] {
        fixture.name_device(name);
    }
    let target = fixture.id(text(&f, "target"));
    let others = OtherLogs::none();
    let mut spaces = Vec::new();
    for case in f["cases"].as_array().unwrap() {
        let view = fixture.view(&case["holds"]);
        let space = fixture
            .resolve(view.as_ref(), &fixture.keys, &others)
            .unwrap();
        let mut administrators: Vec<String> = space
            .administrators()
            .iter()
            .map(|a| {
                fixture.member_names[&frasil_space::MemberRef::device(frasil_space::DeviceId(*a))]
                    .clone()
            })
            .collect();
        administrators.sort();
        let want: Vec<&str> = case["administrators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert_eq!(administrators, want, "{}", text(case, "view"));
        assert_eq!(
            Some(space.stable(&[target])),
            case["stable"].as_bool(),
            "{}",
            text(case, "view")
        );
        spaces.push(space);
    }
    // Retention of the refused unit, in the view before Q's heal and after.
    let unit = fixture.id("M writes, apart");
    for case in f["retention"].as_array().unwrap() {
        let view = text(case, "view");
        let space = if view.starts_with("before") {
            &spaces[0]
        } else {
            &spaces[1]
        };
        assert_eq!(
            case["gap_key_timeout"].as_u64(),
            Some(space.policy().gap_key_timeout)
        );
        let at = |t: &str| Reading {
            timeline: case[t].as_u64().unwrap(),
            wall: None,
            run: 1,
        };
        let retention = space
            .retention(unit, false, &at("first_seen"), &at("now"))
            .expect("a refused unit");
        assert_eq!(
            Some(retention == Retention::MayDrop),
            case["may_drop"].as_bool(),
            "{view}"
        );
    }
}

#[test]
fn refused_units() {
    for case in family("refused_unit").as_array().unwrap() {
        let retention = refused_unit(
            case["own"].as_bool().unwrap(),
            case["stable"].as_bool().unwrap(),
            &reading(&case["first_sight"]),
            &reading(&case["now"]),
            case["timeout"].as_u64().unwrap(),
        );
        assert_eq!(outcome(retention), text(case, "outcome"), "{case}");
    }
}
