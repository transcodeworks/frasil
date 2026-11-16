//! roster.json's `grant_graph` and `effective_membership` (roster.md,
//! "Grants of spaces and effective membership"), over the grants in force
//! the vectors give for each space.

mod common;

use common::{array, family, named, text};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::graph::{
    GrantInForce, GrantTarget, SpaceGrants, Verdicts, edge_verdicts, effective,
};
use frasil_space::{Capability, CapabilityMode, DescriptorKind, Level};
use serde_json::Value as Json;
use std::collections::BTreeMap;

/// The spaces of a case, by ID, and each space's name by ID.
struct Graph {
    spaces: BTreeMap<EventId, SpaceGrants>,
    names: BTreeMap<EventId, String>,
}

fn kind_named(name: &str) -> DescriptorKind {
    [
        DescriptorKind::Space,
        DescriptorKind::Restricted,
        DescriptorKind::CarveOut,
    ]
    .into_iter()
    .find(|kind| kind.name() == name)
    .unwrap_or_else(|| panic!("kind {name}"))
}

fn graph(spaces: &Json) -> Graph {
    let spaces = spaces.as_array().unwrap();
    let ids: BTreeMap<&str, EventId> = spaces
        .iter()
        .map(|s| (text(s, "name"), EventId(array(s, "id"))))
        .collect();
    let mut out = Graph {
        spaces: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    for space in spaces {
        let grants = space["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                let target = text(g, "target");
                GrantInForce {
                    event: EventId(array(g, "event")),
                    target: match text(g, "kind") {
                        "device" => GrantTarget::Device(named(target)),
                        "person" => GrantTarget::Person(named(target)),
                        "space" => GrantTarget::Space(
                            ids.get(target).copied().unwrap_or(EventId(named(target))),
                        ),
                        other => panic!("grant kind {other}"),
                    },
                    level: Level::from_name(text(g, "level")).unwrap(),
                    session: g["session"].as_bool().unwrap(),
                    // ext-restricted-spaces.json leaves out an empty list.
                    capabilities: g["capabilities"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|pair| Capability {
                            name: pair[0].as_str().unwrap().into(),
                            mode: match pair[1].as_str().unwrap() {
                                "extends" => CapabilityMode::Extends,
                                _ => CapabilityMode::Narrows,
                            },
                        })
                        .collect(),
                }
            })
            .collect();
        let id = ids[text(space, "name")];
        out.names.insert(id, text(space, "name").to_owned());
        out.spaces.insert(
            id,
            SpaceGrants {
                kind: kind_named(text(space, "kind")),
                parent: space["parent"].as_str().map(|parent| ids[parent]),
                grants,
            },
        );
    }
    out
}

/// Each edge's verdict as the vectors write it, by the grant's event ID.
fn verdicts_by_event(verdicts: &Verdicts) -> BTreeMap<String, &'static str> {
    verdicts
        .iter()
        .map(|(edge, verdict)| {
            (
                frasil_testkit::hex::encode(edge.event.0),
                verdict.err().map_or("effective", |class| class.name()),
            )
        })
        .collect()
}

fn expected_edges(edges: &Json) -> BTreeMap<String, &str> {
    edges
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (text(e, "event").to_owned(), text(e, "verdict")))
        .collect()
}

/// Every space's effective membership, as the vectors write it, by device
/// name.
fn check_effective(
    graph: &Graph,
    persons: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    verdicts: &Verdicts,
    expected: &Json,
    devices: &[String],
) {
    let device_name: BTreeMap<[u8; 32], &str> =
        devices.iter().map(|d| (named(d), d.as_str())).collect();
    for (&id, name) in &graph.names {
        let members = effective(&graph.spaces, persons, id, verdicts).unwrap();
        let want = expected[name.as_str()].as_object().unwrap();
        assert_eq!(members.len(), want.len(), "{name}");
        for (device, reach) in members {
            let device = device_name[&device];
            let want = &want[device];
            let list = |key: &str| -> Vec<String> {
                want[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect()
            };
            assert_eq!(reach.level.name(), text(want, "level"), "{name} {device}");
            assert_eq!(Some(reach.propagates), want["propagates"].as_bool());
            assert_eq!(
                reach.extends.into_iter().collect::<Vec<_>>(),
                list("extends")
            );
            assert_eq!(
                reach.narrows.into_iter().collect::<Vec<_>>(),
                list("narrows")
            );
            assert_eq!(
                Some(reach.depth as u64),
                want["depth"].as_u64(),
                "{name} {device}"
            );
            // Given where a device's strongest path does not propagate.
            if let Some(propagating) = want.get("propagating_level") {
                assert_eq!(
                    reach.propagating_level.map(Level::name),
                    propagating.as_str(),
                    "{name} {device}"
                );
            }
        }
    }
}

fn devices_of(spaces: &Json, persons: &Json) -> Vec<String> {
    let mut out: Vec<String> = spaces
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["grants"].as_array().unwrap().iter())
        .filter(|g| text(g, "kind") == "device")
        .map(|g| text(g, "target").to_owned())
        .collect();
    if let Some(persons) = persons.as_object() {
        for devices in persons.values() {
            out.extend(
                devices
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d.as_str().unwrap().to_owned()),
            );
        }
    }
    out
}

fn persons_of(persons: &Json) -> BTreeMap<[u8; 32], Vec<[u8; 32]>> {
    persons
        .as_object()
        .map(|persons| {
            persons
                .iter()
                .map(|(person, devices)| {
                    let devices = devices
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|d| named(d.as_str().unwrap()))
                        .collect();
                    (named(person), devices)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn grant_graph() {
    let cases = family("grant_graph");
    let cases = cases.as_array().unwrap();
    // Two concurrent grants that close a cycle, and a chain of ten spaces.
    for case in &cases[..2] {
        let name = text(case, "name");
        let g = graph(&case["spaces"]);
        let verdicts = edge_verdicts(&g.spaces);
        assert_eq!(
            verdicts_by_event(&verdicts),
            expected_edges(&case["edges"]),
            "{name}"
        );
        let devices = devices_of(&case["spaces"], &Json::Null);
        if let Some(expected) = case.get("effective") {
            check_effective(&g, &BTreeMap::new(), &verdicts, expected, &devices);
        }
        if let Some(reach) = case.get("reach_of_s9_device") {
            let mut found: Vec<&str> = g
                .names
                .iter()
                .filter(|&(&id, _)| {
                    effective(&g.spaces, &BTreeMap::new(), id, &verdicts)
                        .unwrap()
                        .contains_key(&named("s9-device"))
                })
                .map(|(_, name)| name.as_str())
                .collect();
            found.sort_unstable();
            let want: Vec<&str> = reach
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(found, want, "{name}");
        }
    }
    // A grant of a restricted space: the spaces are ext-restricted-spaces.json's.
    let case = &cases[2];
    let restricted = frasil_testkit::vectors::family::<Json>(
        "ext-restricted-spaces.json",
        "restricted_membership",
    );
    let g = graph(&restricted["spaces"]);
    let verdicts = edge_verdicts(&g.spaces);
    let edge = verdicts_by_event(&verdicts);
    assert_eq!(edge[text(case, "edge")], text(case, "verdict"));
    // Without ext-restricted-spaces.md, a restricted space's membership is
    // the extension's.
    #[cfg(not(feature = "ext-restricted-spaces"))]
    let f = g
        .names
        .iter()
        .find(|(_, name)| *name == "F")
        .map(|(&id, _)| id)
        .unwrap();
    #[cfg(not(feature = "ext-restricted-spaces"))]
    assert_eq!(
        effective(&g.spaces, &persons_of(&restricted["persons"]), f, &verdicts)
            .map_err(Class::name),
        Err("ExtensionRequired")
    );
    // Spaces with persons: guest grants inside a granted space (roster.md,
    // "Checks across logs", "Paths").
    for case in &cases[3..] {
        let name = text(case, "name");
        let g = graph(&case["spaces"]);
        let verdicts = edge_verdicts(&g.spaces);
        assert_eq!(
            verdicts_by_event(&verdicts),
            expected_edges(&case["edges"]),
            "{name}"
        );
        let devices = devices_of(&case["spaces"], &case["persons"]);
        check_effective(
            &g,
            &persons_of(&case["persons"]),
            &verdicts,
            &case["effective"],
            &devices,
        );
    }
}

/// roster.md, "Grants of spaces and effective membership": a device's
/// highest level and its highest over the paths that propagate are kept
/// apart. A guest at `write` in the team that reaches it at `read` through
/// a person reaches the project at `read`, with the person grant's
/// narrowing capability and not the guest's; its mirror reaches it at
/// `write`.
#[test]
fn effective_membership_over_propagating_paths() {
    let f = &family("effective_membership")["propagating_paths"];
    let g = graph(&f["spaces"]);
    let verdicts = edge_verdicts(&g.spaces);
    assert_eq!(verdicts_by_event(&verdicts), expected_edges(&f["edges"]));
    let persons = persons_of(&f["persons"]);
    let devices = devices_of(&f["spaces"], &f["persons"]);
    check_effective(&g, &persons, &verdicts, &f["effective"], &devices);
}

#[test]
fn effective_membership() {
    let f = family("effective_membership");
    let g = graph(&f["spaces"]);
    let verdicts = edge_verdicts(&g.spaces);
    assert_eq!(verdicts_by_event(&verdicts), expected_edges(&f["edges"]));
    let persons = persons_of(&f["persons"]);
    let devices = devices_of(&f["spaces"], &f["persons"]);
    check_effective(&g, &persons, &verdicts, &f["effective"], &devices);
}
