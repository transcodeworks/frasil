//! roster.json's `held_spaces` (roster.md, "The space descriptor" and 3.3
//! Grants of spaces and effective membership): a genesis whose descriptor
//! is of kind 3, and one with key 5, each with a grant and an anchor after
//! it, at an implementation that lacks the documents defining them: the
//! genesis is valid and every later event is held `ExtensionRequired`; and
//! edges of the grant graph to a space of kind 3 and to an ordinary space
//! whose descriptor carries key 5, which never count (`GrantOfReserved`).

mod common;

use common::space::{Fixture, StandIn};
use common::{array, bytes, family, named, text};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::graph::{GrantInForce, GrantTarget, SpaceGrants, edge_verdicts};
use frasil_space::{
    Checkpointed, Descriptor, DescriptorKind, KeyEventChecks, Level, Limits, Options, OtherLogs,
    Space, Twins,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn a_later_documents_descriptor_holds_every_event_after_the_genesis() {
    let f = family("held_spaces");
    let others = OtherLogs::none();
    let mut failures = Vec::new();
    for case in f["genesis"].as_array().unwrap() {
        let name = text(case, "name");
        let descriptor =
            Descriptor::read(&bytes(case, "descriptor")).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(descriptor.kind.is_reserved(), "{name}");
        let fixture = Fixture::new(text(case, "history_prefix"), &case["events"]);
        let options = Options {
            keys: &fixture.keys,
            limits: Limits::PROTOCOL,
            others: &others,
            units: &StandIn,
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::Context,
            notices: None,
        };
        let space = Space::resolve(&fixture.log, None, options).unwrap();
        assert_eq!(space.screened().genesis().descriptor, descriptor, "{name}");
        for (event, want) in case["verdicts"].as_object().unwrap() {
            let got = fixture.show(space.status(fixture.id(event)).unwrap());
            if got != want.as_str().unwrap() {
                failures.push(format!("{name}: {event}: {got}, not {want}"));
            }
        }
        // Nothing of the space is judged: the roster is the genesis's alone.
        assert_eq!(space.valid(), vec![fixture.log.id()], "{name}");
        // The replica signs nothing more and needs a later version.
        let objects = BTreeMap::<EventId, Vec<u8>>::new();
        let envelopes = BTreeMap::<EventId, frasil_events::Event>::new();
        let judge = Checkpointed::new(
            frasil_space::CheckpointInputs {
                log: &fixture.log,
                options,
                objects: &objects,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        );
        let all: BTreeSet<EventId> = fixture.log.canonical().into_iter().collect();
        assert!(judge.judge(&all).needs_later_rules, "{name}");
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_grant_of_a_later_documents_space_never_counts() {
    let case = &family("held_spaces")["grant"];
    let edge = EventId(array(case, "edge"));
    let (x, z) = (EventId(named("X")), EventId(named("Z")));
    let grants = |kind, grants| SpaceGrants {
        kind,
        parent: None,
        grants,
    };
    let edge_to = GrantInForce {
        event: edge,
        target: GrantTarget::Space(z),
        level: Level::Write,
        session: false,
        capabilities: Vec::new(),
    };
    // At every implementation: with kind 3, and with a key from 5 on an
    // ordinary space or a carve-out.
    for kind in [
        DescriptorKind::Reserved(3),
        DescriptorKind::Reserved(0),
        DescriptorKind::Reserved(2),
    ] {
        let spaces = BTreeMap::from([
            (x, grants(DescriptorKind::Space, vec![edge_to.clone()])),
            (z, grants(kind, Vec::new())),
        ]);
        let verdicts = edge_verdicts(&spaces);
        let (_, verdict) = verdicts
            .iter()
            .find(|(e, _)| e.event == edge)
            .expect("the edge has a verdict");
        assert_eq!(
            verdict.err().map(|class| class.name()),
            Some(text(case, "verdict")),
            "{kind:?}"
        );
        assert_eq!(
            frasil_space::graph::effective(&spaces, &BTreeMap::new(), z, &verdicts)
                .err()
                .map(|class| class.name()),
            Some("ExtensionRequired")
        );
    }
    // A restricted space with a key from 5 stays a restricted space's edge.
    let spaces = BTreeMap::from([
        (x, grants(DescriptorKind::Space, vec![edge_to])),
        (z, grants(DescriptorKind::Reserved(1), Vec::new())),
    ]);
    assert_eq!(
        edge_verdicts(&spaces)
            .values()
            .next()
            .and_then(|v| v.err())
            .map(|class| class.name()),
        Some("GrantOfRestricted")
    );
}

/// `grant_key_5`: an edge to an ordinary space whose descriptor carries key
/// 5 never counts either (`GrantOfReserved`), beside one to a space of kind
/// 3 from the same granting space. Such a descriptor reads as a later
/// document's, with no kind of its own.
#[test]
fn a_grant_of_an_ordinary_space_with_descriptor_key_5_never_counts() {
    use frasil_base::cbor::{Map, Value};
    let case = family("held_spaces");
    let (x, z, k) = (
        EventId(named("X")),
        EventId(named("Z")),
        EventId(named("K")),
    );
    // A descriptor of an ordinary space (no key 2) with key 5.
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(1));
    map.insert(5, Value::Unsigned(1));
    let kind = Descriptor::read(&Value::Map(map).encode())
        .expect("a later document's descriptor reads")
        .kind;
    assert_eq!(kind, DescriptorKind::Reserved(0));
    let edge = |case: &serde_json::Value, target| GrantInForce {
        event: EventId(array(case, "edge")),
        target: GrantTarget::Space(target),
        level: Level::Write,
        session: false,
        capabilities: Vec::new(),
    };
    let grants = |kind, grants| SpaceGrants {
        kind,
        parent: None,
        grants,
    };
    let spaces = BTreeMap::from([
        (
            x,
            grants(
                DescriptorKind::Space,
                vec![edge(&case["grant"], z), edge(&case["grant_key_5"], k)],
            ),
        ),
        (z, grants(DescriptorKind::Reserved(3), Vec::new())),
        (k, grants(kind, Vec::new())),
    ]);
    let verdicts = edge_verdicts(&spaces);
    for name in ["grant", "grant_key_5"] {
        let id = EventId(array(&case[name], "edge"));
        let (_, verdict) = verdicts
            .iter()
            .find(|(e, _)| e.event == id)
            .expect("the edge has a verdict");
        assert_eq!(
            verdict.err().map(|class| class.name()),
            Some(text(&case[name], "verdict")),
            "{name}"
        );
    }
}
