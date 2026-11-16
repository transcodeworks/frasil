//! ext-recovery-agent.json's `parameters`, and the waiting period in a
//! space's key graph, with feature `ext-recovery-agent`:
//!
//! - `parameters` ("The waiting period"): `agent_waiting_period`'s default
//!   and range, as the space policy reads and merges it;
//! - "The waiting period": a device an agent added to a person the space
//!   grants receives no wrap until this replica vouches for it, and then
//!   does. Its writes are unchanged.

#![cfg(feature = "ext-recovery-agent")]

mod common;

use common::space::{
    Fixture, first_member, list_agent, list_device, name_other, person_id, prefix, whole_list,
};
use common::{family, text};
use frasil_base::cbor::{Map, Value};
use frasil_base::time::{Reading, Timer};
use frasil_identity::ext_recovery_agent::{
    AGENT_WAITING_PERIOD, AGENT_WAITING_PERIOD_MAX, AgentWaits,
};
use frasil_identity::{DeviceList, Kind as ListKind, MemberKeys};
use frasil_space::ext_recovery_agent::waiting_period;
use frasil_space::keygraph::{Kind, Member, SpaceHistory, own_delivery, plan};
use frasil_space::policy::DEFAULT_AGENT_WAITING_PERIOD;
use frasil_space::{HeldList, MemberType, OtherLogs, Policy};
use serde_json::Value as Json;

fn vectors(name: &str) -> Json {
    frasil_testkit::vectors::family("ext-recovery-agent.json", name)
}

/// A policy whose only key besides the version is key 2.
fn policy_with(seconds: u64) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(1));
    map.insert(2, Value::Unsigned(seconds));
    Value::Map(map).encode()
}

#[test]
fn parameters() {
    let p = &vectors("parameters")["agent_waiting_period"];
    let (default, minimum, maximum) = (
        p["default"].as_u64().unwrap(),
        p["minimum"].as_u64().unwrap(),
        p["maximum"].as_u64().unwrap(),
    );
    assert_eq!(DEFAULT_AGENT_WAITING_PERIOD, default);
    assert_eq!(Policy::default().agent_waiting_period, default);
    assert_eq!(AGENT_WAITING_PERIOD, default);
    assert_eq!(AGENT_WAITING_PERIOD, minimum);
    assert_eq!(AGENT_WAITING_PERIOD_MAX, maximum);
    let spec = Timer::AgentWaitingPeriod.spec();
    assert_eq!(
        (spec.default, spec.minimum, spec.maximum),
        (Some(default), Some(minimum), Some(maximum))
    );
    // The policy reads the range, and never writes the default.
    assert!(Policy::read(&policy_with(minimum - 1)).is_err());
    assert!(
        Policy::read(&policy_with(default)).is_err(),
        "the default is not written"
    );
    assert_eq!(
        Policy::read(&policy_with(maximum)).map(|p| waiting_period(&p)),
        Ok(maximum)
    );
    assert!(Policy::read(&policy_with(maximum + 1)).is_err());
    // Merged to the longest.
    let longer = Policy {
        agent_waiting_period: 7 * 86_400,
        ..Policy::default()
    };
    assert_eq!(
        Policy::merge([&Policy::default(), &longer])
            .unwrap()
            .agent_waiting_period,
        7 * 86_400
    );
    assert_eq!(waiting_period(&Policy::default()), default);
}

fn at(timeline: u64) -> Reading {
    Reading {
        timeline,
        wall: None,
        run: 1,
    }
}

/// An agent's keys, and a device's, drawn from fixed seeds.
fn keys(name: &str) -> MemberKeys {
    list_device("ext-recovery-agent/space", name)
}

/// roster.json's history in which P grants person B, with B's list
/// extended: b1 names an agent, and the agent adds a device `h`.
#[test]
fn a_waiting_device_receives_once_vouched_for() {
    let name = "a person grant, a revocation in the list, and the space's response";
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap()
        .clone();
    let list_prefix = history["list_prefixes"]["person B"]
        .as_str()
        .unwrap()
        .to_owned();
    let events = &history["lists"]["person B"];
    let mut list: DeviceList = whole_list(events).list().unwrap().clone();
    let person = list.person_id();
    let b1 = list_device(&list_prefix, "b1");
    let (agent, h) = (list_agent("ext-recovery-agent/space", "agent"), keys("h"));
    let named = list
        .name_agent(
            &agent.public(ListKind::RecoveryAgent),
            &agent.prove_possession(&person, b1.device_id(), ListKind::RecoveryAgent),
            &b1,
        )
        .unwrap();
    list.insert(&named).unwrap();
    let added = list
        .agent_add_device(
            &h.public(ListKind::Device),
            &h.prove_possession(&person, agent.device_id(), ListKind::Device),
            &agent,
        )
        .unwrap();
    list.insert(&added).unwrap();
    let h = h.device_id().0;
    let mut extended = HeldList::new(list);
    assert!(extended.waiting(&h) && !extended.receives(&h));
    assert!(extended.receives(&b1.device_id().0));

    let mut fixture = Fixture::new(&prefix(name), &history["events"]);
    fixture.name_events(events);
    name_other(
        &mut fixture,
        "person B",
        person_id(events),
        MemberType::Person,
    );
    let person_b = first_member(&fixture, "P grants person B write");
    let p = fixture.device_key("P");

    // Who the key graph wraps for, at this replica, as it decides.
    let wraps_for_h = |held: &HeldList| {
        let others = OtherLogs::none().with_list(held.clone());
        let space = fixture.resolve(None, &fixture.keys, &others).unwrap();
        let keys = SpaceHistory::new(&space);
        let graph = keys.key_graph();
        let member = Member::Roster(person_b);
        assert!(graph.devices(&member).contains(&h), "h reaches the space");
        let wraps = graph.wrap_devices(&member).contains(&h);
        let planned = plan(&graph, &[], Kind::Content, &[p], false)
            .wraps
            .iter()
            .any(|w| w.device == h);
        let own = own_delivery(&graph, &p, Kind::Content).devices.contains(&h);
        assert_eq!(wraps, planned, "the plan wraps for h");
        assert_eq!(wraps, own, "a rotation's own delivery wraps for h");
        wraps
    };
    let mut waits = AgentWaits::new();
    let period = waiting_period(&Policy::default());
    assert!(extended.vouch(&mut waits, &at(1_000), period).is_empty());
    assert!(!wraps_for_h(&extended), "waiting: no wrap");
    assert!(
        extended
            .vouch(&mut waits, &at(1_000 + period - 1), period)
            .is_empty()
    );
    assert!(!wraps_for_h(&extended));
    assert!(
        extended
            .vouch(&mut waits, &at(1_000 + period), period)
            .contains(&h)
    );
    assert!(wraps_for_h(&extended), "vouched: wrapped for");
    // The space's resolution is the same either way: waiting decides only
    // who this replica wraps for.
    let unchanged = |held: &HeldList| {
        let others = OtherLogs::none().with_list(held.clone());
        let space = fixture.resolve(None, &fixture.keys, &others).unwrap();
        fixture.summary(&space, true)
    };
    let mut waiting = extended.clone();
    waiting.set_vouched(Default::default());
    assert_eq!(unchanged(&waiting), unchanged(&extended));
}
