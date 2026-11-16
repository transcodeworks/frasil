//! ext-recovery-agent.json's families of the waiting decision, with feature
//! `ext-recovery-agent`:
//!
//! - `waiting_decisions` ("The waiting period"): the decision on readings;
//! - `recipients_while_waiting` ("The waiting period", "The late verifier,
//!   and no witness"): a list in which a device names an agent, the agent
//!   adds a device and that device adds another, and the devices each
//!   verifier wraps for.
//!
//! Then "Naming an agent", "Adding a device through the agent" and "Relay
//! and veto", over the same list, rebuilt byte for byte.

#![cfg(feature = "ext-recovery-agent")]

mod common;

use common::{bytes, class, device, list_of, text};
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_identity::MemberKeys;
use frasil_identity::ext_recovery_agent::{
    AGENT_WAITING_PERIOD, AgentWaits, Outcome, agent_waiting, new_agent_adds,
};
use frasil_identity::{DeviceList, Kind, MergedList};
use serde_json::Value as Json;
use std::collections::BTreeMap;

const FILE: &str = "ext-recovery-agent.json";
/// The prefix identity.py's builder named this list's keys under.
const PREFIX: &str = "identity/wait";
const NAMES: [&str; 5] = ["laptop", "agent", "helped", "helped2", "both"];

/// The keys of a list member of this list: the agents have no X-Wing key.
fn member(name: &str) -> MemberKeys {
    if name.contains("agent") {
        common::agent(PREFIX, name)
    } else {
        device(PREFIX, name)
    }
}

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn reading(value: &Json) -> Reading {
    Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    }
}

/// A reading on the timeline alone, as `recipients_while_waiting` gives.
fn at(timeline: u64) -> Reading {
    Reading {
        timeline,
        wall: None,
        run: 1,
    }
}

#[test]
fn waiting_decisions() {
    let cases = family("waiting_decisions");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for (i, case) in cases.iter().enumerate() {
        let got = agent_waiting(
            !case["vetoed"].as_bool().unwrap(),
            !case["confirmed"].as_bool().unwrap(),
            &reading(&case["first_sight"]),
            &reading(&case["now"]),
            case["agent_waiting_period"].as_u64().unwrap(),
        );
        assert_eq!(got.name(), text(case, "outcome"), "case {i}: {case}");
    }
}

/// The list of `recipients_while_waiting`, its events by name, and each
/// list member's name by identity key.
struct Fixture {
    events: Vec<Json>,
    list: DeviceList,
    ids: BTreeMap<String, EventId>,
    names: BTreeMap<DeviceId, &'static str>,
}

impl Fixture {
    fn new() -> Self {
        let family = family("recipients_while_waiting");
        let events = family["events"].as_array().unwrap().clone();
        let rows: Vec<&Json> = events.iter().collect();
        let (list, by_id) = list_of(&rows);
        let ids = by_id.into_iter().map(|(id, name)| (name, id)).collect();
        let names = NAMES
            .into_iter()
            .map(|name| (*member(name).device_id(), name))
            .collect();
        Self {
            events,
            list,
            ids,
            names,
        }
    }

    fn signed(&self, name: &str) -> Vec<u8> {
        let row = self
            .events
            .iter()
            .find(|e| text(e, "name") == name)
            .unwrap();
        bytes(row, "signed")
    }

    /// The list holding the events up to `last`, in the vector's order.
    fn up_to(&self, last: &str) -> DeviceList {
        let end = self
            .events
            .iter()
            .position(|row| text(row, "name") == last)
            .unwrap();
        let mut list = DeviceList::new(&bytes(&self.events[0], "signed")).unwrap();
        for row in &self.events[1..=end] {
            list.insert(&bytes(row, "signed")).unwrap();
        }
        list
    }

    fn named(&self, identities: &[DeviceId]) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = identities.iter().map(|k| self.names[k]).collect();
        out.sort_unstable();
        out
    }
}

#[test]
fn recipients_while_waiting() {
    let fixture = Fixture::new();
    let merged = fixture.list.merge();
    // In core protocol 1 neither device the agent's line added receives
    // anything until a confirm clears it.
    assert_eq!(fixture.named(&merged.recipients()), ["laptop"]);
    let cases = family("recipients_while_waiting")["cases"].clone();
    for case in cases.as_array().unwrap() {
        let mut waits = AgentWaits::new();
        for (add, first) in case["first_sight"].as_object().unwrap() {
            assert!(waits.saw(fixture.ids[add], at(first.as_u64().unwrap())));
        }
        let now = at(case["now"].as_u64().unwrap());
        let period = case["agent_waiting_period"].as_u64().unwrap();
        let got = waits.recipients(&merged, &now, period);
        let want: Vec<&str> = case["wraps_for"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        assert_eq!(fixture.named(&got), want, "{}", text(case, "name"));
    }
}

/// "Vouched sticks": a lengthened period does not take back a decision,
/// and no later add moves a first sight. A veto ends it.
#[test]
fn vouched_sticks_while_active() {
    let fixture = Fixture::new();
    let merged = fixture.list.merge();
    let helped = *member("helped").device_id();
    let mut waits = AgentWaits::new();
    // The agent's adds of helped and both, and helped's of helped2; not the
    // laptop's add of both, which roots nothing in the agent.
    assert_eq!(waits.see(&merged, at(1_000)).len(), 3);
    assert!(
        waits.see(&merged, at(2_000)).is_empty(),
        "a later sight moves nothing"
    );
    let decide = |waits: &mut AgentWaits, now: u64, period: u64| {
        waits.decide(&merged, &helped, &at(now), period)
    };
    assert_eq!(
        decide(&mut waits, 1_000 + 3_600, AGENT_WAITING_PERIOD),
        Some(Outcome::Waiting)
    );
    assert_eq!(
        decide(
            &mut waits,
            1_000 + AGENT_WAITING_PERIOD,
            AGENT_WAITING_PERIOD
        ),
        Some(Outcome::Vouched)
    );
    assert_eq!(
        decide(&mut waits, 1_000 + AGENT_WAITING_PERIOD + 1, 7 * 86_400),
        Some(Outcome::Vouched),
        "a lengthened period"
    );
    let laptop = *member("laptop").device_id();
    assert_eq!(
        waits.decide(&merged, &laptop, &at(0), AGENT_WAITING_PERIOD),
        None
    );
    let agent = *member("agent").device_id();
    assert_eq!(
        waits.decide(&merged, &agent, &at(0), AGENT_WAITING_PERIOD),
        None
    );
}

/// "Naming an agent" and "Adding a device through the agent": the laptop's
/// `add` of the agent and the agent's `add` of the helped device, rebuilt
/// byte for byte from the list before each.
#[test]
fn naming_an_agent_and_its_add() {
    let fixture = Fixture::new();
    let laptop = member("laptop");
    let agent = member("agent");
    let helped = member("helped");

    let first = fixture.up_to("laptop starts the list");
    let person = first.person_id();
    let agent_keys = agent.public(Kind::RecoveryAgent);
    let proof = agent.prove_possession(&person, laptop.device_id(), Kind::RecoveryAgent);
    assert_eq!(
        first.name_agent(&agent_keys, &proof, &laptop).unwrap(),
        fixture.signed("laptop adds agent")
    );
    // The proof binds kind 3 and the naming list member; an agent's keys
    // carry no X-Wing key.
    let as_device = agent.prove_possession(&person, laptop.device_id(), Kind::Device);
    assert_eq!(
        class(first.name_agent(&agent_keys, &as_device, &laptop)),
        Some("BadPossession")
    );
    assert_eq!(
        class(first.name_agent(
            &device(PREFIX, "agent").public(Kind::Device),
            &proof,
            &laptop
        )),
        Some("Malformed")
    );
    assert_eq!(
        class(first.name_agent(
            &laptop.public(Kind::RecoveryAgent),
            &laptop.prove_possession(&person, laptop.device_id(), Kind::RecoveryAgent),
            &laptop
        )),
        Some("AlreadyListed")
    );

    let named = fixture.up_to("laptop adds agent");
    let helped_keys = helped.public(Kind::Device);
    let helped_proof = helped.prove_possession(&person, agent.device_id(), Kind::Device);
    assert_eq!(
        named
            .agent_add_device(&helped_keys, &helped_proof, &agent)
            .unwrap(),
        fixture.signed("agent adds helped")
    );
    // The proof the device signed for the agent serves no other adder.
    assert_eq!(
        class(named.agent_add_device(&helped_keys, &helped_proof, &laptop)),
        Some("BadPossession")
    );
    let for_laptop = helped.prove_possession(&person, laptop.device_id(), Kind::Device);
    assert_eq!(
        class(named.agent_add_device(&helped_keys, &for_laptop, &laptop)),
        Some("UntrustedSigner"),
        "only an agent adds through the agent"
    );
    // A device rooted in the agent names no agent.
    let whole = &fixture.list;
    let other = member("other agent");
    let other_keys = other.public(Kind::RecoveryAgent);
    let for_helped = other.prove_possession(&person, helped.device_id(), Kind::RecoveryAgent);
    assert_eq!(
        class(whole.name_agent(&other_keys, &for_helped, &helped)),
        Some("UntrustedSigner")
    );
    let other_proof = other.prove_possession(&person, laptop.device_id(), Kind::RecoveryAgent);
    assert!(whole.name_agent(&other_keys, &other_proof, &laptop).is_ok());

    // The agent's add travels with the list events before it.
    let add = fixture.ids["agent adds helped"];
    let with_past: Vec<Vec<u8>> = [
        "laptop starts the list",
        "laptop adds agent",
        "agent adds helped",
    ]
    .iter()
    .map(|n| fixture.signed(n))
    .collect();
    assert_eq!(fixture.list.with_past(add), with_past);
}

/// "Relay and veto": what a device raises and relays, and the veto, which
/// a device that is not rooted signs and which outranks the agent's line.
#[test]
fn raise_relay_and_veto() {
    let fixture = Fixture::new();
    let merged = fixture.list.merge();
    let named = fixture.up_to("laptop adds agent").merge();
    let raised = new_agent_adds(Some(&named), &merged);
    assert_eq!(
        raised,
        [
            fixture.ids["agent adds helped"],
            fixture.ids["helped adds helped2"],
            fixture.ids["agent adds both, concurrently"]
        ]
    );
    assert!(new_agent_adds(Some(&merged), &merged).is_empty());
    assert_eq!(new_agent_adds(None, &merged), raised);

    let laptop = member("laptop");
    let [agent, helped, helped2] = ["agent", "helped", "helped2"].map(|n| *member(n).device_id());
    let bodies = fixture.list.veto(&merged, &helped, true);
    let targets: Vec<DeviceId> = bodies.iter().map(|b| b.device).collect();
    assert_eq!(targets[0], helped);
    assert_eq!(
        fixture.named(&targets),
        ["agent", "helped", "helped2"],
        "the device, every list member added through it, and the agent; \
         not both, which the agent added itself"
    );
    assert_eq!(fixture.list.veto(&merged, &helped, false).len(), 2);
    assert!(
        fixture
            .list
            .veto(&merged, laptop.device_id(), true)
            .is_empty()
    );
    assert!(fixture.list.veto(&merged, &agent, true).is_empty());

    let mut list = fixture.list.clone();
    let mut waits = AgentWaits::new();
    waits.see(&merged, at(0));
    for body in &bodies {
        list.insert(&list.sign(body, laptop.signer())).unwrap();
    }
    let vetoed: MergedList = list.merge();
    for identity in [agent, helped, helped2] {
        assert!(vetoed.active(&identity).is_none());
    }
    assert_eq!(
        waits.decide(&vetoed, &helped, &at(80 * 3_600), AGENT_WAITING_PERIOD),
        Some(Outcome::Vetoed)
    );
    assert_eq!(fixture.named(&vetoed.recipients()), ["laptop"]);
    // Every revocation is valid at the laptop's rank.
    for id in list.log().canonical() {
        assert!(vetoed.is_valid(id), "{id:?}");
    }
}
