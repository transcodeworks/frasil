//! identity.md, "What a list vouches for", in a space's key graph, with or
//! without any extension: under a person grant a writer wraps for each
//! active device, passkey member and recovery key of the person's merged
//! list that has not forked and is not waiting; an agent receives nothing;
//! and a space whose policy forbids agents wraps nothing for the devices of
//! a person whose merged list holds an active agent. A recovery key
//! receives wraps but never writes, so it never heals.

mod common;

use common::space::{
    Fixture, first_member, list_agent, list_device, name_other, person_id, prefix, whole_list,
};
use common::{family, text};
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, Kind as ListKind, MemberKeys};
use frasil_space::keygraph::{Kind, Member, SpaceHistory, heal_candidates, own_delivery, plan};
use frasil_space::{HeldList, MemberType, OtherLogs, Policy};

/// roster.json's history in which P grants person B.
const HISTORY: &str = "a person grant, a revocation in the list, and the space's response";

fn keys(name: &str) -> MemberKeys {
    list_device("identity/recipients/space", name)
}

/// Signs and inserts an `add` of `keys` as `kind`, by `signer`.
fn add(list: &mut DeviceList, kind: ListKind, keys: &MemberKeys, signer: &MemberKeys) {
    let person = list.person_id();
    let body = ListBody::add(
        kind,
        &keys.public(kind),
        keys.prove_possession(&person, signer.device_id(), kind),
    );
    let signed = list.sign(&body, signer.signer());
    list.insert(&signed).unwrap();
}

#[test]
fn waiting_members_agents_and_recovery_keys() {
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == HISTORY)
        .unwrap()
        .clone();
    let list_prefix = history["list_prefixes"]["person B"]
        .as_str()
        .unwrap()
        .to_owned();
    let events = &history["lists"]["person B"];
    let mut list: DeviceList = whole_list(events).list().unwrap().clone();
    let b1 = list_device(&list_prefix, "b1");
    let (recovery, agent, h) = (
        keys("recovery"),
        list_agent("identity/recipients/space", "agent"),
        keys("h"),
    );
    add(&mut list, ListKind::RecoveryKey, &recovery, &b1);
    add(&mut list, ListKind::RecoveryAgent, &agent, &b1);
    add(&mut list, ListKind::Device, &h, &agent);
    let (b1, recovery, agent, h) = (
        b1.device_id().0,
        recovery.device_id().0,
        agent.device_id().0,
        h.device_id().0,
    );
    let held = HeldList::new(list);
    assert!(held.waiting(&h) && !held.receives(&h), "h waits");
    assert!(held.receives(&b1) && held.receives(&recovery));
    let devices = held.key_devices();
    assert!(devices.contains(&h) && devices.contains(&recovery) && !devices.contains(&agent));
    assert!(held.members().contains(&h), "h reaches the space");
    assert!(
        !held.members().contains(&recovery),
        "a recovery key does not"
    );

    // A space whose policy forbids agents wraps for none of B's devices.
    let forbids = Policy {
        forbid_agents: true,
        ..Policy::default()
    };
    assert!(held.receives_under(&b1, &Policy::default()));
    for device in [b1, recovery, h] {
        assert!(!held.receives_under(&device, &forbids));
    }

    let mut fixture = Fixture::new(&prefix(HISTORY), &history["events"]);
    fixture.name_events(events);
    name_other(
        &mut fixture,
        "person B",
        person_id(events),
        MemberType::Person,
    );
    let person_b = Member::Roster(first_member(&fixture, "P grants person B write"));
    let p = fixture.device_key("P");
    let others = OtherLogs::none().with_list(held);
    let space = fixture.resolve(None, &fixture.keys, &others).unwrap();
    assert!(!space.policy().forbid_agents);
    let keys = SpaceHistory::new(&space);
    let graph = keys.key_graph();

    let devices = graph.devices(&person_b);
    assert!(devices.contains(&h) && devices.contains(&recovery) && !devices.contains(&agent));
    let wraps = graph.wrap_devices(&person_b);
    assert!(wraps.contains(&b1) && wraps.contains(&recovery));
    assert!(
        !wraps.contains(&h),
        "a waiting list member receives nothing"
    );
    assert!(!wraps.contains(&agent), "an agent receives nothing");
    let planned = plan(&graph, &[], Kind::Content, &[p], false);
    assert!(planned.wraps.iter().any(|w| w.device == recovery));
    assert!(
        planned
            .wraps
            .iter()
            .all(|w| w.device != h && w.device != agent)
    );
    let own = own_delivery(&graph, &p, Kind::Content).devices;
    assert!(own.contains(&recovery) && !own.contains(&h));
    assert!(graph.inside(Kind::Content).contains(&recovery));
    for kind in [Kind::Content, Kind::Grant] {
        let candidates = heal_candidates(&graph, kind);
        assert!(candidates.contains(&b1));
        assert!(
            !candidates.contains(&recovery),
            "a recovery key never heals"
        );
    }
}
