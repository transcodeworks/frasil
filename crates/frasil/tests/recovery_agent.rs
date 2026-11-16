//! The recovery agent through the engine (ext-recovery-agent.md): Bob names
//! an agent, the agent adds a device, Bob's device raises the add and
//! relays it into the space that grants Bob; Alice wraps nothing for the
//! device until her waiting period has run, keeps her decision at rest,
//! then delivers the space to it; and Bob's veto revokes it.
#![cfg(all(feature = "ext-recovery-agent", feature = "adapter-loro"))]

use frasil::advanced::platform::ManualClock;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_identity::{DeviceList, Kind, MemberKeys};
use frasil_space::{HistoryMode, Level, Via};
use std::sync::Arc;

/// `agent_waiting_period`'s default: 72 hours.
const WAIT: u64 = 72 * 3600;

async fn device(clock: &Arc<ManualClock>, key: u8) -> (Engine, Platform, [u8; 235]) {
    let platform = Platform::memory().with_clock(clock.clone());
    let (engine, sealed) = Engine::create(
        platform.clone(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    (engine, platform, sealed)
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

/// A list as the agent holds it: the person's events, in order.
fn list_of(events: Vec<Vec<u8>>) -> DeviceList {
    let mut events = events
        .into_iter()
        .map(|signed| frasil_events::decode(&signed).unwrap());
    let mut list = DeviceList::from_first(events.next().unwrap()).unwrap();
    for event in events {
        list.insert_event(event).unwrap();
    }
    list
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

#[tokio::test]
async fn an_agents_add_waits_then_is_vouched_or_vetoed() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let (alice, alice_platform, alice_sealed) = device(&clock, 1).await;
    let (bob, _, _) = device(&clock, 2).await;
    let (helped, _, _) = device(&clock, 3).await;
    let space = alice.create_space().await.unwrap();
    let person = bob.make_person(&[2; 32]).await.unwrap().person;
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &person).await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "kept").unwrap();
        })
        .await
        .unwrap();
    bob.follow(space).await;
    carry(&alice, &bob, space).await;

    // Bob names an agent; the agent adds the helped device.
    // An agent has no X-Wing key: its device ID hashes an empty one.
    let agent = MemberKeys::without_xwing(&[9; 32], &[11; 32]);
    let (_, past) = bob
        .name_agent(
            agent.public(Kind::RecoveryAgent),
            agent.prove_possession(&person, &bob.device_id(), Kind::RecoveryAgent),
        )
        .await
        .unwrap();
    let list = list_of(past);
    let (keys, proof) = helped.list_keys(&person, agent.device_id());
    let add = list.agent_add_device(&keys, &proof, &agent).unwrap();
    let mut with_past = bob.list_events(&person).await;
    with_past.push(add);

    // Bob's device raises the add, and relays it into the space before
    // anything else it writes there.
    let mut notices = bob.subscribe();
    bob.receive_list(with_past).await.unwrap();
    let raised = notices.try_recv().expect("a raise");
    assert_eq!(raised.space, EventId(person));
    assert_eq!(bob.agent_added().await, vec![helped.device_id()]);
    bob.relay_agent_adds(space).await.unwrap();
    carry(&bob, &alice, space).await;

    // Alice wraps nothing for the helped device while it waits.
    alice.relay_agent_adds(space).await.unwrap();
    assert!(alice.vouched(&space).await.is_empty());
    helped.follow(space).await;
    carry(&alice, &helped, space).await;
    assert!(helped.document(&space, &doc.stream()).await.is_err());

    // After the waiting period Alice vouches, keeps that at rest, and
    // delivers the space to it.
    clock.advance(WAIT);
    alice.maintain_all().await.unwrap();
    assert_eq!(alice.vouched(&space).await, vec![helped.device_id()]);
    alice.relay_agent_adds(space).await.unwrap();
    carry(&alice, &helped, space).await;
    assert_eq!(
        text(&helped.document(&space, &doc.stream()).await.unwrap()),
        "kept"
    );
    drop(alice);
    let alice = Engine::open(
        alice_platform,
        &alice_sealed,
        &[1; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    assert_eq!(alice.vouched(&space).await, vec![helped.device_id()]);

    // Bob vetoes: the helped device and the agent are revoked, each
    // revocation on Bob's chain in turn.
    let revoked = bob.veto(helped.device_id(), true).await.unwrap();
    assert_eq!(revoked.len(), 2);
    assert!(bob.agent_added().await.is_empty());
    // Alice takes the list's new state (the space's cascaded rotation
    // carries it there later), and lets go of her decision.
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    alice.maintain_all().await.unwrap();
    assert!(alice.vouched(&space).await.is_empty());
}

/// The high-level API: a person's device reads the spaces' agent policy,
/// names an agent from the keys and proof the agent returns, and hands
/// the agent the list's events, from which the agent adds a device.
#[tokio::test]
async fn a_device_names_an_agent_through_the_high_level_api() {
    use frasil::{AgentKeys, Device, Options};

    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let (bob, _, _) = device(&clock, 21).await;
    let (helped, _, _) = device(&clock, 22).await;
    let bob = Device::from_engine(bob, Options::new().loopback()).unwrap();
    let person = bob.make_person(&[21; 32]).await.unwrap();
    let personal = bob.personal_space().await.expect("the personal space");
    let space = bob.create_space().await.unwrap();

    let policy = space.agent_policy().await.unwrap();
    assert!(!policy.forbids_agents);
    assert_eq!(policy.waiting_period.as_secs(), WAIT);
    assert!(bob.spaces_forbidding_agents().await.is_empty());
    assert!(
        !bob.space(personal)
            .await
            .unwrap()
            .agent_policy()
            .await
            .unwrap()
            .forbids_agents
    );

    // The agent is given the person ID, and returns its keys and proof.
    let agent = MemberKeys::without_xwing(&[23; 32], &[25; 32]);
    let person_id = *person.as_bytes();
    let bob_id = DeviceId(*bob.id().as_bytes());
    let wrong = AgentKeys::new(
        agent.identity().0,
        agent.mldsa(),
        agent.prove_possession(&[0; 32], &bob_id, Kind::RecoveryAgent),
    )
    .unwrap();
    assert!(
        bob.name_agent(&wrong).await.is_err(),
        "a proof over another person"
    );
    assert!(AgentKeys::new(agent.identity().0, &[0; 10], Vec::new()).is_err());
    let keys = AgentKeys::new(
        agent.identity().0,
        agent.mldsa(),
        agent.prove_possession(&person_id, &bob_id, Kind::RecoveryAgent),
    )
    .unwrap();
    let named = bob.name_agent(&keys).await.unwrap();
    assert_eq!(
        frasil_events::decode(named.list_events.last().unwrap())
            .unwrap()
            .id()
            .0,
        *named.add.as_bytes()
    );

    // From those events the agent adds a device, which Bob's device takes
    // as an add rooted in the agent.
    let list = list_of(named.list_events);
    let (device_keys, proof) = helped.list_keys(&person_id, agent.device_id());
    let add = list.agent_add_device(&device_keys, &proof, &agent).unwrap();
    let mut events = bob.engine().list_events(&person_id).await;
    events.push(add);
    bob.engine().receive_list(events).await.unwrap();
    assert_eq!(bob.engine().agent_added().await, vec![helped.device_id()]);
}
