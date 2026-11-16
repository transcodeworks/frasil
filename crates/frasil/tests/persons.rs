//! Persons: a device list and its personal space, a space that grants a
//! person, sealed list copies, and a person's new device.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, MemberType, Status, Via};

async fn device() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

#[tokio::test]
async fn a_person_and_its_personal_space() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, _) = Engine::create(platform.clone(), &[1; 32], registry.clone())
        .await
        .unwrap();
    let made = alice.make_person(&[1; 32]).await.unwrap();
    let (granted, level) = alice
        .read(&made.personal_space, |r| {
            (
                r.roster()
                    .members_in()
                    .any(|(m, _)| m.kind == MemberType::Person && m.id == made.person),
                r.level_of(&alice.device_id()),
            )
        })
        .await
        .unwrap();
    assert!(granted, "the personal space grants the person");
    assert_eq!(level, Some(Level::Administer));
    assert_eq!(
        alice.person_devices(&made.person).await,
        vec![alice.device_id()]
    );
    drop(alice);
    // The keys now name the person, and the device reopens as its device.
    let alice = Engine::open_as(
        platform,
        &made.sealed,
        &[1; 32],
        Some(made.person),
        registry,
    )
    .await
    .unwrap();
    assert_eq!(alice.person().await, Some(made.person));
    assert_eq!(alice.list_events(&made.person).await.len(), 1);
}

#[tokio::test]
async fn a_space_grants_a_person_whose_devices_write() {
    let alice = device().await;
    let bob = device().await;
    let phone = device().await;
    let space = alice.create_space().await.unwrap();
    let bob_person = bob.make_person(&[7; 32]).await.unwrap().person;

    // Alice holds Bob's list, as a code exchange with a person joiner
    // hands it over, and grants the person with history.
    alice
        .receive_list(bob.list_events(&bob_person).await)
        .await
        .unwrap();
    let grant = alice
        .grant_person(
            space,
            bob_person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &bob_person).await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "for bob").unwrap();
        })
        .await
        .unwrap();

    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    let (status, level) = bob
        .read(&space, |r| {
            (r.status(&grant).copied(), r.level_of(&bob.device_id()))
        })
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        level,
        Some(Level::Write),
        "Bob reaches the space through his person"
    );
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "for bob"
    );
    let unit = bob
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "from bob, ").unwrap();
        })
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    let accepted = alice
        .read(&space, |r| r.status(&unit).copied())
        .await
        .unwrap();
    assert!(matches!(accepted, Some(Status::Valid(_))), "{accepted:?}");

    // Bob adds his phone to his person: the add travels as a list copy,
    // and Bob delivers the space's current state to the phone.
    let (keys, proof) = phone.list_keys(&bob_person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(bob_person, bob.list_events(&bob_person).await, &[7; 32])
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    phone.follow(space).await;
    carry(&alice, &phone, space).await;
    assert_eq!(
        phone
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    assert_eq!(
        text(&phone.document(&space, &doc.stream()).await.unwrap()),
        "from bob, for bob"
    );
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    let _ = MemberRef::person(bob_person);
}

/// A writer's capabilities at a unit's place are those of its strongest
/// path (units.md, 3.17 "Capability checks"): a person granted as a
/// suggester writes only suggestions from each of its devices, and a direct
/// edit from one of them is refused as content at every replica.
#[tokio::test]
async fn a_person_granted_as_a_suggester_writes_no_direct_edit() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let bob_person = bob.make_person(&[7; 32]).await.unwrap().person;
    alice
        .receive_list(bob.list_events(&bob_person).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            bob_person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &bob_person).await.unwrap();
    alice
        .set_suggester(space, MemberRef::person(bob_person), true)
        .await
        .unwrap()
        .expect("the person becomes a suggester");
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "for bob").unwrap();
        })
        .await
        .unwrap();

    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    for (engine, whose) in [(&alice, "Alice's"), (&bob, "Bob's")] {
        let (level, suggester) = engine
            .read(&space, |r| {
                (
                    r.level_of(&bob.device_id()),
                    r.capabilities_of(&bob.device_id()).is_suggester(),
                )
            })
            .await
            .unwrap();
        assert_eq!(level, Some(Level::Write), "in {whose} view");
        assert!(
            suggester,
            "Bob is a suggester through his person in {whose} view"
        );
    }
    let unit = bob
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "from bob, ").unwrap();
        })
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    let status = alice
        .read(&space, |r| r.status(&unit).copied())
        .await
        .unwrap();
    // Valid by the write rule; its content is refused.
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "for bob",
        "a suggester's direct edit is refused"
    );
}
