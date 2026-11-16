//! Automatic heals and cascades: a project that grants a team answers the
//! team's changes, and a space that grants a person answers the person's
//! list's revocation, each after its rank delay.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::maintenance::Maintained;
use frasil::advanced::platform::ManualClock;
use frasil::advanced::{AdapterRegistry, Engine, OsRandom, Platform, Random};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use std::sync::Arc;

async fn device(clock: &Arc<ManualClock>) -> Engine {
    let platform = Platform::memory().with_clock(clock.clone());
    Engine::create(platform, &[7; 32], AdapterRegistry::with_builtins())
        .await
        .expect("a device")
        .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

/// Runs `maintain` until it signs, moving the clock on a second at a time;
/// returns what it signed and the seconds it waited.
async fn maintain_until(device: &Engine, clock: &ManualClock, space: EventId) -> (Maintained, u64) {
    for waited in 0..4_000 {
        let done = device.maintain(space).await.unwrap();
        if done != Maintained::default() {
            return (done, waited);
        }
        clock.advance(1);
    }
    panic!("nothing became due");
}

/// A team of Alice, Carol and Dave, and a project of Alice's that grants
/// the team at `write`; every device holds both logs.
async fn team_and_project(clock: &Arc<ManualClock>) -> ([Engine; 3], EventId, EventId) {
    let alice = device(clock).await;
    let carol = device(clock).await;
    let dave = device(clock).await;
    let team = alice.create_space().await.unwrap();
    for other in [&carol, &dave] {
        alice
            .grant_device(
                team,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let project = alice.create_space().await.unwrap();
    alice
        .grant_space(project, team, Level::Write)
        .await
        .unwrap();
    for other in [&carol, &dave] {
        for space in [team, project] {
            other.follow(space).await;
            carry(&alice, other, space).await;
        }
    }
    ([alice, carol, dave], team, project)
}

#[tokio::test]
async fn a_removal_in_a_granted_team_cascades_into_the_project() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let ([alice, carol, dave], team, project) = team_and_project(&clock).await;
    assert_eq!(
        alice
            .read(&project, |r| r.level_of(&dave.device_id()))
            .await
            .unwrap(),
        Some(Level::Write),
        "Dave reaches the project through the team"
    );
    assert!(alice.owed_responses(&project).await.is_empty());

    let removal = alice
        .remove(team, MemberRef::device(dave.device_id()))
        .await
        .unwrap();
    carry(&alice, &carol, team).await;
    assert_eq!(alice.owed_responses(&project).await, vec![(team, removal)]);
    assert_eq!(carol.owed_responses(&project).await, vec![(team, removal)]);
    // Dave still holds the project's key through the team's old grant
    // key: he is a holder outside the inside.
    let test = alice.read(&project, |r| r.heal_test()).await.unwrap();
    assert!(test.contains(&(false, "outside")), "{test:?}");
    // Until the project rotates, neither writes to it.
    let doc = alice.new_document().unwrap();
    assert!(
        alice
            .edit_document(project, &doc, |d| {
                d.get_text("body").insert(0, "too soon").unwrap();
            })
            .await
            .is_err()
    );

    // Both are candidates; the first in rank order rotates at once, the
    // other waits its delay.
    let a = alice.maintain(project).await.unwrap();
    let c = carol.maintain(project).await.unwrap();
    let (first, second, rotation) = match (a.rotation, c.rotation) {
        (Some(id), None) => (&alice, &carol, id),
        (None, Some(id)) => (&carol, &alice, id),
        other => panic!("exactly one candidate rotates at once: {other:?}"),
    };
    carry(first, second, project).await;
    // The response is in force: the second stands down.
    assert!(second.owed_responses(&project).await.is_empty());
    clock.advance(3_600);
    assert_eq!(
        second.maintain(project).await.unwrap(),
        Maintained::default()
    );
    assert!(
        second
            .read(&project, |r| r.heal_test())
            .await
            .unwrap()
            .is_empty()
    );

    // Carol opens the rotation through the team's new grant key; Dave,
    // who holds every event, does not.
    carry(first, &carol, project).await;
    assert!(
        carol
            .read(&project, |r| r.secrets_held(&rotation))
            .await
            .unwrap()
    );
    carry(&alice, &dave, team).await;
    carry(first, &dave, project).await;
    assert!(
        !dave
            .read(&project, |r| r.secrets_held(&rotation))
            .await
            .unwrap()
    );
    assert_eq!(
        alice
            .read(&project, |r| r.level_of(&dave.device_id()))
            .await
            .unwrap(),
        None
    );
    // Writing resumes.
    alice
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "after the cascade").unwrap();
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_heal_of_the_team_grant_key_rotates_the_project() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let ([alice, carol, _dave], team, project) = team_and_project(&clock).await;
    let heal = alice.heal(team).await.unwrap();
    assert_eq!(alice.owed_responses(&project).await, vec![(team, heal)]);
    let (done, _) = maintain_until(&alice, &clock, project).await;
    let rotation = done.rotation.expect("a heal of C's grant key rotates X");
    assert!(alice.owed_responses(&project).await.is_empty());
    carry(&alice, &carol, team).await;
    carry(&alice, &carol, project).await;
    assert!(
        carol
            .read(&project, |r| r.secrets_held(&rotation))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_change_that_loses_no_device_only_delivers() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let ([alice, carol, dave], team, project) = team_and_project(&clock).await;
    // Dave is also a direct member of the project: when the team removes
    // him, the project loses no device and keeps its key.
    alice
        .grant_device(
            project,
            dave.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let removal = alice
        .remove(team, MemberRef::device(dave.device_id()))
        .await
        .unwrap();
    assert_eq!(alice.owed_responses(&project).await, vec![(team, removal)]);
    let current = alice
        .read(&project, |r| r.current().cloned())
        .await
        .unwrap();
    let (done, _) = maintain_until(&alice, &clock, project).await;
    assert!(done.rotation.is_none(), "{done:?}");
    assert!(done.delivery.is_some(), "{done:?}");
    assert!(alice.owed_responses(&project).await.is_empty());
    assert_eq!(
        alice
            .read(&project, |r| r.current().cloned())
            .await
            .unwrap(),
        current,
        "the project keeps its key"
    );
    assert_eq!(
        alice
            .read(&project, |r| r.level_of(&dave.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    // Carol still reaches the project through the team's new rotation.
    carry(&alice, &carol, team).await;
    carry(&alice, &carol, project).await;
    assert!(carol.owed_responses(&project).await.is_empty());
    assert_eq!(
        carol
            .read(&project, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
}

#[tokio::test]
async fn a_revoked_device_of_a_person_cascades() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let alice = device(&clock).await;
    let bob = device(&clock).await;
    let phone = device(&clock).await;
    let space = alice.create_space().await.unwrap();
    let person = bob.make_person(&[7; 32]).await.unwrap().person;
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
    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    let (keys, proof) = phone.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(person, bob.list_events(&person).await, &[7; 32])
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    // Alice's own events name the list before the phone joined it; the
    // add answers nothing, so nothing is owed yet.
    assert!(alice.owed_responses(&space).await.is_empty());

    // Bob revokes the phone: he knows of the change, so he answers it with
    // a rotation before the list copy that tells Alice.
    let revoke = bob.revoke_device(phone.device_id()).await.unwrap();
    assert_eq!(
        bob.owed_responses(&space).await,
        vec![(EventId(person), revoke)]
    );
    let (done, _) = maintain_until(&bob, &clock, space).await;
    let rotation = done.rotation.expect("a revocation's response rotates");
    assert!(bob.owed_responses(&space).await.is_empty());
    carry(&bob, &alice, space).await;
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        None
    );
    assert!(alice.owed_responses(&space).await.is_empty());
    assert!(
        alice
            .read(&space, |r| r.secrets_held(&rotation))
            .await
            .unwrap()
    );
    phone.follow(space).await;
    carry(&bob, &phone, space).await;
    assert!(
        !phone
            .read(&space, |r| r.secrets_held(&rotation))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_device_added_to_a_granted_person_is_delivered_by_a_member() {
    // Bob's person is granted; Bob never holds the space. He adds his
    // phone, so no device of the space has published the add or delivered
    // to it. Alice receives the list's new events by another path: her
    // maintenance publishes them and delivers the current state to the
    // phone after her rank delay, once (identity.md, "Other spaces").
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let alice = device(&clock).await;
    let bob = device(&clock).await;
    let phone = device(&clock).await;
    let space = alice.create_space().await.unwrap();
    let person = bob.make_person(&[7; 32]).await.unwrap().person;
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
            d.get_text("body").insert(0, "for bob").unwrap();
        })
        .await
        .unwrap();
    // Nothing is owed while the list is as the space has it.
    assert_eq!(alice.maintain(space).await.unwrap(), Maintained::default());

    let (keys, proof) = phone.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(person, bob.list_events(&person).await, &[7; 32])
        .await
        .unwrap();
    phone.follow(space).await;
    carry(&alice, &phone, space).await;
    assert_eq!(
        phone
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        None,
        "nothing delivered to the phone yet"
    );

    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    let (done, _) = maintain_until(&alice, &clock, space).await;
    assert!(done.rotation.is_none(), "a delivery, not a rotation");
    assert!(done.delivery.is_some());
    assert_eq!(
        alice.maintain(space).await.unwrap(),
        Maintained::default(),
        "delivered once"
    );
    carry(&alice, &phone, space).await;
    assert_eq!(
        phone
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    assert_eq!(
        phone
            .document(&space, &doc.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "for bob"
    );
}

/// Randomness that fails the 64-byte draws a key event's wraps take, while
/// armed: a delivery fails, and a unit, whose nonces are shorter, does not.
struct WrapsFail {
    armed: std::sync::atomic::AtomicBool,
}

impl Random for WrapsFail {
    fn fill(&self, out: &mut [u8]) -> frasil::Result<()> {
        if out.len() == 64 && self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(frasil::Error::NoRandomness);
        }
        OsRandom.fill(out)
    }
}

#[tokio::test]
async fn a_failed_delivery_to_a_persons_new_device_is_tried_again() {
    // Alice's first delivery to Bob's phone fails: the add is not
    // published either, so her next maintenance delivers it.
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let random = Arc::new(WrapsFail {
        armed: std::sync::atomic::AtomicBool::new(false),
    });
    let alice = Engine::create(
        Platform::memory()
            .with_clock(clock.clone())
            .with_random(random.clone()),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap()
    .0;
    let bob = device(&clock).await;
    let phone = device(&clock).await;
    let space = alice.create_space().await.unwrap();
    let person = bob.make_person(&[7; 32]).await.unwrap().person;
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
    let (keys, proof) = phone.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(person, bob.list_events(&person).await, &[7; 32])
        .await
        .unwrap();
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();

    random
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut failed = false;
    for _ in 0..4_000 {
        match alice.maintain(space).await {
            Err(frasil::Error::NoRandomness) => {
                failed = true;
                break;
            }
            Ok(done) => assert_eq!(done, Maintained::default(), "nothing written"),
            Err(other) => panic!("{other:?}"),
        }
        clock.advance(1);
    }
    assert!(failed, "the delivery was tried, and failed");
    random
        .armed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (done, _) = maintain_until(&alice, &clock, space).await;
    assert!(done.delivery.is_some(), "tried again: {done:?}");
    phone.follow(space).await;
    carry(&alice, &phone, space).await;
    assert_eq!(
        phone
            .read(&space, |r| r.level_of(&phone.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
}

#[tokio::test]
async fn a_persons_new_device_waits_for_an_owed_cascade() {
    // Bob adds his phone and revokes his tablet; Bob never holds the
    // space. While the revocation's cascade is owed and not yet due at
    // Alice, she writes nothing to the space, no delivery to the phone
    // either; the cascaded rotation then reaches the phone.
    for _ in 0..32 {
        let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
        let alice = device(&clock).await;
        let bob = device(&clock).await;
        let tablet = device(&clock).await;
        let phone = device(&clock).await;
        let space = alice.create_space().await.unwrap();
        let person = bob.make_person(&[7; 32]).await.unwrap().person;
        let (keys, proof) = tablet.list_keys(&person, &bob.device_id());
        bob.add_device(keys, proof).await.unwrap();
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
        let (keys, proof) = phone.list_keys(&person, &bob.device_id());
        let add = bob.add_device(keys, proof).await.unwrap();
        let revoke = bob.revoke_device(tablet.device_id()).await.unwrap();
        phone
            .adopt_person(person, bob.list_events(&person).await, &[7; 32])
            .await
            .unwrap();
        alice
            .receive_list(bob.list_events(&person).await)
            .await
            .unwrap();
        assert_eq!(
            alice.owed_responses(&space).await,
            vec![(EventId(person), revoke)]
        );
        // Alice must not be first in the cascade's rank, or it is due at
        // once; and she must be first for the phone's add, so that the
        // delivery would be due at once were the cascade not owed. Draw the
        // devices again until both hold.
        let candidates: Vec<[u8; 32]> = alice
            .read(&space, |r| {
                r.devices()
                    .into_iter()
                    .filter(|(d, level)| *level >= Level::Write && r.propagates(d))
                    .map(|(d, _)| d.0)
                    .collect()
            })
            .await
            .unwrap();
        let position = frasil_space::keygraph::rank::position(
            &space.0,
            &revoke.0,
            &candidates,
            &alice.device_id().0,
        );
        let without_phone: Vec<[u8; 32]> = candidates
            .iter()
            .copied()
            .filter(|d| *d != phone.device_id().0)
            .collect();
        let for_add = frasil_space::keygraph::rank::position(
            &space.0,
            &add.0,
            &without_phone,
            &alice.device_id().0,
        );
        if position == Some(0) || for_add != Some(0) {
            continue;
        }
        assert_eq!(
            alice.maintain(space).await.unwrap(),
            Maintained::default(),
            "nothing while the cascade is owed"
        );
        let (done, _) = maintain_until(&alice, &clock, space).await;
        assert!(done.rotation.is_some(), "the cascade first: {done:?}");
        assert_eq!(alice.maintain(space).await.unwrap(), Maintained::default());
        phone.follow(space).await;
        carry(&alice, &phone, space).await;
        assert_eq!(
            phone
                .read(&space, |r| r.level_of(&phone.device_id()))
                .await
                .unwrap(),
            Some(Level::Write),
            "the cascaded rotation reaches the phone"
        );
        return;
    }
    panic!("no draw put Alice after the cascade's first and first for the add");
}

#[tokio::test]
async fn a_forked_device_is_healed_out_after_the_rank_delay() {
    use frasil_store::{Commit, DeviceBoundSlot, MemorySlot, MemoryStore, Store};
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let platform = || Platform::new(store.clone(), slot.clone()).with_clock(clock.clone());
    let (alice, sealed) = Engine::create(platform(), &[5; 32], registry.clone())
        .await
        .unwrap();
    let bob = device(&clock).await;
    let carol = device(&clock).await;
    let space = alice.create_space().await.unwrap();
    for other in [&bob, &carol] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let saved = store.scan(&[]).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    for other in [&bob, &carol] {
        other.follow(space).await;
        carry(&alice, other, space).await;
    }
    drop(alice);

    // Alice comes back from the backup and, told wrongly that she is in
    // sync, signs her last sequence number again: her chain forks.
    let restored = Arc::new(MemoryStore::new());
    assert!(
        restored
            .commit(&Commit::new(saved, Vec::new()))
            .await
            .unwrap()
    );
    let alice = Engine::open(
        Platform::new(restored, slot.clone()).with_clock(clock.clone()),
        &sealed,
        &[5; 32],
        registry,
    )
    .await
    .unwrap();
    alice.synced(&space).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " other").unwrap();
        })
        .await
        .unwrap();
    for other in [&bob, &carol] {
        carry(&alice, other, space).await;
        let test = other.read(&space, |r| r.heal_test()).await.unwrap();
        assert!(test.contains(&(false, "outside")), "{test:?}");
    }

    // Bob and Carol are the candidates: one heals at once, the other
    // would after its delay, and stands down when the heal arrives.
    let b = bob.maintain(space).await.unwrap();
    let c = carol.maintain(space).await.unwrap();
    let (first, second, heal) = match (b.rotation, c.rotation) {
        (Some(id), None) => (&bob, &carol, id),
        (None, Some(id)) => (&carol, &bob, id),
        other => panic!("exactly one candidate heals at once: {other:?}"),
    };
    carry(first, second, space).await;
    assert!(
        second
            .read(&space, |r| r.heal_test())
            .await
            .unwrap()
            .is_empty()
    );
    clock.advance(3_600);
    assert_eq!(second.maintain(space).await.unwrap(), Maintained::default());
    assert!(
        second
            .read(&space, |r| r.secrets_held(&heal))
            .await
            .unwrap()
    );
    carry(first, &alice, space).await;
    assert!(!alice.read(&space, |r| r.secrets_held(&heal)).await.unwrap());
}
