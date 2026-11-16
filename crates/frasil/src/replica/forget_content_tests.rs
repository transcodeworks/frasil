//! A device that forgets the past before its checkpoint, and a newcomer
//! admitted from the checkpoint, show a writer's past edits as a device that
//! kept everything shows them, whatever became of the writer's standing
//! between the edit and the checkpoint: lowered to reader, made a
//! suggester, removed, made a writer again after a refused suggestion, or
//! removed and granted again, or reaching the space by two paths with
//! different capabilities. Compared: the document's text, each unit's
//! verdict, content outcome, voiding events and attribution, with the labels its paths had
//! at its place, before forgetting, after it and after opening again from
//! the store. Carol's label changes after her edit, so a label read from
//! the current roster would show.

use crate::advanced::{AdapterRegistry, Engine, Platform};
use crate::checkpoints::CheckpointPolicy;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_units::stream::Opening;

async fn device() -> Engine {
    let (device, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

async fn grant(by: &Engine, to: &Engine, space: EventId, level: Level) {
    by.grant_device_at(
        space,
        to.public_keys().clone(),
        level,
        None,
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .expect("a grant");
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.follow(space).await;
    to.ingest(space, from.events(&space).await)
        .await
        .expect("ingested");
    for locator in to.missing_objects(&space).await {
        if let Some(stored) = from.stored_object(&space, &locator).await {
            to.receive_object(space, &locator, &stored)
                .await
                .expect("an object");
        }
    }
}

async fn write(device: &Engine, space: EventId, doc: &Opening, words: &str) {
    device
        .edit_document(space, doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), words).unwrap();
        })
        .await
        .expect("an edit");
}

/// The text, and for each unit its verdict, content outcome and
/// attribution.
async fn shown(device: &Engine, space: EventId, doc: &Opening, units: &[EventId]) -> String {
    let text = device
        .document(&space, &doc.stream())
        .await
        .map(|d| d.get_text("body").to_string())
        .unwrap_or_default();
    let per_unit = device
        .read(&space, |r| {
            units
                .iter()
                .map(|id| {
                    format!(
                        "{:?} {:?} {:?} {:?}",
                        r.status(id),
                        r.content_outcome(id),
                        r.authorship(id),
                        r.unit_voiders(id)
                    )
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
    format!("{text}\n{}", per_unit.join("\n"))
}

#[derive(Debug, Clone, Copy)]
enum Change {
    LoweredToReader,
    MadeSuggester,
    Removed,
    SuggesterMadeWriter,
    RemovedAndGrantedAgain,
    /// Carol reaches the space by two paths with different capabilities:
    /// her device, a suggester, and her person, which also may comment;
    /// her person is removed after her edit.
    TwoPaths,
}

async fn run(change: Change) {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let (kim, carol) = (device().await, device().await);
    let space = alice.create_space().await.unwrap();
    grant(&alice, &kim, space, Level::Read).await;
    grant(&alice, &carol, space, Level::Write).await;
    let member = MemberRef::device(carol.device_id());
    // A label, changed after Carol's edit.
    let label = |name: &str| frasil_space::Change {
        label: Some(name.into()),
        ..frasil_space::Change::new(frasil_space::Op::Change, Some(member))
    };
    alice
        .sign_roster(space, vec![label("Carol")])
        .await
        .unwrap();
    if matches!(change, Change::SuggesterMadeWriter | Change::TwoPaths) {
        alice.set_suggester(space, member, true).await.unwrap();
    }
    let person = if matches!(change, Change::TwoPaths) {
        let person = carol.make_person(&[9; 32]).await.unwrap().person;
        alice
            .receive_list(carol.list_events(&person).await)
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
        alice
            .sign_roster(
                space,
                vec![frasil_space::Change {
                    capabilities: Some(vec![frasil_space::Capability {
                        name: "comment".into(),
                        mode: frasil_space::CapabilityMode::Extends,
                    }]),
                    ..frasil_space::Change::new(
                        frasil_space::Op::Change,
                        Some(MemberRef::person(person)),
                    )
                }],
            )
            .await
            .unwrap();
        Some(person)
    } else {
        None
    };
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &carol, space).await;
    write(&carol, space, &doc, "b").await;
    carry(&carol, &alice, space).await;
    match change {
        Change::LoweredToReader => {
            alice.set_level(space, member, Level::Read).await.unwrap();
        }
        Change::MadeSuggester => {
            alice.set_suggester(space, member, true).await.unwrap();
        }
        Change::Removed => {
            alice.remove(space, member).await.unwrap();
        }
        Change::SuggesterMadeWriter => {
            alice.set_suggester(space, member, false).await.unwrap();
        }
        Change::RemovedAndGrantedAgain => {
            alice.remove(space, member).await.unwrap();
            grant(&alice, &carol, space, Level::Write).await;
        }
        Change::TwoPaths => {
            let person = person.expect("her person");
            alice
                .remove(space, MemberRef::person(person))
                .await
                .unwrap();
        }
    }
    let _ = alice.sign_roster(space, vec![label("Caroline")]).await;
    // Her person's list changes after her edit: a phone joins it.
    if let Some(person) = person {
        let phone = device().await;
        let (keys, proof) = phone.list_keys(&person, &carol.device_id());
        carol.add_device(keys, proof).await.unwrap();
        alice
            .receive_list(carol.list_events(&person).await)
            .await
            .unwrap();
    }
    write(&alice, space, &doc, "c").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    carry(&alice, &kim, space).await;
    let units: Vec<EventId> = alice
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == frasil_events::kind::UNIT)
        .map(|event| event.id())
        .collect();
    let kept = shown(&kim, space, &doc, &units).await;
    // Carol's edit shows her label at it, never the one she has now.
    assert!(kept.contains("Some(\"Carol\")"), "{change:?}: {kept}");
    assert!(!kept.contains("Caroline"), "{change:?}: {kept}");
    assert_eq!(shown(&alice, space, &doc, &units).await, kept, "{change:?}");

    let pending = alice.outbox(&space).await;
    alice
        .acknowledge(space, crate::outbox::Acknowledger::Peer([1; 32]), &pending)
        .await
        .unwrap();
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
    assert_eq!(
        shown(&alice, space, &doc, &units).await,
        kept,
        "{change:?}, after forgetting"
    );
    drop(alice);
    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    assert_eq!(
        shown(&alice, space, &doc, &units).await,
        kept,
        "{change:?}, opened again"
    );

    // A newcomer admitted from the checkpoint holds none of the past's
    // units: it shows the same text.
    let newcomer = device().await;
    let admitting = alice
        .grant_device(
            space,
            newcomer.public_keys().clone(),
            Level::Read,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    newcomer.follow(space).await;
    newcomer
        .adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    let served: Vec<Vec<u8>> = alice
        .events(&space)
        .await
        .into_iter()
        .filter(|signed| {
            frasil_events::decode(signed).is_ok_and(|event| {
                event.id() == space
                    || event.id() == c
                    || !event.cuts().is_empty()
                    || event.kind() == frasil_events::kind::STORAGE
            })
        })
        .collect();
    newcomer.ingest(space, served).await.unwrap();
    for _ in 0..8 {
        let wanted = newcomer.read(&space, |r| r.wanted()).await.unwrap();
        if wanted.is_empty() {
            break;
        }
        newcomer.take_truncated(space, &wanted).await.unwrap();
    }
    for locator in newcomer.missing_objects(&space).await {
        if let Some(stored) = alice.stored_object(&space, &locator).await {
            newcomer
                .receive_object(space, &locator, &stored)
                .await
                .unwrap();
        }
    }
    let text = |shown: &str| shown.lines().next().unwrap_or_default().to_owned();
    assert_eq!(
        text(&shown(&newcomer, space, &doc, &units).await),
        text(&kept),
        "{change:?}, the newcomer"
    );
}

#[tokio::test]
async fn a_writer_lowered_to_reader_before_the_checkpoint() {
    run(Change::LoweredToReader).await;
}

#[tokio::test]
async fn a_writer_made_a_suggester_before_the_checkpoint() {
    run(Change::MadeSuggester).await;
}

#[tokio::test]
async fn a_writer_removed_before_the_checkpoint() {
    run(Change::Removed).await;
}

#[tokio::test]
async fn a_suggester_made_a_writer_before_the_checkpoint() {
    run(Change::SuggesterMadeWriter).await;
}

#[tokio::test]
async fn a_writer_removed_and_granted_again_before_the_checkpoint() {
    run(Change::RemovedAndGrantedAgain).await;
}

#[tokio::test]
async fn a_writer_reaching_the_space_by_two_paths_with_different_capabilities() {
    run(Change::TwoPaths).await;
}

/// A newly linked device carries its own add before its first edit in each
/// space, and a newcomer counts the same list events at its snapshot base.
#[test]
fn a_linked_devices_first_edit_has_its_add_in_each_space() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let alice = device().await;
            let first = device().await;
            let second = device().await;
            let first_person = first.make_person(&[9; 32]).await.unwrap().person;
            let second_person = second.make_person(&[9; 32]).await.unwrap().person;
            let (former, former_person, laptop, person) = if first_person < second_person {
                (first, first_person, second, second_person)
            } else {
                (second, second_person, first, first_person)
            };
            let phone = device().await;
            let (keys, proof) = phone.list_keys(&former_person, &former.device_id());
            former.add_device(keys, proof).await.unwrap();
            former.revoke_device(phone.device_id()).await.unwrap();
            phone
                .receive_list(former.list_events(&former_person).await)
                .await
                .unwrap();
            alice
                .receive_list(former.list_events(&former_person).await)
                .await
                .unwrap();
            for _ in 0..frasil_units::limits::MAX_LIST_EVENTS {
                let signed = {
                    let state = laptop.lock().await;
                    state.lists[&person]
                        .sign(&frasil_identity::body::ListBody::ack(), laptop.signer())
                };
                laptop.receive_list(vec![signed]).await.unwrap();
            }
            let (keys, proof) = phone.list_keys(&person, &laptop.device_id());
            laptop.add_device(keys, proof).await.unwrap();
            phone
                .adopt_person(person, laptop.list_events(&person).await, &[8; 32])
                .await
                .unwrap();
            alice
                .receive_list(laptop.list_events(&person).await)
                .await
                .unwrap();
            for index in 0..2 {
                let space = alice.create_space().await.unwrap();
                for member in [former_person, person] {
                    alice
                        .grant_person(
                            space,
                            member,
                            Level::Write,
                            HistoryMode::WithHistory,
                            Via::Code,
                        )
                        .await
                        .unwrap();
                }
                carry(&alice, &phone, space).await;
                if index == 1 {
                    let heal = phone.heal(space).await.unwrap();
                    carry(&phone, &alice, space).await;
                    assert!(
                        alice
                            .read(&space, |replica| replica
                                .status(&heal)
                                .is_some_and(|s| s.is_valid()))
                            .await
                            .unwrap()
                    );
                }
                let doc = phone.new_document().unwrap();
                write(&phone, space, &doc, "first").await;
                carry(&phone, &alice, space).await;
                let edited: Vec<_> = phone
                    .events(&space)
                    .await
                    .into_iter()
                    .filter_map(|signed| frasil_events::decode(&signed).ok())
                    .filter(|event| {
                        event.kind() == frasil_events::kind::UNIT
                            && *event.author() == phone.device_id()
                    })
                    .map(|event| event.id())
                    .collect();
                for id in &edited {
                    assert!(
                        alice
                            .read(&space, |replica| replica
                                .status(id)
                                .is_some_and(|status| status.is_valid()))
                            .await
                            .unwrap(),
                        "{id:?}"
                    );
                    assert_eq!(
                        alice
                            .read(&space, |replica| replica.authorship(id).cloned())
                            .await
                            .unwrap(),
                        phone
                            .read(&space, |replica| replica.authorship(id).cloned())
                            .await
                            .unwrap()
                    );
                }
                let newcomer = device().await;
                let admitting = alice
                    .grant_device(
                        space,
                        newcomer.public_keys().clone(),
                        Level::Read,
                        HistoryMode::FromNowOn,
                        Via::Code,
                    )
                    .await
                    .unwrap();
                let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
                newcomer.follow(space).await;
                newcomer
                    .adopt_snapshot(space, &snapshot.signed, snapshot.parts())
                    .await
                    .unwrap();
                carry(&alice, &phone, space).await;
                write(&phone, space, &doc, " next").await;
                carry(&phone, &alice, space).await;
                carry(&alice, &newcomer, space).await;
                assert_eq!(
                    shown(&alice, space, &doc, &[]).await,
                    shown(&newcomer, space, &doc, &[]).await
                );
                for signed in phone.events(&space).await {
                    let event = frasil_events::decode(&signed).unwrap();
                    if event.kind() == frasil_events::kind::UNIT
                        && *event.author() == phone.device_id()
                        && edited.iter().all(|id| *id != event.id())
                    {
                        let old = alice
                            .read(&space, |r| r.status(&event.id()).copied())
                            .await
                            .unwrap();
                        assert!(old.is_some_and(|status| status.is_valid()));
                        assert_eq!(
                            old,
                            newcomer
                                .read(&space, |r| r.status(&event.id()).copied())
                                .await
                                .unwrap()
                        );
                        assert_eq!(
                            alice
                                .read(&space, |r| r.authorship(&event.id()).cloned())
                                .await
                                .unwrap(),
                            newcomer
                                .read(&space, |r| r.authorship(&event.id()).cloned())
                                .await
                                .unwrap()
                        );
                    }
                }
            }
        });
}

#[test]
fn another_person_adding_the_writer_preserves_frozen_authorship() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let platform = Platform::memory();
            let registry = AdapterRegistry::with_builtins();
            let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
                .await
                .unwrap();
            alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
            let phone = device().await;
            let person_a = phone.make_person(&[9; 32]).await.unwrap().person;
            let person_b = alice.make_person(&[8; 32]).await.unwrap().person;
            alice
                .receive_list(phone.list_events(&person_a).await)
                .await
                .unwrap();
            let space = alice.create_space().await.unwrap();
            for person in [person_a, person_b] {
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
            }
            carry(&alice, &phone, space).await;
            let doc = phone.new_document().unwrap();
            write(&phone, space, &doc, "original").await;
            carry(&phone, &alice, space).await;
            let units: Vec<_> = phone
                .events(&space)
                .await
                .iter()
                .filter_map(|signed| frasil_events::decode(signed).ok())
                .filter(|event| {
                    event.kind() == frasil_events::kind::UNIT
                        && *event.author() == phone.device_id()
                })
                .map(|event| event.id())
                .collect();
            let expected = shown(&alice, space, &doc, &units).await;
            alice.propose_checkpoint(space).await.unwrap();
            let pending = alice.outbox(&space).await;
            alice
                .acknowledge(space, crate::outbox::Acknowledger::Peer([1; 32]), &pending)
                .await
                .unwrap();
            assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
            let (keys, proof) = phone.list_keys(&person_b, &alice.device_id());
            alice.add_device(keys, proof).await.unwrap();
            alice.publish_list(space, &person_b).await.unwrap();
            phone
                .receive_list(alice.list_events(&person_b).await)
                .await
                .unwrap();
            carry(&alice, &phone, space).await;
            assert_eq!(shown(&alice, space, &doc, &units).await, expected);
            assert_eq!(shown(&phone, space, &doc, &units).await, expected);
            drop(alice);
            let alice = Engine::open(platform, &sealed, &[2; 32], registry)
                .await
                .unwrap();
            assert_eq!(shown(&alice, space, &doc, &units).await, expected);
        });
}

#[test]
fn a_snapshot_carries_held_list_events_and_marks_only_placed_events() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let alice = device().await;
            let laptop = device().await;
            let phone = device().await;
            let person = laptop.make_person(&[9; 32]).await.unwrap().person;
            alice
                .receive_list(laptop.list_events(&person).await)
                .await
                .unwrap();
            let space = alice.create_space().await.unwrap();
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
            let placed = laptop.list_events(&person).await;
            let (keys, proof) = phone.list_keys(&person, &laptop.device_id());
            let apart = laptop.add_device(keys, proof).await.unwrap();
            alice
                .receive_list(laptop.list_events(&person).await)
                .await
                .unwrap();
            let newcomer = device().await;
            let admitting = alice
                .grant_device(
                    space,
                    newcomer.public_keys().clone(),
                    Level::Read,
                    HistoryMode::FromNowOn,
                    Via::Code,
                )
                .await
                .unwrap();
            let made = alice.newcomer_snapshot(&space, admitting).await.unwrap();
            let read =
                frasil_units::snapshot::SpaceSnapshot::read(&made.signed, &space, &()).unwrap();
            let snapshot = read.into_unverified();
            assert!(
                snapshot
                    .lists
                    .iter()
                    .any(|signed| frasil_events::decode(signed).unwrap().id() == apart)
            );
            assert!(!snapshot.placed.contains(&apart));
            assert_eq!(
                snapshot
                    .placed
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
                placed
                    .iter()
                    .map(|signed| frasil_events::decode(signed).unwrap().id())
                    .collect()
            );
        });
}

#[test]
fn a_snapshot_reads_a_forgotten_lists_add_from_its_space_copy() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let alice = device().await;
            let laptop = device().await;
            let phone = device().await;
            let person = laptop.make_person(&[9; 32]).await.unwrap().person;
            let (keys, proof) = phone.list_keys(&person, &laptop.device_id());
            laptop.add_device(keys, proof).await.unwrap();
            phone
                .adopt_person(person, laptop.list_events(&person).await, &[8; 32])
                .await
                .unwrap();
            let placed = laptop.list_events(&person).await;
            alice.receive_list(placed.clone()).await.unwrap();
            let space = alice.create_space().await.unwrap();
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
            laptop.revoke_device(phone.device_id()).await.unwrap();
            let checkpoint = laptop.propose_list_checkpoint().await.unwrap();
            assert_eq!(
                laptop
                    .list_checkpoint_status()
                    .await
                    .in_effect
                    .map(|id| *id.as_bytes()),
                Some(checkpoint.0)
            );
            alice
                .receive_list(laptop.list_events(&person).await)
                .await
                .unwrap();
            assert!(alice.forget_lists_before_checkpoints().await.unwrap() > 0);
            let newcomer = device().await;
            let admitting = alice
                .grant_device(
                    space,
                    newcomer.public_keys().clone(),
                    Level::Read,
                    HistoryMode::FromNowOn,
                    Via::Code,
                )
                .await
                .unwrap();
            let made = alice.newcomer_snapshot(&space, admitting).await.unwrap();
            let snapshot = frasil_units::snapshot::SpaceSnapshot::read(&made.signed, &space, &())
                .unwrap()
                .into_unverified();
            let ids = |events: &[Vec<u8>]| {
                events
                    .iter()
                    .map(|signed| frasil_events::decode(signed).unwrap().id())
                    .collect::<std::collections::BTreeSet<_>>()
            };
            assert!(ids(&placed).is_subset(&ids(&snapshot.lists)));
            assert_eq!(
                snapshot
                    .placed
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
                ids(&placed)
            );
        });
}
