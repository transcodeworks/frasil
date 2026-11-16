//! A residue re-enters through device mailboxes and erases after a checkpoint.
use frasil::advanced::outbox::Acknowledger;
use frasil::{CheckpointPolicy, Device, Event, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_space::{HistoryMode, Via};
use std::time::Duration;

async fn device(key: u8) -> Device {
    let device = Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .unwrap();
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

async fn carry(
    from: &frasil::advanced::Engine,
    to: &frasil::advanced::Engine,
    space: frasil_events::EventId,
) {
    to.follow(space).await;
    to.ingest(space, from.events(&space).await).await.unwrap();
    for locator in to.missing_objects(&space).await {
        if let Some(object) = from.stored_object(&space, &locator).await {
            to.receive_object(space, &locator, &object).await.unwrap();
        }
    }
}

struct ForegroundTasks;
impl frasil::advanced::Tasks for ForegroundTasks {
    fn spawn(&self, task: frasil_store::BoxFuture<'static, ()>) {
        drop(task);
    }
    fn sleep(&self, duration: Duration) -> frasil_store::BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

async fn late_reentry(standing: u8, void: bool, named: bool) {
    use frasil::advanced::{AdapterRegistry, Engine, Platform};
    use frasil_store::{Commit, MemorySlot, MemoryStore, Store};
    use std::sync::Arc;
    tokio::time::timeout(Duration::from_secs(90), async {
        let peer = spawn_loopback().await.unwrap();
        let bob = device(61).await;
        let unlock = [62; 32];
        let alice_store = Arc::new(MemoryStore::new());
        let (engine, sealed) = Engine::create(
            Platform::new(alice_store.clone(), Arc::new(MemorySlot::new())),
            &unlock,
            AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap();
        let foreground = standing == 0 && !void;
        let mut options = Options::new().loopback();
        if foreground { options = options.tasks(Arc::new(ForegroundTasks)); }
        let alice = Device::from_engine(engine, options).unwrap();
        alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
        let held = bob.create_space().await.unwrap();
        let space = frasil_events::EventId(*held.id().as_bytes());
        let document = held.create_document().unwrap();
        document
            .edit(|doc| doc.get_text("body").insert(0, "recover then erase"))
            .await
            .unwrap();
        let early_backup = if named {
            let backup = Arc::new(MemoryStore::new());
            backup
                .commit(&Commit::new(
                    alice_store.scan(&[]).await.unwrap(),
                    Vec::new(),
                ))
                .await
                .unwrap();
            Some(backup)
        } else {
            None
        };
        bob.engine()
            .grant_administrator(
                space,
                alice.engine().public_keys().clone(),
                200,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let connection = bob.connect(&peer.origin).await.unwrap();
        held.flush().await.unwrap();
        if standing == 1 {
            connection.close();
            while connection.status().connected {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        carry(bob.engine(), alice.engine(), space).await;
        alice.engine().enrol(&space).await.unwrap();
        alice.connect(&peer.origin).await.unwrap();
        alice.space(held.id()).await.unwrap().flush().await.unwrap();
        if foreground { Box::pin(alice.deposit_upkeep()).await; }
        if standing == 0 {
            carry(alice.engine(), bob.engine(), space).await;
        }
        alice.pause_sync([held.id()]);
        let original_erasure = alice.engine().request_erasure(space).await.unwrap();
        let pending = alice.engine().outbox(&space).await;
        alice
            .engine()
            .acknowledge(space, Acknowledger::Peer([99; 32]), &pending)
            .await
            .unwrap();
        let backup = if let Some(backup) = early_backup {
            backup
        } else {
            let backup = Arc::new(MemoryStore::new());
            backup
                .commit(&Commit::new(
                    alice_store.scan(&[]).await.unwrap(),
                    Vec::new(),
                ))
                .await
                .unwrap();
            backup
        };
        alice.engine().drop_for_erasure(&space).await.unwrap();
        // A backup of the same device still holds the pseudonym and the
        // erasure's chain tip, so it can cast both votes without a fork.
        let restored = Engine::open(
            Platform::new(backup, Arc::new(MemorySlot::new())),
            &sealed,
            &unlock,
            AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap();
        restored.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
        if named {
            carry(bob.engine(), &restored, space).await;
            restored.synced(&space).await.unwrap();
            restored.enrol(&space).await.unwrap();
            carry(&restored, bob.engine(), space).await;
        }
        bob.engine().propose_checkpoint(space).await.unwrap();
        carry(bob.engine(), &restored, space).await;
        restored.synced(&space).await.unwrap();
        let vote = restored
            .acknowledge_checkpoint(space)
            .await
            .unwrap()
            .expect("restored member votes for the pending checkpoint");
        carry(&restored, bob.engine(), space).await;
        bob.engine().acknowledge_checkpoint(space).await.unwrap();
        assert!(
            bob.engine()
                .checkpoint_status(&space)
                .await
                .unwrap()
                .in_effect
                .is_some(),
            "checkpoint in effect before the residue asks"
        );
        if standing == 1 {
            bob.connect(&peer.origin).await.unwrap();
        }
        held.flush().await.unwrap();
        if !named {
            frasil::advanced::peer::administer_server(alice.engine(), &peer.origin, space)
                .await
                .unwrap();
        }
        frasil::advanced::peer::administer_server(&restored, &peer.origin, space)
            .await
            .unwrap();
        while !peer.peer.keeps(&space.0, &vote.0) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        frasil::advanced::peer::administer_server(&restored, &peer.origin, space)
            .await
            .unwrap();
        if named {
            frasil::advanced::peer::administer_server(alice.engine(), &peer.origin, space)
                .await
                .unwrap();
        }
        if void {
            let demotion = bob
                .engine()
                .set_level(
                    space,
                    frasil_space::MemberRef::device(alice.engine().device_id()),
                    frasil::Level::Write,
                )
                .await
                .unwrap();
            held.flush().await.unwrap();
            assert_eq!(
                bob.engine()
                    .read(&space, |replica| replica
                        .level_of(&alice.engine().device_id()))
                    .await
                    .unwrap(),
                Some(frasil::Level::Write),
                "the welcome sender has applied the demotion: {}",
                bob.engine()
                    .read(&space, |replica| format!(
                        "status={:?}, member={:?}",
                        replica.status(&demotion),
                        replica
                            .roster()
                            .state(&frasil_space::MemberRef::device(alice.engine().device_id()))
                    ))
                    .await
                    .unwrap()
            );
        }
        let mut events = alice.events();
        alice.resume_sync([held.id()]);
        let mut evidenced = false;
        if foreground {
            Box::pin(alice.retry_erasure(held.id())).await.unwrap();
            loop {
                if let Event::ErasureCheckpoint { space: found, standing: got, .. } = events.next().await.expect("the event stream stays open")
                    && found == held.id()
                {
                    assert_eq!(got, standing);
                    evidenced = true;
                    break;
                }
            }
            loop {
                Box::pin(alice.deposit_upkeep()).await;
                let received = Box::pin(alice.receive_welcomes_via_peer(&peer.origin, |_| {})).await.unwrap();
                if !received.is_empty() {
                    assert!(received.iter().all(|report| report.result.is_ok()));
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        let mut signed_again = None;
        let mut awaiting = false;
        loop {
            match events.next().await {
                Some(Event::ErasureCheckpoint {
                    space: found,
                    standing: got,
                    ..
                }) if found == held.id() => {
                    assert_eq!(got, standing);
                    evidenced = true;
                }
                Some(Event::ErasureAwaitingWelcome { space: found }) if found == held.id() => {
                    awaiting = true;
                }
                Some(Event::SlotHeld {
                    space: found,
                    holder,
                    erasure_waiting,
                    ..
                }) if standing == 1 && found == held.id() => {
                    assert_eq!(
                        holder,
                        if named {
                            "unknown"
                        } else {
                            "another installation of this device"
                        }
                    );
                    if named {
                        assert!(!awaiting);
                        assert!(!alice.engine().spaces().await.contains(&space));
                    }
                    assert!(erasure_waiting);
                    assert!(alice.engine().erasing().await.contains(&space));
                    if !named {
                        assert_eq!(alice.engine().enrol(&space).await.unwrap(), None);
                        assert!(matches!(
                            alice.engine().request_erasure(space).await,
                            Err(frasil::Error::NotAllowed(_))
                        ));
                        Box::pin(alice.retry_erasure(held.id())).await.unwrap();
                        assert!(alice.engine().erasing().await.contains(&space));
                    }
                    alice.close().await.unwrap();
                    bob.close().await.unwrap();
                    peer.shutdown().await;
                    return;
                }
                Some(Event::ErasureVoid { space: found }) if void && found == held.id() => break,
                Some(Event::RequestSignedAgain {
                    space: found,
                    request,
                }) if !void && found == held.id() => {
                    assert_eq!(*request.as_bytes(), original_erasure.0);
                    signed_again = alice
                        .engine()
                        .read(&space, |replica| {
                            replica
                                .log()
                                .unwrap()
                                .events()
                                .find(|event| {
                                    event.id() != original_erasure
                                        && event.kind() == frasil_events::kind::STORAGE
                                        && matches!(
                                            frasil_peers::body::StorageBody::read(
                                                event.unverified_body()
                                            ),
                                            Ok(frasil_peers::body::StorageBody::Erase)
                                        )
                                        && replica
                                            .status(&event.id())
                                            .is_some_and(|status| status.is_valid())
                                })
                                .map(frasil_events::Event::id)
                        })
                        .await
                        .unwrap();
                    assert!(
                        signed_again.is_some(),
                        "a valid new erasure follows the checkpoint"
                    );
                    break;
                }
                _ => {}
            }
        }
        assert!(evidenced, "the real late answer reached the application");
        if void {
            assert!(alice.engine().spaces().await.contains(&space));
        } else {
            let again = signed_again.expect("the re-entry signed a new erasure");
            let stored = tokio::time::timeout(Duration::from_secs(30), async {
                while !peer.peer.erased(&space.0) && !peer.peer.keeps(&space.0, &again.0) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
            if stored.is_err() {
                let pending = alice.engine().outbox(&space).await;
                let dependencies = alice.engine().read(&space, |replica| replica.event(again).map(|event| event.parents().to_vec()).unwrap_or_default()).await.unwrap();
                let dependencies: Vec<_> = dependencies.into_iter().map(|id| (id, peer.peer.keeps(&space.0, &id.0))).collect();
                let statuses: Vec<_> = alice.peers().iter().map(|peer| peer.status()).collect();
                let administered = tokio::time::timeout(Duration::from_secs(3), frasil::advanced::peer::administer_server(alice.engine(), &peer.origin, space)).await;
                panic!("the relay stores or executes the new erasure: {stored:?}; again={again:?}, pending={pending:?}, dependencies={dependencies:?}, statuses={statuses:?}, administered={administered:?}, outcome={:?}", peer.peer.outcome(&space.0, &again.0));
            }
            if !peer.peer.erased(&space.0) {
                assert_eq!(
                    peer.peer
                        .stability(&space.0, &again.0)
                        .map(|(_, valid)| valid),
                    Some(true),
                    "the peer judges the new erasure valid: {:?}",
                    peer.peer.outcome(&space.0, &again.0)
                );
                // A valid request executes once stable or at T.
                peer.advance(7 * 24 * 60 * 60 + 1).await;
            }
            tokio::time::timeout(Duration::from_secs(30), async {
                while !peer.peer.erased(&space.0) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the relay executes the new erasure");
            if foreground {
                alice.close().await.unwrap();
                bob.close().await.unwrap();
                peer.shutdown().await;
                return;
            }
            tokio::time::timeout(Duration::from_secs(30), async {
                while alice.engine().spaces().await.contains(&space) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("the device drops the space after the peer's acknowledgement or tombstone");
            assert!(
                alice
                    .receive_welcomes_via_peer(&peer.origin, |_| {})
                    .await
                    .unwrap()
                    .is_empty(),
                "a delayed welcome cannot restart the completed erasure"
            );
            assert!(!alice.engine().spaces().await.contains(&space));
        }
        alice.close().await.unwrap();
        bob.close().await.unwrap();
        peer.shutdown().await;
    })
    .await
    .expect("late erasure re-entry within the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_erasure_with_standing_zero_is_erased_again() {
    Box::pin(late_reentry(0, false, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_erasure_with_standing_one_reports_the_held_slot() {
    Box::pin(late_reentry(1, false, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_erasure_can_be_void_after_the_welcome() {
    Box::pin(late_reentry(0, true, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_erasure_with_standing_two_retains_its_residue() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let store = std::sync::Arc::new(frasil_store::MemoryStore::new());
        let blobs = std::sync::Arc::new(frasil_relay::blobs::MemoryBlobs::new());
        let peer = frasil_relay::testing::spawn_with(frasil_relay::testing::Options {
            store: Some(store.clone()), blobs: Some(blobs.clone()),
            ..frasil_conformance::options()
        }).await.unwrap();
        let bob = device(63).await;
        let alice = device(64).await;
        let held = bob.create_space().await.unwrap();
        let space = frasil_events::EventId(*held.id().as_bytes());
        bob.engine().grant_administrator(space, alice.engine().public_keys().clone(), 200, HistoryMode::WithHistory, Via::Code).await.unwrap();
        alice.engine().follow(space).await;
        alice.engine().ingest(space, bob.engine().events(&space).await).await.unwrap();
        alice.engine().enrol(&space).await.unwrap();
        bob.connect(&peer.origin).await.unwrap();
        tokio::time::timeout(Duration::from_secs(35), held.flush()).await.expect("Bob's stores acknowledged").unwrap();
        alice.connect(&peer.origin).await.unwrap();
        tokio::time::timeout(Duration::from_secs(35), alice.space(held.id()).await.unwrap().flush()).await.expect("Alice's enrolment acknowledged").unwrap();
        alice.pause_sync([held.id()]);
        bob.engine().ingest(space, alice.engine().events(&space).await).await.unwrap();
        let erasure = alice.engine().request_erasure(space).await.unwrap();
        let pending = alice.engine().outbox(&space).await;
        alice.engine().acknowledge(space, Acknowledger::Peer([99; 32]), &pending).await.unwrap();
        alice.engine().drop_for_erasure(&space).await.unwrap();
        assert!(alice.engine().erasing().await.contains(&space), "residue retained at drop");
        bob.engine().set_level(space, frasil_space::MemberRef::device(alice.engine().device_id()), frasil::Level::Write).await.unwrap();
        bob.engine().propose_checkpoint(space).await.unwrap();
        tokio::time::timeout(Duration::from_secs(35), held.flush()).await.expect("Bob's stores acknowledged").unwrap();
        // Store the late request while the residue's scheduled traffic is paused.
        assert!(alice.engine().erasing().await.contains(&space), "residue retained before the late ask");
        assert!(frasil::advanced::peer::administer_server(alice.engine(), &peer.origin, space).await.unwrap(), "erasure offered on administration connection");
        assert!(peer.peer.keeps(&space.0, &erasure.0));
        assert!(!peer.peer.erased(&space.0));
        peer.advance(frasil_peers::limits::CUT_RETENTION + 1).await;
        assert!(peer.peer.keeps(&space.0, &erasure.0));
        let listen = peer.http;
        let clock = peer.clock.clone();
        peer.shutdown().await;
        let peer = frasil_relay::testing::spawn_with(frasil_relay::testing::Options {
            store: Some(store), blobs: Some(blobs), clock: Some(clock), listen,
            ..frasil_conformance::options()
        }).await.unwrap();
        let mut events = alice.events();
        alice.resume_sync([held.id()]);
        loop {
            if matches!(events.next().await, Some(Event::ErasureCannotErase { space: found, .. }) if found == held.id()) { break; }
        }
        assert!(alice.engine().erasing().await.contains(&space));
        assert!(!alice.engine().spaces().await.contains(&space));
        alice.close().await.unwrap();
        bob.close().await.unwrap();
        peer.shutdown().await;
    }).await.expect("standing two reported within the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_held_slot_requests_no_welcome() {
    Box::pin(late_reentry(1, false, true)).await;
}
