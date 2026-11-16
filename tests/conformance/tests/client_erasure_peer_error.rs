//! A contradictory administration answer never completes an erasure.
use frasil::advanced::{AdapterRegistry, Connect, Engine, Platform, outbox::Acknowledger};
use frasil::{Device, Event, Options};
use frasil_events::EventId;
use frasil_peers::body::StorageBody;
use frasil_space::{HistoryMode, Via};
use frasil_store::BoxFuture;
use frasil_transport::messages::ErasureLate;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

struct LyingPeer(Mutex<Option<ErasureLate>>);
impl Connect for LyingPeer {
    fn connect(
        &self,
        engine: Engine,
        url: String,
        spaces: Vec<EventId>,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::PeerHandle>> {
        Box::pin(async move { frasil::advanced::peer::connect_server(&engine, &url, spaces).await })
    }
    fn administer(
        &self,
        engine: Engine,
        url: String,
        space: EventId,
    ) -> BoxFuture<'static, frasil::Result<bool>> {
        let answer = self.0.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(answer) = answer {
                engine.receive_erasure_late(space, answer).await?;
                Ok(true)
            } else {
                frasil::advanced::peer::administer_server(&engine, &url, space).await
            }
        })
    }
    fn bare(
        &self,
        engine: Engine,
        url: String,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::Bare>> {
        Box::pin(async move { frasil::advanced::peer::bare_server(&engine, &url).await })
    }
}
async fn engine(seed: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[seed; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap()
    .0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contradicted_standing_swapped_envelopes_and_another_erasure_are_unanswered() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let peer = frasil_conformance::spawn_loopback().await.unwrap();
        for corruption in 0..4 {
            let bob = engine(80).await;
            let alice = engine(81).await;
            let space = bob.create_space().await.unwrap();
            bob.grant_administrator(
                space,
                alice.public_keys().clone(),
                200,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
            alice.follow(space).await;
            alice.ingest(space, bob.events(&space).await).await.unwrap();
            alice.enrol(&space).await.unwrap();
            if corruption != 3 {
                bob.ingest(space, alice.events(&space).await).await.unwrap();
            }
            let liar = Arc::new(LyingPeer(Mutex::new(None)));
            let device = Device::from_engine(
                alice.clone(),
                Options::new().loopback().connect_with(liar.clone()),
            )
            .unwrap();
            device.connect(&peer.origin).await.unwrap();
            let held = device
                .space(frasil::SpaceId::from_bytes(space.0))
                .await
                .unwrap();
            held.flush().await.unwrap();
            device.pause_sync([held.id()]);
            let erasure = alice.request_erasure(space).await.unwrap();
            alice
                .acknowledge(
                    space,
                    Acknowledger::Peer([99; 32]),
                    &alice.outbox(&space).await,
                )
                .await
                .unwrap();
            alice.drop_for_erasure(&space).await.unwrap();
            bob.propose_checkpoint(space).await.unwrap();
            let events = bob.events(&space).await;
            let cut = events
                .iter()
                .find(|signed| {
                    frasil_events::decode(signed).is_ok_and(|event| {
                        matches!(
                            StorageBody::read(event.unverified_body()),
                            Ok(StorageBody::Cut(_))
                        )
                    })
                })
                .unwrap()
                .clone();
            let cut_id = frasil_events::decode(&cut).unwrap().id();
            let checkpoint = events
                .iter()
                .find(|signed| {
                    frasil_events::decode(signed).is_ok_and(|event| {
                        event.kind() == frasil_events::kind::SPACE
                            && frasil_peers::skeleton::named_twin(&event) == Some(cut_id)
                    })
                })
                .unwrap()
                .clone();
            let mut answer = ErasureLate {
                space: space.0,
                erasure: erasure.0,
                cut,
                checkpoint: frasil_events::decode(&checkpoint).unwrap().id().0,
                standing: 0,
            };
            match corruption {
                0 => answer.standing = 2,
                1 => answer.cut = checkpoint,
                2 => answer.erasure[0] ^= 1,
                _ => {}
            }
            let expected = answer.encode();
            *liar.0.lock().unwrap() = Some(answer);
            let mut events = device.events();
            device.resume_sync([held.id()]);
            device
                .retry_erasure(frasil::SpaceId::from_bytes(space.0))
                .await
                .unwrap();
            if corruption != 2 {
                loop {
                    match events.next().await {
                        Some(Event::PeerError {
                            space: found,
                            answer,
                            ..
                        }) if *found.as_bytes() == space.0 => {
                            assert_eq!(answer, expected);
                            break;
                        }
                        Some(Event::ErasureCheckpoint { .. }) => {
                            panic!("contradictory evidence reached the application as checked")
                        }
                        _ => {}
                    }
                }
            }
            assert!(device.engine().erasing().await.contains(&space));
            device
                .engine()
                .erasure_answered(&space, None, std::slice::from_ref(&peer.origin))
                .await
                .unwrap();
            assert!(device.engine().erasing().await.contains(&space));
            device.close().await.unwrap();
        }
        peer.shutdown().await;
    })
    .await
    .expect("contradictory answers handled within the deadline");
}

struct ForegroundTasks;
impl frasil::advanced::Tasks for ForegroundTasks {
    fn spawn(&self, task: BoxFuture<'static, ()>) {
        drop(task);
    }
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

struct DelayedAck(std::sync::atomic::AtomicUsize);
impl Connect for DelayedAck {
    fn connect(
        &self,
        engine: Engine,
        url: String,
        _spaces: Vec<EventId>,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::PeerHandle>> {
        // No space is presented here: the administration path must make
        // the pending change durable.
        Box::pin(
            async move { frasil::advanced::peer::connect_server(&engine, &url, Vec::new()).await },
        )
    }
    fn administer(
        &self,
        engine: Engine,
        _: String,
        space: EventId,
    ) -> BoxFuture<'static, frasil::Result<bool>> {
        let attempt = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if attempt > 0 {
                let pending = engine.outbox(&space).await;
                engine
                    .acknowledge(space, Acknowledger::Peer([99; 32]), &pending)
                    .await?;
            }
            Ok(true)
        })
    }
    fn bare(
        &self,
        engine: Engine,
        url: String,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::Bare>> {
        Box::pin(async move { frasil::advanced::peer::bare_server(&engine, &url).await })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flush_drives_administration_again_while_waiting() {
    let peer = frasil_conformance::spawn_loopback().await.unwrap();
    let connector = Arc::new(DelayedAck(std::sync::atomic::AtomicUsize::new(0)));
    let device = Device::from_engine(
        engine(88).await,
        Options::new()
            .loopback()
            .tasks(Arc::new(ForegroundTasks))
            .connect_with(connector.clone()),
    )
    .unwrap();
    let space = device.create_space().await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    let member = engine(89).await;
    device
        .engine()
        .grant_administrator(
            EventId(*space.id().as_bytes()),
            member.public_keys().clone(),
            200,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), space.flush())
        .await
        .unwrap()
        .unwrap();
    assert!(connector.0.load(std::sync::atomic::Ordering::SeqCst) >= 2);
    device.close().await.unwrap();
    peer.shutdown().await;
}
