//! An authenticated device receives administrator access to many spaces
//! through ordinary sealed welcomes, with independent results and retry.
use frasil::{Device, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_authentication_admits_43_spaces_and_checks_authority_per_space() {
    tokio::time::timeout(Duration::from_secs(180), async {
        // Build the existing-space fixture before starting IO drivers.
        let (engine, _) = frasil::advanced::Engine::create(
            frasil::advanced::Platform::memory(),
            &[1; 32],
            frasil::advanced::AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap();
        let source_id = frasil::SpaceId::from_bytes(engine.create_space().await.unwrap().0);
        let mut spaces = Vec::new();
        for _ in 0..43 {
            spaces.push(frasil::SpaceId::from_bytes(
                engine.create_space().await.unwrap().0,
            ));
        }
        let alice = Device::from_engine(engine, Options::new().loopback()).unwrap();
        let bob = device(2).await;
        let carol = device(3).await;
        let source = alice.space(source_id).await.unwrap();
        let comparisons = Arc::new(AtomicUsize::new(0));
        let compared = comparisons.clone();
        let invitation = source
            .invite_with(
                Level::Write,
                frasil::HistoryMode::WithHistory,
                "Alice",
                move |_, _| {
                    compared.fetch_add(1, Ordering::SeqCst);
                    async { true }
                },
            )
            .await
            .unwrap();
        let compared = comparisons.clone();
        bob.join(invitation.text(), "Bob", move |_, _| {
            compared.fetch_add(1, Ordering::SeqCst);
            async { true }
        })
        .await
        .unwrap();
        invitation.admitted().await.unwrap();
        assert_eq!(comparisons.load(Ordering::SeqCst), 2);
        // Authentication is already complete when the peer exchange begins.
        let peer = spawn_loopback().await.unwrap();
        alice.connect(&peer.origin).await.unwrap();
        spaces[0] = source.id();
        let denied = carol.create_space().await.unwrap();
        // Alice is a writer there, not an administrator.
        let denied_id = frasil_events::EventId(*denied.id().as_bytes());
        carol
            .engine()
            .grant_device(
                denied_id,
                alice.engine().public_keys().clone(),
                Level::Write,
                frasil::HistoryMode::WithHistory,
                frasil_space::Via::Code,
            )
            .await
            .unwrap();
        alice
            .engine()
            .follow(frasil_events::EventId(*denied.id().as_bytes()))
            .await;
        alice
            .engine()
            .ingest(denied_id, carol.engine().events(&denied_id).await)
            .await
            .unwrap();
        assert_eq!(
            alice.space(denied.id()).await.unwrap().level().await,
            Some(Level::Write)
        );
        spaces.insert(20, denied.id());
        let mut progress = Vec::new();
        let reports = alice
            .admit_spaces_via_peer(&peer.origin, source.id(), bob.id(), 255, &spaces, |p| {
                progress.push(p.clone())
            })
            .await
            .unwrap();
        assert_eq!(progress, reports);
        assert_eq!(reports.len(), 44);
        let failure = reports.iter().find(|p| p.space == denied.id()).unwrap();
        assert!(!failure.granted);
        assert!(matches!(failure.result, Err(frasil::Error::NotAllowed(_))));
        let delivered: Vec<_> = reports
            .iter()
            .filter(|p| p.result.is_ok())
            .map(|p| p.space)
            .collect();
        assert_eq!(delivered.len(), 43);
        let received = bob
            .receive_spaces_via_peer(&peer.origin, alice.id(), &delivered, |_| {})
            .await
            .unwrap();
        assert_eq!(received.len(), 43);
        for report in received {
            assert!(report.result.is_ok(), "{report:?}");
            assert!(report.granted);
            assert_eq!(
                bob.space(report.space).await.unwrap().level().await,
                Some(Level::Administer)
            );
        }
        assert_eq!(comparisons.load(Ordering::SeqCst), 2);
        // The delivered keys also let the new administrator author and
        // durably publish a roster change, not just observe its level.
        let target = *delivered.iter().min().unwrap();
        bob.connect(&peer.origin).await.unwrap();
        let managed = bob.space(target).await.unwrap();
        managed.set_level(alice.id(), Level::Write).await.unwrap();
        managed.flush().await.unwrap();
        alice.close().await.unwrap();
        bob.close().await.unwrap();
        carol.close().await.unwrap();
        peer.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_dropped_mid_batch_can_retry_even_a_committed_grant() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let peer = spawn_loopback().await.unwrap();
        let alice = device(4).await;
        let bob = device(5).await;
        let source = alice.create_space().await.unwrap();
        let connection = alice.connect(&peer.origin).await.unwrap();
        let joining = bob
            .join_via_peer(&peer.origin, "Bob", |_, _| async { true })
            .await
            .unwrap();
        source
            .admit_with(
                joining.text(),
                Level::Write,
                frasil::HistoryMode::WithHistory,
                "Alice",
                |_, _| async { true },
            )
            .await
            .unwrap();
        joining.joined().await.unwrap();
        let mut spaces = Vec::new();
        for _ in 0..3 {
            spaces.push(alice.create_space().await.unwrap().id());
        }
        let (sent, mut first) = tokio::sync::oneshot::channel();
        let mut sent = Some(sent);
        let mut batch = Box::pin(alice.admit_spaces_via_peer(
            &peer.origin,
            source.id(),
            bob.id(),
            255,
            &spaces,
            |p| {
                if p.result.is_ok()
                    && let Some(sent) = sent.take()
                {
                    let _ = sent.send(p.space);
                }
            },
        ));
        let committed = tokio::select! {
            first = &mut first => first.unwrap(),
            result = &mut batch => panic!("the batch finished before disconnection: {result:?}"),
        };
        connection.close();
        drop(batch);
        assert!(spaces.contains(&committed));
        // Nothing must be undone: some grants may already have committed.
        // Reconnect and retry the entire batch, including the first one.
        while connection.status().connected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        alice.connect(&peer.origin).await.unwrap();
        let retry = alice
            .admit_spaces_via_peer(&peer.origin, source.id(), bob.id(), 255, &spaces, |_| {})
            .await
            .unwrap();
        assert!(retry.iter().all(|p| p.granted && p.result.is_ok()));
        let received = bob
            .receive_spaces_via_peer(&peer.origin, alice.id(), &spaces, |_| {})
            .await
            .unwrap();
        assert!(
            received.iter().all(|p| p.granted && p.result.is_ok()),
            "{received:?}"
        );
        for space in spaces {
            assert_eq!(
                bob.space(space).await.unwrap().level().await,
                Some(Level::Administer)
            );
        }
        alice.close().await.unwrap();
        bob.close().await.unwrap();
        peer.shutdown().await;
    })
    .await
    .unwrap();
}
