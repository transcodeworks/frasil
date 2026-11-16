//! A partial replica's proven order, through the engine (units.md,
//! "Partial replicas"): a unit whose order against its writer's removal
//! the replica cannot prove is held pending, never applied; the `Path`
//! another replica serves proves it, and the unit stands as it does at a
//! full replica.
#![cfg(all(feature = "adapter-loro", feature = "partial-replicas"))]

use frasil::advanced::sync::{Action, SyncSession};
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_units::messages::{Message, SyncMessage};

async fn device(key: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn signed(engine: &Engine, space: EventId, id: EventId) -> Vec<u8> {
    engine
        .read(&space, |r| r.event(id).map(frasil_events::Event::signed))
        .await
        .unwrap()
        .unwrap()
}

async fn status(engine: &Engine, space: EventId, id: EventId) -> Option<&'static str> {
    engine
        .read(&space, |r| {
            r.status(&id)
                .map(|s| s.class().map_or("Valid", |c| Class::name(c)))
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_path_proves_what_a_partial_replica_held_pending() {
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
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
    let alpha = alice.new_document().unwrap();
    let beta = alice.new_document().unwrap();
    // Bob is partial, and holds Alpha alone.
    bob.hold_streams_only();
    for other in [&bob, &carol] {
        other.follow(space).await;
        other
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
    }
    bob.hold_stream(space, alpha.stream()).await.unwrap();

    // Carol writes in Alpha. Alice reads it, writes twice in Beta, then
    // removes Carol: the removal reaches Carol's unit only through Beta.
    let unit = carol
        .edit_document(space, &alpha, |doc| {
            doc.get_text("body").insert(0, "Carol").unwrap();
        })
        .await
        .unwrap();
    alice
        .ingest(space, vec![signed(&carol, space, unit).await])
        .await
        .unwrap();
    let b1 = alice
        .edit_document(space, &beta, |doc| {
            doc.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let b2 = alice
        .edit_document(space, &beta, |doc| {
            doc.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    let removal = alice
        .remove(space, MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    assert_eq!(status(&alice, space, unit).await, Some("Valid"));

    // Bob gets Carol's unit and the removal, and the parent the removal
    // waits for, which he witnesses.
    let ingested = bob
        .ingest(
            space,
            vec![
                signed(&alice, space, unit).await,
                signed(&alice, space, removal).await,
            ],
        )
        .await
        .unwrap();
    assert!(ingested.wanted.contains(&b2));
    bob.ingest(space, vec![signed(&alice, space, b2).await])
        .await
        .unwrap();
    let witnessed = bob
        .read(&space, |r| r.log().unwrap().witnessed(b2).is_some())
        .await
        .unwrap();
    assert!(witnessed, "Beta's unit is witnessed, not placed");
    assert_eq!(status(&bob, space, removal).await, Some("Valid"));
    // Whether Carol's unit precedes her removal is not proven: pending.
    assert_eq!(status(&bob, space, unit).await, Some("Pending"));
    let wanted = bob
        .read(&space, |r| r.paths_wanted().clone())
        .await
        .unwrap();
    assert!(wanted.contains(&(removal, unit)));

    // Alice serves the Path; Bob takes it, and the unit stands.
    let mut session = SyncSession::new(space);
    let actions = alice
        .read(&space, |r| {
            session.receive(
                r,
                SyncMessage {
                    space,
                    message: Message::PathWant {
                        from: removal,
                        to: unit,
                    },
                },
            )
        })
        .await
        .unwrap();
    let [
        Action::Send(SyncMessage {
            message: Message::Path { from, to, events },
            ..
        }),
    ] = actions.as_slice()
    else {
        panic!("a Path: {actions:?}");
    };
    assert_eq!(events.len(), 2, "through both of Beta's units");
    bob.add_path(space, *from, *to, events.clone())
        .await
        .unwrap();
    assert!(
        bob.read(&space, |r| r.log().unwrap().witnessed(b1).is_some())
            .await
            .unwrap()
    );
    assert_eq!(status(&bob, space, unit).await, Some("Valid"));
    assert_eq!(
        bob.document(&space, &alpha.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "Carol"
    );
    // Beta stays out until Bob opens it; then he reads what he witnessed.
    assert!(bob.document(&space, &beta.stream()).await.is_err());
    bob.hold_stream(space, beta.stream()).await.unwrap();
    assert_eq!(
        bob.document(&space, &beta.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "one two"
    );
}

#[tokio::test]
async fn fork_evidence_across_streams_counts_once_both_streams_are_held() {
    use frasil::advanced::{AdapterRegistry, MemorySlot, MemoryStore, Store};
    use frasil_store::{Commit, DeviceBoundSlot};
    use std::sync::Arc;
    let alice = device(1).await;
    let bob = device(2).await;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let (carol, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[3; 32],
        registry.clone(),
    )
    .await
    .unwrap();
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
    let alpha = alice.new_document().unwrap();
    let beta = alice.new_document().unwrap();
    bob.hold_streams_only();
    for other in [&bob, &carol] {
        other.follow(space).await;
        other
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
    }
    bob.hold_stream(space, alpha.stream()).await.unwrap();

    // Carol writes in Beta, then, restored from a backup taken before,
    // signs the same sequence number again in Alpha: her chain forks
    // across two streams.
    let saved = store.scan(&[]).await.unwrap();
    let in_beta = carol
        .edit_document(space, &beta, |doc| {
            doc.get_text("body").insert(0, "B").unwrap();
        })
        .await
        .unwrap();
    let in_beta = signed(&carol, space, in_beta).await;
    drop(carol);
    let restored = Arc::new(MemoryStore::new());
    assert!(
        restored
            .commit(&Commit::new(saved, Vec::new()))
            .await
            .unwrap()
    );
    let carol = Engine::open(Platform::new(restored, slot), &sealed, &[3; 32], registry)
        .await
        .unwrap();
    carol.synced(&space).await.unwrap();
    let in_alpha = carol
        .edit_document(space, &alpha, |doc| {
            doc.get_text("body").insert(0, "A").unwrap();
        })
        .await
        .unwrap();
    let in_alpha = signed(&carol, space, in_alpha).await;

    // Bob witnesses the unit in Beta: a witness is no evidence.
    bob.ingest(space, vec![in_beta, in_alpha]).await.unwrap();
    let forked = || async {
        bob.read(&space, |r| r.forked(&carol.device_id()))
            .await
            .unwrap()
    };
    assert!(!forked().await);
    // Once Bob opens Beta, both units are in his streams: the evidence
    // counts, and he judges again.
    bob.hold_stream(space, beta.stream()).await.unwrap();
    assert!(forked().await);
}

#[tokio::test]
async fn a_partial_replicas_heads_draw_only_its_streams() {
    use frasil::advanced::Acknowledger;
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let alpha = alice.new_document().unwrap();
    let beta = alice.new_document().unwrap();
    for (doc, text) in [(&alpha, "in alpha"), (&beta, "in beta")] {
        alice
            .edit_document(space, doc, |d| {
                d.get_text("body").insert(0, text).unwrap();
            })
            .await
            .unwrap();
    }
    bob.hold_streams_only();
    bob.follow(space).await;
    let frame: Vec<Vec<u8>> = alice
        .events(&space)
        .await
        .into_iter()
        .filter(|s| frasil_events::decode(s).is_ok_and(|e| e.kind() != frasil_events::kind::UNIT))
        .collect();
    bob.ingest(space, frame).await.unwrap();
    bob.hold_stream(space, alpha.stream()).await.unwrap();

    // Bob's `Heads` name his streams; Alice's answer carries no unit of
    // Beta.
    let mut bobs = SyncSession::new(space);
    let mut alices = SyncSession::new(space);
    let opening = bob.sync_start(&mut bobs).await.unwrap();
    let streams = match &opening[0].message {
        Message::Heads { streams, .. } => streams.clone(),
        other => panic!("{other:?}"),
    };
    assert!(streams.contains(&alpha.stream()) && !streams.contains(&beta.stream()));
    let mut sent = Vec::new();
    for message in opening {
        sent.extend(
            alice
                .sync_receive(
                    &mut alices,
                    Acknowledger::Member(bob.device_id().0),
                    message,
                )
                .await
                .unwrap(),
        );
    }
    let units: Vec<[u8; 16]> = sent
        .iter()
        .filter_map(|m| match &m.message {
            Message::Events { events } => Some(events.clone()),
            _ => None,
        })
        .flatten()
        .filter_map(|s| frasil_units::Unit::from_event(frasil_events::decode(&s).ok()?).ok())
        .map(|u| u.body.stream)
        .collect();
    assert!(units.contains(&alpha.stream()), "{units:?}");
    assert!(!units.contains(&beta.stream()), "{units:?}");
}
