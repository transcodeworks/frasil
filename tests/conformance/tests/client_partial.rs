//! A partial replica beside a full one, through a peer on loopback
//! (units.md, "Partial replicas"): the partial device holds its space's
//! frame and the documents it opens, witnesses what its frame cites
//! beyond them, reads and writes its documents, judges every event it
//! holds as the full device does, and places a document it witnessed
//! once it opens it. Every wait has a deadline.
#![cfg(feature = "partial-replicas")]

use frasil::{Device, Document, HistoryMode, Level, Options, Space, Storage, StreamId};
use frasil_conformance::spawn_loopback;
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

async fn device(key: u8, options: Options) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], options.loopback())
        .await
        .expect("a device")
}

/// Admits `newcomer` to `space` through an exchange mailbox at the peer.
async fn admit(space: &Space, newcomer: &Device, origin: &str, level: Level) -> Space {
    let joining = within(newcomer.join_via_peer(origin, "newcomer", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), level, "host", |_, _| async { true }))
        .await
        .unwrap();
    within(joining.joined()).await.unwrap()
}

/// The document once it reads `text`.
async fn document_reading(space: &Space, id: StreamId, text: &str) -> Document {
    within(async {
        loop {
            if let Ok(document) = space.document(id).await
                && document.text("body").await.unwrap() == text
            {
                break document;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

/// Each event the device placed, with its verdict.
async fn verdicts(device: &Device, space: &Space) -> BTreeMap<[u8; 32], String> {
    device
        .engine()
        .read(&frasil_events::EventId(*space.id().as_bytes()), |replica| {
            replica
                .log()
                .map(|log| {
                    log.canonical()
                        .into_iter()
                        .map(|id| (id.0, format!("{:?}", replica.status(&id))))
                        .collect()
                })
                .unwrap_or_default()
        })
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_replica_agrees_with_a_full_one() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let alpha = space.create_document().unwrap();
    alpha
        .edit(|doc| doc.get_text("body").insert(0, "Alpha"))
        .await
        .unwrap();
    let beta = space.create_document().unwrap();
    beta.edit(|doc| doc.get_text("body").insert(0, "Beta"))
        .await
        .unwrap();
    let carol = device(3, Options::new()).await;
    admit(&space, &carol, &peer.origin, Level::Write).await;

    // Bob's device is partial: it holds the frame, and no document yet.
    let bob = device(2, Options::new().partial()).await;
    let bobs_space = admit(&space, &bob, &peer.origin, Level::Write).await;
    assert!(bob.engine().is_partial());
    assert!(bobs_space.streams().await.unwrap().is_empty());

    // He opens Alpha and reads it; Beta stays out.
    let bobs_alpha = document_reading(&bobs_space, alpha.id(), "Alpha").await;
    let held: Vec<StreamId> = bobs_space
        .streams()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(held, vec![alpha.id()]);

    // Alice edits both, then removes Carol: the removal cites Beta's
    // change, which Bob witnesses to place it.
    alpha
        .edit(|doc| doc.get_text("body").insert(5, " one"))
        .await
        .unwrap();
    beta.edit(|doc| doc.get_text("body").insert(4, " two"))
        .await
        .unwrap();
    space.remove(carol.id()).await.unwrap();
    document_reading(&bobs_space, alpha.id(), "Alpha one").await;
    until(|| async {
        !bobs_space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|member| member.id == carol.id())
    })
    .await;

    // Bob writes in Alpha; Alice reads it.
    bobs_alpha
        .edit(|doc| doc.get_text("body").insert(9, " three"))
        .await
        .unwrap();
    document_reading(&space, alpha.id(), "Alpha one three").await;

    // Every event Bob holds has the verdict Alice gives it, and his
    // roster is hers.
    until(|| async {
        let partial = verdicts(&bob, &bobs_space).await;
        let full = verdicts(&alice, &space).await;
        partial
            .iter()
            .all(|(id, verdict)| full.get(id) == Some(verdict))
    })
    .await;
    assert_eq!(
        bobs_space.members().await.unwrap(),
        space.members().await.unwrap()
    );
    assert!(
        verdicts(&bob, &bobs_space).await.len() < verdicts(&alice, &space).await.len(),
        "the partial replica holds less"
    );

    // Beta's change is witnessed, never placed.
    let witnessed = bob
        .engine()
        .read(&frasil_events::EventId(*space.id().as_bytes()), |replica| {
            replica.log().map_or(0, |log| log.witnesses().count())
        })
        .await
        .unwrap();
    assert!(witnessed > 0, "Bob witnesses what the removal cites");

    // Bob opens Beta: what he witnessed is placed, the rest fetched.
    document_reading(&bobs_space, beta.id(), "Beta two").await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_replica_joins_with_history_over_streams_it_does_not_hold() {
    let alice = device(10, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    // Several streams, so that the approver's heads are units a partial
    // replica only witnesses.
    let mut documents = Vec::new();
    for text in ["Alpha", "Beta", "Gamma"] {
        let document = space.create_document().unwrap();
        document
            .edit(|doc| doc.get_text("body").insert(0, text))
            .await
            .unwrap();
        documents.push(document);
    }
    let bob = device(11, Options::new().partial()).await;
    let invitation = space
        .invite_with(
            Level::Write,
            HistoryMode::WithHistory,
            "Alice",
            |_, _| async { true },
        )
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert!(bobs_space.streams().await.unwrap().is_empty());
    document_reading(&bobs_space, documents[1].id(), "Beta").await;
}
