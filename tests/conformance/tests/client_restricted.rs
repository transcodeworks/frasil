//! Restricted spaces end to end, through a peer on loopback
//! (ext-restricted-spaces.md): a restricted space under a parent, which
//! admits a member of the parent and no device outside it; a document
//! moved into it, with an edit made offline before the move re-applied
//! there; and the parent's removal mirrored. Every wait has a deadline.
#![cfg(feature = "ext-restricted-spaces")]

use frasil::{Device, Document, Error, Level, Options, Space, Storage, StreamId};
use frasil_conformance::spawn_loopback;
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

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restricted_space_through_a_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let parent = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let bob = device(2).await;
    let bobs_parent = admit(&parent, &bob, &peer.origin, Level::Write).await;
    let carol = device(3).await;
    let _carols_parent = admit(&parent, &carol, &peer.origin, Level::Write).await;

    // A restricted space under the parent, which admits Bob.
    let restricted = parent.create_restricted().await.unwrap();
    let bobs_restricted = admit(&restricted, &bob, &peer.origin, Level::Write).await;
    assert_eq!(bobs_restricted.level().await, Some(Level::Write));
    let plan = restricted.create_document().unwrap();
    plan.edit(|doc| doc.get_text("body").insert(0, "Secret"))
        .await
        .unwrap();
    let bobs_plan = document_reading(&bobs_restricted, plan.id(), "Secret").await;
    bobs_plan
        .edit(|doc| doc.get_text("body").insert(6, " plan"))
        .await
        .unwrap();
    document_reading(&restricted, plan.id(), "Secret plan").await;

    // A device outside the parent gets nothing: Alice admits it nowhere
    // in the restricted space, and Carol, in the parent but not admitted,
    // holds nothing of it.
    let dave = device(4).await;
    let joining = within(dave.join_via_peer(&peer.origin, "Dave", |_, _| async { true }))
        .await
        .unwrap();
    let refused =
        within(restricted.admit(joining.text(), Level::Write, "host", |_, _| async { true })).await;
    assert!(matches!(refused, Err(Error::NotAllowed(_))), "{refused:?}");
    assert!(within(joining.joined()).await.is_err());
    assert!(dave.space(restricted.id()).await.is_err());
    assert!(carol.space(restricted.id()).await.is_err());

    // A document of the parent moves into the restricted space. Bob edits
    // the parent's copy offline, before he learns of the move.
    let draft = parent.create_document().unwrap();
    draft
        .edit(|doc| doc.get_text("body").insert(0, "Draft"))
        .await
        .unwrap();
    let bobs_draft = document_reading(&bobs_parent, draft.id(), "Draft").await;
    for connection in bob.peers() {
        connection.close();
    }
    until(|| async { bob.peers().iter().all(|p| !p.status().connected) }).await;
    bobs_draft
        .edit(|doc| doc.get_text("body").insert(5, " two"))
        .await
        .unwrap();
    let moved = draft.move_to(&restricted).await.unwrap();
    assert_eq!(moved.text("body").await.unwrap(), "Draft");
    assert_eq!(
        draft.moved().await.unwrap().map(|d| d.id()),
        Some(moved.id())
    );

    // Back online, Bob follows the move, and the late write is re-applied
    // in the moved document, where both read it.
    bob.connect(&peer.origin).await.unwrap();
    let bobs_moved = within(async {
        loop {
            if let Some(document) = bobs_draft.moved().await.unwrap() {
                break document;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(bobs_moved.id(), moved.id());
    until(|| async {
        moved.text("body").await.unwrap().contains(" two")
            && bobs_moved.text("body").await.unwrap().contains(" two")
    })
    .await;

    // Bob's removal from the parent is mirrored in the restricted space.
    parent.remove(bob.id()).await.unwrap();
    until(|| async {
        !restricted
            .members()
            .await
            .unwrap()
            .iter()
            .any(|member| member.id == bob.id())
    })
    .await;
    assert_eq!(restricted.level().await, Some(Level::Administer));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    dave.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_in_a_restricted_space() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let parent = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let bob = device(2).await;
    let _bobs_parent = admit(&parent, &bob, &peer.origin, Level::Write).await;
    let restricted = parent.create_restricted().await.unwrap();
    let bobs_restricted = admit(&restricted, &bob, &peer.origin, Level::Write).await;

    // Put, list and get on the device that wrote it.
    let blobs = restricted.create_blobs().unwrap();
    let id = within(blobs.put(Some("diary.txt"), b"Dear diary."))
        .await
        .unwrap();
    let listed = blobs.list().await.unwrap();
    assert!(
        listed
            .iter()
            .any(|blob| blob.id == id && blob.name.as_deref() == Some("diary.txt")),
        "{listed:?}"
    );
    assert_eq!(
        blobs.get(id).await.unwrap().as_deref(),
        Some(&b"Dear diary."[..])
    );
    // The parent holds no blob of it.
    assert!(parent.blobs(blobs.id()).await.is_err());

    // And on another member's device, through the peer.
    let bobs_blobs = within(async {
        loop {
            if let Ok(found) = bobs_restricted.blobs(blobs.id()).await
                && found.list().await.unwrap().iter().any(|blob| blob.id == id)
            {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let read = within(async {
        loop {
            if let Some(bytes) = bobs_blobs.get(id).await.unwrap() {
                break bytes;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(read, b"Dear diary.");

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
