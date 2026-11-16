//! Guests end to end, through a peer on loopback (ext-guests.md): a guest
//! admitted for a session through an exchange mailbox reads what is shared
//! from now on and writes; ending the session removes it, and what it
//! writes after reaches no one. Every wait has a deadline.
#![cfg(feature = "ext-guests")]

use frasil::{Device, Guest, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_is_admitted_for_a_session_and_removed_with_it() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let before = space.create_document().unwrap();
    before
        .edit(|doc| doc.get_text("body").insert(0, "Before"))
        .await
        .unwrap();

    let bob = device(2).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    let guest = Guest::new(Level::Write, [7; 16]).lasting(Duration::from_secs(3_600));
    within(space.admit_guest(joining.text(), &guest, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    assert_eq!(bobs_space.level().await, Some(Level::Write));

    // The guest reads what is shared from now on, and writes.
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Welcome"))
        .await
        .unwrap();
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(note.id()).await
                && note.text("body").await.unwrap() == "Welcome"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    bobs_note
        .edit(|doc| doc.get_text("body").insert(7, ", Alice"))
        .await
        .unwrap();
    until(|| async { note.text("body").await.unwrap() == "Welcome, Alice" }).await;

    // Ending the session removes the guest: what it writes after does not
    // reach the document.
    space.end_session(guest.session()).await.unwrap();
    assert!(
        !space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|member| member.id == bob.id())
    );
    let _ = bobs_note
        .edit(|doc| doc.get_text("body").insert(0, "Late: "))
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(note.text("body").await.unwrap(), "Welcome, Alice");

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
