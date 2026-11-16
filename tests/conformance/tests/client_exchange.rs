//! Admission by code through an exchange mailbox at a peer, on loopback
//! (admission.md, "Without a nearby connection"): the newcomer shows a QR
//! code naming the peer, the administrator enters it, both compare one
//! code, and the newcomer fetches its snapshot and the space from the
//! peer. A Cancel reaches the other side.

use frasil::{Device, Error, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_joins_through_an_exchange_mailbox() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();

    let bob = device(2).await;
    let shown = Arc::new(Mutex::new(String::new()));
    let bobs_code = shown.clone();
    let joining = within(
        bob.join_via_peer(&peer.origin, "Bob's browser", move |code, host| {
            *bobs_code.lock().unwrap() = code;
            async move { host == "Alice's laptop" }
        }),
    )
    .await
    .unwrap();
    assert!(joining.text().starts_with("FRASIL-ADMIT:"));

    let seen = Arc::new(Mutex::new(String::new()));
    let alices = seen.clone();
    within(space.admit(
        joining.text(),
        Level::Write,
        "Alice's laptop",
        move |code, newcomer| {
            *alices.lock().unwrap() = code;
            async move { newcomer == "Bob's browser" }
        },
    ))
    .await
    .unwrap();
    let alices_code = seen.lock().unwrap().clone();
    let bobs_space = within(joining.joined()).await.unwrap();
    assert_eq!(*shown.lock().unwrap(), alices_code);
    assert_eq!(alices_code.len(), 6);
    assert_eq!(bobs_space.id(), space.id());
    assert_eq!(bobs_space.level().await, Some(Level::Write));
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(note.id()).await
                && note.text("body").await.unwrap() == "Hello"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    bobs_note
        .edit(|doc| doc.get_text("body").insert(5, ", Alice"))
        .await
        .unwrap();
    within(async {
        while note.text("body").await.unwrap() != "Hello, Alice" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // A code a person declines admits no one.
    let carol = device(3).await;
    let joining =
        within(carol.join_via_peer(&peer.origin, "Carol's browser", |_, _| async { true }))
            .await
            .unwrap();
    let declined = within(space.admit(
        joining.text(),
        Level::Read,
        "Alice's laptop",
        |_, _| async { false },
    ))
    .await;
    assert_eq!(declined, Err(Error::Class("Mismatch")));
    // Carol's device reads the Cancel at the peer and stops, long before
    // the code's lifetime ends.
    let stopped = tokio::time::timeout(Duration::from_secs(15), joining.joined())
        .await
        .expect("the joiner stops at the Cancel");
    assert_eq!(stopped.unwrap_err(), Error::Class("Cancelled"));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// A peer that keeps no space without a library ticket: one that trusts an
/// issuer and has no open library.
#[cfg(feature = "ext-libraries")]
async fn peer_without_open_library() -> frasil_relay::testing::TestPeer {
    use frasil_libraries::{Issuer, TrustedIssuers};
    let issuer = Issuer::from_seed(&[5; 32]);
    let mut settings = frasil_conformance::settings();
    settings.libraries.issuers = TrustedIssuers::new([*issuer.public()]).unwrap();
    frasil_relay::testing::spawn_with(frasil_relay::testing::Options {
        settings,
        ..frasil_conformance::options()
    })
    .await
    .unwrap()
}

/// The administrator's device approves, then cannot finish: the peer keeps
/// nothing of a space no library holds, so the newcomer's snapshot never
/// becomes durable there. The newcomer reads the Cancel and stops, rather
/// than wait for a Result until the code's lifetime ends.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newcomer_stops_when_the_approver_cannot_finish() {
    let peer = peer_without_open_library().await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    assert!(!space.is_durable().await);

    let bob = device(2).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    // The approver gives up once the snapshot is not taken within a minute.
    let admitted = tokio::time::timeout(
        Duration::from_secs(90),
        space.admit(
            joining.text(),
            Level::Write,
            "Alice's laptop",
            |_, _| async { true },
        ),
    )
    .await
    .expect("the approver gives up");
    assert!(
        matches!(admitted, Err(Error::Connection(_))),
        "{admitted:?}"
    );
    let stopped = tokio::time::timeout(Duration::from_secs(15), joining.joined())
        .await
        .expect("the joiner stops at the Cancel");
    assert_eq!(stopped.unwrap_err(), Error::Class("Cancelled"));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
