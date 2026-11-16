//! A device collects its own device mailbox on a connection of its own
//! that presents nothing else (transport.md, 3.12 What a peer learns of a
//! device), against a live peer that records what each connection showed
//! it. Every wait has a deadline, and nothing leaves the host.

use frasil::{Device, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::Shown;
use frasil_transport::frame::MessageType;
use frasil_transport::mailbox::{Kind, address};
use std::future::Future;
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

/// The device's collections reach the peer on one connection, which shows
/// it the device's `Hello` and collections and nothing else: no `Present`,
/// no cookie or `Authorization`, no deposit. The connection that presents
/// the device's space carries no collection. Several upkeeps reuse the one
/// collecting connection, and the item deposited for the device is
/// collected there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_collects_on_a_connection_that_presents_nothing() {
    let peer = spawn_loopback().await.unwrap();
    let watch = peer.peer.watch();
    let origin = peer.origin.clone();
    let bob = device(2).await;
    let space = bob.create_space().await.unwrap();
    let connection = bob.connect(&origin).await.unwrap();
    within(async {
        while !connection.status().spaces.contains(&space.id()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // Another device deposits an item for Bob's device, on a connection of
    // its own.
    let alice = device(1).await;
    alice
        .deposit_item(&origin, bob.id(), b"an item for Bob".to_vec())
        .await
        .unwrap();
    within(bob.mailbox_upkeep()).await;
    within(bob.mailbox_upkeep()).await;
    within(bob.mailbox_upkeep()).await;

    let mailbox = address(Kind::Device, bob.id().as_bytes());
    let shown = watch.connections();
    let collecting: Vec<&Shown> = shown.iter().filter(|c| !c.collected.is_empty()).collect();
    assert_eq!(collecting.len(), 1, "one collecting connection: {shown:?}");
    let collecting = collecting[0];
    assert!(collecting.collected.len() >= 3, "{collecting:?}");
    assert!(collecting.collected.iter().all(|a| *a == mailbox));
    assert!(!collecting.credentialed, "{collecting:?}");
    assert!(collecting.presented.is_empty(), "{collecting:?}");
    assert!(collecting.deposits.is_empty(), "{collecting:?}");
    assert!(collecting.draws.is_empty(), "{collecting:?}");
    assert_eq!(collecting.kinds.first(), Some(&MessageType::Hello));
    assert!(
        collecting.kinds[1..]
            .iter()
            .all(|kind| *kind == MessageType::MailboxGet),
        "{collecting:?}"
    );
    // The space connection presented, and collected nothing.
    let presenting: Vec<&Shown> = shown.iter().filter(|c| !c.presented.is_empty()).collect();
    assert!(!presenting.is_empty(), "{shown:?}");
    assert!(presenting.iter().all(|c| c.collected.is_empty()));
    // The deposit went on a connection of its own, which collected
    // nothing either.
    let depositing: Vec<&Shown> = shown.iter().filter(|c| !c.deposits.is_empty()).collect();
    assert_eq!(depositing.len(), 1, "{shown:?}");
    assert!(depositing[0].collected.is_empty() && depositing[0].presented.is_empty());
    assert_eq!(depositing[0].deposits[0].0, mailbox);
    assert_eq!(bob.collecting_opened(&origin).await, 1);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
