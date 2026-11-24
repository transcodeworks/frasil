//! Waiting for a blob that no connected party holds yet: two devices on
//! loopback share a space over a member connection, with no peer.
#![cfg(all(feature = "iroh", feature = "adapter-blobs"))]

use frasil::{BlobState, Device, Level, Options, Read, Storage};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// Longer than a fetch waits with nothing arriving before it gives up.
const PAST_A_STALL: Duration = Duration::from_secs(33);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .expect("a device")
}

/// `get_when_available` waits its whole time for a blob that a connected
/// member does not hold yet, past the time one fetch waits with nothing
/// arriving, and stores nothing for the fetches that got nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wait_for_a_blob_outlasts_a_fetch_that_gets_nowhere() {
    let alice = device(31).await;
    let bob = device(32).await;
    let space = alice.create_space().await.unwrap();
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    let files = space.create_blobs().unwrap();
    let bytes = vec![5u8; 50_000];
    let blob = files.put(Some("a file"), &bytes).await.unwrap();
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.info(blob).await.is_ok()
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // The one member connected holds nothing of the blob.
    files.drop_local(blob).await.unwrap();
    assert_eq!(files.local(blob).await.unwrap().state, BlobState::Absent);
    assert_eq!(
        bobs_files.get(blob, &Read::new().local()).await.unwrap(),
        None
    );

    let waiting = {
        let blobs = bobs_files.clone();
        tokio::spawn(async move { blobs.get_when_available(blob, DEADLINE).await })
    };
    tokio::time::sleep(PAST_A_STALL).await;
    assert!(
        !waiting.is_finished(),
        "a fetch that got nowhere does not end the wait"
    );
    // Nothing was stored for the reads that fetched nothing.
    assert_eq!(
        bobs_files.local(blob).await.unwrap().state,
        BlobState::Absent
    );

    // The wait ends at its own deadline, or when it is given up.
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    let short = bobs_files
        .get_when_available(blob, Duration::from_millis(500))
        .await;
    assert!(matches!(short, Err(frasil::Error::Timeout)), "{short:?}");
    drop(alice);
}
