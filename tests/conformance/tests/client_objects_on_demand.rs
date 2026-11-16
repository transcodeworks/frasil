//! A device that fetches blobs only when asked, through a peer on loopback
//! (`Options::objects_on_demand`): it knows every file of a Blobs stream and
//! holds none, until it asks for one, and then holds that one alone. Every
//! wait has a deadline.

#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use frasil::{Device, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use provider::{DirProvider, temp_dir};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_is_fetched_when_asked_for_and_the_others_are_not() {
    let peer = spawn_loopback().await.unwrap();
    let open = |key, options: Options| async move {
        Device::open_with(Storage::Memory, &[key; 32], options.loopback())
            .await
            .expect("a device")
    };
    let alice = open(1, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();

    let provider = DirProvider::new(temp_dir("on-demand"));
    let bob = open(
        2,
        Options::new()
            .object_provider(provider.clone())
            .objects_on_demand(),
    )
    .await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let asked = files.put(Some("asked"), b"asked for").await.unwrap();
    let other = files.put(Some("other"), b"left alone").await.unwrap();
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() == 2)
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // Long enough for a device that fetches by itself to have fetched both.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(provider.files(), 0, "nothing until it is asked for");

    let token = within(bobs_files.materialise(asked, b"asked.bin"))
        .await
        .unwrap();
    assert_eq!(provider.read(&token), b"asked for");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(provider.files(), 1, "the other file stays where it is");
    assert_eq!(bobs_files.info(other).await.unwrap().token, None);
}
