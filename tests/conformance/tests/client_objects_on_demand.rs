//! A device fetches a blob when it is asked for, through a peer on
//! loopback: it knows every file of a Blobs stream and holds none, until
//! it reads or materialises one, and then holds that one alone. Every wait
//! has a deadline.

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
    let bob = open(2, Options::new().object_provider(provider.clone())).await;
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

/// How long a read may take to fetch a small blob: well under the time a
/// read waits for a fetch that never starts.
const FETCH: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_fetches_a_blob_on_a_device_that_stores_objects_sealed() {
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

    // No provider: the device stores what it fetches sealed.
    let bob = open(2, Options::new()).await;
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
    let local = frasil::Read::new().local();
    assert_eq!(bobs_files.get(asked, &local).await.unwrap(), None);
    assert_eq!(bobs_files.get(other, &local).await.unwrap(), None);

    let mut read = Vec::new();
    tokio::time::timeout(
        FETCH,
        bobs_files.get_stream(asked, &mut read, &frasil::Read::new(), |_, _| {}),
    )
    .await
    .expect("the read asks for the blob")
    .unwrap();
    assert_eq!(read, b"asked for");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        bobs_files.get(other, &local).await.unwrap(),
        None,
        "the other blob stays where it is"
    );
}

/// A blob of two chunks on a device that holds its blobs as files: the
/// second chunk arrives with no header of its own and is checked under
/// the one the receive holds, the file is the blob's bytes, and the
/// connection reports the fetch while it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_of_two_chunks_is_materialised_as_a_file() {
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

    let provider = DirProvider::new(temp_dir("on-demand-two-chunks"));
    let bob = open(2, Options::new().object_provider(provider.clone())).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    // One chunk and a half.
    let big: Vec<u8> = (0..1_600_000u32).map(|i| (i % 251) as u8).collect();
    let asked = files.put(Some("big"), &big).await.unwrap();
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() == 1)
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let token = tokio::time::timeout(FETCH, bobs_files.materialise(asked, b"big.bin"))
        .await
        .expect("the second chunk is kept")
        .unwrap();
    assert_eq!(provider.read(&token), big);
    assert_eq!(provider.files(), 1);
}

/// A blob a device asked for and then released stays released: the mark
/// its read left goes once the blob is whole, so that the next fetch of
/// the space's objects, which a new unit starts, leaves it alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_released_blob_is_not_fetched_again_by_itself() {
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

    let provider = DirProvider::new(temp_dir("on-demand-released"));
    let bob = open(2, Options::new().object_provider(provider.clone())).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let asked = files.put(Some("asked"), b"asked for").await.unwrap();
    let listed = |count: usize| {
        let bobs_space = &bobs_space;
        let id = files.id();
        within(async move {
            loop {
                if let Ok(blobs) = bobs_space.blobs(id).await
                    && blobs.list().await.is_ok_and(|list| list.len() == count)
                {
                    break blobs;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    let bobs_files = listed(1).await;

    let token = within(bobs_files.materialise(asked, b"asked.bin"))
        .await
        .unwrap();
    assert_eq!(provider.read(&token), b"asked for");
    bobs_files.release(asked).await.unwrap();
    assert_eq!(bobs_files.info(asked).await.unwrap().token, None);

    // A new unit: the connection fetches what the space's units name and
    // the device asked for.
    files.put(Some("other"), b"left alone").await.unwrap();
    listed(2).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        bobs_files.info(asked).await.unwrap().token,
        None,
        "released, and not asked for since"
    );
    assert_eq!(provider.files(), 1, "no file but the one released");

    // Asked for again, it is fetched again.
    let token = within(bobs_files.materialise(asked, b"again.bin"))
        .await
        .unwrap();
    assert_eq!(provider.read(&token), b"asked for");
}
