//! What a device keeps of the blobs it reads, through a peer on loopback
//! (at-rest.md, "Retention"): a blob is fetched when it is read and left in
//! a cache with a budget, kept when the application asks, or absent. Every
//! wait has a deadline.

#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use frasil::{
    BlobChange, BlobId, BlobState, BlobStatus, Blobs, Device, Level, Options, Read, Space, Storage,
};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::TestPeer;
use provider::temp_dir;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// How long a device that fetched blobs by itself would need for these.
const BY_ITSELF: Duration = Duration::from_secs(2);

/// The size of each blob: one chunk, and a little more stored.
const SIZE: usize = 100_000;

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn open(key: u8, storage: Storage, options: Options) -> Device {
    Device::open_with(storage, &[key; 32], options.loopback())
        .await
        .expect("a device")
}

/// Alice, her space at the peer, and an empty blob stream.
async fn alice(peer: &TestPeer) -> (Device, Space, Blobs) {
    let alice = open(1, Storage::Memory, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    (alice, space, files)
}

/// Admits a device to Alice's space, then puts `count` blobs there, which
/// the device can open: it was a member when they were put. Returns the
/// stream as the device holds it, once it lists every blob, and the blobs.
async fn join(
    peer: &TestPeer,
    space: &Space,
    files: &Blobs,
    device: &Device,
    count: u8,
) -> (Blobs, Vec<BlobId>) {
    let joining = within(device.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let joined = within(joining.joined()).await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    let mut ids = Vec::new();
    for index in 0..count {
        let bytes = vec![index + 1; SIZE];
        ids.push(files.put(Some("a file"), &bytes).await.unwrap());
    }
    (listed(&joined, files, usize::from(count)).await, ids)
}

/// The blob stream on a device, once it lists `count` blobs.
async fn listed(space: &Space, files: &Blobs, count: usize) -> Blobs {
    within(async {
        loop {
            if let Ok(blobs) = space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() == count)
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

/// A blob's bytes as `read` reads them, once the device holds the key they
/// are sealed under: a newcomer's keys come after the stream's entries.
async fn get(blobs: &Blobs, id: BlobId, read: &Read) -> Option<Vec<u8>> {
    within(async {
        loop {
            match blobs.get(id, read).await {
                Err(frasil::Error::Class("Sealed")) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                other => break other.unwrap(),
            }
        }
    })
    .await
}

async fn state(blobs: &Blobs, id: BlobId) -> BlobState {
    blobs.local(id).await.unwrap().state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_fetches_a_blob_and_stores_nothing_with_a_zero_budget() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let bob = open(2, Storage::Memory, Options::new().blob_cache(0)).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 2).await;

    // Nothing is fetched because a stream names it.
    tokio::time::sleep(BY_ITSELF).await;
    for id in &ids {
        assert_eq!(state(&bobs_files, *id).await, BlobState::Absent);
        assert_eq!(bobs_files.status(*id).await.unwrap(), BlobStatus::Absent);
        assert_eq!(
            bobs_files.get(*id, &Read::new().local()).await.unwrap(),
            None
        );
    }

    // A read fetches the blob, and none of it stays once the read ends.
    let read = get(&bobs_files, ids[0], &Read::new()).await;
    assert_eq!(read, Some(vec![1; SIZE]));
    let local = bobs_files.local(ids[0]).await.unwrap();
    assert_eq!(
        (local.state, local.bytes, local.size),
        (BlobState::Absent, 0, SIZE as u64)
    );
    let usage = bob.blob_cache_usage().await;
    assert_eq!((usage.budget, usage.cached, usage.kept), (0, 0, 0));
    assert_eq!(
        bobs_files.get(ids[0], &Read::new().local()).await.unwrap(),
        None
    );

    // Into a writer, by range and hashed alike.
    let mut streamed = Vec::new();
    within(bobs_files.get_stream(ids[1], &mut streamed, &Read::new(), |_, _| {}))
        .await
        .unwrap();
    assert_eq!(streamed, vec![2; SIZE]);
    let range = within(bobs_files.get_range(ids[1], 10, 5, &Read::new()))
        .await
        .unwrap();
    assert_eq!(range, Some(vec![2; 5]));
    assert!(
        within(bobs_files.content_hash(ids[1], &Read::new()))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        bobs_files
            .content_hash(ids[1], &Read::new().local())
            .await
            .unwrap(),
        None
    );
    assert_eq!(bob.blob_cache_usage().await.cached, 0);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Absent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cache_evicts_at_its_budget_and_an_evicted_blob_comes_back_only_when_read() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    // Room for two blobs and not three.
    let budget = SIZE as u64 * 5 / 2;
    let bob = open(2, Storage::Memory, Options::new().blob_cache(budget)).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 3).await;
    let mut changes = bobs_files.changes().await.unwrap();

    // The feed is followed after each read: it reports what differs from
    // what it last saw, so a blob that arrived and went between two looks
    // is never reported.
    for (index, id) in ids.iter().enumerate() {
        let read = get(&bobs_files, *id, &Read::new()).await;
        assert_eq!(read, Some(vec![index as u8 + 1; SIZE]));
        // The third read makes room first: the first one read goes.
        let mut expected = vec![BlobChange::Arrived { id: *id }];
        if index == 2 {
            expected.push(BlobChange::Evicted { id: ids[0] });
        }
        within(async {
            while !expected.is_empty() {
                let change = changes.next().await.unwrap().unwrap();
                if matches!(
                    change,
                    BlobChange::Arrived { .. } | BlobChange::Evicted { .. }
                ) {
                    let at = expected.iter().position(|wanted| *wanted == change);
                    expected.remove(at.unwrap_or_else(|| panic!("{change:?}")));
                }
            }
        })
        .await;
    }
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Cached);
    let usage = bob.blob_cache_usage().await;
    assert!(usage.cached <= budget, "{usage:?}");
    assert!(usage.cached > 2 * SIZE as u64, "{usage:?}");
    assert_eq!(usage.kept, 0);

    // Absent by the device's own choice: nothing fetches it again.
    tokio::time::sleep(BY_ITSELF).await;
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);
    assert_eq!(bobs_files.status(ids[0]).await.unwrap(), BlobStatus::Absent);
    assert_eq!(
        bobs_files.get(ids[0], &Read::new().local()).await.unwrap(),
        None
    );

    // A read does, and the one read longest ago goes in its turn: the
    // second, since the third was read after it.
    let again = get(&bobs_files, ids[0], &Read::new()).await;
    assert_eq!(again, Some(vec![1; SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Absent);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Cached);
    assert_eq!(
        bobs_files.status(ids[0]).await.unwrap(),
        BlobStatus::Readable
    );
    assert!(bob.blob_cache_usage().await.cached <= budget);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_blob_survives_a_full_cache_and_a_reopen() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let dir = temp_dir("blob-cache-kept");
    let budget = SIZE as u64 * 3 / 2;
    let options = || Options::new().never_restored().blob_cache(budget);
    let bob = open(2, Storage::Directory(dir.clone()), options()).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 3).await;

    // Kept without being read, with its progress.
    let mut progress = Vec::new();
    within(bobs_files.keep(ids[0], |done, total| progress.push((done, total))))
        .await
        .unwrap();
    assert_eq!(progress.last(), Some(&(SIZE as u64, Some(SIZE as u64))));
    let local = bobs_files.local(ids[0]).await.unwrap();
    assert_eq!(local.state, BlobState::Kept);
    assert!(local.bytes > SIZE as u64);
    // Two reads fill the cache past its budget: the kept blob is no part
    // of it.
    for id in &ids[1..] {
        get(&bobs_files, *id, &Read::new()).await.unwrap();
    }
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Kept);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Absent);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Cached);
    let usage = bob.blob_cache_usage().await;
    assert!(
        usage.kept > SIZE as u64 && usage.cached <= budget,
        "{usage:?}"
    );
    // A read that keeps makes a cached blob kept.
    get(&bobs_files, ids[2], &Read::new().keep()).await.unwrap();
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Kept);
    let bobs_space = bobs_files.space().id();
    bob.close().await.unwrap();
    drop(bobs_files);
    drop(bob);

    // Opened again, with no connection and no budget at all.
    let bob = open(
        2,
        Storage::Directory(dir),
        Options::new().never_restored().blob_cache(0),
    )
    .await;
    let bobs_space = bob.space(bobs_space).await.unwrap();
    let bobs_files = listed(&bobs_space, &files, 3).await;
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Kept);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Kept);
    assert_eq!(
        bobs_files.get(ids[0], &Read::new()).await.unwrap(),
        Some(vec![1; SIZE])
    );
    assert_eq!(
        bobs_files.get(ids[2], &Read::new().local()).await.unwrap(),
        Some(vec![3; SIZE])
    );
    // Not connected: what is not here cannot be fetched.
    assert_eq!(bobs_files.get(ids[1], &Read::new()).await.unwrap(), None);
    assert_eq!(
        bobs_files.status(ids[1]).await.unwrap(),
        BlobStatus::Missing
    );

    // The application drops one: it is absent, and the other stays.
    bobs_files.drop_local(ids[0]).await.unwrap();
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);
    assert_eq!(
        bobs_files.get(ids[0], &Read::new().local()).await.unwrap(),
        None
    );
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Kept);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncached_read_leaves_what_the_device_held_and_nothing_more() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let bob = open(2, Storage::Memory, Options::new()).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 2).await;

    let read = get(&bobs_files, ids[0], &Read::new().uncached()).await;
    assert_eq!(read, Some(vec![1; SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);
    assert_eq!(bob.blob_cache_usage().await.cached, 0);

    // A blob the device holds is read from the device, and stays.
    get(&bobs_files, ids[1], &Read::new()).await.unwrap();
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
    let mut streamed = Vec::new();
    within(bobs_files.get_stream(ids[1], &mut streamed, &Read::new().uncached(), |_, _| {}))
        .await
        .unwrap();
    assert_eq!(streamed, vec![2; SIZE]);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);

    // Dropped by the application, it is fetched again by a read.
    bobs_files.drop_local(ids[1]).await.unwrap();
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Absent);
    assert_eq!(
        within(bobs_files.get_when_available(ids[1], DEADLINE))
            .await
            .unwrap(),
        vec![2; SIZE]
    );
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_keeps_every_blob_fetches_them_by_itself() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    // A budget of nothing changes nothing for it.
    let bob = open(
        2,
        Storage::Memory,
        Options::new().keep_all_blobs().blob_cache(0),
    )
    .await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 2).await;
    within(async {
        for (index, id) in ids.iter().enumerate() {
            loop {
                if let Some(bytes) = get(&bobs_files, *id, &Read::new().local()).await {
                    assert_eq!(bytes, vec![index as u8 + 1; SIZE]);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    })
    .await;
    for id in &ids {
        assert_eq!(state(&bobs_files, *id).await, BlobState::Kept);
    }
    let usage = bob.blob_cache_usage().await;
    assert_eq!(usage.cached, 0);
    assert!(usage.kept > 2 * SIZE as u64);
    // It would fetch a dropped blob again at once: the drop is refused.
    assert!(matches!(
        bobs_files.drop_local(ids[0]).await,
        Err(frasil::Error::NotAllowed(_))
    ));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Kept);
}

/// A blob this device put is kept until the peer holds its bytes and the
/// unit that names it, and the cache's from then on. One put with no peer
/// reached stays kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_this_device_put_is_cached_once_the_peer_holds_it() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, _space, files) = alice(&peer).await;
    let id = files.put(Some("a file"), &vec![3; SIZE]).await.unwrap();
    within(async {
        while state(&files, id).await != BlobState::Cached {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let alone = open(3, Storage::Memory, Options::new().blob_cache(0)).await;
    let space = alone.create_space().await.unwrap();
    let files = space.create_blobs().unwrap();
    let id = files.put(Some("a file"), &vec![4; SIZE]).await.unwrap();
    assert_eq!(state(&files, id).await, BlobState::Kept);
    assert_eq!(
        files.get(id, &Read::new().local()).await.unwrap(),
        Some(vec![4; SIZE])
    );
}
