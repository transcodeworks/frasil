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

    // One whose bytes the peer takes before its unit is written.
    let published = files
        .put_version(&vec![5; SIZE], &frasil::PutVersion::new().published())
        .await
        .unwrap();
    within(async {
        while state(&files, published).await != BlobState::Cached {
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

/// A read that is to store nothing, and a read of a blob larger than the
/// whole budget, hold their blob beside the cache while they run: they
/// evict nothing, and their blob goes when they end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_leaves_nothing_displaces_nothing_in_the_cache() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    // Room for two blobs and not three.
    let budget = SIZE as u64 * 5 / 2;
    let bob = open(2, Storage::Memory, Options::new().blob_cache(budget)).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 3).await;
    let large = files
        .put(Some("a large file"), &vec![9; 3 * SIZE])
        .await
        .unwrap();
    within(async {
        while bobs_files.list().await.unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    for (index, id) in ids.iter().take(2).enumerate() {
        let read = get(&bobs_files, *id, &Read::new()).await;
        assert_eq!(read, Some(vec![index as u8 + 1; SIZE]));
    }

    let passing = get(&bobs_files, ids[2], &Read::new().uncached()).await;
    assert_eq!(passing, Some(vec![3; SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Absent);

    let whole = get(&bobs_files, large, &Read::new()).await;
    assert_eq!(whole, Some(vec![9; 3 * SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
    assert_eq!(state(&bobs_files, large).await, BlobState::Absent);
    let usage = bob.blob_cache_usage().await;
    assert!(usage.cached <= budget, "{usage:?}");
    assert!(usage.cached > 2 * SIZE as u64, "{usage:?}");
}

/// Two reads of one blob at once, one of them to store nothing: both get
/// the bytes, and the blob is left in the cache, as the other read asked.
/// Two reads that both store nothing leave nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_reads_of_one_blob_at_once_one_of_them_uncached() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let bob = open(2, Storage::Memory, Options::new()).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 2).await;
    // The keys are here once a first blob reads.
    let first = get(&bobs_files, ids[1], &Read::new()).await;
    assert_eq!(first, Some(vec![2; SIZE]));

    let (cached, passing) = (Read::new(), Read::new().uncached());
    let (kept, passed) = tokio::join!(
        get(&bobs_files, ids[0], &cached),
        get(&bobs_files, ids[0], &passing)
    );
    assert_eq!(kept, Some(vec![1; SIZE]));
    assert_eq!(passed, Some(vec![1; SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Cached);
    assert_eq!(
        bobs_files.get(ids[0], &Read::new().local()).await.unwrap(),
        Some(vec![1; SIZE])
    );

    bobs_files.drop_local(ids[0]).await.unwrap();
    let (one, other) = tokio::join!(
        get(&bobs_files, ids[0], &passing),
        get(&bobs_files, ids[0], &passing)
    );
    assert_eq!(one, Some(vec![1; SIZE]));
    assert_eq!(other, Some(vec![1; SIZE]));
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);

    // One fetches the blob to store nothing, another that stores nothing
    // finds it whole, and they end in either order: the blob goes with
    // the last of them, at once, whichever fetched it.
    for fetcher_first in [true, false] {
        let fetcher = held_read(&bobs_files, ids[0], passing).await;
        let joiner = held_read(&bobs_files, ids[0], passing).await;
        let (first, last) = if fetcher_first {
            (fetcher, joiner)
        } else {
            (joiner, fetcher)
        };
        assert_eq!(finish(first).await, vec![1; SIZE]);
        assert_ne!(
            state(&bobs_files, ids[0]).await,
            BlobState::Absent,
            "a read still uses it"
        );
        assert_eq!(finish(last).await, vec![1; SIZE]);
        assert_eq!(
            state(&bobs_files, ids[0]).await,
            BlobState::Absent,
            "the last read that used it ended; the one that fetched it first: {fetcher_first}"
        );
    }

    // Either of them cancelled: the blob goes once the other ends, or
    // soon after the cancellation when it was the last.
    for cancel_fetcher in [true, false] {
        let fetcher = held_read(&bobs_files, ids[0], passing).await;
        let joiner = held_read(&bobs_files, ids[0], passing).await;
        let (cancelled, other) = if cancel_fetcher {
            (fetcher, joiner)
        } else {
            (joiner, fetcher)
        };
        cancelled.0.abort();
        assert!(cancelled.0.await.unwrap_err().is_cancelled());
        assert_eq!(finish(other).await, vec![1; SIZE]);
        assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Absent);

        let fetcher = held_read(&bobs_files, ids[0], passing).await;
        let joiner = held_read(&bobs_files, ids[0], passing).await;
        let (cancelled, other) = if cancel_fetcher {
            (fetcher, joiner)
        } else {
            (joiner, fetcher)
        };
        assert_eq!(finish(other).await, vec![1; SIZE]);
        cancelled.0.abort();
        assert!(cancelled.0.await.unwrap_err().is_cancelled());
        soon(async {
            while state(&bobs_files, ids[0]).await != BlobState::Absent {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
}

/// A read into a writer that nobody reads from yet: it fetches the blob if
/// the device does not hold it, writes what fits, and waits, using the
/// blob. Returned once it has written its first bytes.
async fn held_read(blobs: &Blobs, id: BlobId, read: Read) -> HeldRead {
    use tokio::io::AsyncReadExt;
    let (writer, mut reader) = tokio::io::duplex(1024);
    let reading = {
        let blobs = blobs.clone();
        tokio::spawn(async move { blobs.get_stream(id, writer, &read, |_, _| {}).await })
    };
    let mut first = [0u8; 1];
    within(reader.read_exact(&mut first)).await.unwrap();
    assert!(!reading.is_finished());
    (reading, reader, first[0])
}

/// A read that waits for its writer to be read, its reader, and the first
/// byte it wrote.
type HeldRead = (
    tokio::task::JoinHandle<frasil::Result<()>>,
    tokio::io::DuplexStream,
    u8,
);

/// Reads a held read to its end: the bytes it gave.
async fn finish((reading, mut reader, first): HeldRead) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut bytes = vec![first];
    within(reader.read_to_end(&mut bytes)).await.unwrap();
    within(reading).await.unwrap().unwrap();
    bytes
}

/// Less than the device's upkeep takes to come round, which looks at the
/// cache too: what must happen at once is not left to it.
async fn soon<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_millis(500), future)
        .await
        .expect("at once, not at the next upkeep")
}

/// A read that leaves its blob in the cache and finds it held beside the
/// cache, by a read that stores nothing, takes it into the cache: the
/// device makes room for it then, and the cache stays within its budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_taken_into_the_cache_from_beside_it_has_room_made_for_it() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    // Room for two blobs and not three.
    let budget = SIZE as u64 * 5 / 2;
    let bob = open(2, Storage::Memory, Options::new().blob_cache(budget)).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 3).await;
    for (index, id) in ids.iter().take(2).enumerate() {
        let read = get(&bobs_files, *id, &Read::new()).await;
        assert_eq!(read, Some(vec![index as u8 + 1; SIZE]));
    }
    let two = bob.blob_cache_usage().await.cached;

    let passing = held_read(&bobs_files, ids[2], Read::new().uncached()).await;
    let usage = bob.blob_cache_usage().await;
    assert!(usage.cached > two, "held beside the cache: {usage:?}");
    assert_eq!(state(&bobs_files, ids[0]).await, BlobState::Cached);

    let cached = get(&bobs_files, ids[2], &Read::new()).await;
    assert_eq!(cached, Some(vec![3; SIZE]));
    let usage = bob.blob_cache_usage().await;
    assert!(usage.cached <= budget, "{usage:?}");
    assert_eq!(
        state(&bobs_files, ids[0]).await,
        BlobState::Absent,
        "the one read longest ago made room"
    );
    assert_eq!(state(&bobs_files, ids[1]).await, BlobState::Cached);
    assert_eq!(finish(passing).await, vec![3; SIZE]);
    assert_eq!(state(&bobs_files, ids[2]).await, BlobState::Cached);
    assert!(bob.blob_cache_usage().await.cached <= budget);
}

/// A read that is to store nothing and is dropped part way, its future
/// cancelled, leaves nothing stored: the blob it fetched goes at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_read_that_stores_nothing_leaves_nothing_stored() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let bob = open(2, Storage::Memory, Options::new()).await;
    let (bobs_files, ids) = join(&peer, &space, &files, &bob, 2).await;
    let first = get(&bobs_files, ids[1], &Read::new()).await;
    assert_eq!(first, Some(vec![2; SIZE]));

    // A writer nobody reads from: the read fetches the blob, writes what
    // fits, and waits.
    let (writer, reader) = tokio::io::duplex(1024);
    let reading = {
        let blobs = bobs_files.clone();
        let id = ids[0];
        tokio::spawn(async move {
            let read = Read::new().uncached();
            blobs.get_stream(id, writer, &read, |_, _| {}).await
        })
    };
    within(async {
        while state(&bobs_files, ids[0]).await == BlobState::Absent {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(!reading.is_finished());
    reading.abort();
    assert!(reading.await.unwrap_err().is_cancelled());
    within(async {
        while state(&bobs_files, ids[0]).await != BlobState::Absent {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert_eq!(bob.blob_cache_usage().await.cached, {
        let kept = bobs_files.local(ids[1]).await.unwrap();
        kept.bytes
    });
    drop(reader);
}

/// A blob put again after the application dropped it, on a connection
/// that uploaded its bytes before: the unit goes with no upload, since the
/// peer answered for the object already, so no answer comes with it. The
/// device offers the object to the peer again, and the blob is released
/// on that answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_put_again_on_the_same_connection_is_released_once_the_peer_answers_again() {
    let peer = spawn_loopback().await.unwrap();
    let (_alice, space, files) = alice(&peer).await;
    let bytes = vec![6; SIZE];
    let id = files.put(Some("a file"), &bytes).await.unwrap();
    within(async {
        while state(&files, id).await != BlobState::Cached {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    files.drop_local(id).await.unwrap();
    assert_eq!(state(&files, id).await, BlobState::Absent);

    let again = files.put(Some("the same file"), &bytes).await.unwrap();
    assert_eq!(state(&files, again).await, BlobState::Kept);
    within(space.flush()).await.unwrap();
    within(async {
        while state(&files, again).await != BlobState::Cached {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}
