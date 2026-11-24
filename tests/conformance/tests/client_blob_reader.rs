//! A reader over a blob that is not whole on the device, through a peer on
//! loopback (adapter-blobs.md, 3.5 Fetching; units.md, 3.3 Reading an
//! object): what it fetches, where the chunks go, and what a fault of the
//! transfer does. A proxy in front of the peer says which slices of the
//! blob's stored bytes were asked for (transport.md, "Objects over HTTP"),
//! and cuts, corrupts or holds some back. Every wait has a deadline.

#[path = "common/fault_proxy.rs"]
mod fault_proxy;
#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use fault_proxy::{Faults, spawn_proxy};
use frasil::{
    BlobId, BlobReader, BlobState, Blobs, Device, Level, Options, Peer, Read, Space, Storage,
    Verified,
};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::TestPeer;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);

/// The plaintext a chunk holds.
const CHUNK: u64 = 1_048_536;

/// Five and a half chunks, which six slices carry: chunk `i` begins in
/// slice `i` and ends in slice `i + 1`, but for chunk 5, which slice 5
/// ends with.
const SIZE: usize = 5_770_000;

fn content(seed: usize) -> Vec<u8> {
    (0..SIZE).map(|i| ((i + seed) % 251) as u8).collect()
}

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
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
}

/// Alice's space at a peer with one blob there, and Bob, a member that
/// reaches the peer through the proxy and holds nothing of the blob.
/// Beside it a small blob, which Bob read once to know that the key both
/// are sealed under is here: no test reads it again, and what the proxy
/// saw asked of it is left out.
struct Scene {
    peer: TestPeer,
    proxy: String,
    faults: Arc<Faults>,
    /// The small blob's locator, as the proxy shows it.
    probe: String,
    _alice: Device,
    _space: Space,
    files: Blobs,
    bob: Device,
    link: Peer,
    blobs: Blobs,
    id: BlobId,
    bytes: Vec<u8>,
}

async fn scene(options: Options) -> Scene {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let alice = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let bob = Device::open_with(Storage::Memory, &[2; 32], options.loopback())
        .await
        .unwrap();
    // Every connection of Bob's goes through the proxy: the one he joins
    // over stays open beside the one he makes.
    let joining = within(bob.join_via_peer(&proxy, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let joined = within(joining.joined()).await.unwrap();
    let link = bob.connect(&proxy).await.unwrap();
    // The key the blobs are sealed under is here once the small one
    // reads, whole and right. It is another blob than the one the tests
    // read, so that nothing of this read, which each of Bob's connections
    // may still be ending, is a fetch of theirs.
    let small = vec![9; 2000];
    let probe = files.put(Some("a probe"), &small).await.unwrap();
    within(space.wait_durable(DEADLINE)).await.unwrap();
    let blobs = listed(&joined, &files, 1).await;
    until(|| async {
        // Through a reader, which makes no file where the application
        // holds the space's blobs.
        let Ok(mut reader) = blobs.open_reader(probe, &Read::new().uncached()).await else {
            return false;
        };
        let mut read = vec![0; small.len()];
        matches!(reader.read_at(0, &mut read).await, Ok(len) if read[..len] == small[..])
    })
    .await;
    let probe = faults.asked.lock().unwrap()[0].0.clone();
    let bytes = content(0);
    let id = files.put(Some("a film"), &bytes).await.unwrap();
    within(space.wait_durable(DEADLINE)).await.unwrap();
    let blobs = listed(&joined, &files, 2).await;
    faults.clear();
    Scene {
        peer,
        proxy,
        faults,
        probe,
        _alice: alice,
        _space: space,
        files,
        bob,
        link,
        blobs,
        id,
        bytes,
    }
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

/// `len` bytes at `offset`, read until they are all here.
async fn read(reader: &mut BlobReader, offset: u64, len: usize) -> frasil::Result<Vec<u8>> {
    let mut out = vec![0; len];
    let mut filled = 0;
    while filled < len {
        let read = within(reader.read_at(offset + filled as u64, &mut out[filled..])).await?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    out.truncate(filled);
    Ok(out)
}

impl Scene {
    fn slice(&self, offset: u64, len: usize) -> &[u8] {
        &self.bytes[offset as usize..offset as usize + len]
    }

    /// The slices asked for since the faults were last cleared, of any
    /// blob but the small one, in the order they were asked for.
    fn asked_in_order(&self) -> Vec<u64> {
        let asked = self.faults.asked.lock().unwrap();
        let others = asked.iter().filter(|(of, _)| *of != self.probe);
        others.map(|(_, index)| *index).collect()
    }

    /// The slices asked for since the faults were last cleared, each once,
    /// in order of index.
    fn asked(&self) -> Vec<u64> {
        let mut asked = self.asked_in_order();
        asked.sort_unstable();
        asked.dedup();
        asked
    }

    /// Waits until exactly these slices were asked for.
    async fn asked_exactly(&self, slices: &[u64]) {
        let waited = tokio::time::timeout(DEADLINE, async {
            while self.asked() != slices {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "asked {:?}, not {slices:?}", self.asked());
    }

    async fn local(&self) -> (BlobState, u64) {
        let local = self.blobs.local(self.id).await.unwrap();
        (local.state, local.bytes)
    }

    async fn close(self) {
        self.link.close();
        self.peer.shutdown().await;
    }
}

/// A seek before anything of the blob is here returns the right bytes
/// after the slice with the header and the slices of the chunk it lands
/// in, and the read-ahead brings the chunks after it and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seek_fetches_only_the_chunk_it_lands_in_and_the_read_ahead() {
    let scene = scene(Options::new()).await;
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(scene.asked().is_empty(), "nothing is fetched until a read");

    let offset = 3 * CHUNK + 17;
    let piece = read(&mut reader, offset, 1000).await.unwrap();
    assert_eq!(piece, scene.slice(offset, 1000));
    assert_eq!(reader.size(), Some(SIZE as u64));
    assert_eq!(reader.verified(), Verified::Chunks);
    // Chunk 3 is slices 3 and 4, after slice 0 for the header; chunk 4,
    // read ahead, ends in slice 5.
    scene.asked_exactly(&[0, 3, 4, 5]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(scene.asked(), vec![0, 3, 4, 5]);
    let (state, bytes) = scene.local().await;
    assert_eq!(state, BlobState::Cached);
    assert!(bytes > 2 * CHUNK && bytes < 3 * CHUNK, "{bytes}");

    // A seek back fetches where it lands, and nothing of what is held.
    scene.faults.clear();
    reader.set_read_ahead(0);
    let piece = read(&mut reader, 10, 50).await.unwrap();
    assert_eq!(piece, scene.slice(10, 50));
    assert_eq!(scene.asked(), vec![0, 1]);
    reader.close().await.unwrap();
    scene.close().await;
}

/// A range of a blob the device holds nothing of fetches the chunks of
/// the range alone, and a second range the chunks it lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_fetches_its_own_chunks_alone() {
    let scene = scene(Options::new()).await;
    // Across the end of chunk 1 into chunk 2.
    let offset = 2 * CHUNK - 100;
    let range = within(scene.blobs.get_range(scene.id, offset, 300, &Read::new()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(range, scene.slice(offset, 300));
    assert_eq!(scene.asked(), vec![0, 1, 2, 3]);
    assert_eq!(scene.local().await.0, BlobState::Cached);

    scene.faults.clear();
    let range = within(scene.blobs.get_range(scene.id, 2 * CHUNK, 10, &Read::new()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(range, scene.slice(2 * CHUNK, 10));
    assert!(scene.asked().is_empty(), "{:?}", scene.asked());

    // Past the end, and nothing asked for.
    let none = scene
        .blobs
        .get_range(scene.id, SIZE as u64 + 5, 10, &Read::new())
        .await
        .unwrap();
    assert_eq!(none, Some(Vec::new()));
    // The rest arrives with a read of the whole, which is then checked
    // whole.
    let whole = within(scene.blobs.get(scene.id, &Read::new()))
        .await
        .unwrap();
    assert_eq!(whole.as_deref(), Some(&scene.bytes[..]));
    assert_eq!(scene.asked(), vec![0, 1, 3, 4, 5]);
    scene.close().await;
}

/// A chunk that arrives wrong fails the read that needs it, with a class
/// that is not the blob's refusal, and the chunks that opened stay; the
/// peer is asked no more on that connection, and another connection
/// serves the chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_chunk_fails_the_read_and_another_connection_serves_it() {
    let scene = scene(Options::new()).await;
    // The first byte of slice 2 is the end of chunk 1.
    *scene.faults.corrupt.lock().unwrap() = Some(2);
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    let piece = read(&mut reader, 5, 100).await.unwrap();
    assert_eq!(piece, scene.slice(5, 100));
    let failed = read(&mut reader, CHUNK + 5, 100).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Decrypt"), "{failed:?}");
    // Chunk 0 is still here, and still reads.
    let (state, bytes) = scene.local().await;
    assert_eq!(state, BlobState::Cached);
    assert!(bytes > CHUNK, "{bytes}");
    assert_eq!(
        read(&mut reader, 5, 100).await.unwrap(),
        scene.slice(5, 100)
    );
    // Not asked of this peer again on this connection.
    scene.faults.clear();
    let failed = read(&mut reader, CHUNK + 5, 100).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Decrypt"), "{failed:?}");
    assert!(scene.asked().is_empty());

    // Another connection, which serves the chunk right: the read made
    // again gets it, and chunk 0 is not fetched again.
    *scene.faults.corrupt.lock().unwrap() = None;
    scene.link.close();
    let link = scene.bob.connect(&scene.proxy).await.unwrap();
    let piece = within(async {
        loop {
            match read(&mut reader, CHUNK + 5, 100).await {
                Ok(piece) => break piece,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert_eq!(piece, scene.slice(CHUNK + 5, 100));
    assert_eq!(scene.asked(), vec![1, 2]);
    reader.close().await.unwrap();
    link.close();
    scene.close().await;
}

/// A slice of the wrong length is the peer's fault: the read that needs
/// it fails for now, what the device holds of the blob stays, no reader
/// fails for good, and another connection serves the chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slice_of_the_wrong_length_fails_the_read_and_no_reader() {
    for mode in [Read::new(), Read::new().uncached()] {
        let scene = scene(Options::new()).await;
        let mut reader = scene.blobs.open_reader(scene.id, &mode).await.unwrap();
        reader.set_read_ahead(0);
        assert_eq!(
            read(&mut reader, 5, 100).await.unwrap(),
            scene.slice(5, 100)
        );
        let held = scene.local().await;
        // Chunk 2 ends in slice 3.
        *scene.faults.shorten.lock().unwrap() = Some(3);
        let failed = read(&mut reader, 2 * CHUNK + 5, 100).await.unwrap_err();
        assert_eq!(failed.class_name(), Some("Malformed"), "{failed:?}");
        assert_eq!(scene.local().await, held);
        if held.0 == BlobState::Cached {
            assert_eq!(
                read(&mut reader, 5, 100).await.unwrap(),
                scene.slice(5, 100)
            );
        }
        // Another connection, which serves the slice whole.
        *scene.faults.shorten.lock().unwrap() = None;
        scene.link.close();
        let link = scene.bob.connect(&scene.proxy).await.unwrap();
        let piece = within(async {
            loop {
                match read(&mut reader, 2 * CHUNK + 5, 100).await {
                    Ok(piece) => break piece,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await;
        assert_eq!(piece, scene.slice(2 * CHUNK + 5, 100));
        reader.close().await.unwrap();
        link.close();
        scene.close().await;
    }
}

/// A transfer cut part way is taken up again by the connection, and the
/// read that waits for it ends with its bytes. With no connection a read
/// is missing at once; made again once one is back, it reads, and what
/// was fetched before is still here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_resumes_after_a_cut_and_after_a_disconnect() {
    let scene = scene(Options::new()).await;
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    assert_eq!(read(&mut reader, 0, 10).await.unwrap(), scene.slice(0, 10));

    // Slice 3 never arrives, until it does.
    *scene.faults.cut_from.lock().unwrap() = Some(3);
    let offset = 2 * CHUNK + 9;
    let lifted = async {
        until(|| async { scene.faults.cut.load(Ordering::SeqCst) > 0 }).await;
        *scene.faults.cut_from.lock().unwrap() = None;
    };
    let (piece, ()) = tokio::join!(read(&mut reader, offset, 10), lifted);
    assert_eq!(piece.unwrap(), scene.slice(offset, 10));

    // Every connection goes.
    for peer in scene.bob.peers() {
        peer.close();
    }
    until(|| async {
        scene
            .bob
            .peers()
            .iter()
            .all(|peer| peer.status().closed.is_some())
    })
    .await;
    let failed = read(&mut reader, 4 * CHUNK, 10).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Missing"), "{failed:?}");
    assert_eq!(read(&mut reader, 3, 10).await.unwrap(), scene.slice(3, 10));
    // Back: the read made again fetches its chunk and no chunk held.
    scene.faults.clear();
    let link = scene.bob.connect(&scene.proxy).await.unwrap();
    let piece = within(async {
        loop {
            match read(&mut reader, 4 * CHUNK, 10).await {
                Ok(piece) => break piece,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    assert_eq!(piece, scene.slice(4 * CHUNK, 10));
    assert_eq!(scene.asked(), vec![4, 5]);
    reader.close().await.unwrap();
    link.close();
    scene.close().await;
}

/// A reader that stores nothing reads the whole blob in order with the
/// store empty and the cache as it was, holds at most its window, and
/// ends whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncached_reader_leaves_the_store_empty_and_the_cache_untouched() {
    let scene = scene(Options::new()).await;
    // Another blob, in the cache.
    let other = scene.files.put(Some("a still"), &[7; 1000]).await.unwrap();
    until(|| async { scene.blobs.list().await.is_ok_and(|list| list.len() == 3) }).await;
    let got = within(async {
        loop {
            if let Ok(Some(got)) = scene.blobs.get(other, &Read::new()).await {
                break got;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(got, vec![7; 1000]);
    let before = scene.bob.blob_cache_usage().await;

    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(2);
    let mut all = Vec::new();
    while all.len() < SIZE {
        let piece = read(&mut reader, all.len() as u64, 200_000).await.unwrap();
        assert!(!piece.is_empty());
        all.extend(piece);
        assert!(
            reader.window_bytes() <= 3 * 1_048_576,
            "{}",
            reader.window_bytes()
        );
        assert_eq!(scene.local().await, (BlobState::Absent, 0));
        assert_eq!(scene.bob.blob_cache_usage().await, before);
    }
    assert_eq!(all, scene.bytes);
    assert_eq!(reader.verified(), Verified::Whole);
    reader.close().await.unwrap();
    assert_eq!(scene.local().await, (BlobState::Absent, 0));
    assert_eq!(scene.bob.blob_cache_usage().await, before);
    assert_eq!(
        scene.blobs.local(other).await.unwrap().state,
        BlobState::Cached
    );
    scene.close().await;
}

/// Two readers of one blob at different places each read their bytes,
/// stored or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_readers_read_one_blob_at_different_places() {
    for mode in [Read::new(), Read::new().uncached()] {
        let scene = scene(Options::new()).await;
        let mut first = scene.blobs.open_reader(scene.id, &mode).await.unwrap();
        let mut second = scene.blobs.open_reader(scene.id, &mode).await.unwrap();
        let far = 4 * CHUNK + 3;
        for step in 0..3u64 {
            let (a, b) = tokio::join!(
                read(&mut first, step * 700_000, 5000),
                read(&mut second, far + step * 300_000, 5000)
            );
            assert_eq!(a.unwrap(), scene.slice(step * 700_000, 5000));
            assert_eq!(b.unwrap(), scene.slice(far + step * 300_000, 5000));
        }
        first.close().await.unwrap();
        second.close().await.unwrap();
        scene.close().await;
    }
}

/// A reader dropped while its chunk is on its way asks for no more, and
/// nothing of the transfer it left is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_dropped_mid_fetch_leaves_no_fetch_running() {
    for mode in [Read::new(), Read::new().uncached()] {
        let scene = scene(Options::new()).await;
        let mut reader = scene.blobs.open_reader(scene.id, &mode).await.unwrap();
        reader.set_read_ahead(0);
        // The header first; each of Bob's connections ends its fetch
        // of it.
        within(reader.fetch_size()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let held = scene.local().await.1;
        scene.faults.clear();
        scene.faults.hold(&[3]);
        let reading = tokio::spawn(async move {
            let mut buf = [0u8; 10];
            let _ = reader.read_at(3 * CHUNK, &mut buf).await;
        });
        until(|| async { scene.asked().contains(&3) }).await;
        reading.abort();
        let _ = reading.await;
        let asked = scene.asked_in_order();
        scene.faults.hold(&[]);
        tokio::time::sleep(Duration::from_secs(2)).await;
        // No slice is asked for after the drop, not even the second one
        // of the chunk, and nothing of the chunk is kept. Before it,
        // slice 3, behind slice 0 where the store held no header yet.
        assert_eq!(scene.asked_in_order(), asked);
        assert!(
            asked.iter().all(|slice| [0, 3].contains(slice)),
            "{asked:?} {mode:?}"
        );
        assert_eq!(scene.local().await.1, held);
        scene.close().await;
    }
}

/// A cached blob a reader has open stays while other reads fill the cache
/// past its budget; once the reader is closed, the next pass takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eviction_leaves_a_blob_a_reader_has_open() {
    // Room for the blob and a little more.
    let scene = scene(Options::new().blob_cache(SIZE as u64 + 500_000)).await;
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    assert_eq!(
        read(&mut reader, CHUNK, 10).await.unwrap(),
        scene.slice(CHUNK, 10)
    );
    assert_eq!(
        read(&mut reader, 4 * CHUNK, 10).await.unwrap(),
        scene.slice(4 * CHUNK, 10)
    );
    let held = scene.local().await.1;
    assert!(held > 2 * CHUNK);

    // Other blobs, read into the cache until it is past its budget.
    let mut others = Vec::new();
    for seed in 1..=3usize {
        let bytes = vec![seed as u8; 1_500_000];
        others.push((scene.files.put(None, &bytes).await.unwrap(), bytes));
    }
    until(|| async { scene.blobs.list().await.is_ok_and(|list| list.len() == 5) }).await;
    for (id, bytes) in &others {
        let got = within(async {
            loop {
                if let Ok(Some(got)) = scene.blobs.get(*id, &Read::new()).await {
                    break got;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert_eq!(&got, bytes);
    }
    // The open blob lost nothing, and the reader reads on.
    assert_eq!(scene.local().await, (BlobState::Cached, held));
    assert_eq!(
        scene.blobs.local(others[0].0).await.unwrap().state,
        BlobState::Absent
    );
    assert_eq!(
        read(&mut reader, CHUNK + 50, 10).await.unwrap(),
        scene.slice(CHUNK + 50, 10)
    );
    assert!(scene.blobs.drop_local(scene.id).await.is_err());
    reader.close().await.unwrap();
    // Read longest ago, it is the first to go when room is needed.
    let got = within(scene.blobs.get(others[0].0, &Read::new()))
        .await
        .unwrap();
    assert_eq!(got.as_ref(), Some(&others[0].1));
    assert_eq!(scene.local().await, (BlobState::Absent, 0));
    scene.close().await;
}

/// A blob streamed into a writer is written as its chunks arrive, and
/// ends checked whole and in the cache; read that way with nothing stored,
/// it leaves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_of_an_absent_blob_ends_whole() {
    let scene = scene(Options::new()).await;
    let mut out = Vec::new();
    within(
        scene
            .blobs
            .get_stream(scene.id, &mut out, &Read::new().uncached(), |_, _| {}),
    )
    .await
    .unwrap();
    assert_eq!(out, scene.bytes);
    assert_eq!(scene.local().await, (BlobState::Absent, 0));

    let mut out = Vec::new();
    let mut seen = Vec::new();
    within(
        scene
            .blobs
            .get_stream(scene.id, &mut out, &Read::new(), |done, _| seen.push(done)),
    )
    .await
    .unwrap();
    assert_eq!(out, scene.bytes);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(scene.local().await.0, BlobState::Cached);
    // Whole here, and checked: a reader of it is whole from the start.
    let reader = scene
        .blobs
        .open_reader(scene.id, &Read::new().local())
        .await
        .unwrap();
    assert_eq!(reader.verified(), Verified::Whole);
    scene.close().await;
}

/// In a space whose blobs the application holds as files, a reader over
/// a blob that is no file yet fetches the chunks it reads into its own
/// memory and makes no file; over a blob held as a file it reads the
/// file, with the file's ID checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_in_a_space_of_held_files_makes_no_file() {
    let files = provider::DirProvider::new(provider::temp_dir("reader-held"));
    let scene = scene(Options::new().object_provider(files.clone())).await;
    assert_eq!(files.files(), 0);
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(1);
    let offset = 2 * CHUNK + 11;
    let piece = read(&mut reader, offset, 500).await.unwrap();
    assert_eq!(piece, scene.slice(offset, 500));
    assert_eq!(reader.verified(), Verified::Chunks);
    assert!(reader.window_bytes() > 0);
    assert_eq!(files.files(), 0);
    assert_eq!(scene.local().await, (BlobState::Absent, 0));
    reader.close().await.unwrap();
    assert_eq!(files.files(), 0);

    // Made a file, it is read from the file.
    within(scene.blobs.materialise(scene.id, &[]))
        .await
        .unwrap();
    assert_eq!(files.files(), 1);
    scene.faults.clear();
    let mut reader = scene
        .blobs
        .open_reader(scene.id, &Read::new())
        .await
        .unwrap();
    assert_eq!(within(reader.fetch_size()).await.unwrap(), SIZE as u64);
    let piece = read(&mut reader, offset, 500).await.unwrap();
    assert_eq!(piece, scene.slice(offset, 500));
    assert_eq!(reader.verified(), Verified::Whole);
    assert!(scene.asked().is_empty());
    scene.close().await;
}
