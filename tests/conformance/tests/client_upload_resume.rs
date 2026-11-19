//! A version put from a file through a peer on loopback: unpublished, it
//! is kept and named at once, survives the device closing before or part
//! way through its upload, and reaches the peer once the device opens again
//! and connects, the upload going on from the slices the peer holds;
//! published, it reaches the stream only once the peer holds it. Every
//! wait has a deadline.

#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use frasil::{Blobs, Device, Error, Options, PutVersion, Space, Storage};
use frasil_relay::blobs::{BlobError, Blobs as PeerBlobs, MemoryBlobs};
use frasil_relay::testing::{TestPeer, spawn_with};
use futures_util::future::BoxFuture;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(120);

/// The peer's piece store, noting what it is asked: a slice stored is one
/// `put` of its key, and a slice sent again, already held, one `get`.
#[derive(Default)]
struct Counting {
    inner: MemoryBlobs,
    asked: Mutex<Vec<(Ask, String)>>,
    /// Milliseconds each `put` takes, so that an upload can be cut short.
    delay: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ask {
    Put,
    Get,
}

impl Counting {
    /// How many times a piece of an object was asked for so.
    fn count(&self, ask: Ask, object: &[u8; 64]) -> usize {
        let object = frasil_base::notation::hex::encode(object);
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(made, key)| *made == ask && key.contains(&object))
            .count()
    }

    /// How many distinct pieces of an object were stored.
    fn stored(&self, object: &[u8; 64]) -> usize {
        let object = frasil_base::notation::hex::encode(object);
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(made, key)| *made == Ask::Put && key.contains(&object))
            .map(|(_, key)| key.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    fn note(&self, ask: Ask, key: &str) {
        self.asked.lock().unwrap().push((ask, key.to_owned()));
    }
}

impl PeerBlobs for Counting {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            let delay = self.delay.load(SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            self.note(Ask::Put, key);
            self.inner.put(key, bytes).await
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>> {
        self.note(Ask::Get, key);
        self.inner.get(key)
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>> {
        self.inner.delete(key)
    }
}

async fn peer(blobs: Arc<Counting>) -> TestPeer {
    spawn_with(frasil_relay::testing::Options {
        blobs: Some(blobs),
        iroh: false,
        ..frasil_conformance::options()
    })
    .await
    .unwrap()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frasil-upload-resume-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A file of `size` bytes from `seed`.
fn file(dir: &Path, name: &str, size: usize, seed: u8) -> PathBuf {
    let path = dir.join(name);
    let bytes: Vec<u8> = (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ (i >> 12) as u8 ^ seed)
        .collect();
    std::fs::write(&path, bytes).unwrap();
    path
}

async fn open(dir: &Path) -> Device {
    Device::open_with(
        Storage::directory(dir.join("device")),
        &[4; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap()
}

/// Waits until the peer holds a blob whole and its put is durable here.
async fn reached(peer: &TestPeer, space: &Space, blobs: &Blobs, id: frasil::BlobId) {
    let object = blobs.info(id).await.unwrap().object;
    let start = Instant::now();
    while !peer.peer.holds_object(space.id().as_bytes(), &object)
        || !blobs.is_durable(id).await.unwrap()
    {
        assert!(
            start.elapsed() < DEADLINE,
            "the blob reaches the peer in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_put_offline_reaches_the_peer_after_a_reopen() {
    let dir = temp("offline");
    let path = file(&dir, "photo.bin", 3 << 20, 1);
    let counting = Arc::new(Counting::default());
    let peer = peer(counting.clone()).await;

    // Put with no peer: kept and named at once, and pending.
    let device = open(&dir).await;
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let id = blobs
        .put_version_file(&path, &PutVersion::new().named("photo"), |_, _| {})
        .await
        .unwrap();
    assert_eq!(blobs.info(id).await.unwrap().name.as_deref(), Some("photo"));
    assert!(!blobs.is_durable(id).await.unwrap());
    assert_eq!(blobs.pending().await.unwrap(), vec![id]);
    let (space_id, stream) = (space.id(), blobs.id());
    device.close().await.unwrap();
    drop((blobs, space, device));
    std::fs::remove_file(&path).unwrap();

    // Opened again, the blob is still pending, then goes once connected.
    let device = open(&dir).await;
    let space = device.space(space_id).await.unwrap();
    let blobs = space.blobs(stream).await.unwrap();
    assert_eq!(blobs.pending().await.unwrap(), vec![id]);
    device.connect(&peer.origin).await.unwrap();
    reached(&peer, &space, &blobs, id).await;
    assert!(blobs.pending().await.unwrap().is_empty());
    assert_eq!(
        blobs.get(id).await.unwrap().map(|bytes| bytes.len()),
        Some(3 << 20)
    );
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_cut_short_goes_on_from_the_slices_the_peer_holds() {
    let dir = temp("cut");
    // 12 slices of the HTTP routes: the stored bytes are the plaintext's,
    // with less than 4 KiB of header and tags.
    let path = file(&dir, "video.bin", (12 << 20) - 4096, 2);
    let counting = Arc::new(Counting::default());
    counting.delay.store(150, SeqCst);
    let peer = peer(counting.clone()).await;

    let device = open(&dir).await;
    let space = device.create_space().await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let id = blobs
        .put_version_file(&path, &PutVersion::new().named("video"), |_, _| {})
        .await
        .unwrap();
    let object = blobs.info(id).await.unwrap().object;

    // Closed once the peer stored a few slices.
    let start = Instant::now();
    while counting.count(Ask::Put, &object) < 4 {
        assert!(start.elapsed() < DEADLINE, "the upload starts in time");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (space_id, stream) = (space.id(), blobs.id());
    device.close().await.unwrap();
    drop((blobs, space, device));
    // What was in flight lands.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = counting.count(Ask::Put, &object);
    let reopened = counting.asked.lock().unwrap().len();
    assert!(!peer.peer.holds_object(space_id.as_bytes(), &object));
    assert!(before < 12, "the upload was cut short: {before} slices");

    // Opened again: the upload goes on from the slices held.
    counting.delay.store(0, SeqCst);
    let device = open(&dir).await;
    let space = device.space(space_id).await.unwrap();
    let blobs = space.blobs(stream).await.unwrap();
    assert_eq!(blobs.pending().await.unwrap(), vec![id]);
    device.connect(&peer.origin).await.unwrap();
    reached(&peer, &space, &blobs, id).await;
    let after = counting.count(Ask::Put, &object) - before;
    // Until a slice past the one in flight at the close is stored, the
    // peer reads only the slices sent again, to compare them: slice 0, to
    // learn what the peer holds. An upload started over would send each
    // slice the peer holds.
    let object_hex = frasil_base::notation::hex::encode(object);
    let index = |key: &str| key.rsplit('/').next().unwrap().parse::<usize>().unwrap();
    let again = counting.asked.lock().unwrap()[reopened..]
        .iter()
        .filter(|(_, key)| key.contains(&object_hex))
        .take_while(|(ask, key)| *ask == Ask::Get || index(key) <= before)
        .filter(|(ask, _)| *ask == Ask::Get)
        .count();
    eprintln!("slices stored before the reopen {before}, after {after}, sent again {again}");
    // A slice in flight as the device closed may still land after the
    // reopen, the same bytes again.
    assert_eq!(counting.stored(&object), 12, "every slice is stored");
    assert_eq!(again, 1, "slices sent again after the reopen");
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_published_version_from_a_file_waits_for_the_peer() {
    let dir = temp("published");
    let first = file(&dir, "v1.bin", (2 << 20) + 5, 3);
    let second = file(&dir, "v2.bin", 100, 4);
    let counting = Arc::new(Counting::default());
    let peer = peer(counting.clone()).await;
    let device = open(&dir).await;
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();

    // No peer: nothing reaches the stream.
    let refused = blobs
        .put_version_file(&first, &PutVersion::new().named("v").published(), |_, _| {})
        .await;
    assert!(
        matches!(refused, Err(Error::Class("Missing"))),
        "{refused:?}"
    );
    assert!(blobs.list().await.unwrap().is_empty());

    // Connected: the peer holds each version before its unit names it.
    device.connect(&peer.origin).await.unwrap();
    let mut seen = Vec::new();
    let v1 = blobs
        .put_version_file(
            &first,
            &PutVersion::new().named("v").published(),
            |done, total| {
                seen.push((done, total));
            },
        )
        .await
        .unwrap();
    assert_eq!(seen.last(), Some(&((2 << 20) + 5, Some((2 << 20) + 5))));
    let object = blobs.info(v1).await.unwrap().object;
    assert!(peer.peer.holds_object(space.id().as_bytes(), &object));
    let v2 = blobs
        .put_version_seekable(
            std::io::Cursor::new(std::fs::read(&second).unwrap()),
            &PutVersion::new().named("v").parents(&[v1]).published(),
            |_, _| {},
        )
        .await
        .unwrap();
    let object = blobs.info(v2).await.unwrap().object;
    assert!(peer.peer.holds_object(space.id().as_bytes(), &object));
    reached(&peer, &space, &blobs, v1).await;
    reached(&peer, &space, &blobs, v2).await;
    assert!(blobs.pending().await.unwrap().is_empty());
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_published_version_from_a_file_is_uploaded_from_the_application_s_file() {
    let dir = temp("held");
    let path = file(&dir, "scan.bin", (3 << 20) + 17, 5);
    let counting = Arc::new(Counting::default());
    let peer = peer(counting.clone()).await;
    let files = provider::DirProvider::new(dir.join("files"));
    let device = open(&dir).await;
    let space = device.create_space().await.unwrap();
    space.hold_objects(files.clone()).await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let id = blobs
        .put_version_file(
            &path,
            &PutVersion::new().named("scan").published(),
            |_, _| {},
        )
        .await
        .unwrap();
    let info = blobs.info(id).await.unwrap();
    assert!(peer.peer.holds_object(space.id().as_bytes(), &info.object));
    // The provider's copy is the blob's.
    let token = info.token.expect("held");
    assert_eq!(files.read(&token), std::fs::read(&path).unwrap());
    reached(&peer, &space, &blobs, id).await;
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
