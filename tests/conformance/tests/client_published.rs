//! `Blobs::put_from_published` through a peer on loopback: a blob reaches
//! the stream only once a peer holds its bytes, and its file stays held
//! here, servable, afterwards. Every wait has a deadline.

#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use frasil::{
    Device, Error, Level, ObjectProvider, ObjectReader, ObjectStat, ObjectWriter, Options,
    PutVersion, Result, Space, SpaceId, Storage,
};
use frasil_conformance::spawn_loopback;
use frasil_store::BoxFuture;
use provider::{DirProvider, temp_dir};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8, provider: Arc<DirProvider>) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().object_provider(provider),
    )
    .await
    .expect("a device")
}

async fn holding(space: &Space, provider: Arc<DirProvider>) {
    space.hold_objects(provider).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_reaches_the_stream_without_a_peer() {
    let provider = DirProvider::new(temp_dir("published-offline"));
    let alice = device(1, provider.clone()).await;
    let space = alice.create_space().await.unwrap();
    holding(&space, provider.clone()).await;
    let files = space.create_blobs().unwrap();
    let token = provider.write("offline.bin", b"not yet anywhere else");
    let refused = within(files.put_from_published("offline", &token)).await;
    assert!(
        matches!(refused, Err(Error::Class("Missing"))),
        "{refused:?}"
    );
    assert!(files.list().await.unwrap().is_empty());
    assert_eq!(provider.read(&token), b"not yet anywhere else");

    // Connected, the same file goes.
    let peer = spawn_loopback().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let id = within(files.put_from_published("offline", &token))
        .await
        .unwrap();
    assert_eq!(
        files.get(id).await.unwrap().as_deref(),
        Some(&b"not yet anywhere else"[..])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_published_blob_stays_held_and_servable() {
    let peer = spawn_loopback().await.unwrap();
    let provider = DirProvider::new(temp_dir("published"));
    let alice = device(1, provider.clone()).await;
    let space = alice.create_space().await.unwrap();
    holding(&space, provider.clone()).await;
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();

    let bobs = DirProvider::new(temp_dir("published-bob"));
    let bob = device(2, bobs.clone()).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();

    let token = provider.write("saved.bin", b"held and at the peer");
    let id = within(files.put_from_published("saved", &token))
        .await
        .unwrap();
    // The file is still the blob's copy here, and nothing was forgotten.
    assert_eq!(files.info(id).await.unwrap().token, Some(token.clone()));
    assert!(provider.forgotten().is_empty());
    assert_eq!(
        files.get(id).await.unwrap().as_deref(),
        Some(&b"held and at the peer"[..])
    );

    // Another device reaches it through the peer.
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
    let mut fetched = Vec::new();
    within(bobs_files.get_stream(id, &mut fetched, |_, _| {}))
        .await
        .unwrap();
    assert_eq!(fetched, b"held and at the peer");
}

/// A provider whose file changes once it has been read for the put, and
/// the put has found it held: when the upload stats it for the fourth
/// time, after the put's two and the check that the device holds it.
#[derive(Debug)]
struct ChangesDuringUpload {
    files: Arc<DirProvider>,
    stats: AtomicUsize,
}

impl ObjectProvider for ChangesDuringUpload {
    fn stat<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Option<ObjectStat>>> {
        if self.stats.fetch_add(1, Ordering::SeqCst) == 3 {
            std::fs::write(self.files.path(token), b"saved again").unwrap();
        }
        self.files.stat(token)
    }

    fn open<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Box<dyn ObjectReader>>> {
        self.files.open(token)
    }

    fn create<'a>(
        &'a self,
        space: SpaceId,
        object_id: [u8; 32],
        size: u64,
        hint: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn ObjectWriter>>> {
        self.files.create(space, object_id, size, hint)
    }

    fn forget<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.files.forget(token)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_that_changes_during_the_upload_is_changed() {
    let peer = spawn_loopback().await.unwrap();
    let files_dir = DirProvider::new(temp_dir("published-changed"));
    let alice = device(1, files_dir.clone()).await;
    let space = alice.create_space().await.unwrap();
    space
        .hold_objects(Arc::new(ChangesDuringUpload {
            files: files_dir.clone(),
            stats: AtomicUsize::new(0),
        }))
        .await
        .unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let token = files_dir.write("changing.bin", b"the first bytes");
    let refused = within(files.put_from_published("changing", &token)).await;
    assert!(
        matches!(refused, Err(Error::Class("Changed"))),
        "{refused:?}"
    );
    assert!(files.list().await.unwrap().is_empty());
}

/// Saved twice before any peer is reached: the held file holds only the
/// second version, so the first version's bytes are gone from this device.
/// The first version's unit still reaches the peer, without its object;
/// the second version, and every unit after it, reach the peer with theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_saved_over_offline_does_not_hold_back_the_stream() {
    let peer = spawn_loopback().await.unwrap();
    let provider = DirProvider::new(temp_dir("superseded-offline"));
    let alice = device(1, provider.clone()).await;
    let space = alice.create_space().await.unwrap();
    holding(&space, provider.clone()).await;
    let files = space.create_blobs().unwrap();
    let link = alice.connect(&peer.origin).await.unwrap();
    let bobs = DirProvider::new(temp_dir("superseded-bob"));
    let bob = device(2, bobs).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    within(space.flush()).await.unwrap();
    link.close();

    // Offline: saved, then saved over.
    let token = provider.write("saved.bin", b"the first version");
    let first = within(files.put_version_from(&token, &PutVersion::new().named("saved")))
        .await
        .unwrap();
    std::fs::write(provider.path(&token), b"the second version, saved over it").unwrap();
    let second =
        within(files.put_version_from(&token, &PutVersion::new().named("saved").parents(&[first])))
            .await
            .unwrap();
    let later = within(files.put(Some("later"), b"written after both"))
        .await
        .unwrap();

    // Online again.
    alice.connect(&peer.origin).await.unwrap();

    // Every unit reaches the peer, and through it Bob.
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() >= 2)
                && blobs.info(later).await.is_ok()
                && blobs.info(second).await.is_ok()
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // The peer holds the second version's bytes and the later blob's.
    assert_eq!(
        within(read(&bobs_files, second)).await.unwrap(),
        b"the second version, saved over it"
    );
    assert_eq!(
        within(read(&bobs_files, later)).await.unwrap(),
        b"written after both"
    );
    // The first version's bytes are nowhere: its fetch never moves.
    let missing = within(read(&bobs_files, first)).await;
    assert!(matches!(missing, Err(Error::Timeout)), "{missing:?}");
}

/// A blob's bytes once the state that sealed it has reached this device.
async fn read(blobs: &frasil::Blobs, id: frasil::BlobId) -> Result<Vec<u8>> {
    loop {
        let mut fetched = Vec::new();
        match blobs.get_stream(id, &mut fetched, |_, _| {}).await {
            Err(Error::Class("Sealed")) => tokio::time::sleep(Duration::from_millis(50)).await,
            other => return other.map(|_| fetched),
        }
    }
}
