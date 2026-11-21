//! Peak live allocations while a blob much larger than a chunk is put from
//! a file and uploaded to a peer over the HTTP chunk routes, then put again
//! as a new version from a file, unpublished and published: a few chunks,
//! whatever the blob's size. The peer runs in this process and keeps its
//! objects in a directory, so the count covers it too.
#![allow(unsafe_code)]

use frasil::{Device, Options, PutVersion, Storage};
use frasil_relay::blobs::FileBlobs;
use frasil_relay::testing::{Options as PeerOptions, spawn_with};
use frasil_units::limits::CHUNK_BYTES;
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

struct Counter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), SeqCst) + layout.size();
            PEAK.fetch_max(live, SeqCst);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            LIVE.fetch_sub(layout.size(), SeqCst);
            let live = LIVE.fetch_add(size, SeqCst) + size;
            PEAK.fetch_max(live, SeqCst);
        }
        next
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), SeqCst);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;

/// The blob: 48 chunks and a remainder, about 48 MiB.
const SIZE: usize = 48 * CHUNK_BYTES + 1234;

/// What a put or an upload may hold at once beyond what was live before
/// it: a few chunks, their sealed records, the store's and the HTTP
/// stack's buffers. A third of the blob.
const BOUND: usize = 16 << 20;

/// How long the upload may take.
const DEADLINE: Duration = Duration::from_secs(180);

/// Writes a file of [`SIZE`] bytes from `seed` a piece at a time, so that
/// it is never in memory.
fn write_file(dir: &std::path::Path, name: &str, seed: u8) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    let mut piece = vec![0u8; 1 << 20];
    let mut written = 0;
    while written < SIZE {
        let length = piece.len().min(SIZE - written);
        for (i, byte) in piece[..length].iter_mut().enumerate() {
            *byte = ((written + i) as u8).wrapping_mul(29) ^ ((written + i) >> 16) as u8 ^ seed;
        }
        file.write_all(&piece[..length]).unwrap();
        written += length;
    }
    path
}

/// The growth of the peak over what is live now, while `work` runs.
async fn peak_during<T>(work: impl Future<Output = T>) -> (T, usize) {
    let base = LIVE.load(SeqCst);
    PEAK.store(base, SeqCst);
    let out = work.await;
    (out, PEAK.load(SeqCst).saturating_sub(base))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_blob_is_put_from_a_file_and_uploaded_in_a_few_chunks() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("object-memory-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let path = write_file(&dir, "big.bin", 0);

    let peer = spawn_with(PeerOptions {
        blobs: Some(Arc::new(FileBlobs::open(dir.join("peer")).unwrap())),
        iroh: false,
        ..PeerOptions::default()
    })
    .await
    .unwrap();
    let device = Device::open_with(
        Storage::directory(dir.join("device")),
        &[7; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap();
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();

    // The put: two passes over the file, a few chunks committed at a time.
    let (blob, put) = peak_during(blobs.put_file("big.bin", &path, |_, _| {})).await;
    let blob = blob.unwrap();
    let info = blobs.info(blob).await.unwrap();
    assert_eq!(info.size, SIZE as u64);

    // The upload: slices cut from the store's chunks as they are read.
    let id = *space.id().as_bytes();
    let ((), upload) = peak_during(async {
        device.connect(&peer.origin).await.unwrap();
        let start = Instant::now();
        while !peer.peer.holds_object(&id, &info.object) {
            assert!(
                start.elapsed() < DEADLINE,
                "the peer holds the blob in time"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    eprintln!(
        "a blob of {} MiB: put {} MiB, upload {} MiB at most beyond what was live",
        SIZE >> 20,
        put >> 20,
        upload >> 20
    );
    assert!(put < BOUND, "the put held {put} bytes at once");
    assert!(upload < BOUND, "the upload held {upload} bytes at once");

    // A new version of it from a file, unpublished: kept and named at
    // once, then uploaded as the plain put was.
    let second = write_file(&dir, "second.bin", 1);
    let (version, put) = peak_during(blobs.put_version_file(
        &second,
        &PutVersion::new().named("big.bin").parents(&[blob]),
        |_, _| {},
    ))
    .await;
    let version = version.unwrap();
    let object = blobs.info(version).await.unwrap().object;
    let ((), upload) = peak_during(async {
        let start = Instant::now();
        while !peer.peer.holds_object(&id, &object) {
            assert!(
                start.elapsed() < DEADLINE,
                "the peer holds the version in time"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    eprintln!(
        "a version put from a file: put {} MiB, upload {} MiB",
        put >> 20,
        upload >> 20
    );
    assert!(put < BOUND, "the versioned put held {put} bytes at once");
    assert!(upload < BOUND, "its upload held {upload} bytes at once");

    // Published: the upload comes before the unit, within the put.
    let third = write_file(&dir, "third.bin", 2);
    let (published, put) = peak_during(
        blobs.put_version_file(
            &third,
            &PutVersion::new()
                .named("big.bin")
                .parents(&[version])
                .published(),
            |_, _| {},
        ),
    )
    .await;
    let object = blobs.info(published.unwrap()).await.unwrap().object;
    assert!(peer.peer.holds_object(&id, &object));
    eprintln!(
        "a published version put from a file and uploaded: {} MiB",
        put >> 20
    );
    assert!(put < BOUND, "the published put held {put} bytes at once");
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}
