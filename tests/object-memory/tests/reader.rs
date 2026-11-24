//! Peak live allocations while a blob much larger than a chunk is read
//! through a reader that stores nothing, from a peer over the HTTP chunk
//! routes: the reader's window, which its read-ahead bounds, and what a
//! few transfers hold, whatever the blob's size. Nothing of the blob
//! reaches the device's store. The peer runs in this process and keeps
//! its objects in a directory, so the count covers it too.
#![allow(unsafe_code)]

use frasil::{BlobState, Device, Options, Read, Storage, Verified};
use frasil_relay::blobs::FileBlobs;
use frasil_relay::testing::{Options as PeerOptions, spawn_with};
use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
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

/// What a read may hold at once beyond the reader's window: the chunk
/// opened, the slices of the transfers that run, of which each connection
/// runs four, at the device and at the peer, and the HTTP stack's
/// buffers.
const BESIDE: usize = 14 << 20;

/// How long each step may take.
const DEADLINE: Duration = Duration::from_secs(180);

fn byte(at: usize) -> u8 {
    (at as u8).wrapping_mul(29) ^ (at >> 16) as u8
}

/// Writes a file of [`SIZE`] bytes a piece at a time, so that it is never
/// in memory.
fn write_file(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    let mut piece = vec![0u8; 1 << 20];
    let mut written = 0;
    while written < SIZE {
        let length = piece.len().min(SIZE - written);
        for (i, out) in piece[..length].iter_mut().enumerate() {
            *out = byte(written + i);
        }
        file.write_all(&piece[..length]).unwrap();
        written += length;
    }
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncached_read_of_a_large_blob_holds_its_window_and_no_more() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("object-memory-reader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = write_file(&dir, "big.bin");

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
    let blob = blobs.put_file("big.bin", &path, |_, _| {}).await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    // Once the peer holds it, it is the cache's, and may be dropped.
    let start = Instant::now();
    while blobs.local(blob).await.unwrap().state != BlobState::Cached {
        assert!(
            start.elapsed() < DEADLINE,
            "the peer holds the blob in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    blobs.drop_local(blob).await.unwrap();
    assert_eq!(blobs.local(blob).await.unwrap().bytes, 0);

    for ahead in [8u64, 2] {
        let window = (ahead as usize + 1) * SEALED_CHUNK_BYTES;
        let mut reader = blobs
            .open_reader(blob, &Read::new().uncached())
            .await
            .unwrap();
        reader.set_read_ahead(ahead);
        let base = LIVE.load(SeqCst);
        PEAK.store(base, SeqCst);
        let mut buf = vec![0u8; 64 * 1024];
        let mut at = 0usize;
        let mut most = 0;
        loop {
            let read = tokio::time::timeout(DEADLINE, reader.read_at(at as u64, &mut buf))
                .await
                .expect("in time")
                .unwrap();
            if read == 0 {
                break;
            }
            assert!(
                buf[..read]
                    .iter()
                    .enumerate()
                    .all(|(i, got)| *got == byte(at + i)),
                "the bytes at {at}"
            );
            at += read;
            most = most.max(reader.window_bytes());
            assert!(reader.window_bytes() <= window, "{}", reader.window_bytes());
        }
        let peak = PEAK.load(SeqCst).saturating_sub(base);
        assert_eq!(at, SIZE);
        assert_eq!(reader.verified(), Verified::Whole);
        eprintln!(
            "a blob of {} MiB read with {ahead} chunks ahead: a window of {} MiB at most, \
             {} MiB at most beyond what was live",
            SIZE >> 20,
            most >> 20,
            peak >> 20
        );
        assert!(most > SEALED_CHUNK_BYTES, "the read-ahead ran: {most}");
        assert!(
            peak < window + BESIDE,
            "the read held {peak} bytes at once, with a window of {window}"
        );
        reader.close().await.unwrap();
        // Nothing of it was stored.
        let local = blobs.local(blob).await.unwrap();
        assert_eq!((local.state, local.bytes), (BlobState::Absent, 0));
        assert_eq!(device.blob_cache_usage().await.cached, 0);
    }
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}
