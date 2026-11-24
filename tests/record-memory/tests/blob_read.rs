//! Peak live allocations while reading a blob much larger than a chunk
//! back from a device's store: streamed whole, by range before and after
//! the whole object was checked, and hashed. Each holds a few chunks.
#![allow(unsafe_code)]
use frasil::{Device, Storage};
use std::alloc::{GlobalAlloc, Layout, System};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::task::{Context, Poll};

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

const CHUNK: usize = 1_048_536;

/// The blob: 48 chunks and a bit, about 50 MB.
const SIZE: usize = 48 * CHUNK + 1234;

/// What a read may hold at once: a batch of eight chunks, sealed and
/// opened, with the store's buffers. A fraction of the blob.
const BOUND: usize = 24 * 1024 * 1024;

/// The blob's byte at `i`.
fn byte(i: usize) -> u8 {
    (i % 251) as u8 ^ (i / 251 % 7) as u8
}

/// A writer that checks what it is given against the blob, and keeps
/// none of it.
struct Check {
    at: usize,
}

impl tokio::io::AsyncWrite for Check {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, byte(self.at + i), "byte {}", self.at + i);
        }
        self.at += buf.len();
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs `read` and returns the most bytes it held live at once, beyond
/// what was live before.
async fn peak_of<T>(read: impl std::future::Future<Output = T>) -> (T, usize) {
    let baseline = LIVE.load(SeqCst);
    PEAK.store(baseline, SeqCst);
    let out = read.await;
    (out, PEAK.load(SeqCst).saturating_sub(baseline))
}

#[tokio::test(flavor = "current_thread")]
async fn a_large_blob_reads_back_in_a_few_chunks_of_memory() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("blob-read-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (space, stream, id) = {
        let device = Device::open(Storage::directory(&dir), &[7; 32])
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        let blobs = space.create_blobs().unwrap();
        let bytes: Vec<u8> = (0..SIZE).map(byte).collect();
        let id = blobs.put(None, &bytes).await.unwrap();
        (space.id(), blobs.id(), id)
    };
    // Opened again, the device finds the blob in its store by ID alone,
    // its bytes not yet hashed nor opened this session.
    let device = Device::open(Storage::directory(&dir), &[7; 32])
        .await
        .unwrap();
    let blobs = device
        .space(space)
        .await
        .unwrap()
        .blobs(stream)
        .await
        .unwrap();

    // A range before any whole read: every step runs on the whole object
    // first, keeping only the chunks of the range.
    let offset = 30 * CHUNK - 100;
    let (range, peak) =
        peak_of(blobs.get_range(id, offset as u64, 300, &frasil::Read::new())).await;
    let range = range.unwrap().unwrap();
    assert!(
        range
            .iter()
            .enumerate()
            .all(|(i, b)| *b == byte(offset + i))
    );
    assert!(peak < BOUND, "first range read: peak {peak}");

    // A range once the object was checked: only its chunks.
    let (range, peak) =
        peak_of(blobs.get_range(id, 5, 2 * CHUNK as u64, &frasil::Read::new())).await;
    let range = range.unwrap().unwrap();
    assert!(range.iter().enumerate().all(|(i, b)| *b == byte(5 + i)));
    assert!(peak < BOUND, "second range read: peak {peak}");

    // The whole blob streamed out, without holding it.
    let mut check = Check { at: 0 };
    let (streamed, peak) =
        peak_of(blobs.get_stream(id, &mut check, &frasil::Read::new(), |_, _| {})).await;
    streamed.unwrap();
    assert_eq!(check.at, SIZE);
    assert!(peak < BOUND, "stream: peak {peak}");

    let (hash, peak) = peak_of(blobs.content_hash(id, &frasil::Read::new())).await;
    assert!(hash.unwrap().is_some());
    assert!(peak < BOUND, "content hash: peak {peak}");

    drop(blobs);
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}
