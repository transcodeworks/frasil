//! What a device stores while it reads, one after another, blobs that are
//! together several times its cache's budget: the budget and the blob being
//! read, whatever the number of blobs. The store is a directory, so the
//! bound is measured on the files it holds, beside what the device counts.

use frasil::{BlobState, Device, Level, Options, Read, Storage};
use frasil_relay::testing::{Options as PeerOptions, spawn_with};
use frasil_units::limits::CHUNK_BYTES;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Each blob: eight chunks, about 8 MiB.
const SIZE: usize = 8 * CHUNK_BYTES;

/// How many blobs are read: 80 MiB together.
const BLOBS: u8 = 10;

/// The cache's budget: one blob fits, and not two.
const BUDGET: u64 = 12 << 20;

/// What the store's files may take at most: the budget, the blob a read
/// holds beyond it while it runs, and the store's own pages and log.
/// Less than half of what is read.
const BOUND: u64 = 36 << 20;

const DEADLINE: Duration = Duration::from_secs(300);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Takes a blob's bytes and keeps their count alone.
struct Count(u64);

impl tokio::io::AsyncWrite for Count {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0 += bytes.len() as u64;
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The bytes of the files under a directory.
fn stored(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|file| file.len())
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_reads_many_blobs_stores_its_budget_and_the_one_it_reads() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("object-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let peer = spawn_with(PeerOptions {
        iroh: false,
        ..PeerOptions::default()
    })
    .await
    .unwrap();
    let writer = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback())
        .await
        .unwrap();
    let space = writer.create_space().await.unwrap();
    writer.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();

    let reader = Device::open_with(
        Storage::directory(dir.join("reader")),
        &[2; 32],
        Options::new()
            .loopback()
            .never_restored()
            .blob_cache(BUDGET),
    )
    .await
    .unwrap();
    let joining = within(reader.join_via_peer(&peer.origin, "Reader", |_, _| async { true }))
        .await
        .unwrap();
    within(
        space.admit(joining.text(), Level::Write, "Writer", |_, _| async {
            true
        }),
    )
    .await
    .unwrap();
    let joined = within(joining.joined()).await.unwrap();
    reader.connect(&peer.origin).await.unwrap();

    let mut blobs = Vec::new();
    for index in 0..BLOBS {
        blobs.push(files.put(None, &vec![index; SIZE]).await.unwrap());
    }
    let readers_files = within(async {
        loop {
            if let Ok(blobs) = joined.blobs(files.id()).await
                && blobs
                    .list()
                    .await
                    .is_ok_and(|list| list.len() == usize::from(BLOBS))
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let empty = stored(&dir.join("reader"));

    let mut most_stored = 0;
    let mut most_cached = 0;
    for blob in &blobs {
        let mut count = Count(0);
        within(readers_files.get_stream(*blob, &mut count, &Read::new(), |_, _| {}))
            .await
            .unwrap();
        assert_eq!(count.0, SIZE as u64);
        most_stored = most_stored.max(stored(&dir.join("reader")));
        let usage = reader.blob_cache_usage().await;
        assert!(
            usage.cached <= BUDGET,
            "within the budget once read: {usage:?}"
        );
        assert_eq!(usage.kept, 0);
        most_cached = most_cached.max(usage.cached);
    }
    // The last one read is the one cached.
    let cached: Vec<bool> = {
        let mut cached = Vec::new();
        for blob in &blobs {
            let local = readers_files.local(*blob).await.unwrap();
            cached.push(local.state == BlobState::Cached);
        }
        cached
    };
    assert_eq!(cached.iter().filter(|cached| **cached).count(), 1);
    assert_eq!(cached.last(), Some(&true));

    eprintln!(
        "{} blobs of {} MiB under a budget of {} MiB: the store held {} MiB at most, \
         {} MiB before any, and {} MiB cached",
        BLOBS,
        SIZE >> 20,
        BUDGET >> 20,
        most_stored >> 20,
        empty >> 20,
        most_cached >> 20
    );
    assert!(most_cached > SIZE as u64);
    assert!(
        most_stored < BOUND,
        "the store held {most_stored} bytes of {} read",
        u64::from(BLOBS) * SIZE as u64
    );
    let _ = std::fs::remove_dir_all(&dir);
}
