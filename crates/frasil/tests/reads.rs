//! Reads for applications that cache: change feeds that say what changed,
//! observed reads, waiting for what has not arrived, a blob's status, range
//! reads of blobs and rows, and receipts, on one device. Two devices
//! through a peer are in `tests/conformance/tests/client_reads.rs`.
#![cfg(all(
    feature = "adapter-records",
    feature = "adapter-blobs",
    feature = "adapter-loro",
    feature = "sqlite"
))]

use frasil::{
    BlobChange, BlobStatus, Device, Error, Origin, RecordChange, Status, Storage, StreamId,
};
use std::future::Future;
use std::time::Duration;

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("within the deadline")
}

/// Whether `future` stays pending for a moment.
async fn stays_pending<T>(future: impl Future<Output = T>) -> bool {
    tokio::time::timeout(Duration::from_millis(300), future)
        .await
        .is_err()
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("reads-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn a_records_feed_names_the_rows_a_write_touched() {
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    let mut changes = records.changes();
    let mut space_changes = space.changes();
    records
        .write(|tx| {
            tx.insert("tasks", b"b")
                .set("tasks", b"b", "title", "B")
                .insert("tasks", b"a")
                .insert("lists", b"l");
        })
        .await
        .unwrap();
    let mut seen = vec![
        within(changes.next()).await.unwrap().unwrap(),
        within(changes.next()).await.unwrap().unwrap(),
    ];
    seen.sort_by_key(|change| format!("{change:?}"));
    assert_eq!(
        seen,
        vec![
            RecordChange::Rows {
                table: "lists".into(),
                keys: vec![b"l".to_vec()],
                origin: Origin::Local,
            },
            RecordChange::Rows {
                table: "tasks".into(),
                keys: vec![b"a".to_vec(), b"b".to_vec()],
                origin: Origin::Local,
            },
        ]
    );
    let change = within(space_changes.next()).await.unwrap().unwrap();
    assert_eq!(change.origin, Origin::Local);
    assert!(change.streams.contains(&records.id()));

    // Another stream's write is not this feed's.
    let other = space.create_records().unwrap();
    other
        .write(|tx| {
            tx.insert("tasks", b"x");
        })
        .await
        .unwrap();
    assert!(stays_pending(changes.next()).await);
}

#[tokio::test]
async fn an_observed_table_tells_only_when_its_rows_differ() {
    let device = Device::open(Storage::Memory, &[2; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            tx.insert("tasks", b"a").set("tasks", b"a", "done", false);
        })
        .await
        .unwrap();
    let mut tasks = records.observe_rows("tasks");
    let first = within(tasks.ready()).await.unwrap();
    assert_eq!(first.len(), 1);
    assert!(tasks.get().is_ready());

    // Another observer of the same table shares the reader and its value.
    let again = records.observe_rows("tasks");
    let shared = again.get().value.unwrap();
    assert!(std::sync::Arc::ptr_eq(&shared, &tasks.get().value.unwrap()));

    // A write to another table changes nothing these rows show.
    records
        .write(|tx| {
            tx.insert("lists", b"l");
        })
        .await
        .unwrap();
    assert!(stays_pending(tasks.changed()).await);

    // Several writes in a row read as one change or more, each different,
    // and the last shows them all.
    for key in [b"b", b"c", b"d"] {
        records
            .write(|tx| {
                tx.insert("tasks", key);
            })
            .await
            .unwrap();
    }
    let latest = within(async {
        loop {
            let seen = tasks.changed().await.unwrap();
            if seen.value.as_ref().is_some_and(|rows| rows.len() == 4) {
                break seen;
            }
        }
    })
    .await;
    assert_eq!(latest.status, Status::Ready);

    // One row.
    let mut row = records.observe_row("tasks", b"a");
    within(row.ready()).await.unwrap();
    records
        .write(|tx| {
            tx.set("tasks", b"a", "done", true);
        })
        .await
        .unwrap();
    let done = within(row.changed()).await.unwrap();
    assert_eq!(
        done.value.unwrap().as_ref().as_ref().unwrap()["done"].as_bool(),
        Ok(true)
    );
}

#[tokio::test]
async fn what_has_not_arrived_is_loading_not_an_error() {
    let device = Device::open(Storage::Memory, &[3; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let unknown = StreamId::from_bytes([7; 16]);
    let observed = space
        .observe(move |space| async move { space.records(unknown).await?.rows("tasks").await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let now = observed.get();
    assert_eq!(now.status, Status::Loading);
    assert!(now.value.is_none() && now.error.is_none());

    assert_eq!(
        space
            .document_when_available(unknown, Duration::from_millis(100))
            .await
            .unwrap_err(),
        Error::Timeout
    );
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hi"))
        .await
        .unwrap();
    let found = within(space.document_when_available(note.id(), Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(found.text("body").await.unwrap(), "hi");

    // A document observed through a read of it.
    let mut body = note.observe(|doc| doc.get_text("body").to_string());
    assert_eq!(*within(body.ready()).await.unwrap(), "hi");
    note.edit(|doc| doc.get_text("body").insert(2, "!"))
        .await
        .unwrap();
    assert_eq!(*within(body.changed()).await.unwrap().value.unwrap(), "hi!");
}

#[tokio::test]
async fn rows_read_by_range_and_by_prefix() {
    let device = Device::open(Storage::Memory, &[4; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            for key in ["a/1", "a/2", "a/3", "b/1", "c/1"] {
                tx.insert("t", key.as_bytes())
                    .set("t", key.as_bytes(), "n", key);
            }
            tx.insert("t", b"a/9");
        })
        .await
        .unwrap();
    records
        .write(|tx| {
            tx.delete("t", b"a/9");
        })
        .await
        .unwrap();
    let keys = |rows: Vec<(Vec<u8>, frasil::Row)>| {
        rows.into_iter()
            .map(|(key, _)| String::from_utf8(key).unwrap())
            .collect::<Vec<_>>()
    };
    let first = records.rows_range("t", None, 2).await.unwrap();
    assert_eq!(keys(first.clone()), ["a/1", "a/2"]);
    let next = records
        .rows_range("t", Some(&first[1].0), 10)
        .await
        .unwrap();
    assert_eq!(keys(next), ["a/3", "b/1", "c/1"]);
    let prefixed = records.rows_with_prefix("t", b"a/").await.unwrap();
    assert_eq!(
        prefixed.keys().cloned().collect::<Vec<_>>(),
        [b"a/1".to_vec(), b"a/2".to_vec(), b"a/3".to_vec()]
    );
    assert_eq!(prefixed[&b"a/2"[..]]["n"], frasil::Value::from("a/2"));
    assert!(
        records
            .rows_range("none", None, 5)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_receipt_names_its_change_and_waits_for_a_peer() {
    let device = Device::open(Storage::Memory, &[5; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    let receipt = records
        .write_with_receipt(|tx| {
            tx.insert("t", b"r");
        })
        .await
        .unwrap();
    let history = records.history().await.unwrap();
    assert_eq!(history.last().unwrap().id, receipt.unit());
    // No peer holds it.
    assert!(!receipt.is_durable().await);
    assert!(matches!(
        receipt.durable(Duration::from_millis(60)).await,
        Err(Error::Connection(_))
    ));
    let note = space.create_document().unwrap();
    let edited = note
        .edit_with_receipt(|doc| doc.get_text("t").insert(0, "x"))
        .await
        .unwrap();
    assert_ne!(edited.unit(), receipt.unit());
}

#[tokio::test]
async fn a_blob_feed_names_puts_and_removals_and_a_status_reads() {
    let device = Device::open(Storage::Memory, &[6; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let first = blobs.put(Some("a"), b"one").await.unwrap();
    let mut changes = within(blobs.changes()).await.unwrap();
    let mut list = blobs.observe_list();
    assert_eq!(within(list.ready()).await.unwrap().len(), 1);
    let second = blobs.put(Some("b"), b"two").await.unwrap();
    assert_eq!(
        within(changes.next()).await.unwrap().unwrap(),
        BlobChange::Added {
            id: second,
            origin: Origin::Local
        }
    );
    assert_eq!(
        within(list.changed()).await.unwrap().value.unwrap().len(),
        2
    );
    blobs.remove(first).await.unwrap();
    assert_eq!(
        within(changes.next()).await.unwrap().unwrap(),
        BlobChange::Removed {
            id: first,
            origin: Origin::Local
        }
    );
    assert_eq!(blobs.status(second).await.unwrap(), BlobStatus::Readable);
    let status = blobs.observe_status(second);
    assert_eq!(
        *within(status.clone().ready()).await.unwrap(),
        BlobStatus::Readable
    );
    assert_eq!(
        within(blobs.get_when_available(second, Duration::from_secs(1)))
            .await
            .unwrap(),
        b"two"
    );
    assert!(blobs.status(first).await.is_err(), "removed");
}

/// Blobs of one, two and three chunks, and a range across each chunk
/// boundary, read the same through `get`, `get_stream` and `get_range`,
/// from a store that keeps them sealed in chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blobs_read_whole_streamed_and_by_range_alike() {
    const CHUNK: usize = 1_048_536;
    let dir = temp_dir("ranges");
    let device = Device::open(Storage::directory(&dir), &[7; 32])
        .await
        .unwrap();
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    for size in [0, 5, CHUNK, CHUNK + 1, 2 * CHUNK + 5] {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let id = blobs.put(None, &bytes).await.unwrap();
        // Read back from the store, not from what the put kept.
        let reopened = blobs.get(id, &frasil::Read::new()).await.unwrap().unwrap();
        assert_eq!(reopened, bytes);
        let mut streamed = Vec::new();
        let mut progress = Vec::new();
        blobs
            .get_stream(id, &mut streamed, &frasil::Read::new(), |done, total| {
                progress.push((done, total))
            })
            .await
            .unwrap();
        assert_eq!(streamed, bytes);
        assert_eq!(progress.last(), Some(&(size as u64, Some(size as u64))));
        let size = size as u64;
        let ranges = [
            (0, 3),
            (0, size),
            (CHUNK as u64 - 2, 4),
            (CHUNK as u64, 10),
            (2 * CHUNK as u64 - 1, 3),
            (size.saturating_sub(1), 10),
            (size, 1),
            (size + 10, 1),
        ];
        for (offset, len) in ranges {
            let read = blobs
                .get_range(id, offset, len, &frasil::Read::new())
                .await
                .unwrap()
                .unwrap();
            let start = (offset as usize).min(bytes.len());
            let end = (offset.saturating_add(len) as usize).min(bytes.len());
            assert_eq!(read, bytes[start..end], "{size} bytes, {offset}+{len}");
        }
    }
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

/// After the device opens again, a blob it stores is found in the store by
/// its ID alone, and reads by range, streamed and whole as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_reads_by_range_and_streamed_after_the_device_opens_again() {
    const CHUNK: usize = 1_048_536;
    let dir = temp_dir("reopened");
    let bytes: Vec<u8> = (0..3 * CHUNK + 11).map(|i| (i % 249) as u8).collect();
    let (space, stream, id) = {
        let device = Device::open(Storage::directory(&dir), &[7; 32])
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        let blobs = space.create_blobs().unwrap();
        let id = blobs.put(None, &bytes).await.unwrap();
        (space.id(), blobs.id(), id)
    };
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
    let offset = 2 * CHUNK as u64 - 5;
    let range = blobs
        .get_range(id, offset, 10, &frasil::Read::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(range, bytes[offset as usize..offset as usize + 10]);
    let mut streamed = Vec::new();
    blobs
        .get_stream(id, &mut streamed, &frasil::Read::new(), |_, _| {})
        .await
        .unwrap();
    assert_eq!(streamed, bytes);
    assert_eq!(
        blobs.get(id, &frasil::Read::new()).await.unwrap().unwrap(),
        bytes
    );
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "ext-drive")]
#[tokio::test]
async fn a_drive_change_says_where_it_was_made_and_a_drive_observes() {
    let device = Device::open(Storage::Memory, &[8; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let mut changes = drive.changes().await.unwrap();
    let mut entries = drive.observe();
    assert!(within(entries.ready()).await.unwrap().is_empty());
    let (folder, receipt) = drive
        .batch_with_receipt(|batch| batch.add_folder(None, "Docs"))
        .await
        .unwrap();
    assert!(receipt.is_some());
    let change = within(changes.next()).await.unwrap();
    assert_eq!(change.entries, vec![folder]);
    assert_eq!(change.origin, Origin::Local);
    assert_eq!(
        within(entries.changed())
            .await
            .unwrap()
            .value
            .unwrap()
            .len(),
        1
    );
    // A write to another stream of the space is not the drive's change.
    space
        .create_records()
        .unwrap()
        .write(|tx| {
            tx.insert("t", b"r");
        })
        .await
        .unwrap();
    assert!(stays_pending(changes.next()).await);
    // A batch that makes no operation writes nothing, and has no receipt.
    let ((), none) = drive.batch_with_receipt(|_| Ok(())).await.unwrap();
    assert!(none.is_none());
}

/// An observer asked for from a thread outside the runtime, as an
/// interface's, still reads on the runtime the device opened in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_observer_from_another_thread_reads_on_the_device_runtime() {
    let device = Device::open(Storage::Memory, &[9; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            tx.insert("t", b"r");
        })
        .await
        .unwrap();
    let observed = std::thread::spawn(move || records.observe_rows("t"))
        .join()
        .unwrap();
    assert_eq!(within(observed.clone().ready()).await.unwrap().len(), 1);
}

/// A feed that falls far behind the device says so: the space's feed lists
/// every stream with its space events, and a Records feed asks for all
/// rows to be read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feed_that_falls_behind_says_so() {
    let device = Device::open(Storage::Memory, &[10; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    let mut rows = records.changes();
    let mut changes = space.changes();
    // More writes than a feed keeps while nobody reads it.
    for k in 0..1100u32 {
        records
            .write(|tx| {
                tx.insert("t", &k.to_be_bytes());
            })
            .await
            .unwrap();
    }
    assert_eq!(
        within(rows.next()).await.unwrap().unwrap(),
        RecordChange::All
    );
    let behind = within(changes.next()).await.unwrap().unwrap();
    assert!(behind.space_events && behind.members);
    assert_eq!(behind.origin, Origin::Remote);
    assert!(behind.streams.contains(&records.id()));
}
