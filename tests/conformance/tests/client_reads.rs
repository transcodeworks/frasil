//! Reads for applications that cache, between two devices through a peer
//! on loopback: feeds say a change came from elsewhere and a blob arrived,
//! a wait returns once what it waits for arrives, and an observed read goes
//! from loading to ready. Every wait has a deadline.

use frasil::{
    BlobChange, BlobStatus, Device, Level, Options, Origin, RecordChange, Status, Storage,
};
use frasil_conformance::spawn_loopback;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feeds_waits_and_observed_reads_follow_another_device() {
    let peer = spawn_loopback().await.unwrap();
    let open = |key| async move {
        Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
            .await
            .expect("a device")
    };
    let alice = open(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let records = space.create_records().unwrap();
    let files = space.create_blobs().unwrap();
    let note = space.create_document().unwrap();

    let bob = open(2).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();

    // Bob observes a table he does not hold yet: loading, then ready.
    let id = records.id();
    let mut observed = bobs_space
        .observe(move |space| async move { space.records(id).await?.rows("tasks").await });
    assert_eq!(observed.get().status, Status::Loading);

    records
        .write(|tx| {
            tx.insert("tasks", b"t1");
        })
        .await
        .unwrap();
    let rows = within(observed.ready()).await.unwrap();
    assert!(rows.contains_key(&b"t1"[..]));

    // Bob's own feeds hear Alice's next write as remote.
    let bobs_records = within(bobs_space.records_when_available(id, DEADLINE))
        .await
        .unwrap();
    let mut changes = bobs_records.changes();
    let mut space_changes = bobs_space.changes();
    records
        .write(|tx| {
            tx.insert("tasks", b"t2");
        })
        .await
        .unwrap();
    assert_eq!(
        within(changes.next()).await.unwrap().unwrap(),
        RecordChange::Rows {
            table: "tasks".into(),
            keys: vec![b"t2".to_vec()],
            origin: Origin::Remote,
        }
    );
    let change = within(async {
        loop {
            let change = space_changes.next().await.unwrap().unwrap();
            if change.streams.contains(&id) {
                break change;
            }
        }
    })
    .await;
    assert_eq!(change.origin, Origin::Remote);

    // A document Bob waits for arrives.
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    let bobs_note = within(bobs_space.document_when_available(note.id(), DEADLINE))
        .await
        .unwrap();
    assert_eq!(
        within(async {
            loop {
                let text = bobs_note.text("body").await.unwrap();
                if !text.is_empty() {
                    break text;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await,
        "hello"
    );

    // A blob: Bob hears it added from elsewhere, then arrived, and reads
    // it once it has.
    files.put(Some("first"), b"first").await.unwrap();
    let bobs_files = within(bobs_space.blobs_when_available(files.id(), DEADLINE))
        .await
        .unwrap();
    let mut blob_changes = within(bobs_files.changes()).await.unwrap();
    let bytes: Vec<u8> = (0..3_000_000).map(|i| (i % 253) as u8).collect();
    let big = files.put(Some("big"), &bytes).await.unwrap();
    let mut added = false;
    let mut arrived = false;
    within(async {
        while !arrived {
            match blob_changes.next().await.unwrap().unwrap() {
                BlobChange::Added { id, origin } if id == big => {
                    assert_eq!(origin, Origin::Remote);
                    added = true;
                }
                BlobChange::Arrived { id } if id == big => arrived = true,
                _ => {}
            }
        }
    })
    .await;
    assert!(added, "added before it arrived, or with it");
    assert_eq!(bobs_files.status(big).await.unwrap(), BlobStatus::Readable);
    assert_eq!(
        within(bobs_files.get_when_available(big, DEADLINE))
            .await
            .unwrap(),
        bytes
    );
    assert_eq!(
        bobs_files
            .get_range(big, 1_048_530, 20)
            .await
            .unwrap()
            .unwrap(),
        bytes[1_048_530..1_048_550]
    );
    peer.shutdown().await;
}
