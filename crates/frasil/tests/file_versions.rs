//! File versions (ext-file-versions.md) at a device: one that starts from
//! a space snapshot gets the supersession set in the stream entry, so a
//! compaction of its own carries the pairs the first compactor's did; and a
//! superseding unit it refuses is reported to the application.
#![cfg(feature = "ext-file-versions")]

use frasil::{Device, Event, Options, PutVersion, Storage};
use frasil_events::{EventId, kind};
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::Unit;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

/// The supersessions of a snapshot unit, as the device holds it.
async fn key_8(device: &Device, space: &EventId, id: EventId) -> Vec<frasil_adapter::Supersession> {
    device
        .engine()
        .events(space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == kind::UNIT && event.id() == id)
        .filter_map(|event| Unit::from_event(event).ok())
        .map(|unit| {
            assert!(unit.is_snapshot());
            unit.body.supersedes
        })
        .next()
        .expect("the snapshot unit")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_newcomer_from_a_space_snapshot_compacts_with_the_same_pairs() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    let files = space.create_blobs().unwrap();
    let stream = *files.id().as_bytes();
    let first = files
        .put_version(b"first", &PutVersion::new())
        .await
        .unwrap();
    files
        .put_version(b"second", &PutVersion::new().parents(&[first]))
        .await
        .unwrap();
    let compacted = alice.engine().compact(id, stream).await.unwrap();
    let pairs = key_8(&alice, &id, compacted).await;
    assert_eq!(pairs.len(), 1, "the second version supersedes the first");

    // Bob joins from now on: he holds no unit of the stream's cover.
    let admitting = alice
        .engine()
        .grant_device(
            id,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice
        .engine()
        .newcomer_snapshot(&id, admitting)
        .await
        .unwrap();
    bob.engine()
        .adopt_snapshot(id, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    let frame: Vec<Vec<u8>> = alice
        .engine()
        .events(&id)
        .await
        .into_iter()
        .filter(|signed| frasil_events::decode(signed).is_ok_and(|e| e.kind() != kind::UNIT))
        .collect();
    bob.engine().ingest(id, frame).await.unwrap();

    // A write of his own, then a compaction over it: the old version stays
    // superseded.
    let bob_files = bob
        .space(space.id())
        .await
        .unwrap()
        .blobs(files.id())
        .await
        .unwrap();
    bob_files
        .put_version(b"another file", &PutVersion::new())
        .await
        .unwrap();
    let again = bob.engine().compact(id, stream).await.unwrap();
    assert_eq!(key_8(&bob, &id, again).await, pairs);
}

/// ext-file-versions.md, 3.10: a removed writer's save, concurrent with its
/// removal, is refused, and the application learns which current blobs a
/// peer may collect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_superseding_unit_is_reported() {
    let alice = device(3).await;
    let bob = device(4).await;
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    alice
        .engine()
        .grant_device(
            id,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(id).await;
    let files = space.create_blobs().unwrap();
    let first = files
        .put_version(b"first", &PutVersion::new())
        .await
        .unwrap();
    bob.engine()
        .ingest(id, alice.engine().events(&id).await)
        .await
        .unwrap();

    // Bob saves a new version while Alice removes him.
    let bob_files = bob
        .space(space.id())
        .await
        .unwrap()
        .blobs(files.id())
        .await
        .unwrap();
    bob_files
        .put_version(b"second", &PutVersion::new().parents(&[first]))
        .await
        .unwrap();
    let mut events = alice.events();
    space.remove(bob.id()).await.unwrap();
    alice
        .engine()
        .ingest(id, bob.engine().events(&id).await)
        .await
        .unwrap();
    let reported = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let Some(Event::SupersessionRefused {
                space: at,
                stream,
                blobs,
                ..
            }) = events.next().await
            {
                return (at, stream, blobs);
            }
        }
    })
    .await
    .expect("reported");
    assert_eq!(reported, (space.id(), files.id(), vec![first]));
}

/// The supersessions of the last unit of a stream in the device's log.
async fn latest_supersessions(
    device: &Device,
    space: &EventId,
    stream: frasil_units::stream::StreamId,
) -> Vec<frasil_adapter::Supersession> {
    device
        .engine()
        .events(space)
        .await
        .into_iter()
        .rev()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == kind::UNIT)
        .filter_map(|event| Unit::from_event(event).ok())
        .find(|unit| unit.body.stream == stream)
        .expect("a unit of the stream")
        .body
        .supersedes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_put_from_a_file_or_a_seekable_source_supersedes_its_parents() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    let files = space.create_blobs().unwrap();
    let stream = *files.id().as_bytes();
    let dir = std::env::temp_dir().join(format!("frasil-versions-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("first.bin");
    std::fs::write(&path, b"first, from a file").unwrap();

    let first = files
        .put_version_file(&path, &PutVersion::new().named("notes.txt"), |_, _| {})
        .await
        .unwrap();
    assert!(latest_supersessions(&alice, &id, stream).await.is_empty());
    let second = files
        .put_version_seekable(
            std::io::Cursor::new(b"second, from a seekable source".to_vec()),
            &PutVersion::new().named("notes.txt").parents(&[first]),
            |_, _| {},
        )
        .await
        .unwrap();
    let supersedes = latest_supersessions(&alice, &id, stream).await;
    assert_eq!(
        supersedes.len(),
        1,
        "the second version supersedes the first"
    );
    let info = files.info(second).await.unwrap();
    assert_eq!(info.name.as_deref(), Some("notes.txt"));
    assert_eq!(
        files
            .get(second, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&b"second, from a seekable source"[..])
    );

    // Published, with no peer: nothing reaches the stream.
    let refused = files
        .put_version_file(
            &path,
            &PutVersion::new().parents(&[second]).published(),
            |_, _| {},
        )
        .await;
    assert!(
        matches!(refused, Err(frasil::Error::Class("Missing"))),
        "{refused:?}"
    );
    assert_eq!(files.list().await.unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}
