//! File versions and retention (ext-file-versions.md) through a client and a
//! peer on loopback, on the peer's manual clock: what a save supersedes is
//! collected on time, and a head never is, whether it is the current
//! version, a side of an open conflict, or a second file with the same
//! bytes.

#![cfg(all(feature = "ext-file-versions", feature = "ext-drive"))]

use frasil::advanced::platform::ManualClock;
use frasil::{BlobId, Blobs, Device, DriveFile, Options, PutVersion, Space, Storage};
use frasil_events::EventId;
use frasil_relay::Settings;
use frasil_relay::testing::{Options as PeerOptions, TestPeer, spawn_with};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);
const DAY: u64 = 86_400;
/// Past T, so every superseding unit counts, stable at the peer or not.
const PAST_T: u64 = 8 * DAY;

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn peer(settings: Settings) -> TestPeer {
    spawn_with(PeerOptions {
        settings,
        ..frasil_conformance::options()
    })
    .await
    .unwrap()
}

/// A peer that keeps five versions of a file, and old versions for a
/// year, so only the count collects.
async fn counting_peer() -> TestPeer {
    peer(Settings {
        max_file_versions: 5,
        file_version_retention: 365 * DAY,
        ..frasil_conformance::settings()
    })
    .await
}

fn event(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// Waits until the peer stored and acknowledged this device's events.
async fn durable(device: &Device, space: &Space) {
    within(async {
        while !device.engine().outbox(&event(space)).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

struct Saved {
    id: BlobId,
    object: [u8; 64],
}

async fn save(files: &Blobs, bytes: &[u8], parents: &[BlobId]) -> Saved {
    let id = files
        .put_version(bytes, &PutVersion::new().parents(parents))
        .await
        .unwrap();
    let object = files.info(id).await.unwrap().object;
    Saved { id, object }
}

fn stored(peer: &TestPeer, space: &Space, saved: &Saved) -> bool {
    peer.peer.holds_object(space.id().as_bytes(), &saved.object)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_count_a_superseded_object_goes_and_the_head_stays() {
    let peer = counting_peer().await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let mut versions: Vec<Saved> = Vec::new();
    for i in 0..7 {
        let parents: Vec<BlobId> = versions.last().map(|v| v.id).into_iter().collect();
        let bytes = format!("version {i}");
        versions.push(save(&files, bytes.as_bytes(), &parents).await);
    }
    durable(&alice, &space).await;
    assert!(versions.iter().all(|v| stored(&peer, &space, v)));

    // Within T nothing is collected: a removed writer's save must not count.
    peer.advance(DAY).await;
    assert!(versions.iter().all(|v| stored(&peer, &space, v)));

    // Past T, five stay: the head and the four beneath it.
    peer.advance(PAST_T).await;
    let kept: Vec<bool> = versions.iter().map(|v| stored(&peer, &space, v)).collect();
    assert_eq!(kept, [false, false, true, true, true, true, true]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_retention_only_the_head_stays() {
    let peer = peer(frasil_conformance::settings()).await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let first = save(&files, b"first", &[]).await;
    let second = save(&files, b"second", &[first.id]).await;
    durable(&alice, &space).await;
    peer.advance(PAST_T).await;
    assert!(!stored(&peer, &space, &first));
    assert!(stored(&peer, &space, &second));
    // A year on, the head is still there.
    peer.advance(365 * DAY).await;
    assert!(stored(&peer, &space, &second));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_side_of_an_open_conflict_stays_until_it_is_resolved() {
    let peer = peer(frasil_conformance::settings()).await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let files = space.create_blobs().unwrap();

    let base = save(&files, b"base", &[]).await;
    let entry = drive
        .add_file(None, "plan.txt", &DriveFile::new(files.id(), base.id))
        .await
        .unwrap();
    let ours = save(&files, b"ours", &[base.id]).await;
    drive
        .set_blob(entry, &DriveFile::new(files.id(), ours.id), &[base.id])
        .await
        .unwrap();
    let theirs = save(&files, b"theirs", &[base.id]).await;
    drive
        .set_blob(entry, &DriveFile::new(files.id(), theirs.id), &[base.id])
        .await
        .unwrap();
    assert_eq!(drive.conflicts().await.unwrap().len(), 1);
    durable(&alice, &space).await;

    peer.advance(PAST_T).await;
    assert!(!stored(&peer, &space, &base), "the common parent goes");
    assert!(stored(&peer, &space, &ours), "a side of the conflict stays");
    assert!(stored(&peer, &space, &theirs), "and the other");

    // A pick puts one side's bytes again: the old listing is superseded,
    // the new one is the head, and the object stays.
    let pick = save(&files, b"ours", &[ours.id, theirs.id]).await;
    assert_eq!(pick.object, ours.object);
    drive
        .set_blob(
            entry,
            &DriveFile::new(files.id(), pick.id),
            &[ours.id, theirs.id],
        )
        .await
        .unwrap();
    assert!(drive.conflicts().await.unwrap().is_empty());
    durable(&alice, &space).await;
    peer.advance(PAST_T).await;
    assert!(stored(&peer, &space, &pick), "the pick stays");
    assert!(!stored(&peer, &space, &theirs), "the side not picked goes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_file_with_the_same_bytes_stays() {
    let peer = peer(frasil_conformance::settings()).await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let old = save(&files, b"shared bytes", &[]).await;
    let other_file = save(&files, b"shared bytes", &[]).await;
    assert_eq!(old.object, other_file.object);
    save(&files, b"newer", &[old.id]).await;
    durable(&alice, &space).await;
    peer.advance(PAST_T).await;
    assert!(stored(&peer, &space, &other_file));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compaction_carries_the_links_forward() {
    let peer = peer(frasil_conformance::settings()).await;
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let first = save(&files, b"first", &[]).await;
    let second = save(&files, b"second", &[first.id]).await;
    durable(&alice, &space).await;

    // The snapshot replaces the log units: the listing that goes on being
    // superseded is its own.
    alice
        .engine()
        .compact(event(&space), *files.id().as_bytes())
        .await
        .unwrap();
    durable(&alice, &space).await;
    assert!(stored(&peer, &space, &first));
    peer.advance(PAST_T).await;
    assert!(!stored(&peer, &space, &first), "the carried link collects");
    assert!(stored(&peer, &space, &second), "the head stays");

    // Nothing is left to compact on the cadence but what comes after.
    let third = save(&files, b"third", &[second.id]).await;
    durable(&alice, &space).await;
    peer.advance(PAST_T).await;
    assert!(stored(&peer, &space, &third));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_compacts_on_its_cadence_once_a_unit_supersedes() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_792_000_000)));
    let alice = Device::open_with(
        Storage::Memory,
        &[1; 32],
        Options::new().loopback().clock(clock.clone()),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let files = space.create_blobs().unwrap();
    let first = save(&files, b"first", &[]).await;

    // Nothing to do without a supersession, however long it has been.
    clock.advance(2 * DAY);
    assert!(alice.engine().compact_versions(DAY).await.is_empty());

    save(&files, b"second", &[first.id]).await;
    clock.advance(DAY - 1);
    assert!(alice.engine().compact_versions(DAY).await.is_empty());
    clock.advance(1);
    assert_eq!(alice.engine().compact_versions(DAY).await.len(), 1);

    // The snapshot's cover holds that unit: nothing is due again.
    clock.advance(2 * DAY);
    assert!(alice.engine().compact_versions(DAY).await.is_empty());
}

#[cfg(feature = "ext-libraries")]
mod holds {
    use super::*;
    use frasil_libraries::LibraryId;
    use frasil_relay::libraries::LibrarySettings;
    use frasil_relay::testing::OPEN_LIBRARY;

    /// A reference to an old version goes with the version, and a reference
    /// to the current one keeps it (ext-file-versions.md, 3.9).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_hold_ends_with_the_version_it_refers_to() {
        let peer = peer(Settings {
            libraries: LibrarySettings {
                open_library: LibraryId::new(OPEN_LIBRARY).ok(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        })
        .await;
        let alice = device(1).await;
        let bank = alice.create_space().await.unwrap();
        let show = alice.create_space().await.unwrap();
        alice.connect(&peer.origin).await.unwrap();
        let bank_files = bank.create_blobs().unwrap();
        let old = bank_files.put(None, b"an old cut").await.unwrap();
        let kept = bank_files.put(None, b"the final cut").await.unwrap();
        let old_object = bank_files.info(old).await.unwrap().object;
        let kept_object = bank_files.info(kept).await.unwrap().object;
        durable(&alice, &bank).await;

        let show_files = show.create_blobs().unwrap();
        let reference = within(show_files.reference_from(&bank_files, old))
            .await
            .unwrap();
        within(show_files.reference_from(&bank_files, kept))
            .await
            .unwrap();
        save(&show_files, b"a newer cut", &[reference]).await;
        durable(&alice, &show).await;

        // The bank lets its two files go.
        bank_files.remove(old).await.unwrap();
        bank_files.remove(kept).await.unwrap();
        durable(&alice, &bank).await;
        alice
            .engine()
            .compact(event(&bank), *bank_files.id().as_bytes())
            .await
            .unwrap();
        durable(&alice, &bank).await;
        let bank_id = bank.id();
        let held = |object: &[u8; 64]| peer.peer.holds_object(bank_id.as_bytes(), object);
        assert!(held(&old_object) && held(&kept_object));

        peer.advance(PAST_T).await;
        assert!(held(&kept_object), "a hold on a current version keeps it");
        peer.advance(PAST_T).await;
        assert!(!held(&old_object), "a hold on an old version ends with it");
        assert!(held(&kept_object));
    }
}
