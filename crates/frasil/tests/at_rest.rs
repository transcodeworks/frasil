//! The device at rest: the SQLite store, and a restore found by the mark
//! (at-rest.md, "Continuity", "After a restore").
#![cfg(feature = "adapter-loro")]

use frasil::Error;
use frasil::advanced::{AdapterRegistry, Continuity, Engine, Platform};
use frasil_space::{HistoryMode, Level, Via};
use frasil_store::{Commit, DeviceBoundSlot, MemorySlot, MemoryStore, Store};
use std::sync::Arc;

/// Every record a store holds: a backup of it.
async fn backup(store: &dyn Store) -> Vec<(Vec<u8>, Vec<u8>)> {
    store.scan(&[]).await.unwrap()
}

/// A store restored from a backup.
async fn restored(records: Vec<(Vec<u8>, Vec<u8>)>) -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    assert!(
        store
            .commit(&Commit::new(records, Vec::new()))
            .await
            .unwrap()
    );
    store
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn a_device_keeps_its_spaces_in_sqlite() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("frasil-client-sqlite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.sqlite");
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let (space, doc, sealed) = {
        let platform = Platform::sqlite(&path, slot.clone()).unwrap();
        let (device, sealed) = Engine::create(platform, &[3; 32], registry.clone())
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        let doc = device.new_document().unwrap();
        device
            .edit_document(space, &doc, |d| {
                d.get_text("body").insert(0, "on disk").unwrap();
            })
            .await
            .unwrap();
        device.keep_reading().await.unwrap();
        (space, doc, sealed)
    };
    let platform = Platform::sqlite(&path, slot).unwrap();
    let device = Engine::open(platform, &sealed, &[3; 32], registry)
        .await
        .unwrap();
    assert_eq!(device.continuity().await, Continuity::Current);
    assert_eq!(device.spaces().await, vec![space]);
    let seen = device.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "on disk");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_wrong_unlock_key_opens_nothing() {
    let platform = Platform::memory();
    let (_, sealed) = Engine::create(platform.clone(), &[1; 32], AdapterRegistry::new())
        .await
        .unwrap();
    let opened = Engine::open(platform, &sealed, &[2; 32], AdapterRegistry::new()).await;
    assert_eq!(opened.unwrap_err(), Error::Class("Decrypt"));
}

#[tokio::test]
async fn a_restored_device_syncs_before_it_signs() {
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[5; 32],
        registry.clone(),
    )
    .await
    .unwrap();
    let (bob, _) = Engine::create(Platform::memory(), &[6; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    // A backup, then a unit written after it, which a member receives.
    let saved = backup(store.as_ref()).await;
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    bob.follow(space).await;
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    drop(alice);

    // The store is restored from the backup; the slot is not.
    let platform = Platform::new(restored(saved).await, slot);
    let alice = Engine::open(platform, &sealed, &[5; 32], registry)
        .await
        .unwrap();
    assert_eq!(alice.continuity().await, Continuity::Restored);
    assert!(!alice.may_sign(&space).await);
    let refused = alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "x").unwrap();
        })
        .await;
    assert_eq!(refused.unwrap_err(), Error::SyncBeforeWriting);

    // It fetches its own newest event from a member, then signs after it:
    // no fork.
    alice.ingest(space, bob.events(&space).await).await.unwrap();
    alice.synced(&space).await.unwrap();
    assert!(alice.may_sign(&space).await);
    let next = alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(7, " three").unwrap();
        })
        .await
        .unwrap();
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let status = bob
        .read(&space, |r| r.status(&next).copied())
        .await
        .unwrap();
    assert!(
        matches!(status, Some(frasil_space::Status::Valid(_))),
        "{status:?}"
    );
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "one two three");
}

/// A space the device originates after a restore is write-ready at once: it
/// holds the only replica of the log, so `create_space_of_kind` finishes,
/// granting the creator's person with no sync first. A space that predates
/// the restore still waits for a sync before the device writes there, and a
/// second restore leaves a newly originated space write-ready just the same
/// (at-rest.md, "After a restore").
#[cfg(all(feature = "sqlite", feature = "adapter-records"))]
#[tokio::test]
async fn a_restored_device_finishes_a_space_it_originates() {
    use frasil::{Device, Storage};

    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("frasil-originate-restore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let unlock = [8; 32];

    // A first run with no restore: a person, and a space of a kind with a
    // record written into it.
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    device.make_person(&unlock).await.unwrap();
    let first = device
        .create_space_of_kind("com.example.notes")
        .await
        .unwrap();
    assert!(first.is_write_ready().await);
    let first_id = first.id();
    first
        .create_records()
        .unwrap()
        .write(|tx| {
            tx.insert("notes", b"n1").set("notes", b"n1", "text", "one");
        })
        .await
        .unwrap();
    device.close().await.unwrap();
    drop(first);

    // Reopened: a directory store counts every start as a restore. The space
    // that predates the restore is not write-ready until it syncs, and a
    // write there is refused.
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    let pre_existing = device.space(first_id).await.unwrap();
    assert!(!pre_existing.is_write_ready().await);
    let refused = pre_existing
        .create_records()
        .unwrap()
        .write(|tx| {
            tx.set("notes", b"n1", "text", "two");
        })
        .await;
    assert_eq!(refused.unwrap_err(), Error::SyncBeforeWriting);

    // A space this device originates after the restore finishes and is
    // write-ready at once: the grant of the creator's person goes through,
    // and a record is written with no sync first.
    let second = device
        .create_space_of_kind("com.example.notes")
        .await
        .unwrap();
    assert!(second.is_write_ready().await);
    second
        .create_records()
        .unwrap()
        .write(|tx| {
            tx.insert("notes", b"n2")
                .set("notes", b"n2", "text", "fresh");
        })
        .await
        .unwrap();
    device.close().await.unwrap();
    drop((pre_existing, second));

    // A second restore: a newly originated space still finishes.
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    let third = device
        .create_space_of_kind("com.example.notes")
        .await
        .unwrap();
    assert!(third.is_write_ready().await);
    third
        .create_records()
        .unwrap()
        .write(|tx| {
            tx.insert("notes", b"n3")
                .set("notes", b"n3", "text", "again");
        })
        .await
        .unwrap();
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
