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
