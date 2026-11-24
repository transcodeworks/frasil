//! What a device keeps of its stored objects and what it drops (at-rest.md,
//! "Retention"): the cache's budget and its order, what is never dropped,
//! and what a drop leaves behind. An object is fetched here as a read
//! fetches it, with no connection: its retention is recorded, then each
//! part another party would send goes through the checks of a received
//! part.

use super::{BlobState, Stays, object_id};
use crate::advanced::{AdapterRegistry, Platform};
use crate::device::Engine;
use crate::error::Error;
use crate::objects::Received;
use crate::outbox::Acknowledger;
use crate::platform::{Clock, ManualClock};
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_store::tables::Retention;
use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, Store, Table};
use std::sync::Arc;

/// A device over a store and a clock that outlive it.
struct Medium {
    store: Arc<MemoryStore>,
    slot: Arc<MemorySlot>,
    clock: Arc<ManualClock>,
}

impl Medium {
    fn new() -> Self {
        Self {
            store: Arc::new(MemoryStore::new()),
            slot: Arc::new(MemorySlot::new()),
            clock: Arc::new(ManualClock::new(100, Some(1_800_000_000))),
        }
    }

    fn platform(&self) -> Platform {
        Platform::new(
            Arc::clone(&self.store) as Arc<dyn Store>,
            Arc::clone(&self.slot) as Arc<dyn DeviceBoundSlot>,
        )
        .with_clock(Arc::clone(&self.clock) as Arc<dyn Clock>)
    }

    /// A new device with one space.
    async fn device(&self) -> (Engine, Vec<u8>, EventId) {
        let (engine, sealed) =
            Engine::create(self.platform(), &[4; 32], AdapterRegistry::with_builtins())
                .await
                .unwrap();
        let space = engine.create_space().await.unwrap();
        (engine, sealed.to_vec(), space)
    }

    /// The device, opened again over what its store holds.
    async fn reopen(&self, engine: Engine, sealed: &[u8]) -> Engine {
        engine.keep_reading().await.unwrap();
        drop(engine);
        Engine::open(
            self.platform(),
            sealed,
            &[4; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap()
    }
}

/// An object of `size` bytes of `fill`, sealed under the space's state as
/// a writer seals it, and not stored: what another party would send.
async fn object(
    engine: &Engine,
    space: EventId,
    fill: u8,
    size: usize,
) -> (Locator, Vec<ObjectPart>) {
    let (locator, _, parts) = engine.seal_parts(space, &vec![fill; size]).await.unwrap();
    (locator, parts)
}

/// Fetches an object as a read does: its retention first, then each part
/// through the checks of a part received.
async fn fetch(
    engine: &Engine,
    space: EventId,
    locator: &Locator,
    parts: &[ObjectPart],
    keep: bool,
) {
    engine.retain(space, locator, keep).await.unwrap();
    let mut last = Received::Kept;
    for part in parts {
        last = engine.receive_part(space, part.clone()).await.unwrap();
    }
    assert_eq!(last, Received::Whole);
}

async fn holds(engine: &Engine, space: EventId, locator: &Locator) -> bool {
    engine
        .read(&space, |replica| replica.holds_object(locator))
        .await
        .unwrap()
}

/// The `retention` records the store holds of a space.
async fn records(engine: &Engine, space: EventId) -> Vec<([u8; 32], Retention)> {
    let state = engine.lock().await;
    state
        .vault
        .scan(&space.0, Table::Retention)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|(item, value)| match value {
            frasil_store::TableValue::Retention(retention) => {
                Some((<[u8; 32]>::try_from(&item[..]).unwrap(), retention))
            }
            _ => None,
        })
        .collect()
}

/// The `object` records the store holds of a space.
async fn parts_stored(engine: &Engine, space: EventId) -> usize {
    let state = engine.lock().await;
    state
        .vault
        .scan_sizes(&space.0, Table::Object)
        .await
        .unwrap()
        .len()
}

const SIZE: usize = 10_000;

#[tokio::test]
async fn the_cache_drops_the_object_read_longest_ago_once_a_write_would_pass_the_budget() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, b_parts) = object(&engine, space, b'b', SIZE).await;
    let (c, c_parts) = object(&engine, space, b'c', SIZE).await;

    fetch(&engine, space, &a, &a_parts, false).await;
    let one = engine.blob_cache_usage().await.cached;
    assert!(one > SIZE as u64, "the sealed chunks and the header count");
    // Room for two and a half.
    engine.set_blob_cache(one * 5 / 2);
    fetch(&engine, space, &b, &b_parts, false).await;
    assert_eq!(engine.blob_cache_usage().await.cached, 2 * one);
    // `a` is read again: `b` is now the one read longest ago.
    engine.touch(space, &a).await.unwrap();

    fetch(&engine, space, &c, &c_parts, false).await;
    assert!(holds(&engine, space, &a).await);
    assert!(
        !holds(&engine, space, &b).await,
        "the one read longest ago went"
    );
    assert!(holds(&engine, space, &c).await);
    let usage = engine.blob_cache_usage().await;
    assert_eq!((usage.cached, usage.kept), (2 * one, 0));
    assert!(usage.cached <= usage.budget);
    // Whole: its record and every part, the header with the chunks.
    assert_eq!(
        engine.retention_of(&space, &b).await,
        (BlobState::Absent, 0)
    );
    assert!(
        !engine
            .read(&space, |r| r.knows_object_id(&object_id(&b)))
            .await
            .unwrap()
    );
    let recorded: Vec<[u8; 32]> = records(&engine, space)
        .await
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(recorded.contains(&object_id(&a)) && recorded.contains(&object_id(&c)));
    assert!(!recorded.contains(&object_id(&b)));
    assert_eq!(parts_stored(&engine, space).await, 2 * (a_parts.len() + 1));
}

#[tokio::test]
async fn the_order_of_the_cache_survives_a_reopen() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, b_parts) = object(&engine, space, b'b', SIZE).await;
    let (c, c_parts) = object(&engine, space, b'c', SIZE).await;

    // `b` first, then `a` two hours later.
    fetch(&engine, space, &b, &b_parts, false).await;
    let one = engine.blob_cache_usage().await.cached;
    medium.clock.advance(2 * 3_600);
    fetch(&engine, space, &a, &a_parts, false).await;
    // `b` is read again another two hours on: its record says so.
    medium.clock.advance(2 * 3_600);
    engine.touch(space, &b).await.unwrap();
    let read = |records: &[([u8; 32], Retention)], of: &Locator| {
        records
            .iter()
            .find_map(|(id, retention)| match retention {
                Retention::Cached { read } if *id == object_id(of) => Some(*read),
                _ => None,
            })
            .unwrap()
    };
    let recorded = records(&engine, space).await;
    assert!(read(&recorded, &b) > read(&recorded, &a));
    assert_eq!(read(&recorded, &b) % 3_600, 0, "rounded down to the hour");

    let engine = medium.reopen(engine, &sealed).await;
    assert_eq!(engine.blob_cache_usage().await.cached, 2 * one);
    engine.set_blob_cache(one * 5 / 2);
    fetch(&engine, space, &c, &c_parts, false).await;
    assert!(
        !holds(&engine, space, &a).await,
        "read before `b` was read again"
    );
    assert!(holds(&engine, space, &b).await);
    assert!(holds(&engine, space, &c).await);
}

#[tokio::test]
async fn a_kept_object_survives_a_full_cache_and_a_reopen() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let (kept, kept_parts) = object(&engine, space, b'k', SIZE).await;
    let (cached, cached_parts) = object(&engine, space, b'c', SIZE).await;
    fetch(&engine, space, &kept, &kept_parts, true).await;
    fetch(&engine, space, &cached, &cached_parts, false).await;
    let usage = engine.blob_cache_usage().await;
    assert_eq!(usage.cached, usage.kept);
    assert_eq!(
        engine.must_stay(&*engine.lock().await, &space, &kept),
        Some(Stays::Kept)
    );

    let engine = medium.reopen(engine, &sealed).await;
    assert_eq!(engine.retention_of(&space, &kept).await.0, BlobState::Kept);
    assert_eq!(
        engine.retention_of(&space, &cached).await.0,
        BlobState::Cached
    );
    // Nothing fits the cache any more.
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &kept).await);
    assert!(!holds(&engine, space, &cached).await);
    let usage = engine.blob_cache_usage().await;
    assert_eq!(usage.cached, 0);
    assert!(usage.kept > SIZE as u64);

    // A cached object becomes kept when asked, and never the other way.
    let (other, other_parts) = object(&engine, space, b'o', SIZE).await;
    fetch(&engine, space, &other, &other_parts, false).await;
    engine.evict().await.unwrap();
    assert!(
        !holds(&engine, space, &other).await,
        "dropped once the read ended, with no budget"
    );
    engine.set_blob_cache(u64::MAX);
    fetch(&engine, space, &other, &other_parts, false).await;
    engine.retain(space, &other, true).await.unwrap();
    engine.retain(space, &other, false).await.unwrap();
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &other).await);

    // The application drops it: nothing stays, and nothing is recorded.
    engine.drop_local_object(space, &kept).await.unwrap();
    assert!(!holds(&engine, space, &kept).await);
    assert_eq!(records(&engine, space).await.len(), 1);
    let engine = medium.reopen(engine, &sealed).await;
    assert_eq!(
        engine.retention_of(&space, &kept).await,
        (BlobState::Absent, 0)
    );
    assert_eq!(engine.retention_of(&space, &other).await.0, BlobState::Kept);
}

#[tokio::test]
async fn objects_stored_with_no_record_are_kept() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    // As a client that knows no `retention` table stored it.
    let (old, old_parts) = object(&engine, space, b'o', SIZE).await;
    engine
        .store_parts(space, &old_parts.iter().collect::<Vec<_>>(), false)
        .await
        .unwrap();
    assert!(records(&engine, space).await.is_empty());

    let engine = medium.reopen(engine, &sealed).await;
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &old).await);
    assert_eq!(engine.retention_of(&space, &old).await.0, BlobState::Kept);
    let usage = engine.blob_cache_usage().await;
    assert_eq!(usage.cached, 0);
    assert!(usage.kept > SIZE as u64);
    // A read of it does not make it cached.
    engine.retain(space, &old, false).await.unwrap();
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &old).await);
    assert!(records(&engine, space).await.is_empty());
    // The application may drop it.
    engine.drop_local_object(space, &old).await.unwrap();
    assert!(!holds(&engine, space, &old).await);
    assert_eq!(parts_stored(&engine, space).await, 0);
}

#[tokio::test]
async fn a_blob_this_device_put_stays_until_a_peer_holds_it() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    // The space has an always-on peer, which has taken nothing yet.
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, Some("a file"), &vec![7; SIZE])
        .await
        .unwrap();
    assert_eq!(
        engine.retention_of(&space, &locator).await.0,
        BlobState::Cached
    );
    assert!(engine.outbox(&space).await.contains(&unit));

    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await, "not durable yet");
    assert_eq!(
        engine.must_stay(&*engine.lock().await, &space, &locator),
        Some(Stays::Pending)
    );
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));
    assert!(holds(&engine, space, &locator).await);

    // The peer acknowledges the unit: it took the object before it.
    engine
        .acknowledge(space, Acknowledger::Peer([9; 32]), &[unit])
        .await
        .unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));
    engine.evict().await.unwrap();
    assert!(
        !holds(&engine, space, &locator).await,
        "cached once durable"
    );
}

#[tokio::test]
async fn a_blob_put_in_a_space_with_no_peer_is_kept_until_the_application_drops_it() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, None, &vec![7; SIZE])
        .await
        .unwrap();
    assert_eq!(
        engine.retention_of(&space, &locator).await.0,
        BlobState::Kept
    );
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    // A member's acknowledgement makes the unit durable, and says nothing
    // of who holds the bytes.
    engine
        .acknowledge(space, Acknowledger::Member([8; 32]), &[unit])
        .await
        .unwrap();
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    engine.drop_local_object(space, &locator).await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
}

#[tokio::test]
async fn frasils_own_objects_survive_a_full_cache_and_a_drop() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let doc = engine.new_document().unwrap();
    engine
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "text").unwrap();
        })
        .await
        .unwrap();
    // A stream snapshot object: the snapshot unit names it.
    let snapshot = engine.compact(space, doc.stream()).await.unwrap();
    let own = engine
        .read(&space, |replica| {
            let event = replica.log().unwrap().event(snapshot).unwrap().clone();
            frasil_units::Unit::from_event(event).unwrap().body.objects[0]
        })
        .await
        .unwrap();
    assert!(holds(&engine, space, &own).await);
    // Even with a record that says cached, as a blob entry that named the
    // same object could not give it: an object the device holds parts of
    // is never recorded as cached.
    engine.retain(space, &own, false).await.unwrap();
    assert!(records(&engine, space).await.is_empty());
    {
        let mut state = engine.lock().await;
        state
            .retained
            .load(space, object_id(&own), Retention::Cached { read: 0 }, 1);
        assert_eq!(engine.must_stay(&state, &space, &own), Some(Stays::Own));
    }
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &own).await);
    assert!(matches!(
        engine.drop_local_object(space, &own).await,
        Err(Error::NotAllowed(_))
    ));
    engine.drop_if_cached(space, &own).await.unwrap();
    assert!(holds(&engine, space, &own).await);
    assert_eq!(
        engine.blob_cache_usage().await.kept,
        0,
        "not the application's"
    );
}

#[tokio::test]
async fn an_object_a_read_or_a_fetch_is_using_is_not_dropped() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    fetch(&engine, space, &a, &a_parts, false).await;
    engine.set_blob_cache(0);

    let reading = engine.use_object(space, &a);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &a).await);
    assert_eq!(
        engine.must_stay(&*engine.lock().await, &space, &a),
        Some(Stays::InUse)
    );
    assert!(matches!(
        engine.drop_local_object(space, &a).await,
        Err(Error::NotAllowed(_))
    ));
    // A request for its chunks, still wanted, holds it too.
    let fetching = engine.fetch_chunks(space, a, 0..1, crate::fetch::FetchPriority::Position);
    drop(reading);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &a).await);

    drop(fetching);
    assert_eq!(engine.must_stay(&*engine.lock().await, &space, &a), None);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &a).await);
}

#[tokio::test]
async fn a_dropped_object_is_checked_from_the_start_when_it_comes_back() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    fetch(&engine, space, &a, &a_parts, false).await;
    // Read whole, every step passing, and hashed.
    let mut plain = engine.plain(&space, &a, None, 0..u64::MAX).await.unwrap();
    while plain.next().await.unwrap().is_some() {}
    engine.keep_content_hash(space, a, [5; 32]);
    assert!(engine.is_verified(&space, &a, true));
    assert!(engine.read(&space, |r| r.is_checked(&a)).await.unwrap());

    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &a).await);
    assert!(!engine.is_verified(&space, &a, false));
    assert_eq!(engine.content_hash(&space, &a), None);
    assert!(!engine.read(&space, |r| r.is_checked(&a)).await.unwrap());

    // Fetched again, the stored bytes are hashed against the locator
    // before the object counts as whole, and a read runs every step.
    engine.set_blob_cache(u64::MAX);
    fetch(&engine, space, &a, &a_parts, false).await;
    assert!(engine.read(&space, |r| r.is_checked(&a)).await.unwrap());
    assert!(!engine.is_verified(&space, &a, false));

    // Bytes that are not the object's leave nothing behind, and how the
    // object is retained stays.
    let (b, mut b_parts) = object(&engine, space, b'b', SIZE).await;
    let last = b_parts[0].chunk.len() - 1;
    b_parts[0].chunk[last] ^= 1;
    engine.retain(space, &b, false).await.unwrap();
    assert_eq!(
        engine
            .receive_part(space, b_parts[0].clone())
            .await
            .unwrap(),
        Received::Refused
    );
    assert!(
        !engine
            .read(&space, |r| r.knows_object_id(&object_id(&b)))
            .await
            .unwrap()
    );
    assert!(matches!(
        engine.lock().await.retained.get(&(space, object_id(&b))),
        Some(Retention::Cached { .. })
    ));
}

#[tokio::test]
async fn a_kept_object_the_device_does_not_hold_is_one_it_means_to_hold() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, _) = object(&engine, space, b'b', SIZE).await;
    // Kept before any part arrived, and cached likewise.
    engine.retain(space, &a, true).await.unwrap();
    engine.retain(space, &b, false).await.unwrap();
    assert!(Engine::keeps_object(&*engine.lock().await, &space, &a));
    assert!(!Engine::keeps_object(&*engine.lock().await, &space, &b));
    assert_eq!(engine.retention_of(&space, &a).await, (BlobState::Kept, 0));
    assert_eq!(
        engine.retention_of(&space, &b).await,
        (BlobState::Absent, 0)
    );

    // After a reopen the kept record stands, and the cached one, of an
    // object with no part, is gone.
    let engine = medium.reopen(engine, &sealed).await;
    assert!(Engine::keeps_object(&*engine.lock().await, &space, &a));
    assert_eq!(
        records(&engine, space).await,
        vec![(object_id(&a), Retention::Kept)]
    );

    // Part of a kept object: still one the device fetches by itself.
    engine
        .receive_part(space, a_parts[0].clone())
        .await
        .unwrap();
    assert!(Engine::keeps_object(&*engine.lock().await, &space, &a));
    // Dropped, it is absent by choice.
    engine.drop_local_object(space, &a).await.unwrap();
    assert!(!Engine::keeps_object(&*engine.lock().await, &space, &a));
    assert!(records(&engine, space).await.is_empty());
}

#[cfg(feature = "ext-guests")]
#[tokio::test]
async fn the_budget_bounds_what_a_space_kept_in_memory_holds() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    engine.keep_in_memory(&space).await.unwrap();
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, b_parts) = object(&engine, space, b'b', SIZE).await;
    fetch(&engine, space, &a, &a_parts, false).await;
    let one = engine.blob_cache_usage().await.cached;
    assert!(one > SIZE as u64);
    // Nothing of it is written.
    assert_eq!(parts_stored(&engine, space).await, 0);
    assert!(records(&engine, space).await.is_empty());

    engine.set_blob_cache(one * 3 / 2);
    fetch(&engine, space, &b, &b_parts, false).await;
    assert!(!holds(&engine, space, &a).await);
    assert!(holds(&engine, space, &b).await);
    assert_eq!(engine.blob_cache_usage().await.cached, one);
    // Nothing is kept there: the grant asked for nothing at rest.
    assert!(matches!(
        engine.retain(space, &b, true).await,
        Err(Error::NotAllowed(_))
    ));
}
