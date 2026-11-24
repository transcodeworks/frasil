//! What a device keeps of its stored objects and what it drops (at-rest.md,
//! "Retention"): the cache's budget and its order, what is never dropped,
//! and what a drop leaves behind. An object is fetched here as a read
//! fetches it, with no connection: its retention is recorded, then each
//! part another party would send goes through the checks of a received
//! part.

use super::{BlobState, Stays, Want, object_id};
use crate::advanced::{AdapterRegistry, Platform};
use crate::device::Engine;
use crate::error::Error;
use crate::fetch::FetchPriority;
use crate::objects::Received;
use crate::outbox::Acknowledger;
use crate::platform::{Clock, ManualClock};
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_store::tables::Retention;
use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, Store, Table};
use std::sync::Arc;

/// A store that can hold one commit back: armed, its next commit says that
/// it began and waits to be let go, so that a test acts while a write made
/// outside the device's lock is under way.
struct Gate {
    inner: Arc<MemoryStore>,
    held: std::sync::Mutex<Option<Held>>,
    /// Whether the next commit fails, with nothing written.
    failing: std::sync::atomic::AtomicBool,
}

/// What a commit held back signals with and waits for.
type Held = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

impl Gate {
    /// Holds the next commit back: the first half is ready once it began,
    /// and sending on the second lets it go.
    fn hold(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (began, begun) = tokio::sync::oneshot::channel();
        let (go, gone) = tokio::sync::oneshot::channel();
        *self.held.lock().unwrap() = Some((began, gone));
        (begun, go)
    }
}

impl Store for Gate {
    fn get<'a>(
        &'a self,
        address: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Option<Vec<u8>>, frasil_store::StoreError>> {
        self.inner.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Vec<(Vec<u8>, Vec<u8>)>, frasil_store::StoreError>>
    {
        self.inner.scan(prefix)
    }

    fn commit<'a>(
        &'a self,
        commit: &'a frasil_store::Commit,
    ) -> frasil_store::BoxFuture<'a, Result<bool, frasil_store::StoreError>> {
        Box::pin(async move {
            if self
                .failing
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(frasil_store::StoreError::new("the medium failed"));
            }
            let held = self.held.lock().unwrap().take();
            if let Some((began, gone)) = held {
                let _ = began.send(());
                let _ = gone.await;
            }
            self.inner.commit(commit).await
        })
    }
}

/// A device over a store and a clock that outlive it.
struct Medium {
    store: Arc<Gate>,
    slot: Arc<MemorySlot>,
    clock: Arc<ManualClock>,
}

impl Medium {
    fn new() -> Self {
        Self {
            store: Arc::new(Gate {
                inner: Arc::new(MemoryStore::new()),
                held: std::sync::Mutex::new(None),
                failing: std::sync::atomic::AtomicBool::new(false),
            }),
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
        last = engine.receive_sent(space, part.clone()).await.unwrap();
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

/// The peer is asked now whether it holds an object, as an upload made
/// now asks it, and answers that it holds the object whole.
async fn answer(engine: &Engine, space: EventId, peer: Acknowledger, locator: &Locator) {
    let after = engine.put_asking(space, peer, locator).await;
    engine
        .object_at_peer(space, peer, locator, after)
        .await
        .unwrap();
}

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

/// A part that arrives a second time, as when two connections fetch one
/// object, adds nothing to the cache: no room is made for it, and no
/// other object goes.
#[tokio::test]
async fn a_part_the_device_holds_already_makes_nothing_go() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let (a, a_parts) = object(&engine, space, b'a', chunk).await;
    let (b, b_parts) = object(&engine, space, b'b', chunk).await;
    let (c, c_parts) = object(&engine, space, b'c', 2 * chunk).await;
    assert_eq!((a_parts.len(), c_parts.len()), (1, 2));

    fetch(&engine, space, &a, &a_parts, false).await;
    let one = engine.blob_cache_usage().await.cached;
    // Room for three and a half: `a`, `b` and the first half of `c`.
    engine.set_blob_cache(one * 7 / 2);
    fetch(&engine, space, &b, &b_parts, false).await;
    engine.retain(space, &c, false).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            engine
                .receive_sent(space, c_parts[0].clone())
                .await
                .unwrap(),
            Received::Kept
        );
        assert!(holds(&engine, space, &a).await);
        assert!(holds(&engine, space, &b).await);
    }
    let usage = engine.blob_cache_usage().await;
    assert!(usage.cached > 3 * chunk as u64 && usage.cached <= usage.budget);

    // The second half is new: the one read longest ago goes for it.
    assert_eq!(
        engine
            .receive_sent(space, c_parts[1].clone())
            .await
            .unwrap(),
        Received::Whole
    );
    assert!(!holds(&engine, space, &a).await);
    assert!(holds(&engine, space, &b).await);
    assert!(holds(&engine, space, &c).await);
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
        engine.must_stay(&mut *engine.lock().await, &space, &kept),
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
        BlobState::Kept
    );
    assert_eq!(
        records(&engine, space).await[0].1,
        Retention::Put { keep: false }
    );
    assert!(engine.outbox(&space).await.contains(&unit));

    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await, "not durable yet");
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &locator),
        Some(Stays::Pending)
    );
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));
    assert!(holds(&engine, space, &locator).await);

    // The peer answers that it holds the object, to the upload made
    // before the unit, then acknowledges the unit that names it.
    let peer = Acknowledger::Peer([9; 32]);
    answer(&engine, space, peer, &locator).await;
    engine.evict().await.unwrap();
    assert!(
        holds(&engine, space, &locator).await,
        "no unit at the peer names it yet"
    );
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));
    assert_eq!(
        records(&engine, space).await[0].1,
        Retention::Put { keep: false },
        "the peer answered before it held the unit"
    );
    // Asked again now that it holds the unit, it answers that it holds
    // the object: cached, and under a budget of nothing dropped at once.
    engine.set_blob_cache(1 << 20);
    assert_eq!(
        engine.puts_to_offer(space, peer, false).await.unwrap(),
        vec![locator]
    );
    answer(&engine, space, peer, &locator).await;
    assert!(
        matches!(records(&engine, space).await[0].1, Retention::Cached { .. }),
        "cached once a peer holds it"
    );
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
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
        assert_eq!(engine.must_stay(&mut state, &space, &own), Some(Stays::Own));
    }
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &own).await);
    assert!(matches!(
        engine.drop_local_object(space, &own).await,
        Err(Error::NotAllowed(_))
    ));
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
        engine.must_stay(&mut *engine.lock().await, &space, &a),
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
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &a),
        None
    );
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
            .receive_sent(space, b_parts[0].clone())
            .await
            .unwrap(),
        Received::BadChunk
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
        .receive_sent(space, a_parts[0].clone())
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

/// A member's acknowledgement makes a unit durable in a space whose peer
/// has not acknowledged since the device opened, and says nothing of who
/// holds the unit's objects: a blob this device put stays, across a
/// reopen too, until a peer holds it.
#[tokio::test]
async fn a_members_acknowledgement_never_releases_a_blob_this_device_put() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    // The space has an always-on peer, which is not reached.
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, Some("a file"), &vec![7; SIZE])
        .await
        .unwrap();
    // A member connected directly acknowledges the unit, which leaves the
    // outbox. It holds nothing of the blob.
    engine
        .acknowledge(space, Acknowledger::Member([8; 32]), &[unit])
        .await
        .unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(
        holds(&engine, space, &locator).await,
        "no party that stores objects holds it"
    );
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));

    // Nor after a reopen, when the peer acknowledges the unit, which
    // another member may have sent it without the object.
    let engine = medium.reopen(engine, &sealed).await;
    engine.set_blob_cache(0);
    let peer = Acknowledger::Peer([9; 32]);
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    assert_eq!(
        records(&engine, space).await[0].1,
        Retention::Put { keep: false }
    );
    assert_eq!(
        engine.retention_of(&space, &locator).await.0,
        BlobState::Kept
    );

    // The peer holds the object, by its answer to an upload made after
    // it acknowledged the unit: the device no longer holds the only copy,
    // and the object is the cache's.
    engine.set_blob_cache(1 << 20);
    answer(&engine, space, peer, &locator).await;
    assert_eq!(
        engine.retention_of(&space, &locator).await.0,
        BlobState::Cached
    );
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
}

/// A space that gains its peer after the put, and loses it again: the
/// blob stays until a peer holds it and a unit that names it.
#[tokio::test]
async fn a_blob_put_before_the_space_had_a_peer_stays_until_one_holds_it() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, None, &vec![7; SIZE])
        .await
        .unwrap();
    engine
        .acknowledge(space, Acknowledger::Member([8; 32]), &[unit])
        .await
        .unwrap();
    engine.set_blob_cache(0);
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    // A peer that acknowledged other events holds nothing of this one.
    let peer = Acknowledger::Peer([9; 32]);
    answer(&engine, space, peer, &locator).await;
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    // Kept by the application meanwhile, it is not made cached.
    let (other_unit, other) = engine
        .put_blob(space, &stream, None, &vec![8; SIZE])
        .await
        .unwrap();
    engine.retain(space, &other, true).await.unwrap();
    engine
        .acknowledge(space, peer, &[other_unit])
        .await
        .unwrap();
    answer(&engine, space, peer, &locator).await;
    answer(&engine, space, peer, &other).await;
    engine.evict().await.unwrap();
    assert!(
        !holds(&engine, space, &locator).await,
        "its unit is covered"
    );
    assert!(holds(&engine, space, &other).await, "the application's");
    assert_eq!(engine.retention_of(&space, &other).await.0, BlobState::Kept);
}

/// What must stay in a space is read from its log once, and then only the
/// events the log gained: an eviction pass that cannot make room, and a
/// look at the cache's usage, read no log again.
#[tokio::test]
async fn what_must_stay_is_read_from_the_log_once_and_then_only_what_is_new() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let doc = engine.new_document().unwrap();
    for _ in 0..20 {
        engine
            .edit_document(space, &doc, |d| {
                d.get_text("body").insert(0, "text").unwrap();
            })
            .await
            .unwrap();
    }
    // A cached object over a budget of zero that a read is using: no pass
    // can make room.
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    fetch(&engine, space, &a, &a_parts, false).await;
    let _reading = engine.use_object(space, &a);
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    engine.blob_cache_usage().await;
    let first = engine.lock().await.retained.log_reads();
    assert!(first >= 20, "{first}");
    for _ in 0..50 {
        engine.evict().await.unwrap();
        engine.blob_cache_usage().await;
        let mut state = engine.lock().await;
        assert_eq!(engine.must_stay(&mut state, &space, &a), Some(Stays::InUse));
    }
    assert_eq!(engine.lock().await.retained.log_reads(), first);

    // A snapshot unit placed since names one of Frasil's own objects: the
    // pass after it reads the new events alone, and the object stays.
    let snapshot = engine.compact(space, doc.stream()).await.unwrap();
    let own = engine
        .read(&space, |replica| {
            let event = replica.log().unwrap().event(snapshot).unwrap().clone();
            frasil_units::Unit::from_event(event).unwrap().body.objects[0]
        })
        .await
        .unwrap();
    {
        let mut state = engine.lock().await;
        state
            .retained
            .load(space, object_id(&own), Retention::Cached { read: 0 }, 1);
        assert_eq!(engine.must_stay(&mut state, &space, &own), Some(Stays::Own));
        let read = state.retained.log_reads() - first;
        assert!((1..=4).contains(&read), "{read}");
    }
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &own).await);

    // A unit this device signed that is not durable yet holds its objects,
    // and no longer once it is acknowledged.
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, put) = engine
        .put_blob(space, &stream, None, &vec![7; SIZE])
        .await
        .unwrap();
    {
        let mut state = engine.lock().await;
        assert_eq!(
            engine.must_stay(&mut state, &space, &put),
            Some(Stays::Pending)
        );
    }
    engine
        .acknowledge(space, Acknowledger::Member([8; 32]), &[unit])
        .await
        .unwrap();
    let mut state = engine.lock().await;
    assert_eq!(
        engine.must_stay(&mut state, &space, &put),
        Some(Stays::Kept)
    );
}

/// The parts of an object the device stores, as another party would send
/// them.
async fn stored_parts(engine: &Engine, space: EventId, locator: &Locator) -> Vec<ObjectPart> {
    let mut state = engine.lock().await;
    let bytes = Engine::stored_bytes(&mut state, &space, locator)
        .await
        .unwrap()
        .unwrap();
    crate::objects::parts_of(locator, &bytes).unwrap()
}

/// A part of a blob that arrives after the device dropped the blob, as a
/// slice asked for before a read gave up does, is not stored: with no
/// record it would be kept, and the device would then fetch the blob whole
/// by itself (at-rest.md, "Retention", recording).
#[tokio::test]
async fn a_part_that_arrives_after_its_blob_was_dropped_is_not_stored() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (_, blob) = engine
        .put_blob(space, &stream, None, &vec![7; SIZE])
        .await
        .unwrap();
    let parts = stored_parts(&engine, space, &blob).await;
    // Absent by the device's own choice, and nothing asks for it.
    engine.drop_local_object(space, &blob).await.unwrap();
    assert_eq!(
        engine.retention_of(&space, &blob).await,
        (BlobState::Absent, 0)
    );

    for part in &parts {
        assert_eq!(
            engine.receive_sent(space, part.clone()).await.unwrap(),
            Received::Left
        );
    }
    assert_eq!(
        engine.retention_of(&space, &blob).await,
        (BlobState::Absent, 0)
    );
    assert_eq!(parts_stored(&engine, space).await, 0);
    assert!(records(&engine, space).await.is_empty());
    assert!(!engine.missing_objects(&space).await.contains(&blob));

    // A request for its chunks says the device means to hold it again.
    let fetching = engine.fetch_chunks(space, blob, 0..u64::MAX, FetchPriority::Position);
    engine.retain(space, &blob, false).await.unwrap();
    let mut last = Received::Kept;
    for part in &parts {
        last = engine.receive_sent(space, part.clone()).await.unwrap();
    }
    assert_eq!(last, Received::Whole);
    drop(fetching);
    assert_eq!(
        engine.retention_of(&space, &blob).await.0,
        BlobState::Cached
    );
}

/// A request for chunks of a blob the device holds nothing of does not
/// keep the blob: its record of state 2 is committed with the first part,
/// so that the part is the cache's and the device does not fetch the rest
/// of the blob by itself (at-rest.md, "Retention", recording).
#[tokio::test]
async fn a_part_fetched_for_a_request_alone_is_cached_and_the_rest_is_not_fetched() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (_, blob) = engine
        .put_blob(space, &stream, None, &vec![7; 2 * chunk + 1])
        .await
        .unwrap();
    let parts = stored_parts(&engine, space, &blob).await;
    assert_eq!(parts.len(), 3);
    engine.drop_local_object(space, &blob).await.unwrap();
    assert!(records(&engine, space).await.is_empty());

    let fetching = engine.fetch_chunks(space, blob, 0..1, FetchPriority::Position);
    assert_eq!(
        engine.receive_sent(space, parts[0].clone()).await.unwrap(),
        Received::Kept
    );
    assert!(matches!(
        record_of(&engine, space, &blob).await,
        Some(Retention::Cached { .. })
    ));
    assert_eq!(
        engine.retention_of(&space, &blob).await.0,
        BlobState::Cached
    );
    assert!(!engine.missing_objects(&space).await.contains(&blob));
    // Still the cache's once the request is gone, and after a reopen.
    drop(fetching);
    assert!(!engine.missing_objects(&space).await.contains(&blob));
    let engine = medium.reopen(engine, &sealed).await;
    assert!(matches!(
        record_of(&engine, space, &blob).await,
        Some(Retention::Cached { .. })
    ));
    assert!(!engine.missing_objects(&space).await.contains(&blob));
}

/// A request may be made for chunks of an object before the device holds
/// the unit that names it, as a device that learnt the locator elsewhere
/// makes one: what it brings is the cache's all the same. Stored with no
/// record, the object would be kept once its unit arrived, and the device
/// would fetch the rest of it by itself.
#[tokio::test]
async fn a_part_fetched_for_a_request_before_a_unit_names_its_object_is_cached() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let (a, a_parts) = object(&engine, space, b'a', 2 * chunk).await;

    let fetching = engine.fetch_chunks(space, a, 0..1, FetchPriority::Position);
    assert_eq!(
        engine
            .receive_sent(space, a_parts[0].clone())
            .await
            .unwrap(),
        Received::Kept
    );
    assert!(matches!(
        record_of(&engine, space, &a).await,
        Some(Retention::Cached { .. })
    ));
    drop(fetching);
}

/// While parts of a cached object are being written, outside the device's
/// lock, nothing drops the object: an eviction then would delete its
/// record and its earlier parts, and the parts under way would land with
/// no record and count as kept.
#[tokio::test]
async fn an_object_is_not_dropped_while_its_parts_are_being_written() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let (a, a_parts) = object(&engine, space, b'a', 2 * chunk + 1).await;
    assert_eq!(a_parts.len(), 3);
    engine.retain(space, &a, false).await.unwrap();
    assert_eq!(
        engine
            .receive_sent(space, a_parts[0].clone())
            .await
            .unwrap(),
        Received::Kept
    );

    // The second part's write begins, and is held back in the store.
    let (begun, go) = medium.store.hold();
    let writing = {
        let engine = engine.clone();
        let part = a_parts[1].clone();
        tokio::spawn(async move { engine.receive_sent(space, part).await.unwrap() })
    };
    begun.await.unwrap();
    // The cache is over its budget meanwhile, and a read of the object
    // that got nothing gives up.
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &a),
        Some(Stays::InUse)
    );
    go.send(()).unwrap();
    assert_eq!(writing.await.unwrap(), Received::Kept);

    // Both parts are the cache's, under the record they were fetched
    // under: none counts as kept.
    assert!(matches!(
        records(&engine, space).await[..],
        [(_, Retention::Cached { .. })]
    ));
    // The header and two chunks.
    assert_eq!(parts_stored(&engine, space).await, 3);
    assert_eq!(engine.retention_of(&space, &a).await.0, BlobState::Cached);
    // Nothing writes it any more: the cache may drop it whole.
    engine.evict().await.unwrap();
    assert_eq!(parts_stored(&engine, space).await, 0);
    assert!(records(&engine, space).await.is_empty());
}

/// The stored bytes the device counts in its cache, and beside it.
async fn counted(engine: &Engine) -> (u64, u64) {
    let state = engine.lock().await;
    (state.retained.cached, state.retained.beside)
}

/// A read says what it wants of a blob when it starts, and the device
/// records the blob when its first part arrives: a read that fetches
/// nothing writes no record, and leaves none to delete.
#[tokio::test]
async fn a_read_that_fetches_nothing_records_nothing() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let sets = engine.lock().await.retained.reads;
    let reading = engine.want_object(space, &a, Want::Cache);
    assert!(records(&engine, space).await.is_empty());
    drop(reading);
    engine.evict().await.unwrap();
    assert!(records(&engine, space).await.is_empty());
    assert_eq!(
        engine.lock().await.retained.reads,
        sets,
        "no record was put"
    );

    // The record is there with the first part, and says cached.
    let reading = engine.want_object(space, &a, Want::Cache);
    let mut last = Received::Kept;
    for part in &a_parts {
        last = engine.receive_sent(space, part.clone()).await.unwrap();
    }
    assert_eq!(last, Received::Whole);
    assert!(matches!(
        records(&engine, space).await[..],
        [(_, Retention::Cached { .. })]
    ));
    drop(reading);
    engine.evict().await.unwrap();
    assert_eq!(engine.retention_of(&space, &a).await.0, BlobState::Cached);
}

/// A blob fetched for a read that is to store nothing is held beside the
/// cache: it counts against no budget, makes no cached blob go, and is
/// dropped once no read uses it. A read that leaves it in the cache takes
/// it over.
#[tokio::test]
async fn a_blob_fetched_to_store_nothing_is_held_beside_the_cache() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, b_parts) = object(&engine, space, b'b', SIZE).await;
    let (c, c_parts) = object(&engine, space, b'c', SIZE).await;
    let (d, d_parts) = object(&engine, space, b'd', SIZE).await;
    // Room for two objects and not three.
    engine.set_blob_cache(SIZE as u64 * 5 / 2);
    fetch(&engine, space, &a, &a_parts, false).await;
    fetch(&engine, space, &b, &b_parts, false).await;
    let (cached, _) = counted(&engine).await;

    let passing = engine.want_object(space, &c, Want::Pass);
    for part in &c_parts {
        engine.receive_sent(space, part.clone()).await.unwrap();
    }
    assert!(holds(&engine, space, &a).await, "nothing went for it");
    assert!(holds(&engine, space, &b).await);
    assert!(holds(&engine, space, &c).await);
    let (still, beside) = counted(&engine).await;
    assert_eq!(still, cached);
    assert!(beside > SIZE as u64);
    assert_eq!(
        engine.blob_cache_usage().await.cached,
        cached + beside,
        "what a running read holds is reported"
    );
    // At rest it is cached: after a crash it is the cache's to drop.
    assert_eq!(records(&engine, space).await.len(), 3);
    // Another read that stores nothing uses it while the first ends.
    let second = engine.want_object(space, &c, Want::Pass);
    drop(passing);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &c).await);
    drop(second);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &c).await, "dropped with its read");
    assert_eq!(counted(&engine).await, (cached, 0));
    assert_eq!(records(&engine, space).await.len(), 2);

    // A read that leaves it in the cache takes it over: it counts, and
    // the blob read longest ago goes for it.
    let passing = engine.want_object(space, &d, Want::Pass);
    engine
        .receive_sent(space, d_parts[0].clone())
        .await
        .unwrap();
    let caching = engine.want_object(space, &d, Want::Cache);
    engine.retain(space, &d, false).await.unwrap();
    drop(passing);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &d).await);
    drop(caching);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &d).await, "the cache's");
    assert!(!holds(&engine, space, &a).await, "read longest ago");
    assert!(holds(&engine, space, &b).await);
    let (cached, beside) = counted(&engine).await;
    assert!(cached <= engine.blob_cache());
    assert_eq!(beside, 0);
}

/// A blob larger than the whole budget is held beside the cache while it
/// is read, beside other cached blobs, which stay; and one found in the
/// cache, as after a crash, goes before any blob that fits.
#[tokio::test]
async fn a_blob_larger_than_the_budget_makes_no_other_blob_go() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    let (b, b_parts) = object(&engine, space, b'b', SIZE).await;
    let (large, large_parts) = object(&engine, space, b'l', 4 * SIZE).await;
    let budget = SIZE as u64 * 5 / 2;
    engine.set_blob_cache(budget);
    fetch(&engine, space, &a, &a_parts, false).await;
    fetch(&engine, space, &b, &b_parts, false).await;

    let reading = engine.want_object(space, &large, Want::Cache);
    for part in &large_parts {
        engine.receive_sent(space, part.clone()).await.unwrap();
    }
    assert!(holds(&engine, space, &large).await);
    assert!(holds(&engine, space, &a).await);
    assert!(holds(&engine, space, &b).await);
    let (cached, beside) = counted(&engine).await;
    assert!(cached <= budget);
    assert!(beside > 4 * SIZE as u64);
    drop(reading);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &large).await);
    assert!(holds(&engine, space, &a).await);
    assert!(holds(&engine, space, &b).await);

    // Found in the cache under a budget it does not fit: it goes first,
    // though it was read last.
    engine.set_blob_cache(u64::MAX);
    fetch(&engine, space, &large, &large_parts, false).await;
    assert_eq!(counted(&engine).await.1, 0);
    engine.set_blob_cache(budget);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &large).await);
    assert!(holds(&engine, space, &a).await);
    assert!(holds(&engine, space, &b).await);
}

/// A store that a client without the `retention` table wrote, opened by
/// this one: every object it holds has no record and is kept, whole or in
/// part, and a blob it holds part of is fetched whole by the device
/// itself (at-rest.md, "Retention", a client without this table).
#[tokio::test]
async fn a_store_with_no_retention_records_keeps_what_it_holds_whole_or_in_part() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    // A blob held whole, and one of which the other client had fetched a
    // part when it stopped.
    let (_, whole) = engine
        .put_blob(space, &stream, Some("whole"), &vec![1; SIZE])
        .await
        .unwrap();
    let (_, partial) = engine
        .put_blob(space, &stream, Some("partial"), &vec![2; 2 * chunk + 1])
        .await
        .unwrap();
    let parts = stored_parts(&engine, space, &partial).await;
    engine.drop_local_object(space, &partial).await.unwrap();
    engine.retain(space, &partial, false).await.unwrap();
    assert_eq!(
        engine.receive_sent(space, parts[0].clone()).await.unwrap(),
        Received::Kept
    );
    // An object no unit names, as a fetch left it.
    let (other, other_parts) = object(&engine, space, b'o', SIZE).await;
    fetch(&engine, space, &other, &other_parts, false).await;
    assert_eq!(records(&engine, space).await.len(), 3);

    // The other client knew no such record.
    {
        let mut state = engine.lock().await;
        let mut batch = crate::at_rest::Batch::default();
        for (item, _) in state.vault.scan(&space.0, Table::Retention).await.unwrap() {
            state
                .vault
                .delete(&mut batch, &space.0, Table::Retention, &item);
        }
        state.vault.commit(batch).await.unwrap();
    }
    let engine = medium.reopen(engine, &sealed).await;
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(records(&engine, space).await.is_empty());
    for locator in [&whole, &other] {
        assert!(holds(&engine, space, locator).await);
        assert_eq!(
            engine.retention_of(&space, locator).await.0,
            BlobState::Kept
        );
    }
    // The part stays, kept, and the device means to hold the blob whole:
    // it fetches the rest by itself, outside the budget.
    let (state, bytes) = engine.retention_of(&space, &partial).await;
    assert_eq!(state, BlobState::Kept);
    assert!(bytes > chunk as u64 && bytes < 2 * chunk as u64);
    assert_eq!(engine.missing_objects(&space).await, vec![partial]);
    let usage = engine.blob_cache_usage().await;
    assert_eq!(usage.cached, 0);
    assert!(usage.kept > (2 * SIZE + chunk) as u64);
    for part in &parts[1..] {
        engine.receive_sent(space, part.clone()).await.unwrap();
    }
    assert!(holds(&engine, space, &partial).await);
    assert!(
        records(&engine, space).await.is_empty(),
        "kept by no record"
    );
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &partial).await);
    // The application may drop each, as any kept blob.
    engine.drop_local_object(space, &partial).await.unwrap();
    assert_eq!(
        engine.retention_of(&space, &partial).await,
        (BlobState::Absent, 0)
    );
}

/// A drop whose commit fails leaves the object as it was, in memory as in
/// the store: the device goes on holding it, and drops it at the next
/// pass.
#[tokio::test]
async fn a_drop_the_store_refuses_changes_nothing() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    fetch(&engine, space, &a, &a_parts, false).await;
    let stored = parts_stored(&engine, space).await;
    let (cached, _) = counted(&engine).await;
    engine.set_blob_cache(0);

    medium
        .store
        .failing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(engine.evict().await.is_err());
    assert!(holds(&engine, space, &a).await, "as the store has it");
    assert_eq!(parts_stored(&engine, space).await, stored);
    assert_eq!(records(&engine, space).await.len(), 1);
    assert_eq!(engine.retention_of(&space, &a).await.0, BlobState::Cached);
    assert_eq!(counted(&engine).await.0, cached);
    // It reads as before.
    let mut plain = engine.plain(&space, &a, None, 0..u64::MAX).await.unwrap();
    let mut read = 0;
    while let Some((_, chunk)) = plain.next().await.unwrap() {
        read += chunk.len();
    }
    assert_eq!(read, SIZE);

    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &a).await);
    assert_eq!(parts_stored(&engine, space).await, 0);
    assert!(records(&engine, space).await.is_empty());
}

/// That the application asked to keep a blob, and that this device put it
/// and no storing party is known to hold it, are two facts: keeping the
/// blob does not make it the application's to drop, across a reopen too,
/// and once a peer holds it the blob is kept, not cached.
#[tokio::test]
async fn keeping_a_blob_this_device_put_leaves_it_put() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    // The space has an always-on peer, which is not reached.
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, Some("a file"), &vec![7; SIZE])
        .await
        .unwrap();
    // A member acknowledges the unit, which leaves the outbox.
    engine
        .acknowledge(space, Acknowledger::Member([8; 32]), &[unit])
        .await
        .unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));

    engine.retain(space, &locator, true).await.unwrap();
    assert_eq!(
        records(&engine, space).await[0].1,
        Retention::Put { keep: true }
    );
    assert!(
        matches!(
            engine.drop_local_object(space, &locator).await,
            Err(Error::NotAllowed(_))
        ),
        "no storing party holds the bytes"
    );
    // Asked again, and read as a read that keeps does: nothing changes.
    engine.retain(space, &locator, true).await.unwrap();
    engine.retain(space, &locator, false).await.unwrap();
    assert_eq!(
        records(&engine, space).await[0].1,
        Retention::Put { keep: true }
    );

    let engine = medium.reopen(engine, &sealed).await;
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));
    assert!(holds(&engine, space, &locator).await);
    assert_eq!(
        engine.retention_of(&space, &locator).await.0,
        BlobState::Kept
    );

    // The peer comes to hold it: kept, as the application asked, and the
    // application's to drop.
    let peer = Acknowledger::Peer([9; 32]);
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    answer(&engine, space, peer, &locator).await;
    assert_eq!(records(&engine, space).await[0].1, Retention::Kept);
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    engine.drop_local_object(space, &locator).await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
}

/// The record of one object, if it has one.
async fn record_of(engine: &Engine, space: EventId, locator: &Locator) -> Option<Retention> {
    records(engine, space)
        .await
        .into_iter()
        .find_map(|(id, retention)| (id == object_id(locator)).then_some(retention))
}

/// An object that is kept, by its record or for want of one, stays kept
/// when this device puts the same bytes again: it gains the put, and is
/// kept, not cached, once a peer holds it. A cached one put again is no
/// longer the cache's until a peer holds it.
#[tokio::test]
async fn an_object_put_again_keeps_what_it_was_and_gains_the_put() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let peer = Acknowledger::Peer([9; 32]);
    let member = Acknowledger::Member([8; 32]);

    // Kept for want of a record, as a store written before the table
    // holds it.
    let (old, old_parts) = object(&engine, space, b'o', SIZE).await;
    engine
        .store_parts(space, &old_parts.iter().collect::<Vec<_>>(), false)
        .await
        .unwrap();
    assert_eq!(record_of(&engine, space, &old).await, None);
    // Kept by its record.
    let (kept, kept_parts) = object(&engine, space, b'k', SIZE).await;
    fetch(&engine, space, &kept, &kept_parts, true).await;
    // Cached.
    let (cached, cached_parts) = object(&engine, space, b'c', SIZE).await;
    fetch(&engine, space, &cached, &cached_parts, false).await;

    let mut units = Vec::new();
    for fill in [b'o', b'k', b'c'] {
        let (unit, _) = engine
            .put_blob(space, &stream, None, &vec![fill; SIZE])
            .await
            .unwrap();
        units.push(unit);
    }
    assert_eq!(
        record_of(&engine, space, &old).await,
        Some(Retention::Put { keep: true })
    );
    assert_eq!(
        record_of(&engine, space, &kept).await,
        Some(Retention::Put { keep: true })
    );
    assert_eq!(
        record_of(&engine, space, &cached).await,
        Some(Retention::Put { keep: false })
    );
    // An object the device held nothing of is put and no more, whether
    // its parts go in the unit's commit or before it.
    let (small_unit, small) = engine
        .put_blob(space, &stream, None, &vec![b's'; SIZE])
        .await
        .unwrap();
    let (large_unit, large) = engine
        .put_blob(
            space,
            &stream,
            None,
            &vec![b'l'; crate::objects::OWN_COMMIT_BYTES],
        )
        .await
        .unwrap();
    units.extend([small_unit, large_unit]);
    for locator in [&small, &large] {
        assert_eq!(
            record_of(&engine, space, locator).await,
            Some(Retention::Put { keep: false })
        );
    }

    // A member's acknowledgement makes the units durable: nothing goes.
    engine.acknowledge(space, member, &units).await.unwrap();
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    for locator in [&old, &kept, &cached, &small, &large] {
        assert!(holds(&engine, space, locator).await);
        assert!(matches!(
            engine.drop_local_object(space, locator).await,
            Err(Error::NotAllowed(_))
        ));
    }

    // The peer holds each, and has acknowledged the units.
    engine.acknowledge(space, peer, &units).await.unwrap();
    for locator in [&old, &kept, &cached, &small, &large] {
        answer(&engine, space, peer, locator).await;
    }
    assert_eq!(record_of(&engine, space, &old).await, Some(Retention::Kept));
    assert_eq!(
        record_of(&engine, space, &kept).await,
        Some(Retention::Kept)
    );
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &old).await);
    assert!(holds(&engine, space, &kept).await);
    for locator in [&cached, &small, &large] {
        assert!(!holds(&engine, space, locator).await);
    }
}

/// A space with one always-on peer, and a blob this device put there.
async fn put_with_peer(medium: &Medium) -> (Engine, EventId, EventId, Locator) {
    let (engine, _, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, Some("a file"), &vec![7; SIZE])
        .await
        .unwrap();
    engine.set_blob_cache(0);
    (engine, space, unit, locator)
}

/// A blob this device put is released by the peer that holds it, and by
/// no other: a peer that was sent the unit without the object acknowledges
/// it, and holds nothing of the blob.
#[tokio::test]
async fn another_peers_acknowledgement_does_not_release_a_blob_this_device_put() {
    let medium = Medium::new();
    let (engine, space, unit, locator) = put_with_peer(&medium).await;
    let holder = Acknowledger::Peer([9; 32]);
    let other = Acknowledger::Peer([10; 32]);
    // The holder took the object, and the connection went before the
    // unit: a member relays the unit to another peer.
    answer(&engine, space, holder, &locator).await;
    engine.acknowledge(space, other, &[unit]).await.unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));
    // The holder answers again, and has acknowledged other events.
    engine.acknowledge(space, holder, &[]).await.unwrap();
    answer(&engine, space, holder, &locator).await;
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
        "the peer that holds it has no unit that names it"
    );
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));
    // Nor is the holder's answer the other peer's, whatever the driver
    // says of when it was asked.
    engine
        .object_at_peer(space, holder, &locator, true)
        .await
        .unwrap();
    assert!(holds(&engine, space, &locator).await);

    // The holder acknowledges the unit, and answers a question put after.
    engine.acknowledge(space, holder, &[unit]).await.unwrap();
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
    );
    engine.set_blob_cache(1 << 20);
    answer(&engine, space, holder, &locator).await;
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
}

/// A peer's answer that it holds an object, to a question put before it
/// acknowledged a unit that names the object, releases nothing, whatever
/// its age: the peer may hold the object as one no unit names, and
/// collect it before the unit arrives, which it then stores ahead of its
/// object and acknowledges (peers.md, "Objects"). Only an answer to a
/// question put after the acknowledgement says that the peer holds both.
#[tokio::test]
async fn an_answer_taken_before_the_acknowledgement_releases_nothing() {
    let medium = Medium::new();
    let (engine, space, unit, locator) = put_with_peer(&medium).await;
    engine.set_blob_cache(1 << 20);
    let peer = Acknowledger::Peer([9; 32]);
    // The upload a writer makes before the unit, answered at once.
    answer(&engine, space, peer, &locator).await;
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
        "the peer may have collected the object before the unit came"
    );
    // Nor does the answer count later, as the time the device counts
    // stands still or runs on.
    for wait in [0, 1_799, 5 * 3_600] {
        medium.clock.advance(wait);
        engine.acknowledge(space, peer, &[unit]).await.unwrap();
        engine.evict().await.unwrap();
        assert_eq!(
            record_of(&engine, space, &locator).await,
            Some(Retention::Put { keep: false }),
        );
        assert!(matches!(
            engine.drop_local_object(space, &locator).await,
            Err(Error::NotAllowed(_))
        ));
    }
    // An upload under way when the acknowledgement came was asked before
    // it: its answer is to the earlier question.
    engine
        .object_at_peer(space, peer, &locator, false)
        .await
        .unwrap();
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
    );

    // Asked again, a day after it acknowledged the unit, the peer answers
    // that it holds the object: it holds both.
    medium.clock.advance(86_400);
    assert_eq!(
        engine.puts_to_offer(space, peer, false).await.unwrap(),
        vec![locator]
    );
    answer(&engine, space, peer, &locator).await;
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));

    // A peer that acknowledged nothing releases nothing, whatever is said
    // of when it was asked.
    let medium = Medium::new();
    let (engine, space, _, locator) = put_with_peer(&medium).await;
    engine
        .object_at_peer(space, peer, &locator, true)
        .await
        .unwrap();
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
    );
}

/// A blob whose record still says that no peer is known to hold it, with
/// no unit of it left in the outbox, is asked of the peer again: at each
/// connection, at once when the peer acknowledged a unit that names it
/// since it was last asked, and otherwise at upkeep once in a while. So
/// is one whose release a crash cut short, after the reopen, and the
/// peer's answer then releases it on the acknowledgement the device kept.
#[tokio::test]
async fn a_blob_still_put_with_no_unit_to_send_is_offered_to_the_peer_again() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (unit, locator) = engine
        .put_blob(space, &stream, Some("a file"), &vec![7; SIZE])
        .await
        .unwrap();
    let peer = Acknowledger::Peer([9; 32]);
    let offer = async |connected: bool| engine.puts_to_offer(space, peer, connected).await.unwrap();
    // Its unit waits in the outbox, and is sent behind its upload, which
    // asks before the peer holds the unit.
    assert!(offer(true).await.is_empty());
    assert!(!engine.put_asking(space, peer, &locator).await);

    // The peer acknowledges the unit: asked at once, since the answer to
    // the earlier question releases nothing.
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    assert!(!engine.outbox(&space).await.contains(&unit));
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false })
    );
    assert_eq!(offer(false).await, vec![locator]);
    assert!(engine.put_asking(space, peer, &locator).await);
    assert!(
        offer(false).await.is_empty(),
        "asked since the acknowledgement: upkeep asks again once in a while"
    );
    assert_eq!(offer(true).await, vec![locator], "a connection asks");
    assert!(engine.put_asking(space, peer, &locator).await);
    medium.clock.advance(super::PUT_OFFER);
    assert!(offer(false).await.is_empty());
    medium.clock.advance(1);
    assert_eq!(offer(false).await, vec![locator]);

    // A peer that refuses the object is not offered it again on that
    // connection, however long it lasts.
    engine.put_refused(space, peer, &locator).await;
    medium.clock.advance(10 * super::PUT_OFFER);
    assert!(offer(false).await.is_empty());
    assert_eq!(offer(true).await, vec![locator], "the next connection asks");

    let engine = medium.reopen(engine, &sealed).await;
    assert_eq!(
        engine.puts_to_offer(space, peer, false).await.unwrap(),
        vec![locator]
    );
    answer(&engine, space, peer, &locator).await;
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));
    assert!(
        engine
            .puts_to_offer(space, peer, true)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A unit names an object for a peer only while it stands there: neither
/// replaced nor released (peers.md, "Objects"). An acknowledgement the
/// device kept of a unit that a snapshot replaced since says nothing of
/// the same bytes put again in a later unit, which the peer may refuse.
#[tokio::test]
async fn an_acknowledged_unit_that_was_replaced_releases_nothing() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let peer = Acknowledger::Peer([9; 32]);
    let member = Acknowledger::Member([8; 32]);
    // Put, and acknowledged by the peer with no answer for the object;
    // then removed, and compacted away.
    let (first, locator) = engine
        .put_blob_under(space, &stream, [1; 16], None, &vec![7; SIZE])
        .await
        .unwrap();
    engine.acknowledge(space, peer, &[first]).await.unwrap();
    let removed = engine.remove_blob(space, &stream, [1; 16]).await.unwrap();
    engine.acknowledge(space, member, &[removed]).await.unwrap();
    let snapshot = engine.compact(space, stream.stream()).await.unwrap();
    engine
        .acknowledge(space, member, &[snapshot])
        .await
        .unwrap();

    // After a restart the same bytes are put again, durable through a
    // member: the peer has not been sent this unit.
    let engine = medium.reopen(engine, &sealed).await;
    let (second, again) = engine
        .put_blob_under(space, &stream, [2; 16], None, &vec![7; SIZE])
        .await
        .unwrap();
    assert_eq!(again, locator);
    engine.acknowledge(space, member, &[second]).await.unwrap();
    assert!(
        !engine.put_asking(space, peer, &locator).await,
        "the unit the peer acknowledged is replaced"
    );
    answer(&engine, space, peer, &locator).await;
    engine
        .object_at_peer(space, peer, &locator, true)
        .await
        .unwrap();
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep: false }),
    );

    // The peer acknowledges the unit that stands, and answers after.
    engine.acknowledge(space, peer, &[second]).await.unwrap();
    assert_eq!(
        engine.puts_to_offer(space, peer, false).await.unwrap(),
        vec![locator]
    );
    answer(&engine, space, peer, &locator).await;
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));
}

/// A blob this device put, removed and compacted away before a peer took
/// it: once the replica collected the units of the snapshot's cover, no
/// unit of its log names the object, so no peer will ever hold a unit
/// that references it. It is put no longer: the cache's, or kept where
/// the application asked for that, and the application's to drop.
async fn put_and_compacted_away(medium: &Medium, keep: bool) -> (Engine, EventId, Locator) {
    let (engine, _, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let member = Acknowledger::Member([8; 32]);
    let (first, locator) = engine
        .put_blob_under(space, &stream, [1; 16], None, &vec![7; SIZE])
        .await
        .unwrap();
    if keep {
        engine.retain(space, &locator, true).await.unwrap();
    }
    let removed = engine.remove_blob(space, &stream, [1; 16]).await.unwrap();
    let snapshot = engine.compact(space, stream.stream()).await.unwrap();
    engine
        .acknowledge(space, member, &[first, removed, snapshot])
        .await
        .unwrap();
    // The snapshot is not used yet: its cover may still stand.
    let peer = Acknowledger::Peer([9; 32]);
    assert_eq!(
        engine.puts_to_offer(space, peer, true).await.unwrap(),
        vec![locator]
    );
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep })
    );
    assert!(matches!(
        engine.drop_local_object(space, &locator).await,
        Err(Error::NotAllowed(_))
    ));
    // Settled, the snapshot is used and its cover collected.
    medium.clock.advance(8 * 86_400);
    let collected = engine.collect(space).await.unwrap();
    assert!(collected.contains(&first), "collected: {collected:?}");
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Put { keep })
    );
    (engine, space, locator)
}

#[tokio::test]
async fn a_put_blob_that_no_unit_names_any_more_is_put_no_longer() {
    let peer = Acknowledger::Peer([9; 32]);
    // Offered to no peer again, and the cache's.
    let medium = Medium::new();
    let (engine, space, locator) = put_and_compacted_away(&medium, false).await;
    assert!(
        engine
            .puts_to_offer(space, peer, true)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &locator).await);

    // The application's to drop, with no connection made.
    let medium = Medium::new();
    let (engine, space, locator) = put_and_compacted_away(&medium, false).await;
    engine.drop_local_object(space, &locator).await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
    assert!(records(&engine, space).await.is_empty());

    // Kept where the application asked to keep it.
    let medium = Medium::new();
    let (engine, space, locator) = put_and_compacted_away(&medium, true).await;
    assert!(
        engine
            .puts_to_offer(space, peer, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Kept)
    );
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &locator).await);
    engine.drop_local_object(space, &locator).await.unwrap();
    assert!(!holds(&engine, space, &locator).await);
}

/// A request for chunks made before the device held the unit that names
/// their object leaves a record that says cached. Once a unit shows the
/// object to be Frasil's own, the record goes and its bytes are no longer
/// counted in the cache: the object is held as Frasil's own are.
#[tokio::test]
async fn a_cached_record_of_an_object_that_proves_frasils_own_goes() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let doc = engine.new_document().unwrap();
    engine
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "text").unwrap();
        })
        .await
        .unwrap();
    let snapshot = engine.compact(space, doc.stream()).await.unwrap();
    let own = engine
        .read(&space, |replica| {
            let event = replica.log().unwrap().event(snapshot).unwrap().clone();
            frasil_units::Unit::from_event(event).unwrap().body.objects[0]
        })
        .await
        .unwrap();
    // The record a request made before the unit arrived would have left.
    {
        let mut state = engine.lock().await;
        let read = engine.read_now(&mut state);
        engine
            .record(
                &mut state,
                space,
                object_id(&own),
                Retention::Cached { read },
            )
            .await
            .unwrap();
    }
    assert!(engine.blob_cache_usage().await.cached > 0);
    assert!(record_of(&engine, space, &own).await.is_some());
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &own).await);
    assert_eq!(engine.blob_cache_usage().await.cached, 0);
    assert_eq!(record_of(&engine, space, &own).await, None);
    let engine = medium.reopen(engine, &sealed).await;
    assert!(holds(&engine, space, &own).await);
    assert_eq!(engine.blob_cache_usage().await.cached, 0);
}

/// A released blob is the cache's from then on, and the cache stays
/// within its budget: the device drops what it read longest ago.
#[tokio::test]
async fn a_blob_released_into_a_full_cache_makes_the_oldest_go() {
    let medium = Medium::new();
    let (engine, space, unit, locator) = put_with_peer(&medium).await;
    let (a, a_parts) = object(&engine, space, b'a', SIZE).await;
    engine.set_blob_cache(1 << 30);
    fetch(&engine, space, &a, &a_parts, false).await;
    let one = engine.blob_cache_usage().await.cached;
    engine.set_blob_cache(one);
    medium.clock.advance(7_200);
    let peer = Acknowledger::Peer([9; 32]);
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    answer(&engine, space, peer, &locator).await;
    let usage = engine.blob_cache_usage().await;
    assert!(usage.cached <= usage.budget, "{usage:?}");
    assert!(!holds(&engine, space, &a).await, "read longest ago");
    assert!(holds(&engine, space, &locator).await);
    assert!(matches!(
        record_of(&engine, space, &locator).await,
        Some(Retention::Cached { .. })
    ));

    // One that cannot fit goes itself.
    let medium = Medium::new();
    let (engine, space, unit, locator) = put_with_peer(&medium).await;
    engine.acknowledge(space, peer, &[unit]).await.unwrap();
    answer(&engine, space, peer, &locator).await;
    assert!(!holds(&engine, space, &locator).await);
    assert!(records(&engine, space).await.is_empty());
}

/// A blob stream's snapshot unit lists the object of every current entry
/// beside its snapshot object (adapter-blobs.md, "Compaction"). The
/// snapshot object is Frasil's own and stays; the entries' objects are
/// blobs still, which the cache drops and the application may drop.
#[tokio::test]
async fn the_blobs_of_a_compacted_blob_stream_are_blobs_still() {
    let medium = Medium::new();
    let (engine, sealed, space) = medium.device().await;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    let (first, kept) = engine
        .put_blob(space, &stream, Some("a"), &vec![1; SIZE])
        .await
        .unwrap();
    let (second, cached) = engine
        .put_blob(space, &stream, Some("b"), &vec![2; SIZE])
        .await
        .unwrap();
    let snapshot = engine.compact(space, stream.stream()).await.unwrap();
    engine
        .acknowledge(
            space,
            Acknowledger::Member([8; 32]),
            &[first, second, snapshot],
        )
        .await
        .unwrap();
    let (objects, own) = engine
        .read(&space, |replica| {
            let event = replica.log().unwrap().event(snapshot).unwrap().clone();
            let unit = frasil_units::Unit::from_event(event).unwrap();
            (
                unit.body.objects.clone(),
                unit.body.compacts.unwrap().object,
            )
        })
        .await
        .unwrap();
    assert!(objects.contains(&kept) && objects.contains(&cached) && objects.contains(&own));
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &own),
        Some(Stays::Own)
    );
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &kept),
        Some(Stays::Kept)
    );
    assert!(engine.blob_cache_usage().await.kept > 0);
    // The space has no peer: the application's to drop.
    let parts = stored_parts(&engine, space, &cached).await;
    engine.drop_local_object(space, &cached).await.unwrap();
    assert!(!holds(&engine, space, &cached).await);
    // Fetched again for a read, it is the cache's, and goes for the
    // budget.
    fetch(&engine, space, &cached, &parts, false).await;
    assert_eq!(
        engine.retention_of(&space, &cached).await.0,
        BlobState::Cached
    );
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(!holds(&engine, space, &cached).await);
    assert!(holds(&engine, space, &kept).await);
    // The snapshot object stays, whatever is asked, and after a reopen
    // the stream is read from it.
    assert!(holds(&engine, space, &own).await);
    assert!(matches!(
        engine.drop_local_object(space, &own).await,
        Err(Error::NotAllowed(_))
    ));
    medium.clock.advance(8 * 86_400);
    engine.collect(space).await.unwrap();
    engine.evict().await.unwrap();
    let engine = medium.reopen(engine, &sealed).await;
    engine.set_blob_cache(0);
    engine.evict().await.unwrap();
    assert!(holds(&engine, space, &own).await);
    assert!(holds(&engine, space, &kept).await);
    assert_eq!(
        engine.must_stay(&mut *engine.lock().await, &space, &own),
        Some(Stays::Own)
    );
    assert!(!engine.missing_objects(&space).await.contains(&cached));
}

/// In a space with no always-on peer, no party is bound to take a blob
/// this device put: the application may drop it, whether or not it asked
/// to keep it.
#[tokio::test]
async fn a_put_blob_in_a_space_with_no_peer_is_the_applications_to_drop() {
    for keep in [false, true] {
        let medium = Medium::new();
        let (engine, sealed, space) = medium.device().await;
        let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
        let (_, locator) = engine
            .put_blob(space, &stream, None, &vec![7; SIZE])
            .await
            .unwrap();
        if keep {
            engine.retain(space, &locator, true).await.unwrap();
        }
        assert_eq!(
            record_of(&engine, space, &locator).await,
            Some(Retention::Put { keep })
        );
        let engine = medium.reopen(engine, &sealed).await;
        engine.set_blob_cache(0);
        engine.evict().await.unwrap();
        assert!(holds(&engine, space, &locator).await);
        engine.drop_local_object(space, &locator).await.unwrap();
        assert!(!holds(&engine, space, &locator).await);
        assert!(records(&engine, space).await.is_empty());
        assert_eq!(
            engine.retention_of(&space, &locator).await.0,
            BlobState::Absent
        );
    }
}

/// A read that is to store nothing leaves an object the device held as it
/// was: with parts and no record, kept, cached, put, and put and kept.
/// The read uses the object, fetches what the device lacks of it, and the
/// cache is looked at when it ends.
#[tokio::test]
async fn a_read_that_stores_nothing_leaves_each_held_state_as_it_was() {
    let medium = Medium::new();
    let (engine, _, space) = medium.device().await;
    engine
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let chunk = frasil_units::limits::CHUNK_BYTES;
    let stream = engine.new_stream(frasil_adapter_blobs::TYPE).unwrap();
    // Parts with no record, the object not whole.
    let (bare, bare_parts) = object(&engine, space, b'b', chunk + 1).await;
    engine
        .store_parts(space, &[&bare_parts[0]], false)
        .await
        .unwrap();
    let (kept, kept_parts) = object(&engine, space, b'k', SIZE).await;
    fetch(&engine, space, &kept, &kept_parts, true).await;
    let (cached, cached_parts) = object(&engine, space, b'c', SIZE).await;
    fetch(&engine, space, &cached, &cached_parts, false).await;
    let (_, put) = engine
        .put_blob(space, &stream, None, &vec![b'p'; SIZE])
        .await
        .unwrap();
    let (_, both) = engine
        .put_blob(space, &stream, None, &vec![b'q'; SIZE])
        .await
        .unwrap();
    engine.retain(space, &both, true).await.unwrap();
    let before = records(&engine, space).await;
    assert_eq!(record_of(&engine, space, &bare).await, None);
    assert_eq!(
        record_of(&engine, space, &kept).await,
        Some(Retention::Kept)
    );
    assert!(matches!(
        record_of(&engine, space, &cached).await,
        Some(Retention::Cached { .. })
    ));
    assert_eq!(
        record_of(&engine, space, &put).await,
        Some(Retention::Put { keep: false })
    );
    assert_eq!(
        record_of(&engine, space, &both).await,
        Some(Retention::Put { keep: true })
    );
    let stored = parts_stored(&engine, space).await;

    // The object the device holds part of is fetched whole by the read.
    let using = [
        engine.use_object(space, &bare),
        engine.want_object(space, &bare, Want::Pass),
    ];
    assert_eq!(
        engine
            .receive_sent(space, bare_parts[1].clone())
            .await
            .unwrap(),
        Received::Whole
    );
    drop(using);
    engine.evict().await.unwrap();
    // Those it holds whole are used, and noted as read.
    for locator in [&kept, &cached, &put, &both] {
        let using = engine.use_object(space, locator);
        engine.touch(space, locator).await.unwrap();
        drop(using);
        engine.evict().await.unwrap();
    }
    assert_eq!(records(&engine, space).await, before);
    assert_eq!(parts_stored(&engine, space).await, stored + 1);
    for locator in [&bare, &kept, &cached, &put, &both] {
        assert!(holds(&engine, space, locator).await);
    }
    assert_eq!(engine.retention_of(&space, &bare).await.0, BlobState::Kept);
    assert_eq!(
        engine.retention_of(&space, &cached).await.0,
        BlobState::Cached
    );
}
