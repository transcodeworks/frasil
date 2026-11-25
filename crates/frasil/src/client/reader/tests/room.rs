//! A store with no room for a chunk a read fetched: the cache gives way,
//! and where that makes none, the read goes on through memory.

use super::*;
use crate::advanced::{AdapterRegistry, Platform};
use frasil_store::{BoxFuture, Commit, MemorySlot, MemoryStore, Store, StoreError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A store that refuses commits of chunks for want of room: the next
/// `refusing` of them, or every one at `usize::MAX`.
struct Tight {
    inner: MemoryStore,
    refusing: AtomicUsize,
}

impl Store for Tight {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        self.inner.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<(Vec<u8>, Vec<u8>)>, StoreError>> {
        self.inner.scan(prefix)
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let chunk = commit
                .puts
                .iter()
                .any(|(_, record)| record.len() >= CHUNK_BYTES / 2);
            let left = self.refusing.load(Ordering::SeqCst);
            if chunk && left > 0 {
                if left != usize::MAX {
                    self.refusing.store(left - 1, Ordering::SeqCst);
                }
                return Err(StoreError::full("the medium has no room"));
            }
            self.inner.commit(commit).await
        })
    }
}

/// A blob absent on a device over a store that can run out of room.
async fn tight() -> (Absent, Arc<Tight>) {
    let store = Arc::new(Tight {
        inner: MemoryStore::new(),
        refusing: AtomicUsize::new(0),
    });
    let platform = Platform::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::new(MemorySlot::new()),
    );
    let (engine, _) = Engine::create(platform, &[1; 32], AdapterRegistry::with_builtins())
        .await
        .unwrap();
    let device = Device::from_engine(engine, Options::new()).unwrap();
    (absent_on(device, bytes()).await, store)
}

/// Another blob of the space, fetched whole into the cache.
async fn cached(absent: &Absent) -> BlobId {
    let bytes = vec![9; CHUNK_BYTES + 10];
    let id = absent.blobs.put(None, &bytes).await.unwrap();
    let heads: Vec<_> = absent.engine.outbox(&absent.of).await.into_iter().collect();
    absent
        .engine
        .acknowledge(absent.of, Acknowledger::Member([8; 32]), &heads)
        .await
        .unwrap();
    absent.blobs.drop_local(id).await.unwrap();
    let (locator, _, parts) = absent.engine.seal_parts(absent.of, &bytes).await.unwrap();
    absent
        .engine
        .retain(absent.of, &locator, false)
        .await
        .unwrap();
    for part in parts {
        absent.engine.receive_sent(absent.of, part).await.unwrap();
    }
    assert_eq!(
        absent.blobs.local(id).await.unwrap().state,
        BlobState::Cached
    );
    id
}

/// The store refuses a chunk once: the device drops the blob read longest
/// ago from its cache, though the cache is within its budget, and the
/// chunk is stored at the second attempt.
#[tokio::test]
async fn a_store_with_no_room_makes_the_cache_give_way() {
    let (absent, store) = tight().await;
    let other = cached(&absent).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    store.refusing.store(1, Ordering::SeqCst);
    assert_eq!(absent.read(&mut reader, 0, 100).await, absent.bytes[..100]);
    assert_eq!(store.refusing.load(Ordering::SeqCst), 0);
    assert!(absent.holds(0).await);
    assert_eq!(absent.state().await, BlobState::Cached);
    assert_eq!(
        absent.blobs.local(other).await.unwrap().state,
        BlobState::Absent
    );
    reader.close().await.unwrap();
}

/// The store refuses every chunk, and the cache holds nothing to drop:
/// the reader goes on through its memory and gives the whole blob,
/// checked, and nothing of it is stored or recorded.
#[tokio::test]
async fn a_read_goes_on_through_memory_when_the_store_stays_full() {
    let (absent, store) = tight().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut reader, 0, len).await, absent.bytes);
    assert_eq!(reader.verified(), Verified::Whole);
    assert!(reader.window_bytes() > 0);
    for index in 0..5 {
        assert!(!absent.holds(index).await);
    }
    let local = absent.blobs.local(absent.id).await.unwrap();
    assert_eq!((local.state, local.bytes), (BlobState::Absent, 0));
    reader.close().await.unwrap();
    // With the readers gone the store is tried again.
    store.refusing.store(0, Ordering::SeqCst);
    let read = Read::new();
    let whole = absent.blobs.get(absent.id, &read);
    tokio::pin!(whole);
    let whole = loop {
        tokio::select! {
            whole = &mut whole => break whole.unwrap(),
            () = tokio::time::sleep(Duration::from_millis(5)) => {
                for (index, _) in absent.asked() {
                    absent.send(index as usize).await;
                }
            }
        }
    };
    assert_eq!(whole.as_deref(), Some(&absent.bytes[..]));
    assert_eq!(absent.state().await, BlobState::Cached);
}

/// With no reader to take it, a part the store has no room for fails as
/// the store does, and nothing of it stays.
#[tokio::test]
async fn a_part_no_reader_takes_fails_as_the_store_does() {
    let (absent, store) = tight().await;
    absent
        .engine
        .retain(absent.of, &absent.locator, true)
        .await
        .unwrap();
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    let sent = absent
        .engine
        .receive_sent(absent.of, absent.parts[0].clone())
        .await;
    assert!(matches!(sent, Err(Error::Store(_))), "{sent:?}");
    assert!(!absent.holds(0).await);
}
