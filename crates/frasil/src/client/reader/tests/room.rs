//! A store with no room for a chunk a read fetched: the cache gives way,
//! and where that makes none, the read goes on through memory.

use super::*;
use crate::advanced::{AdapterRegistry, Platform};
use frasil_store::{BoxFuture, Commit, MemorySlot, MemoryStore, Store, StoreError};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A store that refuses commits of chunks for want of room: the next
/// `refusing` of them, or every one at `usize::MAX`, and those whose
/// numbers `refused_at` names, the first commit of a chunk being 1, each
/// once every commit of a chunk before it that is not refused landed.
struct Tight {
    inner: MemoryStore,
    refusing: AtomicUsize,
    /// The commits of chunks asked for so far.
    commits: AtomicUsize,
    /// The commits of chunks that landed.
    landed: AtomicUsize,
    refused_at: Mutex<BTreeSet<usize>>,
    /// Whether a commit of a chunk lets other tasks run before it lands
    /// or is refused, so that two calls' commits interleave.
    yields: AtomicBool,
}

impl Tight {
    /// How many records of whole chunks the store holds.
    async fn records(&self) -> usize {
        let records = self.inner.scan(&[]).await.unwrap();
        records
            .iter()
            .filter(|(_, record)| record.len() >= CHUNK_BYTES / 2)
            .count()
    }

    /// Refuses the commits of chunks with these numbers, counted from
    /// now, each of which lets other tasks run first.
    fn refuse_at(&self, numbers: &[usize]) {
        self.commits.store(0, Ordering::SeqCst);
        self.landed.store(0, Ordering::SeqCst);
        self.yields.store(true, Ordering::SeqCst);
        *self.refused_at.lock().unwrap() = numbers.iter().copied().collect();
    }
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
            if !chunk {
                return self.inner.commit(commit).await;
            }
            let number = self.commits.fetch_add(1, Ordering::SeqCst) + 1;
            if self.yields.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            let refused = self.refused_at.lock().unwrap().clone();
            if refused.contains(&number) {
                let before = number - 1 - refused.range(..number).count();
                while self.landed.load(Ordering::SeqCst) < before {
                    tokio::task::yield_now().await;
                }
                return Err(StoreError::full("the medium has no room"));
            }
            let left = self.refusing.load(Ordering::SeqCst);
            if left > 0 {
                if left != usize::MAX {
                    self.refusing.store(left - 1, Ordering::SeqCst);
                }
                return Err(StoreError::full("the medium has no room"));
            }
            let landed = self.inner.commit(commit).await;
            self.landed.fetch_add(1, Ordering::SeqCst);
            landed
        })
    }
}

/// A blob absent on a device over a store that can run out of room.
async fn tight() -> (Absent, Arc<Tight>) {
    tight_with(bytes()).await
}

/// [`tight`] for a blob of these bytes.
async fn tight_with(bytes: Vec<u8>) -> (Absent, Arc<Tight>) {
    let store = Arc::new(Tight {
        inner: MemoryStore::new(),
        refusing: AtomicUsize::new(0),
        commits: AtomicUsize::new(0),
        landed: AtomicUsize::new(0),
        refused_at: Mutex::default(),
        yields: AtomicBool::new(false),
    });
    let platform = Platform::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::new(MemorySlot::new()),
    );
    let (engine, _) = Engine::create(platform, &[1; 32], AdapterRegistry::with_builtins())
        .await
        .unwrap();
    let device = Device::from_engine(engine, Options::new()).unwrap();
    (absent_on(device, bytes).await, store)
}

/// Another blob of the space, fetched whole into the cache.
async fn cached(absent: &Absent) -> BlobId {
    fetched(absent, 9, false).await
}

/// Another blob of the space, of bytes `fill`, fetched whole: kept, or
/// into the cache.
async fn fetched(absent: &Absent, fill: u8, keep: bool) -> BlobId {
    let bytes = vec![fill; CHUNK_BYTES + 10];
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
        .retain(absent.of, &locator, keep)
        .await
        .unwrap();
    for part in parts {
        absent.engine.receive_sent(absent.of, part).await.unwrap();
    }
    assert_eq!(
        absent.blobs.local(id).await.unwrap().state,
        if keep {
            BlobState::Kept
        } else {
            BlobState::Cached
        }
    );
    id
}

/// The blob as the device holds it, with nothing fetched: every step of
/// a whole read passed.
async fn held(absent: &Absent, id: BlobId) -> Vec<u8> {
    tokio::time::timeout(
        Duration::from_secs(20),
        absent.blobs.get(id, &Read::new().local()),
    )
    .await
    .expect("the blob reads")
    .unwrap()
    .expect("the device holds the blob")
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

/// The store has room for no more than one attempt after the cache gave
/// way: the chunk is committed twice, and the read goes on through
/// memory though the cache holds nothing more to drop.
#[tokio::test]
async fn a_refused_chunk_is_written_once_more_and_no_further() {
    let (absent, store) = tight().await;
    let other = cached(&absent).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    store.commits.store(0, Ordering::SeqCst);
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(absent.read(&mut reader, 0, 100).await, absent.bytes[..100]);
    assert_eq!(store.commits.load(Ordering::SeqCst), 2);
    assert_eq!(
        absent.blobs.local(other).await.unwrap().state,
        BlobState::Absent
    );
    // Nothing more of the blob is tried while the reader is open.
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut reader, 0, len).await, absent.bytes);
    assert_eq!(store.commits.load(Ordering::SeqCst), 2);
    reader.close().await.unwrap();
}

/// Making room takes only what eviction may take: a kept blob, a cached
/// blob a reader has open, and a blob this device put that no peer holds
/// yet all stay, whole, and the read goes on through memory.
#[tokio::test]
async fn a_store_with_no_room_takes_nothing_that_must_stay() {
    let (absent, store) = tight().await;
    let kept = fetched(&absent, 7, true).await;
    let used = fetched(&absent, 8, false).await;
    let put = absent
        .blobs
        .put(None, &vec![6; CHUNK_BYTES + 10])
        .await
        .unwrap();
    let using = absent.blobs.open_reader(used, &Read::new()).await.unwrap();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let records = store.records().await;
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut reader, 0, len).await, absent.bytes);
    assert_eq!(store.records().await, records);
    for (id, state, fill) in [
        (kept, BlobState::Kept, 7),
        (used, BlobState::Cached, 8),
        (put, BlobState::Kept, 6),
    ] {
        assert_eq!(absent.blobs.local(id).await.unwrap().state, state);
        assert_eq!(held(&absent, id).await, vec![fill; CHUNK_BYTES + 10]);
    }
    using.close().await.unwrap();
    reader.close().await.unwrap();
}

/// Nothing more of the blob is stored while any reader that was open
/// when the store had no room still is: the store is tried again only
/// once the last of them closed.
#[tokio::test]
async fn a_blob_is_stored_again_once_its_last_reader_closed() {
    let (absent, store) = tight().await;
    let mut first = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let mut second = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    assert_eq!(absent.read(&mut first, 0, 100).await, absent.bytes[..100]);
    first.close().await.unwrap();
    // Room again, and a reader still open: nothing is stored.
    store.refusing.store(0, Ordering::SeqCst);
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut second, 0, len).await, absent.bytes);
    for index in 0..5 {
        assert!(!absent.holds(index).await);
    }
    assert_eq!(absent.state().await, BlobState::Absent);
    second.close().await.unwrap();
    let mut third = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    assert_eq!(absent.read(&mut third, 0, len).await, absent.bytes);
    assert_eq!(absent.state().await, BlobState::Cached);
    third.close().await.unwrap();
}

/// A chunk the device holds arrives again, as when two connections fetch
/// one blob, and the store refuses it, once or every time: the header
/// and the chunk it held stay in the store, and the blob reads whole.
#[tokio::test]
async fn a_chunk_held_stays_when_the_store_refuses_it_again() {
    for refusing in [1, usize::MAX] {
        let (absent, store) = tight().await;
        absent
            .engine
            .retain(absent.of, &absent.locator, false)
            .await
            .unwrap();
        assert_eq!(absent.send(0).await, Received::Kept);
        let records = store.records().await;
        store.refusing.store(refusing, Ordering::SeqCst);
        let again = absent
            .engine
            .receive_sent(absent.of, absent.parts[0].clone())
            .await;
        assert!(matches!(again, Err(Error::Store(_))), "{again:?}");
        assert_eq!(store.records().await, records);
        assert!(absent.holds(0).await);
        store.refusing.store(0, Ordering::SeqCst);
        for index in 1..absent.parts.len() {
            absent.send(index).await;
        }
        assert_eq!(held(&absent, absent.id).await, absent.bytes);
    }
}

/// The same under an open reader, which goes on through its memory: what
/// the device held of the blob stays readable, and the reader gives the
/// whole blob, checked.
#[tokio::test]
async fn a_reader_goes_on_when_a_chunk_held_is_refused_again() {
    let (absent, store) = tight().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    assert_eq!(absent.read(&mut reader, 0, 100).await, absent.bytes[..100]);
    assert!(absent.holds(0).await);
    store.refusing.store(usize::MAX, Ordering::SeqCst);
    absent
        .engine
        .receive_sent(absent.of, absent.parts[0].clone())
        .await
        .unwrap();
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut reader, 0, len).await, absent.bytes);
    assert_eq!(reader.verified(), Verified::Whole);
    reader.close().await.unwrap();
}

/// Two calls keep one part at once, and the store refuses the second
/// commit after the first landed: what the other call stored stays, and
/// the blob reads whole.
#[tokio::test]
async fn a_part_another_call_stored_stays_when_the_store_refuses_it() {
    let (absent, store) = tight().await;
    absent
        .engine
        .retain(absent.of, &absent.locator, false)
        .await
        .unwrap();
    let records = store.records().await;
    store.refuse_at(&[2]);
    let (one, other) = tokio::join!(
        absent
            .engine
            .receive_sent(absent.of, absent.parts[0].clone()),
        absent
            .engine
            .receive_sent(absent.of, absent.parts[0].clone()),
    );
    assert!(
        matches!(
            (&one, &other),
            (Ok(Received::Kept), Err(Error::Store(_))) | (Err(Error::Store(_)), Ok(Received::Kept))
        ),
        "{one:?} {other:?}"
    );
    assert_eq!(store.records().await, records + 1);
    assert!(absent.holds(0).await);
    for index in 1..absent.parts.len() {
        absent.send(index).await;
    }
    assert_eq!(held(&absent, absent.id).await, absent.bytes);
}

/// Ten chunks and a bit: parts that take two commits.
fn two_commits() -> Vec<u8> {
    (0..CHUNK_BYTES * 10 + 1000)
        .map(|i| (i % 241) as u8)
        .collect()
}

/// The parts of an object the device holds whole are stored again, and
/// the store refuses the second commit of them: the records the first
/// commit put again are the object's, and stay.
#[tokio::test]
async fn an_object_held_stays_when_a_later_commit_of_it_is_refused() {
    let (absent, store) = tight_with(two_commits()).await;
    let parts: Vec<&ObjectPart> = absent.parts.iter().collect();
    absent
        .engine
        .store_parts(absent.of, &parts, false)
        .await
        .unwrap();
    let records = store.records().await;
    store.refuse_at(&[2]);
    let again = absent.engine.store_parts(absent.of, &parts, false).await;
    assert!(matches!(again, Err(Error::Store(_))), "{again:?}");
    assert_eq!(store.records().await, records);
    assert_eq!(held(&absent, absent.id).await, absent.bytes);
}

/// Two calls store the parts of one object at once, and the store
/// refuses the second commit of one of them while the other is still
/// writing: the records both wrote are left to the other call, which
/// stores the object whole.
#[tokio::test]
async fn records_another_call_is_writing_stay_when_a_commit_is_refused() {
    let (absent, store) = tight_with(two_commits()).await;
    let parts: Vec<&ObjectPart> = absent.parts.iter().collect();
    let records = store.records().await;
    store.refuse_at(&[3]);
    let (one, other) = tokio::join!(
        absent.engine.store_parts(absent.of, &parts, false),
        absent.engine.store_parts(absent.of, &parts, false),
    );
    assert!(
        matches!(
            (&one, &other),
            (Ok(()), Err(Error::Store(_))) | (Err(Error::Store(_)), Ok(()))
        ),
        "{one:?} {other:?}"
    );
    // Each chunk but the last, which is not a whole one.
    assert_eq!(store.records().await, records + absent.parts.len() - 1);
    assert_eq!(held(&absent, absent.id).await, absent.bytes);
}

/// Two calls store the parts of one object at once, and the store
/// refuses the second commit of each: the last to fail deletes what
/// both wrote, and nothing of the object stays.
#[tokio::test]
async fn records_no_call_stored_go_when_every_commit_is_refused() {
    let (absent, store) = tight_with(two_commits()).await;
    let parts: Vec<&ObjectPart> = absent.parts.iter().collect();
    let records = store.records().await;
    store.refuse_at(&[3, 4]);
    let (one, other) = tokio::join!(
        absent.engine.store_parts(absent.of, &parts, false),
        absent.engine.store_parts(absent.of, &parts, false),
    );
    assert!(matches!(one, Err(Error::Store(_))), "{one:?}");
    assert!(matches!(other, Err(Error::Store(_))), "{other:?}");
    assert_eq!(store.records().await, records);
    assert!(!absent.holds(0).await);
}

/// A `get` into the cache reads a blob that is not whole here through a
/// reader of its own: under a store that stays full it gives the bytes
/// all the same, and nothing of them is stored or recorded.
#[tokio::test]
async fn a_get_gives_the_blob_when_the_store_stays_full() {
    let (absent, store) = tight().await;
    store.refusing.store(usize::MAX, Ordering::SeqCst);
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
    for index in 0..5 {
        assert!(!absent.holds(index).await);
    }
    let local = absent.blobs.local(absent.id).await.unwrap();
    assert_eq!((local.state, local.bytes), (BlobState::Absent, 0));
}
