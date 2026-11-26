//! Reading a blob, and what the device keeps of it (at-rest.md,
//! "Retention").
//!
//! A blob on a device is kept, cached or absent ([`BlobState`]). A read
//! takes a [`Read`], which says what becomes of a blob the device has to
//! fetch for it: left in the cache, kept, or stored nowhere once the read
//! ends. A blob the device holds already is read from the device whatever
//! the read says. [`Blobs::keep`] fetches and keeps a blob without reading
//! it, [`Blobs::drop_local`] makes one absent, and [`Blobs::local`] tells
//! where one stands.
//!
//! A read of a blob the device does not hold whole goes through a reader
//! ([`Blobs::open_reader`]), which fetches the chunks it reads and puts
//! them where the read says: the cache, as parts of a cached blob; the
//! store, kept; or, for a read that is to store nothing and for a blob too
//! large for the whole budget, the reader's own memory. [`Blobs::get`],
//! [`Blobs::get_stream`] and [`Blobs::content_hash`] read in order from
//! the first byte, so every check of units.md, 3.3 Reading an object has
//! run when they reach the last chunk. In a space whose blobs the
//! application holds as files, a read fetches the blob whole first, into
//! a file.

use super::blob_stream::Reporter;
use super::{BlobId, Blobs};
use crate::error::{Error, Result};
use crate::fetch::FetchPriority;
pub use crate::retention::{BlobCacheUsage, BlobState};
use crate::retention::{InUse, Want};
use frasil_adapter_blobs::Entry;
use frasil_events::EventId;

/// What a read does about a blob this device does not hold whole, for
/// [`Blobs::get`], [`Blobs::get_stream`], [`Blobs::get_range`] and
/// [`Blobs::content_hash`]. A blob the device holds is read from the
/// device, whatever the read says.
///
/// ```
/// use frasil::Read;
///
/// let cached = Read::new(); // fetch, and leave it in the cache
/// let kept = Read::new().keep(); // fetch, and keep it
/// let passing = Read::new().uncached(); // fetch, and store nothing after
/// let here = Read::new().local(); // fetch nothing
/// # let _ = (cached, kept, passing, here);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Read {
    keep: bool,
    uncached: bool,
    local: bool,
}

impl Read {
    /// A read that fetches a blob the device does not hold and leaves it
    /// in the cache, within the device's budget
    /// ([`Options::blob_cache`](crate::Options::blob_cache)).
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps the blob: fetched or cached, it stays on the device until
    /// [`Blobs::drop_local`], outside the cache's budget. A read that
    /// cannot fetch the blob now still marks it kept, and the device
    /// fetches it by itself once it can.
    #[must_use]
    pub fn keep(mut self) -> Self {
        self.keep = true;
        self.uncached = false;
        self
    }

    /// Stores nothing of a blob the read fetches: its chunks pass through
    /// memory, a few at a time. A blob the device held before, whole or in
    /// part, stays as it was, and what the read fetches of one held in
    /// part joins that part.
    #[must_use]
    pub fn uncached(mut self) -> Self {
        self.uncached = true;
        self.keep = false;
        self
    }

    /// Fetches nothing: the read gives a blob only when the device holds
    /// it whole, and never waits on the network.
    #[must_use]
    pub fn local(mut self) -> Self {
        self.local = true;
        self
    }

    /// Whether the read keeps the blob.
    pub(super) fn keeps(&self) -> bool {
        self.keep
    }

    /// Whether the read stores nothing of what it fetches.
    pub(super) fn stores_nothing(&self) -> bool {
        self.uncached
    }

    /// Whether the read fetches nothing.
    pub(super) fn is_local(&self) -> bool {
        self.local
    }
}

/// Where a blob stands on this device, from [`Blobs::local`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobLocal {
    /// Kept, cached or absent.
    pub state: BlobState,
    /// The bytes the device stores of it: its sealed chunks and header,
    /// which may be part of the blob while it is being fetched. For a blob
    /// the application holds as a file, the same count for the whole blob.
    pub bytes: u64,
    /// The blob's size.
    pub size: u64,
}

/// A blob made ready for a read, or being fetched for one: the device
/// drops nothing of it until the read is [`done`](Reading::done), or is
/// dropped.
#[derive(Debug)]
pub(super) struct Reading {
    blobs: Blobs,
    /// Whether the cache was looked at since the read's uses ended. Every
    /// read's end looks at it, whether the read fetched the blob or found
    /// it here: it may be the last to use a blob that another read
    /// fetched to store nothing.
    settled: bool,
    uses: Vec<InUse>,
}

impl Reading {
    /// A read that uses objects until it is [`done`](Reading::done).
    pub(super) fn holding(blobs: Blobs, uses: Vec<InUse>) -> Self {
        Self {
            blobs,
            settled: false,
            uses,
        }
    }

    /// The read ended: a blob fetched to store nothing, by this read or
    /// by another, is dropped unless a read still uses it, and the cache
    /// is back within its budget.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(super) async fn done(mut self) -> Result<()> {
        let engine = self.blobs.space().device.engine().clone();
        self.uses.clear();
        // Noted only once the cache was looked at: a read cancelled
        // while it waits here is dropped, and looks at it then.
        engine.evict().await?;
        self.settled = true;
        Ok(())
    }
}

/// A read dropped before it was [`done`](Reading::done), as when its
/// future is cancelled part way through a fetch or a read, or while it
/// ends: its uses end here, and the device looks at its cache at once, on
/// a task of its own, since nothing can wait in a drop. A blob fetched to
/// store nothing that no read uses any more is dropped then, as if the
/// read had ended.
///
/// Nothing here panics. Where no task can be started, as on a thread with
/// no runtime of a device that was given none, the cache is looked at the
/// next time it is anyway: when a part arrives, when another read ends,
/// and at the device's upkeep. What the read held beside the cache stays
/// marked for that until then.
impl Drop for Reading {
    fn drop(&mut self) {
        self.uses.clear();
        if !self.settled {
            let device = &self.blobs.space().device;
            let engine = device.engine().clone();
            let _ = device.try_spawn(Box::pin(async move {
                let _ = engine.evict().await;
            }));
        }
    }
}

impl Blobs {
    /// The space whose replica holds an entry's object whole: this space,
    /// or for a reference its source.
    pub(super) async fn holder(&self, entry: &Entry) -> Option<EventId> {
        let engine = self.space().device.engine();
        let mut spaces = vec![self.space().id().event()];
        spaces.extend(entry.reference.as_ref().map(|r| EventId(r.source)));
        for space in spaces {
            if engine
                .read(&space, |replica| replica.holds_object(&entry.object))
                .await
                .unwrap_or(false)
            {
                return Some(space);
            }
        }
        None
    }

    /// Makes an entry's object readable as `read` says: `None` for a local
    /// read of a blob the device does not hold whole.
    ///
    /// # Errors
    ///
    /// `Missing` while nothing is connected that could send it, or what
    /// is connected does not serve it for now; [`Error::Timeout`] when the
    /// fetch stops moving; `ObjectMismatch` or `Malformed` once every
    /// connection of the space gave the blob up; [`Error::NotAllowed`] and
    /// [`Error::Unsupported`] as [`Blobs::get`] says; the store's.
    pub(super) async fn ready<F: FnMut(u64, Option<u64>)>(
        &self,
        entry: &Entry,
        read: &Read,
        progress: &mut Reporter<F>,
    ) -> Result<Option<Reading>> {
        let engine = self.space().device.engine();
        let space = self.space().id().event();
        let locator = entry.object;
        // Used before the device is asked what it holds, so that what it
        // answers stays.
        let mut reading = Reading {
            blobs: self.clone(),
            settled: false,
            uses: vec![engine.use_object(space, &locator)],
        };
        if let Some(reference) = &entry.reference {
            reading
                .uses
                .push(engine.use_object(EventId(reference.source), &locator));
        }
        if let Some(holder) = self.holder(entry).await {
            // A blob another read fetched to store nothing is the cache's
            // once a read that would leave it there reads it, and the
            // device makes room for it then.
            if read.keep || !read.uncached {
                engine.retain(holder, &locator, read.keep).await?;
            }
            engine.touch(holder, &locator).await?;
            return Ok(Some(reading));
        }
        if read.local {
            reading.done().await?;
            return Ok(None);
        }
        let held = engine.object_policy(&space).await == crate::held::ObjectPolicy::Held;
        if read.uncached && held {
            return Err(Error::Unsupported(
                "a space whose blobs the application holds stores each blob it fetches as a \
                 file: read without `uncached`, or use `materialise`",
            ));
        }
        if read.keep {
            engine.retain(space, &locator, true).await?;
        } else {
            // Recorded when its first part arrives, so that a read that
            // fetches nothing writes nothing.
            let want = if read.uncached {
                Want::Pass
            } else {
                Want::Cache
            };
            reading.uses.push(engine.want_object(space, &locator, want));
        }
        let fetched = self
            .fetched(
                space,
                locator,
                entry.size,
                FetchPriority::Position,
                progress,
            )
            .await;
        if let Err(error) = fetched {
            // What an unkept read left of the blob is the cache's; of a
            // read that stores nothing, nothing stays.
            reading.done().await?;
            return Err(error);
        }
        Ok(Some(reading))
    }

    /// Fetches a blob into this device's store and keeps it there until
    /// [`Blobs::drop_local`], without reading it: a download in the
    /// background. `on_progress(bytes, Some(size))` follows the fetch. A
    /// blob the device holds already is kept from now on, and one that
    /// cannot be fetched now stays marked: the device fetches it by itself
    /// once a peer or a member that holds it is connected. A reference
    /// whose bytes the device holds in the space that stores the file is
    /// kept there, and [`Blobs::drop_local`] through the reference drops
    /// them there.
    ///
    /// In a space whose blobs the application holds as files, this is
    /// [`Blobs::materialise`] with an empty hint.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID;
    /// [`Error::NotAllowed`] in a space this device keeps in memory alone
    /// ([`Space::is_memory_only`](crate::Space::is_memory_only)); `Missing`
    /// while neither a peer nor a member that holds it is connected;
    /// [`Error::Timeout`] when the fetch stops moving; `ObjectMismatch` or
    /// `Malformed` once every connection of the space gave the blob up
    /// because what it was sent failed its checks; the store's.
    pub async fn keep(&self, id: BlobId, on_progress: impl FnMut(u64, Option<u64>)) -> Result<()> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        let space = self.space().id().event();
        let size = entry.size;
        let mut progress = Reporter::following(on_progress);
        if engine.object_policy(&space).await == crate::held::ObjectPolicy::Held {
            self.materialise(id, &[]).await?;
            progress.report(size, Some(size));
            return Ok(());
        }
        let _uses = engine.use_object(space, &entry.object);
        if let Some(holder) = self.holder(&entry).await {
            engine.retain(holder, &entry.object, true).await?;
        } else {
            engine.retain(space, &entry.object, true).await?;
            self.fetched(
                space,
                entry.object,
                size,
                FetchPriority::Background,
                &mut progress,
            )
            .await?;
        }
        progress.report(size, Some(size));
        Ok(())
    }

    /// Drops what this device stores of a blob, kept or cached: the blob
    /// is absent here, and a read fetches it again from a peer or a member
    /// that holds it. Nothing changes for anyone else, and the stream
    /// still lists the blob. Dropping a blob the device holds nothing of
    /// changes nothing.
    ///
    /// A read that returned, and a reader that was closed or dropped, use
    /// the blob no more. Chunks fetched for such a read that the device is
    /// still writing are written first, and the drop waits for them.
    ///
    /// A reference's bytes are dropped in this space and in the space that
    /// stores the file, when this device holds that space: where
    /// [`Blobs::keep`] through the reference keeps them, and where the
    /// file's own blob then stands absent too.
    ///
    /// In a space whose blobs the application holds as files, this is
    /// [`Blobs::release`]: the device forgets the file, which stays the
    /// application's to delete.
    ///
    /// An older version of a file that no peer keeps any more cannot be
    /// fetched again once dropped.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID;
    /// [`Error::NotAllowed`] while the blob must stay: a read that has not
    /// returned, an open [`BlobReader`](crate::BlobReader) or a fetch is
    /// using it, this device put it in a space with an always-on peer
    /// and no peer is known to hold its bytes yet, its object is one
    /// Frasil stores for itself, or the device keeps every blob
    /// ([`Options::keep_all_blobs`](crate::Options::keep_all_blobs)) and
    /// would fetch it again at once; the store's and the provider's.
    pub async fn drop_local(&self, id: BlobId) -> Result<()> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        let space = self.space().id().event();
        // A reference's bytes may be stored in its source, where `keep`
        // through the reference keeps them: they are dropped there too,
        // so that the two undo each other.
        if let Some(reference) = &entry.reference
            && EventId(reference.source) != space
        {
            match engine
                .drop_local_object(EventId(reference.source), &entry.object)
                .await
            {
                // A device that does not hold the source stores nothing
                // there.
                Ok(()) | Err(Error::UnknownSpace) => {}
                Err(error) => return Err(error),
            }
        }
        engine.drop_local_object(space, &entry.object).await
    }

    /// Where a blob stands on this device: kept, cached or absent, and how
    /// many bytes the device stores of it. A reference whose bytes the
    /// device holds in the space that stores them stands as it does there.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID.
    pub async fn local(&self, id: BlobId) -> Result<BlobLocal> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        let space = self
            .holder(&entry)
            .await
            .unwrap_or(self.space().id().event());
        let (state, bytes) = engine.retention_of(&space, &entry.object).await;
        Ok(BlobLocal {
            state,
            bytes,
            size: entry.size,
        })
    }
}

impl crate::Device {
    /// The budget of the blob cache, and what the device's cached and kept
    /// blobs take, in stored bytes, across all its spaces.
    pub async fn blob_cache_usage(&self) -> BlobCacheUsage {
        self.engine().blob_cache_usage().await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::Reading;
    use crate::outbox::Acknowledger;
    use crate::retention::Want;
    use crate::tasks::{Tasks, Tokio};
    use crate::{BlobState, Device, Options, Storage};
    use frasil_store::BoxFuture;
    use std::sync::Arc;
    use std::time::Duration;

    /// A device's tasks without its upkeep, which looks at the cache too:
    /// what the device starts by itself is left out, and what must not
    /// fail to start, as a dropped read's look at the cache, runs.
    struct NoUpkeep(Tokio);

    impl Tasks for NoUpkeep {
        fn spawn(&self, task: BoxFuture<'static, ()>) {
            drop(task);
        }

        fn try_spawn(&self, task: BoxFuture<'static, ()>) -> bool {
            self.0.try_spawn(task)
        }

        fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
            self.0.sleep(duration)
        }
    }

    async fn device() -> Device {
        let options = Options::new().tasks(Arc::new(NoUpkeep(Tokio::current())));
        Device::open_with(Storage::Memory, &[1; 32], options)
            .await
            .unwrap()
    }

    /// A blob of a space with no peer, dropped and fetched again for a
    /// read that is to store nothing: the read that uses it, and the blob.
    async fn passing_read(device: &Device) -> (Reading, crate::Blobs, crate::BlobId) {
        let space = device.create_space().await.unwrap();
        let blobs = space.create_blobs().unwrap();
        let bytes = vec![7; 1000];
        let id = blobs.put(None, &bytes).await.unwrap();
        let locator = blobs.entry(id).await.unwrap().object;
        let engine = device.engine().clone();
        let of = space.id().event();
        // Its change is durable, by a member's acknowledgement: nothing
        // but the read holds the blob from here on.
        let heads: Vec<_> = engine.outbox(&of).await.into_iter().collect();
        engine
            .acknowledge(of, Acknowledger::Member([8; 32]), &heads)
            .await
            .unwrap();
        // Absent here, by the application's choice.
        blobs.drop_local(id).await.unwrap();
        let reading = Reading {
            blobs: blobs.clone(),
            settled: false,
            uses: vec![
                engine.use_object(of, &locator),
                engine.want_object(of, &locator, Want::Pass),
            ],
        };
        // Its parts arrive, as a peer would send them.
        let (sealed, _, parts) = engine.seal_parts(of, &bytes).await.unwrap();
        assert_eq!(sealed, locator);
        for part in parts {
            engine.receive_sent(of, part).await.unwrap();
        }
        assert_eq!(blobs.local(id).await.unwrap().state, BlobState::Cached);
        (reading, blobs, id)
    }

    /// The blob is absent within a moment.
    async fn gone_soon(blobs: &crate::Blobs, id: crate::BlobId) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while blobs.local(id).await.unwrap().state != BlobState::Absent {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the cache is looked at once the read is dropped");
    }

    /// A read cancelled while it ends, waiting for the device to look at
    /// its cache, still has the cache looked at: what it fetched to store
    /// nothing goes.
    #[tokio::test]
    async fn a_read_cancelled_while_it_ends_leaves_nothing_stored() {
        let device = device().await;
        let (reading, blobs, id) = passing_read(&device).await;
        // The device is busy: the read's end waits for it.
        let busy = device.engine().lock().await;
        let ending = tokio::spawn(reading.done());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!ending.is_finished());
        ending.abort();
        assert!(ending.await.unwrap_err().is_cancelled());
        drop(busy);
        gone_soon(&blobs, id).await;
    }

    /// A read dropped on a thread outside the device's runtime does not
    /// panic, and the cache is looked at on the device's runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_read_dropped_outside_the_runtime_leaves_nothing_stored() {
        let device = device().await;
        let (reading, blobs, id) = passing_read(&device).await;
        std::thread::spawn(move || drop(reading)).join().unwrap();
        gone_soon(&blobs, id).await;
    }
}
