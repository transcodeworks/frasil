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
//! A read fetches the blob whole before it gives any of it, so every check
//! of units.md, 3.3 Reading an object runs as for any stored object: each
//! chunk as it arrives, the locator's digest once the object is whole, and
//! the rest when it is read. A read that is to store nothing holds the
//! blob in the device's store while it runs and drops it when it ends.

use super::blob_stream::Reporter;
use super::{BlobId, Blobs};
use crate::error::{Error, Result};
use crate::fetch::FetchPriority;
use crate::retention::InUse;
pub use crate::retention::{BlobCacheUsage, BlobState};
use frasil_adapter::Locator;
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

    /// Stores nothing of a blob the read fetches once the read ends. The
    /// blob is held in the device's store while the read runs. A blob the
    /// device held before stays as it was.
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

/// A blob made ready for a read: the device holds it whole, and drops
/// nothing of it until the read is [`done`](Reading::done).
pub(super) struct Reading {
    blobs: Blobs,
    /// The space that stores the object for this read.
    holder: EventId,
    locator: Locator,
    /// Whether this read fetched the object, to store nothing after.
    passing: bool,
    /// Whether this read fetched the object.
    fetched: bool,
    uses: Vec<InUse>,
}

impl Reading {
    /// The read ended: an object it fetched to store nothing is dropped,
    /// and the cache is back within its budget.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(super) async fn done(self) -> Result<()> {
        let engine = self.blobs.space().device.engine();
        drop(self.uses);
        if self.passing {
            engine.drop_if_cached(self.holder, &self.locator).await?;
        }
        if self.fetched {
            engine.evict().await?;
        }
        Ok(())
    }
}

impl Blobs {
    /// The space whose replica holds an entry's object whole: this space,
    /// or for a reference its source.
    async fn holder(&self, entry: &Entry) -> Option<EventId> {
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
    /// `Missing` while nothing is connected that could send it;
    /// [`Error::Timeout`] when the fetch stops moving;
    /// [`Error::NotAllowed`] and [`Error::Unsupported`] as [`Blobs::get`]
    /// says; the store's.
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
        let mut uses = vec![engine.use_object(space, &locator)];
        if let Some(reference) = &entry.reference {
            uses.push(engine.use_object(EventId(reference.source), &locator));
        }
        if let Some(holder) = self.holder(entry).await {
            if read.keep {
                engine.retain(holder, &locator, true).await?;
            }
            engine.touch(holder, &locator).await?;
            return Ok(Some(Reading {
                blobs: self.clone(),
                holder,
                locator,
                passing: false,
                fetched: false,
                uses,
            }));
        }
        if read.local {
            return Ok(None);
        }
        let held = engine.object_policy(&space).await == crate::held::ObjectPolicy::Held;
        if read.uncached && held {
            return Err(Error::Unsupported(
                "a space whose blobs the application holds stores each blob it fetches as a \
                 file: read without `uncached`, or use `materialise`",
            ));
        }
        engine.retain(space, &locator, read.keep).await?;
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
            drop(uses);
            if read.uncached {
                engine.drop_if_cached(space, &locator).await?;
            } else {
                engine.drop_unfetched(space, &locator).await?;
            }
            return Err(error);
        }
        Ok(Some(Reading {
            blobs: self.clone(),
            holder: space,
            locator,
            passing: read.uncached,
            fetched: true,
            uses,
        }))
    }

    /// Fetches a blob into this device's store and keeps it there until
    /// [`Blobs::drop_local`], without reading it: a download in the
    /// background. `on_progress(bytes, Some(size))` follows the fetch. A
    /// blob the device holds already is kept from now on, and one that
    /// cannot be fetched now stays marked: the device fetches it by itself
    /// once a peer or a member that holds it is connected.
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
    /// [`Error::Timeout`] when the fetch stops moving; the store's.
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

    /// Drops what this device stores of a blob, kept or cached, in this
    /// space: the blob is absent here, and a read fetches it again from a
    /// peer or a member that holds it. Nothing changes for anyone else,
    /// and the stream still lists the blob. Dropping a blob the device
    /// holds nothing of changes nothing.
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
    /// [`Error::NotAllowed`] while the blob must stay: a read or a fetch
    /// is using it, this device put it in a space with an always-on peer
    /// and no peer holds it yet ([`Blobs::is_durable`]), its object is one
    /// Frasil stores for itself, or the device keeps every blob
    /// ([`Options::keep_all_blobs`](crate::Options::keep_all_blobs)) and
    /// would fetch it again at once; the store's and the provider's.
    pub async fn drop_local(&self, id: BlobId) -> Result<()> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        engine
            .drop_local_object(self.space().id().event(), &entry.object)
            .await
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
