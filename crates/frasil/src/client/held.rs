//! Held objects through the client (at-rest.md, "Held objects"): a space's
//! policy, and the blob calls that hand a file to the application and take
//! one from it.

use super::Space;
use crate::error::Result;
use crate::held::{ObjectPolicy, ObjectProvider};
use std::sync::Arc;

impl Space {
    /// Holds this space's blobs through `provider` on this device, in
    /// place of a sealed second copy (at-rest.md, "Held objects"): each
    /// blob the device stores is written through the provider and its
    /// chunk records go; from now on a blob put or fetched here is the
    /// application's file, and Frasil keeps its header and a record of the
    /// file's token, size and change stamp. See
    /// [`Options::object_provider`](super::Options::object_provider) for
    /// every space at once.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`](crate::Error::NotAllowed) when this device's
    /// grant carries `frasil.nothing-at-rest`; the provider's and the
    /// store's.
    pub async fn hold_objects(&self, provider: Arc<dyn ObjectProvider>) -> Result<()> {
        self.device
            .engine()
            .hold_objects(self.id().event(), provider)
            .await
    }

    /// Sets this space's blobs back to `sealed` on this device: each held
    /// blob's chunks are sealed again from its file and kept, and the
    /// provider is told to forget each token. A blob whose file changed is
    /// withdrawn instead, and stays fetchable from peers and members.
    ///
    /// # Errors
    ///
    /// The provider's and the store's.
    pub async fn seal_objects(&self) -> Result<()> {
        self.device.engine().seal_objects(self.id().event()).await
    }

    /// This space's object policy on this device.
    pub async fn object_policy(&self) -> ObjectPolicy {
        self.device.engine().object_policy(&self.id().event()).await
    }
}

/// How a blob is put as a version of a file (ext-file-versions.md, section
/// 3.1), for [`Blobs::put_version`](super::Blobs::put_version) from memory,
/// [`Blobs::put_version_file`](super::Blobs::put_version_file),
/// [`Blobs::put_version_seekable`](super::Blobs::put_version_seekable) and
/// [`Blobs::put_version_at`](super::Blobs::put_version_at) from a source
/// read a few chunks at a time, and
/// [`Blobs::put_version_from`](super::Blobs::put_version_from) from the
/// application's provider.
#[cfg(feature = "adapter-blobs")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PutVersion {
    name: Option<String>,
    parents: Vec<super::BlobId>,
    published: bool,
}

#[cfg(feature = "adapter-blobs")]
impl PutVersion {
    /// A put with no name and no parents, published at once.
    pub fn new() -> Self {
        Self::default()
    }

    /// Under this name, none when empty.
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        self.name = (!name.is_empty()).then(|| name.to_owned());
        self
    }

    /// Made from these blobs of the same stream: the one this device's copy
    /// came from, or every head when it resolves a conflict. With the
    /// `ext-file-versions` feature the unit supersedes each one the stream
    /// holds, so that peers keep a bounded number of old versions. Without
    /// it, or for a parent the stream no longer holds, peers keep the old
    /// version until its handle is removed.
    #[must_use]
    pub fn parents(mut self, parents: &[super::BlobId]) -> Self {
        self.parents = parents.to_vec();
        self
    }

    /// Only once a connected peer holds every chunk: otherwise the put is
    /// `Missing`, and nothing reaches the stream. A member takes no object
    /// before a unit names it, so this needs a peer. Unpublished, a held
    /// file saved over before a peer or a member took it loses this
    /// version's bytes, though its unit still reaches peers.
    #[must_use]
    pub fn published(mut self) -> Self {
        self.published = true;
        self
    }

    /// Whether the put waits for a peer to hold the object.
    pub(crate) fn is_published(&self) -> bool {
        self.published
    }

    fn parent_handles(&self) -> Vec<[u8; 16]> {
        self.parents
            .iter()
            .map(|parent| *parent.as_bytes())
            .collect()
    }
}

#[cfg(feature = "adapter-blobs")]
mod blobs {
    use super::super::{BlobId, Blobs};
    use super::PutVersion;
    use crate::error::{Error, Result};

    impl Blobs {
        /// Puts the file a token names with the application's provider,
        /// under `name` (none when empty), reading it twice in pieces
        /// (at-rest.md, "Held objects", putting): the first pass computes
        /// the object ID, and the second seals each chunk. The plaintext is
        /// never gathered whole, but the sealed chunks of the second pass
        /// are held together until the put returns, about the file's size
        /// in memory. Under the `held` policy the file stays the blob's
        /// only copy, and the sealed chunks are let go once the put
        /// returns; under `sealed` the blob's chunks are kept as
        /// [`Blobs::put`] keeps them. Two puts of one plaintext keep the
        /// earlier put's token: the later one's is forgotten. Returns the new blob's ID.
        ///
        /// Under `held`, the blob's bytes are the file's until a peer or a
        /// member takes them. A file saved over before then loses this
        /// blob's bytes: the unit that names it still reaches peers, so
        /// the stream's later units are not held back, and readers find
        /// the blob missing unless a member fetched it first.
        /// [`Blobs::put_from_published`] puts nothing until a peer holds
        /// the bytes.
        ///
        /// # Errors
        ///
        /// `Changed` when the file is gone or changed while it was read;
        /// [`Error::NotAllowed`] with no provider, or unless this device
        /// writes in the space; then as [`Blobs::put`].
        pub async fn put_from(&self, name: &str, token: &[u8]) -> Result<BlobId> {
            self.put_version_from(token, &PutVersion::new().named(name))
                .await
        }

        /// As [`Blobs::put_from`], but the blob is published only once a
        /// peer holds its bytes: the object is uploaded first, and the unit
        /// that names it is written after the peer's answer, so the stream
        /// never names a blob only this device can serve, and a later save
        /// cannot destroy its only bytes. Nothing reaches the stream on a
        /// refusal, and the file stays held here, ready to be put again.
        ///
        /// A member takes no object before a unit names it, so this needs a
        /// peer of the space: in a space of members alone it is `Missing`.
        ///
        /// # Errors
        ///
        /// `Missing` when no connected peer took every chunk; `Changed`
        /// when the file is gone or changed while it was read or uploaded;
        /// then as [`Blobs::put_from`].
        pub async fn put_from_published(&self, name: &str, token: &[u8]) -> Result<BlobId> {
            self.put_version_from(token, &PutVersion::new().named(name).published())
                .await
        }

        /// As [`Blobs::put_from`], as [`PutVersion`] says: a new version of
        /// the blobs it was made from, and published only once a peer holds
        /// its bytes if asked. A blob's handle is never used twice: each
        /// version is a new blob ([`Drive::set_blob`](crate::Drive::set_blob)
        /// then points the file at it).
        ///
        /// Unpublished, each version's bytes are its file's until a peer or
        /// a member takes them. Saved again before then, the file holds the
        /// newer version alone: the earlier version's unit still reaches
        /// peers without its bytes, and the newer one, with every later
        /// unit, follows with its own.
        ///
        /// # Errors
        ///
        /// As [`Blobs::put_from_published`] when published, or else as
        /// [`Blobs::put_from`].
        pub async fn put_version_from(&self, token: &[u8], how: &PutVersion) -> Result<BlobId> {
            let engine = self.space().device.engine();
            let space = self.space().id().event();
            let handle = engine.platform().nonce::<16>()?;
            let (locator, key) = engine.put_held(space, token).await?;
            let size = match engine.held_record(&space, &locator).await {
                Some(record) => record.size,
                None => engine
                    .object_size(&space, &locator)
                    .await
                    .ok_or(Error::Class("Missing"))?,
            };
            self.put_kept(handle, how, locator, key, size, Vec::new())
                .await
        }

        /// Puts a blob as [`PutVersion`] says: a new version of the blobs
        /// it was made from, and published only once a peer holds its bytes
        /// if asked. The bytes are in memory, and sealed whole beside them:
        /// a large file puts with a few chunks in memory through
        /// [`Blobs::put_version_file`] or [`Blobs::put_version_seekable`].
        ///
        /// # Errors
        ///
        /// `Missing` when published and no connected peer took every chunk;
        /// then as [`Blobs::put`].
        pub async fn put_version(&self, bytes: &[u8], how: &PutVersion) -> Result<BlobId> {
            let engine = self.space().device.engine();
            let space = self.space().id().event();
            let handle = engine.platform().nonce::<16>()?;
            let (locator, key) = engine.blob_object(space, bytes).await?;
            self.put_kept(handle, how, locator, key, bytes.len() as u64, Vec::new())
                .await
        }

        /// Names an object this device keeps in a new unit under `handle`,
        /// as [`PutVersion`] says: once a connected peer holds it when
        /// published, then with a supersession of each parent. `stored`
        /// holds a small object's parts to commit with the unit, and must
        /// be empty when published, so that the peer finds the object in
        /// the store.
        pub(crate) async fn put_kept(
            &self,
            handle: [u8; 16],
            how: &PutVersion,
            locator: frasil_adapter::Locator,
            key: Vec<u8>,
            size: u64,
            stored: Vec<crate::snapshots::ObjectPart>,
        ) -> Result<BlobId> {
            use frasil_adapter_blobs::content::Op;
            use frasil_adapter_blobs::entry::Entry;
            let engine = self.space().device.engine();
            let space = self.space().id().event();
            if how.published {
                debug_assert!(stored.is_empty(), "a published put keeps its object first");
                self.taken(space, locator).await?;
            }
            let entry = Entry {
                object: locator,
                key,
                size,
                media_type: None,
                name: how.name.clone(),
                reference: None,
            };
            engine
                .write_blob_op(
                    space,
                    self.opening(),
                    Op::put(handle, entry),
                    vec![locator],
                    &how.parent_handles(),
                    stored,
                )
                .await?;
            Ok(BlobId::from_bytes(handle))
        }

        /// The token of a blob's file with the application's provider,
        /// under the `held` policy: the file is fetched first when this
        /// device does not hold it, with `hint` passed to the provider's
        /// `create`, such as the path the application wants. A file that
        /// changed since it was held is withdrawn and fetched again.
        ///
        /// # Errors
        ///
        /// [`Error::NotAllowed`] under the `sealed` policy;
        /// [`Error::Invalid`] when the stream holds no blob of this ID;
        /// `Missing` while neither a peer nor a member that holds it is
        /// connected; [`Error::Timeout`] when the fetch stops moving; the
        /// provider's.
        pub async fn materialise(&self, id: BlobId, hint: &[u8]) -> Result<Vec<u8>> {
            let engine = self.space().device.engine();
            let space = self.space().id().event();
            if engine.object_policy(&space).await != crate::held::ObjectPolicy::Held {
                return Err(Error::NotAllowed(
                    "the space's blobs are sealed on this device",
                ));
            }
            let entry = self.entry(id).await?;
            if let Ok(token) = engine.held_token(&space, &entry.object).await {
                return Ok(token);
            }
            engine
                .fetch_object(space, entry.object, hint.to_vec())
                .await;
            let mut progress = super::super::blob_stream::Reporter::silent();
            self.fetched(
                space,
                entry.object,
                entry.size,
                crate::fetch::FetchPriority::Position,
                &mut progress,
            )
            .await?;
            engine.held_token(&space, &entry.object).await
        }

        /// Releases a blob's file: the record of it goes, the provider is
        /// told to forget the token, and the blob is `Missing` here until
        /// it is fetched again.
        ///
        /// # Errors
        ///
        /// [`Error::NotAllowed`] under the `sealed` policy;
        /// [`Error::Invalid`] when the stream holds no blob of this ID;
        /// `Missing` when this device does not hold it; the provider's.
        pub async fn release(&self, id: BlobId) -> Result<()> {
            let engine = self.space().device.engine();
            let space = self.space().id().event();
            if engine.object_policy(&space).await != crate::held::ObjectPolicy::Held {
                return Err(Error::NotAllowed(
                    "the space's blobs are sealed on this device",
                ));
            }
            let entry = self.entry(id).await?;
            engine.release_held(&space, &entry.object).await
        }
    }
}
