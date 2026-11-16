//! File references (adapter-blobs.md, "References"; ext-libraries.md,
//! "Holds"): a file stored once in its library, used by any of the
//! library's spaces.
//!
//! A space that uses a file another space stores puts a **reference**: an
//! entry that names the object by its locator and carries the object's own
//! key, sealed in this space like any entry. Before it puts one, the device
//! registers a **hold** at its peers, which then keep the object for this
//! space and serve it to its readers, who never join the source. A
//! reference names one fixed version of the file. [`Blobs::get`] and
//! [`Blobs::get_stream`] read it like any blob; [`Blobs::info`] tells it
//! apart and names its source.

use super::{BlobId, Blobs, SpaceId};
use crate::error::{Error, Result};
use frasil_adapter::Locator;
use frasil_adapter_blobs::Entry;
use frasil_events::EventId;
use frasil_units::runtime::Stream;

/// How long [`Blobs::reference_from`] waits for a peer to accept the hold
/// before it leaves the hold to the connection, which registers it before
/// it sends the reference.
#[cfg(all(
    feature = "ext-libraries",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
const HOLD_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a blob stream holds under an ID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobInfo {
    /// Its ID in the stream.
    pub id: BlobId,
    /// Its name, if it was given one.
    pub name: Option<String>,
    /// Its media type, if it was given one.
    pub media_type: Option<String>,
    /// Its size in bytes.
    pub size: u64,
    /// For a reference, the space that stores the file; `None` for a blob
    /// this space stores.
    pub source: Option<SpaceId>,
    /// The token of its file with the application's provider, when this
    /// device holds it under the `held` policy (at-rest.md, "Held
    /// objects").
    pub token: Option<Vec<u8>>,
    /// Its object's locator: the bytes a peer stores under it, which two
    /// blobs of one plaintext and one state share.
    pub object: [u8; 64],
}

impl BlobInfo {
    /// Whether the blob is a reference to a file another space stores.
    pub fn is_reference(&self) -> bool {
        self.source.is_some()
    }
}

impl Blobs {
    /// The stream's current entry under an ID.
    pub(crate) async fn entry(&self, id: BlobId) -> Result<Entry> {
        let stream = *self.id().as_bytes();
        self.space()
            .read(|replica| {
                replica
                    .stream(&stream)?
                    .as_any()
                    .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()?
                    .state()
                    .entry(id.as_bytes())
                    .cloned()
            })
            .await?
            .ok_or(Error::Invalid("the stream holds no blob of this ID"))
    }

    /// An entry's bytes, opened under this space's state for a blob it
    /// stores, or with the reference's own key.
    pub(crate) async fn open_entry(&self, entry: &Entry) -> Result<Vec<u8>> {
        let engine = self.space().device.engine();
        let space = self.space().id().event();
        match &entry.reference {
            Some(reference) => {
                engine
                    .referenced_object(
                        &space,
                        &entry.object,
                        &EventId(reference.source),
                        &reference.object_key,
                    )
                    .await
            }
            None => engine.object(&space, &entry.object).await,
        }
    }

    /// Whether the device holds an entry's object whole: in this space, or
    /// for a reference in its source too.
    pub(crate) async fn holds_entry(&self, entry: &Entry) -> bool {
        let engine = self.space().device.engine();
        let mut spaces = vec![self.space().id().event()];
        spaces.extend(entry.reference.as_ref().map(|r| EventId(r.source)));
        for space in spaces {
            if engine
                .read(&space, |replica| replica.holds_object(&entry.object))
                .await
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    }

    /// A blob's name, media type and size, and for a reference the space
    /// that stores it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID.
    pub async fn info(&self, id: BlobId) -> Result<BlobInfo> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        let token = engine
            .held_record(&self.space().id().event(), &entry.object)
            .await
            .map(|record| record.token);
        Ok(BlobInfo {
            id,
            object: entry.object,
            name: entry.name,
            media_type: entry.media_type,
            size: entry.size,
            source: entry
                .reference
                .map(|reference| SpaceId::of(EventId(reference.source))),
            token,
        })
    }

    /// Removes a blob from the stream. A reference's hold ends once
    /// compaction drops it and the peers collect what listed it; the file
    /// then goes unless its source or another space still uses it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID;
    /// [`Error::NotAllowed`] unless this device writes in the space.
    pub async fn remove(&self, id: BlobId) -> Result<()> {
        self.entry(id).await?;
        self.space()
            .device
            .engine()
            .remove_blob(self.space().id().event(), self.opening(), *id.as_bytes())
            .await?;
        Ok(())
    }

    /// Puts a reference to a blob of `source`, a blob stream of another
    /// space in the same library: the file is not stored again. The device
    /// first registers a hold for this space at its connected peers, and
    /// puts the reference once one accepts it; with no peer connected, or
    /// none answering, the connection registers it before it sends the
    /// reference. A reference to a reference names the space that stores
    /// the file. A blob of this space's own stream is put again under a
    /// new ID. Returns the new blob's ID.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `source` holds no blob of this ID;
    /// `OtherLibrary` when the two spaces are billed to different
    /// libraries, where the file must be copied, by [`Blobs::get`] and
    /// [`Blobs::put`]; another class the peer refuses the hold with;
    /// `Sealed` without the source's key; [`Error::NotAllowed`] unless this
    /// device writes in this space.
    pub async fn reference_from(&self, source: &Blobs, id: BlobId) -> Result<BlobId> {
        let mut entry = source.entry(id).await?;
        let space = self.space().id().event();
        let from = source.space().id().event();
        if entry.reference.is_none() && from != space {
            let (key, locator) = (entry.key.clone(), entry.object);
            let object_key = source
                .space()
                .read(|replica| crate::objects::object_key_in(replica, &key, &locator))
                .await??;
            entry.reference = Some(frasil_adapter_blobs::Reference {
                source: from.0,
                object_key,
            });
        }
        let engine = self.space().device.engine();
        let handle = engine.platform().nonce::<16>()?;
        if let Some(reference) = entry.reference.clone() {
            self.hold(
                entry.object,
                EventId(reference.source),
                reference.object_key,
            )
            .await?;
        }
        engine
            .put_entry(space, self.opening(), handle, entry)
            .await?;
        Ok(BlobId::from_bytes(handle))
    }

    /// Registers a hold of the object for this space at the connected
    /// peers, and waits for the first answer (ext-libraries.md, 3.7
    /// Registering a hold).
    #[cfg(all(
        feature = "ext-libraries",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    async fn hold(&self, locator: Locator, source: EventId, object_key: [u8; 32]) -> Result<()> {
        use crate::peer::holds::{HoldAsk, wait};
        let space = self.space().id().event();
        if source == space {
            return Ok(());
        }
        let device = &self.space().device;
        let peers: Vec<_> = device
            .peers_of(&space)
            .into_iter()
            .filter(|peer| !peer.handle().is_closed())
            .collect();
        if peers.is_empty() {
            return Ok(());
        }
        let answer = wait(device.engine().device_id(), space, locator);
        for peer in &peers {
            peer.handle().hold(HoldAsk {
                space,
                source,
                locator,
                object_key,
            });
        }
        tokio::select! {
            answer = answer => match answer {
                Ok(Ok(())) | Err(_) => Ok(()),
                Ok(Err(code)) => Err(refused(&code)),
            },
            () = device.sleep(HOLD_WAIT) => Ok(()),
        }
    }

    /// Without a peer binding or libraries, the connection has nothing to
    /// register.
    #[cfg(not(all(
        feature = "ext-libraries",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    )))]
    #[allow(clippy::unused_async)]
    async fn hold(&self, _: Locator, _: EventId, _: [u8; 32]) -> Result<()> {
        Ok(())
    }
}

/// A hold's refusal code as the client's error: the library class it
/// names, or a connection error with the code.
#[cfg(all(
    feature = "ext-libraries",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
fn refused(code: &str) -> Error {
    use frasil_base::errors::Class as _;
    match frasil_libraries::LibraryClass::from_wire_name(code) {
        Some(class) => Error::Class(class.name()),
        None => Error::Connection(format!("the peer refused the hold: {code}")),
    }
}
