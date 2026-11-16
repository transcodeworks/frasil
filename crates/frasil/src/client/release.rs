//! Releasing a stream's bytes at the space's peers, and restoring them
//! (peers.md, 3.18 Release and restore).

use super::{Space, StreamId, StreamKind};
use crate::error::Result;

impl Space {
    /// Releases a stream at the space's peers (peers.md, 3.18 Release and
    /// restore): a writer request that goes to every peer and replica.
    /// While the stream is released, peers answer `released` (410) for it,
    /// leave it out of listings, refuse its new units, and stop counting
    /// its bytes; after their retention they delete them. This device
    /// keeps what it holds, and writes nothing in the stream
    /// ([`Error::Released`](crate::Error::Released)) until a writer
    /// restores it with [`Space::restore_stream`]. Releasing a stream that
    /// is released already signs nothing.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`](crate::Error::NotAllowed) unless this device
    /// writes in the space; [`Error::SyncBeforeWriting`](crate::Error::SyncBeforeWriting);
    /// the store's.
    pub async fn release_stream(&self, stream: StreamId) -> Result<()> {
        self.device
            .engine()
            .release_stream(self.id().event(), *stream.as_bytes())
            .await
    }

    /// Restores a released stream: peers serve it again and take its new
    /// units, and count its bytes again; a peer refuses the restore with
    /// `quota_exceeded` when they no longer fit. A peer that reclaimed the
    /// stream after its retention serves only what members store again.
    /// Restoring a stream that is not released signs nothing.
    ///
    /// # Errors
    ///
    /// As [`Space::release_stream`].
    pub async fn restore_stream(&self, stream: StreamId) -> Result<()> {
        self.device
            .engine()
            .restore_stream(self.id().event(), *stream.as_bytes())
            .await
    }

    /// Whether a stream is released, as this device holds the space.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`](crate::Error::UnknownSpace).
    pub async fn is_released(&self, stream: StreamId) -> Result<bool> {
        self.device
            .engine()
            .stream_released(&self.id().event(), stream.as_bytes())
            .await
    }

    /// Releases every Loro document of the space but those in `keep` that
    /// is not released yet, as [`Space::release_stream`] does each, and
    /// returns them: for a restricted space whose documents the
    /// application discards for good. A drive is a Loro document: name it
    /// in `keep` to keep it. Tables and blob streams stay.
    ///
    /// # Errors
    ///
    /// As [`Space::release_stream`].
    pub async fn release_documents(&self, keep: &[StreamId]) -> Result<Vec<StreamId>> {
        let mut released = Vec::new();
        for info in self.streams().await? {
            if info.kind != StreamKind::Document
                || keep.contains(&info.id)
                || self.is_released(info.id).await?
            {
                continue;
            }
            self.release_stream(info.id).await?;
            released.push(info.id);
        }
        Ok(released)
    }
}

#[cfg(feature = "adapter-loro")]
impl super::Document {
    /// Releases the document at the space's peers: [`Space::release_stream`]
    /// of its stream.
    ///
    /// # Errors
    ///
    /// As [`Space::release_stream`].
    pub async fn release(&self) -> Result<()> {
        self.space.release_stream(self.id()).await
    }

    /// Restores the document: [`Space::restore_stream`] of its stream.
    ///
    /// # Errors
    ///
    /// As [`Space::restore_stream`].
    pub async fn restore(&self) -> Result<()> {
        self.space.restore_stream(self.id()).await
    }

    /// Whether the document is released.
    ///
    /// # Errors
    ///
    /// As [`Space::is_released`].
    pub async fn is_released(&self) -> Result<bool> {
        self.space.is_released(self.id()).await
    }
}
