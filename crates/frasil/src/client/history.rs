//! History through the client: who changed what, when, for a document or
//! a table, and a view of either as it stood.

#[cfg(feature = "adapter-loro")]
mod document {
    use crate::client::streams::Document;
    use crate::error::Result;
    use crate::history::Change;

    impl Document {
        /// The document's history: one [`Change`] per unit this device
        /// holds of it, oldest first, with its author as the roster names
        /// them, its span, and the versions before and after it. Reading
        /// it commits the transaction in flight on a lent document, as an
        /// export does.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`](crate::Error::UnknownSpace);
        /// [`Error::UnknownStream`](crate::Error::UnknownStream) before the
        /// document's first change reached this device.
        pub async fn history(&self) -> Result<Vec<Change>> {
            self.space
                .device
                .engine()
                .stream_history(self.space.id().event(), self.opening.stream())
                .await
        }

        /// The document as it stood at a version, the `before` or `after`
        /// of a change ([`DocumentChange`](crate::DocumentChange)): a copy
        /// of its own, which nothing it is given reaches the document.
        ///
        /// # Errors
        ///
        /// As [`Document::history`];
        /// [`Error::Adapter`](crate::Error::Adapter) when the document does
        /// not reach the version.
        pub async fn at(&self, version: &loro::Frontiers) -> Result<loro::LoroDoc> {
            self.space
                .device
                .engine()
                .document_at(self.space.id().event(), self.opening.stream(), version)
                .await
        }

        /// The document as it stood at a version, as a snapshot's bytes:
        /// what a reader that keeps a Loro document of its own imports, in
        /// one pass.
        ///
        /// # Errors
        ///
        /// As [`Document::at`].
        pub async fn snapshot_at(&self, version: &loro::Frontiers) -> Result<Vec<u8>> {
            self.space
                .device
                .engine()
                .document_snapshot_at(self.space.id().event(), self.opening.stream(), version)
                .await
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use crate::client::UnitId;
    use crate::client::streams::Records;
    use crate::error::Result;
    use crate::history::{Change, Replay, Tables};

    impl Records {
        /// The tables' history: one [`Change`] per unit this device holds
        /// of the stream, oldest first, with its author as the roster names
        /// them and the rows and columns it wrote.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`](crate::Error::UnknownSpace);
        /// [`Error::UnknownStream`](crate::Error::UnknownStream) before the
        /// stream's first change reached this device.
        pub async fn history(&self) -> Result<Vec<Change>> {
            self.space
                .device
                .engine()
                .stream_history(self.space.id().event(), self.opening.stream())
                .await
        }

        /// A walk of the tables' history from the base snapshot, one
        /// change at a time: [`Replay::step`](crate::Replay::step) applies
        /// the next change, and [`Replay::row`](crate::Replay::row) reads a
        /// row as it stood after it. The units are copied out once; a whole
        /// walk is linear in the changes.
        ///
        /// # Errors
        ///
        /// As [`Records::history`]; [`Error::Adapter`](crate::Error::Adapter)
        /// when the base snapshot does not decode.
        pub async fn replay(&self) -> Result<Replay> {
            self.space
                .device
                .engine()
                .records_replay(self.space.id().event(), self.opening.stream())
                .await
        }

        /// The tables as they stood after a change: a replay up to it, so
        /// that "from what" is the row at the change before. For a change a
        /// snapshot compacted, the tables as the snapshot holds them, which
        /// may hold later compacted changes too. Each call replays from the
        /// base; walk the whole history with [`Records::replay`].
        ///
        /// # Errors
        ///
        /// As [`Records::replay`];
        /// [`Error::Invalid`](crate::Error::Invalid) when no change of the
        /// stream has the ID.
        pub async fn at(&self, change: UnitId) -> Result<Tables> {
            let mut replay = self.replay().await?;
            replay.until(change)?;
            Ok(replay.tables())
        }
    }
}
