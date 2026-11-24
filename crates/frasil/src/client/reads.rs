//! Reads for applications that cache and show synced data: waiting for
//! what has not arrived, observed reads of each stream, a blob's status,
//! ranges of rows, and receipts for single writes.

#[cfg(any(feature = "adapter-records", feature = "adapter-blobs"))]
use super::observe::key;
use super::observe::not_arrived;
#[cfg(any(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "adapter-blobs"
))]
use super::{Observed, StreamId, observe::Scope};
use super::{Space, UnitId};
use crate::error::{Error, Result};
use frasil_events::EventId;
use std::future::Future;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

impl Space {
    /// Runs `attempt` until it succeeds, or fails otherwise than with
    /// something not yet arrived ([`Error::UnknownStream`], `Missing`):
    /// again after each change of the space and each blob that arrives,
    /// for at most `within`.
    #[cfg_attr(
        not(any(
            feature = "adapter-loro",
            feature = "adapter-records",
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) async fn when_available<T, Fut>(
        &self,
        within: Duration,
        attempt: impl Fn() -> Fut,
    ) -> Result<T>
    where
        Fut: Future<Output = Result<T>>,
    {
        let engine = self.device.engine();
        let space = self.id().event();
        // Subscribed before the first attempt, so that nothing that
        // arrives between the two is missed.
        let mut notices = engine.subscribe();
        let mut arrivals = engine.subscribe_arrivals();
        let mut deadline = self.device.sleep(within);
        loop {
            match attempt().await {
                Err(error) if not_arrived(&error) => {}
                done => return done,
            }
            loop {
                tokio::select! {
                    () = &mut deadline => return Err(Error::Timeout),
                    notice = notices.recv() => match notice {
                        Ok(notice) if notice.space == space && !notice.placed.is_empty() => break,
                        Ok(_) => {}
                        Err(RecvError::Lagged(_)) => break,
                        Err(RecvError::Closed) => return Err(Error::Timeout),
                    },
                    arrival = arrivals.recv() => match arrival {
                        Ok((from, _)) if from == space => break,
                        Ok(_) => {}
                        Err(RecvError::Lagged(_)) => break,
                        Err(RecvError::Closed) => return Err(Error::Timeout),
                    },
                }
            }
        }
    }
}

/// A receipt for one write: the change it made, and whether a peer keeps
/// it yet. From [`Records::write_with_receipt`](super::Records::write_with_receipt)
/// and the other `with_receipt` methods.
#[derive(Debug, Clone)]
pub struct Receipt {
    space: Space,
    unit: EventId,
}

impl Receipt {
    #[cfg_attr(
        not(any(
            feature = "adapter-loro",
            feature = "adapter-records",
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) fn new(space: &Space, unit: EventId) -> Self {
        Self {
            space: space.clone(),
            unit,
        }
    }

    /// The change the write made.
    pub fn unit(&self) -> UnitId {
        UnitId::from_bytes(self.unit.0)
    }

    /// Whether a peer acknowledged the change, so that it no longer
    /// depends on this device (the same acknowledgement as
    /// [`Space::flush`]).
    pub async fn is_durable(&self) -> bool {
        !self
            .space
            .device
            .engine()
            .outbox(&self.space.id().event())
            .await
            .contains(&self.unit)
    }

    /// Waits until the change is durable, for at most `within`; the other
    /// changes of the space may still be pending. It wakes on each
    /// acknowledgement the device takes for the space.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when no peer acknowledged it in time: it stays
    /// on this device, which sends it once it reaches a peer.
    pub async fn durable(&self, within: Duration) -> Result<()> {
        let engine = self.space.device.engine();
        let space = self.space.id().event();
        // Subscribed before the first look, so that no acknowledgement
        // between the two is missed.
        let mut notices = engine.subscribe();
        let mut deadline = self.space.device.sleep(within);
        loop {
            if self.is_durable().await {
                return Ok(());
            }
            loop {
                tokio::select! {
                    () = &mut deadline => {
                        return Err(Error::Connection(
                            "no peer holds this change yet; it stays on this device".into(),
                        ));
                    }
                    notice = notices.recv() => match notice {
                        Ok(notice) if notice.space == space => break,
                        Ok(_) => {}
                        Err(RecvError::Lagged(_)) => break,
                        Err(RecvError::Closed) => {
                            return Err(Error::Connection("the device is closed".into()));
                        }
                    },
                }
            }
        }
    }
}

#[cfg(feature = "adapter-loro")]
mod document {
    use super::{Duration, Observed, Receipt, Result, Scope, Space, StreamId};
    use crate::client::Document;
    use frasil_store::store::{MaybeSend, MaybeSync};

    impl Space {
        /// A Loro document of the space, once this device holds it: at
        /// once if it does, else as soon as a change of it arrives, for at
        /// most `within`.
        ///
        /// # Errors
        ///
        /// [`crate::Error::Timeout`] when it has not arrived in time;
        /// [`crate::Error::Invalid`] for a stream of another kind.
        pub async fn document_when_available(
            &self,
            id: StreamId,
            within: Duration,
        ) -> Result<Document> {
            self.when_available(within, || self.document(id)).await
        }
    }

    impl Document {
        /// Observes a read of the document: `read` runs on a copy of it
        /// now, then again after each change of it, and the [`Observed`]
        /// tells its observers each time the result differs.
        pub fn observe<T, F>(&self, read: F) -> Observed<T>
        where
            T: PartialEq + MaybeSend + MaybeSync + 'static,
            F: Fn(&loro::LoroDoc) -> T + MaybeSend + MaybeSync + 'static,
        {
            let read = std::sync::Arc::new(read);
            let document = self.clone();
            self.space.device.observed(
                None,
                &self.space,
                Scope::stream(&self.space, self.opening.stream()),
                move |_| {
                    let (document, read) = (document.clone(), read.clone());
                    async move { Ok(read(&document.read().await?)) }
                },
            )
        }

        /// Edits the document as [`Document::edit`] does, and returns a
        /// [`Receipt`] for the change.
        ///
        /// # Errors
        ///
        /// As [`Document::edit`].
        pub async fn edit_with_receipt<E: core::fmt::Display>(
            &self,
            edit: impl FnOnce(&loro::LoroDoc) -> core::result::Result<(), E>,
        ) -> Result<Receipt> {
            let unit = self
                .space
                .device
                .engine()
                .try_edit_document(self.space.id().event(), &self.opening, edit)
                .await?;
            Ok(Receipt::new(&self.space, unit))
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use super::{Duration, Observed, Receipt, Result, Scope, Space, StreamId, key};
    use crate::client::streams::records_state;
    use crate::client::{Records, Row, Transaction};
    use frasil_adapter_records::changeset::MARKER;
    use frasil_base::cbor::Value;
    use std::collections::BTreeMap;
    use std::ops::Bound;

    /// A row's visible columns, when its marker shows it
    /// (adapter-records.md, section 2.1).
    fn visible(cells: &BTreeMap<String, frasil_adapter_records::state::Cell>) -> Option<Row> {
        let shows = cells
            .get(MARKER)
            .is_some_and(|marker| marker.value == Some(Value::Unsigned(1)));
        shows.then(|| {
            cells
                .iter()
                .filter(|(column, _)| column.as_str() != MARKER)
                .filter_map(|(column, cell)| Some((column.clone(), cell.value.clone()?)))
                .collect()
        })
    }

    impl Space {
        /// Records tables of the space, once this device holds them: at
        /// once if it does, else as soon as a change of them arrives, for
        /// at most `within`.
        ///
        /// # Errors
        ///
        /// [`crate::Error::Timeout`] when they have not arrived in time;
        /// [`crate::Error::Invalid`] for a stream of another kind.
        pub async fn records_when_available(
            &self,
            id: StreamId,
            within: Duration,
        ) -> Result<Records> {
            self.when_available(within, || self.records(id)).await
        }
    }

    impl Records {
        /// The visible rows of a table, in key order, from the first key
        /// after `after` (from the first key for `None`), at most `limit`
        /// of them. Pass the last key read as `after` for the next page.
        ///
        /// # Errors
        ///
        /// [`crate::Error::UnknownSpace`].
        pub async fn rows_range(
            &self,
            table: &str,
            after: Option<&[u8]>,
            limit: usize,
        ) -> Result<Vec<(Vec<u8>, Row)>> {
            let stream = self.opening.stream();
            let start = after.map_or(Bound::Unbounded, |key| Bound::Excluded(key.to_vec()));
            self.space
                .read(|replica| {
                    let Some(rows) =
                        records_state(replica, &stream).and_then(|s| s.tables().get(table))
                    else {
                        return Vec::new();
                    };
                    rows.range((start, Bound::Unbounded))
                        .filter_map(|(key, cells)| Some((key.clone(), visible(cells)?)))
                        .take(limit)
                        .collect()
                })
                .await
        }

        /// The visible rows of a table whose keys start with `prefix`, in
        /// key order.
        ///
        /// # Errors
        ///
        /// [`crate::Error::UnknownSpace`].
        pub async fn rows_with_prefix(
            &self,
            table: &str,
            prefix: &[u8],
        ) -> Result<BTreeMap<Vec<u8>, Row>> {
            let stream = self.opening.stream();
            self.space
                .read(|replica| {
                    let Some(rows) =
                        records_state(replica, &stream).and_then(|s| s.tables().get(table))
                    else {
                        return BTreeMap::new();
                    };
                    rows.range(prefix.to_vec()..)
                        .take_while(|(key, _)| key.starts_with(prefix))
                        .filter_map(|(key, cells)| Some((key.clone(), visible(cells)?)))
                        .collect()
                })
                .await
        }

        /// Observes a table's rows, as [`Records::rows`] reads them. Every
        /// observer of the same table shares one reader.
        pub fn observe_rows(&self, table: &str) -> Observed<BTreeMap<Vec<u8>, Row>> {
            let stream = self.opening.stream();
            let records = self.clone();
            let name = table.to_owned();
            self.space.device.observed(
                Some(key(&self.space, &stream, "rows", &[table.as_bytes()])),
                &self.space,
                Scope::stream(&self.space, stream),
                move |_| {
                    let (records, name) = (records.clone(), name.clone());
                    async move { records.rows(&name).await }
                },
            )
        }

        /// Observes one row, as [`Records::row`] reads it: `None` while it
        /// does not show. Every observer of the same row shares one reader.
        pub fn observe_row(&self, table: &str, row: &[u8]) -> Observed<Option<Row>> {
            let stream = self.opening.stream();
            let records = self.clone();
            let (name, row_key) = (table.to_owned(), row.to_vec());
            self.space.device.observed(
                Some(key(&self.space, &stream, "row", &[table.as_bytes(), row])),
                &self.space,
                Scope::stream(&self.space, stream),
                move |_| {
                    let (records, name, row_key) = (records.clone(), name.clone(), row_key.clone());
                    async move { records.row(&name, &row_key).await }
                },
            )
        }

        /// Writes the cells `write` sets, as [`Records::write`] does, and
        /// returns a [`Receipt`] for the change.
        ///
        /// # Errors
        ///
        /// As [`Records::write`].
        pub async fn write_with_receipt(
            &self,
            write: impl FnOnce(&mut Transaction),
        ) -> Result<Receipt> {
            let mut transaction = Transaction::default();
            write(&mut transaction);
            let unit = self.write_unit(transaction).await?;
            Ok(Receipt::new(&self.space, unit))
        }
    }
}

#[cfg(feature = "adapter-blobs")]
mod blobs {
    use super::{Duration, Error, Observed, Result, Scope, Space, StreamId, key};
    use crate::client::{Blob, BlobId, Blobs, Read};

    /// Where a blob's bytes stand on this device, from [`Blobs::status`].
    /// [`Blobs::local`] tells whether a blob the device holds is kept or
    /// cached.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum BlobStatus {
        /// The device holds the bytes whole, kept or cached: a read gives
        /// them at once, with no connection.
        Readable,
        /// A peer or member is sending them: `done` of `total` bytes.
        Fetching {
            /// The bytes fetched so far, by share of the object.
            done: u64,
            /// The blob's size.
            total: u64,
        },
        /// The device does not hold them, and a peer or a member of the
        /// space is connected: a read fetches them now. The device never
        /// fetched them, or dropped them since.
        Absent,
        /// The device does not hold them, and neither a peer nor a member
        /// of the space is connected, so a read cannot fetch them now. A
        /// blob whose key has not arrived is [`BlobStatus::KeysPending`].
        Missing,
        /// The device cannot open the blob yet: the key of the state its
        /// bytes, or the change that adds it, are sealed under has not
        /// reached this device. It opens once a member or a peer delivers
        /// that key; connecting changes nothing until then.
        KeysPending,
        /// The device held them as a held object, and its file changed or
        /// is gone (at-rest.md, "Held objects"). They stay fetchable from
        /// peers and members.
        Withdrawn,
    }

    impl Space {
        /// A blob stream of the space, once this device holds it: at once
        /// if it does, else as soon as a change of it arrives, for at most
        /// `within`.
        ///
        /// # Errors
        ///
        /// [`crate::Error::Timeout`] when it has not arrived in time;
        /// [`crate::Error::Invalid`] for a stream of another kind.
        pub async fn blobs_when_available(&self, id: StreamId, within: Duration) -> Result<Blobs> {
            self.when_available(within, || self.blobs(id)).await
        }
    }

    impl Blobs {
        /// Where a blob's bytes stand on this device: readable, being
        /// fetched, absent, missing or withdrawn.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when the stream holds no blob of this ID.
        pub async fn status(&self, id: BlobId) -> Result<BlobStatus> {
            let stream = self.opening().stream();
            let entry = match self.entry(id).await {
                Ok(entry) => entry,
                // Not listed yet, while a change of the stream waits for its
                // key: it may be the one that adds the blob.
                Err(error @ Error::Invalid(_)) => {
                    let awaits = self
                        .space()
                        .read(|replica| replica.stream_awaits_keys(&stream))
                        .await
                        .unwrap_or(false);
                    return if awaits {
                        Ok(BlobStatus::KeysPending)
                    } else {
                        Err(error)
                    };
                }
                Err(error) => return Err(error),
            };
            // A blob stored in this space opens under its object's state; a
            // reference carries its own key.
            let awaits_key = entry.reference.is_none()
                && self
                    .space()
                    .read(|replica| replica.object_awaits_key(&entry.object))
                    .await
                    .unwrap_or(false);
            if self.holds_entry(&entry).await {
                return Ok(if awaits_key {
                    BlobStatus::KeysPending
                } else {
                    BlobStatus::Readable
                });
            }
            let engine = self.space().device.engine();
            let mut object_id = [0; 32];
            object_id.copy_from_slice(&entry.object[..32]);
            if engine.is_withdrawn(&self.space().id().event(), &object_id) {
                return Ok(BlobStatus::Withdrawn);
            }
            Ok(match self.fetch_progress(entry.object, entry.size).await {
                Some(done) => BlobStatus::Fetching {
                    done,
                    total: entry.size,
                },
                None if awaits_key => BlobStatus::KeysPending,
                None if self.can_fetch() => BlobStatus::Absent,
                None => BlobStatus::Missing,
            })
        }

        /// Whether the change that put a blob is durable, as
        /// [`Space::is_durable`] counts changes: false while this device
        /// put it and no always-on peer acknowledged that change. A peer
        /// takes a put's object before its unit, so once true a peer of the
        /// space holds the blob; in a space with no always-on peer, a
        /// member's acknowledgement counts instead, and a member fetches
        /// the bytes after the unit. A blob another device put is durable
        /// here. The answer outlives a reopen: the device's record of what
        /// is not yet acknowledged is kept in its store.
        ///
        /// [`Event::PendingChanges`](crate::Event::PendingChanges) tells
        /// when to ask again.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when the stream holds no blob of this ID.
        pub async fn is_durable(&self, id: BlobId) -> Result<bool> {
            let unit = self
                .units()
                .await?
                .into_iter()
                .find_map(|(handle, unit)| (handle == id).then_some(unit))
                .ok_or(Error::Invalid("the stream holds no blob of this ID"))?;
            let space = self.space().id().event();
            let outbox = self.space().device.engine().outbox(&space).await;
            Ok(!outbox.contains(&unit))
        }

        /// The blobs of the stream whose put is not durable yet, as
        /// [`Blobs::is_durable`] says: those this device put and no peer
        /// has acknowledged, ascending by ID. After a reopen it lists what
        /// the device uploads once it connects.
        ///
        /// # Errors
        ///
        /// As [`Blobs::list`].
        pub async fn pending(&self) -> Result<Vec<BlobId>> {
            let space = self.space().id().event();
            let outbox = self.space().device.engine().outbox(&space).await;
            if outbox.is_empty() {
                return Ok(Vec::new());
            }
            Ok(self
                .units()
                .await?
                .into_iter()
                .filter(|(_, unit)| outbox.contains(unit))
                .map(|(id, _)| id)
                .collect())
        }

        /// Each current blob of the stream, with the event ID of the unit
        /// that put it.
        async fn units(&self) -> Result<Vec<(BlobId, frasil_events::EventId)>> {
            let stream = *self.id().as_bytes();
            self.space()
                .read(|replica| {
                    replica
                        .stream(&stream)
                        .and_then(|runtime| {
                            runtime
                                .as_any()
                                .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_blobs::Blobs>>()
                        })
                        .map(|blobs| {
                            blobs
                                .state()
                                .slots()
                                .iter()
                                .filter(|(_, slot)| slot.entry.is_some())
                                .map(|(handle, slot)| {
                                    (
                                        BlobId::from_bytes(*handle),
                                        frasil_events::EventId(slot.stamp.event_id),
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .await
        }

        /// A blob's bytes, as [`Blobs::get`] reads them with
        /// [`Read::new`], within a deadline: at once when this device holds
        /// them, else fetched into the cache, for at most `within`. While
        /// nothing is connected that could send them, it waits for the
        /// space to change and tries again.
        ///
        /// # Errors
        ///
        /// [`Error::Timeout`] when they are not here in time; as
        /// [`Blobs::get`].
        pub async fn get_when_available(&self, id: BlobId, within: Duration) -> Result<Vec<u8>> {
            let deadline = self.space().device.sleep(within);
            let read = Read::new();
            let got = self.space().when_available(within, || async {
                self.get(id, &read).await?.ok_or(Error::Class("Missing"))
            });
            tokio::pin!(deadline);
            tokio::select! {
                () = &mut deadline => Err(Error::Timeout),
                got = got => got,
            }
        }

        /// Observes the blobs the stream holds, as [`Blobs::list`] reads
        /// them. Every observer of the stream shares one reader.
        pub fn observe_list(&self) -> Observed<Vec<Blob>> {
            let stream = self.opening().stream();
            let space = self.space();
            let blobs = self.clone();
            space.device.observed(
                Some(key(space, &stream, "list", &[])),
                space,
                Scope::stream(space, stream),
                move |_| {
                    let blobs = blobs.clone();
                    async move { blobs.list().await }
                },
            )
        }

        /// Observes a blob's [`status`](Blobs::status), as its bytes arrive
        /// or are withdrawn. Every observer of the blob shares one reader.
        pub fn observe_status(&self, id: BlobId) -> Observed<BlobStatus> {
            let stream = self.opening().stream();
            let space = self.space();
            let blobs = self.clone();
            space.device.observed(
                Some(key(space, &stream, "status", &[id.as_bytes()])),
                space,
                Scope::stream(space, stream).with_objects(),
                move |_| {
                    let blobs = blobs.clone();
                    async move { blobs.status(id).await }
                },
            )
        }
    }
}

#[cfg(feature = "adapter-blobs")]
pub use blobs::BlobStatus;
