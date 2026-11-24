//! A space's streams, by the adapter that reads them: Loro documents,
//! Records tables and blobs.

#[cfg(any(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "adapter-blobs"
))]
use super::{Space, StreamId};
#[cfg(any(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "adapter-blobs"
))]
use crate::error::{Error, Result};
#[cfg(any(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "adapter-blobs"
))]
use frasil_units::stream::Opening;

#[cfg(any(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "adapter-blobs"
))]
impl Space {
    /// A new stream's opening, of this adapter type: the stream exists in
    /// the space from its first change.
    fn new_stream(&self, adapter_type: &str) -> Result<Opening> {
        self.device.engine().new_stream(adapter_type)
    }

    /// An existing stream's opening, if it is of this adapter type. A
    /// partial device opens the stream first, and fetches it.
    async fn existing(&self, id: StreamId, adapter_type: &'static str) -> Result<Opening> {
        self.device
            .engine()
            .hold_stream(self.id().event(), *id.as_bytes())
            .await?;
        let opening = self
            .read(|replica| replica.opening_of(id.as_bytes()))
            .await?
            .ok_or(Error::UnknownStream)?;
        if opening.type_ == adapter_type {
            Ok(opening)
        } else {
            Err(Error::Invalid("the stream is of another kind"))
        }
    }
}

#[cfg(feature = "adapter-loro")]
mod document {
    use super::{Error, Opening, Result, Space, StreamId};
    use crate::documents::TextWritten;
    use crate::text::{Stopped, compare_text, replace_text};
    use std::time::Duration;

    /// What [`Document::set_text`] does when its time limit passes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum OnLimit {
        /// Replaces the changed part of the text in one operation.
        #[default]
        Replace,
        /// Stops with [`Error::LimitPassed`], the document as it was.
        Stop,
    }

    /// How [`Document::set_text`] compares.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct SetText {
        /// How long the comparison may take. It holds up nothing else on
        /// the device, on a platform with threads.
        pub limit: Duration,
        /// What happens past it.
        pub on_limit: OnLimit,
    }

    impl SetText {
        /// These options with another limit.
        #[must_use]
        pub fn limit(mut self, limit: Duration) -> Self {
            self.limit = limit;
            self
        }

        /// These options, stopping at the limit rather than replacing.
        #[must_use]
        pub fn stop_at_limit(mut self) -> Self {
            self.on_limit = OnLimit::Stop;
            self
        }
    }

    impl Default for SetText {
        fn default() -> Self {
            Self {
                limit: Duration::from_secs(2),
                on_limit: OnLimit::default(),
            }
        }
    }

    /// A Loro document in a space. Each edit is one change, signed and
    /// sealed by this device; every member's edits merge.
    #[derive(Debug, Clone)]
    pub struct Document {
        pub(in crate::client) space: Space,
        pub(in crate::client) opening: Opening,
    }

    impl Space {
        /// Creates a Loro document. It exists in the space from its first
        /// edit.
        ///
        /// # Errors
        ///
        /// [`Error::NoRandomness`].
        pub fn create_document(&self) -> Result<Document> {
            Ok(Document {
                space: self.clone(),
                opening: self.new_stream(frasil_adapter_loro::TYPE)?,
            })
        }

        /// A Loro document of the space.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownStream`] until this device holds a change of it
        /// that names it: a newcomer holds a stream from before its
        /// admission once a member writes there again; [`Error::Invalid`]
        /// for a stream of another kind.
        pub async fn document(&self, id: StreamId) -> Result<Document> {
            Ok(Document {
                space: self.clone(),
                opening: self.existing(id, frasil_adapter_loro::TYPE).await?,
            })
        }
    }

    impl Document {
        /// The document's ID in its space.
        pub fn id(&self) -> StreamId {
            StreamId::from_bytes(self.opening.stream())
        }

        /// Its space.
        pub fn space(&self) -> &Space {
            &self.space
        }

        /// Edits the document: `edit` changes a copy of its current state,
        /// and the operations it makes are written as one change. Nothing
        /// is written when `edit` fails or makes no operation.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`] with the edit's failure, or when it made no
        /// operation; [`Error::NotAllowed`] unless this device writes in
        /// the space; [`Error::SyncBeforeWriting`];
        /// [`Error::RotationDue`].
        pub async fn edit<E: core::fmt::Display>(
            &self,
            edit: impl FnOnce(&loro::LoroDoc) -> core::result::Result<(), E>,
        ) -> Result<()> {
            self.space
                .device
                .engine()
                .try_edit_document(self.space.id().event(), &self.opening, edit)
                .await
                .map(drop)
        }

        /// Sets a text container, by its root name or its `ContainerID`, to
        /// `text`, writing only what differs: an edit within a line stays
        /// small and merges with another writer's.
        /// When most of it changed, or the time limit passes, the changed
        /// part is replaced in one operation instead. It works for a text
        /// of any size: a change too large for one unit goes in several,
        /// and a replica shows it once it holds them all. Fold what should
        /// not count as a change first ([`TextStyle::fold`](crate::TextStyle)).
        ///
        /// The comparison runs with the device free. A change that arrives
        /// during it is not overwritten: the two merge, and the result says
        /// so ([`TextWritten::moved`]). Read [`Document::text`] afterwards
        /// to see what the document holds.
        ///
        /// A change in several units writes each as its own commit. An
        /// error after the first, such as [`Error::Store`] when the disk
        /// fills, can leave some written and syncing: the text stays as it
        /// was at every replica, those units stay pending for good and
        /// show in history, and calling again writes the change anew.
        ///
        /// # Errors
        ///
        /// [`Error::LimitPassed`] past the limit under [`OnLimit::Stop`], the
        /// document as it was; [`Error::Adapter`] when Loro fails;
        /// [`Error::NotAllowed`] unless this device writes in the space, or
        /// when live handles hold every incarnation a unit could take;
        /// [`Error::SyncBeforeWriting`]; [`Error::RotationDue`];
        /// [`Error::Store`], possibly after some units were written.
        pub async fn set_text(
            &self,
            container: impl loro::IntoContainerId,
            text: &str,
            options: SetText,
        ) -> Result<TextWritten> {
            let text = text.to_owned();
            self.space
                .device
                .engine()
                .write_document_text(
                    self.space.id().event(),
                    &self.opening,
                    container,
                    move |current| match compare_text(&current, &text, options.limit) {
                        Ok(comparison) => Ok(comparison),
                        Err(Stopped) if options.on_limit == OnLimit::Replace => {
                            Ok(replace_text(&current, &text))
                        }
                        Err(Stopped) => Err(Error::LimitPassed),
                    },
                )
                .await
        }

        /// A copy of the document as this device holds it: empty before
        /// its first change.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn read(&self) -> Result<loro::LoroDoc> {
            match self
                .space
                .device
                .engine()
                .document(&self.space.id().event(), &self.opening.stream())
                .await
            {
                Err(Error::UnknownStream) => Ok(loro::LoroDoc::new()),
                read => read,
            }
        }

        /// The text of one of the document's text containers.
        ///
        /// # Errors
        ///
        /// As [`Document::read`].
        pub async fn text(&self, container: &str) -> Result<String> {
            Ok(self.read().await?.get_text(container).to_string())
        }

        /// Moves the document to another space this device writes in,
        /// such as a [restricted space](Space::create_restricted) of its
        /// own (ext-restricted-spaces.md, "Moved documents"): the new
        /// document starts from this one's current state, without its
        /// history, and this one ends there. An edit made here afterwards
        /// by a device that had not yet seen the move is re-applied in the
        /// new document by its author, once, if it writes there.
        ///
        /// # Errors
        ///
        /// [`Error::NotAllowed`] unless this device writes in both spaces,
        /// or for a document moved already; [`Error::UnknownStream`]
        /// before its first change; as [`Document::edit`].
        #[cfg(feature = "ext-restricted-spaces")]
        pub async fn move_to(&self, space: &Space) -> Result<Document> {
            let opening = self
                .space
                .device
                .engine()
                .move_stream(
                    self.space.id().event(),
                    self.opening.stream(),
                    space.id().event(),
                )
                .await?;
            Ok(Document {
                space: space.clone(),
                opening,
            })
        }

        /// Carves the document out for a guest (ext-restricted-spaces.md,
        /// "Creating a carve-out"): a new space that grants this one, which
        /// this space's administrator devices administer, takes the
        /// document, and this one ends. Invite the guest to the new space
        /// with [`Space::invite_guest`]; then, unless this device
        /// administers this space, [`Space::step_down`] there.
        ///
        /// # Errors
        ///
        /// [`Error::NotAllowed`] unless this device writes here and its
        /// grant propagates, or in a restricted space; as
        /// [`Document::move_to`].
        #[cfg(feature = "ext-restricted-spaces")]
        pub async fn carve_out(&self) -> Result<Document> {
            let made = self
                .space
                .device
                .engine()
                .create_carve_out(self.space.id().event(), self.opening.stream())
                .await?;
            Ok(Document {
                space: Space::new(
                    self.space.device.clone(),
                    crate::client::SpaceId::of(made.space),
                ),
                opening: made.opening,
            })
        }

        /// Where the document moved, once this device knows of the move and
        /// holds its new document: `None` while it has not moved, or this
        /// device does not reach the space it moved to.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        #[cfg(feature = "ext-restricted-spaces")]
        pub async fn moved(&self) -> Result<Option<Document>> {
            let record = self
                .space
                .read(|replica| replica.moved(&self.opening.stream()).cloned())
                .await?;
            let Some(record) = record else {
                return Ok(None);
            };
            let Ok(space) = self
                .space
                .device
                .space(super::super::SpaceId::of(record.to_space))
                .await
            else {
                return Ok(None);
            };
            Ok(space
                .document(StreamId::from_bytes(record.to_stream))
                .await
                .ok())
        }
    }
}

#[cfg(feature = "adapter-loro")]
pub use document::{Document, OnLimit, SetText};

#[cfg(feature = "adapter-records")]
mod records {
    use super::{Error, Opening, Result, Space, StreamId};
    use frasil_adapter_records::{Changeset, Op};
    use frasil_base::cbor::Value;
    use frasil_units::runtime::Stream;
    use std::collections::BTreeMap;

    /// A row: its columns' values. A cleared column is absent.
    pub type Row = BTreeMap<String, Value>;

    /// Who changed a row last, and when they say they did
    /// (adapter-records.md, section 2.3, "last change").
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct LastChange {
        /// The device that wrote the row's latest cell.
        pub author: crate::client::MemberId,
        /// The person whose device list vouched for that device at the
        /// change's place, as [`Author::person`](crate::Author::person):
        /// `None` for a device the roster granted directly. A replica that
        /// no longer holds the change, one that started from a snapshot,
        /// reads the roster and lists it holds now.
        pub person: Option<crate::client::MemberId>,
        /// The change that wrote it.
        pub change: crate::client::UnitId,
        /// The writer's wall clock when it wrote, in seconds since
        /// 1970-01-01T00:00:00Z, if it recorded one. It is the writer's
        /// claim, which no device checks: show it as the writer's own.
        pub time: Option<u64>,
    }

    impl LastChange {
        /// Who made the change: its [`person`](Self::person), or its
        /// device when no person vouched for it.
        pub fn who(&self) -> crate::client::MemberId {
            self.person.unwrap_or(self.author)
        }
    }

    /// A visible row with its last change, from
    /// [`Records::rows_with_metadata`] and [`Records::row_with_metadata`].
    #[derive(Debug, Clone, PartialEq)]
    #[non_exhaustive]
    pub struct RowWithMetadata {
        /// Its columns' values.
        pub row: Row,
        /// Who changed it last, and when they say they did: what
        /// [`Records::last_change`] gives for the row.
        pub last_change: LastChange,
    }

    /// The last change of a row's cells, with its author's person.
    fn last_of(
        replica: &crate::replica::Replica,
        cells: &BTreeMap<String, frasil_adapter_records::state::Cell>,
    ) -> Option<LastChange> {
        let cell = cells.values().max_by_key(|cell| cell.stamp)?;
        let author = crate::history::author(
            replica,
            cell.stamp.event_id,
            frasil_crypto::device::DeviceId(cell.stamp.author),
        );
        Some(LastChange {
            author: author.device,
            person: author.person,
            change: crate::client::UnitId::from_bytes(cell.stamp.event_id),
            time: cell.time,
        })
    }

    /// A row's visible columns and last change, when its marker shows it
    /// (adapter-records.md, section 2.1).
    fn with_metadata(
        replica: &crate::replica::Replica,
        cells: &BTreeMap<String, frasil_adapter_records::state::Cell>,
    ) -> Option<RowWithMetadata> {
        let shows = cells
            .get(frasil_adapter_records::changeset::MARKER)
            .is_some_and(|marker| marker.value == Some(Value::Unsigned(1)));
        if !shows {
            return None;
        }
        let row = cells
            .iter()
            .filter(|(column, _)| column.as_str() != frasil_adapter_records::changeset::MARKER)
            .filter_map(|(column, cell)| Some((column.clone(), cell.value.clone()?)))
            .collect();
        Some(RowWithMetadata {
            row,
            last_change: last_of(replica, cells)?,
        })
    }

    /// Tables of rows in a space (adapter-records.md). Each write is one
    /// change; for each cell, the latest write wins.
    #[derive(Debug, Clone)]
    pub struct Records {
        pub(in crate::client) space: Space,
        pub(in crate::client) opening: Opening,
    }

    /// The cells one write changes, as one change.
    #[derive(Debug, Default)]
    pub struct Transaction {
        ops: Vec<Op>,
        /// Whether the write is a suggestion ([`Transaction::suggest`]).
        pub(in crate::client) suggestion: bool,
    }

    impl Transaction {
        /// Inserts a row, or keeps it: a row shows once inserted.
        pub fn insert(&mut self, table: &str, key: &[u8]) -> &mut Self {
            self.ops.push(Op::insert_row(table, key));
            self
        }

        /// Sets a cell.
        pub fn set(
            &mut self,
            table: &str,
            key: &[u8],
            column: &str,
            value: impl Into<Value>,
        ) -> &mut Self {
            self.ops.push(Op::set(table, key, column, value.into()));
            self
        }

        /// Clears a cell.
        pub fn clear(&mut self, table: &str, key: &[u8], column: &str) -> &mut Self {
            self.ops.push(Op::clear(table, key, column));
            self
        }

        /// Deletes a row.
        pub fn delete(&mut self, table: &str, key: &[u8]) -> &mut Self {
            self.ops.push(Op::delete_row(table, key));
            self
        }
    }

    fn state<'r>(
        replica: &'r crate::replica::Replica,
        stream: &frasil_units::stream::StreamId,
    ) -> Option<&'r frasil_adapter_records::State> {
        replica
            .stream(stream)?
            .as_any()
            .downcast_ref::<Stream<frasil_adapter_records::Records>>()
            .map(Stream::state)
    }

    /// The Records state of a stream, if the replica reads it.
    pub(in crate::client) fn records_state<'r>(
        replica: &'r crate::replica::Replica,
        stream: &frasil_units::stream::StreamId,
    ) -> Option<&'r frasil_adapter_records::State> {
        state(replica, stream)
    }

    impl Transaction {
        /// The ops so far.
        pub(in crate::client) fn ops(&self) -> &[Op] {
            &self.ops
        }

        /// Adds ops.
        pub(in crate::client) fn extend(&mut self, ops: impl IntoIterator<Item = Op>) {
            self.ops.extend(ops);
        }
    }

    impl Space {
        /// Creates a set of Records tables. It exists in the space from its
        /// first write.
        ///
        /// # Errors
        ///
        /// [`Error::NoRandomness`].
        pub fn create_records(&self) -> Result<Records> {
            Ok(Records {
                space: self.clone(),
                opening: self.new_stream(frasil_adapter_records::TYPE)?,
            })
        }

        /// Records tables of the space.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownStream`] until this device holds a change of
        /// them; [`Error::Invalid`] for a stream of another kind.
        pub async fn records(&self, id: StreamId) -> Result<Records> {
            Ok(Records {
                space: self.clone(),
                opening: self.existing(id, frasil_adapter_records::TYPE).await?,
            })
        }
    }

    impl Records {
        /// The stream's ID in its space.
        pub fn id(&self) -> StreamId {
            StreamId::from_bytes(self.opening.stream())
        }

        /// Its space.
        pub fn space(&self) -> &Space {
            &self.space
        }

        /// Writes the cells `write` sets, as one change.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`] when it sets none, or one does not read;
        /// [`Error::NotAllowed`] unless this device writes in the space;
        /// [`Error::SyncBeforeWriting`]; [`Error::RotationDue`].
        pub async fn write(&self, write: impl FnOnce(&mut Transaction)) -> Result<()> {
            let mut transaction = Transaction::default();
            write(&mut transaction);
            self.write_transaction(transaction).await
        }

        /// Writes a transaction's cells as one change.
        pub(in crate::client) async fn write_transaction(
            &self,
            transaction: Transaction,
        ) -> Result<()> {
            self.write_unit(transaction).await.map(drop)
        }

        /// Writes a transaction's cells as one change, and returns its
        /// unit's ID.
        pub(in crate::client) async fn write_unit(
            &self,
            transaction: Transaction,
        ) -> Result<frasil_events::EventId> {
            if transaction.ops.is_empty() {
                return Err(Error::Adapter("the write sets no cell".into()));
            }
            let stream = self.opening.stream();
            // The writer's wall clock, its claim (adapter-records.md,
            // section 2.2, key 7): none when the device has no wall clock.
            let time = self.space.device.engine().wall_clock();
            self.space
                .device
                .engine()
                .write_unit(self.space.id().event(), &self.opening, |replica, _| {
                    let clock = state(replica, &stream).map_or(1, |s| s.next_clock());
                    let mut changeset = Changeset::new(clock, transaction.ops);
                    changeset.keys.suggestion = transaction.suggestion;
                    changeset.time = time;
                    let content = changeset.encode();
                    // What every replica would refuse is never written: a
                    // NaN, a value nested too deep (adapter-records.md,
                    // section 2.1).
                    Changeset::read(&content).map_err(|class| {
                        Error::Adapter(format!(
                            "the write does not read: {}",
                            frasil_base::errors::Class::name(class)
                        ))
                    })?;
                    Ok(content)
                })
                .await
        }

        /// The rows of a table, by key.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn rows(&self, table: &str) -> Result<BTreeMap<Vec<u8>, Row>> {
            let stream = self.opening.stream();
            self.space
                .read(|replica| {
                    let Some(state) = state(replica, &stream) else {
                        return BTreeMap::new();
                    };
                    state
                        .rows()
                        .remove(table)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(key, columns)| {
                            let row = columns
                                .into_iter()
                                .filter_map(|(column, value)| Some((column, value?)))
                                .collect();
                            (key, row)
                        })
                        .collect()
                })
                .await
        }

        /// One row of a table, if it shows.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn row(&self, table: &str, key: &[u8]) -> Result<Option<Row>> {
            Ok(self
                .row_with_metadata(table, key)
                .await?
                .map(|found| found.row))
        }

        /// Who changed a row last, in which change, and when the writer
        /// says it did: the row's cell with the greatest stamp, its marker
        /// included, cleared or deleted ones too (adapter-records.md,
        /// section 2.3). `None` while no cell of the row is written. A
        /// replica that starts from a snapshot gives the same answer as
        /// one that holds every change.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn last_change(&self, table: &str, key: &[u8]) -> Result<Option<LastChange>> {
            let stream = self.opening.stream();
            self.space
                .device
                .engine()
                .read(&self.space.id().event(), |replica| {
                    let cells = state(replica, &stream)?.tables().get(table)?.get(key)?;
                    last_of(replica, cells)
                })
                .await
        }

        /// The visible rows of a table, by key, each with its last change:
        /// what [`Records::rows`] and [`Records::last_change`] give for
        /// each row, read in one pass under one lock.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn rows_with_metadata(
            &self,
            table: &str,
        ) -> Result<BTreeMap<Vec<u8>, RowWithMetadata>> {
            let stream = self.opening.stream();
            self.space
                .device
                .engine()
                .read(&self.space.id().event(), |replica| {
                    let Some(rows) = state(replica, &stream).and_then(|s| s.tables().get(table))
                    else {
                        return BTreeMap::new();
                    };
                    rows.iter()
                        .filter_map(|(key, cells)| {
                            Some((key.clone(), with_metadata(replica, cells)?))
                        })
                        .collect()
                })
                .await
        }

        /// One visible row of a table with its last change, if it shows.
        /// It reads that row's cells alone, not the table.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn row_with_metadata(
            &self,
            table: &str,
            key: &[u8],
        ) -> Result<Option<RowWithMetadata>> {
            let stream = self.opening.stream();
            self.space
                .device
                .engine()
                .read(&self.space.id().event(), |replica| {
                    let cells = state(replica, &stream)?.tables().get(table)?.get(key)?;
                    with_metadata(replica, cells)
                })
                .await
        }
    }
}

#[cfg(feature = "adapter-records")]
pub(in crate::client) use records::records_state;
#[cfg(feature = "adapter-records")]
pub use records::{LastChange, Records, Row, RowWithMetadata, Transaction};

#[cfg(feature = "adapter-blobs")]
mod blobs {
    use super::{Error, Opening, Result, Space, StreamId};
    use crate::client::{BlobId, Read};
    use frasil_units::runtime::Stream;

    /// Blobs in a space (adapter-blobs.md): files and other bytes, each
    /// sealed as an object, which peers keep and members fetch.
    #[derive(Debug, Clone)]
    pub struct Blobs {
        space: Space,
        opening: Opening,
    }

    /// A blob a blob stream holds.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Blob {
        /// Its ID in the stream.
        pub id: BlobId,
        /// Its name, if it was given one.
        pub name: Option<String>,
        /// Its size in bytes.
        pub size: u64,
    }

    impl Space {
        /// Creates a blob stream. It exists in the space from its first
        /// blob.
        ///
        /// # Errors
        ///
        /// [`Error::NoRandomness`].
        pub fn create_blobs(&self) -> Result<Blobs> {
            Ok(Blobs {
                space: self.clone(),
                opening: self.new_stream(frasil_adapter_blobs::TYPE)?,
            })
        }

        /// A blob stream of the space.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownStream`] until this device holds a change of
        /// it; [`Error::Invalid`] for a stream of another kind.
        pub async fn blobs(&self, id: StreamId) -> Result<Blobs> {
            Ok(Blobs {
                space: self.clone(),
                opening: self.existing(id, frasil_adapter_blobs::TYPE).await?,
            })
        }
    }

    impl Blobs {
        /// The stream's ID in its space.
        pub fn id(&self) -> StreamId {
            StreamId::from_bytes(self.opening.stream())
        }

        /// Its space.
        pub fn space(&self) -> &Space {
            &self.space
        }

        /// Its opening, for writing in it.
        pub(crate) fn opening(&self) -> &Opening {
            &self.opening
        }

        /// Puts a blob, with a name if given. The bytes are sealed in
        /// memory, beside them: for a large file, [`Blobs::put_file`] and
        /// [`Blobs::put_at`] hold a few chunks at a time instead.
        ///
        /// # Errors
        ///
        /// `TooLarge`; [`Error::NotAllowed`] unless this device writes in
        /// the space; [`Error::SyncBeforeWriting`]; [`Error::RotationDue`].
        pub async fn put(&self, name: Option<&str>, bytes: &[u8]) -> Result<BlobId> {
            let engine = self.space.device.engine();
            let handle = engine.platform().nonce::<16>()?;
            engine
                .put_blob_under(self.space.id().event(), &self.opening, handle, name, bytes)
                .await?;
            Ok(BlobId::from_bytes(handle))
        }

        /// The blobs the stream holds.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn list(&self) -> Result<Vec<Blob>> {
            let stream = self.opening.stream();
            self.space
                .read(|replica| {
                    let Some(state) = replica
                        .stream(&stream)
                        .and_then(|s| {
                            s.as_any()
                                .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()
                        })
                        .map(Stream::state)
                    else {
                        return Vec::new();
                    };
                    state
                        .current()
                        .map(|(handle, entry)| Blob {
                            id: BlobId::from_bytes(*handle),
                            name: entry.name.clone(),
                            size: entry.size,
                        })
                        .collect()
                })
                .await
        }

        /// A blob's bytes. A blob this device holds, kept or cached, is
        /// read from the device; one it does not hold whole is fetched
        /// first from a connected peer or member, and then left in the
        /// cache, kept, or dropped again as `read` says ([`Read`]).
        /// `None` when the blob is not here and is not fetched: the read
        /// is [`local`](Read::local), or neither a peer nor a member of
        /// the space is connected. A reference reads like any blob, with
        /// the key it carries.
        ///
        /// The bytes are gathered whole in memory: for a large blob,
        /// [`Blobs::get_stream`] writes them out chunk by chunk.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when the stream holds no blob of this ID;
        /// [`Error::Timeout`] when the fetch stops moving;
        /// `ObjectMismatch` or `Malformed` as soon as every connection of
        /// the space gave the blob up because what it was sent failed its
        /// checks; a class when the bytes do not open; [`Error::NotAllowed`] for a read that
        /// [`keep`](Read::keep)s in a space this device keeps in memory
        /// alone; [`Error::Unsupported`] for an
        /// [`uncached`](Read::uncached) read that would fetch in a space
        /// whose blobs the application holds as files, where each blob
        /// fetched becomes a file.
        pub async fn get(&self, id: BlobId, read: &Read) -> Result<Option<Vec<u8>>> {
            let entry = self.entry(id).await?;
            let mut progress = crate::client::blob_stream::Reporter::silent();
            let reading = match self.ready(&entry, read, &mut progress).await {
                Ok(Some(reading)) => reading,
                Ok(None) | Err(Error::Class("Missing")) => return Ok(None),
                Err(error) => return Err(error),
            };
            let bytes = self.open_entry(&entry).await;
            reading.done().await?;
            match bytes {
                Ok(bytes) => Ok(Some(bytes)),
                Err(Error::Class("Missing")) => Ok(None),
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(feature = "adapter-blobs")]
pub use blobs::{Blob, Blobs};
