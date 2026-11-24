//! Drives (ext-drive.md): a tree of folders and named entries in one Loro
//! document of a space, which every application of the space reads and
//! writes alike.
//!
//! A [`Drive`] reads the document as it is on this device, and writes each
//! change as one change of the document, signed and sealed by this device
//! ([`Document::edit`]); concurrent changes of other members merge, moves
//! included. [`Drive::batch`] makes several changes as one, all or none;
//! [`Drive::changes`] follows what changes, the application's own root
//! containers included.

use super::{BlobId, Document, Origin, Space, SpaceChanges, StreamId};
use crate::documents::loro_state;
use crate::error::{Error, Result};
use frasil_base::collect::CollectMap;
use frasil_drive::write::{self, NewEntry, NewKind, NewVersion};
use frasil_drive::{DOCUMENT, ENTRIES, Kind, PURGED, Tree};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// An entry's ID in a drive: 16 random bytes, shown as 32 hex digits.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId([u8; 16]);

impl EntryId {
    /// The ID of these bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The ID's bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Display for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for EntryId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EntryId({self})")
    }
}

fn hex16(text: &str, what: &'static str) -> Result<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return Err(Error::Invalid(what));
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let digit = |c: u8| (c as char).to_digit(16);
        match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => *slot = (high * 16 + low) as u8,
            _ => return Err(Error::Invalid(what)),
        }
    }
    Ok(out)
}

impl core::str::FromStr for EntryId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        hex16(text, "an EntryId is 16 bytes in hexadecimal").map(Self)
    }
}

/// A file entry's blob: its Blobs stream and handle, and what its Blobs
/// entry says of it, for listings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DriveFile {
    /// The Blobs stream of the drive's space that holds the blob.
    pub stream: StreamId,
    /// The blob in it.
    pub blob: BlobId,
    /// Its plaintext bytes, as the entry says.
    pub size: Option<u64>,
    /// Its media type, as the entry says.
    pub media_type: Option<String>,
    /// The file's versions, by blob, when read from a drive.
    pub versions: BTreeMap<BlobId, FileVersion>,
    /// The file's heads, when read from a drive: the versions no other
    /// names. One is the ordinary case; two or more are a conflict.
    pub heads: Vec<BlobId>,
}

/// A version of a file: a blob the file has pointed at, recorded with the
/// versions it was made from (ext-drive.md, section 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileVersion {
    /// The Blobs stream of the version's blob.
    pub stream: StreamId,
    /// Its plaintext bytes, as the record says.
    pub size: Option<u64>,
    /// When it was written, in seconds since 1970 by its writer's clock.
    pub written: Option<u64>,
    /// The versions it was made from.
    pub parents: Vec<BlobId>,
    /// Who wrote it: the device that signed the change that wrote its
    /// record, and the person whose list held that device then, from the
    /// drive's history (ext-drive.md, 3.3 What a reader shows). Read by
    /// [`Drive::versions`]; `None` in a listing, and for a record whose
    /// change this device does not hold.
    pub author: Option<crate::Author>,
    /// The Loro peer of the record's writer.
    writer: Option<u64>,
}

impl DriveFile {
    /// A blob of a Blobs stream.
    pub fn new(stream: StreamId, blob: BlobId) -> Self {
        Self {
            stream,
            blob,
            size: None,
            media_type: None,
            versions: BTreeMap::new(),
            heads: Vec::new(),
        }
    }

    /// Whether the file is in conflict: it has two or more heads, at every
    /// replica that holds the same changes.
    pub fn in_conflict(&self) -> bool {
        self.heads.len() > 1
    }

    /// The heads other than the file's current version: what an application
    /// shows beside the file until a writer resolves the conflict.
    pub fn other_heads(&self) -> impl Iterator<Item = BlobId> + '_ {
        self.heads.iter().copied().filter(|head| *head != self.blob)
    }

    /// With its size in bytes.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// With its media type, such as `image/png`.
    #[must_use]
    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }
}

/// What a drive entry is.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A folder, which holds entries.
    Folder,
    /// A blob of a Blobs stream.
    File(DriveFile),
    /// A stream of the space that holds an application's document.
    Document {
        /// The stream.
        stream: StreamId,
        /// What the document is, as its application names it, such as
        /// `example.spreadsheet`.
        kind: String,
    },
    /// An application's own kind, such as `example.note`, kept as it is.
    Other(String),
}

/// An entry of a drive.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DriveEntry {
    /// Its ID.
    pub id: EntryId,
    /// What it is.
    pub kind: EntryKind,
    /// Its own name: any text its writer chose, without `/` or control
    /// characters, and as it is when another writer's name is of another
    /// form. It is not a safe file name (see [`Drive`]).
    pub name: String,
    /// The name a listing shows for it: its own, or numbered, as
    /// `photo (2).jpg`, when an earlier entry of the folder has it. Like
    /// [`name`](Self::name), it is not a safe file name.
    pub shown_name: String,
    /// The entry it is in, or `None` at the root.
    pub parent: Option<EntryId>,
    /// When it was added, in seconds since 1970 by its writer's clock.
    pub added: Option<u64>,
    /// When it was last renamed, moved or restored, likewise.
    pub modified: Option<u64>,
    /// When it was sent to the trash itself, while it is there.
    pub trashed: Option<u64>,
    /// Whether it is in the trash: it, or an entry above it, was sent
    /// there.
    pub in_trash: bool,
    /// The applications' own fields.
    pub meta: BTreeMap<String, loro::LoroValue>,
}

/// A drive (ext-drive.md): folders, files and documents of a space, in one
/// Loro document. From [`Space::create_drive`] or [`Space::drive`].
///
/// # Names on disk
///
/// An entry's name is whatever any writer of the space chose. An
/// application that writes entries to a file system maps each name to a
/// safe one itself: `.` and `..`, `\` and `:`, the names Windows reserves
/// (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`, with or
/// without an extension), a trailing dot or space, names that differ only
/// in case, and names past the file system's length. It never joins names
/// into a path without checking that the path stays inside the folder it
/// writes to.
#[derive(Debug, Clone)]
pub struct Drive {
    document: Document,
}

fn drive_error(error: frasil_drive::Error) -> Error {
    match error {
        frasil_drive::Error::Loro(reason) => Error::Adapter(reason),
        other => Error::Invalid(other.message()),
    }
}

fn stream_hex(id: &StreamId) -> String {
    id.to_string()
}

fn entry_of(tree: &Tree, entry: &frasil_drive::Entry, shown: Option<&str>) -> Result<DriveEntry> {
    let id = |text: &str| -> Result<[u8; 16]> { hex16(text, "a drive entry is malformed") };
    let kind = match &entry.kind {
        Kind::Folder => EntryKind::Folder,
        Kind::File {
            stream,
            blob,
            size,
            media_type,
            versions,
            heads,
        } => {
            let blob_of = |text: &String| id(text).map(BlobId::from_bytes);
            let versions = versions
                .iter()
                .map(|(handle, version)| {
                    let found = FileVersion {
                        stream: StreamId::from_bytes(id(&version.stream)?),
                        size: version.size,
                        written: version.at,
                        parents: version.parents.iter().map(blob_of).collect::<Result<_>>()?,
                        author: None,
                        writer: version.writer,
                    };
                    Ok((blob_of(handle)?, found))
                })
                .collect::<Result<_>>()?;
            EntryKind::File(DriveFile {
                stream: StreamId::from_bytes(id(stream)?),
                blob: BlobId::from_bytes(id(blob)?),
                size: *size,
                media_type: media_type.clone(),
                versions,
                heads: heads.iter().map(blob_of).collect::<Result<_>>()?,
            })
        }
        Kind::Document { stream, kind } => EntryKind::Document {
            stream: StreamId::from_bytes(id(stream)?),
            kind: kind.clone(),
        },
        Kind::Other(kind) => EntryKind::Other(kind.clone()),
    };
    Ok(DriveEntry {
        id: EntryId(id(&entry.id)?),
        kind,
        name: entry.name.clone(),
        shown_name: shown.unwrap_or(&entry.name).to_owned(),
        parent: entry.parent.as_deref().map(id).transpose()?.map(EntryId),
        added: entry.added,
        modified: entry.at,
        trashed: entry.trashed,
        in_trash: tree.in_trash(entry),
        meta: entry.meta.clone(),
    })
}

impl Space {
    /// Creates a drive: a new Loro document that names itself one.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; as [`Document::edit`].
    pub async fn create_drive(&self) -> Result<Drive> {
        let document = self.create_document()?;
        document.edit(write::create).await?;
        Ok(Drive { document })
    }

    /// Opens a document of the space as a drive.
    ///
    /// # Errors
    ///
    /// As [`Space::document`]; [`Error::Invalid`] when the document is not
    /// a drive.
    pub async fn drive(&self, id: StreamId) -> Result<Drive> {
        let drive = Drive {
            document: self.document(id).await?,
        };
        drive.tree().await?;
        Ok(drive)
    }
}

impl Drive {
    /// The drive's document ID in its space.
    pub fn id(&self) -> StreamId {
        self.document.id()
    }

    /// Its Loro document, which holds application root containers beside
    /// the drive's.
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// The drive as this device holds it.
    async fn tree(&self) -> Result<Tree> {
        let stream = self.document.opening.stream();
        self.document
            .space
            .read(|replica| match loro_state(replica, &stream) {
                Some(state) => Tree::read(state.doc()),
                None => Err(frasil_drive::Error::NotADrive),
            })
            .await?
            .map_err(drive_error)
    }

    /// A folder's entries, or the root's for `None`, that are not in the
    /// trash themselves, in order, each under its shown name.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::Invalid`] for an entry the drive
    /// does not hold.
    pub async fn entries(&self, folder: Option<EntryId>) -> Result<Vec<DriveEntry>> {
        let tree = self.tree().await?;
        let folder = folder.map(|id| id.to_string());
        if let Some(id) = &folder
            && tree.entry(id).is_none()
        {
            return Err(drive_error(frasil_drive::Error::NoSuchEntry));
        }
        tree.listing(folder.as_deref())
            .iter()
            .map(|shown| entry_of(&tree, shown.entry, Some(&shown.name)))
            .collect()
    }

    /// Every entry, the trash's included, in order, each under its own
    /// name.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn all(&self) -> Result<Vec<DriveEntry>> {
        let tree = self.tree().await?;
        tree.entries()
            .iter()
            .map(|entry| entry_of(&tree, entry, None))
            .collect()
    }

    /// An entry, in the trash or not.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn entry(&self, id: EntryId) -> Result<Option<DriveEntry>> {
        let tree = self.tree().await?;
        tree.entry(&id.to_string())
            .map(|entry| entry_of(&tree, entry, None))
            .transpose()
    }

    /// The entry that lists a document stream of the space, in the trash
    /// or not.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn entry_for(&self, stream: StreamId) -> Result<Option<DriveEntry>> {
        let tree = self.tree().await?;
        tree.stream_entry(&stream_hex(&stream))
            .map(|entry| entry_of(&tree, entry, None))
            .transpose()
    }

    /// The trash: each entry sent there itself and not inside another in
    /// the trash, the most recent first.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn trash(&self) -> Result<Vec<DriveEntry>> {
        let tree = self.tree().await?;
        tree.trash()
            .into_iter()
            .map(|entry| entry_of(&tree, entry, None))
            .collect()
    }

    /// The files in conflict, each with two or more heads, in order
    /// (ext-drive.md, "Open conflicts"). An application that reports a
    /// drive as settled reports these first.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn conflicts(&self) -> Result<Vec<DriveEntry>> {
        let tree = self.tree().await?;
        tree.conflicts()
            .into_iter()
            .map(|entry| entry_of(&tree, entry, None))
            .collect()
    }

    /// A file's versions, oldest first by when they were written, each with
    /// who wrote it: the device that signed the change that wrote its
    /// record, and the person whose list held that device then
    /// (ext-drive.md, 3.3 What a reader shows). The file's heads and current
    /// version are its [`DriveFile`]'s.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold or that is
    /// not a file; as [`Document::history`].
    pub async fn versions(&self, id: EntryId) -> Result<Vec<(BlobId, FileVersion)>> {
        let file = self.file(id).await?;
        // A record is written once, so its writer's Loro peer names the one
        // incarnation, and so the device, that signed it.
        let mut authors: BTreeMap<u64, crate::Author> = BTreeMap::new();
        for change in self.document.history().await? {
            if let crate::Detail::Document(Some(document)) = &change.detail {
                authors.insert(document.span.peer, change.author.clone());
            }
        }
        let mut versions: Vec<(BlobId, FileVersion)> = file
            .versions
            .into_iter()
            .map(|(blob, mut version)| {
                version.author = version.writer.and_then(|peer| authors.get(&peer).cloned());
                (blob, version)
            })
            .collect();
        versions.sort_by_key(|(blob, version)| (version.written.unwrap_or(0), *blob));
        Ok(versions)
    }

    /// A file entry's file, as the drive holds it.
    async fn file(&self, id: EntryId) -> Result<DriveFile> {
        match self.entry(id).await?.map(|entry| entry.kind) {
            Some(EntryKind::File(file)) => Ok(file),
            Some(_) => Err(drive_error(frasil_drive::Error::NotAFile)),
            None => Err(drive_error(frasil_drive::Error::NoSuchEntry)),
        }
    }

    /// Makes an older version of a file its current version again
    /// (ext-drive.md, 3.4 Changes, "Parents"): puts the version's bytes
    /// again under a new handle of its Blobs stream, as a new version of
    /// every head, then sets the file's blob to it with every head as a
    /// parent, which also ends a conflict. Every version stays a version.
    /// Returns the new version's blob.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold, that is not
    /// a file, or a blob that is none of its versions;
    /// `Error::Class("Missing")` when no peer or member serves the
    /// version's bytes any more; as [`Blobs::put_version`](crate::Blobs::put_version)
    /// and [`Drive::set_blob`].
    #[cfg(feature = "adapter-blobs")]
    pub async fn restore_version(&self, id: EntryId, blob: BlobId) -> Result<BlobId> {
        let entry = self
            .entry(id)
            .await?
            .ok_or_else(|| drive_error(frasil_drive::Error::NoSuchEntry))?;
        let EntryKind::File(file) = entry.kind else {
            return Err(drive_error(frasil_drive::Error::NotAFile));
        };
        let stream = match file.versions.get(&blob) {
            Some(version) => version.stream,
            None if blob == file.blob => file.stream,
            None => return Err(Error::Invalid("the blob is none of the file's versions")),
        };
        let blobs = self.document.space.blobs(stream).await?;
        // A version this device does not hold is fetched, into its cache.
        let bytes = blobs
            .get(blob, &crate::Read::new())
            .await?
            .ok_or(Error::Class("Missing"))?;
        // Only the heads in the same stream are superseded
        // (ext-file-versions.md, 3.1 Superseding).
        let same_stream: Vec<BlobId> = file
            .heads
            .iter()
            .copied()
            .filter(|head| {
                file.versions
                    .get(head)
                    .map_or(*head == file.blob && file.stream == stream, |v| {
                        v.stream == stream
                    })
            })
            .collect();
        let restored = blobs
            .put_version(
                &bytes,
                &crate::PutVersion::new()
                    .named(&entry.name)
                    .parents(&same_stream),
            )
            .await?;
        let mut new = DriveFile::new(stream, restored).with_size(bytes.len() as u64);
        if let Some(media_type) = file.media_type {
            new = new.with_media_type(media_type);
        }
        self.set_blob(id, &new, &file.heads).await?;
        Ok(restored)
    }

    /// The writer's wall clock, when known.
    fn now(&self) -> Option<u64> {
        self.document.space.device.engine().platform().clock.wall()
    }

    /// Makes several changes together: `changes` makes them on a
    /// [`DriveBatch`], each checked against the drive as the changes before
    /// it leave it, and they are written as one change of the document,
    /// signed and sealed by this device, or not at all. Returns what
    /// `changes` returned.
    ///
    /// ```no_run
    /// # async fn run(drive: frasil::Drive) -> frasil::Result<()> {
    /// let folder = drive
    ///     .batch(|b| {
    ///         let folder = b.add_folder(None, "Invoices")?;
    ///         b.set_meta(folder, "example.type", "invoices")?;
    ///         Ok(folder)
    ///     })
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// A change the batch refuses writes nothing; when `changes` returns an
    /// error, nothing of the batch is written. A batch that makes no
    /// operation writes nothing and is no error.
    ///
    /// # Errors
    ///
    /// The error `changes` returned; as [`Document::edit`].
    pub async fn batch<T>(&self, changes: impl FnOnce(&mut DriveBatch) -> Result<T>) -> Result<T> {
        self.batch_written(changes).await.map(|(value, _)| value)
    }

    /// Makes changes as one, as [`Drive::batch`] does, and returns a
    /// [`Receipt`](super::Receipt) for the change it wrote: `None` for a
    /// batch that made no operation.
    ///
    /// # Errors
    ///
    /// As [`Drive::batch`].
    pub async fn batch_with_receipt<T>(
        &self,
        changes: impl FnOnce(&mut DriveBatch) -> Result<T>,
    ) -> Result<(T, Option<super::Receipt>)> {
        let (value, unit) = self.batch_written(changes).await?;
        let receipt = unit.map(|unit| super::Receipt::new(&self.document.space, unit));
        Ok((value, receipt))
    }

    /// Observes every entry of the drive, as [`Drive::all`] reads them.
    /// Every observer of the drive shares one reader.
    pub fn observe(&self) -> super::Observed<Vec<DriveEntry>> {
        let space = &self.document.space;
        let stream = self.document.opening.stream();
        let drive = self.clone();
        space.device.observed(
            Some(super::observe::key(space, &stream, "drive", &[])),
            space,
            super::observe::Scope::stream(space, stream),
            move |_| {
                let drive = drive.clone();
                async move { drive.all().await }
            },
        )
    }

    /// [`Drive::batch`], with the unit it wrote.
    async fn batch_written<T>(
        &self,
        changes: impl FnOnce(&mut DriveBatch) -> Result<T>,
    ) -> Result<(T, Option<frasil_events::EventId>)> {
        let at = self.now();
        let mut outcome = None;
        let mut wrote = false;
        let space = &self.document.space;
        let written = space
            .device
            .engine()
            .try_edit_document(space.id().event(), &self.document.opening, |doc| {
                let mut batch = DriveBatch {
                    drive: self.clone(),
                    doc: doc.clone(),
                    at,
                    open: Arc::new(AtomicBool::new(true)),
                    wrote: Arc::new(AtomicBool::new(false)),
                };
                let result = changes(&mut batch);
                batch.open.store(false, Ordering::SeqCst);
                wrote = batch.wrote.load(Ordering::SeqCst);
                let refused = result.as_ref().err().map(ToString::to_string);
                outcome = Some(result);
                match refused {
                    Some(reason) => Err(reason),
                    None => Ok(()),
                }
            })
            .await;
        match outcome {
            Some(Err(refusal)) => Err(refusal),
            Some(Ok(value)) => match written {
                Err(_) if !wrote => Ok((value, None)),
                written => written.map(|unit| (value, Some(unit))),
            },
            None => written.and(Err(Error::Adapter("the change did not run".into()))),
        }
    }

    /// Adds a folder, the last in `parent`, or at the root for `None`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a name of the wrong form (1 to 255 bytes,
    /// no `/`, no control character), or a parent the drive does not hold
    /// or that is not a folder; as [`Document::edit`].
    pub async fn add_folder(&self, parent: Option<EntryId>, name: &str) -> Result<EntryId> {
        self.batch(|b| b.add_folder(parent, name)).await
    }

    /// Adds a file: a blob of a Blobs stream of the space.
    ///
    /// # Errors
    ///
    /// As [`Drive::add_folder`], and for a media type of the wrong form.
    pub async fn add_file(
        &self,
        parent: Option<EntryId>,
        name: &str,
        file: &DriveFile,
    ) -> Result<EntryId> {
        self.batch(|b| b.add_file(parent, name, file)).await
    }

    /// Adds a document: a stream of the space, a Loro document or Records,
    /// of the application's kind `kind`, such as `example.spreadsheet`. A
    /// stream has one entry.
    ///
    /// # Errors
    ///
    /// As [`Drive::add_folder`], for a kind of the wrong form (1 to 64
    /// bytes, no control character or white space), and for a stream that
    /// has an entry or had one that was purged.
    pub async fn add_document(
        &self,
        parent: Option<EntryId>,
        name: &str,
        stream: StreamId,
        kind: &str,
    ) -> Result<EntryId> {
        self.batch(|b| b.add_document(parent, name, stream, kind))
            .await
    }

    /// Renames an entry.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a name of the wrong form or an entry the
    /// drive does not hold; as [`Document::edit`].
    pub async fn rename(&self, id: EntryId, name: &str) -> Result<()> {
        self.batch(|b| b.rename(id, name)).await
    }

    /// Moves an entry to be the last in `parent`, or at the root for
    /// `None`. Concurrent moves merge without a cycle.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry or parent the drive does not hold, a
    /// parent that is not a folder, or a folder moved into itself; as
    /// [`Document::edit`].
    pub async fn move_to(&self, id: EntryId, parent: Option<EntryId>) -> Result<()> {
        self.batch(|b| b.move_to(id, parent)).await
    }

    /// Sends an entry, with what is inside it, to the trash.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold or that was
    /// sent there already; as [`Document::edit`].
    pub async fn move_to_trash(&self, id: EntryId) -> Result<()> {
        self.batch(|b| b.move_to_trash(id)).await
    }

    /// Brings back an entry sent to the trash itself, where it was.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold or that was
    /// not sent to the trash itself; as [`Document::edit`].
    pub async fn restore(&self, id: EntryId) -> Result<()> {
        self.batch(|b| b.restore(id)).await
    }

    /// Forgets an entry and what is inside it, for good. Returns the blobs
    /// no other entry names, which the application may remove from their
    /// Blobs streams; the streams and blobs themselves stay, at this device
    /// and at the space's peers. To drop the bytes of a document the entry
    /// named from the peers, release its stream with
    /// [`Document::release`] or [`Space::release_stream`](super::Space::release_stream).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold; as
    /// [`Document::edit`].
    pub async fn purge(&self, id: EntryId) -> Result<Vec<(StreamId, BlobId)>> {
        self.batch(|b| b.purge(id)).await
    }

    /// Records a new version of a file: `file`'s blob, put under a new handle
    /// with [`Blobs::put_version`](super::Blobs::put_version), which also
    /// tells peers what it replaces. `parents` are what the version was
    /// made from: the version this device's copy came from, for a plain
    /// save, head or not; every head, to resolve a conflict; none, with no
    /// base. A version whose parents name the file's current blob becomes
    /// the file. Any other, as a save from a stale copy, is a second head
    /// beside it, and the conflict is what every replica reads.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold or that is
    /// not a file, a blob that has a version already, a media type of the
    /// wrong form, or parents that are more than 64 or name a blob twice or
    /// the new blob; as [`Document::edit`].
    pub async fn set_blob(&self, id: EntryId, file: &DriveFile, parents: &[BlobId]) -> Result<()> {
        self.batch(|b| b.set_blob(id, file, parents)).await
    }

    /// Forgets a version's record, from the oldest end: one that is not a
    /// head and whose parents have no record. The version's blob stays
    /// until its handle is removed from its Blobs stream.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an entry the drive does not hold or that is
    /// not a file, a blob with no record, a head, or a record one of whose
    /// parents has a record; as [`Document::edit`].
    pub async fn forget_version(&self, id: EntryId, blob: BlobId) -> Result<()> {
        self.batch(|b| b.forget_version(id, blob)).await
    }

    /// Sets one of an entry's application fields. Name keys with a prefix
    /// of the application's own, such as `example.color`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a key of the wrong form (1 to 255 bytes, no
    /// control character), a value that is a container, or an entry the
    /// drive does not hold; as [`Document::edit`].
    pub async fn set_meta(
        &self,
        id: EntryId,
        key: &str,
        value: impl Into<loro::LoroValue>,
    ) -> Result<()> {
        self.batch(|b| b.set_meta(id, key, value)).await
    }

    /// Deletes one of an entry's application fields, if it has it.
    ///
    /// # Errors
    ///
    /// As [`Drive::set_meta`].
    pub async fn delete_meta(&self, id: EntryId, key: &str) -> Result<()> {
        self.batch(|b| b.delete_meta(id, key)).await
    }

    /// What changes from now on, this device's own changes included: the
    /// entries, and the document's other root containers, where
    /// applications keep records of the whole drive.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn changes(&self) -> Result<DriveChanges> {
        let mut changes = DriveChanges {
            drive: self.clone(),
            changes: self.document.space.changes(),
            seen: Seen::default(),
        };
        changes.seen = changes.snapshot().await?;
        Ok(changes)
    }
}

/// Changes to a drive made together, from [`Drive::batch`]. Each change
/// runs its checks against the drive as the changes before it in the batch
/// leave it, and returns as the drive's own method does. A clone makes its
/// changes in the same batch; once the batch is written, every change on
/// it is refused.
#[derive(Clone)]
pub struct DriveBatch {
    drive: Drive,
    doc: loro::LoroDoc,
    at: Option<u64>,
    open: Arc<AtomicBool>,
    wrote: Arc<AtomicBool>,
}

impl core::fmt::Debug for DriveBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DriveBatch")
            .field("drive", &self.drive.id())
            .finish_non_exhaustive()
    }
}

impl DriveBatch {
    /// Makes one change on the batch's document, if the batch is open.
    fn change<T>(
        &mut self,
        change: impl FnOnce(&loro::LoroDoc) -> core::result::Result<T, frasil_drive::Error>,
        wrote: impl FnOnce(&T) -> bool,
    ) -> Result<T> {
        if !self.open.load(Ordering::SeqCst) {
            return Err(Error::Invalid("the batch was written already"));
        }
        let value = change(&self.doc).map_err(drive_error)?;
        if wrote(&value) {
            self.wrote.store(true, Ordering::SeqCst);
        }
        Ok(value)
    }

    fn add(&mut self, parent: Option<EntryId>, name: &str, kind: NewKind<'_>) -> Result<EntryId> {
        let id = EntryId(
            self.drive
                .document
                .space
                .device
                .engine()
                .platform()
                .nonce::<16>()?,
        );
        let (text, parent, at) = (id.to_string(), parent.map(|p| p.to_string()), self.at);
        let new = NewEntry {
            id: &text,
            parent: parent.as_deref(),
            name,
            kind,
        };
        self.change(|doc| write::add(doc, &new, at), |()| true)?;
        Ok(id)
    }

    /// As [`Drive::add_folder`].
    ///
    /// # Errors
    ///
    /// As [`Drive::add_folder`].
    pub fn add_folder(&mut self, parent: Option<EntryId>, name: &str) -> Result<EntryId> {
        self.add(parent, name, NewKind::Folder)
    }

    /// As [`Drive::add_file`].
    ///
    /// # Errors
    ///
    /// As [`Drive::add_file`].
    pub fn add_file(
        &mut self,
        parent: Option<EntryId>,
        name: &str,
        file: &DriveFile,
    ) -> Result<EntryId> {
        let (stream, blob) = (stream_hex(&file.stream), file.blob.to_string());
        let kind = NewKind::File {
            stream: &stream,
            blob: &blob,
            size: file.size,
            media_type: file.media_type.as_deref(),
        };
        self.add(parent, name, kind)
    }

    /// As [`Drive::add_document`].
    ///
    /// # Errors
    ///
    /// As [`Drive::add_document`].
    pub fn add_document(
        &mut self,
        parent: Option<EntryId>,
        name: &str,
        stream: StreamId,
        kind: &str,
    ) -> Result<EntryId> {
        let stream = stream_hex(&stream);
        self.add(
            parent,
            name,
            NewKind::Document {
                stream: &stream,
                kind,
            },
        )
    }

    /// As [`Drive::rename`].
    ///
    /// # Errors
    ///
    /// As [`Drive::rename`].
    pub fn rename(&mut self, id: EntryId, name: &str) -> Result<()> {
        let (id, at) = (id.to_string(), self.at);
        self.change(|doc| write::rename(doc, &id, name, at), |()| true)
    }

    /// As [`Drive::move_to`].
    ///
    /// # Errors
    ///
    /// As [`Drive::move_to`].
    pub fn move_to(&mut self, id: EntryId, parent: Option<EntryId>) -> Result<()> {
        let (id, parent, at) = (id.to_string(), parent.map(|p| p.to_string()), self.at);
        self.change(
            |doc| write::move_to(doc, &id, parent.as_deref(), at),
            |()| true,
        )
    }

    /// As [`Drive::move_to_trash`].
    ///
    /// # Errors
    ///
    /// As [`Drive::move_to_trash`].
    pub fn move_to_trash(&mut self, id: EntryId) -> Result<()> {
        let (id, at) = (id.to_string(), self.at);
        self.change(|doc| write::trash(doc, &id, at), |()| true)
    }

    /// As [`Drive::restore`].
    ///
    /// # Errors
    ///
    /// As [`Drive::restore`].
    pub fn restore(&mut self, id: EntryId) -> Result<()> {
        let (id, at) = (id.to_string(), self.at);
        self.change(|doc| write::restore(doc, &id, at), |()| true)
    }

    /// As [`Drive::purge`]: the blobs no other entry names once this purge
    /// is made, as the batch has left the drive so far.
    ///
    /// # Errors
    ///
    /// As [`Drive::purge`].
    pub fn purge(&mut self, id: EntryId) -> Result<Vec<(StreamId, BlobId)>> {
        let (id, at) = (id.to_string(), self.at);
        let released = self.change(|doc| write::purge(doc, &id, at), |_| true)?;
        released
            .into_iter()
            .map(|(stream, blob)| {
                Ok((
                    StreamId::from_bytes(hex16(&stream, "a released blob is malformed")?),
                    BlobId::from_bytes(hex16(&blob, "a released blob is malformed")?),
                ))
            })
            .collect()
    }

    /// As [`Drive::set_blob`].
    ///
    /// # Errors
    ///
    /// As [`Drive::set_blob`].
    pub fn set_blob(&mut self, id: EntryId, file: &DriveFile, parents: &[BlobId]) -> Result<()> {
        let (id, at) = (id.to_string(), self.at);
        let (stream, blob) = (stream_hex(&file.stream), file.blob.to_string());
        let parents: Vec<String> = parents.iter().map(ToString::to_string).collect();
        let version = NewVersion {
            stream: &stream,
            blob: &blob,
            size: file.size,
            media_type: file.media_type.as_deref(),
            parents: &parents,
        };
        self.change(|doc| write::set_blob(doc, &id, &version, at), |()| true)
    }

    /// As [`Drive::forget_version`].
    ///
    /// # Errors
    ///
    /// As [`Drive::forget_version`].
    pub fn forget_version(&mut self, id: EntryId, blob: BlobId) -> Result<()> {
        let (id, blob) = (id.to_string(), blob.to_string());
        self.change(|doc| write::forget_version(doc, &id, &blob), |()| true)
    }

    /// As [`Drive::set_meta`].
    ///
    /// # Errors
    ///
    /// As [`Drive::set_meta`].
    pub fn set_meta(
        &mut self,
        id: EntryId,
        key: &str,
        value: impl Into<loro::LoroValue>,
    ) -> Result<()> {
        let (id, value) = (id.to_string(), value.into());
        self.change(|doc| write::set_meta(doc, &id, key, value), |()| true)
    }

    /// As [`Drive::delete_meta`].
    ///
    /// # Errors
    ///
    /// As [`Drive::delete_meta`].
    pub fn delete_meta(&mut self, id: EntryId, key: &str) -> Result<()> {
        let id = id.to_string();
        self.change(|doc| write::delete_meta(doc, &id, key), |had| *had)
            .map(drop)
    }
}

/// A change of a drive, from [`DriveChanges::next`]. Read the drive again
/// for what changed is now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DriveChange {
    /// The entries added, changed or gone, by ID, sorted.
    pub entries: Vec<EntryId>,
    /// The document's other root containers that changed, by name, sorted:
    /// the records applications keep of the whole drive beside its
    /// entries (ext-drive.md, section 3.6). The drive's own `document`,
    /// `entries` and `purged` are never among them. Read them from
    /// [`Drive::document`].
    pub roots: Vec<String>,
    /// Where the change was made.
    pub origin: Origin,
}

/// What a change feed last saw: each entry, and each other root container's
/// value.
#[derive(Debug, Default)]
struct Seen {
    entries: BTreeMap<EntryId, DriveEntry>,
    roots: BTreeMap<String, loro::LoroValue>,
}

/// The keys whose values differ between `before` and `after`, sorted.
fn differ<K: Ord + Clone, V: PartialEq>(before: &BTreeMap<K, V>, after: &BTreeMap<K, V>) -> Vec<K> {
    let keys: BTreeSet<&K> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect()
}

/// The values of a document's root containers other than the drive's.
fn other_roots(doc: &loro::LoroDoc) -> BTreeMap<String, loro::LoroValue> {
    match doc.get_deep_value() {
        loro::LoroValue::Map(roots) => roots
            .iter()
            .filter(|(name, _)| ![DOCUMENT, ENTRIES, PURGED].contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect_map(),
        _ => BTreeMap::new(),
    }
}

/// The changes of a drive, from [`Drive::changes`].
#[derive(Debug)]
pub struct DriveChanges {
    drive: Drive,
    changes: SpaceChanges,
    seen: Seen,
}

impl DriveChanges {
    async fn snapshot(&self) -> Result<Seen> {
        let stream = self.drive.document.opening.stream();
        let (tree, roots) = self
            .drive
            .document
            .space
            .read(|replica| match loro_state(replica, &stream) {
                Some(state) => Tree::read(state.doc()).map(|tree| (tree, other_roots(state.doc()))),
                None => Err(frasil_drive::Error::NotADrive),
            })
            .await?
            .map_err(drive_error)?;
        let entries = tree
            .entries()
            .iter()
            .map(|entry| entry_of(&tree, entry, None).map(|entry| (entry.id, entry)))
            .collect::<Result<_>>()?;
        Ok(Seen { entries, roots })
    }

    /// The next change: the entries added, changed or gone, and the other
    /// root containers that changed; `None` once the device is gone, or no
    /// longer holds the drive's space.
    pub async fn next(&mut self) -> Option<DriveChange> {
        let stream = self.drive.id();
        loop {
            let changed = self.changes.next().await.ok()??;
            // Only the drive's own document, who may write it, and keys
            // that let its changes read change what it shows.
            if !(changed.members || changed.space_events || changed.streams.contains(&stream)) {
                continue;
            }
            let Ok(now) = self.snapshot().await else {
                continue;
            };
            let change = DriveChange {
                entries: differ(&self.seen.entries, &now.entries),
                roots: differ(&self.seen.roots, &now.roots),
                origin: changed.origin,
            };
            self.seen = now;
            if !(change.entries.is_empty() && change.roots.is_empty()) {
                return Some(change);
            }
        }
    }
}
