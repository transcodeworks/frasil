//! Section 3.4, Changes: each change's checks, in their order, then its
//! Loro operations on the document. Nothing is written when a check fails.
//! The caller commits the operations as one unit of the drive.
//!
//! `at` is the writer's wall clock in seconds, `None` when it is not
//! known: the change then writes no `added` or `at`, and 0 where a time is
//! required.

use std::collections::HashMap;

use loro::{LoroDoc, LoroMap, LoroTree, LoroValue, TreeParentId};

use crate::read::{Kind, Tree, is_drive, is_parents, meta_map, place, versions_map};
use crate::values::{
    MAX_COUNT, is_entry_id, is_handle, is_kind_string, is_media_type, is_meta_key, is_meta_value,
    is_name, is_stream_id,
};
use crate::{DOCUMENT, DOCUMENT_KIND, ENTRIES, Error, FILE, FOLDER, KIND, PURGED};

/// What an added entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewKind<'a> {
    /// A folder.
    Folder,
    /// A file: a blob of a Blobs stream, with what its Blobs entry says.
    File {
        /// The Blobs stream's ID, in hexadecimal.
        stream: &'a str,
        /// The blob's handle, in hexadecimal.
        blob: &'a str,
        /// Its plaintext bytes.
        size: Option<u64>,
        /// Its media type.
        media_type: Option<&'a str>,
    },
    /// A document: a stream of the space, and what its application calls it.
    Document {
        /// The stream's ID, in hexadecimal.
        stream: &'a str,
        /// The document's kind.
        kind: &'a str,
    },
}

/// An entry to add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewEntry<'a> {
    /// Its entry ID, which the writer drew at random.
    pub id: &'a str,
    /// The folder it goes in, or `None` for the root.
    pub parent: Option<&'a str>,
    /// Its name.
    pub name: &'a str,
    /// What it is.
    pub kind: NewKind<'a>,
}

fn time(at: Option<u64>) -> Result<Option<i64>, Error> {
    match at {
        Some(at) if at > MAX_COUNT => Err(Error::InvalidValue("a time beyond a count")),
        Some(at) => Ok(Some(at as i64)),
        None => Ok(None),
    }
}

fn stamp(fields: &LoroMap, key: &str, at: Option<i64>) -> Result<(), Error> {
    if let Some(at) = at {
        fields.insert(key, at)?;
    }
    Ok(())
}

/// The drive's tree, with fractional index on so that new places sort.
fn entries(doc: &LoroDoc) -> LoroTree {
    let tree = doc.get_tree(ENTRIES);
    tree.enable_fractional_index(0);
    tree
}

/// Check 1 of every change: the document is a drive. Returns it read.
fn drive(doc: &LoroDoc) -> Result<Tree, Error> {
    Tree::read(doc)
}

/// Section 3.1: makes the document a drive, by writing `kind`.
///
/// # Errors
///
/// [`Error::Loro`].
pub fn create(doc: &LoroDoc) -> Result<(), Error> {
    if is_drive(doc) {
        return Ok(());
    }
    doc.get_map(DOCUMENT).insert("kind", KIND)?;
    Ok(())
}

/// Adds an entry, as the last in its folder.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::EntryExists`],
/// [`Error::NoSuchEntry`], [`Error::CannotHold`], [`Error::AlreadyListed`],
/// in that order; [`Error::Loro`].
pub fn add(doc: &LoroDoc, new: &NewEntry<'_>, at: Option<u64>) -> Result<(), Error> {
    let tree = drive(doc)?;
    if !is_entry_id(new.id) {
        return Err(Error::InvalidValue("not an entry ID"));
    }
    if !is_name(new.name) {
        return Err(Error::InvalidValue("not a valid name"));
    }
    match new.kind {
        NewKind::Folder => {}
        NewKind::File {
            stream,
            blob,
            size,
            media_type,
        } => {
            if !is_stream_id(stream) || !is_handle(blob) {
                return Err(Error::InvalidValue(
                    "a file names a Blobs stream and a handle",
                ));
            }
            if size.is_some_and(|size| size > MAX_COUNT) {
                return Err(Error::InvalidValue("a size beyond a count"));
            }
            if media_type.is_some_and(|t| !is_media_type(t)) {
                return Err(Error::InvalidValue("not a media type"));
            }
        }
        NewKind::Document { stream, kind } => {
            if !is_stream_id(stream) {
                return Err(Error::InvalidValue("not a stream ID"));
            }
            if !is_kind_string(kind) {
                return Err(Error::InvalidValue("not a kind string"));
            }
        }
    }
    let at = time(at)?;
    if tree.entry(new.id).is_some() {
        return Err(Error::EntryExists);
    }
    let parent = place(&tree, new.parent)?;
    if let NewKind::Document { stream, .. } = new.kind
        && (tree.stream_entry(stream).is_some() || tree.is_purged(stream))
    {
        return Err(Error::AlreadyListed);
    }
    let entries = entries(doc);
    let node = entries.create(parent)?;
    let fields = entries.get_meta(node)?;
    fields.insert("id", new.id)?;
    let kind = match new.kind {
        NewKind::Folder => FOLDER,
        NewKind::File { .. } => FILE,
        NewKind::Document { .. } => DOCUMENT_KIND,
    };
    fields.insert("kind", kind)?;
    fields.insert("name", new.name)?;
    stamp(&fields, "added", at)?;
    stamp(&fields, "at", at)?;
    match new.kind {
        NewKind::Folder => {}
        NewKind::File {
            stream,
            blob,
            size,
            media_type,
        } => {
            fields.insert("stream", stream)?;
            fields.insert("blob", blob)?;
            if let Some(size) = size {
                fields.insert("size", size as i64)?;
            }
            if let Some(media_type) = media_type {
                fields.insert("type", media_type)?;
            }
        }
        NewKind::Document { stream, kind } => {
            fields.insert("stream", stream)?;
            fields.insert("docKind", kind)?;
        }
    }
    fields.insert_container("meta", LoroMap::new())?;
    if let NewKind::File {
        stream, blob, size, ..
    } = new.kind
    {
        fields
            .insert_container("versions", LoroMap::new())?
            .insert(blob, record(stream, size, at, &[]))?;
    }
    Ok(())
}

/// The metadata map of an entry the drive holds.
fn fields_of(doc: &LoroDoc, tree: &Tree, id: &str) -> Result<(LoroMap, loro::TreeID), Error> {
    let entry = tree.entry(id).ok_or(Error::NoSuchEntry)?;
    Ok((doc.get_tree(ENTRIES).get_meta(entry.node)?, entry.node))
}

/// Renames an entry.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`];
/// [`Error::Loro`].
pub fn rename(doc: &LoroDoc, id: &str, name: &str, at: Option<u64>) -> Result<(), Error> {
    let tree = drive(doc)?;
    if !is_name(name) {
        return Err(Error::InvalidValue("not a valid name"));
    }
    let at = time(at)?;
    let (fields, _) = fields_of(doc, &tree, id)?;
    fields.insert("name", name)?;
    stamp(&fields, "at", at)
}

/// Moves an entry to be the last in `parent`, or the last root.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`],
/// [`Error::CannotHold`], [`Error::MoveIntoItself`]; [`Error::Loro`].
pub fn move_to(
    doc: &LoroDoc,
    id: &str,
    parent: Option<&str>,
    at: Option<u64>,
) -> Result<(), Error> {
    let tree = drive(doc)?;
    let at = time(at)?;
    let (fields, node) = fields_of(doc, &tree, id)?;
    let target = place(&tree, parent)?;
    if let TreeParentId::Node(holder) = target
        && tree.node_within(holder, node)
    {
        return Err(Error::MoveIntoItself);
    }
    entries(doc).mov(node, target)?;
    stamp(&fields, "at", at)
}

/// Sends an entry, with what is inside it, to the trash.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`],
/// [`Error::AlreadyTrashed`]; [`Error::Loro`].
pub fn trash(doc: &LoroDoc, id: &str, at: Option<u64>) -> Result<(), Error> {
    let tree = drive(doc)?;
    let at = time(at)?;
    let (fields, _) = fields_of(doc, &tree, id)?;
    if tree.entry(id).is_some_and(|e| e.trashed.is_some()) {
        return Err(Error::AlreadyTrashed);
    }
    fields.insert("trashed", at.unwrap_or(0))?;
    Ok(())
}

/// Brings back an entry that was trashed itself.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`],
/// [`Error::NotTrashed`]; [`Error::Loro`].
pub fn restore(doc: &LoroDoc, id: &str, at: Option<u64>) -> Result<(), Error> {
    let tree = drive(doc)?;
    let at = time(at)?;
    let (fields, _) = fields_of(doc, &tree, id)?;
    if tree.entry(id).is_some_and(|e| e.trashed.is_none()) {
        return Err(Error::NotTrashed);
    }
    fields.delete("trashed")?;
    stamp(&fields, "at", at)
}

/// Forgets an entry and every node inside it. Records the streams of the
/// document entries it deletes in `purged`, and returns the blobs it
/// releases, as stream and handle, sorted.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`];
/// [`Error::Loro`].
pub fn purge(doc: &LoroDoc, id: &str, at: Option<u64>) -> Result<Vec<(String, String)>, Error> {
    let tree = drive(doc)?;
    let at = time(at)?;
    let (_, node) = fields_of(doc, &tree, id)?;
    let released = tree.released_by(node);
    let purged = doc.get_map(PURGED);
    for entry in tree.entries_within(node) {
        if let Kind::Document { stream, .. } = &entry.kind {
            purged.insert(stream, at.unwrap_or(0))?;
        }
    }
    entries(doc).delete(node)?;
    Ok(released)
}

/// A new version of a file, as a Set blob writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewVersion<'a> {
    /// The Blobs stream's ID, in hexadecimal.
    pub stream: &'a str,
    /// The blob's handle, in hexadecimal: one no version has used.
    pub blob: &'a str,
    /// Its plaintext bytes.
    pub size: Option<u64>,
    /// Its media type.
    pub media_type: Option<&'a str>,
    /// The handles of the versions it was made from.
    pub parents: &'a [String],
}

/// A version record as a writer writes it (section 2.4).
fn record(stream: &str, size: Option<u64>, at: Option<i64>, parents: &[String]) -> LoroValue {
    let mut record = HashMap::from([
        ("stream".to_owned(), LoroValue::from(stream)),
        (
            "parents".to_owned(),
            LoroValue::from(
                parents
                    .iter()
                    .map(|parent| LoroValue::from(parent.as_str()))
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    if let Some(size) = size {
        record.insert("size".to_owned(), LoroValue::I64(size as i64));
    }
    if let Some(at) = at {
        record.insert("at".to_owned(), LoroValue::I64(at));
    }
    LoroValue::from(record)
}

/// Records a new version of a file, and points the file at it when its
/// parents name the file's blob. A stale copy's version stays a head beside
/// the current version (section 3.4).
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`],
/// [`Error::NotAFile`], [`Error::VersionExists`], in that order;
/// [`Error::Loro`].
pub fn set_blob(
    doc: &LoroDoc,
    id: &str,
    version: &NewVersion<'_>,
    at: Option<u64>,
) -> Result<(), Error> {
    let tree = drive(doc)?;
    if !is_handle(version.blob) || !is_stream_id(version.stream) {
        return Err(Error::InvalidValue(
            "a version names a Blobs stream and a handle",
        ));
    }
    if version.size.is_some_and(|size| size > MAX_COUNT) {
        return Err(Error::InvalidValue("a size beyond a count"));
    }
    if version.media_type.is_some_and(|t| !is_media_type(t)) {
        return Err(Error::InvalidValue("not a media type"));
    }
    if !is_parents(version.parents, version.blob) {
        return Err(Error::InvalidValue("not a version's parents"));
    }
    let at = time(at)?;
    let (fields, _) = fields_of(doc, &tree, id)?;
    let Some(Kind::File {
        blob,
        stream,
        size,
        versions,
        ..
    }) = tree.entry(id).map(|e| &e.kind)
    else {
        return Err(Error::NotAFile);
    };
    if versions.contains_key(version.blob) {
        return Err(Error::VersionExists);
    }
    let records = match versions_map(&fields) {
        Some(records) => records,
        None => fields.insert_container("versions", LoroMap::new())?,
    };
    if version.parents.contains(blob) {
        fields.insert("blob", version.blob)?;
        fields.insert("stream", version.stream)?;
        stamp(&fields, "at", at)?;
        match version.size {
            Some(size) => fields.insert("size", size as i64)?,
            None if fields.get("size").is_some() => fields.delete("size")?,
            None => {}
        }
        match version.media_type {
            Some(media_type) => fields.insert("type", media_type)?,
            None if fields.get("type").is_some() => fields.delete("type")?,
            None => {}
        }
    } else if !versions.contains_key(blob) {
        records.insert(blob, record(stream, *size, None, &[]))?;
    }
    records.insert(
        version.blob,
        record(version.stream, version.size, at, version.parents),
    )?;
    Ok(())
}

/// Forgets a version's record: one that is not a head, and whose parents
/// have no record.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`],
/// [`Error::NotAFile`], [`Error::NoSuchVersion`], [`Error::VersionIsHead`],
/// [`Error::VersionHasParents`], in that order; [`Error::Loro`].
pub fn forget_version(doc: &LoroDoc, id: &str, handle: &str) -> Result<(), Error> {
    let tree = drive(doc)?;
    if !is_handle(handle) {
        return Err(Error::InvalidValue("not a handle"));
    }
    let (fields, _) = fields_of(doc, &tree, id)?;
    let Some(Kind::File {
        versions, heads, ..
    }) = tree.entry(id).map(|e| &e.kind)
    else {
        return Err(Error::NotAFile);
    };
    // Step 5: a value of any form. One of the wrong form is no record and
    // names no parents, so step 7 passes it.
    let records = versions_map(&fields)
        .filter(|records| records.get(handle).is_some())
        .ok_or(Error::NoSuchVersion)?;
    if heads.iter().any(|head| head == handle) {
        return Err(Error::VersionIsHead);
    }
    if versions
        .get(handle)
        .is_some_and(|found| found.parents.iter().any(|p| versions.contains_key(p)))
    {
        return Err(Error::VersionHasParents);
    }
    records.delete(handle)?;
    Ok(())
}

/// Sets a key of an entry's `meta`.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`];
/// [`Error::Loro`].
pub fn set_meta(doc: &LoroDoc, id: &str, key: &str, value: LoroValue) -> Result<(), Error> {
    let tree = drive(doc)?;
    if !is_meta_key(key) {
        return Err(Error::InvalidValue("not a meta key"));
    }
    if !is_meta_value(&value) {
        return Err(Error::InvalidValue("a meta value is not a container"));
    }
    let (fields, _) = fields_of(doc, &tree, id)?;
    let meta = match meta_map(&fields) {
        Some(meta) => meta,
        None => fields.insert_container("meta", LoroMap::new())?,
    };
    meta.insert(key, value)?;
    Ok(())
}

/// Deletes a key of an entry's `meta`. Returns whether it had one.
///
/// # Errors
///
/// [`Error::NotADrive`], [`Error::InvalidValue`], [`Error::NoSuchEntry`];
/// [`Error::Loro`].
pub fn delete_meta(doc: &LoroDoc, id: &str, key: &str) -> Result<bool, Error> {
    let tree = drive(doc)?;
    if !is_meta_key(key) {
        return Err(Error::InvalidValue("not a meta key"));
    }
    let (fields, _) = fields_of(doc, &tree, id)?;
    match meta_map(&fields) {
        Some(meta) if meta.get(key).is_some() => {
            meta.delete(key)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
