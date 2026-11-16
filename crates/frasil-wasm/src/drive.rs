//! Drives (ext-drive.md), as JavaScript classes: `frasil::Drive`, opened
//! from a space, its batches and its change feed. IDs cross as the hex
//! `frasil` shows; an entry and a change cross as plain objects.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use crate::convert::{Obj, array, field, id, loro_in, loro_out, text_field};
use crate::error::{Js, invalid};
use crate::promise;
use crate::space::Space;
use frasil::{BlobId, DriveEntry, DriveFile, EntryId, EntryKind, FileVersion, StreamId};
use js_sys::Promise;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A count as a `number`: every count of a drive is below 2^53.
fn count(value: Option<u64>) -> JsValue {
    value.map_or(JsValue::UNDEFINED, |n| JsValue::from_f64(n as f64))
}

/// An entry as `{ id, kind, name, shownName, parent, added, modified,
/// trashed, inTrash, meta }`, with `stream`, `blob`, `size`, `mediaType` and
/// `heads` for a file and `stream` and `docKind` for a document.
fn entry_out(entry: &DriveEntry) -> JsValue {
    let meta = entry
        .meta
        .iter()
        .fold(Obj::new(), |out, (key, value)| {
            out.define(key, &loro_out(value))
        })
        .build();
    let out = Obj::new()
        .set("id", entry.id.to_string())
        .set("name", entry.name.as_str())
        .set("shownName", entry.shown_name.as_str())
        .set(
            "parent",
            entry
                .parent
                .map_or(JsValue::NULL, |p| JsValue::from_str(&p.to_string())),
        )
        .set("added", count(entry.added))
        .set("modified", count(entry.modified))
        .set("trashed", count(entry.trashed))
        .set("inTrash", entry.in_trash)
        .set("meta", meta);
    match &entry.kind {
        EntryKind::Folder => out.set("kind", "folder"),
        EntryKind::File(file) => out
            .set("kind", "file")
            .set("stream", file.stream.to_string())
            .set("blob", file.blob.to_string())
            .set("size", count(file.size))
            .set(
                "mediaType",
                file.media_type
                    .as_deref()
                    .map_or(JsValue::UNDEFINED, JsValue::from_str),
            )
            .set("heads", blobs_out(&file.heads)),
        EntryKind::Document { stream, kind } => out
            .set("kind", "document")
            .set("stream", stream.to_string())
            .set("docKind", kind.as_str()),
        EntryKind::Other(kind) => out.set("kind", kind.as_str()),
        _ => out.set("kind", "unknown"),
    }
    .build()
}

fn blobs_out(blobs: &[BlobId]) -> JsValue {
    array(blobs, |blob| JsValue::from_str(&blob.to_string()))
}

/// A file's version as `{ blob, stream, size, written, parents, author }`,
/// `author` as `{ device, deviceName?, person?, personName?, persons }` or
/// `undefined`.
fn version_out(blob: &BlobId, version: &FileVersion) -> JsValue {
    Obj::new()
        .set("blob", blob.to_string())
        .set("stream", version.stream.to_string())
        .set("size", count(version.size))
        .set("written", count(version.written))
        .set("parents", blobs_out(&version.parents))
        .set(
            "author",
            version
                .author
                .as_ref()
                .map_or(JsValue::UNDEFINED, crate::streams::author_out),
        )
        .build()
}

/// Blob IDs from an array of hex strings.
fn blobs_in(value: &JsValue) -> Result<Vec<BlobId>, JsValue> {
    crate::convert::items(value, "the parents")?
        .iter()
        .map(|item| {
            item.as_string()
                .ok_or_else(|| invalid("a parent is a blob ID, 32 hex digits."))
                .and_then(|text| id::<BlobId>(&text))
        })
        .collect()
}

fn entries_out(entries: Vec<DriveEntry>) -> JsValue {
    array(entries.iter(), entry_out)
}

/// Released blobs as `{ stream, blob }`.
fn released_out(released: Vec<(StreamId, BlobId)>) -> JsValue {
    array(released, |(stream, blob)| {
        Obj::new()
            .set("stream", stream.to_string())
            .set("blob", blob.to_string())
            .build()
    })
}

fn entry_id(text: &str) -> Result<EntryId, JsValue> {
    id::<EntryId>(text)
}

fn parent_id(parent: Option<String>) -> Result<Option<EntryId>, JsValue> {
    parent.as_deref().map(entry_id).transpose()
}

/// A file from `{ stream, blob, size?, mediaType? }`.
fn file_in(value: &JsValue) -> Result<DriveFile, JsValue> {
    const WHAT: &str = "a drive file";
    let stream = id::<StreamId>(&text_field(value, "stream", WHAT)?)?;
    let blob = id::<BlobId>(&text_field(value, "blob", WHAT)?)?;
    let mut file = DriveFile::new(stream, blob);
    let size = field(value, "size")?;
    if !size.is_undefined() && !size.is_null() {
        let n = size
            .as_f64()
            .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n <= 9_007_199_254_740_991.0)
            .ok_or_else(|| invalid("a drive file's size is a whole number of bytes."))?;
        file = file.with_size(n as u64);
    }
    let media_type = field(value, "mediaType")?;
    if !media_type.is_undefined() && !media_type.is_null() {
        let text = media_type
            .as_string()
            .ok_or_else(|| invalid("a drive file's mediaType is a string."))?;
        file = file.with_media_type(text);
    }
    Ok(file)
}

#[wasm_bindgen]
impl Space {
    /// Creates a drive. Resolves to it.
    #[wasm_bindgen(js_name = createDrive)]
    pub fn create_drive(&self) -> Promise {
        let space = self.inner().clone();
        promise(async move {
            Ok(Drive {
                inner: space.create_drive().await.js()?,
            }
            .into())
        })
    }

    /// Opens a document of the space as a drive.
    pub fn drive(&self, stream: String) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner().clone();
        Ok(promise(async move {
            Ok(Drive {
                inner: space.drive(stream).await.js()?,
            }
            .into())
        }))
    }
}

/// A drive (`frasil::Drive`).
#[wasm_bindgen]
pub struct Drive {
    inner: frasil::Drive,
}

#[wasm_bindgen]
impl Drive {
    /// The drive's document ID: 32 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// A folder's entries, or the root's for `null`, under shown names.
    pub fn entries(&self, folder: Option<String>) -> Result<Promise, JsValue> {
        let folder = parent_id(folder)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            Ok(entries_out(drive.entries(folder).await.js()?))
        }))
    }

    /// Every entry, the trash's included.
    pub fn all(&self) -> Promise {
        let drive = self.inner.clone();
        promise(async move { Ok(entries_out(drive.all().await.js()?)) })
    }

    /// An entry, or `undefined`.
    pub fn entry(&self, entry: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            Ok(drive
                .entry(entry)
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, |e| entry_out(&e)))
        }))
    }

    /// The entry that lists a document stream, or `undefined`.
    #[wasm_bindgen(js_name = entryFor)]
    pub fn entry_for(&self, stream: String) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            Ok(drive
                .entry_for(stream)
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, |e| entry_out(&e)))
        }))
    }

    /// The trash, the most recent first.
    pub fn trash(&self) -> Promise {
        let drive = self.inner.clone();
        promise(async move { Ok(entries_out(drive.trash().await.js()?)) })
    }

    /// The files in conflict: two or more heads.
    pub fn conflicts(&self) -> Promise {
        let drive = self.inner.clone();
        promise(async move { Ok(entries_out(drive.conflicts().await.js()?)) })
    }

    /// A file's versions, oldest first, each as `{ blob, stream, size,
    /// written, parents, author }`.
    pub fn versions(&self, entry: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            let versions = drive.versions(entry).await.js()?;
            Ok(array(versions.iter(), |(blob, version)| {
                version_out(blob, version)
            }))
        }))
    }

    /// Sets a file's blob to a new version, `{ stream, blob, size?,
    /// mediaType? }`, made from `parents`: the version this device's copy
    /// came from, or every head to resolve a conflict.
    #[wasm_bindgen(js_name = setBlob)]
    pub fn set_blob(
        &self,
        entry: String,
        file: JsValue,
        parents: JsValue,
    ) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let file = file_in(&file)?;
        let parents = blobs_in(&parents)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.set_blob(entry, &file, &parents).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Makes an older version of a file its current version again, as a
    /// new version made from every head. Resolves to the new version's
    /// blob.
    #[wasm_bindgen(js_name = restoreVersion)]
    pub fn restore_version(&self, entry: String, blob: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let blob = id::<BlobId>(&blob)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            let restored = drive.restore_version(entry, blob).await.js()?;
            Ok(JsValue::from_str(&restored.to_string()))
        }))
    }

    /// Adds a folder. Resolves to its ID.
    #[wasm_bindgen(js_name = addFolder)]
    pub fn add_folder(&self, parent: Option<String>, name: String) -> Result<Promise, JsValue> {
        let parent = parent_id(parent)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            let id = drive.add_folder(parent, &name).await.js()?;
            Ok(JsValue::from_str(&id.to_string()))
        }))
    }

    /// Adds a file: `{ stream, blob, size?, mediaType? }`. Resolves to its
    /// ID.
    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(
        &self,
        parent: Option<String>,
        name: String,
        file: JsValue,
    ) -> Result<Promise, JsValue> {
        let parent = parent_id(parent)?;
        let file = file_in(&file)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            let id = drive.add_file(parent, &name, &file).await.js()?;
            Ok(JsValue::from_str(&id.to_string()))
        }))
    }

    /// Adds a document stream of the application's kind. Resolves to its
    /// ID.
    #[wasm_bindgen(js_name = addDocument)]
    pub fn add_document(
        &self,
        parent: Option<String>,
        name: String,
        stream: String,
        kind: String,
    ) -> Result<Promise, JsValue> {
        let parent = parent_id(parent)?;
        let stream = id::<StreamId>(&stream)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            let id = drive
                .add_document(parent, &name, stream, &kind)
                .await
                .js()?;
            Ok(JsValue::from_str(&id.to_string()))
        }))
    }

    /// Renames an entry.
    pub fn rename(&self, entry: String, name: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.rename(entry, &name).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Moves an entry into a folder, or to the root for `null`.
    #[wasm_bindgen(js_name = moveTo)]
    pub fn move_to(&self, entry: String, parent: Option<String>) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let parent = parent_id(parent)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.move_to(entry, parent).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Sends an entry to the trash.
    #[wasm_bindgen(js_name = moveToTrash)]
    pub fn move_to_trash(&self, entry: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.move_to_trash(entry).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Brings an entry back from the trash.
    pub fn restore(&self, entry: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.restore(entry).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Forgets an entry for good. Resolves to the released blobs, as
    /// `{ stream, blob }`.
    pub fn purge(&self, entry: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            Ok(released_out(drive.purge(entry).await.js()?))
        }))
    }

    /// Sets one of an entry's application fields.
    #[wasm_bindgen(js_name = setMeta)]
    pub fn set_meta(&self, entry: String, key: String, value: JsValue) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let value = loro_in(&value, 1)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.set_meta(entry, &key, value).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Deletes one of an entry's application fields.
    #[wasm_bindgen(js_name = deleteMeta)]
    pub fn delete_meta(&self, entry: String, key: String) -> Result<Promise, JsValue> {
        let entry = entry_id(&entry)?;
        let drive = self.inner.clone();
        Ok(promise(async move {
            drive.delete_meta(entry, &key).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Makes several changes together: `changes(batch)` makes them on a
    /// `DriveBatch`, synchronously, and they are written as one change, or
    /// none if it throws. Resolves to what it returned; rejects with what
    /// it threw, or the write's error.
    pub fn batch(&self, changes: js_sys::Function) -> Promise {
        self.run_batch(changes, false)
    }

    /// As `batch`, resolving to `{ value, receipt }`: what the callback
    /// returned, and a `Receipt` for the change, absent when the batch made
    /// no operation.
    #[wasm_bindgen(js_name = batchWithReceipt)]
    pub fn batch_with_receipt(&self, changes: js_sys::Function) -> Promise {
        self.run_batch(changes, true)
    }

    /// Runs a batch, resolving to what the callback returned, with a
    /// receipt when `receipt` asks for one.
    fn run_batch(&self, changes: js_sys::Function, receipt: bool) -> Promise {
        let drive = self.inner.clone();
        promise(async move {
            let mut thrown = None;
            let mut returned = JsValue::UNDEFINED;
            let written = drive
                .batch_with_receipt(|batch| {
                    let held = Rc::new(RefCell::new(Some(batch.clone())));
                    let lent = DriveBatch {
                        inner: held.clone(),
                    };
                    let result = changes.call1(&JsValue::NULL, &lent.into());
                    if let Ok(mut held) = held.try_borrow_mut() {
                        held.take();
                    }
                    match result {
                        Ok(value) => {
                            returned = value;
                            Ok(())
                        }
                        Err(error) => {
                            thrown = Some(error);
                            Err(frasil::Error::Invalid("the batch's callback threw"))
                        }
                    }
                })
                .await;
            if let Some(error) = thrown {
                return Err(error);
            }
            let ((), written) = written.js()?;
            if !receipt {
                return Ok(returned);
            }
            Ok(Obj::new()
                .set("value", returned)
                .set(
                    "receipt",
                    written.map_or(JsValue::UNDEFINED, |receipt| {
                        crate::reads::Receipt::from(receipt).into()
                    }),
                )
                .build())
        })
    }

    /// The drive's changes from now on. Resolves to a feed.
    pub fn changes(&self) -> Promise {
        let drive = self.inner.clone();
        promise(async move {
            Ok(DriveChanges {
                inner: Rc::new(RefCell::new(Some(drive.changes().await.js()?))),
            }
            .into())
        })
    }
}

/// A drive's changes, as `changes()` yields them.
#[wasm_bindgen]
pub struct DriveChanges {
    /// Lent to the one `next()` in flight, and given back when it settles.
    inner: Rc<RefCell<Option<frasil::DriveChanges>>>,
}

#[wasm_bindgen]
impl DriveChanges {
    /// The next change, as `{ entries, roots }`: the IDs of the entries it
    /// added, changed or removed, and the names of the document's other
    /// root containers it changed; `undefined` once the device is gone.
    /// One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut changes = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("DriveChanges.next is already waiting."))?;
        Ok(promise(async move {
            let changed = changes.next().await;
            if let Ok(mut back) = slot.try_borrow_mut() {
                *back = Some(changes);
            }
            Ok(changed.map_or(JsValue::UNDEFINED, |change| {
                Obj::new()
                    .set(
                        "entries",
                        array(change.entries, |id| JsValue::from_str(&id.to_string())),
                    )
                    .set(
                        "roots",
                        array(change.roots, |name| JsValue::from_str(&name)),
                    )
                    .set("origin", crate::reads::origin(change.origin))
                    .build()
            }))
        }))
    }
}

/// Changes made together (`frasil::DriveBatch`), lent to a `batch` callback
/// while it runs. Each method makes its change at once, against the drive
/// as the changes before it leave it, and throws a refusal, which writes
/// nothing of its own.
#[wasm_bindgen]
pub struct DriveBatch {
    /// The batch, until the callback returns.
    inner: Rc<RefCell<Option<frasil::DriveBatch>>>,
}

impl DriveBatch {
    fn with<T>(
        &self,
        change: impl FnOnce(&mut frasil::DriveBatch) -> frasil::Result<T>,
    ) -> Result<T, JsValue> {
        let mut held = self
            .inner
            .try_borrow_mut()
            .map_err(|_| invalid("DriveBatch is in use."))?;
        let batch = held.as_mut().ok_or_else(|| {
            invalid("The batch was written: make its changes before its callback returns.")
        })?;
        change(batch).js()
    }
}

#[wasm_bindgen]
impl DriveBatch {
    /// Adds a folder. Returns its ID.
    #[wasm_bindgen(js_name = addFolder)]
    pub fn add_folder(&self, parent: Option<String>, name: String) -> Result<String, JsValue> {
        let parent = parent_id(parent)?;
        let id = self.with(|b| b.add_folder(parent, &name))?;
        Ok(id.to_string())
    }

    /// Adds a file: `{ stream, blob, size?, mediaType? }`. Returns its ID.
    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(
        &self,
        parent: Option<String>,
        name: String,
        file: JsValue,
    ) -> Result<String, JsValue> {
        let parent = parent_id(parent)?;
        let file = file_in(&file)?;
        let id = self.with(|b| b.add_file(parent, &name, &file))?;
        Ok(id.to_string())
    }

    /// Adds a document stream of the application's kind. Returns its ID.
    #[wasm_bindgen(js_name = addDocument)]
    pub fn add_document(
        &self,
        parent: Option<String>,
        name: String,
        stream: String,
        kind: String,
    ) -> Result<String, JsValue> {
        let parent = parent_id(parent)?;
        let stream = id::<StreamId>(&stream)?;
        let id = self.with(|b| b.add_document(parent, &name, stream, &kind))?;
        Ok(id.to_string())
    }

    /// Renames an entry.
    pub fn rename(&self, entry: String, name: String) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        self.with(|b| b.rename(entry, &name))
    }

    /// Moves an entry into a folder, or to the root for `null`.
    #[wasm_bindgen(js_name = moveTo)]
    pub fn move_to(&self, entry: String, parent: Option<String>) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        let parent = parent_id(parent)?;
        self.with(|b| b.move_to(entry, parent))
    }

    /// Sends an entry to the trash.
    #[wasm_bindgen(js_name = moveToTrash)]
    pub fn move_to_trash(&self, entry: String) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        self.with(|b| b.move_to_trash(entry))
    }

    /// Brings an entry back from the trash.
    pub fn restore(&self, entry: String) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        self.with(|b| b.restore(entry))
    }

    /// Sets a file's blob to a new version made from `parents`.
    #[wasm_bindgen(js_name = setBlob)]
    pub fn set_blob(&self, entry: String, file: JsValue, parents: JsValue) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        let file = file_in(&file)?;
        let parents = blobs_in(&parents)?;
        self.with(|b| b.set_blob(entry, &file, &parents))
    }

    /// Forgets an entry for good. Returns the released blobs, as
    /// `{ stream, blob }`.
    pub fn purge(&self, entry: String) -> Result<JsValue, JsValue> {
        let entry = entry_id(&entry)?;
        Ok(released_out(self.with(|b| b.purge(entry))?))
    }

    /// Sets one of an entry's application fields.
    #[wasm_bindgen(js_name = setMeta)]
    pub fn set_meta(&self, entry: String, key: String, value: JsValue) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        let value = loro_in(&value, 1)?;
        self.with(|b| b.set_meta(entry, &key, value))
    }

    /// Deletes one of an entry's application fields.
    #[wasm_bindgen(js_name = deleteMeta)]
    pub fn delete_meta(&self, entry: String, key: String) -> Result<(), JsValue> {
        let entry = entry_id(&entry)?;
        self.with(|b| b.delete_meta(entry, &key))
    }
}
