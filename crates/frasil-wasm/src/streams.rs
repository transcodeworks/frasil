//! A space's streams, as JavaScript classes: Loro documents
//! (adapter-loro.md), Records tables (adapter-records.md) and blobs
//! (adapter-blobs.md).
//!
//! A write crosses as a list of operations the TypeScript layer collected
//! from the application's callback, and becomes one change: the operations
//! are read before anything is written, so one that does not read writes
//! nothing.

use crate::callback::progress;
use crate::convert::{
    Obj, array, bytes, bytes_in, field, hex, id, index_field, items, key_in, loro_in, loro_out,
    number, text_field, value_in, value_out,
};
use crate::error::{Js, error, invalid};
use crate::platform::message_of;
use crate::promise;
use crate::space::Space;
use frasil::{
    BlobId, Change, Detail, Effect, Kind, Marked, Review, ReviewChange, Row, Standing, Suggestion,
    SuggestionId, TextStep, UnitId, Value, Version,
};
use js_sys::{Function, Promise};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Suggestion IDs from a JavaScript array of their hex strings.
fn suggestion_ids(value: &JsValue) -> Result<Vec<SuggestionId>, JsValue> {
    items(value, "the suggestions")?
        .iter()
        .map(|item| {
            item.as_string()
                .ok_or_else(|| invalid("the suggestions are an array of IDs."))
                .and_then(|text| id::<SuggestionId>(&text))
        })
        .collect()
}

/// Suggestions as `{ id, author, update }`.
fn suggestions_out(suggestions: Vec<Suggestion>) -> JsValue {
    array(suggestions, |suggestion| {
        Obj::new()
            .set("id", suggestion.id.to_string())
            .set("author", suggestion.author.to_string())
            .set("update", bytes(&suggestion.update))
            .build()
    })
}

/// Lowercase hex as bytes.
fn hex_in(text: &str) -> Result<Vec<u8>, JsValue> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid("hex has an even number of digits"));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or_else(|| invalid("hex digits only"))
        })
        .collect()
}

/// An author (`frasil::Author`) as `{ device, deviceName?, person?,
/// personName?, persons }`.
pub(crate) fn author_out(author: &frasil::Author) -> JsValue {
    let out = Obj::new().set("device", author.device.to_string());
    let out = match &author.device_name {
        Some(name) => out.set("deviceName", name.clone()),
        None => out,
    };
    let out = match author.person {
        Some(person) => out.set("person", person.to_string()),
        None => out,
    };
    let out = match &author.person_name {
        Some(name) => out.set("personName", name.clone()),
        None => out,
    };
    out.set(
        "persons",
        array(&author.persons, |person| {
            JsValue::from_str(&person.to_string())
        }),
    )
    .build()
}

/// A change of a stream's history as a plain object (`frasil::Change`):
/// IDs as hex, the span's peer as a decimal string, versions as hex of
/// Loro's encoding.
fn change_out(change: &Change) -> JsValue {
    let mut out = Obj::new()
        .set("id", change.id.to_string())
        .set("author", author_out(&change.author))
        .set("seq", JsValue::from_f64(change.seq as f64))
        .set("height", JsValue::from_f64(change.height as f64));
    if let Some(time) = change.time {
        out = out.set("time", JsValue::from_f64(time as f64));
    }
    let ids = |ids: &[SuggestionId]| array(ids, |id| JsValue::from_str(&id.to_string()));
    out = match &change.kind {
        Kind::Edit => out.set("kind", "edit"),
        Kind::Suggestion(standing) => out.set("kind", "suggestion").set(
            "standing",
            match standing {
                Standing::Open => "open",
                Standing::Accepted => "accepted",
                Standing::Dismissed => "dismissed",
            },
        ),
        Kind::Review { accepts, dismisses } => out
            .set("kind", "review")
            .set("accepts", ids(accepts))
            .set("dismisses", ids(dismisses)),
        Kind::Snapshot => out.set("kind", "snapshot"),
        _ => out.set("kind", "other"),
    };
    out = match change.effect {
        Effect::Applied => out.set("effect", "applied"),
        Effect::Waiting(class) => out.set("effect", "waiting").set("class", class),
        Effect::Refused(class) => out.set("effect", "refused").set("class", class),
        Effect::Withdrawn => out.set("effect", "withdrawn"),
    };
    match &change.detail {
        Detail::Document(Some(detail)) => {
            let span = Obj::new()
                .set("peer", detail.span.peer.to_string())
                .set("from", JsValue::from_f64(f64::from(detail.span.from)))
                .set("to", JsValue::from_f64(f64::from(detail.span.to)))
                .build();
            out = out
                .set("span", span)
                .set("after", hex(&detail.after.encode()))
                .set(
                    "containers",
                    array(&detail.containers, |c| JsValue::from_str(c)),
                );
            if let Some(before) = &detail.before {
                out = out.set("before", hex(&before.encode()));
            }
        }
        Detail::Document(None) => {}
        Detail::Records(rows) => {
            out = out.set(
                "rows",
                array(rows, |row| {
                    Obj::new()
                        .set("table", row.table.clone())
                        .set("key", String::from_utf8_lossy(&row.key).into_owned())
                        .set("keyBytes", bytes(&row.key))
                        .set("columns", array(&row.columns, |c| JsValue::from_str(c)))
                        .set("inserted", row.inserted)
                        .set("deleted", row.deleted)
                        .build()
                }),
            );
        }
        _ => {}
    }
    out.build()
}

/// A version as a plain object (`frasil::Version`): `marked` holds
/// `frontier` (hex) for a document, `change` (hex) for tables.
pub(crate) fn version_out(version: &Version) -> JsValue {
    let marked = match &version.marked {
        Marked::Document(frontier) => Obj::new().set("frontier", hex(&frontier.encode())),
        Marked::Records(change) => Obj::new().set("change", change.to_string()),
        _ => Obj::new(),
    };
    let mut out = Obj::new()
        .set("id", version.id.to_string())
        .set("stream", version.stream.to_string())
        .set("name", version.name.clone())
        .set("marked", marked.build())
        .set("author", version.author.to_string());
    if let Some(time) = version.time {
        out = out.set("time", JsValue::from_f64(time as f64));
    }
    out.build()
}

/// A review as a plain object (`frasil::Review`): each change with a
/// `kind` of `text`, `map`, `list`, `other` or `cell`.
fn review_out(review: &Review) -> JsValue {
    let mut out = Obj::new()
        .set("id", review.id.to_string())
        .set("author", review.author.to_string())
        .set("baseMissing", review.base_missing);
    if let Some(base) = &review.base {
        out = out.set("base", hex(&base.encode()));
    }
    let changes = array(&review.changes, |change| match change {
        ReviewChange::Text { container, delta } => Obj::new()
            .set("kind", "text")
            .set("container", container.clone())
            .set(
                "delta",
                array(delta, |step| match step {
                    TextStep::Retain(n) => Obj::new().set("retain", number(*n)).build(),
                    TextStep::Insert(text) => Obj::new().set("insert", text.clone()).build(),
                    TextStep::Delete(n) => Obj::new().set("delete", number(*n)).build(),
                    _ => Obj::new().build(),
                }),
            )
            .build(),
        ReviewChange::Map {
            container,
            key,
            from,
            to,
        } => {
            let mut out = Obj::new()
                .set("kind", "map")
                .set("container", container.clone())
                .set("key", key.clone());
            if let Some(from) = from {
                out = out.set("from", loro_out(from));
            }
            if let Some(to) = to {
                out = out.set("to", loro_out(to));
            }
            out.build()
        }
        ReviewChange::List {
            container,
            from,
            to,
        } => Obj::new()
            .set("kind", "list")
            .set("container", container.clone())
            .set("from", array(from, loro_out))
            .set("to", array(to, loro_out))
            .build(),
        ReviewChange::Cell {
            table,
            key,
            column,
            from,
            to,
        } => {
            let mut out = Obj::new()
                .set("kind", "cell")
                .set("table", table.clone())
                .set("key", String::from_utf8_lossy(key).into_owned())
                .set("keyBytes", bytes(key))
                .set("column", column.clone());
            if let Some(from) = from {
                out = out.set("from", value_out(from));
            }
            if let Some(to) = to {
                out = out.set("to", value_out(to));
            }
            out.build()
        }
        ReviewChange::Other { container } => Obj::new()
            .set("kind", "other")
            .set("container", container.clone())
            .build(),
        _ => Obj::new().set("kind", "other").build(),
    });
    out.set("changes", changes).build()
}

/// A suggestion's ID from hex.
fn suggestion_id(text: &str) -> Result<SuggestionId, JsValue> {
    text.parse()
        .map_err(|_| invalid("a suggestion's ID is 64 hex digits"))
}

/// A row as a plain object of its columns' values.
pub(crate) fn row_out(row: &Row) -> JsValue {
    row.iter()
        .fold(Obj::new(), |out, (column, value)| {
            out.define(column, &value_out(value))
        })
        .build()
}

// ---- Documents --------------------------------------------------------------------------------

/// One operation of a document edit. Text positions and lengths count
/// UTF-16 code units, as JavaScript's strings do.
enum Edit {
    TextInsert(String, usize, String),
    TextDelete(String, usize, usize),
    MapSet(String, String, loro::LoroValue),
    MapDelete(String, String),
    ListInsert(String, usize, loro::LoroValue),
    ListDelete(String, usize, usize),
}

impl Edit {
    fn read(op: &JsValue) -> Result<Self, JsValue> {
        const WHAT: &str = "a document edit";
        let kind = text_field(op, "op", WHAT)?;
        let container = text_field(op, "container", WHAT)?;
        Ok(match kind.as_str() {
            "textInsert" => Self::TextInsert(
                container,
                index_field(op, "index", WHAT)?,
                text_field(op, "text", WHAT)?,
            ),
            "textDelete" => Self::TextDelete(
                container,
                index_field(op, "index", WHAT)?,
                index_field(op, "length", WHAT)?,
            ),
            "mapSet" => Self::MapSet(
                container,
                text_field(op, "key", WHAT)?,
                loro_in(&field(op, "value")?, 1)?,
            ),
            "mapDelete" => Self::MapDelete(container, text_field(op, "key", WHAT)?),
            "listInsert" => Self::ListInsert(
                container,
                index_field(op, "index", WHAT)?,
                loro_in(&field(op, "value")?, 1)?,
            ),
            "listDelete" => Self::ListDelete(
                container,
                index_field(op, "index", WHAT)?,
                index_field(op, "length", WHAT)?,
            ),
            _ => {
                return Err(invalid(
                    "a document edit's op is not one this binding knows.",
                ));
            }
        })
    }

    fn apply(self, doc: &loro::LoroDoc) -> loro::LoroResult<()> {
        match self {
            Self::TextInsert(container, index, text) => {
                doc.get_text(container.as_str()).insert_utf16(index, &text)
            }
            Self::TextDelete(container, index, length) => {
                doc.get_text(container.as_str()).delete_utf16(index, length)
            }
            Self::MapSet(container, key, value) => {
                doc.get_map(container.as_str()).insert(&key, value)
            }
            Self::MapDelete(container, key) => doc.get_map(container.as_str()).delete(&key),
            Self::ListInsert(container, index, value) => {
                doc.get_list(container.as_str()).insert(index, value)
            }
            Self::ListDelete(container, index, length) => {
                doc.get_list(container.as_str()).delete(index, length)
            }
        }
    }
}

/// A Loro document in a space.
#[wasm_bindgen]
pub struct Document {
    pub(crate) inner: frasil::Document,
}

impl From<frasil::Document> for Document {
    fn from(inner: frasil::Document) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Document {
    /// The document's ID in its space: 32 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Edits the document: the operations `ops` lists, as one change.
    /// Nothing is written when one fails or there is none.
    pub fn edit(&self, ops: JsValue) -> Result<Promise, JsValue> {
        let edits = items(&ops, "the edits")?
            .iter()
            .map(Edit::read)
            .collect::<Result<Vec<_>, _>>()?;
        let document = self.inner.clone();
        Ok(promise(async move {
            document
                .edit(|doc| edits.into_iter().try_for_each(|edit| edit.apply(doc)))
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Edits the document as `edit` does, and resolves to a `Receipt` for
    /// the change.
    #[wasm_bindgen(js_name = editWithReceipt)]
    pub fn edit_with_receipt(&self, ops: JsValue) -> Result<Promise, JsValue> {
        let edits = items(&ops, "the edits")?
            .iter()
            .map(Edit::read)
            .collect::<Result<Vec<_>, _>>()?;
        let document = self.inner.clone();
        Ok(promise(async move {
            let receipt = document
                .edit_with_receipt(|doc| edits.into_iter().try_for_each(|edit| edit.apply(doc)))
                .await
                .js()?;
            Ok(crate::reads::Receipt::from(receipt).into())
        }))
    }

    /// Sets a text container to `text`, writing only what differs
    /// (`frasil::Document::set_text`), within `limit_ms`, two seconds if
    /// not given. Past it the changed part is replaced in one operation,
    /// or, with `stop_at_limit`, the call fails (`limit_passed`) with the
    /// document as it was. The comparison runs on the page's own thread.
    /// A change in several units commits each on its own: a failure after
    /// the first, such as the store's, can leave some written, pending for
    /// good while the text stays as it was; calling again writes the
    /// change anew.
    #[wasm_bindgen(js_name = setText)]
    pub fn set_text(
        &self,
        container: String,
        text: String,
        limit_ms: Option<f64>,
        stop_at_limit: bool,
    ) -> Promise {
        let document = self.inner.clone();
        promise(async move {
            let mut options = frasil::SetText::default();
            if let Some(limit) =
                limit_ms.and_then(|ms| std::time::Duration::try_from_secs_f64(ms / 1000.0).ok())
            {
                options = options.limit(limit);
            }
            if stop_at_limit {
                options = options.stop_at_limit();
            }
            let written = document
                .set_text(container.as_str(), &text, options)
                .await
                .js()?;
            let outcome = match written.outcome {
                frasil::TextOutcome::Unchanged => "unchanged",
                frasil::TextOutcome::Edited => "edited",
                frasil::TextOutcome::Replaced => "replaced",
            };
            Ok(Obj::new()
                .set("outcome", outcome)
                .set("units", JsValue::from_f64(written.units as f64))
                .set("moved", written.moved)
                .set("limitPassed", written.limit_passed)
                .build())
        })
    }

    /// The text of one of the document's text containers.
    pub fn text(&self, container: String) -> Promise {
        let document = self.inner.clone();
        promise(async move { Ok(JsValue::from_str(&document.text(&container).await.js()?)) })
    }

    /// The whole document as plain values: each root container by name.
    pub fn read(&self) -> Promise {
        let document = self.inner.clone();
        promise(async move {
            let doc = document.read().await.js()?;
            Ok(loro_out(&doc.get_deep_value()))
        })
    }

    /// Moves the document into `space`, a restricted space of its own
    /// space (ext-restricted-spaces.md, "Moved documents"). Resolves to the
    /// new document; this one ends.
    #[wasm_bindgen(js_name = moveTo)]
    pub fn move_to(&self, space: &Space) -> Promise {
        let document = self.inner.clone();
        let space = space.inner().clone();
        promise(async move { Ok(Document::from(document.move_to(&space).await.js()?).into()) })
    }

    /// Live editing: a handle that holds one incarnation of this device,
    /// which the application's own `LoroDoc` commits to and follows.
    pub fn live(&self) -> Promise {
        let document = self.inner.clone();
        promise(async move {
            Ok(Live {
                inner: document.live().await.js()?,
            }
            .into())
        })
    }

    /// Suggests a Loro update for a writer to accept. Resolves to its ID.
    pub fn suggest(&self, update: Vec<u8>) -> Promise {
        let document = self.inner.clone();
        promise(async move {
            let id = document.suggest(&update).await.js()?;
            Ok(JsValue::from_str(&id.to_string()))
        })
    }

    /// The suggestions waiting on the document: `{ id, author, update }`.
    pub fn suggestions(&self) -> Promise {
        let document = self.inner.clone();
        promise(async move { Ok(suggestions_out(document.suggestions().await.js()?)) })
    }

    /// The document's history: its changes, oldest first, as plain
    /// objects (`frasil::Change`).
    pub fn history(&self) -> Promise {
        let document = self.inner.clone();
        promise(async move {
            let history = document.history().await.js()?;
            Ok(array(&history, change_out))
        })
    }

    /// Tags the document as it stands, by name: a synced version.
    pub fn tag(&self, name: String) -> Promise {
        let document = self.inner.clone();
        promise(async move { Ok(version_out(&document.tag(&name).await.js()?)) })
    }

    /// The versions tagged on the document.
    pub fn versions(&self) -> Promise {
        let document = self.inner.clone();
        promise(async move { Ok(array(&document.versions().await.js()?, version_out)) })
    }

    /// Reads a suggestion for review: what it changes against its base.
    pub fn review(&self, suggestion: String) -> Result<Promise, JsValue> {
        let id = suggestion_id(&suggestion)?;
        let document = self.inner.clone();
        Ok(promise(async move {
            Ok(review_out(&document.review(id).await.js()?))
        }))
    }

    /// The document as it stood at a version (a change's `before` or
    /// `after`, hex): a snapshot's bytes, to import into a `LoroDoc` of
    /// the page's own.
    pub fn at(&self, version: String) -> Result<Promise, JsValue> {
        let version =
            loro::Frontiers::decode(&hex_in(&version)?).map_err(|e| invalid(&e.to_string()))?;
        let document = self.inner.clone();
        Ok(promise(async move {
            Ok(bytes(&document.snapshot_at(&version).await.js()?))
        }))
    }

    /// Accepts suggestions by their IDs.
    pub fn accept(&self, ids: JsValue) -> Result<Promise, JsValue> {
        let ids = suggestion_ids(&ids)?;
        let document = self.inner.clone();
        Ok(promise(async move {
            document.accept(&ids).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Dismisses suggestions by their IDs.
    pub fn dismiss(&self, ids: JsValue) -> Result<Promise, JsValue> {
        let ids = suggestion_ids(&ids)?;
        let document = self.inner.clone();
        Ok(promise(async move {
            document.dismiss(&ids).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }
}

/// Live editing of a document (`frasil::Live`): the application's own
/// `LoroDoc`, with `peerId` as its peer, commits its updates here and
/// imports the updates `changes()` yields.
#[wasm_bindgen]
pub struct Live {
    inner: frasil::Live,
}

#[wasm_bindgen]
impl Live {
    /// The peer ID the application sets on its own `LoroDoc`.
    #[wasm_bindgen(getter, js_name = peerId)]
    pub fn peer_id(&self) -> u64 {
        self.inner.peer_id()
    }

    /// Commits a Loro update authored by `peerId`.
    pub fn commit(&self, update: Vec<u8>) -> Promise {
        let live = self.inner.clone();
        promise(async move {
            live.commit(&update).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Suggests a Loro update instead of committing it.
    pub fn suggest(&self, update: Vec<u8>) -> Promise {
        let live = self.inner.clone();
        promise(async move {
            live.suggest(&update).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// The updates since `version`, an encoded Loro version vector; empty
    /// for everything.
    #[wasm_bindgen(js_name = exportSince)]
    pub fn export_since(&self, version: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        self.inner.export_since(&version).js()
    }

    /// The document's version, an encoded Loro version vector.
    pub fn version(&self) -> Vec<u8> {
        self.inner.version()
    }

    /// The updates others make, from now on.
    pub fn changes(&self) -> LiveChanges {
        LiveChanges {
            inner: Rc::new(RefCell::new(Some(self.inner.changes()))),
        }
    }
}

/// Loro updates from others, as `changes()` yields them.
#[wasm_bindgen]
pub struct LiveChanges {
    /// Lent to the one `next()` in flight, and given back when it settles.
    inner: Rc<RefCell<Option<frasil::Changes>>>,
}

#[wasm_bindgen]
impl LiveChanges {
    /// The next update; `undefined` once the document is gone. One call at
    /// a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut changes = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("LiveChanges.next is already waiting."))?;
        Ok(promise(async move {
            let update = changes.next().await;
            if let Ok(mut back) = slot.try_borrow_mut() {
                *back = Some(changes);
            }
            Ok(update.map_or(JsValue::UNDEFINED, |update| bytes(&update)))
        }))
    }
}

// ---- Records ----------------------------------------------------------------------------------

/// One operation of a Records write.
enum Cell {
    Insert(String, Vec<u8>),
    Set(String, Vec<u8>, String, Value),
    Clear(String, Vec<u8>, String),
    Delete(String, Vec<u8>),
}

impl Cell {
    fn read(op: &JsValue) -> Result<Self, JsValue> {
        const WHAT: &str = "a Records write";
        let kind = text_field(op, "op", WHAT)?;
        let table = text_field(op, "table", WHAT)?;
        let key = key_in(&field(op, "key")?, "a row's key")?;
        Ok(match kind.as_str() {
            "insert" => Self::Insert(table, key),
            "set" => Self::Set(
                table,
                key,
                text_field(op, "column", WHAT)?,
                value_in(&field(op, "value")?, 1)?,
            ),
            "clear" => Self::Clear(table, key, text_field(op, "column", WHAT)?),
            "delete" => Self::Delete(table, key),
            _ => {
                return Err(invalid(
                    "a Records write's op is not one this binding knows.",
                ));
            }
        })
    }
}

/// Tables of rows in a space.
#[wasm_bindgen]
pub struct Records {
    pub(crate) inner: frasil::Records,
}

impl From<frasil::Records> for Records {
    fn from(inner: frasil::Records) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Records {
    /// The stream's ID in its space: 32 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Writes the cells `ops` lists, as one change.
    pub fn write(&self, ops: JsValue) -> Result<Promise, JsValue> {
        self.write_cells(&ops, false, false)
    }
}

impl Records {
    /// Writes the cells `ops` lists as one change, or as a suggestion;
    /// resolves to a `Receipt` when `receipt` asks for one.
    pub(crate) fn write_cells(
        &self,
        ops: &JsValue,
        suggestion: bool,
        receipt: bool,
    ) -> Result<Promise, JsValue> {
        let cells = items(ops, "the writes")?
            .iter()
            .map(Cell::read)
            .collect::<Result<Vec<_>, _>>()?;
        let records = self.inner.clone();
        Ok(promise(async move {
            let written = records
                .write_with_receipt(|transaction| {
                    if suggestion {
                        transaction.suggest();
                    }
                    for cell in cells {
                        match cell {
                            Cell::Insert(table, key) => transaction.insert(&table, &key),
                            Cell::Set(table, key, column, value) => {
                                transaction.set(&table, &key, &column, value)
                            }
                            Cell::Clear(table, key, column) => {
                                transaction.clear(&table, &key, &column)
                            }
                            Cell::Delete(table, key) => transaction.delete(&table, &key),
                        };
                    }
                })
                .await
                .js()?;
            Ok(if receipt {
                crate::reads::Receipt::from(written).into()
            } else {
                JsValue::UNDEFINED
            })
        }))
    }
}

#[wasm_bindgen]
impl Records {
    /// The rows of a table, by key: `[key, row]` pairs in key order.
    pub fn rows(&self, table: String) -> Promise {
        let records = self.inner.clone();
        promise(async move {
            let rows = records.rows(&table).await.js()?;
            Ok(array(rows, |(key, row)| {
                js_sys::Array::of2(&bytes(&key), &row_out(&row)).into()
            }))
        })
    }

    /// Suggests the cells `ops` lists, as one change, for a writer to
    /// accept (adapter-records.md, section 3.4).
    pub fn suggest(&self, ops: JsValue) -> Result<Promise, JsValue> {
        self.write_cells(&ops, true, false)
    }

    /// The suggestions waiting on the tables: `{ id, author, update }`.
    pub fn suggestions(&self) -> Promise {
        let records = self.inner.clone();
        promise(async move { Ok(suggestions_out(records.suggestions().await.js()?)) })
    }

    /// The tables' history: their changes, oldest first, as plain objects
    /// (`frasil::Change`).
    pub fn history(&self) -> Promise {
        let records = self.inner.clone();
        promise(async move {
            let history = records.history().await.js()?;
            Ok(array(&history, change_out))
        })
    }

    /// Tags the tables as they stand, by name: a synced version.
    pub fn tag(&self, name: String) -> Promise {
        let records = self.inner.clone();
        promise(async move { Ok(version_out(&records.tag(&name).await.js()?)) })
    }

    /// The versions tagged on the tables.
    pub fn versions(&self) -> Promise {
        let records = self.inner.clone();
        promise(async move { Ok(array(&records.versions().await.js()?, version_out)) })
    }

    /// Reads a suggestion for review: each cell it sets, with its value
    /// now and the one suggested.
    pub fn review(&self, suggestion: String) -> Result<Promise, JsValue> {
        let id = suggestion_id(&suggestion)?;
        let records = self.inner.clone();
        Ok(promise(async move {
            Ok(review_out(&records.review(id).await.js()?))
        }))
    }

    /// The tables as they stood after a change (its ID, hex): each table's
    /// `[key, row]` pairs in key order, by table name.
    pub fn at(&self, change: String) -> Result<Promise, JsValue> {
        let change: UnitId = change
            .parse()
            .map_err(|_| invalid("a change's ID is 64 hex digits"))?;
        let records = self.inner.clone();
        Ok(promise(async move {
            let tables = records.at(change).await.js()?;
            let out = tables.iter().fold(Obj::new(), |out, (table, rows)| {
                out.define(
                    table,
                    &array(rows, |(key, row)| {
                        js_sys::Array::of2(&bytes(key), &row_out(row)).into()
                    }),
                )
            });
            Ok(out.build())
        }))
    }

    /// Accepts suggestions by their IDs.
    pub fn accept(&self, ids: JsValue) -> Result<Promise, JsValue> {
        let ids = suggestion_ids(&ids)?;
        let records = self.inner.clone();
        Ok(promise(async move {
            records.accept(&ids).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Dismisses suggestions by their IDs.
    pub fn dismiss(&self, ids: JsValue) -> Result<Promise, JsValue> {
        let ids = suggestion_ids(&ids)?;
        let records = self.inner.clone();
        Ok(promise(async move {
            records.dismiss(&ids).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// One row of a table; `undefined` unless it shows.
    pub fn row(&self, table: String, key: JsValue) -> Result<Promise, JsValue> {
        let key = key_in(&key, "a row's key")?;
        let records = self.inner.clone();
        Ok(promise(async move {
            Ok(records
                .row(&table, &key)
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, |row| row_out(&row)))
        }))
    }

    /// Who changed a row last, in which change, and when the writer says
    /// it did; `undefined` while no cell of the row is written.
    #[wasm_bindgen(js_name = lastChange)]
    pub fn last_change(&self, table: String, key: JsValue) -> Result<Promise, JsValue> {
        let key = key_in(&key, "a row's key")?;
        let records = self.inner.clone();
        Ok(promise(async move {
            Ok(records
                .last_change(&table, &key)
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, |last| {
                    let mut out = Obj::new()
                        .set("author", last.author.to_string())
                        .set("change", last.change.to_string());
                    if let Some(time) = last.time {
                        out = out.set("time", JsValue::from_f64(time as f64));
                    }
                    out.build()
                }))
        }))
    }
}

// ---- Blobs ------------------------------------------------------------------------------------

/// Blobs in a space.
#[wasm_bindgen]
pub struct Blobs {
    pub(crate) inner: frasil::Blobs,
}

impl From<frasil::Blobs> for Blobs {
    fn from(inner: frasil::Blobs) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Blobs {
    /// The stream's ID in its space: 32 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Puts a blob, with a name if given. Resolves to its ID.
    pub fn put(&self, name: Option<String>, data: Vec<u8>) -> Promise {
        let blobs = self.inner.clone();
        promise(async move {
            let id = blobs.put(name.as_deref(), &data).await.js()?;
            Ok(JsValue::from_str(&id.to_string()))
        })
    }

    /// The blobs the stream holds: `{ id, name, size }`.
    pub fn list(&self) -> Promise {
        let blobs = self.inner.clone();
        promise(async move {
            let list = blobs.list().await.js()?;
            Ok(array(list, |blob| {
                Obj::new()
                    .set("id", blob.id.to_string())
                    .set("name", blob.name.map_or(JsValue::UNDEFINED, JsValue::from))
                    .set("size", JsValue::from_f64(blob.size as f64))
                    .build()
            }))
        })
    }

    /// Puts a blob from a source, with a name if given: `pull()` resolves
    /// to the next chunk, a `Uint8Array`, or `undefined` at the end;
    /// `onProgress(done, total)` reports progress. Resolves to its ID. The
    /// source is read as a stream, and the blob is then sealed whole in
    /// WebAssembly memory, which bounds the largest blob it can put.
    #[wasm_bindgen(js_name = putStream)]
    pub fn put_stream(
        &self,
        name: Option<String>,
        pull: Function,
        on_progress: Option<Function>,
    ) -> Promise {
        let blobs = self.inner.clone();
        promise(async move {
            let reader = Pull {
                pull,
                pending: None,
                chunk: Vec::new(),
                offset: 0,
                done: false,
            };
            let id = blobs
                .put_stream(name.as_deref().unwrap_or(""), reader, progress(on_progress))
                .await
                .js()?;
            Ok(JsValue::from_str(&id.to_string()))
        })
    }

    /// Puts a blob from a source read at offsets, with a name if given:
    /// `readAt(offset, length)` resolves to a `Uint8Array` of at most
    /// `length` bytes from `offset`, empty at the end. The source is read
    /// twice, once for the blob's ID and once to seal it a chunk at a time,
    /// so the put holds a few chunks in WebAssembly memory whatever the
    /// blob's size. `onProgress(done, total)` reports the bytes sealed.
    /// Resolves to its ID; a source that changes rejects with `Changed`.
    #[wasm_bindgen(js_name = putAt)]
    pub fn put_at(
        &self,
        name: Option<String>,
        read_at: Function,
        on_progress: Option<Function>,
    ) -> Promise {
        let blobs = self.inner.clone();
        promise(async move {
            let mut reader = ReadAt { read_at };
            let id = blobs
                .put_at(
                    name.as_deref().unwrap_or(""),
                    &mut reader,
                    progress(on_progress),
                )
                .await
                .js()?;
            Ok(JsValue::from_str(&id.to_string()))
        })
    }

    /// Gets a blob into a sink: `push(chunk)` takes each chunk and resolves
    /// when it may take the next; `onProgress(done, total)` reports
    /// progress. A blob this device does not hold whole is fetched first,
    /// into its cache. Resolves once the whole blob was pushed.
    #[wasm_bindgen(js_name = getStream)]
    pub fn get_stream(
        &self,
        blob: String,
        push: Function,
        on_progress: Option<Function>,
    ) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            let writer = Push {
                push,
                pending: None,
            };
            blobs
                .get_stream(blob, writer, &frasil::Read::new(), progress(on_progress))
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// A blob's bytes. A blob this device does not hold whole is fetched
    /// first, into its cache; `undefined` when it is not here and nothing
    /// is connected that could send it.
    pub fn get(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            match blobs.get(blob, &frasil::Read::new()).await {
                Ok(Some(data)) => Ok(bytes(&data)),
                Ok(None) => Ok(JsValue::UNDEFINED),
                Err(failure) => Err(error(failure)),
            }
        }))
    }
}

/// What JavaScript threw or rejected with, as an I/O error.
fn io_error(thrown: &JsValue) -> std::io::Error {
    std::io::Error::other(message_of(thrown))
}

/// A source over a JavaScript `readAt(offset, length)` that resolves to
/// the bytes there.
struct ReadAt {
    read_at: Function,
}

impl frasil::ObjectReader for ReadAt {
    fn read_at<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> frasil_store::BoxFuture<'a, frasil::Result<usize>> {
        Box::pin(async move {
            let failed = |thrown: &JsValue| {
                frasil::Error::Connection(format!("the blob's source: {}", message_of(thrown)))
            };
            #[allow(clippy::cast_precision_loss)]
            let (at, length) = (
                JsValue::from_f64(offset as f64),
                JsValue::from_f64(buf.len() as f64),
            );
            let value = self
                .read_at
                .call2(&JsValue::NULL, &at, &length)
                .map_err(|thrown| failed(&thrown))?;
            let value = JsFuture::from(Promise::resolve(&value))
                .await
                .map_err(|thrown| failed(&thrown))?;
            let bytes = bytes_in(&value).ok_or_else(|| {
                frasil::Error::Connection(
                    "the blob's source gave something other than a Uint8Array".into(),
                )
            })?;
            let read = bytes.len().min(buf.len());
            buf.get_mut(..read)
                .unwrap_or_default()
                .copy_from_slice(bytes.get(..read).unwrap_or_default());
            Ok(read)
        })
    }
}

/// A reader over a JavaScript `pull()` that resolves to chunks, then
/// `undefined`.
struct Pull {
    pull: Function,
    pending: Option<JsFuture>,
    chunk: Vec<u8>,
    offset: usize,
    done: bool,
}

impl AsyncRead for Pull {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            let rest = this.chunk.get(this.offset..).unwrap_or_default();
            if !rest.is_empty() {
                let n = rest.len().min(buf.remaining());
                buf.put_slice(rest.get(..n).unwrap_or_default());
                this.offset = this.offset.saturating_add(n);
                return Poll::Ready(Ok(()));
            }
            if this.done {
                return Poll::Ready(Ok(()));
            }
            let pending = match &mut this.pending {
                Some(pending) => pending,
                None => {
                    let value = this
                        .pull
                        .call0(&JsValue::NULL)
                        .map_err(|thrown| io_error(&thrown))?;
                    this.pending
                        .insert(JsFuture::from(Promise::resolve(&value)))
                }
            };
            let value = match Pin::new(pending).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value,
            };
            this.pending = None;
            let value = value.map_err(|thrown| io_error(&thrown))?;
            if value.is_undefined() || value.is_null() {
                this.done = true;
            } else {
                this.chunk = bytes_in(&value).ok_or_else(|| {
                    std::io::Error::other("the stream gave something other than a Uint8Array")
                })?;
                this.offset = 0;
            }
        }
    }
}

/// A writer over a JavaScript `push(chunk)` that resolves when it takes
/// the next.
struct Push {
    push: Function,
    /// The chunk handed over, waiting for its promise, and its length.
    pending: Option<(JsFuture, usize)>,
}

impl Push {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<usize>>> {
        let Some((pending, length)) = &mut self.pending else {
            return Poll::Ready(Ok(None));
        };
        let length = *length;
        match Pin::new(pending).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                result.map_err(|thrown| io_error(&thrown))?;
                Poll::Ready(Ok(Some(length)))
            }
        }
    }
}

impl AsyncWrite for Push {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            let value = this
                .push
                .call1(&JsValue::NULL, &bytes(buf))
                .map_err(|thrown| io_error(&thrown))?;
            this.pending = Some((JsFuture::from(Promise::resolve(&value)), buf.len()));
        }
        match this.poll_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.map(Option::unwrap_or_default)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().poll_pending(cx).map_ok(drop)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().poll_pending(cx).map_ok(drop)
    }
}
