//! Reads for applications that cache: change feeds of a space, a Records
//! stream and a blob stream, waits for what has not arrived, a blob's
//! status and ranges, ranges of rows, and receipts for single writes.
//!
//! The TypeScript layer builds its observed stores over these feeds.

use crate::convert::{Obj, array, bytes, id, key_in};
use crate::error::{Js, error, invalid};
use crate::promise;
use crate::space::Space;
use crate::streams::{Blobs, Document, Records, row_out};
use frasil::{BlobChange, BlobId, BlobStatus, Origin, RecordChange, StreamId};
use js_sys::Promise;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::prelude::*;

/// Where a change was made, as the TypeScript layer names it.
pub(crate) fn origin(origin: Origin) -> JsValue {
    JsValue::from_str(match origin {
        Origin::Local => "local",
        Origin::Remote => "remote",
    })
}

/// A wait of `ms` milliseconds; negative or not finite waits not at all.
pub(crate) fn wait(ms: f64) -> Duration {
    if ms.is_finite() && ms > 0.0 {
        Duration::from_secs_f64(ms / 1000.0)
    } else {
        Duration::ZERO
    }
}

/// Lends a feed to the one `next()` in flight, and takes it back when it
/// settles. It resolves to `undefined` once the device is gone, and
/// rejects once the device no longer holds the space.
fn next_of<F: 'static, T>(
    slot: &Rc<RefCell<Option<F>>>,
    what: &str,
    next: impl AsyncFnOnce(&mut F) -> frasil::Result<Option<T>> + 'static,
    out: impl FnOnce(T) -> JsValue + 'static,
) -> Result<Promise, JsValue> {
    let slot = slot.clone();
    let mut feed = slot
        .try_borrow_mut()
        .ok()
        .and_then(|mut held| held.take())
        .ok_or_else(|| invalid(&format!("{what}.next is already waiting.")))?;
    Ok(promise(async move {
        let item = next(&mut feed).await;
        if let Ok(mut back) = slot.try_borrow_mut() {
            *back = Some(feed);
        }
        Ok(item.js()?.map_or(JsValue::UNDEFINED, out))
    }))
}

// ---- Feeds ------------------------------------------------------------------------------------

/// A space's changes, as `Space.changes()` gives them.
#[wasm_bindgen]
pub struct SpaceChanges {
    inner: Rc<RefCell<Option<frasil::SpaceChanges>>>,
}

#[wasm_bindgen]
impl SpaceChanges {
    /// The next change, as `{ streams, members, spaceEvents, origin }`: the
    /// IDs of the streams it changed, whether the members may have changed,
    /// whether it holds events that are no stream's content (keys, which can
    /// make earlier units readable), and `"local"` or `"remote"`; `undefined` once the device is gone. One
    /// call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        next_of(
            &self.inner,
            "SpaceChanges",
            async |feed: &mut frasil::SpaceChanges| feed.next().await,
            |change| {
                Obj::new()
                    .set(
                        "streams",
                        array(change.streams, |id| JsValue::from_str(&id.to_string())),
                    )
                    .set("members", change.members)
                    .set("spaceEvents", change.space_events)
                    .set("origin", origin(change.origin))
                    .build()
            },
        )
    }
}

/// A Records stream's changes, as `Records.changes()` gives them.
#[wasm_bindgen]
pub struct RecordChanges {
    inner: Rc<RefCell<Option<frasil::RecordChanges>>>,
}

#[wasm_bindgen]
impl RecordChanges {
    /// The next change: `{ kind: "rows", table, keys, origin }`, the keys
    /// as bytes, or `{ kind: "all" }` when any row may have changed;
    /// `undefined` once the device is gone. One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        next_of(
            &self.inner,
            "RecordChanges",
            async |feed: &mut frasil::RecordChanges| feed.next().await,
            |change| match change {
                RecordChange::Rows {
                    table,
                    keys,
                    origin: made,
                } => Obj::new()
                    .set("kind", "rows")
                    .set("table", table)
                    .set("keys", array(keys, |key| bytes(&key)))
                    .set("origin", origin(made))
                    .build(),
                _ => Obj::new().set("kind", "all").build(),
            },
        )
    }
}

/// A blob stream's changes, as `Blobs.changes()` gives them.
#[wasm_bindgen]
pub struct BlobChanges {
    inner: Rc<RefCell<Option<frasil::BlobChanges>>>,
}

#[wasm_bindgen]
impl BlobChanges {
    /// The next change, as `{ kind, id }` with `kind` one of `"added"`,
    /// `"removed"` (each with an `origin`), `"arrived"`, `"evicted"` and
    /// `"withdrawn"`;
    /// `undefined` once the device is gone. One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        next_of(
            &self.inner,
            "BlobChanges",
            async |feed: &mut frasil::BlobChanges| feed.next().await,
            |change| {
                let (kind, id, made) = match change {
                    BlobChange::Added { id, origin } => ("added", id, Some(origin)),
                    BlobChange::Removed { id, origin } => ("removed", id, Some(origin)),
                    BlobChange::Arrived { id } => ("arrived", id, None),
                    BlobChange::Evicted { id } => ("evicted", id, None),
                    BlobChange::Withdrawn { id } => ("withdrawn", id, None),
                    _ => ("changed", BlobId::from_bytes([0; 16]), None),
                };
                let mut out = Obj::new().set("kind", kind).set("id", id.to_string());
                if let Some(made) = made {
                    out = out.set("origin", origin(made));
                }
                out.build()
            },
        )
    }
}

// ---- Receipts ---------------------------------------------------------------------------------

/// A receipt for one write: the change it made, and whether a peer keeps
/// it yet.
#[wasm_bindgen]
pub struct Receipt {
    inner: frasil::Receipt,
}

impl From<frasil::Receipt> for Receipt {
    fn from(inner: frasil::Receipt) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Receipt {
    /// The change the write made: 64 hex digits.
    #[wasm_bindgen(getter)]
    pub fn unit(&self) -> String {
        self.inner.unit().to_string()
    }

    /// Whether a peer acknowledged the change.
    #[wasm_bindgen(js_name = isDurable)]
    pub fn is_durable(&self) -> Promise {
        let receipt = self.inner.clone();
        promise(async move { Ok(receipt.is_durable().await.into()) })
    }

    /// Waits until the change is durable, for at most `within_ms`;
    /// rejects with `connection` when no peer acknowledged it in time.
    pub fn durable(&self, within_ms: f64) -> Promise {
        let receipt = self.inner.clone();
        promise(async move {
            receipt.durable(wait(within_ms)).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

// ---- Spaces -----------------------------------------------------------------------------------

#[wasm_bindgen]
impl Space {
    /// The space's changes from now on, this device's own included.
    pub fn changes(&self) -> SpaceChanges {
        SpaceChanges {
            inner: Rc::new(RefCell::new(Some(self.inner.changes()))),
        }
    }

    /// A Loro document of the space, once this device holds it, within
    /// `within_ms`; rejects with `timeout` when it has not arrived.
    #[wasm_bindgen(js_name = documentWhenAvailable)]
    pub fn document_when_available(
        &self,
        stream: String,
        within_ms: f64,
    ) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            let document = space
                .document_when_available(stream, wait(within_ms))
                .await
                .js()?;
            Ok(Document::from(document).into())
        }))
    }

    /// Records tables of the space, once this device holds them, within
    /// `within_ms`; rejects with `timeout` when they have not arrived.
    #[wasm_bindgen(js_name = recordsWhenAvailable)]
    pub fn records_when_available(
        &self,
        stream: String,
        within_ms: f64,
    ) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            let records = space
                .records_when_available(stream, wait(within_ms))
                .await
                .js()?;
            Ok(Records::from(records).into())
        }))
    }

    /// A blob stream of the space, once this device holds it, within
    /// `within_ms`; rejects with `timeout` when it has not arrived.
    #[wasm_bindgen(js_name = blobsWhenAvailable)]
    pub fn blobs_when_available(&self, stream: String, within_ms: f64) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            let blobs = space
                .blobs_when_available(stream, wait(within_ms))
                .await
                .js()?;
            Ok(Blobs::from(blobs).into())
        }))
    }
}

// ---- Records ----------------------------------------------------------------------------------

#[wasm_bindgen]
impl Records {
    /// The rows that change from now on, this device's writes included.
    pub fn changes(&self) -> RecordChanges {
        RecordChanges {
            inner: Rc::new(RefCell::new(Some(self.inner.changes()))),
        }
    }

    /// Writes the cells `ops` lists, as one change, and resolves to a
    /// `Receipt` for it.
    #[wasm_bindgen(js_name = writeWithReceipt)]
    pub fn write_with_receipt(&self, ops: JsValue) -> Result<Promise, JsValue> {
        self.write_cells(&ops, false, true)
    }

    /// At most `limit` visible rows of a table in key order, from the
    /// first key after `after` (from the first for `undefined`): `[key,
    /// row]` pairs.
    #[wasm_bindgen(js_name = rowsRange)]
    pub fn rows_range(
        &self,
        table: String,
        after: JsValue,
        limit: u32,
    ) -> Result<Promise, JsValue> {
        let after = if after.is_undefined() || after.is_null() {
            None
        } else {
            Some(key_in(&after, "a row's key")?)
        };
        let records = self.inner.clone();
        Ok(promise(async move {
            let rows = records
                .rows_range(&table, after.as_deref(), limit as usize)
                .await
                .js()?;
            Ok(array(rows, |(key, row)| {
                js_sys::Array::of2(&bytes(&key), &row_out(&row)).into()
            }))
        }))
    }

    /// The visible rows of a table whose keys start with `prefix`, in key
    /// order: `[key, row]` pairs.
    #[wasm_bindgen(js_name = rowsWithPrefix)]
    pub fn rows_with_prefix(&self, table: String, prefix: JsValue) -> Result<Promise, JsValue> {
        let prefix = key_in(&prefix, "a key prefix")?;
        let records = self.inner.clone();
        Ok(promise(async move {
            let rows = records.rows_with_prefix(&table, &prefix).await.js()?;
            Ok(array(rows, |(key, row)| {
                js_sys::Array::of2(&bytes(&key), &row_out(&row)).into()
            }))
        }))
    }
}

// ---- Blobs ------------------------------------------------------------------------------------

/// A blob's status, as the TypeScript layer names it.
fn status_out(status: BlobStatus) -> JsValue {
    match status {
        BlobStatus::Readable => Obj::new().set("kind", "readable").build(),
        BlobStatus::Fetching { done, total } => Obj::new()
            .set("kind", "fetching")
            .set("done", JsValue::from_f64(done as f64))
            .set("total", JsValue::from_f64(total as f64))
            .build(),
        BlobStatus::Withdrawn => Obj::new().set("kind", "withdrawn").build(),
        BlobStatus::Absent => Obj::new().set("kind", "absent").build(),
        BlobStatus::KeysPending => Obj::new().set("kind", "keysPending").build(),
        _ => Obj::new().set("kind", "missing").build(),
    }
}

#[wasm_bindgen]
impl Blobs {
    /// The blobs that change from now on. Resolves to a feed.
    pub fn changes(&self) -> Promise {
        let blobs = self.inner.clone();
        promise(async move {
            Ok(BlobChanges {
                inner: Rc::new(RefCell::new(Some(blobs.changes().await.js()?))),
            }
            .into())
        })
    }

    /// The SHA-256 of a blob's plaintext, 32 bytes, computed on this device.
    /// A blob this device does not hold whole is fetched first, into its
    /// cache; `undefined` when it cannot be read whole. `options` says
    /// what becomes of a blob the read fetches: `{ keep, uncached, local }`.
    #[wasm_bindgen(js_name = contentHash)]
    pub fn content_hash(&self, blob: String, options: JsValue) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let read = crate::retention::read_of(&options)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            Ok(match blobs.content_hash(blob, &read).await.js()? {
                Some(hash) => bytes(&hash),
                None => JsValue::UNDEFINED,
            })
        }))
    }

    /// Where a blob's bytes stand on this device: `{ kind }`, one of
    /// `"readable"`, `"fetching"` (with `done` and `total`), `"absent"`,
    /// `"missing"`, `"keysPending"` and `"withdrawn"`. `"absent"` is a
    /// blob this device does not hold while a peer or a member is
    /// connected, so that a read fetches it now; `"missing"` is one it
    /// does not hold while none is.
    pub fn status(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            Ok(status_out(blobs.status(blob).await.js()?))
        }))
    }

    /// `length` bytes of a blob from byte `offset`, fewer at its end. Of a
    /// blob this device does not hold whole, only the chunks that hold
    /// the range are fetched, into its cache; `undefined` when it is not
    /// here and nothing is connected that could send it. Each chunk opens
    /// under the blob's key before its bytes are given, and the checks
    /// that need the whole blob do not run on a range: a member that
    /// holds the blob's key can serve a range read other validly sealed
    /// chunks, and nothing refutes them later, so read with `get` what
    /// must be the blob's. `options` says what becomes of the chunks the
    /// read fetches: `{ keep, uncached, local }`.
    #[wasm_bindgen(js_name = getRange)]
    pub fn get_range(
        &self,
        blob: String,
        offset: f64,
        length: f64,
        options: JsValue,
    ) -> Result<Promise, JsValue> {
        use crate::retention::whole;
        let blob = id::<BlobId>(&blob)?;
        let (offset, length) = (whole(offset, "offset")?, whole(length, "length")?);
        let read = crate::retention::read_of(&options)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            match blobs.get_range(blob, offset, length, &read).await {
                Ok(Some(data)) => Ok(bytes(&data)),
                Ok(None) => Ok(JsValue::UNDEFINED),
                Err(failure) => Err(error(failure)),
            }
        }))
    }

    /// A blob's bytes within `within_ms`, fetched into this device's cache
    /// when it does not hold them; rejects with `timeout` when they are
    /// not here in time.
    #[wasm_bindgen(js_name = getWhenAvailable)]
    pub fn get_when_available(&self, blob: String, within_ms: f64) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            Ok(bytes(
                &blobs.get_when_available(blob, wait(within_ms)).await.js()?,
            ))
        }))
    }
}
