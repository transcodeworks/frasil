//! Reading a blob that need not be whole on the device, and what the
//! device keeps of it (at-rest.md, "Retention"; adapter-blobs.md, 3.5
//! Fetching): what a read does about a blob it has to fetch
//! (`frasil::Read`), `Blobs::keep`, `Blobs::drop_local`, `Blobs::local`,
//! the cache's budget and usage, and `frasil::BlobReader`.
//!
//! A reader crosses as a class whose calls run one at a time: the
//! TypeScript layer queues them. A read in flight can be cancelled, which
//! drops its future inside the module and leaves the reader as it was,
//! with nothing asked of the space's connections any more.

use crate::callback::progress;
use crate::convert::{Obj, bytes, field, id};
use crate::device::Device;
use crate::error::{Js, cancelled, invalid};
use crate::promise;
use crate::streams::Blobs;
use frasil::{BlobId, BlobState, Read, Verified};
use js_sys::{Function, Promise};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use wasm_bindgen::prelude::*;

/// The most bytes one call of `BlobReader.read` gives: a chunk's.
const PIECE: usize = frasil_units::limits::CHUNK_BYTES;

/// A whole number of bytes, or `invalid_input` naming `what`.
pub(crate) fn whole(value: f64, what: &str) -> Result<u64, JsValue> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0)
        .then_some(value as u64)
        .ok_or_else(|| invalid(&format!("{what} must be a whole number of bytes.")))
}

/// What a read does about a blob the device does not hold whole, from
/// `{ keep, uncached, local }`, each `true` or absent; `undefined` reads
/// as `frasil::Read::new()`. `keep` and `uncached` exclude each other.
pub(crate) fn read_of(options: &JsValue) -> Result<Read, JsValue> {
    let mut read = Read::new();
    if options.is_undefined() || options.is_null() {
        return Ok(read);
    }
    if !options.is_object() {
        return Err(invalid(
            "a read's options are an object: { keep, uncached, local }.",
        ));
    }
    let on = |key: &str| field(options, key).map(|value| value.is_truthy());
    let (keep, uncached) = (on("keep")?, on("uncached")?);
    if keep && uncached {
        return Err(invalid(
            "a read keeps the blob or stores nothing of it: pass one of keep and uncached.",
        ));
    }
    if keep {
        read = read.keep();
    }
    if uncached {
        read = read.uncached();
    }
    if on("local")? {
        read = read.local();
    }
    Ok(read)
}

/// A count of bytes as a `number`.
#[allow(clippy::cast_precision_loss)]
fn count(value: u64) -> JsValue {
    JsValue::from_f64(value as f64)
}

#[wasm_bindgen]
impl Device {
    /// The budget of the blob cache and what the device's cached and kept
    /// blobs take, in stored bytes, across all its spaces: `{ budget,
    /// cached, kept }`.
    #[wasm_bindgen(js_name = blobCacheUsage)]
    pub fn blob_cache_usage(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let usage = device.blob_cache_usage().await;
            Ok(Obj::new()
                .set("budget", count(usage.budget))
                .set("cached", count(usage.cached))
                .set("kept", count(usage.kept))
                .build())
        })
    }

    /// Sets the budget of the blob cache, in stored bytes: what the
    /// device was opened with, lowered to what the browser's storage can
    /// take. The cache comes within it when the device next looks at it.
    #[wasm_bindgen(js_name = setBlobCache)]
    pub fn set_blob_cache(&self, bytes: f64) -> Result<(), JsValue> {
        let bytes = whole(bytes, "blobCache")?;
        self.inner.engine().set_blob_cache(bytes);
        Ok(())
    }
}

#[wasm_bindgen]
impl Blobs {
    /// Fetches a blob into this device's store and keeps it there until
    /// `dropLocal`, without reading it; `onProgress(done, total)` follows
    /// the fetch. A blob that cannot be fetched now stays marked, and the
    /// device fetches it by itself once it can.
    pub fn keep(&self, blob: String, on_progress: Option<Function>) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            blobs.keep(blob, progress(on_progress)).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Drops what this device stores of a blob, kept or cached: it is
    /// absent here, and a read fetches it again.
    #[wasm_bindgen(js_name = dropLocal)]
    pub fn drop_local(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            blobs.drop_local(blob).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Where a blob stands on this device: `{ state, bytes, size }`, with
    /// `state` one of `"kept"`, `"cached"` and `"absent"`, `bytes` what
    /// the device stores of it, and `size` the blob's size.
    pub fn local(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            let local = blobs.local(blob).await.js()?;
            let state = match local.state {
                BlobState::Kept => "kept",
                BlobState::Cached => "cached",
                _ => "absent",
            };
            Ok(Obj::new()
                .set("state", state)
                .set("bytes", count(local.bytes))
                .set("size", count(local.size))
                .build())
        }))
    }

    /// Opens a reader over a blob, which reads any range of it and fetches
    /// only the chunks it needs, as `options` says (`{ keep, uncached,
    /// local }`). Nothing is fetched until the reader is read or asked its
    /// size. Resolves to a `BlobReader`.
    #[wasm_bindgen(js_name = openReader)]
    pub fn open_reader(&self, blob: String, options: JsValue) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let read = read_of(&options)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            let reader = blobs.open_reader(blob, &read).await.js()?;
            Ok(BlobReader {
                shared: Rc::new(Shared {
                    reader: RefCell::new(Some(reader)),
                    stop: Stop::default(),
                    closed: Cell::new(false),
                    whole: Cell::new(false),
                    size: Cell::new(None),
                    window: Cell::new(0),
                }),
            }
            .into())
        }))
    }
}

/// What tells the call in flight to stop.
#[derive(Default)]
struct Stop {
    asked: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}

impl Stop {
    fn ask(&self) {
        self.asked.set(true);
        let waker = self.waker.try_borrow_mut().ok().and_then(|mut w| w.take());
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A future that ends with `None` once it is asked to stop: what it
/// wraps is dropped where it stands.
struct Stoppable<'a, F> {
    inner: Pin<Box<F>>,
    stop: &'a Stop,
}

impl<F: Future> Future for Stoppable<'_, F> {
    type Output = Option<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.stop.asked.get() {
            return Poll::Ready(None);
        }
        if let Ok(mut waker) = self.stop.waker.try_borrow_mut() {
            *waker = Some(cx.waker().clone());
        }
        self.inner.as_mut().poll(cx).map(Some)
    }
}

/// What a reader's calls share.
struct Shared {
    /// The reader, lent to the one call in flight; `None` meanwhile, and
    /// once closed.
    reader: RefCell<Option<frasil::BlobReader>>,
    stop: Stop,
    closed: Cell<bool>,
    /// Whether every step had passed on what the reader gave when it was
    /// last looked at: what `verified` says while a call holds the reader,
    /// and once it is closed.
    whole: Cell<bool>,
    /// The size and the bytes held in memory, as last looked at: what
    /// `size` and `windowBytes` say while a call holds the reader.
    size: Cell<Option<u64>>,
    window: Cell<usize>,
}

impl Shared {
    /// Notes what the reader says of itself.
    fn look(&self, reader: &frasil::BlobReader) {
        self.whole.set(reader.verified() == Verified::Whole);
        self.size.set(reader.size());
        self.window.set(reader.window_bytes());
    }

    /// The reader, for the one call that runs.
    fn take(&self, what: &str) -> Result<frasil::BlobReader, JsValue> {
        if self.closed.get() {
            return Err(invalid("The reader is closed."));
        }
        let reader = self
            .reader
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid(&format!("BlobReader.{what}: another call is running.")))?;
        // What asked an earlier call to stop does not stop this one.
        self.stop.asked.set(false);
        Ok(reader)
    }

    /// Gives the reader back, or ends it when it was closed meanwhile.
    async fn back(&self, reader: frasil::BlobReader) {
        self.look(&reader);
        if self.closed.get() {
            self.window.set(0);
            let _ = reader.close().await;
        } else if let Ok(mut held) = self.reader.try_borrow_mut() {
            *held = Some(reader);
        }
    }
}

/// Lets go of everything a reader asked of the space's connections, for a
/// call that was given up, in whatever state the reader is: before the
/// blob's header is known as after it.
fn let_go(reader: &mut frasil::BlobReader) {
    reader.cancel();
}

/// A reader over one blob, as `Blobs.openReader` gives it. Freed, it ends
/// its fetches and frees what it holds; `close` does the same and waits
/// until the device has looked at its cache.
#[wasm_bindgen]
pub struct BlobReader {
    shared: Rc<Shared>,
}

#[wasm_bindgen]
impl BlobReader {
    /// The blob's size, once a chunk has opened under its header in this
    /// reader: `undefined` before its first read or `fetchSize`.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> JsValue {
        self.look();
        self.shared.size.get().map_or(JsValue::UNDEFINED, count)
    }

    /// Which steps of units.md, 3.3 Reading an object have passed on what
    /// the reader gave: `"chunks"`, or `"whole"` once the bytes are known
    /// to be the blob's. As it stood before the call in flight, while one
    /// runs.
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> String {
        self.look();
        if self.shared.whole.get() {
            "whole".into()
        } else {
            "chunks".into()
        }
    }

    /// How many sealed bytes the reader holds in memory, of chunks it
    /// fetched to store nothing: as it stood before the call in flight,
    /// while one runs, and none once closed.
    #[wasm_bindgen(getter, js_name = windowBytes)]
    pub fn window_bytes(&self) -> f64 {
        self.look();
        #[allow(clippy::cast_precision_loss)]
        let held = self.shared.window.get() as f64;
        held
    }

    /// How many chunks the reader fetches ahead of where it reads.
    #[wasm_bindgen(getter, js_name = readAhead)]
    pub fn read_ahead(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        self.with(|reader| reader.read_ahead() as f64)
            .unwrap_or(0.0)
    }

    /// Sets how many chunks the reader fetches ahead of where it reads,
    /// at most 64. Nothing changes while a call is running.
    #[wasm_bindgen(js_name = setReadAhead)]
    pub fn set_read_ahead(&self, chunks: f64) -> Result<(), JsValue> {
        let chunks = whole(chunks, "readAhead")?;
        if let Ok(mut held) = self.shared.reader.try_borrow_mut()
            && let Some(reader) = held.as_mut()
        {
            reader.set_read_ahead(chunks);
        }
        Ok(())
    }

    /// The blob's size, once a chunk has opened under its header: fetched
    /// with the header when the device does not hold them. One call at a
    /// time.
    #[wasm_bindgen(js_name = fetchSize)]
    pub fn fetch_size(&self) -> Result<Promise, JsValue> {
        let mut reader = self.shared.take("fetchSize")?;
        let shared = self.shared.clone();
        Ok(promise(async move {
            let size = Stoppable {
                inner: Box::pin(reader.fetch_size()),
                stop: &shared.stop,
            }
            .await;
            if size.is_none() {
                let_go(&mut reader);
            }
            shared.back(reader).await;
            match size {
                Some(size) => Ok(count(size.js()?)),
                None => Err(cancelled()),
            }
        }))
    }

    /// `length` bytes of the blob from byte `offset`, at most a chunk's
    /// 1,048,536, fewer at the blob's end and none past it. The chunks
    /// that hold them are fetched first when the device does not hold
    /// them, ahead of everything else, with the chunks after them behind.
    /// One call at a time. Rejects with `cancelled` when `cancel` was
    /// called meanwhile; the reader lives on.
    pub fn read(&self, offset: f64, length: f64) -> Result<Promise, JsValue> {
        let offset = whole(offset, "offset")?;
        let length = usize::try_from(whole(length, "length")?)
            .unwrap_or(PIECE)
            .min(PIECE);
        let mut reader = self.shared.take("read")?;
        let shared = self.shared.clone();
        Ok(promise(async move {
            let mut out = vec![0; length];
            let read = Stoppable {
                inner: Box::pin(fill(&mut reader, offset, &mut out)),
                stop: &shared.stop,
            }
            .await;
            if read.is_none() {
                let_go(&mut reader);
            }
            shared.back(reader).await;
            match read {
                Some(read) => {
                    let read = read.js()?;
                    Ok(bytes(out.get(..read).unwrap_or_default()))
                }
                None => Err(cancelled()),
            }
        }))
    }

    /// Stops the call in flight, if one is: it rejects with `cancelled`,
    /// what it asked of the space's connections is let go, and the reader
    /// can be read again.
    pub fn cancel(&self) {
        if self.shared.reader.try_borrow().is_ok_and(|r| r.is_none()) && !self.shared.closed.get() {
            self.shared.stop.ask();
        }
    }

    /// Ends the reader: the call in flight stops, its fetches stop, what
    /// it held in memory is freed, and the device looks at its cache.
    /// Resolves once that is done, or at once while a call is still
    /// stopping. Closing twice does nothing.
    pub fn close(&self) -> Promise {
        let shared = self.shared.clone();
        promise(async move {
            if shared.closed.replace(true) {
                return Ok(JsValue::UNDEFINED);
            }
            let reader = shared
                .reader
                .try_borrow_mut()
                .ok()
                .and_then(|mut held| held.take());
            match reader {
                Some(reader) => {
                    shared.look(&reader);
                    shared.window.set(0);
                    reader.close().await.js()?;
                }
                // Lent to a call, which ends the reader once it stops.
                None => shared.stop.ask(),
            }
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl BlobReader {
    /// Looks at the reader, unless a call holds it or it is closed.
    fn with<T>(&self, look: impl FnOnce(&frasil::BlobReader) -> T) -> Option<T> {
        self.shared
            .reader
            .try_borrow()
            .ok()
            .and_then(|held| held.as_ref().map(look))
    }

    /// Notes what the reader says of itself, unless a call holds it.
    fn look(&self) {
        self.with(|reader| self.shared.look(reader));
    }
}

/// A freed reader ends: the call in flight stops, and the reader it holds
/// goes with it.
impl Drop for BlobReader {
    fn drop(&mut self) {
        if !self.shared.closed.replace(true) {
            self.shared.stop.ask();
            if let Ok(mut held) = self.shared.reader.try_borrow_mut() {
                held.take();
            }
        }
    }
}

/// Reads into `out` from `offset` until it is full or the blob ends: how
/// many bytes.
async fn fill(
    reader: &mut frasil::BlobReader,
    offset: u64,
    out: &mut [u8],
) -> frasil::Result<usize> {
    let mut filled = 0usize;
    while let Some(rest) = out.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        let at = offset.saturating_add(filled as u64);
        let read = reader.read_at(at, rest).await?;
        if read == 0 {
            break;
        }
        filled = filled.saturating_add(read);
    }
    Ok(filled)
}
