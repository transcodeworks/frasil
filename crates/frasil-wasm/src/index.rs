//! The index (`frasil::index`) for JavaScript: a typed SQLite cache over
//! the device's spaces, in the origin-private file system, with queries,
//! live queries and the tables it changes. Only the `index` build of the
//! module has it, and it runs in a dedicated worker, where OPFS gives
//! synchronous access handles.

use crate::convert::{Obj, array, bytes, bytes_in, items};
use crate::device::Device;
use crate::error::{index_error, invalid};
use crate::promise;
use frasil::SpaceId;
use frasil::index::{Row, Schema, SqlValue};
use js_sys::{Function, Promise};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A SQL value for JavaScript: `null`, a number (a `bigint` beyond 2^53),
/// a string or a `Uint8Array`.
fn value_out(value: &SqlValue) -> JsValue {
    match value {
        SqlValue::Null => JsValue::NULL,
        SqlValue::Integer(n) if n.unsigned_abs() <= (1 << 53) => JsValue::from_f64(*n as f64),
        SqlValue::Integer(n) => js_sys::BigInt::from(*n).into(),
        SqlValue::Real(x) => JsValue::from_f64(*x),
        SqlValue::Text(text) => JsValue::from_str(text),
        SqlValue::Blob(blob) => bytes(blob),
    }
}

/// A query's parameter from JavaScript: `null` or `undefined`, a boolean,
/// a number, a `bigint`, a string or a `Uint8Array`.
fn value_in(value: &JsValue) -> Result<SqlValue, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(SqlValue::Null);
    }
    if let Some(flag) = value.as_bool() {
        return Ok(flag.into());
    }
    if let Some(x) = value.as_f64() {
        return Ok(if x.fract() == 0.0 && x.abs() <= 9_007_199_254_740_992.0 {
            SqlValue::Integer(x as i64)
        } else {
            SqlValue::Real(x)
        });
    }
    if value.is_bigint() {
        let n = i64::try_from(js_sys::BigInt::from(value.clone()))
            .map_err(|_| invalid("A parameter is beyond a 64-bit integer."))?;
        return Ok(SqlValue::Integer(n));
    }
    if let Some(text) = value.as_string() {
        return Ok(SqlValue::Text(text));
    }
    bytes_in(value)
        .map(SqlValue::Blob)
        .ok_or_else(|| invalid("A parameter is not null, a boolean, a number, a string or bytes."))
}

fn params_in(params: &JsValue) -> Result<Vec<SqlValue>, JsValue> {
    if params.is_undefined() || params.is_null() {
        return Ok(Vec::new());
    }
    items(params, "the parameters")?
        .iter()
        .map(value_in)
        .collect()
}

/// Rows as plain objects, one property per column.
fn rows_out(rows: Vec<Row>) -> JsValue {
    array(rows, |row| {
        row.columns()
            .iter()
            .zip(row.values())
            .fold(Obj::new(), |out, (column, value)| {
                out.define(column, &value_out(value))
            })
            .build()
    })
}

/// An index of a device's spaces.
#[wasm_bindgen]
pub struct Index {
    inner: frasil::index::Index,
}

#[wasm_bindgen]
impl Index {
    /// Opens the index of `device` under `name`, with the tables the JSON
    /// `manifest` describes, in the origin-private file system, and brings
    /// it up to date. Only in a dedicated worker.
    pub fn open(device: &Device, name: String, manifest: String) -> Promise {
        let device = device.inner.clone();
        promise(async move {
            let schema = Schema::from_manifest(&manifest).map_err(index_error)?;
            let inner = frasil::index::Index::open_in_browser(&device, &name, schema)
                .await
                .map_err(index_error)?;
            Ok(Self { inner }.into())
        })
    }

    /// The schema's manifest, as JSON.
    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> String {
        self.inner.schema().manifest()
    }

    /// A count that grows each time the index changes a table.
    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> f64 {
        self.inner.revision() as f64
    }

    /// Runs a read-only query with its parameters: rows as objects.
    pub fn query(&self, sql: String, params: JsValue) -> Result<JsValue, JsValue> {
        let params = params_in(&params)?;
        self.inner
            .query(&sql, &params)
            .map(rows_out)
            .map_err(index_error)
    }

    /// A live query: its `next()` resolves to its rows at once, then each
    /// time they differ after the index changed a table it reads
    /// (`Watch::distinct`).
    pub fn watch(&self, sql: String, params: JsValue) -> Result<IndexWatch, JsValue> {
        let params = params_in(&params)?;
        let watch = self
            .inner
            .watch(sql, params)
            .map_err(index_error)?
            .distinct();
        Ok(IndexWatch {
            inner: Rc::new(RefCell::new(Some(watch))),
        })
    }

    /// The tables the index changes from now on: a feed whose `next()`
    /// resolves to their names.
    #[wasm_bindgen(js_name = tableChanges)]
    pub fn table_changes(&self) -> TableChanges {
        TableChanges {
            inner: Rc::new(RefCell::new(Some(self.inner.table_changes()))),
        }
    }

    /// Brings the whole cache up to date.
    pub fn sync(&self) -> Promise {
        let index = self.inner.clone();
        promise(async move {
            index.sync().await.map_err(index_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Brings one space up to date.
    pub fn refresh(&self, space: String) -> Result<Promise, JsValue> {
        let space: SpaceId = space
            .parse()
            .map_err(|_| invalid("A space's ID is 64 hex digits."))?;
        let index = self.inner.clone();
        Ok(promise(async move {
            index.refresh(space).await.map_err(index_error)?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Drops the cache and reads every space again.
    pub fn rebuild(&self) -> Promise {
        let index = self.inner.clone();
        promise(async move {
            index.rebuild().await.map_err(index_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Follows the device, refreshing what each change touches, and
    /// resolves once the device is gone. `onError(error)` hears of each
    /// refresh that failed before it is retried.
    pub fn follow(&self, on_error: Option<Function>) -> Promise {
        let index = self.inner.clone();
        promise(async move {
            index
                .follow_with(|failure| {
                    if let Some(on_error) = &on_error {
                        let _ = on_error
                            .call1(&JsValue::NULL, &JsValue::from_str(&failure.to_string()));
                    }
                })
                .await
                .map_err(index_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// A live query, from `Index.watch`.
#[wasm_bindgen]
pub struct IndexWatch {
    inner: Rc<RefCell<Option<frasil::index::Watch>>>,
}

#[wasm_bindgen]
impl IndexWatch {
    /// The query's rows: at once the first time, then each time they
    /// differ. One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut watch = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("IndexWatch.next is already waiting."))?;
        Ok(promise(async move {
            let rows = watch.next().await;
            if let Ok(mut back) = slot.try_borrow_mut() {
                *back = Some(watch);
            }
            match rows {
                Ok(rows) => Ok(rows_out(rows)),
                Err(frasil::index::Error::Closed) => Ok(JsValue::UNDEFINED),
                Err(failure) => Err(index_error(failure)),
            }
        }))
    }
}

/// The tables an index changes, from `Index.tableChanges`.
#[wasm_bindgen]
pub struct TableChanges {
    inner: Rc<RefCell<Option<frasil::index::TableChanges>>>,
}

#[wasm_bindgen]
impl TableChanges {
    /// The names of the tables the index changed next; `undefined` once
    /// it is gone. One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut changes = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("TableChanges.next is already waiting."))?;
        Ok(promise(async move {
            let changed = changes.next().await;
            if let Ok(mut back) = slot.try_borrow_mut() {
                *back = Some(changes);
            }
            Ok(changed.map_or(JsValue::UNDEFINED, |tables| {
                array(tables, |name| JsValue::from_str(&name))
            }))
        }))
    }
}
