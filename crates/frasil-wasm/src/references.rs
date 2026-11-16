//! File references (adapter-blobs.md, "References"; ext-libraries.md,
//! "Holds"), on JavaScript's `Blobs`: a reference to a blob another space
//! of the library stores, a blob's details, and removing one. IDs cross as
//! the hex `frasil` shows; details cross as a plain object.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use crate::convert::{Obj, id};
use crate::error::Js;
use crate::promise;
use crate::streams::Blobs;
use frasil::{BlobId, BlobInfo};
use js_sys::Promise;
use wasm_bindgen::prelude::*;

/// A blob's details as `{ id, name, mediaType, size, source }`: `source`,
/// the space that stores a reference's file, only for a reference.
fn info_out(info: &BlobInfo) -> JsValue {
    let text = |value: &Option<String>| value.clone().map_or(JsValue::UNDEFINED, JsValue::from);
    Obj::new()
        .set("id", info.id.to_string())
        .set("name", text(&info.name))
        .set("mediaType", text(&info.media_type))
        .set("size", JsValue::from_f64(info.size as f64))
        .set(
            "source",
            info.source
                .map_or(JsValue::UNDEFINED, |space| JsValue::from(space.to_string())),
        )
        .build()
}

#[wasm_bindgen]
impl Blobs {
    /// Puts a reference to a blob of `source`, a blob stream of another
    /// space of the same library: the file is not stored again. Resolves
    /// to the new blob's ID; rejects with `other_library` when the spaces
    /// are billed to different libraries.
    #[wasm_bindgen(js_name = referenceFrom)]
    pub fn reference_from(&self, source: &Blobs, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let (blobs, source) = (self.inner.clone(), source.inner.clone());
        Ok(promise(async move {
            let id = blobs.reference_from(&source, blob).await.js()?;
            Ok(JsValue::from_str(&id.to_string()))
        }))
    }

    /// A blob's details: its name, media type and size, and for a
    /// reference the space that stores it.
    pub fn info(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            let info = blobs.info(blob).await.js()?;
            Ok(info_out(&info))
        }))
    }

    /// Removes a blob from the stream; a reference's hold ends once the
    /// peers collect what listed it.
    pub fn remove(&self, blob: String) -> Result<Promise, JsValue> {
        let blob = id::<BlobId>(&blob)?;
        let blobs = self.inner.clone();
        Ok(promise(async move {
            blobs.remove(blob).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }
}
