//! Space files in the browser (ext-space-files.md): a space exported to
//! bytes the page saves or sends, appended to, sniffed, and imported from
//! bytes by one of the roads in. A page chooses the kind at run time, so
//! `frasil::space_files::dynamic` does the work, with the same checks as
//! `frasil::SpaceFile`.
//!
//! - An export's options cross as a plain object: `history` (`"full"`, the
//!   default, or `"from-snapshot"`), `streams` (an array of stream IDs;
//!   every stream when absent), `objects` (`"all"`, `"none"`, or a number
//!   of bytes to embed up to; 32 MiB by default), `wayIn` (an array of
//!   `"keys"` or `{ level, lifetime }`; `["keys"]` by default), `seal` (a
//!   32-byte `Uint8Array`) and `sections` (`{ kind, name, bytes }`).
//! - What a sniff reads crosses as a plain object: `space`, `kind`,
//!   `heads`, `streams`, `history`, `objects`, `exporter`, `time` and
//!   `wayIn` (`"none"`, `"clear"` or `"sealed"`).
//! - An import resolves to `{ road, space }`, the road `"member"`,
//!   `"rereading"` or `"reading"`, or to `{ road: "invited", invitation }`:
//!   an `Invitation` the page shows and then accepts or declines.

use crate::convert::{Obj, array, bytes, bytes_in, exact, field, hex, id, items, text_field};
use crate::device::Device;
use crate::error::{Js, invalid};
use crate::promise;
use crate::space::{Space, level};
use frasil::StreamId;
use frasil::space_files::{
    Export, History, Invitation as Invited, Objects, Road, Section, Sniffed, WayIn, dynamic,
};
use js_sys::Promise;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// A history by its name; full when `undefined`.
fn history(value: &JsValue) -> Result<History, JsValue> {
    match value.as_string().as_deref() {
        _ if value.is_undefined() => Ok(History::Full),
        Some("full") => Ok(History::Full),
        Some("from-snapshot") => Ok(History::FromSnapshot),
        _ => Err(invalid("history is \"full\" or \"from-snapshot\".")),
    }
}

fn history_name(history: History) -> &'static str {
    match history {
        History::Full => "full",
        History::FromSnapshot => "from-snapshot",
    }
}

fn road_name(road: &Road) -> &'static str {
    match road {
        Road::Member => "member",
        Road::Rereading => "rereading",
        Road::Invited { .. } => "invited",
        Road::Reading => "reading",
    }
}

/// An invite a space file carries for this device, prepared and checked,
/// waiting for the person's consent (ext-space-files.md, "Import", step
/// 5). Show `inviter`, `level` and `label`, then `accept()` or
/// `decline()`. An `accept()` that rejects leaves the invitation to
/// decline.
#[wasm_bindgen]
pub struct Invitation {
    inner: Invited,
    space: String,
    inviter: String,
    level: &'static str,
    expires_at: f64,
    label: Option<String>,
}

#[wasm_bindgen]
impl Invitation {
    /// The space's ID.
    #[wasm_bindgen(getter)]
    pub fn space(&self) -> String {
        self.space.clone()
    }

    /// The inviting device's ID.
    #[wasm_bindgen(getter)]
    pub fn inviter(&self) -> String {
        self.inviter.clone()
    }

    /// The level the claim gives: `"read"` or `"write"`.
    #[wasm_bindgen(getter)]
    pub fn level(&self) -> String {
        self.level.to_owned()
    }

    /// When the invite expires, as seconds since the epoch.
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> f64 {
        self.expires_at
    }

    /// The way in's label, if the exporter wrote one.
    #[wasm_bindgen(getter)]
    pub fn label(&self) -> Option<String> {
        self.label.clone()
    }

    /// The person consents: resolves to the space, which this device
    /// writes in from now on. Rejects with a claim's refusal, such as
    /// `invite_used` or `expired`, and the invitation can then be declined.
    pub fn accept(&self) -> Promise {
        let invitation = self.inner.clone();
        promise(async move { Ok(Space::from(invitation.accept().await.js()?).into()) })
    }

    /// The person declines: nothing of the file is kept.
    pub fn decline(&self) -> Promise {
        let invitation = self.inner.clone();
        promise(async move {
            invitation.decline().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// Whether a number of seconds is in `link_lifetime`'s range, 15 minutes
/// to 7 days (overview.md, "Every timer").
pub(crate) fn link_lifetime(seconds: f64) -> bool {
    use frasil_space::ext_invite_links::{LINK_LIFETIME_MAX, LINK_LIFETIME_MIN};
    seconds.is_finite() && (LINK_LIFETIME_MIN as f64..=LINK_LIFETIME_MAX as f64).contains(&seconds)
}

/// One part of the way in: `"keys"`, or `{ level, lifetime }`.
fn way_in(value: &JsValue) -> Result<WayIn, JsValue> {
    if value.as_string().as_deref() == Some("keys") {
        return Ok(WayIn::Keys);
    }
    if !value.is_object() {
        return Err(invalid("a way in is \"keys\" or { level, lifetime }."));
    }
    let level = level(&text_field(value, "level", "an invite")?)?;
    let lifetime = field(value, "lifetime")?.as_f64();
    let Some(lifetime) = lifetime.filter(|n| link_lifetime(*n)) else {
        return Err(invalid(
            "an invite's lifetime is a number of seconds, 15 minutes to 7 days.",
        ));
    };
    Ok(WayIn::Invite {
        level,
        lifetime: Duration::from_secs_f64(lifetime),
    })
}

/// An export's options from a plain object, or the defaults when
/// `undefined`.
fn export_options(value: &JsValue) -> Result<Export, JsValue> {
    let mut options = Export::default();
    if value.is_undefined() || value.is_null() {
        return Ok(options);
    }
    if !value.is_object() {
        return Err(invalid("the export options are an object."));
    }
    options.history = history(&field(value, "history")?)?;
    let streams = field(value, "streams")?;
    if !streams.is_undefined() {
        options.streams = Some(
            items(&streams, "streams")?
                .iter()
                .map(|item| {
                    item.as_string()
                        .ok_or_else(|| invalid("streams is an array of stream IDs."))
                        .and_then(|text| id::<StreamId>(&text))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let objects = field(value, "objects")?;
    if !objects.is_undefined() {
        options.objects = match (objects.as_string().as_deref(), objects.as_f64()) {
            (Some("all"), _) => Objects::All,
            (Some("none"), _) => Objects::None,
            (None, Some(n)) if n.is_finite() && n >= 0.0 => Objects::UpTo(n as u64),
            _ => {
                return Err(invalid(
                    "objects is \"all\", \"none\" or a number of bytes.",
                ));
            }
        };
    }
    let ways = field(value, "wayIn")?;
    if !ways.is_undefined() {
        options.way_in = items(&ways, "wayIn")?
            .iter()
            .map(way_in)
            .collect::<Result<Vec<_>, _>>()?;
    }
    let seal = field(value, "seal")?;
    if !seal.is_undefined() {
        let key = bytes_in(&seal).ok_or_else(|| invalid("seal is a Uint8Array."))?;
        options.seal = Some(Zeroizing::new(exact::<32>(&key, "the file key")?));
    }
    let sections = field(value, "sections")?;
    if !sections.is_undefined() {
        options.sections = items(&sections, "sections")?
            .iter()
            .map(|item| {
                let data = field(item, "bytes")?;
                Ok(Section {
                    kind: text_field(item, "kind", "a section")?,
                    name: text_field(item, "name", "a section")?,
                    bytes: bytes_in(&data)
                        .ok_or_else(|| invalid("a section's bytes is a Uint8Array."))?,
                })
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
    }
    Ok(options)
}

/// What a sniff reads, as a plain object.
fn sniffed_out(sniffed: &Sniffed) -> JsValue {
    let manifest = &sniffed.manifest;
    let mut out = Obj::new()
        .set("space", hex(&manifest.space.0))
        .set("kind", manifest.kind.clone())
        .set("heads", JsValue::from_f64(manifest.heads.len() as f64))
        .set("history", history_name(manifest.history))
        .set("objects", JsValue::from_f64(manifest.objects.len() as f64))
        .set("exporter", hex(&manifest.exporter.0))
        .set(
            "wayIn",
            match sniffed.way_in {
                None => "none",
                Some(false) => "clear",
                Some(true) => "sealed",
            },
        );
    if let Some(streams) = &manifest.streams {
        out = out.set(
            "streams",
            array(streams.iter(), |stream| hex(stream).into()),
        );
    }
    if let Some(time) = manifest.time {
        out = out.set("time", JsValue::from_f64(time as f64));
    }
    out.build()
}

/// The kinds an import accepts: a string, or an array of strings.
fn kinds(value: &JsValue) -> Result<Vec<String>, JsValue> {
    if let Some(kind) = value.as_string() {
        return Ok(vec![kind]);
    }
    items(value, "kind")?
        .iter()
        .map(|item| {
            item.as_string()
                .ok_or_else(|| invalid("kind is a string or an array of strings."))
        })
        .collect()
}

#[wasm_bindgen]
impl Space {
    /// Exports the space to a file under `kind` (ext-space-files.md,
    /// "Export"): resolves to the file's bytes. `options` is as the
    /// module describes, or `undefined` for the defaults: full history,
    /// every stream, objects up to 32 MiB, and the keys as the way in.
    #[wasm_bindgen(js_name = exportSpaceFile)]
    pub fn export_space_file(&self, kind: String, options: JsValue) -> Result<Promise, JsValue> {
        let options = export_options(&options)?;
        let space = self.inner().clone();
        Ok(promise(async move {
            let file = dynamic::export(&space, &kind, options).await.js()?;
            Ok(bytes(&file))
        }))
    }

    /// Appends what the device holds of the space since the file's last
    /// manifest (ext-space-files.md, "Append"): resolves to the file's
    /// bytes, grown. The file must have been exported from this space.
    #[wasm_bindgen(js_name = appendSpaceFile)]
    pub fn append_space_file(&self, file: Vec<u8>) -> Promise {
        let space = self.inner().clone();
        promise(async move {
            let grown = dynamic::append(&space, &file).await.js()?;
            Ok(bytes(&grown))
        })
    }
}

#[wasm_bindgen]
impl Device {
    /// Sniffs a file's bytes, which need not be whole (ext-space-files.md,
    /// "Sniff"): what the module describes, with no event read and
    /// nothing opened.
    #[wasm_bindgen(js_name = sniffSpaceFile)]
    pub fn sniff_space_file(file: Vec<u8>) -> Result<JsValue, JsValue> {
        Ok(sniffed_out(&dynamic::sniff(&file).js()?))
    }

    /// Imports a file whose kind is `kind`, a string or an array of
    /// strings (ext-space-files.md, "Import"): resolves to `{ road, space }`,
    /// or to `{ road: "invited", invitation }` for a file whose invite
    /// admits this device on consent. `key`, 32 bytes, opens a sealed way
    /// in.
    #[wasm_bindgen(js_name = importSpaceFile)]
    pub fn import_space_file(
        &self,
        file: Vec<u8>,
        kind: JsValue,
        key: Option<Vec<u8>>,
    ) -> Result<Promise, JsValue> {
        let kinds = kinds(&kind)?;
        let key = key
            .map(|key| exact::<32>(&key, "the file key").map(Zeroizing::new))
            .transpose()?;
        let device = self.inner().clone();
        Ok(promise(async move {
            let names: Vec<&str> = kinds.iter().map(String::as_str).collect();
            match dynamic::import(&device, &names, &file, key.as_deref())
                .await
                .js()?
            {
                dynamic::Import::Opened { road, space } => Ok(Obj::new()
                    .set("road", road_name(&road))
                    .set("space", JsValue::from(Space::from(space)))
                    .build()),
                dynamic::Import::Invited(invitation) => {
                    let handle = Invitation {
                        space: invitation.space().to_string(),
                        inviter: invitation.inviter().to_string(),
                        level: invitation.level().name(),
                        expires_at: invitation.expires_at() as f64,
                        label: invitation.label().map(str::to_owned),
                        inner: invitation,
                    };
                    Ok(Obj::new()
                        .set("road", "invited")
                        .set("invitation", JsValue::from(handle))
                        .build())
                }
            }
        }))
    }
}
