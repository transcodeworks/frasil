//! Signed application requests (ext-app-requests.md), verified by an
//! application's server: in a Cloudflare Worker, through the package's
//! entry `@frasil/client/module`.
//!
//! `frasil::RequestVerifier` reaches its state through synchronous traits,
//! and a Worker's storage answers asynchronously. So the TypeScript layer
//! loads the subject's recorded person and the person's list first, this
//! binding verifies over them in memory, and hands back what to store: the
//! nonce to check and record, a newly recorded person, a grown list. The
//! TypeScript layer checks the nonce in the application's store, atomic
//! across workers, before it accepts the request or stores anything.

use crate::convert::{Obj, array, bytes, bytes_in, items};
use crate::error::{Js, invalid};
use frasil::{DeviceId, DeviceLists, MemberId, NonceStore, PersonId, RequestVerifier};
use wasm_bindgen::prelude::*;

/// A person's placed list events, each with its first sight in seconds.
type Events = Vec<(Vec<u8>, u64)>;

/// The records of one subject and one person, loaded by the caller.
struct Lists {
    recorded: Option<PersonId>,
    person: Option<PersonId>,
    list: Events,
    record: Option<PersonId>,
    kept: Option<(PersonId, Events)>,
}

impl DeviceLists for Lists {
    fn recorded_person(&self, _subject: &str) -> Option<PersonId> {
        self.recorded
    }

    fn record_person(&mut self, _subject: &str, person: PersonId) {
        self.record = Some(person);
    }

    fn list(&self, person: &PersonId) -> Vec<(Vec<u8>, u64)> {
        match &self.kept {
            Some((kept, events)) if kept == person => events.clone(),
            _ if self.person.as_ref() == Some(person) => self.list.clone(),
            _ => Vec::new(),
        }
    }

    fn keep_list(&mut self, person: &PersonId, events: Vec<(Vec<u8>, u64)>) {
        self.kept = Some((*person, events));
    }
}

/// The nonce the verifier asked about, unseen as far as it knows: the
/// caller's store decides.
#[derive(Default)]
struct Nonces {
    asked: Option<(DeviceId, [u8; 16], u64, u64)>,
}

impl NonceStore for Nonces {
    fn check_and_record(
        &mut self,
        device: &DeviceId,
        nonce: &[u8; 16],
        until: u64,
        now: u64,
    ) -> bool {
        self.asked = Some((*device, *nonce, until, now));
        true
    }
}

/// The wall clock, from `Date.now()`, in seconds.
fn wall() -> Option<u64> {
    let milliseconds = js_sys::Date::now();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (milliseconds.is_finite() && milliseconds >= 0.0).then_some((milliseconds / 1000.0) as u64)
}

fn person_in(text: Option<String>) -> Result<Option<PersonId>, JsValue> {
    text.map(|text| crate::convert::id::<PersonId>(&text))
        .transpose()
}

fn seconds(value: &JsValue) -> Option<u64> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    value
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0 && n.fract() == 0.0)
        .map(|n| n as u64)
}

/// List events as `[Uint8Array, number]` pairs.
fn events_in(value: &JsValue) -> Result<Vec<(Vec<u8>, u64)>, JsValue> {
    const SHAPE: &str = "a list is an array of [Uint8Array, seconds] pairs.";
    items(value, "the list")?
        .iter()
        .map(|pair| {
            let pair = items(pair, "a list event").map_err(|_| invalid(SHAPE))?;
            match pair.as_slice() {
                [event, first_seen] => Ok((
                    bytes_in(event).ok_or_else(|| invalid(SHAPE))?,
                    seconds(first_seen).ok_or_else(|| invalid(SHAPE))?,
                )),
                _ => Err(invalid(SHAPE)),
            }
        })
        .collect()
}

fn events_out(events: &[(Vec<u8>, u64)]) -> JsValue {
    array(events, |(event, first_seen)| {
        #[allow(clippy::cast_precision_loss)]
        js_sys::Array::of2(&bytes(event), &JsValue::from_f64(*first_seen as f64)).into()
    })
}

fn hex_of(value: &[u8]) -> String {
    crate::convert::hex(value)
}

/// Verifies a signed request at the server whose origin is `audience`,
/// from its configuration and never from the request: `subject` the
/// verified access token's `sub`, its `method`, `url` (its origin is not
/// read), `headers` as `[name, value]` pairs and
/// `body`, over the subject's `recorded` person and the signing person's
/// `list` (`[event, firstSeen]` pairs) that the caller loaded. Returns `{
/// person, device, listNeeded, nonce, recordPerson, keptList }`: `nonce`
/// is `{ device, nonce, until, now }` to check and record, `recordPerson`
/// the person to record for the subject, `keptList` `{ person, events }`
/// to keep; each `undefined` when there is nothing to do. Throws the
/// refusal's class.
#[wasm_bindgen(js_name = verifyRequest)]
#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    audience: String,
    subject: String,
    method: String,
    url: String,
    headers: JsValue,
    body: Vec<u8>,
    recorded: Option<String>,
    person: Option<String>,
    list: JsValue,
) -> Result<JsValue, JsValue> {
    const SHAPE: &str = "the headers are [name, value] pairs of strings.";
    let headers = items(&headers, "the headers")?
        .iter()
        .map(|pair| {
            let pair = items(pair, "a header").map_err(|_| invalid(SHAPE))?;
            match pair.as_slice() {
                [name, value] => Ok((
                    name.as_string().ok_or_else(|| invalid(SHAPE))?,
                    value.as_string().ok_or_else(|| invalid(SHAPE))?,
                )),
                _ => Err(invalid(SHAPE)),
            }
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    let lists = Lists {
        recorded: person_in(recorded)?,
        person: person_in(person)?,
        list: if list.is_undefined() {
            Vec::new()
        } else {
            events_in(&list)?
        },
        record: None,
        kept: None,
    };
    let mut verifier = RequestVerifier::new(&audience, lists, Nonces::default())
        .js()?
        .with_clock(wall);
    let verified = verifier
        .verify(&subject, &method, &url, &headers, &body)
        .js()?;
    let (lists, nonces) = verifier.into_parts();
    let nonce = nonces
        .asked
        .map_or(JsValue::UNDEFINED, |(device, nonce, until, now)| {
            #[allow(clippy::cast_precision_loss)]
            Obj::new()
                .set("device", hex_of(&device.0))
                .set("nonce", bytes(&nonce))
                .set("until", JsValue::from_f64(until as f64))
                .set("now", JsValue::from_f64(now as f64))
                .build()
        });
    let kept = lists
        .kept
        .as_ref()
        .map_or(JsValue::UNDEFINED, |(person, events)| {
            Obj::new()
                .set("person", person.to_string())
                .set("events", events_out(events))
                .build()
        });
    Ok(Obj::new()
        .set("person", verified.person.to_string())
        .set("device", verified.device.to_string())
        .set("listNeeded", verified.list_needed)
        .set("nonce", nonce)
        .set(
            "recordPerson",
            lists.record.map_or(JsValue::UNDEFINED, |person: MemberId| {
                JsValue::from(person.to_string())
            }),
        )
        .set("keptList", kept)
        .build())
}
