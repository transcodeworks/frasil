//! Helpers the vector tests share.

#![allow(dead_code)]

pub mod space;

use frasil_base::errors::Class;
use frasil_crypto::primitives::sha256;
use frasil_events::{Event, EventId, Log, decode};
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::read_credential;
use frasil_space::{Keyring, Limits, RosterClass, ScreenedLog};
use serde_json::Value as Json;
use zeroize::Zeroizing;

/// The vector file.
pub const FILE: &str = "roster.json";

/// A family of `roster.json`, as JSON.
pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

/// The bytes of a hex string field.
pub fn bytes(value: &Json, key: &str) -> Vec<u8> {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"));
    frasil_testkit::hex::decode(text).unwrap_or_else(|error| panic!("{key}: {error}"))
}

/// The bytes of a hex string field, as an array.
pub fn array<const N: usize>(value: &Json, key: &str) -> [u8; N] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

/// A string field.
pub fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

/// The class name a result failed with, or `None` if it passed.
pub fn class<T, C: Class>(result: Result<T, C>) -> Option<&'static str> {
    result.err().map(Class::name)
}

/// The reference's fixed inputs: SHA-256 of a description, so no value is
/// magic.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// A stand-in ID for a device or a person the vectors name: any injective
/// map of names does.
pub fn named(name: &str) -> [u8; 32] {
    sha256(&[b"name/", name.as_bytes()])
}

/// A history's events, as the vectors give them (`name`, `signed`), in
/// canonical order, decoded.
pub fn events(history: &Json) -> Vec<(String, Event)> {
    history
        .as_array()
        .expect("a history is an array")
        .iter()
        .map(|event| {
            let decoded = decode(&bytes(event, "signed")).expect("the event decodes");
            if let Some(id) = event.get("id").and_then(Json::as_str) {
                assert_eq!(frasil_testkit::hex::encode(decoded.id().0), id);
            }
            (text(event, "name").to_owned(), decoded)
        })
        .collect()
}

/// A log of these events, the first the genesis.
pub fn log_of(events: &[(String, Event)]) -> Log {
    let mut log = Log::new(events[0].1.clone()).expect("a genesis");
    for (_, event) in &events[1..] {
        log.place(event.clone()).expect("placed");
    }
    log
}

/// Whether a space event rotates with this content key as its own: its
/// read credential is the rotation's visible `read`.
pub fn rotates_with(event: &Event, secret: &[u8; 32]) -> bool {
    VisiblePart::read(event.unverified_body(), event.author(), event.seq())
        .ok()
        .and_then(|visible| visible.rotation().map(|rotation| rotation.read))
        .is_some_and(|read| read_credential(secret).public == read)
}

/// Every rotation's content key, as the vectors' builders derive it: the
/// example `<prefix>/<label>/content-key`, `genesis` for the genesis, each
/// event's label its name. Only keys that match a rotation's `read` are
/// held; `extra` gives other candidates, tried for every event.
pub fn keyring(prefix: &str, events: &[(String, Event)], extra: &[[u8; 32]]) -> Keyring {
    let mut keys = Keyring::default();
    for (index, (name, event)) in events.iter().enumerate() {
        let label = if index == 0 { "genesis" } else { name.as_str() };
        let own = example(&format!("{prefix}/{label}/content-key"));
        for candidate in std::iter::once(own).chain(extra.iter().copied()) {
            if rotates_with(event, &candidate) {
                keys.rotations.insert(event.id(), Zeroizing::new(candidate));
                break;
            }
        }
    }
    keys
}

/// The ID of the event a history names so.
pub fn id_named(events: &[(String, Event)], name: &str) -> EventId {
    events
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no event {name}"))
        .1
        .id()
}

/// Screens a log with the protocol's limits and no other log.
pub fn screen(log: &Log, keys: &Keyring) -> Result<ScreenedLog, RosterClass> {
    ScreenedLog::screen(log, keys, &Limits::PROTOCOL, &())
}
