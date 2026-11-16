//! Helpers the vector tests share.

#![allow(dead_code)]

use frasil_base::errors::Class;
use frasil_crypto::device::IdentityKey;
use frasil_crypto::fixtures::{fixture_mldsa_seed, fixture_xwing_seed};
use frasil_crypto::primitives::sha256;
use frasil_identity::MemberKeys;
use serde_json::Value as Json;

/// The vector file.
pub const FILE: &str = "identity.json";

/// A family of `identity.json`, as JSON.
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

/// A device of the vectors, named under a prefix: its identity seed is the
/// example `<prefix>/<name>/ed25519`, and its ML-DSA-65 and X-Wing seeds the
/// fixture derivations (crypto.md, "A device's keys").
pub fn device(prefix: &str, name: &str) -> MemberKeys {
    let identity_seed = example(&format!("{prefix}/{name}/ed25519"));
    MemberKeys::from_seeds(
        &identity_seed,
        &fixture_xwing_seed(&identity_seed),
        &fixture_mldsa_seed(&identity_seed),
    )
}

/// A recovery agent of the vectors, named under a prefix: as [`device`],
/// with no X-Wing key.
pub fn agent(prefix: &str, name: &str) -> MemberKeys {
    let identity_seed = example(&format!("{prefix}/{name}/ed25519"));
    MemberKeys::without_xwing(&identity_seed, &fixture_mldsa_seed(&identity_seed))
}

// ---------------------------------------------------------------------------
// Lists, as the vectors write them.

use frasil_crypto::primitives::ed25519_public;
use frasil_events::{EventId, decode};
use frasil_identity::{DeviceList, Kind, MergedList};
use frasil_resolve::{How, Verdict};
use std::collections::BTreeMap;

/// The kind of a name the vectors use.
pub fn kind_named(name: &str) -> Kind {
    Kind::ALL
        .into_iter()
        .find(|kind| kind.name() == name)
        .unwrap_or_else(|| panic!("no kind {name}"))
}

/// The identity key of a device of the vectors: the Ed25519 key of the
/// example `<prefix>/<name>/ed25519`.
pub fn identity_of(prefix: &str, name: &str) -> IdentityKey {
    IdentityKey(ed25519_public(&example(&format!(
        "{prefix}/{name}/ed25519"
    ))))
}

/// The signed bytes of a hex string.
pub fn hex(text: &str) -> Vec<u8> {
    frasil_testkit::hex::decode(text).unwrap()
}

/// A list of events the vectors describe, each with `name` and `signed`:
/// the first starts the list, and the rest are inserted in the order given.
/// Returns the list and each event's name by ID.
pub fn list_of(rows: &[&Json]) -> (DeviceList, BTreeMap<EventId, String>) {
    let mut names = BTreeMap::new();
    let mut list = None::<DeviceList>;
    for row in rows {
        let signed = bytes(row, "signed");
        let id = decode(&signed).unwrap().id();
        names.insert(id, text(row, "name").to_string());
        match &mut list {
            None => list = Some(DeviceList::new(&signed).unwrap()),
            Some(list) => {
                list.insert(&signed).unwrap();
            }
        }
    }
    let list = list.unwrap();
    assert_eq!(list.log().len(), rows.len(), "every event placed");
    (list, names)
}

/// A verdict as the vectors write it: `valid`, `valid (agreed)`, `valid
/// (seniority)`, a class, or a class `by` the attacker's name.
pub fn verdict_text(
    verdict: &Verdict<EventId, frasil_identity::IdentityClass>,
    names: &BTreeMap<EventId, String>,
) -> String {
    use frasil_base::errors::Class;
    match verdict {
        Verdict::Valid(How::Rules) => "valid".into(),
        Verdict::Valid(How::Agreed) => "valid (agreed)".into(),
        Verdict::Valid(How::Seniority) => "valid (seniority)".into(),
        Verdict::Void { class, by: None } => class.name().into(),
        Verdict::Void {
            class,
            by: Some(by),
        } => format!("{} by {}", class.name(), names[by]),
    }
}

/// Checks a merged list against the reference's summary: every event's
/// status, every list member's kind, activity, rootedness, rank and fork
/// point, the active list members and whether the list is dead. `members`
/// names each list member's Ed25519 key, which the list gives with its
/// device ID.
pub fn check_summary(
    case: &str,
    merged: &MergedList,
    names: &BTreeMap<EventId, String>,
    members: &BTreeMap<IdentityKey, String>,
    expected: &Json,
) {
    let name_of = |m: &frasil_identity::Member| -> String {
        let keys = merged.keys(&m.device).expect("a member's keys");
        assert_eq!(keys.device_id(), m.device, "{case}");
        members
            .get(&keys.identity)
            .unwrap_or_else(|| panic!("{case}: an unnamed list member"))
            .clone()
    };
    let statuses: serde_json::Map<String, Json> = merged
        .verdicts()
        .map(|(id, verdict)| (names[&id].clone(), Json::from(verdict_text(verdict, names))))
        .collect();
    assert_eq!(
        Json::Object(statuses),
        expected["events"],
        "{case}: statuses"
    );
    let summary: serde_json::Map<String, Json> = merged
        .members()
        .values()
        .map(|m| {
            (
                name_of(m),
                serde_json::json!({
                    "kind": m.kind.name(),
                    "active": m.active(),
                    "rooted": m.rooted().name(),
                    "rank": m.rank().number(),
                    "forked_at": merged.fork_point(&m.device),
                }),
            )
        })
        .collect();
    assert_eq!(
        Json::Object(summary),
        expected["members"],
        "{case}: members"
    );
    let mut active: Vec<String> = merged.active_members().map(name_of).collect();
    active.sort_unstable();
    assert_eq!(Json::from(active), expected["active"], "{case}: active");
    assert_eq!(merged.is_dead(), expected["dead"], "{case}: dead");
}

/// Each list member's name by device ID, from the names of their Ed25519
/// keys and the keys the merged list holds for each device ID.
pub fn by_device(
    merged: &MergedList,
    members: &BTreeMap<IdentityKey, String>,
) -> BTreeMap<frasil_crypto::device::DeviceId, String> {
    merged
        .members()
        .keys()
        .filter_map(|device| {
            let keys = merged.keys(device)?;
            Some((*device, members.get(&keys.identity)?.clone()))
        })
        .collect()
}

/// The identity keys of the list members a summary names, as devices of the
/// vectors under `prefix`.
pub fn device_names(prefix: &str, expected: &Json) -> BTreeMap<IdentityKey, String> {
    expected["members"]
        .as_object()
        .unwrap()
        .keys()
        .map(|name| (identity_of(prefix, name), name.clone()))
        .collect()
}
