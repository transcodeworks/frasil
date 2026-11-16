//! `ext-libraries.json`'s `access_keys`, `hold_object` and `holds`: an
//! object's access key, a `HoldObject` as it travels, and a peer's checks
//! of it in order (ext-libraries.md, 2.7 Object keys and access keys, 2.8
//! HoldObject, and 3.7 Registering a hold).

use std::collections::{BTreeMap, BTreeSet};

use frasil_base::errors::Class;
use frasil_crypto::labels::{OBJECT_HOLD, OBJECT_SEAL_KEY};
use frasil_crypto::primitives::{hkdf, hmac_sha256};
use frasil_libraries::hold::{LOCATOR_BYTES, access_seed, held};
use frasil_libraries::{HoldObject, LibraryClass, PeerHolds, access_key, check_hold};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;

const FILE: &str = "ext-libraries.json";

fn array<const N: usize>(text: &str) -> [u8; N] {
    hex::decode_array(text).unwrap()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessKeys {
    source: String,
    content_key: String,
    key_reference: String,
    object_id: String,
    locator: String,
    object_key: String,
    access_seed: String,
    access_key: String,
}

fn access_keys() -> AccessKeys {
    vectors::family(FILE, "access_keys")
}

#[test]
fn an_objects_access_key_derives_from_its_key() {
    let v = access_keys();
    // units.md: object key = HMAC(object_seal_key(S), object ID).
    let seal_key = hkdf(None, &array::<32>(&v.content_key), OBJECT_SEAL_KEY);
    let object_key = hmac_sha256(&*seal_key, &array::<32>(&v.object_id));
    assert_eq!(hex::encode(object_key), v.object_key);
    assert_eq!(hex::encode(*access_seed(&object_key)), v.access_seed);
    assert_eq!(hex::encode(access_key(&object_key)), v.access_key);
    assert_eq!(&v.locator[..64], v.object_id);
    assert!(!v.source.is_empty() && !v.key_reference.is_empty());
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldVector {
    binding: String,
    space: String,
    source: String,
    locator: String,
    access: String,
    held: String,
    signed: String,
    proof: String,
    message: String,
}

#[test]
fn a_hold_object_is_byte_for_byte() {
    let v: HoldVector = vectors::family(FILE, "hold_object");
    let object_key = array::<32>(&access_keys().object_key);
    let binding = array::<32>(&v.binding);
    let (space, source) = (array::<32>(&v.space), array::<32>(&v.source));
    let locator = array::<LOCATOR_BYTES>(&v.locator);
    let access = array::<32>(&v.access);
    assert_eq!(access, access_key(&object_key));
    let message = HoldObject::prove(1, &binding, space, source, locator, &object_key);
    assert_eq!(
        hex::encode(held(&binding, &space, &source, &locator, &access)),
        v.held
    );
    let mut signed = OBJECT_HOLD.to_vec();
    signed.extend_from_slice(&hex::decode(&v.held).unwrap());
    assert_eq!(hex::encode(&signed), v.signed);
    assert_eq!(hex::encode(message.proof), v.proof);
    assert_eq!(hex::encode(message.encode()), v.message);
    assert_eq!(
        HoldObject::decode(&hex::decode(&v.message).unwrap()),
        Ok(message.clone())
    );
    assert!(message.proof_verifies(&binding));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    message: String,
    binding: String,
    store_right: Vec<String>,
    fetch_right: Vec<String>,
    libraries: BTreeMap<String, String>,
    objects: Vec<[String; 2]>,
    holds_before: Vec<[String; 3]>,
    verdict: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    holds_after: Vec<[String; 3]>,
}

/// The peer's setup of one check.
struct Setup<'c>(&'c Check);

impl PeerHolds for Setup<'_> {
    fn store_right(&self, space: &[u8; 32]) -> bool {
        self.0.store_right.contains(&hex::encode(space))
    }
    fn fetch_right(&self, space: &[u8; 32]) -> bool {
        self.0.fetch_right.contains(&hex::encode(space))
    }
    fn vouches(&self, locator: &[u8; LOCATOR_BYTES], access: &[u8; 32]) -> bool {
        self.0
            .holds_before
            .iter()
            .any(|[_, l, a]| *l == hex::encode(locator) && *a == hex::encode(access))
    }
    fn holds_object(&self, source: &[u8; 32], locator: &[u8; LOCATOR_BYTES]) -> bool {
        self.0
            .objects
            .iter()
            .any(|[s, l]| *s == hex::encode(source) && *l == hex::encode(locator))
    }
    fn same_library(&self, space: &[u8; 32], source: &[u8; 32]) -> bool {
        let library = |id: &[u8; 32]| self.0.libraries.get(&hex::encode(id));
        library(space).is_some() && library(space) == library(source)
    }
}

#[test]
fn a_peer_checks_a_hold_in_order() {
    let checks: Vec<Check> = vectors::family(FILE, "holds");
    assert_eq!(checks.len(), 8);
    for check in &checks {
        let name = &check.name;
        let binding = array::<32>(&check.binding);
        let verdict = HoldObject::decode(&hex::decode(&check.message).unwrap())
            .and_then(|hold| check_hold(&hold, &binding, &Setup(check)).map(|()| hold));
        match &verdict {
            Ok(hold) => {
                assert_eq!(check.verdict, "accepted", "{name}");
                // The hold is recorded, named by its space and locator.
                let after: BTreeSet<_> = check.holds_after.iter().collect();
                let row = [
                    hex::encode(hold.space),
                    hex::encode(hold.locator),
                    hex::encode(hold.access),
                ];
                assert!(after.contains(&row), "{name}");
            }
            Err(class) => {
                assert_eq!(class.name(), check.verdict, "{name}");
                assert_eq!(check.code.as_deref(), Some(class.code()), "{name}");
                assert_eq!(check.status, class.status(), "{name}");
                assert_eq!(check.holds_before, check.holds_after, "{name}");
            }
        }
    }
    let classes: Vec<&str> = checks.iter().map(|c| c.verdict.as_str()).collect();
    for class in [
        "NotAuthorized",
        "HoldRefused",
        "UnknownObject",
        "OtherLibrary",
    ] {
        assert!(classes.contains(&class), "{class}");
        assert!(LibraryClass::from_name(class).is_some(), "{class}");
    }
}
