//! `ext-next-endpoints.json`, `rotation` (ext-next-endpoints.md, "Rotating"):
//! the seed a rotation takes, the key it announces, and the
//! `next_endpoint` record before and after.

use frasil_crypto::primitives::ed25519_public;
use frasil_store::tables::{Secret, Table, TableValue};
use frasil_testkit::hex;
use serde_json::Value as Json;

fn array(value: &Json) -> [u8; 32] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

/// The record a seed is kept as, read back as the table reads it.
fn record(seed: [u8; 32]) -> Vec<u8> {
    let value = TableValue::NextEndpoint(Secret::new(seed)).encode();
    assert_eq!(
        TableValue::read(Table::NextEndpoint, &[], &value, None).unwrap(),
        TableValue::NextEndpoint(Secret::new(seed))
    );
    value.to_vec()
}

#[test]
fn a_rotation_takes_the_kept_seed_and_keeps_a_fresh_one() {
    let rotation: Json = frasil_testkit::vectors::family("ext-next-endpoints.json", "rotation");
    let kept = &rotation["with_a_kept_seed"];
    let seed = array(&kept["kept_next_seed"]);
    let next = array(&kept["fresh_next_seed"]);
    assert_eq!(record(seed), array(&kept["record_before"]));
    assert_eq!(ed25519_public(&seed), array(&kept["endpoint_key"]));
    assert_eq!(ed25519_public(&next), array(&kept["announced_key"]));
    assert_eq!(record(next), array(&kept["record_after"]));

    let none = &rotation["with_none"];
    let fresh = array(&none["fresh_seed"]);
    let next = array(&none["fresh_next_seed"]);
    assert_eq!(ed25519_public(&fresh), array(&none["endpoint_key"]));
    assert_eq!(ed25519_public(&next), array(&none["announced_key"]));
    assert_eq!(record(next), array(&none["record_after"]));
    // The first rotation's announced key is the one the second takes.
    assert_eq!(array(&none["announced_key"]), array(&kept["endpoint_key"]));
}
