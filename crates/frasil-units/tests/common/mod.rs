//! What the units.json tests share: the file, hex helpers, and the
//! reference's fixed inputs (`docs/spec/reference/units.py`, "The
//! vectors"), each a hash of a description, so no value is magic.

#![allow(dead_code)]

use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::Signer;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_testkit::hex;
use frasil_units::StreamId;
use serde_json::Value as Json;

pub const FILE: &str = "units.json";

pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

pub fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

pub fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

pub fn id(value: &Json) -> EventId {
    EventId(array(value))
}

pub fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

/// `example(name)`: SHA-256 of `"frasil spec example/" || name`.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The space of the vectors.
pub fn space() -> EventId {
    EventId(example("units/space"))
}

/// A device of the vectors: its identity seed, and the fixture ML-DSA-65
/// and X-Wing seeds crypto.md derives from it.
pub fn signer_of_seed(seed: &[u8; 32]) -> Signer {
    FixtureKeys::from_identity_seed(seed).signer()
}

/// Device `name` of the vectors.
pub fn signer(name: &str) -> Signer {
    signer_of_seed(&example(&format!("units/device/{name}")))
}

/// `nonce(label)`: SHA-256 of `"units/nonce/" || label`, its first 24
/// bytes.
pub fn nonce(label: &str) -> [u8; 24] {
    let digest = sha256(&[b"units/nonce/", label.as_bytes()]);
    digest[..24].try_into().expect("24 bytes")
}

/// The salt of stream `name`.
pub fn salt(name: &str) -> [u8; 16] {
    let digest = sha256(&[b"units/salt/", name.as_bytes()]);
    digest[..16].try_into().expect("16 bytes")
}

/// The system stream the vectors use.
pub fn system() -> StreamId {
    let digest = sha256(&[b"units/system-stream (stands for 16 random bytes)"]);
    digest[..16].try_into().expect("16 bytes")
}

/// Rotation `name` and its content key.
pub fn rotation(name: &str) -> (EventId, [u8; 32]) {
    (
        EventId(example(&format!("units/rotation/{name}"))),
        example(&format!("units/rotation/{name}/content")),
    )
}

/// The content key of the state of these rotations, in the vectors' space.
pub fn state_key(names: &[&str]) -> [u8; 32] {
    state_key_in(&space(), names)
}

/// The content key of the state of these rotations in `space`: a merge
/// binds the space (keys.md, "Derivations").
pub fn state_key_in(space: &EventId, names: &[&str]) -> [u8; 32] {
    let mut pairs: Vec<(EventId, [u8; 32])> = names.iter().map(|n| rotation(n)).collect();
    pairs.sort_unstable_by_key(|(id, _)| *id);
    let set = RotationSet::new(pairs.iter().map(|(id, _)| *id)).expect("a state");
    let inputs: Vec<[u8; 32]> = pairs.iter().map(|(_, key)| *key).collect();
    *state_secret(SecretKind::Content, space, &set, &inputs).expect("a key")
}

/// The key reference of the state of these rotations.
pub fn key_reference(names: &[&str]) -> Vec<u8> {
    RotationSet::new(names.iter().map(|n| rotation(n).0))
        .expect("a state")
        .encode()
}
