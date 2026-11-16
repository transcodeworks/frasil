//! `crypto.json` `wycheproof`: Wycheproof's X25519 and Ed25519 files, at the
//! commit the vectors pin, run against this crate's key checks and its
//! X25519 at use (crypto.md, "Test vectors").
//!
//! The files are not in the repository. The reference script
//! (`docs/spec/reference/generate.py`) fetches them once into its git-ignored
//! cache, `docs/spec/reference/.cache/wycheproof/<commit>/`, and checks
//! their SHA-256. These tests read them from that cache, check the same
//! hashes, and compare every verdict with the one the vectors record:
//!
//! - for each X25519 test, where `x25519_valid` refuses the public key
//!   (`at_entry`), and whether `x25519_at_use` matches Wycheproof's shared
//!   secret or refuses an all-zero one (`at_use`);
//! - for each Ed25519 group, whether `ed25519_valid` accepts its public key.
//!
//! Keys Wycheproof calls valid that are not of order `ℓ` are refused here,
//! by design. A missing file or a wrong hash fails the test with a message
//! saying how to fetch it. Native only: a browser has no file system.
#![cfg(not(target_arch = "wasm32"))]

use frasil_crypto::keys::{self, Ed25519Step, X25519Step};
use frasil_crypto::primitives::sha256;
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

const FILE: &str = "crypto.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    repository: String,
    commit: String,
    licence: String,
    files: BTreeMap<String, PinnedFile>,
    ed25519_public_keys: Vec<Ed25519Group>,
    x25519_tests: Vec<X25519Test>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedFile {
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519Group {
    group: usize,
    tests: usize,
    result: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X25519Test {
    #[serde(rename = "tcId")]
    tc_id: u64,
    flags: String,
    wycheproof_result: String,
    at_entry: String,
    at_use: String,
}

fn pinned() -> Pinned {
    vectors::family(FILE, "wycheproof")
}

/// One Wycheproof file from the reference script's cache, checked against
/// the SHA-256 the vectors pin.
fn wycheproof(pinned: &Pinned, path: &str) -> Vec<u8> {
    let expected = &pinned
        .files
        .get(path)
        .unwrap_or_else(|| panic!("no pinned hash for {path}"))
        .sha256;
    let file: PathBuf = frasil_testkit::workspace_root()
        .join("docs/spec/reference/.cache/wycheproof")
        .join(&pinned.commit)
        .join(path);
    let contents = std::fs::read(&file).unwrap_or_else(|error| {
        panic!(
            "Wycheproof's {path} at commit {} is not in {} ({error}). Run the reference \
             script once with network to fetch it: see docs/spec/reference/README.md.",
            pinned.commit,
            file.display()
        )
    });
    assert_eq!(
        &hex::encode(sha256(&[&contents])),
        expected,
        "Wycheproof's {path} in {} is not the pinned file: its SHA-256 differs. Delete it and \
         run the reference script once with network to fetch it again.",
        file.display()
    );
    contents
}

fn json(contents: &[u8]) -> Value {
    serde_json::from_slice(contents).expect("a Wycheproof file is JSON")
}

fn hex_field(value: &Value) -> Vec<u8> {
    hex::from_value(value).expect("a hex field")
}

#[test]
fn the_source_is_the_pinned_one() {
    let pinned = pinned();
    assert_eq!(pinned.repository, "https://github.com/C2SP/wycheproof");
    assert_eq!(pinned.commit, "3fa63dd0344abb611f1fb1d77e119938603ea230");
    assert!(pinned.licence.starts_with("Apache-2.0"));
    assert_eq!(pinned.files.len(), 3);
    for path in pinned.files.keys() {
        wycheproof(&pinned, path);
    }
}

#[test]
fn x25519_tests_get_the_recorded_verdicts() {
    let pinned = pinned();
    let file = json(&wycheproof(&pinned, "testvectors_v1/x25519_test.json"));
    let tests: Vec<&Value> = file["testGroups"]
        .as_array()
        .expect("test groups")
        .iter()
        .flat_map(|group| group["tests"].as_array().expect("tests"))
        .collect();
    assert_eq!(tests.len(), 518);
    assert_eq!(tests.len(), pinned.x25519_tests.len());
    let mut accepted = 0;
    for (test, verdict) in tests.iter().zip(&pinned.x25519_tests) {
        let id = verdict.tc_id;
        assert_eq!(test["tcId"].as_u64(), Some(id));
        assert_eq!(
            test["result"].as_str(),
            Some(verdict.wycheproof_result.as_str())
        );
        let flags: Vec<&str> = test["flags"]
            .as_array()
            .expect("flags")
            .iter()
            .map(|flag| flag.as_str().expect("a flag"))
            .collect();
        assert_eq!(flags.join(","), verdict.flags, "test {id}");

        let public = hex_field(&test["public"]);
        let at_entry = match keys::check_x25519(&public) {
            Ok(()) => {
                accepted += 1;
                "accept".to_owned()
            }
            Err(step) => format!("refused at {}", X25519Step::name(step)),
        };
        assert_eq!(at_entry, verdict.at_entry, "test {id}");

        let private: [u8; 32] = hex_field(&test["private"]).try_into().unwrap();
        let public: [u8; 32] = public.try_into().unwrap();
        let at_use = match keys::x25519_at_use(&private, &public) {
            Ok(shared) => {
                assert_eq!(
                    hex::encode(shared.as_slice()),
                    test["shared"].as_str().unwrap(),
                    "test {id}"
                );
                "shared secret matches"
            }
            Err(_) => {
                assert_eq!(test["shared"].as_str(), Some(hex::encode([0; 32]).as_str()));
                "refused: all-zero shared secret"
            }
        };
        assert_eq!(at_use, verdict.at_use, "test {id}");
    }
    assert_eq!(accepted, 50);
}

#[test]
fn ed25519_public_keys_get_the_recorded_verdicts() {
    let pinned = pinned();
    let file = json(&wycheproof(&pinned, "testvectors_v1/ed25519_test.json"));
    let groups = file["testGroups"].as_array().expect("test groups");
    assert_eq!(groups.len(), 78);
    assert_eq!(groups.len(), pinned.ed25519_public_keys.len());
    for (index, (group, verdict)) in groups.iter().zip(&pinned.ed25519_public_keys).enumerate() {
        assert_eq!(verdict.group, index);
        let public = hex_field(&group["publicKey"]["pk"]);
        let result = match keys::check_ed25519(&public) {
            Ok(()) => "accept",
            Err(step) => Ed25519Step::name(step),
        };
        assert_eq!(result, verdict.result, "group {index}");
        assert_eq!(
            group["tests"].as_array().map(Vec::len),
            Some(verdict.tests),
            "group {index}"
        );
    }
}
