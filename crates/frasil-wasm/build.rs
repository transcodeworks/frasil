//! Prepares the vector tests of `frasil-crypto`, `frasil-events`,
//! `frasil-store` and `frasil-units` for `tests/vectors.rs`, which runs them
//! again on the JavaScript wasm target, in Node.js.
//!
//! Each test file is copied into `OUT_DIR` for `include!`, with four
//! changes and no other: its inner attributes and inner doc comments go
//! (they cannot stand inside a module); `mod common;` becomes a `use` of
//! the copy of that crate's `tests/common/mod.rs`; and a `use` of
//! `wasm_bindgen_test` as `test` comes first, so each `#[test]` is a
//! `#[wasm_bindgen_test]`, which `wasm-bindgen-test-runner` runs; and
//! `frasil-store`'s SQLite tests are compiled out. On any
//! other target this script does nothing.

use std::path::Path;

/// The copies: their module, the file under `crates/`, and the module that
/// stands in for its `mod common;`.
const SOURCES: &[(&str, &str, Option<&str>)] = &[
    (
        "crypto_keys_and_wraps",
        "frasil-crypto/tests/keys_and_wraps.rs",
        None,
    ),
    (
        "crypto_mldsa65_known_answers",
        "frasil-crypto/tests/mldsa65_known_answers.rs",
        None,
    ),
    ("crypto_schemes", "frasil-crypto/tests/schemes.rs", None),
    ("events_events", "frasil-events/tests/events.rs", None),
    ("events_coverage", "frasil-events/tests/coverage.rs", None),
    ("events_log", "frasil-events/tests/log.rs", None),
    ("store_common", "frasil-store/tests/common/mod.rs", None),
    (
        "store_store",
        "frasil-store/tests/store.rs",
        Some("store_common"),
    ),
    (
        "store_at_rest",
        "frasil-store/tests/at_rest.rs",
        Some("store_common"),
    ),
    ("units_common", "frasil-units/tests/common/mod.rs", None),
    (
        "units_runtime",
        "frasil-units/tests/runtime.rs",
        Some("units_common"),
    ),
    (
        "units_decoders",
        "frasil-units/tests/decoders.rs",
        Some("units_common"),
    ),
    (
        "units_snapshots",
        "frasil-units/tests/snapshots.rs",
        Some("units_common"),
    ),
    (
        "units_procedures",
        "frasil-units/tests/procedures.rs",
        Some("units_common"),
    ),
    (
        "units_formats",
        "frasil-units/tests/formats.rs",
        Some("units_common"),
    ),
];

fn copy(text: &str, common: Option<&str>) -> String {
    let mut out = String::from(
        "#[allow(unused_imports)]\nuse wasm_bindgen_test::wasm_bindgen_test as test;\n",
    );
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//!") || trimmed.starts_with("#![") {
            continue;
        }
        match (trimmed, common) {
            ("mod common;", Some(common)) => {
                out.push_str(&format!("use super::{common} as common;\n"));
            }
            // SQLite does not build for this target.
            ("#[cfg(feature = \"sqlite\")]", _) => out.push_str("#[cfg(any())]\n"),
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("unknown");
    if !wasm {
        return;
    }
    let (Some(manifest), Some(out)) = (
        std::env::var_os("CARGO_MANIFEST_DIR"),
        std::env::var_os("OUT_DIR"),
    ) else {
        return;
    };
    let crates = Path::new(&manifest).join("..");
    for (module, source, common) in SOURCES {
        let path = crates.join(source);
        println!("cargo:rerun-if-changed={}", path.display());
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        std::fs::write(
            Path::new(&out).join(format!("{module}.rs")),
            copy(&text, *common),
        )
        .unwrap_or_else(|error| panic!("{module}: {error}"));
    }
}
