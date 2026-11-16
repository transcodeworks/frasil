//! The vector tests of `frasil-crypto`, `frasil-events`, `frasil-store` (at
//! rest) and `frasil-units`, run again on the JavaScript wasm target: the
//! same tests, compiled for `wasm32-unknown-unknown` and run by
//! `wasm-bindgen-test-runner` in Node.js. `build.rs` copies them in.
//!
//! They load their families through `frasil_testkit`, which reads the vector
//! files from disk; a module in Node.js has no file system. So this crate
//! answers to that name itself, and its [`vectors`] reads the files
//! compiled into the module. Left out: `frasil-crypto`'s Wycheproof test,
//! which reads files fetched apart from the repository, its property tests
//! (proptest does not build for this target) and its randomness test,
//! which runs under wasm32 in `frasil-crypto` itself; and `frasil-store`'s
//! SQLite tests.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

extern crate self as frasil_testkit;

/// Hex, as `frasil-testkit` has it.
pub mod hex {
    pub use testkit::hex::*;
}

/// The vector loader, over the vector files compiled in.
pub mod vectors {
    use serde::de::DeserializeOwned;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use testkit::vectors::VectorError;

    thread_local! {
        static LOADED: RefCell<BTreeMap<String, testkit::vectors::VectorFile>> =
            const { RefCell::new(BTreeMap::new()) };
    }

    fn text(name: &str) -> Option<&'static str> {
        Some(match name {
            "crypto.json" => include_str!("../../../docs/spec/vectors/crypto.json"),
            "events.json" => include_str!("../../../docs/spec/vectors/events.json"),
            "at-rest.json" => include_str!("../../../docs/spec/vectors/at-rest.json"),
            "units.json" => include_str!("../../../docs/spec/vectors/units.json"),
            _ => return None,
        })
    }

    /// `frasil_testkit::vectors::VectorFile`, loaded from the files
    /// compiled in.
    pub struct VectorFile;

    impl VectorFile {
        /// A file by its name, such as `crypto.json`, parsed once.
        pub fn load(name: &str) -> Result<testkit::vectors::VectorFile, VectorError> {
            if let Some(file) = LOADED.with(|loaded| loaded.borrow().get(name).cloned()) {
                return Ok(file);
            }
            let text = text(name).unwrap_or_else(|| panic!("{name} is not compiled in"));
            let file = testkit::vectors::VectorFile::parse(name, text)?;
            LOADED.with(|loaded| loaded.borrow_mut().insert(name.to_owned(), file.clone()));
            Ok(file)
        }
    }

    /// One family, read into a type of the caller's; panics with the file
    /// and family named if it cannot.
    pub fn family<T: DeserializeOwned>(file: &str, family: &str) -> T {
        VectorFile::load(file)
            .and_then(|vectors| vectors.family_as(family))
            .unwrap_or_else(|error| panic!("{error}"))
    }
}

macro_rules! copied {
    ($($module:ident),* $(,)?) => {
        $(
            #[allow(dead_code, unused_imports)]
            mod $module {
                include!(concat!(env!("OUT_DIR"), "/", stringify!($module), ".rs"));
            }
        )*
    };
}

copied!(
    crypto_keys_and_wraps,
    crypto_mldsa65_known_answers,
    crypto_schemes,
    events_events,
    events_coverage,
    events_log,
    store_common,
    store_store,
    store_at_rest,
    units_common,
    units_runtime,
    units_decoders,
    units_snapshots,
    units_procedures,
    units_formats,
);

/// A measurement, not a check: what opening sealed device keys costs here
/// (at-rest.md, "Sealing and opening the device keys"), whose step 10
/// derives the Ed25519, ML-DSA-65 and X-Wing public keys from their seeds
/// to compare their device ID with the header's; beside it, deriving the
/// three public keys alone. Run with `--include-ignored`.
#[wasm_bindgen_test::wasm_bindgen_test]
#[ignore]
fn opening_sealed_device_keys_costs() {
    use frasil_store::device_keys::{KeyKind, open_device_keys, seal_device_keys_with};
    const ROUNDS: u32 = 20;
    let keys = frasil_store::DeviceKeys::new([1; 32], [2; 32], [3; 32], [4; 32]);
    let device = keys.device_id();
    let sealed =
        seal_device_keys_with(&keys, &[0; 32], KeyKind::UnlockKey, &[5; 32], &[6; 24]).unwrap();
    let time = |f: &dyn Fn()| {
        f();
        let start = js_sys::Date::now();
        for _ in 0..ROUNDS {
            f();
        }
        (js_sys::Date::now() - start) / f64::from(ROUNDS)
    };
    let open = time(&|| {
        open_device_keys(
            &sealed,
            KeyKind::UnlockKey,
            &[5; 32],
            &[0; 32],
            Some(&device),
        )
        .unwrap();
    });
    let derive = time(&|| {
        let _ = keys.public_keys();
    });
    wasm_bindgen_test::console_log!(
        "opening sealed device keys: {open:.2} ms; deriving the three public keys: {derive:.2} ms ({ROUNDS} rounds each)"
    );
}
