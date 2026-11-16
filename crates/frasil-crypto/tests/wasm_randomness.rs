//! Randomness on the JavaScript wasm target (crypto.md, "Primitives",
//! "Randomness"): every random byte this crate hands out must come from the
//! host's `crypto.getRandomValues`, and a host without it must get
//! [`NoRandomness`]: never weaker bytes, never a panic.
//!
//! The procedures themselves draw nothing: they take their random bytes as
//! arguments. So [`random_bytes`] is the only draw, and a wrap sealed with
//! its bytes is what the host's generator made it.
//!
//! The first test replaces `getRandomValues` with a stub that fills buffers
//! with one constant byte and counts its calls. The others remove the
//! generator, then `crypto` itself. Each test restores the real one before it
//! returns. Run with `wasm-bindgen-test-runner` under Node.js or a browser.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

use frasil_crypto::wrap::{self, WrapUse};
use frasil_crypto::{NoRandomness, random_bytes};
use js_sys::{Function, Object, Reflect, global};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test as test;

const BYTE: u8 = 0xa5;
const DRAWS: &str = "__frasilRandomDraws";

fn host_crypto() -> Object {
    Reflect::get(&global(), &"crypto".into())
        .expect("globalThis.crypto")
        .into()
}

fn draws() -> u32 {
    Reflect::get(&global(), &DRAWS.into())
        .unwrap()
        .as_f64()
        .unwrap_or(0.0) as u32
}

/// Replaces `crypto.getRandomValues` on the host's `crypto` object until
/// dropped. The stub is an own property that shadows the prototype's method,
/// so removing it restores the real generator.
struct Stubbed;

impl Stubbed {
    fn constant() -> Self {
        let stub = Function::new_with_args(
            "buffer",
            &format!(
                "buffer.fill({BYTE}); globalThis.{DRAWS} = (globalThis.{DRAWS} || 0) + 1; return buffer;"
            ),
        );
        Reflect::set(&host_crypto(), &"getRandomValues".into(), &stub).unwrap();
        Self
    }

    fn missing() -> Self {
        Reflect::set(
            &host_crypto(),
            &"getRandomValues".into(),
            &JsValue::UNDEFINED,
        )
        .unwrap();
        Self
    }
}

impl Drop for Stubbed {
    fn drop(&mut self) {
        Reflect::delete_property(&host_crypto(), &"getRandomValues".into()).unwrap();
        Reflect::delete_property(&global(), &DRAWS.into()).unwrap();
    }
}

/// A wrap to a fixed X-Wing key, sealed with 64 bytes from `random_bytes`.
fn seal_with_drawn_randomness() -> Result<Vec<u8>, NoRandomness> {
    let recipient = wrap::xwing_public(&[3; 32]);
    let randomness = random_bytes::<64>()?;
    Ok(wrap::seal_wrap_with(
        &recipient,
        &WrapUse::Welcome.info(b"recipient"),
        b"plaintext",
        &randomness,
    )
    .expect("a valid X-Wing key"))
}

#[test]
fn every_random_byte_comes_from_get_random_values() {
    let _stub = Stubbed::constant();
    let before = draws();
    let bytes = random_bytes::<32>().unwrap();
    assert_eq!((*bytes, draws() - before), ([BYTE; 32], 1));

    let before = draws();
    let sealed = seal_with_drawn_randomness().unwrap();
    assert_eq!(draws() - before, 1);
    let expected = wrap::seal_wrap_with(
        &wrap::xwing_public(&[3; 32]),
        &WrapUse::Welcome.info(b"recipient"),
        b"plaintext",
        &[BYTE; 64],
    )
    .unwrap();
    assert_eq!(sealed, expected);
}

#[test]
fn a_host_without_get_random_values_gets_no_randomness() {
    {
        let _missing = Stubbed::missing();
        assert_eq!(random_bytes::<32>().unwrap_err(), NoRandomness);
        assert_eq!(seal_with_drawn_randomness(), Err(NoRandomness));
    }
    // Once the host has a generator again, so does this crate.
    assert!(seal_with_drawn_randomness().is_ok());
}

#[test]
fn a_host_without_crypto_gets_no_randomness() {
    // Shadow the global `crypto` itself, as in a host that has none. Browsers
    // define it on the global's prototype and Node.js on the global itself;
    // keep whatever own property there was, to put it back afterwards.
    let global = global();
    let own = Object::get_own_property_descriptor(&global, &"crypto".into());
    let shadow = Object::new();
    Reflect::set(&shadow, &"value".into(), &JsValue::UNDEFINED).unwrap();
    Reflect::set(&shadow, &"configurable".into(), &JsValue::TRUE).unwrap();
    Object::define_property(&global, &"crypto".into(), &shadow);
    let drawn = random_bytes::<32>().map(|_| ());
    if own.is_undefined() {
        Reflect::delete_property(&global, &"crypto".into()).unwrap();
    } else {
        Object::define_property(&global, &"crypto".into(), &own.into());
    }
    assert_eq!(drawn, Err(NoRandomness));
    assert!(random_bytes::<32>().is_ok());
}
