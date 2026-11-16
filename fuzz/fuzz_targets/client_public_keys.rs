//! The developer crate's reader of a device's three public keys
//! (`frasil::advanced::public_keys`; roster.md, "A device's keys"): the
//! bytes, and a real device's 3,200 bytes with bytes the input places, each
//! read under a device ID they do not hash to and under the one they would
//! hash to. It never panics; it refuses only with `Malformed`, a key
//! check's class, or `NotCommitted`; it accepts keys only under the device
//! ID of those keys; and what it accepts is the one encoding of what it
//! returns.
#![no_main]

use frasil::advanced::public_keys::{DEVICE_KEYS_BYTES, DeviceId, decode, encode};
use frasil_crypto::device::{HybridKeys, IdentityKey, device_id};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::sizes::MLDSA65_PUBLIC;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A real device's keys, encoded.
fn device() -> &'static [u8] {
    static DEVICE: OnceLock<Vec<u8>> = OnceLock::new();
    DEVICE.get_or_init(|| {
        let keys = FixtureKeys::from_identity_seed(&[1; 32]).device_keys();
        encode(&keys).expect("a device has an X-Wing key")
    })
}

fn check(bytes: &[u8]) {
    // The device ID the bytes would give, when they split into three keys
    // that pass their checks.
    let own = (bytes.len() == DEVICE_KEYS_BYTES)
        .then(|| {
            let (ed, rest) = bytes.split_at(32);
            let (mldsa, xwing) = rest.split_at(MLDSA65_PUBLIC);
            let keys = HybridKeys::new(mldsa, Some(xwing)).ok()?;
            let ed = IdentityKey(ed.try_into().expect("32 bytes"));
            Some(device_id(&ed, keys.commitment()))
        })
        .flatten();
    for device in [DeviceId([0x5a; 32])].into_iter().chain(own) {
        match decode(bytes, &device) {
            Ok(keys) => {
                assert_eq!(Some(device), own);
                assert_eq!(keys.device_id(), device);
                assert_eq!(encode(&keys).as_deref(), Some(bytes));
            }
            Err(error) => {
                let class = error.class_name();
                assert!(
                    matches!(class, Some("Malformed" | "InvalidKey" | "NotCommitted")),
                    "{error:?}"
                );
                assert!(bytes.len() == DEVICE_KEYS_BYTES || class == Some("Malformed"));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    // Each three bytes of the input place a byte: a big-endian offset
    // into the encoding, then the byte.
    let mut placed = device().to_vec();
    for chunk in data.chunks_exact(3) {
        let at = usize::from(u16::from_be_bytes([chunk[0], chunk[1]])) % DEVICE_KEYS_BYTES;
        placed[at] = chunk[2];
    }
    check(&placed);
});
