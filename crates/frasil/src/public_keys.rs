//! A device's three public keys as bytes, for an application that carries
//! them to a device that grants it directly (roster.md, "A device's keys"):
//!
//! ```text
//! ed25519 (32) || ML-DSA-65 key (1,952) || X-Wing key (1,216)      3,200 bytes
//! ```
//!
//! The keys name no device. The application chooses the device to grant by
//! its device ID, learned in a way it trusts, and [`decode`] accepts the keys
//! only when they hash to that ID (crypto.md, "Keys by their hash"): keys
//! from any source then grant that device and no other.

use crate::error::{Error, Result};
use frasil_crypto::ErrorClass;
pub use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::device::{HybridKeys, IdentityKey};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};

/// The length of a device's encoded keys: 3,200 bytes.
pub const DEVICE_KEYS_BYTES: usize = 32 + MLDSA65_PUBLIC + XWING_PUBLIC;

/// A device's three keys as bytes, or `None` for a holder with no X-Wing
/// key, which no device is.
pub fn encode(keys: &DeviceKeys) -> Option<Vec<u8>> {
    let xwing = keys.keys.xwing()?;
    let mut out = Vec::with_capacity(DEVICE_KEYS_BYTES);
    out.extend_from_slice(keys.ed.as_bytes());
    out.extend_from_slice(keys.keys.mldsa());
    out.extend_from_slice(xwing);
    Some(out)
}

/// The keys of `bytes`, accepted only when they are the keys of `device`.
///
/// # Errors
///
/// In order: `Malformed` for any length but 3,200; the classes of each
/// key's check where it enters (crypto.md, "Where keys are checked"); then
/// `NotCommitted` when the three keys do not hash to `device`.
pub fn decode(bytes: &[u8], device: &DeviceId) -> Result<DeviceKeys> {
    if bytes.len() != DEVICE_KEYS_BYTES {
        return Err(Error::class(ErrorClass::Malformed));
    }
    let (ed, rest) = bytes.split_at(32);
    let (mldsa, xwing) = rest.split_at(MLDSA65_PUBLIC);
    ed25519_valid(ed).map_err(Error::class)?;
    let keys = DeviceKeys {
        ed: IdentityKey(ed.try_into().expect("32 bytes")),
        keys: HybridKeys::new(mldsa, Some(xwing)).map_err(Error::class)?,
    };
    keys.check(device).map_err(Error::class)?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_crypto::fixtures::FixtureKeys;

    #[test]
    fn keys_round_trip_and_are_refused_under_another_device_id() {
        let fixture = FixtureKeys::from_identity_seed(&[1; 32]);
        let signer = fixture.signer();
        let keys = DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        };
        let bytes = encode(&keys).expect("a device has an X-Wing key");
        assert_eq!(bytes.len(), 3_200);
        assert_eq!(decode(&bytes, signer.device_id()).unwrap(), keys);
        assert_eq!(
            decode(&bytes, &DeviceId([0; 32])).unwrap_err().class_name(),
            Some("NotCommitted")
        );
        assert_eq!(
            decode(&bytes[1..], signer.device_id())
                .unwrap_err()
                .class_name(),
            Some("Malformed")
        );
    }
}
