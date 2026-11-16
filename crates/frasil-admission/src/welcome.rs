//! The welcome (admission.md, "The welcome", "Welcomes").
//!
//! ```text
//! welcome = CBOR {1: 1, 2: space ID (32), 3: event ID (32), 4: key name (bytes),
//!                 5: grant key name (bytes; empty if none), 6: bundle wrap (1,236),
//!                 7: approver (32), 8: [peer hints: 0 to 8 texts of 1 to 512 bytes],
//!                 9: snapshot locator (64; optional)}
//!
//! sealed welcome = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
//! (enc, ciphertext) = HPKE-Seal(device's X-Wing key,
//!                               info = "frasil/welcome/v1" || u16be(0x647a) || device ID (32),
//!                               aad = "", welcome)
//! ```
//!
//! Nothing in a welcome is trusted: the event and the roster decide.

use crate::params::VERSION;
use crate::{
    AdmissionClass, array_at, bytes_at, hints_value, malformed, number_at, read_hints, read_map,
};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::sizes::XWING_SEED;
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, WrapUse, open_wrap, seal_wrap_with};
use frasil_events::EventId;
use frasil_keys::limits::WRAP_BYTES;

/// A welcome.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Welcome {
    /// The space ID.
    pub space: [u8; 32],
    /// The space event whose delivery holds the wrap: the admitting event or
    /// a later delivery.
    pub event: EventId,
    /// That delivery's key name.
    pub key_name: Vec<u8>,
    /// That delivery's grant key name; empty if none.
    pub grant_name: Vec<u8>,
    /// A copy of the newcomer's bundle wrap.
    pub wrap: Vec<u8>,
    /// The device ID of the device that signed the admission.
    pub approver: DeviceId,
    /// Where the space's log can be fetched.
    pub peers: Vec<String>,
    /// For an admission "from now on", the locator of the newcomer's
    /// snapshot at those peers ("The newcomer's snapshot").
    pub snapshot: Option<[u8; 64]>,
}

impl Welcome {
    /// The welcome's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION.into()));
        map.insert(2, Value::from(self.space));
        map.insert(3, Value::from(self.event.0));
        map.insert(4, Value::from(self.key_name.clone()));
        map.insert(5, Value::from(self.grant_name.clone()));
        map.insert(6, Value::from(self.wrap.clone()));
        map.insert(7, Value::from(self.approver.0));
        map.insert(8, hints_value(&self.peers));
        if let Some(snapshot) = &self.snapshot {
            map.insert(9, Value::from(&snapshot[..]));
        }
        Value::Map(map).encode()
    }

    /// Reads a welcome's map.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything but the table's keys, version 1, a nonempty
    /// key name, a 1,236-byte wrap and a 64-byte snapshot locator.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let required = [1, 2, 3, 4, 5, 6, 7, 8];
        let map = read_map(data, &[1, 2, 3, 4, 5, 6, 7, 8, 9], &required)?;
        if number_at(&map, 1)? != u64::from(VERSION) {
            return Err(malformed());
        }
        let key_name = bytes_at(&map, 4)?;
        let wrap = bytes_at(&map, 6)?;
        if key_name.is_empty() || wrap.len() != WRAP_BYTES {
            return Err(malformed());
        }
        Ok(Self {
            space: array_at(&map, 2)?,
            event: EventId(array_at(&map, 3)?),
            key_name: key_name.to_vec(),
            grant_name: bytes_at(&map, 5)?.to_vec(),
            wrap: wrap.to_vec(),
            approver: DeviceId(array_at(&map, 7)?),
            peers: read_hints(&map[&8])?,
            snapshot: match map.get(&9) {
                Some(_) => Some(array_at(&map, 9)?),
                None => None,
            },
        })
    }

    /// Seals the welcome to the X-Wing key a device's device ID commits to,
    /// the info naming that device ID, outside an exchange, with X-Wing's 64
    /// bytes of encapsulation randomness given.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for keys with no X-Wing key, or a key X-Wing refuses.
    pub fn seal_with(
        &self,
        recipient: &DeviceKeys,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Vec<u8>, AdmissionClass> {
        let xwing = recipient.keys.xwing().ok_or(ErrorClass::InvalidKey)?;
        Ok(seal_wrap_with(
            xwing,
            &welcome_info(&recipient.device_id()),
            &self.encode(),
            encapsulation_randomness,
        )?)
    }

    /// Opens a sealed welcome by crypto.md's "Opening a wrap", with step 5
    /// requiring at least 1,139 bytes and the info naming the device's own
    /// device ID; then the map reads.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion` for its layout, `Decrypt`, then
    /// [`Welcome::read`]'s.
    pub fn open(
        sealed: &[u8],
        device: &DeviceId,
        xwing_seed: &[u8; XWING_SEED],
    ) -> Result<Self, AdmissionClass> {
        let plaintext = open_wrap(
            sealed,
            xwing_seed,
            &welcome_info(device),
            WrapUse::Welcome.length(),
        )?;
        Self::read(&plaintext)
    }
}

/// A sealed welcome's `info`: the label, the suite, then the device's
/// device ID.
pub fn welcome_info(device: &DeviceId) -> Vec<u8> {
    WrapUse::Welcome.info(&device.0)
}
