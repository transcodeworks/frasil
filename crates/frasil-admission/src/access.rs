//! Access requests (admission.md, "The access request", "Access requests").
//!
//! ```text
//! request = CBOR {1: 1, 2: target space ID (32), 3: carrier space ID (32),
//!                 4: requester member [type 0 or 1, ID], 5: requesting device's device ID (32),
//!                 6: level asked for (0 read, 1 write), 7: note (text, 0 to 256 bytes; optional),
//!                 8: request ID (16)}
//! signed  = CBOR {1: request (bytes),
//!                 2: the device's scheme-2 signature over "frasil/access-request/v1" || field(request)}
//! ```
//!
//! An administering device of the target checks, in order: both maps read
//! (else `Malformed`); key 1 is 1 (else `UnsupportedVersion`); the fields
//! have their types and lengths, the target is not the carrier, and the
//! level is `read` or `write` (else `Malformed`); it holds the requesting
//! device's keys, which hash to its device ID, from the carrier space's
//! records or any other source (else `NoHybridKey`); the signature
//! verifies (else `BadSignature`); the device reaches the carrier
//! through the named member (else it ignores the request). That last check
//! is the caller's, over the carrier's roster.
//!
//! Answering is granting, `via` = `none`; declining sends nothing.

use crate::lookup::{read_signed, record_verifies, sign_record};
use crate::params::{REQUEST_BYTES, VERSION};
use crate::{AdmissionClass, array_at, display_ok, malformed, number_at, read_map};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_crypto::labels::ACCESS_REQUEST;
use frasil_crypto::schemes::Signer;
use frasil_space::{Level, MemberRef, MemberType};

/// An access request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessRequest {
    /// The space the requester cannot open.
    pub target: [u8; 32],
    /// The space it asks in, which it and the target's administrators both
    /// read.
    pub carrier: [u8; 32],
    /// The requester member: a device or a person.
    pub member: MemberRef,
    /// The requesting device's device ID.
    pub device: DeviceId,
    /// The level asked for: `read` or `write`.
    pub level: Level,
    /// A note, 0 to 256 bytes.
    pub note: Option<String>,
    /// The request ID.
    pub request: [u8; REQUEST_BYTES],
}

impl AccessRequest {
    /// The request's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION.into()));
        map.insert(2, Value::from(self.target));
        map.insert(3, Value::from(self.carrier));
        map.insert(4, self.member.to_value());
        map.insert(5, Value::from(self.device.0));
        map.insert(6, Value::Unsigned(self.level.code()));
        if let Some(note) = &self.note {
            map.insert(7, Value::from(note.as_str()));
        }
        map.insert(8, Value::from(self.request));
        Value::Map(map).encode()
    }

    /// The signed request, by the requesting device.
    pub fn sign(&self, signer: &Signer) -> Vec<u8> {
        sign_record(ACCESS_REQUEST, &self.encode(), signer)
    }

    /// Reads a request's map, the first three checks, without its
    /// signature: what it gives is only what a caller may use to find the
    /// keys that verify it.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `Malformed`.
    pub fn read(data: &[u8]) -> Result<UnverifiedAccessRequest, AdmissionClass> {
        Self::decode(data).map(UnverifiedAccessRequest)
    }

    /// The first three checks, on the request's map.
    fn decode(data: &[u8]) -> Result<Self, AdmissionClass> {
        let map = read_map(data, &[1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3, 4, 5, 6, 8])?;
        if map[&1] != Value::Unsigned(VERSION.into()) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let target = array_at(&map, 2)?;
        let carrier = array_at(&map, 3)?;
        if target == carrier {
            return Err(malformed());
        }
        let member = MemberRef::read(&map[&4]).map_err(|_| malformed())?;
        if !matches!(member.kind, MemberType::Device | MemberType::Person) {
            return Err(malformed());
        }
        let level = match Level::from_code(number_at(&map, 6)?) {
            Some(level @ (Level::Read | Level::Write)) => level,
            _ => return Err(malformed()),
        };
        let note = match map.get(&7) {
            Some(value) => {
                let text = value.as_text()?;
                if !display_ok(text) {
                    return Err(malformed());
                }
                Some(text.to_owned())
            }
            None => None,
        };
        Ok(Self {
            target,
            carrier,
            member,
            device: DeviceId(array_at(&map, 5)?),
            level,
            note,
            request: array_at(&map, 8)?,
        })
    }

    /// An administering device's checks of a signed request, in order.
    /// `keys` gives the requesting device's keys by its device ID, from the
    /// carrier space's records or any other source; only keys that hash to
    /// the device ID are used (crypto.md, "Keys by their hash").
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `Malformed`, `NoHybridKey`,
    /// `BadSignature`. `NoHybridKey` waits for keys from any source.
    pub fn verify(signed: &[u8], keys: &impl KeySource) -> Result<Self, AdmissionClass> {
        let (record, signature) = read_signed(signed)?;
        let request = Self::decode(&record)?;
        let held = keys
            .device_keys(&request.device)
            .filter(|held| held.check(&request.device).is_ok())
            .ok_or(ErrorClass::NoHybridKey)?;
        if !record_verifies(ACCESS_REQUEST, &record, &signature, &held.ed, &held.keys) {
            return Err(ErrorClass::BadSignature.into());
        }
        Ok(request)
    }
}

/// An access request read without its signature ([`AccessRequest::read`]).
/// It gives only what finds the keys that verify it: the requesting
/// device, and the carrier space whose records may hold its keys. The
/// request itself comes from [`AccessRequest::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnverifiedAccessRequest(AccessRequest);

impl UnverifiedAccessRequest {
    /// The requesting device's device ID, whose keys verify the request.
    pub fn device(&self) -> &DeviceId {
        &self.0.device
    }

    /// The carrier space, whose records may hold the device's keys.
    pub fn carrier(&self) -> &[u8; 32] {
        &self.0.carrier
    }
}
