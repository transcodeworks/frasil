//! Signed welcome requests (admission.md, 2.12 and 3.14).
use crate::lookup::{read_signed, record_verifies, sign_record};
use crate::{AdmissionClass, array_at, malformed, read_map};
use frasil_base::{
    ErrorClass,
    cbor::{Map, Value},
};
use frasil_crypto::{
    device::{DeviceId, KeySource},
    schemes::Signer,
};

const LABEL: &[u8] = frasil_crypto::labels::WELCOME_REQUEST;

/// A member's request to recover access without granting any rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeRequest {
    /// The space to recover.
    pub space: [u8; 32],
    /// The requesting device.
    pub device: DeviceId,
    /// The request's deduplication identifier.
    pub request: [u8; 16],
}
impl WelcomeRequest {
    /// Encodes the version-1 request with reason 1 (own erasure late).
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(1));
        map.insert(2, self.space.into());
        map.insert(3, self.device.0.into());
        map.insert(4, self.request.into());
        map.insert(5, Value::Unsigned(1));
        Value::Map(map).encode()
    }
    /// Signs with the requesting device's scheme-2 keys.
    pub fn sign(&self, signer: &Signer) -> Vec<u8> {
        sign_record(LABEL, &self.encode(), signer)
    }
    /// Reads both maps, without trusting any field until verification.
    ///
    /// # Errors
    /// `Malformed` or `UnsupportedVersion`.
    pub fn read(signed: &[u8]) -> Result<Self, AdmissionClass> {
        let (record, _) = read_signed(signed)?;
        let map = read_map(&record, &[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5])?;
        if map[&1] != Value::Unsigned(1) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map[&5] != Value::Unsigned(1) {
            return Err(malformed());
        }
        Ok(Self {
            space: array_at(&map, 2)?,
            device: DeviceId(array_at(&map, 3)?),
            request: array_at(&map, 4)?,
        })
    }
    /// Verifies against keys bound to the device ID; membership is the caller's check.
    ///
    /// # Errors
    /// The map's errors, `NoHybridKey` or `BadSignature`.
    pub fn verify(signed: &[u8], keys: &impl KeySource) -> Result<Self, AdmissionClass> {
        let request = Self::read(signed)?;
        let (record, signature) = read_signed(signed)?;
        let held = keys
            .device_keys(&request.device)
            .filter(|held| held.check(&request.device).is_ok())
            .ok_or(ErrorClass::NoHybridKey)?;
        if !record_verifies(LABEL, &record, &signature, &held.ed, &held.keys) {
            return Err(ErrorClass::BadSignature.into());
        }
        Ok(request)
    }
}
