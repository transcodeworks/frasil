//! Holds (ext-libraries.md, 2.7 Object keys and access keys, 2.8
//! HoldObject, and 3.7 Registering a hold).
//!
//! ```text
//! object key  = HMAC(object_seal_key(S), object ID)                  units.md
//! access_seed = HKDF(none, object key, "frasil/object-access/v1")    32 bytes
//! access key  = the Ed25519 public key of access_seed
//!
//! HoldObject = {0: 31, 1: request, 2: space (32), 3: source (32), 4: locator (64),
//!               5: access (32), 6: proof (64)}
//! held       = field(binding) || field(space) || field(source) || field(locator)
//!              || field(access)
//! proof      = Ed25519-Sign(access_seed, "frasil/object-hold/v1" || held)
//! ```
//!
//! A space whose reference entry names an object another space of its
//! library stores registers a hold, so that the peer keeps the object for
//! it and serves it to its readers. The proof shows the object key without
//! revealing it. [`check_hold`] runs the peer's checks in order, reading
//! the connection's rights and the peer's holds through [`PeerHolds`].

use frasil_base::cbor::{self, Malformed, Map};
use frasil_base::notation::field;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels::{OBJECT_ACCESS, OBJECT_HOLD};
use frasil_crypto::primitives::{ed25519_public, ed25519_sign, hkdf};
use frasil_crypto::schemes::ed25519_verify_strict;
use zeroize::Zeroizing;

use crate::HOLD_OBJECT;
use crate::errors::LibraryClass;

/// The bytes of a locator: the object ID, then the digest.
pub const LOCATOR_BYTES: usize = 64;

/// `access_seed = HKDF(none, object key, "frasil/object-access/v1")`.
pub fn access_seed(object_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, object_key, OBJECT_ACCESS)
}

/// The access key: the Ed25519 public key of the object's access seed.
pub fn access_key(object_key: &[u8; 32]) -> [u8; 32] {
    ed25519_public(&access_seed(object_key))
}

/// `held = field(binding) || field(space) || field(source) ||
/// field(locator) || field(access)`.
pub fn held(
    binding: &[u8; 32],
    space: &[u8; 32],
    source: &[u8; 32],
    locator: &[u8; LOCATOR_BYTES],
    access: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 * 4 + 32 * 4 + LOCATOR_BYTES);
    for part in [&binding[..], space, source, locator, access] {
        out.extend_from_slice(&field(part));
    }
    out
}

/// What a hold's proof signs: `"frasil/object-hold/v1" || held`.
pub fn signed_message(
    binding: &[u8; 32],
    space: &[u8; 32],
    source: &[u8; 32],
    locator: &[u8; LOCATOR_BYTES],
    access: &[u8; 32],
) -> Vec<u8> {
    let mut message = OBJECT_HOLD.to_vec();
    message.extend_from_slice(&held(binding, space, source, locator, access));
    message
}

/// A `HoldObject` message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HoldObject {
    /// Key 1: numbers it among the device's requests on the connection.
    pub request: u64,
    /// Key 2: the holding space, whose reference entry names the object.
    pub space: [u8; 32],
    /// Key 3: the space that stores the object.
    pub source: [u8; 32],
    /// Key 4: the object's locator.
    pub locator: [u8; LOCATOR_BYTES],
    /// Key 5: the object's access key.
    pub access: [u8; 32],
    /// Key 6: the proof over `held`.
    pub proof: [u8; 64],
}

impl HoldObject {
    /// A hold of the object whose key this is, proved over the connection's
    /// `binding`.
    pub fn prove(
        request: u64,
        binding: &[u8; 32],
        space: [u8; 32],
        source: [u8; 32],
        locator: [u8; LOCATOR_BYTES],
        object_key: &[u8; 32],
    ) -> Self {
        let seed = access_seed(object_key);
        let access = ed25519_public(&seed);
        let proof = ed25519_sign(
            &seed,
            &signed_message(binding, &space, &source, &locator, &access),
        );
        Self {
            request,
            space,
            source,
            locator,
            access,
            proof,
        }
    }

    /// The message's deterministic CBOR map.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        cbor::map_head(&mut out, 7);
        cbor::unsigned(&mut out, 0);
        cbor::unsigned(&mut out, HOLD_OBJECT);
        cbor::unsigned(&mut out, 1);
        cbor::unsigned(&mut out, self.request);
        cbor::unsigned(&mut out, 2);
        cbor::bytes(&mut out, &self.space);
        cbor::unsigned(&mut out, 3);
        cbor::bytes(&mut out, &self.source);
        cbor::unsigned(&mut out, 4);
        cbor::bytes(&mut out, &self.locator);
        cbor::unsigned(&mut out, 5);
        cbor::bytes(&mut out, &self.access);
        cbor::unsigned(&mut out, 6);
        cbor::bytes(&mut out, &self.proof);
        out
    }

    /// Section 3.7, step 1, on the message's map as transport's framing
    /// read it: exactly keys 0 to 6; key 0 is 31; `request` unsigned;
    /// `space` and `source` of 32 bytes and not equal; `locator` of 64;
    /// `access` of 32; `proof` of 64.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map) -> Result<Self, LibraryClass> {
        read_map(map).map_err(LibraryClass::from)
    }

    /// Reads the message from its bytes: one deterministic CBOR map, by
    /// [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, LibraryClass> {
        let value = cbor::decode(bytes).map_err(LibraryClass::from)?;
        Self::read(value.as_map().map_err(LibraryClass::from)?)
    }

    /// Section 3.7, step 3: the access key passes `ed25519_valid` and the
    /// proof verifies strictly under it over `held`.
    pub fn proof_verifies(&self, binding: &[u8; 32]) -> bool {
        ed25519_valid(&self.access).is_ok()
            && ed25519_verify_strict(
                &self.access,
                &signed_message(
                    binding,
                    &self.space,
                    &self.source,
                    &self.locator,
                    &self.access,
                ),
                &self.proof,
            )
    }
}

fn read_map(map: &Map) -> Result<HoldObject, Malformed> {
    if map.len() != 7 || !(0..=6).all(|key| map.contains_key(&key)) {
        return Err(Malformed);
    }
    if map[&0].as_unsigned()? != HOLD_OBJECT {
        return Err(Malformed);
    }
    let hold = HoldObject {
        request: map[&1].as_unsigned()?,
        space: map[&2].as_byte_array::<32>()?,
        source: map[&3].as_byte_array::<32>()?,
        locator: map[&4].as_byte_array::<LOCATOR_BYTES>()?,
        access: map[&5].as_byte_array::<32>()?,
        proof: map[&6].as_byte_array::<64>()?,
    };
    if hold.space == hold.source {
        return Err(Malformed);
    }
    Ok(hold)
}

/// What [`check_hold`] reads of the connection and the peer.
pub trait PeerHolds {
    /// Whether the connection holds the store right for a space.
    fn store_right(&self, space: &[u8; 32]) -> bool;
    /// Whether the connection holds the fetch right for a space.
    fn fetch_right(&self, space: &[u8; 32]) -> bool;
    /// Whether a hold of the locator at this peer was registered with this
    /// access key.
    fn vouches(&self, locator: &[u8; LOCATOR_BYTES], access: &[u8; 32]) -> bool;
    /// Whether the peer hosts the source and holds the object under the
    /// locator whole.
    fn holds_object(&self, source: &[u8; 32], locator: &[u8; LOCATOR_BYTES]) -> bool;
    /// Whether the two spaces are attached to the same library.
    fn same_library(&self, space: &[u8; 32], source: &[u8; 32]) -> bool;
}

/// Section 3.7, steps 2 to 6, on a `HoldObject` that step 1 read.
///
/// ```text
/// 2. The connection holds the store right for space.                 else NotAuthorized
/// 3. access passes ed25519_valid, and proof verifies strictly under
///    it over held.                                                    else HoldRefused
/// 4. The connection holds the fetch right for source, or a hold of
///    locator at this peer was registered with access.                 else HoldRefused
/// 5. The peer hosts source and holds the object under locator
///    whole.                                                           else UnknownObject
/// 6. space and source are attached to the same library.             else OtherLibrary
/// ```
///
/// # Errors
///
/// The class of the first step that fails.
pub fn check_hold(
    hold: &HoldObject,
    binding: &[u8; 32],
    peer: &impl PeerHolds,
) -> Result<(), LibraryClass> {
    if !peer.store_right(&hold.space) {
        return Err(LibraryClass::NotAuthorized);
    }
    if !hold.proof_verifies(binding) {
        return Err(LibraryClass::HoldRefused);
    }
    if !peer.fetch_right(&hold.source) && !peer.vouches(&hold.locator, &hold.access) {
        return Err(LibraryClass::HoldRefused);
    }
    if !peer.holds_object(&hold.source, &hold.locator) {
        return Err(LibraryClass::UnknownObject);
    }
    if !peer.same_library(&hold.space, &hold.source) {
        return Err(LibraryClass::OtherLibrary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::cbor::Value;

    fn hold() -> HoldObject {
        HoldObject::prove(3, &[1; 32], [2; 32], [3; 32], [4; 64], &[5; 32])
    }

    #[test]
    fn a_message_reads_back_and_its_proof_verifies() {
        let message = hold();
        let bytes = message.encode();
        assert_eq!(HoldObject::decode(&bytes), Ok(message.clone()));
        assert_eq!(cbor::decode(&bytes).unwrap().encode(), bytes);
        assert!(message.proof_verifies(&[1; 32]));
        assert!(!message.proof_verifies(&[9; 32]), "another connection");
        assert_eq!(message.access, access_key(&[5; 32]));
    }

    #[test]
    fn other_keys_and_values_are_malformed() {
        let malformed = Err(LibraryClass::from(Malformed));
        let map = || {
            cbor::decode(&hold().encode())
                .unwrap()
                .as_map()
                .unwrap()
                .clone()
        };
        let mut extra = map();
        extra.insert(7, Value::Unsigned(0));
        assert_eq!(HoldObject::read(&extra), malformed);
        let mut kind = map();
        kind.insert(0, Value::Unsigned(21));
        assert_eq!(HoldObject::read(&kind), malformed);
        let mut same = map();
        same.insert(3, Value::from(&[2u8; 32][..]));
        assert_eq!(HoldObject::read(&same), malformed);
        let mut short = map();
        short.insert(4, Value::from(&[4u8; 63][..]));
        assert_eq!(HoldObject::read(&short), malformed);
    }
}
