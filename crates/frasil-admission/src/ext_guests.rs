//! Guests in admission (ext-guests.md, feature `ext-guests`): offer key 13,
//! the guest's offer, and the leave request.
//!
//! The offer of an admission by code carries the guest preset's `session`
//! and `expires_at` (offer keys 7 and 13), and admission.md's check that the
//! grant matches the offer covers both ("The guest preset").
//!
//! ```text
//! request = CBOR {1: 1, 2: space ID (32), 3: member [type 0 or 1, ID],
//!                 4: the member's grants in force (1 to 64 event IDs, strictly ascending),
//!                 5: request ID (16 random bytes), 6: the signing device's device ID (32)}
//! signed  = CBOR {1: request (bytes),
//!                 2: the device's scheme-2 signature over
//!                    "frasil/leave-request/v1" || field(request) (3,373)}
//! ```
//!
//! An administering device checks a leave request, in order ("A leave
//! request"):
//!
//! ```text
//! 1. Both maps read, with the types, lengths and order of
//!    section 2.2; key 1 is 1.                                    else Malformed / UnsupportedVersion
//! 2. It holds the signing device's keys, which hash to its
//!    device ID: from its device grant, the person's list, or
//!    any other source (crypto.md, "A device's keys").            else NoHybridKey
//! 3. The signature verifies.                                     else BadSignature
//! 4. The space ID is this space's.                               else WrongSpace
//! 5. The member is in the merged roster.                         else NoSuchMember
//! 6. The signing device is the member, or a device that
//!    the person's list vouches for.                              else NotTheMember
//! 7. The named grants are exactly the member's grants in force.  else Stale
//! 8. The member is not a device member at administer.            else MemberAdministers
//! 9. After its rank delay over the space's administering
//!    devices, with SHA-256 of the signed request as the
//!    trigger, unless a removal of the member has arrived:
//!    remove the member in a roster event that rotates.
//! ```
//!
//! Any other outcome sends nothing. Steps 4 to 8 and the rank delay are
//! `frasil_space::ext_guests`'; the mailbox item is
//! `frasil_transport::ext_guests`'.

use crate::lookup::{read_signed, record_verifies, sign_record};
use crate::params::REQUEST_BYTES;
use crate::{AdmissionClass, Offer, array_at, malformed, read_map};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_crypto::labels::LEAVE_REQUEST;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::Signer;
use frasil_events::EventId;
use frasil_space::change::key;
use frasil_space::ext_guests::{GuestClass, LeaveClaim, Preset, check_leave, rank_delay};
use frasil_space::{MemberRef, MemberType, Space};

/// The leave request's format version, key 1.
pub const LEAVE_VERSION: u64 = 1;

/// The most grants a leave request names.
pub const MAX_GRANTS: usize = 64;

/// Offer key 13, a session's expiry: an unsigned, only beside `session`
/// ("The guest preset").
///
/// # Errors
///
/// `Malformed` for key 13 without a session, or not an unsigned.
pub(crate) fn read_offer_expiry(map: &Map, session: bool) -> Result<Option<u64>, AdmissionClass> {
    let Some(value) = map.get(&key::EXPIRES_AT) else {
        return Ok(None);
    };
    if !session {
        return Err(malformed());
    }
    Ok(Some(value.as_unsigned()?))
}

/// The offer of a guest's admission by code: the preset's level,
/// capabilities, label, history, `session` and `expires_at`.
pub fn guest_offer(preset: &Preset) -> Offer {
    let mut offer = Offer::new(preset.level, preset.history);
    offer.capabilities = preset.capabilities();
    offer.label = preset.label.clone();
    offer.session = Some(preset.session);
    offer.expires_at = preset.expires_at;
    offer
}

/// A leave request read without its signature ([`LeaveRequest::read`]).
/// It gives only what a caller uses before it verifies the request: the
/// space, to route it to the roster whose records hold the signer's keys,
/// and the signing device. The request itself comes from
/// [`LeaveRequest::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnverifiedLeaveRequest(LeaveRequest);

impl UnverifiedLeaveRequest {
    /// Key 2: the space it names.
    pub fn space(&self) -> &[u8; 32] {
        &self.0.space
    }

    /// Key 6: the signing device's device ID, whose keys verify it.
    pub fn device(&self) -> &DeviceId {
        &self.0.device
    }

    /// The map's bytes again: the one encoding of what was read.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

/// A leave request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeaveRequest {
    /// Key 2: the space.
    pub space: [u8; 32],
    /// Key 3: the leaver's own device member, or for a person that leaves,
    /// the person.
    pub member: MemberRef,
    /// Key 4: the member's grants in force, 1 to 64, strictly ascending.
    pub grants: Vec<EventId>,
    /// Key 5: the request ID.
    pub request: [u8; REQUEST_BYTES],
    /// Key 6: the signing device's device ID.
    pub device: DeviceId,
}

impl LeaveRequest {
    /// The request's bytes. The grants are written ascending, each once.
    pub fn encode(&self) -> Vec<u8> {
        let mut grants = self.grants.clone();
        grants.sort();
        grants.dedup();
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(LEAVE_VERSION));
        map.insert(2, Value::from(self.space));
        map.insert(3, self.member.to_value());
        map.insert(
            4,
            Value::Array(grants.iter().map(|g| Value::from(g.0)).collect()),
        );
        map.insert(5, Value::from(self.request));
        map.insert(6, Value::from(self.device.0));
        Value::Map(map).encode()
    }

    /// The signed request, by the signing device.
    pub fn sign(&self, signer: &Signer) -> Vec<u8> {
        sign_record(LEAVE_REQUEST, &self.encode(), signer)
    }

    /// Reads a request's map, step 1 for the request, without its
    /// signature: what it gives is only what a caller may use before it
    /// verifies the request, to route it and find the signer's keys.
    ///
    /// # Errors
    ///
    /// `Malformed`, then `UnsupportedVersion`, then `Malformed`.
    pub fn read(data: &[u8]) -> Result<UnverifiedLeaveRequest, AdmissionClass> {
        Self::decode(data).map(UnverifiedLeaveRequest)
    }

    /// Step 1 for the request's map.
    fn decode(data: &[u8]) -> Result<Self, AdmissionClass> {
        let map = read_map(data, &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6])?;
        if map[&1] != Value::Unsigned(LEAVE_VERSION) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let space = array_at(&map, 2)?;
        let member = MemberRef::read(&map[&3]).map_err(|_| malformed())?;
        if !matches!(member.kind, MemberType::Device | MemberType::Person) {
            return Err(malformed());
        }
        let items = map[&4].as_array()?;
        if items.is_empty() || items.len() > MAX_GRANTS {
            return Err(malformed());
        }
        let mut grants: Vec<EventId> = Vec::with_capacity(items.len());
        for item in items {
            let id = EventId(item.as_byte_array::<32>()?);
            if grants.last().is_some_and(|last| *last >= id) {
                return Err(malformed());
            }
            grants.push(id);
        }
        Ok(Self {
            space,
            member,
            grants,
            request: array_at(&map, 5)?,
            device: DeviceId(array_at(&map, 6)?),
        })
    }

    /// Steps 1 to 3 of a signed request. `keys` gives the signing device's
    /// keys by its device ID, from its device grant, the person's list or
    /// any other source; only keys that hash to the device ID are used
    /// (crypto.md, "Keys by their hash").
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `NoHybridKey`, `BadSignature`.
    /// `NoHybridKey` waits for keys from any source.
    pub fn verify(signed: &[u8], keys: &impl KeySource) -> Result<Self, AdmissionClass> {
        let (record, signature) = read_signed(signed)?;
        let request = Self::decode(&record)?;
        let held = keys
            .device_keys(&request.device)
            .filter(|held| held.check(&request.device).is_ok())
            .ok_or(ErrorClass::NoHybridKey)?;
        if !record_verifies(LEAVE_REQUEST, &record, &signature, &held.ed, &held.keys) {
            return Err(ErrorClass::BadSignature.into());
        }
        Ok(request)
    }

    /// Steps 4 to 8, against the merged roster. `vouches(person, device)`
    /// says whether the person's list vouches for the device.
    ///
    /// # Errors
    ///
    /// `WrongSpace`, `NoSuchMember`, `NotTheMember`, `Stale`,
    /// `MemberAdministers`.
    pub fn check(
        &self,
        space: &Space<'_>,
        vouches: impl Fn(&[u8; 32], &[u8; 32]) -> bool,
    ) -> Result<(), GuestClass> {
        let claim = LeaveClaim {
            space: &self.space,
            member: &self.member,
            grants: &self.grants,
            device: &self.device.0,
        };
        check_leave(space, &claim, vouches)
    }
}

/// The trigger of a leave request's rank delay: SHA-256 of the signed
/// request.
pub fn leave_trigger(signed: &[u8]) -> [u8; 32] {
    sha256(&[signed])
}

/// What an administering device does with a leave request that passed
/// steps 1 to 8: after `delay` seconds, its rank's, it removes the member
/// in a roster event that rotates, unless a removal has arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaveDecision {
    /// Its rank over the space's administering devices, 0 first.
    pub rank: u64,
    /// Its delay, in seconds.
    pub delay: u64,
}

/// "A leave request", steps 1 to 9, at the administering device `me`.
/// `keys` and `vouches` are as [`LeaveRequest::verify`] and
/// [`LeaveRequest::check`] take them; `administering` is the space's
/// administering devices in this device's view.
///
/// Returns `None` when `me` does not administer.
///
/// # Errors
///
/// The first step that fails, by its class.
pub fn on_leave(
    signed: &[u8],
    space: &Space<'_>,
    me: &DeviceId,
    administering: &[DeviceId],
    keys: &impl KeySource,
    vouches: impl Fn(&[u8; 32], &[u8; 32]) -> bool,
    rotation_step: u64,
) -> Result<Option<LeaveDecision>, GuestClass> {
    let request = LeaveRequest::verify(signed, keys).map_err(|class| {
        GuestClass::from_name(class.name()).unwrap_or(ErrorClass::Malformed.into())
    })?;
    request.check(space, vouches)?;
    let trigger = leave_trigger(signed);
    Ok(rank_delay(
        &space.log().id(),
        &trigger,
        &administering.iter().map(|id| id.0).collect::<Vec<_>>(),
        &me.0,
        rotation_step,
    )
    .map(|(rank, delay)| LeaveDecision { rank, delay }))
}
