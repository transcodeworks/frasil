//! Recovery entries (identity.md, "Fetch keys and recovery entries").
//!
//! Each recovery entry is recorded in the personal space, in a unit of its
//! system stream of type `frasil:recovery-entry`:
//!
//! ```text
//! recovery entry = CBOR map {
//!   0: 1                  version
//!   1: space ID           bytes(32)
//!   2: key                bytes(32): the fetch key registered at the space's peers
//!   3: member             bytes(32): for the personal space only, the device ID of the
//!                         passkey member or recovery key whose fetch seed gives key
//!   4: seed               bytes(32): for another space only, the random fetch seed
//! }
//! ```
//!
//! An entry whose member is not an active passkey member or recovery key of
//! the merged list is ignored; that check needs the list.

use crate::IdentityClass;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::primitives::ed25519_public;
use zeroize::{Zeroize, Zeroizing};

/// The entry's version, key 0.
pub const VERSION: u64 = 1;

/// Key 0, `version`.
pub const KEY_VERSION: u64 = 0;
/// Key 1, the space ID.
pub const KEY_SPACE: u64 = 1;
/// Key 2, the fetch key.
pub const KEY_KEY: u64 = 2;
/// Key 3, the member, for the personal space only.
pub const KEY_MEMBER: u64 = 3;
/// Key 4, the seed, for another space only.
pub const KEY_SEED: u64 = 4;

/// What gives an entry's fetch key.
pub enum Holder {
    /// In the personal space: the device ID of the passkey member or
    /// recovery key whose fetch seed gives the key.
    Member(DeviceId),
    /// In another space: the random fetch seed, kept in the personal space.
    Seed(Zeroizing<[u8; 32]>),
}

impl core::fmt::Debug for Holder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Holder::Member(member) => write!(f, "Member({member})"),
            Holder::Seed(_) => f.write_str("Seed([redacted])"),
        }
    }
}

/// A recovery entry.
#[derive(Debug)]
pub struct RecoveryEntry {
    /// The space the entry lets a fetch key reach.
    pub space: [u8; 32],
    /// The fetch key registered at the space's peers.
    pub key: [u8; 32],
    /// What gives the key.
    pub holder: Holder,
}

impl RecoveryEntry {
    /// The entry of the personal space for a passkey member or recovery key
    /// `member` whose fetch key is `key`.
    pub fn for_member(personal_space: [u8; 32], key: [u8; 32], member: DeviceId) -> Self {
        Self {
            space: personal_space,
            key,
            holder: Holder::Member(member),
        }
    }

    /// The entry of another space for a fetch key from a random `seed`.
    pub fn for_seed(space: [u8; 32], seed: &[u8; 32]) -> Self {
        Self {
            space,
            key: ed25519_public(seed),
            holder: Holder::Seed(Zeroizing::new(*seed)),
        }
    }

    /// The entry's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(KEY_VERSION, Value::Unsigned(VERSION));
        map.insert(KEY_SPACE, Value::from(self.space));
        map.insert(KEY_KEY, Value::from(self.key));
        match &self.holder {
            Holder::Member(member) => map.insert(KEY_MEMBER, Value::from(member.0)),
            Holder::Seed(seed) => map.insert(KEY_SEED, Value::from(**seed)),
        };
        Value::Map(map).encode()
    }

    /// Reads an entry, checking in order: it is a deterministic CBOR map;
    /// key 0 is 1; it has keys 0 to 2 and exactly one of 3, when key 1 is
    /// `personal_space`, or 4 otherwise, each with its length; `key` passes
    /// `ed25519_valid`; with key 4, `key` is the Ed25519 key of `seed`.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `Malformed`, `InvalidKey` and
    /// `Malformed`, in that order.
    pub fn read(data: &[u8], personal_space: &[u8; 32]) -> Result<Self, IdentityClass> {
        let mut value = cbor::decode(data)?;
        let read = read_map(value.as_map()?, personal_space);
        if let Value::Map(map) = &mut value
            && let Some(Value::Bytes(seed)) = map.get_mut(&KEY_SEED)
        {
            seed.zeroize();
        }
        read
    }
}

fn read_map(map: &Map, personal_space: &[u8; 32]) -> Result<RecoveryEntry, IdentityClass> {
    let malformed = IdentityClass::Shared(ErrorClass::Malformed);
    if map.get(&KEY_VERSION) != Some(&Value::Unsigned(VERSION)) {
        return Err(IdentityClass::Shared(ErrorClass::UnsupportedVersion));
    }
    let personal = map.get(&KEY_SPACE) == Some(&Value::from(*personal_space));
    let own = if personal { KEY_MEMBER } else { KEY_SEED };
    let keys = [KEY_VERSION, KEY_SPACE, KEY_KEY, own];
    if map.len() != keys.len() || !keys.iter().all(|key| map.contains_key(key)) {
        return Err(malformed);
    }
    let space = map[&KEY_SPACE].as_byte_array::<32>()?;
    let key = map[&KEY_KEY].as_byte_array::<32>()?;
    let own_value = Zeroizing::new(map[&own].as_byte_array::<32>()?);
    ed25519_valid(&key)?;
    let holder = if personal {
        Holder::Member(DeviceId(*own_value))
    } else {
        if ed25519_public(&own_value) != key {
            return Err(malformed);
        }
        Holder::Seed(own_value)
    };
    Ok(RecoveryEntry { space, key, holder })
}
