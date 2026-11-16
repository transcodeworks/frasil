//! The merge statement (peers.md, "The merge statement").
//!
//! ```text
//! merge = CBOR map
//!   1  version     1
//!   2  space       bytes(32)
//!   3  state       bytes: encode_set(S), 2 to 64 rotations
//!   4  read        bytes(32): the public half of read_seed(S)
//!   5  upload      bytes(32): the public half of upload_seed(S)
//!   6  signatures  array of bytes(64): one per rotation of S, in the state's order
//!
//! message     = "frasil/storage-merge/v1" || field(space) || field(encode_set(S))
//!               || read || upload
//! signature_i = Ed25519-Sign(upload_seed({R_i}), message)
//! ```
//!
//! The checks against the peer's entries (peers.md, "Merge statements",
//! steps 3 to 5) are [`Entries::merge`](crate::entries::Entries::merge).

use crate::PeersClass;
use crate::limits::{MAX_MERGE_ROTATIONS, MIN_MERGE_ROTATIONS};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::notation::push_field;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels::STORAGE_MERGE;
use frasil_crypto::primitives::ed25519_sign;
use frasil_events::EventId;
use frasil_keys::RotationSet;

/// The statement's version, key 1.
pub const VERSION: u64 = 1;

const KEY_VERSION: u64 = 1;
const KEY_SPACE: u64 = 2;
const KEY_STATE: u64 = 3;
const KEY_READ: u64 = 4;
const KEY_UPLOAD: u64 = 5;
const KEY_SIGNATURES: u64 = 6;

/// A merge statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeStatement {
    /// The space.
    pub space: EventId,
    /// The merged state `S`, 2 to 64 rotations.
    pub state: RotationSet,
    /// The public half of `read_seed(S)`.
    pub read: [u8; 32],
    /// The public half of `upload_seed(S)`.
    pub upload: [u8; 32],
    /// One signature per rotation of `S`, in the state's order.
    pub signatures: Vec<[u8; 64]>,
}

/// What each input signs:
/// `"frasil/storage-merge/v1" || field(space) || field(encode_set(S)) || read || upload`.
pub fn merge_message(
    space: &EventId,
    state: &RotationSet,
    read: &[u8; 32],
    upload: &[u8; 32],
) -> Vec<u8> {
    let mut out = STORAGE_MERGE.to_vec();
    push_field(&mut out, space.as_bytes());
    push_field(&mut out, &state.encode());
    out.extend_from_slice(read);
    out.extend_from_slice(upload);
    out
}

impl MergeStatement {
    /// The statement over a state's merged credentials, signed by each
    /// input's upload seed, given in the state's canonical order.
    ///
    /// # Panics
    ///
    /// If the count of seeds is not the state's.
    pub fn sign(
        space: EventId,
        state: RotationSet,
        read: [u8; 32],
        upload: [u8; 32],
        upload_seeds: &[[u8; 32]],
    ) -> Self {
        assert_eq!(upload_seeds.len(), state.len(), "one upload seed per input");
        let message = merge_message(&space, &state, &read, &upload);
        let signatures = upload_seeds
            .iter()
            .map(|seed| ed25519_sign(seed, &message))
            .collect();
        Self {
            space,
            state,
            read,
            upload,
            signatures,
        }
    }

    /// The message each signature is over.
    pub fn message(&self) -> Vec<u8> {
        merge_message(&self.space, &self.state, &self.read, &self.upload)
    }

    /// The statement's deterministic CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(KEY_VERSION, Value::Unsigned(VERSION));
        map.insert(KEY_SPACE, Value::from(*self.space.as_bytes()));
        map.insert(KEY_STATE, Value::Bytes(self.state.encode()));
        map.insert(KEY_READ, Value::from(self.read));
        map.insert(KEY_UPLOAD, Value::from(self.upload));
        map.insert(
            KEY_SIGNATURES,
            Value::Array(self.signatures.iter().map(|s| Value::from(*s)).collect()),
        );
        Value::Map(map).encode()
    }

    /// Reads a statement (peers.md, "Merge statements", steps 1 and 2): the
    /// map reads, with exactly these keys, version 1; the state is a
    /// rotation set of 2 to 64; one signature per rotation; then keys 4 and
    /// 5 are valid Ed25519 keys.
    ///
    /// # Errors
    ///
    /// `Malformed`; `UnsupportedVersion` for another version; `InvalidKey`.
    pub fn read(data: &[u8]) -> Result<Self, PeersClass> {
        let malformed = || PeersClass::from(ErrorClass::Malformed);
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        if !map.keys().copied().eq(KEY_VERSION..=KEY_SIGNATURES) {
            return Err(malformed());
        }
        let version = map[&KEY_VERSION].as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let space = EventId(map[&KEY_SPACE].as_byte_array()?);
        let state = map[&KEY_STATE].as_bytes()?;
        let read: [u8; 32] = map[&KEY_READ].as_byte_array()?;
        let upload: [u8; 32] = map[&KEY_UPLOAD].as_byte_array()?;
        let items = map[&KEY_SIGNATURES].as_array()?;
        let state = RotationSet::decode(state).map_err(|_| malformed())?;
        if !(MIN_MERGE_ROTATIONS..=MAX_MERGE_ROTATIONS).contains(&state.len())
            || items.len() != state.len()
        {
            return Err(malformed());
        }
        let signatures = items
            .iter()
            .map(|item| item.as_byte_array::<64>())
            .collect::<Result<Vec<_>, _>>()?;
        ed25519_valid(&read)?;
        ed25519_valid(&upload)?;
        Ok(Self {
            space,
            state,
            read,
            upload,
            signatures,
        })
    }
}
