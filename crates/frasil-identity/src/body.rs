//! The device-list event's body (identity.md, "The device-list event") and
//! the checks of it that need only the event (identity.md, "Checking a list
//! event alone", steps 2 to 6).
//!
//! A device-list event is an event of kind 1 under scheme 2. Its body is a
//! deterministic CBOR map:
//!
//! | Key | Field | Type | Value |
//! |---|---|---|---|
//! | 0 | `version` | unsigned | `3` |
//! | 1 | `action` | unsigned | `0` add, `1` revoke, `2` confirm, `3` checkpoint, `4` ack |
//! | 2 | `kind` | unsigned | `0` device, `1` recovery key, `2` passkey member, `3` recovery agent |
//! | 3 | `device` | bytes(32) | the device ID of the list member the event names |
//! | 4 | `possession` | bytes(3,373) | `add` only, required: the possession proof |
//! | 5 | `xwing` | bytes(1,216) | `add` only: required for kinds 0 to 2, absent for an agent |
//! | 6 | `mldsa` | bytes(1,952) | `add` only, required |
//! | 7 | `identity` | bytes(32) | `add` only, required: its Ed25519 identity key |
//! | 8 | `follows` | array of bytes(32) | the list checkpoints the event follows: 1 to 4 IDs, strictly ascending; absent when none, and in the first event |
//! | 9 | `record` | bytes | `checkpoint` only, required: the list record |
//!
//! An `add`'s keys 7, 6 and 5 give its key 3 (crypto.md, "A device's
//! keys"). A `revoke` or `confirm` has keys 0 to 3, and key 8 when it
//! follows a checkpoint; a `checkpoint` keys 0, 1 and 9, and an `ack` keys 0
//! and 1, each with key 8 when it follows one (identity.md, "List
//! checkpoints"). A device-list event never carries envelope cuts: a list's
//! checkpoints are declared in key 8. The envelope's checks (step 1), the event's signature (step 7)
//! and forks (step 8) need the event and the list it appends to.

use crate::IdentityClass;
use crate::keys::{Kind, PublicKeys};
use crate::possession::{self, FIRST_EVENT_PERSON, PROOF_BYTES};
use crate::record::ListRecord;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::version::DEVICE_LIST_BODY_VERSION;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey};
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use frasil_events::EventId;

/// The event kind of a device-list event (events.md, "Kinds").
pub const EVENT_KIND: u64 = 1;

/// The most valid list events in an event's place, itself included
/// (identity.md, "Checks at the event's place", step 8).
pub const MAX_LIST_EVENTS: usize = 4096;

/// Body key 0, `version`.
pub const KEY_VERSION: u64 = 0;
/// Body key 1, `action`.
pub const KEY_ACTION: u64 = 1;
/// Body key 2, `kind`.
pub const KEY_KIND: u64 = 2;
/// Body key 3, `device`.
pub const KEY_DEVICE: u64 = 3;
/// Body key 4, `possession`.
pub const KEY_POSSESSION: u64 = 4;
/// Body key 5, `xwing`.
pub const KEY_XWING: u64 = 5;
/// Body key 6, `mldsa`.
pub const KEY_MLDSA: u64 = 6;
/// Body key 7, `identity`.
pub const KEY_IDENTITY: u64 = 7;
/// Body key 8, `follows`.
pub const KEY_FOLLOWS: u64 = 8;
/// Body key 9, `record`.
pub const KEY_RECORD: u64 = 9;

/// The most list checkpoints an event's `follows` names (events.md, "Cuts",
/// read for a list).
pub const MAX_FOLLOWS: usize = 4;

/// What a list event does: body key 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Adds a list member.
    Add,
    /// Revokes a list member.
    Revoke,
    /// Confirms a rooted list member.
    Confirm,
    /// A list checkpoint, carrying its record (identity.md, "List
    /// checkpoints").
    Checkpoint,
    /// Changes nothing: a vote for the list checkpoints it follows by a
    /// device with nothing else to sign.
    Ack,
}

impl Action {
    /// Every action, in code order.
    pub const ALL: [Action; 5] = [
        Action::Add,
        Action::Revoke,
        Action::Confirm,
        Action::Checkpoint,
        Action::Ack,
    ];

    /// The action's code in the body.
    pub const fn code(self) -> u8 {
        match self {
            Action::Add => 0,
            Action::Revoke => 1,
            Action::Confirm => 2,
            Action::Checkpoint => 3,
            Action::Ack => 4,
        }
    }

    /// Whether the action names a list member in keys 2 and 3: an `add`, a
    /// `revoke` or a `confirm`.
    pub const fn names_member(self) -> bool {
        matches!(self, Action::Add | Action::Revoke | Action::Confirm)
    }

    /// The action of a code, or `None` for a code no action has.
    pub fn from_code(code: u64) -> Option<Self> {
        Action::ALL
            .into_iter()
            .find(|a| u64::from(a.code()) == code)
    }

    /// The action's name, as the document writes it.
    pub const fn name(self) -> &'static str {
        match self {
            Action::Add => "add",
            Action::Revoke => "revoke",
            Action::Confirm => "confirm",
            Action::Checkpoint => "checkpoint",
            Action::Ack => "ack",
        }
    }
}

/// What an `add` carries beside the device ID.
#[derive(Clone, PartialEq, Eq)]
pub struct Added {
    /// Its Ed25519 identity key.
    pub identity: IdentityKey,
    /// The named key's possession proof, 3,373 bytes.
    pub possession: Vec<u8>,
    /// Its X-Wing key; `None` for an agent.
    pub xwing: Option<Box<[u8; XWING_PUBLIC]>>,
    /// Its ML-DSA-65 key.
    pub mldsa: Box<[u8; MLDSA65_PUBLIC]>,
}

/// A device-list event's body, decoded.
///
/// A `checkpoint` or an `ack` names no list member: its `kind` is
/// [`Kind::Device`] and its `device` the zero device ID, which its encoding
/// leaves out. Read them only where [`Action::names_member`] holds.
#[derive(Clone, PartialEq, Eq)]
pub struct ListBody {
    /// Body key 1.
    pub action: Action,
    /// Body key 2: the kind of the list member the event names.
    pub kind: Kind,
    /// Body key 3: the device ID of the list member the event names.
    pub device: DeviceId,
    /// Keys 4 to 7, for an `add` only.
    pub added: Option<Added>,
    /// Key 8: the list checkpoints the event follows, strictly ascending;
    /// empty when none.
    pub follows: Vec<EventId>,
    /// Key 9: a `checkpoint`'s list record, as signed.
    pub record: Option<Vec<u8>>,
}

impl core::fmt::Debug for ListBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ListBody")
            .field("action", &self.action)
            .field("kind", &self.kind)
            .field("device", &self.device)
            .field("follows", &self.follows)
            .finish_non_exhaustive()
    }
}

impl ListBody {
    /// An `add` of `keys` as `kind`, with their possession proof; key 3 is
    /// their device ID.
    pub fn add(kind: Kind, keys: &PublicKeys, possession: Vec<u8>) -> Self {
        Self {
            action: Action::Add,
            kind,
            device: keys.device_id(),
            added: Some(Added {
                identity: keys.identity,
                possession,
                xwing: keys.xwing.clone(),
                mldsa: keys.mldsa.clone(),
            }),
            follows: Vec::new(),
            record: None,
        }
    }

    /// A `revoke` of the list member of this kind and device ID.
    pub fn revoke(kind: Kind, device: DeviceId) -> Self {
        Self {
            action: Action::Revoke,
            kind,
            device,
            added: None,
            follows: Vec::new(),
            record: None,
        }
    }

    /// A `confirm` of the list member of this kind and device ID.
    pub fn confirm(kind: Kind, device: DeviceId) -> Self {
        Self {
            action: Action::Confirm,
            kind,
            device,
            added: None,
            follows: Vec::new(),
            record: None,
        }
    }

    /// A list `checkpoint` carrying this record (identity.md, "List
    /// checkpoints").
    pub fn checkpoint(record: &ListRecord) -> Self {
        Self {
            action: Action::Checkpoint,
            kind: Kind::Device,
            device: DeviceId([0; 32]),
            added: None,
            follows: Vec::new(),
            record: Some(record.encode()),
        }
    }

    /// An `ack`: a list event that changes nothing, which a device with
    /// nothing else to sign signs to vote for the checkpoints it follows.
    pub fn ack() -> Self {
        Self {
            action: Action::Ack,
            kind: Kind::Device,
            device: DeviceId([0; 32]),
            added: None,
            follows: Vec::new(),
            record: None,
        }
    }

    /// The same body declaring that it follows these list checkpoints
    /// (key 8), which a signer derives from the event's parents.
    pub fn with_follows(mut self, mut follows: Vec<EventId>) -> Self {
        follows.sort_unstable();
        follows.dedup();
        self.follows = follows;
        self
    }

    /// A `checkpoint`'s record, read; `None` for another action. Decoding
    /// read it already, so it reads again.
    pub fn list_record(&self) -> Option<ListRecord> {
        self.record
            .as_deref()
            .and_then(|bytes| ListRecord::read(bytes).ok())
    }

    /// The keys an `add` names, or `None` for a `revoke` or `confirm`.
    pub fn keys(&self) -> Option<PublicKeys> {
        self.added.as_ref().map(|added| PublicKeys {
            identity: added.identity,
            xwing: added.xwing.clone(),
            mldsa: added.mldsa.clone(),
        })
    }

    /// The body's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(KEY_VERSION, Value::Unsigned(DEVICE_LIST_BODY_VERSION));
        map.insert(KEY_ACTION, Value::Unsigned(self.action.code().into()));
        if self.action.names_member() {
            map.insert(KEY_KIND, Value::Unsigned(self.kind.code().into()));
            map.insert(KEY_DEVICE, Value::from(self.device.0));
        }
        if !self.follows.is_empty() {
            map.insert(
                KEY_FOLLOWS,
                Value::Array(self.follows.iter().map(|id| Value::from(id.0)).collect()),
            );
        }
        if let Some(record) = &self.record {
            map.insert(KEY_RECORD, Value::from(record.clone()));
        }
        if let Some(added) = &self.added {
            map.insert(KEY_IDENTITY, Value::from(added.identity.0));
            map.insert(KEY_POSSESSION, Value::from(added.possession.clone()));
            if let Some(xwing) = &added.xwing {
                map.insert(KEY_XWING, Value::from(&xwing[..]));
            }
            map.insert(KEY_MLDSA, Value::from(&added.mldsa[..]));
        }
        Value::Map(map).encode()
    }

    /// Step 2 of "Checking a list event alone": the body is a deterministic
    /// CBOR map; version 3; action 0 to 4; for actions 0 to 2, kind 0 to 3;
    /// the keys of "The device-list event" for the action and kind, each
    /// with its length; `follows` 1 to 4 IDs, strictly ascending; and a
    /// checkpoint's record as "List checkpoints" reads it.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else, an action or kind it does not know
    /// included: a verifier cannot skip such an event. A record of another
    /// version is `UnsupportedVersion`, as reading a record says.
    pub fn decode(body: &[u8]) -> Result<Self, IdentityClass> {
        let decoded = decode(body).map_err(|_| IdentityClass::Shared(ErrorClass::Malformed))?;
        if let Some(record) = &decoded.record {
            ListRecord::read(record)?;
        }
        Ok(decoded)
    }

    /// Step 3: the list's first event is an `add` of a device whose device
    /// ID is its author; it follows no checkpoint (`Malformed`).
    ///
    /// # Errors
    ///
    /// `BadGenesis`.
    pub fn check_first(&self, author: &DeviceId) -> Result<(), IdentityClass> {
        if !self.follows.is_empty() {
            return Err(IdentityClass::Shared(ErrorClass::Malformed));
        }
        if self.action == Action::Add && self.kind == Kind::Device && self.device == *author {
            Ok(())
        } else {
            Err(IdentityClass::BadGenesis)
        }
    }

    /// Steps 4 to 6, for an `add`: its identity key passes `ed25519_valid`
    /// and its X-Wing key `xwing_valid`; its keys give its device ID; then
    /// its possession proof verifies, both halves, over the statement with
    /// `person_id` ([`FIRST_EVENT_PERSON`] in the list's first event) and
    /// `adder`, the event's author. A `revoke` or `confirm` passes.
    ///
    /// # Errors
    ///
    /// `InvalidKey`, then `NotCommitted`, then `BadPossession`.
    pub fn check_add(&self, person_id: &[u8; 32], adder: &DeviceId) -> Result<(), IdentityClass> {
        let Some(added) = &self.added else {
            return Ok(());
        };
        // 4. The keys' checks where they enter.
        ed25519_valid(&added.identity.0)?;
        if let Some(xwing) = &added.xwing {
            xwing_valid(&xwing[..])?;
        }
        // 5. identity, mldsa and xwing give device.
        let keys = HybridKeys::from_checked(added.mldsa.clone(), added.xwing.clone());
        if frasil_crypto::device::device_id(&added.identity, keys.commitment()) != self.device {
            return Err(IdentityClass::Shared(ErrorClass::NotCommitted));
        }
        // 6. The possession proof.
        let statement = possession::statement(
            person_id,
            adder,
            self.kind,
            &added.identity,
            &added.mldsa,
            added.xwing.as_deref(),
        );
        possession::verify(&added.identity, &keys, &statement, &added.possession)
    }
}

/// Steps 2 to 6 of "Checking a list event alone", on an event's body, in
/// order. `author` is the event's author; `person_id` is the list's person
/// ID, or `None` for the list's first event, whose proof binds 32 zero bytes.
///
/// # Errors
///
/// `Malformed` (with `UnsupportedVersion` for a record of another version),
/// `BadGenesis`, `InvalidKey`, `NotCommitted` and `BadPossession`, in that
/// order.
pub fn check_body(
    body: &[u8],
    author: &DeviceId,
    person_id: Option<&[u8; 32]>,
) -> Result<ListBody, IdentityClass> {
    // A first event's follows is Malformed before its record is read.
    let decoded = decode(body).map_err(|_| IdentityClass::Shared(ErrorClass::Malformed))?;
    if person_id.is_none() {
        decoded.check_first(author)?;
    }
    if let Some(record) = &decoded.record {
        ListRecord::read(record)?;
    }
    decoded.check_add(person_id.unwrap_or(&FIRST_EVENT_PERSON), author)?;
    Ok(decoded)
}

fn decode(body: &[u8]) -> Result<ListBody, cbor::Malformed> {
    let value = cbor::decode(body)?;
    let map = value.as_map()?;
    if map.get(&KEY_VERSION).map(Value::as_unsigned) != Some(Ok(DEVICE_LIST_BODY_VERSION)) {
        return Err(cbor::Malformed);
    }
    let action = unsigned(map, KEY_ACTION)
        .and_then(Action::from_code)
        .ok_or(cbor::Malformed)?;
    let follows = match map.get(&KEY_FOLLOWS) {
        Some(value) => {
            let ids = value
                .as_array()?
                .iter()
                .map(|id| id.as_byte_array().map(EventId))
                .collect::<Result<Vec<EventId>, _>>()?;
            if ids.is_empty() || ids.len() > MAX_FOLLOWS || ids.windows(2).any(|w| w[0] >= w[1]) {
                return Err(cbor::Malformed);
            }
            ids
        }
        None => Vec::new(),
    };
    let optional = usize::from(map.contains_key(&KEY_FOLLOWS));
    if !action.names_member() {
        // A checkpoint carries its record; an ack nothing.
        let allowed: &[u64] = match action {
            Action::Checkpoint => &[KEY_VERSION, KEY_ACTION, KEY_RECORD],
            _ => &[KEY_VERSION, KEY_ACTION],
        };
        if map.len() != allowed.len() + optional || !allowed.iter().all(|key| map.contains_key(key))
        {
            return Err(cbor::Malformed);
        }
        let record = match map.get(&KEY_RECORD) {
            Some(value) => Some(value.as_bytes()?.to_vec()),
            None => None,
        };
        return Ok(ListBody {
            action,
            kind: Kind::Device,
            device: DeviceId([0; 32]),
            added: None,
            follows,
            record,
        });
    }
    let kind = unsigned(map, KEY_KIND)
        .and_then(Kind::from_code)
        .ok_or(cbor::Malformed)?;
    let device = DeviceId(
        map.get(&KEY_DEVICE)
            .ok_or(cbor::Malformed)?
            .as_byte_array()?,
    );
    let allowed: &[u64] = match action {
        Action::Add if kind.names_xwing() => &[0, 1, 2, 3, 4, 5, 6, 7],
        Action::Add => &[0, 1, 2, 3, 4, 6, 7],
        _ => &[0, 1, 2, 3],
    };
    if map.len() != allowed.len() + optional || !allowed.iter().all(|key| map.contains_key(key)) {
        return Err(cbor::Malformed);
    }
    let added = if action == Action::Add {
        let possession = map[&KEY_POSSESSION].as_bytes()?;
        if possession.len() != PROOF_BYTES {
            return Err(cbor::Malformed);
        }
        let xwing = match map.get(&KEY_XWING) {
            Some(value) => Some(Box::new(value.as_byte_array::<XWING_PUBLIC>()?)),
            None => None,
        };
        Some(Added {
            identity: IdentityKey(map[&KEY_IDENTITY].as_byte_array()?),
            possession: possession.to_vec(),
            xwing,
            mldsa: Box::new(map[&KEY_MLDSA].as_byte_array::<MLDSA65_PUBLIC>()?),
        })
    } else {
        None
    };
    Ok(ListBody {
        action,
        kind,
        device,
        added,
        follows,
        record: None,
    })
}

fn unsigned(map: &Map, key: u64) -> Option<u64> {
    map.get(&key).and_then(|value| value.as_unsigned().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn malformed(body: &[u8]) -> bool {
        ListBody::decode(body) == Err(IdentityClass::Shared(ErrorClass::Malformed))
    }

    #[test]
    fn revoke_round_trips() {
        let body = ListBody::revoke(Kind::PasskeyMember, DeviceId([9; 32]));
        let bytes = body.encode();
        assert_eq!(ListBody::decode(&bytes).unwrap(), body);
        assert!(body.check_add(&[1; 32], &DeviceId([2; 32])).is_ok());
    }

    #[test]
    fn refuses_unknown_actions_kinds_and_keys() {
        let mut map = Map::new();
        map.insert(KEY_VERSION, Value::Unsigned(3));
        map.insert(KEY_ACTION, Value::Unsigned(1));
        map.insert(KEY_KIND, Value::Unsigned(0));
        map.insert(KEY_DEVICE, Value::from([9u8; 32]));
        assert!(!malformed(&Value::Map(map.clone()).encode()));
        for (key, value) in [
            (KEY_VERSION, Value::Unsigned(2)),
            (KEY_ACTION, Value::Unsigned(5)),
            (KEY_KIND, Value::Unsigned(4)),
            (KEY_DEVICE, Value::from([9u8; 31])),
            (KEY_MLDSA, Value::from([9u8; 1952])),
            (KEY_IDENTITY, Value::from([9u8; 32])),
            (KEY_FOLLOWS, Value::Unsigned(0)),
            (KEY_FOLLOWS, Value::Array(vec![])),
            (
                KEY_FOLLOWS,
                Value::Array(vec![Value::from([2u8; 32]), Value::from([1u8; 32])]),
            ),
            (KEY_RECORD, Value::from(vec![0xa0u8])),
            (10, Value::Unsigned(0)),
        ] {
            let mut changed = map.clone();
            changed.insert(key, value);
            assert!(malformed(&Value::Map(changed).encode()), "key {key}");
        }
        assert!(malformed(&Value::Array(vec![]).encode()));
        assert!(malformed(b"\xa0\x00"));
    }

    #[test]
    fn acks_and_checkpoints_name_no_member() {
        let follows = vec![EventId([1; 32]), EventId([2; 32])];
        let ack = ListBody::ack().with_follows(follows.clone());
        let bytes = ack.encode();
        assert_eq!(ListBody::decode(&bytes).unwrap(), ack);
        let Value::Map(map) = cbor::decode(&bytes).unwrap() else {
            unreachable!()
        };
        assert_eq!(
            map.keys().copied().collect::<Vec<_>>(),
            [KEY_VERSION, KEY_ACTION, KEY_FOLLOWS]
        );
        let record = ListRecord {
            epoch: 1,
            previous: None,
            members: Vec::new(),
            tips: Vec::new(),
            forks: Vec::new(),
            heard: Vec::new(),
        };
        let checkpoint = ListBody::checkpoint(&record);
        assert_eq!(ListBody::decode(&checkpoint.encode()).unwrap(), checkpoint);
        assert_eq!(checkpoint.list_record(), Some(record));
        // An ack with a kind, a checkpoint without its record.
        let mut map = Map::new();
        map.insert(KEY_VERSION, Value::Unsigned(3));
        map.insert(KEY_ACTION, Value::Unsigned(4));
        map.insert(KEY_KIND, Value::Unsigned(0));
        assert!(malformed(&Value::Map(map.clone()).encode()));
        map.remove(&KEY_KIND);
        map.insert(KEY_ACTION, Value::Unsigned(3));
        assert!(malformed(&Value::Map(map).encode()));
        // A first event that follows a checkpoint, or that is an ack.
        let author = DeviceId([9; 32]);
        assert_eq!(
            check_body(&ack.encode(), &author, None),
            Err(IdentityClass::Shared(ErrorClass::Malformed))
        );
        assert_eq!(
            check_body(&ListBody::ack().encode(), &author, None),
            Err(IdentityClass::BadGenesis)
        );
    }
}
