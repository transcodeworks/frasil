//! The checkpoint record (roster.md, 2.8 The checkpoint record): the
//! roster, policy, chain tips and fork points of a checkpoint's own past, as
//! a deterministic CBOR map, so that a replica that holds nothing before the
//! checkpoint judges what follows it as one that holds everything.
//!
//! | Key | Field | Value |
//! |---|---|---|
//! | 1 | `version` | 1 |
//! | 2 | `epoch` | 1 for a checkpoint whose past has none in effect; otherwise one more than its predecessor's |
//! | 3 | `previous` | bytes(32): the predecessor; present exactly when `epoch` > 1 |
//! | 4 | `members` | member entries, strictly ascending by the bytes of their member references |
//! | 5 | `policy` | bytes: the merged space policy |
//! | 6 | `tips` | `[author, seq, event ID]`, strictly ascending by author |
//! | 7 | `forks` | `[author, seq]`, strictly ascending by author |
//! | 8 | `heard` | `[device, [epoch, height, grant], rank, Ed25519, ML-DSA-65, X-Wing]`, strictly ascending by device ID: each member the checkpoint hears (roster.md, 3.15.4); present exactly when there are some |
//!
//! `members` holds one entry per member in at the merged roster of the
//! checkpoint's past, and one per invite key out only by valid successors
//! there that no close has removed yet.
//!
//! A **member entry** is a map: 1, the member reference, of type 0 to 3;
//! 2, `level`; 3, capabilities, absent when none; 4, `label`; 5, `history`;
//! 6, `via`; 7, `session`; 8, `replaces`; 9, `seniority`,
//! `[epoch, height, grant]`; 10, 11 and 12, the Ed25519, ML-DSA-65 and
//! X-Wing keys of a device member or an invite key; 13, `slot`,
//! `[c, index, maker, pseudonym]`, for an administrator whose slot the
//! skeleton holds; 14, `expires_at`, a guest's with its `session` and an
//! invite key's always; 15, an invite key's `claims`; 16, its status
//! ([`InviteStatus`]); 17, `claimant`, exactly with status 1; for a
//! space member 18, `notices`, 19, `floor` and 20, `named`; and 21, an
//! administrator's `rank`, exactly at `administer`. A claimed invite
//! key's entry has keys 1, 10, 11, 12, 16 and 17 only.
//!
//! Reading a record, in order ([`Record::read`]): deterministic CBOR, a map
//! with an unsigned key 1 (`Malformed`); version 1 (`UnsupportedVersion`);
//! no record key from 9, member-entry key from 22 or member reference of a
//! type from 4, which later documents define and this implementation does
//! not (`ExtensionRequired`, held, before anything else is read); the keys
//! above, with their types and orders, each member entry
//! with exactly the keys its row and member type allow, `heard` absent or
//! not empty (`Malformed`); each device member's, invite key's and heard
//! member's Ed25519 and X-Wing keys valid (`InvalidKey`); and each giving
//! its member ID (`NotCommitted`).
//!
//! Keys 18 to 20 of a space member's entry read which key events are valid,
//! which can read another log, so a checkpoint's validity compares records
//! without them ([`Record::compared`]); the votes vouch for them.
//!
//! The record travels as an object, sealed under the checkpoint's own
//! content key; reading the object is units.md's ("Objects"). This module
//! takes its plaintext and checks it against the checkpoint's `size` and
//! `digest` ([`Record::read_object`]).

use crate::member::{
    Capability, CapabilityMode, HistoryMode, Level, MemberRef, MemberType, Via, read_capabilities,
};
use crate::part::{CheckpointPart, MAX_RECORD_BYTES};
use crate::policy::Policy;
use crate::state::MemberState;
use crate::{Limits, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, IdentityKey};
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::labels::CHECKPOINT_RECORD;
use frasil_crypto::primitives::sha256;
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The record's version.
pub const VERSION: u64 = 1;

/// The record's keys.
pub mod key {
    /// `version`.
    pub const VERSION: u64 = 1;
    /// `epoch`.
    pub const EPOCH: u64 = 2;
    /// `previous`.
    pub const PREVIOUS: u64 = 3;
    /// `members`.
    pub const MEMBERS: u64 = 4;
    /// `policy`.
    pub const POLICY: u64 = 5;
    /// `tips`.
    pub const TIPS: u64 = 6;
    /// `forks`.
    pub const FORKS: u64 = 7;
    /// `heard`: the members the checkpoint hears.
    pub const HEARD: u64 = 8;
}

/// A member entry's keys.
pub mod member_key {
    /// The member reference.
    pub const MEMBER: u64 = 1;
    /// `level`.
    pub const LEVEL: u64 = 2;
    /// Capabilities.
    pub const CAPABILITIES: u64 = 3;
    /// `label`.
    pub const LABEL: u64 = 4;
    /// `history`.
    pub const HISTORY: u64 = 5;
    /// `via`.
    pub const VIA: u64 = 6;
    /// `session`.
    pub const SESSION: u64 = 7;
    /// `replaces`.
    pub const REPLACES: u64 = 8;
    /// `seniority`: `[epoch, height, grant]`.
    pub const SENIORITY: u64 = 9;
    /// A device member's or invite key's Ed25519 key.
    pub const ED25519: u64 = 10;
    /// A device member's or invite key's ML-DSA-65 key.
    pub const MLDSA: u64 = 11;
    /// A device member's or invite key's X-Wing key.
    pub const XWING: u64 = 12;
    /// An administrator's slot: `[c, index, maker, pseudonym]`.
    pub const SLOT: u64 = 13;
    /// A guest's `expires_at`, or an invite key's.
    pub const EXPIRES_AT: u64 = 14;
    /// An invite key's `claims`.
    pub const CLAIMS: u64 = 15;
    /// An invite key's status.
    pub const INVITE: u64 = 16;
    /// A claimed invite key's claimant.
    pub const CLAIMANT: u64 = 17;
    /// A space member's notices.
    pub const NOTICES: u64 = 18;
    /// A space member's floor.
    pub const FLOOR: u64 = 19;
    /// The granted space's event IDs that sealed refs named.
    pub const NAMED: u64 = 20;
    /// An administrator's rank, exactly at `administer`.
    pub const RANK: u64 = 21;
}

/// The first record key reserved for later documents (roster.md, 2.8 The
/// checkpoint record, "Reserved record keys").
pub const RESERVED_RECORD_KEY: u64 = 9;
/// The first member-entry key reserved for later documents.
pub const RESERVED_MEMBER_KEY: u64 = 22;
/// The first member type reserved for later documents, in a record.
pub const RESERVED_MEMBER_TYPE: u64 = 4;

/// Step 3 of reading a record: whether it uses a record key from 9, a
/// member-entry key from 22 or a member reference of a type from 4, which
/// later documents define. Read before any other check of the record: of
/// `members`, only what is a list of maps, and of an entry's key 1, only a
/// list whose first element is an unsigned integer.
#[cfg(any(test, feature = "oracle"))]
fn uses_later_document(map: &Map) -> bool {
    if map.keys().any(|&k| k >= RESERVED_RECORD_KEY) {
        return true;
    }
    let Some(Value::Array(members)) = map.get(&key::MEMBERS) else {
        return false;
    };
    members.iter().any(|entry| {
        let Value::Map(entry) = entry else {
            return false;
        };
        entry.keys().any(|&k| k >= RESERVED_MEMBER_KEY)
            || matches!(
                entry.get(&member_key::MEMBER),
                Some(Value::Array(member))
                    if matches!(member.first(), Some(Value::Unsigned(t)) if *t >= RESERVED_MEMBER_TYPE)
            )
    })
}

/// What a replica reads of a record that a later document's key or member
/// type holds (roster.md, 2.8, step 3): its `epoch` and its `previous`,
/// from keys 2 and 3 alone, as the record's table types them, without
/// reading the rest. `None` when either does not read so, or `previous` is
/// not present exactly when `epoch` is above 1.
pub fn read_link(data: &[u8]) -> Option<(u64, Option<EventId>)> {
    let value = cbor::decode(data).ok()?;
    let map = value.as_map().ok()?;
    let epoch = map.get(&key::EPOCH)?.as_unsigned().ok()?;
    let previous = map
        .get(&key::PREVIOUS)
        .map(|value| value.as_byte_array::<32>().map(EventId))
        .transpose()
        .ok()?;
    (epoch >= 1 && previous.is_some() == (epoch > 1)).then_some((epoch, previous))
}

/// `claims` 0: the invite admits a device.
const CLAIMS_DEVICE: u64 = 0;
/// `claims` 1: the invite admits a person.
const CLAIMS_PERSON: u64 = 1;

/// `SHA-256("frasil/checkpoint-record/v1" || record)`: what a checkpoint's
/// `digest` holds (roster.md, "The roster part").
pub fn digest(record: &[u8]) -> [u8; 32] {
    sha256(&[CHECKPOINT_RECORD, record])
}

/// An administrator's slot in a record (key 13): its reference in the
/// skeleton and the pseudonym enrolled in it (peers.md), so that a replica
/// that forgot the binding still maps pseudonyms to devices.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlotEntry {
    /// The slot's commitment `c`.
    pub commitment: [u8; 32],
    /// The slot's index in the event that made it.
    pub index: u64,
    /// The event that made the slot.
    pub maker: EventId,
    /// The device ID of the pseudonym enrolled in the slot, as its bytes:
    /// 32 bytes, or none when no pseudonym is enrolled.
    pub pseudonym: Vec<u8>,
}

/// An invite key's status in a record (key 16; ext-invite-links.md,
/// "Across a checkpoint"), from its successors in the checkpoint's past.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InviteStatus {
    /// 0: no successor of it is there.
    Open,
    /// 1: a valid successor of it is there; the key is out.
    Claimed,
    /// 2: a successor of it is void as `ClaimRaced`, and none is valid.
    Raced,
    /// 3: another successor of it is there, and none is valid or raced.
    Used,
}

impl InviteStatus {
    /// The status's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Open => 0,
            Self::Claimed => 1,
            Self::Raced => 2,
            Self::Used => 3,
        }
    }

    /// The status of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        [Self::Open, Self::Claimed, Self::Raced, Self::Used]
            .into_iter()
            .find(|status| status.code() == code)
    }

    /// The order in which a successor's status overrides another's: open,
    /// used, raced, claimed. A record's status is the highest of its
    /// successors', the predecessor's counting as one more where it is not
    /// open (roster.md, 3.15.3).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Used => 1,
            Self::Raced => 2,
            Self::Claimed => 3,
        }
    }

    /// Whether the checkpoint counts as a successor of a key of this status
    /// in its world: every status but open (roster.md, 3.15.5).
    pub const fn used(self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// A notice a record keeps for a granted space (key 18): the notice and the
/// author of the event that carried it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordNotice {
    /// The grant rotation of the granted space it names.
    pub rotation: EventId,
    /// That rotation's `grant_public`.
    pub public: Box<[u8; XWING_PUBLIC]>,
    /// The notice's key 4: "from now on".
    pub from_now_on: bool,
    /// The author of the event that carried it.
    pub author: DeviceId,
}

impl RecordNotice {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.rotation.0.to_vec()),
            Value::Bytes(self.public.to_vec()),
            Value::Unsigned(u64::from(self.from_now_on)),
            Value::Bytes(self.author.0.to_vec()),
        ])
    }

    /// The notice as keys.md's body carries it, for the granted space
    /// `space`.
    pub fn notice(&self, space: EventId) -> frasil_keys::body::Notice {
        frasil_keys::body::Notice {
            space,
            rotation: self.rotation,
            public: self.public.clone(),
            from_now_on: self.from_now_on,
        }
    }
}

/// One member entry of a record: a member in at the checkpoint's past,
/// with its state, its seniority and, for a device member or an invite key,
/// its keys; or an invite key out only by a valid successor.
///
/// A claimed invite key's entry carries keys 1, 10, 11, 12, 16 and 17
/// only: its `level`, `history`, `via` and `seniority` fields are then
/// placeholders that its encoding leaves out ([`Self::is_claimed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEntry {
    /// Key 1.
    pub member: MemberRef,
    /// Key 2.
    pub level: Level,
    /// Key 3, strictly ascending by name; empty when absent.
    pub capabilities: Vec<Capability>,
    /// Key 4.
    pub label: Option<String>,
    /// Key 5.
    pub history: HistoryMode,
    /// Key 6.
    pub via: Via,
    /// Key 7.
    pub session: Option<[u8; 16]>,
    /// Key 8.
    pub replaces: Option<[u8; 32]>,
    /// Key 9: the epoch, height and event ID of the member's most senior
    /// grant in force.
    pub seniority: (u64, u64, EventId),
    /// Keys 10, 11 and 12 of a device member or an invite key.
    pub keys: Option<Arc<DeviceKeys>>,
    /// Key 13, for an administrator whose slot the skeleton holds.
    pub slot: Option<SlotEntry>,
    /// Key 14: a guest's `expires_at`, which comes with its `session`, or an
    /// invite key's.
    pub expires_at: Option<u64>,
    /// Key 15: an invite key's `claims`, as its invite grant's.
    pub claims: Option<u64>,
    /// Key 16: an invite key's status.
    pub invite: Option<InviteStatus>,
    /// Key 17: the claimant a claimed invite key's valid successor granted.
    pub claimant: Option<MemberRef>,
    /// Key 18: a space member's notices, strictly ascending by encoding.
    pub notices: Vec<RecordNotice>,
    /// Key 19: a space member's floor.
    pub floor: bool,
    /// Key 20: the event IDs of a space member's log that sealed refs
    /// named, strictly ascending.
    pub named: Vec<EventId>,
    /// Key 21: an administrator's rank, exactly at `administer`.
    pub rank: Option<u8>,
}

impl MemberEntry {
    /// The entry of a member whose state is `state` in the roster of a
    /// checkpoint's past. `keys` are a device member's or an invite key's,
    /// from any source. `expires_at` is taken from the state with its
    /// `session`; an invite key's other fields are set by the caller.
    pub fn of(
        member: MemberRef,
        state: &MemberState,
        keys: Option<Arc<DeviceKeys>>,
        slot: Option<SlotEntry>,
    ) -> Self {
        Self {
            member,
            level: state.level,
            capabilities: state.capabilities.iter().cloned().collect(),
            label: state.label.clone(),
            history: state.history,
            via: state.via,
            session: state.session,
            replaces: state.replaces,
            seniority: (
                state.seniority.epoch,
                state.seniority.height,
                state.seniority.grant,
            ),
            keys,
            slot,
            expires_at: state.session.and(state.expires_at),
            claims: None,
            invite: None,
            claimant: None,
            notices: Vec::new(),
            floor: false,
            named: Vec::new(),
            rank: state.rank.filter(|_| state.level == Level::Administer),
        }
    }

    /// The entry of an invite key a valid successor put out: its keys, and
    /// the claimant that successor granted.
    pub fn claimed(key: Option<Arc<DeviceKeys>>, member: MemberRef, claimant: MemberRef) -> Self {
        Self {
            member,
            level: Level::Read,
            capabilities: Vec::new(),
            label: None,
            history: HistoryMode::FromNowOn,
            via: Via::Link,
            session: None,
            replaces: None,
            seniority: (0, 0, EventId([0; 32])),
            keys: key,
            slot: None,
            expires_at: None,
            claims: None,
            invite: Some(InviteStatus::Claimed),
            claimant: Some(claimant),
            notices: Vec::new(),
            floor: false,
            named: Vec::new(),
            rank: None,
        }
    }

    /// Whether this is a claimed invite key's entry: out, with keys 1, 10,
    /// 11, 12, 16 and 17 only.
    pub fn is_claimed(&self) -> bool {
        self.invite == Some(InviteStatus::Claimed)
    }

    /// Whether the member is in at the checkpoint's past: every entry but a
    /// claimed invite key's.
    pub fn is_in(&self) -> bool {
        !self.is_claimed()
    }

    pub(crate) fn to_value(&self) -> Value {
        use member_key as k;
        let mut map = Map::new();
        map.insert(k::MEMBER, self.member.to_value());
        if let Some(keys) = &self.keys {
            map.insert(k::ED25519, Value::Bytes(keys.ed.0.to_vec()));
            map.insert(k::MLDSA, Value::Bytes(keys.keys.mldsa().to_vec()));
            if let Some(xwing) = keys.keys.xwing() {
                map.insert(k::XWING, Value::Bytes(xwing.to_vec()));
            }
        }
        if let Some(invite) = self.invite {
            map.insert(k::INVITE, Value::Unsigned(invite.code()));
        }
        if self.is_claimed() {
            if let Some(claimant) = &self.claimant {
                map.insert(k::CLAIMANT, claimant.to_value());
            }
            return Value::Map(map);
        }
        map.insert(k::LEVEL, Value::Unsigned(self.level.code()));
        if !self.capabilities.is_empty() {
            let pairs = self.capabilities.iter().map(Capability::to_value).collect();
            map.insert(k::CAPABILITIES, Value::Array(pairs));
        }
        if let Some(label) = &self.label {
            map.insert(k::LABEL, Value::Text(label.clone()));
        }
        map.insert(k::HISTORY, Value::Unsigned(self.history.code()));
        map.insert(k::VIA, Value::Unsigned(self.via.code()));
        if let Some(session) = self.session {
            map.insert(k::SESSION, Value::Bytes(session.to_vec()));
        }
        if let Some(replaces) = self.replaces {
            map.insert(k::REPLACES, Value::Bytes(replaces.to_vec()));
        }
        let (epoch, height, grant) = self.seniority;
        map.insert(
            k::SENIORITY,
            Value::Array(vec![
                Value::Unsigned(epoch),
                Value::Unsigned(height),
                Value::Bytes(grant.0.to_vec()),
            ]),
        );
        if let Some(slot) = &self.slot {
            map.insert(
                k::SLOT,
                Value::Array(vec![
                    Value::Bytes(slot.commitment.to_vec()),
                    Value::Unsigned(slot.index),
                    Value::Bytes(slot.maker.0.to_vec()),
                    Value::Bytes(slot.pseudonym.clone()),
                ]),
            );
        }
        if let Some(expires_at) = self.expires_at {
            map.insert(k::EXPIRES_AT, Value::Unsigned(expires_at));
        }
        if let Some(claims) = self.claims {
            map.insert(k::CLAIMS, Value::Unsigned(claims));
        }
        if !self.notices.is_empty() {
            let mut notices: Vec<(Vec<u8>, Value)> = self
                .notices
                .iter()
                .map(|n| {
                    let value = n.to_value();
                    (value.encode(), value)
                })
                .collect();
            notices.sort_by(|a, b| a.0.cmp(&b.0));
            notices.dedup_by(|a, b| a.0 == b.0);
            map.insert(
                k::NOTICES,
                Value::Array(notices.into_iter().map(|(_, v)| v).collect()),
            );
        }
        if self.floor {
            map.insert(k::FLOOR, Value::Unsigned(1));
        }
        if !self.named.is_empty() {
            let named: BTreeSet<EventId> = self.named.iter().copied().collect();
            map.insert(
                k::NAMED,
                Value::Array(named.iter().map(|id| Value::Bytes(id.0.to_vec())).collect()),
            );
        }
        if let Some(rank) = self.rank {
            map.insert(k::RANK, Value::Unsigned(u64::from(rank)));
        }
        Value::Map(map)
    }

    /// Reads one entry's shape (roster.md, "The checkpoint record", step
    /// 3), with its keys' bytes but not their validity, which
    /// [`Record::read`] checks for every entry after every shape.
    pub(crate) fn read(value: &Value) -> Result<(Self, Option<RawKeys>), SpaceClass> {
        use member_key as k;
        let map = value.as_map()?;
        let member = read_member(map.get(&k::MEMBER).ok_or_else(malformed)?, true)?;
        let kind = member.kind;
        let keyed = matches!(kind, MemberType::Device | MemberType::Invite);
        let claimed = kind == MemberType::Invite
            && map.get(&k::INVITE).and_then(|v| v.as_unsigned().ok())
                == Some(InviteStatus::Claimed.code());
        let state = [
            k::LEVEL,
            k::CAPABILITIES,
            k::LABEL,
            k::HISTORY,
            k::VIA,
            k::SESSION,
            k::SENIORITY,
        ];
        let mut allowed: BTreeSet<u64> = BTreeSet::from([k::MEMBER]);
        let required: BTreeSet<u64> = if claimed {
            allowed.extend([k::ED25519, k::MLDSA, k::XWING, k::INVITE, k::CLAIMANT]);
            allowed.clone()
        } else {
            allowed.extend(state);
            let mut needed =
                BTreeSet::from([k::MEMBER, k::LEVEL, k::HISTORY, k::VIA, k::SENIORITY]);
            match kind {
                MemberType::Device => {
                    allowed.extend([
                        k::ED25519,
                        k::MLDSA,
                        k::XWING,
                        k::SLOT,
                        k::EXPIRES_AT,
                        k::RANK,
                    ]);
                    needed.extend([k::ED25519, k::MLDSA, k::XWING]);
                }
                MemberType::Invite => {
                    let invite = [
                        k::ED25519,
                        k::MLDSA,
                        k::XWING,
                        k::EXPIRES_AT,
                        k::CLAIMS,
                        k::INVITE,
                    ];
                    allowed.extend(invite);
                    needed.extend(invite);
                }
                MemberType::Person => {
                    allowed.insert(k::REPLACES);
                    allowed.remove(&k::SESSION);
                }
                MemberType::Space => {
                    allowed.extend([k::NOTICES, k::FLOOR, k::NAMED]);
                    allowed.remove(&k::SESSION);
                }
            }
            needed
        };
        if !map.keys().all(|key| allowed.contains(key))
            || !required.iter().all(|key| map.contains_key(key))
        {
            return Err(malformed());
        }
        let raw = if keyed {
            Some(RawKeys {
                ed: map[&k::ED25519].as_byte_array::<32>()?,
                mldsa: Box::new(map[&k::MLDSA].as_byte_array::<MLDSA65_PUBLIC>()?),
                xwing: Box::new(map[&k::XWING].as_byte_array::<XWING_PUBLIC>()?),
            })
        } else {
            None
        };
        let invite = match map.get(&k::INVITE) {
            Some(value) => {
                Some(InviteStatus::from_code(value.as_unsigned()?).ok_or_else(malformed)?)
            }
            None => None,
        };
        if claimed {
            let claimant = read_member(&map[&k::CLAIMANT], true)?;
            if !matches!(claimant.kind, MemberType::Device | MemberType::Person) {
                return Err(malformed());
            }
            let mut entry = Self::claimed(None, member, claimant);
            entry.keys = None;
            return Ok((entry, raw));
        }
        let [epoch, height, grant] = map[&k::SENIORITY].as_array()? else {
            return Err(malformed());
        };
        let seniority = (
            epoch.as_unsigned()?,
            height.as_unsigned()?,
            EventId(grant.as_byte_array::<32>()?),
        );
        let level = Level::from_code(map[&k::LEVEL].as_unsigned()?).ok_or_else(malformed)?;
        let history =
            HistoryMode::from_code(map[&k::HISTORY].as_unsigned()?).ok_or_else(malformed)?;
        let via = Via::from_code(map[&k::VIA].as_unsigned()?).ok_or_else(malformed)?;
        if level == Level::Administer
            && (kind != MemberType::Device || map.contains_key(&k::SESSION))
        {
            return Err(malformed());
        }
        // An administrator's rank, exactly with administer (roster.md, 2.8).
        let rank = map
            .get(&k::RANK)
            .map(|value| u8::try_from(value.as_unsigned()?).map_err(|_| malformed()))
            .transpose()?;
        if rank.is_some() != (level == Level::Administer) {
            return Err(malformed());
        }
        if kind == MemberType::Invite && via != Via::Link {
            return Err(malformed());
        }
        let capabilities = map
            .get(&k::CAPABILITIES)
            .map(|value| read_capabilities(value, Limits::PROTOCOL.max_capabilities))
            .transpose()?
            .unwrap_or_default();
        let label = map
            .get(&k::LABEL)
            .map(crate::member::read_name)
            .transpose()?;
        let session = map
            .get(&k::SESSION)
            .map(Value::as_byte_array::<16>)
            .transpose()?;
        let replaces = map
            .get(&k::REPLACES)
            .map(Value::as_byte_array::<32>)
            .transpose()?;
        let expires_at = map
            .get(&k::EXPIRES_AT)
            .map(Value::as_unsigned)
            .transpose()?;
        if expires_at.is_some() && kind == MemberType::Device && session.is_none() {
            return Err(malformed());
        }
        let claims = map.get(&k::CLAIMS).map(Value::as_unsigned).transpose()?;
        if let Some(claims) = claims
            && (!matches!(claims, CLAIMS_DEVICE | CLAIMS_PERSON)
                || (session.is_some() && claims != CLAIMS_DEVICE))
        {
            return Err(malformed());
        }
        let slot = match map.get(&k::SLOT) {
            Some(value) => {
                if level != Level::Administer {
                    return Err(malformed());
                }
                Some(read_slot(value)?)
            }
            None => None,
        };
        let notices = match map.get(&k::NOTICES) {
            Some(value) => read_notices(value)?,
            None => Vec::new(),
        };
        let floor = match map.get(&k::FLOOR) {
            Some(value) if value.as_unsigned()? == 1 => true,
            Some(_) => return Err(malformed()),
            None => false,
        };
        let named = match map.get(&k::NAMED) {
            Some(value) => read_named(value)?,
            None => Vec::new(),
        };
        let entry = Self {
            member,
            level,
            capabilities,
            label,
            history,
            via,
            session,
            replaces,
            seniority,
            keys: None,
            slot,
            expires_at,
            claims,
            invite,
            claimant: None,
            notices,
            floor,
            named,
            rank,
        };
        Ok((entry, raw))
    }
}

/// A keyed entry's keys as read, before their checks.
pub(crate) struct RawKeys {
    ed: [u8; 32],
    mldsa: Box<[u8; MLDSA65_PUBLIC]>,
    xwing: Box<[u8; XWING_PUBLIC]>,
}

impl RawKeys {
    /// Step 4: the Ed25519 and X-Wing keys valid.
    pub(crate) fn check_valid(&self) -> Result<(), SpaceClass> {
        ed25519_valid(&self.ed)?;
        xwing_valid(&self.xwing[..])?;
        Ok(())
    }

    pub(crate) fn into_keys(self) -> DeviceKeys {
        DeviceKeys {
            ed: IdentityKey(self.ed),
            keys: HybridKeys::from_checked(self.mldsa, Some(self.xwing)),
        }
    }
}

/// A member reference `[type, id]` of type 0 to 3, or of 0 and 1 when
/// `any` is false.
fn read_member(value: &Value, any: bool) -> Result<MemberRef, SpaceClass> {
    let [kind, id] = value.as_array()? else {
        return Err(malformed());
    };
    let kind = MemberType::from_code(kind.as_unsigned()?).ok_or_else(malformed)?;
    if !any && !matches!(kind, MemberType::Device | MemberType::Person) {
        return Err(malformed());
    }
    Ok(MemberRef {
        kind,
        id: id.as_byte_array::<32>()?,
    })
}

/// Key 13: `[c, index, maker, pseudonym]`, the pseudonym 32 bytes or none.
fn read_slot(value: &Value) -> Result<SlotEntry, SpaceClass> {
    let [commitment, index, maker, pseudonym] = value.as_array()? else {
        return Err(malformed());
    };
    let pseudonym = pseudonym.as_bytes()?.to_vec();
    if !matches!(pseudonym.len(), 0 | 32) {
        return Err(malformed());
    }
    Ok(SlotEntry {
        commitment: commitment.as_byte_array::<32>()?,
        index: index.as_unsigned()?,
        maker: EventId(maker.as_byte_array::<32>()?),
        pseudonym,
    })
}

/// Key 18: a nonempty array of `[rotation, grant_public, break, author]`,
/// strictly ascending by encoding.
fn read_notices(value: &Value) -> Result<Vec<RecordNotice>, SpaceClass> {
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(malformed());
    }
    let mut out = Vec::with_capacity(items.len());
    let mut last: Option<Vec<u8>> = None;
    for item in items {
        let [rotation, public, from_now_on, author] = item.as_array()? else {
            return Err(malformed());
        };
        let from_now_on = match from_now_on.as_unsigned()? {
            0 => false,
            1 => true,
            _ => return Err(malformed()),
        };
        let notice = RecordNotice {
            rotation: EventId(rotation.as_byte_array::<32>()?),
            public: Box::new(public.as_byte_array::<XWING_PUBLIC>()?),
            from_now_on,
            author: DeviceId(author.as_byte_array::<32>()?),
        };
        let encoded = item.encode();
        if last.as_ref().is_some_and(|last| *last >= encoded) {
            return Err(malformed());
        }
        last = Some(encoded);
        out.push(notice);
    }
    Ok(out)
}

/// Key 20: a nonempty array of event IDs, strictly ascending.
fn read_named(value: &Value) -> Result<Vec<EventId>, SpaceClass> {
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(malformed());
    }
    let mut out: Vec<EventId> = Vec::with_capacity(items.len());
    for item in items {
        let id = EventId(item.as_byte_array::<32>()?);
        if out.last().is_some_and(|last| *last >= id) {
            return Err(malformed());
        }
        out.push(id);
    }
    Ok(out)
}

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// A member a checkpoint hears (record key 8; roster.md, 3.15.4, "Votes
/// and effect"): an administrator its past lowered from `administer` only
/// by members it outranks, that the record does not keep at
/// `administer`. It stays in the electorate until it votes or is excused,
/// and its votes and excuses are checked under the keys the entry gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeardMember {
    /// Its device ID.
    pub device: DeviceId,
    /// The most senior of its seniorities at the places of the events that
    /// lowered it: epoch, height and grant, as a member entry's key 9.
    pub seniority: (u64, u64, EventId),
    /// The highest of its ranks there.
    pub rank: u8,
    /// The keys that give its device ID.
    pub keys: Arc<DeviceKeys>,
}

/// A heard member's row as read: its device ID, seniority, rank, and its
/// keys' bytes not yet checked.
pub(crate) type HeardRow = (DeviceId, (u64, u64, EventId), u8, RawKeys);

impl HeardMember {
    /// Its seniority as the roster compares it, with the hash of the space
    /// and its device ID (roster.md, 3.2).
    pub fn full_seniority(&self, space: &EventId) -> crate::state::Seniority {
        let (epoch, height, grant) = self.seniority;
        crate::state::Seniority {
            epoch,
            height,
            hash: crate::state::seniority_hash(space, &self.device.0),
            grant,
        }
    }

    fn to_value(&self) -> Value {
        let (epoch, height, grant) = self.seniority;
        let xwing = self
            .keys
            .keys
            .xwing()
            .map(|x| x.to_vec())
            .unwrap_or_default();
        Value::Array(vec![
            Value::Bytes(self.device.0.to_vec()),
            Value::Array(vec![
                Value::Unsigned(epoch),
                Value::Unsigned(height),
                Value::Bytes(grant.0.to_vec()),
            ]),
            Value::Unsigned(u64::from(self.rank)),
            Value::Bytes(self.keys.ed.0.to_vec()),
            Value::Bytes(self.keys.keys.mldsa().to_vec()),
            Value::Bytes(xwing),
        ])
    }

    /// Reads one entry's shape, with its keys' bytes but not their
    /// validity.
    pub(crate) fn read(value: &Value) -> Result<HeardRow, SpaceClass> {
        let [device, seniority, rank, ed, mldsa, xwing] = value.as_array()? else {
            return Err(malformed());
        };
        let [epoch, height, grant] = seniority.as_array()? else {
            return Err(malformed());
        };
        let rank = u8::try_from(rank.as_unsigned()?).map_err(|_| malformed())?;
        Ok((
            DeviceId(device.as_byte_array::<32>()?),
            (
                epoch.as_unsigned()?,
                height.as_unsigned()?,
                EventId(grant.as_byte_array::<32>()?),
            ),
            rank,
            RawKeys {
                ed: ed.as_byte_array::<32>()?,
                mldsa: Box::new(mldsa.as_byte_array::<MLDSA65_PUBLIC>()?),
                xwing: Box::new(xwing.as_byte_array::<XWING_PUBLIC>()?),
            },
        ))
    }
}

/// A checkpoint's record (roster.md, 2.8 The checkpoint record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Key 2: 1 without a predecessor, otherwise one more than its
    /// predecessor's.
    pub epoch: u64,
    /// Key 3: the predecessor, the checkpoint in effect in its past.
    pub previous: Option<EventId>,
    /// Key 4: every member in at the merged roster of the checkpoint's
    /// past, and every invite key out only by valid successors there,
    /// ascending by the bytes of their member references.
    pub members: Vec<MemberEntry>,
    /// Key 5: the merged space policy.
    pub policy: Policy,
    /// Key 6: each author's greatest `seq` there and its event, the smaller
    /// ID on a tie.
    pub tips: BTreeMap<DeviceId, (u64, EventId)>,
    /// Key 7: each author's fork point there.
    pub forks: BTreeMap<DeviceId, u64>,
    /// Key 8: the members the checkpoint hears, strictly ascending by
    /// device ID; empty when the key is absent.
    pub heard: Vec<HeardMember>,
}

impl Record {
    /// The record's one encoding: its members in ascending order of the
    /// bytes of their member references.
    pub fn encode(&self) -> Vec<u8> {
        let mut members: Vec<(Vec<u8>, Value)> = self
            .members
            .iter()
            .map(|entry| (entry.member.to_value().encode(), entry.to_value()))
            .collect();
        members.sort_by(|a, b| a.0.cmp(&b.0));
        let mut map = Map::new();
        map.insert(key::VERSION, Value::Unsigned(VERSION));
        map.insert(key::EPOCH, Value::Unsigned(self.epoch));
        if let Some(previous) = self.previous {
            map.insert(key::PREVIOUS, Value::Bytes(previous.0.to_vec()));
        }
        map.insert(
            key::MEMBERS,
            Value::Array(members.into_iter().map(|(_, value)| value).collect()),
        );
        map.insert(key::POLICY, Value::Bytes(self.policy.encode()));
        map.insert(
            key::TIPS,
            Value::Array(
                self.tips
                    .iter()
                    .map(|(author, (seq, id))| {
                        Value::Array(vec![
                            Value::Bytes(author.0.to_vec()),
                            Value::Unsigned(*seq),
                            Value::Bytes(id.0.to_vec()),
                        ])
                    })
                    .collect(),
            ),
        );
        map.insert(
            key::FORKS,
            Value::Array(
                self.forks
                    .iter()
                    .map(|(author, seq)| {
                        Value::Array(vec![Value::Bytes(author.0.to_vec()), Value::Unsigned(*seq)])
                    })
                    .collect(),
            ),
        );
        if !self.heard.is_empty() {
            let mut heard: Vec<&HeardMember> = self.heard.iter().collect();
            heard.sort_by_key(|h| h.device);
            map.insert(
                key::HEARD,
                Value::Array(heard.into_iter().map(HeardMember::to_value).collect()),
            );
        }
        Value::Map(map).encode()
    }

    /// The record as a checkpoint's validity compares it (roster.md, 3.15.2,
    /// step 7): each space member's keys 18 to 20 left out, since they read
    /// which key events are valid, which can read another log.
    pub fn compared(&self) -> Self {
        let mut out = self.clone();
        for entry in &mut out.members {
            entry.notices.clear();
            entry.floor = false;
            entry.named.clear();
        }
        out
    }

    /// SHA-256 of the compared encoding, without assembling that encoding.
    pub fn compared_digest(&self) -> [u8; 32] {
        self.hash_encoding(true)
    }

    /// The checkpoint record digest, without assembling the encoding.
    pub fn record_digest(&self) -> [u8; 32] {
        self.hash_encoding(false)
    }

    /// The record with each space member's keys 18 through 20 replaced.
    pub fn with_space_fields(mut self, fields: &BTreeMap<[u8; 32], crate::SpaceFields>) -> Record {
        for entry in &mut self.members {
            if entry.member.kind == MemberType::Space {
                let fields = fields.get(&entry.member.id);
                entry.notices = fields.map(|f| f.notices.clone()).unwrap_or_default();
                entry.floor = fields.is_some_and(|f| f.floor);
                entry.named = fields.map(|f| f.named.clone()).unwrap_or_default();
            }
        }
        self
    }

    fn hash_encoding(&self, compared: bool) -> [u8; 32] {
        use crate::record_stream::hash_value;
        use frasil_crypto::primitives::Sha256Hasher;
        let mut hash = Sha256Hasher::new();
        if !compared {
            hash.update(CHECKPOINT_RECORD);
        }
        let mut head = Vec::new();
        cbor::map_head(
            &mut head,
            6 + usize::from(self.previous.is_some()) + usize::from(!self.heard.is_empty()),
        );
        hash.update(&head);
        for (key, value) in [(1, VERSION), (2, self.epoch)] {
            hash_value(&mut hash, &Value::Unsigned(key));
            hash_value(&mut hash, &Value::Unsigned(value));
        }
        if let Some(previous) = self.previous {
            hash_value(&mut hash, &Value::Unsigned(3));
            hash_value(&mut hash, &Value::Bytes(previous.0.to_vec()));
        }
        hash_value(&mut hash, &Value::Unsigned(4));
        head.clear();
        cbor::array_head(&mut head, self.members.len());
        hash.update(&head);
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by_key(|e| e.member.to_value().encode());
        for entry in members {
            let mut value = entry.to_value();
            if compared && let Value::Map(map) = &mut value {
                for key in 18..=20 {
                    map.remove(&key);
                }
            }
            hash_value(&mut hash, &value);
        }
        hash_value(&mut hash, &Value::Unsigned(5));
        hash_value(&mut hash, &Value::Bytes(self.policy.encode()));
        hash_value(&mut hash, &Value::Unsigned(6));
        head.clear();
        cbor::array_head(&mut head, self.tips.len());
        hash.update(&head);
        for (author, (seq, id)) in &self.tips {
            hash_value(
                &mut hash,
                &Value::Array(vec![
                    Value::Bytes(author.0.to_vec()),
                    Value::Unsigned(*seq),
                    Value::Bytes(id.0.to_vec()),
                ]),
            );
        }
        hash_value(&mut hash, &Value::Unsigned(7));
        head.clear();
        cbor::array_head(&mut head, self.forks.len());
        hash.update(&head);
        for (author, seq) in &self.forks {
            hash_value(
                &mut hash,
                &Value::Array(vec![Value::Bytes(author.0.to_vec()), Value::Unsigned(*seq)]),
            );
        }
        if !self.heard.is_empty() {
            hash_value(&mut hash, &Value::Unsigned(8));
            head.clear();
            cbor::array_head(&mut head, self.heard.len());
            hash.update(&head);
            let mut heard: Vec<_> = self.heard.iter().collect();
            heard.sort_by_key(|h| h.device);
            for row in heard {
                hash_value(&mut hash, &row.to_value());
            }
        }
        hash.finish()
    }

    /// Reads a record, in the module's order.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `ExtensionRequired` (held),
    /// `InvalidKey` or `NotCommitted`.
    pub fn read(data: &[u8]) -> Result<Self, SpaceClass> {
        #[cfg(any(test, feature = "oracle"))]
        {
            Self::read_oracle(data)
        }
        #[cfg(not(any(test, feature = "oracle")))]
        {
            use crate::record_stream::{
                ReadRecord, RecordFault, RecordMode, RecordSink, RecordStream,
            };
            let mut sink = RecordStream::new(RecordMode::Build);
            sink.feed(data);
            match sink.finish() {
                Ok(ReadRecord::Built(record)) => Ok(record),
                Err(RecordFault::Class(class)) => Err(class),
                Err(RecordFault::Extension(_)) => Err(ErrorClass::ExtensionRequired.into()),
                _ => unreachable!(),
            }
        }
    }

    #[cfg(any(test, feature = "oracle"))]
    fn read_oracle(data: &[u8]) -> Result<Self, SpaceClass> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map
            .get(&key::VERSION)
            .ok_or_else(malformed)?
            .as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if uses_later_document(map) {
            return Err(ErrorClass::ExtensionRequired.into());
        }
        let required = [
            key::VERSION,
            key::EPOCH,
            key::MEMBERS,
            key::POLICY,
            key::TIPS,
            key::FORKS,
        ];
        if !required.iter().all(|k| map.contains_key(k))
            || !map
                .keys()
                .all(|k| required.contains(k) || *k == key::PREVIOUS || *k == key::HEARD)
        {
            return Err(malformed());
        }
        let epoch = map[&key::EPOCH].as_unsigned()?;
        if epoch < 1 || map.contains_key(&key::PREVIOUS) != (epoch > 1) {
            return Err(malformed());
        }
        let previous = map
            .get(&key::PREVIOUS)
            .map(|value| value.as_byte_array::<32>().map(EventId))
            .transpose()?;
        let policy_bytes = map[&key::POLICY].as_bytes()?;
        let mut members = Vec::new();
        let mut raws = Vec::new();
        let mut last: Option<Vec<u8>> = None;
        for item in map[&key::MEMBERS].as_array()? {
            let (entry, raw) = MemberEntry::read(item)?;
            let encoded = entry.member.to_value().encode();
            if last.as_ref().is_some_and(|last| *last >= encoded) {
                return Err(malformed());
            }
            last = Some(encoded);
            members.push(entry);
            raws.push(raw);
        }
        let mut tips = BTreeMap::new();
        for row in map[&key::TIPS].as_array()? {
            let [author, seq, id] = row.as_array()? else {
                return Err(malformed());
            };
            let author = DeviceId(author.as_byte_array::<32>()?);
            let seq = seq.as_unsigned()?;
            if seq < 1 || tips.keys().next_back().is_some_and(|last| *last >= author) {
                return Err(malformed());
            }
            tips.insert(author, (seq, EventId(id.as_byte_array::<32>()?)));
        }
        let mut forks = BTreeMap::new();
        for row in map[&key::FORKS].as_array()? {
            let [author, seq] = row.as_array()? else {
                return Err(malformed());
            };
            let author = DeviceId(author.as_byte_array::<32>()?);
            let seq = seq.as_unsigned()?;
            if seq < 1 || forks.keys().next_back().is_some_and(|last| *last >= author) {
                return Err(malformed());
            }
            forks.insert(author, seq);
        }
        // Key 8, read as members are: its shape here, its keys below.
        let mut heard_raw = Vec::new();
        if let Some(value) = map.get(&key::HEARD) {
            let rows = value.as_array()?;
            if rows.is_empty() {
                return Err(malformed());
            }
            for row in rows {
                let read = HeardMember::read(row)?;
                if heard_raw
                    .last()
                    .is_some_and(|last: &HeardRow| last.0 >= read.0)
                {
                    return Err(malformed());
                }
                heard_raw.push(read);
            }
        }
        let policy = Policy::read(policy_bytes)?;
        // Step 4, for every entry; then step 5.
        for raw in raws.iter().flatten() {
            raw.check_valid()?;
        }
        for (_, _, _, raw) in &heard_raw {
            raw.check_valid()?;
        }
        for (entry, raw) in members.iter_mut().zip(raws) {
            if let Some(raw) = raw {
                let keys = raw.into_keys();
                keys.check(&DeviceId(entry.member.id))?;
                entry.keys = Some(Arc::new(keys));
            }
        }
        let mut heard = Vec::with_capacity(heard_raw.len());
        for (device, seniority, rank, raw) in heard_raw {
            let keys = raw.into_keys();
            keys.check(&device)?;
            heard.push(HeardMember {
                device,
                seniority,
                rank,
                keys: Arc::new(keys),
            });
        }
        Ok(Self {
            epoch,
            previous,
            members,
            policy,
            tips,
            forks,
            heard,
        })
    }

    /// The record a checkpoint names, from the plaintext of its record
    /// object (roster.md, "The record object", "Reading it"): the
    /// plaintext's length is `size` and its digest `digest`, then it reads
    /// as a record whose epoch is the part's.
    ///
    /// # Errors
    ///
    /// `BadCheckpoint` when the length, the digest or the epoch differs, or
    /// the plaintext does not read as a record: the locator binds that very
    /// object, so no other can repair it. `ExtensionRequired` when the
    /// record uses a key or member type a later document defines (step 3):
    /// the checkpoint is held.
    pub fn read_object(plaintext: &[u8], part: &CheckpointPart) -> Result<Self, SpaceClass> {
        if plaintext.len() as u64 != part.size
            || part.size > MAX_RECORD_BYTES
            || digest(plaintext) != part.digest
        {
            return Err(SpaceClass::BadCheckpoint);
        }
        let record = Self::read(plaintext).map_err(|class| {
            if class.shared() == Some(ErrorClass::ExtensionRequired) {
                class
            } else {
                SpaceClass::BadCheckpoint
            }
        })?;
        if record.epoch != part.epoch {
            return Err(SpaceClass::BadCheckpoint);
        }
        Ok(record)
    }

    /// The device members at `administer`, by device ID.
    pub fn administrators(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.members
            .iter()
            .filter(|entry| entry.is_in() && entry.level == Level::Administer)
            .filter_map(|entry| entry.member.device_id())
    }

    /// The administrators a checkpoint waits for before any excuse
    /// (roster.md, 3.15.4 Votes and effect): those of the record whose
    /// capabilities do not extend `frasil.dormant`.
    pub fn electorate(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.members
            .iter()
            .filter(|entry| entry.is_in() && entry.level == Level::Administer)
            .filter(|entry| {
                !entry.capabilities.iter().any(|c| {
                    c.name == crate::checkpoint::DORMANT && c.mode == CapabilityMode::Extends
                })
            })
            .filter_map(|entry| entry.member.device_id())
    }

    /// The member entry of a member, if the record lists it.
    pub fn entry(&self, member: &MemberRef) -> Option<&MemberEntry> {
        self.members.iter().find(|entry| entry.member == *member)
    }

    /// The heard member of a device, if the record hears it (key 8).
    pub fn heard_member(&self, device: &DeviceId) -> Option<&HeardMember> {
        self.heard.iter().find(|heard| heard.device == *device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_crypto::fixtures::FixtureKeys;

    fn device(seed: u8) -> DeviceKeys {
        let signer = FixtureKeys::from_identity_seed(&[seed; 32]).signer();
        DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        }
    }

    fn entry(keys: &DeviceKeys, level: Level, height: u64) -> MemberEntry {
        MemberEntry {
            member: MemberRef::device(keys.device_id()),
            level,
            capabilities: Vec::new(),
            label: None,
            history: HistoryMode::WithHistory,
            via: Via::Code,
            session: None,
            replaces: None,
            seniority: (0, height, EventId([height as u8; 32])),
            keys: Some(Arc::new(keys.clone())),
            slot: None,
            expires_at: None,
            claims: None,
            invite: None,
            claimant: None,
            notices: Vec::new(),
            floor: false,
            named: Vec::new(),
            rank: (level == Level::Administer).then_some(crate::change::MAX_RANK),
        }
    }

    #[test]
    #[ignore = "large record memory measurement"]
    fn eighty_thousand_device_record() {
        let template = device(1);
        let mut record = record();
        record.members.clear();
        record.tips.clear();
        record.forks.clear();
        record.heard.clear();
        for index in 0..80_000u64 {
            let seed = frasil_crypto::primitives::sha256(&[&index.to_be_bytes()]);
            let keys = DeviceKeys {
                ed: frasil_crypto::device::IdentityKey(frasil_crypto::primitives::ed25519_public(
                    &seed,
                )),
                keys: template.keys.clone(),
            };
            record.members.push(entry(&keys, Level::Write, index));
        }
        let bytes = record.encode();
        eprintln!("record bytes: {}", bytes.len());
        if let Some(path) = std::env::var_os("FRASIL_RECORD_MEASUREMENT") {
            std::fs::write(path, &bytes).unwrap();
        }
        drop(record);
        let started = std::time::Instant::now();
        let read = Record::read(&bytes).unwrap();
        eprintln!("read 80000 members in {:?}", started.elapsed());
        assert_eq!(read.members.len(), 80_000);
    }

    fn invite(keys: &DeviceKeys, status: InviteStatus) -> MemberEntry {
        let mut out = entry(keys, Level::Write, 5);
        out.member = MemberRef {
            kind: MemberType::Invite,
            id: keys.device_id().0,
        };
        out.via = Via::Link;
        out.expires_at = Some(1_760_000_000);
        out.claims = Some(CLAIMS_PERSON);
        out.invite = Some(status);
        out
    }

    fn record() -> Record {
        let a = device(1);
        let b = device(2);
        let mut person = entry(&a, Level::Write, 3);
        person.member = MemberRef::person([7; 32]);
        person.keys = None;
        person.label = Some("team".into());
        let mut space = entry(&a, Level::Write, 4);
        space.member = MemberRef::space([9; 32]);
        space.keys = None;
        space.notices = vec![RecordNotice {
            rotation: EventId([3; 32]),
            public: Box::new([1; XWING_PUBLIC]),
            from_now_on: true,
            author: a.device_id(),
        }];
        space.floor = true;
        space.named = vec![EventId([3; 32]), EventId([4; 32])];
        Record {
            epoch: 1,
            previous: None,
            members: vec![
                person,
                space,
                entry(&a, Level::Administer, 0),
                entry(&b, Level::Write, 2),
                invite(&device(4), InviteStatus::Raced),
                MemberEntry::claimed(
                    Some(Arc::new(device(5))),
                    MemberRef {
                        kind: MemberType::Invite,
                        id: device(5).device_id().0,
                    },
                    MemberRef::person([8; 32]),
                ),
            ],
            policy: Policy::default(),
            tips: BTreeMap::from([(a.device_id(), (4, EventId([4; 32])))]),
            forks: BTreeMap::from([(b.device_id(), 2)]),
            heard: vec![HeardMember {
                device: device(6).device_id(),
                seniority: (0, 3, EventId([6; 32])),
                rank: 200,
                keys: Arc::new(device(6)),
            }],
        }
    }

    #[test]
    fn a_record_reads_back_in_its_one_encoding() {
        let record = record();
        let encoded = record.encode();
        let read = Record::read(&encoded).unwrap();
        assert_eq!(read.encode(), encoded);
        assert_eq!(read.members.len(), 6);
        assert_eq!(read.administrators().count(), 1);
        let claimed = read.members.iter().find(|e| e.is_claimed()).unwrap();
        assert_eq!(claimed.claimant, Some(MemberRef::person([8; 32])));
        let space = read
            .members
            .iter()
            .find(|e| e.member.kind == MemberType::Space)
            .unwrap();
        assert!(space.floor);
        assert_eq!(space.notices.len(), 1);
        assert_eq!(space.named.len(), 2);
        // The comparison leaves the space entries out.
        let compared = read.compared();
        assert!(compared.members.iter().all(|e| e.notices.is_empty()));
        assert_ne!(compared.encode(), encoded);
        // Key 8, the heard member, with its rank and keys.
        assert_eq!(read.heard, record.heard);
        // An administrator's entry carries its rank.
        let admin = read
            .members
            .iter()
            .find(|e| e.level == Level::Administer)
            .unwrap();
        assert_eq!(admin.rank, Some(crate::change::MAX_RANK));
    }

    /// Key 8 absent or not empty; a rank exactly at `administer` (key 21).
    #[test]
    fn heard_members_and_ranks_read_as_their_table_says() {
        let mut record = record();
        record.heard.clear();
        let read = Record::read(&record.encode()).unwrap();
        assert!(read.heard.is_empty());
        let mut value = cbor::decode(&record.encode()).unwrap();
        if let Value::Map(map) = &mut value {
            map.insert(key::HEARD, Value::Array(Vec::new()));
        }
        assert_eq!(
            Record::read(&value.encode()),
            Err(ErrorClass::Malformed.into())
        );
        let mut writer = record.clone();
        for entry in &mut writer.members {
            if entry.level == Level::Write {
                entry.rank = Some(3);
            }
        }
        assert_eq!(
            Record::read(&writer.encode()),
            Err(ErrorClass::Malformed.into())
        );
        let mut admin = record;
        for entry in &mut admin.members {
            if entry.level == Level::Administer {
                entry.rank = None;
            }
        }
        assert_eq!(
            Record::read(&admin.encode()),
            Err(ErrorClass::Malformed.into())
        );
    }

    #[test]
    fn the_object_binds_size_digest_and_epoch() {
        let encoded = record().encode();
        let part = CheckpointPart {
            epoch: 1,
            digest: digest(&encoded),
            size: encoded.len() as u64,
            locator: [0; 64],
        };
        assert!(Record::read_object(&encoded, &part).is_ok());
        let wrong = CheckpointPart {
            epoch: 2,
            ..part.clone()
        };
        assert_eq!(
            Record::read_object(&encoded, &wrong),
            Err(SpaceClass::BadCheckpoint)
        );
        let mut damaged = encoded.clone();
        damaged[3] ^= 1;
        assert_eq!(
            Record::read_object(&damaged, &part),
            Err(SpaceClass::BadCheckpoint)
        );
    }

    #[test]
    fn a_record_refuses_what_its_table_refuses() {
        let mut record = record();
        record.epoch = 2;
        // `previous` is missing while the epoch is above 1.
        assert_eq!(
            Record::read(&record.encode()),
            Err(ErrorClass::Malformed.into())
        );
        record.previous = Some(EventId([9; 32]));
        assert!(Record::read(&record.encode()).is_ok());
        // A device whose keys give another ID.
        let mut lying = self::record();
        let at = lying
            .members
            .iter()
            .position(|e| e.member.kind == MemberType::Device)
            .unwrap();
        lying.members[at].keys = Some(Arc::new(device(3)));
        assert_eq!(
            Record::read(&lying.encode()),
            Err(ErrorClass::NotCommitted.into())
        );
        // A floor on a device member.
        let mut floor = self::record();
        floor.members[at].floor = true;
        assert_eq!(
            Record::read(&floor.encode()),
            Err(ErrorClass::Malformed.into())
        );
        // A guest's `expires_at` without its session.
        let mut expiry = self::record();
        expiry.members[at].expires_at = Some(5);
        assert_eq!(
            Record::read(&expiry.encode()),
            Err(ErrorClass::Malformed.into())
        );
        // Another version.
        let mut map = match cbor::decode(&self::record().encode()).unwrap() {
            Value::Map(map) => map,
            _ => unreachable!(),
        };
        map.insert(key::VERSION, Value::Unsigned(2));
        assert_eq!(
            Record::read(&Value::Map(map).encode()),
            Err(ErrorClass::UnsupportedVersion.into())
        );
    }
}
