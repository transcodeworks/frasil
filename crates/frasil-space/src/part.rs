//! The roster part (roster.md, "The roster part"): a deterministic CBOR map
//! carried as a byte string at inner key 16 of a space event's sealed part.
//!
//! **The genesis**, the space event with no `log`:
//!
//! | Key | Field | Value |
//! |---|---|---|
//! | 0 | `type` | 0 |
//! | 1 | `founder` | a grant of `[0, author]` at `administer`, rank 255, with history, `via` none, the author's keys and proof; no `session`, capabilities or label |
//! | 2 | `duel_policy` | 0: ranks decide, and in a mutual pair of equal ranks the more senior stands |
//! | 3 | `policy` | the space policy |
//! | 4 | `descriptor` | the space descriptor |
//! | 5 | `system_stream` | 16 random bytes, not all zero |
//!
//! **An update**: key 0, `type` = 1, and key 1, `changes`: 1 to 256
//! changes, of which at most 64 grant a device. Nothing else.
//!
//! **A checkpoint** (roster.md, "Checkpoints"): key 0, `type` = 2; key 1,
//! `epoch`, at least 1; key 2, `digest`, bytes(32); key 3, `size`, at most
//! 268,435,456 (`TooLarge`); key 4, `locator`, bytes(64). Nothing else. It
//! rotates and is never a genesis. **Types from 3** are later documents':
//! a replica that lacks them holds the event (`ExtensionRequired`, roster.md,
//! 3.16 Rules this replica lacks).
//!
//! [`RosterPart::read`] runs steps 6 to 10 of roster.md's "The event alone"
//! on the roster part, in order:
//!
//! ```text
//!  6. A map whose key 0 is 0, 1 or 2, 0 exactly in a genesis; a key
//!     0 from 3 is held.                                            else Malformed / ExtensionRequired
//!     A checkpoint: its keys, its size at most the bound; it
//!     rotates.                                                     else Malformed / TooLarge
//!  7. A genesis: keys 0 to 5 with their types; its founder change
//!     as a change, with a valid proof, and as the table says;      else Malformed / that class
//!     duel_policy 0;                                               else UnknownPolicy
//!     its policy and descriptor.                                   else that class
//!  8. An update: keys 0 and 1; 1 to 256 changes, at most 64 of
//!     them grants of a device.                                     else Malformed
//!  9. Each change, in order (`Change::read`).                       else that class
//! 10. Each member named at most once; at most one policy change;
//!     replaces only beside a removal of the person it names;       else Malformed
//!     an event that removes its own author does not rotate.        else SelfRotation
//!     With ext-invite-links.md, a successor's change is its only
//!     one, and it does not rotate.                                 else Malformed
//! ```
//!
//! Whether a genesis has a roster part, a genesis cites nothing, and key 15
//! appears only on an update are the sealed part's checks
//! ([`crate::screen`]).

use crate::change::{Change, Op};
use crate::member::{HistoryMode, Level, MemberRef, MemberType, Via};
use crate::policy::{Descriptor, Policy};
use crate::{Limits, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;

/// The genesis's `type`.
pub const GENESIS: u64 = 0;
/// An update's `type`.
pub const UPDATE: u64 = 1;
/// A checkpoint's `type` (roster.md, "Checkpoints").
pub const CHECKPOINT: u64 = 2;
/// The largest record a checkpoint names, in bytes: 256 MiB.
pub const MAX_RECORD_BYTES: u64 = 256 * 1024 * 1024;
/// A record object's locator's length (units.md, "Objects").
pub const LOCATOR_BYTES: usize = 64;
/// Duel policy 0: ranks decide, and in a mutual pair of equal ranks the
/// more senior's lowering stands (roster.md, 3.5.2). Every other is
/// reserved.
pub const DUEL_RANKS: u64 = 0;
/// Duel policy 0, by its earlier name: [`DUEL_RANKS`].
pub const DUEL_BOTH_STAND: u64 = DUEL_RANKS;
/// A stream ID's length (units.md), the system stream's.
pub const SYSTEM_STREAM_BYTES: usize = 16;

/// The genesis's keys.
pub mod genesis_key {
    /// `type`.
    pub const TYPE: u64 = 0;
    /// `founder`.
    pub const FOUNDER: u64 = 1;
    /// `duel_policy`.
    pub const DUEL_POLICY: u64 = 2;
    /// `policy`.
    pub const POLICY: u64 = 3;
    /// `descriptor`.
    pub const DESCRIPTOR: u64 = 4;
    /// `system_stream`.
    pub const SYSTEM_STREAM: u64 = 5;
}

/// A checkpoint's keys.
pub mod checkpoint_key {
    /// `type`.
    pub const TYPE: u64 = 0;
    /// `epoch`: the record's.
    pub const EPOCH: u64 = 1;
    /// `digest`: `SHA-256("frasil/checkpoint-record/v1" || record)`.
    pub const DIGEST: u64 = 2;
    /// `size`: the record's length in bytes.
    pub const SIZE: u64 = 3;
    /// `locator`: the locator of the object that holds the record.
    pub const LOCATOR: u64 = 4;
}

/// An update's keys.
pub mod update_key {
    /// `type`.
    pub const TYPE: u64 = 0;
    /// `changes`.
    pub const CHANGES: u64 = 1;
}

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// The genesis's roster part.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Genesis {
    /// Key 1: the founder's grant.
    pub founder: Change,
    /// Key 2: always [`DUEL_RANKS`] once read.
    pub duel_policy: u64,
    /// Key 3.
    pub policy: Policy,
    /// Key 4.
    pub descriptor: Descriptor,
    /// Key 5: the system stream's ID, sealed: to a peer it is one more
    /// stream ID.
    pub system_stream: [u8; SYSTEM_STREAM_BYTES],
}

/// An update's roster part.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Update {
    /// Key 1: 1 to 256 changes.
    pub changes: Vec<Change>,
}

/// A checkpoint's roster part (roster.md, "Checkpoints"): it binds the
/// record object by its locator, and the record by its size and digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckpointPart {
    /// Key 1: the record's epoch, at least 1.
    pub epoch: u64,
    /// Key 2: the record's digest ([`crate::checkpoint_record::digest`]).
    pub digest: [u8; 32],
    /// Key 3: the record's length in bytes, at most [`MAX_RECORD_BYTES`].
    pub size: u64,
    /// Key 4: the locator of the object that holds the record (units.md,
    /// "Objects").
    pub locator: [u8; LOCATOR_BYTES],
}

/// A roster part: the genesis's, an update's or a checkpoint's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RosterPart {
    /// Type 0.
    Genesis(Box<Genesis>),
    /// Type 1.
    Update(Update),
    /// Type 2.
    Checkpoint(CheckpointPart),
}

/// Whether a roster part is of a type from 3, which a later document
/// defines (roster.md, 3.16 Rules this replica lacks): a map whose key 0
/// is an unsigned of at least 3, in an event other than a genesis. Such a
/// part is held as `ExtensionRequired`, and with it every event of the log
/// outside its past.
pub fn is_later_rules(data: &[u8], genesis: bool) -> bool {
    if genesis {
        return false;
    }
    let Ok(value) = cbor::decode(data) else {
        return false;
    };
    let Ok(map) = value.as_map() else {
        return false;
    };
    map.get(&0)
        .and_then(|kind| kind.as_unsigned().ok())
        .is_some_and(|kind| kind > CHECKPOINT)
}

/// What reading a roster part needs of the event that carries it.
#[derive(Debug, Clone, Copy)]
pub struct PartContext<'a> {
    /// The event's author.
    pub author: &'a DeviceId,
    /// The space ID, the event's `log`; `None` in the genesis.
    pub space: Option<&'a [u8; 32]>,
    /// Whether the event rotates.
    pub rotates: bool,
    /// The limits.
    pub limits: &'a Limits,
}

impl Genesis {
    /// A genesis's roster part for a founder with these keys, an ordinary
    /// space's descriptor and duel policy 0. The founder is the device ID of
    /// its keys.
    pub fn new(
        keys: crate::DeviceKeys,
        policy: Policy,
        system_stream: [u8; SYSTEM_STREAM_BYTES],
    ) -> Self {
        Self {
            founder: Change::grant_administrator(
                keys,
                crate::change::MAX_RANK,
                HistoryMode::WithHistory,
                Via::None,
            ),
            duel_policy: DUEL_RANKS,
            policy,
            descriptor: Descriptor::ORDINARY,
            system_stream,
        }
    }

    /// Whether a founder change is the one the table asks of the genesis:
    /// a grant of the author's device at `administer` at the top rank, with
    /// history, `via` none, with its keys; no `session`, capabilities or
    /// label.
    fn founder_ok(founder: &Change, author: &DeviceId) -> bool {
        founder.op == Op::Grant
            && founder.member == Some(MemberRef::device(*author))
            && founder.level == Some(Level::Administer)
            && founder.history == Some(HistoryMode::WithHistory)
            && founder.via == Some(Via::None)
            && founder.keys.is_some()
            && founder.session.is_none()
            && founder.capabilities.is_none()
            && founder.label.is_none()
            && founder.expires_at.is_none()
            && founder.rank == Some(crate::change::MAX_RANK)
    }
}

impl RosterPart {
    /// The changes the part makes: the founder's grant in a genesis, none
    /// in a checkpoint.
    pub fn changes(&self) -> &[Change] {
        match self {
            Self::Genesis(genesis) => core::slice::from_ref(&genesis.founder),
            Self::Update(update) => &update.changes,
            Self::Checkpoint(_) => &[],
        }
    }

    /// A checkpoint's part, if this is one.
    pub fn checkpoint(&self) -> Option<&CheckpointPart> {
        match self {
            Self::Checkpoint(part) => Some(part),
            _ => None,
        }
    }

    /// The part's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        match self {
            Self::Genesis(genesis) => {
                use genesis_key as k;
                map.insert(k::TYPE, Value::Unsigned(GENESIS));
                map.insert(k::FOUNDER, genesis.founder.to_value());
                map.insert(k::DUEL_POLICY, Value::Unsigned(genesis.duel_policy));
                map.insert(k::POLICY, Value::Bytes(genesis.policy.encode()));
                map.insert(k::DESCRIPTOR, Value::Bytes(genesis.descriptor.encode()));
                map.insert(
                    k::SYSTEM_STREAM,
                    Value::Bytes(genesis.system_stream.to_vec()),
                );
            }
            Self::Update(update) => {
                map.insert(update_key::TYPE, Value::Unsigned(UPDATE));
                let changes = update.changes.iter().map(Change::to_value).collect();
                map.insert(update_key::CHANGES, Value::Array(changes));
            }
            Self::Checkpoint(part) => {
                use checkpoint_key as k;
                map.insert(k::TYPE, Value::Unsigned(CHECKPOINT));
                map.insert(k::EPOCH, Value::Unsigned(part.epoch));
                map.insert(k::DIGEST, Value::Bytes(part.digest.to_vec()));
                map.insert(k::SIZE, Value::Unsigned(part.size));
                map.insert(k::LOCATOR, Value::Bytes(part.locator.to_vec()));
            }
        }
        Value::Map(map).encode()
    }

    /// Reads and checks a roster part, steps 6 to 10 of the module's
    /// order.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `UnknownPolicy`,
    /// `ExtensionRequired`, `AdministerNotDevice`, `InvalidKey`,
    /// `NotCommitted`, `SelfRotation` or `TooLarge`.
    pub fn read(data: &[u8], context: &PartContext<'_>) -> Result<Self, SpaceClass> {
        // 6.
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let kind = map.get(&0).ok_or_else(malformed)?.as_unsigned()?;
        let genesis = context.space.is_none();
        match (kind, genesis) {
            (GENESIS, true) => read_genesis(map, context).map(|g| Self::Genesis(Box::new(g))),
            (UPDATE, false) => read_update(map, context).map(Self::Update),
            (CHECKPOINT, false) => read_checkpoint(map, context).map(Self::Checkpoint),
            // roster.md, 3.16 Rules this replica lacks.
            (kind, false) if kind > CHECKPOINT => Err(ErrorClass::ExtensionRequired.into()),
            _ => Err(malformed()),
        }
    }
}

/// Step 6 for a checkpoint: exactly its keys with their types, its size at
/// most the bound, and it rotates. That it carries no refs is the sealed
/// part's check ([`crate::screen`]).
fn read_checkpoint(map: &Map, context: &PartContext<'_>) -> Result<CheckpointPart, SpaceClass> {
    use checkpoint_key as k;
    if !map.keys().copied().eq(0..=4) {
        return Err(malformed());
    }
    let epoch = map[&k::EPOCH].as_unsigned()?;
    let digest = map[&k::DIGEST].as_byte_array::<32>()?;
    let size = map[&k::SIZE].as_unsigned()?;
    let locator = map[&k::LOCATOR].as_byte_array::<LOCATOR_BYTES>()?;
    if epoch < 1 {
        return Err(malformed());
    }
    if size > MAX_RECORD_BYTES {
        return Err(ErrorClass::TooLarge.into());
    }
    if !context.rotates {
        return Err(malformed());
    }
    Ok(CheckpointPart {
        epoch,
        digest,
        size,
        locator,
    })
}

/// Step 7.
fn read_genesis(map: &Map, context: &PartContext<'_>) -> Result<Genesis, SpaceClass> {
    use genesis_key as k;
    if !map.keys().copied().eq(0..=5) {
        return Err(malformed());
    }
    let duel_policy = map[&k::DUEL_POLICY].as_unsigned()?;
    let policy = map[&k::POLICY].as_bytes()?;
    let descriptor = map[&k::DESCRIPTOR].as_bytes()?;
    let system_stream = map[&k::SYSTEM_STREAM].as_byte_array::<SYSTEM_STREAM_BYTES>()?;
    if system_stream == [0; SYSTEM_STREAM_BYTES] {
        return Err(malformed());
    }
    let founder = Change::read(&map[&k::FOUNDER], None, context.limits)?;
    if !Genesis::founder_ok(&founder, context.author) {
        return Err(malformed());
    }
    if duel_policy != DUEL_RANKS {
        return Err(SpaceClass::UnknownPolicy);
    }
    let policy = Policy::read(policy)?;
    let descriptor = Descriptor::read(descriptor)?;
    Ok(Genesis {
        founder,
        duel_policy,
        policy,
        descriptor,
        system_stream,
    })
}

/// Whether a change, before it is read, is a grant of a device: an op of
/// 0 and a member of type 0.
fn peeks_as_device_grant(value: &Value) -> bool {
    let Value::Map(map) = value else {
        return false;
    };
    map.get(&crate::change::key::OP) == Some(&Value::Unsigned(Op::Grant.code()))
        && map
            .get(&crate::change::key::MEMBER)
            .and_then(MemberRef::peek_type)
            == Some(MemberType::Device.code())
}

/// Steps 8 to 10.
fn read_update(map: &Map, context: &PartContext<'_>) -> Result<Update, SpaceClass> {
    // 8.
    if !map.keys().copied().eq(0..=1) {
        return Err(malformed());
    }
    let items = map[&update_key::CHANGES].as_array()?;
    if items.is_empty() || items.len() > context.limits.max_changes {
        return Err(malformed());
    }
    if items
        .iter()
        .filter(|item| peeks_as_device_grant(item))
        .count()
        > context.limits.max_device_grants
    {
        return Err(malformed());
    }
    // 9.
    let changes = items
        .iter()
        .map(|item| Change::read(item, context.space, context.limits))
        .collect::<Result<Vec<_>, _>>()?;
    // 10.
    let mut members: Vec<MemberRef> = changes.iter().filter_map(|c| c.member).collect();
    members.sort_unstable();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(malformed());
    }
    if changes.iter().filter(|c| c.op == Op::Policy).count() > 1 {
        return Err(malformed());
    }
    for change in &changes {
        if let Some(replaced) = change.replaces {
            let removed = MemberRef::person(replaced);
            if !changes
                .iter()
                .any(|other| other.op == Op::Remove && other.member == Some(removed))
            {
                return Err(malformed());
            }
        }
    }
    let author = MemberRef::device(*context.author);
    if context.rotates
        && changes
            .iter()
            .any(|c| c.op == Op::Remove && c.member == Some(author))
    {
        return Err(SpaceClass::SelfRotation);
    }
    // ext-invite-links.md: a successor's one change, and it never rotates.
    #[cfg(feature = "ext-invite-links")]
    crate::ext_invite_links::check_successor_part(&changes, context.rotates)?;
    Ok(Update { changes })
}

#[cfg(test)]
mod record_size_tests {
    use super::*;
    #[test]
    fn checkpoint_record_size_bound() {
        let author = DeviceId([1; 32]);
        let limits = Limits::default();
        let context = PartContext {
            author: &author,
            space: Some(&[2; 32]),
            rotates: true,
            limits: &limits,
        };
        for size in [268_435_456, 268_435_457] {
            let mut map = Map::new();
            map.insert(0, Value::Unsigned(CHECKPOINT));
            map.insert(1, Value::Unsigned(1));
            map.insert(2, Value::Bytes(vec![0; 32]));
            map.insert(3, Value::Unsigned(size));
            map.insert(4, Value::Bytes(vec![0; 64]));
            let result = read_checkpoint(&map, &context);
            if size == 268_435_456 {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err().shared(), Some(ErrorClass::TooLarge));
            }
        }
    }
}
