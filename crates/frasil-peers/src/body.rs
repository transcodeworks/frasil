//! The storage event's body (peers.md, "Storage events").
//!
//! A storage event is an event of kind 6, under scheme 2. Its body is a
//! deterministic CBOR map that a peer reads: key 1 `version` (1), key 2
//! `type`, and keys from 3 by type.
//!
//! | Type | Keys |
//! |---|---|
//! | 0 root | 3 `twin` bytes(32); 4 `mldsa` bytes(1,952); 5 `duel_policy`; 6 `founder_mldsa` bytes(1,952); 7 `founder_signature` bytes(3,373); 8 `founder_xwing` bytes(1,216) |
//! | 1 change | 3 `twin` bytes(32); exactly one of 4 `grants`, 1 to 64 grant maps, and 5 `lower`, a slot reference; 6 `salt` bytes(32) |
//! | 2 enrol | 3 `slot`, a slot reference; 4 `mldsa` bytes(1,952); 5 `slot_mldsa` bytes(1,952); 6 `authorization` bytes(3,373); 7 `binding` bytes(3,445) |
//! | 3 disown | 3 `slot` |
//! | 4 ack | none |
//! | 5 erase | 3 `space`, the unsigned 1; keys 4 and 5 are reserved |
//! | 6 credentials | at least one of 3 `live`, 1 to 64 entry names, and 4 `recovery`, a keep list of 0 to 64 fetch keys, each strictly ascending |
//! | 7 cut | 3 `twin` bytes(32); 4 `salt` bytes(32); 5 `record` bytes(64); 6 `epoch`, from 1; 7 `slots`, 0 to 512 slot entries, strictly ascending by the bytes of their slot references; 8 `standing`, 1 to 1,024 standing entries, strictly ascending by the bytes of their slot references; keys from 9 reserved |
//! | 16 release | 3 `stream` bytes(16) |
//! | 17 restore | exactly one of 3 `stream` bytes(16) and 5 `snapshot` bytes(32) |
//!
//! A grant map is 1 `slot_ed` bytes(32), 2 `slot_mldsa_hash` bytes(32), 3
//! `token` bytes(1,171) and 4 `rank`, 0 to 255. A slot entry is `[slot
//! reference, slot_ed, slot_mldsa_hash, [epoch, height, maker], pseudonym,
//! rank]`. A standing entry is `[slot reference, order, dormant, pseudonym]`.
//!
//! Types 0 to 7 are skeleton events, signed by an administrator pseudonym;
//! 16 and 17 are writer requests, signed by a device. An erasure names the
//! whole space and nothing narrower: an erase body that carries key 4 or 5,
//! reserved for naming parts of a space, is `Malformed`.

use crate::PeersClass;
use crate::limits::{
    BINDING_BYTES, MAX_CUT_SLOTS, MAX_GRANTS, MAX_KEEP, MAX_LIVE_NAMED, MAX_STANDING,
    MAX_STORAGE_EVENT, MLDSA_BYTES, RECORD_LOCATOR_BYTES, SEALED_TOKEN_BYTES, SIGNATURE_BYTES,
    STREAM_BYTES,
};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_events::EventId;
use frasil_keys::RotationSet;

/// The body's version, key 1.
pub const VERSION: u64 = 1;

/// The body's keys shared by every type.
mod key {
    pub const VERSION: u64 = 1;
    pub const TYPE: u64 = 2;
}

/// A storage event's type, key 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StorageType {
    /// 0: the skeleton's root.
    Root,
    /// 1: a change, the twin of a roster event.
    Change,
    /// 2: an enrolment of a pseudonym into an administrator slot.
    Enrol,
    /// 3: a disown of an administrator slot.
    Disown,
    /// 4: an acknowledgement.
    Ack,
    /// 5: an erasure.
    Erase,
    /// 6: a credentials request.
    Credentials,
    /// 7: a skeleton cut, the twin of a space checkpoint.
    Cut,
    /// 16: a release, a writer request.
    Release,
    /// 17: a restore, a writer request.
    Restore,
}

impl StorageType {
    /// Every type, in code order.
    pub const ALL: [StorageType; 10] = [
        Self::Root,
        Self::Change,
        Self::Enrol,
        Self::Disown,
        Self::Ack,
        Self::Erase,
        Self::Credentials,
        Self::Cut,
        Self::Release,
        Self::Restore,
    ];

    /// The type's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Root => 0,
            Self::Change => 1,
            Self::Enrol => 2,
            Self::Disown => 3,
            Self::Ack => 4,
            Self::Erase => 5,
            Self::Credentials => 6,
            Self::Cut => 7,
            Self::Release => 16,
            Self::Restore => 17,
        }
    }

    /// The type of a code, if it is one.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The type's name, as the vectors write it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Change => "change",
            Self::Enrol => "enrol",
            Self::Disown => "disown",
            Self::Ack => "ack",
            Self::Erase => "erase",
            Self::Credentials => "credentials",
            Self::Cut => "cut",
            Self::Release => "release",
            Self::Restore => "restore",
        }
    }

    /// Types 0 to 7, signed by an administrator pseudonym.
    pub fn is_skeleton(self) -> bool {
        !self.is_writer_request()
    }

    /// Types 16 and 17, signed by a device.
    pub fn is_writer_request(self) -> bool {
        matches!(self, Self::Release | Self::Restore)
    }

    /// Changes, disowns and enrolments: the events the skeleton's
    /// resolution contests (peers.md, "The skeleton's resolution").
    pub fn is_contested(self) -> bool {
        matches!(self, Self::Change | Self::Disown | Self::Enrol)
    }

    /// Acknowledgements, erasures and credentials requests: the skeleton
    /// requests that are valid at the peer or not.
    pub fn is_request(self) -> bool {
        matches!(self, Self::Ack | Self::Erase | Self::Credentials)
    }

    /// The keys from 3 the type requires, and those it allows besides.
    fn keys(self) -> (&'static [u64], &'static [u64]) {
        match self {
            Self::Root => (&[3, 4, 5, 6, 7, 8], &[]),
            Self::Change => (&[3, 6], &[4, 5]),
            Self::Enrol => (&[3, 4, 5, 6, 7], &[]),
            Self::Disown => (&[3], &[]),
            Self::Ack => (&[], &[]),
            // Keys 4 and 5 are reserved (peers.md, "Storage events").
            Self::Erase => (&[3], &[]),
            Self::Credentials => (&[], &[3, 4]),
            Self::Cut => (&[3, 4, 5, 6, 7, 8], &[]),
            Self::Release => (&[3], &[]),
            Self::Restore => (&[], &[3, 5]),
        }
    }
}

/// `[c, index]` of a slot reference: the twin commitment of the event that
/// made the administrator slot and the slot's position among that event's
/// grants, below 64. The skeleton derivations bind these two (peers.md,
/// "Skeleton derivations"); a slot reference adds the maker ([`SlotId`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotRef {
    /// `c`, the twin commitment.
    pub commitment: [u8; 32],
    /// The index, below 64.
    pub index: u8,
}

impl SlotRef {
    /// The slot reference `[c, index]`.
    pub fn new(commitment: [u8; 32], index: u8) -> Self {
        Self { commitment, index }
    }
}

/// A slot reference (peers.md, "Storage events"): `[c, index, maker]`, which
/// names one administrator slot: the one `maker`, the root or an applied
/// change, made at `index` under its `twin` `c`. The founder's is
/// `[c(genesis), 0, the root's ID]`. A change that repeats a commitment
/// makes administrator slots of its own, which no reference to another
/// maker names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotId {
    /// `[c, index]`.
    pub reference: SlotRef,
    /// The event ID of the root or change that made it.
    pub maker: EventId,
}

impl SlotId {
    /// The slot reference `[c, index, maker]`.
    pub fn new(commitment: [u8; 32], index: u8, maker: EventId) -> Self {
        Self {
            reference: SlotRef::new(commitment, index),
            maker,
        }
    }

    /// The slot reference as CBOR: `[c, index, maker]`.
    pub fn to_value(self) -> Value {
        Value::Array(vec![
            Value::from(self.reference.commitment),
            Value::Unsigned(u64::from(self.reference.index)),
            Value::from(self.maker.0),
        ])
    }

    /// Reads a slot reference: exactly three elements, `c` and `maker` of 32
    /// bytes and `index` below 64 (else `Malformed`).
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(value: &Value) -> Result<Self, PeersClass> {
        match value.as_array()? {
            [c, index, maker] => {
                let commitment = c.as_byte_array::<32>()?;
                let index = index.as_unsigned()?;
                if index >= MAX_GRANTS as u64 {
                    return Err(malformed());
                }
                let maker = EventId(maker.as_byte_array::<32>()?);
                Ok(Self::new(commitment, index as u8, maker))
            }
            _ => Err(malformed()),
        }
    }
}

/// A grant map: an administrator slot a change grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantMap {
    /// Key 1: the administrator slot's Ed25519 key.
    pub slot_ed: [u8; 32],
    /// Key 2: the SHA-256 of the administrator slot's ML-DSA-65 key.
    pub slot_mldsa_hash: [u8; 32],
    /// Key 3: the sealed slot token, 1,171 bytes.
    pub token: Vec<u8>,
    /// Key 4: the administrator slot's rank, 0 to 255: the rank of the
    /// roster grant the change mirrors (roster.md, 2.3 Changes), which
    /// replicas check (peers.md, "What replicas check").
    pub rank: u8,
}

impl GrantMap {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(1, Value::from(self.slot_ed));
        map.insert(2, Value::from(self.slot_mldsa_hash));
        map.insert(3, Value::Bytes(self.token.clone()));
        map.insert(4, Value::Unsigned(u64::from(self.rank)));
        Value::Map(map)
    }

    fn read(value: &Value) -> Result<Self, PeersClass> {
        let map = value.as_map()?;
        if !map.keys().copied().eq(1..=4) {
            return Err(malformed());
        }
        let token = fixed(&map[&3], SEALED_TOKEN_BYTES)?;
        Ok(Self {
            slot_ed: map[&1].as_byte_array()?,
            slot_mldsa_hash: map[&2].as_byte_array()?,
            token,
            rank: read_rank(&map[&4])?,
        })
    }
}

/// A rank: an unsigned integer, 0 to 255 (else `Malformed`).
fn read_rank(value: &Value) -> Result<u8, PeersClass> {
    u8::try_from(value.as_unsigned()?).map_err(|_| malformed())
}

/// What a change does: grant administrator slots, or lower one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChangeEffect {
    /// Key 4: 1 to 64 grant maps, in the order of the roster event's
    /// changes.
    Grants(Vec<GrantMap>),
    /// Key 5: the slot reference of the administrator slot it lowers.
    Lower(SlotId),
}

/// An entry's name: `[encode_set(state), read]` (peers.md, "Entries").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryName {
    /// The entry's state.
    pub state: RotationSet,
    /// The entry's read key.
    pub read: [u8; 32],
}

impl EntryName {
    /// The bytes a credentials request orders names by:
    /// `encode_set(state) || read`.
    pub fn sort_bytes(&self) -> Vec<u8> {
        [self.state.encode().as_slice(), &self.read].concat()
    }

    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.state.encode()),
            Value::from(self.read),
        ])
    }
}

/// A slot entry's seniority, as a cut carries it: `[epoch, height,
/// maker]`. The hash of the full seniority is derived from the slot
/// reference (peers.md, "Skeleton derivations"), so the entry leaves it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CutSeniority {
    /// The epoch of the skeleton's world the administrator slot was made in:
    /// 0 before any cut.
    pub epoch: u64,
    /// The height, in that world, of the event that made it.
    pub height: u64,
    /// The event that made it.
    pub maker: EventId,
}

/// A slot entry of a cut (peers.md, "Storage events"): an administrator
/// slot in at the cut's past, with its keys, its seniority and its enrolled
/// pseudonym.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlotEntry {
    /// The slot reference.
    pub slot: SlotId,
    /// Its Ed25519 key as its grant map gave it; none for the root's slot,
    /// whose entry carries empty bytes.
    pub slot_ed: Option<[u8; 32]>,
    /// The SHA-256 of its ML-DSA-65 key as its grant map gave it; none for
    /// the root's slot.
    pub slot_mldsa_hash: Option<[u8; 32]>,
    /// Its seniority.
    pub seniority: CutSeniority,
    /// The event ID of the root or enrolment that enrolled its pseudonym,
    /// which carries the pseudonym's ML-DSA-65 key and which every holder
    /// keeps (peers.md, "Truncation"); none when none is enrolled.
    pub pseudonym: Option<EventId>,
    /// Its rank, 0 to 255: the root's slot has 255, any other its grant
    /// map's.
    pub rank: u8,
}

impl SlotEntry {
    /// The bytes the entries of a cut are ordered by: the slot reference's
    /// CBOR.
    pub fn sort_bytes(&self) -> Vec<u8> {
        self.slot.to_value().encode()
    }

    fn to_value(&self) -> Value {
        let bytes = |b: Option<[u8; 32]>| Value::Bytes(b.map(|b| b.to_vec()).unwrap_or_default());
        Value::Array(vec![
            self.slot.to_value(),
            bytes(self.slot_ed),
            bytes(self.slot_mldsa_hash),
            Value::Array(vec![
                Value::Unsigned(self.seniority.epoch),
                Value::Unsigned(self.seniority.height),
                Value::from(self.seniority.maker.0),
            ]),
            Value::Bytes(self.pseudonym.map(|id| id.0.to_vec()).unwrap_or_default()),
            Value::Unsigned(u64::from(self.rank)),
        ])
    }

    /// Reads an entry: an array of six, `slot_ed` and `slot_mldsa_hash`
    /// each empty or 32 bytes and both empty or neither, the seniority an
    /// array of two unsigned and 32 bytes, the pseudonym an event ID of 32
    /// bytes or empty, and the rank an unsigned integer up to 255 (else
    /// `Malformed`).
    fn read(value: &Value) -> Result<Self, PeersClass> {
        let [slot, slot_ed, slot_mldsa_hash, seniority, pseudonym, rank] = value.as_array()? else {
            return Err(malformed());
        };
        let rank = read_rank(rank)?;
        let slot = SlotId::read(slot)?;
        let optional = |value: &Value| -> Result<Option<[u8; 32]>, PeersClass> {
            let bytes = value.as_bytes()?;
            match bytes.len() {
                0 => Ok(None),
                32 => Ok(Some(bytes.try_into().expect("32 bytes"))),
                _ => Err(malformed()),
            }
        };
        let slot_ed = optional(slot_ed)?;
        let slot_mldsa_hash = optional(slot_mldsa_hash)?;
        if slot_ed.is_some() != slot_mldsa_hash.is_some() {
            return Err(malformed());
        }
        let [epoch, height, maker] = seniority.as_array()? else {
            return Err(malformed());
        };
        let seniority = CutSeniority {
            epoch: epoch.as_unsigned()?,
            height: height.as_unsigned()?,
            maker: EventId(maker.as_byte_array::<32>()?),
        };
        let pseudonym = optional(pseudonym)?.map(EventId);
        Ok(Self {
            slot,
            slot_ed,
            slot_mldsa_hash,
            seniority,
            pseudonym,
            rank,
        })
    }
}

/// A skeleton cut's body (peers.md, "Storage events" and "Skeleton cuts"):
/// the twin of a space checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cut {
    /// Key 3: `c(R)` of the checkpoint, as a change's twin carries it.
    pub twin: [u8; 32],
    /// Key 4: the salt `c(R)` is taken under.
    pub salt: [u8; 32],
    /// Key 5: the locator of the checkpoint's record object.
    pub record: [u8; RECORD_LOCATOR_BYTES],
    /// Key 6: the epoch, from 1.
    pub epoch: u64,
    /// Key 7: every administrator slot in at the cut's past, strictly
    /// ascending by the bytes of their slot references; at most 64.
    pub slots: Vec<SlotEntry>,
    /// Key 8: the standing entries, 1 to 128, strictly ascending by the
    /// bytes of their slot references: one for the administrator slot of
    /// each administrator of the checkpoint's record, and one for the most
    /// senior slot made for each member the checkpoint hears.
    pub standing: Vec<StandingEntry>,
}

/// A standing entry of a cut (peers.md, "Storage events"): `[slot
/// reference, order, dormant, pseudonym]`. A peer cannot derive these, since
/// it reads no roster; replicas check them against the record, and a peer
/// uses them only to know whose votes a cut waits for and who may excuse
/// whom (peers.md, "Skeleton cuts").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StandingEntry {
    /// The slot: an administrator's slot of the cut, or the most senior
    /// slot made for a member the checkpoint hears, which is out.
    pub slot: SlotId,
    /// From 1: the entry's place among the cut's entries, by the rank of
    /// each one's member, highest first, then by its seniority, most senior
    /// first. 1 outranks every other; the orders are 1 to the number of
    /// entries, with no gap for a member that has no entry.
    pub order: u64,
    /// 0 for a member whose capabilities do not extend `frasil.dormant`, or
    /// a heard member; otherwise 1, or 2 for a recovery member by the
    /// predecessor's record, or `2 + k` when, without a predecessor, its
    /// grant in the checkpoint's past was signed by a member that exactly
    /// `k - 1` entries outrank, whether or not that member has an entry.
    pub dormant: u64,
    /// For a slot that is out, the root or enrolment of the pseudonym
    /// enrolled in it, which votes for it; none when none is, and none for a
    /// slot among the cut's `slots`, whose slot entry names it. Empty bytes
    /// on the wire for none.
    pub pseudonym: Option<EventId>,
}

impl StandingEntry {
    /// The bytes the standing entries of a cut are ordered by: the slot
    /// reference's CBOR.
    pub fn sort_bytes(&self) -> Vec<u8> {
        self.slot.to_value().encode()
    }

    fn to_value(self) -> Value {
        Value::Array(vec![
            self.slot.to_value(),
            Value::Unsigned(self.order),
            Value::Unsigned(self.dormant),
            Value::Bytes(self.pseudonym.map(|id| id.0.to_vec()).unwrap_or_default()),
        ])
    }

    /// Reads an entry: an array of four, a slot reference, an order from 1,
    /// an unsigned `dormant` and a pseudonym of 32 bytes or empty (else
    /// `Malformed`).
    fn read(value: &Value) -> Result<Self, PeersClass> {
        let [slot, order, dormant, pseudonym] = value.as_array()? else {
            return Err(malformed());
        };
        let slot = SlotId::read(slot)?;
        let order = order.as_unsigned()?;
        let dormant = dormant.as_unsigned()?;
        if order == 0 {
            return Err(malformed());
        }
        let pseudonym = match pseudonym.as_bytes()? {
            [] => None,
            bytes => Some(EventId(bytes.try_into().map_err(|_| malformed())?)),
        };
        Ok(Self {
            slot,
            order,
            dormant,
            pseudonym,
        })
    }
}

/// A restore names a stream, or a snapshot unit whose collection it
/// cancels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Restored {
    /// Key 3: the stream it brings back.
    Stream([u8; 16]),
    /// Key 5: a snapshot unit's event ID.
    Snapshot([u8; 32]),
}

/// A storage event's body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageBody {
    /// 0, the root.
    Root {
        /// `c(genesis)`.
        twin: [u8; 32],
        /// The pseudonym's ML-DSA-65 key.
        mldsa: Vec<u8>,
        /// The genesis's duel policy.
        duel_policy: u64,
        /// The founder device's ML-DSA-65 key.
        founder_mldsa: Vec<u8>,
        /// The founder device's scheme-2 signature over the root statement.
        founder_signature: Vec<u8>,
        /// The founder device's X-Wing key: with `founder_mldsa`, the keys
        /// the genesis's `kc` commits to.
        founder_xwing: Vec<u8>,
    },
    /// 1, a change.
    Change {
        /// `c(R)` of the roster event it is the twin of.
        twin: [u8; 32],
        /// Key 6: the salt `c(R)` is taken under, fresh for each twin
        /// (peers.md, "Skeleton derivations").
        salt: [u8; 32],
        /// Its grants or its lower.
        effect: ChangeEffect,
    },
    /// 2, an enrolment.
    Enrol {
        /// The slot reference of the administrator slot it enrols.
        slot: SlotId,
        /// The pseudonym's ML-DSA-65 key.
        mldsa: Vec<u8>,
        /// The administrator slot's ML-DSA-65 key.
        slot_mldsa: Vec<u8>,
        /// The administrator slot keys' scheme-2 signature over the
        /// enrolment statement.
        authorization: Vec<u8>,
        /// The sealed device binding.
        binding: Vec<u8>,
    },
    /// 3, a disown.
    Disown {
        /// The slot reference of the administrator slot it lowers.
        slot: SlotId,
    },
    /// 4, an acknowledgement.
    Ack,
    /// 5, an erasure: key 3, the whole space (peers.md, "Erasure"). It
    /// names nothing narrower.
    Erase,
    /// 6, a credentials request.
    Credentials {
        /// Key 3: the entries that stay live, strictly ascending.
        live: Option<Vec<EntryName>>,
        /// Key 4: the keep list of fetch keys, strictly ascending.
        recovery: Option<Vec<[u8; 32]>>,
    },
    /// 7, a skeleton cut.
    Cut(Cut),
    /// 16, a release.
    Release {
        /// The stream it releases.
        stream: [u8; 16],
    },
    /// 17, a restore.
    Restore(Restored),
}

fn malformed() -> PeersClass {
    ErrorClass::Malformed.into()
}

/// A byte string of exactly `n` bytes.
fn fixed(value: &Value, n: usize) -> Result<Vec<u8>, PeersClass> {
    let bytes = value.as_bytes()?;
    if bytes.len() != n {
        return Err(malformed());
    }
    Ok(bytes.to_vec())
}

/// An array of 1 to `most` IDs of `N` bytes, strictly ascending; stream IDs
/// are not all zero (units.md).
fn ids<const N: usize>(value: &Value, most: usize) -> Result<Vec<[u8; N]>, PeersClass> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > most {
        return Err(malformed());
    }
    let ids = items
        .iter()
        .map(|item| item.as_byte_array::<N>())
        .collect::<Result<Vec<_>, _>>()?;
    if ids.windows(2).any(|w| w[0] >= w[1]) {
        return Err(malformed());
    }
    if N == STREAM_BYTES && ids.iter().any(|id| id.iter().all(|&b| b == 0)) {
        return Err(malformed());
    }
    Ok(ids)
}

impl StorageBody {
    /// The body's type.
    pub fn storage_type(&self) -> StorageType {
        match self {
            Self::Root { .. } => StorageType::Root,
            Self::Change { .. } => StorageType::Change,
            Self::Enrol { .. } => StorageType::Enrol,
            Self::Disown { .. } => StorageType::Disown,
            Self::Ack => StorageType::Ack,
            Self::Erase => StorageType::Erase,
            Self::Credentials { .. } => StorageType::Credentials,
            Self::Cut(_) => StorageType::Cut,
            Self::Release { .. } => StorageType::Release,
            Self::Restore(_) => StorageType::Restore,
        }
    }

    /// The slot reference of the administrator slot a lower or a disown
    /// lowers.
    pub fn lowered(&self) -> Option<SlotId> {
        match self {
            Self::Change {
                effect: ChangeEffect::Lower(slot),
                ..
            }
            | Self::Disown { slot } => Some(*slot),
            _ => None,
        }
    }

    /// The grants of a change.
    pub fn grants(&self) -> &[GrantMap] {
        match self {
            Self::Change {
                effect: ChangeEffect::Grants(grants),
                ..
            } => grants,
            _ => &[],
        }
    }

    /// A cut's fields.
    pub fn cut(&self) -> Option<&Cut> {
        match self {
            Self::Cut(cut) => Some(cut),
            _ => None,
        }
    }

    /// The stream a writer request names, if it names one.
    pub fn stream(&self) -> Option<[u8; 16]> {
        match self {
            Self::Release { stream } | Self::Restore(Restored::Stream(stream)) => Some(*stream),
            _ => None,
        }
    }

    /// The body's deterministic CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(key::VERSION, Value::Unsigned(VERSION));
        map.insert(key::TYPE, Value::Unsigned(self.storage_type().code()));
        match self {
            Self::Root {
                twin,
                mldsa,
                duel_policy,
                founder_mldsa,
                founder_signature,
                founder_xwing,
            } => {
                map.insert(3, Value::from(*twin));
                map.insert(4, Value::Bytes(mldsa.clone()));
                map.insert(5, Value::Unsigned(*duel_policy));
                map.insert(6, Value::Bytes(founder_mldsa.clone()));
                map.insert(7, Value::Bytes(founder_signature.clone()));
                map.insert(8, Value::Bytes(founder_xwing.clone()));
            }
            Self::Change { twin, salt, effect } => {
                map.insert(3, Value::from(*twin));
                map.insert(6, Value::from(*salt));
                match effect {
                    ChangeEffect::Grants(grants) => {
                        map.insert(
                            4,
                            Value::Array(grants.iter().map(GrantMap::to_value).collect()),
                        );
                    }
                    ChangeEffect::Lower(slot) => {
                        map.insert(5, slot.to_value());
                    }
                }
            }
            Self::Enrol {
                slot,
                mldsa,
                slot_mldsa,
                authorization,
                binding,
            } => {
                map.insert(3, slot.to_value());
                map.insert(4, Value::Bytes(mldsa.clone()));
                map.insert(5, Value::Bytes(slot_mldsa.clone()));
                map.insert(6, Value::Bytes(authorization.clone()));
                map.insert(7, Value::Bytes(binding.clone()));
            }
            Self::Disown { slot } => {
                map.insert(3, slot.to_value());
            }
            Self::Ack => {}
            Self::Erase => {
                map.insert(3, Value::Unsigned(1));
            }
            Self::Credentials { live, recovery } => {
                if let Some(live) = live {
                    map.insert(
                        3,
                        Value::Array(live.iter().map(EntryName::to_value).collect()),
                    );
                }
                if let Some(recovery) = recovery {
                    map.insert(
                        4,
                        Value::Array(recovery.iter().map(|k| Value::from(*k)).collect()),
                    );
                }
            }
            Self::Cut(cut) => {
                map.insert(3, Value::from(cut.twin));
                map.insert(4, Value::from(cut.salt));
                map.insert(5, Value::Bytes(cut.record.to_vec()));
                map.insert(6, Value::Unsigned(cut.epoch));
                map.insert(
                    7,
                    Value::Array(cut.slots.iter().map(SlotEntry::to_value).collect()),
                );
                map.insert(
                    8,
                    Value::Array(cut.standing.iter().map(|e| e.to_value()).collect()),
                );
            }
            Self::Release { stream } => {
                map.insert(3, Value::from(*stream));
            }
            Self::Restore(Restored::Stream(stream)) => {
                map.insert(3, Value::from(*stream));
            }
            Self::Restore(Restored::Snapshot(snapshot)) => {
                map.insert(5, Value::from(*snapshot));
            }
        }
        Value::Map(map).encode()
    }

    /// Reads a body, in order (peers.md, "Storage events"): deterministic
    /// CBOR, a map with key 1 (else `Malformed`); `version` 1 (else
    /// `UnsupportedVersion`); a known type (else `Malformed`); a cut with
    /// a key from 9 is held as `ExtensionRequired`, without reading its
    /// fields; otherwise exactly the keys the type allows, with their types, lengths, orders and bounds,
    /// and stream IDs as units.md reads them (else `Malformed`); every
    /// Ed25519 key valid, and a root's `founder_xwing` valid (else
    /// `InvalidKey`).
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `ExtensionRequired` or `InvalidKey`.
    pub fn read(data: &[u8]) -> Result<Self, PeersClass> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map
            .get(&key::VERSION)
            .ok_or_else(malformed)?
            .as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let code = map.get(&key::TYPE).ok_or_else(malformed)?.as_unsigned()?;
        let kind = StorageType::from_code(code).ok_or_else(malformed)?;
        if kind == StorageType::Cut
            && map
                .keys()
                .any(|&key| key >= crate::limits::RESERVED_CUT_KEY)
        {
            return Err(ErrorClass::ExtensionRequired.into());
        }
        let (required, optional) = kind.keys();
        let present: Vec<u64> = map
            .keys()
            .copied()
            .filter(|&k| k != key::VERSION && k != key::TYPE)
            .collect();
        if !required.iter().all(|k| present.contains(k))
            || !present
                .iter()
                .all(|k| required.contains(k) || optional.contains(k))
        {
            return Err(malformed());
        }
        let body = Self::read_fields(kind, map)?;
        body.check_keys()?;
        Ok(body)
    }

    /// The fields of a type whose keys are exactly those it allows.
    fn read_fields(kind: StorageType, map: &Map) -> Result<Self, PeersClass> {
        let at = |k: u64| &map[&k];
        Ok(match kind {
            StorageType::Root => Self::Root {
                twin: at(3).as_byte_array()?,
                mldsa: fixed(at(4), MLDSA_BYTES)?,
                // roster.md, "The genesis": every duel policy other than 0
                // is reserved.
                duel_policy: match at(5).as_unsigned()? {
                    0 => 0,
                    _ => return Err(malformed()),
                },
                founder_mldsa: fixed(at(6), MLDSA_BYTES)?,
                founder_signature: fixed(at(7), SIGNATURE_BYTES)?,
                founder_xwing: fixed(at(8), XWING_PUBLIC)?,
            },
            StorageType::Change => {
                let twin = at(3).as_byte_array()?;
                let salt = at(6).as_byte_array()?;
                let effect = match (map.get(&4), map.get(&5)) {
                    (Some(grants), None) => {
                        let items = grants.as_array()?;
                        if items.is_empty() || items.len() > MAX_GRANTS {
                            return Err(malformed());
                        }
                        ChangeEffect::Grants(
                            items.iter().map(GrantMap::read).collect::<Result<_, _>>()?,
                        )
                    }
                    (None, Some(lower)) => ChangeEffect::Lower(SlotId::read(lower)?),
                    _ => return Err(malformed()),
                };
                Self::Change { twin, salt, effect }
            }
            StorageType::Enrol => Self::Enrol {
                slot: SlotId::read(at(3))?,
                mldsa: fixed(at(4), MLDSA_BYTES)?,
                slot_mldsa: fixed(at(5), MLDSA_BYTES)?,
                authorization: fixed(at(6), SIGNATURE_BYTES)?,
                binding: fixed(at(7), BINDING_BYTES)?,
            },
            StorageType::Disown => Self::Disown {
                slot: SlotId::read(at(3))?,
            },
            StorageType::Ack => Self::Ack,
            StorageType::Erase => {
                if at(3).as_unsigned()? != 1 {
                    return Err(malformed());
                }
                Self::Erase
            }
            StorageType::Credentials => {
                if !map.contains_key(&3) && !map.contains_key(&4) {
                    return Err(malformed());
                }
                let live = map.get(&3).map(read_live).transpose()?;
                let recovery = map.get(&4).map(read_keep).transpose()?;
                Self::Credentials { live, recovery }
            }
            StorageType::Cut => {
                let twin = at(3).as_byte_array()?;
                let salt = at(4).as_byte_array()?;
                let record = at(5).as_byte_array::<RECORD_LOCATOR_BYTES>()?;
                let epoch = at(6).as_unsigned()?;
                let items = at(7).as_array()?;
                if epoch == 0 || items.len() > MAX_CUT_SLOTS {
                    return Err(malformed());
                }
                let slots = items
                    .iter()
                    .map(SlotEntry::read)
                    .collect::<Result<Vec<_>, _>>()?;
                let order: Vec<Vec<u8>> = slots.iter().map(SlotEntry::sort_bytes).collect();
                if order.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(malformed());
                }
                let items = at(8).as_array()?;
                if items.is_empty() || items.len() > MAX_STANDING {
                    return Err(malformed());
                }
                let standing = items
                    .iter()
                    .map(StandingEntry::read)
                    .collect::<Result<Vec<_>, _>>()?;
                let order: Vec<Vec<u8>> = standing.iter().map(StandingEntry::sort_bytes).collect();
                if order.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(malformed());
                }
                Self::Cut(Cut {
                    twin,
                    salt,
                    record,
                    epoch,
                    slots,
                    standing,
                })
            }
            StorageType::Release => Self::Release {
                stream: ids::<16>(&Value::Array(vec![at(3).clone()]), 1)?[0],
            },
            StorageType::Restore => match (map.get(&3), map.get(&5)) {
                (Some(stream), None) => Self::Restore(Restored::Stream(
                    ids::<16>(&Value::Array(vec![stream.clone()]), 1)?[0],
                )),
                (None, Some(snapshot)) => {
                    Self::Restore(Restored::Snapshot(snapshot.as_byte_array()?))
                }
                _ => return Err(malformed()),
            },
        })
    }

    /// The last step: every Ed25519 key the body names is valid.
    fn check_keys(&self) -> Result<(), PeersClass> {
        match self {
            Self::Root { founder_xwing, .. } => {
                xwing_valid(founder_xwing)?;
            }
            Self::Change {
                effect: ChangeEffect::Grants(grants),
                ..
            } => {
                for grant in grants {
                    ed25519_valid(&grant.slot_ed)?;
                }
            }
            Self::Cut(cut) => {
                for slot_ed in cut.slots.iter().filter_map(|entry| entry.slot_ed) {
                    ed25519_valid(&slot_ed)?;
                }
            }
            Self::Credentials { live, recovery } => {
                for name in live.iter().flatten() {
                    ed25519_valid(&name.read)?;
                }
                for key in recovery.iter().flatten() {
                    ed25519_valid(key)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Key 3 of a credentials request: 1 to 64 entry names, strictly ascending
/// by `encode_set(state) || read`.
fn read_live(value: &Value) -> Result<Vec<EntryName>, PeersClass> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_LIVE_NAMED {
        return Err(malformed());
    }
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        let [state, read] = item.as_array()? else {
            return Err(malformed());
        };
        let state = RotationSet::decode(state.as_bytes()?).map_err(|_| malformed())?;
        names.push(EntryName {
            state,
            read: read.as_byte_array()?,
        });
    }
    let order: Vec<Vec<u8>> = names.iter().map(EntryName::sort_bytes).collect();
    if order.windows(2).any(|w| w[0] >= w[1]) {
        return Err(malformed());
    }
    Ok(names)
}

/// Key 4 of a credentials request: a keep list of 0 to 64 fetch keys,
/// strictly ascending.
fn read_keep(value: &Value) -> Result<Vec<[u8; 32]>, PeersClass> {
    let items = value.as_array()?;
    if items.len() > MAX_KEEP {
        return Err(malformed());
    }
    let keys = items
        .iter()
        .map(|item| item.as_byte_array::<32>())
        .collect::<Result<Vec<_>, _>>()?;
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return Err(malformed());
    }
    Ok(keys)
}

/// peers.md, "Limits": a signed storage event over 262,144 bytes is
/// `TooLarge`.
///
/// # Errors
///
/// `TooLarge`.
pub fn check_size(signed_len: usize) -> Result<(), PeersClass> {
    if signed_len > MAX_STORAGE_EVENT {
        return Err(ErrorClass::TooLarge.into());
    }
    Ok(())
}
