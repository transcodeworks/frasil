//! The tables, their items and their values (at-rest.md, "Tables", "The
//! head, events and keys").
//!
//! Each table has a code, a scope (device-wide or a log's), a rule for its
//! item, and a value that must parse exactly. [`check_item`] is the item
//! rule, [`TableValue::read`] the value's, and [`TableValue::encode`] gives
//! the one encoding [`TableValue::read`] accepts.

use frasil_base::ErrorClass;
use frasil_base::cbor::{self, KeyRules, Map, UnknownKeys, Value};
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_events::envelope::{KEY_LOG, event_id};
use frasil_keys::RotationSet;
use zeroize::Zeroizing;

/// The most tips a head holds.
pub const MAX_TIPS: usize = 65_536;
/// The most heads an `ack` record holds.
pub const MAX_ACK_HEADS: usize = 256;
/// The most base heads a `state` record holds.
pub const MAX_BASE_HEADS: usize = 256;
/// The most grants `state` key 4 keeps: a leave request names 1 to 64
/// (ext-guests.md).
pub const MAX_LEFT_GRANTS: usize = 64;
/// The longest item of a `host` record.
pub const MAX_HOST_ITEM: usize = 256;

/// The longest `endpoint` value: a ticket's most bytes (transport.md,
/// "Tickets").
pub const MAX_ENDPOINT_VALUE: usize = 1_024;
/// The most peer hints a `peers` record keeps, as a welcome's
/// (admission.md, "The welcome").
pub const MAX_PEER_HINTS: usize = 8;
/// The longest peer hint or home peer a `peers` record keeps, in UTF-8
/// bytes.
pub const MAX_PEER_URL: usize = 512;
/// The longest object part after the header: one chunk as received
/// (units.md).
pub const MAX_CHUNK: usize = 1_048_576;
/// The shortest object chunk as received: a nonce and a tag (units.md).
pub const MIN_CHUNK: usize = 24 + 16;
/// The longest verdict class an `event` record keeps, in UTF-8 bytes.
pub const MAX_CLASS: usize = 64;
/// The largest object a header may declare (units.md).
pub const MAX_OBJECT_SIZE: u64 = 1 << 40;
/// The longest token of a `held` record (at-rest.md, "Held objects").
pub const MAX_HELD_TOKEN: usize = 1_024;
/// The longest change stamp of a `held` record.
pub const MAX_HELD_STAMP: usize = 64;
/// The most issuing keys a `deposit_keys` record keeps: the newest
/// (ext-deposit-tokens.md, 3.2 Learning a peer's keys).
pub const MAX_SEEN_KEYS: usize = 64;
/// The bytes of a deposit token (ext-deposit-tokens.md, 2.4 Tokens).
pub const TOKEN_BYTES: usize = 129;
/// The largest mailbox item (transport.md, "Mailboxes").
pub const MAX_MAILBOX_ITEM: usize = 262_144;
/// The most peers a `welcome` record names as holding its welcome, and
/// the most peers its welcome is deposited at.
pub const MAX_WELCOME_PEERS: usize = 64;
/// The most deposits of a waiting welcome at one peer: the first and three
/// repeats, `welcome_redeposit` apart (admission.md, 3.10 Welcomes, "A
/// welcome that waits").
pub const WELCOME_DEPOSITS: u8 = 4;
/// The number of administrator slots; a slot reference's index is below it
/// (peers.md).
pub const MAX_SLOT_INDEX: u64 = 64;
/// The most rotations in a rotation set (keys.md, "Rotations and states").
pub const MAX_ROTATIONS: usize = frasil_keys::limits::MAX_ROTATIONS;
/// A recipient bundle (keys.md, "The recipient bundle").
pub const BUNDLE_BYTES: usize = frasil_keys::limits::BUNDLE_BYTES;

/// Whether a table is device-wide or a log's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// A device-wide table, under 16 zero bytes and the store secret.
    Device,
    /// A log's table, under the log's scope tag and its log key.
    Log,
}

macro_rules! tables {
    ($( $(#[$doc:meta])* $variant:ident = $code:literal, $name:literal, $scope:ident; )*) => {
        /// A table (at-rest.md, "Tables"). Every other code is `Malformed`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Table {
            $( $(#[$doc])* $variant, )*
        }

        impl Table {
            /// Every table, in the order of at-rest.md's table.
            pub const ALL: &'static [Table] = &[ $( Table::$variant, )* ];

            /// The table's code, its byte in an address.
            pub fn code(self) -> u8 {
                match self {
                    $( Self::$variant => $code, )*
                }
            }

            /// The table of this code, if it is one.
            pub fn from_code(code: u8) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )*
                    _ => None,
                }
            }

            /// The table's name, as at-rest.md writes it.
            pub fn name(self) -> &'static str {
                match self {
                    $( Self::$variant => $name, )*
                }
            }

            /// Whether the table is device-wide or a log's.
            pub fn scope(self) -> Scope {
                match self {
                    $( Self::$variant => Scope::$scope, )*
                }
            }
        }
    };
}

tables! {
    /// `0x00`, the head: the store's ID, the generation and the tips.
    Head = 0x00, "head", Device;
    /// `0x01`, a log's kind and log key `L`, by log ID.
    Log = 0x01, "log", Device;
    /// `0x02`, the last kept reading (overview.md, "The local timeline").
    Timeline = 0x02, "timeline", Device;
    /// `0x03`, the ephemeral epoch (ext-ephemeral.md).
    Epoch = 0x03, "epoch", Device;
    /// `0x04`, the seed of the member endpoint key this device announced as
    /// its next (ext-next-endpoints.md).
    NextEndpoint = 0x04, "next_endpoint", Device;
    /// `0x05`, what the device keeps of a peer's deposit keys, by the
    /// peer's ID (ext-deposit-tokens.md, 3.2 Learning a peer's keys).
    DepositKeys = 0x05, "deposit_keys", Device;
    /// `0x06`, an unspent deposit token, by the peer's ID and the token's
    /// nonce (ext-deposit-tokens.md, 3.5 Finishing issuance).
    Token = 0x06, "token", Device;
    /// `0x07`, a deposit in a device mailbox that a peer has not accepted
    /// yet (transport.md, "A sender keeps what was refused").
    Deposit = 0x07, "deposit", Device;
    /// `0x10`, an event, its state, flags, verdict class and first sight.
    Event = 0x10, "event", Log;
    /// `0x11`, an object's header or one of its chunks (units.md).
    Object = 0x11, "object", Log;
    /// `0x12`, a key: a rotation's secrets, a state received whole, a body
    /// key or a gap key.
    Key = 0x12, "key", Log;
    /// `0x13`, an event this device signed that is not yet durable.
    Outbox = 0x13, "outbox", Log;
    /// `0x14`, the heads a peer last acknowledged.
    Ack = 0x14, "ack", Log;
    /// `0x15`, a cache of the `StreamHeads` a peer served, and when.
    Listing = 0x15, "listing", Log;
    /// `0x16`, the log's base and its last completed sync.
    State = 0x16, "state", Log;
    /// `0x17`, an administrator pseudonym (peers.md).
    Pseudonym = 0x17, "pseudonym", Log;
    /// `0x18`, an invite this device made (ext-invite-links.md).
    Invite = 0x18, "invite", Log;
    /// `0x19`, a link this device claimed (ext-invite-links.md).
    Claim = 0x19, "claim", Log;
    /// `0x1a`, a sender's replay window (ext-ephemeral.md).
    Replay = 0x1a, "replay", Log;
    /// `0x1b`, a list member this device decided `Vouched` in the space
    /// (ext-recovery-agent.md).
    Vouched = 0x1b, "vouched", Log;
    /// `0x1c`, the member ticket at which this device last reached a member
    /// of the space, never one only learned from another member
    /// (transport.md, "Reconnecting" and "Member addresses").
    Endpoint = 0x1c, "endpoint", Log;
    /// `0x1d`, a held object: the application's token for its plaintext,
    /// the plaintext's length and the application's change stamp
    /// (at-rest.md, "Held objects").
    Held = 0x1d, "held", Log;
    /// `0x1e`, the always-on peers of the space this device knows, and its
    /// library's home peer (admission.md, "The welcome"; ext-libraries.md,
    /// "The home peer").
    Peers = 0x1e, "peers", Log;
    /// `0x1f`, the next member endpoint key a member announced in the space
    /// (ext-next-endpoints.md).
    Announced = 0x1f, "announced", Log;
    /// `0x20`, what a device that hosts the space as an always-on peer keeps
    /// (peers.md).
    Host = 0x20, "host", Log;
    /// `0x21`, an event of the log in the past of its kept checkpoint that
    /// this device does not hold: dropped by it, or answered `Missing` by a
    /// peer (at-rest.md, "Forgetting before a checkpoint").
    Dropped = 0x21, "dropped", Log;
    /// `0x22`, how long this device keeps an object it stores as sealed
    /// chunks: until the application drops it, or within the device's
    /// budget (at-rest.md, "Retention").
    Retention = 0x22, "retention", Log;
    /// `0x23`, a welcome this device signed that waits to be handed over a
    /// member connection or deposited at a peer, by its newcomer's device
    /// ID (admission.md, 3.10 Welcomes, "A welcome that waits").
    Welcome = 0x23, "welcome", Log;
}

// ---------------------------------------------------------------------------
// Secrets.

/// A 32-byte secret kept in a record: zeroed on drop, and never printed by
/// `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    /// The secret of these bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret's bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(..)")
    }
}

// ---------------------------------------------------------------------------
// Items.

/// Whether `data` is exactly one rotation set, as frasil-keys reads it, of
/// at least `minimum` rotations.
fn rotation_set_ok(data: &[u8], minimum: usize) -> bool {
    RotationSet::decode(data).is_ok_and(|set| set.len() >= minimum)
}

/// Whether an item is a slot reference, `[c, index, maker]`: a 32-byte
/// twin commitment, an index below 64 and the 32-byte event ID of the event
/// that made the administrator slot, in deterministic CBOR (peers.md).
pub fn slot_reference_ok(item: &[u8]) -> bool {
    let Ok(Value::Array(parts)) = cbor::decode(item) else {
        return false;
    };
    matches!(
        parts.as_slice(),
        [Value::Bytes(c), Value::Unsigned(index), Value::Bytes(maker)]
            if c.len() == 32 && *index < MAX_SLOT_INDEX && maker.len() == 32
    )
}

/// The key kinds of the `key` table (at-rest.md, "The head, events and
/// keys").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Kind 1: a rotation's secrets, named by its rotation ID.
    Rotation,
    /// Kind 2: a merged state's secrets received whole by wrap, named by
    /// `encode_set(S)` of at least two rotations; provisional.
    StateReceivedWhole,
    /// Kind 3: a body key, named by its event's ID.
    BodyKey,
    /// Kind 4: a gap key, named by `u8(gap kind) || encode_set(B)`.
    GapKey,
    /// Kind 5: a checkpoint's record object key, named by the checkpoint's
    /// event ID.
    RecordKey,
}

impl KeyKind {
    /// The kind's byte, the item's first.
    pub fn code(self) -> u8 {
        match self {
            Self::Rotation => 1,
            Self::StateReceivedWhole => 2,
            Self::BodyKey => 3,
            Self::GapKey => 4,
            Self::RecordKey => 5,
        }
    }

    /// The kind of this byte, if it is one.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Rotation),
            2 => Some(Self::StateReceivedWhole),
            3 => Some(Self::BodyKey),
            4 => Some(Self::GapKey),
            5 => Some(Self::RecordKey),
            _ => None,
        }
    }
}

/// Step 7 for an `object` record (at-rest.md, the `object` table): part 0 a
/// header that names the item's object, any other part a chunk of a sealed
/// chunk's lengths.
///
/// # Errors
///
/// `Malformed` otherwise.
pub fn check_object_value(item: &[u8], value: &[u8]) -> Result<(), ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let part: [u8; 4] = item
        .get(32..)
        .and_then(|p| p.try_into().ok())
        .ok_or(malformed)?;
    if u32::from_be_bytes(part) == 0 {
        let header = map_with(value, &[1, 2, 3, 4], &[])?;
        if header[&1] != Value::Unsigned(1)
            || header[&2].as_bytes()? != &item[..32]
            || header[&4].as_unsigned()? > MAX_OBJECT_SIZE
        {
            return Err(malformed);
        }
        header[&3].as_bytes()?;
    } else if !(MIN_CHUNK..=MAX_CHUNK).contains(&value.len()) {
        return Err(malformed);
    }
    Ok(())
}

/// Whether an item follows its table's rule (at-rest.md, "Tables").
///
/// # Errors
///
/// `Malformed` if it does not.
pub fn check_item(table: Table, item: &[u8]) -> Result<(), ErrorClass> {
    let ok = match table {
        Table::Head
        | Table::Timeline
        | Table::Epoch
        | Table::NextEndpoint
        | Table::State
        | Table::Peers => item.is_empty(),
        Table::Log
        | Table::Event
        | Table::Ack
        | Table::Listing
        | Table::Replay
        | Table::Vouched
        | Table::Endpoint
        | Table::Announced
        | Table::Held
        | Table::Invite
        | Table::Claim
        | Table::DepositKeys
        | Table::Dropped
        | Table::Retention
        | Table::Welcome => item.len() == 32,
        Table::Token => item.len() == 64,
        Table::Deposit => item.len() == 16,
        Table::Object => item.len() == 36,
        Table::Outbox => {
            item.len() == 40 && u64::from_be_bytes(item[32..].try_into().unwrap_or([0; 8])) >= 1
        }
        Table::Pseudonym => slot_reference_ok(item),
        Table::Host => (1..=MAX_HOST_ITEM).contains(&item.len()),
        Table::Key => match item.split_first() {
            Some((&kind, rest)) => match KeyKind::from_code(kind) {
                Some(KeyKind::Rotation | KeyKind::BodyKey | KeyKind::RecordKey) => rest.len() == 32,
                Some(KeyKind::StateReceivedWhole) => rotation_set_ok(rest, 2),
                Some(KeyKind::GapKey) => match rest.split_first() {
                    Some((&gap, set)) => matches!(gap, 1 | 2) && rotation_set_ok(set, 1),
                    None => false,
                },
                None => false,
            },
            None => false,
        },
    };
    if ok {
        Ok(())
    } else {
        Err(ErrorClass::Malformed)
    }
}

// ---------------------------------------------------------------------------
// Values.

/// A tip: the newest event a signer of this device signed in a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tip {
    /// The log's ID.
    pub log: [u8; 32],
    /// The signer's device ID: the device itself, an administrator
    /// pseudonym it holds, or an invite key it claimed with.
    pub author: DeviceId,
    /// The event's `seq`, from 1.
    pub seq: u64,
    /// The event's ID.
    pub event: [u8; 32],
}

impl Tip {
    fn order_key(&self) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&self.log);
        key[32..].copy_from_slice(&self.author.0);
        key
    }
}

/// What the head keeps after a restore: the generation at which it was
/// found, and the logs synced since.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Restore {
    /// Key 4: the generation at which the restore was found, 1 to the
    /// head's generation.
    pub found_at: u64,
    /// Key 5: the logs synced since that restore, strictly ascending.
    pub synced: Vec<[u8; 32]>,
}

/// The `head` record (at-rest.md, "The head, events and keys").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Head {
    /// Key 1: the store's ID, 16 random bytes drawn when the store is made.
    pub store_id: [u8; 16],
    /// Key 2: the generation, from 1.
    pub generation: u64,
    /// Key 3: the tips, strictly ascending by `log ID || author`.
    pub tips: Vec<Tip>,
    /// Keys 4 and 5, after a restore.
    pub restore: Option<Restore>,
    /// Key 6: the revision the store was made under, `None` for a
    /// store made before the head recorded one (overview.md, "Version
    /// policy").
    pub revision: Option<u64>,
}

impl Head {
    /// The head of a new store: its ID, generation 1, no tip.
    pub fn new(store_id: [u8; 16]) -> Self {
        Self {
            store_id,
            generation: 1,
            tips: Vec::new(),
            restore: None,
            revision: Some(frasil_base::version::REVISION),
        }
    }

    /// Checks the head's revision before the store is used (at-rest.md,
    /// "Continuity"): a head without one, or of another, refuses the store.
    ///
    /// # Errors
    ///
    /// `RevisionMismatch` unless key 6 is this implementation's revision.
    pub fn check_revision(&self) -> Result<(), ErrorClass> {
        frasil_base::version::check_revision(self.revision.unwrap_or(0))
    }

    /// The tip of a signer of this device in a log. The next event it signs
    /// there takes the tip's `seq` plus 1 and names the tip's event as
    /// `prev`; the device reads them from the tips and nowhere else.
    pub fn tip(&self, log: &[u8; 32], author: &DeviceId) -> Option<&Tip> {
        let key = Tip {
            log: *log,
            author: *author,
            seq: 0,
            event: [0; 32],
        }
        .order_key();
        self.tips
            .binary_search_by(|tip| tip.order_key().cmp(&key))
            .ok()
            .map(|index| &self.tips[index])
    }

    /// Sets the tip of a signer in a log, keeping the order.
    ///
    /// # Errors
    ///
    /// `TooLarge` if it would be a 65,537th tip.
    pub fn set_tip(&mut self, tip: Tip) -> Result<(), ErrorClass> {
        let key = tip.order_key();
        match self.tips.binary_search_by(|t| t.order_key().cmp(&key)) {
            Ok(index) => self.tips[index] = tip,
            Err(_) if self.tips.len() >= MAX_TIPS => return Err(ErrorClass::TooLarge),
            Err(index) => self.tips.insert(index, tip),
        }
        Ok(())
    }

    /// Whether a signer of this device may sign in a log: always,
    /// unless a restore was found and the log has not been synced since
    /// (at-rest.md, "After a restore", step 2).
    pub fn may_sign(&self, log: &[u8; 32]) -> bool {
        self.restore
            .as_ref()
            .is_none_or(|restore| restore.synced.binary_search(log).is_ok())
    }

    /// Adds a log to key 5 once the device has synced it after a restore.
    /// Without a restore there is nothing to add.
    pub fn add_synced(&mut self, log: &[u8; 32]) {
        if let Some(restore) = &mut self.restore
            && let Err(index) = restore.synced.binary_search(log)
        {
            restore.synced.insert(index, *log);
        }
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(1, self.store_id.into());
        map.insert(2, self.generation.into());
        map.insert(
            3,
            Value::Array(
                self.tips
                    .iter()
                    .map(|tip| {
                        Value::Array(vec![
                            tip.log.into(),
                            tip.author.0.into(),
                            tip.seq.into(),
                            tip.event.into(),
                        ])
                    })
                    .collect(),
            ),
        );
        if let Some(restore) = &self.restore {
            map.insert(4, restore.found_at.into());
            map.insert(5, ids_value(&restore.synced));
        }
        if let Some(revision) = self.revision {
            map.insert(6, revision.into());
        }
        Value::Map(map)
    }

    /// The head's CBOR map.
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Reads a head's CBOR map.
    ///
    /// # Errors
    ///
    /// `Malformed` unless it parses exactly as at-rest.md says.
    pub fn read(value: &[u8]) -> Result<Self, ErrorClass> {
        let map = map_with(value, &[1, 2, 3], &[4, 5, 6])?;
        let store_id = map[&1].as_byte_array::<16>()?;
        let generation = map[&2].as_unsigned()?;
        let tips = map[&3].as_array()?;
        if generation < 1 || tips.len() > MAX_TIPS {
            return Err(ErrorClass::Malformed);
        }
        let tips = tips
            .iter()
            .map(|tip| match tip.as_array()? {
                [log, author, seq, event] => {
                    let seq = seq.as_unsigned()?;
                    if seq < 1 {
                        return Err(cbor::Malformed);
                    }
                    Ok(Tip {
                        log: log.as_byte_array()?,
                        author: DeviceId(author.as_byte_array()?),
                        seq,
                        event: event.as_byte_array()?,
                    })
                }
                _ => Err(cbor::Malformed),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !tips
            .windows(2)
            .all(|pair| pair[0].order_key() < pair[1].order_key())
        {
            return Err(ErrorClass::Malformed);
        }
        let restore = match (map.get(&4), map.get(&5)) {
            (None, None) => None,
            (Some(found_at), Some(synced)) => {
                let found_at = found_at.as_unsigned()?;
                if !(1..=generation).contains(&found_at) {
                    return Err(ErrorClass::Malformed);
                }
                Some(Restore {
                    found_at,
                    synced: ascending_ids(synced)?,
                })
            }
            _ => return Err(ErrorClass::Malformed),
        };
        let revision = map.get(&6).map(Value::as_unsigned).transpose()?;
        Ok(Self {
            store_id,
            generation,
            tips,
            restore,
            revision,
        })
    }
}

/// The kind of a log, in its `log` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogKind {
    /// Kind 1: a space.
    Space,
    /// Kind 2: a person's device list.
    DeviceList,
}

impl LogKind {
    /// The kind's byte.
    pub fn code(self) -> u8 {
        match self {
            Self::Space => 1,
            Self::DeviceList => 2,
        }
    }

    /// The kind of this byte, if it is one.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Space),
            2 => Some(Self::DeviceList),
            _ => None,
        }
    }
}

/// A `log` record's value: `u8(log kind) || L`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// The log's kind.
    pub kind: LogKind,
    /// The log key `L`, 32 random bytes drawn when the device first keeps
    /// anything of the log.
    pub log_key: Secret,
}

/// An event's state, in its `event` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventState {
    /// 1: valid.
    Valid,
    /// 2: void or refused.
    Refused,
    /// 3: pending.
    Pending,
    /// 4: held `Sealed`.
    HeldSealed,
    /// 5: pending on `NoHybridKey`.
    PendingNoHybridKey,
    /// 6: kept alone, never judged: an event a log that forgot keeps
    /// without judging it (at-rest.md, "The head, events and keys").
    KeptAlone,
}

impl EventState {
    /// The state's number.
    pub fn code(self) -> u64 {
        match self {
            Self::Valid => 1,
            Self::Refused => 2,
            Self::Pending => 3,
            Self::HeldSealed => 4,
            Self::PendingNoHybridKey => 5,
            Self::KeptAlone => 6,
        }
    }

    /// The state of this number, if it is one.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Valid),
            2 => Some(Self::Refused),
            3 => Some(Self::Pending),
            4 => Some(Self::HeldSealed),
            5 => Some(Self::PendingNoHybridKey),
            6 => Some(Self::KeptAlone),
            _ => None,
        }
    }
}

/// Flag `0x01` of an `event` record: every signature half the event carries
/// has verified.
pub const FLAG_VERIFIED: u64 = 0x01;
/// Flag `0x02` of an `event` record: its verdict is provisional, resting on
/// a key received whole or handed over.
pub const FLAG_PROVISIONAL: u64 = 0x02;

/// An `event` record's value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventRecord {
    /// Key 1: the signed event.
    pub signed: Vec<u8>,
    /// Key 2: its state.
    pub state: EventState,
    /// Key 3: its flags, [`FLAG_VERIFIED`] and [`FLAG_PROVISIONAL`].
    pub flags: u64,
    /// Key 4, with state 2 only: the class of its verdict, 1 to 64 bytes.
    pub class: Option<String>,
    /// Key 5: its first sight, absent until the device has accepted it.
    pub first_sight: Option<Reading>,
    /// Keys 6 to 8, with state 1 or 2 only: for a unit of the past of the
    /// log's kept checkpoint that the log keeps, what the device froze of
    /// it when it forgot that past ([`Frozen`]).
    pub frozen: Option<Frozen>,
}

/// The most capabilities key 6 of an `event` record carries.
pub const MAX_FROZEN_CAPABILITIES: usize = 64;
/// The longest capability name key 6 carries, in bytes of UTF-8.
pub const MAX_CAPABILITY_NAME: usize = 64;
/// The most entries key 7 of an `event` record carries.
pub const MAX_FROZEN_ATTRIBUTION: usize = 64;
/// The longest label an attribution entry of key 7 carries, in bytes of
/// UTF-8.
pub const MAX_ATTRIBUTION_LABEL: usize = 64;
/// The most events key 8 of an `event` record names.
pub const MAX_FROZEN_VOIDERS: usize = 64;
/// The largest member type a member reference in key 7 carries.
const MAX_MEMBER_TYPE: u64 = 3;

/// Keys 6 to 8 of an `event` record (at-rest.md, "The head, events and
/// keys"; units.md, "The past of a kept checkpoint"): what a device froze
/// of a unit of the past of its kept checkpoint that it keeps, in the same
/// commit as it forgot that past. The record's state, 1 or 2, and its class
/// are the unit's frozen verdict; the device hands the unit to its adapter
/// with these capabilities, never with what it could recompute from what it
/// still holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Frozen {
    /// Key 6: the capabilities its author held at its place, as the adapter
    /// reads them (the meet of its paths' at its highest level), 0 to 64
    /// pairs `(name, mode)`: each name 1 to 64 bytes of UTF-8, the mode 0
    /// (extends) or 1 (narrows), strictly ascending by name bytes then
    /// mode, so that one name may appear in both modes.
    pub capabilities: Vec<(String, u64)>,
    /// Key 7, for a unit the write rule admits, whether its content
    /// applied (state 1) or was refused or held waiting (state 2): its
    /// attribution at its place (roster.md, 3.11), 1 to 64 entries
    /// `(type, ID, label)`, the type 0 to 3, the label 1 to 64 bytes of
    /// UTF-8 when the member had one there, strictly ascending by type then
    /// ID; empty when absent. Never beside key 8.
    pub attribution: Vec<(u64, [u8; 32], Option<String>)>,
    /// Key 8, with state 2 only: the events that void it, 1 to 64 IDs,
    /// strictly ascending; empty when none does, and key 8 is then absent.
    pub voided_by: Vec<[u8; 32]>,
}

impl Frozen {
    /// Puts keys 6 to 8 in an `event` record's map.
    fn put(&self, map: &mut Map) {
        map.insert(
            6,
            Value::Array(
                self.capabilities
                    .iter()
                    .map(|(name, mode)| {
                        Value::Array(vec![name.as_str().into(), Value::Unsigned(*mode)])
                    })
                    .collect(),
            ),
        );
        if !self.attribution.is_empty() {
            map.insert(
                7,
                Value::Array(
                    self.attribution
                        .iter()
                        .map(|(kind, id, label)| {
                            let mut entry = vec![Value::Unsigned(*kind), (*id).into()];
                            if let Some(label) = label {
                                entry.push(label.as_str().into());
                            }
                            Value::Array(entry)
                        })
                        .collect(),
                ),
            );
        }
        if !self.voided_by.is_empty() {
            map.insert(8, ids_value(&self.voided_by));
        }
    }

    /// Reads keys 6 to 8 of an `event` record's map, whose state is
    /// `state`: absent without key 6; key 6 only with state 1 or 2, key 7
    /// only beside it, key 8 only beside it with state 2, and never keys 7
    /// and 8 together (else `Malformed`).
    fn read(map: &Map, state: EventState) -> Result<Option<Self>, cbor::Malformed> {
        let Some(capabilities) = map.get(&6) else {
            if map.contains_key(&7) || map.contains_key(&8) {
                return Err(cbor::Malformed);
            }
            return Ok(None);
        };
        if !matches!(state, EventState::Valid | EventState::Refused) {
            return Err(cbor::Malformed);
        }
        let capabilities = capabilities
            .as_array()?
            .iter()
            .map(|pair| {
                let [name, mode] = pair.as_array()? else {
                    return Err(cbor::Malformed);
                };
                let name = name.as_text()?;
                let mode = mode.as_unsigned()?;
                if !(1..=MAX_CAPABILITY_NAME).contains(&name.len()) || mode > 1 {
                    return Err(cbor::Malformed);
                }
                Ok((name.to_owned(), mode))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if capabilities.len() > MAX_FROZEN_CAPABILITIES
            || !capabilities
                .windows(2)
                .all(|pair| (pair[0].0.as_bytes(), pair[0].1) < (pair[1].0.as_bytes(), pair[1].1))
        {
            return Err(cbor::Malformed);
        }
        if map.contains_key(&7) && map.contains_key(&8) {
            return Err(cbor::Malformed);
        }
        let attribution = match map.get(&7) {
            None => Vec::new(),
            Some(entries) => {
                let entries = entries
                    .as_array()?
                    .iter()
                    .map(|entry| {
                        let (kind, id, label) = match entry.as_array()? {
                            [kind, id] => (kind, id, None),
                            [kind, id, label] => (kind, id, Some(label)),
                            _ => return Err(cbor::Malformed),
                        };
                        let kind = kind.as_unsigned()?;
                        if kind > MAX_MEMBER_TYPE {
                            return Err(cbor::Malformed);
                        }
                        let label = match label {
                            None => None,
                            Some(label) => {
                                let label = label.as_text()?;
                                if !(1..=MAX_ATTRIBUTION_LABEL).contains(&label.len()) {
                                    return Err(cbor::Malformed);
                                }
                                Some(label.to_owned())
                            }
                        };
                        Ok((kind, id.as_byte_array::<32>()?, label))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if !(1..=MAX_FROZEN_ATTRIBUTION).contains(&entries.len())
                    || !entries
                        .windows(2)
                        .all(|pair| (pair[0].0, pair[0].1) < (pair[1].0, pair[1].1))
                {
                    return Err(cbor::Malformed);
                }
                entries
            }
        };
        let voided_by = match map.get(&8) {
            None => Vec::new(),
            Some(_) if state != EventState::Refused => return Err(cbor::Malformed),
            Some(ids) => {
                let ids = ascending_ids(ids)?;
                if !(1..=MAX_FROZEN_VOIDERS).contains(&ids.len()) {
                    return Err(cbor::Malformed);
                }
                ids
            }
        };
        Ok(Some(Self {
            capabilities,
            attribution,
            voided_by,
        }))
    }
}

/// A recipient bundle (keys.md, "The recipient bundle"): the secrets one
/// state gives its recipient.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bundle {
    /// Flag `0x01`: the content key.
    pub content: Option<Secret>,
    /// Flag `0x02`: the upload seed, only with the content key.
    pub upload: Option<Secret>,
    /// Flag `0x04`: the grant seed.
    pub grant: Option<Secret>,
}

impl Bundle {
    /// Reads a bundle with frasil-keys' reader (keys.md, "Reading key
    /// names, bundles, wraps and links"): exactly 97 bytes; no flag outside `0x07`; at least one
    /// flag; the upload flag only with the content flag; every slot whose
    /// flag is clear is zero.
    ///
    /// # Errors
    ///
    /// `Malformed` if any of those fails.
    pub fn read(data: &[u8]) -> Result<Self, ErrorClass> {
        let bundle = frasil_keys::bundle::Bundle::read(data).map_err(|_| ErrorClass::Malformed)?;
        Ok(Self {
            content: bundle.content().copied().map(Secret::new),
            upload: bundle.upload().copied().map(Secret::new),
            grant: bundle.grant().copied().map(Secret::new),
        })
    }

    /// The bundle's 97 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; BUNDLE_BYTES];
        for (i, slot) in [&self.content, &self.upload, &self.grant]
            .into_iter()
            .enumerate()
        {
            if let Some(secret) = slot {
                out[0] |= 1 << i;
                out[1 + 32 * i..33 + 32 * i].copy_from_slice(secret.expose());
            }
        }
        out
    }
}

/// A body key's value in the `key` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyKey {
    /// The body key.
    pub key: Secret,
    /// `None` when this device opened or derived it (`u8(1) || key`); the
    /// unit that handed it otherwise (`u8(2) || key || unit ID`), which
    /// makes it provisional.
    pub handed_by: Option<[u8; 32]>,
}

/// A record key's value in the `key` table (kind 5): the key of a
/// checkpoint's record object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordKey {
    /// The record object key.
    pub key: Secret,
    /// `false` when this device derived it from rotation secrets it holds
    /// (`u8(1) || key`); `true` when a space snapshot handed it (`u8(2) ||
    /// key`), which makes it provisional until the record object opens and
    /// matches its digest.
    pub handed: bool,
}

/// A `key` record's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValue {
    /// Kinds 1, 2 and 4: a bundle.
    Bundle(Bundle),
    /// Kind 3: a body key.
    BodyKey(BodyKey),
    /// Kind 5: a checkpoint's record object key.
    RecordKey(RecordKey),
}

/// Why a log holds a `dropped` record (at-rest.md, the `dropped` table).
///
/// The record is `{1: origin, 2: kind, 3: height}`: key 2 exactly with
/// origin 1, key 3 only with origin 1, and from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DroppedOrigin {
    /// Origin 1: the device held the event and dropped it; the kind of its
    /// envelope.
    Held {
        /// The envelope's kind.
        kind: u8,
        /// Key 3: the event's height, in a space's log, exactly when it is
        /// a parent of an event the log keeps of its kept checkpoint's past
        /// (events.md, "Placement and order"): the device places that event
        /// on it after a restart, so that it keeps the height it was judged
        /// at. Author and `seq` are not kept: a dropped `prev` is not
        /// checked against its chain again.
        height: Option<u64>,
    },
    /// Origin 2: a peer answered `Missing` for it when the device fetched
    /// it as a parent, at a device that started from a checkpoint.
    Missing,
}

impl DroppedOrigin {
    /// The origin's number, key 1.
    pub fn code(self) -> u64 {
        match self {
            Self::Held { .. } => 1,
            Self::Missing => 2,
        }
    }
}

/// A `listing` record's value: `{1: bytes, 2: T}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Listing {
    /// Key 1: the `StreamHeads` the peer served.
    pub served: Vec<u8>,
    /// Key 2: when, on the device's timeline.
    pub at: u64,
}

/// A `state` record's value, at least one key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LogState {
    /// Key 1: the base heads, 1 to 256, strictly ascending: a stream's base
    /// of units (units.md).
    pub base_heads: Option<Vec<[u8; 32]>>,
    /// Key 2: the base stubs, of a stream's base of units.
    pub base_stubs: Option<Vec<Vec<u8>>>,
    /// Key 3: the reading of the last completed sync.
    pub last_sync: Option<Reading>,
    /// Key 4: the grants a leave request this device sent named, 1 to 64,
    /// strictly ascending (ext-guests.md, "A leave request").
    pub left: Option<Vec<[u8; 32]>>,
    /// Key 5, `1`: the log is the person's personal space (identity.md,
    /// "The person ID and the personal space").
    pub personal: bool,
    /// Key 6: the invite entry of a claim this device began in the log and
    /// has not signed (ext-invite-links.md, "Records at rest"). A log that
    /// names one with no `claim` record is a claim that never finished.
    pub claiming: Option<[u8; 32]>,
    /// Key 7: the event ID of the kept checkpoint of a space or device
    /// list log whose past before it this device forgot, or that it started
    /// from (roster.md, 3.15.6 Forgetting, and starting from a checkpoint;
    /// identity.md, "List checkpoints", Forgetting). What it dropped is in
    /// the log's `dropped` records, never in keys 1 and 2, which hold only a
    /// stream's base of units (at-rest.md, "Forgetting before a
    /// checkpoint").
    pub kept_checkpoint: Option<[u8; 32]>,
    /// Key 8, beyond at-rest.md's record: the incarnations whose operations
    /// a lent document's holder wrote again under a fresh one, whose units
    /// are not re-submitted ([`crate::expressed_again`]).
    pub expressed_again: Option<crate::expressed_again::ExpressedAgain>,
    /// Key 9, alone: administering device IDs and X-Wing keys kept by an erasure residue.
    pub erasing: Option<Vec<([u8; 32], Vec<u8>)>>,
}

/// A `pseudonym` record's value: `{1: token, 2: Ed25519 seed, 3: ML-DSA-65
/// seed}`, at least one key, 2 and 3 together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pseudonym {
    /// Key 1: the token, kept from the grant until the enrolment is durable.
    pub token: Option<Secret>,
    /// Keys 2 and 3: the Ed25519 and ML-DSA-65 seeds, committed with the
    /// enrolment that names them.
    pub seeds: Option<(Secret, Secret)>,
}

/// An `invite` or `claim` record's value: `space ID || invite entry ||
/// secret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// The space ID, the log's.
    pub space: [u8; 32],
    /// The invite entry, the item.
    pub invite_entry: [u8; 32],
    /// The link's secret.
    pub secret: Secret,
}

/// A `replay` record's value: a sender's replay window
/// (ext-ephemeral.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayWindow {
    /// The sender's epoch.
    pub epoch: u64,
    /// The highest counter accepted in the epoch.
    pub counter: u64,
    /// The window's bitmap: bit `i`, from the least significant, is set
    /// when `counter - i` was accepted.
    pub window: u64,
}

/// A `held` record: how the application names a held object's plaintext
/// and tells whether it changed (at-rest.md, "Held objects").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRecord {
    /// Key 1: the application's token for the plaintext, 1 to 1,024 bytes.
    pub token: Vec<u8>,
    /// Key 2: the plaintext's length, 0 to 2^40.
    pub size: u64,
    /// Key 3: the application's change stamp, 1 to 64 bytes, compared byte
    /// for byte and never interpreted.
    pub stamp: Vec<u8>,
}

/// A `retention` record: how long this device keeps an object it stores as
/// sealed chunks (at-rest.md, "Retention").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// State 1: the object stays until the application drops it.
    Kept,
    /// State 2: the object counts against the device's budget, and is
    /// dropped when the budget is full.
    Cached {
        /// Key 2: the timeline's `T` at which the device last read the
        /// object, rounded down to a multiple of [`RETENTION_READ_STEP`].
        read: u64,
    },
    /// State 3: this device sealed the object, and knows of no always-on
    /// peer that holds it. The object stays as a kept one does until such
    /// a peer holds it.
    Put {
        /// Key 3: whether the application asked to keep the object. Once
        /// a peer holds it, the object is kept if so, and cached if not.
        keep: bool,
    },
}

/// A `welcome` record: a welcome this device signed that waits for its
/// newcomer, the item (admission.md, 3.10 Welcomes, "A welcome that
/// waits").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeRecord {
    /// Key 1: the event the entry waits on: the event the welcome names,
    /// or the unit that publishes the snapshot of a welcome that answers a
    /// welcome request.
    pub event: [u8; 32],
    /// Key 2: the welcome, sealed to the newcomer's X-Wing key, 1 to
    /// 262,144 bytes.
    pub sealed: Vec<u8>,
    /// Key 3: the timeline's `T` at which the device kept it.
    pub since: u64,
    /// Key 4: the peers it was deposited at in the newcomer's device
    /// mailbox, each by its origin with the timeline's `T` of the latest
    /// deposit there and the number of deposits made there, 1 to
    /// [`WELCOME_DEPOSITS`], 0 to 64 peers, strictly ascending by the
    /// origins' bytes.
    pub deposited: Vec<(String, u64, u8)>,
}

/// What a cached object's last read is rounded down to, in seconds of the
/// timeline: reading an object writes its record at most once in this
/// long (at-rest.md, "Retention").
pub const RETENTION_READ_STEP: u64 = 3_600;

/// A `peers` record: the space's always-on peers this device knows, as
/// origins' URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeersRecord {
    /// Key 1: peer hints, 1 to 8 when present, each 1 to 512 bytes;
    /// empty when the key is absent.
    pub hints: Vec<String>,
    /// Key 2: the home peer of the space's library, 1 to 512 bytes.
    pub home: Option<String>,
}

/// A `deposit_keys` record: what a device keeps of one peer's deposit
/// keys (ext-deposit-tokens.md, 3.2 Learning a peer's keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositKeysRecord {
    /// Key 1: the issuing keys seen there, each with its first sight, a
    /// timeline's `T`, oldest first; 1 to 64.
    pub seen: Vec<([u8; 32], u64)>,
    /// Key 2: the latest key list, each entry its key ID, public key and
    /// role, 1 issuing or 2 accepting only; 1 or 2 entries, exactly one
    /// issuing, no key ID twice.
    pub latest: Vec<([u8; 32], [u8; 32], u64)>,
    /// Key 3: whether the peer was found `KeyInconsistent`.
    pub inconsistent: bool,
    /// Key 4: the reading at which the peer answered a draw
    /// `allowance_exhausted`.
    pub paused: Option<Reading>,
}

/// A deposit token kept at rest: zeroed on drop, and never printed by
/// `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenBytes(Zeroizing<[u8; TOKEN_BYTES]>);

impl TokenBytes {
    /// The token of these bytes.
    pub fn new(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The token's bytes.
    pub fn expose(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for TokenBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TokenBytes(..)")
    }
}

/// A `deposit` record: a deposit in a device mailbox that a peer has not
/// accepted yet (transport.md, "A sender keeps what was refused").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRecord {
    /// Key 1: the origin of the peer it goes to, 1 to 512 bytes.
    pub peer: String,
    /// Key 2: the device mailbox's address.
    pub address: [u8; 32],
    /// Key 3: the item, 1 to 262,144 bytes.
    pub item: Vec<u8>,
    /// Key 4: the reading of the first attempt.
    pub first: Reading,
    /// Key 5: the attempts refused or unanswered so far.
    pub attempts: u64,
    /// Key 6: the timeline's `T` before which the device does not try
    /// again.
    pub next: u64,
    /// Key 7: the token that pays for it, once the device sent it with
    /// one.
    pub token: Option<TokenBytes>,
}

/// A record's value, by table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableValue {
    /// `head`.
    Head(Head),
    /// `log`.
    Log(LogRecord),
    /// `timeline`: the last kept reading.
    Timeline(Reading),
    /// `epoch`: the ephemeral epoch.
    Epoch(u64),
    /// `next_endpoint`: the seed of the member endpoint key this device
    /// announced as its next.
    NextEndpoint(Secret),
    /// `deposit_keys`: a peer's deposit keys as the device saw them.
    DepositKeys(DepositKeysRecord),
    /// `token`: an unspent deposit token, whose nonce is the item's last
    /// 32 bytes.
    Token(TokenBytes),
    /// `deposit`: a deposit a peer has not accepted yet.
    Deposit(DepositRecord),
    /// `event`.
    Event(EventRecord),
    /// `object`: part 0, the object's header; part `i` ≥ 1, chunk `i − 1` as
    /// received.
    Object(Vec<u8>),
    /// `key`.
    Key(KeyValue),
    /// `outbox`: the ID of an event this device signed that is not yet
    /// durable.
    Outbox([u8; 32]),
    /// `ack`: the heads a peer last acknowledged, 1 to 256, strictly
    /// ascending.
    Ack(Vec<[u8; 32]>),
    /// `listing`.
    Listing(Listing),
    /// `state`.
    State(LogState),
    /// `pseudonym`.
    Pseudonym(Pseudonym),
    /// `invite`.
    Invite(InviteRecord),
    /// `claim`.
    Claim(InviteRecord),
    /// `replay`.
    Replay(ReplayWindow),
    /// `vouched`: the person ID of the list member the item names.
    Vouched([u8; 32]),
    /// `endpoint`: the CBOR of a member ticket of the member the item
    /// names, 1 to 1,024 bytes.
    Endpoint(Vec<u8>),
    /// `held`: the token, size and stamp of the held object the item
    /// names.
    Held(HeldRecord),
    /// `peers`: the space's peers and its home peer.
    Peers(PeersRecord),
    /// `retention`: whether the object the item names is kept or cached.
    Retention(Retention),
    /// `welcome`: a welcome that waits for its newcomer.
    Welcome(WelcomeRecord),
    /// `announced`: the next member endpoint key the member the item names
    /// announced.
    Announced([u8; 32]),
    /// `host`: the peer role's own bytes.
    Host(Vec<u8>),
    /// `dropped`: why the log holds the event the item names no more.
    Dropped(DroppedOrigin),
}

fn map_with(value: &[u8], required: &[u64], optional: &[u64]) -> Result<Map, cbor::Malformed> {
    let Value::Map(map) = cbor::decode(value)? else {
        return Err(cbor::Malformed);
    };
    KeyRules {
        required,
        optional,
        unknown: UnknownKeys::Malformed,
    }
    .check(&map)?;
    Ok(map)
}

fn ascending_ids(value: &Value) -> Result<Vec<[u8; 32]>, cbor::Malformed> {
    let ids = value
        .as_array()?
        .iter()
        .map(Value::as_byte_array::<32>)
        .collect::<Result<Vec<_>, _>>()?;
    if ids.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(ids)
    } else {
        Err(cbor::Malformed)
    }
}

fn ids_value(ids: &[[u8; 32]]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(*id)).collect())
}

/// Reads a reading, `{1: T, 2: run, 3: W}`, key 3 absent when the wall
/// clock was not known.
fn reading(value: &Value) -> Result<Reading, cbor::Malformed> {
    let map = value.as_map()?;
    KeyRules {
        required: &[1, 2],
        optional: &[3],
        unknown: UnknownKeys::Malformed,
    }
    .check(map)?;
    Ok(Reading {
        timeline: map[&1].as_unsigned()?,
        run: map[&2].as_unsigned()?,
        wall: map.get(&3).map(Value::as_unsigned).transpose()?,
    })
}

/// A reading as its CBOR map.
pub fn reading_value(reading: &Reading) -> Value {
    let mut map = Map::new();
    map.insert(1, reading.timeline.into());
    map.insert(2, reading.run.into());
    if let Some(wall) = reading.wall {
        map.insert(3, wall.into());
    }
    Value::Map(map)
}

/// A `deposit_keys` value (at-rest.md, "Tables").
fn read_deposit_keys(value: &[u8]) -> Result<DepositKeysRecord, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let map = map_with(value, &[1, 2], &[3, 4])?;
    let seen = map[&1]
        .as_array()?
        .iter()
        .map(|entry| match entry.as_array()? {
            [id, first] => Ok((id.as_byte_array::<32>()?, first.as_unsigned()?)),
            _ => Err(cbor::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !(1..=MAX_SEEN_KEYS).contains(&seen.len()) {
        return Err(malformed);
    }
    let latest = map[&2]
        .as_array()?
        .iter()
        .map(|entry| match entry.as_array()? {
            [id, public, role] => Ok((
                id.as_byte_array::<32>()?,
                public.as_byte_array::<32>()?,
                role.as_unsigned()?,
            )),
            _ => Err(cbor::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let issuing = latest.iter().filter(|entry| entry.2 == 1).count();
    if !(1..=2).contains(&latest.len())
        || latest.iter().any(|entry| !matches!(entry.2, 1 | 2))
        || issuing != 1
        || (latest.len() == 2 && latest[0].0 == latest[1].0)
    {
        return Err(malformed);
    }
    if map
        .get(&3)
        .is_some_and(|v| !matches!(v.as_unsigned(), Ok(1)))
    {
        return Err(malformed);
    }
    Ok(DepositKeysRecord {
        seen,
        latest,
        inconsistent: map.contains_key(&3),
        paused: map.get(&4).map(reading).transpose()?,
    })
}

/// A `deposit` value (at-rest.md, "Tables").
fn read_deposit(value: &[u8]) -> Result<DepositRecord, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let map = map_with(value, &[1, 2, 3, 4, 5, 6], &[7])?;
    let peer = map[&1].as_text().map_err(|_| malformed)?;
    let item = map[&3].as_bytes()?;
    if !(1..=MAX_PEER_URL).contains(&peer.len()) || !(1..=MAX_MAILBOX_ITEM).contains(&item.len()) {
        return Err(malformed);
    }
    let token = map
        .get(&7)
        .map(|token| {
            token
                .as_bytes()
                .ok()
                .and_then(|bytes| <[u8; TOKEN_BYTES]>::try_from(bytes).ok())
                .map(TokenBytes::new)
                .ok_or(malformed)
        })
        .transpose()?;
    Ok(DepositRecord {
        peer: peer.to_owned(),
        address: map[&2].as_byte_array::<32>()?,
        item: item.to_vec(),
        first: reading(&map[&4])?,
        attempts: map[&5].as_unsigned()?,
        next: map[&6].as_unsigned()?,
        token,
    })
}

/// A `welcome` value (at-rest.md, "Tables").
fn read_welcome(value: &[u8]) -> Result<WelcomeRecord, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let map = map_with(value, &[1, 2, 3], &[4])?;
    let sealed = map[&2].as_bytes()?;
    if !(1..=MAX_MAILBOX_ITEM).contains(&sealed.len()) {
        return Err(malformed);
    }
    let deposited = match map.get(&4) {
        Some(peers) => {
            let peers = peers.as_array()?;
            if !(1..=MAX_WELCOME_PEERS).contains(&peers.len()) {
                return Err(malformed);
            }
            let mut out: Vec<(String, u64, u8)> = Vec::with_capacity(peers.len());
            for entry in peers {
                let [peer, at, count] = entry.as_array()? else {
                    return Err(malformed);
                };
                let peer = peer.as_text().map_err(|_| malformed)?;
                let count = u8::try_from(count.as_unsigned()?).map_err(|_| malformed)?;
                if !(1..=MAX_PEER_URL).contains(&peer.len())
                    || !(1..=WELCOME_DEPOSITS).contains(&count)
                    || out
                        .last()
                        .is_some_and(|(prior, _, _)| prior.as_bytes() >= peer.as_bytes())
                {
                    return Err(malformed);
                }
                out.push((peer.to_owned(), at.as_unsigned()?, count));
            }
            out
        }
        None => Vec::new(),
    };
    Ok(WelcomeRecord {
        event: map[&1].as_byte_array::<32>()?,
        sealed: sealed.to_vec(),
        since: map[&3].as_unsigned()?,
        deposited,
    })
}

fn bytes32(data: &[u8]) -> [u8; 32] {
    data.try_into().expect("checked to be 32 bytes")
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

impl TableValue {
    /// The table this value belongs to.
    pub fn table(&self) -> Table {
        match self {
            Self::Head(_) => Table::Head,
            Self::Log(_) => Table::Log,
            Self::Timeline(_) => Table::Timeline,
            Self::Epoch(_) => Table::Epoch,
            Self::NextEndpoint(_) => Table::NextEndpoint,
            Self::DepositKeys(_) => Table::DepositKeys,
            Self::Token(_) => Table::Token,
            Self::Deposit(_) => Table::Deposit,
            Self::Event(_) => Table::Event,
            Self::Object(_) => Table::Object,
            Self::Key(_) => Table::Key,
            Self::Outbox(_) => Table::Outbox,
            Self::Ack(_) => Table::Ack,
            Self::Listing(_) => Table::Listing,
            Self::State(_) => Table::State,
            Self::Pseudonym(_) => Table::Pseudonym,
            Self::Invite(_) => Table::Invite,
            Self::Claim(_) => Table::Claim,
            Self::Replay(_) => Table::Replay,
            Self::Vouched(_) => Table::Vouched,
            Self::Endpoint(_) => Table::Endpoint,
            Self::Held(_) => Table::Held,
            Self::Peers(_) => Table::Peers,
            Self::Announced(_) => Table::Announced,
            Self::Host(_) => Table::Host,
            Self::Dropped(_) => Table::Dropped,
            Self::Retention(_) => Table::Retention,
            Self::Welcome(_) => Table::Welcome,
        }
    }

    /// Reads a record's item and value, as its table says (at-rest.md,
    /// "Opening a record", steps 6 and 7, after the item tag). `log` is the
    /// record's log, `None` for a device-wide table.
    ///
    /// # Errors
    ///
    /// `Malformed` if the item does not follow its table's rule, or the
    /// value does not parse exactly.
    pub fn read(
        table: Table,
        item: &[u8],
        value: &[u8],
        log: Option<&[u8; 32]>,
    ) -> Result<Self, ErrorClass> {
        check_item(table, item)?;
        let malformed = ErrorClass::Malformed;
        Ok(match table {
            Table::Head => Self::Head(Head::read(value)?),
            Table::Log => {
                let kind = match value {
                    [kind, ..] if value.len() == 33 => LogKind::from_code(*kind),
                    _ => None,
                }
                .ok_or(malformed)?;
                Self::Log(LogRecord {
                    kind,
                    log_key: Secret::new(bytes32(&value[1..])),
                })
            }
            Table::Timeline => Self::Timeline(reading(&cbor::decode(value)?)?),
            Table::Epoch => {
                let epoch: [u8; 8] = value.try_into().map_err(|_| malformed)?;
                Self::Epoch(u64::from_be_bytes(epoch))
            }
            Table::NextEndpoint => {
                Self::NextEndpoint(Secret::new(value.try_into().map_err(|_| malformed)?))
            }
            Table::DepositKeys => Self::DepositKeys(read_deposit_keys(value)?),
            Table::Token => {
                let token: [u8; TOKEN_BYTES] = value.try_into().map_err(|_| malformed)?;
                if token[0] != 1 || token[33..65] != item[32..] {
                    return Err(malformed);
                }
                Self::Token(TokenBytes::new(token))
            }
            Table::Deposit => Self::Deposit(read_deposit(value)?),
            Table::Event => Self::Event(read_event(item, value, log)?),
            Table::Object => {
                check_object_value(item, value)?;
                Self::Object(value.to_vec())
            }
            Table::Key => Self::Key(match KeyKind::from_code(item[0]) {
                Some(KeyKind::BodyKey) => {
                    let handed_by = match value.first() {
                        Some(1) if value.len() == 33 => None,
                        Some(2) if value.len() == 65 => Some(bytes32(&value[33..])),
                        _ => return Err(malformed),
                    };
                    KeyValue::BodyKey(BodyKey {
                        key: Secret::new(bytes32(&value[1..33])),
                        handed_by,
                    })
                }
                Some(KeyKind::RecordKey) => {
                    let handed = match value.first() {
                        Some(1) if value.len() == 33 => false,
                        Some(2) if value.len() == 33 => true,
                        _ => return Err(malformed),
                    };
                    KeyValue::RecordKey(RecordKey {
                        key: Secret::new(bytes32(&value[1..])),
                        handed,
                    })
                }
                _ => KeyValue::Bundle(Bundle::read(value)?),
            }),
            Table::Outbox => Self::Outbox(value.try_into().map_err(|_| malformed)?),
            Table::Ack => {
                let heads = ascending_ids(&cbor::decode(value)?)?;
                if !(1..=MAX_ACK_HEADS).contains(&heads.len()) {
                    return Err(malformed);
                }
                Self::Ack(heads)
            }
            Table::Listing => {
                let map = map_with(value, &[1, 2], &[])?;
                Self::Listing(Listing {
                    served: map[&1].as_bytes()?.to_vec(),
                    at: map[&2].as_unsigned()?,
                })
            }
            Table::State => {
                let map = map_with(value, &[], &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
                if map.is_empty()
                    || map
                        .get(&5)
                        .is_some_and(|v| !matches!(v.as_unsigned(), Ok(1)))
                {
                    return Err(malformed);
                }
                let erasing = map
                    .get(&9)
                    .map(|value| {
                        if map.len() != 1 {
                            return Err(malformed);
                        }
                        let entries = value.as_array()?;
                        if !(1..=64).contains(&entries.len()) {
                            return Err(malformed);
                        }
                        let mut devices = Vec::new();
                        for entry in entries {
                            let pair = entry.as_array()?;
                            if pair.len() != 2 {
                                return Err(malformed);
                            }
                            let id = pair[0].as_byte_array::<32>()?;
                            let key = pair[1].as_bytes()?;
                            if key.len() != 1216
                                || devices.last().is_some_and(|(prior, _)| prior >= &id)
                            {
                                return Err(malformed);
                            }
                            devices.push((id, key.to_vec()));
                        }
                        Ok(devices)
                    })
                    .transpose()?;
                let left = map.get(&4).map(ascending_ids).transpose()?;
                if left
                    .as_ref()
                    .is_some_and(|grants| !(1..=MAX_LEFT_GRANTS).contains(&grants.len()))
                {
                    return Err(malformed);
                }
                let base_heads = map.get(&1).map(ascending_ids).transpose()?;
                if base_heads
                    .as_ref()
                    .is_some_and(|heads| !(1..=MAX_BASE_HEADS).contains(&heads.len()))
                {
                    return Err(malformed);
                }
                let base_stubs = map
                    .get(&2)
                    .map(|stubs| {
                        stubs
                            .as_array()?
                            .iter()
                            .map(|stub| stub.as_bytes().map(<[u8]>::to_vec))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?;
                Self::State(LogState {
                    erasing,
                    base_heads,
                    base_stubs,
                    last_sync: map.get(&3).map(reading).transpose()?,
                    left,
                    personal: map.contains_key(&5),
                    claiming: map.get(&6).map(Value::as_byte_array).transpose()?,
                    kept_checkpoint: map.get(&7).map(Value::as_byte_array).transpose()?,
                    expressed_again: map
                        .get(&8)
                        .map(crate::expressed_again::ExpressedAgain::read)
                        .transpose()?,
                })
            }
            Table::Pseudonym => {
                let map = map_with(value, &[], &[1, 2, 3])?;
                if map.is_empty() || map.contains_key(&2) != map.contains_key(&3) {
                    return Err(malformed);
                }
                let secret = |key: u64| {
                    map.get(&key)
                        .map(|value| value.as_byte_array::<32>().map(Secret::new))
                        .transpose()
                };
                let token = secret(1)?;
                let seeds = match (secret(2)?, secret(3)?) {
                    (Some(ed25519), Some(mldsa)) => Some((ed25519, mldsa)),
                    _ => None,
                };
                Self::Pseudonym(Pseudonym { token, seeds })
            }
            Table::Invite | Table::Claim => {
                if value.len() != 96 || Some(&value[..32]) != log.map(|l| &l[..]) {
                    return Err(malformed);
                }
                if value[32..64] != *item {
                    return Err(malformed);
                }
                let record = InviteRecord {
                    space: bytes32(&value[..32]),
                    invite_entry: bytes32(&value[32..64]),
                    secret: Secret::new(bytes32(&value[64..])),
                };
                if table == Table::Invite {
                    Self::Invite(record)
                } else {
                    Self::Claim(record)
                }
            }
            Table::Replay => {
                if value.len() != 24 {
                    return Err(malformed);
                }
                Self::Replay(ReplayWindow {
                    epoch: u64_at(value, 0),
                    counter: u64_at(value, 8),
                    window: u64_at(value, 16),
                })
            }
            Table::Vouched => Self::Vouched(value.try_into().map_err(|_| malformed)?),
            Table::Announced => Self::Announced(value.try_into().map_err(|_| malformed)?),
            Table::Endpoint => {
                if !(1..=MAX_ENDPOINT_VALUE).contains(&value.len()) {
                    return Err(malformed);
                }
                Self::Endpoint(value.to_vec())
            }
            Table::Held => {
                let map = map_with(value, &[1, 2, 3], &[])?;
                let token = map[&1].as_bytes()?;
                let size = map[&2].as_unsigned()?;
                let stamp = map[&3].as_bytes()?;
                if !(1..=MAX_HELD_TOKEN).contains(&token.len())
                    || size > MAX_OBJECT_SIZE
                    || !(1..=MAX_HELD_STAMP).contains(&stamp.len())
                {
                    return Err(malformed);
                }
                Self::Held(HeldRecord {
                    token: token.to_vec(),
                    size,
                    stamp: stamp.to_vec(),
                })
            }
            Table::Retention => {
                let map = map_with(value, &[1], &[2, 3])?;
                // Key 2, the last read, exactly with state 2; key 3, that
                // the application asked to keep the object, only with
                // state 3, and then 1.
                let read = map.get(&2).map(Value::as_unsigned).transpose()?;
                let keep = map.get(&3).map(Value::as_unsigned).transpose()?;
                match (map[&1].as_unsigned()?, read, keep) {
                    (1, None, None) => Self::Retention(Retention::Kept),
                    (2, Some(read), None) => Self::Retention(Retention::Cached { read }),
                    (3, None, None) => Self::Retention(Retention::Put { keep: false }),
                    (3, None, Some(1)) => Self::Retention(Retention::Put { keep: true }),
                    _ => return Err(malformed),
                }
            }
            Table::Welcome => Self::Welcome(read_welcome(value)?),
            Table::Peers => {
                let map = map_with(value, &[], &[1, 2])?;
                let url = |value: &Value| {
                    let text = value.as_text().map_err(|_| malformed)?;
                    if (1..=MAX_PEER_URL).contains(&text.len()) {
                        Ok(text.to_owned())
                    } else {
                        Err(malformed)
                    }
                };
                let hints = match map.get(&1) {
                    Some(hints) => {
                        let hints = hints.as_array()?;
                        if !(1..=MAX_PEER_HINTS).contains(&hints.len()) {
                            return Err(malformed);
                        }
                        hints.iter().map(url).collect::<Result<Vec<_>, _>>()?
                    }
                    None => Vec::new(),
                };
                let home = map.get(&2).map(url).transpose()?;
                if hints.is_empty() && home.is_none() {
                    return Err(malformed);
                }
                Self::Peers(PeersRecord { hints, home })
            }
            Table::Host => Self::Host(value.to_vec()),
            Table::Dropped => {
                let map = map_with(value, &[1], &[2, 3])?;
                let origin = match map[&1].as_unsigned()? {
                    1 => {
                        let kind = map.get(&2).ok_or(malformed)?.as_unsigned()?;
                        let height = map.get(&3).map(Value::as_unsigned).transpose()?;
                        if height == Some(0) {
                            return Err(malformed);
                        }
                        DroppedOrigin::Held {
                            kind: u8::try_from(kind).map_err(|_| malformed)?,
                            height,
                        }
                    }
                    2 if !map.contains_key(&2) && !map.contains_key(&3) => DroppedOrigin::Missing,
                    _ => return Err(malformed),
                };
                Self::Dropped(origin)
            }
        })
    }

    /// The value's one encoding, which [`read`](Self::read) accepts. It
    /// can hold a key, so it is wiped on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.encode_plain())
    }

    fn encode_plain(&self) -> Vec<u8> {
        match self {
            Self::Head(head) => head.encode(),
            Self::Log(record) => [&[record.kind.code()][..], record.log_key.expose()].concat(),
            Self::Timeline(r) => reading_value(r).encode(),
            Self::Epoch(epoch) => epoch.to_be_bytes().to_vec(),
            Self::NextEndpoint(seed) => seed.expose().to_vec(),
            Self::DepositKeys(keys) => {
                let mut map = Map::new();
                map.insert(
                    1,
                    Value::Array(
                        keys.seen
                            .iter()
                            .map(|(id, first)| Value::Array(vec![(*id).into(), (*first).into()]))
                            .collect(),
                    ),
                );
                map.insert(
                    2,
                    Value::Array(
                        keys.latest
                            .iter()
                            .map(|(id, public, role)| {
                                Value::Array(vec![(*id).into(), (*public).into(), (*role).into()])
                            })
                            .collect(),
                    ),
                );
                if keys.inconsistent {
                    map.insert(3, 1u64.into());
                }
                if let Some(paused) = &keys.paused {
                    map.insert(4, reading_value(paused));
                }
                Value::Map(map).encode()
            }
            Self::Token(token) => token.expose().to_vec(),
            Self::Deposit(deposit) => {
                let mut map = Map::new();
                map.insert(1, deposit.peer.as_str().into());
                map.insert(2, deposit.address.into());
                map.insert(3, deposit.item.as_slice().into());
                map.insert(4, reading_value(&deposit.first));
                map.insert(5, deposit.attempts.into());
                map.insert(6, deposit.next.into());
                if let Some(token) = &deposit.token {
                    map.insert(7, token.expose().as_slice().into());
                }
                Value::Map(map).encode()
            }
            Self::Event(event) => {
                let mut map = Map::new();
                map.insert(1, event.signed.clone().into());
                map.insert(2, event.state.code().into());
                map.insert(3, event.flags.into());
                if let Some(class) = &event.class {
                    map.insert(4, class.as_str().into());
                }
                if let Some(first_sight) = &event.first_sight {
                    map.insert(5, reading_value(first_sight));
                }
                if let Some(frozen) = &event.frozen {
                    frozen.put(&mut map);
                }
                Value::Map(map).encode()
            }
            Self::Object(bytes) | Self::Host(bytes) | Self::Endpoint(bytes) => bytes.clone(),
            Self::Held(held) => {
                let mut map = Map::new();
                map.insert(1, held.token.as_slice().into());
                map.insert(2, held.size.into());
                map.insert(3, held.stamp.as_slice().into());
                Value::Map(map).encode()
            }
            Self::Retention(retention) => {
                let mut map = Map::new();
                match retention {
                    Retention::Kept => {
                        map.insert(1, 1u64.into());
                    }
                    Retention::Cached { read } => {
                        map.insert(1, 2u64.into());
                        map.insert(2, (*read).into());
                    }
                    Retention::Put { keep } => {
                        map.insert(1, 3u64.into());
                        if *keep {
                            map.insert(3, 1u64.into());
                        }
                    }
                }
                Value::Map(map).encode()
            }
            Self::Welcome(welcome) => {
                let mut map = Map::new();
                map.insert(1, welcome.event.into());
                map.insert(2, welcome.sealed.as_slice().into());
                map.insert(3, welcome.since.into());
                if !welcome.deposited.is_empty() {
                    map.insert(
                        4,
                        Value::Array(
                            welcome
                                .deposited
                                .iter()
                                .map(|(peer, at, count)| {
                                    Value::Array(vec![
                                        peer.as_str().into(),
                                        (*at).into(),
                                        u64::from(*count).into(),
                                    ])
                                })
                                .collect(),
                        ),
                    );
                }
                Value::Map(map).encode()
            }
            Self::Peers(peers) => {
                let mut map = Map::new();
                if !peers.hints.is_empty() {
                    map.insert(
                        1,
                        Value::Array(peers.hints.iter().map(|h| h.as_str().into()).collect()),
                    );
                }
                if let Some(home) = &peers.home {
                    map.insert(2, home.as_str().into());
                }
                Value::Map(map).encode()
            }
            Self::Key(KeyValue::Bundle(bundle)) => bundle.encode(),
            Self::Key(KeyValue::RecordKey(record)) => [
                &[if record.handed { 2u8 } else { 1 }][..],
                record.key.expose(),
            ]
            .concat(),
            Self::Key(KeyValue::BodyKey(body)) => match &body.handed_by {
                None => [&[1u8][..], body.key.expose()].concat(),
                Some(unit) => [&[2u8][..], body.key.expose(), unit].concat(),
            },
            Self::Outbox(id) => id.to_vec(),
            Self::Ack(heads) => ids_value(heads).encode(),
            Self::Listing(listing) => {
                let mut map = Map::new();
                map.insert(1, listing.served.clone().into());
                map.insert(2, listing.at.into());
                Value::Map(map).encode()
            }
            Self::State(state) => {
                let mut map = Map::new();
                if let Some(devices) = &state.erasing {
                    map.insert(
                        9,
                        Value::Array(
                            devices
                                .iter()
                                .map(|(id, key)| {
                                    Value::Array(vec![(*id).into(), key.clone().into()])
                                })
                                .collect(),
                        ),
                    );
                }
                if let Some(heads) = &state.base_heads {
                    map.insert(1, ids_value(heads));
                }
                if let Some(stubs) = &state.base_stubs {
                    map.insert(
                        2,
                        Value::Array(stubs.iter().map(|s| s.clone().into()).collect()),
                    );
                }
                if let Some(r) = &state.last_sync {
                    map.insert(3, reading_value(r));
                }
                if let Some(grants) = &state.left {
                    map.insert(4, ids_value(grants));
                }
                if state.personal {
                    map.insert(5, 1u64.into());
                }
                if let Some(entry) = &state.claiming {
                    map.insert(6, (*entry).into());
                }
                if let Some(checkpoint) = &state.kept_checkpoint {
                    map.insert(7, (*checkpoint).into());
                }
                if let Some(expressed) = state.expressed_again.as_ref().filter(|e| !e.is_empty()) {
                    map.insert(8, expressed.value());
                }
                Value::Map(map).encode()
            }
            Self::Pseudonym(pseudonym) => {
                let mut map = Map::new();
                if let Some(token) = &pseudonym.token {
                    map.insert(1, (*token.expose()).into());
                }
                if let Some((ed25519, mldsa)) = &pseudonym.seeds {
                    map.insert(2, (*ed25519.expose()).into());
                    map.insert(3, (*mldsa.expose()).into());
                }
                Value::Map(map).encode()
            }
            Self::Invite(record) | Self::Claim(record) => [
                &record.space[..],
                &record.invite_entry[..],
                record.secret.expose(),
            ]
            .concat(),
            Self::Vouched(person) | Self::Announced(person) => person.to_vec(),
            Self::Dropped(origin) => {
                let mut map = Map::new();
                map.insert(1, origin.code().into());
                if let DroppedOrigin::Held { kind, height } = origin {
                    map.insert(2, u64::from(*kind).into());
                    if let Some(height) = height {
                        map.insert(3, Value::Unsigned(*height));
                    }
                }
                Value::Map(map).encode()
            }
            Self::Replay(window) => [
                window.epoch.to_be_bytes(),
                window.counter.to_be_bytes(),
                window.window.to_be_bytes(),
            ]
            .concat(),
        }
    }
}

/// An `event` record's value. Its item is the event's ID, and its log is
/// the event's `log`, or for a genesis its own ID.
fn read_event(
    item: &[u8],
    value: &[u8],
    log: Option<&[u8; 32]>,
) -> Result<EventRecord, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let map = map_with(value, &[1, 2, 3], &[4, 5, 6, 7, 8])?;
    let signed = map[&1].as_bytes()?;
    let state = EventState::from_code(map[&2].as_unsigned()?).ok_or(malformed)?;
    let flags = map[&3].as_unsigned()?;
    if flags > FLAG_VERIFIED | FLAG_PROVISIONAL {
        return Err(malformed);
    }
    if map.contains_key(&4) != (state == EventState::Refused) {
        return Err(malformed);
    }
    let class = map
        .get(&4)
        .map(|class| {
            let class = class.as_text()?;
            if (1..=MAX_CLASS).contains(&class.len()) {
                Ok(class.to_owned())
            } else {
                Err(cbor::Malformed)
            }
        })
        .transpose()?;
    let first_sight = map.get(&5).map(reading).transpose()?;
    let frozen = Frozen::read(&map, state)?;
    let Value::Array(outer) = cbor::decode(signed)? else {
        return Err(malformed);
    };
    let [Value::Bytes(event), Value::Bytes(_signature)] = outer.as_slice() else {
        return Err(malformed);
    };
    let Value::Map(fields) = cbor::decode(event)? else {
        return Err(malformed);
    };
    let own = event_id(event);
    let event_log = match fields.get(&KEY_LOG) {
        Some(Value::Bytes(log)) => Some(log.as_slice()),
        Some(_) => None,
        None => Some(&own.0[..]),
    };
    if &own.0[..] != item || event_log.is_none() || event_log != log.map(|l| &l[..]) {
        return Err(malformed);
    }
    Ok(EventRecord {
        signed: signed.to_vec(),
        state,
        flags,
        class,
        first_sight,
        frozen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `event` record's value for a genesis-like event, which is its own
    /// log, with `extra` keys beside keys 1 to 3 (and 4 for state 2).
    fn event_value(state: u64, extra: &[(u64, Value)]) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let mut fields = Map::new();
        fields.insert(1, Value::Unsigned(0));
        let event = Value::Map(fields).encode();
        let id = event_id(&event).0;
        let signed = Value::Array(vec![event.into(), vec![0u8; 64].into()]).encode();
        let mut map = Map::new();
        map.insert(1, signed.into());
        map.insert(2, Value::Unsigned(state));
        map.insert(3, Value::Unsigned(FLAG_VERIFIED));
        if state == 2 {
            map.insert(4, "RefusedByRemoval".into());
        }
        for (key, value) in extra {
            map.insert(*key, value.clone());
        }
        (id.to_vec(), id, Value::Map(map).encode())
    }

    fn pair(name: &str, mode: u64) -> Value {
        Value::Array(vec![name.into(), Value::Unsigned(mode)])
    }

    fn read_frozen(state: u64, extra: &[(u64, Value)]) -> Result<Option<Frozen>, ErrorClass> {
        let (item, log, value) = event_value(state, extra);
        match TableValue::read(Table::Event, &item, &value, Some(&log))? {
            TableValue::Event(record) => {
                assert_eq!(*TableValue::Event(record.clone()).encode(), value);
                Ok(record.frozen)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn an_event_records_frozen_keys_read_back() {
        let caps = Value::Array(vec![pair("comment", 1), pair("suggest", 0)]);
        let attribution = Value::Array(vec![
            Value::Array(vec![Value::Unsigned(0), [3u8; 32].into()]),
            Value::Array(vec![Value::Unsigned(1), [7u8; 32].into(), "Carol".into()]),
        ]);
        let got = read_frozen(1, &[(6, caps.clone()), (7, attribution.clone())]).unwrap();
        assert_eq!(
            got,
            Some(Frozen {
                capabilities: vec![("comment".into(), 1), ("suggest".into(), 0)],
                attribution: vec![(0, [3; 32], None), (1, [7; 32], Some("Carol".into()))],
                voided_by: Vec::new(),
            })
        );
        // Attributed though its content was refused (state 2).
        let got = read_frozen(2, &[(6, caps.clone()), (7, attribution)]).unwrap();
        assert_eq!(got.map(|frozen| frozen.attribution.len()), Some(2));
        // No capabilities, and a refused unit with the events that void it.
        let voiders = Value::Array(vec![[1u8; 32].into(), [2u8; 32].into()]);
        let got = read_frozen(2, &[(6, Value::Array(Vec::new())), (8, voiders)]).unwrap();
        assert_eq!(
            got,
            Some(Frozen {
                capabilities: Vec::new(),
                attribution: Vec::new(),
                voided_by: vec![[1; 32], [2; 32]],
            })
        );
        assert_eq!(read_frozen(1, &[]).unwrap(), None);
    }

    #[test]
    fn an_event_records_frozen_keys_are_refused_out_of_place() {
        let malformed = Err(ErrorClass::Malformed);
        let empty = || Value::Array(Vec::new());
        let entry = |kind: u64, id: u8| Value::Array(vec![Value::Unsigned(kind), [id; 32].into()]);
        let member = Value::Array(vec![entry(0, 7)]);
        let voiders = Value::Array(vec![[1u8; 32].into()]);
        // Key 6 only with state 1 or 2.
        for state in [3, 4, 5, 6] {
            assert_eq!(read_frozen(state, &[(6, empty())]), malformed, "{state}");
        }
        // Keys 7 and 8 only beside key 6, key 8 with state 2, never both.
        assert_eq!(read_frozen(1, &[(7, member.clone())]), malformed);
        assert_eq!(read_frozen(2, &[(8, voiders.clone())]), malformed);
        assert_eq!(
            read_frozen(
                2,
                &[(6, empty()), (7, member.clone()), (8, voiders.clone())]
            ),
            malformed
        );
        // An attribution: 1 to 64 entries, types 0 to 3, labels of 1 to 64
        // bytes, strictly ascending by type then ID.
        for attribution in [
            Value::Array(Vec::new()),
            Value::Array(vec![entry(4, 1)]),
            Value::Array(vec![entry(1, 1), entry(0, 2)]),
            Value::Array(vec![entry(0, 1), entry(0, 1)]),
            Value::Array(vec![Value::Array(vec![
                Value::Unsigned(0),
                [1u8; 32].into(),
                "".into(),
            ])]),
            Value::Array((0..65).map(|n| entry(0, n)).collect()),
        ] {
            assert_eq!(read_frozen(1, &[(6, empty()), (7, attribution)]), malformed);
        }
        assert_eq!(
            read_frozen(1, &[(6, empty()), (8, voiders.clone())]),
            malformed
        );
        // Capabilities: names of 1 to 64 bytes, modes 0 and 1, strictly
        // ascending by name then mode, at most 64.
        for caps in [
            vec![pair("", 0)],
            vec![pair(&"n".repeat(65), 0)],
            vec![pair("b", 0), pair("a", 0)],
            vec![pair("a", 1), pair("a", 0)],
            vec![pair("a", 0), pair("a", 0)],
            vec![pair("a", 2)],
            vec![Value::Array(vec!["a".into()])],
            (0..65).map(|n| pair(&format!("c{n:02}"), 0)).collect(),
        ] {
            assert_eq!(read_frozen(1, &[(6, Value::Array(caps))]), malformed);
        }
        let most: Vec<Value> = (0..64).map(|n| pair(&format!("c{n:02}"), 0)).collect();
        assert!(read_frozen(1, &[(6, Value::Array(most))]).is_ok());
        let both = vec![pair("a", 0), pair("a", 1), pair("b", 1)];
        assert!(read_frozen(1, &[(6, Value::Array(both))]).is_ok());
        assert!(read_frozen(1, &[(6, Value::Array(vec![pair(&"n".repeat(64), 1)]))]).is_ok());
        // The member reference: a type 0 to 3 and an ID of 32 bytes.
        for member in [
            Value::Array(vec![Value::Unsigned(4), [7u8; 32].into()]),
            Value::Array(vec![Value::Unsigned(0), [7u8; 31].into()]),
            Value::Array(vec![Value::Unsigned(0)]),
        ] {
            assert_eq!(read_frozen(1, &[(6, empty()), (7, member)]), malformed);
        }
        // The voiding events: 1 to 64, strictly ascending.
        let ids = |n: u8| Value::Array((0..n).map(|k| Value::from([k; 32])).collect());
        assert_eq!(read_frozen(2, &[(6, empty()), (8, ids(0))]), malformed);
        assert_eq!(read_frozen(2, &[(6, empty()), (8, ids(65))]), malformed);
        assert!(read_frozen(2, &[(6, empty()), (8, ids(64))]).is_ok());
        let unordered = Value::Array(vec![[2u8; 32].into(), [1u8; 32].into()]);
        assert_eq!(read_frozen(2, &[(6, empty()), (8, unordered)]), malformed);
    }

    #[test]
    fn every_code_is_its_table() {
        for &table in Table::ALL {
            assert_eq!(Table::from_code(table.code()), Some(table));
        }
        let known = (0..=255u8).filter(|c| Table::from_code(*c).is_some());
        assert_eq!(known.count(), Table::ALL.len());
    }

    #[test]
    fn rotation_sets() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let two = [&[2u8][..], &a, &b].concat();
        assert!(rotation_set_ok(&two, 2));
        assert!(!rotation_set_ok(&[&[2u8][..], &b, &a].concat(), 2));
        assert!(!rotation_set_ok(&[&[1u8][..], &a].concat(), 2));
        assert!(rotation_set_ok(&[&[1u8][..], &a].concat(), 1));
        assert!(!rotation_set_ok(&[0u8], 0));
        assert!(!rotation_set_ok(&[], 1));
    }

    #[test]
    fn slot_references() {
        let reference = |index: u64| {
            Value::Array(vec![[0u8; 32].into(), index.into(), [1u8; 32].into()]).encode()
        };
        assert!(slot_reference_ok(&reference(MAX_SLOT_INDEX - 1)));
        assert!(!slot_reference_ok(&reference(MAX_SLOT_INDEX)));
        let two = Value::Array(vec![[0u8; 32].into(), 0u64.into()]).encode();
        assert!(!slot_reference_ok(&two));
    }

    #[test]
    fn an_empty_object_chunk_parses() {
        let item = [&[0u8; 32][..], &1u32.to_be_bytes()].concat();
        let value = vec![0u8; MIN_CHUNK];
        assert_eq!(
            TableValue::read(Table::Object, &item, &value, None),
            Ok(TableValue::Object(value))
        );
    }

    #[test]
    fn a_held_record_keeps_to_its_limits() {
        let held = |token: usize, size: u64, stamp: usize| {
            TableValue::Held(HeldRecord {
                token: vec![1; token],
                size,
                stamp: vec![2; stamp],
            })
            .encode()
        };
        let read = |value: &[u8]| TableValue::read(Table::Held, &[3; 32], value, Some(&[4; 32]));
        assert!(read(&held(1, 0, 1)).is_ok());
        assert!(read(&held(MAX_HELD_TOKEN, MAX_OBJECT_SIZE, MAX_HELD_STAMP)).is_ok());
        for value in [
            held(0, 1, 1),
            held(MAX_HELD_TOKEN + 1, 1, 1),
            held(1, MAX_OBJECT_SIZE + 1, 1),
            held(1, 1, 0),
            held(1, 1, MAX_HELD_STAMP + 1),
        ] {
            assert_eq!(read(&value), Err(ErrorClass::Malformed));
        }
        assert_eq!(
            TableValue::read(Table::Held, &[3; 31], &held(1, 1, 1), Some(&[4; 32])),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn a_retention_record_names_one_state() {
        let read =
            |value: &[u8]| TableValue::read(Table::Retention, &[3; 32], value, Some(&[4; 32]));
        for retention in [
            Retention::Kept,
            Retention::Cached { read: 7_200 },
            // A last read that is no multiple of the step is read as it is.
            Retention::Cached { read: 7_201 },
            Retention::Put { keep: false },
            Retention::Put { keep: true },
        ] {
            let value = TableValue::Retention(retention).encode();
            assert_eq!(read(&value), Ok(TableValue::Retention(retention)));
        }
        let map = |pairs: &[(u64, u64)]| {
            let mut map = Map::new();
            for (key, value) in pairs {
                map.insert(*key, (*value).into());
            }
            Value::Map(map).encode()
        };
        // An unknown state; a kept object with a last read; a cached one
        // without; a put one with a last read; no state; key 3 with a
        // state other than 3, and of a value other than 1; a key the
        // record does not have.
        for value in [
            map(&[(1, 0)]),
            map(&[(1, 4)]),
            map(&[(1, 4), (2, 0)]),
            map(&[(1, 3), (2, 0)]),
            map(&[(1, 1), (2, 0)]),
            map(&[(1, 2)]),
            map(&[(2, 0)]),
            map(&[(1, 1), (3, 1)]),
            map(&[(1, 2), (2, 0), (3, 1)]),
            map(&[(1, 3), (3, 0)]),
            map(&[(1, 3), (3, 2)]),
            map(&[(1, 3), (2, 0), (3, 1)]),
            map(&[(1, 3), (4, 1)]),
        ] {
            assert_eq!(read(&value), Err(ErrorClass::Malformed));
        }
        let kept = TableValue::Retention(Retention::Kept).encode();
        assert_eq!(
            TableValue::read(Table::Retention, &[3; 31], &kept, Some(&[4; 32])),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn head_tips_stay_ordered() {
        let mut head = Head::new([1; 16]);
        for (log, author) in [(3u8, 1u8), (1, 2), (1, 1)] {
            head.set_tip(Tip {
                log: [log; 32],
                author: DeviceId([author; 32]),
                seq: 1,
                event: [9; 32],
            })
            .unwrap();
        }
        let read = Head::read(&head.encode()).unwrap();
        assert_eq!(read, head);
        assert_eq!(
            head.tip(&[1; 32], &DeviceId([2; 32])).map(|t| t.seq),
            Some(1)
        );
        assert!(head.tip(&[2; 32], &DeviceId([2; 32])).is_none());
        assert!(head.may_sign(&[7; 32]));
    }
}
