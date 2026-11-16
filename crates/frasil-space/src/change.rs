//! Changes (roster.md, "Changes").
//!
//! A change is a deterministic CBOR map:
//!
//! | Key | Field | Value |
//! |---|---|---|
//! | 0 | `op` | 0 grant, 1 change, 2 remove, 3 policy, 4 succeed (reserved) |
//! | 1 | `member` | a member reference |
//! | 2 | `level` | 0 to 2 |
//! | 3 | `capabilities` | 1 to 32 pairs `[name, mode]`, strictly ascending by name |
//! | 4 | `label` | 1 to 64 bytes of UTF-8 |
//! | 5 | `history` | 0 from now on, 1 with history |
//! | 6 | `via` | 0 code, 1 link, 2 lookup, 3 none |
//! | 7 | `session` | bytes(16) |
//! | 8 | `replaces` | bytes(32) |
//! | 9 | `exchange_hybrid` | bytes(1,216) |
//! | 10 | `mldsa` | bytes(1,952) |
//! | 11 | `policy` | the whole new space policy |
//! | 12 | `ed25519` | bytes(32) |
//! | 13 | `expires_at` | unsigned, ext-guests.md's |
//! | 14 | `claims` | reserved |
//! | 15 | `rank` | 0 to 255: an administrator's rank |
//!
//! Which keys each change carries ("req" required, "opt" optional):
//!
//! | Change | 1 | 2 | 3, 4 | 5, 6 | 7 | 8 | 9, 10, 12 | 11 | 13 |
//! |---|---|---|---|---|---|---|---|---|---|
//! | grant of a device | req | req | opt | req | opt | | req | | opt, only with 7 |
//! | grant of a person | req | req | opt | req | | opt | | | |
//! | grant of a space | req | req | opt | req | | | | | |
//! | change | req | opt | opt | | | | | | |
//! | remove | req | | | | | | | | |
//! | policy | | | | | | | | req | |
//!
//! Key 15 is required on a grant of a device without key 7, or a change,
//! whose level is `administer`, and absent beside any other level; a rank
//! above 255 is `Malformed` (roster.md, 2.3 Changes, "Ranks").
//!
//! [`Change::read`] checks one change, in this order:
//!
//! ```text
//! 1. A map with an unsigned key 0, the op; an op from 5 is Malformed.
//! 2. A reserved hook of ext-invite-links.md: op 4, member type 3, or
//!    key 14.                                                       else ExtensionRequired (held)
//! 3. Key 13 only on a grant of a device with key 7.
//!    The keys of its row, each with its type and length; a change
//!    carries at least one of keys 2, 3 and 4; key 15 exactly with
//!    administer on a device grant without key 7 or a change, at
//!    most 255; a policy as section 2.6; a space member is not this
//!    space.                                                         else Malformed (or the policy's class)
//! 4. administer only for a device member without session.         else AdministerNotDevice
//! 5. A granted device's Ed25519 and X-Wing keys valid.             else InvalidKey
//! 6. Its keys give its member ID (roster.md, "A device's keys").   else NotCommitted
//! ```
//!
//! A device grant's keys 12, 10 and 9 are its Ed25519, ML-DSA-65 and X-Wing
//! keys, and its member ID is their device ID (crypto.md, "A device's
//! keys").

use crate::member::{
    Capability, HistoryMode, Level, MemberRef, MemberType, Via, read_capabilities, read_name,
};
use crate::policy::Policy;
use crate::{Limits, SpaceClass, ext};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, IdentityKey};
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use std::sync::Arc;

/// A change's keys.
pub mod key {
    /// `op`.
    pub const OP: u64 = 0;
    /// `member`.
    pub const MEMBER: u64 = 1;
    /// `level`.
    pub const LEVEL: u64 = 2;
    /// `capabilities`.
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
    /// `exchange_hybrid`.
    pub const EXCHANGE_HYBRID: u64 = 9;
    /// `mldsa`.
    pub const MLDSA: u64 = 10;
    /// `policy`.
    pub const POLICY: u64 = 11;
    /// `ed25519`: a granted device's Ed25519 identity key.
    pub const ED25519: u64 = 12;
    /// `expires_at`.
    pub const EXPIRES_AT: u64 = 13;
    /// `claims`, reserved for ext-invite-links.md.
    pub const CLAIMS: u64 = 14;
    /// `rank`: an administrator's rank.
    pub const RANK: u64 = 15;
}

/// The top rank, the founder's (roster.md, 2.3 Changes, "Ranks"). A larger
/// rank outranks a smaller one.
pub const MAX_RANK: u8 = 255;

/// A guest's session ID, change key 7.
pub const SESSION_BYTES: usize = 16;

/// A change's op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    /// 0: admits a member.
    Grant,
    /// 1: sets the level, capabilities or label of a member in the roster.
    Change,
    /// 2: ends a member.
    Remove,
    /// 3: replaces the space policy.
    Policy,
    /// 4: reserved for ext-invite-links.md. A core implementation holds a
    /// roster event that uses it as `ExtensionRequired`.
    Succeed,
}

impl Op {
    /// Every op, by code.
    pub const ALL: [Op; 5] = [
        Self::Grant,
        Self::Change,
        Self::Remove,
        Self::Policy,
        Self::Succeed,
    ];

    /// The op's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Grant => 0,
            Self::Change => 1,
            Self::Remove => 2,
            Self::Policy => 3,
            Self::Succeed => 4,
        }
    }

    /// The op of a code. Codes from 5 are `Malformed`.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.code() == code)
    }

    /// The op's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Change => "change",
            Self::Remove => "remove",
            Self::Policy => "policy",
            Self::Succeed => "succeed",
        }
    }
}

/// One change of a roster part. Every field but `op` is present exactly
/// when its key is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Change {
    /// Key 0.
    pub op: Op,
    /// Key 1; `None` only for a policy change.
    pub member: Option<MemberRef>,
    /// Key 2.
    pub level: Option<Level>,
    /// Key 3, strictly ascending by name.
    pub capabilities: Option<Vec<Capability>>,
    /// Key 4.
    pub label: Option<String>,
    /// Key 5.
    pub history: Option<HistoryMode>,
    /// Key 6.
    pub via: Option<Via>,
    /// Key 7: the session a guest belongs to.
    pub session: Option<[u8; SESSION_BYTES]>,
    /// Key 8: the person ID a granted person replaces.
    pub replaces: Option<[u8; 32]>,
    /// Keys 9, 10 and 12 of a device grant.
    pub keys: Option<Arc<DeviceKeys>>,
    /// Key 11: the whole new space policy.
    pub policy: Option<Policy>,
    /// Key 13: an instant for administering devices (ext-guests.md). A core
    /// implementation checks its type and otherwise ignores it.
    pub expires_at: Option<u64>,
    /// Key 14: reserved for ext-invite-links.md.
    pub claims: Option<u64>,
    /// Key 15: the rank of an administrator this change makes one, exactly
    /// with `administer` (roster.md, 2.3 Changes, "Ranks").
    pub rank: Option<u8>,
}

/// Steps 5 and 6 for a device grant: its Ed25519 and X-Wing keys valid,
/// then its keys giving its member ID (roster.md, "A device's keys").
///
/// # Errors
///
/// `InvalidKey`, then `NotCommitted`.
///
/// The checks of keys that give a device ID whose keys passed them before
/// in this process are not run again: only one set of keys gives a device
/// ID, so they are those keys, and pass.
pub fn device_keys(
    member: &MemberRef,
    ed: [u8; 32],
    mldsa: [u8; MLDSA65_PUBLIC],
    xwing: [u8; XWING_PUBLIC],
) -> Result<DeviceKeys, SpaceClass> {
    // The keys' device ID, computed before any check; the keys are handed
    // out only once their checks passed, here or before.
    let keys = DeviceKeys {
        ed: IdentityKey(ed),
        keys: HybridKeys::from_checked(Box::new(mldsa), Some(Box::new(xwing))),
    };
    let id = DeviceId(member.id);
    if keys.device_id() == id && checked_keys().contains(&id) {
        return Ok(keys);
    }
    ed25519_valid(&ed)?;
    xwing_valid(&xwing)?;
    keys.check(&id)?;
    let mut checked = checked_keys();
    if checked.len() >= CHECKED_AT_MOST {
        checked.clear();
    }
    checked.insert(id);
    Ok(keys)
}

/// How many device IDs [`device_keys`] remembers before it starts again.
const CHECKED_AT_MOST: usize = 16_384;

/// The device IDs whose grant keys passed [`device_keys`]'s checks.
fn checked_keys() -> std::sync::MutexGuard<'static, std::collections::BTreeSet<DeviceId>> {
    static CHECKED: std::sync::Mutex<std::collections::BTreeSet<DeviceId>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    CHECKED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// What makes a change one of ext-invite-links.md's reserved hooks: op 4,
/// member type 3 or key 14.
fn reserved(op: u64, map: &Map) -> bool {
    op == Op::Succeed.code()
        || map
            .get(&key::MEMBER)
            .and_then(MemberRef::peek_type)
            .is_some_and(|code| code == MemberType::Invite.code())
        || map.contains_key(&key::CLAIMS)
}

fn bytes_of<const N: usize>(map: &Map, key: u64) -> Result<Option<[u8; N]>, SpaceClass> {
    Ok(map
        .get(&key)
        .map(|value| value.as_byte_array::<N>())
        .transpose()?)
}

fn code_of<T>(map: &Map, key: u64, of: impl Fn(u64) -> Option<T>) -> Result<Option<T>, SpaceClass> {
    map.get(&key)
        .map(|value| of(value.as_unsigned()?).ok_or_else(malformed))
        .transpose()
}

impl Change {
    /// A change with only its op and member.
    pub fn new(op: Op, member: Option<MemberRef>) -> Self {
        Self {
            op,
            member,
            level: None,
            capabilities: None,
            label: None,
            history: None,
            via: None,
            session: None,
            replaces: None,
            keys: None,
            policy: None,
            expires_at: None,
            claims: None,
            rank: None,
        }
    }

    /// A grant of a device, with its keys, whose device ID is the member
    /// ID.
    pub fn grant_device(keys: DeviceKeys, level: Level, history: HistoryMode, via: Via) -> Self {
        Self {
            level: Some(level),
            history: Some(history),
            via: Some(via),
            ..Self::new(Op::Grant, Some(MemberRef::device(keys.device_id())))
        }
        .with_keys(keys)
    }

    /// The change with a device's keys, change keys 9, 10 and 12.
    pub fn with_keys(self, keys: DeviceKeys) -> Self {
        Self {
            keys: Some(Arc::new(keys)),
            ..self
        }
    }

    /// A grant of a device at `administer` with its rank, whose device ID
    /// is the member ID.
    pub fn grant_administrator(keys: DeviceKeys, rank: u8, history: HistoryMode, via: Via) -> Self {
        Self::grant_device(keys, Level::Administer, history, via).with_rank(rank)
    }

    /// The change with key 15, the rank of the administrator it makes:
    /// required with `administer` on a device grant or a change, refused
    /// beside any other level (roster.md, 2.3 Changes, "Ranks").
    pub fn with_rank(self, rank: u8) -> Self {
        Self {
            rank: Some(rank),
            ..self
        }
    }

    /// A grant of a person or a space.
    pub fn grant(member: MemberRef, level: Level, history: HistoryMode, via: Via) -> Self {
        Self {
            level: Some(level),
            history: Some(history),
            via: Some(via),
            ..Self::new(Op::Grant, Some(member))
        }
    }

    /// A removal.
    pub fn remove(member: MemberRef) -> Self {
        Self::new(Op::Remove, Some(member))
    }

    /// A change of a member's level. A change to `administer` needs a rank
    /// ([`Change::raise`], or [`Change::with_rank`]).
    pub fn set_level(member: MemberRef, level: Level) -> Self {
        Self {
            level: Some(level),
            ..Self::new(Op::Change, Some(member))
        }
    }

    /// A change that raises a member to `administer` at `rank`. A rank is
    /// set only so: an administrator's rank never changes in place
    /// (`RankInPlace`), so another rank takes a lowering first.
    pub fn raise(member: MemberRef, rank: u8) -> Self {
        Self::set_level(member, Level::Administer).with_rank(rank)
    }

    /// A policy change.
    pub fn set_policy(policy: Policy) -> Self {
        Self {
            policy: Some(policy),
            ..Self::new(Op::Policy, None)
        }
    }

    /// Whether this change grants a device.
    pub fn grants_device(&self) -> bool {
        self.op == Op::Grant && self.member.is_some_and(|m| m.kind == MemberType::Device)
    }

    /// The change as CBOR.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(key::OP, Value::Unsigned(self.op.code()));
        if let Some(member) = &self.member {
            map.insert(key::MEMBER, member.to_value());
        }
        if let Some(level) = self.level {
            map.insert(key::LEVEL, Value::Unsigned(level.code()));
        }
        if let Some(capabilities) = &self.capabilities {
            let pairs = capabilities.iter().map(Capability::to_value).collect();
            map.insert(key::CAPABILITIES, Value::Array(pairs));
        }
        if let Some(label) = &self.label {
            map.insert(key::LABEL, Value::Text(label.clone()));
        }
        if let Some(history) = self.history {
            map.insert(key::HISTORY, Value::Unsigned(history.code()));
        }
        if let Some(via) = self.via {
            map.insert(key::VIA, Value::Unsigned(via.code()));
        }
        if let Some(session) = self.session {
            map.insert(key::SESSION, Value::Bytes(session.to_vec()));
        }
        if let Some(replaces) = self.replaces {
            map.insert(key::REPLACES, Value::Bytes(replaces.to_vec()));
        }
        if let Some(keys) = &self.keys {
            let xwing = keys
                .keys
                .xwing()
                .expect("a granted device has an X-Wing key");
            map.insert(key::EXCHANGE_HYBRID, Value::Bytes(xwing.to_vec()));
            map.insert(key::MLDSA, Value::Bytes(keys.keys.mldsa().to_vec()));
            map.insert(key::ED25519, Value::Bytes(keys.ed.0.to_vec()));
        }
        if let Some(policy) = &self.policy {
            map.insert(key::POLICY, Value::Bytes(policy.encode()));
        }
        if let Some(expires_at) = self.expires_at {
            map.insert(key::EXPIRES_AT, Value::Unsigned(expires_at));
        }
        if let Some(claims) = self.claims {
            map.insert(key::CLAIMS, Value::Unsigned(claims));
        }
        if let Some(rank) = self.rank {
            map.insert(key::RANK, Value::Unsigned(u64::from(rank)));
        }
        Value::Map(map)
    }

    /// Reads and checks one change, in the module's order. `space` is the
    /// space's ID, which no space member names; `None` inside a genesis,
    /// which cannot name it.
    ///
    /// # Errors
    ///
    /// `Malformed` (or a policy's `UnsupportedVersion`), `ExtensionRequired`,
    /// `AdministerNotDevice`, `InvalidKey` or `NotCommitted`.
    pub fn read(
        value: &Value,
        space: Option<&[u8; 32]>,
        limits: &Limits,
    ) -> Result<Self, SpaceClass> {
        // 1.
        let map = value.as_map()?;
        let op = map.get(&key::OP).ok_or_else(malformed)?.as_unsigned()?;
        let op_known = Op::from_code(op).ok_or_else(malformed)?;
        // 2.
        if reserved(op, map) {
            return ext::reserved_change(value, space, limits);
        }
        // 3.
        use key as k;
        let member = map.get(&k::MEMBER).map(MemberRef::read).transpose()?;
        let kind = member.map(|m| m.kind);
        let expires_at = match map.get(&k::EXPIRES_AT) {
            Some(value)
                if op_known == Op::Grant
                    && kind == Some(MemberType::Device)
                    && map.contains_key(&k::SESSION) =>
            {
                Some(value.as_unsigned()?)
            }
            Some(_) => return Err(malformed()),
            None => None,
        };
        let (allowed, required): (&[u64], &[u64]) = match (op_known, kind) {
            (Op::Policy, _) => (&[k::OP, k::POLICY], &[k::OP, k::POLICY]),
            (_, None) => return Err(malformed()),
            (Op::Grant, Some(MemberType::Device)) => (
                &[
                    k::OP,
                    k::MEMBER,
                    k::LEVEL,
                    k::CAPABILITIES,
                    k::LABEL,
                    k::HISTORY,
                    k::VIA,
                    k::SESSION,
                    k::EXCHANGE_HYBRID,
                    k::MLDSA,
                    k::ED25519,
                    k::EXPIRES_AT,
                    k::RANK,
                ],
                &[
                    k::OP,
                    k::MEMBER,
                    k::LEVEL,
                    k::HISTORY,
                    k::VIA,
                    k::EXCHANGE_HYBRID,
                    k::MLDSA,
                    k::ED25519,
                ],
            ),
            (Op::Grant, Some(MemberType::Person)) => (
                &[
                    k::OP,
                    k::MEMBER,
                    k::LEVEL,
                    k::CAPABILITIES,
                    k::LABEL,
                    k::HISTORY,
                    k::VIA,
                    k::REPLACES,
                    k::RANK,
                ],
                &[k::OP, k::MEMBER, k::LEVEL, k::HISTORY, k::VIA],
            ),
            (Op::Grant, Some(_)) => (
                &[
                    k::OP,
                    k::MEMBER,
                    k::LEVEL,
                    k::CAPABILITIES,
                    k::LABEL,
                    k::HISTORY,
                    k::VIA,
                    k::RANK,
                ],
                &[k::OP, k::MEMBER, k::LEVEL, k::HISTORY, k::VIA],
            ),
            (Op::Change, Some(_)) => (
                &[
                    k::OP,
                    k::MEMBER,
                    k::LEVEL,
                    k::CAPABILITIES,
                    k::LABEL,
                    k::RANK,
                ],
                &[k::OP, k::MEMBER],
            ),
            (Op::Remove, Some(_)) => (&[k::OP, k::MEMBER], &[k::OP, k::MEMBER]),
            (Op::Succeed, Some(_)) => return Err(malformed()),
        };
        if !map.keys().all(|key| allowed.contains(key))
            || !required.iter().all(|key| map.contains_key(key))
        {
            return Err(malformed());
        }
        if op_known == Op::Change
            && ![k::LEVEL, k::CAPABILITIES, k::LABEL]
                .iter()
                .any(|key| map.contains_key(key))
        {
            return Err(malformed());
        }
        let policy = map
            .get(&k::POLICY)
            .map(|value| Policy::read(value.as_bytes()?))
            .transpose()?;
        let level = code_of(map, k::LEVEL, Level::from_code)?;
        // A rank comes exactly with administer: required on a grant of a
        // device without a session or a change that sets administer,
        // absent beside any other level.
        let rank = map
            .get(&k::RANK)
            .map(|value| u8::try_from(value.as_unsigned()?).map_err(|_| malformed()))
            .transpose()?;
        let needs_rank = level == Some(Level::Administer)
            && kind == Some(MemberType::Device)
            && !map.contains_key(&k::SESSION);
        if (rank.is_some() && level != Some(Level::Administer)) || (needs_rank && rank.is_none()) {
            return Err(malformed());
        }
        let capabilities = map
            .get(&k::CAPABILITIES)
            .map(|value| read_capabilities(value, limits.max_capabilities))
            .transpose()?;
        let label = map.get(&k::LABEL).map(read_name).transpose()?;
        let history = code_of(map, k::HISTORY, HistoryMode::from_code)?;
        let via = code_of(map, k::VIA, Via::from_code)?;
        let session = bytes_of::<SESSION_BYTES>(map, k::SESSION)?;
        let replaces = bytes_of::<32>(map, k::REPLACES)?;
        let xwing = bytes_of::<XWING_PUBLIC>(map, k::EXCHANGE_HYBRID)?;
        let mldsa = bytes_of::<MLDSA65_PUBLIC>(map, k::MLDSA)?;
        let ed = bytes_of::<32>(map, k::ED25519)?;
        if let (Some(member), Some(space)) = (member, space)
            && member.kind == MemberType::Space
            && &member.id == space
        {
            return Err(malformed());
        }
        // 4.
        if level == Some(Level::Administer)
            && (kind != Some(MemberType::Device) || session.is_some())
        {
            return Err(SpaceClass::AdministerNotDevice);
        }
        // 5 and 6.
        let keys = match (member, xwing, mldsa, ed) {
            (Some(member), Some(xwing), Some(mldsa), Some(ed)) => {
                Some(Arc::new(device_keys(&member, ed, mldsa, xwing)?))
            }
            _ => None,
        };
        Ok(Self {
            op: op_known,
            member,
            level,
            capabilities,
            label,
            history,
            via,
            session,
            replaces,
            keys,
            policy,
            expires_at,
            claims: None,
            rank,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::Class;

    fn read(value: Value) -> Result<Change, &'static str> {
        Change::read(&value, Some(&[9; 32]), &Limits::PROTOCOL).map_err(Class::name)
    }

    fn map(pairs: &[(u64, Value)]) -> Value {
        Value::Map(pairs.iter().cloned().collect())
    }

    fn member(kind: u64, id: [u8; 32]) -> Value {
        Value::Array(vec![Value::Unsigned(kind), Value::Bytes(id.to_vec())])
    }

    #[test]
    fn removals_and_changes_round_trip() {
        let removal = map(&[(0, Value::Unsigned(2)), (1, member(1, [1; 32]))]);
        assert_eq!(read(removal.clone()).map(|c| c.to_value()), Ok(removal));
        let change = map(&[
            (0, Value::Unsigned(1)),
            (1, member(0, [1; 32])),
            (2, Value::Unsigned(0)),
        ]);
        assert_eq!(read(change.clone()).map(|c| c.to_value()), Ok(change));
        let nothing = map(&[(0, Value::Unsigned(1)), (1, member(0, [1; 32]))]);
        assert_eq!(read(nothing), Err("Malformed"));
    }

    #[test]
    #[cfg(not(feature = "ext-invite-links"))]
    fn reserved_hooks_are_held() {
        let succeed = map(&[(0, Value::Unsigned(4)), (1, member(1, [1; 32]))]);
        assert_eq!(read(succeed), Err("ExtensionRequired"));
        let invite = map(&[(0, Value::Unsigned(2)), (1, member(3, [1; 32]))]);
        assert_eq!(read(invite), Err("ExtensionRequired"));
        let claims = map(&[
            (0, Value::Unsigned(2)),
            (1, member(1, [1; 32])),
            (14, Value::Unsigned(1)),
        ]);
        assert_eq!(read(claims), Err("ExtensionRequired"));
        let op5 = map(&[(0, Value::Unsigned(5)), (1, member(3, [1; 32]))]);
        assert_eq!(read(op5), Err("Malformed"));
        let type4 = map(&[(0, Value::Unsigned(2)), (1, member(4, [1; 32]))]);
        assert_eq!(read(type4), Err("Malformed"));
    }

    #[test]
    fn administer_is_for_devices_only() {
        let person = map(&[
            (0, Value::Unsigned(0)),
            (1, member(1, [1; 32])),
            (2, Value::Unsigned(2)),
            (5, Value::Unsigned(1)),
            (6, Value::Unsigned(0)),
        ]);
        assert_eq!(read(person), Err("AdministerNotDevice"));
        let raise = map(&[
            (0, Value::Unsigned(1)),
            (1, member(2, [1; 32])),
            (2, Value::Unsigned(2)),
        ]);
        assert_eq!(read(raise), Err("AdministerNotDevice"));
        let itself = map(&[
            (0, Value::Unsigned(0)),
            (1, member(2, [9; 32])),
            (2, Value::Unsigned(0)),
            (5, Value::Unsigned(1)),
            (6, Value::Unsigned(3)),
        ]);
        assert_eq!(read(itself), Err("Malformed"));
    }

    /// Key 15 comes exactly with `administer` on a device grant without a
    /// session or a change, at most 255 (roster.md, 2.3 Changes, "Ranks").
    #[test]
    fn a_rank_comes_exactly_with_administer() {
        let raise = |rank: Option<u64>, level: u64| {
            let mut pairs = vec![
                (0, Value::Unsigned(1)),
                (1, member(0, [1; 32])),
                (2, Value::Unsigned(level)),
            ];
            if let Some(rank) = rank {
                pairs.push((15, Value::Unsigned(rank)));
            }
            map(&pairs)
        };
        let read_raise = read(raise(Some(7), 2)).unwrap();
        assert_eq!(read_raise.rank, Some(7));
        assert_eq!(read_raise.to_value(), raise(Some(7), 2));
        assert_eq!(read(raise(None, 2)), Err("Malformed"));
        assert_eq!(read(raise(Some(7), 1)), Err("Malformed"));
        assert_eq!(read(raise(Some(256), 2)), Err("Malformed"));
        // A removal never carries one.
        let removal = map(&[
            (0, Value::Unsigned(2)),
            (1, member(0, [1; 32])),
            (15, Value::Unsigned(1)),
        ]);
        assert_eq!(read(removal), Err("Malformed"));
        // A person's administer is refused as such, rank or not.
        let person = map(&[
            (0, Value::Unsigned(0)),
            (1, member(1, [1; 32])),
            (2, Value::Unsigned(2)),
            (5, Value::Unsigned(1)),
            (6, Value::Unsigned(0)),
            (15, Value::Unsigned(3)),
        ]);
        assert_eq!(read(person), Err("AdministerNotDevice"));
        assert_eq!(
            Change::raise(MemberRef::device(DeviceId([1; 32])), 9).rank,
            Some(9)
        );
    }

    /// A device ID whose keys passed their checks is remembered; keys that
    /// give another ID, or keys that fail, are checked in full again, in
    /// the same order.
    #[test]
    fn grant_keys_checked_once_give_the_same_verdicts() {
        let fixture = frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&[0x5a; 32]);
        let keys = fixture.device_keys();
        let id = keys.device_id();
        let member = MemberRef::device(id);
        let mldsa = *keys.keys.mldsa();
        let xwing = *keys.keys.xwing().expect("an X-Wing key");
        for _ in 0..2 {
            assert_eq!(
                device_keys(&member, keys.ed.0, mldsa, xwing),
                Ok(keys.clone())
            );
        }
        // The same keys named under another device ID.
        let other = MemberRef::device(DeviceId([0x77; 32]));
        assert_eq!(
            device_keys(&other, keys.ed.0, mldsa, xwing).map_err(Class::name),
            Err("NotCommitted")
        );
        // An X-Wing key that fails its check, under the ID checked before:
        // the keys give another ID, and the key check comes first.
        let mut bad = xwing;
        bad[..3].fill(0xff);
        assert_eq!(
            device_keys(&member, keys.ed.0, mldsa, bad).map_err(Class::name),
            Err("InvalidKey")
        );
        // An Ed25519 key that fails its check.
        assert_eq!(
            device_keys(&member, [0xff; 32], mldsa, xwing).map_err(Class::name),
            Err("InvalidKey")
        );
    }
}
