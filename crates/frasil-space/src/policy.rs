//! The space descriptor and the space policy (roster.md, "The space
//! descriptor" and "The space policy"), and the merge of concurrent
//! policies ("The roster at a place").
//!
//! Reading either, in order:
//!
//! ```text
//! 1. Deterministic CBOR, a map with an unsigned key 1.          else Malformed
//! 2. Key 1 is 1.                                                else UnsupportedVersion
//! 3. A descriptor: every key from 1; key 2, when present, from 1.
//!    A key 2 from 3, or a key from 5, is a later document's: read
//!    nothing more, and hold the space (DescriptorKind::Reserved).
//!    Otherwise key 3 present exactly when key 2 is, and 32 bytes;
//!    key 4, when present, text of 1 to 255 bytes.
//!    A policy: keys 1 to 6 only, each an unsigned integer that
//!    check_policy accepts and that is not its default; key 6
//!    equal to 1.                                                else Malformed
//! ```

use crate::SpaceClass;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::time::{Timer, check_policy};

/// The version of the descriptor and of the policy, key 1.
pub const VERSION: u64 = 1;

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// Steps 1 and 2: the map, with key 1 equal to 1.
fn read_versioned(data: &[u8]) -> Result<Map, SpaceClass> {
    let value = cbor::decode(data)?;
    let Value::Map(map) = value else {
        return Err(malformed());
    };
    let version = map.get(&1).ok_or_else(malformed)?.as_unsigned()?;
    if version != VERSION {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// The space descriptor.

/// A space's kind, descriptor key 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DescriptorKind {
    /// Key 2 absent: an ordinary space.
    Space,
    /// 1: a restricted space (ext-restricted-spaces.md). A core
    /// implementation does not use one: once it has read the descriptor, it
    /// holds the space's other events as `ExtensionRequired`.
    Restricted,
    /// 2: a carve-out (ext-restricted-spaces.md). A core implementation
    /// treats it as an ordinary space.
    CarveOut,
    /// A later document's descriptor: key 2 from
    /// [`RESERVED_DESCRIPTOR_KIND`], or any key from
    /// [`RESERVED_DESCRIPTOR_KEY`] (roster.md, "The space descriptor"),
    /// with key 2, or 0 when it is absent. This implementation defines
    /// none: it reads nothing more of the descriptor, holds every event of
    /// the space after the genesis as `ExtensionRequired`, signs nothing in
    /// the space, and an edge of the grant graph to the space never counts
    /// (`GrantOfReserved`).
    Reserved(u64),
}

/// The first descriptor kind reserved for later documents.
pub const RESERVED_DESCRIPTOR_KIND: u64 = 3;
/// The first descriptor key reserved for later documents.
pub const RESERVED_DESCRIPTOR_KEY: u64 = 5;

impl DescriptorKind {
    /// The kind's code, `None` for an ordinary space, whose key 2 is absent,
    /// and for a later document's descriptor without key 2.
    pub const fn code(self) -> Option<u64> {
        match self {
            Self::Space | Self::Reserved(0) => None,
            Self::Restricted => Some(1),
            Self::CarveOut => Some(2),
            Self::Reserved(code) => Some(code),
        }
    }

    /// The kind's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Restricted => "restricted",
            Self::CarveOut => "carve-out",
            Self::Reserved(_) => "reserved",
        }
    }

    /// Whether a later document defines the descriptor: this
    /// implementation holds the space ([`DescriptorKind::Reserved`]).
    pub const fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved(_))
    }
}

/// The space descriptor, key 4 of the genesis's roster part. It never
/// changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Descriptor {
    /// Key 2.
    pub kind: DescriptorKind,
    /// Key 3: the parent's space ID, present exactly when the kind is
    /// [`DescriptorKind::Restricted`] or [`DescriptorKind::CarveOut`]; never
    /// read from a later document's descriptor.
    pub parent: Option<[u8; 32]>,
    /// Key 4: what kind of space the application made it, 1 to
    /// [`MAX_APPLICATION_BYTES`] bytes of text that the protocol never
    /// reads.
    pub application: Option<String>,
}

/// The longest application kind a descriptor carries, in bytes.
pub const MAX_APPLICATION_BYTES: usize = 255;

impl Descriptor {
    /// An ordinary space's descriptor.
    pub const ORDINARY: Self = Self {
        kind: DescriptorKind::Space,
        parent: None,
        application: None,
    };

    /// Reads a descriptor, in the module's order. A later document's
    /// descriptor reads as [`DescriptorKind::Reserved`], with no parent and
    /// no application kind: nothing more of it is read.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn read(data: &[u8]) -> Result<Self, SpaceClass> {
        let map = read_versioned(data)?;
        if map.contains_key(&0) {
            return Err(malformed());
        }
        let code = match map.get(&2) {
            None => 0,
            Some(value) => match value.as_unsigned()? {
                0 => return Err(malformed()),
                code => code,
            },
        };
        if code >= RESERVED_DESCRIPTOR_KIND || map.keys().any(|&key| key >= RESERVED_DESCRIPTOR_KEY)
        {
            return Ok(Self {
                kind: DescriptorKind::Reserved(code),
                parent: None,
                application: None,
            });
        }
        let kind = match code {
            0 => DescriptorKind::Space,
            1 => DescriptorKind::Restricted,
            _ => DescriptorKind::CarveOut,
        };
        let parent = map
            .get(&3)
            .map(|value| value.as_byte_array::<32>())
            .transpose()?;
        if parent.is_some() != (kind != DescriptorKind::Space) {
            return Err(malformed());
        }
        let application = map
            .get(&4)
            .map(|value| value.as_text().map(str::to_owned))
            .transpose()?;
        if application
            .as_ref()
            .is_some_and(|a| a.is_empty() || a.len() > MAX_APPLICATION_BYTES)
        {
            return Err(malformed());
        }
        Ok(Self {
            kind,
            parent,
            application,
        })
    }

    /// The descriptor's one encoding. A later document's descriptor read
    /// here kept only its kind, so its encoding is not the one read.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        if let Some(code) = self.kind.code() {
            map.insert(2, Value::Unsigned(code));
        }
        if let Some(parent) = self.parent {
            map.insert(3, Value::Bytes(parent.to_vec()));
        }
        if let Some(application) = &self.application {
            map.insert(4, Value::Text(application.clone()));
        }
        Value::Map(map).encode()
    }
}

// ---------------------------------------------------------------------------
// The space policy.

/// `agent_waiting_period`'s default, key 2.
pub const DEFAULT_AGENT_WAITING_PERIOD: u64 = 259_200;
/// `gap_key_timeout`'s default, key 5.
pub const DEFAULT_GAP_KEY_TIMEOUT: u64 = 604_800;

/// The space policy: key 3 of the genesis's roster part and key 11 of a
/// policy change. A core implementation that lacks an extension still
/// checks, carries and merges that extension's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Policy {
    /// Key 2, ext-recovery-agent.md's waiting period, in seconds.
    pub agent_waiting_period: u64,
    /// Key 3, ext-guests.md's bounded window; `None` is off.
    pub bounded_window: Option<u64>,
    /// Key 4, ext-guests.md's online freshness; `None` is off.
    pub online_freshness: Option<u64>,
    /// Key 5: refused units' content and a restored member's gap keys.
    pub gap_key_timeout: u64,
    /// Key 6: the space admits no person whose list holds a recovery agent.
    pub forbid_agents: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            agent_waiting_period: DEFAULT_AGENT_WAITING_PERIOD,
            bounded_window: None,
            online_freshness: None,
            gap_key_timeout: DEFAULT_GAP_KEY_TIMEOUT,
            forbid_agents: false,
        }
    }
}

/// The policy's duration keys: their timers and defaults (`None`: absent
/// means off).
const DURATIONS: [(u64, Timer, Option<u64>); 4] = [
    (
        2,
        Timer::AgentWaitingPeriod,
        Some(DEFAULT_AGENT_WAITING_PERIOD),
    ),
    (3, Timer::BoundedWindow, None),
    (4, Timer::OnlineFreshness, None),
    (5, Timer::GapKeyTimeout, Some(DEFAULT_GAP_KEY_TIMEOUT)),
];

/// Key 6.
const FORBID_AGENTS: u64 = 6;

impl Policy {
    /// Reads a policy, in the module's order.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn read(data: &[u8]) -> Result<Self, SpaceClass> {
        let map = read_versioned(data)?;
        if map.keys().any(|key| !(1..=6).contains(key)) {
            return Err(malformed());
        }
        let mut values = [None; 4];
        for (slot, (key, timer, default)) in values.iter_mut().zip(DURATIONS) {
            if let Some(value) = map.get(&key) {
                let seconds = check_policy(timer, value).map_err(SpaceClass::Shared)?;
                if Some(seconds) == default {
                    return Err(malformed());
                }
                *slot = Some(seconds);
            }
        }
        let forbid_agents = match map.get(&FORBID_AGENTS) {
            None => false,
            Some(Value::Unsigned(1)) => true,
            Some(_) => return Err(malformed()),
        };
        let [agent, window, freshness, gap] = values;
        Ok(Self {
            agent_waiting_period: agent.unwrap_or(DEFAULT_AGENT_WAITING_PERIOD),
            bounded_window: window,
            online_freshness: freshness,
            gap_key_timeout: gap.unwrap_or(DEFAULT_GAP_KEY_TIMEOUT),
            forbid_agents,
        })
    }

    /// The policy's one encoding: a value is written only when it differs
    /// from its default.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        let set = [
            Some(self.agent_waiting_period),
            self.bounded_window,
            self.online_freshness,
            Some(self.gap_key_timeout),
        ];
        for (value, (key, _, default)) in set.into_iter().zip(DURATIONS) {
            if let Some(value) = value.filter(|&value| Some(value) != default) {
                map.insert(key, Value::Unsigned(value));
            }
        }
        if self.forbid_agents {
            map.insert(FORBID_AGENTS, Value::Unsigned(1));
        }
        Value::Map(map).encode()
    }

    /// Merges concurrent policies field by field to the stricter value
    /// (roster.md, "The roster at a place"): the longest agent waiting
    /// period and gap-key timeout; the shortest bounded window and online
    /// freshness of those set, off only if off in all; `forbid_agents` if
    /// set in any. `None` for no policy.
    pub fn merge<'a>(policies: impl IntoIterator<Item = &'a Policy>) -> Option<Policy> {
        fn shortest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
            match (a, b) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        }
        policies.into_iter().copied().reduce(|a, b| Policy {
            agent_waiting_period: a.agent_waiting_period.max(b.agent_waiting_period),
            bounded_window: shortest(a.bounded_window, b.bounded_window),
            online_freshness: shortest(a.online_freshness, b.online_freshness),
            gap_key_timeout: a.gap_key_timeout.max(b.gap_key_timeout),
            forbid_agents: a.forbid_agents || b.forbid_agents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_one_encoding() {
        assert_eq!(Policy::default().encode(), [0xa1, 0x01, 0x01]);
        assert_eq!(Policy::read(&[0xa1, 0x01, 0x01]), Ok(Policy::default()));
        assert_eq!(Descriptor::ORDINARY.encode(), [0xa1, 0x01, 0x01]);
    }

    #[test]
    fn concurrent_policies_merge_to_the_stricter() {
        let a = Policy {
            agent_waiting_period: 300_000,
            bounded_window: Some(7200),
            ..Policy::default()
        };
        let b = Policy {
            bounded_window: Some(3600),
            online_freshness: Some(60),
            gap_key_timeout: 700_000,
            forbid_agents: true,
            ..Policy::default()
        };
        let merged = Policy::merge([&a, &b]).unwrap();
        assert_eq!(merged.agent_waiting_period, 300_000);
        assert_eq!(merged.bounded_window, Some(3600));
        assert_eq!(merged.online_freshness, Some(60));
        assert_eq!(merged.gap_key_timeout, 700_000);
        assert!(merged.forbid_agents);
        assert_eq!(Policy::merge([]), None);
    }
}
