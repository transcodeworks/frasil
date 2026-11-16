//! Members, levels, capabilities, labels, history modes and `via`
//! (roster.md, "Members and levels" and "Changes").
//!
//! A **member reference** is `[type, id]`:
//!
//! | Type | Member | ID |
//! |---|---|---|
//! | 0 | device | its device ID (crypto.md, "A device's keys") |
//! | 1 | person | its person ID |
//! | 2 | space | its space ID |
//! | 3 | invite key | reserved for ext-invite-links.md |

use crate::SpaceClass;
use crate::limits::MAX_NAME_BYTES;
use frasil_base::ErrorClass;
use frasil_base::cbor::Value;
use frasil_crypto::device::DeviceId;

/// The prefix of capability names reserved for Frasil's own documents. An
/// application defines no name that begins with it; a replica merges such a
/// capability by its mode like any other (roster.md, "Changes").
pub const RESERVED_CAPABILITY_PREFIX: &str = "frasil.";

fn malformed() -> SpaceClass {
    ErrorClass::Malformed.into()
}

/// A member's type, the first element of a member reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemberType {
    /// 0: a device, by its device ID.
    Device,
    /// 1: a person, by its person ID.
    Person,
    /// 2: a space, by its space ID.
    Space,
    /// 3: an invite key, reserved for ext-invite-links.md. A core
    /// implementation holds a roster event that uses it as
    /// `ExtensionRequired`.
    Invite,
}

impl MemberType {
    /// Every type, by code.
    pub const ALL: [MemberType; 4] = [Self::Device, Self::Person, Self::Space, Self::Invite];

    /// The type's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Device => 0,
            Self::Person => 1,
            Self::Space => 2,
            Self::Invite => 3,
        }
    }

    /// The type of a code; any other code is `Malformed`.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The type's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Person => "person",
            Self::Space => "space",
            Self::Invite => "invite",
        }
    }

    /// Whether the type is reserved for an extension: only the invite key.
    pub const fn is_reserved(self) -> bool {
        matches!(self, Self::Invite)
    }
}

/// A member reference, `[type, id]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberRef {
    /// The member's type.
    pub kind: MemberType,
    /// Its 32-byte ID.
    pub id: [u8; 32],
}

impl MemberRef {
    /// A device member, by its device ID.
    pub const fn device(device: DeviceId) -> Self {
        Self {
            kind: MemberType::Device,
            id: device.0,
        }
    }

    /// The device ID of a device member, or `None` for another type.
    pub fn device_id(&self) -> Option<DeviceId> {
        (self.kind == MemberType::Device).then_some(DeviceId(self.id))
    }

    /// A person member.
    pub const fn person(person_id: [u8; 32]) -> Self {
        Self {
            kind: MemberType::Person,
            id: person_id,
        }
    }

    /// A space member.
    pub const fn space(space_id: [u8; 32]) -> Self {
        Self {
            kind: MemberType::Space,
            id: space_id,
        }
    }

    /// The reference as CBOR, `[type, id]`.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Unsigned(self.kind.code()),
            Value::Bytes(self.id.to_vec()),
        ])
    }

    /// The type a value names, if it is an array of two whose first element
    /// is an unsigned integer. A reader looks at it before anything else,
    /// to find a reserved type.
    pub fn peek_type(value: &Value) -> Option<u64> {
        match value {
            Value::Array(items) if items.len() == 2 => items[0].as_unsigned().ok(),
            _ => None,
        }
    }

    /// Reads a member reference of types 0 to 2. Type 3 is the caller's to
    /// find first ([`MemberRef::peek_type`]).
    ///
    /// # Errors
    ///
    /// `Malformed` unless the value is `[type, id]` with a type of 0 to 2
    /// and an ID of 32 bytes.
    pub fn read(value: &Value) -> Result<Self, SpaceClass> {
        let items = value.as_array()?;
        let [kind, id] = items else {
            return Err(malformed());
        };
        let kind = MemberType::from_code(kind.as_unsigned()?)
            .filter(|kind| !kind.is_reserved())
            .ok_or_else(malformed)?;
        Ok(Self {
            kind,
            id: id.as_byte_array::<32>()?,
        })
    }
}

/// A level (roster.md, "Members and levels").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// 0: the content key of each state the member is entitled to, and the
    /// read credential.
    Read,
    /// 1: also the upload seed; its units and key events are accepted.
    Write,
    /// 2: also its roster events are accepted. Only a device member without
    /// `session` holds it.
    Administer,
}

impl Level {
    /// Every level, lowest first.
    pub const ALL: [Level; 3] = [Self::Read, Self::Write, Self::Administer];

    /// The level's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Administer => 2,
        }
    }

    /// The level of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.code() == code)
    }

    /// The level's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Administer => "administer",
        }
    }

    /// The level of a name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.name() == name)
    }
}

/// A grant's history mode (roster.md, "Changes", key 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HistoryMode {
    /// 0: from now on, a **break** (keys.md).
    FromNowOn,
    /// 1: with history, entitled to earlier keys.
    WithHistory,
}

impl HistoryMode {
    /// The mode's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::FromNowOn => 0,
            Self::WithHistory => 1,
        }
    }

    /// The mode of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::FromNowOn),
            1 => Some(Self::WithHistory),
            _ => None,
        }
    }

    /// The mode's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FromNowOn => "from now on",
            Self::WithHistory => "with history",
        }
    }
}

/// How a member was admitted (roster.md, "Changes", key 6): shown, never
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Via {
    /// 0: an admission code was compared.
    Code,
    /// 1: a link.
    Link,
    /// 2: a lookup; a client shows the member as unverified until a code is
    /// compared.
    Lookup,
    /// 3: none, as for the founder.
    None,
}

impl Via {
    /// Every `via`, by code.
    pub const ALL: [Via; 4] = [Self::Code, Self::Link, Self::Lookup, Self::None];

    /// The code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Code => 0,
            Self::Link => 1,
            Self::Lookup => 2,
            Self::None => 3,
        }
    }

    /// The `via` of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|via| via.code() == code)
    }

    /// The name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Link => "link",
            Self::Lookup => "lookup",
            Self::None => "none",
        }
    }
}

/// A capability's mode (roster.md, "Changes", key 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapabilityMode {
    /// 0: extends the grant.
    Extends,
    /// 1: narrows the grant.
    Narrows,
}

impl CapabilityMode {
    /// The mode's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Extends => 0,
            Self::Narrows => 1,
        }
    }

    /// The mode of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Extends),
            1 => Some(Self::Narrows),
            _ => None,
        }
    }

    /// The mode's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Extends => "extends",
            Self::Narrows => "narrows",
        }
    }
}

/// A capability: an application-defined name and its mode. Ordered by name,
/// as bytes, then mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability {
    /// The name: 1 to 64 bytes of UTF-8, no control character, not only
    /// white space.
    pub name: String,
    /// Its mode.
    pub mode: CapabilityMode,
}

impl Capability {
    /// Whether the name is reserved for Frasil's documents (it begins
    /// `frasil.`). An application defines none; a client refuses to sign
    /// one an application asks for (`frasil`'s `Engine::sign_roster`), and
    /// a replica merges it like any other (roster.md, 2.3 Changes).
    pub fn is_reserved(&self) -> bool {
        self.name.starts_with(RESERVED_CAPABILITY_PREFIX)
    }

    /// Whether it is a reserved capability that a document of Frasil's this
    /// build implements sets, with the mode that document gives it:
    /// ext-guests.md's `frasil.nothing-at-rest`, narrowing, which the guest
    /// preset adds. A client signs no other reserved capability, but one a
    /// change carries over from the member's own state.
    pub fn is_set_by_frasil(&self) -> bool {
        #[cfg(feature = "ext-guests")]
        if *self == crate::ext_guests::nothing_at_rest_capability() {
            return true;
        }
        false
    }

    /// The pair as CBOR, `[name, mode]`.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Text(self.name.clone()),
            Value::Unsigned(self.mode.code()),
        ])
    }
}

/// Whether a name or label is one roster.md accepts: 1 to 64 bytes of UTF-8,
/// no control character (Unicode category Cc), and not only white space.
pub fn name_ok(text: &str) -> bool {
    frasil_base::notation::text_ok(text, MAX_NAME_BYTES)
}

/// Reads a name or a label.
pub(crate) fn read_name(value: &Value) -> Result<String, SpaceClass> {
    let text = value.as_text()?;
    if !name_ok(text) {
        return Err(malformed());
    }
    Ok(text.to_owned())
}

/// Reads a capabilities array: 1 to `max` pairs `[name, mode]`, each name
/// as [`name_ok`] and each mode 0 or 1, strictly ascending by name as bytes.
///
/// # Errors
///
/// `Malformed` for an array that breaks any of those.
pub fn read_capabilities(value: &Value, max: usize) -> Result<Vec<Capability>, SpaceClass> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > max {
        return Err(malformed());
    }
    let mut out: Vec<Capability> = Vec::with_capacity(items.len());
    for item in items {
        let [name, mode] = item.as_array()? else {
            return Err(malformed());
        };
        let name = read_name(name)?;
        let mode = CapabilityMode::from_code(mode.as_unsigned()?).ok_or_else(malformed)?;
        if out
            .last()
            .is_some_and(|last| last.name.as_bytes() >= name.as_bytes())
        {
            return Err(malformed());
        }
        out.push(Capability { name, mode });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rules() {
        assert!(name_ok("drive"));
        assert!(name_ok(&"x".repeat(64)));
        assert!(!name_ok(&"x".repeat(65)));
        assert!(!name_ok(""));
        assert!(!name_ok("   "));
        assert!(!name_ok("a\u{7}b"));
        assert!(name_ok("é"));
    }

    #[test]
    fn capabilities_are_strictly_ascending() {
        let pair = |name: &str, mode: u64| {
            Value::Array(vec![Value::Text(name.into()), Value::Unsigned(mode)])
        };
        let ok = Value::Array(vec![pair("drive", 0), pair("suggest", 1)]);
        assert_eq!(read_capabilities(&ok, 32).map(|c| c.len()), Ok(2));
        let unsorted = Value::Array(vec![pair("suggest", 1), pair("drive", 0)]);
        assert!(read_capabilities(&unsorted, 32).is_err());
        let twice = Value::Array(vec![pair("drive", 0), pair("drive", 1)]);
        assert!(read_capabilities(&twice, 32).is_err());
        assert!(read_capabilities(&Value::Array(vec![]), 32).is_err());
        assert!(read_capabilities(&ok, 1).is_err());
        assert!(read_capabilities(&Value::Array(vec![pair("drive", 2)]), 32).is_err());
        let reserved = Capability {
            name: "frasil.history".into(),
            mode: CapabilityMode::Narrows,
        };
        assert!(reserved.is_reserved());
    }
}
