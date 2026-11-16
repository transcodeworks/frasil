//! The offer (admission.md, "The offer").
//!
//! For ctx `0x02`, a deterministic CBOR map whose keys are the roster's
//! change keys:
//!
//! | Key | Field | Rule |
//! |---|---|---|
//! | 2 | `level` | required; `administer` only for a device joiner without `session` |
//! | 3 | `capabilities` | optional; as roster.md |
//! | 4 | `label` | optional; 1 to 64 bytes |
//! | 5 | `history` | required; 0 from now on, 1 with history |
//! | 7 | `session` | optional, bytes(16); a device joiner only |
//! | 8 | `replaces` | optional, bytes(32); a person joiner only |
//!
//! Key 13, a session's expiry, is ext-guests.md's: a core joiner refuses an
//! offer that carries it as `Malformed` (admission.md, "Invite links and
//! guests"). For ctx `0x01` the offer is empty.

use crate::{AdmissionClass, Ctx, JoinerType, malformed, read_map};
use frasil_base::cbor::{Map, Value};
use frasil_space::change::key;
use frasil_space::limits::MAX_CAPABILITIES;
use frasil_space::member;
use frasil_space::{Capability, HistoryMode, Level};

/// The offer of ctx `0x02`: the grant the approver will sign.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Offer {
    /// Key 2.
    pub level: Level,
    /// Key 3, strictly ascending by name.
    pub capabilities: Option<Vec<Capability>>,
    /// Key 4.
    pub label: Option<String>,
    /// Key 5.
    pub history: HistoryMode,
    /// Key 7: the guest's session.
    pub session: Option<[u8; 16]>,
    /// Key 8: the person the granted person replaces.
    pub replaces: Option<[u8; 32]>,
    /// Key 13: the session's expiry, only with `session`
    /// (ext-guests.md, "The guest preset").
    #[cfg(feature = "ext-guests")]
    pub expires_at: Option<u64>,
}

impl Offer {
    /// An offer of a level and a history mode, with nothing else.
    pub fn new(level: Level, history: HistoryMode) -> Self {
        Self {
            level,
            capabilities: None,
            label: None,
            history,
            session: None,
            replaces: None,
            #[cfg(feature = "ext-guests")]
            expires_at: None,
        }
    }

    /// The offer's one encoding. Capabilities are written in ascending order
    /// of their names.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(key::LEVEL, Value::Unsigned(self.level.code()));
        if let Some(capabilities) = &self.capabilities {
            let mut sorted = capabilities.clone();
            sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
            map.insert(
                key::CAPABILITIES,
                Value::Array(sorted.iter().map(Capability::to_value).collect()),
            );
        }
        if let Some(label) = &self.label {
            map.insert(key::LABEL, Value::from(label.as_str()));
        }
        map.insert(key::HISTORY, Value::Unsigned(self.history.code()));
        if let Some(session) = self.session {
            map.insert(key::SESSION, Value::from(session));
        }
        if let Some(replaces) = self.replaces {
            map.insert(key::REPLACES, Value::from(replaces));
        }
        #[cfg(feature = "ext-guests")]
        if let Some(expires_at) = self.expires_at {
            map.insert(key::EXPIRES_AT, Value::Unsigned(expires_at));
        }
        Value::Map(map).encode()
    }

    /// Reads a ctx `0x02` offer for a joiner of this type, every rule of the
    /// table.
    ///
    /// # Errors
    ///
    /// `Malformed` for any other key, key 13 included unless the build has
    /// ext-guests.md, or any value outside the rules.
    pub fn read(data: &[u8], joiner_type: JoinerType) -> Result<Self, AdmissionClass> {
        let map = read_map(
            data,
            &[
                key::LEVEL,
                key::CAPABILITIES,
                key::LABEL,
                key::HISTORY,
                key::SESSION,
                key::REPLACES,
                #[cfg(feature = "ext-guests")]
                key::EXPIRES_AT,
            ],
            &[key::LEVEL, key::HISTORY],
        )?;
        let level = Level::from_code(map[&key::LEVEL].as_unsigned()?).ok_or_else(malformed)?;
        let history =
            HistoryMode::from_code(map[&key::HISTORY].as_unsigned()?).ok_or_else(malformed)?;
        let session = map
            .get(&key::SESSION)
            .map(|v| v.as_byte_array::<16>())
            .transpose()?;
        if session.is_some() && joiner_type != JoinerType::Device {
            return Err(malformed());
        }
        #[cfg(feature = "ext-guests")]
        let expires_at = crate::ext_guests::read_offer_expiry(&map, session.is_some())?;
        let replaces = map
            .get(&key::REPLACES)
            .map(|v| v.as_byte_array::<32>())
            .transpose()?;
        if replaces.is_some() && joiner_type != JoinerType::Person {
            return Err(malformed());
        }
        if level == Level::Administer && (joiner_type != JoinerType::Device || session.is_some()) {
            return Err(malformed());
        }
        let label = match map.get(&key::LABEL) {
            Some(value) => {
                let text = value.as_text()?;
                if !member::name_ok(text) {
                    return Err(malformed());
                }
                Some(text.to_owned())
            }
            None => None,
        };
        let capabilities = map
            .get(&key::CAPABILITIES)
            .map(read_capabilities)
            .transpose()?;
        Ok(Self {
            level,
            capabilities,
            label,
            history,
            session,
            replaces,
            #[cfg(feature = "ext-guests")]
            expires_at,
        })
    }

    /// Key 13, the session's expiry (ext-guests.md).
    #[cfg(feature = "ext-guests")]
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Key 13, the session's expiry: never, without ext-guests.md.
    #[cfg(not(feature = "ext-guests"))]
    pub fn expires_at(&self) -> Option<u64> {
        None
    }
}

/// 1 to 32 pairs `[name, mode]`, as roster.md reads them.
fn read_capabilities(value: &Value) -> Result<Vec<Capability>, AdmissionClass> {
    member::read_capabilities(value, MAX_CAPABILITIES).map_err(|_| malformed())
}

/// Reads the offer of an exchange of `ctx` for a joiner of this type: for
/// ctx `0x01`, an empty offer and `None`; for ctx `0x02`, [`Offer::read`].
///
/// # Errors
///
/// `Malformed` for a nonempty offer in ctx `0x01`, and as [`Offer::read`].
pub fn read_offer(
    data: &[u8],
    ctx: Ctx,
    joiner_type: JoinerType,
) -> Result<Option<Offer>, AdmissionClass> {
    match ctx {
        Ctx::DeviceList if data.is_empty() => Ok(None),
        Ctx::DeviceList => Err(malformed()),
        Ctx::Space => Offer::read(data, joiner_type).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_space::CapabilityMode;

    #[test]
    fn round_trips() {
        let mut offer = Offer::new(Level::Write, HistoryMode::FromNowOn);
        offer.capabilities = Some(vec![Capability {
            name: "drive".into(),
            mode: CapabilityMode::Extends,
        }]);
        offer.label = Some("Operator".into());
        offer.session = Some([3; 16]);
        assert_eq!(Offer::read(&offer.encode(), JoinerType::Device), Ok(offer));
    }
}
