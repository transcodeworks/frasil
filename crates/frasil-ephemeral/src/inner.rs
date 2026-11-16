//! The inner map (ext-ephemeral.md, "The inner map").
//!
//! | Key | Field | Rule |
//! |---|---|---|
//! | 1 | `version` | 1 |
//! | 2 | `kind` | 1 ephemeral message, 2 ephemeral slot |
//! | 3 | `sender` | the sender's `ed \|\| kc`, 64 bytes; the sender is the device ID they give |
//! | 4 | `epoch` | 1 to 2^64 − 1 |
//! | 5 | `counter` | 1 to 2^64 − 1 |
//! | 6 | `name` | 1 to 64 bytes; no control character; not only white space |
//! | 7 | `stream` | optional; 16 bytes, not all zero |
//! | 8 | `targets` | optional; ephemeral messages only; 1 to 16 device IDs, strictly ascending |
//! | 9 | `fresh` | optional; only with `targets`; 1 to 16 pairs, strictly ascending by target; each a target |
//! | 10 | `adapter` | optional; an adapter type |
//! | 11 | `data` | 0 to 16,384 bytes |

use crate::limits::{
    MAX_ADAPTER_BYTES, MAX_DATA_BYTES, MAX_NAME_BYTES, MAX_TARGETS, RECEIVER_NONCE_BYTES,
    STREAM_BYTES, VERSION,
};
use crate::{EphemeralClass, malformed};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::{DeviceId, Signatory};

/// A frame's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// 1: an ephemeral message, fire-and-forget.
    Message,
    /// 2: an ephemeral slot, latest-wins.
    Slot,
}

impl Kind {
    /// The kind's code.
    pub fn code(self) -> u8 {
        match self {
            Self::Message => 1,
            Self::Slot => 2,
        }
    }

    /// The kind of a code, if it is 1 or 2.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Message),
            2 => Some(Self::Slot),
            _ => None,
        }
    }

    /// The kind as the document names it: `ephemeral message` or
    /// `ephemeral slot`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Message => "ephemeral message",
            Self::Slot => "ephemeral slot",
        }
    }
}

/// One fresh entry: a target's device ID and its receiver nonce as the
/// sender holds it.
pub type FreshEntry = (DeviceId, [u8; RECEIVER_NONCE_BYTES]);

/// The inner map's fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    /// `kind`.
    pub kind: Kind,
    /// `sender`: the sender's `ed || kc` (crypto.md, "A device's keys");
    /// the sender is the device ID they give.
    pub sender: Signatory,
    /// `epoch`.
    pub epoch: u64,
    /// `counter`.
    pub counter: u64,
    /// `name`.
    pub name: String,
    /// `stream`, which narrows the frame to one document.
    pub stream: Option<[u8; STREAM_BYTES]>,
    /// `targets`, device IDs, ascending.
    pub targets: Option<Vec<DeviceId>>,
    /// `fresh`, ascending by target.
    pub fresh: Option<Vec<FreshEntry>>,
    /// `adapter`: the adapter whose capability checks run on the frame.
    pub adapter: Option<String>,
    /// `data`.
    pub data: Vec<u8>,
}

/// Whether a name follows the rule of the inner map: 1 to 64 bytes of
/// UTF-8, no control character (Unicode category Cc), not only white space.
pub fn name_ok(name: &str) -> bool {
    frasil_base::notation::text_ok(name, MAX_NAME_BYTES)
}

/// Whether a text is an adapter type (units.md): 1 to 64 bytes, each `0x21`
/// to `0x7e`.
pub fn adapter_ok(adapter: &str) -> bool {
    (1..=MAX_ADAPTER_BYTES).contains(&adapter.len())
        && adapter.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl Inner {
    /// The fresh entry for `device`, if the frame carries one.
    pub fn fresh_for(&self, device: &DeviceId) -> Option<&[u8; RECEIVER_NONCE_BYTES]> {
        self.fresh
            .as_ref()?
            .iter()
            .find(|(target, _)| target == device)
            .map(|(_, nonce)| nonce)
    }

    /// Whether the frame names targets and `device` is not one of them.
    pub fn excludes(&self, device: &DeviceId) -> bool {
        self.targets
            .as_ref()
            .is_some_and(|targets| !targets.contains(device))
    }

    /// The inner map's bytes, version 1. This writes the fields as they are;
    /// [`read`](Self::read) is where the rules are checked.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(u64::from(self.kind.code())));
        map.insert(3, Value::from(self.sender.to_bytes()));
        map.insert(4, Value::Unsigned(self.epoch));
        map.insert(5, Value::Unsigned(self.counter));
        map.insert(6, Value::from(self.name.as_str()));
        if let Some(stream) = &self.stream {
            map.insert(7, Value::from(&stream[..]));
        }
        if let Some(targets) = &self.targets {
            map.insert(
                8,
                Value::Array(targets.iter().map(|t| Value::from(t.0)).collect()),
            );
        }
        if let Some(fresh) = &self.fresh {
            map.insert(
                9,
                Value::Array(
                    fresh
                        .iter()
                        .map(|(t, n)| Value::Array(vec![Value::from(t.0), Value::from(&n[..])]))
                        .collect(),
                ),
            );
        }
        if let Some(adapter) = &self.adapter {
            map.insert(10, Value::from(adapter.as_str()));
        }
        map.insert(11, Value::from(self.data.as_slice()));
        Value::Map(map).encode()
    }

    /// Reads an inner map by its rules ("Receiving", step 7; the comparison
    /// with the outer kind is the caller's).
    ///
    /// # Errors
    ///
    /// `UnsupportedVersion` for a version other than 1; `Malformed` for
    /// anything else the rules refuse.
    pub fn read(data: &[u8]) -> Result<Self, EphemeralClass> {
        let Value::Map(map) = cbor::decode(data)? else {
            return Err(malformed());
        };
        let version = map.get(&1).ok_or_else(malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.keys().any(|key| !(1..=11).contains(key))
            || [2, 3, 4, 5, 6, 11].iter().any(|key| !map.contains_key(key))
        {
            return Err(malformed());
        }
        let get = |key: u64| map.get(&key).ok_or_else(malformed);
        let kind = Kind::from_code(get(2)?.as_unsigned()?).ok_or_else(malformed)?;
        let sender = Signatory::from_bytes(get(3)?.as_bytes()?)?;
        let mut serials = [0; 2];
        for (slot, key) in serials.iter_mut().zip([4, 5]) {
            *slot = get(key)?.as_unsigned()?;
            if *slot == 0 {
                return Err(malformed());
            }
        }
        let [epoch, counter] = serials;
        let Value::Text(name) = get(6)? else {
            return Err(malformed());
        };
        if !name_ok(name) {
            return Err(malformed());
        }
        let data = get(11)?.as_bytes()?;
        if data.len() > MAX_DATA_BYTES {
            return Err(malformed());
        }
        let stream = match map.get(&7) {
            None => None,
            Some(value) => {
                let stream: [u8; STREAM_BYTES] = value.as_byte_array()?;
                if stream == [0; STREAM_BYTES] {
                    return Err(malformed());
                }
                Some(stream)
            }
        };
        let adapter = match map.get(&10) {
            None => None,
            Some(Value::Text(adapter)) if adapter_ok(adapter) => Some(adapter.clone()),
            Some(_) => return Err(malformed()),
        };
        if kind == Kind::Slot && (map.contains_key(&8) || map.contains_key(&9)) {
            // Targets are for ephemeral messages only.
            return Err(malformed());
        }
        let targets = match map.get(&8) {
            None => None,
            Some(Value::Array(items)) if (1..=MAX_TARGETS).contains(&items.len()) => {
                let targets = items
                    .iter()
                    .map(|item| item.as_byte_array::<32>().map(DeviceId))
                    .collect::<Result<Vec<_>, _>>()?;
                if targets.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(malformed());
                }
                Some(targets)
            }
            Some(_) => return Err(malformed()),
        };
        let fresh = match (map.get(&9), &targets) {
            (None, _) => None,
            (Some(Value::Array(items)), Some(targets))
                if (1..=MAX_TARGETS).contains(&items.len()) =>
            {
                let mut fresh = Vec::with_capacity(items.len());
                for item in items {
                    let Value::Array(pair) = item else {
                        return Err(malformed());
                    };
                    let [device, nonce] = pair.as_slice() else {
                        return Err(malformed());
                    };
                    fresh.push((DeviceId(device.as_byte_array()?), nonce.as_byte_array()?));
                }
                if fresh.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                    || fresh.iter().any(|(device, _)| !targets.contains(device))
                {
                    return Err(malformed());
                }
                Some(fresh)
            }
            (Some(_), _) => return Err(malformed()),
        };
        Ok(Self {
            kind,
            sender,
            epoch,
            counter,
            name: name.clone(),
            stream,
            targets,
            fresh,
            adapter,
            data: data.to_vec(),
        })
    }
}
