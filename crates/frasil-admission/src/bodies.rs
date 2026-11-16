//! Message bodies (admission.md, "Bodies"). Each is a deterministic CBOR
//! map with exactly the keys listed; anything else is `Malformed`.

use crate::params::{NONCE_BYTES, VERSION};
use crate::transcript::{JoinerPart, heads_hash};
use crate::{
    AdmissionClass, Ctx, JoinerType, array_at, boxed_at, bytes_at, display_at, heads_value,
    malformed, number_at, read_heads, read_map,
};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::{
    DeviceId, DeviceKeys, HybridKeys, IdentityKey, device_id, keys_commitment,
};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::sizes::{MLDSA65_PUBLIC, SCHEME2_SIGNATURE, XWING_PUBLIC};
use frasil_events::EventId;

/// The Request, in the clear: `{1: ctx, 2: expires_at, 3: commitment (32),
/// 4: eph_J (1,216)}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestBody {
    /// `ctx`.
    pub ctx: Ctx,
    /// `expires_at`.
    pub expires_at: u64,
    /// The joiner's commitment.
    pub commitment: [u8; 32],
    /// `eph_J`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
}

impl RequestBody {
    /// The body's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(self.ctx.code().into()));
        map.insert(2, Value::Unsigned(self.expires_at));
        map.insert(3, Value::from(self.commitment));
        map.insert(4, Value::from(&self.eph[..]));
        Value::Map(map).encode()
    }

    /// Reads the body.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let map = read_map(data, &[1, 2, 3, 4], &[1, 2, 3, 4])?;
        Ok(Self {
            ctx: Ctx::from_code(number_at(&map, 1)?).ok_or_else(malformed)?,
            expires_at: number_at(&map, 2)?,
            commitment: array_at(&map, 3)?,
            eph: boxed_at(&map, 4)?,
        })
    }
}

/// The Response, sealed to `eph_J`: `{1: nonce_I, 2: log, 3: heads, 4:
/// approver, 5: eph_I, 6: offer, 7: display_I}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResponseBody {
    /// `nonce_I`.
    pub nonce: [u8; NONCE_BYTES],
    /// `log`: the space ID, or for ctx `0x01` the person ID.
    pub log: [u8; 32],
    /// `heads`, strictly ascending.
    pub heads: Vec<EventId>,
    /// `approver`: I's device ID.
    pub approver: DeviceId,
    /// `eph_I`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
    /// The offer's bytes.
    pub offer: Vec<u8>,
    /// `display_I`.
    pub display: String,
}

impl ResponseBody {
    /// The body's bytes; heads are written sorted, each once.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(self.nonce));
        map.insert(2, Value::from(self.log));
        map.insert(3, heads_value(&self.heads));
        map.insert(4, Value::from(self.approver.0));
        map.insert(5, Value::from(&self.eph[..]));
        map.insert(6, Value::from(self.offer.clone()));
        map.insert(7, Value::from(self.display.as_str()));
        Value::Map(map).encode()
    }

    /// Reads the body.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let keys = [1, 2, 3, 4, 5, 6, 7];
        let map = read_map(data, &keys, &keys)?;
        Ok(Self {
            nonce: array_at(&map, 1)?,
            log: array_at(&map, 2)?,
            heads: read_heads(&map[&3])?,
            approver: DeviceId(array_at(&map, 4)?),
            eph: boxed_at(&map, 5)?,
            offer: bytes_at(&map, 6)?.to_vec(),
            display: display_at(&map, 7)?,
        })
    }

    /// `heads_hash(log, heads)`.
    pub fn heads_hash(&self) -> [u8; 32] {
        heads_hash(&self.log, &self.heads).expect("a read Response has 1 to 256 heads")
    }
}

/// A device's three public keys, as a Reveal or a Hello carries them, not
/// yet checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevealedKeys {
    /// The Ed25519 identity key.
    pub identity: [u8; 32],
    /// The ML-DSA-65 key.
    pub mldsa: Box<[u8; MLDSA65_PUBLIC]>,
    /// The X-Wing key.
    pub xwing: Box<[u8; XWING_PUBLIC]>,
}

impl RevealedKeys {
    /// The keys of a device's public keys.
    pub fn of(keys: &DeviceKeys) -> Option<Self> {
        Some(Self {
            identity: keys.ed.0,
            mldsa: Box::new(*keys.keys.mldsa()),
            xwing: Box::new(*keys.keys.xwing()?),
        })
    }

    /// The device ID the three keys give (crypto.md, "A device's keys"),
    /// which `J_fields` and the setup code carry. It needs no check of the
    /// keys: different bytes give a different device ID.
    pub fn device_id(&self) -> DeviceId {
        device_id(
            &IdentityKey(self.identity),
            &keys_commitment(&self.mldsa[..], Some(&self.xwing[..])),
        )
    }

    /// The three keys, each passing crypto.md's checks.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a key a check refuses.
    pub fn checked(&self) -> Result<DeviceKeys, ErrorClass> {
        ed25519_valid(&self.identity)?;
        let keys = HybridKeys::new(&self.mldsa[..], Some(&self.xwing[..]))
            .map_err(|_| ErrorClass::InvalidKey)?;
        Ok(DeviceKeys {
            ed: IdentityKey(self.identity),
            keys,
        })
    }
}

/// The Reveal, sealed to `eph_I`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevealBody {
    /// A device: `{1: nonce_J, 2: 0, 3: identity, 4: mldsa, 5: xwing, 6:
    /// possession (ctx 0x01 only), 7: display_J}`. A device joining a space
    /// signs no statement over its keys: its device ID, in the committed
    /// `J_fields`, is what the grant names.
    Device {
        /// `nonce_J`.
        nonce: [u8; NONCE_BYTES],
        /// Keys 3 to 5.
        keys: RevealedKeys,
        /// Key 6, for ctx `0x01`: the possession statement's proof over the
        /// person ID, with the Response's `approver` as adder.
        possession: Option<Vec<u8>>,
        /// `display_J`.
        display: String,
    },
    /// A person: `{1: nonce_J, 2: 1, 7: display_J, 8: person ID, 9: list
    /// heads}`.
    Person {
        /// `nonce_J`.
        nonce: [u8; NONCE_BYTES],
        /// `display_J`.
        display: String,
        /// The person ID.
        person: [u8; 32],
        /// The list heads, strictly ascending.
        heads: Vec<EventId>,
    },
}

impl RevealBody {
    /// The body's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        match self {
            Self::Device {
                nonce,
                keys,
                possession,
                display,
            } => {
                map.insert(1, Value::from(*nonce));
                map.insert(2, Value::Unsigned(0));
                map.insert(3, Value::from(keys.identity));
                map.insert(4, Value::from(&keys.mldsa[..]));
                map.insert(5, Value::from(&keys.xwing[..]));
                if let Some(proof) = possession {
                    map.insert(6, Value::from(proof.clone()));
                }
                map.insert(7, Value::from(display.as_str()));
            }
            Self::Person {
                nonce,
                display,
                person,
                heads,
            } => {
                map.insert(1, Value::from(*nonce));
                map.insert(2, Value::Unsigned(1));
                map.insert(7, Value::from(display.as_str()));
                map.insert(8, Value::from(*person));
                map.insert(9, heads_value(heads));
            }
        }
        Value::Map(map).encode()
    }

    /// Reads the body of an exchange of `ctx`: a device's carries key 6,
    /// `possession`, exactly in ctx `0x01`, and a person reveals only in ctx
    /// `0x02`.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8], ctx: Ctx) -> Result<Self, AdmissionClass> {
        let map = read_map(data, &[1, 2, 3, 4, 5, 6, 7, 8, 9], &[1, 2, 7])?;
        let nonce = array_at(&map, 1)?;
        let display = display_at(&map, 7)?;
        match JoinerType::from_code(number_at(&map, 2)?) {
            Some(JoinerType::Device) => {
                let with_possession = ctx == Ctx::DeviceList;
                let need: &[u64] = if with_possession {
                    &[1, 2, 3, 4, 5, 6, 7]
                } else {
                    &[1, 2, 3, 4, 5, 7]
                };
                if !map.keys().copied().eq(need.iter().copied()) {
                    return Err(malformed());
                }
                let proof = |key| -> Result<Vec<u8>, AdmissionClass> {
                    let bytes = bytes_at(&map, key)?;
                    if bytes.len() != SCHEME2_SIGNATURE {
                        return Err(malformed());
                    }
                    Ok(bytes.to_vec())
                };
                Ok(Self::Device {
                    nonce,
                    keys: RevealedKeys {
                        identity: array_at(&map, 3)?,
                        mldsa: boxed_at(&map, 4)?,
                        xwing: boxed_at(&map, 5)?,
                    },
                    possession: if with_possession {
                        Some(proof(6)?)
                    } else {
                        None
                    },
                    display,
                })
            }
            Some(JoinerType::Person) => {
                if ctx != Ctx::Space || !map.keys().copied().eq([1, 2, 7, 8, 9]) {
                    return Err(malformed());
                }
                Ok(Self::Person {
                    nonce,
                    display,
                    person: array_at(&map, 8)?,
                    heads: read_heads(&map[&9])?,
                })
            }
            None => Err(malformed()),
        }
    }

    /// `nonce_J`.
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        match self {
            Self::Device { nonce, .. } | Self::Person { nonce, .. } => nonce,
        }
    }

    /// `display_J`.
    pub fn display(&self) -> &str {
        match self {
            Self::Device { display, .. } | Self::Person { display, .. } => display,
        }
    }

    /// `joiner_type || joiner` for `J_fields`.
    pub fn joiner_part(&self) -> JoinerPart {
        match self {
            Self::Device { keys, .. } => JoinerPart::Device(keys.device_id()),
            Self::Person { person, heads, .. } => JoinerPart::Person {
                person: *person,
                heads_hash: heads_hash(person, heads).expect("a read Reveal has 1 to 256 heads"),
            },
        }
    }
}

/// The List, and the Result for ctx `0x01`: `{1: 1, 2: [signed device-list
/// events]}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListEvents {
    /// The signed events, as the sender holds them.
    pub events: Vec<Vec<u8>>,
}

impl ListEvents {
    /// The body's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION.into()));
        map.insert(
            2,
            Value::Array(self.events.iter().map(|e| Value::from(e.clone())).collect()),
        );
        Value::Map(map).encode()
    }

    /// Reads the body: version 1 and a nonempty array of byte strings.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let map = read_map(data, &[1, 2], &[1, 2])?;
        if number_at(&map, 1)? != u64::from(VERSION) {
            return Err(malformed());
        }
        let items = map[&2].as_array()?;
        if items.is_empty() {
            return Err(malformed());
        }
        let events = items
            .iter()
            .map(|item| Ok(item.as_bytes()?.to_vec()))
            .collect::<Result<Vec<_>, AdmissionClass>>()?;
        Ok(Self { events })
    }
}

/// The Hello, in the clear on the nearby connection: `{1: eph_J, 2:
/// identity, 3: mldsa, 4: xwing, 5: display_J}`. The scanned setup code's
/// device ID authenticates the keys; the Hello carries no proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelloBody {
    /// `eph_J`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
    /// The device's keys.
    pub keys: RevealedKeys,
    /// `display_J`.
    pub display: String,
}

impl HelloBody {
    /// The body's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(&self.eph[..]));
        map.insert(2, Value::from(self.keys.identity));
        map.insert(3, Value::from(&self.keys.mldsa[..]));
        map.insert(4, Value::from(&self.keys.xwing[..]));
        map.insert(5, Value::from(self.display.as_str()));
        Value::Map(map).encode()
    }

    /// Reads the body.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let keys = [1, 2, 3, 4, 5];
        let map = read_map(data, &keys, &keys)?;
        Ok(Self {
            eph: boxed_at(&map, 1)?,
            keys: RevealedKeys {
                identity: array_at(&map, 2)?,
                mldsa: boxed_at(&map, 3)?,
                xwing: boxed_at(&map, 4)?,
            },
            display: display_at(&map, 5)?,
        })
    }
}

/// The setup flow's Offer, sealed to `eph_J`: `{1: log, 2: heads, 3:
/// approver, 4: eph_I, 5: offer, 6: display_I, 7: mac (32)}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OfferBody {
    /// `log`: the space ID.
    pub log: [u8; 32],
    /// `heads`, strictly ascending.
    pub heads: Vec<EventId>,
    /// `approver`: the administrator's device ID.
    pub approver: DeviceId,
    /// `eph_I`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
    /// The offer's bytes.
    pub offer: Vec<u8>,
    /// `display_I`.
    pub display: String,
    /// The setup MAC.
    pub mac: [u8; 32],
}

impl OfferBody {
    /// The body's bytes; heads are written sorted, each once.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(self.log));
        map.insert(2, heads_value(&self.heads));
        map.insert(3, Value::from(self.approver.0));
        map.insert(4, Value::from(&self.eph[..]));
        map.insert(5, Value::from(self.offer.clone()));
        map.insert(6, Value::from(self.display.as_str()));
        map.insert(7, Value::from(self.mac));
        Value::Map(map).encode()
    }

    /// Reads the body.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let keys = [1, 2, 3, 4, 5, 6, 7];
        let map = read_map(data, &keys, &keys)?;
        Ok(Self {
            log: array_at(&map, 1)?,
            heads: read_heads(&map[&2])?,
            approver: DeviceId(array_at(&map, 3)?),
            eph: boxed_at(&map, 4)?,
            offer: bytes_at(&map, 5)?.to_vec(),
            display: display_at(&map, 6)?,
            mac: array_at(&map, 7)?,
        })
    }

    /// `heads_hash(log, heads)`.
    pub fn heads_hash(&self) -> [u8; 32] {
        heads_hash(&self.log, &self.heads).expect("a read Offer has 1 to 256 heads")
    }
}
