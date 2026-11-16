//! The space event's body (keys.md, "The space event's body") and its
//! checks ("Checking a space event's body").
//!
//! A space event's `body` is a deterministic CBOR map, the **visible part**,
//! which a peer reads ([`VisiblePart`]). It holds the **sealed part**, which
//! only members open ([`Inner`]), sealed under the event's own body key:
//!
//! ```text
//! aad        = "frasil/space-event/v1" || log || author || u64be(seq), author the device ID the envelope gives
//! body_key   = HKDF(salt = none, ikm = secret, info = aad)
//! commitment = HKDF(salt = none, ikm = body_key, info = "frasil/space-event-commitment/v1")
//! sealed     = nonce (24) || XChaCha20-Poly1305(body_key, nonce, inner, aad)
//! ```
//!
//! Roster events and key events share this one shape. What the roster part
//! (sealed key 16) says is roster.md's; this module carries it as bytes.

use crate::KeyClass;
use crate::derive::{body_aad, body_commitment, body_key};
use crate::limits::{MAX_DELIVERIES_PER_EVENT, MAX_WRAPS_PER_EVENT};
use crate::links::{GapRecord, Link};
use crate::names::{KeyName, RotationSet, SelfRef};
use crate::wraps::read_wrap;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::primitives::{xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_crypto::sizes::{XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG, XWING_PUBLIC};
use frasil_events::EventId;
use frasil_events::refs::{Ref, decode_refs, refs_value};

/// The body's version, visible key 1.
pub const BODY_VERSION: u64 = 1;

/// The shortest sealed part: a nonce, an empty map and a tag.
pub const MIN_SEALED_BYTES: usize = XCHACHA20POLY1305_NONCE + 1 + XCHACHA20POLY1305_TAG;

/// The visible part's keys (keys.md, section 2.6). Keys 4, 5, 6 and 10 are
/// reserved and never appear.
pub mod visible_key {
    /// `version`.
    pub const VERSION: u64 = 1;
    /// `rotates`: 1 when the event rotates.
    pub const ROTATES: u64 = 2;
    /// `grant_commitment`, in every rotation.
    pub const GRANT_COMMITMENT: u64 = 3;
    /// `deliveries`.
    pub const DELIVERIES: u64 = 7;
    /// `sealed`, the sealed part.
    pub const SEALED: u64 = 8;
    /// `sealed_under`, in every event that does not rotate.
    pub const SEALED_UNDER: u64 = 9;
    /// `read`, the read credential's public half, in every rotation.
    pub const READ: u64 = 11;
    /// `upload`, the upload key's public half, in every rotation.
    pub const UPLOAD: u64 = 12;
    /// `nonce`, the genesis's 16 random bytes.
    pub const NONCE: u64 = 13;
    /// `commitment`, the body key's commitment.
    pub const COMMITMENT: u64 = 14;
    /// `twin`, a roster event's skeleton twin.
    pub const TWIN: u64 = 15;
    /// Every key the visible part may hold.
    pub const ALLOWED: [u64; 11] = [
        VERSION,
        ROTATES,
        GRANT_COMMITMENT,
        DELIVERIES,
        SEALED,
        SEALED_UNDER,
        READ,
        UPLOAD,
        NONCE,
        COMMITMENT,
        TWIN,
    ];
}

/// The sealed part's keys (keys.md, section 2.6).
pub mod sealed_key {
    /// `grant`: 1 for a grant rotation, or the own delivery's grant state.
    pub const GRANT: u64 = 1;
    /// `break`: 1 for a rotation with no link back.
    pub const BREAK: u64 = 2;
    /// `links`.
    pub const LINKS: u64 = 3;
    /// `gaps`.
    pub const GAPS: u64 = 4;
    /// `notices`.
    pub const NOTICES: u64 = 5;
    /// `roster`: the roster part (roster.md).
    pub const ROSTER: u64 = 16;
    /// `padding`: zero bytes that hide the length.
    pub const PADDING: u64 = 17;
    /// `refs`: events of other logs the event names.
    pub const REFS: u64 = 18;
    /// Every key the sealed part may hold.
    pub const ALLOWED: [u64; 8] = [GRANT, BREAK, LINKS, GAPS, NOTICES, ROSTER, PADDING, REFS];
}

/// A delivery map's keys.
mod delivery_key {
    pub const KEY_NAME: u64 = 1;
    pub const GRANT_NAME: u64 = 2;
    pub const WRAPS: u64 = 3;
    pub const SPACE_WRAPS: u64 = 4;
}

/// A notice map's keys.
mod notice_key {
    pub const SPACE: u64 = 1;
    pub const ROTATION: u64 = 2;
    pub const PUBLIC: u64 = 3;
    pub const FROM_NOW_ON: u64 = 4;
}

fn malformed() -> KeyClass {
    KeyClass::Shared(ErrorClass::Malformed)
}

/// What a rotation publishes in the clear: keys 3, 11 and 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RotationKeys {
    /// Key 3: `commitment(R)` for a grant rotation, 32 random bytes
    /// otherwise.
    pub grant_commitment: [u8; 32],
    /// Key 11: the read credential's public half, from `k_R`.
    pub read: [u8; 32],
    /// Key 12: the upload key's public half, from `w_R`.
    pub upload: [u8; 32],
}

/// Whether the event rotates, and so what its sealed part is sealed under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Seal {
    /// The event rotates (key 2) and publishes its commitments; its sealed
    /// part is sealed under its own `k_R`.
    Rotation(RotationKeys),
    /// The event does not rotate: key 9, the state whose content key seals
    /// key 8.
    Under(RotationSet),
}

/// A delivery: one state and grant state, and the wraps that carry them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Delivery {
    /// Key 1: the key name of `S`.
    pub key_name: Option<KeyName>,
    /// Key 2: the key name of `G`.
    pub grant_name: Option<KeyName>,
    /// Key 3: bundle wraps.
    pub wraps: Vec<Vec<u8>>,
    /// Key 4: space wraps.
    pub space_wraps: Vec<Vec<u8>>,
}

impl Delivery {
    /// Its wraps, bundle wraps and space wraps together.
    pub fn wrap_count(&self) -> usize {
        self.wraps.len() + self.space_wraps.len()
    }

    /// Whether it is the event's own delivery, naming both states by the
    /// event's self reference.
    pub fn is_own(&self, own: &SelfRef) -> bool {
        let own = KeyName::SelfRef(*own);
        self.key_name.as_ref() == Some(&own) && self.grant_name.as_ref() == Some(&own)
    }

    fn to_value(&self) -> Value {
        let mut map = Map::new();
        if let Some(name) = &self.key_name {
            map.insert(delivery_key::KEY_NAME, Value::Bytes(name.encode()));
        }
        if let Some(name) = &self.grant_name {
            map.insert(delivery_key::GRANT_NAME, Value::Bytes(name.encode()));
        }
        for (key, wraps) in [
            (delivery_key::WRAPS, &self.wraps),
            (delivery_key::SPACE_WRAPS, &self.space_wraps),
        ] {
            if !wraps.is_empty() {
                let items = wraps.iter().map(|w| Value::Bytes(w.clone())).collect();
                map.insert(key, Value::Array(items));
            }
        }
        Value::Map(map)
    }
}

/// A space event body's visible part.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VisiblePart {
    /// Keys 2, 3, 11 and 12, or key 9.
    pub seal: Seal,
    /// Key 7.
    pub deliveries: Vec<Delivery>,
    /// Key 8: the sealed part.
    pub sealed: Vec<u8>,
    /// Key 13: the genesis's nonce.
    pub nonce: Option<[u8; 16]>,
    /// Key 14: the body key's commitment.
    pub commitment: [u8; 32],
    /// Key 15: the event ID of the skeleton twin.
    pub twin: Option<[u8; 32]>,
}

/// Reads the bytes value of a key the caller knows is present, or
/// `Malformed`.
fn bytes_at(map: &Map, key: u64) -> Result<Option<&[u8]>, KeyClass> {
    map.get(&key).map(|value| Ok(value.as_bytes()?)).transpose()
}

fn array_at<const N: usize>(map: &Map, key: u64) -> Result<Option<[u8; N]>, KeyClass> {
    map.get(&key)
        .map(|value| Ok(value.as_byte_array::<N>()?))
        .transpose()
}

/// An array of 1 or more byte strings.
fn byte_list(value: &Value) -> Result<Vec<&[u8]>, KeyClass> {
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(malformed());
    }
    items.iter().map(|item| Ok(item.as_bytes()?)).collect()
}

/// A flag: present only as 1.
fn flag(value: Option<&Value>) -> Result<bool, KeyClass> {
    match value {
        None => Ok(false),
        Some(Value::Unsigned(1)) => Ok(true),
        Some(_) => Err(malformed()),
    }
}

/// A key name a body holds: a self reference only in an event that rotates,
/// and only its own.
fn body_name(value: &Value, own: &SelfRef, rotates: bool) -> Result<KeyName, KeyClass> {
    let name = KeyName::decode(value.as_bytes()?, true)?;
    match &name {
        KeyName::SelfRef(found) if !rotates || found != own => Err(malformed()),
        _ => Ok(name),
    }
}

impl VisiblePart {
    /// Whether the event rotates.
    pub fn rotates(&self) -> bool {
        matches!(self.seal, Seal::Rotation(_))
    }

    /// The commitments the event publishes, if it rotates.
    pub fn rotation(&self) -> Option<&RotationKeys> {
        match &self.seal {
            Seal::Rotation(keys) => Some(keys),
            Seal::Under(_) => None,
        }
    }

    /// The state its sealed part is sealed under, if it does not rotate.
    pub fn sealed_under(&self) -> Option<&RotationSet> {
        match &self.seal {
            Seal::Rotation(_) => None,
            Seal::Under(state) => Some(state),
        }
    }

    /// Its wraps, bundle wraps and space wraps together, over every
    /// delivery.
    pub fn wrap_count(&self) -> usize {
        self.deliveries.iter().map(Delivery::wrap_count).sum()
    }

    /// The body's bytes: the visible part's one deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        use visible_key as k;
        let mut map = Map::new();
        map.insert(k::VERSION, Value::Unsigned(BODY_VERSION));
        match &self.seal {
            Seal::Rotation(keys) => {
                map.insert(k::ROTATES, Value::Unsigned(1));
                map.insert(k::GRANT_COMMITMENT, Value::from(keys.grant_commitment));
                map.insert(k::READ, Value::from(keys.read));
                map.insert(k::UPLOAD, Value::from(keys.upload));
            }
            Seal::Under(state) => {
                map.insert(k::SEALED_UNDER, Value::Bytes(state.encode()));
            }
        }
        if !self.deliveries.is_empty() {
            let items = self.deliveries.iter().map(Delivery::to_value).collect();
            map.insert(k::DELIVERIES, Value::Array(items));
        }
        map.insert(k::SEALED, Value::Bytes(self.sealed.clone()));
        if let Some(nonce) = self.nonce {
            map.insert(k::NONCE, Value::from(nonce));
        }
        map.insert(k::COMMITMENT, Value::from(self.commitment));
        if let Some(twin) = self.twin {
            map.insert(k::TWIN, Value::from(twin));
        }
        Value::Map(map).encode()
    }

    /// Reads and checks a body's visible part, in keys.md's order (section
    /// 3.2, "The visible part"), with the envelope's `author` and `seq`. A
    /// peer can run these checks too. Whether keys 13 and 15 belong is
    /// roster.md's check, which knows the envelope and the event's place.
    ///
    /// # Errors
    ///
    /// 1. `Malformed` unless it decodes as deterministic CBOR, a map with an
    ///    unsigned key 1.
    /// 2. `UnsupportedVersion` unless key 1 is 1.
    /// 3. `Malformed` for a key outside 1, 2, 3, 7, 8, 9, 11, 12, 13, 14
    ///    and 15.
    /// 4. `Malformed` unless keys 3, 11 and 12 are present exactly when key
    ///    2 (which is 1) is, key 9 exactly when key 2 is absent, and keys 8
    ///    and 14 always.
    /// 5. `Malformed` unless keys 3, 11, 12, 14 and 15 are 32 bytes, and key
    ///    13 16 bytes, only with key 2 and never with key 15; then
    ///    `InvalidKey` unless keys 11 and 12 are valid Ed25519 keys.
    /// 6. For each delivery: `Malformed` for another shape, a name that does
    ///    not read as a key name (or that class), a self reference other
    ///    than its own or in an event that does not rotate, or an own key
    ///    name with another grant key name; each wrap's `open_wrap` steps 1
    ///    to 5 (`Malformed` or `UnsupportedVersion`); then `Malformed` for
    ///    more than 64 deliveries or 768 wraps.
    /// 7. `Malformed` unless key 8 is at least 41 bytes and key 9 a key name
    ///    that is no self reference (or that class).
    pub fn read(body: &[u8], author: &DeviceId, seq: u64) -> Result<Self, KeyClass> {
        use visible_key as k;
        let own = SelfRef::new(*author, seq);
        // 1.
        let value = cbor::decode(body)?;
        let map = value.as_map()?;
        let version = map.get(&k::VERSION).ok_or_else(malformed)?.as_unsigned()?;
        // 2.
        if version != BODY_VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        // 3.
        if !map.keys().all(|key| k::ALLOWED.contains(key)) {
            return Err(malformed());
        }
        // 4.
        let rotates = flag(map.get(&k::ROTATES))?;
        let rotation_keys = [k::GRANT_COMMITMENT, k::READ, k::UPLOAD];
        if rotation_keys
            .iter()
            .any(|key| map.contains_key(key) != rotates)
            || map.contains_key(&k::SEALED_UNDER) == rotates
            || !map.contains_key(&k::SEALED)
            || !map.contains_key(&k::COMMITMENT)
        {
            return Err(malformed());
        }
        // 5.
        let grant_commitment = array_at::<32>(map, k::GRANT_COMMITMENT)?;
        let read = array_at::<32>(map, k::READ)?;
        let upload = array_at::<32>(map, k::UPLOAD)?;
        let commitment = array_at::<32>(map, k::COMMITMENT)?.ok_or_else(malformed)?;
        let twin = array_at::<32>(map, k::TWIN)?;
        let nonce = array_at::<16>(map, k::NONCE)?;
        if nonce.is_some() && (!rotates || twin.is_some()) {
            return Err(malformed());
        }
        for key in [read, upload].into_iter().flatten() {
            ed25519_valid(&key)?;
        }
        // 6.
        let mut deliveries = Vec::new();
        if let Some(items) = map.get(&k::DELIVERIES) {
            let items = items.as_array()?;
            if items.is_empty() {
                return Err(malformed());
            }
            for item in items {
                deliveries.push(read_delivery(item, &own, rotates)?);
            }
            let wraps: usize = deliveries.iter().map(Delivery::wrap_count).sum();
            if deliveries.len() > MAX_DELIVERIES_PER_EVENT || wraps > MAX_WRAPS_PER_EVENT {
                return Err(malformed());
            }
        }
        // 7.
        let sealed = bytes_at(map, k::SEALED)?.ok_or_else(malformed)?;
        if sealed.len() < MIN_SEALED_BYTES {
            return Err(malformed());
        }
        let seal = match (grant_commitment, read, upload) {
            (Some(grant_commitment), Some(read), Some(upload)) => Seal::Rotation(RotationKeys {
                grant_commitment,
                read,
                upload,
            }),
            _ => {
                let under = bytes_at(map, k::SEALED_UNDER)?.ok_or_else(malformed)?;
                Seal::Under(RotationSet::decode(under)?)
            }
        };
        Ok(Self {
            seal,
            deliveries,
            sealed: sealed.to_vec(),
            nonce,
            commitment,
            twin,
        })
    }

    /// Opens the sealed part under the event's body key and checks it
    /// (keys.md, section 3.2, "The sealed part"). `log`, `author` and `seq`
    /// are the carrying event's.
    ///
    /// # Errors
    ///
    /// `BadSeal` when the body key misses the visible commitment or the
    /// sealed part does not open under it; then [`Inner::read`]'s classes.
    /// A caller that holds the key only provisionally (keys.md, "Taking a
    /// key") holds the event `Sealed` rather than void on `BadSeal`.
    pub fn open(
        &self,
        body_key: &[u8; 32],
        log: &[u8],
        author: &DeviceId,
        seq: u64,
    ) -> Result<Inner, KeyClass> {
        if body_commitment(body_key) != self.commitment {
            return Err(ErrorClass::BadSeal.into());
        }
        let (nonce, ciphertext) = self
            .sealed
            .split_first_chunk::<XCHACHA20POLY1305_NONCE>()
            .ok_or(ErrorClass::BadSeal)?;
        let plaintext =
            xchacha20poly1305_open(body_key, nonce, &body_aad(log, author, seq), ciphertext)
                .map_err(|_| ErrorClass::BadSeal)?;
        Inner::read(&plaintext, self, &SelfRef::new(*author, seq))
    }

    /// [`VisiblePart::open`] with the secret the event is sealed under:
    /// `k_R` in an event that rotates, `k(S)` of `sealed_under` otherwise.
    ///
    /// # Errors
    ///
    /// As [`VisiblePart::open`].
    pub fn open_with_secret(
        &self,
        secret: &[u8; 32],
        log: &[u8],
        author: &DeviceId,
        seq: u64,
    ) -> Result<Inner, KeyClass> {
        self.open(&body_key(secret, log, author, seq), log, author, seq)
    }
}

fn read_delivery(value: &Value, own: &SelfRef, rotates: bool) -> Result<Delivery, KeyClass> {
    use delivery_key as k;
    let map = value.as_map()?;
    if !map
        .keys()
        .all(|key| (k::KEY_NAME..=k::SPACE_WRAPS).contains(key))
        || !(map.contains_key(&k::KEY_NAME) || map.contains_key(&k::GRANT_NAME))
        || !(map.contains_key(&k::WRAPS) || map.contains_key(&k::SPACE_WRAPS))
    {
        return Err(malformed());
    }
    let name = |key| {
        map.get(&key)
            .map(|value| body_name(value, own, rotates))
            .transpose()
    };
    let key_name = name(k::KEY_NAME)?;
    let grant_name = name(k::GRANT_NAME)?;
    let wraps = |key| -> Result<Vec<Vec<u8>>, KeyClass> {
        let Some(value) = map.get(&key) else {
            return Ok(Vec::new());
        };
        byte_list(value)?
            .into_iter()
            .map(|wrap| {
                read_wrap(wrap)?;
                Ok(wrap.to_vec())
            })
            .collect()
    };
    let delivery = Delivery {
        key_name,
        grant_name,
        wraps: wraps(k::WRAPS)?,
        space_wraps: wraps(k::SPACE_WRAPS)?,
    };
    // The own delivery names both states by the self reference, so a peer
    // cannot tell a grant rotation by its shape.
    if matches!(delivery.key_name, Some(KeyName::SelfRef(_)))
        && delivery.grant_name.is_some()
        && delivery.grant_name != delivery.key_name
    {
        return Err(malformed());
    }
    Ok(delivery)
}

/// Sealed key 1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantSlot {
    /// 1: the event is a grant rotation, and its own delivery's grant slots
    /// carry its new grant seed.
    Rotation,
    /// The key name of the grant state the own delivery's grant slots carry.
    State(RotationSet),
}

/// A notice: the grant key of a space this space's roster grants (keys.md,
/// section 2.6). Whether it is valid is the key graph's check (section 3.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Notice {
    /// Key 1: the granted space's ID.
    pub space: EventId,
    /// Key 2: the event ID of one grant rotation of the granted space.
    pub rotation: EventId,
    /// Key 3: `grant_public` of that rotation.
    pub public: Box<[u8; XWING_PUBLIC]>,
    /// Key 4: that rotation is a break, and the notice admits its principal
    /// "from now on".
    pub from_now_on: bool,
}

impl Notice {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(notice_key::SPACE, Value::from(self.space.0));
        map.insert(notice_key::ROTATION, Value::from(self.rotation.0));
        map.insert(notice_key::PUBLIC, Value::from(&self.public[..]));
        if self.from_now_on {
            map.insert(notice_key::FROM_NOW_ON, Value::Unsigned(1));
        }
        Value::Map(map)
    }

    fn read(value: &Value, is_break: bool) -> Result<Self, KeyClass> {
        use notice_key as k;
        let map = value.as_map()?;
        if !map
            .keys()
            .all(|key| (k::SPACE..=k::FROM_NOW_ON).contains(key))
        {
            return Err(malformed());
        }
        let field = |key| map.get(&key).ok_or_else(malformed);
        let space = EventId(field(k::SPACE)?.as_byte_array()?);
        let rotation = EventId(field(k::ROTATION)?.as_byte_array()?);
        let public = Box::new(field(k::PUBLIC)?.as_byte_array::<XWING_PUBLIC>()?);
        let from_now_on = flag(map.get(&k::FROM_NOW_ON))?;
        if from_now_on && !is_break {
            return Err(malformed());
        }
        xwing_valid(&public[..])?;
        Ok(Self {
            space,
            rotation,
            public,
            from_now_on,
        })
    }
}

/// A space event's sealed part, `inner`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Inner {
    /// Key 1.
    pub grant: Option<GrantSlot>,
    /// Key 2: a rotation with no link back.
    pub is_break: bool,
    /// Key 3.
    pub links: Vec<Link>,
    /// Key 4.
    pub gaps: Vec<GapRecord>,
    /// Key 5.
    pub notices: Vec<Notice>,
    /// Key 16: the roster part, in a roster event.
    pub roster: Option<Vec<u8>>,
    /// Key 17: how many zero bytes of padding.
    pub padding: Option<usize>,
    /// Key 18: the events of other logs it names, in ascending order.
    pub refs: Vec<Ref>,
}

impl Inner {
    /// Whether the event is a grant rotation: sealed key 1 is 1.
    pub fn grant_rotation(&self) -> bool {
        self.grant == Some(GrantSlot::Rotation)
    }

    /// Whether the event responds: it has sealed refs.
    pub fn responds(&self) -> bool {
        !self.refs.is_empty()
    }

    /// The sealed part's plaintext: its one deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        use sealed_key as k;
        let mut map = Map::new();
        match &self.grant {
            Some(GrantSlot::Rotation) => {
                map.insert(k::GRANT, Value::Unsigned(1));
            }
            Some(GrantSlot::State(state)) => {
                map.insert(k::GRANT, Value::Bytes(state.encode()));
            }
            None => {}
        }
        if self.is_break {
            map.insert(k::BREAK, Value::Unsigned(1));
        }
        let lists: [(u64, Vec<Value>); 3] = [
            (
                k::LINKS,
                self.links
                    .iter()
                    .map(|l| Value::Bytes(l.encode()))
                    .collect(),
            ),
            (
                k::GAPS,
                self.gaps.iter().map(|g| Value::Bytes(g.encode())).collect(),
            ),
            (
                k::NOTICES,
                self.notices.iter().map(Notice::to_value).collect(),
            ),
        ];
        for (key, items) in lists {
            if !items.is_empty() {
                map.insert(key, Value::Array(items));
            }
        }
        if let Some(roster) = &self.roster {
            map.insert(k::ROSTER, Value::Bytes(roster.clone()));
        }
        if let Some(padding) = self.padding {
            map.insert(k::PADDING, Value::Bytes(vec![0; padding]));
        }
        if !self.refs.is_empty() {
            map.insert(k::REFS, refs_value(&self.refs));
        }
        Value::Map(map).encode()
    }

    /// The sealed part, key 8: `nonce || XChaCha20-Poly1305(body_key, nonce,
    /// inner, aad)`, with the nonce given.
    pub fn seal_with(
        &self,
        body_key: &[u8; 32],
        log: &[u8],
        author: &DeviceId,
        seq: u64,
        nonce: &[u8; XCHACHA20POLY1305_NONCE],
    ) -> Vec<u8> {
        let ciphertext =
            xchacha20poly1305_seal(body_key, nonce, &body_aad(log, author, seq), &self.encode());
        [&nonce[..], &ciphertext].concat()
    }

    /// Reads and checks an opened sealed part, in keys.md's order (section
    /// 3.2, "The sealed part"), against its visible part and its event's
    /// self reference.
    ///
    /// # Errors
    ///
    /// 1. `Malformed` unless `inner` decodes as a deterministic CBOR map
    ///    with keys among 1 to 5, 16, 17 and 18; keys 1 and 2 only in an
    ///    event that rotates; key 1 present when the own delivery names a
    ///    grant state, and 1 or a rotation set (or that set's class); key 2
    ///    1; key 16 bytes; key 17 bytes of zeros; key 18 refs of events.md
    ///    (`Malformed`, or `TooLarge` for more than 64).
    /// 2. Each link's steps 1 to 5 (section 3.1), a self reference under it
    ///    only its own in an event that rotates (`Malformed`); each gap
    ///    record's.
    /// 3. Each notice: `Malformed` for another shape, or key 4 in an event
    ///    without `break`; `InvalidKey` unless key 3 is a valid X-Wing key.
    pub fn read(plaintext: &[u8], visible: &VisiblePart, own: &SelfRef) -> Result<Self, KeyClass> {
        use sealed_key as k;
        let rotates = visible.rotates();
        // 1.
        let value = cbor::decode(plaintext)?;
        let map = value.as_map()?;
        if !map.keys().all(|key| k::ALLOWED.contains(key)) {
            return Err(malformed());
        }
        if !rotates && (map.contains_key(&k::GRANT) || map.contains_key(&k::BREAK)) {
            return Err(malformed());
        }
        if visible.deliveries.iter().any(|d| d.is_own(own)) && !map.contains_key(&k::GRANT) {
            return Err(malformed());
        }
        let grant = match map.get(&k::GRANT) {
            None => None,
            Some(Value::Unsigned(1)) => Some(GrantSlot::Rotation),
            Some(Value::Bytes(state)) => Some(GrantSlot::State(RotationSet::decode(state)?)),
            Some(_) => return Err(malformed()),
        };
        let is_break = flag(map.get(&k::BREAK))?;
        let roster = bytes_at(map, k::ROSTER)?.map(<[u8]>::to_vec);
        let padding = match bytes_at(map, k::PADDING)? {
            Some(zeros) if zeros.iter().any(|&byte| byte != 0) => return Err(malformed()),
            zeros => zeros.map(<[u8]>::len),
        };
        let refs = match map.get(&k::REFS) {
            Some(value) => decode_refs(value)?,
            None => Vec::new(),
        };
        // 2.
        let mut links = Vec::new();
        if let Some(value) = map.get(&k::LINKS) {
            for bytes in byte_list(value)? {
                let link = Link::read(bytes)?;
                if let KeyName::SelfRef(under) = &link.under
                    && (!rotates || under != own)
                {
                    return Err(malformed());
                }
                links.push(link);
            }
        }
        let mut gaps = Vec::new();
        if let Some(value) = map.get(&k::GAPS) {
            for bytes in byte_list(value)? {
                gaps.push(GapRecord::read(bytes)?);
            }
        }
        // 3.
        let mut notices = Vec::new();
        if let Some(value) = map.get(&k::NOTICES) {
            let items = value.as_array()?;
            if items.is_empty() {
                return Err(malformed());
            }
            for item in items {
                notices.push(Notice::read(item, is_break)?);
            }
        }
        Ok(Self {
            grant,
            is_break,
            links,
            gaps,
            notices,
            roster,
            padding,
            refs,
        })
    }
}
