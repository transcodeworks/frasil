//! The visible body (units.md, section 2.3), stubs (section 2.10), covers
//! and the compaction declaration (section 2.9), and what a peer checks of
//! them (section 3.1, steps 4 to 11).
//!
//! The visible body is a deterministic CBOR map:
//!
//! | Key | Name | Value |
//! |---|---|---|
//! | 1 | `version` | 1 |
//! | 2 | `stream` | bytes(16), not all zero |
//! | 3 | `key` | bytes: the key reference of the state the unit is sealed under |
//! | 4 | `stream_prev` | bytes(32), when the writer has a previous unit in the stream |
//! | 5 | `objects` | 1 to 4,096 locators, strictly ascending, when it names objects |
//! | 6 | `compacts` | the compaction declaration, in a snapshot unit only |
//! | 7 | `sealed` | bytes, at least 72: the seal |
//! | 8 | `supersedes` | 1 to 4,096 supersessions, strictly ascending |
//!
//! A unit with key 6 is a **snapshot unit**; every other unit is a **log
//! unit**. A peer reads keys 1 to 6 and 8 and never the contents of key 7.

use crate::UnitError;
use crate::limits::{
    LOCATOR_BYTES, MAX_COVERS, MAX_LOCATORS, MAX_ROTATIONS_PARENT, MAX_STUBS, MAX_SUPERSESSIONS,
    MIN_UNIT_SEAL_BYTES, NONCE_BYTES, TAG_BYTES,
};
use crate::stream::{self, StreamId};
use frasil_adapter::{Locator, Supersession};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::{Cuts, EventId, MAX_CUTS, kind};
use frasil_keys::{KeyClass, KeyName, RotationSet};

/// The visible body's version.
pub const VERSION: u64 = 1;

const B_VERSION: u64 = 1;
const B_STREAM: u64 = 2;
const B_KEY: u64 = 3;
const B_STREAM_PREV: u64 = 4;
const B_OBJECTS: u64 = 5;
const B_COMPACTS: u64 = 6;
const B_SEALED: u64 = 7;
const B_SUPERSEDES: u64 = 8;

const C_OBJECT: u64 = 1;
const C_COVERS: u64 = 2;
const C_STUBS: u64 = 3;

/// A stub (section 2.10): an event whose bytes a replica does not hold.
///
/// ```text
/// stub = [event ID (bytes(32)), author (bytes(32)), seq (>= 1), height (>= 1), kind]
/// ```
///
/// `kind` is 4, or 64 to 127: space events, anchors and storage events
/// decide authority, coverage and stability, and a replica holds them in
/// full. A stub in a space snapshot adds a sixth element, the unit's
/// stream, so that a newcomer knows which stream a stubbed unit
/// belonged to; such a stub is of kind 4. A stub of an event that declares
/// cuts (events.md, 3.11 Cuts) adds them as its last element, an array of
/// 1 to 4 event IDs, strictly ascending: the sixth element of a snapshot
/// unit's stub, the seventh of a space snapshot's. A stub of an event that
/// declares none has no such element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stub {
    /// The event's ID.
    pub id: EventId,
    /// Its author, the device ID its envelope gives.
    pub author: DeviceId,
    /// Its `seq`.
    pub seq: u64,
    /// Its height.
    pub height: u64,
    /// Its kind: 4, or 64 to 127.
    pub kind: u8,
    /// The unit's stream, in a space snapshot's stub.
    pub stream: Option<StreamId>,
    /// The cuts the event declares; [`Cuts::NONE`] when it declares none.
    pub cuts: Cuts,
}

impl Stub {
    /// The stub frasil-events places against, with the cuts it carries.
    pub fn event_stub(&self) -> frasil_events::Stub {
        frasil_events::Stub {
            id: self.id,
            author: self.author,
            seq: self.seq,
            height: self.height,
            kind: self.kind,
            cuts: self.cuts,
        }
    }

    /// The stub as a CBOR array: five elements, the stream when it has one,
    /// then its cuts when it carries any.
    pub fn to_value(&self) -> Value {
        let mut items = vec![
            Value::from(self.id.0),
            Value::from(self.author.0),
            Value::from(self.seq),
            Value::from(self.height),
            Value::from(u64::from(self.kind)),
        ];
        if let Some(stream) = self.stream {
            items.push(Value::from(stream));
        }
        if !self.cuts.is_empty() {
            items.push(Value::Array(
                self.cuts.iter().map(|id| Value::from(id.0)).collect(),
            ));
        }
        Value::Array(items)
    }

    /// Reads a stub of five to seven elements: five, then the stream when
    /// the next is a byte string, then the cuts when the last is an array.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else: a `seq` or height of 0, a kind other
    /// than 4 or 64 to 127, a stream on a stub that is not of kind 4 or
    /// that is not a stream ID, cuts that are not 1 to 4 event IDs strictly
    /// ascending, or an element after the cuts.
    pub fn read(value: &Value) -> Result<Self, Malformed> {
        let items = value.as_array()?;
        let [id, author, seq, height, kind, rest @ ..] = items else {
            return Err(Malformed);
        };
        // The cuts are the last element when it is an array.
        let (rest, cuts) = match rest.split_last() {
            Some((Value::Array(cuts), before)) => (before, Some(cuts)),
            _ => (rest, None),
        };
        let stream = match rest {
            [] => None,
            [stream] => Some(stream),
            _ => return Err(Malformed),
        };
        let stub = Self {
            id: EventId(id.as_byte_array()?),
            author: DeviceId(author.as_byte_array()?),
            seq: seq.as_unsigned()?,
            height: height.as_unsigned()?,
            kind: u8::try_from(kind.as_unsigned()?).map_err(|_| Malformed)?,
            stream: match stream {
                None => None,
                Some(stream) => {
                    let bytes = stream.as_bytes()?;
                    if !stream::is_valid(bytes) {
                        return Err(Malformed);
                    }
                    Some(bytes.try_into().map_err(|_| Malformed)?)
                }
            },
            cuts: match cuts {
                None => Cuts::NONE,
                Some(cuts) => read_cuts(cuts)?,
            },
        };
        let kind_allowed = stub.kind == kind::UNIT
            || (kind::FIRST_IGNORABLE..=kind::LAST_IGNORABLE).contains(&stub.kind);
        if stub.seq == 0 || stub.height == 0 || !kind_allowed {
            return Err(Malformed);
        }
        if stub.stream.is_some() && stub.kind != kind::UNIT {
            return Err(Malformed);
        }
        Ok(stub)
    }
}

/// A stub's cuts: 1 to 4 event IDs, strictly ascending.
fn read_cuts(items: &[Value]) -> Result<Cuts, Malformed> {
    if items.is_empty() || items.len() > MAX_CUTS {
        return Err(Malformed);
    }
    let ids = items
        .iter()
        .map(|item| item.as_byte_array().map(EventId))
        .collect::<Result<Vec<_>, _>>()?;
    Cuts::new(&ids).ok_or(Malformed)
}

/// Reads an array of at most `limit` stubs, strictly ascending by event ID.
///
/// # Errors
///
/// `Malformed`.
pub fn read_stubs(value: &Value, limit: usize) -> Result<Vec<Stub>, Malformed> {
    let items = value.as_array()?;
    if items.len() > limit {
        return Err(Malformed);
    }
    let stubs = items
        .iter()
        .map(Stub::read)
        .collect::<Result<Vec<_>, _>>()?;
    if !stubs.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return Err(Malformed);
    }
    Ok(stubs)
}

/// A snapshot unit's stubs (section 2.10): at most 8,192, strictly
/// ascending by event ID, each of kind 4 with five elements, or six when
/// its unit declares cuts, the sixth its cuts.
///
/// # Errors
///
/// `Malformed`: another count, a stream where none belongs, or a sixth
/// element that is not 1 to 4 event IDs strictly ascending.
pub fn read_compaction_stubs(value: &Value) -> Result<Vec<Stub>, Malformed> {
    let stubs = read_stubs(value, MAX_STUBS)?;
    if stubs
        .iter()
        .any(|stub| stub.stream.is_some() || stub.kind != kind::UNIT)
    {
        return Err(Malformed);
    }
    Ok(stubs)
}

/// A space snapshot's stubs, and a log entry's (sections 2.10 and 2.11):
/// at most 8,192, strictly ascending by event ID, each with six elements,
/// the sixth the unit's stream, or seven when its unit declares cuts, the
/// seventh its cuts.
///
/// # Errors
///
/// `Malformed`: another count, no stream, or a seventh element that is
/// not 1 to 4 event IDs strictly ascending.
pub fn read_snapshot_stubs(value: &Value) -> Result<Vec<Stub>, Malformed> {
    let stubs = read_stubs(value, MAX_STUBS)?;
    if stubs.iter().any(|stub| stub.stream.is_none()) {
        return Err(Malformed);
    }
    Ok(stubs)
}

/// Stubs as a CBOR array, ascending by event ID.
pub fn stubs_value(stubs: &[Stub]) -> Value {
    let mut stubs = stubs.to_vec();
    stubs.sort_unstable_by_key(|stub| stub.id);
    Value::Array(stubs.iter().map(Stub::to_value).collect())
}

/// One pair of a snapshot unit's `covers` (section 2.9), or of a head
/// statement's stream entry: a writer and its stream frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cover {
    /// The writer's device ID.
    pub writer: DeviceId,
    /// Its unit of greatest `seq` in the stream.
    pub unit: EventId,
}

impl Cover {
    /// The pair `[writer, unit ID]`.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![Value::from(self.writer.0), Value::from(self.unit.0)])
    }
}

/// Reads an array of at most 4,096 pairs `[writer, unit ID]`, bytes(32)
/// each, strictly ascending by writer.
///
/// # Errors
///
/// `Malformed`.
pub fn read_covers(value: &Value) -> Result<Vec<Cover>, Malformed> {
    let items = value.as_array()?;
    if items.len() > MAX_COVERS {
        return Err(Malformed);
    }
    let mut covers: Vec<Cover> = Vec::with_capacity(items.len());
    for item in items {
        let [writer, unit] = item.as_array()? else {
            return Err(Malformed);
        };
        let cover = Cover {
            writer: DeviceId(writer.as_byte_array()?),
            unit: EventId(unit.as_byte_array()?),
        };
        if covers
            .last()
            .is_some_and(|last| last.writer >= cover.writer)
        {
            return Err(Malformed);
        }
        covers.push(cover);
    }
    Ok(covers)
}

/// Covers as a CBOR array, ascending by writer.
pub fn covers_value(covers: &[Cover]) -> Value {
    let mut covers = covers.to_vec();
    covers.sort_unstable();
    Value::Array(covers.iter().map(Cover::to_value).collect())
}

/// A snapshot unit's compaction declaration, visible key 6 (section 2.9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Compacts {
    /// The locator of the stream snapshot object, which key 5 also lists.
    pub object: Locator,
    /// The writers' stream frontiers of the stream past, ascending by
    /// writer.
    pub covers: Vec<Cover>,
    /// The boundary stubs, of five elements and kind 4, with the cuts of an
    /// event that declares any, ascending by event ID.
    pub stubs: Vec<Stub>,
}

impl Compacts {
    /// The declaration as a CBOR map.
    pub fn to_value(&self) -> Value {
        Value::Map(Map::from([
            (C_OBJECT, Value::from(self.object)),
            (C_COVERS, covers_value(&self.covers)),
            (C_STUBS, stubs_value(&self.stubs)),
        ]))
    }

    /// The declaration's encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Section 3.1, step 10: a map of keys 1 to 3, all present; key 1 64
    /// bytes and in `objects`; key 2 at most 4,096 pairs of two 32-byte
    /// strings, strictly ascending by writer; key 3 at most 8,192 stubs of
    /// five elements and kind 4, strictly ascending by event ID, each with
    /// a sixth, its cuts, when its event declares any (section 2.10).
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(value: &Value, objects: &[Locator]) -> Result<Self, Malformed> {
        let map = value.as_map()?;
        if map.len() != 3 || !(C_OBJECT..=C_STUBS).all(|key| map.contains_key(&key)) {
            return Err(Malformed);
        }
        let object: Locator = map[&C_OBJECT].as_byte_array()?;
        if !objects.contains(&object) {
            return Err(Malformed);
        }
        let covers = read_covers(&map[&C_COVERS])?;
        let stubs = read_compaction_stubs(&map[&C_STUBS])?;
        Ok(Self {
            object,
            covers,
            stubs,
        })
    }
}

/// A unit's key reference, as a peer reads it before any key (section 3.1,
/// step 8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyReference {
    /// keys.md, "Reading a unit's key reference", step 1: one rotation set.
    Set(RotationSet),
    /// ext-restricted-spaces.md, "The restricted key reference": the
    /// restricted space's own state in the clear, then its parent's state
    /// sealed (steps 1 and 2 of "Reading a restricted key reference").
    Restricted {
        /// The restricted space's own state, `S_F`.
        own: RotationSet,
        /// The nonce of the sealed parent state.
        nonce: [u8; NONCE_BYTES],
        /// The sealed parent state, `encode_set(S_P)` with its tag.
        sealed: Vec<u8>,
    },
}

impl KeyReference {
    /// Reads a key reference before any key: one rotation set, or one
    /// followed by a sealed parent state of `41 + 32b` bytes, `b` from 1 to
    /// 64 (ext-restricted-spaces.md, section 3.2, steps 1 and 2). A peer
    /// cannot tell a restricted space's units from others', so it reads
    /// both forms.
    ///
    /// # Errors
    ///
    /// `Malformed` or `TooManyRotations`.
    pub fn read(data: &[u8]) -> Result<Self, KeyClass> {
        let (KeyName::Set(own), rest) = KeyName::read(data, false)? else {
            return Err(ErrorClass::Malformed.into());
        };
        if rest.is_empty() {
            return Ok(Self::Set(own));
        }
        #[cfg(feature = "ext-restricted-spaces")]
        if let Ok(reference) = frasil_keys::ext_restricted_spaces::RestrictedReference::read(data) {
            return Ok(Self::Restricted {
                own: reference.own,
                nonce: reference.nonce,
                sealed: reference.sealed,
            });
        }
        let overhead = NONCE_BYTES + 1 + TAG_BYTES;
        if rest.len() < overhead + 32 || !(rest.len() - overhead).is_multiple_of(32) {
            return Err(ErrorClass::Malformed.into());
        }
        if (rest.len() - overhead) / 32 > MAX_ROTATIONS_PARENT {
            return Err(KeyClass::TooManyRotations);
        }
        let (nonce, sealed) = rest.split_at(NONCE_BYTES);
        Ok(Self::Restricted {
            own,
            nonce: nonce.try_into().map_err(|_| ErrorClass::Malformed)?,
            sealed: sealed.to_vec(),
        })
    }

    /// The state the reference names in the clear: the rotation set, or a
    /// restricted space's own state.
    pub fn own(&self) -> &RotationSet {
        match self {
            Self::Set(set) | Self::Restricted { own: set, .. } => set,
        }
    }
}

/// A unit's visible body (section 2.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Body {
    /// Key 2: the stream ID.
    pub stream: StreamId,
    /// Key 3: the key reference's bytes.
    pub key: Vec<u8>,
    /// Key 3, read.
    pub reference: KeyReference,
    /// Key 4: the writer's previous unit in this stream.
    pub stream_prev: Option<EventId>,
    /// Key 5: the locators the unit names, ascending; empty for none.
    pub objects: Vec<Locator>,
    /// Key 6: the compaction declaration of a snapshot unit.
    pub compacts: Option<Compacts>,
    /// Key 7: the seal.
    pub sealed: Vec<u8>,
    /// Key 8: its supersessions, ascending; empty for none.
    pub supersedes: Vec<Supersession>,
}

impl Body {
    /// Whether the unit is a snapshot unit: it has key 6.
    pub fn is_snapshot(&self) -> bool {
        self.compacts.is_some()
    }

    /// The body's deterministic encoding. Objects are written ascending,
    /// each once.
    pub fn encode(&self) -> Vec<u8> {
        encode_body(
            &self.stream,
            &self.key,
            &self.sealed,
            self.stream_prev.as_ref(),
            &self.objects,
            self.compacts.as_ref(),
            &self.supersedes,
        )
    }

    /// Section 3.1, steps 4 to 11, in order, reading no sealed byte.
    ///
    /// # Errors
    ///
    /// 4. `Malformed` for bytes that are not deterministic CBOR, a map with
    ///    an unsigned key 1;
    /// 5. `UnsupportedVersion` for a key 1 other than 1;
    /// 6. `Malformed` for a key outside 1 to 8, or one of keys 1, 2, 3 and
    ///    7 missing;
    /// 7. `Malformed` for a stream that is not 16 bytes, or all zero;
    /// 8. the key reference's class: `Malformed` or `TooManyRotations`;
    /// 9. `Malformed` for a `stream_prev` that is not 32 bytes, objects that
    ///    are not 1 to 4,096 locators strictly ascending, or a seal shorter
    ///    than 72 bytes;
    /// 10. `Malformed` for a compaction declaration that breaks
    ///     [`Compacts::read`];
    /// 11. `Malformed` for supersessions that break section 2.3's form.
    pub fn read(data: &[u8]) -> Result<Self, UnitError> {
        // 4. Deterministic CBOR, a map with an unsigned key 1.
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map.get(&B_VERSION).ok_or(Malformed)?.as_unsigned()?;
        // 5. Version 1.
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        // 6. Keys among 1 to 8; keys 1, 2, 3 and 7 present.
        if map
            .keys()
            .any(|key| !(B_VERSION..=B_SUPERSEDES).contains(key))
            || ![B_STREAM, B_KEY, B_SEALED]
                .iter()
                .all(|key| map.contains_key(key))
        {
            return Err(ErrorClass::Malformed.into());
        }
        // 7. The stream.
        let stream_bytes = map[&B_STREAM].as_bytes()?;
        if !stream::is_valid(stream_bytes) {
            return Err(ErrorClass::Malformed.into());
        }
        let stream: StreamId = stream_bytes.try_into().map_err(|_| Malformed)?;
        // 8. The key reference, before any key.
        let key = map[&B_KEY].as_bytes()?.to_vec();
        let reference = KeyReference::read(&key)?;
        // 9. stream_prev, objects and the seal.
        let stream_prev = match map.get(&B_STREAM_PREV) {
            Some(value) => Some(EventId(value.as_byte_array()?)),
            None => None,
        };
        let objects = match map.get(&B_OBJECTS) {
            Some(value) => read_locators(value)?,
            None => Vec::new(),
        };
        let sealed = map[&B_SEALED].as_bytes()?;
        if sealed.len() < MIN_UNIT_SEAL_BYTES {
            return Err(ErrorClass::Malformed.into());
        }
        // 10. The compaction declaration.
        let compacts = match map.get(&B_COMPACTS) {
            Some(value) => Some(Compacts::read(value, &objects)?),
            None => None,
        };
        // 11. The supersessions.
        let supersedes = match map.get(&B_SUPERSEDES) {
            Some(value) => read_supersessions(value, Some(&objects), compacts.is_some())?,
            None => Vec::new(),
        };
        Ok(Self {
            stream,
            key,
            reference,
            stream_prev,
            objects,
            compacts,
            sealed: sealed.to_vec(),
            supersedes,
        })
    }
}

/// Reads key 8 (section 2.3): 1 to 4,096 supersessions, strictly ascending
/// by their bytes, of three elements in a log unit and two in a snapshot
/// unit; each successor in `objects`, and in a snapshot unit each
/// predecessor too. A space snapshot's stream entry has no `objects`, and
/// passes `None`.
pub(crate) fn read_supersessions(
    value: &Value,
    objects: Option<&[Locator]>,
    snapshot: bool,
) -> Result<Vec<Supersession>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_SUPERSESSIONS {
        return Err(Malformed);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (successor, listing, predecessor) = match (item.as_array()?, snapshot) {
            ([successor, predecessor], true) => (successor, None, predecessor),
            ([successor, listing, predecessor], false) => {
                (successor, Some(listing.as_byte_array()?), predecessor)
            }
            _ => return Err(Malformed),
        };
        let supersession = Supersession {
            successor: successor.as_byte_array::<LOCATOR_BYTES>()?,
            listing,
            predecessor: predecessor.as_byte_array::<LOCATOR_BYTES>()?,
        };
        if let Some(objects) = objects
            && (!objects.contains(&supersession.successor)
                || (snapshot && !objects.contains(&supersession.predecessor)))
        {
            return Err(Malformed);
        }
        out.push(supersession);
    }
    if !out.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(Malformed);
    }
    Ok(out)
}

/// A supersession as a CBOR array.
pub(crate) fn supersession_value(supersession: &Supersession) -> Value {
    let mut items = vec![Value::from(supersession.successor)];
    items.extend(supersession.listing.map(Value::from));
    items.push(Value::from(supersession.predecessor));
    Value::Array(items)
}

/// Reads 1 to 4,096 locators of 64 bytes, strictly ascending.
fn read_locators(value: &Value) -> Result<Vec<Locator>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_LOCATORS {
        return Err(Malformed);
    }
    let locators = items
        .iter()
        .map(Value::as_byte_array::<LOCATOR_BYTES>)
        .collect::<Result<Vec<_>, _>>()?;
    if !locators.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(Malformed);
    }
    Ok(locators)
}

/// Encodes a visible body from its parts. Objects and supersessions are
/// written ascending, each once, and keys 5 and 8 are left out when there
/// are none.
pub fn encode_body(
    stream: &StreamId,
    key: &[u8],
    sealed: &[u8],
    stream_prev: Option<&EventId>,
    objects: &[Locator],
    compacts: Option<&Compacts>,
    supersedes: &[Supersession],
) -> Vec<u8> {
    let mut map = Map::from([
        (B_VERSION, Value::from(VERSION)),
        (B_STREAM, Value::from(*stream)),
        (B_KEY, Value::from(key)),
        (B_SEALED, Value::from(sealed)),
    ]);
    if let Some(prev) = stream_prev {
        map.insert(B_STREAM_PREV, Value::from(prev.0));
    }
    if !objects.is_empty() {
        let mut objects = objects.to_vec();
        objects.sort_unstable();
        objects.dedup();
        map.insert(
            B_OBJECTS,
            Value::Array(objects.into_iter().map(Value::from).collect()),
        );
    }
    if let Some(compacts) = compacts {
        map.insert(B_COMPACTS, compacts.to_value());
    }
    if !supersedes.is_empty() {
        let mut supersedes = supersedes.to_vec();
        supersedes.sort_unstable();
        supersedes.dedup();
        map.insert(
            B_SUPERSEDES,
            Value::Array(supersedes.iter().map(supersession_value).collect()),
        );
    }
    Value::Map(map).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(kind: u8, stream: Option<StreamId>) -> Value {
        Stub {
            id: EventId([1; 32]),
            author: DeviceId([2; 32]),
            seq: 1,
            height: 1,
            kind,
            stream,
            cuts: Cuts::NONE,
        }
        .to_value()
    }

    fn with_cuts(stream: Option<StreamId>, cuts: &[EventId]) -> Stub {
        Stub {
            id: EventId([1; 32]),
            author: DeviceId([2; 32]),
            seq: 1,
            height: 1,
            kind: kind::UNIT,
            stream,
            cuts: Cuts::new(cuts).unwrap(),
        }
    }

    /// units.md, 2.10 Stubs: the cuts are the last element, the sixth of a
    /// snapshot unit's stub and the seventh of a space snapshot's.
    #[test]
    fn a_stub_carries_its_events_cuts_last() {
        let cuts = [EventId([7; 32]), EventId([8; 32])];
        for stream in [None, Some([3; 16])] {
            let stub = with_cuts(stream, &cuts);
            let value = stub.to_value();
            let items = value.as_array().unwrap();
            assert_eq!(items.len(), 6 + usize::from(stream.is_some()));
            assert!(matches!(items.last(), Some(Value::Array(ids)) if ids.len() == 2));
            assert_eq!(Stub::read(&value), Ok(stub));
            assert_eq!(stub.event_stub().cuts.as_slice(), &cuts);
        }
        // Of an ignorable kind too.
        let ignorable = Stub {
            kind: 64,
            ..with_cuts(None, &cuts)
        };
        assert_eq!(Stub::read(&ignorable.to_value()), Ok(ignorable));
        let item = |n: u8| Value::from([n; 32]);
        let base = || {
            vec![
                Value::from([1u8; 32]),
                Value::from([2u8; 32]),
                Value::from(1u64),
                Value::from(1u64),
                Value::from(4u64),
            ]
        };
        let refused = [
            // Empty, five, out of order, repeated, not 32 bytes.
            vec![],
            (1..=5).map(item).collect(),
            vec![item(8), item(7)],
            vec![item(7), item(7)],
            vec![Value::from([7u8; 31])],
        ];
        for cuts in refused {
            let mut items = base();
            items.push(Value::Array(cuts));
            assert_eq!(Stub::read(&Value::Array(items)), Err(Malformed));
        }
        // The stream after the cuts, or two streams, is Malformed.
        let mut after = base();
        after.push(Value::Array(vec![item(7)]));
        after.push(Value::from([3u8; 16]));
        assert_eq!(Stub::read(&Value::Array(after)), Err(Malformed));
        let mut two = base();
        two.push(Value::from([3u8; 16]));
        two.push(Value::from([3u8; 16]));
        assert_eq!(Stub::read(&Value::Array(two)), Err(Malformed));
        // Eight elements are too many.
        let mut eight = base();
        eight.push(Value::from([3u8; 16]));
        eight.push(Value::Array(vec![item(7)]));
        eight.push(Value::Array(vec![item(8)]));
        assert_eq!(Stub::read(&Value::Array(eight)), Err(Malformed));
    }

    /// A snapshot unit's stubs carry cuts as their sixth element, and
    /// still no stream.
    #[test]
    fn a_compaction_declaration_reads_stubs_with_cuts() {
        let object = [9; 64];
        let stub = with_cuts(None, &[EventId([7; 32])]);
        let compacts = Compacts {
            object,
            covers: Vec::new(),
            stubs: vec![stub],
        };
        assert_eq!(
            Compacts::read(&compacts.to_value(), &[object]),
            Ok(compacts)
        );
        let streamed = Compacts {
            object,
            covers: Vec::new(),
            stubs: vec![with_cuts(Some([3; 16]), &[EventId([7; 32])])],
        };
        assert_eq!(
            Compacts::read(&streamed.to_value(), &[object]),
            Err(Malformed)
        );
    }

    #[test]
    fn stubs_are_of_units_or_ignorable_kinds() {
        assert!(Stub::read(&stub(4, None)).is_ok());
        assert!(Stub::read(&stub(64, None)).is_ok());
        assert!(Stub::read(&stub(127, None)).is_ok());
        assert!(Stub::read(&stub(4, Some([3; 16]))).is_ok());
        for kind in [1, 2, 3, 5, 6, 63, 128] {
            assert_eq!(Stub::read(&stub(kind, None)), Err(Malformed), "{kind}");
        }
        assert_eq!(Stub::read(&stub(64, Some([3; 16]))), Err(Malformed));
        assert_eq!(Stub::read(&stub(4, Some([0; 16]))), Err(Malformed));
    }

    #[test]
    fn a_restricted_reference_is_read_by_its_visible_parts() {
        let own = RotationSet::single(EventId([1; 32]));
        let mut data = own.encode();
        assert_eq!(
            KeyReference::read(&data),
            Ok(KeyReference::Set(own.clone()))
        );
        data.extend_from_slice(&[0; NONCE_BYTES + 1 + 32 + TAG_BYTES]);
        assert!(matches!(
            KeyReference::read(&data),
            Ok(KeyReference::Restricted { .. })
        ));
        data.push(0);
        assert_eq!(KeyReference::read(&data), Err(ErrorClass::Malformed.into()));
        let mut many = own.encode();
        many.extend_from_slice(&vec![0; NONCE_BYTES + 1 + 32 * 65 + TAG_BYTES]);
        assert_eq!(KeyReference::read(&many), Err(KeyClass::TooManyRotations));
    }
}
