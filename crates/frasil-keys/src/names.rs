//! Rotation sets, self references and key names (keys.md, "Rotations and
//! states" and "Reading key names, bundles, wraps and links").
//!
//! ```text
//! encode_set(S) = u8(n) || id_1 || ... || id_n      1 <= n <= 64, strictly ascending
//! self_ref      = 0x00 || author || u64be(seq)      41 bytes
//! ```
//!
//! A **key name** says which state a wrap, link or delivery is about: a
//! rotation set, or, for the carrying event's own rotation, its self
//! reference. An event cannot hold its own ID, which is its hash.

use crate::KeyClass;
use crate::limits::{COLLAPSE_ABOVE, MAX_ROTATIONS, SELF_REFERENCE_BYTES};
use frasil_base::ErrorClass;
use frasil_base::notation::u64be;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;

/// A rotation's ID: the ID of the event that is the rotation.
pub type RotationId = EventId;

const ID_BYTES: usize = 32;

/// A state: a set of 1 to 64 rotation IDs, held in canonical order, distinct
/// and strictly ascending as byte strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RotationSet(Vec<RotationId>);

impl RotationSet {
    /// The set of these IDs, in canonical order; repeats count once.
    ///
    /// # Errors
    ///
    /// `Malformed` for no ID; `TooManyRotations` for more than 64.
    pub fn new(ids: impl IntoIterator<Item = RotationId>) -> Result<Self, KeyClass> {
        let mut ids: Vec<RotationId> = ids.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return Err(ErrorClass::Malformed.into());
        }
        if ids.len() > MAX_ROTATIONS {
            return Err(KeyClass::TooManyRotations);
        }
        Ok(Self(ids))
    }

    /// The state of one rotation, `{R}`.
    pub fn single(id: RotationId) -> Self {
        Self(vec![id])
    }

    /// The IDs, in canonical order.
    pub fn ids(&self) -> &[RotationId] {
        &self.0
    }

    /// How many rotations the state holds.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a state holds at least one rotation.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the state holds this rotation.
    pub fn contains(&self, id: &RotationId) -> bool {
        self.0.binary_search(id).is_ok()
    }

    /// Whether a collapse is due for a current state this large: more than 8
    /// rotations (keys.md, "Labels and limits"; section 3.12).
    pub fn collapse_due(&self) -> bool {
        self.0.len() > COLLAPSE_ABOVE
    }

    /// `encode_set(S) = u8(n) || id_1 || ... || id_n`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ID_BYTES * self.0.len());
        self.encode_into(&mut out);
        out
    }

    /// Appends `encode_set(S)`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        // At most 64 rotations: the count fits a byte.
        out.push(u8::try_from(self.0.len()).unwrap_or(u8::MAX));
        for id in &self.0 {
            out.extend_from_slice(id.as_bytes());
        }
    }

    /// Reads exactly one rotation set filling `data`: a key name that is no
    /// self reference, with nothing after it.
    ///
    /// # Errors
    ///
    /// As [`KeyName::read`] with no self reference allowed, then `Malformed`
    /// for bytes after the set.
    pub fn decode(data: &[u8]) -> Result<Self, KeyClass> {
        match KeyName::read(data, false)? {
            (KeyName::Set(set), []) => Ok(set),
            _ => Err(ErrorClass::Malformed.into()),
        }
    }
}

/// The carrying event's own rotation, named by the envelope's `author` and
/// `seq`: `self_ref = 0x00 || author || u64be(seq)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SelfRef {
    /// The event's author, the device ID its envelope gives.
    pub author: DeviceId,
    /// The envelope's `seq`.
    pub seq: u64,
}

impl SelfRef {
    /// The self reference of an event of this author at this `seq`.
    pub fn new(author: DeviceId, seq: u64) -> Self {
        Self { author, seq }
    }

    /// Its 41 bytes.
    pub fn encode(&self) -> [u8; SELF_REFERENCE_BYTES] {
        let mut out = [0; SELF_REFERENCE_BYTES];
        out[1..33].copy_from_slice(&self.author.0);
        out[33..].copy_from_slice(&u64be(self.seq));
        out
    }
}

/// A key name: which state a wrap, link or delivery is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyName {
    /// A state of rotations that exist as events: `encode_set(S)`.
    Set(RotationSet),
    /// The carrying event's own rotation.
    SelfRef(SelfRef),
}

impl KeyName {
    /// The name's bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Set(set) => set.encode(),
            Self::SelfRef(own) => own.encode().to_vec(),
        }
    }

    /// The rotation set it names, unless it is a self reference.
    pub fn as_set(&self) -> Option<&RotationSet> {
        match self {
            Self::Set(set) => Some(set),
            Self::SelfRef(_) => None,
        }
    }

    /// Whether it is a self reference.
    pub fn is_self_ref(&self) -> bool {
        matches!(self, Self::SelfRef(_))
    }

    /// Reads one key name from the front of `data`, in keys.md's order
    /// (section 3.1, "A key name"), and returns it with the bytes after it.
    /// `allow_self` says whether the structure allows a self reference here.
    ///
    /// # Errors
    ///
    /// 1. `Malformed` for no byte.
    /// 2. `Malformed` for a first byte of 0 where no self reference is
    ///    allowed, or fewer than 41 bytes for one.
    /// 3. `TooManyRotations` for a count above 64.
    /// 4. `Malformed` for fewer than `1 + 32n` bytes, or IDs not strictly
    ///    ascending.
    pub fn read(data: &[u8], allow_self: bool) -> Result<(Self, &[u8]), KeyClass> {
        let malformed = || KeyClass::from(ErrorClass::Malformed);
        let (&n, rest) = data.split_first().ok_or_else(malformed)?;
        if n == 0 {
            if !allow_self || data.len() < SELF_REFERENCE_BYTES {
                return Err(malformed());
            }
            let (name, rest) = data.split_at(SELF_REFERENCE_BYTES);
            let author: [u8; 32] = name[1..33].try_into().map_err(|_| malformed())?;
            let seq: [u8; 8] = name[33..].try_into().map_err(|_| malformed())?;
            return Ok((
                Self::SelfRef(SelfRef::new(DeviceId(author), u64::from_be_bytes(seq))),
                rest,
            ));
        }
        let n = usize::from(n);
        if n > MAX_ROTATIONS {
            return Err(KeyClass::TooManyRotations);
        }
        if rest.len() < ID_BYTES * n {
            return Err(malformed());
        }
        let (ids, rest) = rest.split_at(ID_BYTES * n);
        let mut set = Vec::with_capacity(n);
        for chunk in ids.chunks_exact(ID_BYTES) {
            let id = EventId(chunk.try_into().map_err(|_| malformed())?);
            if set.last().is_some_and(|last| *last >= id) {
                return Err(malformed());
            }
            set.push(id);
        }
        Ok((Self::Set(RotationSet(set)), rest))
    }

    /// Reads exactly one key name filling `data`.
    ///
    /// # Errors
    ///
    /// As [`KeyName::read`], then `Malformed` for bytes after the name.
    pub fn decode(data: &[u8], allow_self: bool) -> Result<Self, KeyClass> {
        match Self::read(data, allow_self)? {
            (name, []) => Ok(name),
            _ => Err(ErrorClass::Malformed.into()),
        }
    }
}

impl From<RotationSet> for KeyName {
    fn from(set: RotationSet) -> Self {
        Self::Set(set)
    }
}

impl From<SelfRef> for KeyName {
    fn from(own: SelfRef) -> Self {
        Self::SelfRef(own)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> RotationId {
        EventId([byte; 32])
    }

    #[test]
    fn a_set_is_canonical() {
        let set = RotationSet::new([id(3), id(1), id(2), id(1)]).unwrap();
        assert_eq!(set.ids(), &[id(1), id(2), id(3)]);
        let bytes = set.encode();
        assert_eq!(bytes.len(), 97);
        assert_eq!(bytes[0], 3);
        assert_eq!(RotationSet::decode(&bytes), Ok(set));
        assert_eq!(
            RotationSet::new([]),
            Err(KeyClass::Shared(ErrorClass::Malformed))
        );
        assert_eq!(
            RotationSet::new((0..65).map(id)),
            Err(KeyClass::TooManyRotations)
        );
    }

    #[test]
    fn a_self_reference_reads_only_where_allowed() {
        let own = SelfRef::new(DeviceId([7; 32]), 9);
        let bytes = own.encode();
        assert_eq!(KeyName::decode(&bytes, true), Ok(KeyName::SelfRef(own)));
        assert_eq!(
            KeyName::decode(&bytes, false),
            Err(ErrorClass::Malformed.into())
        );
        let mut longer = bytes.to_vec();
        longer.push(1);
        let (name, rest) = KeyName::read(&longer, true).unwrap();
        assert_eq!((name, rest), (KeyName::SelfRef(own), &[1u8][..]));
    }
}
