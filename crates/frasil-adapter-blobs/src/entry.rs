//! Entries (adapter-blobs.md, section 2.1, "Content"): each names one object by
//! its locator, with the key reference of the state it is sealed under. A
//! **reference** names an object another space of the library stores, with
//! that space's ID and the object's key (keys 6 and 7).

use frasil_adapter::Locator;
use frasil_adapter_records::read;
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::ErrorClass;

/// The greatest plaintext length an entry may state: 2^40.
pub const MAX_SIZE: u64 = 1 << 40;
/// An entry's media type: 1 to 255 bytes of text.
pub const MEDIA_TYPE_BYTES: (usize, usize) = (1, 255);
/// An entry's name: 1 to 1,022 bytes of text.
pub const NAME_BYTES: (usize, usize) = (1, 1022);
/// The most rotations a state or key name holds (keys.md, section 2, "Formats",
/// limits).
pub const MAX_ROTATIONS: usize = 64;
/// A rotation's ID: an event ID.
const ID_BYTES: usize = 32;

/// An entry: one object, named by locator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry {
    /// Key 1: the object's locator.
    pub object: Locator,
    /// Key 2: the key reference of the state the object is sealed under, as
    /// its header names it.
    pub key: Vec<u8>,
    /// Key 3: the plaintext's length, 0 to 2^40.
    pub size: u64,
    /// Key 4: a media type, 1 to 255 bytes, if any.
    pub media_type: Option<String>,
    /// Key 5: a name, 1 to 1,022 bytes, if any.
    pub name: Option<String>,
    /// Keys 6 and 7: for a reference, the space that stores the object and
    /// the object's key.
    pub reference: Option<Reference>,
}

/// What makes an entry a reference (adapter-blobs.md, section 3.7,
/// "References").
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    /// Key 6: the ID of the space that stores the object.
    pub source: [u8; 32],
    /// Key 7: the object's key (units.md, section 2.8).
    pub object_key: [u8; 32],
}

impl core::fmt::Debug for Reference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reference")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// The entry as a deterministic CBOR map.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(1, Value::from(self.object));
        map.insert(2, Value::from(self.key.clone()));
        map.insert(3, Value::Unsigned(self.size));
        if let Some(media_type) = &self.media_type {
            map.insert(4, Value::from(media_type.as_str()));
        }
        if let Some(name) = &self.name {
            map.insert(5, Value::from(name.as_str()));
        }
        if let Some(reference) = &self.reference {
            map.insert(6, Value::from(reference.source));
            map.insert(7, Value::from(reference.object_key));
        }
        Value::Map(map)
    }

    /// Reads an entry: its keys, types and lengths, and its key reference,
    /// which reads in either form, for content already checked. Else
    /// `Malformed`.
    pub fn read(value: &Value) -> Result<Self, ErrorClass> {
        Self::read_in(value, None)
    }

    /// Reads an entry as its space's units are checked (adapter-blobs.md,
    /// section 3.1, "The checks", step 2): its key reference reads in
    /// `form`. Else `Malformed`.
    pub fn read_as(value: &Value, form: KeyForm) -> Result<Self, ErrorClass> {
        Self::read_in(value, Some(form))
    }

    fn read_in(value: &Value, form: Option<KeyForm>) -> Result<Self, ErrorClass> {
        let map = value.as_map()?;
        read::keys(map, &[1, 2, 3], &[1, 2, 3, 4, 5, 6, 7])?;
        let object = map[&1].as_byte_array::<64>()?;
        let key = map[&2].as_bytes()?;
        // Keys 6 and 7 come together.
        let reference = match (map.get(&6), map.get(&7)) {
            (None, None) => None,
            (Some(source), Some(object_key)) => Some(Reference {
                source: source.as_byte_array::<32>()?,
                object_key: object_key.as_byte_array::<32>()?,
            }),
            _ => return Err(ErrorClass::Malformed),
        };
        // A reference's key reference names a state of its source, in the
        // source's form.
        match form.filter(|_| reference.is_none()) {
            Some(form) => read_key_reference(key, form)?,
            None => read_key_reference(key, KeyForm::Plain)
                .or_else(|_| read_key_reference(key, KeyForm::Restricted))?,
        }
        let size = map[&3].as_unsigned()?;
        if size > MAX_SIZE {
            return Err(ErrorClass::Malformed);
        }
        let text = |key: u64, (min, max): (usize, usize)| {
            map.get(&key)
                .map(|value| read::text_of(value, min, max).map(str::to_owned))
                .transpose()
        };
        Ok(Self {
            object,
            key: key.to_vec(),
            size,
            media_type: text(4, MEDIA_TYPE_BYTES)?,
            name: text(5, NAME_BYTES)?,
            reference,
        })
    }

    /// Whether the entry is a reference: an object another space stores.
    pub fn is_reference(&self) -> bool {
        self.reference.is_some()
    }
}

/// The form of a space's key references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeyForm {
    /// One rotation set (keys.md, section 3.15, "Reading a unit's key
    /// reference", step 1).
    #[default]
    Plain,
    /// A restricted space's or a carve-out's: its own rotation set, then
    /// the sealed state of its parent (ext-restricted-spaces.md, "Reading
    /// a restricted key reference", steps 1 and 2).
    Restricted,
}

/// The rotations in a restricted key reference's sealed parent state: at
/// most 64.
const MAX_PARENT_ROTATIONS: usize = 64;
/// A restricted key reference's nonce and tag, after its own set and
/// around the parent's rotation IDs: 24 bytes of nonce, the parent set's
/// count byte, and 16 bytes of tag.
const SEALED_PARENT_OVERHEAD: usize = 41;

/// Reads a key reference in its space's form, with nothing after it.
/// Every failure is `Malformed`.
pub fn read_key_reference(bytes: &[u8], form: KeyForm) -> Result<(), ErrorClass> {
    match form {
        KeyForm::Plain => read_rotation_set(bytes),
        KeyForm::Restricted => {
            // Step 1: a rotation set S_F leads.
            let count = usize::from(*bytes.first().ok_or(ErrorClass::Malformed)?);
            let own = 1 + ID_BYTES * count;
            if bytes.len() < own {
                return Err(ErrorClass::Malformed);
            }
            read_rotation_set(&bytes[..own])?;
            // Step 2: the rest is 41 + 32b bytes, 1 <= b <= 64.
            let rest = bytes.len() - own;
            let parents = rest
                .checked_sub(SEALED_PARENT_OVERHEAD)
                .filter(|ids| ids % ID_BYTES == 0)
                .map(|ids| ids / ID_BYTES)
                .ok_or(ErrorClass::Malformed)?;
            if !(1..=MAX_PARENT_ROTATIONS).contains(&parents) {
                return Err(ErrorClass::Malformed);
            }
            Ok(())
        }
    }
}

/// keys.md, section 3.15, "Reading a unit's key reference", step 1: a unit's
/// key reference reads as one rotation set, read as a key name (section 3.1)
/// that is never a self reference, with nothing after it. A key name of more
/// than 64 rotations is `TooManyRotations` there; said of an entry's content,
/// every failure here is `Malformed`.
pub fn read_rotation_set(bytes: &[u8]) -> Result<(), ErrorClass> {
    // Step 1: at least 1 byte.
    let Some((&count, ids)) = bytes.split_first() else {
        return Err(ErrorClass::Malformed);
    };
    // Step 2: a self reference, first byte 0, is no rotation set.
    // Step 3: at most 64 rotations.
    let count = usize::from(count);
    if count == 0 || count > MAX_ROTATIONS {
        return Err(ErrorClass::Malformed);
    }
    // Step 4, and nothing after the set: exactly `1 + 32n` bytes, the IDs
    // strictly ascending.
    if ids.len() != ID_BYTES * count {
        return Err(ErrorClass::Malformed);
    }
    let ids: Vec<&[u8]> = ids.chunks(ID_BYTES).collect();
    read::strictly_ascending(&ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[u8]) -> Vec<u8> {
        let mut out = vec![u8::try_from(ids.len()).unwrap()];
        for id in ids {
            out.extend([*id; 32]);
        }
        out
    }

    #[test]
    fn a_key_reference_is_one_rotation_set() {
        assert!(read_rotation_set(&set(&[1])).is_ok());
        assert!(read_rotation_set(&set(&[1, 2])).is_ok());
        let most: Vec<u8> = (0..64).collect();
        assert!(read_rotation_set(&set(&most)).is_ok());
        let too_many: Vec<u8> = (0..65).collect();
        for bad in [
            vec![],
            [vec![0], vec![1; 40]].concat(),
            set(&too_many),
            set(&[2, 1]),
            set(&[1, 1]),
            [set(&[1]), vec![0]].concat(),
            set(&[1])[..32].to_vec(),
        ] {
            assert_eq!(read_rotation_set(&bad), Err(ErrorClass::Malformed));
        }
    }

    /// A restricted key reference: an own set, then a sealed parent set of
    /// `parents` rotations.
    fn restricted(own: &[u8], parents: usize) -> Vec<u8> {
        [
            set(own),
            vec![0; SEALED_PARENT_OVERHEAD + ID_BYTES * parents],
        ]
        .concat()
    }

    #[test]
    fn a_restricted_key_reference_carries_its_parents_state() {
        assert!(read_key_reference(&restricted(&[1], 1), KeyForm::Restricted).is_ok());
        assert!(read_key_reference(&restricted(&[1, 2], 64), KeyForm::Restricted).is_ok());
        for bad in [
            set(&[1]),
            restricted(&[1], 0),
            restricted(&[1], 65),
            restricted(&[2, 1], 1),
            [restricted(&[1], 1), vec![0]].concat(),
        ] {
            assert_eq!(
                read_key_reference(&bad, KeyForm::Restricted),
                Err(ErrorClass::Malformed)
            );
        }
        // Each space's units read their own form only.
        assert_eq!(
            read_key_reference(&restricted(&[1], 1), KeyForm::Plain),
            Err(ErrorClass::Malformed)
        );
        let entry = Entry {
            object: [7; 64],
            key: restricted(&[1], 2),
            size: 1,
            media_type: None,
            name: None,
            reference: None,
        };
        assert_eq!(
            Entry::read_as(&entry.to_value(), KeyForm::Restricted),
            Ok(entry.clone())
        );
        assert_eq!(
            Entry::read_as(&entry.to_value(), KeyForm::Plain),
            Err(ErrorClass::Malformed)
        );
        assert_eq!(Entry::read(&entry.to_value()), Ok(entry));
    }

    #[test]
    fn an_entry_round_trips_and_keeps_to_its_bounds() {
        let entry = Entry {
            object: [7; 64],
            key: set(&[1]),
            size: MAX_SIZE,
            media_type: Some("video/mp4".to_owned()),
            name: Some("n".repeat(1022)),
            reference: None,
        };
        assert_eq!(Entry::read(&entry.to_value()), Ok(entry.clone()));
        for bad in [
            Entry {
                size: MAX_SIZE + 1,
                ..entry.clone()
            },
            Entry {
                media_type: Some(String::new()),
                ..entry.clone()
            },
            Entry {
                name: Some("n".repeat(1023)),
                ..entry.clone()
            },
            Entry {
                key: set(&[2, 1]),
                ..entry.clone()
            },
        ] {
            assert_eq!(Entry::read(&bad.to_value()), Err(ErrorClass::Malformed));
        }
        let Value::Map(mut map) = entry.to_value() else {
            unreachable!()
        };
        map.insert(8, Value::Unsigned(0));
        assert_eq!(Entry::read(&Value::Map(map)), Err(ErrorClass::Malformed));
    }

    #[test]
    fn a_reference_carries_its_source_and_key_together() {
        let reference = Entry {
            object: [7; 64],
            key: set(&[1]),
            size: 3,
            media_type: None,
            name: None,
            reference: Some(Reference {
                source: [8; 32],
                object_key: [9; 32],
            }),
        };
        assert_eq!(Entry::read(&reference.to_value()), Ok(reference.clone()));
        assert!(reference.is_reference());
        // A reference's key reference is its source's, in the source's form.
        let restricted_source = Entry {
            key: restricted(&[1], 1),
            ..reference.clone()
        };
        assert_eq!(
            Entry::read_as(&restricted_source.to_value(), KeyForm::Plain),
            Ok(restricted_source)
        );
        let Value::Map(map) = reference.to_value() else {
            unreachable!()
        };
        for missing in [6, 7] {
            let mut half = map.clone();
            half.remove(&missing);
            assert_eq!(Entry::read(&Value::Map(half)), Err(ErrorClass::Malformed));
        }
        let mut short = map;
        short.insert(7, Value::from(&[9u8; 31][..]));
        assert_eq!(Entry::read(&Value::Map(short)), Err(ErrorClass::Malformed));
    }
}
