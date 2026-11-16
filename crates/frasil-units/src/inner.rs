//! The sealed part (units.md, section 2.5, "The sealed part"), and section
//! 3.2, step 14, which reads it.
//!
//! `inner` is a deterministic CBOR map:
//!
//! | Key | Name | Value |
//! |---|---|---|
//! | 1 | `type` | text: the adapter type |
//! | 2 | `content` | bytes: the adapter's content, possibly empty |
//! | 3 | `resubmits` | bytes(32): the refused unit this one re-submits |
//! | 4 | `copied_from` | `[space ID, event ID]`: a late write this unit re-applies |
//! | 5 | `excluded` | 1 to 4,096 event IDs, strictly ascending; a snapshot unit only |
//! | 6 | `stream_opening` | `[type, salt (bytes(16))]`; every unit outside the system stream |
//! | 17 | `padding` | bytes, every byte zero |
//! | 18 | `refs` | 1 to 64 pairs `[log ID, event ID]`, strictly ascending |
//!
//! Keys 3 and 4 never appear together.

use crate::limits::MAX_EXCLUDED;
use crate::stream::{Opening, StreamId};
use crate::{UnitError, types};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_events::refs::{decode_refs, refs_value};
use frasil_events::{EventId, Ref};

const I_TYPE: u64 = 1;
const I_CONTENT: u64 = 2;
const I_RESUBMITS: u64 = 3;
const I_COPIED_FROM: u64 = 4;
const I_EXCLUDED: u64 = 5;
const I_OPENING: u64 = 6;
const I_PADDING: u64 = 17;
const I_REFS: u64 = 18;
const KEYS: [u64; 8] = [
    I_TYPE,
    I_CONTENT,
    I_RESUBMITS,
    I_COPIED_FROM,
    I_EXCLUDED,
    I_OPENING,
    I_PADDING,
    I_REFS,
];

/// A re-application's origin, sealed key 4 (ext-restricted-spaces.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CopiedFrom {
    /// The original space.
    pub space: EventId,
    /// The late write's event ID.
    pub event: EventId,
}

/// A unit's sealed part.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Inner {
    /// Key 1: the adapter type.
    pub type_: String,
    /// Key 2: the adapter's content.
    pub content: Vec<u8>,
    /// Key 3: the refused unit this unit re-submits.
    pub resubmits: Option<EventId>,
    /// Key 4: the late write this unit re-applies. A core implementation
    /// that lacks ext-restricted-spaces.md ignores it.
    pub copied_from: Option<CopiedFrom>,
    /// Key 5: the units of a snapshot unit's cover its state does not
    /// include, ascending; empty for none.
    pub excluded: Vec<EventId>,
    /// Key 6: the stream's opening, in every unit outside the system
    /// stream.
    pub opening: Option<Opening>,
    /// Key 17: how many zero bytes of padding; `Some(0)` for an empty
    /// padding, which is written, and `None` for none.
    pub padding: Option<usize>,
    /// Key 18: the unit's refs, ascending; empty for none.
    pub refs: Vec<Ref>,
}

impl Inner {
    /// A sealed part of this type and content, with no other key.
    pub fn new(type_: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            type_: type_.into(),
            content,
            resubmits: None,
            copied_from: None,
            excluded: Vec::new(),
            opening: None,
            padding: None,
            refs: Vec::new(),
        }
    }

    /// The same sealed part with this opening.
    pub fn with_opening(mut self, opening: Opening) -> Self {
        self.opening = Some(opening);
        self
    }

    /// The deterministic encoding. `excluded` and `refs` are written
    /// ascending, each once; empty ones are left out, and padding is
    /// written whenever it is present, even empty.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::from([
            (I_TYPE, Value::from(self.type_.as_str())),
            (I_CONTENT, Value::from(self.content.as_slice())),
        ]);
        if let Some(resubmits) = self.resubmits {
            map.insert(I_RESUBMITS, Value::from(resubmits.0));
        }
        if let Some(copied) = self.copied_from {
            map.insert(
                I_COPIED_FROM,
                Value::Array(vec![
                    Value::from(copied.space.0),
                    Value::from(copied.event.0),
                ]),
            );
        }
        if !self.excluded.is_empty() {
            let mut excluded = self.excluded.clone();
            excluded.sort_unstable();
            excluded.dedup();
            map.insert(
                I_EXCLUDED,
                Value::Array(excluded.into_iter().map(|id| Value::from(id.0)).collect()),
            );
        }
        if let Some(opening) = &self.opening {
            map.insert(I_OPENING, opening.to_value());
        }
        if let Some(padding) = self.padding {
            map.insert(I_PADDING, Value::from(vec![0; padding]));
        }
        if !self.refs.is_empty() {
            map.insert(I_REFS, refs_value(&self.refs));
        }
        Value::Map(map).encode()
    }

    /// Section 3.2, step 14: deterministic CBOR; keys among 1 to 6, 17 and
    /// 18; keys 1 and 2 present; key 1 an adapter type; key 3 32 bytes; key
    /// 4 two 32-byte strings; keys 3 and 4 not together; key 5 only in a
    /// snapshot unit, 1 to 4,096 IDs ascending; key 6 an adapter type and 16
    /// bytes; key 17 zeros; key 18 as section 2.5, at most 64 refs. When
    /// `system` is given, key 6 is present exactly outside the system
    /// stream.
    ///
    /// # Errors
    ///
    /// `Malformed`, or `TooLarge` for more than 64 refs.
    pub fn read(
        data: &[u8],
        snapshot_unit: bool,
        stream: &StreamId,
        system: Option<&StreamId>,
    ) -> Result<Self, UnitError> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        if map.keys().any(|key| !KEYS.contains(key)) {
            return Err(ErrorClass::Malformed.into());
        }
        let (Some(type_), Some(content)) = (map.get(&I_TYPE), map.get(&I_CONTENT)) else {
            return Err(ErrorClass::Malformed.into());
        };
        let type_ = type_.as_text()?;
        if !types::is_valid(type_) {
            return Err(ErrorClass::Malformed.into());
        }
        let content = content.as_bytes()?.to_vec();
        let resubmits = match map.get(&I_RESUBMITS) {
            Some(value) => Some(EventId(value.as_byte_array()?)),
            None => None,
        };
        let copied_from = match map.get(&I_COPIED_FROM) {
            Some(value) => {
                let [space, event] = value.as_array()? else {
                    return Err(ErrorClass::Malformed.into());
                };
                Some(CopiedFrom {
                    space: EventId(space.as_byte_array()?),
                    event: EventId(event.as_byte_array()?),
                })
            }
            None => None,
        };
        if resubmits.is_some() && copied_from.is_some() {
            return Err(ErrorClass::Malformed.into());
        }
        let excluded = match map.get(&I_EXCLUDED) {
            Some(value) if snapshot_unit => crate::ids::event_ids(value, 1, MAX_EXCLUDED)?,
            Some(_) => return Err(ErrorClass::Malformed.into()),
            None => Vec::new(),
        };
        let opening = map.get(&I_OPENING).map(Opening::read).transpose()?;
        let padding = match map.get(&I_PADDING) {
            Some(value) => {
                let bytes = value.as_bytes()?;
                if bytes.iter().any(|&byte| byte != 0) {
                    return Err(ErrorClass::Malformed.into());
                }
                Some(bytes.len())
            }
            None => None,
        };
        let refs = match map.get(&I_REFS) {
            Some(value) => decode_refs(value)?,
            None => Vec::new(),
        };
        if let Some(system) = system
            && opening.is_some() == (stream == system)
        {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(Self {
            type_: type_.to_owned(),
            content,
            resubmits,
            copied_from,
            excluded,
            opening,
            padding,
            refs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: StreamId = [1; 16];
    const SYSTEM: StreamId = [2; 16];

    #[test]
    fn a_sealed_part_round_trips() {
        let mut inner = Inner::new(types::LORO, b"x".to_vec())
            .with_opening(Opening::with_salt(types::LORO, [3; 16]));
        inner.resubmits = Some(EventId([4; 32]));
        inner.padding = Some(3);
        inner.refs = vec![Ref {
            log: EventId([5; 32]),
            id: EventId([6; 32]),
        }];
        let bytes = inner.encode();
        assert_eq!(
            Inner::read(&bytes, false, &STREAM, Some(&SYSTEM)),
            Ok(inner)
        );
        assert_eq!(
            Inner::read(&bytes, false, &SYSTEM, Some(&SYSTEM)),
            Err(ErrorClass::Malformed.into())
        );
    }

    /// An empty padding is accepted (units.md, 2.5 The sealed part: "bytes,
    /// every byte zero"), and kept apart from no padding, so each sealed
    /// part has one encoding.
    #[test]
    fn an_empty_padding_round_trips() {
        // {1: "+", 2: h'f9', 17: h''}
        let bytes = [0xa3, 0x01, 0x61, 0x2b, 0x02, 0x41, 0xf9, 0x11, 0x40];
        let inner = Inner::read(&bytes, false, &STREAM, None).unwrap();
        assert_eq!(inner.padding, Some(0));
        assert_eq!(inner.encode(), bytes);

        let none = Inner::new(types::LORO, Vec::new());
        let bytes = none.encode();
        assert_eq!(Inner::read(&bytes, false, &STREAM, None), Ok(none));
        let mut empty = Inner::new(types::LORO, Vec::new());
        empty.padding = Some(0);
        assert_ne!(empty.encode(), bytes);
    }

    #[test]
    fn excluded_belongs_to_snapshot_units() {
        let mut inner = Inner::new(types::RECORDS, Vec::new());
        inner.excluded = vec![EventId([1; 32])];
        let bytes = inner.encode();
        assert!(Inner::read(&bytes, true, &STREAM, None).is_ok());
        assert_eq!(
            Inner::read(&bytes, false, &STREAM, None),
            Err(ErrorClass::Malformed.into())
        );
    }

    #[test]
    fn more_than_64_refs_are_too_large() {
        let mut inner = Inner::new(types::RECORDS, Vec::new());
        inner.refs = (0..65u8)
            .map(|i| Ref {
                log: EventId([i; 32]),
                id: EventId([i; 32]),
            })
            .collect();
        assert_eq!(
            Inner::read(&inner.encode(), false, &STREAM, None),
            Err(ErrorClass::TooLarge.into())
        );
    }
}
