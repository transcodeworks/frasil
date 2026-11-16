//! Unit content (adapter-loro.md, section 2.2, "Unit content"), and step 1
//! of section 3.2, "The checks".
//!
//! A log unit's content is a deterministic CBOR map:
//!
//! | Key | Name | Value | Roles |
//! |---|---|---|---|
//! | 1 | `version` | 1 | all |
//! | 2 | `role` | 0 edit, 1 suggestion, 2 accept, 3 dismiss | all |
//! | 3 | `incarnation` | unsigned, at least 1 | 0 and 1 |
//! | 4 | `blob` | bytes: Loro's export of exactly the writer's operations this unit adds | 0 and 1 |
//! | 5 | `targets` | array of 1 to 64 event IDs, strictly ascending | 2 and 3 |
//!
//! A map holds exactly the keys of its role. A snapshot unit's content is
//! empty.

use frasil_adapter::EventId;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::errors::ErrorClass;

/// The content version this adapter reads and writes (key 1).
pub const VERSION: u64 = 1;

/// The most event IDs `targets` names.
pub const MAX_TARGETS: usize = 64;

/// The role of a log unit's content (key 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContentRole {
    /// 0: an edit of the main document.
    Edit,
    /// 1: a suggestion, kept in the suggestion layer.
    Suggestion,
    /// 2: an accept of suggestions.
    Accept,
    /// 3: a dismiss of suggestions.
    Dismiss,
}

impl ContentRole {
    /// The role of a code, or `None` for a code other than 0 to 3.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Edit),
            1 => Some(Self::Suggestion),
            2 => Some(Self::Accept),
            3 => Some(Self::Dismiss),
            _ => None,
        }
    }

    /// The role's code.
    pub fn code(self) -> u64 {
        match self {
            Self::Edit => 0,
            Self::Suggestion => 1,
            Self::Accept => 2,
            Self::Dismiss => 3,
        }
    }

    /// Whether the role carries Loro's bytes: an edit or a suggestion.
    pub fn writes(self) -> bool {
        matches!(self, Self::Edit | Self::Suggestion)
    }
}

/// A log unit's content, as section 2.2 frames it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Content {
    /// Role 0 or 1: Loro's bytes for the writer's new operations, under an
    /// incarnation.
    Ops {
        /// [`ContentRole::Edit`] or [`ContentRole::Suggestion`].
        role: ContentRole,
        /// Key 3: the incarnation, at least 1.
        incarnation: u64,
        /// Key 4: `LoroDoc::export(ExportMode::UpdatesInRange { spans })`.
        blob: Vec<u8>,
    },
    /// Role 2 or 3: the suggestions accepted or dismissed.
    Targets {
        /// [`ContentRole::Accept`] or [`ContentRole::Dismiss`].
        role: ContentRole,
        /// Key 5: 1 to 64 event IDs, strictly ascending.
        targets: Vec<EventId>,
    },
}

impl Content {
    /// An edit (role 0).
    pub fn edit(incarnation: u64, blob: Vec<u8>) -> Self {
        Self::Ops {
            role: ContentRole::Edit,
            incarnation,
            blob,
        }
    }

    /// A suggestion (role 1), whose incarnation is its own `seq`.
    pub fn suggestion(seq: u64, blob: Vec<u8>) -> Self {
        Self::Ops {
            role: ContentRole::Suggestion,
            incarnation: seq,
            blob,
        }
    }

    /// An accept (role 2) of these suggestions, which it sorts.
    pub fn accept(targets: impl IntoIterator<Item = EventId>) -> Self {
        Self::targets(ContentRole::Accept, targets)
    }

    /// A dismiss (role 3) of these suggestions, which it sorts.
    pub fn dismiss(targets: impl IntoIterator<Item = EventId>) -> Self {
        Self::targets(ContentRole::Dismiss, targets)
    }

    fn targets(role: ContentRole, targets: impl IntoIterator<Item = EventId>) -> Self {
        let mut targets: Vec<EventId> = targets.into_iter().collect();
        targets.sort();
        targets.dedup();
        Self::Targets { role, targets }
    }

    /// The content's role.
    pub fn role(&self) -> ContentRole {
        match self {
            Self::Ops { role, .. } | Self::Targets { role, .. } => *role,
        }
    }

    /// The content's one deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.role().code()));
        match self {
            Self::Ops {
                incarnation, blob, ..
            } => {
                map.insert(3, Value::Unsigned(*incarnation));
                map.insert(4, Value::from(blob.clone()));
            }
            Self::Targets { targets, .. } => {
                let ids = targets.iter().map(|id| Value::from(*id)).collect();
                map.insert(5, Value::Array(ids));
            }
        }
        Value::Map(map).encode()
    }

    /// Reads a log unit's content: section 3.2, step 1.
    ///
    /// ```text
    /// 1. The content is deterministic CBOR, a map with an
    ///    unsigned key 1.                                   else Malformed
    ///    Key 1 is 1.                                       else UnknownContentVersion
    ///    The keys of its role, as section 2.2.             else Malformed
    /// ```
    pub fn read(content: &[u8]) -> Result<Self, ErrorClass> {
        let Value::Map(map) = cbor::decode(content)? else {
            return Err(ErrorClass::Malformed);
        };
        match map.get(&1) {
            Some(Value::Unsigned(VERSION)) => {}
            Some(Value::Unsigned(_)) => return Err(ErrorClass::UnknownContentVersion),
            _ => return Err(ErrorClass::Malformed),
        }
        let role = map
            .get(&2)
            .ok_or(ErrorClass::Malformed)?
            .as_unsigned()
            .ok()
            .and_then(ContentRole::from_code)
            .ok_or(ErrorClass::Malformed)?;
        let keys: Vec<u64> = map.keys().copied().collect();
        if role.writes() {
            if keys != [1, 2, 3, 4] {
                return Err(ErrorClass::Malformed);
            }
            let incarnation = map[&3].as_unsigned()?;
            if incarnation < 1 {
                return Err(ErrorClass::Malformed);
            }
            let blob = map[&4].as_bytes()?.to_vec();
            Ok(Self::Ops {
                role,
                incarnation,
                blob,
            })
        } else {
            if keys != [1, 2, 5] {
                return Err(ErrorClass::Malformed);
            }
            let items = map[&5].as_array()?;
            if !(1..=MAX_TARGETS).contains(&items.len()) {
                return Err(ErrorClass::Malformed);
            }
            let targets = items
                .iter()
                .map(|item| Ok(item.as_byte_array::<32>()?))
                .collect::<Result<Vec<EventId>, ErrorClass>>()?;
            if !targets.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(ErrorClass::Malformed);
            }
            Ok(Self::Targets { role, targets })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_role_round_trips() {
        for content in [
            Content::edit(3, b"ops".to_vec()),
            Content::suggestion(9, Vec::new()),
            Content::accept([[2; 32], [1; 32]]),
            Content::dismiss([[1; 32]]),
        ] {
            assert_eq!(Content::read(&content.encode()), Ok(content));
        }
        assert_eq!(
            Content::accept([[2; 32], [1; 32], [2; 32]]),
            Content::Targets {
                role: ContentRole::Accept,
                targets: vec![[1; 32], [2; 32]]
            }
        );
    }

    #[test]
    fn refuses_other_shapes() {
        let ids = |n: u8| Value::Array((0..n).map(|b| Value::from([b; 32])).collect());
        let map = |entries: Vec<(u64, Value)>| Value::Map(entries.into_iter().collect()).encode();
        for bad in [
            map(vec![(1, Value::Unsigned(1)), (2, Value::Unsigned(2))]),
            map(vec![
                (1, Value::Unsigned(1)),
                (2, Value::Unsigned(2)),
                (5, ids(0)),
            ]),
            map(vec![
                (1, Value::Unsigned(1)),
                (2, Value::Unsigned(3)),
                (5, ids(65)),
            ]),
            map(vec![
                (1, Value::Unsigned(1)),
                (2, Value::Unsigned(3)),
                (
                    5,
                    Value::Array(vec![Value::from([2; 32]), Value::from([1; 32])]),
                ),
            ]),
            map(vec![
                (1, Value::Unsigned(1)),
                (2, Value::Unsigned(0)),
                (3, Value::Unsigned(1)),
                (4, Value::from("text")),
            ]),
            map(vec![(1, Value::from("1"))]),
            map(vec![(2, Value::Unsigned(0))]),
            Value::Array(vec![]).encode(),
            Vec::new(),
        ] {
            assert_eq!(
                Content::read(&bad),
                Err(ErrorClass::Malformed),
                "{bad:02x?}"
            );
        }
        assert_eq!(
            Content::read(&map(vec![(1, Value::Unsigned(7))])),
            Err(ErrorClass::UnknownContentVersion)
        );
        let many: Vec<EventId> = (0..64).map(|b| [b; 32]).collect();
        assert!(Content::read(&Content::accept(many).encode()).is_ok());
    }
}
