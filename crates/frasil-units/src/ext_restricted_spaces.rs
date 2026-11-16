//! Units of restricted spaces, and moved documents
//! (ext-restricted-spaces.md, sections 2.3, 2.4, 3.2 and 3.7, feature
//! `ext-restricted-spaces`).
//!
//! - **A restricted space's units** name their state by the restricted key
//!   reference, and seal under `k_F(S_F, S_P)`: [`RestrictedKeys`] reads the
//!   reference in place of keys.md's "Reading a unit's key reference"
//!   (section 3.2, steps 11 and 12 of units.md's "A unit, at a member").
//! - **The move record** ([`MoveRecord`]): the content of a move unit, of
//!   type `frasil:move`, in the document's original stream, and the value
//!   of the document's entry in the original space's index.
//! - **A moved stream**: one this replica holds an accepted move unit of,
//!   or a stream snapshot whose `moved` holds a record that reads
//!   ([`moved_by_snapshot`]).
//! - **Late writes**: units of the original stream, move units aside, in
//!   the past of no accepted move unit ([`late_writes`]); their author alone
//!   re-applies each in the new stream ([`reapplier`]), once, with
//!   `copied_from` (sealed key 4) naming it ([`reapplied`]).

use crate::UnitError;
use crate::body::KeyReference;
use crate::inner::{CopiedFrom, Inner};
use crate::stream::{self, Opening, StreamId};
use crate::types;
use crate::unit::{StateKey, UnitKeys};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_keys::ext_restricted_spaces::{
    RestrictedReference, check_restricted_states, restricted_key,
};
use frasil_keys::limits::MAX_NAME_BYTES;
use frasil_keys::reference::RotationLog;
use frasil_space::Keyring;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

fn malformed() -> UnitError {
    ErrorClass::Malformed.into()
}

// ---------------------------------------------------------------------------
// A restricted space's unit keys (section 3.2).

/// The keys a member of a restricted space F holds for its units: F's own
/// rotation secrets `f_R` over F's log, and P's content keys over P's log.
#[derive(Debug, Clone, Copy)]
pub struct RestrictedKeys<'a, L, M> {
    /// The parent P's space ID.
    pub parent: EventId,
    /// F's own secrets: each rotation's `f_R`, and merged states' `f(S)`
    /// received whole.
    pub own: &'a Keyring,
    /// F's log, as the reader holds it.
    pub own_log: &'a L,
    /// P's content keys.
    pub parent_keys: &'a Keyring,
    /// P's log, as the reader holds it.
    pub parent_log: &'a M,
}

/// The secret of a state from a keyring: derived from the rotation keys
/// held, or a merged state's received whole (provisional).
fn state_key(
    keyring: &Keyring,
    space: &EventId,
    state: &RotationSet,
) -> Option<(Zeroizing<[u8; 32]>, bool)> {
    let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
        .ids()
        .iter()
        .map(|id| keyring.rotations.get(id).map(|key| **key))
        .collect::<Option<Vec<_>>>()
        .map(Zeroizing::new);
    if let Some(inputs) = inputs {
        return state_secret(SecretKind::Content, space, state, &inputs)
            .ok()
            .map(|key| (key, false));
    }
    keyring.states.get(state).map(|key| (key.clone(), true))
}

impl<L: RotationLog, M: RotationLog> UnitKeys for RestrictedKeys<'_, L, M> {
    /// "Reading a restricted key reference" in place of keys.md's, then
    /// `k_F(S_F, S_P)`, provisional when either state's secret was received
    /// whole.
    ///
    /// ```text
    /// 1, 2. The reference's parts (a plain rotation set fails here). else Malformed / TooManyRotations
    /// 3.    The reader holds f(S_F).                                 else Sealed (held)
    /// 4, 5. P's state opens under parent_key.                        else Decrypt / Malformed
    /// 6, 7. Both states against their logs.                          else NotARotation / Pending / Malformed
    ///       The reader holds k_P(S_P).                               else Sealed (held)
    /// ```
    fn key(&self, space: &EventId, reference: &KeyReference) -> Result<StateKey, UnitError> {
        // 1, 2.
        let KeyReference::Restricted { own, nonce, sealed } = reference else {
            return Err(malformed());
        };
        let reference = RestrictedReference {
            own: own.clone(),
            nonce: *nonce,
            sealed: sealed.clone(),
        };
        // 3.
        let (own_secret, own_provisional) =
            state_key(self.own, space, own).ok_or(ErrorClass::Sealed)?;
        // 4, 5.
        let parent = reference.open(space, &own_secret)?;
        // 6, 7.
        check_restricted_states(own, &parent, self.own_log, self.parent_log)?;
        let (parent_key, parent_provisional) =
            state_key(self.parent_keys, &self.parent, &parent).ok_or(ErrorClass::Sealed)?;
        Ok(StateKey {
            key: restricted_key(space, &self.parent, &own_secret, &parent_key).key,
            provisional: own_provisional || parent_provisional,
        })
    }

    fn handed(&self, unit: &EventId) -> &[Zeroizing<[u8; 32]>] {
        self.own.bodies.get(unit).map_or(&[], Vec::as_slice)
    }
}

// ---------------------------------------------------------------------------
// The move record (sections 2.4 and 3.7).

/// The move record's version, key 1.
pub const MOVE_VERSION: u64 = 1;

/// A move record: where a document moved to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MoveRecord {
    /// Key 2: the space the document moved to.
    pub to_space: EventId,
    /// Key 3: its stream there, not all zero.
    pub to_stream: StreamId,
    /// Key 4: a cached name, 1 to 1,022 bytes of UTF-8.
    pub name: Option<String>,
}

impl MoveRecord {
    /// The record's deterministic CBOR map.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::from([
            (1, Value::Unsigned(MOVE_VERSION)),
            (2, Value::from(self.to_space.0)),
            (3, Value::from(self.to_stream.as_slice())),
        ]);
        if let Some(name) = &self.name {
            map.insert(4, Value::from(name.as_str()));
        }
        Value::Map(map).encode()
    }

    /// Reading a move record, whether in a move unit or a pointer, in
    /// order:
    ///
    /// ```text
    /// 1. It is a deterministic CBOR map, and key 1 is an unsigned integer.  else Malformed
    /// 2. Key 1 is 1.                                                        else UnsupportedVersion
    /// 3. Keys 1 to 4 only; keys 2 and 3 present; each as section 2.4.       else Malformed
    /// ```
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn read(data: &[u8]) -> Result<Self, UnitError> {
        // 1.
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map.get(&1).ok_or_else(malformed)?.as_unsigned()?;
        // 2.
        if version != MOVE_VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        // 3.
        if map.keys().any(|key| !(1..=4).contains(key)) {
            return Err(malformed());
        }
        let to_space = map.get(&2).ok_or_else(malformed)?.as_byte_array::<32>()?;
        let to_stream: StreamId = map.get(&3).ok_or_else(malformed)?.as_byte_array()?;
        if !stream::is_valid(&to_stream) {
            return Err(malformed());
        }
        let name = match map.get(&4) {
            None => None,
            Some(value) => {
                let name = value.as_text()?;
                if !(1..=MAX_NAME_BYTES).contains(&name.len()) {
                    return Err(malformed());
                }
                Some(name.to_owned())
            }
        };
        Ok(Self {
            to_space: EventId(to_space),
            to_stream,
            name,
        })
    }
}

/// A move unit's content check, after units.md's: for a unit of type
/// `frasil:move`, its move record, or the class it fails with, a content
/// refusal that leaves the unit valid and the stream not moved. `None` for
/// any other type.
pub fn move_unit(type_: &str, content: &[u8]) -> Option<Result<MoveRecord, UnitError>> {
    (type_ == types::MOVE).then(|| MoveRecord::read(content))
}

/// The record a stream snapshot's `moved` (key 6) holds, if it reads: such
/// a snapshot shows its stream as moved.
pub fn moved_by_snapshot(moved: Option<&[u8]>) -> Option<MoveRecord> {
    moved.and_then(|data| MoveRecord::read(data).ok())
}

// ---------------------------------------------------------------------------
// Late writes and their re-application (section 3.7).

/// The late writes of a moved stream, in the order given: each unit of the
/// original stream, a move unit aside, that is in the past of no accepted
/// move unit. `precedes(a, b)` says whether `a` is in the past of `b`. A
/// late write is valid in its space; adapters show it as written after the
/// move.
pub fn late_writes(
    units: &[EventId],
    moves: &BTreeSet<EventId>,
    precedes: impl Fn(&EventId, &EventId) -> bool,
) -> Vec<EventId> {
    if moves.is_empty() {
        return Vec::new();
    }
    units
        .iter()
        .filter(|u| !moves.contains(u) && !moves.iter().any(|m| precedes(u, m)))
        .copied()
        .collect()
}

/// Who re-applies a late write by `author`, given the devices that reach
/// the new space at `write`: the author, if it is one of them, and no other
/// device, so that the late write has one re-application at most.
pub fn reapplier(author: &DeviceId, writers: &[DeviceId]) -> Option<DeviceId> {
    writers.contains(author).then_some(*author)
}

/// The sealed part of a unit that re-applies a late write: the adapter's
/// `reapply` content, in the new stream, with `copied_from` naming the
/// original space and the late write. It is the re-applier's own unit; no
/// device re-signs another's.
pub fn reapplied(
    opening: Opening,
    content: Vec<u8>,
    original_space: EventId,
    late: EventId,
) -> Inner {
    let mut inner = Inner::new(opening.type_.clone(), content).with_opening(opening);
    inner.copied_from = Some(CopiedFrom {
        space: original_space,
        event: late,
    });
    inner
}

/// Whether the author does not re-apply `late`: it holds a unit of the new
/// stream whose `copied_from` names that late write.
pub fn reapplication_landed<'i>(
    new_stream_units: impl IntoIterator<Item = &'i Inner>,
    original_space: &EventId,
    late: &EventId,
) -> bool {
    new_stream_units.into_iter().any(|inner| {
        inner.copied_from
            == Some(CopiedFrom {
                space: *original_space,
                event: *late,
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips() {
        let record = MoveRecord {
            to_space: EventId([1; 32]),
            to_stream: [2; 16],
            name: Some("Budget".into()),
        };
        assert_eq!(MoveRecord::read(&record.encode()), Ok(record.clone()));
        assert_eq!(
            move_unit(types::MOVE, &record.encode()),
            Some(Ok(record.clone()))
        );
        assert_eq!(move_unit(types::LORO, &record.encode()), None);
        assert_eq!(moved_by_snapshot(Some(&record.encode())), Some(record));
        assert_eq!(moved_by_snapshot(Some(&[0xa0])), None);
    }

    #[test]
    fn a_unit_in_the_past_of_the_move_is_not_late() {
        let id = |b: u8| EventId([b; 32]);
        let moves = BTreeSet::from([id(9)]);
        let precedes = |a: &EventId, b: &EventId| a.0[0] < 3 && b.0[0] == 9;
        assert_eq!(
            late_writes(&[id(1), id(2), id(9), id(4)], &moves, precedes),
            vec![id(4)]
        );
        assert!(late_writes(&[id(1)], &BTreeSet::new(), precedes).is_empty());
    }

    #[test]
    fn only_the_author_reapplies() {
        let (a, b) = (DeviceId([1; 32]), DeviceId([2; 32]));
        assert_eq!(reapplier(&a, &[a, b]), Some(a));
        assert_eq!(reapplier(&a, &[b]), None);
    }
}
