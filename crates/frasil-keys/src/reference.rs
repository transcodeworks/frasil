//! A unit's key reference (keys.md, "Key references in units" and "Reading
//! a unit's key reference").
//!
//! A unit names the state it is sealed under by its key reference,
//! `encode_set(S)`: the content state of its writer's view. A core
//! implementation never reads the restricted form of
//! ext-restricted-spaces.md.

use crate::KeyClass;
use crate::names::{RotationId, RotationSet};
use frasil_base::ErrorClass;

/// What a reader's copy of the space's log says of an ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lookup {
    /// The reader does not hold the event: it fetches it.
    Missing,
    /// The event is in the log and is not a rotation.
    NotARotation,
    /// The event is a rotation of the log, valid or void.
    Rotation,
}

/// The causal questions a key reference asks of the space's log, as the
/// reader holds it.
pub trait RotationLog {
    /// What the log says of this ID.
    fn lookup(&self, id: &RotationId) -> Lookup;

    /// Whether `earlier` is in the past of `later`.
    fn precedes(&self, earlier: &RotationId, later: &RotationId) -> bool;
}

/// Step 1: reads a key reference as one rotation set.
///
/// # Errors
///
/// [`RotationSet::decode`]'s: `Malformed` or `TooManyRotations`.
pub fn read_key_reference(data: &[u8]) -> Result<RotationSet, KeyClass> {
    RotationSet::decode(data)
}

/// Steps 2 and 3, against the space's log: every ID is a rotation of the
/// log, and no ID of the set is in the past of another. A reference may
/// name a void rotation.
///
/// # Errors
///
/// `NotARotation` when an ID names an event that is no rotation; else
/// `Pending` when the reader lacks an ID's event, and the unit waits as if
/// it had not arrived; then `Malformed` when one ID is in the past of
/// another.
pub fn check_key_reference(
    reference: &RotationSet,
    log: &impl RotationLog,
) -> Result<(), KeyClass> {
    let lookups: Vec<Lookup> = reference.ids().iter().map(|id| log.lookup(id)).collect();
    if lookups.contains(&Lookup::NotARotation) {
        return Err(KeyClass::NotARotation);
    }
    if lookups.contains(&Lookup::Missing) {
        return Err(ErrorClass::Pending.into());
    }
    let ids = reference.ids();
    for earlier in ids {
        if ids
            .iter()
            .any(|later| later != earlier && log.precedes(earlier, later))
        {
            return Err(ErrorClass::Malformed.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_events::EventId;

    /// Rotations 1 to 4, where 1 precedes 2; 5 is no rotation.
    struct Log;

    impl RotationLog for Log {
        fn lookup(&self, id: &RotationId) -> Lookup {
            match id.0[0] {
                1..=4 => Lookup::Rotation,
                5 => Lookup::NotARotation,
                _ => Lookup::Missing,
            }
        }

        fn precedes(&self, earlier: &RotationId, later: &RotationId) -> bool {
            earlier.0[0] == 1 && later.0[0] == 2
        }
    }

    fn set(bytes: &[u8]) -> RotationSet {
        RotationSet::new(bytes.iter().map(|&b| EventId([b; 32]))).unwrap()
    }

    #[test]
    fn a_reference_names_concurrent_rotations_of_the_log() {
        assert_eq!(check_key_reference(&set(&[2, 3]), &Log), Ok(()));
        assert_eq!(
            check_key_reference(&set(&[1, 2]), &Log),
            Err(ErrorClass::Malformed.into())
        );
        assert_eq!(
            check_key_reference(&set(&[3, 9]), &Log),
            Err(ErrorClass::Pending.into())
        );
        assert_eq!(
            check_key_reference(&set(&[5, 9]), &Log),
            Err(KeyClass::NotARotation)
        );
        assert_eq!(read_key_reference(&set(&[3, 4]).encode()), Ok(set(&[3, 4])));
    }
}
