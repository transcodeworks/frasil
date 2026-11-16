//! Kinds and limits (events.md, "Kinds" and "Limits").
//!
//! | Kind | Name | May start a log |
//! |---|---|---|
//! | 1 | device-list event | yes: a person's list |
//! | 2 | space event: a roster event or a key event | yes: a space |
//! | 3 | reserved | `Malformed` |
//! | 4 | unit | no |
//! | 5 | anchor | no |
//! | 6 | storage event | no |
//! | 7 to 63 | reserved; must be understood | |
//! | 64 to 127 | ignorable; protocol 1 defines none | no |
//!
//! Kind 0, kind 3 and kinds from 128 are `Malformed`. The schemes each kind
//! may carry are `frasil_crypto::schemes::KindPolicy`'s.

/// A device-list event (identity.md).
pub const DEVICE_LIST: u8 = 1;
/// A space event: a roster event or a key event (roster.md, keys.md).
pub const SPACE: u8 = 2;
/// Reserved and never assigned: `Malformed`.
pub const RESERVED: u8 = 3;
/// A unit (units.md).
pub const UNIT: u8 = 4;
/// An anchor (crypto.md, "Anchors and coverage").
pub const ANCHOR: u8 = 5;
/// A storage event (peers.md).
pub const STORAGE: u8 = 6;
/// The first ignorable kind.
pub const FIRST_IGNORABLE: u8 = 64;
/// The last ignorable kind; every kind above it is `Malformed`.
pub const LAST_IGNORABLE: u8 = 127;
/// The last kind that must be understood.
pub const LAST_MUST_UNDERSTAND: u8 = 63;

/// The largest signed event of any kind, in bytes.
pub const MAX_SIGNED_EVENT_BYTES: usize = 16_777_216;
/// The most parents an event may name, unless its kind sets fewer.
pub const MAX_PARENTS: usize = 256;
/// The most parents a device-list event may name.
pub const MAX_DEVICE_LIST_PARENTS: usize = 16;
/// The most refs one body may carry; it carries at least one, if any.
pub const MAX_REFS: usize = 64;

/// Whether a kind is valid at all: 1 to 127, and not 3.
pub fn is_valid(kind: u64) -> bool {
    (1..=u64::from(LAST_IGNORABLE)).contains(&kind) && kind != u64::from(RESERVED)
}

/// Whether a kind must be understood: 1 to 63.
pub fn must_understand(kind: u8) -> bool {
    (1..=LAST_MUST_UNDERSTAND).contains(&kind)
}

/// Whether a kind is ignorable: 64 to 127. A replica that does not know one
/// verifies its envelope, places it, counts it in its author's chain,
/// forwards it, and gives it no other effect.
pub fn is_ignorable(kind: u8) -> bool {
    (FIRST_IGNORABLE..=LAST_IGNORABLE).contains(&kind)
}

/// Whether this implementation knows a kind that must be understood:
/// protocol 1 defines 1, 2, 4, 5 and 6.
pub fn is_known(kind: u8) -> bool {
    matches!(kind, DEVICE_LIST | SPACE | UNIT | ANCHOR | STORAGE)
}

/// Whether an event of this kind may be a genesis, starting a log: a
/// device-list event or a space event.
pub fn may_start_log(kind: u8) -> bool {
    matches!(kind, DEVICE_LIST | SPACE)
}

/// A kind's limits (events.md, "Limits"): the largest signed event, in
/// bytes, and the most parents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest signed event, in bytes.
    pub bytes: usize,
    /// The most parents.
    pub parents: usize,
}

/// The limits of a valid kind. A kind's document may set lower limits.
pub fn limits(kind: u8) -> Limits {
    match kind {
        DEVICE_LIST => Limits {
            bytes: 16_384,
            parents: MAX_DEVICE_LIST_PARENTS,
        },
        SPACE | UNIT => Limits {
            bytes: 1_048_576,
            parents: MAX_PARENTS,
        },
        STORAGE => Limits {
            bytes: 262_144,
            parents: MAX_PARENTS,
        },
        ANCHOR | FIRST_IGNORABLE..=LAST_IGNORABLE => Limits {
            bytes: 16_384,
            parents: MAX_PARENTS,
        },
        _ => Limits {
            bytes: MAX_SIGNED_EVENT_BYTES,
            parents: MAX_PARENTS,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        for kind in [0, 3, 128, 255, u64::MAX] {
            assert!(!is_valid(kind), "{kind}");
        }
        for kind in [1, 2, 4, 5, 6, 7, 63, 64, 127] {
            assert!(is_valid(kind), "{kind}");
        }
        assert!(must_understand(7) && !is_known(7));
        assert!(is_ignorable(64) && is_ignorable(127) && !is_ignorable(63));
        assert!(may_start_log(1) && may_start_log(2) && !may_start_log(4));
        assert_eq!(limits(DEVICE_LIST).parents, 16);
        assert_eq!(limits(STORAGE).bytes, 262_144);
        assert_eq!(limits(100).bytes, 16_384);
    }
}
