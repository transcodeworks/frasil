//! Adapter types (units.md, section 2.7, "Adapter types").
//!
//! `type` names the adapter that gives a unit's content meaning. It is
//! sealed, so a peer never learns which application a space belongs to.
//! Types that begin `frasil:` are Frasil's; a third-party adapter chooses
//! one that does not, such as a reversed domain name.

use crate::limits::{MAX_TYPE_BYTES, MAX_TYPE_OCTET, MIN_TYPE_BYTES, MIN_TYPE_OCTET};

/// Device-list events, in the system stream (section 2.12).
pub const LIST: &str = "frasil:list";
/// Space events' body keys, in the system stream (section 2.12).
pub const BODY_KEYS: &str = "frasil:body-keys";
/// A recovery entry, in the system stream (section 2.12; identity.md).
pub const RECOVERY_ENTRY: &str = "frasil:recovery-entry";
/// The system stream's snapshot units (section 2.12).
pub const SYSTEM: &str = "frasil:system";
/// A move record, in a document stream (ext-restricted-spaces.md).
pub const MOVE: &str = "frasil:move";
/// The Loro adapter's content (adapter-loro.md).
pub const LORO: &str = "frasil:loro";
/// The Records adapter's content (adapter-records.md).
pub const RECORDS: &str = "frasil:records";
/// The Blobs adapter's content (adapter-blobs.md).
pub const BLOBS: &str = "frasil:blobs";

/// Frasil's types, in section 2.7's table's order.
pub const FRASIL_TYPES: [&str; 8] = [
    LIST,
    BODY_KEYS,
    RECOVERY_ENTRY,
    SYSTEM,
    MOVE,
    LORO,
    RECORDS,
    BLOBS,
];

/// The four types of the system stream.
pub const SYSTEM_TYPES: [&str; 4] = [LIST, BODY_KEYS, RECOVERY_ENTRY, SYSTEM];

/// Whether a text is an adapter type: 1 to 64 bytes, each `0x21` to `0x7e`.
pub fn is_valid(type_: &str) -> bool {
    (MIN_TYPE_BYTES..=MAX_TYPE_BYTES).contains(&type_.len())
        && type_
            .bytes()
            .all(|byte| (MIN_TYPE_OCTET..=MAX_TYPE_OCTET).contains(&byte))
}

/// Whether a type is one of the system stream's four.
pub fn is_system(type_: &str) -> bool {
    SYSTEM_TYPES.contains(&type_)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_are_printable_ascii_without_space() {
        assert!(is_valid("com.example.timesheet"));
        assert!(FRASIL_TYPES.iter().all(|t| is_valid(t)));
        assert!(!is_valid(""));
        assert!(!is_valid("my type"));
        assert!(!is_valid("é"));
        assert!(is_valid(&"a".repeat(64)));
        assert!(!is_valid(&"a".repeat(65)));
        assert!(is_system(LIST) && !is_system(MOVE));
        assert!(!is_system("frasil:stubs"));
    }
}
