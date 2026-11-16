//! The version policy (overview.md, "Version policy").
//!
//! This specification is protocol 1. Every format that carries a version
//! carries 1, and every label ends in `/v1`, except where the label registry
//! or the format's document says otherwise. A reader refuses a version,
//! suite or scheme it does not know as `UnsupportedVersion`, never guesses
//! and never rewrites; a stored record of an unknown version is kept.

use crate::errors::ErrorClass;

/// The protocol this implementation speaks.
pub const PROTOCOL: u64 = 1;

/// The version every versioned format of protocol 1 carries, unless its
/// document says otherwise.
pub const FORMAT_VERSION: u64 = 1;

/// The device-list event body's version (identity.md), the one exception
/// among protocol 1's formats.
pub const DEVICE_LIST_BODY_VERSION: u64 = 3;

/// The protocol's name in connection names, such as the iroh binding's
/// `frasil/p1/member` and the WebSocket subprotocol `frasil.p1`.
pub const PROTOCOL_NAME: &str = "p1";

/// The suffix of every label, except the few the label registry lists
/// otherwise.
pub const LABEL_SUFFIX: &str = "/v1";

/// The revision, protocol 1's version marker, fixed at 1. `Hello`,
/// `PeerHello` and `Offer` carry it, a store's head and a space file's
/// manifest record it, and each end accepts only its own.
pub const REVISION: u64 = 1;

/// Checks a format's version against the one this reader knows: a version
/// it does not know is `UnsupportedVersion`.
pub fn check_version(found: u64, known: u64) -> Result<(), ErrorClass> {
    if found == known {
        Ok(())
    } else {
        Err(ErrorClass::UnsupportedVersion)
    }
}

/// Checks the other end's revision: another revision is
/// `RevisionMismatch`.
pub fn check_revision(found: u64) -> Result<(), ErrorClass> {
    if found == REVISION {
        Ok(())
    } else {
        Err(ErrorClass::RevisionMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_revisions() {
        assert_eq!(check_version(1, FORMAT_VERSION), Ok(()));
        assert_eq!(
            check_version(2, FORMAT_VERSION),
            Err(ErrorClass::UnsupportedVersion)
        );
        assert_eq!(check_version(3, DEVICE_LIST_BODY_VERSION), Ok(()));
        assert_eq!(check_revision(1), Ok(()));
        assert_eq!(check_revision(2), Err(ErrorClass::RevisionMismatch));
        assert_eq!(format!("frasil/{PROTOCOL_NAME}/member"), "frasil/p1/member");
    }
}
