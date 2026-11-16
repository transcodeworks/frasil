//! The `invite` and `claim` records (ext-invite-links.md, "Records at
//! rest", feature `ext-invite-links`).
//!
//! Two log tables, item the invite entry, value `space ID (32) || invite
//! entry (32) || secret (32)`:
//!
//! - `0x18`, `invite`: kept by the inviting device from the commit of the
//!   invite entry until it holds a valid removal of `[3, K]` and its drops
//!   are deleted or expired;
//! - `0x19`, `claim`: kept by the claimant from the commit of its successor
//!   for as long as it holds the space's log, so that it opens wraps for
//!   the invite key ("Keys", receipt).
//!
//! The secret, the event and the record go in one commit, so a device never
//! signs a second successor for one invite key: it finds an earlier one by
//! its `claim` record, or after a restore by syncing its tips before it
//! signs. A core implementation never writes these tables.

use crate::tables::{InviteRecord, Secret, Table, TableValue};

/// The `invite` record of an invite this device made.
pub fn invite_record(space: [u8; 32], invite_entry: [u8; 32], secret: [u8; 32]) -> TableValue {
    TableValue::Invite(InviteRecord {
        space,
        invite_entry,
        secret: Secret::new(secret),
    })
}

/// The `claim` record of a link this device claimed.
pub fn claim_record(space: [u8; 32], invite_entry: [u8; 32], secret: [u8; 32]) -> TableValue {
    TableValue::Claim(InviteRecord {
        space,
        invite_entry,
        secret: Secret::new(secret),
    })
}

/// The tables this extension writes.
pub const TABLES: [Table; 2] = [Table::Invite, Table::Claim];

/// Whether the inviting device keeps its `invite` record: until it holds a
/// valid removal of the invite key and its drops are deleted or expired.
pub fn keeps_invite(removed: bool, drops_gone: bool) -> bool {
    !(removed && drops_gone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_read_back() {
        for value in [
            invite_record([1; 32], [2; 32], [3; 32]),
            claim_record([1; 32], [2; 32], [3; 32]),
        ] {
            let table = value.table();
            assert!(TABLES.contains(&table));
            let bytes = value.encode();
            assert_eq!(&bytes[..32], &[1; 32]);
            assert_eq!(
                TableValue::read(table, &[2; 32], &bytes, Some(&[1; 32])),
                Ok(value)
            );
        }
        assert!(keeps_invite(true, false));
        assert!(!keeps_invite(true, true));
    }
}
