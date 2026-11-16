//! `state` keys 3 and 4 and a memory-only log (ext-guests.md, "The writer's
//! decision" and "Nothing at rest"; at-rest.md, "A memory-only log";
//! feature `ext-guests`).
//!
//! - **The last completed sync.** A space whose policy sets
//!   `online_freshness` reads `last_sync`, the device's reading when it last
//!   completed a sync with an always-on peer of the space, kept as key 3 of
//!   the log's `state` record. A core implementation never writes key 3.
//! - **Left.** Before it sends a leave request, the device keeps the grants
//!   the request names as key 4, so that it seals nothing more in the
//!   space after a restart either (`Left`).
//! - **Nothing at rest.** A client whose grant carries
//!   `frasil.nothing-at-rest` keeps the space's log in memory only: its
//!   keys, events, objects, snapshot and outbox, and no `log` record or tip
//!   in the head. It keeps at rest only what belongs to no space. After a
//!   restart it treats the log as restored before it signs there.

use crate::tables::{LogState, Table, TableValue};
use frasil_base::time::Reading;

/// The `state` record after a completed sync at `at`: the log's base, as
/// held, with key 3 set.
pub fn with_last_sync(held: Option<&LogState>, at: Reading) -> TableValue {
    let mut state = held.cloned().unwrap_or_default();
    state.last_sync = Some(at);
    TableValue::State(state)
}

/// The `state` record once this device has sent a leave request naming
/// `grants`: the log's base and last sync, as held, with key 4 set.
pub fn with_left(held: Option<&LogState>, grants: Vec<[u8; 32]>) -> TableValue {
    let mut state = held.cloned().unwrap_or_default();
    state.left = Some(grants);
    TableValue::State(state)
}

/// The last completed sync a `state` record keeps, if any.
pub fn last_sync(value: &TableValue) -> Option<Reading> {
    match value {
        TableValue::State(state) => state.last_sync,
        _ => None,
    }
}

/// Whether a memory-only log keeps records of this table out of the store:
/// its `log` record and every log table. The device's head, timeline and
/// ephemeral epoch belong to no space, and the head is committed with no
/// tip of the log.
pub fn memory_only(table: Table) -> bool {
    !matches!(table, Table::Head | Table::Timeline | Table::Epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_3_reads_back() {
        let at = Reading {
            timeline: 7,
            wall: Some(1_760_000_000),
            run: 2,
        };
        let value = with_last_sync(None, at);
        assert_eq!(last_sync(&value), Some(at));
        let bytes = value.encode();
        let read = TableValue::read(Table::State, &[], &bytes, Some(&[1; 32])).unwrap();
        assert_eq!(read, value);
        assert!(memory_only(Table::State));
        assert!(!memory_only(Table::Timeline));
    }
}
