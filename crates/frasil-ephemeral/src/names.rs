//! Frasil's names (ext-ephemeral.md, "Frasil's names").
//!
//! Names that begin `frasil/` are Frasil's, and an application MUST NOT send
//! them. Each has one kind, carries no `stream` and no `adapter`, and has
//! the targets and data of [`RESERVED`]. What a record does is its own
//! document's; the frame's verdict is decided by [`check_reserved`].

use crate::inner::{Inner, Kind};
use crate::limits::{MAX_LIST_EVENTS, RECEIVER_NONCE_BYTES};
use crate::{EphemeralClass, malformed};
use frasil_base::cbor::{self, Value};

/// The prefix of Frasil's names.
pub const RESERVED_PREFIX: &str = "frasil/";

/// `frasil/nonce`: the sender's receiver nonce, an ephemeral slot.
pub const NONCE: &str = "frasil/nonce";
/// `frasil/endpoint`: the sender's member ticket, an ephemeral slot.
pub const ENDPOINT: &str = "frasil/endpoint";
/// `frasil/heads`: the sender's signed head statement, an ephemeral slot.
pub const HEADS: &str = "frasil/heads";
/// `frasil/leave`: broadcast when the sender closes the space.
pub const LEAVE: &str = "frasil/leave";
/// `frasil/access-request`: a signed access request, targeted.
pub const ACCESS_REQUEST: &str = "frasil/access-request";
/// `frasil/leave-request`: a signed leave request (ext-guests.md), targeted.
pub const LEAVE_REQUEST: &str = "frasil/leave-request";
/// `frasil/list-events`: a reader's signed list events, targeted.
pub const LIST_EVENTS: &str = "frasil/list-events";

/// An extension a receiver may implement, which a reserved name needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extension {
    /// ext-guests.md, which defines `frasil/leave-request`.
    Guests,
}

/// What a reserved name's data must be, as far as the frame's verdict goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRule {
    /// A receiver nonce: 16 bytes.
    ReceiverNonce,
    /// Empty.
    Empty,
    /// `{1: space ID, 2: array of 1 to 16 signed device-list events}`,
    /// whose space ID is the frame's.
    ListEvents,
    /// A record its own document checks: a member ticket, a head statement,
    /// an access request or a leave request.
    Record,
}

/// One row of the table of Frasil's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedName {
    /// The name.
    pub name: &'static str,
    /// Its kind.
    pub kind: Kind,
    /// Whether targets are required (`true`) or there are none (`false`).
    pub targeted: bool,
    /// Its data.
    pub data: DataRule,
    /// The extension that defines it, if not this document.
    pub extension: Option<Extension>,
}

/// The table of Frasil's names, in the document's order.
pub const RESERVED: [ReservedName; 7] = [
    ReservedName {
        name: NONCE,
        kind: Kind::Slot,
        targeted: false,
        data: DataRule::ReceiverNonce,
        extension: None,
    },
    ReservedName {
        name: ENDPOINT,
        kind: Kind::Slot,
        targeted: false,
        data: DataRule::Record,
        extension: None,
    },
    ReservedName {
        name: HEADS,
        kind: Kind::Slot,
        targeted: false,
        data: DataRule::Record,
        extension: None,
    },
    ReservedName {
        name: LEAVE,
        kind: Kind::Message,
        targeted: false,
        data: DataRule::Empty,
        extension: None,
    },
    ReservedName {
        name: ACCESS_REQUEST,
        kind: Kind::Message,
        targeted: true,
        data: DataRule::Record,
        extension: None,
    },
    ReservedName {
        name: LEAVE_REQUEST,
        kind: Kind::Message,
        targeted: true,
        data: DataRule::Record,
        extension: Some(Extension::Guests),
    },
    ReservedName {
        name: LIST_EVENTS,
        kind: Kind::Message,
        targeted: true,
        data: DataRule::ListEvents,
        extension: None,
    },
];

/// The row of a reserved name, if the table has it.
pub fn reserved(name: &str) -> Option<&'static ReservedName> {
    RESERVED.iter().find(|row| row.name == name)
}

/// Whether a name is Frasil's: it begins `frasil/`.
pub fn is_reserved(name: &str) -> bool {
    name.starts_with(RESERVED_PREFIX)
}

/// "Receiving", step 11: a name that begins `frasil/` is one of the table's
/// that this receiver implements, with its kind, targets, stream, adapter
/// and data as the table says. An application's name passes.
///
/// # Errors
///
/// `UnknownName` for a `frasil/` name the table lacks, or one whose
/// extension `implements` refuses; `Malformed` for a frame the table's row
/// refuses.
pub fn check_reserved(
    inner: &Inner,
    space: &[u8; 32],
    implements: impl Fn(Extension) -> bool,
) -> Result<(), EphemeralClass> {
    if !is_reserved(&inner.name) {
        return Ok(());
    }
    let row = reserved(&inner.name).ok_or(EphemeralClass::UnknownName)?;
    if row
        .extension
        .is_some_and(|extension| !implements(extension))
    {
        return Err(EphemeralClass::UnknownName);
    }
    if inner.kind != row.kind
        || inner.stream.is_some()
        || inner.adapter.is_some()
        || inner.targets.is_some() != row.targeted
    {
        return Err(malformed());
    }
    let ok = match row.data {
        DataRule::ReceiverNonce => inner.data.len() == RECEIVER_NONCE_BYTES,
        DataRule::Empty => inner.data.is_empty(),
        DataRule::ListEvents => list_events_ok(&inner.data, space),
        DataRule::Record => true,
    };
    if ok { Ok(()) } else { Err(malformed()) }
}

/// Whether `data` is the body of units.md's `frasil/list-events`: exactly
/// `{1: space ID, 2: array of 1 to 16 byte strings}`, its space ID `space`.
pub fn list_events_ok(data: &[u8], space: &[u8; 32]) -> bool {
    let Ok(Value::Map(body)) = cbor::decode(data) else {
        return false;
    };
    body.len() == 2
        && body.get(&1).and_then(|v| v.as_bytes().ok()) == Some(&space[..])
        && matches!(body.get(&2), Some(Value::Array(events))
            if (1..=MAX_LIST_EVENTS).contains(&events.len())
                && events.iter().all(|e| matches!(e, Value::Bytes(_))))
}
