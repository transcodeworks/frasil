//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's units: streams, objects, compaction, snapshots and sync messages.
//!
//! Specified by `docs/spec/units.md`. Its vectors are
//! `docs/spec/vectors/units.json`.
//!
//! The formats:
//! - [`limits`]: section 2.1's limits, and the sizes the formats use;
//! - [`types`]: adapter types, Frasil's own and the system stream's
//!   (section 2.7);
//! - [`stream`]: stream IDs, openings, the stream check and the content
//!   check before an adapter (sections 2.6 and 3.2, step 16);
//! - [`body`]: the visible body, stubs, covers and the compaction
//!   declaration, and the checks a peer runs (sections 2.3, 2.9, 2.10 and
//!   3.1);
//! - [`seal`]: the seal (section 2.4);
//! - [`inner`]: the sealed part (section 2.5, and section 3.2, step 14);
//! - [`unit`]: units as a peer and as a member check them, and writing one
//!   (sections 2.2, 3.1 and 3.2);
//! - [`own`]: Frasil's own units and a read-only person's list events
//!   (sections 2.12 and 3.11);
//! - [`objects`]: objects (sections 2.8 and 3.3);
//! - [`record`]: a checkpoint's record object, sealed under the
//!   checkpoint's own state and named by its self reference, its binding by
//!   size and digest, and reading it (roster.md, "The record object");
//! - [`snapshot`]: stream snapshots and the space snapshot (sections 2.9,
//!   2.11 and 3.10);
//! - [`statement`]: head statements (sections 2.13 and 3.13);
//! - [`messages`]: the sync messages (sections 2.14 and 3.14).
//!
//! The procedures:
//! - [`compaction`]: covers, the cover and boundary stubs from a log, and
//!   stubs checked against the events they stand for (sections 3.5 and
//!   3.9);
//! - [`late`]: where a unit stands against the checkpoint in effect, late
//!   units and what their writer re-submits (roster.md, 3.15.1 and 3.15.7);
//! - [`release`]: whether a stream is released at a replica, across
//!   checkpoints, and which releases and restores of a checkpoint's past a
//!   replica that forgets keeps (section 3.12);
//! - [`decisions`]: settling a snapshot, confirming a stub, whom a missing
//!   head is reported against, and a partial replica's verdict on a unit
//!   (sections 3.6, 3.9, 3.13 and 3.15);
//! - [`runtime`]: the replica side of the adapter interface: one stream's
//!   rebuild set and the adapter's state (sections 3.6, 3.8 and 3.17);
//! - [`frozen`]: a kept unit of a forgotten past, read from its frozen
//!   verdict and capabilities ("The past of a kept checkpoint").
//!
//! With feature `ext-restricted-spaces`, `ext_restricted_spaces` holds
//! ext-restricted-spaces.md's parts of units: a restricted space's unit
//! keys, the move record and moved streams, late writes and their
//! re-application.
//!
//! The crate reads no clock, does no IO and draws no randomness: every
//! nonce and salt comes in as an argument (the `_with` forms), so the
//! vectors can drive them.

pub mod body;
pub mod compaction;
pub mod decisions;
#[cfg(feature = "ext-guests")]
pub mod ext_guests;
#[cfg(feature = "ext-restricted-spaces")]
pub mod ext_restricted_spaces;
pub mod frozen;
mod ids;
pub mod inner;
pub mod late;
pub mod limits;
pub mod messages;
pub mod objects;
pub mod own;
pub mod record;
pub mod record_reader;
pub use record_reader::{RecordObjectOutcome, RecordObjectReader};
pub mod release;
pub mod runtime;
pub mod seal;
pub mod snapshot;
pub mod statement;
pub mod stream;
pub mod types;
pub mod unit;

pub use body::{Body, Compacts, Cover, KeyReference, Stub};
pub use inner::Inner;
pub use stream::{Opening, StreamId};
pub use unit::{InWorld, StateKey, Unit, UnitKeys, UnitReader};

use frasil_base::errors::{Class, ErrorClass, Sort};
use frasil_events::EventClass;
use frasil_keys::KeyClass;
use frasil_space::RosterClass;

frasil_base::error_classes! {
    /// units.md's own classes (section 3.18, "Error classes"), with every
    /// shared class. `UnknownMessage`, `UnknownAdapter`,
    /// `UnknownContentVersion`, `CapabilityRefused` and `BadCompaction` are
    /// shared.
    pub enum UnitClass {
        /// An object's bytes or plaintext are not the ones its locator
        /// names. Final, for those bytes.
        ObjectMismatch = "object_mismatch", Final;
        /// A space snapshot or head statement of another space.
        WrongSpace = "wrong_space", Final;
        /// A unit's opening does not hash to its stream.
        StreamMismatch = "stream_mismatch", ContentRefused;
        /// A unit of another type than its stream's opening.
        WrongAdapter = "wrong_adapter", ContentRefused;
        /// A system type outside the system stream, or another type inside
        /// it.
        WrongStream = "wrong_stream", ContentRefused;
        /// Content names an object its unit does not list.
        ObjectNotListed = "object_not_listed", ContentRefused;
        /// A stub that does not match its event; reported against the
        /// stub's signer.
        BadStub = "bad_stub", Report;
        /// A head statement whose author cannot supply its heads; reported
        /// against its author.
        BadStatement = "bad_statement", Report;
        /// A wrong `stream_prev`.
        StreamLinkBroken = "stream_link_broken", Report;
        /// A unit sealed under a state older than the current one.
        StaleKey = "stale_key", Report;
        /// A refused unit inside a settled snapshot that could not be undone.
        Unremovable = "unremovable", Report;
        /// A peer that serves less than a client knows of; reported against
        /// the peer.
        Withheld = "withheld", Report;
        /// A peer that lost what it acknowledged; reported against the peer.
        RolledBack = "rolled_back", Report;
    }
}

/// A class units.md's procedures fail with: units.md's own or a shared one,
/// or one of the documents they reach into: keys.md's key-reference
/// classes, events.md's envelope classes and roster.md's write-rule
/// classes. A shared class is always `Units(UnitClass::Shared(_))`,
/// whichever document raised it, so two equal classes compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitError {
    /// units.md's own, or a shared class.
    Units(UnitClass),
    /// keys.md's own: `TooManyRotations`, `NotARotation`.
    Key(KeyClass),
    /// events.md's own: `UnknownKind`, `WrongLog`, `NotEquivocation`,
    /// `BadCuts`.
    Event(EventClass),
    /// roster.md's own, from the write rule.
    Roster(RosterClass),
}

impl UnitError {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<ErrorClass> {
        match self {
            Self::Units(UnitClass::Shared(class)) => Some(class),
            _ => None,
        }
    }

    /// The class of this UpperCamelCase name: units.md's, a shared one,
    /// then keys.md's, events.md's and roster.md's own.
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(class) = UnitClass::from_name(name) {
            return Some(Self::Units(class));
        }
        if let Some(class) = KeyClass::from_name(name) {
            return Some(class.into());
        }
        if let Some(class) = EventClass::from_name(name) {
            return Some(class.into());
        }
        RosterClass::from_name(name).map(Self::from)
    }
}

impl Class for UnitError {
    fn name(self) -> &'static str {
        match self {
            Self::Units(class) => class.name(),
            Self::Key(class) => class.name(),
            Self::Event(class) => class.name(),
            Self::Roster(class) => class.name(),
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Units(class) => class.wire_name(),
            Self::Key(class) => class.wire_name(),
            Self::Event(class) => class.wire_name(),
            Self::Roster(class) => class.wire_name(),
        }
    }

    fn sort(self) -> Sort {
        match self {
            Self::Units(class) => class.sort(),
            Self::Key(class) => class.sort(),
            Self::Event(class) => class.sort(),
            Self::Roster(class) => class.sort(),
        }
    }
}

impl core::fmt::Display for UnitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl std::error::Error for UnitError {}

impl From<ErrorClass> for UnitError {
    fn from(class: ErrorClass) -> Self {
        Self::Units(UnitClass::Shared(class))
    }
}

impl From<frasil_base::cbor::Malformed> for UnitError {
    fn from(_: frasil_base::cbor::Malformed) -> Self {
        ErrorClass::Malformed.into()
    }
}

impl From<UnitClass> for UnitError {
    fn from(class: UnitClass) -> Self {
        Self::Units(class)
    }
}

impl From<KeyClass> for UnitError {
    fn from(class: KeyClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Key(class),
        }
    }
}

impl From<EventClass> for UnitError {
    fn from(class: EventClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Event(class),
        }
    }
}

impl From<RosterClass> for UnitError {
    fn from(class: RosterClass) -> Self {
        match class {
            RosterClass::Key(class) => class.into(),
            RosterClass::Event(class) => class.into(),
            other => match other.shared() {
                Some(shared) => shared.into(),
                None => Self::Roster(other),
            },
        }
    }
}

impl From<UnitError> for RosterClass {
    /// The class the roster takes for a unit: a shared class, or keys.md's,
    /// events.md's and roster.md's own as they are. units.md's own classes
    /// never reach the write rule; one that did would be `Malformed`.
    fn from(class: UnitError) -> Self {
        match class {
            UnitError::Units(UnitClass::Shared(shared)) => shared.into(),
            UnitError::Units(_) => ErrorClass::Malformed.into(),
            UnitError::Key(class) => class.into(),
            UnitError::Event(class) => class.into(),
            UnitError::Roster(class) => class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::snake_case;

    #[test]
    fn own_classes_are_named_as_the_spec_names_them() {
        for class in UnitClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(UnitClass::StreamMismatch.sort(), Sort::ContentRefused);
        assert_eq!(UnitClass::ObjectMismatch.sort(), Sort::Final);
        assert_eq!(UnitClass::BadStub.sort(), Sort::Report);
    }

    #[test]
    fn classes_of_other_documents_keep_their_names() {
        for name in [
            "TooManyRotations",
            "NotARotation",
            "WrongLog",
            "NotAWriter",
            "Malformed",
            "WrongSpace",
        ] {
            assert_eq!(UnitError::from_name(name).map(Class::name), Some(name));
        }
        assert_eq!(
            UnitError::from(KeyClass::from(ErrorClass::Pending)),
            UnitError::from(ErrorClass::Pending)
        );
    }
}
