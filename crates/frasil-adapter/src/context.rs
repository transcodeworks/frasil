//! The context of a unit: what an adapter may read besides its content
//! (units.md, section 3.17, "The adapter interface").
//!
//! The space ID, the stream, the unit's event ID, author, `seq` and height,
//! its `objects`, whether it is a snapshot unit, its `resubmits` and
//! `copied_from`, and the capabilities its author holds at its place. Never
//! the time, randomness or another stream.
//!
//! The height (events.md, "Placement and order") gives an adapter
//! canonical order, by height then event ID, which a check that compares a
//! unit with the units before it needs, such as adapter-loro.md's step 6.
//! A replica that places a unit against a stub takes the stub's height for
//! that parent (units.md, section 3.9, "Placing against stubs").

use crate::capabilities::Capabilities;

/// A space ID (events.md).
pub type SpaceId = [u8; 32];
/// A stream ID: 16 bytes, never all zero (units.md, section 2.6, "Streams").
pub type StreamId = [u8; 16];
/// An event ID (events.md).
pub type EventId = [u8; 32];
/// A unit's author: its device ID, which the envelope's `ed` and `kc` give
/// (events.md, "The envelope"; crypto.md, "A device's keys"). Never its
/// Ed25519 key.
pub type Author = [u8; 32];

/// The length of a locator: object ID, then the digest (units.md, section
/// 2.8).
pub const LOCATOR_BYTES: usize = 64;
/// An object's locator: its object ID (32) and the SHA-256 digest of its
/// stored bytes (32) (units.md, section 2.8, "Objects").
pub type Locator = [u8; LOCATOR_BYTES];

/// A unit's role in its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A log unit, whose content is a change.
    Log,
    /// A snapshot unit, a seed included (units.md, section 2.9, "Snapshot units
    /// and stream snapshots"). Its content is the adapter's snapshot metadata.
    Snapshot,
}

/// A re-application's origin: the unit's sealed key 4, `[original space ID,
/// the late write's event ID]` (units.md, section 2.5, "The sealed part";
/// ext-restricted-spaces.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CopiedFrom {
    /// The original space.
    pub space: SpaceId,
    /// The late write's event ID.
    pub event_id: EventId,
}

/// A supersession (units.md, section 2.3): one object a unit lists, its
/// successor, replaces an earlier object of the stream, its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Supersession {
    /// The object that replaces.
    pub successor: Locator,
    /// In a log unit, the unit whose listing of the predecessor this one
    /// supersedes; a snapshot unit names its own listings, and has none.
    pub listing: Option<EventId>,
    /// The object replaced.
    pub predecessor: Locator,
}

/// The context of one unit (units.md, section 3.17, "The adapter interface").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The space ID.
    pub space: SpaceId,
    /// The stream.
    pub stream: StreamId,
    /// The unit's event ID.
    pub event_id: EventId,
    /// The unit's author.
    pub author: Author,
    /// The unit's `seq` in its author's chain.
    pub seq: u64,
    /// The unit's height in its space's log (events.md).
    pub height: u64,
    /// The locators the unit lists in its visible `objects`.
    pub objects: Vec<Locator>,
    /// The supersessions in its visible `supersedes`.
    pub supersedes: Vec<Supersession>,
    /// Whether it is a log unit or a snapshot unit.
    pub role: Role,
    /// The refused unit it re-submits, if it is a re-submission.
    pub resubmits: Option<EventId>,
    /// The late write it re-applies, if it is a re-application.
    pub copied_from: Option<CopiedFrom>,
    /// The capabilities its author holds at its place.
    pub capabilities: Capabilities,
    /// Whether its space is a restricted space or a carve-out
    /// (ext-restricted-spaces.md, "The restricted key reference"): a key
    /// reference there carries the parent's state after its own rotation
    /// set.
    pub restricted: bool,
}

impl Context {
    /// The context of a unit with no objects, no `resubmits`, no
    /// `copied_from` and no capabilities.
    pub fn new(
        space: SpaceId,
        stream: StreamId,
        event_id: EventId,
        author: Author,
        seq: u64,
        height: u64,
        role: Role,
    ) -> Self {
        Self {
            space,
            stream,
            event_id,
            author,
            seq,
            height,
            objects: Vec::new(),
            supersedes: Vec::new(),
            role,
            resubmits: None,
            copied_from: None,
            capabilities: Capabilities::none(),
            restricted: false,
        }
    }

    /// The same context in a restricted space, or not.
    pub fn with_restricted(mut self, restricted: bool) -> Self {
        self.restricted = restricted;
        self
    }

    /// The same context with these supersessions.
    pub fn with_supersedes(mut self, supersedes: impl IntoIterator<Item = Supersession>) -> Self {
        self.supersedes = supersedes.into_iter().collect();
        self
    }

    /// The same context with these objects.
    pub fn with_objects(mut self, objects: impl IntoIterator<Item = Locator>) -> Self {
        self.objects = objects.into_iter().collect();
        self
    }

    /// The same context with these capabilities.
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// The same context with this `resubmits`.
    pub fn with_resubmits(mut self, resubmits: Option<EventId>) -> Self {
        self.resubmits = resubmits;
        self
    }

    /// The same context with this `copied_from`.
    pub fn with_copied_from(mut self, copied_from: Option<CopiedFrom>) -> Self {
        self.copied_from = copied_from;
        self
    }

    /// The unit's place in canonical order: its height, then its event ID
    /// (events.md, "Placement and order").
    pub fn canonical(&self) -> (u64, EventId) {
        (self.height, self.event_id)
    }

    /// Whether the unit is a snapshot unit, a seed included.
    pub fn is_snapshot(&self) -> bool {
        self.role == Role::Snapshot
    }

    /// Whether the unit lists this locator in its `objects`.
    pub fn lists(&self, locator: &Locator) -> bool {
        self.objects.contains(locator)
    }
}

/// An ephemeral frame's kind (ext-ephemeral.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EphemeralKind {
    /// An ephemeral message, fire-and-forget.
    Message,
    /// An ephemeral slot value, latest-wins.
    Slot,
}

/// A level in a space (roster.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// `read`.
    Read,
    /// `write`.
    Write,
    /// `administer`.
    Administer,
}

/// The context of an ephemeral message or slot value, for capability
/// checks (ext-ephemeral.md, section 3.5, "Capability checks"; units.md,
/// section 3.17, which runs the same interface "with its own context").
/// The sender's level and capabilities are those of the receiver's current
/// view, merged over the sender's paths. A frame has no place, so there is
/// no event ID, `seq` or height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralContext {
    /// The space ID.
    pub space: SpaceId,
    /// The kind.
    pub kind: EphemeralKind,
    /// `name`.
    pub name: String,
    /// `stream`, if the frame names one.
    pub stream: Option<StreamId>,
    /// `targets`, if the frame names any.
    pub targets: Option<Vec<[u8; 32]>>,
    /// The sender's device ID.
    pub sender: Author,
    /// The sender's level in the receiver's current view.
    pub level: Level,
    /// The sender's capabilities in the receiver's current view.
    pub capabilities: Capabilities,
}

/// The re-applier of a late write (units.md, section 3.17, `reapply`): the
/// writer whose own unit in the moved document carries what
/// [`Adapter::reapply`](crate::Adapter::reapply) returns, at the place that
/// unit will take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Writer {
    /// The moved document's space.
    pub space: SpaceId,
    /// The moved document's stream.
    pub stream: StreamId,
    /// The re-applier's device ID: the new unit's author.
    pub author: Author,
    /// The `seq` the re-applier's new unit takes in its chain.
    pub seq: u64,
}
