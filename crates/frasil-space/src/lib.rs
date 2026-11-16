//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's spaces: the roster and the key graph.
//!
//! Specified by `docs/spec/roster.md` and by `docs/spec/keys.md`, sections
//! 3.4 (Notices and space principals) to 3.14 (Who may publish what). Its
//! vectors are `docs/spec/vectors/roster.json` and the key-graph families
//! of `keys.json`.
//!
//! The formats, which need no log:
//! - [`member`]: member references, levels, capabilities, labels, history
//!   modes and `via` (roster.md, "Members and levels", "Changes");
//! - [`policy`](mod@policy): the space descriptor and the space policy, and
//!   the merge of concurrent policies ("The space descriptor", "The space
//!   policy");
//! - [`change`]: changes ("Changes");
//! - [`part`]: the roster part of a genesis, an update and a checkpoint
//!   ("The roster part"), with steps 6 to 10 of "The event alone";
//! - [`checkpoint_record`]: the record a checkpoint names ("The checkpoint
//!   record").
//!
//! The checks of one event, over a log the caller holds (`frasil-events`):
//! - [`screen`]: steps 2 to 11 of "The event alone", through `frasil-keys`'
//!   body, and "An author's keys"; a
//!   [`ScreenedLog`] holds every space event of a log so checked.
//!
//! The roster at a place, and the grant graph, given what is valid:
//! - [`state`]: member states, the meet, seniority, the roster and the
//!   space policy at a place ("The roster at a place"), and what the rules
//!   read of an event at its place: who it makes or unmakes an
//!   administrator, whether it names its twin where it must, whether it is
//!   self-lowering;
//! - [`graph`]: the grant graph's rules and effective membership ("Grants
//!   of spaces and effective membership").
//!
//! The resolution of a view, and what replicas derive from it:
//! - [`attacks`]: self-lowering events, what attacks what, and which
//!   attacks a duel drops ("Attacks");
//! - [`resolution`]: authority at the place, and the roster events decided
//!   by `frasil-resolve`'s procedure, with the twin step through
//!   `frasil-peers`' replica checks ("Authority at the place", "The
//!   resolution procedure", "The twin");
//! - [`across`]: the other logs a space reads, persons' lists and granted
//!   spaces ("Checks across logs");
//! - [`across_logs`]: persons' lists across list checkpoints, held whole or
//!   from a kept checkpoint on, and the paths a list checkpoint ends at
//!   once (3.15.8 Other logs and extensions);
//! - [`space`]: a view of a space's log resolved in roster.md's order of
//!   verification: held events, the roster, the write rule for key events
//!   then units, anchors and strangers' events ("The order of
//!   verification", "Space events a replica cannot open", "The write
//!   rule", "Anchors, storage events and strangers' events"); and what
//!   replicas derive from it: the maximal valid rotations, the events that
//!   void each void event, frontiers, stability, refused units' retention,
//!   duels and re-submission ("What replicas derive"); and a partial
//!   replica's write rule in proven order ([`Replica::Partial`];
//!   units.md, "Partial replicas");
//! - [`checkpoint`] and [`checkpoint_world`]: checkpoints, their validity,
//!   votes and effect, the world after a checkpoint, late events and the
//!   chain in effect, for a replica that keeps everything and for one that
//!   forgot what came before its kept checkpoint ("Checkpoints"); and the
//!   hold for rules this replica lacks ("Rules this replica lacks").
//!
//! The key graph (keys.md, sections 3.4 to 3.14) is [`keygraph`]. It reads
//! a view through [`keygraph::History`], which a resolved [`Space`]
//! implements ([`keygraph::SpaceHistory`]): its valid set, its roster at any
//! place, its members' devices and the granted spaces it holds. The write
//! rule runs keys.md's checks against a key event and its place
//! ([`KeyEventChecks`]); step 8 of those (keys.md, "Checks against the
//! event and its place") is the key graph's, through the [`Notices`] hook
//! ([`keygraph::GrantedNotices`]). A notice's own checks decide whether it
//! admits a principal, never a verdict.
//!
//! The extensions' hooks are in [`ext`]: features `ext-invite-links` and
//! `ext-restricted-spaces`. Without them a core implementation holds what
//! uses them as `ExtensionRequired`. ext-invite-links.md's rules are in
//! `ext_invite_links`, under its feature. With feature
//! `ext-recovery-agent`, `ext_recovery_agent` gives the key graph
//! ext-recovery-agent.md's waiting period: a person's device rooted in an
//! agent receives wraps once this replica vouches for it. With feature
//! `ext-restricted-spaces`, `ext_restricted_spaces` holds
//! ext-restricted-spaces.md's rules: a restricted space's parent, its
//! membership narrowed by the parent's, its paths through the parent, when
//! it rotates, and the mirrors of the parent's changes.
//!
//! The crate reads no clock, does no IO and draws no randomness: a system
//! stream ID and every key come in as arguments.

pub mod across;
pub mod across_logs;
pub mod attacks;
pub mod change;
pub mod checkpoint;
pub mod checkpoint_record;
pub mod checkpoint_world;
mod derive;
pub mod errors;
pub mod ext;
#[cfg(feature = "ext-guests")]
pub mod ext_guests;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
#[cfg(feature = "ext-recovery-agent")]
pub mod ext_recovery_agent;
#[cfg(feature = "ext-restricted-spaces")]
pub mod ext_restricted_spaces;
pub mod graph;
pub mod keygraph;
pub mod member;
pub mod part;
pub mod policy;
pub mod record_stream;
pub mod resolution;
pub mod screen;
pub mod space;
pub mod state;

pub use across::{GrantedSpace, GranteeRotation, HeldList, OtherLogs, PathsFor};
pub use change::{Change, Op};
pub use checkpoint::{
    AdministratorSlots, AuthorityKey, Checkpointed, Contest, FrozenUnit,
    Inputs as CheckpointInputs, Judged, Kept, KeyWorld, LateRequest, Lowered, Lowering, Placement,
    RecordObject, RecordObjects, RequestState, StandingEntry, Waiting,
};
pub use checkpoint_record::{
    HeardMember, InviteStatus, MemberEntry, Record, RecordNotice, SlotEntry,
};
pub use checkpoint_world::WorldLog;
pub use errors::{RosterClass, SpaceClass};
pub use frasil_crypto::device::{DeviceId, DeviceKeys, KeySource};
pub use member::{Capability, CapabilityMode, HistoryMode, Level, MemberRef, MemberType, Via};
pub use part::{CheckpointPart, Genesis, RosterPart, Update};
pub use policy::{
    Descriptor, DescriptorKind, MAX_APPLICATION_BYTES, Policy, RESERVED_DESCRIPTOR_KEY,
    RESERVED_DESCRIPTOR_KIND,
};
pub use screen::{Body, Keyring, Opened, ScreenedLog, Signature};
pub use space::{
    Checkpointing, KeyEventChecks, NoticeAnswer, NoticeQuery, Notices, Options, Replica, Resolved,
    Retention, Space, Status, Twins, UnitBodies, UnitBody, Valid, refused_unit,
};
pub use state::{
    MemberState, PlaceCache, Places, Roster, RosterEvents, RosterLog, Standing, WorldRoot,
};

/// How many times the resolution procedure has run on this thread, and how
/// many contested events it has weighed in all
/// ([`frasil_resolve::weighed`]), for tests and measurements.
#[doc(hidden)]
pub use frasil_resolve::weighed as resolutions_weighed;

/// The limits of roster.md ("Labels and limits").
pub mod limits {
    /// Changes in one update; more is `Malformed`.
    pub const MAX_CHANGES: usize = 256;
    /// Grants of a device in one update; more is `Malformed`.
    pub const MAX_DEVICE_GRANTS: usize = 64;
    /// Capabilities in one grant or change; more is `Malformed`.
    pub const MAX_CAPABILITIES: usize = 32;
    /// A capability name's or a label's longest length, in bytes.
    pub const MAX_NAME_BYTES: usize = 64;
    /// Valid roster events in an event's place, itself included, counted
    /// from the checkpoint in effect in its past; more is `Full`.
    pub const MAX_ROSTER_EVENTS: usize = 4096;
    /// The largest record a checkpoint names, in bytes; more is `TooLarge`.
    pub const MAX_RECORD_BYTES: u64 = crate::part::MAX_RECORD_BYTES;
    /// Undecided events for the resolution's agreement step; above it the
    /// step is skipped.
    pub const AGREEMENT_LIMIT: usize = 16;
    /// Spaces on a chain of counted grants; more is `GrantTooDeep`.
    pub const MAX_GRANT_DEPTH: usize = crate::graph::MAX_GRANT_DEPTH;
    /// The inner key of a space event's sealed part that holds its refs.
    pub const REFS_INNER_KEY: u64 = frasil_keys::body::sealed_key::REFS;
}

/// The limits a reader applies: the protocol's, or lowered ones, as the
/// vectors lower some to keep their histories short.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// Changes in one update.
    pub max_changes: usize,
    /// Grants of a device in one update.
    pub max_device_grants: usize,
    /// Capabilities in one grant or change.
    pub max_capabilities: usize,
    /// Valid roster events in an event's place, itself included.
    pub max_roster_events: usize,
}

impl Limits {
    /// The protocol's limits.
    pub const PROTOCOL: Self = Self {
        max_changes: limits::MAX_CHANGES,
        max_device_grants: limits::MAX_DEVICE_GRANTS,
        max_capabilities: limits::MAX_CAPABILITIES,
        max_roster_events: limits::MAX_ROSTER_EVENTS,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::PROTOCOL
    }
}

/// The labels crypto.md's registry gives to roster.md ("Labels and
/// limits"). Roster.md also uses crypto.md's own `kc` and device ID labels,
/// through `frasil_crypto::device`.
pub const LABELS: [&[u8]; 2] = [
    frasil_crypto::labels::ROSTER_SENIORITY,
    frasil_crypto::labels::CHECKPOINT_RECORD,
];

pub use record_stream::{
    ReadRecord, RecordFault, RecordMode, RecordSink, RecordStream, RecordSummary, SpaceFields,
};
