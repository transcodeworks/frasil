//! The key graph (keys.md, sections 3.4 to 3.14): notices, taking keys,
//! the current state and the inside, entitlement and the link gate,
//! restored members, healing, cascades, the rank and its delay, and
//! deliveries.
//!
//! - [`notices`]: each notice's check, and keys.md's "Checks against the
//!   event and its place", step 8, as a space's [`Notices`] hook
//!   ("Notices and space principals").
//! - [`take`]: slot by slot, provisional keys, and trial decryption
//!   ("Taking a key").
//! - [`view`]: what the key graph reads of a view ([`History`]).
//! - [`graph`]: the current state, the merged roster with its space
//!   principals, the inside, entitlement, restored members and the link
//!   gate ([`KeyGraph`]).
//! - [`holdings`]: what devices derive, and the heal test ("Healing").
//! - [`plan`](mod@plan): the deliveries a view calls for ("Deliveries").
//! - [`cascade`](mod@cascade): which spaces rotate after a change, and the
//!   candidates ("Cascades").
//! - [`rank`]: the rank and its delay, and the restored member's gap keys
//!   ("The rank and the delay", "Restored members").
//! - [`space`]: a resolved [`Space`](crate::Space) as a [`History`].
//!
//! A replica computes all of it from what it holds; replicas that hold
//! different artifacts may disagree, and the cost is an extra heal, which
//! merges like any rotation. Nothing here makes an event valid or void,
//! except step 8, which reads only the event and the roster at its place.
//! A notice's own checks decide only whether it admits a principal.
//!
//! [`Notices`]: crate::Notices

pub mod cascade;
pub mod graph;
pub mod holdings;
pub mod notices;
pub mod plan;
pub mod rank;
pub mod space;
pub mod take;
pub mod view;

/// Which key graph: the content graph (kind 1) or the grant graph (kind 2),
/// as links and gap records name them.
pub use frasil_keys::links::LinkKind as Kind;

pub use cascade::{Cascade, ChangeKind, cascade, cascade_candidates};
pub use graph::{KeyGraph, Member, Principal, Roster};
pub use holdings::{Artifact, Heal, Holdings, heal_candidates, heal_due};
pub use notices::{GrantedNotices, check_notice};
pub use plan::{
    OwnDelivery, Plan, PlannedLink, PlannedWrap, Why, checkpoint_delivery, entitled_lacking,
    own_delivery, plan, record_principals,
};
pub use rank::{GapKeyDecision, Rank, delay, gap_keys, rank_order, rank_value};
pub use space::SpaceHistory;
pub use take::{
    KeySource, Slot, Taken, key_source, seal_mismatch, take_slots, tries, tries_rooted,
};
pub use view::{EventFacts, Grant, History, Membership, NoticeFacts, Role, Rotation};
