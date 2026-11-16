//! What the key graph reads of a view of one space (keys.md, sections 3.4
//! to 3.13): its events with their causal order, the valid set roster.md
//! decided, the roster at a place, the devices of each member, and what a
//! replica holds of the spaces this one grants.
//!
//! The key graph runs over anything that implements [`History`]: a
//! resolved [`Space`](crate::Space) does (`keygraph::space`), and so can a
//! model of a history whose valid set is given.

use crate::member::Level;
use frasil_events::{EventId, Ref};
use frasil_keys::RotationSet;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

/// Which kind of space event an event is, or that it is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The genesis.
    Genesis,
    /// A roster event.
    Roster,
    /// A key event.
    Key,
    /// A unit.
    Unit,
    /// Any other event: an anchor, a storage event, an ignorable kind.
    Other,
}

/// What a rotation says of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rotation {
    /// A grant rotation: it draws a grant seed.
    pub grant: bool,
    /// It carries `break`: a rotation with no link back.
    pub is_break: bool,
}

/// A grant an event makes (roster.md, "Changes").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Grant<M> {
    /// The member it grants.
    pub member: M,
    /// "With history": `history` is not 0.
    pub with_history: bool,
    /// It carries `session`: a guest, which does not propagate.
    pub session: bool,
}

/// A notice an event carries (keys.md, "The space event's body").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoticeFacts {
    /// The granted space.
    pub space: EventId,
    /// The grant rotation of the granted space it names.
    pub rotation: EventId,
    /// Key 4: that rotation is a break, and the notice admits its principal
    /// "from now on".
    pub from_now_on: bool,
}

/// What the key graph reads of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFacts<D, M> {
    /// The device that signed it.
    pub author: D,
    /// Which kind of event it is.
    pub role: Role,
    /// For a rotation: the genesis, or a roster event or key event that
    /// rotates.
    pub rotation: Option<Rotation>,
    /// The state it is sealed under, when it does not rotate: a unit's key
    /// reference (keys.md, "Key references in units"), or the state a space
    /// event that does not rotate names in its seal.
    pub key_reference: Option<RotationSet>,
    /// The grants it makes.
    pub grants: Vec<Grant<M>>,
    /// The members it removes.
    pub removes: Vec<M>,
    /// The notices it carries.
    pub notices: Vec<NoticeFacts>,
    /// Its sealed refs: events of other logs it names.
    pub refs: Vec<Ref>,
    /// ext-invite-links.md: for a successor, its invite key and its
    /// claimant.
    #[cfg(feature = "ext-invite-links")]
    pub successor: Option<crate::ext_invite_links::Succession<M>>,
}

impl<D, M> EventFacts<D, M> {
    /// Facts with only an author and a role.
    pub fn new(author: D, role: Role) -> Self {
        Self {
            author,
            role,
            rotation: None,
            key_reference: None,
            grants: Vec::new(),
            removes: Vec::new(),
            notices: Vec::new(),
            refs: Vec::new(),
            #[cfg(feature = "ext-invite-links")]
            successor: None,
        }
    }

    /// Whether it is a space event: the genesis, a roster event or a key
    /// event.
    pub fn is_space_event(&self) -> bool {
        matches!(self.role, Role::Genesis | Role::Roster | Role::Key)
    }
}

/// A member's state in the roster at a place, as the key graph reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// Its level.
    pub level: Level,
    /// Whether some grant in force is "with history".
    pub with_history: bool,
    /// Whether every grant in force carries `session`.
    pub session: bool,
    /// Its grants in force, by event ID, ascending.
    pub grants: Vec<EventId>,
}

/// A view of one space, as the key graph reads it.
pub trait History {
    /// A device, as the view names it.
    type Device: Ord + Clone + Debug;
    /// A member of the roster, as the view names it.
    type Member: Ord + Clone + Debug;

    /// The space ID.
    fn space(&self) -> EventId;

    /// The genesis's event ID.
    fn genesis(&self) -> EventId;

    /// The events the view holds, `W`.
    fn events(&self) -> BTreeSet<EventId>;

    /// What the key graph reads of an event of the view.
    fn facts(&self, id: EventId) -> &EventFacts<Self::Device, Self::Member>;

    /// Whether `earlier` is in the past of `later`.
    fn precedes(&self, earlier: EventId, later: EventId) -> bool;

    /// The roster of a set of valid events (roster.md, "The roster at a
    /// place"): the genesis and roster events among them decide it; other
    /// events are ignored. Space principals are the key graph's, added on
    /// top.
    fn roster(&self, place: &BTreeSet<EventId>) -> BTreeMap<Self::Member, Membership>;

    /// A member's devices: a device member's own, a person's as its list
    /// vouches for them. A space member reaches this space only through its
    /// principals.
    fn devices(&self, member: &Self::Member) -> Vec<Self::Device>;

    /// The devices a delivery at event `delivery` wrapped for, for a member
    /// of the roster at its place (keys.md, "Healing"). A device keeps what
    /// it received whatever the lists say later: a device its list has since
    /// revoked, or whose chain has since forked, counts unless the
    /// delivery's past, the delivery included, holds a response to the end
    /// of its path or the evidence of its fork. By default, the member's
    /// devices now.
    fn wrapped_for(&self, member: &Self::Member, delivery: EventId) -> Vec<Self::Device> {
        let _ = delivery;
        self.devices(member)
    }

    /// The space a member is, for a space member.
    fn space_of(&self, member: &Self::Member) -> Option<EventId>;

    /// The valid roster events that void a removal (roster.md, "What
    /// replicas derive").
    fn voiders(&self, valid: &BTreeSet<EventId>, removal: EventId) -> Vec<EventId>;

    /// Whether the voiding of a removal is stable (roster.md, "What
    /// replicas derive").
    fn stable(&self, valid: &BTreeSet<EventId>, removal: EventId) -> bool;

    /// Whether, in a granted space's log, `earlier` is `rotation` or in its
    /// past; `None` when this replica does not hold `rotation`.
    fn grantee_le(&self, space: EventId, earlier: EventId, rotation: EventId) -> Option<bool>;

    /// Whether an event of a granted space is a valid rotation there, as
    /// this replica holds its log; `None` when it does not hold the event.
    /// Only valid rotations that sealed refs name put a principal out of
    /// force (keys.md, "Notices and space principals"). By default every
    /// event a view names is one, for a view whose refs name only rotations.
    fn grantee_rotation(&self, space: EventId, event: EventId) -> Option<bool> {
        let _ = (space, event);
        Some(true)
    }

    /// The devices of a granted space that hold the grant seed of one of its
    /// rotations: a space principal's devices.
    fn principal_devices(&self, space: EventId, rotation: EventId) -> Vec<Self::Device>;

    /// The devices still in a granted space, as this replica holds its log;
    /// `None` when it does not hold it.
    fn grantee_current(&self, space: EventId) -> Option<BTreeSet<Self::Device>>;

    /// Whether a notice that event `event` carries admits its principal at
    /// this replica (keys.md, "Notices and space principals"): the replica
    /// holds the granted space's log and the notice passes its checks
    /// there, `NoticeStale` aside, which the key graph's standing rule
    /// covers. A notice that does not admits nothing, and its event stands
    /// or falls by its other checks. By default every notice of the view
    /// admits, for a view whose notices were checked already.
    fn admits(&self, event: EventId, notice: &NoticeFacts) -> bool {
        let _ = (event, notice);
        true
    }

    /// The checkpoint the view is rooted at, when it is a checkpoint's world
    /// (keys.md, "Keys after a checkpoint"): its genesis is then the
    /// checkpoint, and a state with a rotation it does not hold is a state
    /// before the checkpoint. `None` by default.
    fn world_root(&self) -> Option<EventId> {
        None
    }

    /// In a checkpoint's world, whether the record gives granted space
    /// `space` a floor: a principal of it is then entitled to no state
    /// before the checkpoint (keys.md, "Keys after a checkpoint"). By
    /// default none does.
    fn record_floor(&self, space: EventId) -> bool {
        let _ = space;
        false
    }

    /// In a checkpoint's world, the invite keys its record shows raced:
    /// members, but outside (ext-invite-links.md, "Across a checkpoint").
    /// By default none.
    #[cfg(feature = "ext-invite-links")]
    fn record_raced(&self) -> Vec<Self::Member> {
        Vec::new()
    }

    /// ext-invite-links.md, "Keys": whether a successor of the view that is
    /// not valid is void as `ClaimRaced`, which counts its invite key as
    /// outside. By default every void successor does, for a view whose
    /// classes are not given.
    #[cfg(feature = "ext-invite-links")]
    fn void_as_raced(&self, successor: EventId) -> bool {
        let _ = successor;
        true
    }

    /// ext-restricted-spaces.md, "Keys of a restricted space": whether a
    /// holder outside the inside counts in the heal test. In a restricted
    /// space, only one inside its parent's merged roster does. By default
    /// every one does.
    #[cfg(feature = "ext-restricted-spaces")]
    fn counts_outside(&self, device: &Self::Device) -> bool {
        let _ = device;
        true
    }

    /// Whether this replica wraps for a device of a member of the roster
    /// (identity.md, "What a list vouches for"): a person's list member
    /// that waits receives nothing, nor does any device of a person whose
    /// merged list holds an active agent in a space whose policy forbids
    /// agents. Under ext-recovery-agent.md, a waiting list member receives
    /// once this replica vouches for it. By default every device does, for
    /// a view whose devices wait on nothing.
    fn receives(&self, member: &Self::Member, device: &Self::Device) -> bool {
        let _ = (member, device);
        true
    }

    /// Whether a device of a member of the roster writes through it: a
    /// person's recovery key receives wraps but never writes (identity.md,
    /// "Kinds of list member"). By default every device does.
    fn writes(&self, member: &Self::Member, device: &Self::Device) -> bool {
        let _ = (member, device);
        true
    }
}
