//! The error classes of roster.md ("Error classes"), and [`RosterClass`],
//! which also carries the classes of the documents a space event's checks
//! reach into: events.md, keys.md and peers.md.

use frasil_base::errors::{Class, ErrorClass, Sort};
use frasil_events::EventClass;
use frasil_identity::IdentityClass;
use frasil_keys::KeyClass;
use frasil_peers::PeersClass;

frasil_base::error_classes! {
    /// roster.md's own classes ("Error classes"), with every shared class.
    /// `NoTwin` and `BadTwin` are peers.md's ([`PeersClass`]); `NotCommitted`,
    /// `BadSeal`, `Sealed`, `ExtensionRequired`, `NotAnAdministrator` and
    /// `Full` are shared.
    pub enum SpaceClass {
        /// A genesis duel policy other than 0.
        UnknownPolicy = "unknown_policy", Final;
        /// `administer` for a person, a space or a guest.
        AdministerNotDevice = "administer_not_device", Final;
        /// A self-removal that rotates.
        SelfRotation = "self_rotation", Final;
        /// Authority at the place: an administrator grants its own device.
        SelfGrant = "self_grant", Final;
        /// Authority at the place: a grant of a member already in.
        AlreadyMember = "already_member", Final;
        /// Authority at the place: a change or removal of a member not in.
        NoSuchMember = "no_such_member", Final;
        /// Authority at the place: a change of the author's own device that
        /// does more than lower its level.
        SelfChange = "self_change", Final;
        /// Authority at the place: an event of several changes that lowers an
        /// administrator.
        AdminAlone = "admin_alone", Final;
        /// Authority at the place: a change or removal of an administrator
        /// of a higher rank than its author's, or a grant or change that
        /// gives a rank above it.
        HigherRank = "higher_rank", Final;
        /// Authority at the place: a change to `administer` of a member
        /// already there with another rank.
        RankInPlace = "rank_in_place", Final;
        /// Attack (a): a concurrent event removes the author's member.
        RemovedConcurrently = "removed_concurrently", Final;
        /// Attack (b): a concurrent event demotes the author's device member
        /// below `administer`.
        DemotedConcurrently = "demoted_concurrently", Final;
        /// Attack (c): a concurrent event removes a member this one grants or
        /// changes.
        TargetRemovedConcurrently = "target_removed_concurrently", Final;
        /// Visible key 15 missing from an event that changes who
        /// administers.
        TwinRequired = "twin_required", Final;
        /// Visible key 15 on an event that does not change who administers.
        UnexpectedTwin = "unexpected_twin", Final;
        /// No path admits the author of a unit or key event.
        NotAWriter = "not_a_writer", Final;
        /// A key event by a device rooted in a recovery agent.
        WaitingDevice = "waiting_device", Final;
        /// A write the end of its path refuses (the write rule, step 4).
        RefusedByRemoval = "refused_by_removal", Final;
        /// A write the end of its path refuses (the write rule, step 5).
        RefusedAfterResponse = "refused_after_response", Final;
        /// An edge of the grant graph to a space whose roster the replica
        /// does not hold. A verdict on an edge, not on an event.
        UnknownSpace = "unknown_space", Final;
        /// An edge of the grant graph to a restricted space. A verdict on an
        /// edge, not on an event.
        GrantOfRestricted = "grant_of_restricted", Final;
        /// An edge of the grant graph to a space whose descriptor a later
        /// document defines (roster.md, 2.5 and 3.3), at every
        /// implementation. A verdict on an edge, not on an event.
        GrantOfReserved = "grant_of_reserved", Final;
        /// An edge of the grant graph that closes a cycle, or from a space to
        /// itself. A verdict on an edge, not on an event.
        GrantCycle = "grant_cycle", Final;
        /// An edge of the grant graph past 8 spaces on a chain. A verdict on
        /// an edge, not on an event.
        GrantTooDeep = "grant_too_deep", Final;
        /// A checkpoint whose predecessor or record is not that of its past
        /// (roster.md, 3.15.2 A checkpoint's validity).
        BadCheckpoint = "bad_checkpoint", Final;
        /// A checkpoint made while another in its past still waited for
        /// votes, or before its predecessor took effect.
        CheckpointPending = "checkpoint_pending", Final;
        /// With a checkpoint in effect, an event neither in its past nor
        /// after it; a late unit is refused and kept.
        Late = "late", Final;
        /// An event after a checkpoint with a parent, other than its `prev`,
        /// that is neither the checkpoint nor after it.
        MixedCut = "mixed_cut", Final;
    }
}

impl SpaceClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

/// identity.md's shared classes pass through; any class of identity.md's
/// own is `Malformed` here.
impl From<IdentityClass> for SpaceClass {
    fn from(class: IdentityClass) -> Self {
        match class {
            IdentityClass::Shared(shared) => Self::Shared(shared),
            _ => Self::Shared(ErrorClass::Malformed),
        }
    }
}

/// The classes keys.md's readers of a descriptor's or policy's neighbours
/// raise are shared ones; any of keys.md's own is kept by [`RosterClass`].
impl From<KeyClass> for SpaceClass {
    fn from(class: KeyClass) -> Self {
        Self::Shared(class.shared().unwrap_or(ErrorClass::Malformed))
    }
}

/// A class a space event's checks fail with: roster.md's, or one of the
/// documents they reach into. A shared class is always
/// `Space(SpaceClass::Shared(_))`, whichever document raised it, so two
/// equal classes compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RosterClass {
    /// roster.md's own, or a shared class.
    Space(SpaceClass),
    /// keys.md's own: its checks of the body and against the place.
    Key(KeyClass),
    /// peers.md's own: `NoTwin` and `BadTwin`.
    Peers(PeersClass),
    /// events.md's own: the envelope and placement.
    Event(EventClass),
    /// ext-invite-links.md's own: a successor's authority and the race
    /// rule.
    #[cfg(feature = "ext-invite-links")]
    Invite(crate::ext_invite_links::InviteClass),
    /// ext-restricted-spaces.md's own: a restricted space whose parent is
    /// restricted.
    #[cfg(feature = "ext-restricted-spaces")]
    Restricted(crate::ext_restricted_spaces::RestrictedClass),
}

impl RosterClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<ErrorClass> {
        match self {
            Self::Space(class) => class.shared(),
            _ => None,
        }
    }

    /// The class of this UpperCamelCase name: roster.md's, a shared one,
    /// then keys.md's, peers.md's and events.md's own.
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(class) = SpaceClass::from_name(name) {
            return Some(Self::Space(class));
        }
        #[cfg(feature = "ext-invite-links")]
        if let Some(class) = crate::ext_invite_links::InviteClass::from_name(name) {
            return Some(class.into());
        }
        #[cfg(feature = "ext-restricted-spaces")]
        if let Some(class) = crate::ext_restricted_spaces::RestrictedClass::from_name(name) {
            return Some(class.into());
        }
        if let Some(class) = KeyClass::from_name(name) {
            return Some(Self::from_key(class));
        }
        if let Some(class) = PeersClass::from_name(name) {
            return Some(class.into());
        }
        EventClass::from_name(name).map(Self::from)
    }

    fn from_key(class: KeyClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Key(class),
        }
    }
}

impl Class for RosterClass {
    fn name(self) -> &'static str {
        match self {
            Self::Space(class) => class.name(),
            Self::Key(class) => class.name(),
            Self::Peers(class) => class.name(),
            Self::Event(class) => class.name(),
            #[cfg(feature = "ext-invite-links")]
            Self::Invite(class) => class.name(),
            #[cfg(feature = "ext-restricted-spaces")]
            Self::Restricted(class) => class.name(),
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Space(class) => class.wire_name(),
            Self::Key(class) => class.wire_name(),
            Self::Peers(class) => class.wire_name(),
            Self::Event(class) => class.wire_name(),
            #[cfg(feature = "ext-invite-links")]
            Self::Invite(class) => class.wire_name(),
            #[cfg(feature = "ext-restricted-spaces")]
            Self::Restricted(class) => class.wire_name(),
        }
    }

    fn sort(self) -> Sort {
        match self {
            Self::Space(class) => class.sort(),
            Self::Key(class) => class.sort(),
            Self::Peers(class) => class.sort(),
            Self::Event(class) => class.sort(),
            #[cfg(feature = "ext-invite-links")]
            Self::Invite(class) => class.sort(),
            #[cfg(feature = "ext-restricted-spaces")]
            Self::Restricted(class) => class.sort(),
        }
    }
}

impl core::fmt::Display for RosterClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl std::error::Error for RosterClass {}

impl From<ErrorClass> for RosterClass {
    fn from(class: ErrorClass) -> Self {
        Self::Space(SpaceClass::Shared(class))
    }
}

impl From<SpaceClass> for RosterClass {
    fn from(class: SpaceClass) -> Self {
        Self::Space(class)
    }
}

impl From<KeyClass> for RosterClass {
    fn from(class: KeyClass) -> Self {
        Self::from_key(class)
    }
}

impl From<PeersClass> for RosterClass {
    fn from(class: PeersClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Peers(class),
        }
    }
}

impl From<EventClass> for RosterClass {
    fn from(class: EventClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Event(class),
        }
    }
}

impl From<frasil_base::cbor::Malformed> for RosterClass {
    fn from(_: frasil_base::cbor::Malformed) -> Self {
        ErrorClass::Malformed.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::snake_case;

    #[test]
    fn classes_follow_the_table() {
        for &class in SpaceClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(class.sort(), Sort::Final);
        }
        assert_eq!(
            RosterClass::from(KeyClass::from(ErrorClass::Malformed)),
            RosterClass::from(ErrorClass::Malformed)
        );
        assert_eq!(
            RosterClass::from_name("StaleSeal"),
            Some(RosterClass::Key(KeyClass::StaleSeal))
        );
        assert_eq!(
            RosterClass::from_name("NoTwin").map(Class::sort),
            Some(Sort::Pending)
        );
        assert_eq!(
            RosterClass::from_name("Sealed").map(Class::sort),
            Some(Sort::Held)
        );
        assert_eq!(
            RosterClass::from_name("SelfRotation"),
            Some(RosterClass::Space(SpaceClass::SelfRotation))
        );
        assert_eq!(
            RosterClass::from_name("WrongLog").map(Class::name),
            Some("WrongLog")
        );
        assert_eq!(
            RosterClass::from_name("Late"),
            Some(RosterClass::Space(SpaceClass::Late))
        );
        assert_eq!(
            RosterClass::from_name("BadCuts").map(Class::name),
            Some("BadCuts")
        );
    }
}
