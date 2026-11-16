//! Invite links in the roster and the key graph (ext-invite-links.md,
//! feature `ext-invite-links`).
//!
//! An administrator grants an **invite key** `K`, member `[3, K]`, and
//! whoever holds the link's secret signs one **successor** as `K`: a roster
//! event whose one change, op 4, hands the invite's grant to its claimant.
//! This module fills in the hooks roster.md and keys.md reserve:
//!
//! - `read_change`: the invite grant, its removal and the successor,
//!   read and checked alone ("The invite grant and the successor");
//! - the roster at a place: `K` is out at any place that holds a valid
//!   successor it signed, and a valid successor is a grant of its claimant
//!   ("Invites in the roster", "Member state");
//! - authority at the place: a successor's own steps, an invite key
//!   granted once, and the close ("Authority");
//! - the race rule, around the resolution procedure, and the events that
//!   void a raced successor ("Raced claims");
//! - the key graph: who counts as inside, and rule 4 of entitlement
//!   ("Keys");
//! - `invite_expiry` and the administering devices' delays
//!   ("Administering devices").
//!
//! The link, the drop and the claimant's walk are `frasil-admission`'s, the
//! drop's messages `frasil-transport`'s, a peer's drops `frasil-peers'`, the
//! invite key's bundle `frasil-keys'` and the records at rest
//! `frasil-store`'s, each under the same feature.

mod change;
mod expiry;
mod keys;
mod roster;

pub(crate) use change::read_change;
pub use change::{
    CLAIMS_DEVICE, CLAIMS_PERSON, check_successor_part, invite_grant, invite_member, revoke_invite,
    successor,
};
pub use expiry::{
    InviteExpiry, LINK_LIFETIME_MAX, LINK_LIFETIME_MIN, LINK_SKEW, act_delay, check_claim_expiry,
    invite_expiry,
};
pub use keys::Succession;
pub(crate) use keys::{claimant_entitled, receiving, succession, void_as_raced};
pub use roster::{claimant, invite_grant_of, is_successor};
pub(crate) use roster::{
    invite_change_authority, put_out_invites, racers, resolve_racing, successor_authority,
    successor_state, without_standing,
};

use crate::RosterClass;

frasil_base::error_classes! {
    /// ext-invite-links.md's own classes ("Labels and error classes"), with
    /// every shared class.
    pub enum InviteClass {
        /// A successor whose author is not an invite key in the roster at
        /// its place.
        NotAnInvite = "not_an_invite", Final;
        /// A grant of an invite key already named, or a successor with a
        /// successor of its key in its past; at a claimant, an invite
        /// already claimed.
        InviteUsed = "invite_used", Final;
        /// A claimant of another type than the invite's `claims`.
        ClaimMismatch = "claim_mismatch", Final;
        /// A successor that a concurrent successor of its key voids
        /// ("Raced claims").
        ClaimRaced = "claim_raced", Final;
        /// A fetched entry that is not the link's, or grants another key.
        WrongInvite = "wrong_invite", Decision;
        /// A drop's wrap that does not open.
        NoWrap = "no_wrap", Decision;
        /// An invite entry that is not valid.
        NotInRoster = "not_in_roster", Decision;
        /// The invite key was removed.
        InviteRevoked = "invite_revoked", Decision;
        /// The invite's claims raced.
        InviteRaced = "invite_raced", Decision;
    }
}

impl InviteClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<frasil_base::ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

impl From<InviteClass> for RosterClass {
    fn from(class: InviteClass) -> Self {
        match class.shared() {
            Some(shared) => shared.into(),
            None => Self::Invite(class),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, Sort, snake_case};

    #[test]
    fn classes_follow_the_table() {
        for &class in InviteClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(
                RosterClass::from_name(class.name()),
                Some(RosterClass::from(class))
            );
        }
        assert_eq!(InviteClass::ClaimRaced.sort(), Sort::Final);
        assert_eq!(InviteClass::InviteRaced.sort(), Sort::Decision);
        assert_eq!(
            RosterClass::from(InviteClass::from(frasil_base::ErrorClass::Malformed)),
            RosterClass::from(frasil_base::ErrorClass::Malformed)
        );
    }
}
