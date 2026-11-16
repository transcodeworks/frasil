//! What an invite key receives (ext-invite-links.md, "Keys", feature
//! `ext-invite-links`), and whether it counts as inside in a key graph
//! rooted at a checkpoint.
//!
//! An invite key's bundle holds the content key; the upload seed whatever
//! its level, so that its claimant can store its successor and its list;
//! and the grant seed unless the invite carries `session`, since it
//! propagates as its claimant will. Every bundle is 97 bytes, so a peer
//! cannot tell an invite key's wrap from any other.

use crate::bundle::Slots;
use crate::checkpoint::Side;

/// What an invite key's bundle of a state carries: the content key, the
/// upload seed, and the grant seed when the invite propagates (it carries no
/// `session`).
pub fn invite_bundle_contents(propagates: bool) -> Slots {
    Slots {
        content: true,
        upload: true,
        grant: propagates,
    }
}

/// What a replica rooted at a checkpoint knows of the successors of an
/// invite key that the checkpoint's record lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvitePast {
    /// No successor of the key, valid or void, is in the checkpoint's past:
    /// the invite was open when the checkpoint fixed its record.
    Unclaimed,
    /// A successor of the key is in the checkpoint's past. A valid one
    /// would have put the key out of the record, so it was void: raced, or
    /// held. Its signer, or a racer, holds the link's secret.
    Claimed,
    /// The replica cannot tell: it forgot the past without noting it, or
    /// started from the checkpoint.
    Unknown,
}

/// A successor of an invite key, as a key graph rooted at a checkpoint
/// reads it: where it stands, and its verdict there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Successor {
    /// Where it stands against the checkpoint.
    pub side: Side,
    /// Valid in the checkpoint's world.
    pub valid: bool,
    /// Void as `ClaimRaced` there.
    pub raced: bool,
}

/// Whether an invite key that the record of the checkpoint in effect lists
/// counts as inside the world (ext-invite-links.md, "Keys", "Inside";
/// roster.md, "Other logs and extensions"; keys.md, "Keys after a
/// checkpoint"), so that rotations after the checkpoint wrap for it:
///
/// - a successor in the world that is valid or void as `ClaimRaced` puts it
///   out, as without a checkpoint; so does a valid removal of it there
///   (`removed`);
/// - a late successor puts nothing out: it is void, and its claimant claims
///   again after the checkpoint, wrapped for as the key until then;
/// - a successor in the checkpoint's past did not put the key out of the
///   record, so it was void, and a holder of the secret signed it: the key
///   counts as outside, and so it does when the replica cannot tell
///   ([`InvitePast::Unknown`]). The world does not carry the race the full
///   past shows, and wrapping for the key would hand the world's keys to
///   every racer.
///
/// An invite key granted after the checkpoint is not in the record: the
/// rules without a checkpoint apply to it.
pub fn record_invite_inside(
    past: InvitePast,
    successors: impl IntoIterator<Item = Successor>,
    removed: bool,
) -> bool {
    if removed || past != InvitePast::Unclaimed {
        return false;
    }
    !successors
        .into_iter()
        .any(|s| s.side.in_world() && (s.valid || s.raced))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invite_key_always_gets_the_upload_seed() {
        assert_eq!(invite_bundle_contents(true).flags(), 0x07);
        assert_eq!(invite_bundle_contents(false).flags(), 0x03);
    }

    #[test]
    fn a_record_invite_key_across_a_checkpoint() {
        let late = Successor {
            side: Side::Late,
            valid: false,
            raced: false,
        };
        let claim = Successor {
            side: Side::After,
            valid: true,
            raced: false,
        };
        let raced = Successor {
            valid: false,
            raced: true,
            ..claim
        };
        // An open invite stays open across the checkpoint; a late claim
        // changes nothing.
        assert!(record_invite_inside(InvitePast::Unclaimed, [], false));
        assert!(record_invite_inside(InvitePast::Unclaimed, [late], false));
        // A claim or a race after it puts the key out, as does a revocation.
        assert!(!record_invite_inside(
            InvitePast::Unclaimed,
            [late, claim],
            false
        ));
        assert!(!record_invite_inside(InvitePast::Unclaimed, [raced], false));
        assert!(!record_invite_inside(InvitePast::Unclaimed, [], true));
        // A claim before it, or a past the replica cannot see, keeps it out.
        assert!(!record_invite_inside(InvitePast::Claimed, [], false));
        assert!(!record_invite_inside(InvitePast::Unknown, [], false));
    }
}
