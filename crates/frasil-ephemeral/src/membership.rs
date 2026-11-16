//! Membership against the current view (ext-ephemeral.md, "Membership
//! against the current view").
//!
//! A frame has no place. It is judged against the receiver's current view:
//! the events of the space's log it has accepted, and the other logs it
//! holds, as they stand when the frame arrives.
//!
//! ```text
//! member(view, sender), in order:
//!   1. No evidence of a fork of sender's chain in the space's log. else Forked
//!   2. sender reaches the space at any level by some path.          in
//!   3. No path holds, and a record named sender a member.           MembershipEnded
//!   4. No path holds, and a path cannot be judged.                  Unjudgeable
//!   5. Otherwise.                                                   NotAMember
//! ```
//!
//! Each path is judged from the merged roster of the view and the other
//! logs the receiver holds (roster.md, "Grants of spaces and effective
//! membership" and "Checks across logs"); the receiver's replica does that,
//! and hands the paths' verdicts to [`member`]. The `path_*` functions say
//! what each kind of path's verdict is.

use crate::EphemeralClass;
use frasil_base::ErrorClass;

/// The sender's standing in the receiver's current view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Membership {
    /// The sender is in.
    In,
    /// The receiver holds evidence of a fork of the sender's chain in the
    /// space's log.
    Forked,
    /// No path holds, and a record the receiver holds named the sender a
    /// member of the space.
    MembershipEnded,
    /// No path holds, and one cannot be judged without a log the receiver
    /// lacks.
    Unjudgeable,
    /// No record names the sender.
    NotAMember,
}

impl Membership {
    /// Step 12's verdict: `Ok` for a sender that is in, else its class.
    ///
    /// # Errors
    ///
    /// `Forked`, `MembershipEnded`, `Unjudgeable` or `NotAMember`.
    pub fn check(self) -> Result<(), EphemeralClass> {
        match self {
            Self::In => Ok(()),
            Self::Forked => Err(ErrorClass::Forked.into()),
            Self::MembershipEnded => Err(EphemeralClass::MembershipEnded),
            Self::Unjudgeable => Err(EphemeralClass::Unjudgeable),
            Self::NotAMember => Err(ErrorClass::NotAMember.into()),
        }
    }
}

/// One path's verdict in the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Path {
    /// The path holds: the sender reaches the space by it.
    Holds,
    /// The path does not hold.
    Fails,
    /// The path cannot be judged: a log it needs is not held.
    Unjudgeable,
}

/// A device grant: it counts while it is in, with a session or without.
pub fn path_device(in_force: bool) -> Path {
    if in_force { Path::Holds } else { Path::Fails }
}

/// What the person's merged list, as the receiver holds it, says of the
/// sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListStanding {
    /// A valid add of the sender, as a device or a passkey member.
    pub added: bool,
    /// A valid revocation of it.
    pub revoked: bool,
    /// A fork of it.
    pub forked: bool,
}

/// A person grant: it counts only if the person's merged list, as the
/// receiver holds it (`None`: not held), adds the sender validly, with no
/// valid revocation and no fork of it.
pub fn path_person(list: Option<ListStanding>) -> Path {
    match list {
        None => Path::Unjudgeable,
        Some(list) if list.added && !list.revoked && !list.forked => Path::Holds,
        Some(_) => Path::Fails,
    }
}

/// A space grant: it counts only if the sender reaches the granted space,
/// and propagates there, in that space's merged roster as the receiver
/// holds it (`None`: not held; else whether it reaches and propagates).
pub fn path_space(granted: Option<bool>) -> Path {
    match granted {
        None => Path::Unjudgeable,
        Some(true) => Path::Holds,
        Some(false) => Path::Fails,
    }
}

/// The inputs of section 3.6 for one sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInputs {
    /// Step 1: the receiver holds evidence of a fork of the sender's chain
    /// in the space's log.
    pub forked: bool,
    /// Every path by which the sender may reach the space, judged.
    pub paths: Vec<Path>,
    /// A record the receiver holds named the sender a member of the space
    /// through some path.
    pub named: bool,
    /// In a restricted space: the sender's standing in the parent, by
    /// [`member`] there. `None` in any other space.
    pub parent: Option<Membership>,
}

/// `member(view, sender)`, in order.
pub fn member(inputs: &MemberInputs) -> Membership {
    // 1. Fork evidence.
    if inputs.forked {
        return Membership::Forked;
    }
    // 2. Some path holds; in a restricted space, the parent is reached too.
    if inputs.paths.contains(&Path::Holds) {
        return match inputs.parent {
            None | Some(Membership::In) => Membership::In,
            // The space's own roster names the sender: its end, unless the
            // parent cannot be judged.
            Some(Membership::Unjudgeable) => Membership::Unjudgeable,
            Some(_) => Membership::MembershipEnded,
        };
    }
    // 3. A record named the sender.
    if inputs.named {
        return Membership::MembershipEnded;
    }
    // 4. A path that cannot be judged.
    if inputs.paths.contains(&Path::Unjudgeable) {
        return Membership::Unjudgeable;
    }
    // 5.
    Membership::NotAMember
}
