//! The hooks roster.md reserves for extensions.
//!
//! - **ext-invite-links.md** (feature `ext-invite-links`): member type 3,
//!   op 4 (`succeed`), change key 14, change key 13 on a grant of type 3,
//!   the authority of a successor, and attack (d). A core implementation
//!   holds a roster event that carries one as `ExtensionRequired`, with
//!   every event after it, exactly as it holds an event it cannot open
//!   (roster.md, "Changes"). It never judges such an event valid or void.
//! - **ext-restricted-spaces.md** (feature `ext-restricted-spaces`):
//!   descriptor kind 1, a restricted space. A core implementation does not
//!   use one: once it has read the descriptor, it holds the space's other
//!   events as `ExtensionRequired`. It treats kind 2, a carve-out, as an
//!   ordinary space (roster.md, "The space descriptor"). Every
//!   implementation applies the grant-graph rule for restricted spaces
//!   ([`crate::graph`]).
//!
//! - **Later documents** (roster.md, "The space descriptor"): descriptor
//!   kinds from 3 and keys from 5. No feature defines one: once this
//!   implementation has read such a descriptor, it holds the space's other
//!   events as `ExtensionRequired` and signs nothing there; an edge of the
//!   grant graph to such a space never counts ([`crate::graph`]).
//!
//! With feature `ext-invite-links`, the hooks of ext-invite-links.md call
//! into `crate::ext_invite_links`; with feature `ext-restricted-spaces`,
//! those of ext-restricted-spaces.md into `crate::ext_restricted_spaces`.

use crate::policy::{Descriptor, DescriptorKind};
use crate::{Limits, SpaceClass};
#[cfg(not(feature = "ext-restricted-spaces"))]
use crate::{RosterClass, across::OtherLogs, graph};
use frasil_base::ErrorClass;
use frasil_base::cbor::Value;

/// A change that uses one of ext-invite-links.md's reserved hooks: the
/// invite key's grant and removal, and the successor. Without the
/// extension, `ExtensionRequired`.
#[cfg(not(feature = "ext-invite-links"))]
pub(crate) fn reserved_change(
    _change: &Value,
    _space: Option<&[u8; 32]>,
    _limits: &Limits,
) -> Result<crate::Change, SpaceClass> {
    Err(ErrorClass::ExtensionRequired.into())
}

/// A change that uses one of ext-invite-links.md's reserved hooks: the
/// invite key's grant and removal, and the successor, read as that
/// document's "The invite grant and the successor" says.
#[cfg(feature = "ext-invite-links")]
pub(crate) fn reserved_change(
    change: &Value,
    space: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<crate::Change, SpaceClass> {
    crate::ext_invite_links::read_change(change, space, limits)
}

/// Whether a change is ext-invite-links.md's successor: op 4. Never
/// without the extension, which holds such an event before any rule reads
/// it.
pub(crate) fn is_succeed(change: &crate::Change) -> bool {
    cfg!(feature = "ext-invite-links") && change.op == crate::Op::Succeed
}

/// Whether a roster event's changes make it ext-invite-links.md's
/// successor.
pub(crate) fn is_successor(changes: &[crate::Change]) -> bool {
    changes.iter().any(is_succeed)
}

/// With ext-invite-links.md, the member whose authority a successor by
/// `author` uses: its invite key. `None` for every other event.
pub(crate) fn successor_author(
    author: &[u8; 32],
    changes: &[crate::Change],
) -> Option<crate::MemberRef> {
    is_successor(changes).then_some(crate::MemberRef {
        kind: crate::MemberType::Invite,
        id: *author,
    })
}

/// With ext-invite-links.md, whether a change names `device`'s keys
/// beyond a grant of it as a device: a grant of it as an invite key, or a
/// successor that grants it as a device.
pub(crate) fn names_invite_device(change: &crate::Change, device: &crate::MemberRef) -> bool {
    let as_invite = crate::MemberRef {
        kind: crate::MemberType::Invite,
        id: device.id,
    };
    cfg!(feature = "ext-invite-links")
        && device.kind == crate::MemberType::Device
        && ((change.op == crate::Op::Grant && change.member == Some(as_invite))
            || (is_succeed(change) && change.member == Some(*device)))
}

/// Whether this implementation uses a space of this descriptor: every
/// space but a restricted one without ext-restricted-spaces.md, and one
/// whose descriptor a later document defines.
///
/// # Errors
///
/// `ExtensionRequired` for a restricted space without the extension, and
/// for a descriptor of a kind from 3 or with a key from 5.
pub fn check_descriptor(descriptor: &Descriptor) -> Result<(), SpaceClass> {
    if descriptor.kind.is_reserved()
        || (descriptor.kind == DescriptorKind::Restricted
            && !cfg!(feature = "ext-restricted-spaces"))
    {
        return Err(ErrorClass::ExtensionRequired.into());
    }
    Ok(())
}

/// The effective membership of a restricted space, which
/// ext-restricted-spaces.md narrows by its parent's. `ExtensionRequired`
/// without that extension.
#[cfg(not(feature = "ext-restricted-spaces"))]
pub(crate) fn restricted_membership(
    _spaces: &std::collections::BTreeMap<frasil_events::EventId, graph::SpaceGrants>,
    _persons: &std::collections::BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    _space: frasil_events::EventId,
    _verdicts: &graph::Verdicts,
    _stack: &mut Vec<frasil_events::EventId>,
) -> Result<std::collections::BTreeMap<[u8; 32], graph::Reach>, SpaceClass> {
    Err(ErrorClass::ExtensionRequired.into())
}

/// The effective membership of a restricted space, narrowed by its
/// parent's (ext-restricted-spaces.md, "Membership of a restricted
/// space").
#[cfg(feature = "ext-restricted-spaces")]
pub(crate) use crate::ext_restricted_spaces::restricted_membership;

/// Whether a space's parent lets a replica judge it: always, without
/// ext-restricted-spaces.md, which holds a restricted space's events as
/// `ExtensionRequired` before this runs.
#[cfg(not(feature = "ext-restricted-spaces"))]
pub(crate) fn check_parent(
    _descriptor: &Descriptor,
    _others: &OtherLogs<'_>,
) -> Result<(), RosterClass> {
    Ok(())
}

/// Whether a space's parent lets a replica judge it
/// (ext-restricted-spaces.md, "The parent of a restricted space").
#[cfg(feature = "ext-restricted-spaces")]
pub(crate) use crate::ext_restricted_spaces::check_parent;
