//! Checks against the event and its place (keys.md, "Checks against the
//! event and its place").
//!
//! These read the event's changes, its sealed refs and notices, and the
//! roster `S` at its place. roster.md runs them as part of the event's
//! authority (roster events) or of the write rule (key events). This module
//! takes what roster.md knows as a [`Context`] of flags, and what the body
//! says as [`Facts`]. Each notice's own checks (keys.md, "Notices and space
//! principals") are the key graph's, not this crate's, and decide no
//! verdict.

use crate::KeyClass;
use crate::body::{Inner, VisiblePart};
use frasil_base::ErrorClass;

/// Which kind of space event it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// The genesis.
    Genesis,
    /// A roster event.
    Roster,
    /// A key event.
    Key,
    /// A checkpoint (roster.md, "Checkpoints"): a roster event that these
    /// checks take as they take a genesis (keys.md, "Keys after a
    /// checkpoint"). It rotates, as a grant rotation where its author
    /// propagates and the space is not restricted, and is no break. Unlike
    /// a genesis, its author need not propagate.
    Checkpoint,
}

/// What roster.md knows of the event at its place: keys.md's flags, the
/// event's sealed refs as they bear on notices, and the seal's staleness.
/// `me` is the event's author's member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Context {
    /// Which kind of space event it is.
    pub event: EventKind,
    /// A change removes a member that is in `S`.
    pub removes: bool,
    /// That member is `me`.
    pub removes_self: bool,
    /// The event is not self-lowering, and it removes a member other than
    /// `me` that is in `S` and propagates.
    pub removes_propagating: bool,
    /// A change sets a member that is in `S` at `write` or `administer` to
    /// `read`.
    pub lowers_to_read: bool,
    /// A change lowers `me`.
    pub lowers_self: bool,
    /// A grant has `history` 0.
    pub admits_from_now_on: bool,
    /// Such a grant carries no `session`.
    pub admits_propagating: bool,
    /// `me` is in `S` with no `session`. A genesis's author always
    /// propagates, whatever this says.
    pub author_propagates: bool,
    /// The event has sealed refs.
    pub responds: bool,
    /// The space is restricted (ext-restricted-spaces.md); a core
    /// implementation never has one.
    pub restricted: bool,
    /// For an event that does not rotate: a valid rotation in its place
    /// follows a rotation of `sealed_under` (for a roster event, counting
    /// the genesis and the valid roster events; for a key event, also the
    /// key events decided valid before it).
    pub sealed_under_stale: bool,
    /// Its sealed refs name an event of the log of a space this space
    /// grants.
    pub refs_granted: bool,
    /// Whether it carries a notice for each such space; `None` when the
    /// caller cannot tell, which holds the event `Pending`. Step 8 reads only
    /// the event's refs and notices and the roster at its place, so a
    /// replica can always tell.
    pub notice_covers: Option<bool>,
}

impl Context {
    /// A context of this kind with every flag false and the notice question
    /// answered yes.
    pub fn new(event: EventKind) -> Self {
        Self {
            event,
            removes: false,
            removes_self: false,
            removes_propagating: false,
            lowers_to_read: false,
            lowers_self: false,
            admits_from_now_on: false,
            admits_propagating: false,
            author_propagates: false,
            responds: false,
            restricted: false,
            sealed_under_stale: false,
            refs_granted: false,
            notice_covers: Some(true),
        }
    }

    /// The context of a checkpoint: it changes no member and carries no
    /// refs (roster.md, "The roster part"), so every flag but these two is
    /// false.
    pub fn checkpoint(author_propagates: bool, restricted: bool) -> Self {
        Self {
            author_propagates,
            restricted,
            ..Self::new(EventKind::Checkpoint)
        }
    }
}

/// What an opened body says that these checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Facts {
    /// The event rotates.
    pub rotates: bool,
    /// It carries `break`.
    pub is_break: bool,
    /// It is a grant rotation.
    pub grant_rotation: bool,
}

impl Facts {
    /// The facts of an opened body.
    pub fn of(visible: &VisiblePart, inner: &Inner) -> Self {
        Self {
            rotates: visible.rotates(),
            is_break: inner.is_break,
            grant_rotation: inner.grant_rotation(),
        }
    }
}

/// Runs keys.md's checks against the event and its place, in order, for a
/// body whose facts are `facts`, or `None` for an event that carries no
/// opened body.
///
/// # Errors
///
/// 1. `RotationRequired`: a genesis, a `removes`, a `lowers_to_read` and an
///    `admits_from_now_on` event rotates, unless it is self-lowering
///    (`removes_self` or `lowers_self`), which exempts the removal and the
///    demotion.
/// 2. `StaleSeal`: an event that does not rotate is sealed under its
///    author's current content state.
/// 3. `BreakRequired`: an `admits_from_now_on` event has `break`.
/// 4. `UnexpectedBreak`: `break` appears only in an `admits_from_now_on`
///    event, or in a key event that `responds`.
/// 5. `GrantKeyNotAllowed`: no grant rotation by an author that does not
///    propagate, and none in a restricted space.
/// 6. `GrantKeyRequired`: a grant rotation in a genesis, in a
///    `removes_propagating` event, in an `admits_from_now_on` event that
///    `admits_propagating`, and in a key event that `responds` and rotates.
/// 7. `UnexpectedGrantKey`: a roster event other than a genesis is a grant
///    rotation only when step 6 requires one.
///
/// A checkpoint ([`EventKind::Checkpoint`]) is taken as a genesis (keys.md,
/// "Keys after a checkpoint"): it must rotate (step 1), carries no `break`
/// (step 4), and is a grant rotation exactly when its author propagates and
/// the space is not restricted (steps 5 and 6). Step 7 does not apply to it.
/// 8. `NoticeRequired`: a key event whose sealed refs name an event of the
///    log of a space this space grants carries a notice for that space
///    (`Pending` only while the caller cannot tell).
pub fn check_context(facts: Option<Facts>, context: &Context) -> Result<(), KeyClass> {
    let rotates = facts.is_some_and(|facts| facts.rotates);
    // 1.
    let self_lowering = context.removes_self || context.lowers_self;
    let founding = matches!(context.event, EventKind::Genesis | EventKind::Checkpoint);
    let must_rotate = founding
        || context.admits_from_now_on
        || (!self_lowering && (context.removes || context.lowers_to_read));
    if must_rotate && !rotates {
        return Err(KeyClass::RotationRequired);
    }
    let Some(facts) = facts else {
        return Ok(());
    };
    // 2.
    if !facts.rotates && context.sealed_under_stale {
        return Err(KeyClass::StaleSeal);
    }
    let response = context.event == EventKind::Key && context.responds;
    // 3.
    if context.admits_from_now_on && !facts.is_break {
        return Err(KeyClass::BreakRequired);
    }
    // 4.
    if facts.is_break && !(context.admits_from_now_on || response) {
        return Err(KeyClass::UnexpectedBreak);
    }
    // 5.
    let author_propagates = context.author_propagates || context.event == EventKind::Genesis;
    if facts.grant_rotation && (context.restricted || !author_propagates) {
        return Err(KeyClass::GrantKeyNotAllowed);
    }
    // 6.
    let required = !context.restricted
        && (context.event == EventKind::Genesis
            || (context.event == EventKind::Checkpoint && context.author_propagates)
            || context.removes_propagating
            || (context.admits_from_now_on && context.admits_propagating)
            || (response && facts.rotates));
    if required && !facts.grant_rotation {
        return Err(KeyClass::GrantKeyRequired);
    }
    // 7.
    if context.event == EventKind::Roster && facts.grant_rotation && !required {
        return Err(KeyClass::UnexpectedGrantKey);
    }
    // 8.
    if context.event == EventKind::Key && context.refs_granted {
        match context.notice_covers {
            None => return Err(ErrorClass::Pending.into()),
            Some(false) => return Err(KeyClass::NoticeRequired),
            Some(true) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROTATION: Facts = Facts {
        rotates: true,
        is_break: false,
        grant_rotation: false,
    };

    #[test]
    fn a_self_removal_need_not_rotate() {
        let mut context = Context::new(EventKind::Roster);
        context.removes = true;
        context.removes_self = true;
        context.author_propagates = true;
        assert_eq!(check_context(None, &context), Ok(()));
        context.removes_self = false;
        assert_eq!(
            check_context(None, &context),
            Err(KeyClass::RotationRequired)
        );
    }

    #[test]
    fn a_genesis_is_a_grant_rotation() {
        let context = Context::new(EventKind::Genesis);
        assert_eq!(
            check_context(Some(ROTATION), &context),
            Err(KeyClass::GrantKeyRequired)
        );
        let grant = Facts {
            grant_rotation: true,
            ..ROTATION
        };
        assert_eq!(check_context(Some(grant), &context), Ok(()));
    }

    #[test]
    fn only_a_key_event_needs_a_notice() {
        let delivery = Facts {
            rotates: false,
            ..ROTATION
        };
        let mut context = Context::new(EventKind::Key);
        context.author_propagates = true;
        context.responds = true;
        context.refs_granted = true;
        context.notice_covers = Some(false);
        assert_eq!(
            check_context(Some(delivery), &context),
            Err(KeyClass::NoticeRequired)
        );
        context.event = EventKind::Roster;
        assert_eq!(check_context(Some(delivery), &context), Ok(()));
    }

    #[test]
    fn a_checkpoint_is_taken_as_a_genesis() {
        let grant = Facts {
            grant_rotation: true,
            ..ROTATION
        };
        let delivery = Facts {
            rotates: false,
            ..ROTATION
        };
        let broken = Facts {
            is_break: true,
            ..grant
        };
        let propagating = Context::checkpoint(true, false);
        assert_eq!(check_context(Some(grant), &propagating), Ok(()));
        assert_eq!(
            check_context(Some(ROTATION), &propagating),
            Err(KeyClass::GrantKeyRequired)
        );
        assert_eq!(
            check_context(Some(delivery), &propagating),
            Err(KeyClass::RotationRequired)
        );
        assert_eq!(
            check_context(None, &propagating),
            Err(KeyClass::RotationRequired)
        );
        assert_eq!(
            check_context(Some(broken), &propagating),
            Err(KeyClass::UnexpectedBreak)
        );
        // An author that does not propagate, and any author in a restricted
        // space, makes a checkpoint that is no grant rotation; unlike a
        // genesis, the flag is read.
        for context in [
            Context::checkpoint(false, false),
            Context::checkpoint(true, true),
        ] {
            assert_eq!(check_context(Some(ROTATION), &context), Ok(()));
            assert_eq!(
                check_context(Some(grant), &context),
                Err(KeyClass::GrantKeyNotAllowed)
            );
        }
        // Step 7 is a roster event's, never a checkpoint's.
        let mut roster = propagating;
        roster.event = EventKind::Roster;
        assert_eq!(
            check_context(Some(grant), &roster),
            Err(KeyClass::UnexpectedGrantKey)
        );
    }
}
