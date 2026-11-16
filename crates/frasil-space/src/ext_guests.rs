//! Guests in the roster (ext-guests.md, feature `ext-guests`).
//!
//! A guest, a device member granted with `session`, is core: it never
//! propagates and never holds a grant key. This module adds what
//! ext-guests.md defines on top of the roster:
//!
//! - the guest preset and the capability `frasil.nothing-at-rest`, which
//!   narrows ("The guest preset"); the roster's meet keeps a narrowing
//!   capability if any concurrent grant has it;
//! - ending a session in one roster event, and the administering device's
//!   `session_expiry` ("Ending a session"):
//!
//! ```text
//! session_expiry(expires_at, first_sight, now):
//!   1. Its wall clock is known and now.W >= expires_at.            Remove
//!   2. lower(first_sight, now) >= 2,592,000.                       Remove
//!   3. Otherwise.                                                  Open
//! ```
//!
//! - an administering device's checks of a leave request against the
//!   merged roster, steps 4 to 8 of "A leave request" ([`check_leave`]),
//!   and the rank delay of step 9 ([`rank_delay`]); the request's format
//!   and steps 1 to 3 are `frasil-admission`'s;
//! - which events follow this device's own, and `followed` ("Followed"),
//!   which the writer's decision reads; the decision itself is
//!   `frasil-units`'.
//!
//! The content name `frasil/leave-request` is `frasil-transport`'s, offer
//! key 13 `frasil-admission`'s and `state` key 3 `frasil-store`'s, each
//! under the same feature. Replicas run no check for the capability, and no
//! replica reads a clock.

use crate::keygraph::rank::{delay, rank_order};
use crate::{
    Capability, CapabilityMode, Change, DeviceKeys, HistoryMode, Level, MemberRef, MemberState,
    MemberType, Op, Roster, Space, Via,
};
use frasil_base::collect::CollectMap;
use frasil_base::time::{Reading, check_expiry, lower};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};

/// The capability that asks the guest's client to keep the space in
/// memory only. It narrows.
pub const NOTHING_AT_REST: &str = "frasil.nothing-at-rest";

/// The bytes of a session, drawn at random per session by the application.
pub const SESSION_BYTES: usize = 16;

/// `session_lifetime`'s maximum, 30 days (overview.md, "Every timer"): how
/// long an administering device keeps a guest grant that carries
/// `expires_at` from its first sight of it, and the furthest `expires_at` a
/// guest accepts.
pub const SESSION_LIFETIME_MAX: u64 = 2_592_000;

/// `session_skew` (overview.md, "Every timer"): the guest's allowance for
/// the granter's clock.
pub const SESSION_SKEW: u64 = 60;

/// The most changes of one roster event: a session of more guests ends in
/// several events.
pub const MAX_CHANGES: usize = 256;

frasil_base::error_classes! {
    /// ext-guests.md's own classes ("Names, labels and error classes"),
    /// with every shared class.
    pub enum GuestClass {
        /// A leave request for another space.
        WrongSpace = "wrong_space", Decision;
        /// A leave request for a member not in the merged roster: roster.md's
        /// class, here an administering device's decision on the request.
        NoSuchMember = "no_such_member", Decision;
        /// A leave request signed by a device that is not the member's.
        NotTheMember = "not_the_member", Decision;
        /// A leave request whose grants are not the member's grants in
        /// force.
        Stale = "stale", Decision;
        /// A leave request for a device member at `administer`.
        MemberAdministers = "member_administers", Decision;
        /// This device has sent a leave request for its membership.
        Left = "left", Report;
        /// This device's session has ended by its own clock.
        SessionEnded = "session_ended", Report;
        /// This device has not been followed within the bounded window.
        WindowElapsed = "window_elapsed", Report;
        /// This device has no recent completed sync with an always-on peer.
        NotOnline = "not_online", Report;
    }
}

// ---------------------------------------------------------------------------
// The guest preset.

/// What a guest preset asks for, beyond the device and its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    /// `read` or `write`; never `administer`.
    pub level: Level,
    /// The session, 16 random bytes the application draws.
    pub session: [u8; SESSION_BYTES],
    /// Whether to add `frasil.nothing-at-rest`.
    pub nothing_at_rest: bool,
    /// The granter's wall clock plus `session_lifetime`, or none.
    pub expires_at: Option<u64>,
    /// The application's capabilities.
    pub capabilities: Vec<Capability>,
    /// The label, shown and never checked.
    pub label: Option<String>,
    /// `code` or `link`.
    pub via: Via,
    /// From now on, unless the administrator asks otherwise.
    pub history: HistoryMode,
}

impl Preset {
    /// A guest at `level` of `session`, from now on, by code, and nothing
    /// else.
    pub fn new(level: Level, session: [u8; SESSION_BYTES]) -> Self {
        Self {
            level,
            session,
            nothing_at_rest: false,
            expires_at: None,
            capabilities: Vec::new(),
            label: None,
            via: Via::Code,
            history: HistoryMode::FromNowOn,
        }
    }

    /// The capabilities the grant carries: the application's, with
    /// `frasil.nothing-at-rest` when asked, ascending by name.
    pub fn capabilities(&self) -> Option<Vec<Capability>> {
        let mut capabilities = self.capabilities.clone();
        if self.nothing_at_rest {
            capabilities.push(nothing_at_rest_capability());
        }
        capabilities.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        (!capabilities.is_empty()).then_some(capabilities)
    }

    /// The device grant ("The guest preset"): keys 7, 5, 2, 3, 13 and 6,
    /// with the device's keys, whose device ID is the member.
    pub fn grant(&self, keys: DeviceKeys) -> Change {
        let mut change = Change::grant_device(keys, self.level, self.history, self.via);
        change.capabilities = self.capabilities();
        change.label = self.label.clone();
        change.session = Some(self.session);
        change.expires_at = self.expires_at;
        change
    }
}

/// `frasil.nothing-at-rest`, narrowing.
pub fn nothing_at_rest_capability() -> Capability {
    Capability {
        name: NOTHING_AT_REST.to_owned(),
        mode: CapabilityMode::Narrows,
    }
}

/// Whether a member's state is a guest's: a member granted with `session`.
pub fn is_guest(state: &MemberState) -> bool {
    state.session.is_some()
}

/// Whether a member's state carries `frasil.nothing-at-rest`. The meet of
/// concurrent grants keeps it if any grant has it.
pub fn nothing_at_rest(state: &MemberState) -> bool {
    state.capabilities.contains(&nothing_at_rest_capability())
}

// ---------------------------------------------------------------------------
// Ending a session.

/// The removals that end a session: one for each member in with this
/// `session`, in the order of their references, at most 256 to an event.
/// Each inner list is one roster event's changes, which rotates once.
pub fn end_session(roster: &Roster, session: &[u8; SESSION_BYTES]) -> Vec<Vec<Change>> {
    let removals: Vec<Change> = roster
        .members_in()
        .filter(|(_, state)| state.session.as_ref() == Some(session))
        .map(|(member, _)| Change::remove(*member))
        .collect();
    removals
        .chunks(MAX_CHANGES)
        .map(<[Change]>::to_vec)
        .collect()
}

/// `session_expiry`'s decision for one guest grant in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionExpiry {
    /// The grant stays.
    Open,
    /// The guest is due for removal.
    Remove,
}

impl SessionExpiry {
    /// The decision's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Remove => "Remove",
        }
    }
}

/// `session_expiry(expires_at, first_sight, now)` at an administering
/// device, for one guest grant in force. A grant without `expires_at` is
/// never removed by clock. `first_sight` is the device's first sight of the
/// event that grants the guest: its admission, or for a guest admitted by
/// link its successor.
pub fn session_expiry(
    expires_at: Option<u64>,
    first_sight: &Reading,
    now: &Reading,
) -> SessionExpiry {
    let Some(expires_at) = expires_at else {
        return SessionExpiry::Open;
    };
    if now.wall.is_some_and(|wall| wall >= expires_at)
        || lower(first_sight, now) >= SESSION_LIFETIME_MAX
    {
        SessionExpiry::Remove
    } else {
        SessionExpiry::Open
    }
}

/// Whether a guest is due: one of its grants in force, each `(expires_at,
/// first_sight)`, gives `Remove`.
pub fn guest_due(grants: &[(Option<u64>, Reading)], now: &Reading) -> bool {
    grants
        .iter()
        .any(|(expires_at, seen)| session_expiry(*expires_at, seen, now) == SessionExpiry::Remove)
}

/// The guest's own check of its session's `expires_at`, the writer's
/// decision step 2: `check_expiry(expires_at, its wall clock, 2,592,000,
/// session_skew)` (overview.md). An unknown wall clock is `Expired`.
///
/// # Errors
///
/// `Expired`, or `Malformed` for an `expires_at` beyond the furthest.
pub fn check_session_expiry(
    expires_at: u64,
    now_wall: Option<u64>,
) -> Result<(), frasil_base::ErrorClass> {
    check_expiry(expires_at, now_wall, SESSION_LIFETIME_MAX, SESSION_SKEW)
}

/// The `expires_at` of each of a member's grants in force, by the granting
/// event: the change that grants it there, or for a guest admitted by link
/// its successor, the invite's ("The guest preset").
pub fn grant_expiries(space: &Space<'_>, member: &MemberRef) -> BTreeMap<EventId, Option<u64>> {
    let Some(state) = space.roster().state(member) else {
        return BTreeMap::new();
    };
    state
        .grants
        .iter()
        .map(|&grant| (grant, grant_expiry(space, grant, member)))
        .collect_map()
}

fn grant_expiry(space: &Space<'_>, grant: EventId, member: &MemberRef) -> Option<u64> {
    let changes = space.opened(grant)?.changes();
    let change = changes.iter().find(|c| c.member == Some(*member))?;
    match change.op {
        Op::Grant => change.expires_at,
        Op::Succeed => invite_expiry_of(space, grant),
        _ => None,
    }
}

/// The `expires_at` of the invite a successor claims: its invite key's
/// grant in the successor's past.
#[cfg(feature = "ext-invite-links")]
fn invite_expiry_of(space: &Space<'_>, successor: EventId) -> Option<u64> {
    let key = space.log().event(successor)?.author().0;
    let invite = crate::ext_invite_links::invite_member(key);
    space
        .valid_roster()
        .iter()
        .filter(|&&e| space.log().precedes(e, successor))
        .filter_map(|&e| space.opened(e))
        .flat_map(|opened| opened.changes())
        .find(|c| c.op == Op::Grant && c.member == Some(invite))
        .and_then(|c| c.expires_at)
}

/// Without ext-invite-links.md no successor is ever valid.
#[cfg(not(feature = "ext-invite-links"))]
fn invite_expiry_of(_space: &Space<'_>, _successor: EventId) -> Option<u64> {
    None
}

/// The earliest `expires_at` of a member's grants in force, which the
/// writer's decision step 2 checks; `None` when none carries one.
pub fn earliest_expiry(space: &Space<'_>, member: &MemberRef) -> Option<u64> {
    grant_expiries(space, member).into_values().flatten().min()
}

/// The rank and delay, in seconds, before `device` acts on a due guest or a
/// leave request: its rank delay (keys.md) over the space's administering
/// devices, with `trigger` (the grant's event ID, or SHA-256 of the signed
/// request). `None` for a device that does not administer.
pub fn rank_delay(
    space: &EventId,
    trigger: &[u8],
    administering: &[[u8; 32]],
    device: &[u8; 32],
    rotation_step: u64,
) -> Option<(u64, u64)> {
    let order = rank_order(space.as_bytes(), trigger, administering);
    let position = order.iter().position(|d| d == device)? as u64;
    Some((position, delay(position, rotation_step)))
}

// ---------------------------------------------------------------------------
// A leave request, at an administering device.

/// What a leave request names, once its signature has verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaveClaim<'r> {
    /// Key 2: the space.
    pub space: &'r [u8; 32],
    /// Key 3: the leaving member, a device or a person.
    pub member: &'r MemberRef,
    /// Key 4: the member's grants in force, as the leaver held them.
    pub grants: &'r [EventId],
    /// Key 6: the signing device.
    pub device: &'r [u8; 32],
}

/// "A leave request", steps 4 to 8, against the merged roster.
/// `vouches(person, device)` says whether the person's list vouches for the
/// device.
///
/// # Errors
///
/// In order: `WrongSpace`, `NoSuchMember`, `NotTheMember`, `Stale`,
/// `MemberAdministers`.
pub fn check_leave(
    space: &Space<'_>,
    claim: &LeaveClaim<'_>,
    vouches: impl Fn(&[u8; 32], &[u8; 32]) -> bool,
) -> Result<(), GuestClass> {
    // 4.
    if claim.space != space.log().id().as_bytes() {
        return Err(GuestClass::WrongSpace);
    }
    // 5.
    let state = space
        .roster()
        .state(claim.member)
        .ok_or(GuestClass::NoSuchMember)?;
    // 6.
    let theirs = match claim.member.kind {
        MemberType::Device => claim.member.id == *claim.device,
        MemberType::Person => vouches(&claim.member.id, claim.device),
        _ => false,
    };
    if !theirs {
        return Err(GuestClass::NotTheMember);
    }
    // 7.
    let named: BTreeSet<EventId> = claim.grants.iter().copied().collect();
    if named != state.grants {
        return Err(GuestClass::Stale);
    }
    // 8.
    if claim.member.kind == MemberType::Device && state.level == Level::Administer {
        return Err(GuestClass::MemberAdministers);
    }
    Ok(())
}

/// A device's keys as far as the roster goes: those its grant carries, if
/// it is a device member in. A person's device's keys are in that person's
/// list, which the caller holds; any source serves, by hash.
pub fn roster_keys(space: &Space<'_>, device: &DeviceId) -> Option<DeviceKeys> {
    let state = space.roster().state(&MemberRef::device(*device))?;
    Some(DeviceKeys::clone(state.keys.as_ref()?))
}

// ---------------------------------------------------------------------------
// Followed.

/// For each event of `device` in the view, the events that follow it: valid
/// events of the space, by other devices, with it in their past, in
/// canonical order. A valid event's author reaches the space at its place;
/// void, refused and forked events do not count.
pub fn followers(space: &Space<'_>, device: &DeviceId) -> BTreeMap<EventId, Vec<EventId>> {
    let log = space.log();
    let order = log.canonical_in(space.view());
    let authored = |id: EventId| log.event(id).map(|e| *e.author());
    let mut out = BTreeMap::new();
    for &own in order.iter().filter(|&&i| authored(i) == Some(*device)) {
        let by: Vec<EventId> = order
            .iter()
            .copied()
            .filter(|&i| {
                authored(i).is_some_and(|a| a != *device)
                    && space.is_valid(i)
                    && log.precedes(own, i)
            })
            .collect();
        out.insert(own, by);
    }
    out
}

/// `followed`: this device's reading when it signed its newest event that
/// another member follows, the largest timeline among those events'
/// `signed_at` readings; at first, its first sight of its own admission.
pub fn followed(
    space: &Space<'_>,
    device: &[u8; 32],
    signed_at: &BTreeMap<EventId, Reading>,
    admitted: Reading,
) -> Reading {
    let mut best: Option<Reading> = None;
    for (own, by) in followers(space, &DeviceId(*device)) {
        if by.is_empty() {
            continue;
        }
        if let Some(reading) = signed_at.get(&own)
            && best.is_none_or(|b| reading.timeline > b.timeline)
        {
            best = Some(*reading);
        }
    }
    best.unwrap_or(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, Sort};
    use frasil_base::time::Timer;

    #[test]
    fn the_constants_are_the_timers() {
        assert_eq!(
            Timer::SessionLifetime.spec().maximum,
            Some(SESSION_LIFETIME_MAX)
        );
        assert!(nothing_at_rest_capability().is_reserved());
        assert_eq!(GuestClass::Left.sort(), Sort::Report);
        assert_eq!(GuestClass::Stale.sort(), Sort::Decision);
    }

    #[test]
    fn expiry_follows_the_wall_clock_then_the_maximum() {
        let r = |timeline, wall| Reading {
            timeline,
            wall,
            run: 1,
        };
        assert_eq!(
            session_expiry(Some(200), &r(0, Some(100)), &r(50, Some(150))),
            SessionExpiry::Open
        );
        assert_eq!(
            session_expiry(Some(200), &r(0, Some(100)), &r(100, Some(200))),
            SessionExpiry::Remove
        );
        assert_eq!(
            session_expiry(None, &r(0, None), &r(SESSION_LIFETIME_MAX, None)),
            SessionExpiry::Open
        );
    }
}
