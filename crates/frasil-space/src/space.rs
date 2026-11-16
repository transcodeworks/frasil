//! A space's log resolved in a view (roster.md, "The order of
//! verification").
//!
//! A replica judges a space's log in this order, each step over what the
//! previous ones accepted:
//!
//! 1. Each event's envelope and placement (events.md): the caller's
//!    [`Log`].
//! 2. For a space event, its visible part and its body, opened or held
//!    ("The event alone", steps 2 to 10: [`ScreenedLog`]).
//! 3. The records that name each author's ML-DSA-65 key, then each
//!    signature (step 11).
//! 4. The roster events, by the resolution procedure
//!    ([`crate::resolution`]), with the twins the skeleton gives.
//! 5. Each key event, once, in canonical order, by the write rule.
//! 6. Each unit, anchor, writer request and event of an ignorable kind, by
//!    the write rule and "Anchors, storage events and strangers' events".
//!
//! **Held events** ("Space events a replica cannot open"). A space event
//! this replica cannot open (`Sealed`), holds for an extension
//! (`ExtensionRequired`) or refuses as `BadSeal`, a unit whose seal does
//! not open, a key event or unit whose refs name an event this replica does
//! not hold (the write rule, step 0), and every event with any of them in
//! its past (`Pending`), are judged as if not received; their signatures
//! still count as chain evidence. A roster event's refs never hold it.
//!
//! **The write rule.** A unit or key event `u` by device `d` needs `write`.
//! After "The event alone"'s envelope and signature checks (and, for a
//! unit, its seal opening), in order:
//!
//! ```text
//! 0. Every ref u carries names an event this replica holds.       else Pending (held)
//! 1. d's fork point is above u.seq.                               else Forked
//! 2. The paths through which d writes at u's place: at least one. else NotAWriter
//!                                                                      (Pending if a path cannot be judged;
//!                                                                       Dropped for a stranger)
//! 3. A key event: not every path is waiting: a person grant whose
//!    list holds d as rooted in a recovery agent and not confirmed,
//!    or a space through which d reaches it only by such paths.   else WaitingDevice
//! 4. Drop each path whose write a valid roster event concurrent
//!    with u ends. At least one left.                              else RefusedByRemoval
//! 5. Drop each path through a person or a space that another log
//!    has ended for d, where some response does not have u in its
//!    past. For a key event, only responses decided valid before
//!    it count. At least one left.                                 else RefusedAfterResponse
//! 6. A key event: keys.md's checks against the event and its
//!    place.                                                       else that class
//! 7. u is valid.
//! ```
//!
//! Key events are decided first, once each, in canonical order: a key event
//! counts as responses only roster events and the key events decided valid
//! before it, a least fixed point that nothing revisits. Then units,
//! anchors, writer requests and events of ignorable kinds, against every
//! valid response.
//!
//! The key graph proper (notices, taking keys, heals) is keys.md's
//! ([`crate::keygraph`]): the write rule's step 6 runs keys.md's checks
//! against the event and its place, with step 8 through the [`Notices`]
//! hook. A notice's own checks decide no verdict.
//!
//! **Partial replicas** (units.md, "Partial replicas"). A replica that
//! holds the space's frame and only some streams resolves its view with
//! [`Replica::Partial`] ([`Space::resolve_as`]). It judges a unit or key
//! event by the write rule in proven order ([`Log::proves_before`]): its
//! place is the valid roster events proven in its past, and a verdict that
//! depends on an order it has not proven is `Pending`, never applied. So a
//! unit concurrent with its writer's removal, which a full replica refuses
//! (`RefusedByRemoval`), it holds pending. It resolves the roster only when
//! every two contested roster events are proven ordered or of known heights
//! both, since the roster orders concurrent events by height; until then
//! every event of its view but the genesis is pending, and
//! [`Space::heights_wanted`] names what it fetches to learn the heights.
//!
//! **Checkpoints** (roster.md, "Checkpoints"). [`Space::resolve_checkpointed`]
//! takes the verdicts decided before the procedure ([`Checkpointing`]): each
//! checkpoint's own, judged on its past alone, and those of events whose
//! cuts do not match or whose parents are mixed. A valid checkpoint takes
//! no part in the contest and counts as a valid roster event of every place
//! that holds it. With a [`WorldRoot`], the log is the world of a
//! checkpoint: the checkpoint is its root and stands for the genesis, the
//! record's members its grants and the record's policy its policy, heights
//! count from it, an author the record shows forked stays forked, and one
//! that signs at or below its tip in the record forks there (3.15.5 The
//! world after a checkpoint). [`crate::checkpoint`] decides which world
//! judges which event.
//!
//! **A later document's descriptor** (roster.md, "The space descriptor").
//! A genesis whose descriptor is of a kind from 3, or carries a key from 5,
//! holds every other event of the view as `ExtensionRequired`.
//!
//! **Rules this replica lacks** (roster.md, 3.16). A roster part of a type
//! from 3, by an author with standing in its past, is held as
//! `ExtensionRequired` with every event of the view outside its past; one
//! whose author has none is void (`NotAnAdministrator`).

mod partial;

use crate::across::{GrantedSpace, GranteeRotation, OtherLogs, PathsFor};
use crate::change::{Change, Op};
use crate::graph::{
    Edge, GrantInForce, GrantTarget, Path, Reach, SpaceGrants, Verdicts, combine, edge_verdicts,
};
use crate::member::{CapabilityMode, Level, MemberRef, MemberType};
use crate::policy::Policy;
use crate::resolution::{Facts, Judge};
use crate::screen::{Body, Keyring, Opened, Records, ScreenedLog, Signature};
use crate::state::{PlaceCache, Places, Roster, RosterLog, WorldRoot};
use crate::{Limits, RosterClass, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, KeyRing, KeySource, KeysCommitment};
use frasil_events::{Event, EventId, ForkPoints, Log, Ref, kind};
use frasil_keys::context::{Context, EventKind, check_context};
use frasil_peers::skeleton::{Skeleton, SkeletonParts};
use frasil_peers::twins::{Bound, TwinChecks};
use frasil_resolve::How;
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

/// What units.md tells the roster of a unit whose signature verified
/// (units.md, "A unit, at a member", steps 11 to 14): its seal opening and
/// its sealed refs. The units crate implements it.
pub trait UnitBodies {
    /// A unit's seal and inner part.
    fn open(&self, unit: &Event) -> UnitBody;

    /// List events carried by this system-stream unit, irrespective of its verdict.
    fn list_copy(&self, _unit: &Event) -> Vec<Event> {
        Vec::new()
    }

    /// List events carried by the copies this reader holds, including
    /// copies outside a checkpoint's world.
    fn held_list_copies(&self, log: &Log) -> Vec<Event> {
        log.events()
            .flat_map(|event| self.list_copy(event))
            .collect()
    }

    /// List events at `event`, including copies retained before a checkpoint
    /// and list events supplied at a newcomer's base. `None` is reserved
    /// for abstract histories that place every held list event before the log.
    fn list_events_at(&self, log: &Log, event: EventId) -> Option<Vec<EventId>> {
        Some(
            log.events()
                .filter(|copy| copy.id() == event || log.precedes(copy.id(), event))
                .flat_map(|copy| self.list_copy(copy).into_iter().map(|e| e.id()))
                .collect(),
        )
    }
}

/// A unit's seal and inner part, as units.md reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitBody {
    /// It opened: its sealed refs, ascending.
    Opened(Vec<Ref>),
    /// It is held (`Pending` at step 11, `Sealed` at step 12 or 13 under a
    /// provisional key), with every event after it.
    Held(RosterClass),
    /// It is void with this class: `BadSeal` at step 13 under a key derived
    /// from rotation keys that matched, or a class of step 14 (units.md, "A
    /// unit, at a member"). A unit that fails steps 4 to 10, which drop it,
    /// also reads as void.
    Void(RosterClass),
}

/// Whether this replica checks twins (roster.md, "The twin").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Twins {
    /// Through the skeleton of the space's own log, by `frasil-peers`'
    /// replica checks.
    Skeleton,
    /// Taken as passing, as a replica that models no skeleton does: the
    /// roster vectors' histories carry no storage events and no key 15.
    Assumed,
}

/// Which of keys.md's checks against the event and its place the write
/// rule runs on a key event (roster.md, "The write rule", step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyEventChecks {
    /// Every check of keys.md, "Checks against the event and its place",
    /// with the flags the roster gives; the notice check is the key
    /// graph's.
    Context,
    /// Only `StaleSeal`, as the reference's roster resolution does: the
    /// roster vectors' key events carry stand-in payloads that pass keys.md's
    /// structural checks only.
    StaleSeal,
}

/// What keys.md's step 8 and notice checks read of one space event at its
/// place ("Checks against the event and its place", "Notices and space
/// principals").
#[derive(Debug, Clone)]
pub struct NoticeQuery<'q> {
    /// The event.
    pub event: EventId,
    /// Its author.
    pub author: [u8; 32],
    /// Its opened body: its sealed refs and notices.
    pub opened: &'q Opened,
    /// The spaces the roster at its place grants.
    pub granted: BTreeSet<EventId>,
    /// The events of other logs that valid events at its place name in
    /// their sealed refs, its own included.
    pub named: BTreeSet<Ref>,
}

/// The notice checks' answer for one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeAnswer {
    /// Step 8: it is a key event whose sealed refs name an event of the
    /// log of a space this space grants.
    pub refs_granted: bool,
    /// Step 8: whether it carries a notice for each such space. `None`, from
    /// a hook that cannot tell, holds the event `Pending`;
    /// [`GrantedNotices`](crate::keygraph::GrantedNotices) always tells.
    pub covers: Option<bool>,
    /// Each notice's own outcome, by "Notices and space principals": the
    /// first that admits nothing at this replica. It decides no verdict.
    pub notices: Result<(), RosterClass>,
}

impl Default for NoticeAnswer {
    fn default() -> Self {
        Self {
            refs_granted: false,
            covers: Some(true),
            notices: Ok(()),
        }
    }
}

/// keys.md's notice checks, which the key graph runs: "Checks against the
/// event and its place", step 8, with "Notices and space principals"
/// ([`crate::keygraph::GrantedNotices`]).
pub trait Notices {
    /// The checks for one space event at its place.
    fn check(&self, query: &NoticeQuery<'_>) -> NoticeAnswer;
}

/// Runs keys.md's checks against the event and its place: steps 1 to 8 on
/// the context, with the key graph's answer for step 8. A notice's own
/// outcome decides no verdict.
pub(crate) fn check_with_notices(
    notices: Option<&dyn Notices>,
    query: &NoticeQuery<'_>,
    mut context: Context,
) -> Result<(), RosterClass> {
    let answer = notices.map(|n| n.check(query)).unwrap_or_default();
    if answer.refs_granted {
        context.refs_granted = true;
        context.notice_covers = answer.covers;
    }
    check_context(Some(query.opened.facts()), &context)?;
    Ok(())
}

/// The spaces a roster grants: its space members.
pub(crate) fn granted_spaces(roster: &Roster) -> BTreeSet<EventId> {
    roster
        .members_in()
        .filter(|(m, _)| m.kind == MemberType::Space)
        .map(|(m, _)| EventId(m.id))
        .collect()
}

/// What a space's resolution reads beyond its own log.
#[derive(Clone, Copy)]
pub struct Options<'a> {
    /// The keys this replica holds to open space events.
    pub keys: &'a Keyring,
    /// The limits.
    pub limits: Limits,
    /// The other logs it reads: persons' lists and granted spaces.
    pub others: &'a OtherLogs<'a>,
    /// units.md's reading of units.
    pub units: &'a dyn UnitBodies,
    /// Whether it checks twins.
    pub twins: Twins,
    /// Which checks against the event and its place a key event runs.
    pub key_checks: KeyEventChecks,
    /// The key graph's notice checks, normally
    /// [`GrantedNotices`](crate::keygraph::GrantedNotices) over `others`;
    /// `None` skips them, taking no event's refs to name a granted space's
    /// log, as the roster vectors' stand-in payloads need.
    pub notices: Option<&'a dyn Notices>,
}

impl core::fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options")
            .field("limits", &self.limits)
            .field("others", &self.others)
            .field("twins", &self.twins)
            .field("key_checks", &self.key_checks)
            .finish_non_exhaustive()
    }
}

/// Which replica judges a view (units.md, "Partial replicas").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Replica {
    /// A full replica: it holds every event of the log, or a stub of it,
    /// and judges in causal order.
    #[default]
    Full,
    /// A partial replica: it holds the space's frame and the streams it
    /// opens, places events by witnessed parents and judges the write rule
    /// in proven order.
    Partial,
}

/// How a valid event is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Valid {
    /// The genesis.
    Genesis,
    /// By the rules: propagation, or the write rule.
    Rules,
    /// By the resolution's agreement step.
    Agreed,
    /// By the resolution's seniority pick.
    Seniority,
    /// Kept and chained with no effect of its own: an anchor, a skeleton
    /// event, an event of an ignorable kind.
    Kept,
    /// A checkpoint, valid on its own past alone (roster.md, 3.15.2 A
    /// checkpoint's validity), or the root of a checkpoint's world.
    Checkpoint,
}

/// What [`Space::resolve_checkpointed`] takes beyond a plain resolution
/// (roster.md, "Checkpoints"): the verdicts decided before the procedure,
/// and the world's root when the log is a checkpoint's world.
#[derive(Debug, Clone, Default)]
pub struct Checkpointing {
    /// Verdicts decided before the procedure: each checkpoint's own, and
    /// `BadCuts`, `MixedCut` and the holds of what follows a checkpoint
    /// whose record this replica cannot read. A verdict of steps 2 to 11
    /// comes first. A held class (`Sealed`, `Pending`) holds what follows
    /// the event too.
    pub presets: BTreeMap<EventId, Status>,
    /// The root of the checkpoint's world, when the log is one.
    pub world: Option<WorldRoot>,
}

/// An event's status in a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Valid.
    Valid(Valid),
    /// Void, held, pending or dropped, with its class and, when an event
    /// voids it, that event (an attacker, the event that ends its write, or
    /// a response).
    Void {
        /// The class.
        class: RosterClass,
        /// The event that voids it, if one does.
        by: Option<EventId>,
    },
}

impl Status {
    /// Whether the event is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    /// A void status with this class and no event that voids it.
    pub fn void_with(class: impl Into<RosterClass>) -> Self {
        Self::void(class)
    }

    /// A void status with this class, voided by `by`.
    pub fn void_by(class: impl Into<RosterClass>, by: EventId) -> Self {
        Self::by(class, by)
    }

    /// The class of an event that is not valid.
    pub fn class(&self) -> Option<RosterClass> {
        match self {
            Self::Valid(_) => None,
            Self::Void { class, .. } => Some(*class),
        }
    }

    fn void(class: impl Into<RosterClass>) -> Self {
        Self::Void {
            class: class.into(),
            by: None,
        }
    }

    fn by(class: impl Into<RosterClass>, by: EventId) -> Self {
        Self::Void {
            class: class.into(),
            by: Some(by),
        }
    }
}

/// `refused_unit`'s decision (roster.md, "What replicas derive").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Retention {
    /// Keep the unit's content.
    Keep,
    /// The replica may drop its content under compaction.
    MayDrop,
}

/// How long a replica keeps a refused unit's content (roster.md, "Keeping
/// refused units"):
///
/// ```text
/// refused_unit(own, stable, first_sight, now, gap_key_timeout):
///   1. own: this device is the unit's author.                         Keep
///   2. stable: the refusing event is stable.                          MayDrop
///   3. lower(first_sight, now) >= gap_key_timeout.                    MayDrop
///   4. Otherwise.                                                     Keep
/// ```
pub fn refused_unit(
    own: bool,
    stable: bool,
    first_sight: &frasil_base::time::Reading,
    now: &frasil_base::time::Reading,
    gap_key_timeout: u64,
) -> Retention {
    if own {
        Retention::Keep
    } else if stable || frasil_base::time::lower(first_sight, now) >= gap_key_timeout {
        Retention::MayDrop
    } else {
        Retention::Keep
    }
}

/// The records step 11 reads: the other logs', and the skeleton's
/// pseudonyms when this replica checks twins.
struct SpaceRecords<'r> {
    others: &'r OtherLogs<'r>,
    skeleton: Option<&'r Skeleton<'r>>,
    /// The keys of a checkpoint's world's root: its record's device
    /// members'.
    root_keys: Option<&'r KeyRing>,
}

impl KeySource for SpaceRecords<'_> {
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys> {
        if let Some(keys) = self.root_keys.and_then(|ring| ring.get(kc)) {
            return Some(keys.clone());
        }
        self.others.hybrid_keys(kc).or_else(|| {
            let skeleton = self.skeleton?;
            skeleton
                .pseudonyms()
                .filter_map(|(pseudonym, _)| skeleton.pseudonym_key(pseudonym))
                .find(|keys| keys.commitment() == kc)
                .cloned()
        })
    }

    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys> {
        if let Some(keys) = self.root_keys.and_then(|ring| ring.device_keys(id)) {
            return Some(keys);
        }
        self.others.device_keys(id).or_else(|| {
            self.skeleton
                .and_then(|skeleton| skeleton.pseudonym_keys(id))
                .cloned()
        })
    }
}

impl Records for SpaceRecords<'_> {
    fn names(&self, device: &DeviceId) -> bool {
        self.root_keys
            .is_some_and(|ring| ring.device_keys(device).is_some())
            || self.others.names(device)
    }

    fn vouches_for(&self, pseudonym: &DeviceId) -> bool {
        self.skeleton
            .is_some_and(|skeleton| skeleton.pseudonym_keys(pseudonym).is_some())
    }
}

/// A space's log resolved in a view: every event's status, the roster, the
/// space policy, and what replicas derive from them.
pub struct Space<'a> {
    log: &'a Log,
    pub(crate) options: Options<'a>,
    replica: Replica,
    view: BTreeSet<EventId>,
    screened: ScreenedLog,
    cache: PlaceCache,
    skeleton: Option<Skeleton<'a>>,
    forks: ForkPoints,
    statuses: BTreeMap<EventId, Status>,
    /// The sealed refs of each opened key event, roster event and unit.
    refs: BTreeMap<EventId, Vec<Ref>>,
    /// Units whose seals did not open.
    unopened: BTreeSet<EventId>,
    contested: Vec<EventId>,
    valid_roster: BTreeSet<EventId>,
    roster: Rc<Roster>,
    policy: Policy,
    valid_keys: BTreeSet<EventId>,
    writers: OnceCell<BTreeSet<[u8; 32]>>,
    /// [`GrantedSpace::unwaiting_writers`], found once.
    unwaiting: OnceCell<BTreeSet<[u8; 32]>>,
    /// For each valid roster event, in canonical order, the devices that
    /// write and propagate at its place and no longer after it: what
    /// [`GrantedSpace::ends`] reads of this space's own roster, found once.
    ended: OnceCell<Vec<(EventId, BTreeSet<[u8; 32]>)>>,
    /// The duels' shields among the contested events (roster.md, 3.5.2
    /// What attacks what), found once.
    shields: OnceCell<crate::attacks::Shields>,
    /// The space events in each event's past, found once over the view
    /// in canonical order: what [`place_of`](Space::place_of) reads.
    space_past: OnceCell<Option<SpacePast>>,
    /// At a full replica whose log has no witness: the events held, and
    /// those with a held event in their past.
    after_held: BTreeSet<EventId>,
    /// Likewise, the roster events that wait for their twin, and those
    /// with one in their past.
    after_waiting: BTreeSet<EventId>,
    /// Whether a person's list or a granted space's roster that could name
    /// an author is missing.
    unknown: bool,
    /// The paths through which each valid unit's author wrote it: what
    /// the write rule found alive at step 5.
    alive_paths: RefCell<BTreeMap<EventId, Vec<MemberRef>>>,
    /// At a partial replica whose roster waits for heights, what it
    /// fetches to learn them.
    heights_wanted: Vec<EventId>,
    /// ext-invite-links.md's race rule: the successors forced void as
    /// `ClaimRaced`.
    #[cfg(feature = "ext-invite-links")]
    forced: BTreeSet<EventId>,
    /// The root of a checkpoint's world, when the log is one.
    world: Option<WorldRoot>,
    /// The keys of the world root's record's device members.
    root_keys: Option<KeyRing>,
    /// The verdicts decided before the procedure ([`Checkpointing`]).
    presets: BTreeMap<EventId, Status>,
}

impl core::fmt::Debug for Space<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Space")
            .field("space", &self.log.id())
            .field("statuses", &self.statuses)
            .field("roster", &self.roster)
            .finish_non_exhaustive()
    }
}

/// The space events in each placed event's past, by event.
type SpacePast = BTreeMap<EventId, Arc<BTreeSet<EventId>>>;

/// [`SpacePast`] over placed events in canonical order: an event's past
/// holds its placed parents and their pasts, so a space event is in it
/// exactly when [`Log::precedes`] finds it, on a log with no witness. A
/// stubbed parent ends the past, as it does there.
fn space_past(log: &Log, canonical: &[EventId]) -> SpacePast {
    let mut out = SpacePast::new();
    extend_space_past(&mut out, log, canonical);
    out
}

/// Adds to a [`SpacePast`] the events given, each after its placed parents.
fn extend_space_past(out: &mut SpacePast, log: &Log, events: &[EventId]) {
    let empty: Arc<BTreeSet<EventId>> = Arc::default();
    for &id in events {
        let Some(event) = log.event(id) else {
            continue;
        };
        // Parents in turn; a parent whose past, and itself if a space
        // event, the set holds already adds nothing, and the set stays
        // shared.
        let mut parents: Vec<(&EventId, &Arc<BTreeSet<EventId>>, bool)> = event
            .parents()
            .iter()
            .filter_map(|parent| {
                let theirs = out.get(parent)?;
                let is_space = log.event(*parent).is_some_and(|e| e.kind() == kind::SPACE);
                Some((parent, theirs, is_space))
            })
            .collect();
        // The largest past first: the others are most often within it.
        parents.sort_by_key(|(_, theirs, is_space)| {
            core::cmp::Reverse(theirs.len() + usize::from(*is_space))
        });
        let mut past: Option<Arc<BTreeSet<EventId>>> = None;
        for (parent, theirs, is_space) in parents {
            let within = |ours: &BTreeSet<EventId>| {
                (!is_space || ours.contains(parent))
                    && (theirs.len() <= ours.len() && theirs.iter().all(|id| ours.contains(id)))
            };
            match &mut past {
                None if !is_space => past = Some(Arc::clone(theirs)),
                Some(ours) if Arc::ptr_eq(ours, theirs) && !is_space => {}
                Some(ours) if within(ours) => {}
                _ => {
                    let ours = Arc::make_mut(past.get_or_insert_with(|| Arc::clone(&empty)));
                    ours.extend(theirs.iter().copied());
                    if is_space {
                        ours.insert(*parent);
                    }
                }
            }
        }
        out.insert(id, past.unwrap_or_else(|| Arc::clone(&empty)));
    }
}

/// The events of a view that are in `seeds` or have one in their past, in
/// canonical order from their parents': what a full replica whose log has
/// no witness finds with [`Log::precedes`] event by event.
fn after_any(log: &Log, canonical: &[EventId], seeds: &BTreeSet<EventId>) -> BTreeSet<EventId> {
    let mut out = BTreeSet::new();
    if seeds.is_empty() {
        return out;
    }
    for &id in canonical {
        if seeds.contains(&id)
            || log
                .event(id)
                .is_some_and(|e| e.parents().iter().any(|p| out.contains(p)))
        {
            out.insert(id);
        }
    }
    out
}

/// A resolution kept apart from the log it read, so that a view of the
/// same log that adds content units can be judged from it
/// ([`Space::resolve_appended`]) without judging every event again.
#[derive(Debug, Clone)]
pub struct Resolved {
    view: BTreeSet<EventId>,
    screened: ScreenedLog,
    skeleton: Option<SkeletonParts>,
    forks: ForkPoints,
    statuses: BTreeMap<EventId, Status>,
    refs: BTreeMap<EventId, Vec<Ref>>,
    unopened: BTreeSet<EventId>,
    contested: Vec<EventId>,
    valid_roster: BTreeSet<EventId>,
    roster: Roster,
    policy: Policy,
    valid_keys: BTreeSet<EventId>,
    alive_paths: BTreeMap<EventId, Vec<MemberRef>>,
    #[cfg(feature = "ext-invite-links")]
    forced: BTreeSet<EventId>,
    space_past: SpacePast,
    after_held: BTreeSet<EventId>,
    after_waiting: BTreeSet<EventId>,
    unknown: bool,
    /// A checkpoint's world: its root, the keys the root's record carries,
    /// and the verdicts decided before the procedure ([`Space::into_resolved_world`]).
    world: Option<WorldRoot>,
    root_keys: Option<KeyRing>,
    presets: BTreeMap<EventId, Status>,
}

impl Resolved {
    /// The events resolved.
    pub fn view(&self) -> &BTreeSet<EventId> {
        &self.view
    }
}

static RESOLUTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static APPENDED_RESOLUTIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many views this process has resolved whole
/// ([`Space::resolve_as`], each screening every event of its view), and how
/// many from an earlier resolution ([`Space::resolve_appended`]): for tests
/// and measurements of what a refresh costs.
#[doc(hidden)]
pub fn resolution_counts() -> (u64, u64) {
    (
        RESOLUTIONS.load(std::sync::atomic::Ordering::Relaxed),
        APPENDED_RESOLUTIONS.load(std::sync::atomic::Ordering::Relaxed),
    )
}

impl<'a> Space<'a> {
    /// Resolves a view of a space's log: the whole log for `None`, or a set
    /// of its placed events closed under parents.
    ///
    /// # Errors
    ///
    /// A replica that cannot use the genesis cannot use the space
    /// ([`ScreenedLog::screen_in`]). Checking twins, a genesis also waits
    /// for its root (`NoTwin`), and a space whose root fails is unusable
    /// (`BadTwin`).
    pub fn resolve(
        log: &'a Log,
        view: Option<&BTreeSet<EventId>>,
        options: Options<'a>,
    ) -> Result<Self, RosterClass> {
        Self::resolve_as(log, view, options, Replica::Full)
    }

    /// Resolves a view as [`resolve`](Space::resolve) does, as a full or a
    /// partial replica (units.md, "Partial replicas"). A partial replica's
    /// log places events by witnessed parents ([`Log::witness`]) and holds
    /// the `Path`s it fetched ([`Log::add_path`]).
    ///
    /// # Errors
    ///
    /// As [`resolve`](Space::resolve).
    pub fn resolve_as(
        log: &'a Log,
        view: Option<&BTreeSet<EventId>>,
        options: Options<'a>,
        replica: Replica,
    ) -> Result<Self, RosterClass> {
        Self::resolve_inner(log, view, options, replica, Checkpointing::default(), None)
    }

    /// Resolves a view as [`resolve`](Space::resolve) does, with the
    /// verdicts decided before the procedure and, for a checkpoint's world,
    /// its root (roster.md, "Checkpoints"). A world's log is the one
    /// [`crate::checkpoint_world::WorldLog`] builds: the checkpoint and the
    /// events after it, each linked to its parents among them only, beside
    /// the genesis, which stays the source of the space's descriptor and
    /// system stream and takes no other part. With no presets and no world,
    /// it is [`resolve`](Space::resolve).
    ///
    /// # Errors
    ///
    /// As [`resolve`](Space::resolve).
    pub fn resolve_checkpointed(
        log: &'a Log,
        view: Option<&BTreeSet<EventId>>,
        options: Options<'a>,
        checkpointing: Checkpointing,
    ) -> Result<Self, RosterClass> {
        Self::resolve_inner(log, view, options, Replica::Full, checkpointing, None)
    }

    /// As [`resolve_checkpointed`](Space::resolve_checkpointed), reading
    /// twins, pseudonym keys and the skeleton's slots from `skeleton` when
    /// this replica checks twins, instead of the skeleton of `log`'s own
    /// storage events: in a checkpoint's world, the skeleton after the
    /// checkpoint's cut (roster.md, 3.15.5 The world after a checkpoint,
    /// Skeleton), whose slots of the cut map to devices by the record's
    /// `slot` entries ([`WorldRoot::cut_slots`]). Its events are those of
    /// the world, with the cut and the enrolments it names beside them.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Space::resolve).
    pub fn resolve_checkpointed_with_skeleton(
        log: &'a Log,
        view: Option<&BTreeSet<EventId>>,
        options: Options<'a>,
        checkpointing: Checkpointing,
        skeleton: Option<Skeleton<'a>>,
    ) -> Result<Self, RosterClass> {
        Self::resolve_inner(log, view, options, Replica::Full, checkpointing, skeleton)
    }

    fn resolve_inner(
        log: &'a Log,
        view: Option<&BTreeSet<EventId>>,
        options: Options<'a>,
        replica: Replica,
        checkpointing: Checkpointing,
        given: Option<Skeleton<'a>>,
    ) -> Result<Self, RosterClass> {
        let view: BTreeSet<EventId> = match view {
            Some(view) => view.clone(),
            None => log.canonical().into_iter().collect(),
        };
        let Checkpointing { presets, world } = checkpointing;
        let skeleton = match options.twins {
            Twins::Skeleton => Some(given.unwrap_or_else(|| Skeleton::new(log, Some(&view)))),
            Twins::Assumed => None,
        };
        let root_keys = world.as_ref().map(|world| {
            let mut ring = KeyRing::new();
            for change in &world.changes {
                if let Some(keys) = &change.keys {
                    ring.add_device(DeviceKeys::clone(keys));
                }
            }
            ring
        });
        RESOLUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let screened = {
            let records = SpaceRecords {
                others: options.others,
                skeleton: skeleton.as_ref(),
                root_keys: root_keys.as_ref(),
            };
            match world {
                // The genesis of a world's log supplies no key and names no
                // device (roster.md, 3.15.5 The world after a checkpoint).
                Some(_) => ScreenedLog::screen_world_in(
                    log,
                    &view,
                    options.keys,
                    &options.limits,
                    &records,
                )?,
                None => {
                    ScreenedLog::screen_in(log, &view, options.keys, &options.limits, &records)?
                }
            }
        };
        crate::ext::check_parent(&screened.genesis().descriptor, options.others)?;
        let forks = match &world {
            Some(world) => crate::checkpoint_world::world_forks(log, &view, world, &screened),
            None => screened.fork_points(log),
        };
        let policy = world
            .as_ref()
            .map_or(screened.genesis().policy, |world| world.policy);
        let root = world.as_ref().map_or_else(|| log.id(), |world| world.root);
        let mut space = Self {
            log,
            options,
            replica,
            view,
            screened,
            cache: PlaceCache::default(),
            skeleton,
            forks,
            statuses: BTreeMap::new(),
            refs: BTreeMap::new(),
            unopened: BTreeSet::new(),
            contested: Vec::new(),
            valid_roster: BTreeSet::from([root]),
            roster: Rc::new(Roster::default()),
            policy,
            valid_keys: BTreeSet::new(),
            writers: OnceCell::new(),
            unwaiting: OnceCell::new(),
            ended: OnceCell::new(),
            shields: OnceCell::new(),
            space_past: OnceCell::new(),
            after_held: BTreeSet::new(),
            after_waiting: BTreeSet::new(),
            unknown: false,
            alive_paths: RefCell::new(BTreeMap::new()),
            heights_wanted: Vec::new(),
            #[cfg(feature = "ext-invite-links")]
            forced: BTreeSet::new(),
            world,
            root_keys,
            presets,
        };
        if space.world.is_none() {
            space.check_root()?;
        }
        let mut held = space.screen();
        space.hold_for_later_descriptor(&mut held);
        space.apply_presets(&mut held);
        space.freeze_for_later_rules(&mut held);
        space.hold(&held);
        space.resolve_roster();
        space.hold_for_heights();
        space.hold_for_twins();
        space.judge_writes();
        Ok(space)
    }

    // -- Carrying a resolution

    /// The resolution apart from the log, for
    /// [`resolve_appended`](Space::resolve_appended): `None` at a partial
    /// replica, or one whose log has a witness, which resolve each view
    /// whole.
    pub fn into_resolved(self) -> Option<Resolved> {
        if self.world.is_some() || !self.presets.is_empty() {
            return None;
        }
        self.space_past()?;
        let space_past = self.space_past.into_inner().flatten()?;
        Some(Resolved {
            view: self.view,
            screened: self.screened,
            skeleton: self.skeleton.map(Skeleton::into_parts),
            forks: self.forks,
            statuses: self.statuses,
            refs: self.refs,
            unopened: self.unopened,
            contested: self.contested,
            valid_roster: self.valid_roster,
            roster: Rc::try_unwrap(self.roster).unwrap_or_else(|shared| (*shared).clone()),
            policy: self.policy,
            valid_keys: self.valid_keys,
            alive_paths: self.alive_paths.into_inner(),
            #[cfg(feature = "ext-invite-links")]
            forced: self.forced,
            space_past,
            after_held: self.after_held,
            after_waiting: self.after_waiting,
            unknown: self.unknown,
            world: None,
            root_keys: None,
            presets: BTreeMap::new(),
        })
    }

    /// As [`into_resolved`](Space::into_resolved), for a resolution of a
    /// checkpoint's world too ([`crate::checkpoint_world::WorldLog`]), or
    /// one with verdicts decided before the procedure: what
    /// [`resolve_appended_world`](Space::resolve_appended_world) resumes.
    /// `None` where [`into_resolved`](Space::into_resolved) gives none.
    pub fn into_resolved_world(self) -> Option<Resolved> {
        self.space_past()?;
        let space_past = self.space_past.into_inner().flatten()?;
        Some(Resolved {
            view: self.view,
            screened: self.screened,
            skeleton: self.skeleton.map(Skeleton::into_parts),
            forks: self.forks,
            statuses: self.statuses,
            refs: self.refs,
            unopened: self.unopened,
            contested: self.contested,
            valid_roster: self.valid_roster,
            roster: Rc::try_unwrap(self.roster).unwrap_or_else(|shared| (*shared).clone()),
            policy: self.policy,
            valid_keys: self.valid_keys,
            alive_paths: self.alive_paths.into_inner(),
            #[cfg(feature = "ext-invite-links")]
            forced: self.forced,
            space_past,
            after_held: self.after_held,
            after_waiting: self.after_waiting,
            unknown: self.unknown,
            world: self.world,
            root_keys: self.root_keys,
            presets: self.presets,
        })
    }

    /// Resolves the log as it is now from an earlier resolution of it,
    /// when all it placed since are `added`: content units, each after its
    /// placed parents, none of them fork evidence, under the same keys and
    /// other logs as before. The earlier events keep their statuses, since
    /// none of what decides them reads a later unit; each added unit is
    /// judged as [`resolve`](Space::resolve) judges it: step 11, its seal
    /// and refs, what it is held after, then the write rule at its place.
    /// The caller checks the conditions; the debug comparison with a
    /// resolution from scratch checks the outcome.
    pub fn resolve_appended(
        log: &'a Log,
        options: Options<'a>,
        prior: Resolved,
        added: &[EventId],
    ) -> Self {
        Self::resolve_appended_with(log, log, options, prior, added, &BTreeMap::new())
    }

    /// As [`resolve_appended`](Space::resolve_appended), from a resolution
    /// [`into_resolved_world`](Space::into_resolved_world) kept: of a
    /// checkpoint's world, whose `log` gained the added units since
    /// ([`crate::checkpoint_world::WorldLog::append`]), with the verdicts
    /// decided before the procedure for them in `presets` (as
    /// [`crate::checkpoint::Checkpointed::presets_after`] finds them). A
    /// world resolved with a skeleton over another log
    /// ([`resolve_checkpointed_with_skeleton`](Space::resolve_checkpointed_with_skeleton))
    /// names that log as `skeleton_log`; otherwise it is `log`. Each added
    /// unit is judged as a resolution from scratch judges it, its preset
    /// taken where the procedure takes one.
    pub fn resolve_appended_world(
        log: &'a Log,
        skeleton_log: &'a Log,
        options: Options<'a>,
        prior: Resolved,
        added: &[EventId],
        presets: &BTreeMap<EventId, Status>,
    ) -> Self {
        Self::resolve_appended_with(log, skeleton_log, options, prior, added, presets)
    }

    fn resolve_appended_with(
        log: &'a Log,
        skeleton_log: &'a Log,
        options: Options<'a>,
        prior: Resolved,
        added: &[EventId],
        presets: &BTreeMap<EventId, Status>,
    ) -> Self {
        APPENDED_RESOLUTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut added: Vec<EventId> = added.to_vec();
        added.sort_unstable_by_key(|&id| (log.height(id).unwrap_or(0), id));
        let mut space_past = prior.space_past;
        extend_space_past(&mut space_past, log, &added);
        let mut space = Self {
            log,
            options,
            replica: Replica::Full,
            view: prior.view,
            screened: prior.screened,
            cache: PlaceCache::default(),
            skeleton: prior
                .skeleton
                .map(|parts| Skeleton::from_parts(skeleton_log, parts, added.iter().copied())),
            forks: prior.forks,
            statuses: prior.statuses,
            refs: prior.refs,
            unopened: prior.unopened,
            contested: prior.contested,
            valid_roster: prior.valid_roster,
            roster: Rc::new(prior.roster),
            policy: prior.policy,
            valid_keys: prior.valid_keys,
            writers: OnceCell::new(),
            unwaiting: OnceCell::new(),
            ended: OnceCell::new(),
            shields: OnceCell::new(),
            space_past: OnceCell::from(Some(space_past)),
            after_held: prior.after_held,
            after_waiting: prior.after_waiting,
            unknown: prior.unknown,
            alive_paths: RefCell::new(prior.alive_paths),
            heights_wanted: Vec::new(),
            #[cfg(feature = "ext-invite-links")]
            forced: prior.forced,
            world: prior.world,
            root_keys: prior.root_keys,
            presets: prior.presets,
        };
        for &id in &added {
            space.judge_added(id, presets.get(&id).copied());
        }
        space
            .presets
            .extend(presets.iter().map(|(&id, &s)| (id, s)));
        space
    }

    /// [`resolve`](Space::resolve)'s steps for one content unit placed
    /// after the view resolved, in the same order.
    fn judge_added(&mut self, id: EventId, preset: Option<Status>) {
        let event = self.log.event(id).expect("an added unit is placed");
        self.view.insert(id);
        // Step 11, then the unit's seal and refs (screen).
        let signature = {
            let records = SpaceRecords {
                others: self.options.others,
                skeleton: self.skeleton.as_ref(),
                root_keys: self.root_keys.as_ref(),
            };
            self.screened.add_unit(self.log, id, &records)
        };
        let mut held = None;
        match signature {
            Signature::BadSignature => {
                self.statuses
                    .insert(id, Status::void(ErrorClass::BadSignature));
            }
            Signature::NoHybridKey => {
                self.statuses
                    .insert(id, Status::void(ErrorClass::NoHybridKey));
            }
            Signature::Verified => match self.options.units.open(event) {
                UnitBody::Opened(refs) => {
                    // The write rule, step 0.
                    if !refs.iter().all(|r| self.options.others.resolves(r)) {
                        held = Some(RosterClass::from(ErrorClass::Pending));
                    }
                    self.refs.insert(id, refs);
                }
                UnitBody::Held(class) => {
                    self.unopened.insert(id);
                    held = Some(class);
                }
                UnitBody::Void(class) => {
                    self.unopened.insert(id);
                    self.statuses.insert(id, Status::void(class));
                }
            },
        }
        // A verdict decided before the procedure, where step 11 and the
        // seal left none (apply_presets): a held one holds the unit.
        if let Some(status) = preset
            && !self.statuses.contains_key(&id)
        {
            held = match status {
                Status::Void { class, .. } if class.sort() == frasil_base::errors::Sort::Held => {
                    Some(class)
                }
                _ => None,
            };
            self.statuses.insert(id, status);
        }
        // Held, or after a held event (hold).
        let after = |set: &BTreeSet<EventId>| event.parents().iter().any(|p| set.contains(p));
        let after_held = after(&self.after_held);
        if held.is_some() || after_held {
            self.after_held.insert(id);
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = self.statuses.entry(id) {
            if let Some(class) = held {
                entry.insert(Status::void(class));
            } else if after_held {
                entry.insert(Status::void(ErrorClass::Pending));
            }
        }
        // After a roster event that waits for its twin (hold_for_twins).
        if after(&self.after_waiting) {
            self.after_waiting.insert(id);
            self.statuses
                .entry(id)
                .or_insert(Status::void(ErrorClass::Pending));
        }
        // The write rule (judge_writes).
        if !self.statuses.contains_key(&id) {
            let status = self.write_or_drop(id);
            self.statuses.insert(id, status);
        }
        if !self.unknown && self.statuses.get(&id) == Some(&Status::void(ErrorClass::NoHybridKey)) {
            self.statuses.insert(id, Status::void(ErrorClass::Dropped));
        }
    }

    // -- Construction

    /// Runs `f` with the roster's [`Judge`] over the current valid roster
    /// events' places.
    #[cfg(not(feature = "ext-invite-links"))]
    pub(crate) fn with_judge<T>(&self, f: impl FnOnce(&Judge<'_>) -> T) -> T {
        self.with_judge_forcing(f)
    }

    /// Runs `f` with the roster's [`Judge`] over the current valid roster
    /// events' places, and the successors the race rule forced void.
    #[cfg(feature = "ext-invite-links")]
    pub(crate) fn with_judge<T>(&self, f: impl FnOnce(&Judge<'_>) -> T) -> T {
        self.with_judge_forcing(&self.forced, f)
    }

    /// [`Self::with_judge`], with ext-invite-links.md's successors forced
    /// void as `ClaimRaced` given.
    pub(crate) fn with_judge_forcing<T>(
        &self,
        #[cfg(feature = "ext-invite-links")] forced: &BTreeSet<EventId>,
        f: impl FnOnce(&Judge<'_>) -> T,
    ) -> T {
        let events = RosterLog {
            log: self.log,
            screened: &self.screened,
            pasts: self.pasts(),
            world: self.world.as_ref(),
        };
        let places = Places::with_cache(&events, Rc::clone(&self.cache));
        let judge = Judge {
            log: self.log,
            screened: &self.screened,
            places: &places,
            forks: &self.forks,
            limits: &self.options.limits,
            skeleton: self.skeleton.as_ref(),
            notices: self.options.notices,
            #[cfg(feature = "ext-invite-links")]
            forced,
            shields: RefCell::new(None),
            pasts: self.pasts(),
            standing: OnceCell::new(),
            administration: RefCell::new(None),
            world: self.world.as_ref(),
        };
        f(&judge)
    }

    /// The resolution procedure over the offered roster events. With
    /// ext-invite-links.md, it runs inside that document's race rule.
    #[cfg(not(feature = "ext-invite-links"))]
    fn resolve_offered(
        &mut self,
        offered: Vec<EventId>,
    ) -> frasil_resolve::Resolution<EventId, RosterClass> {
        self.with_judge(|judge| frasil_resolve::resolve(judge, offered))
    }

    /// The resolution procedure over the offered roster events, inside
    /// ext-invite-links.md's race rule ("Raced claims").
    #[cfg(feature = "ext-invite-links")]
    fn resolve_offered(
        &mut self,
        offered: Vec<EventId>,
    ) -> frasil_resolve::Resolution<EventId, RosterClass> {
        let (resolution, forced) = crate::ext_invite_links::resolve_racing(self, &offered);
        self.forced = forced;
        resolution
    }

    /// A genesis waits for its skeleton root; a space whose root fails is
    /// unusable.
    fn check_root(&self) -> Result<(), RosterClass> {
        let Some(skeleton) = &self.skeleton else {
            return Ok(());
        };
        let genesis = self.log.id();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, BTreeSet::from([genesis]));
            TwinChecks::new(skeleton, &facts)
                .check(genesis)
                .map_err(|failure| failure.class().into())
        })
    }

    /// Steps 2 to 11, and units' seals: the classes of events void alone,
    /// each opened event's refs, and what is held, with its class.
    fn screen(&mut self) -> BTreeMap<EventId, RosterClass> {
        let mut held = BTreeMap::new();
        for id in self.log.canonical_in(&self.view) {
            let event = self.log.event(id).expect("a view's events are placed");
            let signature = self.screened.signature(id);
            let refused = match signature {
                Some(Signature::BadSignature) => Some(ErrorClass::BadSignature),
                Some(Signature::NoHybridKey) => Some(ErrorClass::NoHybridKey),
                _ => None,
            };
            match event.kind() {
                // roster.md, 3.15.5 "Seals": in a checkpoint's world, an
                // event sealed under a state with a rotation that is neither
                // the checkpoint nor an event of the world in its past is
                // `StaleSeal`, read from the visible part before any key.
                kind::SPACE if self.sealed_outside_world(id, event) => {
                    self.statuses
                        .insert(id, Status::void(frasil_keys::KeyClass::StaleSeal));
                }
                kind::SPACE => match self.screened.body(id) {
                    Some(Body::Refused(class) | Body::Void(class)) => {
                        self.statuses.insert(id, Status::void(*class));
                    }
                    Some(Body::Held(class)) => {
                        held.insert(id, *class);
                        if signature == Some(Signature::BadSignature) {
                            self.statuses
                                .insert(id, Status::void(ErrorClass::BadSignature));
                        }
                    }
                    Some(Body::Opened(opened)) => {
                        if let Some(class) = refused {
                            self.statuses.insert(id, Status::void(class));
                        } else if id != self.log.id() {
                            self.refs.insert(id, opened.inner.refs.clone());
                        }
                    }
                    None => {}
                },
                kind::STORAGE => match (self.screened.storage(id), refused) {
                    (Some(Err(class)), _) => {
                        self.statuses.insert(id, Status::void(class));
                    }
                    (_, Some(class)) => {
                        self.statuses.insert(id, Status::void(class));
                    }
                    _ => {}
                },
                kind::UNIT => {
                    if let Some(class) = refused {
                        self.statuses.insert(id, Status::void(class));
                        continue;
                    }
                    match self.options.units.open(event) {
                        UnitBody::Opened(refs) => {
                            self.refs.insert(id, refs);
                        }
                        UnitBody::Held(class) => {
                            self.unopened.insert(id);
                            held.insert(id, class);
                        }
                        UnitBody::Void(class) => {
                            self.unopened.insert(id);
                            self.statuses.insert(id, Status::void(class));
                        }
                    }
                }
                _ => {
                    if let Some(class) = refused {
                        self.statuses.insert(id, Status::void(class));
                    }
                }
            }
        }
        // The write rule, step 0: a key event or a unit whose refs name an
        // event this replica does not hold. A roster event's refs never
        // hold it.
        for (&id, refs) in &self.refs {
            let unit = self.log.event(id).is_some_and(|e| e.kind() == kind::UNIT);
            if (unit || self.is_key(id)) && !refs.iter().all(|r| self.options.others.resolves(r)) {
                held.insert(id, ErrorClass::Pending.into());
            }
        }
        held
    }

    /// Holds the held events and every event after one.
    fn hold(&mut self, held: &BTreeMap<EventId, RosterClass>) {
        let order = self.log.canonical_in(&self.view);
        if self.space_past().is_some() {
            // Found once from parents: an event is after a held one when a
            // parent is held or after one.
            let seeds: BTreeSet<EventId> = held.keys().copied().collect();
            self.after_held = after_any(self.log, &order, &seeds);
            for id in order {
                if self.statuses.contains_key(&id) {
                    continue;
                }
                if let Some(&class) = held.get(&id) {
                    self.statuses.insert(id, Status::void(class));
                } else if self.after_held.contains(&id) {
                    self.statuses.insert(id, Status::void(ErrorClass::Pending));
                }
            }
            return;
        }
        for id in order {
            if self.statuses.contains_key(&id) {
                continue;
            }
            if let Some(&class) = held.get(&id) {
                self.statuses.insert(id, Status::void(class));
            } else if held.keys().any(|&h| self.before(h, id)) {
                self.statuses.insert(id, Status::void(ErrorClass::Pending));
            }
        }
    }

    /// Step 4: the roster events, by the resolution procedure.
    fn resolve_roster(&mut self) {
        let genesis = self.log.id();
        let root = self.root();
        let offered: Vec<EventId> = self
            .log
            .canonical_in(&self.view)
            .into_iter()
            .filter(|&id| {
                id != genesis
                    && id != root
                    && !self.statuses.contains_key(&id)
                    && self.is_roster(id)
                    && !self.is_checkpoint(id)
            })
            .collect();
        let resolution = self.resolve_offered(offered);
        self.contested = resolution.contested().to_vec();
        if self.world.is_some() {
            self.statuses.insert(root, Status::Valid(Valid::Checkpoint));
        } else {
            self.statuses.insert(genesis, Status::Valid(Valid::Genesis));
        }
        for (id, verdict) in resolution.iter() {
            let status = match verdict {
                frasil_resolve::Verdict::Valid(How::Rules) => Status::Valid(Valid::Rules),
                frasil_resolve::Verdict::Valid(How::Agreed) => Status::Valid(Valid::Agreed),
                frasil_resolve::Verdict::Valid(How::Seniority) => Status::Valid(Valid::Seniority),
                frasil_resolve::Verdict::Void { class, by } => Status::Void {
                    class: *class,
                    by: *by,
                },
            };
            if status.is_valid() {
                self.valid_roster.insert(id);
            }
            self.statuses.insert(id, status);
        }
        // A valid checkpoint takes no part in the contest, and counts as a
        // valid roster event of every place that holds it (roster.md,
        // 3.15.2).
        let checkpoints: Vec<EventId> = self
            .statuses
            .iter()
            .filter(|&(&id, status)| id != root && status.is_valid() && self.is_checkpoint(id))
            .map(|(&id, _)| id)
            .collect();
        self.valid_roster.extend(checkpoints);
        self.roster = self.roster_at(&self.valid_roster);
        let genesis_policy = self
            .world
            .as_ref()
            .map_or(self.screened.genesis().policy, |world| world.policy);
        let valid = self.valid_roster.clone();
        self.policy = self.with_places(|places| places.policy(&valid, &genesis_policy));
    }

    /// What follows a roster event that waits for its twin is held with
    /// it, as if not received.
    fn hold_for_twins(&mut self) {
        let no_twin = RosterClass::from(frasil_peers::PeersClass::NoTwin);
        let waiting: Vec<EventId> = self
            .statuses
            .iter()
            .filter(|(_, status)| status.class() == Some(no_twin))
            .map(|(&id, _)| id)
            .collect();
        if waiting.is_empty() {
            return;
        }
        let order = self.log.canonical_in(&self.view);
        // roster.md, 3.7 "Standing": an event void before the procedure for
        // want of standing is `Pending` behind a roster event that waits for
        // its twin, as section 3.6's step 0 comes before step 1.
        let without_standing = self.without_standing();
        if self.space_past().is_some() {
            let seeds: BTreeSet<EventId> = waiting.iter().copied().collect();
            self.after_waiting = after_any(self.log, &order, &seeds);
            for id in order {
                if (!self.statuses.contains_key(&id) || without_standing.contains(&id))
                    && !seeds.contains(&id)
                    && self.after_waiting.contains(&id)
                {
                    self.statuses.insert(id, Status::void(ErrorClass::Pending));
                }
            }
            return;
        }
        for id in order {
            if (!self.statuses.contains_key(&id) || without_standing.contains(&id))
                && waiting.iter().any(|&w| self.before(w, id))
            {
                self.statuses.insert(id, Status::void(ErrorClass::Pending));
            }
        }
    }

    /// roster.md, 3.7 "Standing": the roster events void before the
    /// procedure because their author has no standing in their past. They
    /// are the offered roster events left out of the contest whose class is
    /// section 3.6's step 1 (or, for a successor, ext-invite-links.md's
    /// steps 1 and 2), which nothing before the contest gives.
    pub(crate) fn without_standing(&self) -> BTreeSet<EventId> {
        let classes = [
            RosterClass::from(ErrorClass::NotAnAdministrator),
            #[cfg(feature = "ext-invite-links")]
            RosterClass::from(crate::ext_invite_links::InviteClass::NotAnInvite),
            #[cfg(feature = "ext-invite-links")]
            RosterClass::from(crate::ext_invite_links::InviteClass::InviteUsed),
        ];
        let contested: BTreeSet<EventId> = self.contested.iter().copied().collect();
        let genesis = self.log.id();
        let root = self.root();
        self.statuses
            .iter()
            .filter(|&(&id, status)| {
                id != genesis
                    && id != root
                    && !self.is_checkpoint(id)
                    && !contested.contains(&id)
                    && self.is_roster(id)
                    && matches!(status, Status::Void { class, by: None } if classes.contains(class))
            })
            .map(|(&id, _)| id)
            .collect()
    }

    /// Steps 5 and 6: key events once each in canonical order, then units,
    /// anchors, writer requests and events of ignorable kinds.
    fn judge_writes(&mut self) {
        let order = self.log.canonical_in(&self.view);
        for &id in &order {
            if self.is_key(id) && !self.statuses.contains_key(&id) {
                let status = self.write_or_drop(id);
                if status.is_valid() {
                    self.valid_keys.insert(id);
                }
                self.statuses.insert(id, status);
            }
        }
        for &id in &order {
            if self.statuses.contains_key(&id) || self.is_roster(id) {
                continue;
            }
            let event = self.log.event(id).expect("placed");
            let status = match event.kind() {
                kind::ANCHOR => {
                    let roster = self.roster_at(&self.place_of(id));
                    let (paths, unknown) =
                        self.paths_at_event(&event.author().0, &roster, Level::Read, id);
                    if !paths.is_empty() {
                        Status::Valid(Valid::Kept)
                    } else if unknown {
                        Status::void(ErrorClass::Pending)
                    } else {
                        Status::void(ErrorClass::NotAMember)
                    }
                }
                kind::UNIT => self.write_or_drop(id),
                kind::STORAGE => match self.screened.storage(id) {
                    Some(Ok(kind)) if kind.is_writer_request() => self.write_or_drop(id),
                    // A skeleton event is kept only when the skeleton vouches
                    // for its pseudonym (roster.md, "The skeleton's
                    // resolution"), whatever its signature.
                    Some(Ok(kind)) if kind.is_skeleton() && !self.vouches_for(event.author()) => {
                        Status::void(ErrorClass::Dropped)
                    }
                    _ => Status::Valid(Valid::Kept),
                },
                _ if self.named(event.author()) => Status::Valid(Valid::Kept),
                _ => Status::void(ErrorClass::Dropped),
            };
            self.statuses.insert(id, status);
        }
        // A unit, an anchor, a storage event or an ignorable kind whose
        // author no record names is dropped, not held; it stays pending
        // while a person's list or a granted space's roster that could name
        // its author is missing. A skeleton event no record names is
        // dropped.
        let unknown = self.roster.members_in().any(|(m, _)| match m.kind {
            MemberType::Person => self.options.others.list(&m.id).is_none(),
            MemberType::Space => self.options.others.space(&EventId(m.id)).is_none(),
            _ => false,
        });
        self.unknown = unknown;
        let no_key = Status::void(ErrorClass::NoHybridKey);
        for &id in &order {
            if self.statuses.get(&id) != Some(&no_key) {
                continue;
            }
            let event = self.log.event(id).expect("placed");
            let skeleton = matches!(self.screened.storage(id), Some(Ok(k)) if k.is_skeleton());
            let writable = matches!(event.kind(), kind::UNIT | kind::STORAGE | kind::ANCHOR)
                || event.kind() >= kind::FIRST_IGNORABLE;
            if skeleton || (!unknown && writable) {
                self.statuses.insert(id, Status::void(ErrorClass::Dropped));
            }
        }
    }

    /// The write rule, with a stranger's `NotAWriter` dropped.
    fn write_or_drop(&self, id: EventId) -> Status {
        let status = self.write_rule(id);
        let author = &self.log.event(id).expect("placed").author().0;
        if status.class() == Some(SpaceClass::NotAWriter.into()) && !self.named(&DeviceId(*author))
        {
            return Status::void(ErrorClass::Dropped);
        }
        status
    }

    /// The write rule, steps 1 to 7, for a unit, a key event or a writer
    /// request whose step 0 passed; a partial replica's in proven order.
    fn write_rule(&self, u: EventId) -> Status {
        if self.replica == Replica::Partial {
            return self.partial_write_rule(u);
        }
        let event = self.log.event(u).expect("placed");
        let author = &event.author().0;
        // 1.
        if self.forks.is_void(event) {
            return Status::void(ErrorClass::Forked);
        }
        // 2.
        let roster = self.roster_at(&self.place_of(u));
        let (paths, unknown) = self.paths_at_event(author, &roster, Level::Write, u);
        if paths.is_empty() {
            return Status::void(if unknown {
                RosterClass::from(ErrorClass::Pending)
            } else {
                SpaceClass::NotAWriter.into()
            });
        }
        let key = self.is_key(u);
        // 3.
        if key && self.all_waiting(&paths, author) {
            return Status::void(SpaceClass::WaitingDevice);
        }
        // 4.
        let lowering: Vec<(EventId, BTreeSet<MemberRef>)> = self
            .log
            .canonical_in(&self.valid_roster)
            .into_iter()
            .filter(|&x| {
                x != self.log.id()
                    && x != self.root()
                    && x != u
                    && !self.precedes(x, u)
                    && !self.precedes(u, x)
            })
            .map(|x| (x, self.lowered(x)))
            .filter(|(_, lowered)| !lowered.is_empty())
            .collect();
        let remaining: Vec<MemberRef> = paths
            .iter()
            .copied()
            .filter(|m| !lowering.iter().any(|(_, lowered)| lowered.contains(m)))
            .collect();
        if remaining.is_empty() {
            let by = lowering
                .iter()
                .find(|(_, lowered)| paths.iter().any(|m| lowered.contains(m)))
                .map(|(x, _)| *x)
                .expect("a path was lowered");
            return if unknown {
                Status::by(ErrorClass::Pending, by)
            } else {
                Status::by(SpaceClass::RefusedByRemoval, by)
            };
        }
        // 5.
        let mut ended_by = None;
        let mut alive = Vec::new();
        for member in &remaining {
            let ends = self.path_ends(member, author);
            let hit = ends.iter().find_map(|end| {
                self.responses(end, author)
                    .into_iter()
                    .find(|&k| !self.le(u, k))
            });
            match hit {
                Some(response) => {
                    ended_by.get_or_insert(response);
                }
                None => alive.push(*member),
            }
        }
        if alive.is_empty() {
            let by = ended_by.expect("a path was ended");
            return if unknown {
                Status::by(ErrorClass::Pending, by)
            } else {
                Status::by(SpaceClass::RefusedAfterResponse, by)
            };
        }
        // 6.
        if key && let Err(class) = self.key_context(u, &roster, &alive) {
            return Status::void(class);
        }
        // 7.
        self.alive_paths.borrow_mut().insert(u, alive);
        Status::Valid(Valid::Rules)
    }

    /// The members through which a valid event's author held its level at
    /// the event's place, as the write rule found them alive (steps 2 to
    /// 5): the device itself, a person whose list holds it, or a granted
    /// space. Empty for an event the write rule did not find valid, or one
    /// a partial replica judged.
    pub fn write_paths(&self, event: EventId) -> Vec<MemberRef> {
        self.alive_paths
            .borrow()
            .get(&event)
            .cloned()
            .unwrap_or_default()
    }

    /// Step 3: every path is waiting (roster.md, 3.10 The write rule): a
    /// person grant whose list holds `author` as rooted in a recovery agent
    /// and not confirmed, or a granted space through which `author`
    /// reaches this one only by waiting paths, which is to say it is not
    /// among that space's [`GrantedSpace::unwaiting_writers`]. A device
    /// grant never waits.
    fn all_waiting(&self, paths: &[MemberRef], author: &[u8; 32]) -> bool {
        paths.iter().all(|m| match m.kind {
            MemberType::Person => self
                .options
                .others
                .list(&m.id)
                .is_some_and(|list| list.waiting(author)),
            MemberType::Space => self
                .options
                .others
                .space(&EventId(m.id))
                .is_some_and(|space| !space.unwaiting_writers().contains(author)),
            _ => false,
        })
    }

    /// keys.md's checks against a key event and its place: the rotations
    /// counted are the genesis, the valid roster events and the key events
    /// decided valid before it. The notice checks are the key graph's.
    fn key_context(
        &self,
        u: EventId,
        roster: &Roster,
        paths: &[MemberRef],
    ) -> Result<(), RosterClass> {
        let Some(opened) = self.screened.opened(u) else {
            return Ok(());
        };
        let mut context = Context::new(EventKind::Key);
        context.author_propagates = paths.iter().any(|m| match m.kind {
            MemberType::Device => roster.state(m).is_some_and(|s| s.session.is_none()),
            _ => true,
        });
        context.responds = opened.inner.responds();
        context.restricted =
            self.screened.genesis().descriptor.kind == crate::DescriptorKind::Restricted;
        let valid: BTreeSet<EventId> = self.valid_roster.union(&self.valid_keys).copied().collect();
        context.sealed_under_stale = crate::resolution::stale(self.log, &self.screened, u, &valid);
        match self.options.key_checks {
            KeyEventChecks::Context => {
                let author = self.log.event(u).expect("placed").author().0;
                let named = valid
                    .iter()
                    .filter(|&&e| self.before(e, u))
                    .filter_map(|e| self.refs.get(e))
                    .flatten()
                    .chain(&opened.inner.refs)
                    .copied()
                    .collect();
                let query = NoticeQuery {
                    event: u,
                    author,
                    opened,
                    granted: granted_spaces(roster),
                    named,
                };
                check_with_notices(self.options.notices, &query, context)?;
            }
            KeyEventChecks::StaleSeal => {
                if !opened.facts().rotates && context.sealed_under_stale {
                    return Err(frasil_keys::KeyClass::StaleSeal.into());
                }
            }
        }
        Ok(())
    }

    // -- Paths across logs

    /// Every member through which `device` holds `minimum` in a roster, in
    /// order, and whether a path could not be judged for lack of another
    /// log (roster.md, "Checks across logs", "Paths").
    pub fn paths(
        &self,
        device: &[u8; 32],
        roster: &Roster,
        minimum: Level,
    ) -> (Vec<MemberRef>, bool) {
        let mut out = Vec::new();
        let mut unknown = false;
        for (member, state) in roster.members_in() {
            if state.level < minimum {
                continue;
            }
            match member.kind {
                MemberType::Device if member.id == *device => out.push(*member),
                MemberType::Person => match self.options.others.list(&member.id) {
                    None => unknown = true,
                    Some(list) if list.writers().contains(device) => out.push(*member),
                    Some(_) => {}
                },
                MemberType::Space => match self.options.others.space(&EventId(member.id)) {
                    None => unknown = true,
                    Some(space) if space.propagating_writers().contains(device) => {
                        out.push(*member)
                    }
                    Some(_) => {}
                },
                _ => {}
            }
        }
        #[cfg(feature = "ext-restricted-spaces")]
        let (out, unknown) =
            crate::ext_restricted_spaces::through_parent(self, device, out, unknown);
        (out, unknown)
    }

    /// Step-2 paths at an event's causal place (roster.md, 3.11).
    pub fn paths_at_event(
        &self,
        device: &[u8; 32],
        roster: &Roster,
        minimum: Level,
        event: EventId,
    ) -> (Vec<MemberRef>, bool) {
        let (mut paths, unknown) = self.paths(device, roster, minimum);
        paths.retain(|member| {
            member.kind != MemberType::Person || self.list_add_at(&member.id, device, event)
        });
        (paths, unknown)
    }

    pub(crate) fn list_add_at(&self, person: &[u8; 32], device: &[u8; 32], event: EventId) -> bool {
        let Some(list) = self.options.others.list(person) else {
            return false;
        };
        let Some(member) = list.merged().member(&DeviceId(*device)) else {
            return false;
        };
        let Some(placed) = self.options.units.list_events_at(self.log, event) else {
            return true;
        };
        if member.adds.iter().any(|add| placed.contains(add))
            || list.checkpoint_places(&placed, &member.adds)
        {
            return true;
        }
        self.options
            .units
            .held_list_copies(self.log)
            .iter()
            .any(|copy| {
                copy.log_id().0 == *person
                    && placed.contains(&copy.id())
                    && frasil_identity::body::ListBody::decode(copy.unverified_body())
                        .ok()
                        .and_then(|body| body.list_record())
                        .is_some_and(|record| {
                            record
                                .members
                                .iter()
                                .any(|entry| member.adds.contains(&entry.add))
                        })
            })
    }

    /// The author's capabilities through paths at this event's place.
    pub fn author_reach(&self, event: EventId) -> crate::across::AuthorReach {
        let Some(unit) = self.log.event(event) else {
            return crate::across::AuthorReach::Unreached;
        };
        let roster = self.roster_at(&self.place_of(event));
        let (paths, unknown) = self.paths_at_event(&unit.author().0, &roster, Level::Read, event);
        crate::across::AuthorReach::of(
            self.reach_over(&unit.author().0, &roster, PathsFor::Unit, Some(&paths)),
            unknown,
        )
    }

    /// How `device` reaches this space through the members of `roster`
    /// over the paths `paths` names, with its capabilities: those of its
    /// strongest path (units.md, 3.17 "Capability checks"). Along one path a
    /// narrowing capability on any grant applies, and an extending one only
    /// from this roster's own grant; over several paths the highest level
    /// wins, and the paths at that level merge as concurrent grants do: an
    /// extending capability stays only if each carries it, a narrowing one
    /// if any does (roster.md, "Grants of spaces and effective
    /// membership"). A path through a person or a space whose log this
    /// replica does not hold gives nothing. `None` when no path holds.
    pub fn reach_at(&self, device: &[u8; 32], roster: &Roster, paths: PathsFor) -> Option<Reach> {
        self.reach_over(device, roster, paths, None)
    }

    fn reach_over(
        &self,
        device: &[u8; 32],
        roster: &Roster,
        paths: PathsFor,
        only: Option<&[MemberRef]>,
    ) -> Option<Reach> {
        let mut found = Vec::new();
        for (member, state) in roster.members_in() {
            if only.is_some_and(|only| !only.contains(member)) {
                continue;
            }
            let of = |mode| {
                state
                    .capabilities_of(mode)
                    .map(str::to_owned)
                    .collect::<BTreeSet<String>>()
            };
            let (extends, narrows) = (of(CapabilityMode::Extends), of(CapabilityMode::Narrows));
            match member.kind {
                MemberType::Device if member.id == *device => found.push(Path {
                    level: state.level,
                    propagates: state.propagates(),
                    extends,
                    narrows,
                    depth: 1,
                }),
                MemberType::Person => {
                    let Some(list) = self.options.others.list(&member.id) else {
                        continue;
                    };
                    let reaches = match paths {
                        PathsFor::Unit => list.writers().contains(device),
                        PathsFor::Current => list.members().contains(device),
                    };
                    if reaches {
                        found.push(Path {
                            level: state.level,
                            propagates: true,
                            extends,
                            narrows,
                            depth: 1,
                        });
                    }
                }
                MemberType::Space => {
                    let Some(space) = self.options.others.space(&EventId(member.id)) else {
                        continue;
                    };
                    // An edge to a restricted space delivers nothing to the
                    // current view; a unit's paths are the write rule's.
                    if paths == PathsFor::Current && space.is_restricted() {
                        continue;
                    }
                    let Some(inner) = space.reach(device, paths) else {
                        continue;
                    };
                    // A guest of the granted space gains nothing here, and
                    // only its propagating paths there pass on (roster.md,
                    // 3.3).
                    let Some(there) = inner.propagating_level else {
                        continue;
                    };
                    found.push(Path {
                        level: state.level.min(there).min(Level::Write),
                        propagates: true,
                        extends,
                        narrows: narrows.union(&inner.propagating_narrows).cloned().collect(),
                        depth: inner.propagating_depth + 1,
                    });
                }
                _ => {}
            }
        }
        combine(&found)
    }

    /// The ends of `device`'s path through a person or a space member.
    fn path_ends(&self, member: &MemberRef, device: &[u8; 32]) -> Vec<Ref> {
        #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(unused_mut))]
        let mut ends = match member.kind {
            MemberType::Person => self
                .options
                .others
                .list(&member.id)
                .map(|list| {
                    list.ends(device)
                        .into_iter()
                        .map(|id| Ref {
                            log: EventId(member.id),
                            id,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            MemberType::Space => self
                .options
                .others
                .space(&EventId(member.id))
                .map(|space| space.ends(device))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        #[cfg(feature = "ext-restricted-spaces")]
        ends.extend(crate::ext_restricted_spaces::parent_ends(self, device));
        ends
    }

    /// The responses to an end of `ended`'s path, in canonical order: valid
    /// events of this space by another device whose refs name the end or
    /// an event of its log that has it in its past, a valid roster event or
    /// a key event decided valid already (roster.md, "Responses").
    pub fn responses(&self, end: &Ref, ended: &[u8; 32]) -> Vec<EventId> {
        // Only a space event can be a valid roster or key event.
        self.screened
            .events()
            .iter()
            .copied()
            .filter(|&i| {
                let event = self.log.event(i).expect("placed");
                event.author().0 != *ended
                    && self.refs.get(&i).is_some_and(|refs| {
                        refs.iter()
                            .any(|r| self.options.others.covers(r, end.log, end.id))
                    })
                    && ((self.is_roster(i) && self.is_valid(i)) || self.valid_keys.contains(&i))
            })
            .collect()
    }

    /// The members a roster event lowers to below `write`: those it removes
    /// or demotes to `read`.
    pub fn lowered(&self, event: EventId) -> BTreeSet<MemberRef> {
        self.changes(event)
            .iter()
            .filter(|c| {
                c.op == Op::Remove
                    || (c.op == Op::Change && c.level.is_some_and(|l| l < Level::Write))
            })
            .filter_map(|c| c.member)
            .collect()
    }

    /// Effective membership over the roster of `valid`: each device that
    /// reaches this space, with its highest level over every path and its
    /// highest over the paths that propagate, `None` when none does
    /// (roster.md, "Grants of spaces and effective membership"). The two
    /// are kept apart: a space grant passes on, at most at `write`, only
    /// the second, so a device's strongest path, a guest's say, never hides
    /// a weaker one that propagates; and only over an edge that counts: the grant
    /// graph's rules run over every roster this replica holds, this space's
    /// at `valid` and each granted space's merged roster, so a cycle drops
    /// its edge with the highest granting space ID wherever it is entered,
    /// and a chain passes no more than 8 spaces. An edge to a restricted
    /// space delivers nothing, and a path stops where it would enter a
    /// space it already passed.
    pub fn effective_at(
        &self,
        valid: &BTreeSet<EventId>,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        let verdicts = self.grant_verdicts(valid);
        self.effective_with(valid, depth, seen, &verdicts)
    }

    /// The grant graph's verdicts over every roster this replica holds:
    /// this space's at `valid`, and the merged roster of each space it
    /// reaches through grants, as held among the other logs.
    pub fn grant_verdicts(&self, valid: &BTreeSet<EventId>) -> Verdicts {
        let me = self.log.id();
        let roster = self.roster_at(valid);
        let own: Vec<(EventId, EventId)> = roster
            .members_in()
            .filter(|(m, _)| m.kind == MemberType::Space)
            .flat_map(|(m, state)| state.grants.iter().map(move |&g| (g, EventId(m.id))))
            .collect();
        let mut spaces: BTreeMap<EventId, SpaceGrants> = BTreeMap::new();
        let mut todo: Vec<(EventId, Vec<(EventId, EventId)>)> = vec![(me, own)];
        while let Some((id, grants)) = todo.pop() {
            if spaces.contains_key(&id) {
                continue;
            }
            for &(_, to) in &grants {
                if to == id || spaces.contains_key(&to) {
                    continue;
                }
                if let Some(space) = self.find_space(to) {
                    todo.push((to, space.space_grants()));
                }
            }
            let kind = if id == me {
                self.screened.genesis().descriptor.kind
            } else {
                self.find_space(id)
                    .map_or(crate::DescriptorKind::Space, |space| {
                        space.descriptor_kind()
                    })
            };
            let parent = (id == me)
                .then(|| self.screened.genesis().descriptor.parent.map(EventId))
                .flatten();
            spaces.insert(
                id,
                SpaceGrants {
                    kind,
                    parent,
                    grants: grants
                        .into_iter()
                        .map(|(event, to)| GrantInForce {
                            event,
                            target: GrantTarget::Space(to),
                            level: Level::Write,
                            session: false,
                            capabilities: Vec::new(),
                        })
                        .collect(),
                },
            );
        }
        edge_verdicts(&spaces)
    }

    /// A granted space among the other logs, or theirs in turn.
    fn find_space(&self, id: EventId) -> Option<&'a dyn GrantedSpace> {
        if let Some(space) = self.options.others.space(&id) {
            return Some(space);
        }
        let mut seen = BTreeSet::new();
        let mut todo: Vec<&'a dyn GrantedSpace> =
            self.options.others.spaces.values().copied().collect();
        while let Some(space) = todo.pop() {
            if !seen.insert(space.space_id()) {
                continue;
            }
            let others = space.other_logs();
            if let Some(&found) = others.spaces.get(&id) {
                return Some(found);
            }
            todo.extend(others.spaces.values().copied());
        }
        None
    }

    /// [`Self::effective_at`] under given verdicts.
    fn effective_with(
        &self,
        valid: &BTreeSet<EventId>,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.effective_over(valid, depth, seen, verdicts, false)
    }

    /// [`Self::effective_with`]; with `unwaiting`, over the paths that are
    /// not waiting only (roster.md, 3.10 The write rule, step 3). Each
    /// offer raises the highest level, and, when its path propagates, the
    /// highest propagating level: both are maxima, so the order of the
    /// roster's members and of the devices each brings changes nothing.
    fn effective_over(
        &self,
        valid: &BTreeSet<EventId>,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
        unwaiting: bool,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        let mut out: BTreeMap<[u8; 32], (Level, Option<Level>)> = BTreeMap::new();
        let mut offer = |device: [u8; 32], level: Level, propagates: bool| {
            let entry = out.entry(device).or_insert((level, None));
            entry.0 = entry.0.max(level);
            if propagates {
                entry.1 = entry.1.max(Some(level));
            }
        };
        let roster = self.roster_at(valid);
        for (member, state) in roster.members_in() {
            self.member_reach(member, state, depth, seen, verdicts, unwaiting, &mut offer);
        }
        #[cfg(feature = "ext-restricted-spaces")]
        let out = crate::ext_restricted_spaces::narrow_by_parent(self, out, depth, seen);
        out
    }

    /// The devices one member of a roster brings into effective membership,
    /// each offered with its level and whether it propagates; with
    /// `unwaiting`, only over paths that are not waiting: a person's
    /// devices but those its list holds as rooted in a recovery agent and
    /// not confirmed, and a granted space's devices among its
    /// [`GrantedSpace::unwaiting_writers`].
    #[allow(clippy::too_many_arguments)]
    fn member_reach(
        &self,
        member: &MemberRef,
        state: &crate::state::MemberState,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
        unwaiting: bool,
        offer: &mut impl FnMut([u8; 32], Level, bool),
    ) {
        let me = self.log.id();
        match member.kind {
            MemberType::Device => offer(member.id, state.level, state.session.is_none()),
            MemberType::Person => {
                if let Some(list) = self.options.others.list(&member.id) {
                    for device in list.members() {
                        if !(unwaiting && list.waiting(&device)) {
                            offer(device, state.level, true);
                        }
                    }
                }
            }
            MemberType::Space => {
                let id = EventId(member.id);
                let Some(space) = self.options.others.space(&id) else {
                    return;
                };
                let counts = state.grants.iter().any(|&event| {
                    verdicts.get(&Edge {
                        from: me,
                        to: id,
                        event,
                    }) == Some(&Ok(()))
                });
                if !counts
                    || space.is_restricted()
                    || seen.contains(&id)
                    || depth + 1 >= crate::graph::MAX_GRANT_DEPTH
                {
                    return;
                }
                let mut path = seen.to_vec();
                path.push(me);
                let kept = unwaiting.then(|| space.unwaiting_writers());
                // Only what a device's propagating paths there give passes
                // on (roster.md, 3.3).
                for (device, (_, propagating)) in
                    space.effective_counted(depth + 1, &path, verdicts)
                {
                    if kept.as_ref().is_some_and(|kept| !kept.contains(&device)) {
                        continue;
                    }
                    if let Some(level) = propagating {
                        offer(device, state.level.min(level).min(Level::Write), true);
                    }
                }
            }
            _ => {}
        }
    }

    /// The devices that reach this space at `write` and propagate, over
    /// the roster of `valid`.
    fn propagating_at(&self, valid: &BTreeSet<EventId>) -> BTreeSet<[u8; 32]> {
        self.effective_at(valid, 0, &[])
            .into_iter()
            .filter(|(_, (_, propagating))| *propagating >= Some(Level::Write))
            .map(|(device, _)| device)
            .collect()
    }

    /// [`Self::propagating_at`] over the paths that are not waiting only.
    fn unwaiting_at(&self, valid: &BTreeSet<EventId>) -> BTreeSet<[u8; 32]> {
        let verdicts = self.grant_verdicts(valid);
        self.effective_over(valid, 0, &[], &verdicts, true)
            .into_iter()
            .filter(|(_, (_, propagating))| *propagating >= Some(Level::Write))
            .map(|(device, _)| device)
            .collect()
    }

    // -- Helpers

    fn with_places<T>(&self, f: impl FnOnce(&Places<'_, RosterLog<'_>>) -> T) -> T {
        let events = RosterLog {
            log: self.log,
            screened: &self.screened,
            pasts: self.pasts(),
            world: self.world.as_ref(),
        };
        let places = Places::with_cache(&events, Rc::clone(&self.cache));
        f(&places)
    }

    /// The roster at a place.
    pub fn roster_at(&self, place: &BTreeSet<EventId>) -> Rc<Roster> {
        self.with_places(|places| places.roster(place))
    }

    /// An event's place: the genesis and the valid roster events of its
    /// past; at a partial replica, of its proven past.
    pub fn place_of(&self, event: EventId) -> BTreeSet<EventId> {
        let valid = &self.valid_roster;
        match self.replica {
            Replica::Full => match self.space_past().and_then(|past| past.get(&event)) {
                // The valid roster events in its past, as
                // `Places::place_of` finds them one by one.
                Some(past) => {
                    let mut place: BTreeSet<EventId> = past
                        .iter()
                        .copied()
                        .filter(|id| valid.contains(id))
                        .collect();
                    place.insert(self.root());
                    place
                }
                None => self.with_places(|places| places.place_of(event, valid)),
            },
            Replica::Partial => {
                let mut place: BTreeSet<EventId> = valid
                    .iter()
                    .copied()
                    .filter(|&x| self.log.proves_before(x, event))
                    .collect();
                place.insert(self.root());
                place
            }
        }
    }

    /// A rotation's place, the rotation included when it is a valid roster
    /// event.
    /// [`place_of`](Self::place_of) found by walking the event's past for
    /// each valid roster event: what the faster form is checked against.
    #[doc(hidden)]
    pub fn place_of_by_walking(&self, event: EventId) -> BTreeSet<EventId> {
        match self.replica {
            Replica::Full => self.with_places(|places| places.place_of(event, &self.valid_roster)),
            Replica::Partial => self.place_of(event),
        }
    }

    /// The space events in the past of each event of the view, at a full
    /// replica whose log has no witness: each event's from its parents',
    /// in canonical order, sharing a parent's set where it adds nothing.
    /// `None` elsewhere, where the past is found event by event.
    /// The view's space pasts, for the roster's rules: causal order between
    /// space events of the view read without a walk.
    fn pasts(&self) -> Option<crate::state::Pasts<'_>> {
        self.space_past().map(|past| crate::state::Pasts {
            past,
            view: &self.view,
        })
    }

    fn space_past(&self) -> Option<&SpacePast> {
        self.space_past
            .get_or_init(|| {
                if self.replica != Replica::Full || self.log.has_witnesses() {
                    return None;
                }
                Some(space_past(self.log, &self.log.canonical_in(&self.view)))
            })
            .as_ref()
    }

    fn rotation_place(&self, rotation: EventId) -> BTreeSet<EventId> {
        let mut place = self.place_of(rotation);
        if self.valid_roster.contains(&rotation) {
            place.insert(rotation);
        }
        place
    }

    /// The sealed refs of an opened space event or unit, ascending.
    pub fn refs_of(&self, id: EventId) -> &[Ref] {
        self.refs.get(&id).map_or(&[], Vec::as_slice)
    }

    /// The opened body of a space event.
    pub fn opened(&self, id: EventId) -> Option<&Opened> {
        self.screened.opened(id)
    }

    fn changes(&self, id: EventId) -> &[Change] {
        self.opened(id).map_or(&[], Opened::changes)
    }

    /// Whether an event is an opened roster event, the genesis included.
    pub fn is_roster(&self, id: EventId) -> bool {
        self.opened(id).is_some_and(Opened::is_roster)
    }

    /// Whether an event is an opened checkpoint (roster.md, "Checkpoints").
    pub fn is_checkpoint(&self, id: EventId) -> bool {
        self.opened(id)
            .is_some_and(|opened| opened.checkpoint().is_some())
    }

    /// The log's root: the genesis, or in a checkpoint's world the
    /// checkpoint (roster.md, 3.15.5 The world after a checkpoint).
    pub fn root(&self) -> EventId {
        self.world
            .as_ref()
            .map_or_else(|| self.log.id(), |world| world.root)
    }

    /// The root of the checkpoint's world this space is, if it is one.
    pub fn world(&self) -> Option<&WorldRoot> {
        self.world.as_ref()
    }

    /// Whether a space event of a checkpoint's world names, in its visible
    /// `sealed_under`, a rotation that is neither the checkpoint nor an
    /// event of the world in its past (roster.md, 3.15.5 "Seals").
    fn sealed_outside_world(&self, id: EventId, event: &frasil_events::Event) -> bool {
        let Some(world) = &self.world else {
            return false;
        };
        let genesis = self.log.id();
        if id == world.root || id == genesis {
            return false;
        }
        let Ok(visible) = frasil_keys::body::VisiblePart::read(
            event.unverified_body(),
            event.author(),
            event.seq(),
        ) else {
            return false;
        };
        let Some(state) = visible.sealed_under() else {
            return false;
        };
        !state.ids().iter().all(|&r| {
            r == world.root || (r != genesis && self.view.contains(&r) && self.log.precedes(r, id))
        })
    }

    /// The verdicts decided before the procedure: a verdict of steps 2 to
    /// 11 comes first. One of a held class holds what follows it too.
    fn apply_presets(&mut self, held: &mut BTreeMap<EventId, RosterClass>) {
        let genesis = self.log.id();
        let root = self.root();
        let presets = core::mem::take(&mut self.presets);
        for (&id, &status) in &presets {
            if id == genesis
                || id == root
                || !self.view.contains(&id)
                || self.statuses.contains_key(&id)
            {
                continue;
            }
            if let Status::Void { class, .. } = status
                && class.sort() == frasil_base::errors::Sort::Held
            {
                held.insert(id, class);
            } else {
                held.remove(&id);
            }
            self.statuses.insert(id, status);
        }
        // A checkpoint no preset judged is held: only the checkpoint
        // procedure judges one ([`crate::checkpoint`]).
        let unjudged: Vec<EventId> = self
            .screened
            .events()
            .iter()
            .copied()
            .filter(|&id| {
                id != root
                    && self.view.contains(&id)
                    && self.is_checkpoint(id)
                    && !self.statuses.contains_key(&id)
                    && !presets.contains_key(&id)
            })
            .collect();
        for id in unjudged {
            held.insert(id, ErrorClass::Pending.into());
            self.statuses.insert(id, Status::void(ErrorClass::Pending));
        }
        self.presets = presets;
    }

    /// roster.md, "The space descriptor": a descriptor of a kind from 3, or
    /// with a key from 5, is a later document's, which this implementation
    /// lacks. Once it has read it, it holds every event of the space after
    /// the genesis as `ExtensionRequired`, whatever its kind, and judges
    /// nothing of the space; an event already void alone keeps its class.
    /// One whose signature waits for keys (`NoHybridKey`) is held so too:
    /// the keys that would check it are in the events held.
    fn hold_for_later_descriptor(&mut self, held: &mut BTreeMap<EventId, RosterClass>) {
        if !self.screened.genesis().descriptor.kind.is_reserved() {
            return;
        }
        let extension = RosterClass::from(ErrorClass::ExtensionRequired);
        let genesis = self.log.id();
        let root = self.root();
        for &id in &self.view {
            if id == genesis || id == root {
                continue;
            }
            held.insert(id, extension);
            let decided = self
                .statuses
                .get(&id)
                .and_then(Status::class)
                .is_some_and(|class| class.sort() == frasil_base::errors::Sort::Final);
            if !decided {
                self.statuses.insert(id, Status::void(extension));
            }
        }
    }

    /// roster.md, 3.16 Rules this replica lacks: a roster part of a type
    /// from 3 whose author has standing in its past is held as
    /// `ExtensionRequired`, with every event of the view outside its past,
    /// whether after it or concurrent with it; one whose author has none is
    /// void (`NotAnAdministrator`).
    fn freeze_for_later_rules(&mut self, held: &mut BTreeMap<EventId, RosterClass>) {
        let later: Vec<EventId> = self
            .log
            .canonical_in(&self.view)
            .into_iter()
            .filter(|id| self.screened.later_rules().contains(id))
            .collect();
        if later.is_empty() {
            return;
        }
        let extension = RosterClass::from(ErrorClass::ExtensionRequired);
        let genesis = self.log.id();
        let root = self.root();
        let mut frozen = BTreeSet::new();
        for x in later {
            if self.statuses.contains_key(&x) {
                held.remove(&x);
                continue;
            }
            if !self.with_judge(|judge| judge.has_standing(x)) {
                held.remove(&x);
                self.statuses
                    .insert(x, Status::void(ErrorClass::NotAnAdministrator));
                continue;
            }
            self.statuses.insert(x, Status::void(extension));
            held.insert(x, extension);
            for &id in &self.view {
                if id != x && id != genesis && id != root && !self.log.precedes(id, x) {
                    frozen.insert(id);
                }
            }
        }
        for id in frozen {
            held.insert(id, extension);
            self.statuses.entry(id).or_insert(Status::void(extension));
        }
    }

    /// Whether an event is an opened key event.
    pub fn is_key(&self, id: EventId) -> bool {
        self.opened(id).is_some_and(|opened| !opened.is_roster())
    }

    /// The keys of the world root's record's device members, when this
    /// space is a checkpoint's world.
    pub fn root_keys(&self) -> Option<&KeyRing> {
        self.root_keys.as_ref()
    }

    /// `a` is `b` or in its past.
    fn le(&self, a: EventId, b: EventId) -> bool {
        a == b || self.precedes(a, b)
    }

    /// [`Log::precedes`], read from the space events in `b`'s past when `a`
    /// is a space event of the view and that past was found.
    pub(crate) fn precedes(&self, a: EventId, b: EventId) -> bool {
        if let Some(past) = self.space_past().and_then(|past| past.get(&b))
            && self.log.event(a).is_some_and(|e| e.kind() == kind::SPACE)
            && self.view.contains(&a)
        {
            return past.contains(&a);
        }
        self.log.precedes(a, b)
    }

    /// `a` is in the past of `b`: in causal order at a full replica, in
    /// proven order at a partial one.
    fn before(&self, a: EventId, b: EventId) -> bool {
        match self.replica {
            Replica::Full => self.precedes(a, b),
            Replica::Partial => self.log.proves_before(a, b),
        }
    }

    /// Whether a record names a device (roster.md, "Strangers' events"): a
    /// grant of it in this view, valid or void, or an `add` or a grant of it
    /// in the other logs.
    fn named(&self, device: &DeviceId) -> bool {
        self.screened.names(device)
            || self.options.others.names(device)
            || self
                .root_keys
                .as_ref()
                .is_some_and(|ring| ring.device_keys(device).is_some())
    }

    /// Whether the skeleton vouches for a pseudonym: its root or
    /// enrolment passed the peer's checks.
    fn vouches_for(&self, pseudonym: &DeviceId) -> bool {
        self.skeleton
            .as_ref()
            .is_some_and(|skeleton| skeleton.pseudonym_keys(pseudonym).is_some())
    }

    // -- Results

    /// The log.
    pub fn log(&self) -> &'a Log {
        self.log
    }

    /// The events this view holds.
    pub fn view(&self) -> &BTreeSet<EventId> {
        &self.view
    }

    /// The options it was resolved with.
    pub fn options(&self) -> Options<'a> {
        self.options
    }

    /// Whether it was resolved as a full or a partial replica.
    pub fn replica(&self) -> Replica {
        self.replica
    }

    /// The skeleton this resolution read, when it checks twins: the storage
    /// events of its view, resolved as peers.md's skeleton resolution
    /// resolves them.
    pub fn skeleton(&self) -> Option<&Skeleton<'a>> {
        self.skeleton.as_ref()
    }

    /// The holding root or enrolment and the device its binding names.
    pub fn pseudonym_holder(&self, pseudonym: &DeviceId) -> Option<(EventId, Option<DeviceId>)> {
        let skeleton = self.skeleton.as_ref()?;
        let enrolment = skeleton.enrolled_by(pseudonym)?;
        self.with_judge(|judge| {
            let facts = Facts::new(judge, self.valid_roster.clone());
            let holder = match TwinChecks::new(skeleton, &facts).bound(pseudonym) {
                Bound::Device(device) => Some(device),
                _ => None,
            };
            Some((enrolment, holder))
        })
    }

    /// The administrator slots of the merged skeleton this resolution read,
    /// by the device each was made for (peers.md, "What replicas check"):
    /// what a record names in key 13 (roster.md, 2.8 The checkpoint
    /// record). A slot with no enrolled pseudonym names none (empty bytes).
    /// Empty when this replica does not check twins.
    pub fn administrator_slots(&self) -> BTreeMap<DeviceId, crate::SlotEntry> {
        let Some(skeleton) = &self.skeleton else {
            return BTreeMap::new();
        };
        let valid = self.valid_roster.clone();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, valid);
            let checks = TwinChecks::new(skeleton, &facts);
            let mut out = BTreeMap::new();
            for slot in skeleton.administrators() {
                let Some(device) = checks.slot_device(slot) else {
                    continue;
                };
                let enrolled = skeleton.merged().get(&slot).and_then(|s| s.enrolled);
                out.insert(
                    device,
                    crate::SlotEntry {
                        commitment: slot.reference.commitment,
                        index: u64::from(slot.reference.index),
                        maker: slot.maker,
                        pseudonym: enrolled.map(|p| p.0.to_vec()).unwrap_or_default(),
                    },
                );
            }
            out
        })
    }

    /// For each device, the most senior administrator slot made for it that
    /// is out in the merged skeleton this resolution read, with that slot's
    /// seniority and the root or enrolment of the pseudonym enrolled in it,
    /// if one is: what the standing entry of a member a checkpoint hears
    /// names (peers.md, "Storage events"). Empty when this replica does not
    /// check twins.
    #[allow(clippy::type_complexity)]
    pub fn administrator_slots_out(
        &self,
    ) -> BTreeMap<
        DeviceId,
        (
            frasil_peers::derive::Seniority,
            frasil_peers::body::SlotId,
            Option<EventId>,
        ),
    > {
        let Some(skeleton) = &self.skeleton else {
            return BTreeMap::new();
        };
        let valid = self.valid_roster.clone();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, valid);
            let checks = TwinChecks::new(skeleton, &facts);
            let mut out: BTreeMap<DeviceId, (frasil_peers::derive::Seniority, _)> = BTreeMap::new();
            for (&slot, state) in skeleton.merged() {
                if state.is_in {
                    continue;
                }
                let (Some(device), Some(seniority)) =
                    (checks.slot_device(slot), skeleton.seniority(slot))
                else {
                    continue;
                };
                if out.get(&device).is_none_or(|(held, _)| seniority < *held) {
                    out.insert(device, (seniority, slot));
                }
            }
            out.into_iter()
                .map(|(device, (seniority, slot))| {
                    let enrolled = frasil_peers::cut::enrolment_of(skeleton, slot);
                    (device, (seniority, slot, enrolled))
                })
                .collect()
        })
    }

    /// The device an administrator slot of `skeleton` was made for, by the
    /// roster events this resolution opened (peers.md, "What replicas
    /// check"): what [`Self::administrator_slots`] reads, for a skeleton
    /// read apart from this resolution, such as the skeleton after a
    /// checkpoint's cut (roster.md, 3.15.5, Skeleton). A slot of the cut
    /// itself was made by no roster event of a world; its record maps it.
    pub fn slot_device_in(
        &self,
        skeleton: &Skeleton<'_>,
        slot: frasil_peers::body::SlotId,
    ) -> Option<DeviceId> {
        let valid = self.valid_roster.clone();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, valid);
            TwinChecks::new(skeleton, &facts).slot_device(slot)
        })
    }

    /// A checkpoint's twin check (roster.md, 3.15.8, "Twins and the
    /// skeleton"): section 3.8 with its cut as the twin, step 6 the cut's
    /// slots against `record`'s administrators
    /// ([`crate::checkpoint::record_slots`]) and its standing entries
    /// against `standing`, those the record gives
    /// ([`crate::Checkpointed::standing_for`]). The checkpoint is in this
    /// view. Passes when this replica does not check twins.
    ///
    /// # Errors
    ///
    /// `NoTwin` while the cut is not held; `BadTwin` for a cut that fails.
    pub fn check_checkpoint_twin(
        &self,
        checkpoint: EventId,
        record: &crate::Record,
        standing: &[frasil_peers::body::StandingEntry],
    ) -> Result<(), RosterClass> {
        let Some(skeleton) = &self.skeleton else {
            return Ok(());
        };
        let administrators = crate::checkpoint::record_slots(record);
        let valid = self.valid_roster.clone();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, valid);
            TwinChecks::new(skeleton, &facts)
                .check_checkpoint_standing(checkpoint, &administrators, standing)
                .map_err(|failure| failure.class().into())
        })
    }

    /// Its events, each checked alone.
    pub fn screened(&self) -> &ScreenedLog {
        &self.screened
    }

    /// An event's status, `None` for an event the view does not hold.
    pub fn status(&self, id: EventId) -> Option<&Status> {
        self.statuses.get(&id)
    }

    /// Whether an event of the view is valid.
    pub fn is_valid(&self, id: EventId) -> bool {
        self.status(id).is_some_and(Status::is_valid)
    }

    /// The valid events, in canonical order.
    pub fn valid(&self) -> Vec<EventId> {
        self.log
            .canonical_in(&self.view)
            .into_iter()
            .filter(|&id| self.is_valid(id))
            .collect()
    }

    /// The contested roster events, in canonical order.
    pub fn contested(&self) -> &[EventId] {
        &self.contested
    }

    /// The cell that holds the duels' shields among the contested events.
    pub(crate) fn shields_cell(&self) -> &OnceCell<crate::attacks::Shields> {
        &self.shields
    }

    /// The genesis and the valid roster events.
    pub fn valid_roster(&self) -> &BTreeSet<EventId> {
        &self.valid_roster
    }

    /// The key events valid by the write rule.
    pub fn valid_keys(&self) -> &BTreeSet<EventId> {
        &self.valid_keys
    }

    /// What a partial replica fetches, by ID, before it resolves the roster
    /// (units.md, "Partial replicas", "Heights"): the parents it does not
    /// hold beneath contested roster events it can neither order nor place
    /// at known heights. It witnesses each one fetched
    /// ([`Log::witness`]) and resolves again. Empty when the roster is
    /// resolved.
    pub fn heights_wanted(&self) -> &[EventId] {
        &self.heights_wanted
    }

    /// The merged roster: the roster at the place of every valid roster
    /// event.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The space policy of the merged roster.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Each author's fork point among the view's events.
    pub fn forks(&self) -> &ForkPoints {
        &self.forks
    }

    /// Whether the evidence of a device's fork lies in an event's past, the
    /// event included: whoever wrote the event knew of the fork.
    pub fn fork_known_at(&self, device: &[u8; 32], event: EventId) -> bool {
        if self.forks.fork_point(&DeviceId(*device)).is_none() {
            return false;
        }
        let mut past = self.log.past(event);
        past.insert(event);
        past.retain(|e| self.view.contains(e));
        self.screened
            .fork_points_among(self.log, &past)
            .fork_point(&DeviceId(*device))
            .is_some()
    }

    /// The devices of this space that hold a rotation's grant seed (keys.md,
    /// "Notices and space principals"): those that propagate at its place,
    /// and those a valid "with history" grant that propagates brings in
    /// later, or concurrently while the grant is in force, since it is
    /// entitled to every key before it (keys.md, "Entitlement and the link
    /// gate", rule 3). With `ended`, a person's devices include those its
    /// list revoked since, until a response to that end at the rotation or
    /// grant: a device keeps what it received (keys.md, "Healing").
    pub fn holders_of(&self, rotation: EventId, ended: bool) -> BTreeSet<[u8; 32]> {
        let mut out = BTreeSet::new();
        let mut add = |at: &BTreeSet<EventId>, by: EventId, member: &MemberRef| {
            let roster = self.roster_at(at);
            let Some(state) = roster.state(member) else {
                return;
            };
            if member.kind == MemberType::Person && ended {
                if let Some(list) = self.options.others.list(&member.id) {
                    out.extend(
                        list.writers()
                            .into_iter()
                            .filter(|d| !self.end_answered_at(member, d, by)),
                    );
                }
                return;
            }
            let verdicts = self.grant_verdicts(at);
            self.member_reach(
                member,
                state,
                0,
                &[],
                &verdicts,
                false,
                &mut |device, _, propagates| {
                    if propagates {
                        out.insert(device);
                    }
                },
            );
        };
        let place = self.rotation_place(rotation);
        let members: Vec<MemberRef> = self
            .roster_at(&place)
            .members_in()
            .map(|(m, _)| *m)
            .collect();
        for member in &members {
            add(&place, rotation, member);
        }
        for &x in &self.valid_roster {
            if x == rotation || self.log.precedes(x, rotation) {
                continue;
            }
            let after = self.log.precedes(rotation, x);
            let mut at = self.place_of(x);
            at.insert(x);
            for change in self.changes(x) {
                let Some(member) = change.member else {
                    continue;
                };
                let with_history = change.history != Some(crate::member::HistoryMode::FromNowOn);
                if change.op != Op::Grant || !with_history || change.session.is_some() {
                    continue;
                }
                let in_force = self
                    .roster
                    .state(&member)
                    .is_some_and(|state| state.grants.contains(&x));
                if after || in_force {
                    add(&at, x, &member);
                }
            }
        }
        out
    }

    /// Whether an event's past, the event included, holds a response to an
    /// end of `device`'s path through `member` (roster.md, "Checks across
    /// logs"): whoever wrote the event knew of that end.
    pub fn end_answered_at(&self, member: &MemberRef, device: &[u8; 32], event: EventId) -> bool {
        self.path_ends(member, device).iter().any(|end| {
            self.responses(end, device)
                .into_iter()
                .any(|r| r == event || self.log.precedes(r, event))
        })
    }

    /// The events opened under a provisional key (roster.md, "Space events
    /// a replica cannot open"), in canonical order: verdicts reached under
    /// them are provisional.
    pub fn provisional(&self) -> Vec<EventId> {
        self.screened
            .events()
            .iter()
            .copied()
            .filter(|&id| self.opened(id).is_some_and(|o| o.provisional))
            .collect()
    }

    /// The view's devices that skeleton events count for: the device a
    /// pseudonym's binding names (the founder's for the root's), none for
    /// a pseudonym enrolled foreignly or not at all.
    pub fn device_of(&self, id: EventId) -> Option<[u8; 32]> {
        let event = self.log.event(id)?;
        let skeleton_event = matches!(self.screened.storage(id), Some(Ok(k)) if k.is_skeleton());
        if !skeleton_event {
            return Some(event.author().0);
        }
        let skeleton = self.skeleton.as_ref()?;
        let valid = self.valid_roster.clone();
        self.with_judge(|judge| {
            let facts = Facts::new(judge, valid);
            match TwinChecks::new(skeleton, &facts).bound(event.author()) {
                Bound::Device(device) => Some(device.0),
                Bound::Foreign | Bound::Unbound => None,
            }
        })
    }

    /// Whether an event is accepted in full as evidence and as a head: its
    /// signature verified, and, for a unit, its seal opened.
    pub fn accepted(&self, id: EventId) -> bool {
        self.screened.counts_as_evidence(id) && !self.unopened.contains(&id)
    }
}

impl GrantedSpace for Space<'_> {
    fn space_id(&self) -> EventId {
        self.log.id()
    }

    fn holds(&self, event: EventId) -> bool {
        self.view.contains(&event)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.log.precedes(earlier, later)
    }

    fn is_restricted(&self) -> bool {
        self.screened.genesis().descriptor.kind == crate::DescriptorKind::Restricted
    }

    fn descriptor_kind(&self) -> crate::DescriptorKind {
        self.screened.genesis().descriptor.kind
    }

    fn other_logs(&self) -> &OtherLogs<'_> {
        self.options.others
    }

    fn keys(&self) -> &KeyRing {
        self.screened.keys()
    }

    fn world_keys(&self) -> Option<&KeyRing> {
        self.root_keys.as_ref()
    }

    fn names(&self, device: &DeviceId) -> bool {
        self.screened.names(device)
    }

    fn effective(
        &self,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.effective_at(&self.valid_roster, depth, seen)
    }

    fn effective_counted(
        &self,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.effective_with(&self.valid_roster, depth, seen, verdicts)
    }

    /// At the merged roster. For a unit's paths, a device that no longer
    /// propagates here at `write` keeps the paths it had at the places of
    /// the valid roster events where it did, as the write rule's paths
    /// through this space do (roster.md, "Checks across logs", "Paths"),
    /// merged as paths are: the highest level, and the capabilities of
    /// those at that level.
    fn reach(&self, device: &[u8; 32], paths: PathsFor) -> Option<Reach> {
        let now = self.reach_at(device, &self.roster_at(&self.valid_roster), paths);
        if paths == PathsFor::Current {
            return now;
        }
        let writes = |reach: &Reach| reach.propagating_level >= Some(Level::Write);
        if now.as_ref().is_some_and(writes) {
            return now;
        }
        let mut earlier = Vec::new();
        for &x in &self.valid_roster {
            let mut place = self.place_of(x);
            place.insert(x);
            let Some(reach) = self.reach_at(device, &self.roster_at(&place), paths) else {
                continue;
            };
            if let Some(level) = reach.propagating_level.filter(|_| writes(&reach)) {
                earlier.push(Path {
                    level,
                    propagates: true,
                    extends: reach.extends,
                    narrows: reach.propagating_narrows,
                    depth: reach.propagating_depth,
                });
            }
        }
        combine(&earlier).or(now)
    }

    fn space_grants(&self) -> Vec<(EventId, EventId)> {
        self.roster
            .members_in()
            .filter(|(m, _)| m.kind == MemberType::Space)
            .flat_map(|(m, state)| state.grants.iter().map(move |&g| (g, EventId(m.id))))
            .collect()
    }

    fn rotation(&self, id: EventId) -> Option<GranteeRotation> {
        if !self.view.contains(&id) {
            return None;
        }
        let event = self.log.event(id)?;
        let grant_commitment = (event.kind() == kind::SPACE)
            .then(|| {
                // The visible part, which a peer reads too; `valid` says
                // whether the event counts.
                frasil_keys::body::VisiblePart::read(
                    event.unverified_body(),
                    event.author(),
                    event.seq(),
                )
            })
            .and_then(Result::ok)
            .and_then(|visible| visible.rotation().map(|r| r.grant_commitment));
        Some(GranteeRotation {
            valid: self.is_valid(id),
            grant_commitment,
        })
    }

    fn propagates_at(&self, device: &[u8; 32], rotation: EventId) -> Option<bool> {
        if !self.view.contains(&rotation) {
            return None;
        }
        let place = self.rotation_place(rotation);
        if self.holders_of(rotation, false).contains(device) {
            return Some(true);
        }
        let roster = self.roster_at(&place);
        let unknown = roster.members_in().any(|(m, _)| match m.kind {
            MemberType::Person => self.options.others.list(&m.id).is_none(),
            MemberType::Space => self.options.others.space(&EventId(m.id)).is_none(),
            _ => false,
        });
        (!unknown).then_some(false)
    }

    /// The devices of this space that hold the rotation's grant seed
    /// (keys.md, "Notices and space principals"): [`Space::holders_of`],
    /// with the devices whose path ended since.
    fn grant_holders(&self, rotation: EventId) -> BTreeSet<[u8; 32]> {
        self.holders_of(rotation, true)
    }

    /// At the merged roster, or at the place of any valid roster event,
    /// that event included: a device that reached the space earlier keeps
    /// its path until a response to the end of it.
    fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
        self.writers
            .get_or_init(|| {
                let mut out = self.propagating_at(&self.valid_roster);
                for &x in &self.valid_roster {
                    let mut place = self.place_of(x);
                    place.insert(x);
                    out.extend(self.propagating_at(&place));
                }
                out
            })
            .clone()
    }

    /// Over the places [`GrantedSpace::propagating_writers`] reads: the
    /// merged roster and the place of each valid roster event, that event
    /// included.
    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
        self.unwaiting
            .get_or_init(|| {
                let mut out = self.unwaiting_at(&self.valid_roster);
                for &x in &self.valid_roster {
                    let mut place = self.place_of(x);
                    place.insert(x);
                    out.extend(self.unwaiting_at(&place));
                }
                out
            })
            .clone()
    }

    fn ends(&self, device: &[u8; 32]) -> Vec<Ref> {
        let ended = self.ended.get_or_init(|| {
            self.log
                .canonical_in(&self.valid_roster)
                .into_iter()
                .map(|x| {
                    let before = self.place_of(x);
                    let mut after = before.clone();
                    after.insert(x);
                    let after = self.propagating_at(&after);
                    let lost = self
                        .propagating_at(&before)
                        .into_iter()
                        .filter(|d| !after.contains(d))
                        .collect();
                    (x, lost)
                })
                .collect()
        });
        let mut out: Vec<Ref> = ended
            .iter()
            .filter(|(_, lost)| lost.contains(device))
            .map(|&(x, _)| Ref {
                log: self.log.id(),
                id: x,
            })
            .collect();
        for (member, _) in self.roster.iter() {
            match member.kind {
                MemberType::Person => {
                    if let Some(list) = self.options.others.list(&member.id) {
                        out.extend(list.ends(device).into_iter().map(|id| Ref {
                            log: EventId(member.id),
                            id,
                        }));
                    }
                }
                MemberType::Space => {
                    if let Some(space) = self.options.others.space(&EventId(member.id)) {
                        out.extend(space.ends(device));
                    }
                }
                _ => {}
            }
        }
        out
    }
}
