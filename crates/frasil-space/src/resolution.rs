//! The roster's resolution (roster.md, "Authority at the place", "The
//! resolution procedure" and "The twin"), through `frasil-resolve`.
//!
//! [`Judge`] implements [`Resolve`] for the roster events of a view:
//!
//! - **Offered events:** the opened roster events other than the genesis
//!   that are not held (roster.md, "Space events a replica cannot open").
//! - **`check`:** "The event alone", steps 1 to 11, as [`ScreenedLog`] ran
//!   them. **`forked`:** step 12, `Forked`. **`self_lowering`:** "Self-
//!   lowering events". **`check_among`:** "The resolution procedure",
//!   "Standing": an event whose author no event of its past names at
//!   `administer` is `NotAnAdministrator` and not contested
//!   ([`Judge::has_standing`]); the space makes it `Pending` instead behind
//!   a roster event that waits for its twin.
//! - **`authority`:** "Authority at the place", steps 0 to 6, at the roster
//!   of the genesis and the valid contested events of the event's past.
//!   Step 0 reads the standing of the roster events in the past: one void
//!   with `NoTwin` is pending for its twin, and one the agreement step tries
//!   as void is judged again under the trial ("The twin").
//! - **`attack`** and **`mutual`:** "What attacks what", (a), (b), (c) and
//!   (e) ([`crate::attacks`]).
//! - **`attack_counts`:** "What attacks what": in a mutual pair the attack
//!   counts exactly when its author outranks its partner's, each at its own
//!   event's place, so it waits for both contested pasts. Otherwise an
//!   attack does not count when its target lowers each other with its
//!   author and has one change, nor through (a), (b) or (c) against the
//!   support of the attacker's partner in such a duel, unless that
//!   partner's author signed it ([`attacks::counts`]), which reads no
//!   status.
//! - **`pick_key`:** `(255 - rank of the author's member at its place, its
//!   seniority, height, event ID)`.
//!
//! ```text
//! Authority at the place, with S the roster at the event's place:
//! 0. No roster event in its past is pending for its twin.        else Pending
//! 1. The author's device member is in S at administer.           else NotAnAdministrator
//! 2. For each change, in order:
//!    grant:   the member is not the author's device;            else SelfGrant
//!             the member is not in S;                            else AlreadyMember
//!             its rank, if any, is at most the author's.         else HigherRank
//!    change, remove: the member is in S;                         else NoSuchMember
//!             a change of the author's own device only lowers
//!             its level, with no capabilities or label;          else SelfChange
//!             a change to administer names a member whose
//!             state in S has no session;                         else AdministerNotDevice
//!             a member at administer in S, other than the
//!             author's device, has a rank at most the author's,
//!             and a rank the change sets is at most the
//!             author's;                                          else HigherRank
//!             a change to administer of a member already at
//!             administer in S keeps its rank.                    else RankInPlace
//!    policy:  nothing more.
//! 3. With more than one change, none lowers a device member
//!    that is in S at administer.                                 else AdminAlone
//! 4. At most 4,096 valid roster events in its place, itself
//!    included.                                                   else Full
//! 5. keys.md's checks against the event and its place, with the
//!    context it derives from the event's changes and S.          else that class
//! 6. The twin.                                                   else TwinRequired / UnexpectedTwin /
//!                                                                     NoTwin (pending) / BadTwin
//! ```
//!
//! In step 5 the rotations of a roster event's place are the genesis and
//! the roster events valid there: roster resolution never waits on key
//! events.
//!
//! In the world of a checkpoint (roster.md, 3.15.5) the same procedure runs
//! with the checkpoint as the root: every place holds it in place of the
//! genesis, its record's administrators have standing there, and heights
//! count from it.

use crate::attacks::{self, Shields, Side};
use crate::change::{Change, Op};
use crate::member::{HistoryMode, Level, MemberRef};
use crate::screen::ScreenedLog;
use crate::state::{
    Pasts, Places, Roster, RosterLog, Seniority, WorldRoot, administer_changes,
    administer_grant_ranks, check_twin_named, precedes_in, self_lowering,
};
use crate::{Limits, RosterClass, SpaceClass};
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, DeviceKeys, KeySource};

/// The author of an event a view does not hold: no device.
const NO_AUTHOR: DeviceId = DeviceId([0; 32]);
use frasil_events::{EventId, ForkPoints, Log};
use frasil_keys::context::{Context, EventKind};
use frasil_peers::PeersClass;
use frasil_peers::skeleton::Skeleton;
use frasil_peers::twins::{AdministerChanges, RosterFacts, TwinChecks};
use frasil_resolve::{Resolve, Standing, View};
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// What the pick sorts by (roster.md, 3.7, step 4): 255 less the rank of
/// the author's member at the event's place, that member's seniority, the
/// event's height, its ID. The outranking author comes first.
pub type PickKey = (u8, Option<Seniority>, u64, EventId);

/// The roster events of a view, as `frasil-resolve` decides them.
pub struct Judge<'s> {
    /// The space's log.
    pub log: &'s Log,
    /// Its events, each checked alone.
    pub screened: &'s ScreenedLog,
    /// The rosters at its places.
    pub places: &'s Places<'s, RosterLog<'s>>,
    /// Each author's fork point among the view's events.
    pub forks: &'s ForkPoints,
    /// The limits.
    pub limits: &'s Limits,
    /// The skeleton, when this replica checks twins; `None` takes "The
    /// twin" as passing, as the roster vectors do.
    pub skeleton: Option<&'s Skeleton<'s>>,
    /// The key graph's notice check (keys.md, "Checks against the event and
    /// its place", step 8).
    pub notices: Option<&'s dyn crate::space::Notices>,
    /// ext-invite-links.md's race rule: the successors this pass voids as
    /// `ClaimRaced` in their authority.
    #[cfg(feature = "ext-invite-links")]
    pub forced: &'s BTreeSet<EventId>,
    /// The duels' shields, found once over the contested events the
    /// procedure offers ([`Judge::shields`]); empty to start with.
    pub shields: RefCell<Option<(Vec<EventId>, Rc<Shields>)>>,
    /// The view's space pasts, when found once: the causal order between
    /// its space events is read from them, not walked ([`Pasts`]).
    pub pasts: Option<Pasts<'s>>,
    /// The events that can give an author standing, found once
    /// ([`Judge::has_standing`]); empty to start with.
    pub standing: OnceCell<StandingIndex>,
    /// Whether each roster event changes who administers, over the last
    /// set of valid roster events the twin checks read ([`Facts`]): the
    /// same set gives the same places, so the same answers. Empty to start
    /// with.
    pub administration: RefCell<Option<(BTreeSet<EventId>, AdministrationMemo)>>,
    /// The root of a checkpoint's world, when the log is one (roster.md,
    /// 3.15.5); `None` for a log rooted at its genesis.
    pub world: Option<&'s WorldRoot>,
}

/// Whether each roster event changes who administers, over one set of
/// valid roster events.
pub type AdministrationMemo = Rc<RefCell<BTreeMap<EventId, bool>>>;

/// roster.md, 3.7 "Standing": for each device, the opened roster events of
/// a view, the genesis included and valid or void, that name it at
/// `administer`; with ext-invite-links.md, for each invite key, those that
/// grant it.
#[derive(Debug, Default)]
pub struct StandingIndex {
    administer: BTreeMap<[u8; 32], Vec<EventId>>,
    invites: BTreeMap<[u8; 32], Vec<EventId>>,
}

impl StandingIndex {
    /// The index over every opened event of `screened`.
    pub fn new(screened: &ScreenedLog) -> Self {
        Self::rooted(screened, None)
    }

    /// The index over every opened event of `screened`, in the world of a
    /// checkpoint when `world` is given: there the checkpoint stands for the
    /// genesis, so it names its record's administrators, and the genesis
    /// names nobody (roster.md, 3.15.5 The world after a checkpoint).
    pub fn rooted(screened: &ScreenedLog, world: Option<&WorldRoot>) -> Self {
        let mut index = Self::default();
        if let Some(world) = world {
            for change in &world.changes {
                let Some(member) = change.member else {
                    continue;
                };
                if member.kind == crate::MemberType::Device
                    && change.level == Some(Level::Administer)
                {
                    index
                        .administer
                        .entry(member.id)
                        .or_default()
                        .push(world.root);
                } else if member.kind == crate::MemberType::Invite {
                    // The record's invite keys are granted at the root, the
                    // claimed ones included.
                    index.invites.entry(member.id).or_default().push(world.root);
                }
            }
        }
        for &id in screened.events() {
            if world.is_some() && id == screened.space() {
                continue;
            }
            let Some(opened) = screened.opened(id) else {
                continue;
            };
            for change in opened.changes() {
                let Some(member) = change.member else {
                    continue;
                };
                let names = match member.kind {
                    crate::MemberType::Device
                        if matches!(change.op, Op::Grant | Op::Change)
                            && change.level == Some(Level::Administer) =>
                    {
                        &mut index.administer
                    }
                    crate::MemberType::Invite if change.op == Op::Grant => &mut index.invites,
                    _ => continue,
                };
                let events = names.entry(member.id).or_default();
                if events.last() != Some(&id) {
                    events.push(id);
                }
            }
        }
        index
    }

    /// The events that name `device` at `administer`.
    pub fn administer(&self, device: &[u8; 32]) -> &[EventId] {
        self.administer.get(device).map_or(&[], Vec::as_slice)
    }

    /// The events that grant the invite key `key`.
    pub fn invite(&self, key: &[u8; 32]) -> &[EventId] {
        self.invites.get(key).map_or(&[], Vec::as_slice)
    }
}

impl<'s> Judge<'s> {
    /// [`Log::precedes`], read from the view's space pasts where it can.
    pub(crate) fn precedes_fast(&self, earlier: EventId, later: EventId) -> bool {
        precedes_in(self.log, self.pasts, earlier, later)
    }

    /// [`Log::concurrent`], read from the view's space pasts where it can.
    pub(crate) fn concurrent_fast(&self, a: EventId, b: EventId) -> bool {
        a != b && !self.precedes_fast(a, b) && !self.precedes_fast(b, a)
    }

    /// The events that can give an author standing, found once.
    pub(crate) fn standing_index(&self) -> &StandingIndex {
        self.standing
            .get_or_init(|| StandingIndex::rooted(self.screened, self.world))
    }

    /// The events of the view that could give `event`'s author standing in
    /// some event's past: those that name it at `administer`, or for an
    /// ext-invite-links.md successor, those that grant its invite key.
    pub(crate) fn standing_candidates(&self, event: EventId) -> &[EventId] {
        let author = self.author(event).0;
        let index = self.standing_index();
        if crate::ext::is_successor(self.changes(event)) {
            index.invite(&author)
        } else {
            index.administer(&author)
        }
    }

    /// roster.md, 3.7 "Standing": an event of the event's past, the genesis
    /// included, names its author at `administer` (for a successor, grants
    /// its invite key). A device's state reaches `administer` at a place
    /// only through such a change in that place (3.2 "The roster at a
    /// place": a grant gives its own level, a change its level or the prior
    /// one, and the meet takes the lowest), so an author without standing
    /// is no administrator at its event's place under any assignment. An
    /// author that no event of the view names costs no walk.
    pub(crate) fn has_standing(&self, event: EventId) -> bool {
        self.standing_candidates(event)
            .iter()
            .any(|&named| self.precedes_fast(named, event))
    }

    pub(crate) fn author(&self, event: EventId) -> DeviceId {
        self.log
            .event(event)
            .map_or(DeviceId([0; 32]), |e| *e.author())
    }

    pub(crate) fn changes(&self, event: EventId) -> &'s [Change] {
        self.screened
            .opened(event)
            .map_or(&[], |opened| opened.changes())
    }

    /// The duels' shields among `contested` ("What attacks what"), found
    /// once for each set of contested events.
    pub(crate) fn shields(&self, contested: &[EventId]) -> Rc<Shields> {
        if let Some((seen, shields)) = &*self.shields.borrow()
            && seen == contested
        {
            return Rc::clone(shields);
        }
        let shields = Rc::new(Shields::new(
            contested,
            |a, b| self.concurrent_fast(a, b),
            |a, b| self.precedes_fast(a, b),
            |id| self.side(id),
        ));
        *self.shields.borrow_mut() = Some((contested.to_vec(), Rc::clone(&shields)));
        shields
    }

    fn side(&self, event: EventId) -> Side<'s> {
        Side {
            author: self.log.event(event).map_or(&NO_AUTHOR, |e| e.author()),
            changes: self.changes(event),
        }
    }

    /// The log's root: the genesis, or in a checkpoint's world the
    /// checkpoint.
    pub(crate) fn root(&self) -> EventId {
        self.world.map_or_else(|| self.log.id(), |world| world.root)
    }

    /// The event's place under the procedure's statuses: the genesis (the
    /// root) and the valid contested events of its past.
    fn place(&self, event: EventId, view: &View<'_, Self>) -> BTreeSet<EventId> {
        let mut place: BTreeSet<EventId> = view.place(event).into_iter().collect();
        place.insert(self.root());
        place
    }

    /// Whether `x`'s author outranks `e`'s author, each at its own event's
    /// place (roster.md, 3.5.2, mutual pairs): `None` when either is not in
    /// there, which no valid event's author is.
    fn outranks_at(&self, x: EventId, e: EventId, view: &View<'_, Self>) -> Option<bool> {
        let at = |event: EventId| {
            let roster = self.places.roster(&self.place(event, view));
            roster
                .state(&self.side(event).author_member())
                .map(|state| state.authority_key())
        };
        Some(at(x)? < at(e)?)
    }

    /// Steps 1 to 5 at a place; for ext-invite-links.md's successor, that
    /// document's steps in place of 1 to 3.
    fn core(&self, event: EventId, place: &BTreeSet<EventId>) -> Result<(), RosterClass> {
        #[cfg(feature = "ext-invite-links")]
        if let Some(verdict) = crate::ext_invite_links::successor_authority(self, event, place) {
            return verdict;
        }
        let author = self.author(event);
        let roster = self.places.roster(place);
        let me = MemberRef::device(author);
        // 1.
        if !roster.is_administrator(&author.0) {
            return Err(ErrorClass::NotAnAdministrator.into());
        }
        let mine = roster
            .state(&me)
            .and_then(|state| state.rank)
            .unwrap_or(crate::change::MAX_RANK);
        // 2.
        let changes = self.changes(event);
        for change in changes {
            let Some(member) = change.member else {
                continue;
            };
            let current = roster.state(&member);
            // ext-invite-links.md: an invite key is granted once, and its
            // removal after a valid successor is the close.
            #[cfg(feature = "ext-invite-links")]
            if let Some(verdict) =
                crate::ext_invite_links::invite_change_authority(self, change, &roster, place)
            {
                verdict?;
                continue;
            }
            match change.op {
                Op::Grant if member == me => return Err(SpaceClass::SelfGrant.into()),
                Op::Grant if current.is_some() => return Err(SpaceClass::AlreadyMember.into()),
                // Ranks: no grant of a rank above its author's.
                Op::Grant if change.rank.is_some_and(|rank| rank > mine) => {
                    return Err(SpaceClass::HigherRank.into());
                }
                Op::Grant | Op::Policy => {}
                Op::Change | Op::Remove => {
                    let Some(current) = current else {
                        return Err(SpaceClass::NoSuchMember.into());
                    };
                    let only_lowers = change.level.is_some_and(|l| l < current.level)
                        && change.capabilities.is_none()
                        && change.label.is_none();
                    if change.op == Op::Change && member == me && !only_lowers {
                        return Err(SpaceClass::SelfChange.into());
                    }
                    // A change carries no `session`: whether it raises a
                    // guest is the roster's at its place.
                    if change.op == Op::Change
                        && change.level == Some(Level::Administer)
                        && current.session.is_some()
                    {
                        return Err(SpaceClass::AdministerNotDevice.into());
                    }
                    // Ranks (section 3.6): nobody changes or removes an
                    // administrator of a higher rank than its own, or sets a
                    // rank above its own; a rank is set when a device
                    // becomes an administrator, never changed in place.
                    let at_administer = current.level == Level::Administer;
                    if at_administer && member != me && current.rank.is_some_and(|rank| rank > mine)
                    {
                        return Err(SpaceClass::HigherRank.into());
                    }
                    if change.op == Op::Change && change.rank.is_some_and(|rank| rank > mine) {
                        return Err(SpaceClass::HigherRank.into());
                    }
                    if change.op == Op::Change
                        && change.level == Some(Level::Administer)
                        && at_administer
                        && change.rank != current.rank
                    {
                        return Err(SpaceClass::RankInPlace.into());
                    }
                }
                // A successor is ext-invite-links.md's, held by a core
                // implementation before it is offered.
                Op::Succeed => return Err(ErrorClass::ExtensionRequired.into()),
            }
        }
        // 3.
        if changes.len() > 1 && changes.iter().any(|c| lowers_administrator(c, &roster)) {
            return Err(SpaceClass::AdminAlone.into());
        }
        // 4.
        if place.len() + 1 > self.limits.max_roster_events {
            return Err(ErrorClass::Full.into());
        }
        // 5.
        self.place_checks(event, place, &roster)
    }

    /// Step 5: keys.md's checks against the event and its place, with the
    /// context it derives from the event's changes and the roster at its
    /// place.
    pub(crate) fn place_checks(
        &self,
        event: EventId,
        place: &BTreeSet<EventId>,
        roster: &Roster,
    ) -> Result<(), RosterClass> {
        let author = self.author(event);
        let changes = self.changes(event);
        let opened = self
            .screened
            .opened(event)
            .ok_or_else(|| RosterClass::from(ErrorClass::Pending))?;
        let mut context = roster_context(&author, changes, roster);
        context.restricted =
            self.screened.genesis().descriptor.kind == crate::DescriptorKind::Restricted;
        context.responds = opened.inner.responds();
        context.sealed_under_stale = self.stale(event, place);
        let named = place
            .iter()
            .filter_map(|&p| self.screened.opened(p))
            .flat_map(|o| o.inner.refs.iter())
            .chain(&opened.inner.refs)
            .copied()
            .collect();
        let query = crate::space::NoticeQuery {
            event,
            author: author.0,
            opened,
            granted: crate::space::granted_spaces(roster),
            named,
        };
        crate::space::check_with_notices(self.notices, &query, context)
    }

    /// keys.md's `StaleSeal` condition: the event does not rotate, and a
    /// valid rotation of `valid` in its past follows a rotation of the
    /// state it is sealed under.
    pub fn stale(&self, event: EventId, valid: &BTreeSet<EventId>) -> bool {
        if let Some(world) = self.world
            && self.stale_against_checkpoint(world, event)
        {
            return true;
        }
        stale_in(self.log, self.pasts, self.screened, event, valid)
    }

    /// In a checkpoint's world, keys.md's `StaleSeal` read against the
    /// checkpoint ([`frasil_keys::checkpoint::seal_against_checkpoint`]): an
    /// event sealed under a state with a rotation that is neither the
    /// checkpoint nor an event of the world in its past is stale, since the
    /// checkpoint follows every rotation before it.
    fn stale_against_checkpoint(&self, world: &WorldRoot, event: EventId) -> bool {
        let Some(state) = self
            .screened
            .opened(event)
            .and_then(|opened| opened.visible.sealed_under())
        else {
            return false;
        };
        let rooted = WorldSides {
            log: self.log,
            root: world.root,
        };
        let in_past = |r: &EventId| precedes_in(self.log, self.pasts, *r, event);
        frasil_keys::checkpoint::seal_against_checkpoint(&rooted, state, in_past)
            == frasil_keys::checkpoint::SealPlace::Stale
    }

    /// Step 6, "The twin": visible key 15 names the twin exactly when the
    /// event changes who administers at its place, and the twin it names
    /// passes peers.md's replica checks.
    fn twin(
        &self,
        skeleton: &Skeleton<'_>,
        event: EventId,
        place: &BTreeSet<EventId>,
        valid: &BTreeSet<EventId>,
    ) -> Result<(), RosterClass> {
        let roster = self.places.roster(place);
        let changes = administer_changes(self.changes(event), &roster);
        let named = self
            .screened
            .opened(event)
            .and_then(|opened| opened.visible.twin);
        check_twin_named(named.as_ref(), &changes)?;
        if !changes.changes_administration() {
            return Ok(());
        }
        let facts = Facts::new(self, valid.clone());
        TwinChecks::new(skeleton, &facts)
            .check(event)
            .map_err(|failure| failure.class().into())
    }

    /// The valid contested events under the procedure's statuses, with the
    /// genesis: what the twin checks read of other roster events' places.
    fn valid_now(&self, view: &View<'_, Self>) -> BTreeSet<EventId> {
        let mut valid: BTreeSet<EventId> = view
            .contested()
            .iter()
            .copied()
            .filter(|&e| view.is_valid(e))
            .collect();
        valid.insert(self.root());
        valid
    }

    /// Step 0: a roster event in the past waits for its twin.
    fn waits_for_twin(
        &self,
        skeleton: &Skeleton<'_>,
        event: EventId,
        view: &View<'_, Self>,
    ) -> bool {
        let no_twin = RosterClass::from(PeersClass::NoTwin);
        view.contested().iter().copied().any(|p| {
            if !self.precedes_fast(p, event) {
                return false;
            }
            match view.standing(p) {
                Some(Standing::Void { class, .. }) => class == no_twin,
                Some(Standing::Trial(false)) => {
                    let place = self.place(p, view);
                    self.core(p, &place).is_ok()
                        && self.twin(skeleton, p, &place, &self.valid_now(view)) == Err(no_twin)
                }
                _ => false,
            }
        })
    }
}

/// Whether a change lowers a device member that is in the roster at
/// `administer` (step 3).
fn lowers_administrator(change: &Change, roster: &Roster) -> bool {
    let Some(member) = change
        .member
        .filter(|m| m.kind == crate::MemberType::Device)
    else {
        return false;
    };
    let Some(current) = roster.state(&member) else {
        return false;
    };
    let lowers = change.op == Op::Remove
        || (change.op == Op::Change && change.level.is_some_and(|l| l < current.level));
    lowers && current.level == Level::Administer
}

/// keys.md's context for the checks against a roster event and its place,
/// from its changes and the roster `S` at its place (keys.md, "Checks
/// against the event and its place"). `responds`, `restricted` and
/// `sealed_under_stale` are the caller's to set.
pub fn roster_context(author: &DeviceId, changes: &[Change], roster: &Roster) -> Context {
    let me = attacks::author_member(author, changes);
    let mut context = Context::new(EventKind::Roster);
    context.author_propagates = roster.state(&me).is_some_and(|s| s.session.is_none());
    let lowering = self_lowering(&author.0, changes);
    for change in changes {
        let current = change.member.and_then(|m| roster.state(&m));
        match (change.op, current) {
            (Op::Remove, Some(current)) => {
                context.removes = true;
                if change.member == Some(me) {
                    context.removes_self = true;
                } else if current.session.is_none() && !lowering {
                    context.removes_propagating = true;
                }
            }
            (Op::Change, Some(current)) => {
                if let Some(level) = change.level.filter(|&l| l < current.level) {
                    if change.member == Some(me) {
                        context.lowers_self = true;
                    }
                    if level == Level::Read {
                        context.lowers_to_read = true;
                    }
                }
            }
            (Op::Grant, _) if change.history == Some(HistoryMode::FromNowOn) => {
                context.admits_from_now_on = true;
                if change.session.is_none() {
                    context.admits_propagating = true;
                }
            }
            _ => {}
        }
    }
    context
}

/// Where an event stands against the root of a checkpoint's world, read
/// from the world's log: the events it places, but its genesis, follow the
/// checkpoint; every other event is outside the world.
struct WorldSides<'l> {
    log: &'l Log,
    root: EventId,
}

impl frasil_keys::checkpoint::Rooted for WorldSides<'_> {
    fn checkpoint(&self) -> EventId {
        self.root
    }

    fn side(&self, id: &EventId) -> frasil_keys::checkpoint::Side {
        use frasil_keys::checkpoint::Side;
        if *id == self.root {
            Side::Root
        } else if *id != self.log.id() && self.log.event(*id).is_some() {
            Side::After
        } else {
            Side::Unknown
        }
    }
}

/// keys.md's `StaleSeal` condition for a space event of a screened log:
/// it does not rotate, and a rotation of `valid` in its past follows a
/// rotation of the state it is sealed under.
pub fn stale(log: &Log, screened: &ScreenedLog, event: EventId, valid: &BTreeSet<EventId>) -> bool {
    stale_in(log, None, screened, event, valid)
}

/// [`stale`], with the causal order read from the view's space pasts
/// where it can.
fn stale_in(
    log: &Log,
    pasts: Option<Pasts<'_>>,
    screened: &ScreenedLog,
    event: EventId,
    valid: &BTreeSet<EventId>,
) -> bool {
    let Some(state) = screened
        .opened(event)
        .and_then(|opened| opened.visible.sealed_under())
    else {
        return false;
    };
    let sealed = state.ids();
    valid.iter().any(|&r| {
        screened
            .opened(r)
            .is_some_and(|opened| opened.visible.rotates())
            && !sealed.contains(&r)
            && precedes_in(log, pasts, r, event)
            && sealed.iter().any(|&x| precedes_in(log, pasts, x, r))
    })
}

impl<'s> Resolve for Judge<'s> {
    type Id = EventId;
    type Class = RosterClass;
    type PickKey = PickKey;

    fn height(&self, event: EventId) -> u64 {
        let offset = self.world.map_or(0, |world| world.height_offset);
        self.log.height(event).unwrap_or(0).saturating_sub(offset)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.precedes_fast(earlier, later)
    }

    /// "The event alone", steps 1 to 11.
    fn check(&self, event: EventId) -> Result<(), RosterClass> {
        self.screened
            .verdict(event)
            .unwrap_or_else(|| Err(ErrorClass::Pending.into()))
    }

    /// Step 12: the author's fork point is at or below `seq`. An
    /// ext-invite-links.md successor takes that document's race rule
    /// instead.
    fn forked(&self, event: EventId) -> Option<RosterClass> {
        if crate::ext::is_successor(self.changes(event)) {
            return None;
        }
        let event = self.log.event(event)?;
        self.forks.is_void(event).then(|| ErrorClass::Forked.into())
    }

    fn self_lowering(&self, event: EventId) -> bool {
        self_lowering(&self.author(event).0, self.changes(event))
    }

    /// 3.7 "Standing": an event whose author has no standing in its past is
    /// void before the procedure and is not contested, `NotAnAdministrator`
    /// (section 3.6, step 1); for a successor, ext-invite-links.md's class.
    /// Step 0, `Pending` behind a roster event that waits for its twin, is
    /// the space's to apply once the procedure has found those.
    fn check_among(&self, event: EventId, _screened: &[EventId]) -> Result<(), RosterClass> {
        if self.has_standing(event) {
            return Ok(());
        }
        #[cfg(feature = "ext-invite-links")]
        if crate::ext::is_successor(self.changes(event)) {
            return Err(crate::ext_invite_links::without_standing(self, event));
        }
        Err(ErrorClass::NotAnAdministrator.into())
    }

    fn authority(&self, event: EventId, view: &View<'_, Self>) -> Result<(), RosterClass> {
        // 0.
        if let Some(skeleton) = self.skeleton
            && self.waits_for_twin(skeleton, event, view)
        {
            return Err(ErrorClass::Pending.into());
        }
        let place = self.place(event, view);
        // 1. to 5.
        self.core(event, &place)?;
        // 6.
        if let Some(skeleton) = self.skeleton {
            self.twin(skeleton, event, &place, &self.valid_now(view))?;
        }
        Ok(())
    }

    fn attack(&self, attacker: EventId, event: EventId) -> Option<RosterClass> {
        let concurrent = self.concurrent_fast(attacker, event);
        attacks::attack(self.side(attacker), self.side(event), concurrent)
    }

    fn mutual(&self, attacker: EventId, event: EventId) -> bool {
        let concurrent = self.concurrent_fast(attacker, event);
        attacks::mutual(self.side(attacker), self.side(event), concurrent)
    }

    /// "What attacks what": in a mutual pair the attack counts exactly when
    /// its author outranks its partner's, each at its own event's place,
    /// which waits for both contested pasts; otherwise a partner that
    /// lowers each other with the attacker and has one change is spared,
    /// and no duel undoes its partner's authority, which reads no status.
    fn attack_counts(
        &self,
        attacker: EventId,
        event: EventId,
        view: &View<'_, Self>,
    ) -> Option<bool> {
        let class = self.attack(attacker, event)?;
        if self.mutual(attacker, event) {
            if !(view.past_decided(attacker) && view.past_decided(event)) {
                return None;
            }
            return self.outranks_at(attacker, event, view);
        }
        let shields = self.shields(view.contested());
        Some(attacks::counts(
            (attacker, self.side(attacker)),
            (event, self.side(event)),
            self.concurrent_fast(attacker, event),
            class,
            &shields,
        ))
    }

    fn pick_key(&self, event: EventId, view: &View<'_, Self>) -> PickKey {
        let roster = self.places.roster(&self.place(event, view));
        let state = roster.state(&self.side(event).author_member());
        let rank = state.and_then(|state| state.rank).unwrap_or(0);
        (
            crate::change::MAX_RANK - rank,
            state.map(|state| state.seniority),
            self.height(event),
            event,
        )
    }
}

/// What the twin checks read of the roster (`frasil-peers`' [`RosterFacts`]),
/// over a set of valid roster events: each event's administer changes and
/// administrators at its own place within that set.
pub struct Facts<'j, 's> {
    judge: &'j Judge<'s>,
    valid: BTreeSet<EventId>,
    /// Every valid event is a space event of the view whose pasts the
    /// judge holds, so places read from those pasts.
    valid_in_pasts: bool,
    administration: AdministrationMemo,
}

impl<'j, 's> Facts<'j, 's> {
    /// The roster's facts over `valid`, the genesis and valid roster events.
    pub fn new(judge: &'j Judge<'s>, valid: BTreeSet<EventId>) -> Self {
        let administration = {
            let mut kept = judge.administration.borrow_mut();
            match &*kept {
                Some((over, memo)) if *over == valid => Rc::clone(memo),
                _ => {
                    let memo = AdministrationMemo::default();
                    *kept = Some((valid.clone(), Rc::clone(&memo)));
                    memo
                }
            }
        };
        let valid_in_pasts = judge.pasts.is_some_and(|pasts| {
            valid.iter().all(|id| {
                pasts.view.contains(id)
                    && judge
                        .log
                        .event(*id)
                        .is_some_and(|e| e.kind() == frasil_events::kind::SPACE)
            })
        });
        Self {
            judge,
            valid,
            valid_in_pasts,
            administration,
        }
    }

    fn roster_at(&self, event: EventId) -> std::rc::Rc<Roster> {
        let places = self.judge.places;
        places.roster(&self.place_of(event))
    }

    /// `event`'s place within the valid set: [`Places::place_of`], read from
    /// the view's space pasts when they were found. The valid set holds the
    /// genesis and roster events of the view, all space events, so each is
    /// in `event`'s past exactly when that past holds it.
    fn place_of(&self, event: EventId) -> BTreeSet<EventId> {
        match self.judge.pasts.and_then(|pasts| pasts.past.get(&event)) {
            Some(past) if self.valid_in_pasts => {
                let mut place: BTreeSet<EventId> = past
                    .iter()
                    .copied()
                    .filter(|id| self.valid.contains(id))
                    .collect();
                place.insert(self.judge.root());
                place
            }
            _ => self.judge.places.place_of(event, &self.valid),
        }
    }
}

impl RosterFacts for Facts<'_, '_> {
    fn opened(&self) -> Vec<EventId> {
        let screened = self.judge.screened;
        screened
            .events()
            .iter()
            .copied()
            .filter(|&id| screened.opened(id).is_some_and(|o| o.is_roster()))
            .collect()
    }

    fn body_key(&self, event: EventId) -> Option<[u8; 32]> {
        self.judge
            .screened
            .opened(event)
            .map(|opened| *opened.body_key)
    }

    fn administer_changes(&self, event: EventId) -> AdministerChanges {
        if let Some(world) = self.judge.world
            && event == world.root
        {
            return administer_changes(&world.changes, &Roster::default());
        }
        if event == self.judge.log.id() {
            return AdministerChanges {
                grants: vec![self.judge.author(event)],
                lowers: Vec::new(),
            };
        }
        administer_changes(self.judge.changes(event), &self.roster_at(event))
    }

    fn grant_ranks(&self, event: EventId) -> Vec<u8> {
        if let Some(world) = self.judge.world
            && event == world.root
        {
            return administer_grant_ranks(&world.changes, &Roster::default());
        }
        if event == self.judge.log.id() {
            return vec![crate::change::MAX_RANK];
        }
        administer_grant_ranks(self.judge.changes(event), &self.roster_at(event))
    }

    fn twin_of(&self, event: &frasil_events::Event) -> Option<EventId> {
        // An opened event's visible part, read once at the screen.
        match self.judge.screened.opened(event.id()) {
            Some(opened) => opened.visible.twin.map(EventId),
            None => frasil_peers::skeleton::named_twin(event),
        }
    }

    fn changes_administration(&self, event: EventId) -> bool {
        if let Some(&known) = self.administration.borrow().get(&event) {
            return known;
        }
        let changes = self.administer_changes(event).changes_administration();
        self.administration.borrow_mut().insert(event, changes);
        changes
    }

    fn duel_policy(&self) -> u64 {
        self.judge.screened.genesis().duel_policy
    }

    /// In a checkpoint's world, a device the record carries is known by the
    /// keys the record gives it, whose genesis grants name no device: a
    /// slot of the cut enrolled again after the checkpoint binds to it by
    /// them (peers.md, 3.13, and "Skeleton cuts", "A late enrolment").
    fn device_keys(&self, device: &DeviceId) -> Option<DeviceKeys> {
        self.judge.screened.keys().device_keys(device).or_else(|| {
            let world = self.judge.world?;
            let mut ring = frasil_crypto::device::KeyRing::new();
            for change in &world.changes {
                if let Some(keys) = &change.keys {
                    ring.add_device(DeviceKeys::clone(keys));
                }
            }
            ring.device_keys(device)
        })
    }

    fn is_administrator_at(&self, device: &DeviceId, event: EventId) -> bool {
        self.roster_at(event).is_administrator(&device.0)
    }

    /// In a checkpoint's world, a slot of its cut maps as the record's
    /// `slot` entries say (roster.md, 3.15.5, Skeleton).
    fn cut_slot(&self, slot: frasil_peers::body::SlotId) -> Option<(DeviceId, Option<DeviceId>)> {
        self.judge.world?.cut_slots.get(&slot).copied()
    }
}
