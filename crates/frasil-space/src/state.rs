//! The roster at a place (roster.md, "The roster at a place"), and what the
//! rules read of an event and the roster at its place: who it makes or
//! unmakes an administrator, whether it names its twin where it must
//! ("The twin", step 1), and whether it is self-lowering ("Self-lowering
//! events").
//!
//! **Member state.** Given a place `V`, a set of valid roster events with
//! the genesis, the state of member `m`:
//!
//! 1. Take the events of `V` with a change naming `m`. Keep the
//!    **maximal** ones, those no other of them follows.
//! 2. If any maximal one removes `m`, `m` is **out**.
//! 3. Otherwise `m` is **in**, with the meet of the states its maximal
//!    changes give. A grant gives its own fields. A change gives `m`'s
//!    state at the change's own place, with the fields it sets replaced.
//!
//! A member never named is absent. Absent and out are both "not in".
//!
//! Which events are valid, and so which places exist, is the resolution's
//! (`frasil-resolve`); this module takes the place as given, through
//! [`RosterEvents`].
//!
//! **In the world of a checkpoint** (roster.md, 3.15.5 The world after a
//! checkpoint) the log's root is the checkpoint, not the genesis: each
//! member entry of its record stands as a grant at the root, with the
//! entry's state and seniority ([`WorldRoot`]), heights count from the
//! root, and a grant made there has the checkpoint's epoch, which comes
//! first in its seniority.

use crate::SpaceClass;
use crate::change::{Change, MAX_RANK, Op};
use crate::member::{Capability, CapabilityMode, HistoryMode, Level, MemberRef, MemberType, Via};
use crate::policy::Policy;
use crate::screen::ScreenedLog;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::labels::ROSTER_SENIORITY;
use frasil_crypto::primitives::sha256;
use frasil_events::{EventId, Log};
use frasil_peers::twins::AdministerChanges;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

/// What the roster at a place reads of a space's log: each roster event's
/// changes and the causal order.
pub trait RosterEvents {
    /// The space ID, the genesis's event ID.
    fn space(&self) -> EventId;

    /// The log's root, which every place holds: the genesis, or in the
    /// world of a checkpoint the checkpoint (roster.md, 3.15.5).
    fn root(&self) -> EventId {
        self.space()
    }

    /// The epoch grants of this log are made in: 0 before any checkpoint,
    /// the checkpoint's in its world.
    fn epoch(&self) -> u64 {
        0
    }

    /// The state a record gives a member at the root of a checkpoint's
    /// world, in place of the state its grant there would give.
    fn root_state(&self, member: &MemberRef) -> Option<MemberState> {
        let _ = member;
        None
    }

    /// The members the root of a checkpoint's world puts out: the invite
    /// keys its record shows claimed, out as if the checkpoint were their
    /// valid successor (roster.md, 3.15.5).
    fn root_out(&self) -> Vec<MemberRef> {
        Vec::new()
    }

    /// The changes an opened roster event makes: the founder's grant for
    /// the genesis, none for a key event.
    fn changes(&self, event: EventId) -> &[Change];

    /// The event's height.
    fn height(&self, event: EventId) -> u64;

    /// Whether `earlier` is in the past of `later`.
    fn precedes(&self, earlier: EventId, later: EventId) -> bool;

    /// The events of `among` in the past of `later`: each one
    /// [`precedes`](Self::precedes) finds before it.
    fn before_among(&self, among: &BTreeSet<EventId>, later: EventId) -> BTreeSet<EventId> {
        among
            .iter()
            .copied()
            .filter(|&earlier| self.precedes(earlier, later))
            .collect()
    }

    /// The event's author: ext-invite-links.md's successor is signed by its
    /// invite key, which it puts out.
    #[cfg(feature = "ext-invite-links")]
    fn author(&self, event: EventId) -> [u8; 32];
}

/// A log and its screen: the roster events every rule reads.
#[derive(Debug, Clone, Copy)]
pub struct RosterLog<'a> {
    /// The log.
    pub log: &'a Log,
    /// Its space events, each checked alone.
    pub screened: &'a ScreenedLog,
    /// The view's space pasts, when found once: causal order between its
    /// space events read from them rather than walked.
    pub pasts: Option<Pasts<'a>>,
    /// The root of a checkpoint's world, when the log is one; `None` for a
    /// log rooted at its genesis.
    pub world: Option<&'a WorldRoot>,
}

/// The root of a checkpoint's world (roster.md, 3.15.5 The world after a
/// checkpoint): the checkpoint stands as the log's genesis, each member
/// entry of its record as a grant in it with the entry's state and
/// seniority, and the record's policy as the genesis policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldRoot {
    /// The checkpoint.
    pub root: EventId,
    /// Its epoch: the record's.
    pub epoch: u64,
    /// A grant for each member entry of the record: what the roster at a
    /// place reads as the root's changes.
    pub changes: Vec<Change>,
    /// Each member's state as the record gives it.
    pub states: BTreeMap<MemberRef, MemberState>,
    /// The record's policy.
    pub policy: Policy,
    /// The record's fork points: an author forked there stays forked.
    pub forks: BTreeMap<DeviceId, u64>,
    /// The record's chain tips: an author that signs at or below its tip
    /// after the checkpoint forks from that `seq`.
    pub tips: BTreeMap<DeviceId, (u64, EventId)>,
    /// What the log a world is resolved over adds to each height: the
    /// checkpoint's own height there, so that heights count from it at 0.
    pub height_offset: u64,
    /// The invite keys the record shows claimed: out, as if the checkpoint
    /// were their valid successor, so that a close of one is valid.
    pub claimed: BTreeSet<MemberRef>,
    /// The invite keys whose recorded status is not open: the checkpoint
    /// counts as a successor of each, so a later successor of one is
    /// `InviteUsed` (ext-invite-links.md, "Across a checkpoint").
    pub used: BTreeSet<[u8; 32]>,
    /// The notices the record keeps, each with its granted space: the
    /// checkpoint carries them as its own, by the authors the record names.
    pub notices: Vec<(EventId, crate::checkpoint_record::RecordNotice)>,
    /// The granted spaces' event IDs the record names: the checkpoint names
    /// them in its sealed refs.
    pub named: Vec<frasil_events::Ref>,
    /// The invite keys the record shows raced: in, but outside for the key
    /// graph (keys.md, "Keys after a checkpoint").
    pub raced: BTreeSet<MemberRef>,
    /// The granted spaces the record gives a floor: a principal of one is
    /// entitled to no state before the checkpoint.
    pub floors: BTreeSet<EventId>,
    /// The administrator slots of the checkpoint's cut that the record's
    /// `slot` entries name, each with the device whose entry names it and
    /// the pseudonym that entry names, if any: how the skeleton after the
    /// cut maps the cut's slots and pseudonyms to devices (roster.md,
    /// 3.15.5 The world after a checkpoint, Skeleton).
    pub cut_slots: BTreeMap<frasil_peers::body::SlotId, (DeviceId, Option<DeviceId>)>,
}

/// The space events in the past of each event of a view, found once from
/// parents ([`crate::Space`] finds them at a full replica whose log has no
/// witness): [`Log::precedes`] between two space events of the view, read
/// without a walk. The answer is the walk's: a space event is in an
/// event's past set exactly when the walk finds it.
#[derive(Debug, Clone, Copy)]
pub struct Pasts<'a> {
    /// The space events in each event's past.
    pub past: &'a BTreeMap<EventId, Arc<BTreeSet<EventId>>>,
    /// The view.
    pub view: &'a BTreeSet<EventId>,
}

/// [`Log::precedes`], from `pasts` when both events are space events of
/// the view, walked otherwise.
pub fn precedes_in(log: &Log, pasts: Option<Pasts<'_>>, earlier: EventId, later: EventId) -> bool {
    if let Some(pasts) = pasts
        && let Some(past) = pasts.past.get(&later)
        && pasts.view.contains(&earlier)
        && log
            .event(earlier)
            .is_some_and(|e| e.kind() == frasil_events::kind::SPACE)
    {
        return past.contains(&earlier);
    }
    log.precedes(earlier, later)
}

impl RosterEvents for RosterLog<'_> {
    fn space(&self) -> EventId {
        self.log.id()
    }

    fn root(&self) -> EventId {
        self.world.map_or_else(|| self.log.id(), |world| world.root)
    }

    fn epoch(&self) -> u64 {
        self.world.map_or(0, |world| world.epoch)
    }

    fn root_state(&self, member: &MemberRef) -> Option<MemberState> {
        self.world?.states.get(member).cloned()
    }

    fn root_out(&self) -> Vec<MemberRef> {
        self.world
            .map(|world| world.claimed.iter().copied().collect())
            .unwrap_or_default()
    }

    fn changes(&self, event: EventId) -> &[Change] {
        if let Some(world) = self.world
            && event == world.root
        {
            return &world.changes;
        }
        self.screened
            .opened(event)
            .map_or(&[], |opened| opened.changes())
    }

    fn height(&self, event: EventId) -> u64 {
        let offset = self.world.map_or(0, |world| world.height_offset);
        self.log.height(event).unwrap_or(0).saturating_sub(offset)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        precedes_in(self.log, self.pasts, earlier, later)
    }

    fn before_among(&self, among: &BTreeSet<EventId>, later: EventId) -> BTreeSet<EventId> {
        // `later`'s past read once; an event outside it is before `later`
        // only if it is not a space event of the view, which is walked.
        let Some((pasts, past)) = self
            .pasts
            .and_then(|pasts| Some((pasts, pasts.past.get(&later)?)))
        else {
            return among
                .iter()
                .copied()
                .filter(|&earlier| self.precedes(earlier, later))
                .collect();
        };
        among
            .iter()
            .copied()
            .filter(|&earlier| {
                past.contains(&earlier)
                    || (!(pasts.view.contains(&earlier)
                        && self
                            .log
                            .event(earlier)
                            .is_some_and(|e| e.kind() == frasil_events::kind::SPACE))
                        && self.log.precedes(earlier, later))
            })
            .collect()
    }

    #[cfg(feature = "ext-invite-links")]
    fn author(&self, event: EventId) -> [u8; 32] {
        self.log
            .event(event)
            .map(|e| e.author().0)
            .unwrap_or_default()
    }
}

/// `SHA-256("frasil/roster/seniority/v1" || space ID || member ID)`, which
/// the granter does not choose.
pub fn seniority_hash(space: &EventId, member: &[u8; 32]) -> [u8; 32] {
    sha256(&[ROSTER_SENIORITY, space.as_bytes(), member])
}

/// A grant's seniority, smallest first: `(epoch, height, seniority_hash,
/// event ID)`. The founder's grant, the genesis at height 0, is the most
/// senior. The epoch is 0 for a grant made before any checkpoint, and a
/// checkpoint's epoch for one made in its world, where heights count from
/// the checkpoint (roster.md, 3.15.5 The world after a checkpoint): a member
/// of a record keeps the seniority the record gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seniority {
    /// The epoch the grant was made in.
    pub epoch: u64,
    /// The grant's height, in its epoch's world.
    pub height: u64,
    /// [`seniority_hash`] of the space and the grantee.
    pub hash: [u8; 32],
    /// The grant's event ID, which breaks the last tie.
    pub grant: EventId,
}

/// A member's state in the roster at a place, while it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    /// Its level.
    pub level: Level,
    /// Its capabilities, by name then mode.
    pub capabilities: BTreeSet<Capability>,
    /// Its label: shown, never checked.
    pub label: Option<String>,
    /// Its history mode.
    pub history: HistoryMode,
    /// How it was admitted: shown, never checked.
    pub via: Via,
    /// The session a guest belongs to.
    pub session: Option<[u8; 16]>,
    /// The person ID a granted person replaces.
    pub replaces: Option<[u8; 32]>,
    /// The grants in force beneath the state.
    pub grants: BTreeSet<EventId>,
    /// The seniority of its most senior grant in force.
    pub seniority: Seniority,
    /// A device member's keys, which every grant of it carries alike, since
    /// its member ID commits to them.
    pub keys: Option<Arc<DeviceKeys>>,
    /// The canonical order key `(height, ID)` of the event that gave the
    /// state, which the meet reads.
    pub source: (u64, EventId),
    /// The `expires_at` of the grant that gave the state (a guest's, which
    /// comes with its `session`; an invite key's); the meet takes it with
    /// `session` (roster.md, 2.8 The checkpoint record).
    pub expires_at: Option<u64>,
    /// An administrator's rank, exactly at `administer` (roster.md, 2.3
    /// Changes, "Ranks"): its grant's, or that of the change that raised it.
    pub rank: Option<u8>,
}

impl MemberState {
    /// Whether the member propagates: its grant carries no `session`.
    pub fn propagates(&self) -> bool {
        self.session.is_none()
    }

    /// The key of its authority, smallest first: the higher rank, then the
    /// more senior (roster.md, 3.2 "Outranks"). A member without a rank
    /// counts as rank 0.
    pub fn authority_key(&self) -> (u8, Seniority) {
        (MAX_RANK - self.rank.unwrap_or(0), self.seniority)
    }

    /// Whether this member outranks `other`, each at its own place: a
    /// higher rank, or the same rank and the more senior (roster.md, 3.2
    /// "Outranks").
    pub fn outranks(&self, other: &MemberState) -> bool {
        self.authority_key() < other.authority_key()
    }

    /// Its capabilities of one mode, by name.
    pub fn capabilities_of(&self, mode: CapabilityMode) -> impl Iterator<Item = &str> {
        self.capabilities
            .iter()
            .filter(move |c| c.mode == mode)
            .map(|c| c.name.as_str())
    }
}

/// A member named in the roster at a place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// In, with its state.
    In(Box<MemberState>),
    /// Out: removed by these maximal events, in canonical order.
    Out {
        /// The maximal removals.
        removed_by: Vec<EventId>,
    },
}

/// The meet of concurrent states of one member, the most restrictive
/// (roster.md, "The roster at a place"):
///
/// - `level`: the lowest;
/// - capabilities: an extending one stays only if every state has it; a
///   narrowing one stays if any state has it;
/// - `history`: with history only if every state has it;
/// - `session`: present if any state has it, with the value of the state
///   whose event is first in canonical order, and `expires_at` with it;
/// - `label`, `via` and `replaces`: from the state whose event is first in
///   canonical order;
/// - the grants in force: the union;
/// - seniority and the keys: from the most senior grant in force;
/// - `rank`, at `administer`: the lowest.
///
/// `None` for no state.
pub fn meet(states: &[MemberState]) -> Option<MemberState> {
    let first = states.iter().min_by_key(|s| s.source)?;
    let senior = states.iter().min_by_key(|s| s.seniority)?;
    let mut by_source: Vec<&MemberState> = states.iter().collect();
    by_source.sort_by_key(|s| s.source);
    let extends = |c: &&Capability| c.mode == CapabilityMode::Extends;
    let mut capabilities: BTreeSet<Capability> = first
        .capabilities
        .iter()
        .filter(extends)
        .filter(|c| states.iter().all(|s| s.capabilities.contains(c)))
        .cloned()
        .collect();
    for state in states {
        capabilities.extend(
            state
                .capabilities
                .iter()
                .filter(|c| c.mode == CapabilityMode::Narrows)
                .cloned(),
        );
    }
    let level = states.iter().map(|s| s.level).min()?;
    Some(MemberState {
        level,
        rank: if level == Level::Administer {
            states.iter().filter_map(|s| s.rank).min()
        } else {
            None
        },
        capabilities,
        label: first.label.clone(),
        history: if states.iter().all(|s| s.history == HistoryMode::WithHistory) {
            HistoryMode::WithHistory
        } else {
            HistoryMode::FromNowOn
        },
        via: first.via,
        session: by_source.iter().find_map(|s| s.session),
        expires_at: by_source
            .iter()
            .find(|s| s.session.is_some())
            .and_then(|s| s.expires_at),
        replaces: first.replaces,
        grants: states
            .iter()
            .flat_map(|s| s.grants.iter().copied())
            .collect(),
        seniority: senior.seniority,
        keys: senior.keys.clone(),
        source: first.source,
    })
}

/// The roster at a place: every member its events name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    members: BTreeMap<MemberRef, Standing>,
}

impl Roster {
    /// A member's standing, `None` if never named.
    pub fn standing(&self, member: &MemberRef) -> Option<&Standing> {
        self.members.get(member)
    }

    /// A member's state, if it is in.
    pub fn state(&self, member: &MemberRef) -> Option<&MemberState> {
        match self.members.get(member)? {
            Standing::In(state) => Some(state),
            Standing::Out { .. } => None,
        }
    }

    /// Whether a member is in.
    pub fn is_in(&self, member: &MemberRef) -> bool {
        self.state(member).is_some()
    }

    /// A member's level, if it is in.
    pub fn level(&self, member: &MemberRef) -> Option<Level> {
        self.state(member).map(|state| state.level)
    }

    /// Whether a device is an administrator: a device member in at
    /// `administer`.
    pub fn is_administrator(&self, device: &[u8; 32]) -> bool {
        self.level(&MemberRef::device(DeviceId(*device))) == Some(Level::Administer)
    }

    /// The administrators, by device ID.
    pub fn administrators(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.members
            .iter()
            .filter_map(|(member, standing)| match standing {
                Standing::In(state)
                    if member.kind == MemberType::Device && state.level == Level::Administer =>
                {
                    Some(&member.id)
                }
                _ => None,
            })
    }

    /// Every member named, in or out, by reference.
    pub fn iter(&self) -> impl Iterator<Item = (&MemberRef, &Standing)> {
        self.members.iter()
    }

    /// The members in, by reference.
    pub fn members_in(&self) -> impl Iterator<Item = (&MemberRef, &MemberState)> {
        self.members
            .iter()
            .filter_map(|(member, standing)| match standing {
                Standing::In(state) => Some((member, &**state)),
                Standing::Out { .. } => None,
            })
    }
}

/// The rosters already computed for one log's places, by place. The roster
/// at a place depends only on the roster events' changes and their causal
/// order, so one cache serves every [`Places`] over the same events.
pub type PlaceCache = Rc<RefCell<BTreeMap<BTreeSet<EventId>, Rc<Roster>>>>;

/// The rosters at the places of one log, each computed once.
///
/// A place is a set of valid roster events with the genesis. The roster at
/// a place reads the rosters at the places of its changes, so they are
/// cached by place.
pub struct Places<'a, E: RosterEvents> {
    events: &'a E,
    cache: PlaceCache,
}

impl<E: RosterEvents> core::fmt::Debug for Places<'_, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Places")
            .field("cached", &self.cache.borrow().len())
            .finish()
    }
}

impl<'a, E: RosterEvents> Places<'a, E> {
    /// The places of a log's roster events.
    pub fn new(events: &'a E) -> Self {
        Self::with_cache(events, PlaceCache::default())
    }

    /// The places of a log's roster events, sharing a cache with other
    /// [`Places`] over the same events.
    pub fn with_cache(events: &'a E, cache: PlaceCache) -> Self {
        Self { events, cache }
    }

    /// The cache, to share.
    pub fn cache(&self) -> PlaceCache {
        Rc::clone(&self.cache)
    }

    /// The events the places read.
    pub fn events(&self) -> &'a E {
        self.events
    }

    /// The place of `event` within a set of valid roster events: the
    /// genesis (the root) and the events of `valid` in its past.
    pub fn place_of(&self, event: EventId, valid: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let mut place = self.events.before_among(valid, event);
        place.insert(self.events.root());
        place
    }

    /// The roster at a place.
    pub fn roster(&self, place: &BTreeSet<EventId>) -> Rc<Roster> {
        if let Some(hit) = self.cache.borrow().get(place) {
            return Rc::clone(hit);
        }
        let roster = Rc::new(self.compute(place));
        self.cache
            .borrow_mut()
            .insert(place.clone(), Rc::clone(&roster));
        roster
    }

    fn order_key(&self, event: EventId) -> (u64, EventId) {
        (self.events.height(event), event)
    }

    fn compute(&self, place: &BTreeSet<EventId>) -> Roster {
        let mut by_member: BTreeMap<MemberRef, Vec<(EventId, &Change)>> = BTreeMap::new();
        for &event in place {
            for change in self.events.changes(event) {
                if let Some(member) = change.member {
                    by_member.entry(member).or_default().push((event, change));
                }
            }
        }
        let mut members = BTreeMap::new();
        for (member, items) in by_member {
            let maximal: Vec<(EventId, &Change)> = items
                .iter()
                .copied()
                .filter(|&(event, _)| {
                    !items
                        .iter()
                        .any(|&(other, _)| self.events.precedes(event, other))
                })
                .collect();
            let mut removals: Vec<EventId> = maximal
                .iter()
                .filter(|(_, change)| change.op == Op::Remove)
                .map(|&(event, _)| event)
                .collect();
            if !removals.is_empty() {
                removals.sort_unstable_by_key(|&event| self.order_key(event));
                members.insert(
                    member,
                    Standing::Out {
                        removed_by: removals,
                    },
                );
                continue;
            }
            let states: Vec<MemberState> = maximal
                .iter()
                .filter_map(|&(event, change)| self.item_state(member, event, change, place))
                .collect();
            if let Some(state) = meet(&states) {
                members.insert(member, Standing::In(Box::new(state)));
            }
        }
        // roster.md, 3.15.5: the root of a checkpoint's world puts out the
        // invite keys its record shows claimed.
        if place.contains(&self.events.root()) {
            for member in self.events.root_out() {
                if matches!(members.get(&member), Some(Standing::Out { .. })) {
                    continue;
                }
                members.insert(
                    member,
                    Standing::Out {
                        removed_by: vec![self.events.root()],
                    },
                );
            }
        }
        // ext-invite-links.md: an invite key is out at any place that holds
        // a valid successor it signed.
        #[cfg(feature = "ext-invite-links")]
        crate::ext_invite_links::put_out_invites(self.events, place, &mut members);
        Roster { members }
    }

    /// The state one maximal change gives.
    fn item_state(
        &self,
        member: MemberRef,
        event: EventId,
        change: &Change,
        place: &BTreeSet<EventId>,
    ) -> Option<MemberState> {
        let source = self.order_key(event);
        if event == self.events.root()
            && let Some(state) = self.events.root_state(&member)
        {
            return Some(state);
        }
        match change.op {
            Op::Grant => Some(MemberState {
                level: change.level?,
                capabilities: change.capabilities.iter().flatten().cloned().collect(),
                label: change.label.clone(),
                history: change.history.unwrap_or(HistoryMode::FromNowOn),
                via: change.via.unwrap_or(Via::None),
                session: change.session,
                replaces: change.replaces,
                grants: BTreeSet::from([event]),
                seniority: Seniority {
                    epoch: self.events.epoch(),
                    height: source.0,
                    hash: seniority_hash(&self.events.space(), &member.id),
                    grant: event,
                },
                keys: change.keys.clone(),
                source,
                expires_at: change.expires_at,
                rank: change
                    .rank
                    .filter(|_| change.level == Some(Level::Administer)),
            }),
            Op::Change => {
                let prior = self.roster(&self.place_of(event, place));
                let prior = prior.state(&member)?;
                let level = change.level.unwrap_or(prior.level);
                // A change keeping administer keeps the rank; one raising
                // to it sets the change's; below administer, none.
                let rank = match (level, prior.level) {
                    (Level::Administer, Level::Administer) => prior.rank,
                    (Level::Administer, _) => change.rank,
                    _ => None,
                };
                Some(MemberState {
                    level,
                    rank,
                    capabilities: match &change.capabilities {
                        Some(capabilities) => capabilities.iter().cloned().collect(),
                        None => prior.capabilities.clone(),
                    },
                    label: change.label.clone().or_else(|| prior.label.clone()),
                    source,
                    ..prior.clone()
                })
            }
            // A removal is out; a policy change names no member.
            Op::Remove | Op::Policy => None,
            Op::Succeed => self.successor_state(member, event, change, place),
        }
    }

    /// The state a successor gives its claimant: ext-invite-links.md's,
    /// which a core implementation holds before any place reads it.
    #[cfg(not(feature = "ext-invite-links"))]
    fn successor_state(
        &self,
        _member: MemberRef,
        _event: EventId,
        _change: &Change,
        _place: &BTreeSet<EventId>,
    ) -> Option<MemberState> {
        None
    }

    /// The state a successor gives its claimant (ext-invite-links.md,
    /// "Invites in the roster").
    #[cfg(feature = "ext-invite-links")]
    fn successor_state(
        &self,
        member: MemberRef,
        event: EventId,
        change: &Change,
        place: &BTreeSet<EventId>,
    ) -> Option<MemberState> {
        crate::ext_invite_links::successor_state(self, member, event, change, place)
    }

    /// The space policy at a place: the genesis's (the root's) and the
    /// policy changes of the place, the maximal ones merged field by field
    /// to the stricter value.
    pub fn policy(&self, place: &BTreeSet<EventId>, genesis: &Policy) -> Policy {
        let space = self.events.root();
        let mut items: Vec<(EventId, &Policy)> = vec![(space, genesis)];
        for &event in place {
            for change in self.events.changes(event) {
                if let (Op::Policy, Some(policy)) = (change.op, &change.policy) {
                    items.push((event, policy));
                }
            }
        }
        let maximal = items.iter().filter(|&&(event, _)| {
            !items
                .iter()
                .any(|&(other, _)| self.events.precedes(event, other))
        });
        Policy::merge(maximal.map(|&(_, policy)| policy)).unwrap_or(*genesis)
    }
}

/// The devices an event grants `administer` or raises to it, and those at
/// `administer` it removes or demotes, in the order of its changes, at a
/// place whose roster is `roster` (roster.md, "The twin"; peers.md, "The
/// skeleton"). For the genesis, give its founder's grant: it grants its
/// author `administer`.
pub fn administer_changes(changes: &[Change], roster: &Roster) -> AdministerChanges {
    let mut out = AdministerChanges::default();
    for (effect, device) in changes.iter().filter_map(|c| administer_effect(c, roster)) {
        match effect {
            AdministerEffect::Grant(_) => out.grants.push(device),
            AdministerEffect::Lower => out.lowers.push(device),
        }
    }
    out
}

/// The rank each grant of [`administer_changes`] gives, in that order: the
/// rank the change sets (roster.md, 2.3 Changes, key 15), 255 where it
/// sets none (peers.md, "The twin", step 6, reads it).
pub fn administer_grant_ranks(changes: &[Change], roster: &Roster) -> Vec<u8> {
    changes
        .iter()
        .filter_map(|c| administer_effect(c, roster))
        .filter_map(|(effect, _)| match effect {
            AdministerEffect::Grant(rank) => Some(rank),
            AdministerEffect::Lower => None,
        })
        .collect()
}

/// What one change does to who administers.
enum AdministerEffect {
    /// It grants `administer`, or raises to it, at this rank.
    Grant(u8),
    /// It removes or lowers an administrator.
    Lower,
}

fn administer_effect(change: &Change, roster: &Roster) -> Option<(AdministerEffect, DeviceId)> {
    let member = change.member.filter(|m| m.kind == MemberType::Device)?;
    let was = roster.level(&member) == Some(Level::Administer);
    let to = change.level;
    let rank = change.rank.unwrap_or(MAX_RANK);
    let effect = match change.op {
        Op::Grant if to == Some(Level::Administer) => AdministerEffect::Grant(rank),
        Op::Change if to == Some(Level::Administer) && !was => AdministerEffect::Grant(rank),
        Op::Remove if was => AdministerEffect::Lower,
        Op::Change if was && to.is_some_and(|level| level < Level::Administer) => {
            AdministerEffect::Lower
        }
        _ => return None,
    };
    Some((effect, DeviceId(member.id)))
}

/// "The twin", step 1: visible key 15 is present exactly when the event
/// changes who administers at its place.
///
/// # Errors
///
/// `TwinRequired` when it is missing; `UnexpectedTwin` when it is present
/// on any other event.
pub fn check_twin_named(
    twin: Option<&[u8; 32]>,
    changes: &AdministerChanges,
) -> Result<(), SpaceClass> {
    match (changes.changes_administration(), twin) {
        (true, None) => Err(SpaceClass::TwinRequired),
        (false, Some(_)) => Err(SpaceClass::UnexpectedTwin),
        _ => Ok(()),
    }
}

/// Whether a roster event is **self-lowering** (roster.md, "Self-lowering
/// events"): each of its changes names its author's own device member and
/// removes it, or lowers only its level below `administer`.
pub fn self_lowering(author: &[u8; 32], changes: &[Change]) -> bool {
    let me = MemberRef::device(DeviceId(*author));
    !changes.is_empty()
        && changes.iter().all(|change| {
            change.member == Some(me)
                && match change.op {
                    Op::Remove => true,
                    Op::Change => {
                        change.level.is_some_and(|level| level < Level::Administer)
                            && change.capabilities.is_none()
                            && change.label.is_none()
                    }
                    _ => false,
                }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log of roster events by hand: each event's parents and changes.
    struct Hand {
        space: EventId,
        parents: BTreeMap<EventId, Vec<EventId>>,
        changes: BTreeMap<EventId, Vec<Change>>,
    }

    impl Hand {
        fn past(&self, event: EventId) -> BTreeSet<EventId> {
            let mut out = BTreeSet::new();
            let mut todo = self.parents[&event].clone();
            while let Some(p) = todo.pop() {
                if out.insert(p) {
                    todo.extend(self.parents[&p].iter().copied());
                }
            }
            out
        }
    }

    impl RosterEvents for Hand {
        fn space(&self) -> EventId {
            self.space
        }
        fn changes(&self, event: EventId) -> &[Change] {
            self.changes.get(&event).map_or(&[], Vec::as_slice)
        }
        fn height(&self, event: EventId) -> u64 {
            self.parents[&event]
                .iter()
                .map(|&p| self.height(p) + 1)
                .max()
                .unwrap_or(0)
        }
        fn precedes(&self, earlier: EventId, later: EventId) -> bool {
            self.past(later).contains(&earlier)
        }
        #[cfg(feature = "ext-invite-links")]
        fn author(&self, _event: EventId) -> [u8; 32] {
            [0; 32]
        }
    }

    fn id(n: u8) -> EventId {
        EventId([n; 32])
    }

    fn grant(
        who: u8,
        level: Level,
        history: HistoryMode,
        caps: &[(&str, CapabilityMode)],
    ) -> Change {
        let mut change = Change::grant(MemberRef::person([who; 32]), level, history, Via::Code);
        if !caps.is_empty() {
            change.capabilities = Some(
                caps.iter()
                    .map(|&(name, mode)| Capability {
                        name: name.into(),
                        mode,
                    })
                    .collect(),
            );
        }
        change
    }

    fn founder() -> Change {
        Change::grant(
            MemberRef::person([100; 32]),
            Level::Write,
            HistoryMode::WithHistory,
            Via::None,
        )
    }

    #[test]
    fn concurrent_grants_meet() {
        use CapabilityMode::{Extends, Narrows};
        let hand = Hand {
            space: id(0),
            parents: BTreeMap::from([(id(0), vec![]), (id(1), vec![id(0)]), (id(2), vec![id(0)])]),
            changes: BTreeMap::from([
                (id(0), vec![founder()]),
                (
                    id(1),
                    vec![grant(
                        7,
                        Level::Write,
                        HistoryMode::WithHistory,
                        &[("drive", Extends), ("a", Extends)],
                    )],
                ),
                (
                    id(2),
                    vec![grant(
                        7,
                        Level::Read,
                        HistoryMode::FromNowOn,
                        &[("a", Extends), ("suggest", Narrows)],
                    )],
                ),
            ]),
        };
        let places = Places::new(&hand);
        let roster = places.roster(&BTreeSet::from([id(0), id(1), id(2)]));
        let state = roster.state(&MemberRef::person([7; 32])).unwrap();
        assert_eq!(state.level, Level::Read);
        assert_eq!(state.history, HistoryMode::FromNowOn);
        assert_eq!(state.capabilities_of(Extends).collect::<Vec<_>>(), ["a"]);
        assert_eq!(
            state.capabilities_of(Narrows).collect::<Vec<_>>(),
            ["suggest"]
        );
        assert_eq!(state.grants, BTreeSet::from([id(1), id(2)]));
        assert_eq!(state.seniority.grant, id(1));
    }

    #[test]
    fn a_change_reads_the_state_at_its_place_and_a_removal_wins() {
        let member = MemberRef::person([7; 32]);
        let mut label = Change::new(Op::Change, Some(member));
        label.label = Some("operator".into());
        let hand = Hand {
            space: id(0),
            parents: BTreeMap::from([
                (id(0), vec![]),
                (id(1), vec![id(0)]),
                (id(2), vec![id(1)]),
                (id(3), vec![id(1)]),
            ]),
            changes: BTreeMap::from([
                (id(0), vec![founder()]),
                (
                    id(1),
                    vec![grant(7, Level::Write, HistoryMode::WithHistory, &[])],
                ),
                (id(2), vec![label]),
                (id(3), vec![Change::set_level(member, Level::Read)]),
            ]),
        };
        let places = Places::new(&hand);
        let both = places.roster(&BTreeSet::from([id(0), id(1), id(2), id(3)]));
        let state = both.state(&member).unwrap();
        assert_eq!(state.level, Level::Read);
        assert_eq!(state.label.as_deref(), Some("operator"));
        assert_eq!(state.grants, BTreeSet::from([id(1)]));

        let hand = Hand {
            changes: BTreeMap::from([
                (id(0), vec![founder()]),
                (
                    id(1),
                    vec![grant(7, Level::Write, HistoryMode::WithHistory, &[])],
                ),
                (id(2), vec![Change::remove(member)]),
                (id(3), vec![Change::set_level(member, Level::Read)]),
            ]),
            ..hand
        };
        let places = Places::new(&hand);
        let roster = places.roster(&BTreeSet::from([id(0), id(1), id(2), id(3)]));
        assert_eq!(
            roster.standing(&member),
            Some(&Standing::Out {
                removed_by: vec![id(2)]
            })
        );
        assert!(!roster.is_in(&MemberRef::person([8; 32])));
    }

    #[test]
    fn administration_and_self_lowering() {
        let me = [1; 32];
        let other = [2; 32];
        let mut roster = Roster::default();
        let state = |level| MemberState {
            level,
            capabilities: BTreeSet::new(),
            label: None,
            history: HistoryMode::WithHistory,
            via: Via::Code,
            session: None,
            replaces: None,
            grants: BTreeSet::new(),
            seniority: Seniority {
                epoch: 0,
                height: 0,
                hash: [0; 32],
                grant: id(0),
            },
            keys: None,
            source: (0, id(0)),
            expires_at: None,
            rank: (level == Level::Administer).then_some(MAX_RANK),
        };
        roster.members.insert(
            MemberRef::device(DeviceId(me)),
            Standing::In(Box::new(state(Level::Administer))),
        );
        roster.members.insert(
            MemberRef::device(DeviceId(other)),
            Standing::In(Box::new(state(Level::Write))),
        );
        let demote = [Change::set_level(
            MemberRef::device(DeviceId(me)),
            Level::Write,
        )];
        assert!(self_lowering(&me, &demote));
        let changes = administer_changes(&demote, &roster);
        assert_eq!(changes.lowers, vec![DeviceId(me)]);
        assert_eq!(
            check_twin_named(None, &changes),
            Err(SpaceClass::TwinRequired)
        );
        let raise = [Change::set_level(
            MemberRef::device(DeviceId(other)),
            Level::Administer,
        )];
        assert!(!self_lowering(&me, &raise));
        assert_eq!(
            administer_changes(&raise, &roster).grants,
            vec![DeviceId(other)]
        );
        let relabel = [Change::set_level(
            MemberRef::device(DeviceId(other)),
            Level::Read,
        )];
        let none = administer_changes(&relabel, &roster);
        assert!(!none.changes_administration());
        assert_eq!(
            check_twin_named(Some(&[0; 32]), &none),
            Err(SpaceClass::UnexpectedTwin)
        );
        assert_eq!(check_twin_named(None, &none), Ok(()));
    }
}
