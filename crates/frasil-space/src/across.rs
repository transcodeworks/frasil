//! The other logs a space's checks read (roster.md, "Checks across logs"):
//! the device lists of the persons it names, and the rosters of the spaces
//! it grants, each already resolved by its own rules.
//!
//! - A person's list is a [`HeldList`]: `frasil-identity`'s device list,
//!   whole or from its kept checkpoint on, and its merged list (identity.md,
//!   "The merge", "List checkpoints"; see [`crate::across_logs`]).
//! - A granted space is anything that implements [`GrantedSpace`]: a
//!   resolved [`Space`](crate::Space) does.
//!
//! Within the roster, a device member's 32-byte ID is its device ID; the
//! lookups by hash and the list's own records take a [`DeviceId`].
//!
//! [`OtherLogs`] holds both, by ID. It answers what the space asks of them:
//! whether a ref names an event this replica holds, whether a ref covers an
//! end, whether a record names a device, and keys by their hash from every
//! `add` and grant they hold (roster.md, "An author's keys").

use crate::across_logs::ListHolding;
use crate::graph::{Reach, Verdicts};
use crate::member::Level;
use crate::screen::Records;
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, KeyRing, KeySource, KeysCommitment};
use frasil_events::{EventId, Ref};
use frasil_identity::{DeviceList, Kind, MergedList};
use std::collections::{BTreeMap, BTreeSet};

/// A person's device list as this replica holds it, merged.
#[derive(Debug, Clone)]
pub struct HeldList {
    pub(crate) list: ListHolding,
    merged: MergedList,
    /// ext-recovery-agent.md: the waiting list members this replica
    /// vouches for in the space that holds this list.
    #[cfg(feature = "ext-recovery-agent")]
    pub(crate) vouched: BTreeSet<[u8; 32]>,
}

impl HeldList {
    /// Reads a whole list's signed events in causal order, and merges it.
    ///
    /// # Errors
    ///
    /// `Malformed` for an empty list; otherwise the list reader's class.
    pub fn from_signed_events(events: &[Vec<u8>]) -> Result<Self, frasil_identity::Refusal> {
        let first = events.first().ok_or(frasil_identity::IdentityClass::from(
            frasil_base::ErrorClass::Malformed,
        ))?;
        let mut list = DeviceList::new(first)?;
        for event in &events[1..] {
            list.insert(event)?;
        }
        Ok(Self::new(list))
    }

    /// A list as held, merged (identity.md, "The merge").
    pub fn new(list: DeviceList) -> Self {
        Self::holding(ListHolding::Whole(list))
    }

    pub(crate) fn holding(list: ListHolding) -> Self {
        let merged = list.merge();
        Self {
            list,
            merged,
            #[cfg(feature = "ext-recovery-agent")]
            vouched: BTreeSet::new(),
        }
    }

    pub(crate) fn checkpoint_places(&self, placed: &[EventId], adds: &[EventId]) -> bool {
        placed.iter().any(|id| {
            let body = match &self.list {
                ListHolding::Whole(list) => list.body(*id),
                ListHolding::Kept(list) => list.body(*id),
            };
            body.and_then(|body| body.list_record())
                .is_some_and(|record| record.members.iter().any(|entry| adds.contains(&entry.add)))
        })
    }

    /// The person ID.
    pub fn person(&self) -> [u8; 32] {
        self.list.person_id()
    }

    /// The list's events, when the replica holds the whole list; see
    /// [`HeldList::kept_list`] for one it holds from a list checkpoint on.
    pub fn list(&self) -> Option<&DeviceList> {
        match &self.list {
            ListHolding::Whole(list) => Some(list),
            ListHolding::Kept(_) => None,
        }
    }

    /// The merged list.
    pub fn merged(&self) -> &MergedList {
        &self.merged
    }

    /// Whether this replica holds an event of the list, or dropped it when
    /// it forgot the list's earlier events.
    pub fn holds(&self, event: EventId) -> bool {
        self.list.holds(event)
    }

    /// Whether `earlier` is in the past of `later`, in the list.
    pub fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.list.precedes(earlier, later)
    }

    /// The devices that write through a grant of the person: each device or
    /// passkey member a valid `add` names, revoked or not, until a writer
    /// of the space responds to its end. These are candidates: the write
    /// rule also requires the add at the event's place (roster.md, "A list
    /// at an event's place"). With a list checkpoint in effect, the members of its world:
    /// a device the checkpoint does not list writes through the person no
    /// longer ([`crate::across_logs`]).
    pub fn writers(&self) -> BTreeSet<[u8; 32]> {
        self.merged.writers().into_keys().map(|d| d.0).collect()
    }

    /// Whether this replica wraps for a list member in a space under its
    /// merged `policy` (identity.md, "What a list vouches for"): where the
    /// policy forbids agents, nothing while the merged list holds an active
    /// agent; otherwise as [`Self::receives`].
    pub fn receives_under(&self, device: &[u8; 32], policy: &crate::Policy) -> bool {
        !(policy.forbid_agents && self.merged.holds_active_agent()) && self.receives(device)
    }

    /// Every recovery key a valid `add` of the list names, revoked or not:
    /// beside [`Self::writers`], the list members a delivery wrapped for
    /// (keys.md, "Healing").
    pub fn recovery_keys(&self) -> BTreeSet<[u8; 32]> {
        self.merged
            .members()
            .values()
            .filter(|member| member.kind == Kind::RecoveryKey)
            .map(|member| member.device.0)
            .collect()
    }

    /// The events of the list that end a device's path through the person
    /// (roster.md, "Ends").
    pub fn ends(&self, device: &[u8; 32]) -> Vec<EventId> {
        self.merged.ends(&DeviceId(*device))
    }

    /// Whether a device is rooted in a recovery agent and not confirmed
    /// (the write rule, step 3).
    pub fn waiting(&self, device: &[u8; 32]) -> bool {
        self.merged.is_waiting(&DeviceId(*device))
    }

    /// The devices the list vouches for to a space that grants the person,
    /// for effective membership: its active devices and passkey members.
    pub fn members(&self) -> BTreeSet<[u8; 32]> {
        self.merged
            .active_members()
            .filter(|member| matches!(member.kind, Kind::Device | Kind::PasskeyMember))
            .map(|member| member.device.0)
            .collect()
    }

    /// The list members the key graph counts as the person's devices
    /// (identity.md, "What a list vouches for"): each active list member
    /// that is a device, a passkey member or a recovery key, waiting or
    /// not. Whether one receives wraps is [`Self::receives`]; a recovery
    /// key never writes.
    pub fn key_devices(&self) -> BTreeSet<[u8; 32]> {
        self.merged
            .active_members()
            .filter(|member| {
                matches!(
                    member.kind,
                    Kind::Device | Kind::PasskeyMember | Kind::RecoveryKey
                )
            })
            .map(|member| member.device.0)
            .collect()
    }

    /// Whether a list member is a recovery key.
    pub fn is_recovery_key(&self, identity: &[u8; 32]) -> bool {
        self.merged
            .member(&DeviceId(*identity))
            .is_some_and(|member| member.kind == Kind::RecoveryKey)
    }

    /// Whether this replica wraps for a list member, in the space that
    /// holds this list (identity.md, "What a list vouches for"): it is not
    /// waiting, or, under ext-recovery-agent.md, this replica vouches for
    /// it.
    pub fn receives(&self, device: &[u8; 32]) -> bool {
        #[cfg(feature = "ext-recovery-agent")]
        if self.vouched.contains(device) {
            return true;
        }
        !self.waiting(device)
    }

    /// The keys every `add` of the list carries, valid or not, indexed by
    /// their hashes.
    pub fn keys(&self) -> &KeyRing {
        self.list.keys()
    }

    /// Whether an `add` of the list names a device, valid or not; with a
    /// list checkpoint in effect, as a holder that forgot reads the list
    /// ([`crate::across_logs`]).
    pub fn names(&self, device: &DeviceId) -> bool {
        self.list.names(device, &self.merged)
    }
}

/// Which paths a device's capabilities are merged over (units.md, 3.17
/// "Capability checks"): the paths of a unit's author, or of an ephemeral
/// frame's sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathsFor {
    /// The paths by which the write rule admits a unit (roster.md, "Checks
    /// across logs", "Paths"): a device grant, a person whose list holds a
    /// valid add of the device, revoked or not, and a granted space whose
    /// propagating writers it is among, at that space's merged roster or,
    /// once it is no longer there, at any earlier valid place.
    Unit,
    /// The paths of the current view (ext-ephemeral.md, 3.6 "Membership
    /// against the current view"): a device grant, a person whose merged
    /// list vouches for the device now, and a granted space that the
    /// device reaches and propagates in at that space's merged roster.
    Current,
}

/// What a replica holds of an event of a granted space that a notice names
/// (keys.md, "Notices and space principals"): whether it is valid there,
/// and, for a rotation, its visible key 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GranteeRotation {
    /// The event is valid in the granted space's log as this replica holds
    /// it.
    pub valid: bool,
    /// Its `grant_commitment` (visible key 3), when it rotates.
    pub grant_commitment: Option<[u8; 32]>,
}

/// What a space reads of a space it grants, resolved by roster.md over the
/// events this replica holds of it.
pub trait GrantedSpace {
    /// The space ID.
    fn space_id(&self) -> EventId;

    /// Whether this replica holds an event of its log.
    fn holds(&self, event: EventId) -> bool;

    /// Whether `earlier` is in the past of `later`, in its log.
    fn precedes(&self, earlier: EventId, later: EventId) -> bool;

    /// Whether it is a restricted space (ext-restricted-spaces.md): an edge
    /// to it never counts (roster.md, "Grants of spaces and effective
    /// membership").
    fn is_restricted(&self) -> bool {
        false
    }

    /// Its descriptor's kind (roster.md, "The space descriptor"): an edge
    /// to a restricted space, or to one whose descriptor a later document
    /// defines, never counts. By default, restricted or ordinary as
    /// [`is_restricted`](Self::is_restricted) says.
    fn descriptor_kind(&self) -> crate::DescriptorKind {
        if self.is_restricted() {
            crate::DescriptorKind::Restricted
        } else {
            crate::DescriptorKind::Space
        }
    }

    /// The other logs its own checks read.
    fn other_logs(&self) -> &OtherLogs<'_>;

    /// The keys its grants carry, valid or void, indexed by their hashes.
    fn keys(&self) -> &KeyRing;

    /// The keys the record of the checkpoint it is resolved from holds,
    /// when this replica reads it as a checkpoint's world (roster.md,
    /// 3.15.5): the keys of members granted before the checkpoint, which no
    /// grant of the world carries. `None` otherwise.
    fn world_keys(&self) -> Option<&KeyRing> {
        None
    }

    /// Whether a grant of its log names a device, valid or void.
    fn names(&self, device: &DeviceId) -> bool;

    /// Its effective membership over its merged roster: each device that
    /// reaches it, with its highest level over every path and its highest
    /// over the paths that propagate there, `None` when none does
    /// (roster.md, "Grants of spaces and effective membership"). Only the
    /// second passes on to a space that grants it. `depth` counts the
    /// spaces already passed, and `seen` names them.
    fn effective(
        &self,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)>;

    /// Its effective membership as [`Self::effective`], counting only the
    /// grant edges `verdicts` keeps: the verdicts of the grant graph over
    /// every roster the asking replica holds (roster.md, "Grants of spaces
    /// and effective membership").
    fn effective_counted(
        &self,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        let _ = verdicts;
        self.effective(depth, seen)
    }

    /// How a device reaches it over the paths `paths` names, its
    /// capabilities merged as roster.md's "Grants of spaces and effective
    /// membership" merges them; `None` when no such path holds. A space
    /// that grants this one passes on a path through it only where the
    /// result propagates.
    fn reach(&self, device: &[u8; 32], paths: PathsFor) -> Option<Reach>;

    /// Its grants of spaces in force in its merged roster, each as the
    /// grant's event ID and the granted space's ID: its edges of the grant
    /// graph.
    fn space_grants(&self) -> Vec<(EventId, EventId)> {
        Vec::new()
    }

    /// What this replica holds of one of its events; `None` when it does
    /// not hold it.
    fn rotation(&self, id: EventId) -> Option<GranteeRotation> {
        let _ = id;
        None
    }

    /// Whether a device is a propagating member of it at the place of one
    /// of its rotations, that rotation included; `None` while this replica
    /// cannot tell.
    fn propagates_at(&self, device: &[u8; 32], rotation: EventId) -> Option<bool> {
        let _ = (device, rotation);
        None
    }

    /// The devices that hold one of its rotations' grant seed: those that
    /// propagate at the rotation's place.
    fn grant_holders(&self, rotation: EventId) -> BTreeSet<[u8; 32]> {
        let _ = rotation;
        BTreeSet::new()
    }

    /// The devices that propagate in it now, at its merged roster.
    fn propagating(&self) -> BTreeSet<[u8; 32]> {
        self.effective(0, &[])
            .into_iter()
            .filter(|(_, (_, propagating))| propagating.is_some())
            .map(|(device, _)| device)
            .collect()
    }

    /// The devices that reach it at `write` and propagate, at its merged
    /// roster or at the place of any valid roster event of it.
    fn propagating_writers(&self) -> BTreeSet<[u8; 32]>;

    /// The devices among [`Self::propagating_writers`] that reach it, at
    /// the same places, through some path that is not waiting (roster.md,
    /// 3.10 The write rule, step 3): a device grant, a person whose list
    /// does not hold the device as rooted in a recovery agent and not
    /// confirmed, or a space among whose own such devices it is. A path
    /// through this space is waiting for every other propagating writer.
    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]>;

    /// The events that end a device's path into it: its own events after
    /// which the device no longer propagates there at `write`, and the ends
    /// of the paths it had through the persons and spaces it names, each
    /// with its log.
    fn ends(&self, device: &[u8; 32]) -> Vec<Ref>;
}

/// The other logs a space reads, each resolved as this replica holds it:
/// lists by person ID, granted spaces by space ID; and the keys the
/// replica found in any other source.
#[derive(Default)]
pub struct OtherLogs<'a> {
    /// Persons' lists, by person ID.
    pub lists: BTreeMap<[u8; 32], HeldList>,
    /// Granted spaces, by space ID.
    pub spaces: BTreeMap<EventId, &'a dyn GrantedSpace>,
    /// Keys from any other source, by their hash: records of logs the space
    /// does not read, valid or void, admission exchanges, a cache (crypto.md,
    /// "Keys by their hash"). They name no device; a verifier uses them only
    /// when they hash to the commitment or device ID it asks for.
    pub keys: Option<&'a KeyRing>,
}

impl core::fmt::Debug for OtherLogs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OtherLogs")
            .field("lists", &self.lists.keys().collect::<Vec<_>>())
            .field("spaces", &self.spaces.keys().collect::<Vec<_>>())
            .field("keys", &self.keys)
            .finish()
    }
}

/// A log among the other logs.
#[derive(Clone, Copy)]
enum Found<'s> {
    List(&'s HeldList),
    Space(&'s dyn GrantedSpace),
}

impl Found<'_> {
    fn holds(&self, event: EventId) -> bool {
        match self {
            Self::List(list) => list.holds(event),
            Self::Space(space) => space.holds(event),
        }
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        match self {
            Self::List(list) => list.precedes(earlier, later),
            Self::Space(space) => space.precedes(earlier, later),
        }
    }
}

impl<'a> OtherLogs<'a> {
    /// No other log.
    pub fn none() -> Self {
        Self::default()
    }

    /// Adds a person's list.
    pub fn with_list(mut self, list: HeldList) -> Self {
        self.lists.insert(list.person(), list);
        self
    }

    /// Adds a granted space.
    pub fn with_space(mut self, space: &'a dyn GrantedSpace) -> Self {
        self.spaces.insert(space.space_id(), space);
        self
    }

    /// Adds keys from any other source (crypto.md, "Keys by their hash").
    pub fn with_keys(mut self, keys: &'a KeyRing) -> Self {
        self.keys = Some(keys);
        self
    }

    /// A person's list, if held.
    pub fn list(&self, person: &[u8; 32]) -> Option<&HeldList> {
        self.lists.get(person)
    }

    /// A granted space, if held.
    pub fn space(&self, space: &EventId) -> Option<&'a dyn GrantedSpace> {
        self.spaces.get(space).copied()
    }

    /// The log `id` among these logs and theirs in turn, as this replica
    /// holds it.
    fn find(&self, id: EventId) -> Option<Found<'_>> {
        let mut seen = BTreeSet::new();
        self.find_within(id, &mut seen)
    }

    fn find_within(&self, id: EventId, seen: &mut BTreeSet<EventId>) -> Option<Found<'_>> {
        if let Some(list) = self.lists.get(&id.0) {
            return Some(Found::List(list));
        }
        if let Some(&space) = self.spaces.get(&id) {
            return Some(Found::Space(space));
        }
        for (&sid, &space) in &self.spaces {
            if !seen.insert(sid) {
                continue;
            }
            if let Some(found) = space.other_logs().find_within(id, seen) {
                return Some(found);
            }
        }
        None
    }

    /// Whether this replica holds the event a ref names (the write rule,
    /// step 0).
    pub fn resolves(&self, reference: &Ref) -> bool {
        self.find(reference.log)
            .is_some_and(|log| log.holds(reference.id))
    }

    /// Whether a ref names `end` of log `log`, or a held event of that log
    /// that has `end` in its past: its author knew of the end (roster.md,
    /// "Responses").
    pub fn covers(&self, reference: &Ref, log: EventId, end: EventId) -> bool {
        if reference.log != log {
            return false;
        }
        if reference.id == end {
            return true;
        }
        self.find(log)
            .is_some_and(|found| found.holds(reference.id) && found.precedes(end, reference.id))
    }
}

/// Keys by their hash from the lists, by person ID, then the granted spaces,
/// by space ID, each with the keys of the checkpoint record it is resolved
/// from, then any other source (roster.md, "An author's keys").
impl KeySource for OtherLogs<'_> {
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys> {
        let lists = self.lists.values().map(HeldList::keys);
        let spaces = self
            .spaces
            .values()
            .flat_map(|space| std::iter::once(space.keys()).chain(space.world_keys()));
        lists
            .chain(spaces)
            .chain(self.keys)
            .find_map(|ring| ring.get(kc).cloned())
    }

    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys> {
        let lists = self.lists.values().map(HeldList::keys);
        let spaces = self
            .spaces
            .values()
            .flat_map(|space| std::iter::once(space.keys()).chain(space.world_keys()));
        lists
            .chain(spaces)
            .chain(self.keys)
            .find_map(|ring| ring.device_keys(id))
    }
}

/// Whether a list's `add` or a granted space's grant names a device.
impl Records for OtherLogs<'_> {
    fn names(&self, device: &DeviceId) -> bool {
        self.lists.values().any(|list| list.names(device))
            || self.spaces.values().any(|space| space.names(device))
    }
}

/// How a replica finds the capabilities of a unit's author at the unit's
/// place (units.md, 3.17 "Capability checks"): through its strongest path,
/// or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorReach {
    /// The author reaches the space by a path at the place, with the
    /// capabilities of its strongest path.
    Reached(Reach),
    /// No path is found, and one through a person or a space whose log this
    /// replica does not hold cannot be judged: the unit's content waits
    /// (`Pending`), and is judged again when the log arrives.
    Unjudged,
    /// No path is found though every log a path needs is held: the unit's
    /// content is refused (`CapabilityRefused`), without the adapter's
    /// checks. The write rule admits no such unit, so this is a mismatch
    /// between the two path computations, which fails closed.
    Unreached,
}

impl AuthorReach {
    /// The outcome of a reach found or not, where `unjudged` says whether
    /// a path could not be judged for lack of a log.
    pub fn of(reach: Option<Reach>, unjudged: bool) -> Self {
        match reach {
            Some(reach) => Self::Reached(reach),
            None if unjudged => Self::Unjudged,
            None => Self::Unreached,
        }
    }

    /// How `author` reaches `space` at `place`, over the write rule's paths
    /// (roster.md, "Checks across logs", "Paths"): its strongest path, or,
    /// when [`Space::reach_at`](crate::Space::reach_at) finds none, whether
    /// a path cannot be judged, as the write rule's step 2 asks it
    /// ([`Space::paths`](crate::Space::paths)).
    pub fn at(space: &crate::Space<'_>, author: &[u8; 32], place: &BTreeSet<EventId>) -> Self {
        let roster = space.roster_at(place);
        let reach = space.reach_at(author, &roster, PathsFor::Unit);
        if reach.is_some() {
            return Self::of(reach, false);
        }
        let (_, unjudged) = space.paths(author, &roster, Level::Write);
        Self::of(None, unjudged)
    }
}
