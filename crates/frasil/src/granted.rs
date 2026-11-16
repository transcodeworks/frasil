//! A granted space as another space reads it (roster.md, "Checks across
//! logs", "Grants of spaces and effective membership").
//!
//! A space that grants another reads that space's roster, resolved by its
//! own rules over the events this device holds of it. [`GrantedFacts`]
//! keeps what the granting space's checks ask of it, taken from the
//! granted space's last resolution: its view and causal order, its
//! effective membership and propagating writers (and those that reach it
//! through a path that is not waiting), how each of those devices
//! reaches it with its capabilities, the ends of each device's
//! path, its rotations with their grant commitments and grant holders, the
//! devices its grants name, valid or void, and the keys they carry. It reads the granted space's own
//! lists, and the spaces it grants in turn only as far as its own
//! resolution did.

use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, KeyRing};
use frasil_events::{EventId, Log, Ref};
use frasil_space::graph::{Reach, Verdicts};
use frasil_space::{GrantedSpace, GranteeRotation, Level, OtherLogs, PathsFor, Space};
use std::collections::{BTreeMap, BTreeSet};

/// The devices a grant of an opened space event names, valid or void
/// (roster.md, "Strangers' events").
fn named_devices(space: &Space<'_>) -> BTreeSet<DeviceId> {
    let screened = space.screened();
    let mut candidates = BTreeSet::new();
    for &id in screened.events() {
        if let Some(opened) = screened.opened(id) {
            candidates.extend(
                opened
                    .changes()
                    .iter()
                    .filter_map(|change| change.member)
                    .map(|member| DeviceId(member.id)),
            );
        }
    }
    candidates.retain(|device| screened.names(device));
    candidates
}

/// What a space reads of a space it grants.
pub(crate) struct GrantedFacts {
    space: EventId,
    log: Log,
    view: BTreeSet<EventId>,
    /// The devices a grant of its log names, valid or void.
    named: BTreeSet<DeviceId>,
    /// The keys those grants carry, by their hashes.
    keys: KeyRing,
    /// Its effective membership: each device's highest level over every
    /// path, and its highest over the paths that propagate.
    effective: BTreeMap<[u8; 32], (Level, Option<Level>)>,
    /// How each device reaches it, with its capabilities, over each kind
    /// of paths.
    reach: BTreeMap<(PathsFor, [u8; 32]), Reach>,
    grants: Vec<(EventId, EventId)>,
    rotations: BTreeMap<EventId, GranteeRotation>,
    holders: BTreeMap<EventId, BTreeSet<[u8; 32]>>,
    propagating: BTreeMap<EventId, BTreeSet<[u8; 32]>>,
    writers: BTreeSet<[u8; 32]>,
    /// Those of `writers` that reach it through some path that is not
    /// waiting (roster.md, 3.10 The write rule, step 3).
    unwaiting: BTreeSet<[u8; 32]>,
    ends: BTreeMap<[u8; 32], Vec<Ref>>,
    restricted: bool,
    /// Its descriptor's kind: an edge to a space whose descriptor a later
    /// document defines never counts (roster.md, 3.3).
    kind: frasil_space::DescriptorKind,
    /// Distinct for each set of facts this device made, and moved on when
    /// the view grows: what a replica compares to tell whether what it
    /// read of this space changed.
    generation: u64,
}

/// The next [`GrantedFacts`] generation.
fn next_generation() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl core::fmt::Debug for GrantedFacts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrantedFacts")
            .field("space", &self.space)
            .field("effective", &self.effective.len())
            .finish_non_exhaustive()
    }
}

impl GrantedFacts {
    /// The facts of a resolved space.
    pub fn of(space: &Space<'_>, log: &Log) -> Self {
        let effective = GrantedSpace::effective(space, 0, &[]);
        let writers = space.propagating_writers();
        let unwaiting = space.unwaiting_writers();
        let mut devices: BTreeSet<[u8; 32]> = effective.keys().copied().collect();
        devices.extend(writers.iter().copied());
        for (member, _) in space.roster().iter() {
            if member.kind == frasil_space::MemberType::Device {
                devices.insert(member.id);
            }
        }
        let mut reach = BTreeMap::new();
        for (paths, among) in [
            (PathsFor::Current, effective.keys().collect::<Vec<_>>()),
            (PathsFor::Unit, writers.iter().collect()),
        ] {
            for &device in among {
                if let Some(found) = GrantedSpace::reach(space, &device, paths) {
                    reach.insert((paths, device), found);
                }
            }
        }
        let mut rotations = BTreeMap::new();
        let mut holders = BTreeMap::new();
        let mut propagating = BTreeMap::new();
        // A rotation is a space event.
        for &id in space.screened().events() {
            if let Some(rotation) = space.rotation(id)
                && rotation.grant_commitment.is_some()
            {
                rotations.insert(id, rotation);
                if rotation.valid {
                    holders.insert(id, GrantedSpace::grant_holders(space, id));
                    propagating.insert(id, space.holders_of(id, false));
                }
            }
        }
        Self {
            space: log.id(),
            log: log.clone(),
            view: space.view().clone(),
            named: named_devices(space),
            keys: space.screened().keys().clone(),
            ends: devices.iter().map(|d| (*d, space.ends(d))).collect_map(),
            effective,
            reach,
            grants: space.space_grants(),
            rotations,
            holders,
            propagating,
            writers,
            unwaiting,
            restricted: space.is_restricted(),
            kind: space.screened().genesis().descriptor.kind,
            generation: next_generation(),
        }
    }

    /// The facts once content units were placed and judged in the view,
    /// which changes which events the space holds and nothing else these
    /// facts read.
    pub fn add_events(&mut self, log: &Log, added: &[EventId]) {
        for id in added {
            if let Some(event) = log.event(*id) {
                let _ = self.log.place(event.clone());
                self.view.insert(*id);
            }
        }
        self.generation = next_generation();
    }

    /// Whether two sets of facts hold the same events of the space, in
    /// the same order: what [`reads_as`](Self::reads_as) leaves out.
    #[cfg(debug_assertions)]
    pub fn holds_same(&self, other: &Self) -> bool {
        self.view == other.view && self.log.canonical() == other.log.canonical()
    }
}

/// A granted space's facts with the other logs its own checks read: the
/// persons' lists the device holds.
pub(crate) struct GrantedView<'a> {
    facts: &'a GrantedFacts,
    others: OtherLogs<'a>,
}

impl<'a> GrantedView<'a> {
    /// The facts' generation.
    pub fn generation(&self) -> u64 {
        self.facts.generation
    }

    /// A view of the facts over these lists.
    pub fn new(
        facts: &'a GrantedFacts,
        lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
    ) -> Self {
        let mut others = OtherLogs::none();
        for list in lists.values() {
            others = others.with_list(list.held());
        }
        Self { facts, others }
    }
}

impl GrantedSpace for GrantedView<'_> {
    fn space_id(&self) -> EventId {
        self.facts.space
    }

    fn holds(&self, event: EventId) -> bool {
        self.facts.holds(event)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.facts.precedes(earlier, later)
    }

    fn is_restricted(&self) -> bool {
        self.facts.restricted
    }

    fn descriptor_kind(&self) -> frasil_space::DescriptorKind {
        self.facts.kind
    }

    fn other_logs(&self) -> &OtherLogs<'_> {
        &self.others
    }

    fn keys(&self) -> &KeyRing {
        &self.facts.keys
    }

    fn names(&self, device: &DeviceId) -> bool {
        self.facts.named.contains(device)
    }

    fn effective(
        &self,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.facts.effective(depth, seen)
    }

    fn effective_counted(
        &self,
        depth: usize,
        seen: &[EventId],
        verdicts: &Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.facts.effective_counted(depth, seen, verdicts)
    }

    fn reach(&self, device: &[u8; 32], paths: PathsFor) -> Option<Reach> {
        self.facts.reach(device, paths)
    }

    fn space_grants(&self) -> Vec<(EventId, EventId)> {
        self.facts.grants.clone()
    }

    fn rotation(&self, id: EventId) -> Option<GranteeRotation> {
        self.facts.rotation(id)
    }

    fn propagates_at(&self, device: &[u8; 32], rotation: EventId) -> Option<bool> {
        self.facts.propagates_at(device, rotation)
    }

    fn grant_holders(&self, rotation: EventId) -> BTreeSet<[u8; 32]> {
        self.facts.grant_holders(rotation)
    }

    fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
        self.facts.writers.clone()
    }

    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
        self.facts.unwaiting.clone()
    }

    fn ends(&self, device: &[u8; 32]) -> Vec<Ref> {
        self.facts.ends(device)
    }
}

impl GrantedFacts {
    /// Whether another space reads the same of this one in both, leaving
    /// out which events each holds and how they are ordered: what a settle
    /// compares to tell whether the other spaces must be judged again.
    pub(crate) fn reads_as(&self, other: &Self) -> bool {
        self.space == other.space
            && self.named == other.named
            && self.keys == other.keys
            && self.effective == other.effective
            && self.reach == other.reach
            && self.grants == other.grants
            && self.rotations == other.rotations
            && self.holders == other.holders
            && self.propagating == other.propagating
            && self.writers == other.writers
            && self.unwaiting == other.unwaiting
            && self.ends == other.ends
            && self.restricted == other.restricted
            && self.kind == other.kind
    }

    /// How a device reaches the space over the paths `paths` names, with
    /// its capabilities.
    pub(crate) fn reach(&self, device: &[u8; 32], paths: PathsFor) -> Option<Reach> {
        self.reach.get(&(paths, *device)).cloned()
    }

    fn holds(&self, event: EventId) -> bool {
        self.view.contains(&event)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.log.precedes(earlier, later)
    }

    fn effective(
        &self,
        _depth: usize,
        _seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.effective.clone()
    }

    fn effective_counted(
        &self,
        _depth: usize,
        _seen: &[EventId],
        _verdicts: &Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.effective.clone()
    }

    fn rotation(&self, id: EventId) -> Option<GranteeRotation> {
        if !self.view.contains(&id) {
            return None;
        }
        Some(self.rotations.get(&id).copied().unwrap_or(GranteeRotation {
            valid: false,
            grant_commitment: None,
        }))
    }

    fn propagates_at(&self, device: &[u8; 32], rotation: EventId) -> Option<bool> {
        self.propagating
            .get(&rotation)
            .map(|holders| holders.contains(device))
    }

    pub(crate) fn grant_holders(&self, rotation: EventId) -> BTreeSet<[u8; 32]> {
        self.holders.get(&rotation).cloned().unwrap_or_default()
    }

    fn ends(&self, device: &[u8; 32]) -> Vec<Ref> {
        self.ends.get(device).cloned().unwrap_or_default()
    }
}
