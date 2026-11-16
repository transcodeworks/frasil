//! The administrator skeleton at a peer (peers.md, "The skeleton", "What a
//! peer checks before it stores a skeleton event", "The skeleton's
//! resolution" and "Stability at the peer").
//!
//! A [`Skeleton`] reads the storage events of one log in a view: it runs the
//! peer's checks in canonical order, so that the event that makes an
//! administrator slot, and an author's enrolment, come before the events
//! that rely on them; it resolves the applied changes, disowns and
//! enrolments with roster.md's procedure (`frasil-resolve`), read as
//! peers.md says; it judges each request valid at the peer or not; and it
//! answers whether an event is stable at the peer.
//!
//! It reads no sealed part. Replicas run it over the same storage events
//! and compare (peers.md, "What replicas check"; [`crate::twins`]).
//!
//! A skeleton reads either the whole log from its root, or the **world** of
//! a skeleton cut in effect (peers.md, "Skeleton cuts"): the cut and the
//! events that follow its checkpoint, each linked to its parents among them
//! only, heights counted from the cut. The cut stands as the root there,
//! its slots in from the start, each enrolled to the pseudonym its entry
//! carries. [`crate::cut`] decides which cut is in effect and builds that
//! world; with no cut, a skeleton is exactly the one of the whole log.

use crate::PeersClass;
pub use crate::body::SlotId;
use crate::body::{
    ChangeEffect, Cut, CutSeniority, SlotEntry, StorageBody, StorageType, check_size,
};
use crate::derive::{
    Seniority, enrol_statement, root_statement, seniority_in, verify_hybrid, verify_slot,
};
use crate::limits::{MAX_PLANTED, MAX_RANK, MAX_SKELETON_PLACE};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_base::collect::CollectMap;
use frasil_base::time::{Reading, lower};
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys};
use frasil_crypto::primitives::sha256;
use frasil_events::{Event, EventId, Evidence, EvidenceKind, ForkPoints, Log, kind};
use frasil_keys::body::visible_key;
use frasil_resolve::{Resolve, Verdict, View, resolve};
use std::collections::{BTreeMap, BTreeSet};

/// The classes of the peer's checks an event fails by itself (peers.md,
/// "What a peer checks before it stores a skeleton event"), as opposed to
/// its verdict in the peer's own resolution, which replicas do not read. An
/// event with one of them has no signature the peer verified, so it is no
/// fork evidence, and no twin. The peer refuses those of
/// [`refused_by_peer`] and stores the others with no effect.
pub fn refused_at_store(class: PeersClass) -> bool {
    use ErrorClass as E;
    matches!(
        class,
        PeersClass::Shared(
            E::Malformed
                | E::UnsupportedVersion
                | E::InvalidKey
                | E::TooLarge
                | E::BadSignature
                | E::NotCommitted
        ) | PeersClass::NotAuthorized
            | PeersClass::UnknownAdministratorSlot
            | PeersClass::DuplicateRoot
            | PeersClass::PlantedSlotsFull
    )
}

/// Whether a peer refuses a skeleton event whose status has this class
/// (peers.md, "What a peer checks before it stores a skeleton event", "No
/// refusal for standing"): only for what is wrong in it, its body, its
/// signature under a key the peer holds, a slot reference that names
/// nothing, or the planted-slot limit. An event whose author the peer holds
/// no root or enrolment for is stored with no effect (`NotAuthorized`, which
/// [`refused_at_store`] still counts as unverified), and a root after the
/// first is stored and ignored (`DuplicateRoot`).
pub fn refused_by_peer(class: PeersClass) -> bool {
    refused_at_store(class)
        && !matches!(class, PeersClass::NotAuthorized | PeersClass::DuplicateRoot)
}

/// A storage event's status at the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Valid: the root, a valid contested event, or a request valid at the
    /// peer.
    Valid,
    /// Refused or void, with its class and, for an attack or a concurrent
    /// lowering, the event that voids it.
    Void {
        /// The class.
        class: PeersClass,
        /// The attacker or concurrent lowering.
        by: Option<EventId>,
    },
}

impl Status {
    /// Whether the status is valid.
    pub fn is_valid(self) -> bool {
        self == Self::Valid
    }

    fn void(class: PeersClass) -> Self {
        Self::Void { class, by: None }
    }
}

/// An administrator slot the peer holds: the event that made it and, for a
/// change's grant, the grant map's keys; and its rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// The root or applied change that made it.
    pub maker: EventId,
    /// The administrator slot's Ed25519 key; none for the root's.
    pub slot_ed: Option<[u8; 32]>,
    /// The SHA-256 of its ML-DSA-65 key; none for the root's.
    pub slot_mldsa_hash: Option<[u8; 32]>,
    /// Its rank: 255 for the root's, its grant map's for a change's, its
    /// entry's for a slot of a cut. A slot's rank never changes.
    pub rank: u8,
}

/// An administrator slot's state at a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotState {
    /// Whether it is in: made, and not lowered by a lower or a disown.
    pub is_in: bool,
    /// The pseudonym, by its device ID, a valid enrolment binds to it.
    pub enrolled: Option<DeviceId>,
}

/// Readings of the peer's timeline for stability's timeout: each lowering's
/// first sight, now, and `erasure_timeout` (T), in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Clock<'c> {
    /// The peer's first sight of each event.
    pub first_sights: &'c BTreeMap<EventId, Reading>,
    /// Now, on the peer's timeline.
    pub now: Reading,
    /// `erasure_timeout`, T.
    pub timeout: u64,
}

/// The world of a skeleton cut (peers.md, "Skeleton cuts"; roster.md, "The
/// world after a checkpoint"): the cut as its root and the members, each
/// linked to its parents among them only, its height counted from the cut.
#[derive(Debug, Clone)]
pub(crate) struct World {
    /// Member → its height in the world and its parents among the members.
    nodes: BTreeMap<EventId, (u64, Vec<EventId>)>,
}

impl World {
    /// The world rooted at `root` over `members`, placed events of `log`.
    pub(crate) fn new(log: &Log, root: EventId, members: &BTreeSet<EventId>) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(root, (0, Vec::new()));
        // By height in the log, so that each parent comes before its
        // children.
        let mut order: Vec<(u64, EventId)> = members
            .iter()
            .filter(|&&id| id != root)
            .filter_map(|&id| log.height(id).map(|h| (h, id)))
            .collect();
        order.sort_unstable();
        for (_, id) in order {
            let Some(event) = log.event(id) else { continue };
            let parents: Vec<EventId> = event
                .parents()
                .iter()
                .copied()
                .filter(|p| nodes.contains_key(p))
                .collect();
            let height = 1 + parents.iter().map(|p| nodes[p].0).max().unwrap_or(0);
            nodes.insert(id, (height, parents));
        }
        Self { nodes }
    }

    fn contains(&self, id: EventId) -> bool {
        self.nodes.contains_key(&id)
    }

    fn height(&self, id: EventId) -> Option<u64> {
        self.nodes.get(&id).map(|n| n.0)
    }

    /// Whether `earlier` is in the world past of `later`.
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        let (Some(floor), Some(_)) = (self.height(earlier), self.height(later)) else {
            return false;
        };
        let mut seen = BTreeSet::new();
        let mut stack = vec![later];
        while let Some(current) = stack.pop() {
            for &parent in &self.nodes[&current].1 {
                if parent == earlier {
                    return true;
                }
                if self.nodes[&parent].0 > floor && seen.insert(parent) {
                    stack.push(parent);
                }
            }
        }
        false
    }
}

/// The order a skeleton reads: the log's, or a cut's world.
#[derive(Debug, Clone)]
enum Order {
    Log,
    World(World),
}

/// The cut a skeleton's world starts from.
#[derive(Debug, Clone)]
struct Base {
    /// The cut's event ID.
    cut: EventId,
    /// Its slots, each with the device ID of its enrolled pseudonym.
    slots: BTreeMap<SlotId, (SlotEntry, Option<DeviceId>)>,
}

/// Each author's fork point among `ids`, counting only the events `counts`
/// accepts (events.md, "Chains and evidence of a fork"): duplicates, and
/// skips whose `prev` counts too. The peer counts the events whose
/// signatures it verified.
pub fn fork_points(log: &Log, ids: &[EventId], counts: impl Fn(EventId) -> bool) -> ForkPoints {
    let counted: Vec<EventId> = ids.iter().copied().filter(|&id| counts(id)).collect();
    let mut slots: BTreeMap<(DeviceId, u64), Vec<EventId>> = BTreeMap::new();
    let mut evidence = Vec::new();
    for &id in &counted {
        let Some(event) = log.event(id) else { continue };
        slots
            .entry((*event.author(), event.seq()))
            .or_default()
            .push(id);
        let Some(prev) = event.prev() else { continue };
        let Some(previous) = log.event(prev) else {
            continue;
        };
        if !counts(prev) {
            continue;
        }
        let own = previous.author() == event.author();
        if own && previous.seq().checked_add(1) == Some(event.seq()) {
            continue;
        }
        let fork_seq = if own {
            event.seq().min(previous.seq().saturating_add(1))
        } else {
            event.seq()
        };
        evidence.push(Evidence {
            kind: EvidenceKind::Skip,
            author: *event.author(),
            seq: event.seq(),
            first: id,
            second: prev,
            fork_seq,
        });
    }
    for ((author, seq), slot) in slots {
        if let [first, second, ..] = slot[..] {
            evidence.push(Evidence {
                kind: EvidenceKind::Duplicate,
                author,
                seq,
                first,
                second,
                fork_seq: seq,
            });
        }
    }
    ForkPoints::from_evidence(&evidence)
}

/// peers.md, "What a peer checks before it stores a skeleton event", step 2
/// for a root, but for its being the first: its parents are exactly the
/// genesis and its seq is 1 (`Malformed`); its `mldsa`, beside an empty
/// X-Wing key, hashes to its kc, and `founder_mldsa` and `founder_xwing` to
/// the genesis's (`NotCommitted`); it verifies under its keys, and
/// `founder_signature` under the genesis's `ed` and `founder_mldsa`
/// (`BadSignature`).
///
/// # Errors
///
/// The class named; `Malformed` for a body that is not a root.
pub fn check_root(log: &Log, event: &Event, body: &StorageBody) -> Result<(), PeersClass> {
    let StorageBody::Root {
        mldsa,
        founder_mldsa,
        founder_signature,
        founder_xwing,
        ..
    } = body
    else {
        return Err(ErrorClass::Malformed.into());
    };
    let genesis = log.genesis();
    // The pseudonym's keys, beside an empty X-Wing key, and the founder's,
    // each by the kc that names them.
    let own = HybridKeys::new(mldsa, None).ok();
    let founder = HybridKeys::new(founder_mldsa, Some(founder_xwing)).ok();
    if event.seq() != 1 || event.parents() != [log.id()] {
        Err(ErrorClass::Malformed.into())
    } else if own.as_ref().map(HybridKeys::commitment) != Some(event.kc())
        || founder.as_ref().map(HybridKeys::commitment) != Some(genesis.kc())
    {
        Err(ErrorClass::NotCommitted.into())
    } else if log.verify_hybrid_remembered(event, own.as_ref()).is_err()
        || !founder.as_ref().is_some_and(|founder| {
            verify_hybrid(
                genesis.ed(),
                founder,
                &root_statement(&log.id(), event.author()),
                founder_signature,
            )
        })
    {
        Err(ErrorClass::BadSignature.into())
    } else {
        Ok(())
    }
}

/// The root of a log: the first storage event in canonical order whose body
/// reads as a root and that [`check_root`] accepts (peers.md, "The
/// skeleton"). It makes the founder's administrator slot
/// `[c(genesis), 0, the root's ID]`.
pub fn root_of(log: &Log) -> Option<EventId> {
    log.canonical().into_iter().find(|&id| {
        log.event(id).is_some_and(|event| {
            event.kind() == kind::STORAGE
                && check_size(event.signed_len()).is_ok()
                && StorageBody::read(event.unverified_body()).is_ok_and(|body| {
                    matches!(body, StorageBody::Root { .. })
                        && check_root(log, event, &body).is_ok()
                })
        })
    })
}

/// The twin a space event names in its visible key 15, read from its body
/// as CBOR.
pub fn named_twin(event: &Event) -> Option<EventId> {
    if event.kind() != kind::SPACE {
        return None;
    }
    let value = cbor::decode(event.unverified_body()).ok()?;
    let twin = value.as_map().ok()?.get(&visible_key::TWIN)?;
    match twin {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok().map(EventId),
        _ => None,
    }
}

/// The skeleton of one log in a view, as a peer holds it.
#[derive(Debug, Clone)]
pub struct Skeleton<'a> {
    log: &'a Log,
    view: BTreeSet<EventId>,
    space: EventId,
    status: BTreeMap<EventId, Status>,
    bodies: BTreeMap<EventId, StorageBody>,
    /// Skeleton events (types 0 to 7) whose body reads, in canonical order.
    skeleton: Vec<EventId>,
    /// Writer requests (types 16 and 17) whose body reads, in canonical
    /// order.
    requests: Vec<EventId>,
    /// Twin event ID → the first space event, in canonical order, that names
    /// it in visible key 15.
    names: BTreeMap<EventId, EventId>,
    /// Pseudonym, by device ID → its keys, from the root or its enrolment,
    /// which hash to its `kc`.
    key_of: BTreeMap<DeviceId, DeviceKeys>,
    /// Pseudonym → the administrator slot it is enrolled in.
    slot_of: BTreeMap<DeviceId, SlotId>,
    slots: BTreeMap<SlotId, Slot>,
    /// The root and the applied changes, in canonical order.
    makers: Vec<EventId>,
    /// Enrolment → the administrator slot it enrols.
    enrols: BTreeMap<EventId, SlotId>,
    /// Lower or disown → the administrator slot its slot reference names,
    /// which it lowers.
    targets: BTreeMap<EventId, SlotId>,
    /// The changes that repeat a commitment and pass the peer's checks,
    /// pending ones included.
    repeats: BTreeSet<EventId>,
    root: Option<EventId>,
    forks: ForkPoints,
    valid_contested: BTreeSet<EventId>,
    merged: BTreeMap<SlotId, SlotState>,
    /// The log's order, or a cut's world.
    order: Order,
    /// The cut the world starts from, if it does.
    base: Option<Base>,
    /// The world's epoch: 0 before any cut, else the cut's.
    epoch: u64,
    /// Pseudonym → the root or enrolment that enrolled it, by event ID: one
    /// the skeleton accepted, or the one a cut's entry names.
    enrolled_by: BTreeMap<DeviceId, EventId>,
    /// The skeleton events late at the peer under the cut the world starts
    /// from (peers.md, "Skeleton cuts", late skeleton events): stored, their
    /// bodies read, with no effect.
    late: BTreeSet<EventId>,
    /// The keys a late enrolment carries for its pseudonym, which hash to
    /// its `kc`, by device ID.
    late_keys: BTreeMap<DeviceId, DeviceKeys>,
}

/// A [`Skeleton`] apart from the log it read: what a reader keeps between
/// resolutions of a log that only grows.
#[derive(Debug, Clone)]
pub struct SkeletonParts {
    view: BTreeSet<EventId>,
    space: EventId,
    status: BTreeMap<EventId, Status>,
    bodies: BTreeMap<EventId, StorageBody>,
    skeleton: Vec<EventId>,
    requests: Vec<EventId>,
    names: BTreeMap<EventId, EventId>,
    key_of: BTreeMap<DeviceId, DeviceKeys>,
    slot_of: BTreeMap<DeviceId, SlotId>,
    slots: BTreeMap<SlotId, Slot>,
    makers: Vec<EventId>,
    enrols: BTreeMap<EventId, SlotId>,
    targets: BTreeMap<EventId, SlotId>,
    repeats: BTreeSet<EventId>,
    root: Option<EventId>,
    forks: ForkPoints,
    valid_contested: BTreeSet<EventId>,
    merged: BTreeMap<SlotId, SlotState>,
    order: Order,
    base: Option<Base>,
    epoch: u64,
    enrolled_by: BTreeMap<DeviceId, EventId>,
    late: BTreeSet<EventId>,
    late_keys: BTreeMap<DeviceId, DeviceKeys>,
}

impl<'a> Skeleton<'a> {
    /// The skeleton apart from its log.
    pub fn into_parts(self) -> SkeletonParts {
        let Self {
            log: _,
            view,
            space,
            status,
            bodies,
            skeleton,
            requests,
            names,
            key_of,
            slot_of,
            slots,
            makers,
            enrols,
            targets,
            repeats,
            root,
            forks,
            valid_contested,
            merged,
            order,
            base,
            epoch,
            enrolled_by,
            late,
            late_keys,
        } = self;
        SkeletonParts {
            view,
            space,
            status,
            bodies,
            skeleton,
            requests,
            names,
            key_of,
            slot_of,
            slots,
            makers,
            enrols,
            targets,
            repeats,
            root,
            forks,
            valid_contested,
            merged,
            order,
            base,
            epoch,
            enrolled_by,
            late,
            late_keys,
        }
    }

    /// A skeleton read before, over `log` now, with `added` in its view:
    /// placed events that are neither storage nor space events, and that
    /// add no fork evidence, which change nothing a skeleton reads.
    pub fn from_parts(
        log: &'a Log,
        parts: SkeletonParts,
        added: impl IntoIterator<Item = EventId>,
    ) -> Self {
        let SkeletonParts {
            mut view,
            space,
            status,
            bodies,
            skeleton,
            requests,
            names,
            key_of,
            slot_of,
            slots,
            makers,
            enrols,
            targets,
            repeats,
            root,
            forks,
            valid_contested,
            merged,
            order,
            base,
            epoch,
            enrolled_by,
            late,
            late_keys,
        } = parts;
        view.extend(added);
        Self {
            log,
            view,
            space,
            status,
            bodies,
            skeleton,
            requests,
            names,
            key_of,
            slot_of,
            slots,
            makers,
            enrols,
            targets,
            repeats,
            root,
            forks,
            valid_contested,
            merged,
            order,
            base,
            epoch,
            enrolled_by,
            late,
            late_keys,
        }
    }

    /// The skeleton of the storage events of `view`, a set of the log's
    /// placed events closed under parents; `None` for the whole log. It
    /// reads the log from its root and judges no cut: a cut it holds has no
    /// status but a refusal of its signature ([`crate::cut::PeerCuts`]
    /// judges cuts and starts the skeleton from the one in effect).
    pub fn new(log: &'a Log, view: Option<&BTreeSet<EventId>>) -> Self {
        let view: BTreeSet<EventId> = match view {
            Some(view) => view.clone(),
            None => log.canonical().into_iter().collect(),
        };
        Self::build(log, view, Order::Log, None, BTreeMap::new())
    }

    /// As [`Skeleton::new`], with the statuses of the cuts it holds decided
    /// before: each judged on its own past (peers.md, "Skeleton cuts").
    pub(crate) fn with_presets(
        log: &'a Log,
        view: BTreeSet<EventId>,
        presets: BTreeMap<EventId, Status>,
    ) -> Self {
        Self::build(log, view, Order::Log, None, presets)
    }

    /// The skeleton of the world of a cut in effect (peers.md, "Skeleton
    /// cuts"): `members` are the events that follow its checkpoint, the cut
    /// stands as the root, and `presets` are the statuses of the other cuts
    /// among the members, each judged on its own past. A peer starts from
    /// the cut once it is in effect there; a replica starts from it once
    /// its checkpoint takes effect at the replica (roster.md, 3.15.5 The
    /// world after a checkpoint, Skeleton). `log` holds the cut and the
    /// roots and enrolments its slots name.
    pub fn after_cut(
        log: &'a Log,
        cut_id: EventId,
        cut: &Cut,
        members: BTreeSet<EventId>,
        presets: BTreeMap<EventId, Status>,
    ) -> Self {
        let mut view = members;
        view.insert(cut_id);
        let world = World::new(log, cut_id, &view);
        let base = Base {
            cut: cut_id,
            slots: cut
                .slots
                .iter()
                .map(|entry| {
                    let pseudonym = entry
                        .pseudonym
                        .and_then(|id| log.event(id))
                        .map(|event| *event.author());
                    (entry.slot, (entry.clone(), pseudonym))
                })
                .collect_map(),
        };
        let mut skeleton = Self::build_with(log, view, Order::World(world), Some(base), presets);
        skeleton.epoch = cut.epoch;
        skeleton
    }

    fn build(
        log: &'a Log,
        view: BTreeSet<EventId>,
        order: Order,
        base: Option<Base>,
        presets: BTreeMap<EventId, Status>,
    ) -> Self {
        Self::build_with(log, view, order, base, presets)
    }

    fn build_with(
        log: &'a Log,
        view: BTreeSet<EventId>,
        order: Order,
        base: Option<Base>,
        presets: BTreeMap<EventId, Status>,
    ) -> Self {
        let epoch = 0;
        let mut skeleton = Self {
            log,
            space: log.id(),
            view,
            status: BTreeMap::new(),
            bodies: BTreeMap::new(),
            skeleton: Vec::new(),
            requests: Vec::new(),
            names: BTreeMap::new(),
            key_of: BTreeMap::new(),
            slot_of: BTreeMap::new(),
            slots: BTreeMap::new(),
            makers: Vec::new(),
            enrols: BTreeMap::new(),
            targets: BTreeMap::new(),
            repeats: BTreeSet::new(),
            root: None,
            forks: ForkPoints::default(),
            valid_contested: BTreeSet::new(),
            merged: BTreeMap::new(),
            order,
            base: None,
            epoch,
            enrolled_by: BTreeMap::new(),
            late: BTreeSet::new(),
            late_keys: BTreeMap::new(),
        };
        skeleton.status = presets;
        let order = skeleton.canonical(&skeleton.view);
        for &id in &order {
            let event = log.event(id).expect("a view holds placed events");
            match event.kind() {
                kind::STORAGE => {
                    // Step 1 reads the body; steps 2 to 4 check the
                    // signature, the ML-DSA-65 half included.
                    let read = check_size(event.signed_len())
                        .and_then(|()| StorageBody::read(event.unverified_body()));
                    match read {
                        Ok(body) => {
                            if body.storage_type().is_skeleton() {
                                skeleton.skeleton.push(id);
                            } else {
                                skeleton.requests.push(id);
                            }
                            skeleton.bodies.insert(id, body);
                        }
                        Err(class) => {
                            skeleton.status.entry(id).or_insert(Status::void(class));
                        }
                    }
                }
                kind::SPACE => {
                    if let Some(twin) = named_twin(event) {
                        skeleton.names.entry(twin).or_insert(id);
                    }
                }
                _ => {}
            }
        }
        if let Some(base) = base {
            skeleton.install_base(base);
        }
        skeleton.store_checks();
        let verified = |id: EventId| match log.event(id) {
            _ if !skeleton.in_order(id) => false,
            Some(event) if event.kind() == kind::STORAGE => {
                skeleton.bodies.contains_key(&id)
                    && !matches!(skeleton.status.get(&id),
                        Some(Status::Void { class, .. }) if refused_at_store(*class))
            }
            Some(_) => true,
            None => false,
        };
        let forks = fork_points(log, &order, verified);
        skeleton.forks = forks;
        skeleton.run_resolution();
        skeleton
    }

    /// peers.md, "Skeleton cuts": the cut stands as the root. Its slots are
    /// in from the start, each enrolled to the pseudonym of the root or
    /// enrolment its entry names, whose keys that event gives: the peer
    /// holds it in the cut's past and keeps it after truncation.
    fn install_base(&mut self, base: Base) {
        self.root = Some(base.cut);
        for (slot, (entry, pseudonym)) in &base.slots {
            self.slots.insert(
                *slot,
                Slot {
                    maker: slot.maker,
                    slot_ed: entry.slot_ed,
                    slot_mldsa_hash: entry.slot_mldsa_hash,
                    rank: entry.rank,
                },
            );
            let (Some(author), Some(enrolment)) = (pseudonym, entry.pseudonym) else {
                continue;
            };
            let keys = self.log.event(enrolment).and_then(|event| {
                let mldsa = match StorageBody::read(event.unverified_body()).ok()? {
                    StorageBody::Root { mldsa, .. } | StorageBody::Enrol { mldsa, .. } => mldsa,
                    _ => return None,
                };
                let keys = HybridKeys::new(&mldsa, None).ok()?;
                Some(DeviceKeys {
                    ed: *event.ed(),
                    keys,
                })
            });
            if let Some(keys) = keys {
                self.key_of.insert(*author, keys);
            }
            self.slot_of.insert(*author, *slot);
            self.enrolled_by.insert(*author, enrolment);
        }
        self.base = Some(base);
    }

    /// peers.md, "Skeleton cuts", late skeleton events: each event of `late`
    /// is stored once its body reads (section 3.11, step 1) and runs no
    /// other step. It is `Late`: in no skeleton the world resolves, it
    /// makes, enrols and lowers nothing, acknowledges nothing, and a late
    /// erasure or credentials request is void. Its signature is not
    /// verified, so it is never fork evidence. A late enrolment's
    /// pseudonym may still present its credential, under the `ed` of the
    /// enrolment's envelope (section 3.7, step 3).
    ///
    /// A late enrolment of `refused` failed what a late enrolment must pass
    /// (peers.md, "Skeleton cuts", what a late enrolment opens): it takes
    /// that class, a refusal, and is neither late nor its pseudonym's keys
    /// held.
    pub(crate) fn mark_late(
        &mut self,
        late: BTreeSet<EventId>,
        refused: BTreeMap<EventId, PeersClass>,
    ) {
        for &id in &late {
            if let Some(&class) = refused.get(&id) {
                self.status.insert(id, Status::void(class));
                continue;
            }
            let Some(event) = self.log.event(id) else {
                continue;
            };
            let Ok(body) = check_size(event.signed_len())
                .and_then(|()| StorageBody::read(event.unverified_body()))
            else {
                continue;
            };
            if let StorageBody::Enrol { mldsa, .. } = &body
                && !self.key_of.contains_key(event.author())
                && let Some(keys) = HybridKeys::new(mldsa, None)
                    .ok()
                    .filter(|keys| keys.commitment() == event.kc())
            {
                self.late_keys.entry(*event.author()).or_insert(DeviceKeys {
                    ed: *event.ed(),
                    keys,
                });
            }
            self.bodies.insert(id, body);
            self.status.insert(id, Status::void(PeersClass::Late));
            self.late.insert(id);
        }
    }

    // -- What a peer checks before it stores a skeleton event

    /// peers.md, "What a peer checks before it stores a skeleton event",
    /// steps 2 to 7, in canonical order. Step 1, the body, ran when the
    /// events were read. A cut is judged on its own past
    /// ([`crate::cut`]); here it meets step 4 alone, and the cut a world
    /// starts from none.
    fn store_checks(&mut self) {
        let log = self.log;
        let mut checked = Vec::new();
        let base = self.base.as_ref().map(|b| b.cut);
        for id in self.skeleton.clone() {
            if Some(id) == base {
                continue;
            }
            let event = log.event(id).expect("placed");
            let body = self.bodies[&id].clone();
            let outcome = match &body {
                // A cut judged on its own past keeps that status
                // (peers.md, "Skeleton cuts", step 2 reads the pseudonym's
                // key wherever the peer holds its root or enrolment).
                StorageBody::Cut(_) if self.status.contains_key(&id) => Ok(()),
                StorageBody::Cut(_) => self.check_step_4(event),
                StorageBody::Root { twin, mldsa, .. } => {
                    if self.root.is_some() {
                        Err(PeersClass::DuplicateRoot)
                    } else if let Err(class) = check_root(log, event, &body) {
                        Err(class)
                    } else {
                        let own = HybridKeys::new(mldsa, None).ok();
                        let slot = SlotId::new(*twin, 0, id);
                        self.root = Some(id);
                        self.slots.insert(
                            slot,
                            Slot {
                                maker: id,
                                slot_ed: None,
                                slot_mldsa_hash: None,
                                rank: MAX_RANK,
                            },
                        );
                        self.makers.push(id);
                        self.key_of.insert(
                            *event.author(),
                            DeviceKeys {
                                ed: *event.ed(),
                                keys: own.expect("committed keys"),
                            },
                        );
                        self.slot_of.insert(*event.author(), slot);
                        self.enrolled_by.insert(*event.author(), id);
                        Ok(())
                    }
                }
                StorageBody::Enrol {
                    slot,
                    mldsa,
                    slot_mldsa,
                    authorization,
                    ..
                } => {
                    // The administrator slot its slot reference names, made
                    // by an applied change: the root's is enrolled from the
                    // start.
                    let keyed = self
                        .named_slot(*slot, id)
                        .and_then(|s| match self.slots[&s] {
                            Slot {
                                slot_ed: Some(ed),
                                slot_mldsa_hash: Some(hash),
                                ..
                            } => Some((s, ed, hash)),
                            _ => None,
                        });
                    match keyed {
                        None => Err(PeersClass::UnknownAdministratorSlot),
                        Some((enrolled, ed, hash)) => {
                            let statement =
                                enrol_statement(&self.space, slot.reference, event.author());
                            // At seq 1, for an author not held yet, under the
                            // administrator slot's keys (BadSignature); then
                            // the pseudonym's keys, by its kc (NotCommitted);
                            // then the event's ML-DSA-65 half under them
                            // (BadSignature).
                            if event.seq() != 1
                                || self.key_of.contains_key(event.author())
                                || sha256(&[slot_mldsa]) != hash
                                || !verify_slot(&ed, slot_mldsa, &statement, authorization)
                            {
                                Err(ErrorClass::BadSignature.into())
                            } else {
                                let own = HybridKeys::new(mldsa, None)
                                    .ok()
                                    .filter(|own| own.commitment() == event.kc());
                                match own {
                                    None => Err(ErrorClass::NotCommitted.into()),
                                    Some(own)
                                        if log
                                            .verify_hybrid_remembered(event, Some(&own))
                                            .is_err() =>
                                    {
                                        Err(ErrorClass::BadSignature.into())
                                    }
                                    Some(own) => {
                                        self.key_of.insert(
                                            *event.author(),
                                            DeviceKeys {
                                                ed: *event.ed(),
                                                keys: own,
                                            },
                                        );
                                        self.slot_of.insert(*event.author(), enrolled);
                                        self.enrols.insert(id, enrolled);
                                        self.enrolled_by.insert(*event.author(), id);
                                        Ok(())
                                    }
                                }
                            }
                        }
                    }
                }
                _ => self.check_signed(id, event, &body, &mut checked),
            };
            if let Err(class) = outcome {
                self.status.insert(id, Status::void(class));
            }
        }
    }

    /// Step 4: the author is an enrolled pseudonym, and the event verifies
    /// under that pseudonym's ML-DSA-65 key.
    pub(crate) fn check_step_4(&self, event: &Event) -> Result<(), PeersClass> {
        let key = self
            .key_of
            .get(event.author())
            .ok_or(PeersClass::NotAuthorized)?;
        if self
            .log
            .verify_hybrid_remembered(event, Some(&key.keys))
            .is_err()
        {
            return Err(ErrorClass::BadSignature.into());
        }
        Ok(())
    }

    /// Steps 4 to 7 for a change, disown, acknowledgement, erasure or
    /// credentials request; a change that passes is applied. `checked`
    /// holds the changes that passed steps 4 to 6 before it, in canonical
    /// order.
    fn check_signed(
        &mut self,
        id: EventId,
        event: &Event,
        body: &StorageBody,
        checked: &mut Vec<EventId>,
    ) -> Result<(), PeersClass> {
        // 4. Its author is an enrolled pseudonym, and it verifies under that
        // pseudonym's ML-DSA-65 key.
        self.check_step_4(event)?;
        // 5. A lower or a disown: its slot reference names an
        // administrator slot. It lowers that one alone.
        if let Some(target) = body.lowered() {
            let lowered = self
                .named_slot(target, id)
                .ok_or(PeersClass::UnknownAdministratorSlot)?;
            self.targets.insert(id, lowered);
        }
        if let StorageBody::Change { twin, effect, .. } = body {
            // 6. The planted administrator slots the peer recognises: the
            // grants of changes that repeat a commitment, in its past and its
            // own, number at most 256.
            let past: Vec<EventId> = checked
                .iter()
                .copied()
                .filter(|&c| self.before(c, id))
                .collect();
            // The root's commitment: a cut's, when the world starts from one.
            let carries = |c: EventId| match self.bodies.get(&c) {
                Some(
                    StorageBody::Root { twin: t, .. }
                    | StorageBody::Change { twin: t, .. }
                    | StorageBody::Cut(Cut { twin: t, .. }),
                ) => t == twin,
                _ => false,
            };
            let repeats = self.root.is_some_and(|r| self.before(r, id) && carries(r))
                || past.iter().any(|&c| carries(c));
            let grants = body.grants().len();
            if repeats && grants > 0 {
                let count = grants
                    + past
                        .iter()
                        .filter(|c| self.repeats.contains(c))
                        .map(|c| self.bodies[c].grants().len())
                        .sum::<usize>();
                if count > MAX_PLANTED {
                    return Err(PeersClass::PlantedSlotsFull);
                }
            }
            checked.push(id);
            if repeats {
                self.repeats.insert(id);
            }
            // 7. A change applies once a stored space event names it. One
            // that repeats a commitment makes administrator slots of its
            // own.
            if !self.names.contains_key(&id) {
                return Err(PeersClass::Unnamed);
            }
            self.makers.push(id);
            if let ChangeEffect::Grants(grants) = effect {
                for (index, grant) in grants.iter().enumerate() {
                    self.slots.insert(
                        SlotId::new(*twin, index as u8, id),
                        Slot {
                            maker: id,
                            slot_ed: Some(grant.slot_ed),
                            slot_mldsa_hash: Some(grant.slot_mldsa_hash),
                            rank: grant.rank,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// The administrator slot a slot reference in `event` names: the one its
    /// maker, the root or an applied change in `event`'s past whose `twin`
    /// is its commitment, made at its index (peers.md, "Storage events").
    ///
    /// In a cut's world, a slot reference also names a slot of the cut by its
    /// reference as written there.
    fn named_slot(&self, slot: SlotId, event: EventId) -> Option<SlotId> {
        if self
            .base
            .as_ref()
            .is_some_and(|base| base.slots.contains_key(&slot))
        {
            return Some(slot);
        }
        (self.slots.contains_key(&slot) && slot.maker != event && self.before(slot.maker, event))
            .then_some(slot)
    }

    // -- Order, in the log or in a cut's world

    /// Whether the event is in the order the skeleton reads: any held event
    /// of the log, or a member of the cut's world.
    fn in_order(&self, id: EventId) -> bool {
        match &self.order {
            Order::Log => true,
            Order::World(world) => world.contains(id),
        }
    }

    /// Whether `earlier` is in `later`'s past, in the order the skeleton
    /// reads.
    pub fn before(&self, earlier: EventId, later: EventId) -> bool {
        match &self.order {
            Order::Log => self.log.precedes(earlier, later),
            Order::World(world) => world.precedes(earlier, later),
        }
    }

    /// Whether two events are concurrent, in the order the skeleton reads.
    pub fn concurrent(&self, a: EventId, b: EventId) -> bool {
        a != b && !self.before(a, b) && !self.before(b, a)
    }

    /// An event's height, in the log or counted from the cut.
    pub fn height_of(&self, id: EventId) -> Option<u64> {
        match &self.order {
            Order::Log => self.log.height(id),
            Order::World(world) => world.height(id),
        }
    }

    /// The events of `ids` in the order the skeleton reads, in canonical
    /// order: by height, then by ID.
    fn canonical(&self, ids: &BTreeSet<EventId>) -> Vec<EventId> {
        match &self.order {
            Order::Log => self.log.canonical_in(ids),
            Order::World(world) => {
                let mut out: Vec<(u64, EventId)> = ids
                    .iter()
                    .filter_map(|&id| world.height(id).map(|h| (h, id)))
                    .collect();
                out.sort_unstable();
                out.into_iter().map(|(_, id)| id).collect()
            }
        }
    }

    // -- The skeleton's resolution

    fn run_resolution(&mut self) {
        let contested: Vec<EventId> = self
            .skeleton
            .iter()
            .copied()
            .filter(|id| !self.status.contains_key(id) && self.body(*id).is_contested())
            .collect();
        let resolution = resolve(&*self, contested.iter().copied());
        for (id, verdict) in resolution.iter() {
            let status = match *verdict {
                Verdict::Valid(_) => Status::Valid,
                Verdict::Void { class, by } => Status::Void { class, by },
            };
            self.status.insert(id, status);
        }
        if let Some(root) = self.root {
            self.status.insert(root, Status::Valid);
        }
        self.valid_contested = contested
            .iter()
            .copied()
            .filter(|id| self.status[id].is_valid())
            .collect();
        let valid: Vec<EventId> = self.valid_contested.iter().copied().collect();
        self.merged = self.state(&valid);
        for id in self.skeleton.clone() {
            if !self.status.contains_key(&id) && self.body(id).is_request() {
                let status = self.request_status(id);
                self.status.insert(id, status);
            }
        }
    }

    fn body(&self, id: EventId) -> StorageType {
        self.bodies[&id].storage_type()
    }

    fn author(&self, id: EventId) -> &DeviceId {
        self.log.event(id).expect("placed").author()
    }

    /// The administrator slot an event's author holds; for an enrolment, the
    /// one it enrols.
    fn author_slot(&self, id: EventId) -> Option<SlotId> {
        match &self.bodies[&id] {
            StorageBody::Enrol { .. } => self.enrols.get(&id).copied(),
            _ => self.slot_of.get(self.author(id)).copied(),
        }
    }

    fn lowered(&self, id: EventId) -> &[SlotId] {
        self.targets.get(&id).map_or(&[], core::slice::from_ref)
    }

    /// A lower or disown whose slot reference names its author's own
    /// administrator slot.
    fn is_self_lowering(&self, id: EventId) -> bool {
        matches!(self.lowered(id), [only] if self.slot_of.get(self.author(id)) == Some(only))
    }

    /// The administrator slots at a place, a set of valid contested events:
    /// the root's, enrolled to its author, and those the changes of the
    /// place grant; enrolled by its enrolments; out where its lowers and
    /// disowns name them.
    pub fn state(&self, place: &[EventId]) -> BTreeMap<SlotId, SlotState> {
        let mut state = BTreeMap::new();
        if let Some(base) = &self.base {
            for (slot, (_, pseudonym)) in &base.slots {
                state.insert(
                    *slot,
                    SlotState {
                        is_in: true,
                        enrolled: *pseudonym,
                    },
                );
            }
        } else if let Some(root) = self.root {
            let author = *self.author(root);
            state.insert(
                self.slot_of[&author],
                SlotState {
                    is_in: true,
                    enrolled: Some(author),
                },
            );
        }
        let mut place: Vec<EventId> = place
            .iter()
            .copied()
            .filter(|id| self.bodies.contains_key(id))
            .collect();
        place.sort_unstable_by_key(|&id| (self.height_of(id), id));
        for &id in &place {
            if let StorageBody::Change {
                twin,
                effect: ChangeEffect::Grants(grants),
                ..
            } = &self.bodies[&id]
            {
                for index in 0..grants.len() {
                    state.insert(
                        SlotId::new(*twin, index as u8, id),
                        SlotState {
                            is_in: true,
                            enrolled: None,
                        },
                    );
                }
            }
        }
        for &id in &place {
            if let Some(slot) = self.enrols.get(&id)
                && let Some(s) = state.get_mut(slot)
            {
                s.enrolled = Some(*self.author(id));
            }
        }
        for &id in &place {
            for slot in self.lowered(id) {
                if let Some(s) = state.get_mut(slot) {
                    s.is_in = false;
                }
            }
        }
        state
    }

    /// The valid contested events in an event's past.
    fn valid_past(&self, id: EventId) -> Vec<EventId> {
        self.valid_contested
            .iter()
            .copied()
            .filter(|&x| self.before(x, id))
            .collect()
    }

    /// A skeleton request (an acknowledgement, an erasure or a credentials
    /// request) is valid at the peer when its author is enrolled in an
    /// administrator slot that is in at its place, no valid lower or disown
    /// of that administrator slot is concurrent with it, and its author has
    /// not forked at or before it.
    fn request_status(&self, id: EventId) -> Status {
        let event = self.log.event(id).expect("placed");
        if self.forks.is_void(event) {
            return Status::void(ErrorClass::Forked.into());
        }
        let author = event.author();
        let Some(slot) = self.slot_of.get(author).copied() else {
            return Status::void(ErrorClass::NotAnAdministrator.into());
        };
        let state = self.state(&self.valid_past(id));
        match state.get(&slot) {
            Some(s) if s.is_in && s.enrolled.as_ref() == Some(author) => {}
            _ => return Status::void(ErrorClass::NotAnAdministrator.into()),
        }
        let concurrent = self
            .canonical(&self.valid_contested)
            .into_iter()
            .find(|&x| self.lowered(x).contains(&slot) && self.concurrent(x, id));
        match concurrent {
            Some(x) => Status::Void {
                class: PeersClass::RemovedConcurrently,
                by: Some(x),
            },
            None => Status::Valid,
        }
    }

    // -- What the skeleton shows

    /// The log.
    pub fn log(&self) -> &'a Log {
        self.log
    }

    /// The view the skeleton reads.
    pub fn view(&self) -> &BTreeSet<EventId> {
        &self.view
    }

    /// The space ID.
    pub fn space(&self) -> EventId {
        self.space
    }

    /// The root, the first in canonical order that the peer's checks
    /// accept; in a cut's world, the cut.
    pub fn root(&self) -> Option<EventId> {
        self.root
    }

    /// The cut the skeleton's world starts from, if it does.
    pub fn cut(&self) -> Option<EventId> {
        self.base.as_ref().map(|base| base.cut)
    }

    /// Whether an administrator slot is a slot of the cut the world starts
    /// from.
    pub fn is_cut_slot(&self, slot: SlotId) -> bool {
        self.base
            .as_ref()
            .is_some_and(|base| base.slots.contains_key(&slot))
    }

    /// The epoch of the skeleton's world: 0 from the root, else the cut's.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The root or enrolment that enrolled a pseudonym, by event ID: one
    /// the skeleton accepted, or the one a cut's entry names.
    pub fn enrolled_by(&self, pseudonym: &DeviceId) -> Option<EventId> {
        self.enrolled_by.get(pseudonym).copied()
    }

    /// The slot entries of the merged skeleton, as a cut made over it
    /// carries them (peers.md, "Storage events"): every administrator slot
    /// that is in, with its keys, seniority, enrolled pseudonym's root or
    /// enrolment and rank, strictly ascending by the bytes of their slot
    /// references.
    pub fn cut_slots(&self) -> Vec<SlotEntry> {
        let mut out: Vec<SlotEntry> = self
            .administrators()
            .into_iter()
            .filter_map(|slot| {
                let meta = self.slots.get(&slot)?;
                let (epoch, height, _, maker) = self.seniority(slot)?;
                let pseudonym = self.merged[&slot]
                    .enrolled
                    .and_then(|p| self.enrolled_by.get(&p).copied());
                Some(SlotEntry {
                    slot,
                    slot_ed: meta.slot_ed,
                    slot_mldsa_hash: meta.slot_mldsa_hash,
                    seniority: CutSeniority {
                        epoch,
                        height,
                        maker,
                    },
                    pseudonym,
                    rank: meta.rank,
                })
            })
            .collect();
        out.sort_by_cached_key(SlotEntry::sort_bytes);
        out
    }

    /// A storage event's status: its refusal, its verdict in the
    /// resolution, or whether it is valid at the peer. `None` for a writer
    /// request and for any event that is not a storage event.
    pub fn status(&self, id: EventId) -> Option<Status> {
        self.status.get(&id).copied()
    }

    /// Every storage event with a status, in canonical order; then the late
    /// events, and the late enrolments refused, in the log's canonical
    /// order.
    pub fn statuses(&self) -> Vec<(EventId, Status)> {
        let outside: BTreeSet<EventId> = self
            .status
            .keys()
            .copied()
            .filter(|id| !self.view.contains(id))
            .collect();
        self.canonical(&self.view)
            .into_iter()
            .chain(self.log.canonical_in(&outside))
            .filter_map(|id| self.status(id).map(|status| (id, status)))
            .collect()
    }

    /// The skeleton events late at the peer under the cut the world starts
    /// from (peers.md, "Skeleton cuts", late skeleton events), each `Late`,
    /// its body read: none in a skeleton from the root.
    pub fn late_events(&self) -> &BTreeSet<EventId> {
        &self.late
    }

    /// Whether the event has a valid status.
    pub fn is_valid(&self, id: EventId) -> bool {
        self.status(id).is_some_and(Status::is_valid)
    }

    /// A storage event's body, if it reads.
    pub fn body_of(&self, id: EventId) -> Option<&StorageBody> {
        self.bodies.get(&id)
    }

    /// The skeleton events (types 0 to 7) whose body reads, in canonical
    /// order.
    pub fn skeleton_events(&self) -> &[EventId] {
        &self.skeleton
    }

    /// The writer requests whose body reads, in canonical order, with their
    /// bodies.
    pub fn writer_requests(&self) -> Vec<(EventId, &StorageBody)> {
        self.requests
            .iter()
            .map(|id| (*id, &self.bodies[id]))
            .collect()
    }

    /// The space event that names a twin in visible key 15, the first in
    /// canonical order.
    pub fn named_by(&self, twin: EventId) -> Option<EventId> {
        self.names.get(&twin).copied()
    }

    /// The keys a root or an enrolment the peer's checks accept carries for
    /// a pseudonym, which hash to the pseudonym's `kc` (crypto.md, "Keys by
    /// their hash").
    pub fn pseudonym_key(&self, pseudonym: &DeviceId) -> Option<&HybridKeys> {
        self.pseudonym_keys(pseudonym).map(|keys| &keys.keys)
    }

    /// A pseudonym's keys, its Ed25519 key the `ed` of the root's or
    /// enrolment's envelope, under which its credential 3 proof verifies
    /// (peers.md, "Presenting a credential"): of the root or an enrolment
    /// the peer's checks accept, or of a late enrolment, which the peer
    /// stores too.
    pub fn pseudonym_keys(&self, pseudonym: &DeviceId) -> Option<&DeviceKeys> {
        self.key_of
            .get(pseudonym)
            .or_else(|| self.late_keys.get(pseudonym))
    }

    /// The pseudonyms of late enrolments, by device ID, whose keys
    /// [`Skeleton::pseudonym_keys`] gives: enrolled in no slot.
    pub fn late_pseudonyms(&self) -> impl Iterator<Item = &DeviceId> {
        self.late_keys.keys()
    }

    /// The pseudonyms the root and accepted enrolments name, by device ID,
    /// with their administrator slots.
    pub fn pseudonyms(&self) -> impl Iterator<Item = (&DeviceId, SlotId)> {
        self.slot_of.iter().map(|(p, s)| (p, *s))
    }

    /// The administrator slot a pseudonym is enrolled in.
    pub fn slot_of(&self, pseudonym: &DeviceId) -> Option<SlotId> {
        self.slot_of.get(pseudonym).copied()
    }

    /// An administrator slot the peer holds.
    pub fn slot(&self, slot: SlotId) -> Option<Slot> {
        self.slots.get(&slot).copied()
    }

    /// The root and the applied changes, each of which makes administrator
    /// slots, in canonical order.
    pub fn makers(&self) -> &[EventId] {
        &self.makers
    }

    /// The administrator slot a lower or disown that passed the peer's
    /// checks lowers, the one its slot reference names: none or one.
    pub fn lowers(&self, event: EventId) -> &[SlotId] {
        self.lowered(event)
    }

    /// Whether a change that passed the peer's checks repeats a commitment:
    /// its `twin` is the root's, or that of a change in its past that the
    /// peer's checks do not refuse (peers.md, "What a peer checks before it
    /// stores a skeleton event").
    pub fn repeats(&self, change: EventId) -> bool {
        self.repeats.contains(&change)
    }

    /// The fork points among the events the peer verified.
    pub fn forks(&self) -> &ForkPoints {
        &self.forks
    }

    /// The merged skeleton: the state over every valid contested event.
    pub fn merged(&self) -> &BTreeMap<SlotId, SlotState> {
        &self.merged
    }

    /// The administrator slots in the merged skeleton, in order.
    pub fn administrators(&self) -> Vec<SlotId> {
        self.merged
            .iter()
            .filter(|(_, s)| s.is_in)
            .map(|(slot, _)| *slot)
            .collect()
    }

    /// An administrator slot's seniority: `(epoch, height, hash, maker)`. A
    /// slot of the cut a world starts from keeps the one its entry gives.
    pub fn seniority(&self, slot: SlotId) -> Option<Seniority> {
        if let Some((entry, _)) = self.base.as_ref().and_then(|b| b.slots.get(&slot)) {
            let (_, _, hash, _) = seniority_in(0, &self.space, slot.reference, slot.maker, 0);
            let s = entry.seniority;
            return Some((s.epoch, s.height, hash, s.maker));
        }
        let maker = self.slots.get(&slot)?.maker;
        Some(seniority_in(
            self.epoch,
            &self.space,
            slot.reference,
            maker,
            self.height_of(maker).unwrap_or(0),
        ))
    }

    /// An administrator slot's rank (peers.md, "The skeleton's
    /// resolution", ranks): 255 for the root's, its grant map's for a
    /// change's, its entry's for a slot of the cut a world starts from; 0
    /// for a slot the peer does not hold.
    pub fn rank(&self, slot: SlotId) -> u8 {
        self.slots.get(&slot).map_or(0, |s| s.rank)
    }

    /// The order of authority between administrator slots, smallest first:
    /// the higher rank, then the more senior.
    fn authority_key(&self, slot: Option<SlotId>) -> (u8, Option<Seniority>) {
        match slot {
            Some(slot) => (MAX_RANK - self.rank(slot), self.seniority(slot)),
            None => (MAX_RANK, None),
        }
    }

    // -- Stability at the peer

    /// An administrator slot's acknowledging events: the event that made it
    /// and every skeleton event signed by the pseudonym validly enrolled in
    /// it.
    pub(crate) fn acknowledging(&self, slot: SlotId) -> Vec<EventId> {
        // A slot of the cut was made before the world: its maker is not in
        // it.
        let mut out: Vec<EventId> = self
            .slots
            .get(&slot)
            .map(|s| s.maker)
            .filter(|&maker| self.in_order(maker))
            .into_iter()
            .collect();
        if let Some(key) = self.merged.get(&slot).and_then(|s| s.enrolled)
            && self.forks.fork_point(&key).is_none()
        {
            out.extend(self.log.chain_rev(&key).filter(|&id| {
                !self.late.contains(&id)
                    && self
                        .bodies
                        .get(&id)
                        .is_some_and(|body| body.storage_type().is_skeleton())
            }));
        }
        out
    }

    /// Whether, for every administrator slot of `slots` whose pseudonym has
    /// not forked, an acknowledging event of it has `target` in its past or
    /// is `target`.
    pub fn acknowledged(&self, target: EventId, slots: &[SlotId]) -> bool {
        slots.iter().all(|&slot| {
            let forked = self
                .merged
                .get(&slot)
                .and_then(|s| s.enrolled)
                .is_some_and(|key| self.forks.fork_point(&key).is_some());
            forked
                || self
                    .acknowledging(slot)
                    .into_iter()
                    .any(|a| a == target || self.before(target, a))
        })
    }

    /// The valid lowerings of another pseudonym's administrator slot,
    /// disowns and lowers alike, in canonical order.
    pub fn lowerings(&self) -> Vec<EventId> {
        self.canonical(&self.valid_contested)
            .into_iter()
            .filter(|&x| !self.lowered(x).is_empty() && !self.is_self_lowering(x))
            .collect()
    }

    /// Whether a lowering is settled: stable itself over the administrator
    /// slots that are in at its place, the lowered one included, or held by
    /// the peer for T from its first sight.
    pub fn settled(&self, lowering: EventId, clock: Option<&Clock<'_>>) -> bool {
        let before = self.state(&self.valid_past(lowering));
        let slots: Vec<SlotId> = before
            .iter()
            .filter(|(_, s)| s.is_in)
            .map(|(slot, _)| *slot)
            .collect();
        if self.acknowledged(lowering, &slots) {
            return true;
        }
        clock.is_some_and(|clock| {
            clock
                .first_sights
                .get(&lowering)
                .is_some_and(|seen| lower(seen, &clock.now) >= clock.timeout)
        })
    }

    /// The stability set: the administrator slots in the merged skeleton,
    /// and each administrator slot a valid lowering by another pseudonym
    /// lowered, until that lowering is settled. In order.
    pub fn stability_set(&self, clock: Option<&Clock<'_>>) -> Vec<SlotId> {
        let mut slots: BTreeSet<SlotId> = self.administrators().into_iter().collect();
        for x in self.lowerings() {
            if !self.settled(x, clock) {
                slots.extend(self.lowered(x).iter().copied());
            }
        }
        slots.into_iter().collect()
    }

    /// Whether an event is stable at the peer: every administrator slot of
    /// the stability set whose pseudonym has not forked acknowledges it.
    pub fn is_stable(&self, target: EventId, clock: Option<&Clock<'_>>) -> bool {
        self.acknowledged(target, &self.stability_set(clock))
    }
}

/// The skeleton's resolution (peers.md, "The skeleton's resolution"), read
/// as roster.md's procedure over the applied changes, disowns and
/// enrolments that passed the peer's checks.
impl Resolve for Skeleton<'_> {
    type Id = EventId;
    type Class = PeersClass;
    type PickKey = (u8, Option<Seniority>, u64, EventId);

    fn height(&self, event: EventId) -> u64 {
        self.height_of(event).unwrap_or(0)
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.before(earlier, later)
    }

    /// The peer's checks ran first; nothing more.
    fn check(&self, _: EventId) -> Result<(), PeersClass> {
        Ok(())
    }

    /// A pseudonym is void from its fork point, counting only events whose
    /// signatures the peer verified.
    fn forked(&self, event: EventId) -> Option<PeersClass> {
        let event = self.log.event(event)?;
        self.forks
            .is_void(event)
            .then_some(ErrorClass::Forked.into())
    }

    /// A lower or disown of its author's own administrator slot.
    fn self_lowering(&self, event: EventId) -> bool {
        self.is_self_lowering(event)
    }

    /// Two concurrent enrolments of one administrator slot are both void.
    fn check_among(&self, event: EventId, screened: &[EventId]) -> Result<(), PeersClass> {
        let Some(slot) = self.enrols.get(&event) else {
            return Ok(());
        };
        let rival = screened.iter().any(|&other| {
            other != event
                && self.enrols.get(&other) == Some(slot)
                && Skeleton::concurrent(self, event, other)
        });
        if rival {
            Err(PeersClass::ConcurrentEnrolment)
        } else {
            Ok(())
        }
    }

    /// `Full` past 4,096 valid contested events in the place; for an
    /// enrolment, its administrator slot in (`NotAMember`) and not yet
    /// enrolled (`AlreadyEnrolled`); otherwise the author enrolled in an
    /// administrator slot that is in (`NotAnAdministrator`), the slot it
    /// lowers in (`NotAMember`) and of a rank at most its author's slot's
    /// (`HigherRank`).
    fn authority(&self, event: EventId, view: &View<'_, Self>) -> Result<(), PeersClass> {
        let place = view.place(event);
        if place.len() + 1 > MAX_SKELETON_PLACE {
            return Err(ErrorClass::Full.into());
        }
        let state = self.state(&place);
        if let StorageBody::Enrol { .. } = &self.bodies[&event] {
            return match self.enrols.get(&event).and_then(|slot| state.get(slot)) {
                Some(s) if s.is_in => match s.enrolled {
                    Some(_) => Err(PeersClass::AlreadyEnrolled),
                    None => Ok(()),
                },
                _ => Err(ErrorClass::NotAMember.into()),
            };
        }
        let author = self.author(event);
        let mine = self.slot_of.get(author).and_then(|slot| state.get(slot));
        match mine {
            Some(s) if s.is_in && s.enrolled.as_ref() == Some(author) => {}
            _ => return Err(ErrorClass::NotAnAdministrator.into()),
        }
        let targets = self.lowered(event);
        if !targets.is_empty()
            && !targets
                .iter()
                .any(|t| state.get(t).is_some_and(|s| s.is_in))
        {
            return Err(ErrorClass::NotAMember.into());
        }
        // Ranks: no slot lowers a slot of a higher rank.
        let mine = self.slot_of.get(author).map_or(0, |&slot| self.rank(slot));
        if targets.iter().any(|&t| self.rank(t) > mine) {
            return Err(PeersClass::HigherRank);
        }
        Ok(())
    }

    /// `x` attacks `e` when it lowers or disowns `e`'s author's
    /// administrator slot, or for an enrolment the one it enrols.
    fn attack(&self, attacker: EventId, event: EventId) -> Option<PeersClass> {
        let slot = self.author_slot(event)?;
        self.lowered(attacker)
            .contains(&slot)
            .then_some(PeersClass::RemovedConcurrently)
    }

    /// Two changes or disowns, by different authors, that lower each
    /// other's administrator slots: a mutual pair, of which only the
    /// outranking author's lowering counts under duel policy 0.
    fn mutual(&self, attacker: EventId, event: EventId) -> bool {
        !self.is_self_lowering(attacker)
            && self.attack(event, attacker).is_some()
            && self.author(attacker) != self.author(event)
    }

    /// In a mutual pair only the lowering by the author whose slot
    /// outranks the other's (the higher rank, then the more senior) counts;
    /// and neither side's attack on the enrolment its partner's author
    /// signed counts: neither undoes its partner's authority (roster.md,
    /// 3.5.2 What attacks what). Known at once: slot ranks and seniorities
    /// are fixed, and it reads no status.
    fn attack_counts(
        &self,
        attacker: EventId,
        event: EventId,
        view: &View<'_, Self>,
    ) -> Option<bool> {
        if self.mutual(attacker, event) {
            let outranks = self.authority_key(self.author_slot(attacker))
                < self.authority_key(self.author_slot(event));
            return Some(outranks);
        }
        let spares_enrolment = matches!(self.bodies[&event], StorageBody::Enrol { .. })
            && view.contested().iter().any(|&partner| {
                self.author(partner) == self.author(event)
                    && self.before(event, partner)
                    && self.mutual(partner, attacker)
            });
        Some(!spares_enrolment)
    }

    /// `(255 - its author's administrator slot's rank, that slot's
    /// seniority, its height, its ID)`; an enrolment's author's
    /// administrator slot is the one it enrols.
    fn pick_key(&self, event: EventId, _: &View<'_, Self>) -> Self::PickKey {
        let (rank, seniority) = self.authority_key(self.author_slot(event));
        (rank, seniority, self.height(event), event)
    }
}
