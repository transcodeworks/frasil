//! One hosted space at the peer: its log, its entries, what it indexes, and
//! the peer's procedures on it (peers.md, "Storing an event" to
//! "Collection").
//!
//! A [`Space`] is the space's journal replayed (crate `records`): every
//! change to it, live or in a replay, goes through [`Space::apply`], so the
//! state a peer rebuilds at a start, or after it removes what it reclaimed
//! or collected, is the state it had. Its decoded state is kept as a
//! [`Snapshot`], from which it opens without decoding or placing any event,
//! and from which its whole journal can be read again.
//!
//! The skeleton is resolved from the last skeleton cut in effect at the
//! peer ([`resolve`]; peers.md, "Skeleton cuts"). Once a cut has been in
//! effect for `cut_retention`, a sweep truncates the history before its
//! checkpoint (peers.md, "Truncation"): it deletes what
//! [`PeerCuts::truncation_plan`] lets it, keeps a stub of each deleted
//! event for its own placement, and records the truncation
//! ([`Op::Truncated`]) with the releases and restores of the checkpoint's
//! past it kept, from which cut the skeleton then starts and which it
//! counts in that past when it judges what is released.

use crate::config::Settings;
use crate::records::{Held, KeptUnit, ObjectRecord, Op, Snapshot};
use frasil_base::ErrorClass;
use frasil_base::time::{Reading, lower};
use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_events::{Event, EventId, ForkPoints, Log, Placement, kind};
use frasil_keys::body::VisiblePart;
use frasil_peers::PeersClass;
use frasil_peers::body::{Restored, StorageBody, StorageType, check_size};
use frasil_peers::cut::{self as cuts, PeerCuts, RequestState, TruncationPlan};
use frasil_peers::decisions::{self, Collection, Execution, Reclamation};
use frasil_peers::entries::{Connection, Entries, Present, Refusal, Rights, Source};
use frasil_peers::proof::Purpose;
use frasil_peers::retention::{Limits, Listings, Named, Retain, UnitView};
use frasil_peers::skeleton::{self, Skeleton, SkeletonParts, refused_by_peer};
use frasil_units::stream::StreamId;
use frasil_units::{Compacts, Unit};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
thread_local! {
    static DECODED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many events this thread decoded to open or rebuild a space.
#[cfg(test)]
pub(crate) fn decoded() -> u64 {
    DECODED.with(std::cell::Cell::get)
}

/// Decodes an event of a journal record.
fn decode_record(op: &Op) -> Option<Event> {
    match op {
        Op::Event { signed, .. } => {
            #[cfg(test)]
            DECODED.with(|count| count.set(count.get() + 1));
            frasil_events::decode(signed).ok()
        }
        _ => None,
    }
}

/// A locator: an object ID, then the SHA-256 of the stored object.
pub(crate) type Locator = [u8; 64];

/// What a store did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    /// Stored: acknowledged by its ID. With the IDs of every event it
    /// placed, itself and the pending events it released, in order.
    Placed(Vec<EventId>),
    /// Held pending on a parent, or a change no space event names yet.
    Pending,
    /// A second event at one author and `seq`, stored as fork evidence and
    /// answered `conflict`, never acknowledged. With the IDs it placed.
    Conflict(Vec<EventId>),
    /// An identical retry: acknowledged again if it is stored.
    Retry {
        /// Whether to acknowledge it.
        acknowledge: bool,
    },
}

/// What the peer's checks of a skeleton event found, for one it stores
/// ([`Space::check_skeleton`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SkeletonCheck {
    /// The pseudonym an enrolment enrols, by device ID: one the checks
    /// accept, or a late one.
    pub enrols: Option<DeviceId>,
    /// Whether the event is late at the peer (peers.md, "Skeleton cuts",
    /// late skeleton events): stored, with no effect.
    pub late: bool,
}

/// A refusal of a store, by its reason: a class's or a refusal code's
/// (peers.md, "Refusal codes").
pub(crate) fn reason(refusal: Refusal) -> String {
    use frasil_base::errors::Class;
    match refusal {
        Refusal::Class(class) => class.code().map_or_else(
            || class.wire_name().to_owned(),
            |code| code.name().to_owned(),
        ),
        Refusal::Code(code) => code.name().to_owned(),
        Refusal::PurposeViolation => "purpose_violation".to_owned(),
    }
}

/// A class's refusal.
pub(crate) fn refusal(class: impl Into<PeersClass>) -> Refusal {
    Refusal::Class(class.into())
}

/// A refusal code's refusal.
pub(crate) fn code(code: frasil_peers::Code) -> Refusal {
    Refusal::Code(code)
}

/// What a sweep decided and did not yet do: the changes that remove
/// events, which the caller makes at rest before it rebuilds the space.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Removal {
    /// Events whose journal records go.
    pub events: BTreeSet<EventId>,
    /// Stubs the peer keeps for its own placement of removed units.
    pub stubs: Vec<frasil_events::Stub>,
    /// Locators whose pieces and index go.
    pub objects: BTreeSet<Locator>,
    /// Journal records to add.
    pub ops: Vec<Op>,
    /// The space's erasure: its erasure event's signed bytes.
    pub erase_space: Option<Vec<u8>>,
}

impl Removal {
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
            && self.stubs.is_empty()
            && self.objects.is_empty()
            && self.ops.is_empty()
            && self.erase_space.is_none()
    }
}

/// A unit's index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnitIndex {
    pub stream: StreamId,
    pub objects: Vec<Locator>,
    pub compacts: Option<Compacts>,
    pub supersedes: Vec<frasil_adapter::Supersession>,
}

/// A space's skeleton as last resolved (peers.md, 3.12 The skeleton's
/// resolution), kept between uses while no event it reads changes: it is
/// forgotten when a storage or space event is placed, when evidence of a
/// fork arrives, and when a stub is added, and resolved again, its
/// ML-DSA-65 signatures verified again, at its next use. Units placed
/// meanwhile change nothing it reads.
#[derive(Default)]
pub(crate) struct SkeletonCache {
    held: std::sync::Mutex<Resolved>,
    tallies: std::sync::Arc<cuts::CutTallies>,
}

#[derive(Default, Clone)]
struct Resolved {
    parts: Option<SkeletonParts>,
    /// Each pseudonym's Ed25519 key, by device ID: the `ed` of its root's,
    /// accepted enrolment's or late enrolment's envelope.
    eds: BTreeMap<DeviceId, IdentityKey>,
    /// The skeleton cuts in effect at the peer, oldest first: the skeleton
    /// starts from the last.
    chain: Vec<EventId>,
    /// The skeleton events late at the peer under the last cut in effect
    /// (peers.md, "Skeleton cuts", late skeleton events).
    late: BTreeSet<EventId>,
    /// The streams released at the peer, each with the maximal releases
    /// that make it released (peers.md, "Release and restore"), once read.
    released: Option<BTreeMap<StreamId, Vec<EventId>>>,
    /// Each skeleton cut the peer holds, with its checkpoint: the space
    /// event that names it, cites it and has every other parent in its past
    /// (peers.md, "Skeleton cuts", step 3); none for a cut no such event
    /// names, held `Unnamed`.
    checkpoints: BTreeMap<EventId, Option<EventId>>,
    /// How many times it was resolved.
    builds: u64,
}

/// What a peer that truncated keeps of the cut it truncated under: the cut,
/// and the releases and restores of its checkpoint's past it kept, which it
/// counts in that past (peers.md, "Truncation").
pub(crate) type Kept<'s> = Option<(EventId, &'s BTreeSet<EventId>)>;

impl Clone for SkeletonCache {
    fn clone(&self) -> Self {
        Self {
            held: std::sync::Mutex::new(crate::state::lock(&self.held).clone()),
            tallies: std::sync::Arc::new(self.tallies.as_ref().clone()),
        }
    }
}

impl core::fmt::Debug for SkeletonCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SkeletonCache").finish_non_exhaustive()
    }
}

impl SkeletonCache {
    /// The skeleton of `log`, the space's log, at a peer that truncated
    /// under `kept`, if it did: as last resolved, or resolved now and kept.
    fn get<'a>(&self, log: &'a Log, kept: Kept<'_>) -> Skeleton<'a> {
        let mut held = crate::state::lock(&self.held);
        if let Some(parts) = &held.parts {
            return Skeleton::from_parts(log, parts.clone(), std::iter::empty());
        }
        let cuts = peer_cuts(log, kept, None).with_tallies(self.tallies.clone());
        let (resolved, chain) = (cuts.skeleton(), cuts.chain());
        held.checkpoints = cuts
            .cuts()
            .map(|(cut, _)| (cut, cuts.checkpoint_of(cut)))
            .collect();
        held.eds = resolved
            .pseudonyms()
            .map(|(pseudonym, _)| pseudonym)
            .chain(resolved.late_pseudonyms())
            .filter_map(|pseudonym| {
                resolved
                    .pseudonym_keys(pseudonym)
                    .map(|keys| (*pseudonym, keys.ed))
            })
            .collect();
        held.late = resolved.late_events().clone();
        held.chain = chain;
        held.parts = Some(resolved.clone().into_parts());
        held.builds += 1;
        resolved
    }

    /// A pseudonym's Ed25519 key, by device ID.
    fn ed(&self, log: &Log, kept: Kept<'_>, pseudonym: &DeviceId) -> Option<IdentityKey> {
        let resolved = crate::state::lock(&self.held).parts.is_some();
        if !resolved {
            drop(self.get(log, kept));
        }
        crate::state::lock(&self.held).eds.get(pseudonym).copied()
    }

    /// The skeleton cuts in effect at the peer, oldest first.
    fn chain(&self, log: &Log, kept: Kept<'_>) -> Vec<EventId> {
        let resolved = crate::state::lock(&self.held).parts.is_some();
        if !resolved {
            drop(self.get(log, kept));
        }
        crate::state::lock(&self.held).chain.clone()
    }

    /// Whether `id` is a skeleton cut the peer holds, and if so its
    /// checkpoint, if it has one.
    fn checkpoint_of(&self, log: &Log, kept: Kept<'_>, id: EventId) -> Option<Option<EventId>> {
        let resolved = crate::state::lock(&self.held).parts.is_some();
        if !resolved {
            drop(self.get(log, kept));
        }
        crate::state::lock(&self.held).checkpoints.get(&id).copied()
    }

    /// The skeleton events late at the peer under the last cut in effect.
    fn late(&self, log: &Log, kept: Kept<'_>) -> BTreeSet<EventId> {
        let resolved = crate::state::lock(&self.held).parts.is_some();
        if !resolved {
            drop(self.get(log, kept));
        }
        crate::state::lock(&self.held).late.clone()
    }

    /// The streams released at the peer, with the maximal releases that make
    /// each released (peers.md, "Release and restore"): read from the cuts
    /// in effect, a release or restore late under any of them counting for
    /// nothing; at a peer that truncated, from the maximal requests of the
    /// kept cut's past, journaled when it truncated, each before every
    /// event after the kept checkpoint, and among which it reads no order.
    fn released(
        &self,
        log: &Log,
        kept: Kept<'_>,
        requests: &BTreeMap<EventId, StorageBody>,
    ) -> BTreeMap<StreamId, Vec<EventId>> {
        if let Some(released) = &crate::state::lock(&self.held).released {
            return released.clone();
        }
        let streams: BTreeSet<StreamId> =
            requests.values().filter_map(StorageBody::stream).collect();
        let released: BTreeMap<StreamId, Vec<EventId>> = if streams.is_empty() {
            BTreeMap::new()
        } else {
            let cuts = peer_cuts(log, kept, None).with_tallies(self.tallies.clone());
            streams
                .into_iter()
                .filter_map(|stream| {
                    let maximal =
                        cuts.released(requests.iter().map(|(id, body)| (*id, body)), &stream)?;
                    Some((stream, maximal))
                })
                .collect()
        };
        crate::state::lock(&self.held).released = Some(released.clone());
        released
    }

    /// Forgets the resolution: an event it reads changed.
    fn forget(&mut self) {
        let held = self
            .held
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.parts = None;
        held.eds.clear();
        held.chain.clear();
        held.late.clear();
        held.released = None;
        held.checkpoints.clear();
    }

    /// How many times the skeleton was resolved.
    #[cfg(test)]
    pub(crate) fn builds(&self) -> u64 {
        crate::state::lock(&self.held).builds
    }
}

/// The cuts of `view`, the whole log when none, at a peer that truncated
/// under `kept`, if it did, counting in that cut's checkpoint's past the
/// requests it kept there. The peer keeps whole every checkpoint whose
/// envelope it keeps, so the log gives every envelope it holds.
fn peer_cuts<'a>(log: &'a Log, kept: Kept<'_>, view: Option<BTreeSet<EventId>>) -> PeerCuts<'a> {
    match kept {
        Some((cut, past)) => {
            let held = view.unwrap_or_else(|| log.canonical().into_iter().collect());
            PeerCuts::truncated(log, log, held, cut).with_kept_past(past.iter().copied())
        }
        None => PeerCuts::new(log, view.as_ref()),
    }
}

/// The most bytes a checkpoint's record object takes stored: a record of
/// at most 256 MiB (roster.md, "The checkpoint record"), sealed in chunks
/// (units.md, "Objects"), behind its header's length and its header, an
/// object ID, a self reference and a size, which take under 256 bytes. A
/// cut keeps the object its `record` names only within it.
pub(crate) fn max_record_object() -> u64 {
    let size = frasil_units::record::MAX_RECORD_BYTES;
    let chunks = frasil_units::objects::chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64);
    let sealing =
        (frasil_units::limits::SEALED_CHUNK_BYTES - frasil_units::limits::CHUNK_BYTES) as u64;
    4 + 256 + size + chunks * sealing
}

/// The later of two readings of the peer's timeline.
fn later(a: Reading, b: Reading) -> Reading {
    if b.timeline > a.timeline { b } else { a }
}

/// A space the peer hosts.
#[derive(Debug, Clone)]
pub(crate) struct Space {
    pub id: EventId,
    pub log: Log,
    pub entries: Entries,
    /// The peer's first sight of every event it holds, stored or pending.
    pub sights: BTreeMap<EventId, Reading>,
    /// Each held event's journal index.
    pub journal_of: BTreeMap<EventId, u64>,
    /// The next journal index.
    pub next_index: u64,
    /// The upload key of the entry each event was stored under.
    pub stored_under: BTreeMap<EventId, [u8; 32]>,
    /// Units: their stream, objects and compaction declaration.
    pub units: BTreeMap<EventId, UnitIndex>,
    /// Each stream's units.
    pub streams: BTreeMap<StreamId, BTreeSet<EventId>>,
    /// Stubs the peer holds for events it does not hold, with the snapshot
    /// unit that carries each, or none for the peer's own.
    pub stubs: BTreeMap<EventId, Option<EventId>>,
    /// Release and restore requests, by ID.
    pub writer_requests: BTreeMap<EventId, StorageBody>,
    /// Changes (storage type 1), cuts (type 7) and the twins space events
    /// name.
    pub changes: BTreeSet<EventId>,
    /// Cuts whose body holds a reserved key, kept and held as
    /// `ExtensionRequired` (peers.md, "Reserved cut keys"); found again from
    /// the log when the space is restored.
    pub held_cuts: BTreeSet<EventId>,
    pub named: BTreeSet<EventId>,
    /// Each credentials request's first sight in the entries' sequence.
    pub request_sights: BTreeMap<EventId, u64>,
    /// Erasures and credentials requests.
    pub requests: BTreeSet<EventId>,
    /// Requests carried out.
    pub executed: BTreeSet<EventId>,
    /// Snapshot units whose cover the peer checked and collected.
    pub collected: BTreeSet<EventId>,
    /// Second events at one author and `seq`, never acknowledged.
    pub conflicts: BTreeSet<EventId>,
    /// The fork points among the events held.
    pub forks: ForkPoints,
    /// The last judgement of each request.
    pub outcomes: BTreeMap<EventId, Execution>,
    /// The object index.
    pub objects: BTreeMap<Locator, ObjectRecord>,
    /// Units covered by a snapshot unit no restore names.
    pub covered: BTreeSet<EventId>,
    /// `since` of each snapshot unit's own listings (ext-file-versions.md,
    /// 3.6 Listings at a peer).
    pub listing_since: BTreeMap<EventId, BTreeMap<Locator, Reading>>,
    /// Usage, in bytes (peers.md, "Quotas and rates"): its events and
    /// objects. [`Self::used`] adds its invite drops.
    pub usage: u64,
    /// ext-invite-links.md: the invite drops the peer holds for the space,
    /// and their bytes, which count in its usage while it keeps them.
    pub drops: u64,
    /// The bytes of those drops.
    pub drop_bytes: u64,
    /// The events an import stored (peers.md, "Hosting a space").
    pub imported: BTreeSet<EventId>,
    /// Whether ext-file-versions is on: listings' `since` is fixed as
    /// snapshot units arrive, and sweeps keep and remove old versions.
    pub file_versions: bool,
    /// The journal records that are no event's, by index: with the held
    /// events, the whole journal.
    pub ops: BTreeMap<u64, Op>,
    /// The skeleton as last resolved.
    pub skeleton: SkeletonCache,
    /// The last truncation (peers.md, "Truncation"): the cut the peer
    /// truncated under, from which its skeleton starts, and the cut's
    /// checkpoint.
    pub truncated: Option<(EventId, EventId)>,
    /// The releases and restores of that checkpoint's past the peer kept,
    /// which it counts in that past.
    pub kept_requests: BTreeSet<EventId>,
    /// The record objects the skeleton cuts it holds name (peers.md,
    /// "Skeleton cuts", key 5 `record`), by locator.
    pub records: BTreeSet<Locator>,
}

/// What a space opens under: the operator's `credential_cap` (peers.md,
/// "Limits"), and whether ext-file-versions is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rules {
    /// `credential_cap`.
    pub(crate) cap: usize,
    /// Whether ext-file-versions is on.
    pub(crate) file_versions: bool,
}

impl Rules {
    /// The rules of the operator's settings.
    pub(crate) fn of(settings: &Settings) -> Self {
        Self {
            cap: settings.credential_cap,
            file_versions: settings.extensions.file_versions,
        }
    }
}

impl Space {
    /// A space created by its genesis (peers.md, "Hosting a space").
    pub(crate) fn create(genesis: Event, rules: Rules) -> Result<Self, Refusal> {
        let id = genesis.id();
        let log = Log::new(genesis).map_err(|class| refusal(PeersClass::from(class)))?;
        Ok(Self {
            id,
            log,
            entries: Entries::new(rules.cap),
            sights: BTreeMap::new(),
            journal_of: BTreeMap::new(),
            next_index: 0,
            stored_under: BTreeMap::new(),
            units: BTreeMap::new(),
            streams: BTreeMap::new(),
            stubs: BTreeMap::new(),
            writer_requests: BTreeMap::new(),
            changes: BTreeSet::new(),
            held_cuts: BTreeSet::new(),
            named: BTreeSet::new(),
            request_sights: BTreeMap::new(),
            requests: BTreeSet::new(),
            executed: BTreeSet::new(),
            collected: BTreeSet::new(),
            conflicts: BTreeSet::new(),
            forks: ForkPoints::default(),
            outcomes: BTreeMap::new(),
            objects: BTreeMap::new(),
            covered: BTreeSet::new(),
            listing_since: BTreeMap::new(),
            usage: 0,
            drops: 0,
            drop_bytes: 0,
            imported: BTreeSet::new(),
            file_versions: rules.file_versions,
            ops: BTreeMap::new(),
            skeleton: SkeletonCache::default(),
            truncated: None,
            kept_requests: BTreeSet::new(),
            records: BTreeSet::new(),
        })
    }

    /// A space from its journal and object index, replayed in order: each
    /// event decoded from its record.
    pub(crate) fn replay(
        ops: Vec<(u64, Op)>,
        objects: Vec<(Locator, ObjectRecord)>,
        rules: Rules,
    ) -> Option<Self> {
        let decoded = ops
            .into_iter()
            .map(|(index, op)| {
                let event = decode_record(&op);
                (index, op, event)
            })
            .collect();
        Self::replay_decoded(decoded, objects, rules)
    }

    /// A space from its journal, each event's record with the event
    /// decoded already, and its object index, replayed in order.
    ///
    /// Stubs come first: the peer's own, and every stored snapshot unit's,
    /// so that an event whose parent was collected or reclaimed places as
    /// it did when it was stored.
    pub(crate) fn replay_decoded(
        mut decoded: Vec<(u64, Op, Option<Event>)>,
        objects: Vec<(Locator, ObjectRecord)>,
        rules: Rules,
    ) -> Option<Self> {
        let genesis_at = decoded
            .iter()
            .position(|(_, _, event)| event.as_ref().is_some_and(Event::is_genesis))?;
        let (index, op, genesis) = decoded.remove(genesis_at);
        let genesis = genesis?;
        let mut space = Self::create(genesis, rules).ok()?;
        space.add_stubs_first(&decoded);
        space.apply_genesis_record(index, &op);
        for (index, op, event) in decoded {
            space.apply(index, &op, event);
        }
        space.objects = objects.into_iter().collect();
        space.refresh();
        Some(space)
    }

    /// What a replay adds before any event: the stubs of the records to
    /// apply, and the events an import stored.
    fn add_stubs_first(&mut self, decoded: &[(u64, Op, Option<Event>)]) {
        self.skeleton.tallies.clear();
        for (_, op, event) in decoded {
            match (op, event) {
                (Op::Imported { event }, _) => {
                    self.imported.insert(*event);
                }
                (Op::Stub(stub), _) => {
                    self.log.add_stub(*stub);
                    self.stubs.insert(stub.id, None);
                }
                (Op::Event { .. }, Some(event)) if event.kind() == kind::UNIT => {
                    if let Ok(unit) = Unit::from_event(event.clone())
                        && let Some(compacts) = &unit.body.compacts
                    {
                        for stub in &compacts.stubs {
                            self.log.add_stub(stub.event_stub());
                            self.stubs.entry(stub.id).or_insert(Some(event.id()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Applies the journal records after a snapshot, in order, as a replay
    /// does: their stubs first.
    pub(crate) fn apply_tail(&mut self, tail: Vec<(u64, Op)>) {
        let decoded: Vec<(u64, Op, Option<Event>)> = tail
            .into_iter()
            .map(|(index, op)| {
                let event = decode_record(&op);
                (index, op, event)
            })
            .collect();
        self.add_stubs_first(&decoded);
        for (index, op, event) in decoded {
            self.apply(index, &op, event);
        }
        self.refresh();
    }

    /// The space's whole journal, read from its state: each held event's
    /// record with the event, and every other record, by index.
    pub(crate) fn journal(&self) -> Vec<(u64, Op, Option<Event>)> {
        let pending: BTreeMap<EventId, &Event> = self
            .log
            .pending()
            .map(|event| (event.id(), event))
            .collect();
        let mut out: Vec<(u64, Op, Option<Event>)> = self
            .journal_of
            .iter()
            .filter_map(|(id, &index)| {
                let event = self.log.event(*id).or_else(|| pending.get(id).copied())?;
                let op = Op::Event {
                    signed: event.signed(),
                    sight: *self.sights.get(id)?,
                    entry: self.stored_under.get(id).copied(),
                };
                Some((index, op, Some(event.clone())))
            })
            .chain(
                self.ops
                    .iter()
                    .map(|(index, op)| (*index, op.clone(), None)),
            )
            .collect();
        out.sort_by_key(|(index, _, _)| *index);
        out
    }

    /// The space's decoded state as of its next journal index.
    pub(crate) fn to_snapshot(&self) -> Snapshot {
        let ids = |set: &BTreeSet<EventId>| set.iter().copied().collect::<Vec<_>>();
        Snapshot {
            through: self.next_index,
            log: self.log.encode_state(),
            entries: self.entries.encode_state(),
            forks: self.forks.encode(),
            held: self
                .journal_of
                .iter()
                .filter_map(|(id, &index)| {
                    Some(Held {
                        id: *id,
                        index,
                        sight: *self.sights.get(id)?,
                        entry: self.stored_under.get(id).copied(),
                    })
                })
                .collect(),
            ops: self
                .ops
                .iter()
                .map(|(index, op)| (*index, op.clone()))
                .collect(),
            units: self
                .units
                .iter()
                .map(|(id, unit)| KeptUnit {
                    id: *id,
                    stream: unit.stream,
                    objects: unit.objects.clone(),
                    compacts: unit.compacts.as_ref().map(Compacts::encode),
                    supersedes: unit.supersedes.clone(),
                    since: self.listing_since.get(id).map_or_else(Vec::new, |since| {
                        since.iter().map(|(l, r)| (*l, *r)).collect()
                    }),
                })
                .collect(),
            writer_requests: self
                .writer_requests
                .iter()
                .map(|(id, body)| (*id, body.encode()))
                .collect(),
            changes: ids(&self.changes),
            named: ids(&self.named),
            requests: ids(&self.requests),
            executed: ids(&self.executed),
            collected: ids(&self.collected),
            conflicts: ids(&self.conflicts),
            request_sights: self
                .request_sights
                .iter()
                .map(|(id, n)| (*id, *n))
                .collect(),
            stubs: self
                .stubs
                .iter()
                .map(|(id, carrier)| (*id, *carrier))
                .collect(),
            imported: ids(&self.imported),
        }
    }

    /// A space from its decoded state and object index, with no event
    /// decoded or placed; `None` if a part does not read. Under another
    /// `credential_cap` than the snapshot's, the space is replayed from the
    /// journal the snapshot holds, with its events as they are.
    pub(crate) fn from_snapshot(
        snapshot: &Snapshot,
        objects: Vec<(Locator, ObjectRecord)>,
        rules: Rules,
    ) -> Option<Self> {
        let log = Log::decode_state(&snapshot.log)?;
        let entries = Entries::decode_state(&snapshot.entries)?;
        let id = log.id();
        let mut space = Self::create(log.genesis().clone(), rules).ok()?;
        space.log = log;
        space.entries = entries;
        space.forks = ForkPoints::decode(&snapshot.forks)?;
        let mut next = snapshot.through;
        for held in &snapshot.held {
            if !space.log.contains(held.id) && !space.is_pending(held.id) {
                return None;
            }
            space.sights.insert(held.id, held.sight);
            space.journal_of.insert(held.id, held.index);
            if let Some(entry) = held.entry {
                space.stored_under.insert(held.id, entry);
            }
            next = next.max(held.index + 1);
        }
        for (index, op) in &snapshot.ops {
            space.ops.insert(*index, op.clone());
            if let Op::Truncated {
                cut,
                checkpoint,
                requests,
            } = op
            {
                space.truncated = Some((*cut, *checkpoint));
                space.kept_requests = requests.iter().copied().collect();
            }
            next = next.max(index + 1);
        }
        for unit in &snapshot.units {
            let compacts = match &unit.compacts {
                Some(bytes) => {
                    let value = frasil_base::cbor::decode(bytes).ok()?;
                    Some(Compacts::read(&value, &unit.objects).ok()?)
                }
                None => None,
            };
            space
                .streams
                .entry(unit.stream)
                .or_default()
                .insert(unit.id);
            space.units.insert(
                unit.id,
                UnitIndex {
                    stream: unit.stream,
                    objects: unit.objects.clone(),
                    compacts,
                    supersedes: unit.supersedes.clone(),
                },
            );
            if !unit.since.is_empty() {
                space
                    .listing_since
                    .insert(unit.id, unit.since.iter().copied().collect());
            }
        }
        for (request, body) in &snapshot.writer_requests {
            space
                .writer_requests
                .insert(*request, StorageBody::read(body).ok()?);
        }
        let set = |ids: &[EventId]| ids.iter().copied().collect::<BTreeSet<_>>();
        space.changes = set(&snapshot.changes);
        space.held_cuts = space
            .log
            .events()
            .filter(|event| event.kind() == kind::STORAGE && holds_reserved_key(event))
            .map(|event| event.id())
            .collect();
        space.named = set(&snapshot.named);
        space.requests = set(&snapshot.requests);
        space.executed = set(&snapshot.executed);
        space.collected = set(&snapshot.collected);
        space.conflicts = set(&snapshot.conflicts);
        space.request_sights = snapshot.request_sights.iter().copied().collect();
        space.stubs = snapshot.stubs.iter().copied().collect();
        space.imported = set(&snapshot.imported);
        space.next_index = next;
        space.id = id;
        if space.entries.cap() != rules.cap {
            let journal = space.journal();
            return Self::replay_decoded(journal, objects, rules);
        }
        space.objects = objects.into_iter().collect();
        space.refresh();
        Some(space)
    }

    /// Applies the genesis's journal record: the genesis is placed when the
    /// space is made, and its record adds its sight and its entry.
    pub(crate) fn apply_genesis_record(&mut self, index: u64, op: &Op) {
        if let Op::Event { sight, entry, .. } = op {
            let genesis = self.log.id();
            self.note(genesis, index, *sight, *entry);
            self.after_place(genesis);
        }
    }

    fn note(&mut self, id: EventId, index: u64, sight: Reading, entry: Option<[u8; 32]>) {
        self.sights.insert(id, sight);
        self.journal_of.insert(id, index);
        self.next_index = self.next_index.max(index + 1);
        if let Some(entry) = entry {
            self.stored_under.insert(id, entry);
        }
    }

    /// Applies one journal record: in a replay, and live once the record
    /// is written.
    pub(crate) fn apply(&mut self, index: u64, op: &Op, event: Option<Event>) -> Vec<EventId> {
        self.next_index = self.next_index.max(index + 1);
        if !matches!(op, Op::Event { .. }) {
            self.ops.insert(index, op.clone());
        }
        match op {
            Op::Event { sight, entry, .. } => {
                let Some(event) = event else {
                    return Vec::new();
                };
                let id = event.id();
                self.note(id, index, *sight, *entry);
                self.place(event)
            }
            Op::Merge { statement } => {
                let _ = self.entries.merge(&self.log, &self.id, statement);
                Vec::new()
            }
            Op::Proved {
                credential,
                public,
                binding,
                proof,
                importing,
            } => {
                let present = Present {
                    credential: (*credential).into(),
                    space: self.id,
                    public: *public,
                    proof,
                };
                let connection = Connection {
                    binding: *binding,
                    purpose: Purpose::SpaceTraffic,
                    importing: *importing,
                };
                // Only credentials 1 and 2 are kept, so no pseudonym's key.
                let _ = self.entries.present(&present, &connection, None);
                Vec::new()
            }
            Op::Register { key } => {
                let _ = self.entries.register(key, Rights::STORE_AND_RELEASE);
                Vec::new()
            }
            Op::Executed { request } => {
                self.carry_out(*request);
                Vec::new()
            }
            Op::Stub(stub) => {
                self.stubs.entry(stub.id).or_insert(None);
                self.skeleton.tallies.clear();
                self.skeleton.forget();
                self.log.add_stub(*stub)
            }
            Op::Collected { snapshot } => {
                self.collected.insert(*snapshot);
                Vec::new()
            }
            Op::Since { snapshot, since } => {
                // A record left behind by a snapshot unit since removed
                // names no listing.
                if self.units.contains_key(snapshot) {
                    self.listing_since
                        .insert(*snapshot, since.iter().copied().collect());
                }
                Vec::new()
            }
            Op::Imported { event } => {
                self.imported.insert(*event);
                Vec::new()
            }
            Op::Truncated {
                cut,
                checkpoint,
                requests,
            } => {
                self.skeleton.tallies.clear();
                self.truncated = Some((*cut, *checkpoint));
                self.kept_requests = requests.iter().copied().collect();
                self.skeleton.forget();
                Vec::new()
            }
        }
    }

    /// Places an event; returns the IDs it placed, itself and the pending
    /// events it released. Evidence of a fork (events.md, "Chains and
    /// evidence of a fork") retires the forked author's entries (peers.md,
    /// "Learning a rotation's credentials").
    fn place(&mut self, event: Event) -> Vec<EventId> {
        let id = event.id();
        let duplicate = self.is_duplicate(&event);
        if self.log.contains(id) {
            self.skeleton.tallies.clear();
        }
        let placed = match self.log.place(event) {
            Ok(Placement::Placed(ids)) => ids,
            _ => Vec::new(),
        };
        if duplicate {
            self.conflicts.insert(id);
        }
        let mut evidence = duplicate;
        for &placed_id in &placed {
            let Some(placed_event) = self.log.event(placed_id).cloned() else {
                continue;
            };
            if placed_id != id && self.is_duplicate(&placed_event) {
                self.conflicts.insert(placed_id);
                evidence = true;
            }
            evidence |= self.breaks_chain(&placed_event);
        }
        if evidence {
            let order = self.log.canonical();
            self.forks = skeleton::fork_points(&self.log, &order, |_| true);
        }
        // The skeleton reads storage and space events, and fork evidence.
        if evidence
            || placed.iter().any(|&placed_id| {
                self.log
                    .event(placed_id)
                    .is_none_or(|placed| placed.kind() != kind::UNIT)
            })
        {
            self.skeleton.forget();
        }
        for &placed_id in &placed {
            self.after_place(placed_id);
        }
        if evidence {
            self.entries.fork(&self.log, &self.forks);
        }
        placed
    }

    /// Whether another event at the author's `seq` is held, placed or
    /// pending.
    fn is_duplicate(&self, event: &Event) -> bool {
        let id = event.id();
        self.log
            .chain(event.author())
            .into_iter()
            .any(|other| other != id && self.log.event(other).map(Event::seq) == Some(event.seq()))
            || self.log.pending().any(|other| {
                other.id() != id && other.author() == event.author() && other.seq() == event.seq()
            })
    }

    /// Whether an event's `prev` is not its author's event at `seq − 1`: a
    /// skip.
    fn breaks_chain(&self, event: &Event) -> bool {
        event
            .prev()
            .and_then(|prev| self.log.event(prev))
            .is_some_and(|prev| {
                prev.author() != event.author() || prev.seq().checked_add(1) != Some(event.seq())
            })
    }

    /// What an event's placement adds to the index and the entries.
    fn after_place(&mut self, id: EventId) {
        let Some(event) = self.log.event(id).cloned() else {
            return;
        };
        match event.kind() {
            kind::SPACE => {
                if let Some(twin) = skeleton::named_twin(&event) {
                    self.named.insert(twin);
                }
                let source = if self.imported.contains(&id) {
                    Source::Import
                } else {
                    Source::Rotation
                };
                let _ = self
                    .entries
                    .add_rotation(&self.log, id, source, &self.forks);
            }
            kind::STORAGE => {
                if holds_reserved_key(&event) {
                    self.held_cuts.insert(id);
                }
                if let Ok(body) = StorageBody::read(event.unverified_body()) {
                    match body.storage_type() {
                        // A skeleton cut is held unnamed as a change is
                        // (peers.md, "Skeleton cuts"); the skeleton is
                        // resolved from the last cut in effect.
                        StorageType::Change | StorageType::Cut => {
                            self.changes.insert(id);
                            if let StorageBody::Cut(cut) = &body {
                                self.records.insert(cut.record);
                            }
                        }
                        StorageType::Credentials => {
                            let seen = self.entries.first_sight();
                            self.request_sights.insert(id, seen);
                            self.requests.insert(id);
                        }
                        StorageType::Erase => {
                            self.requests.insert(id);
                        }
                        StorageType::Release | StorageType::Restore => {
                            self.writer_requests.insert(id, body);
                        }
                        _ => {}
                    }
                }
            }
            kind::UNIT => {
                if let Ok(unit) = Unit::from_event(event) {
                    let body = unit.body;
                    self.streams.entry(body.stream).or_default().insert(id);
                    if let Some(compacts) = &body.compacts {
                        if !compacts.stubs.is_empty() {
                            self.skeleton.tallies.clear();
                        }
                        for stub in &compacts.stubs {
                            self.log.add_stub(stub.event_stub());
                            self.stubs.entry(stub.id).or_insert(Some(id));
                        }
                    }
                    for locator in &body.objects {
                        if let Some(record) = self.objects.get_mut(locator)
                            && record.complete
                        {
                            record.referenced = true;
                        }
                    }
                    if self.file_versions
                        && let Some(compacts) = body.compacts.as_ref()
                        && !body.supersedes.is_empty()
                    {
                        self.fix_since(id, body.stream, compacts, &body.supersedes);
                    }
                    self.units.insert(
                        id,
                        UnitIndex {
                            stream: body.stream,
                            objects: body.objects,
                            compacts: body.compacts,
                            supersedes: body.supersedes,
                        },
                    );
                }
            }
            _ => {}
        }
    }

    /// Carries out a credentials request's effect on the entries (peers.md,
    /// "Credentials requests"). An erasure names the whole space, which the
    /// peer then drops for a tombstone (peers.md, "Erasure").
    fn carry_out(&mut self, request: EventId) {
        self.executed.insert(request);
        let Some(event) = self.log.event(request).cloned() else {
            return;
        };
        if let Ok(StorageBody::Credentials { .. }) = StorageBody::read(event.unverified_body()) {
            let seen = self.request_sights.get(&request).copied();
            let _ = self.entries.execute_event(&self.log, &event, seen);
        }
    }

    // -- What the space holds and serves

    /// Whether an event is held pending.
    pub(crate) fn is_pending(&self, id: EventId) -> bool {
        self.log.pending().any(|event| event.id() == id)
    }

    /// Whether a change is held unnamed: no stored space event names it
    /// (peers.md, "What a peer checks before it stores a skeleton event",
    /// step 7). A late one runs no step but the first, and is stored as it
    /// comes (peers.md, "Skeleton cuts", late skeleton events). A skeleton
    /// cut is named only by its checkpoint, a space event that names it,
    /// cites it and has every other parent in its past (peers.md, "Skeleton
    /// cuts", step 3): one that only an event that does not cite it names is
    /// held unnamed as well, never served as stored and dropped after
    /// `orphan_grace`.
    pub(crate) fn unnamed(&self, id: EventId) -> bool {
        if !self.changes.contains(&id) {
            return false;
        }
        let kept = self.kept_with_past();
        match self.skeleton.checkpoint_of(&self.log, kept, id) {
            Some(checkpoint) => checkpoint.is_none(),
            None => !self.named.contains(&id) && !self.skeleton.late(&self.log, kept).contains(&id),
        }
    }

    /// The streams released at the peer (peers.md, "Release and restore").
    pub(crate) fn released_streams(&self) -> BTreeSet<StreamId> {
        self.released().into_keys().collect()
    }

    /// The streams released at the peer, each with the maximal releases that
    /// make it released.
    fn released(&self) -> BTreeMap<StreamId, Vec<EventId>> {
        self.skeleton
            .released(&self.log, self.kept_with_past(), &self.writer_requests)
    }

    /// Whether a stream is released.
    pub(crate) fn is_released(&self, stream: &StreamId) -> bool {
        self.released().contains_key(stream)
    }

    /// Whether the peer serves a placed event as stored: not an unnamed
    /// change, and not a unit of a released stream, unless an event outside
    /// the stream names it as a parent, which the peer keeps as an event
    /// alone (peers.md, "Release and restore").
    pub(crate) fn servable(&self, id: EventId, released: &BTreeSet<StreamId>) -> bool {
        self.log.contains(id)
            && !self.unnamed(id)
            && self.units.get(&id).is_none_or(|unit| {
                !released.contains(&unit.stream) || self.named_outside(id, unit.stream)
            })
    }

    /// Whether an event the peer holds outside `stream` names a unit of it
    /// as a parent.
    fn named_outside(&self, id: EventId, stream: StreamId) -> bool {
        self.log.events().any(|event| {
            event.parents().contains(&id)
                && self
                    .units
                    .get(&event.id())
                    .is_none_or(|unit| unit.stream != stream)
        })
    }

    /// Whether a released stream holds what a reclaim removes: a unit not
    /// kept as a parent, or an object only kept units still list.
    fn reclaim_due(&self, stream: &StreamId) -> bool {
        if !self.reclaimable(stream).is_empty() {
            return true;
        }
        let kept: BTreeSet<EventId> = self
            .streams
            .get(stream)
            .into_iter()
            .flatten()
            .copied()
            .collect();
        let mut removal = Removal::default();
        self.remove_objects(&kept, &mut removal);
        removal
            .objects
            .iter()
            .any(|locator| self.objects.contains_key(locator))
    }

    /// The units of a released stream that a reclaim removes: every one
    /// but those an event outside the stream names as a parent, which the
    /// peer keeps as events alone (peers.md, "Release and restore").
    fn reclaimable(&self, stream: &StreamId) -> BTreeSet<EventId> {
        self.streams
            .get(stream)
            .into_iter()
            .flatten()
            .copied()
            .filter(|&id| !self.named_outside(id, *stream))
            .collect()
    }

    // -- Storing an event, steps 4 to 7

    /// peers.md, "Storing an event", steps 4 to 7, after steps 1 to 3. The
    /// kind's shape (step 5) is checked before placement, since an event
    /// that fails it is never stored; the peer still holds an event pending
    /// on a parent (step 4) without answering for it.
    ///
    /// Returns the journal record to write, and what the store does, or the
    /// refusal. The caller writes the record and then applies it.
    pub(crate) fn admit(
        &self,
        event: &Event,
        signed: &[u8],
        rights: &Rights,
        settings: &Settings,
        now: Reading,
        entry: Option<[u8; 32]>,
    ) -> Result<Op, Refusal> {
        // 5. The kind's shape.
        match event.kind() {
            kind::SPACE => {
                VisiblePart::read(event.unverified_body(), event.author(), event.seq())
                    .map_err(|class| refusal(PeersClass::from(class)))?;
            }
            kind::STORAGE => {
                check_size(event.signed_len()).map_err(refusal)?;
                let body = match StorageBody::read(event.unverified_body()) {
                    Ok(body) => Some(body),
                    Err(class) if class.shared() == Some(ErrorClass::ExtensionRequired) => None,
                    Err(class) => return Err(refusal(class)),
                };
                if body.is_some_and(|body| body.storage_type().is_writer_request())
                    && !rights.release
                {
                    return Err(refusal(PeersClass::NotAuthorized));
                }
            }
            kind::UNIT => {
                let unit = Unit::from_event(event.clone()).map_err(|error| {
                    refusal(PeersClass::Shared(
                        error.shared().unwrap_or(ErrorClass::Malformed),
                    ))
                })?;
                let stream = unit.body.stream;
                if self.is_released(&stream) {
                    return Err(code(frasil_peers::Code::Released));
                }
                if !self.streams.contains_key(&stream)
                    && self.streams.len() as u64 >= settings.max_streams_per_space
                {
                    return Err(code(frasil_peers::Code::StreamLimit));
                }
            }
            _ => {}
        }
        // 6. Quota and pending_cap.
        if self.used().saturating_add(signed.len() as u64) > settings.space_quota {
            return Err(code(frasil_peers::Code::QuotaExceeded));
        }
        let missing = event
            .parents()
            .iter()
            .any(|&parent| self.log.height(parent).is_none());
        if missing && self.log.pending().count() >= settings.pending_cap {
            return Err(code(frasil_peers::Code::RateLimited));
        }
        Ok(Op::Event {
            signed: signed.to_vec(),
            sight: now,
            entry,
        })
    }

    /// The cut the peer truncated under last, if it did.
    pub(crate) fn kept(&self) -> Option<EventId> {
        self.truncated.map(|(cut, _)| cut)
    }

    /// The cut the peer truncated under last, with the requests of its
    /// checkpoint's past it kept.
    fn kept_with_past(&self) -> Kept<'_> {
        self.kept().map(|cut| (cut, &self.kept_requests))
    }

    /// The cuts the peer holds (peers.md, "Skeleton cuts").
    pub(crate) fn cuts(&self) -> PeerCuts<'_> {
        peer_cuts(&self.log, self.kept_with_past(), None)
            .with_tallies(self.skeleton.tallies.clone())
    }

    /// The record objects the skeleton cuts the peer holds name (peers.md,
    /// "Skeleton cuts", key 5 `record`), by locator.
    fn cut_records(&self) -> BTreeSet<Locator> {
        self.changes
            .iter()
            .filter_map(|&id| cuts::read_cut(self.log.event(id)?))
            .map(|cut| cut.record)
            .collect()
    }

    /// Whether a cut the peer holds names an object as its checkpoint's
    /// record object, which the peer keeps while it keeps the cut, when the
    /// object is within [`max_record_object`].
    pub(crate) fn record_named(&self, locator: &Locator) -> bool {
        self.records.contains(locator)
            && self.objects.get(locator).is_none_or(|record| {
                record
                    .total
                    .is_none_or(|total| total <= max_record_object())
            })
    }

    /// peers.md, "What a peer checks before it stores a skeleton event": a
    /// skeleton event that the peer's checks refuse is not stored. Run on
    /// the log with the event placed, before the peer commits it. Returns
    /// the pseudonym the event enrols, by device ID, for an enrolment the
    /// peer stores: one the checks accept, whatever the resolution decides
    /// of it, or a late one (peers.md, 3.7 Presenting a credential, and
    /// "Skeleton cuts", late skeleton events); and whether the event is late.
    /// The resolution can change as events arrive, and an enrolment refused
    /// would leave every event that cites it pending here for good.
    ///
    /// A skeleton event is refused only for what is wrong in it (section
    /// 3.11, "No refusal for standing"): one whose author the peer holds no
    /// root or enrolment for, or whose author's slot is out or not in the
    /// skeleton it resolves, is stored with no effect, its signature checked
    /// under the key of its author's root or enrolment wherever the peer
    /// holds one.
    ///
    /// The skeleton starts from the last cut in effect. A late skeleton
    /// event runs the first check alone and is stored, without effect, a late
    /// enrolment besides its own checks; a cut outside that world keeps its
    /// own checks, on its own past.
    pub(crate) fn check_skeleton(&self, event: &Event) -> Result<SkeletonCheck, Refusal> {
        if event.kind() != kind::STORAGE {
            return Ok(SkeletonCheck::default());
        }
        let mut trial = self.log.clone();
        let Ok(Placement::Placed(_)) = trial.place(event.clone()) else {
            return Ok(SkeletonCheck::default());
        };
        let id = event.id();
        let cuts = peer_cuts(&trial, self.kept_with_past(), None)
            .with_tallies(self.skeleton.tallies.clone());
        let skeleton = cuts.skeleton();
        let status = skeleton
            .status(id)
            .or_else(|| cuts::read_cut(event).is_some().then(|| cuts.validity(id)));
        match status {
            Some(skeleton::Status::Void { class, .. }) if refused_by_peer(class) => {
                Err(refusal(class))
            }
            Some(skeleton::Status::Void {
                class: PeersClass::NotAuthorized,
                ..
            }) => {
                cuts::check_held_key(&trial, event, |_| true).map_err(refusal)?;
                Ok(SkeletonCheck {
                    enrols: None,
                    late: false,
                })
            }
            Some(status) => {
                let enrols = matches!(skeleton.body_of(id), Some(StorageBody::Enrol { .. }));
                Ok(SkeletonCheck {
                    enrols: enrols.then_some(*event.author()),
                    late: status
                        == (skeleton::Status::Void {
                            class: PeersClass::Late,
                            by: None,
                        }),
                })
            }
            None => Ok(SkeletonCheck::default()),
        }
    }

    /// Whether a pseudonym, by device ID, is late at the peer: a late
    /// enrolment's, enrolled in no slot of the skeleton it resolves
    /// (peers.md, "Skeleton cuts", what a late enrolment opens). A
    /// connection that presents it may store only that pseudonym's late
    /// skeleton events, and is reported nothing.
    pub(crate) fn is_late_pseudonym(&self, pseudonym: &DeviceId) -> bool {
        let skeleton = self.skeleton();
        skeleton.slot_of(pseudonym).is_none()
            && (skeleton.late_pseudonyms().any(|p| p == pseudonym)
                || self.late_eraser_ed(pseudonym).is_some())
    }

    /// The keyless answer to a late erasure, including after truncation.
    pub(crate) fn erasure_late(
        &self,
        id: EventId,
    ) -> Option<frasil_transport::messages::ErasureLate> {
        let event = self.log.event(id)?;
        if !matches!(
            StorageBody::read(event.unverified_body()),
            Ok(StorageBody::Erase)
        ) || !self
            .skeleton
            .late(&self.log, self.kept_with_past())
            .contains(&id)
        {
            return None;
        }
        let cut = *self
            .skeleton
            .chain(&self.log, self.kept_with_past())
            .last()?;
        let checkpoint = self
            .skeleton
            .checkpoint_of(&self.log, self.kept_with_past(), cut)??;
        let cut = self.log.event(cut)?;
        let StorageBody::Cut(body) = StorageBody::read(cut.unverified_body()).ok()? else {
            return None;
        };
        // A kept root or enrolment identifies the slot even when it is no
        // longer listed in the cut's world.
        let slot = self.log.events().find_map(|enrolment| {
            if enrolment.author() != event.author() {
                return None;
            }
            match StorageBody::read(enrolment.unverified_body()).ok()? {
                StorageBody::Root { twin, .. } => {
                    Some(frasil_peers::body::SlotId::new(twin, 0, enrolment.id()))
                }
                StorageBody::Enrol { slot, .. } => Some(slot),
                _ => None,
            }
        })?;
        let standing = body
            .slots
            .iter()
            .find(|entry| entry.slot == slot)
            .map_or(2, |entry| {
                if entry
                    .pseudonym
                    .and_then(|id| self.log.event(id))
                    .is_some_and(|enrolment| enrolment.author() == event.author())
                {
                    0
                } else {
                    1
                }
            });
        Some(frasil_transport::messages::ErasureLate {
            space: self.id.0,
            erasure: id.0,
            cut: cut.signed(),
            checkpoint: checkpoint.0,
            standing,
        })
    }

    /// What a store of an event already held does: an identical retry. An
    /// event the peer deleted when it truncated, sent again, is acknowledged
    /// as an identical retry and not stored again, nor given a verdict
    /// (peers.md, "Truncation"): the peer held it durably, and it is in the
    /// kept cut's checkpoint's past, where nothing it would store decides
    /// anything. Truncation deletes no unit, so a stub of the peer's own
    /// that is no unit's is one of those.
    pub(crate) fn retry(&self, id: EventId) -> Option<Stored> {
        let truncated = self.truncated.is_some()
            && self.stubs.get(&id) == Some(&None)
            && self
                .log
                .stub(id)
                .is_some_and(|stub| stub.kind != kind::UNIT);
        if truncated {
            return Some(Stored::Retry { acknowledge: true });
        }
        if self.log.contains(id) {
            let released = self.released_streams();
            return Some(Stored::Retry {
                acknowledge: !self.conflicts.contains(&id) && self.servable(id, &released),
            });
        }
        self.is_pending(id)
            .then_some(Stored::Retry { acknowledge: false })
    }

    /// What a store did, once applied.
    pub(crate) fn outcome(&self, id: EventId, placed: Vec<EventId>) -> Stored {
        if self.conflicts.contains(&id) {
            return Stored::Conflict(placed);
        }
        if !self.log.contains(id) || self.unnamed(id) {
            return Stored::Pending;
        }
        Stored::Placed(placed)
    }

    // -- Usage

    /// Its usage with its invite drops (ext-invite-links.md): what the
    /// quota counts.
    pub(crate) fn used(&self) -> u64 {
        self.usage.saturating_add(self.drop_bytes)
    }

    /// Recomputes what depends on the whole space: covers and usage.
    pub(crate) fn refresh(&mut self) {
        self.records = self.cut_records();
        let released = self.released_streams();
        let cancelled = self.cancelled_snapshots();
        let mut covered = BTreeSet::new();
        for (&snapshot, unit) in &self.units {
            if cancelled.contains(&snapshot) {
                continue;
            }
            if let Some(compacts) = &unit.compacts {
                covered.extend(self.cover(unit.stream, compacts));
            }
        }
        self.covered = covered;
        let mut usage: u64 = 0;
        for event in self.log.events().chain(self.log.pending()) {
            let id = event.id();
            let dropped = self.covered.contains(&id)
                || self
                    .units
                    .get(&id)
                    .is_some_and(|unit| released.contains(&unit.stream));
            if !dropped {
                usage = usage.saturating_add(event.signed_len() as u64);
            }
        }
        for (locator, record) in &self.objects {
            let referencing: Vec<&EventId> = self
                .units
                .iter()
                .filter(|(_, unit)| unit.objects.contains(locator))
                .map(|(id, _)| id)
                .collect();
            let dropped = !referencing.is_empty()
                && referencing.iter().all(|id| {
                    self.covered.contains(id) || released.contains(&self.units[*id].stream)
                });
            if !dropped {
                usage = usage.saturating_add(object_bytes(record));
            }
        }
        self.usage = usage;
    }

    /// The units of a snapshot unit's cover the peer holds (units.md,
    /// "Snapshot units and stream snapshots").
    fn cover(&self, stream: StreamId, compacts: &Compacts) -> BTreeSet<EventId> {
        frasil_units::compaction::cover_set(
            &self.log,
            |id| self.units.get(&id).map(|unit| unit.stream),
            &compacts.covers,
            &stream,
        )
    }

    /// Whether a snapshot unit's declaration holds against the peer's own
    /// index (units.md, "A unit, at a peer", and "Collecting"): its covers
    /// are the stream past its parents fix, and its stubs match the events
    /// they stand for. Checked before the first collection, which the
    /// journal keeps, so a later pass collects again what is stored again.
    fn cover_holds(&self, snapshot: EventId, stream: StreamId, compacts: &Compacts) -> bool {
        if self.collected.contains(&snapshot) {
            return true;
        }
        let Some(event) = self.log.event(snapshot) else {
            return false;
        };
        let expected = frasil_units::compaction::covers(
            &self.log,
            |id| self.units.get(&id).map(|unit| unit.stream),
            event.parents(),
            &stream,
        );
        expected == compacts.covers
            && compacts
                .stubs
                .iter()
                .all(|stub| frasil_units::compaction::check_stub(&self.log, stub).is_ok())
    }

    /// The snapshot units a stored restore names.
    /// Whether the peer keeps a unit only as a parent: it is in the stream
    /// past, so the cover, of a snapshot unit the peer collected and no
    /// restore names (peers.md, "Collection"), or a unit of a released
    /// stream that an event outside the stream names (peers.md, "Release
    /// and restore"). Such a unit references no object, and keeps no hold
    /// live.
    pub(crate) fn kept_as_parent(&self, id: EventId) -> bool {
        let Some(stream) = self.units.get(&id).map(|unit| unit.stream) else {
            return false;
        };
        // A unit of a released stream that an event outside it names is
        // kept as an event alone (peers.md, "Release and restore").
        if self.is_released(&stream) && self.named_outside(id, stream) {
            return true;
        }
        let cancelled = self.cancelled_snapshots();
        self.collected.iter().any(|snapshot| {
            *snapshot != id
                && !cancelled.contains(snapshot)
                && self
                    .units
                    .get(snapshot)
                    .is_some_and(|unit| unit.stream == stream)
                && self.log.precedes(id, *snapshot)
        })
    }

    fn cancelled_snapshots(&self) -> BTreeSet<EventId> {
        self.writer_requests
            .values()
            .filter_map(|body| match body {
                StorageBody::Restore(Restored::Snapshot(id)) => Some(EventId(*id)),
                _ => None,
            })
            .collect()
    }

    // -- The sweep: erasure, credentials requests, release and collection

    /// Whether anything waits for a sweep: a request not carried out, a
    /// released stream whose units are held, a cover not collected, an
    /// event pending, a change or cut held unnamed, or an object not both
    /// complete and referenced.
    pub(crate) fn waits(&self) -> bool {
        self.requests.iter().any(|id| !self.executed.contains(id))
            || self.log.pending().next().is_some()
            || self
                .changes
                .iter()
                .any(|&id| self.log.contains(id) && self.unnamed(id))
            || !self.covered.is_empty()
            || self
                .released_streams()
                .iter()
                .any(|stream| self.reclaim_due(stream))
            || self.objects.iter().any(|(locator, record)| {
                !(record.complete && (record.referenced || self.record_named(locator)))
            })
            || self.has_old_versions()
            || self.truncation_waits()
    }

    /// Whether a skeleton cut is in effect that the peer has not truncated
    /// under yet: a sweep truncates once `cut_retention` has passed.
    fn truncation_waits(&self) -> bool {
        self.skeleton
            .chain(&self.log, self.kept_with_past())
            .last()
            .is_some_and(|&cut| Some(cut) != self.kept())
    }

    /// When a cut took effect at the peer, on its timeline (peers.md,
    /// "Skeleton cuts", in effect at the peer): once the peer held the cut,
    /// its checkpoint, and for each slot the cut waits for, a lowering that
    /// excuses it or its first vote that counts. None while one is missing.
    fn in_effect_since(
        &self,
        cuts: &PeerCuts<'_>,
        cut: EventId,
        checkpoint: EventId,
    ) -> Option<Reading> {
        let tally = cuts.tally(cut)?;
        let mut since = later(*self.sights.get(&cut)?, *self.sights.get(&checkpoint)?);
        let first = |ids: &mut dyn Iterator<Item = EventId>| {
            ids.filter_map(|id| self.sights.get(&id).copied())
                .min_by_key(|reading| reading.timeline)
        };
        for slot in &tally.waited {
            let excuses = tally.excuses.get(slot).filter(|e| !e.is_empty());
            let seen = match excuses {
                Some(excuses) => first(&mut excuses.iter().copied()),
                None => first(&mut tally.votes.get(slot)?.iter().copied()),
            }?;
            since = later(since, seen);
        }
        Some(since)
    }

    /// The cut in effect that the peer has not truncated under, if any, with
    /// its checkpoint and that checkpoint's past.
    fn current_cut(&self) -> Option<(EventId, EventId, BTreeSet<EventId>)> {
        self.skeleton
            .chain(&self.log, self.kept_with_past())
            .last()
            .copied()
            .filter(|&cut| Some(cut) != self.kept())
            .and_then(|cut| {
                let checkpoint = self.cuts().checkpoint_of(cut)?;
                Some((cut, checkpoint, self.log.past(checkpoint)))
            })
    }

    /// The skeleton in which an erasure or credentials request of `past`,
    /// the past of `cut`'s checkpoint, is judged while one there is not
    /// carried out (peers.md, "Truncation"): the one before the cut took
    /// effect, from the cut in effect before it or from the root, over every
    /// event the peer holds ([`PeerCuts::skeleton_before`]). The requests
    /// are carried out as before, a vote after the checkpoint acknowledges
    /// them, and truncation waits for them. None when no such request
    /// waits: `skeleton`, the world after the cut, holds none of that past.
    fn skeleton_before(
        &self,
        cut: EventId,
        past: &BTreeSet<EventId>,
        skeleton: &Skeleton<'_>,
    ) -> Option<Skeleton<'_>> {
        let waiting = self.requests.iter().any(|id| {
            !self.executed.contains(id) && past.contains(id) && !skeleton.view().contains(id)
        });
        if !waiting {
            return None;
        }
        self.cuts().skeleton_before(cut)
    }

    /// The plan of a truncation under `cut`, in effect at the peer, whose
    /// checkpoint is `checkpoint`, if it is due now (peers.md,
    /// "Truncation"): the cut has been in effect for `cut_retention`; every
    /// erasure and credentials request in the checkpoint's past is carried
    /// out, or void in `before`, the skeleton before the cut, or judged void
    /// or carried out by this sweep's `outcomes` (with no `before`, none
    /// waits); and the peer holds the envelopes the plan reads. Units are
    /// kept: they follow collection (peers.md, "Collection"), which the
    /// peer runs on them as before.
    fn truncation_due(
        &self,
        cut: EventId,
        checkpoint: EventId,
        before: Option<&Skeleton<'_>>,
        outcomes: &BTreeMap<EventId, Execution>,
        now: Reading,
        settings: &Settings,
    ) -> Option<TruncationPlan> {
        let cuts = self.cuts();
        let since = self.in_effect_since(&cuts, cut, checkpoint)?;
        if !cuts::may_truncate(&since, &now, settings.cut_retention) {
            return None;
        }
        let settled = |id: EventId| {
            self.executed.contains(&id)
                || matches!(
                    outcomes.get(&id),
                    Some(Execution::Execute | Execution::Void)
                )
        };
        if let Some(before) = before
            && !cuts::requests_settled(before, checkpoint, settled)
        {
            return None;
        }
        cuts.truncation_plan(cut, |_, event| event.kind() == kind::UNIT)
            .ok()
    }

    /// Truncates under `cut` by `plan` (peers.md, "Truncation"): records
    /// the truncation, deletes the events the plan names and keeps a stub
    /// of each, so that an event whose parent it deleted is placed as if
    /// that parent were stored, and a `Want` for it is answered `Missing`;
    /// and deletes the record objects of the cuts it deletes that no cut it
    /// keeps names and no unit lists. The plan keeps whole every checkpoint
    /// whose envelope it keeps.
    fn truncate(
        &self,
        cut: EventId,
        checkpoint: EventId,
        plan: &TruncationPlan,
        removal: &mut Removal,
    ) {
        removal.ops.push(Op::Truncated {
            cut,
            checkpoint,
            requests: plan.requests.iter().copied().collect(),
        });
        for &id in &plan.delete {
            removal.events.insert(id);
            if !self.stubs.contains_key(&id)
                && let Some(stub) = frasil_units::compaction::stub_of(&self.log, id)
            {
                removal.stubs.push(stub.event_stub());
            }
        }
        let kept: BTreeSet<Locator> = self
            .changes
            .iter()
            .filter(|id| !plan.delete.contains(id))
            .filter_map(|&id| cuts::read_cut(self.log.event(id)?))
            .map(|cut| cut.record)
            .collect();
        for &id in plan.delete.intersection(&self.changes) {
            let Some(deleted) = self.log.event(id).and_then(cuts::read_cut) else {
                continue;
            };
            let listed = self
                .units
                .values()
                .any(|unit| unit.objects.contains(&deleted.record));
            if !kept.contains(&deleted.record)
                && !listed
                && self.objects.contains_key(&deleted.record)
            {
                removal.objects.insert(deleted.record);
            }
        }
    }

    /// Whether a unit supersedes an object the peer stores still.
    fn has_old_versions(&self) -> bool {
        self.file_versions
            && self.units.values().any(|unit| {
                unit.supersedes
                    .iter()
                    .any(|named| self.objects.contains_key(&named.predecessor))
            })
    }

    /// The units of a stream that are listings as a snapshot unit arrives,
    /// and the `since` of the unit's own listings fixed from them
    /// (ext-file-versions.md, 3.6 Listings at a peer).
    fn fix_since(
        &mut self,
        id: EventId,
        stream: StreamId,
        compacts: &Compacts,
        supersedes: &[frasil_adapter::Supersession],
    ) {
        let seen = self.sights.get(&id).copied().unwrap_or(Reading {
            timeline: 0,
            wall: None,
            run: 1,
        });
        let cover: Vec<[u8; 32]> = self.cover(stream, compacts).iter().map(|c| c.0).collect();
        let listings = self.listings(|_| true);
        let since = supersedes
            .iter()
            .map(|named| {
                let since = listings.inherited_since(&cover, &named.predecessor, seen);
                (named.predecessor, since)
            })
            .collect();
        self.listing_since.insert(id, since);
    }

    /// The space's listings (ext-file-versions.md, 3.6): its stored units,
    /// neither replaced nor released. `stable` says which are stable at the
    /// peer; only a superseding unit is asked.
    ///
    /// It is rebuilt whole on each call, once per sweep and once per held
    /// locator a hold asks about, in O(units) each: acceptable at the sizes
    /// a space has now.
    fn listings(&self, stable: impl Fn(EventId) -> bool) -> Listings {
        let released = self.released_streams();
        let units = self
            .units
            .iter()
            .filter(|(id, unit)| !self.covered.contains(*id) && !released.contains(&unit.stream))
            .map(|(id, unit)| {
                let view = UnitView {
                    stream: unit.stream,
                    objects: unit.objects.clone(),
                    supersedes: unit
                        .supersedes
                        .iter()
                        .map(|named| Named {
                            successor: named.successor,
                            listing: named.listing,
                            predecessor: named.predecessor,
                        })
                        .collect(),
                    seen: self.sights.get(id).copied().unwrap_or(Reading {
                        timeline: 0,
                        wall: None,
                        run: 1,
                    }),
                    snapshot: unit.compacts.is_some(),
                    stable: !unit.supersedes.is_empty() && stable(*id),
                    evidence: self.conflicts.contains(id),
                    since: self.listing_since.get(id).cloned().unwrap_or_default(),
                };
                (id.0, view)
            })
            .collect();
        Listings::new(units)
    }

    /// The objects retention collects now (ext-file-versions.md, 3.8
    /// Retention). A collected object stored again waits for a unit to list
    /// it, as an orphan does (section 3.8): one whose bytes came after every
    /// unit that lists it is left alone for `orphan_grace`.
    fn old_versions(
        &self,
        listings: &Listings,
        now: &Reading,
        limits: &Limits,
        orphan_grace: u64,
    ) -> BTreeSet<Locator> {
        self.objects
            .iter()
            .filter(|(locator, record)| {
                let stored_again = listings.units().values().all(|unit| {
                    !unit.objects.contains(*locator) || unit.seen.timeline < record.last.timeline
                }) && lower(&record.last, now) < orphan_grace;
                !stored_again
                    && matches!(
                        listings.retain(locator, now, limits, false),
                        Retain::Collect(_)
                    )
            })
            .map(|(locator, _)| *locator)
            .collect()
    }

    /// Whether a hold of a locator by this space ends with retention
    /// (ext-file-versions.md, 3.9): every listing of it here is superseded,
    /// and `retain`, over those alone and without its step 2, would collect.
    pub(crate) fn hold_ends(&self, locator: &Locator, now: Reading, settings: &Settings) -> bool {
        let skeleton = self.skeleton.get(&self.log, self.kept_with_past());
        let clock = skeleton::Clock {
            first_sights: &self.sights,
            now,
            timeout: settings.erasure_timeout,
        };
        let listings = self.listings(|id| skeleton.is_stable(id, Some(&clock)));
        let limits = Limits {
            max_file_versions: settings.max_file_versions,
            file_version_retention: settings.file_version_retention,
            erasure_timeout: settings.erasure_timeout,
        };
        matches!(
            listings.retain(locator, &now, &limits, false),
            Retain::Collect(_)
        )
    }

    /// Judges every request, released stream and snapshot unit at `now`
    /// (peers.md, "Erasure" to "Collection"), carries out the credentials
    /// requests it may, and returns what removes events or objects, with
    /// the records to write.
    pub(crate) fn sweep(&mut self, now: Reading, settings: &Settings) -> Removal {
        let mut removal = Removal::default();
        let timeout = settings.erasure_timeout;
        let skeleton = self.skeleton.get(&self.log, self.kept_with_past());
        let current = self.current_cut();
        let pre = current
            .as_ref()
            .and_then(|(cut, _, past)| self.skeleton_before(*cut, past, &skeleton));
        let judge = |id: EventId| -> &Skeleton<'_> {
            match (&current, &pre) {
                (Some((_, _, past)), Some(pre))
                    if !skeleton.view().contains(&id) && past.contains(&id) =>
                {
                    pre
                }
                _ => &skeleton,
            }
        };
        let clock = skeleton::Clock {
            first_sights: &self.sights,
            now,
            timeout,
        };
        let stable = |id: EventId| judge(id).is_stable(id, Some(&clock));
        // peers.md, "Erasure", steps 0 and 1: a request concurrent with a
        // cut that can still take effect waits; once the cut takes effect it
        // is late, and void.
        let cuts = self.cuts();
        // Erasures and credentials requests, in canonical order: those of
        // the checkpoint's past first, then those of the world after the
        // cut in effect, then the late ones, which are void (peers.md,
        // "Skeleton cuts", late skeleton events).
        let mut requests: Vec<EventId> = match (&current, &pre) {
            (Some((_, _, past)), Some(pre)) => pre
                .skeleton_events()
                .iter()
                .copied()
                .filter(|id| past.contains(id) && !skeleton.view().contains(id))
                .collect(),
            _ => Vec::new(),
        };
        let of_past = requests.len();
        requests.extend(skeleton.skeleton_events().iter().copied());
        requests.extend(self.log.canonical_in(skeleton.late_events()));
        let mut executes = Vec::new();
        let mut outcomes = BTreeMap::new();
        for (at, id) in requests.into_iter().enumerate() {
            if self.executed.contains(&id) {
                continue;
            }
            let Some(body) = judge(id).body_of(id) else {
                continue;
            };
            if !matches!(
                body.storage_type(),
                StorageType::Erase | StorageType::Credentials
            ) {
                continue;
            }
            let accepted = self.sights.get(&id).copied().unwrap_or(now);
            let state = cuts.request_state(id);
            let valid = judge(id).is_valid(id) && state != RequestState::Late;
            // A request of the checkpoint's past keeps the verdict and the
            // stability of the skeleton before the cut, a slot of the cut
            // also acknowledging it through its pseudonym in the world after
            // the cut (peers.md, "Skeleton cuts", requests of the cut's
            // past).
            let stable = match &pre {
                Some(pre) if at < of_past => cuts::stable_past(pre, &skeleton, id, Some(&clock)),
                _ => stable(id),
            };
            let undecided = state == RequestState::Wait;
            let outcome =
                decisions::erasure(valid, undecided, valid && stable, &accepted, &now, timeout);
            outcomes.insert(id, outcome);
            if outcome == Execution::Execute {
                executes.push((id, body.clone()));
            }
        }
        // Released streams, each with the maximal releases that make it
        // released. None is reclaimed while one of them is concurrent with a
        // cut that can still take effect (peers.md, "Release and restore",
        // step 2).
        let released = self.released();
        let mut reclaims = Vec::new();
        for (stream, maximal) in &released {
            let undecided = maximal
                .iter()
                .any(|&id| cuts.request_state(id) == RequestState::Wait);
            let released_at = maximal
                .iter()
                .filter_map(|id| self.sights.get(id))
                .max_by_key(|reading| reading.timeline)
                .copied()
                .unwrap_or(now);
            let all_stable = maximal.iter().all(|&id| stable(id));
            let decision = decisions::release(
                true,
                undecided,
                all_stable,
                &released_at,
                &now,
                settings.release_retention,
                timeout,
            );
            if decision == Reclamation::Reclaim && self.reclaim_due(stream) {
                reclaims.push(*stream);
            }
        }
        // Snapshot units.
        let cancelled = self.cancelled_snapshots();
        let mut collects = Vec::new();
        for (&snapshot, unit) in &self.units {
            let Some(compacts) = &unit.compacts else {
                continue;
            };
            let seen = self.sights.get(&snapshot).copied().unwrap_or(now);
            let decision = decisions::collect(
                cancelled.contains(&snapshot),
                stable(snapshot),
                &seen,
                &now,
                timeout,
            );
            if decision == Collection::Collect {
                let cover = self.cover(unit.stream, compacts);
                if !cover.is_empty() && self.cover_holds(snapshot, unit.stream, compacts) {
                    collects.push((snapshot, cover));
                }
            }
        }
        let old_versions = if !self.file_versions {
            BTreeSet::new()
        } else {
            let listings = self.listings(stable);
            let limits = Limits {
                max_file_versions: settings.max_file_versions,
                file_version_retention: settings.file_version_retention,
                erasure_timeout: timeout,
            };
            self.old_versions(&listings, &now, &limits, settings.orphan_grace)
        };
        // Truncation under the cut in effect, once it is due.
        let truncation = current.as_ref().and_then(|(cut, checkpoint, _)| {
            self.truncation_due(*cut, *checkpoint, pre.as_ref(), &outcomes, now, settings)
                .map(|plan| (*cut, *checkpoint, plan))
        });
        drop(cuts);
        drop(pre);
        drop(skeleton);
        self.outcomes.extend(outcomes);
        // Carry out what changes no event: credentials requests.
        for (id, body) in &executes {
            match body {
                StorageBody::Credentials { .. } => {
                    self.carry_out(*id);
                    removal.ops.push(Op::Executed { request: *id });
                }
                StorageBody::Erase => {
                    removal.ops.push(Op::Executed { request: *id });
                    removal.erase_space = self.log.event(*id).map(Event::signed);
                    self.executed.insert(*id);
                    return removal;
                }
                _ => {}
            }
        }
        for stream in reclaims {
            self.reclaim_stream(&stream, &mut removal);
        }
        for (snapshot, cover) in collects {
            if !self.collected.contains(&snapshot) {
                removal.ops.push(Op::Collected { snapshot });
                if let Some(since) = self.listing_since.get(&snapshot) {
                    removal.ops.push(Op::Since {
                        snapshot,
                        since: since.iter().map(|(l, r)| (*l, *r)).collect(),
                    });
                }
            }
            self.collect(snapshot, &cover, &mut removal);
        }
        removal.objects.extend(old_versions);
        // Pending events past orphan_grace, unnamed changes and cuts among
        // them (peers.md, "Storing an event", pending), and orphaned
        // objects.
        let pending = self.log.pending().map(Event::id);
        let unnamed = self
            .changes
            .iter()
            .copied()
            .filter(|&id| self.log.contains(id) && self.unnamed(id));
        for id in pending.chain(unnamed).collect::<Vec<_>>() {
            if self
                .sights
                .get(&id)
                .is_some_and(|seen| lower(seen, &now) >= settings.orphan_grace)
            {
                removal.events.insert(id);
            }
        }
        if let Some((cut, checkpoint, plan)) = truncation {
            self.truncate(cut, checkpoint, &plan, &mut removal);
        }
        for (locator, record) in &self.objects {
            // A cut's record object is kept while the cut is (peers.md,
            // "Truncation").
            let referenced_now =
                self.units.iter().any(|(id, unit)| {
                    !removal.events.contains(id) && unit.objects.contains(locator)
                }) || self.record_named(locator);
            if removal.objects.contains(locator) {
                continue;
            }
            if !(referenced_now || record.complete && record.referenced)
                && lower(&record.last, &now) >= settings.orphan_grace
            {
                removal.objects.insert(*locator);
            }
        }
        // A removed unit lists nothing, so its `since` goes with it
        // (ext-file-versions.md, 3.6 Listings at a peer).
        self.listing_since
            .retain(|id, _| !removal.events.contains(id));
        removal
    }

    /// Reclaims a released stream (peers.md, "Release and restore"): its
    /// units, but each one that an event outside the stream names as a
    /// parent, which the peer keeps as an event alone, served by ID and
    /// with its objects gone; the peer's own stub of each removed unit a
    /// kept or other event names; and the objects no unit outside the
    /// stream references. A release removes a stream's content, not the
    /// fact that its units existed, so a replica that catches up still
    /// places what names them.
    fn reclaim_stream(&self, stream: &StreamId, removal: &mut Removal) {
        let Some(units) = self.streams.get(stream) else {
            return;
        };
        let removed = self.reclaimable(stream);
        let kept: BTreeSet<EventId> = units
            .iter()
            .copied()
            .filter(|id| !removed.contains(id))
            .collect();
        self.remove_units(&removed, removal, true);
        self.remove_objects(&kept, removal);
    }

    /// Collects a snapshot unit's cover (peers.md, "Collection"): every unit
    /// of it, except one an unreplaced event names as a parent for which no
    /// stored snapshot unit holds a stub, and one a space event names as a
    /// parent, which a replica fetches in full to place that event; and the
    /// objects no stored, unreplaced and unreleased unit references. A unit
    /// kept is still covered, so its objects go with the others.
    fn collect(&self, snapshot: EventId, cover: &BTreeSet<EventId>, removal: &mut Removal) {
        let _ = snapshot;
        let carried: BTreeSet<EventId> = self
            .units
            .values()
            .filter_map(|unit| unit.compacts.as_ref())
            .flat_map(|compacts| compacts.stubs.iter().map(|stub| stub.id))
            .collect();
        let keep: BTreeSet<EventId> = cover
            .iter()
            .copied()
            .filter(|id| {
                self.log.events().any(|event| {
                    !self.covered.contains(&event.id())
                        && !cover.contains(&event.id())
                        && event.parents().contains(id)
                        && (!carried.contains(id) || event.kind() == kind::SPACE)
                })
            })
            .collect();
        let removed: BTreeSet<EventId> = cover.difference(&keep).copied().collect();
        // A unit kept stays placed: the peer's own stub stands for each
        // parent of it that goes, for its own placement.
        for id in &removed {
            let named = keep.iter().any(|kept| {
                self.log
                    .event(*kept)
                    .is_some_and(|event| event.parents().contains(id))
            });
            if named && let Some(stub) = frasil_units::compaction::stub_of(&self.log, *id) {
                removal.stubs.push(stub.event_stub());
            }
        }
        self.remove_units(&removed, removal, false);
        self.remove_objects(&keep, removal);
    }

    /// Removes units, and the objects only they reference. With
    /// `own_stubs`, keeps the peer's own stub of each removed unit that a
    /// remaining event names as a parent.
    fn remove_units(&self, units: &BTreeSet<EventId>, removal: &mut Removal, own_stubs: bool) {
        for &id in units {
            removal.events.insert(id);
            if own_stubs
                && self
                    .log
                    .events()
                    .any(|event| !units.contains(&event.id()) && event.parents().contains(&id))
                && let Some(stub) = frasil_units::compaction::stub_of(&self.log, id)
            {
                removal.stubs.push(stub.event_stub());
            }
        }
        self.remove_objects(units, removal);
    }

    /// Removes the objects that `units` reference and no other stored,
    /// uncovered and unreleased unit does.
    fn remove_objects(&self, units: &BTreeSet<EventId>, removal: &mut Removal) {
        let released = self.released_streams();
        let mut locators: BTreeSet<Locator> = BTreeSet::new();
        for id in units {
            if let Some(unit) = self.units.get(id) {
                locators.extend(unit.objects.iter().copied());
            }
        }
        for locator in locators {
            let still = self.units.iter().any(|(id, unit)| {
                !units.contains(id)
                    && !removal.events.contains(id)
                    && !self.covered.contains(id)
                    && !released.contains(&unit.stream)
                    && unit.objects.contains(&locator)
            });
            if !still {
                removal.objects.insert(locator);
            }
        }
    }

    // -- Presents, merge statements and recovery entries

    /// The Ed25519 key of a pseudonym, by device ID, that is the root's or
    /// an accepted enrolment's: the `ed` of that event's envelope, under
    /// which its credential 3 proof verifies (peers.md, 3.7 Presenting a
    /// credential, steps 3 and 4).
    pub(crate) fn pseudonym_ed(&self, pseudonym: &DeviceId) -> Option<IdentityKey> {
        self.skeleton
            .ed(&self.log, self.kept_with_past(), pseudonym)
            .or_else(|| {
                // Presenting a pseudonym remains possible while its root
                // or enrolment is held, even when the cut no longer lists
                // its slot (peers.md, 3.7, credential 3).
                let root = self
                    .skeleton()
                    .root()
                    .or_else(|| skeleton::root_of(&self.log));
                self.log.events().find_map(|event| {
                    let known = match StorageBody::read(event.unverified_body()) {
                        Ok(StorageBody::Root { .. }) => Some(event.id()) == root,
                        Ok(StorageBody::Enrol { .. }) => true,
                        _ => false,
                    };
                    (event.author() == pseudonym && known).then_some(*event.ed())
                })
            })
    }

    /// A retained late erasure still authenticates its pseudonym after truncation.
    fn late_eraser_ed(&self, pseudonym: &DeviceId) -> Option<IdentityKey> {
        self.skeleton
            .late(&self.log, self.kept_with_past())
            .iter()
            .find_map(|id| {
                let event = self.log.event(*id)?;
                (event.author() == pseudonym
                    && matches!(
                        StorageBody::read(event.unverified_body()),
                        Ok(StorageBody::Erase)
                    ))
                .then_some(*event.ed())
            })
    }

    /// The skeleton, as last resolved or resolved now (peers.md, 3.12 The
    /// skeleton's resolution).
    pub(crate) fn skeleton(&self) -> Skeleton<'_> {
        self.skeleton.get(&self.log, self.kept_with_past())
    }

    /// The skeleton before the cut in effect, while an erasure or
    /// credentials request of its checkpoint's past waits there, with that
    /// past: what [`Space::awaiting_lists`] also reads.
    pub(crate) fn waiting_before<'s>(
        &'s self,
        skeleton: &Skeleton<'_>,
    ) -> Option<(BTreeSet<EventId>, Skeleton<'s>)> {
        let (cut, _, past) = self.current_cut()?;
        let before = self.skeleton_before(cut, &past, skeleton)?;
        Some((past, before))
    }

    /// Awaiting lists for all administration connections. Stability and the
    /// cut's pending votes are computed once, then each pseudonym looks up
    /// only its own acknowledgements.
    pub(crate) fn awaiting_lists(
        &self,
        skeleton: &Skeleton<'_>,
        before: Option<&(BTreeSet<EventId>, Skeleton<'_>)>,
        pseudonyms: impl IntoIterator<Item = DeviceId>,
        now: Reading,
        timeout: u64,
    ) -> BTreeMap<DeviceId, Vec<EventId>> {
        let clock = skeleton::Clock {
            first_sights: &self.sights,
            now,
            timeout,
        };
        let stability = skeleton.stability_set(Some(&clock));
        let mut targets: BTreeSet<EventId> = skeleton
            .skeleton_events()
            .iter()
            .copied()
            .filter(|id| {
                !self.executed.contains(id)
                    && skeleton
                        .body_of(*id)
                        .is_some_and(|body| body.storage_type().is_request())
            })
            .collect();
        targets.extend(
            self.writer_requests
                .iter()
                .filter(|(_, body)| matches!(body, StorageBody::Release { .. }))
                .map(|(id, _)| *id),
        );
        targets.extend(
            self.units
                .iter()
                .filter(|(_, unit)| unit.compacts.is_some())
                .map(|(id, _)| *id),
        );
        targets.retain(|&id| !skeleton.acknowledged(id, &stability));

        // Requests preceding the current cut keep their original stability
        // set; votes by its original slots also acknowledge that whole past.
        let (old_slots, old_targets) = match before {
            Some((past, before)) => {
                let slots = before.stability_set(Some(&clock));
                let targets: Vec<_> = before
                    .skeleton_events()
                    .iter()
                    .copied()
                    .filter(|id| {
                        !self.executed.contains(id)
                            && past.contains(id)
                            && !skeleton.view().contains(id)
                            && before.is_valid(*id)
                            && before.body_of(*id).is_some_and(|body| {
                                matches!(
                                    body.storage_type(),
                                    StorageType::Erase | StorageType::Credentials
                                )
                            })
                    })
                    .filter(|&id| {
                        !slots
                            .iter()
                            .all(|&slot| cuts::acknowledged_past(before, skeleton, id, slot))
                    })
                    .collect();
                (slots.into_iter().collect::<BTreeSet<_>>(), targets)
            }
            None => (BTreeSet::new(), Vec::new()),
        };
        let mut lists = self.cuts().awaiting_votes();
        pseudonyms
            .into_iter()
            .map(|pseudonym| {
                let Some(slot) = skeleton.slot_of(&pseudonym) else {
                    return (pseudonym, Vec::new());
                };
                let mut out: Vec<_> = targets
                    .iter()
                    .copied()
                    .filter(|&id| !skeleton.acknowledged(id, &[slot]))
                    .collect();
                if let Some((_, before)) = before
                    && old_slots.contains(&slot)
                    && skeleton.is_cut_slot(slot)
                    && skeleton.merged().get(&slot).and_then(|s| s.enrolled) == Some(pseudonym)
                {
                    out.extend(
                        old_targets
                            .iter()
                            .copied()
                            .filter(|&id| !cuts::acknowledged_past(before, skeleton, id, slot)),
                    );
                }
                out.extend(lists.remove(&pseudonym).unwrap_or_default());
                out.sort_unstable();
                out.dedup();
                out.truncate(frasil_transport::messages::MAX_AWAITING);
                (pseudonym, out)
            })
            .collect()
    }
}

/// An object's bytes as they count toward usage: its stored length once
/// known, or what its pieces hold so far.
pub(crate) fn object_bytes(record: &ObjectRecord) -> u64 {
    match record.total {
        Some(total) if record.complete => total,
        _ => (record.pieces.len() as u64).saturating_mul(crate::objects::PIECE_BYTES as u64),
    }
}

/// Whether a storage event is a cut whose body holds a reserved key, which
/// a peer keeps and holds as `ExtensionRequired` (peers.md, "Reserved cut
/// keys").
pub(crate) fn holds_reserved_key(event: &frasil_events::Event) -> bool {
    StorageBody::read(event.unverified_body())
        .is_err_and(|class| class.shared() == Some(frasil_base::ErrorClass::ExtensionRequired))
}

#[cfg(test)]
mod tests {
    use frasil_transport::messages::{Awaiting, MAX_AWAITING};

    fn awaiting(count: usize) -> usize {
        let ids = (0..count)
            .map(|i| {
                let mut id = [0xffu8; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        Awaiting {
            space: [0xff; 32],
            ids,
        }
        .encode()
        .len()
    }

    /// A space at the peer: a genesis, two units of stream `S`, the second
    /// after the first, a space event after the second, and a release of
    /// `S` after it. Returns the space and the IDs of the units, the space
    /// event and the release.
    fn released_scene() -> (super::Space, [frasil_events::EventId; 4]) {
        use frasil_crypto::schemes::{Scheme, Signer};
        use frasil_events::{Envelope, Event, EventId, kind};
        use frasil_peers::body::StorageBody;
        let founder = Signer::from_seeds(&[1; 32], &[51; 32], None);
        let sign = |kind: u8,
                    log: Option<EventId>,
                    seq: u64,
                    prev: Option<EventId>,
                    body: Vec<u8>|
         -> Event {
            let envelope = Envelope {
                kind,
                log,
                ed: *founder.identity_key(),
                kc: *founder.kc(),
                seq,
                prev,
                parents: prev.into_iter().collect(),
                cuts: Vec::new(),
                body,
                scheme: if kind == kind::UNIT {
                    Scheme::Ed25519
                } else {
                    Scheme::Hybrid
                },
            };
            frasil_events::decode(&envelope.sign(&founder)).unwrap()
        };
        let genesis = sign(kind::SPACE, None, 1, None, b"genesis".to_vec());
        let space_id = genesis.id();
        let first = sign(
            kind::UNIT,
            Some(space_id),
            2,
            Some(space_id),
            b"first".to_vec(),
        );
        let second = sign(
            kind::UNIT,
            Some(space_id),
            3,
            Some(first.id()),
            b"second".to_vec(),
        );
        let event = sign(
            kind::SPACE,
            Some(space_id),
            4,
            Some(second.id()),
            b"event".to_vec(),
        );
        let release = StorageBody::Release { stream: STREAM };
        let request = sign(
            kind::STORAGE,
            Some(space_id),
            5,
            Some(event.id()),
            release.encode(),
        );
        let mut space = super::Space::create(
            genesis,
            super::Rules {
                cap: 8,
                file_versions: false,
            },
        )
        .unwrap();
        let ids = [first.id(), second.id(), event.id(), request.id()];
        for placed in [first, second, event, request] {
            space.log.place(placed).unwrap();
        }
        for unit in &ids[..2] {
            space.units.insert(
                *unit,
                super::UnitIndex {
                    stream: STREAM,
                    objects: Vec::new(),
                    compacts: None,
                    supersedes: Vec::new(),
                },
            );
        }
        space
            .streams
            .insert(STREAM, ids[..2].iter().copied().collect());
        space.writer_requests.insert(ids[3], release);
        (space, ids)
    }

    const STREAM: [u8; 16] = [7; 16];

    /// peers.md, "Release and restore": a reclaim keeps, as an event alone
    /// and served by ID, a unit of the released stream that an event
    /// outside it names as a parent, here a space event; the rest goes,
    /// with the peer's own stub of each removed unit a kept one names.
    #[test]
    fn a_reclaim_keeps_the_units_events_outside_the_stream_name() {
        let (space, [first, second, _, _]) = released_scene();
        let released = space.released_streams();
        assert!(released.contains(&STREAM));
        assert!(space.servable(second, &released), "served as a parent");
        assert!(!space.servable(first, &released));
        assert_eq!(space.reclaimable(&STREAM), [first].into());
        let mut removal = super::Removal::default();
        space.reclaim_stream(&STREAM, &mut removal);
        assert_eq!(removal.events, [first].into());
        assert_eq!(
            removal.stubs.iter().map(|stub| stub.id).collect::<Vec<_>>(),
            vec![first],
            "the kept unit stays placed on the peer's own stub"
        );
    }

    /// peers.md, "Storage events" and "Erasure": an erasure names the whole
    /// space. An erase body that names a stream, alone or beside the
    /// space, is `Malformed`, which the peer's store refuses before it
    /// keeps anything of the event; the stream's units stay.
    #[test]
    fn an_erasure_that_names_a_stream_is_refused() {
        use frasil_base::cbor::Value;
        let (space, [first, second, _, _]) = released_scene();
        for with_space in [false, true] {
            let mut body = frasil_base::cbor::Map::from([
                (1, Value::Unsigned(1)),
                (2, Value::Unsigned(5)),
                (4, Value::Array(vec![Value::from(STREAM)])),
            ]);
            if with_space {
                body.insert(3, Value::Unsigned(1));
            }
            let body = Value::Map(body).encode();
            assert_eq!(
                frasil_peers::body::StorageBody::read(&body),
                Err(frasil_peers::PeersClass::Shared(
                    frasil_base::ErrorClass::Malformed
                ))
            );
        }
        assert!(space.log.contains(first) && space.log.contains(second));
    }

    /// peers.md, "Skeleton cuts" and "Truncation": the record object a cut
    /// names is kept while the cut is, past `orphan_grace`, as long as it
    /// is within the size a 64 MiB record takes stored; another object no
    /// unit lists is collected.
    #[test]
    fn a_cuts_record_object_is_kept_and_an_orphan_is_not() {
        use crate::records::{ObjectRecord, Op};
        use frasil_base::time::Reading;
        let rows: Vec<Vec<u8>> = frasil_testkit::vectors::family::<serde_json::Value>(
            "peers.json",
            "skeleton_cuts",
        )["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap())
            .collect();
        let genesis = frasil_events::decode(&rows[0]).unwrap();
        let mut space = super::Space::create(
            genesis,
            super::Rules {
                cap: 256,
                file_versions: false,
            },
        )
        .unwrap();
        let at = Reading {
            timeline: 10,
            wall: None,
            run: 1,
        };
        for (index, signed) in rows.iter().enumerate().skip(1) {
            let op = Op::Event {
                signed: signed.clone(),
                sight: at,
                entry: None,
            };
            space.apply(index as u64, &op, frasil_events::decode(signed).ok());
        }
        space.refresh();
        let record = space
            .changes
            .iter()
            .find_map(|&id| frasil_peers::cut::read_cut(space.log.event(id)?))
            .expect("the history's cut")
            .record;
        assert!(space.records.contains(&record));
        let object = |total: u64| ObjectRecord {
            pieces: [0].into(),
            total: Some(total),
            complete: true,
            last: at,
            referenced: false,
            entry: None,
        };
        let orphan = [4; 64];
        space.objects.insert(record, object(100));
        space.objects.insert(orphan, object(100));
        let settings = crate::config::Settings::open_core();
        let later = Reading {
            timeline: 10 + 2 * settings.orphan_grace,
            ..at
        };
        let removal = space.sweep(later, &settings);
        assert!(!removal.objects.contains(&record), "kept for its cut");
        assert!(removal.objects.contains(&orphan), "collected");
        // One larger than a record object can be is not the cut's to keep.
        space
            .objects
            .insert(record, object(super::max_record_object() + 1));
        let removal = space.sweep(later, &settings);
        assert!(removal.objects.contains(&record));
        // The bound: 64 MiB of record, sealed, with its header.
        let max = frasil_units::record::MAX_RECORD_BYTES;
        assert!(super::max_record_object() > max);
        assert!(super::max_record_object() < max + max / 1000 + 4096);
    }

    #[test]
    fn the_awaiting_sent_fits_its_cap() {
        let cap = frasil_transport::MessageType::Awaiting.cap();
        assert!(awaiting(MAX_AWAITING) <= cap);
        assert!(awaiting(MAX_AWAITING + 1) > cap);
    }
}
