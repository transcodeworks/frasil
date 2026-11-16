//! Checkpoints at a replica (roster.md, 3.15 Checkpoints, and 3.15.7
//! Clients; identity.md, 3.16 List checkpoints).
//!
//! A replica judges its view with `frasil-space`'s [`Checkpointed`] as soon
//! as the view holds a checkpoint, an event declares cuts, or the replica
//! keeps a checkpoint after forgetting what came before it. That judgement
//! gives:
//!
//! - **the chain in effect** and, with it, every event's verdict: events in
//!   the first checkpoint's past as that past alone judges them, events
//!   after the last one in its world, and every other one `Late`;
//! - **the world** of the last checkpoint in effect ([`KeyWorld`]), which
//!   the replica reads instead of the whole view for its roster, its keys
//!   and its units;
//! - **the pending checkpoints**: valid checkpoints waiting for votes whose
//!   predecessor is the last one in effect, each with the administrators it
//!   waits for (roster.md, 3.15.4, "Waiting for");
//! - **the checkpoint this device follows** (roster.md, 3.15.7,
//!   "Following"): the one in effect, or a pending one, the one its own
//!   events already follow first, else the smallest ID. The device cites
//!   nothing concurrent with it, so that its events follow it and none is
//!   `MixedCut`;
//! - **reports**: `BadCheckpoint`, `Late` and `MixedCut` verdicts, and how
//!   much roster history has grown since the last checkpoint in effect,
//!   which decides when an administrator proposes the next one;
//! - **what the device does not build on**: a pending checkpoint whose
//!   record differs from the one the device derives from its past, space
//!   members' keys 18 to 20 included, or that it cannot derive yet
//!   (roster.md, 3.15.7, "Voting"), and a contested one, which hears the
//!   device or whose author or kept administrator the device's view lowers
//!   by a concurrent event of a member that outranks it
//!   (`Checkpointed::contest`);
//!   the device follows none of them, cites nothing after them, and
//!   commits no event that reaches one;
//! - **rivals** (roster.md, 3.15.6): at a replica that forgot, a held
//!   checkpoint that could replace its kept one. While one is held every
//!   event is pending, the device fetches the rival's past, forgets
//!   nothing more, and once it holds that past judges the view in full;
//! - **backdated checkpoints** (roster.md, section 4): a held removal of a
//!   checkpoint's author concurrent with it, reported to administrators.
//!
//! A checkpoint's record travels as an object (roster.md, "The record
//! object"): the replica reads it with the checkpoint's own content key, or
//! the record's object key a space snapshot handed over
//! ([`frasil_units::record::HeldRecords`]); until then the checkpoint is
//! held `Sealed`, and the device fetches the object by the locator the
//! checkpoint names.

use frasil_adapter::Locator;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, kind};
use frasil_space::{
    Change, CheckpointInputs, CheckpointPart, Checkpointed, Kept, KeyWorld, Options, Policy,
    Record, Roster, RosterClass, Space, SpaceClass, Status, Waiting,
};
use frasil_units::record::HeldRecords;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::Zeroizing;

/// The valid roster events since the last checkpoint in effect at which an
/// administrator's client proposes the next one (roster.md, 3.15.7
/// Clients, "Proposing").
pub const PROPOSE_AT_ROSTER_EVENTS: u64 = 1_024;

/// The bytes of frame events since the last checkpoint in effect at which
/// an administrator's client proposes the next one: 4 MiB (roster.md,
/// 3.15.7 Clients, "Proposing").
pub const PROPOSE_AT_FRAME_BYTES: u64 = 4 << 20;

/// What a device does about checkpoints by itself (roster.md, 3.15.7
/// Clients). The default does everything the text recommends, at the
/// thresholds it gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CheckpointPolicy {
    /// Whether an administrator's client proposes a checkpoint by itself
    /// once the space has [`Self::roster_events`] valid roster events or
    /// [`Self::frame_bytes`] of frame events since the last one in effect,
    /// and whether a device proposes a checkpoint of its person's device
    /// list once the list holds [`Self::roster_events`] events since the
    /// last one. With it off the application proposes, if ever, by itself.
    pub propose: bool,
    /// Whether the device forgets what came before a checkpoint once it is
    /// in effect (roster.md, 3.15.6), in a space and in its person's device
    /// list.
    pub forget: bool,
    /// The valid roster events (or list events) since the last checkpoint
    /// in effect at which the device proposes the next one:
    /// [`PROPOSE_AT_ROSTER_EVENTS`] by default. At least 1.
    pub roster_events: u64,
    /// The bytes of frame events since the last checkpoint in effect at
    /// which the device proposes the next one: [`PROPOSE_AT_FRAME_BYTES`]
    /// by default. At least 1.
    pub frame_bytes: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self::AUTOMATIC
    }
}

impl CheckpointPolicy {
    /// A policy that proposes and forgets by itself, at the thresholds the
    /// text gives, as the default does.
    pub const AUTOMATIC: Self = Self {
        propose: true,
        forget: true,
        roster_events: PROPOSE_AT_ROSTER_EVENTS,
        frame_bytes: PROPOSE_AT_FRAME_BYTES,
    };

    /// A policy under which the application proposes checkpoints itself;
    /// the device still forgets.
    pub const MANUAL: Self = Self {
        propose: false,
        ..Self::AUTOMATIC
    };

    /// This policy, with automatic proposal on or off.
    #[must_use]
    pub const fn proposing(self, propose: bool) -> Self {
        Self { propose, ..self }
    }

    /// This policy, with forgetting on or off.
    #[must_use]
    pub const fn forgetting(self, forget: bool) -> Self {
        Self { forget, ..self }
    }

    /// This policy, proposing at other thresholds: `roster_events` valid
    /// roster events (or list events), or `frame_bytes` bytes of frame
    /// events, since the last checkpoint in effect. Each is at least 1.
    #[must_use]
    pub const fn proposing_at(self, roster_events: u64, frame_bytes: u64) -> Self {
        Self {
            roster_events: if roster_events == 0 { 1 } else { roster_events },
            frame_bytes: if frame_bytes == 0 { 1 } else { frame_bytes },
            ..self
        }
    }
}

/// A valid checkpoint that waits for votes, whose predecessor is the last
/// checkpoint in effect (roster.md, 3.15.4 Votes and effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingCheckpoint {
    /// The checkpoint.
    pub checkpoint: EventId,
    /// Its epoch.
    pub epoch: u64,
    /// Its author.
    pub author: DeviceId,
    /// The administrators of its electorate that have not voted, with the
    /// last event of each the replica holds.
    pub waiting: Vec<Waiting>,
}

/// How much roster history the view holds since the last checkpoint in
/// effect, or since the genesis without one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Growth {
    /// Valid roster events.
    pub roster_events: u64,
    /// Bytes of signed frame events: every event but units.
    pub frame_bytes: u64,
}

impl Growth {
    /// Whether the growth calls for a checkpoint under `policy`'s
    /// thresholds (roster.md, 3.15.7 Clients, "Proposing").
    pub fn calls_for_checkpoint(&self, policy: &CheckpointPolicy) -> bool {
        self.roster_events >= policy.roster_events || self.frame_bytes >= policy.frame_bytes
    }
}

/// The growth of a view that holds no checkpoint, from the genesis on:
/// what [`judge`] counts when it judges the view with its checkpoints.
pub(crate) fn plain_growth(log: &Log, plain: &Space<'_>) -> Growth {
    let mut growth = Growth::default();
    for &id in plain.view() {
        if id == log.id() {
            continue;
        }
        let Some(event) = log.event(id) else {
            continue;
        };
        if event.kind() == kind::UNIT {
            continue;
        }
        growth.frame_bytes = growth.frame_bytes.saturating_add(event.signed_len() as u64);
        if plain.is_roster(id) && plain.status(id).is_some_and(Status::is_valid) {
            growth.roster_events += 1;
        }
    }
    growth
}

/// A roster event the checkpoint in effect made late (roster.md, 3.15.1),
/// with the changes it made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LateRoster {
    /// The late event.
    pub event: EventId,
    /// Its author.
    pub author: DeviceId,
    /// Its changes.
    pub changes: Vec<Change>,
}

/// The record a checkpoint over a past would carry, as a proposal reads it:
/// the parents it cites, and the record of their past (roster.md, 3.15.3).
#[derive(Debug, Clone)]
pub(crate) struct Proposal {
    /// The parents.
    pub parents: Vec<EventId>,
    /// The record.
    pub record: Record,
    /// The standing entries the record gives its cut (peers.md, "Storage
    /// events"), which step 9 of its validity checks.
    pub standing: Vec<frasil_peers::body::StandingEntry>,
}

/// What the last judgement of a replica's view says of its checkpoints.
#[derive(Debug, Clone, Default)]
pub(crate) struct Facts {
    /// Whether the view was judged with its checkpoints at all.
    pub active: bool,
    /// What the judgement froze of each unit of the past of the checkpoint
    /// [`Held::freeze`] named, with that checkpoint.
    pub frozen_units: Option<(EventId, BTreeMap<EventId, frasil_space::FrozenUnit>)>,
    /// Every checkpoint the replica opened, whatever its verdict, with its
    /// roster part.
    pub parts: BTreeMap<EventId, CheckpointPart>,
    /// The checkpoints whose record the replica reads.
    pub records: BTreeSet<EventId>,
    /// The chain in effect, oldest first.
    pub chain: Vec<EventId>,
    /// The valid checkpoints waiting for votes.
    pub pending: Vec<PendingCheckpoint>,
    /// The checkpoint this device follows.
    pub following: Option<EventId>,
    /// Checkpoints void as `BadCheckpoint`.
    pub bad: BTreeSet<EventId>,
    /// Events void as `Late`.
    pub late: BTreeSet<EventId>,
    /// Events void as `MixedCut`.
    pub mixed: BTreeSet<EventId>,
    /// The late roster events this replica opened.
    pub late_roster: Vec<LateRoster>,
    /// The roster history since the last checkpoint in effect.
    pub growth: Growth,
    /// The record a proposal asked for, over the parents it named.
    pub proposal: Option<Proposal>,
    /// Whether each pending checkpoint that waits for this device carries
    /// the record this device derives from its past, space members' keys
    /// 18 to 20 included (roster.md, 3.15.7, "Voting"), once known.
    pub agreement: BTreeMap<EventId, bool>,
    /// Pending checkpoints that wait for this device whose record it cannot
    /// derive yet: it waits for other logs before it votes.
    pub unsure: BTreeSet<EventId>,
    /// Checkpoints this device never builds on, contested for it (roster.md,
    /// 3.15.7, "Contested checkpoints"; `Checkpointed::contest`).
    pub withheld: BTreeSet<EventId>,
    /// Each contested checkpoint's lowering events (roster.md, 3.15.7,
    /// "Contested checkpoints"): those of its past, then those of this
    /// device's view concurrent with it.
    pub contests: BTreeMap<EventId, (Vec<EventId>, Vec<EventId>)>,
    /// The checkpoints this judgement found stable, each with the events
    /// it found it stable over, and those it was given as known: what the
    /// next judgement takes as known (`Checkpointed::seed_stable`).
    pub stable_seed: BTreeMap<EventId, BTreeSet<EventId>>,
    /// The final validity verdicts of checkpoints, with the kept checkpoint
    /// they were reached under (`Checkpointed::seed_validity`).
    pub validity_seed: (Option<EventId>, BTreeMap<EventId, Status>),
    /// Rivals of the kept checkpoint (roster.md, 3.15.6): while one is held,
    /// every event is pending until the device holds the rival's past.
    pub rivals: Vec<EventId>,
    /// The events the device fetches to judge a rival: the parents in its
    /// past the replica does not hold.
    pub rival_wanted: Vec<EventId>,
    /// Checkpoints with a held removal of their author concurrent with them
    /// (roster.md, section 4, "A backdated checkpoint"), with the removal.
    pub backdated: Vec<(EventId, EventId)>,
    /// Whether a valid checkpoint concurrent with the last one in effect,
    /// with a smaller ID, is held and not in the chain: the chain may still
    /// move to it, so the device does not forget yet.
    pub contested: bool,
    /// Pending checkpoints whose cut an always-on peer the device reaches
    /// does not hold yet: the device neither follows nor votes for them
    /// until it does (peers.md, "The administrator's duties").
    pub unacknowledged: BTreeSet<EventId>,
}

/// The checkpoint among `avoid` that an event citing `parents` would
/// reach, if any: the device builds on none of them (roster.md, 3.15.7
/// "Voting", section 4 "A backdated checkpoint").
pub(crate) fn reaches_avoided(
    log: &Log,
    avoid: &BTreeSet<EventId>,
    parents: &[EventId],
) -> Option<EventId> {
    avoid.iter().copied().find(|&c| {
        parents
            .iter()
            .any(|&p| p == c || log.follows(p, c) == Ok(true))
    })
}

impl Facts {
    /// The checkpoints this device builds on no event of: those it
    /// withholds itself from, those whose record differs from its own
    /// derivation, and those whose record it cannot derive yet.
    pub fn avoided(&self) -> BTreeSet<EventId> {
        let mut out = self.withheld.clone();
        out.extend(self.unsure.iter().copied());
        out.extend(self.refused());
        out
    }

    /// Pending checkpoints whose record differs from this device's own
    /// derivation: it never votes for them.
    pub fn refused(&self) -> BTreeSet<EventId> {
        self.agreement
            .iter()
            .filter(|(_, agrees)| !**agrees)
            .map(|(c, _)| *c)
            .collect()
    }

    /// The last checkpoint in effect.
    pub fn last(&self) -> Option<EventId> {
        self.chain.last().copied()
    }

    /// The checkpoints known, as the cuts check reads them: every opened
    /// checkpoint, whatever its verdict.
    pub fn ids(&self) -> BTreeSet<EventId> {
        self.parts.keys().copied().collect()
    }

    /// The locators of record objects the replica cannot read yet.
    pub fn records_wanted(&self) -> Vec<Locator> {
        self.parts
            .iter()
            .filter(|(id, _)| !self.records.contains(id))
            .map(|(_, part)| part.locator)
            .collect()
    }
}

/// The devices whose next checkpoint records carry record key 9, a key a
/// later document defines (roster.md, 2.8 The checkpoint record, step 3):
/// what a device of a later version would sign, for tests.
#[cfg(test)]
pub(crate) static LATER_RECORD_KEY: std::sync::Mutex<BTreeSet<DeviceId>> =
    std::sync::Mutex::new(BTreeSet::new());

/// What a replica keeps of its checkpoints between refreshes, beside the
/// facts its last judgement gave.
#[derive(Debug, Clone, Default)]
pub(crate) struct Held {
    /// The facts of the last judgement.
    pub facts: Facts,
    /// The checkpoint the replica keeps after forgetting what came before
    /// it, with its record (roster.md, 3.15.6).
    pub kept: Option<Kept>,
    /// Record object keys a space snapshot handed over, by checkpoint
    /// (units.md, "The space snapshot", key 13).
    pub object_keys: BTreeMap<EventId, Zeroizing<[u8; 32]>>,
    /// Validated record reads, by checkpoint, made outside judgement.
    pub record_reads: BTreeMap<EventId, frasil_units::record::RecordRead>,
    /// The parents of a checkpoint this device is about to propose: the
    /// next judgement derives the record of their past.
    pub propose: Option<Vec<EventId>>,
    /// The records the last judgement read, by checkpoint.
    pub records: BTreeMap<EventId, Arc<Record>>,
    /// The verdicts of the events of the kept checkpoint's past that a
    /// replica that forgot keeps (its units, roots, enrolments, releases and
    /// restores): it decided them on the whole past before it forgot, and
    /// holds them, never judging them again (roster.md, 3.15.6).
    pub frozen: BTreeMap<EventId, Status>,
    /// The kept checkpoint named at load, until its record reads.
    pub kept_id: Option<EventId>,
    /// The verdicts the event records kept, read at load: those of events
    /// that do not follow the kept checkpoint are held as `frozen` are.
    pub recorded: BTreeMap<EventId, Status>,
    /// Checkpoint envelopes a snapshot handed over before the genesis is
    /// placed.
    pub envelopes: Vec<Event>,
    /// The IDs of dropped events read at load, taken once the log's events
    /// are placed ([`crate::replica::Replica::take_restored_dropped`]).
    pub restored_dropped: Vec<EventId>,
    /// Whether the genesis's descriptor is a later document's (roster.md,
    /// "The space descriptor"): the replica holds every event after it and
    /// signs nothing in the space, even while it holds no other event.
    pub later_descriptor: bool,
    /// Why each event the replica forgot is dropped, with its kind and,
    /// for a parent of a kept event, its height: what its `dropped` record
    /// keeps (at-rest.md, the `dropped` table).
    pub dropped_origins: BTreeMap<EventId, frasil_store::tables::DroppedOrigin>,
    /// What the next judgement reads besides the log's events: the
    /// replica's keys, other logs, record objects and envelopes, as one
    /// fingerprint the replica sets before it judges.
    pub inputs: Vec<u8>,
    /// The judgement of the past of the first checkpoint of the chain, with
    /// the inputs it was made under: taken as known by the next judgement
    /// under the same ([`Checkpointed::seed_judged`]).
    pub before: Option<(Vec<u8>, BTreeSet<EventId>, frasil_space::Judged)>,
    /// What each always-on peer the device reaches is known to hold: a
    /// pending checkpoint is followed, and voted for, only once each holds
    /// its cut (peers.md, "The administrator's duties").
    pub peer_holdings: Vec<BTreeSet<EventId>>,
    /// The event that voids each event `recorded` names, from key 8 of its
    /// `event` record.
    pub recorded_by: BTreeMap<EventId, EventId>,
    /// The checkpoint whose past the device is about to forget: the next
    /// judgement freezes each unit of that past
    /// ([`Checkpointed::frozen_units`]).
    pub freeze: Option<EventId>,
}

/// Whether a storage event of a checkpoint's past is one a replica that
/// forgot keeps: a root or an enrolment, which a cut's slots name, or a
/// release or a restore (roster.md, 3.15.6, "What must be kept").
pub(crate) fn kept_storage(event: &Event) -> bool {
    use frasil_peers::body::StorageBody;
    event.kind() == kind::STORAGE
        && matches!(
            StorageBody::read(event.unverified_body()),
            Ok(StorageBody::Root { .. }
                | StorageBody::Enrol { .. }
                | StorageBody::Release { .. }
                | StorageBody::Restore(_))
        )
}

/// What a replica that started from checkpoint `c`, a snapshot handing
/// over its record key, still fetches of the frame before `c`'s world
/// (units.md, 3.10 The space snapshot, "The checkpoint";
/// [`frasil_units::snapshot::SnapshotCheckpoint::fetches_through`]): the
/// checkpoint, the checkpoints its cuts reach that it keeps no envelope
/// of, its skeleton cut, then the roots and enrolments the cut names. Empty
/// where it holds them all, and for a replica that never started from a
/// snapshot's checkpoint.
pub(crate) fn start_fetches(log: &Log, held: &Held) -> Vec<EventId> {
    let Some(c) = held.kept_id else {
        return Vec::new();
    };
    let Some(record_key) = held.object_keys.get(&c) else {
        return Vec::new();
    };
    let section = frasil_units::snapshot::SnapshotCheckpoint {
        checkpoint: c,
        record_key: **record_key,
        cut_chain: log.kept_envelopes().map(Event::signed).collect(),
    };
    let checkpoint = log.event(c);
    let cut = checkpoint
        .and_then(frasil_units::snapshot::twin_of)
        .and_then(|twin| log.event(twin));
    section
        .fetches_through(&log.id(), checkpoint, cut, |id| {
            log.contains(*id) || log.kept_envelope_of(*id).is_some() || log.is_dropped(*id)
        })
        .unwrap_or_default()
}

/// A judgement of a view with its checkpoints.
pub(crate) struct Judgement {
    /// The facts.
    pub facts: Facts,
    /// Every event's verdict.
    pub statuses: BTreeMap<EventId, Status>,
    /// The roster of the view: that of the last world.
    pub roster: Roster,
    /// The policy of the view.
    pub policy: Policy,
    /// The world of the last checkpoint in effect, if one is.
    pub world: Option<KeyWorld>,
    /// The records read, by checkpoint.
    pub records: BTreeMap<EventId, Arc<Record>>,
    /// The kept checkpoint, once its record reads.
    pub kept: Option<Kept>,
    /// The resolution of the last world in effect, as the judgement made
    /// it, when the world was the one the last judgement had in effect: a
    /// replica resumes it as units after the checkpoint arrive.
    pub world_resolved: Option<frasil_space::Resolved>,
    /// The checkpoints of that world whose record the replica cannot read.
    pub world_unreadable: Vec<EventId>,
    /// The judgement of the past of the first checkpoint of the chain, for
    /// the next one ([`Held::before`]).
    pub before: Option<(Vec<u8>, BTreeSet<EventId>, frasil_space::Judged)>,
}

/// Opens the key world with the same cut-based skeleton the judgement
/// used. The world's own log omits the cut's retained roots and
/// enrolments, which the skeleton must read from the replica's log.
pub(crate) fn resolve_world<'a>(
    judgement: &'a Judgement,
    log: &'a Log,
    options: Options<'a>,
) -> Option<frasil_space::Space<'a>> {
    let world = judgement.world.as_ref()?;
    let checkpoint = world.checkpoint();
    let cut = log
        .event(checkpoint)
        .and_then(frasil_peers::skeleton::named_twin)?;
    let body = log.event(cut).and_then(frasil_peers::cut::read_cut)?;
    let members: BTreeSet<EventId> = world
        .log()
        .view()
        .iter()
        .copied()
        .filter(|&id| id != checkpoint && id != log.id())
        .collect();
    let held = members.iter().copied().chain([cut]).collect();
    let peer = frasil_peers::cut::PeerCuts::truncated(log, log, held, cut);
    let cuts = peer
        .cuts()
        .map(|(id, _)| id)
        .filter(|&id| id != cut && members.contains(&id))
        .map(|id| (id, peer.validity(id)))
        .collect();
    let skeleton = frasil_peers::skeleton::Skeleton::after_cut(log, cut, &body, members, cuts);
    // Ordinary valid roster events must be resolved, rather than preset:
    // only the checkpoint procedure decides checkpoint verdicts in advance.
    let presets = judgement
        .statuses
        .iter()
        .filter(|(_, status)| {
            !status.is_valid() || matches!(status, Status::Valid(frasil_space::Valid::Checkpoint))
        })
        .map(|(&id, &status)| (id, status))
        .collect();
    world
        .log()
        .resolve_with_skeleton(options, world.record(), presets, Some(skeleton))
        .ok()
}

impl core::fmt::Debug for Judgement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Judgement")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// Whether a view must be judged with its checkpoints: it holds one, an
/// event declares cuts, or the replica keeps a checkpoint.
pub(crate) fn applies(log: &Log, plain: &Space<'_>, kept: Option<&Kept>) -> bool {
    kept.is_some()
        || log.kept_envelopes().next().is_some()
        || plain.view().iter().any(|&id| plain.is_checkpoint(id))
        || log.events().any(|event| !event.cuts().is_empty())
}

fn class_is(status: &Status, class: SpaceClass) -> bool {
    status.class() == Some(RosterClass::from(class))
}

/// Judges a view with its checkpoints (roster.md, 3.15.5, "Verdicts").
/// `plain` is the view resolved without them, from which the replica reads
/// which events are checkpoints. `None` when nothing calls for it
/// ([`applies`]) and no proposal asks for a record.
pub(crate) fn judge(
    log: &Log,
    options: Options<'_>,
    plain: &Space<'_>,
    held: &Held,
    me: &DeviceId,
) -> Option<Judgement> {
    if !applies(log, plain, held.kept.as_ref()) && held.propose.is_none() && held.kept_id.is_none()
    {
        return None;
    }
    let mut parts = BTreeMap::new();
    for &id in plain.view() {
        if let Some(part) = plain.opened(id).and_then(|opened| opened.checkpoint()) {
            parts.insert(id, part.clone());
        }
    }
    let records = HeldRecords {
        reads: &held.record_reads,
    };
    let none: BTreeMap<EventId, Event> = BTreeMap::new();
    let inputs = CheckpointInputs {
        log,
        options,
        objects: &records,
        envelopes: &none,
        slots: None,
    };
    // The kept checkpoint named at load is kept once its record reads.
    let kept = match (&held.kept, held.kept_id) {
        (Some(kept), _) => Some(kept.clone()),
        (None, Some(c)) => Checkpointed::new(inputs, None)
            .record(c)
            .map(|record| Kept {
                checkpoint: c,
                record,
            }),
        (None, None) => None,
    };
    // The verdicts a replica that forgot holds for what it kept of the
    // kept checkpoint's past.
    let mut frozen = held.frozen.clone();
    if let Some(kept) = &kept {
        let c = kept.checkpoint;
        // A late event is kept whole and judged as one that kept everything
        // judges it (`Late`, by the checkpoint in effect); its record keeps
        // the class alone.
        let late = SpaceClass::Late;
        frozen.extend(held.recorded.iter().filter_map(|(&id, &status)| {
            let judged_late = class_is(&status, late) && !log.precedes(id, c);
            let status = match (status, held.recorded_by.get(&id)) {
                (Status::Void { class, by: None }, Some(&by)) => Status::Void {
                    class,
                    by: Some(by),
                },
                (status, _) => status,
            };
            (id != c
                && id != log.id()
                && log.contains(id)
                && log.follows(id, c) != Ok(true)
                && !judged_late)
                .then_some((id, status))
        }));
    }
    let mut checkpointed = Checkpointed::new(inputs, kept.clone());
    // What a replica that forgot kept of its kept checkpoint's past, which
    // its log no longer orders against what follows the checkpoint: placed
    // in that past, never late.
    checkpointed.set_kept_past(frozen.keys().copied());
    let view: BTreeSet<EventId> = plain
        .view()
        .iter()
        .copied()
        .filter(|id| !frozen.contains_key(id))
        .collect();
    // The checkpoints the last judgement found in effect were stable over
    // its view, and stay so over any view that holds it: their votes are
    // not counted again.
    if !held.facts.stable_seed.is_empty() {
        checkpointed.seed_stable(held.facts.stable_seed.clone());
    }
    // The records read before, and the final validity verdicts reached
    // with the same kept checkpoint, are not read and judged again.
    checkpointed.seed_records(held.records.clone());
    let kept_now = kept.as_ref().map(|kept| kept.checkpoint);
    if held.facts.validity_seed.0 == kept_now {
        checkpointed.seed_validity(held.facts.validity_seed.1.clone());
    }
    // The past of the first checkpoint of the chain, judged before under
    // the same inputs, is not judged again.
    if let Some((inputs, past, before)) = &held.before
        && *inputs == held.inputs
        && kept.is_none()
    {
        checkpointed.seed_judged(past.clone(), before.clone());
    }
    // The world the last judgement had in effect is kept, to be resumed.
    if let Some(c) = held.facts.chain.last() {
        checkpointed.keep_world(*c);
    }
    let judged = checkpointed.judge(&view);
    let world_resolved = judged
        .chain
        .last()
        .and_then(|&c| checkpointed.take_world(c, &view));
    let world_unreadable = match (&world_resolved, judged.chain.last()) {
        (Some(resolved), Some(&c)) => checkpointed.unreadable_in(c, resolved.view()),
        _ => Vec::new(),
    };
    let before = match (judged.chain.first(), &kept) {
        (Some(&first), None) => {
            let past = log.past(first);
            checkpointed
                .judged_over(&past)
                .map(|judged| (held.inputs.clone(), past, judged))
        }
        _ => None,
    };
    let mut stable_seed = held.facts.stable_seed.clone();
    for (c, over) in checkpointed.found_stable() {
        stable_seed.entry(c).or_insert(over);
    }
    let last = judged.chain.last().copied();
    let mut read = BTreeMap::new();
    for &id in parts.keys() {
        if let Some(record) = checkpointed.record(id) {
            read.insert(id, record);
        }
    }
    if let Some(kept) = &kept {
        read.insert(kept.checkpoint, kept.record.clone());
    }
    let mut pending = Vec::new();
    for (&c, record) in &read {
        if judged.chain.contains(&c) || record.previous != last {
            continue;
        }
        if !checkpointed.validity(c).is_valid() {
            continue;
        }
        if let Some(last) = last
            && checkpointed.follows(c, last) != Ok(true)
        {
            continue;
        }
        let Some(author) = log.event(c).map(|event| *event.author()) else {
            continue;
        };
        pending.push(PendingCheckpoint {
            checkpoint: c,
            epoch: record.epoch,
            author,
            waiting: checkpointed.waiting_for(c, &view),
        });
    }
    // Voting (roster.md, 3.15.7): a pending checkpoint that waits for this
    // device is voted for only once its record, space members' keys 18 to
    // 20 included, equals the one this device derives from its past.
    let mut agreement = BTreeMap::new();
    let mut unsure = BTreeSet::new();
    for p in &pending {
        if !p.waiting.iter().any(|w| w.device == *me) {
            continue;
        }
        let known = held.facts.agreement.get(&p.checkpoint).copied();
        match known.or_else(|| checkpointed.record_agrees(p.checkpoint)) {
            Some(agrees) => {
                agreement.insert(p.checkpoint, agrees);
            }
            None => {
                unsure.insert(p.checkpoint);
            }
        }
    }
    // Contested checkpoints (roster.md, 3.15.7, "Contested checkpoints"):
    // a device never cites or votes for a pending checkpoint that hears it,
    // nor one whose author or kept administrator its own view lowers by a
    // concurrent event signed by a member that outranks the one it lowers.
    // It stops treating one so once it takes effect without the device.
    let mut withheld: BTreeSet<EventId> = held
        .facts
        .withheld
        .iter()
        .copied()
        .filter(|c| parts.contains_key(c) && !judged.chain.contains(c))
        .collect();
    for p in &pending {
        if checkpointed.contest(me, p.checkpoint, &view).is_some() {
            withheld.insert(p.checkpoint);
        }
    }
    // The lowering events on both sides of each contested checkpoint, which
    // the application is told of as it is of a duel.
    let mut contests = BTreeMap::new();
    if !withheld.is_empty() {
        let lowerings = checkpointed.lowerings(&view);
        for &c in &withheld {
            let past = log.past(c);
            let kept: BTreeSet<DeviceId> = read
                .get(&c)
                .map(|record| record.administrators().collect())
                .unwrap_or_default();
            let author = log.event(c).map(|event| *event.author());
            let theirs: Vec<EventId> = lowerings
                .iter()
                .filter(|lowering| past.contains(&lowering.event))
                .map(|lowering| lowering.event)
                .collect();
            let ours: Vec<EventId> = lowerings
                .iter()
                .filter(|lowering| lowering.event != c && log.concurrent(lowering.event, c))
                .filter(|lowering| {
                    lowering
                        .targets
                        .iter()
                        .any(|t| Some(t.device) == author || kept.contains(&t.device))
                })
                .map(|lowering| lowering.event)
                .collect();
            contests.insert(c, (theirs, ours));
        }
    }
    let refused: BTreeSet<EventId> = agreement
        .iter()
        .filter(|(_, agrees)| !**agrees)
        .map(|(c, _)| *c)
        .collect();
    // The checkpoint this device follows: the last in effect, or a pending
    // one its own events already follow, else the pending one with the
    // smallest ID (roster.md, 3.15.7, "Following"); never one it builds on
    // no event of.
    // A pending checkpoint whose cut a peer the device reaches does not hold
    // yet: the device votes for it by no event until each holds it, so that
    // no peer carries out a request the checkpoint could still make late
    // (peers.md, "The administrator's duties"). A device that reaches no
    // peer waits for nothing.
    let unacknowledged: BTreeSet<EventId> = pending
        .iter()
        .map(|p| p.checkpoint)
        .filter(|&c| {
            let Some(cut) = log.event(c).and_then(frasil_peers::skeleton::named_twin) else {
                return false;
            };
            !held
                .peer_holdings
                .iter()
                .all(|holds| holds.contains(&cut) || holds.iter().any(|&x| log.precedes(cut, x)))
        })
        .collect();
    let builds_on = |c: &EventId| {
        !withheld.contains(c)
            && !refused.contains(c)
            && !unsure.contains(c)
            && !unacknowledged.contains(c)
    };
    let own: Vec<EventId> = log.chain(me);
    let following = pending
        .iter()
        .filter(|p| builds_on(&p.checkpoint))
        .find(|p| {
            own.iter()
                .any(|&id| checkpointed.follows(id, p.checkpoint) == Ok(true))
        })
        .or_else(|| pending.iter().find(|p| builds_on(&p.checkpoint)))
        .map(|p| p.checkpoint)
        .or(last);
    let mut bad = BTreeSet::new();
    let mut late = BTreeSet::new();
    let mut mixed = BTreeSet::new();
    for (&id, status) in &judged.statuses {
        if class_is(status, SpaceClass::BadCheckpoint) {
            bad.insert(id);
        } else if class_is(status, SpaceClass::Late) {
            late.insert(id);
        } else if class_is(status, SpaceClass::MixedCut) {
            mixed.insert(id);
        }
    }
    let mut growth = Growth::default();
    for &id in &view {
        if Some(id) == last || id == log.id() {
            continue;
        }
        if let Some(last) = last
            && checkpointed.follows(id, last) != Ok(true)
        {
            continue;
        }
        let Some(event) = log.event(id) else {
            continue;
        };
        if event.kind() == kind::UNIT {
            continue;
        }
        growth.frame_bytes = growth.frame_bytes.saturating_add(event.signed_len() as u64);
        if plain.is_roster(id) && judged.statuses.get(&id).is_some_and(Status::is_valid) {
            growth.roster_events += 1;
        }
    }
    let late_roster = late
        .iter()
        .filter_map(|&id| {
            let opened = plain.opened(id)?;
            if opened.checkpoint().is_some() || opened.changes().is_empty() {
                return None;
            }
            Some(LateRoster {
                event: id,
                author: *log.event(id)?.author(),
                changes: opened.changes().to_vec(),
            })
        })
        .collect();
    // The record a proposal asked for: that of the past of the parents it
    // will cite (roster.md, 3.15.3).
    let proposal = held.propose.as_ref().and_then(|parents| {
        let mut past = BTreeSet::new();
        for &parent in parents {
            past.extend(log.past(parent));
            past.insert(parent);
        }
        Some(Proposal {
            parents: parents.clone(),
            record: checkpointed.record_for(&past)?,
            standing: checkpointed.standing_for(&past)?,
        })
    });
    // The rivals of the kept checkpoint (roster.md, 3.15.6), which hold
    // every event pending, and their past as far as the replica lacks it:
    // the device fetches it.
    let rivals: Vec<EventId> = checkpointed.rivals(&view).into_iter().collect();
    let mut rival_wanted = BTreeSet::new();
    {
        let mut todo: Vec<EventId> = rivals.clone();
        let mut seen = BTreeSet::new();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            match log.event(id) {
                Some(event) => todo.extend(event.parents().iter().copied()),
                None if id != log.id() => {
                    rival_wanted.insert(id);
                }
                None => {}
            }
        }
    }
    // Whether the chain may still move from its last checkpoint to a
    // smaller concurrent one (roster.md, 3.15.4): then nothing is forgotten
    // yet.
    let contested = last.is_some_and(|c| {
        parts.keys().any(|&x| {
            x < c
                && !judged.chain.contains(&x)
                && checkpointed.concurrent(x, c) == Ok(true)
                && checkpointed.validity(x).is_valid()
        })
    });
    // A held removal of a checkpoint's author concurrent with it (roster.md,
    // section 4, "A backdated checkpoint"), reported to the administrators.
    let mut backdated = Vec::new();
    for c in judged
        .chain
        .iter()
        .chain(pending.iter().map(|p| &p.checkpoint))
    {
        let Some(author) = log.event(*c).map(|event| *event.author()) else {
            continue;
        };
        for &id in &view {
            let Some(opened) = plain.opened(id) else {
                continue;
            };
            let removes = opened.changes().iter().any(|change| {
                change.op == frasil_space::Op::Remove
                    && change.member.is_some_and(|member| {
                        member.kind == frasil_space::MemberType::Device && member.id == author.0
                    })
            });
            if removes && checkpointed.concurrent(id, *c) == Ok(true) {
                backdated.push((*c, id));
            }
        }
    }
    let world = checkpointed.key_world(&view);
    // What forgetting the past of `held.freeze` will keep of each unit
    // there, read in the view that judged it.
    let frozen_units = held.freeze.filter(|c| judged.chain.contains(c)).map(|c| {
        let all: BTreeSet<EventId> = plain.view().iter().copied().collect();
        (c, checkpointed.frozen_units(&all, c))
    });
    let facts = Facts {
        active: true,
        frozen_units,
        records: read.keys().copied().collect(),
        parts,
        chain: judged.chain.clone(),
        pending,
        following,
        bad,
        late,
        mixed,
        late_roster,
        growth,
        proposal,
        agreement,
        unsure,
        withheld,
        contests,
        stable_seed,
        validity_seed: (kept_now, checkpointed.final_validity()),
        rivals,
        rival_wanted: rival_wanted.into_iter().collect(),
        backdated,
        contested,
        unacknowledged,
    };
    let mut statuses = judged.statuses.clone();
    statuses.extend(frozen.iter().map(|(id, status)| (*id, *status)));
    Some(Judgement {
        facts,
        kept,
        statuses,
        roster: judged.roster.clone(),
        policy: judged.policy,
        world,
        records: read,
        world_resolved,
        world_unreadable,
        before,
    })
}

/// The verdicts decided before the procedure for content units `added`
/// to the world of checkpoint `c` ([`frasil_space::checkpoint_world::WorldLog`]),
/// once `world` holds them: `None`, with `world` left as it was or not,
/// unless each follows `c` and none is a checkpoint, so that the world's
/// resolution may be resumed with them.
pub(crate) fn presets_after(
    log: &Log,
    options: Options<'_>,
    held: &Held,
    c: EventId,
    world: &mut frasil_space::checkpoint_world::WorldLog,
    unreadable: &[EventId],
    added: &[EventId],
) -> Option<BTreeMap<EventId, Status>> {
    let records = HeldRecords {
        reads: &held.record_reads,
    };
    let none: BTreeMap<EventId, Event> = BTreeMap::new();
    let inputs = CheckpointInputs {
        log,
        options,
        objects: &records,
        envelopes: &none,
        slots: None,
    };
    let checkpointed = Checkpointed::new(inputs, held.kept.clone());
    for &id in added {
        if checkpointed.follows(id, c) != Ok(true) || checkpointed.is_checkpoint(id) {
            return None;
        }
    }
    world.append(log, added).ok()?;
    Some(checkpointed.presets_after(c, world, unreadable, added))
}

/// The parents a device that follows `following` cites (roster.md, 3.15.7,
/// "Following"): among `parents`, the checkpoint itself and the events
/// after it, and `prev` whatever it is; the checkpoint itself when no other
/// parent reaches it. Without a checkpoint to follow, `parents` as given.
pub(crate) fn fence(
    log: &Log,
    following: Option<EventId>,
    prev: Option<EventId>,
    parents: Vec<EventId>,
) -> Vec<EventId> {
    let Some(c) = following else {
        return parents;
    };
    if !log.contains(c) {
        return parents;
    }
    let mut out: Vec<EventId> = parents
        .into_iter()
        .filter(|&p| Some(p) == prev || p == c || log.follows(p, c) == Ok(true))
        .collect();
    let reaches = out
        .iter()
        .any(|&p| p == c || (Some(p) != prev && log.follows(p, c) == Ok(true)))
        || prev.is_some_and(|p| log.follows(p, c) == Ok(true));
    if !reaches {
        out.push(c);
    }
    out.sort_unstable();
    out.dedup();
    out
}

impl crate::replica::Replica {
    /// What the last judgement said of the space's checkpoints.
    pub(crate) fn checkpoint_facts(&self) -> &Facts {
        &self.checkpoints.facts
    }

    /// The checkpoint the replica keeps after forgetting what came before
    /// it.
    pub(crate) fn kept_checkpoint(&self) -> Option<&Kept> {
        self.checkpoints.kept.as_ref()
    }

    /// Whether the space needs a later version than this build: its
    /// descriptor is a later document's, or a space event of it is held as
    /// `ExtensionRequired` (roster.md, "The space
    /// descriptor", 2.8 The checkpoint record, step 3, and 3.16; a
    /// restricted space at a build without ext-restricted-spaces.md, as
    /// "The space descriptor" says). Every hook a later document defines
    /// holds such an event: a later descriptor every event after the
    /// genesis, a later record its checkpoint, whether it follows what the
    /// replica holds, rivals its kept checkpoint or is the one a snapshot
    /// named to start from, and a later roster part itself. The device
    /// signs nothing more in the space while it does.
    pub(crate) fn needs_later_version(&self) -> bool {
        if self.checkpoints.later_descriptor {
            return true;
        }
        let Some(log) = self.log() else {
            return false;
        };
        let extension = RosterClass::from(frasil_base::ErrorClass::ExtensionRequired);
        log.frame_events().any(|event| {
            event.kind() == kind::SPACE
                && self.status(&event.id()).and_then(Status::class) == Some(extension)
        })
    }

    /// The checkpoints an event citing `parents` declares (events.md, 3.11
    /// Cuts): the maximal ones its parents are or reach.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`](crate::Error::NotAllowed) while the answer
    /// waits for checkpoint envelopes or bodies the replica lacks.
    pub(crate) fn cuts_for(&self, parents: &[EventId]) -> crate::Result<Vec<EventId>> {
        let Some(log) = self.log() else {
            return Ok(Vec::new());
        };
        let facts = &self.checkpoints.facts;
        if !facts.active
            && !parents.iter().any(|parent| {
                log.event(*parent)
                    .is_some_and(|event| !event.cuts().is_empty())
                    || log.stub(*parent).is_some_and(|stub| !stub.cuts.is_empty())
            })
        {
            return Ok(Vec::new());
        }
        let mut known = facts.ids();
        known.extend(log.kept_envelopes().map(Event::id));
        known.extend(self.checkpoints.kept.as_ref().map(|kept| kept.checkpoint));
        log.cuts_for(&known, parents).map_err(|_| {
            crate::Error::NotAllowed("the device waits for the envelopes of checkpoints")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_calls_for_a_checkpoint_at_either_threshold() {
        let policy = CheckpointPolicy::default();
        let quiet = Growth::default();
        assert!(!quiet.calls_for_checkpoint(&policy));
        let roster = Growth {
            roster_events: PROPOSE_AT_ROSTER_EVENTS,
            frame_bytes: 0,
        };
        assert!(roster.calls_for_checkpoint(&policy));
        let bytes = Growth {
            roster_events: 0,
            frame_bytes: PROPOSE_AT_FRAME_BYTES,
        };
        assert!(bytes.calls_for_checkpoint(&policy));
        let lowered = policy.proposing_at(8, PROPOSE_AT_FRAME_BYTES);
        let few = Growth {
            roster_events: 8,
            frame_bytes: 0,
        };
        assert!(few.calls_for_checkpoint(&lowered));
        assert!(!few.calls_for_checkpoint(&policy));
    }
}
