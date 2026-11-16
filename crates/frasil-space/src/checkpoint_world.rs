//! The world after a checkpoint (roster.md, 3.15.5): the resolution of
//! sections 3.7 to 3.14 over a log whose root is the checkpoint and whose
//! events are the events the replica holds after it, each linked only to
//! its parents among them (its `prev` too, when it is after the
//! checkpoint).
//!
//! [`WorldLog`] builds that log as a [`Log`] of its own: the space's
//! genesis, which stays the source of the descriptor and the system stream
//! and takes no other part; the checkpoint; and the events after it. Every
//! parent of theirs outside the world stands as a stub, which links
//! nothing: so the world's causal order holds only links between its own
//! events, and a `prev` outside it proves no fork (events.md, "Chains and
//! evidence of a fork": a stubbed `prev` proves nothing). The checkpoint's
//! parents stand at height 0 and every other outside parent at height 1,
//! so the checkpoint sits at height 1 and every event after it one above
//! its height in the world; [`WorldRoot::height_offset`] takes that back.
//!
//! The log is built from the checkpoint and the events after it alone, so
//! a replica that forgot what came before the checkpoint and one that kept
//! everything build the same log and resolve it by the same function.
//!
//! [`WorldRoot::from_record`] makes the checkpoint stand as the genesis:
//! each member entry of its record a grant in it, with the entry's state
//! and seniority, and the record's policy the genesis policy. An invite key
//! the record shows claimed is out, as if the checkpoint were its valid
//! successor; the checkpoint counts as a successor of every invite key
//! whose status is not open; and it carries the record's notices, by the
//! authors the record names, and names the record's `named` IDs in its
//! sealed refs.

use crate::change::Change;
use crate::checkpoint_record::Record;
use crate::member::{HistoryMode, Level, Via};
use crate::screen::ScreenedLog;
use crate::space::{Checkpointing, Options, Space, Status};
use crate::state::{MemberState, Seniority, WorldRoot, seniority_hash};
use crate::{MemberType, RosterClass};
use frasil_base::collect::CollectMap;
use frasil_crypto::device::DeviceId;
use frasil_events::cuts::Cuts;
use frasil_events::{EventId, ForkPoints, Log, Ref, Stub, kind};
use std::collections::{BTreeMap, BTreeSet};

impl WorldRoot {
    /// The root of checkpoint `root`'s world, from its record: each member
    /// entry a grant at the root with the entry's state and seniority, the
    /// record's policy the root's. `space` is the space ID, which the
    /// seniority hash reads; `height_offset` the checkpoint's height in the
    /// log the world is resolved over ([`WorldLog`]).
    pub fn from_record(space: EventId, root: EventId, record: &Record, height_offset: u64) -> Self {
        let mut changes = Vec::with_capacity(record.members.len());
        let mut states = BTreeMap::new();
        let mut claimed = BTreeSet::new();
        let mut used = BTreeSet::new();
        let mut notices = Vec::new();
        let mut named = Vec::new();
        let mut raced = BTreeSet::new();
        let mut floors = BTreeSet::new();
        for entry in &record.members {
            if entry.invite == Some(crate::checkpoint_record::InviteStatus::Raced) {
                raced.insert(entry.member);
            }
            let keyed = matches!(entry.member.kind, MemberType::Device | MemberType::Invite);
            if let Some(status) = entry.invite
                && status.used()
            {
                used.insert(entry.member.id);
            }
            if entry.is_claimed() {
                // Out, as if the checkpoint were its valid successor; its
                // grant at the root keeps its keys and names it, so that a
                // later grant of it is `InviteUsed`.
                let mut grant =
                    Change::grant(entry.member, Level::Read, HistoryMode::FromNowOn, Via::Link);
                grant.keys = entry.keys.clone();
                changes.push(grant);
                claimed.insert(entry.member);
                continue;
            }
            let mut grant = Change::grant(entry.member, entry.level, entry.history, entry.via);
            grant.capabilities =
                (!entry.capabilities.is_empty()).then(|| entry.capabilities.clone());
            grant.label = entry.label.clone();
            grant.session = entry.session;
            grant.replaces = entry.replaces;
            grant.expires_at = entry.expires_at;
            grant.claims = entry.claims;
            grant.rank = entry.rank;
            if keyed {
                grant.keys = entry.keys.clone();
            }
            changes.push(grant);
            let (epoch, height, grant_id) = entry.seniority;
            states.insert(
                entry.member,
                MemberState {
                    level: entry.level,
                    capabilities: entry.capabilities.iter().cloned().collect(),
                    label: entry.label.clone(),
                    history: entry.history,
                    via: entry.via,
                    session: entry.session,
                    replaces: entry.replaces,
                    grants: BTreeSet::from([root]),
                    seniority: Seniority {
                        epoch,
                        height,
                        hash: seniority_hash(&space, &entry.member.id),
                        grant: grant_id,
                    },
                    keys: if keyed { entry.keys.clone() } else { None },
                    source: (0, root),
                    expires_at: entry.expires_at,
                    rank: entry.rank,
                },
            );
            if entry.member.kind == MemberType::Space {
                let granted = EventId(entry.member.id);
                if entry.floor {
                    floors.insert(granted);
                }
                notices.extend(entry.notices.iter().map(|n| (granted, n.clone())));
                named.extend(entry.named.iter().map(|&id| Ref { log: granted, id }));
            }
        }
        named.sort_unstable();
        named.dedup();
        let cut_slots = record
            .members
            .iter()
            .filter_map(|entry| {
                let slot = entry.slot.as_ref()?;
                let index = u8::try_from(slot.index).ok()?;
                let pseudonym = <[u8; 32]>::try_from(slot.pseudonym.as_slice())
                    .ok()
                    .map(DeviceId);
                Some((
                    frasil_peers::body::SlotId::new(slot.commitment, index, slot.maker),
                    (DeviceId(entry.member.id), pseudonym),
                ))
            })
            .collect_map();
        Self {
            root,
            epoch: record.epoch,
            changes,
            states,
            policy: record.policy,
            forks: record.forks.clone(),
            tips: record.tips.clone(),
            height_offset,
            claimed,
            used,
            notices,
            named,
            raced,
            floors,
            cut_slots,
        }
    }
}

/// The log of a checkpoint's world: the genesis, the checkpoint and the
/// events after it a replica holds, each linked to its parents among them
/// only.
#[derive(Debug, Clone)]
pub struct WorldLog {
    log: Log,
    root: EventId,
    view: BTreeSet<EventId>,
}

impl WorldLog {
    /// The world of checkpoint `root` over `members`, the events of
    /// `source` that follow it (the root among them or not). Each must be
    /// placed in `source`, as must the root; the genesis is `source`'s.
    ///
    /// # Errors
    ///
    /// `Pending` when the root or an event of `members` is not placed in
    /// `source`.
    pub fn new(
        source: &Log,
        root: EventId,
        members: &BTreeSet<EventId>,
    ) -> Result<Self, RosterClass> {
        let pending = || RosterClass::from(frasil_base::ErrorClass::Pending);
        let genesis = source.genesis().clone();
        let genesis_id = genesis.id();
        let mut log = Log::new(genesis).map_err(RosterClass::from)?;
        let mut allowed: BTreeSet<EventId> = members.clone();
        allowed.insert(root);
        allowed.remove(&genesis_id);
        let mut order: Vec<(u64, EventId)> = Vec::with_capacity(allowed.len());
        for &id in &allowed {
            let height = source.height(id).ok_or_else(pending)?;
            source.event(id).ok_or_else(pending)?;
            order.push((height, id));
        }
        order.sort_unstable();
        // Each outside parent, at the lowest height it must stand at.
        let mut outside: BTreeMap<EventId, u64> = BTreeMap::new();
        for &(_, id) in &order {
            let event = source.event(id).expect("checked above");
            for &parent in event.parents() {
                if parent == genesis_id || allowed.contains(&parent) {
                    continue;
                }
                let height = u64::from(id != root);
                outside
                    .entry(parent)
                    .and_modify(|h| *h = (*h).min(height))
                    .or_insert(height);
            }
        }
        for (id, height) in outside {
            log.add_stub(Stub {
                id,
                author: DeviceId([0; 32]),
                seq: 1,
                height,
                kind: kind::ANCHOR,
                cuts: Cuts::NONE,
            });
        }
        for &(_, id) in &order {
            let event = source.event(id).expect("checked above").clone();
            log.place(event).map_err(RosterClass::from)?;
        }
        let mut view = allowed;
        view.insert(genesis_id);
        if !view.iter().all(|&id| log.contains(id)) {
            return Err(pending());
        }
        Ok(Self { log, root, view })
    }

    /// Adds events of `source` placed after the world was built, each
    /// following the root: the log a [`WorldLog::new`] over the larger
    /// set of members builds. Each parent outside the world stands as a
    /// stub at height 1, as there.
    ///
    /// # Errors
    ///
    /// `Pending` when an event is not placed in `source`, or does not
    /// place here.
    pub fn append(&mut self, source: &Log, added: &[EventId]) -> Result<(), RosterClass> {
        let pending = || RosterClass::from(frasil_base::ErrorClass::Pending);
        let genesis_id = self.log.id();
        let mut order: Vec<(u64, EventId)> = Vec::with_capacity(added.len());
        for &id in added {
            if self.view.contains(&id) {
                continue;
            }
            order.push((source.height(id).ok_or_else(pending)?, id));
        }
        order.sort_unstable();
        let joining: BTreeSet<EventId> = order.iter().map(|&(_, id)| id).collect();
        for &(_, id) in &order {
            let event = source.event(id).ok_or_else(pending)?;
            for &parent in event.parents() {
                if parent == genesis_id
                    || self.view.contains(&parent)
                    || joining.contains(&parent)
                    || self.log.contains(parent)
                    || self.log.stub(parent).is_some()
                {
                    continue;
                }
                self.log.add_stub(Stub {
                    id: parent,
                    author: DeviceId([0; 32]),
                    seq: 1,
                    height: 1,
                    kind: kind::ANCHOR,
                    cuts: Cuts::NONE,
                });
            }
        }
        for &(_, id) in &order {
            let event = source.event(id).ok_or_else(pending)?.clone();
            self.log.place(event).map_err(RosterClass::from)?;
            if !self.log.contains(id) {
                return Err(pending());
            }
            self.view.insert(id);
        }
        Ok(())
    }

    /// The log.
    pub fn log(&self) -> &Log {
        &self.log
    }

    /// The checkpoint, the world's root.
    pub fn root(&self) -> EventId {
        self.root
    }

    /// The events of the world, with the genesis.
    pub fn view(&self) -> &BTreeSet<EventId> {
        &self.view
    }

    /// The checkpoint's height in this log: what heights in the world are
    /// counted above.
    pub fn height_offset(&self) -> u64 {
        self.log.height(self.root).unwrap_or(0)
    }

    /// Resolves the world under `record`, the checkpoint's, with the
    /// verdicts decided before the procedure.
    ///
    /// # Errors
    ///
    /// As [`Space::resolve`]: a replica that cannot use the genesis cannot
    /// use the space.
    pub fn resolve<'a>(
        &'a self,
        options: Options<'a>,
        record: &Record,
        presets: BTreeMap<EventId, Status>,
    ) -> Result<Space<'a>, RosterClass> {
        self.resolve_with_skeleton(options, record, presets, None)
    }

    /// As [`Self::resolve`], reading twins against `skeleton` when the
    /// replica checks them: the skeleton after the checkpoint's cut over
    /// the skeleton events after the checkpoint, built over the replica's
    /// own log, which holds the cut and the enrolments it names (roster.md,
    /// 3.15.5 The world after a checkpoint, Skeleton;
    /// [`frasil_peers::skeleton::Skeleton::after_cut`]). With `None`, the
    /// skeleton of the world's own log.
    ///
    /// # Errors
    ///
    /// As [`Self::resolve`].
    pub fn resolve_with_skeleton<'a>(
        &'a self,
        options: Options<'a>,
        record: &Record,
        presets: BTreeMap<EventId, Status>,
        skeleton: Option<frasil_peers::skeleton::Skeleton<'a>>,
    ) -> Result<Space<'a>, RosterClass> {
        let world = WorldRoot::from_record(self.log.id(), self.root, record, self.height_offset());
        Space::resolve_checkpointed_with_skeleton(
            &self.log,
            Some(&self.view),
            options,
            Checkpointing {
                presets,
                world: Some(world),
            },
            skeleton,
        )
    }
}

/// Each author's fork point in a checkpoint's world (roster.md, 3.15.5):
/// the evidence among the world's own events, the genesis left out; an
/// author with a fork point in the record forked from that `seq`; and an
/// author with an event after the checkpoint at or below its tip in the
/// record forked from that event's `seq`.
pub fn world_forks(
    log: &Log,
    view: &BTreeSet<EventId>,
    world: &WorldRoot,
    screened: &ScreenedLog,
) -> ForkPoints {
    let genesis = log.id();
    let own: BTreeSet<EventId> = view.iter().copied().filter(|&id| id != genesis).collect();
    let evidence =
        log.fork_points_counting(&own, |id| id != genesis && screened.counts_as_evidence(id));
    let mut points: BTreeMap<DeviceId, u64> = evidence.iter().map(|(a, p)| (*a, p)).collect_map();
    let mut lower = |author: DeviceId, seq: u64| {
        points
            .entry(author)
            .and_modify(|point| *point = (*point).min(seq))
            .or_insert(seq);
    };
    for (&author, &seq) in &world.forks {
        lower(author, seq);
    }
    let tips = &world.tips;
    for &id in &own {
        if id == world.root {
            continue;
        }
        let Some(event) = log.event(id) else {
            continue;
        };
        if let Some(&(tip, _)) = tips.get(event.author())
            && event.seq() <= tip
        {
            lower(*event.author(), event.seq());
        }
    }
    ForkPoints::from_points(points)
}
