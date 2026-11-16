//! The outbox (units.md, "Heads, acknowledgements and durability";
//! at-rest.md, "Tables").
//!
//! An event a signer of this device signed stays in the outbox until
//! it is **durable**: an always-on peer of the space has acknowledged it,
//! or, in a space with no always-on peer, another member has. Until then
//! it is offered again on every connection. The device keeps, per space,
//! the heads each peer last acknowledged; a peer that later lacks an event
//! it acknowledged is rolling back (`RolledBack`).
//!
//! It also keeps what detected loss reads (units.md, 3.13 "Detected
//! loss"): the state each peer last served, and the heads of head
//! statements a peer answered `Missing` for.

use frasil_base::collect::CollectMap;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, kind};
use frasil_units::limits::MAX_MESSAGE_ITEMS;
use frasil_units::messages::VectorEntry;
use std::collections::{BTreeMap, BTreeSet};

/// What a client reports against a peer or a member (units.md, 3.13
/// "Detected loss", "Head statements"; 3.18 Error classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LossClass {
    /// `Withheld`: a peer served less than the client knows of.
    Withheld,
    /// `RolledBack`: a peer, or in a space with no always-on peer a
    /// member, lacks events it acknowledged.
    RolledBack,
    /// `BadStatement`: a member's head statement whose heads its author
    /// could not supply.
    BadStatement,
}

impl LossClass {
    /// The class's name, as units.md writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Withheld => "Withheld",
            Self::RolledBack => "RolledBack",
            Self::BadStatement => "BadStatement",
        }
    }
}

/// One report of detected loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    /// The space.
    pub space: EventId,
    /// The peer or member it is reported against.
    pub by: Acknowledger,
    /// The class.
    pub class: LossClass,
    /// The events lacking, or the statement's heads; empty for a stream a
    /// peer's `StreamHeads` withheld.
    pub events: Vec<EventId>,
}

/// A peer's state as its `Heads` show it (units.md, 3.13 "Detected loss"):
/// the past of its heads, once the client holds them all, and per author
/// the first `seq` events its vector names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Served {
    /// The heads it sent.
    pub heads: Vec<EventId>,
    /// Its vector, if it sent one.
    pub vector: Option<Vec<VectorEntry>>,
}

impl Served {
    /// Whether the log holds every head, so that the past of the heads is
    /// the whole state. A message of the most heads may have been split,
    /// and is never whole.
    pub fn whole(&self, log: &Log) -> bool {
        self.heads.len() < MAX_MESSAGE_ITEMS && self.heads.iter().all(|h| log.contains(*h))
    }

    /// The events of `of` this state lacks: outside the past of the heads
    /// when it is whole; otherwise those its vector shows it lacks, an
    /// author's event above the greatest `seq` it names, or of an author
    /// a vector that was not cut short leaves out.
    pub fn lacking(&self, log: &Log, of: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        if self.whole(log) {
            let state = past_of(log, &self.heads);
            return of.difference(&state).copied().collect();
        }
        let Some(vector) = &self.vector else {
            return BTreeSet::new();
        };
        let complete = vector.len() < MAX_MESSAGE_ITEMS;
        let greatest: BTreeMap<DeviceId, u64> = vector
            .iter()
            .map(|entry| (entry.author, entry.seq))
            .collect_map();
        of.iter()
            .filter(|id| {
                log.event(**id)
                    .is_some_and(|event| match greatest.get(event.author()) {
                        Some(seq) => *seq < event.seq(),
                        None => complete,
                    })
            })
            .copied()
            .collect()
    }
}

/// The heads and every event in their past that the log holds.
pub(crate) fn past_of(log: &Log, heads: &[EventId]) -> BTreeSet<EventId> {
    let mut past = BTreeSet::new();
    for head in heads {
        if log.contains(*head) {
            past.insert(*head);
            past.extend(log.past(*head));
        }
    }
    past
}

/// Of these events, those whose absence from a peer's state shows a loss:
/// held whole, and none a peer stops listing without loss. A peer lists
/// no administration storage event on space traffic (peers.md,
/// "Administration connections"), no unit of a released stream (peers.md,
/// 3.18 Release and restore) and nothing an erasure dropped; so storage
/// events, the units of a stream any release or restore names, and, once
/// the log holds an erasure, every unit, are left out.
pub(crate) fn judged(log: &Log, ids: impl IntoIterator<Item = EventId>) -> BTreeSet<EventId> {
    use frasil_peers::body::{Restored, StorageBody};
    let mut released: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut erased = false;
    for event in log.frame_events().filter(|e| e.kind() == kind::STORAGE) {
        match StorageBody::read(event.unverified_body()) {
            Ok(
                StorageBody::Release { stream } | StorageBody::Restore(Restored::Stream(stream)),
            ) => {
                released.insert(stream);
            }
            Ok(StorageBody::Erase) => erased = true,
            _ => {}
        }
    }
    ids.into_iter()
        .filter(|id| {
            log.event(*id).is_some_and(|event| match event.kind() {
                kind::STORAGE => false,
                kind::UNIT if erased => false,
                kind::UNIT if !released.is_empty() => frasil_units::Unit::from_event(event.clone())
                    .is_ok_and(|unit| !released.contains(&unit.body.stream)),
                _ => true,
            })
        })
        .collect()
}

/// Who acknowledged heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Acknowledger {
    /// An always-on peer, by its stable endpoint key.
    Peer([u8; 32]),
    /// Another member, by its device ID.
    Member([u8; 32]),
}

impl Acknowledger {
    /// The ID its `ack` record is kept under.
    pub fn id(&self) -> [u8; 32] {
        match self {
            Self::Peer(id) | Self::Member(id) => *id,
        }
    }

    /// The same ID as the other kind: an `ack` record names no kind, and
    /// is read back as a member's.
    fn other(&self) -> Self {
        match self {
            Self::Peer(id) => Self::Member(*id),
            Self::Member(id) => Self::Peer(*id),
        }
    }
}

/// An outbox entry: an event's author and `seq`, and the event.
pub type OutboxEntry = ((DeviceId, u64), EventId);

/// One space's outbox and acknowledgements at this device.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    /// Events not yet durable, by author and `seq`.
    entries: BTreeMap<(DeviceId, u64), EventId>,
    /// The heads each peer or member last acknowledged.
    acks: BTreeMap<Acknowledger, Vec<EventId>>,
    /// Heads an acknowledgement named that the log did not hold yet, by
    /// acknowledger: taken once they are placed ([`Outbox::now_held`]).
    awaiting: BTreeMap<Acknowledger, Vec<EventId>>,
    /// The heads each peer last served whole, while the device runs
    /// (units.md, 3.13 "Detected loss").
    served: BTreeMap<Acknowledger, Vec<EventId>>,
    /// Heads of head statements a peer answered `Missing` for, by head,
    /// then by peer (units.md, 3.13 "Head statements").
    stated_missing: BTreeMap<EventId, BTreeMap<Acknowledger, StatedMissing>>,
}

/// A peer's `Missing` answers for one head statement's head, as readings
/// of the device's timeline in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatedMissing {
    /// Its first `Missing` for the head.
    first: u64,
    /// Its latest.
    last: u64,
}

impl Outbox {
    /// Adds an event this device signed.
    pub fn add(&mut self, author: DeviceId, seq: u64, id: EventId) {
        self.entries.insert((author, seq), id);
    }

    /// The events not yet durable, by author and `seq`.
    pub fn pending(&self) -> impl Iterator<Item = (&(DeviceId, u64), &EventId)> {
        self.entries.iter()
    }

    /// Whether an event is still in the outbox.
    pub fn holds(&self, id: &EventId) -> bool {
        self.entries.values().any(|held| held == id)
    }

    /// The heads an acknowledger last acknowledged: under its kind, or,
    /// as read back from an `ack` record, under the other.
    pub fn acknowledged(&self, by: &Acknowledger) -> Option<&[EventId]> {
        self.acks
            .get(by)
            .or_else(|| self.acks.get(&by.other()))
            .map(Vec::as_slice)
    }

    /// Every event an acknowledger acknowledged that the log holds: its
    /// heads and their past.
    pub fn acknowledged_past(&self, log: &Log, by: &Acknowledger) -> BTreeSet<EventId> {
        self.acknowledged(by)
            .map(|heads| past_of(log, heads))
            .unwrap_or_default()
    }

    /// The heads a peer last served whole.
    pub fn served(&self, by: &Acknowledger) -> Option<&[EventId]> {
        self.served.get(by).map(Vec::as_slice)
    }

    /// Keeps the heads a peer served whole.
    pub fn set_served(&mut self, by: Acknowledger, heads: Vec<EventId>) {
        self.served.insert(by, heads);
    }

    /// Notes that a peer answered `Missing` for a statement's head, at
    /// `now` on the device's timeline. Returns whether it is the peer's
    /// first `Missing` for the head, after which the device asks it again
    /// once `withholding_grace` has passed (units.md, 3.13 "Head
    /// statements").
    pub fn note_stated_missing(&mut self, head: EventId, by: Acknowledger, now: u64) -> bool {
        let answers = self.stated_missing.entry(head).or_default();
        match answers.get_mut(&by) {
            Some(missing) => {
                missing.last = missing.last.max(now);
                false
            }
            None => {
                answers.insert(
                    by,
                    StatedMissing {
                        first: now,
                        last: now,
                    },
                );
                true
            }
        }
    }

    /// The statements' heads a peer answered `Missing` for at least
    /// `grace` ago, at `now`, and not again since: the heads to ask it
    /// for again, while the device lacks them.
    pub fn stated_due(&self, by: &Acknowledger, now: u64, grace: u64) -> Vec<EventId> {
        self.stated_missing
            .iter()
            .filter(|(_, answers)| {
                answers.get(by).is_some_and(|missing| {
                    missing.last.saturating_sub(missing.first) < grace
                        && now.saturating_sub(missing.first) >= grace
                })
            })
            .map(|(head, _)| *head)
            .collect()
    }

    /// The statements' heads a peer answered `Missing` for that the log
    /// now holds, by peer, judged with `withholding_grace` (units.md, 3.13
    /// "Head statements"): a peer that had acknowledged a head, or whose
    /// `Missing` answers for it span `grace`, served less (`Withheld`);
    /// any other answer is forgotten, since the device now sends the head
    /// to that peer itself.
    pub fn stated_supplied(&mut self, log: &Log, grace: u64) -> Vec<(Acknowledger, Vec<EventId>)> {
        let held: Vec<EventId> = self
            .stated_missing
            .keys()
            .copied()
            .filter(|head| log.contains(*head))
            .collect();
        let mut out: BTreeMap<Acknowledger, Vec<EventId>> = BTreeMap::new();
        for head in held {
            let Some(answers) = self.stated_missing.remove(&head) else {
                continue;
            };
            for (by, missing) in answers {
                let acknowledged = self.acknowledged_past(log, &by).contains(&head);
                let outcome = frasil_units::decisions::statement_outcome(
                    false,
                    true,
                    acknowledged,
                    missing.last.saturating_sub(missing.first),
                    grace,
                );
                if outcome == frasil_units::decisions::StatementOutcome::WithheldByPeer {
                    out.entry(by).or_default().push(head);
                }
            }
        }
        out.into_iter().collect()
    }

    /// Takes back what an acknowledger lost (units.md, 3.13 "A restored
    /// peer"): of `lost`, the events `own` names are not durable again and
    /// return to the outbox; the acknowledgement keeps only what is not
    /// lost nor rests on what is. Returns the entries that returned, and
    /// the heads the acknowledgement keeps, none when nothing is left.
    pub fn roll_back(
        &mut self,
        log: &Log,
        by: Acknowledger,
        lost: &BTreeSet<EventId>,
        own: impl Fn(&Event) -> bool,
    ) -> (Vec<OutboxEntry>, Vec<EventId>) {
        let acked = self.acknowledged_past(log, &by);
        let mut gone: BTreeSet<EventId> = BTreeSet::new();
        for id in log.canonical() {
            if !acked.contains(&id) {
                continue;
            }
            if lost.contains(&id)
                || log
                    .event(id)
                    .is_some_and(|event| event.parents().iter().any(|p| gone.contains(p)))
            {
                gone.insert(id);
            }
        }
        let kept: BTreeSet<EventId> = acked.difference(&gone).copied().collect();
        let mut cited: BTreeSet<EventId> = BTreeSet::new();
        for id in &kept {
            if let Some(event) = log.event(*id) {
                cited.extend(event.parents().iter().copied());
            }
        }
        let heads: Vec<EventId> = kept
            .iter()
            .filter(|id| !cited.contains(id))
            .copied()
            .collect();
        self.acks.remove(&by.other());
        if heads.is_empty() {
            self.acks.remove(&by);
        } else {
            self.acks.insert(by, heads.clone());
        }
        let mut returned = Vec::new();
        for id in &gone {
            let Some(event) = log.event(*id) else {
                continue;
            };
            if !own(event) || self.holds(id) {
                continue;
            }
            let key = (*event.author(), event.seq());
            self.entries.insert(key, *id);
            returned.push((key, *id));
        }
        (returned, heads)
    }

    /// Restores an acknowledgement kept at rest.
    pub fn keep_ack(&mut self, by: Acknowledger, heads: Vec<EventId>) {
        self.acks.insert(by, heads);
    }

    /// Takes an acknowledgement: the events in the past of `heads` that the
    /// log holds are durable at `by`. A peer's acknowledgement makes them
    /// durable; a member's does when `members_count` (a space with no
    /// always-on peer). Returns the outbox entries now durable, which the
    /// device deletes from the store.
    ///
    /// Heads the log does not hold yet, such as an event the acknowledger
    /// signed after it stored this device's, wait until they are placed
    /// ([`Outbox::now_held`]).
    pub fn acknowledge(
        &mut self,
        log: &Log,
        by: Acknowledger,
        heads: &[EventId],
        members_count: bool,
    ) -> Vec<((DeviceId, u64), EventId)> {
        let (held, unheld): (Vec<EventId>, Vec<EventId>) =
            heads.iter().copied().partition(|h| log.contains(*h));
        if !unheld.is_empty() {
            self.awaiting.insert(by, unheld);
        }
        if held.is_empty() {
            return Vec::new();
        }
        self.acks.insert(by, held.clone());
        if matches!(by, Acknowledger::Member(_)) && !members_count {
            return Vec::new();
        }
        let mut stored: BTreeSet<EventId> = BTreeSet::new();
        for head in &held {
            stored.insert(*head);
            stored.extend(log.past(*head));
        }
        let durable: Vec<((DeviceId, u64), EventId)> = self
            .entries
            .iter()
            .filter(|(_, id)| stored.contains(id))
            .map(|(key, id)| (*key, *id))
            .collect();
        for (key, _) in &durable {
            self.entries.remove(key);
        }
        durable
    }

    /// The heads awaited by [`Outbox::acknowledge`] that the log now holds,
    /// by acknowledger, which the device takes as acknowledgements again.
    pub fn now_held(&mut self, log: &Log) -> Vec<(Acknowledger, Vec<EventId>)> {
        let mut now = Vec::new();
        self.awaiting.retain(|by, heads| {
            let (held, unheld): (Vec<EventId>, Vec<EventId>) =
                heads.iter().copied().partition(|h| log.contains(*h));
            if !held.is_empty() {
                now.push((*by, held));
            }
            *heads = unheld;
            !heads.is_empty()
        });
        now
    }

    /// Events an acknowledger acknowledged that `served` now lacks: a peer
    /// that lost what it acknowledged (`RolledBack`).
    pub fn rolled_back(
        &self,
        log: &Log,
        by: &Acknowledger,
        served: &BTreeSet<EventId>,
    ) -> Vec<EventId> {
        self.acknowledged_past(log, by)
            .difference(served)
            .copied()
            .collect()
    }
}
