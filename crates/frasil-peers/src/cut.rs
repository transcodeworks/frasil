//! Skeleton cuts and truncation (peers.md, "Skeleton cuts" and
//! "Truncation").
//!
//! A space checkpoint (roster.md, "Checkpoints") names, as its twin, a
//! **cut**: a skeleton event of type 7 its author's pseudonym signs first,
//! carrying every administrator slot in at that point, the standing of the
//! checkpoint's electorate, the locator of the checkpoint's record object
//! and an epoch. A peer cannot open the checkpoint, but it reads from
//! envelopes which events follow it (events.md, "Cuts"), and so starts the
//! skeleton afresh from the cut once the slots it waits for have voted or
//! are excused.
//!
//! - [`PeerCuts`] judges each cut a peer holds on its own past ([`PeerCuts::
//!   validity`]), in the specified order (peers.md, 3.21): `Unnamed` until a
//!   stored space event names it, cites it and has every other parent in
//!   its past, `CutPending` for a wrong epoch, a checkpoint that does not
//!   follow the last cut in effect in its past or reaches one concurrent
//!   with it, or a cut made before an earlier one took effect,
//!   `NotAnAdministrator` when its author's slot is not in, enrolled to it,
//!   in the merged skeleton of its past, `BadSignature` unless it verifies
//!   under the key of the root or enrolment that enrolled it there, and
//!   `BadCut` when its slots are not exactly those of that skeleton or its
//!   standing entries are not consistent with each other. It finds the chain of cuts in effect, and resolves the
//!   skeleton from the last one ([`PeerCuts::skeleton`]).
//! - [`check_against_record`] and [`check_standing`] are a replica's checks
//!   of a cut against its checkpoint's record (roster.md, "Checkpoints",
//!   twins and the skeleton); [`standing_entries`] gives the standing
//!   entries a record's administrators and heard members make.
//! - [`stable_past`] and [`acknowledged_past`] judge the erasures and
//!   credentials requests of a cut's past, which keep the verdict and
//!   stability of the skeleton before the cut, a slot of the cut also
//!   acknowledging them through its pseudonym in the world after it;
//! - [`PeerCuts::request_state`] says whether an erasure, a credentials
//!   request or a release may be carried out or reclaimed, waits for a cut
//!   concurrent with it that can still take effect, or is late (peers.md,
//!   "Erasure", steps 0 and 1);
//! - [`PeerCuts::released`] says whether a stream is released, reading only
//!   what a peer that truncated still holds (peers.md, "Release and
//!   restore");
//! - [`may_truncate`], [`requests_settled`] and
//!   [`PeerCuts::truncation_plan`] say when a peer may truncate under a cut
//!   in effect and what it may then delete; [`PeerEnvelopes`],
//!   [`placeable`] and [`answer_want`] are what a peer that truncated reads
//!   and answers.
//!
//! A slot entry names the root or enrolment that enrolled its pseudonym by
//! event ID: the peer holds that event in the cut's past and keeps it when
//! it truncates ([`always_kept`]), so the world after the cut reads the
//! pseudonym's key from it.
//!
//! # Votes and effect
//!
//! A cut **waits** for each slot of a standing entry whose `dormant` is 0:
//! the checkpoint's electorate as its record gives it. A **vote** for the
//! cut is a skeleton event that follows the cut's checkpoint and whose cuts
//! reach no checkpoint concurrent with it, exclusive as a device's is,
//! signed by a pseudonym of the slot it votes for: the one the cut's slot
//! entry names, one whose enrolment of that slot follows the checkpoint (the
//! enrolment is itself a vote), or, for a slot that is out, the one whose
//! root or enrolment its standing entry names. A waited slot is **excused**
//! by a lower or disown of it that follows the checkpoint and reaches no
//! checkpoint concurrent with it, signed by a pseudonym of the slot itself,
//! of a slot of the cut with a lower order, or of a recovery slot of the cut
//! of at least its rank. Each signature, a
//! vote's or a lowering's, counts once the peer verifies it under a key it
//! holds, whatever the resolution decides of the event. A member with no
//! slot has no standing entry: the cut neither waits for it nor lets it
//! excuse.
//!
//! The cut is **in effect at the peer** when every slot it waits for has a
//! vote or is excused ([`PeerCuts::tally`]). Validity is final, and votes
//! and excuses only accumulate, so a cut in effect over some events is in
//! effect over every set that holds them; only the choice among cuts in
//! effect can move, to a concurrent one of the same epoch with a smaller
//! checkpoint ID. This is one function of the skeleton
//! events: a peer applies it to what it holds, and a client to what its view
//! holds. Starting from no cut, or from the cut a peer kept when it
//! truncated, a peer takes, among the valid cuts in effect of the next epoch
//! whose checkpoints follow the current one's, the one whose checkpoint has
//! the smallest event ID, and repeats ([`PeerCuts::chain`]).
//!
//! # The skeleton after a cut
//!
//! The cut stands as the skeleton's root: its slots are in from the start,
//! each enrolled to the pseudonym its entry carries, and keep their
//! references, seniority and rank. Heights count from the cut; a slot made after
//! it has the seniority `(epoch, height, hash, maker)`. The 4,096 bound,
//! stability and the planted-slot count read the cut's world only, so a
//! lowering in the cut's past is settled. With no cut in effect, the
//! skeleton is exactly [`Skeleton::new`]'s.
//!
//! # Late skeleton events
//!
//! With a cut in effect, a skeleton event other than a cut that is neither
//! in the cut's past nor follows its checkpoint is late at the peer
//! ([`PeerCuts::late`]): the peer stores it once its body reads, and gives
//! it no effect. It is `Late` in the world's skeleton, outside its order,
//! never verified and never fork evidence; a late enrolment's pseudonym may
//! present its credential, and is enrolled in no slot. A late enrolment is
//! stored only with `seq` 1 and an author the peer holds no root or
//! enrolment of before it (else `BadSignature`), keys that hash to its `kc`
//! (else `NotCommitted`) and a signature that verifies under them (else
//! `BadSignature`). Lateness follows the cut in effect: an event a later cut
//! no longer makes late is judged as any other in that cut's world. A cut
//! keeps its own checks wherever it stands.
//!
//! A release or restore late under any cut of the chain counts for nothing
//! under that cut and every later one, though a later checkpoint's past
//! holds it ([`PeerCuts::late_under_chain`]): [`PeerCuts::released`],
//! [`PeerCuts::request_state`] and the truncation's keep-set
//! ([`PeerCuts::kept_requests`]) read it alike.
//!
//! # Entries and accounting
//!
//! A cut changes no credential entry ([`crate::entries`]): an entry of a
//! rotation in the cut's past stays as it was, so a member offline across
//! the cut catches up with its retired read credential. Deleted bytes leave
//! usage when the peer deletes them ([`TruncationPlan::deleted_bytes`]).

use crate::PeersClass;
use crate::body::{
    ChangeEffect, Cut, Restored, SlotEntry, SlotId, StandingEntry, StorageBody, StorageType,
    check_size,
};
use crate::derive::{enrol_statement, verify_slot};
use crate::limits::MAX_RANK;
use crate::skeleton::{Clock, Skeleton, Status, named_twin};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_base::time::{Reading, lower};
use frasil_crypto::device::{DeviceId, HybridKeys};
use frasil_crypto::primitives::sha256;
use frasil_events::cuts::{self as event_cuts, HeldEnvelopes};
use frasil_events::{Event, EventId, Log, kind};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

/// A cut's body, if the event is a storage event of type 7 within the size
/// limit.
pub fn read_cut(event: &Event) -> Option<Cut> {
    if event.kind() != kind::STORAGE || check_size(event.signed_len()).is_err() {
        return None;
    }
    match StorageBody::read(event.unverified_body()).ok()? {
        StorageBody::Cut(cut) => Some(cut),
        _ => None,
    }
}

/// A storage event's body, if it reads within the size limit.
fn read_storage(event: &Event) -> Option<StorageBody> {
    if event.kind() != kind::STORAGE || check_size(event.signed_len()).is_err() {
        return None;
    }
    StorageBody::read(event.unverified_body()).ok()
}

/// The device ID of the pseudonym a slot entry names: the author of the
/// root or enrolment its `pseudonym` names, which `log` holds. None when
/// none is enrolled, or the log does not hold that event.
pub fn entry_pseudonym(log: &Log, entry: &SlotEntry) -> Option<DeviceId> {
    let event = log.event(entry.pseudonym?)?;
    Some(*event.author())
}

/// The ML-DSA-65 key a root or an enrolment carries for its own author,
/// when it hashes to the event's `kc` beside an empty X-Wing key.
fn own_key(event: &Event) -> Option<HybridKeys> {
    let mldsa = match read_storage(event)? {
        StorageBody::Root { mldsa, .. } | StorageBody::Enrol { mldsa, .. } => mldsa,
        _ => return None,
    };
    HybridKeys::new(&mldsa, None)
        .ok()
        .filter(|keys| keys.commitment() == event.kc())
}

/// The ML-DSA-65 key a root or enrolment by `event`'s author carries for it,
/// among the events `held` accepts, when it commits to `event`'s `kc`
/// (peers.md, "What a peer checks before it stores a skeleton event", step
/// 4: the key of a pseudonym whose root or enrolment the peer holds).
pub fn pseudonym_key(
    log: &Log,
    event: &Event,
    held: impl Fn(EventId) -> bool,
) -> Option<HybridKeys> {
    log.chain(event.author())
        .into_iter()
        .filter(|&id| held(id))
        .filter_map(|id| log.event(id))
        .find_map(|x| own_key(x).filter(|keys| keys.commitment() == event.kc()))
}

/// peers.md, "What a peer checks before it stores a skeleton event", step 4
/// as a refusal: when the peer holds a root or enrolment of the event's
/// author among the events `held` accepts, the event verifies under that
/// pseudonym's ML-DSA-65 key. An event whose author it holds no key for is
/// stored with no effect, never refused for that (section 3.11, "No refusal
/// for standing").
///
/// # Errors
///
/// `BadSignature`.
pub fn check_held_key(
    log: &Log,
    event: &Event,
    held: impl Fn(EventId) -> bool,
) -> Result<(), PeersClass> {
    match pseudonym_key(log, event, held) {
        Some(key) if log.verify_hybrid_remembered(event, Some(&key)).is_err() => {
            Err(ErrorClass::BadSignature.into())
        }
        _ => Ok(()),
    }
}

/// What may be done with an erasure, a credentials request or a release at
/// the peer while cuts are pending (peers.md, "Erasure", steps 0 and 1;
/// "Release and restore", step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Late under a cut of the chain in effect, though a later
    /// checkpoint's past may hold it: void, and a release or restore counts
    /// for nothing.
    Late,
    /// Concurrent with a valid cut that can still take effect: it waits
    /// until that cut takes effect, which makes it late, or can no longer
    /// take effect.
    Wait,
    /// Neither: stability or the timeout decides.
    Free,
}

/// What a cut waits for at the peer (peers.md, "Skeleton cuts", waited and
/// excused slots, votes, in effect at the peer), over the events a peer
/// holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// The slots the cut waits for: those of its standing entries whose
    /// `dormant` is 0, ascending.
    pub waited: Vec<SlotId>,
    /// For each waited slot, the lowerings that excuse it; empty for a slot
    /// not excused.
    pub excuses: BTreeMap<SlotId, BTreeSet<EventId>>,
    /// For each waited slot that is not excused, its verified votes: those
    /// that count.
    pub votes: BTreeMap<SlotId, Vec<EventId>>,
    /// For each waited slot that is not excused, every vote for it; since
    /// every verified vote counts, the same as `votes`.
    pub all_votes: BTreeMap<SlotId, Vec<EventId>>,
    /// The pseudonyms that vote for each slot of a standing entry.
    pub voters: BTreeMap<SlotId, BTreeSet<DeviceId>>,
}

impl Tally {
    /// The waited slots that are neither excused nor have a vote that
    /// counts: whom the cut waits for.
    pub fn awaiting(&self) -> Vec<SlotId> {
        self.waited
            .iter()
            .copied()
            .filter(|slot| self.excuses.get(slot).is_none_or(BTreeSet::is_empty))
            .filter(|slot| self.votes.get(slot).is_none_or(Vec::is_empty))
            .collect()
    }

    /// Whether the cut is in effect, its validity aside: it waits for
    /// nobody.
    pub fn in_effect(&self) -> bool {
        self.awaiting().is_empty()
    }

    /// Every lowering that excuses a waited slot.
    pub fn excusing(&self) -> BTreeSet<EventId> {
        self.excuses.values().flatten().copied().collect()
    }
}

/// Vote and excuse counters retained across resolutions of one append-only
/// log (peers.md, "What 512 administrators cost"). Each new vote looks up
/// its pseudonym's slots once. Clear this cache before replacing envelopes,
/// adding witnesses or stubs, forgetting events, or reading another log.
#[derive(Debug, Default)]
pub struct CutTallies {
    held: std::sync::Mutex<BTreeMap<EventId, RetainedTally>>,
}

impl Clone for CutTallies {
    fn clone(&self) -> Self {
        Self {
            held: std::sync::Mutex::new(
                self.held
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
            ),
        }
    }
}

impl CutTallies {
    /// Clears counters after a change other than appending placed events.
    pub fn clear(&self) {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
    fn read<T>(
        &self,
        cuts: &PeerCuts<'_>,
        cut: EventId,
        read: impl FnOnce(&RetainedTally) -> T,
    ) -> Option<T> {
        // A caller may also read a restricted view with the same cache.
        if cuts.held.len() != cuts.log.len() {
            return None;
        }
        let checkpoint = cuts.checkpoint_of(cut)?;
        let mut counters = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let added = counters.get(&cut).and_then(|counter| {
            (counter.checkpoint == checkpoint
                && counter.mark <= cuts.log.placed_count()
                && counter.last
                    == counter
                        .mark
                        .checked_sub(1)
                        .and_then(|mark| cuts.log.placed_since(mark).first().copied()))
            .then(|| cuts.log.placed_since(counter.mark))
        });
        let reset = added.is_none();
        if reset {
            counters.insert(cut, RetainedTally::new(cuts, cut)?);
        } else {
            counters.get_mut(&cut)?.advance(cuts, cut, added?);
        }
        Some(read(counters.get(&cut)?))
    }
}

// Optional dispatch lets snapshot readers omit the retained-counter implementation.
trait TallySource: Send + Sync {
    fn tally(&self, cuts: &PeerCuts<'_>, cut: EventId) -> Option<Tally>;
    fn in_effect(&self, cuts: &PeerCuts<'_>, cut: EventId) -> Option<bool>;
}

impl TallySource for CutTallies {
    fn tally(&self, cuts: &PeerCuts<'_>, cut: EventId) -> Option<Tally> {
        self.read(cuts, cut, |counter| counter.tally.clone())
    }

    fn in_effect(&self, cuts: &PeerCuts<'_>, cut: EventId) -> Option<bool> {
        self.read(cuts, cut, |counter| counter.awaiting.is_empty())
    }
}

#[derive(Debug, Clone)]
struct RetainedTally {
    checkpoint: EventId,
    mark: usize,
    last: Option<EventId>,
    tally: Tally,
    slots: BTreeMap<SlotId, SlotEntry>,
    standing: BTreeMap<SlotId, StandingEntry>,
    ranks: BTreeMap<SlotId, Option<u8>>,
    by_author: BTreeMap<DeviceId, BTreeSet<SlotId>>,
    named_voters: BTreeMap<EventId, BTreeSet<SlotId>>,
    missing_ranks: BTreeMap<EventId, Vec<SlotId>>,
    missing_grants: BTreeMap<EventId, BTreeSet<EventId>>,
    missing_cuts: BTreeMap<EventId, BTreeSet<EventId>>,
    lowerings: BTreeMap<SlotId, BTreeSet<EventId>>,
    seen: BTreeSet<(EventId, SlotId)>,
    awaiting: BTreeSet<SlotId>,
}

impl RetainedTally {
    fn new(cuts: &PeerCuts<'_>, cut: EventId) -> Option<Self> {
        let body = cuts.body(cut)?;
        let tally = cuts.tally_within(cut, &cuts.held)?;
        let slots: BTreeMap<_, _> = body.slots.iter().map(|x| (x.slot, x.clone())).collect();
        let standing: BTreeMap<_, _> = body.standing.iter().map(|x| (x.slot, *x)).collect();
        let ranks: BTreeMap<_, _> = standing
            .keys()
            .map(|&slot| {
                (
                    slot,
                    slots
                        .get(&slot)
                        .map(|entry| entry.rank)
                        .or_else(|| cuts.granted(slot).map(|(_, _, rank)| rank)),
                )
            })
            .collect();
        let mut by_author: BTreeMap<DeviceId, BTreeSet<SlotId>> = BTreeMap::new();
        for (&slot, authors) in &tally.voters {
            for &author in authors {
                by_author.entry(author).or_default().insert(slot);
            }
        }
        let mut named_voters: BTreeMap<EventId, BTreeSet<SlotId>> = BTreeMap::new();
        for (slot, pseudonym) in body
            .slots
            .iter()
            .map(|x| (x.slot, x.pseudonym))
            .chain(body.standing.iter().map(|x| (x.slot, x.pseudonym)))
        {
            if let Some(id) = pseudonym
                && tally.voters.contains_key(&slot)
            {
                named_voters.entry(id).or_default().insert(slot);
            }
        }
        let mut missing_ranks: BTreeMap<EventId, Vec<SlotId>> = BTreeMap::new();
        for (&slot, rank) in &ranks {
            if rank.is_none() {
                missing_ranks.entry(slot.maker).or_default().push(slot);
            }
        }
        let mut missing_grants: BTreeMap<EventId, BTreeSet<EventId>> = BTreeMap::new();
        let mut missing_cuts: BTreeMap<EventId, BTreeSet<EventId>> = BTreeMap::new();
        let mut lowerings: BTreeMap<SlotId, BTreeSet<EventId>> = BTreeMap::new();
        for &id in &cuts.held {
            let Some(event) = cuts
                .log
                .event(id)
                .filter(|event| event.kind() == kind::STORAGE)
            else {
                continue;
            };
            let body = read_storage(event);
            if let Some(target) = body.as_ref().and_then(StorageBody::lowered) {
                lowerings.entry(target).or_default().insert(id);
            }
            if let Some(StorageBody::Enrol { slot, .. }) = body
                && standing.contains_key(&slot)
                && !slots.contains_key(&slot)
                && cuts.granted(slot).is_none()
            {
                missing_grants.entry(slot.maker).or_default().insert(id);
            }
            if let Err(missing) = event_cuts::reach(&cuts.envelopes, event.cuts()) {
                for dependency in missing {
                    missing_cuts.entry(dependency).or_default().insert(id);
                }
            }
        }
        let seen = tally
            .votes
            .iter()
            .flat_map(|(&slot, ids)| ids.iter().map(move |&id| (id, slot)))
            .collect();
        let awaiting = tally.awaiting().into_iter().collect();
        Some(Self {
            checkpoint: cuts.checkpoint_of(cut)?,
            mark: cuts.log.placed_count(),
            last: cuts.log.placed_since(0).last().copied(),
            tally,
            slots,
            standing,
            ranks,
            by_author,
            named_voters,
            missing_ranks,
            missing_grants,
            missing_cuts,
            lowerings,
            seen,
            awaiting,
        })
    }

    fn advance(&mut self, cuts: &PeerCuts<'_>, cut: EventId, added: &[EventId]) {
        let mut work: BTreeSet<EventId> = added.iter().copied().collect();
        for &id in added {
            work.extend(self.missing_cuts.remove(&id).unwrap_or_default());
            work.extend(self.missing_grants.remove(&id).unwrap_or_default());
            for slot in self.missing_ranks.remove(&id).unwrap_or_default() {
                self.ranks
                    .insert(slot, cuts.granted(slot).map(|(_, _, rank)| rank));
                work.extend(self.lowerings.get(&slot).into_iter().flatten().copied());
            }
            let Some(event) = cuts.log.event(id) else {
                continue;
            };
            if let Some(slots) = self.named_voters.get(&id) {
                for &slot in slots {
                    self.tally
                        .voters
                        .get_mut(&slot)
                        .expect("standing voter set")
                        .insert(*event.author());
                    self.by_author
                        .entry(*event.author())
                        .or_default()
                        .insert(slot);
                }
                work.extend(cuts.log.chain_rev(event.author()));
            }
            match read_storage(event) {
                Some(StorageBody::Enrol { .. } | StorageBody::Root { .. }) => {
                    // A new key can make earlier events of this author
                    // verifiable; no other author's votes are revisited.
                    work.extend(cuts.log.chain_rev(event.author()));
                }
                Some(body) => {
                    if let Some(target) = body.lowered() {
                        self.lowerings.entry(target).or_default().insert(id);
                    }
                }
                None => {}
            }
        }
        for id in work.iter().copied().collect::<Vec<_>>() {
            let Some(event) = cuts.log.event(id) else {
                continue;
            };
            let Some(StorageBody::Enrol { slot, .. }) = read_storage(event) else {
                continue;
            };
            if !self.standing.contains_key(&slot) {
                continue;
            }
            let keys = match self.slots.get(&slot) {
                Some(entry) => entry.slot_ed.zip(entry.slot_mldsa_hash),
                None => cuts.granted(slot).map(|(ed, hash, _)| (ed, hash)),
            };
            if keys.is_none() && !self.slots.contains_key(&slot) {
                self.missing_grants
                    .entry(slot.maker)
                    .or_default()
                    .insert(id);
            }
            if cuts.follows_cut(id, cut) == Ok(true) && cuts.verified_enrolment(event, slot, keys) {
                self.tally
                    .voters
                    .get_mut(&slot)
                    .expect("standing voter set")
                    .insert(*event.author());
                self.by_author
                    .entry(*event.author())
                    .or_default()
                    .insert(slot);
                work.extend(cuts.log.chain_rev(event.author()));
            }
        }
        let after: Vec<_> = work
            .into_iter()
            .filter_map(|id| {
                let event = cuts.log.event(id)?;
                if event.kind() != kind::STORAGE {
                    return None;
                }
                if let Err(missing) = event_cuts::reach(&cuts.envelopes, event.cuts()) {
                    for dependency in missing {
                        self.missing_cuts.entry(dependency).or_default().insert(id);
                    }
                    return None;
                }
                cuts.reaches_cleanly(event, self.checkpoint)
                    .then_some((id, event))
            })
            .collect();
        for &(id, event) in &after {
            let Some(target) = read_storage(event).and_then(|body| body.lowered()) else {
                continue;
            };
            let Some(mine) = self.standing.get(&target).filter(|x| x.dormant == 0) else {
                continue;
            };
            let by_itself = self.tally.voters[&target].contains(event.author());
            let by_another = self.by_author.get(event.author()).is_some_and(|slots| {
                slots.iter().any(|slot| {
                    let other = &self.standing[slot];
                    self.slots.contains_key(slot)
                        && (other.order < mine.order
                            || (other.dormant >= 2
                                && self.ranks[slot].unwrap_or(0)
                                    >= self.ranks[&target].unwrap_or(MAX_RANK)
                                && (other.dormant == 2 || other.dormant - 2 <= mine.order)))
                })
            });
            if (by_itself || by_another) && cuts.verified(event, &cuts.held) {
                self.tally.excuses.entry(target).or_default().insert(id);
                self.tally.votes.remove(&target);
                self.tally.all_votes.remove(&target);
                self.awaiting.remove(&target);
            }
        }
        for (id, event) in after {
            if let Some(slots) = self.by_author.get(event.author())
                && cuts.verified(event, &cuts.held)
            {
                for &slot in slots {
                    if let Some(votes) = self.tally.votes.get_mut(&slot)
                        && self.seen.insert((id, slot))
                    {
                        votes.push(id);
                        self.tally
                            .all_votes
                            .get_mut(&slot)
                            .expect("unexcused voter set")
                            .push(id);
                        self.awaiting.remove(&slot);
                    }
                }
            }
        }
        self.mark = cuts.log.placed_count();
        self.last = cuts.log.placed_since(0).last().copied();
    }
}

/// The cuts a peer holds, judged on their own pasts, and the skeleton
/// resolved from the last cut in effect (peers.md, "Skeleton cuts").
///
/// It reads a [`Log`] in a view, the events the peer holds, and the
/// envelopes a [`HeldEnvelopes`] gives for ordering checkpoints: the log's
/// own, or [`PeerEnvelopes`] at a peer that truncated and keeps the
/// envelopes of checkpoints it deleted.
pub struct PeerCuts<'a> {
    log: &'a Log,
    envelopes: &'a dyn HeldEnvelopes,
    held: BTreeSet<EventId>,
    kept: Option<(EventId, Cut)>,
    /// The held events of the kept cut's checkpoint's past, whose order
    /// among each other a peer that truncated no longer reads.
    kept_past: BTreeSet<EventId>,
    /// Twin → its naming event: for a cut, its checkpoint, the first space
    /// event in canonical order that names it, cites it and has every other
    /// parent in its past; for any other twin the first that names it.
    names: BTreeMap<EventId, EventId>,
    /// The cuts among the held events.
    cuts: BTreeMap<EventId, Cut>,
    /// Reserved-key cuts, held without reading their fields.
    held_cuts: BTreeSet<EventId>,
    validity: RefCell<BTreeMap<EventId, Status>>,
    /// The chain over the held events, once found.
    chain: RefCell<Option<Vec<EventId>>>,
    /// Each cut's tally over the held events, once counted.
    tallies: RefCell<BTreeMap<EventId, Option<Tally>>>,
    retained_tallies: Option<std::sync::Arc<dyn TallySource>>,
    /// Whether an event is an enrolment of a slot the peer verified, by
    /// event and slot.
    enrolments: RefCell<BTreeMap<(EventId, SlotId), bool>>,
}

impl core::fmt::Debug for PeerCuts<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerCuts")
            .field("held", &self.held.len())
            .field("kept", &self.kept.as_ref().map(|(id, _)| id))
            .field("cuts", &self.cuts.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl<'a> PeerCuts<'a> {
    /// The cuts of `view`, a set of the log's placed events; `None` for the
    /// whole log. A peer that never truncated reads it so.
    pub fn new(log: &'a Log, view: Option<&BTreeSet<EventId>>) -> Self {
        let held = match view {
            Some(view) => view.clone(),
            None => log.canonical().into_iter().collect(),
        };
        Self::build(log, log, held, None)
    }

    /// The cuts a peer that truncated under `kept` holds: `held`, the
    /// events it kept, which hold `kept` and what follows its checkpoint;
    /// `envelopes`, which give the envelopes of the checkpoints it deleted
    /// but keeps for ordering. The kept cut is trusted: it took effect
    /// before the peer truncated, and the peer judges nothing in its past.
    /// The held events in its checkpoint's past are those `log` still
    /// orders before it, and those [`always_kept`] names; a peer whose log
    /// lost that order supplies the rest with [`PeerCuts::with_kept_past`].
    pub fn truncated(
        log: &'a Log,
        envelopes: &'a dyn HeldEnvelopes,
        held: BTreeSet<EventId>,
        kept: EventId,
    ) -> Self {
        Self::build(log, envelopes, held, Some(kept))
    }

    /// Adds `past` to the held events this peer counts in the kept cut's
    /// checkpoint's past: those a peer that truncated noted when it did,
    /// such as the releases and restores it kept, whose order to the
    /// checkpoint its log no longer reads through the events it deleted.
    #[must_use]
    pub fn with_kept_past(mut self, past: impl IntoIterator<Item = EventId>) -> Self {
        self.validity.borrow_mut().clear();
        self.chain.borrow_mut().take();
        self.tallies.borrow_mut().clear();
        if self.kept.is_some() {
            self.kept_past
                .extend(past.into_iter().filter(|id| self.held.contains(id)));
        }
        self
    }

    /// Retains vote counters across resolutions of this whole log. The
    /// caller clears `tallies` for changes other than appended events, as
    /// [`CutTallies`] requires. Restricted views use independent tallies.
    #[must_use]
    pub fn with_tallies(mut self, tallies: std::sync::Arc<CutTallies>) -> Self {
        self.retained_tallies = Some(tallies);
        self
    }

    fn build(
        log: &'a Log,
        envelopes: &'a dyn HeldEnvelopes,
        held: BTreeSet<EventId>,
        kept: Option<EventId>,
    ) -> Self {
        let mut cuts = BTreeMap::new();
        let mut held_cuts = BTreeSet::new();
        for &id in &held {
            let Some(event) = log.event(id) else { continue };
            if event.kind() != kind::STORAGE || check_size(event.signed_len()).is_err() {
                continue;
            }
            match StorageBody::read(event.unverified_body()) {
                Ok(StorageBody::Cut(body)) => {
                    cuts.insert(id, body);
                }
                Err(class) if class.shared() == Some(ErrorClass::ExtensionRequired) => {
                    held_cuts.insert(id);
                }
                _ => {}
            }
        }
        let kept = kept.and_then(|id| Some((id, read_cut(log.event(id)?)?)));
        let names = names(log, &held, |twin| {
            cuts.contains_key(&twin)
                || held_cuts.contains(&twin)
                || kept.as_ref().is_some_and(|(id, _)| *id == twin)
        });
        let mut kept_past = BTreeSet::new();
        if let Some((id, _)) = &kept {
            if let Some(&checkpoint) = names.get(id) {
                kept_past.extend(log.past(checkpoint).intersection(&held).copied());
            }
            kept_past.extend(always_kept(log, *id).intersection(&held).copied());
        }
        Self {
            log,
            envelopes,
            held,
            kept,
            kept_past,
            names,
            cuts,
            held_cuts,
            validity: RefCell::new(BTreeMap::new()),
            chain: RefCell::new(None),
            tallies: RefCell::new(BTreeMap::new()),
            retained_tallies: None,
            enrolments: RefCell::new(BTreeMap::new()),
        }
    }

    /// The log.
    pub fn log(&self) -> &'a Log {
        self.log
    }

    /// The events the peer holds.
    pub fn held(&self) -> &BTreeSet<EventId> {
        &self.held
    }

    /// The cut the peer kept when it truncated, if it did.
    pub fn kept(&self) -> Option<EventId> {
        self.kept.as_ref().map(|(id, _)| *id)
    }

    /// The held events the peer counts in the kept cut's checkpoint's past:
    /// none at a peer that never truncated.
    pub fn kept_past(&self) -> &BTreeSet<EventId> {
        &self.kept_past
    }

    /// The cuts among the held events, by ID.
    pub fn cuts(&self) -> impl Iterator<Item = (EventId, &Cut)> {
        self.cuts.iter().map(|(id, cut)| (*id, cut))
    }

    /// A held cut's body, or the kept cut's.
    pub fn body(&self, cut: EventId) -> Option<&Cut> {
        self.cuts.get(&cut).or_else(|| {
            self.kept
                .as_ref()
                .filter(|(id, _)| *id == cut)
                .map(|k| &k.1)
        })
    }

    /// The checkpoint of a cut, to a peer (peers.md, "Skeleton cuts", step
    /// 3): the first space event in canonical order that names it in
    /// visible key 15, cites it, and has every other parent in the cut's
    /// past. A parent the peer does not hold, one it deleted when it
    /// truncated, counts as in the kept cut's past, so in the past of any
    /// later cut. Any other event that names the cut names nothing, and
    /// without a checkpoint the cut is `Unnamed`.
    pub fn checkpoint_of(&self, cut: EventId) -> Option<EventId> {
        self.names.get(&cut).copied()
    }

    /// Whether `id` follows the checkpoint of `cut`, by its cuts, or is that
    /// checkpoint (events.md, "Cuts"). An event not held, or a cut with no
    /// checkpoint, follows nothing.
    ///
    /// # Errors
    ///
    /// The checkpoints whose envelopes the answer waits for: the peer
    /// neither holds nor keeps them, and the answer is pending until it
    /// fetches them.
    pub fn follows_cut(&self, id: EventId, cut: EventId) -> Result<bool, Vec<EventId>> {
        let Some(c) = self.checkpoint_of(cut) else {
            return Ok(false);
        };
        if id == c {
            return Ok(true);
        }
        match self.envelopes.held_envelope(id) {
            Some(event) => event_cuts::follows(&self.envelopes, event, c),
            None => Ok(false),
        }
    }

    /// Whether `id` is in the past of `checkpoint`, a checkpoint at or after
    /// the kept cut's: the log orders it before, or it is in the kept cut's
    /// checkpoint's past.
    pub fn in_past(&self, id: EventId, checkpoint: EventId) -> bool {
        self.kept_past.contains(&id) || self.log.precedes(id, checkpoint)
    }

    /// Whether `event`'s cuts reach no checkpoint concurrent with the
    /// checkpoint `c`, and reach `c`: an event that votes as exclusively as
    /// a device's vote does. While the envelopes that answer it are missing
    /// it is no vote yet.
    fn reaches_cleanly(&self, event: &Event, c: EventId) -> bool {
        let Ok(reached) = event_cuts::reach(&self.envelopes, event.cuts()) else {
            return false;
        };
        reached.contains(&c)
            && reached
                .iter()
                .all(|&x| matches!(event_cuts::concurrent(&self.envelopes, x, c), Ok(false)))
    }

    /// Whether `event` follows `cut`'s checkpoint and its cuts reach no
    /// checkpoint concurrent with it: an event that, by a pseudonym of a
    /// slot the cut waits for, is a vote for the cut.
    pub fn is_vote(&self, event: &Event, cut: EventId) -> bool {
        self.checkpoint_of(cut)
            .is_some_and(|c| self.reaches_cleanly(event, c))
    }

    /// The keys of an administrator slot that a held change granted, from
    /// its grant map, with the rank it gives.
    fn granted(&self, slot: SlotId) -> Option<([u8; 32], [u8; 32], u8)> {
        let event = self.log.event(slot.maker)?;
        if !self.held.contains(&slot.maker) {
            return None;
        }
        match read_storage(event)? {
            StorageBody::Change {
                twin,
                effect: ChangeEffect::Grants(grants),
                ..
            } if twin == slot.reference.commitment => grants
                .get(usize::from(slot.reference.index))
                .map(|g| (g.slot_ed, g.slot_mldsa_hash, g.rank)),
            _ => None,
        }
    }

    /// Whether `event` is an enrolment of `slot` the peer verified: its
    /// pseudonym's keys hash to its `kc` and the event verifies under them,
    /// and its authorization verifies under the slot's keys, from the cut's
    /// entry or the grant map that made it.
    fn verified_enrolment(
        &self,
        event: &Event,
        slot: SlotId,
        keys: Option<([u8; 32], [u8; 32])>,
    ) -> bool {
        let memo = (event.id(), slot);
        if let Some(&known) = self.enrolments.borrow().get(&memo) {
            return known;
        }
        let verified = self.verify_enrolment(event, slot, keys);
        self.enrolments.borrow_mut().insert(memo, verified);
        verified
    }

    fn verify_enrolment(
        &self,
        event: &Event,
        slot: SlotId,
        keys: Option<([u8; 32], [u8; 32])>,
    ) -> bool {
        let Some(StorageBody::Enrol {
            slot: named,
            slot_mldsa,
            authorization,
            ..
        }) = read_storage(event)
        else {
            return false;
        };
        let Some((ed, hash)) = keys else {
            return false;
        };
        let Some(own) = own_key(event) else {
            return false;
        };
        named == slot
            && sha256(&[&slot_mldsa]) == hash
            && verify_slot(
                &ed,
                &slot_mldsa,
                &enrol_statement(&self.log.id(), slot.reference, event.author()),
                &authorization,
            )
            && self.log.verify_hybrid_remembered(event, Some(&own)).is_ok()
    }

    /// Whether `event` verifies under the key of its author that the peer
    /// holds among `held`.
    fn verified(&self, event: &Event, held: &BTreeSet<EventId>) -> bool {
        pseudonym_key(self.log, event, |id| held.contains(&id))
            .is_some_and(|key| self.log.verify_hybrid_remembered(event, Some(&key)).is_ok())
    }

    /// What `cut` waits for among `held` (peers.md, "Skeleton cuts", waited
    /// and excused slots, votes, in effect at the peer). `None` for a cut
    /// the peer does not hold or with no checkpoint.
    fn tally_within(&self, cut: EventId, held: &BTreeSet<EventId>) -> Option<Tally> {
        let body = self.body(cut)?;
        let c = self.checkpoint_of(cut)?;
        let standing: BTreeMap<SlotId, &StandingEntry> =
            body.standing.iter().map(|x| (x.slot, x)).collect_map();
        let slots: BTreeMap<_, _> = body
            .slots
            .iter()
            .map(|entry| (entry.slot, entry))
            .collect_map();
        let ranks: BTreeMap<_, _> = body
            .standing
            .iter()
            .map(|entry| {
                (
                    entry.slot,
                    slots
                        .get(&entry.slot)
                        .map(|slot| slot.rank)
                        .or_else(|| self.granted(entry.slot).map(|(_, _, rank)| rank)),
                )
            })
            .collect_map();
        let in_cut: BTreeSet<SlotId> = body.slots.iter().map(|entry| entry.slot).collect();
        let waited: Vec<SlotId> = body
            .standing
            .iter()
            .filter(|x| x.dormant == 0)
            .map(|x| x.slot)
            .collect();
        let mut voters: BTreeMap<SlotId, BTreeSet<DeviceId>> = standing
            .keys()
            .map(|&slot| (slot, BTreeSet::new()))
            .collect_map();
        for (&slot, entry) in &slots {
            if let Some(pseudonym) = entry_pseudonym(self.log, entry)
                && let Some(set) = voters.get_mut(&slot)
            {
                set.insert(pseudonym);
            }
        }
        for entry in &body.standing {
            if let Some(event) = entry
                .pseudonym
                .filter(|id| held.contains(id))
                .and_then(|id| self.log.event(id))
            {
                voters.get_mut(&entry.slot)?.insert(*event.author());
            }
        }
        for &id in held {
            let Some(event) = self.log.event(id) else {
                continue;
            };
            let Some(StorageBody::Enrol { slot, .. }) = read_storage(event) else {
                continue;
            };
            if !standing.contains_key(&slot) {
                continue;
            }
            let keys = match slots.get(&slot) {
                Some(entry) => entry.slot_ed.zip(entry.slot_mldsa_hash),
                None => self.granted(slot).map(|(ed, hash, _)| (ed, hash)),
            };
            if self.follows_cut(id, cut) == Ok(true) && self.verified_enrolment(event, slot, keys) {
                voters.get_mut(&slot)?.insert(*event.author());
            }
        }
        let mut by_author: BTreeMap<DeviceId, BTreeSet<SlotId>> = BTreeMap::new();
        for (&slot, authors) in &voters {
            for &author in authors {
                by_author.entry(author).or_default().insert(slot);
            }
        }
        // The held events that follow the checkpoint as a vote does.
        let after: Vec<(EventId, &Event)> = held
            .iter()
            .filter_map(|&id| Some((id, self.log.event(id)?)))
            .filter(|(_, event)| event.kind() == kind::STORAGE && self.reaches_cleanly(event, c))
            .collect();
        let mut excuses: BTreeMap<SlotId, BTreeSet<EventId>> = waited
            .iter()
            .map(|&slot| (slot, BTreeSet::new()))
            .collect_map();
        for &(id, event) in &after {
            let Some(target) = read_storage(event).and_then(|body| body.lowered()) else {
                continue;
            };
            let Some(mine) = standing.get(&target).filter(|x| x.dormant == 0) else {
                continue;
            };
            let author = event.author();
            // By the slot itself, by a slot of the cut that outranks it, or
            // by a recovery slot of the cut of at least its rank.
            let by_itself = voters[&target].contains(author);
            let by_another = || {
                by_author.get(author).is_some_and(|slots| {
                    slots.iter().any(|t| {
                        let x = standing[t];
                        in_cut.contains(t)
                            && (x.order < mine.order
                                || (x.dormant >= 2
                                    && ranks[t].unwrap_or(0) >= ranks[&target].unwrap_or(MAX_RANK)
                                    && (x.dormant == 2 || x.dormant - 2 <= mine.order)))
                    })
                })
            };
            if (by_itself || by_another()) && self.verified(event, held) {
                excuses.entry(target).or_default().insert(id);
            }
        }
        let mut votes = BTreeMap::new();
        let mut all_votes = BTreeMap::new();
        for &slot in &waited {
            if excuses[&slot].is_empty() {
                votes.insert(slot, Vec::new());
                all_votes.insert(slot, Vec::new());
            }
        }
        for &(id, event) in &after {
            if let Some(slots) = by_author.get(event.author())
                && self.verified(event, held)
            {
                for slot in slots {
                    if let Some(mine) = votes.get_mut(slot) {
                        mine.push(id);
                        all_votes.get_mut(slot)?.push(id);
                    }
                }
            }
        }
        Some(Tally {
            waited,
            excuses,
            votes,
            all_votes,
            voters,
        })
    }

    /// What `cut` waits for among the events the peer holds: its waited
    /// slots, the lowerings that excuse them, and their votes. The same
    /// function serves a client over its view, to know when a cut is in
    /// effect there.
    pub fn tally(&self, cut: EventId) -> Option<Tally> {
        if let Some(tally) = self.tallies.borrow().get(&cut) {
            return tally.clone();
        }
        let tally = match self
            .retained_tallies
            .as_ref()
            .and_then(|source| source.tally(self, cut))
        {
            Some(mut tally) => {
                for votes in tally.votes.values_mut() {
                    votes.sort_unstable();
                }
                for votes in tally.all_votes.values_mut() {
                    votes.sort_unstable();
                }
                Some(tally)
            }
            None => self.tally_within(cut, &self.held),
        };
        self.tallies.borrow_mut().insert(cut, tally.clone());
        tally
    }

    /// The slots a cut waits for that are not excused and have no vote that
    /// counts: whom it waits for, which a peer reports as awaiting those
    /// administrators.
    pub fn awaiting(&self, cut: EventId) -> Vec<SlotId> {
        self.tally(cut).map(|t| t.awaiting()).unwrap_or_default()
    }

    fn in_effect_within(&self, cut: EventId, held: &BTreeSet<EventId>) -> bool {
        if core::ptr::eq(held, &self.held) {
            return self
                .retained_tallies
                .as_ref()
                .and_then(|source| source.in_effect(self, cut))
                .unwrap_or_else(|| self.tally(cut).is_some_and(|t| t.in_effect()));
        }
        self.tally_within(cut, held).is_some_and(|t| t.in_effect())
    }

    /// Whether a cut is in effect at the peer: valid, and every slot it waits
    /// for has a vote or is excused. Validity is final and votes and excuses
    /// only accumulate, so a cut in effect over some events is in effect over
    /// every set that holds them. The cut a peer kept when it truncated is.
    pub fn in_effect(&self, cut: EventId) -> bool {
        self.validity(cut).is_valid()
            && (self.kept() == Some(cut) || self.in_effect_within(cut, &self.held))
    }

    /// A cut's status, judged on its own past (peers.md, "Skeleton cuts",
    /// 3.21), in order: (1) the body reads; (2) a stored space event names
    /// and cites it, its checkpoint (`Unnamed`); (3) its epoch
    /// ([`PeerCuts::check_order`], `CutPending`); (4) its author's slot is
    /// in, enrolled to it, in the merged skeleton of its past
    /// (`NotAnAdministrator`); (5) it verifies under the key of the root or
    /// enrolment that enrolled its author there (`BadSignature`), so that a
    /// peer that truncated and one that kept everything judge it alike;
    /// (6) its slots are exactly those of that
    /// skeleton, each with its keys, seniority, enrolling root or enrolment
    /// and rank (`BadCut`); (7) its standing entries are consistent with
    /// each other and with that skeleton (`BadCut`). A reserved-key cut is
    /// held as `ExtensionRequired`, and is never a valid cut.
    pub fn validity(&self, cut: EventId) -> Status {
        if self.kept.as_ref().is_some_and(|(id, _)| *id == cut) {
            return Status::Valid;
        }
        if let Some(status) = self.validity.borrow().get(&cut) {
            return *status;
        }
        let Some(body) = self.cuts.get(&cut) else {
            return void(
                if self.held_cuts.contains(&cut) {
                    ErrorClass::ExtensionRequired
                } else {
                    ErrorClass::Malformed
                }
                .into(),
            );
        };
        self.validity
            .borrow_mut()
            .insert(cut, void(ErrorClass::Pending.into()));
        let status = match self.judge(cut, body) {
            Ok(()) => Status::Valid,
            Err(class) => void(class),
        };
        self.validity.borrow_mut().insert(cut, status);
        status
    }

    fn judge(&self, cut: EventId, body: &Cut) -> Result<(), PeersClass> {
        let event = self.log.event(cut).ok_or(ErrorClass::Malformed)?;
        // 2. It is named and cited: it has a checkpoint.
        let checkpoint = self.checkpoint_of(cut).ok_or(PeersClass::Unnamed)?;
        // Steps 4 to 7 read the merged skeleton of the cut's past, from the
        // cut in effect there.
        let mut pool: BTreeSet<EventId> = self
            .log
            .past(cut)
            .into_iter()
            .filter(|id| self.held.contains(id))
            .collect();
        let base = self
            .kept
            .as_ref()
            .map(|(id, _)| *id)
            .filter(|id| pool.contains(id));
        // At a peer that truncated, what it kept of the kept cut's
        // checkpoint's past is in the past of every cut after it, though
        // its log no longer reads that through the events it deleted: the
        // roots and enrolments the kept cut names among them, whose keys its
        // votes are verified under.
        if base.is_some() {
            pool.extend(self.kept_past.iter().copied());
        }
        let (skeleton, chain) = self.skeleton_within(&pool, base);
        // 3. Its epoch.
        self.check_order(body, checkpoint, &pool, base, &chain)?;
        // 4. Its author's administrator slot is in, enrolled to it, in that
        // skeleton: whatever root or enrolment of the pseudonym the peer
        // holds besides, or deleted when it truncated.
        let author = event.author();
        let Some(slot) = skeleton.slot_of(author).filter(|slot| {
            skeleton
                .merged()
                .get(slot)
                .is_some_and(|s| s.is_in && s.enrolled.as_ref() == Some(author))
        }) else {
            return Err(ErrorClass::NotAnAdministrator.into());
        };
        // 5. It verifies under the key of the root or enrolment that
        // enrolled its author there.
        let key = enrolment_of(&skeleton, slot)
            .and_then(|id| self.log.event(id))
            .and_then(|enrolment| own_key(enrolment).filter(|k| k.commitment() == event.kc()))
            .ok_or(PeersClass::from(ErrorClass::BadSignature))?;
        if self
            .log
            .verify_hybrid_remembered(event, Some(&key))
            .is_err()
        {
            return Err(ErrorClass::BadSignature.into());
        }
        // 6. Its slots are exactly the administrator slots in that skeleton.
        if skeleton.cut_slots() != body.slots {
            return Err(PeersClass::BadCut);
        }
        // 7. Each standing entry names one of its slots, with no pseudonym,
        // or a slot not in that skeleton, with a root or enrolment of it the
        // peer holds, or none; the orders are 1 to n, each once; a dormant
        // value from 3 is 2 + k with k from 1 to n + 1.
        let consistent = standing_consistent(
            body,
            |slot| skeleton.merged().get(&slot).is_none_or(|s| !s.is_in),
            |id, slot| {
                self.held.contains(&id) && self.log.event(id).is_some_and(|e| enrols(e, slot))
            },
        );
        if !consistent {
            return Err(PeersClass::BadCut);
        }
        Ok(())
    }

    /// Step 4 of a cut's checks, its epoch (peers.md, "Skeleton cuts",
    /// "Epochs"), over `pool`, the held events of its past, whose chain of
    /// cuts in effect from `base` is `chain`, with `L` its last cut:
    ///
    /// - at a peer that truncated, the cut it kept is in effect there;
    /// - the cut's `checkpoint` follows `L`'s checkpoint;
    /// - every checkpoint the checkpoint's cuts reach is at or before
    ///   `L`'s checkpoint or after it;
    /// - no valid cut whose checkpoint is after `L`'s checkpoint (any,
    ///   without `L`) is one the checkpoint follows;
    /// - its epoch is one more than `L`'s, or 1 without `L`.
    ///
    /// The order is read from envelopes alone, and the only validity it
    /// asks for is of cuts after `L`'s checkpoint, which a peer that
    /// truncated under `L`, or under an earlier cut, still holds: such a
    /// peer and one that kept everything decide every cut alike.
    ///
    /// # Errors
    ///
    /// `CutPending`, final; `Pending` while the envelopes that order a
    /// checkpoint are missing.
    fn check_order(
        &self,
        body: &Cut,
        checkpoint: EventId,
        pool: &BTreeSet<EventId>,
        base: Option<EventId>,
        chain: &[EventId],
    ) -> Result<(), PeersClass> {
        if let Some(base) = base
            && !self.in_effect_within(base, pool)
        {
            return Err(PeersClass::CutPending);
        }
        // A cut whose place the peer cannot read yet, for want of a
        // checkpoint's envelope, is pending, never final.
        let pending = |_: Vec<EventId>| PeersClass::from(ErrorClass::Pending);
        let envelope = self
            .envelopes
            .envelope(checkpoint)
            .ok_or(PeersClass::from(ErrorClass::Pending))?;
        let reached = event_cuts::reach(self.envelopes, envelope.cuts()).map_err(pending)?;
        if self.held_cuts.iter().any(|cut| {
            pool.contains(cut)
                && self
                    .checkpoint_of(*cut)
                    .is_some_and(|c| reached.contains(&c))
        }) {
            return Err(PeersClass::CutPending);
        }
        let last = chain.last().and_then(|&l| self.checkpoint_of(l));
        if let Some(last) = last {
            if !reached.contains(&last) {
                return Err(PeersClass::CutPending);
            }
            for &x in &reached {
                let ordered = event_cuts::at_or_before(self.envelopes, x, last).map_err(pending)?
                    || event_cuts::at_or_before(self.envelopes, last, x).map_err(pending)?;
                if !ordered {
                    return Err(PeersClass::CutPending);
                }
            }
        }
        for &x in self.cuts.keys().filter(|x| pool.contains(x)) {
            let Some(cx) = self.checkpoint_of(x) else {
                continue;
            };
            if cx == checkpoint || !reached.contains(&cx) {
                continue;
            }
            if let Some(last) = last
                && (cx == last
                    || !event_cuts::at_or_before(self.envelopes, last, cx).map_err(pending)?)
            {
                continue;
            }
            if self.validity(x).is_valid() {
                return Err(PeersClass::CutPending);
            }
        }
        let expected = chain
            .last()
            .and_then(|&last| self.body(last))
            .map_or(1, |last| last.epoch + 1);
        if body.epoch != expected {
            return Err(PeersClass::CutPending);
        }
        Ok(())
    }

    fn chain_within(&self, held: &BTreeSet<EventId>, base: Option<EventId>) -> Vec<EventId> {
        let mut out: Vec<EventId> = base.into_iter().collect();
        let mut current = base;
        loop {
            let epoch = current
                .and_then(|c| self.body(c))
                .map_or(1, |c| c.epoch + 1);
            let next = self
                .cuts
                .iter()
                .filter(|(id, cut)| {
                    Some(**id) != current && held.contains(id) && cut.epoch == epoch
                })
                .map(|(id, _)| *id)
                .filter(|&id| self.validity(id).is_valid())
                .filter_map(|id| Some((self.checkpoint_of(id)?, id)))
                .filter(|&(checkpoint, _)| {
                    // A checkpoint whose following is pending is not taken
                    // yet.
                    current.is_none_or(|c| {
                        self.follows_cut(checkpoint, c) == Ok(true)
                            && Some(checkpoint) != self.checkpoint_of(c)
                    })
                })
                .filter(|&(_, id)| self.in_effect_within(id, held))
                .min();
            let Some((_, next)) = next else {
                return out;
            };
            out.push(next);
            current = Some(next);
        }
    }

    /// The cuts in effect at the peer, oldest first: from the cut it kept,
    /// if it truncated, each of the next epoch.
    pub fn chain(&self) -> Vec<EventId> {
        if let Some(chain) = self.chain.borrow().as_ref() {
            return chain.clone();
        }
        let chain = self.chain_within(&self.held, self.kept.as_ref().map(|(id, _)| *id));
        *self.chain.borrow_mut() = Some(chain.clone());
        chain
    }

    /// The last cut in effect at the peer, from which its skeleton starts.
    pub fn current(&self) -> Option<EventId> {
        self.chain().last().copied()
    }

    fn skeleton_within(
        &self,
        held: &BTreeSet<EventId>,
        base: Option<EventId>,
    ) -> (Skeleton<'a>, Vec<EventId>) {
        let chain = self.chain_within(held, base);
        let skeleton = match chain.last() {
            Some(&last) => self.world(last, held),
            None => {
                let presets = self
                    .cuts
                    .keys()
                    .filter(|id| held.contains(id))
                    .map(|&id| (id, self.validity(id)))
                    .collect_map();
                Skeleton::with_presets(self.log, held.clone(), presets)
            }
        };
        (skeleton, chain)
    }

    /// The world of a cut in effect: the cut and the held events that follow
    /// its checkpoint, the other cuts among them judged on their own past.
    fn world(&self, cut: EventId, held: &BTreeSet<EventId>) -> Skeleton<'a> {
        let members: BTreeSet<EventId> = held
            .iter()
            .copied()
            // An event whose following is pending stays out until the
            // envelopes it waits for are fetched.
            .filter(|&id| id == cut || self.follows_cut(id, cut) == Ok(true))
            .collect();
        let presets = self
            .cuts
            .keys()
            .filter(|&&id| id != cut && members.contains(&id))
            .map(|&id| (id, self.validity(id)))
            .collect_map();
        let body = self.body(cut).expect("a cut in effect").clone();
        let late = self.late_within(cut, held);
        let refused = self.late_enrolment_checks(&late, held);
        let mut skeleton = Skeleton::after_cut(self.log, cut, &body, members, presets);
        skeleton.mark_late(late, refused);
        skeleton
    }

    /// peers.md, "Skeleton cuts", what a late enrolment opens: a late
    /// enrolment is stored only if, in order, its `seq` is 1 and its author
    /// is no pseudonym whose root or enrolment the peer holds before it, in
    /// canonical order (else `BadSignature`, as section 3.11, step 3,
    /// classes the same checks); its `mldsa` beside an empty X-Wing key
    /// hashes to its `kc` (else `NotCommitted`); and it verifies under its
    /// own `ed` and `mldsa` (else `BadSignature`). The late enrolments of
    /// `late` that fail, with their classes.
    fn late_enrolment_checks(
        &self,
        late: &BTreeSet<EventId>,
        held: &BTreeSet<EventId>,
    ) -> BTreeMap<EventId, PeersClass> {
        let mut out = BTreeMap::new();
        for &id in late {
            let Some(event) = self.log.event(id) else {
                continue;
            };
            let Some(StorageBody::Enrol { mldsa, .. }) = read_storage(event) else {
                continue;
            };
            let place = (self.log.height(id), id);
            let other = self
                .log
                .chain(event.author())
                .into_iter()
                .filter(|&x| x != id && held.contains(&x))
                .filter(|&x| (self.log.height(x), x) < place)
                .filter_map(|x| self.log.event(x))
                .any(|x| {
                    matches!(
                        read_storage(x),
                        Some(StorageBody::Root { .. } | StorageBody::Enrol { .. })
                    )
                });
            let own = HybridKeys::new(&mldsa, None)
                .ok()
                .filter(|keys| keys.commitment() == event.kc());
            let class: Option<PeersClass> = if event.seq() != 1 || other {
                Some(ErrorClass::BadSignature.into())
            } else {
                match own {
                    None => Some(ErrorClass::NotCommitted.into()),
                    Some(own)
                        if self
                            .log
                            .verify_hybrid_remembered(event, Some(&own))
                            .is_err() =>
                    {
                        Some(ErrorClass::BadSignature.into())
                    }
                    Some(_) => None,
                }
            };
            if let Some(class) = class {
                out.insert(id, class);
            }
        }
        out
    }

    /// The skeleton events of `held` late at the peer while `cut` is in
    /// effect there (peers.md, "Skeleton cuts", late skeleton events): those
    /// other than a cut that are neither in the cut's past, nor the cut, nor
    /// follow its checkpoint, whose body reads. A cut keeps its own checks,
    /// on its own past, wherever it stands. An event whose following waits
    /// for envelopes is neither late nor in the world until they come.
    ///
    /// The cut's past is its checkpoint's past. A peer that truncated under
    /// a cut no longer holds the whole past of that cut's checkpoint, which
    /// every later checkpoint follows; what it kept of it is in it all the
    /// same ([`PeerCuts::kept_past`]).
    fn late_within(&self, cut: EventId, held: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let Some(checkpoint) = self.checkpoint_of(cut) else {
            return BTreeSet::new();
        };
        let candidates: Vec<EventId> = held
            .iter()
            .copied()
            .filter(|&id| id != cut && id != checkpoint)
            .filter(|&id| {
                self.log
                    .event(id)
                    .and_then(read_storage)
                    .is_some_and(|body| {
                        let kind = body.storage_type();
                        kind.is_skeleton() && kind != StorageType::Cut
                    })
            })
            .filter(|&id| self.follows_cut(id, cut) == Ok(false))
            .collect();
        if candidates.is_empty() {
            return BTreeSet::new();
        }
        let past = self.log.past(checkpoint);
        candidates
            .into_iter()
            .filter(|id| !past.contains(id) && !self.kept_past.contains(id))
            .collect()
    }

    /// The skeleton events the peer holds that would be late under `cut`,
    /// were it in effect: those other than a cut neither in its past, nor the
    /// cut, nor after its checkpoint. A client reads it to know whether its
    /// enrolment is late under a checkpoint it votes for.
    pub fn late_at(&self, cut: EventId) -> BTreeSet<EventId> {
        self.late_within(cut, &self.held)
    }

    /// The skeleton events late at the peer under the last cut in effect
    /// there; none while no cut is.
    pub fn late(&self) -> BTreeSet<EventId> {
        match self.current() {
            Some(cut) => self.late_within(cut, &self.held),
            None => BTreeSet::new(),
        }
    }

    /// Whether `id` is late under `cut`: neither in its checkpoint's past,
    /// nor the checkpoint, nor after it.
    fn late_under(&self, id: EventId, cut: EventId) -> bool {
        let Some(c) = self.checkpoint_of(cut) else {
            return false;
        };
        id != c && !self.in_past(id, c) && self.follows_cut(id, cut) == Ok(false)
    }

    /// Whether `id` is late under some cut of `chain` (peers.md, "Release
    /// and restore"; "Erasure", step 1): a request late under one cut counts
    /// for nothing under it and every later one, though a later
    /// checkpoint's past holds it through its author's chain, and its
    /// verdict stays `Late`. At a peer that truncated, `chain` starts at the
    /// kept cut: a request late under an earlier cut is in no kept past, the
    /// truncation having deleted it.
    pub fn late_under_chain(&self, id: EventId, chain: &[EventId]) -> bool {
        chain.iter().any(|&cut| self.late_under(id, cut))
    }

    /// Whether a cut **can still take effect** at the peer (peers.md,
    /// "Erasure", undecided cuts): it is valid and not in effect, and its
    /// epoch is later than the cut in effect's (any epoch without one), or
    /// equal to that of a cut in effect whose checkpoint has a larger ID,
    /// which it could replace.
    pub fn can_take_effect(&self, cut: EventId) -> bool {
        self.undecided(&self.chain()).contains(&cut)
    }

    /// The cuts that can still take effect, given the chain in effect
    /// ([`can_still_take_effect`], over the cuts' epochs and checkpoints).
    fn undecided(&self, chain: &[EventId]) -> BTreeSet<EventId> {
        let chain: Vec<(u64, EventId)> = chain
            .iter()
            .filter_map(|&j| Some((self.body(j)?.epoch, self.checkpoint_of(j)?)))
            .collect();
        self.cuts
            .iter()
            .filter(|&(&id, cut)| {
                self.checkpoint_of(id).is_some_and(|c| {
                    !chain.iter().any(|&(_, j)| j == c)
                        && can_still_take_effect(cut.epoch, c, &chain)
                })
            })
            .map(|(id, _)| *id)
            .filter(|&id| self.validity(id).is_valid())
            .collect()
    }

    /// peers.md, "Erasure", steps 0 and 1, for an erasure, a credentials
    /// request or a release `request` the peer holds: `Late` under any cut of
    /// the chain in effect, though a later checkpoint's past holds it;
    /// `Wait` while it is concurrent with a cut that can still take
    /// effect, neither in that cut's past, nor the cut, nor after its
    /// checkpoint; otherwise `Free`, for stability or the timeout to decide.
    ///
    /// A peer never carries out a request, and never reclaims a release,
    /// while it waits: so it destroys nothing that a checkpoint replicas may
    /// still put in effect would make late. Once the cut takes effect the
    /// request is late, and void.
    pub fn request_state(&self, request: EventId) -> RequestState {
        let chain = self.chain();
        if self.late_under_chain(request, &chain) {
            return RequestState::Late;
        }
        for cut in self.undecided(&chain) {
            let Some(c) = self.checkpoint_of(cut) else {
                continue;
            };
            if request != cut
                && !self.in_past(request, c)
                && self.follows_cut(request, cut) != Ok(true)
            {
                return RequestState::Wait;
            }
        }
        RequestState::Free
    }

    /// Whether `earlier` is before `later`, as the peer can tell: an event
    /// of the kept cut's checkpoint's past is before each event that follows
    /// that checkpoint and is not in that past, and the peer reads no order
    /// among the events of that past; otherwise by the log's parents.
    pub fn before(&self, earlier: EventId, later: EventId) -> bool {
        if self.kept_past.contains(&earlier) {
            let kept = self.kept().expect("a kept past has its cut");
            return !self.kept_past.contains(&later) && self.follows_cut(later, kept) == Ok(true);
        }
        self.log.precedes(earlier, later)
    }

    /// The maximal releases that make `stream` released at the peer, or
    /// `None` when it is not (peers.md, "Release and restore"): some release
    /// names it and every maximal event among the releases and restores that
    /// name it is a release, a restore concurrent with a release winning.
    /// With a cut in effect, the requests counted are those in its past and
    /// those that follow its checkpoint, every one of the past before every
    /// one after ([`PeerCuts::before`]); a release or restore late under any
    /// cut of the chain counts for nothing ([`PeerCuts::late_under_chain`]).
    pub fn released<'b>(
        &self,
        requests: impl IntoIterator<Item = (EventId, &'b StorageBody)>,
        stream: &[u8; 16],
    ) -> Option<Vec<EventId>> {
        let mut naming: Vec<(EventId, bool)> = requests
            .into_iter()
            .filter_map(|(id, body)| match body {
                StorageBody::Release { stream: s } if s == stream => Some((id, true)),
                StorageBody::Restore(Restored::Stream(s)) if s == stream => Some((id, false)),
                _ => None,
            })
            .collect();
        let chain = self.chain();
        naming.retain(|&(id, _)| !self.late_under_chain(id, &chain));
        if !naming.iter().any(|&(_, is_release)| is_release) {
            return None;
        }
        let maximal: Vec<(EventId, bool)> = naming
            .iter()
            .copied()
            .filter(|&(id, _)| {
                !naming
                    .iter()
                    .any(|&(other, _)| other != id && self.before(id, other))
            })
            .collect();
        maximal
            .iter()
            .all(|&(_, is_release)| is_release)
            .then(|| maximal.into_iter().map(|(id, _)| id).collect())
    }

    /// The releases and restores of `checkpoint`'s past a peer keeps when it
    /// truncates under it (peers.md, "Truncation", what is always kept): of
    /// those that name a stream and are not late under an earlier cut, the
    /// maximal ones of each stream, which are concurrent with each other;
    /// and every restore that names a snapshot unit. Found before anything
    /// is deleted, so that a peer that truncated and one that kept
    /// everything find the same streams released.
    pub fn kept_requests(&self, checkpoint: EventId) -> BTreeSet<EventId> {
        let mut streams: BTreeMap<[u8; 16], Vec<EventId>> = BTreeMap::new();
        let mut out = BTreeSet::new();
        let before = self.chain_before(checkpoint);
        for &id in &self.held {
            let Some(body) = self.log.event(id).and_then(read_storage) else {
                continue;
            };
            if !body.storage_type().is_writer_request() || !self.in_past(id, checkpoint) {
                continue;
            }
            match body.stream() {
                Some(_) if self.late_under_chain(id, &before) => {}
                Some(stream) => streams.entry(stream).or_default().push(id),
                None => {
                    out.insert(id);
                }
            }
        }
        for ids in streams.values() {
            out.extend(ids.iter().copied().filter(|&id| {
                !ids.iter()
                    .any(|&other| other != id && self.before(id, other))
            }));
        }
        out
    }

    /// The chain of cuts in effect over the held events of `checkpoint`'s
    /// past, from the kept cut at a peer that truncated: the cuts before the
    /// checkpoint's.
    fn chain_before(&self, checkpoint: EventId) -> Vec<EventId> {
        let pool: BTreeSet<EventId> = self
            .held
            .iter()
            .copied()
            .filter(|&id| self.in_past(id, checkpoint))
            .collect();
        let base = self
            .kept
            .as_ref()
            .map(|(id, _)| *id)
            .filter(|id| pool.contains(id));
        self.chain_within(&pool, base)
    }

    /// The plan for truncating under `cut`, in effect at the peer, over the
    /// events it holds in its checkpoint's past ([`keep`], [`always_kept`]
    /// and [`PeerCuts::kept_requests`]). The peer keeps the checkpoint, the
    /// cut and the record object the cut names, and everything that does not
    /// precede the checkpoint: the events that follow it and the late
    /// events.
    ///
    /// It never deletes a checkpoint: beside those the checkpoint's cuts
    /// reach, it keeps the envelope of every event in the checkpoint's past
    /// that a stored event's cuts name ([`named_cuts`]), so that it still
    /// serves every checkpoint's envelope to whoever may fetch the space's
    /// events, even when an event declared its cuts wrongly.
    ///
    /// # Errors
    ///
    /// The checkpoints whose envelopes it waits for, or the cut itself
    /// when it has no checkpoint: without them it cannot tell which
    /// envelopes to keep, and it truncates nothing until it fetches them.
    pub fn truncation_plan(
        &self,
        cut: EventId,
        keep_whole: impl Fn(EventId, &Event) -> bool,
    ) -> Result<TruncationPlan, Vec<EventId>> {
        let checkpoint = self.checkpoint_of(cut).ok_or_else(|| vec![cut])?;
        let mut past: BTreeSet<EventId> = self
            .log
            .past(checkpoint)
            .intersection(&self.held)
            .copied()
            .collect();
        past.extend(self.kept_past.iter().copied());
        let requests = self.kept_requests(checkpoint);
        let late_erasers: BTreeSet<_> = self
            .held
            .iter()
            .filter_map(|&id| {
                let event = self.log.event(id)?;
                (matches!(read_storage(event), Some(StorageBody::Erase))
                    && self.request_state(id) == RequestState::Late)
                    .then_some(event.author())
            })
            .collect();
        let enrolments: BTreeSet<_> = self
            .held
            .iter()
            .copied()
            .filter(|&id| {
                self.log.event(id).is_some_and(|event| {
                    late_erasers.contains(&event.author())
                        && matches!(
                            read_storage(event),
                            Some(StorageBody::Root { .. } | StorageBody::Enrol { .. })
                        )
                })
            })
            .collect();
        plan(
            self.log,
            self.envelopes,
            checkpoint,
            cut,
            &past,
            &requests,
            |id, event| enrolments.contains(&id) || keep_whole(id, event),
        )
    }

    /// The skeleton events late at the peer under the last cut in effect
    /// there, with the classes of the late enrolments it refuses (peers.md,
    /// "Skeleton cuts", what a late enrolment opens).
    pub fn late_refused(&self) -> BTreeMap<EventId, PeersClass> {
        match self.current() {
            Some(cut) => {
                let late = self.late_within(cut, &self.held);
                self.late_enrolment_checks(&late, &self.held)
            }
            None => BTreeMap::new(),
        }
    }

    /// The skeleton of the world of a cut in the chain of cuts in effect at
    /// the peer, over every event it holds: the cut and the events that
    /// follow its checkpoint, the late ones marked. In it a slot of the cut
    /// acknowledges the requests of the cut's past ([`stable_past`]).
    pub fn skeleton_after(&self, cut: EventId) -> Option<Skeleton<'a>> {
        self.chain()
            .contains(&cut)
            .then(|| self.world(cut, &self.held))
    }

    /// What the peer reports, as awaiting, to an administration connection
    /// of `pseudonym` (peers.md, "Administration connections"): for each
    /// valid cut of the epoch after the last cut in effect whose checkpoint
    /// follows that cut's, the checkpoint, while a slot the cut waits for
    /// and `pseudonym` votes for has no vote that counts, so that its client
    /// signs an event that follows it. Lowerings that excuse a slot are not
    /// reported: every vote counts whatever its past holds.
    pub fn awaiting_votes_of(&self, pseudonym: &DeviceId) -> Vec<EventId> {
        self.awaiting_votes().remove(pseudonym).unwrap_or_default()
    }

    /// Pending checkpoints by voting pseudonym, computed together for all
    /// administration connections, with one pass over each cut's slots.
    pub fn awaiting_votes(&self) -> BTreeMap<DeviceId, Vec<EventId>> {
        let current = self.current();
        let epoch = current
            .and_then(|c| self.body(c))
            .map_or(1, |c| c.epoch + 1);
        let mut out: BTreeMap<DeviceId, Vec<EventId>> = BTreeMap::new();
        for (&id, cut) in &self.cuts {
            if Some(id) == current || cut.epoch != epoch || !self.validity(id).is_valid() {
                continue;
            }
            let Some(checkpoint) = self.checkpoint_of(id) else {
                continue;
            };
            if !current.is_none_or(|c| {
                self.follows_cut(checkpoint, c) == Ok(true)
                    && Some(checkpoint) != self.checkpoint_of(c)
            }) {
                continue;
            }
            let Some(tally) = self.tally(id) else {
                continue;
            };
            for slot in tally.awaiting() {
                if let Some(voters) = tally.voters.get(&slot) {
                    for &pseudonym in voters {
                        out.entry(pseudonym).or_default().push(checkpoint);
                    }
                }
            }
        }
        for checkpoints in out.values_mut() {
            checkpoints.sort_unstable();
            checkpoints.dedup();
        }
        out
    }

    /// The skeleton a peer resolves over what it holds: from the last cut in
    /// effect, or from the root when none is. Each cut it holds has the
    /// status [`PeerCuts::validity`] gives it.
    pub fn skeleton(&self) -> Skeleton<'a> {
        self.skeleton_within(&self.held, self.kept.as_ref().map(|(id, _)| *id))
            .0
    }

    /// The skeleton in which the erasures and credentials requests of a cut's
    /// checkpoint's past are judged (peers.md, "Truncation", when): the one
    /// the peer resolved before the cut took effect, from the cut in effect
    /// before it, or from the root when none was, over every event the peer
    /// holds, so that a vote after the checkpoint acknowledges them too.
    /// `None` when the cut is not in the chain of cuts in effect at the peer,
    /// or is the cut it kept when it truncated, whose past it no longer
    /// judges.
    ///
    /// A peer waits to truncate under the cut until
    /// [`requests_settled`] holds in it, and carries those requests out as
    /// it judges them there, stable by [`stable_past`]: a slot of the cut
    /// also acknowledges them through its pseudonym in the cut's world
    /// ([`PeerCuts::skeleton_after`]).
    pub fn skeleton_before(&self, cut: EventId) -> Option<Skeleton<'a>> {
        let chain = self.chain();
        let at = chain.iter().position(|&c| c == cut)?;
        if self.kept.as_ref().is_some_and(|(kept, _)| *kept == cut) {
            return None;
        }
        Some(match at.checked_sub(1).map(|before| chain[before]) {
            Some(before) => self.world(before, &self.held),
            None => {
                let presets = self
                    .cuts
                    .keys()
                    .filter(|id| self.held.contains(id))
                    .map(|&id| (id, self.validity(id)))
                    .collect_map();
                Skeleton::with_presets(self.log, self.held.clone(), presets)
            }
        })
    }

    /// The slots a cut made now would carry, with its epoch: those of the
    /// merged skeleton of `past`, the events the cut's parents hold, and one
    /// more than the epoch of the last cut in effect there. A client that
    /// checkpoints signs the cut with them, and with the standing entries
    /// its checkpoint's record gives ([`standing_entries`]).
    pub fn slots_for(&self, past: &BTreeSet<EventId>) -> (u64, Vec<SlotEntry>) {
        let base = self
            .kept
            .as_ref()
            .map(|(id, _)| *id)
            .filter(|id| past.contains(id));
        let (skeleton, chain) = self.skeleton_within(past, base);
        let epoch = chain
            .last()
            .and_then(|&last| self.body(last))
            .map_or(1, |last| last.epoch + 1);
        (epoch, skeleton.cut_slots())
    }

    /// The merged skeleton of `past`, from the last cut in effect there:
    /// where a cut made now finds its slots, and the out slots its standing
    /// entries may name.
    pub fn skeleton_of(&self, past: &BTreeSet<EventId>) -> Skeleton<'a> {
        let base = self
            .kept
            .as_ref()
            .map(|(id, _)| *id)
            .filter(|id| past.contains(id));
        self.skeleton_within(past, base).0
    }
}

/// Twin → its naming event among `held` (peers.md, "Skeleton cuts", step 3):
/// for a twin `is_cut` accepts, the first space event in canonical order
/// that names it, cites it and has every other parent in its past or not
/// held; for any other, the first that names it.
fn names(
    log: &Log,
    held: &BTreeSet<EventId>,
    is_cut: impl Fn(EventId) -> bool,
) -> BTreeMap<EventId, EventId> {
    let mut out = BTreeMap::new();
    for id in log.canonical_in(held) {
        let Some(event) = log.event(id) else { continue };
        let Some(twin) = named_twin(event) else {
            continue;
        };
        if out.contains_key(&twin) {
            continue;
        }
        if is_cut(twin) {
            let cites = event.parents().contains(&twin);
            let rest = event
                .parents()
                .iter()
                .all(|&p| p == twin || !held.contains(&p) || log.precedes(p, twin));
            if !(cites && rest) {
                continue;
            }
        }
        out.insert(twin, id);
    }
    out
}

/// Step 7 of a cut's checks (peers.md, "Skeleton cuts"): each standing entry
/// names a slot of the cut, with no pseudonym; or a slot `out` accepts, one
/// not in the merged skeleton of the cut's past, with no pseudonym or one
/// `enrols` accepts, a root or enrolment of that slot the peer holds. The
/// orders are 1 to n, the number of entries, each once; a `dormant` value
/// from 3 is `2 + k` with `k` from 1 to n + 1.
pub fn standing_consistent(
    cut: &Cut,
    out: impl Fn(SlotId) -> bool,
    enrols: impl Fn(EventId, SlotId) -> bool,
) -> bool {
    let slots: BTreeSet<SlotId> = cut.slots.iter().map(|entry| entry.slot).collect();
    let mut orders: Vec<u64> = cut.standing.iter().map(|x| x.order).collect();
    orders.sort_unstable();
    let n = orders.len() as u64;
    orders.iter().copied().eq(1..=n)
        && cut.standing.iter().all(|x| {
            if slots.contains(&x.slot) {
                x.pseudonym.is_none()
            } else {
                out(x.slot) && x.pseudonym.is_none_or(|id| enrols(id, x.slot))
            }
        })
        && cut
            .standing
            .iter()
            .all(|x| x.dormant < 3 || (1..=n + 1).contains(&(x.dormant - 2)))
}

/// Whether `event` is the root or an enrolment of `slot`: an enrolment that
/// names it, or the root whose event ID is its maker.
pub fn enrols(event: &Event, slot: SlotId) -> bool {
    match read_storage(event) {
        Some(StorageBody::Enrol { slot: named, .. }) => named == slot,
        Some(StorageBody::Root { .. }) => slot.maker == event.id(),
        _ => false,
    }
}

/// The root or enrolment of the pseudonym enrolled in `slot` in
/// `skeleton`, the merged skeleton of a checkpoint's past: what the
/// standing entry of a heard member's out slot names ([`StandingMember::
/// pseudonym`]). None when no pseudonym is enrolled there.
pub fn enrolment_of(skeleton: &Skeleton<'_>, slot: SlotId) -> Option<EventId> {
    let pseudonym = skeleton.merged().get(&slot)?.enrolled?;
    skeleton.enrolled_by(&pseudonym)
}

fn void(class: PeersClass) -> Status {
    Status::Void { class, by: None }
}

// ---------------------------------------------------------------------------
// A replica's check of a cut against the record.

/// An administrator of a checkpoint's record, as its member entry's key 13
/// `slot` gives it (roster.md, "The checkpoint record"): its administrator
/// slot's reference and the pseudonym enrolled in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordSlot {
    /// The slot reference `[c, index, maker]`.
    pub slot: SlotId,
    /// The device ID of the pseudonym enrolled in it; none when none is.
    pub pseudonym: Option<DeviceId>,
}

/// A replica's check of a cut against its checkpoint's record (peers.md,
/// "Skeleton cuts", the replica's check against the record; roster.md,
/// "Checkpoints", twins and the skeleton): each `slot` entry of the record's
/// administrators names a slot of the cut, whose `pseudonym` names a root
/// or enrolment, held in `log`, by that entry's pseudonym, or is empty
/// exactly when the entry's is. The cut's other slots, planted ones and
/// those whose disown a replica deems justified, are slots no `slot` entry
/// names: they map to no device.
///
/// `administrators` holds one item per administrator of the record: its
/// `slot`, or none when its member entry carries no key 13, which names no
/// slot of the cut. That the cut declares the same cuts as its checkpoint
/// is the twin check's step 7 ([`crate::twins`]). The roster layer reads
/// the record and the twin check calls this as its step 6, then
/// [`check_standing`].
///
/// # Errors
///
/// `BadTwin`: a `slot` entry naming a slot the cut lacks, or whose
/// pseudonym is not the one the cut's entry enrols there.
pub fn check_against_record(
    log: &Log,
    cut: &Cut,
    administrators: &[Option<RecordSlot>],
) -> Result<(), PeersClass> {
    let slots: BTreeMap<SlotId, &SlotEntry> = cut
        .slots
        .iter()
        .map(|entry| (entry.slot, entry))
        .collect_map();
    for administrator in administrators.iter().flatten() {
        let Some(entry) = slots.get(&administrator.slot) else {
            return Err(PeersClass::BadTwin);
        };
        let pseudonym = match entry.pseudonym {
            None => None,
            Some(_) => Some(entry_pseudonym(log, entry).ok_or(PeersClass::BadTwin)?),
        };
        if pseudonym != administrator.pseudonym {
            return Err(PeersClass::BadTwin);
        }
    }
    Ok(())
}

/// Whether a checkpoint of `epoch`, `checkpoint` its ID, valid and not in
/// the chain in effect, can still take effect (peers.md, "Erasure",
/// undecided cuts; roster.md, 3.15.4): its epoch is later than the last of
/// `chain`'s (any, without one), or equal to that of a checkpoint of
/// `chain` whose ID is larger, which it could replace. `chain` gives each
/// checkpoint in effect, oldest first, with its epoch. A peer reads it of
/// its cuts and their checkpoints, a replica of its own chain of
/// checkpoints: one test over two holdings.
pub fn can_still_take_effect(epoch: u64, checkpoint: EventId, chain: &[(u64, EventId)]) -> bool {
    let current = chain.last().map_or(0, |&(e, _)| e);
    epoch > current || chain.iter().any(|&(e, c)| e == epoch && checkpoint < c)
}

/// A replica's check of a cut's standing entries against its checkpoint's
/// record (peers.md, "Skeleton cuts", the replica's check against the
/// record): they are exactly `expected`, the entries the record gives
/// ([`standing_entries`]), in any order.
///
/// # Errors
///
/// `BadTwin`.
pub fn check_standing(cut: &Cut, expected: &[StandingEntry]) -> Result<(), PeersClass> {
    let key = |x: &StandingEntry| (x.sort_bytes(), x.order, x.dormant, x.pseudonym);
    let mut have: Vec<_> = cut.standing.iter().map(key).collect();
    let mut want: Vec<_> = expected.iter().map(key).collect();
    have.sort_unstable();
    want.sort_unstable();
    if have == want {
        Ok(())
    } else {
        Err(PeersClass::BadTwin)
    }
}

/// How a member of a checkpoint's record stands as to `frasil.dormant`, for
/// its standing entry's `dormant` (peers.md, "Storage events").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dormancy {
    /// Its capabilities do not extend `frasil.dormant`, or it is a heard
    /// member: 0.
    Votes,
    /// Dormant, and none of the below: 1.
    Dormant,
    /// A recovery member by the predecessor's record: 2.
    Recovery,
    /// Without a predecessor, dormant with its grant in the checkpoint's past
    /// signed by the member at this index of the members given: `2 + k`,
    /// where exactly `k - 1` entries outrank that member, whether or not it
    /// has an entry itself. Its own index, or one past the members, counts
    /// as [`Dormancy::Dormant`].
    GrantedBy(usize),
}

/// A member of a checkpoint's record that a standing entry may name: an
/// administrator of the record, or a member it hears. Every such member is
/// given, with a slot or without: one without a slot has no entry and no
/// order, but may still have signed another's grant
/// ([`Dormancy::GrantedBy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StandingMember<K> {
    /// The order of authority, smallest first: the higher rank, then the
    /// more senior, as the record gives them.
    pub key: K,
    /// The slot its entry names: an administrator's `slot` entry (key 13),
    /// or the most senior slot made for a heard member, out in the
    /// skeleton of the checkpoint's past. None for a member with no such
    /// slot, which has no entry.
    pub slot: Option<SlotId>,
    /// For a slot that is out, a heard member's: the event ID of the root or
    /// enrolment of the pseudonym enrolled in it in the skeleton of the
    /// checkpoint's past ([`enrolment_of`]), whose pseudonym votes for it.
    /// None when no pseudonym is enrolled there, and always none for an
    /// administrator's slot, which is among the cut's `slots`.
    pub pseudonym: Option<EventId>,
    /// Its dormancy.
    pub dormancy: Dormancy,
}

/// The standing entries a checkpoint's record gives (peers.md, "Storage
/// events"): one for each member with a slot, strictly ascending by the
/// bytes of its slot reference. The orders are 1 to the number of entries,
/// by `key` among the members with a slot, with no gap for a member without
/// one; a member granted by another ([`Dormancy::GrantedBy`]) is `2 + k`,
/// `k` one more than the number of entries whose member outranks its
/// granter.
pub fn standing_entries<K: Ord>(members: &[StandingMember<K>]) -> Vec<StandingEntry> {
    let mut ranked: Vec<usize> = (0..members.len())
        .filter(|&index| members[index].slot.is_some())
        .collect();
    ranked.sort_by(|&a, &b| members[a].key.cmp(&members[b].key));
    let mut order = vec![0u64; members.len()];
    for (place, &index) in ranked.iter().enumerate() {
        order[index] = place as u64 + 1;
    }
    let outranking = |granter: usize| {
        ranked.partition_point(|&index| members[index].key < members[granter].key) as u64
    };
    let mut out: Vec<StandingEntry> = members
        .iter()
        .enumerate()
        .filter_map(|(index, member)| {
            let slot = member.slot?;
            let dormant = match member.dormancy {
                Dormancy::Votes => 0,
                Dormancy::Dormant => 1,
                Dormancy::Recovery => 2,
                Dormancy::GrantedBy(granter) if granter != index && granter < members.len() => {
                    3 + outranking(granter)
                }
                Dormancy::GrantedBy(_) => 1,
            };
            Some(StandingEntry {
                slot,
                order: order[index],
                dormant,
                pseudonym: member.pseudonym,
            })
        })
        .collect();
    out.sort_by_cached_key(StandingEntry::sort_bytes);
    out
}

// ---------------------------------------------------------------------------
// Truncation (peers.md, "Truncation").

/// Whether a peer may truncate under a cut that took effect at
/// `in_effect_since` on its timeline: once that has held for
/// `cut_retention`, read with `lower`.
pub fn may_truncate(in_effect_since: &Reading, now: &Reading, retention: u64) -> bool {
    lower(in_effect_since, now) >= retention
}

/// What a peer keeps of an event in a checkpoint's past when it truncates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Keep {
    /// It may delete the event, and keeps its ID for its own placement.
    Delete,
    /// It keeps the event's envelope: a checkpoint the kept checkpoint's
    /// cuts reach, which orders checkpoints (events.md, "Cuts").
    Envelope,
    /// It keeps the event whole.
    Whole,
}

/// What a peer keeps and deletes when it truncates under a checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TruncationPlan {
    /// The events it may delete; it keeps their IDs ([`placeable`],
    /// [`answer_want`]).
    pub delete: BTreeSet<EventId>,
    /// The checkpoints whose envelopes it keeps.
    pub envelopes: BTreeSet<EventId>,
    /// The events in the checkpoint's past it keeps whole.
    pub whole: BTreeSet<EventId>,
    /// The releases and restores of the checkpoint's past it keeps
    /// ([`PeerCuts::kept_requests`]), among [`TruncationPlan::whole`]: a
    /// peer notes them, since the order that put them in that past goes
    /// with the events it deletes.
    pub requests: BTreeSet<EventId>,
}

impl TruncationPlan {
    /// The bytes deleting [`TruncationPlan::delete`] takes out of usage: the
    /// signed events. The objects only those units reference leave with
    /// them, by the peer's own index.
    pub fn deleted_bytes(&self, log: &Log) -> u64 {
        self.delete
            .iter()
            .filter_map(|&id| log.event(id))
            .map(|event| event.signed_len() as u64)
            .sum()
    }
}

/// What a peer keeps of an event in a checkpoint's past when it truncates
/// under it (peers.md, "Truncation"): `always`, the genesis, the cut, the
/// roots and enrolments the cut's slot entries name and the releases and
/// restores it keeps, whole; the envelopes of `reached`, the checkpoints the
/// checkpoint's cuts reach; and whatever `keep` asks for whole: the units,
/// which follow collection. Everything else it may delete.
pub fn keep(
    event: &Event,
    always: &BTreeSet<EventId>,
    reached: &BTreeSet<EventId>,
    keep: impl Fn(EventId, &Event) -> bool,
) -> Keep {
    let id = event.id();
    if always.contains(&id) {
        return Keep::Whole;
    }
    if reached.contains(&id) {
        return Keep::Envelope;
    }
    if keep(id, event) {
        Keep::Whole
    } else {
        Keep::Delete
    }
}

/// The events of a checkpoint's past a peer always keeps whole when it
/// truncates under its cut (peers.md, "Truncation"): the genesis, the cut,
/// the root or enrolment each slot entry of the cut names, which carries
/// its pseudonym's key, and the root or enrolment each of its standing
/// entries names, whose pseudonym votes for an out slot. Of the releases
/// and restores it keeps some too ([`PeerCuts::kept_requests`]).
pub fn always_kept(log: &Log, cut: EventId) -> BTreeSet<EventId> {
    let mut out = BTreeSet::from([log.id(), cut]);
    if let Some(body) = log.event(cut).and_then(read_cut) {
        out.extend(body.slots.iter().filter_map(|entry| entry.pseudonym));
        out.extend(body.standing.iter().filter_map(|x| x.pseudonym));
    }
    out
}

/// The plan for truncating under `checkpoint`, whose cut is `cut`, over the
/// events `log` holds in its past ([`keep`], [`always_kept`]), keeping
/// `requests`, the releases and restores [`PeerCuts::kept_requests`] gives.
/// [`PeerCuts::truncation_plan`] is this over what a peer holds, at a peer
/// that may have truncated before.
///
/// # Errors
///
/// The checkpoints whose envelopes it waits for.
pub fn truncation_plan(
    log: &Log,
    envelopes: &impl HeldEnvelopes,
    checkpoint: EventId,
    cut: EventId,
    requests: &BTreeSet<EventId>,
    keep_whole: impl Fn(EventId, &Event) -> bool,
) -> Result<TruncationPlan, Vec<EventId>> {
    let past = log.past(checkpoint);
    plan(log, envelopes, checkpoint, cut, &past, requests, keep_whole)
}

fn plan(
    log: &Log,
    envelopes: &(impl HeldEnvelopes + ?Sized),
    checkpoint: EventId,
    cut: EventId,
    past: &BTreeSet<EventId>,
    requests: &BTreeSet<EventId>,
    keep_whole: impl Fn(EventId, &Event) -> bool,
) -> Result<TruncationPlan, Vec<EventId>> {
    let mut reached = match envelopes.held_envelope(checkpoint) {
        Some(c) => event_cuts::reach(envelopes, c.cuts())?,
        None => BTreeSet::new(),
    };
    reached.extend(named_cuts(
        log.canonical().into_iter().filter_map(|id| log.event(id)),
    ));
    let mut always = always_kept(log, cut);
    always.extend(requests.iter().copied());
    let mut plan = TruncationPlan::default();
    for &id in past {
        let Some(event) = log.event(id) else { continue };
        match keep(event, &always, &reached, &keep_whole) {
            Keep::Delete => plan.delete.insert(id),
            Keep::Envelope => plan.envelopes.insert(id),
            Keep::Whole => {
                if requests.contains(&id) {
                    plan.requests.insert(id);
                }
                plan.whole.insert(id)
            }
        };
    }
    Ok(plan)
}

/// Whether every erasure and credentials request in `checkpoint`'s past is
/// carried out or void at the peer, as truncation under it waits for
/// (peers.md, "Truncation", when): each such request `skeleton` holds is
/// void there, or `settled` says it was carried out. Truncation would take
/// away the place a waiting one is judged at. `skeleton` is the one those
/// requests are judged in, [`PeerCuts::skeleton_before`] the cut.
pub fn requests_settled(
    skeleton: &Skeleton<'_>,
    checkpoint: EventId,
    settled: impl Fn(EventId) -> bool,
) -> bool {
    let past = skeleton.log().past(checkpoint);
    skeleton.skeleton_events().iter().all(|&id| {
        let request = skeleton.body_of(id).is_some_and(|body| {
            matches!(
                body.storage_type(),
                StorageType::Erase | StorageType::Credentials
            )
        });
        !request || !past.contains(&id) || !skeleton.is_valid(id) || settled(id)
    })
}

/// Whether an administrator slot acknowledged `target`, an erasure or
/// credentials request of a cut's checkpoint's past (peers.md, "Skeleton
/// cuts", requests of the cut's past): in `before`, the skeleton the request
/// was made in, from the cut in effect before the cut or the root, over
/// every event the peer holds, by an acknowledging event that holds it
/// ([`Skeleton::acknowledged`], which excuses a forked pseudonym); or, for
/// a slot of the cut, by any skeleton event after the cut of the pseudonym
/// enrolled in it in `after`, the cut's world, at the cut or later. Every
/// such event holds the cut's whole past, so no acknowledgement needs the
/// request itself.
pub fn acknowledged_past(
    before: &Skeleton<'_>,
    after: &Skeleton<'_>,
    target: EventId,
    slot: SlotId,
) -> bool {
    if before.acknowledged(target, &[slot]) {
        return true;
    }
    if !after.is_cut_slot(slot) {
        return false;
    }
    let Some(pseudonym) = after.merged().get(&slot).and_then(|s| s.enrolled) else {
        return false;
    };
    after.forks().fork_point(&pseudonym).is_none()
        && after.log().chain_rev(&pseudonym).any(|id| {
            Some(id) != after.root()
                && !after.late_events().contains(&id)
                && after
                    .body_of(id)
                    .is_some_and(|body| body.storage_type().is_skeleton())
        })
}

/// Whether `target`, an erasure or credentials request of a cut's
/// checkpoint's past, is stable at the peer (peers.md, "Skeleton cuts",
/// requests of the cut's past): every administrator slot of `before`'s
/// stability set acknowledged it ([`acknowledged_past`]). `after` is the
/// cut's world ([`PeerCuts::skeleton_after`]); `before` the skeleton
/// before it ([`PeerCuts::skeleton_before`]), in which the request keeps
/// its verdict.
pub fn stable_past(
    before: &Skeleton<'_>,
    after: &Skeleton<'_>,
    target: EventId,
    clock: Option<&Clock<'_>>,
) -> bool {
    before
        .stability_set(clock)
        .into_iter()
        .all(|slot| acknowledged_past(before, after, target, slot))
}

/// The envelopes a peer that truncated reads: the log's, then those of the
/// checkpoints it deleted but keeps for ordering (events.md, "Cuts").
#[derive(Debug, Clone, Copy)]
pub struct PeerEnvelopes<'a> {
    /// The log of what it holds.
    pub log: &'a Log,
    /// The envelopes it keeps of deleted checkpoints, by ID.
    pub kept: &'a BTreeMap<EventId, Event>,
}

impl HeldEnvelopes for PeerEnvelopes<'_> {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        self.log.held_envelope(id).or_else(|| self.kept.get(&id))
    }
}

/// Whether a peer that truncated places an event with these parents: each
/// is stored, or deleted, in which case it is placed as if that parent were
/// stored (peers.md, "Truncation").
///
/// # Errors
///
/// The parents it lacks, ascending: the event is pending.
pub fn placeable(
    parents: &[EventId],
    stored: impl Fn(EventId) -> bool,
    deleted: &BTreeSet<EventId>,
) -> Result<(), Vec<EventId>> {
    let mut missing: Vec<EventId> = parents
        .iter()
        .copied()
        .filter(|&p| !stored(p) && !deleted.contains(&p))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        missing.sort_unstable();
        missing.dedup();
        Err(missing)
    }
}

/// A peer's answer to a `Want` for one event (units.md, "Messages").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WantAnswer {
    /// It serves the event.
    Serve,
    /// It answers `Missing`: it deleted the event when it truncated, or never
    /// held it.
    Missing,
}

/// A `Want` for an event after truncation: a deleted event is `Missing`
/// (peers.md, "Truncation"), even when its ID still places its children.
pub fn answer_want(
    id: EventId,
    stored: impl Fn(EventId) -> bool,
    deleted: &BTreeSet<EventId>,
) -> WantAnswer {
    if !deleted.contains(&id) && stored(id) {
        WantAnswer::Serve
    } else {
        WantAnswer::Missing
    }
}

/// The checkpoints a peer calls cuts (peers.md, "Truncation"): those some
/// stored event's cuts name.
pub fn named_cuts<'e>(events: impl IntoIterator<Item = &'e Event>) -> BTreeSet<EventId> {
    events
        .into_iter()
        .flat_map(|event| event.cuts().iter().copied())
        .collect()
}

/// Whether an event is late at a peer that keeps `checkpoint`: it neither
/// is it nor follows it. A late event is stored as any event, so that
/// replicas can read its envelope.
///
/// # Errors
///
/// The checkpoints whose envelopes the answer waits for.
pub fn is_late(
    envelopes: &impl HeldEnvelopes,
    event: &Event,
    checkpoint: EventId,
) -> Result<bool, Vec<EventId>> {
    if event.id() == checkpoint {
        return Ok(false);
    }
    event_cuts::follows(envelopes, event, checkpoint).map(|follows| !follows)
}
