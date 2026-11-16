//! What replicas check of twins, roots and enrolments (peers.md, "What
//! replicas check").
//!
//! A replica runs these for the genesis and for each roster event `R` it has
//! opened that changes who administers:
//!
//! ```text
//! 1. The genesis: a root is held.                                      else NoTwin
//!    R: roster.md checks that R names a twin exactly when it changes
//!    who administers.                                                  else TwinRequired / UnexpectedTwin
//! 2. The twin R names is held.                                         else NoTwin
//! 3. A root: one that the peer's checks do not refuse, with twin
//!    c(genesis) and duel_policy the genesis's.
//!    A twin: a change that the peer's checks do not refuse, with
//!    twin = c(R) under its own salt.                                   else BadTwin
//! 4. Its author's administrator slot was made for R's author's device,
//!    and its enrolment is not foreign.                                 else BadTwin
//! 5. Its author has not forked at or before it.                        else BadTwin
//! 6. Its grants are one per device R grants administer, each with the
//!    rank R gives that device, in R's order; or its lower names the
//!    administrator slot of the device R lowers.                        else BadTwin
//! 7. R cites it; its parents are skeleton events and checkpoints; its
//!    cuts are R's; every skeleton event in R's past other than the twin
//!    is in its past.                                                   else BadTwin
//! 8. The cite-together rule holds for R.                               else BadTwin
//! ```
//!
//! A checkpoint's twin is its skeleton cut (roster.md, 3.15.8 Other logs and
//! extensions, "Twins and the skeleton"; peers.md, "Skeleton cuts"): the
//! same steps hold, step 3 reading a cut where it reads a change, and step
//! 6 read as: the cut's slots are, one for one, the administrators of the
//! checkpoint's record, each slot's enrolled pseudonym the one the record's
//! `slot` names, and its standing entries exactly those the record gives
//! ([`TwinChecks::check_checkpoint_standing`], with [`check_against_record`]
//! and [`check_standing`]); and step 7 as: every other parent of the
//! checkpoint is in the cut's past, whatever the cut's own parents are.
//!
//! Step 1's roster half is roster.md's. What only the roster knows (which
//! roster events the replica opened, their body keys, the devices each
//! grants `administer` or lowers from it and the rank each grant gives, the
//! genesis's duel policy, each device's keys by its device ID and who
//! administers at a place) comes through [`RosterFacts`], which the roster
//! implements.

use crate::PeersClass;
use crate::body::{Cut, SlotId, StandingEntry, StorageBody};
use crate::cut::{RecordSlot, check_against_record, check_standing, read_cut};
use crate::derive::{device_statement, open_binding, twin_commitment, twin_secret, verify_hybrid};
use crate::limits::MAX_RANK;
use crate::skeleton::{Skeleton, Status, named_twin, refused_at_store};
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// The devices a roster event grants `administer` and those it lowers from
/// it, each in the order of the roster event's changes (peers.md, "The
/// skeleton", a change).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdministerChanges {
    /// Devices granted `administer`, or raised to it, by device ID.
    pub grants: Vec<DeviceId>,
    /// Devices at `administer` removed or lowered, by device ID.
    pub lowers: Vec<DeviceId>,
}

impl AdministerChanges {
    /// Whether the roster event changes who administers.
    pub fn changes_administration(&self) -> bool {
        !self.grants.is_empty() || !self.lowers.is_empty()
    }
}

/// What the roster tells the twin checks (roster.md; keys.md, "The space
/// event's body"). The roster implements it.
pub trait RosterFacts {
    /// The roster events the replica has opened, the genesis among them, in
    /// canonical order.
    fn opened(&self) -> Vec<EventId>;

    /// An opened roster event's body key.
    fn body_key(&self, event: EventId) -> Option<[u8; 32]>;

    /// The devices an opened roster event grants `administer` and lowers
    /// from it; for the genesis, its founder.
    fn administer_changes(&self, event: EventId) -> AdministerChanges;

    /// The rank each grant of an opened roster event gives (roster.md, 2.3
    /// Changes, key 15), one per device of
    /// [`administer_changes`](Self::administer_changes)'s `grants`, in that
    /// order; for the genesis, 255, its founder's. Step 6 checks each twin
    /// grant map's `rank` against it.
    ///
    /// By default, 255 for each grant: a roster whose administrators all
    /// hold the top rank.
    fn grant_ranks(&self, event: EventId) -> Vec<u8> {
        vec![MAX_RANK; self.administer_changes(event).grants.len()]
    }

    /// Whether an opened roster event changes who administers:
    /// [`administer_changes`](Self::administer_changes) and
    /// [`AdministerChanges::changes_administration`], which an
    /// implementation may remember for the roster it reads.
    fn changes_administration(&self, event: EventId) -> bool {
        self.administer_changes(event).changes_administration()
    }

    /// The twin an opened roster event's visible part names, as
    /// [`named_twin`] reads it from the event, which an implementation that
    /// has read the visible part may give from there.
    fn twin_of(&self, event: &frasil_events::Event) -> Option<EventId> {
        named_twin(event)
    }

    /// The genesis's duel policy.
    fn duel_policy(&self) -> u64;

    /// A device's three keys, from any source, which the implementation has
    /// checked hash to `device` (crypto.md, "Keys by their hash"); `None`
    /// when none are held.
    fn device_keys(&self, device: &DeviceId) -> Option<DeviceKeys>;

    /// Whether a device is an administrator in the roster at an event's
    /// place.
    fn is_administrator_at(&self, device: &DeviceId, event: EventId) -> bool;

    /// For a skeleton that starts at a cut ([`Skeleton::cut`]): the device a
    /// slot of the cut maps to, and the pseudonym the mapping names, as the
    /// member entry of the cut's checkpoint record that names the slot in
    /// its `slot` gives them (roster.md, 3.15.5 The world after a
    /// checkpoint, Skeleton). `None` for a slot no entry names, which maps
    /// to no device. None by default: a skeleton from the root.
    fn cut_slot(&self, slot: SlotId) -> Option<(DeviceId, Option<DeviceId>)> {
        let _ = slot;
        None
    }
}

/// What a checkpoint's record gives the twin check of its cut: one item per
/// administrator, its `slot` or none, and the standing entries, when the
/// check compares them.
type CheckpointRecord<'r> = (&'r [Option<RecordSlot>], Option<&'r [StandingEntry]>);

/// Why a twin or root fails, as the vectors name the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BadTwin {
    /// The roster event names no twin.
    NamesNoTwin,
    /// Step 3, a root: refused at the peer, or its commitment or duel
    /// policy.
    Root,
    /// Step 3: not a change the peer's checks accept.
    NotAChange,
    /// Step 3: `twin` is not `c(R)`.
    Commitment,
    /// Step 4.
    Author,
    /// Step 5.
    Forked,
    /// Step 6: the number of grants, or the slot a lower names.
    Grants,
    /// Step 6: a grant's rank is not the one R gives its device.
    Ranks,
    /// Step 7.
    Parents,
    /// Step 8.
    CiteTogether,
    /// Step 6 for a checkpoint: its cut's slots are not the record's
    /// administrators, or its standing entries not those the record gives.
    Record,
}

impl BadTwin {
    /// The reason's name, as the vectors write it.
    pub fn name(self) -> &'static str {
        match self {
            Self::NamesNoTwin => "names no twin",
            Self::Root => "root",
            Self::NotAChange => "not a change",
            Self::Commitment => "commitment",
            Self::Author => "author",
            Self::Forked => "forked",
            Self::Grants => "grants",
            Self::Ranks => "ranks",
            Self::Parents => "parents",
            Self::CiteTogether => "cite-together",
            Self::Record => "record",
        }
    }
}

/// A twin check that fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TwinFailure {
    /// The twin or root is not held: pending (`NoTwin`).
    NoTwin,
    /// It fails a check (`BadTwin`).
    BadTwin(BadTwin),
}

impl TwinFailure {
    /// The class.
    pub fn class(self) -> PeersClass {
        match self {
            Self::NoTwin => PeersClass::NoTwin,
            Self::BadTwin(_) => PeersClass::BadTwin,
        }
    }
}

/// The device a pseudonym's enrolment binds (peers.md, "What replicas
/// check", enrolments).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bound {
    /// The binding opens, names the device the roster event granted at that
    /// index, and its signature verifies under that device's keys. The root's
    /// pseudonym is bound to the genesis's author.
    Device(DeviceId),
    /// The enrolment is foreign: replicas map its pseudonym to no device,
    /// and a disown of its administrator slot is justified.
    Foreign,
    /// No enrolment of the pseudonym is held.
    Unbound,
}

/// A roster event's twin secret and its commitment `c(R)`, under the salt of
/// the twin it names; `None` for the commitment when it names no change.
pub type Commitment = (Zeroizing<[u8; 32]>, Option<[u8; 32]>);

/// A replica's twin checks over a skeleton and the roster's facts.
pub struct TwinChecks<'s, 'a, R: RosterFacts> {
    skeleton: &'s Skeleton<'a>,
    roster: &'s R,
    commitments: RefCell<BTreeMap<EventId, Option<Commitment>>>,
    bound: RefCell<BTreeMap<DeviceId, Bound>>,
}

impl<'s, 'a, R: RosterFacts> TwinChecks<'s, 'a, R> {
    /// The twin checks of a replica that holds `skeleton`'s events and has
    /// opened the roster `roster` describes.
    pub fn new(skeleton: &'s Skeleton<'a>, roster: &'s R) -> Self {
        Self {
            skeleton,
            roster,
            commitments: RefCell::new(BTreeMap::new()),
            bound: RefCell::new(BTreeMap::new()),
        }
    }

    /// An opened roster event's twin secret and commitment `c(R)`, under the
    /// salt of the twin it names in visible key 15; for the genesis, whose
    /// twin is the root, under no salt (peers.md, "Skeleton derivations").
    pub fn commitment(&self, event: EventId) -> Option<Commitment> {
        self.commitments
            .borrow_mut()
            .entry(event)
            .or_insert_with(|| {
                let body_key = self.roster.body_key(event)?;
                let log = self.skeleton.log();
                let e = log.event(event)?;
                let secret = twin_secret(&body_key);
                let salt: Option<Vec<u8>> = if event == log.id() {
                    Some(Vec::new())
                } else {
                    named_twin(e)
                        .and_then(|twin| self.skeleton.body_of(twin))
                        .and_then(|body| match body {
                            StorageBody::Change { salt, .. }
                            | StorageBody::Cut(Cut { salt, .. }) => Some(salt.to_vec()),
                            _ => None,
                        })
                };
                let c = salt.map(|salt| twin_commitment(e.author(), e.seq(), &secret, &salt));
                Some((secret, c))
            })
            .clone()
    }

    /// The opened roster event that made an administrator slot through its
    /// twin: the genesis for the root's; otherwise the roster event the
    /// replica opened that names the slot's maker in visible key 15.
    pub fn roster_event_of(&self, slot: SlotId) -> Option<EventId> {
        let sk = self.skeleton;
        if sk.root() == Some(slot.maker) {
            return Some(sk.log().id());
        }
        let event = sk.named_by(slot.maker)?;
        self.roster.opened().contains(&event).then_some(event)
    }

    /// The device an administrator slot `[c, index, maker]` was made for
    /// (peers.md, "What replicas check"): the device granted `administer`
    /// at `index` by the roster event that names `maker`, the genesis's
    /// author for the root's, when `c` is that event's commitment under
    /// `maker`'s salt; none otherwise.
    ///
    /// In a skeleton that starts at a cut, a slot of the cut maps to the
    /// device its checkpoint record names it for ([`RosterFacts::cut_slot`]).
    pub fn slot_device(&self, slot: SlotId) -> Option<DeviceId> {
        if self.skeleton.cut().is_some()
            && let Some((device, _)) = self.roster.cut_slot(slot)
        {
            return Some(device);
        }
        let event = self.roster_event_of(slot)?;
        let (_, c) = self.commitment(event)?;
        if c != Some(slot.reference.commitment) {
            return None;
        }
        self.roster
            .administer_changes(event)
            .grants
            .get(usize::from(slot.reference.index))
            .copied()
    }

    /// The device a pseudonym's binding names.
    pub fn bound(&self, pseudonym: &DeviceId) -> Bound {
        if let Some(bound) = self.bound.borrow().get(pseudonym) {
            return *bound;
        }
        let bound = self.binding(pseudonym);
        self.bound.borrow_mut().insert(*pseudonym, bound);
        bound
    }

    /// The secret an enrolment's binding is sealed under (peers.md, 2.5
    /// Skeleton derivations): when the enrolment's cuts name a space
    /// checkpoint whose skeleton cut lists its administrator slot, that
    /// checkpoint's `twin_secret`, the one with the smallest event ID if
    /// several; otherwise `twin_secret(R)` of the roster event that names
    /// the slot's maker. It is read from the enrolment's own envelope, so
    /// every replica, whichever checkpoints are in effect at it and whether
    /// or not it forgot the roster event that made the slot, opens the
    /// binding under the same key.
    pub fn binding_secret(
        &self,
        enrolment: &frasil_events::Event,
        slot: SlotId,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let log = self.skeleton.log();
        let listing = enrolment.cuts().iter().copied().filter(|&checkpoint| {
            log.event(checkpoint)
                .and_then(named_twin)
                .and_then(|cut| log.event(cut))
                .and_then(read_cut)
                .is_some_and(|cut| cut.slots.iter().any(|entry| entry.slot == slot))
        });
        let roster_event = match listing.min() {
            Some(checkpoint) => checkpoint,
            None => self.roster_event_of(slot)?,
        };
        self.commitment(roster_event).map(|(secret, _)| secret)
    }

    fn binding(&self, pseudonym: &DeviceId) -> Bound {
        let sk = self.skeleton;
        let log = sk.log();
        if sk.cut().is_some() {
            // A pseudonym enrolled in a slot of the cut, by a root or an
            // enrolment in the cut's past: the device the record maps that
            // slot to, when its entry names the same pseudonym; otherwise
            // no device, as a foreign enrolment's (roster.md, 3.15.5,
            // Skeleton).
            if let Some(enrolment) = sk.enrolled_by(pseudonym)
                && !sk.view().contains(&enrolment)
            {
                return match sk.slot_of(pseudonym).and_then(|s| self.roster.cut_slot(s)) {
                    Some((device, Some(named))) if named == *pseudonym => Bound::Device(device),
                    _ => Bound::Foreign,
                };
            }
        } else if let Some(root) = sk.root()
            && log.event(root).is_some_and(|e| e.author() == pseudonym)
        {
            return Bound::Device(*log.genesis().author());
        }
        for &id in sk.skeleton_events() {
            let event = log.event(id).expect("placed");
            let Some(StorageBody::Enrol { slot, binding, .. }) = sk.body_of(id) else {
                continue;
            };
            if event.author() != pseudonym
                || matches!(sk.status(id), Some(Status::Void { class, .. })
                    if class == PeersClass::UnknownAdministratorSlot
                        || class == frasil_base::ErrorClass::NotCommitted.into()
                        || class == frasil_base::ErrorClass::BadSignature.into())
            {
                continue;
            }
            let (Some(secret), Some(device)) =
                (self.binding_secret(event, *slot), self.slot_device(*slot))
            else {
                return Bound::Foreign;
            };
            let Ok(opened) = open_binding(binding, &secret, &sk.space(), slot.reference, pseudonym)
            else {
                return Bound::Foreign;
            };
            // The device's signature, under the keys its device ID commits
            // to, wherever the roster found them.
            let statement = device_statement(&sk.space(), slot.reference, pseudonym);
            let verifies = opened.device == device
                && self
                    .roster
                    .device_keys(&device)
                    .filter(|keys| keys.check(&device).is_ok())
                    .is_some_and(|keys| {
                        verify_hybrid(&keys.ed, &keys.keys, &statement, &opened.device_signature)
                    });
            return if verifies {
                Bound::Device(device)
            } else {
                Bound::Foreign
            };
        }
        Bound::Unbound
    }

    /// The root's checks (steps 1 and 3 for the genesis).
    ///
    /// # Errors
    ///
    /// `NoTwin` when no root is held; `BadTwin` when the only roots held
    /// are refused by the peer's checks, or the root's commitment or duel
    /// policy is not the genesis's.
    pub fn check_root(&self) -> Result<(), TwinFailure> {
        let sk = self.skeleton;
        let Some(root) = sk.root() else {
            // A root the peer's checks refuse, its founder's keys not the
            // genesis's among them, is held but never passes.
            let refused = sk
                .skeleton_events()
                .iter()
                .any(|&id| matches!(sk.body_of(id), Some(StorageBody::Root { .. })));
            return Err(if refused {
                TwinFailure::BadTwin(BadTwin::Root)
            } else {
                TwinFailure::NoTwin
            });
        };
        let Some(StorageBody::Root {
            twin, duel_policy, ..
        }) = sk.body_of(root)
        else {
            return Err(TwinFailure::NoTwin);
        };
        let genesis = sk.log().id();
        let commitment = self.commitment(genesis).and_then(|(_, c)| c);
        if *duel_policy != self.roster.duel_policy() || commitment != Some(*twin) {
            return Err(TwinFailure::BadTwin(BadTwin::Root));
        }
        Ok(())
    }

    /// Steps 2 to 8 for a roster event that changes who administers, or the
    /// root's checks for the genesis.
    ///
    /// # Errors
    ///
    /// The first step that fails.
    pub fn check(&self, roster_event: EventId) -> Result<(), TwinFailure> {
        if roster_event == self.skeleton.log().id() {
            return self.check_root();
        }
        self.check_named(roster_event, None)
    }

    /// Steps 2 to 8 for a checkpoint, whose twin is its skeleton cut: step 3
    /// reads a cut, and step 6 is [`check_against_record`] of the cut against
    /// `administrators`, one item per administrator of the checkpoint's
    /// record, its `slot` or none.
    ///
    /// # Errors
    ///
    /// The first step that fails: `NoTwin` while the cut is not held.
    ///
    /// It does not compare the cut's standing entries with the record:
    /// [`TwinChecks::check_checkpoint_standing`] does both.
    pub fn check_checkpoint(
        &self,
        checkpoint: EventId,
        administrators: &[Option<RecordSlot>],
    ) -> Result<(), TwinFailure> {
        self.check_named(checkpoint, Some((administrators, None)))
    }

    /// Steps 2 to 8 for a checkpoint, as [`TwinChecks::check_checkpoint`],
    /// step 6 also asking that the cut's standing entries are exactly
    /// `standing`, those the checkpoint's record gives
    /// ([`crate::cut::standing_entries`], [`check_standing`]).
    ///
    /// # Errors
    ///
    /// The first step that fails: `NoTwin` while the cut is not held.
    pub fn check_checkpoint_standing(
        &self,
        checkpoint: EventId,
        administrators: &[Option<RecordSlot>],
        standing: &[StandingEntry],
    ) -> Result<(), TwinFailure> {
        self.check_named(checkpoint, Some((administrators, Some(standing))))
    }

    fn check_named(
        &self,
        roster_event: EventId,
        record: Option<CheckpointRecord<'_>>,
    ) -> Result<(), TwinFailure> {
        let sk = self.skeleton;
        let log = sk.log();
        let bad = |reason| Err(TwinFailure::BadTwin(reason));
        let r = log.event(roster_event).ok_or(TwinFailure::NoTwin)?;
        let Some(twin) = named_twin(r) else {
            return bad(BadTwin::NamesNoTwin);
        };
        // 2. The twin is held.
        if !sk.view().contains(&twin) {
            return Err(TwinFailure::NoTwin);
        }
        let s = log.event(twin).ok_or(TwinFailure::NoTwin)?;
        // 3. A change the peer's checks do not refuse, with twin = c(R)
        // under its own salt.
        let refused =
            matches!(sk.status(twin), Some(Status::Void { class, .. }) if refused_at_store(class));
        let c = match (sk.body_of(twin).filter(|_| !refused), record) {
            (Some(StorageBody::Change { twin: c, .. }), None)
            | (Some(StorageBody::Cut(Cut { twin: c, .. })), Some(_)) => c,
            _ => return bad(BadTwin::NotAChange),
        };
        if self.commitment(roster_event).and_then(|(_, rc)| rc) != Some(*c) {
            return bad(BadTwin::Commitment);
        }
        // 4. Its author's administrator slot was made for R's author's
        // device, and its enrolment is not foreign.
        let slot = sk.slot_of(s.author());
        if slot.and_then(|slot| self.slot_device(slot)).as_ref() != Some(r.author())
            || !matches!(self.bound(s.author()), Bound::Device(_))
        {
            return bad(BadTwin::Author);
        }
        // 5. Its author has not forked at or before it.
        if sk.forks().is_void(s) {
            return bad(BadTwin::Forked);
        }
        // 6. One grant per device R grants administer, each with the rank
        // R gives it; or its lower names the administrator slot of the
        // device R lowers. For a checkpoint, the cut's slots are the
        // record's administrators.
        let body = sk.body_of(twin).expect("a change or a cut");
        if let (StorageBody::Cut(cut), Some((administrators, standing))) = (body, record) {
            if check_against_record(log, cut, administrators).is_err()
                || standing.is_some_and(|standing| check_standing(cut, standing).is_err())
            {
                return bad(BadTwin::Record);
            }
        } else if !self.grants_match(roster_event, body) {
            return bad(BadTwin::Grants);
        } else if !self.ranks_match(roster_event, body) {
            return bad(BadTwin::Ranks);
        }
        self.check_order(roster_event, twin, record.is_some())
    }

    /// Step 6 for a change.
    fn grants_match(&self, roster_event: EventId, body: &StorageBody) -> bool {
        let changes = self.roster.administer_changes(roster_event);
        if let Some(&lowered) = changes.lowers.first() {
            body.lowered()
                .and_then(|slot| self.slot_device(slot))
                .is_some_and(|device| device == lowered)
        } else {
            body.grants().len() == changes.grants.len()
        }
    }

    /// Step 6 for a change's grants: each grant map's `rank` is the rank R
    /// gives the device at its index (peers.md, "What replicas check").
    fn ranks_match(&self, roster_event: EventId, body: &StorageBody) -> bool {
        let grants = body.grants();
        grants.is_empty()
            || grants
                .iter()
                .map(|grant| grant.rank)
                .eq(self.roster.grant_ranks(roster_event))
    }

    /// Steps 7 and 8. For a checkpoint (`cut`), step 7 reads: R cites it,
    /// every other parent of R is in its past, and its cuts are R's
    /// (peers.md, "Skeleton cuts", parents): a cut cites every parent of its
    /// checkpoint beside its pseudonym's previous event, so it is not held
    /// to citing only skeleton events and checkpoints.
    fn check_order(
        &self,
        roster_event: EventId,
        twin: EventId,
        cut: bool,
    ) -> Result<(), TwinFailure> {
        let sk = self.skeleton;
        let log = sk.log();
        let bad = |reason| Err(TwinFailure::BadTwin(reason));
        let r = log.event(roster_event).ok_or(TwinFailure::NoTwin)?;
        let s = log.event(twin).ok_or(TwinFailure::NoTwin)?;
        // 7. R cites it; its parents are skeleton events and checkpoints;
        // its cuts are R's; every skeleton event in R's past other than the
        // twin is in its past. Order is read from R's and the twin's pasts,
        // each found once. A twin follows what its roster event follows
        // (peers.md, "Skeleton cuts"), so beside skeleton events it cites
        // only checkpoints, which its own cuts reach.
        let skeleton: BTreeSet<EventId> = sk.skeleton_events().iter().copied().collect();
        let before_r = log.ancestry(roster_event);
        let before_twin = log.ancestry(twin);
        let parents_ok = if cut {
            r.parents()
                .iter()
                .all(|&p| p == twin || before_twin.includes(p))
        } else {
            let checkpoints = frasil_events::cuts::reach(log, s.cuts())
                .unwrap_or_else(|_| s.cuts().iter().copied().collect());
            s.parents()
                .iter()
                .all(|p| skeleton.contains(p) || checkpoints.contains(p))
        };
        if !r.parents().contains(&twin)
            || !parents_ok
            || s.cuts() != r.cuts()
            || skeleton
                .iter()
                .any(|&x| x != twin && before_r.includes(x) && !before_twin.includes(x))
        {
            return bad(BadTwin::Parents);
        }
        // 8. The cite-together rule: for every other roster event that needs
        // a twin, it is in R's past exactly when its twin is.
        // An event and its twin both in R's past, or both outside it, keep
        // the rule whatever the event changes; only the others need to be
        // asked whether they change who administers.
        for other in self.roster.opened() {
            if other == roster_event || other == log.id() {
                continue;
            }
            let Some(other_twin) = log.event(other).and_then(|e| self.roster.twin_of(e)) else {
                continue;
            };
            if before_r.includes(other) != before_r.includes(other_twin)
                && self.roster.changes_administration(other)
            {
                return bad(BadTwin::CiteTogether);
            }
        }
        Ok(())
    }

    /// Planted administrator slots: made by an applied change that is not
    /// the valid twin of the roster event naming it, such as one a key event
    /// names, or one that repeats another roster event's commitment. In
    /// canonical order of the changes.
    pub fn planted(&self) -> Vec<SlotId> {
        let sk = self.skeleton;
        let opened: BTreeSet<EventId> = self.roster.opened().into_iter().collect();
        let mut out = Vec::new();
        for &change in sk.makers() {
            let Some(StorageBody::Change { twin: c, .. }) = sk.body_of(change) else {
                continue;
            };
            let valid = sk.named_by(change).is_some_and(|r| {
                opened.contains(&r)
                    && self.roster.changes_administration(r)
                    && self.check(r).is_ok()
            });
            if !valid {
                let grants = sk.body_of(change).map_or(0, |b| b.grants().len());
                out.extend((0..grants).map(|index| SlotId::new(*c, index as u8, change)));
            }
        }
        out
    }

    /// Whether a replica deems a disown justified (peers.md, "The
    /// skeleton", a disown): at its place, the administrator slot is
    /// planted, is enrolled foreignly, or belongs to a device that is not an
    /// administrator in the roster.
    pub fn justified(&self, disown: EventId) -> bool {
        let sk = self.skeleton;
        let Some(StorageBody::Disown { slot }) = sk.body_of(disown) else {
            return false;
        };
        let slot = *slot;
        if self.planted().contains(&slot) {
            return true;
        }
        match self.roster_event_of(slot) {
            Some(r) if self.check(r).is_ok() => {}
            _ => return true,
        }
        if sk
            .pseudonyms()
            .any(|(p, s)| s == slot && self.bound(p) == Bound::Foreign)
        {
            return true;
        }
        match self.slot_device(slot) {
            Some(device) => !self.roster.is_administrator_at(&device, disown),
            None => true,
        }
    }

    /// The device of each pseudonym that signs a skeleton event, as the
    /// vectors name them: a device, or foreign (no device).
    pub fn bindings(&self) -> BTreeMap<DeviceId, Option<DeviceId>> {
        let sk = self.skeleton;
        let mut out = BTreeMap::new();
        for &id in sk.skeleton_events() {
            let author = *sk.log().event(id).expect("placed").author();
            out.entry(author)
                .or_insert_with(|| match self.bound(&author) {
                    Bound::Device(device) => Some(device),
                    Bound::Foreign | Bound::Unbound => None,
                });
        }
        out
    }
}
