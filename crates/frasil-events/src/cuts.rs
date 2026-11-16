//! Cuts: the checkpoints an event follows (events.md, 3.11 Cuts).
//!
//! A **checkpoint** is a space event whose roster part is of type 2
//! (roster.md, "Checkpoints"). Only a replica that opens a space event knows
//! whether it is one, so this module asks a [`Checkpoints`] for that and
//! knows nothing else of the roster. An event's `cuts` (envelope key 7)
//! name the checkpoints it follows, so that any party, a peer included,
//! reads from the envelope alone which checkpoints are in an event's past.
//!
//! - **Order among checkpoints.** Checkpoint `x` is **at or before**
//!   checkpoint `y` when `x = y`, or `x` is among the checkpoints `y`'s cuts
//!   reach ([`at_or_before`]). The checkpoints an event's cuts **reach** are
//!   its cuts and, for each, the checkpoints that checkpoint's cuts reach
//!   ([`reach`]).
//! - **What an event declares.** An event's `cuts` are exactly the maximal
//!   checkpoints, under that order, among its parents that are checkpoints
//!   and the cuts its parents declare; none when there is none
//!   ([`expected`]). An event whose `cuts` differ is void (`BadCuts`,
//!   [`check`]). The check waits until each parent's envelope is held
//!   (placed, or fetched and witnessed) and each parent that is a space
//!   event is opened; until then the event is pending.
//! - **A parent held as a stub** (units.md, "Stubs") contributes the cuts
//!   its stub carries ([`Stub::cuts`](crate::Stub::cuts)). A stub stands
//!   only for a unit or an event of an ignorable kind, never for a
//!   checkpoint, so the stub alone answers for the parent.
//! - **A parent the party dropped** after a checkpoint took effect
//!   ([`HeldEnvelopes::dropped`]) is in that checkpoint's past, so all it
//!   could contribute is at or before the checkpoint, which the event's
//!   other parents reach: it contributes nothing, and the check never waits
//!   for it (roster.md, 3.15.6 Forgetting, and starting from a checkpoint).
//!   A newcomer counts as dropped a parent a peer answers `Missing` for.
//! - **The wait ends.** A checkpoint a placed event is or declares is in
//!   that event's causal past, so the party holds it, dropped it, or
//!   fetched it while placing the event. One that is none of these is in no
//!   parent's past: the declaring event's cuts are wrong (`BadCuts`), and
//!   the ID reaches nothing ([`HeldEnvelopes::placed`]; events.md, 3.11
//!   Cuts, "Ordering needs envelopes"; roster.md, 3.15.6, "Envelopes it
//!   fetches"). Only what a placed event declares settles so: the cuts of a
//!   witnessed event, a kept envelope or a stub still wait for what they
//!   name.
//! - **Following.** An event **follows** checkpoint `c` when its cuts reach
//!   `c` ([`follows`]).
//! - At most [`MAX_CUTS`] cuts: a writer that would declare more first waits
//!   for one of the checkpoints it follows to take effect or be voided
//!   (roster.md, "Checkpoints").
//!
//! The check runs after placement (events.md, 3.2 Placement and order) and
//! after the replica opened the space events among the parents (events.md,
//! 3.10 Handing an event to its kind): decoding checks only the shape of
//! `cuts` (events.md, 3.1 Decoding an event, steps 11 and 12).
//!
//! # Ordering needs envelopes
//!
//! [`reach`] walks the cuts of the checkpoints it reaches through their
//! envelopes, which a [`HeldEnvelopes`] gives: the events a party holds,
//! and the envelopes of checkpoints it keeps after it forgot the events
//! around them ([`HeldEnvelopes::kept_envelope`]). A replica keeps the
//! envelope of every checkpoint its kept checkpoint's cuts reach
//! (roster.md, 3.15.6 Forgetting, and starting from a checkpoint), and a
//! space snapshot hands a newcomer those envelopes (units.md, "The space
//! snapshot", key 14). A walk that needs the envelope of a checkpoint the
//! party neither holds nor keeps is pending, never void: it names that
//! checkpoint, which the party fetches. A checkpoint a placed event
//! declares is the exception above: the party dropped it or never will
//! hold it, and the walk goes no further below it.

use crate::EventClass;
use crate::decode::Event;
use crate::envelope::EventId;
use crate::kind;
use crate::log::Log;
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use std::collections::{BTreeMap, BTreeSet};

/// The most cuts an event may declare.
pub const MAX_CUTS: usize = 4;

/// The cuts an event declares, as a stub carries them (units.md, "Stubs"):
/// none, or 1 to [`MAX_CUTS`] event IDs, strictly ascending. It is `Copy`,
/// so that a stub stays one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cuts {
    len: u8,
    ids: [EventId; MAX_CUTS],
}

impl Cuts {
    /// No cuts: an event whose past holds no checkpoint.
    pub const NONE: Self = Self {
        len: 0,
        ids: [EventId([0; 32]); MAX_CUTS],
    };

    /// The cuts these IDs give, if they are at most [`MAX_CUTS`] IDs,
    /// strictly ascending; an empty slice gives [`Cuts::NONE`].
    pub fn new(ids: &[EventId]) -> Option<Self> {
        if ids.len() > MAX_CUTS || !ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return None;
        }
        let mut out = Self::NONE;
        out.ids[..ids.len()].copy_from_slice(ids);
        out.len = u8::try_from(ids.len()).ok()?;
        Some(out)
    }

    /// The cuts an event declares in its envelope.
    pub fn of(event: &Event) -> Self {
        // Decoding admits 1 to 4 IDs, strictly ascending.
        Self::new(event.cuts()).unwrap_or(Self::NONE)
    }

    /// The IDs, strictly ascending.
    pub fn as_slice(&self) -> &[EventId] {
        &self.ids[..usize::from(self.len)]
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::ops::Deref for Cuts {
    type Target = [EventId];

    fn deref(&self) -> &[EventId] {
        self.as_slice()
    }
}

impl core::fmt::Debug for Cuts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl Default for Cuts {
    fn default() -> Self {
        Self::NONE
    }
}

/// What a party holds of the events [`reach`] and [`expected`] read: the
/// envelopes of the events it holds, the envelopes of the checkpoints it
/// keeps beyond them, and the stubs it holds.
///
/// A [`Log`] holds its placed and witnessed events, the checkpoint
/// envelopes it keeps ([`Log::keep_envelope`]) and its stubs. A peer, or a
/// layer that keeps envelopes of its own, implements it over what it holds.
pub trait HeldEnvelopes {
    /// The event with this ID, if its envelope is held: placed, or fetched
    /// and witnessed.
    fn held_envelope(&self, id: EventId) -> Option<&Event>;

    /// The envelope of a checkpoint the party keeps although it does not
    /// hold the event as placed or witnessed (events.md, 3.11 Cuts,
    /// "Ordering needs envelopes"). None by default.
    fn kept_envelope(&self, id: EventId) -> Option<&Event> {
        let _ = id;
        None
    }

    /// The cuts a held stub of this event carries (units.md, "Stubs"), if
    /// the party holds a stub of it that counts. None by default.
    fn stub_cuts(&self, id: EventId) -> Option<Cuts> {
        let _ = id;
        None
    }

    /// Whether the party dropped this event when it forgot the past of its
    /// kept checkpoint, and keeps only its ID (roster.md, 3.15.6
    /// Forgetting, and starting from a checkpoint), or, as a newcomer,
    /// fetched it and was answered `Missing` by a peer that truncated it.
    /// Such a parent contributes no cuts and never holds the check pending.
    /// False by default.
    fn dropped(&self, id: EventId) -> bool {
        let _ = id;
        false
    }

    /// Whether the party placed this event (events.md, 3.2 Placement and
    /// order): its whole past is then held, dropped or stubbed, so a
    /// checkpoint it is or declares whose envelope the party neither holds,
    /// keeps nor dropped is in no parent's past and reaches nothing,
    /// instead of holding a check pending (events.md, 3.11 Cuts, "Ordering
    /// needs envelopes"). False by default: a party that cannot tell waits.
    /// A [`Log`] answers true for an event placed on parents it placed or
    /// dropped; a layer over a log forwards to it.
    fn placed(&self, id: EventId) -> bool {
        let _ = id;
        false
    }

    /// The envelope this party reads an event's cuts from: held, or kept.
    fn envelope(&self, id: EventId) -> Option<&Event> {
        self.held_envelope(id).or_else(|| self.kept_envelope(id))
    }
}

impl HeldEnvelopes for Log {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        self.event(id).or_else(|| self.witnessed(id))
    }

    fn kept_envelope(&self, id: EventId) -> Option<&Event> {
        self.kept_envelope_of(id)
    }

    fn stub_cuts(&self, id: EventId) -> Option<Cuts> {
        self.stub(id).map(|stub| stub.cuts)
    }

    fn dropped(&self, id: EventId) -> bool {
        self.is_dropped(id)
    }

    /// A placed event whose parents are each placed or dropped: one placed
    /// on a stub or a witness rests on a past the log does not hold, and
    /// its declarations still wait for what they name.
    fn placed(&self, id: EventId) -> bool {
        self.event(id).is_some_and(|event| {
            event
                .parents()
                .iter()
                .all(|&parent| self.contains(parent) || self.is_dropped(parent))
        })
    }
}

impl HeldEnvelopes for BTreeMap<EventId, Event> {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        self.get(&id)
    }
}

impl<T: HeldEnvelopes + ?Sized> HeldEnvelopes for &T {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        (**self).held_envelope(id)
    }

    fn kept_envelope(&self, id: EventId) -> Option<&Event> {
        (**self).kept_envelope(id)
    }

    fn stub_cuts(&self, id: EventId) -> Option<Cuts> {
        (**self).stub_cuts(id)
    }

    fn dropped(&self, id: EventId) -> bool {
        (**self).dropped(id)
    }

    fn placed(&self, id: EventId) -> bool {
        (**self).placed(id)
    }
}

/// A [`HeldEnvelopes`] and checkpoint envelopes kept beside it: what a
/// party that keeps envelopes of its own, such as a newcomer handed a
/// snapshot's cut chain, reads through.
#[derive(Debug, Clone, Copy)]
pub struct WithKept<'a, H: ?Sized> {
    /// What the party holds.
    pub held: &'a H,
    /// The checkpoint envelopes it keeps, by ID.
    pub kept: &'a BTreeMap<EventId, Event>,
}

impl<H: HeldEnvelopes + ?Sized> HeldEnvelopes for WithKept<'_, H> {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        self.held.held_envelope(id)
    }

    fn kept_envelope(&self, id: EventId) -> Option<&Event> {
        self.held.kept_envelope(id).or_else(|| self.kept.get(&id))
    }

    fn stub_cuts(&self, id: EventId) -> Option<Cuts> {
        self.held.stub_cuts(id)
    }

    fn dropped(&self, id: EventId) -> bool {
        self.held.dropped(id)
    }

    fn placed(&self, id: EventId) -> bool {
        self.held.placed(id)
    }
}

/// Which space events are checkpoints: what the roster layer knows once it
/// opens a space event's body (roster.md, "Checkpoints"), and the only
/// thing the cuts check needs from it.
///
/// It is asked only about an event that [`may_be_checkpoint`]: a space
/// event other than a genesis. Every other event is no checkpoint.
pub trait Checkpoints {
    /// `Some(true)` when the space event is a checkpoint (its roster part
    /// is of type 2), `Some(false)` when it is not, and `None` while the
    /// replica has not opened it: the cuts of an event that names it as a
    /// parent are then pending.
    fn is_checkpoint(&self, event: &Event) -> Option<bool>;
}

/// A closure answers for each space event.
impl<F: Fn(&Event) -> Option<bool>> Checkpoints for F {
    fn is_checkpoint(&self, event: &Event) -> Option<bool> {
        self(event)
    }
}

/// Exactly these events are checkpoints, and every other space event is
/// opened and is not one.
impl Checkpoints for BTreeSet<EventId> {
    fn is_checkpoint(&self, event: &Event) -> Option<bool> {
        Some(self.contains(&event.id()))
    }
}

/// No space event is a checkpoint: a log in which none was ever signed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoCheckpoints;

impl Checkpoints for NoCheckpoints {
    fn is_checkpoint(&self, _: &Event) -> Option<bool> {
        Some(false)
    }
}

/// Whether an event may be a checkpoint: a space event other than a
/// genesis. Only opening its body tells whether it is one.
pub fn may_be_checkpoint(event: &Event) -> bool {
    event.kind() == kind::SPACE && !event.is_genesis()
}

/// A walk of the cuts from some checkpoints: what it reached, and the
/// reached checkpoints whose envelope the party neither holds nor keeps,
/// below which it could not go.
struct Walk {
    reached: BTreeSet<EventId>,
    missing: BTreeSet<EventId>,
}

/// Walks down from `cuts`. `settled` says that a placed event declares
/// them: a cut whose envelope the party neither holds nor keeps then
/// reaches nothing, as does one the party dropped; below a placed
/// checkpoint the same holds of its own cuts.
fn walk(held: &(impl HeldEnvelopes + ?Sized), cuts: &[EventId], settled: bool) -> Walk {
    let mut reached = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut stack: Vec<(EventId, bool)> = cuts.iter().map(|&cut| (cut, settled)).collect();
    while let Some((cut, settled)) = stack.pop() {
        if !reached.insert(cut) {
            // Reached again from a placed event: no longer waited for.
            if settled {
                missing.remove(&cut);
            }
            continue;
        }
        match held.envelope(cut) {
            Some(event) => {
                let below = held.placed(cut);
                stack.extend(
                    event
                        .cuts()
                        .iter()
                        .copied()
                        .filter(|c| !reached.contains(c) || (below && missing.contains(c)))
                        .map(|c| (c, below)),
                );
            }
            None if settled || held.dropped(cut) => {}
            None => {
                missing.insert(cut);
            }
        }
    }
    Walk { reached, missing }
}

/// The checkpoints these cuts reach: the cuts and, for each, the
/// checkpoints its own cuts reach, read from the envelopes `held` gives.
///
/// # Errors
///
/// The reached checkpoints whose envelope `held` neither holds nor keeps,
/// strictly ascending: the walk is pending until they are fetched.
pub fn reach(
    held: &(impl HeldEnvelopes + ?Sized),
    cuts: &[EventId],
) -> Result<BTreeSet<EventId>, Vec<EventId>> {
    let walk = walk(held, cuts, false);
    if walk.missing.is_empty() {
        Ok(walk.reached)
    } else {
        Err(walk.missing.into_iter().collect())
    }
}

/// Whether `target` is among the checkpoints these cuts reach: yes as soon
/// as the walk finds it, no only once the walk is complete.
fn reaches(
    held: &(impl HeldEnvelopes + ?Sized),
    cuts: &[EventId],
    settled: bool,
    target: EventId,
) -> Result<bool, Vec<EventId>> {
    let walk = walk(held, cuts, settled);
    if walk.reached.contains(&target) {
        Ok(true)
    } else if walk.missing.is_empty() {
        Ok(false)
    } else {
        Err(walk.missing.into_iter().collect())
    }
}

/// Whether checkpoint `x` is at or before checkpoint `y`: `x = y`, or `y`'s
/// cuts reach `x`.
///
/// # Errors
///
/// The checkpoints whose envelopes the answer waits for: `y`'s, or those of
/// checkpoints its cuts reach, that `held` neither holds nor keeps.
pub fn at_or_before(
    held: &(impl HeldEnvelopes + ?Sized),
    x: EventId,
    y: EventId,
) -> Result<bool, Vec<EventId>> {
    if x == y {
        return Ok(true);
    }
    let Some(later) = held.envelope(y) else {
        return Err(vec![y]);
    };
    reaches(held, later.cuts(), held.placed(y), x)
}

/// Whether checkpoints `x` and `y` are concurrent: neither is at or before
/// the other.
///
/// # Errors
///
/// As [`at_or_before`], for either order.
pub fn concurrent(
    held: &(impl HeldEnvelopes + ?Sized),
    x: EventId,
    y: EventId,
) -> Result<bool, Vec<EventId>> {
    let one = at_or_before(held, x, y);
    let other = at_or_before(held, y, x);
    match (one, other) {
        (Ok(true), _) | (_, Ok(true)) => Ok(false),
        (Ok(false), Ok(false)) => Ok(true),
        (Err(a), Err(b)) => Err(a
            .into_iter()
            .chain(b)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()),
        (Err(missing), Ok(false)) | (Ok(false), Err(missing)) => Err(missing),
    }
}

/// Whether `event` follows checkpoint `c`: its cuts reach `c`. It reads the
/// event's envelope, and the envelopes of the checkpoints it reaches.
///
/// # Errors
///
/// The checkpoints whose envelopes the answer waits for, when the walk has
/// not found `c` and could not go below them.
pub fn follows(
    held: &(impl HeldEnvelopes + ?Sized),
    event: &Event,
    c: EventId,
) -> Result<bool, Vec<EventId>> {
    reaches(held, event.cuts(), held.placed(event.id()), c)
}

/// The maximal checkpoints among `found`, under at or before, strictly
/// ascending.
///
/// A member `x` is maximal unless another member's cuts reach it. A member
/// `y` whose walk stopped short could still reach `x`, unless `x` reaches
/// `y`: event IDs are hashes, so no two checkpoints reach each other.
///
/// # Errors
///
/// The checkpoints whose envelopes the answer waits for, strictly
/// ascending: those of members, or of checkpoints below them, without
/// which some member's place is unknown.
pub fn maximal(
    held: &(impl HeldEnvelopes + ?Sized),
    found: &BTreeSet<EventId>,
) -> Result<Vec<EventId>, Vec<EventId>> {
    maximal_settled(held, found, &BTreeSet::new())
}

/// [`maximal`], where a member in `settled` is one a placed event is or
/// declares: without its envelope, it reaches nothing.
fn maximal_settled(
    held: &(impl HeldEnvelopes + ?Sized),
    found: &BTreeSet<EventId>,
    settled: &BTreeSet<EventId>,
) -> Result<Vec<EventId>, Vec<EventId>> {
    if found.len() < 2 {
        return Ok(found.iter().copied().collect());
    }
    // Each member's walk below it, or none when its envelope is not held
    // and its place is not settled.
    let walks: BTreeMap<EventId, Option<Walk>> = found
        .iter()
        .map(|&y| {
            let walk = match held.envelope(y) {
                Some(event) => Some(walk(held, event.cuts(), held.placed(y))),
                None if settled.contains(&y) || held.dropped(y) => Some(Walk {
                    reached: BTreeSet::new(),
                    missing: BTreeSet::new(),
                }),
                None => None,
            };
            (y, walk)
        })
        .collect_map();
    let mut out = Vec::new();
    let mut missing = BTreeSet::new();
    for &x in found {
        let below = walks
            .iter()
            .any(|(&y, walk)| y != x && walk.as_ref().is_some_and(|w| w.reached.contains(&x)));
        if below {
            continue;
        }
        let own = walks[&x].as_ref();
        let mut known = true;
        for (&y, walk) in &walks {
            if y == x || own.is_some_and(|w| w.reached.contains(&y)) {
                continue;
            }
            match walk {
                None => {
                    known = false;
                    missing.insert(y);
                }
                Some(w) if !w.missing.is_empty() => {
                    known = false;
                    missing.extend(w.missing.iter().copied());
                }
                Some(_) => {}
            }
        }
        if known {
            out.push(x);
        }
    }
    if missing.is_empty() {
        Ok(out)
    } else {
        Err(missing.into_iter().collect())
    }
}

/// The cuts an event with these parents declares (events.md, 3.11 Cuts):
/// the maximal checkpoints among the parents that are checkpoints and the
/// cuts the parents declare, strictly ascending; empty when there is none.
/// A parent held only as a stub contributes the cuts its stub carries; a
/// parent the party dropped contributes nothing. A writer sets [`Envelope::cuts`](crate::Envelope::cuts) to them.
///
/// # Errors
///
/// What the answer waits for, in ascending order: the parents whose
/// envelope is not held, that have no stub and that the party did not
/// drop, and the space events among
/// them whose body `checkpoints` has not opened; once those are read, the
/// checkpoints whose envelopes ordering them needs and that the party
/// neither holds nor keeps. The answer is pending until they are.
pub fn expected(
    held: &(impl HeldEnvelopes + ?Sized),
    checkpoints: &(impl Checkpoints + ?Sized),
    parents: &[EventId],
) -> Result<Vec<EventId>, Vec<EventId>> {
    let (found, settled) = found(held, checkpoints, parents)?;
    maximal_settled(held, &found, &settled)
}

/// The checkpoints among the parents and the cuts the parents declare, and
/// those of them a placed parent is or declares.
fn found(
    held: &(impl HeldEnvelopes + ?Sized),
    checkpoints: &(impl Checkpoints + ?Sized),
    parents: &[EventId],
) -> Result<(BTreeSet<EventId>, BTreeSet<EventId>), Vec<EventId>> {
    let mut found = BTreeSet::new();
    let mut settled = BTreeSet::new();
    let mut wanted = BTreeSet::new();
    for &parent in parents {
        let event = match held.held_envelope(parent) {
            Some(event) => event,
            None => {
                // A stub stands for a unit or an ignorable event, never a
                // checkpoint: it gives the parent's cuts and nothing else.
                if let Some(cuts) = held.stub_cuts(parent) {
                    found.extend(cuts.iter().copied());
                    continue;
                }
                match held.kept_envelope(parent) {
                    Some(event) => event,
                    // A dropped parent is in the kept checkpoint's past:
                    // it contributes nothing the other parents do not
                    // reach, and is never waited for.
                    None if held.dropped(parent) => continue,
                    None => {
                        wanted.insert(parent);
                        continue;
                    }
                }
            }
        };
        if may_be_checkpoint(event) {
            match checkpoints.is_checkpoint(event) {
                Some(true) => {
                    found.insert(parent);
                }
                Some(false) => {}
                None => {
                    wanted.insert(parent);
                }
            }
        }
        found.extend(event.cuts().iter().copied());
        if held.placed(parent) {
            settled.extend(event.cuts().iter().copied());
        }
    }
    if wanted.is_empty() {
        Ok((found, settled))
    } else {
        Err(wanted.into_iter().collect())
    }
}

/// What [`check`] found of an event's cuts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutsCheck {
    /// The cuts are the ones the parents give.
    Correct,
    /// The cuts differ from the ones the parents give: the event is void
    /// (`BadCuts`, final).
    Bad,
    /// The check waits for these, strictly ascending (`Pending`): parents
    /// whose envelopes are not held and that have no stub, space events
    /// among them not yet opened, or checkpoints whose envelopes ordering
    /// needs and that the party neither holds nor keeps. The party fetches
    /// them.
    Pending(Vec<EventId>),
}

impl CutsCheck {
    /// The check as a verdict: `BadCuts` or `Pending`, or none.
    ///
    /// # Errors
    ///
    /// [`EventClass::BadCuts`] for [`CutsCheck::Bad`]; the shared
    /// `Pending` for [`CutsCheck::Pending`].
    pub fn verdict(&self) -> Result<(), EventClass> {
        match self {
            Self::Correct => Ok(()),
            Self::Bad => Err(EventClass::BadCuts),
            Self::Pending(_) => Err(ErrorClass::Pending.into()),
        }
    }
}

/// Checks an event's cuts against its parents (events.md, 3.11 Cuts): they
/// must be exactly [`expected`]. A genesis has none, which decoding
/// enforces, and passes.
///
/// Once every parent is read, a declared cut that is neither a parent
/// checkpoint nor among the parents' cuts is void at once: the maximal
/// checkpoints are among those, whatever ordering them finds.
pub fn check(
    held: &(impl HeldEnvelopes + ?Sized),
    checkpoints: &(impl Checkpoints + ?Sized),
    event: &Event,
) -> CutsCheck {
    if event.is_genesis() {
        return CutsCheck::Correct;
    }
    let (found, settled) = match found(held, checkpoints, event.parents()) {
        Ok(found) => found,
        Err(wanted) => return CutsCheck::Pending(wanted),
    };
    if event.cuts().iter().any(|cut| !found.contains(cut)) {
        return CutsCheck::Bad;
    }
    match maximal_settled(held, &found, &settled) {
        Ok(cuts) if cuts == event.cuts() => CutsCheck::Correct,
        Ok(_) => CutsCheck::Bad,
        Err(wanted) => CutsCheck::Pending(wanted),
    }
}

impl Log {
    /// The checkpoints a held event's cuts reach ([`reach`]); empty for an
    /// event not held.
    ///
    /// # Errors
    ///
    /// As [`reach`]: the checkpoint envelopes the walk waits for.
    pub fn cuts_reach(&self, id: EventId) -> Result<BTreeSet<EventId>, Vec<EventId>> {
        match self.held_envelope(id) {
            Some(event) => {
                let walk = walk(self, event.cuts(), HeldEnvelopes::placed(self, id));
                if walk.missing.is_empty() {
                    Ok(walk.reached)
                } else {
                    Err(walk.missing.into_iter().collect())
                }
            }
            None => Ok(BTreeSet::new()),
        }
    }

    /// Whether the held event `id` follows checkpoint `c` ([`follows`]); an
    /// event not held follows none.
    ///
    /// # Errors
    ///
    /// As [`follows`]: the checkpoint envelopes the answer waits for.
    pub fn follows(&self, id: EventId, c: EventId) -> Result<bool, Vec<EventId>> {
        match self.held_envelope(id) {
            Some(event) => follows(self, event, c),
            None => Ok(false),
        }
    }

    /// The cuts an event with these parents declares, from this log's
    /// placed and witnessed events, its stubs and the checkpoint envelopes
    /// it keeps ([`expected`]).
    ///
    /// # Errors
    ///
    /// As [`expected`]: what the answer waits for.
    pub fn cuts_for(
        &self,
        checkpoints: &(impl Checkpoints + ?Sized),
        parents: &[EventId],
    ) -> Result<Vec<EventId>, Vec<EventId>> {
        expected(self, checkpoints, parents)
    }

    /// Checks a placed, witnessed or arriving event's cuts against its
    /// parents in this log ([`check`]).
    pub fn check_cuts(
        &self,
        checkpoints: &(impl Checkpoints + ?Sized),
        event: &Event,
    ) -> CutsCheck {
        check(self, checkpoints, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use crate::log::Placement;
    use frasil_crypto::schemes::{Scheme, Signer};

    fn signer() -> Signer {
        Signer::from_seeds(&[1; 32], &[101; 32], None)
    }

    struct Builder {
        signer: Signer,
        log: Log,
        seq: u64,
        prev: Option<EventId>,
    }

    impl Builder {
        fn new() -> Self {
            let signer = signer();
            let genesis = Envelope {
                kind: kind::SPACE,
                log: None,
                ed: *signer.identity_key(),
                kc: *signer.kc(),
                seq: 1,
                prev: None,
                parents: vec![],
                cuts: Vec::new(),
                body: b"genesis".to_vec(),
                scheme: Scheme::Hybrid,
            };
            let genesis = crate::decode(&genesis.sign(&signer)).unwrap();
            let id = genesis.id();
            Self {
                signer,
                log: Log::new(genesis).unwrap(),
                seq: 1,
                prev: Some(id),
            }
        }

        /// An event of `kind` with these parents and cuts, placed. Each
        /// one takes the next `seq` of the one author and cites its `prev`.
        fn add(&mut self, kind: u8, parents: &[EventId], cuts: &[EventId]) -> Event {
            self.seq += 1;
            let mut parents = parents.to_vec();
            parents.extend(self.prev);
            let envelope = Envelope {
                kind,
                log: Some(self.log.id()),
                ed: *self.signer.identity_key(),
                kc: *self.signer.kc(),
                seq: self.seq,
                prev: self.prev,
                parents,
                cuts: cuts.to_vec(),
                body: if kind == kind::ANCHOR {
                    vec![]
                } else {
                    self.seq.to_be_bytes().to_vec()
                },
                // A space event is scheme 2 (crypto.md, "Kind policy").
                scheme: if kind == kind::UNIT {
                    Scheme::Ed25519
                } else {
                    Scheme::Hybrid
                },
            };
            let event = crate::decode(&envelope.sign(&self.signer)).unwrap();
            assert!(matches!(
                self.log.place(event.clone()).unwrap(),
                Placement::Placed(_)
            ));
            self.prev = Some(event.id());
            event
        }
    }

    #[test]
    fn a_log_without_checkpoints_declares_none() {
        let mut b = Builder::new();
        let g = b.log.id();
        let unit = b.add(kind::UNIT, &[g], &[]);
        let space = b.add(kind::SPACE, &[], &[]);
        assert_eq!(b.log.check_cuts(&NoCheckpoints, &unit), CutsCheck::Correct);
        assert_eq!(b.log.check_cuts(&NoCheckpoints, &space), CutsCheck::Correct);
        assert_eq!(b.log.cuts_for(&NoCheckpoints, &[space.id()]), Ok(vec![]));
        let genesis = b.log.genesis().clone();
        assert_eq!(
            b.log.check_cuts(&NoCheckpoints, &genesis),
            CutsCheck::Correct
        );
    }

    #[test]
    fn an_event_after_a_checkpoint_names_it() {
        let mut b = Builder::new();
        let c1 = b.add(kind::SPACE, &[], &[]);
        let checkpoints: BTreeSet<EventId> = [c1.id()].into();
        // A checkpoint among the parents is declared.
        assert_eq!(b.log.cuts_for(&checkpoints, &[c1.id()]), Ok(vec![c1.id()]));
        let after = b.add(kind::UNIT, &[], &[c1.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &after), CutsCheck::Correct);
        assert_eq!(b.log.follows(after.id(), c1.id()), Ok(true));
        assert_eq!(b.log.follows(c1.id(), c1.id()), Ok(false));
        // A child of an event after it inherits its cut.
        let next = b.add(kind::UNIT, &[], &[c1.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &next), CutsCheck::Correct);
        // Leaving it out, or naming another, is BadCuts.
        let none = b.add(kind::UNIT, &[], &[]);
        assert_eq!(b.log.check_cuts(&checkpoints, &none), CutsCheck::Bad);
        assert_eq!(
            b.log.check_cuts(&checkpoints, &none).verdict(),
            Err(EventClass::BadCuts)
        );
        let g = b.log.id();
        let wrong = b.add(kind::UNIT, &[], &[g]);
        assert_eq!(b.log.check_cuts(&checkpoints, &wrong), CutsCheck::Bad);
        // Before it is opened, the check waits for it.
        let unopened = |event: &Event| (event.id() != c1.id()).then_some(false);
        assert_eq!(
            b.log.check_cuts(&unopened, &after),
            CutsCheck::Pending(vec![c1.id()])
        );
        assert_eq!(
            b.log.check_cuts(&unopened, &after).verdict(),
            Err(ErrorClass::Pending.into())
        );
        // Only the parents' declarations count past the first event: the
        // grandchild reads `after`'s cuts, not whether c1 is opened.
        assert_eq!(b.log.check_cuts(&unopened, &next), CutsCheck::Correct);
    }

    #[test]
    fn only_the_maximal_checkpoints_are_declared() {
        let mut b = Builder::new();
        let c1 = b.add(kind::SPACE, &[], &[]);
        let c2 = b.add(kind::SPACE, &[], &[c1.id()]);
        let checkpoints: BTreeSet<EventId> = [c1.id(), c2.id()].into();
        assert_eq!(b.log.check_cuts(&checkpoints, &c2), CutsCheck::Correct);
        assert_eq!(at_or_before(&b.log, c1.id(), c2.id()), Ok(true));
        assert_eq!(at_or_before(&b.log, c2.id(), c1.id()), Ok(false));
        assert_eq!(at_or_before(&b.log, c2.id(), c2.id()), Ok(true));
        assert_eq!(concurrent(&b.log, c1.id(), c2.id()), Ok(false));
        // c2 is a parent and a checkpoint; c1, which its cuts reach, is not
        // maximal.
        assert_eq!(b.log.cuts_for(&checkpoints, &[c2.id()]), Ok(vec![c2.id()]));
        let both = b.add(kind::UNIT, &[], &[c1.id(), c2.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &both), CutsCheck::Bad);
        // Its child reads the cuts `both` declares, wrong as they are, and
        // keeps the maximal one.
        let after = b.add(kind::UNIT, &[], &[c2.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &after), CutsCheck::Correct);
        assert_eq!(
            b.log.cuts_reach(after.id()),
            Ok([c1.id(), c2.id()].into_iter().collect())
        );
        assert_eq!(b.log.follows(after.id(), c1.id()), Ok(true));
    }

    #[test]
    fn concurrent_checkpoints_are_both_declared() {
        let mut b = Builder::new();
        let g = b.log.id();
        let c1 = b.add(kind::SPACE, &[], &[]);
        // A second chain from the genesis: another author's view would be
        // the same. The builder cites its own prev, so start the second
        // checkpoint from the genesis by hand.
        let other = Signer::from_seeds(&[2; 32], &[102; 32], None);
        let c2 = Envelope {
            kind: kind::SPACE,
            log: Some(g),
            ed: *other.identity_key(),
            kc: *other.kc(),
            seq: 1,
            prev: None,
            parents: vec![g],
            cuts: Vec::new(),
            body: b"c2".to_vec(),
            scheme: Scheme::Hybrid,
        };
        let c2 = crate::decode(&c2.sign(&other)).unwrap();
        b.log.place(c2.clone()).unwrap();
        let checkpoints: BTreeSet<EventId> = [c1.id(), c2.id()].into();
        assert_eq!(concurrent(&b.log, c1.id(), c2.id()), Ok(true));
        let mut expected = vec![c1.id(), c2.id()];
        expected.sort();
        assert_eq!(
            b.log.cuts_for(&checkpoints, &[c1.id(), c2.id()]),
            Ok(expected.clone())
        );
        let merge = b.add(kind::UNIT, &[c2.id()], &expected);
        assert_eq!(b.log.check_cuts(&checkpoints, &merge), CutsCheck::Correct);
    }

    #[test]
    fn a_parent_not_held_keeps_the_check_pending() {
        let b = Builder::new();
        let missing = EventId([0xee; 32]);
        assert_eq!(
            b.log.cuts_for(&NoCheckpoints, &[b.log.id(), missing]),
            Err(vec![missing])
        );
    }

    #[test]
    fn reach_waits_for_a_checkpoint_not_held() {
        let mut held = BTreeMap::new();
        let b = Builder::new();
        let genesis = b.log.genesis().clone();
        held.insert(genesis.id(), genesis.clone());
        let far = EventId([0xaa; 32]);
        // Its envelope is neither held nor kept: pending, never void.
        assert_eq!(reach(&held, &[far]), Err(vec![far]));
        assert_eq!(at_or_before(&held, genesis.id(), far), Err(vec![far]));
        assert_eq!(at_or_before(&held, far, far), Ok(true));
        assert_eq!(concurrent(&held, far, far), Ok(false));
    }

    /// A replica that forgot the events around two checkpoints keeps their
    /// envelopes, and orders them through those alone.
    #[test]
    fn kept_envelopes_order_checkpoints() {
        let mut b = Builder::new();
        let c1 = b.add(kind::SPACE, &[], &[]);
        let c2 = b.add(kind::SPACE, &[], &[c1.id()]);
        let checkpoints: BTreeSet<EventId> = [c1.id(), c2.id()].into();
        let after = b.add(kind::UNIT, &[], &[c2.id()]);
        // Another log that holds only `after` and c2, then c1 kept.
        let mut forgot = Log::new(b.log.genesis().clone()).unwrap();
        forgot.witness(after.clone()).unwrap();
        assert_eq!(forgot.cuts_reach(after.id()), Err(vec![c2.id()]));
        assert_eq!(forgot.follows(after.id(), c2.id()), Ok(true));
        assert_eq!(forgot.follows(after.id(), c1.id()), Err(vec![c2.id()]));
        assert!(forgot.keep_envelope(c2.clone()).unwrap());
        assert_eq!(forgot.cuts_reach(after.id()), Err(vec![c1.id()]));
        assert_eq!(forgot.follows(after.id(), c1.id()), Ok(true));
        assert!(forgot.keep_envelope(c1.clone()).unwrap());
        assert_eq!(
            forgot.cuts_reach(after.id()),
            Ok([c1.id(), c2.id()].into_iter().collect())
        );
        assert_eq!(at_or_before(&forgot, c1.id(), c2.id()), Ok(true));
        assert_eq!(at_or_before(&forgot, c2.id(), c1.id()), Ok(false));
        // A kept envelope is no placed event.
        assert!(!forgot.contains(c2.id()));
        assert_eq!(forgot.kept_envelopes().count(), 2);
        // An event citing `after` declares c2: its order with c1 is read
        // from the kept envelope of c2.
        let next = {
            let mut envelope = after.fields().clone();
            envelope.seq += 1;
            envelope.prev = Some(after.id());
            envelope.parents = vec![after.id()];
            crate::decode(&envelope.sign(&b.signer)).unwrap()
        };
        assert_eq!(forgot.check_cuts(&checkpoints, &next), CutsCheck::Correct);
        assert_eq!(forgot.drop_kept_envelope(c1.id()), Some(c1.clone()));
        assert_eq!(forgot.check_cuts(&checkpoints, &next), CutsCheck::Correct);
        // Through a lone kept envelope beside a map of held events.
        let kept = BTreeMap::from([(c2.id(), c2.clone())]);
        let held = BTreeMap::from([(after.id(), after.clone())]);
        let with = WithKept {
            held: &held,
            kept: &kept,
        };
        assert_eq!(follows(&with, &after, c2.id()), Ok(true));
        // c2's cuts name c1, so the walk reaches it without its envelope.
        assert_eq!(follows(&with, &after, c1.id()), Ok(true));
        assert_eq!(reach(&with, after.cuts()), Err(vec![c1.id()]));
        assert_eq!(check(&with, &checkpoints, &next), CutsCheck::Correct);
    }

    /// Two parents that each declare a checkpoint: which is maximal is
    /// read from their envelopes, and pending while one is neither held
    /// nor kept.
    #[test]
    fn ordering_two_cuts_waits_for_the_later_envelope() {
        let mut b = Builder::new();
        let c1 = b.add(kind::SPACE, &[], &[]);
        let u1 = b.add(kind::UNIT, &[], &[c1.id()]);
        let c2 = b.add(kind::SPACE, &[], &[c1.id()]);
        let u2 = b.add(kind::UNIT, &[], &[c2.id()]);
        let checkpoints: BTreeSet<EventId> = [c1.id(), c2.id()].into();
        let merge = b.add(kind::UNIT, &[u1.id()], &[c2.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &merge), CutsCheck::Correct);
        // A party that holds the two units only.
        let held = BTreeMap::from([(u1.id(), u1.clone()), (u2.id(), u2.clone())]);
        // Neither envelope: neither checkpoint's place is known.
        let mut both = vec![c1.id(), c2.id()];
        both.sort();
        assert_eq!(
            check(&held, &checkpoints, &merge),
            CutsCheck::Pending(both.clone())
        );
        assert_eq!(
            expected(&held, &checkpoints, &[u1.id(), u2.id()]),
            Err(both)
        );
        // With c2's envelope kept, c1 is below it, and c1, which c2
        // reaches, cannot reach c2: c1's own envelope is not needed.
        let kept = BTreeMap::from([(c2.id(), c2.clone())]);
        let with = WithKept {
            held: &held,
            kept: &kept,
        };
        assert_eq!(check(&with, &checkpoints, &merge), CutsCheck::Correct);
        // A cut that no parent gives is void without any envelope.
        let wrong = {
            let mut envelope = merge.fields().clone();
            envelope.cuts = vec![EventId([0x01; 32])];
            crate::decode(&envelope.sign(&b.signer)).unwrap()
        };
        assert_eq!(check(&held, &checkpoints, &wrong), CutsCheck::Bad);
    }

    /// A replica that forgot the past of its kept checkpoint keeps the IDs
    /// of what it dropped: such a parent contributes no cuts and never
    /// holds the check pending.
    #[test]
    fn a_dropped_parent_contributes_nothing_and_is_not_waited_for() {
        let mut b = Builder::new();
        let before = b.add(kind::UNIT, &[], &[]);
        let c1 = b.add(kind::SPACE, &[], &[]);
        let checkpoints: BTreeSet<EventId> = [c1.id()].into();
        let after = b.add(kind::UNIT, &[before.id()], &[c1.id()]);
        assert_eq!(b.log.check_cuts(&checkpoints, &after), CutsCheck::Correct);
        let mut forgot = Log::new(b.log.genesis().clone()).unwrap();
        assert!(forgot.keep_envelope(c1.clone()).unwrap());
        assert_eq!(
            forgot.check_cuts(&checkpoints, &after),
            CutsCheck::Pending(vec![before.id()])
        );
        assert!(forgot.mark_dropped(before.id()));
        assert!(!forgot.mark_dropped(before.id()));
        assert!(forgot.is_dropped(before.id()));
        assert_eq!(forgot.check_cuts(&checkpoints, &after), CutsCheck::Correct);
        assert_eq!(
            forgot.cuts_for(&checkpoints, &[before.id()]),
            Ok(Vec::new())
        );
        // Through a reference and beside kept envelopes, alike.
        let kept = BTreeMap::new();
        let with = WithKept {
            held: &forgot,
            kept: &kept,
        };
        assert_eq!(check(&with, &checkpoints, &after), CutsCheck::Correct);
        // A kept envelope is never dropped; the state keeps the IDs.
        assert!(!forgot.mark_dropped(c1.id()));
        let back = Log::decode_state(&forgot.encode_state()).unwrap();
        assert!(back.is_dropped(before.id()));
        assert_eq!(back.encode_state(), forgot.encode_state());
        // Once the event is held again, it is no longer dropped.
        forgot.witness(before.clone()).unwrap();
        assert!(!forgot.is_dropped(before.id()));
        let back = Log::decode_state(&forgot.encode_state()).unwrap();
        assert_eq!(back.dropped_ids().count(), 0);
    }

    /// A checkpoint a placed parent declares, whose envelope the party
    /// neither holds, keeps nor dropped, is in no parent's past: that
    /// parent's cuts are wrong, and the ID reaches nothing instead of
    /// holding the check pending.
    #[test]
    fn a_cut_no_placed_parent_could_have_reaches_nothing() {
        let mut b = Builder::new();
        let c1 = b.add(kind::SPACE, &[], &[]);
        let checkpoints: BTreeSet<EventId> = [c1.id()].into();
        let nowhere = EventId([0x5a; 32]);
        // Placement does not check cuts: `liar` is placed, declaring an ID
        // no parent gives, and its own check finds it.
        let liar = b.add(kind::UNIT, &[], &[nowhere]);
        assert_eq!(b.log.check_cuts(&checkpoints, &liar), CutsCheck::Bad);
        // Its child reads what `liar` declares: `nowhere` reaches nothing,
        // so c1 is not below it, nor it below c1, and the check ends.
        let mut both = vec![c1.id(), nowhere];
        both.sort();
        assert_eq!(
            b.log.cuts_for(&checkpoints, &[liar.id()]),
            Ok(vec![nowhere])
        );
        assert_eq!(
            b.log.cuts_for(&checkpoints, &[liar.id(), c1.id()]),
            Ok(both.clone())
        );
        assert_eq!(b.log.cuts_reach(liar.id()), Ok([nowhere].into()));
        assert_eq!(b.log.follows(liar.id(), c1.id()), Ok(false));
        // A party that holds `liar` without having placed it still waits.
        let held = BTreeMap::from([(liar.id(), liar.clone()), (c1.id(), c1.clone())]);
        assert_eq!(
            expected(&held, &checkpoints, &[liar.id(), c1.id()]),
            Err(vec![nowhere])
        );
    }

    /// A parent the replica dropped counts as present for placement: an
    /// event resting on it is placed, adds nothing to its height from it,
    /// and may be cited.
    #[test]
    fn an_event_is_placed_on_a_dropped_parent() {
        let mut b = Builder::new();
        let before = b.add(kind::UNIT, &[], &[]);
        let c1 = b.add(kind::SPACE, &[], &[]);
        let after = b.add(kind::UNIT, &[before.id()], &[c1.id()]);
        let mut forgot = Log::new(b.log.genesis().clone()).unwrap();
        assert_eq!(
            forgot.place(c1.clone()).unwrap(),
            Placement::Pending(vec![before.id()])
        );
        assert_eq!(forgot.wanted(), vec![before.id()]);
        assert_eq!(forgot.drop_parent(before.id()), vec![c1.id()]);
        assert!(forgot.is_dropped(before.id()));
        assert!(forgot.wanted().is_empty());
        assert_eq!(forgot.height(c1.id()), Some(1));
        assert!(forgot.heights_wanted([c1.id()]).is_empty());
        assert_eq!(
            forgot.place(after.clone()).unwrap(),
            Placement::Placed(vec![after.id()])
        );
        let checkpoints: BTreeSet<EventId> = [c1.id()].into();
        assert_eq!(forgot.check_cuts(&checkpoints, &after), CutsCheck::Correct);
        let citable = forgot.citable(|_| true);
        assert!(citable.contains(&c1.id()) && citable.contains(&after.id()));
        assert!(forgot.is_closed(&citable));
        // Dropping an ID marked already releases nothing more.
        assert!(forgot.drop_parent(before.id()).is_empty());
    }

    /// A dropped parent whose height the replica kept places what rests on
    /// it at the height it had before forgetting (events.md, "Placement and
    /// order"); one without adds nothing. The state keeps the heights.
    #[test]
    fn an_event_keeps_its_height_on_a_dropped_parent_with_a_height() {
        let mut b = Builder::new();
        let first = b.add(kind::SPACE, &[], &[]);
        let second = b.add(kind::SPACE, &[], &[]);
        let kept = b.add(kind::UNIT, &[], &[]);
        let later = b.add(kind::UNIT, &[], &[]);
        assert_eq!(b.log.height(second.id()), Some(2));
        assert_eq!(b.log.height(kept.id()), Some(3));
        assert_eq!(b.log.height(later.id()), Some(4));
        let mut forgot = Log::new(b.log.genesis().clone()).unwrap();
        assert_eq!(
            forgot.place(kept.clone()).unwrap(),
            Placement::Pending(vec![second.id()])
        );
        assert_eq!(forgot.drop_parent_at(second.id(), 2), vec![kept.id()]);
        assert_eq!(forgot.height(kept.id()), Some(3));
        assert_eq!(forgot.dropped_height(second.id()), Some(2));
        assert_eq!(forgot.height(second.id()), None);
        forgot.place(later.clone()).unwrap();
        assert_eq!(forgot.height(later.id()), Some(4));
        assert_eq!(forgot.canonical(), vec![forgot.id(), kept.id(), later.id()]);
        // A height of 0, or one of a placed event, changes nothing.
        assert!(!forgot.mark_dropped_at(first.id(), 0));
        assert!(!forgot.mark_dropped_at(kept.id(), 7));
        assert!(!forgot.mark_dropped_at(second.id(), 2));
        // The state keeps the heights, and reads back to the same heights.
        let back = Log::decode_state(&forgot.encode_state()).unwrap();
        assert_eq!(back.encode_state(), forgot.encode_state());
        assert_eq!(back.dropped_height(second.id()), Some(2));
        assert_eq!(back.height(kept.id()), Some(3));
        // Without a height the parent adds nothing; a height kept later
        // lifts what rests on it.
        let mut bare = Log::new(b.log.genesis().clone()).unwrap();
        bare.place(kept.clone()).unwrap();
        assert_eq!(bare.drop_parent(second.id()), vec![kept.id()]);
        bare.place(later.clone()).unwrap();
        assert_eq!(bare.height(kept.id()), Some(1));
        assert_eq!(bare.height(later.id()), Some(2));
        assert!(bare.mark_dropped_at(second.id(), 2));
        assert_eq!(bare.height(kept.id()), Some(3));
        assert_eq!(bare.height(later.id()), Some(4));
        // Once the event is held again, its kept height goes with it.
        bare.witness(second.clone()).unwrap();
        assert!(!bare.is_dropped(second.id()));
        assert_eq!(bare.dropped_height(second.id()), None);
        let state = bare.encode_state();
        assert_eq!(Log::decode_state(&state).unwrap().encode_state(), state);
    }

    #[test]
    fn cuts_hold_up_to_four_ids_ascending() {
        let ids = [EventId([1; 32]), EventId([2; 32]), EventId([3; 32])];
        let cuts = Cuts::new(&ids).unwrap();
        assert_eq!(cuts.as_slice(), &ids);
        assert_eq!(&*cuts, &ids);
        assert_eq!(Cuts::new(&[]), Some(Cuts::NONE));
        assert!(Cuts::default().is_empty());
        assert_eq!(Cuts::new(&[ids[1], ids[0]]), None);
        assert_eq!(Cuts::new(&[ids[0], ids[0]]), None);
        let five = [1u8, 2, 3, 4, 5].map(|n| EventId([n; 32]));
        assert_eq!(Cuts::new(&five), None);
        assert_eq!(Cuts::new(&five[..4]).unwrap().len(), 4);
        assert_eq!(format!("{:?}", Cuts::NONE), "[]");
    }
}
