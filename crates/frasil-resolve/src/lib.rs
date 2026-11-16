//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's resolution procedure, over a trait.
//!
//! Specified by `docs/spec/roster.md`, section 3.7 (The resolution
//! procedure). It has no vector file of its own: the identity, roster and
//! peers vectors prove it.
//!
//! One procedure decides three logs, each read with its own rules:
//!
//! - a person's device list (identity.md, "The merge");
//! - a space's roster (roster.md, "Attacks", "Authority at the place" and
//!   "The resolution procedure");
//! - a space's skeleton at a peer (peers.md, "The skeleton's resolution").
//!
//! A log implements [`Resolve`], and [`resolve`] decides each of its events
//! valid or void. The crate is pure: it reads no clock, does no IO and draws
//! no randomness. Every answer it needs comes from the log through the
//! trait.
//!
//! # The procedure
//!
//! [`resolve`] takes the events a log offers, sorts them in canonical order
//! (by height, then by event ID: events.md, "Placement and order"), and
//! then:
//!
//! 1. **Screens** each event, in canonical order: [`Resolve::check`] (the
//!    event alone), then the chain penalty ([`Resolve::forked`]), which a
//!    self-lowering event ([`Resolve::self_lowering`]) survives, then
//!    [`Resolve::check_among`] (a check that reads the other screened
//!    events). An event that fails is void with that class. The rest are the
//!    **contested** events.
//! 2. **Propagates.** Repeatedly, in canonical order, each undecided event
//!    whose contested past is all decided: void with its class if its
//!    authority fails ([`Resolve::authority`]); void with the attack's class
//!    if a valid event attacks it and the attack counts
//!    ([`Resolve::attack`], [`Resolve::attack_counts`]); valid if no
//!    attacker that counts is undecided.
//! 3. **Agrees.** With at most [`AGREEMENT_LIMIT`] undecided events, every
//!    assignment of valid or void to them is tried. An assignment is
//!    allowed when each undecided event is valid in it exactly when its
//!    authority holds and no event valid in it attacks it with an attack
//!    that counts. Every event with one status in all allowed assignments
//!    takes it, and the procedure returns to step 2.
//! 4. **Picks by seniority.** Otherwise, among the undecided events whose
//!    contested past is decided, the one with the smallest
//!    [`Resolve::pick_key`] is valid, and the procedure returns to step 2.
//!
//! An event voided in step 3 stays void, whatever a later seniority pick
//! decides, with the reason it has in the first allowed assignment of that
//! step: the class of its authority there, or else that of the first valid
//! attacker, in canonical order, whose attack counts. Of two assignments,
//! the first is the one that makes void the earliest event on which they
//! differ.
//!
//! The result, a [`Resolution`], gives each event a [`Verdict`]: valid, with
//! the step that decided it ([`How`]), or void, with its class and, for an
//! attack, the attacker.
//!
//! # What each log supplies
//!
//! The trait's methods fall in four groups:
//!
//! - **The causal order:** [`Resolve::height`] and [`Resolve::precedes`].
//!   Concurrency follows: two events are concurrent when neither precedes
//!   the other.
//! - **The screen:** [`Resolve::check`], [`Resolve::forked`],
//!   [`Resolve::self_lowering`] and [`Resolve::check_among`].
//! - **The rules at a place:** [`Resolve::authority`], [`Resolve::attack`],
//!   [`Resolve::mutual`] and [`Resolve::attack_counts`]. Authority reads the
//!   log's state at the event's **place**: the valid contested events of
//!   its past, under the procedure's current statuses, which a [`View`]
//!   gives. The log adds what is valid without being contested (a list's
//!   first event, a roster's genesis, a skeleton's root).
//! - **The pick:** [`Resolve::pick_key`].
//!
//! ## A device list (identity.md)
//!
//! - **Offered events:** the list events other than the first.
//! - **`check`:** identity.md section 3.1, steps 1 to 6. **`forked`:**
//!   step 7, `Forked`. **`self_lowering`:** a `revoke` that names its own
//!   author. **`check_among`:** the default.
//! - **`authority`:** identity.md section 3.3, at the state of the first
//!   event and the valid list events of [`View::place`] (section 3.2).
//! - **`attack`:** `RevokedConcurrently`, `TargetRevokedConcurrently` and
//!   `AlreadyListed`, as section 3.4 gives them.
//! - **`attack_counts`:** overridden for the mutual pairs by rank: two
//!   revokes by different authors that each name the other's author. The
//!   attack of `x` on `e` is dropped when `e`'s author ranks at least as high
//!   as `x`'s, each rank at its own event's place. It answers `None` until
//!   both events' contested pasts are decided ([`View::past_decided`]), so
//!   that both ranks are known.
//! - **`pick_key`:** `(rank of the author at its place, seniority of the
//!   author, height, event ID)`, the seniority being the smallest
//!   `(height, SHA-256("frasil/device-list/seniority/v1" || person ID ||
//!   identity), add's ID)` over the author's valid adds at the place.
//!
//! ## A roster (roster.md)
//!
//! - **Offered events:** the roster events other than the genesis that are
//!   not held (section 3.9). Held events are left out, as if never
//!   received.
//! - **`check`:** section 3.4.1, steps 1 to 11, already run when the
//!   events were opened. **`forked`:** step 12, `Forked`, except for an
//!   ext-invite-links successor, which its race rule judges instead.
//!   **`self_lowering`:** section 3.5.1. **`check_among`:** section 3.7's
//!   standing: an event whose author no event of its past names at
//!   `administer` (for a successor, no grant of its invite key) is void and
//!   not contested, so it never counts toward [`AGREEMENT_LIMIT`].
//! - **`authority`:** section 3.6, steps 0 to 6, at the roster of the
//!   genesis and [`View::place`]. Step 0 reads the standing of the roster
//!   events in the past ([`View::standing`]): one void with `NoTwin` is
//!   pending for its twin, and one the agreement step is trying as void
//!   ([`Standing::Trial`]) is judged again under the trial (section 3.8).
//! - **`attack`:** section 3.5.2, (a), (b), (c) and (e), with their classes.
//! - **`mutual`:** two events by different authors that each attack the
//!   other through (a) or (b), with one change each.
//! - **`attack_counts`:** overridden for duels. In a mutual pair the
//!   attack counts exactly when its author outranks its partner's (the
//!   higher rank, then the more senior, each at its own event's place), so
//!   it is `None` until both pasts are decided. Of two other events that
//!   lower each other, the attack on one with a single change does not
//!   count; and neither's attack through (a), (b) or (c) counts against the
//!   events that grant or change the other's author, back along their
//!   granters, unless that author signed them. Those read no status.
//! - **`pick_key`:** `(255 - rank of the author's member at its place, its
//!   seniority, height, event ID)`, with section 3.2's seniority.
//! - ext-invite-links.md's race rule for successors runs around
//!   [`resolve`]: the roster resolves, finds the successors its rule voids,
//!   and resolves again with those voided in its authority, until nothing
//!   changes.
//!
//! ## A skeleton (peers.md)
//!
//! - **Offered events:** the applied changes, disowns and enrolments that
//!   passed the peer's checks (section 3.11).
//! - **`check`:** nothing more; the store checks ran first. **`forked`:**
//!   `Forked` from the pseudonym's fork point, counting only events whose
//!   signatures the peer verified. **`self_lowering`:** a lower or disown of
//!   the author's own administrator slot. **`check_among`:** two concurrent
//!   enrolments of one administrator slot are both void,
//!   `ConcurrentEnrolment`.
//! - **`authority`:** `Full` past 4,096 valid contested events in the
//!   place; for an enrolment, its administrator slot in (`NotAMember`) and
//!   not yet enrolled (`AlreadyEnrolled`); otherwise the author enrolled in
//!   an administrator slot that is in (`NotAnAdministrator`) and the slot it
//!   lowers in (`NotAMember`). The state is the root's administrator slot
//!   and [`View::place`].
//! - **`attack`:** `RemovedConcurrently` when `x` lowers or disowns `e`'s
//!   author's administrator slot, or for an enrolment the one it enrols.
//! - **`mutual`:** both attack each other and their authors differ.
//! - **`attack_counts`:** a mutual pair's attacks do not count, nor does
//!   either side's attack on the enrolment its partner's author signed.
//! - **`pick_key`:** `(seniority of the author's administrator slot,
//!   height, event ID)`; an enrolment's slot is the one it enrols.

mod bits;
mod engine;
#[cfg(test)]
mod proptests;
mod verdict;
mod view;

use core::fmt::Debug;

pub use engine::{resolve, weighed};
pub use verdict::{How, Resolution, Verdict};
pub use view::{Standing, View};

/// The most undecided events the agreement step tries every assignment of
/// (roster.md, 3.7 The resolution procedure, step 3): at most 2^16 trials.
/// Above it, the seniority pick decides directly.
pub const AGREEMENT_LIMIT: usize = 16;

/// A log that [`resolve`] decides: its causal order, its screen, its rules
/// at a place and its pick.
///
/// Every method is a pure function of the log and its arguments. The
/// procedure calls them many times and in no promised order, so a log that
/// reads its state at a place should cache it by place.
///
/// # Contract
///
/// - Height extends the causal order: if `a` precedes `b`, `a`'s height is
///   smaller. Canonical order, by height then ID, then extends it too.
/// - [`authority`](Resolve::authority) and
///   [`pick_key`](Resolve::pick_key) read only the standing of the event's
///   past, through the [`View`]; [`attack_counts`](Resolve::attack_counts)
///   reads only the standing of the two events' pasts.
/// - [`attack`](Resolve::attack) and [`mutual`](Resolve::mutual) read only
///   the two events, never a state, so every replica computes them alike
///   (roster.md, 3.5.2 What attacks what).
pub trait Resolve: Sized {
    /// An event ID. Its order is the byte order that breaks ties in
    /// canonical order.
    type Id: Copy + Ord + Debug;

    /// The log's error classes.
    type Class: frasil_base::Class;

    /// What the seniority pick sorts by, smallest first. It should end with
    /// the event ID, so that no two events tie.
    type PickKey: Ord;

    // -- The causal order (events.md, "Placement and order")

    /// The event's height: 0 for an event with no parents, otherwise one more
    /// than the highest of its parents.
    fn height(&self, event: Self::Id) -> u64;

    /// Whether `earlier` is in the past of `later`: an ancestor, never the
    /// event itself.
    fn precedes(&self, earlier: Self::Id, later: Self::Id) -> bool;

    // -- The screen

    /// The checks of the event alone, before the procedure. An event that
    /// fails is void with the class, and is not contested.
    fn check(&self, event: Self::Id) -> Result<(), Self::Class>;

    /// The chain penalty (events.md, "The penalty"): `Some(Forked)` when the
    /// event's author forked its chain at or before this event. A
    /// self-lowering event survives it.
    fn forked(&self, event: Self::Id) -> Option<Self::Class>;

    /// Whether the event is **self-lowering**: it only lowers or removes
    /// its own author (roster.md, 3.5.1 Self-lowering events; a device
    /// list's self-revocation; a skeleton's lower or disown of its author's
    /// own administrator slot). It is never attacked and survives its
    /// author's chain penalty.
    fn self_lowering(&self, event: Self::Id) -> bool;

    /// A check that reads the other events that passed
    /// [`check`](Resolve::check) and the chain penalty. `screened` holds
    /// them all, `event` included, in canonical order. An event that fails
    /// is void with the class, and is not contested.
    ///
    /// The default passes every event. A skeleton voids two concurrent
    /// enrolments of one administrator slot here, and a roster an event
    /// whose author has no standing in its past.
    fn check_among(&self, event: Self::Id, screened: &[Self::Id]) -> Result<(), Self::Class> {
        let _ = (event, screened);
        Ok(())
    }

    // -- The rules at a place

    /// The event's authority at its place (roster.md, 3.6 Authority at the
    /// place; identity.md, 3.3 Checks at the event's place; peers.md, 3.12
    /// The skeleton's resolution). The first check that fails gives the
    /// class.
    ///
    /// The procedure calls it once every contested event in the event's past
    /// has a status in `view`: decided, or tried by the agreement step.
    /// [`View::place`] gives the valid ones.
    fn authority(&self, event: Self::Id, view: &View<'_, Self>) -> Result<(), Self::Class>;

    /// Whether `attacker`, if valid, attacks `event`, and with which class
    /// (roster.md, 3.5.2 What attacks what).
    ///
    /// The procedure asks only for two different contested events that are
    /// concurrent, with `event` not self-lowering, so the log need not check
    /// those.
    fn attack(&self, attacker: Self::Id, event: Self::Id) -> Option<Self::Class>;

    /// Whether `attacker` and `event` are a **mutual pair**: they lower each
    /// other, one change each. The default
    /// [`attack_counts`](Resolve::attack_counts) drops a mutual pair's
    /// attack; a roster, whose pairs ranks settle (roster.md, 3.5.2),
    /// overrides it. Asked only where [`attack`](Resolve::attack) holds.
    /// The default is never.
    fn mutual(&self, attacker: Self::Id, event: Self::Id) -> bool {
        let _ = (attacker, event);
        false
    }

    /// Whether the attack of `attacker` on `event` counts: `Some(true)` if
    /// it does, `Some(false)` if it is dropped, `None` if that is not yet
    /// known. Asked only where [`attack`](Resolve::attack) holds.
    ///
    /// The default counts every attack but a mutual pair's. A device list
    /// and a roster override it to count a mutual pair's attack by rank and
    /// seniority, and answer `None` until the two events' pasts are decided
    /// ([`View::past_decided`]). Under a trial of the agreement step, `None`
    /// counts.
    fn attack_counts(
        &self,
        attacker: Self::Id,
        event: Self::Id,
        view: &View<'_, Self>,
    ) -> Option<bool> {
        let _ = view;
        Some(!self.mutual(attacker, event))
    }

    // -- The pick

    /// The event's key for the pick (step 4), smallest first: its author's
    /// rank (a roster's or a device list's) and seniority at its place, its
    /// height and its ID. Called only once the event's contested past is
    /// decided.
    fn pick_key(&self, event: Self::Id, view: &View<'_, Self>) -> Self::PickKey;
}
