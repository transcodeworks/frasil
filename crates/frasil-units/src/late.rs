//! Late units: units made without having seen a checkpoint that is now in
//! effect (roster.md, 3.15.1 What follows a checkpoint, and 3.15.7
//! Clients; units.md, 3.11 Frasil's own units, "Re-submission").
//!
//! With checkpoint `c` in effect, the last of the chain in effect, an event
//! is one of: in `c`'s **past**; `c` itself; **after** `c`, when its cuts
//! reach `c`; or **late**, any other ([`standing`]). A late event is void
//! (`Late`, roster.md's class, final). A late unit is refused (`Late`, with
//! `c` as the event that refuses it, [`LateUnit`]): it is kept as any
//! refused unit is (roster.md, 3.14 What replicas derive, "Keeping refused
//! units"), and its author re-submits it.
//!
//! **What the writer does.** A client whose units become late re-submits
//! them, each of its own late units in canonical order
//! ([`resubmission_order`]): a new unit after its current heads, which
//! follow the checkpoint, with the same type, content, stream opening and
//! refs, whose `resubmits` names the late unit, or with the late unit's
//! `copied_from` and no `resubmits` when it carries one ([`resubmission`]).
//! It seals
//! the new unit under the current state of the checkpoint's world. A device
//! offline across a checkpoint syncs from the checkpoint on, finds its own
//! concurrent units late, re-submits them and continues its chain. A
//! snapshot unit is never re-submitted: the units of its cover are, as each
//! writer's own.

use crate::UnitError;
use crate::inner::Inner;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, Log, kind};
use frasil_space::{RosterClass, SpaceClass};

/// The name of roster.md's class for a late event, `Late` (roster.md,
/// 3.17 Error classes): final; a late unit is refused and kept.
pub const LATE: &str = "Late";

/// Where an event stands against the checkpoint in effect (roster.md,
/// 3.15.1 What follows a checkpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// In the checkpoint's past: judged as that past alone judges it.
    Past,
    /// The checkpoint itself.
    Checkpoint,
    /// After the checkpoint: its cuts reach it.
    After,
    /// Neither: void, and a unit refused (`Late`).
    Late,
}

/// Where the held event `event` stands against `c`, the last checkpoint of
/// the chain in effect, from the log alone: `c` itself; after it, when its
/// cuts reach `c` (read from its envelope, events.md, 3.11 Cuts); in its
/// past, when the log orders it before `c`; late otherwise.
///
/// A replica that forgot `c`'s past holds none of it, and never receives
/// it again; an event of that past that reaches it stays pending on its
/// parents and is never judged here.
///
/// # Errors
///
/// The checkpoint envelopes the answer waits for (events.md, 3.11 Cuts,
/// "Ordering needs envelopes"): its cuts' walk stopped short of `c`.
pub fn standing(log: &Log, c: EventId, event: EventId) -> Result<Standing, Vec<EventId>> {
    if event == c {
        return Ok(Standing::Checkpoint);
    }
    if log.follows(event, c)? {
        return Ok(Standing::After);
    }
    if log.precedes(event, c) {
        return Ok(Standing::Past);
    }
    Ok(Standing::Late)
}

/// A late unit, refused by the checkpoint in effect (roster.md, 3.15.1):
/// its verdict is `Late` ([`LATE`]), and `refused_by` is the event that
/// refuses it, as a refused unit names one (roster.md, 3.14 What replicas
/// derive, "The events that void an event").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LateUnit {
    /// The late unit.
    pub unit: EventId,
    /// The checkpoint that refuses it.
    pub refused_by: EventId,
}

impl LateUnit {
    /// The class the unit is refused with: roster.md's `Late` ([`LATE`]),
    /// final.
    pub fn class() -> UnitError {
        RosterClass::from(SpaceClass::Late).into()
    }
}

/// The late units of a log against `c`, the last checkpoint of the chain in
/// effect, in canonical order, each refused by `c`. Units whose standing
/// waits for an envelope are left out until it arrives.
pub fn late_units(log: &Log, c: EventId) -> Vec<LateUnit> {
    log.canonical()
        .into_iter()
        .filter(|&id| {
            log.event(id)
                .is_some_and(|event| event.kind() == kind::UNIT)
        })
        .filter(|&id| standing(log, c, id) == Ok(Standing::Late))
        .map(|unit| LateUnit {
            unit,
            refused_by: c,
        })
        .collect()
}

/// The order a writer re-submits its own late units in: canonical order,
/// its own units alone.
pub fn resubmission_order(log: &Log, writer: &DeviceId, late: &[LateUnit]) -> Vec<EventId> {
    let late: std::collections::BTreeSet<EventId> = late.iter().map(|l| l.unit).collect();
    log.canonical()
        .into_iter()
        .filter(|id| late.contains(id))
        .filter(|&id| log.event(id).is_some_and(|event| event.author() == writer))
        .collect()
}

/// The sealed part of the unit that re-submits a late or refused one
/// (units.md, 2.5, and 3.11, "Re-submission"): the same type, content,
/// stream opening and refs, with `resubmits` naming the late unit; `None`
/// for a snapshot unit, which is never re-submitted. A unit that carries
/// `copied_from` (it re-applied a late write of another space,
/// ext-restricted-spaces.md) is re-submitted with the same `copied_from`
/// and no `resubmits`, since the two keys never appear together: it
/// re-applies the same late write again, which adapters merge
/// idempotently, and the client matches it to the refused unit by that
/// pair. Padding is the writer's to choose again.
pub fn resubmission(late: &Inner, late_unit: EventId, snapshot: bool) -> Option<Inner> {
    if snapshot || !late.excluded.is_empty() {
        return None;
    }
    let mut inner = Inner::new(late.type_.clone(), late.content.clone());
    inner.opening = late.opening.clone();
    inner.refs = late.refs.clone();
    match late.copied_from {
        Some(copied) => inner.copied_from = Some(copied),
        None => inner.resubmits = Some(late_unit),
    }
    Some(inner)
}
