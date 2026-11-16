//! What a replica that forgot the past before its kept checkpoint reads of
//! each unit it kept of that past (units.md, "The past of a kept
//! checkpoint"): the library's [`Frozen`], made when it forgot from what
//! the space froze of the unit at its place
//! ([`frasil_space::Checkpointed::frozen_units`]) and what its adapter made
//! of the content there. This module only carries it to and from the unit's
//! `event` record, whose state and class are the frozen verdict and keys 6
//! to 8 the capabilities, the admitting path and the voiding events
//! (at-rest.md, "The head, events and keys"), and reads it as the replica
//! needs it.

use crate::adapters::ContentOutcome;
use crate::replica::Authorship;
use frasil_base::ErrorClass;
use frasil_base::errors::Class as _;
use frasil_space::{RosterClass, Status};
use frasil_store::tables::{EventState, Frozen as AtRest};
use frasil_units::frozen::Frozen;

/// What became of the content of a valid unit whose author no path reached
/// at its place: it waits (`Pending`), or is refused (`CapabilityRefused`).
/// `None` for any other unit: its adapter, handed the frozen capabilities,
/// applies or refuses its content as it did there.
pub(crate) fn unreached(frozen: &Frozen) -> Option<ContentOutcome> {
    match frozen.verdict.as_ref().map_err(String::as_str) {
        Err(class) if class == ErrorClass::Pending.name() => {
            Some(ContentOutcome::Waiting(ErrorClass::Pending.name()))
        }
        Err(class) if class == ErrorClass::CapabilityRefused.name() => Some(
            ContentOutcome::Refused(ErrorClass::CapabilityRefused.name()),
        ),
        _ => None,
    }
}

/// Who wrote the unit: its attribution as frozen at its place, with the
/// labels of then (roster.md, 3.11, "Attribution"); `None` for a unit the
/// write rule voids, or that no path reached.
pub(crate) fn authorship(frozen: &Frozen) -> Option<Authorship> {
    (!frozen.attribution.is_empty()).then(|| Authorship {
        paths: frozen.attribution.clone(),
    })
}

/// The unit's `event` record state, class and keys 6 to 8.
pub(crate) fn record(frozen: &Frozen) -> (EventState, Option<String>, AtRest) {
    let (state, class) = match &frozen.verdict {
        Ok(()) => (EventState::Valid, None),
        Err(class) => (EventState::Refused, Some(class.clone())),
    };
    let at_rest = AtRest {
        capabilities: frozen.capability_pairs(),
        attribution: frozen.attribution_entries(),
        voided_by: frozen.voided_by.iter().map(|id| id.0).collect(),
    };
    (state, class, at_rest)
}

/// What an `event` record with keys 6 to 8 keeps of a unit, and its
/// verdict by the write rule: void with the record's class when that is the
/// write rule's, else valid, its content refused or waiting.
pub(crate) fn from_record(
    state: EventState,
    class: Option<&str>,
    at_rest: &AtRest,
) -> Option<(Frozen, Status)> {
    let frozen = Frozen::from_parts(
        state == EventState::Valid,
        class,
        &at_rest.capabilities,
        &at_rest.attribution,
        &at_rest.voided_by,
    )?;
    // A class shared across documents (`Pending`, `CapabilityRefused`, an
    // adapter's) is what became of the content of a unit valid by the
    // write rule; the write rule's own classes are roster.md's.
    let by_rule = class
        .and_then(RosterClass::from_name)
        .filter(|class| class.shared().is_none());
    let status = match by_rule {
        Some(class) => Status::Void {
            class,
            by: frozen.voided_by.first().copied(),
        },
        None => Status::Valid(frasil_space::Valid::Rules),
    };
    Some((frozen, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_adapter::{Capabilities, Capability, Mode};
    use frasil_events::EventId;

    #[test]
    fn a_record_reads_back() {
        let cases = [
            Frozen {
                verdict: Ok(()),
                capabilities: Capabilities::new([
                    Capability::new("comment", Mode::Extends),
                    Capability::new("suggest", Mode::Narrows),
                ]),
                attribution: vec![(
                    frasil_space::MemberRef::person([4; 32]),
                    Some("Carol".to_owned()),
                )],
                voided_by: Vec::new(),
            },
            Frozen {
                verdict: Err(ErrorClass::CapabilityRefused.name().to_owned()),
                capabilities: Capabilities::none(),
                attribution: Vec::new(),
                voided_by: Vec::new(),
            },
            Frozen {
                verdict: Err("RefusedByRemoval".to_owned()),
                capabilities: Capabilities::none(),
                attribution: Vec::new(),
                voided_by: vec![EventId([9; 32])],
            },
        ];
        for frozen in cases {
            let (state, class, at_rest) = record(&frozen);
            let (back, status) = from_record(state, class.as_deref(), &at_rest).unwrap();
            assert_eq!(back, frozen);
            assert_eq!(
                status.is_valid(),
                frozen.verdict.as_ref().map_err(String::as_str) != Err("RefusedByRemoval")
            );
        }
    }
}
