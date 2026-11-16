//! A kept unit of a forgotten past (units.md, "The past of a kept
//! checkpoint"): its verdict and its author's capabilities at its place,
//! frozen when the replica forgot that past, which the replica reads instead
//! of judging the unit again.
//!
//! A replica that forgets the past of its kept checkpoint no longer holds a
//! unit's place there, so neither its verdict nor its context can be derived
//! again. Before it forgets, it takes what the space froze of each unit it
//! keeps ([`frasil_space::FrozenUnit`], from
//! [`frasil_space::Checkpointed::frozen_units`]) and what its adapter made of
//! the content there, and keeps them ([`Frozen::of`]; at-rest.md, the
//! `event` record's state and keys 6 to 8). From then on it hands the unit
//! to its adapter with the frozen capabilities ([`Frozen::context`]),
//! never with what the checkpoint's record or any later place gives its
//! author: every adapter is a pure function of content and context, so a
//! replica that forgot shows exactly what one that kept everything shows.
//! An edit by a writer lowered to reader before the checkpoint stays
//! applied, and a suggester's direct edit stays refused though it was
//! raised to writer later.

use crate::inner::Inner;
use crate::runtime;
use crate::unit::Unit;
use frasil_adapter::{Capabilities, Capability, Context, Mode};
use frasil_base::ErrorClass;
use frasil_base::errors::Class as _;
use frasil_events::EventId;
use frasil_space::across::AuthorReach;
use frasil_space::{CapabilityMode, FrozenUnit, MemberRef, MemberType};

/// The most capabilities a frozen unit keeps (at-rest.md, key 6).
pub const MAX_CAPABILITIES: usize = 64;
/// The most events a frozen unit names as voiding it (at-rest.md, key 8).
pub const MAX_VOIDED_BY: usize = 64;
/// The most paths a frozen unit's attribution names (at-rest.md, key 7).
pub const MAX_ATTRIBUTION: usize = 64;

/// What a replica keeps of a unit of its forgotten past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frozen {
    /// Its verdict: accepted, or refused with its class: the write rule's;
    /// `Pending` for content held as waiting for a log its author's path
    /// needs, or `CapabilityRefused` where no path was found; or its
    /// adapter's for its content.
    pub verdict: Result<(), String>,
    /// The capabilities its author held at its place, which its adapter
    /// reads (key 6).
    pub capabilities: Capabilities,
    /// For a unit the write rule admits, whether its content applied or
    /// was refused or held waiting, its attribution at its place: each path
    /// it was written through with its label there, by type then ID, at
    /// most 64 (key 7; roster.md, 3.11, "Attribution"). Empty for a unit the
    /// write rule voids, and for one no path reached.
    pub attribution: Vec<(MemberRef, Option<String>)>,
    /// For a refused unit, the events that void it, ascending, at most 64
    /// (key 8).
    pub voided_by: Vec<EventId>,
}

impl Frozen {
    /// What a replica keeps of a unit from what the space froze of it at its
    /// place, `unit`, and its adapter's refusal of its content there, if it
    /// refused it (`content`, its class).
    pub fn of(unit: &FrozenUnit, content: Option<&str>) -> Self {
        let capabilities = Capabilities::new(unit.capabilities().into_iter().map(|c| {
            Capability::new(
                c.name,
                match c.mode {
                    CapabilityMode::Extends => Mode::Extends,
                    CapabilityMode::Narrows => Mode::Narrows,
                },
            )
        }));
        let verdict = match (unit.status.class(), &unit.reach) {
            (Some(class), _) => Err(class.name().to_owned()),
            (None, Some(AuthorReach::Unjudged)) => Err(ErrorClass::Pending.name().to_owned()),
            (None, Some(AuthorReach::Unreached)) => {
                Err(ErrorClass::CapabilityRefused.name().to_owned())
            }
            (None, _) => match content {
                Some(class) => Err(class.to_owned()),
                None => Ok(()),
            },
        };
        // The write rule admits it: attributed, whatever became of its
        // content, unless no path reached it.
        let admitted = unit.status.is_valid();
        let attribution = match (&unit.attribution, &unit.reach) {
            (_, Some(AuthorReach::Unreached)) => Vec::new(),
            (Some(paths), _) if admitted => paths.iter().take(MAX_ATTRIBUTION).cloned().collect(),
            _ => Vec::new(),
        };
        Self {
            verdict,
            capabilities,
            attribution,
            // At most 64 are kept, the first by ID: they explain the
            // verdict, which is frozen whole.
            voided_by: match admitted {
                true => Vec::new(),
                false => unit.voided_by.iter().copied().take(MAX_VOIDED_BY).collect(),
            },
        }
    }

    /// Whether the unit's content applies: an accepted unit.
    pub fn applies(&self) -> bool {
        self.verdict.is_ok()
    }

    /// The unit's context (section 3.17), with the frozen capabilities: what
    /// the replica hands its adapter, never recomputed from what it still
    /// holds.
    pub fn context(&self, unit: &Unit, inner: &Inner, height: u64) -> Context {
        runtime::context(unit, inner, height, self.capabilities.clone())
    }

    /// The capabilities as at-rest.md's key 6 keeps them: pairs `(name,
    /// mode)`, strictly ascending by name and then mode, a name held in
    /// both modes kept in both.
    pub fn capability_pairs(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .capabilities
            .iter()
            .map(|capability| (capability.name.clone(), capability.mode.code()))
            .collect();
        out.sort_by(|a, b| (a.0.as_bytes(), a.1).cmp(&(b.0.as_bytes(), b.1)));
        out.dedup();
        out
    }

    /// The attribution as key 7 keeps it: `(type, ID, label)`, strictly
    /// ascending by type then ID.
    pub fn attribution_entries(&self) -> Vec<(u64, [u8; 32], Option<String>)> {
        let mut out: Vec<(u64, [u8; 32], Option<String>)> = self
            .attribution
            .iter()
            .map(|(member, label)| (member.kind.code(), member.id, label.clone()))
            .collect();
        out.sort_by_key(|entry| (entry.0, entry.1));
        out.dedup_by_key(|entry| (entry.0, entry.1));
        out
    }

    /// Reads what a replica kept of a unit at rest: `accepted`, its state
    /// (1, or 2 with `class`), and keys 6 to 8. `None` for a refused unit
    /// with no class, an accepted one with one, a mode that is neither 0
    /// nor 1, a member type no document defines, more capabilities,
    /// attribution entries or voiding events than the record holds, or an
    /// attribution beside voiding events.
    pub fn from_parts(
        accepted: bool,
        class: Option<&str>,
        capabilities: &[(String, u64)],
        attribution: &[(u64, [u8; 32], Option<String>)],
        voided_by: &[[u8; 32]],
    ) -> Option<Self> {
        let verdict = match (accepted, class) {
            (true, None) => Ok(()),
            (false, Some(class)) => Err(class.to_owned()),
            _ => return None,
        };
        if capabilities.len() > MAX_CAPABILITIES
            || voided_by.len() > MAX_VOIDED_BY
            || attribution.len() > MAX_ATTRIBUTION
            || (!attribution.is_empty() && !voided_by.is_empty())
        {
            return None;
        }
        let capabilities = capabilities
            .iter()
            .map(|(name, mode)| Some(Capability::new(name.clone(), Mode::from_code(*mode)?)))
            .collect::<Option<Capabilities>>()?;
        let attribution = attribution
            .iter()
            .map(|(kind, id, label)| {
                Some((
                    MemberRef {
                        kind: MemberType::from_code(*kind)?,
                        id: *id,
                    },
                    label.clone(),
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            verdict,
            capabilities,
            attribution,
            voided_by: voided_by.iter().copied().map(EventId).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_space::graph::Reach;
    use frasil_space::{Level, Status, Valid};
    use std::collections::BTreeSet;

    fn reached(extends: &[&str], narrows: &[&str]) -> AuthorReach {
        let set = |names: &[&str]| {
            names
                .iter()
                .map(|n| (*n).to_owned())
                .collect::<BTreeSet<_>>()
        };
        AuthorReach::Reached(Reach {
            level: Level::Write,
            propagates: true,
            propagating_level: Some(Level::Write),
            extends: set(extends),
            narrows: set(narrows),
            depth: 1,
            propagating_narrows: BTreeSet::new(),
            propagating_depth: 1,
        })
    }

    fn unit(status: Status, reach: Option<AuthorReach>) -> FrozenUnit {
        let valid = status.is_valid();
        FrozenUnit {
            status,
            reach,
            attribution: valid.then(|| {
                vec![
                    (
                        MemberRef::device(frasil_crypto::device::DeviceId([2; 32])),
                        None,
                    ),
                    (MemberRef::person([4; 32]), Some("Carol".to_owned())),
                ]
            }),
            voided_by: if valid {
                Vec::new()
            } else {
                vec![EventId([9; 32])]
            },
        }
    }

    #[test]
    fn an_accepted_unit_keeps_its_capabilities_and_its_attribution() {
        let frozen = Frozen::of(
            &unit(
                Status::Valid(Valid::Rules),
                Some(reached(&["comment"], &["suggest"])),
            ),
            None,
        );
        assert!(frozen.applies());
        assert!(frozen.capabilities.is_suggester());
        assert_eq!(
            frozen.capability_pairs(),
            vec![("comment".to_owned(), 0), ("suggest".to_owned(), 1)]
        );
        assert_eq!(
            frozen.attribution_entries(),
            vec![(0, [2; 32], None), (1, [4; 32], Some("Carol".to_owned()))]
        );
        assert!(frozen.voided_by.is_empty(), "only a voided unit's");
        let back = Frozen::from_parts(
            true,
            None,
            &frozen.capability_pairs(),
            &frozen.attribution_entries(),
            &[],
        );
        assert_eq!(back, Some(frozen));
    }

    #[test]
    fn refusals_keep_their_class_and_what_voids_them() {
        let refused = Status::void_by(frasil_space::SpaceClass::RefusedByRemoval, EventId([9; 32]));
        let frozen = Frozen::of(&unit(refused, Some(reached(&[], &[]))), None);
        assert_eq!(frozen.verdict, Err("RefusedByRemoval".to_owned()));
        assert_eq!(frozen.voided_by, vec![EventId([9; 32])]);
        assert!(
            frozen.attribution.is_empty(),
            "a voided unit names no member"
        );
        // Content waits for a log: attributed; no path was found: not.
        let valid = Status::Valid(Valid::Rules);
        let waits = Frozen::of(&unit(valid, Some(AuthorReach::Unjudged)), None);
        assert_eq!(waits.verdict, Err("Pending".to_owned()));
        assert_eq!(waits.attribution.len(), 2);
        let unreached = Frozen::of(&unit(valid, Some(AuthorReach::Unreached)), None);
        assert_eq!(unreached.verdict, Err("CapabilityRefused".to_owned()));
        assert!(unreached.attribution.is_empty());
        // The adapter refused its content at its place: still attributed.
        let content = Frozen::of(
            &unit(valid, Some(reached(&[], &["suggest"]))),
            Some("Refused"),
        );
        assert!(!content.applies());
        assert!(content.capabilities.is_suggester());
        assert_eq!(content.attribution.len(), 2);
        let back = Frozen::from_parts(
            false,
            Some("Refused"),
            &content.capability_pairs(),
            &content.attribution_entries(),
            &[],
        )
        .unwrap();
        assert_eq!(back, content);
    }

    #[test]
    fn what_does_not_read_is_none() {
        assert_eq!(Frozen::from_parts(false, None, &[], &[], &[]), None);
        assert_eq!(Frozen::from_parts(true, Some("Late"), &[], &[], &[]), None);
        assert_eq!(
            Frozen::from_parts(true, None, &[("a".into(), 2)], &[], &[]),
            None
        );
        assert_eq!(
            Frozen::from_parts(true, None, &[], &[(9, [0; 32], None)], &[]),
            None
        );
        // Keys 7 and 8 never together.
        assert_eq!(
            Frozen::from_parts(false, Some("Late"), &[], &[(0, [0; 32], None)], &[[1; 32]]),
            None
        );
    }
}
