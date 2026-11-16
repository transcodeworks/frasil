//! Chains, evidence of a fork, and the penalty (events.md, "Chains and
//! evidence of a fork" and "The penalty").
//!
//! The events one author signs in one log form its **chain** there: the
//! first has `seq` 1 and no `prev`; each later one has `seq` one more than
//! the previous and `prev` naming it. Two kinds of evidence prove a fork:
//!
//! - **Duplicate:** two events of one author in one log at one `seq`, with
//!   different IDs. The fork point is that `seq`.
//! - **Skip:** an event `e` whose `prev` names an event `p` that is not its
//!   author's event at `seq − 1`. If `p` is the author's own, the fork point
//!   is `min(e.seq, p.seq + 1)`; if `p` is another author's, it is `e.seq`.
//!
//! An event counts as evidence once its signature verifies: scheme 0
//! strictly, scheme 2 both halves; after the classical sunset, scheme 2 or a
//! covered scheme 0. Whether the replica can open it does not matter. A stub
//! is never evidence.
//!
//! From its fork point on, an author's events in the log are void
//! (`Forked`); its events before the fork point stand. A kind may exempt an
//! event that only lowers its own author; that is the kind's rule, applied
//! by its resolution.

use crate::decode::Event;
use crate::envelope::EventId;
use crate::log::Log;
use crate::proofs::ProofType;
use frasil_crypto::device::DeviceId;
use std::collections::{BTreeMap, BTreeSet};

/// Which evidence of a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceKind {
    /// Two events of one author at one `seq`.
    Duplicate,
    /// An event whose `prev` is not its author's event at `seq − 1`.
    Skip,
}

impl EvidenceKind {
    /// The proof type that carries this evidence (events.md, "Equivocation
    /// proofs").
    pub fn proof_type(self) -> ProofType {
        match self {
            Self::Duplicate => ProofType::Duplicate,
            Self::Skip => ProofType::Skip,
        }
    }
}

/// One piece of evidence that an author forked its chain in a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Evidence {
    /// Duplicate or skip.
    pub kind: EvidenceKind,
    /// The author that forked.
    pub author: DeviceId,
    /// The `seq` the evidence is at: the duplicate's, or the skipping
    /// event's.
    pub seq: u64,
    /// For a duplicate, the event with the smaller ID; for a skip, the event
    /// whose `prev` skips.
    pub first: EventId,
    /// For a duplicate, the event with the larger ID; for a skip, the event
    /// its `prev` names.
    pub second: EventId,
    /// The fork point this evidence shows.
    pub fork_seq: u64,
}

/// Each author's fork point in a log: the smallest its evidence shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForkPoints(BTreeMap<DeviceId, u64>);

impl ForkPoints {
    /// The fork points the evidence shows.
    pub fn from_evidence<'a>(evidence: impl IntoIterator<Item = &'a Evidence>) -> Self {
        let mut points = BTreeMap::new();
        for item in evidence {
            points
                .entry(item.author)
                .and_modify(|point: &mut u64| *point = (*point).min(item.fork_seq))
                .or_insert(item.fork_seq);
        }
        Self(points)
    }

    /// Fork points as kept at rest: each author's point.
    pub fn from_points(points: BTreeMap<DeviceId, u64>) -> Self {
        Self(points)
    }

    /// An author's fork point, if its evidence shows one.
    pub fn fork_point(&self, author: &DeviceId) -> Option<u64> {
        self.0.get(author).copied()
    }

    /// Whether an event of an author at a `seq` is void by the penalty
    /// (`Forked`): at or after its author's fork point.
    pub fn is_void_at(&self, author: &DeviceId, seq: u64) -> bool {
        self.fork_point(author).is_some_and(|point| seq >= point)
    }

    /// Whether an event is void by the penalty (`Forked`). A kind's
    /// exemption for an event that only lowers its own author is applied by
    /// the kind.
    pub fn is_void(&self, event: &Event) -> bool {
        self.is_void_at(event.author(), event.seq())
    }

    /// Every author with a fork point, and the point.
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)> {
        self.0.iter().map(|(author, &point)| (author, point))
    }

    /// Whether no author forked.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Log {
    /// The evidence of every fork among the log's placed events, see
    /// [`evidence_in`](Log::evidence_in).
    pub fn evidence(&self, counts: impl Fn(&Event) -> bool) -> Vec<Evidence> {
        self.evidence_among(self.canonical(), counts)
    }

    /// The evidence of every fork among a view's events: every duplicate, by
    /// author and `seq` and then by the two IDs, then every skip, in
    /// canonical order.
    ///
    /// An event counts once its signature verified in full
    /// ([`Log::is_verified`]) and `counts` accepts it: before the classical
    /// sunset, pass `|_| true`; after it, accept scheme 2 and a covered
    /// scheme 0 ([`Log::covered`]). A skip counts only if the event its
    /// `prev` names is placed and counts too; a stubbed `prev` proves
    /// nothing.
    pub fn evidence_in(
        &self,
        view: &BTreeSet<EventId>,
        counts: impl Fn(&Event) -> bool,
    ) -> Vec<Evidence> {
        self.evidence_among(self.canonical_in(view), counts)
    }

    fn evidence_among(
        &self,
        order: Vec<EventId>,
        counts: impl Fn(&Event) -> bool,
    ) -> Vec<Evidence> {
        self.evidence_counting(order, |id| {
            self.verified(id).is_some_and(|event| counts(event))
        })
    }

    fn evidence_counting(
        &self,
        order: Vec<EventId>,
        counted: impl Fn(EventId) -> bool,
    ) -> Vec<Evidence> {
        let ids: Vec<EventId> = order.into_iter().filter(|&id| counted(id)).collect();
        let mut slots: BTreeMap<(DeviceId, u64), Vec<EventId>> = BTreeMap::new();
        for &id in &ids {
            let event = self.event(id).expect("placed");
            slots
                .entry((*event.author(), event.seq()))
                .or_default()
                .push(id);
        }
        let mut out = Vec::new();
        for ((author, seq), mut slot) in slots {
            slot.sort_unstable();
            for (i, &first) in slot.iter().enumerate() {
                for &second in &slot[i + 1..] {
                    out.push(Evidence {
                        kind: EvidenceKind::Duplicate,
                        author,
                        seq,
                        first,
                        second,
                        fork_seq: seq,
                    });
                }
            }
        }
        for &id in &ids {
            let event = self.event(id).expect("placed");
            let Some(prev) = event.prev() else {
                continue;
            };
            let Some(previous) = self.event(prev) else {
                continue;
            };
            if !counted(prev) {
                continue;
            }
            let own = previous.author() == event.author();
            if own && previous.seq().checked_add(1) == Some(event.seq()) {
                continue;
            }
            let fork_seq = if own {
                event.seq().min(previous.seq().saturating_add(1))
            } else {
                event.seq()
            };
            out.push(Evidence {
                kind: EvidenceKind::Skip,
                author: *event.author(),
                seq: event.seq(),
                first: id,
                second: prev,
                fork_seq,
            });
        }
        out
    }

    /// Each author's fork point among the log's placed events.
    pub fn fork_points(&self, counts: impl Fn(&Event) -> bool) -> ForkPoints {
        ForkPoints::from_evidence(&self.evidence(counts))
    }

    /// [`evidence_in`](Log::evidence_in), counting the events `counted`
    /// accepts, whether or not this log marks them verified.
    pub fn evidence_counting_in(
        &self,
        view: &BTreeSet<EventId>,
        counted: impl Fn(EventId) -> bool,
    ) -> Vec<Evidence> {
        self.evidence_counting(self.canonical_in(view), counted)
    }

    /// Each author's fork point among a view's events, counting those
    /// `counted` accepts, whether or not this log marks them verified: for a
    /// reader that checked signatures itself.
    pub fn fork_points_counting(
        &self,
        view: &BTreeSet<EventId>,
        counted: impl Fn(EventId) -> bool,
    ) -> ForkPoints {
        ForkPoints::from_evidence(&self.evidence_counting(self.canonical_in(view), counted))
    }

    /// Each author's fork point among a view's events.
    pub fn fork_points_in(
        &self,
        view: &BTreeSet<EventId>,
        counts: impl Fn(&Event) -> bool,
    ) -> ForkPoints {
        ForkPoints::from_evidence(&self.evidence_in(view, counts))
    }

    /// The equivocation proof of a piece of evidence (events.md,
    /// "Equivocation proofs"), from the signed copies the log keeps. `None`
    /// if either event is not placed.
    pub fn proof(&self, evidence: &Evidence) -> Option<Vec<u8>> {
        let first = self.event(evidence.first)?;
        let second = self.event(evidence.second)?;
        Some(crate::proofs::encode_proof(
            evidence.kind.proof_type(),
            &first.signed(),
            &second.signed(),
        ))
    }
}
