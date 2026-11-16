//! Decisions a replica takes from what it holds: settling a snapshot
//! (units.md, section 3.6), confirming a stub (section 3.9), whom a missing
//! head is reported against (section 3.13), and a partial replica's verdict
//! on a unit (section 3.15).

use crate::body::Stub;
use frasil_base::time::{Reading, lower};
use std::collections::BTreeSet;

/// Section 3.6, "Settling", at a replica, in order:
///
/// ```text
/// settled(s):
///   1. s is stable (roster.md).                                         Settled
///   2. lower(first sight of s, now) >= gap_key_timeout.                 Settled
///   3. Otherwise.                                                       Unsettled
/// ```
///
/// Step 2 bounds a space that never reaches stability, such as one whose
/// recovery member never signs. Returns whether `s` is settled.
pub fn settled(stable: bool, first_sight: &Reading, now: &Reading, gap_key_timeout: u64) -> bool {
    stable || lower(first_sight, now) >= gap_key_timeout
}

/// Whether a stub that a space event rests on counts (section 3.9,
/// "Confirming heights").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StubDecision {
    /// The parent is held in full.
    HeldInFull,
    /// Two different signers sign the same stub.
    TwoSignersAgree,
    /// Only one signer signs it, perhaps more than once: the space event
    /// stays pending.
    OneSigner,
    /// Two stubs disagree for one ID: every event that has it as a parent
    /// stays pending until the replica holds the event itself.
    StubsDisagree,
}

impl StubDecision {
    /// Whether the space event that rests on the stub is placed.
    pub fn placed(self) -> bool {
        matches!(self, Self::HeldInFull | Self::TwoSignersAgree)
    }
}

/// Section 3.9, "Confirming heights": for every parent of a space event
/// that a replica places against a stub, it either fetches the parent in
/// full, or holds the same stub from two signed sources by two different
/// signers. `sources` are the signed sources that gave the stub: each
/// signer, and the stub it gave.
pub fn confirm_stub<S: Ord>(held_in_full: bool, sources: &[(S, Stub)]) -> StubDecision {
    if held_in_full {
        return StubDecision::HeldInFull;
    }
    let stubs: BTreeSet<&Stub> = sources.iter().map(|(_, stub)| stub).collect();
    if stubs.len() > 1 {
        return StubDecision::StubsDisagree;
    }
    let signers: BTreeSet<&S> = sources.iter().map(|(signer, _)| signer).collect();
    if signers.len() >= 2 {
        StubDecision::TwoSignersAgree
    } else {
        StubDecision::OneSigner
    }
}

/// Whom a head statement's missing head is reported against (section
/// 3.13, "Head statements").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementOutcome {
    /// The peer served the statement's heads and their past.
    Consistent,
    /// The peer served less, the statement's author supplied them, and the
    /// peer had acknowledged them or still lacked them after
    /// `withholding_grace`: the peer was withholding (`Withheld`).
    WithheldByPeer,
    /// The author supplied them, but the peer may simply not have received
    /// them yet: nothing is reported.
    NotReported,
    /// The author answered `Missing` for them: the statement is junk
    /// (`BadStatement`), reported against its author.
    BadStatement,
}

/// A receiver that cannot obtain a statement's heads, or their past, asks
/// the statement's author first. If the author does not supply them, the
/// statement is junk. If it does, a peer that served less was withholding
/// when it had acknowledged them, or when its `Missing` answers for them
/// span at least `withholding_grace`: `missing_for` is the time from its
/// first `Missing` to its latest, on the receiver's monotonic clock.
pub fn statement_outcome(
    peer_serves: bool,
    author_supplies: bool,
    peer_acknowledged: bool,
    missing_for: u64,
    withholding_grace: u64,
) -> StatementOutcome {
    if peer_serves {
        StatementOutcome::Consistent
    } else if !author_supplies {
        StatementOutcome::BadStatement
    } else if peer_acknowledged || missing_for >= withholding_grace {
        StatementOutcome::WithheldByPeer
    } else {
        StatementOutcome::NotReported
    }
}

/// A partial replica's verdict on a unit `u` whose writer's removal `r` it
/// holds (section 3.15, "Proven order").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartialVerdict {
    /// `r` is proven in the past of `u`: `NotAWriter`.
    NotAWriter,
    /// `u` is proven before `r`, by a `Path` from `r` down to `u`: valid.
    Valid,
    /// Its order against `r` is not proven: pending, never applied.
    Pending,
}

/// Section 3.15: a partial replica counts a space event `r` as in the past
/// of `u` only when it is among `u`'s parents, or in the past of such a
/// space event through space events, or a `Path` from `u` down to `r`
/// checks (`r_in_past_proven`); and counts `u` as before `r` only when a
/// `Path` from `r` down to `u` checks (`u_before_r_proven`). A unit whose
/// verdict depends on an order it has not proven is pending: a unit
/// concurrent with its writer's removal can never be proven before it, so
/// it is never applied.
pub fn partial_verdict(r_in_past_proven: bool, u_before_r_proven: bool) -> PartialVerdict {
    if r_in_past_proven {
        PartialVerdict::NotAWriter
    } else if u_before_r_proven {
        PartialVerdict::Valid
    } else {
        PartialVerdict::Pending
    }
}
