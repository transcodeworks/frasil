//! The rank and the delay (keys.md, "The rank and the delay"), and the
//! restored member's decision on gap keys ("Restored members").
//!
//! ```text
//! rank_value(d) = u64be(first 8 bytes of SHA-256("frasil/rotation-rank/v1"
//!                 || field(space) || field(trigger) || device ID of d))
//! position(d)   = d's index, from 0, among the candidates ordered by
//!                 ascending rank_value, then ascending device ID
//! delay(d)      = min(position(d), rotation_rank_cap) × rotation_step
//! ```
//!
//! The delay counts from the device's first sight of the trigger, on the
//! lower estimate, and decides only when this device acts: a rotation made
//! early, late or by several devices is valid by the same rules.

use frasil_base::notation::push_field;
use frasil_base::time::{Reading, Timer, lower};
use frasil_crypto::labels::ROTATION_RANK;
use frasil_crypto::primitives::sha256;

/// `rotation_rank_cap` (overview.md, "Every timer"): the highest position
/// the delay counts.
pub fn rotation_rank_cap() -> u64 {
    Timer::RotationRankCap.spec().default.unwrap_or(63)
}

/// A candidate's rank: the digest and its first 8 bytes, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rank {
    /// `SHA-256("frasil/rotation-rank/v1" || field(space) || field(trigger)
    /// || device ID)`.
    pub digest: [u8; 32],
    /// `rank_value`: the digest's first 8 bytes, big-endian.
    pub value: u64,
}

/// `rank_value` of a device, by its device ID, for a trigger in a space.
pub fn rank_value(space: &[u8; 32], trigger: &[u8], identity: &[u8; 32]) -> Rank {
    let mut prefix = ROTATION_RANK.to_vec();
    push_field(&mut prefix, space);
    push_field(&mut prefix, trigger);
    let digest = sha256(&[&prefix, identity]);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    Rank {
        digest,
        value: u64::from_be_bytes(first),
    }
}

/// The candidates in rank order: ascending `rank_value`, then ascending
/// device ID. A device's position is its index here.
pub fn rank_order(space: &[u8; 32], trigger: &[u8], candidates: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out: Vec<(u64, [u8; 32])> = candidates
        .iter()
        .map(|identity| (rank_value(space, trigger, identity).value, *identity))
        .collect();
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(|(_, identity)| identity).collect()
}

/// A device's position among the candidates, if it is one.
pub fn position(
    space: &[u8; 32],
    trigger: &[u8],
    candidates: &[[u8; 32]],
    identity: &[u8; 32],
) -> Option<u64> {
    rank_order(space, trigger, candidates)
        .iter()
        .position(|c| c == identity)
        .map(|p| p as u64)
}

/// `delay(d) = min(position(d), rotation_rank_cap) × rotation_step`, in
/// seconds.
pub fn delay(position: u64, rotation_step: u64) -> u64 {
    position
        .min(rotation_rank_cap())
        .saturating_mul(rotation_step)
}

/// Whether a candidate's delay has passed, counted on the lower estimate
/// from its first sight of the trigger. First sight never moves, so a
/// device that returns after its delay acts at once.
pub fn due(first_sight: &Reading, now: &Reading, position: u64, rotation_step: u64) -> bool {
    lower(first_sight, now) >= delay(position, rotation_step)
}

/// What a holder does with a key made while a restored member was out
/// (keys.md, "Restored members").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapKeyDecision {
    /// Wrap it for the restored member.
    Wrap,
    /// Hold it back, and list it as waiting.
    Wait,
}

/// keys.md, "Restored members":
///
/// ```text
/// gap_keys(stable, first_sight, now, gap_key_timeout):
///   1. stable: the voiding of r is stable (roster.md).               Wrap
///   2. lower(first_sight, now) >= gap_key_timeout.                   Wrap
///   3. Otherwise.                                                    Wait
/// ```
///
/// The decision is only whether this device wraps; it never makes a key or
/// an event valid or void.
pub fn gap_keys(
    stable: bool,
    first_sight: &Reading,
    now: &Reading,
    gap_key_timeout: u64,
) -> GapKeyDecision {
    if stable || lower(first_sight, now) >= gap_key_timeout {
        GapKeyDecision::Wrap
    } else {
        GapKeyDecision::Wait
    }
}
