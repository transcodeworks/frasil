//! What an erasure residue can check without a space key (peers.md, 3.16).

use crate::PeersClass;
use crate::body::{SlotId, StorageBody};
use frasil_base::ErrorClass;
use frasil_events::{EventId, decode, kind};

/// The fields of a peer's late-erasure answer, before the residue checks them.
#[derive(Debug, Clone, Copy)]
pub struct LateErasure<'a> {
    /// The space the peer names.
    pub space: EventId,
    /// The erasure the peer names.
    pub erasure: EventId,
    /// The cut's signed envelope.
    pub cut: &'a [u8],
    /// The checkpoint's ID.
    pub checkpoint: EventId,
    /// The slot's standing, 0 to 2.
    pub standing: u8,
}

/// Checks a peer's late-erasure answer without a space key.
///
/// The caller first checks the message's shape. This cannot establish that
/// the cut is in effect or that the erasure is outside its past. Returns the
/// checkpoint ID for the application; the residue must be kept.
///
/// # Errors
///
/// `Malformed` for another space or erasure or a standing outside 0 to 2;
/// `PeerError` for a cut envelope that does not decode and verify its Ed25519
/// half, another space in the envelope, a body that is not a cut, or a
/// contradictory slot.
pub fn check_late(
    space: EventId,
    erasure: EventId,
    slot: SlotId,
    answer: LateErasure<'_>,
) -> Result<EventId, PeersClass> {
    if answer.space != space || answer.erasure != erasure || answer.standing > 2 {
        return Err(ErrorClass::Malformed.into());
    }
    let LateErasure {
        cut,
        checkpoint,
        standing,
        ..
    } = answer;
    let cut = decode(cut).map_err(|_| PeersClass::PeerError)?;
    if cut.log() != Some(space) || cut.kind() != kind::STORAGE {
        return Err(PeersClass::PeerError);
    }
    let body = StorageBody::read(cut.unverified_body()).map_err(|_| PeersClass::PeerError)?;
    let StorageBody::Cut(body) = body else {
        return Err(PeersClass::PeerError);
    };
    if body.slots.iter().any(|entry| entry.slot == slot) != (standing < 2) {
        return Err(PeersClass::PeerError);
    }
    if standing == 0
        && body
            .slots
            .iter()
            .find(|entry| entry.slot == slot)
            .is_none_or(|entry| entry.pseudonym.is_none())
    {
        return Err(PeersClass::PeerError);
    }
    Ok(checkpoint)
}
