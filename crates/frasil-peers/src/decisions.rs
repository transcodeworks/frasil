//! The peer's decisions on erasure, credentials requests, release and
//! collection (peers.md, "Erasure", "Credentials requests", "Release and
//! restore", "Collection").
//!
//! Each reads `lower`, the lower estimate of elapsed time on the peer's
//! timeline (overview.md, "The two estimates"), from the peer's first sight
//! of the request to now.

use crate::body::{Restored, StorageBody};
use frasil_base::time::{Reading, lower};
use frasil_events::{EventId, Log};

/// An erasure's or a credentials request's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Execution {
    /// Not valid at the peer.
    Void,
    /// Carried out.
    Execute,
    /// Waits for stability or T.
    Wait,
}

/// ```text
/// erasure(valid, undecided, stable, accepted, now, T):
///   0. not valid at the peer, or late under the cut in effect.  Void
///   1. concurrent with a cut that can still take effect.        Wait
///   2. stable at the peer.                                      Execute
///   3. lower(accepted, now) >= T, on the peer's timeline.       Execute
///   4. otherwise.                                               Wait
/// ```
///
/// A credentials request is carried out by the same rule. The peer judges
/// validity again when it executes, so a concurrent lowering that arrived
/// during the wait voids the request. `undecided` is
/// [`crate::cut::PeerCuts::request_state`]'s `Wait`: the timeout of step 3
/// runs on meanwhile, and once the cut takes effect the request is late
/// (step 0).
pub fn erasure(
    valid: bool,
    undecided: bool,
    stable: bool,
    accepted: &Reading,
    now: &Reading,
    timeout: u64,
) -> Execution {
    if !valid {
        Execution::Void
    } else if undecided {
        Execution::Wait
    } else if stable || lower(accepted, now) >= timeout {
        Execution::Execute
    } else {
        Execution::Wait
    }
}

/// A credentials request: [`erasure`]'s rule, its steps 0 and 1 included.
pub fn credentials_request(
    valid: bool,
    undecided: bool,
    stable: bool,
    accepted: &Reading,
    now: &Reading,
    timeout: u64,
) -> Execution {
    erasure(valid, undecided, stable, accepted, now, timeout)
}

/// A released stream's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reclamation {
    /// Its bytes stay.
    Keep,
    /// Its units, and the objects only they reference, are deleted; stubs
    /// and a released marker stay.
    Reclaim,
}

/// ```text
/// release(released, undecided, stable, released_at, now, retention, T):
///   1. not released.                                            Keep
///   2. a release that makes it released is concurrent with a
///      cut that can still take effect.                         Keep
///   3. lower(released_at, now) >= retention, and (stable at the
///      peer, or lower(released_at, now) >= T).                  Reclaim
///   4. otherwise.                                               Keep
/// ```
///
/// `released_at` is the peer's first sight of the latest release that makes
/// the stream released; `stable` asks that each such release be stable at
/// the peer; `retention` is `release_retention`; `undecided` that one of
/// them waits for a cut ([`crate::cut::PeerCuts::request_state`]).
pub fn release(
    released: bool,
    undecided: bool,
    stable: bool,
    released_at: &Reading,
    now: &Reading,
    retention: u64,
    timeout: u64,
) -> Reclamation {
    if !released || undecided {
        return Reclamation::Keep;
    }
    let waited = lower(released_at, now);
    if waited >= retention && (stable || waited >= timeout) {
        Reclamation::Reclaim
    } else {
        Reclamation::Keep
    }
}

/// A snapshot unit's cover's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Collection {
    /// The cover stays.
    Keep,
    /// The cover is collected.
    Collect,
}

/// ```text
/// collect(cancelled, stable, seen, now, T):
///   1. cancelled: a stored restore names the snapshot unit.     Keep
///   2. stable at the peer, or lower(seen, now) >= T.            Collect
///   3. otherwise.                                               Keep
/// ```
pub fn collect(
    cancelled: bool,
    stable: bool,
    seen: &Reading,
    now: &Reading,
    timeout: u64,
) -> Collection {
    if cancelled {
        Collection::Keep
    } else if stable || lower(seen, now) >= timeout {
        Collection::Collect
    } else {
        Collection::Keep
    }
}

/// Whether a stream is released at a peer with no cut in effect (peers.md,
/// "Release and restore"): some release names it, and every maximal event
/// among the releases and restores that name it is a release. A restore
/// concurrent with a release wins. With cuts, and at a peer that truncated,
/// [`crate::cut::PeerCuts::released`] says it.
pub fn is_released<'b>(
    log: &Log,
    requests: impl IntoIterator<Item = (EventId, &'b StorageBody)>,
    stream: &[u8; 16],
) -> bool {
    let naming: Vec<(EventId, bool)> = requests
        .into_iter()
        .filter_map(|(id, body)| match body {
            StorageBody::Release { stream: s } if s == stream => Some((id, true)),
            StorageBody::Restore(Restored::Stream(s)) if s == stream => Some((id, false)),
            _ => None,
        })
        .collect();
    if !naming.iter().any(|&(_, is_release)| is_release) {
        return false;
    }
    naming
        .iter()
        .filter(|&&(id, _)| !naming.iter().any(|&(other, _)| log.precedes(id, other)))
        .all(|&(_, is_release)| is_release)
}

/// Whether a stored restore names a snapshot unit, cancelling its
/// collection.
pub fn is_cancelled<'b>(
    requests: impl IntoIterator<Item = (EventId, &'b StorageBody)>,
    snapshot: &[u8; 32],
) -> bool {
    requests.into_iter().any(
        |(_, body)| matches!(body, StorageBody::Restore(Restored::Snapshot(s)) if s == snapshot),
    )
}
