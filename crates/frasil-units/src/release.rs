//! Release and restore at a replica, across checkpoints (units.md, 3.12
//! Release, restore and erasure at a replica, "After a checkpoint";
//! peers.md, 3.18 Release and restore).
//!
//! A stream is released when some release names it and every maximal event
//! among the releases and restores that name it is a release: a restore
//! concurrent with a release wins. With a checkpoint in effect, the events
//! counted are those of its past and those after it, and every one of the
//! past is before every one after it, which holds that whole past. A
//! release or restore late under any checkpoint of the chain in effect
//! counts for nothing, then and under every later checkpoint, though a
//! later checkpoint's past holds it; its verdict stays `Late`, and its
//! author signs it again after the checkpoint. So no late event's place
//! among the events of the past is needed.
//!
//! A replica that forgot keeps, of the releases and restores of its kept
//! checkpoint's past that are not late under an earlier checkpoint, the
//! maximal ones of each stream, which it finds before it drops anything,
//! and every restore that names a snapshot unit ([`kept_requests`]). They
//! are concurrent with each other, so it reads no order among them, and it
//! orders each before every event after the kept checkpoint
//! ([`frasil_space::Checkpointed::precedes`]), as one that kept everything
//! finds them ordered: it finds every stream released as one that kept
//! everything does ([`released`]).
//!
//! A replica judges releases and restores by the write rule, which a peer
//! does not run: maximality reads every request, valid or void, as a peer
//! counts them, and a stream one of whose maximal requests the replica
//! judged void is not released there; it keeps its units.

use frasil_events::EventId;
use frasil_peers::body::{Restored, StorageBody};
use frasil_space::Placement;
use std::collections::{BTreeMap, BTreeSet};

/// A release or restore a replica holds, as [`released`] counts it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'b> {
    /// Its event.
    pub id: EventId,
    /// Its body: a release, or a restore.
    pub body: &'b StorageBody,
    /// Where it stands against the chain in effect
    /// ([`frasil_space::Checkpointed::placement`]): late under any of its
    /// checkpoints is [`Placement::Late`]. A replica that forgot places the
    /// requests it kept of its kept checkpoint's past there,
    /// [`Placement::Past`], once it names them
    /// ([`frasil_space::Checkpointed::set_kept_past`]).
    pub placement: Placement,
    /// Whether the replica judged it valid by the write rule.
    pub valid: bool,
}

impl Request<'_> {
    /// The stream it names, and whether it releases it.
    fn stream(&self) -> Option<([u8; 16], bool)> {
        match self.body {
            StorageBody::Release { stream } => Some((*stream, true)),
            StorageBody::Restore(Restored::Stream(stream)) => Some((*stream, false)),
            _ => None,
        }
    }
}

/// Whether `stream` is released at a replica that holds `requests`, with
/// `precedes` the order the replica reads between two of them
/// ([`frasil_space::Checkpointed::precedes`]) (units.md, 3.12, "After a
/// checkpoint"):
///
/// - a request late under any checkpoint of the chain counts for nothing,
///   a release or a restore, though a later checkpoint's past holds it;
/// - one whose place waits for envelopes counts for nothing if a release,
///   and, if a restore, as maximal, so the stream is not released until
///   its place is known;
/// - one of the last checkpoint's past precedes every one after it; between
///   two of that past, or two after it, `precedes` decides. A replica that
///   forgot holds what it kept of its kept checkpoint's past without the
///   order to what came between: [`frasil_space::Checkpointed::precedes`]
///   puts each such request before every event that follows the kept
///   checkpoint, as a peer that truncated orders them (peers.md, 3.18), and
///   reads its log otherwise;
/// - the stream is released when some counted release names it, and every
///   maximal counted request naming it is a release the replica judged
///   valid.
pub fn released(
    requests: &[Request<'_>],
    stream: &[u8; 16],
    precedes: impl Fn(EventId, EventId) -> bool,
) -> bool {
    let naming: Vec<(&Request<'_>, bool)> = requests
        .iter()
        .filter_map(|request| match request.stream() {
            Some((s, is_release)) if s == *stream => Some((request, is_release)),
            _ => None,
        })
        .collect();
    let set_aside = |r: &Request<'_>| matches!(r.placement, Placement::Late | Placement::Pending);
    if naming
        .iter()
        .any(|&(r, is_release)| !is_release && r.placement == Placement::Pending)
    {
        return false;
    }
    let counted: Vec<(&Request<'_>, bool)> =
        naming.into_iter().filter(|&(r, _)| !set_aside(r)).collect();
    if !counted.iter().any(|&(_, is_release)| is_release) {
        return false;
    }
    let before = |a: &Request<'_>, b: &Request<'_>| match (a.placement, b.placement) {
        (Placement::Past, Placement::After) => true,
        (Placement::After, Placement::Past) => false,
        _ => precedes(a.id, b.id),
    };
    counted
        .iter()
        .filter(|&&(a, _)| !counted.iter().any(|&(b, _)| a.id != b.id && before(a, b)))
        .all(|&(r, is_release)| is_release && r.valid)
}

/// The releases and restores of a checkpoint's past that a replica that
/// forgets under it keeps (roster.md, 3.15.6, "What must be kept"; units.md,
/// 3.12): of those that name a stream, the maximal ones of each stream, by
/// `precedes`, found while the replica holds the whole past; and every
/// restore that names a snapshot unit. `requests` are every release and
/// restore of that past, valid or void, with their bodies, but those late
/// under an earlier checkpoint of the chain, which count for nothing
/// ([`frasil_space::Checkpointed::placement`] places them
/// [`Placement::Late`]): such a one must not hide an earlier request of its
/// stream that counts.
pub fn kept_requests<'b>(
    requests: impl IntoIterator<Item = (EventId, &'b StorageBody)>,
    precedes: impl Fn(EventId, EventId) -> bool,
) -> BTreeSet<EventId> {
    let mut out = BTreeSet::new();
    let mut streams: BTreeMap<[u8; 16], Vec<EventId>> = BTreeMap::new();
    for (id, body) in requests {
        match body {
            StorageBody::Release { stream } | StorageBody::Restore(Restored::Stream(stream)) => {
                streams.entry(*stream).or_default().push(id);
            }
            StorageBody::Restore(Restored::Snapshot(_)) => {
                out.insert(id);
            }
            _ => {}
        }
    }
    for ids in streams.values() {
        out.extend(
            ids.iter()
                .copied()
                .filter(|&a| !ids.iter().any(|&b| a != b && precedes(a, b))),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: [u8; 16] = [7; 16];

    fn id(n: u8) -> EventId {
        EventId([n; 32])
    }

    fn release() -> StorageBody {
        StorageBody::Release { stream: X }
    }

    fn restore() -> StorageBody {
        StorageBody::Restore(Restored::Stream(X))
    }

    fn at<'b>(n: u8, body: &'b StorageBody, placement: Placement) -> Request<'b> {
        Request {
            id: id(n),
            body,
            placement,
            valid: true,
        }
    }

    #[test]
    fn a_concurrent_restore_wins() {
        let (rel, res) = (release(), restore());
        let never = |_, _| false;
        let one = [at(1, &rel, Placement::Unchecked)];
        assert!(released(&one, &X, never));
        let both = [
            at(1, &rel, Placement::Unchecked),
            at(2, &res, Placement::Unchecked),
        ];
        assert!(!released(&both, &X, never));
        // The restore before the release: released.
        let order = |a: EventId, b: EventId| a == id(2) && b == id(1);
        assert!(released(&both, &X, order));
        assert!(!released(&[], &X, never));
    }

    #[test]
    fn the_past_precedes_what_follows_the_checkpoint() {
        // A release of the past and a restore after the checkpoint, which
        // the log cannot order once the replica forgot what lay between.
        let (rel, res) = (release(), restore());
        let never = |_, _| false;
        let requests = [at(1, &rel, Placement::Past), at(2, &res, Placement::After)];
        assert!(!released(&requests, &X, never));
        let requests = [at(1, &res, Placement::Past), at(2, &rel, Placement::After)];
        assert!(released(&requests, &X, never));
    }

    #[test]
    fn late_releases_and_restores_count_for_nothing() {
        let (rel, res) = (release(), restore());
        let never = |_, _| false;
        let requests = [at(1, &rel, Placement::Past), at(2, &rel, Placement::Late)];
        assert!(released(&requests, &X, never));
        let requests = [at(1, &res, Placement::Past), at(2, &rel, Placement::Late)];
        assert!(!released(&requests, &X, never));
        // A late restore keeps nothing: its author signs it again after the
        // checkpoint.
        let requests = [at(1, &rel, Placement::After), at(2, &res, Placement::Late)];
        assert!(released(&requests, &X, never));
        let requests = [at(1, &rel, Placement::Past), at(2, &res, Placement::Late)];
        assert!(released(&requests, &X, never));
        assert!(!released(&[at(2, &rel, Placement::Late)], &X, never));
        // A restore whose place waits for envelopes may be after the
        // release: the stream is not released until it is placed.
        let requests = [
            at(1, &rel, Placement::After),
            at(2, &res, Placement::Pending),
        ];
        assert!(!released(&requests, &X, never));
    }

    #[test]
    fn a_void_maximal_request_keeps_the_units() {
        let (rel, res) = (release(), restore());
        let mut void = at(2, &rel, Placement::Unchecked);
        void.valid = false;
        let before = |a: EventId, b: EventId| a == id(1) && b == id(2);
        assert!(!released(
            &[at(1, &rel, Placement::Unchecked), void],
            &X,
            before
        ));
        // A void restore below a valid release decides nothing.
        let mut void = at(1, &res, Placement::Unchecked);
        void.valid = false;
        assert!(released(
            &[void, at(2, &rel, Placement::Unchecked)],
            &X,
            before
        ));
    }

    #[test]
    fn a_replica_that_forgot_keeps_the_maximal_requests() {
        // restore 1 < release 2 (through an anchor), restore 3 concurrent
        // with both, another stream's release 4, and a snapshot's restore 5.
        let (rel, res) = (release(), restore());
        let other = StorageBody::Release { stream: [8; 16] };
        let snapshot = StorageBody::Restore(Restored::Snapshot([9; 32]));
        let precedes = |a: EventId, b: EventId| a == id(1) && b == id(2);
        let all = [
            (id(1), &res),
            (id(2), &rel),
            (id(3), &res),
            (id(4), &other),
            (id(5), &snapshot),
        ];
        let kept = kept_requests(all.iter().map(|&(i, b)| (i, b)), precedes);
        assert_eq!(kept, BTreeSet::from([id(2), id(3), id(4), id(5)]));
        // It and a replica that kept everything find the same, with or
        // without a request after the checkpoint.
        let full: Vec<Request<'_>> = all[..3]
            .iter()
            .map(|&(i, b)| Request {
                id: i,
                body: b,
                placement: Placement::Past,
                valid: true,
            })
            .collect();
        let forgot: Vec<Request<'_>> = full
            .iter()
            .copied()
            .filter(|r| kept.contains(&r.id))
            .collect();
        let never = |_, _| false;
        assert_eq!(released(&full, &X, precedes), released(&forgot, &X, never));
        let after = at(6, &rel, Placement::After);
        let mut full_after = full.clone();
        full_after.push(after);
        let mut forgot_after = forgot.clone();
        forgot_after.push(after);
        assert!(released(&full_after, &X, precedes));
        assert!(released(&forgot_after, &X, never));
    }
}
