//! Release and restore of a stream (peers.md, 3.18 Release and restore):
//! writer requests, signed by a writer's device as storage events, that
//! tell every peer to stop serving a stream's units and the objects only
//! they reference, or to serve them again.

use crate::device::Engine;
use crate::error::{Error, Result};
use crate::replica::Replica;
use frasil_events::{EventId, kind};
use frasil_peers::body::{Restored, StorageBody};
use frasil_space::{Level, Placement};
use frasil_units::release::Request;
use frasil_units::stream::StreamId;

/// Whether `stream` is released in this replica (peers.md, 3.18 Release
/// and restore): some release names it, and every maximal event among the
/// releases and restores that name it is a release. Only requests whose
/// author writes in the space count, by roster.md's write rule as the
/// replica's roster holds it now, and none the checkpoint in effect made
/// late.
pub(crate) fn released(replica: &Replica, stream: &StreamId) -> bool {
    let Some(log) = replica.log() else {
        return false;
    };
    // Only requests whose signature verified in full count: a storage
    // event's ML-DSA-65 half that is `NoHybridKey` or `BadSignature` is
    // never applied (events.md, 3.3 The ML-DSA-65 half).
    let requests: Vec<(EventId, StorageBody)> = log
        .frame_events()
        .filter(|event| event.kind() == kind::STORAGE)
        .filter_map(|event| replica.verified_event(&event.id()))
        .filter(|event| replica.level_of(event.author()) >= Some(Level::Write))
        .filter_map(|event| {
            let body = StorageBody::read(event.body()).ok()?;
            matches!(
                body,
                StorageBody::Release { .. } | StorageBody::Restore(Restored::Stream(_))
            )
            .then(|| (event.id(), body))
        })
        .collect();
    // Where each stands against the chain in effect: late under any of its
    // checkpoints counts for nothing (roster.md, 3.15.7, "Work concurrent
    // with a checkpoint"); one kept of a forgotten past is in that past,
    // before everything after the kept checkpoint (units.md, 3.12, "After a
    // checkpoint").
    let facts = replica.checkpoint_facts();
    let kept_past = &replica.checkpoints.frozen;
    let kept = replica
        .checkpoints
        .kept
        .as_ref()
        .map(|kept| kept.checkpoint);
    let placement = |id: EventId| match facts.last() {
        _ if facts.late.contains(&id) => Placement::Late,
        None => Placement::Unchecked,
        Some(_) if kept_past.contains_key(&id) => Placement::Past,
        Some(c) if id == c || log.precedes(id, c) => Placement::Past,
        Some(c) => match log.follows(id, c) {
            Ok(true) => Placement::After,
            Ok(false) => Placement::Late,
            Err(_) => Placement::Pending,
        },
    };
    let precedes = |a: EventId, b: EventId| {
        log.precedes(a, b)
            || kept.is_some_and(|k| {
                kept_past.contains_key(&a)
                    && !kept_past.contains_key(&b)
                    && (b == k || log.follows(b, k) == Ok(true))
            })
    };
    let requests: Vec<Request<'_>> = requests
        .iter()
        .map(|(id, body)| Request {
            id: *id,
            body,
            placement: placement(*id),
            valid: true,
        })
        .collect();
    frasil_units::release::released(&requests, stream, precedes)
}

impl Engine {
    /// Releases a stream (peers.md, 3.18 Release and restore): signs and
    /// commits a release that names it, which goes to the space's peers as
    /// any event. Nothing is signed for a stream released already.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device writes in the space;
    /// [`Error::UnknownSpace`]; [`Error::SyncBeforeWriting`]; the store's.
    pub async fn release_stream(&self, space: EventId, stream: StreamId) -> Result<()> {
        self.write_request(space, stream, true).await
    }

    /// Restores a released stream (peers.md, 3.18 Release and restore):
    /// signs and commits a restore that names it. Nothing is signed for a
    /// stream that is not released.
    ///
    /// # Errors
    ///
    /// As [`Engine::release_stream`].
    pub async fn restore_stream(&self, space: EventId, stream: StreamId) -> Result<()> {
        self.write_request(space, stream, false).await
    }

    /// Whether a stream is released, as this device's replica holds the
    /// space.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn stream_released(&self, space: &EventId, stream: &StreamId) -> Result<bool> {
        self.read(space, |replica| released(replica, stream)).await
    }

    async fn write_request(&self, space: EventId, stream: StreamId, release: bool) -> Result<()> {
        let me = self.device_id();
        let mut state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&me) < Some(Level::Write) {
            return Err(Error::NotAllowed("releasing and restoring needs write"));
        }
        if released(replica, &stream) == release {
            return Ok(());
        }
        Self::check_may_sign(&state, &space)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let (seq, prev) = Self::next(&state, &space, &me);
        let mut parents = replica.parents(prev);
        parents.extend(prev);
        let body = if release {
            StorageBody::Release { stream }
        } else {
            StorageBody::Restore(Restored::Stream(stream))
        };
        parents.sort_unstable();
        parents.dedup();
        let cuts = replica.cuts_for(&parents)?;
        let event = frasil_events::Envelope {
            kind: kind::STORAGE,
            log: Some(space),
            ed: *self.signer().identity_key(),
            kc: *self.signer().kc(),
            seq,
            prev,
            parents,
            cuts,
            body: body.encode(),
            scheme: frasil_crypto::schemes::Scheme::Hybrid,
        };
        let signed = event.sign(self.signer());
        self.commit_own(&mut state, space, &signed, None)
            .await
            .map(drop)
    }
}
