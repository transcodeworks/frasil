//! The body keys a newcomer's snapshot carries, top-ups, and a newcomer
//! that starts from a checkpoint (admission.md, "The newcomer's snapshot",
//! "Top-ups"; roster.md, 3.15.6 Forgetting, and starting from a
//! checkpoint).
//!
//! A newcomer admitted from now on starts from a space snapshot (units.md's
//! format). Among what it carries are the **body keys** of every space
//! event the sender opened that the newcomer cannot open with the keys it
//! will hold: the genesis, the roster it joins, and its admitting event's
//! past ([`snapshot_body_keys`]).
//!
//! The **top-up set** of a member admitted from now on is every space event
//! sealed under a state from before its break that is not in its break's
//! past ([`top_up_set`]). Such an event stays held (`Sealed`) at the member
//! until it receives the body key. Any writer that opens an event of that
//! set whose body key the member has not received waits its rank delay
//! (keys.md's cascades, over the space's writer devices, with the event's
//! ID as the trigger: [`top_up_rank`]); if no body-keys unit carrying that
//! key has arrived by then, it writes one in the space's system stream,
//! sealed under the current state.
//!
//! With a checkpoint in effect at the base, the snapshot's keys 12 to 14
//! name it, hand its record's object key and carry its cut chain
//! ([`snapshot_checkpoint`]).

use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, Log};
use frasil_keys::body::VisiblePart;
use frasil_space::Space;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// The rotations whose keys open a space event: itself if it rotates, else
/// the state it names.
fn sealed_under(id: EventId, visible: &VisiblePart) -> Vec<EventId> {
    match visible.sealed_under() {
        Some(state) => state.ids().to_vec(),
        None => vec![id],
    }
}

/// The body key of every space event of the resolved view that the sender
/// opened and that a newcomer holding only the rotation keys `held` could
/// not open itself, by event ID.
pub fn snapshot_body_keys(
    space: &Space<'_>,
    held: &BTreeSet<EventId>,
) -> BTreeMap<EventId, Zeroizing<[u8; 32]>> {
    space
        .view()
        .iter()
        .filter_map(|&id| {
            let opened = space.opened(id)?;
            let needs = sealed_under(id, &opened.visible)
                .iter()
                .any(|rotation| !held.contains(rotation));
            needs.then(|| (id, opened.body_key.clone()))
        })
        .collect()
}

/// The top-up set of a member whose admission is the break `brk`: every
/// space event of the view, other than the break and its past, sealed under
/// a state none of whose rotations is the break or follows it.
pub fn top_up_set(space: &Space<'_>, brk: EventId) -> BTreeSet<EventId> {
    let log = space.log();
    let before = log.past(brk);
    let after_break = |rotation: EventId| rotation == brk || log.precedes(brk, rotation);
    space
        .view()
        .iter()
        .copied()
        .filter(|&id| id != brk && !before.contains(&id))
        .filter(|&id| {
            let Some(event) = log.event(id) else {
                return false;
            };
            if event.kind() != frasil_events::kind::SPACE {
                return false;
            }
            let Ok(visible) =
                VisiblePart::read(event.unverified_body(), event.author(), event.seq())
            else {
                return false;
            };
            !sealed_under(id, &visible).into_iter().any(after_break)
        })
        .collect()
}

/// The order in which the space's writer devices top up an event: keys.md's
/// rank over `writers`, by device ID, with the event's ID as the trigger. The writer at
/// position `p` waits `p` rank delays.
pub fn top_up_rank(space: &EventId, event: &EventId, writers: &[DeviceId]) -> Vec<DeviceId> {
    let writers: Vec<[u8; 32]> = writers.iter().map(|id| id.0).collect();
    frasil_space::keygraph::rank_order(&space.0, &event.0, &writers)
        .into_iter()
        .map(DeviceId)
        .collect()
}

/// The cut chain a space snapshot hands a newcomer that starts from
/// `checkpoint`, the checkpoint in effect at its base (units.md, "The space
/// snapshot", key 14): the signed envelopes of the checkpoints its cuts
/// reach, strictly ascending by event ID, read from the events the sender
/// holds and the envelopes it keeps. `None` while the sender lacks one of
/// them, or does not hold the checkpoint.
pub fn cut_chain(log: &Log, checkpoint: EventId) -> Option<Vec<Vec<u8>>> {
    log.event(checkpoint)?;
    // The reached IDs ascend, so the envelopes do.
    let reached = log.cuts_reach(checkpoint).ok()?;
    let mut chain = Vec::with_capacity(reached.len());
    for id in reached {
        let event = log.event(id).or_else(|| log.kept_envelope_of(id))?;
        chain.push(event.signed());
    }
    Some(chain)
}

/// The key a snapshot's sender hands at key 13 for a checkpoint's record
/// object: derived from the checkpoint's own content key `k_R` when the
/// sender holds it, or the object key a snapshot handed the sender.
#[derive(Debug, Clone, Copy)]
pub enum RecordKeySource<'k> {
    /// `k_R`, the checkpoint's content key: the object key is derived from
    /// it and the record object's locator.
    Content(&'k [u8; 32]),
    /// The record object's key as a snapshot handed it over.
    Object(&'k [u8; 32]),
}

/// Keys 12 to 14 of a space snapshot the sender writes (units.md, 2.11
/// The space snapshot, and 3.10, "The checkpoint"): `checkpoint`, the last
/// checkpoint in effect at the base; the object key of its record object,
/// whose locator its roster part names (`part`), from `key`; and its cut
/// chain ([`cut_chain`]). `None` while the sender lacks the envelope of a
/// checkpoint the chain needs, or does not hold the checkpoint.
pub fn snapshot_checkpoint(
    log: &Log,
    checkpoint: EventId,
    part: &frasil_space::CheckpointPart,
    key: RecordKeySource<'_>,
) -> Option<frasil_units::snapshot::SnapshotCheckpoint> {
    let record_key = match key {
        RecordKeySource::Content(content) => {
            *frasil_units::record::record_object_key(content, &part.locator)
        }
        RecordKeySource::Object(object) => *object,
    };
    Some(frasil_units::snapshot::SnapshotCheckpoint {
        checkpoint,
        record_key,
        cut_chain: cut_chain(log, checkpoint)?,
    })
}

/// The stub a newcomer that starts from a checkpoint places for a parent
/// that a peer answered `Missing` for (roster.md, 3.15.6, "Starting from a
/// checkpoint"): the peer truncated it, so it is in the checkpoint's past
/// and counts as a dropped parent. It stands for an event of no kind the
/// newcomer judges, contributes no cuts, and is height 1: in the
/// checkpoint's world a parent outside it counts for nothing (roster.md,
/// 3.15.5, "Heights").
pub fn truncated_parent(id: EventId) -> frasil_events::Stub {
    frasil_events::Stub {
        id,
        author: DeviceId([0; 32]),
        seq: 1,
        height: 1,
        kind: frasil_events::kind::ANCHOR,
        cuts: frasil_events::Cuts::NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_crypto::schemes::{Scheme, Signer};
    use frasil_events::envelope::Envelope;
    use frasil_events::{Event, kind};

    fn space_event(
        signer: &Signer,
        log: Option<EventId>,
        seq: u64,
        prev: Option<EventId>,
        cuts: &[EventId],
    ) -> Event {
        let envelope = Envelope {
            kind: kind::SPACE,
            log,
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents: prev.into_iter().collect(),
            cuts: cuts.to_vec(),
            body: format!("event {seq}").into_bytes(),
            scheme: Scheme::Hybrid,
        };
        frasil_events::decode(&envelope.sign(signer)).unwrap()
    }

    #[test]
    fn the_checkpoint_section_names_the_checkpoint_its_key_and_its_chain() {
        let signer = Signer::from_seeds(&[3; 32], &[103; 32], None);
        let genesis = space_event(&signer, None, 1, None, &[]);
        let space = genesis.id();
        let c1 = space_event(&signer, Some(space), 2, Some(space), &[]);
        let c2 = space_event(&signer, Some(space), 3, Some(c1.id()), &[c1.id()]);
        let mut log = Log::new(genesis).unwrap();
        log.place(c1.clone()).unwrap();
        let part = frasil_space::CheckpointPart {
            epoch: 2,
            digest: [5; 32],
            size: 10,
            locator: [6; frasil_units::limits::LOCATOR_BYTES],
        };
        let content = [7; 32];
        // The checkpoint itself is not held yet.
        assert_eq!(
            snapshot_checkpoint(&log, c2.id(), &part, RecordKeySource::Content(&content)),
            None
        );
        log.place(c2.clone()).unwrap();
        let section =
            snapshot_checkpoint(&log, c2.id(), &part, RecordKeySource::Content(&content)).unwrap();
        assert_eq!(section.checkpoint, c2.id());
        assert_eq!(
            section.record_key,
            *frasil_units::record::record_object_key(&content, &part.locator)
        );
        assert_eq!(section.cut_chain, vec![c1.signed()]);
        let handed = [8; 32];
        let section =
            snapshot_checkpoint(&log, c2.id(), &part, RecordKeySource::Object(&handed)).unwrap();
        assert_eq!(section.record_key, handed);
        // The first checkpoint's chain is empty.
        let first =
            snapshot_checkpoint(&log, c1.id(), &part, RecordKeySource::Object(&handed)).unwrap();
        assert!(first.cut_chain.is_empty());
    }
}
