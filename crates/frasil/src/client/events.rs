//! What changed in a device's spaces, as it happens.

use super::{SpaceId, StreamId};
use crate::device::{Engine, Notice};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::broadcast;

/// Something that happened on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Another pseudonym holds this device's administrator slot.
    SlotHeld {
        /// The space.
        space: SpaceId,
        /// The holding root or enrolment.
        holding: super::ChangeId,
        /// "another installation of this device", "another device", or "unknown".
        holder: String,
        /// Whether this device's erasure waits on the slot.
        erasure_waiting: bool,
        /// The peer that supplied keyless evidence, if any.
        peer: Option<String>,
    },
    /// The observed count of locally authored events awaiting durability changed.
    /// Rapid changes can coalesce; query `Space::pending_authored_changes`
    /// for the current value.
    PendingChanges {
        /// The space.
        space: SpaceId,
        /// The number of events awaiting the same acknowledgement as `Space::flush`.
        count: u64,
    },
    /// A space changed: this device wrote there, or it received changes
    /// from another member or a peer.
    Changed {
        /// The space.
        space: SpaceId,
        /// The streams whose content changed.
        streams: Vec<StreamId>,
        /// Whether its members or their levels may have changed.
        members: bool,
    },
    /// This device, opened as restored, has synced the space and may write
    /// there again (at-rest.md, 3.6 "After a restore"): until now each
    /// write there failed with
    /// [`Error::SyncBeforeWriting`](crate::Error::SyncBeforeWriting).
    /// Reported once per space while the device is open, and never for a
    /// space the device could already write in;
    /// [`Space::is_write_ready`](super::Space::is_write_ready) gives the
    /// current answer.
    WriteReady {
        /// The space.
        space: SpaceId,
    },
    /// This device is no longer a member of the space: it holds the event
    /// that removes it, or removes its person, and the space's roster
    /// resolves without it (roster.md, "Space events a replica cannot
    /// open"). [`Space::level`](super::Space::level) is now `None`, and
    /// [`Space::members`](super::Space::members) no longer lists it. It
    /// reads nothing written after the removal. Reported once per removal:
    /// a device admitted again, then removed again, is told again.
    Removed {
        /// The space.
        space: SpaceId,
    },
    /// A recovery agent added devices to this device's person
    /// (ext-recovery-agent.md, "Relay and veto"). Tell the person at once:
    /// unless one of their devices vetoes with [`Device::veto`], each
    /// device receives the person's spaces once their waiting period has
    /// passed.
    ///
    /// [`Device::veto`]: super::Device::veto
    #[cfg(feature = "ext-recovery-agent")]
    AgentAdded {
        /// The devices the agent added.
        devices: Vec<super::MemberId>,
    },
    /// A peer served less of a space than this device knows of
    /// (`Withheld`, units.md, 3.13 "Detected loss"): it left out units a
    /// stream's listing should name, events of a state it served before, or
    /// a member's head statement's heads that the member then supplied,
    /// when the peer had acknowledged them or still lacked them after
    /// `withholding_grace` (five minutes; units.md, 3.13 "Head
    /// statements"), not when it merely had not received them yet.
    /// The device fetches what it lacks from other replicas;
    /// [`Peer::status`](super::Peer::status) says which peer.
    Withheld {
        /// The space.
        space: SpaceId,
    },
    /// A peer, or in a space with no always-on peer the member `member`,
    /// no longer holds events it acknowledged (`RolledBack`, units.md,
    /// 3.13 "A restored peer"). This device's own events among them count
    /// as not durable again: they are back among the changes awaiting
    /// durability (an [`Event::PendingChanges`] follows), and are offered
    /// again on every connection.
    RolledBack {
        /// The space.
        space: SpaceId,
        /// The member, when a member acknowledged; `None` for a peer.
        member: Option<super::MemberId>,
    },
    /// A member's head statement named events that member could not supply
    /// when asked (`BadStatement`, units.md, 3.13 "Head statements"): the
    /// statement is dropped.
    BadStatement {
        /// The space.
        space: SpaceId,
        /// The member that made it.
        member: super::MemberId,
    },
    /// A blob failed a whole-object check while a
    /// [`BlobReader`](super::BlobReader) of it was open (units.md, 3.3
    /// Reading an object, steps 0 and 7; adapter-blobs.md, 4 Security
    /// considerations), or a chunk a reader gave came again as other
    /// bytes, so that step 0 cannot pass on what was given: bytes the
    /// reader gave may not be the blob's. Every open reader of the blob
    /// fails with `ObjectMismatch`, and what the device cached of it is
    /// dropped. So when a part of the blob arrives under another header
    /// than the one the reader gave bytes under, and nothing says which
    /// of the two is the blob's. Reported once for each refusal: when it
    /// happens, by a task of the device's ([`Options::tasks`](crate::Options::tasks)) that
    /// follows the blob for each open reader; and where the device's
    /// tasks take no such task, by the next call on a reader of the
    /// blob, or the next read of it. A chunk
    /// that does not open as it arrives is its sender's fault, and no
    /// refusal: it is not given, no reader fails, and another party is
    /// asked for it.
    #[cfg(feature = "adapter-blobs")]
    ObjectRefused {
        /// The space.
        space: SpaceId,
        /// The blob stream.
        stream: StreamId,
        /// The blob.
        blob: super::BlobId,
    },
    /// A blob's entry names another key reference or another size than
    /// the header of its object (adapter-blobs.md, 3.5 Fetching; 4
    /// Security considerations, "A wrong entry"). The header decides what
    /// is read: [`BlobReader::size`](super::BlobReader::size) is its
    /// size, and what [`Blob`](super::Blob) shows of the entry is only
    /// what its writer wrote. Reported by a
    /// [`BlobReader`](super::BlobReader), once, when a chunk has opened
    /// under the header, which binds the header's size.
    #[cfg(feature = "adapter-blobs")]
    EntryMismatch {
        /// The space.
        space: SpaceId,
        /// The blob stream.
        stream: StreamId,
        /// The blob.
        blob: super::BlobId,
    },
    /// A held blob's file changed or is gone, so this device no longer
    /// holds the blob (at-rest.md, "Held objects"): the record of it is
    /// gone, the blob stays fetchable from peers and members, and the
    /// application may put the changed file as a new blob with
    /// [`Blobs::put_from`](super::Blobs::put_from).
    ObjectWithdrawn {
        /// The space.
        space: SpaceId,
        /// The token the file was held under.
        token: Vec<u8>,
        /// The object's ID.
        object_id: [u8; 32],
    },
    /// A peer answered that it handed the space over to another peer, and
    /// every peer the device knows for the space answered that it does not
    /// host it: its home peer and its peer hints (peers.md, "Refusal
    /// codes"; ext-libraries.md, "The home peer"). Reported once, until a
    /// peer grants the space again; an [`Events`] that fell behind gives
    /// each space still reported again, so none is lost. For a library the person's account
    /// holds, ask its issuer for the library's home peer and, with the
    /// `ext-libraries` feature, give it to `Space::set_home_peer`: the
    /// device then syncs there.
    Moved {
        /// The space.
        space: SpaceId,
    },
    /// A deposit in a device mailbox, such as a welcome, a leave request or
    /// a person's list, was not accepted: the peer at `peer` answered
    /// `busy` or `rate_limited`, or was not reached (`reason` says which).
    /// The device keeps it and deposits it again by itself, after a random
    /// wait that grows to an hour, for up to 30 days (transport.md, "A
    /// sender keeps what was refused"). Reported at each attempt that
    /// fails.
    Delayed {
        /// The peer's origin.
        peer: String,
        /// The peer's reason code, or why it was not reached.
        reason: String,
    },
    /// A deposit reported [`Event::Delayed`] was accepted by the peer at
    /// `peer`.
    Delivered {
        /// The peer's origin.
        peer: String,
    },
    /// A deposit was given up: 30 days passed since its first attempt
    /// with no peer accepting it, or the peer refused it for good
    /// (`reason`, such as `too_large`).
    Undelivered {
        /// The peer's origin.
        peer: String,
        /// Why: `expired`, or the peer's reason code.
        reason: String,
    },
    /// The device stopped drawing and spending deposit tokens at the peer
    /// at `peer` (ext-deposit-tokens.md, 3.2 and 3.5): its key lists
    /// contradict one another (`key_inconsistent`), which may mean it is
    /// telling devices apart by key, or a batch's proof did not hold
    /// (`bad_proof`). Deposits there go on without tokens. For
    /// `key_inconsistent` the stop lasts until
    /// [`Device::trust_deposit_keys`](super::Device::trust_deposit_keys)
    /// clears it; a `bad_proof` drops only that batch.
    #[cfg(feature = "ext-deposit-tokens")]
    DepositPeerDistrusted {
        /// The peer's origin.
        peer: String,
        /// `key_inconsistent` or `bad_proof`.
        reason: String,
    },
    /// A unit that put new versions of blobs was refused, by the write
    /// rule or as content: a writer removed concurrently, or a snapshot
    /// whose supersessions its cover does not support (ext-file-versions.md,
    /// 3.10 A superseding unit refused). Peers still count its
    /// supersessions, so once it is stable at a peer, or past the space's
    /// erasure timeout, a peer may delete the bytes of `blobs`, which this
    /// device still shows as current: they then become unavailable. Put
    /// each again as a new blob, with no parents, while this device or a
    /// peer can still give its bytes. Reported once per unit.
    #[cfg(feature = "ext-file-versions")]
    SupersessionRefused {
        /// The space.
        space: SpaceId,
        /// The blob stream.
        stream: StreamId,
        /// The unit refused.
        unit: super::UnitId,
        /// The blobs, current at this device, whose versions it superseded.
        blobs: Vec<super::BlobId>,
    },
    /// A valid checkpoint of the space waits for votes (roster.md, 3.15.4,
    /// "Waiting for"): it takes effect once each administrator in
    /// `waiting_for` has written anything after it. Reported when it
    /// appears, and again each time whom it waits for changes;
    /// [`Space::checkpoints`](super::Space::checkpoints) gives the current
    /// answer. An administrator that will not return can be removed, or
    /// marked dormant, by another administrator.
    CheckpointPending {
        /// The space.
        space: SpaceId,
        /// The checkpoint.
        checkpoint: super::CheckpointId,
        /// The administrators it waits for.
        waiting_for: Vec<super::MemberId>,
    },
    /// A checkpoint of the space took effect: nothing before it changes any
    /// verdict again, work concurrent with it is void, and this device may
    /// forget what came before it. Reported once per checkpoint.
    CheckpointInEffect {
        /// The space.
        space: SpaceId,
        /// The checkpoint.
        checkpoint: super::CheckpointId,
    },
    /// A checkpoint of the space is void (`BadCheckpoint`): its record or
    /// its predecessor is not that of its past, or its record object does
    /// not match it. It never takes effect. Reported once per checkpoint.
    BadCheckpoint {
        /// The space.
        space: SpaceId,
        /// The checkpoint.
        checkpoint: super::CheckpointId,
    },
    /// Membership changes this device made concurrently with a checkpoint
    /// in effect are void (`Late`), and the device does not make them again
    /// by itself: the administrator decides whether to make each again.
    /// Late removals and demotions are signed again, and late edits re-sent,
    /// by the device itself. Reported each time the list changes;
    /// [`Space::late_changes`](super::Space::late_changes) gives it.
    Late {
        /// The space.
        space: SpaceId,
        /// The changes.
        changes: Vec<super::LateChange>,
    },
    /// An event of the space is void as `MixedCut`: it follows a checkpoint
    /// and cites an event that does not. Reported once per event.
    MixedCut {
        /// The space.
        space: SpaceId,
        /// The event.
        event: super::ChangeId,
    },
    /// A checkpoint of the space rivals the one this device kept when it
    /// forgot what came before it (roster.md, 3.15.6): two groups of
    /// administrators each made one at the same time. Until the device has
    /// fetched the rival's past from a member or peer that kept it, every
    /// change of the space waits; it fetches it by itself. Reported once per
    /// checkpoint.
    CheckpointRival {
        /// The space.
        space: SpaceId,
        /// The rival checkpoint.
        checkpoint: super::CheckpointId,
    },
    /// The space needs a later version of Frasil than this build: it uses a
    /// hook a later document defines, which this build does not implement
    /// (roster.md, "The space descriptor", 2.8 The checkpoint record and
    /// 3.16). Its descriptor is of a later kind, or carries a later key; a
    /// checkpoint's record carries a later key or member type, whether that
    /// checkpoint follows what this device holds, rivals the one it kept,
    /// or is the one a snapshot asked it to start from; or a roster event
    /// is of a later type. The device holds what uses it, and everything
    /// after, as `ExtensionRequired`, and signs nothing more in the space:
    /// each write there fails with
    /// [`Error::NeedsLaterVersion`](crate::Error::NeedsLaterVersion).
    /// Ask the person to update the application. Reported once per space;
    /// [`Space::needs_later_version`](super::Space::needs_later_version)
    /// gives the current answer.
    NeedsLaterVersion {
        /// The space.
        space: SpaceId,
    },
    /// A checkpoint of the space is contested for this device (roster.md,
    /// 3.15.7, "Contested checkpoints"): it hears the device, or the
    /// device's view lowers its author or an administrator it keeps by a
    /// concurrent event of a member that outranks them. The device writes
    /// nothing that builds on it. Show it as a duel, with who proposed it
    /// and the lowering events on both sides. Reported once per
    /// checkpoint.
    CheckpointWithheld {
        /// The space.
        space: SpaceId,
        /// The checkpoint.
        checkpoint: super::CheckpointId,
        /// Who proposed it.
        proposed_by: super::MemberId,
        /// The roster events of its past that lower administrators.
        theirs: Vec<super::ChangeId>,
        /// The roster events of this device's view, concurrent with it,
        /// that lower its author or an administrator its record keeps.
        ours: Vec<super::ChangeId>,
    },
    /// A checkpoint of the space was proposed by an administrator that a
    /// change concurrent with it removes (roster.md, section 4, "A
    /// backdated checkpoint"). Reported to administrators, once per
    /// checkpoint and removal.
    BackdatedCheckpoint {
        /// The space.
        space: SpaceId,
        /// The checkpoint.
        checkpoint: super::CheckpointId,
        /// The removal concurrent with it.
        removal: super::ChangeId,
    },
    /// A roster event of the space is void because its author acted on an
    /// administrator of a higher rank, or granted a rank above its own
    /// (`HigherRank`; roster.md, 2.3 Changes, "Ranks"). Not a duel: the
    /// application lists it apart. Reported once per event.
    RankAttemptRefused {
        /// The space.
        space: SpaceId,
        /// The void roster event.
        event: super::ChangeId,
        /// Its author.
        author: super::MemberId,
    },
    /// A request of this device's that a checkpoint made late, an erasure,
    /// or a release or restore of a document, was signed again after the
    /// checkpoint (peers.md, "The administrator's duties"; roster.md,
    /// 3.15.7, "Work concurrent with a checkpoint"): the late one counts for
    /// nothing. Reported once per request.
    RequestSignedAgain {
        /// The space.
        space: SpaceId,
        /// The late request.
        request: super::ChangeId,
    },
    /// A peer erased the space, though this device's view holds the
    /// erasure late under a checkpoint that kept the space: the peer
    /// carried it out before the checkpoint's cut reached it. The space is
    /// gone from that peer for good; move it to another peer, or give it
    /// up (peers.md, "The administrator's duties").
    ErasedWhileLate {
        /// The space.
        space: SpaceId,
        /// The device that asked for the erasure, when this device knows
        /// the slot its pseudonym was enrolled in.
        by: Option<super::MemberId>,
    },
    /// This device dropped a space for its own erasure, and past the bound,
    /// `erasure_timeout` at its default from the erasure's first sight,
    /// these peers have not answered `erased`: the space may live on there.
    /// The device keeps asking until each answers, or the application
    /// gives the space up ([`Device::give_up_space`](super::Device::give_up_space))
    /// (peers.md, 3.16, "A device's own erasure").
    ErasureUnanswered {
        /// The space.
        space: SpaceId,
        /// The peers, by address, that have not answered.
        peers: Vec<String>,
    },
    /// A peer served, instead of `erased`, a checkpoint that makes this
    /// device's erasure of a space it dropped late: the space lives on
    /// there. The device fetches it again, to sign the erasure again after
    /// the checkpoint or to report it void; the application may give it up
    /// instead.
    ErasureLateAtPeer {
        /// The space.
        space: SpaceId,
        /// The peer, by address.
        peer: String,
    },
    /// This peer needs a later version to follow the space's checkpoints.
    PeerNeedsVersion {
        /// The space.
        space: SpaceId,
        /// The peer address.
        peer: String,
    },
    /// A peer's late-erasure answer contradicted its signed evidence.
    PeerError {
        /// The space whose residue asked.
        space: SpaceId,
        /// The peer's address.
        peer: String,
        /// The encoded, untrusted ErasureLate message.
        answer: Vec<u8>,
    },
    /// The keyless evidence reported by a peer that still holds the space.
    ErasureCheckpoint {
        /// The space.
        space: SpaceId,
        /// The peer's address.
        peer: String,
        /// The checkpoint named by the peer.
        checkpoint: super::CheckpointId,
        /// The slot's standing in the cut (0, 1 or 2).
        standing: u8,
    },
    /// A residue has requested a welcome and retains its erasure meanwhile.
    ErasureAwaitingWelcome {
        /// The space.
        space: SpaceId,
    },
    /// The peer says the administrator slot is absent; the space lives on there.
    ErasureCannotErase {
        /// The space.
        space: SpaceId,
        /// The peer's address.
        peer: String,
    },
    /// After a checkpoint made this device's erasure late, the device no
    /// longer administers the space there: the erasure is void, and the
    /// space lives on.
    ErasureVoid {
        /// The space.
        space: SpaceId,
    },
    /// A checkpoint of this device's person's device list rivals the one
    /// this device kept when it forgot the list's earlier events
    /// (identity.md, 3.16 List checkpoints): until the device holds its
    /// past, the list's changes wait. Reported once per checkpoint.
    ListCheckpointRival {
        /// The rival list checkpoint.
        checkpoint: super::CheckpointId,
    },
    /// A checkpoint of this device's person's device list waits for votes
    /// (identity.md, 3.16 List checkpoints): it takes effect once each
    /// device in `waiting_for` has signed a list event after it. Reported
    /// when it appears, and again each time whom it waits for changes.
    ListCheckpointPending {
        /// The list checkpoint.
        checkpoint: super::CheckpointId,
        /// The devices it waits for.
        waiting_for: Vec<super::MemberId>,
    },
}

/// The spaces a device reported moved and no peer has granted since.
pub(super) type Reported = Arc<Mutex<BTreeSet<frasil_events::EventId>>>;

/// The next space no known peer hosts; pending forever once the device
/// sends no more. Once the receiver fell behind, the spaces still reported
/// come first, since the one it skipped is among them.
async fn next_moved(
    moved: &mut Option<broadcast::Receiver<frasil_events::EventId>>,
    reported: &Reported,
    again: &mut VecDeque<frasil_events::EventId>,
) -> frasil_events::EventId {
    loop {
        if let Some(space) = again.pop_front() {
            return space;
        }
        let Some(receiver) = moved.as_mut() else {
            return std::future::pending().await;
        };
        match receiver.recv().await {
            Ok(space) => return space,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                again.extend(
                    reported
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .iter()
                        .copied(),
                );
            }
            Err(broadcast::error::RecvError::Closed) => *moved = None,
        }
    }
}

/// The next report of the device's deposits; pending forever once the
/// device stopped sending them. A holder that fell behind skips the
/// oldest, as for every other event.
async fn next_report(reports: &mut Option<broadcast::Receiver<Event>>) -> Event {
    loop {
        let Some(receiver) = reports.as_mut() else {
            return std::future::pending().await;
        };
        match receiver.recv().await {
            Ok(event) => return event,
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => *reports = None,
        }
    }
}

/// The next detected loss, as an event; pending forever once the device
/// stopped sending them. A holder that fell behind skips the oldest.
async fn next_loss(losses: &mut Option<broadcast::Receiver<crate::outbox::Loss>>) -> Event {
    use crate::outbox::{Acknowledger, LossClass};
    loop {
        let Some(receiver) = losses.as_mut() else {
            return std::future::pending().await;
        };
        match receiver.recv().await {
            Ok(loss) => {
                let space = SpaceId::of(loss.space);
                let member = match loss.by {
                    Acknowledger::Member(id) => Some(super::MemberId::from_bytes(id)),
                    Acknowledger::Peer(_) => None,
                };
                return match (loss.class, member) {
                    (LossClass::Withheld, _) => Event::Withheld { space },
                    (LossClass::RolledBack, member) => Event::RolledBack { space, member },
                    (LossClass::BadStatement, Some(member)) => {
                        Event::BadStatement { space, member }
                    }
                    (LossClass::BadStatement, None) => continue,
                };
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => *losses = None,
        }
    }
}

/// The next space this device may write in again after a restore;
/// pending forever once the device stopped sending them. A holder that
/// fell behind skips the oldest.
async fn next_ready(ready: &mut Option<broadcast::Receiver<frasil_events::EventId>>) -> Event {
    loop {
        let Some(receiver) = ready.as_mut() else {
            return std::future::pending().await;
        };
        match receiver.recv().await {
            Ok(space) => {
                return Event::WriteReady {
                    space: SpaceId::of(space),
                };
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => *ready = None,
        }
    }
}

/// A device's events, from the moment they were asked for. Each holder
/// receives every event; one that falls far behind skips the oldest.
#[derive(Debug)]
pub struct Events {
    engine: Engine,
    counts: BTreeMap<frasil_events::EventId, u64>,
    queued: VecDeque<Event>,
    notices: broadcast::Receiver<Notice>,
    /// Spaces no known peer hosts any longer, while the device sends them.
    moved: Option<broadcast::Receiver<frasil_events::EventId>>,
    /// What the device's deposits report, while the device sends it.
    reports: Option<broadcast::Receiver<Event>>,
    /// Detected loss, while the device sends it.
    losses: Option<broadcast::Receiver<crate::outbox::Loss>>,
    /// Spaces the device may write in again after a restore, while the
    /// device sends them.
    ready: Option<broadcast::Receiver<frasil_events::EventId>>,
    /// The spaces the device reported moved, read once `moved` fell behind.
    reported: Reported,
    /// Those spaces, to give again.
    again: VecDeque<frasil_events::EventId>,
    /// Refused superseding units reported to this holder, and those still
    /// to give.
    #[cfg(feature = "ext-file-versions")]
    refused: (BTreeSet<frasil_events::EventId>, VecDeque<Event>),
    /// The spaces this holder reported this device removed from, until it
    /// is a member there again.
    removed: BTreeSet<frasil_events::EventId>,
    /// The checkpoint reports this holder gave.
    checkpoint_reports: Vec<Event>,
}

impl Events {
    pub(super) fn new(
        engine: Engine,
        moved: broadcast::Receiver<frasil_events::EventId>,
        reports: broadcast::Receiver<Event>,
        reported: Reported,
    ) -> Self {
        let notices = engine.subscribe();
        let losses = Some(engine.losses());
        let ready = Some(engine.write_ready());
        Self {
            losses,
            ready,
            engine,
            counts: BTreeMap::new(),
            queued: VecDeque::new(),
            notices,
            moved: Some(moved),
            reports: Some(reports),
            reported,
            again: VecDeque::new(),
            #[cfg(feature = "ext-file-versions")]
            refused: (BTreeSet::new(), VecDeque::new()),
            removed: BTreeSet::new(),
            checkpoint_reports: Vec::new(),
        }
    }

    /// The next event; `None` once the device is gone.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.queued.pop_front() {
                return Some(event);
            }
            #[cfg(feature = "ext-file-versions")]
            if let Some(event) = self.refused.1.pop_front() {
                return Some(event);
            }
            let notice = tokio::select! {
                notice = self.notices.recv() => notice,
                space = next_moved(&mut self.moved, &self.reported, &mut self.again) => {
                    return Some(Event::Moved { space: SpaceId::of(space) });
                }
                report = next_report(&mut self.reports) => return Some(report),
                loss = next_loss(&mut self.losses) => return Some(loss),
                ready = next_ready(&mut self.ready) => return Some(ready),
            };
            match notice {
                // Every notice can wake an outbox observer, including an
                // acknowledgement with no newly placed events.
                Ok(notice) => {
                    let count = self.engine.outbox(&notice.space).await.len() as u64;
                    if self.counts.insert(notice.space, count) != Some(count) {
                        self.queued.push_back(Event::PendingChanges {
                            space: SpaceId::of(notice.space),
                            count,
                        });
                    }
                    if notice.placed.is_empty() && notice.withdrawn.is_empty() {
                        continue;
                    }
                    #[cfg(feature = "ext-file-versions")]
                    self.refusals(&notice.space).await;
                    self.checkpoint_reports(&notice.space).await;
                    let event = self.event(notice).await;
                    if let Event::Changed {
                        space,
                        members: true,
                        ..
                    } = &event
                        && self.removed(space.event()).await
                    {
                        return Some(Event::Removed { space: *space });
                    }
                    return Some(event);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Whether this device has just lost its membership of the space: its
    /// view gave it a level since the replica was loaded, gives it none
    /// now, and this holder has not reported it yet. A claim that waits
    /// for consent was never a member, so it is never reported.
    async fn removed(&mut self, space: frasil_events::EventId) -> bool {
        let me = self.engine.device_id();
        let (was, is) = self
            .engine
            .read(&space, |replica| {
                (replica.was_member(), replica.level_of(&me).is_some())
            })
            .await
            .unwrap_or((false, true));
        if is {
            self.removed.remove(&space);
            return false;
        }
        was && self.removed.insert(space)
    }

    /// Queues each refused superseding unit of the space not yet reported
    /// (ext-file-versions.md, 3.10).
    #[cfg(feature = "ext-file-versions")]
    async fn refusals(&mut self, space: &frasil_events::EventId) {
        let refused = self
            .engine
            .read(space, crate::replica::Replica::refused_superseding)
            .await
            .unwrap_or_default();
        for (unit, stream, handles) in refused {
            if self.refused.0.insert(unit) {
                self.refused.1.push_back(Event::SupersessionRefused {
                    space: SpaceId::of(*space),
                    stream: StreamId::from_bytes(stream),
                    unit: super::UnitId::from_bytes(unit.0),
                    blobs: handles.into_iter().map(super::BlobId::from_bytes).collect(),
                });
            }
        }
    }

    /// Queues each checkpoint report of the space, and of the person's
    /// device list, that this holder has not given yet (roster.md, 3.15.4,
    /// "Waiting for"; 3.15.7 Clients).
    async fn checkpoint_reports(&mut self, space: &frasil_events::EventId) {
        let me = self.engine.device_id();
        let id = SpaceId::of(*space);
        let pseudonyms = self.engine.pseudonym_ids(space).await;
        let erased = self.engine.erased_at_peer(space);
        let (erasure_waiting, refetching) = {
            let state = self.engine.lock().await;
            (
                state.erasing.contains_key(space)
                    || crate::device::Engine::own_erasure(&state, space).is_some(),
                state
                    .erasing
                    .get(space)
                    .is_some_and(|residue| residue.refetching),
            )
        };
        let mut reports = self
            .engine
            .read(space, |replica| {
                let status = super::checkpoints::status_of(replica);
                let mut out = Vec::new();
                for pending in status.pending {
                    out.push(Event::CheckpointPending {
                        space: id,
                        checkpoint: pending.id,
                        waiting_for: pending.waiting_for,
                    });
                }
                if let Some(checkpoint) = status.in_effect {
                    out.push(Event::CheckpointInEffect {
                        space: id,
                        checkpoint,
                    });
                }
                // Void checkpoints, and those whose record this device
                // found to differ from its own derivation.
                for checkpoint in status.bad.into_iter().chain(status.refused) {
                    out.push(Event::BadCheckpoint {
                        space: id,
                        checkpoint,
                    });
                }
                for checkpoint in status.rivals {
                    out.push(Event::CheckpointRival {
                        space: id,
                        checkpoint,
                    });
                }
                for contested in status.contested {
                    out.push(Event::CheckpointWithheld {
                        space: id,
                        checkpoint: contested.id,
                        proposed_by: contested.proposed_by,
                        theirs: contested.theirs,
                        ours: contested.ours,
                    });
                }
                if replica.level_of(&me) == Some(frasil_space::Level::Administer) {
                    for backdated in status.backdated {
                        out.push(Event::BackdatedCheckpoint {
                            space: id,
                            checkpoint: backdated.checkpoint,
                            removal: backdated.removal,
                        });
                    }
                }
                for event in status.mixed {
                    out.push(Event::MixedCut { space: id, event });
                }
                for (event, author) in replica.rank_attempts() {
                    out.push(Event::RankAttemptRefused {
                        space: id,
                        event: super::ChangeId::from_bytes(event.0),
                        author: super::MemberId::from_bytes(author.0),
                    });
                }
                if !refetching
                    && let Some(info) = replica.slot_of(&me)
                    && let Some(enrolled) = replica.enrolled(&info.slot)
                    && !pseudonyms.contains(&enrolled)
                    && let Some((holding, bound)) = replica.slot_holder(&enrolled)
                {
                    out.push(Event::SlotHeld {
                        space: id,
                        holding: super::ChangeId::from_bytes(holding.0),
                        holder: if bound == Some(me) {
                            "another installation of this device"
                        } else {
                            "another device"
                        }
                        .into(),
                        erasure_waiting,
                        peer: None,
                    });
                }
                if replica.needs_later_version() {
                    out.push(Event::NeedsLaterVersion { space: id });
                }
                let mut mine: std::collections::BTreeSet<frasil_crypto::device::DeviceId> =
                    std::collections::BTreeSet::from([me]);
                mine.extend(pseudonyms.iter().copied());
                for (request, _, again) in super::checkpoints::late_requests(replica, &mine) {
                    if again {
                        out.push(Event::RequestSignedAgain {
                            space: id,
                            request: super::ChangeId::from_bytes(request.0),
                        });
                    }
                }
                // The late erasure, and the device that asked for it: the
                // one its pseudonym's slot belongs to.
                let late_erasure = replica.log().and_then(|log| {
                    replica.checkpoint_facts().late.iter().find_map(|late| {
                        let event = log.event(*late)?;
                        (event.kind() == frasil_events::kind::STORAGE
                            && matches!(
                                frasil_peers::body::StorageBody::read(event.unverified_body()),
                                Ok(frasil_peers::body::StorageBody::Erase)
                            ))
                        .then(|| replica.device_of_pseudonym(event.author()))
                    })
                });
                if let Some(by) = late_erasure
                    && erased
                {
                    out.push(Event::ErasedWhileLate {
                        space: id,
                        by: by.map(|device| super::MemberId::from_bytes(device.0)),
                    });
                }
                let late = super::checkpoints::late_changes_of(replica, &me);
                if !late.is_empty() {
                    out.push(Event::Late {
                        space: id,
                        changes: late,
                    });
                }
                out
            })
            .await
            .unwrap_or_default();
        for checkpoint in self.engine.list_checkpoint_status().await.rivals {
            reports.push(Event::ListCheckpointRival { checkpoint });
        }
        for (checkpoint, devices) in self.engine.list_waiting_for().await {
            reports.push(Event::ListCheckpointPending {
                checkpoint: super::CheckpointId::from_bytes(checkpoint.0),
                waiting_for: devices.into_iter().map(super::MemberId::device).collect(),
            });
        }
        for report in reports {
            if !self.checkpoint_reports.contains(&report) {
                self.checkpoint_reports.push(report.clone());
                self.queued.push_back(report);
            }
        }
    }

    async fn event(&self, notice: Notice) -> Event {
        if let Some(withdrawn) = notice.withdrawn.first() {
            return Event::ObjectWithdrawn {
                space: SpaceId::of(withdrawn.space),
                token: withdrawn.token.clone(),
                object_id: withdrawn.object_id,
            };
        }
        #[cfg(feature = "ext-recovery-agent")]
        if let Some(devices) = self.engine.raised(&notice).await {
            return Event::AgentAdded {
                devices: devices.into_iter().map(super::MemberId::device).collect(),
            };
        }
        let (streams, members) = self
            .engine
            .read(&notice.space, |replica| {
                let system = replica.system_stream();
                let mut streams = BTreeSet::new();
                let mut members = false;
                for id in &notice.placed {
                    members |= replica.is_roster(id);
                    let stream = replica.stream_of_event(id);
                    if let Some(stream) = stream.filter(|s| Some(*s) != system) {
                        streams.insert(StreamId::from_bytes(stream));
                    }
                }
                (streams.into_iter().collect(), members)
            })
            .await
            .unwrap_or_default();
        Event::Changed {
            space: SpaceId::of(notice.space),
            streams,
            members,
        }
    }
}
