//! Frasil's client for Swift and Kotlin, through UniFFI: a device, its
//! spaces and blob streams, and the feeds an application follows, each
//! delivered to a listener the application implements.
//!
//! IDs cross as lowercase hexadecimal, as `frasil`'s IDs show and parse.
//! A feed runs on the device's runtime until its [`Subscription`] is
//! cancelled or dropped, and calls its listener from there: a listener
//! hands each value to its own thread or actor.
//!
//! The Swift package is `bindings/swift`, the Kotlin library
//! `bindings/kotlin`; `scripts/bindings.sh` generates both from this crate.

uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

/// The runtime every call and feed runs on. Swift and Kotlin poll async
/// calls on threads of their own, with stacks too small for the device's
/// work; each call is spawned here, on threads with full-size stacks, and
/// its caller awaits the result.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name("frasil")
            .thread_stack_size(8 << 20)
            .enable_all()
            .build()
            .expect("the bindings' runtime starts")
    })
}

/// Runs `work` on [`runtime`], and waits for it.
async fn run<T: Send + 'static>(work: impl Future<Output = T> + Send + 'static) -> T {
    match runtime().spawn(work).await {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

/// A failure, with `frasil`'s description of it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum FrasilError {
    /// The call failed.
    Failed {
        /// What went wrong, and what to do.
        reason: String,
    },
}

impl core::fmt::Display for FrasilError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Failed { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for FrasilError {}

impl From<frasil::Error> for FrasilError {
    fn from(error: frasil::Error) -> Self {
        Self::Failed {
            reason: format!("{error:#}"),
        }
    }
}

type Result<T> = std::result::Result<T, FrasilError>;

fn parse<T: core::str::FromStr<Err = frasil::Error>>(text: &str) -> Result<T> {
    Ok(text.parse()?)
}

/// The 32-byte unlock key, in a buffer wiped on drop; the bytes that
/// crossed the boundary are wiped at once.
fn unlock(mut key: Vec<u8>) -> Result<Zeroizing<[u8; 32]>> {
    let unlocked = <[u8; 32]>::try_from(key.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| FrasilError::Failed {
            reason: "an unlock key is 32 bytes".into(),
        });
    key.zeroize();
    unlocked
}

/// A feed that runs until it is cancelled or dropped.
#[derive(uniffi::Object)]
pub struct Subscription {
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Subscription {
    fn spawn(runtime: &Handle, feed: impl Future<Output = ()> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            task: Mutex::new(Some(runtime.spawn(feed))),
        })
    }
}

#[uniffi::export]
impl Subscription {
    /// Stops the feed: its listener is called no more.
    pub fn cancel(&self) {
        if let Some(task) = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Follows an observed read: each value once it is ready, and each failure.
async fn follow<T: Clone + PartialEq + Send + Sync + 'static>(
    mut observed: frasil::Observed<T>,
    mut ready: impl FnMut(T) + Send,
    mut failed: impl FnMut(String) + Send,
) {
    let mut observation = observed.get();
    loop {
        match observation.status {
            frasil::Status::Ready => {
                if let Some(value) = observation.value.as_deref() {
                    ready(value.clone());
                }
            }
            frasil::Status::Failed => failed(
                observation
                    .error
                    .as_ref()
                    .map_or_else(|| "the read failed".into(), |error| format!("{error:#}")),
            ),
            _ => {}
        }
        match observed.changed().await {
            Some(next) => observation = next,
            None => return,
        }
    }
}

/// Where a blob's bytes stand on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BlobStatus {
    /// The device holds the bytes whole.
    Readable,
    /// A peer or member is sending them.
    Fetching {
        /// The bytes fetched so far, by share of the object.
        done: u64,
        /// The blob's size.
        total: u64,
    },
    /// The device does not hold them, and nothing is sending them now. A
    /// read fetches them while a peer or member is connected.
    Missing,
    /// The key they are sealed under has not reached this device yet.
    KeysPending,
    /// A held file changed or is gone; peers and members still have them.
    Withdrawn,
}

impl From<frasil::BlobStatus> for BlobStatus {
    fn from(status: frasil::BlobStatus) -> Self {
        match status {
            frasil::BlobStatus::Readable => Self::Readable,
            frasil::BlobStatus::Fetching { done, total } => Self::Fetching { done, total },
            frasil::BlobStatus::KeysPending => Self::KeysPending,
            frasil::BlobStatus::Withdrawn => Self::Withdrawn,
            _ => Self::Missing,
        }
    }
}

/// Something a device holds for the first time.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Arrival {
    /// A space: its streams follow.
    Space {
        /// The space's ID.
        space: String,
    },
    /// A stream of a space.
    Stream {
        /// The space's ID.
        space: String,
        /// The stream's ID.
        stream: String,
    },
}

/// Hears whether a space has nothing unsent.
#[uniffi::export(with_foreign)]
pub trait DurableListener: Send + Sync {
    /// `true` once every change this device made in the space is
    /// acknowledged; `false` while any waits.
    fn durable(&self, durable: bool);
    /// The read failed.
    fn failed(&self, message: String);
}

/// Hears whether this device may write in a space after a restore.
#[uniffi::export(with_foreign)]
pub trait WriteReadyListener: Send + Sync {
    /// `false` while a device opened as restored has not synced the space;
    /// `true` once it may write there.
    fn write_ready(&self, ready: bool);
    /// The read failed.
    fn failed(&self, message: String);
}

/// Hears where a blob's bytes stand.
#[uniffi::export(with_foreign)]
pub trait BlobStatusListener: Send + Sync {
    /// The blob's status, each time it changes.
    fn status(&self, status: BlobStatus);
    /// The read failed.
    fn failed(&self, message: String);
}

/// Hears how far a blob's transfer has gone.
#[uniffi::export(with_foreign)]
pub trait BlobProgressListener: Send + Sync {
    /// `bytes` done, of `total` when known. The count never goes back.
    fn progress(&self, bytes: u64, total: Option<u64>);
}

/// Hears what a device holds for the first time.
#[uniffi::export(with_foreign)]
pub trait ArrivalListener: Send + Sync {
    /// A space or a stream arrived.
    fn arrived(&self, arrival: Arrival);
}

/// What a device's deposits in device mailboxes report: welcomes, leave
/// requests and a person's list (transport.md, "A sender keeps what was
/// refused"; ext-deposit-tokens.md).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DepositReport {
    /// The peer answered `busy` or `rate_limited`, or was not reached: the
    /// device keeps the item and sends it again by itself, after a random
    /// wait that grows to an hour, for up to 30 days.
    Delayed {
        /// The peer's origin.
        peer: String,
        /// The peer's reason code, or why it was not reached.
        reason: String,
    },
    /// A delayed deposit was accepted.
    Delivered {
        /// The peer's origin.
        peer: String,
    },
    /// A deposit was given up: `expired` after 30 days, or the peer's
    /// final refusal.
    Undelivered {
        /// The peer's origin.
        peer: String,
        /// `expired`, or the peer's reason code.
        reason: String,
    },
    /// The device stopped drawing and spending deposit tokens at the peer:
    /// `key_inconsistent` until `trust_deposit_keys`, or `bad_proof`, which
    /// drops one batch. Deposits there go on without tokens.
    PeerDistrusted {
        /// The peer's origin.
        peer: String,
        /// `key_inconsistent` or `bad_proof`.
        reason: String,
    },
}

/// How many deposit tokens a device holds for a peer, and whether it
/// draws there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct DepositTokens {
    /// The unspent tokens of the peer's live keys.
    pub held: u64,
    /// The peer answered a draw `allowance_exhausted` less than 24 hours
    /// ago: no draw meanwhile.
    pub paused: bool,
    /// The peer's key lists contradicted one another: no draw or spend
    /// until `trust_deposit_keys`.
    pub distrusted: bool,
    /// A grant is held that no draw used yet.
    pub grant: bool,
}

/// Hears what a device's deposits report.
#[uniffi::export(with_foreign)]
pub trait DepositListener: Send + Sync {
    /// A deposit was delayed, delivered or given up, or a peer distrusted.
    fn reported(&self, report: DepositReport);
}

/// What a device detects of the peers and members it syncs with
/// (units.md, 3.13 "Detected loss", "Head statements").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LossReport {
    /// A peer served less of a space than this device knows of
    /// (`Withheld`): it left out units a stream's listing should name,
    /// events of a state it served before, or a member's head statement's
    /// heads that the member then supplied, when the peer had acknowledged
    /// them or still lacked them after `withholding_grace`. The device
    /// fetches what it lacks from other replicas.
    Withheld {
        /// The space's ID.
        space: String,
    },
    /// A peer, or in a space with no always-on peer the member `member`,
    /// no longer holds events it acknowledged (`RolledBack`). This
    /// device's own events among them count as not durable again, and are
    /// offered again on every connection.
    RolledBack {
        /// The space's ID.
        space: String,
        /// The member's ID, when a member acknowledged; none for a peer.
        member: Option<String>,
    },
    /// A member's head statement named events that member could not
    /// supply when asked (`BadStatement`): the statement is dropped.
    BadStatement {
        /// The space's ID.
        space: String,
        /// The ID of the member that made it.
        member: String,
    },
}

/// Hears what a device detects of its peers and members.
#[uniffi::export(with_foreign)]
pub trait LossListener: Send + Sync {
    /// A peer withheld or rolled back, or a member's statement was junk.
    fn reported(&self, report: LossReport);
}

/// What a device does about checkpoints by itself (roster.md, 3.15.7
/// Clients). Each field left out takes the default's value: proposing and
/// forgetting, at `frasil::PROPOSE_AT_ROSTER_EVENTS` roster events or
/// `frasil::PROPOSE_AT_FRAME_BYTES` bytes of frame events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointPolicy {
    /// Whether an administrator's device proposes a checkpoint by itself
    /// once the space's history since the last one reaches a threshold, and
    /// whether a device proposes one of its person's device list. With it
    /// off, the application proposes, if ever, by itself.
    #[uniffi(default = true)]
    pub propose: bool,
    /// Whether the device forgets what came before a checkpoint once it is
    /// in effect, in a space and in its person's device list.
    #[uniffi(default = true)]
    pub forget: bool,
    /// The valid roster events (or device-list events) since the last
    /// checkpoint in effect at which the device proposes the next one. 0
    /// counts as 1.
    #[uniffi(default = 1024)]
    pub roster_events: u64,
    /// The bytes of frame events since the last checkpoint in effect at
    /// which the device proposes the next one: 4 MiB by default. 0 counts
    /// as 1.
    #[uniffi(default = 4194304)]
    pub frame_bytes: u64,
}

impl From<frasil::CheckpointPolicy> for CheckpointPolicy {
    fn from(policy: frasil::CheckpointPolicy) -> Self {
        Self {
            propose: policy.propose,
            forget: policy.forget,
            roster_events: policy.roster_events,
            frame_bytes: policy.frame_bytes,
        }
    }
}

impl From<CheckpointPolicy> for frasil::CheckpointPolicy {
    fn from(policy: CheckpointPolicy) -> Self {
        Self::default()
            .proposing(policy.propose)
            .forgetting(policy.forget)
            .proposing_at(policy.roster_events, policy.frame_bytes)
    }
}

fn ids<T: ToString>(ids: &[T]) -> Vec<String> {
    ids.iter().map(ToString::to_string).collect()
}

/// A valid checkpoint of a space that waits for votes (roster.md, 3.15.4
/// Votes and effect, "Waiting for").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingCheckpoint {
    /// The checkpoint's ID.
    pub id: String,
    /// Its epoch: 1 for the space's first checkpoint.
    pub epoch: u64,
    /// The ID of the administrator that proposed it.
    pub proposed_by: String,
    /// The administrators it waits for: each must write anything after it.
    /// One that will not return can be removed by another administrator,
    /// which excuses it.
    pub waiting_for: Vec<String>,
}

/// A checkpoint whose proposer a removal concurrent with it removes
/// (roster.md, section 4, "A backdated checkpoint"): an administrator should
/// check that it is not a removed device's attempt to keep the space.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BackdatedCheckpoint {
    /// The checkpoint's ID.
    pub checkpoint: String,
    /// The ID of the administrator that proposed it.
    pub proposed_by: String,
    /// The ID of the roster event that removes that administrator.
    pub removal: String,
}

/// A space's checkpoints, as this device holds them (roster.md, 3.15
/// Checkpoints).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CheckpointStatus {
    /// The last checkpoint in effect, if any.
    pub in_effect: Option<String>,
    /// Its epoch; 0 with none.
    pub epoch: u64,
    /// The checkpoints waiting for votes.
    pub pending: Vec<PendingCheckpoint>,
    /// The checkpoint this device follows: the one in effect, or a pending
    /// one.
    pub following: Option<String>,
    /// Checkpoints void as `BadCheckpoint`: they never take effect.
    pub bad: Vec<String>,
    /// Events void as `Late`: made concurrently with the checkpoint in
    /// effect.
    pub late: Vec<String>,
    /// Events void as `MixedCut`.
    pub mixed: Vec<String>,
    /// Valid roster events since the last checkpoint in effect.
    pub roster_events_since: u64,
    /// Bytes of frame events since the last checkpoint in effect.
    pub frame_bytes_since: u64,
    /// Whether this device forgot what came before the checkpoint in
    /// effect.
    pub forgot: bool,
    /// Pending checkpoints whose record differs from the one this device
    /// derives from their past: it never votes for them.
    pub refused: Vec<String>,
    /// Pending checkpoints whose record this device cannot check yet: it
    /// votes once it has checked it.
    pub checking: Vec<String>,
    /// Checkpoints that drop this device as an administrator while its own
    /// view says it still is one: it writes nothing that builds on them.
    pub withheld: Vec<String>,
    /// Checkpoints that rival the one this device kept when it forgot:
    /// until it has fetched their past, every change of the space waits.
    pub rivals: Vec<String>,
    /// Checkpoints whose proposer a removal concurrent with them removes.
    pub backdated: Vec<BackdatedCheckpoint>,
}

impl From<frasil::CheckpointStatus> for CheckpointStatus {
    fn from(status: frasil::CheckpointStatus) -> Self {
        Self {
            in_effect: status.in_effect.map(|id| id.to_string()),
            epoch: status.epoch,
            pending: status
                .pending
                .iter()
                .map(|pending| PendingCheckpoint {
                    id: pending.id.to_string(),
                    epoch: pending.epoch,
                    proposed_by: pending.proposed_by.to_string(),
                    waiting_for: ids(&pending.waiting_for),
                })
                .collect(),
            following: status.following.map(|id| id.to_string()),
            bad: ids(&status.bad),
            late: ids(&status.late),
            mixed: ids(&status.mixed),
            roster_events_since: status.roster_events_since,
            frame_bytes_since: status.frame_bytes_since,
            forgot: status.forgot,
            refused: ids(&status.refused),
            checking: ids(&status.checking),
            withheld: ids(&status.withheld),
            rivals: ids(&status.rivals),
            backdated: status
                .backdated
                .iter()
                .map(|backdated| BackdatedCheckpoint {
                    checkpoint: backdated.checkpoint.to_string(),
                    proposed_by: backdated.proposed_by.to_string(),
                    removal: backdated.removal.to_string(),
                })
                .collect(),
        }
    }
}

/// What a late membership change did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LateChangeKind {
    /// It admitted a member.
    Grant,
    /// It changed a member's level or capabilities.
    Change,
    /// It removed a member.
    Remove,
    /// Another change.
    Other,
}

/// A membership change of this device that a checkpoint made late, and that
/// the device does not make again by itself: the administrator decides
/// whether to make it again (roster.md, 3.15.7, "Work concurrent with a
/// checkpoint").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LateChange {
    /// The late roster event's ID.
    pub event: String,
    /// The ID of the member it named, if any.
    pub member: Option<String>,
    /// What it did.
    pub kind: LateChangeKind,
    /// The level it set, if any: `read`, `write` or `administer`.
    pub level: Option<String>,
}

impl From<&frasil::LateChange> for LateChange {
    fn from(change: &frasil::LateChange) -> Self {
        Self {
            event: change.event.to_string(),
            member: change.member.map(|member| member.to_string()),
            kind: match change.kind {
                frasil::LateChangeKind::Grant => LateChangeKind::Grant,
                frasil::LateChangeKind::Change => LateChangeKind::Change,
                frasil::LateChangeKind::Remove => LateChangeKind::Remove,
                _ => LateChangeKind::Other,
            },
            level: change.level.map(|level| level.name().to_owned()),
        }
    }
}

fn late_changes(changes: &[frasil::LateChange]) -> Vec<LateChange> {
    changes.iter().map(LateChange::from).collect()
}

/// A checkpoint of this device's person's device list that waits for votes
/// (identity.md, 3.16 List checkpoints).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingListCheckpoint {
    /// The list checkpoint's ID.
    pub id: String,
    /// The person's devices it waits for: each must sign a list event after
    /// it. One that will not return can be removed from the list.
    pub waiting_for: Vec<String>,
}

/// The checkpoints of this device's person's device list, as this device
/// holds them (identity.md, 3.16 List checkpoints).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ListCheckpointStatus {
    /// The list checkpoint in effect, if any.
    pub in_effect: Option<String>,
    /// The list checkpoints waiting for votes.
    pub pending: Vec<PendingListCheckpoint>,
    /// Whether this device forgot the list events before the checkpoint in
    /// effect.
    pub forgot: bool,
    /// List checkpoints that rival the one this device kept: until it holds
    /// their past, the list's changes wait.
    pub rivals: Vec<String>,
}

impl From<frasil::ListCheckpointStatus> for ListCheckpointStatus {
    fn from(status: frasil::ListCheckpointStatus) -> Self {
        Self {
            in_effect: status.in_effect.map(|id| id.to_string()),
            pending: status
                .pending
                .iter()
                .map(|pending| PendingListCheckpoint {
                    id: pending.id.to_string(),
                    waiting_for: ids(&pending.waiting_for),
                })
                .collect(),
            forgot: status.forgot,
            rivals: ids(&status.rivals),
        }
    }
}

/// A member of a space, as this device's view has it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Member {
    /// Its ID.
    pub id: String,
    /// What it is: `device`, `person` or `space`.
    pub kind: String,
    /// Its level: `read`, `write` or `administer`.
    pub level: String,
    /// The name it was admitted with, if any: shown, never checked.
    pub name: Option<String>,
    /// Its rank, 0 to 255, while it administers.
    pub rank: Option<u8>,
    /// Whether it administers marked dormant, as a recovery member is.
    pub dormant: bool,
}

/// What a device reports of the checkpoints of its spaces and of its
/// person's device list (roster.md, 3.15 Checkpoints; identity.md, 3.16
/// List checkpoints).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum CheckpointReport {
    /// A valid checkpoint of the space waits for votes: it takes effect once
    /// each administrator in `waiting_for` has written anything after it.
    /// Reported when it appears, and again each time whom it waits for
    /// changes.
    Pending {
        /// The space's ID.
        space: String,
        /// The checkpoint's ID.
        checkpoint: String,
        /// The IDs of the administrators it waits for.
        waiting_for: Vec<String>,
    },
    /// A checkpoint of the space took effect: work concurrent with it is
    /// void, and this device may forget what came before it.
    InEffect {
        /// The space's ID.
        space: String,
        /// The checkpoint's ID.
        checkpoint: String,
    },
    /// A checkpoint of the space is void (`BadCheckpoint`): it never takes
    /// effect.
    Bad {
        /// The space's ID.
        space: String,
        /// The checkpoint's ID.
        checkpoint: String,
    },
    /// Membership changes this device made concurrently with a checkpoint
    /// in effect are void (`Late`), and the device does not make them again
    /// by itself: the administrator decides whether to make each again.
    Late {
        /// The space's ID.
        space: String,
        /// The changes.
        changes: Vec<LateChange>,
    },
    /// An event of the space is void as `MixedCut`: it follows a checkpoint
    /// and cites an event that does not.
    MixedCut {
        /// The space's ID.
        space: String,
        /// The event's ID.
        event: String,
    },
    /// A checkpoint of the space rivals the one this device kept when it
    /// forgot what came before it: until the device has fetched the rival's
    /// past, which it does by itself, every change of the space waits.
    Rival {
        /// The space's ID.
        space: String,
        /// The rival checkpoint's ID.
        checkpoint: String,
    },
    /// A checkpoint of the space is contested for this device: it hears
    /// the device, or the device's view lowers its author or an
    /// administrator it keeps by a concurrent event of a member that
    /// outranks them. The device writes nothing that builds on it. Show it
    /// as a duel.
    Withheld {
        /// The space's ID.
        space: String,
        /// The checkpoint's ID.
        checkpoint: String,
        /// Who proposed it.
        proposed_by: String,
        /// The roster events of its past that lower administrators.
        theirs: Vec<String>,
        /// The roster events of this device's view, concurrent with it,
        /// that lower its author or an administrator it keeps.
        ours: Vec<String>,
    },
    /// A checkpoint of the space was proposed by an administrator that a
    /// removal concurrent with it removes.
    Backdated {
        /// The space's ID.
        space: String,
        /// The checkpoint's ID.
        checkpoint: String,
        /// The removal's ID.
        removal: String,
    },
    /// A roster event of the space is void because its author acted on an
    /// administrator of a higher rank, or granted a rank above its own
    /// (`HigherRank`). Not a duel: list it apart.
    RankAttemptRefused {
        /// The space's ID.
        space: String,
        /// The void roster event's ID.
        event: String,
        /// Its author's ID.
        author: String,
    },
    /// The space needs a later version of this application: a descriptor,
    /// a checkpoint record or a roster event of a later document's type.
    /// The device holds what uses it, and everything after, and signs
    /// nothing more in the space; each write there fails. Ask the person to
    /// update the application. Reported once per space.
    NeedsLaterVersion {
        /// The space's ID.
        space: String,
    },
    /// A request of this device's that a checkpoint made late (an erasure,
    /// or a release or restore of a document) was signed again after the
    /// checkpoint: the late one counts for nothing. Reported once per
    /// request.
    RequestSignedAgain {
        /// The space's ID.
        space: String,
        /// The late request's ID.
        request: String,
    },
    /// A peer erased the space, though this device's view holds the
    /// erasure late under a checkpoint that kept the space. The space is
    /// gone from that peer for good: move it to another peer, or give it
    /// up.
    ErasedWhileLate {
        /// The space's ID.
        space: String,
        /// The device that asked for the erasure, when known.
        by: Option<String>,
    },
    /// This device dropped the space for its own erasure, and past the
    /// bound these peers have not answered `erased`: the space may live on
    /// there. The device keeps asking until each answers, or the
    /// application gives the space up.
    ErasureUnanswered {
        /// The space's ID.
        space: String,
        /// The peers, by address, that have not answered.
        peers: Vec<String>,
    },
    /// A peer served a checkpoint that makes this device's erasure late:
    /// the space lives on there; the device fetches it again.
    ErasureLateAtPeer {
        /// The space's ID.
        space: String,
        /// The peer, by address.
        peer: String,
    },
    /// This peer needs a later version to follow the space checkpoints.
    PeerNeedsVersion {
        /// The space ID.
        space: String,
        /// The peer address.
        peer: String,
    },
    /// A peer contradicted its signed late-erasure evidence.
    PeerError {
        /// The space ID.
        space: String,
        /// The peer's address.
        peer: String,
        /// The encoded untrusted answer.
        answer: Vec<u8>,
    },
    /// Keyless evidence from a peer that still holds the space.
    ErasureCheckpoint {
        /// The space ID.
        space: String,
        /// The peer's address.
        peer: String,
        /// The checkpoint ID.
        checkpoint: String,
        /// The slot standing (0, 1 or 2).
        standing: u8,
    },
    /// The device waits for a member's welcome.
    ErasureAwaitingWelcome {
        /// The space ID.
        space: String,
    },
    /// The peer says the device can no longer erase the space.
    ErasureCannotErase {
        /// The space ID.
        space: String,
        /// The peer's address.
        peer: String,
    },
    /// Another pseudonym holds this device's administrator slot.
    SlotHeld {
        /// The space ID.
        space: String,
        /// The holding root or enrolment.
        holding: String,
        /// The holder description.
        holder: String,
        /// Whether an erasure waits on it.
        erasure_waiting: bool,
        /// The peer supplying keyless evidence, if any.
        peer: Option<String>,
    },
    /// The erasure is void.
    ErasureVoid {
        /// The space's ID.
        space: String,
    },
    /// A checkpoint of this device's person's device list waits for votes:
    /// it takes effect once each device in `waiting_for` has signed a list
    /// event after it.
    ListPending {
        /// The list checkpoint's ID.
        checkpoint: String,
        /// The IDs of the devices it waits for.
        waiting_for: Vec<String>,
    },
    /// A checkpoint of this device's person's device list rivals the one
    /// this device kept when it forgot the list's earlier events: until the
    /// device holds its past, the list's changes wait.
    ListRival {
        /// The rival list checkpoint's ID.
        checkpoint: String,
    },
}

impl CheckpointReport {
    /// The report of a device event, if it is one of checkpoints.
    fn of(event: frasil::Event) -> Option<Self> {
        Some(match event {
            frasil::Event::CheckpointPending {
                space,
                checkpoint,
                waiting_for,
            } => Self::Pending {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
                waiting_for: ids(&waiting_for),
            },
            frasil::Event::CheckpointInEffect { space, checkpoint } => Self::InEffect {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
            },
            frasil::Event::BadCheckpoint { space, checkpoint } => Self::Bad {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
            },
            frasil::Event::Late { space, changes } => Self::Late {
                space: space.to_string(),
                changes: late_changes(&changes),
            },
            frasil::Event::MixedCut { space, event } => Self::MixedCut {
                space: space.to_string(),
                event: event.to_string(),
            },
            frasil::Event::CheckpointRival { space, checkpoint } => Self::Rival {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
            },
            frasil::Event::CheckpointWithheld {
                space,
                checkpoint,
                proposed_by,
                theirs,
                ours,
            } => Self::Withheld {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
                proposed_by: proposed_by.to_string(),
                theirs: ids(&theirs),
                ours: ids(&ours),
            },
            frasil::Event::BackdatedCheckpoint {
                space,
                checkpoint,
                removal,
            } => Self::Backdated {
                space: space.to_string(),
                checkpoint: checkpoint.to_string(),
                removal: removal.to_string(),
            },
            frasil::Event::ListCheckpointPending {
                checkpoint,
                waiting_for,
            } => Self::ListPending {
                checkpoint: checkpoint.to_string(),
                waiting_for: ids(&waiting_for),
            },
            frasil::Event::ListCheckpointRival { checkpoint } => Self::ListRival {
                checkpoint: checkpoint.to_string(),
            },
            frasil::Event::RankAttemptRefused {
                space,
                event,
                author,
            } => Self::RankAttemptRefused {
                space: space.to_string(),
                event: event.to_string(),
                author: author.to_string(),
            },
            frasil::Event::NeedsLaterVersion { space } => Self::NeedsLaterVersion {
                space: space.to_string(),
            },
            frasil::Event::RequestSignedAgain { space, request } => Self::RequestSignedAgain {
                space: space.to_string(),
                request: request.to_string(),
            },
            frasil::Event::ErasedWhileLate { space, by } => Self::ErasedWhileLate {
                space: space.to_string(),
                by: by.map(|by| by.to_string()),
            },
            frasil::Event::ErasureUnanswered { space, peers } => Self::ErasureUnanswered {
                space: space.to_string(),
                peers,
            },
            frasil::Event::ErasureLateAtPeer { space, peer } => Self::ErasureLateAtPeer {
                space: space.to_string(),
                peer,
            },
            frasil::Event::PeerNeedsVersion { space, peer } => Self::PeerNeedsVersion {
                space: space.to_string(),
                peer,
            },
            frasil::Event::PeerError {
                space,
                peer,
                answer,
            } => Self::PeerError {
                space: space.to_string(),
                peer,
                answer,
            },
            frasil::Event::ErasureCheckpoint {
                space,
                peer,
                checkpoint,
                standing,
            } => Self::ErasureCheckpoint {
                space: space.to_string(),
                peer,
                checkpoint: checkpoint.to_string(),
                standing,
            },
            frasil::Event::ErasureAwaitingWelcome { space } => Self::ErasureAwaitingWelcome {
                space: space.to_string(),
            },
            frasil::Event::ErasureCannotErase { space, peer } => Self::ErasureCannotErase {
                space: space.to_string(),
                peer,
            },
            frasil::Event::SlotHeld {
                space,
                holding,
                holder,
                erasure_waiting,
                peer,
            } => Self::SlotHeld {
                space: space.to_string(),
                holding: holding.to_string(),
                holder,
                erasure_waiting,
                peer,
            },
            frasil::Event::ErasureVoid { space } => Self::ErasureVoid {
                space: space.to_string(),
            },
            _ => return None,
        })
    }
}

/// Hears what a device reports of checkpoints.
#[uniffi::export(with_foreign)]
pub trait CheckpointListener: Send + Sync {
    /// A checkpoint waits for votes, took effect, or needs the application's
    /// attention.
    fn reported(&self, report: CheckpointReport);
}

/// A device: its keys, its store and its connections.
#[derive(uniffi::Object)]
pub struct Device {
    inner: frasil::Device,
    runtime: Handle,
}

#[uniffi::export(async_runtime = "tokio")]
impl Device {
    /// Opens the device whose store is the directory `path`, creating it on
    /// first use, under its 32-byte unlock key.
    #[uniffi::constructor]
    pub async fn open(path: String, unlock_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = unlock(unlock_key)?;
        let inner =
            run(async move { frasil::Device::open(frasil::Storage::directory(path), &key).await })
                .await?;
        Ok(Self::of(inner))
    }

    /// Opens a device that keeps everything in memory, for tests and
    /// devices that keep nothing.
    #[uniffi::constructor]
    pub async fn open_in_memory(unlock_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = unlock(unlock_key)?;
        let inner =
            run(async move { frasil::Device::open(frasil::Storage::Memory, &key).await }).await?;
        Ok(Self::of(inner))
    }

    /// The device's ID, as 64 hex digits: the hash of its Ed25519 key and
    /// the commitment to its other keys, by which spaces name it. Show and
    /// compare devices by it.
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Connects to the always-on peer at `url`.
    pub async fn connect(&self, url: String) -> Result<()> {
        let device = self.inner.clone();
        run(async move { device.connect(&url).await.map(drop) }).await?;
        Ok(())
    }

    /// Creates a space this device administers.
    pub async fn create_space(&self) -> Result<Arc<Space>> {
        let device = self.inner.clone();
        let space = run(async move { device.create_space().await }).await?;
        Ok(self.space_of(space))
    }

    /// A space this device holds, by its ID.
    pub async fn space(&self, id: String) -> Result<Arc<Space>> {
        let id = parse(&id)?;
        let device = self.inner.clone();
        let space = run(async move { device.space(id).await }).await?;
        Ok(self.space_of(space))
    }

    /// Asks connected peers again about a retained erasure.
    pub async fn retry_erasure(&self, id: String) -> Result<()> {
        let id = parse(&id)?;
        let device = self.inner.clone();
        Ok(run(async move { device.retry_erasure(id).await }).await?)
    }

    /// Gives up a space this device dropped for its own erasure: it no
    /// longer waits for each peer to answer `erased`, and forgets what it
    /// kept of the space, which may live on at the peers that did not
    /// answer.
    pub async fn give_up_space(&self, id: String) -> Result<()> {
        let id = parse(&id)?;
        let device = self.inner.clone();
        Ok(run(async move { device.give_up_space(id).await }).await?)
    }

    /// The IDs of the spaces this device holds.
    pub async fn spaces(&self) -> Vec<String> {
        let device = self.inner.clone();
        run(async move {
            device
                .spaces()
                .await
                .iter()
                .map(|space| space.id().to_string())
                .collect()
        })
        .await
    }

    /// Follows each space and stream this device holds for the first time,
    /// from now on.
    pub async fn arrivals(&self, listener: Arc<dyn ArrivalListener>) -> Arc<Subscription> {
        let device = self.inner.clone();
        let mut arrivals = run(async move { device.arrivals().await }).await;
        Subscription::spawn(&self.runtime, async move {
            while let Some(arrival) = arrivals.next().await {
                listener.arrived(match arrival {
                    frasil::Arrival::Space(space) => Arrival::Space {
                        space: space.to_string(),
                    },
                    frasil::Arrival::Stream { space, stream } => Arrival::Stream {
                        space: space.to_string(),
                        stream: stream.to_string(),
                    },
                    _ => continue,
                });
            }
        })
    }

    /// Hands the device a deposit grant for the peer at `peer`, the bytes
    /// the library's issuer gave the application (ext-deposit-tokens.md,
    /// 3.1.1). The device never reads, stores or shows it: within the hour,
    /// at a random moment, it draws one batch of tokens with it there,
    /// unless it holds enough already, then forgets it.
    pub fn give_deposit_grant(&self, peer: String, grant: Vec<u8>) {
        self.inner.give_deposit_grant(&peer, grant);
    }

    /// How many deposit tokens the device holds for the peer at `peer`,
    /// and whether it draws there.
    pub async fn deposit_tokens(&self, peer: String) -> DepositTokens {
        let device = self.inner.clone();
        let tokens = run(async move { device.deposit_tokens(&peer).await }).await;
        DepositTokens {
            held: tokens.held as u64,
            paused: tokens.paused,
            distrusted: tokens.distrusted,
            grant: tokens.grant,
        }
    }

    /// Trusts the deposit keys of the peer at `peer` again after a
    /// `PeerDistrusted` report with `key_inconsistent`: the device learns
    /// them anew. Call it only when a person decided so.
    pub async fn trust_deposit_keys(&self, peer: String) -> Result<()> {
        let device = self.inner.clone();
        run(async move { device.trust_deposit_keys(&peer).await }).await?;
        Ok(())
    }

    /// How many deposits in device mailboxes the device keeps to send
    /// again.
    pub async fn waiting_deposits(&self) -> u64 {
        let device = self.inner.clone();
        run(async move { device.waiting_deposits().await as u64 }).await
    }

    /// Follows what the device's deposits report, from now on.
    pub fn deposit_reports(&self, listener: Arc<dyn DepositListener>) -> Arc<Subscription> {
        let mut events = self.inner.events();
        Subscription::spawn(&self.runtime, async move {
            while let Some(event) = events.next().await {
                listener.reported(match event {
                    frasil::Event::Delayed { peer, reason } => {
                        DepositReport::Delayed { peer, reason }
                    }
                    frasil::Event::Delivered { peer } => DepositReport::Delivered { peer },
                    frasil::Event::Undelivered { peer, reason } => {
                        DepositReport::Undelivered { peer, reason }
                    }
                    frasil::Event::DepositPeerDistrusted { peer, reason } => {
                        DepositReport::PeerDistrusted { peer, reason }
                    }
                    _ => continue,
                });
            }
        })
    }

    /// Follows what the device detects of its peers and members, from now
    /// on.
    pub fn loss_reports(&self, listener: Arc<dyn LossListener>) -> Arc<Subscription> {
        let mut events = self.inner.events();
        Subscription::spawn(&self.runtime, async move {
            while let Some(event) = events.next().await {
                listener.reported(match event {
                    frasil::Event::Withheld { space } => LossReport::Withheld {
                        space: space.to_string(),
                    },
                    frasil::Event::RolledBack { space, member } => LossReport::RolledBack {
                        space: space.to_string(),
                        member: member.map(|member| member.to_string()),
                    },
                    frasil::Event::BadStatement { space, member } => LossReport::BadStatement {
                        space: space.to_string(),
                        member: member.to_string(),
                    },
                    _ => continue,
                });
            }
        })
    }

    /// Follows what the device reports of the checkpoints of its spaces and
    /// of its person's device list, from now on.
    pub fn checkpoint_reports(&self, listener: Arc<dyn CheckpointListener>) -> Arc<Subscription> {
        let mut events = self.inner.events();
        Subscription::spawn(&self.runtime, async move {
            while let Some(event) = events.next().await {
                if let Some(report) = CheckpointReport::of(event) {
                    listener.reported(report);
                }
            }
        })
    }

    /// Sets what the device does about checkpoints by itself: whether it
    /// proposes them when a space's history, or its person's device list,
    /// calls for one, and whether it forgets what came before one in
    /// effect.
    pub fn set_checkpoint_policy(&self, policy: CheckpointPolicy) {
        self.inner.set_checkpoint_policy(policy.into());
    }

    /// The device's checkpoint policy.
    pub fn checkpoint_policy(&self) -> CheckpointPolicy {
        self.inner.engine().checkpoint_policy().into()
    }

    /// Proposes a checkpoint of this device's person's device list now
    /// (identity.md, 3.16 List checkpoints); returns its ID.
    pub async fn propose_list_checkpoint(&self) -> Result<String> {
        let device = self.inner.clone();
        let id = run(async move { device.propose_list_checkpoint().await }).await?;
        Ok(id.to_string())
    }

    /// The checkpoints of this device's person's device list: the one in
    /// effect, those waiting for votes with whom each waits for, and
    /// whether the device forgot the list's earlier events. None for a
    /// device of no person.
    pub async fn list_checkpoints(&self) -> ListCheckpointStatus {
        let device = self.inner.clone();
        run(async move { device.list_checkpoints().await })
            .await
            .into()
    }

    /// Pauses the sync of these spaces with always-on peers, such as every
    /// space of one library: no store and no fetch until resumed.
    pub fn pause_sync(&self, spaces: Vec<String>) -> Result<()> {
        let ids = spaces
            .iter()
            .map(|space| parse(space))
            .collect::<Result<Vec<_>>>()?;
        self.inner.pause_sync(ids);
        Ok(())
    }

    /// Resumes the sync of these spaces with always-on peers: each catches
    /// up.
    pub fn resume_sync(&self, spaces: Vec<String>) -> Result<()> {
        let ids = spaces
            .iter()
            .map(|space| parse(space))
            .collect::<Result<Vec<_>>>()?;
        self.inner.resume_sync(ids);
        Ok(())
    }

    /// Closes the device: its upkeep and connections stop. (Named so that
    /// it does not meet the generated objects' own `close`, which frees
    /// the handle.)
    pub async fn shutdown(&self) -> Result<()> {
        let device = self.inner.clone();
        run(async move { device.close().await }).await?;
        Ok(())
    }
}

impl Device {
    fn of(inner: frasil::Device) -> Arc<Self> {
        Arc::new(Self {
            inner,
            runtime: runtime().handle().clone(),
        })
    }

    fn space_of(&self, inner: frasil::Space) -> Arc<Space> {
        Arc::new(Space {
            inner,
            runtime: self.runtime.clone(),
        })
    }
}

/// A space this device holds.
#[derive(uniffi::Object)]
pub struct Space {
    inner: frasil::Space,
    runtime: Handle,
}

#[uniffi::export(async_runtime = "tokio")]
impl Space {
    /// The space's ID.
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Whether this device keeps nothing of the space at rest: a guest
    /// admitted with nothing at rest keeps the space's keys, events,
    /// objects and snapshot in memory only, and forgets them when the
    /// session ends, the device is removed or leaves, or the application
    /// closes the device (ext-guests.md, "Nothing at rest"). The
    /// application then keeps no copy of the space's content in its own
    /// files or caches either.
    pub async fn keeps_nothing_at_rest(&self) -> bool {
        let space = self.inner.clone();
        run(async move { space.keeps_nothing_at_rest().await }).await
    }

    /// Whether every change this device made in the space is durable.
    pub async fn is_durable(&self) -> bool {
        let space = self.inner.clone();
        run(async move { space.is_durable().await }).await
    }

    /// Waits at most `within_ms` milliseconds until every change this
    /// device made in the space is durable.
    pub async fn wait_durable(&self, within_ms: u64) -> Result<()> {
        let space = self.inner.clone();
        let within = std::time::Duration::from_millis(within_ms);
        run(async move { space.wait_durable(within).await }).await?;
        Ok(())
    }

    /// Follows whether the space has nothing unsent: the current value,
    /// then each change.
    pub fn observe_durable(&self, listener: Arc<dyn DurableListener>) -> Arc<Subscription> {
        let observed = self.inner.observe_durable();
        let failing = listener.clone();
        Subscription::spawn(
            &self.runtime,
            follow(
                observed,
                move |durable| listener.durable(durable),
                move |message| failing.failed(message),
            ),
        )
    }

    /// Whether this device may write in the space as far as a restore
    /// goes: `false` only while a device opened as restored has not synced
    /// the space; each write until then fails with `SyncBeforeWriting`.
    pub async fn is_write_ready(&self) -> bool {
        let space = self.inner.clone();
        run(async move { space.is_write_ready().await }).await
    }

    /// Waits at most `within_ms` milliseconds until this device may write
    /// in the space, and returns at once when it already may; fails with
    /// `SyncBeforeWriting` when it has not synced the space by then.
    pub async fn wait_write_ready(&self, within_ms: u64) -> Result<()> {
        let space = self.inner.clone();
        let within = std::time::Duration::from_millis(within_ms);
        run(async move { space.wait_write_ready(within).await }).await?;
        Ok(())
    }

    /// Follows whether this device may write in the space after a restore:
    /// the current value, then its change, at most once while the device is
    /// open.
    pub fn observe_write_ready(&self, listener: Arc<dyn WriteReadyListener>) -> Arc<Subscription> {
        let observed = self.inner.observe_write_ready();
        let failing = listener.clone();
        Subscription::spawn(
            &self.runtime,
            follow(
                observed,
                move |ready| listener.write_ready(ready),
                move |message| failing.failed(message),
            ),
        )
    }

    /// The space's checkpoints as this device holds them: the one in
    /// effect, those waiting for votes with whom each waits for, and the
    /// verdicts checkpoints gave (roster.md, 3.15 Checkpoints).
    pub async fn checkpoints(&self) -> Result<CheckpointStatus> {
        let space = self.inner.clone();
        Ok(run(async move { space.checkpoints().await }).await?.into())
    }

    /// Proposes a checkpoint of the space now, whatever the device's
    /// checkpoint policy: once every administrator has written anything
    /// after it, it takes effect. Returns its ID. Fails unless this device
    /// administers the space, and while a checkpoint waits for votes.
    pub async fn propose_checkpoint(&self) -> Result<String> {
        let space = self.inner.clone();
        let id = run(async move { space.propose_checkpoint().await }).await?;
        Ok(id.to_string())
    }

    /// This device's membership changes that a checkpoint made late and
    /// that it does not make again by itself: grants and raised levels,
    /// which the administrator decides whether to make again.
    pub async fn late_changes(&self) -> Result<Vec<LateChange>> {
        let space = self.inner.clone();
        let changes = run(async move { space.late_changes().await }).await?;
        Ok(late_changes(&changes))
    }

    /// Raises a device member to administer at `rank`, 0 to 255, at most
    /// this device's own: a larger rank outranks a smaller one, and nobody
    /// changes or removes an administrator of a higher rank.
    pub async fn raise(&self, member: String, rank: u8) -> Result<()> {
        let member: frasil::MemberId = parse(&member)?;
        let space = self.inner.clone();
        Ok(run(async move { space.raise(member, rank).await }).await?)
    }

    /// Changes an administrator's rank: a lowering to write, then a raise
    /// at `rank`.
    pub async fn set_rank(&self, member: String, rank: u8) -> Result<()> {
        let member: frasil::MemberId = parse(&member)?;
        let space = self.inner.clone();
        Ok(run(async move { space.set_rank(member, rank).await }).await?)
    }

    /// Makes a device member the space's recovery member: an administrator
    /// at the top rank marked dormant, so that checkpoints do not wait for
    /// it and it can excuse and remove any member. Only a device at the top
    /// rank makes one.
    pub async fn make_recovery_member(&self, member: String) -> Result<()> {
        let member: frasil::MemberId = parse(&member)?;
        let space = self.inner.clone();
        Ok(run(async move { space.make_recovery_member(member).await }).await?)
    }

    /// Marks an administrator dormant, or no longer: a checkpoint does not
    /// wait for a dormant administrator.
    pub async fn set_dormant(&self, member: String, dormant: bool) -> Result<()> {
        let member: frasil::MemberId = parse(&member)?;
        let space = self.inner.clone();
        Ok(run(async move { space.set_dormant(member, dormant).await }).await?)
    }

    /// The IDs of the space's recovery members.
    pub async fn recovery_members(&self) -> Result<Vec<String>> {
        let space = self.inner.clone();
        let members = run(async move { space.recovery_members().await }).await?;
        Ok(members.iter().map(ToString::to_string).collect())
    }

    /// The space's members, as this device's view has them.
    pub async fn members(&self) -> Result<Vec<Member>> {
        let space = self.inner.clone();
        let members = run(async move { space.members().await }).await?;
        Ok(members
            .into_iter()
            .map(|member| Member {
                id: member.id.to_string(),
                kind: match member.kind {
                    frasil::MemberKind::Device => "device",
                    frasil::MemberKind::Person => "person",
                    _ => "space",
                }
                .to_owned(),
                level: member.level.name().to_owned(),
                name: member.name,
                rank: member.rank,
                dormant: member.dormant,
            })
            .collect())
    }

    /// A member's rank while it administers.
    pub async fn rank(&self, member: String) -> Result<Option<u8>> {
        let member: frasil::MemberId = parse(&member)?;
        let space = self.inner.clone();
        Ok(run(async move { space.rank(member).await }).await?)
    }

    /// This device's rank while it administers; the space's creator holds
    /// 255.
    pub async fn my_rank(&self) -> Result<Option<u8>> {
        let space = self.inner.clone();
        Ok(run(async move { space.my_rank().await }).await?)
    }

    /// Pauses the space's sync with always-on peers.
    pub fn pause_sync(&self) {
        self.inner.pause_sync();
    }

    /// Resumes the space's sync with always-on peers: it catches up.
    pub fn resume_sync(&self) {
        self.inner.resume_sync();
    }

    /// Whether the space's sync with always-on peers is paused.
    pub fn is_sync_paused(&self) -> bool {
        self.inner.is_sync_paused()
    }

    /// Creates a blob stream; it exists in the space from its first blob.
    pub fn create_blobs(&self) -> Result<Arc<Blobs>> {
        Ok(self.blobs_of(self.inner.create_blobs()?))
    }

    /// A blob stream of the space, by its ID.
    pub async fn blobs(&self, id: String) -> Result<Arc<Blobs>> {
        let id = parse(&id)?;
        let space = self.inner.clone();
        let blobs = run(async move { space.blobs(id).await }).await?;
        Ok(self.blobs_of(blobs))
    }
}

impl Space {
    fn blobs_of(&self, inner: frasil::Blobs) -> Arc<Blobs> {
        Arc::new(Blobs {
            inner,
            runtime: self.runtime.clone(),
        })
    }
}

/// A blob stream: files and other bytes, each kept whole.
#[derive(uniffi::Object)]
pub struct Blobs {
    inner: frasil::Blobs,
    runtime: Handle,
}

#[uniffi::export(async_runtime = "tokio")]
impl Blobs {
    /// The stream's ID.
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Puts a blob, with a name if given; returns its ID.
    pub async fn put(&self, name: Option<String>, bytes: Vec<u8>) -> Result<String> {
        let blobs = self.inner.clone();
        let id = run(async move { blobs.put(name.as_deref(), &bytes).await }).await?;
        Ok(id.to_string())
    }

    /// Puts a blob from the file at `path`, with a name if given; returns
    /// its ID. The file is read twice, once for the blob's ID and once to
    /// seal it a chunk at a time, so a put holds a few chunks in memory
    /// whatever the file's size. The file must not change during the put:
    /// one that does fails `Changed`, and nothing is kept.
    pub async fn put_file(
        &self,
        name: Option<String>,
        path: String,
        listener: Option<Arc<dyn BlobProgressListener>>,
    ) -> Result<String> {
        let blobs = self.inner.clone();
        let id = run(async move {
            blobs
                .put_file(name.as_deref().unwrap_or(""), &path, |bytes, total| {
                    if let Some(listener) = &listener {
                        listener.progress(bytes, total);
                    }
                })
                .await
        })
        .await?;
        Ok(id.to_string())
    }

    /// A blob's bytes. A blob this device does not hold whole is fetched
    /// first from a connected peer or member, into the device's cache; none
    /// when it is not here and nothing is connected that could send it.
    pub async fn get(&self, id: String) -> Result<Option<Vec<u8>>> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        Ok(run(async move { blobs.get(id, &frasil::Read::new()).await }).await?)
    }

    /// Writes a blob's bytes to a new file at `path`, replacing any file
    /// there, fetching them first from connected peers or members, into
    /// the device's cache, while this device does not hold them whole. It
    /// holds a few chunks at a time, never the blob. `listener` hears the fetch, then the writing.
    /// A read that fails deletes the file.
    pub async fn get_to_file(
        &self,
        id: String,
        path: String,
        listener: Option<Arc<dyn BlobProgressListener>>,
    ) -> Result<()> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        run(async move {
            let file =
                tokio::fs::File::create(&path)
                    .await
                    .map_err(|error| FrasilError::Failed {
                        reason: format!("the file at {path}: {error}"),
                    })?;
            let mut file = tokio::io::BufWriter::new(file);
            let progress = move |bytes, total| {
                if let Some(listener) = &listener {
                    listener.progress(bytes, total);
                }
            };
            let read = blobs
                .get_stream(id, &mut file, &frasil::Read::new(), progress)
                .await;
            let read = match read {
                Ok(()) => file
                    .into_inner()
                    .sync_all()
                    .await
                    .map_err(|error| FrasilError::Failed {
                        reason: format!("the file at {path}: {error}"),
                    }),
                Err(error) => Err(error.into()),
            };
            if read.is_err() {
                let _ = tokio::fs::remove_file(&path).await;
            }
            read
        })
        .await
    }

    /// `length` bytes of a blob from byte `offset`, fewer at its end. Of a
    /// blob this device does not hold whole, only the chunks that hold
    /// the range are fetched, into the device's cache; none when it is
    /// not here and nothing is connected that could send it. Each chunk
    /// opens under the blob's key before its bytes are given, and the
    /// checks that need the whole blob do not run on a range: a member
    /// that holds the blob's key can serve a range read other validly
    /// sealed chunks, and nothing refutes them later, so read with `get`
    /// what must be the blob's. Of a blob the device holds whole, it
    /// opens only the chunks the range needs once every check has run on
    /// the whole blob.
    pub async fn get_range(&self, id: String, offset: u64, length: u64) -> Result<Option<Vec<u8>>> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        Ok(run(async move {
            blobs
                .get_range(id, offset, length, &frasil::Read::new())
                .await
        })
        .await?)
    }

    /// Where a blob's bytes stand on this device.
    pub async fn status(&self, id: String) -> Result<BlobStatus> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        Ok(run(async move { blobs.status(id).await }).await?.into())
    }

    /// The SHA-256 of a blob's plaintext, computed on this device. A blob
    /// this device does not hold whole is fetched first, into the device's
    /// cache; none when it cannot be read whole.
    pub async fn content_hash(&self, id: String) -> Result<Option<Vec<u8>>> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        let hash = run(async move { blobs.content_hash(id, &frasil::Read::new()).await }).await?;
        Ok(hash.map(|hash| hash.to_vec()))
    }

    /// Follows where a blob's bytes stand: the current status, then each
    /// change.
    pub fn observe_status(
        &self,
        id: String,
        listener: Arc<dyn BlobStatusListener>,
    ) -> Result<Arc<Subscription>> {
        let observed = self.inner.observe_status(parse(&id)?);
        let failing = listener.clone();
        Ok(Subscription::spawn(
            &self.runtime,
            follow(
                observed,
                move |status: frasil::BlobStatus| listener.status(status.into()),
                move |message| failing.failed(message),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::CheckpointPolicy;

    /// The record's defaults, which the generated Swift and Kotlin glue
    /// carries as literals, are the crate's default policy.
    #[test]
    fn the_default_policy_crosses_as_the_crate_has_it() {
        let crossed = CheckpointPolicy {
            propose: true,
            forget: true,
            roster_events: 1024,
            frame_bytes: 4_194_304,
        };
        assert_eq!(crossed, frasil::CheckpointPolicy::default().into());
        assert_eq!(frasil::CheckpointPolicy::from(crossed), Default::default());
        assert_eq!(crossed.roster_events, frasil::PROPOSE_AT_ROSTER_EVENTS);
        assert_eq!(crossed.frame_bytes, frasil::PROPOSE_AT_FRAME_BYTES);
    }

    /// A threshold of 0 counts as 1, and the flags cross as they are.
    #[test]
    fn a_manual_policy_crosses_back() {
        let manual = CheckpointPolicy {
            propose: false,
            forget: true,
            roster_events: 0,
            frame_bytes: 0,
        };
        let policy = frasil::CheckpointPolicy::from(manual);
        assert_eq!(policy, frasil::CheckpointPolicy::MANUAL.proposing_at(1, 1),);
        assert_eq!(
            CheckpointPolicy::from(policy),
            CheckpointPolicy {
                roster_events: 1,
                frame_bytes: 1,
                ..manual
            }
        );
    }
}
