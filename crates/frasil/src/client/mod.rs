//! What an application uses: a [`Device`], its [`Space`]s and their
//! streams, its [`Peer`]s, admission and [`Events`].
//!
//! A device runs its own upkeep in the background: heals and cascades
//! (keys.md, "Healing", "Cascades"), presenting new spaces to the peers it
//! is connected to, and keeping its timeline's reading. Sync and
//! durability run on each connection.

mod arrivals;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod batch_admission;
mod checkpoints;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod collecting;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod deposits;
mod events;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod exchange;
mod feeds;
#[cfg(feature = "ext-guests")]
mod guest;
mod ids;
#[cfg(any(
    feature = "iroh",
    all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    )
))]
mod invite;
#[cfg(all(
    feature = "ext-invite-links",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
mod link;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod moved;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod new_device;
mod observe;
mod pause;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub(crate) mod peers;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod person_grants;
mod reads;
mod recovery;
mod release;
mod space;
mod streams;
#[cfg(all(
    feature = "ext-deposit-tokens",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
mod tokens;
// The root API's later additions, one file per area.
#[cfg(feature = "ext-recovery-agent")]
mod agent;
#[cfg(feature = "ext-app-requests")]
mod app_requests;
#[cfg(feature = "adapter-blobs")]
mod blob_source;
#[cfg(feature = "adapter-blobs")]
mod blob_stream;
// Added for the drive extension, file references and local admission.
#[cfg(feature = "ext-drive")]
mod drive;
#[cfg(feature = "ephemeral")]
mod ephemeral_api;
mod erasure;
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
mod history;
mod leaving;
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
mod lent;
#[cfg(feature = "ext-libraries")]
mod library;
#[cfg(feature = "adapter-loro")]
mod live;
#[cfg(feature = "iroh")]
mod local_admission;
mod membership;
#[cfg(feature = "adapter-blobs")]
mod reader;
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
mod rebase;
#[cfg(feature = "adapter-blobs")]
mod references;
#[cfg(feature = "adapter-blobs")]
mod retention;
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
mod review;
mod suggestions;
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
mod undo;
#[cfg(feature = "adapter-records")]
mod versions;
// Held objects (at-rest.md, "Held objects").
mod held;
// Space files (ext-space-files.md).
#[cfg(feature = "space-files")]
pub(crate) mod space_file;

#[cfg(feature = "ext-recovery-agent")]
pub use agent::{AgentKeys, AgentPolicy, NamedAgent};
#[cfg(feature = "ext-app-requests")]
pub use app_requests::{DeviceLists, NonceStore, RequestVerifier, SignedHeaders, VerifiedRequest};
pub use arrivals::{Arrival, Arrivals};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use batch_admission::SpaceAdmission;
pub use checkpoints::{
    BackdatedCheckpoint, CheckpointStatus, CheckpointWork, ContestedCheckpoint, LateChange,
    LateChangeKind, ListCheckpointStatus, ListCheckpointWork, PendingCheckpoint,
    PendingListCheckpoint,
};
#[cfg(feature = "ext-drive")]
pub use drive::{
    Drive, DriveBatch, DriveChange, DriveChanges, DriveEntry, DriveFile, EntryId, EntryKind,
    FileVersion,
};
#[cfg(feature = "ephemeral")]
pub use ephemeral_api::{Ephemeral, EphemeralStream};
pub use events::{Event, Events};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use exchange::Joining;
#[cfg(feature = "adapter-blobs")]
pub use feeds::{BlobChange, BlobChanges};
pub use feeds::{Origin, SpaceChange, SpaceChanges};
#[cfg(feature = "adapter-records")]
pub use feeds::{RecordChange, RecordChanges};
#[cfg(all(feature = "adapter-records", feature = "index"))]
pub(crate) use feeds::{Touched, touched};
#[cfg(feature = "ext-guests")]
pub use guest::Guest;
#[cfg(feature = "adapter-blobs")]
pub use held::PutVersion;
pub use ids::{BlobId, ChangeId, CheckpointId, MemberId, SpaceId, StreamId, UnitId, VersionId};
#[cfg(feature = "iroh")]
pub use invite::Invitation;
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
pub use lent::{
    Lent, PENDING_LIMIT as LENT_PENDING_LIMIT, RETRY_LIMIT as LENT_RETRY_LIMIT,
    WINDOW as LENT_WINDOW,
};
#[cfg(feature = "adapter-loro")]
pub use live::{Changes, Live};
#[cfg(feature = "iroh")]
pub use local_admission::DeviceInvitation;
pub use membership::PersonId;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use new_device::JoiningPerson;
pub use observe::{Observation, Observed, Status};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use peers::{Peer, PeerStatus};
#[cfg(feature = "adapter-blobs")]
pub use reader::{BlobReader, MAX_READ_AHEAD, READ_AHEAD, Verified};
#[cfg(feature = "adapter-blobs")]
pub use reads::BlobStatus;
pub use reads::Receipt;
pub use recovery::{Passkey, PasskeyAssertion, PasskeyFuture, PrfOutput, RecoverySheet};
#[cfg(feature = "adapter-blobs")]
pub use references::BlobInfo;
#[cfg(feature = "adapter-blobs")]
pub use retention::{BlobCacheUsage, BlobLocal, BlobState, Read};
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub use review::{Review, ReviewChange, TextStep};
pub use space::{Member, MemberKind, Space, StreamInfo, StreamKind};
#[cfg(feature = "space-files")]
pub use space_file::{SpaceFile, SpaceFileFormat};
#[cfg(feature = "adapter-blobs")]
pub use streams::{Blob, Blobs};
#[cfg(feature = "adapter-loro")]
pub use streams::{Document, OnLimit, SetText};
#[cfg(feature = "adapter-records")]
pub use streams::{LastChange, Records, Row, RowWithMetadata, Transaction};
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub use suggestions::{Suggestion, SuggestionId};
#[cfg(all(
    feature = "ext-deposit-tokens",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
pub use tokens::DepositTokens;
#[cfg(feature = "adapter-records")]
pub use undo::RecordsUndo;
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
pub use undo::Undo;
#[cfg(feature = "adapter-records")]
pub use versions::{Marked, Version};

use crate::adapters::AdapterRegistry;
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::platform::{Clock, Platform, Random};
use crate::tasks::Tasks;
use frasil_store::store::{MaybeSend, MaybeSync};
use frasil_store::{DeviceBoundSlot, RestoreMode};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// Where a device keeps its records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Storage {
    /// In memory: everything is lost when the device is dropped. For tests,
    /// examples and devices that keep nothing.
    Memory,
    /// A directory of its own: the store, a SQLite database, and the
    /// sealed device keys beside it. The unlock key is never kept there.
    #[cfg(feature = "sqlite")]
    Directory(std::path::PathBuf),
    /// An IndexedDB database of its own, in a browser or a web worker: the
    /// store and the sealed device keys beside it, as `@frasil/client`'s
    /// `IndexedDbStore` keeps them. The unlock key is never kept there.
    #[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
    IndexedDb(String),
}

impl Storage {
    /// The IndexedDB database `name`, created when it does not exist.
    #[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
    pub fn indexed_db(name: impl Into<String>) -> Self {
        Self::IndexedDb(name.into())
    }

    /// A directory of the device's own.
    #[cfg(feature = "sqlite")]
    pub fn directory(path: impl Into<std::path::PathBuf>) -> Self {
        Self::Directory(path.into())
    }
}

/// How a device runs. The defaults suit an application; each setting
/// changes one thing.
#[derive(Default)]
pub struct Options {
    restore: Option<RestoreMode>,
    slot: Option<Arc<dyn DeviceBoundSlot>>,
    clock: Option<Arc<dyn Clock>>,
    random: Option<Arc<dyn Random>>,
    adapters: Option<AdapterRegistry>,
    tasks: Option<Arc<dyn Tasks>>,
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    connect: Option<Arc<dyn peers::Connect>>,
    loopback: bool,
    #[cfg(feature = "iroh")]
    relay_only: bool,
    #[cfg(feature = "iroh")]
    relay_roots: Vec<Vec<u8>>,
    #[cfg(feature = "iroh")]
    relays: Vec<String>,
    #[cfg(feature = "iroh")]
    local_discovery: bool,
    #[cfg_attr(not(feature = "partial-replicas"), allow(dead_code))]
    partial: bool,
    /// The budget of the blob cache, in stored bytes; 256 MiB when none is
    /// given.
    blob_cache: Option<u64>,
    keep_all_blobs: bool,
    /// `version_compaction_interval`, in seconds (ext-file-versions.md).
    #[cfg(feature = "ext-file-versions")]
    version_compaction_interval: Option<u64>,
    /// A directory store's path, where a new person's keys are kept.
    #[cfg(feature = "sqlite")]
    directory: Option<std::path::PathBuf>,
    /// Where an application's store keeps the sealed device keys.
    keep_keys: Option<Arc<dyn KeepKeys>>,
    /// A library ticket for the next space created at a peer that needs one.
    #[cfg(feature = "ext-libraries")]
    library_ticket: Option<Vec<u8>>,
    /// The provider every space's blobs are held through (at-rest.md,
    /// "Held objects").
    object_provider: Option<Arc<dyn crate::held::ObjectProvider>>,
    /// The deposit tokens a draw asks for (ext-deposit-tokens.md, 3.12).
    #[cfg(feature = "ext-deposit-tokens")]
    deposit_batch: Option<usize>,
}

impl core::fmt::Debug for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options")
            .field("restore", &self.restore)
            .field("loopback", &self.loopback)
            .field("partial", &self.partial)
            .field("blob_cache", &self.blob_cache)
            .field("keep_all_blobs", &self.keep_all_blobs)
            .finish_non_exhaustive()
    }
}

impl Options {
    /// The defaults: the system's clocks and randomness, the built-in
    /// adapters, tokio's runtime, and connections over any network. A
    /// directory store counts every start as a restore, so after a start
    /// the device syncs each space before it writes there again, unless
    /// [`device_bound`](Self::device_bound) or
    /// [`never_restored`](Self::never_restored) says otherwise.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detects a restored store through a slot that no backup restores,
    /// such as a keychain item bound to the device and left out of
    /// backups (at-rest.md, "Continuity"). The best choice wherever the
    /// platform has such a place.
    #[must_use]
    pub fn device_bound(mut self, slot: Arc<dyn crate::DeviceBoundSlot>) -> Self {
        self.restore = Some(RestoreMode::DeviceBound);
        self.slot = Some(slot);
        self
    }

    /// States that the store is never restored from a backup.
    #[must_use]
    pub fn never_restored(mut self) -> Self {
        self.restore = Some(RestoreMode::NeverRestored);
        self
    }

    /// Attaches the next space this device creates at a peer to a library,
    /// with a create ticket from the library's issuer (ext-libraries.md).
    #[cfg(feature = "ext-libraries")]
    #[must_use]
    pub fn library_ticket(mut self, ticket: Vec<u8>) -> Self {
        self.library_ticket = Some(ticket);
        self
    }

    /// How many deposit tokens the device draws in one batch at a peer, 1
    /// to 256; 16 by default (ext-deposit-tokens.md, 3.12 When to draw, and
    /// how many). It draws a batch when it holds fewer than 4 of the
    /// peer's issuing key. A grant draw asks for this many, so ask the
    /// issuer for grants of at least as many tokens. Give every device of
    /// an application the same batch: the pattern of draws then tells the
    /// peer no more than the library does.
    #[cfg(feature = "ext-deposit-tokens")]
    #[must_use]
    pub fn deposit_batch(mut self, tokens: usize) -> Self {
        self.deposit_batch = Some(tokens.clamp(1, 256));
        self
    }

    /// Holds every space's blobs through `provider`, on this device, in
    /// place of a sealed second copy (at-rest.md, "Held objects"): the
    /// application keeps each blob's plaintext as a file of its own, and
    /// Frasil keeps the blob's header and a record of the file's token,
    /// size and change stamp, sealing the chunks again from the file when
    /// it serves them. [`Space::hold_objects`] and [`Space::seal_objects`]
    /// set one space otherwise. A space whose grant to this device carries
    /// `frasil.nothing-at-rest` is never held.
    ///
    /// The policy is this device's alone: it is never synced and never
    /// stored, so an application names its provider at every open. A held
    /// blob's plaintext is readable from the disk with no unlock key; the
    /// platform's disk encryption protects it.
    #[must_use]
    pub fn object_provider(mut self, provider: Arc<dyn crate::held::ObjectProvider>) -> Self {
        self.object_provider = Some(provider);
        self
    }

    /// Binds the device's own endpoints on loopback alone, with no relay
    /// unless [`relay`](Self::relay) names one: nothing leaves the machine.
    /// For tests and examples.
    #[must_use]
    pub fn loopback(mut self) -> Self {
        self.loopback = true;
        self
    }

    /// An iroh relay the device registers with and dials through, such as
    /// the one a `frasil-relay` embeds: `https://relay.example.org`, or
    /// plain `http` on loopback for tests. Devices with no direct path
    /// between them still connect through it, and the session between them
    /// stays end to end (transport.md, "The iroh binding"). Its URL goes
    /// into the device's tickets, so name one that every member can reach.
    /// Call it again to name up to four. Without it, the device takes the
    /// relays that the first peer it connects to names in its discovery
    /// document, and uses none until then.
    ///
    /// Frasil names no relay of its own. A device with no relay reaches
    /// other members only directly, which in practice means on the same
    /// network; an application that lets people collaborate across the
    /// internet with no always-on peer names its relays here.
    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn relay(mut self, url: impl Into<String>) -> Self {
        self.relays.push(url.into());
        self
    }

    /// Binds the device's own endpoints with no IP socket at all, so that
    /// every connection goes through the relays [`relay`](Self::relay)
    /// names. For tests that a relay alone carries a session.
    #[cfg(feature = "iroh")]
    #[doc(hidden)]
    #[must_use]
    pub fn relay_only(mut self) -> Self {
        self.relay_only = true;
        self
    }

    /// Trusts only this certificate authority, its DER bytes, for the
    /// relays' TLS certificates, in place of the WebPKI roots. Call it
    /// again to trust several. For tests of a relay under a test
    /// authority.
    #[cfg(feature = "iroh")]
    #[doc(hidden)]
    #[must_use]
    pub fn relay_root(mut self, der: Vec<u8>) -> Self {
        self.relay_roots.push(der);
        self
    }

    /// Finds the members of the device's spaces on the local network, and
    /// lets them find it: once open, the device announces the spaces it
    /// holds, four every 2 seconds in turn, and dials each member whose
    /// announcement it opens, with no peer and no internet (transport.md,
    /// "Member announcements"). With N spaces, each is announced once
    /// every ceil(N / 4) × 2 seconds, and a connection that one of them
    /// started carries every space its two devices share. Two
    /// members another device admitted then connect to each other, sync
    /// and hear each other on the ephemeral channel. With
    /// [`loopback`](Self::loopback), on the loopback interface alone. A
    /// device whose local-network socket does not bind runs without it;
    /// [`Device::discover_locally`] says why. Without it, a device still
    /// reaches the members that the members it reaches tell it of
    /// (transport.md, "The iroh binding", member addresses).
    #[cfg(feature = "iroh")]
    #[must_use]
    pub fn local_discovery(mut self) -> Self {
        self.local_discovery = true;
        self
    }

    /// Holds in each space only what the application opens: the space's
    /// members, keys and own records, and the documents, tables and blobs
    /// it opens or writes in (units.md, "Partial replicas"). A stream
    /// opens when `Space::document`, `Space::records` or `Space::blobs`
    /// first names it, and its changes are fetched then;
    /// the device judges every change as a device that holds everything
    /// would, and holds back a change whose verdict it cannot yet prove.
    /// For large spaces on small devices.
    #[cfg(feature = "partial-replicas")]
    #[must_use]
    pub fn partial(mut self) -> Self {
        self.partial = true;
        self
    }

    /// The budget of the blob cache, in bytes as the device stores them: a
    /// blob's sealed chunks and its header, a little more than its size.
    /// 256 MiB when not set.
    ///
    /// A device fetches a blob when it is read and leaves it in the cache
    /// ([`Blobs::get`], [`Read`]). When the cached blobs of all its spaces
    /// would pass the budget, it drops whole blobs, the one read longest
    /// ago first; a read fetches a dropped blob again. With a budget of
    /// zero a read stores nothing once it ends, and a blob larger than
    /// the budget is dropped once the read that fetched it ends. Blobs the
    /// device keeps ([`Blobs::keep`]), blobs it put that no peer holds
    /// yet, and what Frasil stores for itself are outside the budget and
    /// never dropped for it. The budget is not stored: give it at each
    /// open.
    #[must_use]
    pub fn blob_cache(mut self, bytes: u64) -> Self {
        self.blob_cache = Some(bytes);
        self
    }

    /// Fetches every blob the device's spaces name, because a stream
    /// names it, and keeps each: a full copy, for a device that must read
    /// every blob with no connection. Nothing is evicted, and the budget
    /// of [`blob_cache`](Self::blob_cache) is not used. Without it, a
    /// device knows every blob of the streams it holds and fetches one
    /// when it is read or kept. This is the device's own choice of what to
    /// fetch, which no peer or member can see.
    #[must_use]
    pub fn keep_all_blobs(mut self) -> Self {
        self.keep_all_blobs = true;
        self
    }

    /// How long after the first supersession since a Blobs stream's last
    /// snapshot this device compacts the stream, so that an old version
    /// waits at most this long beyond a peer's retention
    /// (ext-file-versions.md, section 3.11). 24 hours by default, and held
    /// between 1 hour and 7 days.
    #[cfg(feature = "ext-file-versions")]
    #[must_use]
    pub fn version_compaction_interval(mut self, interval: std::time::Duration) -> Self {
        let spec = frasil_base::time::Timer::VersionCompactionInterval.spec();
        let (low, high) = (spec.minimum.unwrap_or(0), spec.maximum.unwrap_or(u64::MAX));
        self.version_compaction_interval = Some(interval.as_secs().clamp(low, high));
        self
    }

    /// Another clock, such as a [`ManualClock`](crate::advanced::ManualClock).
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Another source of randomness.
    #[must_use]
    pub fn random(mut self, random: Arc<dyn Random>) -> Self {
        self.random = Some(random);
        self
    }

    /// Other adapters than the built-in ones.
    #[must_use]
    pub fn adapters(mut self, adapters: AdapterRegistry) -> Self {
        self.adapters = Some(adapters);
        self
    }

    /// Where the device keeps its sealed keys when they are sealed again,
    /// for an application that supplies its own store and keeps the keys
    /// beside it ([`Device::from_engine`]); a directory store keeps its
    /// own.
    #[must_use]
    pub fn keep_keys(mut self, keep: Arc<dyn KeepKeys>) -> Self {
        self.keep_keys = Some(keep);
        self
    }

    /// Where the device runs its background work, where tokio has no
    /// runtime.
    #[must_use]
    pub fn tasks(mut self, tasks: Arc<dyn Tasks>) -> Self {
        self.tasks = Some(tasks);
        self
    }

    /// How the device connects to a peer by URL, where this crate opens no
    /// socket of its own, such as in a browser.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    #[must_use]
    pub fn connect_with(mut self, connect: Arc<dyn crate::advanced::Connect>) -> Self {
        self.connect = Some(connect);
        self
    }

    fn platform(&mut self, platform: Platform) -> Platform {
        let mut platform = platform;
        if let Some(mode) = self.restore {
            platform = platform.with_restore_mode(mode);
        }
        if let Some(slot) = self.slot.take() {
            platform.slot = Some(slot);
        }
        if let Some(clock) = self.clock.take() {
            platform = platform.with_clock(clock);
        }
        if let Some(random) = self.random.take() {
            platform = platform.with_random(random);
        }
        // Known at open, so that the first resolution is a partial
        // replica's (units.md, 3.15 Partial replicas).
        #[cfg(feature = "partial-replicas")]
        if self.partial {
            platform = platform.holding_streams_only();
        }
        platform
    }
}

/// How often the device's upkeep runs: every `rotation_step` (keys.md,
/// "The rank and the delay").
fn upkeep_every() -> Duration {
    Duration::from_secs(crate::maintenance::rotation_step().max(1))
}

/// The name of the sealed device keys in a directory store.
#[cfg(feature = "sqlite")]
const KEYS_FILE: &str = "device-keys";

/// The name of the SQLite store in a directory store.
#[cfg(feature = "sqlite")]
const STORE_FILE: &str = "store.sqlite3";

/// The name of the person ID a directory store's device keys name, beside
/// them, for a device of a person: the ID the client expects when it opens
/// them (at-rest.md, "Sealing and opening the device keys").
#[cfg(feature = "sqlite")]
const PERSON_FILE: &str = "person";

/// Writes a file aside, then renames it: a crash leaves the old file or
/// the whole new one.
#[cfg(feature = "sqlite")]
fn write_whole(path: &std::path::Path, name: &str, bytes: &[u8]) -> Result<()> {
    let failed = |error: std::io::Error| Error::Store(format!("{}: {error}", path.display()));
    let partial = path.join(format!("{name}.partial"));
    std::fs::write(&partial, bytes).map_err(failed)?;
    std::fs::rename(&partial, path.join(name)).map_err(failed)
}

/// Keeps a directory store's device keys sealed again to name a person,
/// and the person ID they name: the person first, so that a crash between
/// the two leaves keys that open as before or not at all, never keys of an
/// unrecorded person.
#[cfg(feature = "sqlite")]
pub(crate) fn keep_person(path: &std::path::Path, person: &[u8; 32], sealed: &[u8]) -> Result<()> {
    write_whole(path, PERSON_FILE, person)?;
    write_whole(path, KEYS_FILE, sealed)
}

/// Where an application that supplies its own store keeps the device's
/// sealed keys (at-rest.md, "Sealing and opening the device keys"):
/// [`Device::make_person`] seals them again to name the person, and keeps
/// them here in place of the old ones, which no longer open the device.
/// Recovery and device admission also retain resealed keys here. A failure
/// is returned to the caller; success means the replacement is durable.
pub trait KeepKeys: MaybeSend + MaybeSync {
    /// Keeps `sealed` in place of the sealed keys kept before, durably
    /// when the future completes.
    fn keep<'a>(&'a self, sealed: &'a [u8]) -> frasil_store::BoxFuture<'a, Result<()>>;
}

pub(crate) struct Inner {
    engine: Engine,
    tasks: Arc<dyn Tasks>,
    /// `version_compaction_interval`, in seconds.
    #[cfg(feature = "ext-file-versions")]
    version_interval: u64,
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    connect: Option<Arc<dyn peers::Connect>>,
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    peers: Mutex<Vec<Peer>>,
    /// Held while the device stores its skeleton events at its peers, so
    /// that one administration connection at a time carries them.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    administering: tokio::sync::Mutex<()>,
    /// One collection of welcomes at a peer at a time.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    receiving: tokio::sync::Mutex<()>,
    /// Spaces a peer handed over, and the peers kept for them.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    moves: moved::Moves,
    /// Each space none of its known peers hosts, for [`Events`].
    moved: tokio::sync::broadcast::Sender<frasil_events::EventId>,
    /// What the device's deposits and erasures report, for [`Events`].
    reports: tokio::sync::broadcast::Sender<Event>,
    /// The deposits being attempted now, by their IDs, so that an upkeep
    /// does not attempt one twice at once.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    depositing: Mutex<std::collections::BTreeSet<[u8; 16]>>,
    /// Deposits of spaces kept in memory only, which go again as those at
    /// rest do but are lost to a restart.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    unkept: Mutex<std::collections::BTreeMap<[u8; 16], frasil_store::DepositRecord>>,
    /// Each peer's collecting connection, where the device collects its
    /// own device mailbox (transport.md, 3.12 What a peer learns of a
    /// device).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    collecting: collecting::Collectors,
    /// The slot of the schedule each claim's list was last handed to its
    /// space on, in this run (ext-invite-links.md, "Claiming", step 11).
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    handed_lists: Mutex<std::collections::BTreeMap<frasil_events::EventId, u32>>,
    /// Deposit tokens: grants, and when to draw (ext-deposit-tokens.md).
    #[cfg(all(
        feature = "ext-deposit-tokens",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    tokens: tokens::Tokens,
    /// The spaces reported to the application as moved: not reported
    /// again until a peer grants the space, or the application names a
    /// home peer. An [`Events`] that fell behind gives them again.
    reported: events::Reported,
    /// The observed reads shared by key ([`Observed`]).
    observers: observe::Registry,
    #[cfg(feature = "iroh")]
    node: tokio::sync::Mutex<Option<crate::node::Node>>,
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    loopback: bool,
    #[cfg(feature = "iroh")]
    relay_only: bool,
    #[cfg(feature = "iroh")]
    relay_roots: Vec<Vec<u8>>,
    /// The member endpoint's home relays: the application's, or else
    /// those the first peer that names any lists in its discovery.
    #[cfg(feature = "iroh")]
    relays: Mutex<Vec<String>>,
    /// Whether the application named the relays, so that no peer's replace
    /// them.
    #[cfg(feature = "iroh")]
    #[cfg_attr(not(feature = "server"), allow(dead_code))]
    named_relays: bool,
    closed: AtomicBool,
    #[cfg(feature = "sqlite")]
    directory: Option<std::path::PathBuf>,
    keep_keys: Option<Arc<dyn KeepKeys>>,
}

/// A Frasil device: its keys, its store, the spaces it holds, and its
/// connections.
///
/// A device is a cheap handle: clones share one device. Open it once per
/// process, with [`Device::open`], in a tokio runtime. While it is open it
/// runs its own upkeep in the background; [`Device::close`] stops it.
#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Opens the device kept in `storage`, or creates one there if it holds
    /// none, with the default [`Options`]. `unlock_key` seals the device's
    /// keys: 32 bytes of high entropy from a keychain, a secure element or
    /// a hardware token, never a password, and never stored beside the
    /// store (at-rest.md, "What the application provides").
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the store does not open; a class such as
    /// `BadSeal` when `unlock_key` does not open the device's keys.
    pub async fn open(storage: Storage, unlock_key: &[u8; 32]) -> Result<Self> {
        Self::open_with(storage, unlock_key, Options::new()).await
    }

    /// [`Device::open`], with these options.
    ///
    /// # Errors
    ///
    /// As [`Device::open`].
    pub async fn open_with(
        storage: Storage,
        unlock_key: &[u8; 32],
        mut options: Options,
    ) -> Result<Self> {
        let adapters = options
            .adapters
            .take()
            .unwrap_or_else(AdapterRegistry::with_builtins);
        let engine = match storage {
            #[cfg(not(all(feature = "browser", target_arch = "wasm32", target_os = "unknown")))]
            Storage::Memory => {
                let platform = options.platform(Platform::memory());
                Engine::create(platform, unlock_key, adapters).await?.0
            }
            // A browser's store in memory, on the browser's clocks.
            #[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
            Storage::Memory => {
                let store = Arc::new(frasil_store::MemoryStore::new());
                let platform = options.platform(crate::browser::platform(store));
                Engine::create(platform, unlock_key, adapters).await?.0
            }
            #[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
            Storage::IndexedDb(name) => {
                let store = Arc::new(
                    crate::browser::IndexedDbStore::open(&name)
                        .await
                        .map_err(|error| Error::Store(error.to_string()))?,
                );
                let platform = options.platform(crate::browser::platform(store.clone()));
                if options.keep_keys.is_none() {
                    options.keep_keys = Some(store.clone());
                }
                open_indexed_db(&store, platform, unlock_key, adapters).await?
            }
            #[cfg(feature = "sqlite")]
            Storage::Directory(path) => {
                std::fs::create_dir_all(&path)
                    .map_err(|error| Error::Store(format!("{}: {error}", path.display())))?;
                let platform = Platform::sqlite(
                    path.join(STORE_FILE),
                    Arc::new(frasil_store::MemorySlot::new()),
                )
                .map(|platform| platform.with_restore_mode(RestoreMode::None))?;
                let platform = options.platform(platform);
                options.directory = Some(path.clone());
                open_directory(&path, platform, unlock_key, adapters).await?
            }
        };
        Self::from_engine(engine, options)
    }

    /// A device over an engine the caller made, with these options' tasks,
    /// connections and endpoints; their store settings are the engine's
    /// already. For bindings and tools (see [`advanced`](crate::advanced)).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] where tokio has no runtime and the options
    /// supply no [`Tasks`].
    pub fn from_engine(engine: Engine, options: Options) -> Result<Self> {
        #[cfg(feature = "partial-replicas")]
        if options.partial {
            engine.hold_streams_only();
        }
        if let Some(bytes) = options.blob_cache {
            engine.set_blob_cache(bytes);
        }
        if options.keep_all_blobs {
            engine.keep_all_blobs();
        }
        #[cfg(feature = "ext-file-versions")]
        let version_interval = options
            .version_compaction_interval
            .unwrap_or_else(frasil_adapter_blobs::versions::default_compaction_interval);
        if let Some(provider) = options.object_provider {
            engine.hold_all_objects(provider);
        }
        #[cfg(all(
            feature = "ext-libraries",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        ))]
        if let Some(ticket) = options.library_ticket {
            crate::peer::library::set_default(engine.device_id(), ticket);
        }
        let tasks = match options.tasks {
            Some(tasks) => tasks,
            None => default_tasks()?,
        };
        let inner = Arc::new(Inner {
            engine,
            tasks,
            #[cfg(feature = "ext-file-versions")]
            version_interval,
            #[cfg(all(
                any(feature = "server", feature = "iroh", feature = "server-socket"),
                not(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))
            ))]
            connect: options.connect,
            // A browser connects over its own WebSocket unless the
            // application supplies its own connector.
            #[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
            connect: options
                .connect
                .or_else(|| Some(Arc::new(crate::browser::BrowserConnect))),
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            peers: Mutex::new(Vec::new()),
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            administering: tokio::sync::Mutex::new(()),
            receiving: tokio::sync::Mutex::new(()),
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            moves: moved::Moves::default(),
            moved: tokio::sync::broadcast::channel(64).0,
            reports: tokio::sync::broadcast::channel(256).0,
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            depositing: Mutex::default(),
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            unkept: Mutex::default(),
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            collecting: collecting::Collectors::default(),
            #[cfg(all(
                feature = "ext-invite-links",
                any(feature = "server", feature = "iroh", feature = "server-socket")
            ))]
            handed_lists: Mutex::default(),
            #[cfg(all(
                feature = "ext-deposit-tokens",
                any(feature = "server", feature = "iroh", feature = "server-socket")
            ))]
            tokens: tokens::Tokens::new(options.deposit_batch),
            reported: events::Reported::default(),
            observers: observe::Registry::default(),
            #[cfg(feature = "iroh")]
            node: tokio::sync::Mutex::new(None),
            loopback: options.loopback,
            #[cfg(feature = "iroh")]
            relay_only: options.relay_only,
            #[cfg(feature = "iroh")]
            relay_roots: options.relay_roots,
            #[cfg(feature = "iroh")]
            named_relays: !options.relays.is_empty(),
            #[cfg(feature = "iroh")]
            relays: Mutex::new(options.relays),
            closed: AtomicBool::new(false),
            #[cfg(feature = "sqlite")]
            directory: options.directory,
            keep_keys: options.keep_keys,
        });
        start_upkeep(&inner);
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        start_administration(&inner);
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        moved::start(&inner);
        #[cfg(feature = "iroh")]
        start_member_connections(&inner, options.local_discovery);
        Ok(Self { inner })
    }

    /// Switches local discovery on, as [`Options::local_discovery`] does at
    /// open: the device announces the spaces it holds on the local
    /// network, four every 2 seconds in turn, and dials each member whose
    /// announcement it opens (transport.md, "Member announcements").
    /// Switching it on again does nothing.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when no local-network socket binds, on IPv4
    /// or IPv6; [`Error::NotAllowed`] once the device is closed.
    #[cfg(feature = "iroh")]
    pub async fn discover_locally(&self) -> Result<()> {
        use frasil_iroh::lan::LanConfig;
        let node = self.node().await?;
        let configs = if self.inner.loopback {
            vec![LanConfig::loopback_v4()]
        } else {
            let both = LanConfig::default();
            vec![
                both,
                LanConfig { v6: None, ..both },
                LanConfig { v4: None, ..both },
            ]
        };
        let mut failure = Error::Connection("no local-network socket".into());
        for config in configs {
            match node.discover(config) {
                Ok(()) => return Ok(()),
                Err(error) => failure = error,
            }
        }
        Err(failure)
    }

    /// The device's ID, by which spaces name it as a member: its device ID,
    /// the hash of its Ed25519 key and the commitment to its other keys
    /// (crypto.md, "A device's keys").
    pub fn id(&self) -> MemberId {
        MemberId::device(self.inner.engine.device_id())
    }

    /// The engine the device runs: every procedure of the protocol, with
    /// nothing scheduled. See [`advanced`](crate::advanced).
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }

    /// Creates a space that this device administers, and presents it to
    /// every peer the device is connected to.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; the store's.
    pub async fn create_space(&self) -> Result<Space> {
        let id = self.inner.engine.create_space().await?;
        self.grant_own_person(id).await?;
        self.present(id);
        Ok(Space::new(self.clone(), SpaceId::of(id)))
    }

    /// Creates a space that this device administers, as
    /// [`Device::create_space`] does, whose descriptor names `kind`: what
    /// kind of space the application makes, such as `"notes"`. It never
    /// changes, every member reads it with [`Space::kind`], and no peer
    /// does: it travels sealed in the space's genesis (roster.md, "The
    /// space descriptor").
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a kind that is empty or longer than 255
    /// bytes; as [`Device::create_space`].
    pub async fn create_space_of_kind(&self, kind: &str) -> Result<Space> {
        if kind.is_empty() || kind.len() > frasil_space::MAX_APPLICATION_BYTES {
            return Err(Error::Invalid("a space kind is 1 to 255 bytes"));
        }
        let descriptor = frasil_space::Descriptor {
            application: Some(kind.to_owned()),
            ..frasil_space::Descriptor::ORDINARY
        };
        let id = self
            .inner
            .engine
            .create_space_as(frasil_space::Policy::default(), descriptor)
            .await?;
        self.grant_own_person(id).await?;
        self.present(id);
        Ok(Space::new(self.clone(), SpaceId::of(id)))
    }

    /// A 32-byte key for the application's own data on this device, such
    /// as a cache or an index it keeps at rest: `purpose` names what it is
    /// for, such as `"com.example.cache"`, and each purpose gives a key of
    /// its own (at-rest.md, "Application keys"). The same device gives the
    /// same key for the same purpose after every restart. It derives from
    /// the device's store secret through a one-way function with a label of
    /// its own, so it reveals none of the device's keys, and no other
    /// device can derive it. Frasil neither stores nor uses it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an empty purpose.
    pub async fn derive_key(&self, purpose: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        if purpose.is_empty() {
            return Err(Error::Invalid("a key's purpose is not empty"));
        }
        self.inner.engine.app_key(None, purpose.as_bytes()).await
    }

    /// A space the device holds.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] when it holds none of this ID.
    pub async fn space(&self, id: SpaceId) -> Result<Space> {
        if self.inner.engine.spaces().await.contains(&id.event())
            && !self.claim_pending(&id.event()).await
        {
            Ok(Space::new(self.clone(), id))
        } else {
            Err(Error::UnknownSpace)
        }
    }

    /// Every space the device holds. A space whose claim waits for the
    /// person's consent is not among them.
    pub async fn spaces(&self) -> Vec<Space> {
        let pending = self.pending_claims().await;
        self.inner
            .engine
            .spaces()
            .await
            .into_iter()
            .filter(|id| !pending.contains(id))
            .map(|id| Space::new(self.clone(), SpaceId::of(id)))
            .collect()
    }

    /// The spaces where a claim is begun and not signed: held for the
    /// claim, listed nowhere.
    async fn pending_claims(&self) -> Vec<frasil_events::EventId> {
        #[cfg(feature = "ext-invite-links")]
        {
            self.inner.engine.pending_claims().await
        }
        #[cfg(not(feature = "ext-invite-links"))]
        {
            Vec::new()
        }
    }

    async fn claim_pending(&self, space: &frasil_events::EventId) -> bool {
        self.pending_claims().await.contains(space)
    }

    /// Connects to an always-on peer at its URL, such as
    /// `https://peer.example.org` (plain `http` only to a loopback host),
    /// and keeps every space the device holds there: the connection syncs
    /// them both ways, live, and the peer's acknowledgements make this
    /// device's changes durable. Spaces the device creates or joins later
    /// are presented too. The connection runs until [`Peer::close`] or
    /// [`Device::close`]; when the peer asks the device to connect again,
    /// it does, and the same [`Peer`] goes on ([`PeerStatus::reconnecting`]).
    /// A device with no relay yet takes the relays the
    /// peer's discovery document names ([`Device::relays`]).
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the peer does not answer;
    /// [`Error::NotAllowed`] for a URL that is not HTTPS;
    /// [`Error::Unsupported`] in a build without the `server` feature and
    /// no [`Options::connect_with`].
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn connect(&self, url: &str) -> Result<Peer> {
        let spaces = self.inner.engine.presentable_spaces().await;
        let peer = self.open_connection(url, spaces).await?;
        self.inner
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(peer.clone());
        #[cfg(all(feature = "iroh", feature = "server"))]
        self.take_relays_of(url);
        Ok(peer)
    }

    /// A connection to the peer at `url` presenting `spaces` only, through
    /// the application's connector when it has one.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn open_connection(
        &self,
        url: &str,
        spaces: Vec<frasil_events::EventId>,
    ) -> Result<Peer> {
        let handle = match &self.inner.connect {
            Some(connect) => {
                connect
                    .connect(self.inner.engine.clone(), url.to_owned(), spaces.clone())
                    .await?
            }
            None => peers::connect_default(&self.inner.engine, url, spaces.clone()).await?,
        };
        Ok(Peer::new(url, handle, spaces))
    }

    /// The connections that may carry a space: the peers the device
    /// connected to, and those it opened for that space alone as it
    /// followed the space to another peer (transport.md, 3.11 Presenting
    /// credentials).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn peers_of(&self, space: &frasil_events::EventId) -> Vec<Peer> {
        // A paused space's sync goes to no peer ([`Space::pause_sync`]).
        if self.engine().links().is_paused(space) {
            return Vec::new();
        }
        let mut peers = self.peers();
        peers.extend(self.inner.moves.scoped_to(space));
        peers
    }

    /// The iroh relays the device's member endpoint registers with and
    /// dials through: those [`Options::relay`] named, or else those of the
    /// first peer it connected to that names any; none until then.
    #[cfg(feature = "iroh")]
    pub fn relays(&self) -> Vec<String> {
        self.inner
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes the relays the peer at `url` names in its discovery document
    /// as the member endpoint's home relays, in the background, when the
    /// device has none yet (transport.md, "The server binding").
    #[cfg(all(feature = "iroh", feature = "server"))]
    fn take_relays_of(&self, url: &str) {
        if self.inner.named_relays || !self.relays().is_empty() {
            return;
        }
        let (device, url) = (self.clone(), url.to_owned());
        self.inner.tasks.spawn(Box::pin(async move {
            let Some(relays) = peers::discovery_relays(&url).await else {
                return;
            };
            {
                let mut own = device
                    .inner
                    .relays
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if !own.is_empty() {
                    return;
                }
                own.clone_from(&relays);
            }
            if let Some(node) = device.inner.node.lock().await.as_ref() {
                let _ = node.add_relays(&relays).await;
            }
        }));
    }

    /// The peers the device has connected to, open or closed. The
    /// connections it opens on its own to follow a space that a peer handed
    /// over, which carry that space alone, are not among them.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub fn peers(&self) -> Vec<Peer> {
        self.inner
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Joins a space by the text of an [`Invitation`] another device shows,
    /// as its person entered or scanned it. `name` is what the other screen
    /// shows for this device. Both screens then show the same six-digit
    /// admission code: `confirm` is given the code and the other device's
    /// name, and its future says whether this device's person saw that
    /// code on both, so that an application can wait for the person's
    /// answer.
    ///
    /// With the `ext-invite-links` feature, the text may also be an invite
    /// link that [`Space::invite_link`] made. The device fetches the link's
    /// drop from the peer the link names, or from a peer it is connected
    /// to, and the space with it; there is no code: `confirm` is given an
    /// empty code and the inviting device's ID, and its future says whether
    /// this device's person consents to join.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for text that is no invitation; `Mismatch` when a
    /// person did not confirm the code; [`Error::Connection`] when the
    /// other device is not reachable. For a link, also `Declined`;
    /// `NotFound` when no peer holds its drop; `InviteUsed`,
    /// `InviteRevoked`, `InviteRaced` or `Expired` for an invite that can
    /// no longer be claimed; [`Error::Timeout`] when the space does not
    /// arrive.
    #[cfg(any(
        feature = "iroh",
        all(
            feature = "ext-invite-links",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        )
    ))]
    pub async fn join<F>(
        &self,
        invitation: &str,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + frasil_store::store::MaybeSend + 'static,
    ) -> Result<Space>
    where
        F: std::future::Future<Output = bool> + frasil_store::store::MaybeSend + 'static,
    {
        Box::pin(invite::join(self, invitation, name, confirm)).await
    }

    /// Vetoes a device that a recovery agent added to this device's person
    /// ([`Event::AgentAdded`]): revokes it, every device added through it,
    /// and the agent, so that it adds no more (ext-recovery-agent.md,
    /// "Relay and veto"). The person's spaces then rotate their keys by
    /// themselves.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person, or a `device` that
    /// no agent added; `AgentLimited` when this device was itself added
    /// through the agent.
    #[cfg(feature = "ext-recovery-agent")]
    pub async fn veto(&self, device: MemberId) -> Result<()> {
        self.inner
            .engine
            .veto(frasil_crypto::device::DeviceId(*device.as_bytes()), true)
            .await
            .map(drop)
    }

    /// Tells the application's [`Events`]: what its deposits and erasures
    /// report.
    pub(crate) fn report(&self, event: Event) {
        let _ = self.inner.reports.send(event);
    }

    /// The device's events, from now on: what changed in its spaces.
    pub fn events(&self) -> Events {
        Events::new(
            self.inner.engine.clone(),
            self.inner.moved.subscribe(),
            self.inner.reports.subscribe(),
            self.inner.reported.clone(),
        )
    }

    /// Closes the device: stops its upkeep, closes its connections and
    /// endpoints, forgets every space it keeps in memory only (a guest's
    /// that keeps nothing at rest), and keeps its timeline's reading at
    /// rest. The device can still be read; it connects no more.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn close(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::SeqCst);
        // Lent documents: what the window holds reaches a unit.
        #[cfg(feature = "adapter-loro")]
        self.inner.engine.flush_all_lent().await?;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        for peer in self
            .peers()
            .into_iter()
            .chain(self.inner.moves.all_scoped())
        {
            peer.close();
        }
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        self.inner.collecting.close_all();
        #[cfg(feature = "iroh")]
        if let Some(node) = self.inner.node.lock().await.take() {
            node.close().await;
        }
        // A space kept in memory only goes when the application closes it
        // (ext-guests.md, "Nothing at rest").
        #[cfg(feature = "ext-guests")]
        self.inner.engine.forget_memory_only().await?;
        self.inner.engine.keep_reading().await
    }

    /// A future that is ready once `duration` has passed, on the device's
    /// tasks.
    pub(crate) fn sleep(&self, duration: Duration) -> frasil_store::BoxFuture<'static, ()> {
        self.inner.tasks.sleep(duration)
    }

    /// Whether [`Device::close`] was called.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Runs a task in the background on the device's tasks.
    pub(crate) fn spawn(&self, task: frasil_store::BoxFuture<'static, ()>) {
        self.inner.tasks.spawn(task);
    }

    /// Runs a task in the background if the device's tasks can take it
    /// now, without a panic when they cannot: whether it was taken.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn try_spawn(&self, task: frasil_store::BoxFuture<'static, ()>) -> bool {
        self.inner.tasks.try_spawn(task)
    }

    /// Joins a space through an exchange mailbox at the peer at `url`,
    /// where this device cannot take part in nearby pairing, such as in a
    /// browser (admission.md, "Without a nearby connection"). Show the
    /// returned [`Joining::text`] as a QR code; an administrator enters it
    /// in [`Space::admit`]. Both screens then show the same six-digit
    /// admission code: `confirm` is given the code and the administrator's
    /// device name, and its future says whether this device's person saw
    /// that code on both. `name` is what the other screen shows for this device.
    /// [`Joining::joined`] waits for the space.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the peer does not answer;
    /// [`Error::NotAllowed`] for a URL that is not HTTPS; `Expired`
    /// without a wall clock.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn join_via_peer<F>(
        &self,
        url: &str,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + frasil_store::store::MaybeSend + 'static,
    ) -> Result<Joining>
    where
        F: std::future::Future<Output = bool> + frasil_store::store::MaybeSend + 'static,
    {
        exchange::join_via_peer(self, url, name, confirm).await
    }

    /// Fetches the newcomer's snapshot a space awaits, at every open peer
    /// connection, while it awaits one: it may reach a peer after the
    /// welcome or the drop that names it.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn fetch_snapshot(&self, space: frasil_events::EventId) {
        let awaits = self
            .inner
            .engine
            .read(&space, |replica| replica.awaited_snapshot().is_some())
            .await
            .unwrap_or(false);
        if awaits {
            for peer in self.peers() {
                peer.handle().fetch(space);
            }
        }
    }

    /// Presents a space to every open peer connection.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(unused_variables)
    )]
    pub(crate) fn present(&self, space: frasil_events::EventId) {
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        for peer in self.peers() {
            peer.present(space);
        }
    }

    /// The device's iroh endpoint, bound on first use.
    #[cfg(feature = "iroh")]
    pub(crate) async fn node(&self) -> Result<crate::node::Node> {
        let mut node = self.inner.node.lock().await;
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(Error::NotAllowed("the device is closed"));
        }
        if let Some(node) = node.as_ref() {
            return Ok(node.clone());
        }
        let (loopback, relay_only, relays) =
            (self.inner.loopback, self.inner.relay_only, self.relays());
        let roots = self.inner.relay_roots.clone();
        let bound = crate::node::Node::bind(self.inner.engine.clone(), move |config| {
            let config = if relay_only {
                config.relay_only()
            } else if loopback {
                config.loopback()
            } else {
                config
            };
            let config = if roots.is_empty() {
                config
            } else {
                config.relay_root_ders(roots)
            };
            config.relays(relays)
        })
        .await?;
        *node = Some(bound.clone());
        Ok(bound)
    }
}

#[cfg(feature = "sqlite")]
async fn open_directory(
    path: &std::path::Path,
    platform: Platform,
    unlock_key: &[u8; 32],
    adapters: AdapterRegistry,
) -> Result<Engine> {
    let failed = |error: std::io::Error| Error::Store(format!("{}: {error}", path.display()));
    let keys = path.join(KEYS_FILE);
    let person = match std::fs::read(path.join(PERSON_FILE)) {
        Ok(bytes) => {
            Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Class("Malformed"))?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(failed(error)),
    };
    match std::fs::read(&keys) {
        Ok(sealed) => match (
            Engine::open_as(
                platform.clone(),
                &sealed,
                unlock_key,
                person,
                adapters.clone(),
            )
            .await,
            person,
        ) {
            // Keys that do not name the recorded person yet: a crash came
            // between recording a person and sealing the keys again. They
            // open as a device member's, and the step is finished only for
            // a device active in that person's list it holds; any other
            // keys stay refused (at-rest.md, 3.1).
            (Err(Error::Class("WrongPerson")), Some(person)) => {
                let engine = Engine::open(platform, &sealed, unlock_key, adapters).await?;
                let resealed = engine.resume_person(person, unlock_key).await?;
                keep_person(path, &person, &resealed)?;
                Ok(engine)
            }
            (opened, _) => opened,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (engine, sealed) = Engine::create(platform, unlock_key, adapters).await?;
            // Written aside, then renamed: a crash leaves the old file or
            // the whole new one.
            let partial = path.join(format!("{KEYS_FILE}.partial"));
            std::fs::write(&partial, sealed).map_err(failed)?;
            std::fs::rename(&partial, &keys).map_err(failed)?;
            Ok(engine)
        }
        Err(error) => Err(failed(error)),
    }
}

/// Opens the device whose sealed keys an IndexedDB store keeps, or makes
/// one there. The person the keys name is read from them: the store keeps
/// one device's keys, so it is the person the application expects
/// (at-rest.md, "Sealing and opening the device keys").
#[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
async fn open_indexed_db(
    store: &crate::browser::IndexedDbStore,
    platform: Platform,
    unlock_key: &[u8; 32],
    adapters: AdapterRegistry,
) -> Result<Engine> {
    let stored = |error: frasil_store::StoreError| Error::Store(error.to_string());
    match store.load_sealed_keys().await.map_err(stored)? {
        Some(sealed) => {
            let person = sealed
                .get(34..66)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .filter(|person| *person != [0; 32]);
            Engine::open_as(platform, &sealed, unlock_key, person, adapters).await
        }
        None => {
            let (engine, sealed) = Engine::create(platform, unlock_key, adapters).await?;
            store.save_sealed_keys(&sealed).await.map_err(stored)?;
            Ok(engine)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn default_tasks() -> Result<Arc<dyn Tasks>> {
    Ok(Arc::new(crate::tasks::Tokio::current()))
}

#[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
fn default_tasks() -> Result<Arc<dyn Tasks>> {
    Ok(Arc::new(crate::browser::BrowserTasks))
}

#[cfg(all(
    target_arch = "wasm32",
    not(all(feature = "browser", target_os = "unknown"))
))]
fn default_tasks() -> Result<Arc<dyn Tasks>> {
    Err(Error::Unsupported(
        "no tokio runtime here: supply Options::tasks",
    ))
}

/// Starts the device's member connections when it opens: local discovery
/// when the options switch it on, and dialing again the members it keeps
/// tickets of (transport.md, "Reconnecting"). The member endpoint is bound
/// only when one of them needs it.
#[cfg(feature = "iroh")]
fn start_member_connections(inner: &Arc<Inner>, discover: bool) {
    let device = Device {
        inner: inner.clone(),
    };
    inner.tasks.spawn(Box::pin(async move {
        if discover {
            let _ = device.discover_locally().await;
        }
        let keeps = device
            .inner
            .engine
            .remembered_endpoints()
            .await
            .is_ok_and(|kept| !kept.is_empty());
        if keeps && let Ok(node) = device.node().await {
            node.keep_reconnecting();
        }
    }));
}

/// Runs the device's upkeep every [`upkeep_every`] while it is open: heals
/// and cascades, and presenting new spaces to its peers.
fn start_upkeep(inner: &Arc<Inner>) {
    let weak = Arc::downgrade(inner);
    inner.tasks.spawn(Box::pin(async move {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.closed.load(Ordering::SeqCst) {
                return;
            }
            let _ = Box::pin(inner.engine.maintain_all()).await;
            // The blob cache, back within its budget.
            let _ = inner.engine.evict().await;
            #[cfg(feature = "ext-file-versions")]
            inner.engine.compact_versions(inner.version_interval).await;
            // Each space that grants the person gets its recovery entry
            // once the person holds a recovery key or a passkey member.
            let _ = inner.engine.ensure_recovery_entries().await;
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            {
                let spaces = inner.engine.presentable_spaces().await;
                let peers = inner
                    .peers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                for peer in &peers {
                    for space in &spaces {
                        peer.present(*space);
                    }
                }
                // The blobs this device put that no peer is known to hold
                // yet, and that no change waiting to be sent names.
                for peer in peers.iter().chain(&inner.moves.all_scoped()) {
                    peer.offer_puts();
                }
                // This device's own skeleton events that a failed
                // administration connection left, once more.
                let device = Device {
                    inner: inner.clone(),
                };
                for peer in &peers {
                    peer.report_versions(&device);
                }
                for space in &spaces {
                    device.administer(*space).await;
                }
                // Spaces dropped for their own erasure, until each peer
                // answers `erased`.
                device.finish_erasures().await;
            }
            // The welcomes this device signed, at its peers; then its own
            // device mailbox: readers' list events, leave requests and
            // welcomes.
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            {
                let device = Device {
                    inner: inner.clone(),
                };
                person_grants::deposit_welcomes(&device).await;
                deposits::retry(&device).await;
                #[cfg(feature = "ext-deposit-tokens")]
                tokens::upkeep(&device).await;
                collect_mailboxes(&device).await;
            }
            #[cfg(all(
                feature = "ext-invite-links",
                any(feature = "server", feature = "iroh", feature = "server-socket")
            ))]
            {
                let device = Device {
                    inner: inner.clone(),
                };
                link::delete_spent_drops(&device).await;
                link::hand_over_lists_again(&device).await;
            }
            let sleep = inner.tasks.sleep(upkeep_every());
            drop(inner);
            sleep.await;
        }
    }));
}

/// Stores this device's own skeleton events as soon as the device places
/// one, such as the twin of a change of who administers or an
/// enrolment, rather than at the next upkeep: the roster event that
/// changes who administers cites its twin, so no peer acknowledges it
/// before it holds the twin (peers.md, "The skeleton").
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
fn start_administration(inner: &Arc<Inner>) {
    let weak = Arc::downgrade(inner);
    let mut notices = inner.engine.subscribe();
    inner.tasks.spawn(Box::pin(async move {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.closed.load(Ordering::SeqCst) {
                return;
            }
            // A pause in the notices still looks at whether the device
            // was closed.
            let sleep = inner.tasks.sleep(upkeep_every());
            drop(inner);
            let notice = tokio::select! {
                notice = notices.recv() => notice,
                () = sleep => continue,
            };
            let space = match notice {
                Ok(notice) => notice.space,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            };
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.engine.skeleton_pending(&space).await {
                Device { inner }.administer(space).await;
            }
        }
    }));
}

/// Collects this device's own device mailbox at each peer it is connected
/// to, and takes each item in it (transport.md, "Collecting a device
/// mailbox"): a reader's list events, or a leave request. It collects on
/// the peer's collecting connection, never on the connection that
/// presents its spaces ([`collecting`]). It collects at every connected
/// peer, an empty mailbox's included, since a collection claims the
/// mailbox there (transport.md, "Claimed device mailboxes"). The
/// collecting connections of peers it is no longer connected to close.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
async fn collect_mailboxes(device: &Device) {
    let connected: Vec<Peer> = device
        .peers()
        .into_iter()
        .filter(|peer| peer.status().connected)
        .collect();
    let urls: Vec<String> = connected.iter().map(|peer| peer.url().to_owned()).collect();
    device.inner.collecting.keep_only(&urls);
    for peer in connected {
        let after = peer.collected();
        let Ok(items) = device.collect_own(peer.url(), after).await else {
            continue;
        };
        let mut welcomed = false;
        for (id, item) in items {
            // An item that does not pass, or that has already been taken,
            // sends nothing. A welcome is taken from the whole mailbox
            // below (admission.md, 3.10 Welcomes).
            let welcome_answer = device.answer_welcome_request(peer.url(), &item).await;
            if welcome_answer.unwrap_or(false) {
                peer.set_collected(id);
                continue;
            }
            if device.engine().take_device_item(&item).await.is_err() {
                welcomed |= frasil_admission::welcome::Welcome::open(
                    &item,
                    &device.engine().device_id(),
                    device.engine().xwing_seed(),
                )
                .is_ok();
            }
            peer.set_collected(id);
        }
        if welcomed {
            let device = device.clone();
            let url = peer.url().to_owned();
            device.clone().spawn(Box::pin(async move {
                let _one = device.inner.receiving.lock().await;
                let _ = device.receive_welcomes_via_peer(&url, |_| {}).await;
            }));
        }
    }
}
