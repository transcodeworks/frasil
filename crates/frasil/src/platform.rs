//! What the application supplies (at-rest.md, "What the application
//! provides"; overview.md, "Clocks"): the store and the device-bound slot,
//! the restore mode, the clocks and the random source.
//!
//! The [`Engine`](crate::advanced::Engine) owns its platform. Everything the client
//! keeps goes through the [`Store`]; every reading of time goes through the
//! [`Clock`], which gives the monotonic clock and the wall clock with its
//! "known" flag; every random draw goes through [`Random`]. The protocol
//! crates hold none of these, so a test can drive the device with a clock
//! it moves by hand.

use crate::error::{Error, Result};
use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, RestoreMode, Store};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// The device's clocks (overview.md, "Clocks").
pub trait Clock: Send + Sync {
    /// The monotonic clock, in seconds: it never jumps, and keeps counting
    /// through suspend where the platform allows.
    fn monotonic(&self) -> u64;

    /// The wall clock, in seconds since 1970-01-01T00:00:00Z as POSIX counts
    /// them, when it is **known**: the platform says it is synchronised or
    /// backed by a battery-powered clock. `None` otherwise.
    fn wall(&self) -> Option<u64>;
}

/// The operating system's clocks. Its wall clock counts as known.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// The system clocks, with the monotonic clock counted from now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn monotonic(&self) -> u64 {
        self.origin.elapsed().as_secs()
    }

    fn wall(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|elapsed| elapsed.as_secs())
    }
}

/// A clock the caller sets by hand, for tests: both clocks start where the
/// caller says and move only by [`ManualClock::advance`] and
/// [`ManualClock::set_wall`].
#[derive(Debug, Default)]
pub struct ManualClock {
    state: Mutex<(u64, Option<u64>)>,
}

impl ManualClock {
    /// A clock whose monotonic clock reads `monotonic` and whose wall clock
    /// reads `wall`, or is not known.
    pub fn new(monotonic: u64, wall: Option<u64>) -> Self {
        Self {
            state: Mutex::new((monotonic, wall)),
        }
    }

    /// Moves both clocks on by `seconds`.
    pub fn advance(&self, seconds: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = state.0.saturating_add(seconds);
        state.1 = state.1.map(|wall| wall.saturating_add(seconds));
    }

    /// Sets the wall clock, or makes it unknown.
    pub fn set_wall(&self, wall: Option<u64>) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = wall;
    }
}

impl Clock for ManualClock {
    fn monotonic(&self) -> u64 {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0
    }

    fn wall(&self) -> Option<u64> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1
    }
}

/// The random source (crypto.md, "Randomness").
pub trait Random: Send + Sync {
    /// Fills `out` from a cryptographically secure source.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`] when the source fails. Never weaker bytes.
    fn fill(&self, out: &mut [u8]) -> Result<()>;
}

/// The operating system's random source, through `frasil-crypto`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<()> {
        for chunk in out.chunks_mut(64) {
            let bytes = frasil_crypto::random_bytes::<64>()?;
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// Everything an [`Engine`](crate::advanced::Engine) runs on.
#[derive(Clone)]
pub struct Platform {
    /// The store of sealed records.
    pub store: Arc<dyn Store>,
    /// The device-bound slot, in restore mode `device-bound`.
    pub slot: Option<Arc<dyn DeviceBoundSlot>>,
    /// The restore mode the application names (at-rest.md, "Continuity").
    pub restore_mode: RestoreMode,
    /// The clocks.
    pub clock: Arc<dyn Clock>,
    /// The random source.
    pub random: Arc<dyn Random>,
    /// Whether every replica is partial from the device's first resolution
    /// on (units.md, 3.15 Partial replicas): the application's choice for
    /// this run, which nothing at rest records, so that a device opened
    /// from its store resolves each space as the partial replica it is.
    /// Read only with the `partial-replicas` feature.
    pub streams_only: bool,
}

impl core::fmt::Debug for Platform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Platform")
            .field("restore_mode", &self.restore_mode)
            .field("slot", &self.slot.is_some())
            .finish_non_exhaustive()
    }
}

impl Platform {
    /// A platform over a store and a slot, in restore mode `device-bound`,
    /// with the system's clocks and random source.
    pub fn new(store: Arc<dyn Store>, slot: Arc<dyn DeviceBoundSlot>) -> Self {
        Self {
            store,
            slot: Some(slot),
            restore_mode: RestoreMode::DeviceBound,
            clock: Arc::new(SystemClock::new()),
            random: Arc::new(OsRandom),
            streams_only: false,
        }
    }

    /// A platform in memory: a [`MemoryStore`] and a [`MemorySlot`]. For
    /// tests, and for a device that keeps nothing.
    pub fn memory() -> Self {
        Self::new(Arc::new(MemoryStore::new()), Arc::new(MemorySlot::new()))
    }

    /// A platform whose store is a SQLite database at `path`, in WAL mode,
    /// with the slot the application gives.
    ///
    /// # Errors
    ///
    /// The store's, when the database does not open.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(
        path: impl AsRef<std::path::Path>,
        slot: Arc<dyn DeviceBoundSlot>,
    ) -> Result<Self> {
        let store = frasil_store::SqliteStore::open(path)?;
        Ok(Self::new(Arc::new(OffExecutor::new(store)), slot))
    }

    /// The same platform with another clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The same platform with another random source.
    #[must_use]
    pub fn with_random(mut self, random: Arc<dyn Random>) -> Self {
        self.random = random;
        self
    }

    /// The same platform for a device whose replicas are partial from its
    /// first resolution on, at open included (units.md, 3.15 Partial
    /// replicas), as [`Engine::hold_streams_only`] makes them afterwards.
    ///
    /// [`Engine::hold_streams_only`]: crate::advanced::Engine::hold_streams_only
    #[cfg(feature = "partial-replicas")]
    #[must_use]
    pub fn holding_streams_only(mut self) -> Self {
        self.streams_only = true;
        self
    }

    /// The same platform in another restore mode. A mode other than
    /// `device-bound` writes no mark.
    #[must_use]
    pub fn with_restore_mode(mut self, mode: RestoreMode) -> Self {
        self.restore_mode = mode;
        self
    }

    /// `N` random bytes.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    pub fn draw<const N: usize>(&self) -> Result<Zeroizing<[u8; N]>> {
        let mut out = Zeroizing::new([0u8; N]);
        self.random.fill(out.as_mut_slice())?;
        Ok(out)
    }

    /// `N` random bytes, as a plain array, for values that are not secret:
    /// nonces and IDs.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    pub fn nonce<const N: usize>(&self) -> Result<[u8; N]> {
        Ok(*self.draw::<N>()?)
    }
}

/// Fails unless the platform's random source works, before the device
/// makes keys from it.
pub(crate) fn check_random(random: &dyn Random) -> Result<()> {
    let mut probe = [0u8; 32];
    random.fill(&mut probe)?;
    if probe == [0; 32] {
        return Err(Error::NoRandomness);
    }
    Ok(())
}

/// A SQLite store whose blocking work runs off the async executor: reads on
/// tokio's blocking threads (inline outside a runtime), commits on one
/// writer thread of its own. Commits that wait while one is made are made
/// together, in one transaction and one fsync ([`Store::commit_all`]), each
/// against what those before it left.
#[cfg(feature = "sqlite")]
struct OffExecutor {
    store: Arc<frasil_store::SqliteStore>,
    writer: Mutex<std::sync::mpsc::Sender<Queued>>,
}

/// A commit waiting for the writer thread, and where its answer goes.
#[cfg(feature = "sqlite")]
type Queued = (
    frasil_store::Commit,
    tokio::sync::oneshot::Sender<std::result::Result<bool, frasil_store::StoreError>>,
);

#[cfg(feature = "sqlite")]
impl OffExecutor {
    fn new(store: frasil_store::SqliteStore) -> Self {
        let store = Arc::new(store);
        let (sender, receiver) = std::sync::mpsc::channel::<Queued>();
        let writing = Arc::clone(&store);
        // The thread ends once the store, and with it the sender, is gone.
        std::thread::Builder::new()
            .name("frasil-store-writer".into())
            .spawn(move || {
                while let Ok(first) = receiver.recv() {
                    let mut queued = vec![first];
                    queued.extend(receiver.try_iter());
                    let (commits, answers): (Vec<_>, Vec<_>) = queued.into_iter().unzip();
                    match writing.commit_now(&commits) {
                        Ok(made) => {
                            for (answer, made) in answers.into_iter().zip(made) {
                                let _ = answer.send(Ok(made));
                            }
                        }
                        Err(error) => {
                            for answer in answers {
                                let _ = answer.send(Err(error.clone()));
                            }
                        }
                    }
                }
            })
            .expect("the store's writer thread starts");
        Self {
            store,
            writer: Mutex::new(sender),
        }
    }

    /// Runs a read off the executor's threads: on a blocking thread inside
    /// a tokio runtime, inline outside one.
    async fn read<T: Send + 'static>(
        &self,
        read: impl FnOnce(
            &frasil_store::SqliteStore,
        ) -> std::result::Result<T, frasil_store::StoreError>
        + Send
        + 'static,
    ) -> std::result::Result<T, frasil_store::StoreError> {
        let store = Arc::clone(&self.store);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(move || read(&store))
                .await
                .map_err(|_| frasil_store::StoreError::new("sqlite: a read was cancelled"))?,
            Err(_) => read(&store),
        }
    }

    async fn commit_one(
        &self,
        commit: frasil_store::Commit,
    ) -> std::result::Result<bool, frasil_store::StoreError> {
        let (answer, answered) = tokio::sync::oneshot::channel();
        self.writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send((commit, answer))
            .map_err(|_| frasil_store::StoreError::new("sqlite: the writer has stopped"))?;
        answered
            .await
            .map_err(|_| frasil_store::StoreError::new("sqlite: the writer has stopped"))?
    }
}

#[cfg(feature = "sqlite")]
impl Store for OffExecutor {
    fn get<'a>(
        &'a self,
        address: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, std::result::Result<Option<Vec<u8>>, frasil_store::StoreError>>
    {
        let address = address.to_vec();
        Box::pin(self.read(move |store| store.get_now(&address)))
    }

    fn get_many<'a>(
        &'a self,
        addresses: &'a [Vec<u8>],
    ) -> frasil_store::BoxFuture<
        'a,
        std::result::Result<Vec<Option<Vec<u8>>>, frasil_store::StoreError>,
    > {
        let addresses = addresses.to_vec();
        Box::pin(self.read(move |store| store.get_many_now(&addresses)))
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<
        'a,
        std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, frasil_store::StoreError>,
    > {
        let prefix = prefix.to_vec();
        Box::pin(self.read(move |store| store.scan_now(&prefix)))
    }

    fn scan_sizes<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<
        'a,
        std::result::Result<frasil_store::Sizes, frasil_store::StoreError>,
    > {
        let prefix = prefix.to_vec();
        Box::pin(self.read(move |store| store.scan_sizes_now(&prefix)))
    }

    fn commit<'a>(
        &'a self,
        commit: &'a frasil_store::Commit,
    ) -> frasil_store::BoxFuture<'a, std::result::Result<bool, frasil_store::StoreError>> {
        Box::pin(self.commit_one(commit.clone()))
    }

    fn scrub(
        &self,
    ) -> frasil_store::BoxFuture<'_, std::result::Result<(), frasil_store::StoreError>> {
        Box::pin(self.read(frasil_store::SqliteStore::scrub_now))
    }

    fn commit_all<'a>(
        &'a self,
        commits: &'a [frasil_store::Commit],
    ) -> frasil_store::BoxFuture<'a, std::result::Result<Vec<bool>, frasil_store::StoreError>> {
        let commits = commits.to_vec();
        Box::pin(self.read(move |store| store.commit_now(&commits)))
    }
}
