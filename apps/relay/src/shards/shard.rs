//! One shard: its SQLite working copy, and, with a bucket, its copy of
//! record there (crate `shards`, module `format`).
//!
//! The working copy is always the state of the last batch applied: a batch
//! is applied only once the bucket holds it, so what the peer reads is what
//! it has acknowledged or may acknowledge. The working copy keeps its own
//! position and the shard's reading, under addresses no record of the peer
//! takes, so that a node that opens the shard again from the same cache
//! replays only the batches after it.
//!
//! Batches are sent from the writer's thread. Everything else that waits
//! for the bucket, a fold's copy and upload, a kept reading, a close, a
//! check that no other writer holds the shard, runs on the bucket's
//! runtime, so that no acknowledgement waits for it.
//!
//! A shard is **broken** once a write's outcome is unknown, or once it finds
//! that another writer holds it: it then writes nothing, acknowledges
//! nothing more, and opens again from the bucket before its next use.

use super::bucket::{BucketError, BucketIo};
use super::fence::Fence;
use super::format::{
    self, Batch, Kind, MANIFEST_PREFIX, Manifest, Position, Run, SnapshotRef, log_key,
    manifest_key, snapshot_key,
};
use super::{NodeClock, node_reading};
use crate::clock::wall_now;
use frasil_base::time::{Reading, Timeline};
use frasil_store::{Commit, Durability, SqliteStore, Store, StoreError};
use futures_util::FutureExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The working copy's position, `[epoch, seq]`.
pub(crate) const META_POSITION: &[u8] = &[0, b'p'];
/// The working copy's last kept reading of the shard's timeline.
pub(crate) const META_READING: &[u8] = &[0, b'r'];

/// The log after the snapshot, in bytes, below which the shard never folds
/// before it closes.
pub(crate) const FOLD_MIN: u64 = 64 << 10;
/// The batches after the snapshot at which the shard folds whatever their
/// size, so that an open reads a bounded number of them.
pub(crate) const FOLD_BATCHES: u64 = 256;
/// Batches fetched at once when a shard opens.
const FETCH_WINDOW: usize = 16;

/// Runs a store's future, which the SQLite store makes ready at once.
pub(crate) fn ready<T>(
    future: frasil_store::BoxFuture<'_, Result<T, StoreError>>,
) -> Result<T, StoreError> {
    future
        .now_or_never()
        .unwrap_or_else(|| Err(StoreError::new("the store answered asynchronously")))
}

fn bucket_failed(error: BucketError) -> StoreError {
    StoreError::new(error.to_string())
}

fn not_held() -> StoreError {
    StoreError::new("this node no longer holds the shard")
}

/// The copy of record in a bucket.
struct Remote {
    io: Arc<BucketIo>,
    fence: Arc<dyn Fence>,
    /// `<shard>/`.
    root: String,
    /// The epoch this node opened the shard under.
    epoch: u64,
    /// What this node drew when it opened the shard, in each manifest it
    /// writes.
    nonce: [u8; 16],
}

impl Remote {
    fn key(&self, name: &str) -> String {
        format!("{}{name}", self.root)
    }

    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let bucket = self.io.bucket();
        let key = self.key(name);
        self.io
            .block(async move { bucket.get(&key).await })
            .map_err(bucket_failed)
    }

    /// The keys under the shard's root that start with `prefix`, without
    /// the root.
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let bucket = self.io.bucket();
        let full = self.key(prefix);
        let root = self.root.clone();
        let keys = self
            .io
            .block(async move { bucket.list(&full).await })
            .map_err(bucket_failed)?;
        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(root.as_str()).map(str::to_owned))
            .collect())
    }

    /// A write, issued only while the fence allows it: checked again on
    /// the bucket's runtime as the request starts, so that no wait for the
    /// runtime carries it past the lease.
    fn put(&self, name: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        if !self.fence.may_write(self.epoch) {
            return Err(not_held());
        }
        let bucket = self.io.bucket();
        let key = self.key(name);
        let fence = self.fence.clone();
        let epoch = self.epoch;
        self.io
            .block(async move {
                if !fence.may_write(epoch) {
                    return Err(BucketError("this node no longer holds the shard".into()));
                }
                bucket.put(&key, bytes).await
            })
            .map_err(bucket_failed)
    }

    /// An object written to a file, streamed where the bucket can: whether
    /// it was there. A file left by an object that is not there is removed.
    fn get_file(&self, name: &str, path: &Path) -> Result<bool, StoreError> {
        let bucket = self.io.bucket();
        let key = self.key(name);
        let file = path.to_owned();
        let found = self
            .io
            .block(async move { bucket.get_file(&key, &file).await })
            .map_err(bucket_failed);
        if !matches!(found, Ok(true)) {
            let _ = std::fs::remove_file(path);
        }
        found
    }

    /// Whether the log holds a batch of an epoch above `epoch`.
    fn has_log_after(&self, epoch: u64) -> Result<bool, StoreError> {
        Ok(self
            .list("log/")?
            .iter()
            .any(|key| matches!(format::parse_key(key), Some((Kind::Log, at)) if at.0 > epoch)))
    }

    /// Objects by name, fetched at once, a window at a time.
    fn get_all(&self, names: &[String]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let mut out = Vec::with_capacity(names.len());
        for window in names.chunks(FETCH_WINDOW * 2) {
            let bucket = self.io.bucket();
            let keys: Vec<String> = window.iter().map(|name| self.key(name)).collect();
            let fetched = self.io.block(async move {
                let gets = keys.iter().map(|key| {
                    let bucket = bucket.clone();
                    async move { bucket.get(key).await }
                });
                futures_util::future::join_all(gets).await
            });
            for result in fetched {
                out.push(result.map_err(bucket_failed)?);
            }
        }
        Ok(out)
    }

    /// Batches of `epoch` from `first` on, until one is missing: in windows
    /// of 1, 2, 4 and so on to 16.
    fn probe(&self, epoch: u64, first: u64) -> Result<Vec<(Position, Vec<u8>)>, StoreError> {
        let mut out = Vec::new();
        let mut seq = first;
        let mut width = 1u64;
        loop {
            let names: Vec<String> = (seq..seq + width)
                .map(|seq| log_key((epoch, seq)))
                .collect();
            for (offset, found) in self.get_all(&names)?.into_iter().enumerate() {
                match found {
                    Some(bytes) => out.push(((epoch, seq + offset as u64), bytes)),
                    None => return Ok(out),
                }
            }
            seq += width;
            width = (width * 2).min(FETCH_WINDOW as u64);
        }
    }
}

/// A fold under way.
type Folding = tokio::task::JoinHandle<()>;

/// What changes as the shard is written.
struct State {
    /// The last position applied to the working copy.
    applied: Position,
    /// The next seq of this node's epoch.
    next_seq: u64,
    /// The manifest this node last wrote, or, before its first, the one it
    /// writes first.
    manifest: Manifest,
    /// Whether the bucket holds a manifest of this node's epoch.
    manifest_written: bool,
    /// The last generation of a manifest this node drew, written or not.
    generation: u64,
    /// The batches after the snapshot that earlier epochs wrote: count and
    /// bytes.
    adopted: (u64, u64),
    /// This node's batches after the snapshot: seq and bytes.
    own: Vec<(u64, u64)>,
    /// The snapshot's bytes.
    snapshot_bytes: u64,
    /// A fold under way.
    folding: Option<Folding>,
    /// Broken: see the module's documentation.
    broken: bool,
    /// Being given up to another node: it takes no batch more.
    releasing: bool,
    /// The shard's timeline, when it keeps one of its own.
    timeline: Option<Timeline>,
    /// The node's timeline at the last reading kept, at the last use, and
    /// at the last check that no other writer holds the shard.
    kept_at: u64,
    last_use: u64,
    checked_at: u64,
    /// Whether the shard wrote a batch since that check.
    wrote: bool,
    /// Every position applied to this working copy since it opened, for
    /// tests.
    #[cfg(test)]
    applied_log: Vec<Position>,
}

/// One open shard.
pub(crate) struct Shard {
    pub(crate) name: String,
    pub(crate) store: SqliteStore,
    path: PathBuf,
    remote: Option<Remote>,
    clock: NodeClock,
    state: Mutex<State>,
    /// Held while a manifest is written, so that manifests are written in
    /// the order of their generations.
    manifests: Mutex<()>,
    /// Held from a batch's preparation to its end, so that batches from the
    /// writer and from other nodes of a cluster follow each other.
    pub(crate) writing: Mutex<()>,
}

impl core::fmt::Debug for Shard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shard")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A batch on its way to the bucket.
pub(crate) struct Pending {
    pub(crate) key: Option<String>,
    pub(crate) bytes: Vec<u8>,
    seq: u64,
    batch: Batch,
}

/// Where a shard opens from.
pub(crate) enum Opening<'a> {
    /// A data directory, the copy of record itself.
    Local,
    /// A bucket, with a cache for the working copy. `floor` is the greatest
    /// epoch this node opened the shard under before, if any.
    Bucket {
        io: &'a Arc<BucketIo>,
        fence: &'a Arc<dyn Fence>,
        floor: Option<u64>,
        /// Told the epoch the shard opens under, before anything is
        /// written under it.
        used: &'a (dyn Fn(u64) + Sync),
    },
}

fn remove_database(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
}

/// The shard's reading of its timeline at the node's reading `node`.
fn read_timeline(timeline: &mut Option<Timeline>, node: &Reading) -> Reading {
    match timeline {
        Some(timeline) => timeline.read(node.timeline, node.wall),
        None => *node,
    }
}

/// What a shard opened from: its working copy, the manifest it read, and
/// the batches it applied.
struct Opened {
    store: SqliteStore,
    manifest: Manifest,
    applied: Position,
    adopted: (u64, u64),
    last_tail: Option<u64>,
    kept: Option<Reading>,
    #[cfg(test)]
    applied_log: Vec<Position>,
}

/// Why an open from one manifest did not go through.
enum Missed {
    /// The manifest's snapshot, or a batch it names, is not in the bucket:
    /// an earlier manifest may serve.
    Gone,
    /// Anything else.
    Failed(StoreError),
}

impl From<StoreError> for Missed {
    fn from(error: StoreError) -> Self {
        Self::Failed(error)
    }
}

impl Shard {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a shard. `own_timeline` says whether it keeps a timeline of its
    /// own (overview.md, 6.7), taken up from its last kept reading; without
    /// one it reads the node's.
    ///
    /// With a bucket: lists the manifests and reads the latest whose
    /// snapshot and named batches are in the bucket, or, past one that is
    /// not, the history it names from an earlier manifest's snapshot; an
    /// earlier manifest alone serves only if no later epoch wrote batches
    /// after it, and with no manifest that serves, the open fails; reuses the working copy in the cache if
    /// its position is in the shard's history after that snapshot, and
    /// fetches the snapshot otherwise; applies the batches after it, those
    /// of the manifest's epoch until one is missing; and records them in a
    /// new manifest under this node's epoch (crate `fence`), which it reads
    /// back. A shard with nothing in the bucket writes its first manifest
    /// with its first batch.
    ///
    /// # Errors
    ///
    /// If the working copy or the bucket cannot be read, the bucket holds
    /// what does not read, no manifest serves, or another writer's manifest
    /// replaced this one.
    pub(crate) fn open(
        name: &str,
        path: PathBuf,
        opening: Opening<'_>,
        own_timeline: bool,
        clock: NodeClock,
    ) -> Result<Arc<Self>, StoreError> {
        let node = node_reading(&clock);
        let (io, fence, floor, used) = match opening {
            Opening::Local => {
                let store = SqliteStore::open_with(&path, 1, Durability::Full)?;
                let kept = ready(store.get(META_READING))?
                    .and_then(|bytes| format::decode_reading(&bytes));
                let opened = Opened {
                    store,
                    manifest: Manifest::empty(0, [0; 16]),
                    applied: (0, 0),
                    adopted: (0, 0),
                    last_tail: None,
                    kept,
                    #[cfg(test)]
                    applied_log: Vec::new(),
                };
                return Ok(Self::assemble(
                    name,
                    path,
                    None,
                    opened,
                    true,
                    own_timeline,
                    clock,
                ));
            }
            Opening::Bucket {
                io,
                fence,
                floor,
                used,
            } => (io.clone(), fence.clone(), floor, used),
        };
        let nonce = *frasil_crypto::random_bytes::<16>()
            .map_err(|_| StoreError::new("no randomness for a shard's nonce"))?;
        let probe = Remote {
            io: io.clone(),
            fence: fence.clone(),
            root: format!("{name}/"),
            epoch: 0,
            nonce,
        };
        // The manifests, the latest first.
        let mut manifests: Vec<Position> = probe
            .list(MANIFEST_PREFIX)?
            .iter()
            .filter_map(|key| match format::parse_key(key) {
                Some((Kind::Manifest, at)) => Some(at),
                _ => None,
            })
            .collect();
        manifests.sort_unstable_by(|a, b| b.cmp(a));
        let seen = manifests
            .first()
            .map(|at| at.0)
            .into_iter()
            .chain(floor)
            .max();
        let listed = !manifests.is_empty();
        let mut opened = None;
        // The latest manifest that reads, once one did not open: what an
        // earlier manifest's snapshot may still open.
        let mut latest: Option<Manifest> = None;
        for (epoch, generation) in manifests {
            let Some(bytes) = probe.get(&manifest_key(epoch, generation))? else {
                continue;
            };
            let manifest = Manifest::decode(&bytes)
                .ok_or_else(|| StoreError::new(format!("{name}: a manifest that does not read")))?;
            // The latest manifest's history, from this one's snapshot.
            if let Some(rebased) = latest.as_ref().and_then(|latest| rebase(latest, &manifest)) {
                match Self::open_from(name, &path, &probe, rebased) {
                    Ok(done) => {
                        opened = Some(done);
                        break;
                    }
                    Err(Missed::Gone) => {}
                    Err(Missed::Failed(error)) => return Err(error),
                }
            }
            // This manifest alone, unless a later epoch wrote batches on a
            // history it does not hold: that later epoch's batches would
            // be dropped without a word.
            if latest.is_some() && probe.has_log_after(epoch)? {
                crate::util::log(format_args!(
                    "{name}: manifest {epoch}-{generation} is passed over: a later epoch wrote \
                     batches after it"
                ));
                continue;
            }
            match Self::open_from(name, &path, &probe, manifest.clone()) {
                Ok(done) => {
                    opened = Some(done);
                    break;
                }
                Err(Missed::Gone) => {
                    crate::util::log(format_args!(
                        "{name}: manifest {epoch}-{generation} names a snapshot or a batch that \
                         is gone"
                    ));
                    latest.get_or_insert(manifest);
                }
                Err(Missed::Failed(error)) => return Err(error),
            }
        }
        if opened.is_none() && listed {
            // The bucket holds the shard, but no manifest of it opens: an
            // empty shard here would drop it.
            return Err(StoreError::new(format!(
                "{name}: no manifest of the shard opens"
            )));
        }
        let Some(opened) = opened else {
            // Nothing in the bucket: a working copy left in the cache is of
            // nothing the bucket holds.
            remove_database(&path);
            let store = SqliteStore::open_with(&path, 1, Durability::Cache)?;
            let epoch = fence.open_epoch(seen);
            used(epoch);
            let remote = Remote { epoch, ..probe };
            let opened = Opened {
                store,
                manifest: Manifest::empty(epoch, nonce),
                applied: (0, 0),
                adopted: (0, 0),
                last_tail: None,
                kept: None,
                #[cfg(test)]
                applied_log: Vec::new(),
            };
            return Ok(Self::assemble(
                name,
                path,
                Some(remote),
                opened,
                false,
                own_timeline,
                clock,
            ));
        };
        let epoch = fence.open_epoch(seen.max(Some(opened.manifest.epoch)));
        used(epoch);
        let mut runs = opened.manifest.runs.clone();
        if let Some(last) = opened.last_tail {
            runs.push(Run {
                epoch: opened.manifest.epoch,
                first: opened.manifest.next,
                last,
            });
        }
        let snapshot = opened.manifest.snapshot;
        let mut opened = opened;
        opened.manifest = Manifest {
            epoch,
            snapshot,
            runs,
            next: 1,
            reading: None,
            nonce,
        };
        let remote = Remote { epoch, ..probe };
        let shard = Self::assemble(name, path, Some(remote), opened, false, own_timeline, clock);
        shard.lock().snapshot_bytes = snapshot.map_or(0, |s| s.bytes);
        shard.write_manifest(&node, |manifest| manifest)?;
        Ok(shard)
    }

    /// Opens from one manifest: the working copy from the cache or the
    /// snapshot, and the batches after it.
    fn open_from(
        name: &str,
        path: &Path,
        probe: &Remote,
        manifest: Manifest,
    ) -> Result<Opened, Missed> {
        let base = manifest.base();
        let run_positions: Vec<Position> = manifest
            .runs
            .iter()
            .flat_map(|run| (run.first..=run.last).map(move |seq| (run.epoch, seq)))
            .collect();
        // The working copy in the cache, if its position is in the history.
        let cached = if path.exists() {
            SqliteStore::open_with(path, 1, Durability::Cache)
                .ok()
                .and_then(|store| {
                    let position = ready(store.get(META_POSITION))
                        .ok()?
                        .and_then(|bytes| format::decode_position(&bytes))
                        .unwrap_or((0, 0));
                    let usable = position == base
                        || run_positions.contains(&position)
                        || (position.0 == manifest.epoch && position.1 >= manifest.next);
                    usable.then_some((store, position))
                })
        } else {
            None
        };
        // At once: the snapshot, if the working copy is not usable; the
        // runs after the working copy's position; and the first batch of the
        // manifest's epoch after it.
        let (cached, from) = match cached {
            Some((store, position)) => (Some(store), position),
            None => (None, base),
        };
        let in_tail = from.0 == manifest.epoch && from.1 >= manifest.next;
        let tail_from = if in_tail { from.1 + 1 } else { manifest.next };
        let after: Vec<Position> = if in_tail {
            Vec::new()
        } else {
            run_positions
                .iter()
                .copied()
                .filter(|&position| position > from)
                .collect()
        };
        let snapshot = manifest.snapshot.filter(|_| cached.is_none());
        let mut names: Vec<String> = after.iter().map(|&position| log_key(position)).collect();
        names.push(log_key((manifest.epoch, tail_from)));
        let mut fetched = probe.get_all(&names)?.into_iter();
        let store = match cached {
            Some(store) => store,
            None => {
                // The snapshot goes to a file of its own as it arrives,
                // then takes the working copy's place.
                let partial = path.with_extension("partial");
                if let Some(snapshot) = snapshot
                    && !probe.get_file(&snapshot_key(snapshot.position), &partial)?
                {
                    return Err(Missed::Gone);
                }
                remove_database(path);
                if snapshot.is_some() {
                    std::fs::rename(&partial, path)
                        .map_err(|e| StoreError::new(format!("{}: {e}", path.display())))?;
                }
                SqliteStore::open_with(path, 1, Durability::Cache)?
            }
        };
        let mut batches = Vec::new();
        for &position in &after {
            let bytes = fetched.next().flatten().ok_or(Missed::Gone)?;
            batches.push((position, bytes));
        }
        if let Some(bytes) = fetched.next().flatten() {
            batches.push(((manifest.epoch, tail_from), bytes));
            batches.extend(probe.probe(manifest.epoch, tail_from + 1)?);
        }
        let last_tail = batches
            .iter()
            .rev()
            .find(|(position, _)| position.0 == manifest.epoch && position.1 >= manifest.next)
            .map(|(position, _)| position.1)
            .or_else(|| in_tail.then_some(from.1));
        let mut applied = from;
        let mut kept = manifest.reading;
        #[cfg(test)]
        let mut applied_log = Vec::new();
        for (position, bytes) in &batches {
            let batch = Batch::decode(bytes)
                .ok_or_else(|| StoreError::new(format!("{name}: a batch that does not read")))?;
            apply(&store, *position, &batch)?;
            #[cfg(test)]
            applied_log.push(*position);
            applied = *position;
            if batch.reading.is_some() {
                kept = batch.reading;
            }
        }
        // Every batch after the snapshot counts toward the next fold, those
        // the working copy held already too.
        let count =
            run_positions.len() as u64 + last_tail.map_or(0, |last| last + 1 - manifest.next);
        let bytes = batches.iter().map(|(_, bytes)| bytes.len() as u64).sum();
        if kept.is_none() {
            kept = ready(store.get(META_READING))?.and_then(|bytes| format::decode_reading(&bytes));
        }
        Ok(Opened {
            store,
            manifest,
            applied,
            adopted: (count, bytes),
            last_tail,
            kept,
            #[cfg(test)]
            applied_log,
        })
    }

    fn assemble(
        name: &str,
        path: PathBuf,
        remote: Option<Remote>,
        opened: Opened,
        manifest_written: bool,
        own_timeline: bool,
        clock: NodeClock,
    ) -> Arc<Self> {
        let node = node_reading(&clock);
        let timeline = own_timeline
            .then(|| Timeline::start(opened.kept, node.wall.or_else(wall_now), node.timeline));
        Arc::new(Self {
            name: name.to_owned(),
            store: opened.store,
            path,
            remote,
            clock,
            state: Mutex::new(State {
                applied: opened.applied,
                next_seq: 1,
                manifest: opened.manifest,
                manifest_written,
                generation: 0,
                adopted: opened.adopted,
                own: Vec::new(),
                snapshot_bytes: 0,
                folding: None,
                broken: false,
                releasing: false,
                timeline,
                kept_at: node.timeline,
                last_use: node.timeline,
                checked_at: node.timeline,
                wrote: false,
                #[cfg(test)]
                applied_log: opened.applied_log,
            }),
            manifests: Mutex::new(()),
            writing: Mutex::new(()),
        })
    }

    /// Writes a new manifest generation: `change` makes it from the last,
    /// with the shard's reading now. The manifest is read back: one with
    /// another nonce means another writer holds the shard, which then
    /// breaks. Returns the manifest written and its key, once the bucket
    /// holds it.
    fn write_manifest(
        &self,
        node: &Reading,
        change: impl FnOnce(Manifest) -> Manifest,
    ) -> Result<(Manifest, String), StoreError> {
        let Some(remote) = &self.remote else {
            return Ok((self.lock().manifest.clone(), String::new()));
        };
        let _order = self
            .manifests
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (manifest, generation) = {
            let mut state = self.lock();
            if state.broken {
                return Err(StoreError::new(format!("{}: opens again", self.name)));
            }
            state.generation += 1;
            let mut manifest = change(state.manifest.clone());
            manifest.reading = Some(read_timeline(&mut state.timeline, node));
            manifest.nonce = remote.nonce;
            (manifest, state.generation)
        };
        let key = manifest_key(remote.epoch, generation);
        let bytes = manifest.encode();
        let written = remote
            .put(&key, bytes.clone())
            .and_then(|()| match remote.get(&key)? {
                Some(back) if back == bytes => Ok(()),
                _ => Err(StoreError::new(format!(
                    "{}: another writer holds the shard",
                    self.name
                ))),
            });
        let mut state = self.lock();
        match written {
            Ok(()) => {
                state.manifest = manifest.clone();
                state.manifest_written = true;
                state.kept_at = node.timeline;
                Ok((manifest, remote.key(&key)))
            }
            Err(error) => {
                if error.message().contains("another writer") {
                    crate::util::log(format_args!("{error}: it writes nothing more"));
                    state.broken = true;
                }
                Err(error)
            }
        }
    }

    /// Takes the shard's timeline up from a reading another peer kept of
    /// it, as from its own last kept reading (overview.md, 6.7 Clocks of a
    /// replicated peer): for a shard handed over to this peer, before its
    /// first batch. A shard that reads the node's timeline is left as it
    /// is.
    pub(crate) fn take_up(&self, kept: Reading) {
        let node = node_reading(&self.clock);
        let mut state = self.lock();
        if state.timeline.is_some() {
            state.timeline = Some(Timeline::start(
                Some(kept),
                node.wall.or_else(wall_now),
                node.timeline,
            ));
        }
    }

    /// The shard's reading at the node's reading `node`.
    pub(crate) fn reading(&self, node: &Reading) -> Reading {
        read_timeline(&mut self.lock().timeline, node)
    }

    /// Marks a use, at the node's timeline.
    pub(crate) fn touch(&self, now: u64) {
        let mut state = self.lock();
        state.last_use = state.last_use.max(now);
    }

    /// The node's timeline at the last use.
    pub(crate) fn last_use(&self) -> u64 {
        self.lock().last_use
    }

    /// Whether the shard is broken, and opens again before its next use.
    pub(crate) fn broken(&self) -> bool {
        self.lock().broken
    }

    /// Whether the shard's last kept reading is at least `every` seconds
    /// old on the node's timeline.
    pub(crate) fn reading_due(&self, now: u64, every: u64) -> bool {
        now.saturating_sub(self.lock().kept_at) >= every
    }

    /// Whether an expectation holds against the working copy.
    pub(crate) fn holds(&self, address: &[u8], record: Option<&[u8]>) -> Result<bool, StoreError> {
        Ok(ready(self.store.get(address))?.as_deref() == record)
    }

    /// Prepares a batch of changes: with a bucket, its key and bytes, and
    /// the shard's first manifest written if the bucket holds none.
    ///
    /// # Errors
    ///
    /// If the shard is broken, or its first manifest is not written.
    pub(crate) fn prepare(&self, batch: Batch, node: &Reading) -> Result<Pending, StoreError> {
        let first = {
            let state = self.lock();
            if state.broken || state.releasing {
                return Err(StoreError::new(format!("{}: opens again", self.name)));
            }
            !state.manifest_written
        };
        if first && self.remote.is_some() {
            self.write_manifest(node, |manifest| manifest)
                .inspect_err(|_| {
                    self.lock().broken = true;
                })?;
        }
        let mut state = self.lock();
        let mut batch = batch;
        batch.reading = Some(read_timeline(&mut state.timeline, node));
        state.last_use = state.last_use.max(node.timeline);
        let Some(remote) = &self.remote else {
            return Ok(Pending {
                key: None,
                bytes: Vec::new(),
                seq: 0,
                batch,
            });
        };
        let seq = state.next_seq;
        state.next_seq += 1;
        let bytes = batch.encode();
        Ok(Pending {
            key: Some(remote.key(&log_key((remote.epoch, seq)))),
            bytes,
            seq,
            batch,
        })
    }

    /// Gives back a prepared batch that will not be sent, so that the log
    /// keeps no gap: the shard's seqs follow each other.
    pub(crate) fn abandon(&self, pending: Pending) {
        let mut state = self.lock();
        if self.remote.is_some() && pending.seq + 1 == state.next_seq {
            state.next_seq = pending.seq;
        } else if self.remote.is_some() {
            state.broken = true;
        }
    }

    /// Whether this node may send the shard's batches now.
    pub(crate) fn may_write(&self) -> bool {
        !self.broken()
            && self
                .remote
                .as_ref()
                .is_none_or(|remote| remote.fence.may_write(remote.epoch))
    }

    /// Ends a prepared batch: once the bucket holds it (`sent`), and this
    /// node still holds the shard, applies it to the working copy, which
    /// lets the batch be acknowledged. A batch that was not sent, or whose
    /// shard this node lost meanwhile, breaks the shard, since the bucket
    /// may hold it or not.
    ///
    /// # Errors
    ///
    /// The send's failure, the loss of the shard, or the working copy's.
    pub(crate) fn finish(
        &self,
        pending: Pending,
        sent: Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let sent = sent.and_then(|()| {
            if self.may_write() {
                Ok(())
            } else {
                Err(not_held())
            }
        });
        if let Err(error) = sent {
            self.lock().broken = true;
            return Err(error);
        }
        let position = match &self.remote {
            Some(remote) => (remote.epoch, pending.seq),
            None => (0, 0),
        };
        if let Err(error) = apply(&self.store, position, &pending.batch) {
            self.lock().broken = true;
            return Err(error);
        }
        let mut state = self.lock();
        state.applied = position;
        state.kept_at = state.kept_at.max(state.last_use);
        #[cfg(test)]
        state.applied_log.push(position);
        if self.remote.is_some() {
            state.own.push((pending.seq, pending.bytes.len() as u64));
            // The node's timeline reading, kept every minute whether or not
            // anything happens, is nothing another writer could lose: it
            // does not make an idle node check its manifests every minute.
            state.wrote |= !keeps_timeline_only(&pending.batch);
        }
        Ok(())
    }

    /// Whether the log after the snapshot has grown enough to fold: to
    /// `batches` batches, or to half the snapshot's bytes and at least
    /// `min` bytes.
    pub(crate) fn wants_fold(&self, batches: u64, min: u64) -> bool {
        let state = self.lock();
        if self.remote.is_none() || state.folding.is_some() || state.broken {
            return false;
        }
        let count = state.adopted.0 + state.own.len() as u64;
        let bytes = state.adopted.1 + state.own.iter().map(|(_, b)| b).sum::<u64>();
        count >= batches || bytes >= min.max(state.snapshot_bytes / 2)
    }

    /// Whether any batch follows the snapshot.
    fn has_log(state: &State) -> bool {
        state.adopted.0 > 0 || !state.own.is_empty()
    }

    /// Starts a fold on the bucket's runtime, unless one is under way:
    /// [`Self::fold`].
    pub(crate) fn start_fold(self: &Arc<Self>) {
        let Some(remote) = &self.remote else {
            return;
        };
        let mut state = self.lock();
        if state.folding.is_some() || state.broken {
            return;
        }
        let shard = self.clone();
        state.folding = Some(remote.io.spawn_blocking(move || {
            if let Err(error) = shard.fold() {
                crate::util::log(format_args!(
                    "{}: a snapshot was not kept: {error}",
                    shard.name
                ));
            }
        }));
    }

    /// A fold: a reader's consistent copy of the working copy, streamed to
    /// the bucket as the snapshot of the position it holds; the manifest
    /// that names it, taken in once the bucket holds it; then, at best, the
    /// objects that manifest no longer reads deleted, which a later fold
    /// tries again. Commits go on meanwhile. Blocking.
    fn fold(&self) -> Result<(), StoreError> {
        let Some(remote) = &self.remote else {
            return Ok(());
        };
        let random = crate::util::hex(
            &*frasil_crypto::random_bytes::<8>()
                .map_err(|_| StoreError::new("no randomness for a copy's name"))?,
        );
        let copy = self.path.with_extension(format!("copy-{random}"));
        let made = (|| {
            self.store.copy_into(&copy)?;
            let position = SqliteStore::read_file(&copy, META_POSITION)?
                .and_then(|bytes| format::decode_position(&bytes))
                .unwrap_or((0, 0));
            let size = std::fs::metadata(&copy)
                .map_err(|e| StoreError::new(format!("{}: {e}", copy.display())))?
                .len();
            if !remote.fence.may_write(remote.epoch) {
                return Err(not_held());
            }
            let bucket = remote.io.bucket();
            let key = remote.key(&snapshot_key(position));
            let file = copy.clone();
            remote
                .io
                .block({
                    let fence = remote.fence.clone();
                    let epoch = remote.epoch;
                    async move {
                        if !fence.may_write(epoch) {
                            return Err(BucketError("this node no longer holds the shard".into()));
                        }
                        bucket.put_file(&key, &file).await
                    }
                })
                .map_err(bucket_failed)?;
            Ok((position, size))
        })();
        let _ = std::fs::remove_file(&copy);
        let (position, size) = made?;
        let epoch = remote.epoch;
        let node = node_reading(&self.clock);
        let (_, key) = self.write_manifest(&node, |manifest| Manifest {
            snapshot: Some(SnapshotRef {
                position,
                bytes: size,
            }),
            runs: Vec::new(),
            next: if position.0 == epoch {
                position.1 + 1
            } else {
                1
            },
            ..manifest
        })?;
        {
            let mut state = self.lock();
            state.own.retain(|(seq, _)| (epoch, *seq) > position);
            state.adopted = (0, 0);
            state.snapshot_bytes = size;
        }
        let written = format::parse_key(key.strip_prefix(remote.root.as_str()).unwrap_or(&key))
            .map(|(_, at)| at)
            .unwrap_or((epoch, 0));
        self.clean_up(position, written);
        Ok(())
    }

    /// Deletes, at best, what the shard's manifest no longer reads: earlier
    /// snapshots, batches up to the snapshot, batches of earlier epochs
    /// after it, which landed after their tail was recorded, and earlier
    /// manifests. Only while this node holds the shard, by its fence and by
    /// the latest manifest, which must be its own; and nothing of a later
    /// epoch, nor anything a later owner's manifest could name that this
    /// node's latest manifest does not cover. A failure is left for a later
    /// fold.
    fn clean_up(&self, position: Position, manifest: Position) {
        let Some(remote) = &self.remote else {
            return;
        };
        let epoch = remote.epoch;
        if !self.may_write() || self.latest_is_ours() != Some(true) {
            crate::util::log(format_args!(
                "{}: not cleaned up: this node may no longer hold the shard",
                self.name
            ));
            return;
        }
        let keys = match remote.list("") {
            Ok(keys) => keys,
            Err(error) => {
                crate::util::log(format_args!("{}: not cleaned up: {error}", self.name));
                return;
            }
        };
        let stale: Vec<String> = keys
            .into_iter()
            .filter(|key| match format::parse_key(key) {
                Some((Kind::Log, at)) => at <= position || at.0 < epoch,
                Some((Kind::Snapshot, at)) => at < position,
                Some((Kind::Manifest, at)) => at < manifest,
                None => false,
            })
            .map(|key| remote.key(&key))
            .collect();
        let bucket = remote.io.bucket();
        let fence = remote.fence.clone();
        let failed = remote.io.block(async move {
            let mut failed = 0;
            for key in stale {
                // Checked again before each request, so that no deletion
                // is issued once this node may no longer write.
                if !fence.may_write(epoch) {
                    failed += 1;
                    continue;
                }
                if bucket.delete(&key).await.is_err() {
                    failed += 1;
                }
            }
            failed
        });
        if failed > 0 {
            crate::util::log(format_args!(
                "{}: {failed} objects left for the next fold",
                self.name
            ));
        }
    }

    /// Waits for a fold under way.
    pub(crate) fn settle_fold(&self) {
        let Some(remote) = &self.remote else {
            return;
        };
        let folding = self.lock().folding.take();
        if let Some(task) = folding {
            remote.io.join(task);
        }
    }

    /// Whether a fold has ended and waits to be taken off.
    pub(crate) fn fold_done(&self) -> bool {
        self.lock()
            .folding
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
    }

    /// Whether a fold is under way.
    fn folding(&self) -> bool {
        self.lock()
            .folding
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    /// Keeps the shard's reading: with a bucket, a new manifest generation
    /// on the bucket's runtime, unless a fold is under way, which keeps one
    /// itself, or the bucket holds no manifest yet; in a data directory, the
    /// reading in the working copy. Returns at once.
    pub(crate) fn keep_reading(self: &Arc<Self>) {
        let node = node_reading(&self.clock);
        let Some(remote) = &self.remote else {
            let reading = self.reading(&node);
            let commit = Commit::new(
                vec![(META_READING.to_vec(), format::encode_reading(&reading))],
                Vec::new(),
            );
            if ready(self.store.commit(&commit)).is_ok() {
                self.lock().kept_at = node.timeline;
            }
            return;
        };
        {
            let mut state = self.lock();
            if state.broken || !state.manifest_written {
                return;
            }
            // Not again until this one is written, or a minute has passed.
            state.kept_at = node.timeline;
        }
        if self.folding() {
            return;
        }
        let shard = self.clone();
        drop(remote.io.spawn_blocking(move || {
            if let Err(error) = shard.write_manifest(&node, |manifest| manifest) {
                crate::util::log(format_args!(
                    "{}: the reading was not kept: {error}",
                    shard.name
                ));
            }
        }));
    }

    /// Checks, on the bucket's runtime, that no other writer holds the
    /// shard, if it wrote since the last check `every` seconds ago or more:
    /// the latest manifest is of this node's epoch and holds its nonce.
    /// One that is not breaks the shard. Returns at once.
    pub(crate) fn check_holder(self: &Arc<Self>, every: u64) {
        let Some(remote) = &self.remote else {
            return;
        };
        let now = node_reading(&self.clock).timeline;
        {
            let mut state = self.lock();
            if state.broken
                || !state.wrote
                || !state.manifest_written
                || now.saturating_sub(state.checked_at) < every
            {
                return;
            }
            state.wrote = false;
            state.checked_at = now;
        }
        let shard = self.clone();
        drop(remote.io.spawn_blocking(move || shard.check_now()));
    }

    /// [`Self::check_holder`], now and blocking: whether this node still
    /// holds the shard. A shard that cannot tell is left as it is.
    pub(crate) fn check_now(&self) -> bool {
        match self.latest_is_ours() {
            Some(ours) => ours,
            None => !self.broken(),
        }
    }

    /// Whether the latest manifest in the bucket is of this node's epoch
    /// and holds its nonce; none if the bucket does not tell. One that is
    /// not breaks the shard. Blocking.
    fn latest_is_ours(&self) -> Option<bool> {
        let Some(remote) = &self.remote else {
            return Some(true);
        };
        let latest = remote.list(MANIFEST_PREFIX).ok().map(|keys| {
            keys.iter()
                .filter_map(|key| match format::parse_key(key) {
                    Some((Kind::Manifest, at)) => Some(at),
                    _ => None,
                })
                .max()
        })?;
        let (epoch, generation) = latest?;
        let ours = epoch == remote.epoch
            && remote
                .get(&manifest_key(epoch, generation))
                .ok()?
                .and_then(|bytes| Manifest::decode(&bytes))
                .is_some_and(|manifest| manifest.nonce == remote.nonce);
        if !ours {
            crate::util::log(format_args!(
                "{}: another writer holds the shard: it writes nothing more",
                self.name
            ));
            self.lock().broken = true;
        }
        Some(ours)
    }

    /// Closes the shard: it takes no batch more, and the batch under way
    /// ends first, as in [`Self::release`]; then it waits for a fold under
    /// way; with a bucket, folds what follows the snapshot, or keeps the
    /// reading in a manifest if anything has been written; in a data
    /// directory, keeps the reading. A broken shard writes nothing. The
    /// shard is broken after, so that a writer that still holds it opens
    /// it again. Blocking.
    ///
    /// # Errors
    ///
    /// If what it writes is not written; the shard is closed all the same.
    pub(crate) fn close(self: &Arc<Self>) -> Result<(), StoreError> {
        self.lock().releasing = true;
        let _turn = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = self.close_held();
        self.lock().broken = true;
        outcome
    }

    /// [`Self::close`], with the writing turn held.
    fn close_held(&self) -> Result<(), StoreError> {
        self.settle_fold();
        if self.broken() {
            return Ok(());
        }
        let node = node_reading(&self.clock);
        let Some(_) = &self.remote else {
            let reading = self.reading(&node);
            let commit = Commit::new(
                vec![(META_READING.to_vec(), format::encode_reading(&reading))],
                Vec::new(),
            );
            return ready(self.store.commit(&commit)).map(|_| ());
        };
        let (written, log) = {
            let state = self.lock();
            (state.manifest_written, Self::has_log(&state))
        };
        if log {
            return self.fold();
        }
        if written {
            self.write_manifest(&node, |manifest| manifest)?;
        }
        Ok(())
    }

    /// Whether the shard is being closed or given up: it takes no batch,
    /// and a writer looks it up again.
    pub(crate) fn closing(&self) -> bool {
        self.lock().releasing
    }

    /// The epoch this node opened the shard under, with a bucket.
    pub(crate) fn epoch(&self) -> Option<u64> {
        self.remote.as_ref().map(|remote| remote.epoch)
    }

    /// Gives the shard up to another node: it takes no batch more, the
    /// batch under way ends, and, if the bucket holds a manifest of this
    /// node's, a last one keeps the shard's reading, as a timed write. No
    /// fold: the next owner folds. The shard is broken after, whatever the
    /// manifest's outcome, since the next owner reads the log in any case.
    /// Blocking.
    ///
    /// # Errors
    ///
    /// If the last manifest is not written.
    pub(crate) fn release(&self) -> Result<(), StoreError> {
        self.lock().releasing = true;
        let _turn = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let (broken, written) = {
            let state = self.lock();
            (state.broken, state.manifest_written)
        };
        let outcome = if broken || !written || self.remote.is_none() {
            Ok(())
        } else {
            let node = node_reading(&self.clock);
            self.write_manifest(&node, |manifest| manifest).map(|_| ())
        };
        self.lock().broken = true;
        outcome
    }

    /// Breaks the shard at once, writing nothing: a node that must not
    /// write it any more.
    pub(crate) fn discard(&self) {
        self.lock().broken = true;
    }

    /// Every position applied to this working copy since it opened.
    #[cfg(test)]
    pub(crate) fn applied_log(&self) -> Vec<Position> {
        self.lock().applied_log.clone()
    }
}

/// Whether a batch only keeps the node's timeline reading.
fn keeps_timeline_only(batch: &Batch) -> bool {
    matches!(
        batch.changes.as_slice(),
        [(address, Some(_))] if *address == crate::records::Records::timeline_address()
    )
}

/// The history `latest` names, opened from `older`'s snapshot instead of
/// its own: if that snapshot is at a batch `latest` names, the batches
/// `latest` names after it.
fn rebase(latest: &Manifest, older: &Manifest) -> Option<Manifest> {
    let snapshot = older.snapshot?;
    let at = snapshot.position;
    let named = latest
        .runs
        .iter()
        .any(|run| run.epoch == at.0 && run.first <= at.1 && at.1 <= run.last);
    if !named {
        return None;
    }
    let runs = latest
        .runs
        .iter()
        .filter_map(|run| match run.epoch.cmp(&at.0) {
            core::cmp::Ordering::Less => None,
            core::cmp::Ordering::Equal => (run.last > at.1).then_some(Run {
                first: run.first.max(at.1 + 1),
                ..*run
            }),
            core::cmp::Ordering::Greater => Some(*run),
        })
        .collect();
    Some(Manifest {
        snapshot: Some(snapshot),
        runs,
        ..latest.clone()
    })
}

/// Applies a batch to a working copy, with its position and reading.
fn apply(store: &SqliteStore, position: Position, batch: &Batch) -> Result<(), StoreError> {
    let mut puts = Vec::with_capacity(batch.changes.len() + 2);
    let mut deletes = Vec::new();
    for (address, record) in &batch.changes {
        match record {
            Some(record) => puts.push((address.clone(), record.clone())),
            None => deletes.push(address.clone()),
        }
    }
    puts.push((META_POSITION.to_vec(), format::encode_position(position)));
    if let Some(reading) = &batch.reading {
        puts.push((META_READING.to_vec(), format::encode_reading(reading)));
    }
    if ready(store.commit(&Commit::new(puts, deletes)))? {
        Ok(())
    } else {
        Err(StoreError::new("a batch was refused"))
    }
}
