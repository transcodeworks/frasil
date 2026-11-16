//! The peer's records in shards: each a part of its state that one machine
//! keeps at a time, with a timeline of its own (overview.md, 6.7 Clocks of
//! a replicated peer), and one SQLite working copy on local disk.
//!
//! # Shards
//!
//! - **A library** (ext-libraries.md) is one shard, `libraries/<id>`, with
//!   the library ID's UTF-8 in hex: every record of each space a ticket
//!   attached to it when the peer took the space up.
//! - **Spaces of no library**, and those of the operator's open library,
//!   are sharded by a hash of the space ID, `spaces/<2 hex>`.
//! - What belongs to no library is sharded by hash, 16 ways each: the
//!   **space index** (`index/<hex>`: which spaces the peer hosts and in
//!   which shard, wait markers, tombstones, moves under way, departure
//!   records, and ext-libraries' settings,
//!   attachments, tickets, deletions, detachments and holds), **device
//!   mailboxes** by address (`mailboxes/<hex>`), **invite drops** by
//!   address (`drops/<hex>`), and **exchange mailboxes** by address
//!   (`exchange/<hex>`). A mailbox's claim is beside its items, and a
//!   spent deposit token (ext-deposit-tokens.md) in the mailbox shard its
//!   nonce names; the deposit keys are in `index/0`, and a library's
//!   allowance window and the grants it used beside its settings.
//!
//! A space stays in the shard the index names for it, whatever later
//! happens to its attachment, until a move takes it elsewhere.
//!
//! # Where the copy of record is
//!
//! In a **data directory**, each shard's SQLite file is the copy of record,
//! under `shards/`. In a **bucket**, the copy of record is the shard's
//! manifest, snapshots and log under `<shard>/` (module `format`), and the
//! SQLite file is a working copy in the cache directory: a group's changes
//! to a shard are one batch, acknowledged only once the bucket holds it.
//! The layout is the same either way.
//!
//! # Commits across shards
//!
//! Each shard's part of a group of commits is one atomic step. A commit
//! that touches several shards is made shard by shard, so that the index
//! never names what is not at rest: the shards that keep a space's records
//! first, then the hashed shards, and the other way round for a commit that
//! deletes a space's records. A group whose commits go both ways is made in
//! runs, one way at a time.
//!
//! A commit with expectations names them all in one hashed shard. Its
//! records in shards of spaces are made first; then its part of that
//! shard, only if each expectation holds there, checked and made in one
//! step by the node that keeps the shard, which makes such parts one at a
//! time; then its other hashed parts. So of two commits that each expect a
//! space's index entry absent, one is made. A commit that is not made
//! leaves what it wrote in a shard of spaces, for a space the index places
//! in another shard; such records are collected as that shard opens.
//!
//! # Timelines
//!
//! Each library's and each hashed space shard keeps a timeline of its own,
//! taken up from its last kept reading as overview.md, 6.7 says. On one
//! node, the hashed shards of the index, mailboxes, drops and exchange are
//! taken up together when the node starts, and read the node's timeline.
//!
//! # In a cluster
//!
//! With an [`Ownership`](fence::Ownership), a node opens only the shards it
//! owns, once the nodes that kept them before have given them up. A record
//! of a hashed shard another node owns is read from that node, and a batch
//! of one is made by it, in one step, under its lease: so the index, the
//! mailboxes, the drops and the exchange each have one writer however many
//! nodes commit to them. A shard this node no longer owns is closed, which
//! folds or keeps its manifest, before the node confirms the new epoch.

pub mod bucket;
pub mod fence;
pub mod format;
mod shard;
#[cfg(test)]
mod tests;

use crate::clock::Clock;
use crate::records::{
    ARRIVAL, CLAIM, DEPARTURE, DEPOSIT_KEY, DROP, DROP_AT, EXCHANGE, HOSTED, JOURNAL, LIBRARY,
    MAILBOX, META, MOVE, OBJECT, OFFSET, SNAPSHOT, SPENT, TOMBSTONE, USAGE, WAITS,
};
use bucket::BucketIo;
use fence::{Fence, Ownership};
use format::Batch;
use frasil_base::time::Reading;
use frasil_store::store::Records as Found;
use frasil_store::{BoxFuture, Commit, Store, StoreError};
use shard::{Opening, Pending, Shard};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};

/// The hashed families, and how many shards each has.
const INDEX: &str = "index";
const MAILBOXES: &str = "mailboxes";
const DROPS: &str = "drops";
const EXCHANGES: &str = "exchange";
const SPACES: &str = "spaces";
const LIBRARIES: &str = "libraries";
/// Shards of each family that belongs to no space.
#[cfg(not(test))]
pub(crate) const HASHED: usize = 16;
/// Fewer in this crate's tests, which start many nodes.
#[cfg(test)]
pub(crate) const HASHED: usize = 2;
/// Shards of spaces of no library.
const SPACE_SHARDS: usize = 256;
/// The shard of the deposit keys (ext-deposit-tokens.md, 3.10 In a
/// cluster): the first of the index's, beside the kept reading.
pub(crate) const KEYS_SHARD: &str = "index/0";
/// The records a space keeps in its shard, each by its prefix and the
/// space ID.
pub(crate) const SPACE_PREFIXES: [u8; 6] = [JOURNAL, SNAPSHOT, OBJECT, USAGE, OFFSET, ARRIVAL];

/// How often a shard keeps its reading while it is open, at least.
const KEEP_EVERY: u64 = 60;
/// How often, in seconds, at least, a shard that writes checks that no
/// other writer holds it. Under a fence that reads less often, as often as
/// the fence: another writer stops this node by then, and a check costs a
/// LIST and a GET.
const CHECK_EVERY: u64 = 10;

/// The node's clock, once it is set: what each shard's timeline counts
/// from.
pub(crate) type NodeClock = Arc<OnceLock<Arc<dyn Clock>>>;

/// The node's reading now, or a reading at 0 before its clock is set.
pub(crate) fn node_reading(clock: &NodeClock) -> Reading {
    clock.get().map_or(
        Reading {
            timeline: 0,
            wall: crate::clock::wall_now(),
            run: 1,
        },
        |clock| clock.now(),
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The shard of `key` among `count` of a family: the first two bytes of
/// SHA-256 over a label, the family and the key.
fn hashed(family: &str, key: &[u8], count: usize) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"frasil-relay/shard/v1\0");
    hash.update(family.as_bytes());
    hash.update([0]);
    hash.update(key);
    let digest = hash.finalize();
    let n = usize::from(u16::from_be_bytes([digest[0], digest[1]])) % count;
    if count <= 16 {
        format!("{family}/{n:x}")
    } else {
        format!("{family}/{n:02x}")
    }
}

/// The shard of a space of no library, or of the operator's open library.
pub(crate) fn space_shard(space: &[u8; 32]) -> String {
    hashed(SPACES, space, SPACE_SHARDS)
}

/// The shard of a library.
pub(crate) fn library_shard(library: &str) -> String {
    format!("{LIBRARIES}/{}", crate::util::hex(library.as_bytes()))
}

/// The shard a space's entry in the index names, if it is one this peer
/// makes.
fn hosted_shard(record: &[u8]) -> Option<String> {
    crate::records::Records::hosted_shard(record).filter(|shard| valid_name(shard))
}

/// Whether a shard's name is one this peer makes.
fn valid_name(name: &str) -> bool {
    let Some((family, rest)) = name.split_once('/') else {
        return false;
    };
    let hex = !rest.is_empty() && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    match family {
        INDEX | MAILBOXES | DROPS | EXCHANGES => hex && rest.len() == 1,
        SPACES => hex && rest.len() == 2,
        LIBRARIES => hex && rest.len() % 2 == 0 && rest.len() <= 256,
        _ => false,
    }
}

/// Whether a shard is one of the hashed families that belong to no space:
/// always open, on the node's timeline.
fn is_hashed(name: &str) -> bool {
    [INDEX, MAILBOXES, DROPS, EXCHANGES].iter().any(|family| {
        name.strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Every shard of a hashed family.
fn family(name: &str) -> Vec<String> {
    (0..HASHED).map(|n| format!("{name}/{n:x}")).collect()
}

/// The working copy's file name for a shard.
fn file_name(name: &str) -> String {
    if name.len() <= 100 {
        format!("{}.sqlite", name.replace('/', "-"))
    } else {
        use sha2::{Digest, Sha256};
        let (family, _) = name.split_once('/').unwrap_or((name, ""));
        let digest = Sha256::digest(name.as_bytes());
        format!("{family}-h{}.sqlite", crate::util::hex(&digest))
    }
}

/// A space's offset record: the shard's reading and the space's at its
/// move in.
type Offset = (u64, u64);

/// A shard's changes in one batch: each address, with its record or none.
type Changes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// An address of a commit, routed: its shard, the address, and its record
/// or none.
type Routed = (String, Vec<u8>, Option<Vec<u8>>);

/// A batch's PUT: its key, its bytes, and its shard, which checks again as
/// the request starts that it may still be written.
type Upload = (String, Vec<u8>, Arc<Shard>);

/// Where a record or a scan goes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// One shard.
    One(String),
    /// Every shard of a hashed family.
    Family(&'static str),
}

/// Where the copy of record is.
enum Layout {
    Local {
        dir: PathBuf,
    },
    Bucket {
        io: Arc<BucketIo>,
        cache: PathBuf,
        fence: Arc<dyn Fence>,
    },
}

/// The peer's shards: a [`Store`] that routes each record to its shard.
///
/// Its calls block, the bucket's requests included: like the SQLite store's,
/// its futures are ready when first polled, and are run off the async
/// runtime's workers (crate `writer`, crate `records`).
pub struct Shards {
    layout: Layout,
    open: Mutex<BTreeMap<String, Arc<Shard>>>,
    /// One lock per shard name, held while it opens or closes.
    lifecycle: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Each hosted space's shard, as the index names it.
    placement: RwLock<HashMap<[u8; 32], String>>,
    /// A test's hold between a reading of the placements and its taking
    /// effect.
    #[cfg(test)]
    placements_hold: Mutex<Option<Arc<tests::Hold>>>,
    clock: NodeClock,
    idle_close: AtomicU64,
    opens: AtomicU64,
    /// When a shard folds: its batches after the snapshot, and its bytes.
    fold: (AtomicU64, AtomicU64),
    /// The greatest epoch this node opened each shard under.
    epochs: Mutex<HashMap<String, u64>>,
    /// Whether the hashed shards are open and the placements read.
    started: AtomicBool,
    /// Shards of spaces whose records of erased spaces the writer's next
    /// maintenance collects.
    to_collect: Mutex<Vec<String>>,
    /// What a walk off the writer's thread found to collect: by shard, each
    /// space and the addresses it keeps there.
    collected: Mutex<Vec<(String, Vec<Collectable>)>>,
    /// In a cluster: which shards this node keeps.
    ownership: Option<Arc<dyn Ownership>>,
    /// Held to read by each open from its check of ownership to its entry
    /// among the open shards, and to write by [`Shards::barrier`]: so a
    /// change of epoch sees every shard an open under the old one made.
    opening: RwLock<()>,
    /// Held while a conditional part of a hashed shard this node keeps is
    /// checked and made (crate `shards`, "Commits across shards").
    conditions: Mutex<()>,
    /// Each space's offset record, as read, for the spaces that moved in
    /// from another shard.
    offsets: Mutex<HashMap<[u8; 32], Option<Offset>>>,
}

impl core::fmt::Debug for Shards {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shards")
            .field("open", &lock(&self.open).len())
            .finish_non_exhaustive()
    }
}

fn io_error(path: &Path, error: std::io::Error) -> StoreError {
    StoreError::new(format!("{}: {error}", path.display()))
}

impl Shards {
    /// Shards in a data directory: each SQLite file under `dir` is a
    /// shard's copy of record.
    ///
    /// # Errors
    ///
    /// If the directory cannot be made, or a hashed shard cannot be opened.
    pub fn local(dir: impl AsRef<Path>) -> Result<Arc<Self>, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
        Self::start(Layout::Local { dir }, None)
    }

    /// Shards whose copy of record is a bucket, with their working copies
    /// in `cache`.
    ///
    /// # Errors
    ///
    /// If the cache cannot be made, or a hashed shard cannot be opened.
    pub fn bucket(
        io: Arc<BucketIo>,
        cache: impl AsRef<Path>,
        fence: Arc<dyn Fence>,
    ) -> Result<Arc<Self>, StoreError> {
        let cache = cache.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache).map_err(|e| io_error(&cache, e))?;
        Self::start(Layout::Bucket { io, cache, fence }, None)
    }

    /// Shards of a node of a cluster, whose copy of record is the region's
    /// bucket: it keeps those `ownership` names (crate `shards`, "In a
    /// cluster").
    ///
    /// # Errors
    ///
    /// If the cache cannot be made, a hashed shard it owns cannot be
    /// opened, or the index cannot be read.
    pub fn clustered(
        io: Arc<BucketIo>,
        cache: impl AsRef<Path>,
        fence: Arc<dyn Fence>,
        ownership: Arc<dyn Ownership>,
    ) -> Result<Arc<Self>, StoreError> {
        let cache = cache.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache).map_err(|e| io_error(&cache, e))?;
        Self::start(Layout::Bucket { io, cache, fence }, Some(ownership))
    }

    /// Opens the hashed shards this node keeps and reads the index's
    /// placements.
    fn start(
        layout: Layout,
        ownership: Option<Arc<dyn Ownership>>,
    ) -> Result<Arc<Self>, StoreError> {
        let shards = Arc::new(Self {
            layout,
            open: Mutex::new(BTreeMap::new()),
            lifecycle: Mutex::new(HashMap::new()),
            placement: RwLock::new(HashMap::new()),
            #[cfg(test)]
            placements_hold: Mutex::new(None),
            clock: Arc::new(OnceLock::new()),
            idle_close: AtomicU64::new(600),
            opens: AtomicU64::new(0),
            fold: (
                AtomicU64::new(shard::FOLD_BATCHES),
                AtomicU64::new(shard::FOLD_MIN),
            ),
            epochs: Mutex::new(HashMap::new()),
            started: AtomicBool::new(false),
            to_collect: Mutex::new(Vec::new()),
            collected: Mutex::new(Vec::new()),
            ownership,
            opening: RwLock::new(()),
            conditions: Mutex::new(()),
            offsets: Mutex::new(HashMap::new()),
        });
        for name in [INDEX, MAILBOXES, DROPS, EXCHANGES]
            .into_iter()
            .flat_map(family)
        {
            if shards.keeps(&name) {
                // In a cluster, a shard opens once the nodes that kept it
                // gave it up, which may take the time of a lease.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    match shards.shard(&name) {
                        Ok(_) => break,
                        Err(_) if shards.ownership.is_some() && !shards.keeps(&name) => break,
                        Err(_)
                            if shards.ownership.is_some()
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        shards.reload_placements()?;
        shards.started.store(true, Ordering::SeqCst);
        Ok(shards)
    }

    /// Reads every placement the index names again: what memory holds is
    /// what the index holds, whichever nodes wrote it.
    ///
    /// # Errors
    ///
    /// If an index shard cannot be read.
    pub fn reload_placements(&self) -> Result<(), StoreError> {
        let before = self.placements_now();
        let mut placement = HashMap::new();
        for (address, record) in self.scan_family(INDEX, &[HOSTED])? {
            let Some(space) = address
                .get(1..33)
                .and_then(|s| <[u8; 32]>::try_from(s).ok())
            else {
                continue;
            };
            if let Some(shard) = hosted_shard(&record) {
                placement.insert(space, shard);
            }
        }
        self.placements_read();
        let mut held = self
            .placement
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *held = since_read(&before, &held, placement, |_| true);
        Ok(())
    }

    /// What memory holds of the placements now.
    fn placements_now(&self) -> HashMap<[u8; 32], String> {
        self.placement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Where a reading of the placements waits, in a test that asked.
    fn placements_read(&self) {
        #[cfg(test)]
        if let Some(hold) = lock(&self.placements_hold).take() {
            hold.wait();
        }
    }

    /// Whether these shards are a node of a cluster.
    pub fn clustered_now(&self) -> bool {
        self.ownership.is_some()
    }

    /// Whether this node keeps a shard: always on one node; in a cluster,
    /// the shards it owns.
    fn keeps(&self, name: &str) -> bool {
        self.ownership.as_ref().is_none_or(|o| o.owns(name))
    }

    /// The node that keeps a hashed shard this one does not, in a cluster.
    fn remote(&self, name: &str) -> Option<&Arc<dyn Ownership>> {
        self.ownership
            .as_ref()
            .filter(|o| is_hashed(name) && !o.owns(name))
    }

    /// Whether this node keeps a shard, by its name.
    pub fn keeps_shard(&self, name: &str) -> bool {
        self.keeps(name)
    }

    /// Whether this node keeps the shard of a space's records.
    pub fn keeps_space(&self, space: &[u8; 32]) -> bool {
        self.space(space).is_some_and(|name| self.keeps(&name))
    }

    /// Whether this node keeps the shard of a mailbox, an exchange mailbox
    /// or a drop of this address: `family` is `mailboxes`, `exchange` or
    /// `drops`.
    pub fn keeps_address(&self, family_name: &str, address: &[u8; 32]) -> bool {
        self.keeps(&hashed(family_name, address, HASHED))
    }

    /// The shard of a hashed family that an address of 32 bytes is kept in.
    pub fn address_shard(family_name: &str, address: &[u8; 32]) -> String {
        hashed(family_name, address, HASHED)
    }

    /// The shard a space's records are in, as far as this node knows: the
    /// index's placement, or the space's hashed shard.
    pub fn space_shard_of(&self, space: &[u8; 32]) -> String {
        self.space(space).unwrap_or_else(|| space_shard(space))
    }

    /// The shard the index names for a space, read from the index's shard,
    /// wherever it is kept: none if the index names none.
    ///
    /// # Errors
    ///
    /// If the index cannot be read.
    pub fn locate(&self, space: &[u8; 32]) -> Result<Option<String>, StoreError> {
        if let Some(placed) = self
            .placement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(space)
            .cloned()
        {
            return Ok(Some(placed));
        }
        let address = crate::records::Records::hosted_address(&frasil_events::EventId(*space));
        let Some(placed) = self.get_now(&address)?.as_deref().and_then(hosted_shard) else {
            return Ok(None);
        };
        self.placement
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*space, placed.clone());
        Ok(Some(placed))
    }

    /// The shard the index names for a space, read from the index's shard
    /// whatever memory holds, and noted: none if the index names none. For
    /// a space that may have moved since memory noted it.
    ///
    /// # Errors
    ///
    /// If the index cannot be read.
    pub fn locate_fresh(&self, space: &[u8; 32]) -> Result<Option<String>, StoreError> {
        let address = crate::records::Records::hosted_address(&frasil_events::EventId(*space));
        let placed = self.get_now(&address)?.as_deref().and_then(hosted_shard);
        let mut placement = self
            .placement
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match &placed {
            Some(shard) => placement.insert(*space, shard.clone()),
            None => placement.remove(space),
        };
        Ok(placed)
    }

    /// Writes and deletes records of one shard of spaces this node keeps,
    /// in one batch, whatever shard the index names for their space: a
    /// move's records arriving, or the records a shard keeps of a space the
    /// index places elsewhere going. Blocking.
    ///
    /// # Errors
    ///
    /// If the shard is hashed, not kept here, or the batch is not made.
    pub fn commit_into(
        &self,
        name: &str,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if is_hashed(name) || !valid_name(name) || !self.keeps(name) {
            return Err(StoreError::new(format!(
                "{name}: not a shard of spaces kept here"
            )));
        }
        let mut changes: Changes = deletes.into_iter().map(|address| (address, None)).collect();
        for (address, record) in puts {
            changes.insert(address, Some(record));
        }
        if changes.is_empty() {
            return Ok(());
        }
        let node = self.node();
        self.write_local(vec![(name.to_owned(), changes)], &node)
    }

    /// The records under a prefix of one shard of spaces this node keeps,
    /// whatever shard the index names for their space. Blocking.
    ///
    /// # Errors
    ///
    /// If the shard is hashed, not kept here, or cannot be read.
    pub fn scan_in(&self, name: &str, prefix: &[u8]) -> Result<Found, StoreError> {
        if is_hashed(name) || !self.keeps(name) {
            return Err(StoreError::new(format!(
                "{name}: not a shard of spaces kept here"
            )));
        }
        shard::ready(self.shard(name)?.store.scan(prefix))
    }

    /// Takes up a shard of spaces handed over from another peer: it holds
    /// no record yet, and its timeline goes on from `kept`, the last
    /// reading the other peer kept of it (peers.md, 3.1 Hosting a space,
    /// "Hand-over"). Blocking.
    ///
    /// # Errors
    ///
    /// If the shard is hashed, not kept here, cannot be opened, or holds a
    /// record already.
    pub fn take_up(&self, name: &str, kept: Reading) -> Result<(), StoreError> {
        for prefix in SPACE_PREFIXES {
            if !self.scan_in(name, &[prefix])?.is_empty() {
                return Err(StoreError::new(format!("{name}: holds records already")));
            }
        }
        self.shard(name)?.take_up(kept);
        Ok(())
    }

    /// Deletes every record a shard of spaces keeps of a space the index
    /// places nowhere: what an import that did not end left, before the
    /// import is made again. Blocking.
    ///
    /// # Errors
    ///
    /// If the shard is hashed, not kept here, or cannot be read or written.
    pub fn clear_unplaced(&self, name: &str) -> Result<(), StoreError> {
        let mut gone = Vec::new();
        let mut unplaced: BTreeMap<[u8; 32], bool> = BTreeMap::new();
        for prefix in SPACE_PREFIXES {
            for (address, _) in self.scan_in(name, &[prefix])? {
                let Some(space) = address
                    .get(1..33)
                    .and_then(|s| <[u8; 32]>::try_from(s).ok())
                else {
                    continue;
                };
                let none = match unplaced.get(&space) {
                    Some(none) => *none,
                    None => {
                        let hosted =
                            crate::records::Records::hosted_address(&frasil_events::EventId(space));
                        let none = self.get_now(&hosted)?.is_none();
                        unplaced.insert(space, none);
                        none
                    }
                };
                if none {
                    gone.push(address);
                }
            }
        }
        if !gone.is_empty() {
            crate::util::log(format_args!(
                "{name}: {} records an import left are cleared",
                gone.len()
            ));
        }
        self.commit_into(name, Vec::new(), gone)
    }

    /// Notes the shard that keeps a space's records, as a move made it,
    /// and forgets the offset noted of the space.
    pub fn set_placement(&self, space: &[u8; 32], shard: &str) {
        self.placement
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*space, shard.to_owned());
        lock(&self.offsets).remove(space);
    }

    /// Where a space's timeline stands against its shard's: the shard's
    /// reading and the space's at its move in, read from its offset record
    /// and noted; none for a space that never moved between shards.
    pub fn space_offset(&self, space: &[u8; 32]) -> Option<(u64, u64)> {
        if let Some(noted) = lock(&self.offsets).get(space) {
            return *noted;
        }
        let address = crate::records::Records::offset_address(&frasil_events::EventId(*space));
        let read = match self.get_now(&address) {
            Ok(record) => record
                .as_deref()
                .and_then(crate::records::Records::read_offset),
            Err(_) => return None,
        };
        lock(&self.offsets).insert(*space, read);
        read
    }

    /// Gives up a shard this node no longer owns: it takes no batch more,
    /// and a last manifest, a timed write, keeps its reading; no fold.
    /// Blocking.
    ///
    /// # Errors
    ///
    /// If the last manifest is not written; the shard is given up all the
    /// same.
    pub fn release(&self, name: &str) -> Result<(), StoreError> {
        let gate = self.lifecycle(name);
        let _held = lock(&gate);
        let Some(shard) = lock(&self.open).remove(name) else {
            return Ok(());
        };
        shard.release()
    }

    /// Breaks a shard and forgets it, writing nothing: a shard this node
    /// opened before an absence from the cluster, which another node may
    /// have written meanwhile.
    pub fn discard(&self, name: &str) {
        let gate = self.lifecycle(name);
        let _held = lock(&gate);
        if let Some(shard) = lock(&self.open).remove(name) {
            shard.discard();
        }
    }

    /// Each open shard and the epoch it was opened under.
    pub fn open_epochs(&self) -> Vec<(String, Option<u64>)> {
        lock(&self.open)
            .iter()
            .map(|(name, shard)| (name.clone(), shard.epoch()))
            .collect()
    }

    /// Whether a shard is open here, and not broken.
    pub fn is_open(&self, name: &str) -> bool {
        lock(&self.open)
            .get(name)
            .is_some_and(|shard| !shard.broken())
    }

    /// Opens every hashed shard this node keeps and has not opened: in a
    /// cluster, once an epoch settles, so that no request waits for the
    /// open. Blocking.
    pub fn open_kept(&self) {
        for name in [INDEX, MAILBOXES, DROPS, EXCHANGES]
            .into_iter()
            .flat_map(family)
        {
            if self.keeps(&name)
                && !self.is_open(&name)
                && let Err(error) = self.shard(&name)
            {
                crate::util::log(format_args!("{name}: not opened yet: {error}"));
            }
        }
    }

    /// Waits until no open under way is between its check of ownership
    /// and its entry among the open shards. Blocking.
    pub fn barrier(&self) {
        drop(self.opening.write().unwrap_or_else(PoisonError::into_inner));
    }

    /// A record of a hashed shard this node keeps, for another node.
    ///
    /// # Errors
    ///
    /// If this node does not keep it, or it cannot be read.
    pub fn local_get(&self, name: &str, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.check_local(name, address)?;
        shard::ready(self.shard(name)?.store.get(address))
    }

    /// The records under a prefix of a hashed shard this node keeps, for
    /// another node.
    ///
    /// # Errors
    ///
    /// If this node does not keep it, or it cannot be read.
    pub fn local_scan(&self, name: &str, prefix: &[u8]) -> Result<Found, StoreError> {
        if !is_hashed(name) || !self.keeps(name) {
            return Err(StoreError::new(format!("{name}: not kept here")));
        }
        shard::ready(self.shard(name)?.store.scan(prefix))
    }

    /// A batch of a hashed shard this node keeps, from another node: made
    /// in one step, in turn with the writer's, once the bucket holds it.
    ///
    /// # Errors
    ///
    /// If this node does not keep the shard, an address is not of it, or
    /// the batch is not known to be made.
    pub fn apply_remote(
        &self,
        name: &str,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StoreError> {
        for (address, _) in &changes {
            self.check_local(name, address)?;
        }
        self.apply_kept(name, changes)
    }

    /// A conditional batch of a hashed shard this node keeps, from another
    /// node: made only if each address of `expect` holds what it names,
    /// checked and made in one step (crate `shards`, "Commits across
    /// shards"). Whether it was made.
    ///
    /// # Errors
    ///
    /// If this node does not keep the shard, an address is not of it, or
    /// the batch is not known to be made.
    pub fn apply_remote_if(
        &self,
        name: &str,
        expect: &[(Vec<u8>, Option<Vec<u8>>)],
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<bool, StoreError> {
        for (address, _) in expect.iter().chain(&changes) {
            self.check_local(name, address)?;
        }
        let _held = lock(&self.conditions);
        if !self.expected(name, expect)? {
            return Ok(false);
        }
        self.apply_kept(name, changes).map(|()| true)
    }

    /// Whether each address of a shard this node keeps holds what `expect`
    /// names.
    fn expected(
        &self,
        name: &str,
        expect: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<bool, StoreError> {
        let shard = self.shard(name)?;
        for (address, record) in expect {
            if !shard.holds(address, record.as_deref())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Makes a batch of a hashed shard this node keeps, its placements
    /// noted.
    fn apply_kept(
        &self,
        name: &str,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StoreError> {
        let mut puts = Vec::new();
        let mut deletes = Vec::new();
        for (address, record) in &changes {
            match record {
                Some(record) => puts.push((address.clone(), record.clone())),
                None => deletes.push(address.clone()),
            }
        }
        let commit = Commit::new(puts, deletes);
        let undo = self.place(&commit);
        let node = self.node();
        let written = self.write_phase(
            vec![(name.to_owned(), changes.into_iter().collect())],
            &node,
        );
        match written {
            Ok(()) => {
                self.unplace(&commit);
                Ok(())
            }
            Err(error) => {
                self.unplace_failed(undo);
                Err(error)
            }
        }
    }

    /// Whether an address is of a hashed shard this node keeps.
    fn check_local(&self, name: &str, address: &[u8]) -> Result<(), StoreError> {
        if !is_hashed(name) || !self.keeps(name) {
            return Err(StoreError::new(format!("{name}: not kept here")));
        }
        match self.route(address)? {
            Route::One(routed) if routed == name => Ok(()),
            Route::Family(family_name) if name.starts_with(family_name) => Ok(()),
            _ => Err(StoreError::new(format!(
                "{name}: an address of another shard"
            ))),
        }
    }

    /// Reads the placements an index shard names again, as it opens again
    /// after the node started: what memory holds of its spaces is what the
    /// shard holds.
    fn reload_placement(&self, shard: &Shard) -> Result<(), StoreError> {
        let before = self.placements_now();
        let mut found = HashMap::new();
        for (address, record) in shard::ready(shard.store.scan(&[HOSTED]))? {
            if let (Some(space), Some(placed)) = (
                address
                    .get(1..33)
                    .and_then(|s| <[u8; 32]>::try_from(s).ok()),
                hosted_shard(&record),
            ) {
                found.insert(space, placed);
            }
        }
        self.placements_read();
        let mut placement = self
            .placement
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let of_shard = |space: &[u8; 32]| hashed(INDEX, space, HASHED) == shard.name;
        let mut merged = since_read(&before, &placement, found, of_shard);
        merged.extend(
            placement
                .iter()
                .filter(|(space, _)| !of_shard(space))
                .map(|(space, placed)| (*space, placed.clone())),
        );
        *placement = merged;
        Ok(())
    }

    /// Sets the node's clock, from which each shard's timeline counts.
    pub fn set_clock(&self, clock: Arc<dyn Clock>) {
        let _ = self.clock.set(clock);
    }

    /// The fence the shards write under, with a bucket.
    pub fn fence(&self) -> Option<Arc<dyn Fence>> {
        match &self.layout {
            Layout::Bucket { fence, .. } => Some(fence.clone()),
            Layout::Local { .. } => None,
        }
    }

    /// Sets how long, in seconds of the node's timeline, a shard of spaces
    /// stays open after its last use.
    pub fn set_idle_close(&self, seconds: u64) {
        self.idle_close.store(seconds, Ordering::Relaxed);
    }

    /// Sets when a shard folds its log into a snapshot: once `batches`
    /// follow the snapshot, or their bytes reach half the snapshot's and at
    /// least `bytes`.
    pub fn set_fold(&self, batches: u64, bytes: u64) {
        self.fold.0.store(batches, Ordering::Relaxed);
        self.fold.1.store(bytes, Ordering::Relaxed);
    }

    /// The node's reading now.
    fn node(&self) -> Reading {
        node_reading(&self.clock)
    }

    /// How many times a shard was opened.
    pub fn opens(&self) -> u64 {
        self.opens.load(Ordering::Relaxed)
    }

    /// How many shards are open.
    pub fn open_shards(&self) -> usize {
        lock(&self.open).len()
    }

    /// The names of the open shards.
    pub fn open_names(&self) -> Vec<String> {
        lock(&self.open).keys().cloned().collect()
    }

    // -- Routing

    /// The shard of a space's records.
    fn space(&self, space: &[u8]) -> Option<String> {
        let space: [u8; 32] = space.get(..32)?.try_into().ok()?;
        let placed = self
            .placement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&space)
            .cloned();
        Some(placed.unwrap_or_else(|| space_shard(&space)))
    }

    /// Where a record, or a scan of a prefix, goes.
    fn route(&self, address: &[u8]) -> Result<Route, StoreError> {
        let unroutable = || {
            StoreError::new(format!(
                "a record of no shard: {}",
                crate::util::hex(&address[..address.len().min(8)])
            ))
        };
        let tail = |from: usize| address.get(from..).unwrap_or(&[]);
        let by = |family: &'static str, key: &[u8]| {
            if key.len() >= 32 {
                Route::One(hashed(family, &key[..32], HASHED))
            } else {
                Route::Family(family)
            }
        };
        let Some(&prefix) = address.first() else {
            return Err(unroutable());
        };
        Ok(match prefix {
            JOURNAL | SNAPSHOT | OBJECT | USAGE | OFFSET | ARRIVAL => {
                Route::One(self.space(tail(1)).ok_or_else(unroutable)?)
            }
            HOSTED | WAITS | TOMBSTONE | MOVE | DEPARTURE => by(INDEX, tail(1)),
            // A mailbox's items and claim by its address; a spent token
            // by its nonce (ext-deposit-tokens.md, 3.10 In a cluster).
            MAILBOX | CLAIM | SPENT => by(MAILBOXES, tail(1)),
            // ext-deposit-tokens.md: the deposit keys, one shard every
            // node reads.
            DEPOSIT_KEY => Route::One(KEYS_SHARD.to_owned()),
            DROP => by(DROPS, tail(33)),
            DROP_AT => by(DROPS, tail(1)),
            EXCHANGE => by(EXCHANGES, tail(1)),
            META => Route::One(format!("{INDEX}/0")),
            LIBRARY => match address.get(1) {
                // Settings, tickets, copies, hand-overs and allowance
                // windows, by their whole key.
                Some(b'L' | b'T' | b'C' | b'O' | b'W') if address.len() > 2 => {
                    Route::One(hashed(INDEX, &hash_key(tail(2)), HASHED))
                }
                // Attachments, deletions, detachments and holds, by space;
                // grants used by their key's first 32 bytes, the hash of
                // their library's ID, beside its allowance window.
                Some(b'S' | b'D' | b'X' | b'H' | b'G') => by(INDEX, tail(2)),
                _ => Route::Family(INDEX),
            },
            _ => return Err(unroutable()),
        })
    }

    // -- Opening and closing

    fn lifecycle(&self, name: &str) -> Arc<Mutex<()>> {
        lock(&self.lifecycle)
            .entry(name.to_owned())
            .or_default()
            .clone()
    }

    /// An open shard, opened if it is closed or must open again.
    fn shard(&self, name: &str) -> Result<Arc<Shard>, StoreError> {
        let open = lock(&self.open).get(name).cloned();
        if let Some(shard) = open
            && !shard.broken()
        {
            return Ok(shard);
        }
        let gate = self.lifecycle(name);
        let _held = lock(&gate);
        let existing = lock(&self.open).get(name).cloned();
        if let Some(shard) = existing {
            if !shard.broken() {
                return Ok(shard);
            }
            shard.settle_fold();
            lock(&self.open).remove(name);
        }
        if !valid_name(name) {
            return Err(StoreError::new(format!("{name}: not a shard")));
        }
        // An open writes a manifest, which a stopped node may not: it
        // spends no reads on finding that out.
        if let Some(why) = self.fence().and_then(|fence| fence.stopped()) {
            return Err(StoreError::new(format!("{name}: {why}")));
        }
        // From the check of ownership to the entry among the open shards,
        // no change of epoch is handled (crate `shards`, "In a cluster").
        let _opening = self.opening.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(ownership) = &self.ownership {
            ownership.may_open(name)?;
        }
        let own_timeline = !is_hashed(name);
        let shard = match &self.layout {
            Layout::Local { dir } => Shard::open(
                name,
                dir.join(file_name(name)),
                Opening::Local,
                own_timeline,
                self.clock.clone(),
            )?,
            Layout::Bucket { io, cache, fence } => {
                let floor = lock(&self.epochs).get(name).copied();
                let used = |epoch: u64| {
                    let mut epochs = lock(&self.epochs);
                    let kept = epochs.entry(name.to_owned()).or_default();
                    *kept = (*kept).max(epoch);
                };
                Shard::open(
                    name,
                    cache.join(file_name(name)),
                    Opening::Bucket {
                        io,
                        fence,
                        floor,
                        used: &used,
                    },
                    own_timeline,
                    self.clock.clone(),
                )?
            }
        };
        self.opens.fetch_add(1, Ordering::Relaxed);
        // The epoch may have moved the shard while it opened: it is then
        // dropped, and writes nothing more.
        if let Some(ownership) = &self.ownership
            && !ownership.owns(name)
        {
            shard.discard();
            return Err(StoreError::new(format!(
                "{name}: moved to another node as it opened"
            )));
        }
        if self.started.load(Ordering::SeqCst) {
            if name.starts_with(INDEX) {
                self.reload_placement(&shard)?;
            } else if !is_hashed(name) {
                lock(&self.to_collect).push(name.to_owned());
            }
        }
        lock(&self.open).insert(name.to_owned(), shard.clone());
        Ok(shard)
    }

    /// Closes a shard, if it is open.
    fn close(&self, name: &str) -> Result<(), StoreError> {
        let gate = self.lifecycle(name);
        let _held = lock(&gate);
        let Some(shard) = lock(&self.open).remove(name) else {
            return Ok(());
        };
        shard.close()
    }

    /// Closes every shard: as the peer stops, once its writer has made every
    /// commit. Returns the first failure; every shard is closed all the
    /// same.
    ///
    /// # Errors
    ///
    /// The first close that did not keep what it writes.
    pub fn close_all(&self) -> Result<(), StoreError> {
        let mut outcome = Ok(());
        for name in self.open_names() {
            if let Err(error) = self.close(&name)
                && outcome.is_ok()
            {
                outcome = Err(error);
            }
        }
        outcome
    }

    /// The writer's maintenance between groups: refreshes the fence, takes
    /// off folds that ended, closes the shards of spaces idle for the idle
    /// time, keeps each open shard's reading at least once a minute, checks
    /// that no other writer holds a shard that writes, and collects the
    /// records of erased spaces from shards that opened or folded. Only the
    /// collection's commits wait here: closes, kept readings, checks and the
    /// walks that find what to collect run on the bucket's runtime.
    pub fn maintain(self: &Arc<Self>) {
        let fence = self.fence();
        if let Some(fence) = &fence {
            fence.refresh();
        }
        let check_every = fence.map_or(CHECK_EVERY, |fence| fence.reading_secs().max(CHECK_EVERY));
        let node = self.node();
        let idle = self.idle_close.load(Ordering::Relaxed);
        let open: Vec<Arc<Shard>> = lock(&self.open).values().cloned().collect();
        for shard in open {
            if shard.fold_done() {
                shard.settle_fold();
            }
            if is_hashed(&shard.name) {
                // The hashed shards read the node's timeline, which the node
                // keeps.
                shard.check_holder(check_every);
                continue;
            }
            if node.timeline.saturating_sub(shard.last_use()) >= idle {
                self.close_later(&shard.name);
                continue;
            }
            if shard.reading_due(node.timeline, KEEP_EVERY) {
                shard.keep_reading();
            }
            shard.check_holder(check_every);
        }
        let names = std::mem::take(&mut *lock(&self.to_collect));
        for name in names {
            self.find_later(&name);
        }
        let found = std::mem::take(&mut *lock(&self.collected));
        for (name, spaces) in found {
            if let Err(error) = self.collect(&name, spaces) {
                crate::util::log(format_args!("{name}: not collected: {error}"));
            }
        }
    }

    /// Finds what a shard keeps to collect ([`Self::find_collectable`]):
    /// with a bucket on its runtime, so that the walk of a large shard
    /// holds up no commit; in a data directory at once. The writer collects
    /// it at its next maintenance.
    fn find_later(self: &Arc<Self>, name: &str) {
        let shards = self.clone();
        let name = name.to_owned();
        let find = move || match shards.find_collectable(&name) {
            Ok(spaces) if spaces.is_empty() => {}
            Ok(spaces) => lock(&shards.collected).push((name, spaces)),
            Err(error) => crate::util::log(format_args!("{name}: not collected: {error}")),
        };
        match &self.layout {
            Layout::Bucket { io, .. } => drop(io.spawn_blocking(find)),
            Layout::Local { .. } => find(),
        }
    }

    /// Closes a shard: in a data directory at once; with a bucket on its
    /// runtime, so that the close's fold and manifest wait for nobody. A use
    /// of the shard meanwhile waits for the close, then opens it again.
    fn close_later(self: &Arc<Self>, name: &str) {
        let Layout::Bucket { io, .. } = &self.layout else {
            if let Err(error) = self.close(name) {
                crate::util::log(format_args!("{name}: {error}"));
            }
            return;
        };
        let shards = self.clone();
        let name = name.to_owned();
        drop(io.spawn_blocking(move || {
            if let Err(error) = shards.close(&name) {
                crate::util::log(format_args!("{name}: {error}"));
            }
        }));
    }

    /// Whether a shard keeps a space only to be collected: the index says
    /// it is erased, or places it in another shard and moves it into no
    /// other.
    fn collectable(&self, name: &str, space: &[u8; 32]) -> Result<bool, StoreError> {
        let mut tombstone = vec![TOMBSTONE];
        tombstone.extend_from_slice(space);
        Ok(self.get_now(&tombstone)?.is_some() || self.placed_elsewhere(name, space)?)
    }

    /// Walks a shard of spaces for the records of each space it keeps only
    /// to be collected ([`Self::collectable`]): what a crash between an
    /// erasure's two steps left, and what a move or a create that was not
    /// made left (crate `shards`, "Commits across shards"). Reads only.
    fn find_collectable(&self, name: &str) -> Result<Vec<Collectable>, StoreError> {
        let Some(shard) = lock(&self.open).get(name).cloned() else {
            return Ok(Vec::new());
        };
        let mut erased = Vec::new();
        for prefix in SPACE_PREFIXES {
            let mut after = vec![prefix];
            while let Some(address) = shard.store.next_address(&after)? {
                if address.first() != Some(&prefix) {
                    break;
                }
                let Some(space) = address
                    .get(1..33)
                    .and_then(|s| <[u8; 32]>::try_from(s).ok())
                else {
                    break;
                };
                if !erased.contains(&space) && self.collectable(name, &space)? {
                    erased.push(space);
                }
                after = vec![prefix];
                after.extend_from_slice(&space);
                after.extend_from_slice(&[0xff; 64]);
            }
        }
        let mut found = Vec::new();
        for space in erased {
            let mut addresses = Vec::new();
            for prefix in SPACE_PREFIXES {
                let mut start = vec![prefix];
                start.extend_from_slice(&space);
                addresses.extend(
                    shard::ready(shard.store.scan(&start))?
                        .into_iter()
                        .map(|(address, _)| address),
                );
            }
            found.push((space, addresses));
        }
        Ok(found)
    }

    /// Deletes what a walk found to collect in a shard, of each space that
    /// is still only to be collected: a move may have brought one back
    /// since. On the writer's thread.
    fn collect(&self, name: &str, found: Vec<Collectable>) -> Result<(), StoreError> {
        let mut deletes = Vec::new();
        let mut spaces = 0;
        for (space, addresses) in found {
            if self.collectable(name, &space)? {
                spaces += 1;
                deletes.extend(addresses);
            }
        }
        if deletes.is_empty() {
            return Ok(());
        }
        crate::util::log(format_args!(
            "{name}: the records of {spaces} spaces erased or kept elsewhere collected"
        ));
        self.commit_into(name, Vec::new(), deletes)
    }

    /// Whether the index places a space in a shard other than `name`, and
    /// no move under way takes it into `name`.
    fn placed_elsewhere(&self, name: &str, space: &[u8; 32]) -> Result<bool, StoreError> {
        // Memory first: only a placement it notes elsewhere is read again.
        let noted = self
            .placement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(space)
            .cloned();
        if noted.is_none_or(|noted| noted == name) {
            return Ok(false);
        }
        let id = frasil_events::EventId(*space);
        let placed = self
            .get_now(&crate::records::Records::hosted_address(&id))?
            .as_deref()
            .and_then(hosted_shard);
        if placed.is_none_or(|placed| placed == name) {
            return Ok(false);
        }
        let moving_here = self
            .get_now(&crate::records::Records::move_address(&id))?
            .as_deref()
            .and_then(crate::records::MoveRecord::decode)
            .is_some_and(|moving| moving.target == name);
        Ok(!moving_here)
    }

    // -- Reading

    /// The records under a prefix of the mailbox shards this node keeps,
    /// read from no other node. Blocking.
    ///
    /// # Errors
    ///
    /// If a shard cannot be read.
    pub(crate) fn scan_kept_mailboxes(&self, prefix: &[u8]) -> Result<Found, StoreError> {
        let mut out = Vec::new();
        for name in family(MAILBOXES) {
            if self.remote(&name).is_some() {
                continue;
            }
            let shard = self.shard(&name)?;
            out.extend(shard::ready(shard.store.scan(prefix))?);
        }
        out.sort();
        Ok(out)
    }

    fn scan_family(&self, family_name: &str, prefix: &[u8]) -> Result<Found, StoreError> {
        let mut out = Vec::new();
        for name in family(family_name) {
            if let Some(remote) = self.remote(&name) {
                out.extend(remote.scan(&name, prefix)?);
                continue;
            }
            let shard = self.shard(&name)?;
            out.extend(shard::ready(shard.store.scan(prefix))?);
        }
        out.sort();
        Ok(out)
    }

    fn get_now(&self, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        match self.route(address)? {
            Route::One(name) if self.remote(&name).is_some() => self
                .remote(&name)
                .map_or(Ok(None), |remote| remote.get(&name, address)),
            Route::One(name) => {
                let shard = self.shard(&name)?;
                shard.touch(self.node().timeline);
                shard::ready(shard.store.get(address))
            }
            Route::Family(_) => Err(StoreError::new("a record of no one shard")),
        }
    }

    fn scan_now(&self, prefix: &[u8]) -> Result<Found, StoreError> {
        match self.route(prefix)? {
            Route::One(name) if self.remote(&name).is_some() => self
                .remote(&name)
                .map_or(Ok(Vec::new()), |remote| remote.scan(&name, prefix)),
            Route::One(name) => {
                let shard = self.shard(&name)?;
                shard.touch(self.node().timeline);
                shard::ready(shard.store.scan(prefix))
            }
            Route::Family(family_name) => self.scan_family(family_name, prefix),
        }
    }

    /// [`Self::reading`] without opening a shard: `None` if the shard is
    /// closed.
    pub(crate) fn reading_open(&self, address: &[u8], node: Reading) -> Option<Reading> {
        match self.route(address).ok()? {
            Route::One(name) if !is_hashed(&name) => lock(&self.open)
                .get(&name)
                .filter(|shard| !shard.broken())
                .map(|shard| shard.reading(&node)),
            _ => Some(node),
        }
    }

    /// The reading of the timeline of the shard `address` routes to, at the
    /// node's reading `node`: a library's or a space shard's own, opened if
    /// it is closed; the node's for the hashed shards.
    ///
    /// # Errors
    ///
    /// If the shard cannot be opened.
    pub(crate) fn reading(&self, address: &[u8], node: Reading) -> Result<Reading, StoreError> {
        if let Some(reading) = self.reading_open(address, node) {
            return Ok(reading);
        }
        match self.route(address)? {
            Route::One(name) if !is_hashed(&name) => Ok(self.shard(&name)?.reading(&node)),
            _ => Ok(node),
        }
    }

    /// The reading of a shard's timeline at the node's reading `node`, by
    /// the shard's name: a library's or a space shard's own, opened if it is
    /// closed; the node's for the hashed shards.
    ///
    /// # Errors
    ///
    /// If the shard cannot be opened.
    pub(crate) fn reading_of(&self, name: &str, node: Reading) -> Result<Reading, StoreError> {
        if is_hashed(name) {
            return Ok(node);
        }
        Ok(self.shard(name)?.reading(&node))
    }

    // -- Writing

    /// Notes the placements a commit puts in the index, before its records
    /// are routed; returns what they replace, to put back if the commit is
    /// not made.
    fn place(&self, commit: &Commit) -> Vec<([u8; 32], Option<String>)> {
        let placed: Vec<([u8; 32], String)> = commit
            .puts
            .iter()
            .filter(|(address, _)| address.first() == Some(&HOSTED))
            .filter_map(|(address, record)| {
                let space = <[u8; 32]>::try_from(address.get(1..33)?).ok()?;
                Some((space, hosted_shard(record)?))
            })
            .collect();
        if placed.is_empty() {
            return Vec::new();
        }
        let mut placement = self
            .placement
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        placed
            .into_iter()
            .map(|(space, shard)| (space, placement.insert(space, shard)))
            .collect()
    }

    /// Puts placements back as they were before a commit that was not made.
    fn unplace_failed(&self, undo: Vec<([u8; 32], Option<String>)>) {
        if undo.is_empty() {
            return;
        }
        let mut placement = self
            .placement
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for (space, before) in undo.into_iter().rev() {
            match before {
                Some(shard) => placement.insert(space, shard),
                None => placement.remove(&space),
            };
        }
    }

    /// Forgets the placements a commit deletes from the index, once its
    /// records are routed.
    fn unplace(&self, commit: &Commit) {
        let gone: Vec<[u8; 32]> = commit
            .deletes
            .iter()
            .filter(|address| address.first() == Some(&HOSTED))
            .filter_map(|address| <[u8; 32]>::try_from(address.get(1..33)?).ok())
            .filter(|space| {
                !commit
                    .puts
                    .iter()
                    .any(|(a, _)| a.get(1..33) == Some(&space[..]) && a[0] == HOSTED)
            })
            .collect();
        if !gone.is_empty() {
            let mut placement = self
                .placement
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            for space in gone {
                placement.remove(&space);
            }
        }
    }

    /// The shard of one address of a commit.
    fn shard_of(&self, address: &[u8]) -> Result<String, StoreError> {
        match self.route(address)? {
            Route::One(name) => Ok(name),
            Route::Family(_) => Err(StoreError::new("a commit to a record of no one shard")),
        }
    }

    /// Whether a commit deletes records of a space's shard while it also
    /// writes a hashed shard: then the hashed shards go first.
    fn index_first(&self, commit: &Commit) -> Result<bool, StoreError> {
        let mut deletes_space = false;
        for address in &commit.deletes {
            if !is_hashed(&self.shard_of(address)?) {
                deletes_space = true;
            }
        }
        if !deletes_space {
            return Ok(false);
        }
        for address in commit
            .deletes
            .iter()
            .chain(commit.puts.iter().map(|(a, _)| a))
        {
            if is_hashed(&self.shard_of(address)?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn commit_now(&self, commits: &[Commit]) -> Result<Vec<bool>, StoreError> {
        let mut made = Vec::with_capacity(commits.len());
        let mut start = 0;
        while start < commits.len() {
            if !commits[start].expect.is_empty() {
                made.push(self.commit_conditional(&commits[start])?);
                start += 1;
                continue;
            }
            let first = self.index_first(&commits[start])?;
            let mut end = start + 1;
            while end < commits.len()
                && commits[end].expect.is_empty()
                && self.index_first(&commits[end])? == first
            {
                end += 1;
            }
            made.extend(self.commit_run(&commits[start..end], first)?);
            start = end;
        }
        Ok(made)
    }

    /// Whether each address holds what `changes` leave there.
    fn holds_changes(&self, changes: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<bool, StoreError> {
        for (address, record) in changes {
            if self.get_now(address)? != *record {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Makes a commit with expectations (crate `shards`, "Commits across
    /// shards"): its shards of spaces, then its part of the hashed shard
    /// its expectations name if they hold there, then its other hashed
    /// shards. Whether it was made.
    fn commit_conditional(&self, commit: &Commit) -> Result<bool, StoreError> {
        let mut named = None;
        for (address, _) in &commit.expect {
            let name = self.shard_of(address)?;
            if !is_hashed(&name) || named.as_ref().is_some_and(|n| *n != name) {
                return Err(StoreError::new(
                    "a commit's expectations name more than one hashed shard",
                ));
            }
            named = Some(name);
        }
        let Some(named) = named else {
            return self
                .commit_run(std::slice::from_ref(commit), false)
                .map(|m| m[0]);
        };
        let node = self.node();
        let undo = self.place(commit);
        let outcome = (|| {
            let mut batches: BTreeMap<String, Changes> = BTreeMap::new();
            for address in &commit.deletes {
                batches
                    .entry(self.shard_of(address)?)
                    .or_default()
                    .insert(address.clone(), None);
            }
            for (address, record) in &commit.puts {
                batches
                    .entry(self.shard_of(address)?)
                    .or_default()
                    .insert(address.clone(), Some(record.clone()));
            }
            let condition = batches.remove(&named).unwrap_or_default();
            let (spaces, hashed): (Vec<_>, Vec<_>) =
                batches.into_iter().partition(|(name, _)| !is_hashed(name));
            self.write_phase(spaces, &node)?;
            let changes: Vec<(Vec<u8>, Option<Vec<u8>>)> = condition.into_iter().collect();
            let held = match self.remote(&named) {
                Some(owner) => {
                    let held = owner.commit_if(&named, commit.expect.clone(), changes.clone())?;
                    // A batch sent again, at a keeper that took over after
                    // the first one landed, finds that batch's own records:
                    // it was made, if what it puts is there and what it
                    // deletes is gone.
                    held || (changes.iter().any(|(_, record)| record.is_some())
                        && self.holds_changes(&changes)?)
                }
                None => {
                    let _held = lock(&self.conditions);
                    if self.expected(&named, &commit.expect)? {
                        self.write_local(
                            vec![(named.clone(), changes.into_iter().collect())],
                            &node,
                        )?;
                        true
                    } else {
                        false
                    }
                }
            };
            if held {
                self.write_phase(hashed, &node)?;
            }
            Ok(held)
        })();
        match outcome {
            Ok(true) => {
                self.unplace(commit);
                Ok(true)
            }
            Ok(false) => {
                self.unplace_failed(undo);
                Ok(false)
            }
            Err(error) => {
                self.unplace_failed(undo);
                Err(error)
            }
        }
    }

    /// Makes a run of commits that go one way: each shard's part in one
    /// batch, the space shards' first unless `index_first`.
    fn commit_run(&self, commits: &[Commit], index_first: bool) -> Result<Vec<bool>, StoreError> {
        let mut undo = Vec::new();
        let made = self.commit_run_placed(commits, index_first, &mut undo);
        if made.is_err() {
            self.unplace_failed(undo);
        }
        made
    }

    fn commit_run_placed(
        &self,
        commits: &[Commit],
        index_first: bool,
        undo: &mut Vec<([u8; 32], Option<String>)>,
    ) -> Result<Vec<bool>, StoreError> {
        let node = self.node();
        // Route every address, with the placements the run's commits make.
        // A commit with expectations is made alone (`commit_conditional`).
        let mut routed: Vec<Vec<Routed>> = Vec::new();
        for commit in commits {
            undo.extend(self.place(commit));
            let mut changes = Vec::new();
            for address in &commit.deletes {
                changes.push((self.shard_of(address)?, address.clone(), None));
            }
            for (address, record) in &commit.puts {
                changes.push((
                    self.shard_of(address)?,
                    address.clone(),
                    Some(record.clone()),
                ));
            }
            routed.push(changes);
        }
        let made = vec![true; commits.len()];
        let mut batches: BTreeMap<String, Changes> = BTreeMap::new();
        for changes in routed {
            for (name, address, record) in changes {
                batches.entry(name).or_default().insert(address, record);
            }
        }
        let (mut first, mut second): (Vec<_>, Vec<_>) =
            batches.into_iter().partition(|(name, _)| !is_hashed(name));
        if index_first {
            std::mem::swap(&mut first, &mut second);
        }
        for phase in [first, second] {
            self.write_phase(phase, &node)?;
        }
        for commit in commits {
            self.unplace(commit);
        }
        Ok(made)
    }

    /// Writes one batch to each of several shards: every bucket PUT at
    /// once, then each working copy that the bucket now holds.
    fn write_phase(&self, phase: Vec<(String, Changes)>, node: &Reading) -> Result<(), StoreError> {
        if phase.is_empty() {
            return Ok(());
        }
        // In a cluster, the batches of hashed shards other nodes keep are
        // made by those nodes, once this node's own are made, with no lock
        // held meanwhile.
        let (remote, phase): (Vec<_>, Vec<_>) = phase
            .into_iter()
            .partition(|(name, _)| self.remote(name).is_some());
        self.write_local(phase, node)?;
        for (name, changes) in remote {
            if let Some(owner) = self.remote(&name) {
                owner.commit(&name, changes.into_iter().collect())?;
            }
        }
        Ok(())
    }

    /// Writes one batch to each of several shards this node keeps. A shard
    /// closed or given up between its lookup and its turn takes no batch:
    /// the phase looks its shards up again, which waits for the close.
    fn write_local(&self, phase: Vec<(String, Changes)>, node: &Reading) -> Result<(), StoreError> {
        if phase.is_empty() {
            return Ok(());
        }
        let mut tries = 0;
        loop {
            let mut resolved: Vec<(Arc<Shard>, &Changes)> = Vec::with_capacity(phase.len());
            for (name, changes) in &phase {
                resolved.push((self.shard(name)?, changes));
            }
            match self.write_resolved(&resolved, node) {
                Some(outcome) => return outcome,
                None if tries < 3 => tries += 1,
                None => {
                    return Err(StoreError::new(
                        "a shard closed again and again as it was written",
                    ));
                }
            }
        }
    }

    /// [`Self::write_local`] once its shards are looked up: none if one of
    /// them is closed or given up meanwhile, and nothing was sent.
    fn write_resolved(
        &self,
        resolved: &[(Arc<Shard>, &Changes)],
        node: &Reading,
    ) -> Option<Result<(), StoreError>> {
        // Held in the order of the shards' names until every batch ends.
        let _turns: Vec<MutexGuard<'_, ()>> = resolved
            .iter()
            .map(|(shard, _)| lock(&shard.writing))
            .collect();
        if resolved.iter().any(|(shard, _)| shard.closing()) {
            return None;
        }
        let mut prepared: Vec<(Arc<Shard>, Pending)> = Vec::with_capacity(resolved.len());
        for (shard, changes) in resolved {
            let batch = Batch {
                changes: (*changes).clone().into_iter().collect(),
                reading: None,
            };
            match shard.prepare(batch, node) {
                Ok(pending) => prepared.push((shard.clone(), pending)),
                Err(error) => {
                    // Nothing of the phase is sent: the later batches are
                    // given back first.
                    for (shard, pending) in prepared.into_iter().rev() {
                        shard.abandon(pending);
                    }
                    if resolved.iter().any(|(shard, _)| shard.closing()) {
                        return None;
                    }
                    return Some(Err(error));
                }
            }
        }
        // The PUTs, together, on the bucket's runtime.
        // Whether the shard may still be written is checked again as each
        // request starts on the bucket's runtime.
        let sends: Vec<Option<Upload>> = prepared
            .iter()
            .map(|(shard, pending)| {
                Some((pending.key.clone()?, pending.bytes.clone(), shard.clone()))
            })
            .collect();
        let results: Vec<Result<(), StoreError>> = match &self.layout {
            Layout::Local { .. } => sends.iter().map(|_| Ok(())).collect(),
            Layout::Bucket { io, .. } => {
                let bucket = io.bucket();
                io.block(async move {
                    let puts = sends.into_iter().map(|send| {
                        let bucket = bucket.clone();
                        async move {
                            match send {
                                None => Ok(()),
                                Some((_, _, shard)) if !shard.may_write() => {
                                    Err(StoreError::new("this node no longer holds the shard"))
                                }
                                Some((key, bytes, _)) => bucket
                                    .put(&key, bytes)
                                    .await
                                    .map_err(|e| StoreError::new(e.to_string())),
                            }
                        }
                    });
                    futures_util::future::join_all(puts).await
                })
            }
        };
        let mut outcome = Ok(());
        let mut folds = Vec::new();
        for ((shard, pending), sent) in prepared.into_iter().zip(results) {
            match shard.finish(pending, sent) {
                Ok(()) => {
                    let batches = self.fold.0.load(Ordering::Relaxed);
                    let bytes = self.fold.1.load(Ordering::Relaxed);
                    if shard.wants_fold(batches, bytes) {
                        folds.push(shard);
                    }
                }
                Err(error) if outcome.is_ok() => outcome = Err(error),
                Err(_) => {}
            }
        }
        for shard in folds {
            shard.start_fold();
            lock(&self.to_collect).push(shard.name.clone());
        }
        Some(outcome)
    }
}

/// A space a shard keeps only to be collected, and the addresses it keeps
/// there.
type Collectable = ([u8; 32], Vec<Vec<u8>>);

/// A key of variable length, hashed to 32 bytes for routing.
fn hash_key(key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(key).into()
}

impl Store for Shards {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        let found = self.get_now(address);
        Box::pin(async move { found })
    }

    fn scan<'a>(&'a self, prefix: &'a [u8]) -> BoxFuture<'a, Result<Found, StoreError>> {
        let found = self.scan_now(prefix);
        Box::pin(async move { found })
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        let made = self
            .commit_now(std::slice::from_ref(commit))
            .map(|made| made[0]);
        Box::pin(async move { made })
    }

    fn commit_all<'a>(
        &'a self,
        commits: &'a [Commit],
    ) -> BoxFuture<'a, Result<Vec<bool>, StoreError>> {
        let made = self.commit_now(commits);
        Box::pin(async move { made })
    }
}

/// What tests read and wait for.
#[cfg(test)]
impl Shards {
    /// Waits for every fold under way, and takes each in.
    pub(crate) fn settle_folds(&self) {
        let open: Vec<Arc<Shard>> = lock(&self.open).values().cloned().collect();
        for shard in open {
            shard.settle_fold();
        }
    }

    /// Closes one shard.
    pub(crate) fn close_shard(&self, name: &str) -> Result<(), StoreError> {
        self.close(name)
    }

    /// The bucket's runtime.
    pub(crate) fn layout_io(&self) -> Arc<BucketIo> {
        match &self.layout {
            Layout::Bucket { io, .. } => io.clone(),
            Layout::Local { .. } => panic!("a data directory has no bucket"),
        }
    }

    /// Every position each open shard applied since it opened.
    pub(crate) fn applied_logs(&self) -> BTreeMap<String, Vec<format::Position>> {
        lock(&self.open)
            .iter()
            .map(|(name, shard)| (name.clone(), shard.applied_log()))
            .collect()
    }

    /// The spaces a placement map names.
    pub(crate) fn placed(&self) -> std::collections::BTreeSet<[u8; 32]> {
        self.placement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}

/// The placements of the spaces `scope` takes, as a reading of the index
/// found them, with what memory changed while it read: a move that noted
/// a space's new shard, or forgot one, during the reading keeps what it
/// noted, since the reading may predate it. `before` is what memory held
/// as the reading began, `now` what it holds as it ends.
fn since_read(
    before: &HashMap<[u8; 32], String>,
    now: &HashMap<[u8; 32], String>,
    read: HashMap<[u8; 32], String>,
    scope: impl Fn(&[u8; 32]) -> bool,
) -> HashMap<[u8; 32], String> {
    let mut out: HashMap<[u8; 32], String> =
        read.into_iter().filter(|(space, _)| scope(space)).collect();
    for (space, placed) in now.iter().filter(|(space, _)| scope(space)) {
        if before.get(space) != Some(placed) {
            out.insert(*space, placed.clone());
        }
    }
    for space in before.keys().filter(|space| scope(space)) {
        if !now.contains_key(space) {
            out.remove(space);
        }
    }
    out
}
