//! Epochs and fencing: the one place that says under which epoch this node
//! opens a shard, and whether it may still write one it holds.
//!
//! A shard's batches are `log/<epoch>-<seq>`, and an owner opens a shard
//! under an epoch above the epoch of its manifest, so a batch that lands
//! after the next owner opened the shard lands after the tail that owner
//! recorded, where nothing reads it (crate `shards`, "The bucket").
//!
//! [`SingleNode`] is the peer alone on its bucket: its epoch is raised at
//! each start and kept in the bucket's `nodes/<node>` object, and it names
//! itself in `nodes/active`; its process names itself, by a random run
//! nonce, in `nodes/<node>.run`, as a cluster's nodes do. It reads both
//! records again every [`READING_EVERY`], or the interval its operator set.
//!
//! - Once another node has named itself in the one, or another process in
//!   the other, it writes nothing, for good: a second node on the bucket, or
//!   a restart, or a second start under the same name, while the old process
//!   still runs, stops the earlier one at its next reading, and a start that
//!   finds a later one already named in either refuses to run.
//! - Once it could not confirm them for [`lapse_after`] the interval, it has
//!   lapsed: it writes nothing, and keeps reading. A reading that finds it
//!   still named in both ends the lapse. Nothing was written meanwhile, and
//!   each process that can write named itself with a nonce of its own, which
//!   no later reading can take for this node's, so the records naming this
//!   node mean that no other process took the bucket since its last reading.
//!
//! Both records are read: a late write can leave `nodes/active` naming an
//! earlier process, and only the run object then stops it. The store gives
//! no conditional write, so two starts under one name that overlap may both
//! claim one epoch until that reading; each shard's open then still takes an
//! epoch above any manifest's it reads. Each shard also checks its manifests
//! (crate `shards`, module `shard`). A cluster replaces it with epochs that
//! the nodes agree on and node leases, behind the same [`Fence`]: a node then
//! opens a shard under the membership's epoch, and writes only while its
//! lease outlasts the write's timeout.

use super::bucket::{BucketError, BucketIo};
use super::format::{Active, decode_node, encode_node};
use frasil_store::StoreError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Says under which epoch a shard opens, and whether this node may write.
pub trait Fence: Send + Sync {
    /// The epoch to open a shard under, given the greatest epoch the shard
    /// was opened under before, or none. Always above `previous`.
    fn open_epoch(&self, previous: Option<u64>) -> u64;

    /// Whether this node may still write, now, a shard it opened under
    /// `epoch`. A write is issued only while this holds, and acknowledged
    /// only if it still holds once the write returns.
    fn may_write(&self, epoch: u64) -> bool;

    /// Checks again what [`Fence::may_write`] answers from, when it is
    /// due, without waiting: the writer calls it between groups.
    fn refresh(&self) {}

    /// Why this node may write nothing now, if so, in words fit for a
    /// health answer. A fence that does not say answers none.
    fn stopped(&self) -> Option<&'static str> {
        None
    }

    /// The seconds between two readings of what [`Fence::may_write`]
    /// answers from, when something other than each shard's checks of its
    /// manifests stops a node: those then need not run more often.
    fn reading_secs(&self) -> u64 {
        0
    }
}

/// Which node of a cluster keeps each shard, and the hashed shards that
/// other nodes keep (crate `cluster`). Without one, the node keeps every
/// shard.
pub trait Ownership: Send + Sync {
    /// Whether this node owns the shard under the membership's epoch.
    fn owns(&self, shard: &str) -> bool;

    /// Waits, a few seconds at most, until this node may open a shard it
    /// owns: until every node that kept it under an earlier epoch has given
    /// it up, or its lease has ended. Blocking.
    ///
    /// # Errors
    ///
    /// If this node does not own the shard, or may not open it in time.
    fn may_open(&self, shard: &str) -> Result<(), StoreError>;

    /// A record of a hashed shard another node keeps. Blocking.
    ///
    /// # Errors
    ///
    /// If the node that keeps it does not answer.
    fn get(&self, shard: &str, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    /// The records under a prefix of a hashed shard another node keeps.
    /// Blocking.
    ///
    /// # Errors
    ///
    /// If the node that keeps it does not answer.
    fn scan(&self, shard: &str, prefix: &[u8]) -> Result<frasil_store::store::Records, StoreError>;

    /// A batch of a hashed shard another node keeps, made by that node in
    /// one step: done once the bucket holds it. Blocking.
    ///
    /// # Errors
    ///
    /// If it is not known to be made.
    fn commit(
        &self,
        shard: &str,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StoreError>;

    /// A batch of a hashed shard another node keeps, made by that node
    /// only if each address of `expect` holds what it names, checked and
    /// made in one step there: whether it was made. Blocking.
    ///
    /// # Errors
    ///
    /// If it is not known to be made or refused.
    fn commit_if(
        &self,
        shard: &str,
        expect: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<bool, StoreError>;
}

/// The key of a node's record, under the bucket's prefix.
pub fn node_key(node: &str) -> String {
    format!("nodes/{node}")
}

/// How often a single node reads its records, unless its operator sets
/// another interval: 480 readings a day of two GETs each.
pub const READING_EVERY: Duration = Duration::from_secs(180);

/// How long, at least, a node writes without confirming its records, when
/// the bucket does not answer.
const LAPSE: Duration = Duration::from_secs(30);

/// How many intervals a node writes without confirming its records, when
/// the bucket does not answer: two readings in a row may fail.
const LAPSE_READINGS: u32 = 3;

/// How long a node that reads its records every `every` writes without
/// confirming them.
pub fn lapse_after(every: Duration) -> Duration {
    (every * LAPSE_READINGS).max(LAPSE)
}

/// The key of the record of the node that writes the bucket now.
pub const ACTIVE: &str = "nodes/active";

const ANOTHER_NODE: &str = "another node writes this bucket now";
const ANOTHER_PROCESS: &str = "another process runs this node now";
const LAPSED: &str = "this node could not confirm its records in the bucket";

/// What one reading of the records found.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    /// Both name this node and this process.
    Named,
    /// Another node or process is named, as this says.
    Replaced(&'static str),
    /// It tells nothing: a read failed, or a record is gone or does not
    /// read, as this says.
    Unconfirmed(String),
}

/// What the node last learned of its records.
#[derive(Debug)]
struct Check {
    /// Who replaced this node, for good.
    replaced: Option<&'static str>,
    /// When the last reading that found it named started.
    confirmed: Instant,
    /// When the last reading started, whatever it found.
    tried: Instant,
    /// What the last reading that told nothing said, while they go on.
    unconfirmed: Option<String>,
    /// Whether the lapse has been logged.
    lapsed: bool,
}

impl Check {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            replaced: None,
            confirmed: now,
            tried: now,
            unconfirmed: None,
            lapsed: false,
        }
    }

    /// Takes in what a reading that started at `started` found, and logs
    /// each change.
    fn note(&mut self, found: Finding, started: Instant, lapse: Duration) {
        match found {
            Finding::Named => {
                self.confirmed = self.confirmed.max(started);
                let was_lapsed = core::mem::take(&mut self.lapsed);
                if self.unconfirmed.take().is_some() && self.replaced.is_none() {
                    crate::util::log(if was_lapsed {
                        "the records in the bucket name this node again: it writes again"
                    } else {
                        "the records in the bucket read again"
                    });
                }
            }
            Finding::Replaced(who) => {
                if self.replaced.is_none() {
                    crate::util::log(format_args!("{who}: this one writes nothing more"));
                }
                self.replaced = Some(who);
            }
            Finding::Unconfirmed(why) => {
                let left = lapse.saturating_sub(self.confirmed.elapsed());
                if self.unconfirmed.as_deref() != Some(why.as_str()) {
                    crate::util::log(format_args!(
                        "the node's records in the bucket did not read: {why}; it writes for \
                         {} seconds more without them",
                        left.as_secs()
                    ));
                }
                self.unconfirmed = Some(why);
                if left.is_zero() && !self.lapsed {
                    self.lapsed = true;
                    crate::util::log(format_args!(
                        "the node's records did not read for {} seconds: it writes nothing \
                         until a reading finds it named",
                        lapse.as_secs()
                    ));
                }
            }
        }
    }
}

/// Reads the records, the second only if the first leaves it open.
async fn read_records(
    bucket: &dyn super::bucket::Bucket,
    active: &Active,
    (run_key, run): (&str, &[u8]),
    lapsed: bool,
) -> Finding {
    let found = match bucket.get(ACTIVE).await {
        Ok(Some(found)) => found,
        Ok(None) => return Finding::Unconfirmed(format!("{ACTIVE} is gone")),
        Err(error) => return Finding::Unconfirmed(format!("{ACTIVE}: {error}")),
    };
    if found != active.encode() {
        return match Active::decode(&found) {
            Some(_) => Finding::Replaced(ANOTHER_NODE),
            None => Finding::Unconfirmed(format!("{ACTIVE} does not read")),
        };
    }
    match bucket.get(run_key).await {
        Ok(Some(found)) if found == run => Finding::Named,
        Ok(Some(_)) => Finding::Replaced(ANOTHER_PROCESS),
        // A run object that is missing fences nothing, but does not end a
        // lapse: that takes both records.
        Ok(None) if !lapsed => Finding::Named,
        Ok(None) => Finding::Unconfirmed(format!("{run_key} is gone")),
        Err(error) => Finding::Unconfirmed(format!("{run_key}: {error}")),
    }
}

/// One node, alone on its bucket.
pub struct SingleNode {
    epoch: u64,
    io: Option<Arc<BucketIo>>,
    active: Active,
    /// `nodes/<node>.run`, and this process's run nonce in it.
    run: (String, Vec<u8>),
    every: Duration,
    check: Arc<Mutex<Check>>,
    checking: Arc<AtomicBool>,
}

impl core::fmt::Debug for SingleNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SingleNode")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl SingleNode {
    /// A node of a fixed epoch whose hold never lapses, for tests.
    pub fn at(epoch: u64) -> Self {
        Self {
            epoch,
            io: None,
            active: Active {
                epoch,
                node: String::new(),
                nonce: [0; 16],
            },
            run: (String::new(), Vec::new()),
            every: READING_EVERY,
            check: Arc::new(Mutex::new(Check::new())),
            checking: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the node, reading its records again every [`READING_EVERY`].
    ///
    /// # Errors
    ///
    /// As [`SingleNode::start_with`].
    pub fn start(io: &Arc<BucketIo>, node: &str) -> Result<Self, BucketError> {
        Self::start_with(io, node, READING_EVERY)
    }

    /// Starts the node: its epoch is one above the one its record keeps, the
    /// record keeps the new one, and `nodes/active` names this node, before
    /// it opens any shard. It reads its records again every `every`, and
    /// writes nothing while [`lapse_after`] that has passed without a
    /// reading that found it named.
    ///
    /// # Errors
    ///
    /// If a record cannot be read or written, or does not read, or another
    /// node named itself in `nodes/active` meanwhile.
    pub fn start_with(
        io: &Arc<BucketIo>,
        node: &str,
        every: Duration,
    ) -> Result<Self, BucketError> {
        // This process runs the node from now on: an earlier one still
        // running under its name stops at its next reading.
        let run_nonce = frasil_crypto::random_bytes::<16>()
            .map_err(|_| BucketError("no randomness for the node's run".into()))?;
        let run = (
            crate::cluster::run_object(node),
            crate::util::hex(&*run_nonce).into_bytes(),
        );
        let bucket = io.bucket();
        let (run_key, run_bytes) = run.clone();
        io.block(async move { bucket.put(&run_key, run_bytes).await })?;
        let bucket = io.bucket();
        let key = node_key(node);
        let read = key.clone();
        let kept = io.block(async move { bucket.get(&read).await })?;
        let previous = match kept {
            Some(bytes) => {
                decode_node(&bytes).ok_or_else(|| BucketError(format!("{key} does not read")))?
            }
            None => 0,
        };
        let epoch = previous + 1;
        let bucket = io.bucket();
        io.block(async move { bucket.put(&key, encode_node(epoch)).await })?;
        let nonce = frasil_crypto::random_bytes::<16>()
            .map_err(|_| BucketError("no randomness for the node's nonce".into()))?;
        let active = Active {
            epoch,
            node: node.to_owned(),
            nonce: *nonce,
        };
        let bucket = io.bucket();
        let record = active.encode();
        let run_key = run.0.clone();
        let (back, run_back) = io.block(async move {
            bucket.put(ACTIVE, record).await?;
            Ok::<_, BucketError>((bucket.get(ACTIVE).await?, bucket.get(&run_key).await?))
        })?;
        // Read back: a start that overlapped this one and named itself
        // after it stops this one now, not at its first reading.
        if back.as_deref() != Some(active.encode().as_slice())
            || run_back.as_deref() != Some(run.1.as_slice())
        {
            return Err(BucketError(
                "another process named itself in nodes/active or this node's run object as \
                 this one started"
                    .into(),
            ));
        }
        Ok(Self {
            epoch,
            io: Some(io.clone()),
            active,
            run,
            every,
            check: Arc::new(Mutex::new(Check::new())),
            checking: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The node's epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Reads the records now and waits for it, for tests and for a caller
    /// that must know.
    pub fn refresh_now(&self) {
        if let Some(io) = &self.io {
            let task = self.spawn_check(io);
            io.join(task);
        }
    }

    /// Moves the last reading that found this node named back, as if `ago`
    /// had passed without one.
    #[cfg(test)]
    pub(crate) fn unconfirmed_for(&self, ago: Duration) {
        let mut check = self.lock();
        check.confirmed = Instant::now() - ago;
        check.tried = check.confirmed;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Check> {
        self.check.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn spawn_check(&self, io: &Arc<BucketIo>) -> tokio::task::JoinHandle<()> {
        let bucket = io.bucket();
        let active = self.active.clone();
        let (run_key, run) = self.run.clone();
        let check = self.check.clone();
        let checking = self.checking.clone();
        let lapse = lapse_after(self.every);
        let started = Instant::now();
        let lapsed = {
            let mut check = self.lock();
            check.tried = started;
            check.confirmed.elapsed() >= lapse
        };
        io.spawn(async move {
            let found = read_records(&*bucket, &active, (&run_key, &run), lapsed).await;
            check
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .note(found, started, lapse);
            checking.store(false, Ordering::SeqCst);
        })
    }
}

impl Fence for SingleNode {
    fn open_epoch(&self, previous: Option<u64>) -> u64 {
        previous.map_or(self.epoch, |previous| self.epoch.max(previous + 1))
    }

    fn may_write(&self, _epoch: u64) -> bool {
        self.stopped().is_none()
    }

    fn refresh(&self) {
        let Some(io) = &self.io else {
            return;
        };
        // Replaced is for good, so nothing more is read. A reading that
        // failed counts: the next one waits the interval too, however
        // long the bucket refuses.
        let due = {
            let check = self.lock();
            check.replaced.is_none() && check.tried.elapsed() >= self.every
        };
        if due && !self.checking.swap(true, Ordering::SeqCst) {
            drop(self.spawn_check(io));
        }
    }

    fn stopped(&self) -> Option<&'static str> {
        let check = self.lock();
        if check.replaced.is_some() {
            return check.replaced;
        }
        let lapse = lapse_after(self.every);
        (self.io.is_some() && check.confirmed.elapsed() >= lapse).then_some(LAPSED)
    }

    fn reading_secs(&self) -> u64 {
        self.every.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shards::bucket::{Bucket, MemoryBucket};

    #[test]
    fn a_node_record_reads_back() {
        assert_eq!(decode_node(&encode_node(9)), Some(9));
        assert_eq!(decode_node(&encode_node(9)[1..]), None);
        let node = SingleNode::at(3);
        assert_eq!(node.open_epoch(None), 3);
        assert_eq!(node.open_epoch(Some(1)), 3);
        assert_eq!(node.open_epoch(Some(5)), 6);
        assert!(node.may_write(3));
    }

    /// A second node on the bucket, or the same node started again, stops
    /// the first.
    #[test]
    fn a_node_that_another_replaces_writes_nothing() {
        let bucket: Arc<dyn Bucket> = Arc::new(MemoryBucket::new());
        let io = Arc::new(BucketIo::new(bucket).unwrap());
        let every = Duration::from_millis(10);
        let first = SingleNode::start_with(&io, "a", every).unwrap();
        first.refresh_now();
        assert!(first.may_write(first.epoch()));
        let again = SingleNode::start_with(&io, "a", every).unwrap();
        assert!(again.epoch() > first.epoch());
        first.refresh_now();
        assert!(
            !first.may_write(first.epoch()),
            "a restart fences the old process"
        );
        let other = SingleNode::start_with(&io, "b", every).unwrap();
        again.refresh_now();
        assert!(
            !again.may_write(again.epoch()),
            "another node fences this one"
        );
        other.refresh_now();
        assert!(other.may_write(other.epoch()));
    }

    fn node(every: Duration) -> (Arc<MemoryBucket>, Arc<BucketIo>, SingleNode) {
        let bucket = Arc::new(MemoryBucket::new());
        let shared: Arc<dyn Bucket> = bucket.clone();
        let io = Arc::new(BucketIo::new(shared).unwrap());
        let node = SingleNode::start_with(&io, "a", every).unwrap();
        (bucket, io, node)
    }

    fn wait_for_reading(node: &SingleNode) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while node.checking.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn the_lapse_scales_with_the_interval() {
        assert_eq!(lapse_after(Duration::from_secs(1)), LAPSE);
        assert_eq!(lapse_after(Duration::from_secs(10)), LAPSE);
        assert_eq!(lapse_after(READING_EVERY), Duration::from_secs(540));
        assert_eq!(
            lapse_after(Duration::from_secs(3600)),
            Duration::from_hours(3)
        );
    }

    /// The default's arithmetic, and that it spends what it says.
    #[test]
    fn a_reading_is_two_gets_and_a_day_of_them_fits_a_metered_store() {
        let (bucket, _io, node) = node(READING_EVERY);
        let before = bucket.requests();
        node.refresh_now();
        let after = bucket.requests();
        assert_eq!(after.gets - before.gets, 2);
        assert_eq!(after.lists, before.lists);
        let readings = 86_400 / READING_EVERY.as_secs();
        assert!(readings * 2 <= 1_000, "{} GETs a day", readings * 2);
    }

    /// One failed reading stops nothing, and neither does a second; the
    /// node stops only after the lapse.
    #[test]
    fn failed_readings_stop_writes_only_after_the_lapse() {
        let every = Duration::from_secs(100);
        let (bucket, _io, node) = node(every);
        bucket.refuse_reads(true);
        node.unconfirmed_for(every * 2);
        node.refresh_now();
        assert!(node.may_write(1), "two intervals without a reading");
        assert_eq!(node.stopped(), None);
        node.unconfirmed_for(lapse_after(every));
        node.refresh_now();
        assert!(!node.may_write(1));
        assert_eq!(node.stopped(), Some(LAPSED));
    }

    /// The bucket refuses reads for a while and answers again: nothing
    /// else claimed it, so the node writes again.
    #[test]
    fn a_node_that_lapsed_only_because_it_could_not_read_resumes() {
        let every = Duration::from_secs(10);
        let (bucket, _io, node) = node(every);
        bucket.refuse_reads(true);
        node.unconfirmed_for(lapse_after(every));
        node.refresh_now();
        assert!(!node.may_write(1));
        node.refresh_now();
        assert!(!node.may_write(1), "a failed reading ends no lapse");
        bucket.refuse_reads(false);
        node.refresh_now();
        assert!(node.may_write(1));
        assert_eq!(node.stopped(), None);
        assert!(!node.lock().lapsed);
    }

    /// A start while a node has lapsed stops it for good, however well the
    /// bucket reads after, even if that start is long gone.
    #[test]
    fn a_node_replaced_during_its_lapse_never_resumes() {
        let every = Duration::from_secs(10);
        for other in ["a", "b"] {
            let (bucket, io, node) = node(every);
            bucket.refuse_reads(true);
            node.unconfirmed_for(lapse_after(every));
            node.refresh_now();
            bucket.refuse_reads(false);
            drop(SingleNode::start_with(&io, other, every).unwrap());
            node.refresh_now();
            assert!(!node.may_write(1), "replaced by {other}");
            assert_ne!(node.stopped(), Some(LAPSED));
            assert!(node.stopped().is_some());
            // No reading is spent on a node that is stopped for good.
            let before = bucket.requests().gets;
            node.unconfirmed_for(every * 2);
            node.refresh();
            wait_for_reading(&node);
            assert_eq!(bucket.requests().gets, before);
        }
    }

    /// One record alone does not end a lapse, and the one that names
    /// another process stops it for good.
    #[test]
    fn a_lapse_ends_only_on_both_records() {
        let every = Duration::from_secs(10);
        let (bucket, _io, node) = node(every);
        let run = node.run.0.clone();
        bucket.refuse_reads(true);
        node.unconfirmed_for(lapse_after(every));
        node.refresh_now();
        bucket.refuse_reads(false);
        let kept = bucket.peek(&run).unwrap();
        bucket.remove(&run);
        node.refresh_now();
        assert!(!node.may_write(1), "the run object is gone");
        bucket.insert(&run, kept);
        node.refresh_now();
        assert!(node.may_write(1));
        bucket.insert(&run, b"another".to_vec());
        node.unconfirmed_for(every);
        node.refresh_now();
        assert_eq!(node.stopped(), Some(ANOTHER_PROCESS));
    }

    /// A record that is gone or does not read names nobody: the node stops,
    /// but not for good.
    #[test]
    fn a_record_that_names_nobody_is_not_a_replacement() {
        let every = Duration::from_secs(10);
        let (bucket, _io, node) = node(every);
        let kept = bucket.peek(ACTIVE).unwrap();
        bucket.remove(ACTIVE);
        node.unconfirmed_for(lapse_after(every));
        node.refresh_now();
        assert_eq!(node.stopped(), Some(LAPSED));
        bucket.insert(ACTIVE, b"not a record".to_vec());
        node.refresh_now();
        assert_eq!(node.stopped(), Some(LAPSED));
        bucket.insert(ACTIVE, kept);
        node.refresh_now();
        assert_eq!(node.stopped(), None);
    }

    /// A refused reading waits the whole interval, like any other, and
    /// spends one GET: a cap is not read against once a second.
    #[test]
    fn a_refused_reading_is_not_tried_again_before_the_interval() {
        let every = Duration::from_secs(60);
        let (bucket, _io, node) = node(every);
        bucket.refuse_reads(true);
        let before = bucket.requests().gets;
        for _ in 0..50 {
            node.refresh();
            wait_for_reading(&node);
        }
        assert_eq!(bucket.requests().gets, before, "not due yet");
        node.lock().tried = Instant::now() - every;
        for _ in 0..50 {
            node.refresh();
            wait_for_reading(&node);
        }
        assert_eq!(bucket.requests().gets, before + 1, "one GET, once");
    }
}
