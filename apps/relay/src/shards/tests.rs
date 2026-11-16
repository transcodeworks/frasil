//! The shards against an in-memory bucket that delays, fails and crashes:
//! no acknowledged batch is lost and none is applied twice, whatever write
//! the bucket and the node crash at; folds run beside writes; a batch,
//! snapshot or manifest that lands late is never read; commits across
//! shards go in order; erased spaces' records are collected; each shard's
//! timeline travels with it; and cold opens of many small shards,
//! measured.

use super::bucket::{Bucket, BucketIo, MemoryBucket, Requests, S3Bucket};
use super::fence::{Fence, SingleNode, lapse_after};
use super::format::{self, Batch, Manifest};
use super::*;
use crate::clock::ManualClock;
use crate::records::Records;
use frasil_events::EventId;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A directory of its own under the system's temporary directory, removed
/// when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let random = crate::util::hex(&*frasil_crypto::random_bytes::<8>().unwrap());
        let path = std::env::temp_dir().join(format!("frasil-shards-{name}-{random}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node over a bucket, its working copies in `cache`.
fn node(bucket: &Arc<MemoryBucket>, cache: &Path) -> Arc<Shards> {
    node_with(bucket, cache, &Arc::new(ManualClock::new(1000)))
}

/// A node over a bucket on a clock the test moves.
fn node_with(bucket: &Arc<MemoryBucket>, cache: &Path, clock: &Arc<ManualClock>) -> Arc<Shards> {
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let fence = SingleNode::start(&io, "test").unwrap();
    let shards = Shards::bucket(io, cache, Arc::new(fence)).unwrap();
    let clock: Arc<dyn Clock> = clock.clone();
    shards.set_clock(clock);
    shards
}

fn commit(
    store: &dyn Store,
    puts: Vec<(Vec<u8>, Vec<u8>)>,
    deletes: Vec<Vec<u8>>,
) -> Result<(), StoreError> {
    match shard::ready(store.commit(&Commit::new(puts, deletes)))? {
        true => Ok(()),
        false => Err(StoreError::new("refused")),
    }
}

fn get(store: &dyn Store, address: &[u8]) -> Option<Vec<u8>> {
    shard::ready(store.get(address)).unwrap()
}

fn space(n: u8) -> EventId {
    EventId([n; 32])
}

fn journal(space: &EventId, index: u64) -> Vec<u8> {
    Records::journal_address(space, index)
}

/// What a test knows is at rest: each address's record, or none.
type Model = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// A commit's records to write.
type Puts = Vec<(Vec<u8>, Vec<u8>)>;

/// One step of the workload: a commit to one space's shard, with a delete
/// every third step, and the index's wait marker every fourth.
fn step(i: u64) -> (Puts, Vec<Vec<u8>>) {
    let a = space(1);
    let mut puts = vec![
        (journal(&a, i), i.to_be_bytes().to_vec()),
        (journal(&a, 1 << 40), i.to_be_bytes().to_vec()),
    ];
    let mut deletes = Vec::new();
    if i % 3 == 2 {
        deletes.push(journal(&a, i - 1));
    }
    if i % 4 == 3 {
        puts.push((Records::waits_address(&a), i.to_be_bytes().to_vec()));
        puts.push((journal(&space(2), i), vec![2]));
    }
    (puts, deletes)
}

fn apply(model: &mut Model, puts: &[(Vec<u8>, Vec<u8>)], deletes: &[Vec<u8>]) {
    for address in deletes {
        model.insert(address.clone(), None);
    }
    for (address, record) in puts {
        model.insert(address.clone(), Some(record.clone()));
    }
}

/// Runs the workload from step `from`, folding often and closing the
/// space's shard every seventh step, until a step fails: returns the steps
/// acknowledged and the one that failed.
fn run(shards: &Shards, model: &mut Model, from: u64, to: u64) -> (u64, Option<u64>) {
    let a_shard = space_shard(space(1).as_bytes());
    for i in from..to {
        let (puts, deletes) = step(i);
        let made = commit(shards, puts.clone(), deletes.clone());
        shards.settle_folds();
        if made.is_err() {
            return (i, Some(i));
        }
        apply(model, &puts, &deletes);
        if i % 7 == 6 && shards.close_shard(&a_shard).is_err() {
            return (i + 1, None);
        }
    }
    (to, None)
}

/// Checks a node against what was acknowledged: every acknowledged record
/// as it was left, unless the step whose outcome is unknown changed it.
fn check(shards: &Shards, model: &Model, unknown: Option<u64>, context: &str) {
    let maybe: Model = unknown
        .map(|i| {
            let (puts, deletes) = step(i);
            let mut changes = Model::new();
            apply(&mut changes, &puts, &deletes);
            changes
        })
        .unwrap_or_default();
    let mut addresses: Vec<&Vec<u8>> = model.keys().collect();
    addresses.extend(maybe.keys());
    for address in addresses {
        let held = get(shards, address);
        let acknowledged = model.get(address).cloned().flatten();
        let ok = held == acknowledged || maybe.get(address).is_some_and(|record| *record == held);
        assert!(
            ok,
            "{context}: {} holds {held:?}, acknowledged {acknowledged:?}",
            crate::util::hex(address)
        );
    }
}

/// Writes (PUTs and DELETEs) a bucket has served.
fn writes(requests: Requests) -> u64 {
    requests.puts + requests.deletes
}

/// The key of a shard's latest manifest in the bucket.
fn latest_manifest(bucket: &MemoryBucket, root: &str) -> String {
    bucket
        .keys()
        .into_iter()
        .filter(|key| key.starts_with(&format!("{root}{}", format::MANIFEST_PREFIX)))
        .max()
        .expect("a manifest")
}

/// No working copy applied a position twice, or out of order, since it
/// opened.
fn applied_once(shards: &Shards, context: &str) {
    for (name, log) in shards.applied_logs() {
        assert!(
            log.windows(2).all(|pair| pair[0] < pair[1]),
            "{context}: {name} applied {log:?}"
        );
    }
}

/// A copy of a cache directory as a crash leaves it: with each working
/// copy's write-ahead log as it was (`wal`), or without it, as a power loss
/// leaves a database at `synchronous=NORMAL` at its last checkpoint.
fn crashed_copy(cache: &Path, wal: bool) -> Dir {
    let copy = Dir::new("crashed");
    for entry in std::fs::read_dir(cache).unwrap().flatten() {
        let name = entry.file_name().into_string().unwrap();
        let keep = name.ends_with(".sqlite") || (wal && name.ends_with(".sqlite-wal"));
        if keep {
            std::fs::copy(entry.path(), copy.0.join(&name)).unwrap();
        }
    }
    copy
}

#[test]
fn batches_reach_the_bucket_before_the_working_copy() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("ack");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    commit(&*shards, vec![(journal(&a, 0), vec![7])], Vec::new()).unwrap();
    let root = format!("{}/", space_shard(a.as_bytes()));
    let logs: Vec<String> = bucket
        .keys()
        .into_iter()
        .filter(|key| key.starts_with(&format!("{root}log/")))
        .collect();
    assert_eq!(logs.len(), 1, "{:?}", bucket.keys());
    let batch = Batch::decode(&bucket.peek(&logs[0]).unwrap()).unwrap();
    assert_eq!(batch.changes, vec![(journal(&a, 0), Some(vec![7]))]);
    assert!(batch.reading.is_some());
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![7]));
    let first = latest_manifest(&bucket, &root);
    assert_eq!(
        Manifest::decode(&bucket.peek(&first).unwrap())
            .unwrap()
            .next,
        1
    );

    // A batch the bucket refuses is not applied, and the shard opens again
    // under a new epoch before its next batch.
    bucket.fail_puts("log/", 1);
    assert!(commit(&*shards, vec![(journal(&a, 1), vec![8])], Vec::new()).is_err());
    assert_eq!(get(&*shards, &journal(&a, 1)), None);
    commit(&*shards, vec![(journal(&a, 2), vec![9])], Vec::new()).unwrap();
    let again = latest_manifest(&bucket, &root);
    assert!(again > first);
    assert!(
        Manifest::decode(&bucket.peek(&again).unwrap())
            .unwrap()
            .epoch
            > 1
    );
    assert_eq!(get(&*shards, &journal(&a, 2)), Some(vec![9]));
    applied_once(&shards, "a refused batch");
}

#[test]
fn a_shard_opens_from_its_snapshot_and_the_log_after_it() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("open");
    let mut model = Model::new();
    {
        let shards = node(&bucket, &cache.0);
        shards.set_fold(4, 1);
        assert_eq!(run(&shards, &mut model, 0, 30), (30, None));
        // The node stops without closing anything.
    }
    let root = format!("{}/", space_shard(space(1).as_bytes()));
    let count = |prefix: &str| {
        bucket
            .keys()
            .into_iter()
            .filter(|key| key.starts_with(&format!("{root}{prefix}")))
            .count()
    };
    assert_eq!(count("snapshot-"), 1, "old snapshots are deleted");
    assert!(count("manifest-") <= 3, "old manifests are deleted");
    // On another machine, with an empty cache.
    let other = Dir::new("open-other");
    let shards = node(&bucket, &other.0);
    check(&shards, &model, None, "another machine");
    // Again on the first, whose working copy is in its cache: fewer GETs.
    drop(shards);
    let before = bucket.requests();
    let shards = node(&bucket, &cache.0);
    check(&shards, &model, None, "the same machine");
    let warm = bucket.requests().gets - before.gets;
    let before = bucket.requests();
    let cold = Dir::new("open-cold");
    let shards = node(&bucket, &cold.0);
    check(&shards, &model, None, "a third machine");
    let cold = bucket.requests().gets - before.gets;
    assert!(warm < cold, "warm {warm}, cold {cold}");
    applied_once(&shards, "a third machine");
}

/// A crash of the bucket and the node at every write of the workload: each
/// batch PUT, each snapshot, manifest and deletion of its folds, and each
/// close. A new node finds every acknowledged batch and applies none twice:
/// on another machine; on the same one with its working copies as the
/// process left them; and on the same one after a power loss that lost the
/// working copies' write-ahead logs. Then it carries on.
#[test]
fn a_crash_at_any_write_loses_no_acknowledged_batch() {
    const STEPS: u64 = 16;
    // The writes of a run with no crash.
    let total = {
        let bucket = Arc::new(MemoryBucket::new());
        let cache = Dir::new("count");
        let shards = node(&bucket, &cache.0);
        shards.set_fold(3, 1);
        let before = writes(bucket.requests());
        let mut model = Model::new();
        assert_eq!(run(&shards, &mut model, 0, STEPS), (STEPS, None));
        writes(bucket.requests()) - before
    };
    assert!(total > 2 * STEPS, "folds and closes write too: {total}");
    let started = Instant::now();
    for restart in ["another machine", "the same machine", "a power loss"] {
        for crash in 0..total {
            let bucket = Arc::new(MemoryBucket::new());
            let cache = Dir::new("crash");
            let mut model = Model::new();
            let (done, unknown, kept) = {
                let shards = node(&bucket, &cache.0);
                shards.set_fold(3, 1);
                bucket.crash_after(crash);
                let (done, unknown) = run(&shards, &mut model, 0, STEPS);
                // The node dies with the bucket: its cache as it is now.
                let kept = match restart {
                    "the same machine" => Some(crashed_copy(&cache.0, true)),
                    "a power loss" => Some(crashed_copy(&cache.0, false)),
                    _ => None,
                };
                (done, unknown, kept)
            };
            bucket.recover();
            let context = format!("crash at write {crash}, then {restart}");
            let other = Dir::new("crash-other");
            let at = kept.as_ref().map_or(&other.0, |kept| &kept.0);
            let shards = node(&bucket, at);
            shards.set_fold(3, 1);
            check(&shards, &model, unknown, &context);
            applied_once(&shards, &context);
            // The step whose outcome was unknown is made again, as a device
            // sends again what was not acknowledged; then the rest.
            let next = unknown.unwrap_or(done);
            let (puts, deletes) = step(next);
            commit(&*shards, puts.clone(), deletes.clone()).unwrap();
            apply(&mut model, &puts, &deletes);
            let (_, failed) = run(&shards, &mut model, next + 1, STEPS + 6);
            assert_eq!(failed, None, "{context}");
            applied_once(&shards, &context);
            drop(shards);
            let again = Dir::new("crash-again");
            let shards = node(&bucket, &again.0);
            check(&shards, &model, None, &format!("{context}, after"));
        }
    }
    println!(
        "{total} crash points, each with three restarts, in {:?}",
        started.elapsed()
    );
}

/// Folds run on the bucket's runtime while batches go on: none is lost.
#[test]
fn folds_concurrent_with_writes_lose_nothing() {
    let bucket = Arc::new(MemoryBucket::new());
    bucket.set_delay(Duration::from_millis(3));
    let cache = Dir::new("concurrent");
    let shards = node(&bucket, &cache.0);
    shards.set_fold(2, 1);
    let mut model = Model::new();
    for i in 0..40 {
        let (puts, deletes) = step(i);
        commit(&*shards, puts.clone(), deletes.clone()).unwrap();
        apply(&mut model, &puts, &deletes);
    }
    shards.settle_folds();
    let root = format!("{}/", space_shard(space(1).as_bytes()));
    let manifest =
        Manifest::decode(&bucket.peek(&latest_manifest(&bucket, &root)).unwrap()).unwrap();
    assert!(manifest.snapshot.is_some(), "a fold ended");
    applied_once(&shards, "concurrent folds");
    drop(shards);
    let other = Dir::new("concurrent-other");
    let shards = node(&bucket, &other.0);
    check(&shards, &model, None, "after concurrent folds");
}

/// A snapshot PUT and a manifest PUT whose answers are lost, which land
/// late: the shard keeps folding, and opens from its latest manifest
/// whose snapshot is in the bucket.
#[test]
fn a_snapshot_or_manifest_that_lands_late_is_harmless() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("late-fold");
    let shards = node(&bucket, &cache.0);
    shards.set_fold(3, 1);
    let mut model = Model::new();
    let root = format!("{}/", space_shard(space(1).as_bytes()));
    bucket.hold_puts(&format!("{root}snapshot-"), 1);
    assert_eq!(run(&shards, &mut model, 0, 8), (8, None));
    bucket.hold_puts(&format!("{root}manifest-"), 1);
    assert_eq!(run(&shards, &mut model, 8, 16), (16, None));
    // The held PUTs land now, after later folds deleted what they name.
    let landed = bucket.release_held();
    assert_eq!(landed.len(), 2, "{landed:?}");
    drop(shards);
    let other = Dir::new("late-fold-other");
    let shards = node(&bucket, &other.0);
    check(&shards, &model, None, "after late landings");
    // A manifest above the rest whose snapshot is gone is passed over.
    let latest = latest_manifest(&bucket, &root);
    let mut bogus = Manifest::decode(&bucket.peek(&latest).unwrap()).unwrap();
    bogus.epoch += 5;
    bogus.snapshot = Some(format::SnapshotRef {
        position: (bogus.epoch, 99),
        bytes: 1,
    });
    bogus.runs.clear();
    bogus.next = 100;
    let key = format!("{root}{}", format::manifest_key(bogus.epoch, 1));
    shards
        .layout_io()
        .block({
            let bucket = bucket.clone();
            let bytes = bogus.encode();
            async move { bucket.put(&key, bytes).await }
        })
        .unwrap();
    drop(shards);
    let third = Dir::new("late-fold-third");
    let shards = node(&bucket, &third.0);
    check(
        &shards,
        &model,
        None,
        "past a manifest whose snapshot is gone",
    );
    // Its next fold deletes what landed late.
    shards.set_fold(1, 1);
    commit(
        &*shards,
        vec![(journal(&space(1), 500), vec![5])],
        Vec::new(),
    )
    .unwrap();
    shards.settle_folds();
    for key in landed {
        assert!(bucket.peek(&key).is_none(), "{key} is cleaned up");
    }
}

/// A fold whose clean-up fails is kept all the same, and a later fold
/// cleans up; nothing folds again batch after batch.
#[test]
fn a_fold_kept_whatever_its_clean_up() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("cleanup");
    let shards = node(&bucket, &cache.0);
    // By batches alone: a fold by bytes would start at the first batch,
    // and which batches its snapshot holds would depend on how soon it
    // ran, and with it when the next fold starts.
    shards.set_fold(3, u64::MAX);
    let a = space(1);
    for i in 0..3 {
        commit(&*shards, vec![(journal(&a, i), vec![1])], Vec::new()).unwrap();
    }
    shards.settle_folds();
    // Deletes fail: the bucket crashes after the third batch's PUT and the
    // fold's two, set before the batch that starts the fold, so that the
    // fold cannot be done before the crash is set.
    let before = bucket.requests().puts;
    for i in 3..5 {
        commit(&*shards, vec![(journal(&a, i), vec![1])], Vec::new()).unwrap();
    }
    bucket.crash_after(3);
    commit(&*shards, vec![(journal(&a, 5), vec![1])], Vec::new()).unwrap();
    shards.settle_folds();
    bucket.recover();
    let puts = bucket.requests().puts - before;
    // Three batches, a snapshot and its manifest.
    assert_eq!(puts, 5, "the fold is taken in");
    commit(&*shards, vec![(journal(&a, 6), vec![1])], Vec::new()).unwrap();
    shards.settle_folds();
    assert_eq!(
        bucket.requests().puts - before,
        6,
        "no fold after one batch"
    );
}

/// An idle open shard keeps its reading in a new manifest once a minute,
/// and a close of a shard with nothing new uploads no snapshot.
#[test]
fn an_idle_shard_keeps_its_reading_in_its_manifest() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("idle");
    let clock = Arc::new(ManualClock::new(1000));
    let shards = node_with(&bucket, &cache.0, &clock);
    let a = space(1);
    let name = space_shard(a.as_bytes());
    commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
    shards.close_shard(&name).unwrap();
    assert!(get(&*shards, &journal(&a, 0)).is_some());
    let root = format!("{name}/");
    let snapshots = |bucket: &MemoryBucket| {
        bucket
            .keys()
            .iter()
            .filter(|key| key.starts_with(&format!("{root}snapshot-")))
            .count()
    };
    let snapshot_puts = snapshots(&bucket);
    let before = bucket.requests();
    clock.advance(61);
    shards.maintain();
    shards.layout_io().block(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let after = bucket.requests();
    assert_eq!(after.puts - before.puts, 1, "one manifest");
    let latest = Manifest::decode(&bucket.peek(&latest_manifest(&bucket, &root)).unwrap()).unwrap();
    assert!(latest.reading.unwrap().timeline >= 61);
    shards.maintain();
    assert_eq!(
        bucket.requests().puts,
        after.puts,
        "not again within the minute"
    );
    shards.close_shard(&name).unwrap();
    assert_eq!(
        snapshots(&bucket),
        snapshot_puts,
        "no snapshot for nothing new"
    );
}

/// A library create reads the genesis's sight on the timeline of the
/// shard it goes to, not on a shard of spaces of no library.
#[test]
fn a_shard_named_reads_its_own_timeline() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("reading-of");
    let clock = Arc::new(ManualClock::new(1000));
    let shards = node_with(&bucket, &cache.0, &clock);
    let library = "libraries/6c6962";
    assert_eq!(shards.reading_of(library, clock.now()).unwrap().timeline, 0);
    clock.advance(50);
    assert_eq!(
        shards.reading_of(library, clock.now()).unwrap().timeline,
        50
    );
    assert!(
        !shards
            .open_names()
            .iter()
            .any(|name| name.starts_with("spaces/")),
        "no shard of spaces opened"
    );
    assert_eq!(
        shards.reading_of("index/0", clock.now()).unwrap(),
        clock.now()
    );
}

/// A shard of spaces drops the records of a space the index says is
/// erased, which a crash between an erasure's two steps leaves.
#[test]
fn records_of_erased_spaces_are_collected() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("collect");
    let shards = node(&bucket, &cache.0);
    let (a, b) = (space(1), space(3));
    commit(
        &*shards,
        vec![(journal(&a, 0), vec![1]), (journal(&b, 0), vec![2])],
        Vec::new(),
    )
    .unwrap();
    // The erasure's first step, alone.
    commit(
        &*shards,
        vec![(Records::tombstone_address(&a), vec![9])],
        Vec::new(),
    )
    .unwrap();
    for name in [space_shard(a.as_bytes()), space_shard(b.as_bytes())] {
        shards.close_shard(&name).unwrap();
    }
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    get(&*shards, &journal(&b, 0));
    // The walk runs on the bucket's runtime, off the writer's thread, and a
    // later maintenance commits what it found.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while get(&*shards, &journal(&a, 0)).is_some() {
        assert!(std::time::Instant::now() < deadline, "collected");
        shards.maintain();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(get(&*shards, &journal(&b, 0)), Some(vec![2]));
}

/// A PUT whose answer is lost may land: the shard opens again under a new
/// epoch and adopts it if it is there; one that lands after that is never
/// read, and the next fold deletes it.
#[test]
fn a_batch_that_lands_late_is_never_read() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("late");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
    // The answer is lost; the batch lands.
    bucket.set_land_failed(true);
    bucket.fail_puts("log/", 1);
    assert!(commit(&*shards, vec![(journal(&a, 1), vec![2])], Vec::new()).is_err());
    bucket.set_land_failed(false);
    // The shard opens again and adopts it.
    commit(&*shards, vec![(journal(&a, 2), vec![3])], Vec::new()).unwrap();
    assert_eq!(get(&*shards, &journal(&a, 1)), Some(vec![2]));
    // Now a batch of the old epoch lands after the shard opened again.
    let root = format!("{}/", space_shard(a.as_bytes()));
    let manifest =
        Manifest::decode(&bucket.peek(&latest_manifest(&bucket, &root)).unwrap()).unwrap();
    let old = manifest.runs.last().copied().expect("the adopted run");
    let late = Batch {
        changes: vec![(journal(&a, 0), Some(vec![66]))],
        reading: None,
    };
    let late_key = format!("{root}{}", format::log_key((old.epoch, old.last + 1)));
    shards
        .layout_io()
        .block({
            let bucket = bucket.clone();
            let key = late_key.clone();
            async move { bucket.put(&key, late.encode()).await }
        })
        .unwrap();
    drop(shards);
    let other = Dir::new("late-other");
    let shards = node(&bucket, &other.0);
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]), "never read");
    assert_eq!(get(&*shards, &journal(&a, 2)), Some(vec![3]));
    // A fold deletes it.
    shards.set_fold(1, 1);
    commit(&*shards, vec![(journal(&a, 3), vec![4])], Vec::new()).unwrap();
    shards.settle_folds();
    assert!(bucket.peek(&late_key).is_none());
}

/// A commit across shards: the shard of the space's records first, then
/// the index; one that deletes a space's records, the index first. A
/// placement whose commit fails is put back.
#[test]
fn commits_across_shards_go_in_order() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("order");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let library = "libraries/6c6962";
    let hosted = |shard: &str| (Records::hosted_address(&a), Records::hosted_record(shard));
    // The index's PUT fails: the journal is at rest, the index is not, and
    // the placement is put back.
    bucket.fail_puts("index/", 1);
    assert!(
        commit(
            &*shards,
            vec![(journal(&a, 0), vec![1]), hosted(library)],
            Vec::new()
        )
        .is_err()
    );
    assert!(shards.placed().is_empty(), "the placement is put back");
    let hashed = space_shard(a.as_bytes());
    commit(
        &*shards,
        vec![(journal(&a, 0), vec![1]), hosted(&hashed)],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    // An erasure: the space shard's PUT fails, the tombstone is at rest.
    bucket.fail_puts("spaces/", 1);
    let erase = (
        vec![(Records::tombstone_address(&a), vec![9])],
        vec![journal(&a, 0), Records::hosted_address(&a)],
    );
    assert!(commit(&*shards, erase.0.clone(), erase.1.clone()).is_err());
    assert_eq!(
        get(&*shards, &Records::tombstone_address(&a)),
        Some(vec![9])
    );
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    commit(&*shards, erase.0, erase.1).unwrap();
    assert_eq!(get(&*shards, &journal(&a, 0)), None);
    assert!(shards.placed().is_empty());
}

/// An index shard that opens again reads its placements again.
#[test]
fn an_index_shard_that_opens_again_reads_its_placements() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("replace");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let library = "libraries/6c6962";
    commit(
        &*shards,
        vec![
            (Records::hosted_address(&a), Records::hosted_record(library)),
            (journal(&a, 0), vec![1]),
        ],
        Vec::new(),
    )
    .unwrap();
    let index = hashed(INDEX, a.as_bytes(), HASHED);
    // A PUT whose answer is lost and that did not land: the index breaks.
    bucket.fail_puts("index/", 1);
    assert!(
        commit(
            &*shards,
            vec![(
                Records::hosted_address(&a),
                Records::hosted_record("spaces/00")
            )],
            Vec::new(),
        )
        .is_err()
    );
    // Opening again, it names the library's shard, as the bucket does.
    assert!(get(&*shards, &Records::hosted_address(&a)).is_some());
    assert!(shards.open_names().contains(&index));
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
}

/// A library's shard keeps a timeline of its own: its reading at a close
/// is kept, and another node, with another cache, that opens it again
/// counts on from there, with the wall clock's advance meanwhile
/// (overview.md, 6.7). The hashed shards read the node's.
#[test]
fn a_shards_timeline_travels_with_it() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("timeline");
    let clock = Arc::new(ManualClock::new(5000));
    let shards = node_with(&bucket, &cache.0, &clock);
    let a = space(1);
    let library = "libraries/6c6962";
    commit(
        &*shards,
        vec![
            (Records::hosted_address(&a), Records::hosted_record(library)),
            (journal(&a, 0), vec![1]),
        ],
        Vec::new(),
    )
    .unwrap();
    let address = journal(&a, 0);
    // A new shard's timeline starts at 0.
    assert_eq!(shards.reading(&address, clock.now()).unwrap().timeline, 0);
    clock.advance(100);
    assert_eq!(shards.reading(&address, clock.now()).unwrap().timeline, 100);
    shards.close_all().unwrap();
    drop(shards);
    // Another node, on another machine, 3,900 seconds later by its clocks.
    clock.advance(3900);
    let other = Dir::new("timeline-other");
    let shards = node_with(&bucket, &other.0, &clock);
    let later = shards.reading(&address, clock.now()).unwrap();
    assert_eq!(later.timeline, 4000);
    assert_eq!(later.run, 2);
    let index = Records::hosted_address(&a);
    assert_eq!(shards.reading(&index, clock.now()).unwrap(), clock.now());
}

#[test]
fn a_data_directory_keeps_the_same_shards() {
    let dir = Dir::new("local");
    let a = space(1);
    {
        let shards = Shards::local(&dir.0).unwrap();
        shards.set_clock(Arc::new(ManualClock::new(10)));
        commit(
            &*shards,
            vec![
                (journal(&a, 0), vec![1]),
                (
                    Records::hosted_address(&a),
                    Records::hosted_record(&space_shard(a.as_bytes())),
                ),
            ],
            Vec::new(),
        )
        .unwrap();
        shards.close_all().unwrap();
    }
    let shards = Shards::local(&dir.0).unwrap();
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    assert_eq!(shards.placed(), [*a.as_bytes()].into());
    let files: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".sqlite"))
        .collect();
    assert!(files.contains(&"index-0.sqlite".to_owned()), "{files:?}");
    assert!(files.contains(&format!(
        "{}.sqlite",
        space_shard(a.as_bytes()).replace('/', "-")
    )));
}

/// Opens `count` small library shards, each with a few records and closed
/// cleanly, on a node with an empty cache: the time, and the requests per
/// shard.
fn cold_open(count: u32) {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("many");
    let ids: Vec<EventId> = (0..count)
        .map(|n| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id[31] = 1;
            EventId(id)
        })
        .collect();
    let shard_of = |n: u32| format!("libraries/{}", crate::util::hex(&n.to_be_bytes()));
    {
        let shards = node(&bucket, &cache.0);
        let started = Instant::now();
        for (n, id) in ids.iter().enumerate() {
            let n = u32::try_from(n).unwrap();
            commit(
                &*shards,
                vec![
                    (
                        Records::hosted_address(id),
                        Records::hosted_record(&shard_of(n)),
                    ),
                    (journal(id, 0), vec![n as u8; 200]),
                    (journal(id, 1), vec![1; 300]),
                    (Records::object_address(id, &[2; 64]), vec![2; 100]),
                ],
                Vec::new(),
            )
            .unwrap();
        }
        let wrote = started.elapsed();
        let started = Instant::now();
        shards.close_all().unwrap();
        println!(
            "{count} shards: written in {wrote:?}, closed in {:?}",
            started.elapsed()
        );
    }
    for (delay, label) in [
        (Duration::ZERO, "no delay"),
        (Duration::from_millis(20), "20 ms a request"),
    ] {
        if count > 1_000 && !delay.is_zero() {
            continue;
        }
        let empty = Dir::new("many-cold");
        let start = bucket.requests();
        let shards = node(&bucket, &empty.0);
        bucket.set_delay(delay);
        let index = bucket.requests();
        let started = Instant::now();
        for id in &ids {
            assert!(get(&*shards, &journal(id, 0)).is_some());
        }
        let took = started.elapsed();
        bucket.set_delay(Duration::ZERO);
        let opened = bucket.requests();
        let per = |n: u64| n as f64 / f64::from(count);
        println!(
            "{count} cold opens, {label}: {took:?} ({:?} each); per shard {:.2} GET, {:.2} PUT, \
             {:.2} LIST; node start {} requests",
            took / count,
            per(opened.gets - index.gets),
            per(opened.puts - index.puts),
            per(opened.lists - index.lists),
            index.total() - start.total()
        );
    }
}

/// `cargo test -p frasil-relay --release -- --ignored --nocapture cold_opens`
#[test]
#[ignore = "a measurement"]
fn cold_opens_of_1000_shards() {
    cold_open(1_000);
}

/// `cargo test -p frasil-relay --release -- --ignored --nocapture cold_opens`
#[test]
#[ignore = "a measurement"]
fn cold_opens_of_10000_shards() {
    cold_open(10_000);
}

#[test]
fn cold_opens_of_a_few_shards() {
    cold_open(20);
}

/// The bucket as a real S3-compatible service: set `FRASIL_TEST_S3_ENDPOINT`
/// (loopback HTTP, or HTTPS), `FRASIL_TEST_S3_BUCKET`,
/// `FRASIL_TEST_S3_ACCESS_KEY` and `FRASIL_TEST_S3_SECRET_KEY`, then
/// `cargo test -p frasil-relay -- --ignored --nocapture a_real_bucket`.
/// Checks read-after-write for new and overwritten keys, LIST after PUT and
/// DELETE, and a shard's batches, snapshot and reopening.
#[test]
#[ignore = "needs an S3-compatible service"]
fn a_real_bucket() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is set"));
    let config = crate::config::S3Config {
        endpoint: var("FRASIL_TEST_S3_ENDPOINT"),
        region: std::env::var("FRASIL_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        bucket: var("FRASIL_TEST_S3_BUCKET"),
        access_key: var("FRASIL_TEST_S3_ACCESS_KEY"),
        secret_key: var("FRASIL_TEST_S3_SECRET_KEY"),
        prefix: String::new(),
        path_style: true,
    };
    let tag = crate::util::hex(&*frasil_crypto::random_bytes::<6>().unwrap());
    let prefix = format!("frasil-test-{tag}/");
    let bucket: Arc<dyn Bucket> = Arc::new(S3Bucket::open(&config, &prefix).unwrap());
    let io = Arc::new(BucketIo::new(bucket.clone()).unwrap());
    let call = |work: BoxFuture<'static, Result<Option<Vec<u8>>, bucket::BucketError>>| {
        io.block(work).unwrap()
    };
    // Read-after-write, for a new key and an overwritten one, many times.
    let mut misses = 0;
    let started = Instant::now();
    for n in 0..100u32 {
        let key = format!("raw/{n}");
        for round in 0..2u8 {
            let bytes = vec![round; 1000];
            let b = bucket.clone();
            let k = key.clone();
            let put = bytes.clone();
            io.block(async move { b.put(&k, put).await }).unwrap();
            let b = bucket.clone();
            let k = key.clone();
            if call(Box::pin(async move { b.get(&k).await })) != Some(bytes) {
                misses += 1;
            }
        }
    }
    println!(
        "read-after-write: {misses} stale reads of 200, in {:?}",
        started.elapsed()
    );
    assert_eq!(misses, 0);
    // LIST after PUT and after DELETE.
    let b = bucket.clone();
    let listed = io.block(async move { b.list("raw/").await }).unwrap();
    println!("LIST after 100 PUTs: {} keys", listed.len());
    assert_eq!(listed.len(), 100);
    for n in 0..50u32 {
        let b = bucket.clone();
        io.block(async move { b.delete(&format!("raw/{n}")).await })
            .unwrap();
    }
    let b = bucket.clone();
    let listed = io.block(async move { b.list("raw/").await }).unwrap();
    println!("LIST after 50 DELETEs: {} keys", listed.len());
    assert_eq!(listed.len(), 50);
    let b = bucket.clone();
    assert_eq!(
        call(Box::pin(async move { b.get("raw/0").await })),
        None,
        "GET after DELETE"
    );
    // A shard on it.
    let cache = Dir::new("real");
    let fence = SingleNode::start(&io, "test").unwrap();
    let shards = Shards::bucket(io.clone(), &cache.0, Arc::new(fence)).unwrap();
    shards.set_fold(4, 1);
    let mut model = Model::new();
    let started = Instant::now();
    assert_eq!(run(&shards, &mut model, 0, 20), (20, None));
    println!("20 commits with folds and closes: {:?}", started.elapsed());
    shards.close_all().unwrap();
    drop(shards);
    let other = Dir::new("real-other");
    let fence = SingleNode::start(&io, "test").unwrap();
    let shards = Shards::bucket(io.clone(), &other.0, Arc::new(fence)).unwrap();
    check(&shards, &model, None, "a real bucket");
    // Clean up.
    let b = bucket.clone();
    let keys = io.block(async move { b.list("").await }).unwrap();
    for key in keys {
        let b = bucket.clone();
        io.block(async move { b.delete(&key).await }).unwrap();
    }
}

/// Which shards a test's node of a cluster owns: every hashed one, and the
/// others until the first open begins, when the epoch moves them away.
struct MovesAsItOpens {
    moved: std::sync::atomic::AtomicBool,
}

impl fence::Ownership for MovesAsItOpens {
    fn owns(&self, shard: &str) -> bool {
        is_hashed(shard) || !self.moved.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn may_open(&self, shard: &str) -> Result<(), StoreError> {
        if !self.owns(shard) {
            return Err(StoreError::new("not this node's"));
        }
        if !is_hashed(shard) {
            self.moved.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    fn get(&self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Err(StoreError::new("no other node"))
    }

    fn scan(&self, _: &str, _: &[u8]) -> Result<Found, StoreError> {
        Err(StoreError::new("no other node"))
    }

    fn commit(&self, _: &str, _: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Result<(), StoreError> {
        Err(StoreError::new("no other node"))
    }

    fn commit_if(
        &self,
        _: &str,
        _: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        _: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<bool, StoreError> {
        Err(StoreError::new("no other node"))
    }
}

/// An epoch that moves a shard while it opens: the open is dropped, and
/// nothing of the shard is written or kept open.
#[test]
fn a_shard_the_epoch_moves_as_it_opens_is_dropped() {
    let dir = Dir::new("moves");
    let bucket = Arc::new(MemoryBucket::new());
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let fence = SingleNode::start(&io, "test").unwrap();
    let ownership = Arc::new(MovesAsItOpens {
        moved: std::sync::atomic::AtomicBool::new(false),
    });
    let shards = Shards::clustered(io, &dir.0, Arc::new(fence), ownership).unwrap();
    let space = space(1);
    let written = commit(&*shards, vec![(journal(&space, 0), vec![1])], Vec::new());
    assert!(written.is_err(), "the batch is not made");
    let name = space_shard(space.as_bytes());
    assert!(!shards.open_names().contains(&name));
    assert!(
        bucket
            .keys()
            .iter()
            .all(|key| !key.starts_with(&format!("{name}/"))),
        "nothing of the shard is in the bucket"
    );
}

/// A shard handed over from another peer goes on from the reading that
/// peer kept of it, with the wall clock's advance since (overview.md, 6.7
/// Clocks of a replicated peer), and only while it holds no record.
#[test]
fn a_shard_taken_up_goes_on_from_the_other_peers_reading() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("take-up");
    let shards = node(&bucket, &cache.0);
    let name = format!("{LIBRARIES}/{}", crate::util::hex(b"project:t"));
    // The node's own wall clock, which the take-up reads.
    let wall = node_reading(&shards.clock).wall.unwrap();
    let kept = Reading {
        timeline: 5_000,
        wall: Some(wall - 30),
        run: 3,
    };
    shards.take_up(&name, kept).unwrap();
    let a = space(7);
    shards
        .commit_into(&name, vec![(journal(&a, 0), vec![1])], Vec::new())
        .unwrap();
    let reading = shards
        .reading_of(&name, node_reading(&shards.clock))
        .unwrap();
    assert!(reading.timeline >= 5_030, "{reading:?}");
    assert!(reading.run > 3);
    assert!(
        shards.take_up(&name, kept).is_err(),
        "it holds a record now"
    );
}

/// An idle close while a batch is on its way to the bucket: the close
/// waits for the batch, and folds it, so that what the writer acknowledged
/// is named by the manifest the close writes; the shard opens again for
/// the next batch, and a later fold deletes nothing that was acknowledged.
#[test]
fn a_close_during_a_batch_keeps_what_was_acknowledged() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("close-race");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let name = space_shard(a.as_bytes());
    let root = format!("{name}/");
    commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
    // The next batch's PUT is slow: the close begins while it is sent.
    bucket.slow_puts(&format!("{root}log/"), 1, Duration::from_millis(300));
    let writer = {
        let shards = shards.clone();
        std::thread::spawn(move || commit(&*shards, vec![(journal(&a, 1), vec![2])], Vec::new()))
    };
    std::thread::sleep(Duration::from_millis(100));
    shards.close_shard(&name).unwrap();
    // The close's manifest, read before anything opens the shard again.
    let latest = Manifest::decode(&bucket.peek(&latest_manifest(&bucket, &root)).unwrap()).unwrap();
    // The shard opens again at once, under a new epoch.
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    let made = writer.join().unwrap();
    assert!(made.is_ok(), "the close waits for the batch: {made:?}");
    let snapshot = latest.snapshot.expect("the close folds");
    let file = cache.0.join("close-race-snapshot");
    std::fs::write(
        &file,
        bucket
            .peek(&format!(
                "{root}{}",
                format::snapshot_key(snapshot.position)
            ))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        frasil_store::SqliteStore::read_file(&file, &journal(&a, 1)).unwrap(),
        Some(vec![2]),
        "the close's manifest names the acknowledged batch"
    );
    // A fold of the shard opened again deletes what no manifest names.
    shards.set_fold(1, 1);
    commit(&*shards, vec![(journal(&a, 2), vec![3])], Vec::new()).unwrap();
    shards.settle_folds();
    drop(shards);
    let other = Dir::new("close-race-other");
    let shards = node(&bucket, &other.0);
    assert_eq!(get(&*shards, &journal(&a, 1)), Some(vec![2]));
    assert_eq!(get(&*shards, &journal(&a, 2)), Some(vec![3]));
}

/// A batch the latest manifest names that is gone, as a writer that no
/// longer held the shard may delete: the shard opens from an earlier
/// manifest. With no manifest that opens, the open fails: it never opens
/// the shard empty.
#[test]
fn a_manifest_whose_batch_is_gone_is_passed_over() {
    let bucket = Arc::new(MemoryBucket::new());
    let a = space(1);
    let name = space_shard(a.as_bytes());
    let root = format!("{name}/");
    let first = Dir::new("gone-first");
    {
        let shards = node(&bucket, &first.0);
        commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
        shards.close_shard(&name).unwrap();
        // Opens again under a new epoch; the batch is in its tail.
        commit(&*shards, vec![(journal(&a, 1), vec![2])], Vec::new()).unwrap();
    }
    let second = Dir::new("gone-second");
    {
        // Records the tail as a run of its manifest.
        let shards = node(&bucket, &second.0);
        assert_eq!(get(&*shards, &journal(&a, 1)), Some(vec![2]));
    }
    let manifest =
        Manifest::decode(&bucket.peek(&latest_manifest(&bucket, &root)).unwrap()).unwrap();
    let run = *manifest.runs.last().expect("the tail, as a run");
    let delete = |key: String| {
        let bucket = bucket.clone();
        let io = BucketIo::new(bucket).unwrap();
        io.block({
            let bucket = io.bucket();
            async move { bucket.delete(&key).await }
        })
        .unwrap();
    };
    delete(format!("{root}{}", format::log_key((run.epoch, run.first))));
    let third = Dir::new("gone-third");
    {
        let shards = node(&bucket, &third.0);
        assert_eq!(
            get(&*shards, &journal(&a, 0)),
            Some(vec![1]),
            "opened from the manifest before"
        );
    }
    // Every snapshot gone too: nothing opens.
    for key in bucket.keys() {
        if key.starts_with(&format!("{root}snapshot-")) {
            delete(key);
        }
    }
    let fourth = Dir::new("gone-fourth");
    let shards = node(&bucket, &fourth.0);
    assert!(
        shard::ready(shards.get(&journal(&a, 0))).is_err(),
        "no manifest opens: the shard is not opened empty"
    );
}

/// Two starts of one single node under the same name, on one bucket: the
/// later one writes, and the earlier one writes nothing from its next
/// reading on. Its run object alone stops the earlier one, when a late
/// write leaves `nodes/active` naming the earlier one again.
#[test]
fn a_second_start_under_the_same_name_stops_the_first() {
    let bucket = Arc::new(MemoryBucket::new());
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let every = Duration::from_millis(10);
    let first = SingleNode::start_with(&io, "same", every).unwrap();
    first.refresh_now();
    assert!(first.may_write(first.epoch()));
    let second = SingleNode::start_with(&io, "same", every).unwrap();
    first.refresh_now();
    second.refresh_now();
    assert!(!first.may_write(first.epoch()), "the first stops");
    assert!(second.may_write(second.epoch()), "the second writes");
    // A third start, then a fourth, whose `nodes/active` the third's late
    // write replaces: only the run object names the fourth.
    let third = SingleNode::start_with(&io, "same", every).unwrap();
    let named_third = bucket.peek(fence::ACTIVE).unwrap();
    let _fourth = SingleNode::start_with(&io, "same", every).unwrap();
    io.block({
        let bucket = io.bucket();
        async move { bucket.put(fence::ACTIVE, named_third).await }
    })
    .unwrap();
    third.refresh_now();
    assert!(
        !third.may_write(third.epoch()),
        "the run object stops the third"
    );
}

/// The peer's writer over the shards, gathering each group for `window`.
fn writer(shards: &Arc<Shards>, window: Duration) -> crate::writer::Writer {
    let store: Arc<dyn Store> = shards.clone();
    let policy = crate::config::GroupCommit {
        window,
        commits: 16,
        bytes: 1 << 20,
    };
    crate::writer::Writer::spawn_with(store, policy, None).unwrap()
}

/// A writer's answer, waited for outside any runtime.
fn answer<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

/// The epoch of a shard's batch, from its key.
fn batch_epoch(key: &str) -> u64 {
    let position = &key[key.find("/log/").expect("a batch's key") + "/log/".len()..];
    position.split('-').next().unwrap().parse().unwrap()
}

/// A create, which expects the space not hosted, that the writer receives
/// with a commit to another shard whose batch fails: the create is made,
/// and its caller is told so. Tried again alone after the other commit's
/// failure, the create would have found its own record and been refused.
#[test]
fn a_create_made_beside_a_failed_commit_is_answered_as_made() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("create-beside");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let b = (2..=u8::MAX)
        .map(space)
        .find(|b| space_shard(b.as_bytes()) != space_shard(a.as_bytes()))
        .expect("a space of another shard");
    let hosted = Records::hosted_address(&a);
    let create = Commit::new(
        vec![
            (journal(&a, 0), vec![1]),
            (
                hosted.clone(),
                Records::hosted_record(&space_shard(a.as_bytes())),
            ),
        ],
        Vec::new(),
    )
    .expecting(&hosted, None);
    bucket.fail_puts(&format!("{}/log/", space_shard(b.as_bytes())), 1);
    let writer = writer(&shards, Duration::from_millis(200));
    let created = writer.submit(create);
    let other = writer.submit(Commit::new(vec![(journal(&b, 0), vec![2])], Vec::new()));
    assert!(answer(created).unwrap(), "the create was made");
    assert!(answer(other).is_err(), "the other commit fails alone");
    assert_eq!(get(&*shards, &journal(&a, 0)), Some(vec![1]));
    assert!(get(&*shards, &hosted).is_some());
    assert_eq!(get(&*shards, &journal(&b, 0)), None);
}

/// A group's batch PUT that times out, its answer lost, and that lands
/// only after the shard opened again under a later epoch: no commit is
/// acknowledged from it. The writer makes each commit again alone, under
/// the later epoch, and a node that opens the shard afterwards reads what
/// was acknowledged and nothing of the late batch.
#[test]
fn a_timed_out_put_at_an_old_epoch_is_never_acknowledged() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("timed-out");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let root = format!("{}/", space_shard(a.as_bytes()));
    commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
    let before: Vec<String> = bucket
        .keys()
        .into_iter()
        .filter(|key| key.starts_with(&format!("{root}log/")))
        .collect();
    bucket.hold_puts(&format!("{root}log/"), 1);
    let writer = writer(&shards, Duration::from_millis(100));
    let first = writer.submit(Commit::new(vec![(journal(&a, 1), vec![2])], Vec::new()));
    let second = writer.submit(Commit::new(vec![(journal(&a, 2), vec![3])], Vec::new()));
    assert!(answer(first).unwrap());
    assert!(answer(second).unwrap());
    // What acknowledged them: batches that landed, each under an epoch
    // above the timed-out one's, which is still on its way.
    let acknowledged: Vec<String> = bucket
        .keys()
        .into_iter()
        .filter(|key| key.starts_with(&format!("{root}log/")) && !before.contains(key))
        .collect();
    // A later commit changes what the late batch also writes.
    answer(writer.commit(vec![(journal(&a, 1), vec![9])], Vec::new())).unwrap();
    let late = bucket.release_held();
    assert_eq!(late.len(), 1, "{late:?}");
    let old = batch_epoch(&late[0]);
    assert!(!acknowledged.is_empty());
    for key in &acknowledged {
        assert!(batch_epoch(key) > old, "{key} is at or below {}", late[0]);
    }
    drop(writer);
    drop(shards);
    let other = Dir::new("timed-out-other");
    let shards = node(&bucket, &other.0);
    assert_eq!(get(&*shards, &journal(&a, 1)), Some(vec![9]), "never read");
    assert_eq!(get(&*shards, &journal(&a, 2)), Some(vec![3]));
}

/// The fence as a metered store sees it end to end: reads refused, then a
/// lapse in which nothing is written or read, then a reading that finds the
/// node still named, after which it writes as before, and all it
/// acknowledged is there for the next start.
#[test]
fn a_node_that_lapsed_writes_again_and_loses_nothing() {
    let cache = Dir::new("lapse");
    let bucket = Arc::new(MemoryBucket::new());
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let every = Duration::from_secs(10);
    let fence = Arc::new(SingleNode::start_with(&io, "test", every).unwrap());
    let held: Arc<dyn Fence> = fence.clone();
    let shards = Shards::bucket(io.clone(), &cache.0, held).unwrap();
    let a = space(1);
    let put = |i: u64| commit(&*shards, vec![(journal(&a, i), vec![1])], Vec::new());
    put(0).unwrap();

    bucket.refuse_reads(true);
    fence.refresh_now();
    put(1).unwrap();
    fence.unconfirmed_for(lapse_after(every));
    let before = bucket.requests();
    let refused = put(2).unwrap_err();
    assert!(refused.message().contains("no longer holds"), "{refused}");
    // The refused write broke its shard: while the node has lapsed, each
    // try to open it again spends nothing.
    for _ in 0..3 {
        assert!(put(2).is_err());
    }
    assert_eq!(bucket.requests(), before, "nothing sent while it lapsed");

    bucket.refuse_reads(false);
    fence.refresh_now();
    put(3).unwrap();
    put(4).unwrap();
    assert!(fence.may_write(fence.epoch()));
    shards.close_all().unwrap();
    drop(shards);

    let cache = Dir::new("lapse-next");
    let next = node(&bucket, &cache.0);
    for i in [0, 1, 3, 4] {
        assert!(get(&*next, &journal(&a, i)).is_some(), "batch {i}");
    }
    assert!(get(&*next, &journal(&a, 2)).is_none(), "refused, not made");
}

/// Waits for what maintenance started on the bucket's runtime.
fn settle() {
    std::thread::sleep(Duration::from_millis(20));
}

/// The minute's timeline reading is the only write of an idle node: it does
/// not send the node to its manifests, or a day of them would be 1,440
/// LISTs and as many GETs.
#[test]
fn an_idle_node_reads_nothing_for_its_timeline() {
    let cache = Dir::new("idle");
    let bucket = Arc::new(MemoryBucket::new());
    let clock = Arc::new(ManualClock::new(1000));
    let shards = node_with(&bucket, &cache.0, &clock);
    let keep = || {
        let reading = shards.node();
        commit(&*shards, vec![Records::reading_put(&reading)], Vec::new()).unwrap();
    };
    keep();
    let before = bucket.requests();
    for _ in 0..30 {
        clock.advance(60);
        keep();
        shards.maintain();
        settle();
    }
    let after = bucket.requests();
    assert_eq!(after.puts - before.puts, 30, "the readings are kept");
    assert_eq!((after.gets, after.lists), (before.gets, before.lists));
}

/// A shard that writes records checks its manifests, as often as the fence
/// reads and no more.
#[test]
fn a_writing_shard_checks_its_manifests_as_often_as_the_fence_reads() {
    let cache = Dir::new("check");
    let bucket = Arc::new(MemoryBucket::new());
    let clock = Arc::new(ManualClock::new(1000));
    let shards = node_with(&bucket, &cache.0, &clock);
    let a = space(1);
    commit(&*shards, vec![(journal(&a, 0), vec![1])], Vec::new()).unwrap();
    let every = shards.fence().unwrap().reading_secs();
    assert_eq!(every, fence::READING_EVERY.as_secs());
    let lists = bucket.requests().lists;
    clock.advance(every - 1);
    shards.maintain();
    settle();
    assert_eq!(bucket.requests().lists, lists, "not due");
    clock.advance(1);
    shards.maintain();
    settle();
    assert_eq!(bucket.requests().lists, lists + 1);
}

/// A hold a test sets on a node's next reading of the placements: the
/// reading waits there, after it read the index and before it takes
/// effect, until the test lets it go.
#[derive(Default)]
pub(super) struct Hold {
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

impl Hold {
    /// The reading's side: notes that it is here and waits for the test.
    pub(super) fn wait(&self) {
        let mut state = lock(&self.state);
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn reached(&self) {
        let mut state = lock(&self.state);
        while !state.0 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn release(&self) {
        lock(&self.state).1 = true;
        self.changed.notify_all();
    }
}

/// A move notes a space's new shard while the node reads the index's
/// placements again, as a node that takes shards up after a cluster heals
/// does: the reading found the shard the space left, and must not put it
/// back over the move's. Both readings: the whole index's, and one index
/// shard's as it opens again.
#[test]
fn a_placement_noted_while_the_index_is_read_again_stays() {
    let bucket = Arc::new(MemoryBucket::new());
    let cache = Dir::new("placement-race");
    let shards = node(&bucket, &cache.0);
    let a = space(1);
    let source = "spaces/00";
    let library = "libraries/6c6962";
    commit(
        &*shards,
        vec![(Records::hosted_address(&a), Records::hosted_record(source))],
        Vec::new(),
    )
    .unwrap();
    shards.reload_placements().unwrap();
    assert_eq!(
        shards.locate(a.as_bytes()).unwrap().as_deref(),
        Some(source)
    );

    for index_shard in [false, true] {
        let hold = Arc::new(Hold::default());
        *lock(&shards.placements_hold) = Some(hold.clone());
        let reading = {
            let shards = shards.clone();
            std::thread::spawn(move || {
                if index_shard {
                    let name = hashed(INDEX, a.as_bytes(), HASHED);
                    let shard = lock(&shards.open).get(&name).cloned().unwrap();
                    shards.reload_placement(&shard).unwrap();
                } else {
                    shards.reload_placements().unwrap();
                }
            })
        };
        // The reading has found the source's shard in the index; the move
        // ends now, at this node.
        hold.reached();
        shards.set_placement(a.as_bytes(), library);
        hold.release();
        reading.join().unwrap();
        assert_eq!(
            shards.locate(a.as_bytes()).unwrap().as_deref(),
            Some(library),
            "the move's placement stays (index shard: {index_shard})"
        );
        // Put the source back for the next round.
        shards.set_placement(a.as_bytes(), source);
    }
}
