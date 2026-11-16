//! Spaces in parallel, opened on first use and closed when idle, from their
//! snapshots; commits in groups, acknowledged only once durable. Two
//! histories of `peers.json` are the spaces: `credentials` and `skeleton`.

use crate::clock::{Clock, ManualClock};
use crate::config::Settings;
use crate::records::{Op, Records, Snapshot};
use crate::space::{Rules, Space};
use crate::spaces::blocking;
use crate::state::{Core, Grant, StoreAnswer, lock};
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_peers::entries::Rights;
use frasil_store::{BoxFuture, Commit, MemoryStore, Store, StoreError};
use serde_json::Value as Json;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A history's signed events, in order.
fn history(name: &str) -> Vec<Vec<u8>> {
    frasil_testkit::vectors::family::<Json>("peers.json", name)["events"]
        .as_array()
        .expect("an events list")
        .iter()
        .map(|row| frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap())
        .collect()
}

fn space_of(events: &[Vec<u8>]) -> EventId {
    frasil_events::decode(&events[0]).unwrap().log_id()
}

fn writer() -> Grant {
    Grant {
        rights: Rights::STORE_AND_RELEASE.union(Rights::ERASE),
        ..Grant::default()
    }
}

/// A grant that may store `signed`: an administrator's skeleton event
/// under its author's pseudonym.
fn grant_for(signed: &[u8]) -> Grant {
    let event = frasil_events::decode(signed).unwrap();
    let mut grant = writer();
    if event.kind() == frasil_events::kind::STORAGE {
        grant.pseudonym = Some(*event.author());
    }
    grant
}

/// A store whose commits a test can hold back or fail, and which counts
/// the commits of each group.
#[derive(Default)]
struct Gate {
    inner: MemoryStore,
    held: Mutex<bool>,
    opened: Condvar,
    fail: AtomicBool,
    groups: Mutex<Vec<usize>>,
}

impl Gate {
    fn hold(&self) {
        *lock(&self.held) = true;
    }

    fn release(&self) {
        *lock(&self.held) = false;
        self.opened.notify_all();
    }

    /// Blocks the writer while commits are held.
    fn wait(&self) {
        let mut held = lock(&self.held);
        while *held {
            held = self
                .opened
                .wait(held)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn groups(&self) -> Vec<usize> {
        lock(&self.groups).clone()
    }
}

impl Store for Gate {
    fn get<'a>(&'a self, address: &'a [u8]) -> BoxFuture<'a, Result<Option<Vec<u8>>, StoreError>> {
        self.inner.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> BoxFuture<'a, Result<frasil_store::store::Records, StoreError>> {
        self.inner.scan(prefix)
    }

    fn commit<'a>(&'a self, commit: &'a Commit) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            self.commit_all(std::slice::from_ref(commit))
                .await
                .map(|made| made[0])
        })
    }

    fn commit_all<'a>(
        &'a self,
        commits: &'a [Commit],
    ) -> BoxFuture<'a, Result<Vec<bool>, StoreError>> {
        lock(&self.groups).push(commits.len());
        self.wait();
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(StoreError::new("the disk failed")) });
        }
        self.inner.commit_all(commits)
    }
}

fn core_over(store: Arc<dyn Store>, clock: &Arc<ManualClock>) -> Arc<Core> {
    core_with(store, clock, crate::Extensions::NONE)
}

/// A core with `extensions` on. With ext-libraries, creates go to the
/// operator's open library.
fn core_with(
    store: Arc<dyn Store>,
    clock: &Arc<ManualClock>,
    extensions: crate::Extensions,
) -> Arc<Core> {
    let clock: Arc<dyn Clock> = clock.clone();
    let mut settings = Settings {
        extensions,
        ..Settings::open_core()
    };
    if extensions.libraries {
        settings.libraries.open_library =
            frasil_libraries::LibraryId::new(crate::testing::OPEN_LIBRARY).ok();
    }
    Arc::new(Core::open(settings, Records::new(store), clock).unwrap())
}

/// ext-libraries on.
const LIBRARIES: crate::Extensions = crate::Extensions {
    libraries: true,
    ..crate::Extensions::NONE
};

fn now(clock: &ManualClock) -> Reading {
    clock.now()
}

/// Stores events in order; returns those acknowledged.
async fn store_all(
    core: &Core,
    link: u64,
    events: &[Vec<u8>],
    clock: &ManualClock,
) -> Vec<EventId> {
    let space = space_of(events);
    let mut acked = Vec::new();
    for signed in events {
        let mut grant = grant_for(signed);
        if let StoreAnswer::Acknowledge(id) = core
            .store(link, &mut grant, space, signed, now(clock))
            .await
        {
            acked.push(id);
        }
    }
    acked
}

fn link(core: &Core) -> u64 {
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    std::mem::forget(rx);
    core.link(tx)
}

/// A space as it is in memory, without the judgements of its requests:
/// the peer keeps those in memory only and makes them again at each sweep,
/// and answers `Execute` for a request carried out from its record.
fn debug(core: &Core, space: EventId) -> String {
    core.read_blocking(space, |held| {
        let mut held = held.clone();
        held.outcomes.clear();
        format!("{held:?}")
    })
    .expect("an open space")
}

/// A space as it is in memory.
fn debug_all(core: &Core, space: EventId) -> String {
    core.read_blocking(space, |held| format!("{held:?}"))
        .expect("an open space")
}

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("within ten seconds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_proceed_while_another_is_held() {
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_over(Arc::new(MemoryStore::new()), &clock);
    let (a, b) = (history("credentials"), history("skeleton"));
    assert_ne!(space_of(&a), space_of(&b));
    let link = link(&core);
    store_all(&core, link, &a[..1], &clock).await;
    store_all(&core, link, &b[..1], &clock).await;

    // A writer holds space A, as one waiting for its commit would.
    let held = core.write(space_of(&a)).await.unwrap();
    // Space B stores, and space A still reads.
    let acked = within(store_all(&core, link, &b[1..3], &clock)).await;
    assert!(!acked.is_empty(), "B stores while A is held");
    let read = within(core.read(space_of(&a), |space| space.log.len())).await;
    assert_eq!(read, Some(1));
    // A's next writer waits for the first.
    let waiting = {
        let core = core.clone();
        let clock = clock.clone();
        let event = a[1].clone();
        let space = space_of(&a);
        tokio::spawn(async move {
            let mut grant = grant_for(&event);
            core.store(link, &mut grant, space, &event, now(&clock))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "A's writers take turns");
    drop(held);
    let answer = within(waiting).await.unwrap();
    assert!(matches!(answer, StoreAnswer::Acknowledge(_)), "{answer:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_acknowledged_before_its_group_is_durable() {
    let clock = Arc::new(ManualClock::new(1000));
    let gate = Arc::new(Gate::default());
    let core = core_over(gate.clone(), &clock);
    let (a, b) = (history("credentials"), history("skeleton"));
    let link = link(&core);
    store_all(&core, link, &a[..1], &clock).await;
    store_all(&core, link, &b[..1], &clock).await;

    // A commit held back: no answer, and nothing applied, until it is
    // durable.
    gate.hold();
    let store = |events: Vec<Vec<u8>>| {
        let core = core.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            let mut grant = grant_for(&events[1]);
            let space = space_of(&events);
            core.store(link, &mut grant, space, &events[1], now(&clock))
                .await
        })
    };
    let first = store(a.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Two more writers, of another space, wait behind it and share a group.
    let second = store(b.clone());
    let third = {
        let core = core.clone();
        let clock = clock.clone();
        let event = b[2].clone();
        let space = space_of(&b);
        tokio::spawn(async move {
            // After B's first writer, in the same space.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut grant = grant_for(&event);
            core.store(link, &mut grant, space, &event, now(&clock))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!first.is_finished() && !second.is_finished());
    let a1 = frasil_events::decode(&a[1]).unwrap().id();
    assert_eq!(
        core.read(space_of(&a), |space| space.log.contains(a1))
            .await,
        Some(false),
        "nothing is applied before it is durable"
    );
    let before = gate.groups().len();
    gate.release();
    assert!(matches!(
        within(first).await.unwrap(),
        StoreAnswer::Acknowledge(_)
    ));
    assert!(matches!(
        within(second).await.unwrap(),
        StoreAnswer::Acknowledge(_)
    ));
    let _ = within(third).await.unwrap();
    assert_eq!(
        core.read(space_of(&a), |space| space.log.contains(a1))
            .await,
        Some(true)
    );
    // B's writer committed in a group after the held one.
    assert!(gate.groups().len() > before);

    // A failed commit acknowledges nothing and changes nothing.
    gate.fail.store(true, Ordering::SeqCst);
    let a2 = frasil_events::decode(&a[2]).unwrap().id();
    let mut grant = writer();
    let answer = core
        .store(link, &mut grant, space_of(&a), &a[2], now(&clock))
        .await;
    assert_eq!(answer, StoreAnswer::Refused("busy".into()));
    // The space opens again from its records once the store answers.
    gate.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        core.read(space_of(&a), |space| space.log.contains(a2))
            .await,
        Some(false)
    );
    let answer = core
        .store(link, &mut grant, space_of(&a), &a[2], now(&clock))
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(a2));
}

#[tokio::test]
async fn writers_at_once_share_one_group() {
    let clock = Arc::new(ManualClock::new(1000));
    let gate = Arc::new(Gate::default());
    let core = core_over(gate.clone(), &clock);
    let (a, b) = (history("credentials"), history("skeleton"));
    let link = link(&core);
    // A create is a group of its own: it has expectations.
    store_all(&core, link, &a[..1], &clock).await;
    store_all(&core, link, &b[..1], &clock).await;
    // The writer is held on a commit; two stores queue behind it.
    let start = gate.groups().len();
    gate.hold();
    let blocker = core
        .writer
        .submit(Commit::new(vec![(vec![0xfe], vec![1])], Vec::new()));
    let blocker = tokio::spawn(blocker);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stores = [a, b].map(|events| {
        let core = core.clone();
        let clock = clock.clone();
        tokio::spawn(async move { store_all(&core, link, &events[1..2], &clock).await })
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    gate.release();
    within(blocker).await.unwrap().unwrap();
    for store in stores {
        assert_eq!(within(store).await.unwrap().len(), 1);
    }
    assert!(
        gate.groups()[start..].starts_with(&[1, 2]),
        "the two stores share a group: {:?}",
        gate.groups()
    );
}

#[tokio::test]
async fn a_restart_opens_no_space_until_one_is_used() {
    let clock = Arc::new(ManualClock::new(1000));
    let (a, b) = (history("credentials"), history("skeleton"));
    let replays = |core: &Core| core.replays.load(Ordering::Relaxed);
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    {
        let core = core_over(store.clone(), &clock);
        let link = link(&core);
        store_all(&core, link, &a, &clock).await;
        store_all(&core, link, &b[..1], &clock).await;
        // A clean shutdown closes what may close.
        assert_eq!(core.close_idle(true).await, 2);
        assert_eq!(core.open_spaces(), 0);
    }
    let core = core_over(store.clone(), &clock);
    assert_eq!(replays(&core), 0);
    assert!(core.hosts(&space_of(&a)) && core.hosts(&space_of(&b)));
    core.sweep(now(&clock)).await;
    assert_eq!(replays(&core), 0, "nothing to sweep");
    assert!(core.read(space_of(&a), |_| ()).await.is_some());
    assert_eq!(replays(&core), 1);
    assert_eq!(core.open_spaces(), 1);
    drop(core);

    // Without a clean shutdown a start opens no space either; its first
    // sweep opens those written since they last opened, once.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    {
        let core = core_over(store.clone(), &clock);
        let link = link(&core);
        store_all(&core, link, &a, &clock).await;
        store_all(&core, link, &b[..1], &clock).await;
    }
    let core = core_over(store.clone(), &clock);
    assert_eq!(replays(&core), 0);
    core.sweep(now(&clock)).await;
    assert_eq!(replays(&core), 2);
    core.sweep(now(&clock)).await;
    assert_eq!(replays(&core), 2);
    assert_eq!(core.close_idle(true).await, 2);
    drop(core);
    let core = core_over(store, &clock);
    core.sweep(now(&clock)).await;
    assert_eq!(replays(&core), 0);
}

/// Live delivery: an event pending at the peer that another connection's
/// store releases reaches every subscriber, that connection too, since it
/// never sent it.
#[tokio::test]
async fn a_released_event_reaches_the_connection_that_released_it() {
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_over(Arc::new(MemoryStore::new()), &clock);
    let a = history("credentials");
    let space = space_of(&a);
    let founder = link(&core);
    store_all(&core, founder, &a[..1], &clock).await;
    let mut queues = Vec::new();
    let mut links = Vec::new();
    for _ in 0..2 {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let number = core.link(tx);
        core.subscribe(number, space, None);
        links.push(number);
        queues.push(rx);
    }
    // The first connection's event waits for its parent, which the second
    // stores.
    let mut grant = grant_for(&a[2]);
    let held = core
        .store(links[0], &mut grant, space, &a[2], now(&clock))
        .await;
    assert_eq!(held, StoreAnswer::Held(None));
    let mut grant = grant_for(&a[1]);
    let stored = core
        .store(links[1], &mut grant, space, &a[1], now(&clock))
        .await;
    assert!(matches!(stored, StoreAnswer::Acknowledge(_)), "{stored:?}");
    let carries = |queue: &mut tokio::sync::mpsc::Receiver<crate::state::Outgoing>,
                   signed: &[u8]| {
        let mut found = false;
        while let Ok(outgoing) = queue.try_recv() {
            if let crate::state::Outgoing::Sync(_, bytes) = outgoing {
                found |= bytes.windows(signed.len()).any(|window| window == signed);
            }
        }
        found
    };
    assert!(carries(&mut queues[1], &a[2]), "the released event");
    assert!(carries(&mut queues[0], &a[1]), "the other's event");
}

/// A space closed and opened again, from a snapshot and the journal after
/// it, is the space never closed.
#[tokio::test]
async fn closing_and_reopening_changes_nothing() {
    let clock = Arc::new(ManualClock::new(1000));
    let (closed, kept) = (
        core_over(Arc::new(MemoryStore::new()), &clock),
        core_over(Arc::new(MemoryStore::new()), &clock),
    );
    let a = history("credentials");
    let space = space_of(&a);
    let (l1, l2) = (link(&closed), link(&kept));
    let half = a.len() / 2;
    assert_eq!(
        store_all(&closed, l1, &a[..half], &clock).await,
        store_all(&kept, l2, &a[..half], &clock).await
    );
    // A snapshot of the first half, then a close.
    {
        let writing = closed.write(space).await.unwrap();
        closed
            .fold(&writing, BTreeSet::new(), Vec::new(), Vec::new())
            .await
            .unwrap();
    }
    assert_eq!(closed.close_idle(true).await, 1);
    assert_eq!(debug(&closed, space), debug(&kept, space));
    // The rest, then a close without a new snapshot: the snapshot and the
    // journal after it.
    assert_eq!(
        store_all(&closed, l1, &a[half..], &clock).await,
        store_all(&kept, l2, &a[half..], &clock).await
    );
    assert_eq!(closed.close_idle(true).await, 1);
    let before = closed.replays.load(Ordering::Relaxed);
    assert_eq!(debug(&closed, space), debug(&kept, space));
    assert_eq!(closed.replays.load(Ordering::Relaxed), before + 1);
    assert!(closed.through_of(space) > 0);

    // A space with requests waiting never closes on its own; taken out of
    // memory all the same, it opens to the space it was.
    let b = history("skeleton");
    let space = space_of(&b);
    assert_eq!(
        store_all(&closed, l1, &b, &clock).await,
        store_all(&kept, l2, &b, &clock).await
    );
    closed.close_idle(true).await;
    assert_eq!(
        closed.open_spaces(),
        1,
        "a space with requests waiting stays open"
    );
    closed.unload(space).await;
    assert_eq!(debug(&closed, space), debug(&kept, space));
    // The next sweep judges its requests as the peer that kept it did.
    closed.sweep(now(&clock)).await;
    kept.sweep(now(&clock)).await;
    assert_eq!(debug_all(&closed, space), debug_all(&kept, space));
}

/// A history's journal: each event at an even index, with a sight, and a
/// registration last.
fn journal_of(name: &str) -> Vec<(u64, Op)> {
    history(name)
        .into_iter()
        .enumerate()
        .map(|(index, signed)| {
            (
                index as u64 * 2,
                Op::Event {
                    signed,
                    sight: Reading {
                        timeline: 1000 + index as u64,
                        wall: None,
                        run: 1,
                    },
                    entry: (index % 2 == 1).then_some([index as u8; 32]),
                },
            )
        })
        .chain([(99, Op::Register { key: [9; 32] })])
        .collect()
}

/// Opening from a snapshot of any prefix of a journal, and the records
/// after it, is the whole journal replayed; a journal record the snapshot
/// already holds is left out; and the snapshot decodes no event.
#[test]
fn a_snapshot_and_its_tail_open_to_the_whole_journal() {
    let cap = Rules::of(&Settings::open_core());
    for name in ["skeleton", "credentials"] {
        let ops = journal_of(name);
        let whole = Space::replay(ops.clone(), Vec::new(), cap).expect("a genesis");
        let whole = format!("{whole:?}");
        for split in 1..=ops.len() {
            let prefix = Space::replay(ops[..split].to_vec(), Vec::new(), cap).unwrap();
            let mut snapshot = prefix.to_snapshot();
            snapshot.through = ops.get(split).map_or(100, |(index, _)| *index);
            let read = Snapshot::decode(&snapshot.encode()).expect("it reads back");
            assert_eq!(read, snapshot);
            let records = Records::new(Arc::new(MemoryStore::new()));
            let space = EventId([1; 32]);
            let mut puts = Records::snapshot_puts(&space, &read);
            for (index, op) in &ops[split..] {
                puts.push((Records::journal_address(&space, *index), op.encode()));
            }
            // A record a fold already holds, left behind: never replayed
            // twice.
            let (index, op) = &ops[split - 1];
            puts.push((Records::journal_address(&space, *index), op.encode()));
            records.commit(puts, Vec::new()).unwrap();
            let opened = records.opened(&space).unwrap();
            let decoded = crate::space::decoded();
            let mut reopened =
                Space::from_snapshot(opened.snapshot.as_ref().unwrap(), Vec::new(), cap)
                    .expect("its state reads");
            assert_eq!(crate::space::decoded(), decoded, "no event decoded");
            let tail = opened
                .tail
                .iter()
                .map(|(index, op, _)| (*index, op.clone()))
                .collect();
            reopened.apply_tail(tail);
            assert_eq!(format!("{reopened:?}"), whole, "{name}, {split}");
        }
    }
}

/// A space's journal, read from its state, replays to the space.
#[test]
fn a_spaces_journal_reads_back_from_its_state() {
    let cap = Rules::of(&Settings::open_core());
    for name in ["skeleton", "credentials"] {
        let space = Space::replay(journal_of(name), Vec::new(), cap).unwrap();
        let again = Space::replay_decoded(space.journal(), Vec::new(), cap).unwrap();
        assert_eq!(format!("{again:?}"), format!("{space:?}"));
        // Under another cap, a snapshot opens by replaying that journal.
        let other = Space::from_snapshot(
            &space.to_snapshot(),
            Vec::new(),
            Rules {
                cap: cap.cap / 2,
                ..cap
            },
        )
        .unwrap();
        assert_eq!(other.entries.cap(), cap.cap / 2);
        assert_eq!(other.log.canonical(), space.log.canonical());
    }
}

#[test]
fn snapshots_read_only_in_their_one_encoding() {
    let cap = Rules::of(&Settings::open_core());
    let space = Space::replay(journal_of("skeleton"), Vec::new(), cap).unwrap();
    let snapshot = space.to_snapshot();
    let bytes = snapshot.encode();
    assert_eq!(Snapshot::decode(&bytes), Some(snapshot.clone()));
    // Trailing bytes, another version, a record at or past `through`, and
    // lists out of order are refused.
    assert_eq!(Snapshot::decode(&[bytes.as_slice(), &[0]].concat()), None);
    let mut other = bytes.clone();
    other[1] = 4;
    assert_eq!(Snapshot::decode(&other), None);
    let past = Snapshot {
        through: 99,
        ..snapshot.clone()
    };
    assert_eq!(Snapshot::decode(&past.encode()), None);
    let mut unordered = snapshot.clone();
    unordered.held.reverse();
    assert_eq!(Snapshot::decode(&unordered.encode()), None);
    // Every byte changed, or the snapshot cut there: no panic, and what
    // reads is the one encoding of what it returns.
    for at in (0..bytes.len()).step_by(29) {
        for value in [0u8, 0xff, bytes[at] ^ 1] {
            let mut changed = bytes.clone();
            changed[at] = value;
            for cut in [&changed[..], &changed[..at]] {
                if let Some(read) = Snapshot::decode(cut) {
                    // A version-2 snapshot reads, and is written again as
                    // this version.
                    if u64::from(cut[1]) == Snapshot::VERSION {
                        assert_eq!(read.encode(), cut);
                    }
                    let _ = Space::from_snapshot(&read, Vec::new(), cap);
                }
            }
        }
    }
    // A large snapshot is kept in parts, which read back as one.
    let records = Records::new(Arc::new(MemoryStore::new()));
    let id = EventId([3; 32]);
    let big = Snapshot {
        log: vec![7; crate::records::SNAPSHOT_PART + 10],
        ..snapshot
    };
    let puts = Records::snapshot_puts(&id, &big);
    assert_eq!(puts.len(), 2);
    records.commit(puts, Vec::new()).unwrap();
    assert_eq!(records.opened(&id).unwrap().snapshot, Some(big));
    // A part missing is an error, not a shorter snapshot.
    records
        .commit(Vec::new(), vec![Records::snapshot_address(&id, 0)])
        .unwrap();
    assert!(records.opened(&id).is_err());
}

/// Commits per second with 1 and with 100 spaces at once, on SQLite in a
/// file: `cargo test -p frasil-relay --release -- --ignored --nocapture
/// commits_per_second`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement"]
async fn commits_per_second() {
    let dir = std::env::temp_dir().join(format!("frasil-relay-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for writers in [1usize, 100] {
        let path = dir.join(format!("bench-{writers}.sqlite"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        let store: Arc<dyn Store> = Arc::new(frasil_store::SqliteStore::open(&path).unwrap());
        let clock = Arc::new(ManualClock::new(1000));
        let core = core_over(store, &clock);
        let per = 2000 / writers;
        let started = std::time::Instant::now();
        let tasks: Vec<_> = (0..writers)
            .map(|n| {
                let core = core.clone();
                tokio::spawn(async move {
                    for i in 0..per {
                        let mut address = vec![b'z'];
                        address.extend_from_slice(&(n as u64).to_be_bytes());
                        address.extend_from_slice(&(i as u64).to_be_bytes());
                        core.writer
                            .commit(vec![(address, vec![0; 200])], Vec::new())
                            .await
                            .unwrap();
                    }
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        let elapsed = started.elapsed();
        println!(
            "{writers} writers: {} commits in {elapsed:?}, {:.0} commits/s",
            per * writers,
            (per * writers) as f64 / elapsed.as_secs_f64()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store and a present that wait for a space's gate while a sweep
/// erases the space see the erasure when they get it: the genesis sent
/// again, by a connection the store right lets past the check made before
/// the gate, is refused `erased`, and the space is not hosted again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_waiting_through_an_erasure_see_it() {
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_over(Arc::new(MemoryStore::new()), &clock);
    let a = history("credentials");
    let space = space_of(&a);
    let link = link(&core);
    store_all(&core, link, &a[..1], &clock).await;
    let held = core.write(space).await.unwrap();
    let store = {
        let core = core.clone();
        let clock = clock.clone();
        let genesis = a[0].clone();
        tokio::spawn(async move {
            let mut grant = Grant::default();
            grant.rights.store = true;
            core.store(link, &mut grant, space, &genesis, now(&clock))
                .await
        })
    };
    let present = {
        let core = core.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            let on = crate::state::On {
                link,
                binding: [0; 32],
                purpose: frasil_peers::proof::Purpose::SpaceTraffic,
                now: now(&clock),
            };
            let present = frasil_transport::messages::Present {
                request: 1,
                space: *space.as_bytes(),
                credential: 2,
                public: vec![1; 32],
                proof: vec![0; 64],
            };
            let mut grants = std::collections::BTreeMap::new();
            core.present(&on, &mut grants, &present, None).await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let erasure = crate::space::Removal {
        erase_space: Some(vec![9; 8]),
        ..crate::space::Removal::default()
    };
    core.remove(&held, erasure).await.unwrap();
    drop(held);
    assert_eq!(
        within(store).await.unwrap(),
        StoreAnswer::Refused("erased".into())
    );
    assert_eq!(
        within(present).await.unwrap(),
        crate::state::refused(1, "erased")
    );
    assert!(!core.hosts(&space) && core.tombstoned(&space));
}

/// A store dropped while its commit is in flight, its caller gone, leaves
/// memory as the records are: the space opens again once the commit is
/// made, and the next store takes the next journal record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_dropped_mid_commit_leaves_memory_as_at_rest() {
    let clock = Arc::new(ManualClock::new(1000));
    let gate = Arc::new(Gate::default());
    let core = core_over(gate.clone(), &clock);
    let a = history("credentials");
    let space = space_of(&a);
    let link = link(&core);
    store_all(&core, link, &a[..1], &clock).await;
    gate.hold();
    let dropped = {
        let core = core.clone();
        let clock = clock.clone();
        let event = a[1].clone();
        tokio::spawn(async move {
            let mut grant = grant_for(&event);
            core.store(link, &mut grant, space, &event, now(&clock))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    dropped.abort();
    assert!(dropped.await.is_err(), "the store was dropped");
    gate.release();
    let first = frasil_events::decode(&a[1]).unwrap().id();
    assert_eq!(
        within(core.read(space, |held| held.log.contains(first))).await,
        Some(true),
        "the commit was made, and memory has it"
    );
    let acked = within(store_all(&core, link, &a[2..4], &clock)).await;
    assert_eq!(acked.len(), 2);
    let fresh = core_over(gate, &clock);
    assert_eq!(debug(&fresh, space), debug(&core, space));
}

/// ext-libraries.md, 3.4 Storing: two spaces of one library at its quota's
/// edge, storing at once, each with room alone: one is stored, and the
/// other refused, since the first's bytes count while it commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_of_a_library_at_its_quota_share_it() {
    let clock = Arc::new(ManualClock::new(1000));
    let gate = Arc::new(Gate::default());
    let core = core_with(gate.clone(), &clock, LIBRARIES);
    let (a, b) = (history("credentials"), history("skeleton"));
    let link = link(&core);
    store_all(&core, link, &a[..1], &clock).await;
    store_all(&core, link, &b[..1], &clock).await;
    let used = |events: &[Vec<u8>]| core.read_blocking(space_of(events), Space::used).unwrap();
    let quota = used(&a) + used(&b) + a[1].len().max(b[1].len()) as u64;
    {
        let library = frasil_libraries::LibraryId::new(crate::testing::OPEN_LIBRARY).unwrap();
        lock(&core.libraries)
            .update(
                &library,
                crate::libraries::LibraryUpdate {
                    quota: Some(Some(quota)),
                    ..crate::libraries::LibraryUpdate::default()
                },
            )
            .unwrap();
    }
    gate.hold();
    let store = |events: Vec<Vec<u8>>| {
        let core = core.clone();
        let clock = clock.clone();
        tokio::spawn(async move {
            let mut grant = grant_for(&events[1]);
            let space = space_of(&events);
            core.store(link, &mut grant, space, &events[1], now(&clock))
                .await
        })
    };
    let first = store(a.clone());
    // The first holds its bytes before the second asks: it waits at the
    // gate with them reserved, however slowly it got there.
    within(async {
        while lock(&core.index).reserved.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let second = store(b.clone());
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.release();
    let answers = [within(first).await.unwrap(), within(second).await.unwrap()];
    assert!(
        matches!(answers[0], StoreAnswer::Acknowledge(_)),
        "{answers:?}"
    );
    assert_eq!(answers[1], StoreAnswer::Refused("quota_exceeded".into()));
    // Once both are answered, no bytes are held.
    assert_eq!(lock(&core.index).reserved.len(), 0);
}

/// A node of the peer over shards in a bucket, its working copies in a
/// directory of their own.
fn sharded(
    bucket: &Arc<crate::shards::bucket::MemoryBucket>,
    clock: &Arc<ManualClock>,
) -> (Arc<crate::shards::Shards>, Arc<Core>, std::path::PathBuf) {
    use crate::shards::bucket::{Bucket, BucketIo};
    let random = crate::util::hex(&*frasil_crypto::random_bytes::<8>().unwrap());
    let cache = std::env::temp_dir().join(format!("frasil-spaces-shards-{random}"));
    let shared: Arc<dyn Bucket> = bucket.clone();
    let io = Arc::new(BucketIo::new(shared).unwrap());
    let fence = crate::shards::fence::SingleNode::start(&io, "node").unwrap();
    let shards = crate::shards::Shards::bucket(io, &cache, Arc::new(fence)).unwrap();
    let node_clock: Arc<dyn Clock> = clock.clone();
    shards.set_clock(node_clock.clone());
    let settings = Settings::open_core();
    let store: Arc<dyn Store> = shards.clone();
    let core = Core::open_with(
        settings,
        Records::new(store),
        node_clock,
        Some(shards.clone()),
    )
    .unwrap();
    (shards, Arc::new(core), cache)
}

/// Spaces kept in shards in a bucket: a node that stops cleanly, and
/// another that takes the bucket up on another machine with nothing in its
/// cache, serve the same spaces, and the second stores on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spaces_in_a_bucket_open_on_another_machine() {
    let bucket = Arc::new(crate::shards::bucket::MemoryBucket::new());
    let clock = Arc::new(ManualClock::new(1000));
    let (a, b) = (history("credentials"), history("skeleton"));
    // What a peer over memory acknowledges.
    let reference = core_over(Arc::new(MemoryStore::new()), &clock);
    let link_r = link(&reference);
    let expected = store_all(&reference, link_r, &a[..a.len() - 1], &clock).await;
    let (shards, core, first) = sharded(&bucket, &clock);
    let link_a = link(&core);
    let acked = store_all(&core, link_a, &a[..a.len() - 1], &clock).await;
    assert_eq!(acked, expected);
    store_all(&core, link_a, &b, &clock).await;
    let (space_a, space_b) = (space_of(&a), space_of(&b));
    let (before_a, before_b) = (debug(&core, space_a), debug(&core, space_b));
    core.close_idle(true).await;
    core.writer.barrier().await.unwrap();
    let closing = shards.clone();
    blocking(move || closing.close_all()).await.unwrap();
    drop(core);
    drop(shards);

    let (shards, core, second) = sharded(&bucket, &clock);
    assert!(core.hosts(&space_a) && core.hosts(&space_b));
    assert_eq!(debug(&core, space_a), before_a);
    assert_eq!(debug(&core, space_b), before_b);
    let last = store_all(&core, link(&core), &a[a.len() - 1..], &clock).await;
    let expected = store_all(&reference, link_r, &a[a.len() - 1..], &clock).await;
    assert_eq!(last, expected);
    // The node stops without closing anything; a third takes the bucket up.
    let after_a = debug(&core, space_a);
    drop(core);
    drop(shards);
    let (_shards, core, third) = sharded(&bucket, &clock);
    assert_eq!(debug(&core, space_a), after_a);
    for dir in [first, second, third] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A closed space's usage, which its library's ledger reads without
/// opening it (ext-libraries.md, 2.5 What a peer keeps).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ledger_reads_closed_spaces_without_opening_them() {
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_with(Arc::new(MemoryStore::new()), &clock, LIBRARIES);
    let (a, b) = (history("credentials"), history("skeleton"));
    let link = link(&core);
    store_all(&core, link, &a, &clock).await;
    store_all(&core, link, &b[..1], &clock).await;
    let library = frasil_libraries::LibraryId::new(crate::testing::OPEN_LIBRARY).unwrap();
    let open = core.ledger(&library).await.expect("the open library");
    assert_eq!(open.spaces.len(), 2);
    assert_eq!(core.close_idle(true).await, 2);
    let replays = core.replays.load(Ordering::Relaxed);
    let closed = core.ledger(&library).await.unwrap();
    assert_eq!(closed, open);
    assert_eq!(core.ledger_blocking(&library), Some(open.clone()));
    assert_eq!(
        core.replays.load(Ordering::Relaxed),
        replays,
        "no space opened"
    );
    // A space that changes reads open again, then from its record once it
    // closes.
    let space = space_of(&b);
    store_all(&core, link, &b[1..2], &clock).await;
    let changed = core.ledger(&library).await.unwrap();
    assert_ne!(changed, open);
    assert_eq!(core.close_idle(true).await, 1);
    assert_eq!(core.ledger(&library).await.unwrap(), changed);
    assert!(!core.hosts(&space) || core.peek(&space, |_| ()).is_none());
}

/// A create reads its genesis's sight on the timeline of the shard that
/// keeps the space from then on (overview.md, 6.7), such as its library's,
/// and opens no other shard for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_reads_the_timeline_of_the_shard_it_goes_to() {
    let bucket = Arc::new(crate::shards::bucket::MemoryBucket::new());
    let clock = Arc::new(ManualClock::new(1000));
    let (shards, core, cache) = sharded(&bucket, &clock);
    let library = "libraries/6c6962";
    // The library's shard opens first, its timeline at 0.
    {
        let opened = shards.clone();
        let now = clock.now();
        let reading = blocking(move || opened.reading_of(library, now))
            .await
            .unwrap();
        assert_eq!(reading.timeline, 0);
    }
    clock.advance(50);
    let a = history("credentials");
    let space = space_of(&a);
    let genesis = frasil_events::decode(&a[0]).unwrap();
    let writing = core.write(space).await.unwrap();
    let answer = core
        .create(
            &writing,
            genesis,
            &a[0],
            now(&clock),
            library.to_owned(),
            false,
        )
        .await;
    assert!(matches!(answer, StoreAnswer::Acknowledge(_)), "{answer:?}");
    drop(writing);
    let sight = core
        .read(space, |held| held.sights[&space].timeline)
        .await
        .unwrap();
    // On the library's timeline, not the node's, nor a new shard's.
    assert_eq!(sight, 50);
    assert!(
        !shards
            .open_names()
            .contains(&crate::shards::space_shard(space.as_bytes())),
        "the shard of spaces of no library is not opened"
    );
    let _ = std::fs::remove_dir_all(cache);
}

/// peers.md, "What a peer checks before it stores a skeleton event", step
/// 2: a root whose founder keys do not hash to the genesis's `kc` is
/// refused `NotCommitted` and not stored (`twin_checks`).
#[tokio::test]
async fn a_root_whose_founder_keys_miss_the_genesis_kc_is_refused() {
    let case = frasil_testkit::vectors::family::<Json>("peers.json", "twin_checks")
        ["root_founder_keys_not_committed"]
        .clone();
    assert_eq!(case["peer"], "NotCommitted");
    let events: Vec<Vec<u8>> = case["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap())
        .collect();
    let root = frasil_testkit::hex::decode(case["root"].as_str().unwrap()).unwrap();
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_over(Arc::new(MemoryStore::new()), &clock);
    let link = link(&core);
    let space = space_of(&events);
    assert_eq!(store_all(&core, link, &events[..1], &clock).await.len(), 1);
    let mut grant = grant_for(&root);
    let answer = core
        .store(link, &mut grant, space, &root, now(&clock))
        .await;
    assert_eq!(answer, StoreAnswer::Refused("not_committed".into()));
    let root_id = frasil_events::decode(&root).unwrap().id();
    assert!(
        core.read_blocking(space, |held| !held.log.contains(root_id))
            .unwrap()
    );
}

/// Credential 3 names a pseudonym by device ID (peers.md, 3.7 Presenting
/// a credential): a known pseudonym's proof verifies under its root's or
/// enrolment's `ed`, and one the peer does not know yet is granted until
/// its enrolment arrives, whose `ed` the proof must verify under.
#[tokio::test]
async fn a_pseudonym_presents_by_device_id() {
    let proofs = frasil_testkit::vectors::family::<Json>("peers.json", "proofs");
    let hex = |value: &Json| frasil_testkit::hex::decode(value.as_str().unwrap()).unwrap();
    let case = proofs["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["credential"] == 3 && case["purpose"] == "administration")
        .unwrap()
        .clone();
    let binding: [u8; 32] = hex(&proofs["binding_administration"]).try_into().unwrap();
    let clock = Arc::new(ManualClock::new(1000));
    let core = core_over(Arc::new(MemoryStore::new()), &clock);
    let a = history("skeleton");
    let space = space_of(&a);
    let writers = link(&core);
    store_all(&core, writers, &a[..4], &clock).await;
    let present = |public: Vec<u8>, proof: Vec<u8>| {
        let core = core.clone();
        let clock = clock.clone();
        async move {
            let on = crate::state::On {
                link: link(&core),
                binding,
                purpose: frasil_peers::proof::Purpose::Administration,
                now: now(&clock),
            };
            let present = frasil_transport::messages::Present {
                request: 1,
                space: *space.as_bytes(),
                credential: 3,
                public,
                proof,
            };
            let mut grants = std::collections::BTreeMap::new();
            let answer = core.present(&on, &mut grants, &present, None).await;
            (answer, grants.remove(&space), on.link)
        }
    };
    let granted = crate::state::Outgoing::Control(
        frasil_transport::messages::Granted {
            request: 1,
            rights: frasil_transport::codes::Right::of(Rights::ERASE),
            transfer_token: None,
        }
        .encode(),
    );
    // The root's pseudonym, under the root's `ed`.
    let (answer, grant, _) = present(hex(&case["public"]), hex(&case["proof"])).await;
    assert_eq!(answer, granted);
    assert!(grant.unwrap().provisional.is_none());
    // A pseudonym not enrolled yet: granted, its proof checked at its
    // enrolment, which a proof by another key does not pass.
    let enrolment = frasil_events::decode(&a[4]).unwrap();
    let pseudonym = enrolment.author().0.to_vec();
    let (answer, grant, admin) = present(pseudonym.clone(), hex(&case["proof"])).await;
    assert_eq!(answer, granted);
    let mut grant = grant.unwrap();
    assert!(grant.provisional.is_some());
    let stored = core
        .store(admin, &mut grant, space, &a[4], now(&clock))
        .await;
    assert_eq!(stored, StoreAnswer::Refused("not_authorized".into()));
    // Enrolled, its proof verifies under the enrolment's `ed` at once.
    let mut writer = writer();
    let stored = core
        .store(writers, &mut writer, space, &a[4], now(&clock))
        .await;
    assert!(matches!(stored, StoreAnswer::Acknowledge(_)), "{stored:?}");
    let (answer, _, _) = present(pseudonym, hex(&case["proof"])).await;
    assert_eq!(answer, crate::state::refused(1, "credential_refused"));
}
