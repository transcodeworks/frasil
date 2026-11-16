//! The peer's one writer: every commit of its records goes through it, on
//! a thread of its own, so that no store call runs on the async runtime.
//!
//! The writer commits in groups. It takes the first commit that waits, then
//! every commit that arrives within the group's window, up to its size
//! cap, and makes them in one [`Store::commit_all`]: one transaction and one
//! sync for all of them. Each writer's future completes only once its
//! group is durable, so nothing is acknowledged to a device before then
//! (transport.md, 3.12 What a peer learns of a device, and
//! acknowledgements).
//!
//! Commits are made in the order they were submitted. A caller that must
//! order its commit against others submits it while it holds the lock that
//! orders them, and awaits it after letting go.
//!
//! If a group fails, its commits are tried again one by one, so that one
//! bad commit fails alone; each caller learns its own commit's outcome.
//! A store that makes a group in several steps, as the shards do, may have
//! made some of its commits before it failed. A commit with no expectation
//! made again leaves what it left the first time. A commit with
//! expectations would be judged again against its own write, and refused,
//! so it is always a group of its own, whose failure is its caller's
//! answer.

use crate::config::GroupCommit;
use frasil_store::{Commit, Store, StoreError};
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::oneshot;

/// Where a commit's outcome goes.
enum Done {
    /// To a task, which awaits it.
    Task(oneshot::Sender<Result<bool, StoreError>>),
    /// To a thread outside the runtime, which blocks on it.
    Thread(mpsc::Sender<Result<bool, StoreError>>),
}

impl Done {
    fn send(self, outcome: Result<bool, StoreError>) {
        match self {
            Self::Task(tx) => {
                let _ = tx.send(outcome);
            }
            Self::Thread(tx) => {
                let _ = tx.send(outcome);
            }
        }
    }
}

struct Job {
    commit: Commit,
    bytes: usize,
    done: Done,
}

/// The size of a commit's records.
fn size(commit: &Commit) -> usize {
    commit
        .puts
        .iter()
        .map(|(address, record)| address.len() + record.len())
        .chain(commit.deletes.iter().map(Vec::len))
        .sum()
}

/// Work the writer's thread does between groups, and once a second while
/// no commit comes: the shards' folds, closes and kept readings.
pub(crate) type Maintain = Arc<dyn Fn() + Send + Sync>;

/// The handle to the writer. The thread ends once every handle is dropped
/// and every commit submitted is made.
#[derive(Clone)]
pub(crate) struct Writer {
    tx: mpsc::Sender<Job>,
}

impl core::fmt::Debug for Writer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

impl Writer {
    /// Starts the writer's thread over a store, with the maintenance it
    /// runs between groups.
    ///
    /// # Errors
    ///
    /// If the thread cannot start.
    pub(crate) fn spawn_with(
        store: Arc<dyn Store>,
        policy: GroupCommit,
        maintain: Option<Maintain>,
    ) -> Result<Self, StoreError> {
        let (tx, rx) = mpsc::channel::<Job>();
        // A store whose futures need the runtime's IO is driven on it.
        let handle = tokio::runtime::Handle::try_current().ok();
        std::thread::Builder::new()
            .name("frasil-writer".into())
            .spawn(move || run(&*store, &rx, policy, handle.as_ref(), maintain.as_ref()))
            .map_err(|e| StoreError::new(format!("the writer's thread: {e}")))?;
        Ok(Self { tx })
    }

    /// Submits a commit, in order after every commit submitted before it.
    /// The future completes once the commit's group is durable; dropping it
    /// leaves the commit submitted.
    pub(crate) fn submit(
        &self,
        commit: Commit,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send + 'static {
        let (tx, rx) = oneshot::channel();
        let sent = self
            .tx
            .send(Job {
                bytes: size(&commit),
                commit,
                done: Done::Task(tx),
            })
            .is_ok();
        async move {
            if !sent {
                return Err(StoreError::new("the writer has stopped"));
            }
            rx.await
                .unwrap_or_else(|_| Err(StoreError::new("the writer has stopped")))
        }
    }

    /// Writes and deletes, in one atomic commit, once durable.
    pub(crate) async fn commit(
        &self,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        made(self.submit(Commit::new(puts, deletes)).await)
    }

    /// [`Self::commit`], blocking the calling thread: for a thread outside
    /// the async runtime.
    pub(crate) fn commit_blocking(
        &self,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        self.submit_blocking(Commit::new(puts, deletes))
    }

    /// Waits, blocking, until every commit submitted before is made.
    pub(crate) fn barrier_blocking(&self) -> Result<(), StoreError> {
        self.submit_blocking(Commit::default())
    }

    /// Waits until every commit submitted before is made.
    pub(crate) async fn barrier(&self) -> Result<(), StoreError> {
        made(self.submit(Commit::default()).await)
    }

    fn submit_blocking(&self, commit: Commit) -> Result<(), StoreError> {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Job {
                bytes: size(&commit),
                commit,
                done: Done::Thread(tx),
            })
            .map_err(|_| StoreError::new("the writer has stopped"))?;
        made(
            rx.recv()
                .unwrap_or_else(|_| Err(StoreError::new("the writer has stopped"))),
        )
    }
}

/// A commit with no expectation is always made.
pub(crate) fn made(outcome: Result<bool, StoreError>) -> Result<(), StoreError> {
    match outcome {
        Ok(true) => Ok(()),
        Ok(false) => Err(StoreError::new("a commit with no expectation was refused")),
        Err(error) => Err(error),
    }
}

/// Runs a store's future to its end on this thread: at once for the
/// stores that do their work when first polled, on the runtime otherwise.
fn finish<T>(
    future: frasil_store::BoxFuture<'_, Result<T, StoreError>>,
    handle: Option<&tokio::runtime::Handle>,
) -> Result<T, StoreError> {
    let mut future = pin!(future);
    if let Poll::Ready(outcome) = future
        .as_mut()
        .poll(&mut Context::from_waker(std::task::Waker::noop()))
    {
        return outcome;
    }
    match handle {
        Some(handle) => handle.block_on(future),
        None => Err(StoreError::new("the store answered asynchronously")),
    }
}

fn run(
    store: &dyn Store,
    rx: &mpsc::Receiver<Job>,
    policy: GroupCommit,
    handle: Option<&tokio::runtime::Handle>,
    maintain: Option<&Maintain>,
) {
    let mut maintained = Instant::now();
    // A commit with expectations that arrived while a group gathered: the
    // first of the next group.
    let mut waiting: Option<Job> = None;
    loop {
        let first = match waiting.take() {
            Some(job) => job,
            None => match maintain {
                None => match rx.recv() {
                    Ok(job) => job,
                    Err(_) => return,
                },
                Some(maintain) => {
                    if maintained.elapsed() >= std::time::Duration::from_secs(1) {
                        maintain();
                        maintained = Instant::now();
                    }
                    match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            },
        };
        let mut bytes = first.bytes;
        let alone = conditional(&first.commit);
        let mut group = vec![first];
        let deadline = Instant::now() + policy.window;
        while !alone && group.len() < policy.commits && bytes < policy.bytes {
            let next = match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => rx.recv_timeout(left).ok(),
                _ => rx.try_recv().ok(),
            };
            let Some(job) = next else {
                break;
            };
            if conditional(&job.commit) {
                waiting = Some(job);
                break;
            }
            bytes += job.bytes;
            group.push(job);
        }
        commit_group(store, group, handle);
    }
}

/// Whether a commit has expectations: then it is a group of its own.
fn conditional(commit: &Commit) -> bool {
    !commit.expect.is_empty()
}

fn commit_group(store: &dyn Store, group: Vec<Job>, handle: Option<&tokio::runtime::Handle>) {
    let (commits, dones): (Vec<Commit>, Vec<Done>) =
        group.into_iter().map(|job| (job.commit, job.done)).unzip();
    match finish(store.commit_all(&commits), handle) {
        Ok(made) if made.len() == commits.len() => {
            for (done, made) in dones.into_iter().zip(made) {
                done.send(Ok(made));
            }
        }
        Ok(_) => {
            let error = StoreError::new("the store answered for another count of commits");
            for done in dones {
                done.send(Err(error.clone()));
            }
        }
        Err(error) if commits.len() == 1 => {
            for done in dones {
                done.send(Err(error.clone()));
            }
        }
        // Each commit alone, in order. Every commit of the group is
        // without expectations, so one the group made is made again to the
        // same end.
        Err(_) => {
            for (commit, done) in commits.iter().zip(dones) {
                let outcome = finish(store.commit_all(std::slice::from_ref(commit)), handle)
                    .and_then(|made| {
                        made.first()
                            .copied()
                            .ok_or_else(|| StoreError::new("the store answered for no commit"))
                    });
                done.send(outcome);
            }
        }
    }
}
