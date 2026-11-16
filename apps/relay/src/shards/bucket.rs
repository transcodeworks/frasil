//! The bucket that is the copy of record of the peer's shards: any
//! S3-compatible store, through four requests only, PUT, GET, LIST and
//! DELETE, and one guarantee, that a GET after a successful PUT returns what
//! was written, for new and overwritten keys. No request is conditional.
//!
//! - [`Bucket`] is the trait; [`S3Bucket`] is the S3 client the object
//!   store uses too; [`MemoryBucket`] is a fake for tests, which counts
//!   requests and injects delays, failures and crashes.
//! - [`BucketIo`] runs a bucket's requests on a small runtime of its own,
//!   so that the peer's blocking store calls can wait for them from any
//!   thread.

use crate::config::S3Config;
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// A bucket request failed. The message never holds a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketError(pub String);

impl core::fmt::Display for BucketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bucket: {}", self.0)
    }
}

impl std::error::Error for BucketError {}

/// A bucket: objects by key. Keys are ASCII.
pub trait Bucket: Send + Sync {
    /// Writes an object, replacing any under the key; when the future
    /// succeeds, every later GET returns it.
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BucketError>>;

    /// The object under a key, or `None`.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BucketError>>;

    /// Every key that starts with `prefix`, in key order.
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, BucketError>>;

    /// Deletes the object under a key; deleting nothing succeeds.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BucketError>>;

    /// Writes a file as an object, as [`Bucket::put`] does. A bucket that
    /// can stream it from the file overrides this; by default the file is
    /// read whole first.
    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            let bytes = tokio::fs::read(path)
                .await
                .map_err(|e| BucketError(format!("{}: {e}", path.display())))?;
            self.put(key, bytes).await
        })
    }

    /// Writes an object to a file: whether it was there. A bucket that can
    /// stream it to the file overrides this; by default it is read whole
    /// first. The file may be left partly written on a failure.
    fn get_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<bool, BucketError>> {
        Box::pin(async move {
            let Some(bytes) = self.get(key).await? else {
                return Ok(false);
            };
            tokio::fs::write(path, bytes)
                .await
                .map_err(|e| BucketError(format!("{}: {e}", path.display())))?;
            Ok(true)
        })
    }
}

/// Requests a bucket served, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Requests {
    /// PUTs.
    pub puts: u64,
    /// GETs, those that found nothing included.
    pub gets: u64,
    /// LISTs.
    pub lists: u64,
    /// DELETEs.
    pub deletes: u64,
}

impl Requests {
    /// Every request.
    pub fn total(&self) -> u64 {
        self.puts + self.gets + self.lists + self.deletes
    }
}

#[derive(Debug, Default)]
struct Counters {
    puts: AtomicU64,
    gets: AtomicU64,
    lists: AtomicU64,
    deletes: AtomicU64,
}

impl Counters {
    fn read(&self) -> Requests {
        Requests {
            puts: self.puts.load(Ordering::Relaxed),
            gets: self.gets.load(Ordering::Relaxed),
            lists: self.lists.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
        }
    }
}

/// What the fake does wrong, as a test asks.
#[derive(Debug, Default)]
struct Faults {
    /// Every request waits this long first.
    delay: Duration,
    /// Writes (PUT and DELETE) left before the bucket crashes; none for no
    /// crash.
    writes_left: Option<u64>,
    /// The bucket has crashed: every request fails until it recovers.
    crashed: bool,
    /// The next PUTs whose key contains the text fail, this many times.
    fail_puts: Vec<(String, u64)>,
    /// A failed PUT still lands, as a PUT whose answer is lost does.
    land_failed: bool,
    /// PUTs whose key contains the text fail and are held back, this many
    /// times: they land when the test releases them, as a lost answer's PUT
    /// that lands late.
    hold_puts: Vec<(String, u64)>,
    /// The PUTs held back.
    held: Vec<(String, Vec<u8>)>,
    /// PUTs whose key contains the text wait this long more, this many
    /// times.
    slow_puts: Vec<(String, u64, Duration)>,
    /// Every GET is refused, as a read cap refuses them; PUTs go on.
    reads_refused: bool,
}

/// A bucket in memory, for tests: it counts requests, and can wait before
/// each one, fail chosen PUTs, and crash after a number of writes.
#[derive(Debug, Default)]
pub struct MemoryBucket {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    faults: Mutex<Faults>,
    counters: Counters,
}

impl MemoryBucket {
    /// An empty bucket that does everything right.
    pub fn new() -> Self {
        Self::default()
    }

    fn faults(&self) -> std::sync::MutexGuard<'_, Faults> {
        self.faults.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn objects(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.objects.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every request waits `delay` first.
    pub fn set_delay(&self, delay: Duration) {
        self.faults().delay = delay;
    }

    /// The bucket crashes after `writes` more PUTs and DELETEs: the next
    /// write and every request after it fail, until [`Self::recover`].
    pub fn crash_after(&self, writes: u64) {
        self.faults().writes_left = Some(writes);
    }

    /// Ends a crash: every request succeeds again.
    pub fn recover(&self) {
        let mut faults = self.faults();
        faults.crashed = false;
        faults.writes_left = None;
    }

    /// Whether the bucket has crashed.
    pub fn crashed(&self) -> bool {
        self.faults().crashed
    }

    /// The next `times` PUTs whose key contains `text` fail.
    pub fn fail_puts(&self, text: &str, times: u64) {
        self.faults().fail_puts.push((text.to_owned(), times));
    }

    /// Whether a PUT that fails still lands, as one whose answer is lost.
    pub fn set_land_failed(&self, land: bool) {
        self.faults().land_failed = land;
    }

    /// The next `times` PUTs whose key contains `text` fail, and are held
    /// back until [`Self::release_held`].
    pub fn hold_puts(&self, text: &str, times: u64) {
        self.faults().hold_puts.push((text.to_owned(), times));
    }

    /// The next `times` PUTs whose key contains `text` wait `delay` more
    /// before they land.
    pub fn slow_puts(&self, text: &str, times: u64, delay: Duration) {
        self.faults()
            .slow_puts
            .push((text.to_owned(), times, delay));
    }

    /// Lands every PUT held back, in order: their keys.
    pub fn release_held(&self) -> Vec<String> {
        let held = std::mem::take(&mut self.faults().held);
        let mut objects = self.objects();
        held.into_iter()
            .map(|(key, bytes)| {
                objects.insert(key.clone(), bytes);
                key
            })
            .collect()
    }

    /// Whether every GET is refused, as a read cap refuses them, while
    /// PUTs go on.
    pub fn refuse_reads(&self, refused: bool) {
        self.faults().reads_refused = refused;
    }

    /// Writes an object without a request.
    pub fn insert(&self, key: &str, bytes: Vec<u8>) {
        self.objects().insert(key.to_owned(), bytes);
    }

    /// Removes an object without a request.
    pub fn remove(&self, key: &str) {
        self.objects().remove(key);
    }

    /// The requests served so far.
    pub fn requests(&self) -> Requests {
        self.counters.read()
    }

    /// Every key, in order.
    pub fn keys(&self) -> Vec<String> {
        self.objects().keys().cloned().collect()
    }

    /// An object's bytes, read without a request.
    pub fn peek(&self, key: &str) -> Option<Vec<u8>> {
        self.objects().get(key).cloned()
    }

    async fn wait(&self) {
        let delay = self.faults().delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    /// Whether a write may proceed: counts it down to the crash.
    fn write_allowed(&self) -> bool {
        let mut faults = self.faults();
        if faults.crashed {
            return false;
        }
        match &mut faults.writes_left {
            Some(0) => {
                faults.crashed = true;
                false
            }
            Some(left) => {
                *left -= 1;
                true
            }
            None => true,
        }
    }
}

/// What the fake answers a GET it refuses: a read cap's answer.
const CAP_ANSWER: &str = "<Error><Code>AccessDenied</Code><Message>Transaction cap exceeded\
                          </Message></Error>";

fn crashed() -> BucketError {
    BucketError("the bucket is down".into())
}

impl Bucket for MemoryBucket {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            self.counters.puts.fetch_add(1, Ordering::Relaxed);
            self.wait().await;
            let slow = self
                .faults()
                .slow_puts
                .iter_mut()
                .find(|(text, times, _)| *times > 0 && key.contains(text.as_str()))
                .map(|(_, times, delay)| {
                    *times -= 1;
                    *delay
                });
            if let Some(delay) = slow {
                tokio::time::sleep(delay).await;
            }
            let (failing, land) = {
                let mut faults = self.faults();
                let land = faults.land_failed;
                let failing = faults
                    .fail_puts
                    .iter_mut()
                    .find(|(text, times)| *times > 0 && key.contains(text.as_str()))
                    .map(|(_, times)| *times -= 1)
                    .is_some();
                (failing, land)
            };
            if failing {
                if land {
                    self.objects().insert(key.to_owned(), bytes);
                }
                return Err(BucketError("an injected PUT failure".into()));
            }
            {
                let mut faults = self.faults();
                let holding = faults
                    .hold_puts
                    .iter_mut()
                    .find(|(text, times)| *times > 0 && key.contains(text.as_str()))
                    .map(|(_, times)| *times -= 1)
                    .is_some();
                if holding {
                    faults.held.push((key.to_owned(), bytes));
                    return Err(BucketError("an answer that is lost".into()));
                }
            }
            if !self.write_allowed() {
                return Err(crashed());
            }
            self.objects().insert(key.to_owned(), bytes);
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BucketError>> {
        Box::pin(async move {
            self.counters.gets.fetch_add(1, Ordering::Relaxed);
            self.wait().await;
            let faults = self.faults();
            if faults.crashed {
                return Err(crashed());
            }
            if faults.reads_refused {
                return Err(s3_refused("GET", 403, CAP_ANSWER.as_bytes()));
            }
            drop(faults);
            Ok(self.objects().get(key).cloned())
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, BucketError>> {
        Box::pin(async move {
            self.counters.lists.fetch_add(1, Ordering::Relaxed);
            self.wait().await;
            if self.faults().crashed {
                return Err(crashed());
            }
            Ok(self
                .objects()
                .range(prefix.to_owned()..)
                .take_while(|(key, _)| key.starts_with(prefix))
                .map(|(key, _)| key.clone())
                .collect())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            self.counters.deletes.fetch_add(1, Ordering::Relaxed);
            self.wait().await;
            if !self.write_allowed() {
                return Err(crashed());
            }
            self.objects().remove(key);
            Ok(())
        })
    }
}

/// A bucket on an S3-compatible service, under a prefix of its own.
pub struct S3Bucket {
    bucket: Box<s3::Bucket>,
    prefix: String,
}

impl core::fmt::Debug for S3Bucket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Bucket")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl S3Bucket {
    /// A client for the bucket `config` names, with every key under
    /// `prefix` (the object store's own prefix is not used).
    ///
    /// # Errors
    ///
    /// For an endpoint, bucket or credentials that do not read.
    pub fn open(config: &S3Config, prefix: &str) -> Result<Self, BucketError> {
        let bucket = crate::blobs::s3_client(config).map_err(|error| BucketError(error.0))?;
        Ok(Self {
            bucket,
            prefix: prefix.to_owned(),
        })
    }
}

fn s3_failed(request: &str, status: u16) -> BucketError {
    BucketError(format!("S3 answered {status} to a {request}"))
}

/// The text between an XML element's tags, in a service's error answer.
fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let (_, after) = body.split_once(&format!("<{name}>"))?;
    Some(after.split_once(&format!("</{name}>"))?.0)
}

/// A service's refusal, by its answer's status and error code, and whether
/// it says a usage cap was reached. The answer goes no further: its other
/// elements can hold the request's key, its signature or the access key.
fn s3_refused(request: &str, status: u16, body: &[u8]) -> BucketError {
    let body = String::from_utf8_lossy(body);
    let code = element(&body, "Code").filter(|code| {
        !code.is_empty()
            && code.len() <= 64
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    });
    let said = format!(
        "{} {}",
        code.unwrap_or_default(),
        element(&body, "Message").unwrap_or_default()
    )
    .to_ascii_lowercase();
    let cap = ["cap exceeded", "cap_exceeded", "cap reached", "usage cap"]
        .iter()
        .any(|text| said.contains(text));
    BucketError(match (code, cap) {
        (Some(code), true) => {
            format!("S3 answered {status} ({code}, a usage cap reached) to a {request}")
        }
        (None, true) => format!("S3 answered {status} (a usage cap reached) to a {request}"),
        (Some(code), false) => format!("S3 answered {status} ({code}) to a {request}"),
        (None, false) => format!("S3 answered {status} to a {request}"),
    })
}

/// A request with no answer to report, by what became of it. The client's
/// error goes no further: it names the request's URL.
fn s3_unanswered(request: &str, error: &s3::error::S3Error) -> BucketError {
    BucketError(match error {
        s3::error::S3Error::Reqwest(error) if error.is_timeout() => {
            format!("an S3 {request} timed out")
        }
        s3::error::S3Error::Reqwest(error) if error.is_connect() => {
            format!("an S3 {request} did not connect")
        }
        _ => format!("an S3 {request} failed"),
    })
}

impl Bucket for S3Bucket {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            let response = self
                .bucket
                .put_object(format!("{}{key}", self.prefix), &bytes)
                .await
                .map_err(|error| s3_unanswered("PUT", &error))?;
            match response.status_code() {
                200..=299 => Ok(()),
                status => Err(s3_failed("PUT", status)),
            }
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BucketError>> {
        Box::pin(async move {
            match self
                .bucket
                .get_object(format!("{}{key}", self.prefix))
                .await
            {
                Ok(response) => match response.status_code() {
                    200..=299 => Ok(Some(response.bytes().to_vec())),
                    404 => Ok(None),
                    status => Err(s3_refused("GET", status, response.bytes())),
                },
                Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(None),
                Err(error) => Err(s3_unanswered("GET", &error)),
            }
        })
    }

    fn get_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<bool, BucketError>> {
        use tokio::io::AsyncWriteExt;
        Box::pin(async move {
            let failed = |e: std::io::Error| BucketError(format!("{}: {e}", path.display()));
            let mut file = tokio::fs::File::create(path).await.map_err(failed)?;
            let status = match self
                .bucket
                .get_object_to_writer(format!("{}{key}", self.prefix), &mut file)
                .await
            {
                Ok(status) => status,
                Err(s3::error::S3Error::HttpFailWithBody(404, _)) => 404,
                Err(error) => return Err(s3_unanswered("streamed GET", &error)),
            };
            match status {
                200..=299 => {
                    file.flush().await.map_err(failed)?;
                    Ok(true)
                }
                404 => Ok(false),
                status => Err(s3_failed("GET", status)),
            }
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<String>, BucketError>> {
        Box::pin(async move {
            let full = format!("{}{prefix}", self.prefix);
            let pages = self
                .bucket
                .list(full, None)
                .await
                .map_err(|error| s3_unanswered("LIST", &error))?;
            let mut keys: Vec<String> = pages
                .into_iter()
                .flat_map(|page| page.contents)
                .filter_map(|object| object.key.strip_prefix(&self.prefix).map(str::to_owned))
                .collect();
            keys.sort();
            Ok(keys)
        })
    }

    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
    ) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|e| BucketError(format!("{}: {e}", path.display())))?;
            let response = self
                .bucket
                .put_object_stream(&mut file, format!("{}{key}", self.prefix))
                .await
                .map_err(|error| s3_unanswered("streamed PUT", &error))?;
            match response.status_code() {
                200..=299 => Ok(()),
                status => Err(s3_failed("PUT", status)),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BucketError>> {
        Box::pin(async move {
            let response = self
                .bucket
                .delete_object(format!("{}{key}", self.prefix))
                .await
                .map_err(|error| s3_unanswered("DELETE", &error))?;
            match response.status_code() {
                200..=299 | 404 => Ok(()),
                status => Err(s3_failed("DELETE", status)),
            }
        })
    }
}

/// A bucket and the runtime its requests run on.
///
/// The peer's store calls block (crate `writer`, crate `records`): they wait
/// here for requests that run on this runtime's threads, so they may wait
/// from any thread, the writer's included, without a runtime of their own.
pub struct BucketIo {
    bucket: Arc<dyn Bucket>,
    runtime: Option<tokio::runtime::Runtime>,
    handle: tokio::runtime::Handle,
}

impl core::fmt::Debug for BucketIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BucketIo").finish_non_exhaustive()
    }
}

impl Drop for BucketIo {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl BucketIo {
    /// The bucket's requests on a runtime of two threads.
    ///
    /// # Errors
    ///
    /// If the runtime does not start.
    pub fn new(bucket: Arc<dyn Bucket>) -> Result<Self, BucketError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("frasil-bucket")
            .enable_all()
            .build()
            .map_err(|e| BucketError(format!("the bucket's runtime: {e}")))?;
        let handle = runtime.handle().clone();
        Ok(Self {
            bucket,
            runtime: Some(runtime),
            handle,
        })
    }

    /// The bucket.
    pub fn bucket(&self) -> Arc<dyn Bucket> {
        self.bucket.clone()
    }

    /// Starts work on the bucket's runtime.
    pub fn spawn<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.handle.spawn(work)
    }

    /// Runs work on the bucket's runtime and waits for it, blocking this
    /// thread.
    pub fn block<T: Send + 'static>(&self, work: impl Future<Output = T> + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        self.handle.spawn(async move {
            let _ = tx.send(work.await);
        });
        rx.recv()
            .expect("the bucket's runtime runs every task it is given")
    }

    /// Starts blocking work on the bucket runtime's blocking threads: work
    /// that reads a working copy and waits for the bucket with
    /// [`Self::block`].
    pub fn spawn_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        self.handle.spawn_blocking(work)
    }

    /// Waits for a task started by [`Self::spawn`], blocking this thread.
    pub fn join<T: Send + 'static>(&self, task: tokio::task::JoinHandle<T>) -> Option<T> {
        self.block(async move { task.await.ok() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_its_code_and_a_cap_and_nothing_else() {
        let cap = s3_refused(
            "GET",
            403,
            b"<Error><Code>transaction_cap_exceeded</Code><Message>Cap exceeded.</Message>\
              <Resource>records/nodes/active</Resource></Error>",
        );
        assert_eq!(
            cap.0,
            "S3 answered 403 (transaction_cap_exceeded, a usage cap reached) to a GET"
        );
        let message = s3_refused("GET", 403, CAP_ANSWER.as_bytes());
        assert_eq!(
            message.0,
            "S3 answered 403 (AccessDenied, a usage cap reached) to a GET"
        );
        let other = s3_refused(
            "GET",
            403,
            b"<Error><Code>SignatureDoesNotMatch</Code><Message>sig</Message>\
              <AWSAccessKeyId>AKIDSECRETLOOKING</AWSAccessKeyId>\
              <StringToSign>AWS4 secret</StringToSign></Error>",
        );
        assert_eq!(other.0, "S3 answered 403 (SignatureDoesNotMatch) to a GET");
        // A code that is not one, and no answer at all.
        let odd = s3_refused("GET", 500, b"<Code>AKID key=secret</Code>");
        assert_eq!(odd.0, "S3 answered 500 to a GET");
        assert_eq!(s3_refused("GET", 503, b"").0, "S3 answered 503 to a GET");
    }
}
