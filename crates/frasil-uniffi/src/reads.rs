//! Blob reads and what a device keeps of its blobs: what a read does
//! about a blob that is not here, a reader over a blob that need not be
//! whole on the device, and keeping and dropping (at-rest.md,
//! "Retention"; adapter-blobs.md, 3.5 Fetching).

use crate::cancel::{cancelled, flag_of, raised, run_while_awaited};
use crate::{BlobProgressListener, Blobs, Cancellation, Device, FrasilError, Result, parse, run};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::{OwnedMutexGuard, watch};

/// What a read does about a blob this device does not hold whole. A blob
/// the device holds is read from the device, whatever the read says. With
/// every field left out, the read fetches the blob and leaves it in the
/// cache, within the device's budget.
///
/// The fields are applied in the order they stand here, as
/// `Read::new().keep().uncached().local()` applies the ones that are set:
/// `keep` and `uncached` exclude each other, and of the two together
/// `uncached` holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct ReadOptions {
    /// Keeps the blob: fetched or cached, it stays on the device until
    /// `drop_local`, outside the cache's budget. A read that cannot fetch
    /// the blob now still marks it kept, and the device fetches it by
    /// itself once it can.
    #[uniffi(default = false)]
    pub keep: bool,
    /// Stores nothing of a blob the read fetches: its chunks pass through
    /// memory, a few at a time. A blob the device held before, whole or in
    /// part, stays as it was.
    #[uniffi(default = false)]
    pub uncached: bool,
    /// Fetches nothing: the read gives a blob only when the device holds
    /// it whole, and never waits on the network.
    #[uniffi(default = false)]
    pub local: bool,
}

impl ReadOptions {
    /// The crate's read for these, or its default for none.
    pub(crate) fn of(options: Option<Self>) -> frasil::Read {
        let options = options.unwrap_or_default();
        let mut read = frasil::Read::new();
        if options.keep {
            read = read.keep();
        }
        if options.uncached {
            read = read.uncached();
        }
        if options.local {
            read = read.local();
        }
        read
    }
}

/// How a blob stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BlobState {
    /// The device keeps it until the application drops it. A kept blob
    /// that is not whole here yet is fetched by the device itself. A blob
    /// this device put is kept until an always-on peer holds its bytes and
    /// has acknowledged the change that put it.
    Kept,
    /// The device holds it within its cache's budget, and may drop it.
    Cached,
    /// The device holds nothing of it. A read fetches it.
    Absent,
}

/// Where a blob stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct BlobLocal {
    /// Kept, cached or absent.
    pub state: BlobState,
    /// The bytes the device stores of it: its sealed chunks and header,
    /// which may be part of the blob while it is being fetched or after a
    /// reader read part of it.
    pub bytes: u64,
    /// The blob's size.
    pub size: u64,
}

/// The budget of a device's blob cache and what its blobs take, in stored
/// bytes: a blob's sealed chunks and its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct BlobCacheUsage {
    /// The budget of the cache, as the device was opened with.
    pub budget: u64,
    /// The bytes of the cached blobs, whole or in part: within the budget,
    /// but for what running reads hold beside the cache.
    pub cached: u64,
    /// The bytes of the blobs the device keeps, outside the budget.
    pub kept: u64,
}

/// Which checks of the object format have passed on what a [`BlobReader`]
/// gave (units.md, 3.3 Reading an object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Verified {
    /// Every byte given came from a chunk that opened under the blob's
    /// key at its own place. The checks that need the whole blob have not
    /// run: a member that holds the blob's key can have served chunks that
    /// are not the blob's, and the reader then fails with
    /// `ObjectMismatch`.
    Chunks,
    /// Every check has run: the bytes are the blob's.
    Whole,
}

impl From<frasil::Verified> for Verified {
    fn from(verified: frasil::Verified) -> Self {
        match verified {
            frasil::Verified::Whole => Self::Whole,
            _ => Self::Chunks,
        }
    }
}

fn failed(reason: &str) -> FrasilError {
    FrasilError::Failed {
        reason: reason.into(),
    }
}

/// What a reader last showed of itself: what the calls that do not wait
/// answer while a read holds the reader.
#[derive(Debug, Clone, Copy)]
struct Seen {
    size: Option<u64>,
    verified: Verified,
    window_bytes: u64,
}

impl Seen {
    fn of(reader: &frasil::BlobReader) -> Self {
        Self {
            size: reader.size(),
            verified: reader.verified().into(),
            window_bytes: reader.window_bytes() as u64,
        }
    }
}

/// The reader, held for one call: what it shows is noted when the call
/// ends, however it ends.
struct Turn {
    reader: OwnedMutexGuard<Option<frasil::BlobReader>>,
    seen: Arc<Mutex<Seen>>,
}

impl Turn {
    fn reader(&mut self) -> Result<&mut frasil::BlobReader> {
        self.reader
            .as_mut()
            .ok_or_else(|| failed("the reader is closed"))
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.as_ref() {
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Seen::of(reader);
        }
    }
}

/// The most a reader asks of the blob in one read: a chunk holds less.
const PIECE: u64 = 1 << 20;

/// The most one `read_at` gives, 64 MiB: a read holds its whole range in
/// memory and crosses to the application in one piece.
pub(crate) const MAX_READ: u64 = 64 << 20;

/// Reads `length` bytes of the blob from `offset`, fewer at its end. When
/// a chunk after the first fails, what was read before it is given: the
/// crate's reader gives a chunk at a time, and reports a failure to the
/// read that asks for the chunk that failed.
async fn fill(reader: &mut frasil::BlobReader, offset: u64, length: u64) -> Result<Vec<u8>> {
    let end = offset.saturating_add(length);
    let mut bytes = Vec::new();
    let mut at = offset;
    while at < end {
        let filled = bytes.len();
        let piece = usize::try_from((end - at).min(PIECE)).unwrap_or(usize::MAX);
        bytes.resize(filled + piece, 0);
        let read = match reader.read_at(at, &mut bytes[filled..]).await {
            Ok(read) => read,
            Err(error) if filled == 0 => return Err(error.into()),
            Err(_) => {
                bytes.truncate(filled);
                break;
            }
        };
        bytes.truncate(filled + read);
        if read == 0 {
            break;
        }
        at += read as u64;
    }
    Ok(bytes)
}

/// A reader over one blob, from `Blobs::open_reader`: it reads any range
/// of the blob and fetches only the chunks that hold it, as its
/// [`ReadOptions`] say. Nothing is fetched until it is read or asked its
/// size. One call reads at a time: a read made while another waits takes
/// its turn after it.
///
/// Before the reader gives any byte, the blob's header has passed its
/// checks and the byte's chunk has opened under the blob's key, at its
/// own place in its own blob. [`BlobReader::verified`] says whether the
/// checks that need the whole blob have run.
///
/// A read stops in three ways only: [`BlobReader::end`], its
/// [`Cancellation`], and its caller no longer waiting, as a cancelled
/// Kotlin coroutine. Freeing the reader's handle stops none: a call in
/// flight holds the reader until it ends, so the reader is freed after
/// its last call. A Swift task that is cancelled stops no read either;
/// without a `Cancellation` its read goes on to the end and holds its
/// turn until then.
///
/// End a reader that is done with: [`BlobReader::end`] stops its fetches
/// and waits until the device has looked at its cache. A reader that is
/// only freed ends the same way once no call holds it, and the device
/// looks at its cache afterwards, with nothing waiting for it.
#[derive(uniffi::Object)]
pub struct BlobReader {
    reader: Arc<tokio::sync::Mutex<Option<frasil::BlobReader>>>,
    seen: Arc<Mutex<Seen>>,
    read_ahead: AtomicU64,
    closed: watch::Sender<bool>,
}

impl BlobReader {
    fn of(reader: frasil::BlobReader) -> Arc<Self> {
        Arc::new(Self {
            seen: Arc::new(Mutex::new(Seen::of(&reader))),
            read_ahead: AtomicU64::new(reader.read_ahead()),
            reader: Arc::new(tokio::sync::Mutex::new(Some(reader))),
            closed: watch::Sender::new(false),
        })
    }

    /// What the reader shows now, or showed before the read that holds
    /// it.
    fn seen(&self) -> Seen {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if let Ok(reader) = self.reader.try_lock()
            && let Some(reader) = reader.as_ref()
        {
            *seen = Seen::of(reader);
        }
        *seen
    }

    /// Runs `work` with the reader once its turn comes, until the reader
    /// is ended, `cancellation` is cancelled, or the caller stops
    /// waiting.
    async fn turn<T: Send + 'static>(
        &self,
        cancellation: Option<Arc<Cancellation>>,
        work: Work<T>,
    ) -> Result<T> {
        let reader = self.reader.clone();
        let seen = self.seen.clone();
        let read_ahead = self.read_ahead.load(Ordering::SeqCst);
        let mut closed = self.closed.subscribe();
        run_while_awaited(async move {
            let mut cancel = flag_of(cancellation.as_ref());
            tokio::select! {
                biased;
                () = raised(Some(&mut closed)) => Err(failed("the reader is closed")),
                () = raised(cancel.as_mut()) => Err(cancelled("the read")),
                result = async {
                    let mut turn = Turn {
                        reader: reader.lock_owned().await,
                        seen,
                    };
                    let reader = turn.reader()?;
                    reader.set_read_ahead(read_ahead);
                    work(reader).await
                } => result,
            }
        })
        .await
    }
}

/// What one call does with the reader.
type Work<T> =
    Box<dyn for<'a> FnOnce(&'a mut frasil::BlobReader) -> frasil::BoxFuture<'a, Result<T>> + Send>;

#[uniffi::export(async_runtime = "tokio")]
impl BlobReader {
    /// The blob's size, once a chunk has opened under its header in this
    /// reader: none before the reader's first read or
    /// [`fetch_size`](Self::fetch_size). The header's size is bound by
    /// each chunk, so until one has opened it is only what the party that
    /// sent the header says. While a read holds the reader, what held
    /// before it.
    pub fn size(&self) -> Option<u64> {
        self.seen().size
    }

    /// The blob's size, once a chunk has opened under its header: the
    /// chunk the reader stands in, or the blob's last when it stands past
    /// the end, fetched with the header when the device does not hold
    /// them. Fails as [`read_at`](Self::read_at) does.
    #[uniffi::method(default(cancellation = None))]
    pub async fn fetch_size(&self, cancellation: Option<Arc<Cancellation>>) -> Result<u64> {
        let work: Work<u64> =
            Box::new(|reader| Box::pin(async move { Ok(reader.fetch_size().await?) }));
        self.turn(cancellation, work).await
    }

    /// `length` bytes of the blob from byte `offset`, fewer at its end and
    /// none at or past it. Each chunk the range lies in is fetched first
    /// when the device does not hold it, ahead of everything else asked of
    /// the space's connections, with the chunks after it behind.
    ///
    /// A read holds its whole range in memory, so `length` is at most
    /// 67,108,864 (64 MiB): a longer read is refused before anything is
    /// fetched. Read a large range in pieces; a player's requests are far
    /// smaller.
    ///
    /// When a chunk after the range's first fails, the read gives the
    /// bytes before it, fewer than asked, and loses none: read again from
    /// where it ended, and that read reports the failure. So a read that
    /// gives fewer bytes than asked has reached the blob's end or met a
    /// failure, and only a read that starts at or past the end gives
    /// none.
    ///
    /// It fails with `Missing` while the device does not hold a chunk and
    /// nothing is connected that could send it, or the reader is `local`;
    /// with `Timeout` when for half a minute nothing the reader asked for
    /// arrives; with `Decrypt` or `Malformed` for a chunk that does not
    /// open. After each of these the reader lives on and the read may be
    /// made again. `ObjectMismatch` says the blob was refused: the reader
    /// has failed for good.
    ///
    /// A read ends early, and fails, when `cancellation` is cancelled,
    /// when the reader is ended, and when its caller stops waiting for
    /// it, as a cancelled coroutine does; nothing else stops it. The
    /// bytes it had read are not given. What it had fetched stays where
    /// the reader's options put it, and the reader reads on.
    #[uniffi::method(default(cancellation = None))]
    pub async fn read_at(
        &self,
        offset: u64,
        length: u64,
        cancellation: Option<Arc<Cancellation>>,
    ) -> Result<Vec<u8>> {
        if length > MAX_READ {
            return Err(failed(&format!(
                "a read gives at most {MAX_READ} bytes (64 MiB), and this one asks for \
                 {length}: read the range in pieces"
            )));
        }
        let work: Work<Vec<u8>> = Box::new(move |reader| Box::pin(fill(reader, offset, length)));
        self.turn(cancellation, work).await
    }

    /// How many chunks the reader fetches ahead of where it reads: 8
    /// unless set.
    pub fn read_ahead(&self) -> u64 {
        self.read_ahead.load(Ordering::SeqCst)
    }

    /// Sets how many chunks the reader fetches ahead of where it reads,
    /// at most 64, from its next read on. A reader that stores nothing
    /// holds one sealed chunk more than this in memory. Set it to 0 for a
    /// reader that jumps about.
    pub fn set_read_ahead(&self, chunks: u64) {
        self.read_ahead
            .store(chunks.min(frasil::MAX_READ_AHEAD), Ordering::SeqCst);
    }

    /// Which checks have passed on what the reader gave: `Whole` once the
    /// reader has read the blob in order from its first byte to its last,
    /// or once the device holds the blob whole in its store and every
    /// check ran on it there. While a read holds the reader, what held
    /// before it.
    pub fn verified(&self) -> Verified {
        self.seen().verified
    }

    /// How many sealed bytes the reader holds in memory, of chunks it
    /// fetched to store nothing: at most `(read_ahead + 1) × 1,048,576`.
    /// While a read holds the reader, what held before it.
    pub fn window_bytes(&self) -> u64 {
        self.seen().window_bytes
    }

    /// Ends the reader: its fetches stop, the reads waiting on it fail,
    /// what it held in memory is freed, and the device looks at its
    /// cache, so that a blob it held beside the cache for this reader
    /// alone goes. Every later call on the reader fails. (Named so that
    /// it does not meet the generated objects' own `close`, which frees
    /// the handle and ends nothing that is in flight.)
    pub async fn end(&self) -> Result<()> {
        self.closed.send_replace(true);
        let reader = self.reader.clone();
        let seen = self.seen.clone();
        run(async move {
            let Some(reader) = reader.lock().await.take() else {
                return Ok(());
            };
            *seen.lock().unwrap_or_else(PoisonError::into_inner) = Seen::of(&reader);
            Ok(reader.close().await?)
        })
        .await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Blobs {
    /// Opens a reader over a blob, which reads any range of it and fetches
    /// only the chunks it needs, as `read` says: into the cache when left
    /// out, kept with `keep`, into the reader's own memory with
    /// `uncached`, and nothing with `local`, which reads only what the
    /// device holds. A blob the device holds, whole or in part, is read
    /// from the device whatever `read` says. A blob larger than the
    /// cache's whole budget, and any blob under a budget of zero, is read
    /// through the reader's memory.
    #[uniffi::method(default(read = None))]
    pub async fn open_reader(
        &self,
        id: String,
        read: Option<ReadOptions>,
    ) -> Result<Arc<BlobReader>> {
        let id = parse(&id)?;
        let read = ReadOptions::of(read);
        let blobs = self.inner.clone();
        let reader = run(async move { blobs.open_reader(id, &read).await }).await?;
        Ok(BlobReader::of(reader))
    }

    /// Fetches a blob into this device's store and keeps it there until
    /// `drop_local`, without reading it: a download in the background,
    /// which `listener` follows. A blob the device holds already is kept
    /// from now on, and one that cannot be fetched now fails the call and
    /// stays marked: the device fetches it by itself once a peer or a
    /// member that holds it is connected.
    pub async fn keep(
        &self,
        id: String,
        listener: Option<Arc<dyn BlobProgressListener>>,
    ) -> Result<()> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        run(async move {
            blobs
                .keep(id, |bytes, total| {
                    if let Some(listener) = &listener {
                        listener.progress(bytes, total);
                    }
                })
                .await
        })
        .await?;
        Ok(())
    }

    /// Drops what this device stores of a blob, kept or cached: the blob
    /// is absent here, and a read fetches it again from a peer or a member
    /// that holds it. Nothing changes for anyone else, and the stream
    /// still lists the blob. It fails while the blob must stay: a read, a
    /// reader or a fetch is using it, this device put it in a space with
    /// an always-on peer and no peer is known to hold its bytes yet, or
    /// the device keeps every blob.
    pub async fn drop_local(&self, id: String) -> Result<()> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        Ok(run(async move { blobs.drop_local(id).await }).await?)
    }

    /// Where a blob stands on this device: kept, cached or absent, and how
    /// many bytes the device stores of it.
    pub async fn local(&self, id: String) -> Result<BlobLocal> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        let local = run(async move { blobs.local(id).await }).await?;
        Ok(BlobLocal {
            state: match local.state {
                frasil::BlobState::Kept => BlobState::Kept,
                frasil::BlobState::Cached => BlobState::Cached,
                _ => BlobState::Absent,
            },
            bytes: local.bytes,
            size: local.size,
        })
    }

    /// Whether the change that put a blob is durable: `false` while it
    /// waits for an acknowledgement. It says nothing of the blob's bytes:
    /// `local` tells whether this device still keeps them for want of a
    /// peer that holds them.
    pub async fn is_durable(&self, id: String) -> Result<bool> {
        let id = parse(&id)?;
        let blobs = self.inner.clone();
        Ok(run(async move { blobs.is_durable(id).await }).await?)
    }

    /// The IDs of the stream's blobs whose put is not durable yet: those
    /// this device put whose change still waits for an acknowledgement,
    /// ascending.
    pub async fn pending(&self) -> Result<Vec<String>> {
        let blobs = self.inner.clone();
        let pending = run(async move { blobs.pending().await }).await?;
        Ok(pending.iter().map(ToString::to_string).collect())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Device {
    /// The budget of the blob cache, and what the device's cached and
    /// kept blobs take, in stored bytes, across all its spaces.
    pub async fn blob_cache_usage(&self) -> BlobCacheUsage {
        let device = self.inner.clone();
        let usage = run(async move { device.blob_cache_usage().await }).await;
        BlobCacheUsage {
            budget: usage.budget,
            cached: usage.cached,
            kept: usage.kept,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlobReader, MAX_READ, ReadOptions, Work};
    use crate::{Blobs, Cancellation, Device, DeviceOptions, FrasilError, Result};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    /// A device in memory that holds a blob of three chunks, with a
    /// reader over it.
    async fn held(key: u8) -> (Arc<Device>, Vec<u8>, Arc<BlobReader>) {
        let device = Device::open_in_memory(vec![key; 32], None).await.unwrap();
        let space = device.create_space().await.unwrap();
        let blobs = space.create_blobs().unwrap();
        let bytes: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let id = blobs.put(None, bytes.clone()).await.unwrap();
        let reader = blobs.open_reader(id, None).await.unwrap();
        (device, bytes, reader)
    }

    /// A call that holds the reader and waits for something that never
    /// comes, as a read waits for a chunk nothing sends: once it holds
    /// the reader.
    async fn waiting(
        reader: &Arc<BlobReader>,
        cancellation: Option<Arc<Cancellation>>,
    ) -> JoinHandle<Result<()>> {
        let (holds, held) = oneshot::channel();
        let work: Work<()> = Box::new(move |_reader| {
            Box::pin(async move {
                let _ = holds.send(());
                std::future::pending::<Result<()>>().await
            })
        });
        let reader = reader.clone();
        let call = tokio::spawn(async move { reader.turn(cancellation, work).await });
        held.await.expect("the call holds the reader");
        call
    }

    /// Waits until nothing holds the reader.
    async fn free(reader: &BlobReader) {
        let lock = tokio::time::timeout(Duration::from_secs(10), reader.reader.lock());
        drop(lock.await.expect("the reader's lock is free"));
    }

    fn says(result: &Result<impl Sized>, part: &str) -> bool {
        matches!(result, Err(FrasilError::Failed { reason }) if reason.contains(part))
    }

    /// A read that waits ends when its cancellation is cancelled: it fails
    /// as cancelled, lets the reader go, and the reader reads on.
    #[tokio::test]
    async fn a_waiting_read_ends_when_it_is_cancelled() {
        let (device, bytes, reader) = held(5).await;
        let cancellation = Cancellation::new();
        let call = waiting(&reader, Some(cancellation.clone())).await;
        assert!(reader.reader.try_lock().is_err());
        cancellation.cancel();
        let ended = tokio::time::timeout(Duration::from_secs(10), call).await;
        let ended = ended.expect("the read ends").unwrap();
        assert!(says(&ended, "the read was cancelled"), "{ended:?}");
        free(&reader).await;
        assert_eq!(reader.read_at(7, 10, None).await, Ok(bytes[7..17].to_vec()));
        reader.end().await.unwrap();
        device.shutdown().await.unwrap();
    }

    /// A read that waits ends when its reader is ended: it fails as
    /// closed, `end` returns, and every later read fails as closed.
    #[tokio::test]
    async fn a_waiting_read_ends_when_its_reader_is_ended() {
        let (device, _, reader) = held(6).await;
        let call = waiting(&reader, None).await;
        tokio::time::timeout(Duration::from_secs(10), reader.end())
            .await
            .expect("the reader ends")
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(10), call).await;
        let ended = ended.expect("the read ends").unwrap();
        assert!(says(&ended, "the reader is closed"), "{ended:?}");
        free(&reader).await;
        let after = reader.read_at(7, 10, None).await;
        assert!(says(&after, "the reader is closed"), "{after:?}");
        device.shutdown().await.unwrap();
    }

    /// A read that waits ends when its caller stops waiting, as a
    /// cancelled coroutine does: its work is dropped, the reader is let
    /// go, and the reader reads on.
    #[tokio::test]
    async fn a_waiting_read_ends_when_its_caller_stops_waiting() {
        let (device, bytes, reader) = held(7).await;
        let call = waiting(&reader, None).await;
        call.abort();
        assert!(call.await.is_err_and(|ended| ended.is_cancelled()));
        free(&reader).await;
        assert_eq!(reader.read_at(7, 10, None).await, Ok(bytes[7..17].to_vec()));
        reader.end().await.unwrap();
        device.shutdown().await.unwrap();
    }

    /// A read of 64 MiB is made, and one byte more is refused, whatever
    /// its offset, with nothing read.
    #[tokio::test]
    async fn a_read_longer_than_the_cap_is_refused() {
        let (device, bytes, reader) = held(8).await;
        assert_eq!(MAX_READ, 67_108_864);
        assert_eq!(reader.read_at(0, MAX_READ, None).await, Ok(bytes.clone()));
        assert_eq!(
            reader.read_at(u64::MAX, MAX_READ, None).await,
            Ok(Vec::new())
        );
        for offset in [0, 2_999_999, u64::MAX] {
            let refused = reader.read_at(offset, MAX_READ + 1, None).await;
            assert!(says(&refused, "at most 67108864 bytes"), "{refused:?}");
            assert!(says(&refused, "in pieces"), "{refused:?}");
        }
        assert!(says(&reader.read_at(0, u64::MAX, None).await, "at most"));
        reader.end().await.unwrap();
        device.shutdown().await.unwrap();
    }

    /// Waits up to thirty seconds until `check` gives a value.
    async fn eventually<T, F: Future<Output = Option<T>>>(what: &str, check: impl Fn() -> F) -> T {
        for _ in 0..600 {
            if let Some(found) = check().await {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("not in time: {what}");
    }

    /// A second device, which joins `holder`'s space over loopback, and
    /// the space as it holds it.
    async fn joined(holder: &Arc<Device>, key: u8) -> (Arc<Device>, Arc<crate::Space>) {
        struct Confirms;
        impl crate::AdmissionListener for Confirms {
            fn confirm(&self, _code: String, _name: String) -> Result<bool> {
                Ok(true)
            }
        }
        let options = DeviceOptions {
            blob_cache: None,
            keep_all_blobs: false,
            loopback: true,
        };
        let device = Device::open_in_memory(vec![key; 32], Some(options))
            .await
            .unwrap();
        let space = holder.spaces().await.remove(0);
        let space = holder.space(space).await.unwrap();
        let invitation = space
            .invite("write".into(), "holder".into(), Arc::new(Confirms))
            .await
            .unwrap();
        let text = invitation.text();
        let joined = device
            .join(text, "reader".into(), Arc::new(Confirms), None)
            .await
            .unwrap();
        invitation.admitted(None).await.unwrap();
        (device, joined)
    }

    /// A read whose second chunk fails gives the first chunk's bytes, and
    /// the read from where it ended reports the failure.
    #[tokio::test]
    async fn a_read_gives_what_it_read_before_a_chunk_that_fails() {
        let options = DeviceOptions {
            blob_cache: None,
            keep_all_blobs: false,
            loopback: true,
        };
        let holder = Device::open_in_memory(vec![31; 32], Some(options))
            .await
            .unwrap();
        let space = holder.create_space().await.unwrap();
        let files = space.create_blobs().unwrap();
        let (device, joined) = joined(&holder, 32).await;
        let bytes: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let id = files.put(None, bytes.clone()).await.unwrap();
        // A stream exists in its space from its first blob.
        let blobs: Arc<Blobs> = eventually("the stream arrives", || async {
            joined.blobs(files.id()).await.ok()
        })
        .await;
        eventually("the blob is listed", || async {
            let status = blobs.status(id.clone()).await.ok();
            status.filter(|status| *status == crate::BlobStatus::Absent)
        })
        .await;

        // The first chunk alone is fetched, into the cache.
        let first = blobs.get_range(id.clone(), 0, 10, None).await.unwrap();
        assert_eq!(first.as_deref(), Some(&bytes[..10]));

        // A reader that fetches nothing holds the first chunk, and no
        // other: a read over both gives the first chunk's bytes.
        let local = ReadOptions {
            local: true,
            ..ReadOptions::default()
        };
        let reader = blobs.open_reader(id, Some(local)).await.unwrap();
        let read = reader.read_at(100, 2_000_000, None).await.unwrap();
        assert!(!read.is_empty() && read.len() < 2_000_000);
        assert_eq!(read, bytes[100..100 + read.len()]);
        // From where it ended, the failure is the read's own.
        let after = reader.read_at(100 + read.len() as u64, 10, None).await;
        assert!(says(&after, "Missing"), "{after:?}");
        reader.end().await.unwrap();
        device.shutdown().await.unwrap();
        holder.shutdown().await.unwrap();
    }

    /// Each set of read options crosses as the read the crate's builder
    /// makes of the same calls, in the fields' order.
    #[test]
    fn read_options_cross_as_the_builder_makes_them() {
        let read = |keep, uncached, local| {
            ReadOptions::of(Some(ReadOptions {
                keep,
                uncached,
                local,
            }))
        };
        let new = frasil::Read::new;
        assert_eq!(ReadOptions::of(None), new());
        assert_eq!(read(false, false, false), new());
        assert_eq!(read(true, false, false), new().keep());
        assert_eq!(read(false, true, false), new().uncached());
        assert_eq!(read(false, false, true), new().local());
        assert_eq!(read(true, false, true), new().keep().local());
        assert_eq!(read(false, true, true), new().uncached().local());
        // The two exclude each other in the crate: the later call holds.
        assert_eq!(read(true, true, false), new().keep().uncached());
        assert_eq!(read(true, true, false), new().uncached());
        assert_eq!(read(true, true, true), new().uncached().local());
    }

    /// A read given a cancellation that was cancelled fails and leaves the
    /// reader reading; an ended reader fails every call, and ends again.
    #[tokio::test]
    async fn a_cancelled_read_fails_and_an_ended_reader_stays_ended() {
        let (device, bytes, reader) = held(3).await;
        assert_eq!(reader.size(), None);

        let cancellation = Cancellation::new();
        assert_eq!(
            reader.read_at(0, 10, Some(cancellation.clone())).await,
            Ok(bytes[..10].to_vec())
        );
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        let cancelled = reader.read_at(0, 10, Some(cancellation.clone())).await;
        assert!(says(&cancelled, "the read was cancelled"));
        assert!(reader.fetch_size(Some(cancellation)).await.is_err());

        // Over the end of two chunks, and past the blob's end.
        assert_eq!(
            reader.read_at(1_000_000, 1_500_000, None).await.unwrap(),
            bytes[1_000_000..2_500_000]
        );
        assert_eq!(
            reader.read_at(2_999_990, 100, None).await.unwrap(),
            bytes[2_999_990..]
        );
        assert_eq!(reader.read_at(3_000_000, 100, None).await, Ok(Vec::new()));
        assert_eq!(reader.read_at(u64::MAX, 100, None).await, Ok(Vec::new()));
        assert_eq!(reader.size(), Some(3_000_000));

        reader.end().await.unwrap();
        let ended = reader.read_at(0, 10, None).await;
        assert!(says(&ended, "the reader is closed"));
        assert!(reader.fetch_size(None).await.is_err());
        assert_eq!(reader.size(), Some(3_000_000));
        reader.end().await.unwrap();
        device.shutdown().await.unwrap();
    }

    /// A device opened with a budget reports it, and one opened with none
    /// reports the crate's default.
    #[tokio::test]
    async fn a_budget_crosses_to_the_device() {
        let open = |options| async move {
            let device = frasil::Device::open_with(
                frasil::Storage::Memory,
                &[1; 32],
                DeviceOptions::of(options),
            )
            .await
            .unwrap();
            let usage = device.blob_cache_usage().await;
            device.close().await.unwrap();
            usage.budget
        };
        assert_eq!(open(None).await, 256 << 20);
        let options = DeviceOptions {
            blob_cache: Some(4096),
            keep_all_blobs: false,
            loopback: true,
        };
        assert_eq!(open(Some(options)).await, 4096);
    }
}
