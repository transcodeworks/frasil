//! Observed reads: a read of a space that runs again when what it reads
//! changes, and tells its observers only when its result differs.
//!
//! [`Space::observe`] turns any read into an [`Observed`]; the prebuilt
//! ones ([`Records::observe_rows`](super::Records::observe_rows),
//! [`Drive::observe`](super::Drive::observe), and others) also share one
//! reader between every observer of the same thing. Each observation has a
//! [`Status`]: data that has not arrived yet is [`Status::Loading`], not an
//! error.
//!
//! One background task per observed read waits for the space's changes.
//! Changes that arrive while a read runs are taken together, so that a
//! burst of changes costs one read more, not one per change. The task ends
//! once every clone of the [`Observed`] is dropped.

use super::{Device, Space};
use crate::device::Notice;
use crate::error::{Error, Result};
use frasil_events::EventId;
use frasil_store::store::{MaybeSend, MaybeSync};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};
use tokio::sync::watch;

/// Where an observed read stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Its first read has not finished, or what it reads has not arrived
    /// at this device yet: a stream it holds no change of, or bytes it does
    /// not hold whole. It reads again as they arrive.
    Loading,
    /// It read what the device holds now.
    Ready,
    /// Its last read failed with [`Observation::error`]. It reads again on
    /// the next change; [`Observation::value`] keeps the last value read.
    Failed,
}

/// What an observed read gave, from [`Observed::get`].
#[derive(Debug)]
#[non_exhaustive]
pub struct Observation<T> {
    /// Where the read stands.
    pub status: Status,
    /// What it read: `None` while loading, and before any read succeeded.
    pub value: Option<Arc<T>>,
    /// Why its last read failed, under [`Status::Failed`].
    pub error: Option<Error>,
}

impl<T> Clone for Observation<T> {
    fn clone(&self) -> Self {
        Self {
            status: self.status,
            value: self.value.clone(),
            error: self.error.clone(),
        }
    }
}

impl<T: PartialEq> PartialEq for Observation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status && self.value == other.value && self.error == other.error
    }
}

impl<T> Observation<T> {
    fn loading() -> Self {
        Self {
            status: Status::Loading,
            value: None,
            error: None,
        }
    }

    /// Whether the read is [`Status::Ready`].
    pub fn is_ready(&self) -> bool {
        self.status == Status::Ready
    }

    /// The observation after a read, from the one before it.
    fn after(&self, read: Result<T>) -> Self {
        match read {
            Ok(value) => Self {
                status: Status::Ready,
                value: Some(Arc::new(value)),
                error: None,
            },
            Err(error) if not_arrived(&error) => Self::loading(),
            Err(error) => Self {
                status: Status::Failed,
                value: self.value.clone(),
                error: Some(error),
            },
        }
    }
}

/// Whether an error says that what a read needs has not arrived at this
/// device yet.
pub(crate) fn not_arrived(error: &Error) -> bool {
    matches!(error, Error::UnknownStream | Error::Class("Missing"))
}

/// A reader shared between observers, of any value type: `Send` and
/// `Sync` on native targets.
#[cfg(not(target_arch = "wasm32"))]
type AnyShared = dyn Any + Send + Sync;
/// A reader shared between observers, of any value type.
#[cfg(target_arch = "wasm32")]
type AnyShared = dyn Any;

/// A read that follows the device: from [`Space::observe`] and the
/// prebuilt `observe` methods. Clones share one reader.
#[derive(Debug)]
pub struct Observed<T> {
    /// Keeps the reader shared while any clone lives.
    _shared: Arc<AnyShared>,
    receiver: watch::Receiver<Observation<T>>,
}

impl<T> Clone for Observed<T> {
    fn clone(&self) -> Self {
        Self {
            _shared: self._shared.clone(),
            receiver: self.receiver.clone(),
        }
    }
}

impl<T> Observed<T> {
    /// The latest observation.
    pub fn get(&self) -> Observation<T> {
        self.receiver.borrow().clone()
    }

    /// Waits until the observation differs from the last one this handle
    /// saw, and returns it; `None` once the device is gone.
    pub async fn changed(&mut self) -> Option<Observation<T>> {
        self.receiver.changed().await.ok()?;
        Some(self.receiver.borrow_and_update().clone())
    }

    /// Waits until the read is [`Status::Ready`], and returns its value;
    /// `None` once the device is gone.
    pub async fn ready(&mut self) -> Option<Arc<T>> {
        loop {
            let now = self.receiver.borrow_and_update().clone();
            if let (Status::Ready, Some(value)) = (now.status, now.value) {
                return Some(value);
            }
            self.receiver.changed().await.ok()?;
        }
    }
}

/// What changes an observed read: its space's events in some streams, or
/// in any, and blobs that arrive or are withdrawn.
#[derive(Debug, Clone)]
pub(crate) struct Scope {
    space: EventId,
    streams: Option<BTreeSet<[u8; 16]>>,
    objects: bool,
    /// Every notice of the space, an acknowledgement with no events placed
    /// among them.
    every: bool,
}

impl Scope {
    /// Any change of the space.
    pub(crate) fn space(space: &Space) -> Self {
        Self {
            space: space.id().event(),
            streams: None,
            objects: false,
            every: false,
        }
    }

    /// Every notice of the space, acknowledgements included.
    pub(crate) fn every(space: &Space) -> Self {
        Self {
            every: true,
            ..Self::space(space)
        }
    }

    /// Changes of one stream of the space, and of who may write there.
    #[cfg_attr(
        not(any(
            feature = "adapter-loro",
            feature = "adapter-records",
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) fn stream(space: &Space, stream: [u8; 16]) -> Self {
        Self {
            space: space.id().event(),
            streams: Some(BTreeSet::from([stream])),
            objects: false,
            every: false,
        }
    }

    /// Also blobs that arrive or are withdrawn.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn with_objects(mut self) -> Self {
        self.objects = true;
        self
    }
}

/// The readers shared by key, while any observer holds one.
pub(crate) type Registry = Mutex<BTreeMap<Vec<u8>, Weak<AnyShared>>>;

/// What a reader shares: the receiver its observers clone.
struct Shared<T> {
    receiver: watch::Receiver<Observation<T>>,
}

/// What the reader gathered of the changes since its last read.
#[derive(Default)]
struct Gathered {
    placed: Vec<EventId>,
    wake: bool,
}

impl Gathered {
    fn take(&mut self, scope: &Scope, notice: Notice) {
        if notice.space != scope.space {
            return;
        }
        self.placed.extend(notice.placed);
        self.wake |= scope.every || (scope.objects && !notice.withdrawn.is_empty());
    }
}

impl Device {
    /// An observed read, shared under `key` when one is given.
    pub(crate) fn observed<T, F, Fut>(
        &self,
        key: Option<Vec<u8>>,
        space: &Space,
        scope: Scope,
        read: F,
    ) -> Observed<T>
    where
        T: PartialEq + MaybeSend + MaybeSync + 'static,
        F: Fn(Space) -> Fut + MaybeSend + MaybeSync + 'static,
        Fut: Future<Output = Result<T>> + MaybeSend + 'static,
    {
        let registry = &self.inner.observers;
        if let Some(key) = &key {
            let found = registry
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(key)
                .and_then(Weak::upgrade);
            if let Some(shared) = found
                && let Some(typed) = (shared.as_ref() as &dyn Any).downcast_ref::<Shared<T>>()
            {
                return Observed {
                    receiver: typed.receiver.clone(),
                    _shared: shared,
                };
            }
        }
        let (sender, receiver) = watch::channel(Observation::loading());
        let shared: Arc<AnyShared> = Arc::new(Shared {
            receiver: receiver.clone(),
        });
        if let Some(key) = key {
            let mut registry = registry.lock().unwrap_or_else(PoisonError::into_inner);
            registry.retain(|_, shared| shared.strong_count() > 0);
            registry.insert(key, Arc::downgrade(&shared));
        }
        let engine = self.engine();
        let notices = engine.subscribe();
        let arrivals = engine.subscribe_arrivals();
        self.spawn(Box::pin(run(
            space.clone(),
            scope,
            read,
            sender,
            notices,
            arrivals,
        )));
        Observed {
            _shared: shared,
            receiver,
        }
    }
}

/// The reader: reads, then reads again after each batch of changes in its
/// scope, until no observer is left or the device is gone.
async fn run<T, F, Fut>(
    space: Space,
    scope: Scope,
    read: F,
    sender: watch::Sender<Observation<T>>,
    mut notices: broadcast::Receiver<Notice>,
    mut arrivals: broadcast::Receiver<(EventId, frasil_adapter::Locator)>,
) where
    T: PartialEq,
    F: Fn(Space) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let publish = |read: Result<T>| {
        sender.send_if_modified(|current| {
            let next = current.after(read);
            let differs = *current != next;
            if differs {
                *current = next;
            }
            differs
        });
    };
    publish(read(space.clone()).await);
    loop {
        let mut gathered = Gathered::default();
        tokio::select! {
            () = sender.closed() => return,
            notice = notices.recv() => match notice {
                Ok(notice) => gathered.take(&scope, notice),
                Err(RecvError::Lagged(_)) => gathered.wake = true,
                Err(RecvError::Closed) => return,
            },
            arrival = arrivals.recv(), if scope.objects => match arrival {
                Ok((from, _)) => gathered.wake |= from == scope.space,
                Err(RecvError::Lagged(_)) => gathered.wake = true,
                Err(RecvError::Closed) => return,
            },
        }
        // What else came meanwhile goes in the same read.
        loop {
            match notices.try_recv() {
                Ok(notice) => gathered.take(&scope, notice),
                Err(TryRecvError::Lagged(_)) => gathered.wake = true,
                Err(_) => break,
            }
        }
        if scope.objects {
            loop {
                match arrivals.try_recv() {
                    Ok((from, _)) => gathered.wake |= from == scope.space,
                    Err(TryRecvError::Lagged(_)) => gathered.wake = true,
                    Err(_) => break,
                }
            }
        }
        if !(gathered.wake || touches(&space, &scope, &gathered.placed).await) {
            continue;
        }
        publish(read(space.clone()).await);
    }
}

/// Whether the events placed touch the scope's streams: a unit of one of
/// them, a change of who may write, or an event that is no stream's
/// content, such as a key that makes units placed earlier readable.
async fn touches(space: &Space, scope: &Scope, placed: &[EventId]) -> bool {
    if placed.is_empty() {
        return false;
    }
    let Some(streams) = &scope.streams else {
        return true;
    };
    space
        .read(|replica| {
            let (changed, members, space_events) = super::feeds::classify(replica, placed);
            members || space_events || !changed.is_disjoint(streams)
        })
        .await
        .unwrap_or(true)
}

impl Space {
    /// Observes a read of this space: `read` runs at once, then again
    /// after the space changes, and the [`Observed`] tells its observers
    /// each time the result differs. A read that fails with
    /// [`Error::UnknownStream`], or `Missing` for bytes not held whole, is
    /// [`Status::Loading`] until it succeeds, so a read of something that
    /// has not arrived yet shows as loading.
    ///
    /// ```ignore
    /// let note = space.observe(move |space| async move {
    ///     space.document(id).await?.text("body").await
    /// });
    /// let text = note.clone().ready().await;
    /// ```
    pub fn observe<T, F, Fut>(&self, read: F) -> Observed<T>
    where
        T: PartialEq + MaybeSend + MaybeSync + 'static,
        F: Fn(Space) -> Fut + MaybeSend + MaybeSync + 'static,
        Fut: Future<Output = Result<T>> + MaybeSend + 'static,
    {
        self.device.observed(None, self, Scope::space(self), read)
    }

    /// Observes whether every change this device made in the space is
    /// durable, as [`Space::is_durable`] says: `true` once the space has
    /// nothing unsent, `false` while anything waits for a peer's, or a
    /// member's, acknowledgement. It changes as this device writes and as
    /// acknowledgements arrive. Every observer of the space shares one
    /// reader.
    pub fn observe_durable(&self) -> Observed<bool> {
        self.device.observed(
            Some(key(self, &[0; 16], "durable", &[])),
            self,
            Scope::every(self),
            |space| async move { Ok(space.is_durable().await) },
        )
    }

    /// Observes whether this device may write in the space as far as a
    /// restore goes, as [`Space::is_write_ready`] says: `false` while a
    /// device opened as restored has not synced the space, then `true`
    /// once it has. It changes at most once while the device is open.
    /// Every observer of the space shares one reader.
    pub fn observe_write_ready(&self) -> Observed<bool> {
        self.device.observed(
            Some(key(self, &[0; 16], "write-ready", &[])),
            self,
            Scope::every(self),
            |space| async move { Ok(space.is_write_ready().await) },
        )
    }
}

/// The key a prebuilt observer is shared under: what it reads, where.
pub(crate) fn key(space: &Space, stream: &[u8; 16], what: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut key = space.id().event().0.to_vec();
    key.extend_from_slice(stream);
    for part in std::iter::once(what.as_bytes()).chain(args.iter().copied()) {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part);
    }
    key
}

#[cfg(all(test, feature = "adapter-records"))]
mod tests {
    use super::Scope;
    use crate::device::Notice;
    use crate::{Device, Storage};
    use frasil_events::EventId;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// An event of no stream, such as a key that makes units placed earlier
    /// readable, wakes an observer of one stream; a unit of another stream
    /// does not.
    #[tokio::test]
    async fn an_event_of_no_stream_wakes_an_observer_of_a_stream() {
        let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
        let space = device.create_space().await.unwrap();
        let records = space.create_records().unwrap();
        records
            .write(|tx| {
                tx.insert("t", b"r");
            })
            .await
            .unwrap();
        let reads = Arc::new(AtomicU64::new(0));
        let counted = reads.clone();
        let mut observed = device.observed(
            None,
            &space,
            Scope::stream(&space, records.opening.stream()),
            move |_| {
                let n = counted.fetch_add(1, Ordering::SeqCst);
                async move { Ok(n) }
            },
        );
        observed.ready().await.unwrap();

        // A unit of another stream: no read.
        let other = space.create_records().unwrap();
        other
            .write(|tx| {
                tx.insert("t", b"x");
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), observed.changed())
                .await
                .is_err()
        );

        // An event the space holds that is no stream's unit.
        let _ = device.engine().notices().send(Notice {
            space: space.id().event(),
            placed: vec![EventId([9; 32])],
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        tokio::time::timeout(Duration::from_secs(5), observed.changed())
            .await
            .expect("read again")
            .unwrap();
    }
}
