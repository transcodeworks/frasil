//! Fetching chunks of objects (units.md, "Sync", objects; transport.md,
//! "Objects over HTTP"): which chunks a device wants, how urgently, and
//! until when.
//!
//! A **request** names a space, an object, a range of its chunks and a
//! priority, and can be cancelled. The device keeps the requests made of
//! it ([`Requests`]); each connection of the space takes them, beside the
//! objects the space's units name that it fetches by itself, into a queue
//! of its own ([`Queue`]), highest priority first, and serves each on a
//! task, so that the connection goes on reading messages meanwhile. A
//! connection over the HTTP chunk routes runs a few slice requests at
//! once, and asks once for a slice two of them need ([`Slices`]). On a
//! stream, a request becomes `ObjectWant`s ([`Asks`]); nothing on the
//! wire cancels one, so an answer no longer wanted is dropped as it
//! arrives. A connection that asks an object's chunks of the other side
//! no further says so, and once no connection of the space will try, the
//! holders of the requests for it hear why ([`FetchEnd`]).
//!
//! A fetch changes nothing of what is checked: every chunk passes
//! [`Engine::receive_part`](crate::device::Engine) before it is kept, and
//! an object these chunks make whole is checked against its locator's
//! digest there. A request made for a reader that stores nothing brings
//! chunks for that reader's window alone (`reading.rs`): they pass the
//! same checks, and the device stores none of them.

use frasil_adapter::Locator;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::{Notify, watch};

/// The most chunks one `ObjectWant` asks for (units.md, "Sync messages").
pub(crate) const CHUNKS_PER_WANT: u64 = 64;

/// How many slice requests a connection runs at once on the HTTP chunk
/// routes.
#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) const SLICES_AT_ONCE: usize = 4;

/// How urgent a fetch is. A connection serves the most urgent first, and
/// those of one priority in the order they were made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FetchPriority {
    /// The chunks a reader stands at: what it hands out next.
    Position,
    /// The chunks after a reader's position, fetched ahead of it.
    ReadAhead,
    /// Chunks nobody waits for at a position: an object kept whole, or
    /// one the space's units name.
    Background,
}

/// A signal that a fetch is no longer wanted. Clones share it.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<Cancelled>);

#[derive(Debug, Default)]
struct Cancelled {
    flag: AtomicBool,
    waiters: Notify,
}

impl Cancel {
    /// A signal not yet given.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the signal: a fetch that follows it stops before its next
    /// slice, and a transfer that can be aborted is.
    pub fn cancel(&self) {
        self.0.flag.store(true, Ordering::Release);
        self.0.waiters.notify_waiters();
    }

    /// Whether the signal was given.
    pub fn is_cancelled(&self) -> bool {
        self.0.flag.load(Ordering::Acquire)
    }

    /// Ready once the signal is given.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.0.waiters.notified();
            tokio::pin!(notified);
            // Registered before the flag is read, so that a signal given
            // between the two is not missed.
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Why the connections of a space gave a request up: each that takes the
/// device's requests asks the other side for no more of the object. A
/// connection made later may still serve the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchEnd {
    /// A chunk the other side sent failed its checks (units.md, 3.3
    /// Reading an object), or the object, once whole, did not hash to its
    /// locator. What the device held of the object stays where the fault
    /// is that chunk's alone: it does not check under the header it came
    /// with, or under the header the device holds, under which a chunk
    /// has opened. It was dropped where the object did not hash to its
    /// locator, and where a chunk opened under each of two headers, the
    /// one held and the one that arrived.
    Refused,
    /// The stored bytes the other side sent do not read as the object's
    /// header gives them (transport.md, "Objects over HTTP"). What the
    /// device held of the object stays.
    Malformed,
    /// The other side of a stream sent nothing the device could keep of
    /// the chunks asked for, time after time: no answer, or chunks it
    /// could not check or take. What the device holds of the object
    /// stays, and the object is not refused: a request made afterwards
    /// asks for it again.
    Unserved,
}

/// One request for chunks of an object.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    /// The device's number for it; 0 for a fetch a connection starts by
    /// itself.
    pub id: u64,
    pub space: EventId,
    pub locator: Locator,
    /// The chunks wanted; an end past the object's chunk count means to
    /// its last chunk.
    pub chunks: Range<u64>,
    pub priority: FetchPriority,
    pub cancel: Cancel,
    /// Whether the chunks it brings are the store's. A request of a reader
    /// that stores nothing is not: its chunks go to the reader's window,
    /// and the device does not mean to hold the object for it.
    pub stores: bool,
    /// How a connection gave the request up, for its [`Fetch`].
    pub ended: Arc<watch::Sender<Option<FetchEnd>>>,
}

#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
impl Request {
    /// A fetch a connection starts by itself, of an object the space's
    /// units name: whole, behind what readers wait for.
    pub(crate) fn of_units(space: EventId, locator: Locator) -> Self {
        Self {
            id: 0,
            space,
            locator,
            chunks: 0..u64::MAX,
            priority: FetchPriority::Background,
            cancel: Cancel::new(),
            stores: true,
            ended: Arc::new(watch::channel(None).0),
        }
    }
}

/// How long a request whose fetch stopped waits before it is tried again
/// on the same connection, by how many times in a row it stopped with
/// nothing kept: half a second, doubled each time, at most half a minute.
#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) fn again_after(stopped: u32) -> Duration {
    const FIRST_MS: u64 = 500;
    const MOST_MS: u64 = 30_000;
    let wait = FIRST_MS.saturating_mul(1u64.checked_shl(stopped).unwrap_or(u64::MAX));
    Duration::from_millis(wait.min(MOST_MS))
}

/// The requests made of a device and still wanted.
#[derive(Debug)]
pub(crate) struct Requests {
    live: Mutex<Live>,
    /// Counts the changes, so that connections look again.
    changed: watch::Sender<u64>,
}

#[derive(Debug, Default)]
struct Live {
    next: u64,
    requests: BTreeMap<u64, Request>,
    /// The connections that take the device's requests, each for one
    /// space, by the numbers given them.
    takers: BTreeMap<u64, Taking>,
    /// The connections being made that will take a space's requests, by
    /// the numbers given them, each with its space.
    expected: BTreeMap<u64, EventId>,
}

/// One connection that takes a space's requests.
#[derive(Debug)]
struct Taking {
    space: EventId,
    /// The objects it gave up for good, and why.
    given_up: BTreeMap<Locator, FetchEnd>,
    /// The requests whose chunks it left unserved, by their numbers: it
    /// asks no further for them, and has not given their object up.
    unserved: BTreeSet<u64>,
}

impl Live {
    /// Whether a connection is being made that will take the space's
    /// requests.
    fn expecting(&self, space: &EventId) -> bool {
        self.expected.values().any(|of| of == space)
    }

    /// Why no connection will fetch an object: `None` while no
    /// connection takes the space's requests, one of them has not given
    /// the object up, or one is still being made. `but` leaves one
    /// connection out.
    fn given_up(&self, space: &EventId, locator: &Locator, but: Option<u64>) -> Option<FetchEnd> {
        if self.expecting(space) {
            return None;
        }
        let mut end = None;
        for (id, taking) in &self.takers {
            if taking.space != *space || but == Some(*id) {
                continue;
            }
            end = Some(*taking.given_up.get(locator)?);
        }
        end
    }

    /// Tells each request of a space that has no end yet the one it has
    /// now, if every connection that would have tried gave its object up,
    /// or left the request's chunks unserved: after one of them went, or
    /// left chunks unserved, and once no connection is being made.
    fn tell_again(&self, space: &EventId) {
        if self.expecting(space) {
            return;
        }
        for request in self.requests.values() {
            if request.space != *space || request.ended.borrow().is_some() {
                continue;
            }
            if let Some(end) = self.given_up(&request.space, &request.locator, None) {
                request.ended.send_replace(Some(end));
                continue;
            }
            // Each connection is done with it, and one at least would
            // serve a request made afterwards.
            let mut takers = self.takers.values().filter(|taking| taking.space == *space);
            let mut unserved = false;
            let done = takers.all(|taking| {
                let left = taking.unserved.contains(&request.id);
                unserved |= left;
                left || taking.given_up.contains_key(&request.locator)
            });
            if done && unserved {
                request.ended.send_replace(Some(FetchEnd::Unserved));
            }
        }
    }

    /// Tells each request still wanted for an object why it ended.
    fn tell(&self, space: &EventId, locator: &Locator, end: FetchEnd) {
        for request in self.requests.values() {
            if request.space == *space && request.locator == *locator {
                request.ended.send_replace(Some(end));
            }
        }
    }
}

impl Default for Requests {
    fn default() -> Self {
        Self {
            live: Mutex::default(),
            changed: watch::channel(0).0,
        }
    }
}

impl Requests {
    fn live(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes a request: wanted until its [`Fetch`] is cancelled or
    /// dropped. One for an object that every connection of the space
    /// gave up already has its end from the start.
    pub(crate) fn add(
        self: &Arc<Self>,
        space: EventId,
        locator: Locator,
        chunks: Range<u64>,
        priority: FetchPriority,
    ) -> Fetch {
        self.add_for(space, locator, chunks, priority, true)
    }

    /// [`add`](Self::add), saying whether the chunks the request brings
    /// are the store's (`stores`) or a reader's window's.
    pub(crate) fn add_for(
        self: &Arc<Self>,
        space: EventId,
        locator: Locator,
        chunks: Range<u64>,
        priority: FetchPriority,
        stores: bool,
    ) -> Fetch {
        let cancel = Cancel::new();
        let (id, ended) = {
            let mut live = self.live();
            let ended = Arc::new(watch::channel(live.given_up(&space, &locator, None)).0);
            live.next += 1;
            let id = live.next;
            live.requests.insert(
                id,
                Request {
                    id,
                    space,
                    locator,
                    chunks,
                    priority,
                    cancel: cancel.clone(),
                    stores,
                    ended: ended.clone(),
                },
            );
            (id, ended)
        };
        self.changed.send_modify(|count| *count += 1);
        Fetch {
            id,
            cancel,
            ended,
            requests: self.clone(),
        }
    }

    /// A connection that takes a space's requests from now on, until
    /// the [`Taker`] is dropped.
    pub(crate) fn attach(self: &Arc<Self>, space: EventId) -> Taker {
        let mut live = self.live();
        live.next += 1;
        let id = live.next;
        live.takers.insert(
            id,
            Taking {
                space,
                given_up: BTreeMap::new(),
                unserved: BTreeSet::new(),
            },
        );
        Taker {
            id,
            space,
            requests: self.clone(),
        }
    }

    /// A connection that is being made and will take a space's requests,
    /// until the [`Expected`] is dropped: when the connection takes them
    /// ([`attach`](Self::attach)), or is not made after all. No request of
    /// the space ends meanwhile because the other connections gave it up:
    /// this one may still serve it.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) fn expect(self: &Arc<Self>, space: EventId) -> Expected {
        let mut live = self.live();
        live.next += 1;
        let id = live.next;
        live.expected.insert(id, space);
        Expected {
            id,
            space,
            requests: self.clone(),
        }
    }

    /// Whether a connection is being made that will take the space's
    /// requests.
    #[cfg_attr(
        not(all(
            feature = "adapter-blobs",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        )),
        allow(dead_code)
    )]
    pub(crate) fn expecting(&self, space: &EventId) -> bool {
        self.live().expecting(space)
    }

    /// Whether a connection takes the space's requests now.
    #[cfg_attr(
        not(all(
            feature = "adapter-blobs",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        )),
        allow(dead_code)
    )]
    pub(crate) fn taken(&self, space: &EventId) -> bool {
        self.live()
            .takers
            .values()
            .any(|taking| taking.space == *space)
    }

    /// The requests of a space still wanted, oldest first.
    pub(crate) fn of(&self, space: &EventId) -> Vec<Request> {
        self.live()
            .requests
            .values()
            .filter(|request| request.space == *space && !request.cancel.is_cancelled())
            .cloned()
            .collect()
    }

    /// Whether a request still wanted names this chunk.
    pub(crate) fn wants(&self, space: &EventId, locator: &Locator, index: u64) -> bool {
        self.live().requests.values().any(|request| {
            request.space == *space
                && request.locator == *locator
                && request.chunks.contains(&index)
                && !request.cancel.is_cancelled()
        })
    }

    /// Whether a request still wanted for an object means its chunks for
    /// the store.
    pub(crate) fn stores(&self, space: &EventId, locator: &Locator) -> bool {
        self.live().requests.values().any(|request| {
            request.space == *space
                && request.locator[..32] == locator[..32]
                && request.stores
                && !request.cancel.is_cancelled()
        })
    }

    /// Whether a request still wanted names this chunk for the store.
    pub(crate) fn stores_chunk(&self, space: &EventId, locator: &Locator, index: u64) -> bool {
        self.live().requests.values().any(|request| {
            request.space == *space
                && request.locator == *locator
                && request.chunks.contains(&index)
                && request.stores
                && !request.cancel.is_cancelled()
        })
    }

    /// Whether a request still wanted names this chunk or a later one:
    /// what an object taken in order needs before the chunks asked for.
    pub(crate) fn reaches(&self, space: &EventId, locator: &Locator, index: u64) -> bool {
        self.live().requests.values().any(|request| {
            request.space == *space
                && request.locator == *locator
                && index < request.chunks.end
                && !request.chunks.is_empty()
                && !request.cancel.is_cancelled()
        })
    }

    /// Whether a request is still wanted, by its number.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) fn is_live(&self, id: u64) -> bool {
        self.live().requests.contains_key(&id)
    }

    /// Follows the requests: the receiver changes when one is made or
    /// ends.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn end(&self, id: u64) {
        if self.live().requests.remove(&id).is_some() {
            self.changed.send_modify(|count| *count += 1);
        }
    }
}

/// One connection's place among those that take a space's requests
/// ([`Requests::attach`]): through it the connection says which objects
/// it asks the other side for no further. The holders of the requests for
/// an object hear of its end once every connection of the space that
/// takes requests gave it up and none is still being made
/// ([`Requests::expect`]), so that none hears of an end while another
/// connection will still try.
#[derive(Debug)]
pub(crate) struct Taker {
    id: u64,
    space: EventId,
    requests: Arc<Requests>,
}

impl Taker {
    /// The connection gave an object up for good: it is not asked of the
    /// other side again on this connection. Once no other connection of
    /// the space will try, each request still wanted for it hears why,
    /// and so does each made afterwards.
    pub(crate) fn give_up(&self, locator: &Locator, end: FetchEnd) {
        let mut live = self.requests.live();
        if let Some(taking) = live.takers.get_mut(&self.id) {
            taking.given_up.insert(*locator, end);
        }
        if live.given_up(&self.space, locator, None).is_some() {
            live.tell(&self.space, locator, end);
        }
    }

    /// The connection asks no further for the chunks it asked of an
    /// object, for want of an answer it could keep, without giving the
    /// object up: a request made afterwards is asked for again. Each
    /// request wanted for it now hears of it, unless another connection
    /// of the space will still try; while one is being made, it hears
    /// once that connection is made and is done with it too, or is not
    /// made after all.
    pub(crate) fn unserved(&self, locator: &Locator) {
        let mut live = self.requests.live();
        let wanted: BTreeSet<u64> = live
            .requests
            .values()
            .filter(|request| request.space == self.space && request.locator == *locator)
            .map(|request| request.id)
            .collect();
        let known: BTreeSet<u64> = live.requests.keys().copied().collect();
        if let Some(taking) = live.takers.get_mut(&self.id) {
            // Those of requests that ended are of no use any more.
            taking.unserved.retain(|id| known.contains(id));
            taking.unserved.extend(wanted);
        }
        live.tell_again(&self.space);
    }
}

impl Drop for Taker {
    fn drop(&mut self) {
        let mut live = self.requests.live();
        live.takers.remove(&self.id);
        // The connections that stay may each have given up an object
        // this one would still have tried.
        live.tell_again(&self.space);
    }
}

/// A connection being made that will take a space's requests
/// ([`Requests::expect`]): while it is held, no request of the space ends
/// for want of a connection that will try.
#[derive(Debug)]
pub(crate) struct Expected {
    id: u64,
    space: EventId,
    requests: Arc<Requests>,
}

impl Drop for Expected {
    fn drop(&mut self) {
        let mut live = self.requests.live();
        live.expected.remove(&self.id);
        // Made, and among the takers now; or not made, and the
        // connections that stay may each have given an object up.
        live.tell_again(&self.space);
    }
}

/// A request for chunks of an object, wanted while this is held: dropping
/// it cancels the request.
#[derive(Debug)]
pub struct Fetch {
    id: u64,
    cancel: Cancel,
    ended: Arc<watch::Sender<Option<FetchEnd>>>,
    requests: Arc<Requests>,
}

impl Fetch {
    /// Cancels the request: a fetch for it stops before its next slice,
    /// and a chunk that arrives for it alone is not kept.
    pub fn cancel(&self) {
        self.cancel.cancel();
        self.requests.end(self.id);
    }

    /// Whether the request was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Why the space's connections gave the request up, once each that
    /// takes the device's requests did: the latest to do so. While
    /// another connection will still try, nothing is reported. A fetch
    /// that only stopped, because its transfer was cut or the other side
    /// lacks the object for now, is tried again and is not reported
    /// here.
    pub fn end(&self) -> Option<FetchEnd> {
        *self.ended.borrow()
    }

    /// Follows the request's end: the receiver changes when the space's
    /// connections give the request up.
    pub(crate) fn follow_end(&self) -> watch::Receiver<Option<FetchEnd>> {
        self.ended.subscribe()
    }

    /// Ready once the space's connections gave the request up, with why
    /// ([`end`](Self::end)): a holder that waits for the chunks can stop
    /// waiting for them, until another connection is made. Ready at once
    /// for a request made for an object they gave up before. Never ready
    /// for a request some connection goes on trying, nor while a
    /// connection of the space is still being made: a peer that has not
    /// yet granted the space, or a member whose attach is not yet
    /// started.
    pub async fn ended(&self) -> FetchEnd {
        let mut ended = self.ended.subscribe();
        loop {
            if let Some(end) = *ended.borrow_and_update() {
                return end;
            }
            // The sender lives as long as this handle.
            if ended.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for Fetch {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// The requests a connection has yet to serve, most urgent first.
#[derive(Debug, Default)]
#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) struct Queue {
    waiting: BTreeMap<(FetchPriority, u64), Request>,
    /// Counts the requests taken, to keep those of one priority in order.
    taken: u64,
}

#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
impl Queue {
    /// Takes a request, behind those of its priority taken before.
    pub(crate) fn push(&mut self, request: Request) {
        self.taken += 1;
        self.waiting.insert((request.priority, self.taken), request);
    }

    /// The most urgent request still wanted, and the oldest of those;
    /// cancelled ones are dropped on the way.
    pub(crate) fn pop(&mut self) -> Option<Request> {
        while let Some((_, request)) = self.waiting.pop_first() {
            if !request.cancel.is_cancelled() {
                return Some(request);
            }
        }
        None
    }

    /// The priority of the most urgent request still wanted; cancelled
    /// ones are dropped on the way.
    pub(crate) fn most_urgent(&mut self) -> Option<FetchPriority> {
        while let Some(first) = self.waiting.first_entry() {
            if !first.get().cancel.is_cancelled() {
                return Some(first.key().0);
            }
            first.remove();
        }
        None
    }

    /// Whether no request waits.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

/// Slices of stored objects that fetches of one connection share
/// (transport.md, "Objects over HTTP"). A sealed chunk spans two slices,
/// so two fetches of neighbouring chunks need one slice both: each claims
/// the slices it is about to take, the first to need one asks for it, and
/// the other takes the same bytes. A slice stays here only while a fetch
/// that claimed it has not taken it.
#[derive(Debug)]
#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) struct Slices<K: Ord + Clone, T> {
    slots: Mutex<BTreeMap<K, Slot<T>>>,
}

#[derive(Debug)]
struct Slot<T> {
    /// How many fetches have yet to take the slice.
    claims: usize,
    state: SlotState<T>,
}

#[derive(Debug)]
enum SlotState<T> {
    /// Nobody asked for it yet, or the request for it failed.
    Idle,
    /// A fetch asked for it: those that wait for its answer, which hear
    /// `None` when the request fails or is given up.
    Asked(Vec<tokio::sync::oneshot::Sender<Option<Arc<T>>>>),
    /// It arrived.
    Here(Arc<T>),
}

impl<K: Ord + Clone, T> Default for Slices<K, T> {
    fn default() -> Self {
        Self {
            slots: Mutex::default(),
        }
    }
}

/// Puts a slot back to idle when the request for it is given up part way,
/// so that those that wait ask for it themselves.
struct Asking<'a, K: Ord + Clone, T> {
    slices: &'a Slices<K, T>,
    key: K,
    done: bool,
}

impl<K: Ord + Clone, T> Drop for Asking<'_, K, T> {
    fn drop(&mut self) {
        if !self.done {
            self.slices.settle(&self.key, None);
        }
    }
}

#[cfg_attr(
    not(any(feature = "server", feature = "server-socket")),
    allow(dead_code)
)]
impl<K: Ord + Clone, T> Slices<K, T> {
    fn slots(&self) -> std::sync::MutexGuard<'_, BTreeMap<K, Slot<T>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes that a fetch is about to take a slice.
    pub(crate) fn claim(&self, key: K) {
        self.slots()
            .entry(key)
            .or_insert(Slot {
                claims: 0,
                state: SlotState::Idle,
            })
            .claims += 1;
    }

    /// A fetch took a slice it claimed, or no longer needs it.
    pub(crate) fn release(&self, key: &K) {
        let mut slots = self.slots();
        if let Some(slot) = slots.get_mut(key) {
            slot.claims = slot.claims.saturating_sub(1);
            // One being asked for stays until its answer, for those that
            // wait.
            if slot.claims == 0 && !matches!(slot.state, SlotState::Asked(_)) {
                slots.remove(key);
            }
        }
    }

    /// How many slices are held or being asked for.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots().len()
    }

    /// Ends a request for a slice: with its bytes, kept while a fetch
    /// still claims them, or with none.
    fn settle(&self, key: &K, value: Option<Arc<T>>) {
        let mut slots = self.slots();
        let Some(slot) = slots.get_mut(key) else {
            return;
        };
        let next = match &value {
            Some(value) => SlotState::Here(value.clone()),
            None => SlotState::Idle,
        };
        if let SlotState::Asked(waiters) = std::mem::replace(&mut slot.state, next) {
            for waiter in waiters {
                let _ = waiter.send(value.clone());
            }
        }
        if slot.claims == 0 {
            slots.remove(key);
        }
    }

    /// A slice: the one held or being asked for, or else the answer of
    /// `ask`, which is then run once for every fetch that waits.
    ///
    /// # Errors
    ///
    /// `ask`'s.
    pub(crate) async fn get<E>(
        &self,
        key: &K,
        ask: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<Arc<T>, E> {
        let mut ask = std::pin::pin!(ask);
        loop {
            let waiting = {
                let mut slots = self.slots();
                let slot = slots.entry(key.clone()).or_insert(Slot {
                    claims: 0,
                    state: SlotState::Idle,
                });
                match &mut slot.state {
                    SlotState::Here(value) => return Ok(value.clone()),
                    SlotState::Asked(waiters) => {
                        let (answer, waiting) = tokio::sync::oneshot::channel();
                        waiters.push(answer);
                        Some(waiting)
                    }
                    SlotState::Idle => {
                        slot.state = SlotState::Asked(Vec::new());
                        None
                    }
                }
            };
            let Some(waiting) = waiting else {
                let mut asking = Asking {
                    slices: self,
                    key: key.clone(),
                    done: false,
                };
                let answer = ask.as_mut().await;
                asking.done = true;
                return match answer {
                    Ok(value) => {
                        let value = Arc::new(value);
                        self.settle(key, Some(value.clone()));
                        Ok(value)
                    }
                    Err(error) => {
                        self.settle(key, None);
                        Err(error)
                    }
                };
            };
            // The other fetch's request failed or was given up: ask.
            if let Ok(Some(value)) = waiting.await {
                return Ok(value);
            }
        }
    }
}

/// The chunks of objects asked of the other side of a stream by
/// `ObjectWant`, and those yet to ask (units.md, "Sync", objects). A
/// chunk asked for is awaited until it arrives; an answer to a chunk not
/// awaited is not taken.
#[derive(Debug, Clone, Default)]
pub(crate) struct Asks {
    objects: BTreeMap<Locator, Asked>,
}

#[derive(Debug, Clone, Default)]
struct Asked {
    /// The chunks asked for and not yet arrived.
    awaited: BTreeSet<u64>,
    /// The chunks to ask for once those awaited arrived, in order.
    later: VecDeque<Range<u64>>,
    /// The object's chunk count, once a header is held or arrived.
    count: Option<u64>,
    /// How many times in a row, with no chunk of the object kept
    /// between, a chunk was asked for again or those awaited were given
    /// up for want of an answer.
    again: u32,
    /// How long chunks have been awaited with nothing asked for arriving
    /// on the session.
    idle: Duration,
}

/// How many times in a row chunks of one object are asked for again on a
/// stream with none of it kept, before the object is asked for no
/// further.
const ASK_AGAIN: u32 = 8;

/// How long chunks asked for on a stream are awaited while nothing asked
/// for arrives on the session, before they are given up and asked for
/// again: the other side sends nothing for a chunk past the object's end,
/// and nothing says so. A session hears of a chunk only once all of it
/// arrived, so the wait is long enough for one sealed chunk, about a
/// mebibyte, on a link of 70 kbit/s, and a chunk of any object the
/// session asked for starts it over, since the other side answers what it
/// was asked in turn.
pub(crate) const AWAIT_MOST: Duration = Duration::from_secs(120);

/// How often a connection tells its sessions of the time passed
/// ([`Asks::waited`]).
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) const AWAIT_TICK: Duration = Duration::from_secs(5);

/// How many chunks in a row a range with no known end is searched for one
/// to ask for, before the rest of it is left.
const SEARCH: u64 = 4096;

/// An `ObjectWant`'s fields: the first chunk and the count.
pub(crate) type Want = (u64, u64);

impl Asks {
    /// Whether any chunk of the object is awaited or yet to ask.
    pub(crate) fn has(&self, locator: &Locator) -> bool {
        self.objects.contains_key(locator)
    }

    /// Whether a chunk was asked for and has not arrived.
    pub(crate) fn awaits(&self, locator: &Locator, index: u64) -> bool {
        self.objects
            .get(locator)
            .is_some_and(|asked| asked.awaited.contains(&index))
    }

    /// Forgets an object: nothing of it is awaited.
    pub(crate) fn forget(&mut self, locator: &Locator) {
        self.objects.remove(locator);
    }

    /// Wants the chunks `chunks` of an object: the `ObjectWant`s to send
    /// now. `count` is the object's chunk count when the device holds its
    /// header, and `skip` says which chunks are not to be asked for:
    /// those the device holds, and those nobody wants any more. With
    /// `at_once`, the first chunks neither left out nor awaited are asked
    /// for now, as a reader's position needs, at most [`CHUNKS_PER_WANT`]
    /// of them. The rest is asked for `batch` chunks at a time, each
    /// batch once nothing is awaited.
    pub(crate) fn want(
        &mut self,
        locator: Locator,
        chunks: Range<u64>,
        at_once: bool,
        batch: u64,
        count: Option<u64>,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<Want> {
        let asked = self.objects.entry(locator).or_default();
        if let Some(count) = count {
            asked.learn(count);
        }
        let end = asked
            .count
            .map_or(chunks.end, |count| chunks.end.min(count));
        let mut rest = chunks.start..end;
        let mut wants = Vec::new();
        if at_once {
            let (now, reached) = asked.take(rest.clone(), CHUNKS_PER_WANT, &skip);
            wants = now;
            rest = reached..end;
        }
        // What is awaited, or left for later already, is not noted twice.
        while rest.start < rest.end && asked.awaited.contains(&rest.start) {
            rest.start += 1;
        }
        let noted = asked
            .later
            .iter()
            .any(|later| later.start <= rest.start && rest.end <= later.end);
        if !rest.is_empty() && !noted {
            asked.later.push_back(rest);
        }
        if asked.awaited.is_empty() {
            wants.extend(asked.next_batch(batch, &skip));
        }
        self.drop_idle(&locator);
        wants
    }

    /// A chunk arrived: whether it was awaited, and the `ObjectWant`s for
    /// the next batch, once none is awaited. `count` is the object's
    /// chunk count when the chunk carries a header or the device holds
    /// one, and `kept` says whether the device kept the chunk: one
    /// awaited and kept shows that the other side serves the object, so
    /// that what was asked for again before counts no longer.
    pub(crate) fn arrived(
        &mut self,
        locator: &Locator,
        index: u64,
        count: Option<u64>,
        kept: bool,
        skip: impl Fn(u64) -> bool,
    ) -> (bool, Vec<Want>) {
        let Some(asked) = self.objects.get_mut(locator) else {
            return (false, Vec::new());
        };
        if let Some(count) = count {
            asked.learn(count);
        }
        let awaited = asked.awaited.remove(&index);
        if awaited && kept {
            asked.again = 0;
        }
        let wants = if awaited && asked.awaited.is_empty() {
            asked.next_batch(CHUNKS_PER_WANT, &skip)
        } else {
            Vec::new()
        };
        self.drop_idle(locator);
        if awaited {
            self.heard();
        }
        (awaited, wants)
    }

    /// A chunk awaited arrived and was not kept: it is asked for again
    /// with the next batch, whose `ObjectWant`s these are once nothing
    /// else is awaited. [`ASK_AGAIN`] times in a row for one object, so
    /// that a side whose answers are never kept is not asked without
    /// end: after that the object is asked for no further, which `true`
    /// says.
    pub(crate) fn again(
        &mut self,
        locator: &Locator,
        index: u64,
        skip: impl Fn(u64) -> bool,
    ) -> (Vec<Want>, bool) {
        let Some(asked) = self.objects.get_mut(locator) else {
            return (Vec::new(), false);
        };
        if !asked.awaited.remove(&index) {
            return (Vec::new(), false);
        }
        asked.again = asked.again.saturating_add(1);
        if asked.again > ASK_AGAIN {
            self.objects.remove(locator);
            self.heard();
            return (Vec::new(), true);
        }
        asked.put_back(index);
        let wants = if asked.awaited.is_empty() {
            asked.next_batch(CHUNKS_PER_WANT, &skip)
        } else {
            Vec::new()
        };
        self.drop_idle(locator);
        self.heard();
        (wants, false)
    }

    /// Something asked for arrived on the session: the other side
    /// answers, and the wait for each object's chunks starts over.
    fn heard(&mut self) {
        for asked in self.objects.values_mut() {
            asked.idle = Duration::ZERO;
        }
    }

    /// The objects with chunks awaited or yet to ask for.
    pub(crate) fn objects(&self) -> Vec<Locator> {
        self.objects.keys().copied().collect()
    }

    /// Time passed with nothing asked for arriving on the session: the
    /// `ObjectWant`s that follow for an object. `count` is the object's
    /// chunk count when the device holds its header by now, from this
    /// side or another: no chunk past it is awaited any longer. Chunks
    /// awaited for [`AWAIT_MOST`] are given up and put back among those
    /// yet to ask for, so that they are asked for again with the rest.
    /// An object whose chunks were given up, or asked for again,
    /// [`ASK_AGAIN`] times in a row with none of it kept is asked for no
    /// further, which `true` says.
    pub(crate) fn waited(
        &mut self,
        locator: &Locator,
        elapsed: Duration,
        count: Option<u64>,
        skip: impl Fn(u64) -> bool,
    ) -> (Vec<Want>, bool) {
        let Some(asked) = self.objects.get_mut(locator) else {
            return (Vec::new(), false);
        };
        if let Some(count) = count {
            asked.learn(count);
        }
        if !asked.awaited.is_empty() {
            asked.idle = asked.idle.saturating_add(elapsed);
            if asked.idle < AWAIT_MOST {
                return (Vec::new(), false);
            }
            asked.again = asked.again.saturating_add(1);
            if asked.again > ASK_AGAIN {
                self.objects.remove(locator);
                return (Vec::new(), true);
            }
            // From the last, so that a run of them joins the range it
            // was taken from.
            for index in std::mem::take(&mut asked.awaited).into_iter().rev() {
                asked.put_back(index);
            }
        }
        asked.idle = Duration::ZERO;
        let wants = asked.next_batch(CHUNKS_PER_WANT, &skip);
        self.drop_idle(locator);
        (wants, false)
    }

    fn drop_idle(&mut self, locator: &Locator) {
        if self
            .objects
            .get(locator)
            .is_some_and(|asked| asked.awaited.is_empty() && asked.later.is_empty())
        {
            self.objects.remove(locator);
        }
    }
}

impl Asked {
    /// The object has `count` chunks: none past them is awaited or asked.
    fn learn(&mut self, count: u64) {
        self.count = Some(count);
        self.awaited.retain(|index| *index < count);
        for later in &mut self.later {
            later.end = later.end.min(count);
        }
        self.later.retain(|later| !later.is_empty());
    }

    /// Puts a chunk no longer awaited back among those yet to ask for,
    /// in the order of their indices: into a range that holds it or ends
    /// beside it, or else before the first range after it.
    fn put_back(&mut self, index: u64) {
        if self.count.is_some_and(|count| index >= count)
            || self.later.iter().any(|later| later.contains(&index))
        {
            return;
        }
        let after = index.saturating_add(1);
        if let Some(later) = self.later.iter_mut().find(|later| later.start == after) {
            later.start = index;
            return;
        }
        if let Some(later) = self.later.iter_mut().find(|later| later.end == index) {
            later.end = after;
            return;
        }
        let at = self
            .later
            .iter()
            .position(|later| later.start > index)
            .unwrap_or(self.later.len());
        self.later.insert(at, index..after);
    }

    /// Awaits the first chunks of `chunks` that are neither awaited nor
    /// left out by `skip`, at most `most` of them: one `ObjectWant` for
    /// each run of them, and the chunk reached.
    fn take(
        &mut self,
        chunks: Range<u64>,
        most: u64,
        skip: &impl Fn(u64) -> bool,
    ) -> (Vec<Want>, u64) {
        let mut wants = Vec::new();
        let mut taken = 0;
        let mut passed = 0;
        let mut at = chunks.start;
        while at < chunks.end && taken < most {
            if self.awaited.contains(&at) || skip(at) {
                at = at.saturating_add(1);
                passed += 1;
                // A range to an end not yet known, of which nothing is
                // wanted any more.
                if self.count.is_none() && passed > SEARCH {
                    at = chunks.end;
                }
                continue;
            }
            passed = 0;
            let first = at;
            while at < chunks.end
                && taken < most
                && at - first < CHUNKS_PER_WANT
                && !self.awaited.contains(&at)
                && !skip(at)
            {
                at = at.saturating_add(1);
                taken += 1;
            }
            wants.push((first, at - first));
        }
        for (first, count) in &wants {
            self.awaited.extend(*first..first.saturating_add(*count));
        }
        if !wants.is_empty() {
            // The wait for an answer starts with the latest ask.
            self.idle = Duration::ZERO;
        }
        (wants, at)
    }

    /// The next chunks to ask for of those left for later, at most
    /// `batch`.
    fn next_batch(&mut self, batch: u64, skip: &impl Fn(u64) -> bool) -> Vec<Want> {
        let mut wants = Vec::new();
        let mut left = batch;
        while left > 0 {
            let Some(later) = self.later.pop_front() else {
                break;
            };
            let (now, reached) = self.take(later.clone(), left, skip);
            left -= now.iter().map(|(_, count)| count).sum::<u64>().min(left);
            wants.extend(now);
            if reached < later.end {
                self.later.push_front(reached..later.end);
                break;
            }
        }
        wants
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Asks, CHUNKS_PER_WANT, Cancel, FetchEnd, FetchPriority, Queue, Request, Requests, Slices,
    };
    use frasil_events::EventId;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SPACE: EventId = EventId([1; 32]);

    fn request(id: u64, priority: FetchPriority) -> Request {
        Request {
            id,
            space: SPACE,
            locator: [2; 64],
            chunks: 0..1,
            priority,
            cancel: Cancel::new(),
            stores: true,
            ended: Arc::new(tokio::sync::watch::channel(None).0),
        }
    }

    /// A reader's position goes before its read-ahead, and both before
    /// background fetches; those of one priority go in the order taken.
    #[test]
    fn the_most_urgent_request_goes_first() {
        let mut queue = Queue::default();
        queue.push(request(1, FetchPriority::Background));
        queue.push(request(2, FetchPriority::ReadAhead));
        queue.push(request(3, FetchPriority::Background));
        queue.push(request(4, FetchPriority::Position));
        queue.push(request(5, FetchPriority::ReadAhead));
        queue.push(request(6, FetchPriority::Position));
        assert_eq!(queue.most_urgent(), Some(FetchPriority::Position));
        let order: Vec<u64> = std::iter::from_fn(|| queue.pop())
            .map(|request| request.id)
            .collect();
        assert_eq!(order, vec![4, 6, 2, 5, 1, 3]);
        assert!(queue.is_empty());
    }

    /// A request cancelled while it waits is never served.
    #[test]
    fn a_cancelled_request_leaves_the_queue() {
        let mut queue = Queue::default();
        let first = request(1, FetchPriority::Position);
        let cancel = first.cancel.clone();
        queue.push(first);
        queue.push(request(2, FetchPriority::Background));
        cancel.cancel();
        assert_eq!(queue.most_urgent(), Some(FetchPriority::Background));
        assert_eq!(queue.pop().map(|request| request.id), Some(2));
        assert_eq!(queue.most_urgent(), None);
        assert!(queue.pop().is_none());
        assert!(queue.is_empty());
    }

    /// A request is wanted while its handle is held, and a cancel is heard
    /// by whoever waits for it.
    #[tokio::test]
    async fn a_request_is_wanted_until_cancelled_or_dropped() {
        let requests = Arc::new(Requests::default());
        let mut follow = requests.follow();
        let fetch = requests.add(SPACE, [2; 64], 3..5, FetchPriority::Position);
        assert!(follow.has_changed().unwrap());
        follow.mark_unchanged();
        let listed = requests.of(&SPACE);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].chunks, 3..5);
        assert_eq!(listed[0].priority, FetchPriority::Position);
        assert!(requests.wants(&SPACE, &[2; 64], 4));
        assert!(!requests.wants(&SPACE, &[2; 64], 5));
        assert!(!requests.wants(&SPACE, &[2; 64], 0));
        assert!(requests.reaches(&SPACE, &[2; 64], 0));
        assert!(requests.reaches(&SPACE, &[2; 64], 4));
        assert!(!requests.reaches(&SPACE, &[2; 64], 5));
        assert!(!requests.wants(&EventId([9; 32]), &[2; 64], 4));
        let heard = listed[0].cancel.clone();
        let waiting = tokio::spawn(async move { heard.cancelled().await });
        fetch.cancel();
        waiting.await.unwrap();
        assert!(fetch.is_cancelled());
        assert!(follow.has_changed().unwrap());
        assert!(requests.of(&SPACE).is_empty());
        assert!(!requests.wants(&SPACE, &[2; 64], 4));
        // Dropped: cancelled as well.
        let fetch = requests.add(SPACE, [2; 64], 0..1, FetchPriority::Background);
        let cancel = requests.of(&SPACE)[0].cancel.clone();
        drop(fetch);
        assert!(cancel.is_cancelled());
        assert!(requests.of(&SPACE).is_empty());
        // A signal given before anyone waits is heard at once.
        cancel.cancelled().await;
    }

    /// A request whose fetch stopped waits longer each time, to a bound.
    #[test]
    fn a_stopped_request_waits_longer_each_time_to_a_bound() {
        use std::time::Duration;
        assert_eq!(super::again_after(0), Duration::from_millis(500));
        assert_eq!(super::again_after(1), Duration::from_secs(1));
        assert_eq!(super::again_after(5), Duration::from_secs(16));
        assert_eq!(super::again_after(6), Duration::from_secs(30));
        assert_eq!(super::again_after(64), Duration::from_secs(30));
        assert_eq!(super::again_after(u32::MAX), Duration::from_secs(30));
    }

    /// A request the space's one connection gives up for good tells its
    /// holder why, no other request hears of it, and a request made
    /// afterwards for the object hears it at once.
    #[tokio::test]
    async fn a_request_given_up_tells_its_holder_why() {
        let requests = Arc::new(Requests::default());
        let taker = requests.attach(SPACE);
        let fetch = requests.add(SPACE, [2; 64], 0..4, FetchPriority::Position);
        let other = requests.add(SPACE, [3; 64], 0..4, FetchPriority::Position);
        assert_eq!(fetch.end(), None);
        let waiting = async {
            tokio::task::yield_now().await;
            taker.give_up(&[2; 64], FetchEnd::Refused);
        };
        let (end, ()) = tokio::join!(fetch.ended(), waiting);
        assert_eq!(end, FetchEnd::Refused);
        assert_eq!(fetch.end(), Some(FetchEnd::Refused));
        assert_eq!(other.end(), None);
        // The request stays wanted: a connection made later may serve it.
        assert!(!fetch.is_cancelled());
        assert_eq!(requests.of(&SPACE).len(), 2);
        taker.give_up(&[2; 64], FetchEnd::Malformed);
        assert_eq!(fetch.ended().await, FetchEnd::Malformed);
        // Made after the connection gave the object up.
        let later = requests.add(SPACE, [2; 64], 0..1, FetchPriority::Background);
        assert_eq!(later.ended().await, FetchEnd::Malformed);
        // Another space's requests hear nothing of it.
        let elsewhere = requests.add(EventId([9; 32]), [2; 64], 0..1, FetchPriority::Position);
        assert_eq!(elsewhere.end(), None);
        // The connection gone, nobody has given the object up.
        drop(taker);
        let after = requests.add(SPACE, [2; 64], 0..1, FetchPriority::Background);
        assert_eq!(after.end(), None);
    }

    /// While another connection of the space will still try, a request
    /// hears of no end: it hears once each connection gave the object
    /// up, or the last that had not is gone.
    #[tokio::test]
    async fn a_request_hears_no_end_while_another_connection_will_try() {
        let requests = Arc::new(Requests::default());
        let first = requests.attach(SPACE);
        let second = requests.attach(SPACE);
        let elsewhere = requests.attach(EventId([9; 32]));
        let fetch = requests.add(SPACE, [2; 64], 0..4, FetchPriority::Position);
        first.give_up(&[2; 64], FetchEnd::Refused);
        assert_eq!(fetch.end(), None);
        let later = requests.add(SPACE, [2; 64], 4..5, FetchPriority::Position);
        assert_eq!(later.end(), None);
        second.give_up(&[2; 64], FetchEnd::Malformed);
        assert_eq!(fetch.ended().await, FetchEnd::Malformed);
        assert_eq!(later.ended().await, FetchEnd::Malformed);

        // The connection that would have tried goes: those that stay
        // gave the object up.
        let other = requests.add(SPACE, [3; 64], 0..1, FetchPriority::Position);
        first.give_up(&[3; 64], FetchEnd::Refused);
        assert_eq!(other.end(), None);
        drop(second);
        assert_eq!(other.ended().await, FetchEnd::Refused);

        // Chunks left unserved are told of when no other connection will
        // try, and the object is not given up: a later request waits.
        let third = requests.attach(SPACE);
        let unserved = requests.add(SPACE, [4; 64], 0..1, FetchPriority::Position);
        third.unserved(&[4; 64]);
        assert_eq!(unserved.end(), None, "the first connection will try");
        first.give_up(&[4; 64], FetchEnd::Refused);
        assert_eq!(unserved.end(), None, "the third has not given it up");
        third.unserved(&[4; 64]);
        assert_eq!(unserved.ended().await, FetchEnd::Unserved);
        drop(first);
        third.unserved(&[5; 64]);
        let again = requests.add(SPACE, [5; 64], 0..1, FetchPriority::Position);
        assert_eq!(again.end(), None);
        third.unserved(&[5; 64]);
        assert_eq!(again.ended().await, FetchEnd::Unserved);
        drop(elsewhere);
    }

    /// Chunks left unserved while a connection is being made are told of
    /// once that connection is not made after all, and not while it may
    /// still serve them.
    #[tokio::test]
    async fn chunks_left_unserved_while_a_connection_is_expected_are_told_of_after() {
        let requests = Arc::new(Requests::default());
        let taker = requests.attach(SPACE);
        let expected = requests.expect(SPACE);
        let fetch = requests.add(SPACE, [2; 64], 0..1, FetchPriority::Position);
        taker.unserved(&[2; 64]);
        assert_eq!(fetch.end(), None, "a connection is being made");
        drop(expected);
        assert_eq!(fetch.ended().await, FetchEnd::Unserved);
        // A request made afterwards is asked for again.
        let later = requests.add(SPACE, [2; 64], 0..1, FetchPriority::Position);
        assert_eq!(later.end(), None);

        // The connection is made, and takes the requests: it will try.
        let expected = requests.expect(SPACE);
        let other = requests.add(SPACE, [3; 64], 0..1, FetchPriority::Position);
        taker.unserved(&[3; 64]);
        let second = requests.attach(SPACE);
        drop(expected);
        assert_eq!(other.end(), None, "the second connection will try");
        second.unserved(&[3; 64]);
        assert_eq!(other.ended().await, FetchEnd::Unserved);
    }

    /// Two fetches that need one slice ask for it once, and it goes once
    /// both took it.
    #[tokio::test]
    async fn a_slice_two_fetches_need_is_asked_for_once() {
        let slices: Arc<Slices<u64, Vec<u8>>> = Arc::default();
        let asked = Arc::new(AtomicUsize::new(0));
        slices.claim(6);
        slices.claim(6);
        let ask = |asked: Arc<AtomicUsize>| async move {
            asked.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok::<_, ()>(vec![6])
        };
        let (first, second) = tokio::join!(
            slices.get(&6, ask(asked.clone())),
            slices.get(&6, ask(asked.clone()))
        );
        assert_eq!(*first.unwrap(), vec![6]);
        assert_eq!(*second.unwrap(), vec![6]);
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // Held for the second fetch once the first took it.
        slices.release(&6);
        assert_eq!(slices.len(), 1);
        let again = slices.get(&6, ask(asked.clone())).await.unwrap();
        assert_eq!(*again, vec![6]);
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        slices.release(&6);
        assert_eq!(slices.len(), 0);
        // Claimed by nobody, a slice is not kept.
        slices.get(&7, ask(asked.clone())).await.unwrap();
        assert_eq!(slices.len(), 0);
    }

    /// A request for a slice that fails, or is given up part way, leaves
    /// the slice to the fetch that waits for it.
    #[tokio::test]
    async fn a_slice_whose_request_fails_is_asked_for_again() {
        let slices: Arc<Slices<u64, Vec<u8>>> = Arc::default();
        slices.claim(1);
        slices.claim(1);
        let failing = slices.get(&1, async {
            tokio::task::yield_now().await;
            Err::<Vec<u8>, _>("cut")
        });
        let waiting = slices.get(&1, async { Ok::<_, &str>(vec![1]) });
        let (failed, waited) = tokio::join!(failing, waiting);
        assert_eq!(failed.unwrap_err(), "cut");
        assert_eq!(*waited.unwrap(), vec![1]);
        slices.release(&1);
        slices.release(&1);
        assert_eq!(slices.len(), 0);
        // Given up before its answer: the next fetch asks.
        slices.claim(2);
        {
            let given_up = slices.get(&2, std::future::pending::<Result<Vec<u8>, ()>>());
            let mut given_up = std::pin::pin!(given_up);
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                std::future::Future::poll(given_up.as_mut(), &mut context).is_pending(),
                "the request is under way"
            );
        }
        let value = slices.get(&2, async { Ok::<_, ()>(vec![2]) }).await;
        assert_eq!(*value.unwrap(), vec![2]);
    }

    /// A whole object is asked for a batch at a time from chunk 0, and
    /// the next batch once the last chunk awaited arrived.
    #[test]
    fn an_object_is_asked_for_a_batch_at_a_time() {
        let mut asks = Asks::default();
        let locator = [3; 64];
        let wants = asks.want(locator, 0..u64::MAX, false, CHUNKS_PER_WANT, None, |_| {
            false
        });
        assert_eq!(wants, vec![(0, 64)]);
        // Asked for already: nothing more.
        assert!(
            asks.want(locator, 0..u64::MAX, false, CHUNKS_PER_WANT, None, |_| {
                false
            })
            .is_empty()
        );
        // Chunk 0 carries the header: 100 chunks.
        let (awaited, wants) = asks.arrived(&locator, 0, Some(100), true, |_| false);
        assert!(awaited && wants.is_empty());
        for index in 1..63 {
            let (awaited, wants) = asks.arrived(&locator, index, None, true, |_| false);
            assert!(awaited && wants.is_empty(), "{index}");
        }
        let (awaited, wants) = asks.arrived(&locator, 63, None, true, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(64, 36)]);
        // A chunk nobody awaits is not taken.
        assert_eq!(
            asks.arrived(&locator, 63, None, true, |_| false),
            (false, vec![])
        );
        assert_eq!(
            asks.arrived(&locator, 200, None, true, |_| false),
            (false, vec![])
        );
        for index in 64..100 {
            assert!(asks.arrived(&locator, index, None, true, |_| false).0);
        }
        assert!(!asks.has(&locator));
    }

    /// An object shorter than a batch awaits no chunk past its count once
    /// the header says so, and a first chunk asked for alone, for its
    /// header, is followed by the rest.
    #[test]
    fn a_short_object_awaits_no_chunk_past_its_count() {
        let mut asks = Asks::default();
        let locator = [3; 64];
        assert_eq!(
            asks.want(locator, 0..u64::MAX, false, 1, None, |_| false),
            vec![(0, 1)]
        );
        let (awaited, wants) = asks.arrived(&locator, 0, Some(3), true, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(1, 2)]);
        assert!(asks.arrived(&locator, 1, None, true, |_| false).0);
        assert!(asks.arrived(&locator, 2, None, true, |_| false).0);
        assert!(!asks.has(&locator));
        // A whole batch asked of an object of two chunks.
        let other = [4; 64];
        asks.want(other, 0..u64::MAX, false, CHUNKS_PER_WANT, None, |_| false);
        assert!(asks.awaits(&other, 40));
        assert!(asks.arrived(&other, 0, Some(2), true, |_| false).0);
        assert!(!asks.awaits(&other, 40));
        assert!(asks.arrived(&other, 1, None, true, |_| false).0);
        assert!(!asks.has(&other));
    }

    /// A reader's chunks are asked for at once from any index, beside a
    /// batch under way, leaving out what is held or awaited; a batch
    /// leaves out what is held too.
    #[test]
    fn chunks_are_asked_for_from_any_index() {
        let mut asks = Asks::default();
        let locator = [3; 64];
        let count = Some(400);
        assert_eq!(
            asks.want(locator, 0..u64::MAX, false, 4, count, |_| false),
            vec![(0, 4)]
        );
        // A position ahead of the batch: asked for now, less what is held.
        let wants = asks.want(locator, 10..14, true, CHUNKS_PER_WANT, count, |index| {
            index == 11
        });
        assert_eq!(wants, vec![(10, 1), (12, 2)]);
        assert!(asks.awaits(&locator, 12));
        assert!(!asks.awaits(&locator, 11));
        // Awaited already: not asked for twice.
        assert!(
            asks.want(locator, 2..4, true, CHUNKS_PER_WANT, count, |_| false)
                .is_empty()
        );
        // At most one want's worth at once; the rest goes with the batches.
        let wants = asks.want(locator, 100..230, true, CHUNKS_PER_WANT, count, |_| false);
        assert_eq!(wants, vec![(100, 64)]);
        // The batch ends: the next one leaves out the chunks held.
        let held = |index: u64| (10..14).contains(&index) || index == 5;
        for index in [0, 1, 2] {
            assert!(asks.arrived(&locator, index, None, true, held).1.is_empty());
        }
        for index in (10..14).chain(100..164).filter(|index| *index != 11) {
            assert!(asks.arrived(&locator, index, None, true, held).0);
        }
        let (awaited, wants) = asks.arrived(&locator, 3, Some(40), true, held);
        assert!(awaited);
        assert_eq!(wants, vec![(4, 1), (6, 4), (14, 26)]);
    }

    /// A range to an end not yet known, of which nothing is wanted any
    /// more, is left: no chunk of it is asked for, and none awaited.
    #[test]
    fn a_range_nobody_wants_is_left() {
        let mut asks = Asks::default();
        let wants = asks.want([4; 64], 0..u64::MAX, true, CHUNKS_PER_WANT, None, |_| true);
        assert!(wants.is_empty());
        assert!(!asks.has(&[4; 64]));
        // The chunks still wanted of a range are asked for, and no other.
        let wants = asks.want([3; 64], 5..9, true, CHUNKS_PER_WANT, None, |index| {
            index != 6
        });
        assert_eq!(wants, vec![(6, 1)]);
    }

    /// Chunks asked for past the end of an object, of which no header is
    /// held, get no answer: once the header is held by another route
    /// they are awaited no longer, and without one they are given up
    /// after a wait and asked for again with what is yet to ask for.
    #[test]
    fn chunks_past_the_end_do_not_hold_up_the_object() {
        use super::AWAIT_MOST;
        use std::time::Duration;
        let tick = Duration::from_secs(5);
        let locator = [3; 64];
        // The header arrives by another route.
        let mut asks = Asks::default();
        assert_eq!(
            asks.want(locator, 10..20, true, CHUNKS_PER_WANT, None, |_| false),
            vec![(10, 10)]
        );
        assert!(
            asks.want(locator, 0..u64::MAX, false, CHUNKS_PER_WANT, None, |_| {
                false
            })
            .is_empty(),
            "the batch waits for the chunks awaited"
        );
        assert!(asks.waited(&locator, tick, None, |_| false).0.is_empty());
        assert_eq!(
            asks.waited(&locator, tick, Some(5), |_| false),
            (vec![(0, 5)], false)
        );
        assert!(!asks.awaits(&locator, 10));
        // No header by any route: given up after the wait, not before,
        // and asked for again behind the chunks before them.
        let mut asks = Asks::default();
        asks.want(locator, 10..20, true, CHUNKS_PER_WANT, None, |_| false);
        asks.want(locator, 0..2, false, CHUNKS_PER_WANT, None, |_| false);
        let mut waited = Duration::ZERO;
        let wants = loop {
            let (wants, ended) = asks.waited(&locator, tick, None, |_| false);
            assert!(!ended);
            waited += tick;
            if !wants.is_empty() {
                break wants;
            }
            assert!(waited < AWAIT_MOST, "{waited:?}");
        };
        assert_eq!(waited, AWAIT_MOST);
        assert_eq!(wants, vec![(0, 2), (10, 10)]);
        assert!(asks.awaits(&locator, 10));
        // An arrival starts the wait again, and its header ends the wait
        // for the chunks past the end.
        assert!(
            asks.waited(&locator, AWAIT_MOST - tick, None, |_| false)
                .0
                .is_empty()
        );
        assert!(asks.arrived(&locator, 0, Some(2), true, |_| false).0);
        assert!(!asks.awaits(&locator, 10));
        assert!(
            asks.waited(&locator, AWAIT_MOST - tick, None, |_| false)
                .0
                .is_empty()
        );
        assert!(asks.awaits(&locator, 1));
        assert!(asks.arrived(&locator, 1, None, true, |_| false).0);
        // Nothing awaited and nothing to ask for: forgotten.
        assert!(!asks.has(&locator));
        assert!(asks.objects().is_empty());
    }

    /// Chunks given up for want of an answer are asked for again, in the
    /// order of their indices, with what was yet to ask for.
    #[test]
    fn chunks_given_up_are_asked_for_again() {
        use super::AWAIT_MOST;
        let locator = [3; 64];
        let mut asks = Asks::default();
        let first = asks.want(locator, 0..u64::MAX, false, 4, Some(10), |_| false);
        assert_eq!(first, vec![(0, 4)]);
        // Chunks 0 and 2 arrive; 1 and 3 do not.
        assert!(asks.arrived(&locator, 0, None, true, |_| false).0);
        assert!(asks.arrived(&locator, 2, None, true, |_| false).0);
        let (wants, ended) = asks.waited(&locator, AWAIT_MOST, None, |_| false);
        assert!(!ended);
        assert_eq!(wants, vec![(1, 1), (3, 7)]);
        assert!(asks.awaits(&locator, 1) && asks.awaits(&locator, 9));
        // A chunk not kept goes back to its place too.
        let (wants, ended) = asks.again(&locator, 5, |_| false);
        assert!(wants.is_empty() && !ended);
        for index in [1, 3, 4, 6, 7, 8] {
            assert!(asks.arrived(&locator, index, None, true, |_| false).0);
        }
        let (awaited, wants) = asks.arrived(&locator, 9, None, true, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(5, 1)]);
    }

    /// A slow side is not given up: each chunk that is kept starts the
    /// count of the times its object was asked for again over, so that
    /// any number of waits across a download ends nothing.
    #[test]
    fn a_chunk_kept_starts_the_count_over() {
        use super::AWAIT_MOST;
        let locator = [3; 64];
        let mut asks = Asks::default();
        asks.want(locator, 0..u64::MAX, false, 1, Some(40), |_| false);
        for index in 0..40 {
            assert!(asks.awaits(&locator, index), "{index}");
            // The chunk takes longer than the wait: asked for again.
            let (wants, ended) = asks.waited(&locator, AWAIT_MOST, None, |_| false);
            assert!(!ended, "{index}");
            assert_eq!(wants.first(), Some(&(index, 40 - index)), "{index}");
            assert!(asks.arrived(&locator, index, None, true, |_| false).0);
        }
        // A chunk that arrives and is not kept does not start it over.
        let mut asks = Asks::default();
        asks.want(locator, 0..u64::MAX, false, 2, Some(40), |_| false);
        for round in 0..8 {
            assert!(!asks.waited(&locator, AWAIT_MOST, None, |_| false).1);
            assert!(
                asks.arrived(&locator, round, None, false, |_| false).0,
                "{round}"
            );
        }
        assert!(asks.waited(&locator, AWAIT_MOST, None, |_| false).1);
        assert!(!asks.has(&locator));
    }

    /// A chunk asked for that arrives starts the wait over for every
    /// object of the session: the other side answers in turn.
    #[test]
    fn an_arrival_starts_every_objects_wait_over() {
        use super::AWAIT_MOST;
        use std::time::Duration;
        let tick = Duration::from_secs(5);
        let (first, second) = ([3; 64], [4; 64]);
        let mut asks = Asks::default();
        asks.want(first, 0..4, true, CHUNKS_PER_WANT, Some(4), |_| false);
        asks.want(second, 0..4, true, CHUNKS_PER_WANT, Some(4), |_| false);
        // The first object's chunks arrive, each just within the wait.
        for index in 0..4 {
            for locator in [first, second] {
                let waited = asks.waited(&locator, AWAIT_MOST - tick, None, |_| false);
                assert_eq!(waited, (Vec::new(), false), "{index}");
            }
            assert!(asks.arrived(&first, index, None, true, |_| false).0);
        }
        assert!(!asks.has(&first));
        assert!(asks.awaits(&second, 0), "not given up meanwhile");
        // Nothing more arrives: the second is given up after the wait,
        // and asked for again.
        let waited = asks.waited(&second, AWAIT_MOST - tick, None, |_| false);
        assert_eq!(waited, (Vec::new(), false));
        assert_eq!(
            asks.waited(&second, tick, None, |_| false),
            (vec![(0, 4)], false)
        );
    }

    /// A side that answers nothing at all is asked a few times, and then
    /// no more, which the session hears.
    #[test]
    fn a_side_that_never_answers_is_not_asked_without_end() {
        use super::AWAIT_MOST;
        let locator = [3; 64];
        let mut asks = Asks::default();
        let first = asks.want(locator, 0..u64::MAX, false, 4, None, |_| false);
        assert_eq!(first, vec![(0, 4)]);
        let mut asked = 1;
        let mut ended = false;
        while asks.has(&locator) {
            assert!(!ended);
            let (wants, end) = asks.waited(&locator, AWAIT_MOST, None, |_| false);
            ended = end;
            if !wants.is_empty() {
                // The same chunks again, with those yet to ask for.
                assert_eq!(wants, vec![(0, 64)]);
                asked += 1;
            }
            assert!(asked < 100);
        }
        assert_eq!(asked, 9);
        assert!(ended);
    }

    /// A chunk that was not kept is asked for again with the next batch,
    /// a few times in a row and then no more, which the session hears.
    #[test]
    fn a_chunk_not_kept_is_asked_for_again() {
        let mut asks = Asks::default();
        let locator = [3; 64];
        assert_eq!(
            asks.want(locator, 4..6, true, 64, Some(9), |_| false),
            vec![(4, 2)]
        );
        assert_eq!(asks.again(&locator, 4, |_| false), (Vec::new(), false));
        assert!(!asks.awaits(&locator, 4));
        // Not awaited: nothing to ask for again.
        assert_eq!(asks.again(&locator, 4, |_| false), (Vec::new(), false));
        let (awaited, wants) = asks.arrived(&locator, 5, None, false, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(4, 1)]);
        for _ in 0..7 {
            assert_eq!(asks.again(&locator, 4, |_| false), (vec![(4, 1)], false));
        }
        assert_eq!(asks.again(&locator, 4, |_| false), (Vec::new(), true));
        assert!(!asks.has(&locator));
        asks.want(locator, 0..2, true, 64, None, |_| false);
        asks.forget(&locator);
        assert!(!asks.has(&locator));
    }
}
