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
//! arrives.
//!
//! A fetch changes nothing of what is checked: every chunk passes
//! [`Engine::receive_part`](crate::device::Engine) before it is kept, and
//! an object these chunks make whole is checked against its locator's
//! digest there.

use frasil_adapter::Locator;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
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
    /// dropped.
    pub(crate) fn add(
        self: &Arc<Self>,
        space: EventId,
        locator: Locator,
        chunks: Range<u64>,
        priority: FetchPriority,
    ) -> Fetch {
        let cancel = Cancel::new();
        let id = {
            let mut live = self.live();
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
                },
            );
            id
        };
        self.changed.send_modify(|count| *count += 1);
        Fetch {
            id,
            cancel,
            requests: self.clone(),
        }
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

    /// Whether a request is still wanted, by its number.
    pub(crate) fn is_live(&self, id: u64) -> bool {
        self.live().requests.contains_key(&id)
    }

    /// Follows the requests: the receiver changes when one is made or
    /// ends.
    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn end(&self, id: u64) {
        if self.live().requests.remove(&id).is_some() {
            self.changed.send_modify(|count| *count += 1);
        }
    }
}

/// A request for chunks of an object, wanted while this is held: dropping
/// it cancels the request.
#[derive(Debug)]
pub struct Fetch {
    id: u64,
    cancel: Cancel,
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
    /// How many chunks were asked for again.
    again: u32,
}

/// How many chunks of one object are asked for again on a stream.
const ASK_AGAIN: u32 = 8;

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
    /// one.
    pub(crate) fn arrived(
        &mut self,
        locator: &Locator,
        index: u64,
        count: Option<u64>,
        skip: impl Fn(u64) -> bool,
    ) -> (bool, Vec<Want>) {
        let Some(asked) = self.objects.get_mut(locator) else {
            return (false, Vec::new());
        };
        if let Some(count) = count {
            asked.learn(count);
        }
        let awaited = asked.awaited.remove(&index);
        let wants = if awaited && asked.awaited.is_empty() {
            asked.next_batch(CHUNKS_PER_WANT, &skip)
        } else {
            Vec::new()
        };
        self.drop_idle(locator);
        (awaited, wants)
    }

    /// A chunk awaited arrived and was not kept: it is asked for again
    /// with the next batch, whose `ObjectWant`s these are once nothing
    /// else is awaited. A few times for one object, so that a side whose
    /// answers are never kept is not asked without end.
    pub(crate) fn again(
        &mut self,
        locator: &Locator,
        index: u64,
        skip: impl Fn(u64) -> bool,
    ) -> Vec<Want> {
        let Some(asked) = self.objects.get_mut(locator) else {
            return Vec::new();
        };
        if !asked.awaited.remove(&index) {
            return Vec::new();
        }
        if asked.again < ASK_AGAIN {
            asked.again += 1;
            asked.later.push_front(index..index.saturating_add(1));
        }
        let wants = if asked.awaited.is_empty() {
            asked.next_batch(CHUNKS_PER_WANT, &skip)
        } else {
            Vec::new()
        };
        self.drop_idle(locator);
        wants
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
    use super::{Asks, CHUNKS_PER_WANT, Cancel, FetchPriority, Queue, Request, Requests, Slices};
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
        assert_eq!(queue.pop().map(|request| request.id), Some(2));
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
        let (awaited, wants) = asks.arrived(&locator, 0, Some(100), |_| false);
        assert!(awaited && wants.is_empty());
        for index in 1..63 {
            let (awaited, wants) = asks.arrived(&locator, index, None, |_| false);
            assert!(awaited && wants.is_empty(), "{index}");
        }
        let (awaited, wants) = asks.arrived(&locator, 63, None, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(64, 36)]);
        // A chunk nobody awaits is not taken.
        assert_eq!(asks.arrived(&locator, 63, None, |_| false), (false, vec![]));
        assert_eq!(
            asks.arrived(&locator, 200, None, |_| false),
            (false, vec![])
        );
        for index in 64..100 {
            assert!(asks.arrived(&locator, index, None, |_| false).0);
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
        let (awaited, wants) = asks.arrived(&locator, 0, Some(3), |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(1, 2)]);
        assert!(asks.arrived(&locator, 1, None, |_| false).0);
        assert!(asks.arrived(&locator, 2, None, |_| false).0);
        assert!(!asks.has(&locator));
        // A whole batch asked of an object of two chunks.
        let other = [4; 64];
        asks.want(other, 0..u64::MAX, false, CHUNKS_PER_WANT, None, |_| false);
        assert!(asks.awaits(&other, 40));
        assert!(asks.arrived(&other, 0, Some(2), |_| false).0);
        assert!(!asks.awaits(&other, 40));
        assert!(asks.arrived(&other, 1, None, |_| false).0);
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
            assert!(asks.arrived(&locator, index, None, held).1.is_empty());
        }
        for index in (10..14).chain(100..164).filter(|index| *index != 11) {
            assert!(asks.arrived(&locator, index, None, held).0);
        }
        let (awaited, wants) = asks.arrived(&locator, 3, Some(40), held);
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

    /// A chunk that was not kept is asked for again with the next batch,
    /// a few times and then no more.
    #[test]
    fn a_chunk_not_kept_is_asked_for_again() {
        let mut asks = Asks::default();
        let locator = [3; 64];
        assert_eq!(
            asks.want(locator, 4..6, true, 64, Some(9), |_| false),
            vec![(4, 2)]
        );
        assert!(asks.again(&locator, 4, |_| false).is_empty());
        assert!(!asks.awaits(&locator, 4));
        // Not awaited: nothing to ask for again.
        assert!(asks.again(&locator, 4, |_| false).is_empty());
        let (awaited, wants) = asks.arrived(&locator, 5, None, |_| false);
        assert!(awaited);
        assert_eq!(wants, vec![(4, 1)]);
        for _ in 0..7 {
            assert_eq!(asks.again(&locator, 4, |_| false), vec![(4, 1)]);
        }
        assert!(asks.again(&locator, 4, |_| false).is_empty());
        assert!(!asks.has(&locator));
        asks.want(locator, 0..2, true, 64, None, |_| false);
        asks.forget(&locator);
        assert!(!asks.has(&locator));
    }
}
