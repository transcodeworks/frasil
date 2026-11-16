//! Which spaces the peer hosts, and which of them are in memory.
//!
//! Each hosted space has a [`Slot`] while it is in use: a **gate** that its
//! writers hold, in turn, from their first check to the moment their
//! records are durable and applied, and its **state**, behind a lock of its
//! own that readers and writers hold only while they compute. Spaces
//! proceed in parallel; writers of one space take turns, and its readers
//! never wait for a commit.
//!
//! A space opens on first use: from its snapshot, its decoded state, and
//! the journal records after it (crate `records`), on a blocking thread. A
//! sweep closes a space that has been idle for
//! [`Settings::idle_close`](crate::Settings), with nothing waiting in it and
//! no connection on it; its rate windows stay while they count anything.
//! A sweep folds an open space's journal into a new snapshot when the
//! records after the snapshot have grown to half its size, and a close
//! whenever they hold anything, so that a space that closed opens again
//! from its snapshot alone, decoding no event. The peer
//! starts without opening any space: the index says what it hosts, and the
//! wait markers which spaces its first sweep must open.
//!
//! Locks are taken in one order: a space's gate, then its state, then any
//! of the peer's other locks, each held briefly. No code takes a space's
//! state while it holds another space's state or one of the other locks.

use crate::records::{Opened, Records, Snapshot};
use crate::space::{Rules, Space};
use crate::state::{Core, Window, lock};
use crate::util::log;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_store::StoreError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// The journal bytes after a snapshot below which the peer never folds.
const FOLD_MIN: u64 = 256 << 10;

/// A space's slot.
#[derive(Debug, Default)]
pub(crate) struct Slot {
    gate: Arc<tokio::sync::Mutex<()>>,
    state: Mutex<Resident>,
}

/// A space in memory, or its place while it is closed.
#[derive(Debug, Default)]
pub(crate) struct Resident {
    /// The space, while it is open.
    pub space: Option<Space>,
    /// Counts the times the space was closed or erased, so that a reader's
    /// load from older records is never installed.
    generation: u64,
    /// The peer's timeline at its last use.
    last_use: u64,
    /// Whether its wait marker is at rest.
    marked: bool,
    /// The snapshot's `through`, its bytes and its parts.
    through: u64,
    snapshot_bytes: u64,
    snapshot_parts: u32,
    /// The bytes of its journal records after the snapshot.
    tail_bytes: u64,
    /// Whether a writer went away with a commit submitted: the space opens
    /// again once every commit submitted is made.
    stale: bool,
    /// Rates, per author, by device ID, and kind (peers.md, "Quotas and
    /// rates").
    pub rates: BTreeMap<(DeviceId, u8), Window>,
    /// Rates, per entry, by the upload key the storing connection proved,
    /// and kind (peers.md, 3.20 Quotas and rates).
    pub entry_rates: BTreeMap<([u8; 32], u8), Window>,
    /// Merge statements, per hour.
    pub merges: Window,
}

impl Resident {
    /// The space; a writer holds it open.
    pub(crate) fn held(&mut self) -> &mut Space {
        self.space.as_mut().expect("a writer holds its space open")
    }
}

/// What the peer hosts.
#[derive(Debug, Default)]
pub(crate) struct Index {
    /// Every space it hosts.
    pub hosted: BTreeSet<EventId>,
    /// The slots of spaces in use.
    slots: BTreeMap<EventId, Arc<Slot>>,
    /// Spaces with a wait marker at rest that are not open: the next sweep
    /// opens them.
    pub(crate) waiting: BTreeSet<EventId>,
    /// The rate windows of closed spaces that still count something, so
    /// that closing a space resets no rate.
    windows: BTreeMap<EventId, Windows>,
    /// ext-libraries.md: each space's `used_bytes` as last computed, for
    /// its library's quota over all its spaces.
    pub used: BTreeMap<EventId, u64>,
    /// ext-libraries.md: the bytes each space's writers hold in its
    /// library's quota for stores not yet made.
    pub reserved: BTreeMap<EventId, u64>,
}

/// A space's rate windows (peers.md, "Quotas and rates").
#[derive(Debug, Default)]
struct Windows {
    rates: BTreeMap<(DeviceId, u8), Window>,
    entry_rates: BTreeMap<([u8; 32], u8), Window>,
    merges: Window,
}

impl Windows {
    fn idle(&self, now: u64) -> bool {
        self.rates.values().all(|window| window.idle(now, 3600))
            && self
                .entry_rates
                .values()
                .all(|window| window.idle(now, 3600))
            && self.merges.idle(now, 3600)
    }
}

impl Index {
    pub(crate) fn new(hosted: BTreeSet<EventId>, waiting: BTreeSet<EventId>) -> Self {
        let waiting = waiting.intersection(&hosted).copied().collect();
        Self {
            hosted,
            waiting,
            ..Self::default()
        }
    }
}

/// A space held for writing: its gate is held, and the space is open if
/// the peer hosts it. No other writer changes it, and no sweep closes it,
/// until this is dropped.
pub(crate) struct Writing {
    pub id: EventId,
    slot: Arc<Slot>,
    /// How many of its changes are submitted and not yet applied. A writer
    /// dropped meanwhile, its caller gone, leaves the space to open again
    /// from its records once every commit submitted is made, so that
    /// memory never misses what is at rest.
    unsettled: AtomicU32,
    _gate: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for Writing {
    fn drop(&mut self) {
        if self.unsettled.load(Ordering::SeqCst) > 0 {
            self.unload();
        }
    }
}

impl Writing {
    /// Takes the space out of memory: it opens again from its records once
    /// every commit submitted is made.
    pub(crate) fn unload(&self) {
        let mut state = lock(&self.slot.state);
        state.space = None;
        state.generation += 1;
        state.stale = true;
    }

    /// Marks a change submitted and not yet applied, until
    /// [`Self::settled`].
    pub(crate) fn unsettle(&self) {
        self.unsettled.fetch_add(1, Ordering::SeqCst);
    }

    /// Marks a change applied, or not made.
    pub(crate) fn settled(&self) {
        self.unsettled.fetch_sub(1, Ordering::SeqCst);
    }

    /// The space's state, held while the caller computes. Never held
    /// across an await.
    pub(crate) fn state(&self) -> MutexGuard<'_, Resident> {
        lock(&self.slot.state)
    }

    /// Whether the space is open: the peer hosts it.
    pub(crate) fn hosted(&self) -> bool {
        self.state().space.is_some()
    }
}

/// A space read from its records.
struct Loaded {
    space: Space,
    opened: Opened,
}

/// Opens a space from its records: blocking. A space with a snapshot opens
/// from it, decoding only the events of the journal after it.
fn load_now(records: &Records, id: &EventId, rules: Rules) -> Result<Loaded, StoreError> {
    let opened = records.opened(id)?;
    let objects = records.objects(id)?;
    let tail: Vec<(u64, crate::records::Op)> = opened
        .tail
        .iter()
        .map(|(index, op, _)| (*index, op.clone()))
        .collect();
    let space = match &opened.snapshot {
        Some(snapshot) => {
            let mut space = Space::from_snapshot(snapshot, objects, rules)
                .ok_or_else(|| StoreError::new("a snapshot whose state does not read"))?;
            space.apply_tail(tail);
            space
        }
        None => Space::replay(tail, objects, rules)
            .ok_or_else(|| StoreError::new("a journal without a genesis"))?,
    };
    Ok(Loaded { space, opened })
}

/// Runs blocking work from async code: on a blocking thread.
pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|e| Err(StoreError::new(format!("a blocking task failed: {e}"))))
}

/// Runs blocking work from a caller that may be on the runtime but cannot
/// await: off the worker where the runtime allows it.
pub(crate) fn blocking_here<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

impl Core {
    /// Whether a closed space's wait marker is at rest: it may hold
    /// something a sweep must judge.
    pub(crate) fn waiting(&self, id: &EventId) -> bool {
        lock(&self.index).waiting.contains(id)
    }

    /// Whether the peer hosts a space.
    pub(crate) fn hosts(&self, id: &EventId) -> bool {
        lock(&self.index).hosted.contains(id)
    }

    fn slot(&self, id: EventId) -> Arc<Slot> {
        lock(&self.index).slots.entry(id).or_default().clone()
    }

    /// Holds a space for writing, opened if hosted.
    ///
    /// # Errors
    ///
    /// If its records cannot be read.
    pub(crate) async fn write(&self, id: EventId) -> Result<Writing, StoreError> {
        let slot = self.slot(id);
        let gate = slot.gate.clone().lock_owned().await;
        self.load(&slot, id).await?;
        // Only a gate's holder closes or forgets a space: a hosted space is
        // open here.
        if self.hosts(&id) && lock(&slot.state).space.is_none() {
            return Err(StoreError::new("a hosted space did not open"));
        }
        self.touch(&slot);
        Ok(Writing {
            id,
            slot,
            unsettled: AtomicU32::new(0),
            _gate: gate,
        })
    }

    /// Reads an open space, opening it first if it is closed; `None` for a
    /// space the peer does not host, or whose records cannot be read.
    pub(crate) async fn read<T>(&self, id: EventId, f: impl FnOnce(&Space) -> T) -> Option<T> {
        if !self.hosts(&id) {
            return None;
        }
        // A close or a stale writer between the load and the read takes
        // the space from memory again: load again.
        for _ in 0..8 {
            let slot = self.slot(id);
            if let Err(error) = self.load(&slot, id).await {
                log(format_args!("a space did not open: {error}"));
                return None;
            }
            if !self.hosts(&id) {
                return None;
            }
            self.touch(&slot);
            let state = lock(&slot.state);
            if let Some(space) = state.space.as_ref() {
                return Some(f(space));
            }
        }
        log("a space closed each time it opened");
        None
    }

    /// [`Self::read`] for a caller that cannot await: the operator's and
    /// the tests' reads.
    pub(crate) fn read_blocking<T>(&self, id: EventId, f: impl FnOnce(&Space) -> T) -> Option<T> {
        if !self.hosts(&id) {
            return None;
        }
        let slot = self.slot(id);
        let (generation, stale) = {
            let state = lock(&slot.state);
            if let Some(space) = &state.space {
                return Some(f(space));
            }
            (state.generation, state.stale)
        };
        if stale {
            let barrier = blocking_here(|| self.writer.barrier_blocking());
            if let Err(error) = barrier {
                log(format_args!("a space did not open: {error}"));
                return None;
            }
            let mut state = lock(&slot.state);
            if state.generation == generation {
                state.stale = false;
            }
        }
        let rules = Rules::of(&self.settings);
        match blocking_here(|| load_now(&self.records, &id, rules)) {
            Ok(loaded) => {
                let mut state = lock(&slot.state);
                if state.space.is_none() && state.generation == generation {
                    self.install(&mut state, id, loaded);
                }
                state.space.as_ref().map(f)
            }
            Err(error) => {
                log(format_args!("a space did not open: {error}"));
                None
            }
        }
    }

    /// Opens a space that is closed, if the peer hosts it.
    async fn load(&self, slot: &Arc<Slot>, id: EventId) -> Result<(), StoreError> {
        let (generation, stale) = {
            let state = lock(&slot.state);
            if state.space.is_some() {
                return Ok(());
            }
            (state.generation, state.stale)
        };
        if !self.hosts(&id) {
            return Ok(());
        }
        // Every commit submitted before is made first: the writer makes
        // them in order.
        if stale {
            self.writer.barrier().await?;
            let mut state = lock(&slot.state);
            if state.generation == generation {
                state.stale = false;
            }
        }
        let records = self.records.clone();
        let rules = Rules::of(&self.settings);
        let loaded = blocking(move || load_now(&records, &id, rules)).await?;
        let mut state = lock(&slot.state);
        if state.space.is_none() && state.generation == generation && self.hosts(&id) {
            self.install(&mut state, id, loaded);
        }
        Ok(())
    }

    fn install(&self, state: &mut Resident, id: EventId, loaded: Loaded) {
        let Loaded { mut space, opened } = loaded;
        state.through = opened.snapshot.as_ref().map_or(0, |s| s.through);
        state.snapshot_bytes = opened.snapshot_bytes;
        state.snapshot_parts = opened.snapshot_parts;
        state.tail_bytes = opened.tail_bytes();
        {
            let mut index = lock(&self.index);
            state.marked = index.waiting.remove(&id);
            if let Some(windows) = index.windows.remove(&id) {
                state.rates = windows.rates;
                state.entry_rates = windows.entry_rates;
                state.merges = windows.merges;
            }
        }
        // Each space's drops count in its usage from its opening on.
        if self.settings.extensions.invite_links {
            self.count_drops(&mut space, self.clock.now().timeline);
        }
        self.note(&space);
        space.next_index = space.next_index.max(state.through);
        state.space = Some(space);
        self.replays.fetch_add(1, Ordering::Relaxed);
    }

    fn touch(&self, slot: &Slot) {
        lock(&slot.state).last_use = self.clock.now().timeline;
    }

    /// Installs a space just created, open, with its wait marker at rest.
    pub(crate) fn install_created(&self, writing: &Writing, space: Space, tail_bytes: u64) {
        let mut state = writing.state();
        self.note(&space);
        state.space = Some(space);
        state.marked = true;
        state.through = 0;
        state.snapshot_bytes = 0;
        state.snapshot_parts = 0;
        state.tail_bytes = tail_bytes;
        lock(&self.index).hosted.insert(writing.id);
    }

    /// Notes a space's `used_bytes` for its library's quota.
    pub(crate) fn note(&self, space: &Space) {
        if self.settings.extensions.libraries {
            lock(&self.index).used.insert(space.id, space.used());
        }
    }

    /// Commits records of a space while its writer holds it: with its wait
    /// marker, on its first commit since it opened. Durable when it
    /// returns.
    ///
    /// # Errors
    ///
    /// If the commit fails: nothing of it is at rest.
    pub(crate) async fn commit_space(
        &self,
        writing: &Writing,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if self
            .commit_space_if(writing, puts, deletes, Vec::new())
            .await?
        {
            Ok(())
        } else {
            Err(StoreError::new("a commit with no expectation was refused"))
        }
    }

    /// [`Self::commit_space`], made only if each address of `expect` holds
    /// what it names (crate `shards`, "Commits across shards"): whether it
    /// was made. A commit not made leaves the space as it was in memory.
    ///
    /// # Errors
    ///
    /// If the commit fails: what of it is at rest is unknown, and the space
    /// opens again from its records.
    pub(crate) async fn commit_space_if(
        &self,
        writing: &Writing,
        mut puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
        expect: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<bool, StoreError> {
        // A library being handed over takes no store (peers.md, 3.1
        // Hosting a space, "Hand-over"): what it holds is what it exports.
        if self.handing_over(&writing.id) {
            return Err(StoreError::new("the space's library is being handed over"));
        }
        // Nor does a space whose move into another shard is under way
        // (crate `libraries`, module `moves`).
        if lock(&self.moves).contains_key(&writing.id) {
            return Err(StoreError::new("the space is moving into another shard"));
        }
        let journal: u64 = puts
            .iter()
            .filter(|(address, _)| Records::is_journal(address))
            .map(|(address, record)| (address.len() + record.len()) as u64)
            .sum();
        let marking = !writing.state().marked;
        if marking {
            puts.push((Records::waits_address(&writing.id), Records::waits_record()));
        }
        // Its first commit since it opened also takes its usage record out
        // of date: the ledger reads the space open until it closes again.
        let mut deletes = deletes;
        if marking {
            deletes.push(Records::usage_address(&writing.id));
        }
        if puts.is_empty() && deletes.is_empty() && expect.is_empty() {
            return Ok(true);
        }
        writing.unsettle();
        let commit = frasil_store::Commit {
            expect,
            puts,
            deletes,
        };
        let made = self.writer.submit(commit).await;
        writing.settled();
        match made {
            Err(error) => {
                // The records may hold the commit or not: the space opens
                // again from them.
                writing.unload();
                Err(error)
            }
            Ok(false) => Ok(false),
            Ok(true) => {
                let mut state = writing.state();
                state.marked = true;
                state.tail_bytes += journal;
                Ok(true)
            }
        }
    }

    /// Forgets a space erased or deleted, whose records are gone.
    pub(crate) fn forget_space(&self, writing: &Writing) {
        let mut state = writing.state();
        state.space = None;
        state.generation += 1;
        state.marked = false;
        state.rates.clear();
        state.entry_rates.clear();
        let mut index = lock(&self.index);
        index.hosted.remove(&writing.id);
        index.waiting.remove(&writing.id);
        index.windows.remove(&writing.id);
        index.used.remove(&writing.id);
    }

    /// Rebuilds a space from its records, after a sweep removed some of
    /// them; the judgements of its requests and its drops stay.
    pub(crate) async fn rebuild(&self, writing: &Writing) -> Result<(), StoreError> {
        let records = self.records.clone();
        let rules = Rules::of(&self.settings);
        let id = writing.id;
        let loaded = blocking(move || load_now(&records, &id, rules)).await?;
        let mut state = writing.state();
        let Some(old) = state.space.take() else {
            return Ok(());
        };
        let Loaded { mut space, opened } = loaded;
        space.outcomes = old.outcomes;
        space.drops = old.drops;
        space.drop_bytes = old.drop_bytes;
        state.through = opened.snapshot.as_ref().map_or(0, |s| s.through);
        state.snapshot_bytes = opened.snapshot_bytes;
        state.snapshot_parts = opened.snapshot_parts;
        state.tail_bytes = opened.tail_bytes();
        space.next_index = space.next_index.max(state.through);
        self.note(&space);
        state.space = Some(space);
        self.replays.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// The first journal index of a space that is not in its snapshot.
    pub(crate) fn through(&self, writing: &Writing) -> u64 {
        writing.state().through
    }

    // -- Folding and closing

    /// The records that fold a space's journal into a new snapshot of its
    /// state, without the journal records at `removed`: the new snapshot's
    /// parts, the old parts and journal records to delete, and the
    /// snapshot. With nothing removed, the snapshot is the space's state in
    /// memory, which is its records' state while its writer holds it;
    /// otherwise it is the space's journal, read from that state, replayed
    /// without the records removed.
    async fn fold_records(
        &self,
        writing: &Writing,
        removed: BTreeSet<u64>,
    ) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>, Snapshot), StoreError> {
        let records = self.records.clone();
        let id = writing.id;
        let opened = blocking(move || records.opened(&id)).await?;
        let mut deletes: Vec<Vec<u8>> = (0..opened.snapshot_parts)
            .map(|part| Records::snapshot_address(&id, part))
            .collect();
        deletes.extend(
            opened
                .tail
                .iter()
                .map(|(index, _, _)| Records::journal_address(&id, *index)),
        );
        let old_through = opened.snapshot.as_ref().map_or(0, |s| s.through);
        let mut snapshot = {
            let state = writing.state();
            let space = state
                .space
                .as_ref()
                .ok_or_else(|| StoreError::new("a fold of a space that is not open"))?;
            if removed.is_empty() {
                space.to_snapshot()
            } else {
                let journal = space
                    .journal()
                    .into_iter()
                    .filter(|(index, _, _)| !removed.contains(index))
                    .collect();
                let objects = space.objects.iter().map(|(l, r)| (*l, r.clone())).collect();
                let rebuilt = Space::replay_decoded(journal, objects, Rules::of(&self.settings))
                    .ok_or_else(|| StoreError::new("a journal without a genesis"))?;
                let mut snapshot = rebuilt.to_snapshot();
                snapshot.through = space.next_index;
                snapshot
            }
        };
        snapshot.through = snapshot.through.max(old_through);
        let puts = Records::snapshot_puts(&id, &snapshot);
        Ok((puts, deletes, snapshot))
    }

    fn folded(&self, writing: &Writing, puts: &[(Vec<u8>, Vec<u8>)], snapshot: &Snapshot) {
        let mut state = writing.state();
        state.through = snapshot.through;
        state.snapshot_bytes = puts.iter().map(|(_, part)| part.len() as u64).sum();
        state.snapshot_parts = u32::try_from(puts.len()).unwrap_or(u32::MAX);
        state.tail_bytes = 0;
    }

    /// Folds a space's journal into a new snapshot now, leaving out the
    /// journal records at `removed`, with the caller's `puts` and
    /// `deletes` in the same commit.
    pub(crate) async fn fold(
        &self,
        writing: &Writing,
        removed: BTreeSet<u64>,
        mut puts: Vec<(Vec<u8>, Vec<u8>)>,
        mut deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        let (parts, old, snapshot) = self.fold_records(writing, removed).await?;
        deletes.extend(old);
        puts.extend(parts.iter().cloned());
        self.commit_space(writing, puts, deletes).await?;
        self.folded(writing, &parts, &snapshot);
        Ok(())
    }

    /// Whether a space's journal after its snapshot has grown to half the
    /// snapshot; or, as it closes, holds anything: a close is idle time.
    fn wants_fold(state: &Resident, closing: bool) -> bool {
        if closing {
            return state.tail_bytes > 0;
        }
        state.tail_bytes >= FOLD_MIN.max(state.snapshot_bytes / 2)
    }

    /// Whether a space may close now: open, idle long enough unless
    /// `force`, nothing waiting in it, and nothing of a connection on it.
    fn closable(&self, id: &EventId, state: &Resident, now: u64, force: bool) -> bool {
        let Some(space) = &state.space else {
            return false;
        };
        let idle = force || now.saturating_sub(state.last_use) >= self.settings.idle_close;
        idle && !space.waits() && !self.in_use(id)
    }

    /// Folds a space if its journal has grown, and closes it if it may: the
    /// wait marker goes with it. Returns whether it closed.
    async fn close(&self, writing: &Writing, now: u64, force: bool) -> bool {
        let (fold, closable) = {
            let state = writing.state();
            let closable = self.closable(&writing.id, &state, now, force);
            (Self::wants_fold(&state, closable), closable)
        };
        if fold
            && let Err(error) = self
                .fold(writing, BTreeSet::new(), Vec::new(), Vec::new())
                .await
        {
            log(format_args!("a snapshot was not kept: {error}"));
            return false;
        }
        if !closable {
            return false;
        }
        // Read after the fold, whose commit may write the marker. A space
        // that changed since it opened leaves its usage for its library's
        // ledger (ext-libraries.md, 2.5 What a peer keeps).
        let marked = writing.state().marked;
        if marked {
            let unmark = vec![Records::waits_address(&writing.id)];
            let mut usage = Vec::new();
            if self.settings.extensions.libraries
                && let Some(space) = writing.state().space.as_ref()
            {
                usage.push((
                    Records::usage_address(&writing.id),
                    crate::libraries::usage_record(space),
                ));
            }
            if let Err(error) = self.writer.commit(usage, unmark).await {
                log(format_args!(
                    "a space's wait marker was not cleared: {error}"
                ));
                return false;
            }
        }
        let mut state = writing.state();
        state.space = None;
        state.generation += 1;
        state.marked = false;
        let windows = Windows {
            rates: std::mem::take(&mut state.rates),
            entry_rates: std::mem::take(&mut state.entry_rates),
            merges: std::mem::take(&mut state.merges),
        };
        if !windows.idle(now) {
            lock(&self.index).windows.insert(writing.id, windows);
        }
        true
    }

    /// The sweep's closing pass: each open space idle long enough, or every
    /// open space that may close with `force`.
    pub(crate) async fn close_idle(&self, force: bool) -> usize {
        let now = self.clock.now().timeline;
        let candidates: Vec<(EventId, Arc<Slot>)> = {
            let mut index = lock(&self.index);
            index.windows.retain(|_, windows| !windows.idle(now));
            index
                .slots
                .iter()
                .map(|(id, slot)| (*id, slot.clone()))
                .collect()
        };
        let mut closed = 0;
        for (id, slot) in candidates {
            let Ok(gate) = slot.gate.clone().try_lock_owned() else {
                continue;
            };
            let writing = Writing {
                id,
                slot: slot.clone(),
                unsettled: AtomicU32::new(0),
                _gate: gate,
            };
            if writing.state().space.is_none() {
                drop(writing);
                self.release(id, &slot);
                continue;
            }
            if self.close(&writing, now, force).await {
                closed += 1;
                drop(writing);
                self.release(id, &slot);
            }
        }
        closed
    }

    /// Ends a writer of a space; the space's slot goes with it if the
    /// space is not open and nobody else holds the slot, as for a space the
    /// peer does not host.
    pub(crate) fn let_go(&self, writing: Writing) {
        let (id, slot) = (writing.id, writing.slot.clone());
        drop(writing);
        if lock(&slot.state).space.is_none() {
            self.release(id, &slot);
        }
    }

    /// Drops a closed space's slot, unless someone holds it.
    fn release(&self, id: EventId, slot: &Arc<Slot>) {
        let mut index = lock(&self.index);
        let unused = Arc::strong_count(slot) == 2
            && slot
                .state
                .try_lock()
                .is_ok_and(|state| state.space.is_none());
        if unused
            && index
                .slots
                .get(&id)
                .is_some_and(|held| Arc::ptr_eq(held, slot))
        {
            index.slots.remove(&id);
        }
    }

    /// The spaces a sweep visits: those open, and those whose wait marker
    /// says they may hold something to judge.
    pub(crate) fn to_sweep(&self) -> Vec<EventId> {
        let index = lock(&self.index);
        let open: BTreeSet<EventId> = index
            .slots
            .iter()
            .filter(|(_, slot)| {
                slot.state
                    .try_lock()
                    .map_or(true, |state| state.space.is_some())
            })
            .map(|(id, _)| *id)
            .collect();
        open.union(&index.waiting).copied().collect()
    }

    /// Changes each open space in turn, without its gate: for what no
    /// writer's records depend on, such as the count of its drops.
    pub(crate) fn each_open(&self, mut change: impl FnMut(&mut Space)) {
        let slots: Vec<Arc<Slot>> = lock(&self.index).slots.values().cloned().collect();
        for slot in slots {
            if let Some(space) = lock(&slot.state).space.as_mut() {
                change(space);
            }
        }
    }

    /// Reads an open space, without opening a closed one.
    pub(crate) fn peek<T>(&self, id: &EventId, f: impl FnOnce(&Space) -> T) -> Option<T> {
        let slot = lock(&self.index).slots.get(id).cloned()?;
        let state = lock(&slot.state);
        state.space.as_ref().map(f)
    }

    /// The first journal index a space's snapshot does not hold, while it
    /// is open.
    #[cfg(test)]
    pub(crate) fn through_of(&self, id: EventId) -> u64 {
        let slot = lock(&self.index).slots.get(&id).cloned();
        slot.map_or(0, |slot| lock(&slot.state).through)
    }

    /// Takes an open space out of memory as a close does, whatever waits in
    /// it: its next use opens it from its records.
    #[cfg(test)]
    pub(crate) async fn unload(&self, id: EventId) {
        let writing = self.write(id).await.expect("its records read");
        let mut state = writing.state();
        state.space = None;
        state.generation += 1;
    }

    /// Takes out of memory every open space whose records are in one of
    /// `shards`, as a close does: in a cluster, as this node gives the
    /// shards up. Its next use here opens it from its records.
    pub(crate) async fn unload_shards(&self, shards: &[String]) {
        let Some(placed) = &self.shards else {
            return;
        };
        let ids: Vec<EventId> = lock(&self.index)
            .slots
            .keys()
            .filter(|id| shards.contains(&placed.space_shard_of(id.as_bytes())))
            .copied()
            .collect();
        for id in ids {
            let Ok(writing) = self.write(id).await else {
                continue;
            };
            let mut state = writing.state();
            state.space = None;
            state.generation += 1;
        }
    }

    /// How many slots the index holds, of spaces open or in use.
    #[cfg(test)]
    pub(crate) fn slots(&self) -> usize {
        lock(&self.index).slots.len()
    }

    /// How many spaces are open.
    pub(crate) fn open_spaces(&self) -> usize {
        lock(&self.index)
            .slots
            .values()
            .filter(|slot| {
                slot.state
                    .try_lock()
                    .map_or(true, |state| state.space.is_some())
            })
            .count()
    }
}

#[cfg(test)]
mod tests;
