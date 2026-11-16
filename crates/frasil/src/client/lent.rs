//! One document: a Loro document lent to the application.
//!
//! A [`Lent`] handle, from [`Document::lend`], is a reference to Frasil's
//! own main document for the stream (`LoroDoc::clone` shares one
//! document), with this device's fresh incarnation as its peer ID
//! (adapter-loro.md, section 3.1). The application edits that document
//! directly, with its own undo manager; other members' operations arrive
//! in it as Frasil applies their units, and reach the application as
//! Loro's own events. Nothing is held twice.
//!
//! **Units.** Frasil decides where the application's local commits become
//! units: every unit carries a signature, so commits are batched within a
//! window. A unit is written [`WINDOW`] after the first commit it holds,
//! or at once when the commits since the last unit exceed
//! [`PENDING_LIMIT`] bytes, on [`Lent::flush`], and when the handle is
//! dropped or the device closes. Within the window the operations are in
//! memory only, and nothing else keeps them: a crash loses what the window
//! holds and leaves nothing to re-express, since the store and the
//! application hold the same document. An application that keeps a file
//! of its own writes it after [`Lent::flush`].
//!
//! **A unit refused** (the device must sync first, a rotation is due, its
//! level fell, the store failed) stays pending: the handle tries again,
//! after [`WINDOW`] and then twice as long each time up to [`RETRY_LIMIT`],
//! and says so through [`Lent::failed`] until a unit is written.
//!
//! **Replacement.** Frasil builds the main document again after a rebuild
//! (adapter-loro.md, section 3.3): the handle then refers to the new
//! document, with the operations not yet in a unit carried over, and
//! [`Lent::replaced`] tells the application, which takes the new
//! reference ([`Lent::doc`]) and binds its undo manager again. Loro's
//! `UndoManager` belongs to one document and undoes one peer's operations,
//! the lent peer's; across a replacement a new one is bound to the new
//! document, and undoes what is written after. The reference the
//! application held before stays watched until it takes the new one:
//! what it still commits there is carried over too, before every unit,
//! the handle's last on drop and the device's close included.
//!
//! Operations are carried over as they are when that is exact: the new
//! document holds nothing of the peer past them, and none of them
//! depends on an operation the rebuild left out (section 3.3: such an
//! operation would stay pending inside Loro). Otherwise the handle's own
//! operations, and nothing of any other peer, are replayed onto the new
//! document ([`super::rebase`]): each change the new document does not
//! hold is read as the difference it made at its own parent version and
//! applied again as new operations, every position found through the
//! stable IDs of the elements around it. An insertion goes after the
//! nearest element before it that the new document holds; a deletion
//! takes what the new document still shows of what it deleted; a mark,
//! a counter's step, a map key and a move are the change's own, never one
//! another writer made. What the replays made is kept for the reference,
//! so its later commits find the handle's own replayed text, across a
//! further replacement too. The next unit carries it.
//!
//! What has no place is left out and reported ([`Lent::failed`]), never
//! written as another writer's: an operation inside a container, under a
//! tree node or on a list item that only another writer's lost operation
//! made (a key set in that writer's map, a child created under its node,
//! a move or a set of its list item), and anything Loro refuses. The report stays until
//! the next replacement carries clean, whatever units are written
//! meanwhile; what was left out is not tried again.
//!
//! **A unit of its own withdrawn.** When the rebuilt document does not
//! hold an operation this handle wrote to a unit (its unit was withdrawn,
//! as when its writer was removed and granted again, or waits inside Loro
//! on one that was, section 3.3), the incarnation does not go on (section
//! 3.1): the handle takes a fresh one, and replays, as above, what it
//! committed that the new document does not hold.
//!
//! Each writer expresses its own operations, and only its own: a lost
//! operation is expressed by the handle that wrote it, once, whoever else
//! renews and whenever; and another writer's operation made over it
//! keeps its place without it, expressed by its own writer. Nothing
//! depends on another writer coming back, and a forked device's operations
//! are never expressed again. A writer that is not lent (one that writes
//! with [`Document::edit`]) has no handle to express its operations: they
//! stay pending inside Loro, which the replica reports
//! (`LoroDependsOnRefused`), and its writer writes them again (section
//! 3.3).
//!
//! **A previous incarnation has no handle.** The handle keeps the old
//! document only while it lives. A device that restarted, or whose handle
//! was dropped, lends again at a fresh incarnation (section 3.1); when a
//! unit of the earlier incarnation is withdrawn after that, nothing holds
//! its operations to express them again, and the rebuilt document is
//! without them. An application that must keep them writes them again
//! from its own copy.
//!
//! **Suggestions.** [`Lent::suggest`] takes an update made on a fork of the
//! document (`LoroDoc::fork`): a suggestion stays in Frasil's suggestion
//! layer, out of the lent document, until a writer accepts it.

use super::rebase::Mapping;
use super::streams::Document;
use crate::device::Engine;
use crate::documents::{Lending, LentDoc, loro_state};
use crate::error::{Error, Result};
use frasil_adapter_loro::Incarnation;
use frasil_adapter_loro::meta::Counter;
use frasil_adapter_loro::write::export_since;
use frasil_events::EventId;
use frasil_units::stream::StreamId;
use loro::LoroDoc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;
use tokio::sync::{Notify, broadcast, watch};

/// How long after the first local commit since the last unit Frasil
/// writes the next one: a bounded window, so that typing makes a unit
/// every so often rather than one per keystroke, each with a signature.
pub const WINDOW: Duration = Duration::from_millis(250);

/// The bytes of local updates since the last unit that end the window
/// early: a large paste reaches a unit at once.
pub const PENDING_LIMIT: usize = 64 * 1024;

/// The longest wait between two tries of a unit the engine refused.
pub const RETRY_LIMIT: Duration = Duration::from_secs(8);

/// A Loro document lent to the application, from [`Document::lend`]:
/// the application edits [`Lent::doc`] directly under [`Lent::peer_id`].
/// Clones share the handle; the last one dropped ends the incarnation,
/// after a last unit.
#[derive(Clone)]
pub struct Lent {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Lent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lent")
            .field("document", &self.shared.document.id())
            .field("peer", &self.shared.peer())
            .field("generation", &self.shared.generation.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

struct Shared {
    document: Document,
    engine: Engine,
    space: EventId,
    stream: StreamId,
    /// The incarnation the document writes under; renewed when lost.
    incarnation: Mutex<Incarnation>,
    /// The current reference: the replica's main document, or its
    /// replacement after a rebuild.
    doc: Mutex<LoroDoc>,
    /// The state's generation `doc` belongs to.
    generation: AtomicU64,
    /// The local-update subscription on `doc`, replaced with it.
    subscription: Mutex<Option<loro::Subscription>>,
    /// References from before a replacement, watched until the
    /// application takes the current document.
    retired: Mutex<Vec<Retired>>,
    /// Held while a replacement is taken, so the task and a flush never
    /// take one twice.
    rebinding: tokio::sync::Mutex<()>,
    /// What runs on the new document before the handle refers to it
    /// ([`Lent::on_replaced`]).
    hooks: Mutex<Vec<Hook>>,
    /// Woken by each local commit, to the current document or a retired
    /// one.
    dirty: Arc<Notify>,
    /// The bytes of local updates since the last unit.
    pending: Arc<AtomicUsize>,
    /// Rises with each replacement.
    replaced: watch::Sender<u64>,
    /// The failure of the last unit tried, until one is written; a change
    /// that could not be carried, until the next replacement.
    failed: watch::Sender<Option<Error>>,
    /// Whether `failed` holds a change that could not be carried, which a
    /// written unit does not clear.
    carry_failed: AtomicBool,
    /// Set when the last handle goes, so the task writes a last unit and
    /// ends the incarnation.
    closing: Arc<Notify>,
    /// Set by the task once it ended: the device is gone, or its notices.
    closed: Arc<AtomicBool>,
    /// The carry the last handle's drop runs off the async worker: set
    /// once it is done, and told. The task, finding the handle gone, waits
    /// for it before its last unit: the shared state is gone before its
    /// drop has run.
    carried: Arc<AtomicBool>,
    dropped: Arc<Notify>,
}

/// What runs on a new document before the handle refers to it
/// ([`Lent::on_replaced`]): the document and its generation.
type Hook = Box<dyn Fn(&LoroDoc, u64) + Send + Sync>;

/// A reference the application held before a replacement.
struct Retired {
    doc: LoroDoc,
    carry: Carry,
    /// Its local-update subscription, kept so its commits wake the task.
    _subscription: loro::Subscription,
}

/// How a retired reference's commits reach the current document.
enum Carry {
    /// The same incarnation: its operations from `end` on are imported as
    /// they are while that is exact; else it turns into `Replay`.
    Import { peer: u64, end: Counter },
    /// The handle's own operations from `from` on are replayed, rebased,
    /// under the current peer ([`super::rebase`]), with what the earlier
    /// replays made in the current document.
    Replay { from: Counter, map: Mapping },
}

/// Whether the old document's operations of `peer` from `end` on import
/// into `current` as they are: it holds nothing of the peer past `end`, and
/// none of them would wait inside Loro on an operation it lacks.
fn exact(old: &LoroDoc, current: &LoroDoc, peer: u64, end: Counter) -> bool {
    if current.oplog_vv().get(&peer).copied().unwrap_or(0) != end {
        return false;
    }
    match export_since(old, peer, end) {
        Ok(None) => true,
        Ok(Some((update, _))) => current
            .fork()
            .import(&update)
            .is_ok_and(|status| status.pending.is_none()),
        Err(_) => false,
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        // What the retired references still hold reaches the document
        // before the task's last unit: off the async worker when there is
        // a runtime, since a carry may replay, and the task is told to
        // close once it is done.
        let retired =
            std::mem::take(&mut *self.retired.lock().unwrap_or_else(PoisonError::into_inner));
        let current = self.doc();
        let closing = self.closing.clone();
        let (carried, dropped) = (self.carried.clone(), self.dropped.clone());
        let carry = move || {
            for mut reference in retired {
                let _ = Self::carry_into(&current, &reference.doc, &mut reference.carry);
            }
            carried.store(true, Ordering::SeqCst);
            dropped.notify_one();
            closing.notify_one();
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(carry);
            }
            Err(_) => carry(),
        }
    }
}

fn adapter(error: impl core::fmt::Display) -> Error {
    Error::Adapter(error.to_string())
}

impl Shared {
    fn doc(&self) -> LoroDoc {
        self.doc
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn peer(&self) -> u64 {
        self.incarnation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .peer()
    }

    /// Subscribes to a document's local commits: each wakes the task.
    fn subscribe(&self, doc: &LoroDoc) -> loro::Subscription {
        let dirty = self.dirty.clone();
        let pending = self.pending.clone();
        doc.subscribe_local_update(Box::new(move |update: &Vec<u8>| {
            pending.fetch_add(update.len(), Ordering::SeqCst);
            dirty.notify_one();
            true
        }))
    }

    /// Watches the current document.
    fn watch(&self, doc: &LoroDoc) {
        *self
            .subscription
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(self.subscribe(doc));
    }

    /// Takes the replacement after a rebuild, if the state was built
    /// again: the reference held before is retired, its operations not
    /// yet in a unit carried over, the application told. A unit of this
    /// handle's own withdrawn renews the incarnation first. `true` when
    /// the document was replaced.
    async fn rebind(&self) -> Result<bool> {
        let _taking = self.rebinding.lock().await;
        let LentDoc {
            doc,
            generation,
            lost,
        } = self.engine.lent_doc(self.space, self.stream).await?;
        if generation == self.generation.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let old = self.doc();
        let subscription = self
            .subscription
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let peer = self.peer();
        // What the accepted units hold of the peer.
        let applied = self
            .engine
            .read(&self.space, |replica| {
                loro_state(replica, &self.stream).map(|state| state.applied_end(peer))
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        // What the rebuilt document holds of the peer, at most: an accepted
        // unit's operations that wait inside Loro on a refused unit are not
        // held.
        let held = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
        let committed = applied.min(held);
        let doc = if lost {
            let Lending {
                incarnation, doc, ..
            } = self.engine.renew_lent(self.space, self.stream).await?;
            *self
                .incarnation
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = incarnation;
            doc
        } else {
            doc
        };
        // What the rebuilt document does not hold of the peer is replayed
        // onto it, rebased, under the handle's peer, the renewed one when
        // the incarnation was lost; the rest of the old document is not.
        let carry = if !lost && exact(&old, &doc, peer, committed) {
            Carry::Import {
                peer,
                end: committed,
            }
        } else {
            let from = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
            Carry::Replay {
                from,
                map: Mapping::new(peer, from),
            }
        };
        // Off the async worker: a replay checks the old document out at
        // each change it replays.
        let (carry, carried) = {
            let (old, doc) = (old.clone(), doc.clone());
            let mut carry = carry;
            tokio::task::spawn_blocking(move || {
                let carried = Self::carry_into(&doc, &old, &mut carry);
                (carry, carried)
            })
            .await
            .map_err(|_| Error::Adapter("the replay stopped".into()))?
        };
        // The references retired before name the old document's elements
        // as it held them: once it is replayed into the new one, they name
        // them as that replay does.
        if let Carry::Replay { map: next, .. } = &carry {
            let mut retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
            for reference in retired.iter_mut() {
                let converted = match &mut reference.carry {
                    Carry::Replay { map, .. } => {
                        map.through(next);
                        None
                    }
                    Carry::Import { end, .. } => Some(Carry::Replay {
                        from: *end,
                        map: Mapping::imported(
                            next,
                            *end,
                            super::rebase::lamport_at(&old, peer, *end),
                        ),
                    }),
                };
                if let Some(converted) = converted {
                    reference.carry = converted;
                }
            }
        }
        let retired = Retired {
            doc: old,
            carry,
            _subscription: subscription.unwrap_or_else(|| self.subscribe(&doc)),
        };
        // Bound to the new document before the handle refers to it. The
        // document and its generation are stored under the hooks' lock, so
        // a hook bound meanwhile ([`Lent::bind_replaced`]) sees either the
        // old pair or this one, whole.
        {
            let hooks = self.hooks.lock().unwrap_or_else(PoisonError::into_inner);
            for hook in hooks.iter() {
                hook(&doc, generation);
            }
            self.watch(&doc);
            *self.doc.lock().unwrap_or_else(PoisonError::into_inner) = doc;
            self.generation.store(generation, Ordering::SeqCst);
        }
        // A change the new document could not place stays reported until
        // the next replacement carries clean.
        let was_failed = self.carry_failed.swap(carried.is_err(), Ordering::SeqCst);
        if was_failed && carried.is_ok() {
            self.failed.send_replace(None);
        }
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(retired);
        self.replaced.send_replace(generation);
        self.dirty.notify_one();
        carried.map(|()| true)
    }

    /// Carries a retired reference's commits into the current document:
    /// imported as they are while that is exact, else replayed, rebased,
    /// with what cannot be placed reported.
    fn carry_into(current: &LoroDoc, old: &LoroDoc, carry: &mut Carry) -> Result<()> {
        if let Carry::Import { peer, end } = carry {
            if exact(old, current, *peer, *end) {
                if let Some((update, span)) = export_since(old, *peer, *end).map_err(adapter)? {
                    current.import(&update).map_err(adapter)?;
                    *end = span.end;
                }
                return Ok(());
            }
            *carry = Carry::Replay {
                from: *end,
                map: Mapping::new(*peer, *end),
            };
        }
        let Carry::Replay { from, map } = carry else {
            return Ok(());
        };
        let replayed = super::rebase::replay_own(old, current, *from, map);
        *from = replayed.next;
        if replayed.left_out.is_empty() {
            Ok(())
        } else {
            Err(Error::Adapter(format!(
                "LoroDependsOnRefused: left out, and left to its writer (adapter-loro.md, \
                 section 3.3): {}",
                replayed.left_out.join("; ")
            )))
        }
    }

    /// Carries every retired reference's commits into the current
    /// document; `forget` drops the references after. The references are
    /// taken out while Loro runs, since Loro calls subscriptions on the
    /// committing thread and one may take the document ([`Lent::doc`]).
    fn carry(&self, forget: bool) -> Result<()> {
        let mut taken =
            std::mem::take(&mut *self.retired.lock().unwrap_or_else(PoisonError::into_inner));
        if taken.is_empty() {
            return Ok(());
        }
        let current = self.doc();
        let mut result = Ok(());
        for reference in &mut taken {
            if let Err(error) = Self::carry_into(&current, &reference.doc, &mut reference.carry) {
                result = Err(error);
            }
        }
        if !forget {
            let mut retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
            taken.append(&mut retired);
            *retired = taken;
        }
        result
    }

    /// [`Shared::carry`], its failure reported through `failed` and kept
    /// there until the next replacement carries clean.
    fn carry_reported(&self, forget: bool) {
        if let Err(error) = self.carry(forget) {
            self.carry_failed.store(true, Ordering::SeqCst);
            self.failed.send_replace(Some(error));
        }
    }

    /// Writes the pending operations as a unit, the retired references'
    /// carried first, and reports the outcome through `failed`: a unit's
    /// failure stays reported until a unit is written, a carry's until the
    /// next replacement.
    async fn write(self: &Arc<Self>) -> Result<()> {
        // Off the async worker: a carry may replay.
        let this = Arc::clone(self);
        let _ = tokio::task::spawn_blocking(move || this.carry_reported(false)).await;
        self.pending.store(0, Ordering::SeqCst);
        let written = self.engine.flush_lent(self.space, self.stream).await;
        match &written {
            Ok(Some(_)) => {
                if self.failed.borrow().is_some() && !self.carry_failed.load(Ordering::SeqCst) {
                    self.failed.send_replace(None);
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.failed.send_replace(Some(error.clone()));
            }
        }
        written.map(drop)
    }
}

impl Document {
    /// Lends the document to the application: a reference to Frasil's own
    /// Loro document for the stream, under a fresh incarnation of this
    /// device. Edit it directly and commit as Loro does; Frasil writes the
    /// commits as units within the module's window. One handle at a time
    /// per document and device; a document created and not yet written in
    /// can be lent. A member that only reads may lend it too, to read
    /// other members' edits as they arrive: a commit it makes is refused
    /// as a unit and reported through [`Lent::failed`], and reaches no
    /// one.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] when the document is
    /// lent already, or no incarnation is free; [`Error::Adapter`] when
    /// Loro refuses the peer ID.
    pub async fn lend(&self) -> Result<Lent> {
        let engine = self.space.device.engine().clone();
        let space = self.space.id().event();
        let stream = self.opening.stream();
        let notices = engine.subscribe();
        let Lending {
            incarnation,
            doc,
            generation,
        } = engine.begin_lent(space, &self.opening).await?;
        let (replaced, _) = watch::channel(generation);
        let (failed, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            document: self.clone(),
            engine: engine.clone(),
            space,
            stream,
            incarnation: Mutex::new(incarnation),
            doc: Mutex::new(doc.clone()),
            generation: AtomicU64::new(generation),
            subscription: Mutex::new(None),
            retired: Mutex::new(Vec::new()),
            rebinding: tokio::sync::Mutex::new(()),
            hooks: Mutex::new(Vec::new()),
            dirty: Arc::new(Notify::new()),
            pending: Arc::new(AtomicUsize::new(0)),
            replaced,
            failed,
            carry_failed: AtomicBool::new(false),
            closing: Arc::new(Notify::new()),
            closed: Arc::new(AtomicBool::new(false)),
            carried: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(Notify::new()),
        });
        shared.watch(&doc);
        // Every flush the engine makes on its own (the device's close, an
        // export) carries the retired references first.
        let weak = Arc::downgrade(&shared);
        engine
            .lent_carry(
                space,
                stream,
                Arc::new(move || {
                    if let Some(shared) = weak.upgrade() {
                        shared.carry_reported(false);
                    }
                }),
            )
            .await?;
        let task = Task {
            shared: Arc::downgrade(&shared),
            dirty: shared.dirty.clone(),
            pending: shared.pending.clone(),
            closing: shared.closing.clone(),
            closed: shared.closed.clone(),
            carried: shared.carried.clone(),
            dropped: shared.dropped.clone(),
            engine,
            space,
            stream,
        };
        self.space.device.spawn(Box::pin(task.run(notices)));
        Ok(Lent { shared })
    }
}

/// What keeps a lent document: the window, the replacements, the tries
/// and the end.
struct Task {
    shared: Weak<Shared>,
    dirty: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    closing: Arc<Notify>,
    closed: Arc<AtomicBool>,
    carried: Arc<AtomicBool>,
    dropped: Arc<Notify>,
    engine: Engine,
    space: EventId,
    stream: StreamId,
}

impl Task {
    async fn run(self, mut notices: broadcast::Receiver<crate::device::Notice>) {
        let retry = tokio::time::sleep(WINDOW);
        tokio::pin!(retry);
        let mut failing = false;
        let mut backoff = WINDOW;
        loop {
            let mut tried = false;
            tokio::select! {
                () = self.dirty.notified() => {
                    self.window().await;
                    failing = self.write().await.is_err();
                    tried = true;
                }
                () = &mut retry, if failing => {
                    failing = self.write().await.is_err();
                    tried = true;
                }
                notice = notices.recv() => match notice {
                    // A notice of the space, or notices missed: the
                    // document may have been built again.
                    Ok(crate::device::Notice { space, .. }) if space == self.space => {
                        if self.rebind().await {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if self.rebind().await {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                () = self.closing.notified() => break,
            }
            if self.shared.upgrade().is_none() {
                break;
            }
            // After a try that failed, the next one waits twice as long as
            // the last; a try that wrote starts the wait over.
            if tried && failing {
                retry.as_mut().reset(tokio::time::Instant::now() + backoff);
                backoff = (backoff * 2).min(RETRY_LIMIT);
            } else if tried {
                backoff = WINDOW;
            }
        }
        // The last handle is gone, or the device: a last unit, and the
        // incarnation ends. With the handle gone, its drop's carry goes in
        // the document first; the drop may not have begun yet, so the task
        // waits for its signal rather than for a flag set within it.
        if self.shared.upgrade().is_none() {
            while !self.carried.load(Ordering::SeqCst) {
                self.dropped.notified().await;
            }
        }
        self.closed.store(true, Ordering::SeqCst);
        let _ = self.engine.end_lent(self.space, self.stream).await;
    }

    /// Takes a replacement, if any. `true` when the handle is gone.
    async fn rebind(&self) -> bool {
        let Some(shared) = self.shared.upgrade() else {
            return true;
        };
        if let Err(error) = shared.rebind().await {
            shared.failed.send_replace(Some(error));
        }
        false
    }

    /// Waits the window out, or until the pending bytes pass the limit.
    async fn window(&self) {
        if self.pending.load(Ordering::SeqCst) >= PENDING_LIMIT {
            return;
        }
        let deadline = tokio::time::sleep(WINDOW);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                () = self.dirty.notified() => {
                    if self.pending.load(Ordering::SeqCst) >= PENDING_LIMIT {
                        break;
                    }
                }
                () = self.closing.notified() => break,
            }
        }
    }

    /// Writes the pending operations as a unit, while the handle is held.
    async fn write(&self) -> Result<()> {
        match self.shared.upgrade() {
            Some(shared) => shared.write().await,
            None => self
                .engine
                .flush_lent(self.space, self.stream)
                .await
                .map(drop),
        }
    }
}

impl Lent {
    /// The document: edit it, and commit as Loro does. After a
    /// replacement ([`Lent::replaced`]) this is the new document, and
    /// taking it is what ends the watch on the reference held before.
    ///
    /// Loro commits the transaction in flight whenever the document is
    /// exported or imported: the unit Frasil writes, and every unit of
    /// another member it applies, so a logical edit made in several steps
    /// can land in two units and two undo groups. An application that
    /// wants an edit whole commits it before yielding, or makes it within
    /// one transaction of its own.
    ///
    /// Taking the document carries into it, on the calling thread, what
    /// the application committed to the reference it held before since the
    /// last unit: the call is synchronous and returns the document with
    /// those commits in it. Every unit carries them first, off the async
    /// worker, so what is left here is what was committed since, and a
    /// carry with nothing new returns at once.
    pub fn doc(&self) -> LoroDoc {
        self.shared.carry_reported(true);
        self.shared.doc()
    }

    /// The peer ID the document writes under: this device's incarnation,
    /// renewed when a unit of its own was withdrawn. The document has it
    /// set; the application does not change it.
    pub fn peer_id(&self) -> u64 {
        self.shared.peer()
    }

    /// The generation of the document in hand, which [`Lent::replaced`]
    /// raises.
    pub fn generation(&self) -> u64 {
        self.shared.generation.load(Ordering::SeqCst)
    }

    /// Writes the operations committed since the last unit as a unit now,
    /// before the window ends: a replacement is taken first. Nothing is
    /// written when there are none.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device writes in the space;
    /// [`Error::SyncBeforeWriting`]; [`Error::RotationDue`]; the store's.
    /// A carried change the new document cannot place is reported through
    /// [`Lent::failed`], not here.
    pub async fn flush(&self) -> Result<()> {
        let rebound = self.shared.rebind().await;
        let written = self.shared.write().await;
        rebound.and(written)
    }

    /// Replacements, as a watch on the generation: `changed().await` wakes
    /// once Frasil built the document again and the handle refers to the
    /// new one. Take [`Lent::doc`] again then, and bind the undo manager
    /// to it.
    pub fn replaced(&self) -> watch::Receiver<u64> {
        self.shared.replaced.subscribe()
    }

    /// Runs `hook` on each replacement, with the new document and its
    /// generation, before the handle refers to it and before
    /// [`Lent::replaced`] wakes: what must be bound to the new document
    /// before the application can write to it, such as an undo manager,
    /// binds here. The hook runs on the task that takes the replacement,
    /// after the pending operations were carried over.
    pub fn on_replaced(&self, hook: impl Fn(&LoroDoc, u64) + Send + Sync + 'static) {
        self.shared
            .hooks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Box::new(hook));
    }

    /// [`Lent::on_replaced`], with the hook run once now on the current
    /// document and its generation, under the same lock as a replacement
    /// takes: no replacement falls between that first run and the hook's
    /// registration.
    pub(crate) fn bind_replaced(&self, hook: impl Fn(&LoroDoc, u64) + Send + Sync + 'static) {
        let mut hooks = self
            .shared
            .hooks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        hook(
            &self.shared.doc(),
            self.shared.generation.load(Ordering::SeqCst),
        );
        hooks.push(Box::new(hook));
    }

    /// The failure of the last unit tried, as a watch: `Some` while the
    /// engine refuses the unit and the handle tries again, `None` once a
    /// unit is written; and `Some` once a carried change could not be
    /// placed, until the next replacement. [`Lent::flush`] returns a
    /// unit's failure.
    pub fn failed(&self) -> watch::Receiver<Option<Error>> {
        self.shared.failed.subscribe()
    }

    /// Suggests a change (adapter-loro.md, section 3.4): `update`, Loro's
    /// bytes for operations over the document's current state, made on a
    /// fork of it (`LoroDoc::fork`), never committed to the lent document.
    /// It enters the document only once accepted ([`Document::accept`]).
    ///
    /// # Errors
    ///
    /// As [`Document::suggest`].
    pub async fn suggest(&self, update: &[u8]) -> Result<()> {
        self.shared.document.suggest(update).await.map(drop)
    }

    /// The document this handle was lent from.
    pub fn document(&self) -> &Document {
        &self.shared.document
    }

    /// Whether the handle still writes: `false` once the device is gone.
    pub fn is_open(&self) -> bool {
        !self.shared.closed.load(Ordering::SeqCst)
    }
}
