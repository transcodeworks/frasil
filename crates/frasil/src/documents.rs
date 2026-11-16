//! Loro documents (adapter-loro.md), through the device.
//!
//! A writer edits a fork of the stream's current document under the peer
//! ID of an incarnation that begins at its unit's own `seq`
//! (adapter-loro.md, "Writing"), so it never continues an incarnation it
//! may have lost; the unit carries Loro's bytes for those operations.

use crate::device::Engine;
use crate::error::{Error, Result};
use crate::replica::Replica;
use crate::text::{Comparison, TextSplice, divide};
use frasil_adapter_loro::write::{Writer, export_unit};
use frasil_adapter_loro::{Counter, Incarnation, Loro, State};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_units::limits::MAX_UNIT_BYTES;
use frasil_units::runtime::Stream;
use frasil_units::stream::{Opening, StreamId};
use loro::{IntoContainerId, LoroDoc, LoroText, TextDelta};
use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

/// The peer IDs live and lent incarnations of this process hold: two
/// handles never take the same incarnation, even before either has
/// written.
static LIVE_PEERS: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

/// The most `seq`s [`Engine::begin_live`] tries.
const LIVE_TRIES: u64 = 4096;

/// What one unit of a text change holds, as [`divide`] prices it. Far below
/// the limit on a signed unit (units.md, "Limits"), because importing a
/// change takes time in the square of the text it inserts, at every replica
/// and under its engine: 800 KB takes seconds as one change, and a tenth of
/// that as units of this size, whatever order they arrive in.
const TEXT_PER_UNIT: usize = 64 * 1024;

/// The most a unit's content may be: below the limit on a signed unit by
/// more than its other fields take.
const MOST_CONTENT: usize = MAX_UNIT_BYTES - 16 * 1024;

/// How a change of a text ended, from [`Engine::write_document_text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextOutcome {
    /// The text was already this: nothing was written.
    Unchanged,
    /// The changed parts were written as small edits, which merge with
    /// other writers' within a line.
    Edited,
    /// The changed part was replaced in one operation, because most of the
    /// text changed or the time limit passed. It merges with another
    /// writer's change as a block.
    Replaced,
}

/// What a change of a text did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextWritten {
    /// How it ended.
    pub outcome: TextOutcome,
    /// How many units it took: more than one when it did not fit one.
    pub units: usize,
    /// Whether the document took another change after the comparison began.
    /// The new text was then written as a change concurrent with it, and
    /// the two merged, so the document holds both and may differ from the
    /// text given: nothing of the other change was overwritten.
    pub moved: bool,
    /// Whether the time limit passed, so that the text was replaced rather
    /// than compared.
    pub limit_passed: bool,
}

/// Applies splices to the text they were compared against, as one delta:
/// inserting and deleting one by one takes time in the document's
/// length for each. What an application on a document of its own uses in
/// place of `LoroText::update`, with
/// [`compare_text`](crate::advanced::documents::compare_text).
///
/// # Errors
///
/// [`Error::Adapter`] when a splice does not fit the text.
pub fn apply_splices(text: &LoroText, splices: &[TextSplice]) -> Result<()> {
    let mut delta = Vec::with_capacity(splices.len() * 3);
    let mut cursor = 0;
    for splice in splices {
        if splice.at > cursor {
            delta.push(TextDelta::Retain {
                retain: splice.at - cursor,
                attributes: None,
            });
        }
        if !splice.insert.is_empty() {
            delta.push(TextDelta::Insert {
                insert: splice.insert.clone(),
                attributes: None,
            });
        }
        if splice.delete > 0 {
            delta.push(TextDelta::Delete {
                delete: splice.delete,
            });
        }
        cursor = splice.at + splice.delete;
    }
    text.apply_delta(&delta)
        .map_err(|e| Error::Adapter(e.to_string()))
}

/// A division of a text change on `doc`, as a unit's content of
/// `incarnation`.
fn write_division(
    doc: &LoroDoc,
    text: &LoroText,
    incarnation: Incarnation,
    division: &[TextSplice],
) -> Result<Vec<u8>> {
    let adapter = |e: &dyn core::fmt::Display| Error::Adapter(e.to_string());
    let mut writer = Writer::new(doc, incarnation).map_err(|e| adapter(&e))?;
    apply_splices(text, division)?;
    let content = writer
        .edit(doc)
        .map_err(|e| adapter(&e))?
        .ok_or_else(|| Error::Adapter("the change made no operation".into()))?
        .encode();
    if content.len() > MOST_CONTENT {
        return Err(Error::class(frasil_base::ErrorClass::TooLarge));
    }
    Ok(content)
}

/// A document lent to the application, from [`Engine::begin_lent`].
#[derive(Debug, Clone)]
pub struct Lending {
    /// The incarnation the application writes under: its peer is the
    /// document's peer ID.
    pub incarnation: Incarnation,
    /// A reference to the replica's main document.
    pub doc: LoroDoc,
    /// The state's generation the reference belongs to.
    pub generation: u64,
}

/// A lent document as the replica holds it now, from [`Engine::lent_doc`].
#[derive(Debug, Clone)]
pub struct LentDoc {
    /// A reference to the replica's main document, writing under the lent
    /// incarnation's peer.
    pub doc: LoroDoc,
    /// The state's generation the reference belongs to.
    pub generation: u64,
    /// Whether the rebuilt document no longer holds every operation a
    /// flush wrote under the lent incarnation: a unit of its own was
    /// refused or withdrawn, and the incarnation may be lost
    /// (adapter-loro.md, section 3.1), or an accepted one waits inside
    /// Loro on a refused unit (section 3.3). The application renews the
    /// incarnation ([`Engine::renew_lent`]) and writes the operations again
    /// under the new one.
    pub lost: bool,
}

/// What the engine keeps of a lent document.
#[derive(Clone)]
pub(crate) struct LentEntry {
    pub(crate) opening: Opening,
    pub(crate) incarnation: Incarnation,
    /// The counter up to which flushes wrote the incarnation's operations.
    pub(crate) written_end: Counter,
    /// What runs before each flush: the holder of the lent document brings
    /// into it what it still holds apart ([`Engine::lent_carry`]).
    pub(crate) carry: Option<Carry>,
}

/// What a holder of a lent document runs before each flush.
pub type Carry = std::sync::Arc<dyn Fn() + Send + Sync>;

/// The first incarnation at or below `next` whose peer is free, as
/// [`Engine::begin_live`] chooses one: `free` says whether the state holds
/// nothing of a peer, and no handle of this process holds it either.
fn free_incarnation(
    space: EventId,
    stream: StreamId,
    author: [u8; 32],
    next: u64,
    free: impl Fn(u64) -> bool,
) -> Result<Incarnation> {
    let mut held = LIVE_PEERS.lock().unwrap_or_else(PoisonError::into_inner);
    let used = (1..next).rev().chain([next]).take(LIVE_TRIES as usize);
    for seq in used {
        let incarnation = Incarnation {
            space: space.0,
            stream,
            author,
            incarnation: seq,
        };
        let peer = incarnation.peer();
        if free(peer) && !held.contains(&peer) {
            held.insert(peer);
            return Ok(incarnation);
        }
    }
    Err(Error::NotAllowed(
        "no incarnation is free for a live handle",
    ))
}

/// The incarnations of the `units` units of a text change, the first
/// written at `seq`: each its unit's own `seq` where that peer is free, as
/// [`Engine::write_document_text`] needs a fresh peer per unit, else the
/// nearest free one below it (check 3 allows an incarnation up to the
/// unit's `seq`, as [`Engine::begin_live`] chooses one). A peer is free when
/// the state holds, counts and suggests nothing of it, no unit waits on it,
/// and no handle of this process holds it.
fn text_incarnations(
    loro: Option<&State>,
    space: EventId,
    stream: StreamId,
    author: [u8; 32],
    seq: u64,
    units: usize,
) -> Result<Vec<Incarnation>> {
    let live = LIVE_PEERS.lock().unwrap_or_else(PoisonError::into_inner);
    let vv = loro.map(|state| state.doc().oplog_vv());
    let awaited = loro.map(State::awaited_peers).unwrap_or_default();
    let suggested: BTreeSet<u64> = loro
        .map(|state| {
            state
                .layer()
                .values()
                .map(|(suggestion, _)| suggestion.written.peer)
                .collect()
        })
        .unwrap_or_default();
    let free = |peer: u64| {
        !live.contains(&peer)
            && !awaited.contains(&peer)
            && !suggested.contains(&peer)
            && vv
                .as_ref()
                .is_none_or(|vv| vv.get(&peer).copied().unwrap_or(0) == 0)
            && loro.is_none_or(|state| state.committed_end(peer) == 0)
    };
    let mut planned: Vec<Incarnation> = Vec::with_capacity(units);
    for at in (seq..).take(units) {
        let found = (1..=at)
            .rev()
            .take(LIVE_TRIES as usize)
            .map(|incarnation| Incarnation {
                space: space.0,
                stream,
                author,
                incarnation,
            })
            .find(|candidate| !planned.contains(candidate) && free(candidate.peer()))
            .ok_or(Error::NotAllowed(
                "no incarnation is free for a change of a text",
            ))?;
        planned.push(found);
    }
    Ok(planned)
}

/// Whether a refused unit of this device in `stream` holds an edit of an
/// incarnation a lent document's holder expresses: the one lent now, whose
/// holder renews it and writes its operations again once it takes the
/// rebuild, or one it renewed away from ([`Engine::renew_lent`]).
/// Re-submitting it as well would hold them twice.
pub(crate) fn expressed_again(
    state: &crate::device::State,
    space: EventId,
    stream: StreamId,
    inner: &frasil_units::Inner,
) -> bool {
    if inner.type_ != frasil_adapter_loro::TYPE {
        return false;
    }
    match frasil_adapter_loro::Content::read(&inner.content) {
        Ok(frasil_adapter_loro::Content::Ops {
            role: frasil_adapter_loro::ContentRole::Edit,
            incarnation,
            ..
        }) => {
            state
                .lent
                .get(&(space, stream))
                .is_some_and(|entry| entry.incarnation.incarnation == incarnation)
                || state
                    .expressed_again
                    .contains(&(space, stream, incarnation))
        }
        _ => false,
    }
}

/// The `state` record of `space` with the incarnations its lent documents
/// expressed again (`state` key 8, [`frasil_store::expressed_again`]),
/// when the record at rest does not hold them all yet.
async fn expressed_again_record(
    state: &mut crate::device::State,
    space: EventId,
) -> Result<
    Option<(
        frasil_store::Table,
        Vec<u8>,
        Option<frasil_store::TableValue>,
    )>,
> {
    let mut log_state = crate::device::log_state(&state.vault, &space.0).await?;
    let held = log_state.expressed_again.clone().unwrap_or_default();
    let mut wanted = held.clone();
    wanted.0.extend(
        state
            .expressed_again
            .iter()
            .filter(|(s, _, _)| *s == space)
            .map(|(_, stream, incarnation)| (*stream, *incarnation)),
    );
    if wanted == held {
        return Ok(None);
    }
    log_state.expressed_again = Some(wanted);
    Ok(Some((
        frasil_store::Table::State,
        Vec::new(),
        Some(frasil_store::TableValue::State(log_state)),
    )))
}

const _: () = assert!(
    core::mem::size_of::<StreamId>() == frasil_store::expressed_again::STREAM_BYTES,
    "a stream ID at rest is a stream ID"
);

/// Keeps each local commit of a lent document a change of its own: Loro
/// otherwise merges a peer's consecutive changes within its merge interval,
/// and a unit written after another would carry the earlier unit's time in
/// its blob. History reads each unit's time from its blob.
fn unmerged(doc: &LoroDoc) {
    doc.set_change_merge_interval(-1);
}

/// Runs `work` where it holds up neither the engine nor the async worker;
/// in a browser, which has one thread, in place.
async fn off_the_engine<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|e| Error::Adapter(e.to_string()))?
    }
    #[cfg(target_arch = "wasm32")]
    {
        work()
    }
}

/// The Loro state of a stream, if the replica reads it.
pub fn loro_state<'r>(replica: &'r Replica, stream: &StreamId) -> Option<&'r State> {
    replica
        .stream(stream)?
        .as_any()
        .downcast_ref::<Stream<Loro>>()
        .map(Stream::state)
}

impl Engine {
    /// A new Loro document's opening (adapter-loro.md): the stream exists
    /// from its first unit.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    pub fn new_document(&self) -> Result<Opening> {
        self.new_stream(frasil_adapter_loro::TYPE)
    }

    /// Edits a Loro document: `edit` changes a fork of its current state,
    /// and the operations it makes are written as one unit.
    ///
    /// # Errors
    ///
    /// [`Error::Adapter`] when the edit makes no operation or Loro fails;
    /// as [`Engine::write_unit`].
    pub async fn edit_document(
        &self,
        space: EventId,
        document: &Opening,
        edit: impl FnOnce(&LoroDoc),
    ) -> Result<EventId> {
        self.try_edit_document(space, document, |doc| {
            edit(doc);
            Ok::<(), core::convert::Infallible>(())
        })
        .await
    }

    /// [`Engine::edit_document`] with an edit that may fail: when it does,
    /// nothing is written.
    ///
    /// # Errors
    ///
    /// [`Error::Adapter`] with the edit's failure; as
    /// [`Engine::edit_document`].
    pub async fn try_edit_document<E: core::fmt::Display>(
        &self,
        space: EventId,
        document: &Opening,
        edit: impl FnOnce(&LoroDoc) -> core::result::Result<(), E>,
    ) -> Result<EventId> {
        let author = self.device_id().0;
        self.write_unit(space, document, |replica, seq| {
            let loro = loro_state(replica, &document.stream());
            let doc = loro.map_or_else(LoroDoc::new, |state| state.doc().fork());
            let mut incarnation = Incarnation {
                space: space.0,
                stream: document.stream(),
                author,
                incarnation: seq,
            };
            // A unit waits on this peer's operations, from a change of a
            // text whose writer stopped part way: new ones would stand in
            // for them.
            if loro.is_some_and(|state| state.awaited_peers().contains(&incarnation.peer())) {
                incarnation = text_incarnations(loro, space, document.stream(), author, seq, 1)?
                    .pop()
                    .ok_or(Error::Invalid("an edit has an incarnation"))?;
            }
            doc.set_record_timestamp(true);
            let mut writer =
                Writer::new(&doc, incarnation).map_err(|e| Error::Adapter(e.to_string()))?;
            edit(&doc).map_err(|e| Error::Adapter(e.to_string()))?;
            let content = writer
                .edit(&doc)
                .map_err(|e| Error::Adapter(e.to_string()))?
                .ok_or_else(|| Error::Adapter("the edit made no operation".into()))?;
            Ok(content.encode())
        })
        .await
    }

    /// Sets a text container of a Loro document, by its root name or its
    /// `ContainerID`, to a new text, by what `compare` finds between its current text and the new one
    /// ([`compare_text`](crate::advanced::documents::compare_text)).
    ///
    /// `compare` runs with the engine free, off the async worker, so a slow
    /// comparison stalls nothing else on the device. Only writing its
    /// splices holds the engine.
    ///
    /// Its splices are applied to the version it compared, not to the
    /// document as it is by then. **A document that moved meanwhile** so
    /// takes the change as a change concurrent with what moved it, the
    /// same as if the other writer's had arrived a moment later: every
    /// replica merges the two alike, and neither overwrites the other
    /// ([`TextWritten::moved`]).
    ///
    /// **A change of much text** is divided, well below the limit on a unit
    /// (units.md, "Limits"), since a smaller change imports faster at every
    /// replica. Each unit is an edit with an incarnation of its own (adapter-loro.md,
    /// section 3.1), and the operations of each depend on those of the next
    /// unit written: the first unit written holds the last operations. A
    /// replica that lacks a unit of the change accepts the ones it has,
    /// since no check of section 3.2 looks at a blob's Loro `deps` on
    /// other peers, and Loro holds their operations pending until the
    /// changes they depend on arrive, as it does for operations that
    /// depend on a refused unit's (section 3.3). Its text stays as it was
    /// until the last unit arrives.
    ///
    /// **Each unit is its own commit.** An error after the first leaves the
    /// units before it written, signed and syncing: every replica holds
    /// them pending for good, shows the text as it was, and lists them in
    /// history as applied. A later call writes from the next `seq` as
    /// usual, under peers those units do not wait on.
    ///
    /// # Errors
    ///
    /// `compare`'s, with nothing written; [`Error::NotAllowed`] when no
    /// incarnation is free for a unit, with nothing written;
    /// [`Error::Adapter`] when Loro fails; `TooLarge`; as
    /// [`Engine::write_unit`], such as [`Error::Store`], possibly after
    /// some units were written.
    pub async fn write_document_text(
        &self,
        space: EventId,
        document: &Opening,
        container: impl IntoContainerId,
        compare: impl FnOnce(String) -> Result<Comparison> + Send + 'static,
    ) -> Result<TextWritten> {
        let stream = document.stream();
        let base = match self.document(&space, &stream).await {
            Err(Error::UnknownStream) => LoroDoc::new(),
            read => read?,
        };
        let text = base.get_text(container);
        let current = text.to_string();
        let comparison = off_the_engine(move || compare(current)).await?;
        if comparison.splices.is_empty() {
            return Ok(TextWritten {
                outcome: TextOutcome::Unchanged,
                units: 0,
                moved: false,
                limit_passed: false,
            });
        }
        let divisions = divide(comparison.splices, TEXT_PER_UNIT);
        let units = divisions.len();
        let version = base.oplog_frontiers();
        base.set_record_timestamp(true);
        let author = self.device_id().0;
        let mut state = self.lock().await;
        let mut moved = false;
        let mut contents: Vec<Vec<u8>> = Vec::with_capacity(units);
        let mut first = 0;
        self.write_parts(
            &mut state,
            space,
            stream,
            Some(document.clone()),
            &document.type_,
            |replica, seq, _| {
                first = seq;
                let loro = loro_state(replica, &stream);
                moved = loro.is_some_and(|state| state.doc().oplog_frontiers() != version);
                let planned = text_incarnations(loro, space, stream, author, seq, units)?;
                for (index, division) in divisions.iter().enumerate() {
                    // The last division is written first: see above.
                    let of_unit = planned[units - 1 - index];
                    contents.push(write_division(&base, &text, of_unit, division)?);
                }
                contents.reverse();
                Ok(crate::device::UnitParts {
                    content: core::mem::take(
                        contents
                            .first_mut()
                            .ok_or(Error::Invalid("a change of a text has a unit"))?,
                    ),
                    ..crate::device::UnitParts::default()
                })
            },
        )
        .await?;
        for (index, content) in contents.into_iter().enumerate().skip(1) {
            self.write_parts_now(
                &mut state,
                space,
                stream,
                Some(document.clone()),
                &document.type_,
                |_, seq, _| {
                    if seq != first + index as u64 {
                        return Err(Error::Adapter("another unit came between".into()));
                    }
                    Ok(crate::device::UnitParts {
                        content,
                        ..crate::device::UnitParts::default()
                    })
                },
            )
            .await?;
        }
        Ok(TextWritten {
            outcome: if comparison.replaced {
                TextOutcome::Replaced
            } else {
                TextOutcome::Edited
            },
            units,
            moved,
            limit_passed: comparison.limit_passed,
        })
    }

    /// A copy of a Loro document's current state, as this device's replica
    /// holds it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`].
    pub async fn document(&self, space: &EventId, stream: &StreamId) -> Result<LoroDoc> {
        self.read(space, |replica| {
            loro_state(replica, stream).map(|state| state.doc().fork())
        })
        .await?
        .ok_or(Error::UnknownStream)
    }

    /// Begins a live incarnation of this device in a Loro document
    /// (adapter-loro.md, section 3.1, "Writing"), and a copy of the
    /// document's current state.
    ///
    /// Its incarnation is a `seq` this device has already used in the
    /// space, or the next one, so it is never above the `seq` of a unit it
    /// writes later; and its peer holds no operation in the document nor in
    /// its suggestion layer, so it begins there. A later edit begins its own
    /// incarnation at a `seq` above it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] when no `seq` is free.
    pub async fn begin_live(
        &self,
        space: EventId,
        document: &Opening,
    ) -> Result<(Incarnation, LoroDoc)> {
        let author = self.device_id().0;
        let stream = document.stream();
        let state = self.lock().await;
        let (next, _) = Self::next(&state, &space, &DeviceId(author));
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let loro = loro_state(replica, &stream);
        let doc = loro.map_or_else(LoroDoc::new, |state| state.doc().fork());
        let vv = doc.oplog_vv();
        let suggested: BTreeSet<u64> = loro
            .map(|state| {
                state
                    .layer()
                    .values()
                    .map(|(suggestion, _)| suggestion.written.peer)
                    .collect()
            })
            .unwrap_or_default();
        let based = |peer: u64| {
            loro.and_then(|state| state.base_counters().get(&peer).copied())
                .unwrap_or(0)
                > 0
        };
        // A peer the units count (step 6), its units withdrawn or not, is
        // never begun again: a unit under it would overlap.
        let counted = |peer: u64| loro.is_some_and(|state| state.committed_end(peer) > 0);
        let awaited = loro.map(State::awaited_peers).unwrap_or_default();
        let incarnation = free_incarnation(space, stream, author, next, |peer| {
            vv.get(&peer).copied().unwrap_or(0) == 0
                && !suggested.contains(&peer)
                && !based(peer)
                && !counted(peer)
                && !awaited.contains(&peer)
        })?;
        Ok((incarnation, doc))
    }

    /// Lends a Loro document to the application (decision: one document):
    /// a reference to the replica's own main document, with this device's
    /// fresh incarnation as its peer ID, which the application edits
    /// directly. [`Engine::flush_lent`] writes the operations it commits
    /// as units; the state's generation says when the document was built
    /// again and the reference must be taken anew ([`Engine::lent_doc`]).
    /// A document not yet written in gets its stream's runtime now.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] when the document is
    /// lent already, or no incarnation is free; [`Error::Adapter`] when
    /// Loro refuses the peer ID.
    pub async fn begin_lent(&self, space: EventId, document: &Opening) -> Result<Lending> {
        let author = self.device_id().0;
        let stream = document.stream();
        let mut state = self.lock().await;
        if state.lent.contains_key(&(space, stream)) {
            return Err(Error::NotAllowed("the document is lent already"));
        }
        let (next, _) = Self::next(&state, &space, &DeviceId(author));
        let registry = self.registry();
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        if !replica.open_stream(stream, &document.type_, registry) {
            return Err(Error::Adapter("no adapter for the document".into()));
        }
        let loro = loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
        let vv = loro.doc().oplog_vv();
        let suggested: BTreeSet<u64> = loro
            .layer()
            .values()
            .map(|(suggestion, _)| suggestion.written.peer)
            .collect();
        let awaited = loro.awaited_peers();
        let incarnation = free_incarnation(space, stream, author, next, |peer| {
            vv.get(&peer).copied().unwrap_or(0) == 0
                && !suggested.contains(&peer)
                && loro.committed_end(peer) == 0
                && !awaited.contains(&peer)
        })?;
        let doc = loro.doc().clone();
        doc.set_peer_id(incarnation.peer())
            .map_err(|e| Error::Adapter(e.to_string()))?;
        unmerged(&doc);
        // The writer's clock in each change, for history: shown, never
        // checked.
        doc.set_record_timestamp(true);
        let generation = loro.generation();
        state.lent.insert(
            (space, stream),
            LentEntry {
                opening: document.clone(),
                incarnation,
                written_end: 0,
                carry: None,
            },
        );
        Ok(Lending {
            incarnation,
            doc,
            generation,
        })
    }

    /// Renews a lent document's incarnation: a fresh one, whose peer the
    /// document now writes under, for operations the units no longer hold
    /// to be written again under it ([`LentDoc::lost`]). The old
    /// incarnation ends, and is never continued.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`] when the document
    /// is not lent; [`Error::NotAllowed`] when no incarnation is free;
    /// [`Error::Adapter`] when Loro refuses the peer ID.
    pub async fn renew_lent(&self, space: EventId, stream: StreamId) -> Result<Lending> {
        let author = self.device_id().0;
        let mut state = self.lock().await;
        let entry = state
            .lent
            .get(&(space, stream))
            .cloned()
            .ok_or(Error::UnknownStream)?;
        let (next, _) = Self::next(&state, &space, &DeviceId(author));
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let loro = loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
        let vv = loro.doc().oplog_vv();
        let suggested: BTreeSet<u64> = loro
            .layer()
            .values()
            .map(|(suggestion, _)| suggestion.written.peer)
            .collect();
        let old = entry.incarnation.peer();
        let awaited = loro.awaited_peers();
        let incarnation = free_incarnation(space, stream, author, next, |peer| {
            peer != old
                && vv.get(&peer).copied().unwrap_or(0) == 0
                && !suggested.contains(&peer)
                && loro.committed_end(peer) == 0
                && !awaited.contains(&peer)
        })?;
        LIVE_PEERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&old);
        let doc = loro.doc().clone();
        doc.set_peer_id(incarnation.peer())
            .map_err(|e| Error::Adapter(e.to_string()))?;
        unmerged(&doc);
        doc.set_record_timestamp(true);
        let generation = loro.generation();
        // The holder writes the old incarnation's operations again under
        // the new one: its refused units are not re-submitted as well,
        // which would hold them twice.
        state
            .expressed_again
            .insert((space, stream, entry.incarnation.incarnation));
        state.lent.insert(
            (space, stream),
            LentEntry {
                opening: entry.opening,
                incarnation,
                written_end: 0,
                carry: entry.carry,
            },
        );
        Ok(Lending {
            incarnation,
            doc,
            generation,
        })
    }

    /// The lent document as the replica holds it now, with its state's
    /// generation: the same document while the generation is the one
    /// [`Lending`] gave, a replacement once the state was built again. The
    /// replacement writes under the lent incarnation's peer. `lost` says
    /// whether a unit written under the incarnation was withdrawn.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`] when the document
    /// is not lent; [`Error::Adapter`] when Loro refuses the peer ID.
    pub async fn lent_doc(&self, space: EventId, stream: StreamId) -> Result<LentDoc> {
        let state = self.lock().await;
        let entry = state
            .lent
            .get(&(space, stream))
            .ok_or(Error::UnknownStream)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let loro = loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
        let doc = loro.doc().clone();
        let peer = entry.incarnation.peer();
        if doc.peer_id() != peer {
            doc.set_peer_id(peer)
                .map_err(|e| Error::Adapter(e.to_string()))?;
        }
        unmerged(&doc);
        // A rebuilt document is a new `LoroDoc`: its writer's clock goes
        // into each change again (history's time).
        doc.set_record_timestamp(true);
        // Operations of the incarnation a flush wrote and the rebuilt
        // document does not hold: in a unit refused or withdrawn, or in an
        // accepted one that waits inside Loro on a refused unit
        // (adapter-loro.md, section 3.3). Either way the incarnation does
        // not go on: a new operation would take a counter they hold.
        let held = loro.doc().oplog_vv().get(&peer).copied().unwrap_or(0);
        Ok(LentDoc {
            doc,
            generation: loro.generation(),
            lost: loro.applied_end(peer).min(held) < entry.written_end,
        })
    }

    /// Writes the operations the application committed to a lent document
    /// since the last unit as one unit, or as many, one after another, as
    /// step 4 of the checks needs (adapter-loro.md, section 3.1):
    /// those of the lent incarnation's peer beyond the counter the units
    /// hold. Nothing is written when there are none. The unit, once
    /// placed, counts at the state, and the document is as it was. The ID
    /// is the last unit's.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`]; [`Error::Adapter`] when Loro does not
    /// export, or when one of Loro's changes alone breaks a limit of step 4.
    pub async fn flush_lent(&self, space: EventId, stream: StreamId) -> Result<Option<EventId>> {
        let carry = self
            .lock()
            .await
            .lent
            .get(&(space, stream))
            .and_then(|entry| entry.carry.clone());
        if let Some(carry) = carry {
            // Off the async worker: the holder's carry may replay.
            #[cfg(not(target_arch = "wasm32"))]
            let _ = tokio::task::spawn_blocking(move || carry()).await;
            #[cfg(target_arch = "wasm32")]
            carry();
        }
        let mut state = self.lock().await;
        let Some(entry) = state.lent.get(&(space, stream)).cloned() else {
            return Ok(None);
        };
        let peer = entry.incarnation.peer();
        let incarnation = entry.incarnation;
        let mut end = entry.written_end;
        // The incarnations expressed again, at rest in the commit of the
        // first unit that writes their operations again.
        let mut expressed = expressed_again_record(&mut state, space).await?;
        // What each unit written here holds, so that the next starts after
        // it whatever the state counted.
        let mut written: Counter = 0;
        let mut last = None;
        loop {
            let pending = {
                let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                let loro = loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
                let doc_end = loro.doc().oplog_vv().get(&peer).copied().unwrap_or(0);
                doc_end > loro.committed_end(peer).max(written)
            };
            if !pending {
                break;
            }
            // As many units as step 4 of the checks needs (adapter-loro.md,
            // section 3.1), one after another.
            let id = self
                .write_parts(
                    &mut state,
                    space,
                    stream,
                    Some(entry.opening.clone()),
                    &entry.opening.type_,
                    |replica, _, _| {
                        let loro = loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
                        let from = loro.committed_end(peer).max(written);
                        let (blob, span) = export_unit(loro.doc(), peer, from)
                            .map_err(|e| Error::Adapter(e.to_string()))?
                            .ok_or_else(|| Error::Adapter("nothing to write".into()))?;
                        end = end.max(span.end);
                        written = span.end;
                        Ok(crate::device::UnitParts {
                            content: frasil_adapter_loro::Content::edit(
                                incarnation.incarnation,
                                blob,
                            )
                            .encode(),
                            records: expressed.take().into_iter().collect(),
                            ..crate::device::UnitParts::default()
                        })
                    },
                )
                .await?;
            if let Some(entry) = state.lent.get_mut(&(space, stream))
                && entry.incarnation == incarnation
            {
                entry.written_end = end;
            }
            last = Some(id);
        }
        Ok(last)
    }

    /// Sets what runs before each flush of a lent document: the holder
    /// brings into the document what it still holds apart (commits to a
    /// reference from before a replacement), so that every flush, the
    /// device's close and the exports included, writes them.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownStream`] when the document is not lent.
    pub async fn lent_carry(&self, space: EventId, stream: StreamId, carry: Carry) -> Result<()> {
        let mut state = self.lock().await;
        let entry = state
            .lent
            .get_mut(&(space, stream))
            .ok_or(Error::UnknownStream)?;
        entry.carry = Some(carry);
        Ok(())
    }

    /// [`Engine::flush_lent`] for every document lent in `space`: what runs
    /// before the space's streams are exported, so that an export never
    /// carries an operation no unit holds.
    ///
    /// # Errors
    ///
    /// As [`Engine::flush_lent`].
    pub async fn flush_lent_in(&self, space: EventId) -> Result<()> {
        let streams: Vec<StreamId> = {
            let state = self.lock().await;
            state
                .lent
                .keys()
                .filter(|(s, _)| *s == space)
                .map(|(_, stream)| *stream)
                .collect()
        };
        for stream in streams {
            self.flush_lent(space, stream).await?;
        }
        Ok(())
    }

    /// [`Engine::flush_lent`] for every lent document: what a device does
    /// as it closes.
    ///
    /// # Errors
    ///
    /// As [`Engine::flush_lent`].
    pub async fn flush_all_lent(&self) -> Result<()> {
        let keys: Vec<(EventId, StreamId)> = self.lock().await.lent.keys().copied().collect();
        for (space, stream) in keys {
            self.flush_lent(space, stream).await?;
        }
        Ok(())
    }

    /// Ends a lent document's incarnation: what remains unwritten is
    /// written first. The application's reference goes on reading, and
    /// writes nothing more that Frasil takes.
    ///
    /// # Errors
    ///
    /// As [`Engine::flush_lent`].
    pub async fn end_lent(&self, space: EventId, stream: StreamId) -> Result<()> {
        let flushed = self.flush_lent(space, stream).await;
        if let Some(entry) = self.lock().await.lent.remove(&(space, stream)) {
            LIVE_PEERS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&entry.incarnation.peer());
        }
        flushed.map(drop)
    }

    /// Suggests a change to a Loro document (adapter-loro.md, section
    /// 3.4): `update`, Loro's bytes for operations over the document's
    /// current state, is written again under the suggestion's own
    /// incarnation, its `seq`, as one suggestion unit.
    ///
    /// # Errors
    ///
    /// [`Error::Adapter`] when Loro does not read `update`, or it changes
    /// nothing; as [`Engine::write_unit`].
    pub async fn suggest_document(
        &self,
        space: EventId,
        document: &Opening,
        update: &[u8],
    ) -> Result<EventId> {
        let author = self.device_id().0;
        let adapter = |e: &dyn core::fmt::Display| Error::Adapter(e.to_string());
        self.write_unit(space, document, |replica, seq| {
            let main = match loro_state(replica, &document.stream()) {
                Some(state) => state.doc().fork(),
                None => LoroDoc::new(),
            };
            let changed = main.fork();
            let before = changed.oplog_frontiers();
            changed.import(update).map_err(|e| adapter(&e))?;
            let after = changed.oplog_frontiers();
            let diff = changed.diff(&before, &after).map_err(|e| adapter(&e))?;
            let incarnation = Incarnation {
                space: space.0,
                stream: document.stream(),
                author,
                incarnation: seq,
            };
            let mut writer = Writer::new(&main, incarnation).map_err(|e| adapter(&e))?;
            main.apply_diff(diff).map_err(|e| adapter(&e))?;
            let content = writer
                .suggestion(&main)
                .map_err(|e| adapter(&e))?
                .ok_or_else(|| Error::Adapter("the suggestion makes no operation".into()))?;
            Ok(content.encode())
        })
        .await
    }

    /// Writes a Loro unit of these contents (adapter-loro.md, section 2.2):
    /// an accept or a dismiss.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    pub async fn write_document_content(
        &self,
        space: EventId,
        document: &Opening,
        content: frasil_adapter_loro::Content,
    ) -> Result<EventId> {
        self.write_unit(space, document, |_, _| Ok(content.encode()))
            .await
    }
}
