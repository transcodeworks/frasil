//! A Loro stream's state: the main document, the suggestion layer, and
//! what steps 6 and 7 of the checks read (adapter-loro.md, sections 3.2 to
//! 3.5).
//!
//! **Derived, not accumulated.** The main document is always the base
//! snapshot's `main` with the blobs of the stream's accepted edits and
//! accepted suggestions imported. Loro's import is order-independent and
//! idempotent, so the state does not depend on the order in which units
//! arrive. When a unit already imported is found refused, as when an
//! earlier unit of the same peer arrives that overlaps it, the document is
//! built again without it (section 3.3, "Merge and rebuild").
//!
//! **Canonical order among one peer's units.** Step 6 compares a unit with
//! the units of its peer earlier in canonical order (events.md, by height,
//! then event ID), which the context's height gives.
//!
//! **Re-submissions.** Step 6 does not count the units a unit re-submits
//! (units.md, 3.11 "Re-submission"): the unit its `resubmits` names, the one
//! that unit's `resubmits` names, and so on, each only where its content is
//! byte for byte the re-submission's. The state keeps each placed unit's
//! `resubmits` and a digest of each counted unit's content for that.

use crate::LoroClass;
use crate::checks::{Change, Written, check_overlap, counted_span};
use crate::guard::{self, Import};
use crate::meta::{BlobMeta, Counter, OpId, Span};
use crate::peer::PeerId;
use crate::snapshot::{LayerRow, SnapshotState};
use frasil_adapter::{Author, Context, EventId};
use frasil_base::collect::CollectMap;
use frasil_base::errors::ErrorClass;
use frasil_crypto::primitives::sha256;
use loro::{EncodedBlobMode, ExportMode, LoroDoc, VersionVector};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

/// A unit's place in canonical order: its height, then its event ID.
type Place = (u64, EventId);

/// The SHA-256 digest of a unit's content: what step 6 compares a
/// re-submission's content with.
type Digest = [u8; 32];

/// A unit step 6 counts: its ID, its span, and its content's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counted {
    unit: EventId,
    span: Span,
    content: Digest,
}

/// One suggestion of the layer: its author and its operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Suggestion {
    /// The suggestion's author.
    pub author: Author,
    /// Its operations: its incarnation is its own `seq`.
    pub written: Written,
}

/// Where a suggestion stands (adapter-loro.md, section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Standing {
    /// No applied accept or dismiss names it.
    Open,
    /// Only dismisses name it.
    Dismissed,
    /// An accept names it: it is part of the main document.
    Accepted,
}

/// An applied accept or dismiss.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Closer {
    accept: bool,
    targets: Vec<EventId>,
}

/// What the base snapshot holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Base {
    /// Key 2, as loaded.
    main: Option<Vec<u8>>,
    /// Whether `main` is a shallow snapshot.
    history_free: bool,
    /// The counters the base snapshot holds per peer.
    counters: BTreeMap<PeerId, Counter>,
    /// Keys 3 and 4: the suggestions it holds.
    layer: BTreeMap<EventId, Suggestion>,
    /// Key 4: those dismissed.
    dismissed: BTreeSet<EventId>,
}

/// What [`State::refresh`] derives from the units.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Derived {
    /// Applied edits and suggestions refused at step 6.
    overlapped: BTreeSet<EventId>,
    /// Accepts and dismisses whose targets are all held.
    effective: BTreeSet<EventId>,
    /// Suggestions named by an effective accept.
    accepted: BTreeSet<EventId>,
    /// Suggestions named by an effective dismiss or in the base's key 4.
    dismissed: BTreeSet<EventId>,
}

/// Generations of main documents, one per document built: a state built
/// again has a new one, so a holder of a reference to its document knows
/// to take the replacement.
static GENERATIONS: AtomicU64 = AtomicU64::new(1);

fn next_generation() -> u64 {
    GENERATIONS.fetch_add(1, Ordering::Relaxed)
}

/// A Loro stream's state.
pub struct State {
    doc: LoroDoc,
    /// The main document's generation: new with each document built.
    generation: u64,
    base: Base,
    /// Every unit handed over: what step 7 holds as a unit.
    placed: BTreeSet<EventId>,
    /// What step 6 counts: the span of every placed unit whose content
    /// passes steps 1 and 3 to 5, by peer and place.
    ledger: BTreeMap<PeerId, BTreeMap<Place, Counted>>,
    /// The `resubmits` of each placed unit that has one.
    resubmits: BTreeMap<EventId, EventId>,
    /// Applied edits, with their places.
    edits: BTreeMap<EventId, (Place, Written)>,
    /// Applied suggestions, with their places and authors.
    suggestions: BTreeMap<EventId, (Place, Suggestion)>,
    /// Applied accepts and dismisses.
    closers: BTreeMap<EventId, Closer>,
    /// The blobs imported into `doc`, by unit ID.
    imported: BTreeSet<EventId>,
    /// Blobs the pinned Loro would not import into `doc`.
    unimportable: BTreeSet<EventId>,
    /// Blobs whose import the pinned Loro panicked in, into the main
    /// document or a preview: never imported again, into any document
    /// built, since each such import leaves a document that cannot be
    /// dropped ([`guard::discard`]).
    panicked: Mutex<BTreeSet<EventId>>,
    derived: Derived,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("oplog_vv", &self.doc.oplog_vv())
            .field("value", &self.doc.get_deep_value())
            .field("open", &self.open())
            .field("dismissed", &self.dismissed())
            .finish_non_exhaustive()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// An empty document. Its own peer ID is never used: a replica never
/// commits to the main document.
/// Asks `doc` for the state of each container that `keys`, the container
/// IDs of a snapshot's state store, name: Loro decodes a container's tables
/// the first time its state is asked for, and panics on tables that do not
/// decode. A key that names no container Loro knows is left alone.
fn decode_states(doc: &LoroDoc, keys: &[Vec<u8>]) {
    use loro::{Container, ContainerID};
    for key in keys {
        let Ok(id) = ContainerID::try_from_bytes(key) else {
            continue;
        };
        match doc.get_container(id) {
            Some(Container::Text(text)) => {
                let _ = text.get_richtext_value();
            }
            Some(Container::List(list)) => {
                let _ = list.get_id_at(0);
            }
            Some(Container::MovableList(list)) => {
                let _ = list.get_creator_at(0);
            }
            Some(Container::Map(map)) => {
                let _ = map.get_last_editor("");
            }
            Some(Container::Tree(tree)) => {
                let _ = tree.nodes();
            }
            _ => {}
        }
    }
}

fn empty_doc() -> LoroDoc {
    LoroDoc::new()
}

impl State {
    /// A stream's state before any unit, over no base.
    pub fn new() -> Self {
        Self::over(Base::default(), empty_doc())
    }

    fn over(base: Base, doc: LoroDoc) -> Self {
        Self {
            doc,
            generation: next_generation(),
            base,
            placed: BTreeSet::new(),
            ledger: BTreeMap::new(),
            resubmits: BTreeMap::new(),
            edits: BTreeMap::new(),
            suggestions: BTreeMap::new(),
            closers: BTreeMap::new(),
            imported: BTreeSet::new(),
            unimportable: BTreeSet::new(),
            panicked: Mutex::new(BTreeSet::new()),
            derived: Derived::default(),
        }
    }

    /// `load(snapshot state) → state` (adapter-loro.md, section 3.3,
    /// "Rebuild"): an empty document with the state's `main` imported, and
    /// the suggestion layer restored from keys 3 and 4. A state that does
    /// not decode, that the checks of section 3.5, "Loading a state",
    /// refuse ([`snapshot::check`](crate::snapshot::check)), or whose
    /// `main` or suggestion blobs the pinned Loro does not read, is
    /// `Malformed`; so is one on which Loro panics, where panics unwind.
    ///
    /// Loro reads a container's state lazily: its value when the container
    /// is first read, its tables when it is first changed or its state
    /// first asked for. Every container's value, and the state of every
    /// container the state store holds, are read here, inside the catch, so
    /// that a value or a state Loro panics on refuses the state rather than
    /// panicking in a later read or edit (adapter-loro.md, 3.5, "Loading a
    /// state").
    pub fn load(bytes: &[u8]) -> Result<Self, ErrorClass> {
        let framed = crate::snapshot::check(bytes)?;
        let meta = guard::caught(|| LoroDoc::decode_import_blob_meta(&framed.main, true))
            .and_then(Result::ok)
            .ok_or(ErrorClass::Malformed)?;
        let history_free = match meta.mode {
            EncodedBlobMode::Snapshot => false,
            EncodedBlobMode::ShallowSnapshot => true,
            _ => return Err(ErrorClass::Malformed),
        };
        let doc = empty_doc();
        match guard::import(&doc, &framed.main) {
            Import::Imported => {}
            Import::Refused => return Err(ErrorClass::Malformed),
            Import::Panicked => {
                guard::discard(doc);
                return Err(ErrorClass::Malformed);
            }
        }
        let containers = crate::screen::state_containers(&framed.main);
        let read = containers.is_some_and(|containers| {
            guard::caught(|| {
                doc.get_deep_value();
                decode_states(&doc, &containers);
            })
            .is_some()
        });
        if !read {
            guard::discard(doc);
            return Err(ErrorClass::Malformed);
        }
        let mut counters: BTreeMap<PeerId, Counter> = doc
            .oplog_vv()
            .iter()
            .map(|(peer, counter)| (*peer, *counter))
            .collect_map();
        let mut layer = BTreeMap::new();
        let mut dismissed = BTreeSet::new();
        for (row, is_dismissed) in framed
            .suggestions
            .iter()
            .map(|row| (row, false))
            .chain(framed.dismissed.iter().map(|row| (row, true)))
        {
            let suggestion = suggestion_of(row)?;
            let peer = suggestion.written.peer;
            let end = suggestion.written.span.end;
            let counter = counters.entry(peer).or_default();
            *counter = (*counter).max(end);
            if is_dismissed {
                dismissed.insert(row.unit);
            }
            layer.insert(row.unit, suggestion);
        }
        let base = Base {
            main: Some(framed.main),
            history_free,
            counters,
            layer,
            dismissed,
        };
        let mut state = Self::over(base, doc);
        state.refresh();
        Ok(state)
    }

    /// The main document. An application reads it, and commits to it only
    /// through a lent reference, under an incarnation of its own whose
    /// operations a unit then carries (`committed_end`). Reading a root
    /// container that the document does not hold adds it, empty, to the
    /// document's value; compaction and [`matches`](Self::matches) do not
    /// see it.
    pub fn doc(&self) -> &LoroDoc {
        &self.doc
    }

    /// The main document's generation: it changes whenever the main
    /// document is built again (section 3.3, "Rebuild"), so a holder of a
    /// reference to it (`LoroDoc::clone`) knows to take the new one.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The counter up to which the stream's units hold `peer`'s
    /// operations: the end of its highest span counted at step 6, whatever
    /// the unit's verdict, or the counter the base snapshot holds for it,
    /// whichever is higher. Operations of the peer in the main document
    /// beyond it are a lent document's, not yet written as a unit; a unit
    /// written below it is never written again under the peer (step 6).
    pub fn committed_end(&self, peer: PeerId) -> Counter {
        let base = self.base.counters.get(&peer).copied().unwrap_or(0);
        let units = self
            .ledger
            .get(&peer)
            .and_then(|units| units.values().map(|counted| counted.span.end).max())
            .unwrap_or(0);
        base.max(units)
    }

    /// The counter up to which the stream's accepted edits hold `peer`'s
    /// operations: as [`committed_end`](Self::committed_end), over the
    /// edits applied to the main document alone. Below
    /// [`committed_end`](Self::committed_end) once a unit of the peer was
    /// refused or withdrawn: its operations are no longer in the document,
    /// and the incarnation is not continued.
    pub fn applied_end(&self, peer: PeerId) -> Counter {
        let base = self.base.counters.get(&peer).copied().unwrap_or(0);
        let edits = self
            .edits
            .iter()
            .filter(|(id, _)| !self.derived.overlapped.contains(*id))
            .map(|(_, (_, written))| written)
            .filter(|written| written.peer == peer)
            .map(|written| written.span.end)
            .max()
            .unwrap_or(0);
        base.max(edits)
    }

    /// Whether the base's `main` is a shallow snapshot: a history-free
    /// export, or a compaction over one. Units concurrent with its cut
    /// cannot be imported over it ([`unimportable`](Self::unimportable)).
    pub fn is_history_free(&self) -> bool {
        self.base.history_free
    }

    /// The counters the base snapshot holds per peer: those of its `main`
    /// and of the suggestions it holds.
    pub fn base_counters(&self) -> &BTreeMap<PeerId, Counter> {
        &self.base.counters
    }

    /// Every suggestion of the layer, from units and from the base, with
    /// where it stands.
    pub fn layer(&self) -> BTreeMap<EventId, (&Suggestion, Standing)> {
        self.layer_suggestions()
            .into_iter()
            .map(|(id, suggestion)| (id, (suggestion, self.standing(&id))))
            .collect_map()
    }

    /// The open suggestions, ascending.
    pub fn open(&self) -> Vec<EventId> {
        self.with_standing(Standing::Open)
    }

    /// The dismissed suggestions, ascending.
    pub fn dismissed(&self) -> Vec<EventId> {
        self.with_standing(Standing::Dismissed)
    }

    /// The accepted suggestions, ascending.
    pub fn accepted(&self) -> Vec<EventId> {
        self.with_standing(Standing::Accepted)
    }

    fn with_standing(&self, standing: Standing) -> Vec<EventId> {
        self.layer()
            .into_iter()
            .filter(|(_, (_, found))| *found == standing)
            .map(|(id, _)| id)
            .collect()
    }

    /// The main document forked, with a suggestion of the layer imported:
    /// how an application shows it (section 3.4).
    pub fn preview(&self, suggestion: &EventId) -> Option<LoroDoc> {
        let id = suggestion;
        let suggestion = self.layer_suggestions().remove(id)?;
        let mut panicked = self.panicked.lock().unwrap_or_else(PoisonError::into_inner);
        if panicked.contains(id) {
            return None;
        }
        let fork = self.doc.fork();
        match guard::import(&fork, &suggestion.written.blob) {
            Import::Imported => Some(fork),
            Import::Refused => None,
            Import::Panicked => {
                panicked.insert(*id);
                guard::discard(fork);
                None
            }
        }
    }

    /// Whether two states match as section 3.5, "Checking a snapshot",
    /// compares them: both main documents have the same version vector and
    /// value, and both layers hold the same suggestions.
    ///
    /// Each side's document is compared as its units built it: reading a
    /// root container of [`doc`](Self::doc) adds it, empty, to the
    /// document's value.
    pub fn matches(&self, other: &State) -> bool {
        let (mine, theirs) = (self.built(), other.built());
        mine.oplog_vv() == theirs.oplog_vv()
            && mine.get_deep_value() == theirs.get_deep_value()
            && self.open() == other.open()
            && self.dismissed() == other.dismissed()
    }

    /// The main document as the base and the accepted units build it, in a
    /// new document: what compaction exports, whatever an application read
    /// of [`doc`](Self::doc).
    fn built(&self) -> LoroDoc {
        // Each of these imported into the main document already.
        let doc = empty_doc();
        if let Some(main) = &self.base.main {
            let _ = doc.import(main);
        }
        for id in &self.imported {
            if let Some(written) = self.written(id) {
                let _ = doc.import(&written.blob);
            }
        }
        doc
    }

    /// The operations of an applied edit or a suggestion of the layer.
    fn written(&self, id: &EventId) -> Option<&Written> {
        match (self.edits.get(id), self.suggestions.get(id)) {
            (Some((_, written)), _) => Some(written),
            (_, Some((_, suggestion))) => Some(&suggestion.written),
            _ => self
                .base
                .layer
                .get(id)
                .map(|suggestion| &suggestion.written),
        }
    }

    /// Applied edits and suggestions refused at step 6 (`LoroOverlap`),
    /// ascending. A unit applied before an earlier overlapping unit
    /// arrived is listed here once it does, and its operations are gone
    /// from the main document.
    pub fn refused(&self) -> Vec<(EventId, LoroClass)> {
        self.derived
            .overlapped
            .iter()
            .map(|id| (*id, LoroClass::LoroOverlap))
            .collect()
    }

    /// Accepted blobs the pinned Loro does not import into the main
    /// document, such as operations concurrent with a history-free base:
    /// the replica asks for a fresh export (units.md, section 3.8). A blob
    /// whose import Loro panicked in stays here whenever the document is
    /// built again, and is not imported again.
    pub fn unimportable(&self) -> &BTreeSet<EventId> {
        &self.unimportable
    }

    /// Marks units the replica holds besides those handed over, such as
    /// the units of the base snapshot's cover, as held for step 7. A
    /// suggestion accepted inside the cover is in neither key 3 nor key 4
    /// of the snapshot state, so an accept or dismiss after the cover that
    /// names it is held only through this.
    pub fn hold(&mut self, units: impl IntoIterator<Item = EventId>) {
        let before = self.placed.len();
        self.placed.extend(units);
        if self.placed.len() != before {
            self.refresh();
        }
    }

    /// Counts a placed unit for steps 6 and 7, whatever its verdict.
    pub(crate) fn count(&mut self, context: &Context, content: &[u8]) {
        let mut changed = self.placed.insert(context.event_id);
        changed |= self.link(context);
        if let Some((peer, span)) = counted_span(content, context) {
            changed |= self.record(peer, context.canonical(), span, sha256(&[content]));
        }
        if changed {
            self.refresh();
        }
    }

    /// Records a counted unit's span and content digest; the first record
    /// of a unit stands.
    fn record(&mut self, peer: PeerId, place: Place, span: Span, content: Digest) -> bool {
        let units = self.ledger.entry(peer).or_default();
        if units.contains_key(&place) {
            return false;
        }
        let unit = place.1;
        units.insert(
            place,
            Counted {
                unit,
                span,
                content,
            },
        );
        true
    }

    /// Records a unit's `resubmits`, if it has one.
    fn link(&mut self, context: &Context) -> bool {
        match context.resubmits {
            Some(named) => self
                .resubmits
                .insert(context.event_id, named)
                .is_none_or(|before| before != named),
            None => false,
        }
    }

    /// Applies an accepted unit's change: section 3.3, "Apply", with steps
    /// 6 and 7 of the checks.
    pub(crate) fn apply(&mut self, context: &Context, change: &Change) -> Outcome {
        let id = context.event_id;
        let place = context.canonical();
        self.placed.insert(id);
        self.link(context);
        match change {
            Change::Snapshot => return Outcome::Applied,
            Change::Edit(written) => {
                self.record(written.peer, place, written.span, digest(change));
                self.edits.insert(id, (place, written.clone()));
            }
            Change::Suggestion(written) => {
                self.record(written.peer, place, written.span, digest(change));
                let suggestion = Suggestion {
                    author: context.author,
                    written: written.clone(),
                };
                self.suggestions.insert(id, (place, suggestion));
            }
            Change::Accept(targets) | Change::Dismiss(targets) => {
                let closer = Closer {
                    accept: matches!(change, Change::Accept(_)),
                    targets: targets.clone(),
                };
                self.closers.insert(id, closer);
            }
        }
        self.refresh();
        if self.derived.overlapped.contains(&id) {
            Outcome::Refused(LoroClass::LoroOverlap)
        } else if self.closers.contains_key(&id) && !self.derived.effective.contains(&id) {
            Outcome::Waiting(LoroClass::TargetNotHeld)
        } else {
            Outcome::Applied
        }
    }

    /// Step 6 on an applied unit: the units of its peer earlier in
    /// canonical order count, but those it re-submits.
    fn overlapped(&self, place: Place, written: &Written) -> bool {
        let units = self.ledger.get(&written.peer);
        let resubmitted = units
            .map(|units| self.resubmitted(place, units))
            .unwrap_or_default();
        let earlier = units
            .into_iter()
            .flat_map(|units| units.range(..place))
            .filter(|(_, counted)| !resubmitted.contains(&counted.unit))
            .map(|(_, counted)| (written.peer, counted.span));
        check_overlap(written.peer, written.span, earlier, &self.base.counters).is_err()
    }

    /// The units the unit at `place` re-submits whose content is byte for
    /// byte its own (units.md, 3.11 "Re-submission"), among `units`, the
    /// counted units of its peer: the unit its `resubmits` names, the one
    /// that unit's names, and so on. Units of the same content advance the
    /// same peer, so no other peer's need be looked at. The chain is
    /// followed at most once around, so a cycle of names ends.
    fn resubmitted(&self, place: Place, units: &BTreeMap<Place, Counted>) -> BTreeSet<EventId> {
        let mut found = BTreeSet::new();
        let Some(own) = units.get(&place) else {
            return found;
        };
        let mut next = self.resubmits.get(&own.unit);
        if next.is_none() {
            return found;
        }
        let by_unit: BTreeMap<EventId, &Counted> = units
            .values()
            .map(|counted| (counted.unit, counted))
            .collect_map();
        let mut seen = BTreeSet::from([own.unit]);
        while let Some(named) = next {
            if !seen.insert(*named) {
                break;
            }
            if by_unit
                .get(named)
                .is_some_and(|counted| counted.content == own.content)
            {
                found.insert(*named);
            }
            next = self.resubmits.get(named);
        }
        found
    }

    /// Step 7 on a target: held as a unit, or in the base's key 3 or 4.
    fn held_target(&self, target: &EventId) -> bool {
        self.placed.contains(target) || self.base.layer.contains_key(target)
    }

    /// The layer's suggestions: applied suggestions not refused at step 6,
    /// and the base's.
    fn layer_suggestions(&self) -> BTreeMap<EventId, &Suggestion> {
        let units = self
            .suggestions
            .iter()
            .filter(|(id, _)| !self.derived.overlapped.contains(*id))
            .map(|(id, (_, suggestion))| (*id, suggestion));
        let base = self.base.layer.iter().map(|(id, s)| (*id, s));
        base.chain(units).collect_map()
    }

    /// Accept wins over dismiss, whatever the order (section 3.4).
    fn standing(&self, id: &EventId) -> Standing {
        if self.derived.accepted.contains(id) {
            Standing::Accepted
        } else if self.derived.dismissed.contains(id) {
            Standing::Dismissed
        } else {
            Standing::Open
        }
    }

    /// Derives the verdicts of steps 6 and 7 and the suggestions' standing
    /// from the units, then brings the main document to the base with every
    /// accepted blob imported.
    fn refresh(&mut self) {
        let mut derived = Derived {
            dismissed: self.base.dismissed.clone(),
            ..Derived::default()
        };
        for (id, (place, written)) in &self.edits {
            if self.overlapped(*place, written) {
                derived.overlapped.insert(*id);
            }
        }
        for (id, (place, suggestion)) in &self.suggestions {
            if self.overlapped(*place, &suggestion.written) {
                derived.overlapped.insert(*id);
            }
        }
        for (id, closer) in &self.closers {
            if closer.targets.iter().all(|target| self.held_target(target)) {
                derived.effective.insert(*id);
                let into = if closer.accept {
                    &mut derived.accepted
                } else {
                    &mut derived.dismissed
                };
                into.extend(closer.targets.iter().copied());
            }
        }
        self.derived = derived;

        // The blobs wanted, by ID only: each is read where it is kept when
        // it is imported, and those imported already are not copied.
        let mut wanted: BTreeSet<EventId> = self
            .edits
            .keys()
            .filter(|id| !self.derived.overlapped.contains(*id))
            .copied()
            .collect();
        for (id, _) in self.layer_suggestions() {
            if self.derived.accepted.contains(&id) {
                wanted.insert(id);
            }
        }
        if !self.imported.iter().all(|id| wanted.contains(id)) {
            // A blob already imported is no longer accepted: build the main
            // document again without it.
            self.rebuild_doc();
        }
        loop {
            let mut panicked = None;
            for id in &wanted {
                if self.imported.contains(id) || self.unimportable.contains(id) {
                    continue;
                }
                let blob = match self.edits.get(id) {
                    Some((_, written)) => &written.blob,
                    None => match self.suggestions.get(id) {
                        Some((_, suggestion)) => &suggestion.written.blob,
                        None => match self.base.layer.get(id) {
                            Some(suggestion) => &suggestion.written.blob,
                            None => continue,
                        },
                    },
                };
                match guard::import(&self.doc, blob) {
                    Import::Imported => {
                        self.imported.insert(*id);
                    }
                    Import::Refused => {
                        self.unimportable.insert(*id);
                    }
                    Import::Panicked => {
                        panicked = Some(*id);
                        break;
                    }
                }
            }
            let Some(id) = panicked else {
                break;
            };
            // Loro panicked part-way through an import: the blob is one it
            // does not import, and the document is built again without it.
            self.panicked
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id);
            guard::discard(std::mem::replace(&mut self.doc, empty_doc()));
            let mut unimportable = std::mem::take(&mut self.unimportable);
            unimportable.insert(id);
            self.rebuild_doc();
            self.unimportable = unimportable;
        }
    }

    /// A new main document with the base's `main` imported, and no blob.
    /// The blobs Loro panicked on stay unimportable.
    fn rebuild_doc(&mut self) {
        self.doc = empty_doc();
        self.generation = next_generation();
        if let Some(main) = &self.base.main {
            // `load` imported it once already.
            let _ = self.doc.import(main);
        }
        self.imported.clear();
        self.unimportable = self
            .panicked
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
    }

    /// Whether every operation of a blob is in the main document, not
    /// pending inside Loro.
    fn complete(&self, vv: &VersionVector, written: &Written) -> bool {
        vv.get(&written.peer).copied().unwrap_or(0) >= written.span.end
    }

    /// The peers whose operations, not yet in the main document, an
    /// imported unit's operations wait on, pending inside Loro. A writer
    /// begins no incarnation under one of them: its new operations would
    /// stand in for the awaited ones, and release operations made over
    /// something else.
    pub fn awaited_peers(&self) -> BTreeSet<PeerId> {
        let vv = self.doc.oplog_vv();
        let mut awaited = BTreeSet::new();
        for id in &self.imported {
            let Some(written) = self.written(id) else {
                continue;
            };
            if self.complete(&vv, written) {
                continue;
            }
            for op in &written.deps {
                if vv.get(&op.peer).copied().unwrap_or(0) <= op.counter {
                    awaited.insert(op.peer);
                }
            }
        }
        awaited
    }

    /// The imported units whose operations stay pending inside Loro because
    /// they depend, directly or through another such unit, on operations
    /// of a refused unit (`LoroDependsOnRefused`, section 3.3).
    pub fn depends_on_refused(&self) -> BTreeSet<EventId> {
        let vv = self.doc.oplog_vv();
        let accepted: BTreeSet<EventId> = self
            .edits
            .keys()
            .chain(self.suggestions.keys())
            .filter(|id| !self.derived.overlapped.contains(*id))
            .copied()
            .collect();
        let pending: Vec<(EventId, &Written)> = self
            .imported
            .iter()
            .filter_map(|id| {
                let written = self.written(id)?;
                (!self.complete(&vv, written)).then_some((*id, written))
            })
            .collect();
        let mut dependent: BTreeSet<EventId> = BTreeSet::new();
        loop {
            let before = dependent.len();
            for (id, written) in &pending {
                if dependent.contains(id) {
                    continue;
                }
                let refused_holds = |op: &OpId| {
                    self.ledger.get(&op.peer).is_some_and(|units| {
                        units.values().any(|counted| {
                            counted.span.contains(op.counter)
                                && (!accepted.contains(&counted.unit)
                                    || dependent.contains(&counted.unit))
                        })
                    })
                };
                let mut deps = written.deps.clone();
                if written.span.start > 0 {
                    deps.push(OpId::new(written.peer, written.span.start - 1));
                }
                let waits = deps.iter().any(|op| {
                    vv.get(&op.peer).copied().unwrap_or(0) <= op.counter && refused_holds(op)
                });
                if waits {
                    dependent.insert(*id);
                }
            }
            if dependent.len() == before {
                return dependent;
            }
        }
    }

    /// Accepted units that wait: accepts and dismisses whose targets are not
    /// all held (`TargetNotHeld`), and units whose operations wait on a
    /// refused unit's (`LoroDependsOnRefused`), ascending by unit ID.
    pub fn held(&self) -> Vec<(EventId, LoroClass)> {
        let mut held: Vec<(EventId, LoroClass)> = self
            .closers
            .keys()
            .filter(|id| !self.derived.effective.contains(*id))
            .map(|id| (*id, LoroClass::TargetNotHeld))
            .collect();
        held.extend(
            self.depends_on_refused()
                .into_iter()
                .map(|id| (id, LoroClass::LoroDependsOnRefused)),
        );
        held.sort_by_key(|(id, _)| *id);
        held
    }

    /// Compaction (section 3.5): the main document exported with its
    /// history, the open suggestions in key 3 and the dismissed ones in key
    /// 4; and the units of those applied since the state was loaded that
    /// the state includes.
    ///
    /// An accepted suggestion whose operations are still pending inside
    /// Loro is not in the exported document, so it stays in key 3, and the
    /// accepts that name it are left out of the state: a replica that uses
    /// the snapshot applies them again over it.
    pub fn compact(&self) -> (Vec<u8>, BTreeSet<EventId>) {
        let vv = self.doc.oplog_vv();
        let mut open = Vec::new();
        let mut dismissed = Vec::new();
        let mut pending_accepted = BTreeSet::new();
        for (id, suggestion) in self.layer_suggestions() {
            let row = LayerRow {
                unit: id,
                author: suggestion.author,
                incarnation: suggestion.written.incarnation,
                blob: suggestion.written.blob.clone(),
            };
            match self.standing(&id) {
                Standing::Accepted if self.complete(&vv, &suggestion.written) => {}
                Standing::Accepted => {
                    pending_accepted.insert(id);
                    open.push(row);
                }
                Standing::Dismissed => dismissed.push(row),
                Standing::Open => open.push(row),
            }
        }
        let state = SnapshotState {
            main: self
                .built()
                .export(ExportMode::Snapshot)
                .unwrap_or_default(),
            suggestions: open,
            dismissed,
        };
        let mut included: BTreeSet<EventId> = self
            .edits
            .iter()
            .filter(|(id, (_, written))| {
                !self.derived.overlapped.contains(*id) && self.complete(&vv, written)
            })
            .map(|(id, _)| *id)
            .collect();
        included.extend(
            self.suggestions
                .keys()
                .filter(|id| !self.derived.overlapped.contains(*id)),
        );
        included.extend(self.closers.iter().filter_map(|(id, closer)| {
            let effective = self.derived.effective.contains(id);
            let names_pending = closer.accept
                && closer
                    .targets
                    .iter()
                    .any(|target| pending_accepted.contains(target));
            (effective && !names_pending).then_some(*id)
        }));
        (state.encode(), included)
    }

    /// The history-free export (section 3.5): a shallow snapshot of the main
    /// document at its current frontiers, with no suggestion.
    ///
    /// # Errors
    ///
    /// `Malformed` when Loro does not export it, or when the checks of
    /// section 3.5, "Loading a state", refuse it, as past their limits: a
    /// replica would not load it.
    pub fn export_history_free(&self) -> Result<Vec<u8>, ErrorClass> {
        let doc = self.built();
        let main = doc
            .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
            .map_err(|_| ErrorClass::Malformed)?;
        let state = SnapshotState {
            main,
            suggestions: Vec::new(),
            dismissed: Vec::new(),
        }
        .encode();
        crate::snapshot::check(&state)?;
        Ok(state)
    }
}

/// The digest of an applied unit's content: its change's one encoding,
/// which is the content it was read from (section 2.2).
fn digest(change: &Change) -> Digest {
    sha256(&[&change.encode()])
}

/// What applying a change did, before the adapter interface's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Applied,
    Waiting(LoroClass),
    Refused(LoroClass),
}

/// A suggestion of the base's key 3 or 4. The state names no space or
/// stream, so the blob is checked to be an updates blob of exactly one
/// peer, whose operations it holds.
fn suggestion_of(row: &LayerRow) -> Result<Suggestion, ErrorClass> {
    let meta = BlobMeta::read(&row.blob).ok_or(ErrorClass::Malformed)?;
    if !meta.is_updates() {
        return Err(ErrorClass::Malformed);
    }
    let [(peer, span)] = meta.spans.iter().collect::<Vec<_>>()[..] else {
        return Err(ErrorClass::Malformed);
    };
    Ok(Suggestion {
        author: row.author,
        written: Written {
            incarnation: row.incarnation,
            blob: row.blob.clone(),
            peer: *peer,
            span: *span,
            deps: meta.deps,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crafted;
    use frasil_adapter::Role;

    fn context(id: u8) -> Context {
        Context::new(
            [0; 32],
            [1; 16],
            [id; 32],
            [2; 32],
            1,
            u64::from(id),
            Role::Log,
        )
    }

    /// An edit of `peer` that writes `text`: span 0..5.
    fn edit(peer: u64, text: &str) -> Written {
        let doc = LoroDoc::new();
        doc.set_peer_id(peer).unwrap();
        doc.get_text("t").insert(0, text).unwrap();
        doc.commit();
        Written {
            incarnation: 1,
            blob: doc.export(ExportMode::all_updates()).unwrap(),
            peer,
            span: Span::new(0, 5),
            deps: Vec::new(),
        }
    }

    /// An edit of peer 8 whose blob Loro panics on: step 4 refuses each,
    /// so only a state given it directly imports it.
    fn panicking_edits() -> [Written; 2] {
        [
            crafted::style_end_alone(),
            crafted::too_many_dependencies(8),
        ]
        .map(|blob| {
            assert!(BlobMeta::read(&blob).is_none());
            Written {
                incarnation: 1,
                blob,
                peer: 8,
                span: Span::new(0, 1),
                deps: Vec::new(),
            }
        })
    }

    thread_local! {
        /// Panics on this thread.
        static PANICS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Counts the panics on each thread, then reports them as before.
    fn count_panics() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let report = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                PANICS.with(|panics| panics.set(panics.get() + 1));
                report(info);
            }));
        });
    }

    /// A unit of author 2 at height `height`, writing under incarnation 1,
    /// with this `resubmits`.
    fn unit(id: u8, height: u64, resubmits: Option<u8>) -> Context {
        Context::new([0; 32], [1; 16], [id; 32], [2; 32], 1, height, Role::Log)
            .with_resubmits(resubmits.map(|named| [named; 32]))
    }

    /// Author 2's edit under incarnation 1 that writes `text` after
    /// `before`, and its content.
    fn own_edit(before: &str, text: &str) -> (Written, Vec<u8>) {
        let peer = crate::peer::peer(&[0; 32], &[1; 16], &[2; 32], 1);
        let doc = LoroDoc::new();
        doc.set_peer_id(peer).unwrap();
        doc.get_text("t").insert(0, before).unwrap();
        doc.commit();
        let from = doc.oplog_vv();
        doc.get_text("t").insert(0, text).unwrap();
        doc.commit();
        let blob = doc.export(ExportMode::updates(&from)).unwrap();
        let content = crate::content::Content::edit(1, blob).encode();
        let Ok(Change::Edit(written)) = crate::checks::check_content(
            &content,
            &unit(0, 0, None),
            &frasil_adapter::CapabilityChecks::new(),
            BlobMeta::read,
        ) else {
            panic!("an edit");
        };
        (written, content)
    }

    #[test]
    fn a_resubmission_does_not_count_the_unit_it_resubmits() {
        let (first, first_content) = own_edit("", "a");
        let (late, late_content) = own_edit("a", "b");
        // The same operations re-sent, and others over the same counters.
        let (other, other_content) = own_edit("a", "c");
        assert_eq!(late.span, other.span);
        for applied_late in [false, true] {
            let mut state = State::new();
            state.count(&unit(1, 1, None), &first_content);
            assert_eq!(
                state.apply(&unit(1, 1, None), &Change::Edit(first.clone())),
                Outcome::Applied
            );
            // The late unit is counted; a replica may also have applied it.
            state.count(&unit(2, 2, None), &late_content);
            if applied_late {
                state.apply(&unit(2, 2, None), &Change::Edit(late.clone()));
            }
            // Its re-submission names it: the same content is accepted.
            state.count(&unit(3, 3, Some(2)), &late_content);
            assert_eq!(
                state.apply(&unit(3, 3, Some(2)), &Change::Edit(late.clone())),
                Outcome::Applied
            );
            assert_eq!(state.doc().get_text("t").to_string(), "ba");
            // Other content naming it overlaps.
            state.count(&unit(4, 4, Some(2)), &other_content);
            assert_eq!(
                state.apply(&unit(4, 4, Some(2)), &Change::Edit(other.clone())),
                Outcome::Refused(LoroClass::LoroOverlap)
            );
            // The same content naming no unit overlaps.
            assert_eq!(
                state.apply(&unit(5, 5, None), &Change::Edit(late.clone())),
                Outcome::Refused(LoroClass::LoroOverlap)
            );
        }
    }

    #[test]
    fn a_resubmission_does_not_count_the_units_down_its_chain() {
        let (first, first_content) = own_edit("", "a");
        let (late, late_content) = own_edit("a", "b");
        let mut state = State::new();
        state.count(&unit(1, 1, None), &first_content);
        state.apply(&unit(1, 1, None), &Change::Edit(first));
        // Refused, re-submitted and refused again, then re-submitted once
        // more: neither earlier one counts.
        state.count(&unit(2, 2, None), &late_content);
        state.count(&unit(3, 3, Some(2)), &late_content);
        assert_eq!(
            state.apply(&unit(4, 4, Some(3)), &Change::Edit(late.clone())),
            Outcome::Applied
        );
        assert_eq!(state.doc().get_text("t").to_string(), "ba");
        // A cycle of names ends.
        let mut state = State::new();
        state.count(&unit(6, 1, Some(7)), &late_content);
        state.count(&unit(7, 2, Some(6)), &late_content);
        assert_eq!(
            state.apply(&unit(8, 3, Some(7)), &Change::Edit(late)),
            Outcome::Applied
        );
    }

    #[test]
    fn a_blob_loro_panics_on_is_left_out_of_a_document_built_again() {
        for crafted in panicking_edits() {
            let mut state = State::new();
            let generation = state.generation();
            assert_eq!(
                state.apply(&context(1), &Change::Edit(crafted)),
                Outcome::Applied
            );
            assert_eq!(state.unimportable(), &BTreeSet::from([[1; 32]]));
            assert_ne!(state.generation(), generation);
            assert_eq!(
                state.apply(&context(2), &Change::Edit(edit(7, "hello"))),
                Outcome::Applied
            );
            assert_eq!(state.doc().get_text("t").to_string(), "hello");
        }
    }

    #[test]
    fn a_blob_loro_panicked_on_is_not_imported_again_when_the_document_is_rebuilt() {
        count_panics();
        for crafted in panicking_edits() {
            let before = PANICS.with(std::cell::Cell::get);
            let mut state = State::new();
            state.apply(&context(3), &Change::Edit(crafted));
            // One import, which may panic more than once as it unwinds.
            let after = PANICS.with(std::cell::Cell::get);
            assert!(after > before);
            assert_eq!(
                state.apply(&context(5), &Change::Edit(edit(7, "hello"))),
                Outcome::Applied
            );
            // An earlier unit of peer 7 overlaps the one at height 5, which
            // is refused: the main document is built again without it.
            let generation = state.generation();
            assert_eq!(
                state.apply(&context(4), &Change::Edit(edit(7, "world"))),
                Outcome::Applied
            );
            assert_ne!(state.generation(), generation);
            assert_eq!(state.refused(), vec![([5; 32], LoroClass::LoroOverlap)]);
            assert_eq!(state.doc().get_text("t").to_string(), "world");
            assert!(state.unimportable().contains(&[3; 32]));
            assert_eq!(PANICS.with(std::cell::Cell::get), after);
        }
    }
}
