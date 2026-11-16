//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's Loro adapter.
//!
//! Specified by `docs/spec/adapter-loro.md`, on the interface of
//! `docs/spec/units.md`, section 3.17 (The adapter interface). Its vectors
//! are `docs/spec/vectors/adapter-loro.json`.
//!
//! A stream of type `frasil:loro` holds a rich document in a Loro document,
//! pinned at Loro 1.17.0 (section 2.1). A unit carries Loro's bytes for its
//! writer's new operations; the checks read only their metadata. Each peer
//! ID is bound to one writer, stream and incarnation, so no writer writes
//! under another's name. Suggestions are operations kept apart from the
//! main document until a writer that is not a suggester accepts or
//! dismisses them.
//!
//! - [`peer`]: peer IDs (section 2.3) and incarnations.
//! - [`content`]: unit content (section 2.2) and step 1 of the checks.
//! - [`meta`]: what the checks read of a blob.
//! - [`checks`]: the checks of section 3.2, in order.
//! - [`snapshot`]: the snapshot state's framing (section 2.4).
//! - [`state`]: the main document, the suggestion layer, compaction and
//!   the history-free export (sections 3.3 to 3.5).
//! - [`write`]: what a writer does (section 3.1), and re-applying a late
//!   write (section 3.6).
//! - [`Loro`]: the adapter.
//!
//! # Bytes from other writers
//!
//! Step 4 of the checks (section 3.2) walks an updates blob as the pinned
//! Loro decodes it before Loro reads it, and refuses as `LoroMalformed` a
//! blob that would make the decoder fail, panic, or reserve memory out of
//! proportion to the blob, and one that breaks the limits section 3.2 sets:
//! at most 2^20 operations, tree positions and deletion starts each, tree
//! positions of at most 2^24 bytes in all, and a style's end always
//! directly after its start. That screen holds on every target.
//!
//! A snapshot state's `main` is screened the same way before Loro reads it
//! (section 3.5, "Loading a state"): a state of at most 2^28 bytes, its
//! key-value tables read as Loro reads them, their LZ4 blocks decompressed
//! to at most 2^28 bytes in all and 256 times the snapshot's length, every
//! change block passing step 4, every container state's header, and the
//! rows of a text's, a list's, a movable list's and a tree's tables, read
//! run by run. Loro reads a container's state when the container is first
//! read or changed; [`State::load`] reads every value and every state of
//! the state store then, inside the catch below.
//!
//! A writer runs the same checks on what it writes: [`write::export_unit`]
//! and [`write::Writer::edits`] divide operations that break step 4's
//! limits into more than one unit, [`snapshot::check`] tells a compactor
//! that a state is over section 3.5's (section 3.1), and a history-free
//! export over them is refused.
//!
//! Where panics unwind, a panic inside Loro on bytes from another writer
//! that the screen does not foresee is caught as well: the blob is refused,
//! or left out of the main document and never imported again, and a
//! snapshot state is `Malformed`. Catching needs unwinding. On
//! `wasm32-unknown-unknown`, and in an application built with
//! `panic = "abort"`, such a panic aborts the process instead: those get the
//! screen only.

pub mod checks;
pub mod content;
mod guard;
mod lz4;
pub mod meta;
pub mod peer;
mod screen;
pub mod snapshot;
mod sstable;
pub mod state;
pub mod write;

#[cfg(test)]
#[path = "../tests/support/crafted.rs"]
mod crafted;

pub use checks::{
    Change, Written, check, check_content, check_overlap, check_overlap_resubmitted,
    check_resubmitted, check_targets,
};
pub use content::{Content, ContentRole};
pub use meta::{BlobMeta, BlobMode, Counter, OpId, Span};
pub use peer::{Incarnation, PeerDerivation, PeerId, derive, peer};
pub use snapshot::{LayerRow, SnapshotState};
pub use state::{Standing, State, Suggestion};

use frasil_adapter::{
    Adapter, CapabilityChecks, Compaction, Context, EphemeralContext, EventId, Outcome, Writer,
};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeSet;

/// The adapter type.
pub const TYPE: &str = "frasil:loro";

/// The pinned Loro version (section 2.1, "The pinned version").
pub const LORO_VERSION: &str = "1.17.0";

frasil_base::error_classes! {
    /// The classes adapter-loro.md defines (section 3.7). Each concerns
    /// content only; the unit's verdict stands. It also uses `Malformed`,
    /// `UnknownContentVersion`, `CapabilityRefused` and `BadCompaction`.
    pub enum LoroClass {
        /// An incarnation above the unit's `seq`, or a suggestion's other
        /// than its `seq`.
        LoroIncarnation = "loro_incarnation", ContentRefused;
        /// A blob the pinned Loro does not read, or a snapshot blob.
        LoroMalformed = "loro_malformed", ContentRefused;
        /// A blob that advances another peer, or more than one.
        LoroForeignPeer = "loro_foreign_peer", ContentRefused;
        /// Counters that an earlier unit or the base snapshot already holds.
        LoroOverlap = "loro_overlap", ContentRefused;
        /// An accept or dismiss naming a target not yet held. Its content
        /// waits; the unit's verdict stands.
        TargetNotHeld = "target_not_held", Pending;
        /// An accepted unit whose operations wait on a refused unit's.
        LoroDependsOnRefused = "loro_depends_on_refused", Report;
    }
}

/// The Loro adapter, with the capability checks registered with it.
#[derive(Debug, Clone, Default)]
pub struct Loro {
    /// Capability checks, which run at step 2 of section 3.2 after the
    /// `suggest` check.
    pub checks: CapabilityChecks,
}

impl Loro {
    /// The adapter with no registered capability checks.
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter with these registered capability checks.
    pub fn with_checks(checks: CapabilityChecks) -> Self {
        Self { checks }
    }

    /// Re-applies a late write (section 3.6) as `writer`'s own edit in the
    /// moved document, under that incarnation: the content of the
    /// re-applier's unit, or `None` when the change is not an edit, cannot
    /// be placed, or changes nothing. The adapter interface's
    /// [`reapply`](Adapter::reapply) begins a new incarnation at the
    /// re-applier's unit; a writer that continues one of its own calls
    /// this.
    pub fn reapply_as(
        &self,
        original: &State,
        change: &Change,
        new: &State,
        writer: &Incarnation,
    ) -> Option<Vec<u8>> {
        let Change::Edit(late) = change else {
            return None;
        };
        write::reapply(original.doc(), late, new.doc(), writer)
            .ok()
            .flatten()
            .map(|content| content.encode())
    }
}

impl Adapter for Loro {
    const TYPE: &'static str = TYPE;
    type Change = Change;
    type State = State;
    type Class = LoroClass;

    fn max_state_bytes(&self) -> Option<u64> {
        Some(snapshot::MAX_STATE_BYTES as u64)
    }

    fn encode(&self, change: &Change) -> Vec<u8> {
        change.encode()
    }

    /// Steps 1 to 5 of section 3.2, reading the blob with the pinned Loro.
    /// Steps 6 and 7 read the stream's other units: they are
    /// [`apply`](Adapter::apply)'s.
    fn decode(&self, content: &[u8], context: &Context) -> Result<Change, LoroClass> {
        check_content(content, context, &self.checks, BlobMeta::read)
    }

    fn empty(&self) -> State {
        State::new()
    }

    /// Counts a placed unit, whatever its verdict: it is held for step 7,
    /// and, when its content passes steps 1 and 3 to 5, its span counts for
    /// step 6.
    fn count(&self, state: &mut State, context: &Context, content: &[u8]) {
        state.count(context, content);
    }

    /// Applies an accepted unit (section 3.3, "Apply") after steps 6 and 7.
    /// An edit refused at step 6 is `LoroOverlap`; an accept or dismiss whose
    /// targets are not all held waits (`TargetNotHeld`), and applies when
    /// they arrive.
    fn apply(&self, state: &mut State, context: &Context, change: &Change) -> Outcome<LoroClass> {
        match state.apply(context, change) {
            state::Outcome::Applied => Outcome::Applied,
            state::Outcome::Waiting(class) => Outcome::Waiting(class),
            state::Outcome::Refused(class) => Outcome::Refused(class),
        }
    }

    /// Marks the units of a loaded snapshot's cover as held for step 7: a
    /// suggestion accepted inside the cover is in neither key 3 nor key 4
    /// of the snapshot state.
    fn hold(&self, state: &mut State, units: &BTreeSet<EventId>) {
        state.hold(units.iter().copied());
    }

    fn held(&self, state: &State) -> Vec<(EventId, LoroClass)> {
        state.held()
    }

    /// Compaction (section 3.5): the snapshot unit's content is empty, and
    /// Loro references no object.
    fn compact(&self, state: &State) -> Compaction {
        let (bytes, included) = state.compact();
        Compaction {
            state: bytes,
            metadata: Vec::new(),
            included,
            objects: BTreeSet::new(),
            supersedes: Vec::new(),
        }
    }

    fn load(&self, snapshot_state: &[u8]) -> Result<State, LoroClass> {
        Ok(State::load(snapshot_state)?)
    }

    fn export_history_free(&self, state: &State) -> Result<Vec<u8>, LoroClass> {
        Ok(state.export_history_free()?)
    }

    /// Re-applies a late write (section 3.6) as the re-applier's own edit,
    /// in a new incarnation that begins at its unit: incarnation `writer.seq`
    /// (section 3.1, "Writing").
    fn reapply(
        &self,
        original: &State,
        _late: &Context,
        change: &Change,
        new: &State,
        writer: &Writer,
    ) -> Option<Vec<u8>> {
        let incarnation = Incarnation {
            space: writer.space,
            stream: writer.stream,
            author: writer.author,
            incarnation: writer.seq,
        };
        self.reapply_as(original, change, new, &incarnation)
    }

    /// The registered capability checks on ephemeral data that names this
    /// adapter (ext-ephemeral.md, section 3.5).
    fn check_ephemeral(&self, context: &EphemeralContext, data: &[u8]) -> Result<(), ErrorClass> {
        self.checks.run_ephemeral(context, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, Sort, snake_case};

    #[test]
    fn its_own_classes_are_named_as_the_spec_names_them() {
        for class in LoroClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(LoroClass::TargetNotHeld.sort(), Sort::Pending);
        assert_eq!(LoroClass::LoroOverlap.sort(), Sort::ContentRefused);
        assert_eq!(LoroClass::LoroDependsOnRefused.sort(), Sort::Report);
    }
}
