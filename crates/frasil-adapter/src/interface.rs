//! The adapter interface (units.md, section 3.17, "The adapter interface").
//!
//! An adapter is registered under a type (units.md, section 2.7, "Adapter
//! types") and provides, per stream:
//!
//! 1. `encode(change) → content` and `decode(content, context) → change`,
//!    or a content refusal: [`Adapter::encode`], [`Adapter::decode`].
//! 2. `apply(state, unit) → state`, which merges one accepted unit:
//!    [`Adapter::apply`]. A unit whose own dependencies are not yet applied
//!    may wait inside the adapter ([`Outcome::Waiting`]).
//! 3. `compact(state) → (snapshot state, metadata)`: [`Adapter::compact`],
//!    which also states which units of the cover its state includes.
//! 4. `load(snapshot state) → state` and `rebuild(snapshot state or
//!    nothing, accepted units) → state`: [`Adapter::load`],
//!    [`Adapter::rebuild`].
//! 5. `export_history_free(state) → snapshot state`:
//!    [`Adapter::export_history_free`].
//!
//! Optionally, capability checks
//! ([`CapabilityChecks`](crate::CapabilityChecks), run inside `decode`), and
//! `reapply(original state, late unit, new state, writer) → content or
//! nothing` ([`Adapter::reapply`]), which only ext-restricted-spaces.md
//! uses.
//!
//! **A snapshot's cover.** A replica that loads a snapshot's state marks
//! the units of its cover as held ([`Adapter::hold`]), so that a check
//! that asks whether a unit is held, such as adapter-loro.md's step 7,
//! counts them. It then hands back, by [`Adapter::receive`], every unit of
//! the cover that the state does not include (the snapshot unit's
//! `excluded`) and that it holds, valid or not, so that what a check counts
//! over the cover is what a rebuild from the units counts (units.md,
//! section 3.6, "Using").
//!
//! **Counting.** An adapter's state may depend on units whose content it
//! does not apply: Records and Blobs admit clocks over every placed unit
//! whose content is well formed, whatever its verdict. A replica therefore
//! hands every placed unit of the stream to [`Adapter::count`], and each
//! accepted one to [`Adapter::apply`]; [`Adapter::receive`] does both.
//!
//! **Accepted** units are those valid by the write rule whose content the
//! adapter does not refuse.

use crate::context::{Context, EphemeralContext, EventId, Locator, Role, Supersession, Writer};
use frasil_base::errors::{Class, ErrorClass};
use std::collections::BTreeSet;

/// What became of a unit's content when it was handed to an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome<C> {
    /// The content is accepted and applied.
    Applied,
    /// The content is accepted but waits inside the adapter, and applies
    /// when what it waits for arrives. Its class is pending, such as
    /// `ClockAhead`; the unit's verdict stands.
    Waiting(C),
    /// The content has no effect. The class says why: refused as content
    /// (`Malformed`, `CapabilityRefused`, `ObjectNotListed` and the
    /// adapter's own), or kept and ignored (`UnknownContentVersion`). The
    /// unit stays a valid event (units.md, section 3.17, "Content
    /// refusals").
    Refused(C),
    /// The unit is not valid by the write rule: its content only counted.
    Counted,
}

impl<C> Outcome<C> {
    /// Whether the content was applied.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// One unit of a stream as a replica hands it over: its context, its
/// opened content, and whether it is valid by the write rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamUnit {
    /// The unit's context.
    pub context: Context,
    /// The unit's content, from its sealed part.
    pub content: Vec<u8>,
    /// Whether the unit is valid by the write rule at this replica now.
    pub valid: bool,
}

/// What [`Adapter::compact`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compaction {
    /// The stream snapshot's `state` (units.md, section 2.9, "Snapshot units
    /// and stream snapshots", key 5).
    pub state: Vec<u8>,
    /// The snapshot unit's content: the adapter's snapshot metadata.
    pub metadata: Vec<u8>,
    /// The units the state includes, of those applied since the state was
    /// loaded or created. Every other unit of the cover goes in `excluded`
    /// (units.md, section 3.5, "Compacting", step 2).
    pub included: BTreeSet<EventId>,
    /// Every object the state still references, which the snapshot unit
    /// lists in `objects` beside its snapshot object (units.md, section
    /// 3.5, step 4).
    pub objects: BTreeSet<Locator>,
    /// The supersessions the snapshot unit lists among those objects
    /// (ext-file-versions.md, section 3.4), strictly ascending.
    pub supersedes: Vec<Supersession>,
}

/// An adapter: one type's meaning for a stream's units (units.md, section
/// 3.17).
///
/// **Determinism.** Every method that affects state or a verdict is a pure
/// function of its inputs, so that one adapter version gives the same state
/// and content refusals on every replica and platform. The state must not
/// depend on the order in which accepted units are applied, nor on how
/// many times each is.
pub trait Adapter {
    /// The adapter type it is registered under, such as `frasil:records`.
    const TYPE: &'static str;

    /// A unit's decoded content.
    type Change;

    /// A stream's state.
    type State;

    /// The classes of its content refusals.
    type Class: Class + From<ErrorClass>;

    /// `encode(change) → content`.
    fn encode(&self, change: &Self::Change) -> Vec<u8>;

    /// `decode(content, context) → change`, or a content refusal. It runs
    /// the adapter's checks on the content, the `suggest` check and the
    /// registered capability checks among them, in its document's order;
    /// checks that depend on other units run in [`apply`](Self::apply).
    fn decode(&self, content: &[u8], context: &Context) -> Result<Self::Change, Self::Class>;

    /// A stream's state before any unit: what `rebuild` starts from without
    /// a snapshot.
    fn empty(&self) -> Self::State;

    /// Counts a placed unit of the stream, whatever its verdict, for an
    /// adapter whose state depends on more than accepted units. Counting a
    /// unit twice changes nothing. By default it does nothing.
    fn count(&self, state: &mut Self::State, context: &Context, content: &[u8]) {
        let _ = (state, context, content);
    }

    /// `apply(state, unit) → state`: merges one accepted unit, whose content
    /// [`decode`](Self::decode) gave.
    fn apply(
        &self,
        state: &mut Self::State,
        context: &Context,
        change: &Self::Change,
    ) -> Outcome<Self::Class>;

    /// Marks units the replica holds besides those handed over, such as
    /// the units of a loaded snapshot's cover, as held, for a check that
    /// asks whether a unit is held. Marking a unit twice changes nothing.
    /// By default it does nothing.
    fn hold(&self, state: &mut Self::State, units: &BTreeSet<EventId>) {
        let _ = (state, units);
    }

    /// Accepted units that wait inside the adapter, with the class each
    /// waits under. By default, none.
    fn held(&self, state: &Self::State) -> Vec<(EventId, Self::Class)> {
        let _ = state;
        Vec::new()
    }

    /// `compact(state) → (snapshot state, metadata)`. The state handed in is
    /// the one built over the base snapshot and the cover alone.
    fn compact(&self, state: &Self::State) -> Compaction;

    /// `load(snapshot state) → state`. A state that does not decode is
    /// refused (`Malformed`); the replica reports `BadCompaction` and never
    /// uses it.
    fn load(&self, snapshot_state: &[u8]) -> Result<Self::State, Self::Class>;

    /// The largest snapshot state, in bytes, that [`load`](Adapter::load)
    /// takes: a replica refuses to fetch a state object whose header names
    /// a larger plaintext, since the state in it could never load. `None`,
    /// by default, for an adapter with no such limit.
    fn max_state_bytes(&self) -> Option<u64> {
        None
    }

    /// Takes in the supersessions of the snapshot unit whose state `state`
    /// was loaded from. By default, nothing.
    fn load_supersedes(&self, state: &mut Self::State, supersedes: &[Supersession]) {
        let _ = (state, supersedes);
    }

    /// `export_history_free(state) → snapshot state`: the current state and
    /// what later merges need to apply units written after it, and nothing
    /// that shows earlier states. Refused, with the class
    /// [`load`](Adapter::load) would give it, when `load` would refuse the
    /// export, as one past the adapter's limits; the caller then writes no
    /// history-free state of the stream.
    ///
    /// # Errors
    ///
    /// The class of a state `load` would refuse.
    fn export_history_free(&self, state: &Self::State) -> Result<Vec<u8>, Self::Class>;

    /// The supersessions that travel beside
    /// [`export_history_free`](Self::export_history_free)'s state, in a
    /// snapshot unit's two-element form (ext-file-versions.md, 3.3 The
    /// supersession set). By default, none.
    fn export_supersedes(&self, state: &Self::State) -> Vec<Supersession> {
        let _ = state;
        Vec::new()
    }

    /// `reapply(original state, late unit, new state, writer) → content or
    /// nothing`, which only ext-restricted-spaces.md calls. The content is
    /// the re-applier's own, written in the moved document by `writer`, as
    /// the unit at `writer`'s place. By default, nothing.
    fn reapply(
        &self,
        original: &Self::State,
        late: &Context,
        change: &Self::Change,
        new: &Self::State,
        writer: &Writer,
    ) -> Option<Vec<u8>> {
        let _ = (original, late, change, new, writer);
        None
    }

    /// The adapter's capability checks on an ephemeral message or slot
    /// value that names it (ext-ephemeral.md, section 3.5): `data` with
    /// the frame's own context. By default every frame passes.
    fn check_ephemeral(&self, context: &EphemeralContext, data: &[u8]) -> Result<(), ErrorClass> {
        let _ = (context, data);
        Ok(())
    }

    /// Hands over one placed unit: counts it, and, if it is valid by the
    /// write rule, decodes its content and applies it.
    fn receive(&self, state: &mut Self::State, unit: &StreamUnit) -> Outcome<Self::Class> {
        self.count(state, &unit.context, &unit.content);
        if !unit.valid {
            return Outcome::Counted;
        }
        match self.decode(&unit.content, &unit.context) {
            Ok(change) => self.apply(state, &unit.context, &change),
            Err(class) => Outcome::Refused(class),
        }
    }

    /// `rebuild(snapshot state or nothing, units) → state`: `load`, or
    /// `empty`, then each unit of the stream after the snapshot's cover,
    /// valid or not, handed over by [`receive`](Self::receive), in the
    /// order given. A replica gives canonical order, and the state does not
    /// depend on it.
    fn rebuild(
        &self,
        snapshot_state: Option<&[u8]>,
        units: &[StreamUnit],
    ) -> Result<Self::State, Self::Class> {
        self.rebuild_with(snapshot_state, &[], units)
    }

    /// [`rebuild`](Self::rebuild) over a snapshot state and the
    /// supersessions of its snapshot unit.
    fn rebuild_with(
        &self,
        snapshot_state: Option<&[u8]>,
        supersedes: &[Supersession],
        units: &[StreamUnit],
    ) -> Result<Self::State, Self::Class> {
        let mut state = match snapshot_state {
            Some(bytes) => {
                let mut state = self.load(bytes)?;
                self.load_supersedes(&mut state, supersedes);
                state
            }
            None => self.empty(),
        };
        for unit in units {
            self.receive(&mut state, unit);
        }
        Ok(state)
    }
}

/// The part of the `suggest` check every built-in adapter shares: a
/// suggester writes no snapshot unit, a seed included (units.md, section
/// 3.17, "`suggest`"). What else a suggester may write is each adapter's.
pub fn suggest_check_snapshot(context: &Context) -> Result<(), ErrorClass> {
    if context.role == Role::Snapshot && context.capabilities.is_suggester() {
        Err(ErrorClass::CapabilityRefused)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{Capabilities, Capability, Mode, SUGGEST};

    /// A toy adapter: a set of bytes per unit, merged by union, whose
    /// content must not be empty, and which counts every well-formed unit.
    struct Union;

    #[derive(Default)]
    struct UnionState {
        items: BTreeSet<Vec<u8>>,
        counted: BTreeSet<EventId>,
        included: BTreeSet<EventId>,
    }

    impl Adapter for Union {
        const TYPE: &'static str = "com.example.union";
        type Change = Vec<u8>;
        type State = UnionState;
        type Class = ErrorClass;

        fn encode(&self, change: &Vec<u8>) -> Vec<u8> {
            change.clone()
        }

        fn decode(&self, content: &[u8], context: &Context) -> Result<Vec<u8>, ErrorClass> {
            suggest_check_snapshot(context)?;
            if content.is_empty() {
                return Err(ErrorClass::Malformed);
            }
            Ok(content.to_vec())
        }

        fn empty(&self) -> UnionState {
            UnionState::default()
        }

        fn count(&self, state: &mut UnionState, context: &Context, content: &[u8]) {
            if !content.is_empty() {
                state.counted.insert(context.event_id);
            }
        }

        fn apply(
            &self,
            state: &mut UnionState,
            context: &Context,
            change: &Vec<u8>,
        ) -> Outcome<ErrorClass> {
            state.items.insert(change.clone());
            state.included.insert(context.event_id);
            Outcome::Applied
        }

        fn compact(&self, state: &UnionState) -> Compaction {
            Compaction {
                state: state.items.iter().flatten().copied().collect(),
                metadata: Vec::new(),
                included: state.included.clone(),
                objects: BTreeSet::new(),
                supersedes: Vec::new(),
            }
        }

        fn load(&self, snapshot_state: &[u8]) -> Result<UnionState, ErrorClass> {
            let mut state = UnionState::default();
            state.items.extend(snapshot_state.iter().map(|b| vec![*b]));
            Ok(state)
        }

        fn export_history_free(&self, state: &UnionState) -> Result<Vec<u8>, ErrorClass> {
            Ok(self.compact(state).state)
        }
    }

    fn unit(id: u8, content: &[u8], valid: bool) -> StreamUnit {
        StreamUnit {
            context: Context::new(
                [0; 32],
                [1; 16],
                [id; 32],
                [9; 32],
                u64::from(id),
                u64::from(id),
                Role::Log,
            ),
            content: content.to_vec(),
            valid,
        }
    }

    #[test]
    fn receive_counts_every_unit_and_applies_valid_ones() {
        let adapter = Union;
        let mut state = adapter.empty();
        assert_eq!(
            adapter.receive(&mut state, &unit(1, b"a", true)),
            Outcome::Applied
        );
        assert_eq!(
            adapter.receive(&mut state, &unit(2, b"b", false)),
            Outcome::Counted
        );
        assert_eq!(
            adapter.receive(&mut state, &unit(3, b"", true)),
            Outcome::Refused(ErrorClass::Malformed)
        );
        assert_eq!(state.counted, BTreeSet::from([[1; 32], [2; 32]]));
        assert_eq!(adapter.compact(&state).included, BTreeSet::from([[1; 32]]));
        assert!(adapter.held(&state).is_empty());
    }

    #[test]
    fn rebuild_loads_then_receives_in_any_order() {
        let adapter = Union;
        let units = [unit(1, b"c", true), unit(2, b"b", true)];
        let forward = adapter.rebuild(Some(b"a"), &units).unwrap();
        let reversed: Vec<StreamUnit> = units.iter().rev().cloned().collect();
        let backward = adapter.rebuild(Some(b"a"), &reversed).unwrap();
        assert_eq!(adapter.export_history_free(&forward).unwrap(), b"abc");
        assert_eq!(
            adapter.export_history_free(&forward),
            adapter.export_history_free(&backward)
        );
        let writer = Writer {
            space: [0; 32],
            stream: [1; 16],
            author: [9; 32],
            seq: 3,
        };
        assert_eq!(
            adapter.reapply(&forward, &units[0].context, &vec![1], &backward, &writer),
            None
        );
        let mut held = forward;
        adapter.hold(&mut held, &BTreeSet::from([[7; 32]]));
        assert!(adapter.held(&held).is_empty());
    }

    #[test]
    fn a_suggester_writes_no_snapshot_unit() {
        let suggester = Capabilities::new([Capability::new(SUGGEST, Mode::Narrows)]);
        let extends = Capabilities::new([Capability::new(SUGGEST, Mode::Extends)]);
        let snapshot = Context::new([0; 32], [1; 16], [2; 32], [3; 32], 4, 4, Role::Snapshot);
        assert_eq!(suggest_check_snapshot(&snapshot), Ok(()));
        assert_eq!(
            suggest_check_snapshot(&snapshot.clone().with_capabilities(suggester.clone())),
            Err(ErrorClass::CapabilityRefused)
        );
        assert_eq!(
            suggest_check_snapshot(&snapshot.with_capabilities(extends)),
            Ok(())
        );
        let log = Context::new([0; 32], [1; 16], [2; 32], [3; 32], 4, 4, Role::Log)
            .with_capabilities(suggester);
        assert_eq!(suggest_check_snapshot(&log), Ok(()));
    }
}
