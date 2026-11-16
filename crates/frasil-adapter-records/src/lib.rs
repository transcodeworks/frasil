//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's Records adapter.
//!
//! Specified by `docs/spec/adapter-records.md`, on the interface of
//! `docs/spec/units.md`, section 3.17, "The adapter interface". Its vectors
//! are `docs/spec/vectors/adapter-records.json`.
//!
//! A Records stream holds a small database: tables of rows, each row a set
//! of columns. A transaction is one changeset, the content of one unit.
//! Each cell keeps the value of the changeset with the greatest stamp: a
//! logical clock, then the writer, then the event ID. A changeset's clock is
//! admitted only when the changesets that exist support it.
//!
//! - [`changeset`]: the data model and changesets (sections 2.1, 2.2).
//! - [`clock`]: the logical clock, admission and the stamp (sections 3.1,
//!   3.3), which the Blobs adapter uses too.
//! - [`suggestions`]: keys 4 to 6, the `suggest` check and the suggestion
//!   layer (section 3.4), which the Blobs adapter uses too.
//! - [`state`]: the stream's state and the snapshot state (sections 2.3,
//!   3.3).
//! - [`Records`]: the adapter, with the checks of section 3.2.

pub mod changeset;
pub mod clock;
pub mod read;
pub mod state;
pub mod suggestions;

pub use changeset::{Changeset, Content, Op};
pub use clock::{Admission, Clock, Stamp, admit};
pub use state::State;
pub use suggestions::{Layer, Suggestion, SuggestionKeys};

use frasil_adapter::{
    Adapter, CapabilityChecks, Compaction, Context, EphemeralContext, EventId, Outcome, Writer,
    suggest_check_snapshot,
};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeSet;

/// The adapter type.
pub const TYPE: &str = "frasil:records";

frasil_base::error_classes! {
    /// The classes adapter-records.md defines (section 3.7). It also uses
    /// `Malformed`, `UnknownContentVersion`, `CapabilityRefused` and
    /// `BadCompaction`; each refuses content only.
    pub enum RecordsClass {
        /// A changeset whose clock the counted changesets do not yet
        /// support. Its content waits; the unit's verdict stands.
        ClockAhead = "clock_ahead", Pending;
    }
}

/// The Records adapter, with the capability checks registered with it.
#[derive(Debug, Clone, Default)]
pub struct Records {
    /// Capability checks, which run at step 4 of section 3.2 after the
    /// `suggest` check.
    pub checks: CapabilityChecks,
}

impl Records {
    /// The adapter with no registered capability checks.
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter with these registered capability checks.
    pub fn with_checks(checks: CapabilityChecks) -> Self {
        Self { checks }
    }
}

impl Adapter for Records {
    const TYPE: &'static str = TYPE;
    type Change = Content;
    type State = State;
    type Class = RecordsClass;

    fn encode(&self, change: &Content) -> Vec<u8> {
        change.encode()
    }

    /// adapter-records.md, section 3.2, "The checks", steps 1 to 4. Step 5,
    /// admission, is [`apply`](Adapter::apply)'s.
    fn decode(&self, content: &[u8], context: &Context) -> Result<Content, RecordsClass> {
        // Steps 1 to 3.
        let read = Content::read(content, context.role)?;
        // Step 4: the suggest check, then any registered capability checks.
        match &read {
            Content::Changeset(changeset) => changeset.keys.suggest_check(context)?,
            Content::Snapshot => suggest_check_snapshot(context)?,
        }
        self.checks.run(context, content)?;
        Ok(read)
    }

    fn empty(&self) -> State {
        State::new()
    }

    /// Counts a placed unit's changeset whose content passes steps 1 to 3,
    /// whatever the write rule's verdict (section 3.1).
    fn count(&self, state: &mut State, context: &Context, content: &[u8]) {
        if let Ok(Content::Changeset(changeset)) = Content::read(content, context.role) {
            state.count(context.event_id, changeset.clock);
        }
    }

    /// Applies an accepted changeset once it is admitted (step 5); until
    /// then it waits (`ClockAhead`). A snapshot unit applies nothing.
    fn apply(
        &self,
        state: &mut State,
        context: &Context,
        change: &Content,
    ) -> Outcome<RecordsClass> {
        match change {
            Content::Snapshot => Outcome::Applied,
            Content::Changeset(changeset) => {
                if state.submit(context.event_id, context.author, changeset) {
                    Outcome::Applied
                } else {
                    Outcome::Waiting(RecordsClass::ClockAhead)
                }
            }
        }
    }

    fn held(&self, state: &State) -> Vec<(EventId, RecordsClass)> {
        state
            .admission()
            .held()
            .map(|event_id| (*event_id, RecordsClass::ClockAhead))
            .collect()
    }

    /// Compaction (section 3.5): the state, built over the base and the
    /// cover alone, with its open suggestions; the snapshot unit's content
    /// is empty, and Records references no object.
    fn compact(&self, state: &State) -> Compaction {
        Compaction {
            state: state.to_bytes(false),
            metadata: Vec::new(),
            included: state.included().clone(),
            objects: BTreeSet::new(),
            supersedes: Vec::new(),
        }
    }

    fn load(&self, snapshot_state: &[u8]) -> Result<State, RecordsClass> {
        Ok(State::from_bytes(snapshot_state)?)
    }

    /// The same map without key 4 (section 2.3).
    fn export_history_free(&self, state: &State) -> Result<Vec<u8>, RecordsClass> {
        Ok(state.to_bytes(true))
    }

    /// Re-applying a late write (section 3.6): its ops again, in a
    /// changeset of the re-applier's own under its own clock in the moved
    /// document. A suggestion, which no writer but its author may write, is
    /// not re-applied; accepts and dismisses name suggestions of the
    /// original stream and are dropped.
    fn reapply(
        &self,
        _original: &State,
        _late: &Context,
        change: &Content,
        new: &State,
        _writer: &Writer,
    ) -> Option<Vec<u8>> {
        match change {
            Content::Changeset(changeset) if !changeset.keys.suggestion => {
                Some(Changeset::new(new.next_clock(), changeset.ops.clone()).encode())
            }
            _ => None,
        }
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
    use frasil_adapter::{Capabilities, Capability, Check, Mode, Role, SUGGEST};
    use frasil_base::cbor::Value;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    const WRITER: Writer = Writer {
        space: [0; 32],
        stream: [1; 16],
        author: [2; 32],
        seq: 2,
    };

    fn context(id: u8, role: Role) -> Context {
        Context::new([0; 32], [1; 16], [id; 32], [id; 32], 1, 1, role)
    }

    #[test]
    fn its_own_class_is_named_as_the_spec_names_it() {
        for class in RecordsClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(RecordsClass::ClockAhead.sort(), Sort::Pending);
    }

    #[test]
    fn registered_checks_run_after_the_suggest_check() {
        let mut checks = CapabilityChecks::new();
        checks.register("no-snapshots", |_, context, _| {
            if context.is_snapshot() {
                Check::Refuse
            } else {
                Check::Accept
            }
        });
        let records = Records::with_checks(checks);
        assert_eq!(
            records.decode(&[], &context(1, Role::Snapshot)),
            Err(RecordsClass::Shared(ErrorClass::CapabilityRefused))
        );
        let content = Changeset::new(1, vec![Op::insert_row("t", b"r".to_vec())]).encode();
        assert!(records.decode(&content, &context(1, Role::Log)).is_ok());
    }

    #[test]
    fn a_late_write_is_reapplied_under_the_new_clock() {
        let records = Records::new();
        let late = Changeset::new(7, vec![Op::set("t", b"r".to_vec(), "c", Value::from("x"))]);
        let mut new = State::new();
        new.submit(
            [1; 32],
            [1; 32],
            &Changeset::new(1, vec![Op::insert_row("t", b"r".to_vec())]),
        );
        let content = records
            .reapply(
                &State::new(),
                &context(2, Role::Log),
                &Content::Changeset(late.clone()),
                &new,
                &WRITER,
            )
            .unwrap();
        assert_eq!(Changeset::read(&content), Ok(Changeset::new(2, late.ops)));
        let mut suggestion = Changeset::new(1, vec![Op::insert_row("t", b"r".to_vec())]);
        suggestion.keys.suggestion = true;
        assert!(
            records
                .reapply(
                    &new,
                    &context(2, Role::Log),
                    &Content::Changeset(suggestion),
                    &new,
                    &WRITER
                )
                .is_none()
        );
    }

    #[test]
    fn a_suggesters_suggestion_is_accepted_and_its_snapshot_unit_refused() {
        let records = Records::new();
        let suggester = Capabilities::new([Capability::new(SUGGEST, Mode::Narrows)]);
        let mut suggestion = Changeset::new(1, vec![Op::insert_row("t", b"r".to_vec())]);
        suggestion.keys.suggestion = true;
        let log = context(1, Role::Log).with_capabilities(suggester.clone());
        assert!(records.decode(&suggestion.encode(), &log).is_ok());
        let snapshot = context(1, Role::Snapshot).with_capabilities(suggester);
        assert_eq!(
            records.decode(&[], &snapshot).map_err(Class::name),
            Err("CapabilityRefused")
        );
    }
}
