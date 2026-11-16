//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's Blobs adapter.
//!
//! Specified by `docs/spec/adapter-blobs.md`, on the interface of
//! `docs/spec/units.md`, section 3.17, "The adapter interface". Its vectors
//! are `docs/spec/vectors/adapter-blobs.json`.
//!
//! A Blobs stream is a set of entries. Each entry is named by a handle and
//! names one object by its locator. Entries resolve per handle by the
//! stamps of adapter-records.md: a put or a remove with the greater stamp
//! holds the handle. The clock, the floor, admission, a writer's clock,
//! stamps and suggestions are `frasil-adapter-records`'s.
//!
//! - [`entry`]: entries and their key references (section 2.1), and
//!   references to an object another space of the library stores, with
//!   that space's ID and the object's key (sections 2.1 and 3.7).
//! - [`content`]: a unit's content and its format checks (sections 2.1,
//!   3.1).
//! - [`state`]: the stream's state and the snapshot state (sections 2.2,
//!   3.2).
//! - [`versions`]: supersessions, with `docs/spec/ext-file-versions.md`.
//! - [`Blobs`]: the adapter, with the checks of section 3.1.

pub mod content;
pub mod entry;
pub mod state;
pub mod versions;

pub use content::{Change, Content, Handle, Op};
pub use entry::{Entry, KeyForm, Reference};
pub use state::State;

use frasil_adapter::{
    Adapter, CapabilityChecks, Compaction, Context, EphemeralContext, EventId, Outcome,
    Supersession, Writer, suggest_check_snapshot,
};
use frasil_base::errors::ErrorClass;

/// The adapter type.
pub const TYPE: &str = "frasil:blobs";

frasil_base::error_classes! {
    /// The classes adapter-blobs.md uses beside the shared ones. It adds no
    /// class: `ObjectNotListed` is units.md's, and `ClockAhead`
    /// adapter-records.md's. Each refuses or holds content only.
    pub enum BlobsClass {
        /// Content names an object its unit does not list (units.md,
        /// section 3.18).
        ObjectNotListed = "object_not_listed", ContentRefused;
        /// A unit whose clock the counted units do not yet support
        /// (adapter-records.md, section 3.7, "Error classes"). Its content
        /// waits; the unit's verdict stands.
        ClockAhead = "clock_ahead", Pending;
        /// A supersession whose successor no put of its unit names, or, in a
        /// snapshot unit, whose successor or predecessor no current entry
        /// names (ext-file-versions.md, section 3.2). It is ignored, and the
        /// content stands.
        BadSupersession = "bad_supersession", Report;
    }
}

impl From<frasil_adapter::ContentClass> for BlobsClass {
    fn from(class: frasil_adapter::ContentClass) -> Self {
        match class {
            frasil_adapter::ContentClass::Shared(class) => Self::Shared(class),
            frasil_adapter::ContentClass::ObjectNotListed => Self::ObjectNotListed,
        }
    }
}

impl From<frasil_adapter_records::RecordsClass> for BlobsClass {
    fn from(class: frasil_adapter_records::RecordsClass) -> Self {
        match class {
            frasil_adapter_records::RecordsClass::Shared(class) => Self::Shared(class),
            frasil_adapter_records::RecordsClass::ClockAhead => Self::ClockAhead,
        }
    }
}

/// The Blobs adapter, with the capability checks registered with it.
#[derive(Debug, Clone, Default)]
pub struct Blobs {
    /// Capability checks, which run at step 4 of section 3.1 after the
    /// `suggest` check.
    pub checks: CapabilityChecks,
}

impl Blobs {
    /// The adapter with no registered capability checks.
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter with these registered capability checks.
    pub fn with_checks(checks: CapabilityChecks) -> Self {
        Self { checks }
    }
}

impl Adapter for Blobs {
    const TYPE: &'static str = TYPE;
    type Change = Content;
    type State = State;
    type Class = BlobsClass;

    fn encode(&self, change: &Content) -> Vec<u8> {
        change.encode()
    }

    /// adapter-blobs.md, section 3.1, "The checks", steps 1 to 4. Step 5,
    /// admission, is [`apply`](Adapter::apply)'s.
    fn decode(&self, content: &[u8], context: &Context) -> Result<Content, BlobsClass> {
        // Steps 1 and 2, the key references in the space's form.
        let form = if context.restricted {
            KeyForm::Restricted
        } else {
            KeyForm::Plain
        };
        let read = Content::read_as(content, context.role, form)?;
        match &read {
            Content::Change(change) => {
                // Step 3.
                if !change.check_objects(&context.objects) {
                    return Err(BlobsClass::ObjectNotListed);
                }
                // Step 4: the suggest check.
                change.keys.suggest_check(context)?;
            }
            Content::Snapshot => suggest_check_snapshot(context)?,
        }
        // Step 4: any registered capability checks.
        self.checks.run(context, content)?;
        Ok(read)
    }

    fn empty(&self) -> State {
        State::new()
    }

    /// Counts a placed unit whose content passes steps 1 and 2, whatever
    /// the write rule's verdict (section 3.2).
    fn count(&self, state: &mut State, context: &Context, content: &[u8]) {
        if let Ok(Content::Change(change)) = Content::read(content, context.role) {
            state.count(context.event_id, change.clock);
        }
    }

    /// Applies an accepted unit once it is admitted (step 5); until then it
    /// waits (`ClockAhead`). A snapshot unit applies nothing.
    fn apply(&self, state: &mut State, context: &Context, change: &Content) -> Outcome<BlobsClass> {
        match change {
            Content::Snapshot => Outcome::Applied,
            Content::Change(change) => {
                let supersedes: &[Supersession] = if cfg!(feature = "ext-file-versions") {
                    &context.supersedes
                } else {
                    &[]
                };
                if state.submit_with(context.event_id, context.author, change, supersedes) {
                    Outcome::Applied
                } else {
                    Outcome::Waiting(BlobsClass::ClockAhead)
                }
            }
        }
    }

    fn held(&self, state: &State) -> Vec<(EventId, BlobsClass)> {
        state
            .admission()
            .held()
            .map(|event_id| (*event_id, BlobsClass::ClockAhead))
            .collect()
    }

    /// Compaction (section 3.4): the state, built over the base and the
    /// cover alone; the snapshot unit's content is empty, and it lists
    /// every current entry's object and every open suggestion's.
    fn compact(&self, state: &State) -> Compaction {
        Compaction {
            state: state.to_bytes(false),
            metadata: Vec::new(),
            included: state.included().clone(),
            objects: state.objects(),
            supersedes: if cfg!(feature = "ext-file-versions") {
                state.snapshot_supersedes()
            } else {
                Vec::new()
            },
        }
    }

    fn load(&self, snapshot_state: &[u8]) -> Result<State, BlobsClass> {
        Ok(State::from_bytes(snapshot_state)?)
    }

    fn load_supersedes(&self, state: &mut State, supersedes: &[Supersession]) {
        if cfg!(feature = "ext-file-versions") {
            state.load_supersedes(supersedes);
        }
    }

    /// The same map without key 4 and without removed handles (section
    /// 2.2).
    fn export_history_free(&self, state: &State) -> Result<Vec<u8>, BlobsClass> {
        Ok(state.to_bytes(true))
    }

    /// The pairs section 3.4 of ext-file-versions.md derives from the
    /// current entries and Σ: a history-free export keeps every current
    /// entry, so the same pairs hold for it (section 3.3).
    fn export_supersedes(&self, state: &State) -> Vec<Supersession> {
        if cfg!(feature = "ext-file-versions") {
            state.snapshot_supersedes()
        } else {
            Vec::new()
        }
    }

    /// Re-applying a late write (section 3.6): its ops again, in a unit of
    /// the re-applier's own under its own clock in the moved document. Its
    /// unit lists the objects they name ([`Change::objects`]). A suggestion
    /// is not re-applied; accepts and dismisses are dropped.
    fn reapply(
        &self,
        _original: &State,
        _late: &Context,
        change: &Content,
        new: &State,
        _writer: &Writer,
    ) -> Option<Vec<u8>> {
        match change {
            Content::Change(change) if !change.keys.suggestion => {
                Some(Change::new(new.next_clock(), change.ops.clone()).encode())
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
    use frasil_adapter::{Check, Role};
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn its_classes_are_named_as_the_spec_names_them() {
        for class in BlobsClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(BlobsClass::ClockAhead.sort(), Sort::Pending);
        assert_eq!(BlobsClass::ObjectNotListed.sort(), Sort::ContentRefused);
        assert_eq!(
            BlobsClass::from(frasil_adapter::ContentClass::ObjectNotListed),
            BlobsClass::ObjectNotListed
        );
        assert_eq!(
            BlobsClass::from(frasil_adapter_records::RecordsClass::ClockAhead),
            BlobsClass::ClockAhead
        );
    }

    #[test]
    fn registered_checks_run_on_snapshot_units() {
        let mut checks = CapabilityChecks::new();
        checks.register("no-snapshots", |_, context, _| {
            if context.is_snapshot() {
                Check::Refuse
            } else {
                Check::Accept
            }
        });
        let context = Context::new([0; 32], [1; 16], [2; 32], [3; 32], 1, 1, Role::Snapshot);
        assert_eq!(
            Blobs::with_checks(checks).decode(&[], &context),
            Err(BlobsClass::Shared(ErrorClass::CapabilityRefused))
        );
        assert_eq!(Blobs::new().decode(&[], &context), Ok(Content::Snapshot));
    }

    const WRITER: Writer = Writer {
        space: [0; 32],
        stream: [1; 16],
        author: [4; 32],
        seq: 2,
    };

    #[test]
    fn a_late_write_is_reapplied_under_the_new_clock() {
        let late = Change::new(9, vec![Op::remove([1; 16])]);
        let context = Context::new([0; 32], [1; 16], [2; 32], [3; 32], 1, 1, Role::Log);
        let content = Blobs::new()
            .reapply(
                &State::new(),
                &context,
                &Content::Change(late),
                &State::new(),
                &WRITER,
            )
            .unwrap();
        assert_eq!(
            Change::read(&content),
            Ok(Change::new(1, vec![Op::remove([1; 16])]))
        );
    }
}
