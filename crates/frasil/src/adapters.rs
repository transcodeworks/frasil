//! The adapter registry (units.md, "The adapter interface").
//!
//! An adapter is registered under a type (units.md, "Adapter types"). The
//! replica keeps one [`StreamRuntime`] per stream it reads: the stream's
//! rebuild set and its adapter's state (`frasil_units::runtime::Stream`),
//! behind a trait object so that one replica holds streams of many types.
//! A unit of a type the registry has no adapter for is kept and its content
//! ignored (`UnknownAdapter`).

use frasil_adapter::{Adapter, Compaction, Outcome, StreamUnit};
use frasil_base::errors::Class;
use frasil_units::runtime::{Stream, VerdictChange};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What became of a unit's content at its adapter, with the class by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentOutcome {
    /// The content is accepted and applied.
    Applied,
    /// The content is accepted and waits inside the adapter.
    Waiting(&'static str),
    /// The content has no effect: refused as content, or ignored.
    Refused(&'static str),
    /// The unit is not valid by the write rule; its content only counted.
    Counted,
}

impl<C: Class> From<Outcome<C>> for ContentOutcome {
    fn from(outcome: Outcome<C>) -> Self {
        match outcome {
            Outcome::Applied => Self::Applied,
            Outcome::Waiting(class) => Self::Waiting(class.name()),
            Outcome::Refused(class) => Self::Refused(class.name()),
            Outcome::Counted => Self::Counted,
        }
    }
}

/// One stream at a replica, whatever its adapter.
pub trait StreamRuntime: Send {
    /// The adapter type.
    fn adapter_type(&self) -> &'static str;

    /// Hands over one unit as it arrives (units.md, "Rebuilds").
    fn receive(&mut self, unit: StreamUnit) -> Option<ContentOutcome>;

    /// Records a unit's verdict by the write rule.
    fn set_valid(&mut self, id: &[u8; 32], valid: bool) -> VerdictChange;

    /// Records the capabilities a unit's author holds at its place, as the
    /// roster or a granted space's facts change them (units.md, 3.17
    /// "Capability checks").
    fn set_capabilities(
        &mut self,
        id: &[u8; 32],
        capabilities: frasil_adapter::Capabilities,
    ) -> VerdictChange;

    /// Rebuilds the stream's state from its rebuild set, in canonical order.
    fn rebuild(&mut self);

    /// Drops the snapshot in use and rebuilds from the units held.
    fn drop_snapshot(&mut self);

    /// Uses a snapshot's state (units.md, "Checking, using and settling a
    /// snapshot"): its cover held, the units it does not include handed
    /// back. `false` when the adapter cannot load the state.
    fn use_snapshot(
        &mut self,
        state: Vec<u8>,
        cover: std::collections::BTreeSet<[u8; 32]>,
        excluded: std::collections::BTreeSet<[u8; 32]>,
        supersedes: Vec<frasil_adapter::Supersession>,
    ) -> bool;

    /// What became of a unit's content.
    fn outcome(&self, id: &[u8; 32]) -> Option<ContentOutcome>;

    /// The adapter's history-free export of the state (units.md, "The
    /// adapter interface", item 5); `None` when the adapter refuses it, as
    /// a state its `load` would refuse.
    fn export_history_free(&self) -> Option<Vec<u8>>;

    /// The largest snapshot state the adapter loads, if it has a limit
    /// ([`Adapter::max_state_bytes`]).
    fn max_state_bytes(&self) -> Option<u64>;

    /// The supersessions that travel beside that export
    /// (ext-file-versions.md, 3.3 The supersession set).
    fn export_supersedes(&self) -> Vec<frasil_adapter::Supersession>;

    /// Whether the stream holds no unit and uses no snapshot: a stream
    /// opened for a lent document before its first write.
    fn is_empty(&self) -> bool;

    /// The runtime itself, for typed access to the adapter's state.
    fn as_any(&self) -> &dyn Any;

    /// The adapter's compaction of the state built over the snapshot in use
    /// and the units of `cover` alone (units.md, "Compacting").
    fn compact(&self, cover: &BTreeSet<[u8; 32]>) -> Option<Compaction>;

    /// The units the snapshot in use includes.
    fn base_cover(&self) -> BTreeSet<[u8; 32]>;

    /// Whether the stream holds any of these units.
    fn holds_any(&self, units: &BTreeSet<[u8; 32]>) -> bool;

    /// The adapter's capability checks on an ephemeral message or slot
    /// value (ext-ephemeral.md, "Capability checks"): whether `data`, with
    /// the frame's context, passes.
    #[cfg(feature = "ephemeral")]
    fn check_ephemeral(&self, context: &frasil_adapter::EphemeralContext, data: &[u8]) -> bool;

    /// `reapply(original state, late unit, new state, writer)` of a unit
    /// this stream holds, against `new`, a stream of the same adapter
    /// (units.md, "The adapter interface"; ext-restricted-spaces.md,
    /// "Re-applying a late write"): the content of the re-applier's unit,
    /// or `None`.
    #[cfg(feature = "ext-restricted-spaces")]
    fn reapply(
        &self,
        late: &[u8; 32],
        new: &dyn StreamRuntime,
        writer: &frasil_adapter::Writer,
    ) -> Option<Vec<u8>>;
}

impl<A> StreamRuntime for Stream<A>
where
    A: Adapter + Send + 'static,
    A::State: Send + 'static,
    A::Class: Send + 'static,
{
    #[cfg(feature = "ephemeral")]
    fn check_ephemeral(&self, context: &frasil_adapter::EphemeralContext, data: &[u8]) -> bool {
        self.adapter().check_ephemeral(context, data).is_ok()
    }

    fn adapter_type(&self) -> &'static str {
        A::TYPE
    }

    fn receive(&mut self, unit: StreamUnit) -> Option<ContentOutcome> {
        Stream::receive(self, unit).map(ContentOutcome::from)
    }

    fn set_valid(&mut self, id: &[u8; 32], valid: bool) -> VerdictChange {
        Stream::set_valid(self, id, valid)
    }

    fn set_capabilities(
        &mut self,
        id: &[u8; 32],
        capabilities: frasil_adapter::Capabilities,
    ) -> VerdictChange {
        Stream::set_capabilities(self, id, capabilities)
    }

    fn rebuild(&mut self) {
        // A stream with no snapshot always rebuilds; a snapshot that does
        // not load leaves the stream as it was.
        let _ = Stream::rebuild(self);
    }

    fn drop_snapshot(&mut self) {
        Stream::drop_snapshot(self);
    }

    fn use_snapshot(
        &mut self,
        state: Vec<u8>,
        cover: std::collections::BTreeSet<[u8; 32]>,
        excluded: std::collections::BTreeSet<[u8; 32]>,
        supersedes: Vec<frasil_adapter::Supersession>,
    ) -> bool {
        Stream::use_snapshot(
            self,
            frasil_units::runtime::Base {
                state,
                cover,
                excluded,
                supersedes,
            },
        )
        .is_ok()
    }

    fn outcome(&self, id: &[u8; 32]) -> Option<ContentOutcome> {
        Stream::outcome(self, id).copied().map(ContentOutcome::from)
    }

    fn export_history_free(&self) -> Option<Vec<u8>> {
        self.adapter().export_history_free(self.state()).ok()
    }

    fn max_state_bytes(&self) -> Option<u64> {
        self.adapter().max_state_bytes()
    }

    fn export_supersedes(&self) -> Vec<frasil_adapter::Supersession> {
        self.adapter().export_supersedes(self.state())
    }

    fn is_empty(&self) -> bool {
        self.base().is_none() && self.units().next().is_none()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn compact(&self, cover: &BTreeSet<[u8; 32]>) -> Option<Compaction> {
        let base = self.base();
        let units: Vec<StreamUnit> = self
            .units()
            .filter(|unit| {
                cover.contains(&unit.context.event_id)
                    && !base.is_some_and(|base| base.includes(&unit.context.event_id))
            })
            .cloned()
            .collect();
        let state = self
            .adapter()
            .rebuild_with(
                base.map(|base| base.state.as_slice()),
                base.map_or(&[], |base| base.supersedes.as_slice()),
                &units,
            )
            .ok()?;
        Some(self.adapter().compact(&state))
    }

    fn base_cover(&self) -> BTreeSet<[u8; 32]> {
        self.base()
            .map(|base| {
                base.cover
                    .iter()
                    .filter(|id| !base.excluded.contains(*id))
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn holds_any(&self, units: &BTreeSet<[u8; 32]>) -> bool {
        self.units()
            .any(|unit| units.contains(&unit.context.event_id))
    }

    #[cfg(feature = "ext-restricted-spaces")]
    fn reapply(
        &self,
        late: &[u8; 32],
        new: &dyn StreamRuntime,
        writer: &frasil_adapter::Writer,
    ) -> Option<Vec<u8>> {
        let unit = self.units().find(|unit| unit.context.event_id == *late)?;
        let change = self.adapter().decode(&unit.content, &unit.context).ok()?;
        let new = new.as_any().downcast_ref::<Stream<A>>()?;
        self.adapter()
            .reapply(self.state(), &unit.context, &change, new.state(), writer)
    }
}

type Factory = Arc<dyn Fn() -> Box<dyn StreamRuntime> + Send + Sync>;

/// The adapters a device registers, by type.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    factories: BTreeMap<String, Factory>,
}

impl core::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.factories.keys()).finish()
    }
}

impl AdapterRegistry {
    /// A registry with no adapter.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with every built-in adapter this build has: Loro,
    /// Records and Blobs, each by its feature.
    pub fn with_builtins() -> Self {
        #[allow(unused_mut)]
        let mut registry = Self::new();
        #[cfg(feature = "adapter-loro")]
        registry.register(frasil_adapter_loro::Loro::new());
        #[cfg(feature = "adapter-records")]
        registry.register(frasil_adapter_records::Records::default());
        #[cfg(feature = "adapter-blobs")]
        registry.register(frasil_adapter_blobs::Blobs::default());
        registry
    }

    /// Registers an adapter under its type, replacing any earlier one.
    pub fn register<A>(&mut self, adapter: A)
    where
        A: Adapter + Clone + Send + Sync + 'static,
        A::State: Send + 'static,
        A::Class: Send + 'static,
    {
        let factory: Factory = Arc::new(move || Box::new(Stream::new(adapter.clone())));
        self.factories.insert(A::TYPE.to_owned(), factory);
    }

    /// Whether an adapter is registered under a type.
    pub fn knows(&self, adapter_type: &str) -> bool {
        self.factories.contains_key(adapter_type)
    }

    /// The capability checks of the adapter registered under a type on an
    /// ephemeral frame's data (ext-ephemeral.md, "Capability checks"):
    /// `None` when no adapter is registered under it.
    #[cfg(feature = "ephemeral")]
    pub fn check_ephemeral(
        &self,
        adapter_type: &str,
        context: &frasil_adapter::EphemeralContext,
        data: &[u8],
    ) -> Option<bool> {
        self.stream(adapter_type)
            .map(|stream| stream.check_ephemeral(context, data))
    }

    /// A new stream of a type, if an adapter is registered under it.
    pub fn stream(&self, adapter_type: &str) -> Option<Box<dyn StreamRuntime>> {
        self.factories.get(adapter_type).map(|factory| factory())
    }

    /// The largest snapshot state an adapter type loads, if it has a
    /// limit: what a state object of a stream of that type may hold.
    pub fn max_state_bytes(&self, adapter_type: &str) -> Option<u64> {
        self.stream(adapter_type)?.max_state_bytes()
    }

    /// The registered types.
    pub fn types(&self) -> impl Iterator<Item = &str> {
        self.factories.keys().map(String::as_str)
    }
}

#[cfg(all(test, feature = "ephemeral", feature = "adapter-records"))]
mod tests {
    use super::*;
    use frasil_adapter::{
        Capabilities, CapabilityChecks, Check, EphemeralContext, EphemeralKind, Level,
    };

    #[test]
    fn an_ephemeral_frame_runs_the_named_adapters_checks() {
        let mut checks = CapabilityChecks::new();
        checks.register_ephemeral("example.writers-only", |_, context, _| {
            if context.level >= Level::Write {
                Check::Accept
            } else {
                Check::Refuse
            }
        });
        let mut registry = AdapterRegistry::new();
        registry.register(frasil_adapter_records::Records::with_checks(checks));
        let frame = |level| EphemeralContext {
            space: [1; 32],
            kind: EphemeralKind::Message,
            name: "cursor".into(),
            stream: None,
            targets: None,
            sender: [2; 32],
            level,
            capabilities: Capabilities::default(),
        };
        let records = frasil_adapter_records::Records::TYPE;
        assert_eq!(
            registry.check_ephemeral(records, &frame(Level::Write), b""),
            Some(true)
        );
        assert_eq!(
            registry.check_ephemeral(records, &frame(Level::Read), b""),
            Some(false)
        );
        assert_eq!(
            registry.check_ephemeral("example", &frame(Level::Write), b""),
            None
        );
    }
}
