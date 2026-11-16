//! The replica side of the adapter interface (units.md, section 3.17, with
//! section 3.6, "Using", and section 3.8, "Rebuilds"): one stream's
//! rebuild set and its adapter's state.
//!
//! - **The rebuild set.** For each stream, a replica keeps the latest
//!   settled snapshot it uses, or none, and every unit of the stream after
//!   its cover: valid, refused, pending and unopened. With the snapshot
//!   object, that is all an adapter needs.
//! - **Using a snapshot.** A replica loads the snapshot's state in place of
//!   the units it covers. It marks the units of the cover as held
//!   ([`Adapter::hold`]), so that a check that asks whether a unit is held
//!   counts them. Then it hands back, valid or not, every unit of the cover
//!   that the state does not include (the snapshot unit's `excluded`) and
//!   that it holds, so that what a check counts over the cover, such as
//!   adapter-loro.md's step 6 or adapter-records.md's clock, is what a
//!   rebuild from the units counts; over that state it applies any
//!   excluded unit it finds valid. Then the units after the cover.
//! - **Order.** A replica hands accepted units over in canonical order when
//!   it rebuilds, and in arrival order otherwise; the state does not
//!   depend on which.
//! - **When verdicts change** the replica rebuilds each stream that holds a
//!   unit whose verdict changed, once per batch of events it processes.
//!
//! The units handed to a [`Stream`] are those of the stream's own type
//! whose content check passed (section 3.2, step 16:
//! [`content_check`](crate::stream::content_check)).

use crate::inner::Inner;
use crate::unit::Unit;
use frasil_adapter::{Adapter, Capabilities, Context, EventId, Outcome, Role, StreamUnit};
use std::collections::{BTreeMap, BTreeSet};

/// The context of a unit (section 3.17): its space, stream, event ID,
/// author, `seq` and height, its `objects`, whether it is a snapshot unit,
/// its `resubmits` and, with ext-restricted-spaces.md, its `copied_from`,
/// and the capabilities its author holds at its place.
pub fn context(unit: &Unit, inner: &Inner, height: u64, capabilities: Capabilities) -> Context {
    let role = if unit.is_snapshot() {
        Role::Snapshot
    } else {
        Role::Log
    };
    let context = Context::new(
        unit.space().0,
        unit.body.stream,
        unit.id().0,
        unit.event.author().0,
        unit.event.seq(),
        height,
        role,
    )
    .with_objects(unit.body.objects.iter().copied())
    .with_supersedes(unit.body.supersedes.iter().copied())
    .with_capabilities(capabilities)
    .with_resubmits(inner.resubmits.map(|id| id.0));
    #[cfg(feature = "ext-restricted-spaces")]
    let context =
        context.with_copied_from(inner.copied_from.map(|copied| frasil_adapter::CopiedFrom {
            space: copied.space.0,
            event_id: copied.event.0,
        }));
    context
}

/// A snapshot a replica uses for a stream: its state and its cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// The stream snapshot's `state` (key 5).
    pub state: Vec<u8>,
    /// The units of the cover the replica knows of, held or stubbed.
    pub cover: BTreeSet<EventId>,
    /// The snapshot unit's `excluded`: the units of the cover the state
    /// does not include.
    pub excluded: BTreeSet<EventId>,
    /// The supersessions of the snapshot unit (ext-file-versions.md,
    /// section 3.3, "Load").
    pub supersedes: Vec<frasil_adapter::Supersession>,
}

impl Base {
    /// Whether the state includes a unit: it is in the cover and not
    /// excluded.
    pub fn includes(&self, id: &EventId) -> bool {
        self.cover.contains(id) && !self.excluded.contains(id)
    }
}

/// What a verdict change asks of the replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictChange {
    /// Nothing: the verdict is the one held, or the unit is not held.
    None,
    /// A unit of the rebuild set changed: rebuild the stream once the batch
    /// is processed ([`Stream::rebuild`]).
    Rebuild,
    /// A unit the snapshot's state includes is now refused. The replica
    /// drops the state and rebuilds from the units if it holds them
    /// ([`Stream::drop_snapshot`]); else it asks members for a snapshot
    /// built without it, or reports `Unremovable` (section 3.8).
    InsideSnapshot,
}

/// One stream at a replica: its adapter, the snapshot it uses, every unit
/// it holds of the stream, and the adapter's state.
pub struct Stream<A: Adapter> {
    adapter: A,
    base: Option<Base>,
    /// Every unit held, by canonical place.
    units: BTreeMap<(u64, EventId), StreamUnit>,
    places: BTreeMap<EventId, (u64, EventId)>,
    state: A::State,
    outcomes: BTreeMap<EventId, Outcome<A::Class>>,
}

impl<A: Adapter> core::fmt::Debug for Stream<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stream")
            .field("type", &A::TYPE)
            .field("base", &self.base.as_ref().map(|base| base.cover.len()))
            .field("units", &self.units.len())
            .finish_non_exhaustive()
    }
}

impl<A: Adapter> Stream<A> {
    /// A stream with no unit and no snapshot.
    pub fn new(adapter: A) -> Self {
        let state = adapter.empty();
        Self {
            adapter,
            base: None,
            units: BTreeMap::new(),
            places: BTreeMap::new(),
            state,
            outcomes: BTreeMap::new(),
        }
    }

    /// The adapter.
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    /// The adapter's state.
    pub fn state(&self) -> &A::State {
        &self.state
    }

    /// The snapshot in use.
    pub fn base(&self) -> Option<&Base> {
        self.base.as_ref()
    }

    /// What became of a unit's content, or `None` if it was not handed
    /// over: it is not held, or the snapshot's state includes it. A unit
    /// that waited inside the adapter shows as applied once the adapter no
    /// longer holds it.
    pub fn outcome(&self, id: &EventId) -> Option<&Outcome<A::Class>> {
        self.outcomes.get(id)
    }

    /// The units the replica holds of the stream, in canonical order.
    pub fn units(&self) -> impl DoubleEndedIterator<Item = &StreamUnit> {
        self.units.values()
    }

    /// Whether the snapshot's state includes a unit.
    fn included(&self, id: &EventId) -> bool {
        self.base.as_ref().is_some_and(|base| base.includes(id))
    }

    /// Hands over one unit as it arrives: keeps it, and, unless the
    /// snapshot's state includes it, counts it and, if it is valid by the
    /// write rule, applies its content. Returns what became of it. A unit
    /// already held is kept as first held, and handed over again, which
    /// changes nothing.
    pub fn receive(&mut self, unit: StreamUnit) -> Option<Outcome<A::Class>> {
        let id = unit.context.event_id;
        let place = unit.context.canonical();
        let unit = match self.places.get(&id) {
            Some(held) => self.units[held].clone(),
            None => {
                self.places.insert(id, place);
                self.units.insert(place, unit.clone());
                unit
            }
        };
        if self.included(&id) {
            return None;
        }
        let outcome = self.adapter.receive(&mut self.state, &unit);
        self.outcomes.insert(id, outcome);
        settle_waiting(&self.adapter, &self.state, &mut self.outcomes);
        self.outcomes.get(&id).copied()
    }

    /// Records a unit's verdict by the write rule, as a removal learned
    /// late, a removal voided at a merge, or a duel changes it.
    pub fn set_valid(&mut self, id: &EventId, valid: bool) -> VerdictChange {
        let Some(place) = self.places.get(id) else {
            return VerdictChange::None;
        };
        let Some(unit) = self.units.get_mut(place) else {
            return VerdictChange::None;
        };
        if unit.valid == valid {
            return VerdictChange::None;
        }
        unit.valid = valid;
        if self.included(id) {
            if valid {
                VerdictChange::None
            } else {
                VerdictChange::InsideSnapshot
            }
        } else {
            VerdictChange::Rebuild
        }
    }

    /// Records the capabilities a unit's author holds at its place, as the
    /// roster or a granted space's facts change them (section 3.17,
    /// "Capability checks"): the adapter's checks run on its content again.
    pub fn set_capabilities(&mut self, id: &EventId, capabilities: Capabilities) -> VerdictChange {
        let Some(place) = self.places.get(id) else {
            return VerdictChange::None;
        };
        let Some(unit) = self.units.get_mut(place) else {
            return VerdictChange::None;
        };
        if unit.context.capabilities == capabilities {
            return VerdictChange::None;
        }
        unit.context.capabilities = capabilities;
        let valid = unit.valid;
        if self.included(id) {
            // The state includes its content as the compactor judged it.
            VerdictChange::InsideSnapshot
        } else if valid {
            VerdictChange::Rebuild
        } else {
            VerdictChange::None
        }
    }

    /// Uses a snapshot (section 3.6, "Using"): loads its state, marks its
    /// cover as held, hands back every unit of the cover the state does not
    /// include, then the units after the cover, in canonical order.
    ///
    /// # Errors
    ///
    /// The adapter's `load`, for a state that does not decode (`Malformed`):
    /// the replica reports `BadCompaction` and never uses it. The stream is
    /// then as it was.
    pub fn use_snapshot(&mut self, base: Base) -> Result<(), A::Class> {
        let state = self.build(Some(&base))?;
        self.base = Some(base);
        self.state = state;
        Ok(())
    }

    /// Drops the snapshot in use and rebuilds from the units held.
    pub fn drop_snapshot(&mut self) {
        self.base = None;
        // An empty state always loads.
        if let Ok(state) = self.build(None) {
            self.state = state;
        }
    }

    /// Rebuilds the stream's state (section 3.8): loads the snapshot in
    /// use, marks its cover as held, then hands over the rebuild set in
    /// canonical order.
    ///
    /// # Errors
    ///
    /// The adapter's `load`; the stream is then as it was.
    pub fn rebuild(&mut self) -> Result<(), A::Class> {
        let base = self.base.take();
        let built = self.build(base.as_ref());
        self.base = base;
        self.state = built?;
        Ok(())
    }

    fn build(&mut self, base: Option<&Base>) -> Result<A::State, A::Class> {
        let mut state = match base {
            Some(base) => {
                let mut state = self.adapter.load(&base.state)?;
                self.adapter.load_supersedes(&mut state, &base.supersedes);
                self.adapter.hold(&mut state, &base.cover);
                state
            }
            None => self.adapter.empty(),
        };
        let mut outcomes = BTreeMap::new();
        for unit in self.units.values() {
            let id = unit.context.event_id;
            if base.is_some_and(|base| base.includes(&id)) {
                continue;
            }
            outcomes.insert(id, self.adapter.receive(&mut state, unit));
        }
        settle_waiting(&self.adapter, &state, &mut outcomes);
        self.outcomes = outcomes;
        Ok(state)
    }
}

/// A unit whose content waited inside the adapter is applied once the
/// adapter no longer holds it (section 3.17, `apply`: it applies when what
/// it waits for arrives).
fn settle_waiting<A: Adapter>(
    adapter: &A,
    state: &A::State,
    outcomes: &mut BTreeMap<EventId, Outcome<A::Class>>,
) {
    if !outcomes.values().any(|o| matches!(o, Outcome::Waiting(_))) {
        return;
    }
    let held: BTreeMap<EventId, A::Class> = adapter.held(state).into_iter().collect();
    for (id, outcome) in outcomes.iter_mut() {
        if let Outcome::Waiting(_) = outcome {
            *outcome = match held.get(id) {
                Some(class) => Outcome::Waiting(*class),
                None => Outcome::Applied,
            };
        }
    }
}
