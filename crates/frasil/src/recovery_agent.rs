//! The recovery agent through the engine (ext-recovery-agent.md, feature
//! `ext-recovery-agent`).
//!
//! - **The waiting period.** Each space's verifier decisions run at every
//!   refresh ([`Agents::decide`]): the device's own first sight of each
//!   `add` rooted in an agent is its list event's first sight, kept in its
//!   event record; a list member decided `Vouched` is kept in the space's
//!   `vouched` table, committed with the refresh that decided it, before
//!   any wrap made on the strength of it, and deleted once the member is no
//!   longer active. `W` is the space's `agent_waiting_period`.
//! - **Recipients.** A person grant wraps for a waiting list member only
//!   once the space vouches for it ([`crate::device::person_recipients`]).
//!   A writer then delivers the space's current state to it
//!   ([`Engine::deliver_vouched`]).
//! - **Relay and raise.** A device that first holds an `add` rooted in an
//!   agent forwards it, with the list events before it, into the system
//!   stream of each space it writes in that grants the person, before
//!   anything else it writes there; for its own person, it raises the add
//!   as a notice whose `space` is the person ID.
//! - **Veto.** [`Engine::veto`] signs the revocations in order, each
//!   inserted before the next is signed, so the signer's chain never forks.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::writer::Recipient;
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_identity::ext_recovery_agent::{AgentWaits, new_agent_adds};
use frasil_identity::merge::MergedList;
use frasil_space::ext_recovery_agent::waiting_period;
use frasil_space::{Level, MemberType, Policy};
use std::collections::{BTreeMap, BTreeSet};

/// What a device keeps of the recovery agent.
#[derive(Default)]
pub(crate) struct AgentState {
    /// Each space's `vouched` records: list member to person.
    pub vouched: BTreeMap<EventId, BTreeMap<DeviceId, [u8; 32]>>,
    /// Spaces that owe a relay of a person's list, each with the persons.
    pub relays: BTreeMap<EventId, BTreeSet<[u8; 32]>>,
    /// List members a space newly vouched for, which a writer delivers the
    /// space's current state to.
    pub deliveries: BTreeMap<EventId, BTreeSet<DeviceId>>,
}

/// What a replica's refresh reads to decide its waiting list members.
pub(crate) struct Agents<'a> {
    /// The reading now.
    pub now: Reading,
    /// The first sight of each list event this device holds.
    pub sights: &'a BTreeMap<EventId, Reading>,
    /// The space's `vouched` records.
    pub vouched: Option<&'a BTreeMap<DeviceId, [u8; 32]>>,
}

impl Agents<'_> {
    /// The list members this verifier vouches for in a space of `policy`,
    /// by person (ext-recovery-agent.md, "The waiting period").
    pub fn decide(
        &self,
        lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
        policy: &Policy,
    ) -> BTreeMap<[u8; 32], BTreeSet<DeviceId>> {
        let period = waiting_period(policy);
        let mut out = BTreeMap::new();
        for (person, list) in lists {
            let merged = list.merge();
            if merged.agent_rooted().next().is_none() {
                continue;
            }
            let kept = self.vouched.into_iter().flat_map(|records| {
                records
                    .iter()
                    .filter(|(_, p)| *p == person)
                    .map(|(device, _)| *device)
            });
            let mut waits = AgentWaits::from_parts(
                self.sights.iter().map(|(id, reading)| (*id, *reading)),
                kept,
            );
            waits.see(&merged, self.now);
            let vouched = waits.decide_all(&merged, &self.now, period);
            if !vouched.is_empty() {
                out.insert(*person, vouched);
            }
        }
        out
    }
}

/// The recipients under a person grant: the merged list's, with each
/// waiting list member this space vouches for; none at all where the space
/// forbids agents and the list holds an active one (identity.md, "What a
/// list vouches for").
pub(crate) fn vouched_recipients(
    merged: &MergedList,
    vouched: &BTreeSet<DeviceId>,
) -> Vec<DeviceId> {
    merged.recipients_with(|member| vouched.contains(&member.device))
}

/// The `add`s rooted in an agent that a list holds now and did not
/// before.
pub(crate) fn new_adds(before: Option<&MergedList>, after: &MergedList) -> Vec<EventId> {
    new_agent_adds(before, after)
}

impl Engine {
    /// Notes what new list events bring (ext-recovery-agent.md, "Relay and
    /// veto"): each space this device holds that grants a person with a new
    /// `add` rooted in an agent owes its relay; an `add` to this device's
    /// own person is raised. Returns the raised adds.
    pub(crate) fn note_agent_adds(
        state: &mut State,
        before: &BTreeMap<[u8; 32], Option<MergedList>>,
    ) -> Vec<EventId> {
        let mut raised = Vec::new();
        let persons: Vec<[u8; 32]> = before.keys().copied().collect();
        for person in persons {
            let Some(list) = state.lists.get(&person) else {
                continue;
            };
            let after = list.merge();
            let adds = new_adds(before.get(&person).and_then(Option::as_ref), &after);
            if adds.is_empty() {
                continue;
            }
            if state.person == Some(person) {
                raised.extend(adds.iter().copied());
            }
            let granting: Vec<EventId> = state
                .replicas
                .iter()
                .filter(|(_, replica)| {
                    replica
                        .roster()
                        .members_in()
                        .any(|(m, _)| m.kind == MemberType::Person && m.id == person)
                })
                .map(|(space, _)| *space)
                .collect();
            for space in granting {
                state.agents.relays.entry(space).or_default().insert(person);
            }
        }
        raised
    }

    /// The relays `space` owes, taken: the persons whose list goes into its
    /// system stream before anything else this device writes there.
    pub(crate) fn take_relays(state: &mut State, space: &EventId) -> Vec<[u8; 32]> {
        state
            .agents
            .relays
            .remove(space)
            .map(|persons| persons.into_iter().collect())
            .unwrap_or_default()
    }

    /// The list events of `person` that `space` holds no copy of, in
    /// canonical order: an `add`, with the events before it.
    pub(crate) fn relay_events(state: &State, space: &EventId, person: &[u8; 32]) -> Vec<Vec<u8>> {
        let Some(list) = state.lists.get(person) else {
            return Vec::new();
        };
        let held = state
            .replicas
            .get(space)
            .map(crate::replica::Replica::list_copies_held)
            .unwrap_or_default();
        list.canonical()
            .into_iter()
            .filter(|id| !held.contains(id))
            .filter_map(|id| list.event(id).map(frasil_events::Event::signed))
            .collect()
    }

    /// Relays the lists `space` owes into its system stream, and delivers
    /// the space's current state to the list members it newly vouched for:
    /// what the device's upkeep runs where it writes.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_system`] and [`Engine::deliver_vouched`].
    pub async fn relay_agent_adds(&self, space: EventId) -> Result<()> {
        // A waiting period that ran since the last refresh: judge again,
        // which keeps the new decisions.
        {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let changed = state.replicas.get(&space).is_some_and(|replica| {
                let agents = Agents {
                    now,
                    sights: &state.list_sights,
                    vouched: state.agents.vouched.get(&space),
                };
                agents.decide(&state.lists, replica.policy()) != *replica.vouched()
            });
            if changed {
                Box::pin(self.settle_one(&mut state, space, Vec::new(), now)).await?;
            }
        }
        let writes = self
            .read(&space, |replica| {
                replica.level_of(&self.device_id()) >= Some(Level::Write)
            })
            .await?;
        if !writes {
            return Ok(());
        }
        let pending = !self
            .lock()
            .await
            .agents
            .relays
            .get(&space)
            .is_none_or(BTreeSet::is_empty);
        if pending {
            // A write relays first.
            let mut state = self.lock().await;
            self.relay_owed(&mut state, space).await?;
        }
        self.deliver_vouched(space).await
    }

    /// Delivers the space's current state to each list member it newly
    /// vouched for (ext-recovery-agent.md, "Adding a device through the
    /// agent", step 4).
    ///
    /// # Errors
    ///
    /// As [`Engine::deliver`].
    pub async fn deliver_vouched(&self, space: EventId) -> Result<()> {
        let recipients: Vec<Recipient> = {
            let mut state = self.lock().await;
            let Some(devices) = state.agents.deliveries.remove(&space) else {
                return Ok(());
            };
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(());
            };
            devices
                .iter()
                .filter_map(|device| {
                    let (person, level) = replica.roster().members_in().find_map(|(m, s)| {
                        (m.kind == MemberType::Person
                            && state
                                .lists
                                .get(&m.id)
                                .is_some_and(|list| list.merge().active(device).is_some()))
                        .then_some((m.id, s.level))
                    })?;
                    let list = state.lists.get(&person)?;
                    let merged = list.merge();
                    let keys = merged.keys(device)?;
                    keys.xwing.as_ref()?;
                    Some(Recipient {
                        keys: keys.device_keys(),
                        writes: level >= Level::Write,
                        propagates: true,
                    })
                })
                .collect()
        };
        if recipients.is_empty() {
            return Ok(());
        }
        self.deliver(space, recipients).await.map(drop)
    }

    /// Vetoes an `add` rooted in an agent to this device's own person
    /// (ext-recovery-agent.md, "Relay and veto"): revokes `device`, every
    /// list member added through it, and with `with_agent` the agent too.
    /// Each revocation is signed and inserted before the next, then the
    /// list goes to every space that grants the person where this device
    /// writes. Returns the revocations.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is no person's, or a
    /// `device` that is no active list member rooted in an agent;
    /// `AgentLimited` and the list's classes; the store's.
    pub async fn veto(&self, device: DeviceId, with_agent: bool) -> Result<Vec<EventId>> {
        let person = self
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let bodies = {
            let state = self.lock().await;
            let list = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?;
            list.veto(&list.merge(), &device, with_agent)
        };
        if bodies.is_empty() {
            return Err(Error::NotAllowed(
                "the veto names an active list member an agent added",
            ));
        }
        let mut revoked = Vec::new();
        for body in bodies {
            let mut state = self.lock().await;
            let signed = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?
                .sign(&body, self.signer());
            let id = frasil_events::decode(&signed).map_err(Error::class)?.id();
            self.keep_lists(&mut state, vec![signed]).await?;
            let merged = state
                .lists
                .get(&person)
                .map(crate::lists::PersonList::merge);
            if !merged.is_some_and(|m| m.is_valid(id)) {
                return Err(Error::Class("AgentLimited"));
            }
            revoked.push(id);
        }
        for space in self.spaces().await {
            let grants = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .members_in()
                        .any(|(m, _)| m.kind == MemberType::Person && m.id == person)
                        && replica.level_of(&self.device_id()) >= Some(Level::Write)
                })
                .await?;
            let waits = {
                let state = self.lock().await;
                self.cascade_waits(&state, &space)
            };
            if grants && !waits {
                self.publish_list(space, &person).await?;
            }
        }
        Ok(revoked)
    }

    /// Names a recovery agent for this device's person
    /// (ext-recovery-agent.md, "Naming an agent", step 3): checks its keys
    /// and proof, signs its `add` with this device, which must be active
    /// and not rooted, and publishes the list in every space that grants
    /// the person where this device writes. Before this, the application
    /// tells the person that the agent can take over their identity after
    /// the waiting period unless one of their devices vetoes, and which of
    /// their spaces forbid agents ([`Engine::spaces_forbidding_agents`]).
    /// Returns the `add`; the agent receives the list's events up to it.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; the list's classes;
    /// the store's.
    pub async fn name_agent(
        &self,
        agent: frasil_identity::PublicKeys,
        proof: Vec<u8>,
    ) -> Result<(EventId, Vec<Vec<u8>>)> {
        let person = self
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let signed = {
            let state = self.lock().await;
            state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?
                .whole()
                .ok_or(Error::NotAllowed(
                    "the device holds this list from a checkpoint on",
                ))?
                .name_agent(&agent, &proof, &self.member_keys())
                .map_err(Error::class)?
        };
        let add = frasil_events::decode(&signed).map_err(Error::class)?.id();
        let past = {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, vec![signed]).await?;
            let list = state.lists.get(&person);
            if !list.is_some_and(|l| l.merge().is_valid(add)) {
                return Err(Error::Class("NotInList"));
            }
            list.map(|l| l.with_past(add)).unwrap_or_default()
        };
        for space in self.spaces().await {
            let grants = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .members_in()
                        .any(|(m, _)| m.kind == MemberType::Person && m.id == person)
                        && replica.level_of(&self.device_id()) >= Some(Level::Write)
                })
                .await?;
            if grants {
                self.publish_list(space, &person).await?;
            }
        }
        Ok((add, past))
    }

    /// The spaces this device holds whose policy forbids agents, which a
    /// person is told of before naming one.
    pub async fn spaces_forbidding_agents(&self) -> Vec<EventId> {
        let state = self.lock().await;
        state
            .replicas
            .iter()
            .filter(|(_, replica)| replica.policy().forbid_agents)
            .map(|(space, _)| *space)
            .collect()
    }

    /// The waiting list members this device vouches for in `space`, kept
    /// in its `vouched` records.
    pub async fn vouched(&self, space: &EventId) -> Vec<DeviceId> {
        let state = self.lock().await;
        state
            .agents
            .vouched
            .get(space)
            .map(|records| records.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The list members an agent added to this device's own person that
    /// are active and still wait at this device: what the person may veto.
    pub async fn agent_added(&self) -> Vec<DeviceId> {
        let state = self.lock().await;
        let Some(list) = state.person.and_then(|p| state.lists.get(&p)) else {
            return Vec::new();
        };
        let merged = list.merge();
        merged
            .agent_rooted()
            .filter(|m| merged.active(&m.device).is_some())
            .map(|m| m.device)
            .collect()
    }

    /// Writes the relays `space` owes into its system stream: each person's
    /// list events it holds no copy of, as `frasil:list` units, before
    /// anything else this device writes there (ext-recovery-agent.md,
    /// "Relay and veto").
    pub(crate) async fn relay_owed(&self, state: &mut State, space: EventId) -> Result<()> {
        let persons = Self::take_relays(state, &space);
        if persons.is_empty() {
            return Ok(());
        }
        let system = state
            .replicas
            .get(&space)
            .and_then(crate::replica::Replica::system_stream)
            .ok_or(Error::NotAllowed("the genesis is not opened"))?;
        for person in persons {
            let events = Self::relay_events(state, &space, &person);
            for chunk in events.chunks(frasil_units::limits::MAX_LIST_EVENTS) {
                let content = frasil_units::own::list_copy_content(chunk);
                self.write_parts_now(
                    state,
                    space,
                    system,
                    None,
                    frasil_units::types::LIST,
                    |_, _, _| {
                        Ok(crate::device::UnitParts {
                            content,
                            ..crate::device::UnitParts::default()
                        })
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    /// The list members a raised notice names: `Some` when the notice is
    /// the raise of `add`s rooted in an agent to this device's own person,
    /// whose `space` is the person ID.
    pub(crate) async fn raised(&self, notice: &crate::device::Notice) -> Option<Vec<DeviceId>> {
        let state = self.lock().await;
        let person = state.person.filter(|p| *p == notice.space.0)?;
        let list = state.lists.get(&person)?;
        Some(
            notice
                .placed
                .iter()
                .filter_map(|add| list.body(*add).map(|body| body.device))
                .collect(),
        )
    }
}
