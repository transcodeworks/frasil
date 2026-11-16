//! The recovery agent (ext-recovery-agent.md).
//!
//! identity.md defines the agent's list member kind, rootedness and rank,
//! what an agent may sign, and **waiting**; this module adds what a verifier
//! and a client do with them:
//!
//! - [`agent_waiting`]: the waiting decision, `Waiting`, `Vouched` or
//!   `Vetoed` ("The waiting period");
//! - [`AgentWaits`]: one verifier's first sights of the adds that root list
//!   members in an agent, and its decisions, in one space, with "Vouched
//!   sticks";
//! - [`DeviceList::name_agent`] and [`DeviceList::agent_add_device`]:
//!   "Naming an agent" and "Adding a device through the agent";
//! - [`new_agent_adds`]: what a device raises to its person and relays to
//!   a space ("Relay and veto");
//! - [`DeviceList::veto`] and [`KeptList::veto`]: the veto, an ordinary
//!   revocation, traced through the authors of the adds that rooted list
//!   members in the agent; a list that forgot finds them by its record's
//!   rooting adds, which it keeps.
//!
//! Nothing here reads a clock: every decision takes the verifier's readings
//! (overview.md, "Time"). The decision changes only who this verifier wraps
//! for, never a verdict.

use crate::body::ListBody;
use crate::errors::IdentityClass;
use crate::kept::KeptList;
use crate::keys::{Kind, MemberKeys, PublicKeys};
use crate::list::DeviceList;
use crate::merge::MergedList;
use crate::state::{Member, Rootedness};
use frasil_base::errors::ErrorClass;
use frasil_base::time::{Reading, lower};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet};

/// `agent_waiting_period`'s default and least value, in seconds: 72 hours.
/// A verifier that judges a person's devices outside any space uses it.
pub const AGENT_WAITING_PERIOD: u64 = 259_200;

/// `agent_waiting_period`'s greatest value, in seconds: 30 days.
pub const AGENT_WAITING_PERIOD_MAX: u64 = 2_592_000;

/// The waiting decision's outcome (ext-recovery-agent.md, "Outcomes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Outcome {
    /// The verifier wraps nothing for the list member yet.
    Waiting,
    /// The verifier treats the list member as one that is not waiting.
    Vouched,
    /// The list member is no longer active in the merged list.
    Vetoed,
}

impl Outcome {
    /// The name the vectors use.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Waiting => "Waiting",
            Self::Vouched => "Vouched",
            Self::Vetoed => "Vetoed",
        }
    }
}

/// `agent_waiting(m, first, now, W)` (ext-recovery-agent.md, "The waiting
/// period"), in order:
///
/// ```text
///   1. m is not an active list member of the merged list.        Vetoed
///   2. m is not rooted: a confirm has cleared it.                Vouched
///   3. lower(first, now) >= W.                                   Vouched
///   4. Otherwise.                                                Waiting
/// ```
///
/// `first` is the verifier's earliest first sight of a valid `add` that
/// roots `m` in the agent; `lower` is overview.md's lower estimate, so a
/// wall clock moved while the verifier runs does not shorten the wait.
pub fn agent_waiting(
    active: bool,
    rooted: bool,
    first: &Reading,
    now: &Reading,
    period: u64,
) -> Outcome {
    if !active {
        Outcome::Vetoed
    } else if !rooted || lower(first, now) >= period {
        Outcome::Vouched
    } else {
        Outcome::Waiting
    }
}

/// Whether an `add` rooted the list member in an agent: one of its `add`s
/// the list holds did, or a list checkpoint's record says so, naming that
/// `add` (identity.md, "List checkpoints"), which every holder keeps.
fn rooted_in_agent(m: &Member) -> bool {
    !m.agent_adds.is_empty() || m.root == Rootedness::Agent
}

impl MergedList {
    /// The list members the waiting decision applies to: those an `add`
    /// rooted in an agent, which are not agents themselves, revoked or not.
    pub fn agent_rooted(&self) -> impl Iterator<Item = &Member> {
        self.members()
            .values()
            .filter(|m| m.kind != Kind::RecoveryAgent && rooted_in_agent(m))
    }

    /// `agent_waiting` for the list member `identity`, given the
    /// verifier's earliest first sight of an `add` that roots it in an
    /// agent. `None` for an identity the decision does not apply to: no
    /// list member, an agent, or a list member no `add` rooted in an agent.
    pub fn agent_waiting(
        &self,
        identity: &DeviceId,
        first: &Reading,
        now: &Reading,
        period: u64,
    ) -> Option<Outcome> {
        let member = self.member(identity)?;
        if member.kind == Kind::RecoveryAgent || !rooted_in_agent(member) {
            return None;
        }
        Some(agent_waiting(
            self.active(identity).is_some(),
            member.rooted() == Rootedness::Agent,
            first,
            now,
            period,
        ))
    }
}

/// One verifier's waiting decisions in one space (ext-recovery-agent.md,
/// "The waiting period", "The late verifier, and no witness").
///
/// It keeps the verifier's own first sight of each `add` that roots a list
/// member in an agent, and the list members it has decided `Vouched`. No
/// statement of another party moves a first sight: only a `confirm` ends a
/// wait early. Once `Vouched`, a list member stays so while it is active,
/// even if the period later lengthens: wraps already sent cannot be taken
/// back.
///
/// A device keeps one per space, its own person's devices judged under the
/// personal space's policy, and keeps it at rest with the space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentWaits {
    first: BTreeMap<EventId, Reading>,
    vouched: BTreeSet<DeviceId>,
}

impl AgentWaits {
    /// No first sight and no decision.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds the record a device kept at rest.
    pub fn from_parts(
        first: impl IntoIterator<Item = (EventId, Reading)>,
        vouched: impl IntoIterator<Item = DeviceId>,
    ) -> Self {
        Self {
            first: first.into_iter().collect(),
            vouched: vouched.into_iter().collect(),
        }
    }

    /// Each `add` this verifier has seen, with its first sight.
    pub fn first_sights(&self) -> &BTreeMap<EventId, Reading> {
        &self.first
    }

    /// The list members this verifier has decided `Vouched`.
    pub fn vouched(&self) -> &BTreeSet<DeviceId> {
        &self.vouched
    }

    /// Records the first sight of an `add` at `at`. A later sight of the
    /// same `add` moves nothing. Returns whether it was the first.
    pub fn saw(&mut self, add: EventId, at: Reading) -> bool {
        if self.first.contains_key(&add) {
            return false;
        }
        self.first.insert(add, at);
        true
    }

    /// Records, at `at`, the first sight of every valid `add` of the merged
    /// list that roots a list member in an agent and that this verifier
    /// has not seen. Returns those adds.
    pub fn see(&mut self, merged: &MergedList, at: Reading) -> Vec<EventId> {
        let adds: Vec<EventId> = merged
            .agent_rooted()
            .flat_map(|m| m.agent_adds.iter().copied())
            .collect();
        adds.into_iter().filter(|&add| self.saw(add, at)).collect()
    }

    /// The verifier's earliest first sight of a valid `add` that roots the
    /// list member in an agent: the earliest on its timeline. `None` when
    /// it has seen none. A later add does not move it.
    pub fn first_sight(&self, merged: &MergedList, identity: &DeviceId) -> Option<Reading> {
        merged
            .member(identity)?
            .agent_adds
            .iter()
            .filter_map(|add| self.first.get(add))
            .min_by_key(|reading| reading.timeline)
            .copied()
    }

    /// The waiting decision for a list member in this space, at `now`,
    /// under the space's `agent_waiting_period` `period`. `None` for an
    /// identity the decision does not apply to (see
    /// [`MergedList::agent_waiting`]). A list member whose rooting `add`
    /// this verifier has not recorded counts from `now`. A verifier that
    /// first holds the list from a list checkpoint on counts from its first
    /// sight of the rooting `add` the record names, never earlier than it
    /// receives the list, so no checkpoint shortens a wait.
    pub fn decide(
        &mut self,
        merged: &MergedList,
        identity: &DeviceId,
        now: &Reading,
        period: u64,
    ) -> Option<Outcome> {
        let first = self.first_sight(merged, identity).unwrap_or(*now);
        let mut outcome = merged.agent_waiting(identity, &first, now, period)?;
        match outcome {
            Outcome::Vetoed => {
                self.vouched.remove(identity);
            }
            Outcome::Vouched => {
                self.vouched.insert(*identity);
            }
            Outcome::Waiting if self.vouched.contains(identity) => outcome = Outcome::Vouched,
            Outcome::Waiting => {}
        }
        Some(outcome)
    }

    /// Decides every list member the decision applies to, and returns
    /// those this verifier vouches for, by device ID.
    pub fn decide_all(
        &mut self,
        merged: &MergedList,
        now: &Reading,
        period: u64,
    ) -> BTreeSet<DeviceId> {
        let members: Vec<DeviceId> = merged.agent_rooted().map(|m| m.device).collect();
        members
            .into_iter()
            .filter(|identity| self.decide(merged, identity, now, period) == Some(Outcome::Vouched))
            .collect()
    }

    /// The recipients under a person grant at this verifier (identity.md,
    /// "What a list vouches for"), with the waiting period: each waiting
    /// list member it vouches for is one. By device ID.
    pub fn recipients(&mut self, merged: &MergedList, now: &Reading, period: u64) -> Vec<DeviceId> {
        let vouched = self.decide_all(merged, now, period);
        merged.recipients_with(|m| vouched.contains(&m.device))
    }
}

/// The valid `add`s rooted in an agent that `after` holds and `before` did
/// not: what a device of the person raises at once, offering the veto, and
/// what a member device relays into the system stream of each space that
/// grants the person, before anything else it writes there
/// (ext-recovery-agent.md, "Relay and veto"). In canonical order; `before`
/// is `None` for a list first held.
pub fn new_agent_adds(before: Option<&MergedList>, after: &MergedList) -> Vec<EventId> {
    let held: BTreeSet<EventId> = before
        .map(|b| {
            b.agent_rooted()
                .flat_map(|m| m.agent_adds.iter().copied())
                .collect()
        })
        .unwrap_or_default();
    let rooting: BTreeSet<EventId> = after
        .agent_rooted()
        .flat_map(|m| m.agent_adds.iter().copied())
        .collect();
    after
        .valid()
        .filter(|add| rooting.contains(add) && !held.contains(add))
        .collect()
}

impl DeviceList {
    /// Steps 4 to 6 of "Checking a list event alone" for an `add` of
    /// these keys as `kind` with this proof, which `adder` will sign
    /// (identity.md); then that no list member of the merged list holds
    /// any of the keys.
    fn check_new(
        &self,
        merged: &MergedList,
        kind: Kind,
        keys: &PublicKeys,
        proof: &[u8],
        adder: &DeviceId,
    ) -> Result<ListBody, IdentityClass> {
        if kind.names_xwing() != keys.xwing.is_some() {
            return Err(IdentityClass::Shared(ErrorClass::Malformed));
        }
        let body = ListBody::add(kind, keys, proof.to_vec());
        body.check_add(&self.person_id(), adder)?;
        let device = keys.device_id();
        let clash = merged.members().keys().any(|listed| {
            *listed == device
                || merged.keys(listed).is_some_and(|held| {
                    held.identity == keys.identity
                        || held.mldsa == keys.mldsa
                        || (held.xwing.is_some() && held.xwing == keys.xwing)
                })
        });
        if clash {
            return Err(IdentityClass::AlreadyListed);
        }
        Ok(body)
    }

    /// Step 3 of naming an agent (ext-recovery-agent.md, "Naming an
    /// agent"): checks the agent's keys and its possession proof over
    /// identity.md's statement with kind 3 and `signer` as adder, then
    /// signs the `add` with `signer`, a device or a recovery key of the
    /// merged list that is active and not rooted. Returns the signed `add`, not yet inserted;
    /// the signer publishes it in the personal space as any list event, and
    /// gives the agent the list's events up to and including it
    /// ([`DeviceList::with_past`]).
    ///
    /// Before this step the client tells the person that the agent can
    /// take over their identity after the waiting period unless one of
    /// their devices vetoes, and which of their spaces forbid agents.
    ///
    /// # Errors
    ///
    /// `Malformed` for keys with an X-Wing key, `InvalidKey`,
    /// `BadPossession`, then `AlreadyListed`, then `UntrustedSigner`.
    pub fn name_agent(
        &self,
        agent: &PublicKeys,
        proof: &[u8],
        signer: &MemberKeys,
    ) -> Result<Vec<u8>, IdentityClass> {
        let merged = self.merge();
        let body = self.check_new(
            &merged,
            Kind::RecoveryAgent,
            agent,
            proof,
            signer.device_id(),
        )?;
        let named = merged
            .active(signer.device_id())
            .filter(|m| matches!(m.kind, Kind::Device | Kind::RecoveryKey))
            .filter(|m| m.rooted() == Rootedness::None);
        if named.is_none() {
            return Err(IdentityClass::UntrustedSigner);
        }
        Ok(self.sign(&body, signer.signer()))
    }

    /// Step 1 of adding a device through the agent (ext-recovery-agent.md,
    /// "Adding a device through the agent"): checks the new device's keys
    /// and its possession proof over the person ID with `agent` as adder,
    /// then signs its `add` with `agent`, an active agent of the merged
    /// list, on the agent's own chain and on the heads it holds. Returns the signed `add`, not yet
    /// inserted. How the agent satisfies itself that it helps the person is
    /// its own policy.
    ///
    /// # Errors
    ///
    /// `Malformed` for keys without an X-Wing key, `InvalidKey`,
    /// `BadPossession`, then `AlreadyListed`, then `UntrustedSigner`.
    pub fn agent_add_device(
        &self,
        device: &PublicKeys,
        proof: &[u8],
        agent: &MemberKeys,
    ) -> Result<Vec<u8>, IdentityClass> {
        let merged = self.merge();
        let body = self.check_new(&merged, Kind::Device, device, proof, agent.device_id())?;
        if merged
            .active(agent.device_id())
            .is_none_or(|m| m.kind != Kind::RecoveryAgent)
        {
            return Err(IdentityClass::UntrustedSigner);
        }
        Ok(self.sign(&body, agent.signer()))
    }

    /// The list events an `add` travels with to the person's writers
    /// (ext-recovery-agent.md, "Adding a device through the agent", step
    /// 2; "Relay and veto"): the events of its past, then the `add`, in
    /// canonical order, as signed bytes. Empty for an event the list does
    /// not hold.
    pub fn with_past(&self, add: EventId) -> Vec<Vec<u8>> {
        if !self.log().contains(add) {
            return Vec::new();
        }
        let mut wanted = self.log().past(add);
        wanted.insert(add);
        self.log()
            .canonical()
            .into_iter()
            .filter(|id| wanted.contains(id))
            .filter_map(|id| self.log().event(id).map(|e| e.signed()))
            .collect()
    }

    /// The veto (ext-recovery-agent.md, "Relay and veto"): the revocations
    /// of `device`, an active list member rooted in an agent, and of every
    /// active list member rooted in it, each a `revoke` body, `device`
    /// first, then by device ID; with `with_agent`, last the revocation
    /// of the agent too, which stops further adds. Empty for a list member
    /// that is not active, is an agent, or that no `add` rooted in an
    /// agent.
    ///
    /// A list member of the person that is not rooted in an agent signs
    /// them ([`DeviceList::sign`]), each on its own chain in turn; it
    /// outranks the agent's device, so a duel between them goes to the
    /// person.
    pub fn veto(&self, merged: &MergedList, device: &DeviceId, with_agent: bool) -> Vec<ListBody> {
        veto_in(merged, device, with_agent, &|add| {
            self.log().event(*add).map(|e| *e.author())
        })
    }
}

impl KeptList {
    /// The veto, as [`DeviceList::veto`] gives it, for a list that forgot
    /// under a list checkpoint: it traces through the authors of the
    /// rooting adds its record names, which it keeps, and of the adds after
    /// the checkpoint (ext-recovery-agent.md, "Relay and veto").
    pub fn veto(&self, merged: &MergedList, device: &DeviceId, with_agent: bool) -> Vec<ListBody> {
        veto_in(merged, device, with_agent, &|add| {
            self.any_event(*add).map(|e| *e.author())
        })
    }
}

/// The veto over a merged list, each `add`'s author read through `author`.
fn veto_in(
    merged: &MergedList,
    device: &DeviceId,
    with_agent: bool,
    author: &dyn Fn(&EventId) -> Option<DeviceId>,
) -> Vec<ListBody> {
    let Some(target) = merged.active(device) else {
        return Vec::new();
    };
    if target.kind == Kind::RecoveryAgent || !rooted_in_agent(target) {
        return Vec::new();
    }
    let mut rooted: BTreeSet<DeviceId> = BTreeSet::from([*device]);
    loop {
        let more: Vec<DeviceId> = merged
            .agent_rooted()
            .filter(|m| !rooted.contains(&m.device))
            .filter(|m| {
                m.agent_adds
                    .iter()
                    .any(|add| author(add).is_some_and(|a| rooted.contains(&a)))
            })
            .map(|m| m.device)
            .collect();
        if more.is_empty() {
            break;
        }
        rooted.extend(more);
    }
    let mut out = vec![ListBody::revoke(target.kind, *device)];
    out.extend(
        rooted
            .iter()
            .filter(|identity| *identity != device)
            .filter_map(|identity| merged.active(identity))
            .map(|m| ListBody::revoke(m.kind, m.device)),
    );
    if with_agent && let Some(agent) = target.agent.and_then(|a| merged.active(&a)) {
        out.push(ListBody::revoke(Kind::RecoveryAgent, agent.device));
    }
    out
}
