//! Naming a recovery agent, and the spaces' agent policy, from the
//! high-level API (ext-recovery-agent.md, 3.1 Naming an agent).

use super::{Device, MemberId, Space, SpaceId, UnitId};
use crate::error::{Error, Result};
use frasil_crypto::sizes::MLDSA65_PUBLIC;
use std::time::Duration;

/// What a recovery agent returns to the device that names it
/// (ext-recovery-agent.md, 3.1 Naming an agent, step 2): its Ed25519 key,
/// its ML-DSA-65 key, and its possession proof over the person ID, of
/// list-member kind 3, which names the naming device as adder. An agent
/// has no X-Wing key; the list names it by the device ID of the two.
#[derive(Clone)]
pub struct AgentKeys {
    keys: frasil_identity::PublicKeys,
    proof: Vec<u8>,
}

impl core::fmt::Debug for AgentKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentKeys")
            .field("device_id", &self.keys.device_id())
            .finish_non_exhaustive()
    }
}

impl AgentKeys {
    /// The agent's keys as it returns them: its 32-byte Ed25519 key, its
    /// 1,952-byte ML-DSA-65 key, and its possession proof.
    /// [`Device::name_agent`] checks the proof.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `ml_dsa` is not 1,952 bytes.
    pub fn new(ed25519: [u8; 32], ml_dsa: &[u8], proof: Vec<u8>) -> Result<Self> {
        let mldsa: [u8; MLDSA65_PUBLIC] = ml_dsa
            .try_into()
            .map_err(|_| Error::Invalid("an ML-DSA-65 public key is 1,952 bytes"))?;
        Ok(Self {
            keys: frasil_identity::PublicKeys {
                identity: frasil_crypto::device::IdentityKey(ed25519),
                xwing: None,
                mldsa: Box::new(mldsa),
            },
            proof,
        })
    }

    /// The agent's device ID, which names it on the person's list: the
    /// hash of its Ed25519 key and the commitment to its ML-DSA-65 key.
    pub fn device_id(&self) -> MemberId {
        MemberId::device(self.keys.device_id())
    }
}

/// An agent named on the person's list, from [`Device::name_agent`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NamedAgent {
    /// The list event that adds the agent.
    pub add: UnitId,
    /// The person's list events up to and including that `add`, each
    /// signed: what the application gives the agent, which builds each add
    /// of its own on them (ext-recovery-agent.md, 3.1 Naming an agent,
    /// step 4).
    pub list_events: Vec<Vec<u8>>,
}

/// A space's policy towards recovery agents (roster.md, "The space
/// policy"; ext-recovery-agent.md, 2.2 The waiting period).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentPolicy {
    /// The space admits no person whose list holds a recovery agent: once
    /// an agent is named, it wraps nothing more for the person's devices.
    pub forbids_agents: bool,
    /// How long each member waits, from its own first sight of a device
    /// an agent added, before it wraps anything for that device.
    pub waiting_period: Duration,
}

impl Device {
    /// Names a recovery agent for this device's person
    /// (ext-recovery-agent.md, 3.1 Naming an agent, step 3): checks the
    /// agent's proof, signs its `add`, and publishes the person's list in
    /// every space that grants the person where this device writes. The
    /// agent asks for the person ID, the personal space ID and this
    /// device's ID first ([`Device::person`],
    /// [`Device::personal_space`], [`Device::id`]), since its proof names
    /// the device that adds it; afterwards, give it
    /// [`NamedAgent::list_events`].
    ///
    /// Before calling it, tell the person that the agent can take over
    /// their identity after the waiting period unless one of their devices
    /// vetoes ([`Device::veto`]), and which of their spaces forbid agents
    /// ([`Device::spaces_forbidding_agents`]): those wrap nothing more for
    /// the person's devices once the agent is named. When the agent is
    /// hosted, tell them not to let its operator be the only peer of every
    /// space they share.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; the list's classes,
    /// such as a proof that does not verify, or a device itself added
    /// through an agent; the store's.
    pub async fn name_agent(&self, agent: &AgentKeys) -> Result<NamedAgent> {
        let (add, list_events) = self
            .engine()
            .name_agent(agent.keys.clone(), agent.proof.clone())
            .await?;
        Ok(NamedAgent {
            add: UnitId::from_bytes(add.0),
            list_events,
        })
    }

    /// The spaces this device holds whose policy forbids recovery agents.
    pub async fn spaces_forbidding_agents(&self) -> Vec<SpaceId> {
        self.engine()
            .spaces_forbidding_agents()
            .await
            .into_iter()
            .map(SpaceId::of)
            .collect()
    }
}

impl Space {
    /// The space's policy towards recovery agents, as this device holds
    /// the space now.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn agent_policy(&self) -> Result<AgentPolicy> {
        self.read(|replica| {
            let policy = replica.policy();
            AgentPolicy {
                forbids_agents: policy.forbid_agents,
                waiting_period: Duration::from_secs(
                    frasil_space::ext_recovery_agent::waiting_period(policy),
                ),
            }
        })
        .await
    }
}
