//! The recovery agent in a space (ext-recovery-agent.md).
//!
//! Each verifier decides, per space and per list member rooted in an agent,
//! whether it wraps for it yet ("The waiting period"). The decision is
//! `frasil-identity`'s ([`AgentWaits`]); this module gives it the space's
//! `agent_waiting_period` and carries what it vouches for into the key
//! graph:
//!
//! - [`waiting_period`]: `W`, key 2 of the space policy in this replica's
//!   current view, merged to the longest (roster.md, "The space policy");
//! - [`HeldList::vouch`]: decides every list member of a held list rooted
//!   in an agent, and keeps those this replica vouches for in the space;
//! - [`HeldList::receives`]: whether the key graph wraps for a list member
//!   of the person ([`crate::keygraph::History::receives`]): one that
//!   waits receives nothing until this replica vouches for it.
//!
//! What waiting governs is only whether this replica wraps for a list
//! member: no verdict depends on it. A list member waiting still writes
//! units through the person's grants, and makes no key event until a
//! `confirm` (`WaitingDevice`).

use crate::across::HeldList;
use crate::policy::Policy;
use frasil_base::time::Reading;
use frasil_identity::ext_recovery_agent::AgentWaits;
use std::collections::BTreeSet;

/// `agent_waiting_period` of a space's policy: the `W` this replica's
/// decisions in the space use.
pub fn waiting_period(policy: &Policy) -> u64 {
    policy.agent_waiting_period
}

impl HeldList {
    /// The waiting list members this replica vouches for in the space.
    pub fn vouched(&self) -> &BTreeSet<[u8; 32]> {
        &self.vouched
    }

    /// Sets the waiting list members this replica vouches for in the space,
    /// as its own decisions gave them.
    pub fn set_vouched(&mut self, vouched: BTreeSet<[u8; 32]>) {
        self.vouched = vouched;
    }

    /// Records this replica's first sight, at `now`, of each `add` rooted
    /// in an agent that it has not seen, then decides every list member
    /// such an `add` roots under `period`, the space's
    /// `agent_waiting_period` ([`waiting_period`]), and keeps those it
    /// vouches for. `waits` is this replica's record for the space, kept
    /// at rest: no other party's statement moves a first sight, and a
    /// decision of `Vouched` sticks while the list member is active.
    /// Returns the list members vouched for.
    pub fn vouch(
        &mut self,
        waits: &mut AgentWaits,
        now: &Reading,
        period: u64,
    ) -> &BTreeSet<[u8; 32]> {
        waits.see(self.merged(), *now);
        self.vouched = waits
            .decide_all(self.merged(), now, period)
            .into_iter()
            .map(|device| device.0)
            .collect();
        &self.vouched
    }
}
