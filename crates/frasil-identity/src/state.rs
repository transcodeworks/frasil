//! List members, rootedness and ranks (identity.md, "The state of a list at
//! a place").
//!
//! The **place** of a list event is the valid list events in its past, with
//! the first event. At a place `V`:
//!
//! - each device ID that an `add` of `V` names is a list member, with the
//!   kind of the first such `add` in canonical order, and the keys its
//!   device ID commits to. It is
//!   **revoked** when a `revoke` of `V` names it, **active** when it is not,
//!   and **confirmed** when a `confirm` of `V` names it;
//! - an `add` other than the first event roots the list member it adds from
//!   its author's state at the `add`'s own place: in an agent, when the
//!   author is an agent or is rooted in one; otherwise in a passkey, when the
//!   added list member is a passkey member or the author is rooted in a
//!   passkey; otherwise not;
//! - a list member takes the most rooted of its adds, an agent over a
//!   passkey over none, so rootedness fails closed. An agent is rooted in an
//!   agent; a passkey member in an agent if an add rooted it there, and
//!   otherwise in a passkey; any other list member is not rooted once it is
//!   confirmed, and otherwise as its adds made it.
//!
//! [`crate::merge`] computes the state at each place; this module holds what
//! it computes.

use crate::keys::{Kind, Rank};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;

/// How rooted a list member is, least rooted first: an agent over a passkey
/// over none, so that the larger value wins when two adds disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rootedness {
    /// Not rooted.
    None,
    /// Rooted in a passkey.
    Passkey,
    /// Rooted in an agent.
    Agent,
}

impl Rootedness {
    /// The name the vectors use: `none`, `passkey` or `agent`.
    pub const fn name(self) -> &'static str {
        match self {
            Rootedness::None => "none",
            Rootedness::Passkey => "passkey",
            Rootedness::Agent => "agent",
        }
    }
}

/// A list member at a place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Its kind, from the first `add` that names it in canonical order.
    pub kind: Kind,
    /// Its device ID, which names it.
    pub device: DeviceId,
    /// The `add`s of the place that name it, in canonical order. The first
    /// gives its kind and keys.
    pub adds: Vec<EventId>,
    /// The most rooted of its adds, before its kind and any `confirm` are
    /// taken into account: see [`Member::rooted`].
    pub root: Rootedness,
    /// The agent it is rooted in, from the first `add` in canonical order
    /// that rooted it there: the author itself for an add by an agent, or
    /// the author's own agent for an add by a list member rooted in one.
    pub agent: Option<DeviceId>,
    /// The `revoke`s of the place that name it, in canonical order.
    pub revoked_by: Vec<EventId>,
    /// The `confirm`s of the place that name it, in canonical order.
    pub confirmed_by: Vec<EventId>,
    /// The `add`s of the place that rooted it in an agent, in canonical
    /// order: those whose first sight starts ext-recovery-agent.md's
    /// waiting period. In a list checkpoint's world, the first is the
    /// `rooting` add its record names (identity.md, "List checkpoints").
    pub agent_adds: Vec<EventId>,
}

impl Member {
    /// A list member that `add` names first.
    pub fn new(kind: Kind, device: DeviceId, add: EventId) -> Self {
        Self {
            kind,
            device,
            adds: vec![add],
            root: Rootedness::None,
            agent: None,
            revoked_by: Vec::new(),
            confirmed_by: Vec::new(),
            agent_adds: Vec::new(),
        }
    }

    /// Active: no `revoke` of the place names it.
    pub fn active(&self) -> bool {
        self.revoked_by.is_empty()
    }

    /// Confirmed: a `confirm` of the place names it.
    pub fn confirmed(&self) -> bool {
        !self.confirmed_by.is_empty()
    }

    /// Its rootedness: an agent is rooted in an agent; a passkey member in
    /// an agent if an add rooted it there, and otherwise in a passkey; any
    /// other list member is not rooted once it is confirmed, and otherwise
    /// as its adds made it.
    pub fn rooted(&self) -> Rootedness {
        match self.kind {
            Kind::RecoveryAgent => Rootedness::Agent,
            Kind::PasskeyMember => self.root.max(Rootedness::Passkey),
            _ if self.confirmed() => Rootedness::None,
            _ => self.root,
        }
    }

    /// Its rank, 1 the highest: a recovery key that is not rooted; a device
    /// that is not rooted; a passkey member, and any list member rooted in a
    /// passkey; an agent, and any list member rooted in an agent.
    pub fn rank(&self) -> Rank {
        match (self.rooted(), self.kind) {
            (Rootedness::Agent, _) => Rank::Agent,
            (Rootedness::None, Kind::RecoveryKey) => Rank::RecoveryKey,
            (Rootedness::None, Kind::Device) => Rank::Device,
            _ => Rank::Passkey,
        }
    }

    /// Waiting: rooted in an agent, and not an agent (identity.md, "What a
    /// list vouches for"). In core protocol 1 it waits until a `confirm`
    /// clears it.
    pub fn waiting(&self) -> bool {
        self.kind != Kind::RecoveryAgent && self.rooted() == Rootedness::Agent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(kind: Kind, root: Rootedness, confirmed: bool) -> Member {
        let mut m = Member::new(kind, DeviceId([1; 32]), EventId([2; 32]));
        m.root = root;
        if confirmed {
            m.confirmed_by.push(EventId([3; 32]));
        }
        m
    }

    #[test]
    fn ranks_follow_the_table() {
        use Rootedness::{Agent, None, Passkey};
        let cases = [
            (Kind::RecoveryKey, None, false, Rank::RecoveryKey),
            (Kind::RecoveryKey, Passkey, false, Rank::Passkey),
            (Kind::RecoveryKey, Passkey, true, Rank::RecoveryKey),
            (Kind::Device, None, false, Rank::Device),
            (Kind::Device, Passkey, false, Rank::Passkey),
            (Kind::Device, Agent, false, Rank::Agent),
            (Kind::Device, Agent, true, Rank::Device),
            (Kind::PasskeyMember, None, true, Rank::Passkey),
            (Kind::PasskeyMember, Agent, true, Rank::Agent),
            (Kind::RecoveryAgent, None, true, Rank::Agent),
        ];
        for (kind, root, confirmed, rank) in cases {
            assert_eq!(
                member(kind, root, confirmed).rank(),
                rank,
                "{kind:?} {root:?}"
            );
        }
        assert!(member(Kind::Device, Agent, false).waiting());
        assert!(!member(Kind::Device, Agent, true).waiting());
        assert!(!member(Kind::RecoveryAgent, Agent, false).waiting());
    }
}
