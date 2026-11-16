//! The bodies of the internal links that travel as JSON (module `wire`):
//! Raft's own messages and their answers, the commands a leader commits
//! ([`Command`], answered by [`Applied`]) and joins ([`Join`]), with the
//! membership the commands make ([`Membership`]). serde reads them.
//!
//! The module depends on `openraft`, `serde` and `serde_json` alone, so
//! that its fuzz target builds it alone.

use super::wire::{JOIN, PROPOSE, RAFT_APPEND, RAFT_SNAPSHOT, RAFT_VOTE};
use openraft::BasicNode;
use openraft::error::{InstallSnapshotError, RaftError};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Cursor;

/// A node of the cluster, as module `link` names it.
pub type NodeId = u64;

openraft::declare_raft_types!(
    /// The cluster's Raft types: commands of [`Command`], answered by
    /// [`Applied`], between nodes named by `u64`.
    pub TypeConfig:
        D = Command,
        R = Applied,
        NodeId = u64,
        Node = BasicNode,
);

/// One node, as the membership keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Its node's name in the bucket.
    pub name: String,
    /// Where its internal links listen.
    pub address: String,
    /// Its weight in placement.
    pub capacity: u32,
    /// Its iroh endpoint key in hex, when it serves the iroh binding.
    pub iroh: Option<String>,
    /// Whether shards are placed on it: false once it leaves.
    pub placed: bool,
    /// The last epoch at which it confirmed it gave up every shard it no
    /// longer owns.
    pub confirmed: u64,
    /// The process that joined, drawn at each start: only its renewals
    /// count, so that a second process under the node's name holds no
    /// lease.
    #[serde(default)]
    pub run: u64,
    /// The epoch of its latest join: it writes nothing it opened before.
    #[serde(default)]
    pub joined: u64,
}

impl Member {
    /// Whether two records name the same process with the same settings,
    /// whatever their placement and confirmations.
    pub fn same_process(&self, other: &Self) -> bool {
        self.name == other.name
            && self.address == other.address
            && self.capacity == other.capacity
            && self.iroh == other.iroh
            && self.run == other.run
    }
}

/// What Raft agrees on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    /// The cluster's ID, in hex; empty before the first node set it.
    pub cluster: String,
    /// The epoch: raised at each change of the nodes shards are placed on.
    pub epoch: u64,
    /// The nodes.
    pub nodes: BTreeMap<NodeId, Member>,
}

impl Membership {
    /// The nodes shards are placed on, with their capacities.
    pub fn placed(&self) -> Vec<(NodeId, u32)> {
        self.nodes
            .iter()
            .filter(|(_, member)| member.placed)
            .map(|(&id, member)| (id, member.capacity))
            .collect()
    }

    /// Whether every node confirmed the epoch: no node still keeps a shard
    /// it does not own under it.
    pub fn settled(&self) -> bool {
        self.nodes
            .values()
            .all(|member| member.confirmed >= self.epoch)
    }

    /// Applies a command Raft committed: what it answers.
    pub fn apply(&mut self, command: &Command) -> Applied {
        let ok = match command {
            Command::Init { cluster } => {
                if self.cluster.is_empty() {
                    self.cluster.clone_from(cluster);
                }
                self.cluster == *cluster
            }
            // A join of the same process, placed already, changes nothing:
            // a node that joins again after a lost answer moves no shard.
            Command::Join { node, member } => {
                let same = self
                    .nodes
                    .get(node)
                    .is_some_and(|kept| kept.placed && kept.same_process(member));
                if !same {
                    self.epoch += 1;
                    let mut member = member.clone();
                    member.placed = true;
                    member.confirmed = 0;
                    member.joined = self.epoch;
                    self.nodes.insert(*node, member);
                }
                true
            }
            Command::Renew { node, run } => {
                return match self.nodes.get(node) {
                    Some(member) if member.run == *run => Applied {
                        ok: true,
                        epoch: self.epoch,
                        joined: member.joined,
                    },
                    _ => Applied {
                        ok: false,
                        epoch: self.epoch,
                        joined: 0,
                    },
                };
            }
            Command::Confirm { node, epoch } => match self.nodes.get_mut(node) {
                Some(member) => {
                    member.confirmed = member.confirmed.max((*epoch).min(self.epoch));
                    true
                }
                None => false,
            },
            Command::Leave { node } => match self.nodes.get_mut(node) {
                Some(member) if member.placed => {
                    member.placed = false;
                    self.epoch += 1;
                    true
                }
                Some(_) => true,
                None => false,
            },
            Command::Remove { node } => {
                if self.nodes.remove(node).is_some() {
                    self.epoch += 1;
                }
                true
            }
        };
        Applied {
            ok,
            epoch: self.epoch,
            joined: 0,
        }
    }
}

/// A command Raft commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// The first node names the cluster.
    Init {
        /// The cluster's ID, in hex.
        cluster: String,
    },
    /// A node joins, or joins again with new settings.
    Join {
        /// The node.
        node: NodeId,
        /// What it is.
        member: Member,
    },
    /// A node renews its lease.
    Renew {
        /// The node.
        node: NodeId,
        /// The process renewing.
        run: u64,
    },
    /// A node gave up every shard it does not own at `epoch`.
    Confirm {
        /// The node.
        node: NodeId,
        /// The epoch.
        epoch: u64,
    },
    /// A node leaves: no shard is placed on it any more, and it gives up
    /// what it kept before it confirms.
    Leave {
        /// The node.
        node: NodeId,
    },
    /// The leader removes a node whose lease has ended.
    Remove {
        /// The node.
        node: NodeId,
    },
}

/// What a command's application answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// Whether it took effect: false for a renewal of a node that is no
    /// member.
    pub ok: bool,
    /// The epoch after it.
    pub epoch: u64,
    /// For a renewal, the epoch of the node's latest join.
    #[serde(default)]
    pub joined: u64,
}

/// A request to join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Join {
    /// The node.
    pub node: NodeId,
    /// What it is.
    pub member: Member,
}

/// Reads a JSON body by its tag, as a request's (`request`) or its
/// answer's, and writes it again: what the fuzz target checks. Returns
/// whether the body read.
///
/// # Panics
///
/// If a body that read does not read back as it was written.
pub fn round_trip(request: bool, tag: u8, body: &[u8]) -> bool {
    fn again<T: Serialize + DeserializeOwned>(body: &[u8]) -> bool {
        let Ok(read) = serde_json::from_slice::<T>(body) else {
            return false;
        };
        let once = serde_json::to_vec(&read).unwrap_or_default();
        let back = serde_json::from_slice::<T>(&once).map(|back| serde_json::to_vec(&back).ok());
        assert_eq!(
            back.ok().flatten().as_deref(),
            Some(once.as_slice()),
            "a body reads back as it was written"
        );
        true
    }
    match (request, tag) {
        (true, RAFT_APPEND) => again::<AppendEntriesRequest<TypeConfig>>(body),
        (true, RAFT_VOTE) => again::<VoteRequest<u64>>(body),
        (true, RAFT_SNAPSHOT) => again::<InstallSnapshotRequest<TypeConfig>>(body),
        (true, PROPOSE) => again::<Command>(body),
        (true, JOIN) => again::<Join>(body),
        (false, RAFT_APPEND) => again::<Result<AppendEntriesResponse<u64>, RaftError<u64>>>(body),
        (false, RAFT_VOTE) => again::<Result<VoteResponse<u64>, RaftError<u64>>>(body),
        (false, RAFT_SNAPSHOT) => again::<
            Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>>,
        >(body),
        (false, PROPOSE) => again::<Result<Applied, String>>(body),
        (false, JOIN) => again::<Result<String, String>>(body),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each body reads back, and what is not one of them is refused.
    #[test]
    fn json_bodies_read_back() {
        let command = Command::Renew { node: 1, run: 2 };
        assert!(round_trip(
            true,
            PROPOSE,
            &serde_json::to_vec(&command).unwrap()
        ));
        let applied: Result<Applied, String> = Ok(Applied {
            ok: true,
            epoch: 3,
            joined: 1,
        });
        assert!(round_trip(
            false,
            PROPOSE,
            &serde_json::to_vec(&applied).unwrap()
        ));
        let join = Join {
            node: 4,
            member: Member {
                name: "a".into(),
                address: "node-a".into(),
                capacity: 100,
                iroh: None,
                placed: true,
                confirmed: 0,
                run: 5,
                joined: 0,
            },
        };
        assert!(round_trip(true, JOIN, &serde_json::to_vec(&join).unwrap()));
        let vote = VoteRequest::<u64>::new(openraft::Vote::new(2, 1), None);
        assert!(round_trip(
            true,
            RAFT_VOTE,
            &serde_json::to_vec(&vote).unwrap()
        ));
        assert!(!round_trip(true, PROPOSE, b"{"));
        assert!(!round_trip(true, 99, b"{}"));
    }
}
