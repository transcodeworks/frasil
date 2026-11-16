//! Which node owns a shard: rendezvous hashing of the shard's name over
//! the epoch's placed nodes, weighted by capacity. Every node computes the
//! same owner from the same membership, with no lookup and nothing per
//! shard in Raft, and a node that joins or leaves moves about its share of
//! the shards.
//!
//! Each node scores `capacity / −ln(u)`, where `u` in (0, 1) is drawn from
//! SHA-256 over a label, the shard's name and the node; the highest score
//! owns the shard. A node of twice the capacity owns twice the shards.

use super::link::NodeId;
use frasil_crypto::primitives::sha256;

/// The owner of `shard` among `nodes`, each with its capacity; none when
/// there is no node of positive capacity.
pub fn owner(shard: &str, nodes: &[(NodeId, u32)]) -> Option<NodeId> {
    let mut best: Option<(f64, NodeId)> = None;
    for &(node, capacity) in nodes {
        if capacity == 0 {
            continue;
        }
        let digest = sha256(&[
            b"frasil-relay/placement/v1\0",
            shard.as_bytes(),
            &[0],
            &node.to_be_bytes(),
        ]);
        let x = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
        // (x + 0.5) / 2^64 is strictly within (0, 1).
        let u = (x as f64 + 0.5) / 18_446_744_073_709_551_616.0;
        let score = f64::from(capacity) / -u.ln();
        if best.is_none_or(|(top, at)| score > top || (score == top && node < at)) {
            best = Some((score, node));
        }
    }
    best.map(|(_, node)| node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn counts(nodes: &[(NodeId, u32)], shards: usize) -> BTreeMap<NodeId, usize> {
        let mut counts = BTreeMap::new();
        for n in 0..shards {
            let owner = owner(&format!("spaces/{n:04x}"), nodes).unwrap();
            *counts.entry(owner).or_default() += 1;
        }
        counts
    }

    #[test]
    fn shards_spread_by_capacity() {
        let even = counts(&[(1, 100), (2, 100), (3, 100)], 6000);
        for count in even.values() {
            assert!((1700..2300).contains(count), "{even:?}");
        }
        let weighted = counts(&[(1, 200), (2, 100)], 6000);
        assert!((3600..4400).contains(&weighted[&1]), "{weighted:?}");
        assert_eq!(owner("x", &[(1, 0)]), None);
    }

    #[test]
    fn a_node_that_joins_moves_only_its_share() {
        let before = [(1, 100), (2, 100), (3, 100)];
        let after = [(1, 100), (2, 100), (3, 100), (4, 100)];
        let mut moved = 0;
        for n in 0..4000 {
            let shard = format!("libraries/{n:04x}");
            let (a, b) = (owner(&shard, &before), owner(&shard, &after));
            if a != b {
                assert_eq!(b, Some(4), "a shard moves only to the new node");
                moved += 1;
            }
        }
        assert!((800..1200).contains(&moved), "{moved}");
    }
}
