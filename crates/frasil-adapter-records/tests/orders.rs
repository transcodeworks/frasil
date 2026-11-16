//! Order independence (units.md, section 3.17, "The adapter interface",
//! `apply`): the vectors' changesets handed over in any order, any number of
//! times each, give one state, and a snapshot of any prefix, with the units it
//! excludes, rebuilds to it.

use frasil_adapter::{Adapter, Context, Role, StreamUnit};
use frasil_adapter_records::{Changeset, Records};
use frasil_testkit::{hex, vectors};
use proptest::prelude::*;
use serde::Deserialize;

const FILE: &str = "adapter-records.json";

#[derive(Deserialize)]
struct Row {
    name: String,
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
struct MergeOrders {
    accepted: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
}

fn units() -> (Vec<StreamUnit>, Vec<u8>) {
    let rows: Vec<Row> = vectors::family(FILE, "changesets");
    let merge: MergeOrders = vectors::family(FILE, "merge_orders");
    let units = rows
        .into_iter()
        .map(|row| StreamUnit {
            context: Context::new([0; 32], [1; 16], row.id, row.author, 1, 1, Role::Log),
            content: row.content,
            valid: merge.accepted.contains(&row.name),
        })
        .collect();
    (units, merge.snapshot)
}

/// The first `cut` units, with every suggestion they accept or dismiss
/// moved in from later, and the rest.
fn causal_cut(units: &[StreamUnit], cut: usize) -> (Vec<StreamUnit>, Vec<StreamUnit>) {
    let (head, tail) = units.split_at(cut);
    let named: Vec<[u8; 32]> = head
        .iter()
        .filter_map(|unit| Changeset::read(&unit.content).ok())
        .flat_map(|changeset| changeset.keys.targets().copied().collect::<Vec<_>>())
        .collect();
    let (moved, rest): (Vec<StreamUnit>, Vec<StreamUnit>) = tail
        .iter()
        .cloned()
        .partition(|unit| named.contains(&unit.context.event_id));
    ([head.to_vec(), moved].concat(), rest)
}

proptest! {
    #[test]
    fn any_order_any_repetition_gives_one_state(
        order in Just((0..8).collect::<Vec<usize>>()).prop_shuffle(),
        repeats in proptest::collection::vec(0..8usize, 0..8),
        cut in 0..=8usize,
    ) {
        let (units, expected) = units();
        let records = Records::new();
        let mut sequence: Vec<StreamUnit> = order.iter().map(|i| units[*i].clone()).collect();
        sequence.extend(repeats.iter().map(|i| units[*i].clone()));
        let state = records.rebuild(None, &sequence).unwrap();
        prop_assert_eq!(records.compact(&state).state, expected.clone());

        // A snapshot of the first `cut` units in this order as its cover, then
        // the units it excludes and the units after the cover, as a replica
        // that uses it applies them (units.md, section 3.6, "Checking, using
        // and settling a snapshot", "Using"). Units of the cover the state
        // includes are never handed over again. The cover is a causal past, so
        // it holds the suggestions its accepts name (adapter-records.md,
        // section 3.4, "Suggestions").
        let in_order: Vec<StreamUnit> = order.iter().map(|i| units[*i].clone()).collect();
        let (head, tail) = causal_cut(&in_order, cut);
        let (head, tail) = (&head[..], &tail[..]);
        let compaction = records.compact(&records.rebuild(None, head).unwrap());
        let mut after: Vec<StreamUnit> = head
            .iter()
            .filter(|unit| !compaction.included.contains(&unit.context.event_id))
            .cloned()
            .collect();
        after.extend_from_slice(tail);
        let rebuilt = records.rebuild(Some(&compaction.state), &after).unwrap();
        prop_assert_eq!(records.compact(&rebuilt).state, expected);
    }
}
