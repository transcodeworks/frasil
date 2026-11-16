//! Order independence (units.md, section 3.17, "The adapter interface",
//! `apply`): the vectors' units handed over in any order, any number of times
//! each, give one state, and a snapshot of any prefix, with the units it
//! excludes, rebuilds to it.

use frasil_adapter::{Adapter, Context, Locator, Role, StreamUnit};
use frasil_adapter_blobs::Blobs;
use frasil_testkit::{hex, vectors};
use proptest::prelude::*;
use serde::Deserialize;

const FILE: &str = "adapter-blobs.json";

#[derive(Deserialize)]
struct Row {
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    objects: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
struct MergeOrders {
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
}

fn units() -> (Vec<StreamUnit>, Vec<u8>) {
    let rows: Vec<Row> = vectors::family(FILE, "units");
    let merge: MergeOrders = vectors::family(FILE, "merge_orders");
    let units = rows
        .into_iter()
        .map(|row| {
            let objects: Vec<Locator> = row
                .objects
                .iter()
                .map(|text| hex::decode_array(text).unwrap())
                .collect();
            StreamUnit {
                context: Context::new([0; 32], [1; 16], row.id, row.author, 1, 1, Role::Log)
                    .with_objects(objects),
                content: row.content,
                valid: true,
            }
        })
        .collect();
    (units, merge.snapshot)
}

proptest! {
    #[test]
    fn any_order_any_repetition_gives_one_state(
        order in Just((0..3).collect::<Vec<usize>>()).prop_shuffle(),
        repeats in proptest::collection::vec(0..3usize, 0..4),
        cut in 0..=3usize,
    ) {
        let (units, expected) = units();
        let blobs = Blobs::new();
        let mut sequence: Vec<StreamUnit> = order.iter().map(|i| units[*i].clone()).collect();
        sequence.extend(repeats.iter().map(|i| units[*i].clone()));
        let state = blobs.rebuild(None, &sequence).unwrap();
        prop_assert_eq!(blobs.compact(&state).state, expected.clone());

        // A snapshot of the first `cut` units in this order as its cover, then
        // the units it excludes and the units after the cover, as a replica
        // that uses it applies them (units.md, section 3.6, "Checking, using
        // and settling a snapshot", "Using"). Units of the cover the state
        // includes are never handed over again.
        let in_order: Vec<StreamUnit> = order.iter().map(|i| units[*i].clone()).collect();
        let (head, tail) = in_order.split_at(cut);
        let compaction = blobs.compact(&blobs.rebuild(None, head).unwrap());
        let mut after: Vec<StreamUnit> = head
            .iter()
            .filter(|unit| !compaction.included.contains(&unit.context.event_id))
            .cloned()
            .collect();
        after.extend_from_slice(tail);
        let rebuilt = blobs.rebuild(Some(&compaction.state), &after).unwrap();
        prop_assert_eq!(blobs.compact(&rebuilt).state, expected);
    }
}
