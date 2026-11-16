//! `crypto.json`'s `coverage` (crypto.md, "Anchors and coverage" and "The
//! classical sunset").

use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_crypto::schemes::Scheme;
use frasil_events::{CoverageEvent, coverage};
use frasil_testkit::vectors;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Graph {
    name: String,
    events: Vec<GraphEvent>,
    held_before_sunset: Vec<String>,
    before_sunset: BTreeMap<String, String>,
    after_sunset: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphEvent {
    id: String,
    scheme: u8,
    refs: Vec<String>,
}

fn verdicts(found: BTreeMap<String, Result<(), ErrorClass>>) -> BTreeMap<String, String> {
    found
        .into_iter()
        .map(|(id, verdict)| {
            let verdict =
                verdict.map_or_else(|class| class.name().to_owned(), |()| "accepted".to_owned());
            (id, verdict)
        })
        .collect()
}

#[test]
fn coverage_graphs() {
    let graphs: Vec<Graph> = vectors::family("crypto.json", "coverage");
    assert_eq!(graphs.len(), 4);
    for graph in &graphs {
        // `refs` here are the IDs an envelope names by hash: its prev and
        // parents.
        let events: Vec<CoverageEvent<String>> = graph
            .events
            .iter()
            .map(|event| CoverageEvent {
                id: event.id.clone(),
                scheme: match event.scheme {
                    0 => Scheme::Ed25519,
                    2 => Scheme::Hybrid,
                    other => panic!("scheme {other}"),
                },
                names: event.refs.clone(),
            })
            .collect();
        let held: BTreeSet<String> = graph.held_before_sunset.iter().cloned().collect();
        assert_eq!(
            verdicts(coverage(&events, false, &held)),
            graph.before_sunset,
            "{}",
            graph.name
        );
        assert_eq!(
            verdicts(coverage(&events, true, &held)),
            graph.after_sunset,
            "{}",
            graph.name
        );
    }
}
