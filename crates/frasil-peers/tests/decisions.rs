//! `peers.json`: `decisions` (peers.md, sections 3.16 to 3.19: erasure,
//! credentials requests, release and restore, and collection).

mod common;

use common::*;
use frasil_base::time::Reading;
use frasil_peers::decisions::{
    Collection, Execution, Reclamation, collect, credentials_request, erasure, release,
};
use serde_json::Value as Json;

/// The reference's readings: the first sight at 1,000 on the peer's
/// timeline, and now `elapsed` later.
const SEEN: u64 = 1000;

fn u(value: &Json) -> u64 {
    value.as_u64().unwrap()
}

fn b(value: &Json) -> bool {
    value.as_bool().unwrap()
}

fn rows(name: &str) -> Vec<Json> {
    family("decisions")[name].as_array().unwrap().clone()
}

fn execution(outcome: Execution) -> &'static str {
    match outcome {
        Execution::Void => "Void",
        Execution::Execute => "Execute",
        Execution::Wait => "Wait",
    }
}

#[test]
fn erasures_and_credentials_requests() {
    for (family, rule) in [
        (
            "erasure",
            erasure as fn(bool, bool, bool, &Reading, &Reading, u64) -> Execution,
        ),
        ("credentials_request", credentials_request),
    ] {
        for row in rows(family) {
            let outcome = |undecided| {
                rule(
                    b(&row["valid"]),
                    undecided,
                    b(&row["stable"]),
                    &reading(SEEN),
                    &reading(SEEN + u(&row["elapsed"])),
                    u(&row["timeout"]),
                )
            };
            assert_eq!(
                execution(outcome(false)),
                text(&row["outcome"]),
                "{family}: {row}"
            );
            // Step 1: while a cut concurrent with it can still take effect,
            // a valid request waits, stable or past T; a void one stays
            // void.
            let waiting = if b(&row["valid"]) { "Wait" } else { "Void" };
            assert_eq!(execution(outcome(true)), waiting, "{family}: {row}");
        }
    }
}

#[test]
fn releases() {
    for row in rows("release") {
        let outcome = |undecided| match release(
            b(&row["released"]),
            undecided,
            b(&row["stable"]),
            &reading(SEEN),
            &reading(SEEN + u(&row["elapsed"])),
            u(&row["retention"]),
            u(&row["timeout"]),
        ) {
            Reclamation::Keep => "Keep",
            Reclamation::Reclaim => "Reclaim",
        };
        assert_eq!(outcome(false), text(&row["outcome"]), "{row}");
        // Step 2: a release concurrent with a cut that can still take
        // effect is never reclaimed.
        assert_eq!(outcome(true), "Keep", "{row}");
    }
}

#[test]
fn collections() {
    for row in rows("collection") {
        let outcome = collect(
            b(&row["cancelled"]),
            b(&row["stable"]),
            &reading(SEEN),
            &reading(SEEN + u(&row["elapsed"])),
            u(&row["timeout"]),
        );
        let outcome = match outcome {
            Collection::Keep => "Keep",
            Collection::Collect => "Collect",
        };
        assert_eq!(outcome, text(&row["outcome"]), "{row}");
    }
}
