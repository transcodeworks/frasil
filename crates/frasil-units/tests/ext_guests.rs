//! ext-guests.json's families of the writer, with feature `ext-guests`
//! (ext-guests.md, "The writer's decision"):
//!
//! - `writer_decisions`: the decision over readings, the two policies'
//!   encodings, and concurrent policies merged;
//! - `heartbeats`: the heartbeat decision.

#![cfg(feature = "ext-guests")]

use frasil_base::time::Reading;
use frasil_space::Policy;
use frasil_space::ext_guests::GuestClass;
use frasil_testkit::hex;
use frasil_units::ext_guests::{WriterState, heartbeat, may_seal};
use serde_json::{Value as Json, json};

const FILE: &str = "ext-guests.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn reading(value: &Json) -> Reading {
    Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    }
}

fn optional(value: &Json) -> Option<Reading> {
    (!value.is_null()).then(|| reading(value))
}

fn shown(result: Result<(), GuestClass>) -> &'static str {
    use frasil_base::errors::Class;
    match result {
        Ok(()) => "MayWrite",
        Err(class) => class.name(),
    }
}

/// A policy of the vectors' `{name: seconds}`.
fn policy(value: &Json) -> Policy {
    let map = value.as_object().unwrap();
    assert!(
        map.keys()
            .all(|k| k == "bounded_window" || k == "online_freshness")
    );
    Policy {
        bounded_window: value["bounded_window"].as_u64(),
        online_freshness: value["online_freshness"].as_u64(),
        ..Policy::default()
    }
}

#[test]
fn writer_decisions() {
    let f = family("writer_decisions");
    let rows = f["decisions"].as_array().unwrap();
    assert_eq!(rows.len(), 15);
    for row in rows {
        let s = &row["state"];
        let mut state = WriterState::new(&policy(&s["policy"]), reading(&s["admitted"]));
        state.left = s["left"].as_bool().unwrap_or(false);
        state.session_expires_at = s["session_expires_at"].as_u64();
        state.followed = optional(&s["followed"]);
        state.last_sync = optional(&s["last_sync"]);
        let got = shown(may_seal(&state, &reading(&row["now"])));
        assert_eq!(got, row["outcome"], "{}", row["description"]);
    }

    // The policies' encodings, which a core implementation also carries.
    let encodings = &f["policy_encodings"];
    let cases = [
        ("bounded window of an hour", Some(3600), None),
        ("online-only at the default", None, Some(300)),
        ("both", Some(86_400), Some(60)),
    ];
    assert_eq!(encodings.as_object().unwrap().len(), cases.len());
    for (name, window, freshness) in cases {
        let p = Policy {
            bounded_window: window,
            online_freshness: freshness,
            ..Policy::default()
        };
        assert_eq!(hex::encode(p.encode()), encodings[name], "{name}");
        assert_eq!(
            Policy::read(&hex::decode(encodings[name].as_str().unwrap()).unwrap()),
            Ok(p)
        );
    }

    // Two concurrent policies merge to the stricter value of each field.
    let a = Policy {
        bounded_window: Some(7200),
        ..Policy::default()
    };
    let b = Policy {
        bounded_window: Some(3600),
        online_freshness: Some(300),
        ..Policy::default()
    };
    let merged = Policy::merge([&a, &b]).unwrap();
    assert_eq!(
        json!({
            "agent_waiting_period": merged.agent_waiting_period,
            "gap_key_timeout": merged.gap_key_timeout,
            "bounded_window": merged.bounded_window,
            "online_freshness": merged.online_freshness,
            "forbid_agents": merged.forbid_agents,
        }),
        f["concurrent_policies_merged"]
    );
}

#[test]
fn heartbeats() {
    let rows = family("heartbeats");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let got = heartbeat(
            &reading(&row["last_signed"]),
            optional(&row["last_heartbeat"]).as_ref(),
            &reading(&row["now"]),
            row["window"].as_u64().unwrap(),
            row["unanswered"].as_bool().unwrap(),
        );
        assert_eq!(got.name(), row["outcome"], "{}", row["description"]);
    }
}
