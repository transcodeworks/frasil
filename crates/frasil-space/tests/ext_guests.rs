//! ext-guests.json's `session_expiry` family, with feature `ext-guests`
//! (ext-guests.md, "Ending a session"): `session_expiry` at and around each
//! bound, and a guest due when any of its grants is.

#![cfg(feature = "ext-guests")]

use frasil_base::time::Reading;
use frasil_space::ext_guests::{SESSION_LIFETIME_MAX, guest_due, session_expiry};
use serde_json::Value as Json;

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

#[test]
fn session_expiry_family() {
    let f = family("session_expiry");
    assert_eq!(
        f["session_lifetime_max"].as_u64(),
        Some(SESSION_LIFETIME_MAX)
    );
    let rows = f["decisions"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for row in rows {
        let got = session_expiry(
            row["expires_at"].as_u64(),
            &reading(&row["first_sight"]),
            &reading(&row["now"]),
        );
        assert_eq!(got.name(), row["outcome"], "{}", row["description"]);
    }
    let due = &f["due"];
    let now = reading(&due["now"]);
    let grants: Vec<(Option<u64>, Reading)> = due["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["expires_at"].as_u64(), reading(&g["first_sight"])))
        .collect();
    let outcomes: Vec<&str> = grants
        .iter()
        .map(|(e, seen)| session_expiry(*e, seen, &now).name())
        .collect();
    assert_eq!(serde_json::json!(outcomes), due["outcomes"]);
    assert_eq!(Some(guest_due(&grants, &now)), due["due"].as_bool());
}
