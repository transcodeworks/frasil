//! The twin step through `frasil-peers`' replica checks (roster.md, "The
//! twin"; "Authority at the place", step 6), over the one history of
//! peers.json's `twin_checks` that gives every event: a roster event that
//! grants `administer` with its twin, a foreign enrolment and a planted
//! administrator slot. The roster vectors carry no twins; peers.json tests
//! the twin checks themselves.

mod common;

use common::space::StandIn;
use common::{events, keyring, log_of};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::{KeyEventChecks, Level, Limits, MemberRef, Options, OtherLogs, Space, Twins};
use std::collections::BTreeSet;

const PREFIX: &str = "storage/replica-foreign";

fn options<'a>(
    keys: &'a frasil_space::Keyring,
    others: &'a OtherLogs<'a>,
    twins: Twins,
) -> Options<'a> {
    Options {
        keys,
        limits: Limits::PROTOCOL,
        others,
        units: &StandIn,
        twins,
        key_checks: KeyEventChecks::Context,
        notices: None,
    }
}

#[test]
fn a_roster_event_and_its_twin() {
    let case: serde_json::Value = frasil_testkit::vectors::family("peers.json", "twin_checks");
    let history = events(&case["foreign_enrolment_and_planted_administrator_slot"]["events"]);
    let log = log_of(&history);
    let keys = keyring(PREFIX, &history, &[]);
    let id = |name: &str| {
        history
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.id())
            .unwrap()
    };
    let author = |name: &str| {
        history
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.author().0)
            .unwrap()
    };
    let others = OtherLogs::none();
    let grant = id("P grants A administer");
    for twins in [Twins::Skeleton, Twins::Assumed] {
        let space = Space::resolve(&log, None, options(&keys, &others, twins)).unwrap();
        assert!(space.is_valid(grant), "{twins:?}");
        let a = space.opened(grant).unwrap().changes()[0].member.unwrap();
        assert_eq!(space.roster().level(&a), Some(Level::Administer));
        assert!(
            space
                .roster()
                .is_administrator(&author("P creates the space"))
        );
    }
    // Checking twins, a skeleton event counts for the device its
    // pseudonym's binding names, and a foreign enrolment's for none.
    let space = Space::resolve(&log, None, options(&keys, &others, Twins::Skeleton)).unwrap();
    let p = author("P creates the space");
    assert_eq!(space.device_of(id("P0: root")), Some(p));
    assert_eq!(
        space.device_of(id(
            "X: P enrols its own pseudonym into A's administrator slot"
        )),
        None
    );
    assert_eq!(
        space
            .roster()
            .state(&MemberRef::device(frasil_space::DeviceId(p)))
            .map(|s| s.level),
        Some(Level::Administer)
    );
    // A genesis waits for its root.
    let genesis: BTreeSet<EventId> = BTreeSet::from([log.id()]);
    let outcome = Space::resolve(
        &log,
        Some(&genesis),
        options(&keys, &others, Twins::Skeleton),
    );
    assert_eq!(outcome.map(|_| ()).map_err(Class::name), Err("NoTwin"));
    let assumed = Space::resolve(
        &log,
        Some(&genesis),
        options(&keys, &others, Twins::Assumed),
    );
    assert!(assumed.is_ok());
}
