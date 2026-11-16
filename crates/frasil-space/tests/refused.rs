//! roster.json's `refused_events` (roster.md, "The event alone"): a base
//! history, and events refused alone or at their place, with their class.
//!
//! The checks of the event alone, steps 2 to 11, decide most cases. The
//! cases refused at the event's place (authority, and keys.md's checks
//! against the event and its place) pass every check of the event alone;
//! the resolution (a roster event) or the write rule (a key event) decides
//! them.

mod common;

use common::space::{StandIn, prefix_at};
use common::{bytes, events, example, keyring, log_of, screen, text};
use frasil_base::errors::Class;
use frasil_events::decode;
use frasil_space::keygraph::GrantedNotices;
use frasil_space::{Body, KeyEventChecks, Limits, Options, OtherLogs, ScreenedLog, Space, Twins};

/// Cases decided at the event's place, by roster.md's "Authority at the
/// place" or keys.md's checks against the event and its place.
const AT_THE_PLACE: [&str; 8] = [
    "a writer signs a roster event",
    "an administrator grants itself",
    "a grant of a member already in",
    "a removal of a member not in",
    "an administrator raises itself",
    "an event lowering an administrator and another member",
    "a policy change sealed under a state a valid rotation in its past follows",
    "a delivery sealed under a state a valid rotation in its past follows",
];

/// The case whose limit the vector lowers.
const LOWERED: &str = "more device grants than the limit (lowered to 1 for the vector)";

#[test]
fn refused_events() {
    let f = family();
    let base = events(&f["base"]);
    let mut at_the_place = Vec::new();
    for case in f["cases"].as_array().unwrap() {
        let name = text(case, "name");
        let error = text(case, "error");
        let event = decode(&bytes(case, "event")).expect("the event decodes");
        if case["genesis"].as_bool() == Some(true) {
            // A space whose genesis fails is unusable.
            let history = vec![("genesis".to_owned(), event)];
            let log = log_of(&history);
            // The genesis's content key is `<geneses>/genesis/content-key`,
            // as in every history.
            let geneses = prefix_at(&["refused_events", "geneses"]);
            let keys = keyring(&geneses, &history, &[]);
            let outcome = screen(&log, &keys).map(|_| ());
            assert_eq!(outcome.map_err(Class::name), Err(error), "{name}");
            continue;
        }
        let mut history = base.clone();
        history.push(("bad".to_owned(), event.clone()));
        let log = log_of(&history);
        let updates = prefix_at(&["refused_events", "updates"]);
        let content_key = example(&format!("{updates}/content-key"));
        let keys = keyring(&updates, &history, &[content_key]);
        let limits = if name == LOWERED {
            Limits {
                max_device_grants: 1,
                ..Limits::PROTOCOL
            }
        } else {
            Limits::PROTOCOL
        };
        let screened = ScreenedLog::screen(&log, &keys, &limits, &()).expect("usable");
        for (base_name, base_event) in &base {
            assert_eq!(
                screened.verdict(base_event.id()),
                Some(Ok(())),
                "{base_name}"
            );
        }
        let verdict = screened.verdict(event.id()).expect("a space event");
        if AT_THE_PLACE.contains(&name) {
            assert_eq!(
                verdict,
                Ok(()),
                "{name} passes the checks of the event alone"
            );
            let others = OtherLogs::none();
            let notices = GrantedNotices::new(&others);
            let options = Options {
                keys: &keys,
                limits,
                others: &others,
                units: &StandIn,
                twins: Twins::Assumed,
                key_checks: KeyEventChecks::Context,
                notices: Some(&notices),
            };
            let space = Space::resolve(&log, None, options).expect("usable");
            for (base_name, base_event) in &base[1..] {
                assert!(space.is_valid(base_event.id()), "{base_name}");
            }
            let status = space.status(event.id()).expect("held");
            assert_eq!(status.class().map(Class::name), Some(error), "{name}");
            at_the_place.push(name);
            continue;
        }
        assert_eq!(verdict.map_err(Class::name), Err(error), "{name}");
        // BadSeal holds the event; every other class here voids it.
        let held = matches!(screened.body(event.id()), Some(Body::Held(_)));
        assert_eq!(held, error == "BadSeal", "{name}");
    }
    assert_eq!(at_the_place, AT_THE_PLACE, "every case at the place is met");
}

fn family() -> serde_json::Value {
    common::family("refused_events")
}
