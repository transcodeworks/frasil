//! A partial replica's verdicts (units.md, "Partial replicas"): the write
//! rule in proven order over roster.json's `writes` histories, held in full
//! and in part, with witnessed parents, stubs and `Path`s; and the roster
//! resolved only on heights the replica knows ("Heights"), over every
//! roster.json history it can hold the frame of.

mod common;

use common::space::{Fixture, StandIn, prefix, whole_list};
use common::{example, family, text};
use frasil_crypto::schemes::Scheme;
use frasil_events::envelope::Envelope;
use frasil_events::{Event, EventId, Log, Stub, decode, kind};
use frasil_space::Status;
use frasil_space::keygraph::GrantedNotices;
use frasil_space::{KeyEventChecks, Options, OtherLogs, Replica, Space, Twins};
use serde_json::Value as Json;
use std::collections::BTreeSet;

/// Resolves a log as a full or a partial replica, with the history's
/// lists.
fn resolve<'a>(
    fixture: &'a Fixture,
    log: &'a Log,
    others: &'a OtherLogs<'a>,
    notices: &'a GrantedNotices<'a>,
    replica: Replica,
) -> Space<'a> {
    let options = Options {
        keys: &fixture.keys,
        limits: fixture.limits,
        others,
        units: &StandIn,
        twins: Twins::Assumed,
        key_checks: KeyEventChecks::Context,
        notices: Some(notices),
    };
    Space::resolve_as(log, None, options, replica).expect("the space resolves")
}

fn others_of(history: &Json) -> OtherLogs<'static> {
    let mut others = OtherLogs::none();
    for (_, events) in history
        .get("lists")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
    {
        others = others.with_list(whole_list(events));
    }
    others
}

fn history(name: &str) -> Json {
    family("writes")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap_or_else(|| panic!("no history {name:?}"))
        .clone()
}

const CONCURRENT: &str = "a unit concurrent with its writer's removal";

/// Every `writes` history, held in full by a partial replica: a verdict
/// that reads only proven order matches the full replica's, and a unit
/// concurrent with its writer's removal or demotion, which the full
/// replica refuses, is pending, never applied.
#[test]
fn a_partial_replica_that_holds_every_event() {
    for history in family("writes").as_array().unwrap() {
        let name = text(history, "name");
        let fixture = Fixture::new(&prefix(name), &history["events"]);
        let others = others_of(history);
        let notices = GrantedNotices::new(&others);
        let full = resolve(&fixture, &fixture.log, &others, &notices, Replica::Full);
        let partial = resolve(&fixture, &fixture.log, &others, &notices, Replica::Partial);
        assert_eq!(partial.replica(), Replica::Partial);
        for (event, want) in history["views"]["all"]["events"].as_object().unwrap() {
            let id = fixture.id(event);
            let shown = fixture.show(full.status(id).unwrap());
            assert_eq!(shown, want.as_str().unwrap(), "{name}: {event}, full");
            let want = match want.as_str().unwrap().strip_prefix("RefusedByRemoval") {
                Some(by) => format!("Pending{by}"),
                None => want.as_str().unwrap().to_owned(),
            };
            let shown = fixture.show(partial.status(id).unwrap());
            assert_eq!(shown, want, "{name}: {event}, partial");
            // A partial replica never applies a unit a full replica refuses.
            assert!(
                !partial.is_valid(id) || full.is_valid(id),
                "{name}: {event}"
            );
        }
    }
}

/// The events of `CONCURRENT`, by their names.
struct Concurrent {
    fixture: Fixture,
    history: Json,
}

impl Concurrent {
    fn new() -> Self {
        let history = history(CONCURRENT);
        let fixture = Fixture::new(&prefix(CONCURRENT), &history["events"]);
        Self { fixture, history }
    }

    fn event(&self, name: &str) -> Event {
        let id = self.fixture.id(name);
        self.fixture.log.event(id).unwrap().clone()
    }

    fn stub(&self, name: &str) -> Stub {
        let event = self.event(name);
        Stub {
            id: event.id(),
            author: *event.author(),
            seq: event.seq(),
            height: self.fixture.log.height(event.id()).unwrap(),
            kind: event.kind(),
            cuts: frasil_events::Cuts::of(&event),
        }
    }

    /// A log of the genesis and the named events, in canonical order, each
    /// placed or left pending.
    fn log_of(&self, names: &[&str]) -> Log {
        let mut log = Log::new(self.event("P creates the space")).unwrap();
        for name in names {
            log.place(self.event(name)).unwrap();
        }
        log
    }

    /// X's next unit, citing its removal.
    fn after_removal(&self) -> Event {
        let w2 = self.event(W2);
        let removal = self.event(REMOVAL);
        let seed = example(&format!("{}/X/ed25519", prefix(CONCURRENT)));
        let x = frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&seed).signer();
        assert_eq!(x.device_id(), w2.author());
        let u3 = self.event(U3);
        let mut parents = vec![removal.id(), u3.id()];
        parents.sort();
        let envelope = Envelope {
            kind: kind::UNIT,
            log: Some(self.fixture.log.id()),
            ed: *w2.ed(),
            kc: *w2.kc(),
            seq: u3.seq() + 1,
            prev: Some(u3.id()),
            parents,
            cuts: Vec::new(),
            body: b"X writes after its removal".to_vec(),
            scheme: Scheme::Ed25519,
        };
        decode(&envelope.sign(&x)).unwrap()
    }

    /// A `partial_replica` case: the partial replica's verdict on its unit,
    /// and the full replica's, which holds every event.
    fn case(&self, case: &str) -> (String, String) {
        let removal = self.fixture.id(REMOVAL);
        let u1 = self.fixture.id(U1);
        let (log, u) = match case {
            "u before r, a Path from r down to u fetched" => {
                let mut log = self.log_of(&[GRANT, U1, REMOVAL]);
                log.add_stub(self.stub(W2));
                let path = vec![self.event(W2)];
                assert!(log.add_path(removal, u1, path).unwrap().is_some());
                (log, self.event(U1))
            }
            "u before r, no Path yet" => {
                let mut log = self.log_of(&[GRANT, U1, REMOVAL]);
                log.add_stub(self.stub(W2));
                (log, self.event(U1))
            }
            "u after r, r among u's parents" => {
                let after = self.after_removal();
                let mut log = self.log_of(&[GRANT, U1, REMOVAL, U3]);
                log.witness(self.event(W2)).unwrap();
                log.place(after.clone()).unwrap();
                (log, after)
            }
            "u concurrent with r" => {
                let mut log = self.log_of(&[GRANT, U1, REMOVAL, U3]);
                log.witness(self.event(W2)).unwrap();
                (log, self.event(U3))
            }
            other => panic!("no case {other:?}"),
        };
        let mut whole = self.fixture.log.clone();
        whole.place(u.clone()).unwrap();
        let others = others_of(&self.history);
        let notices = GrantedNotices::new(&others);
        let partial = resolve(&self.fixture, &log, &others, &notices, Replica::Partial);
        let full = resolve(&self.fixture, &whole, &others, &notices, Replica::Full);
        let show = |space: &Space<'_>| self.fixture.show(space.status(u.id()).expect("held"));
        (show(&partial), show(&full))
    }

    fn verdict(&self, log: &Log, name: &str) -> String {
        let others = others_of(&self.history);
        let notices = GrantedNotices::new(&others);
        let space = resolve(&self.fixture, log, &others, &notices, Replica::Partial);
        let id = self.fixture.id(name);
        self.fixture.show(space.status(id).expect("in the view"))
    }
}

const GRANT: &str = "P grants X write";
const U1: &str = "X writes 1";
const W2: &str = "X writes 2";
const REMOVAL: &str = "P removes X";
const U3: &str = "X writes 3, not having seen its removal";

/// units.json's `partial_replica` cases, on events: the partial replica
/// holds the frame and X's units 1 and 3, not unit 2, which the removal
/// cites.
#[test]
fn a_partial_replica_proves_order_through_witnesses_and_paths() {
    let h = Concurrent::new();
    // Unit 2 stands as a stub: the removal is placed, but no chain from it
    // reaches unit 1. u before r, no Path yet: pending.
    let mut log = h.log_of(&[GRANT, U1, REMOVAL, U3]);
    assert!(!log.contains(h.fixture.id(REMOVAL)));
    log.add_stub(h.stub(W2));
    assert!(log.contains(h.fixture.id(REMOVAL)));
    assert!(log.contains(h.fixture.id(U3)));
    assert_eq!(h.verdict(&log, U1), "Pending by P removes X");
    // Unit 3 rests on the stub alone: even its order against X's grant is
    // not proven.
    assert_eq!(h.verdict(&log, U3), "Pending by P grants X write");
    // u before r, a Path from r down to u fetched: valid.
    let path = vec![h.event(W2)];
    let removal = h.fixture.id(REMOVAL);
    let u1 = h.fixture.id(U1);
    assert_eq!(log.add_path(removal, u1, path).unwrap(), Some(Vec::new()));
    assert_eq!(h.verdict(&log, U1), "valid");
    // Unit 2 is witnessed now, so unit 3's grant is proven in its past.
    // u concurrent with r: pending, where a full replica refuses it. No
    // Path can prove it before the removal.
    assert_eq!(h.verdict(&log, U3), "Pending by P removes X");
    assert_eq!(h.verdict(&log, GRANT), "valid");
    assert_eq!(h.verdict(&log, REMOVAL), "valid");
}

/// A witnessed parent places the removal, and its envelope's parents are a
/// `Path` of one step: unit 1 is proven before the removal.
#[test]
fn a_witnessed_parent_places_and_proves() {
    let h = Concurrent::new();
    let mut log = h.log_of(&[GRANT, U1, REMOVAL]);
    let placed = log.witness(h.event(W2)).unwrap();
    assert_eq!(placed, vec![h.fixture.id(REMOVAL)]);
    assert_eq!(h.verdict(&log, U1), "valid");
    assert_eq!(h.verdict(&log, REMOVAL), "valid");
    assert!(log.precedes(h.fixture.id(U1), h.fixture.id(REMOVAL)));
}

/// u after r, r among u's parents: `NotAWriter` at both replicas.
#[test]
fn a_unit_after_its_writers_removal_is_not_a_writers() {
    let h = Concurrent::new();
    let (partial, full) = h.case("u after r, r among u's parents");
    assert_eq!(partial, "NotAWriter");
    assert_eq!(full, "NotAWriter");
}

/// units.json's `partial_replica` rows, each built on events of
/// `CONCURRENT` and judged by a partial and a full replica. The family is
/// frasil-units' claim; this runs its cases through the write rule.
#[test]
fn units_partial_replica_cases_on_events() {
    let h = Concurrent::new();
    let rows: Json = frasil_testkit::vectors::family("units.json", "partial_replica");
    for row in rows.as_array().unwrap() {
        let case = text(row, "case");
        let (partial, full) = h.case(case);
        let partial = match partial.split_once(" by ") {
            Some(("Pending", _)) => "Pending: order not proven".to_owned(),
            _ => partial,
        };
        let full = full.split(" by ").next().unwrap().to_owned();
        assert_eq!(partial, text(row, "partial_replica"), "{case}: partial");
        assert_eq!(full, text(row, "full_replica"), "{case}: full");
    }
}

/// A partial replica that holds the frame alone judges every space event
/// as a full replica does: space events cite the maximal space events their
/// authors hold.
#[test]
fn the_frame_alone() {
    let h = Concurrent::new();
    let mut log = h.log_of(&[GRANT, REMOVAL]);
    log.witness(h.event(W2)).unwrap();
    assert_eq!(h.verdict(&log, GRANT), "valid");
    assert_eq!(h.verdict(&log, REMOVAL), "valid");
    assert_eq!(
        log.witnesses().map(Event::id).collect::<Vec<EventId>>(),
        vec![h.fixture.id(W2)]
    );
}

const HEIGHTS: &str =
    "administrators granted concurrently after units, in an odd cycle, at a partial replica";

/// The events a vector names.
fn ids(fixture: &Fixture, names: &Json) -> Vec<EventId> {
    names
        .as_array()
        .unwrap()
        .iter()
        .map(|name| fixture.id(name.as_str().unwrap()))
        .collect()
}

fn names(fixture: &Fixture, ids: &[EventId]) -> Vec<String> {
    ids.iter()
        .map(|&id| fixture.event_names[&id].clone())
        .collect()
}

/// A space event, anchor or storage event: the frame (units.md, "Partial
/// replicas").
fn in_frame(event: &Event) -> bool {
    matches!(event.kind(), kind::SPACE | kind::ANCHOR | kind::STORAGE)
}

/// A partial replica's log of a history's frame: each frame event placed,
/// and each parent of one outside the frame witnessed.
fn frame_log(fixture: &Fixture) -> Log {
    let full = &fixture.log;
    let mut log = Log::new(full.genesis().clone()).unwrap();
    let frame: Vec<&Event> = fixture
        .events
        .iter()
        .map(|(_, event)| event)
        .filter(|event| in_frame(event) && !event.is_genesis())
        .collect();
    for event in &frame {
        log.place((*event).clone()).unwrap();
    }
    for event in &frame {
        for &parent in event.parents() {
            let outside = full.event(parent).is_some_and(|p| !in_frame(p));
            if outside {
                log.witness(full.event(parent).unwrap().clone()).unwrap();
            }
        }
    }
    for event in &frame {
        assert!(log.contains(event.id()), "every frame event is placed");
    }
    log
}

/// A partial replica resolves the log; whatever it does not hold pending
/// it judges as the full replica does. Returns the IDs it wants for
/// heights.
fn never_disagrees(
    fixture: &Fixture,
    log: &Log,
    full: &Space<'_>,
    others: &OtherLogs<'_>,
    notices: &GrantedNotices<'_>,
    what: &str,
) -> Vec<EventId> {
    let partial = resolve(fixture, log, others, notices, Replica::Partial);
    for id in log.canonical() {
        let status = partial.status(id).expect("judged");
        if status.class() == Some(frasil_base::ErrorClass::Pending.into()) {
            continue;
        }
        assert_eq!(
            fixture.show(status),
            fixture.show(full.status(id).expect("the full replica holds it")),
            "{what}: {}",
            fixture.event_names[&id]
        );
    }
    partial.heights_wanted().to_vec()
}

/// roster.json's cycle whose seniority pick reads a grant's height that
/// rests on units: a partial replica holding the frame has only a lower
/// bound for it, which taken as a height flips the pick. It holds every
/// event pending, fetches what it wants by ID until it knows the heights,
/// and then reaches the full replica's verdicts.
#[test]
fn a_partial_replica_resolves_the_roster_on_known_heights_only() {
    let history = family("cycles")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == HEIGHTS)
        .unwrap_or_else(|| panic!("no history {HEIGHTS:?}"))
        .clone();
    let fixture = Fixture::new(&prefix(HEIGHTS), &history["events"]);
    let vector = &history["partial_replica"];
    let others = OtherLogs::none();
    let notices = GrantedNotices::new(&others);
    let full = resolve(&fixture, &fixture.log, &others, &notices, Replica::Full);

    let mut log = frame_log(&fixture);
    let holds: BTreeSet<EventId> = ids(&fixture, &vector["holds"]).into_iter().collect();
    assert_eq!(log.canonical().into_iter().collect::<BTreeSet<_>>(), holds);
    let witnessed: BTreeSet<EventId> = log.witnesses().map(Event::id).collect();
    let want: BTreeSet<EventId> = ids(&fixture, &vector["witnessed"]).into_iter().collect();
    assert_eq!(witnessed, want);
    for (name, height) in vector["heights"].as_object().unwrap() {
        let id = fixture.id(name);
        assert_eq!(
            log.height(id),
            height["lower_bound"].as_u64(),
            "{name}: lower bound"
        );
        assert_eq!(
            log.is_height_exact(id),
            height["known"].as_bool().unwrap(),
            "{name}: known"
        );
        assert_eq!(
            fixture.log.height(id),
            height["height"].as_u64(),
            "{name}: height"
        );
    }

    // A replica that took the lower bounds as heights picks the other way.
    let bounded = resolve(&fixture, &log, &others, &notices, Replica::Full);
    let mut flipped = false;
    for (name, want) in vector["with_lower_bounds"].as_object().unwrap() {
        let id = fixture.id(name);
        let shown = fixture.show(bounded.status(id).unwrap());
        assert_eq!(shown, want.as_str().unwrap(), "{name}: with lower bounds");
        flipped |= shown != fixture.show(full.status(id).unwrap());
    }
    assert!(flipped, "the lower bounds flip the pick");

    // The partial replica holds every event pending, and fetches.
    let partial = resolve(&fixture, &log, &others, &notices, Replica::Partial);
    for (name, want) in vector["events"].as_object().unwrap() {
        let shown = fixture.show(partial.status(fixture.id(name)).unwrap());
        assert_eq!(shown, want.as_str().unwrap(), "{name}: partial");
    }
    let fetches = vector["fetches"].as_array().unwrap();
    for (round, fetch) in fetches.iter().enumerate() {
        let wanted = never_disagrees(&fixture, &log, &full, &others, &notices, HEIGHTS);
        assert_eq!(
            names(&fixture, &wanted),
            names(&fixture, &ids(&fixture, fetch)),
            "fetch {round}"
        );
        for id in wanted {
            log.witness(fixture.log.event(id).unwrap().clone()).unwrap();
        }
    }
    let wanted = never_disagrees(&fixture, &log, &full, &others, &notices, HEIGHTS);
    assert!(wanted.is_empty());
    let partial = resolve(&fixture, &log, &others, &notices, Replica::Partial);
    for (name, want) in vector["after_fetching"].as_object().unwrap() {
        let id = fixture.id(name);
        let shown = fixture.show(partial.status(id).unwrap());
        assert_eq!(shown, want.as_str().unwrap(), "{name}: after fetching");
        assert_eq!(shown, fixture.show(full.status(id).unwrap()), "{name}");
    }
}

/// Every roster.json history whose events a partial replica can hold the
/// frame of: it never reaches a final verdict the full replica does not,
/// before or after it fetches what it wants for heights; and once it wants
/// nothing, it judges every contested roster event as the full replica
/// does. Histories with fork evidence among units are left out: a partial
/// replica sees fork evidence only in its frame and streams.
#[test]
fn a_partial_replica_and_a_full_one_never_disagree() {
    let (mut checked, mut fetched) = (0, 0);
    for family_name in [
        "concurrent_changes",
        "cycles",
        "duels",
        "writes",
        "key_histories",
    ] {
        for history in family(family_name).as_array().unwrap() {
            let name = text(history, "name");
            let fixture = Fixture::new(&prefix(name), &history["events"]);
            let others = others_of(history);
            let notices = GrantedNotices::new(&others);
            let full = resolve(&fixture, &fixture.log, &others, &notices, Replica::Full);
            if !full.forks().is_empty() || history.get("team").is_some() {
                continue;
            }
            let mut log = frame_log(&fixture);
            let mut rounds = 0;
            loop {
                let wanted = never_disagrees(&fixture, &log, &full, &others, &notices, name);
                if wanted.is_empty() {
                    break;
                }
                for id in wanted {
                    log.witness(fixture.log.event(id).unwrap().clone()).unwrap();
                }
                rounds += 1;
                assert!(rounds <= fixture.events.len(), "{name}: fetching ends");
            }
            fetched += usize::from(rounds > 0);
            let partial = resolve(&fixture, &log, &others, &notices, Replica::Partial);
            for &id in full.contested() {
                let status: &Status = partial.status(id).unwrap();
                assert_eq!(
                    fixture.show(status),
                    fixture.show(full.status(id).unwrap()),
                    "{name}: {}",
                    fixture.event_names[&id]
                );
            }
            checked += 1;
        }
    }
    assert!(checked >= 20, "{checked} histories");
    assert!(fetched >= 1, "{fetched} histories fetched for heights");
}
