//! Roster list-copy placement vectors (roster.md, 3.11).

use frasil_base::errors::Class;
use frasil_crypto::primitives::sha256;
use frasil_events::{Event, EventId, Log};
use frasil_space::{
    HeldList, KeyEventChecks, Keyring, Limits, Options, OtherLogs, Space, Twins, UnitBodies,
    UnitBody,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}
fn event(row: &Value) -> Event {
    frasil_events::decode(&frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap())
        .unwrap()
}

struct Copies(BTreeMap<EventId, Vec<EventId>>);
impl UnitBodies for Copies {
    fn open(&self, _: &Event) -> UnitBody {
        UnitBody::Opened(Vec::new())
    }
    fn list_events_at(&self, log: &Log, at: EventId) -> Option<Vec<EventId>> {
        Some(
            self.0
                .iter()
                .filter(|(copy, _)| **copy == at || log.precedes(**copy, at))
                .flat_map(|(_, events)| events.iter().copied())
                .collect(),
        )
    }
}

#[test]
fn moved_and_second_lists_do_not_rewrite_an_earlier_place() {
    let vectors: Value = frasil_testkit::vectors::family("roster.json", "across_logs");
    for how in ["moved", "second"] {
        let title = if how == "moved" {
            "a device moved from one person's list to another after an edit"
        } else {
            "a device added to a second person's list after an edit"
        };
        let case = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == title)
            .unwrap();
        let rows = case["events"].as_array().unwrap();
        let events: BTreeMap<_, _> = rows
            .iter()
            .map(|row| (row["name"].as_str().unwrap(), event(row)))
            .collect();
        let genesis = event(&rows[0]);
        let mut log = Log::new(genesis.clone()).unwrap();
        for row in rows.iter().skip(1) {
            log.place(event(row)).unwrap();
        }
        let mut keys = Keyring::default();
        for (index, row) in rows.iter().enumerate() {
            let event = event(row);
            let label = if index == 0 {
                "genesis"
            } else {
                row["name"].as_str().unwrap()
            };
            let key = example(&format!("roster/list-place/{how}/{label}/content-key"));
            if frasil_keys::body::VisiblePart::read(
                event.unverified_body(),
                event.author(),
                event.seq(),
            )
            .ok()
            .and_then(|visible| visible.rotation().map(|rotation| rotation.read))
            .is_some_and(|read| frasil_keys::derive::read_credential(&key).public == read)
            {
                keys.rotations.insert(event.id(), key.into());
            }
        }
        let mut others = OtherLogs::none();
        let mut named = BTreeMap::new();
        let mut copies = Copies(BTreeMap::new());
        for (person, copy_first, copy_add, add_name) in [
            (
                "person A",
                "a1 copies A's first event",
                "a1 copies the add of d",
                "a1 adds d to A",
            ),
            (
                "person B",
                "b1 copies B's first event",
                "b1 copies the add of d",
                "b1 adds d to B",
            ),
        ] {
            let list_rows = case["lists"][person].as_array().unwrap();
            let first = event(&list_rows[0]);
            let list = HeldList::from_signed_events(
                &list_rows
                    .iter()
                    .map(|row| event(row).signed())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            copies.0.insert(events[copy_first].id(), vec![first.id()]);
            let add = list_rows
                .iter()
                .find(|row| row["name"] == add_name)
                .unwrap();
            copies
                .0
                .insert(events[copy_add].id(), vec![event(add).id()]);
            if person == "person A" && how == "moved" {
                let revoke = list_rows
                    .iter()
                    .find(|row| row["name"] == "a1 revokes d from A")
                    .unwrap();
                copies.0.insert(
                    events["a1 copies the revocation of d"].id(),
                    vec![event(revoke).id()],
                );
            }
            if person == "person B" {
                let add = list_rows
                    .iter()
                    .find(|row| row["name"] == "b1 adds e to B, copied nowhere yet")
                    .unwrap();
                copies.0.insert(
                    events["b1 copies the add of e, after e's unit"].id(),
                    vec![event(add).id()],
                );
            }
            named.insert(list.person(), person);
            others = others.with_list(list);
        }
        let options = Options {
            keys: &keys,
            limits: Limits::PROTOCOL,
            others: &others,
            units: &copies,
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::StaleSeal,
            notices: None,
        };
        let late_copy = events["b1 copies the add of e, after e's unit"].id();
        let before: BTreeSet<_> = log
            .events()
            .map(Event::id)
            .filter(|id| *id != late_copy)
            .collect();
        let earlier = Space::resolve(&log, Some(&before), options).unwrap();
        let early = events["e writes before any copy of its add"].id();
        assert_eq!(
            earlier.status(early).unwrap().class().unwrap().name(),
            "NotAWriter"
        );
        let space = Space::resolve(&log, None, options).unwrap();
        for (name, expected) in case["views"]["all"]["events"].as_object().unwrap() {
            let status = space.status(events[name.as_str()].id()).unwrap();
            let got = if status.is_valid() {
                "valid"
            } else {
                status.class().unwrap().name()
            };
            assert_eq!(got, expected.as_str().unwrap(), "{how}: {name}: {status:?}");
        }
        for (name, expected) in case["attribution"].as_object().unwrap() {
            let id = events[name.as_str()].id();
            let got = space.attribution(id).map(|paths| {
                Value::Array(
                    paths
                        .into_iter()
                        .map(|(member, label)| {
                            serde_json::json!([
                                member.kind.code(),
                                named[&member.id],
                                label.unwrap()
                            ])
                        })
                        .collect(),
                )
            });
            assert_eq!(got.unwrap_or(Value::Null), *expected, "{how}: {name}");
        }
        let early = events["e writes before any copy of its add"].id();
        assert_eq!(
            space.status(early).unwrap().class().unwrap().name(),
            "NotAWriter"
        );
    }
}
