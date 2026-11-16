//! `identity.json`: persons, lists, their refusals, merges, enrolment and
//! pins (identity.md, "The person ID and the personal space", "Checking a
//! list event alone", "The state of a list at a place", "Checks at the
//! event's place", "What a list vouches for", "Adding list members",
//! "Using a passkey member" and "Pins"). `merges` is in tests/merges.rs.

mod common;

use common::{
    array, by_device, bytes, check_summary, class, device, device_names, example, family,
    identity_of, kind_named, list_of, text, verdict_text,
};
use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_events::decode;
use frasil_identity::passkey::PasskeyMember;
use frasil_identity::possession::{self, FIRST_EVENT_PERSON};
use frasil_identity::recovery::{RecoveryKey, RecoverySecret};
use frasil_identity::{DeviceList, Kind, Pin, PinCheck};
use serde_json::Value as Json;
use std::collections::BTreeMap;

fn rows(value: &Json) -> Vec<&Json> {
    value.as_array().unwrap().iter().collect()
}

/// Checks each event row of `list` or `passkey_list`: its signed bytes
/// decode to its ID, author and body, and the body reads as the row says,
/// with the statement an add's proof signs.
fn check_event_rows(list: &DeviceList, events: &[&Json], members: &BTreeMap<IdentityKey, String>) {
    let person = list.person_id();
    let authors = by_device(&list.merge(), members);
    for row in events {
        let name = text(row, "name");
        let event = decode(&bytes(row, "signed")).unwrap();
        assert_eq!(event.id().0, array::<32>(row, "id"), "{name}");
        assert_eq!(event.unverified_body(), &bytes(row, "body")[..], "{name}");
        assert_eq!(event.seq(), row["seq"].as_u64().unwrap(), "{name}");
        assert_eq!(authors[event.author()], text(row, "author"), "{name}");
        let body = list.body(event.id()).expect("passes alone");
        assert_eq!(body.action.name(), text(row, "action"), "{name}");
        assert_eq!(body.kind, kind_named(text(row, "kind")), "{name}");
        assert_eq!(body.device.0, array::<32>(row, "device"), "{name}");
        if let Some(added) = &body.added {
            assert_eq!(added.identity.0, array::<32>(row, "identity"), "{name}");
            let keys = body.keys().unwrap();
            assert_eq!(
                keys.hybrid().commitment().0,
                array::<32>(row, "kc"),
                "{name}"
            );
            assert_eq!(keys.device_id(), body.device, "{name}");
            let bound = if event.is_genesis() {
                FIRST_EVENT_PERSON
            } else {
                person
            };
            let statement = possession::statement(
                &bound,
                event.author(),
                body.kind,
                &added.identity,
                &added.mldsa,
                added.xwing.as_deref(),
            );
            assert_eq!(statement, bytes(row, "statement"), "{name}");
            assert_eq!(added.possession, bytes(row, "possession"), "{name}");
            assert_eq!(&added.mldsa[..], &bytes(row, "mldsa")[..], "{name}");
            let xwing = added.xwing.as_ref().map(|x| x.to_vec());
            let expected = (!row["xwing"].is_null()).then(|| bytes(row, "xwing"));
            assert_eq!(xwing, expected, "{name}");
        }
    }
}

#[test]
fn persons() {
    let f = family("persons");
    let persons = f.as_object().unwrap();
    assert_eq!(persons.len(), 2);
    for (name, person) in persons {
        let first = bytes(person, "first_event");
        let list = DeviceList::new(&first).unwrap();
        let person_id: [u8; 32] = array(person, "person_id");
        assert_eq!(list.person_id(), person_id, "{name}");
        // The personal space ID is a fixture standing for a space's genesis.
        let space = example(&format!(
            "identity/personal-space/{}",
            frasil_testkit::hex::encode(person_id)
        ));
        assert_eq!(space, array::<32>(person, "personal_space_id"), "{name}");
        // The first event adds its author, a device: the only list member.
        let laptop = device(&format!("identity/{name}"), "laptop");
        assert_eq!(DeviceList::first_event(&laptop), first, "{name}");
        let merged = list.merge();
        let active: Vec<_> = merged.active_members().map(|m| m.device).collect();
        assert_eq!(active, vec![*laptop.device_id()], "{name}");
        assert_eq!(merged.recipients(), vec![*laptop.device_id()], "{name}");
        assert_eq!(
            laptop.signer().kc().0,
            array::<32>(person, "first_device_kc")
        );
        assert_eq!(laptop.device_id().0, array::<32>(person, "first_device_id"));
    }
}

#[test]
fn forged_list() {
    let f = family("forged_list");
    let mut list = DeviceList::new(&bytes(&f, "forger_first_event")).unwrap();
    assert_eq!(list.person_id(), array::<32>(&f, "forger_person_id"));
    assert_ne!(list.person_id(), array::<32>(&f, "person_id"));
    let events = rows(&f["events"]);
    assert_eq!(events.len(), 4);
    for row in &events {
        list.insert(&bytes(row, "event")).unwrap();
    }
    let merged = list.merge();
    for row in &events[..3] {
        let id = decode(&bytes(row, "event")).unwrap().id();
        let verdict = merged.verdict(id).unwrap();
        assert_eq!(
            verdict.class().map(|c| c.name()),
            Some(text(row, "error")),
            "{}",
            text(row, "name")
        );
    }
    // The other person's device's Ed25519 key, added beside keys of the
    // forger's own: valid in the forger's list, under a device ID of its
    // own, never the other person's device.
    let lent = events[3];
    assert_eq!(text(lent, "verdict"), "valid");
    let add = decode(&bytes(lent, "event")).unwrap();
    assert!(merged.is_valid(add.id()));
    let named = DeviceId(array(lent, "named_device_id"));
    let victim = DeviceId(array(lent, "victim_device_id"));
    assert_ne!(named, victim);
    assert_eq!(list.body(add.id()).unwrap().device, named);
    assert!(merged.member(&named).is_some());
    assert!(merged.member(&victim).is_none());
    // An event that key set signs: its author is that device ID, and it
    // verifies in the forger's list under the keys the add names.
    let signed = decode(&bytes(lent, "signed_by_that_key_set")).unwrap();
    assert_eq!(signed.author().0, array::<32>(lent, "its_author"));
    assert_eq!(*signed.author(), named);
    assert_ne!(*signed.author(), victim);
    assert!(signed.verify_hybrid_in(list.keys()).is_ok());
    assert_eq!(merged.members().len(), 2);
}

#[test]
fn list() {
    let f = family("list");
    let events = rows(&f["events"]);
    let (list, names) = list_of(&events);
    assert_eq!(list.person_id(), array::<32>(&f, "person_id"));
    let members = device_names("identity", &f["result"]);
    check_event_rows(&list, &events, &members);
    let merged = list.merge();
    check_summary("list", &merged, &names, &members, &f["result"]);

    // What the list vouches for: the helped device waits on its agent, the
    // agent receives nothing, and the revoked browser neither; the recovery
    // key receives. Under a policy that forbids agents, nobody does while
    // the list holds an active agent.
    let devices = by_device(&merged, &members);
    let named = |name: &str| -> DeviceId {
        *devices
            .iter()
            .find(|(_, n)| n.as_str() == name)
            .unwrap_or_else(|| panic!("no member {name}"))
            .0
    };
    let names_of = |devices_named: Vec<DeviceId>| {
        let mut out: Vec<&str> = devices_named.iter().map(|k| devices[k].as_str()).collect();
        out.sort_unstable();
        out
    };
    let listed = |key: &str| -> Vec<&str> {
        f[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect()
    };
    assert_eq!(names_of(merged.recipients()), listed("recipients"));
    assert_eq!(
        listed("recipients"),
        ["laptop", "passkey", "phone", "recovery"]
    );
    assert!(merged.holds_active_agent());
    let forbidding = if merged.holds_active_agent() {
        Vec::new()
    } else {
        merged.recipients()
    };
    assert_eq!(names_of(forbidding), listed("recipients_forbidding_agents"));
    assert!(merged.is_waiting(&named("helped")));
    assert!(merged.recipients_with(|_| true).contains(&named("helped")));
    let writers = merged.writers();
    for name in ["laptop", "phone", "passkey", "browser", "helped"] {
        assert!(writers.contains_key(&named(name)), "{name}");
    }
    assert!(!writers.contains_key(&named("recovery")));
    assert!(!writers.contains_key(&named("agent")));
    let revocation = events
        .iter()
        .find(|row| text(row, "name") == "phone revokes browser")
        .map(|row| array::<32>(row, "id"))
        .unwrap();
    let ends: Vec<[u8; 32]> = merged
        .ends(&named("browser"))
        .iter()
        .map(|id| id.0)
        .collect();
    assert_eq!(ends, vec![revocation]);
}

#[test]
fn passkey_list() {
    let f = family("passkey_list");
    let prefix = "identity/passkey-list";
    let person: [u8; 32] = array(&f, "person_id");

    // Each derived list member, derived again.
    let mut members = BTreeMap::new();
    for row in rows(&f["derived"]) {
        let name = text(row, "name");
        let (keys, fetch) = if text(row, "kind") == "passkey member" {
            let member = PasskeyMember::derive(&person, &bytes(row, "prf_output")).unwrap();
            let public = member.member().public(Kind::PasskeyMember);
            (public, *member.fetch().public())
        } else {
            let secret = RecoverySecret::from_bytes(&array(row, "secret"));
            let key = RecoveryKey::derive(&secret);
            (
                key.member().public(Kind::RecoveryKey),
                *key.fetch().public(),
            )
        };
        assert_eq!(keys.identity.0, array::<32>(row, "identity"), "{name}");
        assert_eq!(&keys.mldsa[..], &bytes(row, "mldsa_public")[..], "{name}");
        assert_eq!(
            keys.xwing.as_ref().map(|x| x.to_vec()),
            Some(bytes(row, "xwing")),
            "{name}"
        );
        assert_eq!(fetch, array::<32>(row, "fetch_key"), "{name}");
        members.insert(keys.identity, name.to_string());
    }
    for name in ["laptop", "browser", "tablet", "desk"] {
        members.insert(identity_of(prefix, name), name.to_string());
    }

    let events = rows(&f["events"]);
    assert_eq!(events.len(), 17);
    let (list, names) = list_of(&events);
    assert_eq!(list.person_id(), person);
    check_event_rows(&list, &events, &members);
    let merged = list.merge();
    let devices = by_device(&merged, &members);
    for row in &events {
        let event = decode(&bytes(row, "signed")).unwrap();
        assert_eq!(devices[event.author()], text(row, "signed_by"));
        let body = list.body(event.id()).unwrap();
        assert_eq!(devices[&body.device], text(row, "names"));
    }
    check_summary("passkey_list", &merged, &names, &members, &f["result"]);

    // The active recovery key and passkey member count as recovery
    // entries' members; the revoked passkey member does not.
    use frasil_identity::entries::RecoveryEntry;
    let space = [7; 32];
    let by_name = |wanted: &str| {
        *devices
            .iter()
            .find(|(_, name)| name.as_str() == wanted)
            .unwrap()
            .0
    };
    let entry = |name| RecoveryEntry::for_member(space, [1; 32], by_name(name));
    assert!(merged.entry_counts(&entry("recovery-3")));
    assert!(!merged.entry_counts(&entry("passkey-1")));
    assert!(!merged.entry_counts(&entry("laptop")));
    assert!(merged.entry_counts(&RecoveryEntry::for_seed(space, &[3; 32])));

    // Using a passkey member: the revoked one is no longer on the list.
    let output = |name: &str| {
        rows(&f["derived"])
            .into_iter()
            .find(|row| text(row, "name") == name)
            .map(|row| bytes(row, "prf_output"))
            .unwrap()
    };
    assert_eq!(
        class(merged.use_passkey_member(&person, &output("passkey-1"))),
        Some("NotOnList")
    );
    let mut handle = person.to_vec();
    handle.extend_from_slice(&space);
    assert!(frasil_identity::read_user_handle(&handle, Some(&merged)).is_ok());
    assert_eq!(
        class(frasil_identity::read_user_handle(
            &handle[1..],
            Some(&merged)
        )),
        Some("Malformed")
    );
    handle[0] ^= 1;
    assert_eq!(
        class(frasil_identity::read_user_handle(&handle, Some(&merged))),
        Some("WrongPerson")
    );
    assert!(frasil_identity::read_user_handle(&handle, None).is_ok());
}

#[test]
fn list_refusals() {
    let f = family("list_refusals");
    let base = rows(&f["base"]);
    assert_eq!(base.len(), 6);
    let cases = rows(&f["cases"]);
    assert_eq!(cases.len(), 39);
    for case in cases {
        let name = text(case, "name");
        let mut events = base.clone();
        events.extend(rows(&case["also_before"]));
        let (mut list, names) = list_of(&events);
        let bad = bytes(case, "event");
        list.insert(&bad).unwrap();
        let merged = list.merge();
        for (id, verdict) in merged.verdicts() {
            if let Some(event_name) = names.get(&id) {
                assert!(verdict.is_valid(), "{name}: {event_name}");
            }
        }
        let id = decode(&bad).unwrap().id();
        let verdict = merged.verdict(id).unwrap();
        assert_eq!(
            verdict.class().map(|c| c.name()),
            Some(text(case, "error")),
            "{name}: {}",
            verdict_text(verdict, &names)
        );
    }
}

#[test]
fn enrolment() {
    let f = family("enrolment");
    let cases = rows(&f);
    assert_eq!(cases.len(), 2);
    let laptop = device("identity/enrolment", "laptop");
    let list = DeviceList::new(&DeviceList::first_event(&laptop)).unwrap();
    for case in cases {
        let name = text(case, "name");
        let person: [u8; 32] = array(case, "person_id");
        assert_eq!(list.person_id(), person, "{name}");
        let (first, second) = (
            bytes(case, "first_prf_output"),
            bytes(case, "second_prf_output"),
        );
        let enrolled = PasskeyMember::enrol(&person, &first, &second);
        let added = list.add_passkey_member(&first, &second, &laptop);
        if let Some(error) = case.get("error") {
            assert_eq!(class(enrolled), error.as_str(), "{name}");
            assert_eq!(class(added), error.as_str(), "{name}");
            continue;
        }
        let member = enrolled.unwrap();
        let keys = member.member();
        assert_eq!(keys.identity().0, array::<32>(case, "identity"), "{name}");
        assert_eq!(
            &keys.xwing().unwrap()[..],
            &bytes(case, "xwing")[..],
            "{name}"
        );
        assert_eq!(
            &keys.mldsa()[..],
            &bytes(case, "mldsa_public")[..],
            "{name}"
        );
        assert_eq!(
            member.fetch().public(),
            &array::<32>(case, "fetch_key"),
            "{name}"
        );

        // The add the device signs makes it an active passkey member, and
        // the same keys cannot be added twice.
        let (signed, _) = added.unwrap();
        let mut grown = list.clone();
        grown.insert(&signed).unwrap();
        let merged = grown.merge();
        assert!(merged.is_valid(decode(&signed).unwrap().id()), "{name}");
        let public = keys.public(Kind::PasskeyMember);
        assert_eq!(merged.check_on_list(Kind::PasskeyMember, &public), Ok(()));
        assert!(merged.use_passkey_member(&person, &first).is_ok());
        assert_eq!(
            class(grown.add_passkey_member(&first, &second, &laptop)),
            Some("AlreadyListed")
        );
    }
}

#[test]
fn pins() {
    let f = family("pins");
    let events = rows(&f["events"]);
    let by_name: BTreeMap<&str, &Json> =
        events.iter().map(|row| (text(row, "name"), *row)).collect();
    let state = |names: &[Json]| {
        let mut chosen: Vec<&Json> = names.iter().map(|n| by_name[n.as_str().unwrap()]).collect();
        // The first event starts the list.
        chosen.sort_by_key(|row| {
            !row["prev"].is_null() || !row["parents"].as_array().unwrap().is_empty()
        });
        list_of(&chosen).0
    };
    let cases = rows(&f["cases"]);
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = text(case, "name");
        let pinned = state(case["pinned"].as_array().unwrap());
        let offered = state(case["offered"].as_array().unwrap());
        let pin = Pin::of(&pinned);
        let check = pin.check(&offered);
        let result = match &check {
            PinCheck::Advances => "Advanced",
            PinCheck::RolledBack => "RolledBack",
            PinCheck::ForkDetected(evidence) => {
                assert!(!evidence.is_empty(), "{name}");
                "ForkDetected"
            }
        };
        assert_eq!(result, text(case, "result"), "{name}");
        assert_eq!(
            check.class().map(|c| c.name()),
            (result != "Advanced").then_some(result),
            "{name}"
        );
        if result != "RolledBack" {
            let mut grown = pin.clone();
            grown.advance(&offered);
            assert_eq!(grown.check(&offered), PinCheck::Advances, "{name}");
            assert!(grown.events().is_superset(pin.events()), "{name}");
        }
    }
}
