//! A person member across a list checkpoint (roster.md, 3.15.8 Other logs
//! and extensions; identity.md, "List checkpoints", "Spaces"): a list
//! checkpoint in effect ends at once, in every space, the path of every
//! device it does not list, and a replica that kept the whole list and one
//! that forgot it agree. With no list checkpoint, nothing changes.

mod common;

use common::space::{Fixture, list_device, name_other, person_id, prefix, whole_list};
use common::{family, text};
use frasil_crypto::device::KeyRing;
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, Kind as ListKind, MemberKeys};
use frasil_space::{HeldList, Level, MemberType, OtherLogs, PathsFor, Space};
use serde_json::Value as Json;

/// roster.json's history in which P grants person B, B's list revokes b2,
/// and W responds.
const HISTORY: &str = "a person grant, a revocation in the list, and the space's response";

fn history() -> Json {
    family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == HISTORY)
        .unwrap()
        .clone()
}

/// The person's list with b3 added by b1, then a list checkpoint by b1 in
/// effect once b3 acks: b2, revoked before it, is not listed.
fn checkpointed(mut list: DeviceList, prefix: &str) -> (DeviceList, MemberKeys) {
    let b1 = list_device(prefix, "b1");
    let b3 = list_device(prefix, "b3");
    let person = list.person_id();
    let add = ListBody::add(
        ListKind::Device,
        &b3.public(ListKind::Device),
        b3.prove_possession(&person, b1.device_id(), ListKind::Device),
    );
    let signed = list.sign(&add, b1.signer());
    list.insert(&signed).unwrap();
    let checkpoint = list.propose_checkpoint(b1.signer()).unwrap();
    list.insert(&checkpoint).unwrap();
    let ack = list.ack(b3.signer());
    list.insert(&ack).unwrap();
    (list, b3)
}

/// Every event's status, by name.
fn statuses(fixture: &Fixture, space: &Space<'_>) -> Json {
    fixture.summary(space, false)["events"].clone()
}

#[test]
fn a_person_member_across_a_list_checkpoint() {
    let history = history();
    let list_prefix = history["list_prefixes"]["person B"]
        .as_str()
        .unwrap()
        .to_owned();
    let events = &history["lists"]["person B"];
    let whole: DeviceList = whole_list(events).list().unwrap().clone();
    let mut fixture = Fixture::new(&prefix(HISTORY), &history["events"]);
    fixture.name_events(events);
    name_other(
        &mut fixture,
        "person B",
        person_id(events),
        MemberType::Person,
    );
    let b1 = list_device(&list_prefix, "b1").device_id().0;
    let b2 = fixture.device_key("b2");

    // With no list checkpoint, the space reads the list as before: b2's
    // path ends once W responds.
    let plain = OtherLogs::none().with_list(HeldList::new(whole.clone()));
    let space = fixture.resolve(None, &fixture.keys, &plain).unwrap();
    assert_eq!(
        statuses(&fixture, &space),
        history["views"]["all"]["events"]
    );
    assert!(space.attribution(fixture.id("b2 writes")).is_some());
    let held = plain.list(&person_id(events)).unwrap();
    assert!(
        held.writers().contains(&b2),
        "b2 still writes until a response"
    );
    assert_eq!(held.unlisted_end(&b2), None);

    // A list checkpoint in effect does not list b2.
    let (list, b3) = checkpointed(whole, &list_prefix);
    let b3 = b3.device_id().0;
    let merged = list.merge();
    let c = *merged.chain().last().expect("a checkpoint in effect");
    let full = HeldList::new(list.clone());
    let kept = list.forget(&merged).expect("a checkpoint in effect");
    let forgot = HeldList::kept(kept.clone());
    for (holder, held) in [("full", &full), ("forgot", &forgot)] {
        assert_eq!(held.merged().chain(), [c], "{holder}");
        assert!(
            !held.writers().contains(&b2),
            "{holder}: b2 writes no longer"
        );
        assert!(held.writers().contains(&b1) && held.writers().contains(&b3));
        assert_eq!(held.unlisted_end(&b2), Some(c), "{holder}");
        assert_eq!(held.unlisted_end(&b1), None, "{holder}");
    }
    assert!(forgot.kept_list().is_some() && forgot.list().is_none());
    assert_eq!(full.writers(), forgot.writers());
    assert_eq!(full.members(), forgot.members());
    assert_eq!(full.key_devices(), forgot.key_devices());

    // The space reads each: b2 has no path through the person, at once,
    // with no response to wait for; b1 and b3 keep theirs. A holder that
    // forgot b2's add holds b2's keys only from another source.
    let mut b2_keys = KeyRing::new();
    b2_keys.extend(list.keys());
    let with_full = OtherLogs::none().with_list(full);
    let with_forgot = OtherLogs::none().with_list(forgot).with_keys(&b2_keys);
    let spaces = [
        (
            "full",
            fixture.resolve(None, &fixture.keys, &with_full).unwrap(),
        ),
        (
            "forgot",
            fixture.resolve(None, &fixture.keys, &with_forgot).unwrap(),
        ),
    ];
    for (holder, space) in &spaces {
        let roster = space.roster();
        let (paths, unknown) = space.paths(&b2, roster, Level::Write);
        assert!(paths.is_empty() && !unknown, "{holder}: b2 has no path");
        assert!(space.reach_at(&b2, roster, PathsFor::Unit).is_none());
        for device in [b1, b3] {
            let (paths, _) = space.paths(&device, roster, Level::Write);
            assert_eq!(paths.len(), 1, "{holder}: a listed device keeps its path");
            assert!(space.reach_at(&device, roster, PathsFor::Unit).is_some());
        }
        let status = statuses(&fixture, space);
        for name in ["P grants W write", "P grants person B write"] {
            assert_eq!(status[name], "valid", "{holder}: {name}");
        }
        for name in [
            "b2 writes",
            "b2 writes before anyone in the space hears",
            "b2 writes after the response, apart",
        ] {
            assert_ne!(status[name], "valid", "{holder}: {name}");
            assert!(
                space.attribution(fixture.id(name)).is_none(),
                "{holder}: {name}"
            );
        }
    }
    // A replica that kept the whole list and one that forgot it agree.
    assert_eq!(
        statuses(&fixture, &spaces[0].1),
        statuses(&fixture, &spaces[1].1)
    );

    // Without b2's keys from another source, the one that forgot holds
    // b2's key event until they arrive, and drops its units: none is valid.
    let bare = OtherLogs::none().with_list(HeldList::kept(kept.clone()));
    let space = fixture.resolve(None, &fixture.keys, &bare).unwrap();
    let status = statuses(&fixture, &space);
    assert_eq!(status["b2 heals"], "NoHybridKey");
    for name in [
        "b2 writes",
        "b2 writes before anyone in the space hears",
        "b2 writes after the response, apart",
    ] {
        assert_eq!(status[name], "Dropped", "{name}");
    }

    // Its sealed copy reads alike, given the IDs of the list events its
    // writer forgot, which travel beside it.
    let copy = kept.signed_events();
    let sealed = frasil_identity::KeptList::from_sealed_copy(
        copy.iter().map(Vec::as_slice),
        kept.forgotten(),
    )
    .unwrap();
    let from_copy = OtherLogs::none()
        .with_list(HeldList::kept(sealed))
        .with_keys(&b2_keys);
    let space = fixture.resolve(None, &fixture.keys, &from_copy).unwrap();
    assert_eq!(statuses(&fixture, &space), statuses(&fixture, &spaces[0].1));
}

/// Every event's verdict as roster.json's `checkpoints` writes it: `valid`,
/// or the class alone.
fn verdicts(fixture: &Fixture, space: &Space<'_>) -> Json {
    let mut events = statuses(fixture, space);
    // The summary leaves the genesis out; these vectors name it.
    let genesis = fixture.log.id();
    events.as_object_mut().unwrap().insert(
        fixture_name(fixture, genesis),
        Json::from(fixture.show(space.status(genesis).unwrap())),
    );
    Json::Object(
        events
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, shown)| {
                let shown = shown.as_str().unwrap();
                let class = if shown.starts_with("valid") {
                    "valid"
                } else {
                    shown.split(" by ").next().unwrap()
                };
                (name.clone(), Json::from(class))
            })
            .collect(),
    )
}

/// roster.json `checkpoints.adversarial.person_across_list` (roster.md,
/// 3.15.8, "What an unlisted device loses"): B's list checkpoint, in
/// effect, does not list b2, so every unit of b2 is `Dropped`, those
/// before the checkpoint too, at a replica that kept B's whole list and at
/// one that forgot it; b2's key event is `Dropped` where b2's keys are held
/// and `NoHybridKey` (held) where they are not. W's response cites the
/// list's revocation, before the list checkpoint: it resolves at both.
#[test]
fn person_across_list_vectors() {
    let case = family("checkpoints")["adversarial"]["person_across_list"].clone();
    let prefix = text(&case, "history_prefix");
    let list_events = &case["list"];
    let mut fixture = Fixture::new(prefix, &case["events"]);
    fixture.name_events(list_events);
    name_other(
        &mut fixture,
        "person B",
        person_id(list_events),
        MemberType::Person,
    );

    // Without the list checkpoint: the list as the space first read it.
    let before = common::space::held_list(
        list_events,
        &serde_json::json!([
            "b1 starts the list",
            "b1 adds b2",
            "b1 revokes b2 in B's list"
        ]),
    );
    let plain = OtherLogs::none().with_list(before);
    let space = fixture.resolve(None, &fixture.keys, &plain).unwrap();
    assert_eq!(verdicts(&fixture, &space), case["without_list_checkpoint"]);

    // A replica that kept B's whole list, and so b2's keys.
    let whole: DeviceList = whole_list(list_events).list().unwrap().clone();
    let merged = whole.merge();
    assert_eq!(
        merged
            .chain()
            .iter()
            .map(|id| fixture_name(&fixture, *id))
            .collect::<Vec<_>>(),
        [text(&case, "list_checkpoint").to_owned()]
    );
    let full = OtherLogs::none().with_list(HeldList::new(whole.clone()));
    let space = fixture.resolve(None, &fixture.keys, &full).unwrap();
    assert_eq!(verdicts(&fixture, &space), case["whole_list"]);

    // A replica that forgot it under its checkpoint, with no other source
    // of b2's keys.
    let kept = whole.forget(&merged).expect("a list checkpoint in effect");
    let mut holds: Vec<String> = kept
        .canonical()
        .iter()
        .map(|id| fixture_name(&fixture, *id))
        .collect();
    holds.sort_unstable();
    assert_eq!(Json::from(holds), case["list_held_after_forgetting"]);
    let forgot = OtherLogs::none().with_list(HeldList::kept(kept.clone()));
    let space = fixture.resolve(None, &fixture.keys, &forgot).unwrap();
    assert_eq!(verdicts(&fixture, &space), case["forgotten_list"]);

    // A newcomer from the list's sealed copy and the forgotten IDs that
    // travel beside it judges alike: W's ref to the revocation resolves.
    let copy = kept.signed_events();
    let sealed = frasil_identity::KeptList::from_sealed_copy(
        copy.iter().map(Vec::as_slice),
        kept.forgotten(),
    )
    .unwrap();
    let revoke = fixture.id("b1 revokes b2 in B's list");
    assert!(sealed.merge().resolves_before_checkpoint(revoke));
    let from_copy = OtherLogs::none().with_list(HeldList::kept(sealed));
    let space = fixture.resolve(None, &fixture.keys, &from_copy).unwrap();
    assert_eq!(verdicts(&fixture, &space), case["forgotten_list"]);
}

/// The name the fixture gives an event.
fn fixture_name(fixture: &Fixture, id: frasil_events::EventId) -> String {
    fixture
        .event_names
        .get(&id)
        .cloned()
        .unwrap_or_else(|| format!("{id:?}"))
}
