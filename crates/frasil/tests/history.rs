//! History (decision: a client toolkit): a change names its device and
//! its person as the roster does; a document's history walks edits,
//! suggestions and reviews, with a checkout before and after each; a
//! table's history names rows and columns, and a replay answers "from
//! what".
#![cfg(all(
    feature = "adapter-loro",
    feature = "adapter-records",
    feature = "iroh"
))]

use frasil::advanced::Engine;
use frasil::loro::ExportMode;
use frasil::{
    Detail, Device, Effect, Kind, Level, Options, Space, Standing, Storage, UnitId, Value,
};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Via};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(30);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .expect("a device")
}

fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// Every event `from` holds of the space, handed to `to`.
async fn carry(from: &Engine, to: &Engine, space: EventId) {
    let events = from.events(&space).await;
    let ingested = to.ingest(space, events).await.expect("ingested");
    assert!(
        ingested.refused.is_empty(),
        "refused: {:?}",
        ingested.refused
    );
}

/// Alice's space, with Bob granted `level` and holding every event.
async fn with_member(alice: &Device, bob: &Device, level: Level) -> Space {
    let space = alice.create_space().await.unwrap();
    alice
        .engine()
        .grant_device_at(
            event_of(&space),
            bob.engine().public_keys().clone(),
            level,
            (level == Level::Administer).then_some(255),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(event_of(&space)).await;
    carry(alice.engine(), bob.engine(), event_of(&space)).await;
    space
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_names_a_device_the_roster_grants_directly() {
    // Bob joins by a code: a device the roster grants directly, which
    // every change of his carries. The names the screens showed at the
    // join are not roster labels, and no flow writes one yet: the roster
    // names him by identity alone.
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "alice "))
        .await
        .unwrap();
    let bobs = within(async {
        loop {
            if let Ok(doc) = bobs_space.document(document.id()).await {
                break doc;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    bobs.edit(|doc| doc.get_text("body").insert(0, "bob "))
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), event_of(&space)).await;

    let history = document.history().await.unwrap();
    assert_eq!(history.len(), 2, "{history:?}");
    let bobs_change = history
        .iter()
        .find(|change| change.author.device == bob.id())
        .expect("Bob's change");
    assert_eq!(bobs_change.author.device_name, None, "no label written");
    assert_eq!(bobs_change.author.person, None);
    assert_eq!(bobs_change.author.person_name, None);
    let alices_change = history
        .iter()
        .find(|change| change.author.device == alice.id())
        .expect("Alice's change");
    assert_eq!(alices_change.author.person, None);
    for change in &history {
        assert_eq!(change.kind, Kind::Edit);
        assert_eq!(change.effect, Effect::Applied);
        assert!(change.time.is_some(), "the writer's clock: {change:?}");
    }
    assert!(
        history.windows(2).all(|w| w[0].height <= w[1].height),
        "canonical order"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_names_its_person_as_the_roster_does() {
    // Carol reaches the space through her person: her device is not
    // granted directly, her person's list vouches for it.
    let alice = device(3).await;
    let carol = device(4).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    let carols_person = *carol.make_person(&[4; 32]).await.unwrap().as_bytes();
    alice
        .engine()
        .receive_list(carol.engine().list_events(&carols_person).await)
        .await
        .unwrap();
    alice
        .engine()
        .grant_person(
            id,
            carols_person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice
        .engine()
        .publish_list(id, &carols_person)
        .await
        .unwrap();
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "alice "))
        .await
        .unwrap();
    carol.engine().follow(id).await;
    carry(alice.engine(), carol.engine(), id).await;
    let carols = carol
        .space(space.id())
        .await
        .unwrap()
        .document(document.id())
        .await
        .unwrap();
    carols
        .edit(|doc| doc.get_text("body").insert(0, "carol "))
        .await
        .unwrap();
    carry(carol.engine(), alice.engine(), id).await;

    let history = document.history().await.unwrap();
    assert_eq!(history.len(), 2, "{history:?}");
    let carols_change = history
        .iter()
        .find(|change| change.author.device == carol.id())
        .expect("Carol's change");
    assert_eq!(
        carols_change.author.device_name, None,
        "not granted directly"
    );
    assert_eq!(
        carols_change.author.person.map(|p| *p.as_bytes()),
        Some(carols_person),
        "her person vouches for her device"
    );
    assert_eq!(carols_change.author.device, carol.id());
    assert_eq!(document.text("body").await.unwrap(), "carol alice ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_document_history_walks_edits_suggestions_and_reviews_with_checkouts() {
    let alice = device(4).await;
    let bob = device(5).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(5, " world"))
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = bob
        .space(space.id())
        .await
        .unwrap()
        .document(document.id())
        .await
        .unwrap();
    let fork = bobs.read().await.unwrap().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").insert(11, "!").unwrap();
    fork.commit();
    let suggestion = bobs
        .suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    let open = document.history().await.unwrap();
    assert_eq!(open[2].kind, Kind::Suggestion(Standing::Open), "{open:?}");
    document.accept(&[suggestion]).await.unwrap();

    let history = document.history().await.unwrap();
    assert_eq!(history.len(), 4, "{history:?}");
    assert_eq!(history[0].kind, Kind::Edit);
    assert_eq!(history[1].kind, Kind::Edit);
    assert_eq!(history[2].kind, Kind::Suggestion(Standing::Accepted));
    assert_eq!(
        history[3].kind,
        Kind::Review {
            accepts: vec![suggestion],
            dismisses: Vec::new()
        }
    );
    assert_eq!(history[2].author.device, bob.id());
    assert!(history.iter().all(|c| c.effect == Effect::Applied));

    // Each edit's span, its containers, and a checkout before and after.
    let Detail::Document(Some(second)) = &history[1].detail else {
        panic!("{:?}", history[1].detail);
    };
    assert_eq!(second.span.to - second.span.from, 6, "' world'");
    assert_eq!(second.containers, vec!["cid:root-body:Text".to_string()]);
    let before = document.at(second.before.as_ref().unwrap()).await.unwrap();
    assert_eq!(before.get_text("body").to_string(), "hello");
    let after = document.at(&second.after).await.unwrap();
    assert_eq!(after.get_text("body").to_string(), "hello world");
    // A copy of its own: an edit to it reaches nothing.
    after.get_text("body").insert(0, "x").unwrap();
    after.commit();
    assert_eq!(document.text("body").await.unwrap(), "hello world!");
    let Detail::Document(Some(suggested)) = &history[2].detail else {
        panic!("{:?}", history[2].detail);
    };
    assert_eq!(
        document
            .at(&suggested.after)
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "hello world!"
    );
    assert_eq!(document.text("body").await.unwrap(), "hello world!");
    assert!(matches!(history[3].detail, Detail::Document(None)));
}

fn value(n: u64) -> Value {
    Value::from(n)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_table_history_names_rows_and_columns_and_a_replay_says_from_what() {
    let alice = device(6).await;
    let bob = device(7).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    let records = space.create_records().unwrap();
    records
        .write(|t| {
            t.insert("cues", b"c1")
                .set("cues", b"c1", "level", value(1));
        })
        .await
        .unwrap();
    records
        .write(|t| {
            t.set("cues", b"c1", "level", value(2))
                .set("cues", b"c1", "label", Value::from("go"));
        })
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = bob
        .space(space.id())
        .await
        .unwrap()
        .records(records.id())
        .await
        .unwrap();
    bobs.write(|t| {
        t.suggest().set("cues", b"c1", "level", value(3));
    })
    .await
    .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    let open = records.suggestions().await.unwrap();
    assert_eq!(open.len(), 1);
    let suggestion = open[0].id;
    records.accept(&[suggestion]).await.unwrap();

    let history = records.history().await.unwrap();
    assert_eq!(history.len(), 4, "{history:?}");
    let Detail::Records(first) = &history[0].detail else {
        panic!("{:?}", history[0].detail);
    };
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].table, "cues");
    assert_eq!(first[0].key, b"c1");
    assert!(first[0].inserted && !first[0].deleted);
    assert_eq!(first[0].columns, vec!["level".to_string()]);
    let Detail::Records(second) = &history[1].detail else {
        panic!("{:?}", history[1].detail);
    };
    assert!(!second[0].inserted);
    let mut columns = second[0].columns.clone();
    columns.sort();
    assert_eq!(columns, vec!["label".to_string(), "level".to_string()]);
    assert_eq!(history[2].kind, Kind::Suggestion(Standing::Accepted));
    assert_eq!(history[2].author.device, bob.id());
    assert_eq!(
        history[3].kind,
        Kind::Review {
            accepts: vec![suggestion],
            dismisses: Vec::new()
        }
    );
    // Each change carries the time its writer's wall clock claimed: the
    // snapshot excepted, which writes no changeset (adapter-records.md,
    // section 2.2).
    assert!(
        history
            .iter()
            .filter(|c| c.kind != Kind::Snapshot)
            .all(|c| c.time.is_some()),
        "every change claims a time"
    );
    assert!(history.iter().all(|c| c.effect == Effect::Applied));

    // From what: the row after each change.
    let level_at = |change: UnitId| {
        let records = records.clone();
        async move {
            records.at(change).await.unwrap()["cues"][&b"c1".to_vec()]
                .get("level")
                .cloned()
        }
    };
    assert_eq!(level_at(history[0].id).await, Some(value(1)));
    assert_eq!(level_at(history[1].id).await, Some(value(2)));
    assert_eq!(
        level_at(history[2].id).await,
        Some(value(2)),
        "a suggestion, open then"
    );
    assert_eq!(level_at(history[3].id).await, Some(value(3)), "accepted");
    assert_eq!(
        records.at(history[0].id).await.unwrap()["cues"][&b"c1".to_vec()].get("label"),
        None
    );
    assert!(
        records.at(UnitId::from_bytes([7; 32])).await.is_err(),
        "no such change"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lent_document_history_has_each_unit_before_and_time() {
    // One incarnation writes three units within Loro's merge window: each
    // change's version before is the one after the unit before it, and its
    // time is its own, at the writer and at a reader.
    let alice = device(51).await;
    let bob = device(52).await;
    let space = with_member(&alice, &bob, Level::Read).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    for (at, text) in [(0, "one "), (4, "two "), (8, "three")] {
        lent.doc().get_text("body").insert(at, text).unwrap();
        lent.doc().commit();
        lent.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = bob
        .space(space.id())
        .await
        .unwrap()
        .document(document.id())
        .await
        .unwrap();
    for (who, history) in [
        ("writer", document.history().await.unwrap()),
        ("reader", bobs.history().await.unwrap()),
    ] {
        assert_eq!(history.len(), 3, "{who}: {history:?}");
        let details: Vec<_> = history
            .iter()
            .map(|change| match &change.detail {
                Detail::Document(Some(detail)) => detail.clone(),
                other => panic!("{who}: {other:?}"),
            })
            .collect();
        assert!(
            details.iter().all(|d| d.span.peer == lent.peer_id()),
            "{who}: one peer"
        );
        for pair in details.windows(2) {
            assert_eq!(
                pair[1].before.as_ref(),
                Some(&pair[0].after),
                "{who}: before is the unit before's after"
            );
        }
        let times: Vec<u64> = history.iter().map(|c| c.time.expect("a time")).collect();
        assert!(
            times[0] < times[1] && times[1] < times[2],
            "{who}: each its own: {times:?}"
        );
        let before_third = document
            .at(details[2].before.as_ref().unwrap())
            .await
            .unwrap();
        assert_eq!(
            before_third.get_text("body").to_string(),
            "one two ",
            "{who}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_walks_a_delete_and_an_insert_again() {
    let alice = device(53).await;
    let space = alice.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    let mut seen = Vec::new();
    let steps: [&dyn Fn(&mut frasil::Transaction); 4] = [
        &|t| {
            t.insert("cues", b"c1")
                .set("cues", b"c1", "level", value(1));
        },
        &|t| {
            t.set("cues", b"c1", "label", Value::from("go"));
        },
        &|t| {
            t.delete("cues", b"c1");
        },
        &|t| {
            t.insert("cues", b"c1")
                .set("cues", b"c1", "level", value(2));
        },
    ];
    for step in steps {
        records.write(|t| step(t)).await.unwrap();
        seen.push(records.row("cues", b"c1").await.unwrap());
    }
    let history = records.history().await.unwrap();
    assert_eq!(history.len(), 4);
    assert!(
        history[2].detail
            == Detail::Records(vec![frasil::RowChange {
                table: "cues".into(),
                key: b"c1".to_vec(),
                columns: Vec::new(),
                inserted: false,
                deleted: true,
            }])
    );
    // The walk, one change at a time, reads each row as it was then.
    let mut replay = records.replay().await.unwrap();
    for (index, change) in history.iter().enumerate() {
        assert_eq!(replay.step(), Some(change.id));
        assert_eq!(
            replay.row("cues", b"c1"),
            seen[index],
            "after change {index}"
        );
        assert_eq!(
            records
                .at(change.id)
                .await
                .unwrap()
                .get("cues")
                .and_then(|rows| rows.get(&b"c1".to_vec()))
                .cloned(),
            seen[index],
            "at change {index}"
        );
    }
    assert_eq!(replay.step(), None);
    assert_eq!(seen[2], None, "deleted");
    assert!(seen[3].is_some(), "inserted again");
}

/// A device granted with history after a nearby join by code resolves the
/// space by plain ingest, through its person or directly. The join's
/// admission is a break, so the newcomer holds no state that opens the
/// genesis, which names the system stream; the genesis's body key is in a
/// `frasil:body-keys` unit of that stream (admission.md, "The newcomer's
/// snapshot"), which the replica takes before it knows the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_with_history_after_a_nearby_join_resolves() {
    async fn level(join_first: bool, person: bool) -> Option<Level> {
        let alice = device(61).await;
        let bob = device(62).await;
        let carol = device(63).await;
        let space = alice.create_space().await.unwrap();
        let id = event_of(&space);
        if join_first {
            let invitation = space
                .invite(Level::Write, "Alice's laptop", |_, _| async { true })
                .await
                .unwrap();
            let _bobs = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
                .await
                .unwrap();
            within(invitation.admitted()).await.unwrap();
        }
        if person {
            let carols_person = *carol.make_person(&[63; 32]).await.unwrap().as_bytes();
            alice
                .engine()
                .receive_list(carol.engine().list_events(&carols_person).await)
                .await
                .unwrap();
            alice
                .engine()
                .grant_person(
                    id,
                    carols_person,
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap();
            alice
                .engine()
                .publish_list(id, &carols_person)
                .await
                .unwrap();
        } else {
            alice
                .engine()
                .grant_device(
                    id,
                    carol.engine().public_keys().clone(),
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap();
        }
        carol.engine().follow(id).await;
        carry(alice.engine(), carol.engine(), id).await;
        carol
            .engine()
            .read(&id, |r| r.level_of(&carol.engine().device_id()))
            .await
            .unwrap()
    }
    for person in [true, false] {
        assert_eq!(level(false, person).await, Some(Level::Write), "{person}");
        assert_eq!(
            level(true, person).await,
            Some(Level::Write),
            "after a nearby join, {person}"
        );
    }
}

/// A device granted with history after a heal resolves the space by plain
/// ingest: its grant delivers the state after the heal, which links back to
/// the genesis's; the link is followed before the space resolves, since the
/// genesis does not open without it (keys.md, "Links").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_with_history_after_a_heal_resolves() {
    let alice = device(64).await;
    let carol = device(65).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    alice.engine().heal(id).await.unwrap();
    alice
        .engine()
        .grant_device(
            id,
            carol.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.engine().follow(id).await;
    carry(alice.engine(), carol.engine(), id).await;
    assert_eq!(
        carol
            .engine()
            .read(&id, |r| (
                r.level_of(&carol.engine().device_id()),
                r.unresolved()
            ))
            .await
            .unwrap(),
        (Some(Level::Write), None)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_merges_same_second_units_and_keeps_each_unit_before() {
    // Three units of one lent incarnation within a second: a reader's
    // Loro merges them into one change, and each unit's version before is
    // still the one after the unit before it.
    let alice = device(54).await;
    let bob = device(55).await;
    let space = with_member(&alice, &bob, Level::Read).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    for (at, text) in [(0, "one "), (4, "two "), (8, "three")] {
        lent.doc().get_text("body").insert(at, text).unwrap();
        // One second for all three, however slow the machine.
        lent.doc().set_next_commit_timestamp(1_800_000_000);
        lent.doc().commit();
        lent.flush().await.unwrap();
    }
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = bob
        .space(space.id())
        .await
        .unwrap()
        .document(document.id())
        .await
        .unwrap();
    let history = bobs.history().await.unwrap();
    assert_eq!(history.len(), 3, "{history:?}");
    let details: Vec<_> = history
        .iter()
        .map(|change| match &change.detail {
            Detail::Document(Some(detail)) => detail.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    let merged = bob
        .engine()
        .read(&id, |r| {
            frasil::advanced::documents::loro_state(r, document.id().as_bytes())
                .and_then(|state| {
                    state.doc().get_change(frasil::loro::ID::new(
                        details[1].span.peer,
                        details[1].span.from,
                    ))
                })
                .map(|change| change.id.counter < details[1].span.from)
        })
        .await
        .unwrap();
    assert_eq!(merged, Some(true), "the reader's Loro merged the units");
    for pair in details.windows(2) {
        assert_eq!(pair[1].before.as_ref(), Some(&pair[0].after));
    }
    let before_third = bobs.at(details[2].before.as_ref().unwrap()).await.unwrap();
    assert_eq!(before_third.get_text("body").to_string(), "one two ");
}
