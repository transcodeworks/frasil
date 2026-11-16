//! The client toolkit: undo that follows
//! Frasil across a replacement and keeps suggestions apart, undo for
//! tables by the previous value, named versions synced to every member,
//! and suggestions reviewed against their base.
#![cfg(all(feature = "adapter-loro", feature = "adapter-records"))]

use frasil::advanced::Engine;
use frasil::loro::{ExportMode, LoroValue};
use frasil::{
    Device, Error, Lent, Level, Marked, Options, Records, RecordsUndo, ReviewChange, Space,
    Storage, TextStep, Undo, Value,
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

async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
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

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    let events = from.events(&space).await;
    let ingested = to.ingest(space, events).await.expect("ingested");
    assert!(
        ingested.refused.is_empty(),
        "refused: {:?}",
        ingested.refused
    );
}

fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

fn body(doc: &frasil::loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

async fn grant(alice: &Device, space: &Space, device: &Device) {
    alice
        .engine()
        .grant_device(
            event_of(space),
            device.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
}

async fn with_member(alice: &Device, bob: &Device) -> Space {
    let space = alice.create_space().await.unwrap();
    grant(alice, &space, bob).await;
    bob.engine().follow(event_of(&space)).await;
    carry(alice.engine(), bob.engine(), event_of(&space)).await;
    space
}

async fn space_of(device: &Device, space: &Space) -> Space {
    device.space(space.id()).await.unwrap()
}

/// Alice's space with a document; Bob and Carol write; Bob's unit over
/// Alice's text reached Carol, not Alice.
struct BobsUnitAtCarol {
    alice: Device,
    bob: Device,
    carol: Device,
    space: Space,
    document: frasil::Document,
    bobs: Lent,
}

async fn bobs_unit_at_carol(keys: [u8; 3]) -> BobsUnitAtCarol {
    let alice = device(keys[0]).await;
    let bob = device(keys[1]).await;
    let carol = device(keys[2]).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    grant(&alice, &space, &carol).await;
    carol.engine().follow(id).await;
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "base ").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    drop(alices);
    for engine in [bob.engine(), carol.engine()] {
        carry(alice.engine(), engine, id).await;
    }
    let bobs_doc = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let bobs = bobs_doc.lend().await.unwrap();
    bobs.doc().get_text("body").insert(5, "bob ").unwrap();
    bobs.doc().commit();
    bobs.flush().await.unwrap();
    carry(bob.engine(), carol.engine(), id).await;
    BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undo_follows_a_replacement_and_a_renewal_without_rebinding() {
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs,
    } = bobs_unit_at_carol([1, 2, 3]).await;
    let id = event_of(&space);

    // Carol's undo, bound once.
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let undo = Undo::new(&lent);
    lent.doc().get_text("body").insert(0, "carol ").unwrap();
    lent.doc().commit();
    assert!(undo.can_undo());
    assert!(undo.undo().unwrap());
    assert_eq!(body(&lent.doc()), "base bob ");
    assert!(undo.redo().unwrap());
    assert_eq!(body(&lent.doc()), "carol base bob ");

    // Bob's unit withdrawn at Carol: the document is replaced, her
    // pending edit carried over, and the same `Undo` undoes what she
    // writes after, without a rebind.
    let generation = undo.generation();
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(lent.generation(), generation);
    assert_eq!(body(&lent.doc()), "carol base ");
    let doc = lent.doc();
    doc.get_text("body").insert(0, "after ").unwrap();
    doc.commit();
    assert_eq!(
        undo.generation(),
        lent.generation(),
        "bound to the new document"
    );
    assert!(undo.can_undo());
    assert!(undo.undo().unwrap());
    assert_eq!(body(&lent.doc()), "carol base ");
    assert!(!undo.can_undo(), "the old stack does not carry over");

    // Bob's own handle: his unit withdrawn and his incarnation renewed;
    // his `Undo` goes on under the new peer.
    let bobs_undo = Undo::new(&bobs);
    let mut bobs_replaced = bobs.replaced();
    grant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    within(bobs_replaced.changed()).await.unwrap();
    assert_eq!(body(&bobs.doc()), "base bob ", "expressed again");
    bobs.doc().get_text("body").insert(0, "renewed ").unwrap();
    bobs.doc().commit();
    assert!(bobs_undo.undo().unwrap());
    assert_eq!(body(&bobs.doc()), "base bob ");
    bobs.flush().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undo_used_while_a_replacement_binds_stays_on_the_new_document() {
    // A hook runs after the undo's own, in the window where the new
    // document is bound but the handle still names the old one: an undo
    // used there neither binds back to the old document nor takes the old
    // generation.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([30, 31, 32]).await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let undo = Undo::new(&lent);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (probe, record) = (undo.clone(), seen.clone());
    lent.on_replaced(move |_, generation| {
        let _ = probe.can_undo();
        record
            .lock()
            .unwrap()
            .push((generation, probe.generation()));
    });
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.is_empty());
    for (generation, bound) in seen {
        assert_eq!(bound, generation, "bound to the new document in the window");
    }
    assert_eq!(undo.generation(), lent.generation());
    let doc = lent.doc();
    doc.get_text("body").insert(0, "after ").unwrap();
    doc.commit();
    assert!(undo.can_undo(), "the manager follows the new document");
    assert!(undo.undo().unwrap());
    assert_eq!(body(&lent.doc()), "base ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commit_under_an_excluded_origin_never_enters_the_stack() {
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([33, 34, 35]).await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let mut undo = Undo::new(&lent);
    undo.exclude_origin_prefix("sync:");
    let excluded = |doc: &frasil::loro::LoroDoc, text: &str| {
        doc.set_next_commit_origin("sync:calendar");
        doc.get_text("body").insert(0, text).unwrap();
        doc.commit();
    };
    excluded(&lent.doc(), "synced ");
    assert!(!undo.can_undo(), "an excluded origin");
    lent.doc().get_text("body").insert(0, "own ").unwrap();
    lent.doc().commit();
    assert_eq!(undo.undo_count(), 1);

    // After a replacement, the new manager leaves the origin out too.
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_eq!(undo.generation(), lent.generation());
    excluded(&lent.doc(), "again ");
    assert!(
        !undo.can_undo(),
        "an excluded origin, after the replacement"
    );
    lent.doc().get_text("body").insert(0, "mine ").unwrap();
    lent.doc().commit();
    assert_eq!(undo.undo_count(), 1);
    assert!(undo.undo().unwrap());
    assert!(
        body(&lent.doc()).starts_with("again "),
        "{}",
        body(&lent.doc())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undo_keeps_suggestions_apart() {
    let alice = device(4).await;
    let bob = device(5).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    let undo = Undo::new(&lent);
    lent.doc().get_text("body").insert(0, "hello").unwrap();
    lent.doc().commit();
    lent.flush().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;

    // Bob suggests; Alice accepts: the accepted text is not hers to undo.
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let fork = bobs.read().await.unwrap().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").insert(5, "!").unwrap();
    fork.commit();
    let suggestion = bobs
        .suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(body(&lent.doc()), "hello", "a suggestion stays apart");
    document.accept(&[suggestion]).await.unwrap();
    until(|| async { body(&lent.doc()) == "hello!" }).await;
    assert!(undo.undo().unwrap(), "her own edit");
    assert_eq!(body(&lent.doc()), "!", "the accepted text stays");
    assert!(!undo.can_undo());
    // Her own suggestion, made on a fork, is not in her stack either.
    let fork = lent.doc().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").insert(0, "?").unwrap();
    fork.commit();
    lent.suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    assert!(!undo.can_undo());
    assert_eq!(body(&lent.doc()), "!");
}

fn n(value: u64) -> Value {
    Value::from(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_undo_writes_the_previous_value() {
    let alice = device(6).await;
    let bob = device(7).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let records = space.create_records().unwrap();
    let undo = RecordsUndo::new(&records);
    undo.write(|t| {
        t.insert("cues", b"c1").set("cues", b"c1", "level", n(1));
    })
    .await
    .unwrap();
    undo.write(|t| {
        t.set("cues", b"c1", "level", n(2))
            .set("cues", b"c1", "label", Value::from("go"));
    })
    .await
    .unwrap();
    let level = |records: Records| async move {
        records
            .row("cues", b"c1")
            .await
            .unwrap()
            .map(|row| (row.get("level").cloned(), row.get("label").cloned()))
    };
    assert_eq!(
        level(records.clone()).await,
        Some((Some(n(2)), Some(Value::from("go"))))
    );
    assert!(undo.undo().await.unwrap());
    assert_eq!(
        level(records.clone()).await,
        Some((Some(n(1)), None)),
        "the previous values"
    );
    assert!(undo.undo().await.unwrap());
    assert_eq!(level(records.clone()).await, None, "the row is gone");
    assert!(!undo.can_undo());
    assert!(undo.redo().await.unwrap());
    assert_eq!(level(records.clone()).await, Some((Some(n(1)), None)));
    assert!(undo.redo().await.unwrap());
    assert_eq!(
        level(records.clone()).await,
        Some((Some(n(2)), Some(Value::from("go"))))
    );
    // Every step was a change of Alice's, which Bob reads.
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = space_of(&bob, &space)
        .await
        .records(records.id())
        .await
        .unwrap();
    assert_eq!(
        level(bobs).await,
        Some((Some(n(2)), Some(Value::from("go"))))
    );
    assert_eq!(records.history().await.unwrap().len(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_version_is_synced_and_reads_back() {
    let alice = device(8).await;
    let bob = device(9).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "first"))
        .await
        .unwrap();
    let first = document.tag("first draft").await.unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(5, " second"))
        .await
        .unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|t| {
            t.insert("cues", b"c1").set("cues", b"c1", "level", n(1));
        })
        .await
        .unwrap();
    let cues = records.tag("cues v1").await.unwrap();
    records
        .write(|t| {
            t.set("cues", b"c1", "level", n(2));
        })
        .await
        .unwrap();
    assert!(matches!(document.tag("").await, Err(Error::Invalid(_))));

    // Bob reads the tags and what they mark.
    carry(alice.engine(), bob.engine(), id).await;
    let bobs_space = space_of(&bob, &space).await;
    let versions = bobs_space.versions().await.unwrap();
    assert_eq!(versions.len(), 2, "{versions:?}");
    let bobs_doc = bobs_space.document(document.id()).await.unwrap();
    let doc_versions = bobs_doc.versions().await.unwrap();
    assert_eq!(doc_versions, vec![first.clone()]);
    assert_eq!(first.name, "first draft");
    assert_eq!(first.author, alice.id());
    let Marked::Document(frontier) = &first.marked else {
        panic!("{first:?}");
    };
    assert_eq!(
        body(&bobs_doc.at(frontier).await.unwrap()),
        "first",
        "the version reads back"
    );
    assert_eq!(bobs_doc.text("body").await.unwrap(), "first second");
    let bobs_records = bobs_space.records(records.id()).await.unwrap();
    assert_eq!(bobs_records.versions().await.unwrap(), vec![cues.clone()]);
    let Marked::Records(change) = &cues.marked else {
        panic!("{cues:?}");
    };
    let then = bobs_records.at(*change).await.unwrap();
    assert_eq!(then["cues"][&b"c1".to_vec()]["level"], n(1));
    assert_eq!(
        space.versions_stream(),
        bobs_space.versions_stream(),
        "derived from the space"
    );
    assert!(
        space
            .streams()
            .await
            .unwrap()
            .iter()
            .any(|s| s.id == space.versions_stream()),
        "a Records stream of the space"
    );

    // A tag removed is gone for everyone.
    space.untag(first.id).await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    assert_eq!(bobs_space.versions().await.unwrap(), vec![cues]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suggestion_reviews_against_its_base_on_documents_and_tables() {
    let alice = device(10).await;
    let bob = device(11).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| {
            doc.get_text("body").insert(0, "hello world")?;
            doc.get_map("meta").insert("title", "draft")?;
            doc.get_list("tags").insert(0, "a")
        })
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;

    // Bob suggests on a fork; Alice reviews: the text delta, the map
    // key's values before and after, the list's items; then accepts.
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let fork = bobs.read().await.unwrap().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").delete(0, 5).unwrap();
    fork.get_text("body").insert(0, "goodbye").unwrap();
    fork.get_map("meta").insert("title", "final").unwrap();
    fork.get_list("tags").push("b").unwrap();
    fork.commit();
    let suggestion = bobs
        .suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    let review = document.review(suggestion).await.unwrap();
    assert_eq!(review.id, suggestion);
    assert_eq!(review.author, bob.id());
    assert!(review.base.is_some(), "the base is held");
    assert_eq!(
        body(&document.at(review.base.as_ref().unwrap()).await.unwrap()),
        "hello world"
    );
    let text = review
        .changes
        .iter()
        .find_map(|c| match c {
            ReviewChange::Text { container, delta } if container.contains("body") => Some(delta),
            _ => None,
        })
        .expect("the text change");
    assert!(
        text.contains(&TextStep::Insert("goodbye".into())),
        "{text:?}"
    );
    assert!(text.contains(&TextStep::Delete(5)), "{text:?}");
    let title = review
        .changes
        .iter()
        .find_map(|c| match c {
            ReviewChange::Map { key, from, to, .. } if key == "title" => Some((from, to)),
            _ => None,
        })
        .expect("the map change");
    assert_eq!(title.0.clone(), Some(LoroValue::from("draft")));
    assert_eq!(title.1.clone(), Some(LoroValue::from("final")));
    let tags = review
        .changes
        .iter()
        .find_map(|c| match c {
            ReviewChange::List { from, to, .. } => Some((from.len(), to.len())),
            _ => None,
        })
        .expect("the list change");
    assert_eq!(tags, (1, 2));
    assert_eq!(
        document.text("body").await.unwrap(),
        "hello world",
        "not touched"
    );
    document.accept(&[suggestion]).await.unwrap();
    assert_eq!(document.text("body").await.unwrap(), "goodbye world");
    assert!(matches!(
        document.review(suggestion).await,
        Err(Error::Invalid(_))
    ));

    // Tables: the cell's value now and the one suggested; then dismissed.
    let records = space.create_records().unwrap();
    records
        .write(|t| {
            t.insert("cues", b"c1").set("cues", b"c1", "level", n(1));
        })
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs_records = space_of(&bob, &space)
        .await
        .records(records.id())
        .await
        .unwrap();
    bobs_records
        .write(|t| {
            t.suggest().set("cues", b"c1", "level", n(3)).set(
                "cues",
                b"c1",
                "label",
                Value::from("go"),
            );
        })
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    let open = records.suggestions().await.unwrap();
    assert_eq!(open.len(), 1);
    let review = records.review(open[0].id).await.unwrap();
    assert_eq!(review.author, bob.id());
    assert_eq!(review.base, None);
    let mut cells: Vec<(String, Option<Value>, Option<Value>)> = review
        .changes
        .iter()
        .filter_map(|c| match c {
            ReviewChange::Cell {
                column, from, to, ..
            } => Some((column.clone(), from.clone(), to.clone())),
            _ => None,
        })
        .collect();
    cells.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        cells,
        vec![
            ("label".to_string(), None, Some(Value::from("go"))),
            ("level".to_string(), Some(n(1)), Some(n(3))),
        ]
    );
    records.dismiss(&[open[0].id]).await.unwrap();
    assert!(records.suggestions().await.unwrap().is_empty());
    assert_eq!(
        records
            .row("cues", b"c1")
            .await
            .unwrap()
            .unwrap()
            .get("level"),
        Some(&n(1))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_review_whose_base_is_missing_says_so() {
    // Bob suggests on his lent document before its window wrote his own
    // edit as a unit: Alice holds the suggestion, not what it was made on.
    // Its review is flagged, with no changes, rather than empty with no
    // signal.
    let alice = device(42).await;
    let bob = device(43).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = bobs.lend().await.unwrap();
    lent.doc().get_text("body").insert(5, " unseen").unwrap();
    lent.doc().commit();
    let fork = lent.doc().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").insert(0, "say ").unwrap();
    fork.commit();
    let suggestion = bobs
        .suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(
        document.text("body").await.unwrap(),
        "hello",
        "Bob's edit is not in a unit yet"
    );
    let review = document.review(suggestion).await.unwrap();
    assert!(review.base_missing, "{review:?}");
    assert!(review.base.is_none());
    assert!(review.changes.is_empty());
}

#[cfg(feature = "partial-replicas")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_replica_holds_the_versions_stream() {
    // Bob holds only what he opens: asking for the versions holds their
    // stream, and the tags arrive with the next changes he receives.
    let alice = device(40).await;
    let bob = Device::open_with(
        Storage::Memory,
        &[41; 32],
        Options::new().loopback().never_restored().partial(),
    )
    .await
    .unwrap();
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "first"))
        .await
        .unwrap();
    let first = document.tag("first draft").await.unwrap();
    let bobs_space = space_of(&bob, &space).await;
    let _ = bobs_space.versions().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    assert_eq!(bobs_space.versions().await.unwrap(), vec![first]);
}

/// A live document follows changes that arrive from another device with
/// only the adapters built in: its follower runs on the device's tasks,
/// without a binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_document_follows_arriving_changes_without_a_binding() {
    let alice = device(91).await;
    let bob = device(92).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "first").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;

    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap()
        .live()
        .await
        .unwrap();
    let mut changes = bobs.changes();
    alices.doc().get_text("body").insert(5, " second").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;

    let update = within(changes.next()).await.expect("an update");
    let mirror = frasil::loro::LoroDoc::new();
    mirror.import(&bobs.export_since(&[]).unwrap()).unwrap();
    mirror.import(&update).unwrap();
    assert_eq!(body(&mirror), "first second");
}
