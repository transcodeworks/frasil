//! Setting a document's text: a comparison off the engine, within a limit,
//! written as small edits, as one replacement, or across several units.
#![cfg(all(feature = "adapter-loro", feature = "sqlite"))]

#[path = "support/scripts.rs"]
mod scripts;

use frasil::advanced::documents::{Comparison, apply_splices, compare_text};
use frasil::loro::{Container, ContainerTrait, LoroDoc, LoroText, ValueOrContainer};
use frasil::{
    Device, Document, Effect, Error, Level, Options, SetText, Space, Storage, TextOutcome,
    TextStyle,
};
use frasil_events::{EventId, kind};
use frasil_space::{HistoryMode, Via};
use scripts::{Kind, crlf, one_word, reflow, script};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const LONG: Duration = Duration::from_secs(60);

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
async fn carry(from: &Device, to: &Device, space: EventId) {
    let events = from.engine().events(&space).await;
    let ingested = to.engine().ingest(space, events).await.expect("ingested");
    assert!(
        ingested.refused.is_empty(),
        "refused: {:?}",
        ingested.refused
    );
}

/// Alice's space, with Bob a writer and holding every event.
async fn with_member(alice: &Device, bob: &Device) -> Space {
    let space = alice.create_space().await.unwrap();
    alice
        .engine()
        .grant_device(
            event_of(&space),
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(event_of(&space)).await;
    carry(alice, bob, event_of(&space)).await;
    space
}

/// The units of the space `device` holds, in the order it holds them.
async fn units(device: &Device, space: EventId) -> Vec<Vec<u8>> {
    device
        .engine()
        .events(&space)
        .await
        .into_iter()
        .filter(|signed| frasil_events::decode(signed).is_ok_and(|e| e.kind() == kind::UNIT))
        .collect()
}

/// A document of `device`, holding `text`.
async fn document_with(space: &Space, text: &str) -> Document {
    let document = space.create_document().unwrap();
    document
        .set_text("body", text, SetText::default().limit(LONG))
        .await
        .unwrap();
    document
}

/// The engine's call, with a comparison that waits for a word from the
/// test: what a slow diff looks like to the rest of the device.
async fn set_text_when_told(
    document: &Document,
    text: &str,
    go: mpsc::Receiver<()>,
    started: mpsc::Sender<()>,
) -> frasil::Result<frasil::TextWritten> {
    let new = text.to_owned();
    let engine = document.space().device().engine();
    let opening = engine
        .read(&event_of(document.space()), |replica| {
            replica.opening_of(document.id().as_bytes())
        })
        .await
        .unwrap()
        .expect("the document has a change");
    engine
        .write_document_text(
            event_of(document.space()),
            &opening,
            "body",
            move |current| -> frasil::Result<Comparison> {
                started.send(()).unwrap();
                go.recv().unwrap();
                compare_text(&current, &new, LONG).map_err(|_| Error::LimitPassed)
            },
        )
        .await
}

#[tokio::test]
async fn a_small_change_writes_a_small_unit() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let text = script(Kind::Play, 200_000, 1);
    let document = document_with(&space, &text).await;
    let before = units(&alice, event_of(&space)).await.len();

    let target = one_word(&text);
    let written = document
        .set_text("body", &target, SetText::default())
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Edited);
    assert_eq!(written.units, 1);
    assert!(!written.moved);
    assert_eq!(document.text("body").await.unwrap(), target);
    let all = units(&alice, event_of(&space)).await;
    assert_eq!(all.len(), before + 1);
    assert!(
        all[before].len() < 2048,
        "a one-word unit is small: {} bytes",
        all[before].len()
    );
}

#[tokio::test]
async fn the_same_text_writes_nothing() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = document_with(&space, "one\ntwo\n").await;
    let before = units(&alice, event_of(&space)).await.len();

    let written = document
        .set_text("body", "one\ntwo\n", SetText::default())
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Unchanged);
    assert_eq!(written.units, 0);
    assert_eq!(units(&alice, event_of(&space)).await.len(), before);
}

#[tokio::test]
async fn a_line_ending_flip_folded_is_no_change() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let text = script(Kind::Prose, 20_000, 2);
    let document = document_with(&space, &text).await;
    let before = units(&alice, event_of(&space)).await.len();

    let file = format!("\u{feff}{}", crlf(&text));
    let (folded, style) = TextStyle::fold(&file);
    let written = document
        .set_text("body", &folded, SetText::default())
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Unchanged);
    assert_eq!(units(&alice, event_of(&space)).await.len(), before);
    assert_eq!(style.restore(&document.text("body").await.unwrap()), file);
}

#[tokio::test]
async fn a_timeout_leaves_the_document_exactly_as_it_was() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let text = script(Kind::Worst, 20_000, 3);
    let document = document_with(&space, &text).await;
    let version = document.read().await.unwrap().oplog_frontiers();
    let before = alice.engine().events(&event_of(&space)).await;

    let rewrite = script(Kind::Worst, 20_000, 4);
    let stopped = document
        .set_text(
            "body",
            &rewrite,
            SetText::default().limit(Duration::ZERO).stop_at_limit(),
        )
        .await;
    assert_eq!(stopped, Err(Error::LimitPassed));
    assert_eq!(document.text("body").await.unwrap(), text);
    assert_eq!(document.read().await.unwrap().oplog_frontiers(), version);
    assert_eq!(alice.engine().events(&event_of(&space)).await, before);

    // The next write goes on as if nothing happened.
    let target = one_word(&text);
    document
        .set_text("body", &target, SetText::default())
        .await
        .unwrap();
    assert_eq!(document.text("body").await.unwrap(), target);
}

#[tokio::test]
async fn past_the_limit_the_text_is_replaced_in_one_operation() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = document_with(&space, &script(Kind::Worst, 20_000, 5)).await;

    let rewrite = script(Kind::Worst, 20_000, 6);
    let written = document
        .set_text("body", &rewrite, SetText::default().limit(Duration::ZERO))
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Replaced);
    assert!(written.limit_passed);
    assert_eq!(document.text("body").await.unwrap(), rewrite);
}

#[tokio::test]
async fn a_whole_rewrite_is_replaced_without_waiting_for_the_limit() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = document_with(&space, &script(Kind::Worst, 60_000, 7)).await;

    let rewrite = script(Kind::Worst, 60_000, 8);
    let started = Instant::now();
    let written = document
        .set_text("body", &rewrite, SetText::default().limit(LONG))
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Replaced);
    assert!(!written.limit_passed);
    assert_eq!(document.text("body").await.unwrap(), rewrite);
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[tokio::test]
async fn the_device_answers_while_a_comparison_runs() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = document_with(&space, "one\ntwo\n").await;
    let other = document_with(&space, "elsewhere\n").await;

    let (go, wait) = mpsc::channel();
    let (tell, started) = mpsc::channel();
    let setting = {
        let document = document.clone();
        tokio::spawn(async move { set_text_when_told(&document, "one\nthree\n", wait, tell).await })
    };
    tokio::task::spawn_blocking(move || started.recv().unwrap())
        .await
        .unwrap();

    // The comparison is running, and waits on this test: everything below
    // would hang here if it held the engine.
    tokio::time::timeout(Duration::from_secs(10), async {
        assert_eq!(document.text("body").await.unwrap(), "one\ntwo\n");
        other
            .edit(|doc| doc.get_text("body").insert(0, "still "))
            .await
            .unwrap();
        assert_eq!(other.text("body").await.unwrap(), "still elsewhere\n");
        alice.create_space().await.unwrap();
    })
    .await
    .expect("the device stayed responsive during the comparison");

    go.send(()).unwrap();
    let written = setting.await.unwrap().unwrap();
    assert_eq!(written.outcome, TextOutcome::Edited);
    assert!(!written.moved, "another document's change does not move it");
    assert_eq!(document.text("body").await.unwrap(), "one\nthree\n");
}

/// Sets the text to `target` while `during` changes the document under the
/// comparison, and returns what it reported.
async fn with_change_during(
    document: &Document,
    target: &str,
    during: impl AsyncFnOnce(),
) -> frasil::TextWritten {
    let (go, wait) = mpsc::channel();
    let (tell, started) = mpsc::channel();
    let setting = {
        let document = document.clone();
        let target = target.to_owned();
        tokio::spawn(async move { set_text_when_told(&document, &target, wait, tell).await })
    };
    tokio::task::spawn_blocking(move || started.recv().unwrap())
        .await
        .unwrap();
    during().await;
    go.send(()).unwrap();
    setting.await.unwrap().unwrap()
}

#[tokio::test]
async fn a_change_during_the_comparison_is_kept_and_merged() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let text = "first line\nsecond line\nthird line\n";
    let document = document_with(&space, text).await;
    carry(&alice, &bob, id).await;

    // Bob's edit reaches Alice while her comparison runs.
    let written = with_change_during(
        &document,
        "first line\nsecond line\nthird words\n",
        async || {
            let theirs = bob
                .space(space.id())
                .await
                .unwrap()
                .document(document.id())
                .await
                .unwrap();
            theirs
                .set_text(
                    "body",
                    "first edited line\nsecond line\nthird line\n",
                    SetText::default(),
                )
                .await
                .unwrap();
            carry(&bob, &alice, id).await;
        },
    )
    .await;

    assert!(written.moved);
    let merged = "first edited line\nsecond line\nthird words\n";
    assert_eq!(document.text("body").await.unwrap(), merged);
    carry(&alice, &bob, id).await;
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();
    assert_eq!(theirs.text("body").await.unwrap(), merged, "both replicas");
}

#[tokio::test]
async fn edits_within_one_line_merge() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let document = document_with(&space, "Nothing to be done.\n").await;
    carry(&alice, &bob, id).await;
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();

    document
        .set_text("body", "Nothing at all to be done.\n", SetText::default())
        .await
        .unwrap();
    theirs
        .set_text("body", "Nothing to be done, truly.\n", SetText::default())
        .await
        .unwrap();
    carry(&bob, &alice, id).await;
    carry(&alice, &bob, id).await;
    let merged = "Nothing at all to be done, truly.\n";
    assert_eq!(document.text("body").await.unwrap(), merged);
    assert_eq!(theirs.text("body").await.unwrap(), merged);
}

/// Code, edited in three places: the middle line is aligned as a run of
/// its own, indent and line end included. Its edit is one word, so Bob's
/// comment typed before its line end stays on it.
#[tokio::test]
async fn an_edit_within_an_indented_line_merges_in_place() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let old = "fn first() {\n    let a = 1;\n    return x;\n}\nfn second() {\n    return z;\n}\n";
    let document = document_with(&space, old).await;
    carry(&alice, &bob, id).await;
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();

    let new = "fn one() {\n    let a = 1;\n    return y;\n}\nfn second() {\n    return w;\n}\n";
    let written = document
        .set_text("body", new, SetText::default())
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Edited);
    theirs
        .set_text(
            "body",
            &old.replace("return x;", "return x; // why"),
            SetText::default(),
        )
        .await
        .unwrap();
    carry(&bob, &alice, id).await;
    carry(&alice, &bob, id).await;
    let merged = new.replace("return y;", "return y; // why");
    assert_eq!(document.text("body").await.unwrap(), merged);
    assert_eq!(theirs.text("body").await.unwrap(), merged);
}

#[tokio::test]
async fn a_replacement_keeps_a_change_made_during_it() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let text = script(Kind::Worst, 20_000, 9);
    let document = document_with(&space, &text).await;

    let rewrite = script(Kind::Prose, 20_000, 10);
    let written = with_change_during(&document, &rewrite, async || {
        document
            .edit(|doc| doc.get_text("body").insert(100, "KEPT"))
            .await
            .unwrap();
    })
    .await;
    assert!(written.moved);
    assert_eq!(written.outcome, TextOutcome::Replaced);
    let merged = document.text("body").await.unwrap();
    assert!(
        merged.contains("KEPT"),
        "the other change is not overwritten"
    );
    assert_eq!(merged.replace("KEPT", ""), rewrite);
}

/// Two distant versions of a text, the second too large for one unit.
fn large_pair() -> (String, String) {
    (
        script(Kind::Prose, 200_000, 11),
        script(Kind::Prose, 1_200_000, 12),
    )
}

/// What the large tests write with: past the limit at once, since the
/// comparison is not what they test.
fn at_once() -> SetText {
    SetText::default().limit(Duration::ZERO)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_over_the_unit_limit_goes_in_several_units() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let (old, new) = large_pair();
    let document = document_with(&space, &old).await;
    carry(&alice, &bob, id).await;
    let before = units(&alice, id).await.len();

    let written = document.set_text("body", &new, at_once()).await.unwrap();
    assert!(written.units >= 3, "took {} units", written.units);
    assert_eq!(document.text("body").await.unwrap(), new);

    let all = units(&alice, id).await;
    assert_eq!(all.len(), before + written.units);
    assert!(all.iter().all(|unit| unit.len() <= 1_048_576));

    let changes = document.history().await.unwrap();
    assert!(
        changes
            .iter()
            .all(|change| change.effect == Effect::Applied)
    );

    carry(&alice, &bob, id).await;
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();
    assert_eq!(theirs.text("body").await.unwrap(), new);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replica_with_some_units_keeps_the_old_text() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let (old, new) = large_pair();
    let document = document_with(&space, &old).await;
    carry(&alice, &bob, id).await;
    let before = alice.engine().events(&id).await.len();

    let written = document.set_text("body", &new, at_once()).await.unwrap();
    let events = alice.engine().events(&id).await;
    assert_eq!(events.len(), before + written.units);
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();

    // Unit by unit, Bob holds the old text whole until the last one.
    for arrived in &events[before..events.len() - 1] {
        let ingested = bob
            .engine()
            .ingest(id, vec![arrived.clone()])
            .await
            .unwrap();
        assert!(ingested.refused.is_empty());
        assert_eq!(theirs.text("body").await.unwrap(), old);
    }

    // Bob's own edit in that window merges with the rewrite once it lands.
    let edit = format!("{}\nBob's line.\n", old.trim_end());
    theirs
        .set_text("body", &edit, SetText::default())
        .await
        .unwrap();

    let last = events[events.len() - 1].clone();
    assert!(
        bob.engine()
            .ingest(id, vec![last])
            .await
            .unwrap()
            .refused
            .is_empty()
    );
    let merged = theirs.text("body").await.unwrap();
    assert!(merged.contains("Bob's line."));
    assert_eq!(merged.replace("\nBob's line.\n", ""), new.trim_end());
    carry(&bob, &alice, id).await;
    assert_eq!(
        document.text("body").await.unwrap(),
        merged,
        "both replicas"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_that_stops_part_way_leaves_the_old_text() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let (old, new) = large_pair();
    let document = document_with(&space, &old).await;
    carry(&alice, &bob, id).await;
    let before = alice.engine().events(&id).await.len();
    document.set_text("body", &new, at_once()).await.unwrap();
    let events = alice.engine().events(&id).await;

    // All but the last unit reach Bob, and the last is never written, as
    // far as Bob can tell. His document stays whole, and goes on.
    let some = events[before..events.len() - 1].to_vec();
    assert!(
        bob.engine()
            .ingest(id, some)
            .await
            .unwrap()
            .refused
            .is_empty()
    );
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();
    let edit = one_word(&old);
    theirs
        .set_text("body", &edit, SetText::default())
        .await
        .unwrap();
    assert_eq!(theirs.text("body").await.unwrap(), edit);
}

/// A store whose disk fills once armed: the first large commit after it,
/// a unit's, is made, and every large one after that fails.
#[derive(Default)]
struct FillingStore {
    inner: frasil_store::MemoryStore,
    armed: AtomicBool,
    made: AtomicUsize,
}

impl frasil_store::Store for FillingStore {
    fn get<'a>(
        &'a self,
        address: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Option<Vec<u8>>, frasil_store::StoreError>> {
        self.inner.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Vec<(Vec<u8>, Vec<u8>)>, frasil_store::StoreError>>
    {
        self.inner.scan(prefix)
    }

    fn commit<'a>(
        &'a self,
        commit: &'a frasil_store::Commit,
    ) -> frasil_store::BoxFuture<'a, Result<bool, frasil_store::StoreError>> {
        let size: usize = commit.puts.iter().map(|(_, record)| record.len()).sum();
        if self.armed.load(Ordering::SeqCst)
            && size > 32 * 1024
            && self.made.fetch_add(1, Ordering::SeqCst) > 0
        {
            return Box::pin(async { Err(frasil_store::StoreError::new("the disk is full")) });
        }
        self.inner.commit(commit)
    }
}

/// The `seq`s of the units `device` signed in the space, in order.
async fn own_seqs(device: &Device, space: EventId) -> Vec<u64> {
    let me = device.engine().device_id();
    let mut seqs: Vec<u64> = units(device, space)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|event| *event.author() == me)
        .map(|event| event.seq())
        .collect();
    seqs.sort_unstable();
    seqs
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_whose_store_fails_part_way_writes_again_after() {
    use frasil::advanced::{AdapterRegistry, Engine, MemorySlot, Platform};
    let store = Arc::new(FillingStore::default());
    let (engine, _) = Engine::create(
        Platform::new(store.clone(), Arc::new(MemorySlot::new())),
        &[1; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    let alice = Device::from_engine(engine, Options::new().loopback()).unwrap();
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let (old, new) = large_pair();
    let document = document_with(&space, &old).await;
    carry(&alice, &bob, id).await;
    let before = own_seqs(&alice, id).await;

    // The disk fills part way through the change: the call fails, with
    // the units before written, signed and on their way.
    store.armed.store(true, Ordering::SeqCst);
    let failed = document.set_text("body", &new, at_once()).await;
    assert!(matches!(failed, Err(Error::Store(_))), "{failed:?}");
    let stranded = own_seqs(&alice, id).await;
    assert!(stranded.len() > before.len(), "some units written");
    assert_eq!(document.text("body").await.unwrap(), old);

    // Space again: the next change goes on from the next `seq`, and both
    // replicas end with it. It is one unit with more operations than the
    // stranded units wait on: under the peer they wait on, it would
    // release them over text they were not made on.
    store.armed.store(false, Ordering::SeqCst);
    let again = script(Kind::Play, 30_000, 14);
    let written = document.set_text("body", &again, at_once()).await.unwrap();
    assert_eq!(written.units, 1);
    let after = own_seqs(&alice, id).await;
    assert_eq!(after[stranded.len()], stranded[stranded.len() - 1] + 1);
    assert_eq!(after.len(), stranded.len() + written.units);
    assert_eq!(document.text("body").await.unwrap(), again);
    carry(&alice, &bob, id).await;
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();
    assert_eq!(theirs.text("body").await.unwrap(), again);

    // And an edit after it, under the next peer, leaves the stranded
    // unit waiting.
    document
        .edit(|doc| doc.get_text("body").insert(0, "Top. "))
        .await
        .unwrap();
    carry(&alice, &bob, id).await;
    let top = format!("Top. {again}");
    assert_eq!(document.text("body").await.unwrap(), top);
    assert_eq!(theirs.text("body").await.unwrap(), top);
}

/// Live handles holding every incarnation a change could begin: the call
/// says so, and writes nothing.
#[tokio::test]
async fn no_free_incarnation_is_said_and_writes_nothing() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    let document = document_with(&space, "one\n").await;
    let engine = alice.engine();
    let opening = engine
        .read(&id, |replica| replica.opening_of(document.id().as_bytes()))
        .await
        .unwrap()
        .expect("the document has a change");
    while engine.begin_live(id, &opening).await.is_ok() {}
    let before = units(&alice, id).await.len();
    let refused = document.set_text("body", "two\n", SetText::default()).await;
    assert!(matches!(refused, Err(Error::NotAllowed(_))), "{refused:?}");
    assert_eq!(units(&alice, id).await.len(), before);
    assert_eq!(document.text("body").await.unwrap(), "one\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compaction_with_some_units_loses_none_of_them() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob).await;
    let id = event_of(&space);
    let (old, new) = large_pair();
    let document = document_with(&space, &old).await;
    carry(&alice, &bob, id).await;
    let before = alice.engine().events(&id).await.len();
    document.set_text("body", &new, at_once()).await.unwrap();
    let events = alice.engine().events(&id).await;

    let last = events.len() - 1;
    assert!(
        bob.engine()
            .ingest(id, events[before..last].to_vec())
            .await
            .unwrap()
            .refused
            .is_empty()
    );
    bob.engine()
        .compact(id, *document.id().as_bytes())
        .await
        .expect("compacts over the waiting units");
    let theirs = bob.space(space.id()).await.unwrap();
    let theirs = theirs.document(document.id()).await.unwrap();
    assert_eq!(theirs.text("body").await.unwrap(), old);

    assert!(
        bob.engine()
            .ingest(id, vec![events[last].clone()])
            .await
            .unwrap()
            .refused
            .is_empty()
    );
    assert_eq!(theirs.text("body").await.unwrap(), new);
}

#[tokio::test]
async fn positions_count_characters_beyond_the_ascii_range() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = document_with(&space, "🎭 Acte I\nCafé crème\nÀ bientôt 🎬\n").await;
    let target = "🎭 Acte II\nCafé noir\nÀ bientôt 🎬 !\n";
    let written = document
        .set_text("body", target, SetText::default())
        .await
        .unwrap();
    assert_eq!(written.outcome, TextOutcome::Edited);
    assert_eq!(document.text("body").await.unwrap(), target);
}

#[tokio::test]
async fn a_nested_text_is_set_by_its_container_id() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = space.create_document().unwrap();
    document
        .edit(|doc| {
            let meta = doc.get_map("notes");
            meta.insert_container("body", LoroText::new()).map(drop)
        })
        .await
        .unwrap();
    let read = document.read().await.unwrap();
    let Some(ValueOrContainer::Container(Container::Text(text))) =
        read.get_map("notes").get("body")
    else {
        panic!("a text in the map");
    };
    document
        .set_text(text.id(), "Hello\n", SetText::default())
        .await
        .unwrap();
    let again = document.read().await.unwrap();
    assert_eq!(again.get_text(text.id()).to_string(), "Hello\n");
}

#[tokio::test]
async fn a_comparison_applies_to_a_document_of_ones_own() {
    let doc = LoroDoc::new();
    let text = doc.get_text("body");
    let old = script(Kind::Play, 20_000, 13);
    text.insert(0, &old).unwrap();
    let new = reflow(&one_word(&old), 48);
    let comparison = compare_text(&old, &new, LONG).unwrap();
    apply_splices(&text, &comparison.splices).unwrap();
    assert_eq!(text.to_string(), new);
}

#[tokio::test]
async fn a_first_write_needs_no_earlier_change() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let document = space.create_document().unwrap();
    let written = document
        .set_text("body", "Hello\n", SetText::default())
        .await
        .unwrap();
    assert_eq!(written.units, 1);
    assert_eq!(document.text("body").await.unwrap(), "Hello\n");
}
