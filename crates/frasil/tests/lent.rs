//! One document: a Loro document lent to the application,
//! edited directly. Edits become units within the window; a rebuild
//! replaces the document and the undo manager is bound again; a suggestion
//! stays in a fork until accepted; a crash between a commit and the store
//! leaves nothing to re-express.
#![cfg(all(feature = "adapter-loro", feature = "sqlite"))]

use frasil::advanced::Engine;
use frasil::loro::{
    Container, ExportMode, LoroDoc, LoroMap, LoroValue, TreeParentId, UndoManager, ValueOrContainer,
};
use frasil::{
    Device, Error, LENT_PENDING_LIMIT, LENT_WINDOW, Lent, Level, Options, Space, Storage,
};
use frasil_events::{EventId, kind};
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

fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

fn body(doc: &LoroDoc) -> String {
    doc.get_text("body").to_string()
}

/// How many units of the space `engine` holds.
async fn units(engine: &Engine, space: EventId) -> usize {
    engine
        .events(&space)
        .await
        .iter()
        .filter(|signed| frasil_events::decode(signed).is_ok_and(|e| e.kind() == kind::UNIT))
        .count()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edits_under_the_lent_document_become_units_within_the_window() {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    let doc = lent.doc();
    assert_eq!(
        doc.peer_id(),
        lent.peer_id(),
        "the document writes as the lent peer"
    );

    // Two commits inside the window: one unit, after the window.
    let before = units(alice.engine(), event_of(&space)).await;
    doc.get_text("body").insert(0, "Hel").unwrap();
    doc.commit();
    doc.get_text("body").insert(3, "lo").unwrap();
    doc.commit();
    assert_eq!(
        units(alice.engine(), event_of(&space)).await,
        before,
        "not yet"
    );
    until(|| async { units(alice.engine(), event_of(&space)).await == before + 1 }).await;
    assert_eq!(document.text("body").await.unwrap(), "Hello");
    tokio::time::sleep(LENT_WINDOW).await;
    assert_eq!(
        units(alice.engine(), event_of(&space)).await,
        before + 1,
        "one unit"
    );

    // A flush writes at once; Bob reads the two units.
    doc.get_text("body").insert(5, ", world").unwrap();
    doc.commit();
    lent.flush().await.unwrap();
    assert_eq!(units(alice.engine(), event_of(&space)).await, before + 2);
    carry(alice.engine(), bob.engine(), event_of(&space)).await;
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    assert_eq!(bobs.text("body").await.unwrap(), "Hello, world");

    // Others' operations arrive in the lent document itself.
    let bobs_lent = bobs.lend().await.unwrap();
    bobs_lent.doc().get_text("body").insert(0, "> ").unwrap();
    bobs_lent.doc().commit();
    bobs_lent.flush().await.unwrap();
    carry(bob.engine(), alice.engine(), event_of(&space)).await;
    assert_eq!(body(&lent.doc()), "> Hello, world");
    assert_eq!(lent.generation(), lent.generation(), "the same document");
}

async fn space_of(device: &Device, space: &Space) -> Space {
    device.space(space.id()).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebuild_replaces_the_document_and_the_undo_manager_is_bound_again() {
    // Bob's store restored from a copy, as a device that lost its own
    // operations is: the two openings write at one `seq`, which forks Bob
    // (events.md, 3.5), and a replica that applied the first unit voids it
    // and rebuilds.
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lent-rebuild-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let open = |store: &str| {
        let store = dir.join(store);
        async move {
            Device::open_with(
                Storage::directory(store),
                &[4; 32],
                Options::new().loopback().never_restored(),
            )
            .await
            .unwrap()
        }
    };
    let alice = device(3).await;
    let carol = device(5).await;
    let bob = open("bob").await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
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
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "base ").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    for engine in [bob.engine(), carol.engine()] {
        carry(alice.engine(), engine, id).await;
    }
    bob.close().await.unwrap();
    copy_dir(&dir.join("bob"), &dir.join("bob-copy"));
    let bob_a = open("bob").await;
    let bob_b = open("bob-copy").await;
    assert_eq!(bob_a.engine().device_id(), bob_b.engine().device_id());

    // Carol edits under her lent document, with her undo manager.
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let undo = UndoManager::new(&lent.doc());
    let old_doc = lent.doc();
    old_doc.get_text("body").insert(0, "carol ").unwrap();
    old_doc.commit();
    assert!(undo.can_undo());
    // Not flushed: the window's operations cross the rebuild.

    // Bob's first opening writes a unit Carol applies.
    let bob_a_doc = space_of(&bob_a, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let bob_a_lent = bob_a_doc.lend().await.unwrap();
    bob_a_lent.doc().get_text("body").insert(5, "bob ").unwrap();
    bob_a_lent.doc().commit();
    bob_a_lent.flush().await.unwrap();
    carry(bob_a.engine(), carol.engine(), id).await;
    until(|| async { body(&lent.doc()).contains("bob ") }).await;
    // An edit over Bob's: it depends on the operation the rebuild leaves
    // out, so the window is expressed again rather than imported.
    old_doc.get_text("body").insert(0, "after ").unwrap();
    old_doc.commit();
    assert_eq!(body(&old_doc), "after carol base bob ");
    let generation = lent.generation();
    let mut replaced = lent.replaced();
    let mut failed = lent.failed();
    // The two openings share this process, and a live peer is held once
    // per process: the first opening's handle goes before the second
    // opening lends, at the same incarnation.
    drop(bob_a_lent);

    // Bob's second opening, which never saw the first, writes at the same
    // `seq`: Bob forks, and Carol withdraws his unit.
    let bob_b_doc = space_of(&bob_b, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let bob_b_lent = within(async {
        loop {
            if let Ok(lent) = bob_b_doc.lend().await {
                break lent;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    bob_b_lent
        .doc()
        .get_text("body")
        .insert(5, "other ")
        .unwrap();
    bob_b_lent.doc().commit();
    bob_b_lent.flush().await.unwrap();
    carry(bob_b.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(lent.generation(), generation, "a new document");
    // A commit to the reference held before, not yet replaced by the
    // application: carried over too.
    old_doc.get_text("body").insert(0, "late ").unwrap();
    old_doc.commit();
    let doc = lent.doc();
    assert_eq!(
        doc.peer_id(),
        lent.peer_id(),
        "the replacement writes as the lent peer"
    );
    assert_eq!(body(&doc), "late after carol base ", "the window, carried");
    assert!(failed.borrow_and_update().is_none(), "nothing left behind");
    lent.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(
        document.text("body").await.unwrap(),
        "late after carol base ",
        "the unit carries the window"
    );

    // The undo manager is bound to the replacement and undoes what is
    // written after; the content before survived.
    let mut undo = UndoManager::new(&doc);
    doc.get_text("body").insert(0, "x").unwrap();
    doc.commit();
    assert!(undo.can_undo());
    assert!(undo.undo().unwrap());
    assert!(!body(&doc).starts_with('x'));
    assert!(body(&doc).contains("carol "));
    lent.flush().await.unwrap();
    assert_eq!(carols_doc.text("body").await.unwrap(), body(&doc));
    drop(bob_b_lent);
    bob_a.close().await.unwrap();
    bob_b.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Copies a store's directory, as a backup restored beside the original.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suggestion_stays_in_a_fork_until_accepted() {
    let alice = device(6).await;
    let space = alice.create_space().await.unwrap();
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    lent.doc().get_text("body").insert(0, "hello").unwrap();
    lent.doc().commit();
    lent.flush().await.unwrap();

    let fork = lent.doc().fork();
    let before = fork.oplog_vv();
    fork.get_text("body").insert(0, "> ").unwrap();
    fork.commit();
    lent.suggest(&fork.export(ExportMode::updates(&before)).unwrap())
        .await
        .unwrap();
    assert_eq!(body(&lent.doc()), "hello", "the suggestion is apart");
    let open = document.suggestions().await.unwrap();
    assert_eq!(open.len(), 1);
    document.accept(&[open[0].id]).await.unwrap();
    until(|| async { body(&lent.doc()) == "> hello" }).await;
    assert_eq!(lent.generation(), lent.generation());
    assert!(document.suggestions().await.unwrap().is_empty());
}

#[test]
fn a_crash_between_a_commit_and_the_store_leaves_nothing_to_re_express() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lent-crash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("bob");
    let open = || async {
        Device::open_with(
            Storage::Directory(store.clone()),
            &[7; 32],
            Options::new().loopback().never_restored(),
        )
        .await
        .unwrap()
    };
    // A runtime of its own, dropped as a crash would: the task that writes
    // the window's unit never runs again.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (space, stream, file): (frasil::SpaceId, frasil::StreamId, Vec<u8>) =
        runtime.block_on(async {
            let bob = open().await;
            let space = bob.create_space().await.unwrap();
            let document = space.create_document().unwrap();
            let lent = document.lend().await.unwrap();
            lent.doc().get_text("body").insert(0, "saved").unwrap();
            lent.doc().commit();
            lent.flush().await.unwrap();
            // The application's own file, written after the flush: the
            // stored state, and nothing ahead of it.
            let file = lent.doc().export(ExportMode::Snapshot).unwrap();
            lent.doc().get_text("body").insert(5, " lost").unwrap();
            lent.doc().commit();
            assert_eq!(body(&lent.doc()), "saved lost");
            // The crash: the handle is not dropped (a drop writes a last
            // unit), and the runtime goes down with the window's task.
            std::mem::forget(lent);
            std::mem::forget(bob);
            (space.id(), document.id(), file)
        });
    runtime.shutdown_timeout(Duration::from_secs(0));

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let bob = open().await;
        let space = bob.space(space).await.unwrap();
        let document = space.document(stream).await.unwrap();
        assert_eq!(document.text("body").await.unwrap(), "saved");
        let kept = LoroDoc::new();
        kept.import(&file).unwrap();
        assert_eq!(
            kept.oplog_vv(),
            document.read().await.unwrap().oplog_vv(),
            "the file and the store agree: nothing to re-express"
        );
        // Lent again, under a new incarnation, the document goes on.
        let lent = document.lend().await.unwrap();
        lent.doc().get_text("body").insert(5, " again").unwrap();
        lent.doc().commit();
        lent.flush().await.unwrap();
        assert_eq!(document.text("body").await.unwrap(), "saved again");
        bob.close().await.unwrap();
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// On tokio's paused clock, which moves only when every task waits on a
/// timer: the time a unit takes to reach the store, as the window and other
/// timers count it, however slow the machine.
async fn unit_after(space: &Space, alice: &Device, text: &str) -> Duration {
    let before = units(alice.engine(), event_of(space)).await;
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    lent.doc().get_text("body").insert(0, text).unwrap();
    let started = tokio::time::Instant::now();
    lent.doc().commit();
    until(|| async { units(alice.engine(), event_of(space)).await == before + 1 }).await;
    started.elapsed()
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_paste_past_the_limit_reaches_a_unit_at_once() {
    // Past the limit a unit does not wait for the window. The clock is
    // tokio's paused one, so signing and sealing take no time on it and a
    // slow machine cannot make the paste look as if it waited.
    let alice = device(8).await;
    let space = alice.create_space().await.unwrap();
    // Text that does not compress away: the limit is on the update's bytes.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let paste: String = (0..LENT_PENDING_LIMIT + 1)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(b'a' + (state % 26) as u8)
        })
        .collect();
    // A small edit waits the window out: the clock does count it.
    let small = unit_after(&space, &alice, "a word").await;
    assert!(
        small >= LENT_WINDOW,
        "a small edit waits the window: {small:?}"
    );
    let pasted = unit_after(&space, &alice, &paste).await;
    assert!(
        pasted < LENT_WINDOW,
        "a paste past the limit does not: {pasted:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_unit_is_tried_again_and_reported_meanwhile() {
    // Bob reads: his unit is refused until Alice grants him write.
    let alice = device(9).await;
    let bob = device(10).await;
    let space = with_member(&alice, &bob, Level::Read).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "base ").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = bobs.lend().await.unwrap();
    let mut failed = lent.failed();
    lent.doc().get_text("body").insert(5, "bob ").unwrap();
    lent.doc().commit();
    within(failed.changed()).await.unwrap();
    assert!(
        matches!(&*failed.borrow_and_update(), Some(Error::NotAllowed(_))),
        "{:?}",
        failed.borrow()
    );
    assert!(matches!(lent.flush().await, Err(Error::NotAllowed(_))));
    assert_eq!(units(bob.engine(), id).await, 1, "Alice's only");

    space.set_level(bob.id(), Level::Write).await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    // The handle tries again on its own, with backoff.
    until(|| async { units(bob.engine(), id).await == 2 }).await;
    within(async {
        while failed.borrow_and_update().is_some() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base bob ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_handle_and_a_closing_device_write_the_window() {
    let alice = device(11).await;
    let space = alice.create_space().await.unwrap();
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let lent = document.lend().await.unwrap();
    lent.doc().get_text("body").insert(0, "dropped").unwrap();
    lent.doc().commit();
    let twice = document.lend().await;
    assert!(
        matches!(twice, Err(Error::NotAllowed(_))),
        "one handle at a time: {twice:?}"
    );
    drop(lent);
    until(|| async { units(alice.engine(), id).await == 1 }).await;
    assert_eq!(document.text("body").await.unwrap(), "dropped");

    // Lent again once the first handle ended; the window reaches a unit
    // as the device closes.
    let lent = within(async {
        loop {
            if let Ok(lent) = document.lend().await {
                break lent;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    lent.doc().get_text("body").insert(7, " closed").unwrap();
    lent.doc().commit();
    alice.close().await.unwrap();
    assert_eq!(units(alice.engine(), id).await, 2);
    assert_eq!(document.text("body").await.unwrap(), "dropped closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_of_its_own_withdrawn_renews_the_incarnation() {
    // Bob writes; Alice, without his unit, removes him and grants him
    // again. Bob learns the removal late: his unit is withdrawn, the
    // document built again, and his operations written again under a
    // fresh incarnation.
    let alice = device(12).await;
    let bob = device(13).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "base ").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = bobs.lend().await.unwrap();
    let peer = lent.peer_id();
    lent.doc().get_text("body").insert(5, "bob ").unwrap();
    lent.doc().commit();
    lent.flush().await.unwrap();
    let withdrawn = units(bob.engine(), id).await;
    // Pending too, over his own unit.
    lent.doc().get_text("body").insert(9, "more ").unwrap();
    lent.doc().commit();

    space.remove(bob.id()).await.unwrap();
    alice
        .engine()
        .grant_device(
            id,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let mut replaced = lent.replaced();
    carry(alice.engine(), bob.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(lent.peer_id(), peer, "a fresh incarnation");
    let doc = lent.doc();
    assert_eq!(doc.peer_id(), lent.peer_id());
    assert_eq!(body(&doc), "base bob more ", "expressed again");
    assert_eq!(
        doc.oplog_vv().get(&peer).copied().unwrap_or(0),
        0,
        "nothing of the lost incarnation"
    );
    lent.flush().await.unwrap();
    assert!(units(bob.engine(), id).await > withdrawn);
    // Whatever reached a unit under the lost peer before the removal
    // arrived is withdrawn with it.
    let history = bobs.history().await.unwrap();
    let old: Vec<_> = history
        .iter()
        .filter(|c| matches!(&c.detail, frasil::Detail::Document(Some(d)) if d.span.peer == peer))
        .collect();
    assert!(!old.is_empty());
    assert!(
        old.iter().all(|c| c.effect == frasil::Effect::Withdrawn),
        "{old:?}"
    );
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base bob more ");
}

/// Alice's space with a document, Bob and Carol writing: Bob's unit over
/// Alice's text reached Carol, not Alice, so that Alice's removal of Bob
/// is concurrent with it and withdraws it where it was applied. Bob's unit
/// also creates a map, `box` in the root map `meta`.
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
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
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
    bobs.doc()
        .get_map("meta")
        .insert_container("box", LoroMap::new())
        .unwrap()
        .insert("by", "bob")
        .unwrap();
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
async fn a_withdrawn_incarnation_is_never_begun_again() {
    // Item 1: a peer the units count, its units withdrawn, stays counted
    // at step 6, so a later handle begins elsewhere.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol: _carol,
        space,
        document,
        bobs,
    } = bobs_unit_at_carol([14, 15, 16]).await;
    let id = event_of(&space);
    let withdrawn = bobs.peer_id();
    let mut replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    alice
        .engine()
        .grant_device(
            id,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    let renewed = bobs.peer_id();
    assert_ne!(renewed, withdrawn);
    bobs.flush().await.unwrap();
    drop(bobs);
    let bobs_doc = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let again = within(async {
        loop {
            if let Ok(lent) = bobs_doc.lend().await {
                break lent;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert_ne!(again.peer_id(), withdrawn, "the withdrawn incarnation");
    assert_ne!(again.peer_id(), renewed, "the renewed one, with a unit");
    again.doc().get_text("body").insert(0, "again ").unwrap();
    again.doc().commit();
    again.flush().await.unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "again base bob ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commits_to_a_retired_reference_reach_the_unit_on_drop() {
    // Item 2: what the application still commits to the reference it
    // held before a replacement is carried when the handle goes.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([17, 18, 19]).await;
    let id = event_of(&space);
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let old = lent.doc();
    old.get_text("body").insert(0, "carol ").unwrap();
    old.commit();
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    // The application never takes the new document: it commits to the
    // old reference, then drops the handle.
    old.get_text("body").insert(0, "late ").unwrap();
    old.commit();
    let before = units(carol.engine(), id).await;
    drop(lent);
    until(|| async { units(carol.engine(), id).await > before }).await;
    assert_eq!(carols_doc.text("body").await.unwrap(), "late carol base ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commits_to_a_retired_reference_reach_the_unit_on_close() {
    // Item 2, at the device's close.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([20, 21, 22]).await;
    let id = event_of(&space);
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let old = lent.doc();
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    old.get_text("body").insert(0, "late ").unwrap();
    old.commit();
    let before = units(carol.engine(), id).await;
    carol.close().await.unwrap();
    assert_eq!(units(carol.engine(), id).await, before + 1);
    assert_eq!(carols_doc.text("body").await.unwrap(), "late base ");
    drop(lent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_over_withdrawn_text_is_placed_without_it() {
    // Carol typed past Bob's text; when Bob's unit is withdrawn, her change
    // is expressed again with his text taken out, where she put it: after
    // the text that remains before it.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([23, 24, 25]).await;
    let id = event_of(&space);
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let old = lent.doc();
    assert_eq!(body(&old), "base bob ");
    old.get_text("body").insert(9, "end").unwrap();
    old.commit();
    let mut replaced = lent.replaced();
    let failed = lent.failed();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_eq!(body(&lent.doc()), "base end");
    assert!(failed.borrow().is_none());
    lent.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base end");
    let _ = bob;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_commit_that_cannot_be_placed_stays_reported() {
    // After the replacement, Carol still commits to the reference she held
    // before: text past Bob's withdrawn text, which has a place, and a key
    // inside the map only Bob's withdrawn unit made, which has none. The
    // text is carried, the key is left out and reported, and the report
    // outlives the next unit.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([33, 34, 35]).await;
    let id = event_of(&space);
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let old = lent.doc();
    let mut replaced = lent.replaced();
    let mut failed = lent.failed();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    old.get_text("body").insert(9, "end").unwrap();
    bobs_box(&old).unwrap().insert("carol", true).unwrap();
    old.commit();
    let _ = lent.doc();
    within(async {
        while failed.borrow_and_update().is_none() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    let report = failed.borrow().clone().unwrap();
    assert!(
        matches!(&report, Error::Adapter(text) if text.starts_with("LoroDependsOnRefused")),
        "{report:?}"
    );
    assert!(
        matches!(&report, Error::Adapter(text) if text.contains("another writer's lost operation")),
        "{report:?}"
    );
    until(|| async { body(&lent.doc()) == "base end" }).await;
    assert!(bobs_box(&lent.doc()).is_none(), "nothing of Bob's");
    let doc = lent.doc();
    doc.get_text("body").insert(0, "new ").unwrap();
    doc.commit();
    lent.flush().await.unwrap();
    assert_eq!(carols_doc.text("body").await.unwrap(), "new base end");
    assert_eq!(*failed.borrow(), Some(report));
    let _ = (alice, bob);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_carries_a_change_that_depended_on_the_withdrawn_unit() {
    // Item 5: Carol typed over Bob's unit and wrote it; Bob holds both.
    // When Bob's unit is withdrawn at his own replica, Carol's change
    // depends on it and stays pending inside Loro at every replica: the
    // renewal expresses it again with Bob's own, from the new document's
    // version, and Carol reads it back.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs,
    } = bobs_unit_at_carol([26, 27, 28]).await;
    let id = event_of(&space);
    let carols_space = space_of(&carol, &space).await;
    let carols_doc = carols_space.document(document.id()).await.unwrap();
    let carols = carols_doc.lend().await.unwrap();
    assert_eq!(body(&carols.doc()), "base bob ");
    carols.doc().get_text("body").insert(9, "carol ").unwrap();
    carols.doc().commit();
    carols.flush().await.unwrap();
    carry(carol.engine(), bob.engine(), id).await;
    assert_eq!(body(&bobs.doc()), "base bob carol ");

    let withdrawn = bobs.peer_id();
    let mut replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    alice
        .engine()
        .grant_device(
            id,
            bob.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(bobs.peer_id(), withdrawn);
    let doc = bobs.doc();
    assert_eq!(
        body(&doc),
        "base bob ",
        "his own; Carol's is hers to express"
    );
    bobs.flush().await.unwrap();

    // Carol learns the removal: Bob's unit withdrawn, her own waits inside
    // Loro on it, so her handle renews and expresses her text without his.
    let mut carols_replaced = carols.replaced();
    carry(alice.engine(), carol.engine(), id).await;
    within(carols_replaced.changed()).await.unwrap();
    assert_eq!(body(&carols.doc()), "base carol ");
    carols.flush().await.unwrap();
    carry(bob.engine(), carol.engine(), id).await;
    carry(carol.engine(), bob.engine(), id).await;
    carry(carol.engine(), alice.engine(), id).await;
    carry(bob.engine(), alice.engine(), id).await;
    once_each(&document.text("body").await.unwrap());
    until(|| async { body(&carols.doc()) == body(&bobs.doc()) }).await;
    assert_eq!(body(&carols.doc()), document.text("body").await.unwrap());
}

/// Bob's map, as a document holds it.
fn bobs_box(doc: &LoroDoc) -> Option<LoroMap> {
    match doc.get_map("meta").get("box")? {
        ValueOrContainer::Container(Container::Map(map)) => Some(map),
        _ => None,
    }
}

/// Grants a device write in Alice's space again, after a removal.
async fn regrant(alice: &Device, space: &Space, device: &Device) {
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

/// The text holds Alice's base, Bob's and Carol's text, each once.
fn once_each(text: &str) {
    for part in ["base", "bob", "carol"] {
        assert_eq!(text.matches(part).count(), 1, "{part} once in {text:?}");
    }
}

/// Bob's unit over Alice's text and Carol's over Bob's, each holding
/// both: what two lost incarnations share.
async fn two_writers_each_holding_both(keys: [u8; 3]) -> (BobsUnitAtCarol, Lent) {
    let scene = bobs_unit_at_carol(keys).await;
    let id = event_of(&scene.space);
    let carols_doc = space_of(&scene.carol, &scene.space)
        .await
        .document(scene.document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    assert_eq!(body(&carols.doc()), "base bob ");
    carols.doc().get_text("body").insert(0, "carol ").unwrap();
    carols.doc().commit();
    carols.flush().await.unwrap();
    carry(scene.carol.engine(), scene.bob.engine(), id).await;
    assert_eq!(body(&scene.bobs.doc()), "carol base bob ");
    (scene, carols)
}

/// Both lost in one rebuild at each replica: each expresses its own text,
/// the other's taken out, and every replica reads each text once. Returns
/// whether Bob's peer was the lower.
async fn two_lost_in_one_rebuild(keys: [u8; 3]) -> bool {
    let (
        BobsUnitAtCarol {
            alice,
            bob,
            carol,
            space,
            document,
            bobs,
        },
        carols,
    ) = two_writers_each_holding_both(keys).await;
    let id = event_of(&space);
    let (bobs_peer, carols_peer) = (bobs.peer_id(), carols.peer_id());
    let mut bobs_replaced = bobs.replaced();
    let mut carols_replaced = carols.replaced();
    space.remove(bob.id()).await.unwrap();
    space.remove(carol.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    regrant(&alice, &space, &carol).await;
    carry(alice.engine(), bob.engine(), id).await;
    carry(alice.engine(), carol.engine(), id).await;
    within(bobs_replaced.changed()).await.unwrap();
    within(carols_replaced.changed()).await.unwrap();
    assert_ne!(bobs.peer_id(), bobs_peer);
    assert_ne!(carols.peer_id(), carols_peer);
    let bob_lower = bobs_peer < carols_peer;
    assert_eq!(body(&bobs.doc()), "base bob ", "Bob's own");
    assert_eq!(body(&carols.doc()), "carol base ", "Carol's own");
    bobs.flush().await.unwrap();
    carols.flush().await.unwrap();
    carry(bob.engine(), carol.engine(), id).await;
    carry(carol.engine(), bob.engine(), id).await;
    until(|| async { body(&bobs.doc()) == "carol base bob " }).await;
    until(|| async { body(&carols.doc()) == "carol base bob " }).await;
    carry(bob.engine(), alice.engine(), id).await;
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "carol base bob ");
    bob_lower
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lost_incarnations_express_their_own_once_in_either_order() {
    // Peers derive from the space's and the stream's random IDs: run the
    // scene until each order of the two peers was seen.
    let (mut bob_lower, mut carol_lower) = (false, false);
    for run in 0..32u8 {
        if two_lost_in_one_rebuild([100 + 3 * run, 101 + 3 * run, 102 + 3 * run]).await {
            bob_lower = true;
        } else {
            carol_lower = true;
        }
        if bob_lower && carol_lower {
            return;
        }
    }
    panic!("both orders within 32 runs: Bob lower {bob_lower}, Carol lower {carol_lower}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_lost_incarnations_in_separate_rebuilds_express_their_own_once() {
    // Bob learns Carol's removal first, and his own in a later rebuild;
    // Carol learns both at once. Each expresses its own text, and the text
    // comes back once whatever the order.
    let (
        BobsUnitAtCarol {
            alice,
            bob,
            carol,
            space,
            document,
            bobs,
        },
        carols,
    ) = two_writers_each_holding_both([40, 41, 42]).await;
    let id = event_of(&space);
    let mut bobs_replaced = bobs.replaced();
    space.remove(carol.id()).await.unwrap();
    regrant(&alice, &space, &carol).await;
    carry(alice.engine(), bob.engine(), id).await;
    within(bobs_replaced.changed()).await.unwrap();
    assert_eq!(body(&bobs.doc()), "base bob ", "Carol's unit withdrawn");
    let bobs_peer = bobs.peer_id();
    space.remove(bob.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    until(|| async { bobs.peer_id() != bobs_peer }).await;
    let mut carols_replaced = carols.replaced();
    carry(alice.engine(), carol.engine(), id).await;
    within(carols_replaced.changed()).await.unwrap();
    assert_eq!(body(&bobs.doc()), "base bob ", "Bob's own");
    assert_eq!(body(&carols.doc()), "carol base ", "Carol's own");
    bobs.flush().await.unwrap();
    carols.flush().await.unwrap();
    carry(bob.engine(), carol.engine(), id).await;
    carry(carol.engine(), bob.engine(), id).await;
    until(|| async { body(&bobs.doc()) == "carol base bob " }).await;
    until(|| async { body(&carols.doc()) == "carol base bob " }).await;
    carry(bob.engine(), alice.engine(), id).await;
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "carol base bob ");
}

/// A lent document's holder writes the operations of its withdrawn unit
/// again under a fresh incarnation; the device's upkeep, once it writes
/// again, does not re-submit that unit as well, which would hold them
/// twice, whether it runs before the holder takes the rebuild or after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_its_holder_expressed_again_is_not_re_submitted_too() {
    let BobsUnitAtCarol {
        alice,
        bob,
        space,
        document,
        bobs,
        ..
    } = bobs_unit_at_carol([43, 44, 45]).await;
    let id = event_of(&space);
    let peer = bobs.peer_id();
    let mut bobs_replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    // The upkeep's re-submission, as it runs once the device writes again:
    // before the holder takes the rebuild, and after.
    assert_eq!(
        bob.engine().resubmit_refused_units(id).await.unwrap(),
        Vec::new(),
        "nothing re-submitted while the holder has it"
    );
    within(bobs_replaced.changed()).await.unwrap();
    assert_ne!(bobs.peer_id(), peer, "renewed");
    assert_eq!(body(&bobs.doc()), "base bob ", "expressed again");
    bobs.flush().await.unwrap();
    assert_eq!(
        bob.engine().resubmit_refused_units(id).await.unwrap(),
        Vec::new(),
        "nothing re-submitted once it expressed them"
    );
    assert_eq!(body(&bobs.doc()), "base bob ");
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base bob ");
}

/// Background work held until the test lets it run: a device opened with
/// it does no upkeep meanwhile.
#[derive(Default)]
struct HeldTasks(std::sync::Mutex<Vec<frasil::BoxFuture<'static, ()>>>);

impl HeldTasks {
    fn release(&self) {
        for task in std::mem::take(&mut *self.0.lock().unwrap()) {
            tokio::spawn(task);
        }
    }
}

impl frasil::advanced::Tasks for HeldTasks {
    fn spawn(&self, task: frasil::BoxFuture<'static, ()>) {
        self.0.lock().unwrap().push(task);
    }

    fn sleep(&self, duration: Duration) -> frasil::BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The incarnations a holder expressed again are kept at rest with the
/// units that express them: after the device reopens, with no holder of
/// the document any more, its upkeep still does not re-submit the unit
/// whose operations the renewal wrote again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_expressed_again_is_not_re_submitted_after_a_restart() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lent-expressed-again-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let open = |tasks: Option<std::sync::Arc<HeldTasks>>| {
        let store = dir.join("bob");
        async move {
            let options = Options::new().loopback().never_restored();
            let options = match tasks {
                Some(tasks) => options.tasks(tasks),
                None => options,
            };
            Device::open_with(Storage::directory(store), &[47; 32], options)
                .await
                .unwrap()
        }
    };
    let alice = device(46).await;
    let bob = open(None).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    alices.doc().get_text("body").insert(0, "base ").unwrap();
    alices.doc().commit();
    alices.flush().await.unwrap();
    drop(alices);
    carry(alice.engine(), bob.engine(), id).await;
    let bobs = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap()
        .lend()
        .await
        .unwrap();
    bobs.doc().get_text("body").insert(5, "bob ").unwrap();
    bobs.doc().commit();
    bobs.flush().await.unwrap();
    // Alice removes Bob before his unit reaches her, and grants him again:
    // the unit is withdrawn, and Bob's holder writes it again.
    let peer = bobs.peer_id();
    let mut replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(bobs.peer_id(), peer, "renewed");
    assert_eq!(body(&bobs.doc()), "base bob ");
    bobs.flush().await.unwrap();
    drop(bobs);
    bob.close().await.unwrap();
    drop(bob);

    // Reopened, with no upkeep yet and no holder: re-submission runs as the
    // upkeep would run it.
    let tasks = std::sync::Arc::new(HeldTasks::default());
    let bob = open(Some(tasks.clone())).await;
    assert_eq!(
        bob.engine().resubmit_refused_units(id).await.unwrap(),
        Vec::new(),
        "nothing re-submitted"
    );
    let text = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap()
        .text("body")
        .await
        .unwrap();
    assert_eq!(text, "base bob ", "Bob's text once");
    tasks.release();
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base bob ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_carry_clears_the_report_of_one_that_failed() {
    // Carol set a key inside Bob's map: Bob's unit withdrawn, the change
    // has no place, and it is reported. Then Dave's unit, which Carol
    // applied, is withdrawn: a replacement whose carry is clean clears the
    // report.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([43, 44, 45]).await;
    let id = event_of(&space);
    let dave = device(46).await;
    regrant(&alice, &space, &dave).await;
    dave.engine().follow(id).await;
    carry(alice.engine(), dave.engine(), id).await;
    let daves = space_of(&dave, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    daves
        .edit(|doc| doc.get_text("body").insert(0, "dave "))
        .await
        .unwrap();
    carry(dave.engine(), carol.engine(), id).await;
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let old = lent.doc();
    assert_eq!(body(&old), "dave base bob ");
    let mut replaced = lent.replaced();
    let mut failed = lent.failed();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    // A late commit to the old reference, inside Bob's withdrawn map.
    bobs_box(&old).unwrap().insert("carol", true).unwrap();
    old.commit();
    let _ = lent.doc();
    within(async {
        while failed.borrow_and_update().is_none() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    space.remove(dave.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(async {
        while failed.borrow_and_update().is_some() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    assert_eq!(body(&lent.doc()), "base ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_then_a_withdrawn_unit_of_one_incarnation_express_only_the_withdrawn() {
    // Bob's handle writes two units; Alice holds the first and removes
    // Bob concurrently with the second: only the second is withdrawn, and
    // the renewal expresses its operations alone.
    let alice = device(47).await;
    let bob = device(48).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "base "))
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs_doc = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let bobs = bobs_doc.lend().await.unwrap();
    let peer = bobs.peer_id();
    bobs.doc().get_text("body").insert(5, "one ").unwrap();
    bobs.doc().commit();
    bobs.flush().await.unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    bobs.doc().get_text("body").insert(9, "two ").unwrap();
    bobs.doc().commit();
    bobs.flush().await.unwrap();
    let mut replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_ne!(bobs.peer_id(), peer, "renewed");
    assert_eq!(body(&bobs.doc()), "base one two ", "each once");
    bobs.flush().await.unwrap();
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base one two ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dependent_unit_reaching_a_writer_after_its_renewal_is_its_own_writers() {
    // Carol typed over Bob's text, a unit that reaches Bob only after he
    // renewed: he does not renew again, and need not; Carol's handle
    // expresses her text, and every replica reads each text once.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs,
    } = bobs_unit_at_carol([60, 61, 62]).await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    carols.doc().get_text("body").insert(9, "carol").unwrap();
    carols.doc().commit();
    carols.flush().await.unwrap();
    let mut bobs_replaced = bobs.replaced();
    space.remove(bob.id()).await.unwrap();
    regrant(&alice, &space, &bob).await;
    carry(alice.engine(), bob.engine(), id).await;
    within(bobs_replaced.changed()).await.unwrap();
    assert_eq!(body(&bobs.doc()), "base bob ");
    bobs.flush().await.unwrap();
    // Carol's unit reaches Bob after his renewal: it waits inside Loro on
    // his withdrawn unit there.
    carry(carol.engine(), bob.engine(), id).await;
    assert_eq!(body(&bobs.doc()), "base bob ");
    let mut carols_replaced = carols.replaced();
    carry(alice.engine(), carol.engine(), id).await;
    within(carols_replaced.changed()).await.unwrap();
    assert_eq!(body(&carols.doc()), "base carol");
    carols.flush().await.unwrap();
    for (from, to) in [
        (&bob, &carol),
        (&carol, &bob),
        (&bob, &alice),
        (&carol, &alice),
    ] {
        carry(from.engine(), to.engine(), id).await;
    }
    let text = document.text("body").await.unwrap();
    for part in ["base", "bob", "carol"] {
        assert_eq!(text.matches(part).count(), 1, "{part} once in {text:?}");
    }
    until(|| async { body(&bobs.doc()) == text && body(&carols.doc()) == text }).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_writers_text_goes_and_a_dependent_writer_keeps_its_own() {
    // Bob is removed for good. Carol, still a writer, typed over his text:
    // her text stays, without his, at every replica.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([63, 64, 65]).await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    carols.doc().get_text("body").insert(9, "carol").unwrap();
    carols.doc().commit();
    carols.flush().await.unwrap();
    let mut replaced = carols.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_eq!(body(&carols.doc()), "base carol");
    carols.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base carol");
    let _ = bob;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_after_a_replacement_carries_its_own_time() {
    // A rebuilt document is a new Loro document: its writer's clock still
    // goes into each change, so history's time is the unit's own.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol,
        space,
        document,
        bobs: _bobs,
    } = bobs_unit_at_carol([66, 67, 68]).await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let lent = carols_doc.lend().await.unwrap();
    let mut replaced = lent.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    lent.doc().get_text("body").insert(0, "after ").unwrap();
    lent.doc().commit();
    lent.flush().await.unwrap();
    let history = carols_doc.history().await.unwrap();
    let last = history
        .iter()
        .rev()
        .find(|c| c.author.device == carol.id())
        .expect("Carol's change");
    let time = last.time.expect("a time");
    assert!(
        time >= started,
        "its own time, {time}, not before {started}"
    );
}

/// Alice's space with Bob and Carol writing, and a document Alice wrote
/// with `base`. Bob's unit, written with `bobs`, reaches Carol and not
/// Alice, so that Alice's removal of Bob withdraws it where it was applied.
async fn bob_writes_for_carol(
    keys: [u8; 3],
    base: impl FnOnce(&LoroDoc),
    bobs: impl FnOnce(&LoroDoc),
) -> (Device, Device, Device, Space, frasil::Document) {
    let alice = device(keys[0]).await;
    let bob = device(keys[1]).await;
    let carol = device(keys[2]).await;
    let space = with_member(&alice, &bob, Level::Write).await;
    let id = event_of(&space);
    regrant(&alice, &space, &carol).await;
    carol.engine().follow(id).await;
    let document = space.create_document().unwrap();
    let alices = document.lend().await.unwrap();
    base(&alices.doc());
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
    let lent = bobs_doc.lend().await.unwrap();
    bobs(&lent.doc());
    lent.doc().commit();
    lent.flush().await.unwrap();
    drop(lent);
    carry(bob.engine(), carol.engine(), id).await;
    (alice, bob, carol, space, document)
}

/// The tree node whose meta `name` is `name`.
fn node_named(doc: &LoroDoc, name: &str) -> Option<frasil::loro::TreeID> {
    let tree = doc.get_tree("outline");
    tree.get_nodes(false)
        .into_iter()
        .map(|node| node.id)
        .find(|node| {
            tree.get_meta(*node)
            .ok()
            .and_then(|meta| meta.get("name"))
            .is_some_and(|value| {
                matches!(value, ValueOrContainer::Value(LoroValue::String(s)) if *s == *name)
            })
        })
}

/// The names of a tree node's children, or of the roots.
fn children(doc: &LoroDoc, parent: Option<frasil::loro::TreeID>) -> Vec<String> {
    let tree = doc.get_tree("outline");
    let parent = parent.map_or(TreeParentId::Root, TreeParentId::Node);
    let mut names: Vec<String> = tree
        .children(parent)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|node| match tree.get_meta(node).ok()?.get("name")? {
            ValueOrContainer::Value(LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        })
        .collect();
    names.sort();
    names
}

/// The values of a list or movable list, as strings.
fn items(value: LoroValue) -> Vec<String> {
    match value {
        LoroValue::List(items) => items
            .iter()
            .map(|item| match item {
                LoroValue::String(s) => s.to_string(),
                other => format!("{other:?}"),
            })
            .collect(),
        other => panic!("not a list: {other:?}"),
    }
}

fn base_of_every_kind(doc: &LoroDoc) {
    doc.get_text("body").insert(0, "base text").unwrap();
    doc.get_counter("count").increment(1.0).unwrap();
    let order = doc.get_movable_list("order");
    let tags = doc.get_list("tags");
    for item in ["a", "b", "c"] {
        order.push(item).unwrap();
        tags.push(item).unwrap();
    }
    let meta = doc.get_map("meta");
    meta.insert("title", "draft").unwrap();
    meta.insert("subtitle", "first").unwrap();
    let tree = doc.get_tree("outline");
    for name in ["one", "two"] {
        let node = tree.create(TreeParentId::Root).unwrap();
        tree.get_meta(node).unwrap().insert("name", name).unwrap();
    }
}

/// What Alice's base and Carol's own operations make, and nothing of Bob's.
fn assert_alices_and_carols(doc: &LoroDoc, replica: &str) {
    assert_eq!(body(doc), "base text carol", "text at {replica}");
    let marked = doc
        .get_text("body")
        .to_delta()
        .iter()
        .any(|step| matches!(step, frasil::loro::TextDelta::Insert { attributes: Some(a), .. } if !a.is_empty()));
    assert!(!marked, "no mark at {replica}");
    assert_eq!(
        doc.get_counter("count").get_value(),
        3.0,
        "counter at {replica}"
    );
    // Carol pushed "d" after "b", the item before it where she wrote it:
    // without Bob's move, "c" follows "b" and "d" goes between them.
    assert_eq!(
        items(doc.get_movable_list("order").get_deep_value()),
        ["a", "b", "d", "c"],
        "movable list at {replica}"
    );
    assert_eq!(
        items(doc.get_list("tags").get_deep_value()),
        ["a", "b", "c"],
        "list at {replica}"
    );
    let meta = doc.get_map("meta").get_deep_value();
    let LoroValue::Map(meta) = meta else {
        panic!("not a map")
    };
    let mut keys: Vec<&String> = meta.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["carol", "subtitle", "title"],
        "map keys at {replica}"
    );
    assert_eq!(meta.get("title"), Some(&LoroValue::from("draft")));
    assert_eq!(meta.get("subtitle"), Some(&LoroValue::from("first")));
    assert_eq!(meta.get("carol"), Some(&LoroValue::from(true)));
    assert_eq!(children(doc, None), ["one", "two"], "roots at {replica}");
    assert_eq!(
        children(doc, node_named(doc, "one")),
        ["carol's"],
        "children at {replica}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawn_writers_operations_of_every_kind_are_not_expressed_again() {
    // Bob deletes, marks, increments, moves, sets, removes a key, sets a
    // container as a map value, edits a list and the tree; Carol writes
    // her own over all of it. Bob is removed: Carol's handle expresses
    // exactly her own operations, and every member.s replica reads Alice.s base
    // and Carol's, with nothing of Bob's.
    let (alice, bob, carol, space, document) =
        bob_writes_for_carol([70, 71, 72], base_of_every_kind, |doc| {
            let text = doc.get_text("body");
            text.delete(0, 5).unwrap();
            text.mark(0..4, "bold", true).unwrap();
            doc.get_counter("count").increment(5.0).unwrap();
            doc.get_movable_list("order").mov(2, 0).unwrap();
            let meta = doc.get_map("meta");
            meta.insert("title", "final").unwrap();
            meta.delete("subtitle").unwrap();
            meta.insert_container("box", LoroMap::new())
                .unwrap()
                .insert("by", "bob")
                .unwrap();
            let tags = doc.get_list("tags");
            tags.delete(1, 1).unwrap();
            tags.push("x").unwrap();
            let tree = doc.get_tree("outline");
            let one = node_named(doc, "one").unwrap();
            let child = tree.create(TreeParentId::Node(one)).unwrap();
            tree.get_meta(child)
                .unwrap()
                .insert("name", "bob's")
                .unwrap();
            tree.delete(node_named(doc, "two").unwrap()).unwrap();
        })
        .await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    let doc = carols.doc();
    assert_eq!(body(&doc), "text");
    doc.get_text("body").insert(4, " carol").unwrap();
    doc.get_counter("count").increment(2.0).unwrap();
    doc.get_movable_list("order").push("d").unwrap();
    doc.get_map("meta").insert("carol", true).unwrap();
    let tree = doc.get_tree("outline");
    let one = node_named(&doc, "one").unwrap();
    let child = tree.create(TreeParentId::Node(one)).unwrap();
    tree.get_meta(child)
        .unwrap()
        .insert("name", "carol's")
        .unwrap();
    doc.commit();
    carols.flush().await.unwrap();
    let failed = carols.failed();
    let mut replaced = carols.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert_alices_and_carols(&carols.doc(), "Carol's handle");
    assert!(failed.borrow().is_none(), "{:?}", failed.borrow());
    carols.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    assert_alices_and_carols(&document.read().await.unwrap(), "Alice");
    assert_alices_and_carols(&carols_doc.read().await.unwrap(), "Carol");
    // Bob's own replica is left out here;
    // `a_removed_devices_own_replica_learns_its_removal` covers it.
    let _ = bob;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_devices_own_replica_learns_its_removal() {
    // Bob's unit reached Carol, not Alice; Alice removes Bob. Bob ingests
    // every event Alice holds, the removal among them, and his replica
    // resolves his standing as Alice's does.
    let BobsUnitAtCarol {
        alice,
        bob,
        carol: _carol,
        space,
        document: _document,
        bobs: _bobs,
    } = bobs_unit_at_carol([77, 78, 79]).await;
    let id = event_of(&space);
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let me = bob.engine().device_id();
    assert_eq!(
        format!("{:?}", alice.engine().standing(&id, &me).await),
        format!("{:?}", bob.engine().standing(&id, &me).await),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_operations_under_a_withdrawn_writers_content_are_reported() {
    // Carol sets a key inside Bob's map, creates a child under Bob's tree
    // node and moves Bob's list item. Bob is removed: those three have no
    // place in the rebuilt document, and Frasil never writes Bob's
    // operations again, so they are left out and reported through
    // `failed()`. The rest of Carol's change is expressed.
    let (alice, bob, carol, space, document) = bob_writes_for_carol(
        [73, 74, 75],
        |doc| {
            doc.get_text("body").insert(0, "base").unwrap();
            let order = doc.get_movable_list("order");
            order.push("a").unwrap();
            order.push("b").unwrap();
        },
        |doc| {
            doc.get_map("meta")
                .insert_container("box", LoroMap::new())
                .unwrap()
                .insert("by", "bob")
                .unwrap();
            let tree = doc.get_tree("outline");
            let node = tree.create(TreeParentId::Root).unwrap();
            tree.get_meta(node)
                .unwrap()
                .insert("name", "bob's")
                .unwrap();
            doc.get_movable_list("order").push("x").unwrap();
        },
    )
    .await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    let doc = carols.doc();
    bobs_box(&doc).unwrap().insert("carol", true).unwrap();
    let bobs_node = node_named(&doc, "bob's").unwrap();
    doc.get_tree("outline")
        .create(TreeParentId::Node(bobs_node))
        .unwrap();
    doc.get_movable_list("order").mov(2, 0).unwrap();
    doc.get_text("body").insert(4, " carol").unwrap();
    doc.commit();
    carols.flush().await.unwrap();
    let mut failed = carols.failed();
    let mut replaced = carols.replaced();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    within(async {
        while failed.borrow_and_update().is_none() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    let report = failed.borrow().clone().unwrap();
    let Error::Adapter(text) = &report else {
        panic!("{report:?}")
    };
    assert!(text.starts_with("LoroDependsOnRefused"), "{text}");
    for what in ["a change in", "a tree node", "a move in"] {
        assert!(text.contains(what), "{what:?} in {text}");
    }
    let doc = carols.doc();
    assert_eq!(body(&doc), "base carol");
    assert!(bobs_box(&doc).is_none());
    assert_eq!(doc.get_tree("outline").get_nodes(false).len(), 0);
    assert_eq!(
        items(doc.get_movable_list("order").get_deep_value()),
        ["a", "b"]
    );
    carols.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "base carol");
}

/// The text's runs, each with its style keys.
fn styled(doc: &LoroDoc) -> Vec<(String, Vec<String>)> {
    doc.get_text("body")
        .to_delta()
        .into_iter()
        .filter_map(|step| match step {
            frasil::loro::TextDelta::Insert { insert, attributes } => {
                let mut keys: Vec<String> = attributes
                    .map(|attributes| attributes.keys().cloned().collect())
                    .unwrap_or_default();
                keys.sort();
                Some((insert, keys))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writers_own_moves_sets_marks_and_deletions_are_expressed_at_every_member() {
    // Bob moves an item, bolds Alice's text and types his own. Carol, over
    // all of it, moves one item earlier and one later, sets one, bolds a
    // word and deletes one. Bob is removed: Carol's handle, her replica and
    // Alice's read Alice's base with exactly Carol's operations.
    let (alice, bob, carol, space, document) = bob_writes_for_carol(
        [80, 81, 82],
        |doc| {
            doc.get_text("body").insert(0, "base text").unwrap();
            let order = doc.get_movable_list("order");
            for item in ["a", "b", "c", "d", "e"] {
                order.push(item).unwrap();
            }
        },
        |doc| {
            // [b, c, d, e, a], "base bob text" with "base" bold.
            doc.get_movable_list("order").mov(0, 4).unwrap();
            let text = doc.get_text("body");
            text.mark(0..4, "bold", true).unwrap();
            text.insert(5, "bob ").unwrap();
        },
    )
    .await;
    let id = event_of(&space);
    let carols_doc = space_of(&carol, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let carols = carols_doc.lend().await.unwrap();
    let doc = carols.doc();
    let order = doc.get_movable_list("order");
    // d to the front, b after e, c set to C.
    order.mov(2, 0).unwrap();
    order.mov(1, 3).unwrap();
    order.set(1, "C").unwrap();
    assert_eq!(items(order.get_deep_value()), ["d", "C", "e", "b", "a"]);
    // "text" bold, "base " deleted.
    let text = doc.get_text("body");
    text.mark(9..13, "bold", true).unwrap();
    text.delete(0, 5).unwrap();
    assert_eq!(body(&doc), "bob text");
    doc.commit();
    carols.flush().await.unwrap();
    let mut replaced = carols.replaced();
    let failed = carols.failed();
    space.remove(bob.id()).await.unwrap();
    carry(alice.engine(), carol.engine(), id).await;
    within(replaced.changed()).await.unwrap();
    assert!(failed.borrow().is_none(), "{:?}", failed.borrow());
    carols.flush().await.unwrap();
    carry(carol.engine(), alice.engine(), id).await;
    // Carol moved d to the front: it goes there. b goes after e, where she
    // put it, and a, without Bob's move, after d.
    let expected_order = ["d", "a", "C", "e", "b"];
    let expected_text = vec![("text".to_string(), vec!["bold".to_string()])];
    for (replica, doc) in [
        ("Carol's handle", carols.doc()),
        ("Carol", carols_doc.read().await.unwrap()),
        ("Alice", document.read().await.unwrap()),
    ] {
        assert_eq!(
            items(doc.get_movable_list("order").get_deep_value()),
            expected_order,
            "list at {replica}"
        );
        assert_eq!(styled(&doc), expected_text, "text at {replica}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_lends_reads_and_its_commit_is_refused() {
    // Bob reads: he lends the document and sees Alice's edits as they
    // arrive. A commit he makes is refused as a unit, reported through
    // `failed()`, and reaches no one.
    let alice = device(90).await;
    let bob = device(91).await;
    let space = with_member(&alice, &bob, Level::Read).await;
    let id = event_of(&space);
    let document = space.create_document().unwrap();
    document
        .edit(|doc| doc.get_text("body").insert(0, "one"))
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    let bobs_doc = space_of(&bob, &space)
        .await
        .document(document.id())
        .await
        .unwrap();
    let bobs = bobs_doc.lend().await.unwrap();
    assert_eq!(body(&bobs.doc()), "one");
    document
        .edit(|doc| doc.get_text("body").insert(3, " two"))
        .await
        .unwrap();
    carry(alice.engine(), bob.engine(), id).await;
    until(|| async { body(&bobs.doc()) == "one two" }).await;

    let before = units(bob.engine(), id).await;
    let mut failed = bobs.failed();
    bobs.doc().get_text("body").insert(0, "bob ").unwrap();
    bobs.doc().commit();
    assert!(bobs.flush().await.is_err(), "a reader's unit is refused");
    within(async {
        while failed.borrow_and_update().is_none() {
            failed.changed().await.unwrap();
        }
    })
    .await;
    assert!(
        matches!(&*failed.borrow(), Some(Error::NotAllowed(_))),
        "{:?}",
        failed.borrow()
    );
    assert_eq!(units(bob.engine(), id).await, before, "no unit written");
    carry(bob.engine(), alice.engine(), id).await;
    assert_eq!(document.text("body").await.unwrap(), "one two");
}
