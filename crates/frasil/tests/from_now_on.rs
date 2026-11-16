//! A device member admitted "from now on": a break, a space snapshot with
//! its base, stubs, body keys and history-free documents, and the
//! `frasil:body-keys` units writers publish.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::{AdapterRegistry, Engine, ManualClock, Platform};
use frasil_events::{EventId, kind};
use frasil_space::keygraph::{delay, rank_order};
use frasil_space::{HistoryMode, Level, Status, Via};
use std::future::Future;
use std::sync::Arc;

async fn device() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

/// The events of a space that are not units: what a newcomer holds in
/// full.
async fn frame_events(device: &Engine, space: &EventId) -> Vec<Vec<u8>> {
    device
        .events(space)
        .await
        .into_iter()
        .filter(|signed| frasil_events::decode(signed).is_ok_and(|e| e.kind() != kind::UNIT))
        .collect()
}

/// Alice's space with a document, and Bob admitted from now on, started
/// from Alice's snapshot.
async fn admitted() -> (
    Engine,
    Engine,
    EventId,
    frasil_units::stream::Opening,
    EventId,
) {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before the break").unwrap();
        })
        .await
        .unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    (alice, bob, space, doc, admitting)
}

#[tokio::test]
async fn a_newcomer_from_now_on_starts_from_the_snapshot() {
    let (alice, bob, space, doc, admitting) = admitted().await;
    let (unresolved, level, genesis, grant, holds_genesis_key) = bob
        .read(&space, |r| {
            (
                r.unresolved(),
                r.level_of(&bob.device_id()),
                r.status(&space).copied(),
                r.status(&admitting).copied(),
                r.secrets_held(&space),
            )
        })
        .await
        .unwrap();
    assert_eq!(unresolved, None);
    assert_eq!(level, Some(Level::Write));
    assert!(matches!(genesis, Some(Status::Valid(_))), "{genesis:?}");
    assert!(matches!(grant, Some(Status::Valid(_))), "{grant:?}");
    // It reads the roster's history through body keys, never a content
    // key from before its break.
    assert!(!holds_genesis_key);
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "before the break");

    // Bob writes after his break; Alice reads it.
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "> ").unwrap();
    })
    .await
    .unwrap();
    alice.ingest(space, bob.events(&space).await).await.unwrap();
    let seen = alice.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "> before the break");

    // Every event Alice holds, the units from before the base included,
    // changes nothing at Bob: those are decided, held as stubs.
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "> before the break");
    assert_eq!(bob.read(&space, |r| r.unresolved()).await.unwrap(), None);
}

#[tokio::test]
async fn a_newcomer_reopens_from_its_store() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let alice = device().await;
    let (bob, sealed) = Engine::create(platform.clone(), &[4; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    drop(bob);
    let bob = Engine::open(platform, &sealed, &[4; 32], registry)
        .await
        .unwrap();
    let (genesis, level) = bob
        .read(&space, |r| {
            (r.status(&space).copied(), r.level_of(&bob.device_id()))
        })
        .await
        .unwrap();
    assert!(matches!(genesis, Some(Status::Valid(_))), "{genesis:?}");
    assert_eq!(level, Some(Level::Write));
}

#[tokio::test]
async fn a_body_keys_unit_opens_an_event_the_newcomer_could_not() {
    // Carol heals concurrently with Bob's break, under the state before it:
    // Bob cannot open her heal until a writer that opened it publishes its
    // body key (admission.md, "Top-ups").
    let alice = device().await;
    let carol = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            carol.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.follow(space).await;
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let heal = carol.heal(space).await.unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    bob.ingest(space, frame_events(&carol, &space).await)
        .await
        .unwrap();
    let held = bob
        .read(&space, |r| r.status(&heal).and_then(|s| s.class()))
        .await
        .unwrap();
    assert_eq!(held.map(frasil_base::errors::Class::name), Some("Sealed"));

    // Alice, who opened the heal, merges it with the break by a rotation
    // of her own, then publishes its body key under that state.
    alice
        .ingest(space, carol.events(&space).await)
        .await
        .unwrap();
    alice.heal(space).await.unwrap();
    alice.publish_body_keys(space, &[heal]).await.unwrap();
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let status = bob
        .read(&space, |r| r.status(&heal).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
}

#[tokio::test]
async fn a_writer_tops_up_an_event_concurrent_with_a_break() {
    // Carol grants Dave concurrently with Bob's break, sealed under the
    // state before it, as a claim's successor is beside the next invite:
    // the grant does not rotate, so the current state stays Bob's break.
    // With no body key published by hand, each writer that opened Carol's
    // grant tops it up after its rank delay, and stands down once a
    // body-keys unit after Bob's break carries it (admission.md, "Top-ups").
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let open = |key: u8| {
        let clock = clock.clone();
        async move {
            Engine::create(
                Platform::memory().with_clock(clock),
                &[key; 32],
                AdapterRegistry::with_builtins(),
            )
            .await
            .expect("a device")
            .0
        }
    };
    let alice = open(1).await;
    let carol = open(2).await;
    let bob = open(3).await;
    let dave = open(4).await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_administrator(
            space,
            carol.public_keys().clone(),
            255,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.follow(space).await;
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let grant = carol
        .grant_device(
            space,
            dave.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    for from in [&alice, &carol] {
        bob.ingest(space, frame_events(from, &space).await)
            .await
            .unwrap();
    }
    alice
        .ingest(space, carol.events(&space).await)
        .await
        .unwrap();
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let sealed = |device: &Engine| {
        let device = device.clone();
        async move {
            device
                .read(&space, |r| {
                    r.status(&grant)
                        .and_then(|s| s.class())
                        .map(frasil_base::errors::Class::name)
                })
                .await
                .unwrap()
        }
    };
    assert_eq!(sealed(&bob).await, Some("Sealed"));
    // Bob cannot open the grant, so he owes nothing.
    assert!(bob.top_up(space).await.unwrap().is_empty());

    // The writer ranked later of Alice and Carol waits its delay.
    let writers = [
        alice.device_id().0,
        carol.device_id().0,
        bob.device_id().0,
        dave.device_id().0,
    ];
    let order = rank_order(&space.0, &grant.0, &writers);
    let position = |d: &Engine| order.iter().position(|w| *w == d.device_id().0).unwrap() as u64;
    let (first, later) = if position(&alice) < position(&carol) {
        (&alice, &carol)
    } else {
        (&carol, &alice)
    };
    assert!(later.top_up(space).await.unwrap().is_empty());
    clock.advance(delay(position(later), 5));
    let written = later.top_up(space).await.unwrap();
    assert_eq!(written.len(), 1);
    // Once it holds that unit, the other writer stands down, and neither
    // writes it again.
    first
        .ingest(space, later.events(&space).await)
        .await
        .unwrap();
    clock.advance(60);
    assert!(first.top_up(space).await.unwrap().is_empty());
    assert!(later.top_up(space).await.unwrap().is_empty());

    bob.ingest(space, later.events(&space).await).await.unwrap();
    let status = bob
        .read(&space, |r| r.status(&grant).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
}

/// Carries sync messages between two members' sessions until neither has
/// anything more to send.
async fn pump(
    a: (&Engine, &mut frasil::advanced::sync::SyncSession),
    b: (&Engine, &mut frasil::advanced::sync::SyncSession),
    first: Vec<frasil_units::messages::SyncMessage>,
) {
    use frasil::advanced::Acknowledger;
    let (a, a_session) = a;
    let (b, b_session) = b;
    let mut to_b = first;
    let mut to_a = Vec::new();
    for _ in 0..64 {
        if to_a.is_empty() && to_b.is_empty() {
            return;
        }
        for message in std::mem::take(&mut to_b) {
            to_a.extend(
                b.sync_receive(b_session, Acknowledger::Member(a.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
        for message in std::mem::take(&mut to_a) {
            to_b.extend(
                a.sync_receive(a_session, Acknowledger::Member(b.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
    }
}

#[tokio::test]
async fn a_newcomer_that_restarts_before_its_snapshot_asks_a_member() {
    use frasil::advanced::sync::SyncSession;
    use frasil::advanced::{MemorySlot, MemoryStore};
    use std::sync::Arc;
    let alice = device().await;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn frasil_store::DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let platform = Platform::new(store, slot);
    let (bob, sealed) = Engine::create(platform.clone(), &[8; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before the break").unwrap();
        })
        .await
        .unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    // Bob takes the space's frame, then stops before he used a snapshot.
    bob.follow(space).await;
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    bob.keep_reading().await.unwrap();
    drop(bob);
    let bob = Engine::open(platform, &sealed, &[8; 32], registry)
        .await
        .unwrap();

    // Opened again, he asks a member for a snapshot before anything else.
    let mut bobs = SyncSession::new(space);
    let mut alices = SyncSession::new(space);
    let first = bob.sync_start(&mut bobs).await.unwrap();
    assert!(
        matches!(
            first.as_slice(),
            [frasil_units::messages::SyncMessage {
                message: frasil_units::messages::Message::SnapshotWant { .. },
                ..
            }]
        ),
        "{first:?}"
    );
    pump((&bob, &mut bobs), (&alice, &mut alices), first).await;
    // Alice's snapshot, its objects, then the space's events: Bob reads
    // the document's history-free state.
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "before the break"
    );
}

/// Bob, admitted from now on by Alice, restarted before he used a
/// snapshot: he waits for any member's (admission.md, "The newcomer's
/// snapshot"). With the admitting event.
async fn waiting_for_a_snapshot() -> (Engine, Engine, EventId, EventId) {
    use frasil::advanced::{MemorySlot, MemoryStore};
    let alice = device().await;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn frasil_store::DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let platform = Platform::new(store, slot);
    let (bob, sealed) = Engine::create(platform.clone(), &[8; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before the break").unwrap();
        })
        .await
        .unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    bob.follow(space).await;
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    bob.keep_reading().await.unwrap();
    drop(bob);
    let bob = Engine::open(platform, &sealed, &[8; 32], registry)
        .await
        .unwrap();
    (alice, bob, space, admitting)
}

/// Whether a device opens a new session by asking for a space snapshot:
/// it waits for one.
async fn asks_for_a_snapshot(device: &Engine, space: EventId) -> bool {
    let mut session = frasil::advanced::sync::SyncSession::new(space);
    matches!(
        device.sync_start(&mut session).await.unwrap().as_slice(),
        [frasil_units::messages::SyncMessage {
            message: frasil_units::messages::Message::SnapshotWant { .. },
            ..
        }]
    )
}

/// units.md, "The space snapshot": an offer is taken only on a session
/// that asked for one, and only when its sender is the device the
/// connection identified.
#[tokio::test]
async fn a_snapshot_offer_is_taken_only_where_asked_and_from_its_sender() {
    use frasil::advanced::Acknowledger;
    use frasil::advanced::sync::SyncSession;
    let (alice, bob, space, admitting) = waiting_for_a_snapshot().await;
    let carol = device().await;
    let made = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    let offer = frasil_units::messages::SyncMessage {
        space,
        message: frasil_units::messages::Message::SnapshotOffer {
            snapshot: made.signed.clone(),
        },
    };
    let from_alice = Acknowledger::Member(alice.device_id().0);
    // A session on which Bob asked for nothing.
    let mut quiet = SyncSession::new(space);
    bob.sync_receive(&mut quiet, from_alice, offer.clone())
        .await
        .unwrap();
    assert!(asks_for_a_snapshot(&bob, space).await);
    // A session that asked, and an offer Alice signed on a connection
    // that identified Carol.
    let mut asked = SyncSession::new(space);
    let first = bob.sync_start(&mut asked).await.unwrap();
    assert!(matches!(
        first[0].message,
        frasil_units::messages::Message::SnapshotWant { .. }
    ));
    bob.sync_receive(
        &mut asked,
        Acknowledger::Member(carol.device_id().0),
        offer.clone(),
    )
    .await
    .unwrap();
    assert!(asks_for_a_snapshot(&bob, space).await);
    // From Alice, on the session that asked: taken.
    bob.sync_receive(&mut asked, from_alice, offer)
        .await
        .unwrap();
    assert!(!asks_for_a_snapshot(&bob, space).await);
}

/// units.md, "The space snapshot", "Using it": once the view grants the
/// newcomer, the snapshot's sender must reach the space. A member removed
/// by the time the newcomer's view resolves was not entitled to hand it
/// the space: the base is discarded, and the newcomer asks for a snapshot
/// again.
#[tokio::test]
async fn a_snapshot_from_a_sender_that_no_longer_reaches_the_space_is_discarded() {
    let alice = device().await;
    let bob = device().await;
    let dave = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before the break").unwrap();
        })
        .await
        .unwrap();
    alice
        .grant_device(
            space,
            dave.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    dave.follow(space).await;
    dave.ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let made = dave.newcomer_snapshot(&space, admitting).await.unwrap();
    alice
        .remove(space, frasil_space::MemberRef::device(dave.device_id()))
        .await
        .unwrap();
    bob.adopt_snapshot(space, &made.signed, made.parts())
        .await
        .unwrap();
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    assert!(asks_for_a_snapshot(&bob, space).await);
    assert!(
        !bob.read(&space, |r| r.snapshot_unconfirmed())
            .await
            .unwrap()
    );
}

#[cfg(feature = "adapter-blobs")]
#[tokio::test]
async fn a_member_announces_the_objects_it_sends_and_serves_them() {
    use frasil::advanced::sync::SyncSession;
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let files = alice
        .new_stream(<frasil_adapter_blobs::Blobs as frasil_adapter::Adapter>::TYPE)
        .unwrap();
    // A blob of three chunks and a little.
    let blob = vec![7u8; 3 * frasil_units::limits::CHUNK_BYTES + 5];
    let (_, locator) = alice
        .put_blob(space, &files, Some("photo"), &blob)
        .await
        .unwrap();
    bob.follow(space).await;
    let mut bobs = SyncSession::new(space);
    let mut alices = SyncSession::new(space);
    let first = bob.sync_start(&mut bobs).await.unwrap();
    let alice_first = alice.sync_start(&mut alices).await.unwrap();
    let mut both = first;
    // Each side opens with its heads; Alice's events come with an
    // `ObjectHave`, Bob asks, and she serves the chunks.
    for message in alice_first {
        both.extend(
            bob.sync_receive(
                &mut bobs,
                frasil::advanced::Acknowledger::Member(alice.device_id().0),
                message,
            )
            .await
            .unwrap(),
        );
    }
    pump((&bob, &mut bobs), (&alice, &mut alices), both).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), blob);
}

/// Engines on one manual clock.
fn on_clock(
    clock: &Arc<ManualClock>,
) -> impl Fn(u8) -> std::pin::Pin<Box<dyn Future<Output = Engine>>> {
    let clock = clock.clone();
    move |key: u8| {
        let clock = clock.clone();
        Box::pin(async move {
            Engine::create(
                Platform::memory().with_clock(clock),
                &[key; 32],
                AdapterRegistry::with_builtins(),
            )
            .await
            .expect("a device")
            .0
        })
    }
}

/// Of two writers, the one the rank puts first for `trigger`, then the
/// other.
fn ranked<'a>(
    space: &EventId,
    trigger: &[u8],
    a: &'a Engine,
    b: &'a Engine,
    writers: &[[u8; 32]],
) -> ((&'a Engine, u64), (&'a Engine, u64)) {
    let order = rank_order(&space.0, trigger, writers);
    let position = |d: &Engine| order.iter().position(|w| *w == d.device_id().0).unwrap() as u64;
    let (pa, pb) = (position(a), position(b));
    if pa < pb {
        ((a, pa), (b, pb))
    } else {
        ((b, pb), (a, pa))
    }
}

#[tokio::test]
async fn a_writer_tops_up_a_unit_concurrent_with_a_break() {
    // Carol edits the document while Alice admits Bob from now on, before
    // she sees his break: her unit is sealed under the state before it, so
    // Bob holds it, and Alice's next edit after it, until a writer tops up
    // the unit's body key (admission.md, "Top-ups").
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let open = on_clock(&clock);
    let alice = open(1).await;
    let carol = open(2).await;
    let bob = open(3).await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "base").unwrap();
        })
        .await
        .unwrap();
    alice
        .grant_device(
            space,
            carol.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.follow(space).await;
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    carol
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "carol ").unwrap();
        })
        .await
        .unwrap();
    let edit = carol.events(&space).await;
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    bob.ingest(space, frame_events(&alice, &space).await)
        .await
        .unwrap();
    alice.ingest(space, edit.clone()).await.unwrap();
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    alice
        .edit_document(space, &doc, |d| {
            let at = d.get_text("body").len_unicode();
            d.get_text("body").insert(at, " alice").unwrap();
        })
        .await
        .unwrap();
    let carols_unit = edit
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .find(|e| e.kind() == kind::UNIT && *e.author() == carol.device_id())
        .map(|e| e.id())
        .expect("Carol's unit");
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let class = |device: &Engine| {
        let device = device.clone();
        async move {
            device
                .read(&space, |r| {
                    r.status(&carols_unit)
                        .and_then(|s| s.class())
                        .map(frasil_base::errors::Class::name)
                })
                .await
                .unwrap()
        }
    };
    assert_eq!(class(&bob).await, Some("Sealed"));
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "base");
    assert!(bob.top_up(space).await.unwrap().is_empty());

    // The later of Alice and Carol waits its delay; the first writes.
    let writers = [alice.device_id().0, carol.device_id().0, bob.device_id().0];
    let ((first, _), (later, position)) = ranked(&space, &carols_unit.0, &alice, &carol, &writers);
    assert!(later.top_up(space).await.unwrap().is_empty());
    clock.advance(delay(position, 5));
    let written = later.top_up(space).await.unwrap();
    assert_eq!(written.len(), 1);
    first
        .ingest(space, later.events(&space).await)
        .await
        .unwrap();
    clock.advance(60);
    assert!(first.top_up(space).await.unwrap().is_empty());
    assert!(later.top_up(space).await.unwrap().is_empty());

    // Bob reads Carol's edit, and Alice's after it.
    bob.ingest(space, later.events(&space).await).await.unwrap();
    bob.ingest(space, first.events(&space).await).await.unwrap();
    let status = bob
        .read(&space, |r| r.status(&carols_unit).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "carol base alice");
}

#[tokio::test]
async fn a_newcomer_receives_the_state_its_break_merges_into() {
    // Carol rotates while Alice admits Bob from now on. The current state
    // merges both rotations; Bob holds only his break's key, so a writer
    // delivers him the merged state (keys.md, "Deliveries"), and he reads
    // what is written under it.
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let open = on_clock(&clock);
    let alice = open(1).await;
    let carol = open(2).await;
    let bob = open(3).await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "base").unwrap();
        })
        .await
        .unwrap();
    alice
        .grant_device(
            space,
            carol.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.follow(space).await;
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let rotation = carol.heal(space).await.unwrap();
    let admitting = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .unwrap();
    let snapshot = alice.newcomer_snapshot(&space, admitting).await.unwrap();
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    alice
        .ingest(space, carol.events(&space).await)
        .await
        .unwrap();
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    let merged = alice.read(&space, |r| r.current().cloned()).await.unwrap();
    assert_eq!(
        merged.as_ref().map(|s| s.ids().to_vec()),
        Some({
            let mut ids = vec![rotation, admitting];
            ids.sort();
            ids
        })
    );
    alice
        .edit_document(space, &doc, |d| {
            let at = d.get_text("body").len_unicode();
            d.get_text("body").insert(at, " merged").unwrap();
        })
        .await
        .unwrap();
    // The rotation's body key goes out as a top-up, sealed under the
    // merged state, which Bob cannot derive: he reads nothing new yet.
    let ((first, _), (later, position)) = {
        let writers = [alice.device_id().0, carol.device_id().0, bob.device_id().0];
        ranked(&space, &rotation.0, &alice, &carol, &writers)
    };
    clock.advance(delay(position, 5));
    first.top_up(space).await.unwrap();
    later.top_up(space).await.unwrap();
    for from in [&alice, &carol] {
        bob.ingest(space, from.events(&space).await).await.unwrap();
    }
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "base");

    // One writer delivers the merged state after its rank delay; the other
    // stands down once it holds that delivery.
    let trigger = merged.as_ref().unwrap().encode();
    let writers = [alice.device_id().0, carol.device_id().0];
    let ((first, _), (later, position)) = ranked(&space, &trigger, &alice, &carol, &writers);
    clock.advance(delay(position, 5));
    let delivered = first.maintain(space).await.unwrap().delivery;
    assert!(delivered.is_some());
    later
        .ingest(space, first.events(&space).await)
        .await
        .unwrap();
    assert_eq!(later.maintain(space).await.unwrap().delivery, None);
    assert_eq!(first.maintain(space).await.unwrap().delivery, None);

    bob.ingest(space, first.events(&space).await).await.unwrap();
    let status = bob
        .read(&space, |r| r.status(&rotation).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "base merged");
}

/// units.md, "A base": the stubs of a space snapshot's base stand
/// confirmed on the sender's signature. The admitting grant names Alice's
/// unit from before the base, which Bob places it on without holding it
/// in full, never asks for, and does not place when it arrives; it matches
/// its stub, so nothing is reported against the sender.
#[tokio::test]
async fn a_newcomer_stops_at_its_base_stubs() {
    let (alice, bob, space, _doc, admitting) = admitted().await;
    let events: Vec<frasil_events::Event> = alice
        .events(&space)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .collect();
    let is_unit = |id: &EventId| {
        events
            .iter()
            .any(|event| event.id() == *id && event.kind() == kind::UNIT)
    };
    let units_named: Vec<EventId> = events
        .iter()
        .find(|event| event.id() == admitting)
        .expect("the admitting grant")
        .parents()
        .iter()
        .copied()
        .filter(|parent| is_unit(parent))
        .collect();
    assert!(!units_named.is_empty(), "the grant names Alice's unit");
    assert!(stopped_at_base(&bob, space, &units_named).await);
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    assert!(stopped_at_base(&bob, space, &units_named).await);
}

/// Whether each unit stands at the device as a confirmed base stub, not
/// held in full and not asked for, with nothing reported against the
/// snapshot's sender.
async fn stopped_at_base(device: &Engine, space: EventId, units: &[EventId]) -> bool {
    device
        .read(&space, |r| {
            let log = r.log().expect("the device holds the log");
            let wanted = r.wanted();
            units
                .iter()
                .all(|id| log.is_stub_confirmed(*id) && !log.contains(*id) && !wanted.contains(id))
                && r.contradicted_base().is_empty()
        })
        .await
        .unwrap()
}
