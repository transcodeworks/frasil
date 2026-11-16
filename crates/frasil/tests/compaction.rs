//! Compaction: a snapshot unit and its stream snapshot object, checked at a
//! member that holds the stream past, and used in place of its cover by a
//! member that holds none of it.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::{EventId, kind};
use frasil_space::{HistoryMode, Level, Status, Via};

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

/// Every event of a space but the units of one stream before `keep`.
async fn without_units(device: &Engine, space: &EventId, keep: &[EventId]) -> Vec<Vec<u8>> {
    device
        .events(space)
        .await
        .into_iter()
        .filter(|signed| {
            frasil_events::decode(signed)
                .is_ok_and(|e| e.kind() != kind::UNIT || keep.contains(&e.id()))
        })
        .collect()
}

#[tokio::test]
async fn a_compaction_is_checked_and_used_in_place_of_its_cover() {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for other in [&bob, &carol] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let doc = alice.new_document().unwrap();
    for word in ["one", " two", " three"] {
        alice
            .edit_document(space, &doc, |d| {
                let body = d.get_text("body");
                body.insert(body.len_unicode(), word).unwrap();
            })
            .await
            .unwrap();
    }
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), " four").unwrap();
        })
        .await
        .unwrap();
    let after = alice.events(&space).await;
    let status = alice
        .read(&space, |r| r.status(&snapshot).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");

    // Bob holds the stream past: he checks the snapshot and rebuilds from
    // the units.
    bob.follow(space).await;
    bob.ingest(space, after.clone()).await.unwrap();
    let (bad, used) = bob
        .read(&space, |r| {
            (r.bad_compactions().clone(), r.used_snapshots().clone())
        })
        .await
        .unwrap();
    assert!(bad.is_empty() && used.is_empty(), "{bad:?} {used:?}");
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "one two three four"
    );

    // Carol holds none of the cover: the snapshot unit places against its
    // stubs, and its state stands in for the cover.
    let later: Vec<EventId> = after
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|e| e.kind() == kind::UNIT)
        .map(|e| e.id())
        .skip_while(|id| *id != snapshot)
        .collect();
    let locator = alice
        .read(&space, |r| {
            r.event(snapshot)
                .and_then(|e| frasil_units::Unit::from_event(e.clone()).ok())
                .and_then(|u| u.body.compacts.map(|c| c.object))
        })
        .await
        .unwrap()
        .expect("a snapshot unit");
    let stored = alice.stored_object(&space, &locator).await.unwrap();
    carol.follow(space).await;
    carol
        .receive_object(space, &locator, &stored)
        .await
        .unwrap();
    carol
        .ingest(space, without_units(&alice, &space, &later).await)
        .await
        .unwrap();
    let used = carol
        .read(&space, |r| r.used_snapshots().clone())
        .await
        .unwrap();
    assert!(used.contains(&snapshot), "{used:?}");
    assert_eq!(
        text(&carol.document(&space, &doc.stream()).await.unwrap()),
        "one two three four"
    );
}

#[tokio::test]
async fn a_missing_unit_is_placed_against_the_stub_its_carrier_holds() {
    use frasil::advanced::sync::SyncSession;
    use frasil_units::messages::{Message, SyncMessage};
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for other in [&bob, &carol] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let doc = alice.new_document().unwrap();
    let mut words = Vec::new();
    for word in ["one", " two", " three"] {
        words.push(
            alice
                .edit_document(space, &doc, |d| {
                    let body = d.get_text("body");
                    body.insert(body.len_unicode(), word).unwrap();
                })
                .await
                .unwrap(),
        );
    }
    // Bob writes in another document, citing Alice's last unit.
    bob.follow(space).await;
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let other = bob.new_document().unwrap();
    let bobs = bob
        .edit_document(space, &other, |d| {
            d.get_text("body").insert(0, "Bob").unwrap();
        })
        .await
        .unwrap();
    alice.ingest(space, bob.events(&space).await).await.unwrap();
    // Alice compacts her document: its units are the snapshot's cover.
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    let mut all = alice.events(&space).await;
    all.extend(bob.events(&space).await);
    let signed_of = |id: EventId| {
        all.iter()
            .find(|s| frasil_events::decode(s).is_ok_and(|e| e.id() == id))
            .cloned()
            .unwrap()
    };
    // Carol holds everything but the cover and the snapshot unit: Bob's
    // unit waits for Alice's last unit.
    carol.follow(space).await;
    let held: Vec<Vec<u8>> = all
        .iter()
        .filter(|s| {
            frasil_events::decode(s).is_ok_and(|e| !words.contains(&e.id()) && e.id() != snapshot)
        })
        .cloned()
        .collect();
    carol.ingest(space, held).await.unwrap();
    let wanted = carol.read(&space, |r| r.wanted()).await.unwrap();
    assert!(wanted.contains(&words[2]), "{wanted:?}");

    // The other side has collected it: its `Missing` names the snapshot
    // unit that carries its stub, and Carol asks for that unit instead.
    let mut session = SyncSession::new(space);
    let out = carol
        .sync_receive(
            &mut session,
            frasil::advanced::Acknowledger::Member(alice.device_id().0),
            SyncMessage {
                space,
                message: Message::Missing {
                    ids: Vec::new(),
                    carried: vec![(words[2], snapshot)],
                },
            },
        )
        .await
        .unwrap();
    assert!(
        out.iter().any(|m| matches!(
            &m.message,
            Message::Want { ids, .. } if ids.contains(&snapshot) && !ids.contains(&words[2])
        )),
        "{out:?}"
    );
    carol
        .sync_receive(
            &mut session,
            frasil::advanced::Acknowledger::Member(alice.device_id().0),
            SyncMessage {
                space,
                message: Message::Events {
                    events: vec![signed_of(snapshot)],
                },
            },
        )
        .await
        .unwrap();
    // Bob's unit is placed against the stub.
    let placed = carol
        .read(&space, |r| r.log().is_some_and(|log| log.contains(bobs)))
        .await
        .unwrap();
    assert!(placed);
}

async fn three_writers() -> (
    Engine,
    Engine,
    Engine,
    EventId,
    frasil_units::stream::Opening,
) {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for other in [&bob, &carol] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let doc = alice.new_document().unwrap();
    for word in ["one", " two", " three"] {
        alice
            .edit_document(space, &doc, |d| {
                let body = d.get_text("body");
                body.insert(body.len_unicode(), word).unwrap();
            })
            .await
            .unwrap();
    }
    for other in [&bob, &carol] {
        other.follow(space).await;
        other
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
    }
    (alice, bob, carol, space, doc)
}

#[tokio::test]
async fn a_settled_snapshot_is_used_and_its_cover_collected() {
    use frasil::advanced::{AdapterRegistry, MemorySlot, MemoryStore, Platform};
    use frasil_store::DeviceBoundSlot;
    use std::sync::Arc;
    let (alice, _, _, space, doc) = three_writers().await;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let platform = Platform::new(store, slot);
    let registry = AdapterRegistry::with_builtins();
    let (dave, sealed) = Engine::create(platform.clone(), &[4; 32], registry.clone())
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
    dave.follow(space).await;
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    let locator = alice
        .read(&space, |r| {
            r.event(snapshot)
                .and_then(|e| frasil_units::Unit::from_event(e.clone()).ok())
                .and_then(|u| u.body.compacts.map(|c| c.object))
        })
        .await
        .unwrap()
        .unwrap();
    let stored = alice.stored_object(&space, &locator).await.unwrap();
    dave.receive_object(space, &locator, &stored).await.unwrap();
    dave.ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    // Alice administers alone and signed the snapshot unit: it is stable,
    // so settled. Dave uses it and collects its cover, but for the last
    // unit, which his own grant names as a parent: he places that space
    // event against the unit in full, never against a stub only the
    // compactor signed (units.md, "Confirming heights").
    let collected = dave.collect(space).await.unwrap();
    assert_eq!(collected.len(), 2, "{collected:?}");
    assert!(
        dave.read(&space, |r| r.used_snapshots().contains(&snapshot))
            .await
            .unwrap()
    );
    dave.keep_reading().await.unwrap();
    drop(dave);
    // Opened again, Dave holds none of the cover, and reads the document
    // from the snapshot.
    let dave = Engine::open(platform, &sealed, &[4; 32], registry)
        .await
        .unwrap();
    let held = dave
        .read(&space, |r| {
            collected
                .iter()
                .filter(|id| r.event(**id).is_some())
                .count()
        })
        .await
        .unwrap();
    assert_eq!(held, 0);
    assert_eq!(
        text(&dave.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );
}

#[tokio::test]
async fn a_refused_snapshot_is_restored_once() {
    let (alice, bob, carol, space, doc) = three_writers().await;
    // Alice removes Carol; Carol, not knowing, compacts.
    alice
        .remove(space, frasil_space::MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    let snapshot = carol.compact(space, doc.stream()).await.unwrap();
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    bob.ingest(space, carol.events(&space).await).await.unwrap();
    let refused = bob
        .read(&space, |r| {
            r.status(&snapshot).is_some_and(|s| !s.is_valid())
        })
        .await
        .unwrap();
    assert!(refused);
    // Bob, a writer, stores a restore that names it, once.
    assert_eq!(bob.restore_compactions(space).await.unwrap().len(), 1);
    assert!(bob.restore_compactions(space).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_peer_that_lists_less_than_a_device_holds_withholds() {
    use frasil_units::messages::StreamWriter;
    let (alice, bob, _, space, doc) = three_writers().await;
    let units: Vec<(EventId, u64)> = alice
        .events(&space)
        .await
        .iter()
        .filter_map(|s| frasil_events::decode(s).ok())
        .filter(|e| {
            e.kind() == kind::UNIT
                && frasil_units::Unit::from_event(e.clone())
                    .is_ok_and(|u| u.body.stream == doc.stream())
        })
        .map(|e| (e.id(), e.seq()))
        .collect();
    let (last, seq) = *units.last().unwrap();
    let writer = |unit, seq| StreamWriter {
        writer: alice.device_id(),
        unit,
        seq,
    };
    // A full listing: nothing missing, nothing withheld.
    let (missing, withheld) = bob
        .stream_heads_check(space, doc.stream(), None, &[writer(last, seq)])
        .await;
    assert!(missing.is_empty() && !withheld);
    // A listing that stops at an older unit than Bob holds withholds.
    let (first, first_seq) = units[0];
    let (_, withheld) = bob
        .stream_heads_check(space, doc.stream(), None, &[writer(first, first_seq)])
        .await;
    assert!(withheld);
    // A unit listed that Bob lacks is asked for.
    let unknown = EventId([9; 32]);
    let (missing, _) = bob
        .stream_heads_check(space, doc.stream(), None, &[writer(unknown, seq + 1)])
        .await;
    assert_eq!(missing, vec![unknown]);
}

/// A writer the latest snapshot covers is still listed for its units after
/// the snapshot (units.md, 3.14 "By stream"): a listing that stops at the
/// snapshot withholds the unit written after it.
#[tokio::test]
async fn a_peer_that_lists_a_covered_writer_short_of_its_later_units_withholds() {
    use frasil_units::messages::StreamWriter;
    let (alice, bob, _, space, doc) = three_writers().await;
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    alice
        .edit_document(space, &doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), " four").unwrap();
        })
        .await
        .unwrap();
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let seq_of = |signed: &[Vec<u8>], id: EventId| {
        signed
            .iter()
            .filter_map(|s| frasil_events::decode(s).ok())
            .find(|e| e.id() == id)
            .map(|e| e.seq())
            .unwrap()
    };
    let events = alice.events(&space).await;
    let after = *units_of(&events, doc.stream()).last().unwrap();
    assert_ne!(after, snapshot);
    let writer = |unit, seq| StreamWriter {
        writer: alice.device_id(),
        unit,
        seq,
    };
    // Listed at the unit after the snapshot: nothing withheld.
    let (_, withheld) = bob
        .stream_heads_check(
            space,
            doc.stream(),
            Some(snapshot),
            &[writer(after, seq_of(&events, after))],
        )
        .await;
    assert!(!withheld);
    // Listed at the snapshot unit, which covers Alice: the unit after it
    // is withheld.
    let (_, withheld) = bob
        .stream_heads_check(
            space,
            doc.stream(),
            Some(snapshot),
            &[writer(snapshot, seq_of(&events, snapshot))],
        )
        .await;
    assert!(withheld);
    // Alice left out altogether.
    let (_, withheld) = bob
        .stream_heads_check(space, doc.stream(), Some(snapshot), &[])
        .await;
    assert!(withheld);
}

/// The locator of a snapshot unit's stream snapshot object, and the object
/// as its writer stores it.
async fn snapshot_object(
    writer: &Engine,
    space: EventId,
    snapshot: EventId,
) -> (frasil_adapter::Locator, Vec<u8>) {
    let locator = writer
        .read(&space, |r| {
            r.event(snapshot)
                .and_then(|e| frasil_units::Unit::from_event(e.clone()).ok())
                .and_then(|u| u.body.compacts.map(|c| c.object))
        })
        .await
        .unwrap()
        .expect("a snapshot unit");
    let stored = writer.stored_object(&space, &locator).await.unwrap();
    (locator, stored)
}

/// The units of one stream among signed events, in order.
fn units_of(signed: &[Vec<u8>], stream: frasil_units::stream::StreamId) -> Vec<EventId> {
    signed
        .iter()
        .filter_map(|s| frasil_events::decode(s).ok())
        .filter(|e| {
            e.kind() == kind::UNIT
                && frasil_units::Unit::from_event(e.clone()).is_ok_and(|u| u.body.stream == stream)
        })
        .map(|e| e.id())
        .collect()
}

/// Alice, Carol and Dave, writers of a space, Carol a suggester if
/// `suggester`, and a document of Alice's three units that Carol holds and
/// Dave does not.
async fn alice_carol_and_dave(
    suggester: bool,
) -> (
    Engine,
    Engine,
    Engine,
    EventId,
    frasil_units::stream::Opening,
) {
    let alice = device().await;
    let carol = device().await;
    let dave = device().await;
    let space = alice.create_space().await.unwrap();
    for other in [&carol, &dave] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    if suggester {
        alice
            .set_suggester(
                space,
                frasil_space::MemberRef::device(carol.device_id()),
                true,
            )
            .await
            .unwrap()
            .expect("Carol becomes a suggester");
    }
    let doc = alice.new_document().unwrap();
    for word in ["one", " two", " three"] {
        alice
            .edit_document(space, &doc, |d| {
                let body = d.get_text("body");
                body.insert(body.len_unicode(), word).unwrap();
            })
            .await
            .unwrap();
    }
    carol.follow(space).await;
    carol
        .ingest(space, alice.events(&space).await)
        .await
        .unwrap();
    dave.follow(space).await;
    (alice, carol, dave, space, doc)
}

/// The events of `signed` but those in `leave_out`.
fn except(signed: Vec<Vec<u8>>, leave_out: &[EventId]) -> Vec<Vec<u8>> {
    signed
        .into_iter()
        .filter(|s| frasil_events::decode(s).is_ok_and(|e| !leave_out.contains(&e.id())))
        .collect()
}

/// The events of `signed` among `only`.
fn only(signed: Vec<Vec<u8>>, only: &[EventId]) -> Vec<Vec<u8>> {
    signed
        .into_iter()
        .filter(|s| frasil_events::decode(s).is_ok_and(|e| only.contains(&e.id())))
        .collect()
}

/// A suggester writes no snapshot unit (units.md, 3.17 "`suggest`";
/// adapter-loro.md, 3.4 Suggestions): its compaction is a valid unit whose
/// content is refused, and a replica that holds none of its cover does not
/// load its state (units.md, 3.6 "Using": "its content is not refused").
#[tokio::test]
async fn a_suggesters_snapshot_is_not_used_where_the_cover_is_not_held() {
    let (alice, carol, dave, space, doc) = alice_carol_and_dave(true).await;
    let snapshot = carol.compact(space, doc.stream()).await.unwrap();
    alice
        .ingest(space, carol.events(&space).await)
        .await
        .unwrap();
    let (status, outcome) = alice
        .read(&space, |r| {
            (r.status(&snapshot).copied(), r.content_outcome(&snapshot))
        })
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert!(
        matches!(
            outcome,
            Some(frasil::advanced::ContentOutcome::Refused(
                "CapabilityRefused"
            ))
        ),
        "{outcome:?}"
    );

    // Dave holds none of the cover, as a newcomer or after a collection.
    let (locator, stored) = snapshot_object(&carol, space, snapshot).await;
    let cover = units_of(&alice.events(&space).await, doc.stream());
    let cover: Vec<EventId> = cover.into_iter().filter(|id| *id != snapshot).collect();
    dave.receive_object(space, &locator, &stored).await.unwrap();
    dave.ingest(space, except(alice.events(&space).await, &cover))
        .await
        .unwrap();
    let (placed, used, base) = dave
        .read(&space, |r| {
            (
                r.event(snapshot).is_some(),
                r.used_snapshots().clone(),
                r.stream(&doc.stream())
                    .map(|runtime| runtime.base_cover().len()),
            )
        })
        .await
        .unwrap();
    assert!(placed, "the snapshot unit is placed against its stubs");
    assert!(!used.contains(&snapshot), "{used:?}");
    assert!(base.is_none_or(|len| len == 0), "{base:?}");
    // The cover, fetched again, is the stream's state.
    dave.ingest(space, only(alice.events(&space).await, &cover))
        .await
        .unwrap();
    assert_eq!(
        text(&dave.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );
}

/// A snapshot in use whose unit is later refused, here by a removal
/// learned late, is no longer used: the replica drops its state and
/// rebuilds from the units it holds (units.md, 3.6 "Using", 3.8 Rebuilds).
#[tokio::test]
async fn a_snapshot_in_use_whose_unit_turns_refused_is_dropped() {
    let (alice, carol, dave, space, doc) = alice_carol_and_dave(false).await;
    let before = alice.events(&space).await;
    let cover = units_of(&before, doc.stream());
    // Alice removes Carol; Carol, not knowing, compacts.
    alice
        .remove(space, frasil_space::MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    let snapshot = carol.compact(space, doc.stream()).await.unwrap();
    let (locator, stored) = snapshot_object(&carol, space, snapshot).await;

    // Dave holds none of the cover and has not learned the removal: he
    // uses the snapshot.
    let mut first = except(before, &cover);
    first.extend(only(carol.events(&space).await, &[snapshot]));
    dave.receive_object(space, &locator, &stored).await.unwrap();
    dave.ingest(space, first).await.unwrap();
    let used = dave
        .read(&space, |r| r.used_snapshots().clone())
        .await
        .unwrap();
    assert!(used.contains(&snapshot), "{used:?}");
    assert_eq!(
        text(&dave.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );

    // The removal arrives. It names a unit of the cover as a parent, whose
    // only stub Carol signed: Dave places it only once he holds that unit
    // in full (units.md, "Confirming heights"), and asks for it.
    dave.ingest(space, except(alice.events(&space).await, &cover))
        .await
        .unwrap();
    let wanted = dave.read(&space, |r| r.wanted()).await.unwrap();
    assert!(
        cover.iter().any(|id| wanted.contains(id)),
        "Dave asks for the cover unit the removal names: {wanted:?}"
    );
    // The cover, fetched again, places the removal: the snapshot unit is
    // refused, its state is no longer the stream's base, and the cover is
    // the stream's state.
    dave.ingest(space, only(alice.events(&space).await, &cover))
        .await
        .unwrap();
    let (refused, used, base) = dave
        .read(&space, |r| {
            (
                r.status(&snapshot).is_some_and(|s| !s.is_valid()),
                r.used_snapshots().clone(),
                r.stream(&doc.stream())
                    .map(|runtime| runtime.base_cover().len()),
            )
        })
        .await
        .unwrap();
    assert!(refused, "the removal refuses Carol's snapshot unit");
    assert!(!used.contains(&snapshot), "{used:?}");
    assert!(base.is_none_or(|len| len == 0), "{base:?}");
    assert_eq!(
        text(&dave.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );

    // The real events replaced the stubs: every event Dave holds stands at
    // the height Alice, who never used the snapshot, gives it.
    let heights = |engine: &Engine| {
        let engine = engine.clone();
        async move {
            engine
                .read(&space, |r| {
                    let log = r.log().unwrap();
                    log.canonical()
                        .into_iter()
                        .map(|id| (id, log.height(id)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .await
                .unwrap()
        }
    };
    let at_alice = heights(&alice).await;
    for (id, height) in heights(&dave).await {
        if let Some(theirs) = at_alice.get(&id) {
            assert_eq!(height, *theirs, "the height of {id:?}");
        }
    }
    // Dave stores a restore that names the refused snapshot unit, and
    // offers the cover he holds again, so that it returns at the peers
    // (units.md, 3.6 "Checking"; peers.md, 3.19 Collection).
    assert_eq!(dave.restore_compactions(space).await.unwrap().len(), 1);
    let outbox = dave.outbox(&space).await;
    assert!(
        cover.iter().all(|id| outbox.contains(id)),
        "the cover is offered again: {outbox:?}"
    );
}
