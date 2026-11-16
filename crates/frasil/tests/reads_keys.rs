//! A key that arrives after the units it opens: a person's new device holds
//! a document's units it cannot read, then a member's delivery, an event of
//! no stream, makes them readable. An observed read of the document, and the
//! space's change feed, follow it.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::maintenance::Maintained;
use frasil::advanced::platform::ManualClock;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Device, Options, SpaceId, Status, StreamId};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use std::sync::Arc;
use std::time::Duration;

async fn engine(clock: &Arc<ManualClock>) -> Engine {
    let platform = Platform::memory().with_clock(clock.clone());
    Engine::create(platform, &[7; 32], AdapterRegistry::with_builtins())
        .await
        .expect("a device")
        .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_that_arrives_after_its_units_wakes_observers_and_feeds() {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let alice = engine(&clock).await;
    let bob = engine(&clock).await;
    let phone_engine = engine(&clock).await;
    let space = alice.create_space().await.unwrap();
    let person = bob.make_person(&[7; 32]).await.unwrap().person;
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &person).await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "for bob").unwrap();
        })
        .await
        .unwrap();

    let (keys, proof) = phone_engine.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone_engine
        .adopt_person(person, bob.list_events(&person).await, &[7; 32])
        .await
        .unwrap();
    phone_engine.follow(space).await;
    let phone = Device::from_engine(phone_engine.clone(), Options::new()).unwrap();
    let phone_space = phone.space(SpaceId::from_bytes(space.0)).await.unwrap();
    let id = StreamId::from_bytes(doc.stream());
    let mut text = phone_space
        .observe(move |space| async move { space.document(id).await?.text("body").await });
    let mut changes = phone_space.changes();

    // The first batch: the document's units, which the phone cannot read.
    carry(&alice, &phone_engine, space).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_ne!(text.get().status, Status::Ready, "nothing to read yet");

    // A later batch: the delivery, an event of no stream.
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    let delivered = loop {
        let done = alice.maintain(space).await.unwrap();
        if done != Maintained::default() {
            break done;
        }
        clock.advance(1);
    };
    assert!(delivered.delivery.is_some(), "{delivered:?}");
    // What the first batch brought, seen by the feed before the delivery.
    while tokio::time::timeout(Duration::from_millis(100), changes.next())
        .await
        .is_ok()
    {}
    carry(&alice, &phone_engine, space).await;

    let read = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let now = text.get();
            if now.status == Status::Ready {
                break now.value.unwrap();
            }
            text.changed().await.unwrap();
        }
    })
    .await
    .expect("the observer reads again once the key arrives");
    assert_eq!(*read, "for bob");

    let change = tokio::time::timeout(Duration::from_secs(10), changes.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(change.space_events || change.members, "{change:?}");
}
