//! A person's devices reach a space through a running peer (roster.md,
//! "Effective membership"; admission.md, "A person's new device",
//! "The newcomer's snapshot"; identity.md, "Other spaces"):
//!
//! - a device granted through its person with history, after a nearby join
//!   by code broke the space's key history, takes the space by plain
//!   ingest, then presents at the peer and receives what is written after;
//! - a device a granted person's list adds after the grant, by a device
//!   that does not hold the space, is delivered the current state by a
//!   member's maintenance, then does the same.

use frasil::advanced::Engine;
use frasil::{Device, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Via};
use frasil_units::stream::Opening;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// Runs the future to its end within the deadline, or fails naming what
/// was waited for.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(DEADLINE, future).await {
        Ok(value) => value,
        Err(_) => panic!("not within the deadline: {what}"),
    }
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn text(engine: &Engine, space: &EventId, stream: &[u8; 16]) -> String {
    engine
        .document(space, stream)
        .await
        .map(|doc| doc.get_text("body").to_string())
        .unwrap_or_default()
}

/// Waits until the device's outbox for the space is empty: all it wrote
/// is at the peer. Past the deadline, fails naming the kinds of the events
/// still there and what each peer connection reports.
async fn durable(device: &Device, space: &EventId) {
    let engine = device.engine();
    let emptied = tokio::time::timeout(DEADLINE, async {
        while !engine.outbox(space).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if emptied.is_ok() {
        return;
    }
    let pending = engine.outbox(space).await;
    let kinds: Vec<u8> = engine
        .events(space)
        .await
        .iter()
        .filter(|signed| pending.contains(&frasil_events::envelope::event_id(signed)))
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| event.kind())
        .collect();
    let peers: Vec<_> = device.peers().iter().map(frasil::Peer::status).collect();
    panic!(
        "the outbox did not empty at the peer within the deadline: {} events of kinds {kinds:?} pending; peers: {peers:#?}",
        pending.len()
    );
}

/// The device takes the space by plain ingest of Alice's events, presents
/// at the peer, and reads Alice's edit written after.
async fn reaches_through_the_peer(
    alice: &Device,
    newcomer: &Device,
    peer: &str,
    space: EventId,
    doc: &Opening,
) {
    let stream = &doc.stream();
    newcomer.engine().follow(space).await;
    newcomer
        .engine()
        .ingest(space, alice.engine().events(&space).await)
        .await
        .unwrap();
    assert_eq!(
        newcomer
            .engine()
            .read(&space, |r| r.level_of(&newcomer.engine().device_id()))
            .await
            .unwrap(),
        Some(Level::Write),
        "the roster resolves at the newcomer"
    );
    newcomer.connect(peer).await.unwrap();
    alice
        .engine()
        .edit_document(space, doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), ", and after").unwrap();
        })
        .await
        .unwrap();
    durable(alice, &space).await;
    within("the newcomer reads the edit written after", async {
        while text(newcomer.engine(), &space, stream).await != "before, and after" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_granted_after_a_nearby_join_reaches_the_space_from_the_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    // Bob joins nearby by code: an admission from now on, a break.
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let _bobs = within(
        "Bob joins by code",
        bob.join(invitation.text(), "Bob's phone", |_, _| async { true }),
    )
    .await
    .unwrap();
    within("Alice admits Bob", invitation.admitted())
        .await
        .unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let doc = alice.engine().new_document().unwrap();
    alice
        .engine()
        .edit_document(id, &doc, |d| {
            d.get_text("body").insert(0, "before").unwrap()
        })
        .await
        .unwrap();
    // Alice grants Carol's person with history.
    let person = *carol.make_person(&[3; 32]).await.unwrap().as_bytes();
    alice
        .engine()
        .receive_list(carol.engine().list_events(&person).await)
        .await
        .unwrap();
    alice
        .engine()
        .grant_person(
            id,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.engine().publish_list(id, &person).await.unwrap();
    durable(&alice, &id).await;
    reaches_through_the_peer(&alice, &carol, &peer.origin, id, &doc).await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_added_to_a_granted_person_is_delivered_by_a_member() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(4).await;
    let bob = device(5).await;
    let phone = device(6).await;
    let id = alice.engine().create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let doc = alice.engine().new_document().unwrap();
    alice
        .engine()
        .edit_document(id, &doc, |d| {
            d.get_text("body").insert(0, "before").unwrap()
        })
        .await
        .unwrap();
    // Bob's person is granted; Bob never holds the space.
    let person = *bob.make_person(&[5; 32]).await.unwrap().as_bytes();
    alice
        .engine()
        .receive_list(bob.engine().list_events(&person).await)
        .await
        .unwrap();
    alice
        .engine()
        .grant_person(
            id,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.engine().publish_list(id, &person).await.unwrap();
    // Bob adds his phone to his person.
    let (keys, proof) = phone.engine().list_keys(&person, &bob.engine().device_id());
    bob.engine().add_device(keys, proof).await.unwrap();
    phone
        .engine()
        .adopt_person(person, bob.engine().list_events(&person).await, &[6; 32])
        .await
        .unwrap();
    // Alice receives the list's new events, and her maintenance (her own
    // runs, or this call) publishes them and delivers the current state to
    // the phone after her rank delay.
    alice
        .engine()
        .receive_list(bob.engine().list_events(&person).await)
        .await
        .unwrap();
    phone.engine().follow(id).await;
    within(
        "a member's maintenance delivers the space to the phone",
        async {
            loop {
                let done = alice.engine().maintain(id).await.unwrap();
                assert!(done.rotation.is_none(), "a delivery, not a rotation");
                phone
                    .engine()
                    .ingest(id, alice.engine().events(&id).await)
                    .await
                    .unwrap();
                let level = phone
                    .engine()
                    .read(&id, |r| r.level_of(&phone.engine().device_id()))
                    .await
                    .unwrap();
                if level == Some(Level::Write) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        },
    )
    .await;
    durable(&alice, &id).await;
    reaches_through_the_peer(&alice, &phone, &peer.origin, id, &doc).await;
    peer.shutdown().await;
}
