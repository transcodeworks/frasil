//! Guests through the engine (ext-guests.md), with the events carried by
//! hand: a session ended in one event, a session's expiry at the guest and
//! at its administrator, a leave request, and a guest that keeps nothing
//! at rest.
#![cfg(all(feature = "adapter-loro", feature = "ext-guests"))]

use frasil::Error;
use frasil::advanced::{AdapterRegistry, Engine, ManualClock, Platform};
use frasil_events::EventId;
use frasil_space::ext_guests::Preset;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use std::sync::Arc;

/// The wall clock the devices start at: 2026-10-21.
const NOW: u64 = 1_792_540_800;

async fn device(key: u8, clock: &Arc<ManualClock>) -> (Engine, Platform) {
    let platform = Platform::memory().with_clock(clock.clone());
    let engine = Engine::create(
        platform.clone(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0;
    (engine, platform)
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

fn guest(level: Level, session: u8) -> Preset {
    let mut preset = Preset::new(level, [session; 16]);
    preset.history = HistoryMode::WithHistory;
    preset.via = Via::Code;
    preset
}

async fn admit(alice: &Engine, space: EventId, newcomer: &Engine, preset: &Preset) {
    alice
        .grant_guest(space, newcomer.public_keys().clone(), preset)
        .await
        .unwrap();
    newcomer.follow(space).await;
    carry(alice, newcomer, space).await;
}

async fn member(engine: &Engine, space: EventId, of: &Engine) -> bool {
    engine
        .read(&space, |r| {
            r.roster()
                .state(&MemberRef::device(of.device_id()))
                .is_some()
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_session_ends_in_one_event() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let (bob, _) = device(2, &clock).await;
    let (carol, _) = device(3, &clock).await;
    let (dave, _) = device(4, &clock).await;
    let space = alice.create_space().await.unwrap();
    admit(&alice, space, &bob, &guest(Level::Write, 1)).await;
    admit(&alice, space, &carol, &guest(Level::Read, 1)).await;
    admit(&alice, space, &dave, &guest(Level::Write, 2)).await;
    for other in [&bob, &carol, &dave] {
        carry(&alice, other, space).await;
    }
    // A guest writes.
    let note = alice.new_document().unwrap();
    bob.edit_document(space, &note, |doc| {
        doc.get_text("body").insert(0, "Bob").unwrap();
    })
    .await
    .unwrap();
    carry(&bob, &alice, space).await;
    // The first session ends in one event; the other guest stays.
    let ended = alice.end_session(space, &[1; 16]).await.unwrap();
    assert_eq!(ended.len(), 1);
    assert!(!member(&alice, space, &bob).await);
    assert!(!member(&alice, space, &carol).await);
    assert!(member(&alice, space, &dave).await);
    assert!(alice.end_session(space, &[1; 16]).await.is_err());
}

#[tokio::test]
async fn a_session_expires_at_the_guest_and_at_its_administrator() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let (bob, _) = device(2, &clock).await;
    let space = alice.create_space().await.unwrap();
    let mut preset = guest(Level::Write, 1);
    preset.expires_at = Some(NOW + 3_600);
    admit(&alice, space, &bob, &preset).await;
    let note = alice.new_document().unwrap();
    bob.edit_document(space, &note, |doc| {
        doc.get_text("body").insert(0, "in time").unwrap();
    })
    .await
    .unwrap();
    // Nothing is due before the session's end.
    assert_eq!(alice.expire_guests(space).await.unwrap(), None);
    // Past the session's end and the clocks' allowed skew.
    clock.advance(3_700);
    clock.set_wall(Some(NOW + 3_700));
    // The guest's own client stops writing...
    let late = bob
        .edit_document(space, &note, |doc| {
            doc.get_text("body").insert(0, "late ").unwrap();
        })
        .await;
    assert_eq!(late.unwrap_err(), Error::Class("SessionEnded"));
    // ...and its administrator removes it.
    assert!(alice.expire_guests(space).await.unwrap().is_some());
    assert!(!member(&alice, space, &bob).await);
}

#[tokio::test]
async fn a_member_leaves_by_request() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let (bob, _) = device(2, &clock).await;
    let space = alice.create_space().await.unwrap();
    admit(&alice, space, &bob, &guest(Level::Write, 1)).await;
    let signed = bob.leave(space).await.unwrap().signed;
    // Once it has asked, it seals nothing more there.
    let note = alice.new_document().unwrap();
    let after = bob
        .edit_document(space, &note, |doc| {
            doc.get_text("body").insert(0, "after").unwrap();
        })
        .await;
    assert_eq!(after.unwrap_err(), Error::Class("Left"));
    // An administrator cannot leave by request.
    assert!(alice.leave(space).await.is_err());
    // Its administrator removes it after its rank delay, none here.
    alice.take_leave_request(space, &signed).await.unwrap();
    assert!(alice.expire_guests(space).await.unwrap().is_some());
    assert!(!member(&alice, space, &bob).await);
    // A request whose grants are no longer in force is stale.
    assert!(alice.take_leave_request(space, &signed).await.is_err());
}

#[tokio::test]
async fn a_guest_keeps_nothing_at_rest() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let platform = Platform::memory().with_clock(clock.clone());
    let registry = AdapterRegistry::with_builtins();
    let (bob, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let mut preset = guest(Level::Write, 1);
    preset.nothing_at_rest = true;
    admit(&alice, space, &bob, &preset).await;
    let note = alice.new_document().unwrap();
    alice
        .edit_document(space, &note, |doc| {
            doc.get_text("body").insert(0, "Hello").unwrap();
        })
        .await
        .unwrap();
    carry(&alice, &bob, space).await;
    // Bob reads and writes in memory.
    bob.edit_document(space, &note, |doc| {
        doc.get_text("body").insert(5, ", Alice").unwrap();
    })
    .await
    .unwrap();
    bob.edit_document(space, &note, |doc| {
        doc.get_text("body").insert(12, "!").unwrap();
    })
    .await
    .unwrap();
    assert_eq!(
        bob.document(&space, &note.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "Hello, Alice!"
    );
    carry(&bob, &alice, space).await;
    assert_eq!(
        alice
            .document(&space, &note.stream())
            .await
            .unwrap()
            .get_text("body")
            .to_string(),
        "Hello, Alice!"
    );
    bob.keep_reading().await.unwrap();
    drop(bob);
    // Opened again from its store, Bob's device holds nothing of it.
    let reopened = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    assert!(reopened.spaces().await.is_empty());
}

#[tokio::test]
async fn heartbeats_keep_a_bounded_window_open() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let (bob, _) = device(2, &clock).await;
    let policy = frasil_space::Policy {
        bounded_window: Some(3_600),
        ..frasil_space::Policy::default()
    };
    let space = alice.create_space_with(policy).await.unwrap();
    admit(&alice, space, &bob, &guest(Level::Write, 1)).await;
    // Nothing is due before half the window.
    assert_eq!(bob.heartbeat(space).await.unwrap(), None);
    clock.advance(1_900);
    // Bob has signed nothing for half the window: it beats...
    assert!(bob.heartbeat(space).await.unwrap().is_some());
    assert_eq!(bob.heartbeat(space).await.unwrap(), None);
    carry(&bob, &alice, space).await;
    // ...and Alice answers it.
    assert!(alice.heartbeat(space).await.unwrap().is_some());
    carry(&alice, &bob, space).await;
    // Past the window from Bob's admission, Bob still writes: Alice
    // followed its heartbeat.
    clock.advance(1_900);
    let note = alice.new_document().unwrap();
    bob.edit_document(space, &note, |doc| {
        doc.get_text("body").insert(0, "still here").unwrap();
    })
    .await
    .unwrap();
    // With nobody answering, the window closes.
    clock.advance(3_700);
    let late = bob
        .edit_document(space, &note, |doc| {
            doc.get_text("body").insert(0, "alone ").unwrap();
        })
        .await;
    assert_eq!(late.unwrap_err(), Error::Class("WindowElapsed"));
}

#[tokio::test]
async fn a_leave_request_arrives_through_a_device_mailbox() {
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let (bob, _) = device(2, &clock).await;
    let (carol, _) = device(3, &clock).await;
    let space = alice.create_space().await.unwrap();
    admit(&alice, space, &bob, &guest(Level::Write, 1)).await;
    let leaving = bob.leave(space).await.unwrap();
    // One item, for the one administering device's mailbox.
    assert_eq!(leaving.deposits.len(), 1);
    let (address, item) = &leaving.deposits[0];
    assert_eq!(
        *address,
        frasil_transport::mailbox::address(
            frasil_transport::mailbox::Kind::Device,
            &alice.device_id().0
        )
    );
    // Only its recipient opens it.
    assert!(carol.take_mailbox_item(item).await.is_err());
    alice.take_mailbox_item(item).await.unwrap();
    assert!(alice.expire_guests(space).await.unwrap().is_some());
    assert!(!member(&alice, space, &bob).await);
}

#[tokio::test]
async fn left_outlasts_a_restart() {
    use frasil::advanced::{DeviceBoundSlot, MemorySlot, MemoryStore};
    let clock = Arc::new(ManualClock::new(0, Some(NOW)));
    let (alice, _) = device(1, &clock).await;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let platform = Platform::new(store, slot).with_clock(clock.clone());
    let registry = AdapterRegistry::with_builtins();
    let (bob, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    admit(&alice, space, &bob, &guest(Level::Write, 1)).await;
    bob.leave(space).await.unwrap();
    bob.keep_reading().await.unwrap();
    drop(bob);
    // Opened again before its removal arrives, Bob still seals nothing.
    let bob = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    let note = alice.new_document().unwrap();
    let after = bob
        .edit_document(space, &note, |doc| {
            doc.get_text("body").insert(0, "after a restart").unwrap();
        })
        .await;
    assert_eq!(after.unwrap_err(), Error::Class("Left"));
}
