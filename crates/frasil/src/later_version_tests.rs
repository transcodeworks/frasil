//! A space that needs a later version than this build (roster.md, "The
//! space descriptor", 2.8 The checkpoint record, step 3): the application
//! is told, by an event and a query, and the device signs nothing in the
//! space.

use crate::checkpoints::LATER_RECORD_KEY;
use crate::{Device, Error, Event, Events, Options, Storage};
use frasil_events::EventId;
use frasil_space::{Descriptor, DescriptorKind, HistoryMode, Level, Policy, Status, Via};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().never_restored())
        .await
        .expect("a device")
}

/// Waits for the report that `space` needs a later version.
async fn told(events: &mut Events, space: EventId) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events.next().await {
                Some(Event::NeedsLaterVersion { space: at }) if at.event() == space => return,
                Some(_) => {}
                None => panic!("the device is gone"),
            }
        }
    })
    .await
    .expect("the application is told");
}

/// Grants `to` write in the space, which must sign nothing: refused, and
/// the space holds as many events as before.
async fn signs_nothing(by: &Device, to: &Device, space: EventId) {
    let engine = by.engine();
    let held = engine.events(&space).await.len();
    let refused = engine
        .grant_device_at(
            space,
            to.engine().public_keys().clone(),
            Level::Write,
            None,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await;
    assert_eq!(refused.err(), Some(Error::NeedsLaterVersion));
    assert_eq!(engine.events(&space).await.len(), held, "nothing is signed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_space_of_a_later_documents_descriptor_is_reported_and_signs_nothing() {
    let alice = device(61).await;
    let bob = device(62).await;
    let mut events = alice.events();
    // A descriptor of kind 3, as a device of a later version makes it.
    let later = Descriptor {
        kind: DescriptorKind::Reserved(3),
        parent: None,
        application: None,
    };
    let space = alice
        .engine()
        .create_space_as(Policy::default(), later)
        .await
        .unwrap();
    assert!(alice.engine().needs_later_version(&space).await.unwrap());
    signs_nothing(&alice, &bob, space).await;
    told(&mut events, space).await;
    // An ordinary space of the same device needs nothing more.
    let ordinary = alice.engine().create_space().await.unwrap();
    assert!(!alice.engine().needs_later_version(&ordinary).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkpoint_of_a_later_documents_record_is_reported_and_signs_nothing() {
    let alice = device(63).await;
    let bob = device(64).await;
    let mut events = alice.events();
    let engine = alice.engine();
    let space = engine.create_space().await.unwrap();
    assert!(!engine.needs_later_version(&space).await.unwrap());
    // Alice proposes a checkpoint whose record carries record key 9, as a
    // device of a later version would.
    let me = engine.device_id();
    LATER_RECORD_KEY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(me);
    let proposed = engine.propose_checkpoint(space).await;
    LATER_RECORD_KEY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&me);
    let c = proposed.unwrap();
    let class = engine
        .read(&space, |r| r.status(&c).and_then(Status::class))
        .await
        .unwrap();
    assert_eq!(
        class,
        Some(frasil_space::RosterClass::from(
            frasil_base::ErrorClass::ExtensionRequired
        ))
    );
    let status = engine.checkpoint_status(&space).await.unwrap();
    assert_eq!(status.in_effect, None, "it never takes effect");
    assert!(status.pending.is_empty(), "nor waits for votes");
    assert!(engine.needs_later_version(&space).await.unwrap());
    signs_nothing(&alice, &bob, space).await;
    told(&mut events, space).await;
}
