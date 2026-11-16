//! What a replica remembers between refreshes of a roster (failed wrap
//! trials, the skeleton it read, verdicts of ML-DSA-65 halves) gives way to
//! what changes it: a removal and a grant again with history, a twin that
//! arrives after its roster event. Every refresh here is also checked
//! against one from scratch ([`Replica::check_from_scratch`]), which
//! verifies every signature again, and each device against a new instance
//! of it given the same events. Keys that arrive after the events that
//! wait for them are `frasil-space`'s `bound_keys` tests, over one log.

use crate::advanced::{AdapterRegistry, Engine, MemorySlot, MemoryStore, Platform};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Via};
use frasil_store::{DeviceBoundSlot, Store};
use frasil_units::stream::Opening;
use std::sync::Arc;

struct Device {
    engine: Engine,
    sealed: Vec<u8>,
    key: [u8; 32],
}

async fn device(key: u8) -> Device {
    let (engine, sealed) = Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    Device {
        engine,
        sealed: sealed.to_vec(),
        key: [key; 32],
    }
}

impl Device {
    /// A new instance of the same device over an empty store.
    async fn again(&self) -> Engine {
        Engine::open(
            Platform::new(
                Arc::new(MemoryStore::new()) as Arc<dyn Store>,
                Arc::new(MemorySlot::new()) as Arc<dyn DeviceBoundSlot>,
            ),
            &self.sealed,
            &self.key,
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a new instance")
    }
}

fn checked() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
}

async fn grant(admin: &Engine, space: EventId, to: &Engine, history: HistoryMode) {
    admin
        .grant_device(
            space,
            to.public_keys().clone(),
            Level::Write,
            history,
            Via::Code,
        )
        .await
        .expect("a grant");
}

async fn write(engine: &Engine, space: EventId, doc: &Opening, text: &str) {
    engine
        .edit_document(space, doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), text).expect("an insert");
        })
        .await
        .expect("an edit");
}

async fn text(engine: &Engine, space: EventId, doc: &Opening) -> String {
    engine
        .document(&space, &doc.stream())
        .await
        .map(|d| d.get_text("body").to_string())
        .unwrap_or_default()
}

/// The events `to` lacks of `from`'s.
async fn lacking(to: &Engine, from: &Engine, space: EventId) -> Vec<Vec<u8>> {
    let held: std::collections::BTreeSet<Vec<u8>> = to.events(&space).await.into_iter().collect();
    from.events(&space)
        .await
        .into_iter()
        .filter(|signed| !held.contains(signed))
        .collect()
}

async fn level_of(
    engine: &Engine,
    space: EventId,
    device: frasil_crypto::device::DeviceId,
) -> Option<Level> {
    engine
        .read(&space, |replica| replica.level_of(&device))
        .await
        .unwrap()
}

fn run(test: impl std::future::Future<Output = ()>) {
    checked();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// A device removed, then granted again with history: the deliveries of
/// the rotation it was left out of found no wrap for it, and the grant
/// that hands it that state again is a delivery of its own, which it
/// tries and opens.
#[test]
fn a_device_granted_again_opens_what_it_was_left_out_of() {
    run(async {
        let alice = device(41).await;
        let bob = device(42).await;
        let space = alice.engine.create_space().await.unwrap();
        let doc = alice.engine.new_document().unwrap();
        grant(&alice.engine, space, &bob.engine, HistoryMode::WithHistory).await;
        write(&alice.engine, space, &doc, "a").await;
        alice
            .engine
            .remove(space, MemberRef::device(bob.engine.device_id()))
            .await
            .unwrap();
        write(&alice.engine, space, &doc, "b").await;
        bob.engine.follow(space).await;
        let all = alice.engine.events(&space).await;
        bob.engine.ingest(space, all).await.unwrap();
        assert_eq!(text(&bob.engine, space, &doc).await, "a");

        grant(&alice.engine, space, &bob.engine, HistoryMode::WithHistory).await;
        let more = lacking(&bob.engine, &alice.engine, space).await;
        bob.engine.ingest(space, more).await.unwrap();
        assert_eq!(text(&bob.engine, space, &doc).await, "ab");

        // A new instance of bob given every event at once reads the same.
        let again = bob.again().await;
        again.follow(space).await;
        let all = alice.engine.events(&space).await;
        again.ingest(space, all).await.unwrap();
        assert_eq!(text(&again, space, &doc).await, "ab");
    });
}

/// A raise to `administer` names a twin, a skeleton event: a replica that
/// receives the roster event first holds it until the twin arrives, then
/// judges it valid, as a replica that received both at once does.
#[test]
fn a_twin_that_arrives_late_makes_its_roster_event_valid() {
    run(async {
        let alice = device(61).await;
        let bob = device(62).await;
        let carol = device(63).await;
        let space = alice.engine.create_space().await.unwrap();
        for to in [&bob.engine, &carol.engine] {
            grant(&alice.engine, space, to, HistoryMode::WithHistory).await;
        }
        carol.engine.follow(space).await;
        let all = alice.engine.events(&space).await;
        carol.engine.ingest(space, all).await.unwrap();

        let raised = alice
            .engine
            .sign_roster(
                space,
                vec![Change::raise(
                    MemberRef::device(bob.engine.device_id()),
                    255,
                )],
            )
            .await
            .unwrap();
        let more = lacking(&carol.engine, &alice.engine, space).await;
        let (twins, rest): (Vec<Vec<u8>>, Vec<Vec<u8>>) = more.into_iter().partition(|signed| {
            frasil_events::decode(signed)
                .is_ok_and(|event| event.kind() == frasil_events::kind::STORAGE)
        });
        assert!(!twins.is_empty(), "the raise names a twin");

        carol.engine.ingest(space, rest).await.unwrap();
        let held = carol
            .engine
            .read(&space, |replica| replica.status(&raised).copied())
            .await
            .unwrap();
        let raised_to = bob.engine.device_id();
        assert_ne!(
            level_of(&carol.engine, space, raised_to).await,
            Some(Level::Administer),
            "{held:?}"
        );

        carol.engine.ingest(space, twins).await.unwrap();
        assert_eq!(
            level_of(&carol.engine, space, raised_to).await,
            Some(Level::Administer)
        );

        let again = carol.again().await;
        again.follow(space).await;
        let all = alice.engine.events(&space).await;
        again.ingest(space, all).await.unwrap();
        assert_eq!(
            level_of(&again, space, raised_to).await,
            Some(Level::Administer)
        );
    });
}
