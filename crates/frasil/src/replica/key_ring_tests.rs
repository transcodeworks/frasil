//! The key ring costs no resolution it does not need: a device opened again
//! resolves a space's new units from the resolution its load kept, and keys
//! it holds already change nothing (crypto.md, "Keys by their hash").

use crate::advanced::{AdapterRegistry, Engine, MemorySlot, MemoryStore, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_store::{DeviceBoundSlot, Store};
use std::sync::Arc;

struct Held {
    store: Arc<MemoryStore>,
    slot: Arc<MemorySlot>,
    sealed: Vec<u8>,
}

impl Held {
    fn platform(&self) -> Platform {
        Platform::new(
            Arc::clone(&self.store) as Arc<dyn Store>,
            Arc::clone(&self.slot) as Arc<dyn DeviceBoundSlot>,
        )
    }

    async fn open(&self, key: u8) -> Engine {
        Engine::open(
            self.platform(),
            &self.sealed,
            &[key; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("opened again")
    }
}

async fn device(key: u8) -> (Engine, Held) {
    let store = Arc::new(MemoryStore::new());
    let slot = Arc::new(MemorySlot::new());
    let held = Held {
        store,
        slot,
        sealed: Vec::new(),
    };
    let (engine, sealed) = Engine::create(
        held.platform(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    (
        engine,
        Held {
            sealed: sealed.to_vec(),
            ..held
        },
    )
}

async fn full_resolutions(engine: &Engine, space: EventId) -> usize {
    engine
        .read(&space, crate::replica::Replica::full_resolutions)
        .await
        .unwrap()
}

/// Alice's spaces, each granting Bob, and one document Bob writes in each.
async fn scene(
    spaces: usize,
) -> (
    Engine,
    Held,
    Engine,
    Vec<(EventId, frasil_units::stream::Opening)>,
) {
    let (alice, held) = device(1).await;
    let (bob, _) = device(2).await;
    let mut out = Vec::new();
    for _ in 0..spaces {
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
        let doc = alice.new_document().unwrap();
        alice
            .edit_document(space, &doc, |d| {
                let _ = d.get_text("body").insert(0, "a");
            })
            .await
            .unwrap();
        bob.follow(space).await;
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        out.push((space, doc));
    }
    (alice, held, bob, out)
}

#[tokio::test]
async fn a_device_opened_again_resolves_new_units_from_the_resolution_its_load_kept() {
    // One space: a resolution of another space the device holds would
    // change what this one reads of it.
    let (alice, held, bob, spaces) = scene(1).await;
    drop(alice);
    let alice = held.open(1).await;
    let (space, doc) = &spaces[0];
    for _ in 0..3 {
        let before = full_resolutions(&alice, *space).await;
        bob.edit_document(*space, doc, |d| {
            let body = d.get_text("body");
            let _ = body.insert(body.len_unicode(), "b");
        })
        .await
        .unwrap();
        alice.ingest(*space, bob.events(space).await).await.unwrap();
        assert_eq!(
            full_resolutions(&alice, *space).await,
            before,
            "a unit placed after the load resolves from the kept resolution"
        );
    }
}

#[tokio::test]
async fn keys_the_device_holds_already_resolve_nothing_again() {
    let (alice, _held, bob, spaces) = scene(2).await;
    let before: Vec<usize> = {
        let mut out = Vec::new();
        for (space, _) in &spaces {
            out.push(full_resolutions(&alice, *space).await);
        }
        out
    };
    // Its own keys, then Bob's, which its spaces' grants carry, twice: no
    // space waits for keys, so no space is resolved again.
    alice.learn_keys(alice.public_keys().clone()).await.unwrap();
    alice.learn_keys(bob.public_keys().clone()).await.unwrap();
    alice.learn_keys(bob.public_keys().clone()).await.unwrap();
    for ((space, _), before) in spaces.iter().zip(before) {
        assert_eq!(full_resolutions(&alice, *space).await, before);
    }
}
