//! What a replica keeps of events it cannot place (events.md, "Placement
//! and order"; roster.md, "Strangers' events"): within limits per author
//! and in all, and nothing at rest of an author no record names.

use frasil::advanced::{AdapterRegistry, Engine, MemorySlot, MemoryStore, Platform};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::envelope::Envelope;
use frasil_events::{EventId, kind};
use std::sync::Arc;

/// A stranger's chain of `count` units in a log, the first resting on a
/// parent no one holds: none of them can be placed.
fn stranger_chain(seed: u8, log: EventId, count: u64) -> Vec<Vec<u8>> {
    let signer = Signer::from_seeds(&[seed; 32], &[seed.wrapping_add(50); 32], None);
    let missing = EventId([seed; 32]);
    let mut prev: Option<EventId> = None;
    let mut out = Vec::new();
    for seq in 1..=count {
        let parents = match prev {
            None => vec![missing],
            Some(prev) => vec![prev],
        };
        let signed = Envelope {
            kind: kind::UNIT,
            log: Some(log),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts: Vec::new(),
            body: format!("unit {seq}").into_bytes(),
            scheme: Scheme::Ed25519,
        }
        .sign(&signer);
        prev = Some(frasil_events::decode(&signed).unwrap().id());
        out.push(signed);
    }
    out
}

async fn pending(device: &Engine, space: &EventId) -> usize {
    device
        .read(space, |r| {
            r.log().map_or(0, frasil_events::Log::pending_count)
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_replica_keeps_at_most_its_limit_of_one_authors_pending_events() {
    let (alice, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let limit = frasil::advanced::replica::MAX_PENDING_PER_AUTHOR;
    let chain = stranger_chain(3, space, limit as u64 + 16);
    alice.ingest(space, chain).await.unwrap();
    assert_eq!(pending(&alice, &space).await, limit);
    // The greatest `seq`s went first: the chain's start is kept, and its
    // missing parent is still fetched.
    let wanted = alice.read(&space, |r| r.wanted()).await.unwrap();
    assert!(wanted.contains(&EventId([3; 32])), "{wanted:?}");
}

#[tokio::test]
async fn a_replica_keeps_at_most_its_limit_of_pending_events_in_all() {
    let (alice, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    let per_author = frasil::advanced::replica::MAX_PENDING_PER_AUTHOR;
    let limit = frasil::advanced::replica::MAX_PENDING_EVENTS;
    let authors = limit / per_author + 1;
    for seed in 0..authors {
        let chain = stranger_chain(10 + seed as u8, space, per_author as u64);
        alice.ingest(space, chain).await.unwrap();
    }
    assert_eq!(pending(&alice, &space).await, limit);
}

#[tokio::test]
async fn a_strangers_pending_events_are_not_kept_at_rest() {
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn frasil_store::DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let registry = AdapterRegistry::with_builtins();
    let platform = Platform::new(store, slot);
    let (alice, sealed) = Engine::create(platform.clone(), &[8; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    alice
        .ingest(space, stranger_chain(4, space, 8))
        .await
        .unwrap();
    assert_eq!(pending(&alice, &space).await, 8);
    alice.keep_reading().await.unwrap();
    drop(alice);
    let alice = Engine::open(platform, &sealed, &[8; 32], registry)
        .await
        .unwrap();
    assert_eq!(pending(&alice, &space).await, 0);
}
