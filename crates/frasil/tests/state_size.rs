//! A state object larger than its adapter loads is fetched no further than
//! its header and first chunk (units.md, "Sync", objects; "The space
//! snapshot", "Using it"): a newcomer asks for a state object's header
//! first, and a header that names more than the adapter's largest state
//! ends the fetch and drops the stream entry, so nothing waits for it.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::sync::SyncSession;
use frasil::advanced::{Acknowledger, AdapterRegistry, Engine, Platform};
use frasil_adapter::{Adapter, Compaction, Context, EventId as UnitId, Outcome};
use frasil_adapter_loro::Loro;
use frasil_events::kind;
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::messages::{Message, SyncMessage};
use std::collections::BTreeSet;

/// The Loro adapter, but for a largest state of 16 bytes.
#[derive(Debug, Clone, Default)]
struct SmallLoro(Loro);

impl Adapter for SmallLoro {
    const TYPE: &'static str = <Loro as Adapter>::TYPE;
    type Change = <Loro as Adapter>::Change;
    type State = <Loro as Adapter>::State;
    type Class = <Loro as Adapter>::Class;

    fn max_state_bytes(&self) -> Option<u64> {
        Some(16)
    }

    fn encode(&self, change: &Self::Change) -> Vec<u8> {
        self.0.encode(change)
    }

    fn decode(&self, content: &[u8], context: &Context) -> Result<Self::Change, Self::Class> {
        self.0.decode(content, context)
    }

    fn empty(&self) -> Self::State {
        self.0.empty()
    }

    fn count(&self, state: &mut Self::State, context: &Context, content: &[u8]) {
        self.0.count(state, context, content);
    }

    fn apply(
        &self,
        state: &mut Self::State,
        context: &Context,
        change: &Self::Change,
    ) -> Outcome<Self::Class> {
        self.0.apply(state, context, change)
    }

    fn hold(&self, state: &mut Self::State, units: &BTreeSet<UnitId>) {
        self.0.hold(state, units);
    }

    fn held(&self, state: &Self::State) -> Vec<(UnitId, Self::Class)> {
        self.0.held(state)
    }

    fn compact(&self, state: &Self::State) -> Compaction {
        self.0.compact(state)
    }

    fn load(&self, snapshot_state: &[u8]) -> Result<Self::State, Self::Class> {
        self.0.load(snapshot_state)
    }

    fn export_history_free(&self, state: &Self::State) -> Result<Vec<u8>, Self::Class> {
        self.0.export_history_free(state)
    }
}

/// Text that no compression shrinks much: letters from a xorshift.
fn noise(length: usize) -> String {
    let mut x: u32 = 0x9e37_79b9;
    (0..length)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            char::from(b'a' + (x % 26) as u8)
        })
        .collect()
}

async fn device(registry: AdapterRegistry) -> Engine {
    Engine::create(Platform::memory(), &[7; 32], registry)
        .await
        .expect("a device")
        .0
}

#[tokio::test]
async fn a_state_object_over_the_adapters_limit_is_fetched_no_further() {
    let alice = device(AdapterRegistry::with_builtins()).await;
    let mut small = AdapterRegistry::new();
    small.register(SmallLoro::default());
    let bob = device(small).await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, &noise(20_000)).unwrap();
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
    let parts = snapshot.parts();
    let first = parts
        .iter()
        .find(|part| part.header.is_some())
        .expect("a stream snapshot object")
        .clone();
    let locator = first.locator;

    // Bob takes the snapshot without its objects, and the space's frame.
    bob.adopt_snapshot(space, &snapshot.signed, Vec::new())
        .await
        .unwrap();
    let frame: Vec<Vec<u8>> = alice
        .events(&space)
        .await
        .into_iter()
        .filter(|signed| frasil_events::decode(signed).is_ok_and(|e| e.kind() != kind::UNIT))
        .collect();
    bob.ingest(space, frame).await.unwrap();
    assert!(bob.missing_objects(&space).await.contains(&locator));

    // Told Alice holds it, Bob asks for its first chunk alone.
    let from_alice = Acknowledger::Member(alice.device_id().0);
    let mut session = SyncSession::new(space);
    let wants = bob
        .sync_receive(
            &mut session,
            from_alice,
            SyncMessage {
                space,
                message: Message::ObjectHave {
                    locators: vec![locator],
                    counts: None,
                },
            },
        )
        .await
        .unwrap();
    assert!(wants.iter().any(|want| matches!(
        want.message,
        Message::ObjectWant { locator: l, first: 0, count: 1 } if l == locator
    )));

    // Its header names more than the adapter loads: Bob asks for nothing
    // more, keeps nothing of it, and no longer waits for it.
    let more = bob
        .sync_receive(
            &mut session,
            from_alice,
            SyncMessage {
                space,
                message: Message::ObjectChunks {
                    locator,
                    header: first.header.clone(),
                    index: first.index,
                    chunk: first.chunk.clone(),
                },
            },
        )
        .await
        .unwrap();
    assert!(
        !more
            .iter()
            .any(|m| matches!(m.message, Message::ObjectWant { .. }))
    );
    assert!(!bob.missing_objects(&space).await.contains(&locator));
    assert!(bob.stored_object(&space, &locator).await.is_none());
}
