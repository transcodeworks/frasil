//! Where stubs come from (units.md, 3.9 Placing against stubs): a stub
//! counts only from a signed source the replica has judged. A snapshot unit
//! that is pending, or that no record lets write, cannot make a replica
//! treat an event as known without holding it, nor give it a height.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::sync::SyncSession;
use frasil::advanced::{Acknowledger, AdapterRegistry, Engine, Platform};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::{Envelope, EventId, kind};
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_units::Unit;
use frasil_units::messages::{Message, SyncMessage};

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

fn id_of(signed: &[u8]) -> EventId {
    frasil_events::decode(signed).expect("an event").id()
}

/// A space where Alice compacts a document, removes Bob (`removal`), then
/// writes `after`: with `grant`, a grant of Dave that cites the removal and
/// a unit after it; without, a unit that cites the removal. Carol, a
/// writer, holds everything but the removal.
struct Scene {
    alice: Engine,
    carol: Engine,
    space: EventId,
    /// Alice's snapshot unit, whose body the forged units copy.
    template: Vec<u8>,
    removal: Vec<u8>,
    /// What Alice signed after the removal, in order.
    after: Vec<EventId>,
}

async fn scene(grant: bool) -> Scene {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let dave = device().await;
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
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let snapshot = alice.compact(space, doc.stream()).await.unwrap();
    let removal = alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    let mut after = Vec::new();
    if grant {
        after.push(
            alice
                .grant_device(
                    space,
                    dave.public_keys().clone(),
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap(),
        );
    }
    after.push(
        alice
            .edit_document(space, &doc, |d| {
                let body = d.get_text("body");
                body.insert(body.len_unicode(), " two").unwrap();
            })
            .await
            .unwrap(),
    );
    let all = alice.events(&space).await;
    let signed_of = |id: EventId| {
        all.iter()
            .find(|s| id_of(s) == id)
            .cloned()
            .expect("a signed event")
    };
    carol.follow(space).await;
    carol
        .ingest(
            space,
            all.iter()
                .filter(|s| id_of(s) != removal)
                .cloned()
                .collect(),
        )
        .await
        .unwrap();
    Scene {
        template: signed_of(snapshot),
        removal: signed_of(removal),
        alice,
        carol,
        space,
        after,
    }
}

impl Scene {
    /// The removal's stub as Alice's replica knows it, with `lift` added to
    /// its height.
    async fn stub(&self, lift: u64) -> frasil_units::Stub {
        let removal = frasil_events::decode(&self.removal).unwrap();
        let height = self
            .alice
            .read(&self.space, |r| r.log().unwrap().height(removal.id()))
            .await
            .unwrap()
            .unwrap();
        frasil_units::Stub {
            id: removal.id(),
            author: *removal.author(),
            seq: removal.seq(),
            height: height + lift,
            // A snapshot unit's stubs are all of kind 4.
            kind: kind::UNIT,
            stream: None,
            cuts: frasil_events::Cuts::of(&removal),
        }
    }

    /// A snapshot unit signed by a key no record names, with Alice's
    /// snapshot unit's body but `stubs`, citing `parents`.
    fn forged(&self, seed: u8, parents: Vec<EventId>, stubs: Vec<frasil_units::Stub>) -> Vec<u8> {
        let mut body = Unit::from_event(frasil_events::decode(&self.template).unwrap())
            .unwrap()
            .body;
        let mut stubs = stubs;
        stubs.sort_by_key(|s| s.id);
        body.compacts.as_mut().expect("a snapshot unit").stubs = stubs;
        let signer = Signer::from_seeds(&[seed; 32], &[seed; 32], None);
        Envelope {
            kind: kind::UNIT,
            log: Some(self.space),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq: 1,
            prev: None,
            parents,
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Ed25519,
        }
        .sign(&signer)
    }

    async fn placed(&self, id: EventId) -> bool {
        self.carol
            .read(&self.space, |r| r.log().is_some_and(|log| log.contains(id)))
            .await
            .unwrap()
    }

    async fn wanted(&self) -> Vec<EventId> {
        self.carol.read(&self.space, |r| r.wanted()).await.unwrap()
    }
}

/// A parent no replica holds, which keeps a forged unit pending.
const UNKNOWN: EventId = EventId([0xee; 32]);

#[tokio::test]
async fn a_pending_unit_signed_by_a_stranger_does_not_hide_an_event() {
    let scene = scene(false).await;
    let removal = id_of(&scene.removal);
    let unit = scene.after[0];
    assert!(!scene.placed(unit).await);
    assert!(scene.wanted().await.contains(&removal));

    // A unit no record lets write, pending on a parent no one holds,
    // stubs the removal.
    let forged = scene.forged(0x51, vec![UNKNOWN], vec![scene.stub(0).await]);
    scene.carol.ingest(scene.space, vec![forged]).await.unwrap();
    assert!(
        !scene.placed(unit).await,
        "the unit after the removal is placed without it"
    );
    assert!(
        scene.wanted().await.contains(&removal),
        "the removal is no longer asked for"
    );
}

#[tokio::test]
async fn a_unit_placed_on_its_own_stubs_and_refused_takes_them_back() {
    let scene = scene(false).await;
    let removal = id_of(&scene.removal);
    let unit = scene.after[0];
    // The forged unit cites the unit after the removal and stubs every
    // parent it lacks: it places against its own stubs, and is judged.
    let mut unknown = scene.stub(0).await;
    unknown.id = UNKNOWN;
    let forged = scene.forged(
        0x52,
        vec![UNKNOWN, unit],
        vec![scene.stub(0).await, unknown],
    );
    let forged_id = id_of(&forged);
    scene.carol.ingest(scene.space, vec![forged]).await.unwrap();
    assert!(!scene.placed(unit).await);
    assert!(!scene.placed(forged_id).await);
    assert!(scene.wanted().await.contains(&removal));
    let status = scene
        .carol
        .read(&scene.space, |r| r.status(&unit).copied())
        .await
        .unwrap();
    assert!(status.is_none(), "{status:?}");

    // The removal arrives: everything places on it.
    scene
        .carol
        .ingest(scene.space, vec![scene.removal.clone()])
        .await
        .unwrap();
    assert!(scene.placed(unit).await);
}

#[tokio::test]
async fn a_forged_height_does_not_outlive_the_event() {
    let scene = scene(false).await;
    let removal = id_of(&scene.removal);
    let unit = scene.after[0];
    let forged = scene.forged(0x53, vec![UNKNOWN], vec![scene.stub(40).await]);
    scene.carol.ingest(scene.space, vec![forged]).await.unwrap();
    scene
        .carol
        .ingest(scene.space, vec![scene.removal.clone()])
        .await
        .unwrap();
    let (heights, heads) = scene
        .carol
        .read(&scene.space, |r| {
            let log = r.log().unwrap();
            ((log.height(removal), log.height(unit)), log.heads())
        })
        .await
        .unwrap();
    let real = scene
        .alice
        .read(&scene.space, |r| {
            let log = r.log().unwrap();
            (log.height(removal), log.height(unit))
        })
        .await
        .unwrap();
    assert_eq!(heights, real, "heights at Carol differ from Alice's");
    assert!(!heads.contains(&removal), "{heads:?}");
}

#[tokio::test]
async fn stubs_carried_by_two_strangers_do_not_confirm_a_height() {
    let scene = scene(true).await;
    let removal = id_of(&scene.removal);
    let grant = scene.after[0];
    let unit = scene.after[1];
    assert!(!scene.placed(grant).await);
    let stub = scene.stub(0).await;
    let first = scene.forged(0x54, vec![UNKNOWN], vec![stub]);
    let second = scene.forged(0x55, vec![UNKNOWN], vec![stub]);
    let carried = vec![(removal, id_of(&first)), (removal, id_of(&second))];

    // A `Missing` names the two as carriers of the removal's stub, and
    // then serves them.
    let mut session = SyncSession::new(scene.space);
    let by = Acknowledger::Member(scene.alice.device_id().0);
    for message in [
        Message::Missing {
            ids: Vec::new(),
            carried,
        },
        Message::Events {
            events: vec![first, second],
        },
    ] {
        scene
            .carol
            .sync_receive(
                &mut session,
                by,
                SyncMessage {
                    space: scene.space,
                    message,
                },
            )
            .await
            .unwrap();
    }
    assert!(
        !scene.placed(grant).await,
        "the grant after the removal is placed without it"
    );
    assert!(!scene.placed(unit).await);
    assert!(
        scene.wanted().await.contains(&removal),
        "the removal is no longer asked for"
    );
}
