//! Keys by their hash (crypto.md, "Keys by their hash"): an event that
//! arrives before any keys that hash to its `kc` is pending (`NoHybridKey`),
//! and is judged again once the device holds such keys, from whichever
//! source brings them: an admission exchange, a record of a log the space
//! does not read, a person's list, or a granted space.

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};

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

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

async fn grant(by: &Engine, space: EventId, to: &Engine, level: Level) {
    by.grant_device_at(
        space,
        to.public_keys().clone(),
        level,
        (level == Level::Administer).then_some(255),
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .unwrap();
}

/// The scene: Alice's team grants Carol, Alice's project grants the team,
/// and Carol heals the project, a scheme-2 event whose author reaches the
/// project only through the team. Dave reads the project, holds no record
/// that carries Carol's keys, and has her heal: its ML-DSA-65 half waits.
struct Scene {
    alice: Engine,
    carol: Engine,
    dave: Engine,
    team: EventId,
    project: EventId,
    heal: EventId,
}

impl Scene {
    async fn new() -> Self {
        let (alice, carol, dave) = (device().await, device().await, device().await);
        let team = alice.create_space().await.unwrap();
        grant(&alice, team, &carol, Level::Write).await;
        carol.follow(team).await;
        carry(&alice, &carol, team).await;
        let project = alice.create_space().await.unwrap();
        alice
            .grant_space(project, team, Level::Write)
            .await
            .unwrap();
        grant(&alice, project, &dave, Level::Read).await;
        carol.follow(project).await;
        carry(&alice, &carol, project).await;
        let heal = carol.heal(project).await.unwrap();
        dave.follow(project).await;
        carry(&alice, &dave, project).await;
        carry(&carol, &dave, project).await;
        let scene = Self {
            alice,
            carol,
            dave,
            team,
            project,
            heal,
        };
        assert_eq!(scene.dave_judges().await, Some("NoHybridKey"));
        scene
    }

    /// The class of Dave's verdict on Carol's heal, or `None` while valid.
    async fn dave_judges(&self) -> Option<&'static str> {
        self.dave
            .read(&self.project, |r| {
                r.status(&self.heal)
                    .expect("the heal is judged")
                    .class()
                    .map(|class| class.name())
            })
            .await
            .unwrap()
    }
}

/// Dave's verdict once Carol's keys verify her heal: it no longer waits for
/// keys, whatever else it still waits for.
fn verified(class: Option<&str>) -> bool {
    class != Some("NoHybridKey")
}

#[tokio::test]
async fn keys_from_an_admission_exchange_verify_a_pending_event() {
    let scene = Scene::new().await;
    scene
        .dave
        .learn_keys(scene.carol.public_keys().clone())
        .await
        .unwrap();
    let class = scene.dave_judges().await;
    assert!(verified(class), "{class:?}");
}

#[tokio::test]
async fn keys_from_a_space_the_project_does_not_read_verify_a_pending_event() {
    let scene = Scene::new().await;
    // An unrelated space that grants Carol directly: the project reads
    // nothing of it, but its grant carries her keys.
    let other = scene.alice.create_space().await.unwrap();
    grant(&scene.alice, other, &scene.carol, Level::Read).await;
    grant(&scene.alice, other, &scene.dave, Level::Read).await;
    scene.dave.follow(other).await;
    carry(&scene.alice, &scene.dave, other).await;
    let class = scene.dave_judges().await;
    assert!(verified(class), "{class:?}");
}

#[tokio::test]
async fn keys_from_a_persons_list_verify_a_pending_event() {
    let scene = Scene::new().await;
    let person = scene.carol.make_person(&[3; 32]).await.unwrap().person;
    scene
        .dave
        .receive_list(scene.carol.list_events(&person).await)
        .await
        .unwrap();
    let class = scene.dave_judges().await;
    assert!(verified(class), "{class:?}");
}

#[tokio::test]
async fn keys_from_the_granted_space_verify_a_pending_event_and_admit_it() {
    let scene = Scene::new().await;
    grant(&scene.alice, scene.team, &scene.dave, Level::Read).await;
    scene.dave.follow(scene.team).await;
    carry(&scene.alice, &scene.dave, scene.team).await;
    assert_eq!(scene.dave_judges().await, None, "valid through the team");
}
