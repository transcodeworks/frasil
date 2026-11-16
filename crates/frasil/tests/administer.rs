//! Changes to who administers, with their twins in the skeleton (roster.md,
//! "The twin"; peers.md, "The skeleton"): a grant of `administer`, the
//! grantee's enrolment, a grant by the new administrator, and a removal of
//! an administrator.

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Status, Via};

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

async fn valid(device: &Engine, space: &EventId, event: &EventId) -> bool {
    let status = device
        .read(space, |r| r.status(event).copied())
        .await
        .unwrap();
    matches!(status, Some(Status::Valid(_)))
}

async fn grant(by: &Engine, to: &Engine, space: EventId, level: Level) -> EventId {
    by.grant_device_at(
        space,
        to.public_keys().clone(),
        level,
        (level == Level::Administer).then_some(255),
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn administrators_change_with_their_twins() {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();

    // Alice grants Bob administer: a twin first, then the grant.
    let granted = grant(&alice, &bob, space, Level::Administer).await;
    assert!(valid(&alice, &space, &granted).await);
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Administer)
    );

    // Bob enrols at his first sync after the grant.
    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    assert!(valid(&bob, &space, &granted).await);
    carry(&bob, &alice, space).await;

    // Bob, enrolled, grants Carol administer with a twin of his own.
    let by_bob = grant(&bob, &carol, space, Level::Administer).await;
    carry(&bob, &alice, space).await;
    assert!(
        valid(&alice, &space, &by_bob).await,
        "Bob's grant stands at Alice"
    );
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Administer)
    );

    // Alice removes Bob: the twin lowers his slot.
    let removal = alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    assert!(valid(&alice, &space, &removal).await);
    carol.follow(space).await;
    carry(&alice, &carol, space).await;
    for device in [&alice, &carol] {
        assert!(valid(device, &space, &removal).await);
        assert_eq!(
            device
                .read(&space, |r| r.level_of(&bob.device_id()))
                .await
                .unwrap(),
            None
        );
    }
    // Carol enrolled too, and may lower an administrator in turn.
    carry(&carol, &alice, space).await;
    let demotion = carol
        .sign_roster(
            space,
            vec![frasil_space::Change::set_level(
                MemberRef::device(alice.device_id()),
                Level::Write,
            )],
        )
        .await
        .unwrap();
    carry(&carol, &alice, space).await;
    assert!(valid(&alice, &space, &demotion).await);
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&alice.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
}

#[tokio::test]
async fn an_enrolled_administrator_reopens_with_its_pseudonym() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let alice = device().await;
    let (bob, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    drop(bob);
    let bob = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    let by_bob = grant(&bob, &carol, space, Level::Administer).await;
    carry(&bob, &alice, space).await;
    assert!(valid(&alice, &space, &by_bob).await);
}
