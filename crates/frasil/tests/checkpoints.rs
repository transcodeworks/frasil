//! Checkpoints at a device (roster.md, 3.15 Checkpoints, 3.15.7 Clients):
//! a checkpoint that takes effect once every administrator wrote after it,
//! one proposed by itself at the threshold, a device that forgets what came
//! before it and keeps working, at rest too, late work re-sent, re-signed or
//! listed, a newcomer that starts from the checkpoint and opens again from
//! its store, a person's device list checkpointed and forgotten, and a
//! device that forgot under the losing one of two concurrent checkpoints.
#![cfg(feature = "adapter-loro")]

use frasil::CheckpointPolicy;
use frasil::advanced::outbox::Acknowledger;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::{EventId, kind};
use frasil_space::{Change, HistoryMode, Level, MemberRef, Status, Via};

async fn device() -> Engine {
    let (device, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    // Each test proposes and forgets when it means to.
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
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
    .expect("a grant")
}

/// Every event `from` holds, and the record objects `to` lacks, to `to`.
async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.follow(space).await;
    to.ingest(space, from.events(&space).await)
        .await
        .expect("ingested");
    for locator in to.missing_objects(&space).await {
        if let Some(stored) = from.stored_object(&space, &locator).await {
            to.receive_object(space, &locator, &stored)
                .await
                .expect("an object");
        }
    }
}

/// Takes every event `device` signed in the space as durable at a peer: a
/// device forgets nothing its outbox still holds.
async fn durable(device: &Engine, space: EventId) {
    let pending = device.outbox(&space).await;
    device
        .acknowledge(space, Acknowledger::Peer([1; 32]), &pending)
        .await
        .expect("acknowledged");
}

async fn sync(a: &Engine, b: &Engine, space: EventId) {
    carry(a, b, space).await;
    carry(b, a, space).await;
}

async fn status(device: &Engine, space: &EventId, id: &EventId) -> Option<Status> {
    device
        .read(space, |r| r.status(id).copied())
        .await
        .expect("a space")
}

async fn in_effect(device: &Engine, space: &EventId) -> Option<[u8; 32]> {
    device
        .checkpoint_status(space)
        .await
        .expect("a space")
        .in_effect
        .map(|id| *id.as_bytes())
}

async fn write(device: &Engine, space: EventId, doc: &frasil_units::stream::Opening, words: &str) {
    device
        .edit_document(space, doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), words).unwrap();
        })
        .await
        .expect("an edit");
}

#[tokio::test]
async fn a_checkpoint_takes_effect_once_every_administrator_wrote_after_it() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    carry(&alice, &bob, space).await;

    let c = alice.propose_checkpoint(space).await.unwrap();
    assert!(matches!(
        status(&alice, &space, &c).await,
        Some(Status::Valid(_))
    ));
    let pending = alice.checkpoint_status(&space).await.unwrap();
    assert_eq!(pending.in_effect, None);
    assert_eq!(pending.pending.len(), 1);
    assert_eq!(*pending.pending[0].id.as_bytes(), c.0);
    assert_eq!(
        pending.pending[0]
            .waiting_for
            .iter()
            .map(|m| *m.as_bytes())
            .collect::<Vec<_>>(),
        vec![bob.device_id().0],
        "it waits for Bob alone: Alice voted by the checkpoint itself"
    );

    // Bob has nothing to write: he votes by an anchor after it.
    sync(&alice, &bob, space).await;
    let anchor = bob.acknowledge_checkpoint(space).await.unwrap();
    assert!(anchor.is_some());
    assert_eq!(in_effect(&bob, &space).await, Some(c.0));
    // He votes once.
    assert_eq!(bob.acknowledge_checkpoint(space).await.unwrap(), None);
    sync(&alice, &bob, space).await;
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    assert!(
        alice
            .checkpoint_status(&space)
            .await
            .unwrap()
            .pending
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "signs 1,024 roster events, each judged in full"]
async fn an_administrator_proposes_by_itself_at_the_threshold() {
    let alice = device().await;
    let bob = device().await;
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL);
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Write).await;
    let member = MemberRef::device(bob.device_id());
    let mut level = Level::Read;
    while alice
        .checkpoint_status(&space)
        .await
        .unwrap()
        .roster_events_since
        < frasil::PROPOSE_AT_ROSTER_EVENTS
    {
        alice
            .sign_roster(space, vec![Change::set_level(member, level)])
            .await
            .unwrap();
        level = if level == Level::Read {
            Level::Write
        } else {
            Level::Read
        };
        // Under the manual policy, nothing is proposed.
        assert_eq!(
            alice.maintain_checkpoints(space).await.unwrap().proposed,
            None
        );
    }
    alice.set_checkpoint_policy(CheckpointPolicy::AUTOMATIC.forgetting(false));
    let work = alice.maintain_checkpoints(space).await.unwrap();
    let c = work.proposed.expect("a checkpoint at the threshold");
    // Alice is the only administrator: it is in effect at once, and the
    // count starts again from it.
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    let after = alice.checkpoint_status(&space).await.unwrap();
    assert_eq!(after.epoch, 1);
    assert!(after.roster_events_since < frasil::PROPOSE_AT_ROSTER_EVENTS);
}

#[tokio::test]
async fn a_device_forgets_what_came_before_and_keeps_working() {
    let alice = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "one").await;
    carry(&alice, &carol, space).await;

    // Alice administers alone: her checkpoint is in effect at once.
    let c = alice.propose_checkpoint(space).await.unwrap();
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    let before = alice.events(&space).await.len();
    durable(&alice, space).await;
    let dropped = alice.forget_before_checkpoint(space).await.unwrap();
    assert!(dropped > 0, "the grant before the checkpoint is forgotten");
    assert!(alice.events(&space).await.len() < before);
    let forgot = alice.checkpoint_status(&space).await.unwrap();
    assert!(forgot.forgot);
    assert_eq!(forgot.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    // Forgetting again drops nothing.
    durable(&alice, space).await;
    assert_eq!(alice.forget_before_checkpoint(space).await.unwrap(), 0);

    // The document keeps its content, and both keep writing.
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "one"
    );
    write(&alice, space, &doc, " two").await;
    carry(&alice, &carol, space).await;
    write(&carol, space, &doc, " three").await;
    carry(&carol, &alice, space).await;
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );
    assert_eq!(
        text(&carol.document(&space, &doc.stream()).await.unwrap()),
        "one two three"
    );
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
}

#[tokio::test]
async fn a_device_that_forgot_opens_again_from_its_store() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "kept").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    // Carol holds the history before it: she is no newcomer, whom a
    // snapshot admits.
    carry(&alice, &carol, space).await;
    durable(&alice, space).await;
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
    let held = alice.events(&space).await.len();
    drop(alice);

    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    let reopened = alice.checkpoint_status(&space).await.unwrap();
    assert_eq!(reopened.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    assert!(reopened.forgot);
    assert_eq!(alice.events(&space).await.len(), held);
    assert_eq!(
        alice
            .read(&space, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "kept"
    );
    write(&alice, space, &doc, " and more").await;
    carry(&alice, &carol, space).await;
    assert_eq!(
        text(&carol.document(&space, &doc.stream()).await.unwrap()),
        "kept and more"
    );
}

/// Each event of the space the device holds, with its height, and the
/// status of each unit.
async fn placed(device: &Engine, space: &EventId) -> Vec<(EventId, u64, Option<Status>)> {
    device
        .read(space, |r| {
            let log = r.log().expect("a log");
            log.canonical()
                .into_iter()
                .map(|id| {
                    let unit = log.event(id).is_some_and(|e| e.kind() == kind::UNIT);
                    let status = if unit { r.status(&id).copied() } else { None };
                    (id, log.height(id).expect("placed"), status)
                })
                .collect()
        })
        .await
        .expect("a space")
}

/// A device that forgot places each event it kept of the checkpoint's past
/// on its dropped parents at the heights it was judged at (events.md,
/// "Placement and order"; at-rest.md, the `dropped` table, key 3): Alice
/// edits between roster events, so that her units rest on frame events she
/// drops. Each kept event keeps its height, each unit its verdict, and the
/// document its content, in memory and after opening again.
#[tokio::test]
async fn kept_events_keep_their_heights_on_dropped_parents() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[3; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let carol = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "one").await;
    grant(&alice, &bob, space, Level::Read).await;
    write(&alice, space, &doc, " two").await;
    write(&alice, space, &doc, " three").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    let content = text(&alice.document(&space, &doc.stream()).await.unwrap());
    let before = placed(&alice, &space).await;
    durable(&alice, space).await;
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);

    let same = |after: &[(EventId, u64, Option<Status>)], label: &str| {
        assert!(
            after.len() < before.len(),
            "{label}: some events are dropped"
        );
        for kept in after {
            assert!(before.contains(kept), "{label}: {kept:?} as before");
        }
    };
    let forgot = placed(&alice, &space).await;
    same(&forgot, "forgot");
    // Some kept event rests on a dropped parent whose height is kept.
    let on_dropped = alice
        .read(&space, |r| {
            let log = r.log().unwrap();
            log.events()
                .flat_map(|event| event.parents().to_vec())
                .filter(|&p| log.dropped_height(p).is_some())
                .count()
        })
        .await
        .unwrap();
    assert!(on_dropped > 0, "a kept event cites a dropped parent");
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        content,
        "in memory"
    );
    drop(alice);

    let alice = Engine::open(platform, &sealed, &[3; 32], registry)
        .await
        .unwrap();
    let reopened = placed(&alice, &space).await;
    same(&reopened, "reopened");
    assert_eq!(reopened, forgot);
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        content
    );
    write(&alice, space, &doc, " five").await;
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        format!("{content} five")
    );
}

/// Carol edits while Alice, the only administrator, checkpoints: her unit
/// is late, and she sends it again after the checkpoint, once. Returns
/// Alice, the space, the document and the re-submission.
async fn a_late_edit_sent_again() -> (Engine, EventId, frasil_units::stream::Opening, EventId) {
    let (alice, _, space, doc, again) = a_late_edit_sent_again_between(device().await).await;
    (alice, space, doc, again)
}

/// As [`a_late_edit_sent_again`], with Alice given: Alice and Carol, the
/// space, the document, and Carol's re-submission.
async fn a_late_edit_sent_again_between(
    alice: Engine,
) -> (
    Engine,
    Engine,
    EventId,
    frasil_units::stream::Opening,
    EventId,
) {
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &carol, space).await;

    // Carol's unit is concurrent with the checkpoint.
    write(&carol, space, &doc, "b").await;
    let late = carol
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.author() == &carol.device_id())
        .map(|event| event.id())
        .next_back()
        .expect("Carol's unit");
    let c = alice.propose_checkpoint(space).await.unwrap();
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));

    sync(&alice, &carol, space).await;
    assert_eq!(in_effect(&carol, &space).await, Some(c.0));
    let class = status(&carol, &space, &late).await.and_then(|s| s.class());
    assert_eq!(class.map(frasil_base::errors::Class::name), Some("Late"));

    let again = carol.resubmit_late_units(space).await.unwrap();
    assert_eq!(again.len(), 1);
    assert!(carol.resubmit_late_units(space).await.unwrap().is_empty());
    carry(&carol, &alice, space).await;
    (alice, carol, space, doc, again[0])
}

#[tokio::test]
async fn a_late_edit_is_sent_again() {
    let (alice, space, _, again) = a_late_edit_sent_again().await;
    assert!(matches!(
        status(&alice, &space, &again).await,
        Some(Status::Valid(_))
    ));
}

#[tokio::test]
async fn a_late_edits_content_arrives_again() {
    let (alice, space, doc, _) = a_late_edit_sent_again().await;
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "ab"
    );
}

#[tokio::test]
async fn a_late_edits_content_arrives_again_at_its_writer() {
    let (_, carol, space, doc, _) = a_late_edit_sent_again_between(device().await).await;
    // Carol holds the late unit and its re-submission alike.
    assert_eq!(
        text(&carol.document(&space, &doc.stream()).await.unwrap()),
        "ab"
    );
}

#[tokio::test]
async fn a_late_edits_content_stays_after_opening_again_from_the_store() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let (alice, _, space, doc, again) = a_late_edit_sent_again_between(alice).await;
    durable(&alice, space).await;
    drop(alice);

    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    assert!(matches!(
        status(&alice, &space, &again).await,
        Some(Status::Valid(_))
    ));
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "ab"
    );
}

/// Alice and Bob administer, with Dave writing; Bob makes `changes` while
/// Alice checkpoints, then votes for her checkpoint once he receives it.
async fn concurrent_with_a_checkpoint(
    dave: &Engine,
    changes: Vec<Change>,
) -> (Engine, Engine, EventId, EventId) {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    grant(&alice, dave, space, Level::Write).await;
    carry(&alice, &bob, space).await;
    let late = bob.sign_roster(space, changes).await.unwrap();
    let c = alice.propose_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    assert_eq!(in_effect(&bob, &space).await, Some(c.0));
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    let class = status(&bob, &space, &late).await.and_then(|s| s.class());
    assert_eq!(class.map(frasil_base::errors::Class::name), Some("Late"));
    (alice, bob, space, late)
}

#[tokio::test]
async fn a_late_removal_is_signed_again() {
    let dave_keys = device().await;
    let dave = MemberRef::device(dave_keys.device_id());
    let (alice, bob, space, _) =
        concurrent_with_a_checkpoint(&dave_keys, vec![Change::remove(dave)]).await;
    // The removal is late, so Dave is still in, until Bob signs it again.
    assert!(bob.read(&space, |r| r.roster().is_in(&dave)).await.unwrap());
    let again = bob.resign_late_removals(space).await.unwrap();
    assert_eq!(again.len(), 1);
    assert!(bob.resign_late_removals(space).await.unwrap().is_empty());
    assert!(bob.late_changes(&space).await.unwrap().is_empty());
    carry(&bob, &alice, space).await;
    assert!(
        !alice
            .read(&space, |r| r.roster().is_in(&dave))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_late_grant_is_listed_for_the_administrator() {
    let erin = device().await;
    let change = Change::grant_device(
        erin.public_keys().clone(),
        Level::Write,
        HistoryMode::WithHistory,
        Via::Code,
    );
    let dave = device().await;
    let (alice, bob, space, late) = concurrent_with_a_checkpoint(&dave, vec![change]).await;
    // A grant is not made again by itself: it is listed.
    assert!(bob.resign_late_removals(space).await.unwrap().is_empty());
    let listed = bob.late_changes(&space).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(*listed[0].event.as_bytes(), late.0);
    assert_eq!(listed[0].kind, frasil::LateChangeKind::Grant);
    assert_eq!(
        listed[0].member.map(|m| *m.as_bytes()),
        Some(erin.device_id().0)
    );
    let erin_ref = MemberRef::device(erin.device_id());
    assert!(
        !alice
            .read(&space, |r| r.roster().is_in(&erin_ref))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_newcomer_starts_from_the_checkpoint_without_the_history_before_it() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "before").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    durable(&alice, space).await;
    alice.forget_before_checkpoint(space).await.unwrap();

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
    bob.follow(space).await;
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    // Bob is served the genesis, the checkpoint and what follows it; a
    // peer that truncated answers `Missing` for what came before.
    let served: Vec<Vec<u8>> = alice
        .events(&space)
        .await
        .into_iter()
        .filter(|signed| {
            frasil_events::decode(signed).is_ok_and(|event| {
                event.id() == space
                    || event.id() == c
                    || !event.cuts().is_empty()
                    || event.kind() == frasil_events::kind::STORAGE
            })
        })
        .collect();
    bob.ingest(space, served).await.unwrap();
    for _ in 0..8 {
        let wanted = bob.read(&space, |r| r.wanted()).await.unwrap();
        if wanted.is_empty() {
            break;
        }
        bob.take_truncated(space, &wanted).await.unwrap();
    }
    for locator in bob.missing_objects(&space).await {
        if let Some(stored) = alice.stored_object(&space, &locator).await {
            bob.receive_object(space, &locator, &stored).await.unwrap();
        }
    }
    let started = bob.checkpoint_status(&space).await.unwrap();
    assert_eq!(started.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "before"
    );
    // Bob writes after the checkpoint, and Alice reads it.
    write(&bob, space, &doc, ", after").await;
    carry(&bob, &alice, space).await;
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "before, after"
    );
}

#[tokio::test]
async fn an_administrator_proposes_by_itself_at_a_lowered_threshold() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Write).await;
    let member = MemberRef::device(bob.device_id());
    // Four roster events call for a checkpoint under this policy.
    let policy = CheckpointPolicy::AUTOMATIC
        .forgetting(false)
        .proposing_at(4, frasil::PROPOSE_AT_FRAME_BYTES);
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let mut level = Level::Read;
    while alice
        .checkpoint_status(&space)
        .await
        .unwrap()
        .roster_events_since
        < 4
    {
        alice
            .sign_roster(space, vec![Change::set_level(member, level)])
            .await
            .unwrap();
        level = if level == Level::Read {
            Level::Write
        } else {
            Level::Read
        };
    }
    // The default thresholds are far off.
    alice.set_checkpoint_policy(CheckpointPolicy::AUTOMATIC.forgetting(false));
    assert_eq!(
        alice.maintain_checkpoints(space).await.unwrap().proposed,
        None
    );
    alice.set_checkpoint_policy(policy);
    let c = alice
        .maintain_checkpoints(space)
        .await
        .unwrap()
        .proposed
        .expect("a checkpoint at the lowered threshold");
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    let after = alice.checkpoint_status(&space).await.unwrap();
    assert_eq!(after.epoch, 1);
    assert!(after.roster_events_since < 4);
}

#[tokio::test]
async fn a_newcomer_from_a_checkpoint_opens_again_from_its_store() {
    let alice = device().await;
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (bob, sealed) = Engine::create(platform.clone(), &[3; 32], registry.clone())
        .await
        .unwrap();
    bob.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let space = alice.create_space().await.unwrap();
    // A roster event before the checkpoint, which a peer that truncated
    // no longer serves.
    let carol = device().await;
    grant(&alice, &carol, space, Level::Read).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "before").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    durable(&alice, space).await;
    alice.forget_before_checkpoint(space).await.unwrap();
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
    bob.follow(space).await;
    bob.adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    let served: Vec<Vec<u8>> = alice
        .events(&space)
        .await
        .into_iter()
        .filter(|signed| {
            frasil_events::decode(signed).is_ok_and(|event| {
                event.id() == space
                    || event.id() == c
                    || !event.cuts().is_empty()
                    || event.kind() == frasil_events::kind::STORAGE
            })
        })
        .collect();
    bob.ingest(space, served).await.unwrap();
    // What a peer that truncated answers `Missing` for stands as dropped.
    let mut truncated = 0;
    for _ in 0..8 {
        let wanted = bob.read(&space, |r| r.wanted()).await.unwrap();
        if wanted.is_empty() {
            break;
        }
        truncated += wanted.len();
        bob.take_truncated(space, &wanted).await.unwrap();
    }
    assert!(truncated > 0, "the checkpoint's past was truncated");
    for locator in bob.missing_objects(&space).await {
        if let Some(stored) = alice.stored_object(&space, &locator).await {
            bob.receive_object(space, &locator, &stored).await.unwrap();
        }
    }
    assert_eq!(in_effect(&bob, &space).await, Some(c.0));
    let held = bob.events(&space).await.len();
    drop(bob);

    // Reopened, Bob places the checkpoint again: its record key, the
    // dropped parents and the kept envelopes came back from the store.
    let bob = Engine::open(platform, &sealed, &[3; 32], registry)
        .await
        .unwrap();
    assert_eq!(in_effect(&bob, &space).await, Some(c.0));
    assert_eq!(bob.events(&space).await.len(), held);
    assert!(
        bob.read(&space, |r| r.wanted()).await.unwrap().is_empty(),
        "nothing truncated is asked for again"
    );
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "before"
    );
    write(&bob, space, &doc, ", after").await;
    carry(&bob, &alice, space).await;
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "before, after"
    );
}

#[tokio::test]
async fn a_list_checkpoint_takes_effect_and_the_device_forgets_the_list() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (bob, _) = Engine::create(platform.clone(), &[4; 32], registry.clone())
        .await
        .unwrap();
    bob.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let phone = device().await;
    let made = bob.make_person(&[4; 32]).await.unwrap();
    let person = made.person;
    // A phone added, then revoked: neither event outlives the checkpoint.
    let (keys, proof) = phone.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    bob.revoke_device(phone.device_id()).await.unwrap();
    let before = bob.list_events(&person).await.len();

    // Bob is the only device of his person that votes: his list checkpoint
    // is in effect at once.
    let c = bob.propose_list_checkpoint().await.unwrap();
    let status = bob.list_checkpoint_status().await;
    assert_eq!(status.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    assert!(status.pending.is_empty());
    assert!(!status.forgot);
    assert!(status.rivals.is_empty());

    let dropped = bob.forget_lists_before_checkpoints().await.unwrap();
    assert!(
        dropped >= 2,
        "the phone's add and its revocation are dropped"
    );
    assert!(bob.list_events(&person).await.len() < before + 1);
    let forgot = bob.list_checkpoint_status().await;
    assert!(forgot.forgot);
    assert_eq!(forgot.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    // Forgetting again drops nothing.
    assert_eq!(bob.forget_lists_before_checkpoints().await.unwrap(), 0);
    assert_eq!(bob.person_devices(&person).await, vec![bob.device_id()]);

    // The personal space reads the list as held: Bob still administers it
    // through his person.
    let space = made.personal_space;
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Administer)
    );
    let doc = bob.new_document().unwrap();
    write(&bob, space, &doc, "after the list checkpoint").await;
    assert_eq!(
        text(&bob.document(&space, &doc.stream()).await.unwrap()),
        "after the list checkpoint"
    );
    let held = bob.list_events(&person).await.len();
    drop(bob);

    // At rest, the list is held from its checkpoint on.
    let bob =
        frasil::advanced::Engine::open_as(platform, &made.sealed, &[4; 32], Some(person), registry)
            .await
            .unwrap();
    let reopened = bob.list_checkpoint_status().await;
    assert!(reopened.forgot);
    assert_eq!(reopened.in_effect.map(|id| *id.as_bytes()), Some(c.0));
    assert_eq!(bob.list_events(&person).await.len(), held);
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Administer)
    );
}

#[tokio::test]
async fn a_device_that_forgot_under_the_losing_checkpoint_holds_a_rival_pending() {
    let alice = device().await;
    let bob = device().await;
    // Rex is the space's recovery member; Carol keeps everything.
    let rex = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_administrator(
            space,
            bob.public_keys().clone(),
            100,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice
        .grant_recovery_member(
            space,
            rex.public_keys().clone(),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    carry(&alice, &bob, space).await;
    carry(&alice, &rex, space).await;
    carry(&alice, &carol, space).await;
    assert_eq!(
        alice.recovery_members(&space).await.unwrap(),
        vec![rex.device_id()]
    );

    // Two concurrent checkpoints that both take effect (roster.md, 3.15.4,
    // "Concurrent checkpoints that are both stable"): Alice demotes Bob,
    // whom she outranks, and checkpoints alone; Bob checkpoints in his own
    // branch, and Rex, the recovery member, excuses Alice there by marking
    // her dormant after it.
    alice
        .sign_roster(
            space,
            vec![Change::set_level(
                MemberRef::device(bob.device_id()),
                Level::Write,
            )],
        )
        .await
        .unwrap();
    let ca = alice.propose_checkpoint(space).await.unwrap();
    let cb = bob.propose_checkpoint(space).await.unwrap();
    carry(&bob, &rex, space).await;
    rex.set_dormant(space, MemberRef::device(alice.device_id()), true)
        .await
        .unwrap()
        .expect("Alice marked dormant");
    carry(&rex, &bob, space).await;
    carry(&rex, &carol, space).await;
    assert_eq!(in_effect(&alice, &space).await, Some(ca.0));
    assert_eq!(in_effect(&bob, &space).await, Some(cb.0));
    carry(&alice, &carol, space).await;
    carry(&bob, &carol, space).await;
    durable(&alice, space).await;
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
    durable(&bob, space).await;
    assert!(bob.forget_before_checkpoint(space).await.unwrap() > 0);

    // The smaller ID wins; the device that forgot under the other one
    // meets the winner as a rival.
    let (winner, loser, won, lost) = if ca < cb {
        (&alice, &bob, ca, cb)
    } else {
        (&bob, &alice, cb, ca)
    };
    carry(winner, loser, space).await;
    // The winner forgot its own events before its checkpoint: the loser
    // fetches the parents it lacks from Carol, and nothing else.
    for _ in 0..4 {
        let wanted = loser.read(&space, |r| r.wanted()).await.unwrap();
        if status(loser, &space, &won).await.is_some() || wanted.is_empty() {
            break;
        }
        let served: Vec<Vec<u8>> = carol
            .events(&space)
            .await
            .into_iter()
            .filter(|signed| {
                frasil_events::decode(signed).is_ok_and(|event| wanted.contains(&event.id()))
            })
            .collect();
        loser.ingest(space, served).await.unwrap();
    }
    for locator in loser.missing_objects(&space).await {
        if let Some(stored) = carol.stored_object(&space, &locator).await {
            loser
                .receive_object(space, &locator, &stored)
                .await
                .unwrap();
        }
    }
    let held = loser.checkpoint_status(&space).await.unwrap();
    assert_eq!(
        held.rivals
            .iter()
            .map(|id| *id.as_bytes())
            .collect::<Vec<_>>(),
        vec![won.0]
    );
    let class = status(loser, &space, &lost)
        .await
        .and_then(|s| s.class())
        .map(|c| frasil_base::errors::Class::name(c));
    assert_eq!(
        class,
        Some("Pending"),
        "everything waits for the rival's past"
    );
    // It forgets nothing more meanwhile, and asks for the rival's past.
    durable(loser, space).await;
    assert_eq!(loser.forget_before_checkpoint(space).await.unwrap(), 0);
    assert!(!loser.read(&space, |r| r.wanted()).await.unwrap().is_empty());

    // Carol, which kept everything, serves it; the loser then follows the
    // winner.
    carry(&carol, loser, space).await;
    let doc = carol.new_document().unwrap();
    write(&carol, space, &doc, "settled").await;
    carry(&carol, loser, space).await;
    let settled = loser.checkpoint_status(&space).await.unwrap();
    assert!(settled.rivals.is_empty());
    assert_eq!(settled.in_effect.map(|id| *id.as_bytes()), Some(won.0));
}

#[tokio::test]
async fn a_contested_checkpoint_is_reported_with_its_lowering_and_never_voted_for() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_administrator(
            space,
            bob.public_keys().clone(),
            100,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(&alice, &bob, space).await;

    // Alice demotes Bob, whom she outranks, while Bob checkpoints: Bob's
    // checkpoint is contested at Alice (roster.md, 3.15.7, "Contested
    // checkpoints").
    let demotion = alice
        .sign_roster(
            space,
            vec![Change::set_level(
                MemberRef::device(bob.device_id()),
                Level::Write,
            )],
        )
        .await
        .unwrap();
    let theirs = bob.propose_checkpoint(space).await.unwrap();
    carry(&bob, &alice, space).await;
    let status = alice.checkpoint_status(&space).await.unwrap();
    assert_eq!(
        status
            .withheld
            .iter()
            .map(|id| *id.as_bytes())
            .collect::<Vec<_>>(),
        vec![theirs.0]
    );
    let contested = &status.contested[0];
    assert_eq!(*contested.id.as_bytes(), theirs.0);
    assert_eq!(*contested.proposed_by.as_bytes(), bob.device_id().0);
    assert_eq!(
        contested
            .ours
            .iter()
            .map(|id| *id.as_bytes())
            .collect::<Vec<_>>(),
        vec![demotion.0]
    );
    // Alice never votes for it, and it waits for her for good.
    assert_eq!(alice.acknowledge_checkpoint(space).await.unwrap(), None);
    carry(&alice, &bob, space).await;
    assert_eq!(in_effect(&bob, &space).await, None);
}

#[tokio::test]
async fn a_device_signs_no_ack_for_a_list_checkpoint_it_contests() {
    let laptop = device().await;
    let made = laptop.make_person(&[4; 32]).await.unwrap();
    let person = made.person;
    let phone = device().await;
    let tablet = device().await;
    for joiner in [&phone, &tablet] {
        let (keys, proof) = joiner.list_keys(&person, &laptop.device_id());
        laptop.add_device(keys, proof).await.unwrap();
    }
    for joiner in [&phone, &tablet] {
        joiner
            .adopt_person(person, laptop.list_events(&person).await, &[7; 32])
            .await
            .unwrap();
    }

    // The tablet, the most junior device, revokes the laptop and the phone
    // from its view and checkpoints the list: its checkpoint hears both,
    // revoked there only by a device they outrank (identity.md, "List
    // checkpoints", heard devices).
    tablet.revoke_device(laptop.device_id()).await.unwrap();
    tablet.revoke_device(phone.device_id()).await.unwrap();
    let x = tablet.propose_list_checkpoint().await.unwrap();
    phone
        .receive_list(tablet.list_events(&person).await)
        .await
        .unwrap();
    let waiting = phone.list_waiting_for().await;
    let waits_for_phone = waiting
        .iter()
        .any(|(c, devices)| *c == x && devices.contains(&phone.device_id()));
    assert!(waits_for_phone, "{waiting:?}");
    // The phone contests it: it signs no ack, and it never takes effect.
    let work = phone.maintain_list_checkpoint().await.unwrap();
    assert_eq!(work.acknowledged, None);
    assert_eq!(phone.list_checkpoint_status().await.in_effect, None);
}

#[tokio::test]
async fn a_unit_refused_by_a_removal_is_sent_again_after_a_regrant() {
    let alice = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &carol, space).await;

    // Carol edits while Alice removes her: her unit is refused.
    write(&carol, space, &doc, "b").await;
    let refused = carol
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.author() == &carol.device_id())
        .map(|event| event.id())
        .next_back()
        .expect("Carol's unit");
    alice
        .remove(space, MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    sync(&alice, &carol, space).await;
    assert_eq!(
        status(&alice, &space, &refused)
            .await
            .and_then(|s| s.class())
            .map(frasil_base::errors::Class::name),
        Some("RefusedByRemoval")
    );
    // Nothing goes again while Carol does not write.
    assert!(
        carol
            .resubmit_refused_units(space)
            .await
            .unwrap()
            .is_empty()
    );

    // Alice grants her again; Carol sends the edit again, once.
    grant(&alice, &carol, space, Level::Write).await;
    carry(&alice, &carol, space).await;
    let again = carol.resubmit_refused_units(space).await.unwrap();
    assert_eq!(again.len(), 1);
    assert!(
        carol
            .resubmit_refused_units(space)
            .await
            .unwrap()
            .is_empty()
    );
    carry(&carol, &alice, space).await;
    assert!(matches!(
        status(&alice, &space, &again[0]).await,
        Some(Status::Valid(_))
    ));
    assert_eq!(
        text(&alice.document(&space, &doc.stream()).await.unwrap()),
        "ab"
    );
}

#[tokio::test]
async fn a_checkpointed_space_judged_refresh_by_refresh_matches_one_judged_at_once() {
    // Alice's replica judges after every change, taking what the last
    // judgement found (stable checkpoints, records, final validity); a
    // device that takes the same events at once judges them from scratch.
    let alice = device().await;
    let bob = device().await;
    let fresh = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    grant(&alice, &fresh, space, Level::Read).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &bob, space).await;
    alice.propose_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    for round in 0..6 {
        write(&alice, space, &doc, "b").await;
        if round % 2 == 0 {
            let other = device().await;
            grant(&alice, &other, space, Level::Write).await;
        }
        if round == 3 {
            // Alice's pseudonym votes for the first cut before she proposes
            // the second checkpoint, whose cut counts its epoch from it.
            alice.acknowledge_checkpoint(space).await.unwrap();
            alice.propose_checkpoint(space).await.unwrap();
            sync(&alice, &bob, space).await;
            bob.acknowledge_checkpoint(space).await.unwrap();
            sync(&alice, &bob, space).await;
        }
    }
    carry(&alice, &fresh, space).await;
    let ids: Vec<EventId> = alice
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .map(|event| event.id())
        .collect();
    for id in &ids {
        assert_eq!(
            status(&alice, &space, id).await,
            status(&fresh, &space, id).await,
            "{id:?}"
        );
    }
    assert_eq!(
        in_effect(&alice, &space).await,
        in_effect(&fresh, &space).await
    );
    assert_eq!(
        alice.checkpoint_status(&space).await.unwrap().pending.len(),
        fresh.checkpoint_status(&space).await.unwrap().pending.len()
    );
    assert!(in_effect(&alice, &space).await.is_some());
}

#[tokio::test]
async fn a_space_with_no_peer_checkpoints_three_times_in_a_row() {
    // Alice and Bob administer a space that never meets a peer, and sync
    // with each other only. Each checkpoint takes effect once both vote,
    // and its skeleton cut once both pseudonyms vote for it, which their
    // acknowledgements do: so the next checkpoint's cut counts its epoch
    // from it, and each checkpoint in turn takes effect (peers.md,
    // "Skeleton cuts"; roster.md, 3.15.7).
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &bob, space).await;
    bob.enrol(&space).await.unwrap();
    sync(&alice, &bob, space).await;
    let mut chain = Vec::new();
    for epoch in 1..=3u64 {
        let c = alice.propose_checkpoint(space).await.unwrap();
        sync(&alice, &bob, space).await;
        assert!(bob.acknowledge_checkpoint(space).await.unwrap().is_some());
        sync(&alice, &bob, space).await;
        // The proposer's pseudonym votes for its own cut after it.
        alice.acknowledge_checkpoint(space).await.unwrap();
        sync(&alice, &bob, space).await;
        for device in [&alice, &bob] {
            let status = device.checkpoint_status(&space).await.unwrap();
            assert_eq!(status.in_effect.map(|id| *id.as_bytes()), Some(c.0));
            assert_eq!(status.epoch, epoch);
        }
        chain.push(c);
        write(&alice, space, &doc, "b").await;
        write(&bob, space, &doc, "c").await;
        sync(&alice, &bob, space).await;
    }
    for c in &chain {
        assert!(status(&bob, &space, c).await.is_some_and(|s| s.is_valid()));
    }
}

#[tokio::test]
async fn a_checkpoint_is_not_proposed_before_the_last_cut_is_in_effect() {
    // The first checkpoint is in effect, but Alice's pseudonym has not yet
    // voted for its cut: a second checkpoint now would count its cut's
    // epoch from no cut in effect and be void (`BadTwin`), so the client
    // refuses to propose it (roster.md, 3.15.7, "Proposing"). Once her
    // pseudonym votes, it proposes.
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    carry(&alice, &bob, space).await;
    bob.enrol(&space).await.unwrap();
    sync(&alice, &bob, space).await;
    let first = alice.propose_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    assert_eq!(in_effect(&alice, &space).await, Some(first.0));
    assert!(matches!(
        alice.propose_checkpoint(space).await,
        Err(frasil::Error::NotAllowed(_))
    ));
    alice.acknowledge_checkpoint(space).await.unwrap();
    let second = alice.propose_checkpoint(space).await.unwrap();
    let pending = alice.checkpoint_status(&space).await.unwrap().pending;
    assert!(
        pending.iter().any(|p| *p.id.as_bytes() == second.0),
        "the second checkpoint waits for Bob: {pending:?}"
    );
}

/// Every event's verdict and the document's text at a device.
async fn shown(
    device: &Engine,
    space: EventId,
    doc: &frasil_units::stream::Opening,
    ids: &[EventId],
) -> (String, Vec<Option<Status>>) {
    let text = text(&device.document(&space, &doc.stream()).await.unwrap());
    let mut statuses = Vec::new();
    for id in ids {
        statuses.push(status(device, &space, id).await);
    }
    (text, statuses)
}

#[tokio::test]
async fn a_device_that_forgot_shows_a_writers_edits_from_before_the_checkpoint() {
    // Carol writes, granted before Alice's checkpoint, and edits before
    // and after it. Alice forgets the past; Bob keeps everything. Alice
    // shows what Bob shows: the text and every unit's verdict, before and
    // after she opens again from her store.
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Read).await;
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "one").await;
    carry(&alice, &carol, space).await;
    write(&carol, space, &doc, " two").await;
    carry(&carol, &alice, space).await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    carry(&alice, &carol, space).await;
    write(&carol, space, &doc, " three").await;
    carry(&carol, &alice, space).await;
    carry(&alice, &bob, space).await;
    let ids: Vec<EventId> = alice
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == frasil_events::kind::UNIT)
        .map(|event| event.id())
        .collect();
    let kept = shown(&bob, space, &doc, &ids).await;
    assert_eq!(kept.0, "one two three");
    assert_eq!(shown(&alice, space, &doc, &ids).await, kept);

    durable(&alice, space).await;
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    assert_eq!(
        shown(&alice, space, &doc, &ids).await,
        kept,
        "after forgetting"
    );
    // The checkpoint's own cut, which the replica keeps, keeps its verdict.
    let cut = alice
        .read(&space, |r| {
            r.event(c).and_then(frasil_peers::skeleton::named_twin)
        })
        .await
        .unwrap()
        .expect("a cut");
    assert_eq!(
        status(&alice, &space, &cut).await,
        status(&bob, &space, &cut).await,
        "the cut"
    );
    drop(alice);

    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    assert_eq!(shown(&alice, space, &doc, &ids).await, kept, "opened again");
    assert_eq!(
        status(&alice, &space, &cut).await,
        status(&bob, &space, &cut).await,
        "the cut, opened again"
    );
}

/// The document's text, every unit's verdict and what became of each
/// unit's content, at a device.
async fn content(
    device: &Engine,
    space: EventId,
    doc: &frasil_units::stream::Opening,
    ids: &[EventId],
) -> (String, Vec<(Option<Status>, String)>) {
    let text = text(&device.document(&space, &doc.stream()).await.unwrap());
    let mut out = Vec::new();
    for id in ids {
        let outcome = device
            .read(&space, |r| format!("{:?}", r.content_outcome(id)))
            .await
            .unwrap();
        out.push((status(device, &space, id).await, outcome));
    }
    (text, out)
}

#[tokio::test]
async fn a_device_that_forgot_shows_every_writers_content_as_one_that_kept_everything() {
    // Writers at every standing edit before the checkpoint, concurrently
    // with it and after it: Alice, the administrator; Carol, a writer;
    // Erin, a suggester, whose direct edits are refused as content; Tom,
    // through a team space the project grants; Bob, through his person, and
    // his phone, a second device of it; Gus, a guest; and Ray, whose edit
    // comes as he is lowered to reader.
    // Alice forgets the project's past; Kim, a reader, keeps everything.
    // Alice shows what Kim shows, before and after she opens again.
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let (carol, erin, tom, bob, kim) = (
        device().await,
        device().await,
        device().await,
        device().await,
        device().await,
    );
    let team = alice.create_space().await.unwrap();
    grant(&alice, &tom, team, Level::Write).await;
    // Kim reads the team too, as the project's paths through it need.
    grant(&alice, &kim, team, Level::Read).await;
    let project = alice.create_space().await.unwrap();
    grant(&alice, &kim, project, Level::Read).await;
    grant(&alice, &carol, project, Level::Write).await;
    grant(&alice, &erin, project, Level::Write).await;
    alice
        .set_suggester(project, MemberRef::device(erin.device_id()), true)
        .await
        .unwrap();
    alice
        .grant_space(project, team, Level::Write)
        .await
        .unwrap();
    let person = bob.make_person(&[9; 32]).await.unwrap().person;
    alice
        .receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    kim.receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    alice
        .grant_person(
            project,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    // Bob's phone, a person's second device, added to his person once Bob
    // holds the project: the add travels as a list copy.
    carry(&alice, &bob, project).await;
    let phone = device().await;
    let (keys, proof) = phone.list_keys(&person, &bob.device_id());
    bob.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(person, bob.list_events(&person).await, &[9; 32])
        .await
        .unwrap();
    carry(&bob, &alice, project).await;
    kim.receive_list(bob.list_events(&person).await)
        .await
        .unwrap();
    // Gus, a guest of a session (nothing of the space at rest at his
    // device).
    #[cfg(feature = "ext-guests")]
    let gus = {
        let gus = device().await;
        let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [5; 16]);
        preset.history = HistoryMode::WithHistory;
        preset.via = Via::Code;
        alice
            .grant_guest(project, gus.public_keys().clone(), &preset)
            .await
            .unwrap();
        gus
    };
    // Ray, a writer whose edit comes at the same time as his lowering to
    // reader: refused.
    let ray = device().await;
    grant(&alice, &ray, project, Level::Write).await;
    for (to, space) in [(&tom, team), (&kim, team)] {
        carry(&alice, to, space).await;
    }
    let doc = alice.new_document().unwrap();
    #[cfg(feature = "ext-guests")]
    let writers = [&carol, &erin, &tom, &bob, &phone, &gus];
    #[cfg(not(feature = "ext-guests"))]
    let writers = [&carol, &erin, &tom, &bob, &phone];
    let round = |word: &'static str| {
        let alice = &alice;
        let doc = &doc;
        async move {
            write(alice, project, doc, word).await;
            for writer in writers {
                carry(alice, writer, project).await;
                write(writer, project, doc, word).await;
                carry(writer, alice, project).await;
            }
        }
    };
    round(" before").await;
    // Ray edits while Alice lowers him to reader.
    carry(&alice, &ray, project).await;
    write(&ray, project, &doc, " ray").await;
    alice
        .set_level(project, MemberRef::device(ray.device_id()), Level::Read)
        .await
        .unwrap();
    carry(&ray, &alice, project).await;
    // Carol writes apart while Alice checkpoints: late.
    write(&carol, project, &doc, " apart").await;
    let c = alice.propose_checkpoint(project).await.unwrap();
    carry(&carol, &alice, project).await;
    round(" after").await;
    carry(&alice, &kim, team).await;
    carry(&alice, &kim, project).await;
    let ids: Vec<EventId> = alice
        .events(&project)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.kind() == frasil_events::kind::UNIT)
        .map(|event| event.id())
        .collect();
    let kept = content(&kim, project, &doc, &ids).await;
    assert!(kept.0.contains("before"), "{}", kept.0);
    assert!(
        kept.1
            .iter()
            .any(|(_, outcome)| outcome.contains("CapabilityRefused")),
        "Erin's direct edits are refused as content: {:?}",
        kept.1
    );
    assert!(
        kept.1
            .iter()
            .any(|(status, _)| status.is_some_and(|s| matches!(s, Status::Void { .. }))),
        "Carol's edit made apart is late"
    );
    assert_eq!(content(&alice, project, &doc, &ids).await, kept);

    durable(&alice, project).await;
    assert!(alice.forget_before_checkpoint(project).await.unwrap() > 0);
    assert_eq!(in_effect(&alice, &project).await, Some(c.0));
    assert_eq!(
        content(&alice, project, &doc, &ids).await,
        kept,
        "after forgetting"
    );
    drop(alice);
    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    let reopened = content(&alice, project, &doc, &ids).await;
    for (i, (a, b)) in reopened.1.iter().zip(kept.1.iter()).enumerate() {
        if a != b {
            eprintln!("DIFF {i} {:?}: reopened {a:?} kept {b:?}", ids[i]);
        }
    }
    assert_eq!(reopened, kept, "opened again");
}

#[tokio::test]
async fn a_release_made_late_by_a_checkpoint_is_signed_again_after_it() {
    // Carol releases a document while Alice, the only administrator,
    // checkpoints: the release is late, counts for nothing, and Carol's
    // upkeep signs it again after the checkpoint (roster.md, 3.15.7, "Work
    // concurrent with a checkpoint").
    let alice = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &carol, space, Level::Write).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "kept").await;
    carry(&alice, &carol, space).await;
    carol.release_stream(space, doc.stream()).await.unwrap();
    let c = alice.propose_checkpoint(space).await.unwrap();
    sync(&alice, &carol, space).await;
    assert_eq!(in_effect(&carol, &space).await, Some(c.0));
    let late = carol.checkpoint_status(&space).await.unwrap().late;
    assert!(!late.is_empty(), "the release is late");
    assert!(!carol.stream_released(&space, &doc.stream()).await.unwrap());
    carol.maintain_checkpoints(space).await.unwrap();
    sync(&alice, &carol, space).await;
    assert!(
        alice.stream_released(&space, &doc.stream()).await.unwrap(),
        "released after the checkpoint"
    );
    assert!(carol.stream_released(&space, &doc.stream()).await.unwrap());
}

#[tokio::test]
async fn an_administrator_granted_before_a_checkpoint_enrols_after_it() {
    // Bob is granted administer before Alice's checkpoint and enrols only
    // after it: the cut leaves his slot unenrolled, and his enrolment's
    // binding is sealed under the checkpoint's secret (peers.md, 2.5,
    // "After a checkpoint"). His twin is then valid at Alice, who kept
    // everything, and at Kim, who forgot the past before the checkpoint.
    let alice = device().await;
    let bob = device().await;
    let kim = device().await;
    let dave = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &kim, space, Level::Read).await;
    grant(&alice, &bob, space, Level::Administer).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    let c = alice.propose_checkpoint(space).await.unwrap();
    // Bob takes the space now, votes, and enrols after the checkpoint.
    carry(&alice, &bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    alice.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    carry(&alice, &kim, space).await;
    durable(&kim, space).await;
    assert!(kim.forget_before_checkpoint(space).await.unwrap() > 0);

    let grant = bob
        .grant_administrator(
            space,
            dave.public_keys().clone(),
            100,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    sync(&alice, &bob, space).await;
    carry(&alice, &kim, space).await;
    for at in [&alice, &kim] {
        let verdict = status(at, &space, &grant).await;
        assert!(verdict.is_some_and(|s| s.is_valid()), "{verdict:?}");
    }
}

/// Rows with metadata, open suggestions and history of a records stream,
/// as a device shows them.
#[cfg(feature = "adapter-records")]
async fn records_shown(device: &Engine, space: EventId, stream: frasil::StreamId) -> String {
    let device = frasil::Device::from_engine(device.clone(), frasil::Options::new().loopback())
        .expect("a device");
    let space = device
        .space(frasil::SpaceId::from_bytes(space.0))
        .await
        .unwrap();
    let records = space.records(stream).await.unwrap();
    format!(
        "{:?}\n{:?}\n{:?}",
        records.rows_with_metadata("t").await.unwrap(),
        records.suggestions().await.unwrap(),
        records.history().await.unwrap()
    )
}

#[cfg(feature = "adapter-records")]
#[tokio::test]
async fn a_device_that_forgot_shows_records_as_one_that_kept_everything() {
    // Carol suggests a row, Dan writes one and is then lowered to reader,
    // Erin writes one and is then made a suggester, all before Alice's
    // checkpoint. Alice forgets the past; Kim kept everything. Rows with
    // their metadata, open suggestions and history match, before and
    // after Alice opens again.
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[2; 32], registry.clone())
        .await
        .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let (kim, carol, dan, erin) = (
        device().await,
        device().await,
        device().await,
        device().await,
    );
    let space = alice.create_space().await.unwrap();
    grant(&alice, &kim, space, Level::Read).await;
    for writer in [&carol, &dan] {
        grant(&alice, writer, space, Level::Write).await;
    }
    // Erin writes through her person's list.
    let erins = erin.make_person(&[9; 32]).await.unwrap().person;
    alice
        .receive_list(erin.list_events(&erins).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            erins,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &erins).await.unwrap();
    erin.follow(space).await;
    // Roster labels, which history shows as the device's and the person's
    // names as they were at each edit (roster.md, 3.11), at the device
    // that kept everything and at the one that forgot alike: they change
    // after the edits, and the new names never show.
    let label = |member, name: &str| Change {
        label: Some(name.into()),
        ..Change::new(frasil_space::Op::Change, Some(member))
    };
    alice
        .sign_roster(
            space,
            vec![
                label(MemberRef::device(carol.device_id()), "Carol's phone"),
                label(MemberRef::device(dan.device_id()), "Dan's laptop"),
                label(MemberRef::person(erins), "Erin"),
            ],
        )
        .await
        .unwrap();
    alice
        .set_suggester(space, MemberRef::device(carol.device_id()), true)
        .await
        .unwrap();
    let alices =
        frasil::Device::from_engine(alice.clone(), frasil::Options::new().loopback()).unwrap();
    let records = alices
        .space(frasil::SpaceId::from_bytes(space.0))
        .await
        .unwrap()
        .create_records()
        .unwrap();
    let stream = records.id();
    records
        .write(|t| {
            t.insert("t", b"alice").set("t", b"alice", "v", "a");
        })
        .await
        .unwrap();
    for (writer, key, suggest) in [
        (&carol, b"carol", true),
        (&dan, b"dan__", false),
        (&erin, b"erin_", false),
    ] {
        carry(&alice, writer, space).await;
        let device =
            frasil::Device::from_engine(writer.clone(), frasil::Options::new().loopback()).unwrap();
        let theirs = device
            .space(frasil::SpaceId::from_bytes(space.0))
            .await
            .unwrap()
            .records(stream)
            .await
            .unwrap();
        theirs
            .write(|t| {
                if suggest {
                    t.suggest();
                }
                t.insert("t", key).set("t", key, "v", "b");
            })
            .await
            .unwrap();
        carry(writer, &alice, space).await;
    }
    alice
        .set_level(space, MemberRef::device(dan.device_id()), Level::Read)
        .await
        .unwrap();
    alice
        .set_suggester(space, MemberRef::person(erins), true)
        .await
        .unwrap();
    // Relabelled after their edits: history keeps the names of then.
    alice
        .sign_roster(
            space,
            vec![
                label(MemberRef::device(carol.device_id()), "Carol's tablet"),
                label(MemberRef::person(erins), "Erin K."),
            ],
        )
        .await
        .unwrap();
    let c = alice.propose_checkpoint(space).await.unwrap();
    carry(&alice, &kim, space).await;
    let kept = records_shown(&kim, space, stream).await;
    for shown in [
        "[100, 97, 110, 95, 95]: RowWithMetadata",
        "[101, 114, 105, 110, 95]: RowWithMetadata",
        "Suggestion { id",
        "device_name: Some(\"Carol's phone\")",
        "device_name: Some(\"Dan's laptop\")",
        "person_name: Some(\"Erin\")",
        "kind: Suggestion(Open)",
    ] {
        assert!(kept.contains(shown), "{shown} in {kept}");
    }
    assert!(
        !kept.contains("tablet") && !kept.contains("Erin K."),
        "{kept}"
    );
    assert_eq!(records_shown(&alice, space, stream).await, kept);
    durable(&alice, space).await;
    assert!(alice.forget_before_checkpoint(space).await.unwrap() > 0);
    assert_eq!(in_effect(&alice, &space).await, Some(c.0));
    assert_eq!(
        records_shown(&alice, space, stream).await,
        kept,
        "after forgetting"
    );
    drop(alices);
    drop(alice);
    let alice = Engine::open(platform, &sealed, &[2; 32], registry)
        .await
        .unwrap();
    assert_eq!(
        records_shown(&alice, space, stream).await,
        kept,
        "opened again"
    );
}

/// roster.md, 3.14, re-submission: Bob grants Dave while Alice removes
/// Bob, so Bob's grant is void and Dave's edit through it is `NotAWriter`,
/// voided by Alice's removal; granted again, Dave re-submits it, once. One
/// that nothing voids is never re-submitted: the library finds it has no
/// voiding events (frasil-space, the `roster/never-voided` vector).
#[tokio::test]
async fn a_not_a_writer_unit_is_sent_again_exactly_when_events_void_it() {
    let alice = device().await;
    let bob = device().await;
    let dave = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    carry(&alice, &bob, space).await;
    // Bob grants Dave while Alice removes Bob.
    grant(&bob, &dave, space, Level::Write).await;
    carry(&bob, &dave, space).await;
    write(&dave, space, &doc, "d").await;
    let refused = dave
        .events(&space)
        .await
        .into_iter()
        .filter_map(|signed| frasil_events::decode(&signed).ok())
        .filter(|event| event.author() == &dave.device_id())
        .map(|event| event.id())
        .next_back()
        .expect("Dave's unit");
    alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    carry(&dave, &alice, space).await;
    carry(&alice, &dave, space).await;
    let class = status(&alice, &space, &refused)
        .await
        .and_then(|s| s.class())
        .map(frasil_base::errors::Class::name);
    assert_eq!(class, Some("NotAWriter"));
    // Granted by Alice, Dave, who then judges it so too, sends it again,
    // once.
    grant(&alice, &dave, space, Level::Write).await;
    carry(&alice, &dave, space).await;
    let class = status(&dave, &space, &refused)
        .await
        .and_then(|s| s.class())
        .map(frasil_base::errors::Class::name);
    assert_eq!(class, Some("NotAWriter"));
    let again = dave.resubmit_refused_units(space).await.unwrap();
    assert_eq!(again.len(), 1);
    assert!(dave.resubmit_refused_units(space).await.unwrap().is_empty());
    carry(&dave, &alice, space).await;
    assert!(matches!(
        status(&alice, &space, &again[0]).await,
        Some(Status::Valid(_))
    ));
}
