//! A checkpointed space judged refresh by refresh gives the verdicts a
//! judgement from scratch gives: a history with two checkpoints in a row
//! (no peer: the pseudonyms' votes travel between the devices), grants,
//! administrators' edits and an edit made apart, late, is delivered to
//! fresh readers event by event in seeded random orders, in its own order
//! and in reverse, its record objects at random points. Every refresh is
//! checked against a judgement from scratch ([`Replica::check_from_scratch`]:
//! verdicts, chain, whom each pending checkpoint waits for, roster and the
//! key world), and each reader ends where a reader given everything at once
//! does. In order, the units after the checkpoint in effect resume its world
//! instead of judging the view again.

use crate::advanced::{AdapterRegistry, Engine, Platform};
use crate::checkpoints::CheckpointPolicy;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::stream::Opening;

async fn device() -> Engine {
    let (device, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    device.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    device
}

async fn grant(by: &Engine, to: &Engine, space: EventId, level: Level) {
    by.grant_device_at(
        space,
        to.public_keys().clone(),
        level,
        (level == Level::Administer).then_some(255),
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .expect("a grant");
}

/// Hands `to` every event `from` holds, and the objects `to` lacks.
async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.follow(space).await;
    to.ingest(space, from.events(&space).await)
        .await
        .expect("ingested");
    objects(from, to, space).await;
}

async fn objects(from: &Engine, to: &Engine, space: EventId) {
    for locator in to.missing_objects(&space).await {
        if let Some(stored) = from.stored_object(&space, &locator).await {
            to.receive_object(space, &locator, &stored)
                .await
                .expect("an object");
        }
    }
}

async fn sync(a: &Engine, b: &Engine, space: EventId) {
    carry(a, b, space).await;
    carry(b, a, space).await;
}

async fn write(device: &Engine, space: EventId, doc: &Opening, words: &str) {
    device
        .edit_document(space, doc, |d| {
            let body = d.get_text("body");
            body.insert(body.len_unicode(), words).unwrap();
        })
        .await
        .expect("an edit");
}

/// What a reader ends with: every event's verdict, the checkpoint in
/// effect and its epoch, each pending checkpoint with whom it waits for,
/// the roster's members, and the key world's current states.
async fn reading(device: &Engine, space: EventId, doc: &Opening, ids: &[EventId]) -> String {
    let status = device.checkpoint_status(&space).await.expect("a space");
    let text = device
        .document(&space, &doc.stream())
        .await
        .map(|d| d.get_text("body").to_string())
        .unwrap_or_default();
    let replica = device
        .read(&space, |r| {
            let statuses: Vec<_> = ids.iter().map(|id| r.status(id).copied()).collect();
            let members: Vec<_> = r
                .roster()
                .members_in()
                .map(|(m, s)| (*m, s.level))
                .collect();
            format!(
                "{statuses:?}\n{members:?}\n{:?}\n{:?}",
                r.current, r.grant_current
            )
        })
        .await
        .expect("a space");
    let pending: Vec<_> = status
        .pending
        .iter()
        .map(|p| (p.id, p.waiting_for.clone()))
        .collect();
    format!(
        "{text}\n{replica}\n{:?} {} {pending:?}",
        status.in_effect, status.epoch
    )
}

/// A seeded order: xorshift over the indices.
fn shuffled(len: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    for i in (1..len).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    order
}

#[test]
fn a_checkpointed_space_judged_event_by_event_matches_one_judged_from_scratch() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

/// The devices of the scene, and what they write in.
struct Scene {
    alice: Engine,
    bob: Engine,
    carol: Engine,
    readers: Vec<Engine>,
    space: EventId,
    doc: Opening,
}

// The scene runs in steps, each an async function of its own: an
// unoptimised build gives every await of a function its own stack slot,
// and one function awaiting the whole scene takes more than a test
// thread's stack.
async fn run() {
    let mut scene = Box::pin(members()).await;
    Box::pin(checkpoints(&scene)).await;
    let (events, ids, expected) = Box::pin(judged_at_once(&mut scene)).await;
    Box::pin(forgetting(&mut scene, &ids, &expected)).await;
    Box::pin(in_orders(&scene, &events, &ids, &expected)).await;
    assert!(
        super::WORLD_RESUMED.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "units in order resume the world of the checkpoint in effect"
    );
}

async fn members() -> Scene {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    grant(&alice, &bob, space, Level::Administer).await;
    let mut readers = Vec::new();
    for _ in 0..8 {
        let reader = device().await;
        grant(&alice, &reader, space, Level::Read).await;
        readers.push(reader);
    }
    // Carol writes, granted before the checkpoints, before and after them;
    // Erin, a suggester, edits directly (refused as content); Ray edits as
    // he is lowered to reader (refused).
    let carol = device().await;
    grant(&alice, &carol, space, Level::Write).await;
    let erin = device().await;
    grant(&alice, &erin, space, Level::Write).await;
    alice
        .set_suggester(
            space,
            frasil_space::MemberRef::device(erin.device_id()),
            true,
        )
        .await
        .unwrap();
    let ray = device().await;
    grant(&alice, &ray, space, Level::Write).await;
    // Pat writes from her laptop and her phone through her person's list,
    // the phone added once the laptop holds the space; Gus is a guest.
    let laptop = device().await;
    let pat = laptop.make_person(&[9; 32]).await.unwrap().person;
    alice
        .receive_list(laptop.list_events(&pat).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            pat,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &pat).await.unwrap();
    carry(&alice, &laptop, space).await;
    let phone = device().await;
    let (keys, proof) = phone.list_keys(&pat, &laptop.device_id());
    laptop.add_device(keys, proof).await.unwrap();
    phone
        .adopt_person(pat, laptop.list_events(&pat).await, &[9; 32])
        .await
        .unwrap();
    carry(&laptop, &alice, space).await;
    let mut writers = vec![
        (carol.clone(), "w"),
        (erin, "s"),
        (laptop, "l"),
        (phone, "p"),
    ];
    #[cfg(feature = "ext-guests")]
    {
        let gus = device().await;
        let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [5; 16]);
        preset.history = HistoryMode::WithHistory;
        preset.via = Via::Code;
        alice
            .grant_guest(space, gus.public_keys().clone(), &preset)
            .await
            .unwrap();
        writers.push((gus, "g"));
    }
    writers.push((ray.clone(), "r"));
    let doc = alice.new_document().unwrap();
    write(&alice, space, &doc, "a").await;
    for (writer, word) in &writers {
        carry(&alice, writer, space).await;
        write(writer, space, &doc, word).await;
    }
    alice
        .set_level(
            space,
            frasil_space::MemberRef::device(ray.device_id()),
            Level::Read,
        )
        .await
        .unwrap();
    for (writer, _) in &writers {
        carry(writer, &alice, space).await;
    }
    sync(&alice, &bob, space).await;
    Scene {
        alice,
        bob,
        carol,
        readers,
        space,
        doc,
    }
}

async fn checkpoints(scene: &Scene) {
    let (alice, bob, carol, space, doc) = (
        &scene.alice,
        &scene.bob,
        &scene.carol,
        scene.space,
        &scene.doc,
    );
    // Bob writes apart while Alice checkpoints: his edit is late. The
    // checkpoint takes effect once Bob votes.
    write(bob, space, doc, "b").await;
    alice.propose_checkpoint(space).await.unwrap();
    sync(alice, bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(alice, bob, space).await;
    for round in 0..4 {
        write(alice, space, doc, "c").await;
        if round == 1 {
            let other = device().await;
            grant(alice, &other, space, Level::Write).await;
        }
    }
    sync(alice, bob, space).await;
    // A second checkpoint, in the first one's world, once Alice's
    // pseudonym voted for the first one's cut; it takes effect once Bob
    // votes.
    alice.acknowledge_checkpoint(space).await.unwrap();
    alice.propose_checkpoint(space).await.unwrap();
    sync(alice, bob, space).await;
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(alice, bob, space).await;
    for _ in 0..5 {
        write(alice, space, doc, "d").await;
        write(bob, space, doc, "e").await;
        sync(alice, bob, space).await;
    }
    carry(alice, carol, space).await;
    write(carol, space, doc, "x").await;
    carry(carol, alice, space).await;
}

/// The events Alice holds, and what a reader given them at once reads.
async fn judged_at_once(scene: &mut Scene) -> (Vec<Vec<u8>>, Vec<EventId>, String) {
    let (alice, space, doc) = (&scene.alice, scene.space, &scene.doc);
    let events = alice.events(&space).await;
    let ids: Vec<EventId> = events
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .map(|event| event.id())
        .collect();
    let at_once = scene.readers.pop().unwrap();
    carry(alice, &at_once, space).await;
    let expected = reading(&at_once, space, doc, &ids).await;
    let status = at_once.checkpoint_status(&space).await.unwrap();
    assert!(status.in_effect.is_some(), "a checkpoint is in effect");
    assert!(expected.contains("Late"), "Bob's edit made apart is late");
    assert_eq!(status.epoch, 2, "both checkpoints took effect");
    let text = expected.lines().next().unwrap_or_default();
    assert!(text.starts_with('a') && text.contains('w'), "{expected}");
    // Pat's devices write through her list, Gus as a guest.
    assert!(text.contains('l') && text.contains('p'), "{expected}");
    #[cfg(feature = "ext-guests")]
    assert!(text.contains('g'), "{expected}");
    (events, ids, expected)
}

async fn forgetting(scene: &mut Scene, ids: &[EventId], expected: &str) {
    let (alice, space, doc) = (&scene.alice, scene.space, &scene.doc);
    // A reader that forgets the past shows what one that kept it shows.
    let forgetting = scene.readers.pop().unwrap();
    carry(alice, &forgetting, space).await;
    assert_eq!(reading(&forgetting, space, doc, ids).await, expected);
    assert!(forgetting.forget_before_checkpoint(space).await.unwrap() > 0);
    let forgot = reading(&forgetting, space, doc, ids).await;
    assert_eq!(
        forgot.lines().next(),
        expected.lines().next(),
        "the text, after forgetting"
    );
}

/// Readers given the events one by one, each in an order of its own.
async fn in_orders(scene: &Scene, events: &[Vec<u8>], ids: &[EventId], expected: &str) {
    let (alice, space, doc, readers) = (&scene.alice, scene.space, &scene.doc, &scene.readers);
    let orders: Vec<Vec<usize>> = [
        (0..events.len()).collect(),
        (0..events.len()).rev().collect(),
    ]
    .into_iter()
    .chain((1..=readers.len() as u64 - 2).map(|seed| shuffled(events.len(), seed)))
    .collect();
    for (reader, order) in readers.iter().zip(orders) {
        reader.follow(space).await;
        for (step, index) in order.iter().enumerate() {
            reader
                .ingest(space, vec![events[*index].clone()])
                .await
                .expect("ingested");
            // The record objects at points of the order's own.
            if (step + *index) % 5 == 0 {
                objects(alice, reader, space).await;
            }
        }
        objects(alice, reader, space).await;
        reader.ingest(space, Vec::new()).await.expect("ingested");
        assert_eq!(
            reading(reader, space, doc, ids).await,
            expected,
            "order {order:?}"
        );
    }
}
