//! Restricted spaces through the engine (ext-restricted-spaces.md), with
//! the events carried by hand: a restricted space under its parent, read
//! by the members it grants and by no other member of the parent; a device
//! outside the parent that its roster grants receives nothing; the
//! parent's removal mirrored; a document moved in, and a late write
//! re-applied.
#![cfg(all(feature = "adapter-loro", feature = "ext-restricted-spaces"))]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};

async fn device(key: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

/// Carries a space's events, then the objects they name.
async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
    for locator in to.missing_objects(&space).await {
        if let Some(stored) = from.stored_object(&space, &locator).await {
            to.receive_object(space, &locator, &stored).await.unwrap();
        }
    }
}

/// Carries every event of these spaces both ways between every two
/// devices, twice, so that what a device signs on arrival travels too.
async fn exchange(devices: &[&Engine], spaces: &[EventId]) {
    for _ in 0..2 {
        for from in devices {
            for to in devices {
                if from.device_id() == to.device_id() {
                    continue;
                }
                for space in spaces {
                    if to.spaces().await.contains(space) && from.spaces().await.contains(space) {
                        carry(from, to, *space).await;
                    }
                }
            }
        }
    }
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

async fn grant(by: &Engine, space: EventId, to: &Engine, level: Level) -> EventId {
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

/// Alice's parent space P with Bob and Carol, and her restricted space F
/// under it, which grants Bob alone.
async fn parent_and_restricted() -> (Engine, Engine, Engine, EventId, EventId) {
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let p = alice.create_space().await.unwrap();
    grant(&alice, p, &bob, Level::Write).await;
    grant(&alice, p, &carol, Level::Write).await;
    for other in [&bob, &carol] {
        other.follow(p).await;
        carry(&alice, other, p).await;
    }
    let f = alice.create_restricted(p).await.unwrap();
    grant(&alice, f, &bob, Level::Write).await;
    bob.follow(f).await;
    carry(&alice, &bob, f).await;
    (alice, bob, carol, p, f)
}

#[tokio::test]
async fn a_restricted_space_reaches_only_its_members_inside_the_parent() {
    let (alice, bob, carol, p, f) = parent_and_restricted().await;
    assert_eq!(
        bob.read(&f, |r| r.restricted_parent()).await.unwrap(),
        Some(p)
    );
    assert_eq!(
        bob.read(&f, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    // Restricted spaces do not nest.
    assert!(alice.create_restricted(f).await.is_err());

    // Alice writes in F; Bob reads it and writes back.
    let note = alice.new_document().unwrap();
    alice
        .edit_document(f, &note, |doc| {
            doc.get_text("body").insert(0, "Secret").unwrap();
        })
        .await
        .unwrap();
    carry(&alice, &bob, f).await;
    assert_eq!(
        text(&bob.document(&f, &note.stream()).await.unwrap()),
        "Secret"
    );
    bob.edit_document(f, &note, |doc| {
        doc.get_text("body").insert(6, " plan").unwrap();
    })
    .await
    .unwrap();
    carry(&bob, &alice, f).await;
    assert_eq!(
        text(&alice.document(&f, &note.stream()).await.unwrap()),
        "Secret plan"
    );

    // Carol, a member of P that F does not grant, holds all of F and
    // reads none of it.
    carol.follow(f).await;
    carry(&alice, &carol, f).await;
    assert_eq!(
        carol.read(&f, |r| r.current().cloned()).await.unwrap(),
        None
    );
    assert!(carol.document(&f, &note.stream()).await.is_err());
}

#[tokio::test]
async fn a_device_outside_the_parent_receives_nothing() {
    let (alice, _bob, _carol, _p, f) = parent_and_restricted().await;
    let dave = device(4).await;
    // Alice's own client admits no newcomer outside P.
    assert!(!alice.reaches_parent_of(&f, &dave.device_id()).await);
    // F's roster may still grant Dave: he is not in F's effective
    // membership, and no wrap reaches him.
    grant(&alice, f, &dave, Level::Write).await;
    assert_eq!(
        alice
            .read(&f, |r| r.level_of(&dave.device_id()))
            .await
            .unwrap(),
        None
    );
    let note = alice.new_document().unwrap();
    alice
        .edit_document(f, &note, |doc| {
            doc.get_text("body").insert(0, "Not for Dave").unwrap();
        })
        .await
        .unwrap();
    dave.follow(f).await;
    carry(&alice, &dave, f).await;
    assert_eq!(dave.read(&f, |r| r.current().cloned()).await.unwrap(), None);
    assert!(dave.document(&f, &note.stream()).await.is_err());
}

#[tokio::test]
async fn the_parents_removal_is_mirrored() {
    let (alice, bob, _carol, p, f) = parent_and_restricted().await;
    alice
        .remove(p, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    // Bob no longer reaches F at once, through its parent.
    assert_eq!(
        alice
            .read(&f, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        None
    );
    // F's only administrator is the first candidate: no delay.
    let mirror = alice.mirror_parent(f).await.unwrap();
    assert!(mirror.is_some());
    let named = alice
        .read(&f, |r| {
            r.roster()
                .state(&MemberRef::device(bob.device_id()))
                .is_some()
        })
        .await
        .unwrap();
    assert!(!named, "the mirror removes Bob from F's roster");
    // Landed: it is not made twice.
    assert_eq!(alice.mirror_parent(f).await.unwrap(), None);
}

#[tokio::test]
async fn a_document_moves_in_and_a_late_write_is_reapplied() {
    let (alice, bob, _carol, p, f) = parent_and_restricted().await;
    let note = alice.new_document().unwrap();
    alice
        .edit_document(p, &note, |doc| {
            doc.get_text("body").insert(0, "Draft").unwrap();
        })
        .await
        .unwrap();
    carry(&alice, &bob, p).await;
    // Bob edits P's copy before he learns of the move: a late write.
    bob.edit_document(p, &note, |doc| {
        doc.get_text("body").insert(5, " two").unwrap();
    })
    .await
    .unwrap();
    let moved = alice.move_stream(p, note.stream(), f).await.unwrap();
    assert_eq!(
        text(&alice.document(&f, &moved.stream()).await.unwrap()),
        "Draft"
    );
    exchange(&[&alice, &bob], &[p, f]).await;
    let record = bob
        .read(&p, |r| r.moved(&note.stream()).cloned())
        .await
        .unwrap()
        .expect("Bob sees the move");
    assert_eq!(record.to_space, f);
    assert_eq!(record.to_stream, moved.stream());
    let late = bob
        .read(&p, |r| r.late_writes(&note.stream()))
        .await
        .unwrap();
    assert_eq!(late.len(), 1, "Bob's edit is a late write");
    // No other writer re-applies it, however long it waits.
    assert!(alice.reapply_late_writes(p).await.unwrap().is_empty());
    // Its author re-applies it at once in the new document.
    let written = bob.reapply_late_writes(p).await.unwrap();
    assert_eq!(written.len(), 1);
    // A re-applied late write is not re-applied again.
    assert!(bob.reapply_late_writes(p).await.unwrap().is_empty());
    exchange(&[&alice, &bob], &[p, f]).await;
    assert!(alice.reapply_late_writes(p).await.unwrap().is_empty());
    for device in [&alice, &bob] {
        assert_eq!(
            text(&device.document(&f, &moved.stream()).await.unwrap()),
            "Draft two"
        );
    }
}

#[tokio::test]
async fn a_space_it_grants_reaches_only_its_members_inside_the_parent() {
    let alice = device(1).await;
    let carol = device(3).await;
    let dave = device(4).await;
    // P holds Alice and Carol; the team T holds Carol and Dave too.
    let p = alice.create_space().await.unwrap();
    grant(&alice, p, &carol, Level::Write).await;
    let team = alice.create_space().await.unwrap();
    grant(&alice, team, &carol, Level::Write).await;
    grant(&alice, team, &dave, Level::Write).await;
    carol.follow(p).await;
    carry(&alice, &carol, p).await;
    for other in [&carol, &dave] {
        other.follow(team).await;
        carry(&alice, other, team).await;
    }
    // F, under P, grants the team.
    let f = alice.create_restricted(p).await.unwrap();
    alice.grant_space(f, team, Level::Write).await.unwrap();
    let note = alice.new_document().unwrap();
    alice
        .edit_document(f, &note, |doc| {
            doc.get_text("body").insert(0, "For the team").unwrap();
        })
        .await
        .unwrap();
    for other in [&carol, &dave] {
        other.follow(f).await;
        carry(&alice, other, f).await;
    }
    // Carol reaches F through the team and inside P; Dave, outside P,
    // takes F's own secrets from the space wrap and opens nothing.
    assert_eq!(
        text(&carol.document(&f, &note.stream()).await.unwrap()),
        "For the team"
    );
    assert!(dave.document(&f, &note.stream()).await.is_err());
}

#[cfg(feature = "ext-guests")]
#[tokio::test]
async fn a_carve_out_gives_a_guest_one_document_and_mirrors_administrators() {
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let dave = device(4).await;
    let erin = device(5).await;
    let frank = device(6).await;
    let p = alice.create_space().await.unwrap();
    grant(&alice, p, &bob, Level::Administer).await;
    grant(&alice, p, &carol, Level::Write).await;
    grant(&alice, p, &frank, Level::Write).await;
    for other in [&bob, &carol, &frank] {
        other.follow(p).await;
    }
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(p, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    exchange(&[&alice, &bob, &carol, &frank], &[p]).await;

    // Carol, a writer of P, carves the document out.
    let made = carol.create_carve_out(p, doc.stream()).await.unwrap();
    let n = made.space;
    for other in [&alice, &bob] {
        other.follow(n).await;
    }
    exchange(&[&alice, &bob, &carol], &[p, n]).await;
    for (who, level) in [
        (&alice, Level::Administer),
        (&bob, Level::Administer),
        (&carol, Level::Administer),
    ] {
        assert_eq!(
            alice
                .read(&n, |r| r.level_of(&who.device_id()))
                .await
                .unwrap(),
            Some(level)
        );
    }
    // The document moved: its new stream in N holds its state.
    assert_eq!(
        text(&alice.document(&n, &made.opening.stream()).await.unwrap()),
        "hello"
    );

    // A guest, from now on, reads the document in N.
    let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [7; 16]);
    preset.via = Via::Code;
    let admitting = carol
        .grant_guest(n, dave.public_keys().clone(), &preset)
        .await
        .unwrap();
    let snapshot = carol.newcomer_snapshot(&n, admitting).await.unwrap();
    dave.adopt_snapshot(n, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    dave.ingest(n, carol.events(&n).await).await.unwrap();
    assert_eq!(
        text(&dave.document(&n, &made.opening.stream()).await.unwrap()),
        "hello"
    );
    // Frank reaches N only through its grant of P. Dave's snapshot carried
    // P's roster, so he checks Frank's write.
    assert!(dave.spaces().await.contains(&p));
    frank.follow(n).await;
    carry(&carol, &frank, n).await;
    frank
        .edit_document(n, &made.opening, |d| {
            d.get_text("body").insert(5, ", Dave").unwrap();
        })
        .await
        .unwrap();
    carry(&frank, &dave, n).await;
    assert_eq!(
        text(&dave.document(&n, &made.opening.stream()).await.unwrap()),
        "hello, Dave"
    );

    // Carol does not administer P: she steps down in N.
    assert!(carol.step_down_in_carve_out(n).await.unwrap().is_some());
    exchange(&[&alice, &bob, &carol], &[p, n]).await;
    assert_eq!(
        alice
            .read(&n, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );

    // P's administrators change; N's administrators mirror them. Alice
    // is the only candidate each time, so each mirror is due at once.
    alice
        .remove(p, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    grant(&alice, p, &erin, Level::Administer).await;
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    let (erin_level, bob_in) = alice
        .read(&n, |r| {
            (
                r.level_of(&erin.device_id()),
                r.roster()
                    .state(&MemberRef::device(bob.device_id()))
                    .is_some(),
            )
        })
        .await
        .unwrap();
    assert_eq!(erin_level, Some(Level::Administer));
    assert!(!bob_in);
    // Each mirror landed: nothing more is due.
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
}

/// A device on a clock the test moves, so that a candidate ranked after
/// another is due.
async fn device_on(
    key: u8,
    clock: &std::sync::Arc<frasil::advanced::platform::ManualClock>,
) -> Engine {
    Engine::create(
        Platform::memory().with_clock(clock.clone()),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

/// Alice's P, which Bob administers and Carol writes in, with one
/// document, and the carve-out of that document by `creator` (Bob or
/// Carol), which Alice and Bob hold.
async fn carved_by(
    creator: u8,
) -> (
    std::sync::Arc<frasil::advanced::platform::ManualClock>,
    Engine,
    Engine,
    Engine,
    EventId,
    EventId,
) {
    let clock = std::sync::Arc::new(frasil::advanced::platform::ManualClock::new(
        1_000,
        Some(1_800_000_000),
    ));
    let alice = device_on(1, &clock).await;
    let bob = device_on(2, &clock).await;
    let carol = device_on(3, &clock).await;
    let p = alice.create_space().await.unwrap();
    grant(&alice, p, &bob, Level::Administer).await;
    grant(&alice, p, &carol, Level::Write).await;
    for other in [&bob, &carol] {
        other.follow(p).await;
    }
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(p, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    exchange(&[&alice, &bob, &carol], &[p]).await;
    let maker = if creator == 2 { &bob } else { &carol };
    let n = maker.create_carve_out(p, doc.stream()).await.unwrap().space;
    for other in [&alice, &bob, &carol] {
        other.follow(n).await;
    }
    exchange(&[&alice, &bob, &carol], &[p, n]).await;
    (clock, alice, bob, carol, p, n)
}

/// Whether N's roster names a device directly, and the device's level in N.
async fn in_n(by: &Engine, n: EventId, who: &Engine) -> (bool, Option<Level>) {
    by.read(&n, |r| {
        (
            r.roster()
                .state(&MemberRef::device(who.device_id()))
                .is_some(),
            r.level_of(&who.device_id()),
        )
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn a_creator_that_administered_the_parent_and_is_removed_is_mirrored_out() {
    let (clock, alice, bob, _carol, p, n) = carved_by(2).await;
    assert_eq!(in_n(&alice, n, &bob).await, (true, Some(Level::Administer)));
    // Bob administers P: he keeps `administer` in N, and nothing is due.
    assert_eq!(bob.step_down_in_carve_out(n).await.unwrap(), None);
    clock.advance(3_600);
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);

    alice
        .remove(p, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    clock.advance(3_600);
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    assert_eq!(in_n(&alice, n, &bob).await, (false, None));
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
}

#[tokio::test]
async fn a_creator_that_administered_the_parent_and_is_lowered_is_mirrored_to_its_path() {
    let (clock, alice, bob, _carol, p, n) = carved_by(2).await;
    alice
        .set_level(p, MemberRef::device(bob.device_id()), Level::Write)
        .await
        .unwrap();
    // Alice and Bob are both candidates: past every delay, Alice's mirror
    // is due whatever her rank.
    clock.advance(3_600);
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    // Bob's direct grant is gone; he writes in N through its grant of P.
    assert_eq!(in_n(&alice, n, &bob).await, (false, Some(Level::Write)));
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
}

#[tokio::test]
async fn a_creator_that_never_administered_the_parent_steps_down_then_is_mirrored_out() {
    let (clock, alice, bob, carol, p, n) = carved_by(3).await;
    assert_eq!(
        in_n(&alice, n, &carol).await,
        (true, Some(Level::Administer))
    );
    // Before she steps down, no mirror lowers her: that is hers to do.
    clock.advance(3_600);
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
    assert!(carol.step_down_in_carve_out(n).await.unwrap().is_some());
    exchange(&[&alice, &bob, &carol], &[p, n]).await;
    assert_eq!(in_n(&alice, n, &carol).await, (true, Some(Level::Write)));
    // A writer of P at `write` in N: nothing is due.
    clock.advance(3_600);
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);

    // Removed from P, she loses her direct `write` in N too.
    alice
        .remove(p, MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    clock.advance(3_600);
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    assert_eq!(in_n(&alice, n, &carol).await, (false, None));
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
}

#[cfg(feature = "ext-guests")]
#[tokio::test]
async fn a_carve_outs_guest_is_never_mirrored() {
    let (clock, alice, bob, carol, p, n) = carved_by(3).await;
    let dave = device(4).await;
    let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [7; 16]);
    preset.via = Via::Code;
    carol
        .grant_guest(n, dave.public_keys().clone(), &preset)
        .await
        .unwrap();
    assert!(carol.step_down_in_carve_out(n).await.unwrap().is_some());
    exchange(&[&alice, &bob, &carol], &[p, n]).await;
    assert_eq!(in_n(&alice, n, &dave).await, (true, Some(Level::Write)));
    // P changes, and N mirrors Bob's removal; the guest, whom P never
    // granted, stays.
    alice
        .remove(p, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    clock.advance(3_600);
    assert!(alice.mirror_administrators(n).await.unwrap().is_some());
    assert_eq!(alice.mirror_administrators(n).await.unwrap(), None);
    assert_eq!(in_n(&alice, n, &dave).await, (true, Some(Level::Write)));
    assert_eq!(in_n(&alice, n, &bob).await, (false, None));
}
