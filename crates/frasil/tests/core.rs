//! The local core: devices that make spaces, admit, remove, heal and write
//! Loro units, with events carried between them by hand.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::{AdapterRegistry, ContentOutcome, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Status, Via};
use loro::LoroDoc;

async fn device() -> Engine {
    let (device, _) = Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    device
}

/// Hands every event `from` holds of a space to `to`.
async fn carry(from: &Engine, to: &Engine, space: EventId) {
    let events = from.events(&space).await;
    to.ingest(space, events).await.expect("ingested");
}

fn text(doc: &LoroDoc) -> String {
    doc.get_text("body").to_string()
}

#[tokio::test]
async fn a_founder_makes_a_space_and_administers_it() {
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let (unresolved, level, genesis) = alice
        .read(&space, |r| {
            (
                r.unresolved(),
                r.level_of(&alice.device_id()),
                r.status(&space).copied(),
            )
        })
        .await
        .unwrap();
    assert_eq!(unresolved, None);
    assert_eq!(level, Some(Level::Administer));
    assert!(matches!(genesis, Some(Status::Valid(_))));
    // The genesis and the root wait in the outbox until acknowledged.
    assert_eq!(alice.outbox(&space).await.len(), 2);
}

#[tokio::test]
async fn a_newcomer_with_history_reads_and_writes() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    let grant = alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    assert!(matches!(
        alice
            .read(&space, |r| r.status(&grant).copied())
            .await
            .unwrap(),
        Some(Status::Valid(_))
    ));

    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    let level = bob
        .read(&space, |r| r.level_of(&bob.device_id()))
        .await
        .unwrap();
    assert_eq!(level, Some(Level::Write));
    let seen = bob.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "hello");

    let unit = bob
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(5, ", world").unwrap();
        })
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    assert_eq!(
        alice
            .read(&space, |r| r.content_outcome(&unit))
            .await
            .unwrap(),
        Some(ContentOutcome::Applied)
    );
    let seen = alice.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "hello, world");
}

#[tokio::test]
async fn a_removed_writer_reads_nothing_sealed_after_its_removal() {
    let alice = device().await;
    let bob = device().await;
    let carol = device().await;
    let space = alice.create_space().await.unwrap();
    for newcomer in [&bob, &carol] {
        alice
            .grant_device(
                space,
                newcomer.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    for newcomer in [&bob, &carol] {
        newcomer.follow(space).await;
        carry(&alice, newcomer, space).await;
    }
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before").unwrap();
        })
        .await
        .unwrap();
    // Bob writes concurrently with his removal, not having seen it.
    let concurrent = bob
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "late ").unwrap();
        })
        .await
        .unwrap();
    let removal = alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(6, " and after").unwrap();
        })
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    carry(&alice, &carol, space).await;
    carry(&alice, &bob, space).await;

    for reader in [&alice, &carol] {
        let status = reader
            .read(&space, |r| r.status(&concurrent).copied())
            .await
            .unwrap();
        match status {
            Some(Status::Void { class, by }) => {
                assert_eq!(frasil_base::errors::Class::name(class), "RefusedByRemoval");
                assert_eq!(by, Some(removal));
            }
            other => panic!("the concurrent unit is refused: {other:?}"),
        }
        let seen = reader.document(&space, &doc.stream()).await.unwrap();
        assert_eq!(text(&seen), "before and after");
    }
    // Bob holds no key of the state after his removal.
    let (current, holds) = bob
        .read(&space, |r| {
            let current = r.current().cloned();
            let holds = r.secrets_held(&removal);
            (current, holds)
        })
        .await
        .unwrap();
    assert!(current.is_some());
    assert!(!holds, "the removed device takes no key of the removal");
    // The removal wrap hands it the removal's body key alone: it opens
    // its removal and resolves a roster without itself (roster.md, "Space
    // events a replica cannot open").
    let (held, level) = bob
        .read(&space, |r| {
            (
                r.status(&removal).and_then(|s| s.class()),
                r.level_of(&bob.device_id()),
            )
        })
        .await
        .unwrap();
    assert_eq!(held.map(frasil_base::errors::Class::name), None);
    assert_eq!(level, None);
    // What Alice wrote after the removal stays unreadable to it.
    if let Ok(seen) = bob.document(&space, &doc.stream()).await {
        assert!(!text(&seen).contains("and after"));
    }
}

#[tokio::test]
async fn a_heal_rotates_for_every_member() {
    let alice = device().await;
    let bob = device().await;
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
    bob.follow(space).await;
    carry(&alice, &bob, space).await;
    let heal = bob.heal(space).await.unwrap();
    carry(&bob, &alice, space).await;
    for device in [&alice, &bob] {
        let (status, current, holds) = device
            .read(&space, |r| {
                (
                    r.status(&heal).copied(),
                    r.current().cloned(),
                    r.secrets_held(&heal),
                )
            })
            .await
            .unwrap();
        assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
        assert_eq!(current.map(|c| c.ids().to_vec()), Some(vec![heal]));
        assert!(holds);
    }
}

#[tokio::test]
async fn a_device_reopens_from_its_store() {
    let platform = Platform::memory();
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(platform.clone(), &[9; 32], registry.clone())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "kept").unwrap();
        })
        .await
        .unwrap();
    drop(alice);
    let again = Engine::open(platform, &sealed, &[9; 32], registry)
        .await
        .unwrap();
    assert_eq!(
        again.continuity().await,
        frasil::advanced::Continuity::Current
    );
    let seen = again.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "kept");
    // The next unit continues the chain from the head's tip.
    again
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(4, "!").unwrap();
        })
        .await
        .unwrap();
    let seen = again.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "kept!");
}

/// Runs sync sessions between two devices until neither has anything to
/// send, every message encoded and read again as a connection would carry
/// it.
async fn converge(a: &Engine, b: &Engine, space: EventId) {
    use frasil::advanced::Acknowledger;
    use frasil::advanced::sync::SyncSession;
    let (mut at_a, mut at_b) = (SyncSession::new(space), SyncSession::new(space));
    let mut to_b = a.sync_start(&mut at_a).await.unwrap();
    let mut to_a = b.sync_start(&mut at_b).await.unwrap();
    for _ in 0..32 {
        if to_a.is_empty() && to_b.is_empty() {
            return;
        }
        let mut next_to_a = Vec::new();
        for message in std::mem::take(&mut to_b) {
            let message = frasil::advanced::intake::read_sync(&message.encode())
                .unwrap()
                .unwrap();
            next_to_a.extend(
                b.sync_receive(&mut at_b, Acknowledger::Member(a.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
        let mut next_to_b = Vec::new();
        for message in std::mem::take(&mut to_a) {
            let message = frasil::advanced::intake::read_sync(&message.encode())
                .unwrap()
                .unwrap();
            next_to_b.extend(
                a.sync_receive(&mut at_a, Acknowledger::Member(b.device_id().0), message)
                    .await
                    .unwrap(),
            );
        }
        to_a = next_to_a;
        to_b = next_to_b;
    }
    panic!("the sessions did not settle");
}

#[tokio::test]
async fn sync_sessions_converge_and_make_events_durable() {
    let alice = device().await;
    let bob = device().await;
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
    bob.follow(space).await;
    converge(&alice, &bob, space).await;
    let doc = bob.new_document().unwrap();
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "synced").unwrap();
    })
    .await
    .unwrap();
    converge(&alice, &bob, space).await;
    let seen = alice.document(&space, &doc.stream()).await.unwrap();
    assert_eq!(text(&seen), "synced");
    // With no always-on peer, a member's acknowledgement makes an event
    // durable: both outboxes are empty.
    assert!(alice.outbox(&space).await.is_empty());
    assert!(bob.outbox(&space).await.is_empty());
    assert_eq!(
        alice.read(&space, |r| r.heads()).await.unwrap(),
        bob.read(&space, |r| r.heads()).await.unwrap()
    );
}

/// A release whose ML-DSA-65 half does not verify is never applied
/// (events.md, 3.3 The ML-DSA-65 half): a replica that receives it holds
/// the stream unreleased. Its Ed25519 half verifies, as a holder of the
/// writer's Ed25519 key alone could make it.
#[tokio::test]
async fn a_release_whose_mldsa_half_fails_releases_nothing() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
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
    let before = alice.events(&space).await;
    alice.release_stream(space, doc.stream()).await.unwrap();
    assert!(alice.stream_released(&space, &doc.stream()).await.unwrap());

    // The release, its ML-DSA-65 half altered: the signature's last byte.
    let mut events = alice.events(&space).await;
    let mut altered = 0;
    for signed in &mut events {
        let event = frasil_events::decode(signed).unwrap();
        if before.contains(signed) || event.kind() != frasil_events::kind::STORAGE {
            continue;
        }
        *signed.last_mut().unwrap() ^= 1;
        let copy = frasil_events::decode(signed).expect("the Ed25519 half still verifies");
        assert_eq!(copy.id(), event.id());
        altered += 1;
    }
    assert_eq!(altered, 1);

    bob.follow(space).await;
    bob.ingest(space, events).await.unwrap();
    let level = bob
        .read(&space, |r| r.level_of(&bob.device_id()))
        .await
        .unwrap();
    assert_eq!(level, Some(Level::Write));
    assert!(!bob.stream_released(&space, &doc.stream()).await.unwrap());
}

/// A peer whose `Heads` lack an event it acknowledged rolled back (units.md,
/// 3.13 "A restored peer"): the event is not durable again, returns to the
/// outbox, is offered again, and the loss is reported.
#[tokio::test]
async fn a_peer_that_lacks_what_it_acknowledged_rolled_back() {
    use frasil::advanced::Acknowledger;
    use frasil::advanced::outbox::LossClass;
    use frasil::advanced::sync::SyncSession;
    use frasil_units::messages::{Message, SyncMessage};
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    let unit = alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "kept").unwrap();
        })
        .await
        .unwrap();
    let peer = Acknowledger::Peer([9; 32]);
    let mut session = SyncSession::new(space);
    let mut losses = alice.losses();
    let heads = alice.read(&space, |r| r.heads()).await.unwrap();
    alice
        .sync_receive(
            &mut session,
            peer,
            SyncMessage {
                space,
                message: Message::Ack { heads },
            },
        )
        .await
        .unwrap();
    assert!(alice.outbox(&space).await.is_empty(), "durable at the peer");
    // The peer, restored, serves the state before the unit.
    let parents = alice
        .read(&space, |r| r.event(unit).map(|e| e.parents().to_vec()))
        .await
        .unwrap()
        .unwrap();
    let out = alice
        .sync_receive(
            &mut session,
            peer,
            SyncMessage {
                space,
                message: Message::Heads {
                    heads: parents,
                    vector: None,
                    streams: Vec::new(),
                },
            },
        )
        .await
        .unwrap();
    assert!(
        alice.outbox(&space).await.contains(&unit),
        "not durable again"
    );
    assert!(
        out.iter()
            .any(|m| matches!(&m.message, Message::Events { events }
            if events.iter().any(|s| frasil_events::decode(s).is_ok_and(|e| e.id() == unit)))),
        "offered again"
    );
    let loss = losses.try_recv().unwrap();
    assert_eq!(loss.class, LossClass::RolledBack);
    assert!(loss.events.contains(&unit));
    assert!(
        alice
            .lost_by(&peer)
            .contains(&(space, LossClass::RolledBack))
    );
    // Acknowledged again, it is durable again.
    let heads = alice.read(&space, |r| r.heads()).await.unwrap();
    alice
        .sync_receive(
            &mut session,
            peer,
            SyncMessage {
                space,
                message: Message::Ack { heads },
            },
        )
        .await
        .unwrap();
    assert!(alice.outbox(&space).await.is_empty());
}

/// Head statements of one device (units.md, 3.13 "Head statements"): one
/// whose heads the receiver lacks is kept beside an older one, its heads are
/// asked of its author, and an author that answers `Missing` for them made
/// a junk statement; once the receiver holds a statement's heads, an older
/// statement replayed after it is not kept.
#[tokio::test]
async fn head_statements_are_kept_in_order_and_junk_is_reported() {
    use frasil::advanced::Acknowledger;
    use frasil::advanced::outbox::LossClass;
    use frasil::advanced::sync::SyncSession;
    use frasil_units::messages::{Message, SyncMessage};
    let alice = device().await;
    let bob = device().await;
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
    bob.follow(space).await;
    converge(&alice, &bob, space).await;
    let (older, _) = alice.head_statement(&space).await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "new").unwrap();
        })
        .await
        .unwrap();
    let (newer, newer_heads) = alice.head_statement(&space).await.unwrap();
    let kept_of_alice = |bob: &Engine| {
        let bob = bob.clone();
        let alice = alice.device_id();
        async move {
            bob.read(&space, |r| {
                r.statements()
                    .get(&alice)
                    .map(|kept| kept.iter().map(|s| s.heads.clone()).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .await
            .unwrap()
        }
    };
    // Bob lacks the newer heads: the two are not ordered, both are kept.
    assert_eq!(
        bob.take_statements(&space, std::slice::from_ref(&newer))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        bob.take_statements(&space, std::slice::from_ref(&older))
            .await
            .unwrap(),
        1
    );
    assert_eq!(kept_of_alice(&bob).await.len(), 2);
    // Bob asks Alice for the heads it lacks.
    let mut session = SyncSession::new(space);
    let asked = bob
        .sync_stated(&mut session, &alice.device_id())
        .await
        .unwrap();
    assert!(
        asked
            .iter()
            .any(|m| matches!(&m.message, Message::Want { ids, .. }
        if newer_heads.iter().any(|h| ids.contains(h))))
    );
    // Alice answers that she does not hold them: the statement is junk.
    let mut losses = bob.losses();
    bob.sync_receive(
        &mut session,
        Acknowledger::Member(alice.device_id().0),
        SyncMessage {
            space,
            message: Message::Missing {
                ids: newer_heads.clone(),
                carried: Vec::new(),
            },
        },
    )
    .await
    .unwrap();
    let loss = losses.try_recv().unwrap();
    assert_eq!(loss.class, LossClass::BadStatement);
    assert_eq!(kept_of_alice(&bob).await.len(), 1);
    // Once Bob holds the newer heads, the newer statement takes the older
    // one's place, and the older one replayed is not kept.
    converge(&alice, &bob, space).await;
    assert_eq!(bob.take_statements(&space, &[newer]).await.unwrap(), 1);
    assert_eq!(bob.take_statements(&space, &[older]).await.unwrap(), 0);
    assert_eq!(kept_of_alice(&bob).await, vec![newer_heads]);
}

/// A peer that answers `Missing` for a head statement's heads (units.md,
/// 3.13 "Head statements") may not have received them yet: it is not
/// reported when the author supplies them within `withholding_grace`. It is
/// reported `Withheld` once it answered `Missing` again, asked after the
/// grace, and the author then supplied them; and at once when it had
/// acknowledged them.
#[tokio::test]
async fn a_peer_missing_stated_heads_is_withheld_only_after_the_grace_or_its_acknowledgement() {
    use frasil::advanced::outbox::LossClass;
    use frasil::advanced::sync::SyncSession;
    use frasil::advanced::{Acknowledger, ManualClock};
    use frasil_units::messages::{Message, SyncMessage};
    use std::sync::Arc;
    let grace = frasil_base::time::Timer::WithholdingGrace
        .spec()
        .default
        .unwrap();
    let alice = device().await;
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let (bob, _) = Engine::create(
        Platform::memory().with_clock(clock.clone()),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
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
    bob.follow(space).await;
    converge(&alice, &bob, space).await;
    let peer = Acknowledger::Peer([9; 32]);
    let doc = alice.new_document().unwrap();
    // Alice writes and states her new heads; Bob takes the statement and
    // asks her for them, then the peer, which answers `Missing`.
    let stated = |round: &'static str| {
        let (alice, bob, doc) = (alice.clone(), bob.clone(), doc.clone());
        async move {
            alice
                .edit_document(space, &doc, |d| {
                    d.get_text("body").insert(0, round).unwrap();
                })
                .await
                .unwrap();
            let (statement, heads) = alice.head_statement(&space).await.unwrap();
            assert_eq!(bob.take_statements(&space, &[statement]).await.unwrap(), 1);
            let mut to_alice = SyncSession::new(space);
            let asked = bob
                .sync_stated(&mut to_alice, &alice.device_id())
                .await
                .unwrap();
            assert!(!asked.is_empty());
            heads
        }
    };
    let missing = |heads: &[EventId]| SyncMessage {
        space,
        message: Message::Missing {
            ids: heads.to_vec(),
            carried: Vec::new(),
        },
    };
    let wants = |messages: &[SyncMessage], heads: &[EventId]| {
        messages.iter().any(|m| {
            matches!(&m.message, Message::Want { ids, .. } if heads.iter().all(|h| ids.contains(h)))
        })
    };
    let mut losses = bob.losses();

    // Within the grace: the author supplies the heads, nothing is reported.
    let heads = stated("one").await;
    let mut at_peer = SyncSession::new(space);
    bob.sync_receive(&mut at_peer, peer, missing(&heads))
        .await
        .unwrap();
    assert!(at_peer.take_stated_missing(), "asked again after the grace");
    clock.advance(grace - 1);
    assert!(
        bob.sync_restated(&mut at_peer, peer)
            .await
            .unwrap()
            .is_empty(),
        "not before the grace"
    );
    converge(&alice, &bob, space).await;
    assert!(
        losses.try_recv().is_err(),
        "a late upload is no withholding"
    );

    // Past the grace: the peer is asked again, still answers `Missing`, and
    // the author then supplies the heads: `Withheld`.
    let heads = stated("two").await;
    let mut at_peer = SyncSession::new(space);
    bob.sync_receive(&mut at_peer, peer, missing(&heads))
        .await
        .unwrap();
    assert!(at_peer.take_stated_missing());
    clock.advance(grace);
    let again = bob.sync_restated(&mut at_peer, peer).await.unwrap();
    assert!(wants(&again, &heads), "asked again: {again:?}");
    bob.sync_receive(&mut at_peer, peer, missing(&heads))
        .await
        .unwrap();
    assert!(!at_peer.take_stated_missing(), "not its first answer");
    assert!(
        losses.try_recv().is_err(),
        "not before the author supplies them"
    );
    converge(&alice, &bob, space).await;
    let loss = losses.try_recv().unwrap();
    assert_eq!((loss.class, loss.by), (LossClass::Withheld, peer));
    assert!(heads.iter().all(|h| loss.events.contains(h)));

    // A peer that acknowledged the heads, then answered `Missing` for
    // them, is reported as soon as the author supplies them.
    let heads = stated("three").await;
    let mut at_peer = SyncSession::new(space);
    bob.sync_receive(
        &mut at_peer,
        peer,
        SyncMessage {
            space,
            message: Message::Ack {
                heads: heads.clone(),
            },
        },
    )
    .await
    .unwrap();
    bob.sync_receive(&mut at_peer, peer, missing(&heads))
        .await
        .unwrap();
    converge(&alice, &bob, space).await;
    let loss = losses.try_recv().unwrap();
    assert_eq!((loss.class, loss.by), (LossClass::Withheld, peer));
    assert!(heads.iter().all(|h| loss.events.contains(h)));
}
