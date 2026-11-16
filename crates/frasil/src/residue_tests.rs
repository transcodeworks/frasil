//! A space a device dropped for its own erasure (peers.md, 3.16, "A
//! device's own erasure"; at-rest.md, 3.4): only its `log` record, its
//! `pseudonym` records, its tips and the erasure's own `event` record stay,
//! through a restart, until each peer answers `erased` or the application
//! gives the space up; past the bound the peers that have not answered are
//! named. An erasure a checkpoint made late is signed again after it, or
//! reported void once the space is fetched again.

use crate::advanced::{AdapterRegistry, Engine, Platform};
use crate::checkpoints::CheckpointPolicy;
use crate::erasing::ErasureProgress;
use crate::outbox::Acknowledger;
use crate::platform::ManualClock;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_store::tables::{Scope, Table};
use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, Store};
use std::sync::Arc;

/// The tables of the space's log that hold records.
async fn tables_held(engine: &Engine, space: &frasil_events::EventId) -> Vec<Table> {
    let state = engine.lock().await;
    let mut out = Vec::new();
    for table in Table::ALL
        .iter()
        .copied()
        .filter(|t| t.scope() == Scope::Log)
    {
        if !state.vault.scan(&space.0, table).await.unwrap().is_empty() {
            out.push(table);
        }
    }
    out
}

/// A device over a store and a clock that outlive it.
struct Medium {
    store: Arc<MemoryStore>,
    slot: Arc<MemorySlot>,
    clock: Arc<ManualClock>,
}

impl Medium {
    fn new() -> Self {
        Self {
            store: Arc::new(MemoryStore::new()),
            slot: Arc::new(MemorySlot::new()),
            clock: Arc::new(ManualClock::new(100, Some(1_800_000_000))),
        }
    }

    fn platform(&self) -> Platform {
        Platform::new(
            Arc::clone(&self.store) as Arc<dyn Store>,
            Arc::clone(&self.slot) as Arc<dyn DeviceBoundSlot>,
        )
        .with_clock(Arc::clone(&self.clock) as Arc<dyn crate::platform::Clock>)
    }
}

/// A space with content, erased by its founder and dropped.
async fn dropped(medium: &Medium) -> (Engine, Vec<u8>, EventId, EventId) {
    let registry = AdapterRegistry::with_builtins();
    let (alice, sealed) = Engine::create(medium.platform(), &[4; 32], registry)
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    alice
        .keep_peer_hints(&space, &["https://peer.example".to_owned()])
        .await
        .unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "secret").unwrap();
        })
        .await
        .unwrap();
    let erasure = alice
        .sign_skeleton(space, &frasil_peers::body::StorageBody::Erase)
        .await
        .unwrap();
    alice.keep_reading().await.unwrap();
    let before = tables_held(&alice, &space).await;
    assert!(before.contains(&Table::Event) && before.contains(&Table::Pseudonym));
    alice.drop_for_erasure(&space).await.unwrap();
    (alice, sealed.to_vec(), space, erasure)
}

/// What the residue keeps at rest: the pseudonym records and the
/// erasure's own `event` record, nothing of the content.
async fn assert_residue(
    alice: &Engine,
    space: EventId,
    erasure: EventId,
    expected_administrators: usize,
    expected_peers: &[&str],
) {
    let mut tables = vec![Table::Event, Table::State, Table::Pseudonym];
    if !expected_peers.is_empty() {
        tables.push(Table::Peers);
    }
    assert_eq!(tables_held(alice, &space).await, tables);
    assert_eq!(
        alice.kept_peers(&space).await.unwrap().hints,
        expected_peers
    );
    let state = alice.lock().await;
    let records = state.vault.scan(&space.0, Table::State).await.unwrap();
    let frasil_store::TableValue::State(residue) = &records[0].1 else {
        panic!("state")
    };
    let administrators = residue.erasing.as_ref().unwrap();
    assert_eq!(administrators.len(), expected_administrators);
    assert!(
        administrators
            .iter()
            .any(|(id, _)| *id == alice.device_id().0)
    );
    assert!(administrators.iter().all(|(_, key)| key.len() == 1216));
    assert!(administrators.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert_eq!(
        residue,
        &frasil_store::tables::LogState {
            erasing: Some(administrators.clone()),
            ..Default::default()
        }
    );
    let events = state.vault.scan(&space.0, Table::Event).await.unwrap();
    assert_eq!(events.len(), 1, "the erasure's record alone");
    assert_eq!(events[0].0, erasure.0.to_vec());
}

const BOUND: u64 = 7 * 24 * 60 * 60;

#[tokio::test]
async fn a_space_dropped_for_its_own_erasure_keeps_its_erasure_alone_until_the_peers_answer() {
    let medium = Medium::new();
    let (alice, sealed, space, erasure) = dropped(&medium).await;
    assert_residue(&alice, space, erasure, 1, &["https://peer.example"]).await;
    assert!(alice.spaces().await.is_empty());
    assert_eq!(alice.erasing().await, vec![space]);

    // Opened again in that state: the residue is found, nothing else, and
    // it presents its erasure again.
    drop(alice);
    let registry = AdapterRegistry::with_builtins();
    let alice = Engine::open(medium.platform(), &sealed, &[4; 32], registry.clone())
        .await
        .unwrap();
    assert!(alice.spaces().await.is_empty());
    assert_eq!(alice.erasing().await, vec![space]);
    assert_residue(&alice, space, erasure, 1, &["https://peer.example"]).await;
    let (_, _, pending) = alice
        .administration(&space, |public| public.to_vec())
        .await
        .expect("its pseudonym presents");
    assert_eq!(pending.len(), 1, "the erasure, presented again");

    // One of two peers answers within the bound: kept, nothing to tell.
    let peers = ["wss://a".to_owned(), "wss://b".to_owned()];
    assert_eq!(
        alice
            .erasure_answered(&space, Some("wss://a"), &peers)
            .await
            .unwrap(),
        ErasureProgress::Waiting { unanswered: None }
    );
    // Past the bound, across a restart, from the erasure's first sight:
    // the peer that has not answered is named, once, and the residue kept.
    drop(alice);
    medium.clock.advance(BOUND + 1);
    let alice = Engine::open(medium.platform(), &sealed, &[4; 32], registry.clone())
        .await
        .unwrap();
    // The answers are asked again after a restart: peer a answers again.
    assert_eq!(
        alice
            .erasure_answered(&space, Some("wss://a"), &peers)
            .await
            .unwrap(),
        ErasureProgress::Waiting {
            unanswered: Some(vec!["wss://b".to_owned()])
        }
    );
    assert_eq!(
        alice.erasure_answered(&space, None, &peers).await.unwrap(),
        ErasureProgress::Waiting { unanswered: None }
    );
    assert_residue(&alice, space, erasure, 1, &["https://peer.example"]).await;
    // Both answered: forgotten, at rest too.
    assert_eq!(
        alice
            .erasure_answered(&space, Some("wss://b"), &peers)
            .await
            .unwrap(),
        ErasureProgress::Forgotten
    );
    drop(alice);
    let alice = Engine::open(medium.platform(), &sealed, &[4; 32], registry)
        .await
        .unwrap();
    assert!(alice.erasing().await.is_empty());
    assert!(tables_held(&alice, &space).await.is_empty());
}

#[tokio::test]
async fn the_application_gives_up_a_space_dropped_for_its_own_erasure() {
    let medium = Medium::new();
    let (alice, sealed, space, _) = dropped(&medium).await;
    assert!(matches!(
        alice.give_up_erasure(&EventId([9; 32])).await,
        Err(crate::Error::UnknownSpace)
    ));
    alice.give_up_erasure(&space).await.unwrap();
    assert!(alice.erasing().await.is_empty());
    drop(alice);
    let alice = Engine::open(
        medium.platform(),
        &sealed,
        &[4; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    assert!(alice.erasing().await.is_empty());
    assert!(tables_held(&alice, &space).await.is_empty());
}

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

async fn sync(a: &Engine, b: &Engine, space: EventId) {
    carry(a, b, space).await;
    carry(b, a, space).await;
}

/// Every pending event of `device` acknowledged by a peer.
async fn acknowledged(device: &Engine, space: EventId) {
    let pending = device.outbox(&space).await;
    device
        .acknowledge(space, Acknowledger::Peer([1; 32]), &pending)
        .await
        .unwrap();
}

/// Bob erases the space while Alice checkpoints: he keeps the space while
/// her checkpoint can still make the erasure late, signs it again once the
/// checkpoint is in effect, and drops the space once that erasure is
/// acknowledged, keeping its pseudonym alone until the peers answer.
#[tokio::test]
async fn an_erasure_made_late_by_a_concurrent_checkpoint_is_signed_again_before_the_space_is_dropped()
 {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device_at(
            space,
            bob.public_keys().clone(),
            Level::Administer,
            Some(255),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(&alice, &bob, space).await;
    bob.enrol(&space).await.unwrap();
    carry(&bob, &alice, space).await;
    acknowledged(&bob, space).await;
    let erasure = bob
        .sign_skeleton(space, &frasil_peers::body::StorageBody::Erase)
        .await
        .unwrap();
    let c = alice.propose_checkpoint(space).await.unwrap();
    acknowledged(&bob, space).await;
    // Acknowledged, before the checkpoint reaches Bob: nothing concurrent
    // is known yet.
    assert!(bob.own_erasure_droppable(&space).await);
    sync(&alice, &bob, space).await;
    // The checkpoint, pending and concurrent, could still make it late.
    assert!(!bob.own_erasure_droppable(&space).await);
    bob.acknowledge_checkpoint(space).await.unwrap();
    sync(&alice, &bob, space).await;
    assert_eq!(
        bob.checkpoint_status(&space)
            .await
            .unwrap()
            .in_effect
            .map(|k| *k.as_bytes()),
        Some(c.0)
    );
    let class = bob
        .read(&space, |r| r.status(&erasure).copied())
        .await
        .unwrap()
        .and_then(|s| s.class());
    assert_eq!(class.map(frasil_base::errors::Class::name), Some("Late"));
    assert!(!bob.own_erasure_droppable(&space).await);
    let again = bob.resign_late_requests(space).await.unwrap();
    assert_eq!(again, vec![erasure]);
    acknowledged(&bob, space).await;
    assert!(bob.own_erasure_droppable(&space).await);
    bob.drop_for_erasure(&space).await.unwrap();
    assert!(bob.spaces().await.is_empty());
    assert_eq!(bob.erasing().await, vec![space]);
}

/// Alice erases the space and drops it; Bob, who outranks her, lowers her
/// to write and checkpoints, concurrently: her erasure is late there. Told
/// so, she fetches the space again from Bob's snapshot, finds she no
/// longer administers it, and the erasure is void.
#[tokio::test]
async fn an_erasure_a_checkpoint_made_late_after_the_drop_is_void_once_the_device_no_longer_administers()
 {
    let bob = device().await;
    let space = bob.create_space().await.unwrap();
    let medium = Medium::new();
    let (alice, _) = Engine::create(
        medium.platform(),
        &[4; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let granted = bob
        .grant_device_at(
            space,
            alice.public_keys().clone(),
            Level::Administer,
            Some(200),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    alice.enrol(&space).await.unwrap();
    sync(&alice, &bob, space).await;
    acknowledged(&alice, space).await;
    acknowledged(&bob, space).await;

    // Alice erases and drops the space, knowing of no checkpoint.
    let erasure = alice
        .sign_skeleton(space, &frasil_peers::body::StorageBody::Erase)
        .await
        .unwrap();
    acknowledged(&alice, space).await;
    assert!(alice.own_erasure_droppable(&space).await);
    alice.drop_for_erasure(&space).await.unwrap();
    assert_residue(&alice, space, erasure, 2, &[]).await;

    // Meanwhile Bob lowers her and checkpoints.
    bob.set_level(
        space,
        frasil_space::MemberRef::device(alice.device_id()),
        Level::Write,
    )
    .await
    .unwrap();
    bob.propose_checkpoint(space).await.unwrap();
    assert!(
        bob.checkpoint_status(&space)
            .await
            .unwrap()
            .in_effect
            .is_some(),
        "in effect without Alice, whom the lowering excuses"
    );

    // Told of it, Alice fetches the space again from Bob's snapshot.
    assert!(alice.erasure_late_at(&space, "wss://peer").await);
    assert!(!alice.erasure_late_at(&space, "wss://peer").await, "once");
    alice.refetch_erased(&space).await.unwrap();
    assert!(
        alice.erasing().await.is_empty(),
        "no longer waiting for answers"
    );
    let snapshot = bob.newcomer_snapshot(&space, granted).await.unwrap();
    alice
        .adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    assert_eq!(
        alice.settle_refetched(&space).await.unwrap(),
        Some(crate::erasing::Refetched::Void)
    );
    assert!(alice.erasing().await.is_empty());
    assert!(alice.spaces().await.contains(&space), "the space lives on");
}

/// Alice, granted to administer, enrols and erases the space apart from
/// Bob, who checkpoints meanwhile with her slot unenrolled. Told that a
/// peer serves that checkpoint, she fetches the space again, votes for it,
/// which makes her erasure late, still administers the space, enrols her
/// slot again and signs the erasure again after the checkpoint.
#[tokio::test]
async fn an_erasure_a_checkpoint_made_late_after_the_drop_is_signed_again_while_the_device_administers()
 {
    let bob = device().await;
    let space = bob.create_space().await.unwrap();
    let medium = Medium::new();
    let (alice, _) = Engine::create(
        medium.platform(),
        &[4; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    alice.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
    let granted = bob
        .grant_device_at(
            space,
            alice.public_keys().clone(),
            Level::Administer,
            Some(200),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    // Apart: Alice enrols and erases; Bob checkpoints.
    alice.enrol(&space).await.unwrap();
    let erasure = alice
        .sign_skeleton(space, &frasil_peers::body::StorageBody::Erase)
        .await
        .unwrap();
    acknowledged(&alice, space).await;
    alice.drop_for_erasure(&space).await.unwrap();
    assert_residue(&alice, space, erasure, 2, &[]).await;
    bob.propose_checkpoint(space).await.unwrap();
    // It waits for Alice's vote, which a residue cannot give.
    assert!(
        bob.checkpoint_status(&space)
            .await
            .unwrap()
            .in_effect
            .is_none()
    );

    alice.erasure_late_at(&space, "wss://peer").await;
    alice.refetch_erased(&space).await.unwrap();
    let snapshot = bob.newcomer_snapshot(&space, granted).await.unwrap();
    alice
        .adopt_snapshot(space, &snapshot.signed, snapshot.parts())
        .await
        .unwrap();
    carry(&bob, &alice, space).await;
    // Not decided while the checkpoint is not in effect in her view.
    assert_eq!(alice.settle_refetched(&space).await.unwrap(), None);
    // Her vote puts it in effect, which makes her erasure late.
    alice.acknowledge_checkpoint(space).await.unwrap();
    let Some(crate::erasing::Refetched::SignedAgain(again)) =
        alice.settle_refetched(&space).await.unwrap()
    else {
        panic!("signed again");
    };
    assert_ne!(again, erasure);
    carry(&alice, &bob, space).await;
    // The new erasure follows the checkpoint at Bob: not late.
    let late = bob.checkpoint_status(&space).await.unwrap().late;
    assert!(!late.iter().any(|id| *id.as_bytes() == again.0), "{late:?}");
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
#[tokio::test]
async fn welcome_requests_never_deliver_to_non_members_or_bad_signatures() {
    use frasil_admission::welcome_request::WelcomeRequest;
    let admin = device().await;
    let member = device().await;
    let space = admin.create_space().await.unwrap();
    admin
        .grant_device(
            space,
            member.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    admin.propose_checkpoint(space).await.unwrap();
    assert!(
        admin
            .checkpoint_status(&space)
            .await
            .unwrap()
            .in_effect
            .is_some()
    );
    let request = WelcomeRequest {
        space: space.0,
        device: member.device_id(),
        request: [42; 16],
    };
    let signed = request.sign(member.signer());
    let (found, keys) = admin.welcome_request_member(&signed).await.unwrap();
    assert_eq!(found, space);
    let (_, wraps) = admin.deliver_returning_member(space, &keys).await.unwrap();
    assert!(wraps.contains_key(&member.device_id()));
    let before = admin.events(&space).await;
    assert!(matches!(
        admin
            .welcome_request_member(&request.sign(admin.signer()))
            .await,
        Err(crate::Error::Class("BadSignature"))
    ));
    assert_eq!(admin.events(&space).await, before);
    admin
        .remove(space, frasil_space::MemberRef::device(member.device_id()))
        .await
        .unwrap();
    assert!(admin.welcome_request_member(&signed).await.is_err());
    assert!(admin.deliver_returning_member(space, &keys).await.is_err());
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
#[tokio::test]
async fn contradictory_erasure_answers_leave_the_peer_unanswered() {
    use frasil_peers::body::StorageBody;
    use frasil_transport::messages::ErasureLate;
    let bob = device().await;
    let alice = device().await;
    let space = bob.create_space().await.unwrap();
    bob.grant_administrator(
        space,
        alice.public_keys().clone(),
        200,
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .unwrap();
    carry(&bob, &alice, space).await;
    alice.enrol(&space).await.unwrap();
    let erasure = alice.request_erasure(space).await.unwrap();
    acknowledged(&alice, space).await;
    alice.drop_for_erasure(&space).await.unwrap();
    bob.propose_checkpoint(space).await.unwrap();
    let events: Vec<_> = bob
        .events(&space)
        .await
        .iter()
        .map(|signed| frasil_events::decode(signed).unwrap())
        .collect();
    let cut = events
        .iter()
        .find(|event| {
            matches!(
                StorageBody::read(event.unverified_body()),
                Ok(StorageBody::Cut(_))
            )
        })
        .unwrap();
    let checkpoint = events
        .iter()
        .find(|event| {
            event.kind() == frasil_events::kind::SPACE && event.parents().contains(&cut.id())
        })
        .unwrap();
    let good = ErasureLate {
        space: space.0,
        erasure: erasure.0,
        cut: cut.signed(),
        checkpoint: checkpoint.id().0,
        standing: 1,
    };
    alice
        .receive_erasure_late(space, good.clone())
        .await
        .unwrap();
    assert_eq!(alice.take_erasure_late(&space).await.unwrap(), good);
    let mut contradictory = good.clone();
    contradictory.standing = 2;
    assert!(matches!(
        alice
            .receive_erasure_late(space, contradictory.clone())
            .await,
        Err(crate::Error::Class("PeerError"))
    ));
    assert_eq!(
        alice.take_erasure_peer_error(&space).await.unwrap(),
        contradictory.encode()
    );
    let mut swapped = good.clone();
    swapped.cut = checkpoint.signed();
    assert!(matches!(
        alice.receive_erasure_late(space, swapped).await,
        Err(crate::Error::Class("PeerError"))
    ));
    assert!(alice.take_erasure_peer_error(&space).await.is_some());
    let mut unrelated = good;
    unrelated.erasure[0] ^= 1;
    assert!(matches!(
        alice.receive_erasure_late(space, unrelated).await,
        Err(crate::Error::Class("Malformed"))
    ));
    assert_eq!(
        alice
            .erasure_answered(&space, None, &["https://peer.example".to_owned()])
            .await
            .unwrap(),
        ErasureProgress::Waiting { unanswered: None }
    );
    assert_eq!(alice.erasing().await, vec![space]);
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
#[tokio::test]
async fn welcome_requests_renew_with_fresh_ids_and_include_the_requesting_administrator() {
    let medium = Medium::new();
    let (engine, _, space, _) = dropped(&medium).await;
    assert!(engine.erasure_welcome_due(&space).await.unwrap());
    assert!(!engine.erasure_awaiting_welcome(&space).await);
    let read_request = |requests: Vec<([u8; 32], Vec<u8>)>| {
        assert_eq!(
            requests.len(),
            1,
            "the only administrator's mailbox is still addressed"
        );
        let opened = frasil_transport::mailbox::open_item(
            &requests[0].1,
            &engine.device_id(),
            engine.xwing_seed(),
            |name| name == frasil_transport::mailbox::content::WELCOME_REQUEST,
        )
        .unwrap();
        frasil_admission::welcome_request::WelcomeRequest::read(&opened.body).unwrap()
    };
    let first = read_request(engine.erasure_welcome_requests(&space).await.unwrap());
    assert_eq!(first.space, space.0);
    assert_eq!(first.device, engine.device_id());
    assert!(engine.erasure_awaiting_welcome(&space).await);
    assert!(!engine.erasure_welcome_due(&space).await.unwrap());
    medium.clock.advance(24 * 60 * 60);
    assert!(engine.erasure_welcome_due(&space).await.unwrap());
    let second = read_request(engine.erasure_welcome_requests(&space).await.unwrap());
    assert_ne!(
        first.request, second.request,
        "a prior request may have expired at the mailbox"
    );
    assert!(!engine.erasure_welcome_due(&space).await.unwrap());
    engine.give_up_erasure(&space).await.unwrap();
    assert!(
        engine
            .lock()
            .await
            .ignored_erasure_welcomes
            .contains(&space)
    );
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
#[tokio::test]
async fn a_returning_snapshot_does_not_publish_under_a_replaced_delivery_state() {
    let admin = device().await;
    let member = device().await;
    let other = device().await;
    let space = admin.create_space().await.unwrap();
    for device in [&member, &other] {
        admin
            .grant_device(
                space,
                device.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    admin.propose_checkpoint(space).await.unwrap();
    let (delivery, wraps) = admin
        .deliver_returning_member(space, member.public_keys())
        .await
        .unwrap();
    let under = wraps[&member.device_id()].key_name.as_set().unwrap();
    let snapshot = admin
        .returning_member_snapshot(&space, delivery, under)
        .await
        .unwrap();
    admin
        .publish_returning_snapshot(&space, delivery, &snapshot, member.device_id(), under)
        .await
        .unwrap();
    // A removal during snapshot construction changes the key under which
    // new content may be published, even though the requester stays in.
    admin
        .remove(space, frasil_space::MemberRef::device(other.device_id()))
        .await
        .unwrap();
    assert_eq!(
        admin
            .read(&space, |replica| replica.level_of(&member.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    let before = admin.events(&space).await;
    assert!(
        admin
            .publish_returning_snapshot(&space, delivery, &snapshot, member.device_id(), under)
            .await
            .is_err()
    );
    assert_eq!(admin.events(&space).await, before);
}
