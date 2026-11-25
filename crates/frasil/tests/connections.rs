//! Connections and sync over loopback QUIC: admission by code on a nearby
//! connection, then a member connection that syncs Loro units both ways,
//! live; local discovery; every space two devices share on one connection;
//! and a removal that ends a member's connection.
//! Every wait has a deadline, and nothing leaves the host.
#![cfg(all(feature = "iroh", feature = "adapter-loro"))]

use frasil::advanced::member::run_member;
use frasil::advanced::node::Node;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_iroh::lan::LanConfig;
use frasil_iroh::{Alpn, Config, Endpoint};
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_transport::ticket::TicketKind;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(30);

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

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

async fn text_of(device: &Engine, space: &EventId, stream: &[u8; 16]) -> Option<String> {
    device
        .document(space, stream)
        .await
        .ok()
        .map(|doc| doc.get_text("body").to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_admit_by_code_and_sync_loro_units() {
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
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();

    // Both screens show a code; each person confirms what they see.
    let codes = Arc::new(Mutex::new(Vec::new()));
    let seen = codes.clone();
    let hosted = alice_node.host_pairing(
        space,
        frasil::advanced::pairing::default_offer(Level::Write),
        "Alice's laptop",
        move |code, newcomer| {
            assert_eq!(newcomer, "Bob's phone");
            seen.lock().unwrap().push(code.to_string());
            async { true }
        },
    );
    let seen = codes.clone();
    let joined = within(bob_node.join(
        &alice_node.ticket(TicketKind::Nearby),
        "Bob's phone",
        move |code, host| {
            assert_eq!(host, "Alice's laptop");
            seen.lock().unwrap().push(code.to_string());
            async { true }
        },
    ))
    .await
    .unwrap();
    let admitting = within(hosted).await.unwrap().unwrap();
    assert_eq!(joined.admitting, admitting);
    assert_eq!(joined.space, space);
    let codes = codes.lock().unwrap().clone();
    assert_eq!(codes.len(), 2);
    assert_eq!(codes[0], codes[1], "both screens show one code");
    assert_eq!(
        bob.read(&space, |r| r.level_of(&bob.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );

    // The member connection carries what follows, both ways, live.
    until(|| async { text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("hello") })
        .await;
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(5, ", world").unwrap();
    })
    .await
    .unwrap();
    until(|| async {
        text_of(&alice, &space, &doc.stream()).await.as_deref() == Some("hello, world")
    })
    .await;
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(12, "!").unwrap();
        })
        .await
        .unwrap();
    until(|| async {
        text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("hello, world!")
    })
    .await;
    // Each side acknowledged the other's events: the outboxes empty.
    until(|| async {
        alice.outbox(&space).await.is_empty() && bob.outbox(&space).await.is_empty()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_codes_mismatch_admits_nobody() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    let hosted = alice_node.host_pairing(
        space,
        frasil::advanced::pairing::default_offer(Level::Write),
        "Alice",
        |_, _| async { false },
    );
    let joined = within(bob_node.join(
        &alice_node.ticket(TicketKind::Nearby),
        "Bob",
        |_, _| async { true },
    ))
    .await;
    assert!(joined.is_err());
    assert_eq!(
        within(hosted).await.unwrap().unwrap_err(),
        frasil::Error::Class("Mismatch")
    );
    let devices = alice.read(&space, |r| r.devices()).await.unwrap();
    assert_eq!(devices.len(), 1, "only the founder");
}

/// Two members whose events were carried by hand: the space, a grant.
async fn two_members() -> (Engine, Engine, EventId) {
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
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    (alice, bob, space)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_find_each_other_on_the_local_network() {
    let (alice, bob, space) = two_members().await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    alice_node.discover(LanConfig::loopback_v4()).unwrap();
    bob_node.discover(LanConfig::loopback_v4()).unwrap();
    let doc = bob.new_document().unwrap();
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, "offline").unwrap();
    })
    .await
    .unwrap();
    until(|| async { text_of(&alice, &space, &doc.stream()).await.as_deref() == Some("offline") })
        .await;
}

/// Two members of `count` spaces whose events were carried by hand, the
/// spaces in ascending order of ID, as a device ranks them.
async fn members_of(count: usize) -> (Engine, Engine, Vec<EventId>) {
    let alice = device().await;
    let bob = device().await;
    let mut spaces = Vec::new();
    for _ in 0..count {
        spaces.push(share(&alice, &bob).await);
    }
    spaces.sort_unstable();
    (alice, bob, spaces)
}

/// A space `host` creates and grants `member`, its events carried by hand.
async fn share(host: &Engine, member: &Engine) -> EventId {
    let space = host.create_space().await.unwrap();
    host.grant_device(
        space,
        member.public_keys().clone(),
        Level::Write,
        HistoryMode::WithHistory,
        Via::Code,
    )
    .await
    .unwrap();
    member.follow(space).await;
    member
        .ingest(space, host.events(&space).await)
        .await
        .unwrap();
    space
}

/// `from` writes `text` in a new document of `space`, and `to` reads it.
async fn carries(from: &Engine, to: &Engine, space: EventId, text: &str) {
    let doc = from.new_document().unwrap();
    from.edit_document(space, &doc, |d| {
        d.get_text("body").insert(0, text).unwrap();
    })
    .await
    .unwrap();
    until(|| async { text_of(to, &space, &doc.stream()).await.as_deref() == Some(text) }).await;
}

/// A device announces four spaces at a time (transport.md, "Member
/// announcements"), and a member connection attaches every space its two
/// devices share (transport.md, "Further attaches"): the fifth syncs too,
/// with no peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_of_five_spaces_sync_them_all_on_the_local_network() {
    let (alice, bob, spaces) = members_of(5).await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    alice_node.discover(LanConfig::loopback_v4()).unwrap();
    bob_node.discover(LanConfig::loopback_v4()).unwrap();
    for space in spaces {
        carries(&bob, &alice, space, "from Bob").await;
        carries(&alice, &bob, space, "from Alice").await;
    }
}

/// A device announces its spaces four at a time, each in turn
/// (transport.md, "Member announcements"): two devices whose one shared
/// space is the fifth or later of each, by ID, still find each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_find_each_other_by_a_space_neither_announces_first() {
    let alice = device().await;
    let bob = device().await;
    // Alice's spaces, the shared one last by ID.
    let mut hers = Vec::new();
    for _ in 0..9 {
        hers.push(alice.create_space().await.unwrap());
    }
    hers.sort_unstable();
    let space = hers[8];
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
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    // Bob's own, until four come before the shared one.
    let mut before = 0;
    for _ in 0..64 {
        if before == 4 {
            break;
        }
        if bob.create_space().await.unwrap() < space {
            before += 1;
        }
    }
    assert_eq!(before, 4, "four of Bob's spaces come before the shared one");
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    alice_node.discover(LanConfig::loopback_v4()).unwrap();
    bob_node.discover(LanConfig::loopback_v4()).unwrap();
    carries(&bob, &alice, space, "from Bob").await;
    carries(&alice, &bob, space, "from Alice").await;
}

/// Whether each device holds exactly one admitted attach of each space
/// with the other.
async fn attached_once(alice: &Engine, bob: &Engine, spaces: &[EventId]) -> bool {
    spaces.iter().all(|space| {
        alice.attaches_with(space, &bob.device_id()) == 1
            && bob.attaches_with(space, &alice.device_id()) == 1
    })
}

/// A member endpoint on loopback, under a key of its own.
async fn member_endpoint(key: u8) -> Endpoint {
    Endpoint::bind(Config::new([key; 32], &[Alpn::Member]).loopback())
        .await
        .unwrap()
}

/// The dialer offers a second space once attach 0 is proved, and so does
/// the listener, each before it reads the other's offer. The offer with
/// the lower attach number is answered and the other refused (transport.md,
/// "Further attaches"): one attach carries the space, and the connection
/// stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_both_sides_offer_at_once_is_attached_once() {
    let (alice, bob, spaces) = members_of(2).await;
    let host = member_endpoint(41).await;
    let guest = member_endpoint(42).await;
    let (key, addresses) = (host.key(), host.local_addresses());
    let (dialed, accepted) = within(async {
        tokio::join!(guest.connect(&key, &addresses, &[], Alpn::Member), async {
            host.accept().await.unwrap()
        },)
    })
    .await;
    let dialing = tokio::spawn(run_member(alice.clone(), dialed.unwrap(), spaces.clone()));
    let listening = tokio::spawn(run_member(bob.clone(), accepted.unwrap(), vec![spaces[1]]));
    for space in &spaces {
        carries(&bob, &alice, *space, "from Bob").await;
        carries(&alice, &bob, *space, "from Alice").await;
    }
    until(|| attached_once(&alice, &bob, &spaces)).await;
    // What follows still arrives, on the one attach of each space.
    for space in &spaces {
        carries(&bob, &alice, *space, "more from Bob").await;
        carries(&alice, &bob, *space, "more from Alice").await;
    }
    until(|| attached_once(&alice, &bob, &spaces)).await;
    assert!(!dialing.is_finished() && !listening.is_finished());
}

/// A device offers the spaces the other device reaches in its own view,
/// and no other. Bob, who has not heard that Alice removed him from a
/// space, offers it; Alice detaches him at once, and the spaces they share
/// keep their connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_the_other_device_does_not_reach_is_not_attached() {
    let (alice, bob, spaces) = members_of(3).await;
    let (shared, ended) = ([spaces[0], spaces[2]], spaces[1]);
    alice
        .remove(ended, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    let alone = alice.create_space().await.unwrap();
    assert_eq!(alice.spaces_shared_with(&bob.device_id()).await, shared);
    assert!(!shared.contains(&alone));
    // Bob's view is behind: it still names Alice in all three.
    assert_eq!(bob.spaces_shared_with(&alice.device_id()).await, spaces);

    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    bob_node
        .dial(&alice_node.ticket(TicketKind::Member), vec![shared[0]])
        .await
        .unwrap();
    // Bob offers the space he was removed from before the last one, in
    // the order of their IDs: once the last syncs, Alice has detached him.
    for space in shared {
        carries(&bob, &alice, space, "from Bob").await;
        carries(&alice, &bob, space, "from Alice").await;
    }
    let kept = alice.new_document().unwrap();
    alice
        .edit_document(ended, &kept, |d| {
            d.get_text("body").insert(0, "after Bob").unwrap();
        })
        .await
        .unwrap();
    let late = bob.new_document().unwrap();
    bob.edit_document(ended, &late, |d| {
        d.get_text("body").insert(0, "from outside").unwrap();
    })
    .await
    .unwrap();
    for space in shared {
        carries(&bob, &alice, space, "more from Bob").await;
        carries(&alice, &bob, space, "more from Alice").await;
    }
    assert_eq!(text_of(&bob, &ended, &kept.stream()).await, None);
    assert_eq!(text_of(&alice, &ended, &late.stream()).await, None);
    assert_eq!(alice.attaches_with(&ended, &bob.device_id()), 0);
    assert!(attached_once(&alice, &bob, &shared).await);
    assert!(alice_node.connected_to(&bob_node.key()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_is_detached_and_reads_nothing_new() {
    let (alice, bob, space) = two_members().await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    bob_node
        .dial(&alice_node.ticket(TicketKind::Member), vec![space])
        .await
        .unwrap();
    until(|| async { alice_node.connected_to(&bob_node.key()) }).await;
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "shared").unwrap();
        })
        .await
        .unwrap();
    until(|| async { text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("shared") })
        .await;
    alice
        .remove(space, MemberRef::device(bob.device_id()))
        .await
        .unwrap();
    // The re-check detaches Bob, the last attach, and the connection
    // closes.
    until(|| async { !alice_node.connected_to(&bob_node.key()) }).await;
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(6, " secret").unwrap();
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        text_of(&bob, &space, &doc.stream()).await.as_deref(),
        Some("shared")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_members_gossip_head_statements() {
    let (alice, bob, space) = two_members().await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    bob_node
        .dial(&alice_node.ticket(TicketKind::Member), vec![space])
        .await
        .unwrap();
    // Each states its heads once the attach is admitted.
    until(|| async {
        alice
            .read(&space, |r| r.statements().contains_key(&bob.device_id()))
            .await
            .unwrap()
    })
    .await;
    until(|| async {
        bob.read(&space, |r| r.statements().contains_key(&alice.device_id()))
            .await
            .unwrap()
    })
    .await;
    let (stated, heads) = alice
        .read(&space, |r| {
            let mut heads = r.heads();
            heads.sort_unstable();
            let stated: Vec<Vec<EventId>> = r.statements()[&bob.device_id()]
                .iter()
                .map(|s| s.heads.clone())
                .collect();
            (stated, heads)
        })
        .await
        .unwrap();
    assert!(stated.contains(&heads), "Bob states what both hold");
}

/// The units among a device's own events of a space.
#[cfg(feature = "ext-guests")]
async fn own_units(device: &Engine, space: &EventId) -> usize {
    device
        .events(space)
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|e| e.kind() == frasil_events::kind::UNIT && e.author() == &device.device_id())
        .count()
}

#[cfg(feature = "ext-guests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_that_keeps_nothing_at_rest_takes_its_snapshot_on_the_connection() {
    let alice = device().await;
    let bob = Engine::create(
        Platform::memory(),
        &[8; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    let units = own_units(&alice, &space).await;
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [9; 16]);
    preset.nothing_at_rest = true;
    let hosted = alice_node.host_pairing(
        space,
        frasil_admission::ext_guests::guest_offer(&preset),
        "Alice's laptop",
        |_, _| async { true },
    );
    let joined = within(bob_node.join(
        &alice_node.ticket(TicketKind::Nearby),
        "Bob's phone",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    within(hosted).await.unwrap().unwrap();
    assert_eq!(joined.space, space);
    // Bob starts from the snapshot the connection carried...
    until(|| async { text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("hello") })
        .await;
    // ...and Alice published none for a peer: no body-keys unit.
    assert_eq!(own_units(&alice, &space).await, units);
}

/// A store that watches every commit: after each, it counts the records
/// it holds of any log (a scope tag that is not the device's) and the
/// `log` records, and keeps the largest count it saw.
#[cfg(feature = "ext-guests")]
struct Watched {
    inner: frasil_store::MemoryStore,
    most: Mutex<usize>,
}

#[cfg(feature = "ext-guests")]
impl Watched {
    fn log_records(records: &[(Vec<u8>, Vec<u8>)]) -> usize {
        records
            .iter()
            .filter(|(address, _)| {
                address[..16] != [0; 16] || address[16] == frasil_store::Table::Log.code()
            })
            .count()
    }

    fn most(&self) -> usize {
        *self.most.lock().unwrap()
    }
}

#[cfg(feature = "ext-guests")]
impl frasil_store::Store for Watched {
    fn get<'a>(
        &'a self,
        address: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Option<Vec<u8>>, frasil_store::StoreError>> {
        self.inner.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Vec<(Vec<u8>, Vec<u8>)>, frasil_store::StoreError>>
    {
        self.inner.scan(prefix)
    }

    fn commit<'a>(
        &'a self,
        commit: &'a frasil_store::Commit,
    ) -> frasil_store::BoxFuture<'a, Result<bool, frasil_store::StoreError>> {
        Box::pin(async move {
            let made = self.inner.commit(commit).await?;
            let held = Self::log_records(&self.inner.scan(&[]).await?);
            let mut most = self.most.lock().unwrap();
            *most = (*most).max(held);
            Ok(made)
        })
    }
}

#[cfg(feature = "ext-guests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_admitted_nearby_that_keeps_nothing_at_rest_commits_nothing_of_the_space() {
    let alice = device().await;
    let store = Arc::new(Watched {
        inner: frasil_store::MemoryStore::new(),
        most: Mutex::new(0),
    });
    let bob = Engine::create(
        Platform::new(store.clone(), Arc::new(frasil_store::MemorySlot::new())),
        &[8; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0;
    // What Bob's store holds of logs before he joins: his own, if any.
    let before = store.most();
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let bob_node = Node::loopback(bob.clone()).await.unwrap();
    let mut preset = frasil_space::ext_guests::Preset::new(Level::Write, [9; 16]);
    preset.nothing_at_rest = true;
    let hosted = alice_node.host_pairing(
        space,
        frasil_admission::ext_guests::guest_offer(&preset),
        "Alice's laptop",
        |_, _| async { true },
    );
    let joined = within(bob_node.join(
        &alice_node.ticket(TicketKind::Nearby),
        "Bob's phone",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    within(hosted).await.unwrap().unwrap();
    assert_eq!(joined.space, space);
    until(|| async { text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("hello") })
        .await;
    // No commit at any step of the join left a record of the space, its
    // log key or its snapshot in Bob's store.
    assert_eq!(store.most(), before);
    // Nor does writing there.
    bob.edit_document(space, &doc, |d| {
        d.get_text("body").insert(5, ", Alice").unwrap();
    })
    .await
    .unwrap();
    assert_eq!(store.most(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_display_is_set_up_by_its_setup_code() {
    let alice = device().await;
    let dave = Engine::create(
        Platform::memory(),
        &[9; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "hello").unwrap();
        })
        .await
        .unwrap();
    let alice_node = Node::loopback(alice.clone()).await.unwrap();
    let dave_node = Node::loopback(dave.clone()).await.unwrap();
    // Dave prints its setup code and waits; Alice scans it and dials Dave,
    // which writes its Hello first.
    let (code, provisioned) = dave_node.await_setup("Thermostat").unwrap();
    assert!(code.starts_with("FRASIL-SETUP:"));
    let admitting = within(alice_node.set_up(
        &dave_node.ticket(TicketKind::Nearby),
        &code,
        space,
        frasil::advanced::pairing::default_offer(Level::Write),
        "Alice's laptop",
    ))
    .await
    .unwrap();
    let provisioned = within(provisioned).await.unwrap().unwrap();
    assert_eq!(provisioned.space, space);
    assert_eq!(provisioned.admitting, admitting);
    // A code for another device's keys does not set this one up.
    let (other, _) = Node::loopback(device().await)
        .await
        .unwrap()
        .await_setup("Other")
        .unwrap();
    let (_, waiting) = dave_node.await_setup("Thermostat").unwrap();
    drop(waiting);
    assert!(
        within(alice_node.set_up(
            &dave_node.ticket(TicketKind::Nearby),
            &other,
            space,
            frasil::advanced::pairing::default_offer(Level::Write),
            "Alice's laptop",
        ))
        .await
        .is_err()
    );
    // Dave is a member, and its member connection carries the space.
    assert_eq!(
        dave.read(&space, |r| r.level_of(&dave.device_id()))
            .await
            .unwrap(),
        Some(Level::Write)
    );
    until(|| async { text_of(&dave, &space, &doc.stream()).await.as_deref() == Some("hello") })
        .await;
}
