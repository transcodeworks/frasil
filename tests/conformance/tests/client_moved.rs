//! A space a peer handed over, at the device: the device looks for it among
//! the peers it knows for the space, its home peer first and then its peer
//! hints, and syncs where one hosts it (peers.md, "Refusal codes";
//! ext-libraries.md, "The home peer"; admission.md, "The welcome"). The
//! hints it keeps survive a restart, and the peers it syncs with go into
//! the welcomes it signs. A peer it reaches only by a hint is presented
//! that one space alone, on a connection of the device's own, which the
//! application's list of peers does not show.
//!
//! `moved` comes from a peer that answers every present of some spaces
//! with it and grants nothing; the peer that hosts the space is a real
//! `frasil-relay` on loopback. Every wait has a deadline, and nothing
//! leaves the host.

use frasil::{Device, Event, Options, Space, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_relay::testing::TestPeer;
use futures_util::{SinkExt, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::TcpListener;

/// Long enough for a few rounds of the device's upkeep and the
/// connections it opens.
const DEADLINE: Duration = Duration::from_secs(45);

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

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn device(storage: Storage, key: u8) -> Device {
    Device::open_with(storage, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

/// Whether an open connection of the device to `origin` syncs the space.
fn synced_at(device: &Device, origin: &str, space: &Space) -> bool {
    device.peers().iter().any(|peer| {
        let status = peer.status();
        peer.url() == origin && status.connected && status.spaces.contains(&space.id())
    })
}

/// Connects to the peer, waits until it syncs the space and the device
/// keeps it among the space's peers, then closes that connection.
async fn synced_once(device: &Device, peer: &TestPeer, space: &Space) {
    let link = device.connect(&peer.origin).await.unwrap();
    until(|| async { synced_at(device, &peer.origin, space) }).await;
    until(|| async { space.known_peers().await.unwrap().contains(&peer.origin) }).await;
    link.close();
}

/// Writes in a space, once the device has synced it since it opened, and
/// waits until a peer has kept it.
async fn durable_write(space: &Space, text: &str) {
    let doc = space.create_document().unwrap();
    within(async {
        loop {
            match doc.edit(|d| d.get_text("body").insert(0, text)).await {
                Ok(_) => break,
                Err(frasil::Error::SyncBeforeWriting) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await;
    until(|| async { space.is_durable().await }).await;
}

/// A peer that answers each present of some spaces `moved`, grants
/// nothing, and counts the presents of each space.
struct MovingPeer {
    origin: String,
    presents: Arc<Mutex<BTreeMap<[u8; 32], usize>>>,
}

impl MovingPeer {
    async fn start(moved: BTreeSet<EventId>) -> Self {
        use frasil_transport::frame::{ConnectionKind, Extensions, MessageType, StreamClass};
        use frasil_transport::messages::Refused;
        use frasil_transport::peer::{Checked, Limits, PeerSide};
        use tokio_tungstenite::tungstenite::Message as WsMessage;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let presents = Arc::new(Mutex::new(BTreeMap::new()));
        let (counts, channel) = (
            presents.clone(),
            frasil_transport::peer::server_channel(&origin),
        );
        let moved = Arc::new(moved);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (counts, moved) = (counts.clone(), moved.clone());
                tokio::spawn(async move {
                    // tungstenite's own callback type.
                    #[allow(clippy::result_large_err)]
                    let echo = |_: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            frasil_transport::labels::WEBSOCKET_SUBPROTOCOL
                                .parse()
                                .expect("a header"),
                        );
                        Ok(response)
                    };
                    let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, echo).await
                    else {
                        return;
                    };
                    let (mut side, hello) =
                        PeerSide::start_with(channel, [9; 32], &[], &Limits::PROTOCOL);
                    if socket.send(WsMessage::Binary(hello.into())).await.is_err() {
                        return;
                    }
                    while let Some(Ok(item)) = socket.next().await {
                        let WsMessage::Binary(bytes) = item else {
                            continue;
                        };
                        let Ok(Some(message)) = frasil_transport::frame::read_message(
                            &bytes,
                            StreamClass::Control,
                            ConnectionKind::DeviceToPeer,
                            Extensions::NONE,
                        ) else {
                            continue;
                        };
                        if message.kind == MessageType::Hello {
                            let _ = side.on_hello(&message);
                            continue;
                        }
                        let Ok(Checked::Present(present)) = side.on_message(&message) else {
                            continue;
                        };
                        *lock(&counts).entry(present.space).or_default() += 1;
                        if moved.contains(&EventId(present.space)) {
                            let refused = Refused {
                                request: present.request,
                                code: "moved".into(),
                            }
                            .encode();
                            if socket
                                .send(WsMessage::Binary(refused.into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self { origin, presents }
    }

    fn presents(&self, space: &Space) -> usize {
        lock(&self.presents)
            .get(space.id().as_bytes())
            .copied()
            .unwrap_or(0)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_refused_moved_syncs_at_a_peer_that_granted_it_before() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(Storage::Memory, 1).await;
    let space = alice.create_space().await.unwrap();
    synced_once(&alice, &peer, &space).await;

    // A space the peer never saw, which the device holds too.
    let other = alice.create_space().await.unwrap();

    // The peer the device reaches next answers `moved`: the device goes
    // back to the peer it kept as a hint, and syncs there; only the
    // moving peer can acknowledge nothing.
    let moving = MovingPeer::start([EventId(*space.id().as_bytes())].into()).await;
    alice.connect(&moving.origin).await.unwrap();
    durable_write(&space, "after the move").await;
    assert!(moving.presents(&space) >= 1);
    // The hint's peer learned of that space alone, on a connection the
    // application did not open.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!peer.peer.hosts(other.id().as_bytes()));
    assert!(
        !alice
            .peers()
            .iter()
            .any(|p| p.url() == peer.origin && p.status().connected)
    );
    // The peer that handed the space over is no hint of it.
    let known = space.known_peers().await.unwrap();
    assert_eq!(known, std::slice::from_ref(&peer.origin));
    alice.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_kept_hints_survive_a_restart_and_the_device_follows_them() {
    let dir = std::env::temp_dir().join(format!(
        "frasil-moved-{}",
        frasil_testkit::hex::encode(*frasil_crypto::random_bytes::<6>().unwrap())
    ));
    let peer = spawn_loopback().await.unwrap();
    let id = {
        let alice = device(Storage::directory(&dir), 2).await;
        let space = alice.create_space().await.unwrap();
        synced_once(&alice, &peer, &space).await;
        alice.close().await.unwrap();
        space.id()
    };

    // Opened again from its directory, the device still knows the peer,
    // and follows the space there when another answers `moved`.
    let alice = device(Storage::directory(&dir), 2).await;
    let space = alice.space(id).await.unwrap();
    assert_eq!(
        space.known_peers().await.unwrap(),
        std::slice::from_ref(&peer.origin)
    );
    let moving = MovingPeer::start([EventId(*id.as_bytes())].into()).await;
    alice.connect(&moving.origin).await.unwrap();
    durable_write(&space, "after a restart").await;
    alice.close().await.unwrap();
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_no_known_peer_hosts_is_reported_moved() {
    let alice = device(Storage::Memory, 3).await;
    let space = alice.create_space().await.unwrap();
    let mut events = alice.events();
    let moving = MovingPeer::start([EventId(*space.id().as_bytes())].into()).await;
    alice.connect(&moving.origin).await.unwrap();
    let reported = within(async {
        loop {
            if let Some(Event::Moved { space }) = events.next().await {
                break space;
            }
        }
    })
    .await;
    assert_eq!(reported, space.id());
    // Reported once: the device does not keep asking the same peers, and
    // tells the application no more.
    let presents = moving.presents(&space);
    let again = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if let Some(Event::Moved { .. }) = events.next().await {
                return;
            }
        }
    })
    .await;
    assert!(again.is_err(), "Event::Moved is not emitted again");
    assert_eq!(moving.presents(&space), presents);
    alice.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_welcome_names_the_peers_the_approver_knows_and_the_newcomer_keeps_them() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(Storage::Memory, 4).await;
    let bob = device(Storage::Memory, 5).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    until(|| async { space.known_peers().await.unwrap().contains(&peer.origin) }).await;
    #[cfg(feature = "ext-libraries")]
    let home = {
        let home = "https://home.example".to_owned();
        space.set_home_peer(&home).await.unwrap();
        home
    };
    let invitation = space
        .invite(frasil::Level::Write, "Alice", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    let expected = space.known_peers().await.unwrap();
    #[cfg(feature = "ext-libraries")]
    assert_eq!(expected, [home, peer.origin.clone()]);
    #[cfg(not(feature = "ext-libraries"))]
    assert_eq!(expected, std::slice::from_ref(&peer.origin));
    assert_eq!(bobs_space.known_peers().await.unwrap(), expected);
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_home_peer_is_tried_first_then_the_hints() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(Storage::Memory, 6).await;
    let space = alice.create_space().await.unwrap();
    synced_once(&alice, &peer, &space).await;
    let id = EventId(*space.id().as_bytes());
    // The home peer the issuer named has handed the space over too.
    let home = MovingPeer::start([id].into()).await;
    space.set_home_peer(&home.origin).await.unwrap();
    assert_eq!(
        space.known_peers().await.unwrap(),
        [home.origin.clone(), peer.origin.clone()]
    );
    let moving = MovingPeer::start([id].into()).await;
    alice.connect(&moving.origin).await.unwrap();
    durable_write(&space, "after the move").await;
    assert!(home.presents(&space) >= 1, "the home peer was tried");
    // The home peer that answered `moved` is no home peer any more, and
    // comes last, after the hint that hosts the space.
    until(|| async {
        space.known_peers().await.unwrap() == [peer.origin.clone(), home.origin.clone()]
    })
    .await;
    assert!(
        space
            .set_home_peer("https://peer.example/path")
            .await
            .is_err(),
        "an origin's URL only"
    );
    alice.close().await.unwrap();
    peer.shutdown().await;
}

/// Opened again with no connection, a device given its space's home peer
/// syncs there at once.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_restart_the_home_peer_named_is_synced_with() {
    let dir = std::env::temp_dir().join(format!(
        "frasil-moved-home-{}",
        frasil_testkit::hex::encode(*frasil_crypto::random_bytes::<6>().unwrap())
    ));
    let peer = spawn_loopback().await.unwrap();
    let id = {
        let alice = device(Storage::directory(&dir), 7).await;
        let space = alice.create_space().await.unwrap();
        synced_once(&alice, &peer, &space).await;
        alice.close().await.unwrap();
        space.id()
    };
    let alice = device(Storage::directory(&dir), 7).await;
    let space = alice.space(id).await.unwrap();
    space.set_home_peer(&peer.origin).await.unwrap();
    durable_write(&space, "at the home peer").await;
    assert!(
        alice.peers().is_empty(),
        "the application opened no connection"
    );
    alice.close().await.unwrap();
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A home peer that does not host the space yet, as while the space is
/// handed over to it, is asked again on a fresh connection a little later,
/// and the device syncs there once it does. It never creates the space
/// there meanwhile, and reports no move.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_home_peer_that_does_not_host_the_space_yet_is_asked_again() {
    let later = spawn_loopback().await.unwrap();
    let alice = device(Storage::Memory, 8).await;
    let bob = device(Storage::Memory, 9).await;
    let space = alice.create_space().await.unwrap();
    let invitation = space
        .invite(frasil::Level::Write, "Alice", |_, _| async { true })
        .await
        .unwrap();
    within(bob.join(invitation.text(), "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    let mut events = alice.events();
    // Alice is told the space's home: it answers `no_library`.
    space.set_home_peer(&later.origin).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !later.peer.hosts(space.id().as_bytes()),
        "the device never creates the space at a peer it looks for it at"
    );
    // The space arrives there through another member; Alice finds it.
    bob.connect(&later.origin).await.unwrap();
    until(|| async { later.peer.hosts(space.id().as_bytes()) }).await;
    durable_write(&space, "at the peer that took the space").await;
    assert!(alice.peers().is_empty());
    let reported = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if let Some(Event::Moved { .. }) = events.next().await {
                return;
            }
        }
    })
    .await;
    assert!(reported.is_err(), "no move is reported");
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    later.shutdown().await;
}

/// A TCP gate in front of a peer, at an origin of its own: open, it passes
/// every byte both ways; shut, it drops each connection as it comes, as a
/// peer that cannot be reached. The peer takes the origin from the `Host`
/// header, so the device knows the peer by the gate's origin.
struct Gate {
    origin: String,
    open: Arc<AtomicBool>,
    refused: Arc<AtomicUsize>,
}

impl Gate {
    async fn start(peer: &TestPeer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (open, refused) = (
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicUsize::new(0)),
        );
        let (opened, dropped, upstream) = (open.clone(), refused.clone(), peer.http);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                if !opened.load(Ordering::SeqCst) {
                    dropped.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                tokio::spawn(async move {
                    let Ok(mut server) = tokio::net::TcpStream::connect(upstream).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        });
        Self {
            origin,
            open,
            refused,
        }
    }
}

/// The only peer that hosts the space cannot be reached through every
/// round the device looks for it after a `moved`; once it can, the device
/// finds it there by itself, with no other `moved` and no home peer named.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hint_unreachable_through_the_rounds_is_looked_for_again() {
    let peer = spawn_loopback().await.unwrap();
    let gate = Gate::start(&peer).await;
    let alice = device(Storage::Memory, 10).await;
    let space = alice.create_space().await.unwrap();
    let link = alice.connect(&gate.origin).await.unwrap();
    until(|| async { synced_at(&alice, &gate.origin, &space) }).await;
    until(|| async { space.known_peers().await.unwrap().contains(&gate.origin) }).await;
    link.close();
    until(|| async { !synced_at(&alice, &gate.origin, &space) }).await;
    gate.open.store(false, Ordering::SeqCst);

    let moving = MovingPeer::start([EventId(*space.id().as_bytes())].into()).await;
    alice.connect(&moving.origin).await.unwrap();
    // The first look and its four rounds, 15 seconds of waits, all fail
    // to reach the hint.
    until(|| async { gate.refused.load(Ordering::SeqCst) >= 1 }).await;
    tokio::time::sleep(Duration::from_secs(17)).await;
    let presents = moving.presents(&space);
    gate.open.store(true, Ordering::SeqCst);
    durable_write(&space, "found again").await;
    // The peer that answered `moved` on the application's connection was
    // not asked again on connections of the device's own.
    assert_eq!(moving.presents(&space), presents);
    alice.close().await.unwrap();
    peer.shutdown().await;
}
