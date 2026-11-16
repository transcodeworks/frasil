//! A peer's `reconnect` close and its `moved` refusal, at the device
//! (transport.md, "Reconnecting elsewhere"; peers.md, "Refusal codes").
//!
//! The device reaches the peer on loopback through a TCP front that passes
//! every byte both ways and, on demand, closes a WebSocket with 4017
//! between two of the peer's frames, as a peer that moves its load would;
//! a stopping peer closes every connection so, on both bindings. `moved`
//! comes from a peer that answers every present of one space with it.
//! Every wait has a deadline, and nothing leaves the host.

use frasil::advanced::peer::{
    PeerHandle, connect_iroh, connect_iroh_origin, connect_server, discovery_endpoints,
};
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Device, Options};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_relay::testing::TestPeer;
use frasil_space::{HistoryMode, Level, Via};
use frasil_transport::codes::Right;
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Long enough for two waits of `reconnect_wait` and its double, 15
/// seconds at most, and the connections.
const DEADLINE: Duration = Duration::from_secs(45);

/// `reconnect`'s WebSocket close code.
const RECONNECT: u16 = 4017;

/// A WebSocket close frame from the server, unmasked, with this code.
fn close_frame(code: u16) -> [u8; 4] {
    let [high, low] = code.to_be_bytes();
    [0x88, 0x02, high, low]
}

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
            tokio::time::sleep(Duration::from_millis(20)).await;
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

/// Waits until the peer has acknowledged every event the device signed in
/// the space.
async fn durable(device: &Engine, space: &EventId) {
    until(|| async { device.outbox(space).await.is_empty() }).await;
}

/// A space of Alice's with Bob granted "with history", carried by hand.
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

fn granted(link: &PeerHandle, space: &EventId) -> bool {
    link.status()
        .granted
        .get(space)
        .is_some_and(|rights| rights.contains(&Right::Store))
}

/// A message of the device after which, or in place of which, the front
/// closes the WebSocket with `reconnect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// After an `Events` sync message reaches the peer, before the peer's
    /// answer reaches the device.
    AfterEvents,
    /// In place of a `LibraryAttach`, which never reaches the peer.
    #[cfg_attr(not(feature = "ext-libraries"), allow(dead_code))]
    InsteadOfLibraryAttach,
}

/// What the front does to the WebSockets through it.
#[derive(Default)]
struct FrontState {
    /// A WebSocket open now, or one that has ended, by its closer.
    open: Mutex<Vec<watch::Sender<bool>>>,
    /// How many of the next WebSockets close just after the peer's first
    /// frame, its `PeerHello`.
    early: AtomicUsize,
    /// The close code they close with, or 0 for none.
    early_code: AtomicU16,
    /// The next message of the device to close a WebSocket at.
    trigger: Mutex<Option<Trigger>>,
    /// How many `Events` sync messages devices sent through the front.
    events: AtomicUsize,
    /// When each WebSocket opened, in order.
    opened: Mutex<Vec<Instant>>,
    /// How many WebSockets carried a `Present`: the device's own
    /// connections to the space, not a fresh one that collects its mailbox
    /// and presents nothing (transport.md, 3.12).
    presenting: AtomicUsize,
}

/// A TCP front of a peer on loopback, at an origin of its own: the peer
/// takes the origin from the `Host` header the device sends, so the
/// connection's channel is the front's.
struct Front {
    origin: String,
    state: Arc<FrontState>,
}

impl Front {
    async fn start(peer: &TestPeer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(FrontState::default());
        let upstream = peer.http;
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(pass(client, upstream, shared.clone()));
            }
        });
        Self { origin, state }
    }

    /// Closes every open WebSocket with `reconnect`.
    fn reconnect_all(&self) {
        let open = std::mem::take(&mut *lock(&self.state.open));
        for closer in open {
            let _ = closer.send(true);
        }
    }

    /// Closes the next `count` WebSockets before the peer sends anything
    /// but its `PeerHello`: with this close code, or, without one, by
    /// dropping the connection, as a stopping peer does.
    fn close_early(&self, count: usize, code: Option<u16>) {
        self.state
            .early_code
            .store(code.unwrap_or(0), Ordering::SeqCst);
        self.state.early.store(count, Ordering::SeqCst);
    }

    /// Closes the WebSocket that carries the next such message.
    fn close_at(&self, trigger: Trigger) {
        *lock(&self.state.trigger) = Some(trigger);
    }

    fn events(&self) -> usize {
        self.state.events.load(Ordering::SeqCst)
    }

    fn opened(&self) -> Vec<Instant> {
        lock(&self.state.opened).clone()
    }

    /// How many WebSockets carried a `Present`.
    fn presenting(&self) -> usize {
        self.state.presenting.load(Ordering::SeqCst)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The length of the whole WebSocket frame at the start of `bytes`, once
/// it has all arrived (RFC 6455, section 5.2).
fn frame_length(bytes: &[u8]) -> Option<usize> {
    let second = *bytes.get(1)?;
    let (length, mut header) = match second & 0x7f {
        126 => (
            usize::from(u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?)),
            4,
        ),
        127 => (
            usize::try_from(u64::from_be_bytes(bytes.get(2..10)?.try_into().ok()?)).ok()?,
            10,
        ),
        short => (usize::from(short), 2),
    };
    if second & 0x80 != 0 {
        header += 4;
    }
    let total = header + length;
    (bytes.len() >= total).then_some(total)
}

/// The device's message in one whole client frame: binary, masked.
fn device_message(frame: &[u8]) -> Option<frasil_transport::frame::Message> {
    use frasil_transport::frame::{ConnectionKind, Extensions, MessageType, StreamClass};
    if frame.first()? & 0x0f != 2 {
        return None;
    }
    let second = *frame.get(1)?;
    let at = match second & 0x7f {
        126 => 4,
        127 => 10,
        _ => 2,
    };
    let mask: [u8; 4] = frame.get(at..at + 4)?.try_into().ok()?;
    let payload: Vec<u8> = frame
        .get(at + 4..)?
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ mask[i % 4])
        .collect();
    let kind = frasil_base::cbor::decode(&payload)
        .ok()?
        .as_map()
        .ok()?
        .get(&0)?
        .as_unsigned()
        .ok()
        .and_then(MessageType::from_code)?;
    let class = match kind {
        MessageType::Sync | MessageType::Open | MessageType::AdapterSync => StreamClass::Sync,
        MessageType::Ephemeral => StreamClass::Ephemeral,
        _ => StreamClass::Control,
    };
    frasil_transport::frame::read_message(
        &payload,
        class,
        ConnectionKind::DeviceToPeer,
        Extensions {
            libraries: true,
            invite_links: true,
            ..Extensions::NONE
        },
    )
    .ok()
    .flatten()
}

/// Whether a device's message is an `Events` sync message.
fn carries_events(message: &frasil_transport::frame::Message) -> bool {
    use frasil_transport::frame::{ConnectionKind, MessageType};
    use frasil_units::messages::{Message as UnitMessage, Received, SyncMessage};
    if message.kind != MessageType::Sync {
        return false;
    }
    let Ok(sync) = frasil_transport::messages::Sync::read(message, ConnectionKind::DeviceToPeer)
    else {
        return false;
    };
    matches!(
        SyncMessage::read(&sync.message),
        Ok(Received::Message(SyncMessage {
            message: UnitMessage::Events { .. },
            ..
        }))
    )
}

/// The device's bytes of one TCP connection, to the peer: its request
/// head, then, on the connect route, its frames whole, each looked at for
/// a trigger.
async fn pass_up(
    mut from_client: tokio::net::tcp::OwnedReadHalf,
    mut to_server: tokio::net::tcp::OwnedWriteHalf,
    state: Arc<FrontState>,
    stop: Arc<AtomicBool>,
    closer: watch::Sender<bool>,
) {
    use frasil_transport::frame::MessageType;
    let mut pending = Vec::new();
    let head = loop {
        if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match from_client.read_buf(&mut pending).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    };
    let connect = pending.starts_with(b"GET /frasil/p1/connect");
    if !connect {
        let _ = to_server.write_all(&pending).await;
        let _ = tokio::io::copy(&mut from_client, &mut to_server).await;
        let _ = to_server.shutdown().await;
        return;
    }
    if to_server.write_all(&pending[..head]).await.is_err() {
        return;
    }
    pending.drain(..head);
    let mut presented = false;
    loop {
        while let Some(length) = frame_length(&pending) {
            let frame: Vec<u8> = pending.drain(..length).collect();
            let message = device_message(&frame);
            if !presented
                && message
                    .as_ref()
                    .is_some_and(|m| m.kind == MessageType::Present)
            {
                presented = true;
                state.presenting.fetch_add(1, Ordering::SeqCst);
            }
            let events = message.as_ref().is_some_and(carries_events);
            if events {
                state.events.fetch_add(1, Ordering::SeqCst);
            }
            let fired = {
                let mut trigger = lock(&state.trigger);
                let fired = match *trigger {
                    Some(Trigger::AfterEvents) => events.then_some(true),
                    Some(Trigger::InsteadOfLibraryAttach) => message
                        .as_ref()
                        .is_some_and(|m| m.kind == MessageType::LibraryAttach)
                        .then_some(false),
                    None => None,
                };
                if fired.is_some() {
                    *trigger = None;
                    // Nothing the peer sends from now on reaches the device.
                    stop.store(true, Ordering::SeqCst);
                }
                fired
            };
            if fired != Some(false) && to_server.write_all(&frame).await.is_err() {
                return;
            }
            if fired.is_some() {
                let _ = closer.send(true);
                return;
            }
        }
        match from_client.read_buf(&mut pending).await {
            Ok(0) | Err(_) => {
                let _ = to_server.shutdown().await;
                return;
            }
            Ok(_) => {}
        }
    }
}

/// One TCP connection through the front: the device's bytes up as
/// [`pass_up`] sends them; the peer's response head, then, for a
/// WebSocket, its frames whole.
async fn pass(client: TcpStream, upstream: SocketAddr, state: Arc<FrontState>) {
    let Ok(server) = TcpStream::connect(upstream).await else {
        return;
    };
    let (from_client, mut to_client) = client.into_split();
    let (mut from_server, to_server) = server.into_split();
    let (closer, mut close) = watch::channel(false);
    let stop = Arc::new(AtomicBool::new(false));
    let up = tokio::spawn(pass_up(
        from_client,
        to_server,
        state.clone(),
        stop.clone(),
        closer.clone(),
    ));
    let mut pending = Vec::new();
    let head = loop {
        if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match from_server.read_buf(&mut pending).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    };
    if to_client.write_all(&pending[..head]).await.is_err() {
        return;
    }
    let upgraded = pending.starts_with(b"HTTP/1.1 101");
    pending.drain(..head);
    if !upgraded {
        let _ = to_client.write_all(&pending).await;
        let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
        return;
    }
    let early = state
        .early
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok();
    let code = if early {
        state.early_code.load(Ordering::SeqCst)
    } else {
        RECONNECT
    };
    lock(&state.open).push(closer);
    lock(&state.opened).push(Instant::now());
    let mut frames = 0;
    'frames: loop {
        while let Some(length) = frame_length(&pending) {
            if stop.load(Ordering::SeqCst) || *close.borrow() {
                break 'frames;
            }
            if to_client.write_all(&pending[..length]).await.is_err() {
                return;
            }
            pending.drain(..length);
            frames += 1;
            if early && frames == 1 {
                break 'frames;
            }
        }
        tokio::select! {
            read = from_server.read_buf(&mut pending) => match read {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            },
            _ = close.changed() => break 'frames,
        }
    }
    if code != 0 {
        let _ = to_client.write_all(&close_frame(code)).await;
    }
    let _ = to_client.shutdown().await;
    up.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_keeps_syncing_across_a_reconnect_close() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let (alice, bob, space) = two_members().await;
    let alice = Device::from_engine(alice, Options::new()).unwrap();
    let link = alice.connect(&front.origin).await.unwrap();
    let bob_link = connect_server(&bob, &peer.origin, vec![space])
        .await
        .unwrap();
    let doc = alice.engine().new_document().unwrap();
    alice
        .engine()
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "before").unwrap();
        })
        .await
        .unwrap();
    until(|| async { text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("before") })
        .await;

    // The peer asks the device to connect again: the same `Peer` goes on.
    front.reconnect_all();
    until(|| async {
        let status = link.status();
        assert!(status.closed.is_none(), "{status:?}");
        status.reconnects == 1 && status.connected && !status.spaces.is_empty()
    })
    .await;
    alice
        .engine()
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "after, ").unwrap();
        })
        .await
        .unwrap();
    until(|| async {
        text_of(&bob, &space, &doc.stream()).await.as_deref() == Some("after, before")
    })
    .await;
    durable(alice.engine(), &space).await;
    let status = link.status();
    assert!(status.connected && !status.reconnecting && status.closed.is_none());
    assert!(status.refused.is_empty(), "{status:?}");
    // The first connection and the one after the reconnect; the device may
    // also have collected its own mailbox on fresh connections of its own.
    assert_eq!(front.presenting(), 2);
    link.close();
    bob_link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_close_before_any_grant_counts_as_a_failed_attempt() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "kept").unwrap();
        })
        .await
        .unwrap();
    let link = connect_server(&alice, &front.origin, vec![space])
        .await
        .unwrap();
    durable(&alice, &space).await;

    // The connection that the peer closes had its grant: the first wait is
    // drawn under `reconnect_wait`. The next connection closes before any
    // grant, so it counts as a failed attempt and the bound doubles.
    front.close_early(1, Some(RECONNECT));
    let closed_at = Instant::now();
    front.reconnect_all();
    until(|| async {
        let status = link.status();
        assert!(status.closed.is_none(), "{status:?}");
        status.reconnect_attempts == 2 && !status.reconnecting && granted(&link, &space)
    })
    .await;
    let status = link.status();
    let (bound, wait) = status.reconnect_wait.expect("a wait was drawn");
    assert_eq!(bound, Duration::from_secs(10));
    assert!(wait <= bound);
    let opened = front.opened();
    assert_eq!(opened.len(), 3, "the first, the one closed early, the last");
    let slack = Duration::from_secs(2);
    assert!(opened[1].duration_since(closed_at) <= Duration::from_secs(5) + slack);
    let second = opened[2].duration_since(opened[1]);
    assert!(second >= wait && second <= bound + slack, "{second:?}");

    // The connection goes on: a new edit becomes durable.
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(4, " on").unwrap();
        })
        .await
        .unwrap();
    durable(&alice, &space).await;
    assert!(link.status().refused.is_empty());
    link.close();
    peer.shutdown().await;
}

/// A transport opened again that the peer drops right after its
/// `PeerHello`, with no close code, is an attempt that failed too: the
/// device tries again under a doubled bound, and the connection goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_dropped_before_any_grant_after_a_reconnect_is_tried_again() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let link = connect_server(&alice, &front.origin, vec![space])
        .await
        .unwrap();
    until(|| async { granted(&link, &space) }).await;
    front.close_early(1, None);
    front.reconnect_all();
    until(|| async {
        let status = link.status();
        assert!(status.closed.is_none(), "{status:?}");
        status.reconnect_attempts == 2 && !status.reconnecting && granted(&link, &space)
    })
    .await;
    let (bound, _) = link.status().reconnect_wait.expect("a wait was drawn");
    assert_eq!(bound, Duration::from_secs(10));
    assert_eq!(front.opened().len(), 3);
    link.close();
    peer.shutdown().await;
}

/// A transport opened again after a `reconnect` close that the peer closes
/// with another code, here `unsupported_version` as a machine of another
/// release would, ends the connection with that reason: it is no failed
/// attempt, and the device does not connect again (transport.md,
/// "Reconnecting elsewhere").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_close_code_after_a_reconnect_ends_the_connection() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let link = connect_server(&alice, &front.origin, vec![space])
        .await
        .unwrap();
    until(|| async { granted(&link, &space) }).await;
    let unsupported = frasil_transport::Code::UnsupportedVersion.websocket();
    front.close_early(1, Some(unsupported));
    front.reconnect_all();
    until(|| async { link.status().closed.is_some() }).await;
    let status = link.status();
    let why = status.closed.clone().expect("closed");
    assert!(why.contains("unsupported_version"), "{why}");
    assert!(!status.reconnecting, "{status:?}");
    assert_eq!(status.reconnect_attempts, 1, "{status:?}");
    // No attempt follows within a whole `reconnect_wait`.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(front.opened().len(), 2, "the first and the one closed");
    assert_eq!(link.status().reconnect_attempts, 1);
    peer.shutdown().await;
}

/// A first connection the peer closes with `reconnect` before any grant
/// is followed as any other: the device connects again by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_connection_closed_with_reconnect_connects_again() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    front.close_early(1, Some(RECONNECT));
    let link = connect_server(&alice, &front.origin, vec![space])
        .await
        .expect("a reconnect close is no error");
    until(|| async {
        let status = link.status();
        assert!(status.closed.is_none(), "{status:?}");
        status.reconnects == 1 && !status.reconnecting && granted(&link, &space)
    })
    .await;
    assert_eq!(front.opened().len(), 2);
    link.close();
    peer.shutdown().await;
}

/// The peer stores an event and the connection closes before its
/// acknowledgement reaches the device: the event stays in the outbox, goes
/// again on the next transport, and the peer acknowledges the identical
/// retry, storing it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_whose_acknowledgement_was_lost_goes_again_and_is_stored_once() {
    let peer = spawn_loopback().await.unwrap();
    let front = Front::start(&peer).await;
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let doc = alice.new_document().unwrap();
    let link = connect_server(&alice, &front.origin, vec![space])
        .await
        .unwrap();
    until(|| async { granted(&link, &space) }).await;
    durable(&alice, &space).await;
    let before = peer.peer.usage(&space.0).expect("the peer hosts the space");
    let sent = front.events();
    front.close_at(Trigger::AfterEvents);
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "once").unwrap();
        })
        .await
        .unwrap();
    let pending = alice.outbox(&space).await;
    assert!(!pending.is_empty());
    // The peer stores it; the device never hears the answer.
    until(|| async { peer.peer.usage(&space.0).is_some_and(|used| used > before) }).await;
    let stored = peer.peer.usage(&space.0).unwrap();
    until(|| async { link.status().reconnects == 1 }).await;
    durable(&alice, &space).await;
    assert!(front.events() >= sent + 2, "the event went again");
    assert_eq!(peer.peer.usage(&space.0), Some(stored), "stored once");
    for event in &pending {
        assert!(peer.peer.keeps(&space.0, &event.0));
    }
    let status = link.status();
    assert!(status.refused_events.is_empty(), "{status:?}");
    assert!(status.closed.is_none());
    link.close();
    peer.shutdown().await;
}

/// A `LibraryAttach` lost with its transport goes again on the next one,
/// with its ticket, and the caller hears the peer's answer.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_library_attach_lost_at_a_reconnect_goes_again() {
    use frasil_libraries::{Issuer, LibraryId, Purpose, Ticket, TrustedIssuers};
    use frasil_relay::Clock;
    use frasil_relay::libraries::LibrarySettings;
    use frasil_relay::testing::{OPEN_LIBRARY, Options as PeerOptions, spawn_with};
    let issuer = Issuer::from_seed(&[7; 32]);
    let peer = spawn_with(PeerOptions {
        settings: frasil_relay::Settings {
            libraries: LibrarySettings {
                issuers: TrustedIssuers::new([*issuer.public()]).unwrap(),
                open_library: LibraryId::new(OPEN_LIBRARY).ok(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        },
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    let front = Front::start(&peer).await;
    let alice = Device::open_with(frasil::Storage::Memory, &[3; 32], Options::new().loopback())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    let link = alice.connect(&front.origin).await.unwrap();
    until(|| async { !link.status().spaces.is_empty() }).await;
    durable(alice.engine(), &id).await;
    let wall = peer.clock.now().wall.expect("the wall clock");
    let library = LibraryId::new("project:elsewhere").unwrap();
    let ticket = issuer.sign(&Ticket {
        library: library.clone(),
        id: [4; 16],
        purpose: Purpose::Move,
        not_after: wall + 3600,
        issuer: *issuer.public(),
        tokens: None,
    });
    front.close_at(Trigger::InsteadOfLibraryAttach);
    within(space.attach_library(&ticket))
        .await
        .expect("the peer accepts the ticket sent again");
    assert_eq!(link.status().reconnects, 1);
    let ledger = peer.peer.ledger(&library).expect("the library's ledger");
    assert!(ledger.spaces.iter().any(|row| row.space == id.0));
    alice.close().await.unwrap();
    peer.shutdown().await;
}

/// A connection the device closes while its `LibraryAttach` is under way
/// stays open until the peer has stored the genesis, so that the create
/// does not lapse with its ticket used: each new space is durable on
/// `wait_durable` alone, with no `flush`, while a fresh connection takes
/// the place of the last.
#[cfg(feature = "ext-libraries")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_library_attach_lost_with_a_closed_connection_goes_on_another() {
    use frasil_libraries::{Issuer, LibraryId, Purpose, Ticket, TrustedIssuers};
    use frasil_relay::Clock;
    use frasil_relay::libraries::LibrarySettings;
    use frasil_relay::testing::{Options as PeerOptions, spawn_with};
    // No open library: a space is hosted only once its ticket attached it.
    let issuer = Issuer::from_seed(&[7; 32]);
    let peer = spawn_with(PeerOptions {
        settings: frasil_relay::Settings {
            libraries: LibrarySettings {
                issuers: TrustedIssuers::new([*issuer.public()]).unwrap(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        },
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    let alice = Device::open_with(frasil::Storage::Memory, &[5; 32], Options::new().loopback())
        .await
        .unwrap();
    let wall = peer.clock.now().wall.expect("the wall clock");
    let library = LibraryId::new("project:sheets").unwrap();
    let mut link = alice.connect(&peer.origin).await.unwrap();
    for round in 1..=12u8 {
        let fresh = alice.connect(&peer.origin).await.unwrap();
        until(|| async { fresh.status().connected }).await;
        let space = alice.create_space().await.unwrap();
        let note = space.create_document().unwrap();
        note.edit(|doc| doc.get_text("body").insert(0, "Recovery sheet"))
            .await
            .unwrap();
        let ticket = issuer.sign(&Ticket {
            library: library.clone(),
            id: [round; 16],
            purpose: Purpose::Create,
            not_after: wall + 3600,
            issuer: *issuer.public(),
            tokens: None,
        });
        // The ticket goes to both connections, and the older one is
        // closed at once: when it took the ticket, the create is its own.
        let (attached, durable, ()) = tokio::join!(
            space.attach_library(&ticket),
            space.wait_durable(Duration::from_secs(15)),
            async { link.close() },
        );
        durable.unwrap_or_else(|error| panic!("round {round}: {error}"));
        attached.unwrap_or_else(|error| panic!("round {round}: {error}"));
        assert!(space.is_durable().await, "round {round}");
        link = fresh;
    }
    let ledger = peer.peer.ledger(&library).expect("the library's ledger");
    assert_eq!(ledger.spaces.len(), 12);
    alice.close().await.unwrap();
    peer.shutdown().await;
}

/// A peer that stops closes its connections with `reconnect`, on both
/// bindings, and those that arrive after its drain too: no error at the
/// device, which waits to connect again until it closes the connection
/// itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopping_peers_reconnect_is_no_error_on_either_binding() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let ws = connect_server(&alice, &peer.origin, vec![space])
        .await
        .unwrap();
    let info = peer.iroh.clone().expect("the peer listens on iroh");
    let iroh = connect_iroh(
        &alice,
        info.endpoint,
        &info.addresses,
        &[],
        frasil_iroh::Config::loopback,
        vec![space],
    )
    .await
    .unwrap();
    until(|| async { granted(&ws, &space) && granted(&iroh, &space) }).await;
    peer.peer.stop_connections(Duration::from_secs(5)).await;
    for link in [&ws, &iroh] {
        until(|| async {
            let status = link.status();
            assert!(status.closed.is_none(), "{status:?}");
            status.reconnecting && status.reconnect_wait.is_some()
        })
        .await;
    }
    // Each device's first attempt comes within `reconnect_wait`, five
    // seconds, to a peer past its drain: it is closed with `reconnect`
    // again, still no error.
    let watched = Instant::now();
    while watched.elapsed() < Duration::from_secs(6) {
        for link in [&ws, &iroh] {
            let status = link.status();
            assert!(status.closed.is_none(), "{status:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ws.close();
    iroh.close();
    for link in [&ws, &iroh] {
        until(|| async { link.status().closed.is_some() }).await;
        assert!(!link.status().reconnecting);
    }
    peer.shutdown().await;
}

/// A peer on two machines lists both endpoint keys in its discovery. When
/// the machine a device reached over iroh stops, closing with
/// `reconnect`, the device dials the other key, and keeps acknowledgements
/// under the origin throughout (transport.md, "Reconnecting elsewhere",
/// 3.12 "Whose acknowledgement").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_iroh_a_reconnect_dials_another_key_the_discovery_lists() {
    let first = spawn_loopback().await.unwrap();
    let second = spawn_loopback().await.unwrap();
    let (one, two) = (
        first.iroh.clone().expect("iroh"),
        second.iroh.clone().expect("iroh"),
    );
    // The discovery document names the machine's own key.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let url = format!("{}/.well-known/frasil", first.origin);
    let body = reqwest::get(url).await.unwrap().bytes().await.unwrap();
    assert_eq!(discovery_endpoints(&body), [one.endpoint]);
    let document = format!(
        r#"{{"iroh": {{"endpoint": "{}", "endpoints": ["{}", "{}"]}}}}"#,
        frasil_testkit::hex::encode(one.endpoint),
        frasil_testkit::hex::encode(two.endpoint),
        frasil_testkit::hex::encode(one.endpoint),
    );
    assert_eq!(
        discovery_endpoints(document.as_bytes()),
        [one.endpoint, two.endpoint]
    );

    let alice = device().await;
    let space = alice.create_space().await.unwrap();
    let link = connect_iroh_origin(
        &alice,
        &first.origin,
        &[
            (one.endpoint, one.addresses.clone()),
            (two.endpoint, two.addresses.clone()),
        ],
        &[],
        frasil_iroh::Config::loopback,
        vec![space],
    )
    .await
    .unwrap();
    let origin =
        frasil::advanced::Acknowledger::Peer(frasil_transport::peer::server_channel(&first.origin));
    assert_eq!(link.acknowledger(), origin);
    until(|| async { granted(&link, &space) }).await;
    assert!(first.peer.hosts(&space.0));
    first.peer.stop_connections(Duration::from_secs(5)).await;
    until(|| async {
        let status = link.status();
        assert!(status.closed.is_none(), "{status:?}");
        status.reconnects == 1 && !status.reconnecting && granted(&link, &space)
    })
    .await;
    assert!(second.peer.hosts(&space.0), "the other machine's key");
    durable(&alice, &space).await;
    assert_eq!(link.acknowledger(), origin);
    link.close();
    first.shutdown().await;
    second.shutdown().await;
}

/// The presents of one connection, by space.
type Presents = BTreeMap<[u8; 32], usize>;

/// A peer that answers each present of one space `moved`, and nothing
/// else, counting the presents of each space on each connection.
struct MovingPeer {
    origin: String,
    presents: Arc<Mutex<Vec<Presents>>>,
    closer: watch::Sender<bool>,
}

impl MovingPeer {
    async fn start(moved: EventId) -> Self {
        use frasil_transport::frame::{ConnectionKind, Extensions, MessageType, StreamClass};
        use frasil_transport::messages::Refused;
        use frasil_transport::peer::{Checked, Limits, PeerSide};
        use tokio_tungstenite::tungstenite::Message as WsMessage;
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let presents = Arc::new(Mutex::new(Vec::new()));
        let (closer, close) = watch::channel(false);
        let (counts, channel) = (
            presents.clone(),
            frasil_transport::peer::server_channel(&origin),
        );
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let counts = counts.clone();
                let mut close = close.clone();
                close.mark_unchanged();
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
                    // Only WebSockets count: another local process may
                    // probe the port with plain HTTP or TLS.
                    let connection = {
                        let mut counts = lock(&counts);
                        counts.push(BTreeMap::new());
                        counts.len() - 1
                    };
                    let (mut side, hello) =
                        PeerSide::start_with(channel, [9; 32], &[], &Limits::PROTOCOL);
                    if socket.send(WsMessage::Binary(hello.into())).await.is_err() {
                        return;
                    }
                    loop {
                        let item = tokio::select! {
                            item = socket.next() => item,
                            _ = close.changed() => {
                                use tokio_tungstenite::tungstenite::protocol::CloseFrame;
                                let frame = CloseFrame {
                                    code: 4017.into(),
                                    reason: "".into(),
                                };
                                let _ = socket.send(WsMessage::Close(Some(frame))).await;
                                return;
                            }
                        };
                        let Some(Ok(item)) = item else {
                            return;
                        };
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
                        *lock(&counts)[connection].entry(present.space).or_default() += 1;
                        if present.space == moved.0 {
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
        Self {
            origin,
            presents,
            closer,
        }
    }

    /// The presents of a space on the connection of this index.
    fn presents_on(&self, connection: usize, space: &EventId) -> usize {
        lock(&self.presents)
            .get(connection)
            .and_then(|counts| counts.get(&space.0).copied())
            .unwrap_or(0)
    }

    fn presents(&self, space: &EventId) -> usize {
        self.presents_on(0, space)
    }

    /// Closes every open connection with `reconnect`.
    fn reconnect_all(&self) {
        let _ = self.closer.send(true);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_refused_moved_shows_in_the_status_and_is_not_presented_again() {
    let alice = device().await;
    let moved = alice.create_space().await.unwrap();
    let kept = alice.create_space().await.unwrap();
    let peer = MovingPeer::start(moved).await;
    let link = connect_server(&alice, &peer.origin, vec![moved, kept])
        .await
        .unwrap();
    let code = "moved".to_owned();
    until(|| async { link.status().refused.contains(&(moved, code.clone())) }).await;
    until(|| async { peer.presents(&kept) >= 1 }).await;
    let presented = peer.presents(&moved);
    assert!(presented >= 1);

    // Neither a change of the space nor a present asked of the connection
    // presents it again.
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(moved, &doc, |d| {
            d.get_text("body").insert(0, "here").unwrap();
        })
        .await
        .unwrap();
    link.attach(moved);
    // The connection goes on: a space presented later is presented.
    let later = alice.create_space().await.unwrap();
    link.attach(later);
    until(|| async { peer.presents(&later) >= 1 }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(peer.presents(&moved), presented);
    let status = link.status();
    assert!(status.closed.is_none(), "{status:?}");
    assert_eq!(
        status
            .refused
            .iter()
            .filter(|(space, _)| *space == moved)
            .count(),
        1,
        "{status:?}"
    );

    // On the next transport, every space is presented again but that one.
    peer.reconnect_all();
    until(|| async { peer.presents_on(1, &kept) >= 1 && peer.presents_on(1, &later) >= 1 }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(peer.presents_on(1, &moved), 0);
    assert!(link.status().closed.is_none());
    link.close();
}
