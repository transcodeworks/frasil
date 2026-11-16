//! A device collects its own device mailbox on a connection of its own
//! that presents nothing else (transport.md, 3.12 What a peer learns of a
//! device), against a peer this test stands in for: each connection the
//! device opens is a socket whose other end answers as a peer would, and
//! records what it was sent. The device runs no background upkeep here;
//! each test runs the mailbox upkeep itself.
//!
//! What a live `frasil-relay` records of the same connections is
//! `tests/conformance`'s (`client_collecting`).

use frasil::advanced::peer::socket::{ServerSocket, bare_socket, connect_socket};
use frasil::advanced::peer::{Bare, PeerHandle};
use frasil::advanced::{Connect, Engine, ManualClock, Tasks};
use frasil::{Device, Options, Storage};
use frasil_base::cbor;
use frasil_store::BoxFuture;
use frasil_transport::codes::Service;
use frasil_transport::mailbox::MailboxItems;
use frasil_transport::peer::{Limits, PeerHello};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const PEER: &str = "https://peer.example";

/// `Hello`, `Present`, `MailboxGet`.
const HELLO: u64 = 17;
const PRESENT: u64 = 18;
const MAILBOX_GET: u64 = 25;

/// What one connection carried from the device.
#[derive(Debug, Clone, Default)]
struct Connection {
    /// Whether the device opened it as its space connection.
    space: bool,
    /// Each message's type, in order.
    kinds: Vec<u64>,
    /// The `Hello`'s purpose.
    purpose: Option<u64>,
    /// Each `MailboxGet` that carried a collector's `ed || kc`: its
    /// `after`.
    collected: Vec<Option<Vec<u8>>>,
}

/// The peer this test stands in for.
#[derive(Default)]
struct FakePeer {
    /// Every connection, in order.
    connections: Mutex<Vec<Connection>>,
    /// Each connection's way to the device, until the peer closes it.
    to_device: Mutex<Vec<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
    /// The device's mailbox: each item's ID and bytes.
    mailbox: Mutex<Vec<([u8; 16], Vec<u8>)>>,
}

impl FakePeer {
    fn connections(&self) -> Vec<Connection> {
        self.connections.lock().unwrap().clone()
    }

    /// Deposits an item in the device's mailbox.
    fn deposit(&self, item: &[u8]) {
        let mut mailbox = self.mailbox.lock().unwrap();
        let mut id = [0; 16];
        id[15] = u8::try_from(mailbox.len() + 1).unwrap();
        mailbox.push((id, item.to_vec()));
    }

    /// Closes connection `at` from the peer's side.
    fn close(&self, at: usize) {
        self.to_device.lock().unwrap()[at] = None;
    }

    /// Takes one message on connection `at`, and answers a collection.
    fn take(&self, at: usize, message: &[u8]) {
        let Ok(value) = cbor::decode(message) else {
            return;
        };
        let Ok(map) = value.as_map() else {
            return;
        };
        let Some(kind) = map.get(&0).and_then(|v| v.as_unsigned().ok()) else {
            return;
        };
        let request = map.get(&1).and_then(|v| v.as_unsigned().ok());
        let after = map
            .get(&3)
            .and_then(|v| v.as_bytes().ok())
            .map(<[u8]>::to_vec);
        let collects = kind == MAILBOX_GET && map.get(&4).is_some();
        {
            let mut connections = self.connections.lock().unwrap();
            let connection = &mut connections[at];
            connection.kinds.push(kind);
            if kind == HELLO {
                connection.purpose = map.get(&3).and_then(|v| v.as_unsigned().ok());
            }
            if collects {
                connection.collected.push(after.clone());
            }
        }
        if !collects {
            return;
        }
        let items: Vec<([u8; 16], Vec<u8>)> = self
            .mailbox
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| after.as_deref().is_none_or(|after| id.as_slice() > after))
            .cloned()
            .collect();
        let answer = MailboxItems {
            request: request.unwrap_or_default(),
            items,
        }
        .encode();
        if let Some(Some(to_device)) = self.to_device.lock().unwrap().get(at) {
            let _ = to_device.send(answer);
        }
    }
}

/// One connection's socket, whose other end is the fake peer.
struct FakeSocket {
    peer: Arc<FakePeer>,
    at: usize,
    from_peer: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl FakeSocket {
    fn open(peer: &Arc<FakePeer>, space: bool) -> Arc<dyn ServerSocket> {
        let at = {
            let mut connections = peer.connections.lock().unwrap();
            connections.push(Connection {
                space,
                ..Connection::default()
            });
            connections.len() - 1
        };
        let (to_device, from_peer) = mpsc::unbounded_channel();
        let _ = to_device.send(PeerHello::encode(
            &[u8::try_from(at).unwrap(); 32],
            &[Service::Relay, Service::Store, Service::Mailbox],
            &Limits::PROTOCOL,
        ));
        peer.to_device.lock().unwrap().push(Some(to_device));
        Arc::new(Self {
            peer: peer.clone(),
            at,
            from_peer: tokio::sync::Mutex::new(from_peer),
        })
    }
}

impl ServerSocket for FakeSocket {
    fn send<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        self.peer.take(self.at, message);
        Box::pin(async { Ok(()) })
    }

    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async {
            self.from_peer
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| "closed".to_owned())
        })
    }

    fn close(&self) {}

    fn request<'a>(
        &'a self,
        _method: &'a str,
        _url: &'a str,
        _authorization: &'a str,
        _body: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Result<(u16, Vec<u8>), String>> {
        Box::pin(async { Err("no HTTP here".to_owned()) })
    }

    fn spawn(&self, task: BoxFuture<'static, ()>) {
        tokio::spawn(task);
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The application's connector: every connection reaches the fake peer.
struct FakeConnect(Arc<FakePeer>);

impl Connect for FakeConnect {
    fn connect(
        &self,
        engine: Engine,
        url: String,
        spaces: Vec<frasil_events::EventId>,
    ) -> BoxFuture<'static, frasil::Result<PeerHandle>> {
        let socket = FakeSocket::open(&self.0, true);
        Box::pin(async move { connect_socket(&engine, &url, socket, spaces).await })
    }

    fn bare(&self, engine: Engine, url: String) -> BoxFuture<'static, frasil::Result<Bare>> {
        let socket = FakeSocket::open(&self.0, false);
        Box::pin(async move { bare_socket(&engine, &url, socket).await })
    }
}

/// A device's tasks that run no background upkeep: the test runs it.
struct NoUpkeep;

impl Tasks for NoUpkeep {
    fn spawn(&self, task: BoxFuture<'static, ()>) {
        drop(task);
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// A device connected to the fake peer, with a space it presents there.
async fn connected(peer: &Arc<FakePeer>) -> Device {
    let options = Options::new()
        .never_restored()
        .clock(Arc::new(ManualClock::new(1_000, Some(1_800_000_000))))
        .tasks(Arc::new(NoUpkeep))
        .connect_with(Arc::new(FakeConnect(peer.clone())));
    let device = Device::open_with(Storage::Memory, &[7; 32], options)
        .await
        .unwrap();
    device.create_space().await.unwrap();
    let connection = device.connect(PEER).await.unwrap();
    assert!(connection.status().connected);
    device
}

/// Waits until the device's connection has sent what the peer records, so
/// that a test reads the space connection's messages once they are sent.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// transport.md, 3.12: the collection goes on a connection of the
/// device's own that carries its `Hello` and collections alone; the
/// connection that presents the device's spaces carries no collection.
#[tokio::test]
async fn the_collecting_connection_shows_no_credential() {
    let peer = Arc::new(FakePeer::default());
    let device = connected(&peer).await;
    peer.deposit(b"an item");
    device.mailbox_upkeep().await;
    settle().await;
    let connections = peer.connections();
    assert_eq!(connections.len(), 2, "{connections:?}");
    let (space, collecting) = (&connections[0], &connections[1]);
    assert!(space.space && !collecting.space);
    assert!(space.kinds.contains(&PRESENT), "{space:?}");
    assert!(space.collected.is_empty(), "{space:?}");
    assert!(!space.kinds.contains(&MAILBOX_GET), "{space:?}");
    assert_eq!(collecting.kinds, [HELLO, MAILBOX_GET]);
    assert_eq!(collecting.purpose, Some(1));
    assert_eq!(collecting.collected, [None]);
    device.close().await.unwrap();
}

/// One collecting connection per peer carries every collection: the
/// next upkeep's goes on it, after the last item collected, and an empty
/// mailbox is collected as well, since a collection claims the mailbox
/// (transport.md, "Claimed device mailboxes").
#[tokio::test]
async fn the_collecting_connection_is_kept_across_upkeeps() {
    let peer = Arc::new(FakePeer::default());
    let device = connected(&peer).await;
    device.mailbox_upkeep().await;
    peer.deposit(b"an item");
    device.mailbox_upkeep().await;
    device.mailbox_upkeep().await;
    settle().await;
    let connections = peer.connections();
    assert_eq!(connections.len(), 2, "{connections:?}");
    let collecting = &connections[1];
    assert_eq!(
        collecting.kinds,
        [HELLO, MAILBOX_GET, MAILBOX_GET, MAILBOX_GET]
    );
    let mut last = [0; 16];
    last[15] = 1;
    assert_eq!(
        collecting.collected,
        [None, None, Some(last.to_vec())],
        "the empty mailbox, then the item, then after it"
    );
    assert_eq!(device.collecting_opened(PEER).await, 1);
    assert!(connections[0].collected.is_empty());
    device.close().await.unwrap();
}

/// A collecting connection the peer closes is opened again, fresh, at the
/// next collection, which goes on the new one.
#[tokio::test]
async fn the_collecting_connection_is_opened_again_after_a_drop() {
    let peer = Arc::new(FakePeer::default());
    let device = connected(&peer).await;
    device.mailbox_upkeep().await;
    assert_eq!(peer.connections().len(), 2);
    peer.close(1);
    settle().await;
    peer.deposit(b"an item");
    device.mailbox_upkeep().await;
    settle().await;
    let connections = peer.connections();
    assert_eq!(connections.len(), 3, "{connections:?}");
    assert_eq!(connections[1].kinds, [HELLO, MAILBOX_GET]);
    assert_eq!(connections[2].kinds, [HELLO, MAILBOX_GET]);
    assert!(!connections[2].space);
    assert_eq!(device.collecting_opened(PEER).await, 2);
    // The item came on the new connection: the next collection goes on
    // after it.
    device.mailbox_upkeep().await;
    settle().await;
    let mut last = [0; 16];
    last[15] = 1;
    assert_eq!(peer.connections()[2].collected, [None, Some(last.to_vec())]);
    assert!(
        peer.connections()
            .iter()
            .all(|c| c.space || !c.kinds.contains(&PRESENT))
    );
    device.close().await.unwrap();
}
