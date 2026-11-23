//! Deposit tokens and kept deposits at a device, against a peer that this
//! test stands in for: each connection the device opens of its own is a
//! socket whose other end answers as a peer that implements
//! ext-deposit-tokens.md would, and records what it was sent.
//!
//! What a live `frasil-relay` does with the same messages is
//! `tests/conformance`'s.

use frasil::advanced::peer::socket::{ServerSocket, bare_socket};
use frasil::advanced::peer::{Bare, PeerHandle};
use frasil::advanced::{Connect, Engine, ManualClock};
use frasil::{Device, Event, MemberId, Options, Storage};
use frasil_base::cbor::{self, Value};
use frasil_deposit_tokens::messages::KeyEntry;
use frasil_deposit_tokens::{DepositKey, Role, Token, TokenIssue, TokenKeys, TokenRequest};
use frasil_store::BoxFuture;
use frasil_transport::codes::Service;
use frasil_transport::messages::{Accepted, Refused};
use frasil_transport::peer::{Limits, PeerHello};
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

const PEER: &str = "https://peer.example";
const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

/// What one connection carried from the device: each message's type, and
/// whether a `MailboxPut` carried a token.
#[derive(Debug, Clone, Default)]
struct Connection {
    kinds: Vec<u64>,
    purpose: Option<u64>,
    tokens: Vec<[u8; 129]>,
}

/// The peer this test stands in for.
#[derive(Default)]
struct FakePeer {
    /// Its live keys, issuing first.
    keys: Mutex<Vec<(DepositKey, Role)>>,
    /// Whether it lists service 6.
    no_service: Mutex<bool>,
    /// The next refusals of a `TokenRequest`.
    draw_refusals: Mutex<VecDeque<String>>,
    /// The next answers to a deposit: a refusal's code, or `None` to
    /// accept.
    deposit_answers: Mutex<VecDeque<Option<String>>>,
    /// Every connection, in order.
    connections: Mutex<Vec<Connection>>,
    /// The tokens spent, by nonce.
    spent: Mutex<BTreeSet<[u8; 32]>>,
    /// The items accepted.
    accepted: Mutex<Vec<Vec<u8>>>,
}

impl FakePeer {
    fn with_key(seed: u8) -> Arc<Self> {
        let peer = Self::default();
        peer.keys
            .lock()
            .unwrap()
            .push((DepositKey::from_seed(&[seed; 32]), Role::Issuing));
        Arc::new(peer)
    }

    fn set_keys(&self, keys: &[(u8, Role)]) {
        *self.keys.lock().unwrap() = keys
            .iter()
            .map(|(seed, role)| (DepositKey::from_seed(&[*seed; 32]), *role))
            .collect();
    }

    fn connections(&self) -> Vec<Connection> {
        self.connections.lock().unwrap().clone()
    }

    /// The peer's answer to one message on connection `at`.
    fn answer(&self, at: usize, message: &[u8]) -> Option<Vec<u8>> {
        let value = cbor::decode(message).ok()?;
        let map = value.as_map().ok()?;
        let kind = map.get(&0)?.as_unsigned().ok()?;
        let request = map.get(&1).and_then(|v| v.as_unsigned().ok());
        {
            let mut connections = self.connections.lock().unwrap();
            let connection = &mut connections[at];
            connection.kinds.push(kind);
            if kind == 17 {
                connection.purpose = map.get(&3).and_then(|v| v.as_unsigned().ok());
            }
            if kind == 24
                && let Some(Value::Bytes(token)) = map.get(&7)
            {
                connection.tokens.push(token.as_slice().try_into().unwrap());
            }
        }
        let request = request?;
        let refused = |code: &str| {
            Some(
                Refused {
                    request,
                    code: code.into(),
                }
                .encode(),
            )
        };
        match kind {
            40 => Some(
                TokenKeys {
                    request,
                    keys: self
                        .keys
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(key, role)| KeyEntry {
                            key_id: *key.id(),
                            public: *key.public(),
                            role: *role,
                        })
                        .collect(),
                }
                .encode(),
            ),
            42 => {
                if let Some(code) = self.draw_refusals.lock().unwrap().pop_front() {
                    return refused(&code);
                }
                let request_message = TokenRequest::decode(message).ok()?;
                let keys = self.keys.lock().unwrap();
                let (key, _) = keys.iter().find(|(_, role)| *role == Role::Issuing)?;
                if *key.id() != request_message.key_id {
                    return refused("token_expired");
                }
                let mut scalar = [0x11; 64];
                scalar[0] = at as u8;
                let scalar = frasil_deposit_tokens::suite::scalar_from_wide(&scalar)?;
                let (evaluated, proof) = key
                    .evaluate_batch_with(&request_message.blinded, &scalar)
                    .ok()?;
                Some(
                    TokenIssue {
                        request,
                        evaluated,
                        proof,
                    }
                    .encode(),
                )
            }
            24 => {
                if let Some(Some(code)) = self.deposit_answers.lock().unwrap().pop_front() {
                    return refused(&code);
                }
                if let Some(Value::Bytes(token)) = map.get(&7) {
                    let token = Token::from_bytes(token).ok()?;
                    let keys = self.keys.lock().unwrap();
                    let Some((key, _)) = keys.iter().find(|(key, _)| *key.id() == token.key_id())
                    else {
                        return refused("token_expired");
                    };
                    if !key.verify(&token.input(), token.authenticator()) {
                        return refused("token_refused");
                    }
                    self.spent.lock().unwrap().insert(token.nonce());
                }
                let item = map.get(&3)?.as_bytes().ok()?.to_vec();
                self.accepted.lock().unwrap().push(item);
                Some(Accepted { request }.encode())
            }
            _ => None,
        }
    }
}

/// One connection's socket, whose other end is the fake peer.
struct FakeSocket {
    peer: Arc<FakePeer>,
    at: usize,
    to_device: mpsc::UnboundedSender<Vec<u8>>,
    from_peer: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl FakeSocket {
    fn open(peer: &Arc<FakePeer>) -> Arc<dyn ServerSocket> {
        let at = {
            let mut connections = peer.connections.lock().unwrap();
            connections.push(Connection::default());
            connections.len() - 1
        };
        let (to_device, from_peer) = mpsc::unbounded_channel();
        let mut services = vec![Service::Mailbox];
        if !*peer.no_service.lock().unwrap() {
            services.push(Service::Deposit);
        }
        let _ = to_device.send(PeerHello::encode(
            &[at as u8; 32],
            &services,
            &Limits::PROTOCOL,
        ));
        Arc::new(Self {
            peer: peer.clone(),
            at,
            to_device,
            from_peer: tokio::sync::Mutex::new(from_peer),
        })
    }
}

impl ServerSocket for FakeSocket {
    fn send<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        if let Some(answer) = self.peer.answer(self.at, message) {
            let _ = self.to_device.send(answer);
        }
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
        _abort: &'a frasil::advanced::peer::socket::Cancel,
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

/// The application's connector: every connection of the device's own
/// reaches the fake peer; it opens no space-traffic connection.
struct FakeConnect(Arc<FakePeer>);

impl Connect for FakeConnect {
    fn connect(
        &self,
        _engine: Engine,
        _url: String,
        _spaces: Vec<frasil_events::EventId>,
    ) -> BoxFuture<'static, frasil::Result<PeerHandle>> {
        Box::pin(async { Err(frasil::Error::Unsupported("no space traffic here")) })
    }

    fn bare(&self, engine: Engine, url: String) -> BoxFuture<'static, frasil::Result<Bare>> {
        let socket = FakeSocket::open(&self.0);
        Box::pin(async move { bare_socket(&engine, &url, socket).await })
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("deposit-tokens-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn open(storage: Storage, peer: &Arc<FakePeer>, clock: &Arc<ManualClock>) -> Device {
    let options = Options::new()
        .never_restored()
        .clock(clock.clone())
        .connect_with(Arc::new(FakeConnect(peer.clone())));
    Device::open_with(storage, &[7; 32], options).await.unwrap()
}

/// The device deposits to itself: a recipient is any device ID.
fn recipient(device: &Device) -> MemberId {
    device.id()
}

/// Hands over a grant and lets an hour pass: the device draws a batch.
async fn draw_a_batch(device: &Device, clock: &ManualClock) {
    device.give_deposit_grant(PEER, b"a grant the issuer signed".to_vec());
    device.deposit_upkeep().await;
    assert_eq!(device.deposit_tokens(PEER).await.held, 0, "never at once");
    clock.advance(HOUR + 1);
    device.deposit_upkeep().await;
    // The device's own upkeep may have begun the draw, which this upkeep
    // then leaves to it: wait until it ends, with the batch kept or the
    // drawing paused.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let tokens = device.deposit_tokens(PEER).await;
            if tokens.held > 0 || tokens.paused {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the draw ends");
}

/// ext-deposit-tokens.md, 3.12: a grant draws one batch at a random moment
/// in the next hour, and 3.2 and 3.3: its keys come on a connection that
/// presents nothing else, and the draw on another.
#[tokio::test]
async fn a_grant_draws_a_batch_within_the_hour_on_connections_of_its_own() {
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    draw_a_batch(&device, &clock).await;
    let tokens = device.deposit_tokens(PEER).await;
    assert_eq!(tokens.held, 16);
    assert!(!tokens.grant, "a grant draws once");
    let connections = peer.connections();
    assert_eq!(connections.len(), 2);
    // Hello, then only TokenKeysGet; Hello, then only TokenRequest.
    assert_eq!(connections[0].kinds, [17, 40]);
    assert_eq!(connections[1].kinds, [17, 42]);
    assert!(connections.iter().all(|c| c.purpose == Some(1)));
    // At the low mark or above, nothing more is drawn; once an hour the
    // device asks the keys again, on a connection of their own.
    clock.advance(2 * HOUR);
    device.deposit_upkeep().await;
    let connections = peer.connections();
    assert_eq!(connections.len(), 3);
    assert_eq!(connections[2].kinds, [17, 40]);
}

/// ext-deposit-tokens.md, 3.6 and section 4: a deposit pays with a token
/// on a connection of its own that carries nothing but the `Hello` and the
/// deposit: no `Present`, no collection, no draw.
#[tokio::test]
async fn a_deposit_pays_with_a_token_on_a_connection_that_shows_nothing() {
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    draw_a_batch(&device, &clock).await;
    let before = peer.connections().len();
    device
        .deposit_item(PEER, recipient(&device), b"a sealed welcome".to_vec())
        .await
        .unwrap();
    let connections = peer.connections();
    let deposit = &connections[before];
    assert_eq!(deposit.kinds, [17, 24]);
    assert_eq!(deposit.purpose, Some(1));
    assert_eq!(deposit.tokens.len(), 1, "paid with a token");
    assert_eq!(peer.spent.lock().unwrap().len(), 1);
    assert_eq!(device.deposit_tokens(PEER).await.held, 15);
    assert_eq!(device.waiting_deposits().await, 0);
    // The draw's connections never carried a deposit, nor this one a draw.
    for connection in &connections[..before] {
        assert!(!connection.kinds.contains(&24));
    }
}

/// transport.md, "A sender keeps what was refused", and
/// ext-deposit-tokens.md, 3.5 and 3.6: a deposit answered `busy` is kept
/// at rest with the token it was sent with; after a restart it goes again
/// once its wait has passed, with the same token, and the tokens held
/// survive the restart.
#[tokio::test]
async fn a_busy_deposit_goes_again_after_a_restart_with_the_same_token() {
    let dir = temp_dir("busy");
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::directory(&dir), &peer, &clock).await;
    draw_a_batch(&device, &clock).await;
    peer.deposit_answers
        .lock()
        .unwrap()
        .push_back(Some("busy".into()));
    let mut events = device.events();
    let first = device
        .deposit_item(PEER, recipient(&device), b"a sealed welcome".to_vec())
        .await;
    assert!(matches!(first, Err(frasil::Error::Delayed(ref why)) if why == "busy"));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), events.next()).await,
        Ok(Some(Event::Delayed { ref reason, .. })) if reason == "busy"
    ));
    let sent = *peer.connections().last().unwrap().tokens.first().unwrap();
    assert_eq!(device.waiting_deposits().await, 1);
    assert_eq!(
        device.deposit_tokens(PEER).await.held,
        15,
        "the token is the deposit's"
    );
    device.close().await.unwrap();
    drop(device);

    let clock = Arc::new(ManualClock::new(5, Some(1_800_000_000 + 2 * HOUR)));
    let device = open(Storage::directory(&dir), &peer, &clock).await;
    assert_eq!(device.waiting_deposits().await, 1);
    assert_eq!(device.deposit_tokens(PEER).await.held, 15);
    clock.advance(61);
    device.deposit_upkeep().await;
    assert_eq!(device.waiting_deposits().await, 0);
    let again = peer
        .connections()
        .into_iter()
        .rev()
        .find(|c| c.kinds.contains(&24))
        .unwrap();
    assert_eq!(again.tokens, [sent], "the same item, the same token");
    assert_eq!(peer.accepted.lock().unwrap().len(), 1);
    assert_eq!(device.deposit_tokens(PEER).await.held, 15);
}

/// transport.md, "A sender keeps what was refused": with no token, a
/// deposit the peer cannot be reached for is kept, and its waits grow from
/// a minute.
#[tokio::test]
async fn a_deposit_without_a_token_is_kept_and_its_wait_grows() {
    let peer = FakePeer::with_key(1);
    *peer.no_service.lock().unwrap() = true;
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    for _ in 0..3 {
        peer.deposit_answers
            .lock()
            .unwrap()
            .push_back(Some("rate_limited".into()));
    }
    let first = device
        .deposit_item(PEER, recipient(&device), b"a list".to_vec())
        .await;
    assert!(matches!(first, Err(frasil::Error::Delayed(_))));
    let attempts = || {
        peer.connections()
            .iter()
            .filter(|c| c.kinds.contains(&24))
            .count()
    };
    assert_eq!(attempts(), 1);
    // The first wait is at most a minute; the second at most two.
    clock.advance(60);
    device.deposit_upkeep().await;
    assert_eq!(attempts(), 2);
    clock.advance(120);
    device.deposit_upkeep().await;
    assert_eq!(attempts(), 3);
    clock.advance(240);
    device.deposit_upkeep().await;
    assert_eq!(attempts(), 4);
    assert_eq!(device.waiting_deposits().await, 0);
    assert!(peer.connections().iter().all(|c| c.tokens.is_empty()));
}

/// ext-deposit-tokens.md, 3.11: a token refused drops that token, and the
/// item goes again at once, here with another token.
#[tokio::test]
async fn a_refused_token_is_dropped_and_the_item_goes_again() {
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    draw_a_batch(&device, &clock).await;
    peer.deposit_answers
        .lock()
        .unwrap()
        .push_back(Some("token_refused".into()));
    device
        .deposit_item(PEER, recipient(&device), b"a sealed welcome".to_vec())
        .await
        .unwrap();
    let deposits: Vec<_> = peer
        .connections()
        .into_iter()
        .filter(|c| c.kinds.contains(&24))
        .collect();
    assert_eq!(deposits.len(), 2);
    assert_ne!(deposits[0].tokens, deposits[1].tokens);
    assert_eq!(device.deposit_tokens(PEER).await.held, 14);
}

/// ext-deposit-tokens.md, 3.2: a key list whose issuing key is one the
/// device saw replaced stops drawing and spending there, drops the tokens,
/// and is reported, until the application trusts the peer again.
#[tokio::test]
async fn a_replaced_key_that_returns_stops_the_peer_until_trusted() {
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    draw_a_batch(&device, &clock).await;
    let mut events = device.events();
    // A rotation two days later: the older key's tokens still pay, and a
    // second grant draws under the new key.
    clock.advance(2 * DAY);
    peer.set_keys(&[(2, Role::Issuing), (1, Role::Accepting)]);
    for _ in 0..4 {
        device
            .deposit_item(PEER, recipient(&device), b"one".to_vec())
            .await
            .unwrap();
    }
    device.give_deposit_grant(PEER, b"a second grant".to_vec());
    device.deposit_upkeep().await;
    device.deposit_upkeep().await;
    clock.advance(HOUR + 1);
    device.deposit_upkeep().await;
    assert_eq!(device.deposit_tokens(PEER).await.held, 12 + 16);
    // Then the first key issuing again.
    peer.set_keys(&[(1, Role::Issuing)]);
    clock.advance(2 * HOUR);
    device.deposit_upkeep().await;
    let tokens = device.deposit_tokens(PEER).await;
    assert!(tokens.distrusted);
    assert_eq!(tokens.held, 0, "every token of the peer is dropped");
    let mut reported = false;
    while let Ok(Some(event)) =
        tokio::time::timeout(Duration::from_millis(200), events.next()).await
    {
        reported |= matches!(event, Event::DepositPeerDistrusted { ref reason, .. } if reason == "key_inconsistent");
    }
    assert!(reported);
    // Deposits go on without tokens.
    device
        .deposit_item(PEER, recipient(&device), b"two".to_vec())
        .await
        .unwrap();
    assert!(peer.connections().last().unwrap().tokens.is_empty());
    // Trusted again, the device learns the keys anew and draws.
    device.trust_deposit_keys(PEER).await.unwrap();
    device.give_deposit_grant(PEER, b"another grant".to_vec());
    device.deposit_upkeep().await;
    clock.advance(HOUR + 1);
    device.deposit_upkeep().await;
    let tokens = device.deposit_tokens(PEER).await;
    assert!(!tokens.distrusted);
    assert_eq!(tokens.held, 16);
}

/// ext-deposit-tokens.md, 3.11: `allowance_exhausted` pauses drawing at
/// the peer for `allowance_window`.
#[tokio::test]
async fn an_exhausted_allowance_pauses_drawing_for_a_day() {
    let peer = FakePeer::with_key(1);
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let device = open(Storage::Memory, &peer, &clock).await;
    peer.draw_refusals
        .lock()
        .unwrap()
        .push_back("allowance_exhausted".into());
    draw_a_batch(&device, &clock).await;
    let tokens = device.deposit_tokens(PEER).await;
    assert_eq!(tokens.held, 0);
    assert!(tokens.paused);
    assert!(tokens.grant, "a grant refused for the allowance is kept");
    let draws = || {
        peer.connections()
            .iter()
            .filter(|c| c.kinds.contains(&42))
            .count()
    };
    assert_eq!(draws(), 1);
    clock.advance(12 * HOUR);
    device.deposit_upkeep().await;
    clock.advance(2 * HOUR);
    device.deposit_upkeep().await;
    assert_eq!(draws(), 1, "paused");
    clock.advance(DAY);
    device.deposit_upkeep().await;
    clock.advance(HOUR + 1);
    device.deposit_upkeep().await;
    assert_eq!(draws(), 2);
    assert_eq!(device.deposit_tokens(PEER).await.held, 16);
}
