//! The server binding's connections under the operator's limits: caps on
//! open connections, the deadline of a request's head, the keep-alive and
//! the idle time after `Hello`. A WebSocket here is driven by hand, over
//! TCP, so that a test chooses when it reads and what it answers.

use super::*;
use crate::config::{ConnectionLimits, Settings};
use crate::testing::{Options, TestPeer, spawn_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn peer(limits: ConnectionLimits) -> TestPeer {
    spawn_with(Options {
        settings: Settings {
            connections: limits,
            ..Settings::open_core()
        },
        iroh: false,
        ..Options::default()
    })
    .await
    .unwrap()
}

/// Reads until the connection ends, within `wait`: whether it ended.
async fn ends_within(stream: &mut TcpStream, wait: Duration) -> bool {
    tokio::time::timeout(wait, async {
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

/// A connection whose request head does not arrive within
/// `header_read_timeout` is closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_head_that_does_not_arrive_in_time_closes_the_connection() {
    let peer = peer(ConnectionLimits {
        header_read_timeout: 1,
        ..ConnectionLimits::DEFAULT
    })
    .await;
    let mut slow = TcpStream::connect(peer.http).await.unwrap();
    slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: peer\r\n")
        .await
        .unwrap();
    assert!(ends_within(&mut slow, Duration::from_secs(5)).await);
    // A head that arrives in time is answered.
    let status =
        super::tests::status_without_body(peer.http, "GET /healthz HTTP/1.1\r\nHost: peer\r\n\r\n")
            .await;
    assert!(status.is_some_and(|line| line.contains(" 200")));
    peer.shutdown().await;
}

/// Past `max_connections_per_source`, and past `max_connections`, a new
/// connection is answered 503 `busy` and closed; one that closes makes
/// room.
#[tokio::test(flavor = "multi_thread")]
async fn connections_are_capped_overall_and_per_source() {
    let peer = peer(ConnectionLimits {
        max_connections: 3,
        max_connections_per_source: 2,
        ..ConnectionLimits::DEFAULT
    })
    .await;
    let first = TcpStream::connect(peer.http).await.unwrap();
    let _second = TcpStream::connect(peer.http).await.unwrap();
    // Each is accepted in turn; wait for both to be counted.
    let shared = peer.peer.shared.clone();
    for _ in 0..100 {
        if shared.connections.open() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(shared.connections.open(), 2);
    // The refusal is written as the connection is taken, before any
    // request: read it without sending one, so that nothing unread is left
    // on the peer's side when it closes.
    let mut refused = TcpStream::connect(peer.http).await.unwrap();
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), refused.read_to_end(&mut answer)).await;
    assert!(matches!(read, Ok(Ok(_))), "{read:?}");
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 503 "), "{answer}");
    assert!(answer.ends_with(r#"{"code":"busy"}"#), "{answer}");
    drop(first);
    let head = "GET /healthz HTTP/1.1\r\nHost: peer\r\n\r\n";
    for _ in 0..100 {
        if shared.connections.open() < 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = super::tests::status_without_body(peer.http, head).await;
    assert!(
        status.as_deref().is_some_and(|line| line.contains(" 200")),
        "{status:?}"
    );
    peer.shutdown().await;
}

/// A WebSocket driven by hand: the device's end.
struct Socket {
    stream: TcpStream,
    channel: frasil_transport::Channel,
}

/// The opcodes RFC 6455 gives a frame.
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xa;

impl Socket {
    /// Opens the connect route as a WebSocket of subprotocol `frasil.p1`.
    async fn open(http: SocketAddr) -> Self {
        let mut stream = TcpStream::connect(http).await.unwrap();
        let request = format!(
            "GET {CONNECT_PATH} HTTP/1.1\r\nHost: {http}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {WEBSOCKET_SUBPROTOCOL}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
        Self {
            stream,
            channel: server_channel(&format!("http://{http}")),
        }
    }

    /// Sends one frame, masked as a client's are.
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let mut frame = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => frame.push(0x80 | n as u8),
            n if n <= usize::from(u16::MAX) => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mask = [1u8, 2, 3, 4];
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
    }

    /// Reads one frame of the peer's within `wait`: its opcode and payload;
    /// `None` if none came, or the connection ended.
    async fn read(&mut self, wait: Duration) -> Option<(u8, Vec<u8>)> {
        tokio::time::timeout(wait, async {
            let mut head = [0u8; 2];
            self.stream.read_exact(&mut head).await.ok()?;
            let length = match head[1] & 0x7f {
                126 => {
                    let mut n = [0u8; 2];
                    self.stream.read_exact(&mut n).await.ok()?;
                    u64::from(u16::from_be_bytes(n))
                }
                127 => {
                    let mut n = [0u8; 8];
                    self.stream.read_exact(&mut n).await.ok()?;
                    u64::from_be_bytes(n)
                }
                n => u64::from(n),
            };
            let mut payload = vec![0u8; usize::try_from(length).ok()?];
            self.stream.read_exact(&mut payload).await.ok()?;
            Some((head[0] & 0x0f, payload))
        })
        .await
        .ok()
        .flatten()
    }

    /// Reads the `PeerHello` and answers with a `Hello` of space traffic.
    async fn hello(&mut self) -> frasil_transport::peer::DeviceSide {
        let (opcode, peer_hello) = self.read(Duration::from_secs(5)).await.unwrap();
        assert_eq!(opcode, BINARY);
        let message = read(&peer_hello, Extensions::NONE).unwrap().unwrap();
        let device = frasil_transport::peer::DeviceSide::answer_with(
            &self.channel,
            &message,
            [7; 32],
            frasil_transport::peer::Purpose::SpaceTraffic,
        )
        .unwrap();
        self.send(BINARY, &device.hello).await;
        device
    }
}

/// A connection that holds no grant and sends nothing for `idle_timeout`
/// after its `Hello` is closed `done`.
#[tokio::test(flavor = "multi_thread")]
async fn an_idle_connection_without_a_grant_is_closed() {
    let peer = peer(ConnectionLimits {
        idle_timeout: 1,
        keepalive_interval: 1,
        ..ConnectionLimits::DEFAULT
    })
    .await;
    let mut socket = Socket::open(peer.http).await;
    socket.hello().await;
    let mut closed = None;
    while let Some((opcode, payload)) = socket.read(Duration::from_secs(5)).await {
        if opcode == PING {
            socket.send(PONG, &payload).await;
        }
        if opcode == CLOSE {
            closed = payload
                .get(..2)
                .map(|code| u16::from_be_bytes([code[0], code[1]]));
            break;
        }
    }
    assert_eq!(closed, Some(Code::Done.websocket()));
    peer.shutdown().await;
}

/// A connection that holds a grant stays open while it answers the
/// keep-alive, however quiet; once it answers nothing for three
/// intervals, the peer drops it.
#[tokio::test(flavor = "multi_thread")]
async fn a_granted_connection_stays_while_it_answers_the_keep_alive() {
    // Idle for longer than an interval, so that a busy machine that sends
    // the genesis and the present late does not run into the idle close
    // before the grant: what the test is about is the grant held after.
    let peer = peer(ConnectionLimits {
        idle_timeout: 3,
        keepalive_interval: 1,
        ..ConnectionLimits::DEFAULT
    })
    .await;
    let mut socket = Socket::open(peer.http).await;
    let device = socket.hello().await;
    // The device creates a space and proves its upload key.
    let events = crate::session::tests::history();
    let space = crate::session::tests::id_of(&events[0].1);
    let genesis = crate::state::sync(
        space,
        frasil_units::messages::Message::Events {
            events: vec![events[0].1.clone()],
        },
    );
    socket.send(BINARY, &genesis).await;
    let present = device.present(
        1,
        space.as_bytes(),
        frasil_peers::proof::Credential::Upload,
        &crate::session::tests::upload_seed(),
    );
    socket.send(BINARY, &present).await;
    let mut granted = false;
    let mut pings = 0;
    let until = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < until {
        let Some((opcode, payload)) = socket.read(Duration::from_secs(2)).await else {
            continue;
        };
        match opcode {
            PING => {
                pings += 1;
                socket.send(PONG, &payload).await;
            }
            BINARY => {
                let message = read(&payload, Extensions::NONE).unwrap().unwrap();
                granted |= message.kind == MessageType::Granted;
            }
            CLOSE => panic!("closed while it answers the keep-alive"),
            _ => {}
        }
    }
    assert!(granted);
    assert!(pings >= 2, "{pings} pings");
    // It answers nothing more: within three intervals and one more, the
    // peer drops it.
    assert!(ends_within(&mut socket.stream, Duration::from_secs(6)).await);
    peer.shutdown().await;
}
