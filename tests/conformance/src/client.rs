//! A device's end of a device-to-peer connection, for scenarios: the
//! handshake of transport.md, section 3.10, presents, `Sync` messages,
//! requests and mailboxes, over the server binding's WebSocket or the iroh
//! binding's `frasil/p1/peer`.
//!
//! It is a test driver, not a client: it sends what a test tells it to and
//! hands back what arrives. Every wait has a deadline.

use frasil_base::cbor;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_iroh::{Alpn, Connection, Endpoint, FrameReceiver, FrameSender, Stream};
use frasil_relay::testing::TestPeer;
use frasil_transport::frame::{
    ConnectionKind, Extensions, Message, MessageType, StreamClass, read_message,
};
use frasil_transport::messages::{EventRefused, Granted, Refused, Scope, Sync};
use frasil_transport::peer::{DeviceSide, PeerHello, Purpose};
use frasil_units::messages::{Message as UnitMessage, Received, SyncMessage};
use futures_util::{SinkExt, StreamExt};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite;

pub use frasil_peers::proof::Credential;

/// The longest any step waits for an answer that should come.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// How long a step waits for an answer that should not come.
pub const QUIET: Duration = Duration::from_millis(400);

/// What arrives on a connection.
#[derive(Debug, Clone)]
pub enum Inbound {
    /// A message, on any stream.
    Message(Message),
    /// The connection closed, with the peer's code if it gave one: a
    /// WebSocket close code (4000 plus transport.md's code), or a QUIC
    /// application code.
    Closed(Option<u64>),
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

enum Sender {
    WebSocket(futures_util::stream::SplitSink<Socket, tungstenite::Message>),
    Iroh {
        _endpoint: Endpoint,
        connection: Arc<Connection>,
        control: FrameSender,
        sync: BTreeMap<EventId, FrameSender>,
        inbox: mpsc::UnboundedSender<Inbound>,
    },
}

/// A device's connection to a peer.
pub struct PeerClient {
    sender: Sender,
    inbox: mpsc::UnboundedReceiver<Inbound>,
    pending: VecDeque<Inbound>,
    /// The connection's `binding`.
    pub binding: [u8; 32],
    /// The peer's `PeerHello`.
    pub peer_hello: PeerHello,
    /// The first message the peer sent, as received.
    pub first: Message,
    /// The connection's purpose.
    pub purpose: Purpose,
    next_request: u64,
    /// The transfer token of each space's grant, on the server binding.
    pub tokens: BTreeMap<EventId, [u8; 32]>,
    http: Option<String>,
}

/// Reads one WebSocket message in the class that carries its type.
pub fn read_ws(payload: &[u8]) -> Option<Message> {
    let class = cbor::decode(payload)
        .ok()
        .and_then(|value| value.as_map().ok()?.get(&0)?.as_unsigned().ok())
        .and_then(MessageType::from_code)
        .map_or(StreamClass::Control, |kind| match kind {
            MessageType::Sync | MessageType::AdapterSync | MessageType::Open => StreamClass::Sync,
            MessageType::Ephemeral => StreamClass::Ephemeral,
            _ => StreamClass::Control,
        });
    read_message(payload, class, ConnectionKind::DeviceToPeer, EXTENSIONS)
        .ok()
        .flatten()
}

/// The message types a device reads: ext-deposit-tokens.md's answers,
/// types 41 and 43, with the feature `ext-deposit-tokens`.
pub const EXTENSIONS: Extensions = Extensions {
    deposit_tokens: cfg!(feature = "ext-deposit-tokens"),
    ..Extensions::NONE
};

fn random<const N: usize>() -> [u8; N] {
    *frasil_crypto::random_bytes::<N>().expect("randomness")
}

fn read_frames(mut receiver: FrameReceiver, inbox: mpsc::UnboundedSender<Inbound>) {
    tokio::spawn(async move {
        loop {
            match receiver.receive().await {
                Ok(Some(message)) => {
                    if inbox.send(Inbound::Message(message)).is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = inbox.send(Inbound::Closed(error.code().map(|c| c.number())));
                    return;
                }
            }
        }
    });
}

impl PeerClient {
    /// Connects over the server binding's WebSocket, with subprotocol
    /// `frasil.p1`, and runs the device's end of the handshake.
    ///
    /// # Panics
    ///
    /// If the connection or the handshake fails.
    pub async fn ws(peer: &TestPeer, purpose: Purpose) -> Self {
        Self::ws_to(&peer.connect_url, &peer.origin, purpose).await
    }

    /// [`PeerClient::ws`] to a URL, whose origin is `origin`.
    ///
    /// # Panics
    ///
    /// If the connection or the handshake fails.
    pub async fn ws_to(url: &str, origin: &str, purpose: Purpose) -> Self {
        use tungstenite::client::IntoClientRequest;
        let mut request = url.into_client_request().expect("a WebSocket URL");
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            frasil_transport::labels::WEBSOCKET_SUBPROTOCOL
                .parse()
                .expect("a header"),
        );
        let (socket, response) =
            tokio::time::timeout(DEADLINE, tokio_tungstenite::connect_async(request))
                .await
                .expect("within the deadline")
                .expect("the WebSocket opens");
        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some(frasil_transport::labels::WEBSOCKET_SUBPROTOCOL),
            "the peer echoes the subprotocol"
        );
        let (sink, mut stream) = socket.split();
        let (tx, inbox) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(tungstenite::Message::Binary(bytes)) => {
                        if let Some(message) = read_ws(&bytes)
                            && tx.send(Inbound::Message(message)).is_err()
                        {
                            return;
                        }
                    }
                    Ok(tungstenite::Message::Close(frame)) => {
                        let _ =
                            tx.send(Inbound::Closed(frame.map(|f| u64::from(u16::from(f.code)))));
                        return;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        let _ = tx.send(Inbound::Closed(None));
                        return;
                    }
                }
            }
            let _ = tx.send(Inbound::Closed(None));
        });
        let channel = frasil_transport::peer::server_channel(origin);
        let http = url
            .strip_prefix("ws://")
            .and_then(|rest| rest.split('/').next())
            .map(|host| format!("http://{host}"));
        Self::handshake(Sender::WebSocket(sink), inbox, channel, purpose, http, None).await
    }

    /// Connects over the iroh binding, ALPN `frasil/p1/peer`, from a fresh
    /// endpoint key on loopback, and runs the device's end of the
    /// handshake: the peer opens the control stream and writes first.
    ///
    /// # Panics
    ///
    /// If the peer does not listen on iroh, or the handshake fails.
    pub async fn iroh(peer: &TestPeer, purpose: Purpose) -> Self {
        Self::iroh_with(peer, purpose, None).await
    }

    /// [`PeerClient::iroh`] that sends `events` of `space` on a sync stream
    /// before its `Hello`, and lets the peer read them before it sends the
    /// `Hello`: QUIC orders each stream alone, so a sync stream may reach
    /// the peer first, as it can under load. A peer that closed the
    /// connection meanwhile leaves its close in the client's inbox.
    ///
    /// # Panics
    ///
    /// As [`PeerClient::iroh`].
    pub async fn iroh_sync_before_hello(
        peer: &TestPeer,
        space: EventId,
        events: Vec<Vec<u8>>,
    ) -> Self {
        Self::iroh_with(peer, Purpose::SpaceTraffic, Some((space, events))).await
    }

    async fn iroh_with(
        peer: &TestPeer,
        purpose: Purpose,
        early: Option<(EventId, Vec<Vec<u8>>)>,
    ) -> Self {
        let info = peer.iroh.as_ref().expect("the peer listens on iroh");
        let endpoint = Endpoint::bind(
            frasil_iroh::Config::new(frasil_iroh::fresh_secret_key().expect("a key"), &[])
                .loopback()
                .extensions(EXTENSIONS),
        )
        .await
        .expect("an endpoint");
        let connection = tokio::time::timeout(
            DEADLINE,
            endpoint.connect(&info.endpoint, &info.addresses, &[], Alpn::Peer),
        )
        .await
        .expect("within the deadline")
        .expect("dialed");
        let connection = Arc::new(connection);
        assert!(
            !connection.opens_control(),
            "the device accepts the control stream"
        );
        let (control, receiver) = tokio::time::timeout(DEADLINE, connection.control())
            .await
            .expect("within the deadline")
            .expect("the peer opens the control stream");
        let (tx, inbox) = mpsc::unbounded_channel();
        read_frames(receiver, tx.clone());
        {
            let connection = connection.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match connection.accept_stream().await {
                        Ok(Stream::Object { receiver, .. }) => read_frames(receiver, tx.clone()),
                        Ok(Stream::Sync { receiver, .. }) => read_frames(receiver, tx.clone()),
                        Ok(Stream::Ephemeral { .. }) => {}
                        Err(error) => {
                            let _ = tx.send(Inbound::Closed(error.code().map(|c| c.number())));
                            return;
                        }
                    }
                }
            });
        }
        let channel = connection.channel();
        Self::handshake(
            Sender::Iroh {
                _endpoint: endpoint,
                connection,
                control,
                sync: BTreeMap::new(),
                inbox: tx,
            },
            inbox,
            channel,
            purpose,
            None,
            early,
        )
        .await
    }

    async fn handshake(
        sender: Sender,
        inbox: mpsc::UnboundedReceiver<Inbound>,
        channel: [u8; 32],
        purpose: Purpose,
        http: Option<String>,
        early: Option<(EventId, Vec<Vec<u8>>)>,
    ) -> Self {
        let mut client = Self {
            sender,
            inbox,
            pending: VecDeque::new(),
            binding: [0; 32],
            peer_hello: PeerHello {
                nonce: [0; 32],
                services: cbor::Value::Array(Vec::new()),
                limits: cbor::Value::Array(Vec::new()),
            },
            first: Message {
                kind: MessageType::PeerHello,
                map: Default::default(),
                bytes: Vec::new(),
            },
            purpose,
            next_request: 1,
            tokens: BTreeMap::new(),
            http,
        };
        let first = match client.next(DEADLINE).await {
            Some(Inbound::Message(message)) => message,
            other => panic!("no PeerHello: {other:?}"),
        };
        assert_eq!(first.kind, MessageType::PeerHello, "the peer writes first");
        let side = DeviceSide::answer_with(&channel, &first, random(), purpose)
            .expect("the PeerHello reads");
        client.binding = side.binding;
        client.peer_hello = side.peer_hello.clone();
        client.first = first;
        if let Some((space, events)) = early {
            client
                .send_sync(space, UnitMessage::Events { events })
                .await;
            // What the peer does with them before the Hello: a close stays
            // in the inbox for the store that follows to find.
            if let Some(item) = client.next(QUIET).await {
                client.pending.push_back(item);
            }
        }
        client.send_control(&side.hello).await;
        client
    }

    /// The next request number.
    pub fn request(&mut self) -> u64 {
        let request = self.next_request;
        self.next_request += 1;
        request
    }

    /// Sends a control message.
    pub async fn send_control(&mut self, bytes: &[u8]) {
        match &mut self.sender {
            Sender::WebSocket(sink) => {
                let _ = sink
                    .send(tungstenite::Message::Binary(bytes.to_vec().into()))
                    .await;
            }
            Sender::Iroh { control, .. } => {
                let _ = control.send(bytes).await;
            }
        }
    }

    /// Sends a text WebSocket message, which the server binding refuses.
    pub async fn send_text(&mut self, text: &str) {
        if let Sender::WebSocket(sink) = &mut self.sender {
            let _ = sink.send(tungstenite::Message::Text(text.into())).await;
        }
    }

    /// Sends units.md's message in a `Sync` of the space: on the
    /// WebSocket, or on the space's sync stream, which it opens first.
    pub async fn send_sync(&mut self, space: EventId, message: UnitMessage) {
        let bytes = Sync {
            scope: Scope::Space(*space.as_bytes()),
            message: SyncMessage { space, message }.encode(),
        }
        .encode();
        self.send_sync_bytes(space, &bytes).await;
    }

    /// Sends a `Sync` message's bytes as they are.
    pub async fn send_sync_bytes(&mut self, space: EventId, bytes: &[u8]) {
        match &mut self.sender {
            Sender::WebSocket(sink) => {
                let _ = sink
                    .send(tungstenite::Message::Binary(bytes.to_vec().into()))
                    .await;
            }
            Sender::Iroh {
                connection,
                sync,
                inbox,
                ..
            } => {
                let sender = match sync.entry(space) {
                    std::collections::btree_map::Entry::Occupied(held) => held.into_mut(),
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        let (sender, receiver) = connection
                            .open_sync(Scope::Space(*space.as_bytes()))
                            .await
                            .expect("a sync stream");
                        read_frames(receiver, inbox.clone());
                        slot.insert(sender)
                    }
                };
                let _ = sender.send(bytes).await;
            }
        }
    }

    /// The next thing that arrives, within `wait`.
    pub async fn next(&mut self, wait: Duration) -> Option<Inbound> {
        if let Some(item) = self.pending.pop_front() {
            return Some(item);
        }
        tokio::time::timeout(wait, self.inbox.recv())
            .await
            .ok()
            .flatten()
    }

    /// Waits within `wait` for a message `pick` takes; others are kept for
    /// later waits, in order. A close ends the wait.
    pub async fn wait_for<T>(
        &mut self,
        wait: Duration,
        mut pick: impl FnMut(&Message) -> Option<T>,
    ) -> Option<T> {
        let mut kept = VecDeque::new();
        let mut found = None;
        while let Some(item) = self.pending.pop_front() {
            if found.is_none()
                && let Inbound::Message(message) = &item
                && let Some(value) = pick(message)
            {
                found = Some(value);
                continue;
            }
            kept.push_back(item);
        }
        self.pending = kept;
        if found.is_some() {
            return found;
        }
        if self
            .pending
            .iter()
            .any(|item| matches!(item, Inbound::Closed(_)))
        {
            return None;
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let item = tokio::time::timeout_at(deadline, self.inbox.recv())
                .await
                .ok()
                .flatten()?;
            if let Inbound::Message(message) = &item
                && let Some(value) = pick(message)
            {
                return Some(value);
            }
            let closed = matches!(item, Inbound::Closed(_));
            self.pending.push_back(item);
            if closed {
                return None;
            }
        }
    }

    /// Waits for the connection to close; its code.
    pub async fn closed(&mut self, wait: Duration) -> Option<Option<u64>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(index) = self
                .pending
                .iter()
                .position(|item| matches!(item, Inbound::Closed(_)))
                && let Some(Inbound::Closed(code)) = self.pending.remove(index)
            {
                return Some(code);
            }
            match tokio::time::timeout_at(deadline, self.inbox.recv()).await {
                Ok(Some(Inbound::Closed(code))) => return Some(code),
                Ok(Some(other)) => self.pending.push_back(other),
                Ok(None) => return Some(None),
                Err(_) => return None,
            }
        }
    }

    // -- Presents and requests

    /// Presents a credential's Ed25519 seed for a space: its `Granted`, or
    /// the `Refused` code.
    pub async fn present(
        &mut self,
        space: EventId,
        credential: Credential,
        seed: &[u8; 32],
    ) -> Result<Granted, String> {
        let request = self.request();
        let present = self
            .side()
            .present(request, space.as_bytes(), credential, seed);
        self.presented(space, request, &present).await
    }

    /// Presents an administrator pseudonym (credential 3): its device ID,
    /// with a proof by its Ed25519 seed (peers.md, "Presenting
    /// credentials").
    pub async fn present_pseudonym(
        &mut self,
        space: EventId,
        seed: &[u8; 32],
        pseudonym: &DeviceId,
    ) -> Result<Granted, String> {
        let request = self.request();
        let present = self
            .side()
            .present_pseudonym(request, space.as_bytes(), seed, pseudonym);
        self.presented(space, request, &present).await
    }

    /// The device's side of the connection, for the messages it signs.
    pub fn side(&self) -> DeviceSide {
        DeviceSide {
            peer_hello: self.peer_hello.clone(),
            hello: Vec::new(),
            purpose: self.purpose,
            binding: self.binding,
        }
    }

    async fn presented(
        &mut self,
        space: EventId,
        request: u64,
        present: &[u8],
    ) -> Result<Granted, String> {
        self.send_control(present).await;
        let answer = self.answer(request).await;
        if let Ok(granted) = &answer
            && let Some(token) = granted.transfer_token
        {
            self.tokens.insert(space, token);
        }
        answer
    }

    /// The `Granted` or `Refused` of a request.
    pub async fn answer(&mut self, request: u64) -> Result<Granted, String> {
        self.wait_for(DEADLINE, |message| match message.kind {
            MessageType::Granted => Granted::read(message)
                .ok()
                .filter(|g| g.request == request)
                .map(Ok),
            MessageType::Refused => Refused::read(message)
                .ok()
                .filter(|r| r.request == request)
                .map(|r| Err(r.code)),
            _ => None,
        })
        .await
        .unwrap_or_else(|| Err("no answer".into()))
    }

    /// Sends a request message and waits for its `Accepted` (`Ok`), a
    /// `MailboxItems` (`Ok`, with the message), or `Refused` (`Err`).
    pub async fn request_answer(
        &mut self,
        request: u64,
        bytes: &[u8],
    ) -> Result<Option<Message>, String> {
        self.send_control(bytes).await;
        self.wait_for(DEADLINE, |message| {
            let number = message.get(1).and_then(|v| v.as_unsigned().ok());
            if number != Some(request) {
                return None;
            }
            match message.kind {
                MessageType::Accepted => Some(Ok(None)),
                MessageType::MailboxItems => Some(Ok(Some(message.clone()))),
                MessageType::Refused => Some(Err(Refused::read(message)
                    .map(|r| r.code)
                    .unwrap_or_default())),
                _ => None,
            }
        })
        .await
        .unwrap_or_else(|| Err("no answer".into()))
    }

    // -- Sync

    /// A units.md message of the space, from a received message.
    pub fn unit_message(message: &Message, space: EventId) -> Option<UnitMessage> {
        if message.kind != MessageType::Sync {
            return None;
        }
        let sync = Sync::read(message, ConnectionKind::DeviceToPeer).ok()?;
        if sync.scope != Scope::Space(*space.as_bytes()) {
            return None;
        }
        match SyncMessage::read(&sync.message).ok()? {
            Received::Message(unit) if unit.space == space => Some(unit.message),
            _ => None,
        }
    }

    /// Stores events in one `Events` message, and waits `wait` at most for
    /// its `Ack`; returns the IDs acknowledged. The peer answers one
    /// message with one `Ack` of every event it stored, and with none when
    /// it stored none.
    pub async fn store(
        &mut self,
        space: EventId,
        events: Vec<Vec<u8>>,
        wait: Duration,
    ) -> Vec<EventId> {
        let ids: Vec<EventId> = events
            .iter()
            .filter_map(|signed| frasil_events::decode(signed).ok().map(|e| e.id()))
            .collect();
        self.send_sync(space, UnitMessage::Events { events }).await;
        self.wait_for(wait, |message| match Self::unit_message(message, space) {
            Some(UnitMessage::Ack { heads }) if heads.iter().any(|id| ids.contains(id)) => {
                Some(heads.into_iter().filter(|id| ids.contains(id)).collect())
            }
            _ => None,
        })
        .await
        .unwrap_or_default()
    }

    /// Stores one event and waits `wait` at most for the peer's answer:
    /// `Ok` for its `Ack`, `Err` with the code of its `EventRefused`
    /// (transport.md, section 3.10), `None` for neither, as for an event
    /// held pending.
    pub async fn store_answer(
        &mut self,
        space: EventId,
        signed: &[u8],
        wait: Duration,
    ) -> Option<Result<(), String>> {
        let id = frasil_events::decode(signed).ok()?.id();
        self.send_sync(
            space,
            UnitMessage::Events {
                events: vec![signed.to_vec()],
            },
        )
        .await;
        self.wait_for(wait, |message| {
            if message.kind == MessageType::EventRefused {
                let refused = EventRefused::read(message).ok()?;
                return (refused.space == *space.as_bytes() && refused.event == *id.as_bytes())
                    .then_some(Err(refused.code));
            }
            match Self::unit_message(message, space) {
                Some(UnitMessage::Ack { heads }) if heads.contains(&id) => Some(Ok(())),
                _ => None,
            }
        })
        .await
    }

    /// Stores one event; whether it was acknowledged.
    pub async fn store_one(&mut self, space: EventId, signed: &[u8], wait: Duration) -> bool {
        !self
            .store(space, vec![signed.to_vec()], wait)
            .await
            .is_empty()
    }

    /// Collects units.md messages of a space until none arrives for
    /// [`QUIET`].
    pub async fn collect(&mut self, space: EventId) -> Vec<UnitMessage> {
        let mut out = Vec::new();
        while let Some(message) = self
            .wait_for(QUIET, |message| Self::unit_message(message, space))
            .await
        {
            out.push(message);
        }
        out
    }

    /// Sends a units.md message and collects what answers it.
    pub async fn exchange(&mut self, space: EventId, message: UnitMessage) -> Vec<UnitMessage> {
        self.send_sync(space, message).await;
        self.collect(space).await
    }

    /// The events of collected messages, decoded, with their IDs.
    pub fn events_of(messages: &[UnitMessage]) -> Vec<EventId> {
        messages
            .iter()
            .filter_map(|m| match m {
                UnitMessage::Events { events } => Some(events),
                _ => None,
            })
            .flatten()
            .filter_map(|signed| frasil_events::decode(signed).ok().map(|e| e.id()))
            .collect()
    }

    // -- Objects over HTTP

    /// The HTTP base of the server binding, `http://host:port`.
    pub fn http(&self) -> Option<&str> {
        self.http.as_deref()
    }

    /// Closes the connection.
    pub async fn close(mut self) {
        match &mut self.sender {
            Sender::WebSocket(sink) => {
                let _ = sink.send(tungstenite::Message::Close(None)).await;
            }
            Sender::Iroh { connection, .. } => connection.close(frasil_transport::Code::Done),
        }
    }
}
