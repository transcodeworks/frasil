//! transport.md's device-to-peer handshake (section 3.10) and presents
//! (section 3.11), against `frasil-relay` over the server binding's
//! WebSocket and over the iroh binding. On iroh the peer, the listener,
//! opens the control stream and sends `PeerHello` first (section 3.16).

mod common;

use common::*;
use frasil_conformance::client::{Credential, Inbound};
use frasil_conformance::history::History;
use frasil_transport::Code;
use frasil_transport::codes::{Right, Service};
use frasil_transport::frame::MessageType;
use frasil_transport::messages::Present;
use frasil_transport::peer::{Hello, Purpose, presented};

async fn handshake(binding: Binding) {
    let peer = peer(frasil_conformance::settings()).await;
    let history = History::credentials();
    let space = history.space();
    let genesis = "P creates the space";
    let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;

    // The PeerHello came first, and lists what this peer serves.
    assert_eq!(device.first.kind, MessageType::PeerHello);
    let mut services = vec![Service::Relay, Service::Store, Service::Mailbox];
    // ext-libraries.md's service 5, `library`, while it is on.
    if frasil_conformance::EXTENSIONS.libraries {
        services.push(Service::Library);
    }
    // ext-deposit-tokens.md's service 6, `deposit`, while it is on.
    if frasil_conformance::EXTENSIONS.deposit_tokens {
        services.push(Service::Deposit);
    }
    assert_eq!(device.peer_hello.services(), services);
    assert_eq!(device.peer_hello.limit(1), Some(1_056_768));
    assert_eq!(device.peer_hello.limit(2), Some(65_536));
    assert_eq!(device.peer_hello.limit(3), Some(262_144));
    assert_eq!(device.peer_hello.limit(4), Some(1_048_576));

    // A space the peer does not host.
    assert_eq!(
        device
            .present(space, Credential::Read, &history.read_seed(genesis))
            .await
            .unwrap_err(),
        "no_library"
    );

    // A create: the first event the connection stores is the genesis.
    let acked = device
        .store(space, history.events(&[genesis]), DEADLINE)
        .await;
    assert_eq!(acked, vec![space]);
    assert!(peer.peer.hosts(space.as_bytes()));

    // The genesis's read credential grants fetch and live; its upload key
    // store and release. The proofs bind this connection's `binding`, so
    // the peer computed the same one.
    let read = device
        .present(space, Credential::Read, &history.read_seed(genesis))
        .await
        .expect("a live read credential");
    assert_eq!(read.rights, vec![Right::Fetch, Right::Live]);
    assert_eq!(
        read.transfer_token.is_some(),
        binding == Binding::WebSocket,
        "a transfer token on the server binding only"
    );
    let upload = device
        .present(space, Credential::Upload, &history.upload_seed(genesis))
        .await
        .expect("a live upload key");
    assert_eq!(upload.rights, vec![Right::Store, Right::Release]);

    // A proof over another binding, and a key the space does not hold.
    let seed = history.read_seed(genesis);
    let public = frasil_crypto::primitives::ed25519_public(&seed);
    let elsewhere = presented(&[9; 32], space.as_bytes(), 1, &public);
    let request = device.request();
    let forged = Present {
        request,
        space: *space.as_bytes(),
        credential: 1,
        public: public.to_vec(),
        proof: frasil_peers::proof::prove(&seed, &elsewhere).to_vec(),
    }
    .encode();
    device.send_control(&forged).await;
    assert_eq!(
        device.answer(request).await.unwrap_err(),
        "credential_refused"
    );
    assert_eq!(
        device
            .present(space, Credential::Read, &[7; 32])
            .await
            .unwrap_err(),
        "credential_refused"
    );

    // A pseudonym on a space-traffic connection breaks the purpose rules.
    let request = device.request();
    let pseudonym = frasil_transport::peer::DeviceSide {
        peer_hello: device.peer_hello.clone(),
        hello: Vec::new(),
        purpose: Purpose::SpaceTraffic,
        binding: device.binding,
    }
    .present_pseudonym(
        request,
        space.as_bytes(),
        &history.seed("P0"),
        &history.device_id("P0"),
    );
    device.send_control(&pseudonym).await;
    let code = device.closed(DEADLINE).await.expect("the peer closes");
    let expected = match binding {
        Binding::WebSocket => u64::from(Code::PurposeViolation.websocket()),
        Binding::Iroh => Code::PurposeViolation.number(),
    };
    assert_eq!(code, Some(expected));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_handshake_completes_over_the_websocket() {
    within(handshake(Binding::WebSocket)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_handshake_completes_over_iroh_with_the_peer_writing_first() {
    within(handshake(Binding::Iroh)).await;
}

async fn administration(binding: Binding) {
    let peer = peer(frasil_conformance::settings()).await;
    let history = History::credentials();
    let space = history.space();
    let mut founder = founder(&peer, binding, &history).await;
    store_all(
        &mut founder,
        space,
        history.events(&["P0: root", "P grants W write"]),
    )
    .await;

    // One pseudonym, on a connection of its own.
    let mut admin = connect(&peer, binding, Purpose::Administration).await;
    let granted = admin
        .present_pseudonym(space, &history.seed("P0"), &history.device_id("P0"))
        .await
        .expect("the root's pseudonym");
    assert_eq!(granted.rights, vec![Right::Erase]);
    // The peer reports what awaits the pseudonym's acknowledgement.
    let awaiting = admin
        .wait_for(DEADLINE, |message| {
            (message.kind == MessageType::Awaiting).then_some(())
        })
        .await;
    assert!(awaiting.is_some(), "an Awaiting report");
    // A second present breaks the purpose rules.
    let again = admin
        .present_pseudonym(space, &history.seed("P0"), &history.device_id("P0"))
        .await;
    assert!(again.is_err());
    let code = admin.closed(DEADLINE).await.expect("the peer closes");
    let expected = match binding {
        Binding::WebSocket => u64::from(Code::PurposeViolation.websocket()),
        Binding::Iroh => Code::PurposeViolation.number(),
    };
    assert_eq!(code, Some(expected));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_administration_connection_presents_one_pseudonym_over_the_websocket() {
    within(administration(Binding::WebSocket)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_administration_connection_presents_one_pseudonym_over_iroh() {
    within(administration(Binding::Iroh)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hellos_of_another_revision_and_text_messages_close_the_connection() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        // A Hello of another protocol closes with unsupported_version.
        let mut device = raw_socket(&peer).await;
        let mut hello = Hello::encode(&[1; 32], Purpose::SpaceTraffic);
        // Key 1, the protocol: 2 instead of 1.
        let position = hello
            .windows(2)
            .position(|w| w == [0x01, 0x01])
            .expect("key 1");
        hello[position + 1] = 0x02;
        device.send_control(&hello).await;
        assert_eq!(
            device.closed(DEADLINE).await,
            Some(Some(u64::from(Code::UnsupportedVersion.websocket())))
        );
        // A text message closes with 1003.
        let mut device = raw_socket(&peer).await;
        device.send_text("hello").await;
        assert_eq!(device.closed(DEADLINE).await, Some(Some(1003)));
        peer.shutdown().await;
    })
    .await;
}

/// A WebSocket device that has not answered the `PeerHello`.
async fn raw_socket(peer: &frasil_relay::testing::TestPeer) -> RawSocket {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = peer.connect_url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "frasil.p1".parse().unwrap());
    let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let (sink, mut stream) = socket.split();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(item) = stream.next().await {
            let closed = match item {
                Ok(tokio_tungstenite::tungstenite::Message::Close(frame)) => {
                    Some(frame.map(|f| u64::from(u16::from(f.code))))
                }
                Err(_) => Some(None),
                _ => None,
            };
            if let Some(code) = closed {
                let _ = tx.send(Inbound::Closed(code));
                return;
            }
        }
    });
    RawSocket { sink, rx }
}

struct RawSocket {
    sink: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Message,
    >,
    rx: tokio::sync::mpsc::UnboundedReceiver<Inbound>,
}

impl RawSocket {
    async fn send_control(&mut self, bytes: &[u8]) {
        use futures_util::SinkExt;
        self.sink
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes.to_vec().into(),
            ))
            .await
            .unwrap();
    }

    async fn send_text(&mut self, text: &str) {
        use futures_util::SinkExt;
        self.sink
            .send(tokio_tungstenite::tungstenite::Message::Text(text.into()))
            .await
            .unwrap();
    }

    async fn closed(&mut self, wait: std::time::Duration) -> Option<Option<u64>> {
        match tokio::time::timeout(wait, self.rx.recv()).await {
            Ok(Some(Inbound::Closed(code))) => Some(code),
            _ => None,
        }
    }
}
