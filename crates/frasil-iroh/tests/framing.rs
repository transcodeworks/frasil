//! transport.json's `framing` family on real sockets: each frame crosses a
//! loopback QUIC connection on a stream of its class, and the receiving
//! end reads, refuses or drops it as section 3.1 says. A refusal closes the
//! connection with section 2.5's code, which the sending end sees.

mod common;

use common::*;
use frasil_base::Class;
use frasil_iroh::{Alpn, Connection, Endpoint, Error, FrameReceiver, FrameSender, Lossy, Stream};
use frasil_transport::Code;
use frasil_transport::frame::{MessageType, StreamClass, frame};
use frasil_transport::messages::{Pairing, Scope};
use serde_json::Value as Json;

fn alpn(connection: &str) -> Alpn {
    match connection {
        "member" => Alpn::Member,
        "peer" => Alpn::Peer,
        "nearby" => Alpn::Nearby,
        other => panic!("connection {other}"),
    }
}

fn scope(alpn: Alpn) -> Scope {
    match alpn {
        Alpn::Member => Scope::Attach(0),
        Alpn::Peer | Alpn::Nearby => Scope::Space([7; 32]),
    }
}

/// Two loopback endpoints: the listener takes every ALPN.
struct Pair {
    dialer: Endpoint,
    listener: Endpoint,
}

impl Pair {
    async fn new() -> Self {
        Self {
            dialer: endpoint(&[]).await,
            listener: endpoint(&Alpn::ALL).await,
        }
    }

    async fn connect(&self, alpn: Alpn) -> (Connection, Connection) {
        connect(&self.dialer, &self.listener, alpn).await
    }
}

/// A stream of a class, with its sending half (after its `Open`, for a
/// class that has one), its receiving half, and the sending end's
/// connection. The control and nearby streams go from the end that opens
/// them, the peer on a device-to-peer connection, and carry their first
/// frame before the other end sees them, so the frame is written first.
/// Every other stream goes from the dialer to the listener.
async fn stream<'a>(
    dialer: &'a Connection,
    listener: &'a Connection,
    class: StreamClass,
    first: &[u8],
) -> (FrameSender, FrameReceiver, &'a Connection) {
    within(async {
        match class {
            StreamClass::Control | StreamClass::Nearby => {
                let (opener, acceptor) = if dialer.opens_control() {
                    (dialer, listener)
                } else {
                    (listener, dialer)
                };
                assert!(!acceptor.opens_control());
                let (mut sender, _) = opener.control().await.unwrap();
                sender.write_bytes(first).await.unwrap();
                let (_, receiver) = acceptor.control().await.unwrap();
                assert_eq!(receiver.class(), class);
                (sender, receiver, opener)
            }
            StreamClass::Sync => {
                let (mut sender, _) = dialer.open_sync(scope(dialer.alpn())).await.unwrap();
                sender.write_bytes(first).await.unwrap();
                let Stream::Sync {
                    scope: got,
                    receiver,
                    ..
                } = listener.accept_stream().await.unwrap()
                else {
                    panic!("a sync stream")
                };
                assert_eq!(got, scope(dialer.alpn()));
                (sender, receiver, dialer)
            }
            StreamClass::Object => {
                let mut sender = dialer.open_object(scope(dialer.alpn())).await.unwrap();
                sender.write_bytes(first).await.unwrap();
                let Stream::Object {
                    scope: got,
                    receiver,
                } = listener.accept_stream().await.unwrap()
                else {
                    panic!("an object stream")
                };
                assert_eq!(got, scope(dialer.alpn()));
                (sender, receiver, dialer)
            }
            StreamClass::Ephemeral => {
                let mut sender = dialer.open_ephemeral().await.unwrap();
                sender.write_bytes(first).await.unwrap();
                let Stream::Ephemeral { receiver } = listener.accept_stream().await.unwrap() else {
                    panic!("an ephemeral stream")
                };
                (sender, receiver, dialer)
            }
        }
    })
    .await
}

fn class(name: &str) -> StreamClass {
    StreamClass::from_name(name).expect("a stream class")
}

#[tokio::test]
async fn framing_examples_cross_real_streams() {
    let family = family("framing");
    let pair = Pair::new().await;
    for case in family["examples"].as_array().unwrap() {
        let description = text(&case["description"]);
        let data = bytes(&case["frame"]);
        let class = class(text(&case["stream"]));
        let alpn = alpn(text(&case["connection"]));
        let (dialer, listener) = pair.connect(alpn).await;
        // Written in two pieces, the second split from the first inside
        // the prefix, so the receiver reads a frame however it arrives.
        let (mut sender, mut receiver, _) = stream(&dialer, &listener, class, &data[..3]).await;
        sender.write_bytes(&data[3..]).await.unwrap();
        // The same frame again, through the sender's own framing.
        sender.send(&data[4..]).await.unwrap();
        sender.finish().unwrap();
        for _ in 0..2 {
            let message = within(receiver.receive())
                .await
                .unwrap_or_else(|e| panic!("{description}: {e}"))
                .unwrap_or_else(|| panic!("{description}: a message"));
            assert_eq!(frame(&message.bytes), data, "{description}");
        }
        assert_eq!(within(receiver.receive()).await, Ok(None), "{description}");
        dialer.close(Code::Done);
        assert_eq!(within(listener.closed()).await.code(), Some(Code::Done));
    }
}

#[tokio::test]
async fn ephemeral_examples_cross_as_datagrams() {
    let family = family("framing");
    let pair = Pair::new().await;
    let ephemeral: Vec<&Json> = family["examples"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| text(&case["stream"]) == "ephemeral")
        .collect();
    assert_eq!(ephemeral.len(), 2);
    for case in ephemeral {
        let description = text(&case["description"]);
        let data = bytes(&case["frame"]);
        let (dialer, listener) = pair.connect(alpn(text(&case["connection"]))).await;
        assert!(dialer.max_datagram_size().is_some(), "{description}");
        // On a message channel one message is one frame, with no prefix.
        let message = &data[4..];
        assert_eq!(
            within(dialer.send_lossy(message)).await,
            Ok(Lossy::Datagram)
        );
        let received = within(listener.receive_datagram()).await.unwrap();
        assert_eq!(received.kind, MessageType::Ephemeral, "{description}");
        assert_eq!(received.bytes, message, "{description}");
    }
}

#[tokio::test]
async fn lossy_messages_too_large_for_a_datagram_take_the_ephemeral_stream() {
    let pair = Pair::new().await;
    let (dialer, listener) = pair.connect(Alpn::Member).await;
    let size = dialer.max_datagram_size().unwrap();
    let message = frasil_transport::messages::Ephemeral {
        scope: Scope::Attach(0),
        frame: vec![0x5a; size + 100],
        origin: None,
    }
    .encode();
    assert!(message.len() > size);
    assert_eq!(within(dialer.send_lossy(&message)).await, Ok(Lossy::Stream));
    let Stream::Ephemeral { mut receiver } = within(listener.accept_stream()).await.unwrap() else {
        panic!("the ephemeral stream")
    };
    let received = within(receiver.receive()).await.unwrap().unwrap();
    assert_eq!(received.bytes, message);
    // A message that is not an Ephemeral, or one with an origin on a member
    // connection, is not sent.
    let gone = frasil_transport::messages::Ephemeral {
        scope: Scope::Attach(0),
        frame: vec![1],
        origin: Some([0; 8]),
    }
    .encode();
    assert_eq!(
        within(dialer.send_lossy(&gone)).await.unwrap_err().code(),
        Some(Code::Malformed)
    );
}

/// The receiver's failure, and the code the sending end sees the connection
/// closed with.
async fn refusal(sending: &Connection, receiver: &mut FrameReceiver) -> (Error, Error) {
    let error = within(receiver.receive()).await.unwrap_err();
    let closed = within(sending.closed()).await;
    (error, closed)
}

#[tokio::test]
async fn framing_caps_on_real_streams() {
    let pair = Pair::new().await;
    for case in family("framing")["caps"].as_array().unwrap() {
        let prefix = bytes(&case["prefix"]);
        let class = class(text(&case["stream"]));
        let alpn = match class {
            StreamClass::Nearby => Alpn::Nearby,
            StreamClass::Ephemeral => Alpn::Member,
            _ => Alpn::Peer,
        };
        let (dialer, listener) = pair.connect(alpn).await;
        let (mut sender, mut receiver, sending) = stream(&dialer, &listener, class, &prefix).await;
        match text(&case["result"]) {
            // A prefix at the cap is read on: the stream ending there
            // leaves a frame cut short, not one over the cap.
            "read on" => {
                sender.finish().unwrap();
                assert_eq!(
                    within(receiver.receive()).await,
                    Err(Error::Truncated),
                    "{class:?}"
                );
            }
            expected => {
                let (error, closed) = refusal(sending, &mut receiver).await;
                assert_eq!(error.class().map(Class::name), Some(expected), "{class:?}");
                assert_eq!(closed.code(), Some(Code::TooLarge), "{class:?}");
                assert_eq!(closed, Error::ClosedByPeer(Code::TooLarge.number()));
            }
        }
    }
}

#[tokio::test]
async fn framing_refusals_close_the_connection_with_their_code() {
    let family = family("framing");
    let pair = Pair::new().await;
    for case in family["refused"].as_array().unwrap() {
        let description = text(&case["description"]);
        let data = bytes(&case["frame"]);
        let (dialer, listener) = pair.connect(alpn(text(&case["connection"]))).await;
        let (_sender, mut receiver, sending) =
            stream(&dialer, &listener, class(text(&case["stream"])), &data).await;
        let (error, closed) = refusal(sending, &mut receiver).await;
        let expected = text(&case["error"]);
        assert_eq!(
            error.class().map(Class::name),
            Some(expected),
            "{description}"
        );
        let code = error.code().unwrap();
        assert_eq!(closed.code(), Some(code), "{description}");
        let wire = if expected == "UnknownMessage" {
            "malformed"
        } else {
            error.class().map(Class::wire_name).unwrap()
        };
        assert_eq!(code.name(), wire, "{description}");
    }
    for case in family["dropped"].as_array().unwrap() {
        let data = bytes(&case["frame"]);
        let (dialer, listener) = pair.connect(alpn(text(&case["connection"]))).await;
        let (mut sender, mut receiver, _) =
            stream(&dialer, &listener, class(text(&case["stream"])), &data).await;
        sender.finish().unwrap();
        // Dropped, and the stream reads on to its end.
        assert_eq!(within(receiver.receive()).await, Ok(None));
        assert_eq!(text(&case["result"]), "dropped");
    }
}

#[tokio::test]
async fn a_second_ephemeral_stream_from_one_end_is_accepted() {
    let pair = Pair::new().await;
    let (dialer, listener) = pair.connect(Alpn::Member).await;
    let message = |byte: u8| {
        frasil_transport::messages::Ephemeral {
            scope: Scope::Attach(0),
            frame: vec![byte; 8],
            origin: None,
        }
        .encode()
    };
    for byte in [1, 2] {
        let mut sender = within(dialer.open_ephemeral()).await.unwrap();
        within(sender.send(&message(byte))).await.unwrap();
        let Stream::Ephemeral { mut receiver } = within(listener.accept_stream()).await.unwrap()
        else {
            panic!("an ephemeral stream")
        };
        let received = within(receiver.receive()).await.unwrap().unwrap();
        assert_eq!(received.bytes, message(byte));
    }
}

/// In setup the device being set up, the listener, writes first, so it
/// opens the nearby stream and the dialer accepts it (transport.md,
/// section 3.16): `control` answers for pairing only.
#[tokio::test]
async fn in_setup_the_listener_opens_the_nearby_stream() {
    within(async {
        let pair = Pair::new().await;
        let (dialer, listener) = pair.connect(Alpn::Nearby).await;
        assert!(dialer.opens_control() && !listener.opens_control());
        let hello = Pairing {
            message: vec![1, 2, 3],
            ticket: None,
        };
        let (mut sender, _) = listener.open_control().await.unwrap();
        sender.send(&hello.encode()).await.unwrap();
        let (_, mut receiver) = dialer.accept_control().await.unwrap();
        assert_eq!(receiver.class(), StreamClass::Nearby);
        let message = receiver.receive().await.unwrap().unwrap();
        assert_eq!(Pairing::read(&message).unwrap(), hello);
    })
    .await;
}
