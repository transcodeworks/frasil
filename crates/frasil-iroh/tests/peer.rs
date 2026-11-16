//! The device-to-peer handshake (transport.md, section 3.10) over loopback
//! QUIC: on `frasil/p1/peer` the peer, the listener, opens the control
//! stream and sends `PeerHello` first (section 3.16); the device, the
//! dialer, accepts the stream and answers with `Hello`. Both ends derive
//! the same `binding` from the connection's channel.

mod common;

use common::*;
use frasil_iroh::{Alpn, Role};
use frasil_transport::Code;
use frasil_transport::codes::Service;
use frasil_transport::frame::MessageType;
use frasil_transport::peer::{DeviceSide, Limits, PeerSide, Purpose};

fn random<const N: usize>() -> [u8; N] {
    *frasil_crypto::random_bytes::<N>().unwrap()
}

#[tokio::test]
async fn the_peer_opens_the_control_stream_and_its_peer_hello_arrives_first() {
    let (_device_endpoint, _peer_endpoint, device, peer) = pair(Alpn::Peer).await;
    assert_eq!(device.role(), Role::Dialer);
    assert_eq!(peer.role(), Role::Listener);
    assert!(peer.opens_control());
    assert!(!device.opens_control());
    assert_eq!(device.channel(), peer.channel());

    let peer_end = async {
        let (mut sender, mut receiver) = peer.control().await.unwrap();
        let (mut side, hello) = PeerSide::start_with(
            peer.channel(),
            random(),
            &[Service::Relay, Service::Store],
            &Limits::PROTOCOL,
        );
        // 1. Send PeerHello, before anything has arrived.
        sender.send(&hello).await.unwrap();
        let message = receiver.receive().await.unwrap().expect("the Hello");
        assert_eq!(message.kind, MessageType::Hello);
        // 2 to 5.
        let binding = side.on_hello(&message).unwrap();
        assert_eq!(side.purpose(), Some(Purpose::SpaceTraffic));
        (binding, sender, receiver)
    };
    let device_end = async {
        // The device accepts the stream the peer opened; its first frame
        // is the PeerHello.
        let (mut sender, mut receiver) = device.control().await.unwrap();
        let first = receiver.receive().await.unwrap().expect("a first frame");
        assert_eq!(first.kind, MessageType::PeerHello);
        let side =
            DeviceSide::answer_with(&device.channel(), &first, random(), Purpose::SpaceTraffic)
                .unwrap();
        sender.send(&side.hello).await.unwrap();
        (side, sender, receiver)
    };
    let ((binding, _peer_sender, _peer_receiver), (side, _sender, _receiver)) =
        within(async { tokio::join!(peer_end, device_end) }).await;
    assert_eq!(binding, side.binding);

    device.close(Code::Done);
    assert_eq!(within(peer.closed()).await.code(), Some(Code::Done));
}
