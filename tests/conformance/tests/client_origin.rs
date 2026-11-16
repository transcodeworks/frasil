//! The server binding's origin (transport.md, "The server binding"): a
//! peer that browsers reach at another site's origin, through its proxy,
//! binds a native client's connection, which sends no `Origin` header, to
//! its native origin, where the client connected. Nothing leaves the host.

use frasil::{Device, Options, Storage};
use frasil_relay::Settings;
use frasil_relay::testing::{Options as PeerOptions, spawn_with};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

const BROWSER_ORIGIN: &str = "https://app.example.org";

/// A free port on loopback, for a peer whose native origin names it.
fn free_address() -> SocketAddr {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_native_connection_with_no_origin_is_accepted() {
    let listen = free_address();
    let native = format!("http://{listen}");
    let peer = spawn_with(PeerOptions {
        settings: Settings {
            origin: Some(BROWSER_ORIGIN.into()),
            native_origin: Some(native.clone()),
            ..frasil_conformance::settings()
        },
        listen,
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    assert_eq!(peer.origin, native);

    // A native device connects at the peer's own origin, with no Origin
    // header: its channel matches the peer's, and it keeps its space
    // there. Bound to the browsers' origin, its handshake would fail.
    let device = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback())
        .await
        .unwrap();
    let space = device.create_space().await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "native"))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("durable at the peer");
    assert!(device.peers()[0].status().connected);

    device.close().await.unwrap();
    peer.shutdown().await;
}
