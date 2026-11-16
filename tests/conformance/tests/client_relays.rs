//! A device's home relays (transport.md, "The server binding" and "The
//! iroh binding"): a device whose application names none takes those its
//! first peer's discovery document names, whether or not that peer serves
//! the iroh binding, and keeps an application's own. Nothing leaves the
//! host.

use frasil::{Device, Options, Storage};
use frasil_relay::testing::{Options as PeerOptions, TestPeer, spawn_with};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// A peer that serves the server binding alone and names its embedded
/// relay.
async fn peer_naming_its_relay() -> TestPeer {
    spawn_with(PeerOptions {
        iroh: false,
        iroh_relay: true,
        ..frasil_conformance::options()
    })
    .await
    .unwrap()
}

async fn relays_become(device: &Device, expected: &[String]) {
    tokio::time::timeout(DEADLINE, async {
        while device.relays() != expected {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("within the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_relay_takes_its_peers() {
    let peer = peer_naming_its_relay().await;
    let url = peer.relay_url.clone().expect("the relay runs");
    let device = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback())
        .await
        .unwrap();
    assert!(device.relays().is_empty());
    // The member endpoint is bound before the peer names a relay.
    device.discover_locally().await.unwrap();
    device.connect(&peer.origin).await.unwrap();
    relays_become(&device, std::slice::from_ref(&url)).await;

    // A second peer that names another relay changes nothing.
    let other = peer_naming_its_relay().await;
    device.connect(&other.origin).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(device.relays(), [url]);

    device.close().await.unwrap();
    other.shutdown().await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_keeps_the_relays_its_application_names() {
    let peer = peer_naming_its_relay().await;
    let own = "http://127.0.0.1:9".to_owned();
    let device = Device::open_with(
        Storage::Memory,
        &[1; 32],
        Options::new().loopback().relay(own.clone()),
    )
    .await
    .unwrap();
    device.connect(&peer.origin).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(device.relays(), [own]);
    device.close().await.unwrap();
    peer.shutdown().await;
}
