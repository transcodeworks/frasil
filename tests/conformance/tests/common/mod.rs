//! What the scenarios share: a peer on loopback, a device on either
//! binding, and timeouts on every wait.

#![allow(dead_code)]

#[cfg(feature = "ext-deposit-tokens")]
pub mod tokens;

use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::History;
use frasil_events::EventId;
use frasil_relay::Settings;
use frasil_relay::testing::{Options, TestPeer, spawn_with};
use frasil_transport::peer::Purpose;
use std::future::Future;
use std::time::Duration;

#[allow(unused_imports)]
pub use frasil_conformance::client::{DEADLINE, QUIET};

/// The longest a whole scenario runs.
pub const SCENARIO: Duration = Duration::from_secs(120);

/// Runs a scenario within its deadline.
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(SCENARIO, future)
        .await
        .expect("the scenario ends within its deadline")
}

/// The two bindings a device reaches a peer by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The server binding's WebSocket.
    WebSocket,
    /// The iroh binding's `frasil/p1/peer`.
    Iroh,
}

/// Both bindings.
pub const BINDINGS: [Binding; 2] = [Binding::WebSocket, Binding::Iroh];

/// A peer on loopback with these settings.
pub async fn peer(settings: Settings) -> TestPeer {
    spawn_with(Options {
        settings,
        ..frasil_conformance::options()
    })
    .await
    .expect("a peer on loopback")
}

/// A device's connection on a binding.
pub async fn connect(peer: &TestPeer, binding: Binding, purpose: Purpose) -> PeerClient {
    match binding {
        Binding::WebSocket => PeerClient::ws(peer, purpose).await,
        Binding::Iroh => PeerClient::iroh(peer, purpose).await,
    }
}

/// A space-traffic connection that created the space from `history`'s
/// genesis and holds the genesis entry's upload key: the store right.
pub async fn founder(peer: &TestPeer, binding: Binding, history: &History) -> PeerClient {
    let space = history.space();
    let mut device = connect(peer, binding, Purpose::SpaceTraffic).await;
    let genesis = history.order[0].clone();
    if !peer.peer.hosts(space.as_bytes()) {
        let acked = device
            .store(space, history.events(&[&genesis]), DEADLINE)
            .await;
        assert_eq!(acked, vec![space], "the genesis creates the space");
    }
    device
        .present(space, Credential::Upload, &history.upload_seed(&genesis))
        .await
        .expect("the genesis's upload key");
    device
}

/// The rotation of the credentials history whose entry its credentials
/// requests keep live: the history's current state once both are carried
/// out.
pub const CURRENT: &str = "V rotates, citing W's rotation";

/// Presents, on a connection that stored the credentials history, the
/// upload key of its current state. Its first credentials request, stable
/// at the peer as soon as it is stored, retires the genesis's entry, and
/// with it the store right and transfer token the genesis's upload key
/// granted (peers.md, 3.6 Retirement and the cap, "Connections").
pub async fn present_current(device: &mut PeerClient, history: &History) {
    device
        .present(
            history.space(),
            Credential::Upload,
            &history.upload_seed(CURRENT),
        )
        .await
        .expect("the current state's upload key");
}

/// Stores events in order, each acknowledged.
pub async fn store_all(device: &mut PeerClient, space: EventId, events: Vec<Vec<u8>>) {
    let ids: Vec<EventId> = events
        .iter()
        .map(|e| frasil_events::decode(e).unwrap().id())
        .collect();
    let acked = device.store(space, events, DEADLINE).await;
    for id in ids {
        assert!(acked.contains(&id), "{id:?} is acknowledged");
    }
}
