//! Device mailboxes at a peer (transport.md, 2.7 Mailboxes and 3.14
//! Mailboxes): anyone deposits, with no credential, "subject to the peer's
//! rate limits". A source past the peer's rate is refused `rate_limited` on
//! every binding, and a peer whose device mailboxes hold its caps refuses
//! new deposits `busy` (2.5 Codes: "the responder's budget") while what it
//! holds stays collectible, across a restart. In a cluster, the node that
//! keeps a mailbox's shard applies the caps, whichever node a deposit
//! reaches.

mod common;

use common::*;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_relay::testing::{Options, spawn_with};
use frasil_relay::{DeviceMailLimits, Settings};
use frasil_store::{MemoryStore, Store};
use frasil_transport::frame::MessageType;
use frasil_transport::mailbox::{self, Kind, MailboxItems, MailboxPut};
use frasil_transport::peer::{Purpose, mailbox_path};
use std::sync::Arc;

/// A device's identity seed and its mailbox's address: `n` names it. Its
/// keys commitment is [`kc`] of the seed.
fn device(n: u32) -> ([u8; 32], [u8; 32]) {
    let mut seed = [0x11u8; 32];
    seed[..4].copy_from_slice(&n.to_be_bytes());
    let signer = Signatory {
        ed: IdentityKey(frasil_crypto::primitives::ed25519_public(&seed)),
        kc: kc(&seed),
    };
    (
        seed,
        mailbox::address(Kind::Device, signer.device_id().as_bytes()),
    )
}

/// A stand-in keys commitment for the device of `seed`: the peer never
/// sees the keys, only that the device ID of `ed || kc` names the mailbox.
fn kc(seed: &[u8; 32]) -> KeysCommitment {
    KeysCommitment(frasil_crypto::primitives::sha256(&[b"kc of ", seed]))
}

/// Deposits `item` in a device mailbox over the server binding, with no
/// credential: the status and the body's reason code, if any.
async fn deposit(origin: &str, address: &[u8; 32], item: Vec<u8>) -> (u16, Option<String>) {
    let response = frasil_conformance::http_client()
        .post(format!("{origin}{}", mailbox_path(3, address)))
        .body(item)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    (status, body["code"].as_str().map(str::to_owned))
}

/// The items a device collects from its own mailbox, over the WebSocket.
async fn collect(peer: &frasil_relay::testing::TestPeer, seed: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut device = connect(peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
    let request = device.request();
    let get = mailbox::collect(request, seed, &kc(seed), &device.binding, None);
    let answer = device
        .request_answer(request, &get)
        .await
        .expect("MailboxItems")
        .expect("a message");
    assert_eq!(answer.kind, MessageType::MailboxItems);
    device.close().await;
    MailboxItems::read(&answer)
        .unwrap()
        .items
        .into_iter()
        .map(|(_, item)| item)
        .collect()
}

fn limits(items: usize, bytes: usize, deposits_per_minute: usize) -> Settings {
    Settings {
        device_mail: DeviceMailLimits {
            items,
            bytes,
            deposits_per_minute,
        },
        ..frasil_conformance::settings()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_depositing_in_many_device_mailboxes_is_rate_limited() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let mut refused = None;
        for n in 0..1_000u32 {
            let (status, code) = deposit(&peer.origin, &device(n).1, vec![0xab; 64]).await;
            if status != 201 {
                refused = Some((n, status, code));
                break;
            }
        }
        let (n, status, code) = refused.expect("the peer stops accepting deposits");
        assert_eq!((status, code.as_deref()), (429, Some("rate_limited")));
        assert_eq!(
            n as usize,
            DeviceMailLimits::DEFAULT.deposits_per_minute,
            "the default rate is reached first"
        );
        // A minute later, the source deposits again.
        peer.advance(60).await;
        assert_eq!(
            deposit(&peer.origin, &device(5_000).1, vec![0xab; 64])
                .await
                .0,
            201
        );
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_source_past_its_rate_is_refused_on_both_bindings() {
    within(async {
        let peer = peer(limits(1 << 16, 256 << 20, 3)).await;
        for binding in BINDINGS {
            let mut stranger = connect(&peer, binding, Purpose::SpaceTraffic).await;
            let mut answers = Vec::new();
            for n in 0..4u32 {
                let request = stranger.request();
                let put = MailboxPut {
                    request,
                    address: device(n).1,
                    item: vec![0xcd; 64],
                    kind: Kind::Device,
                }
                .encode();
                answers.push(stranger.request_answer(request, &put).await);
            }
            assert_eq!(
                answers,
                vec![Ok(None), Ok(None), Ok(None), Err("rate_limited".into())],
                "{binding:?}"
            );
            stranger.close().await;
            peer.advance(60).await;
        }
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_peer_refuses_new_deposits_and_keeps_what_it_holds_across_a_restart() {
    within(async {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let options = |store: &Arc<dyn Store>| Options {
            settings: limits(4, 256 << 20, 1_000),
            store: Some(store.clone()),
            ..frasil_conformance::options()
        };
        let peer = spawn_with(options(&store)).await.unwrap();
        for n in 0..4u32 {
            let item = vec![n as u8; 2000];
            assert_eq!(deposit(&peer.origin, &device(n).1, item).await.0, 201);
        }
        // Full: a deposit in another mailbox is refused, and evicts nothing.
        assert_eq!(
            deposit(&peer.origin, &device(4).1, vec![4; 2000]).await,
            (503, Some("busy".into()))
        );
        assert_eq!(collect(&peer, &device(0).0).await, vec![vec![0u8; 2000]]);
        peer.shutdown().await;

        // Started again on the same records: still full, and every item
        // is read from them when collected.
        let peer = spawn_with(options(&store)).await.unwrap();
        assert_eq!(
            deposit(&peer.origin, &device(4).1, vec![4; 2000]).await,
            (503, Some("busy".into()))
        );
        for n in 0..4u32 {
            assert_eq!(
                collect(&peer, &device(n).0).await,
                vec![vec![n as u8; 2000]]
            );
        }
        // Past mailbox_retention the items go, and there is room again.
        peer.advance(Settings::default().mailbox_retention).await;
        assert!(collect(&peer, &device(0).0).await.is_empty());
        assert_eq!(
            deposit(&peer.origin, &device(4).1, vec![4; 2000]).await.0,
            201
        );
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bytes_cap_refuses_a_deposit_that_would_pass_it() {
    within(async {
        let peer = peer(limits(1 << 16, 300_000, 1_000)).await;
        assert_eq!(
            deposit(&peer.origin, &device(0).1, vec![0; 200_000])
                .await
                .0,
            201
        );
        assert_eq!(
            deposit(&peer.origin, &device(1).1, vec![1; 200_000]).await,
            (503, Some("busy".into()))
        );
        assert_eq!(
            deposit(&peer.origin, &device(1).1, vec![1; 100_000])
                .await
                .0,
            201
        );
        peer.shutdown().await;
    })
    .await;
}

/// In a cluster, each mailbox shard holds an even share of the caps, and
/// the node that keeps a shard decides its deposits, whichever node they
/// reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_a_cluster_the_node_that_keeps_a_mailbox_applies_the_caps() {
    use frasil_relay::shards::Shards;
    use frasil_relay::testing::cluster::{TIMING, TestCluster};
    within(async {
        // 16 items over the 16 mailbox shards: one item each.
        let cluster = TestCluster::start_with(3, TIMING, 21, limits(16, 64 << 20, 1_000))
            .await
            .expect("three nodes form a cluster");
        // Two mailboxes of one shard.
        let shard = Shards::address_shard("mailboxes", &device(0).1);
        let other = (1..10_000u32)
            .find(|&n| Shards::address_shard("mailboxes", &device(n).1) == shard)
            .expect("another mailbox of the shard");
        let owner = (0..3)
            .find(|&n| {
                cluster
                    .node(n)
                    .shards
                    .keeps_address("mailboxes", &device(0).1)
            })
            .expect("a node keeps the shard");
        let gateways: Vec<usize> = (0..3).filter(|&n| n != owner).collect();
        let origin = |n: usize| cluster.node(n).peer.origin.clone();
        assert_eq!(
            deposit(&origin(gateways[0]), &device(0).1, vec![0; 2000])
                .await
                .0,
            201
        );
        for n in [gateways[1], owner] {
            assert_eq!(
                deposit(&origin(n), &device(other).1, vec![1; 2000]).await,
                (503, Some("busy".into())),
                "through node {n}"
            );
        }
        // Another shard has room of its own.
        let elsewhere = (1..10_000u32)
            .find(|&n| Shards::address_shard("mailboxes", &device(n).1) != shard)
            .expect("a mailbox of another shard");
        assert_eq!(
            deposit(&origin(gateways[1]), &device(elsewhere).1, vec![2; 2000])
                .await
                .0,
            201
        );
        cluster.shutdown().await;
    })
    .await;
}
