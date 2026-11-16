//! ext-deposit-tokens.md, 3.10 In a cluster: a peer on several machines is
//! one peer, with one set of keys, one spent-token record per token and
//! one count per library's window. A token whose record and whose mailbox
//! are in shards on different nodes pays once; two spends of one token at
//! once, through two nodes, keep one; draws at every node against one
//! library's window never pass its allowance; and the keys' shard moving
//! to another node keeps the keys, so the tokens drawn before still pay.

#![cfg(feature = "ext-deposit-tokens")]

mod common;

use common::tokens::*;
use common::{DEADLINE, within};
use frasil_conformance::client::PeerClient;
use frasil_deposit_tokens::{Draw, Token};
use frasil_libraries::LibraryId;
use frasil_relay::libraries::LibraryUpdate;
use frasil_relay::shards::Shards;
use frasil_relay::testing::cluster::{TIMING, TestCluster};
use frasil_transport::peer::Purpose;
use std::time::Duration;

/// Long enough for a dead owner's lease to end and its shards to open
/// elsewhere.
const TAKEOVER: Duration = Duration::from_secs(15);

/// The shard the deposit keys are kept in (ext-deposit-tokens.md, 3.10).
const KEYS_SHARD: &str = "index/0";

/// Three nodes, whose keys' keeper has begun the first key: until then,
/// or until its first sweep, the others answer `busy` (ext-deposit-tokens.md,
/// 3.4: a peer that cannot read its keys now).
async fn cluster(seed: u64) -> TestCluster {
    let cluster = TestCluster::start_with(3, TIMING, seed, token_settings())
        .await
        .expect("three nodes form a cluster");
    for n in 0..3 {
        cluster.node(n).peer.peer.sweep().await;
    }
    cluster
}

/// The node that keeps the shard of a mailbox-family key: an address, or
/// a token's nonce.
fn keeper(cluster: &TestCluster, key: &[u8; 32]) -> usize {
    (0..cluster.nodes.len())
        .find(|&n| {
            cluster.nodes[n].is_some() && cluster.node(n).shards.keeps_address("mailboxes", key)
        })
        .expect("a node keeps the shard")
}

/// `count` tokens drawn at node `n` by grant `id`.
async fn tokens_at(cluster: &TestCluster, n: usize, count: usize, id: u8) -> Vec<Token> {
    let peer = &cluster.node(n).peer;
    let mut device = PeerClient::ws(peer, Purpose::SpaceTraffic).await;
    let list = keys(&mut device).await;
    let tokens = draw(
        &mut device,
        &list,
        Draw::Grant(grant(peer, count as u64, id)),
        count,
    )
    .await
    .unwrap();
    device.close().await;
    tokens
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_whose_record_and_mailbox_are_on_different_nodes_pays_once() {
    within(async {
        let cluster = cluster(31).await;
        let tokens = tokens_at(&cluster, 0, 16, 1).await;
        // A recipient, and a token whose nonce's shard another node keeps.
        let bob = recipient(1);
        let mailbox = keeper(&cluster, &bob.address);
        let token = tokens
            .iter()
            .find(|t| keeper(&cluster, &t.nonce()) != mailbox)
            .expect("a token whose record is elsewhere")
            .clone();
        let record = keeper(&cluster, &token.nonce());
        let gateway = (0..3).find(|&n| n != mailbox && n != record).unwrap();
        assert_ne!(
            Shards::address_shard("mailboxes", &bob.address),
            Shards::address_shard("mailboxes", &token.nonce())
        );
        let mut through = PeerClient::ws(&cluster.node(gateway).peer, Purpose::SpaceTraffic).await;
        assert_eq!(
            spend(&mut through, bob.address, b"one", &token).await,
            Ok(())
        );
        // Repeated through each node: the same answer; another item, spent.
        for n in 0..3 {
            let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
            assert_eq!(
                spend(&mut device, bob.address, b"one", &token).await,
                Ok(())
            );
            assert_eq!(
                spend(&mut device, bob.address, b"two", &token).await,
                Err("token_spent".into()),
                "through node {n}"
            );
        }
        // One record, kept where the nonce names.
        let nonce_key = token.key_id();
        let blocking = cluster.node(record).peer.peer.clone();
        let spent = tokio::task::spawn_blocking(move || blocking.spent_tokens().unwrap())
            .await
            .unwrap();
        assert_eq!(spent, [nonce_key]);
        let items = collect(&cluster.node(gateway).peer, &bob).await;
        assert_eq!(items.len(), 1);
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_spends_of_one_token_at_once_through_two_nodes_keep_one() {
    within(async {
        let cluster = cluster(32).await;
        let tokens = tokens_at(&cluster, 1, 8, 1).await;
        for (round, token) in tokens.into_iter().enumerate() {
            let bob = recipient(10 + round as u32);
            let mut a = PeerClient::ws(&cluster.node(0).peer, Purpose::SpaceTraffic).await;
            let mut b = PeerClient::ws(&cluster.node(2).peer, Purpose::SpaceTraffic).await;
            let (first, second) = tokio::join!(
                spend(&mut a, bob.address, b"from a", &token),
                spend(&mut b, bob.address, b"from b", &token),
            );
            let accepted = [&first, &second].iter().filter(|a| a.is_ok()).count();
            assert_eq!(accepted, 1, "round {round}: {first:?} {second:?}");
            for refused in [&first, &second]
                .into_iter()
                .filter_map(|a| a.as_ref().err())
            {
                assert!(
                    refused == "busy" || refused == "token_spent",
                    "round {round}: {refused}"
                );
            }
            // Once settled, the other item is `token_spent`.
            let loser: &[u8] = if first.is_ok() { b"from b" } else { b"from a" };
            assert_eq!(
                spend(&mut a, bob.address, loser, &token).await,
                Err("token_spent".into())
            );
            let items = collect(&cluster.node(1).peer, &bob).await;
            assert_eq!(items.len(), 1, "round {round}");
        }
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn draws_at_every_node_never_pass_the_library_s_allowance() {
    within(async {
        let cluster = cluster(33).await;
        let library = LibraryId::new(LIBRARY).unwrap();
        cluster
            .node(0)
            .peer
            .peer
            .set_library(
                &library,
                LibraryUpdate {
                    deposit_allowance: Some(Some(20)),
                    ..LibraryUpdate::default()
                },
            )
            .unwrap();
        // Nine grants of eight, three at each node, drawn at once.
        let mut lists = Vec::new();
        for n in 0..3 {
            let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
            lists.push(keys(&mut device).await);
        }
        let mut draws = Vec::new();
        for id in 0..9u8 {
            let n = usize::from(id % 3);
            let list = lists[n].clone();
            let grant = grant(&cluster.node(n).peer, 8, id + 1);
            let node = &cluster.node(n).peer;
            let mut device = PeerClient::ws(node, Purpose::SpaceTraffic).await;
            draws.push(async move { draw(&mut device, &list, Draw::Grant(grant), 8).await });
        }
        let results = futures_util::future::join_all(draws).await;
        let drawn: usize = results.iter().map(|r| r.as_ref().map_or(0, Vec::len)).sum();
        assert_eq!(drawn, 20, "{results:?}");
        for refused in results.iter().filter_map(|r| r.as_ref().err()) {
            assert!(
                refused == "allowance_exhausted" || refused == "busy",
                "{refused}"
            );
        }
        // The ledger, at the node that keeps the library, counts them all.
        let ledger = (0..3)
            .find_map(|n| cluster.node(n).peer.peer.ledger(&library))
            .expect("a node keeps the library");
        assert_eq!(ledger.deposit.unwrap().tokens_drawn, 20);
        cluster.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keys_shard_moving_to_another_node_keeps_the_keys() {
    within(async {
        let mut cluster = cluster(34).await;
        let keeper = (0..3)
            .find(|&n| cluster.node(n).shards.keeps_shard(KEYS_SHARD))
            .expect("a node keeps the keys");
        let survivor = (0..3).find(|&n| n != keeper).unwrap();
        let mut tokens = tokens_at(&cluster, survivor, 8, 1).await;
        let mut device = PeerClient::ws(&cluster.node(survivor).peer, Purpose::SpaceTraffic).await;
        let before = keys(&mut device).await;
        device.close().await;
        cluster.kill(keeper).await;
        cluster.settle(TAKEOVER).await.expect("the cluster settles");
        let heir = (0..3)
            .find(|&n| cluster.nodes[n].is_some() && cluster.node(n).shards.keeps_shard(KEYS_SHARD))
            .expect("another node keeps the keys");
        assert_ne!(heir, keeper);
        // Every node lists the same keys, and the tokens drawn before pay.
        for n in (0..3).filter(|&n| n != keeper) {
            let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
            let after = keys(&mut device).await;
            assert_eq!(after.issuing().id, before.issuing().id, "node {n}");
            let bob = recipient(20 + n as u32);
            let token = tokens.pop().unwrap();
            let answer =
                tokio::time::timeout(DEADLINE, spend(&mut device, bob.address, b"x", &token))
                    .await
                    .unwrap();
            assert_eq!(answer, Ok(()), "node {n}");
        }
        cluster.shutdown().await;
    })
    .await;
}
