//! A ticket's move of a space between two libraries, each its own shard
//! (ext-libraries.md, 3.3 Attaching, Move): on one node over a bucket, and
//! across the owners of a cluster, whose source, target and index owners
//! crash at each step of the move. Every acknowledged event ends at the
//! owner of the one shard the index names, no other node holds the space,
//! no move stays under way, the space takes stores again, and the two
//! libraries' usage counts it once.

#![cfg(feature = "ext-libraries")]

mod common;

use common::{DEADLINE, within};
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{History, object, object_id, stream};
use frasil_events::EventId;
use frasil_libraries::{
    Issuer, LibraryAttach, LibraryId, Purpose as TicketPurpose, Ticket, TrustedIssuers,
};
use frasil_relay::Settings;
use frasil_relay::libraries::{LibrarySettings, OperatorToken};
use frasil_relay::shards::Shards;
use frasil_relay::shards::bucket::{Bucket, BucketIo, MemoryBucket};
use frasil_relay::shards::fence::SingleNode;
use frasil_relay::testing::cluster::{TIMING, TestCluster};
use frasil_relay::testing::{
    MoveStep, Options, TestPeer, hold_move, move_one_row_per_page, spawn_with,
};
use frasil_transport::peer::{Purpose, chunk_path, transfer_authorization};
use serde_json::Value as Json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TOKEN: &str = "operator-token-of-tests";

fn issuer() -> Issuer {
    Issuer::from_seed(&[13; 32])
}

fn settings() -> Settings {
    Settings {
        libraries: LibrarySettings {
            issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
            operator_token: Some(OperatorToken::new(TOKEN).unwrap()),
            // A library of kind `tiny` holds a byte.
            default_quotas: [("tiny".to_owned(), 1)].into_iter().collect(),
            ..LibrarySettings::default()
        },
        ..frasil_conformance::settings()
    }
}

fn ticket(library: &str, purpose: TicketPurpose, id: u8) -> Vec<u8> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = issuer();
    issuer.sign(&Ticket {
        library: LibraryId::new(library).unwrap(),
        id: [id; 16],
        purpose,
        not_after: wall + 3600,
        issuer: *issuer.public(),
        tokens: None,
    })
}

/// A library's shard name, as the peer makes it.
fn shard(library: &str) -> String {
    let hex: String = library.bytes().map(|b| format!("{b:02x}")).collect();
    format!("libraries/{hex}")
}

fn directory(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("frasil-peer-moves")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A library's usage through `peer`'s operator route: its `spaces` and
/// `used_bytes`, both 0 for a library the peer does not know.
async fn usage(peer: &TestPeer, library: &str) -> (u64, u64) {
    let response = frasil_conformance::http_client()
        .get(format!(
            "{}/frasil/p1/libraries/{library}/usage",
            peer.origin
        ))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap();
    if response.status().as_u16() == 404 {
        return (0, 0);
    }
    assert_eq!(response.status().as_u16(), 200);
    let body: Json = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    (
        body["spaces"].as_u64().unwrap(),
        body["used_bytes"].as_u64().unwrap(),
    )
}

/// `LibraryAttach` of `space` on `device`: its answer. A `busy` answer is
/// sent again a little later, as a device does: a cluster that has just
/// formed may still be placing its shards.
async fn attach(
    device: &mut PeerClient,
    space: EventId,
    library: &str,
    purpose: TicketPurpose,
    id: u8,
) -> Result<(), String> {
    for _ in 0..20 {
        let request = device.request();
        let message = LibraryAttach {
            request,
            space: *space.as_bytes(),
            purpose,
            signed: ticket(library, purpose, id),
        }
        .encode();
        match device.request_answer(request, &message).await {
            Err(code) if code == "busy" => tokio::time::sleep(Duration::from_millis(250)).await,
            answer => return answer.map(|_| ()),
        }
    }
    Err("busy".into())
}

/// A device on `peer` that creates the space in `library`, stores the
/// credentials history and a unit, and stays connected, granted. Returns
/// it and every event acknowledged.
async fn fill(peer: &TestPeer, history: &mut History, library: &str) -> (PeerClient, Vec<EventId>) {
    let space = history.space();
    let mut device = PeerClient::ws(peer, Purpose::SpaceTraffic).await;
    attach(&mut device, space, library, TicketPurpose::Create, 1)
        .await
        .expect("the create is accepted");
    let genesis = history.signed(&history.order[0]);
    assert!(device.store_one(space, &genesis, DEADLINE).await);
    device
        .present(
            space,
            Credential::Upload,
            &history.upload_seed(&history.order[0]),
        )
        .await
        .expect("the genesis's upload key");
    let mut acked = vec![space];
    for name in history.order[1..].iter().cloned() {
        if name == "W forks" {
            continue;
        }
        acked.extend(
            device
                .store(space, history.events(&[name.as_str()]), DEADLINE)
                .await,
        );
        // P0's first request, carried out as soon as it is stored, retires
        // the genesis's entry and keeps the removal's: the store right goes
        // on under that one (peers.md, 3.6 Retirement and the cap,
        // "Connections").
        if name == "P0 asks to keep the removal's entry live" {
            device
                .present(
                    space,
                    Credential::Upload,
                    &history.upload_seed("P removes W"),
                )
                .await
                .expect("the removal's upload key");
        }
    }
    // The current upload key, as a device presents once it rotated: what
    // a gateway presents again at another owner. The second request retired
    // the removal's entry.
    device
        .present(
            space,
            Credential::Upload,
            &history.upload_seed("V rotates, citing W's rotation"),
        )
        .await
        .expect("the current upload key");
    let unit = history.unit("V", "V writes", stream("notes"), Vec::new(), None, &[]);
    acked.extend(device.store(space, vec![unit], DEADLINE).await);
    (device, acked)
}

/// A fresh device on `peer` that presents the space's current upload key
/// and stores a unit: whether it was acknowledged.
async fn stores_again(peer: &TestPeer, history: &mut History, text: &str) -> bool {
    let space = history.space();
    let mut device = PeerClient::ws(peer, Purpose::SpaceTraffic).await;
    let current = history.upload_seed("V rotates, citing W's rotation");
    if device
        .present(space, Credential::Upload, &current)
        .await
        .is_err()
    {
        device.close().await;
        return false;
    }
    let unit = history.unit("V", text, stream("notes"), Vec::new(), None, &[]);
    let stored = device.store_one(space, &unit, DEADLINE).await;
    device.close().await;
    stored
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_on_one_node_takes_the_space_into_the_other_librarys_shard() {
    within(async {
        let bucket: Arc<dyn Bucket> = Arc::new(MemoryBucket::new());
        let io = Arc::new(BucketIo::new(bucket).unwrap());
        let fence = SingleNode::start_with(&io, "moves", Duration::from_millis(50)).unwrap();
        let shards = Shards::bucket(io, directory("one-node"), Arc::new(fence)).unwrap();
        let peer = spawn_with(Options {
            settings: settings(),
            shards: Some(shards.clone()),
            ..frasil_conformance::options()
        })
        .await
        .expect("a peer on loopback");
        let (from, to) = ("project:from", "project:to");
        let mut history = History::credentials();
        let space = history.space();
        let (mut device, acked) = fill(&peer, &mut history, from).await;
        let (spaces, used) = usage(&peer, from).await;
        assert_eq!(spaces, 1);
        assert!(used > 0);
        // A target whose headroom does not hold the space refuses it, and
        // the move is abandoned: the space stays, and stores.
        assert_eq!(
            attach(&mut device, space, "tiny:full", TicketPurpose::Move, 4).await,
            Err("quota_exceeded".into())
        );
        assert!(!peer.peer.moving(space.as_bytes()));
        assert_eq!(usage(&peer, from).await, (1, used));
        assert_eq!(usage(&peer, "tiny:full").await.0, 0);
        // The headroom is checked before the ticket is recorded: it stays
        // unused (ext-libraries.md, 3.3 Attaching, Move).
        assert!(!peer.peer.library_tickets_used().contains(&[4; 16]));
        attach(&mut device, space, to, TicketPurpose::Move, 2)
            .await
            .expect("the move is accepted");
        // The index names the target's shard, which keeps every record.
        let located = {
            let shards = shards.clone();
            tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(located, Some(shard(to)));
        assert!(!peer.peer.moving(space.as_bytes()));
        for id in &acked {
            assert!(peer.peer.holds(space.as_bytes(), id.as_bytes()));
        }
        // The usage moved whole, and counts once.
        assert_eq!(usage(&peer, from).await, (0, 0));
        assert_eq!(usage(&peer, to).await, (1, used));
        // The granted connection stores on, into the new shard.
        let unit = history.unit(
            "V",
            "V writes after",
            stream("notes"),
            Vec::new(),
            None,
            &[],
        );
        assert_eq!(
            device.store_answer(space, &unit, DEADLINE).await,
            Some(Ok(()))
        );
        // A move back takes it into the first shard again.
        attach(&mut device, space, from, TicketPurpose::Move, 3)
            .await
            .expect("the move back is accepted");
        assert_eq!(usage(&peer, to).await, (0, 0));
        assert_eq!(usage(&peer, from).await.0, 1);
        assert!(stores_again(&peer, &mut history, "V writes once back").await);
        device.close().await;
        peer.shutdown().await;
    })
    .await;
}

/// Two libraries, named after `test`, whose shards nodes `x` and `y` own,
/// and, with `apart`, whose space's index shard a third node owns.
fn libraries(cluster: &TestCluster, space: EventId, test: &str, apart: bool) -> (String, String) {
    let owner = |library: &str| {
        let id = cluster.node(0).cluster.owner(&shard(library)).unwrap();
        cluster.index_of(id).unwrap()
    };
    let index = {
        let name = Shards::address_shard("index", space.as_bytes());
        let id = cluster.node(0).cluster.owner(&name).unwrap();
        cluster.index_of(id).unwrap()
    };
    for n in 0..256 {
        let from = format!("project:{test}-from-{n}");
        for m in 0..64 {
            let to = format!("project:{test}-to-{m}");
            let (x, y) = (owner(&from), owner(&to));
            if x != y && (!apart || (index != x && index != y)) {
                return (from, to);
            }
        }
    }
    panic!("no two libraries owned apart");
}

/// Waits until the space is settled in one shard: no move under way, the
/// two libraries counting it once, and the owner of the shard the index
/// names holding every acknowledged event, which no other node holds.
/// Sweeps every node meanwhile, which carries a move left under way on.
async fn settled(
    cluster: &TestCluster,
    live: &[usize],
    space: EventId,
    acked: &[EventId],
    from: &str,
    to: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        for &n in live {
            cluster.node(n).peer.peer.sweep().await;
        }
        let shards = cluster.node(live[0]).shards.clone();
        let located = tokio::task::spawn_blocking(move || shards.locate_fresh(space.as_bytes()))
            .await
            .unwrap()
            .ok()
            .flatten();
        let moving = cluster.node(live[0]).peer.peer.moving(space.as_bytes());
        if let Some(placed) = located
            && !moving
            && let Some(at) = cluster
                .node(live[0])
                .cluster
                .owner(&placed)
                .and_then(|id| cluster.index_of(id))
            && live.contains(&at)
        {
            let at_owner = acked.iter().all(|id| {
                cluster
                    .node(at)
                    .peer
                    .peer
                    .holds(space.as_bytes(), id.as_bytes())
            });
            let elsewhere = live.iter().filter(|n| **n != at).any(|n| {
                acked.iter().any(|id| {
                    cluster
                        .node(*n)
                        .peer
                        .peer
                        .holds(space.as_bytes(), id.as_bytes())
                })
            });
            let peer = &cluster.node(live[0]).peer;
            let (a, _) = usage(peer, from).await;
            let (b, _) = usage(peer, to).await;
            if at_owner && !elsewhere && a + b == 1 {
                assert!(placed == shard(from) || placed == shard(to), "{placed}");
                return placed;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the space settled in one shard after the move"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_across_owners_keeps_every_event_once_and_counts_usage_once() {
    within(async {
        let cluster = TestCluster::start_with(3, TIMING, 31, settings())
            .await
            .expect("three nodes form a cluster");
        let mut history = History::credentials();
        let space = history.space();
        let (from, to) = libraries(&cluster, space, "across", false);
        let owner = |library: &str| {
            cluster
                .index_of(cluster.node(0).cluster.owner(&shard(library)).unwrap())
                .unwrap()
        };
        let (x, y) = (owner(&from), owner(&to));
        let gateway = (0..3).find(|n| *n != x && *n != y).unwrap();
        let (mut device, acked) = fill(&cluster.node(gateway).peer, &mut history, &from).await;
        let (spaces, used) = usage(&cluster.node(y).peer, &from).await;
        assert_eq!(spaces, 1);
        attach(&mut device, space, &to, TicketPurpose::Move, 2)
            .await
            .expect("the move is accepted");
        let placed = settled(&cluster, &[0, 1, 2], space, &acked, &from, &to).await;
        assert_eq!(placed, shard(&to));
        for n in 0..3 {
            assert_eq!(usage(&cluster.node(n).peer, &to).await, (1, used));
            assert_eq!(usage(&cluster.node(n).peer, &from).await, (0, 0));
        }
        // The connection that moved it stores on, at the target's owner.
        let unit = history.unit(
            "V",
            "V writes after",
            stream("notes"),
            Vec::new(),
            None,
            &[],
        );
        assert_eq!(
            device.store_answer(space, &unit, DEADLINE).await,
            Some(Ok(()))
        );
        let id = frasil_events::decode(&unit).unwrap().id();
        assert!(
            cluster
                .node(y)
                .peer
                .peer
                .holds(space.as_bytes(), id.as_bytes())
        );
        assert!(
            !cluster
                .node(x)
                .peer
                .peer
                .holds(space.as_bytes(), id.as_bytes())
        );
        device.close().await;
        cluster.shutdown().await;
    })
    .await;
}

/// A space that holds an object another space of its library stores, moved
/// to a library owned by another node: the object is copied into the
/// target's library, which counts it once, and the library the source
/// stays in counts the source alone (ext-libraries.md, 3.8 "Holds across a
/// move"). The single-process `a_hold_across_two_libraries_points_at_a_copy`
/// covers the ledger; this runs the move over the cluster's links.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_of_a_holding_space_across_owners_copies_the_object_once() {
    within(holding_move(59, false)).await;
}

/// The same move, one record or copy per page, with the target shard's
/// owner killed before the last page: the node that keeps the shard next
/// finds the copy the first page carried in the shard, and records it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_owner_change_mid_move_keeps_the_copies_carried() {
    within(holding_move(61, true)).await;
}

/// A space that holds an object of another space in its library moves to
/// another library, kept by another node; with `target_down`, in pages of
/// one row, and the target shard's owner is killed before the last page.
async fn holding_move(seed: u64, target_down: bool) {
    {
        let mut cluster = TestCluster::start_with(3, TIMING, seed, settings())
            .await
            .expect("three nodes form a cluster");
        let mut source_history = History::credentials();
        let holder_history = History::skeleton();
        let (source, holder) = (source_history.space(), holder_history.space());
        let (from, to) = libraries(&cluster, holder, "holding", false);
        let owner = |library: &str| {
            cluster
                .index_of(cluster.node(0).cluster.owner(&shard(library)).unwrap())
                .unwrap()
        };
        let (x, y) = (owner(&from), owner(&to));
        let gateway = (0..3).find(|n| *n != x && *n != y).unwrap();
        let peer = &cluster.node(gateway).peer;
        let (mut device, _) = fill(peer, &mut source_history, &from).await;
        let (_, source_bare) = usage(peer, &from).await;
        // The source stores an object, by its transfer token.
        let (piece, locator) = object(object_id("held across"), 2_000, source);
        let response = frasil_conformance::http_client()
            .put(format!(
                "{}{}",
                peer.origin,
                chunk_path(source.as_bytes(), &locator, 0)
            ))
            .header(
                "Authorization",
                transfer_authorization(&device.tokens[&source]),
            )
            .body(piece)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201, "the object is stored");
        let (_, source_used) = usage(peer, &from).await;
        let object_bytes = source_used - source_bare;
        assert!(object_bytes > 0);
        // The holder joins the source's library, and holds the object.
        attach(&mut device, holder, &from, TicketPurpose::Create, 3)
            .await
            .expect("the create is accepted");
        let genesis = holder_history.signed(&holder_history.order[0]);
        assert!(device.store_one(holder, &genesis, DEADLINE).await);
        device
            .present(
                holder,
                Credential::Upload,
                &holder_history.upload_seed(&holder_history.order[0]),
            )
            .await
            .expect("the holder's upload key");
        device
            .present(
                source,
                Credential::Read,
                &source_history.read_seed("V rotates, citing W's rotation"),
            )
            .await
            .expect("the source's read credential");
        let request = device.request();
        let hold = frasil_libraries::HoldObject::prove(
            request,
            &device.binding,
            *holder.as_bytes(),
            *source.as_bytes(),
            locator,
            &[7; 32],
        )
        .encode();
        device
            .request_answer(request, &hold)
            .await
            .expect("the hold is accepted");
        let (spaces, both) = usage(peer, &from).await;
        assert_eq!(spaces, 2);
        let holder_used = both - source_used;
        if target_down {
            move_one_row_per_page();
            let hold = hold_move(*holder.as_bytes(), &to, MoveStep::LastPage);
            let moving = {
                let to = to.clone();
                tokio::spawn(async move {
                    let answer = attach(&mut device, holder, &to, TicketPurpose::Move, 2).await;
                    (device, answer)
                })
            };
            tokio::time::timeout(Duration::from_secs(20), hold.reached())
                .await
                .expect("the move reaches its last page");
            cluster.kill(y).await;
            hold.release();
            let answer;
            (device, answer) = tokio::time::timeout(Duration::from_secs(60), moving)
                .await
                .expect("the move is answered")
                .unwrap();
            answer.expect("the move is accepted");
        } else {
            attach(&mut device, holder, &to, TicketPurpose::Move, 2)
                .await
                .expect("the move is accepted");
        }
        // Every node counts the holder once, in the target's library, with
        // one copy of the object; the source stays in its library alone.
        for n in (0..3).filter(|n| !target_down || *n != y) {
            let node = &cluster.node(n).peer;
            assert_eq!(usage(node, &from).await, (1, source_used));
            assert_eq!(
                usage(node, &to).await,
                (1, holder_used + object_bytes),
                "the copy is counted once at the target"
            );
        }
        device.close().await;
        cluster.shutdown().await;
    }
}

/// Which node crashes, and at which step of the move.
#[derive(Debug, Clone, Copy)]
enum Crash {
    Source(MoveStep),
    Target,
    Index,
}

async fn crash_during_a_move(crash: Crash, seed: u64) {
    let mut cluster = TestCluster::start_with(3, TIMING, seed, settings())
        .await
        .expect("three nodes form a cluster");
    let mut history = History::credentials();
    let space = history.space();
    let test = format!("{crash:?}")
        .to_lowercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
    let (from, to) = libraries(&cluster, space, &test, true);
    let owner = |cluster: &TestCluster, name: &str| {
        cluster
            .index_of(cluster.node(0).cluster.owner(name).unwrap())
            .unwrap()
    };
    let x = owner(&cluster, &shard(&from));
    let y = owner(&cluster, &shard(&to));
    let w = owner(&cluster, &Shards::address_shard("index", space.as_bytes()));
    let (victim, step) = match crash {
        Crash::Source(step) => (x, step),
        Crash::Target => (y, MoveStep::Naming),
        Crash::Index => (w, MoveStep::Naming),
    };
    let gateway = (0..3).find(|n| *n != victim).unwrap();
    let (mut device, acked) = fill(&cluster.node(gateway).peer, &mut history, &from).await;
    let hold = hold_move(*space.as_bytes(), &to, step);
    let moving = {
        let to = to.clone();
        tokio::spawn(async move {
            let answer = attach(&mut device, space, &to, TicketPurpose::Move, 2).await;
            (device, answer)
        })
    };
    tokio::time::timeout(Duration::from_secs(20), hold.reached())
        .await
        .expect("the move reaches the step");
    cluster.kill(victim).await;
    hold.release();
    let live: Vec<usize> = (0..3).filter(|n| *n != victim).collect();
    let (device, answer) = tokio::time::timeout(Duration::from_secs(60), moving)
        .await
        .expect("the move is answered")
        .unwrap();
    let placed = settled(&cluster, &live, space, &acked, &from, &to).await;
    // Accepted means moved; a refusal may still have been carried on.
    if answer.is_ok() {
        assert_eq!(placed, shard(&to), "{crash:?}: an accepted move is made");
    }
    // The index is settled; the owner it names may still be taking the
    // space up, so a store refused is tried again, with a fresh device,
    // for a while. One that never takes stores fails here.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempt = 0;
    while !stores_again(
        &cluster.node(live[0]).peer,
        &mut history,
        &format!("V writes after, attempt {attempt}"),
    )
    .await
    {
        assert!(
            Instant::now() < deadline,
            "{crash:?}: the space takes stores where the index names it"
        );
        attempt += 1;
        for &n in &live {
            cluster.node(n).peer.peer.sweep().await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    device.close().await;
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_crashes_once_the_move_is_recorded_leaves_it_to_the_next_owner() {
    within(crash_during_a_move(Crash::Source(MoveStep::Recorded), 41)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_crashes_before_the_last_page_leaves_it_to_the_next_owner() {
    within(crash_during_a_move(Crash::Source(MoveStep::LastPage), 43)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_that_crashes_before_the_index_names_it_leaves_one_shard() {
    within(crash_during_a_move(Crash::Target, 47)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_index_owner_that_crashes_as_the_target_names_itself_leaves_one_shard() {
    within(crash_during_a_move(Crash::Index, 53)).await;
}

/// A library's settings through `peer`'s settings route: its status and
/// JSON body. `change` is a `PUT`'s body; none is a `GET`.
async fn settings_route(peer: &TestPeer, library: &str, change: Option<&str>) -> (u16, Json) {
    let client = frasil_conformance::http_client();
    let url = format!("{}/frasil/p1/libraries/{library}/settings", peer.origin);
    let request = match change {
        Some(change) => client.put(url).body(change.to_owned()),
        None => client.get(url),
    };
    let response = request
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Json::Null);
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settings_set_through_any_node_close_and_reopen_the_library_at_its_owner() {
    within(async {
        let cluster = TestCluster::start_with(3, TIMING, 37, settings())
            .await
            .expect("three nodes form a cluster");
        let mut history = History::credentials();
        let space = history.space();
        let (library, _) = libraries(&cluster, space, "settings", false);
        let owner = cluster
            .index_of(cluster.node(0).cluster.owner(&shard(&library)).unwrap())
            .unwrap();
        let other = (0..3).find(|n| *n != owner).unwrap();
        let (device, _) = fill(&cluster.node(owner).peer, &mut history, &library).await;
        device.close().await;
        // A bound already past, set through a node that does not own the
        // library's shard, closes the library for every node.
        let (status, body) = settings_route(
            &cluster.node(other).peer,
            &library,
            Some(r#"{"open_until":1}"#),
        )
        .await;
        assert_eq!((status, &body["open"]), (200, &Json::Bool(false)), "{body}");
        for n in 0..3 {
            let (status, body) = settings_route(&cluster.node(n).peer, &library, None).await;
            assert_eq!(status, 200);
            assert_eq!(body["open_until"], 1, "node {n}");
            // A writer of its own, whose only parent is the genesis, so that
            // no later unit cites what was refused.
            let mut device = PeerClient::ws(&cluster.node(n).peer, Purpose::SpaceTraffic).await;
            device
                .present(
                    space,
                    Credential::Upload,
                    &history.upload_seed("V rotates, citing W's rotation"),
                )
                .await
                .expect("the current upload key");
            let genesis = history.order[0].clone();
            let unit = history.unit(
                &format!("closed writer {n}"),
                &format!("closed at {n}"),
                stream("notes"),
                Vec::new(),
                None,
                &[&genesis],
            );
            assert_eq!(
                device.store_answer(space, &unit, DEADLINE).await,
                Some(Err("library_closed".into())),
                "node {n}"
            );
            device.close().await;
        }
        // Cleared through another node, it takes stores again.
        let third = (0..3).find(|n| *n != owner && *n != other).unwrap();
        let (status, body) = settings_route(
            &cluster.node(third).peer,
            &library,
            Some(r#"{"open_until":null}"#),
        )
        .await;
        assert_eq!((status, &body["open"]), (200, &Json::Bool(true)), "{body}");
        assert!(stores_again(&cluster.node(other).peer, &mut history, "reopened").await);
        cluster.shutdown().await;
    })
    .await;
}
