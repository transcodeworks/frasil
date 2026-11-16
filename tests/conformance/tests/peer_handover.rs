//! A library handed over to another peer (peers.md, 3.1 Hosting a space,
//! "Hand-over"; ext-libraries.md, 3.10 The home peer), each peer on a
//! bucket of its own: the operator stops the old peer storing into the
//! library and exports it, imports it at the new peer, and departs the old
//! one. The new peer serves every acknowledged event and object with the
//! same usage, and takes stores; the old one answers `moved` only to a
//! valid proof under a public half the space held, `no_library` to anyone
//! else, `erased` to its genesis, and `moved` to later traffic of a
//! connection granted before. The old peer is one node, then a cluster of
//! three whose routes are answered by nodes that do not own the library's
//! shard.

#![cfg(feature = "ext-libraries")]

mod common;

use common::{DEADLINE, present_current, within};
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{History, object, object_id, stream};
use frasil_events::EventId;
use frasil_libraries::{
    Issuer, LibraryAttach, LibraryId, Purpose as TicketPurpose, Ticket, TrustedIssuers,
};
use frasil_relay::Settings;
use frasil_relay::libraries::{LibrarySettings, LibraryUpdate, OperatorToken};
use frasil_relay::shards::Shards;
use frasil_relay::shards::bucket::{Bucket, BucketIo, MemoryBucket};
use frasil_relay::shards::fence::SingleNode;
use frasil_relay::testing::cluster::{TIMING, TestCluster};
use frasil_relay::testing::{Options, TestPeer, spawn_with};
use frasil_transport::peer::{Purpose, chunk_path, transfer_authorization};
use serde_json::Value as Json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const LIBRARY: &str = "project:handover";
const TOKEN: &str = "operator-token-of-tests";

fn issuer() -> Issuer {
    Issuer::from_seed(&[11; 32])
}

fn settings() -> Settings {
    Settings {
        libraries: LibrarySettings {
            issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
            operator_token: Some(OperatorToken::new(TOKEN).unwrap()),
            ..LibrarySettings::default()
        },
        ..frasil_conformance::settings()
    }
}

fn ticket(id: u8) -> Vec<u8> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = issuer();
    issuer.sign(&Ticket {
        library: LibraryId::new(LIBRARY).unwrap(),
        id: [id; 16],
        purpose: TicketPurpose::Create,
        not_after: wall + 3600,
        issuer: *issuer.public(),
        tokens: None,
    })
}

/// A directory of its own for this test run.
fn directory(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("frasil-peer-handover")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One node over a bucket of its own.
async fn single(name: &str) -> TestPeer {
    let bucket: Arc<dyn Bucket> = Arc::new(MemoryBucket::new());
    let io = Arc::new(BucketIo::new(bucket).unwrap());
    let fence = SingleNode::start_with(&io, name, Duration::from_millis(50)).unwrap();
    let shards = Shards::bucket(io, directory(name), Arc::new(fence)).unwrap();
    spawn_with(Options {
        settings: settings(),
        shards: Some(shards),
        ..frasil_conformance::options()
    })
    .await
    .expect("a peer on loopback")
}

/// An operator route: its status and body.
async fn operator(peer: &TestPeer, path: &str, body: Option<Vec<u8>>) -> (u16, Vec<u8>) {
    let client = frasil_conformance::http_client();
    let url = format!("{}/frasil/p1/libraries/{LIBRARY}/{path}", peer.origin);
    let request = match body {
        Some(body) => client.post(url).body(body),
        None if path == "usage" => client.get(url),
        None => client.post(url),
    };
    let response = request
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.bytes().await.unwrap().to_vec())
}

fn json(body: &[u8]) -> Json {
    serde_json::from_slice(body).unwrap_or(Json::Null)
}

/// What the old peer held: the space, every event acknowledged in it, the
/// object stored, and the library's usage.
struct Held {
    space: EventId,
    acked: Vec<EventId>,
    locator: [u8; 64],
    piece: Vec<u8>,
    used: u64,
}

/// A device on `peer` that creates the space by a ticket, stores the whole
/// credentials history and an object, and stays connected, granted.
async fn fill(peer: &TestPeer, history: &mut History) -> (PeerClient, Held) {
    let space = history.space();
    let mut device = PeerClient::ws(peer, Purpose::SpaceTraffic).await;
    let request = device.request();
    let attach = LibraryAttach {
        request,
        space: *space.as_bytes(),
        purpose: TicketPurpose::Create,
        signed: ticket(1),
    }
    .encode();
    device
        .request_answer(request, &attach)
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
    // The second request retires the removal's entry in turn; the store
    // right, and the transfer token, come from the current state's.
    present_current(&mut device, history).await;
    let unit = history.unit("V", "V writes", stream("notes"), Vec::new(), None, &[]);
    acked.extend(device.store(space, vec![unit], DEADLINE).await);
    // An object of one piece, over HTTP, by the transfer token.
    let (piece, locator) = object(object_id("handed over"), 2_000, space);
    let token = device.tokens[&space];
    let response = frasil_conformance::http_client()
        .put(format!(
            "{}{}",
            peer.origin,
            chunk_path(space.as_bytes(), &locator, 0)
        ))
        .header("Authorization", transfer_authorization(&token))
        .body(piece.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 201, "the object is stored");
    let (status, usage) = operator(peer, "usage", None).await;
    assert_eq!(status, 200);
    let used = json(&usage)["used_bytes"].as_u64().unwrap();
    assert!(used > 0);
    (
        device,
        Held {
            space,
            acked,
            locator,
            piece,
            used,
        },
    )
}

/// The hand-over, from the old peer's nodes `old` (devices on the first,
/// the routes on the others in turn) to `new`.
async fn hand_over(old: &[&TestPeer], new: &TestPeer) {
    let mut history = History::credentials();
    let (mut granted, held) = fill(old[0], &mut history).await;
    let space = held.space;
    let route = |n: usize| old[n % old.len()];
    // Export: the library takes no store from now on.
    let (status, bundle) = operator(route(1), "handover/export", Some(Vec::new())).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bundle));
    let late = history.unit("V", "V writes late", stream("notes"), Vec::new(), None, &[]);
    assert_eq!(
        granted.store_answer(space, &late, DEADLINE).await,
        Some(Err("busy".into())),
        "a library being handed over stores nothing"
    );
    // Resumed and exported again, it stores meanwhile.
    let (status, _) = operator(route(2), "handover/resume", Some(Vec::new())).await;
    assert_eq!(status, 200);
    assert_eq!(
        granted.store_answer(space, &late, DEADLINE).await,
        Some(Ok(()))
    );
    let mut acked = held.acked.clone();
    acked.push(frasil_events::decode(&late).unwrap().id());
    let (status, usage) = operator(route(1), "usage", None).await;
    assert_eq!(status, 200);
    let used = json(&usage)["used_bytes"].as_u64().unwrap();
    assert!(used > held.used);
    let (status, bundle) = operator(route(1), "handover/export", Some(Vec::new())).await;
    assert_eq!(status, 200);
    // Import at the new peer.
    let (status, body) = operator(new, "handover/import", Some(bundle.clone())).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["spaces"], 1);
    // A second import is refused: the library is there.
    let (status, _) = operator(new, "handover/import", Some(bundle)).await;
    assert_eq!(status, 409);
    // Depart the old peer.
    let (status, body) = operator(route(2), "handover/depart", Some(Vec::new())).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    // Re-sent after a lost answer, the step answers as it did.
    let (status, again) = operator(route(2), "handover/depart", Some(Vec::new())).await;
    assert_eq!((status, json(&again)), (200, json(&body)));
    // The new peer serves all of it, with the same usage, once.
    assert!(new.peer.hosts(space.as_bytes()));
    for id in &acked {
        assert!(
            new.peer.keeps(space.as_bytes(), id.as_bytes()),
            "{id:?} was acknowledged and is at the new peer"
        );
    }
    assert!(new.peer.holds_object(space.as_bytes(), &held.locator));
    let (status, usage) = operator(new, "usage", None).await;
    assert_eq!(status, 200);
    let usage = json(&usage);
    assert_eq!(usage["used_bytes"].as_u64(), Some(used), "{usage}");
    assert_eq!(usage["spaces"], 1);
    // The old peer: the library is gone, and its space answers by proof.
    let (status, _) = operator(route(1), "usage", None).await;
    assert_eq!(status, 404);
    let upload = history.upload_seed(&history.order[0]);
    let mut stranger = PeerClient::ws(old[0], Purpose::SpaceTraffic).await;
    assert_eq!(
        stranger
            .present(space, Credential::Upload, &upload)
            .await
            .err()
            .as_deref(),
        Some("moved"),
        "a valid proof under a key the space held learns it moved"
    );
    assert_eq!(
        stranger
            .present(space, Credential::Upload, &[42; 32])
            .await
            .err()
            .as_deref(),
        Some("no_library"),
        "any other proof learns nothing"
    );
    let reader = history.read_seed(&history.order[0]);
    assert_eq!(
        stranger
            .present(space, Credential::Read, &reader)
            .await
            .err()
            .as_deref(),
        Some("moved")
    );
    let genesis = history.signed(&history.order[0]);
    let mut creator = PeerClient::ws(old[0], Purpose::SpaceTraffic).await;
    assert_eq!(
        creator.store_answer(space, &genesis, DEADLINE).await,
        Some(Err("erased".into())),
        "a space handed over is not created again"
    );
    let after = history.unit(
        "V",
        "V writes after",
        stream("notes"),
        Vec::new(),
        None,
        &[],
    );
    assert_eq!(
        granted.store_answer(space, &after, DEADLINE).await,
        Some(Err("moved".into())),
        "a connection granted before the hand-over is told the space moved"
    );
    // At the new peer the space takes stores, and its object is served.
    let mut device = PeerClient::ws(new, Purpose::SpaceTraffic).await;
    let current = history.upload_seed("V rotates, citing W's rotation");
    device
        .present(space, Credential::Upload, &current)
        .await
        .expect("the same entries at the new peer");
    assert_eq!(
        device.store_answer(space, &after, DEADLINE).await,
        Some(Ok(()))
    );
    device
        .present(
            space,
            Credential::Read,
            &history.read_seed("V rotates, citing W's rotation"),
        )
        .await
        .expect("the current read key at the new peer");
    let token = device.tokens[&space];
    let response = frasil_conformance::http_client()
        .get(format!(
            "{}{}",
            new.origin,
            chunk_path(space.as_bytes(), &held.locator, 0)
        ))
        .header("Authorization", transfer_authorization(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.bytes().await.unwrap().to_vec(), held.piece);
    for device in [granted, stranger, creator, device] {
        device.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_library_handed_over_between_two_single_nodes_moves_whole() {
    within(async {
        let old = single("old").await;
        let new = single("new").await;
        hand_over(&[&old], &new).await;
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_import_leaves_a_library_this_peer_configured_alone() {
    within(async {
        let old = single("configured-old").await;
        let new = single("configured-new").await;
        let mut history = History::credentials();
        fill(&old, &mut history).await;
        let library = LibraryId::new(LIBRARY).unwrap();
        new.peer
            .set_library(
                &library,
                LibraryUpdate {
                    quota: Some(Some(1)),
                    ..LibraryUpdate::default()
                },
            )
            .unwrap();
        let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
        assert_eq!(status, 200);
        let (status, body) = operator(&new, "handover/import", Some(bundle)).await;
        assert_eq!(status, 409, "{}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["code"], "exists");
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_library_handed_over_from_a_cluster_moves_whole() {
    within(async {
        let cluster = TestCluster::start_with(3, TIMING, 21, settings())
            .await
            .expect("three nodes form a cluster");
        let shard = {
            let hex: String = LIBRARY.bytes().map(|b| format!("{b:02x}")).collect();
            format!("libraries/{hex}")
        };
        let owner = cluster
            .index_of(cluster.node(0).cluster.owner(&shard).unwrap())
            .unwrap();
        // Devices on the owner, the routes on the other two nodes.
        let mut order = vec![owner];
        order.extend((0..3).filter(|n| *n != owner));
        let old: Vec<&TestPeer> = order.iter().map(|n| &cluster.node(*n).peer).collect();
        let new = single("new-of-cluster").await;
        hand_over(&old, &new).await;
        new.shutdown().await;
        cluster.shutdown().await;
    })
    .await;
}

/// Waits for a future, within the client's deadline.
async fn wait<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// A device that syncs a space at the old peer follows it to the new one
/// once the library is handed over: the old peer answers `moved`, no peer
/// the device knows hosts the space, so it reports the move; its
/// application then names the new home peer, as the issuer does
/// (ext-libraries.md, 3.10 The home peer), and the device syncs there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_follows_its_space_to_the_new_home_peer() {
    use frasil::{Device, Event, Options as DeviceOptions, Storage};
    let old = single("device-old").await;
    let new = single("device-new").await;
    let alice = Device::open_with(Storage::Memory, &[5; 32], DeviceOptions::new().loopback())
        .await
        .unwrap();
    alice.set_library_ticket(ticket(9)).unwrap();
    let space = alice.create_space().await.unwrap();
    let id = EventId(*space.id().as_bytes());
    let synced_at = |origin: &str| {
        alice.peers().iter().any(|peer| {
            let status = peer.status();
            peer.url() == origin && status.connected && status.spaces.contains(&space.id())
        })
    };
    let link = alice.connect(&old.origin).await.unwrap();
    let doc = space.create_document().unwrap();
    doc.edit(|d| d.get_text("body").insert(0, "before"))
        .await
        .unwrap();
    wait(async {
        while !(synced_at(&old.origin) && space.is_durable().await) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(old.peer.hosts(id.as_bytes()));
    link.close();
    for step in ["handover/export", "handover/import", "handover/depart"] {
        let (peer, body) = match step {
            "handover/import" => {
                let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
                assert_eq!(status, 200);
                (&new, Some(bundle))
            }
            _ => (&old, Some(Vec::new())),
        };
        let (status, answer) = operator(peer, step, body).await;
        assert_eq!(status, 200, "{step}: {}", String::from_utf8_lossy(&answer));
    }
    // The old peer answers `moved`; the device knows no other peer.
    let mut events = alice.events();
    alice.connect(&old.origin).await.unwrap();
    let reported = wait(async {
        loop {
            if let Some(Event::Moved { space }) = events.next().await {
                break space;
            }
        }
    })
    .await;
    assert_eq!(reported, space.id());
    // Its application names the new home, and the device syncs there, on
    // a connection of its own that carries that space alone.
    space.set_home_peer(&new.origin).await.unwrap();
    doc.edit(|d| d.get_text("body").insert(0, "after "))
        .await
        .unwrap();
    wait(async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(new.peer.hosts(id.as_bytes()));
    assert!(!old.peer.hosts(id.as_bytes()));
    alice.close().await.unwrap();
    old.shutdown().await;
    new.shutdown().await;
}

/// One node over a bucket of its own, and its shards.
async fn single_with_shards(name: &str) -> (TestPeer, Arc<Shards>) {
    let bucket: Arc<dyn Bucket> = Arc::new(MemoryBucket::new());
    let io = Arc::new(BucketIo::new(bucket).unwrap());
    let fence = SingleNode::start_with(&io, name, Duration::from_millis(50)).unwrap();
    let shards = Shards::bucket(io, directory(name), Arc::new(fence)).unwrap();
    let peer = spawn_with(Options {
        settings: settings(),
        shards: Some(shards.clone()),
        ..frasil_conformance::options()
    })
    .await
    .expect("a peer on loopback");
    (peer, shards)
}

fn ticket_for(library: &str, purpose: TicketPurpose, id: u8) -> Vec<u8> {
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
fn library_shard(library: &str) -> String {
    let hex: String = library.bytes().map(|b| format!("{b:02x}")).collect();
    format!("libraries/{hex}")
}

/// An HTTP request written by hand on a fresh connection, and the status
/// of the answer, within five seconds.
async fn raw_status(peer: &TestPeer, request: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(peer.http).await.ok()?;
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut answer = vec![0; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut answer))
        .await
        .ok()?
        .ok()?;
    let line = String::from_utf8_lossy(&answer[..read]).to_string();
    line.split(' ').nth(1)?.parse().ok()
}

/// The hand-over's import route reads no body before the operator's token
/// checks, and refuses a bundle whose first item is over the item limit
/// without reading the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_import_route_reads_a_body_only_once_the_token_checks() {
    within(async {
        let peer = single("limits").await;
        let path = format!("/frasil/p1/libraries/{LIBRARY}/handover/import");
        let anyone =
            format!("POST {path} HTTP/1.1\r\nHost: peer\r\nContent-Length: 1000000000\r\n\r\nabc");
        assert_eq!(raw_status(&peer, &anyone).await, Some(401));
        let operator = format!(
            "POST {path} HTTP/1.1\r\nHost: peer\r\nAuthorization: Bearer {TOKEN}\r\n\
             Content-Length: 4294967296\r\n\r\n\u{ff}\u{ff}"
        );
        // The two characters are four bytes, a length far over the limit.
        assert_eq!(raw_status(&peer, &operator).await, Some(400));
        peer.shutdown().await;
    })
    .await;
}

/// A space a move took into the library is handed over with its offset
/// record, so that its timeline goes on at the new peer (overview.md, 6.7
/// Policy values and a peer's clock).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_moved_into_the_library_is_handed_over_with_its_timeline() {
    within(async {
        let (old, old_shards) = single_with_shards("moved-old").await;
        let new = single("moved-new").await;
        let history = History::credentials();
        let space = history.space();
        let mut device = PeerClient::ws(&old, Purpose::SpaceTraffic).await;
        let attach = |purpose, signed: Vec<u8>, request| {
            LibraryAttach {
                request,
                space: *space.as_bytes(),
                purpose,
                signed,
            }
            .encode()
        };
        let request = device.request();
        let created = attach(
            TicketPurpose::Create,
            ticket_for("project:before", TicketPurpose::Create, 1),
            request,
        );
        device
            .request_answer(request, &created)
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
        acked.extend(
            device
                .store(
                    space,
                    history.events(&[history.order[1].as_str()]),
                    DEADLINE,
                )
                .await,
        );
        let request = device.request();
        let moving = attach(
            TicketPurpose::Move,
            ticket_for(LIBRARY, TicketPurpose::Move, 2),
            request,
        );
        device
            .request_answer(request, &moving)
            .await
            .expect("the move is accepted");
        // The space's offset record is in the library's shard.
        let shard = library_shard(LIBRARY);
        let mut offset = vec![b'k'];
        offset.extend_from_slice(space.as_bytes());
        let rows = {
            let shards = old_shards.clone();
            let shard = shard.clone();
            tokio::task::spawn_blocking(move || shards.scan_in(&shard, &offset))
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(rows.len(), 1, "the move kept the space's offset");
        let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
        assert_eq!(status, 200);
        let (status, body) = operator(&new, "handover/import", Some(bundle)).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let (status, _) = operator(&old, "handover/depart", Some(Vec::new())).await;
        assert_eq!(status, 200);
        for id in &acked {
            assert!(new.peer.keeps(space.as_bytes(), id.as_bytes()));
        }
        device.close().await;
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}

/// An import that stopped part way, leaving records of the bundle's
/// spaces in the library's shard and, after its first commit, their
/// attachments in the index with no hosted row, is made again: what it
/// left is cleared or written over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_import_that_stopped_part_way_is_made_again() {
    within(async {
        let old = single("again-old").await;
        let (new, new_shards) = single_with_shards("again-new").await;
        let mut history = History::credentials();
        let (device, held) = fill(&old, &mut history).await;
        let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
        assert_eq!(status, 200);
        // What a first import left: a record of the space, and its shard's
        // timeline taken up, with nothing in the index.
        let mut leftover = vec![b'j'];
        leftover.extend_from_slice(held.space.as_bytes());
        leftover.extend_from_slice(&u64::MAX.to_be_bytes());
        {
            let shards = new_shards.clone();
            let shard = library_shard(LIBRARY);
            tokio::task::spawn_blocking(move || {
                shards.commit_into(&shard, vec![(leftover, vec![0])], Vec::new())
            })
            .await
            .unwrap()
            .unwrap();
        }
        // And the first commit of the index: the space's attachment, with
        // no hosted row. A peer started afterwards reads it.
        let attachment = {
            use frasil_base::cbor::{Map, Value};
            let mut at = Map::new();
            at.insert(1, Value::Unsigned(1));
            at.insert(2, Value::Unsigned(1));
            let mut map = Map::new();
            map.insert(1, Value::from(LIBRARY));
            map.insert(3, Value::Map(at));
            Value::Map(map).encode()
        };
        let mut address = vec![b'l', b'S'];
        address.extend_from_slice(held.space.as_bytes());
        let seeded = frasil_store::Store::commit(
            &*new_shards,
            &frasil_store::Commit::new(vec![(address, attachment)], Vec::new()),
        )
        .await
        .unwrap();
        assert!(seeded);
        new.shutdown().await;
        let new = spawn_with(Options {
            settings: settings(),
            shards: Some(new_shards.clone()),
            ..frasil_conformance::options()
        })
        .await
        .expect("a peer on loopback");
        let (status, body) = operator(&new, "handover/import", Some(bundle)).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        for id in &held.acked {
            assert!(new.peer.keeps(held.space.as_bytes(), id.as_bytes()));
        }
        let rows = {
            let shards = new_shards.clone();
            let shard = library_shard(LIBRARY);
            let mut prefix = vec![b'j'];
            prefix.extend_from_slice(held.space.as_bytes());
            tokio::task::spawn_blocking(move || shards.scan_in(&shard, &prefix))
                .await
                .unwrap()
                .unwrap()
        };
        assert!(
            rows.iter()
                .all(|(address, _)| !address.ends_with(&u64::MAX.to_be_bytes())),
            "what the first import left is gone"
        );
        device.close().await;
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}

/// A bundle that stops before its end, at an item's boundary or inside an
/// item, is refused `malformed`, and puts no piece and names no space; the
/// whole bundle imports after it. The ticket that attached the space comes
/// with the bundle, so the new peer refuses it for another space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundle_cut_short_is_refused_and_its_tickets_come_along() {
    within(async {
        let old = single("short-old").await;
        let new = single("short-new").await;
        let mut history = History::credentials();
        let (device, held) = fill(&old, &mut history).await;
        let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
        assert_eq!(status, 200);
        // The end item is `u32 1 || [0]`, six bytes.
        for cut in [6, 7] {
            let short = bundle[..bundle.len() - cut].to_vec();
            let (status, body) = operator(&new, "handover/import", Some(short)).await;
            assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
            assert_eq!(json(&body)["code"], "malformed");
            assert!(!new.peer.hosts(held.space.as_bytes()));
            assert!(!new.peer.holds_object(held.space.as_bytes(), &held.locator));
        }
        let (status, body) = operator(&new, "handover/import", Some(bundle)).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert!(new.peer.holds_object(held.space.as_bytes(), &held.locator));
        // The ticket that created the space is used at the new peer too.
        let other = History::skeleton().space();
        let mut fresh = PeerClient::ws(&new, Purpose::SpaceTraffic).await;
        let request = fresh.request();
        let attach = LibraryAttach {
            request,
            space: *other.as_bytes(),
            purpose: TicketPurpose::Create,
            signed: ticket(1),
        }
        .encode();
        assert!(
            fresh.request_answer(request, &attach).await.is_err(),
            "a ticket used at the old peer is used at the new one"
        );
        fresh.close().await;
        device.close().await;
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}

/// An import of a space this peer erased is refused `erased`, not
/// `exists` (ext-libraries.md, section 5), and puts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_import_of_an_erased_space_is_refused_erased() {
    within(async {
        let old = single("erased-old").await;
        let new = single("erased-new").await;
        let mut history = History::credentials();
        let (device, held) = fill(&old, &mut history).await;
        let (other, _) = fill(&new, &mut history).await;
        // The new peer's administrator erases the space.
        let mut admin = PeerClient::ws(&new, Purpose::Administration).await;
        admin
            .present_pseudonym(held.space, &history.seed("P0"), &history.device_id("P0"))
            .await
            .expect("the administrator's pseudonym");
        let gone = history.storage(
            "P0",
            "P0 erases the space",
            &frasil_conformance::history::erase_space(),
            &[],
        );
        assert!(admin.store_one(held.space, &gone, DEADLINE).await);
        assert!(new.peer.erased(held.space.as_bytes()));
        admin.close().await;
        let (status, bundle) = operator(&old, "handover/export", Some(Vec::new())).await;
        assert_eq!(status, 200);
        let (status, body) = operator(&new, "handover/import", Some(bundle)).await;
        assert_eq!(status, 410, "{}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["code"], "erased");
        device.close().await;
        other.close().await;
        old.shutdown().await;
        new.shutdown().await;
    })
    .await;
}
