//! A device that fetches an object over the server binding's HTTP chunk
//! routes (transport.md, "Objects over HTTP") through a proxy on loopback
//! that can cut the transfer, corrupt a slice or hold one back: each
//! sealed chunk is kept as its slices arrive, a fetch cut part way resumes
//! after the chunks kept, even once the device is opened again, and a
//! corrupted slice keeps nothing. A range of chunks is fetched from any
//! index, ahead of a download that runs beside the connection; a fetch
//! that is cancelled stops before its next slice; and a fetch leaves out
//! the chunks the device holds, wherever they are. Every wait has a
//! deadline, and nothing leaves the host.

use frasil::advanced::peer::{PeerHandle, connect_server};
use frasil::advanced::{AdapterRegistry, Engine, FetchPriority, Platform};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEADLINE: Duration = Duration::from_secs(90);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
}

/// What the proxy does to the chunk routes, and what it saw of them.
#[derive(Default)]
struct Faults {
    /// Each chunk request's locator, in hex, and slice index, in order.
    asked: Mutex<Vec<(String, u64)>>,
    /// Chunk requests for this slice or a later one end the connection
    /// with no answer.
    cut_from: Mutex<Option<u64>>,
    /// This slice is served with its first byte flipped.
    corrupt: Mutex<Option<u64>>,
    /// Requests for these slices wait, once counted, until they are no
    /// longer held back.
    hold: Mutex<Vec<u64>>,
    /// How many requests the proxy cut.
    cut: AtomicUsize,
}

impl Faults {
    /// The slices asked for of one object, in order.
    fn asked(&self, locator: &[u8; 64]) -> Vec<u64> {
        let hex: String = locator.iter().map(|byte| format!("{byte:02x}")).collect();
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(of, _)| *of == hex)
            .map(|(_, index)| *index)
            .collect()
    }

    fn clear(&self) {
        self.asked.lock().unwrap().clear();
    }

    /// Holds back the requests for these slices, and no others.
    fn hold(&self, slices: &[u64]) {
        *self.hold.lock().unwrap() = slices.to_vec();
    }
}

/// A proxy on loopback in front of `upstream`: it answers chunk requests
/// (`GET …/chunks/{index}`) itself, fetching each from the peer, and
/// passes everything else, the WebSocket among it, through untouched.
async fn spawn_proxy(upstream: &str) -> (String, Arc<Faults>) {
    // ring, the only provider linked, for the proxy's own client.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let faults = Arc::new(Faults::default());
    let upstream = upstream.to_owned();
    let shared = faults.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(
                socket,
                upstream.clone(),
                client.clone(),
                shared.clone(),
            ));
        }
    });
    (origin, faults)
}

/// One connection to the proxy, request by request until one is not a
/// chunk request: from there on, bytes pass both ways as they are.
async fn serve(
    mut socket: TcpStream,
    upstream: String,
    client: reqwest::Client,
    faults: Arc<Faults>,
) {
    let mut buffer = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut piece = [0u8; 8192];
            match socket.read(&mut piece).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&piece[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let request = lines.next().unwrap_or_default().to_owned();
        let mut words = request.split(' ');
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let slice = path
            .split_once("/objects/")
            .and_then(|(_, rest)| rest.split_once("/chunks/"))
            .and_then(|(locator, index)| Some((locator.to_owned(), index.parse::<u64>().ok()?)))
            .filter(|_| method == "GET");
        let Some((locator, index)) = slice else {
            let Ok(mut onward) = TcpStream::connect(upstream.trim_start_matches("http://")).await
            else {
                return;
            };
            if onward.write_all(&buffer).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut onward).await;
            return;
        };
        buffer.drain(..end);
        faults.asked.lock().unwrap().push((locator, index));
        if faults
            .cut_from
            .lock()
            .unwrap()
            .is_some_and(|from| index >= from)
        {
            faults.cut.fetch_add(1, Ordering::SeqCst);
            return;
        }
        while faults.hold.lock().unwrap().contains(&index) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let authorization = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim().to_owned())
            .unwrap_or_default();
        let Ok(response) = client
            .get(format!("{upstream}{path}"))
            .header("Authorization", authorization)
            .send()
            .await
        else {
            return;
        };
        let status = response.status().as_u16();
        let Ok(body) = response.bytes().await else {
            return;
        };
        let mut body = body.to_vec();
        if *faults.corrupt.lock().unwrap() == Some(index)
            && let Some(first) = body.first_mut()
        {
            *first ^= 1;
        }
        let answer = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        if socket.write_all(answer.as_bytes()).await.is_err()
            || socket.write_all(&body).await.is_err()
        {
            return;
        }
    }
}

/// Bob's device, on a store that outlives it.
struct Store {
    store: Arc<MemoryStore>,
    slot: Arc<dyn DeviceBoundSlot>,
    sealed: Vec<u8>,
}

impl Store {
    async fn reopen(&self) -> Engine {
        Engine::open(
            Platform::new(self.store.clone(), self.slot.clone()),
            &self.sealed,
            &[2; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("the device opens again")
    }
}

/// Alice's space with Bob granted "with history", Alice connected to the
/// peer, and a blob of three and a half chunks, four slices, durable there.
async fn setup(
    peer_origin: &str,
) -> (
    Engine,
    PeerHandle,
    Engine,
    Store,
    EventId,
    [u8; 64],
    Vec<u8>,
) {
    setup_with(peer_origin, 3_670_000).await
}

/// A blob of five and a half chunks, which six slices carry: chunk `i`
/// begins in slice `i` and ends in slice `i + 1`, but for chunk 5, which
/// slice 5 ends with.
const SIX_CHUNKS: u32 = 5_770_000;

/// Whether the device holds a chunk of the blob.
async fn holds(device: &Engine, space: &EventId, locator: &[u8; 64], chunk: u64) -> bool {
    device
        .read(space, |replica| replica.holds_chunk(locator, chunk))
        .await
        .unwrap()
}

/// [`setup`] with a blob of `size` bytes.
async fn setup_with(
    peer_origin: &str,
    size: u32,
) -> (
    Engine,
    PeerHandle,
    Engine,
    Store,
    EventId,
    [u8; 64],
    Vec<u8>,
) {
    let alice = Engine::create(
        Platform::memory(),
        &[1; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap()
    .0;
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let (bob, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[2; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    let space = alice.create_space().await.unwrap();
    alice
        .grant_device(
            space,
            bob.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    bob.follow(space).await;
    bob.ingest(space, alice.events(&space).await).await.unwrap();
    let alice_link = connect_server(&alice, peer_origin, vec![space])
        .await
        .unwrap();
    let big: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let stream = alice.new_stream("frasil:blobs").unwrap();
    let (_, locator) = alice
        .put_blob(space, &stream, Some("big.bin"), &big)
        .await
        .unwrap();
    until(|| async { alice.outbox(&space).await.is_empty() }).await;
    let store = Store {
        store,
        slot,
        sealed: sealed.to_vec(),
    };
    (alice, alice_link, bob, store, space, locator, big)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_cut_part_way_resumes_after_the_chunks_kept() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, store, space, locator, big) = setup(&peer.origin).await;

    // Slices 0 to 2 arrive, which carry chunks 0 and 1; slice 3 never does.
    *faults.cut_from.lock().unwrap() = Some(3);
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { faults.cut.load(Ordering::SeqCst) > 0 }).await;
    assert_eq!(&faults.asked(&locator)[..4], &[0, 1, 2, 3]);
    assert!(bob.object(&space, &locator).await.is_err());
    link.close();
    until(|| async { link.is_closed() }).await;
    drop(link);
    drop(bob);

    // Opened again, Bob asks for slice 2 first: chunk 2 begins there, after
    // the tail of chunk 1, which it keeps.
    *faults.cut_from.lock().unwrap() = None;
    faults.clear();
    let bob = store.reopen().await;
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    assert_eq!(faults.asked(&locator), vec![2, 3]);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupted_slice_keeps_nothing_of_the_object() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, big) = setup(&peer.origin).await;

    // The first byte of slice 2 is the end of chunk 1, which then fails to
    // open: chunk 0, kept, is dropped with it, and the object is missing.
    *faults.corrupt.lock().unwrap() = Some(2);
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { faults.asked(&locator).contains(&2) }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let refused = bob.object(&space, &locator).await.unwrap_err();
    assert_eq!(refused.class_name(), Some("Missing"), "{refused:?}");
    // Not asked of this peer again on this connection.
    assert_eq!(faults.asked(&locator), vec![0, 1, 2]);
    link.close();
    until(|| async { link.is_closed() }).await;

    // Served whole, it is fetched again from slice 0: nothing was kept.
    *faults.corrupt.lock().unwrap() = None;
    faults.clear();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    assert_eq!(faults.asked(&locator), vec![0, 1, 2, 3]);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A download runs beside the connection: while one of its slices is held
/// back, the connection takes the events the peer sends, and a range asked
/// for at a reader's position is fetched ahead of it, from the slice its
/// first chunk begins in. The download then leaves out the chunk it finds
/// held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_is_fetched_ahead_of_a_download_that_runs_beside_the_connection() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (alice, alice_link, bob, _store, space, locator, big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;

    // The download takes slice 0 and waits for slice 1, which ends chunk 0.
    faults.hold(&[1]);
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { faults.asked(&locator) == vec![0, 1] }).await;

    // The connection goes on: a unit Alice writes now reaches Bob.
    let notes = alice.new_stream("frasil:blobs").unwrap();
    let (unit, _) = alice
        .put_blob(space, &notes, Some("note"), b"written meanwhile")
        .await
        .unwrap();
    until(|| async {
        bob.read(&space, |replica| replica.holds(unit))
            .await
            .unwrap()
    })
    .await;

    // Chunk 4, at a reader's position: with no header held yet, slice 0
    // first, then the two slices that carry the chunk.
    let ahead = bob.fetch_chunks(space, locator, 4..5, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 4).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 1, 0, 4, 5]);
    assert!(!holds(&bob, &space, &locator, 0).await);
    assert!(bob.object(&space, &locator).await.is_err());
    assert!(!ahead.is_cancelled());

    // The download goes on to the end, and asks for no slice on account of
    // chunk 4: slice 4 ends chunk 3, and slice 5 is the last chunk.
    faults.hold(&[]);
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    assert_eq!(faults.asked(&locator), vec![0, 1, 0, 4, 5, 2, 3, 4, 5]);
    drop(ahead);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A fetch that is cancelled stops before its next slice: the slice under
/// way is given up, the chunks kept stay, and nothing more is asked for
/// until another request wants it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_fetch_stops_before_its_next_slice() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // Nothing is fetched until it is asked for.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(faults.asked(&locator).is_empty());

    // The whole object, at a reader's position; slice 2 is held back.
    faults.hold(&[2]);
    let fetch = bob.fetch_chunks(space, locator, 0..u64::MAX, FetchPriority::Position);
    until(|| async { faults.asked(&locator) == vec![0, 1, 2] }).await;
    until(|| async { holds(&bob, &space, &locator, 0).await }).await;
    fetch.cancel();
    assert!(fetch.is_cancelled());
    faults.hold(&[]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(faults.asked(&locator), vec![0, 1, 2]);
    assert!(holds(&bob, &space, &locator, 0).await);
    assert!(!holds(&bob, &space, &locator, 1).await);
    assert!(link.status().fetching.is_empty());

    // Another request takes up what is lacking, under the header held.
    let again = bob.fetch_chunks(space, locator, 1..2, FetchPriority::ReadAhead);
    until(|| async { holds(&bob, &space, &locator, 1).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 1, 2, 1, 2]);
    assert!(bob.object(&space, &locator).await.is_err());
    drop(again);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A fetch resumes over holes: a device that holds chunks 3 and 4 alone,
/// opened again, asks for the slices of chunks 0 to 2 and of chunk 5, and
/// not for slice 4, which only chunks it holds begin or end in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_resumes_over_the_chunks_held_wherever_they_are() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, store, space, locator, big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    // Chunks 3 and 4, with slice 5, which ends chunk 4, held back.
    faults.hold(&[5]);
    let ahead = bob.fetch_chunks(space, locator, 3..5, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 3).await }).await;
    until(|| async { faults.asked(&locator) == vec![0, 3, 4, 5] }).await;
    // The progress counts the stored bytes held, not a prefix: the header
    // with its length and one sealed chunk, of the object's stored length.
    let stored = |fetching: Option<(u64, Option<u64>)>| {
        let (held, total) = fetching.expect("the fetch's progress");
        let total = total.expect("the stored length");
        let prefix = total - big.len() as u64 - 6 * 40;
        (held - prefix, prefix)
    };
    let (held, prefix) = stored(link.status().fetching.get(&locator).copied());
    assert_eq!(held, 1 << 20);
    assert!(prefix > 4 && prefix < 1024, "{prefix}");
    faults.hold(&[]);
    until(|| async { holds(&bob, &space, &locator, 4).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 3, 4, 5]);
    drop(ahead);
    link.close();
    until(|| async { link.is_closed() }).await;
    drop(link);
    drop(bob);

    // Opened again, it fetches every object the space's units name.
    faults.clear();
    let bob = store.reopen().await;
    assert!(holds(&bob, &space, &locator, 4).await);
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    assert_eq!(faults.asked(&locator), vec![0, 1, 2, 3, 5]);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A chunk cut from slices carries no header of its own: a fetch that
/// holds none takes slice 0 first and keeps the chunk under the header
/// read there. Then two fetches of neighbouring chunks, which one slice
/// both carries, ask for that slice once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_with_no_header_starts_at_slice_0_and_neighbours_share_a_slice() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // The last chunk alone: slice 0 for the header, then slice 5.
    let last = bob.fetch_chunks(space, locator, 5..6, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 5).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 5]);
    assert!(!holds(&bob, &space, &locator, 0).await);

    // Chunk 1 is in slices 1 and 2, chunk 2 in slices 2 and 3. The first
    // fetch waits for slice 1; the second takes slice 2, which is kept
    // for the first.
    faults.hold(&[1]);
    let first = bob.fetch_chunks(space, locator, 1..2, FetchPriority::Position);
    until(|| async { faults.asked(&locator) == vec![0, 5, 1] }).await;
    let second = bob.fetch_chunks(space, locator, 2..3, FetchPriority::ReadAhead);
    until(|| async { holds(&bob, &space, &locator, 2).await }).await;
    assert!(!holds(&bob, &space, &locator, 1).await);
    faults.hold(&[]);
    until(|| async { holds(&bob, &space, &locator, 1).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 5, 1, 2, 3]);
    drop((last, first, second));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A reader's position does not wait for background fetches: when as many
/// fetches run as a connection runs at once, the last started of the least
/// urgent gives up its slice and waits again, and goes on once the
/// reader's chunk is in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readers_position_takes_the_place_of_a_background_fetch() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    let last = bob.fetch_chunks(space, locator, 5..6, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 5).await }).await;
    assert_eq!(faults.asked(&locator), vec![0, 5]);

    // Four background fetches, one chunk each, whose first slices are
    // held back: as many as the connection runs at once.
    faults.hold(&[0, 1, 2, 3]);
    let mut background = Vec::new();
    for chunk in 0..4 {
        background.push(bob.fetch_chunks(
            space,
            locator,
            chunk..chunk + 1,
            FetchPriority::Background,
        ));
        until(|| async { faults.asked(&locator).len() as u64 == chunk + 3 }).await;
    }
    assert_eq!(faults.asked(&locator), vec![0, 5, 0, 1, 2, 3]);

    // Chunk 4, at a reader's position: the fetch of chunk 3 gives way.
    let position = bob.fetch_chunks(space, locator, 4..5, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 4).await }).await;
    for chunk in 0..4 {
        assert!(!holds(&bob, &space, &locator, chunk).await, "{chunk}");
    }
    // Then it asks for its slice again.
    until(|| async { faults.asked(&locator) == vec![0, 5, 0, 1, 2, 3, 4, 5, 3] }).await;

    faults.hold(&[]);
    until(|| async {
        for chunk in 0..4 {
            if !holds(&bob, &space, &locator, chunk).await {
                return false;
            }
        }
        true
    })
    .await;
    assert!(bob.object(&space, &locator).await.is_ok());
    drop((last, background, position));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}
