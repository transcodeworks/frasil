//! A device that fetches an object over the server binding's HTTP chunk
//! routes (transport.md, "Objects over HTTP") through a proxy on loopback
//! that can cut the transfer, corrupt a slice or hold one back: each
//! sealed chunk is kept as its slices arrive, a fetch cut part way resumes
//! after the chunks kept, even once the device is opened again, and a
//! corrupted slice keeps nothing. A range of chunks is fetched from any
//! index, ahead of a download that runs beside the connection; a fetch
//! that is cancelled stops before its next slice; and a fetch leaves out
//! the chunks the device holds, wherever they are. A device that holds
//! its blobs as files takes an object in order, whichever chunks are
//! asked for. A request whose transfer is cut is tried again after a
//! wait, which only its own progress starts over, and one whose slices
//! the peer sends wrong is given up for good, which its holder hears,
//! as does the holder of a request made afterwards. Two fetches that end
//! one object leave it whole, a space paused while a fetch runs fetches
//! nothing more until it is resumed, and a read that waits for a blob
//! released meanwhile asks for it again. Every wait has a deadline, and
//! nothing leaves the host.

#[path = "../../../crates/frasil/tests/support/provider.rs"]
mod provider;

use frasil::advanced::peer::{PeerHandle, connect_server};
use frasil::advanced::{AdapterRegistry, Engine, FetchEnd, FetchPriority, Platform};
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
    /// Chunk requests for these slices end the connection with no answer.
    cut_only: Mutex<Vec<u64>>,
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
            || faults.cut_only.lock().unwrap().contains(&index)
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

/// A device that holds its blobs as files takes an object in order from
/// chunk 0 (at-rest.md, "Held objects", receiving): a range asked for at
/// chunk 4 is fetched from slice 0 through the slices of chunk 4, each
/// chunk after the first checked under the header the receive holds, and
/// the connection reports the bytes written. A later range goes on from
/// where the receive stands, and the file is the blob once it is whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_range_of_an_object_held_as_a_file_is_fetched_in_order() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    let files = provider::DirProvider::new(provider::temp_dir("slices-held"));
    bob.hold_all_objects(files.clone());
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    // Bob knows the blob once its entry is current in its stream.
    until(|| async {
        bob.read(&space, |replica| replica.streams().next().is_some())
            .await
            .unwrap()
    })
    .await;

    // Chunk 4, at a reader's position; slice 3, which ends chunk 2, is
    // held back.
    faults.hold(&[3]);
    let ahead = bob.fetch_chunks(space, locator, 4..5, FetchPriority::Position);
    until(|| async { faults.asked(&locator) == vec![0, 1, 2, 3] }).await;
    // Chunks 0 and 1 are written: the header with its length and two
    // sealed chunks, of the object's stored length.
    until(|| async {
        link.status()
            .fetching
            .get(&locator)
            .is_some_and(|(held, total)| {
                let total = total.expect("the stored length");
                let prefix = total - big.len() as u64 - 6 * 40;
                *held == prefix + 2 * (1 << 20)
            })
    })
    .await;
    faults.hold(&[]);
    until(|| async { faults.asked(&locator) == vec![0, 1, 2, 3, 4, 5] }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(faults.asked(&locator), vec![0, 1, 2, 3, 4, 5]);
    assert!(bob.held_record(&space, &locator).await.is_none());

    // The last chunk: the receive stands at chunk 5, which slice 5 is.
    let last = bob.fetch_chunks(space, locator, 5..6, FetchPriority::Position);
    until(|| async { bob.held_record(&space, &locator).await.is_some() }).await;
    assert_eq!(faults.asked(&locator), vec![0, 1, 2, 3, 4, 5, 5]);
    let record = bob.held_record(&space, &locator).await.unwrap();
    assert_eq!(files.read(&record.token), big);
    drop((ahead, last));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A request whose transfer is cut is tried again on the same connection,
/// after a wait, with nothing else happening in the space: once the peer
/// answers, the chunk is kept. Its holder hears of no end meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_whose_fetch_stops_is_tried_again() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // Chunk 0 is in slices 0 and 1; slice 1 never arrives.
    *faults.cut_from.lock().unwrap() = Some(1);
    let fetch = bob.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    until(|| async { faults.cut.load(Ordering::SeqCst) >= 3 }).await;
    assert_eq!(&faults.asked(&locator)[..6], &[0, 1, 0, 1, 0, 1]);
    assert!(!holds(&bob, &space, &locator, 0).await);
    assert_eq!(fetch.end(), None);
    assert!(!link.is_closed());

    *faults.cut_from.lock().unwrap() = None;
    until(|| async { holds(&bob, &space, &locator, 0).await }).await;
    assert_eq!(fetch.end(), None);

    // Cancelled while it waits, a request is not tried again.
    *faults.cut_from.lock().unwrap() = Some(2);
    let cut = faults.cut.load(Ordering::SeqCst);
    let next = bob.fetch_chunks(space, locator, 1..2, FetchPriority::Position);
    until(|| async { faults.cut.load(Ordering::SeqCst) > cut }).await;
    next.cancel();
    let cut = faults.cut.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(faults.cut.load(Ordering::SeqCst), cut);
    drop(fetch);
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A slice the peer sends wrong ends every fetch of the object from it:
/// the fetch that ran beside the one that found it stops before its next
/// slice and keeps nothing, and both holders hear that the connection
/// gave the object up. Nothing of it is asked of this peer again, and the
/// holder of a request made afterwards hears the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_object_stops_its_other_fetches_and_tells_their_holders() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // Chunk 4 waits for slice 4, which is held back.
    faults.hold(&[4]);
    let waiting = bob.fetch_chunks(space, locator, 4..5, FetchPriority::Position);
    until(|| async { faults.asked(&locator) == vec![0, 4] }).await;

    // The first byte of slice 2 ends chunk 1, which then fails to open.
    *faults.corrupt.lock().unwrap() = Some(2);
    let refused = bob.fetch_chunks(space, locator, 1..2, FetchPriority::Position);
    assert_eq!(within(refused.ended()).await, FetchEnd::Refused);
    assert_eq!(within(waiting.ended()).await, FetchEnd::Refused);
    assert_eq!(faults.asked(&locator), vec![0, 4, 0, 1, 2]);

    // The fetch of chunk 4 takes no further slice, and is not tried again.
    faults.hold(&[]);
    *faults.corrupt.lock().unwrap() = None;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(faults.asked(&locator), vec![0, 4, 0, 1, 2]);
    assert!(!holds(&bob, &space, &locator, 4).await);
    assert!(link.status().fetching.is_empty());

    // A request made now is not served by this connection either.
    // Its holder hears why at once: no connection will try.
    let later = bob.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    let heard = tokio::time::timeout(Duration::from_secs(10), later.ended()).await;
    assert_eq!(heard, Ok(FetchEnd::Refused));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(faults.asked(&locator), vec![0, 4, 0, 1, 2]);
    drop((waiting, refused, later));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// How many times a slice of the object was asked for.
fn asked_times(faults: &Faults, locator: &[u8; 64], slice: u64) -> usize {
    let asked = faults.asked(locator);
    asked.iter().filter(|index| **index == slice).count()
}

/// A request whose fetch stops with nothing kept waits longer each time,
/// and what another fetch keeps of the object meanwhile does not start
/// its wait over: only a chunk its own fetch kept does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_fetchs_progress_does_not_start_a_stopped_requests_wait_over() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    let first = bob.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 0).await }).await;

    // Chunk 1 is in slices 1 and 2; slice 2 never arrives. Four fetches
    // stop with nothing kept: the request waits four seconds, then eight.
    *faults.cut_only.lock().unwrap() = vec![2];
    let stopped = bob.fetch_chunks(space, locator, 1..2, FetchPriority::Position);
    until(|| async { faults.cut.load(Ordering::SeqCst) == 4 }).await;
    assert_eq!(asked_times(&faults, &locator, 1), 5);

    // Its fifth fetch waits for slice 1, and chunk 4 is kept beside it.
    faults.hold(&[1]);
    until(|| async { asked_times(&faults, &locator, 1) == 6 }).await;
    let other = bob.fetch_chunks(space, locator, 4..5, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 4).await }).await;
    faults.hold(&[]);
    until(|| async { faults.cut.load(Ordering::SeqCst) == 5 }).await;

    // The fifth fetch kept nothing itself: the wait goes on growing.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(faults.cut.load(Ordering::SeqCst), 5);
    assert!(!holds(&bob, &space, &locator, 1).await);
    drop((first, stopped, other));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A chunk a request's own fetch kept starts its wait over: the fetch
/// that stops after it is tried again half a second later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requests_own_progress_starts_its_wait_over() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();
    let first = bob.fetch_chunks(space, locator, 0..1, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 0).await }).await;

    // Chunks 2 and 3 are in slices 2 to 4. No slice from 2 on arrives:
    // four fetches stop with nothing kept, and the request waits four
    // seconds.
    *faults.cut_from.lock().unwrap() = Some(2);
    let stopped = bob.fetch_chunks(space, locator, 2..4, FetchPriority::Position);
    until(|| async { faults.cut.load(Ordering::SeqCst) == 4 }).await;

    // Slice 4 alone is cut now: the fifth fetch keeps chunk 2 and stops.
    *faults.cut_from.lock().unwrap() = None;
    *faults.cut_only.lock().unwrap() = vec![4];
    until(|| async { holds(&bob, &space, &locator, 2).await }).await;
    let kept = std::time::Instant::now();
    until(|| async { faults.cut.load(Ordering::SeqCst) >= 6 }).await;
    assert!(
        kept.elapsed() < Duration::from_secs(4),
        "{:?}",
        kept.elapsed()
    );
    drop((first, stopped));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// The connection reports an object while any fetch of it runs: a fetch
/// that ends beside another of the same object leaves the object's
/// progress where it is, and the last to end takes it away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_object_is_reported_while_any_fetch_of_it_runs() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, _big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // Chunk 1 waits for slice 2, which is held back.
    faults.hold(&[2]);
    let waiting = bob.fetch_chunks(space, locator, 1..2, FetchPriority::Position);
    until(|| async { faults.asked(&locator) == vec![0, 1, 2] }).await;
    assert!(link.status().fetching.is_empty(), "nothing is held yet");

    // Chunk 5 is fetched beside it, and its fetch ends.
    let last = bob.fetch_chunks(space, locator, 5..6, FetchPriority::Position);
    until(|| async { holds(&bob, &space, &locator, 5).await }).await;
    until(|| async { faults.asked(&locator) == vec![0, 1, 2, 0, 5] }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (held, total) = link
        .status()
        .fetching
        .get(&locator)
        .copied()
        .expect("the fetch of chunk 1 still runs");
    assert!(held > 0 && total.is_some_and(|total| held < total));

    faults.hold(&[]);
    until(|| async { holds(&bob, &space, &locator, 1).await }).await;
    until(|| async { link.status().fetching.is_empty() }).await;
    drop((waiting, last));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// Two fetches that run side by side complete one object between them:
/// each chunk is kept once, the object is whole and reads as the blob,
/// neither holder hears of an end, and nothing is reported as fetching
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_fetches_that_complete_one_object_leave_it_whole() {
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let (_alice, alice_link, bob, _store, space, locator, big) =
        setup_with(&peer.origin, SIX_CHUNKS).await;
    bob.fetch_objects_on_demand();
    let link = connect_server(&bob, &proxy, vec![space]).await.unwrap();

    // Both wait for slice 3, which ends chunk 2 and begins chunk 3.
    faults.hold(&[3]);
    let first = bob.fetch_chunks(space, locator, 0..3, FetchPriority::Position);
    let second = bob.fetch_chunks(space, locator, 3..6, FetchPriority::Position);
    until(|| async {
        faults.asked(&locator).contains(&3) && holds(&bob, &space, &locator, 1).await
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(bob.object(&space, &locator).await.is_err());
    faults.hold(&[]);
    until(|| async { bob.object(&space, &locator).await.is_ok() }).await;
    assert_eq!(bob.object(&space, &locator).await.unwrap(), big);
    assert!(
        bob.read(&space, |replica| replica.holds_object(&locator))
            .await
            .unwrap()
    );
    until(|| async { link.status().fetching.is_empty() }).await;
    assert_eq!((first.end(), second.end()), (None, None));
    // Slice 3 carries the end of chunk 2 and the start of chunk 3: both
    // fetches need it, and no slice is asked for more than twice.
    let asked = faults.asked(&locator);
    for slice in 0..6 {
        let times = asked.iter().filter(|index| **index == slice).count();
        assert!((1..=2).contains(&times), "slice {slice}: {asked:?}");
    }
    drop((first, second));
    link.close();
    alice_link.close();
    peer.shutdown().await;
}

/// A space paused while fetches of one of its objects run, on two
/// connections: each stops before its next slice, and nothing more is
/// asked for while the space is paused. Resumed, they go on from the
/// chunks kept, the object the two complete is whole, and the read that
/// waited ends with the blob.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_paused_while_a_fetch_runs_fetches_no_more_until_resumed() {
    use frasil::{Device, Level, Options, Storage};
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let open = |key, options: Options| async move {
        Device::open_with(Storage::Memory, &[key; 32], options.loopback())
            .await
            .expect("a device")
    };
    let alice = open(1, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let bob = open(2, Options::new().objects_on_demand()).await;
    let joining = within(bob.join_via_peer(&proxy, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&proxy).await.unwrap();
    // Three chunks and a half, which four slices carry.
    let big: Vec<u8> = (0..3_670_000u32).map(|i| (i % 251) as u8).collect();
    let blob = files.put(Some("big"), &big).await.unwrap();
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() == 1)
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let locator = bobs_files.info(blob).await.unwrap().object;
    // A read asks for the blob; slice 2 is held back.
    faults.hold(&[2]);
    let reading = {
        let bobs_files = bobs_files.clone();
        tokio::spawn(async move {
            let mut read = Vec::new();
            bobs_files
                .get_stream(blob, &mut read, |_, _| {})
                .await
                .map(|()| read)
        })
    };
    // Bob has two connections to the peer, the one he joined over and
    // the one he opened since, and each fetches the blob: both wait for
    // slice 2.
    let twice = |slice: u64| {
        let asked = faults.asked(&locator);
        asked.iter().filter(|index| **index == slice).count() == 2
    };
    until(|| async { twice(2) }).await;
    assert!(twice(0) && twice(1));

    // Paused: the slice under way is taken, and no other.
    bobs_space.pause_sync();
    faults.hold(&[]);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(faults.asked(&locator).len(), 6);
    assert!(!reading.is_finished());

    // Resumed: the fetches go on after the chunks kept, and the two
    // connections complete the blob between them.
    bobs_space.resume_sync();
    let read = within(reading).await.unwrap().unwrap();
    assert_eq!(read, big);
    let asked = faults.asked(&locator);
    assert!(asked[6..].contains(&3), "{asked:?}");
    assert!(!asked[6..].contains(&0), "{asked:?}");
    peer.shutdown().await;
}

/// A read that waits for a blob asks for it again when the blob became
/// whole meanwhile, as for another read, and was released before this
/// read looked: it does not wait out its time with nothing fetching.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_waits_asks_again_for_a_blob_released_meanwhile() {
    use frasil::{Device, Level, Options, Storage};
    let peer = spawn_loopback().await.unwrap();
    let (proxy, faults) = spawn_proxy(&peer.origin).await;
    let open = |key, options: Options| async move {
        Device::open_with(Storage::Memory, &[key; 32], options.loopback())
            .await
            .expect("a device")
    };
    let alice = open(1, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let files = space.create_blobs().unwrap();
    let held = provider::DirProvider::new(provider::temp_dir("slices-released"));
    let bob = open(
        2,
        Options::new()
            .object_provider(held.clone())
            .objects_on_demand(),
    )
    .await;
    let joining = within(bob.join_via_peer(&proxy, "Bob", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(joining.text(), Level::Write, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    bob.connect(&proxy).await.unwrap();
    let bytes = b"read by two".to_vec();
    let blob = files.put(Some("twice"), &bytes).await.unwrap();
    let bobs_files = within(async {
        loop {
            if let Ok(blobs) = bobs_space.blobs(files.id()).await
                && blobs.list().await.is_ok_and(|list| list.len() == 1)
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let locator = bobs_files.info(blob).await.unwrap().object;

    // A read asks for the blob, and no slice of it arrives.
    *faults.cut_from.lock().unwrap() = Some(0);
    let reading = {
        let bobs_files = bobs_files.clone();
        tokio::spawn(async move { bobs_files.materialise(blob, b"read.bin").await })
    };
    until(|| async { faults.cut.load(Ordering::SeqCst) >= 1 }).await;

    // The blob becomes whole by another route, and is released at once.
    let space_id = EventId(*space.id().as_bytes());
    let stored = alice
        .engine()
        .stored_object(&space_id, &locator)
        .await
        .unwrap();
    bob.engine()
        .receive_object(space_id, &locator, &stored)
        .await
        .unwrap();
    bobs_files.release(blob).await.unwrap();
    *faults.cut_from.lock().unwrap() = None;

    // The read that still waits asks again, and has its file.
    let read = tokio::time::timeout(Duration::from_secs(20), reading)
        .await
        .expect("asked for again before the read gives up")
        .unwrap();
    assert!(read.is_ok(), "{read:?}");
    peer.shutdown().await;
}
