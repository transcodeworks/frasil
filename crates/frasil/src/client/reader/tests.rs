//! A reader over a blob the device does not hold whole: what it fetches,
//! where the chunks go, what it gives, and what a fault does. The chunks
//! arrive as a connection would bring them, through
//! [`Engine::receive_part`](crate::device::Engine).

use super::{BlobReader, MAX_READ_AHEAD, Verified};
use crate::device::Engine;
use crate::fetch::{FetchPriority, Taker};
use crate::objects::Received;
use crate::outbox::Acknowledger;
use crate::snapshots::ObjectPart;
use crate::{BlobId, BlobState, Blobs, Device, Error, Event, Options, Read, Space, Storage};
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
use std::time::Duration;

const CHUNK: u64 = CHUNK_BYTES as u64;

/// Four chunks and a bit.
fn bytes() -> Vec<u8> {
    (0..CHUNK_BYTES * 4 + 1000)
        .map(|i| (i % 251) as u8)
        .collect()
}

/// A blob of a space whose one member is this device, absent here, with
/// the parts a party that holds it would send, and a connection that
/// takes the space's requests.
struct Absent {
    device: Device,
    engine: Engine,
    space: Space,
    of: EventId,
    blobs: Blobs,
    id: BlobId,
    locator: Locator,
    bytes: Vec<u8>,
    parts: Vec<ObjectPart>,
    _taker: Taker,
}

async fn absent_with(options: Options, bytes: Vec<u8>) -> Absent {
    let device = Device::open_with(Storage::Memory, &[1; 32], options)
        .await
        .unwrap();
    let engine = device.engine().clone();
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let id = blobs.put(None, &bytes).await.unwrap();
    let locator = blobs.entry(id).await.unwrap().object;
    // Durable, by a member's acknowledgement, and dropped: absent.
    let heads: Vec<_> = engine.outbox(&of).await.into_iter().collect();
    engine
        .acknowledge(of, Acknowledger::Member([8; 32]), &heads)
        .await
        .unwrap();
    blobs.drop_local(id).await.unwrap();
    let (sealed, _, parts) = engine.seal_parts(of, &bytes).await.unwrap();
    assert_eq!(sealed, locator);
    // Each part with the header, as the first chunk of an answer has it.
    let header = parts[0].header.clone();
    let parts = parts
        .into_iter()
        .map(|part| ObjectPart {
            header: header.clone(),
            ..part
        })
        .collect();
    let taker = engine.fetches().attach(of);
    Absent {
        device,
        engine,
        space,
        of,
        blobs,
        id,
        locator,
        bytes,
        parts,
        _taker: taker,
    }
}

async fn absent() -> Absent {
    absent_with(Options::new(), bytes()).await
}

/// A reference in one space to an object another space sealed, absent
/// here, with the object key its entry carries: the space the reader
/// fetches in holds no key of the state the object's header names, so
/// nothing of it opens as it arrives.
async fn referenced() -> (Absent, [u8; 32]) {
    use frasil_adapter_blobs::{Entry, Reference};
    use frasil_units::objects::ObjectKeys;
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let engine = device.engine().clone();
    let source = device.create_space().await.unwrap().id().event();
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let bytes = bytes();
    let (locator, reference, parts) = engine.seal_parts(source, &bytes).await.unwrap();
    let key = {
        let state = engine.lock().await;
        engine.sealing(&state, &source).unwrap().1
    };
    let id: [u8; 32] = locator[..32].try_into().unwrap();
    let object_key = *ObjectKeys::of(&key).object_key(&id);
    let handle = [4; 16];
    engine
        .put_entry(
            of,
            blobs.opening(),
            handle,
            Entry {
                object: locator,
                key: reference,
                size: bytes.len() as u64,
                media_type: None,
                name: None,
                reference: Some(Reference {
                    source: source.0,
                    object_key,
                }),
            },
        )
        .await
        .unwrap();
    let heads: Vec<_> = engine.outbox(&of).await.into_iter().collect();
    engine
        .acknowledge(of, Acknowledger::Member([8; 32]), &heads)
        .await
        .unwrap();
    let header = parts[0].header.clone();
    let parts = parts
        .into_iter()
        .map(|part| ObjectPart {
            header: header.clone(),
            ..part
        })
        .collect();
    let taker = engine.fetches().attach(of);
    let absent = Absent {
        device,
        engine,
        space,
        of,
        blobs,
        id: BlobId::from_bytes(handle),
        locator,
        bytes,
        parts,
        _taker: taker,
    };
    (absent, object_key)
}

/// A run of bytes as `Debug` lists them, without the brackets.
fn listed(bytes: &[u8]) -> String {
    let shown = format!("{bytes:?}");
    shown[1..shown.len() - 1].to_owned()
}

impl Absent {
    /// The chunks asked for now, with their priorities, in order.
    fn asked(&self) -> Vec<(u64, FetchPriority)> {
        let mut asked: Vec<_> = self
            .engine
            .fetches()
            .of(&self.of)
            .iter()
            .flat_map(|request| {
                request
                    .chunks
                    .clone()
                    .map(|index| (index, request.priority))
                    .collect::<Vec<_>>()
            })
            .collect();
        asked.sort_unstable();
        asked
    }

    /// Waits until chunk `index` is asked for.
    async fn asked_for(&self, index: u64) {
        soon(|| async { self.asked().iter().any(|(at, _)| *at == index) }).await;
    }

    async fn send(&self, index: usize) -> Received {
        self.engine
            .receive_part(self.of, self.parts[index].clone())
            .await
            .unwrap()
    }

    async fn holds(&self, index: u64) -> bool {
        self.engine
            .read(&self.of, |replica| {
                replica.holds_sealed_chunk(&self.locator, index)
            })
            .await
            .unwrap()
    }

    async fn state(&self) -> BlobState {
        self.blobs.local(self.id).await.unwrap().state
    }

    /// Reads `len` bytes at `offset` while the chunks asked for arrive.
    async fn read(&self, reader: &mut BlobReader, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        let mut filled = 0;
        while filled < len {
            let reading = reader.read_at(offset + filled as u64, &mut out[filled..]);
            tokio::pin!(reading);
            let read = loop {
                tokio::select! {
                    read = &mut reading => break read.unwrap(),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        for (index, _) in self.asked() {
                            self.send(index as usize).await;
                        }
                    }
                }
            };
            if read == 0 {
                break;
            }
            filled += read;
        }
        out.truncate(filled);
        out
    }
}

/// Waits until `check` holds.
async fn soon<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(20), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("soon");
}

/// A read at a place in a blob of which nothing is here asks for the
/// chunk it lands in, ahead of the chunks after it, and for no other;
/// it returns once that chunk arrived, with the right bytes, and the
/// chunk is the cache's.
#[tokio::test]
async fn a_seek_fetches_the_chunk_it_lands_in_and_those_after() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    assert_eq!(reader.size(), None);
    assert!(absent.asked().is_empty(), "nothing is fetched until a read");
    reader.set_read_ahead(1);
    let offset = 2 * CHUNK + 5;
    let mut buf = [0u8; 100];
    {
        let reading = reader.read_at(offset, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(2) => {}
        }
        // The header is not here: only the chunk the read lands in.
        assert_eq!(absent.asked(), vec![(2, FetchPriority::Position)]);
        assert_eq!(absent.send(2).await, Received::Kept);
        assert_eq!(reading.await.unwrap(), 100);
    }
    assert_eq!(
        buf[..],
        absent.bytes[offset as usize..offset as usize + 100]
    );
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
    assert_eq!(reader.verified(), Verified::Chunks);
    // The chunk after it is read ahead, behind what a reader waits for.
    assert_eq!(absent.asked(), vec![(3, FetchPriority::ReadAhead)]);
    assert!(absent.holds(2).await && !absent.holds(0).await);
    assert_eq!(absent.state().await, BlobState::Cached);
    // A seek lets go of what it leaves behind.
    reader.seek(0);
    assert!(absent.asked().is_empty());
    let read = absent.read(&mut reader, 10, 20).await;
    assert_eq!(read, absent.bytes[10..30]);
    assert!(absent.holds(0).await && absent.holds(1).await && !absent.holds(3).await);
    // Dropped: nothing is asked for any more, and what it fetched stays
    // in the cache, in part.
    reader.close().await.unwrap();
    assert!(absent.asked().is_empty());
    assert_eq!(absent.state().await, BlobState::Cached);
    let usage = absent.device.blob_cache_usage().await;
    assert!(
        usage.cached > 3 * CHUNK && usage.cached < 4 * CHUNK,
        "{usage:?}"
    );
    assert_eq!(usage.kept, 0);
}

/// The lengths: a read past the end, at an offset near the largest, and
/// into no buffer give nothing; a read near the end gives what is left.
#[tokio::test]
async fn reads_at_and_past_the_end_give_what_is_there() {
    let absent = absent().await;
    let size = absent.bytes.len() as u64;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    // No buffer: nothing is fetched for it.
    assert_eq!(reader.read_at(5, &mut []).await.unwrap(), 0);
    assert!(absent.asked().is_empty());
    for offset in [size, size + 1, u64::MAX - 1, u64::MAX] {
        assert!(
            absent.read(&mut reader, offset, 10).await.is_empty(),
            "{offset}"
        );
    }
    assert_eq!(reader.size(), Some(size));
    let tail = absent.read(&mut reader, size - 3, 10).await;
    assert_eq!(tail, absent.bytes[absent.bytes.len() - 3..]);
    // A read stops at its chunk's end, and goes on in the next.
    let mut buf = [0u8; 10];
    let read = {
        let reading = reader.read_at(CHUNK - 4, &mut buf);
        tokio::pin!(reading);
        loop {
            tokio::select! {
                read = &mut reading => break read.unwrap(),
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    for (index, _) in absent.asked() {
                        absent.send(index as usize).await;
                    }
                }
            }
        }
    };
    assert_eq!(read, 4);
    assert_eq!(reader.position(), CHUNK);
    // The read-ahead has a most.
    reader.set_read_ahead(u64::MAX);
    assert_eq!(reader.read_ahead(), MAX_READ_AHEAD);
}

/// An empty blob reads as nothing, and its one chunk's checks make it
/// whole.
#[tokio::test]
async fn an_empty_blob_reads_as_nothing_and_is_whole() {
    let absent = absent_with(Options::new(), Vec::new()).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    assert!(absent.read(&mut reader, 0, 10).await.is_empty());
    assert_eq!(reader.size(), Some(0));
    assert_eq!(reader.verified(), Verified::Whole);
    assert_eq!(absent.state().await, BlobState::Absent);
}

/// A reader that stores nothing holds what it fetched in its window, at
/// most the chunk it stands in and its read-ahead, takes no chunk it did
/// not ask for, and leaves the store and the cache as they were. Read in
/// order to the end, it is whole.
#[tokio::test]
async fn an_uncached_reader_stores_nothing_and_holds_a_bounded_window() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(1);
    let bound = 2 * SEALED_CHUNK_BYTES;
    // A chunk nobody asked for is not taken.
    assert_eq!(absent.send(3).await, Received::Left);
    assert_eq!(reader.window_bytes(), 0);
    let mut most = 0;
    let mut at = 0;
    let mut read = Vec::new();
    while at < absent.bytes.len() {
        let piece = absent.read(&mut reader, at as u64, 300_000).await;
        // Everything else a party sends meanwhile is left.
        for index in 0..absent.parts.len() {
            let wanted = absent.asked().iter().any(|(at, _)| *at == index as u64);
            if !wanted {
                assert_eq!(absent.send(index).await, Received::Left);
            }
        }
        most = most.max(reader.window_bytes());
        assert!(reader.window_bytes() <= bound, "{}", reader.window_bytes());
        at += piece.len();
        read.extend(piece);
        for index in 0..5 {
            assert!(!absent.holds(index).await);
        }
        assert_eq!(absent.state().await, BlobState::Absent);
    }
    assert_eq!(read, absent.bytes);
    assert!(most > SEALED_CHUNK_BYTES, "{most}");
    assert_eq!(reader.verified(), Verified::Whole);
    assert_eq!(absent.device.blob_cache_usage().await.cached, 0);
    drop(reader);
    assert!(absent.asked().is_empty());
    assert_eq!(absent.state().await, BlobState::Absent);
}

/// A reader that stores nothing and seeks is not whole, however much it
/// read.
#[tokio::test]
async fn an_uncached_reader_that_seeks_is_not_whole() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    for chunk in [1u64, 0, 2, 3, 4] {
        let piece = absent.read(&mut reader, chunk * CHUNK, 10).await;
        let from = (chunk * CHUNK) as usize;
        assert_eq!(piece, absent.bytes[from..from + 10]);
    }
    assert_eq!(reader.verified(), Verified::Chunks);
}

/// A blob larger than the whole budget, and any blob under a budget of
/// zero, is read through the reader's memory.
#[tokio::test]
async fn a_blob_that_cannot_fit_the_cache_streams_through() {
    for budget in [0, 2 * CHUNK] {
        let absent = absent_with(Options::new().blob_cache(budget), bytes()).await;
        let mut reader = absent
            .blobs
            .open_reader(absent.id, &Read::new())
            .await
            .unwrap();
        let piece = absent.read(&mut reader, CHUNK, 10).await;
        assert_eq!(piece, absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
        assert!(reader.window_bytes() > 0);
        assert_eq!(absent.state().await, BlobState::Absent, "{budget}");
    }
}

/// Two readers of one blob at different places each get their bytes, and
/// each asks for its own chunks.
#[tokio::test]
async fn two_readers_of_one_blob_read_at_different_places() {
    for read in [Read::new(), Read::new().uncached()] {
        let absent = absent().await;
        let mut first = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        let mut second = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        first.set_read_ahead(0);
        second.set_read_ahead(0);
        let (mut a, mut b) = ([0u8; 50], [0u8; 50]);
        let read = {
            let both = async {
                let (a, b) =
                    tokio::join!(first.read_at(7, &mut a), second.read_at(3 * CHUNK, &mut b));
                (a.unwrap(), b.unwrap())
            };
            tokio::pin!(both);
            loop {
                tokio::select! {
                    read = &mut both => break read,
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        let asked: Vec<u64> = absent.asked().iter().map(|(at, _)| *at).collect();
                        assert!(asked.iter().all(|at| [0, 3].contains(at)), "{asked:?}");
                        for index in asked {
                            absent.send(index as usize).await;
                        }
                    }
                }
            }
        };
        assert_eq!(read, (50, 50));
        assert_eq!(a[..], absent.bytes[7..57]);
        let from = 3 * CHUNK as usize;
        assert_eq!(b[..], absent.bytes[from..from + 50]);
        drop(first);
        drop(second);
        assert!(absent.asked().is_empty());
    }
}

/// A reader dropped while its chunk is on its way leaves no request, and
/// a chunk that arrives for it afterwards is kept nowhere.
#[tokio::test]
async fn a_reader_dropped_mid_fetch_leaves_no_fetch() {
    for read in [Read::new(), Read::new().uncached()] {
        let absent = absent().await;
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        {
            let mut buf = [0u8; 10];
            let reading = reader.read_at(CHUNK, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived"),
                () = absent.asked_for(1) => {}
            }
        }
        drop(reader);
        assert!(absent.asked().is_empty());
        // The use ended with it: the eviction pass leaves nothing.
        assert_eq!(absent.send(1).await, Received::Left);
        absent.engine.evict().await.unwrap();
        assert_eq!(absent.state().await, BlobState::Absent);
        assert!(
            absent
                .engine
                .retention_of(&absent.of, &absent.locator)
                .await
                .1
                == 0
        );
    }
}

/// Once the blob is whole in the store through a reader that seeks, every
/// step runs on it there, and the reader is whole.
#[tokio::test]
async fn a_blob_that_becomes_whole_in_the_store_is_checked_whole() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    for chunk in [3u64, 1, 0, 2] {
        absent.read(&mut reader, chunk * CHUNK, 10).await;
        assert_eq!(reader.verified(), Verified::Chunks);
    }
    absent.read(&mut reader, 4 * CHUNK, 10).await;
    soon(|| async { reader.verified() == Verified::Whole }).await;
    assert!(absent.engine.is_verified(&absent.of, &absent.locator, true));
    // A `get` of it then reads the store.
    let got = absent
        .blobs
        .get(absent.id, &Read::new().local())
        .await
        .unwrap();
    assert_eq!(got, Some(absent.bytes.clone()));
}

/// A chunk that does not open as it arrives fails nothing of what is
/// held: the part is not kept, and the chunks that opened stay, however
/// often. A part under another header than the one held takes the object
/// with it, and its readers fail.
#[tokio::test]
async fn a_bad_chunk_is_refused_and_the_good_ones_stay() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    absent.read(&mut reader, 0, 10).await;
    assert!(absent.holds(0).await);
    // Chunk 2 sent in the place of chunk 1, and chunk 3 with a bit
    // flipped: neither opens there.
    let replayed = ObjectPart {
        index: 1,
        ..absent.parts[2].clone()
    };
    let mut flipped = absent.parts[3].clone();
    flipped.chunk[100] ^= 1;
    for bad in [replayed, flipped.clone(), flipped] {
        assert_eq!(
            absent.engine.receive_part(absent.of, bad).await.unwrap(),
            Received::BadChunk
        );
        assert!(absent.holds(0).await && !absent.holds(1).await && !absent.holds(3).await);
    }
    // The reader still reads what is held, and the right chunk 1 when it
    // comes.
    let piece = absent.read(&mut reader, CHUNK - 5, 10).await;
    assert_eq!(piece, absent.bytes[CHUNK as usize - 5..CHUNK as usize + 5]);
    assert_eq!(reader.verified(), Verified::Chunks);

    // Another header for the same object: which of the two is the
    // object's is not known, so what is held goes, and the reader fails.
    let mut header =
        frasil_units::objects::Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
    header.size += 1;
    let other = ObjectPart {
        header: Some(header.encode()),
        ..absent.parts[2].clone()
    };
    assert_eq!(
        absent.engine.receive_part(absent.of, other).await.unwrap(),
        Received::Refused
    );
    assert!(!absent.holds(0).await && !absent.holds(1).await);
    let failed = reader.read_at(0, &mut [0u8; 10]).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    assert_eq!(reader.verified(), Verified::Chunks);
}

/// A chunk of another object, a header of another object, and a chunk
/// at another index, put in the store past the checks of arrival: the
/// reader gives none of their bytes.
#[tokio::test]
async fn the_reader_checks_what_the_store_holds() {
    let absent = absent().await;
    let other: Vec<u8> = bytes().iter().map(|byte| byte ^ 0x55).collect();
    let (_, _, others) = absent.engine.seal_parts(absent.of, &other).await.unwrap();
    let stored = |index: u64, from: &ObjectPart, header: Option<Vec<u8>>| ObjectPart {
        locator: absent.locator,
        header,
        index,
        chunk: from.chunk.clone(),
    };
    let header = absent.parts[0].header.clone();
    // The header, and at chunk 1 the other object's chunk 1.
    let parts = [
        stored(0, &absent.parts[0], header.clone()),
        stored(1, &others[1], None),
        stored(2, &absent.parts[3], None),
    ];
    absent
        .engine
        .store_parts(absent.of, &parts.iter().collect::<Vec<_>>(), false)
        .await
        .unwrap();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().local())
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    assert_eq!(reader.read_at(0, &mut buf).await.unwrap(), 10);
    let failed = reader.read_at(CHUNK, &mut buf).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Decrypt"));
    // What is held went with it, and the reader fails from then on.
    assert!(!absent.holds(0).await);
    let failed = reader.read_at(0, &mut buf).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    drop(reader);

    // A header of another object is not even stored under this ID
    // (at-rest.md, the `object` table); the reader's own check of it is
    // `reading::tests::the_header_is_checked_before_any_chunk`.
    let parts = [stored(0, &absent.parts[0], others[0].header.clone())];
    let stored = absent
        .engine
        .store_parts(absent.of, &parts.iter().collect::<Vec<_>>(), false)
        .await;
    assert!(stored.is_err());
}

/// A blob whose plaintext is not what its ID names, read by a reader that
/// seeks: bytes are given while it is in part, and once the device holds
/// it whole the last step fails. The reader fails, the application is
/// told, the blob is dropped, and no reader opens on it again.
#[tokio::test]
async fn a_blob_refused_whole_fails_its_readers_and_tells_the_application() {
    use frasil_units::objects::{Header, ObjectKeys, seal_chunk};
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let engine = device.engine().clone();
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let plain = bytes();
    let (reference, key) = {
        let state = engine.lock().await;
        engine.sealing(&state, &of).unwrap()
    };
    let keys = ObjectKeys::of(&key);
    let id = [9; 32];
    let object_key = keys.object_key(&id);
    let size = plain.len() as u64;
    let header = Header {
        object_id: id,
        key_reference: reference.clone(),
        size,
    }
    .encode();
    let chunks: Vec<Vec<u8>> = (0u64..)
        .zip(plain.chunks(CHUNK_BYTES))
        .map(|(index, plain)| seal_chunk(&of, &keys, &object_key, &id, size, index, plain).sealed)
        .collect();
    let mut stored = u32::try_from(header.len()).unwrap().to_be_bytes().to_vec();
    stored.extend_from_slice(&header);
    for chunk in &chunks {
        stored.extend_from_slice(chunk);
    }
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(&id);
    locator[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&stored]));
    let handle = [4; 16];
    engine
        .put_entry(
            of,
            blobs.opening(),
            handle,
            frasil_adapter_blobs::Entry {
                object: locator,
                key: reference,
                size,
                media_type: None,
                name: None,
                reference: None,
            },
        )
        .await
        .unwrap();
    let blob = BlobId::from_bytes(handle);
    // Its change is durable: nothing but the cache holds the blob.
    let heads: Vec<_> = engine.outbox(&of).await.into_iter().collect();
    engine
        .acknowledge(of, Acknowledger::Member([8; 32]), &heads)
        .await
        .unwrap();
    let _taker = engine.fetches().attach(of);
    let mut events = device.events();
    let mut reader = blobs.open_reader(blob, &Read::new()).await.unwrap();
    reader.set_read_ahead(0);
    let part = |index: usize| ObjectPart {
        locator,
        header: Some(header.clone()),
        index: index as u64,
        chunk: chunks[index].clone(),
    };
    // Every chunk opens, so bytes are given while the blob is in part.
    for index in [2usize, 0, 1, 3] {
        let mut buf = [0u8; 10];
        let read = {
            let reading = reader.read_at(index as u64 * CHUNK, &mut buf);
            tokio::pin!(reading);
            loop {
                tokio::select! {
                    read = &mut reading => break read.unwrap(),
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        if !engine.fetches().of(&of).is_empty() {
                            engine.receive_part(of, part(index)).await.unwrap();
                        }
                    }
                }
            }
        };
        assert_eq!(read, 10);
        assert_eq!(
            buf[..],
            plain[index * CHUNK_BYTES..index * CHUNK_BYTES + 10]
        );
        assert_eq!(reader.verified(), Verified::Chunks);
    }
    // The last chunk makes it whole: its bytes hash to the locator, and
    // its plaintext is not its ID's.
    assert_eq!(
        engine.receive_part(of, part(4)).await.unwrap(),
        Received::Whole
    );
    let refused = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(Event::ObjectRefused {
                space,
                stream,
                blob,
            }) = events.next().await
            {
                break (space, stream, blob);
            }
        }
    })
    .await
    .expect("the application is told");
    assert_eq!(refused, (space.id(), blobs.id(), blob));
    let failed = reader.read_at(0, &mut [0u8; 10]).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    assert_eq!(reader.verified(), Verified::Chunks);
    assert_eq!(blobs.local(blob).await.unwrap().state, BlobState::Absent);
    drop(reader);
    // The fault is the object's, whoever sends it.
    let again = blobs.open_reader(blob, &Read::new()).await.unwrap_err();
    assert!(matches!(again, Error::Class("ObjectMismatch")), "{again:?}");
}

/// A cached blob a reader has open is not evicted, whole or in part,
/// however full the cache; once the reader is closed it is.
#[tokio::test]
async fn eviction_leaves_a_blob_a_reader_has_open() {
    let absent = absent_with(Options::new().blob_cache(6 * CHUNK), bytes()).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    absent.read(&mut reader, 0, 10).await;
    absent.read(&mut reader, 2 * CHUNK, 10).await;
    assert_eq!(absent.state().await, BlobState::Cached);
    // A smaller budget than what it holds, and a pass.
    absent.engine.set_blob_cache(CHUNK);
    absent.engine.evict().await.unwrap();
    assert!(absent.holds(0).await && absent.holds(2).await);
    assert!(absent.blobs.drop_local(absent.id).await.is_err());
    // More arrives for it, over the budget: it stays.
    absent.read(&mut reader, CHUNK, 10).await;
    assert!(absent.holds(0).await && absent.holds(1).await && absent.holds(2).await);
    let piece = absent.read(&mut reader, 5, 10).await;
    assert_eq!(piece, absent.bytes[5..15]);
    reader.close().await.unwrap();
    assert_eq!(absent.state().await, BlobState::Absent);
    assert_eq!(absent.device.blob_cache_usage().await.cached, 0);
}

/// A kept read marks the blob kept before anything arrives, and what the
/// reader fetches is kept.
#[tokio::test]
async fn a_kept_reader_keeps_what_it_fetches() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().keep())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    absent.read(&mut reader, CHUNK, 10).await;
    assert_eq!(absent.state().await, BlobState::Kept);
    reader.close().await.unwrap();
    assert_eq!(absent.state().await, BlobState::Kept);
    let usage = absent.device.blob_cache_usage().await;
    assert_eq!(usage.cached, 0);
    assert!(usage.kept > CHUNK);
}

/// With nothing connected a read fails at once, and may be made again
/// when something is.
#[tokio::test]
async fn a_read_with_nothing_connected_is_missing_and_may_be_made_again() {
    let mut absent = absent().await;
    let taker = std::mem::replace(
        &mut absent._taker,
        absent.engine.fetches().attach(absent.of),
    );
    drop(taker);
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let again = absent.engine.fetches().attach(absent.of);
    drop(std::mem::replace(&mut absent._taker, again));
    absent.read(&mut reader, 0, 10).await;
    // The connection goes: a chunk not here is missing.
    let gone = std::mem::replace(
        &mut absent._taker,
        absent.engine.fetches().attach(EventId([0; 32])),
    );
    drop(gone);
    reader.set_read_ahead(0);
    let failed = reader.read_at(3 * CHUNK, &mut [0u8; 10]).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Missing"));
    // What is held still reads, and the rest once a connection is back.
    assert_eq!(absent.read(&mut reader, 3, 4).await, absent.bytes[3..7]);
    absent._taker = absent.engine.fetches().attach(absent.of);
    let piece = absent.read(&mut reader, 3 * CHUNK, 10).await;
    let from = 3 * CHUNK as usize;
    assert_eq!(piece, absent.bytes[from..from + 10]);
}

/// A local reader fetches nothing: it reads what the device holds.
#[tokio::test]
async fn a_local_reader_reads_what_is_held_and_fetches_nothing() {
    let absent = absent().await;
    let mut cached = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    cached.set_read_ahead(0);
    absent.read(&mut cached, CHUNK, 10).await;
    let mut local = absent
        .blobs
        .open_reader(absent.id, &Read::new().local())
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    assert_eq!(local.read_at(CHUNK, &mut buf).await.unwrap(), 10);
    assert_eq!(buf[..], absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
    let failed = local.read_at(0, &mut buf).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Missing"));
    assert!(absent.asked().is_empty());
    let _ = absent.space;
}

/// A reader formatted for a log shows neither the plaintext it holds nor
/// the object key of a reference.
#[tokio::test]
async fn a_formatted_reader_shows_neither_plaintext_nor_key() {
    let (absent, object_key) = referenced().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    let piece = absent.read(&mut reader, 0, 64).await;
    assert_eq!(piece, absent.bytes[..64]);
    let shown = format!("{reader:?}");
    assert!(!shown.contains(&listed(&piece[..16])), "{shown}");
    assert!(!shown.contains(&listed(&object_key[..8])), "{shown}");
}
