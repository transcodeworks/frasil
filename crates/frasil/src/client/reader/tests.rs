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

mod arrival;
mod faults;
mod keys;
mod sealed;
mod whole;

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
            .receive_sent(self.of, self.parts[index].clone())
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
    assert_eq!(absent.send(3).await, Received::Unwanted);
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
                assert_eq!(absent.send(index).await, Received::Unwanted);
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
            absent.engine.receive_sent(absent.of, bad).await.unwrap(),
            Received::BadChunk
        );
        assert!(absent.holds(0).await && !absent.holds(1).await && !absent.holds(3).await);
    }
    // The reader still reads what is held, and the right chunk 1 when it
    // comes.
    let piece = absent.read(&mut reader, CHUNK - 5, 10).await;
    assert_eq!(piece, absent.bytes[CHUNK as usize - 5..CHUNK as usize + 5]);
    assert_eq!(reader.verified(), Verified::Chunks);

    // Another header for the same object, with a chunk that does not
    // open under it: its sender's fault, and what is held stays.
    let mut header =
        frasil_units::objects::Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
    header.size += 1;
    let other = ObjectPart {
        header: Some(header.encode()),
        ..absent.parts[2].clone()
    };
    assert_eq!(
        absent.engine.receive_sent(absent.of, other).await.unwrap(),
        Received::BadChunk
    );
    assert!(absent.holds(0).await && absent.holds(1).await);
    // Another header under which a holder of the key sealed the chunk:
    // which of the two is the object's is not known, so what is held
    // goes, and the reader, which gave bytes under the first, fails.
    let other = {
        use frasil_units::objects::{ObjectKeys, seal_chunk};
        let key = {
            let state = absent.engine.lock().await;
            absent.engine.sealing(&state, &absent.of).unwrap().1
        };
        let keys = ObjectKeys::of(&key);
        let id: [u8; 32] = absent.locator[..32].try_into().unwrap();
        let from = 2 * CHUNK as usize;
        let plain = &absent.bytes[from..from + CHUNK_BYTES];
        let sealed = seal_chunk(
            &absent.of,
            &keys,
            &keys.object_key(&id),
            &id,
            header.size,
            2,
            plain,
        );
        ObjectPart {
            header: Some(header.encode()),
            chunk: sealed.sealed,
            ..absent.parts[2].clone()
        }
    };
    assert_eq!(
        absent.engine.receive_sent(absent.of, other).await.unwrap(),
        Received::Refused
    );
    assert!(!absent.holds(0).await && !absent.holds(1).await);
    let failed = reader.read_at(0, &mut [0u8; 10]).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    assert_eq!(reader.verified(), Verified::Chunks);
}

/// A chunk of another object, a header of another object, and a chunk
/// at another index, put in the store past the checks of arrival: the
/// reader gives none of their bytes, and drops nothing for them. Each is
/// asked for again, and the chunk that opens takes its place.
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
    // Nothing held goes for it, and the reader lives: it reads the chunk
    // from the store no more, and this one fetches nothing.
    assert!(absent.holds(0).await && absent.holds(1).await);
    assert_eq!(reader.read_at(0, &mut buf).await.unwrap(), 10);
    let failed = reader.read_at(CHUNK, &mut buf).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Missing"));
    drop(reader);
    // A reader that fetches asks for the chunk again, and reads it once
    // a chunk that opens took the other's place: so too for the chunk
    // that sits at another's index.
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    for index in [1, 2] {
        let from = index * CHUNK_BYTES;
        let piece = read_again(&absent, &mut reader, from as u64, 10).await;
        assert_eq!(piece, absent.bytes[from..from + 10]);
    }
    assert!(absent.holds(0).await);
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
/// told, the blob's bytes stay, since they are the object's, and no
/// reader opens on it again.
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
                            engine.receive_sent(of, part(index)).await.unwrap();
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
        engine.receive_sent(of, part(4)).await.unwrap(),
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
    // Its bytes hash to its locator, so they are the object's: they
    // stay, and fetching them again would bring the same.
    assert_eq!(blobs.local(blob).await.unwrap().state, BlobState::Cached);
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

/// A header of the same object with another size, and the last chunk
/// that size gives, of its length, which does not open.
fn forged(absent: &Absent, size: u64) -> ObjectPart {
    let mut header =
        frasil_units::objects::Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
    header.size = size;
    let index = (size - 1) / CHUNK;
    ObjectPart {
        locator: absent.locator,
        header: Some(header.encode()),
        index,
        chunk: vec![7; (size - index * CHUNK) as usize + 40],
    }
}

/// Reads at `offset` until a read succeeds, while the chunks asked for
/// arrive: a read that failed for a chunk that did not open is made again.
async fn read_again(absent: &Absent, reader: &mut BlobReader, offset: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    let read = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let reading = reader.read_at(offset, &mut out);
            tokio::pin!(reading);
            let read = loop {
                tokio::select! {
                    read = &mut reading => break read,
                    () = tokio::time::sleep(Duration::from_millis(5)) => {
                        for (index, _) in absent.asked() {
                            absent.send(index as usize).await;
                        }
                    }
                }
            };
            match read {
                Ok(read) => break read,
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await
    .expect("read again");
    out.truncate(read);
    out
}

/// A reference, whose object nothing opens as it arrives: a party answers
/// with a header that names the right object and a size of its choice,
/// and a chunk that does not open. The reader gives no size and no end of
/// the blob from that header, and reads the blob once its chunks come.
#[tokio::test]
async fn a_forged_size_gives_neither_a_size_nor_an_end_of_a_reference() {
    for uncached in [true, false] {
        let (absent, _) = referenced().await;
        let read = if uncached {
            Read::new().uncached()
        } else {
            Read::new()
        };
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        reader.set_read_ahead(0);
        // Three chunks by the forged header, of the blob's five.
        let size = 2 * CHUNK + 10;
        reader.seek(size);
        {
            let sizing = reader.fetch_size();
            tokio::pin!(sizing);
            tokio::select! {
                _ = &mut sizing => panic!("nothing arrived yet"),
                () = absent.asked_for(2) => {}
            }
            let _ = absent
                .engine
                .receive_sent(absent.of, forged(&absent, size))
                .await
                .unwrap();
            let sized = tokio::time::timeout(Duration::from_millis(300), &mut sizing).await;
            assert!(!matches!(sized, Ok(Ok(_))), "{sized:?} {uncached}");
        }
        assert_eq!(reader.size(), None);
        // At the size the forged header names: no end of the blob.
        let piece = read_again(&absent, &mut reader, size, 5).await;
        assert_eq!(piece, absent.bytes[size as usize..size as usize + 5]);
        assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
        drop(reader);

        // A range read there gives the blob's bytes or nothing, never an
        // empty range.
        let (absent, _) = referenced().await;
        let ranging = absent.blobs.get_range(absent.id, size, 5, &read);
        tokio::pin!(ranging);
        tokio::select! {
            _ = &mut ranging => panic!("nothing arrived yet"),
            () = absent.asked_for(2) => {}
        }
        let _ = absent
            .engine
            .receive_sent(absent.of, forged(&absent, size))
            .await
            .unwrap();
        let ranged = tokio::time::timeout(Duration::from_millis(300), &mut ranging).await;
        assert!(!matches!(ranged, Ok(Ok(Some(_)))), "{ranged:?} {uncached}");
    }
}

/// A header and a chunk that the store took while nothing could open
/// them, under a size that is not the blob's: a reader gives no size and
/// no end of the blob from them. Nothing was given under that header, so
/// what is held of it goes, no reader fails, and the blob is read once
/// its chunks come.
#[tokio::test]
async fn a_stored_header_gives_no_size_before_a_chunk_opens_under_it() {
    let absent = absent().await;
    let part = forged(&absent, 10);
    absent
        .engine
        .store_parts(absent.of, &[&part], false)
        .await
        .unwrap();
    assert!(absent.holds(0).await);
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    assert_eq!(reader.size(), None);
    let failed = reader.fetch_size().await.unwrap_err();
    assert_eq!(failed.class_name(), Some("Decrypt"));
    assert_eq!(reader.size(), None);
    assert!(!absent.holds(0).await);
    // Past the size that header named.
    let piece = read_again(&absent, &mut reader, 20, 5).await;
    assert_eq!(piece, absent.bytes[20..25]);
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
    let end = read_again(&absent, &mut reader, absent.bytes.len() as u64, 5).await;
    assert!(end.is_empty());
}

/// Chunk `index` of the blob sealed again by a holder of its key, under
/// the same header, with other plaintext of the same length.
async fn substituted(absent: &Absent, index: u64) -> ObjectPart {
    use frasil_units::objects::{ObjectKeys, seal_chunk};
    let key = {
        let state = absent.engine.lock().await;
        absent.engine.sealing(&state, &absent.of).unwrap().1
    };
    let keys = ObjectKeys::of(&key);
    let id: [u8; 32] = absent.locator[..32].try_into().unwrap();
    let object_key = keys.object_key(&id);
    let from = (index * CHUNK) as usize;
    let plain: Vec<u8> = absent.bytes[from..(from + CHUNK_BYTES).min(absent.bytes.len())]
        .iter()
        .map(|byte| byte ^ 0x55)
        .collect();
    let size = absent.bytes.len() as u64;
    ObjectPart {
        index,
        chunk: seal_chunk(&absent.of, &keys, &object_key, &id, size, index, &plain).sealed,
        ..absent.parts[index as usize].clone()
    }
}

/// Reads at `offset` while `part` is sent for the chunk asked for.
async fn read_with(
    absent: &Absent,
    reader: &mut BlobReader,
    offset: u64,
    part: &ObjectPart,
) -> crate::Result<Vec<u8>> {
    let mut buf = vec![0u8; 10];
    let read = {
        let reading = reader.read_at(offset, &mut buf);
        tokio::pin!(reading);
        loop {
            tokio::select! {
                read = &mut reading => break read,
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    if absent.asked().iter().any(|(at, _)| *at == part.index) {
                        absent.engine.receive_sent(absent.of, part.clone()).await.unwrap();
                    }
                }
            }
        }
    };
    read.map(|read| buf[..read].to_vec())
}

/// A reader that stores nothing reads the blob in order and is whole. It
/// then reads a chunk again, which its window let go, and a holder of the
/// key serves another validly sealed chunk at that place: the reader
/// gives none of it, fails, is whole no longer, and the application is
/// told.
#[tokio::test]
async fn a_chunk_read_again_after_whole_must_be_the_one_given() {
    let absent = absent().await;
    let mut events = absent.device.events();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    let mut at = 0;
    while at < absent.bytes.len() {
        at += absent.read(&mut reader, at as u64, 400_000).await.len();
    }
    assert_eq!(reader.verified(), Verified::Whole);
    // The same chunk again is the one given: the reader stays whole.
    let again = absent.read(&mut reader, CHUNK + 5, 10).await;
    assert_eq!(again, absent.bytes[CHUNK as usize + 5..CHUNK as usize + 15]);
    assert_eq!(reader.verified(), Verified::Whole);
    absent.read(&mut reader, 3 * CHUNK, 10).await;
    let other = substituted(&absent, 1).await;
    let failed = read_with(&absent, &mut reader, CHUNK + 5, &other).await;
    assert_eq!(
        failed.unwrap_err().class_name(),
        Some("ObjectMismatch"),
        "bytes the whole-object checks never saw"
    );
    assert_eq!(reader.verified(), Verified::Chunks);
    let failed = reader.read_at(0, &mut [0u8; 10]).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    let told = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(Event::ObjectRefused { blob, .. }) = events.next().await {
                break blob;
            }
        }
    })
    .await
    .expect("the application is told");
    assert_eq!(told, absent.id);
}

/// A chunk read out of order from a holder of the key that serves other
/// bytes, let go by a seek, and fetched again right for the pass in
/// order: the pass does not make whole a reader that gave the other
/// bytes.
#[tokio::test]
async fn the_pass_in_order_must_read_the_chunks_given() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    let other = substituted(&absent, 1).await;
    let given = read_with(&absent, &mut reader, CHUNK, &other)
        .await
        .unwrap();
    assert_ne!(given, absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
    let first = absent.read(&mut reader, 0, 10).await;
    assert_eq!(first, absent.bytes[..10]);
    let right = absent.parts[1].clone();
    let failed = read_with(&absent, &mut reader, CHUNK, &right).await;
    assert_eq!(failed.unwrap_err().class_name(), Some("ObjectMismatch"));
    assert_eq!(reader.verified(), Verified::Chunks);
}

/// No refusal was told to the application.
async fn nothing_told(events: &mut crate::Events) {
    let told = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            if let Some(Event::ObjectRefused { .. }) = events.next().await {
                break;
            }
        }
    })
    .await;
    assert!(told.is_err(), "a chunk that does not open is no refusal");
}

/// A reader that stores nothing has read a chunk, and a party then sends
/// chunks that do not open: one with a bit flipped, one of another length,
/// one of the same plaintext sealed in another space. Each is that
/// party's fault: it is not given, nothing the reader holds goes, no
/// reader fails, the application is told of no refusal, and the read ends
/// with the chunk another party sends.
#[tokio::test]
async fn a_bad_chunk_to_a_reader_that_stores_nothing_is_asked_of_another_party() {
    let absent = absent().await;
    let second = absent.engine.fetches().attach(absent.of);
    let other = absent.device.create_space().await.unwrap().id().event();
    let (_, _, elsewhere) = absent
        .engine
        .seal_parts(other, &absent.bytes)
        .await
        .unwrap();
    let mut events = absent.device.events();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    absent.read(&mut reader, 0, 10).await;
    let mut flipped = absent.parts[2].clone();
    flipped.chunk[100] ^= 1;
    let mut short = absent.parts[2].clone();
    short.chunk.truncate(1000);
    let foreign = ObjectPart {
        chunk: elsewhere[2].chunk.clone(),
        ..absent.parts[2].clone()
    };
    let mut buf = [0u8; 10];
    let read = {
        let reading = reader.read_at(2 * CHUNK, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(2) => {}
        }
        for bad in [flipped, short, foreign] {
            let received = absent.engine.receive_sent(absent.of, bad).await.unwrap();
            assert_eq!(received, Received::BadChunk);
        }
        // That connection asks for no more of the object; the other one
        // serves the chunk.
        absent
            ._taker
            .give_up(&absent.locator, crate::fetch::FetchEnd::Refused);
        assert_eq!(absent.send(2).await, Received::Kept);
        reading.await.unwrap()
    };
    assert_eq!(read, 10);
    let from = 2 * CHUNK as usize;
    assert_eq!(buf[..], absent.bytes[from..from + 10]);
    // What was read before still reads, from the chunk asked for again.
    assert_eq!(absent.read(&mut reader, 5, 10).await, absent.bytes[5..15]);
    nothing_told(&mut events).await;
    drop(second);
}

/// The first chunk a read gets does not open: nothing is held and
/// nothing was given, so no reader fails, and the read ends with the
/// chunk another party sends. So for a reference, whose chunks open as
/// they arrive under the key its reader holds: one chunk that does not
/// fails no read.
#[tokio::test]
async fn a_bad_first_chunk_fails_no_reader() {
    for (reference, read) in [
        (false, Read::new()),
        (false, Read::new().uncached()),
        (true, Read::new()),
        (true, Read::new().uncached()),
    ] {
        let absent = if reference {
            referenced().await.0
        } else {
            absent().await
        };
        let second = absent.engine.fetches().attach(absent.of);
        let mut events = absent.device.events();
        {
            let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
            reader.set_read_ahead(0);
            let mut flipped = absent.parts[1].clone();
            flipped.chunk[100] ^= 1;
            let mut buf = [0u8; 10];
            let read = {
                let reading = reader.read_at(CHUNK, &mut buf);
                tokio::pin!(reading);
                tokio::select! {
                    _ = &mut reading => panic!("nothing arrived yet"),
                    () = absent.asked_for(1) => {}
                }
                let received = absent
                    .engine
                    .receive_sent(absent.of, flipped)
                    .await
                    .unwrap();
                // Where only the object key of the reader's entry
                // could open it, nothing says the chunk is at fault and
                // not the key: its sender is not given up.
                let expected = if reference {
                    Received::Undecided
                } else {
                    Received::BadChunk
                };
                assert_eq!(received, expected);
                assert_eq!(absent.send(1).await, Received::Kept);
                reading.await.unwrap()
            };
            assert_eq!(read, 10);
            assert_eq!(buf[..], absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
            reader.close().await.unwrap();
        }
        nothing_told(&mut events).await;
        drop(second);
    }
}

/// Every connection gave the chunk a read waits for up, or left it
/// unserved: the read fails with a class that is not the refusal of the
/// blob, the reader does not fail, and the read made again asks again,
/// with a request of its own that a connection serves.
#[tokio::test]
async fn a_read_made_again_asks_again_once_its_request_ended() {
    use crate::fetch::FetchEnd;
    for (end, class) in [
        (FetchEnd::Refused, "Decrypt"),
        (FetchEnd::Malformed, "Malformed"),
        (FetchEnd::Unserved, "Missing"),
    ] {
        let absent = absent().await;
        let mut reader = absent
            .blobs
            .open_reader(absent.id, &Read::new())
            .await
            .unwrap();
        reader.set_read_ahead(0);
        absent.read(&mut reader, 0, 10).await;
        let ids = |absent: &Absent| -> Vec<u64> {
            let requests = absent.engine.fetches().of(&absent.of);
            requests.iter().map(|request| request.id).collect()
        };
        let mut buf = [0u8; 10];
        let asked = {
            let reading = reader.read_at(CHUNK, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = absent.asked_for(1) => {}
            }
            let asked = ids(&absent);
            match end {
                FetchEnd::Unserved => absent._taker.unserved(&absent.locator),
                end => absent._taker.give_up(&absent.locator, end),
            }
            let failed = reading.await.unwrap_err();
            assert_eq!(failed.class_name(), Some(class));
            asked
        };
        // The same again while nothing else is connected, at once.
        if end != FetchEnd::Unserved {
            let failed = reader.read_at(CHUNK, &mut buf).await.unwrap_err();
            assert_eq!(failed.class_name(), Some(class));
        }
        assert_eq!(reader.verified(), Verified::Chunks);
        assert_eq!(absent.read(&mut reader, 3, 4).await, absent.bytes[3..7]);
        // Another connection: the read made again asks again.
        let _second = absent.engine.fetches().attach(absent.of);
        let read = {
            let reading = reader.read_at(CHUNK, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                read = &mut reading => panic!("no new request: {read:?}"),
                () = soon(|| async { ids(&absent).iter().any(|id| !asked.contains(id)) }) => {}
            }
            assert_eq!(absent.send(1).await, Received::Kept);
            reading.await.unwrap()
        };
        assert_eq!(read, 10);
        assert_eq!(buf[..], absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
    }
}

/// Eleven chunks and a bit.
fn long() -> Vec<u8> {
    (0..CHUNK_BYTES * 11 + 1000)
        .map(|i| (i % 251) as u8)
        .collect()
}

/// Reads ten bytes at the start of chunk `index` once that chunk alone
/// was sent.
async fn read_chunk(absent: &Absent, reader: &mut BlobReader, index: u64) {
    let mut buf = [0u8; 10];
    let reading = reader.read_at(index * CHUNK, &mut buf);
    tokio::pin!(reading);
    tokio::select! {
        _ = &mut reading => panic!("nothing arrived yet"),
        () = absent.asked_for(index) => {}
    }
    absent.send(index as usize).await;
    assert_eq!(reading.await.unwrap(), 10);
}

/// A reader stands in a chunk with the chunks after it on their way, and
/// seeks forward to one of them: that chunk is asked for ahead of
/// everything else, the chunks it left behind are asked for no longer,
/// and the read-ahead goes on from where it landed.
#[tokio::test]
async fn a_seek_within_the_read_ahead_asks_for_where_it_lands_first() {
    for (read, seeks) in [
        (Read::new(), false),
        (Read::new(), true),
        (Read::new().keep(), false),
        (Read::new().uncached(), false),
    ] {
        let absent = absent_with(Options::new(), long()).await;
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        read_chunk(&absent, &mut reader, 0).await;
        // The run after it, of which one chunk arrived.
        let run: Vec<_> = (1..=8).map(|at| (at, FetchPriority::ReadAhead)).collect();
        assert_eq!(absent.asked(), run);
        absent.send(1).await;
        if seeks {
            reader.seek(7 * CHUNK + 3);
            assert!(absent.asked().is_empty(), "{:?}", absent.asked());
        }
        let mut buf = [0u8; 10];
        {
            let reading = reader.read_at(7 * CHUNK + 3, &mut buf);
            tokio::pin!(reading);
            let landed = tokio::time::timeout(Duration::from_secs(2), async {
                while !absent.asked().contains(&(7, FetchPriority::Position)) {
                    tokio::select! {
                        _ = &mut reading => panic!("nothing arrived yet"),
                        () = tokio::time::sleep(Duration::from_millis(5)) => {}
                    }
                }
            })
            .await;
            assert!(landed.is_ok(), "{:?}", absent.asked());
            let mut next = vec![(7, FetchPriority::Position)];
            next.extend((8..=11).map(|at| (at, FetchPriority::ReadAhead)));
            assert_eq!(absent.asked(), next);
            absent.send(7).await;
            assert_eq!(reading.await.unwrap(), 10);
        }
        let from = 7 * CHUNK as usize + 3;
        assert_eq!(buf[..], absent.bytes[from..from + 10]);
    }
}

/// A read that comes to wait for a chunk asked for only as read-ahead
/// asks for it ahead of everything else, and the rest of the run stays
/// as it was asked.
#[tokio::test]
async fn a_read_that_waits_for_a_chunk_read_ahead_asks_for_it_first() {
    let absent = absent_with(Options::new(), long()).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    read_chunk(&absent, &mut reader, 0).await;
    let id_of = |index: u64| {
        let requests = absent.engine.fetches().of(&absent.of);
        let request = requests
            .iter()
            .find(|request| request.chunks.contains(&index));
        request.map(|request| request.id)
    };
    let run = id_of(2);
    assert_eq!(absent.asked()[0], (1, FetchPriority::ReadAhead));
    let mut buf = [0u8; 10];
    let reading = reader.read_at(CHUNK, &mut buf);
    tokio::pin!(reading);
    let raised = tokio::time::timeout(Duration::from_secs(2), async {
        while !absent.asked().contains(&(1, FetchPriority::Position)) {
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    })
    .await;
    assert!(raised.is_ok(), "{:?}", absent.asked());
    assert_eq!(id_of(2), run);
    absent.send(1).await;
    assert_eq!(reading.await.unwrap(), 10);
}

/// A chunk on its way for a request that ended is stored for nobody: a
/// reader that stores nothing asked for it on two connections, one
/// brought it, the reader went, and the other brings it once a reader
/// that caches has opened on the blob. A chunk asked for by a reader that
/// stores nothing, while another reader caches the blob, begins no cached
/// blob either.
#[tokio::test]
async fn a_chunk_that_arrives_for_a_request_that_ended_is_not_stored() {
    use crate::objects::Asked;
    let absent = absent().await;
    let mut probe = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    probe.set_read_ahead(0);
    let request = {
        let mut buf = [0u8; 10];
        let reading = probe.read_at(0, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(0) => {}
        }
        let request = absent.engine.fetches().of(&absent.of).remove(0);
        assert_eq!(absent.send(0).await, Received::Kept);
        assert_eq!(reading.await.unwrap(), 10);
        request
    };
    let asked = |request: &crate::fetch::Request| {
        let cancel = request.cancel.clone();
        (move || !cancel.is_cancelled(), request.stores)
    };
    // A reader that caches opens, and asks for another chunk; the probe
    // asks for one more.
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    let (wanted, stores) = asked(&request);
    assert!(!stores);
    drop(probe);
    assert!(request.cancel.is_cancelled());
    // The other connection's copy of the chunk the probe asked for.
    let late = absent
        .engine
        .receive_part(
            absent.of,
            absent.parts[0].clone(),
            Asked {
                wanted: &wanted,
                stores,
            },
        )
        .await
        .unwrap();
    assert_ne!(late, Received::Kept);
    assert!(!absent.holds(0).await);
    assert_eq!(absent.state().await, BlobState::Absent);
    assert_eq!(absent.device.blob_cache_usage().await.cached, 0);

    // A second reader that stores nothing, beside the one that caches:
    // its chunk is its own.
    let mut passing = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    passing.set_read_ahead(0);
    let mut buf = [0u8; 10];
    {
        let reading = passing.read_at(2 * CHUNK, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(2) => {}
        }
        let request = absent.engine.fetches().of(&absent.of).remove(0);
        let (wanted, stores) = asked(&request);
        let received = absent
            .engine
            .receive_part(
                absent.of,
                absent.parts[2].clone(),
                Asked {
                    wanted: &wanted,
                    stores,
                },
            )
            .await
            .unwrap();
        assert_eq!(received, Received::Kept);
        assert_eq!(reading.await.unwrap(), 10);
    }
    assert!(!absent.holds(2).await);
    assert_eq!(absent.state().await, BlobState::Absent);
    // What the reader that caches asks for is the cache's.
    absent.read(&mut reader, CHUNK, 10).await;
    assert!(absent.holds(1).await);
    assert_eq!(absent.state().await, BlobState::Cached);
}

/// The task that follows a reader's object ends with its reader, in
/// whatever order the reader's parts go: woken by the reader's window
/// going while the rest of the reader is still there, it does not stay
/// parked on the object, with a window of its own and the device.
#[tokio::test]
async fn the_task_that_follows_the_object_ends_with_its_reader() {
    let absent = absent().await;
    let key = (absent.of, crate::replica::object_id(&absent.locator));
    let reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    // The reader's window and the task's.
    soon(|| async { absent.engine.readers().windows(&key) == 2 }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let BlobReader { window, alive, .. } = reader;
    drop(window);
    // The task wakes, finds the reader alive, and waits again.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(absent.engine.readers().windows(&key), 1);
    drop(alive);
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        while absent.engine.readers().windows(&key) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(ended.is_ok(), "the task outlived its reader");
}

/// A party that sends again a chunk the reader already has, and never
/// the chunk a read waits for, does not hold that read open: nothing the
/// read waits for arrives, and it ends when its time is up.
#[tokio::test(start_paused = true)]
async fn a_chunk_sent_again_does_not_hold_a_read_open() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(1);
    read_chunk(&absent, &mut reader, 0).await;
    let mut buf = [0u8; 10];
    let reading = reader.read_at(2 * CHUNK, &mut buf);
    tokio::pin!(reading);
    tokio::select! {
        _ = &mut reading => panic!("nothing arrived yet"),
        () = absent.asked_for(3) => {}
    }
    // The chunk read ahead arrives, again and again.
    let read = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            tokio::select! {
                read = &mut reading => break read,
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    assert_ne!(absent.send(3).await, Received::BadChunk);
                }
            }
        }
    })
    .await;
    assert!(
        matches!(read, Ok(Err(Error::Timeout))),
        "the read is held open: {read:?}"
    );
}

/// A blob of this device's space, absent here, whose entry shows `size`
/// and not the size of its object.
async fn mislabelled(size: u64) -> Absent {
    mislabelled_with(Options::new(), size).await
}

async fn mislabelled_with(options: Options, size: u64) -> Absent {
    entered(options, Some(size), false).await
}

/// A blob of this device's space, absent here, whose entry shows `size`
/// if one is given, and names, with `misnamed`, a locator whose digest is
/// not that of the object's stored bytes.
async fn entered(options: Options, size: Option<u64>, misnamed: bool) -> Absent {
    use frasil_adapter_blobs::Entry;
    let device = Device::open_with(Storage::Memory, &[1; 32], options)
        .await
        .unwrap();
    let engine = device.engine().clone();
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let bytes = bytes();
    let size = size.unwrap_or(bytes.len() as u64);
    let (mut locator, key, mut parts) = engine.seal_parts(of, &bytes).await.unwrap();
    if misnamed {
        locator[63] ^= 1;
        for part in &mut parts {
            part.locator = locator;
        }
    }
    let handle = [4; 16];
    let entry = Entry {
        object: locator,
        key,
        size,
        media_type: None,
        name: None,
        reference: None,
    };
    engine
        .put_entry(of, blobs.opening(), handle, entry)
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
    Absent {
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
    }
}

/// An entry whose size is not its object's: the reader reads by the
/// header, whose size a chunk that opened binds, and tells the
/// application once that the entry differs. An entry that agrees is not
/// reported.
#[tokio::test]
async fn an_entry_whose_size_is_not_the_headers_is_reported() {
    /// How many times the application was told that an entry differs.
    async fn told(events: &mut crate::Events) -> usize {
        let mut told = 0;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(100), events.next()).await
        {
            told += usize::from(matches!(event, Event::EntryMismatch { .. }));
        }
        told
    }
    let absent = mislabelled(CHUNK + 7).await;
    let mut events = absent.device.events();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    // Past the end the entry shows, and before the blob's.
    let offset = 3 * CHUNK + 5;
    let piece = absent.read(&mut reader, offset, 10).await;
    assert_eq!(piece, absent.bytes[offset as usize..offset as usize + 10]);
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
    absent.read(&mut reader, 5, 10).await;
    assert_eq!(told(&mut events).await, 1);

    let agreeing = self::absent().await;
    let mut events = agreeing.device.events();
    let mut reader = agreeing
        .blobs
        .open_reader(agreeing.id, &Read::new())
        .await
        .unwrap();
    agreeing.read(&mut reader, 5, 10).await;
    assert_eq!(told(&mut events).await, 0);
}

/// An entry that shows more than its object holds, and a reader that
/// stands past the object's end with nothing of it here: the chunk it
/// asks for by the entry does not exist. Once a party shows the object's
/// header, the reader asks for a chunk the object has, and answers the
/// end of the blob when that chunk has opened.
#[tokio::test]
async fn a_read_past_the_end_of_a_blob_its_entry_overstates_ends() {
    for read in [Read::new(), Read::new().uncached()] {
        let absent = mislabelled(20 * CHUNK).await;
        let key = (absent.of, crate::replica::object_id(&absent.locator));
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        reader.set_read_ahead(0);
        let mut buf = [0u8; 10];
        let read = {
            let reading = reader.read_at(10 * CHUNK, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = absent.asked_for(10) => {}
            }
            // As a connection does that reads the header in slice 0 and
            // finds no such chunk.
            let header = absent.parts[0].header.clone().unwrap();
            absent.engine.readers().hint(&key, &header);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = absent.asked_for(4) => {}
            }
            assert_eq!(absent.asked(), vec![(4, FetchPriority::Position)]);
            absent.send(4).await;
            reading.await.unwrap()
        };
        assert_eq!(read, 0);
        assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
        reader.close().await.unwrap();
    }
}

/// A reader that stores nothing asked two connections for a chunk: the
/// second copy is kept nowhere, and is no failure of the connection that
/// brought it.
#[tokio::test]
async fn a_second_copy_of_a_chunk_taken_is_no_failure() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    let mut buf = [0u8; 10];
    let reading = reader.read_at(CHUNK, &mut buf);
    tokio::pin!(reading);
    tokio::select! {
        _ = &mut reading => panic!("nothing arrived yet"),
        () = absent.asked_for(1) => {}
    }
    assert_eq!(absent.send(1).await, Received::Kept);
    assert_eq!(absent.send(1).await, Received::Unwanted);
    assert_eq!(reading.await.unwrap(), 10);
}

/// An entry that shows less than its object holds, of a blob that cannot
/// fit the cache: a reader that caches finds the size once a chunk has
/// opened under the header, and reads the rest through its own memory,
/// so that the device does not store the blob beside the cache without
/// bound while the reader is open.
#[tokio::test]
async fn a_blob_its_entry_understates_is_not_stored_past_the_budget() {
    let absent = mislabelled_with(Options::new().blob_cache(2 * CHUNK), 1000).await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(1);
    let mut at = 0;
    while at < absent.bytes.len() {
        let piece = absent.read(&mut reader, at as u64, 500_000).await;
        assert_eq!(piece, absent.bytes[at..at + piece.len()]);
        at += piece.len();
        let stored = absent.blobs.local(absent.id).await.unwrap().bytes;
        assert_eq!(stored, 0, "at {at}");
        assert!(reader.window_bytes() <= 2 * SEALED_CHUNK_BYTES);
    }
    assert_eq!(reader.verified(), Verified::Whole);
    assert_eq!(absent.state().await, BlobState::Absent);
    reader.close().await.unwrap();
    assert_eq!(absent.device.blob_cache_usage().await.cached, 0);
}

/// A device's tasks that take no task of a reader's: no task follows a
/// reader's object.
struct NoFollowing(crate::tasks::Tokio);

impl crate::tasks::Tasks for NoFollowing {
    fn spawn(&self, task: frasil_store::BoxFuture<'static, ()>) {
        self.0.spawn(task);
    }

    fn try_spawn(&self, task: frasil_store::BoxFuture<'static, ()>) -> bool {
        drop(task);
        false
    }

    fn sleep(&self, duration: Duration) -> frasil_store::BoxFuture<'static, ()> {
        self.0.sleep(duration)
    }
}

/// Whether the application is told of a refusal of `blob` within a
/// second.
async fn refusal_told(events: &mut crate::Events, blob: BlobId) -> bool {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(Event::ObjectRefused { blob: told, .. }) = events.next().await
                && told == blob
            {
                break;
            }
        }
    })
    .await
    .is_ok()
}

/// A blob whose stored bytes do not hash to its locator, read in order
/// through a reader: every chunk opens and is given but the last, before
/// which step 0 fails. The reader fails, is not whole, and the
/// application is told; nothing of the blob stays.
#[tokio::test]
async fn a_read_in_order_of_bytes_that_are_not_the_locators_fails_at_the_last_chunk() {
    for read in [Read::new().uncached(), Read::new()] {
        let absent = entered(Options::new(), None, true).await;
        let mut events = absent.device.events();
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        reader.set_read_ahead(0);
        let mut at = 0;
        while at < 4 * CHUNK_BYTES {
            let piece = absent.read(&mut reader, at as u64, CHUNK_BYTES).await;
            assert_eq!(piece, absent.bytes[at..at + CHUNK_BYTES]);
            at += piece.len();
            assert_eq!(reader.verified(), Verified::Chunks);
        }
        let last = {
            let mut buf = [0u8; 10];
            let reading = reader.read_at(at as u64, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = absent.asked_for(4) => {}
            }
            absent.send(4).await;
            reading.await
        };
        assert_eq!(last.unwrap_err().class_name(), Some("ObjectMismatch"));
        assert_eq!(reader.verified(), Verified::Chunks);
        let again = reader.read_at(0, &mut [0u8; 10]).await.unwrap_err();
        assert_eq!(again.class_name(), Some("ObjectMismatch"));
        assert!(refusal_told(&mut events, absent.id).await);
        assert!(!absent.holds(0).await && !absent.holds(4).await);
    }
}

/// Where the device's tasks take no task that follows a reader's object,
/// and the reader that gave bytes of a blob is not read again after the
/// blob is refused, the application is told by the next reader of the
/// blob, or the next read of it.
#[tokio::test]
async fn a_refusal_no_task_told_is_told_by_the_next_read() {
    use crate::tasks::Tokio;
    for reads in [false, true] {
        let tasks = std::sync::Arc::new(NoFollowing(Tokio::current()));
        let absent = absent_with(Options::new().tasks(tasks), bytes()).await;
        let mut events = absent.device.events();
        let mut reader = absent
            .blobs
            .open_reader(absent.id, &Read::new())
            .await
            .unwrap();
        reader.set_read_ahead(0);
        absent.read(&mut reader, 0, 10).await;
        // Another header, under which a holder of the key sealed a chunk.
        let other = {
            use frasil_units::objects::{Header, ObjectKeys, seal_chunk};
            let mut header = Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
            header.size += 1;
            let key = {
                let state = absent.engine.lock().await;
                absent.engine.sealing(&state, &absent.of).unwrap().1
            };
            let keys = ObjectKeys::of(&key);
            let id: [u8; 32] = absent.locator[..32].try_into().unwrap();
            let plain = &absent.bytes[CHUNK_BYTES..2 * CHUNK_BYTES];
            let object_key = keys.object_key(&id);
            let sealed = seal_chunk(&absent.of, &keys, &object_key, &id, header.size, 1, plain);
            ObjectPart {
                header: Some(header.encode()),
                chunk: sealed.sealed,
                ..absent.parts[1].clone()
            }
        };
        let received = absent.engine.receive_sent(absent.of, other).await.unwrap();
        assert_eq!(received, Received::Refused);
        assert!(!refusal_told(&mut events, absent.id).await);
        drop(reader);
        if reads {
            let local = Read::new().local();
            let _ = absent.blobs.get_range(absent.id, 0, 10, &local).await;
        } else {
            let _ = absent.blobs.open_reader(absent.id, &Read::new()).await;
        }
        assert!(refusal_told(&mut events, absent.id).await, "{reads}");
    }
}

/// A reader that made the blob whole in the store and is closed leaves
/// nothing that uses the blob: the check of the whole blob that began for
/// it has ended, and the application may drop the blob at once.
#[tokio::test]
async fn a_closed_reader_leaves_nothing_that_uses_the_blob() {
    for _ in 0..10 {
        let absent = absent().await;
        let mut reader = absent
            .blobs
            .open_reader(absent.id, &Read::new())
            .await
            .unwrap();
        reader.set_read_ahead(0);
        for chunk in [1u64, 0, 2, 3, 4] {
            absent.read(&mut reader, chunk * CHUNK, 10).await;
        }
        reader.close().await.unwrap();
        absent.blobs.drop_local(absent.id).await.unwrap();
        assert_eq!(absent.state().await, BlobState::Absent);
    }
}
