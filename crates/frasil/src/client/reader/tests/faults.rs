//! What a chunk that does not open in a reader does to what the device
//! stores: nothing, whoever supplied the key.

use super::*;
use frasil_adapter_blobs::{Entry, Reference};
use frasil_units::objects::ObjectKeys;

/// A blob one space of the device holds whole, which it put and no peer
/// holds, and entries of another space that reference it: one for each
/// object key given, the right one for `None`.
struct Sourced {
    device: Device,
    engine: Engine,
    source: EventId,
    source_blobs: Blobs,
    source_id: BlobId,
    blobs: Blobs,
    ids: Vec<BlobId>,
    locator: Locator,
    bytes: Vec<u8>,
    _spaces: (Space, Space),
}

async fn sourced(keys: &[Option<[u8; 32]>]) -> Sourced {
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let engine = device.engine().clone();
    let from = device.create_space().await.unwrap();
    let source = from.id().event();
    let source_blobs = from.create_blobs().unwrap();
    let bytes = bytes();
    let source_id = source_blobs.put(None, &bytes).await.unwrap();
    let entry = source_blobs.entry(source_id).await.unwrap();
    let locator = entry.object;
    let key = {
        let state = engine.lock().await;
        engine.sealing(&state, &source).unwrap().1
    };
    let id: [u8; 32] = locator[..32].try_into().unwrap();
    let right = *ObjectKeys::of(&key).object_key(&id);
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let mut ids = Vec::new();
    for (at, object_key) in keys.iter().enumerate() {
        let handle = [at as u8 + 1; 16];
        let reference = Some(Reference {
            source: source.0,
            object_key: object_key.unwrap_or(right),
        });
        let entry = Entry {
            reference,
            ..entry.clone()
        };
        engine
            .put_entry(of, blobs.opening(), handle, entry)
            .await
            .unwrap();
        ids.push(BlobId::from_bytes(handle));
    }
    Sourced {
        device,
        engine,
        source,
        source_blobs,
        source_id,
        blobs,
        ids,
        locator,
        bytes,
        _spaces: (from, space),
    }
}

impl Sourced {
    async fn holds_whole(&self) -> bool {
        self.engine
            .read(&self.source, |replica| replica.holds_object(&self.locator))
            .await
            .unwrap()
    }
}

/// An entry that references a blob another space of the device holds,
/// with an object key that is not the blob's: reading it fails, and
/// changes nothing. The source still holds the blob, which this device
/// put and no peer holds; a reader of the source reads it; and so does a
/// reader of an entry that carries the right key.
#[tokio::test]
async fn a_reference_with_a_wrong_key_drops_nothing_of_its_source() {
    for read in [Read::new(), Read::new().uncached(), Read::new().local()] {
        let sourced = sourced(&[Some([9; 32]), None]).await;
        let mut events = sourced.device.events();
        let mut reader = sourced
            .blobs
            .open_reader(sourced.ids[0], &read)
            .await
            .unwrap();
        let mut buf = [0u8; 10];
        for _ in 0..2 {
            let failed = reader.read_at(0, &mut buf).await.unwrap_err();
            assert_eq!(failed.class_name(), Some("Decrypt"));
            assert!(sourced.holds_whole().await, "the source's blob was dropped");
        }
        assert_eq!(reader.size(), None);
        // The task that follows the object has looked at it by now.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(sourced.holds_whole().await);
        let local = sourced.source_blobs.local(sourced.source_id).await.unwrap();
        assert_eq!(local.state, BlobState::Kept);
        let got = sourced
            .source_blobs
            .get(sourced.source_id, &Read::new().local())
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some(sourced.bytes.as_slice()));
        for (blobs, id) in [
            (&sourced.source_blobs, sourced.source_id),
            (&sourced.blobs, sourced.ids[1]),
        ] {
            let mut right = blobs.open_reader(id, &read).await.unwrap();
            assert_eq!(right.read_at(CHUNK, &mut buf).await.unwrap(), 10);
            assert_eq!(buf[..], sourced.bytes[CHUNK as usize..CHUNK as usize + 10]);
        }
        nothing_told(&mut events).await;
        drop(reader);
    }
}

/// A blob whose stored bytes hash to its locator, with one chunk that
/// does not open, held whole: the fault is the object's own (units.md,
/// 3.3 Reading an object, a fault at steps 1 to 7 once step 0 passed).
/// The read is refused, the bytes stay, and nothing is fetched again.
#[tokio::test]
async fn a_fault_in_an_object_that_hashes_to_its_locator_stands() {
    let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let engine = device.engine().clone();
    let space = device.create_space().await.unwrap();
    let of = space.id().event();
    let blobs = space.create_blobs().unwrap();
    let bytes = bytes();
    let (mut locator, key, mut parts) = engine.seal_parts(of, &bytes).await.unwrap();
    // One bit of chunk 2 flipped, and the locator of those bytes.
    parts[2].chunk[100] ^= 1;
    let header = parts[0].header.clone().unwrap();
    let mut hasher = frasil_units::objects::stored_bytes_hasher(&header).unwrap();
    for part in &parts {
        hasher.update(&part.chunk);
    }
    locator[32..].copy_from_slice(&hasher.finish());
    for part in &mut parts {
        part.locator = locator;
    }
    let handle = [4; 16];
    let entry = Entry {
        object: locator,
        key,
        size: bytes.len() as u64,
        media_type: None,
        name: None,
        reference: None,
    };
    engine
        .put_entry(of, blobs.opening(), handle, entry)
        .await
        .unwrap();
    let id = BlobId::from_bytes(handle);
    // Held whole: its bytes hash to its locator.
    engine.keep_parts(of, &parts).await.unwrap();
    let whole = || async {
        engine
            .read(&of, |replica| {
                replica.holds_object(&locator) && replica.is_checked(&locator)
            })
            .await
            .unwrap()
    };
    assert!(whole().await);
    let _taker = engine.fetches().attach(of);
    let mut reader = blobs.open_reader(id, &Read::new()).await.unwrap();
    let mut buf = [0u8; 10];
    for _ in 0..2 {
        let failed = reader.read_at(2 * CHUNK, &mut buf).await.unwrap_err();
        assert!(
            matches!(failed.class_name(), Some("Decrypt" | "ObjectMismatch")),
            "{failed:?}"
        );
        assert!(whole().await, "the bytes were dropped");
        assert!(engine.fetches().of(&of).is_empty(), "fetched again");
    }
    drop(reader);
    // A read made later is refused too, with the bytes still here.
    let mut reader = match blobs.open_reader(id, &Read::new()).await {
        Ok(reader) => reader,
        Err(refused) => {
            assert!(refused.class_name().is_some());
            assert!(whole().await);
            return;
        }
    };
    assert!(reader.read_at(2 * CHUNK, &mut buf).await.is_err());
    assert!(whole().await);
}
