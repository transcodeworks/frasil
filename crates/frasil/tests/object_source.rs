//! Objects put from a source read twice (units.md, 2.8 Objects): the
//! locator and stored bytes are those of a put from memory, at every size;
//! a source that changes between the passes or during the second is
//! refused and keeps nothing, and cannot write over an object the store
//! already holds under the same ID; and the client's puts from a reader, a
//! seekable reader and a file, sealed or held.
#![cfg(all(feature = "adapter-blobs", feature = "sqlite"))]

#[path = "support/provider.rs"]
mod provider;

use frasil::advanced::held::ObjectReader;
use frasil::{Device, Error, Options, Result, Storage};
use frasil_events::EventId;
use frasil_store::BoxFuture;
use frasil_units::limits::CHUNK_BYTES;
use provider::{DirProvider, temp_dir};

/// A plaintext of `size` bytes that differs from chunk to chunk.
fn plaintext(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ (i / 4093) as u8 ^ seed)
        .collect()
}

/// A source over bytes that become `then` once the first pass has read to
/// the end, or once `after` reads have been made.
struct Source {
    first: Vec<u8>,
    then: Option<Vec<u8>>,
    after: Option<usize>,
    reads: usize,
    switched: bool,
}

impl Source {
    fn of(bytes: Vec<u8>) -> Self {
        Self {
            first: bytes,
            then: None,
            after: None,
            reads: 0,
            switched: false,
        }
    }

    fn changing(first: Vec<u8>, then: Vec<u8>) -> Self {
        Self {
            then: Some(then),
            ..Self::of(first)
        }
    }
}

impl ObjectReader for Source {
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.reads += 1;
            if self.after.is_some_and(|after| self.reads > after) {
                self.switched = true;
            }
            let bytes = match (&self.then, self.switched) {
                (Some(then), true) => then,
                _ => &self.first,
            };
            let start = usize::try_from(offset).unwrap().min(bytes.len());
            let read = (bytes.len() - start).min(buf.len());
            buf[..read].copy_from_slice(&bytes[start..start + read]);
            if read == 0 && self.after.is_none() {
                self.switched = true;
            }
            Ok(read)
        })
    }
}

async fn device(name: &str, key: u8) -> (Device, std::path::PathBuf) {
    let dir = temp_dir(name);
    let device = Device::open_with(
        Storage::directory(dir.join("device")),
        &[key; 32],
        Options::new().never_restored(),
    )
    .await
    .expect("a device");
    (device, dir)
}

/// Pass two commits a few chunks at a time to the store, or hands a small
/// object's parts to the unit; either way the locator is a put from
/// memory's, and the object reads back. Sizes: empty, part of a chunk, a
/// chunk exactly, chunks and a remainder under the unit's share, and
/// enough chunks and a remainder to be committed apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_from_a_source_is_a_put_from_memory() {
    let (device, dir) = device("source-sizes", 1).await;
    let space = device.create_space().await.unwrap();
    let space = EventId(*space.id().as_bytes());
    let engine = device.engine();
    for (i, size) in [
        0,
        1000,
        CHUNK_BYTES,
        3 * CHUNK_BYTES + 17,
        6 * CHUNK_BYTES,
        6 * CHUNK_BYTES + 3,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = plaintext(size, i as u8);
        let (locator, length) = engine
            .put_object_from(space, &mut Source::of(bytes.clone()))
            .await
            .unwrap();
        assert_eq!(length, size as u64);
        let stored = engine.stored_object(&space, &locator).await.unwrap();
        assert_eq!(engine.put_object(space, &bytes).await.unwrap(), locator);
        assert_eq!(
            engine.stored_object(&space, &locator).await.unwrap(),
            stored,
            "size {size}"
        );
        assert_eq!(engine.object(&space, &locator).await.unwrap(), bytes);
    }
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A source that changes between the passes, or during the second, is
/// `Changed`, and the put keeps nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_that_changes_is_refused() {
    let (device, dir) = device("source-changes", 2).await;
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let size = 6 * CHUNK_BYTES + 9;
    let before = plaintext(size, 1);
    let mut after = before.clone();
    after[5 * CHUNK_BYTES] ^= 1;
    // Between the passes, the same length.
    let refused = blobs
        .put_at(
            "a",
            &mut Source::changing(before.clone(), after.clone()),
            |_, _| {},
        )
        .await;
    assert_eq!(refused.unwrap_err(), Error::Class("Changed"));
    // Longer, and shorter, between the passes.
    let mut longer = before.clone();
    longer.push(0);
    let refused = blobs
        .put_at(
            "b",
            &mut Source::changing(before.clone(), longer),
            |_, _| {},
        )
        .await;
    assert_eq!(refused.unwrap_err(), Error::Class("Changed"));
    let refused = blobs
        .put_at(
            "c",
            &mut Source::changing(before.clone(), before[..size - 1].to_vec()),
            |_, _| {},
        )
        .await;
    assert_eq!(refused.unwrap_err(), Error::Class("Changed"));
    // Part way through the second pass: pass one reads in 64 KiB pieces.
    let mut source = Source::changing(before.clone(), after);
    source.after = Some(size.div_ceil(64 * 1024) + 3);
    let refused = blobs.put_at("d", &mut source, |_, _| {}).await;
    assert_eq!(refused.unwrap_err(), Error::Class("Changed"));
    assert!(blobs.list().await.unwrap().is_empty());
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The store keeps an object's parts by ID, and pass two writes them
/// before the digest is known: a source whose first pass matches an
/// object held already, and whose second does not, leaves that object as
/// it was. The same source unchanged finds it held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_source_does_not_write_over_a_held_object() {
    let (device, dir) = device("source-held-id", 3).await;
    let space = device.create_space().await.unwrap();
    let space = EventId(*space.id().as_bytes());
    let engine = device.engine();
    let size = 6 * CHUNK_BYTES + 1;
    let bytes = plaintext(size, 4);
    let locator = engine.put_object(space, &bytes).await.unwrap();
    let stored = engine.stored_object(&space, &locator).await.unwrap();
    let mut other = bytes.clone();
    other[CHUNK_BYTES + 3] ^= 0x40;
    let refused = engine
        .put_object_from(space, &mut Source::changing(bytes.clone(), other))
        .await;
    assert_eq!(refused.unwrap_err(), Error::Class("Changed"));
    assert_eq!(
        engine.stored_object(&space, &locator).await.unwrap(),
        stored
    );
    assert_eq!(engine.object(&space, &locator).await.unwrap(), bytes);
    let (again, _) = engine
        .put_object_from(space, &mut Source::of(bytes.clone()))
        .await
        .unwrap();
    assert_eq!(again, locator);
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The client's puts: from a reader at offsets, a seekable reader and a
/// file. Each blob has the locator a put from memory gives, reads back,
/// and its progress ends at its size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_puts_from_a_reader_a_seekable_reader_and_a_file() {
    let (device, dir) = device("source-client", 5).await;
    let space = device.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let bytes = plaintext(5 * CHUNK_BYTES + 77, 6);

    let from_memory = blobs.put(Some("memory"), &bytes).await.unwrap();
    let object = blobs.info(from_memory).await.unwrap().object;

    let mut seen = Vec::new();
    let at = blobs
        .put_at("at", &mut Source::of(bytes.clone()), |done, total| {
            seen.push((done, total));
        })
        .await
        .unwrap();
    assert_eq!(
        seen.last(),
        Some(&(bytes.len() as u64, Some(bytes.len() as u64)))
    );
    assert!(seen.windows(2).all(|pair| pair[0].0 < pair[1].0));

    let seekable = blobs
        .put_seekable("seekable", std::io::Cursor::new(bytes.clone()), |_, _| {})
        .await
        .unwrap();
    let path = dir.join("file.bin");
    std::fs::write(&path, &bytes).unwrap();
    let file = blobs.put_file("file", &path, |_, _| {}).await.unwrap();
    let empty_path = dir.join("empty.bin");
    std::fs::write(&empty_path, b"").unwrap();
    let mut empty_seen = Vec::new();
    let empty = blobs
        .put_file("", &empty_path, |done, total| {
            empty_seen.push((done, total))
        })
        .await
        .unwrap();
    assert_eq!(empty_seen, vec![(0, Some(0))]);
    assert_eq!(blobs.get(empty).await.unwrap().as_deref(), Some(&[][..]));
    assert_eq!(blobs.info(empty).await.unwrap().name, None);

    for blob in [at, seekable, file] {
        let info = blobs.info(blob).await.unwrap();
        assert_eq!(info.object, object);
        assert_eq!(info.size, bytes.len() as u64);
        assert_eq!(blobs.get(blob).await.unwrap().as_deref(), Some(&bytes[..]));
    }
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under the `held` policy, a put from a source copies it through the
/// provider's writer and holds the file it made: the store keeps the
/// header, and the blob reads as the file's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_put_from_a_source_goes_through_the_provider() {
    let (device, dir) = device("source-held", 7).await;
    let provider = DirProvider::new(dir.join("files"));
    let space = device.create_space().await.unwrap();
    space.hold_objects(provider.clone()).await.unwrap();
    let blobs = space.create_blobs().unwrap();
    let bytes = plaintext(3 * CHUNK_BYTES + 5, 8);
    let blob = blobs
        .put_at("held", &mut Source::of(bytes.clone()), |_, _| {})
        .await
        .unwrap();
    let info = blobs.info(blob).await.unwrap();
    assert_eq!(info.size, bytes.len() as u64);
    let token = info.token.expect("held through the provider");
    assert_eq!(provider.read(&token), bytes);
    assert_eq!(blobs.get(blob).await.unwrap().as_deref(), Some(&bytes[..]));
    drop(device);
    let _ = std::fs::remove_dir_all(&dir);
}
