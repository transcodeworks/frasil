//! What an open reader reads from the store is not removed under it, and
//! a reader hears when it is found not to be the object's.

use super::*;

/// Two readers that cache read a blob whose entry shows one that fits the
/// cache, and whose header shows one that cannot. Each goes on through
/// its own memory; neither drops what the other still reads from the
/// store, and both read the blob. Once they are closed, nothing of it
/// stays.
#[tokio::test]
async fn a_reader_that_falls_back_drops_nothing_another_reader_uses() {
    let absent = mislabelled_with(Options::new().blob_cache(2 * CHUNK), 1000).await;
    let mut first = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let mut second = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    first.set_read_ahead(0);
    second.set_read_ahead(0);
    assert_eq!(absent.read(&mut first, 0, 10).await, absent.bytes[..10]);
    assert!(absent.holds(0).await);
    assert_eq!(absent.read(&mut second, 0, 10).await, absent.bytes[..10]);
    assert!(
        absent.holds(0).await,
        "a chunk two readers read from the store went under them"
    );
    for reader in [&mut first, &mut second] {
        let piece = absent.read(reader, CHUNK, 10).await;
        assert_eq!(piece, absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
        assert_eq!(absent.read(reader, 5, 10).await, absent.bytes[5..15]);
    }
    first.close().await.unwrap();
    second.close().await.unwrap();
    assert_eq!(absent.state().await, BlobState::Absent);
    assert_eq!(absent.device.blob_cache_usage().await.cached, 0);
}

/// A reader of a reference reads a chunk the reference's source stores.
/// The source then drops what it holds of the object, for a part under
/// another header that a holder of its key sealed: the reader, which
/// gave bytes of what was dropped, fails, and the application is told.
#[tokio::test]
async fn a_reader_of_a_reference_hears_when_its_source_drops_the_object() {
    use frasil_units::objects::{Header, ObjectKeys, seal_chunk};
    let (absent, _) = referenced().await;
    let source = {
        let entry = absent.blobs.entry(absent.id).await.unwrap();
        EventId(entry.reference.unwrap().source)
    };
    // The source stores two chunks, which open under its key.
    for index in [0, 1] {
        let part = absent.parts[index].clone();
        let received = absent.engine.receive_sent(source, part).await.unwrap();
        assert_eq!(received, Received::Kept);
    }
    let mut events = absent.device.events();
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().local())
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    assert_eq!(reader.read_at(0, &mut buf).await.unwrap(), 10);
    assert_eq!(buf[..], absent.bytes[..10]);
    // Another header for the object, with a chunk sealed under it by a
    // holder of the source's key.
    let other = {
        let mut header = Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
        header.size += 1;
        let key = {
            let state = absent.engine.lock().await;
            absent.engine.sealing(&state, &source).unwrap().1
        };
        let keys = ObjectKeys::of(&key);
        let id: [u8; 32] = absent.locator[..32].try_into().unwrap();
        let from = 2 * CHUNK as usize;
        let plain = &absent.bytes[from..from + CHUNK_BYTES];
        let object_key = keys.object_key(&id);
        let sealed = seal_chunk(&source, &keys, &object_key, &id, header.size, 2, plain);
        ObjectPart {
            header: Some(header.encode()),
            chunk: sealed.sealed,
            ..absent.parts[2].clone()
        }
    };
    let received = absent.engine.receive_sent(source, other).await.unwrap();
    assert_eq!(received, Received::Refused);
    let failed = reader.read_at(0, &mut buf).await.unwrap_err();
    assert_eq!(failed.class_name(), Some("ObjectMismatch"));
    assert!(refusal_told(&mut events, absent.id).await);
}
