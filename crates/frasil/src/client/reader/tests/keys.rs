//! An entry that carries a wrong object key fails its own reads, and
//! nothing else: no party is given up for it, and no other reader loses
//! what it holds.

use super::*;

/// [`referenced`], with a second entry for the same object whose object
/// key is not the object's.
async fn referenced_twice() -> (Absent, BlobId) {
    use frasil_adapter_blobs::Reference;
    let (absent, _) = referenced().await;
    let mut entry = absent.blobs.entry(absent.id).await.unwrap();
    let source = entry.reference.as_ref().unwrap().source;
    entry.reference = Some(Reference {
        source,
        object_key: [9; 32],
    });
    let handle = [5; 16];
    absent
        .engine
        .put_entry(absent.of, absent.blobs.opening(), handle, entry)
        .await
        .unwrap();
    let heads: Vec<_> = absent.engine.outbox(&absent.of).await.into_iter().collect();
    absent
        .engine
        .acknowledge(absent.of, Acknowledger::Member([8; 32]), &heads)
        .await
        .unwrap();
    (absent, BlobId::from_bytes(handle))
}

/// Only a reader with a wrong object key is open when the object's chunks
/// arrive: they do not open under its key, and the device has no other
/// to judge them by. They are not taken, their sender is not given up,
/// and the read fails as its entry's own. A reader of an entry with the
/// right key, opened afterwards, reads the blob from the same party.
#[tokio::test]
async fn a_wrong_key_gets_no_party_given_up() {
    for read in [Read::new(), Read::new().uncached()] {
        let (absent, wrong) = referenced_twice().await;
        let mut events = absent.device.events();
        let mut reader = absent.blobs.open_reader(wrong, &read).await.unwrap();
        reader.set_read_ahead(0);
        let mut buf = [0u8; 10];
        let failed = {
            let reading = reader.read_at(CHUNK, &mut buf);
            tokio::pin!(reading);
            tokio::select! {
                _ = &mut reading => panic!("nothing arrived yet"),
                () = absent.asked_for(1) => {}
            }
            // Once may be the sender's fault, and the chunk is asked
            // for again; twice is the key's.
            for _ in 0..2 {
                assert_eq!(absent.send(1).await, Received::Undecided);
            }
            tokio::time::timeout(Duration::from_secs(5), reading)
                .await
                .expect("the read ends once a chunk came that its key does not open")
                .unwrap_err()
        };
        assert_eq!(failed.class_name(), Some("Decrypt"));
        assert!(!absent.holds(1).await);
        drop(reader);
        let mut right = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        right.set_read_ahead(0);
        let piece = absent.read(&mut right, CHUNK, 10).await;
        assert_eq!(piece, absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
        nothing_told(&mut events).await;
    }
}

/// Two readers that store nothing wait for one chunk of one object, one
/// with the right object key and one with a wrong one. The chunk arrives
/// and the reader with the wrong key fails to open it, before the other
/// has opened anything: the other still holds the chunk, and reads it
/// with nothing sent again.
#[tokio::test]
async fn a_wrong_key_takes_nothing_from_another_readers_window() {
    let (absent, wrong) = referenced_twice().await;
    let read = Read::new().uncached();
    let mut right = absent.blobs.open_reader(absent.id, &read).await.unwrap();
    let mut other = absent.blobs.open_reader(wrong, &read).await.unwrap();
    right.set_read_ahead(0);
    other.set_read_ahead(0);
    let (mut buf, mut scratch) = ([0u8; 10], [0u8; 10]);
    let read = {
        let reading = right.read_at(CHUNK, &mut buf);
        let failing = other.read_at(CHUNK, &mut scratch);
        tokio::pin!(reading, failing);
        let both = || async { absent.asked().iter().filter(|(at, _)| *at == 1).count() == 2 };
        tokio::select! {
            biased;
            _ = &mut reading => panic!("nothing arrived yet"),
            _ = &mut failing => panic!("nothing arrived yet"),
            () = soon(both) => {}
        }
        assert_eq!(absent.send(1).await, Received::Kept);
        let failed = failing.await.unwrap_err();
        assert_eq!(failed.class_name(), Some("Decrypt"));
        tokio::time::timeout(Duration::from_secs(2), reading)
            .await
            .expect("the chunk left the window of the reader that could open it")
    };
    assert_eq!(read.unwrap(), 10);
    assert_eq!(buf[..], absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
}
