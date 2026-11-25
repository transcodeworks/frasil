//! What a part that does not simply fit does to what the device holds of
//! its object, to its sender and to the object's readers
//! ([`Engine::receive_part`](crate::device::Engine)).

use super::*;
use frasil_units::objects::Header;

/// A header that names the blob's object and a state the device holds no
/// key of, with a chunk of the length that header gives it: what a party
/// that holds no key can make.
pub(super) fn unkeyed(absent: &Absent, index: u64) -> ObjectPart {
    let mut header = Header::read(absent.parts[0].header.as_ref().unwrap()).unwrap();
    // Another state: a rotation the device never heard of.
    *header.key_reference.last_mut().unwrap() ^= 1;
    let encoded = header.encode();
    assert!(Header::read(&encoded).is_ok());
    ObjectPart {
        locator: absent.locator,
        header: Some(encoded),
        index,
        chunk: vec![7; absent.parts[index as usize].chunk.len()],
    }
}

/// A chunk has opened under the header the device holds, and a reader gave
/// its bytes. A party then sends a part under another header, which names
/// the right object and a state the device holds no key of, with a chunk
/// nothing opens: its sender's fault. Nothing held is dropped, no reader
/// fails, and the application is told of no refusal.
#[tokio::test]
async fn a_forged_header_with_an_unknown_key_drops_nothing_that_opened() {
    for read in [Read::new(), Read::new().uncached()] {
        let absent = absent().await;
        let mut events = absent.device.events();
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        reader.set_read_ahead(0);
        let stores = !read.stores_nothing();
        assert_eq!(absent.read(&mut reader, 0, 10).await, absent.bytes[..10]);
        assert_eq!(absent.holds(0).await, stores);
        for index in [0, 2] {
            let received = absent
                .engine
                .receive_sent(absent.of, unkeyed(&absent, index))
                .await
                .unwrap();
            assert_eq!(received, Received::BadChunk, "chunk {index}");
            assert_eq!(absent.holds(0).await, stores);
        }
        // The reader lives, and reads on.
        let piece = absent.read(&mut reader, CHUNK, 10).await;
        assert_eq!(piece, absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
        assert_eq!(absent.read(&mut reader, 5, 10).await, absent.bytes[5..15]);
        nothing_told(&mut events).await;
    }
}

/// The device holds part of an object it cannot open, a reference no
/// reader is open on, and so nothing has opened under the header held. A
/// part under another header that it cannot open either, and a part with
/// no header that is not of the length the header held gives: nothing
/// says which party is wrong, so what is held stays, the part is not
/// taken, and its sender is not given up.
#[tokio::test]
async fn a_part_that_does_not_open_drops_nothing_held_that_did_not_either() {
    let (absent, _) = referenced().await;
    absent
        .engine
        .retain(absent.of, &absent.locator, true)
        .await
        .unwrap();
    assert_eq!(absent.send(0).await, Received::Kept);
    assert!(absent.holds(0).await);
    let received = absent
        .engine
        .receive_sent(absent.of, forged(&absent, 2 * CHUNK + 10))
        .await
        .unwrap();
    assert_eq!(received, Received::Undecided);
    assert!(absent.holds(0).await);
    let short = ObjectPart {
        header: None,
        chunk: vec![7; 1000],
        ..absent.parts[1].clone()
    };
    let received = absent.engine.receive_sent(absent.of, short).await.unwrap();
    assert_eq!(received, Received::Undecided);
    assert!(absent.holds(0).await);
    // The parts of the object still join what is held.
    assert_eq!(absent.send(1).await, Received::Kept);
}

/// The device holds a header and a chunk of a reference that a party
/// without its key made up, kept while no reader was open. A reader then
/// opens with the object's key: the chunks that open under it take the
/// place of what was held, and the blob is read.
#[tokio::test]
async fn what_was_held_unopened_gives_way_to_a_part_that_opens() {
    let (absent, _) = referenced().await;
    absent
        .engine
        .retain(absent.of, &absent.locator, true)
        .await
        .unwrap();
    let made_up = forged(&absent, 2 * CHUNK + 10);
    let received = absent
        .engine
        .receive_sent(absent.of, made_up)
        .await
        .unwrap();
    assert_eq!(received, Received::Kept);
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    // At the chunk that was made up, and elsewhere.
    for offset in [2 * CHUNK + 3, 5] {
        let piece = read_again(&absent, &mut reader, offset, 5).await;
        assert_eq!(piece, absent.bytes[offset as usize..offset as usize + 5]);
    }
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
}
