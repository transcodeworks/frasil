//! A header that names a state the device holds no key of, where the
//! blob's entry names one it holds: not admitted, and let go where the
//! device holds it already.

use super::arrival::unkeyed;
use super::*;

/// Nothing is held of a blob whose entry names a state the device holds
/// the key of. A party answers a read with a header that names another
/// state, which the device holds no key of, and a chunk nothing opens:
/// the part is not admitted, and the read ends with the chunk another
/// party sends, not with `Sealed`.
#[tokio::test]
async fn a_header_of_a_state_the_entry_does_not_name_is_not_admitted() {
    for read in [Read::new(), Read::new().uncached()] {
        let absent = absent().await;
        let second = absent.engine.fetches().attach(absent.of);
        let mut reader = absent.blobs.open_reader(absent.id, &read).await.unwrap();
        reader.set_read_ahead(0);
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
                .receive_sent(absent.of, unkeyed(&absent, 1))
                .await
                .unwrap();
            assert_eq!(received, Received::BadChunk);
            assert!(!absent.holds(1).await);
            assert_eq!(absent.send(1).await, Received::Kept);
            reading.await
        };
        assert_eq!(read.unwrap(), 10);
        assert_eq!(buf[..], absent.bytes[CHUNK as usize..CHUNK as usize + 10]);
        drop(second);
    }
}

/// The store holds such a header and chunk from before, under which
/// nothing opened. A read lets them go and asks again: it ends with the
/// blob's bytes once a party sends a chunk that opens, and is not
/// `Sealed` for as long as the cache holds what was made up.
#[tokio::test]
async fn a_stored_header_the_device_cannot_open_is_let_go() {
    let absent = absent().await;
    let part = unkeyed(&absent, 1);
    absent
        .engine
        .store_parts(absent.of, &[&part], false)
        .await
        .unwrap();
    assert!(absent.holds(1).await);
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(0);
    for offset in [CHUNK + 7, 3] {
        let piece = read_again(&absent, &mut reader, offset, 5).await;
        assert_eq!(piece, absent.bytes[offset as usize..offset as usize + 5]);
    }
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
}
