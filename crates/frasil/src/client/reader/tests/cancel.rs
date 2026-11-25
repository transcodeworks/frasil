//! A reader that gives up what it asked for: every request it made goes,
//! whatever state it is in, and it reads again.

use super::*;

/// Before the header is known, a call that asked for the first chunk is
/// given up: its request stands until the reader cancels, then nothing is
/// asked for, nothing was stored, and the reader reads.
#[tokio::test]
async fn cancel_lets_go_of_what_was_asked_before_the_header_is_known() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    for sizing in [true, false] {
        {
            let mut buf = [0u8; 10];
            let waiting = async {
                if sizing {
                    reader.fetch_size().await.map(drop)
                } else {
                    reader.read_at(0, &mut buf).await.map(drop)
                }
            };
            tokio::pin!(waiting);
            tokio::select! {
                _ = &mut waiting => panic!("nothing arrived yet"),
                () = absent.asked_for(0) => {}
            }
        }
        assert!(!absent.asked().is_empty());
        assert_eq!(reader.size(), None);
        reader.cancel();
        assert!(absent.asked().is_empty());
    }
    assert!(!absent.holds(0).await);
    assert_eq!(absent.state().await, BlobState::Absent);
    assert_eq!(absent.read(&mut reader, 0, 100).await, absent.bytes[..100]);
    reader.close().await.unwrap();
}

/// In the middle of the blob, with chunks asked for ahead and a read
/// waiting for one: all of it goes, and a read elsewhere asks anew.
#[tokio::test]
async fn cancel_lets_go_of_a_read_and_of_what_was_asked_ahead() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    reader.set_read_ahead(2);
    let mut buf = [0u8; 10];
    {
        let reading = reader.read_at(0, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(0) => {}
        }
        assert_eq!(absent.send(0).await, Received::Kept);
        assert_eq!(reading.await.unwrap(), 10);
    }
    absent.asked_for(2).await;
    {
        let reading = reader.read_at(CHUNK, &mut buf);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    assert!(!absent.asked().is_empty());
    reader.cancel();
    assert!(absent.asked().is_empty());
    assert_eq!(reader.size(), Some(absent.bytes.len() as u64));
    assert!(!absent.holds(1).await);
    let at = 3 * CHUNK_BYTES;
    assert_eq!(
        absent.read(&mut reader, at as u64, 50).await,
        absent.bytes[at..at + 50]
    );
    reader.close().await.unwrap();
}

/// After the end there is nothing to let go, and the reader stays as it
/// was: whole, and readable.
#[tokio::test]
async fn cancel_after_the_end_leaves_the_reader_readable() {
    let absent = absent().await;
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let len = absent.bytes.len();
    assert_eq!(absent.read(&mut reader, 0, len).await, absent.bytes);
    let mut buf = [0u8; 10];
    assert_eq!(reader.read_at(len as u64, &mut buf).await.unwrap(), 0);
    reader.cancel();
    assert!(absent.asked().is_empty());
    assert_eq!(reader.verified(), Verified::Whole);
    assert_eq!(reader.read_at(len as u64, &mut buf).await.unwrap(), 0);
    assert_eq!(absent.read(&mut reader, 0, 100).await, absent.bytes[..100]);
    reader.close().await.unwrap();
}
