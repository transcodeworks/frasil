//! How long a read waits: not while the connection that holds its request
//! brings other chunks.

use super::*;
use crate::objects::Asked;

/// Two readers on one connection, which brings the chunks of one of them
/// ten seconds apart. The read of the other, queued behind them, does not
/// time out while they arrive, though none of its own does for longer
/// than a read waits. Once the connection only sends again chunks the
/// device has taken, the read's time is up.
#[tokio::test(start_paused = true)]
async fn a_read_queued_behind_another_readers_chunks_is_not_stalled() {
    let absent = absent_with(Options::new(), long()).await;
    let read = Read::new().uncached();
    let mut first = absent.blobs.open_reader(absent.id, &read).await.unwrap();
    let mut second = absent.blobs.open_reader(absent.id, &read).await.unwrap();
    first.set_read_ahead(0);
    second.set_read_ahead(6);
    // As the connection that holds the space's requests brings a part.
    let taken = || absent._taker.progressed();
    let send = |index: usize| {
        let asked = Asked {
            wanted: &|| true,
            stores: true,
            taken: &taken,
        };
        absent
            .engine
            .receive_part(absent.of, absent.parts[index].clone(), asked)
    };
    let mut scratch = [0u8; 10];
    {
        let reading = second.read_at(4 * CHUNK, &mut scratch);
        tokio::pin!(reading);
        tokio::select! {
            _ = &mut reading => panic!("nothing arrived yet"),
            () = absent.asked_for(4) => {}
        }
        assert_eq!(send(4).await.unwrap(), Received::Kept);
        assert_eq!(reading.await.unwrap(), 10);
    }
    // The chunks after it are asked for ahead.
    absent.asked_for(10).await;
    let mut buf = [0u8; 10];
    let reading = first.read_at(CHUNK, &mut buf);
    tokio::pin!(reading);
    tokio::select! {
        _ = &mut reading => panic!("nothing arrived yet"),
        () = absent.asked_for(1) => {}
    }
    // A minute of the other reader's chunks.
    for index in 5..=10 {
        tokio::select! {
            read = &mut reading => panic!("stalled while its connection brought chunks: {read:?}"),
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        assert_eq!(send(index).await.unwrap(), Received::Kept);
    }
    // The same chunk again and again is no progress.
    let read = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            tokio::select! {
                read = &mut reading => break read,
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    assert_ne!(send(10).await.unwrap(), Received::Kept);
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
