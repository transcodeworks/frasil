//! What a reader whose `close` does not run to its end leaves behind:
//! nothing.

use super::*;

/// A reader whose `close` is dropped before it ends leaves nothing that
/// uses the blob: its requests end, the task that follows the blob ends,
/// and the device looks at its cache.
#[tokio::test]
async fn a_close_that_is_dropped_leaves_nothing_that_uses_the_blob() {
    let absent = absent().await;
    let key = (absent.of, crate::replica::object_id(&absent.locator));
    let mut reader = absent
        .blobs
        .open_reader(absent.id, &Read::new().uncached())
        .await
        .unwrap();
    assert_eq!(absent.read(&mut reader, 0, 10).await, absent.bytes[..10]);
    {
        let closing = reader.close();
        tokio::pin!(closing);
        // Polled once, and dropped wherever it stands.
        tokio::select! {
            biased;
            _ = &mut closing => {}
            () = std::future::ready(()) => {}
        }
    }
    soon(|| async {
        absent.engine.readers().windows(&key) == 0
            && absent.engine.fetches().of(&absent.of).is_empty()
            && absent.engine.wanted(&key).is_none()
            && absent.blobs.drop_local(absent.id).await.is_ok()
    })
    .await;
    assert_eq!(absent.state().await, BlobState::Absent);
}
