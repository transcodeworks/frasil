//! What a request that ends leaves behind: nothing.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The request that asked for a chunk ends between the moment the device
/// decides to hold its object and the moment it would store the chunk:
/// the chunk is not stored, and the cached record made for it does not
/// stay behind with no part.
#[tokio::test]
async fn a_request_that_ends_as_its_chunk_is_admitted_leaves_no_record() {
    let absent = absent().await;
    let reader = absent
        .blobs
        .open_reader(absent.id, &Read::new())
        .await
        .unwrap();
    let key = (absent.of, crate::replica::object_id(&absent.locator));
    let recorded = || async { absent.engine.lock().await.retained.get(&key).is_some() };
    assert!(!recorded().await);
    // Wanted when the device is asked whether it means to hold the
    // object, and no longer once it has said so.
    let asked = AtomicUsize::new(0);
    let wanted = || asked.fetch_add(1, Ordering::SeqCst) == 0;
    let received = absent
        .engine
        .receive_part(
            absent.of,
            absent.parts[0].clone(),
            crate::objects::Asked {
                wanted: &wanted,
                stores: true,
                taken: &|| (),
            },
        )
        .await
        .unwrap();
    assert_ne!(received, Received::Kept);
    assert!(!absent.holds(0).await);
    assert!(!recorded().await, "a cached record with no part stays");
    reader.close().await.unwrap();
    assert_eq!(absent.state().await, BlobState::Absent);
}
