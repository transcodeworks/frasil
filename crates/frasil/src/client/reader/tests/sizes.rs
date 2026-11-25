//! The size a whole read and a range read go by is the header's, which
//! the blob's chunks bind, and not the entry's.

use super::*;

/// An entry that shows less than its object holds: a stream of the blob
/// ends its progress with the size the header gives, and a range read of
/// the blob held whole reaches past the size the entry shows.
#[tokio::test]
async fn a_whole_read_and_a_range_read_go_by_the_headers_size() {
    let absent = mislabelled(1000).await;
    let size = absent.bytes.len() as u64;
    let mut reports = Vec::new();
    let mut out = Vec::new();
    {
        let read = Read::new();
        let streaming = absent
            .blobs
            .get_stream(absent.id, &mut out, &read, |at, of| reports.push((at, of)));
        tokio::pin!(streaming);
        loop {
            tokio::select! {
                streamed = &mut streaming => break streamed.unwrap(),
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    for (index, _) in absent.asked() {
                        absent.send(index as usize).await;
                    }
                }
            }
        }
    }
    assert_eq!(out, absent.bytes);
    assert_eq!(reports.last(), Some(&(size, Some(size))));
    // Held whole now: a range past the size the entry shows.
    assert!(
        absent
            .engine
            .read(&absent.of, |replica| replica.holds_object(&absent.locator))
            .await
            .unwrap()
    );
    let range = absent
        .blobs
        .get_range(absent.id, 2000, 10, &Read::new())
        .await
        .unwrap();
    assert_eq!(range.as_deref(), Some(&absent.bytes[2000..2010]));
    let end = absent
        .blobs
        .get_range(absent.id, size - 4, 10, &Read::new())
        .await
        .unwrap();
    assert_eq!(
        end.as_deref(),
        Some(&absent.bytes[absent.bytes.len() - 4..])
    );
}
