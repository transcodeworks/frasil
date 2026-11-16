//! Offline authored changes and partial durability acknowledgements.
#![cfg(feature = "adapter-records")]

use frasil::advanced::outbox::Acknowledger;
use frasil::{Device, Event, Storage};

#[tokio::test]
async fn two_offline_writes_and_partial_acknowledgement() {
    let device = Device::open(Storage::Memory, &[42; 32]).await.unwrap();
    let mut events = device.events();
    let space = device.create_space().await.unwrap();
    let id = frasil_events::EventId(*space.id().as_bytes());
    let initial = space.pending_authored_changes().await;
    async fn count_event(events: &mut frasil::Events, expected: u64) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(Event::PendingChanges { count, .. }) = events.next().await {
                    assert_eq!(count, expected);
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    count_event(&mut events, initial).await;
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            tx.insert("rows", b"one");
        })
        .await
        .unwrap();
    count_event(&mut events, initial + 1).await;
    let first = device.engine().outbox(&id).await;
    records
        .write(|tx| {
            tx.insert("rows", b"two");
        })
        .await
        .unwrap();
    assert_eq!(space.pending_authored_changes().await, initial + 2);
    assert!(!space.is_durable().await);
    count_event(&mut events, initial + 2).await;
    device
        .engine()
        .acknowledge(id, Acknowledger::Peer([1; 32]), &first)
        .await
        .unwrap();
    assert_eq!(space.pending_authored_changes().await, 1);
    count_event(&mut events, 1).await;
    let heads = device.engine().outbox(&id).await;
    device
        .engine()
        .acknowledge(id, Acknowledger::Peer([1; 32]), &heads)
        .await
        .unwrap();
    assert_eq!(space.pending_authored_changes().await, 0);
    space.flush().await.unwrap();
    loop {
        if let Some(Event::PendingChanges {
            space: changed,
            count,
        }) = events.next().await
        {
            assert_eq!(changed, space.id());
            assert_eq!(count, 0);
            break;
        }
    }
    device.close().await.unwrap();
}
