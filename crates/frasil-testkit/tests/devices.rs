//! The device helpers, as an application's test uses them.

use frasil::Level;
use frasil_testkit::devices::{admit, device, eventually, shared};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_share_a_space_without_a_peer() {
    let pair = shared(Level::Write).await;
    assert_eq!(pair.bobs_space.level().await, Some(Level::Write));
    let notes = pair.space.create_records().unwrap();
    notes
        .write(|tx| {
            tx.insert("notes", b"n1").set("notes", b"n1", "text", "hi");
        })
        .await
        .unwrap();
    eventually("Bob reads the note", || async {
        match pair.bobs_space.records(notes.id()).await {
            Ok(theirs) => theirs.row("notes", b"n1").await.unwrap().is_some(),
            Err(_) => false,
        }
    })
    .await;

    // A third device, admitted to read.
    let carol = device(3).await;
    let carols_space = admit(&pair.space, &carol, Level::Read).await;
    assert_eq!(carols_space.level().await, Some(Level::Read));
    carol.close().await.unwrap();
    pair.close().await;
}
