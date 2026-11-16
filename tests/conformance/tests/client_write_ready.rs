//! A device reopened as restored writes in a space only once it has synced
//! it (at-rest.md, 3.6 "After a restore"): the root API says when, by
//! `Space::is_write_ready`, `Space::wait_write_ready`,
//! `Space::observe_write_ready` and `Event::WriteReady`. Every wait has a
//! deadline, and nothing leaves the host.

use frasil::{Device, Error, Event, Options, Status, Storage};
use frasil_conformance::spawn_loopback;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(30);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

fn directory(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_device_waits_until_it_may_write() {
    let peer = spawn_loopback().await.unwrap();
    let dir = directory("write-ready-restored");
    let key = [11; 32];
    // The default restore mode counts every start as a restore.
    let options = || Options::new().loopback();
    let space = {
        let device = Device::open_with(Storage::directory(&dir), &key, options())
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        assert!(space.is_write_ready().await);
        device.connect(&peer.origin).await.unwrap();
        within(space.flush()).await.unwrap();
        device.close().await.unwrap();
        space.id()
    };

    let device = Device::open_with(Storage::directory(&dir), &key, options())
        .await
        .unwrap();
    let mut events = device.events();
    let held = device.space(space).await.unwrap();
    assert!(!held.is_write_ready().await);
    let mut observed = held.observe_write_ready();
    let first = within(async {
        loop {
            let observation = observed.get();
            if observation.status == Status::Ready {
                break observation.value.as_deref().copied();
            }
            observed.changed().await.expect("the device is open");
        }
    })
    .await;
    assert_eq!(first, Some(false));

    // Without a peer the wait ends refused, and a write is refused too.
    assert_eq!(
        held.wait_write_ready(Duration::from_millis(100)).await,
        Err(Error::SyncBeforeWriting)
    );
    let note = held.create_document().unwrap();
    assert_eq!(
        note.edit(|doc| doc.get_text("body").insert(0, "x"))
            .await
            .unwrap_err(),
        Error::SyncBeforeWriting
    );

    // Once connected, the device syncs the space, and may write there.
    device.connect(&peer.origin).await.unwrap();
    within(held.wait_write_ready(DEADLINE)).await.unwrap();
    assert!(held.is_write_ready().await);
    note.edit(|doc| doc.get_text("body").insert(0, "x"))
        .await
        .unwrap();
    let ready = within(async {
        loop {
            if let Some(Event::WriteReady { space: ready }) = events.next().await {
                break ready;
            }
        }
    })
    .await;
    assert_eq!(ready, space);
    within(async {
        loop {
            let observation = observed.get();
            if observation.value.as_deref() == Some(&true) {
                break;
            }
            observed.changed().await.expect("the device is open");
        }
    })
    .await;
    // A space the device may already write in returns at once.
    held.wait_write_ready(Duration::ZERO).await.unwrap();

    device.close().await.unwrap();
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_device_never_restored_may_write_at_once() {
    let dir = directory("write-ready-never-restored");
    let key = [12; 32];
    let options = || Options::new().never_restored();
    let space = {
        let device = Device::open_with(Storage::directory(&dir), &key, options())
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        device.close().await.unwrap();
        space.id()
    };
    let device = Device::open_with(Storage::directory(&dir), &key, options())
        .await
        .unwrap();
    let held = device.space(space).await.unwrap();
    assert!(held.is_write_ready().await);
    held.wait_write_ready(Duration::ZERO).await.unwrap();
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
