//! The person a directory store expects (at-rest.md, 3.1): keys that name
//! no person yet open as the recorded person's only when the device is
//! active in that person's list, which a crash between recording the
//! person and sealing the keys again leaves; keys of a device of no such
//! list stay refused `WrongPerson`.
#![cfg(feature = "sqlite")]

use frasil::{Device, Error, Storage};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("expected-person-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn keys_of_no_person_open_only_for_a_device_in_the_recorded_persons_list() {
    let unlock = [9; 32];
    let dir = temp_dir("resumed");
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    let unsealed = std::fs::read(dir.join("device-keys")).unwrap();
    let person = device.make_person(&unlock).await.unwrap();
    device.close().await.unwrap();

    // A crash after the person was recorded, before the keys were sealed
    // again: the step is finished on the next opening.
    std::fs::write(dir.join("device-keys"), &unsealed).unwrap();
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    assert_eq!(device.person().await, Some(person));
    device.close().await.unwrap();
    assert_ne!(std::fs::read(dir.join("device-keys")).unwrap(), unsealed);

    // Keys of a device that is in no list of the recorded person.
    let other = temp_dir("other");
    let stranger = Device::open(Storage::directory(&other), &unlock)
        .await
        .unwrap();
    stranger.close().await.unwrap();
    std::fs::write(other.join("person"), person.as_bytes()).unwrap();
    assert!(matches!(
        Device::open(Storage::directory(&other), &unlock).await,
        Err(Error::Class("WrongPerson"))
    ));
}
