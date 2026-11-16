//! Keys for the application's own data (at-rest.md, "Application keys"),
//! through the client: one per purpose, stable across restarts, and a
//! space's going with the space.
#![cfg(feature = "sqlite")]

use frasil::{Device, Error, Storage};

#[tokio::test]
async fn a_device_derives_the_same_key_for_a_purpose_after_a_restart() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("app-keys");
    let _ = std::fs::remove_dir_all(&dir);
    let unlock = [7; 32];
    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    let cache = device.derive_key("com.example.cache").await.unwrap();
    let index = device.derive_key("com.example.index").await.unwrap();
    assert_ne!(*cache, *index);
    assert!(matches!(
        device.derive_key("").await,
        Err(Error::Invalid(_))
    ));
    let space = device.create_space().await.unwrap();
    let in_space = space.derive_key("com.example.cache").await.unwrap();
    assert_ne!(*in_space, *cache);
    let id = space.id();
    device.close().await.unwrap();

    let device = Device::open(Storage::directory(&dir), &unlock)
        .await
        .unwrap();
    assert_eq!(
        *device.derive_key("com.example.cache").await.unwrap(),
        *cache
    );
    let space = device.space(id).await.unwrap();
    assert_eq!(
        *space.derive_key("com.example.cache").await.unwrap(),
        *in_space
    );
    // Another device derives another key for the same purpose.
    let other = Device::open(Storage::Memory, &[8; 32]).await.unwrap();
    assert_ne!(
        *other.derive_key("com.example.cache").await.unwrap(),
        *cache
    );

    // A space's keys go with it.
    space.forget().await.unwrap();
    assert!(matches!(
        space.derive_key("com.example.cache").await,
        Err(Error::UnknownSpace)
    ));
    device.close().await.unwrap();
    other.close().await.unwrap();
}
