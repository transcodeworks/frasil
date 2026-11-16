//! Host adapters implemented using only the high-level root API.
use frasil::{BoxFuture, DeviceBoundSlot, KeepKeys, Options, Result, StoreError};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct HostStorage(Mutex<Option<Vec<u8>>>);

impl KeepKeys for HostStorage {
    fn keep<'a>(&'a self, sealed: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            *self.0.lock().unwrap() = Some(sealed.to_vec());
            Ok(())
        })
    }
}

impl DeviceBoundSlot for HostStorage {
    fn read(&self) -> BoxFuture<'_, std::result::Result<Option<Vec<u8>>, StoreError>> {
        Box::pin(async { Ok(self.0.lock().unwrap().clone()) })
    }
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, std::result::Result<(), StoreError>> {
        Box::pin(async move {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        })
    }
}

#[test]
fn host_adapters_are_available_at_the_root() {
    let _ = Options::new()
        .keep_keys(Arc::new(HostStorage::default()))
        .device_bound(Arc::new(HostStorage::default()));
}
