//! The client fits on a native main thread's stack in debug builds.
#![cfg(all(not(target_arch = "wasm32"), feature = "adapter-loro"))]

use frasil::{Device, Options, Storage};

#[test]
fn client_runs_on_a_one_megabyte_stack() {
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let device = Device::open_with(
                    Storage::Memory,
                    &[7; 32],
                    Options::new().loopback().never_restored(),
                )
                .await
                .unwrap();
                let space = device.create_space().await.unwrap();
                let document = space.create_document().unwrap();
                document
                    .edit(|doc| doc.get_text("body").insert(0, "hello"))
                    .await
                    .unwrap();
                assert_eq!(document.text("body").await.unwrap(), "hello");
                device.engine().maintain_all().await.unwrap();
                tokio::task::yield_now().await;
                device.close().await.unwrap();
            });
        })
        .unwrap()
        .join()
        .unwrap();
}
