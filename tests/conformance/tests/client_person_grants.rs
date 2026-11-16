//! A person granted in a space reaches devices connected only through a
//! peer (admission.md, 3.10 Welcomes): the granting device deposits each of
//! the person's devices' welcomes in its device mailbox at the peer, and
//! each device collects it there, whether it connects over the server
//! binding or through a connector the application supplies, as a browser
//! does. Every wait has a deadline, and nothing leaves the host.

use frasil::advanced::{Connect, Engine};
use frasil::{Device, Level, Options, Space, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_store::BoxFuture;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Connects as a browser's connector does: through the application, here
/// over the server binding's own WebSocket.
struct Supplied;

impl Connect for Supplied {
    fn connect(
        &self,
        engine: Engine,
        url: String,
        spaces: Vec<EventId>,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::PeerHandle>> {
        Box::pin(async move { frasil::advanced::peer::connect_server(&engine, &url, spaces).await })
    }

    fn administer(
        &self,
        engine: Engine,
        url: String,
        space: EventId,
    ) -> BoxFuture<'static, frasil::Result<bool>> {
        Box::pin(
            async move { frasil::advanced::peer::administer_server(&engine, &url, space).await },
        )
    }

    fn bare(
        &self,
        engine: Engine,
        url: String,
    ) -> BoxFuture<'static, frasil::Result<frasil::advanced::peer::Bare>> {
        Box::pin(async move { frasil::advanced::peer::bare_server(&engine, &url).await })
    }
}

async fn device(key: u8, options: Options) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], options.loopback())
        .await
        .expect("a device")
}

/// A new device of the person of `first`, joined through the peer's
/// exchange mailbox.
async fn joined(first: &Device, new: &Device, origin: &str, key: u8) {
    let person = first.person().await.unwrap();
    let joining =
        within(new.join_person_via_peer(origin, person, "New", &[key; 32], |_, _| async { true }))
            .await
            .unwrap();
    within(first.admit_device(joining.text(), "First", |_, _| async { true }))
        .await
        .unwrap();
    within(joining.joined()).await.unwrap();
}

async fn reads(device: &Device, space: &Space, text: &str) {
    within(async {
        loop {
            if let Ok(held) = device.space(space.id()).await
                && let Ok(streams) = held.streams().await
                && let Some(stream) = streams.first()
                && let Ok(document) = held.document(stream.id).await
                && document.text("body").await.ok().as_deref() == Some(text)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_grant_reaches_devices_connected_only_through_a_peer() {
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let alice = device(1, Options::new()).await;
    alice.make_person(&[1; 32]).await.unwrap();
    alice.connect(&origin).await.unwrap();

    // Bob's first device, then a server-only device and a browser-style
    // device of Bob, each joined through the peer.
    let bob = device(2, Options::new()).await;
    let person = bob.make_person(&[2; 32]).await.unwrap();
    bob.connect(&origin).await.unwrap();
    let server = device(3, Options::new()).await;
    server.connect(&origin).await.unwrap();
    joined(&bob, &server, &origin, 3).await;
    let browser = device(4, Options::new().connect_with(Arc::new(Supplied))).await;
    browser.connect(&origin).await.unwrap();
    joined(&bob, &browser, &origin, 4).await;

    // Alice holds Bob's list, as a person admission leaves it, and grants
    // Bob's person in a space of hers.
    alice
        .engine()
        .receive_list(bob.engine().list_events(person.as_bytes()).await)
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "for Bob"))
        .await
        .unwrap();
    space.grant_person(person, Level::Read).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();

    // The server-only device's upkeep collects its welcome.
    reads(&server, &space, "for Bob").await;
    // The browser-style device collects it on request, or its upkeep did.
    let reports = within(browser.receive_welcomes_via_peer(&origin, |_| {}))
        .await
        .unwrap();
    assert!(
        reports.iter().all(|report| report.result.is_ok()),
        "{reports:?}"
    );
    reads(&browser, &space, "for Bob").await;
    // Collecting again finds nothing new: the space is held.
    let again = within(browser.receive_welcomes_via_peer(&origin, |_| {}))
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");

    for device in [alice, bob, server, browser] {
        device.close().await.unwrap();
    }
    peer.shutdown().await;
}
