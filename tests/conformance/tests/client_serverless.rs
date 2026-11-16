//! Collaboration with no always-on peer (ext-guests.md, "A session with no
//! peer"): two devices that have no direct path to each other share only an
//! iroh relay, on loopback under a test certificate, and no peer runs at
//! all. One writes a space alone, invites the other as a guest, both
//! compare the admission code, both edit the same document at once and
//! converge, and once the session ends the guest receives nothing written
//! after. Every wait has a deadline.
#![cfg(feature = "ext-guests")]

use frasil::{Device, Guest, Level, Options, Storage};
use iroh_relay::server::{CertConfig, Server, testing};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// An iroh relay on loopback, its HTTPS URL, and the certificate a device
/// trusts it by.
async fn relay() -> (Server, String, Vec<u8>) {
    let (certs, server_config) = testing::self_signed_tls_certs_and_config();
    let mut config = testing::server_config();
    config.quic = None;
    let tls = config.relay.as_mut().unwrap().tls.as_mut().unwrap();
    tls.cert = CertConfig::Manual { server_config };
    let server = Server::spawn(config).await.unwrap();
    let url = server.https_url().unwrap().to_string();
    (server, url, certs[0].to_vec())
}

/// A device with no IP socket, so that it reaches the other only through
/// the relay.
async fn device(key: u8, url: &str, root: &[u8]) -> Device {
    let options = Options::new()
        .relay_only()
        .relay_root(root.to_vec())
        .relay(url);
    Device::open_with(Storage::Memory, &[key; 32], options)
        .await
        .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_with_no_peer_collaborate_through_a_relay() {
    let (server, url, root) = relay().await;

    // Alice writes a space alone.
    let alice = device(1, &url, &root).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Draft"))
        .await
        .unwrap();
    assert!(alice.peers().is_empty());

    // She invites Bob as a guest; he joins from the invitation's text, and
    // both compare the same code.
    let codes = Arc::new(Mutex::new(Vec::new()));
    let guest = Guest::new(Level::Write, [9; 16]);
    let hosting = codes.clone();
    let invitation = within(space.invite_guest(&guest, "Alice", move |code, _| {
        hosting.lock().unwrap().push(code);
        async { true }
    }))
    .await
    .unwrap();
    let bob = device(2, &url, &root).await;
    let text = invitation.text().to_owned();
    let joining = codes.clone();
    let (bobs_space, admitted) = within(async {
        tokio::join!(
            bob.join(&text, "Bob", move |code, _| {
                joining.lock().unwrap().push(code);
                async { true }
            }),
            invitation.admitted()
        )
    })
    .await;
    let bobs_space = bobs_space.unwrap();
    admitted.unwrap();
    {
        let codes = codes.lock().unwrap();
        assert_eq!(codes.len(), 2);
        assert_eq!(codes[0], codes[1], "both screens show one code");
    }
    assert_eq!(bobs_space.level().await, Some(Level::Write));
    assert!(bob.peers().is_empty());

    // Each sees the other connected, and Bob reads the draft.
    until(|| async { space.connected_members().contains(&bob.id()) }).await;
    until(|| async { bobs_space.connected_members().contains(&alice.id()) }).await;
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(note.id()).await
                && note.text("body").await.unwrap() == "Draft"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // Both edit at once, and converge.
    let (alices, bobs) = tokio::join!(
        note.edit(|doc| {
            let body = doc.get_text("body");
            body.insert(body.len_unicode(), " by Alice")
        }),
        bobs_note.edit(|doc| doc.get_text("body").insert(0, "Bob: "))
    );
    alices.unwrap();
    bobs.unwrap();
    until(|| async {
        let (a, b) = (
            note.text("body").await.unwrap(),
            bobs_note.text("body").await.unwrap(),
        );
        a == b && a.contains("Bob: ") && a.contains(" by Alice")
    })
    .await;

    // Alice ends the session: Bob is out, and receives nothing written
    // after.
    space.end_session(guest.session()).await.unwrap();
    let before = bobs_note.text("body").await.unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Later. "))
        .await
        .unwrap();
    until(|| async { !space.connected_members().contains(&bob.id()) }).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(bobs_note.text("body").await.unwrap(), before);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    server.shutdown().await.unwrap();
}

/// One document of a larger space, carved out (ext-restricted-spaces.md)
/// and shared with a guest through the relay alone: the guest reads that
/// document, and nothing else of the space it came from.
#[cfg(feature = "ext-restricted-spaces")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_with_no_peer_reads_one_carved_out_document() {
    let (server, url, root) = relay().await;
    let alice = device(1, &url, &root).await;
    let space = alice.create_space().await.unwrap();
    let shared = space.create_document().unwrap();
    shared
        .edit(|doc| doc.get_text("body").insert(0, "Shared"))
        .await
        .unwrap();
    let private = space.create_document().unwrap();
    private
        .edit(|doc| doc.get_text("body").insert(0, "Private"))
        .await
        .unwrap();
    let carved = shared.carve_out().await.unwrap();
    let guest = Guest::new(Level::Write, [5; 16]);
    let invitation = within(
        carved
            .space()
            .invite_guest(&guest, "Alice", |_, _| async { true }),
    )
    .await
    .unwrap();
    let bob = device(2, &url, &root).await;
    let text = invitation.text().to_owned();
    let (bobs_space, admitted) = within(async {
        tokio::join!(
            bob.join(&text, "Bob", |_, _| async { true }),
            invitation.admitted()
        )
    })
    .await;
    let bobs_space = bobs_space.unwrap();
    admitted.unwrap();
    assert_eq!(bobs_space.id(), carved.space().id());
    until(|| async {
        match bobs_space.document(carved.id()).await {
            Ok(note) => note.text("body").await.unwrap() == "Shared",
            Err(_) => false,
        }
    })
    .await;
    // Of the larger space Bob holds at most its membership: no level, and
    // no document.
    if let Ok(larger) = bob.space(space.id()).await {
        assert_eq!(larger.level().await, None);
        assert!(larger.document(private.id()).await.is_err());
    }
    assert!(bobs_space.document(private.id()).await.is_err());
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    server.shutdown().await.unwrap();
}

/// A device whose store is a directory, so that it opens again, reaching
/// the other only through the relay.
#[cfg(feature = "ext-next-endpoints")]
async fn directory_device(dir: &std::path::Path, key: u8, url: &str, root: &[u8]) -> Device {
    let options = Options::new()
        .relay_only()
        .relay_root(root.to_vec())
        .relay(url);
    Device::open_with(Storage::directory(dir), &[key; 32], options)
        .await
        .expect("a device")
}

#[cfg(feature = "ext-next-endpoints")]
fn temp_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "frasil-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// ext-next-endpoints.md: a host and its guest, with no peer, both close
/// and open again, so both member endpoint keys rotate. Each dials the
/// ticket it kept of the other under the key the other announced, and
/// they sync again with no new invitation.
#[cfg(feature = "ext-next-endpoints")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_and_its_guest_meet_again_after_both_rotate() {
    let (server, url, root) = relay().await;
    let (alices_dir, bobs_dir) = (temp_dir("next-alice"), temp_dir("next-bob"));

    let alice = directory_device(&alices_dir, 1, &url, &root).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Draft"))
        .await
        .unwrap();
    let guest = Guest::new(Level::Write, [7; 16]);
    let invitation = within(space.invite_guest(&guest, "Alice", |_, _| async { true }))
        .await
        .unwrap();
    let bob = directory_device(&bobs_dir, 2, &url, &root).await;
    let text = invitation.text().to_owned();
    let (bobs_space, admitted) = within(async {
        tokio::join!(
            bob.join(&text, "Bob", |_, _| async { true }),
            invitation.admitted()
        )
    })
    .await;
    let bobs_space = bobs_space.unwrap();
    admitted.unwrap();
    until(|| async { space.connected_members().contains(&bob.id()) }).await;
    until(|| async { bobs_space.connected_members().contains(&alice.id()) }).await;
    // Each has announced its next key, every half second on an attach both
    // admitted, and the other has kept it.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let space_id = space.id();
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    drop((space, note, bobs_space, alice, bob));

    // Both open again: each binds under the key it announced.
    let alice = directory_device(&alices_dir, 1, &url, &root).await;
    let bob = directory_device(&bobs_dir, 2, &url, &root).await;
    let space = alice.space(space_id).await.unwrap();
    let bobs_space = bob.space(space_id).await.unwrap();
    until(|| async { space.connected_members().contains(&bob.id()) }).await;
    until(|| async { bobs_space.connected_members().contains(&alice.id()) }).await;
    // A device in a directory opens as restored (RestoreMode::None), so it
    // signs in the space only once it has synced it again (at-rest.md,
    // "After a restore").
    let event = frasil_events::EventId(*space_id.as_bytes());
    until(|| async { alice.engine().may_sign(&event).await }).await;

    // A document written now reaches the other.
    let later = space.create_document().unwrap();
    later
        .edit(|doc| doc.get_text("body").insert(0, "Again"))
        .await
        .unwrap();
    until(|| async {
        match bobs_space.document(later.id()).await {
            Ok(note) => note.text("body").await.unwrap() == "Again",
            Err(_) => false,
        }
    })
    .await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&alices_dir);
    let _ = std::fs::remove_dir_all(&bobs_dir);
}

/// A newcomer keeps what its admission's snapshot brought: closed and
/// opened again from its directory, it still reads the document it read
/// before, with no peer and the host gone.
async fn a_newcomer_reads_its_snapshot_after_reopening(guest: bool) {
    let (server, url, root) = relay().await;
    let dir = std::env::temp_dir().join(format!(
        "frasil-snapshot-reopen-{guest}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let options = || {
        Options::new()
            .relay_only()
            .relay_root(root.clone())
            .relay(&url)
    };
    let alice = device(1, &url, &root).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Draft"))
        .await
        .unwrap();
    let invitation = if guest {
        within(
            space.invite_guest(&Guest::new(Level::Write, [7; 16]), "Alice", |_, _| async {
                true
            }),
        )
        .await
        .unwrap()
    } else {
        within(space.invite(Level::Write, "Alice", |_, _| async { true }))
            .await
            .unwrap()
    };
    let bob = Device::open_with(Storage::directory(&dir), &[2; 32], options())
        .await
        .unwrap();
    let text = invitation.text().to_owned();
    let (bobs_space, admitted) = within(async {
        tokio::join!(
            bob.join(&text, "Bob", |_, _| async { true }),
            invitation.admitted()
        )
    })
    .await;
    let bobs_space = bobs_space.unwrap();
    admitted.unwrap();
    until(|| async {
        match bobs_space.document(note.id()).await {
            Ok(note) => note.text("body").await.unwrap() == "Draft",
            Err(_) => false,
        }
    })
    .await;
    let id = space.id();
    bob.close().await.unwrap();
    drop((bobs_space, bob));
    alice.close().await.unwrap();

    let bob = Device::open_with(Storage::directory(&dir), &[2; 32], options())
        .await
        .unwrap();
    let reopened = bob.space(id).await.unwrap();
    let read = match reopened.document(note.id()).await {
        Ok(note) => note.text("body").await.map_err(|e| e.to_string()),
        Err(error) => Err(error.to_string()),
    };
    assert_eq!(read, Ok("Draft".to_owned()), "guest: {guest}");
    bob.close().await.unwrap();
    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_reads_its_snapshot_after_reopening() {
    a_newcomer_reads_its_snapshot_after_reopening(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_reads_its_snapshot_after_reopening() {
    a_newcomer_reads_its_snapshot_after_reopening(false).await;
}
