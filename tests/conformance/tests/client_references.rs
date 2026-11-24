//! File references (adapter-blobs.md, "References"; ext-libraries.md,
//! "Holds") through the client, on loopback: Alice stores a file in space
//! A, a media bank, and references it from space B, a show. The file is
//! deleted in A and stays for B, whose hold keeps it; Bob, whose device
//! belongs to B alone, then plays it. The library's ledger counts it once,
//! and once B removes its reference the peer collects the file. A
//! reference to a space of another library is refused.

#![cfg(feature = "ext-libraries")]

use frasil::{Device, Error, Level, Options, Space, Storage};
use frasil_events::EventId;
use frasil_libraries::{Issuer, LibraryId, Purpose, Ticket, TrustedIssuers};
use frasil_relay::libraries::{Ledger, LibrarySettings};
use frasil_relay::testing::{OPEN_LIBRARY, Options as PeerOptions, TestPeer, spawn_with};
use frasil_relay::{Clock, Settings};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);

/// The file: large enough that counting it twice would show.
const FILE_BYTES: usize = 300_000;

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

fn issuer() -> Issuer {
    Issuer::from_seed(&[7; 32])
}

/// A peer whose open library takes creates without a ticket, and that
/// trusts one issuer for other libraries.
async fn peer() -> TestPeer {
    spawn_with(PeerOptions {
        settings: Settings {
            libraries: LibrarySettings {
                issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
                open_library: LibraryId::new(OPEN_LIBRARY).ok(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        },
        ..frasil_conformance::options()
    })
    .await
    .unwrap()
}

fn move_ticket(peer: &TestPeer, library: &str) -> Vec<u8> {
    let issuer = issuer();
    let wall = peer.clock.now().wall.expect("the wall clock");
    issuer.sign(&Ticket {
        library: LibraryId::new(library).unwrap(),
        id: [3; 16],
        purpose: Purpose::Move,
        not_after: wall + 3600,
        issuer: *issuer.public(),
        tokens: None,
    })
}

fn event(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// Waits until the peer acknowledged every event of the space.
async fn durable(device: &Device, space: &Space) {
    within(async {
        while !device.engine().outbox(&event(space)).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

fn ledger(peer: &TestPeer) -> Ledger {
    peer.peer
        .ledger(&LibraryId::new(OPEN_LIBRARY).unwrap())
        .expect("the open library's ledger")
}

/// A space's usage in the ledger: `used_bytes`, `held_bytes`, `holds`.
fn usage(ledger: &Ledger, space: &Space) -> (u64, u64, u64) {
    let row = ledger
        .spaces
        .iter()
        .find(|row| row.space == *space.id().as_bytes())
        .expect("the space is in the ledger");
    (
        row.usage.used_bytes(),
        row.usage.held_bytes,
        row.usage.holds,
    )
}

/// Compacts a blob stream, waits for the peer, and lets the peer's
/// timeline pass the library's erasure timeout, so that it collects the
/// cover.
async fn compact_and_collect(peer: &TestPeer, device: &Device, space: &Space, stream: [u8; 16]) {
    device
        .engine()
        .compact(event(space), stream)
        .await
        .expect("a snapshot");
    // The snapshot unit waits for its object, so once it is durable the
    // peer holds both.
    durable(device, space).await;
    peer.advance(8 * 86_400).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_is_stored_once_and_referenced_across_a_library() {
    let peer = peer().await;
    let alice = device(1).await;
    let bank = alice.create_space().await.unwrap();
    let show = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();

    // Alice stores the file once, in the media bank.
    let file: Vec<u8> = (0..FILE_BYTES).map(|i| (i % 251) as u8).collect();
    let bank_blobs = bank.create_blobs().unwrap();
    let stored = within(bank_blobs.put(Some("opening.mp4"), &file))
        .await
        .unwrap();
    durable(&alice, &bank).await;
    let before = ledger(&peer).used_bytes();

    // The show references it: a hold at the peer, and an entry in B.
    let show_blobs = show.create_blobs().unwrap();
    let referenced = within(show_blobs.reference_from(&bank_blobs, stored))
        .await
        .unwrap();
    durable(&alice, &show).await;
    let info = show_blobs.info(referenced).await.unwrap();
    assert!(info.is_reference());
    assert_eq!(info.source, Some(bank.id()));
    assert_eq!(info.size, FILE_BYTES as u64);
    assert_eq!(info.name.as_deref(), Some("opening.mp4"));
    assert!(!bank_blobs.info(stored).await.unwrap().is_reference());
    assert_eq!(
        show_blobs
            .get(referenced, &frasil::Read::new())
            .await
            .unwrap(),
        Some(file.clone())
    );
    // A range of it, opened with the reference's key.
    let (at, len) = (FILE_BYTES / 3, 4096.min(FILE_BYTES / 3));
    assert_eq!(
        show_blobs
            .get_range(referenced, at as u64, len as u64, &frasil::Read::new())
            .await
            .unwrap(),
        Some(file[at..at + len].to_vec())
    );

    // The library's ledger counts the file once: the show added its own
    // events, and a hold.
    let after = ledger(&peer);
    let added = after.used_bytes() - before;
    assert!(
        added < FILE_BYTES as u64 / 10,
        "the file counted again: {added}"
    );
    let (show_used, _, show_holds) = usage(&after, &show);
    assert!(show_used < FILE_BYTES as u64);
    assert_eq!(show_holds, 1);
    let (bank_used, bank_held, _) = usage(&after, &bank);
    assert!(bank_used >= FILE_BYTES as u64);
    assert_eq!(bank_held, 0, "the bank still lists the file");

    // The bank deletes the file: its entry removed, compacted and
    // collected. The show's hold keeps it, still counted once, in the bank.
    bank_blobs.remove(stored).await.unwrap();
    durable(&alice, &bank).await;
    compact_and_collect(&peer, &alice, &bank, *bank_blobs.id().as_bytes()).await;
    let kept = ledger(&peer);
    let (bank_used, bank_held, _) = usage(&kept, &bank);
    assert!(bank_held >= FILE_BYTES as u64, "the hold keeps the file");
    assert!(bank_used >= bank_held);
    assert!(kept.used_bytes() < before + FILE_BYTES as u64);

    // Bob's device joins the show alone, and plays the file.
    let bob = device(2).await;
    let invitation = show
        .invite(Level::Read, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_show = within(bob.join(invitation.text(), "Venue", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    assert!(
        bob.space(bank.id()).await.is_err(),
        "Bob is no member of the bank"
    );
    let bobs_blobs = within(async {
        loop {
            if let Ok(blobs) = bobs_show.blobs(show_blobs.id()).await
                && blobs.info(referenced).await.is_ok()
            {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let bobs_info = bobs_blobs.info(referenced).await.unwrap();
    assert_eq!(bobs_info.source, Some(bank.id()));
    let mut played = Vec::new();
    within(bobs_blobs.get_stream(referenced, &mut played, &frasil::Read::new(), |_, _| {}))
        .await
        .unwrap();
    assert_eq!(played, file, "Bob plays the file");
    assert_eq!(
        bobs_blobs
            .get_range(
                referenced,
                (FILE_BYTES - 10) as u64,
                100,
                &frasil::Read::new()
            )
            .await
            .unwrap(),
        Some(file[FILE_BYTES - 10..].to_vec()),
        "Bob reads its end"
    );

    // The show removes its reference: once compacted and collected, the
    // hold ends and the peer collects the file.
    show_blobs.remove(referenced).await.unwrap();
    durable(&alice, &show).await;
    compact_and_collect(&peer, &alice, &show, *show_blobs.id().as_bytes()).await;
    let gone = ledger(&peer);
    let (_, bank_held, _) = usage(&gone, &bank);
    let (_, _, show_holds) = usage(&gone, &show);
    assert_eq!(bank_held, 0, "the file is collected");
    assert_eq!(show_holds, 0, "the hold ended");
    assert!(gone.used_bytes() < before);

    // A space of another library: a reference to it is refused, and
    // copying stays the rule.
    let elsewhere = alice.create_space().await.unwrap();
    let elsewhere_blobs = elsewhere.create_blobs().unwrap();
    let other = within(elsewhere_blobs.put(Some("other.wav"), b"another library"))
        .await
        .unwrap();
    durable(&alice, &elsewhere).await;
    within(elsewhere.attach_library(&move_ticket(&peer, "project:elsewhere")))
        .await
        .unwrap();
    let refused = within(show_blobs.reference_from(&elsewhere_blobs, other)).await;
    assert!(
        matches!(refused, Err(Error::Class("OtherLibrary"))),
        "{refused:?}"
    );

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

/// A reference's bytes are stored in the space that stores the file:
/// keeping the blob through the reference keeps them there, and dropping
/// it through the reference drops them there, so that the two undo each
/// other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reference_keeps_and_drops_the_bytes_where_they_are_stored() {
    use frasil::{BlobState, Read};
    let peer = peer().await;
    let alice = device(1).await;
    let bank = alice.create_space().await.unwrap();
    let show = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let file: Vec<u8> = (0..FILE_BYTES).map(|i| (i % 251) as u8).collect();
    let bank_blobs = bank.create_blobs().unwrap();
    let stored = within(bank_blobs.put(Some("opening.mp4"), &file))
        .await
        .unwrap();
    durable(&alice, &bank).await;
    let show_blobs = show.create_blobs().unwrap();
    let referenced = within(show_blobs.reference_from(&bank_blobs, stored))
        .await
        .unwrap();
    durable(&alice, &show).await;
    // The peer holds the bytes: they are the cache's on this device.
    within(async {
        while bank_blobs.local(stored).await.unwrap().state != BlobState::Cached {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    within(show_blobs.keep(referenced, |_, _| {}))
        .await
        .unwrap();
    let state = |blobs: frasil::Blobs, id| async move { blobs.local(id).await.unwrap().state };
    assert_eq!(state(show_blobs.clone(), referenced).await, BlobState::Kept);
    assert_eq!(state(bank_blobs.clone(), stored).await, BlobState::Kept);

    show_blobs.drop_local(referenced).await.unwrap();
    assert_eq!(
        state(show_blobs.clone(), referenced).await,
        BlobState::Absent
    );
    assert_eq!(state(bank_blobs.clone(), stored).await, BlobState::Absent);
    // A read through the reference fetches them again.
    let read = within(show_blobs.get(referenced, &Read::new()))
        .await
        .unwrap();
    assert_eq!(read, Some(file));
}
