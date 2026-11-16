//! Newcomers admitted "from now on" at a peer, on loopback (admission.md,
//! "The newcomer's snapshot"): by an invite link, and through an exchange
//! mailbox. The administrator publishes the snapshot at the peer and names
//! it in the drop or the welcome; the newcomer fetches it, starts from it,
//! reads and writes what comes after, and can open nothing written before.
//! Every wait has a deadline, and nothing leaves the host.

use frasil::{Device, Level, Options, Space, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::{EventId, kind};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
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

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

/// A space's ID as the engine names it.
fn event_of(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// Alice's space at the peer, with a note whose history holds a draft that
/// its current text no longer does. Returns the note and the units written
/// so far: everything before the newcomer.
async fn before(alice: &Device, space: &Space) -> (frasil::Document, Vec<EventId>) {
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "secret draft"))
        .await
        .unwrap();
    note.edit(|doc| {
        let text = doc.get_text("body");
        text.delete(0, "secret draft".len())?;
        text.insert(0, "Hello")
    })
    .await
    .unwrap();
    until(|| async { space.is_durable().await }).await;
    let units = alice
        .engine()
        .events(&event_of(space))
        .await
        .iter()
        .filter_map(|signed| frasil_events::decode(signed).ok())
        .filter(|event| event.kind() == kind::UNIT)
        .map(|event| event.id())
        .collect();
    (note, units)
}

/// The newcomer reads and writes what comes after its admission, and opens
/// nothing from before it: no key of the states before its break, no unit
/// written before, and no edit history in the documents it starts from.
async fn from_now_on(
    alice_note: &frasil::Document,
    bob: &Device,
    bobs_space: &Space,
    units_before: &[EventId],
) {
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;
    // The note's current text, from the snapshot.
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(alice_note.id()).await
                && note.text("body").await.unwrap() == "Hello"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // What comes after, both ways.
    bobs_note
        .edit(|doc| doc.get_text("body").insert(5, ", Alice"))
        .await
        .unwrap();
    until(|| async { alice_note.text("body").await.unwrap() == "Hello, Alice" }).await;
    alice_note
        .edit(|doc| doc.get_text("body").insert(0, "Bob: "))
        .await
        .unwrap();
    until(|| async { bobs_note.text("body").await.unwrap() == "Bob: Hello, Alice" }).await;

    // Nothing from before.
    let space = event_of(bobs_space);
    let (genesis_key, applied) = bob
        .engine()
        .read(&space, |replica| {
            (
                replica.secrets_held(&space),
                units_before
                    .iter()
                    .filter(|id| {
                        matches!(
                            replica.content_outcome(id),
                            Some(frasil::advanced::ContentOutcome::Applied)
                        )
                    })
                    .count(),
            )
        })
        .await
        .unwrap();
    assert!(
        !genesis_key,
        "the newcomer holds a key from before its break"
    );
    assert_eq!(applied, 0, "the newcomer opened a unit from before it");
    let history = bobs_note
        .read()
        .await
        .unwrap()
        .export(frasil::loro::ExportMode::Snapshot)
        .unwrap();
    assert!(
        !history.windows(5).any(|w| w == b"draft"),
        "the newcomer's document carries its history"
    );
}

#[cfg(feature = "ext-invite-links")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_admits_from_now_on() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let (note, units) = before(&alice, &space).await;

    let link = within(space.invite_link(Level::Write, Duration::from_secs(3600)))
        .await
        .unwrap();
    // Bob's device is connected to nothing: the link names the peer.
    let bob = device(2).await;
    let bobs_space = within(bob.join(&link, "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    assert_eq!(bobs_space.id(), space.id());
    from_now_on(&note, &bob, &bobs_space, &units).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_mailbox_admits_from_now_on() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let (note, units) = before(&alice, &space).await;

    let bob = device(2).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    within(space.admit(
        joining.text(),
        Level::Write,
        "Alice's laptop",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    let bobs_space = within(joining.joined()).await.unwrap();
    assert_eq!(bobs_space.id(), space.id());
    from_now_on(&note, &bob, &bobs_space, &units).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
