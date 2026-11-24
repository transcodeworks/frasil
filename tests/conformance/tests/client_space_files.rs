//! Space files between devices with a peer on loopback
//! (ext-space-files.md): a space exported at one device without its
//! objects, imported at another by the claim the file carries, whose blob
//! then comes through the peer; a copy read by its keys, with the blob
//! embedded, and nothing written; and the file appended to after the
//! claimant's changes came back. Every wait has a deadline, and nothing
//! leaves the host.
#![cfg(feature = "space-files")]

use frasil::space_files::{Export, Objects, Opened, WayIn};
use frasil::{
    Blobs, Device, Document, Error, Level, Options, Space, SpaceFile, SpaceFileFormat, Storage,
    StreamKind,
};
use frasil_conformance::spawn_loopback;
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

/// The application's format: one note and one blob stream.
struct Notes;

struct Opened_ {
    space: Space,
    note: Document,
    files: Blobs,
}

impl SpaceFileFormat for Notes {
    const KIND: &'static str = "example.notes";
    type Opened = Opened_;

    async fn open(space: Space) -> frasil::Result<Opened_> {
        let streams = space.streams().await?;
        let note = streams
            .iter()
            .find(|s| s.kind == StreamKind::Document)
            .ok_or(Error::Class("WrongKind"))?;
        let files = streams
            .iter()
            .find(|s| s.kind == StreamKind::Blobs)
            .ok_or(Error::Class("WrongKind"))?;
        Ok(Opened_ {
            note: space.document(note.id).await?,
            files: space.blobs(files.id).await?,
            space,
        })
    }
}

async fn text(note: &Document) -> String {
    note.read().await.unwrap().get_text("body").to_string()
}

static PHOTO: [u8; 70_000] = [7; 70_000];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_without_objects_admits_a_claimant_who_fetches_them_through_the_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("photo"), &PHOTO).await.unwrap();
    until(|| async { space.is_durable().await }).await;

    // The file: the space without its blob, with an invite to write.
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::None,
            way_in: vec![WayIn::Invite {
                level: Level::Write,
                lifetime: Duration::from_secs(3600),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    assert!(file.manifest().objects.is_empty(), "no object embedded");

    // Bob, connected to nothing, claims the invite from the file and
    // writes; the blob is not there yet.
    let bob = device(2).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("the invite admits Bob");
    };
    assert_eq!(invited.invitation().inviter(), alice.id());
    let bobs = invited.accept().await.unwrap();
    assert_eq!(bobs.space.id(), space.id());
    assert_eq!(text(&bobs.note).await, "hello");
    until(|| async { bobs.space.level().await == Some(Level::Write) }).await;
    assert_eq!(
        bobs.files.get(blob, &frasil::Read::new()).await.unwrap(),
        None,
        "left out"
    );
    bobs.note
        .edit(|doc| doc.get_text("body").insert(5, ", bob"))
        .await
        .unwrap();

    // Through the peer: Bob's claim and edit reach Alice, and Alice's blob
    // reaches Bob.
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { text(&note).await == "hello, bob" }).await;
    let members = space.members().await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.id == bob.id() && m.level == Level::Write),
        "{members:?}"
    );
    until(|| async {
        bobs.files
            .get(blob, &frasil::Read::new())
            .await
            .unwrap()
            .is_some()
    })
    .await;
    assert_eq!(
        bobs.files
            .get(blob, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&PHOTO[..])
    );

    // The file, appended to at Alice once Bob's changes came back, reads
    // at a third device as a copy: Bob's edit included, nothing written.
    until(|| async { space.is_durable().await }).await;
    let grown = SpaceFile::<Notes>::append_bytes(&space, file.bytes())
        .await
        .unwrap();
    assert!(
        grown.bytes().starts_with(file.bytes()),
        "an append rewrites nothing"
    );
    let carol = device(3).await;
    let refused = SpaceFile::<Notes>::import_bytes(&carol, grown.bytes(), None).await;
    assert_eq!(
        refused.unwrap_err(),
        Error::Class("InviteUsed"),
        "the invite is spent, and the file carries no keys"
    );
    assert!(carol.spaces().await.is_empty());

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_by_keys_reads_what_it_carries_and_fetches_the_rest_through_the_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(4).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    let small = files.put(Some("note.txt"), b"a small one").await.unwrap();
    let large = files.put(Some("photo"), &PHOTO).await.unwrap();
    until(|| async { space.is_durable().await }).await;

    // Objects up to 1,000 bytes: the small blob rides, the large one is
    // left out.
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::UpTo(1_000),
            ..Export::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(file.manifest().objects.len(), 1, "the small blob only");

    // Dan reads the copy by its keys: the note and the small blob at once,
    // with no member, no peer and no grant.
    let dan = device(5).await;
    let Opened::Reading(dans) = SpaceFile::<Notes>::import_bytes(&dan, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("a reader by keys");
    };
    assert_eq!(text(&dans.note).await, "hello");
    assert_eq!(dans.space.level().await, None);
    assert_eq!(
        dans.files
            .get(small, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&b"a small one"[..])
    );
    assert_eq!(
        dans.files.get(large, &frasil::Read::new()).await.unwrap(),
        None,
        "left out"
    );
    assert!(matches!(
        dans.note
            .edit(|doc| doc.get_text("body").insert(0, "x"))
            .await,
        Err(Error::NotAllowed(_))
    ));

    // Connected to the peer, Dan fetches the large blob with the read
    // credential the keys give.
    dan.connect(&peer.origin).await.unwrap();
    until(|| async {
        dans.files
            .get(large, &frasil::Read::new())
            .await
            .unwrap()
            .is_some()
    })
    .await;
    assert_eq!(
        dans.files
            .get(large, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&PHOTO[..])
    );

    alice.close().await.unwrap();
    dan.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_claim_is_presented_to_no_peer_until_the_person_consents() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(6).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    files.put(Some("note.txt"), b"a small one").await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::None,
            way_in: vec![WayIn::Invite {
                level: Level::Write,
                lifetime: Duration::from_secs(3600),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();

    // Bob is connected before he imports: the peer must not hear of the
    // space while the claim waits, through the handshake or the upkeep.
    let bob = device(7).await;
    let bobs_peer = bob.connect(&peer.origin).await.unwrap();
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !bobs_peer.status().spaces.contains(&space.id()),
        "presented while pending: {:?}",
        bobs_peer.status().spaces
    );
    assert!(bob.spaces().await.is_empty());

    // On consent, the space is presented, and the claim reaches Alice.
    let bobs = invited.accept().await.unwrap();
    until(|| async { bobs_peer.status().spaces.contains(&space.id()) }).await;
    until(|| async {
        space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == bob.id() && m.level == Level::Write)
    })
    .await;
    assert_eq!(text(&bobs.note).await, "hello");

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
