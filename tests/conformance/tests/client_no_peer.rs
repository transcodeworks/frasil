//! Sharing with no peer at all, on loopback: what member connections carry
//! between devices on one network.
//!
//! - A newcomer admitted over a nearby connection fetches, from the member
//!   that admitted it, the files put before its admission (units.md,
//!   "Sync", objects). Admitted "from now on", it fetches them too, and
//!   opens only those put again after its break.
//! - A space created for a person after two of its devices paired reaches
//!   the other device: the welcome travels over their member connection,
//!   and the space follows on it (admission.md, "Welcomes"; transport.md,
//!   "Mailboxes").
//! - The device knows its person's personal space, and still knows it once
//!   it opens again (identity.md, "The person ID and the personal space";
//!   at-rest.md, "Tables").

use frasil::{Device, Error, HistoryMode, Level, Options, Storage};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

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

/// A second device of `first`'s person, paired over a direct connection.
async fn paired(first: &Device, key: u8) -> Device {
    let invitation =
        within(first.invite_device("Desktop", |_, newcomer| async move { newcomer == "Carol" }))
            .await
            .unwrap();
    let second = device(key).await;
    let person = first.person().await.expect("a person's device");
    within(second.join_person(
        invitation.text(),
        person,
        "Carol",
        &[key; 32],
        |_, other| async move { other == "Desktop" },
    ))
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    second
}

/// Waits for a blob a device does not hold yet: `Missing` until a member
/// connection serves its space.
async fn fetched(blobs: &frasil::Blobs, id: frasil::BlobId) -> frasil::Result<Vec<u8>> {
    within(async {
        loop {
            let mut out = Vec::new();
            match blobs.get_stream(id, &mut out, |_, _| {}).await {
                Ok(()) => return Ok(out),
                Err(Error::Class("Missing")) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
}

/// A blob stream a device holds once its events or its snapshot arrive.
async fn blobs_of(space: &frasil::Space, id: frasil::StreamId) -> frasil::Blobs {
    within(async {
        loop {
            if let Ok(found) = space.blobs(id).await {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newcomer_fetches_files_put_before_it_joined_with_no_peer() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    // Two chunks: 1 MiB and some.
    let file: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let id = blobs.put(Some("cue-1.wav"), &file).await.unwrap();

    // Admitted with history over a nearby connection: the file, put before
    // the admission, comes from the member that admitted it.
    let invitation = space
        .invite_with(
            Level::Write,
            HistoryMode::WithHistory,
            "Alice's laptop",
            |_, newcomer| async move { newcomer == "Bob's laptop" },
        )
        .await
        .unwrap();
    let bob = device(2).await;
    let bobs_space = within(
        bob.join(invitation.text(), "Bob's laptop", |_, host| async move {
            host == "Alice's laptop"
        }),
    )
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert!(alice.peers().is_empty() && bob.peers().is_empty());
    let bobs_blobs = blobs_of(&bobs_space, blobs.id()).await;
    let progress = Arc::new(Mutex::new(Vec::new()));
    let seen = progress.clone();
    let mut out = Vec::new();
    within(async {
        loop {
            let seen = seen.clone();
            match bobs_blobs
                .get_stream(id, &mut out, move |done, total| {
                    seen.lock().unwrap().push((done, total));
                })
                .await
            {
                Ok(()) => break,
                Err(Error::Class("Missing")) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("the file: {error}"),
            }
        }
    })
    .await;
    assert_eq!(out, file);
    let size = file.len() as u64;
    assert_eq!(progress.lock().unwrap().last(), Some(&(size, Some(size))));

    // Admitted from now on, a newcomer fetches the same file from the
    // member, and cannot open it: it was sealed before its break. Put
    // again, it opens.
    let invitation = space
        .invite(Level::Read, "Alice's laptop", |_, newcomer| async move {
            newcomer == "Carol's laptop"
        })
        .await
        .unwrap();
    let carol = device(3).await;
    let carols_space = within(carol.join(
        invitation.text(),
        "Carol's laptop",
        |_, host| async move { host == "Alice's laptop" },
    ))
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    let carols_blobs = blobs_of(&carols_space, blobs.id()).await;
    assert_eq!(
        fetched(&carols_blobs, id).await,
        Err(Error::Class("Sealed"))
    );
    let again = blobs.put(Some("cue-1.wav"), &file).await.unwrap();
    within(async {
        while !carols_blobs
            .list()
            .await
            .unwrap()
            .iter()
            .any(|blob| blob.id == again)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(fetched(&carols_blobs, again).await.unwrap(), file);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_made_after_pairing_reaches_the_persons_other_device_with_no_peer() {
    let desktop = device(1).await;
    desktop.make_person(&[1; 32]).await.unwrap();
    let carol = paired(&desktop, 2).await;
    assert_eq!(carol.spaces().await.len(), 1);

    // Made once the two devices paired: it grants the person, and its
    // welcome goes over their member connection.
    let space = desktop.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Cue 1"))
        .await
        .unwrap();
    let regis_note = within(async {
        loop {
            if let Ok(found) = carol.space(space.id()).await
                && let Ok(document) = found.document(note.id()).await
                && document.text("body").await.unwrap() == "Cue 1"
            {
                break document;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let carol_space = carol.space(space.id()).await.unwrap();
    assert_eq!(carol_space.level().await, Some(Level::Write));
    assert!(desktop.peers().is_empty() && carol.peers().is_empty());

    // And back.
    regis_note
        .edit(|doc| doc.get_text("body").insert(5, ", go"))
        .await
        .unwrap();
    within(async {
        while note.text("body").await.unwrap() != "Cue 1, go" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    desktop.close().await.unwrap();
    carol.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_device_knows_its_persons_personal_space() {
    let directory = std::env::temp_dir().join(format!(
        "frasil-personal-space-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let options = || Options::new().loopback();
    let desktop = Device::open_with(Storage::directory(&directory), &[1; 32], options())
        .await
        .unwrap();
    assert_eq!(desktop.personal_space().await, None);
    desktop.make_person(&[1; 32]).await.unwrap();
    let spaces = desktop.spaces().await;
    assert_eq!(spaces.len(), 1);
    let personal = spaces[0].id();
    assert_eq!(desktop.personal_space().await, Some(personal));

    // A device of the person paired before any other space knows it too.
    let carol = paired(&desktop, 2).await;
    assert_eq!(carol.personal_space().await, Some(personal));

    // Other spaces that grant the person alone leave it as it is, and the
    // device still knows it once it opens again.
    desktop.create_space().await.unwrap();
    desktop.create_space().await.unwrap();
    assert_eq!(desktop.personal_space().await, Some(personal));
    desktop.close().await.unwrap();
    drop(desktop);
    let reopened = Device::open_with(Storage::directory(&directory), &[1; 32], options())
        .await
        .unwrap();
    assert_eq!(reopened.spaces().await.len(), 3);
    assert_eq!(reopened.personal_space().await, Some(personal));

    reopened.close().await.unwrap();
    carol.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}
