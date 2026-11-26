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
            match blobs
                .get_stream(id, &mut out, &frasil::Read::new(), |_, _| {})
                .await
            {
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
                .get_stream(id, &mut out, &frasil::Read::new(), move |done, total| {
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

/// Two devices of one space with no peer, joined over a nearby connection,
/// and the blob stream as each holds it. The second opens with `options`.
async fn two_devices(options: Options) -> (Device, frasil::Blobs, Device, frasil::Blobs) {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    // The stream exists for a newcomer once a unit of it does.
    blobs.put(None, b"first").await.unwrap();
    let invitation = space
        .invite_with(
            Level::Write,
            HistoryMode::WithHistory,
            "Alice's laptop",
            |_, newcomer| async move { newcomer == "Bob's laptop" },
        )
        .await
        .unwrap();
    let bob = Device::open_with(Storage::Memory, &[2; 32], options.loopback())
        .await
        .expect("a device");
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
    (alice, blobs, bob, bobs_blobs)
}

/// Puts a blob of `size` bytes on one device, and gives it once the other
/// lists it.
async fn put(
    blobs: &frasil::Blobs,
    others: &frasil::Blobs,
    size: usize,
) -> (frasil::BlobId, Vec<u8>) {
    let file: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let id = blobs.put(None, &file).await.unwrap();
    within(async {
        while !others.list().await.unwrap().iter().any(|e| e.id == id) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    (id, file)
}

/// A blob as `read` reads it on a device that may have to fetch it.
/// Compared by a flag, so that a failure does not print the bytes.
async fn reads(blobs: &frasil::Blobs, id: frasil::BlobId, read: frasil::Read, file: &[u8]) {
    let got = within(blobs.get(id, &read)).await;
    let same = got.as_ref().map(|got| got.as_deref() == Some(file));
    assert_eq!(same, Ok(true));
}

/// Drops a blob here, once nothing on the device uses it any more:
/// `drop_local` answers `NotAllowed` while a read or a fetch does.
async fn dropped(blobs: &frasil::Blobs, id: frasil::BlobId) {
    within(async {
        loop {
            match blobs.drop_local(id).await {
                Err(Error::NotAllowed(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
                other => break other.unwrap(),
            }
        }
    })
    .await;
}

/// [`reads`], once a member that holds the blob whole has announced it: a
/// member announces an object on its connection's next tick after it
/// becomes whole, and a read made before that ends `Missing` when the
/// other members say they lack the blob (units.md, "Sync", sources
/// between members).
async fn reads_once_announced(blobs: &frasil::Blobs, id: frasil::BlobId, file: &[u8]) {
    let got = within(async {
        loop {
            match blobs.get(id, &frasil::Read::new()).await {
                Ok(None) | Err(Error::Class("Missing")) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                other => break other,
            }
        }
    })
    .await;
    let same = got.as_ref().map(|got| got.as_deref() == Some(file));
    assert_eq!(same, Ok(true));
}

async fn state(blobs: &frasil::Blobs, id: frasil::BlobId) -> frasil::BlobState {
    blobs.local(id).await.unwrap().state
}

/// A member that announced a blob is asked for it again, on the same
/// connection, each time the device that fetched it holds it no longer
/// (units.md, "Sync", objects; at-rest.md, "Retention"): after
/// `drop_local`, whether the blob was read into the cache or kept, and
/// whatever the next read is to do with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_dropped_here_is_fetched_again_from_a_member() {
    use frasil::{BlobState, Read};
    let (alice, blobs, bob, bobs_blobs) = two_devices(Options::new()).await;
    // Several chunks, one chunk to the byte, and less than one.
    for size in [5_500_000, 1_048_536, 1000] {
        let (id, file) = put(&blobs, &bobs_blobs, size).await;
        // Read into the cache, dropped, and read again.
        assert_eq!(fetched(&bobs_blobs, id).await.unwrap(), file, "{size}");
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Cached);
        dropped(&bobs_blobs, id).await;
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Absent);
        reads(&bobs_blobs, id, Read::new(), &file).await;
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Cached);

        // Kept, dropped, and read to store nothing, twice.
        dropped(&bobs_blobs, id).await;
        within(bobs_blobs.keep(id, |_, _| {})).await.unwrap();
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Kept);
        dropped(&bobs_blobs, id).await;
        reads(&bobs_blobs, id, Read::new().uncached(), &file).await;
        reads(&bobs_blobs, id, Read::new().uncached(), &file).await;
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Absent);

        // A reader closed part way, and the blob read whole after it.
        let mut reader = within(bobs_blobs.open_reader(id, &Read::new()))
            .await
            .unwrap();
        let mut first = [0; 100];
        let read = within(reader.read(&mut first)).await.unwrap();
        assert_eq!(first[..read], file[..read]);
        within(reader.close()).await.unwrap();
        reads(&bobs_blobs, id, Read::new(), &file).await;

        // Kept, dropped, and read into the cache.
        within(bobs_blobs.keep(id, |_, _| {})).await.unwrap();
        dropped(&bobs_blobs, id).await;
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Absent);
        reads(&bobs_blobs, id, Read::new(), &file).await;
        assert_eq!(state(&bobs_blobs, id).await, BlobState::Cached);
    }
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}

/// A blob the cache evicted for its budget is fetched from the member
/// again when it is read (at-rest.md, "Retention").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_evicted_here_is_fetched_again_from_a_member() {
    use frasil::{BlobState, Read};
    const SIZE: usize = 100_000;
    // Room for one blob and not two.
    let options = Options::new().blob_cache(SIZE as u64 * 3 / 2);
    let (alice, blobs, bob, bobs_blobs) = two_devices(options).await;
    let (one, first) = put(&blobs, &bobs_blobs, SIZE).await;
    let (two, second) = put(&blobs, &bobs_blobs, SIZE + 1).await;
    assert_eq!(fetched(&bobs_blobs, one).await.unwrap(), first);
    for _ in 0..2 {
        reads(&bobs_blobs, two, Read::new(), &second).await;
        assert_eq!(state(&bobs_blobs, one).await, BlobState::Absent);
        reads(&bobs_blobs, one, Read::new(), &first).await;
        assert_eq!(state(&bobs_blobs, two).await, BlobState::Absent);
    }
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}

/// A newcomer admitted to `space` over a nearby connection with the
/// device that holds it, and the blob stream `id` as the newcomer holds it.
async fn admitted(
    space: &frasil::Space,
    id: frasil::StreamId,
    key: u8,
    name: &'static str,
) -> (Device, frasil::Blobs) {
    let invitation = space
        .invite_with(
            Level::Write,
            HistoryMode::WithHistory,
            "Alice's laptop",
            move |_, newcomer| async move { newcomer == name },
        )
        .await
        .unwrap();
    let newcomer = device(key).await;
    let joined = within(
        newcomer.join(invitation.text(), name, |_, host| async move {
            host == "Alice's laptop"
        }),
    )
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    let blobs = blobs_of(&joined, id).await;
    (newcomer, blobs)
}

/// The device that put a blob, and dropped it, reads it back from the
/// member that fetched it whole, on the same connection: the member
/// announced the blob when it became whole there (units.md, "Sync",
/// sources between members).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_put_and_dropped_is_read_back_from_the_member_that_fetched_it() {
    use frasil::{BlobState, Read};
    let (alice, blobs, bob, bobs_blobs) = two_devices(Options::new()).await;
    for size in [1_500_000, 1000] {
        let (id, file) = put(&blobs, &bobs_blobs, size).await;
        assert_eq!(fetched(&bobs_blobs, id).await.unwrap(), file, "{size}");
        dropped(&blobs, id).await;
        assert_eq!(state(&blobs, id).await, BlobState::Absent);
        reads(&blobs, id, Read::new(), &file).await;
        assert_eq!(state(&blobs, id).await, BlobState::Cached);
    }
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}

/// Three members with no peer. Alice puts a blob, Bob and Carol fetch it
/// whole, and Bob drops it: Alice, who dropped it too, reads it from
/// Carol, Bob saying he no longer holds it. Bob reads it again, so that he
/// holds it whole once more; Carol drops it, and Alice, who dropped it
/// again, reads it from Bob once he has announced it. No connection is
/// made again on the way (units.md, "Sync", sources between members).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_dropped_a_blob_is_no_source_until_it_holds_it_again() {
    use frasil::{BlobState, Read};
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    blobs.put(None, b"first").await.unwrap();
    let (bob, bobs_blobs) = admitted(&space, blobs.id(), 2, "Bob's laptop").await;
    let (carol, carols_blobs) = admitted(&space, blobs.id(), 3, "Carol's laptop").await;
    assert!(alice.peers().is_empty() && bob.peers().is_empty() && carol.peers().is_empty());

    let (id, file) = put(&blobs, &bobs_blobs, 1_500_000).await;
    within(async {
        while !carols_blobs
            .list()
            .await
            .unwrap()
            .iter()
            .any(|e| e.id == id)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(fetched(&bobs_blobs, id).await.unwrap(), file);
    assert_eq!(fetched(&carols_blobs, id).await.unwrap(), file);

    dropped(&bobs_blobs, id).await;
    dropped(&blobs, id).await;
    reads_once_announced(&blobs, id, &file).await;
    assert_eq!(state(&blobs, id).await, BlobState::Cached);
    assert_eq!(state(&bobs_blobs, id).await, BlobState::Absent);

    reads(&bobs_blobs, id, Read::new(), &file).await;
    assert_eq!(state(&bobs_blobs, id).await, BlobState::Cached);
    dropped(&carols_blobs, id).await;
    dropped(&blobs, id).await;
    reads_once_announced(&blobs, id, &file).await;
    assert_eq!(state(&blobs, id).await, BlobState::Cached);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
}

/// Three members with no peer, and a blob neither of Alice's members will
/// serve: Bob fetched it whole and announced it, and Carol never fetched
/// it. Alice drops it and reads it back from Bob, so Bob is a source of
/// it; then both drop it. Alice reads it again: Bob says he no longer
/// holds it, Alice's connection with Carol declines the read as one Carol
/// announced nothing for, and the read ends at once as `Missing`, long
/// before a fetch with nothing arriving would stall (units.md, "Sync",
/// sources between members).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_no_member_will_serve_ends_promptly() {
    use frasil::{BlobState, Read};
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    let blobs = space.create_blobs().unwrap();
    blobs.put(None, b"first").await.unwrap();
    let (bob, bobs_blobs) = admitted(&space, blobs.id(), 2, "Bob's laptop").await;
    let (carol, carols_blobs) = admitted(&space, blobs.id(), 3, "Carol's laptop").await;
    assert!(alice.peers().is_empty() && bob.peers().is_empty() && carol.peers().is_empty());

    let (id, file) = put(&blobs, &bobs_blobs, 1_500_000).await;
    within(async {
        while !carols_blobs
            .list()
            .await
            .unwrap()
            .iter()
            .any(|e| e.id == id)
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(fetched(&bobs_blobs, id).await.unwrap(), file);
    dropped(&blobs, id).await;
    reads(&blobs, id, Read::new(), &file).await;
    dropped(&blobs, id).await;
    dropped(&bobs_blobs, id).await;

    let started = std::time::Instant::now();
    let got = within(blobs.get(id, &Read::new())).await;
    let took = started.elapsed();
    assert!(
        matches!(got, Ok(None) | Err(Error::Class("Missing"))),
        "{:?}",
        got.map(|bytes| bytes.map(|bytes| bytes.len()))
    );
    assert!(took < Duration::from_secs(15), "{took:?}");
    assert_eq!(state(&blobs, id).await, BlobState::Absent);
    assert_eq!(state(&carols_blobs, id).await, BlobState::Absent);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
}
