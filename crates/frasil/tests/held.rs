//! Held objects through the client (at-rest.md, "Held objects"): two
//! devices on loopback share a space, one holding its blobs as files, the
//! other sealing them; a held file is served and read as the file's bytes;
//! a changed file is withdrawn and fetched again from the other holder; a
//! reference is held but never served; and forgetting a space tells the
//! provider to forget each token.
#![cfg(all(feature = "iroh", feature = "adapter-blobs"))]

#[path = "support/provider.rs"]
mod provider;

use frasil::advanced::held::ObjectPolicy;
use frasil::{Device, Error, Event, Level, Options, Storage};
use provider::{DirProvider, temp_dir};
use std::future::Future;
use std::sync::Arc;
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

async fn device(key: u8, options: Options) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        options.loopback().never_restored(),
    )
    .await
    .expect("a device")
}

/// Two members of one space over a member connection on loopback: Alice,
/// who founded it and holds its blobs through `provider`, and Bob, who
/// seals them.
async fn shared_space(
    provider: Arc<DirProvider>,
) -> (Device, Device, frasil::Space, frasil::Space) {
    let alice = device(21, Options::new().object_provider(provider)).await;
    let bob = device(22, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    (alice, bob, space, bobs_space)
}

/// A device that fetches objects only when asked, with no peer: a blob it
/// materialises comes from a member over the member connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_on_demand_member_materialises_from_a_member_without_a_peer() {
    let dir = temp_dir("held-on-demand-member");
    let alices = DirProvider::new(dir.join("alice"));
    let bobs = DirProvider::new(dir.join("bob"));
    let alice = device(25, Options::new().object_provider(alices.clone())).await;
    let bob = device(
        26,
        Options::new()
            .object_provider(bobs.clone())
            .objects_on_demand(),
    )
    .await;
    let space = alice.create_space().await.unwrap();
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's laptop", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    let files = space.create_blobs().unwrap();
    let token = alices.write("cue.wav", b"only on Alice's disk");
    let blob = files.put_from("cue", &token).await.unwrap();
    let bobs_files = until_stream(&bobs_space, files.id()).await;
    until(|| async { bobs_files.info(blob).await.is_ok() }).await;
    assert_eq!(bobs.files(), 0, "nothing until it is asked for");

    let bobs_token = within(bobs_files.materialise(blob, b"cue.wav"))
        .await
        .unwrap();
    assert_eq!(bobs.read(&bobs_token), b"only on Alice's disk");
    drop(alice);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_file_is_served_to_a_sealed_member_and_read_as_its_bytes() {
    let dir = temp_dir("held-serve");
    let provider = DirProvider::new(dir.join("alice"));
    let (alice, bob, space, bobs_space) = shared_space(provider.clone()).await;
    assert_eq!(space.object_policy().await, ObjectPolicy::Held);
    assert_eq!(bobs_space.object_policy().await, ObjectPolicy::Sealed);

    // A file of three chunks and a little, put from its token: never read
    // whole into memory by Frasil, and stored only as the file.
    let mut file = vec![0u8; 3 * frasil_units::limits::CHUNK_BYTES + 5];
    for (i, byte) in file.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let token = provider.write("photo.bin", &file);
    let files = space.create_blobs().unwrap();
    let blob = files.put_from("photo", &token).await.unwrap();
    let info = files.info(blob).await.unwrap();
    assert_eq!(info.size, file.len() as u64);
    assert_eq!(info.token.as_deref(), Some(&token[..]));
    assert_eq!(files.get(blob).await.unwrap().as_deref(), Some(&file[..]));
    assert_eq!(files.materialise(blob, b"").await.unwrap(), token);
    assert_eq!(
        std::fs::read_dir(&provider.dir).unwrap().count(),
        1,
        "one file, no copy"
    );

    // Bob fetches the blob over the member connection: Alice announces it
    // and seals its chunks again from the file.
    let bobs_files = until_stream(&bobs_space, files.id()).await;
    let fetched = within(async {
        loop {
            if let Ok(Some(bytes)) = bobs_files.get(blob).await {
                break bytes;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert_eq!(fetched, file, "Bob's bytes are the file");
    assert_eq!(
        bobs_files.materialise(blob, b"").await.unwrap_err(),
        Error::NotAllowed("the space's blobs are sealed on this device")
    );
    assert!(bobs_files.info(blob).await.unwrap().token.is_none());

    // A put from memory under `held` goes through the provider too.
    let small = files.put(Some("note"), b"a small blob").await.unwrap();
    let small_token = files.materialise(small, b"").await.unwrap();
    assert_eq!(provider.read(&small_token), b"a small blob");
    assert_eq!(
        files.get(small).await.unwrap().as_deref(),
        Some(&b"a small blob"[..])
    );

    // Release: the record goes, the provider is told, the blob is missing
    // here until fetched again.
    files.release(small).await.unwrap();
    assert_eq!(provider.forgotten(), vec![small_token.clone()]);
    assert!(files.get(small).await.unwrap().is_none());
    assert!(files.info(small).await.unwrap().token.is_none());

    // Forgetting the space tells the provider about every held token.
    alice
        .engine()
        .forget_space(&frasil_events::EventId(*space.id().as_bytes()))
        .await
        .unwrap();
    assert_eq!(provider.forgotten(), vec![small_token, token]);
    let _ = (alice, bob);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_file_is_withdrawn_and_fetched_again_from_the_other_holder() {
    let dir = temp_dir("held-withdraw");
    let provider = DirProvider::new(dir.join("alice"));
    let (alice, _bob, space, bobs_space) = shared_space(provider.clone()).await;
    let mut events = alice.events();
    let file: Vec<u8> = (0..200_000u32).map(|i| (i % 199) as u8).collect();
    let token = provider.write("entry-1", &file);
    let files = space.create_blobs().unwrap();
    let blob = files.put_from("entry", &token).await.unwrap();

    // Bob fetches and seals it.
    let bobs_files = until_stream(&bobs_space, files.id()).await;
    until(|| async { matches!(bobs_files.get(blob).await, Ok(Some(_))) }).await;

    // Alice's file changes under its token: at the next read, Alice finds
    // it not held and withdraws it, and the application hears of it.
    let mut blob_changes = files.changes().await.unwrap();
    let mut changed = file.clone();
    changed[100] ^= 1;
    provider.write("entry-1", &changed);
    assert_eq!(files.get(blob).await.unwrap(), None, "withdrawn, not read");
    let withdrawn = within(async {
        loop {
            match events.next().await {
                Some(Event::ObjectWithdrawn { token, .. }) => break token,
                Some(_) => {}
                None => panic!("the device is gone"),
            }
        }
    })
    .await;
    assert_eq!(withdrawn, token);
    assert!(files.info(blob).await.unwrap().token.is_none());
    // The blob feed and the blob's status say so too.
    let change = within(async {
        loop {
            match blob_changes.next().await.unwrap() {
                Some(frasil::BlobChange::Withdrawn { id }) => break id,
                Some(_) => {}
                None => panic!("the device is gone"),
            }
        }
    })
    .await;
    assert_eq!(change, blob);
    assert_eq!(
        files.status(blob).await.unwrap(),
        frasil::BlobStatus::Withdrawn
    );
    assert!(
        provider.forgotten().is_empty(),
        "a withdrawal forgets nothing: the application decides"
    );

    // Materialising it fetches it again from Bob, who holds it sealed, into
    // the place the application names; the bytes are the original file's.
    let again = files.materialise(blob, b"entry-1-restored").await.unwrap();
    assert_eq!(again, b"entry-1-restored");
    assert_eq!(provider.read(&again), file);
    assert_eq!(files.get(blob).await.unwrap().as_deref(), Some(&file[..]));
    assert_eq!(provider.calls.lock().unwrap().aborted, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reference_is_held_but_never_served() {
    use frasil::advanced::Engine;
    use frasil_events::EventId;

    // Alice stores a file in one space and references it from another; Carol
    // is a member of the second alone, holding its blobs. She receives the
    // referenced object's bytes as a peer would hand them, with the object
    // key alone, and holds the file; she announces and serves nothing of
    // it, since she cannot seal its chunks again.
    let dir = temp_dir("held-reference");
    let alice = device(31, Options::new()).await;
    let carols_provider = DirProvider::new(dir.join("carol"));
    let carol = device(32, Options::new().object_provider(carols_provider.clone())).await;
    let source = alice.create_space().await.unwrap();
    let library = alice.create_space().await.unwrap();
    let source_files = source.create_blobs().unwrap();
    let plaintext = vec![42u8; 70_000];
    let stored = source_files
        .put(Some("shared.bin"), &plaintext)
        .await
        .unwrap();
    let library_files = library.create_blobs().unwrap();
    let reference = library_files
        .reference_from(&source_files, stored)
        .await
        .unwrap();
    let info = library_files.info(reference).await.unwrap();
    assert!(info.is_reference());

    // Carol joins the library space, and receives its events by hand.
    let invitation = library
        .invite_with(
            Level::Write,
            frasil::HistoryMode::WithHistory,
            "Alice's laptop",
            |_, _| async { true },
        )
        .await
        .unwrap();
    let carols_library =
        within(carol.join(invitation.text(), "Carol's desk", |_, _| async { true }))
            .await
            .unwrap();
    within(invitation.admitted()).await.unwrap();
    let carols_files = until_stream(&carols_library, library_files.id()).await;
    assert!(
        carols_files.get(reference).await.unwrap().is_none(),
        "not fetched yet"
    );

    // The object's bytes, as a peer holding it for the library would serve
    // them, handed to Carol's engine whole.
    let engine: &Engine = carol.engine();
    let locator = {
        let entry = library_files.info(reference).await.unwrap();
        let _ = entry;
        alice
            .engine()
            .read(&EventId(*source.id().as_bytes()), |replica| {
                replica.whole_objects()
            })
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    };
    let bytes = alice
        .engine()
        .stored_object(&EventId(*source.id().as_bytes()), &locator)
        .await
        .unwrap();
    let library_id = EventId(*library.id().as_bytes());
    engine
        .receive_object(library_id, &locator, &bytes)
        .await
        .unwrap();
    assert_eq!(
        carols_files.get(reference).await.unwrap().as_deref(),
        Some(&plaintext[..]),
        "held through the object key alone"
    );
    let token = carols_files.materialise(reference, b"").await.unwrap();
    assert_eq!(carols_provider.read(&token), plaintext);
    assert!(
        engine.stored_object(&library_id, &locator).await.is_none(),
        "never served: the chunks cannot be sealed again without k(S)"
    );
    assert!(
        engine
            .read(&library_id, |replica| replica.whole_objects())
            .await
            .unwrap()
            .contains(&locator),
        "held whole, so not asked for again"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_policy_changes_locally_in_both_directions() {
    let dir = temp_dir("held-policy");
    let provider = DirProvider::new(dir.join("files"));
    let alice = device(41, Options::new()).await;
    let space = alice.create_space().await.unwrap();
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("a.bin"), &[7u8; 150_000]).await.unwrap();
    assert_eq!(space.object_policy().await, ObjectPolicy::Sealed);
    assert_eq!(
        files.put_from("b", b"nothing").await.unwrap_err(),
        Error::NotAllowed("the device has no object provider")
    );

    // To held: the stored blob is written through the provider.
    space.hold_objects(provider.clone()).await.unwrap();
    assert_eq!(space.object_policy().await, ObjectPolicy::Held);
    let token = files.materialise(blob, b"").await.unwrap();
    assert_eq!(provider.read(&token), vec![7u8; 150_000]);
    assert_eq!(
        files.get(blob).await.unwrap().as_deref(),
        Some(&[7u8; 150_000][..])
    );

    // The device opened again from the same store finds the record and,
    // given the provider again, holds the blob; without one it is not held.
    // (A memory store is gone with the device, so this stays within one
    // device here.)

    // Back to sealed: the chunks are sealed again from the file and kept,
    // and the provider forgets the token.
    space.seal_objects().await.unwrap();
    assert_eq!(space.object_policy().await, ObjectPolicy::Sealed);
    assert_eq!(provider.forgotten(), vec![token]);
    assert_eq!(
        files.get(blob).await.unwrap().as_deref(),
        Some(&[7u8; 150_000][..])
    );
    assert!(files.info(blob).await.unwrap().token.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A held blob reads from its file chunk by chunk: streamed, by range
/// across a chunk boundary, and hashed, alike; once the file changes it is
/// withdrawn, and no read gives its bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_blob_streams_and_reads_by_range_from_its_file() {
    const CHUNK: usize = 1_048_536;
    let dir = temp_dir("held-ranges");
    let provider = DirProvider::new(dir.join("files"));
    let alice = device(43, Options::new().object_provider(provider.clone())).await;
    let space = alice.create_space().await.unwrap();
    let files = space.create_blobs().unwrap();
    let file: Vec<u8> = (0..2 * CHUNK + 300).map(|i| (i % 241) as u8).collect();
    let token = provider.write("clip", &file);
    let blob = files.put_from("clip", &token).await.unwrap();
    let mut streamed = Vec::new();
    files
        .get_stream(blob, &mut streamed, |_, _| {})
        .await
        .unwrap();
    assert_eq!(streamed, file);
    for (offset, len) in [(0, 10), (CHUNK as u64 - 3, 6), (2 * CHUNK as u64, 1000)] {
        let start = offset as usize;
        let end = (start + len as usize).min(file.len());
        assert_eq!(
            files.get_range(blob, offset, len).await.unwrap().unwrap(),
            file[start..end],
            "{offset}+{len}"
        );
    }
    let hash = files.content_hash(blob).await.unwrap().unwrap();
    assert_eq!(&hash[..16], &provider::stamp_of(&file)[..]);

    let mut changed = file.clone();
    changed[CHUNK + 5] ^= 1;
    provider.write("clip", &changed);
    assert_eq!(files.get_range(blob, 0, 10).await.unwrap(), None);
    assert_eq!(
        files
            .get_stream(blob, Vec::new(), |_, _| {})
            .await
            .unwrap_err(),
        Error::Class("Missing")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A blob stream of a space, once this device holds its first change.
async fn until_stream(space: &frasil::Space, id: frasil::StreamId) -> frasil::Blobs {
    within(async {
        loop {
            if let Ok(blobs) = space.blobs(id).await {
                break blobs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

/// A device kept in a directory: its store holds the held records, which
/// count as held only while a provider is given.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_records_reopen_from_disk_and_need_a_provider() {
    let dir = temp_dir("held-reopen");
    let store = dir.join("store");
    let provider = DirProvider::new(dir.join("files"));
    let file: Vec<u8> = (0..150_000u32).map(|i| (i % 97) as u8).collect();
    let token = provider.write("kept.bin", &file);
    let (space_id, stream, blob) = {
        let alice = Device::open_with(
            Storage::directory(&store),
            &[51; 32],
            Options::new().object_provider(provider.clone()),
        )
        .await
        .unwrap();
        let space = alice.create_space().await.unwrap();
        let files = space.create_blobs().unwrap();
        let blob = files.put_from("kept", &token).await.unwrap();
        assert_eq!(
            files.info(blob).await.unwrap().token.as_deref(),
            Some(&token[..])
        );
        alice.close().await.unwrap();
        (space.id(), files.id(), blob)
    };

    // Opened again with the provider: the record is read from disk, the
    // file is the blob, and nothing is fetched or copied.
    {
        let alice = Device::open_with(
            Storage::directory(&store),
            &[51; 32],
            Options::new().object_provider(provider.clone()),
        )
        .await
        .unwrap();
        let space = alice.space(space_id).await.unwrap();
        assert_eq!(space.object_policy().await, ObjectPolicy::Held);
        let files = space.blobs(stream).await.unwrap();
        assert_eq!(
            files.info(blob).await.unwrap().token.as_deref(),
            Some(&token[..])
        );
        assert_eq!(files.materialise(blob, b"").await.unwrap(), token);
        assert_eq!(files.get(blob).await.unwrap().as_deref(), Some(&file[..]));
        assert_eq!(
            std::fs::read_dir(provider.dir.as_path()).unwrap().count(),
            1
        );
        alice.close().await.unwrap();
    }

    // Opened without a provider: the record stays, but the blob is not
    // held: nothing is read from the file, and nothing is deleted.
    {
        let alice = Device::open_with(Storage::directory(&store), &[51; 32], Options::new())
            .await
            .unwrap();
        let space = alice.space(space_id).await.unwrap();
        assert_eq!(space.object_policy().await, ObjectPolicy::Sealed);
        let files = space.blobs(stream).await.unwrap();
        assert!(files.info(blob).await.unwrap().token.is_none());
        assert_eq!(
            files.get(blob).await.unwrap(),
            None,
            "not held without a provider"
        );
        assert_eq!(
            files.materialise(blob, b"").await.unwrap_err(),
            Error::NotAllowed("the space's blobs are sealed on this device")
        );
        // Given the provider again, the record counts once more.
        space.hold_objects(provider.clone()).await.unwrap();
        assert_eq!(
            files.info(blob).await.unwrap().token.as_deref(),
            Some(&token[..])
        );
        assert_eq!(files.get(blob).await.unwrap().as_deref(), Some(&file[..]));
        assert!(provider.forgotten().is_empty());
        alice.close().await.unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two equal puts from memory under `held` leave one file: the second
/// put's file is forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equal_concurrent_puts_keep_one_file() {
    let dir = temp_dir("held-equal-puts");
    let provider = DirProvider::new(dir.join("files"));
    let alice = device(61, Options::new().object_provider(provider.clone())).await;
    let space = alice.create_space().await.unwrap();
    let files = space.create_blobs().unwrap();
    let bytes = vec![3u8; 40_000];
    let (first, second) = tokio::join!(files.put(Some("a"), &bytes), files.put(Some("b"), &bytes));
    let (first, second) = (first.unwrap(), second.unwrap());
    let token = files.materialise(first, b"").await.unwrap();
    assert_eq!(files.materialise(second, b"").await.unwrap(), token);
    let forgotten = provider.forgotten();
    assert_eq!(forgotten.len(), 1, "the file put twice is forgotten once");
    assert_ne!(forgotten[0], token);
    assert_eq!(
        files.get(second).await.unwrap().as_deref(),
        Some(&bytes[..])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A newcomer admitted from now on under `held` fetches the space snapshot
/// and its stream snapshot objects, which a `frasil:body-keys` unit names:
/// Frasil's own, stored sealed, and never written through the provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newcomers_snapshot_never_reaches_the_provider() {
    let dir = temp_dir("held-newcomer");
    let provider = DirProvider::new(dir.join("bob"));
    let alice = device(71, Options::new()).await;
    let bob = device(72, Options::new().object_provider(provider.clone())).await;
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "before the newcomer"))
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    files.put(Some("early"), &[9u8; 3000]).await.unwrap();
    // From now on: Bob starts from Alice's snapshot, handed over the
    // member connection with the body keys.
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert_eq!(bobs_space.object_policy().await, ObjectPolicy::Held);
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(note.id()).await {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let doc = bobs_note.read().await.unwrap();
    assert_eq!(doc.get_text("body").to_string(), "before the newcomer");
    assert_eq!(
        provider.calls.lock().unwrap().created,
        0,
        "no file for Frasil's own objects"
    );
    assert_eq!(
        std::fs::read_dir(provider.dir.as_path()).unwrap().count(),
        0
    );
    // A blob put after the admission is held as usual.
    let late = files.put(Some("late"), &[8u8; 3000]).await.unwrap();
    let bobs_files = until_stream(&bobs_space, files.id()).await;
    until(|| async { matches!(bobs_files.get(late).await, Ok(Some(_))) }).await;
    assert_eq!(provider.calls.lock().unwrap().created, 1);
    let _ = (alice, bob);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A blob whose chunks arrive before the entry that names it is stored
/// sealed, and held once the entry is current.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_whose_chunks_come_first_is_held_once_its_entry_is_current() {
    use frasil_events::EventId;
    let dir = temp_dir("held-chunks-first");
    let provider = DirProvider::new(dir.join("bob"));
    let alice = device(81, Options::new()).await;
    let bob = device(82, Options::new().object_provider(provider.clone())).await;
    let space = alice.create_space().await.unwrap();
    let space_id = EventId(*space.id().as_bytes());
    alice
        .engine()
        .grant_device(
            space_id,
            bob.engine().public_keys().clone(),
            Level::Write,
            frasil::HistoryMode::WithHistory,
            frasil_space::Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(space_id).await;
    bob.engine()
        .ingest(space_id, alice.engine().events(&space_id).await)
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    let bytes = vec![5u8; 90_000];
    let blob = files.put(Some("first"), &bytes).await.unwrap();
    let locator = alice
        .engine()
        .read(&space_id, |replica| replica.whole_objects()[0])
        .await
        .unwrap();
    let stored = alice
        .engine()
        .stored_object(&space_id, &locator)
        .await
        .unwrap();
    // The object's bytes reach Bob before the unit that names it: stored
    // sealed, with no file.
    bob.engine()
        .receive_object(space_id, &locator, &stored)
        .await
        .unwrap();
    assert_eq!(provider.calls.lock().unwrap().created, 0);
    // The unit arrives: the entry is current, and the blob is held.
    bob.engine()
        .ingest(space_id, alice.engine().events(&space_id).await)
        .await
        .unwrap();
    let bobs_space = bob.space(space.id()).await.unwrap();
    let bobs_files = until_stream(&bobs_space, files.id()).await;
    assert_eq!(
        bobs_files.get(blob).await.unwrap().as_deref(),
        Some(&bytes[..])
    );
    assert!(bobs_files.info(blob).await.unwrap().token.is_some());
    assert_eq!(provider.calls.lock().unwrap().created, 1);
    let _ = std::fs::remove_dir_all(&dir);
}
