//! Drives (ext-drive.md) through the client, on loopback: two devices of a
//! space, apart, move two folders into each other and rename one file
//! differently, then meet again through the peer and read the same tree,
//! with no cycle; and one device's trash, restore, purge and refusals.

#![cfg(feature = "ext-drive")]

use frasil::{Device, DriveEntry, DriveFile, EntryId, EntryKind, Error, Level, Options, Storage};
use frasil_conformance::spawn_loopback;
use std::collections::BTreeMap;
use std::future::Future;
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

/// Each entry's parent and name.
fn shape(entries: &[DriveEntry]) -> BTreeMap<EntryId, (Option<EntryId>, String)> {
    entries
        .iter()
        .map(|e| (e.id, (e.parent, e.name.clone())))
        .collect()
}

fn within_folder(
    shape: &BTreeMap<EntryId, (Option<EntryId>, String)>,
    id: EntryId,
    top: EntryId,
) -> bool {
    let mut at = Some(id);
    for _ in 0..=shape.len() {
        match at {
            Some(current) if current == top => return true,
            Some(current) => at = shape.get(&current).and_then(|(parent, _)| *parent),
            None => return false,
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_moves_and_renames_converge() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();

    // Alice's drive: folders A and B, a file, and a document.
    let drive = space.create_drive().await.unwrap();
    let a = drive.add_folder(None, "A").await.unwrap();
    let b = drive.add_folder(None, "B").await.unwrap();
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("notes.txt"), b"hello").await.unwrap();
    let file = drive
        .add_file(
            Some(a),
            "notes.txt",
            &DriveFile::new(files.id(), blob)
                .with_size(5)
                .with_media_type("text/plain"),
        )
        .await
        .unwrap();
    let sheet = space.create_document().unwrap();
    sheet
        .edit(|doc| doc.get_map("cells").insert("A1", 1))
        .await
        .unwrap();
    drive
        .add_document(None, "Budget", sheet.id(), "example.spreadsheet")
        .await
        .unwrap();

    // Bob joins through the peer and holds the drive.
    let bob = device(2).await;
    let joining = within(bob.join_via_peer(&peer.origin, "Bob's laptop", |_, _| async { true }))
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
    let bobs_drive = within(async {
        loop {
            if let Ok(drive) = bobs_space.drive(drive.id()).await
                && drive.all().await.unwrap().len() == 4
            {
                break drive;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let listed = bobs_drive.entries(Some(a)).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].shown_name, "notes.txt");
    assert!(matches!(&listed[0].kind, EntryKind::File(f) if f.blob == blob && f.size == Some(5)));

    // Apart: Bob closes his connections, and both change the same entries.
    for link in bob.peers() {
        link.close();
    }
    within(async {
        while bob.peers().iter().any(|p| p.status().connected) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    let mut alices_changes = drive.changes().await.unwrap();
    drive.move_to(a, Some(b)).await.unwrap();
    drive.rename(file, "alice.txt").await.unwrap();
    drive.set_meta(file, "example.color", "red").await.unwrap();
    bobs_drive.move_to(b, Some(a)).await.unwrap();
    bobs_drive.rename(file, "bob.txt").await.unwrap();
    bobs_drive
        .set_meta(file, "example.pinned", true)
        .await
        .unwrap();
    let bobs_folder = bobs_drive.add_folder(Some(a), "Bob's").await.unwrap();
    // Each sees its own changes only.
    let alices = shape(&drive.all().await.unwrap());
    assert!(within_folder(&alices, a, b));
    assert!(!alices.contains_key(&bobs_folder));

    // Together again: both read the same tree, with no cycle.
    bob.connect(&peer.origin).await.unwrap();
    let (alices, bobs) = within(async {
        loop {
            let alices = shape(&drive.all().await.unwrap());
            let bobs = shape(&bobs_drive.all().await.unwrap());
            if alices == bobs && alices.contains_key(&bobs_folder) {
                break (alices, bobs);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(alices, bobs);
    assert!(!(within_folder(&alices, a, b) && within_folder(&alices, b, a)));
    assert!(within_folder(&alices, a, b) || within_folder(&alices, b, a));
    let name = &alices[&file].1;
    assert!(name == "alice.txt" || name == "bob.txt", "{name}");
    // Both application fields merged, key by key.
    let entry = drive.entry(file).await.unwrap().unwrap();
    assert_eq!(entry.meta.len(), 2, "{:?}", entry.meta);
    // Alice's change feed told of the entries that changed.
    let changed = within(async {
        let mut all = Vec::new();
        while !all.contains(&bobs_folder) {
            all.extend(alices_changes.next().await.unwrap().entries);
        }
        all
    })
    .await;
    assert!(changed.contains(&a) && changed.contains(&file));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trash_restore_purge_and_refusals() {
    let alice = Device::open_with(Storage::Memory, &[3; 32], Options::new().never_restored())
        .await
        .unwrap();
    let space = alice.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let docs = drive.add_folder(None, "Docs").await.unwrap();
    let again = drive.add_folder(None, "Docs").await.unwrap();
    let shown: Vec<String> = drive
        .entries(None)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.shown_name)
        .collect();
    assert_eq!(shown, ["Docs", "Docs (2)"]);
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "x"))
        .await
        .unwrap();
    let listed = drive
        .add_document(Some(docs), "Note", note.id(), "example.note")
        .await
        .unwrap();

    // Refusals write nothing.
    let refused = [
        drive.add_folder(None, "a/b").await.map(drop),
        drive
            .add_folder(Some(listed), "Inside a document")
            .await
            .map(drop),
        drive.move_to(docs, Some(docs)).await,
        drive
            .add_document(None, "Twice", note.id(), "example.note")
            .await
            .map(drop),
        drive.restore(docs).await,
        drive.set_meta(docs, "", 1).await,
    ];
    for result in refused {
        assert!(matches!(result, Err(Error::Invalid(_))), "{result:?}");
    }
    assert!(matches!(
        space.drive(note.id()).await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(drive.all().await.unwrap().len(), 3);
    drive.delete_meta(docs, "example.absent").await.unwrap();

    // The trash, and back.
    drive.move_to_trash(docs).await.unwrap();
    assert!(matches!(
        drive.move_to_trash(docs).await,
        Err(Error::Invalid(_))
    ));
    let trash = drive.trash().await.unwrap();
    assert_eq!(trash.len(), 1);
    assert_eq!(trash[0].id, docs);
    assert!(drive.entry(listed).await.unwrap().unwrap().in_trash);
    assert_eq!(drive.entries(None).await.unwrap().len(), 1);
    drive.restore(docs).await.unwrap();
    assert!(drive.trash().await.unwrap().is_empty());

    // A purge forgets the folder and what is in it; the stream cannot be
    // listed again.
    assert_eq!(
        drive.entry_for(note.id()).await.unwrap().map(|e| e.id),
        Some(listed)
    );
    assert!(drive.purge(docs).await.unwrap().is_empty());
    assert!(drive.entry(listed).await.unwrap().is_none());
    assert!(matches!(
        drive
            .add_document(Some(again), "Back", note.id(), "example.note")
            .await,
        Err(Error::Invalid(_))
    ));
    alice.close().await.unwrap();
}
