//! Drives (ext-drive.md) through the client: changes made together in one
//! batch, all or none, and the change feed's report of the application's
//! own root containers.
#![cfg(feature = "ext-drive")]

use frasil::{
    Device, DriveChange, DriveChanges, DriveEntry, DriveFile, EntryKind, Error, Options, Storage,
};
use std::time::Duration;

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().never_restored())
        .await
        .expect("a device")
}

async fn next(changes: &mut DriveChanges) -> DriveChange {
    tokio::time::timeout(Duration::from_secs(30), changes.next())
        .await
        .expect("within the deadline")
        .expect("a change")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batches_write_all_or_nothing() {
    let alice = device(4).await;
    let space = alice.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let mut changes = drive.changes().await.unwrap();

    // A typed folder: the folder and its meta keys, as one change.
    let folder = drive
        .batch(|b| {
            let folder = b.add_folder(None, "Invoices")?;
            b.set_meta(folder, "example.type", "invoices")?;
            b.set_meta(folder, "example.color", "green")?;
            Ok(folder)
        })
        .await
        .unwrap();
    let entry = drive.entry(folder).await.unwrap().unwrap();
    assert_eq!(entry.meta.len(), 2, "{:?}", entry.meta);
    assert_eq!(next(&mut changes).await.entries, [folder]);

    // A note with its attachment, moved together: one change tells of both.
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("scan.png"), b"png").await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "x"))
        .await
        .unwrap();
    let (listed, attachment) = drive
        .batch(|b| {
            let listed = b.add_document(None, "Note", note.id(), "example.note")?;
            let attachment = b.add_file(None, "scan.png", &DriveFile::new(files.id(), blob))?;
            b.set_meta(attachment, "example.note", listed.to_string())?;
            Ok((listed, attachment))
        })
        .await
        .unwrap();
    next(&mut changes).await;
    drive
        .batch(|b| {
            b.move_to(listed, Some(folder))?;
            b.move_to(attachment, Some(folder))
        })
        .await
        .unwrap();
    let mut moved = vec![listed, attachment];
    moved.sort();
    assert_eq!(next(&mut changes).await.entries, moved);

    // A refused change refuses the batch: nothing before it is written.
    let before = drive.all().await.unwrap();
    let refused = drive
        .batch(|b| {
            b.add_folder(None, "Kept?")?;
            b.rename(folder, "Renamed")?;
            b.set_meta(folder, "", 1)
        })
        .await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");
    let failed = drive
        .batch(|b| {
            b.purge(attachment)?;
            Err::<(), _>(Error::Invalid("the application changed its mind"))
        })
        .await;
    assert!(matches!(failed, Err(Error::Invalid(_))), "{failed:?}");
    assert_eq!(drive.all().await.unwrap(), before);

    // Each change sees the ones before it in the batch; a refusal the
    // application catches writes nothing of its own.
    let inner = drive
        .batch(|b| {
            let inner = b.add_folder(Some(folder), "Paid")?;
            assert!(b.add_folder(Some(inner), "a/b").is_err());
            b.move_to_trash(inner)?;
            b.restore(inner)?;
            Ok(inner)
        })
        .await
        .unwrap();
    assert_eq!(
        drive.entry(inner).await.unwrap().unwrap().parent,
        Some(folder)
    );

    // A purge of the note with its attachment releases the blob.
    let released = drive
        .batch(|b| {
            let mut released = b.purge(listed)?;
            released.extend(b.purge(attachment)?);
            Ok(released)
        })
        .await
        .unwrap();
    assert_eq!(released, [(files.id(), blob)]);
    assert!(drive.entry(listed).await.unwrap().is_none());
    assert!(drive.entry(attachment).await.unwrap().is_none());

    // A batch that makes no operation is no error; a batch kept past its
    // write refuses every change.
    let mut kept = None;
    drive
        .batch(|b| {
            kept = Some(b.clone());
            b.delete_meta(folder, "example.absent")
        })
        .await
        .unwrap();
    assert!(matches!(
        kept.unwrap().add_folder(None, "Late"),
        Err(Error::Invalid(_))
    ));
    alice.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_change_feed_reports_application_root_containers() {
    let alice = device(5).await;
    let space = alice.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let mut changes = drive.changes().await.unwrap();

    drive
        .document()
        .edit(|doc| doc.get_map("example.labels").insert("red", "Urgent"))
        .await
        .unwrap();
    let change = next(&mut changes).await;
    assert!(change.entries.is_empty(), "{change:?}");
    assert_eq!(change.roots, ["example.labels"]);

    // An entry's change names no root container.
    let folder = drive.add_folder(None, "Docs").await.unwrap();
    let change = next(&mut changes).await;
    assert_eq!(change.entries, [folder]);
    assert!(change.roots.is_empty(), "{change:?}");

    // Both, in one change.
    drive
        .document()
        .edit(|doc| {
            frasil::drive_format::write::rename(doc, &folder.to_string(), "Papers", None)
                .map_err(|e| e.to_string())?;
            doc.get_map("example.labels")
                .insert("red", "Later")
                .map_err(|e| e.to_string())
        })
        .await
        .unwrap();
    let change = next(&mut changes).await;
    assert_eq!(change.entries, [folder]);
    assert_eq!(change.roots, ["example.labels"]);
    alice.close().await.unwrap();
}

fn file(entry: DriveEntry) -> DriveFile {
    match entry.kind {
        EntryKind::File(file) => file,
        other => panic!("not a file: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_takes_versions_and_a_stale_save_is_a_conflict() {
    let device = device(3).await;
    let space = device.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let files = space.create_blobs().unwrap();
    let first = files.put(None, b"one").await.unwrap();
    let id = drive
        .add_file(
            None,
            "plan.txt",
            &DriveFile::new(files.id(), first).with_size(3),
        )
        .await
        .unwrap();
    let added = file(drive.entry(id).await.unwrap().unwrap());
    assert_eq!(added.heads, [first]);
    assert!(added.versions[&first].parents.is_empty());
    assert_eq!(added.versions[&first].size, Some(3));

    // A plain save moves the file, and it keeps its ID, name and place.
    let second = files.put(None, b"two").await.unwrap();
    drive
        .set_blob(id, &DriveFile::new(files.id(), second), &[first])
        .await
        .unwrap();
    let saved = file(drive.entry(id).await.unwrap().unwrap());
    assert_eq!((saved.blob, saved.size), (second, None));
    assert_eq!(saved.heads, [second]);
    assert_eq!(saved.versions.len(), 2);
    assert!(drive.conflicts().await.unwrap().is_empty());

    // A handle is never used for a second version.
    assert!(matches!(
        drive
            .set_blob(id, &DriveFile::new(files.id(), first), &[second])
            .await,
        Err(Error::Invalid(_))
    ));

    // A save from a stale copy is a second head, which every reader sees.
    let stale = files.put(None, b"three").await.unwrap();
    drive
        .set_blob(id, &DriveFile::new(files.id(), stale), &[first])
        .await
        .unwrap();
    let conflict = file(drive.entry(id).await.unwrap().unwrap());
    assert!(conflict.in_conflict());
    assert_eq!(conflict.blob, second, "the current version keeps its place");
    assert_eq!(conflict.other_heads().collect::<Vec<_>>(), [stale]);
    assert_eq!(drive.conflicts().await.unwrap().len(), 1);

    // Naming every head ends it. The oldest record then can go, and a head
    // cannot.
    let picked = files.put(None, b"two").await.unwrap();
    drive
        .set_blob(id, &DriveFile::new(files.id(), picked), &[second, stale])
        .await
        .unwrap();
    assert!(drive.conflicts().await.unwrap().is_empty());
    assert!(matches!(
        drive.forget_version(id, picked).await,
        Err(Error::Invalid(_))
    ));
    drive.forget_version(id, first).await.unwrap();
    let kept = file(drive.entry(id).await.unwrap().unwrap());
    assert_eq!(kept.versions.len(), 3);
    assert_eq!(kept.heads, [picked]);
}

/// A file's versions name who wrote them, from the signed changes that
/// wrote their records (ext-drive.md, 3.3 What a reader shows), and an
/// older version restored becomes the file's current version again as a
/// new version made from every head, which ends a conflict.
#[cfg(feature = "adapter-blobs")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_name_their_author_and_an_old_one_is_restored() {
    let device = device(5).await;
    let person = device.make_person(&[6; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    let drive = space.create_drive().await.unwrap();
    let files = space.create_blobs().unwrap();
    let first = files.put(None, b"draft").await.unwrap();
    let id = drive
        .add_file(None, "plan.txt", &DriveFile::new(files.id(), first))
        .await
        .unwrap();
    let second = files.put(None, b"final").await.unwrap();
    drive
        .set_blob(id, &DriveFile::new(files.id(), second), &[first])
        .await
        .unwrap();
    let stale = files.put(None, b"stale").await.unwrap();
    drive
        .set_blob(id, &DriveFile::new(files.id(), stale), &[first])
        .await
        .unwrap();

    let versions = drive.versions(id).await.unwrap();
    assert_eq!(versions.len(), 3);
    for (_, version) in &versions {
        let author = version.author.as_ref().expect("an author");
        assert_eq!(author.device, device.id());
        assert_eq!(author.person, Some(person));
    }
    // A listing reads no history.
    let listed = file(drive.entry(id).await.unwrap().unwrap());
    assert!(listed.versions.values().all(|v| v.author.is_none()));

    let restored = drive.restore_version(id, first).await.unwrap();
    let now = file(drive.entry(id).await.unwrap().unwrap());
    assert_eq!(now.blob, restored);
    assert_eq!(now.heads, [restored]);
    assert!(drive.conflicts().await.unwrap().is_empty());
    let mut parents = now.versions[&restored].parents.clone();
    parents.sort();
    let mut heads = vec![second, stale];
    heads.sort();
    assert_eq!(parents, heads);
    assert_eq!(
        files.get(restored).await.unwrap().as_deref(),
        Some(&b"draft"[..])
    );
    assert_eq!(drive.versions(id).await.unwrap().len(), 4);
    // A blob that is no version of the file is refused.
    let other = files.put(None, b"other").await.unwrap();
    assert!(matches!(
        drive.restore_version(id, other).await,
        Err(Error::Invalid(_))
    ));
}
