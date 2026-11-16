//! The application's surface, end to end on loopback: the flow of
//! `examples/shared_note.rs`, then Records, blobs, members and their
//! removal, events, a directory store and errors. Every wait has a
//! deadline, and nothing leaves the host.

use frasil::{
    Device, Document, Error, Event, Level, MemberKind, Options, Space, SpaceId, Storage,
    StreamKind, Value,
};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::TestPeer;
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
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

/// Alice's space at the peer, with Bob admitted by an invitation; both
/// connected to the peer.
async fn shared(peer: &TestPeer) -> (Device, Device, Space, Space) {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, newcomer| async move {
            newcomer == "Bob's phone"
        })
        .await
        .unwrap();
    assert_eq!(invitation.space(), space.id());
    let bobs_space = within(
        bob.join(invitation.text(), "Bob's phone", |_, host| async move {
            host == "Alice's laptop"
        }),
    )
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert_eq!(bobs_space.id(), space.id());
    bob.connect(&peer.origin).await.unwrap();
    (alice, bob, space, bobs_space)
}

async fn text_is(document: &Document, text: &str) -> bool {
    document.text("body").await.unwrap() == text
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_share_a_note() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    assert_eq!(bobs_space.level().await, Some(Level::Write));

    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    let mut events = bob.events();
    let bobs_note = within(async {
        loop {
            match bobs_space.document(note.id()).await {
                Ok(note) => break note,
                Err(_) => {
                    events.next().await;
                }
            }
        }
    })
    .await;
    note.edit(|doc| doc.get_text("body").insert(5, ", world"))
        .await
        .unwrap();
    bobs_note
        .edit(|doc| doc.get_text("body").insert(0, "Bob: "))
        .await
        .unwrap();
    until(|| async {
        text_is(&note, "Bob: Hello, world").await && text_is(&bobs_note, "Bob: Hello, world").await
    })
    .await;
    // The peer keeps every change of both. Bob, a member, may have
    // acknowledged Alice's changes before her connection carries the space,
    // which counts while no peer has acknowledged anything of it: the
    // connection carries it first.
    until(|| async { alice.peers()[0].status().spaces == vec![space.id()] }).await;
    until(|| async { space.is_durable().await && bobs_space.is_durable().await }).await;
    let status = alice.peers()[0].status();
    assert!(status.connected);
    assert_eq!(status.spaces, vec![space.id()]);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    until(|| async { !alice.peers()[0].status().connected }).await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_blobs_members_and_events() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    let mut events = alice.events();

    // Records: Alice writes a row; Bob reads it.
    let tasks = space.create_records().unwrap();
    tasks
        .write(|tx| {
            tx.insert("tasks", b"t1")
                .set("tasks", b"t1", "title", "Buy milk")
                .set("tasks", b"t1", "done", 0u64);
        })
        .await
        .unwrap();
    let row = tasks.row("tasks", b"t1").await.unwrap().unwrap();
    assert_eq!(row["title"], Value::from("Buy milk"));
    // Alice's own write is an event. A change of her count of changes
    // awaiting acknowledgement may come first, from any notice of the
    // space: it is another event, reported whenever the count changes.
    let event = within(async {
        loop {
            match events.next().await {
                Some(Event::PendingChanges { .. }) => {}
                other => break other,
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        event,
        Event::Changed {
            space: space.id(),
            streams: vec![tasks.id()],
            members: false,
        }
    );
    until(|| async { bobs_space.records(tasks.id()).await.is_ok() }).await;
    let bobs_tasks = bobs_space.records(tasks.id()).await.unwrap();
    bobs_tasks
        .write(|tx| {
            tx.set("tasks", b"t1", "done", 1u64);
        })
        .await
        .unwrap();
    until(|| async {
        tasks
            .row("tasks", b"t1")
            .await
            .unwrap()
            .is_some_and(|row| row.get("done") == Some(&Value::from(1u64)))
    })
    .await;
    assert!(matches!(tasks.write(|_| {}).await, Err(Error::Adapter(_))));

    // Blobs: Alice puts one; Bob receives its bytes through the peer.
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("hello.txt"), b"hello").await.unwrap();
    assert_eq!(
        files.get(blob).await.unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    until(|| async { bobs_space.blobs(files.id()).await.is_ok() }).await;
    let bobs_files = bobs_space.blobs(files.id()).await.unwrap();
    let listed = bobs_files.list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name.as_deref(), Some("hello.txt"));
    assert_eq!(listed[0].size, 5);
    until(|| async { bobs_files.get(blob).await.unwrap().is_some() }).await;

    // The streams, by kind.
    let mut kinds: Vec<StreamKind> = space
        .streams()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.kind)
        .collect();
    kinds.sort();
    assert_eq!(kinds, vec![StreamKind::Records, StreamKind::Blobs]);

    // Members, and a removal.
    let members = space.members().await.unwrap();
    let bobs = members
        .iter()
        .find(|m| m.id == bob.id())
        .expect("Bob is a member");
    assert_eq!((bobs.kind, bobs.level), (MemberKind::Device, Level::Write));
    assert!(matches!(
        bobs_space.remove(alice.id()).await,
        Err(Error::NotAllowed(_))
    ));
    space.remove(bob.id()).await.unwrap();
    assert!(
        space
            .members()
            .await
            .unwrap()
            .iter()
            .all(|m| m.id != bob.id())
    );
    assert!(matches!(
        space.remove(bob.id()).await,
        Err(Error::Invalid(_))
    ));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_device_sees_its_removal() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    until(|| async { bobs_space.members().await.unwrap().len() == 2 }).await;
    let mut events = bob.events();
    space.remove(bob.id()).await.unwrap();

    // Bob holds the removal and sees it: a notice, no level, not a member.
    let removed = within(async {
        loop {
            match events.next().await {
                Some(event @ Event::Removed { .. }) => break event,
                Some(_) => {}
                None => panic!("Bob's device is gone"),
            }
        }
    })
    .await;
    assert_eq!(removed, Event::Removed { space: space.id() });
    assert_eq!(bobs_space.level().await, None);
    let members = bobs_space.members().await.unwrap();
    assert!(members.iter().all(|m| m.id != bob.id()));
    assert!(members.iter().any(|m| m.id == alice.id()));
    // What Alice writes after the removal stays sealed to Bob.
    let notes = space.create_records().unwrap();
    notes
        .write(|tx| {
            tx.insert("notes", b"n1")
                .set("notes", b"n1", "text", "after");
        })
        .await
        .unwrap();
    until(|| async { space.is_durable().await }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(bobs_space.records(notes.id()).await.is_err());

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_store_keeps_the_device() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("client-directory");
    let _ = std::fs::remove_dir_all(&dir);
    let key = [9; 32];
    let (id, space) = {
        let device = Device::open(Storage::directory(&dir), &key).await.unwrap();
        let space = device.create_space().await.unwrap();
        device.close().await.unwrap();
        (device.id(), space.id())
    };
    // The default restore mode counts every start as a restore: the device
    // holds its spaces, and syncs before it writes again.
    let device = Device::open(Storage::directory(&dir), &key).await.unwrap();
    assert_eq!(device.id(), id);
    let held = device.space(space).await.unwrap();
    let note = held.create_document().unwrap();
    let refused = note
        .edit(|doc| doc.get_text("body").insert(0, "x"))
        .await
        .unwrap_err();
    assert_eq!(refused, Error::SyncBeforeWriting);
    assert!(format!("{refused:#}").contains("connect to a peer"));
    device.close().await.unwrap();
    drop(device);
    // A wrong unlock key opens nothing.
    assert!(matches!(
        Device::open(Storage::directory(&dir), &[8; 32]).await,
        Err(Error::Class(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
    // A store stated never restored writes again at once.
    let options = || Options::new().never_restored();
    let space = {
        let device = Device::open_with(Storage::directory(&dir), &key, options())
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        device.close().await.unwrap();
        space.id()
    };
    let device = Device::open_with(Storage::directory(&dir), &key, options())
        .await
        .unwrap();
    let note = device
        .space(space)
        .await
        .unwrap()
        .create_document()
        .unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "x"))
        .await
        .unwrap();
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn names_and_errors_say_what_they_are() {
    let device = device(3).await;
    let space = device.create_space().await.unwrap();
    let text = space.id().to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text.parse::<SpaceId>().unwrap(), space.id());
    assert!(matches!("zz".parse::<SpaceId>(), Err(Error::Invalid(_))));
    let unknown = SpaceId::from_bytes([0xee; 32]);
    let missing = device.space(unknown).await.unwrap_err();
    assert_eq!(missing, Error::UnknownSpace);
    assert!(missing.what_to_do().contains("join"));
    assert!(matches!(
        device
            .join("not an invitation", "me", |_, _| async { true })
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        device.connect("http://example.org").await,
        Err(Error::NotAllowed(_))
    ));
    // A new document reads empty until its first edit.
    let note = space.create_document().unwrap();
    assert_eq!(note.text("body").await.unwrap(), "");
    assert!(matches!(
        space.document(note.id()).await,
        Err(Error::UnknownStream)
    ));
    note.edit(|doc| doc.get_text("body").insert(0, "kept"))
        .await
        .unwrap();
    assert!(matches!(
        space.records(note.id()).await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        note.edit(|_| Err::<(), _>("no change")).await,
        Err(Error::Adapter(_))
    ));
    assert_eq!(
        space
            .document(note.id())
            .await
            .unwrap()
            .text("body")
            .await
            .unwrap(),
        "kept"
    );
    device.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_leaves_or_forgets_a_space() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    until(|| async { bobs_space.members().await.unwrap().len() == 2 }).await;

    // The last administering device stays.
    assert!(matches!(space.leave().await, Err(Error::NotAllowed(_))));

    // With Bob administering too, Alice leaves: Bob sees her go, and her
    // device no longer holds the space.
    space.raise(bob.id(), 255).await.unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Administer) }).await;
    within(space.leave()).await.unwrap();
    assert!(alice.spaces().await.is_empty());
    assert!(matches!(
        alice.space(space.id()).await,
        Err(Error::UnknownSpace)
    ));
    until(|| async {
        bobs_space
            .members()
            .await
            .unwrap()
            .iter()
            .all(|m| m.id != alice.id())
    })
    .await;

    // Forgetting drops the space from this device alone.
    bobs_space.forget().await.unwrap();
    assert!(bob.spaces().await.is_empty());

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_reads_the_kind_a_space_was_made_as() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    assert!(matches!(
        alice.create_space_of_kind("").await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        alice.create_space_of_kind(&"k".repeat(256)).await,
        Err(Error::Invalid(_))
    ));
    let plain = alice.create_space().await.unwrap();
    assert_eq!(plain.kind().await.unwrap(), None);
    let space = alice.create_space_of_kind("notes").await.unwrap();
    assert_eq!(space.kind().await.unwrap().as_deref(), Some("notes"));
    alice.connect(&peer.origin).await.unwrap();
    let invitation = space
        .invite(Level::Read, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert_eq!(bobs_space.kind().await.unwrap().as_deref(), Some("notes"));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_sees_who_changed_a_row_last_and_when_they_say() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    let tasks = space.create_records().unwrap();
    tasks
        .write(|tx| {
            tx.insert("tasks", b"t1")
                .set("tasks", b"t1", "title", "Buy milk");
        })
        .await
        .unwrap();
    let mine = tasks.last_change("tasks", b"t1").await.unwrap().unwrap();
    assert_eq!(mine.author, alice.id());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(mine.time.is_some_and(|t| t.abs_diff(now) < 60), "{mine:?}");
    assert_eq!(tasks.last_change("tasks", b"none").await.unwrap(), None);

    until(|| async { bobs_space.records(tasks.id()).await.is_ok() }).await;
    let bobs_tasks = bobs_space.records(tasks.id()).await.unwrap();
    until(|| async { bobs_tasks.row("tasks", b"t1").await.unwrap().is_some() }).await;
    bobs_tasks
        .write(|tx| {
            tx.set("tasks", b"t1", "done", true);
        })
        .await
        .unwrap();
    until(|| async {
        tasks
            .last_change("tasks", b"t1")
            .await
            .unwrap()
            .is_some_and(|last| last.author == bob.id())
    })
    .await;
    let theirs = tasks.last_change("tasks", b"t1").await.unwrap().unwrap();
    assert!(theirs.time.is_some_and(|t| t.abs_diff(now) < 60));
    // The history shows each change's time too.
    let history = tasks.history().await.unwrap();
    assert!(history.iter().all(|change| change.time.is_some()));
    assert!(history.iter().any(|change| change.id == theirs.change));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

/// Alice grants Bob `administer`, waits for a peer to hold it, and goes
/// offline at once: through the peer alone, Bob administers, and a third
/// device sees what he does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_granted_administrator_administers_once_the_granter_is_gone() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, bob, space, bobs_space) = shared(&peer).await;
    let carol = device(3).await;
    let invitation = space
        .invite(Level::Write, "Alice's laptop", |_, newcomer| async move {
            newcomer == "Carol's tablet"
        })
        .await
        .unwrap();
    let carols_space = within(carol.join(
        invitation.text(),
        "Carol's tablet",
        |_, host| async move { host == "Alice's laptop" },
    ))
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    carol.connect(&peer.origin).await.unwrap();
    until(|| async { bobs_space.members().await.unwrap().len() == 3 }).await;

    space.raise(bob.id(), 255).await.unwrap();
    within(space.flush()).await.unwrap();
    alice.close().await.unwrap();

    until(|| async { bobs_space.level().await == Some(Level::Administer) }).await;
    bobs_space.raise(carol.id(), 255).await.unwrap();
    within(bobs_space.flush()).await.unwrap();
    until(|| async { carols_space.level().await == Some(Level::Administer) }).await;
    let level_of_bob = |members: Vec<frasil::Member>| {
        members
            .into_iter()
            .find(|m| m.id == bob.id())
            .map(|m| m.level)
    };
    assert_eq!(
        level_of_bob(carols_space.members().await.unwrap()),
        Some(Level::Administer)
    );

    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// Bob joins with `read`, Alice grants him `administer` and waits for a
/// peer to hold it, and Bob's first write in the space, a row in Alice's
/// Records stream and one in a stream of his own, reaches Alice through
/// the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_made_administrator_writes_through_the_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let tasks = space.create_records().unwrap();
    tasks
        .write(|tx| {
            tx.insert("tasks", b"t1")
                .set("tasks", b"t1", "title", "Plan");
        })
        .await
        .unwrap();
    let invitation = space
        .invite(Level::Read, "Alice's laptop", |_, newcomer| async move {
            newcomer == "Bob's phone"
        })
        .await
        .unwrap();
    let bobs_space = within(
        bob.join(invitation.text(), "Bob's phone", |_, host| async move {
            host == "Alice's laptop"
        }),
    )
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    until(|| async { bobs_space.records(tasks.id()).await.is_ok() }).await;
    assert_eq!(bobs_space.level().await, Some(Level::Read));

    space.raise(bob.id(), 255).await.unwrap();
    within(space.flush()).await.unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Administer) }).await;

    let bobs_tasks = bobs_space.records(tasks.id()).await.unwrap();
    bobs_tasks
        .write(|tx| {
            tx.insert("tasks", b"t2")
                .set("tasks", b"t2", "title", "Approve");
        })
        .await
        .unwrap();
    let approvals = bobs_space.create_records().unwrap();
    approvals
        .write(|tx| {
            tx.insert("approvals", b"a1")
                .set("approvals", b"a1", "week", 44u64);
        })
        .await
        .unwrap();
    within(bobs_space.flush()).await.unwrap();
    until(|| async { tasks.row("tasks", b"t2").await.unwrap().is_some() }).await;
    until(|| async { space.records(approvals.id()).await.is_ok() }).await;
    let alices_approvals = space.records(approvals.id()).await.unwrap();
    until(|| async {
        alices_approvals
            .row("approvals", b"a1")
            .await
            .unwrap()
            .is_some()
    })
    .await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

/// No admission hands out a rank implicitly (roster.md, 2.3 Changes,
/// "Ranks"): `admit` refuses `administer`, and `admit_administrator`
/// refuses a rank above the approver's own, both before any code is
/// exchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_administrator_is_admitted_only_at_a_rank_at_most_the_approvers() {
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    assert_eq!(space.my_rank().await.unwrap(), Some(255));
    let refused = space
        .admit("not a code", Level::Administer, "Alice", |_, _| async {
            true
        })
        .await;
    assert!(
        matches!(refused, Err(frasil::Error::Invalid(_))),
        "{refused:?}"
    );
    // Bob administers at rank 7 and cannot admit at 8.
    let bob = device(2).await;
    let id = frasil_events::EventId(*space.id().as_bytes());
    alice
        .engine()
        .grant_administrator(
            id,
            bob.engine().public_keys().clone(),
            7,
            frasil_space::HistoryMode::WithHistory,
            frasil_space::Via::Code,
        )
        .await
        .unwrap();
    bob.engine().follow(id).await;
    bob.engine()
        .ingest(id, alice.engine().events(&id).await)
        .await
        .unwrap();
    let bobs_space = bob.space(space.id()).await.unwrap();
    assert_eq!(bobs_space.my_rank().await.unwrap(), Some(7));
    let above = bobs_space
        .admit_administrator(
            "not a code",
            8,
            frasil_space::HistoryMode::FromNowOn,
            "Bob",
            |_, _| async { true },
        )
        .await;
    assert!(
        matches!(above, Err(frasil::Error::Class("HigherRank"))),
        "{above:?}"
    );
    alice.close().await.unwrap();
    bob.close().await.unwrap();
}
