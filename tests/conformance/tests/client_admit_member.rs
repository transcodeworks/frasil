//! A member of another space reaches a device connected only through a peer
//! (admission.md, 3.16 A member of another space; 3.10 Welcomes): the
//! granter deposits the device's welcome in its device mailbox at the peer,
//! and the device collects it there. A welcome of a space whose roster no
//! longer reaches the device is deposited nowhere. The granter keeps its
//! waiting welcomes at rest, with the peers that hold each (admission.md,
//! 3.10 Welcomes, "A welcome that waits"), so a restart neither loses a
//! deposit nor makes one twice. Every wait has a deadline, and nothing
//! leaves the host.

use frasil::{Device, Level, Options, Space, SpaceId, Storage};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_space::{HistoryMode, MemberRef, Via};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(90);

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

fn ev(space: SpaceId) -> EventId {
    EventId(*space.as_bytes())
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "conformance-admit-member-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A device whose store is the directory `dir`, which it opens again.
async fn stored(dir: &std::path::Path, key: u8) -> Device {
    Device::open_with(
        Storage::Directory(dir.to_owned()),
        &[key; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .expect("a device")
}

/// A space of `granter`'s that grants `member` directly: the two devices
/// never open a member connection, so only a peer carries welcomes.
async fn known(granter: &Device, member: &Device) -> Space {
    let known = granter.create_space().await.unwrap();
    granter
        .engine()
        .grant_device(
            ev(known.id()),
            member.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    known
}

/// A space of `granter`'s with a note in it.
async fn with_note(granter: &Device, text: &str) -> Space {
    let space = granter.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, text))
        .await
        .unwrap();
    space
}

async fn reads(device: &Device, space: SpaceId, text: &str) {
    within(async {
        loop {
            if let Ok(held) = device.space(space).await
                && let Ok(streams) = held.streams().await
                && let Some(stream) = streams.first()
                && let Ok(document) = held.document(stream.id).await
                && document.text("body").await.ok().as_deref() == Some(text)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_of_another_space_collects_its_welcome_at_a_peer_unless_removed() {
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let granter = device(81).await;
    let member = device(82).await;

    // The known space grants the member directly; the two devices never
    // open a member connection, so the peer alone carries the welcomes.
    let known = granter.create_space().await.unwrap();
    granter
        .engine()
        .grant_device(
            ev(known.id()),
            member.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();

    // Before the granter connects: one space the member is admitted to and
    // then removed from, then one it keeps. Both welcomes wait, the first
    // oldest.
    let removed = with_note(&granter, "removed").await;
    removed
        .admit_member(known.id(), member.id(), Level::Read)
        .await
        .unwrap();
    granter
        .engine()
        .remove(
            ev(removed.id()),
            MemberRef::device(frasil_crypto::device::DeviceId(*member.id().as_bytes())),
        )
        .await
        .unwrap();
    let kept = with_note(&granter, "kept").await;
    kept.admit_member(known.id(), member.id(), Level::Read)
        .await
        .unwrap();

    granter.connect(&origin).await.unwrap();
    member.connect(&origin).await.unwrap();
    within(kept.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    within(removed.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();

    // The member's upkeep collects its welcome at the peer.
    reads(&member, kept.id(), "kept").await;

    // Its mailbox there holds no welcome of the space it was removed from.
    let reports = within(member.receive_welcomes_via_peer(&origin, |_| {}))
        .await
        .unwrap();
    assert!(
        reports.iter().all(|report| report.space != removed.id()),
        "{reports:?}"
    );
    assert!(!member.engine().spaces().await.contains(&ev(removed.id())));

    for device in [granter, member] {
        device.close().await.unwrap();
    }
    peer.shutdown().await;
}

/// The granter admits the member and restarts before it reaches any peer;
/// then it connects to a peer, and the member connects only to that peer.
/// The welcome waited at rest, so the granter deposits it there, and the
/// member follows the space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_welcome_kept_before_a_restart_is_deposited_at_a_peer_reached_after_it() {
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let dir = temp_dir("restart-then-peer");
    let granter = stored(&dir, 83).await;
    let member = device(84).await;
    let known = known(&granter, &member).await;
    let space = with_note(&granter, "waited").await;
    let space_id = space.id();
    space
        .admit_member(known.id(), member.id(), Level::Read)
        .await
        .unwrap();
    granter.close().await.unwrap();
    drop((space, known, granter));

    let granter = stored(&dir, 83).await;
    assert_eq!(
        granter.waiting_welcomes().len(),
        1,
        "the welcome waits again"
    );
    granter.connect(&origin).await.unwrap();
    member.connect(&origin).await.unwrap();
    let space = granter.space(space_id).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    reads(&member, space_id, "waited").await;

    for device in [granter, member] {
        device.close().await.unwrap();
    }
    drop(space);
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A welcome deposited at a peer is kept with that peer named, so the
/// granter, opened again and connected to the same peer, does not deposit
/// it there a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_deposits_no_welcome_again_at_a_peer_that_holds_it() {
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let dir = temp_dir("deposited-once");
    let granter = stored(&dir, 85).await;
    let member = device(86).await;
    let known = known(&granter, &member).await;
    let space = with_note(&granter, "once").await;
    let space_id = space.id();
    space
        .admit_member(known.id(), member.id(), Level::Read)
        .await
        .unwrap();
    granter.connect(&origin).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    within(async {
        loop {
            granter.welcome_upkeep().await;
            if granter.waiting_welcomes()[0].2 == [origin.as_str()] {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(granter.welcome_deposits() >= 1);
    granter.close().await.unwrap();
    drop((space, known, granter));

    let granter = stored(&dir, 85).await;
    let waiting = granter.waiting_welcomes();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].2, [origin.as_str()], "the peer that holds it");
    granter.connect(&origin).await.unwrap();
    let space = granter.space(space_id).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    granter.welcome_upkeep().await;
    assert_eq!(granter.welcome_deposits(), 0, "deposited there once");

    // The member still finds it there.
    member.connect(&origin).await.unwrap();
    reads(&member, space_id, "once").await;

    for device in [granter, member] {
        device.close().await.unwrap();
    }
    drop(space);
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
