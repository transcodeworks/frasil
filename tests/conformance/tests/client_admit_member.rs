//! A member of another space reaches a device connected only through a peer
//! (admission.md, 3.16 A member of another space; 3.10 Welcomes): the
//! granter deposits the device's welcome in its device mailbox at the peer,
//! and the device collects it there. A welcome of a space whose roster no
//! longer reaches the device is deposited nowhere. Every wait has a
//! deadline, and nothing leaves the host.

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

/// A space of `granter`'s with a note in it.
async fn with_note(granter: &Device, text: &str) -> Space {
    let space = granter.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, text))
        .await
        .unwrap();
    space
}

async fn reads(device: &Device, space: &Space, text: &str) {
    within(async {
        loop {
            if let Ok(held) = device.space(space.id()).await
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
    reads(&member, &kept, "kept").await;

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
