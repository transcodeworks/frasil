//! A member of another space reaches a device connected only through a peer
//! (admission.md, 3.16 A member of another space; 3.10 Welcomes): the
//! granter deposits the device's welcome in its device mailbox at the peer,
//! and the device collects it there. A welcome of a space whose roster no
//! longer reaches the device is deposited nowhere. The granter keeps its
//! waiting welcomes at rest, with the peers it deposited each at and when
//! (admission.md, 3.10 Welcomes, "A welcome that waits"), so a restart
//! neither loses a deposit nor makes one again before it is due, and it
//! deposits each again at a peer before the peer lets it go, four times
//! there at most. Every wait has a deadline, and nothing leaves the host.

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
/// it there again before `welcome_redeposit` has passed.
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
            // The peer is named once the deposit is kept, and the deposit
            // counted once its first attempt has ended.
            if granter.waiting_welcomes()[0].2 == [origin.as_str()]
                && granter.welcome_deposits() >= 1
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
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
    assert_eq!(granter.welcome_deposits(), 0, "not due there yet");

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

/// A peer keeps an item of a mailbox its device has never collected for
/// `uncollected_retention`, 72 hours by default, so the granter deposits a
/// waiting welcome there again `welcome_redeposit`, 48 hours, after its
/// latest deposit there, four times there at most: a member that first
/// reaches the peer on the fourth day still finds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_welcome_is_deposited_again_before_the_peer_lets_it_go() {
    const HOUR: u64 = 3_600;
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let clock = std::sync::Arc::new(frasil::advanced::ManualClock::new(
        1_000,
        Some(1_800_000_000),
    ));
    let granter = Device::open_with(
        Storage::Memory,
        &[87; 32],
        Options::new().loopback().clock(clock.clone()),
    )
    .await
    .expect("a device");
    let member = device(88).await;
    let known = known(&granter, &member).await;
    let space = with_note(&granter, "again").await;
    let space_id = space.id();
    space
        .admit_member(known.id(), member.id(), Level::Read)
        .await
        .unwrap();
    granter.connect(&origin).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    let deposited = |at_least: u64| {
        let granter = granter.clone();
        async move {
            within(async {
                while granter.welcome_deposits() < at_least {
                    granter.welcome_upkeep().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await;
        }
    };
    deposited(1).await;
    let first = granter.welcome_deposits();

    // A day later, nothing is due yet.
    peer.advance(24 * HOUR).await;
    clock.advance(24 * HOUR);
    granter.welcome_upkeep().await;
    assert_eq!(granter.welcome_deposits(), first);

    // Two days after the first deposit, the granter deposits again.
    peer.advance(24 * HOUR).await;
    clock.advance(24 * HOUR);
    deposited(first + 1).await;

    // On the fourth day of the peer's, the first copy is gone and the
    // second is not; the granter's clock stays, so it deposits no third.
    peer.advance(48 * HOUR).await;
    member.connect(&origin).await.unwrap();
    reads(&member, space_id, "again").await;

    for device in [granter, member] {
        device.close().await.unwrap();
    }
    drop((space, known));
    peer.shutdown().await;
}

/// A newcomer whose keys come from `seed`, so that a test collects its
/// device mailbox itself: its identity seed and its keys.
fn newcomer(seed: u8) -> ([u8; 32], frasil_crypto::device::DeviceKeys) {
    let identity = [seed; 32];
    let xwing = frasil_crypto::wrap::xwing_public(&identity);
    let signer =
        frasil_crypto::schemes::Signer::from_seeds(&identity, &[seed + 1; 32], Some(&xwing));
    let keys = frasil_crypto::device::DeviceKeys {
        ed: *signer.identity_key(),
        keys: frasil_crypto::device::HybridKeys::new(signer.mldsa_public(), Some(&xwing)).unwrap(),
    };
    (identity, keys)
}

/// Every item in the device mailbox of `keys` at `peer`, collected over the
/// WebSocket with its identity seed: the first collection claims the
/// mailbox (transport.md, "Claimed device mailboxes").
async fn mailbox_items(
    peer: &frasil_relay::testing::TestPeer,
    identity: &[u8; 32],
    keys: &frasil_crypto::device::DeviceKeys,
) -> Vec<Vec<u8>> {
    use frasil_transport::frame::MessageType;
    use frasil_transport::mailbox::{MailboxItems, collect};
    let mut device = frasil_conformance::client::PeerClient::ws(
        peer,
        frasil_transport::peer::Purpose::SpaceTraffic,
    )
    .await;
    let request = device.request();
    let get = collect(
        request,
        identity,
        keys.keys.commitment(),
        &device.binding,
        None,
    );
    let answer = device
        .request_answer(request, &get)
        .await
        .expect("MailboxItems")
        .expect("a message");
    assert_eq!(answer.kind, MessageType::MailboxItems);
    device.close().await;
    MailboxItems::read(&answer)
        .unwrap()
        .items
        .into_iter()
        .map(|(_, item)| item)
        .collect()
}

/// A granter deposits a waiting welcome at one peer four times at most,
/// the first and three repeats `welcome_redeposit` apart, so a mailbox the
/// newcomer claimed, which keeps every copy for `mailbox_retention`, holds
/// four copies of it and no more, while the welcome waits on (admission.md,
/// 3.10 Welcomes, "A welcome that waits").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_welcome_is_deposited_at_a_peer_four_times_at_most() {
    const HOUR: u64 = 3_600;
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let clock = std::sync::Arc::new(frasil::advanced::ManualClock::new(
        1_000,
        Some(1_800_000_000),
    ));
    let granter = Device::open_with(
        Storage::Memory,
        &[89; 32],
        Options::new().loopback().clock(clock.clone()),
    )
    .await
    .expect("a device");
    let (identity, keys) = newcomer(91);
    assert!(
        within(mailbox_items(&peer, &identity, &keys))
            .await
            .is_empty()
    );
    let known = granter.create_space().await.unwrap();
    granter
        .engine()
        .grant_device(
            ev(known.id()),
            keys.clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    let space = with_note(&granter, "four").await;
    granter
        .engine()
        .admit_member(
            ev(space.id()),
            ev(known.id()),
            keys.device_id(),
            Level::Read,
            None,
        )
        .await
        .unwrap();
    granter.connect(&origin).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    let deposited = |at_least: u64| {
        let granter = granter.clone();
        async move {
            within(async {
                while granter.welcome_deposits() < at_least {
                    granter.welcome_upkeep().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await;
        }
    };
    deposited(1).await;
    for count in 2..=4 {
        peer.advance(48 * HOUR).await;
        clock.advance(48 * HOUR);
        deposited(count).await;
    }
    // Three more periods of `welcome_redeposit`: no fifth deposit.
    for _ in 0..3 {
        peer.advance(48 * HOUR).await;
        clock.advance(48 * HOUR);
        granter.welcome_upkeep().await;
    }
    assert_eq!(granter.welcome_deposits(), 4);
    let items = within(mailbox_items(&peer, &identity, &keys)).await;
    assert_eq!(items.len(), 4, "four copies at the peer");
    assert!(items.iter().all(|item| *item == items[0]));
    assert_eq!(granter.waiting_welcomes().len(), 1, "the welcome waits on");

    granter.close().await.unwrap();
    drop((space, known));
    peer.shutdown().await;
}

/// An administrator that admits several devices in a loop starts a pass
/// of deposits for each grant, and its upkeep runs one too, all at once:
/// each pass finds every welcome due at the peer, yet each welcome is
/// deposited there once, counted once, and the peer holds one copy of each
/// (admission.md, 3.10 Welcomes, "A welcome that waits").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn welcomes_of_grants_made_at_once_are_deposited_once_each() {
    const DEVICES: u8 = 5;
    let peer = spawn_loopback().await.unwrap();
    let origin = peer.origin.clone();
    let granter = device(93).await;
    let newcomers: Vec<_> = (0..DEVICES).map(|n| newcomer(101 + 2 * n)).collect();
    let known = granter.create_space().await.unwrap();
    for (_, keys) in &newcomers {
        granter
            .engine()
            .grant_device(
                ev(known.id()),
                keys.clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let space = with_note(&granter, "at once").await;
    granter.connect(&origin).await.unwrap();
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    for (_, keys) in &newcomers {
        space
            .admit_member(
                known.id(),
                frasil::MemberId::from_bytes(keys.device_id().0),
                Level::Read,
            )
            .await
            .unwrap();
    }
    within(async {
        while granter.welcome_deposits() < u64::from(DEVICES) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    // Every pass the grants started has ended.
    within(space.wait_durable(Duration::from_secs(60)))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    granter.welcome_upkeep().await;
    assert_eq!(granter.welcome_deposits(), u64::from(DEVICES));
    let waiting = granter.waiting_welcomes();
    assert_eq!(waiting.len(), usize::from(DEVICES));
    assert!(
        waiting
            .iter()
            .all(|(_, _, peers)| *peers == [origin.as_str()])
    );
    assert_eq!(
        granter.welcome_deposit_counts(&origin),
        vec![1; usize::from(DEVICES)],
        "each counted once"
    );
    for (identity, keys) in &newcomers {
        let items = within(mailbox_items(&peer, identity, keys)).await;
        assert_eq!(items.len(), 1, "one copy at the peer");
    }

    granter.close().await.unwrap();
    drop((space, known));
    peer.shutdown().await;
}
