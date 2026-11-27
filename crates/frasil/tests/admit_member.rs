//! A member of another space (admission.md, 3.16): an administrator of one
//! space admits a direct device member of another space it holds, with no
//! code and no peer, and the welcome goes over the member connection the two
//! devices hold for the other space. The granter keeps the welcome waiting
//! at rest, so a restart loses none and makes none again (admission.md,
//! 3.10 Welcomes, "A welcome that waits").
#![cfg(all(feature = "iroh", feature = "sqlite", feature = "adapter-loro"))]

use frasil::{Device, Document, Error, Level, MemberId, Options, Space, SpaceId, Storage};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_space::{HistoryMode, MemberRef, Via};
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn memory(key: u8) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .expect("a device")
}

fn dir(name: &str) -> PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("admit-member-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn stored(path: &std::path::Path, key: u8) -> Device {
    stored_with(path, key, Options::new().loopback().never_restored()).await
}

async fn stored_with(path: &std::path::Path, key: u8, options: Options) -> Device {
    Device::open_with(Storage::Directory(path.to_owned()), &[key; 32], options)
        .await
        .expect("a device")
}

/// Local discovery on loopback: two devices that both restarted, whose
/// member endpoint keys are both new, find each other again.
fn discovering() -> Options {
    Options::new().loopback().local_discovery().never_restored()
}

/// `newcomer` joins a new space of `granter`'s by a compared code, over a
/// nearby connection on loopback: the known space, which grants it
/// directly.
async fn known_space(granter: &Device, newcomer: &Device) -> Space {
    let space = granter.create_space().await.unwrap();
    let invitation = space
        .invite(Level::Write, "granter", |_, _| async { true })
        .await
        .unwrap();
    within(newcomer.join(invitation.text(), "newcomer", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    space
}

/// Waits until a member connection for `known` joins the two devices and
/// `device` keeps a ticket of the granter, which it dials when it opens
/// again (transport.md, "Reconnecting").
async fn connected(known: &Space, device: &Device) {
    let id = ev(known.id());
    within(async {
        while !known.connected_members().contains(&device.id())
            || device
                .engine()
                .kept_endpoints(&id)
                .await
                .unwrap()
                .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// A space with a note written before anyone else joins it.
async fn space_with_note(granter: &Device) -> (Space, Document) {
    let space = granter.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "before"))
        .await
        .unwrap();
    (space, note)
}

/// The space once `device` follows it and its roster reaches the device.
async fn arrives(device: &Device, space: SpaceId) -> Space {
    within(async {
        loop {
            if let Ok(held) = device.space(space).await
                && held.level().await.is_some()
            {
                return held;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
}

async fn reads(space: &Space, note: &Document, text: &str) -> Document {
    let note = space
        .document_when_available(note.id(), DEADLINE)
        .await
        .unwrap();
    within(async {
        while note.text("body").await.unwrap() != text {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    note
}

fn ev(space: SpaceId) -> EventId {
    EventId(*space.as_bytes())
}

fn device_of(member: MemberId) -> DeviceId {
    DeviceId(*member.as_bytes())
}

/// How the granter's roster of `space` holds `member`'s direct grant.
async fn grant_of(
    granter: &Device,
    space: SpaceId,
    member: MemberId,
) -> Option<(Level, Option<u8>, HistoryMode, Via)> {
    granter
        .engine()
        .read(&ev(space), |replica| {
            replica
                .roster()
                .state(&MemberRef::device(device_of(member)))
                .map(|state| (state.level, state.rank, state.history, state.via))
        })
        .await
        .unwrap()
}

/// The events in `device`'s log of `space`.
async fn events_in(device: &Device, space: SpaceId) -> usize {
    device
        .engine()
        .read(&ev(space), |replica| {
            replica.log().map_or(0, |log| log.events().count())
        })
        .await
        .unwrap()
}

/// Two devices and no peer: an administrator of a space admits a device
/// that another space grants directly; the device follows the space over
/// the member connection the two hold for the other space, reads what was
/// written before, and writes. The grant records `via` = `none`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_member_of_one_space_is_admitted_to_another_with_no_peer() {
    let granter = memory(41).await;
    let device = memory(42).await;
    let known = known_space(&granter, &device).await;
    let (space, note) = space_with_note(&granter).await;

    space
        .admit_member(known.id(), device.id(), Level::Write)
        .await
        .unwrap();
    assert_eq!(
        grant_of(&granter, space.id(), device.id()).await,
        Some((Level::Write, None, HistoryMode::WithHistory, Via::None)),
        "a device grant with history, via none"
    );

    let arrived = arrives(&device, space.id()).await;
    assert_eq!(arrived.level().await, Some(Level::Write));
    let theirs = reads(&arrived, &note, "before").await;
    theirs
        .edit(|doc| doc.get_text("body").insert(6, ", after"))
        .await
        .unwrap();
    reads(&space, &note, "before, after").await;
    granter.close().await.unwrap();
    device.close().await.unwrap();
}

/// A device admitted as an administrator arrives as one, at its rank, and
/// administers the space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_admitted_as_an_administrator_arrives_as_one() {
    let granter = memory(63).await;
    let device = memory(64).await;
    let known = known_space(&granter, &device).await;
    let (space, note) = space_with_note(&granter).await;

    space
        .admit_member_administrator(known.id(), device.id(), 1)
        .await
        .unwrap();
    let arrived = arrives(&device, space.id()).await;
    assert_eq!(arrived.level().await, Some(Level::Administer));
    reads(&arrived, &note, "before").await;
    assert_eq!(
        grant_of(&device, space.id(), device.id()).await,
        Some((
            Level::Administer,
            Some(1),
            HistoryMode::WithHistory,
            Via::None
        ))
    );
    granter.close().await.unwrap();
    device.close().await.unwrap();
}

/// A device that is not connected when it is admitted gets the space when
/// it next connects for the space the two share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_away_at_the_grant_gets_the_space_when_it_connects() {
    let dir = dir("away");
    let granter = memory(43).await;
    let device = stored(&dir, 44).await;
    let known = known_space(&granter, &device).await;
    let id = device.id();
    connected(&known, &device).await;
    device.close().await.unwrap();
    drop(device);
    let (space, note) = space_with_note(&granter).await;

    space
        .admit_member(known.id(), id, Level::Read)
        .await
        .unwrap();

    let device = stored(&dir, 44).await;
    let arrived = arrives(&device, space.id()).await;
    assert_eq!(arrived.level().await, Some(Level::Read));
    reads(&arrived, &note, "before").await;
    granter.close().await.unwrap();
    device.close().await.unwrap();
    drop((arrived, device));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The granter restarts between the grant and the device's connecting, and
/// no peer is anywhere: the welcome it kept at rest waits again, and it
/// hands it over when the two meet. No event is signed to replace it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_granter_that_restarts_hands_the_kept_welcome_over() {
    let dir = dir("restart");
    let granter = stored_with(&dir.join("granter"), 45, discovering()).await;
    let device = stored_with(&dir.join("device"), 46, discovering()).await;
    let known = known_space(&granter, &device).await;
    let id = device.id();
    connected(&known, &device).await;
    device.close().await.unwrap();
    drop(device);
    let (space, note) = space_with_note(&granter).await;
    let (space_id, note_id) = (space.id(), note.id());

    space
        .admit_member(known.id(), id, Level::Write)
        .await
        .unwrap();
    let before = events_in(&granter, space_id).await;
    granter.close().await.unwrap();
    drop((space, note, known, granter));

    let granter = stored_with(&dir.join("granter"), 45, discovering()).await;
    assert_eq!(
        granter.waiting_welcomes().len(),
        1,
        "the welcome waits again"
    );
    let device = stored_with(&dir.join("device"), 46, discovering()).await;
    let arrived = arrives(&device, space_id).await;
    assert_eq!(arrived.level().await, Some(Level::Write));
    let theirs = arrived
        .document_when_available(note_id, DEADLINE)
        .await
        .unwrap();
    within(async {
        while theirs.text("body").await.unwrap() != "before" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(
        grant_of(&granter, space_id, id).await,
        Some((Level::Write, None, HistoryMode::WithHistory, Via::None))
    );
    // The welcome the grant made, and no other event.
    assert_eq!(events_in(&granter, space_id).await, before);
    assert_eq!(events_in(&device, space_id).await, before);
    // The attach the member connection admitted ends it, at rest too.
    within(async {
        while !granter.waiting_welcomes().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    granter.close().await.unwrap();
    device.close().await.unwrap();
    drop((theirs, arrived, granter, device));
    let granter = stored_with(&dir.join("granter"), 45, discovering()).await;
    assert!(granter.waiting_welcomes().is_empty());
    granter.close().await.unwrap();
    drop(granter);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same holds for a person's grant: the welcome of a device of the
/// person waits at rest through the granter's restart, and is handed over
/// when they meet, with no event signed to replace it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_grant_survives_the_granters_restart() {
    let dir = dir("person");
    let granter = stored_with(&dir.join("granter"), 61, discovering()).await;
    let device = stored_with(&dir.join("device"), 62, discovering()).await;
    let person = device.make_person(&[62; 32]).await.unwrap();
    let known = known_space(&granter, &device).await;
    granter
        .engine()
        .receive_list(device.engine().list_events(person.as_bytes()).await)
        .await
        .unwrap();
    connected(&known, &device).await;
    device.close().await.unwrap();
    drop(device);
    let (space, note) = space_with_note(&granter).await;
    let (space_id, note_id) = (space.id(), note.id());

    space.grant_person(person, Level::Write).await.unwrap();
    let before = events_in(&granter, space_id).await;
    granter.close().await.unwrap();
    drop((space, note, known, granter));

    let granter = stored_with(&dir.join("granter"), 61, discovering()).await;
    assert_eq!(
        granter.waiting_welcomes().len(),
        1,
        "the welcome waits again"
    );
    let device = stored_with(&dir.join("device"), 62, discovering()).await;
    let arrived = arrives(&device, space_id).await;
    assert_eq!(arrived.level().await, Some(Level::Write));
    let theirs = arrived
        .document_when_available(note_id, DEADLINE)
        .await
        .unwrap();
    within(async {
        while theirs.text("body").await.unwrap() != "before" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(events_in(&granter, space_id).await, before);
    granter.close().await.unwrap();
    device.close().await.unwrap();
    drop((theirs, arrived, granter, device));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A device removed from the space before it connects is offered nothing:
/// the welcome that waited for it goes nowhere, and it never follows the
/// space. Its record goes too: the granter opens again with nothing
/// waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_removed_before_it_connects_is_offered_nothing() {
    let dir = dir("removed");
    let granter = stored(&dir.join("granter"), 47).await;
    let device = stored(&dir.join("device"), 48).await;
    let known = known_space(&granter, &device).await;
    let id = device.id();
    connected(&known, &device).await;
    device.close().await.unwrap();
    drop(device);
    let (space, _) = space_with_note(&granter).await;

    space
        .admit_member(known.id(), id, Level::Read)
        .await
        .unwrap();
    space.remove(id).await.unwrap();
    // A later grant whose welcome waits behind the first: a connection
    // hands welcomes over oldest first, on one ordered stream, so once the
    // device follows this space it has been offered all it will be.
    let (later, _) = space_with_note(&granter).await;
    later
        .admit_member(known.id(), id, Level::Read)
        .await
        .unwrap();

    assert_eq!(granter.waiting_welcomes().len(), 2);

    let device = stored(&dir.join("device"), 48).await;
    let arrived = arrives(&device, later.id()).await;
    assert!(
        !device.engine().spaces().await.contains(&ev(space.id())),
        "the device never follows the space"
    );
    // The removed device's welcome ended at the hand-over, and the later
    // one once the device attached its space.
    within(async {
        while !granter.waiting_welcomes().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    granter.close().await.unwrap();
    device.close().await.unwrap();
    drop((arrived, device, space, later, known, granter));
    let granter = stored(&dir.join("granter"), 47).await;
    assert!(granter.waiting_welcomes().is_empty(), "no record is left");
    granter.close().await.unwrap();
    drop(granter);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every space event `from` holds, handed to `to`, which follows the space.
async fn carry(from: &Device, to: &Device, space: SpaceId) {
    to.engine().follow(ev(space)).await;
    to.engine()
        .ingest(ev(space), from.engine().events(&ev(space)).await)
        .await
        .unwrap();
}

fn not_allowed<T: std::fmt::Debug>(result: frasil::Result<T>, why: &str) {
    assert!(
        matches!(result, Err(Error::NotAllowed(_))),
        "{why}: {result:?}"
    );
}

/// What the granter refuses, and the rank rule.
#[tokio::test]
async fn the_granter_refuses_what_the_known_space_does_not_vouch_for() {
    let granter = memory(51).await;
    let device = memory(52).await;
    let other = memory(53).await;
    let person = memory(54).await;
    let engine = granter.engine();
    let known = granter.create_space().await.unwrap();
    let space = granter.create_space().await.unwrap();
    engine
        .grant_device(
            ev(known.id()),
            device.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();

    assert!(
        matches!(
            space
                .admit_member(known.id(), device.id(), Level::Administer)
                .await,
            Err(Error::Invalid(_))
        ),
        "administer is admitted at a rank"
    );
    not_allowed(
        space
            .admit_member(known.id(), other.id(), Level::Read)
            .await,
        "a device the known space does not grant",
    );
    assert!(
        matches!(
            space
                .admit_member(SpaceId::from_bytes([9; 32]), device.id(), Level::Read)
                .await,
            Err(Error::UnknownSpace)
        ),
        "a known space this device does not hold"
    );

    // A device in the known space only through its person.
    let made = person.engine().make_person(&[54; 32]).await.unwrap();
    engine
        .receive_list(person.engine().list_events(&made.person).await)
        .await
        .unwrap();
    engine
        .grant_person(
            ev(known.id()),
            made.person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    not_allowed(
        space
            .admit_member(known.id(), person.id(), Level::Read)
            .await,
        "a device in the known space only through a person",
    );

    // A device the space reaches already.
    for target in [known.id(), space.id()] {
        engine
            .grant_device(
                ev(target),
                other.engine().public_keys().clone(),
                Level::Read,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    not_allowed(
        space
            .admit_member(known.id(), other.id(), Level::Read)
            .await,
        "a device that is a member already",
    );

    // A device that does not administer the space admits nobody.
    carry(&granter, &other, known.id()).await;
    carry(&granter, &other, space.id()).await;
    let theirs = other.space(space.id()).await.unwrap();
    not_allowed(
        theirs
            .admit_member(known.id(), device.id(), Level::Read)
            .await,
        "a reader of the space",
    );

    // An administrator admits at most at its own rank.
    space.raise(other.id(), 10).await.unwrap();
    carry(&granter, &other, space.id()).await;
    let ranked = theirs
        .admit_member_administrator(known.id(), device.id(), 11)
        .await;
    assert!(
        matches!(ranked, Err(Error::Class("HigherRank"))),
        "a rank above the caller's: {ranked:?}"
    );
    theirs
        .admit_member_administrator(known.id(), device.id(), 10)
        .await
        .unwrap();
    assert_eq!(
        grant_of(&other, space.id(), device.id()).await,
        Some((
            Level::Administer,
            Some(10),
            HistoryMode::WithHistory,
            Via::None
        ))
    );
    not_allowed(
        theirs
            .admit_member(known.id(), device.id(), Level::Read)
            .await,
        "a device admitted already",
    );
}

/// The known space must reach the granter, whose view of its roster is
/// otherwise no longer kept current, and its grant of the device must be
/// in effect: a device that forked there is refused.
#[tokio::test]
async fn the_known_space_must_reach_the_granter_and_the_device() {
    use frasil::advanced::{AdapterRegistry, Engine, Platform};
    use frasil_store::{Commit, DeviceBoundSlot, MemorySlot, MemoryStore, Store};
    use std::sync::Arc;

    let founder = memory(73).await;
    let granter = memory(74).await;
    let device = memory(75).await;
    let known = founder.create_space().await.unwrap();
    let space = granter.create_space().await.unwrap();
    for member in [&granter, &device] {
        founder
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
    }
    founder
        .engine()
        .remove(ev(known.id()), MemberRef::device(device_of(granter.id())))
        .await
        .unwrap();
    carry(&founder, &granter, known.id()).await;
    not_allowed(
        space
            .admit_member(known.id(), device.id(), Level::Read)
            .await,
        "a known space that no longer reaches the granter",
    );

    // A device of the known space that signs one sequence number twice.
    let store = Arc::new(MemoryStore::new());
    let slot: Arc<dyn DeviceBoundSlot> = Arc::new(MemorySlot::new());
    let (forker, sealed) = Engine::create(
        Platform::new(store.clone(), slot.clone()),
        &[76; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    let forker_id = forker.device_id();
    let engine = founder.engine();
    let known = ev(known.id());
    engine
        .grant_device(
            known,
            forker.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    forker.follow(known).await;
    forker
        .ingest(known, engine.events(&known).await)
        .await
        .unwrap();
    let doc = forker.new_document().unwrap();
    forker
        .edit_document(known, &doc, |d| {
            d.get_text("body").insert(0, "one").unwrap();
        })
        .await
        .unwrap();
    let saved = store.scan(&[]).await.unwrap();
    forker
        .edit_document(known, &doc, |d| {
            d.get_text("body").insert(3, " two").unwrap();
        })
        .await
        .unwrap();
    engine
        .ingest(known, forker.events(&known).await)
        .await
        .unwrap();
    drop(forker);
    let restored = Arc::new(MemoryStore::new());
    assert!(
        restored
            .commit(&Commit::new(saved, Vec::new()))
            .await
            .unwrap()
    );
    let forker = Engine::open(
        Platform::new(restored, slot),
        &sealed,
        &[76; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .unwrap();
    forker.synced(&known).await.unwrap();
    forker
        .edit_document(known, &doc, |d| {
            d.get_text("body").insert(3, " other").unwrap();
        })
        .await
        .unwrap();
    engine
        .ingest(known, forker.events(&known).await)
        .await
        .unwrap();
    assert!(
        engine
            .read(&known, |replica| replica.forked(&forker_id))
            .await
            .unwrap(),
        "the device forked in the known space"
    );
    let theirs = founder.create_space().await.unwrap();
    not_allowed(
        theirs
            .admit_member(
                SpaceId::from_bytes(known.0),
                MemberId::from_bytes(forker_id.0),
                Level::Read,
            )
            .await,
        "a device that forked in the known space",
    );
}

/// A guest of the known space is not admitted by it.
#[cfg(feature = "ext-guests")]
#[tokio::test]
async fn a_guest_of_the_known_space_is_refused() {
    let granter = memory(55).await;
    let guest = memory(56).await;
    let known = granter.create_space().await.unwrap();
    let space = granter.create_space().await.unwrap();
    granter
        .engine()
        .grant_guest(
            ev(known.id()),
            guest.engine().public_keys().clone(),
            &frasil_space::ext_guests::Preset::new(Level::Write, [5; 16]),
        )
        .await
        .unwrap();
    not_allowed(
        space
            .admit_member(known.id(), guest.id(), Level::Read)
            .await,
        "a guest",
    );
}

/// A restricted space admits only a device its parent reaches.
#[cfg(feature = "ext-restricted-spaces")]
#[tokio::test]
async fn a_restricted_space_admits_only_a_device_its_parent_reaches() {
    let granter = memory(57).await;
    let device = memory(58).await;
    let known = granter.create_space().await.unwrap();
    let parent = granter.create_space().await.unwrap();
    let restricted = parent.create_restricted().await.unwrap();
    granter
        .engine()
        .grant_device(
            ev(known.id()),
            device.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    not_allowed(
        restricted
            .admit_member(known.id(), device.id(), Level::Read)
            .await,
        "a device outside the parent",
    );
    parent
        .admit_member(known.id(), device.id(), Level::Read)
        .await
        .unwrap();
    restricted
        .admit_member(known.id(), device.id(), Level::Read)
        .await
        .unwrap();
}

/// A restricted known space whose parent does not reach the device grants
/// it with no effect, and vouches for nothing.
#[cfg(feature = "ext-restricted-spaces")]
#[tokio::test]
async fn a_restricted_known_space_vouches_only_for_a_device_its_parent_reaches() {
    let granter = memory(77).await;
    let device = memory(78).await;
    let parent = granter.create_space().await.unwrap();
    let known = parent.create_restricted().await.unwrap();
    let space = granter.create_space().await.unwrap();
    granter
        .engine()
        .grant_device(
            ev(known.id()),
            device.engine().public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    not_allowed(
        space
            .admit_member(known.id(), device.id(), Level::Read)
            .await,
        "a grant with no effect",
    );
    parent
        .admit_member(known.id(), device.id(), Level::Read)
        .await
        .unwrap_err();
}

/// A note `device` writes in `space`, as one unit it signs.
async fn write_note(device: &Device, space: SpaceId, text: &str) {
    let held = device.space(space).await.unwrap();
    let note = held.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, text))
        .await
        .unwrap();
}

/// The welcome ends once the granter's own view of the space holds an
/// event the newcomer signed with the admitting event in its past: the
/// newcomer holds that event and the wrap in it (admission.md, 3.10
/// Welcomes, "A welcome that waits"). An event it signed before the grant,
/// as a member under an earlier grant that a removal ended, or
/// concurrently with the grant, ends nothing. No member connection joins the two devices: the events are
/// carried by hand.
#[tokio::test]
async fn an_event_the_newcomer_signs_after_the_grant_ends_its_welcome() {
    let dir = dir("acted");
    let granter = stored(&dir, 61).await;
    let device = memory(62).await;
    let known = granter.create_space().await.unwrap();
    let space = granter.create_space().await.unwrap();
    for held in [&known, &space] {
        granter
            .engine()
            .grant_device(
                ev(held.id()),
                device.engine().public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    let space_id = space.id();
    // A writer under the earlier grant, the device writes before it is
    // removed and admitted again, and again concurrently with that.
    carry(&granter, &device, space_id).await;
    write_note(&device, space_id, "before").await;
    carry(&device, &granter, space_id).await;
    granter
        .engine()
        .remove(ev(space_id), MemberRef::device(device.engine().device_id()))
        .await
        .unwrap();
    space
        .admit_member(known.id(), device.id(), Level::Write)
        .await
        .unwrap();
    assert_eq!(granter.waiting_welcomes().len(), 1);
    write_note(&device, space_id, "concurrently").await;
    carry(&device, &granter, space_id).await;
    granter.welcome_upkeep().await;
    assert_eq!(
        granter.waiting_welcomes().len(),
        1,
        "an event without the grant in its past ends nothing"
    );
    granter.close().await.unwrap();
    drop((space, known, granter));
    let granter = stored(&dir, 61).await;
    granter.welcome_upkeep().await;
    assert_eq!(granter.waiting_welcomes().len(), 1, "nor after a restart");

    // Once the device holds the grant and writes, its event has the grant
    // in its past: the welcome ends, at rest too.
    carry(&granter, &device, space_id).await;
    write_note(&device, space_id, "after").await;
    carry(&device, &granter, space_id).await;
    granter.welcome_upkeep().await;
    assert!(granter.waiting_welcomes().is_empty());
    granter.close().await.unwrap();
    drop(granter);
    let granter = stored(&dir, 61).await;
    assert!(granter.waiting_welcomes().is_empty(), "no record is left");
    granter.close().await.unwrap();
    device.close().await.unwrap();
    drop((granter, device));
    let _ = std::fs::remove_dir_all(&dir);
}
