//! Invite links end to end on loopback (ext-invite-links.md), against a
//! peer with its drops on: the inviter's link and drop, the claimant's
//! walk through `Device::join`, the inviter's close and the drop's
//! deletion, the heal that leaves the link's state behind, a second claim
//! refused, and an invite revoked at expiry.
//! Every wait has a deadline, and nothing leaves the host.
#![cfg(feature = "ext-invite-links")]

use frasil::advanced::platform::ManualClock;
use frasil::{Claimant, Device, Error, HistoryMode, Level, Options, Space, Storage};
use frasil_admission::ext_invite_links::{drop_address, open_drop, read_fragment};
use frasil_conformance::spawn_loopback;
use frasil_relay::testing::TestPeer;
use frasil_space::Status;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn device_at(key: u8, clock: &Arc<ManualClock>) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().loopback().clock(clock.clone()),
    )
    .await
    .expect("a device")
}

/// A space's ID as the engine names it.
fn event_of(space: &Space) -> frasil_events::EventId {
    frasil_events::EventId(*space.id().as_bytes())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// How many items the peer serves at a link's drop address, on the server
/// binding's mailbox route.
async fn drops_served(peer: &TestPeer, link: &str) -> usize {
    let (_, fragment) = link.rsplit_once('#').expect("a fragment");
    let secret = read_fragment(fragment).expect("a fragment").secret;
    let address = drop_address(&secret);
    let url = format!(
        "{}{}",
        peer.origin,
        frasil_transport::peer::mailbox_path(4, &address)
    );
    let text = frasil_conformance::http_client()
        .get(url)
        .send()
        .await
        .expect("the route answers")
        .text()
        .await
        .expect("a body");
    let body: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    body["items"].as_array().map_or(0, Vec::len)
}

/// The key name of the state a link's drop delivers, as the peer serves
/// the drop to anyone who names its address.
async fn drop_state(peer: &TestPeer, link: &str) -> Vec<u8> {
    let (_, fragment) = link.rsplit_once('#').expect("a fragment");
    let secret = read_fragment(fragment).expect("a fragment").secret;
    let url = format!(
        "{}{}",
        peer.origin,
        frasil_transport::peer::mailbox_path(4, &drop_address(&secret))
    );
    let text = frasil_conformance::http_client()
        .get(url)
        .send()
        .await
        .expect("the route answers")
        .text()
        .await
        .expect("a body");
    let body: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let drop: Vec<u8> = body["items"][0]["item"]
        .as_str()
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .expect("a drop");
    open_drop(&secret, &drop).expect("a drop").key_name
}

/// The encoding of a device's current content state.
async fn current_state(space: &Space) -> Option<Vec<u8>> {
    space
        .device()
        .engine()
        .read(&event_of(space), |replica| {
            replica.current().map(|state| state.encode())
        })
        .await
        .ok()
        .flatten()
}

/// Whether the inviter's view holds an invite key out by its own removal:
/// a close or a revocation, not the successor alone.
async fn invite_removed(space: &Space) -> bool {
    let me = space.device().engine().device_id();
    space
        .device()
        .engine()
        .read(&event_of(space), |replica| {
            replica.roster().iter().any(|(member, standing)| {
                member.kind == frasil_space::MemberType::Invite
                    && matches!(standing, frasil_space::Standing::Out { removed_by }
                    if removed_by.iter().any(|id| {
                        replica.event(*id).is_some_and(|e| *e.author() == me)
                    }))
            })
        })
        .await
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_admits_a_device_with_history_and_closes() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    // Written before the invite: the claimant reads it, with history.
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();

    let link = within(space.invite_link_with(
        Level::Write,
        Duration::from_secs(3600),
        HistoryMode::WithHistory,
    ))
    .await
    .unwrap();
    assert!(link.starts_with(&format!("{}#", peer.origin)), "{link}");
    assert_eq!(drops_served(&peer, &link).await, 1);
    // What anyone who names the drop's address can open with the link.
    let leaked = drop_state(&peer, &link).await;
    assert_eq!(current_state(&space).await, Some(leaked.clone()));

    // Bob's device is connected to nothing: the link names the peer.
    let bob = device(2).await;
    let inviter = alice.id().to_string();
    let bobs_space = within(
        bob.join(&link, "Bob's phone", move |code, host| async move {
            code.is_empty() && host == inviter
        }),
    )
    .await
    .unwrap();
    assert_eq!(bobs_space.id(), space.id());
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;
    assert_eq!(bob.peers().len(), 1);

    // Bob reads what came before, and writes.
    let bobs_note = within(async {
        loop {
            if let Ok(note) = bobs_space.document(note.id()).await
                && note.text("body").await.unwrap() == "Hello"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    bobs_note
        .edit(|doc| doc.get_text("body").insert(5, ", Alice"))
        .await
        .unwrap();
    until(|| async { note.text("body").await.unwrap() == "Hello, Alice" }).await;
    until(|| async { bobs_space.is_durable().await }).await;
    let members = space.members().await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.id == bob.id() && m.level == Level::Write)
    );

    // Alice's device closes its invite at once, then deletes its drop.
    until(|| async {
        invite_removed(&space).await && alice.engine().spent_invites().await.is_empty()
    })
    .await;
    until(|| async { drops_served(&peer, &link).await == 0 }).await;

    // The claim put the invite key outside, holding the drop's state: a
    // writer heals, and both members move past it. What Alice writes now
    // reaches Bob, under a state the link never reached.
    until(|| async {
        let current = current_state(&space).await;
        current.is_some() && current != Some(leaked.clone())
    })
    .await;
    until(|| async { current_state(&bobs_space).await == current_state(&space).await }).await;
    note.edit(|doc| doc.get_text("body").insert(12, "!"))
        .await
        .unwrap();
    until(|| async { bobs_note.text("body").await.unwrap() == "Hello, Alice!" }).await;

    // A second claimant finds no drop.
    let carol = device(3).await;
    let refused = within(carol.join(&link, "Carol's phone", |_, _| async { true })).await;
    assert_eq!(refused.unwrap_err(), Error::Class("NotFound"));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_after_the_close_is_refused() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let link = within(space.invite_link(Level::Read, Duration::from_secs(900)))
        .await
        .unwrap();
    // Carol keeps the drop before anyone claims.
    let (_, fragment) = link.rsplit_once('#').unwrap();
    let secret = read_fragment(fragment).unwrap().secret;
    let url = format!(
        "{}{}",
        peer.origin,
        frasil_transport::peer::mailbox_path(4, &drop_address(&secret))
    );
    let text = frasil_conformance::http_client()
        .get(url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let drop: Vec<u8> = body["items"][0]["item"]
        .as_str()
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .unwrap();

    let bob = device(2).await;
    let bobs_space = within(bob.join(&link, "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Read) }).await;
    // Bob's successor is durable at the peer, though Bob only reads.
    until(|| async { bobs_space.is_durable().await }).await;
    until(|| async {
        alice.engine().spent_invites().await.is_empty() && invite_removed(&space).await
    })
    .await;
    until(|| async { space.is_durable().await }).await;

    // Carol claims with the drop she kept: the invite is used. Her
    // connection presents the state the drop hands her.
    let carol = device(3).await;
    let engine = carol.engine();
    let claimed = engine.begin_claim(fragment, &drop).await.unwrap();
    assert_eq!(claimed, event_of(&space));
    carol.connect(&peer.origin).await.unwrap();
    let refusal = within(async {
        loop {
            match engine.claim_status(&claimed).await {
                Ok(frasil::advanced::invite_links::ClaimStatus::Waiting) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                other => break other,
            }
        }
    })
    .await;
    assert_eq!(refusal.unwrap_err(), Error::Class("InviteUsed"));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invite_is_revoked_at_expiry() {
    let peer = spawn_loopback().await.unwrap();
    let clock = Arc::new(ManualClock::new(1_000, Some(now())));
    let alice = device_at(1, &clock).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let link = within(space.invite_link(Level::Write, Duration::from_secs(900)))
        .await
        .unwrap();
    // Open until then.
    assert_eq!(
        alice
            .engine()
            .maintain_invites(event_of(&space))
            .await
            .unwrap(),
        None
    );
    clock.advance(900);
    let revoked = alice
        .engine()
        .maintain_invites(event_of(&space))
        .await
        .unwrap();
    assert!(revoked.is_some());
    until(|| async { invite_removed(&space).await }).await;

    // A claimant whose clock reads past `expires_at` refuses the link.
    let bobs_clock = Arc::new(ManualClock::new(1_000, Some(now() + 1_020)));
    let bob = device_at(2, &bobs_clock).await;
    let refused = within(bob.join(&link, "Bob's phone", |_, _| async { true })).await;
    assert!(
        matches!(
            refused.as_ref().map_err(Error::class_name),
            Err(Some("Expired" | "NotFound" | "InviteRevoked"))
        ),
        "{refused:?}"
    );
    assert!(bob.spaces().await.is_empty());

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_link_is_refused() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let link = within(space.invite_link(Level::Write, Duration::from_secs(3600)))
        .await
        .unwrap();
    assert_eq!(drops_served(&peer, &link).await, 1);

    within(space.revoke_invite_link(&link)).await.unwrap();
    assert!(invite_removed(&space).await);
    // The drop goes from the peer, and the revocation reaches it.
    until(|| async { drops_served(&peer, &link).await == 0 }).await;
    until(|| async { space.is_durable().await }).await;
    // Revoking again changes nothing.
    within(space.revoke_invite_link(&link)).await.unwrap();

    let bob = device(2).await;
    let refused = within(bob.join(&link, "Bob's phone", |_, _| async { true })).await;
    assert!(
        matches!(
            refused.as_ref().map_err(Error::class_name),
            Err(Some("NotFound" | "InviteRevoked"))
        ),
        "{refused:?}"
    );
    assert!(bob.spaces().await.is_empty());

    // A link into another space is no link of this one.
    let other = alice.create_space().await.unwrap();
    assert!(matches!(
        other.revoke_invite_link(&link).await,
        Err(Error::Invalid(_))
    ));

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suggester_can_suggest_and_a_reader_cannot() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    assert!(!space.can_suggest().await);

    let writer_link = within(space.invite_link(Level::Write, Duration::from_secs(900)))
        .await
        .unwrap();
    let bob = device(2).await;
    let bobs_space = within(bob.join(&writer_link, "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;
    // A full writer is no suggester.
    assert!(!bobs_space.can_suggest().await);

    let reader_link = within(space.invite_link(Level::Read, Duration::from_secs(900)))
        .await
        .unwrap();
    let carol = device(3).await;
    let carols_space = within(carol.join(&reader_link, "Carol's phone", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { carols_space.level().await == Some(Level::Read) }).await;

    until(|| async {
        space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == bob.id())
    })
    .await;
    within(space.set_suggester(bob.id(), true)).await.unwrap();
    until(|| async { bobs_space.can_suggest().await }).await;
    assert!(!carols_space.can_suggest().await);
    assert!(!space.can_suggest().await);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// A device whose store is a directory, so that it reopens.
async fn directory_device(dir: &std::path::Path, key: u8) -> Device {
    Device::open_with(
        frasil::Storage::Directory(dir.to_path_buf()),
        &[key; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_by_link_left_pending_is_forgotten_when_the_device_reopens() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let space = alice.create_space().await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let link = within(space.invite_link(Level::Write, Duration::from_secs(900)))
        .await
        .unwrap();
    // The drop, as Carol keeps it in `a_claim_after_the_close_is_refused`.
    let (_, fragment) = link.rsplit_once('#').unwrap();
    let secret = read_fragment(fragment).unwrap().secret;
    let url = format!(
        "{}{}",
        peer.origin,
        frasil_transport::peer::mailbox_path(4, &drop_address(&secret))
    );
    let text = frasil_conformance::http_client()
        .get(url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    let kept_drop: Vec<u8> = body["items"][0]["item"]
        .as_str()
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .unwrap();

    // Bob begins the claim and stops before anything else: the log is
    // marked as a claim's. Reopened, the device forgets it.
    let dir = std::env::temp_dir().join(format!(
        "frasil-conformance-pending-link-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let bob = directory_device(&dir, 2).await;
    let claimed = bob
        .engine()
        .begin_claim(fragment, &kept_drop)
        .await
        .unwrap();
    assert_eq!(claimed, event_of(&space));
    assert!(bob.engine().spaces().await.contains(&claimed));
    assert!(
        bob.spaces().await.is_empty(),
        "listed nowhere while pending"
    );
    bob.close().await.unwrap();
    std::mem::drop(bob);
    let bob = directory_device(&dir, 2).await;
    assert!(bob.engine().spaces().await.is_empty(), "no ghost log");

    // The link still works for him: a fresh join claims it.
    let inviter = alice.id().to_string();
    let bobs_space = within(
        bob.join(&link, "Bob's phone", move |code, host| async move {
            code.is_empty() && host == inviter
        }),
    )
    .await
    .unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;

    // A member holding the space already begins no claim on it.
    let again = bob.engine().begin_claim(fragment, &kept_drop).await;
    assert!(
        matches!(again, Err(Error::NotAllowed(_)) | Ok(_)),
        "{again:?}"
    );
    assert_eq!(bob.spaces().await.len(), 1);

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A person's device claims a link "from now on" into a space that grants
/// its inviter's person and whose log holds a void roster event before the
/// invite: the snapshot for `K` carries that event's body key, so the
/// claimant judges it void and the invite entry valid ("Claiming", step 6;
/// roster.md, "Space events a replica cannot open"). The client itself
/// refuses to raise a person to `administer`, the change that is void.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_claims_a_link_after_a_void_roster_event() {
    use frasil_space::{Change, MemberRef};
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    let person = alice.make_person(&[11; 32]).await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    assert_eq!(
        space.set_level(person, Level::Administer).await,
        Err(Error::Class("AdministerNotDevice"))
    );
    // The same change signed below the client, as an older client did.
    alice
        .engine()
        .sign_roster(
            event_of(&space),
            vec![Change::set_level(
                MemberRef::person(*person.as_bytes()),
                Level::Administer,
            )],
        )
        .await
        .unwrap();
    until(|| async { space.is_durable().await }).await;

    let link = within(space.invite_link(Level::Read, Duration::from_secs(3600)))
        .await
        .unwrap();
    let bob = device(2).await;
    bob.make_person(&[12; 32]).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let bobs_space = within(bob.join(&link, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Read) }).await;
    until(|| async {
        space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == bob.id() && m.level == Level::Read)
    })
    .await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}

/// A link a person claims: the claimant's person is admitted, its device a
/// reader through it, and the claimant hands the person's list to a writer
/// through the writer's device mailbox at the peer ("Claiming", step 11;
/// units.md, "A read-only person's list events"). The inviter's device then
/// holds the list, and raises the person to `write`, which reaches the
/// claimant's device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_claims_a_link_and_its_list_reaches_the_inviter() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    alice.make_person(&[11; 32]).await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let link = within(space.invite_link_for(
        Claimant::Person,
        Level::Read,
        Duration::from_secs(3600),
        HistoryMode::FromNowOn,
    ))
    .await
    .unwrap();

    // A device of no person cannot claim it.
    let carol = device(3).await;
    let refused = within(carol.join(&link, "Carol's phone", |_, _| async { true })).await;
    assert!(matches!(refused, Err(Error::NotAllowed(_))), "{refused:?}");

    let bob = device(2).await;
    let bobs_person = bob.make_person(&[12; 32]).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let bobs_space = within(bob.join(&link, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Read) }).await;
    until(|| async {
        space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == bobs_person && m.level == Level::Read)
    })
    .await;
    // The list arrives through Alice's device mailbox; then Alice raises
    // Bob's person, and Bob's device writes.
    until(|| async { space.set_level(bobs_person, Level::Write).await.is_ok() }).await;
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// Whether `peer` holds every event `device` holds of `space`.
async fn peer_holds_all(peer: &TestPeer, device: &Device, space: &Space) -> bool {
    let id = event_of(space);
    device.engine().events(&id).await.iter().all(|signed| {
        frasil_events::decode(signed).is_ok_and(|e| peer.peer.holds(&id.0, e.id().as_bytes()))
    })
}

/// Waits until the probe row is in `records`.
async fn reads_probe(records: &frasil::Records) {
    until(|| async {
        records
            .rows("probe")
            .await
            .is_ok_and(|rows| !rows.is_empty())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claimant_admitted_beside_an_earlier_claim_reads_what_follows() {
    // Bob claims his link through a peer Alice's device is not connected
    // to, and Alice makes Carol's link "from now on" before she holds Bob's
    // successor: the successor is concurrent with Carol's break, sealed
    // under a state from before it. Carol holds it `Sealed` until a writer
    // tops up its body key (admission.md, "Top-ups"), and with it every
    // event after it.
    let p1 = spawn_loopback().await.unwrap();
    let p2 = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    alice.connect(&p1.origin).await.unwrap();
    let to_p2 = alice.connect(&p2.origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            tx.insert("meta", b"space");
        })
        .await
        .unwrap();

    let link = within(space.invite_link(Level::Write, Duration::from_secs(3600)))
        .await
        .unwrap();
    within(space.wait_durable(DEADLINE)).await.unwrap();
    until(|| peer_holds_all(&p2, &alice, &space)).await;
    to_p2.close();
    until(|| async { !to_p2.status().connected }).await;

    let bob = device(2).await;
    bob.connect(&p2.origin).await.unwrap();
    let (_, fragment) = link.rsplit_once('#').unwrap();
    let bobs_space = within(bob.join(
        &format!("{}#{fragment}", p2.origin),
        "Bob's phone",
        |_, _| async { true },
    ))
    .await
    .unwrap();
    within(bobs_space.wait_durable(DEADLINE)).await.unwrap();
    let bobs_records = within(bobs_space.records_when_available(records.id(), DEADLINE))
        .await
        .unwrap();

    // Alice has not seen Bob's claim when she invites Carol.
    let successor = bob
        .engine()
        .read(&event_of(&space), |r| r.heads())
        .await
        .unwrap();
    let alice_holds = alice
        .engine()
        .read(&event_of(&space), |r| {
            successor.iter().any(|id| r.holds(*id))
        })
        .await
        .unwrap();
    assert!(!alice_holds, "Alice holds Bob's successor already");
    let link = within(space.invite_link(Level::Write, Duration::from_secs(3600)))
        .await
        .unwrap();
    let carol = device(3).await;
    carol.connect(&p1.origin).await.unwrap();
    let carols_space = within(carol.join(&link, "Carol's phone", |_, _| async { true }))
        .await
        .unwrap();
    let carols_records = within(carols_space.records_when_available(records.id(), DEADLINE))
        .await
        .unwrap();

    // Alice meets Bob's successor, and writes after it.
    alice.connect(&p2.origin).await.unwrap();
    until(|| async {
        alice
            .engine()
            .read(&event_of(&space), |r| {
                successor.iter().all(|id| r.holds(*id))
            })
            .await
            .unwrap()
    })
    .await;
    records
        .write(|tx| {
            tx.insert("probe", b"p");
        })
        .await
        .unwrap();
    reads_probe(&bobs_records).await;
    reads_probe(&carols_records).await;
    let status = carol
        .engine()
        .read(&event_of(&space), |r| {
            successor
                .iter()
                .map(|id| r.status(id).copied())
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
    assert!(
        status.iter().all(|s| matches!(s, Some(Status::Valid(_)))),
        "{status:?}"
    );

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    p1.shutdown().await;
    p2.shutdown().await;
}

/// A deadline for one step of the many-spaces scenario: a hundred devices
/// in one process, beside the other tests, take longer than one.
const LOADED: Duration = Duration::from_secs(300);

async fn slowly<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(LOADED, future)
        .await
        .expect("within the deadline")
}

/// One space set up as the load-test kit does: its creator admits four
/// devices by link one after another, then writes a row each member must
/// read.
async fn space_of_five(origin: Arc<String>, n: u32) {
    let open = |k: u32| async move {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&k.to_be_bytes());
        key[31] = 0xa5;
        Device::open_with(Storage::Memory, &key, Options::new().loopback())
            .await
            .unwrap()
    };
    let alice = open(n * 8).await;
    alice.connect(&origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    let records = space.create_records().unwrap();
    records
        .write(|tx| {
            tx.insert("meta", b"space");
        })
        .await
        .unwrap();
    slowly(space.wait_durable(LOADED)).await.unwrap();
    let mut members = Vec::new();
    for i in 1..5 {
        let member = open(n * 8 + i).await;
        member.connect(&origin).await.unwrap();
        let link = slowly(space.invite_link(Level::Write, Duration::from_secs(3600)))
            .await
            .unwrap();
        let joined = slowly(member.join(&link, "member", |_, _| async { true }))
            .await
            .unwrap();
        let read = slowly(joined.records_when_available(records.id(), LOADED))
            .await
            .unwrap();
        let _ = space.wait_durable(LOADED).await;
        members.push((member, read));
    }
    records
        .write(|tx| {
            tx.insert("probe", b"p");
        })
        .await
        .unwrap();
    for (_, read) in &members {
        slowly(async {
            while !read.rows("probe").await.is_ok_and(|rows| !rows.is_empty()) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
    }
    for (member, _) in members {
        member.close().await.unwrap();
    }
    alice.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn members_admitted_by_link_in_many_spaces_at_once_all_read() {
    // Under load, a creator often makes the next link before it holds the
    // last claim's successor; the last member admitted then depends on a
    // top-up for everything after.
    // A hundred devices in one process share one source, and each holds a
    // collecting connection beside its space connection: no cap per source.
    let mut options = frasil_conformance::options();
    options.settings.connections.max_connections_per_source = 0;
    let peer = frasil_relay::testing::spawn_with(options).await.unwrap();
    let origin = Arc::new(peer.origin.clone());
    let spaces: Vec<_> = (0..20)
        .map(|n| tokio::spawn(space_of_five(origin.clone(), n)))
        .collect();
    for space in spaces {
        space.await.unwrap();
    }
    peer.shutdown().await;
}

/// The state a successor is sealed under, by the claimant's view.
async fn sealed_under(space: &Space, successor: frasil_events::EventId) -> Option<Vec<u8>> {
    space
        .device()
        .engine()
        .read(&event_of(space), |replica| {
            let event = replica.event(successor)?;
            let visible = frasil_keys::body::VisiblePart::read(
                event.unverified_body(),
                event.author(),
                event.seq(),
            )
            .ok()?;
            visible.sealed_under().map(|state| state.encode())
        })
        .await
        .ok()
        .flatten()
}

/// A claim made while a heal concurrent with the invite's break has
/// merged the state ("Claiming", step 11, and "Where the successor is
/// stored"): Carol heals offline while Alice makes an invite "from now
/// on", and once they meet, a writer delivers the merge whole to the
/// invite key. Bob claims, and seals his successor under the merge, whose
/// upload seed he lacks: the successor goes to the peer under the upload
/// key of the state the invite delivered, and becomes durable there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successor_sealed_under_a_merge_reaches_the_peer() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    alice.connect(&peer.origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    until(|| async { space.is_durable().await }).await;
    // Carol joins as a writer, then leaves the peer.
    let carol = device(3).await;
    let carols_peer = carol.connect(&peer.origin).await.unwrap();
    let link = within(space.invite_link(Level::Write, Duration::from_secs(3600)))
        .await
        .unwrap();
    let carols_space = within(carol.join(&link, "Carol's phone", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { carols_space.level().await == Some(Level::Write) }).await;
    until(|| async { carols_space.is_durable().await }).await;
    until(|| async { current_state(&carols_space).await == current_state(&space).await }).await;
    carols_peer.close();
    until(|| async { !carols_peer.status().connected }).await;

    // Alice's invite "from now on" breaks; Carol heals, concurrently.
    let link = within(space.invite_link_for(
        Claimant::Device,
        Level::Read,
        Duration::from_secs(3600),
        HistoryMode::FromNowOn,
    ))
    .await
    .unwrap();
    carol.engine().heal(event_of(&space)).await.unwrap();
    carol.connect(&peer.origin).await.unwrap();
    // Both hold the merge of the break and the heal, and a writer
    // delivers it whole to the invite key after its rank delay.
    until(|| async {
        let alices = current_state(&space).await;
        alices.is_some_and(|state| state.first() == Some(&2))
            && current_state(&carols_space).await == current_state(&space).await
    })
    .await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    until(|| async { space.is_durable().await && carols_space.is_durable().await }).await;
    let merged = current_state(&space).await;

    let bob = device(2).await;
    bob.connect(&peer.origin).await.unwrap();
    let bobs_space = within(bob.join(&link, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    let successor = match bob.engine().claim_status(&event_of(&bobs_space)).await {
        Ok(frasil::advanced::invite_links::ClaimStatus::Claimed(id)) => id,
        other => panic!("Bob's claim: {other:?}"),
    };
    assert_eq!(
        sealed_under(&bobs_space, successor).await,
        merged,
        "the successor is sealed under the merge"
    );
    // It becomes durable at the peer.
    until(|| async { bobs_space.is_durable().await }).await;
    assert!(peer.peer.holds(&event_of(&space).0, successor.as_bytes()));
    until(|| async { bobs_space.level().await == Some(Level::Read) }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    carol.close().await.unwrap();
    peer.shutdown().await;
}

/// A person's claim whose list reaches the inviter's device before the
/// successor does (units.md, "A read-only person's list events"): Alice's
/// device collects its mailbox while her space's sync is paused, so it
/// holds no successor naming Bob's person and drops the list. Bob's device
/// hands the list again from its upkeep, 30 seconds after the claim on its
/// timeline, and once Alice's device holds the successor, the list lands:
/// Alice's device knows Bob's devices, and raising Bob's person reaches
/// them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claimants_list_dropped_before_the_successor_lands_when_sent_again() {
    let peer = spawn_loopback().await.unwrap();
    let alice = device(1).await;
    alice.make_person(&[11; 32]).await.unwrap();
    alice.connect(&peer.origin).await.unwrap();
    let space = alice.create_space().await.unwrap();
    until(|| async { space.is_durable().await }).await;
    let link = within(space.invite_link_for(
        Claimant::Person,
        Level::Read,
        Duration::from_secs(3600),
        HistoryMode::FromNowOn,
    ))
    .await
    .unwrap();
    until(|| async { space.is_durable().await }).await;
    space.pause_sync();

    let clock = Arc::new(ManualClock::new(1_000, Some(now())));
    let bob = device_at(2, &clock).await;
    let bobs_person = bob.make_person(&[12; 32]).await.unwrap();
    bob.connect(&peer.origin).await.unwrap();
    let bobs_space = within(bob.join(&link, "Bob's browser", |_, _| async { true }))
        .await
        .unwrap();
    until(|| async { bobs_space.is_durable().await }).await;
    // Alice's upkeep collects the list now, and drops it.
    tokio::time::sleep(Duration::from_secs(6)).await;
    space.resume_sync();
    until(|| async {
        space
            .members()
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == bobs_person && m.level == Level::Read)
    })
    .await;
    // Several upkeeps of Alice's device later, it still knows none of
    // Bob's devices: the first hand-over was dropped, and nothing took its
    // place.
    let person = *bobs_person.as_bytes();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        alice.engine().person_devices(&person).await.is_empty(),
        "the first hand-over was dropped"
    );
    // Bob's next slot: the list goes again, and lands.
    clock.advance(31);
    until(|| async { !alice.engine().person_devices(&person).await.is_empty() }).await;
    space.set_level(bobs_person, Level::Write).await.unwrap();
    until(|| async { bobs_space.level().await == Some(Level::Write) }).await;

    alice.close().await.unwrap();
    bob.close().await.unwrap();
    peer.shutdown().await;
}
