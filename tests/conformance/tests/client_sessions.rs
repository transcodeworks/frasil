//! Live sessions between the members of a space, as an application runs
//! them over the ephemeral channel (ext-ephemeral.md), on loopback:
//!
//! - With local discovery on and no peer, two members that another member
//!   admitted find each other (transport.md, "Member announcements") and
//!   hear each other, also once that member is gone.
//! - A device that opens again dials the members it last reached
//!   (transport.md, "Reconnecting"; at-rest.md, `endpoint`), with no peer.
//! - A device without local discovery, as an iPad without the multicast
//!   entitlement, reaches every member through the `Addresses` of the
//!   member that admitted it, keeps hearing them once that member is gone,
//!   and finds a member whose endpoint changed while it was closed
//!   (transport.md, "The iroh binding", member addresses).
//! - A guest learns only the local-network addresses of the members, where
//!   a full member learns their tickets whole; and a false ticket a member
//!   lists is dialed, never kept, and gone after a restart.
//! - Through a peer, every connection comes to relay the channel: a
//!   refused credential is presented again (transport.md, "Presenting
//!   credentials"), 30 newcomers in a row.
//!
//! Every wait has a deadline, and nothing leaves the host.
#![cfg(feature = "ephemeral")]

use frasil::{Device, Level, MemberId, Options, Space, Storage};
use frasil_conformance::spawn_loopback;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_transport::ticket::{Address, Ticket, TicketKind};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// How long a connection may take to carry the channel.
const RELAYED_WITHIN: Duration = Duration::from_secs(15);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8, options: Options) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], options)
        .await
        .expect("a device")
}

/// Admits `newcomer` to `space` by an invitation over a nearby
/// connection; it keeps a member connection with `space`'s device.
async fn admit(space: &Space, newcomer: &Device, name: &str) -> Space {
    let invitation = space
        .invite(Level::Write, "Desk", |_, _| async { true })
        .await
        .unwrap();
    let joined = within(newcomer.join(invitation.text(), name, |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    joined
}

/// `from` sends on its space's ephemeral channel until `to` hears it, as
/// sent by `sender`, within `deadline`: the channel is lossy, and a
/// connection joins it once granted.
async fn hears(from: &Space, to: &Space, sender: MemberId, data: &[u8], deadline: Duration) {
    let mut heard = to.ephemeral().subscribe();
    tokio::time::timeout(deadline, async {
        loop {
            let _ = from.ephemeral().send(data).await;
            if let Ok(Some((who, got))) =
                tokio::time::timeout(Duration::from_millis(100), heard.next()).await
                && who == sender
                && got == data
            {
                return;
            }
        }
    })
    .await
    .expect("heard within the deadline");
}

/// Waits, within the deadline, until `check` holds.
async fn until(mut check: impl FnMut() -> bool) {
    within(async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// The engine's name of a space.
fn event(space: &Space) -> EventId {
    EventId(*space.id().as_bytes())
}

/// A member ticket at these addresses, under an endpoint key no device
/// answers at, and with no relay, so that dialing it leaves no host.
fn ticket_at(seed: u8, addresses: Vec<Address>) -> Ticket {
    Ticket {
        kind: TicketKind::Member,
        endpoint: frasil_crypto::primitives::ed25519_public(&[seed; 32]),
        relays: Vec::new(),
        addresses,
    }
}

/// Admits `member` to `space`, then closes it: `space`'s device keeps a
/// ticket of it, and holds no connection with it.
async fn admitted_and_gone(space: &Space, member: Device, name: &str) -> DeviceId {
    let joined = admit(space, &member, name).await;
    drop(joined);
    let id = member.engine().device_id();
    member.close().await.unwrap();
    id
}

/// A directory of its own for a device's store, removed when dropped.
struct Directory(std::path::PathBuf);

impl Directory {
    fn new(name: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "frasil-sessions-{name}-{}-{unique}",
            std::process::id()
        )))
    }

    async fn open(&self, key: u8) -> Device {
        Device::open_with(
            Storage::directory(&self.0),
            &[key; 32],
            Options::new().loopback().never_restored(),
        )
        .await
        .expect("a device")
    }

    /// Opens a device with local discovery on.
    async fn open_discovering(&self, key: u8) -> Device {
        Device::open_with(
            Storage::directory(&self.0),
            &[key; 32],
            Options::new().loopback().never_restored().local_discovery(),
        )
        .await
        .expect("a device")
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_find_each_other_on_the_local_network_with_no_peer() {
    let options = || Options::new().loopback().local_discovery();
    let desk = device(1, options()).await;
    let space = desk.create_space().await.unwrap();
    let venue = device(2, options()).await;
    let venues = admit(&space, &venue, "Venue").await;
    let booth = device(3, options()).await;
    let booths = admit(&space, &booth, "Booth").await;
    assert!(venue.peers().is_empty() && booth.peers().is_empty());
    // Admission opened member connections from the desk only: the venue
    // and the booth find each other by their announcements.
    hears(&venues, &booths, venue.id(), b"venue", DEADLINE).await;
    hears(&booths, &venues, booth.id(), b"booth", DEADLINE).await;
    // They keep hearing each other once the desk that admitted them is
    // gone, and a document edit syncs between them.
    desk.close().await.unwrap();
    drop(desk);
    hears(&venues, &booths, venue.id(), b"venue, alone", DEADLINE).await;
    hears(&booths, &venues, booth.id(), b"booth, alone", DEADLINE).await;
    let note = venues.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Cue 1"))
        .await
        .unwrap();
    within(async {
        loop {
            if let Ok(theirs) = booths.document(note.id()).await
                && theirs.text("body").await.unwrap() == "Cue 1"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    venue.close().await.unwrap();
    booth.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_dials_its_members_again_when_it_opens_again() {
    let desk_store = Directory::new("desk");
    let crew_store = Directory::new("crew");
    let mut desk = desk_store.open(1).await;
    let space = desk.create_space().await.unwrap();
    let mut crew = crew_store.open(2).await;
    let crews = admit(&space, &crew, "Crew").await;
    let id = space.id();
    // Their member connection carries the channel, and each side keeps
    // where it reached the other.
    hears(&space, &crews, desk.id(), b"before", DEADLINE).await;
    drop(crews);

    // The crew restarts: it dials the desk at the ticket it kept, with no
    // peer and no discovery.
    crew.close().await.unwrap();
    drop(crew);
    crew = crew_store.open(2).await;
    let desks = desk.space(id).await.unwrap();
    let crews = crew.space(id).await.unwrap();
    hears(&desks, &crews, desk.id(), b"after the crew", DEADLINE).await;
    hears(&crews, &desks, crew.id(), b"back", DEADLINE).await;

    // The desk restarts: it dials the crew, which it reached when the crew
    // dialed it.
    desk.close().await.unwrap();
    drop(desks);
    drop(desk);
    desk = desk_store.open(1).await;
    let desks = desk.space(id).await.unwrap();
    hears(&desks, &crews, desk.id(), b"after the desk", DEADLINE).await;
    hears(&crews, &desks, crew.id(), b"back again", DEADLINE).await;

    // An edit made while connected arrives too.
    let note = crews.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Cue 2"))
        .await
        .unwrap();
    within(async {
        loop {
            if let Ok(theirs) = desks.document(note.id()).await
                && theirs.text("body").await.unwrap() == "Cue 2"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    desk.close().await.unwrap();
    crew.close().await.unwrap();
}

/// `a` and `b` each hear the other.
async fn hear_each_other(a: (&Space, MemberId), b: (&Space, MemberId), data: &[u8]) {
    hears(a.0, b.0, a.1, data, DEADLINE).await;
    hears(b.0, a.0, b.1, data, DEADLINE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_local_discovery_reaches_every_member_with_no_peer() {
    let discovering = || Options::new().loopback().local_discovery();
    let desk = device(1, discovering()).await;
    let space = desk.create_space().await.unwrap();
    let venue = device(2, discovering()).await;
    let venues = admit(&space, &venue, "Venue").await;
    let booth = device(3, discovering()).await;
    let booths = admit(&space, &booth, "Booth").await;
    // The iPad sends and receives no local-network packet, as without
    // Apple's multicast entitlement or on a venue network that blocks
    // multicast. Its member connection is with the desk alone.
    let ipad = device(4, Options::new().loopback()).await;
    let ipads = admit(&space, &ipad, "iPad").await;
    assert!(desk.peers().is_empty() && ipad.peers().is_empty());
    // The desk lists the venue and the booth in its `Addresses`: the iPad
    // dials both, and hears every member.
    hear_each_other((&space, desk.id()), (&ipads, ipad.id()), b"desk").await;
    hear_each_other((&venues, venue.id()), (&ipads, ipad.id()), b"venue").await;
    hear_each_other((&booths, booth.id()), (&ipads, ipad.id()), b"booth").await;
    // The desk that admitted it leaves: the iPad keeps hearing the venue
    // and the booth, and an edit syncs to it.
    desk.close().await.unwrap();
    drop(space);
    drop(desk);
    hear_each_other((&venues, venue.id()), (&ipads, ipad.id()), b"venue, alone").await;
    hear_each_other((&booths, booth.id()), (&ipads, ipad.id()), b"booth, alone").await;
    let note = booths.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Cue 3"))
        .await
        .unwrap();
    within(async {
        loop {
            if let Ok(theirs) = ipads.document(note.id()).await
                && theirs.text("body").await.unwrap() == "Cue 3"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    for device in [venue, booth, ipad] {
        device.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_local_discovery_keeps_and_refreshes_member_addresses_across_restarts() {
    let venue_store = Directory::new("venue");
    let ipad_store = Directory::new("ipad");
    let desk = device(1, Options::new().loopback().local_discovery()).await;
    let space = desk.create_space().await.unwrap();
    let id = space.id();
    let mut venue = venue_store.open_discovering(2).await;
    let venues = admit(&space, &venue, "Venue").await;
    let mut ipad = ipad_store.open(3).await;
    let ipads = admit(&space, &ipad, "iPad").await;
    // The iPad reaches the venue through the desk's `Addresses`.
    hear_each_other((&venues, venue.id()), (&ipads, ipad.id()), b"first").await;
    drop((venues, ipads));

    // The iPad closes, and the venue opens again at a new endpoint key:
    // the ticket the iPad keeps of it no longer dials.
    ipad.close().await.unwrap();
    drop(ipad);
    venue.close().await.unwrap();
    drop(venue);
    venue = venue_store.open_discovering(2).await;
    let venues = venue.space(id).await.unwrap();
    hear_each_other((&space, desk.id()), (&venues, venue.id()), b"venue back").await;

    // The iPad opens again: it reaches the desk at the ticket it kept, the
    // desk lists the venue's new ticket, and the iPad dials it.
    ipad = ipad_store.open(3).await;
    let ipads = ipad.space(id).await.unwrap();
    hear_each_other((&venues, venue.id()), (&ipads, ipad.id()), b"refreshed").await;
    drop(ipads);

    // With the desk gone, the iPad opens once more: it dials the venue at
    // the ticket it now keeps, with no peer, no discovery of its own and
    // no other member.
    desk.close().await.unwrap();
    drop(space);
    drop(desk);
    ipad.close().await.unwrap();
    drop(ipad);
    ipad = ipad_store.open(3).await;
    let ipads = ipad.space(id).await.unwrap();
    hear_each_other((&venues, venue.id()), (&ipads, ipad.id()), b"kept").await;
    venue.close().await.unwrap();
    ipad.close().await.unwrap();
}

#[cfg(feature = "ext-guests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_learns_only_the_local_network_addresses_of_the_members() {
    let desk = device(1, Options::new().loopback()).await;
    let space = desk.create_space().await.unwrap();
    let id = event(&space);
    let booth =
        admitted_and_gone(&space, device(2, Options::new().loopback()).await, "Booth").await;
    let lighting = admitted_and_gone(
        &space,
        device(3, Options::new().loopback()).await,
        "Lighting",
    )
    .await;
    // The desk keeps a ticket of each: the booth's with a public address
    // beside a loopback one, the lighting desk's with public addresses
    // alone.
    let public = Address::V4([203, 0, 113, 7], 47_000);
    let loopback = Address::V4([127, 0, 0, 1], 9);
    let booths = ticket_at(0xb0, vec![public, loopback]);
    let mut v6 = [0u8; 16];
    v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    v6[15] = 9;
    let lightings = ticket_at(
        0x11,
        vec![
            Address::V4([198, 51, 100, 9], 47_000),
            Address::V6(v6, 47_000),
        ],
    );
    for (member, ticket) in [(&booth, &booths), (&lighting, &lightings)] {
        desk.engine()
            .remember_endpoint(&id, member, ticket)
            .await
            .unwrap();
    }
    // A full member and a guest join, and the desk tells each where the
    // others are.
    let crew = device(4, Options::new().loopback()).await;
    let _crews = admit(&space, &crew, "Crew").await;
    let guest = device(5, Options::new().loopback()).await;
    let terms = frasil::Guest::new(Level::Write, [5; 16]);
    let invitation = space
        .invite_guest(&terms, "Desk", |_, _| async { true })
        .await
        .unwrap();
    let _guests = within(guest.join(invitation.text(), "Guest", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    // The full member learns both tickets whole, the public addresses
    // included.
    until(|| {
        let held = crew.engine().learned_tickets(&id);
        held.contains(&(booth, booths.clone())) && held.contains(&(lighting, lightings.clone()))
    })
    .await;
    // The guest learns the booth at its loopback address alone, and nothing
    // of the lighting desk, which has no local-network address.
    let narrowed = Ticket {
        addresses: vec![loopback],
        ..booths.clone()
    };
    until(|| {
        guest
            .engine()
            .learned_tickets(&id)
            .contains(&(booth, narrowed.clone()))
    })
    .await;
    let held = guest.engine().learned_tickets(&id);
    assert!(held.iter().all(|(member, _)| *member != lighting));
    assert!(held.iter().all(|(_, ticket)| {
        ticket.relays.is_empty()
            && ticket
                .addresses
                .iter()
                .all(frasil_transport::addresses::local_network)
    }));
    for device in [desk, crew, guest] {
        device.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_false_ticket_a_member_lists_is_never_kept_across_a_restart() {
    let ipad_store = Directory::new("ipad-false-ticket");
    let desk = device(1, Options::new().loopback()).await;
    let space = desk.create_space().await.unwrap();
    let id = event(&space);
    let booth =
        admitted_and_gone(&space, device(2, Options::new().loopback()).await, "Booth").await;
    // The desk lists a false ticket of the booth: an endpoint key no device
    // answers at.
    let false_ticket = ticket_at(0xfa, vec![Address::V4([127, 0, 0, 1], 9)]);
    desk.engine()
        .remember_endpoint(&id, &booth, &false_ticket)
        .await
        .unwrap();
    let mut ipad = ipad_store.open(3).await;
    let ipads = admit(&space, &ipad, "iPad").await;
    // The iPad holds it among its learned tickets and dials it, and keeps
    // only the desk's ticket, at which it reached the desk.
    until(|| {
        ipad.engine()
            .learned_tickets(&id)
            .contains(&(booth, false_ticket.clone()))
    })
    .await;
    let desk_id = desk.engine().device_id();
    let kept = within(async {
        loop {
            let kept = ipad.engine().kept_endpoints(&id).await.unwrap();
            if !kept.is_empty() {
                break kept;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        kept.iter().all(|(member, _)| *member == desk_id),
        "{kept:?}"
    );
    // It opens again: it keeps no ticket of the booth, and dials the desk
    // alone at what it keeps.
    drop(ipads);
    ipad.close().await.unwrap();
    drop(ipad);
    ipad = ipad_store.open(3).await;
    let _ipads = ipad.space(space.id()).await.unwrap();
    let kept = ipad.engine().kept_endpoints(&id).await.unwrap();
    assert!(
        !kept.is_empty()
            && kept
                .iter()
                .all(|(member, ticket)| { *member == desk_id && *ticket != false_ticket }),
        "{kept:?}"
    );
    ipad.close().await.unwrap();
    desk.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_peer_connections_in_a_row_all_relay_ephemeral_messages() {
    let peer = spawn_loopback().await.unwrap();
    for round in 0..30u8 {
        // A space shared with no peer, then kept at one: the desk and its
        // two members connect at once, so that a member may present its
        // state before the desk has stored it there.
        let desk = device(1, Options::new().loopback()).await;
        let space = desk.create_space().await.unwrap();
        let venue = device(2, Options::new().loopback()).await;
        let venues = admit(&space, &venue, "Venue").await;
        let booth = device(3, Options::new().loopback()).await;
        let booths = admit(&space, &booth, "Booth").await;
        let (a, b, c) = tokio::join!(
            desk.connect(&peer.origin),
            venue.connect(&peer.origin),
            booth.connect(&peer.origin)
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        // The venue and the booth meet at the peer, and over the member
        // connection the desk's `Addresses` leads them to.
        let message = [round];
        hears(&venues, &booths, venue.id(), &message, RELAYED_WITHIN).await;
        hears(&booths, &venues, booth.id(), &message, RELAYED_WITHIN).await;
        for device in [desk, venue, booth] {
            device.close().await.unwrap();
        }
    }
    peer.shutdown().await;
}
