//! Admission by code over a nearby connection (admission.md, "The joiner",
//! "The approver", "Accepting a grant", "Nearby pairing"; transport.md,
//! "The iroh binding", nearby pairing).
//!
//! The newcomer dials the host's nearby endpoint (`frasil/p1/nearby`) and
//! writes first. Each message of the exchange travels in a `Pairing` frame
//! of the connection's one stream, and both codes bind the connection's
//! exporter, so a party in the middle, which holds two sessions, makes the
//! two codes differ.
//!
//! - **The host** ([`host_pairing`]) answers the Request with its
//!   `Approver`, shows the code, and once its person confirms that the
//!   newcomer's screen shows the same, signs the grant (`via` = `code`)
//!   and sends the Result, a welcome with a member ticket beside it in the
//!   same `Pairing` frame (transport.md, "Messages"), then the space's
//!   events as `Sync` frames on an object stream scoped by the
//!   space.
//! - **The newcomer** ([`join_nearby`]) runs its `Joiner`, shows the code,
//!   opens the welcome's wrap, and checks the admitting event, steps 1 to 6
//!   of "Accepting a grant"; step 7 is its own resolution of the space,
//!   which must find the event valid. Nothing on the nearby connection
//!   admits it to anything by itself: it then dials the member ticket.

use crate::device::Engine;
use crate::error::{Error, Result};
use frasil_admission::approver::{ApproverSide, ResponseDraw};
use frasil_admission::grant::grant_change;
use frasil_admission::joiner::{JoinerKeys, JoinerStart, expires_at};
use frasil_admission::welcome::Welcome;
use frasil_admission::{Approver, Code, Ctx, Joiner, Offer};
use frasil_events::EventId;
use frasil_iroh::{Connection, FrameReceiver, FrameSender, Stream};
use frasil_transport::Code as Close;
use frasil_transport::frame::{ConnectionKind, MessageType};
use frasil_transport::messages::{Pairing, Scope, Sync};
use frasil_transport::ticket::{Ticket, TicketKind};
use frasil_units::messages::{Message as UnitsMessage, SyncMessage};

/// What a newcomer holds once admitted.
#[derive(Debug, Clone)]
pub struct Joined {
    /// The space.
    pub space: EventId,
    /// The admitting event.
    pub admitting: EventId,
    /// The member ticket the host handed over, to dial next.
    pub ticket: Ticket,
    /// The code both screens showed.
    pub code: Code,
}

fn failed(error: impl core::fmt::Display) -> Error {
    Error::Connection(error.to_string())
}

fn wall(device: &Engine) -> Option<u64> {
    device.platform().clock.wall()
}

async fn next_frame(receiver: &mut FrameReceiver) -> Result<Pairing> {
    loop {
        let Some(message) = receiver.receive().await.map_err(failed)? else {
            return Err(Error::Connection("the nearby connection ended".into()));
        };
        if message.kind == MessageType::Pairing {
            return Pairing::read(&message).map_err(Error::class);
        }
    }
}

async fn next_pairing(receiver: &mut FrameReceiver) -> Result<Vec<u8>> {
    Ok(next_frame(receiver).await?.message)
}

pub(crate) async fn send_frame(
    sender: &mut FrameSender,
    message: Vec<u8>,
    ticket: Option<String>,
) -> Result<()> {
    sender
        .send(&Pairing { message, ticket }.encode())
        .await
        .map_err(failed)
}

async fn send_pairing(sender: &mut FrameSender, message: Vec<u8>) -> Result<()> {
    send_frame(sender, message, None).await
}

/// Hosts one admission exchange on a nearby connection the newcomer
/// dialed: grants the newcomer `offer` in `space` once `confirm` says the
/// person saw the same code on both screens. `confirm` is given the code
/// and the newcomer's display text. `ticket` is the member ticket handed
/// over with the welcome.
///
/// # Errors
///
/// admission.md's classes; [`Error::NotAllowed`] unless this device
/// administers the space; the connection's failure.
pub async fn host_pairing<F>(
    device: &Engine,
    connection: &Connection,
    space: EventId,
    offer: Offer,
    display: &str,
    ticket: &Ticket,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<EventId>
where
    F: std::future::Future<Output = bool>,
{
    // This flow carries no rank: it admits at most `write`, and an
    // explicit raise at a rank follows (roster.md, 2.3 Changes, "Ranks").
    if offer.level == frasil_space::Level::Administer {
        return Err(Error::Invalid(
            "nearby admission grants at most write; raise the member at a rank after",
        ));
    }
    let (mut sender, mut receiver) = connection.control().await.map_err(failed)?;
    let heads = device
        .read(&space, |replica| {
            let mut heads = replica.citable_heads();
            heads.sort_unstable();
            heads.truncate(256);
            heads
        })
        .await?;
    let mut approver = Approver::new(ApproverSide {
        approver: device.device_id(),
        ctx: Ctx::Space,
        log: space.0,
        heads,
        offer: offer.encode(),
        display: display.to_owned(),
        channel: connection.channel().to_vec(),
    })
    .map_err(Error::class)?;
    let request = next_pairing(&mut receiver).await?;
    let platform = device.platform();
    let response = approver
        .on_request_with(
            &request,
            wall(device),
            ResponseDraw {
                nonce: platform.draw()?,
                eph_seed: platform.draw()?,
                encapsulation: platform.draw()?,
            },
        )
        .map_err(Error::class)?;
    send_pairing(&mut sender, response).await?;
    let reveal = next_pairing(&mut receiver).await?;
    let approved = approver
        .on_reveal(&reveal, wall(device))
        .map_err(Error::class)?
        .ok_or(Error::Class("Replayed"))?;
    if !confirm(
        approved.code.to_string(),
        approved.reveal.display().to_owned(),
    )
    .await
    {
        let cancel = approver.cancel(&approved.request);
        send_pairing(&mut sender, cancel).await?;
        return Err(Error::Class("Mismatch"));
    }
    let change = grant_change(&offer, &approved.reveal).map_err(Error::class)?;
    let Some(joiner) = change.member.and_then(|member| member.device_id()) else {
        return Err(Error::Class("Malformed"));
    };
    // The revealed keys, which the code authenticated by their device ID,
    // are a source of keys for every check (crypto.md, "Keys by their
    // hash").
    if let Some(keys) = change.keys.as_deref() {
        device.learn_keys(keys.clone()).await?;
    }
    if !device.reaches_parent_of(&space, &joiner).await {
        let cancel = approver.cancel(&approved.request);
        send_pairing(&mut sender, cancel).await?;
        return Err(Error::NotAllowed(
            "the newcomer does not reach the restricted space's parent",
        ));
    }
    let (admitting, wraps) = device.sign_roster_with(space, vec![change]).await?;
    let wrap = wraps.get(&joiner).ok_or(Error::NotAllowed(
        "the grant delivered nothing to the newcomer",
    ))?;
    let snapshot = snapshot_for(device, &offer, space, admitting).await?;
    let welcome = welcome_for(device, space, admitting, wrap, &snapshot).await;
    let result = approver
        .result_with(
            &approved.request,
            &welcome.encode(),
            wall(device),
            &*platform.draw::<64>()?,
        )
        .map_err(Error::class)?;
    // The member ticket travels beside the welcome, in its frame.
    let ticket = ticket.encode().map_err(Error::class)?;
    send_frame(&mut sender, result, Some(ticket)).await?;
    hand_over(device, connection, &mut receiver, space, snapshot).await?;
    Ok(admitting)
}

/// From now on: the newcomer's snapshot, published and named in the
/// welcome, and handed over the connection (admission.md, "The newcomer's
/// snapshot"). A guest that keeps nothing at rest takes it over the
/// connection only, never from a peer (ext-guests.md, "Admitting a
/// guest").
async fn snapshot_for(
    device: &Engine,
    offer: &Offer,
    space: EventId,
    admitting: EventId,
) -> Result<
    Option<(
        crate::snapshots::NewcomerSnapshot,
        Option<frasil_adapter::Locator>,
    )>,
> {
    if offer.history != frasil_space::HistoryMode::FromNowOn {
        return Ok(None);
    }
    let made = device.newcomer_snapshot(&space, admitting).await?;
    let locator = if crate::admitting::keeps_nothing_at_rest(offer) {
        None
    } else {
        let (locator, _) = device
            .publish_newcomer_snapshot(&space, admitting, &made)
            .await?;
        Some(locator)
    };
    Ok(Some((made, locator)))
}

/// The welcome a newcomer is handed: the admitting event, its wrap, the
/// space's peers, home peer first, and the snapshot's locator.
async fn welcome_for(
    device: &Engine,
    space: EventId,
    admitting: EventId,
    wrap: &crate::writer::WrapOf,
    snapshot: &Option<(
        crate::snapshots::NewcomerSnapshot,
        Option<frasil_adapter::Locator>,
    )>,
) -> Welcome {
    Welcome {
        space: space.0,
        event: admitting,
        key_name: wrap.key_name.encode(),
        grant_name: wrap
            .grant_name
            .as_ref()
            .map(|n| n.encode())
            .unwrap_or_default(),
        wrap: wrap.wrap.clone(),
        approver: device.device_id(),
        peers: device.welcome_hints(&space, &[]).await,
        snapshot: snapshot.as_ref().and_then(|(_, locator)| *locator),
    }
}

/// Hands the newcomer the space on an object stream: with history, the
/// space's events; from now on, the space snapshot, the objects it names,
/// and the events the newcomer holds in full, every one but the units
/// before its base. Waits for the newcomer to close.
async fn hand_over(
    device: &Engine,
    connection: &Connection,
    receiver: &mut FrameReceiver,
    space: EventId,
    snapshot: Option<(
        crate::snapshots::NewcomerSnapshot,
        Option<frasil_adapter::Locator>,
    )>,
) -> Result<()> {
    let mut object = connection
        .open_object(Scope::Space(space.0))
        .await
        .map_err(failed)?;
    let mut messages = Vec::new();
    let mut events = device.events(&space).await;
    if let Some((snapshot, _)) = snapshot {
        messages.push(SyncMessage {
            space,
            message: UnitsMessage::SnapshotOffer {
                snapshot: snapshot.signed.clone(),
            },
        });
        for part in snapshot.parts() {
            messages.push(SyncMessage {
                space,
                message: UnitsMessage::ObjectChunks {
                    locator: part.locator,
                    header: part.header,
                    index: part.index,
                    chunk: part.chunk,
                },
            });
        }
        events.retain(|signed| {
            frasil_events::decode(signed).is_ok_and(|e| e.kind() != frasil_events::kind::UNIT)
        });
    }
    messages.extend(events_messages(space, events));
    for message in messages {
        object
            .send(
                &Sync {
                    scope: Scope::Space(space.0),
                    message: message.encode(),
                }
                .encode(),
            )
            .await
            .map_err(failed)?;
    }
    object.finish().map_err(failed)?;
    // The newcomer closes the connection once it has read everything.
    let _ = receiver.receive().await;
    Ok(())
}

/// What a device set up by a setup code holds once provisioned.
#[derive(Debug, Clone)]
pub struct Provisioned {
    /// The space.
    pub space: EventId,
    /// The admitting event.
    pub admitting: EventId,
    /// The member ticket the administrator handed over, to dial next.
    pub ticket: Ticket,
}

/// The administrator's side of setup (admission.md, "Setup"), on a nearby
/// connection it dialed to the device whose setup code it scanned: the
/// device, the listener, opens the control stream and writes its Hello
/// first. The Hello must match the scanned keys digest; the administrator
/// sends the Offer, MACed over this connection's channel, then grants the
/// device `offer` with `via` = code and sends the Result, the newcomer's
/// snapshot and `ticket`. Returns the admitting event.
///
/// # Errors
///
/// `SetupMismatch`, `InvalidKey`, `BadPossession` and the message's
/// classes; [`Error::NotAllowed`] unless this device administers the space;
/// the connection's failure.
pub async fn administer_setup(
    device: &Engine,
    connection: &Connection,
    space: EventId,
    offer: Offer,
    scanned: &frasil_admission::setup::SetupCode,
    display: &str,
    ticket: &Ticket,
) -> Result<EventId> {
    use frasil_admission::setup::{SetupAnswer, check_hello, offer_message_with, read_hello};
    // This flow carries no rank: it admits at most `write`, and an
    // explicit raise at a rank follows (roster.md, 2.3 Changes, "Ranks").
    if offer.level == frasil_space::Level::Administer {
        return Err(Error::Invalid(
            "nearby admission grants at most write; raise the member at a rank after",
        ));
    }
    let (mut sender, mut receiver) = connection.accept_control().await.map_err(failed)?;
    let hello = next_pairing(&mut receiver).await?;
    let (request, hello) = read_hello(&hello).map_err(Error::class)?;
    // The Hello's keys give the device ID the scanned code carries
    // (admission.md, "Setup").
    let keys = check_hello(scanned, &hello).map_err(Error::class)?;
    device.learn_keys(keys.clone()).await?;
    let heads = device
        .read(&space, |replica| {
            let mut heads = replica.citable_heads();
            heads.sort_unstable();
            heads.truncate(256);
            heads
        })
        .await?;
    let platform = device.platform();
    let (offer_message, _) = offer_message_with(
        scanned,
        &request,
        &hello,
        &SetupAnswer {
            approver: device.device_id(),
            log: space.0,
            heads,
            offer: &offer,
            display: display.to_owned(),
            eph_seed: platform.draw()?,
            channel: &connection.channel(),
        },
        &*platform.draw::<64>()?,
    )
    .map_err(Error::class)?;
    send_pairing(&mut sender, offer_message).await?;
    // A device grant with the offer's fields and `via` = code, carrying the
    // device's three keys (roster.md, "A device's keys").
    let joiner = keys.device_id();
    let mut change = frasil_space::Change::grant_device(
        keys,
        offer.level,
        offer.history,
        frasil_space::Via::Code,
    );
    change.capabilities = offer.capabilities.clone();
    change.label = offer.label.clone();
    change.session = offer.session;
    change.replaces = offer.replaces;
    change.expires_at = offer.expires_at();
    let (admitting, wraps) = device.sign_roster_with(space, vec![change]).await?;
    let wrap = wraps.get(&joiner).ok_or(Error::NotAllowed(
        "the grant delivered nothing to the device",
    ))?;
    let snapshot = snapshot_for(device, &offer, space, admitting).await?;
    let welcome = welcome_for(device, space, admitting, wrap, &snapshot).await;
    let result = frasil_admission::message::sealed_message_with(
        frasil_admission::MessageType::Result,
        &request,
        &hello.eph[..],
        &welcome.encode(),
        &*platform.draw::<64>()?,
    )
    .map_err(Error::class)?;
    let ticket = ticket.encode().map_err(Error::class)?;
    send_frame(&mut sender, result, Some(ticket)).await?;
    hand_over(device, connection, &mut receiver, space, snapshot).await?;
    Ok(admitting)
}

/// The device's side of setup (admission.md, "Setup"), on a nearby
/// connection the administrator dialed: as the listener, it opens the
/// control stream and writes its Hello first, binds to the Offer whose MAC
/// verifies over this connection's channel, then takes the Result, the
/// snapshot and the space, and checks the grant ("Accepting a grant", with
/// the Offer in place of the Response). A match provisions `headless`.
///
/// # Errors
///
/// `Provisioned`, `BadMac` and admission.md's classes; the connection's
/// failure.
pub async fn serve_setup(
    device: &Engine,
    connection: &Connection,
    headless: &mut frasil_admission::setup::HeadlessDevice,
) -> Result<Provisioned> {
    let (mut sender, mut receiver) = connection.open_control().await.map_err(failed)?;
    send_pairing(&mut sender, headless.hello()).await?;
    let offer = next_pairing(&mut receiver).await?;
    let body = headless
        .on_offer(&offer, &connection.channel())
        .map_err(Error::class)?
        .clone();
    let frame = next_frame(&mut receiver).await?;
    let read = frasil_admission::message::read_message(&frame.message).map_err(Error::class)?;
    if read.kind != frasil_admission::MessageType::Result || read.request != *headless.request() {
        return Err(Error::Class("Malformed"));
    }
    let plaintext = frasil_admission::message::open_body(
        frasil_admission::MessageType::Result,
        &read.request,
        headless.eph_seed(),
        read.body,
    )
    .map_err(Error::class)?;
    let welcome = Welcome::read(&plaintext).map_err(Error::class)?;
    let ticket = frame
        .ticket
        .as_deref()
        .ok_or(Error::Class("Malformed"))
        .and_then(|text| Ticket::read(text).map_err(Error::class))?;
    if ticket.kind != TicketKind::Member || welcome.space != body.log {
        return Err(Error::Class("Malformed"));
    }
    let space = EventId(body.log);
    crate::admitting::keep_as_offered(device, space, &body.offer).await?;
    let received = receive_snapshot(connection, space).await?;
    device.follow(space).await;
    if let Some(snapshot) = &received.snapshot {
        device
            .adopt_snapshot(space, snapshot, received.parts.clone())
            .await?;
    }
    device.ingest(space, received.events).await?;
    // "Accepting a grant", with the Offer in place of the Response.
    let host = frasil_admission::bodies::ResponseBody {
        nonce: Default::default(),
        log: body.log,
        heads: body.heads.clone(),
        approver: body.approver,
        eph: body.eph.clone(),
        offer: body.offer.clone(),
        display: body.display.clone(),
    };
    crate::admitting::accept_grant(device, &welcome, &host).await?;
    headless.provision();
    connection.close(Close::Done);
    Ok(Provisioned {
        space,
        admitting: welcome.event,
        ticket,
    })
}

/// `Events` messages carrying these signed events, within the limits.
pub(crate) fn events_messages(space: EventId, events: Vec<Vec<u8>>) -> Vec<SyncMessage> {
    let mut out = Vec::new();
    let mut batch = Vec::new();
    let mut size = 64;
    for event in events {
        if !batch.is_empty()
            && (size + event.len() + 8 > frasil_units::limits::MAX_MESSAGE_BYTES
                || batch.len() == frasil_units::limits::MAX_MESSAGE_ITEMS)
        {
            out.push(SyncMessage {
                space,
                message: UnitsMessage::Events {
                    events: std::mem::take(&mut batch),
                },
            });
            size = 64;
        }
        size += event.len() + 8;
        batch.push(event);
    }
    if !batch.is_empty() {
        out.push(SyncMessage {
            space,
            message: UnitsMessage::Events { events: batch },
        });
    }
    out
}

/// Joins a space through a host's nearby endpoint this device dialed:
/// runs the exchange as the joiner, and once `confirm` says the person
/// saw the same code on both screens, checks the grant and its own
/// resolution of the space. `confirm` is given the code and the host's
/// display text.
///
/// # Errors
///
/// admission.md's classes; the connection's failure.
pub async fn join_nearby<F>(
    device: &Engine,
    connection: &Connection,
    display: &str,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<Joined>
where
    F: std::future::Future<Output = bool>,
{
    let (mut sender, mut receiver) = connection.control().await.map_err(failed)?;
    let platform = device.platform();
    let now = wall(device).ok_or(Error::Class("Expired"))?;
    let (mut joiner, request) = Joiner::start_with(
        JoinerStart {
            ctx: Ctx::Space,
            request: platform.nonce()?,
            expires_at: expires_at(now),
            nonce: platform.draw()?,
            eph_seed: platform.draw()?,
            display: display.to_owned(),
            channel: connection.channel().to_vec(),
        },
        JoinerKeys::Device {
            signer: device.signer(),
        },
    )
    .map_err(Error::class)?;
    send_pairing(&mut sender, request).await?;
    let response = next_pairing(&mut receiver).await?;
    let revealed = joiner
        .on_response_with(
            &response,
            wall(device).unwrap_or(now),
            &*platform.draw::<64>()?,
        )
        .ok_or(Error::Class("Malformed"))?;
    send_pairing(&mut sender, revealed.message.clone()).await?;
    let host = joiner
        .response()
        .cloned()
        .ok_or(Error::Class("Malformed"))?;
    if !confirm(revealed.code.to_string(), host.display.clone()).await {
        send_pairing(&mut sender, joiner.cancel()).await?;
        return Err(Error::Class("Mismatch"));
    }
    let frame = next_frame(&mut receiver).await?;
    let plaintext = joiner.open_result(&frame.message).map_err(Error::class)?;
    let welcome = Welcome::read(&plaintext).map_err(Error::class)?;
    // The member ticket beside the welcome: a member ticket, never another
    // kind.
    let ticket = frame
        .ticket
        .as_deref()
        .ok_or(Error::Class("Malformed"))
        .and_then(|text| Ticket::read(text).map_err(Error::class))?;
    if ticket.kind != TicketKind::Member {
        return Err(Error::Class("Malformed"));
    }
    let space = EventId(host.log);
    if welcome.space != host.log {
        return Err(Error::Class("WrongSpace"));
    }
    // A guest that keeps nothing at rest keeps the space in memory only
    // before anything of it is adopted (ext-guests.md, "Nothing at rest").
    crate::admitting::keep_as_offered(device, space, &host.offer).await?;
    // The space's events, on the object stream the host opened.
    let received = receive_snapshot(connection, space).await?;
    device.follow(space).await;
    if let Some(snapshot) = &received.snapshot {
        device
            .adopt_snapshot(space, snapshot, received.parts.clone())
            .await?;
    }
    device.ingest(space, received.events).await?;
    crate::admitting::accept_grant(device, &welcome, &host).await?;
    connection.close(Close::Done);
    Ok(Joined {
        space,
        admitting: welcome.event,
        ticket,
        code: revealed.code,
    })
}

/// What a host hands a newcomer on the nearby connection's object stream.
#[derive(Debug, Default)]
pub(crate) struct Received {
    pub(crate) snapshot: Option<Vec<u8>>,
    pub(crate) parts: Vec<crate::snapshots::ObjectPart>,
    pub(crate) events: Vec<Vec<u8>>,
}

pub(crate) async fn receive_snapshot(connection: &Connection, space: EventId) -> Result<Received> {
    let mut receiver = loop {
        match connection.accept_stream().await.map_err(failed)? {
            Stream::Object {
                scope: Scope::Space(scoped),
                receiver,
            } if scoped == space.0 => break receiver,
            _ => continue,
        }
    };
    let mut received = Received::default();
    while let Some(message) = receiver.receive().await.map_err(failed)? {
        let sync = Sync::read(&message, ConnectionKind::Nearby).map_err(Error::class)?;
        let Some(units) = crate::intake::read_sync(&sync.message).map_err(Error::Class)? else {
            continue;
        };
        if units.space != space {
            return Err(Error::Class("Malformed"));
        }
        match units.message {
            UnitsMessage::Events { events } => received.events.extend(events),
            UnitsMessage::SnapshotOffer { snapshot } => received.snapshot = Some(snapshot),
            UnitsMessage::ObjectChunks {
                locator,
                header,
                index,
                chunk,
            } => received.parts.push(crate::snapshots::ObjectPart {
                locator,
                header,
                index,
                chunk,
            }),
            _ => {}
        }
    }
    Ok(received)
}

/// The offer a client makes a device member by default: "from now on"
/// (roster.md, "Changes": clients default to "with history" for a person,
/// and to "from now on" for a device member and a guest).
pub fn default_offer(level: frasil_space::Level) -> Offer {
    Offer::new(level, frasil_space::HistoryMode::FromNowOn)
}
