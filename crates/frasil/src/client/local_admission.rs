//! A person's new device, admitted by code over a direct connection with no
//! peer (admission.md, "A person's new device", "Over a direct
//! connection"): two applications on one machine, or two machines on a
//! local network.
//!
//! A device of the person hosts: [`Device::invite_device`] shows its nearby
//! endpoint's ticket as a [`DeviceInvitation`]. The new device enters it in
//! [`Device::join_person`], dials, and runs the joiner with ctx `0x01` over
//! that connection, whose channel both codes bind. Both compare the same
//! six-digit code; while one side waits for its person, it still reads the
//! other's messages and stops at a Cancel. On a match the host signs an
//! `add` of the new device in the person's list and sends the Result, the
//! list's events. It then hands over each space it writes in that grants
//! the person: a Welcome naming the delivery that reaches the new device,
//! with the host's member ticket beside it, then the space's events on an
//! object stream. The new device checks the list, takes the person, keeps
//! its keys sealed again under its unlock key, checks each Welcome and its
//! own resolution of each space, closes the connection, and dials the
//! member ticket. No mailbox and no peer take part.

use super::{Device, Space, SpaceId};
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::pairing::{events_messages, receive_snapshot, send_frame};
use frasil_admission::approver::{ApproverSide, ResponseDraw};
use frasil_admission::bodies::{ListEvents, RevealBody};
use frasil_admission::joiner::{JoinerKeys, JoinerStart, expires_at};
use frasil_admission::message::read_message;
use frasil_admission::new_device::check_list_result;
use frasil_admission::welcome::Welcome;
use frasil_admission::{Approver, Ctx, Joiner, MessageType};
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_identity::PublicKeys;
use frasil_iroh::{Config, Connection, Endpoint, FrameReceiver, FrameSender};
use frasil_space::Status;
use frasil_store::store::MaybeSend;
use frasil_transport::Code as Close;
use frasil_transport::frame::MessageType as FrameType;
use frasil_transport::messages::{Pairing, Scope, Sync};
use frasil_transport::ticket::{Ticket, TicketKind};
use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How long a side that sent a Cancel, or finished its stream, waits for
/// the other to close the connection, so that what it sent arrives.
const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// An invitation for one of the person's new devices, waiting for it.
#[derive(Debug)]
pub struct DeviceInvitation {
    text: String,
    done: oneshot::Receiver<Result<()>>,
}

impl DeviceInvitation {
    /// The text the new device enters in [`Device::join_person`]: show it,
    /// or a QR code of it, or hand it to the other application over local
    /// IPC. It names this device's endpoint, not the person, and admits no
    /// one by itself.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Waits until the new device is on the person's list and has been
    /// handed the person's spaces.
    ///
    /// # Errors
    ///
    /// `Mismatch` when this device's person did not confirm the code;
    /// `Cancelled` when the new device cancelled; `Expired`; the
    /// connection's failure; [`Error::Connection`] when the device closed,
    /// or hosted another pairing, before a new device came.
    pub async fn admitted(self) -> Result<()> {
        self.done
            .await
            .map_err(|_| Error::Connection("the device closed before a new device came".into()))?
    }
}

impl Device {
    /// Invites a new device of this device's person over a direct
    /// connection, with no peer (admission.md, "A person's new device",
    /// "Over a direct connection"): another application on this machine,
    /// or a machine on the same local network. The invitation's
    /// [`text`](DeviceInvitation::text) goes to the new device, which
    /// enters it in [`Device::join_person`]. Both then show the same
    /// six-digit admission code: `confirm` is given the code and the new
    /// device's name, and its future says whether the code is the same on
    /// both, as this device's person saw it, or as two applications on one
    /// machine compared it between themselves over local IPC that
    /// authenticates both. `name` is what the new device shows for this
    /// device.
    ///
    /// The new device then reaches every space this device writes in that
    /// grants the person, as the person's grant there says. A device hosts
    /// one invitation at a time; a new one replaces the last, of either
    /// kind.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; [`Error::Connection`]
    /// when its endpoint does not bind.
    pub async fn invite_device<F>(
        &self,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<DeviceInvitation>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        if self.engine().person().await.is_none() {
            return Err(Error::NotAllowed("the device is no person's"));
        }
        let node = self.node().await?;
        let text = node
            .ticket(TicketKind::Nearby)
            .encode()
            .map_err(Error::class)?;
        let (finished, done) = oneshot::channel();
        let engine = self.engine().clone();
        let name = name.to_owned();
        node.host_nearby(Box::new(move |node, connection| {
            Box::pin(async move {
                let ticket = node.ticket(TicketKind::Member);
                let result = host(&engine, &connection, &name, &ticket, confirm).await;
                let _ = finished.send(result);
            })
        }));
        Ok(DeviceInvitation { text, done })
    }

    /// Joins `person` as its new device over a direct connection, with no
    /// peer (admission.md, "A person's new device", "Over a direct
    /// connection"): `text` is the [`DeviceInvitation::text`] a device of
    /// the person shows. A device of another person adds this device to no
    /// list: this device refuses its answer before it reveals anything
    /// (admission.md, 3.1 The joiner, step 5). Both then
    /// show the same six-digit admission code: `confirm` is given the code
    /// and the other device's name, and its future says whether the code
    /// is the same on both. `name` is what the other device shows for this
    /// one. `unlock_key` is the key this device was opened with: once
    /// admitted, its keys are sealed again under it to name the person, and
    /// kept as [`Device::make_person`] keeps them.
    ///
    /// Returns the person's spaces the other device handed over;
    /// [`Device::person`] is the person from then on. The device keeps a
    /// member connection with the other device for those spaces.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of a person already;
    /// [`Error::Invalid`] for text that is no device invitation; `BadSeal`
    /// when `unlock_key` does not open this device's keys; `WrongPerson`
    /// when a device of another person than `person` answered; `Mismatch` when
    /// this device's person did not confirm the code; `Cancelled` when the
    /// other device cancelled; the list's classes (`WrongPerson`,
    /// `WrongMember`, `WrongApprover`, `NotFollowing`, `NotInList`); a
    /// Welcome's classes and each space's verdict; [`Error::Connection`]
    /// when the other device is not reachable.
    pub async fn join_person<F>(
        &self,
        text: &str,
        person: super::PersonId,
        name: &str,
        unlock_key: &[u8; 32],
        confirm: impl FnOnce(String, String) -> F,
    ) -> Result<Vec<Space>>
    where
        F: Future<Output = bool>,
    {
        if self.engine().person().await.is_some() {
            return Err(Error::NotAllowed("the device is already a person's"));
        }
        self.check_unlock_key(unlock_key)?;
        let ticket = Ticket::read(text.trim())
            .ok()
            .filter(|ticket| ticket.kind == TicketKind::Nearby)
            .ok_or(Error::Invalid(
                "a device invitation is the text that another device's \
                 Device::invite_device shows",
            ))?;
        let node = self.node().await?;
        // A fresh endpoint key per pairing session (transport.md, "Endpoint
        // keys"), on loopback alone when the device's options say so.
        let key = self.engine().platform().nonce::<32>()?;
        let config = Config::new(key, &[]);
        let config = if self.inner.loopback {
            config.loopback()
        } else {
            config
        };
        let dialer = Endpoint::bind(config).await.map_err(failed)?;
        let joined = match dialer.dial(&ticket).await {
            Ok(connection) => {
                join(
                    self,
                    &connection,
                    *person.as_bytes(),
                    name,
                    unlock_key,
                    confirm,
                )
                .await
            }
            Err(error) => Err(failed(error)),
        };
        dialer.close().await;
        let (spaces, member) = joined?;
        if let Some(member) = member
            && !spaces.is_empty()
        {
            node.dial(&member, spaces.clone()).await?;
        }
        Ok(spaces
            .into_iter()
            .map(|space| {
                self.present(space);
                Space::new(self.clone(), SpaceId::of(space))
            })
            .collect())
    }
}

fn failed(error: impl core::fmt::Display) -> Error {
    Error::Connection(error.to_string())
}

/// Frames read ahead of the exchange, or held while a person decides, at
/// most; the exchange needs a few, so a side that sends more is refused.
const FRAMES_AHEAD: usize = 8;

/// The nearby stream's frames, read as they come by a task of their own,
/// so that a side waiting for its person still sees the other's Cancel.
struct Incoming {
    frames: mpsc::Receiver<Result<Pairing>>,
    held: VecDeque<Pairing>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Incoming {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Incoming {
    fn new(mut receiver: FrameReceiver) -> Self {
        let (sender, frames) = mpsc::channel(FRAMES_AHEAD);
        let reader = tokio::spawn(async move {
            loop {
                let frame = match receiver.receive().await {
                    Ok(Some(message)) if message.kind == FrameType::Pairing => {
                        Pairing::read(&message).map_err(Error::class)
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) => return,
                    Err(error) => Err(failed(error)),
                };
                let ended = frame.is_err();
                if sender.send(frame).await.is_err() || ended {
                    return;
                }
            }
        });
        Self {
            frames,
            held: VecDeque::new(),
            reader,
        }
    }

    /// The next frame, or `None` once the other side finished the stream.
    async fn next_or_end(&mut self) -> Result<Option<Pairing>> {
        if let Some(frame) = self.held.pop_front() {
            return Ok(Some(frame));
        }
        self.frames.recv().await.transpose()
    }

    /// The next frame; the other's Cancel ends the exchange.
    async fn next(&mut self) -> Result<Pairing> {
        let frame = self
            .next_or_end()
            .await?
            .ok_or_else(|| Error::Connection("the nearby connection ended".into()))?;
        if is_cancel(&frame) {
            return Err(Error::Class("Cancelled"));
        }
        Ok(frame)
    }

    /// Waits for the person's decision while reading on: a Cancel ends the
    /// exchange; any other frame is held for later.
    async fn decided(&mut self, decision: impl Future<Output = bool>) -> Result<bool> {
        let mut decision = std::pin::pin!(decision);
        let agreed = loop {
            tokio::select! {
                agreed = &mut decision => break agreed,
                frame = self.frames.recv() => match frame {
                    Some(Ok(frame)) if is_cancel(&frame) => {
                        return Err(Error::Class("Cancelled"));
                    }
                    Some(Ok(frame)) => self.hold(frame)?,
                    Some(Err(error)) => return Err(error),
                    None => return Err(Error::Connection("the nearby connection ended".into())),
                },
            }
        };
        // A Cancel that came while the decision resolved.
        while let Ok(frame) = self.frames.try_recv() {
            let frame = frame?;
            if is_cancel(&frame) {
                return Err(Error::Class("Cancelled"));
            }
            self.hold(frame)?;
        }
        Ok(agreed)
    }

    /// Holds a frame for later: `Malformed` past [`FRAMES_AHEAD`].
    fn hold(&mut self, frame: Pairing) -> Result<()> {
        if self.held.len() >= FRAMES_AHEAD {
            return Err(Error::Class("Malformed"));
        }
        self.held.push_back(frame);
        Ok(())
    }

    /// Waits, a little, for the other side to close or finish.
    async fn closed(&mut self) {
        let _ = tokio::time::timeout(CLOSE_DEADLINE, async {
            while let Some(Ok(_)) = self.frames.recv().await {}
        })
        .await;
    }
}

fn is_cancel(frame: &Pairing) -> bool {
    read_message(&frame.message).is_ok_and(|read| read.kind == MessageType::Cancel)
}

async fn send(sender: &mut FrameSender, message: Vec<u8>) -> Result<()> {
    send_frame(sender, message, None).await
}

/// Sends the Cancel, and waits for the other side to close.
async fn cancel(sender: &mut FrameSender, incoming: &mut Incoming, message: Vec<u8>) {
    if send(sender, message).await.is_ok() {
        incoming.closed().await;
    }
}

/// The host: the approver with ctx `0x01`, on the connection the new device
/// dialed (admission.md, "The approver", "A person's new device").
async fn host<F>(
    engine: &Engine,
    connection: &Connection,
    display: &str,
    ticket: &Ticket,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<()>
where
    F: Future<Output = bool>,
{
    let person = engine
        .person()
        .await
        .ok_or(Error::NotAllowed("the device is no person's"))?;
    let (mut sender, receiver) = connection.control().await.map_err(failed)?;
    let mut incoming = Incoming::new(receiver);
    let mut heads = engine.list_heads(&person).await;
    heads.sort_unstable();
    heads.truncate(256);
    let mut approver = Approver::new(ApproverSide {
        approver: engine.device_id(),
        ctx: Ctx::DeviceList,
        log: person,
        heads,
        offer: Vec::new(),
        display: display.to_owned(),
        channel: connection.channel().to_vec(),
    })
    .map_err(Error::class)?;
    let platform = engine.platform();
    let wall = || platform.clock.wall();
    let request = incoming.next().await?;
    let response = approver
        .on_request_with(
            &request.message,
            wall(),
            ResponseDraw {
                nonce: platform.draw()?,
                eph_seed: platform.draw()?,
                encapsulation: platform.draw()?,
            },
        )
        .map_err(Error::class)?;
    send(&mut sender, response).await?;
    let reveal = incoming.next().await?;
    let approved = approver
        .on_reveal(&reveal.message, wall())
        .map_err(Error::class)?
        .ok_or(Error::Class("Replayed"))?;
    let agreed = incoming
        .decided(confirm(
            approved.code.to_string(),
            approved.reveal.display().to_owned(),
        ))
        .await?;
    if !agreed {
        let message = approver.cancel(&approved.request);
        cancel(&mut sender, &mut incoming, message).await;
        return Err(Error::Class("Mismatch"));
    }
    // Once the person approved, the new device waits for the Result: a
    // failure on the way to it ends the exchange with a Cancel.
    let added = async {
        let RevealBody::Device {
            keys, possession, ..
        } = &approved.reveal
        else {
            return Err(Error::Class("Malformed"));
        };
        // The keys the code authenticated by their device ID, and the
        // device's possession proof for the list `add` (identity.md, "The
        // possession statement").
        let device_keys = keys.checked().map_err(Error::class)?;
        let possession = possession.clone().ok_or(Error::Class("Malformed"))?;
        let (_, reached) = engine
            .add_device_reaching(
                PublicKeys {
                    identity: device_keys.ed,
                    xwing: Some(keys.xwing.clone()),
                    mldsa: keys.mldsa.clone(),
                },
                possession,
            )
            .await?;
        let list = ListEvents {
            events: engine.list_events(&person).await,
        };
        let result = approver
            .result_with(
                &approved.request,
                &list.encode(),
                wall(),
                &*platform.draw::<64>()?,
            )
            .map_err(Error::class)?;
        Ok((result, reached))
    }
    .await;
    let (result, reached) = match added {
        Ok(added) => added,
        Err(error) => {
            let message = approver.cancel(&approved.request);
            cancel(&mut sender, &mut incoming, message).await;
            return Err(error);
        }
    };
    send(&mut sender, result).await?;
    // The person's spaces, each a Welcome and then its events.
    let member = ticket.encode().map_err(Error::class)?;
    for (space, delivery, wrap) in reached {
        let welcome = Welcome {
            space: space.0,
            event: delivery,
            key_name: wrap.key_name.encode(),
            grant_name: wrap
                .grant_name
                .as_ref()
                .map(|n| n.encode())
                .unwrap_or_default(),
            wrap: wrap.wrap.clone(),
            approver: engine.device_id(),
            peers: engine.welcome_hints(&space, &[]).await,
            snapshot: None,
        };
        let message = approver
            .welcome_with(
                &approved.request,
                &welcome.encode(),
                &*platform.draw::<64>()?,
            )
            .map_err(Error::class)?;
        send_frame(&mut sender, message, Some(member.clone())).await?;
        hand_over(engine, connection, space).await?;
    }
    sender.finish().map_err(failed)?;
    // The new device closes the connection once it has read everything.
    incoming.closed().await;
    Ok(())
}

/// A space's events, on an object stream scoped by the space.
async fn hand_over(engine: &Engine, connection: &Connection, space: EventId) -> Result<()> {
    let mut object = connection
        .open_object(Scope::Space(space.0))
        .await
        .map_err(failed)?;
    for message in events_messages(space, engine.events(&space).await) {
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
    object.finish().map_err(failed)
}

/// The new device: the joiner with ctx `0x01`, on the connection it
/// dialed. Returns the spaces it accepted and the member ticket to dial.
async fn join<F>(
    device: &Device,
    connection: &Connection,
    person: [u8; 32],
    name: &str,
    unlock_key: &[u8; 32],
    confirm: impl FnOnce(String, String) -> F,
) -> Result<(Vec<EventId>, Option<Ticket>)>
where
    F: Future<Output = bool>,
{
    let engine = device.engine();
    let platform = engine.platform();
    let (mut sender, receiver) = connection.control().await.map_err(failed)?;
    let mut incoming = Incoming::new(receiver);
    let now = platform.clock.wall().ok_or(Error::Class("Expired"))?;
    let me = engine.device_id();
    let (mut joiner, request) = Joiner::start_with(
        JoinerStart {
            ctx: Ctx::DeviceList,
            request: platform.nonce()?,
            expires_at: expires_at(now),
            nonce: platform.draw()?,
            eph_seed: platform.draw()?,
            display: name.to_owned(),
            channel: connection.channel().to_vec(),
        },
        JoinerKeys::Device {
            signer: engine.signer(),
        },
    )
    .map_err(Error::class)?;
    joiner.expect_person(person);
    send(&mut sender, request).await?;
    let response = incoming.next().await?;
    let revealed = match joiner.accept_response_with(
        &response.message,
        platform.clock.wall().unwrap_or(now),
        &*platform.draw::<64>()?,
    ) {
        Ok(Some(revealed)) => revealed,
        Ok(None) => return Err(Error::Class("Malformed")),
        Err(class) => {
            cancel(&mut sender, &mut incoming, joiner.cancel()).await;
            return Err(Error::class(class));
        }
    };
    send(&mut sender, revealed.message.clone()).await?;
    let host = joiner
        .response()
        .cloned()
        .ok_or(Error::Class("Malformed"))?;
    let agreed = incoming
        .decided(confirm(revealed.code.to_string(), host.display.clone()))
        .await?;
    if !agreed {
        cancel(&mut sender, &mut incoming, joiner.cancel()).await;
        return Err(Error::Class("Mismatch"));
    }
    // The Result: the person's list, with this device's add.
    let result = incoming.next().await?;
    let plaintext = joiner.open_result(&result.message).map_err(Error::class)?;
    check_list_result(&plaintext, &host.log, &host.approver, &host.heads, &me)
        .map_err(Error::class)?;
    let events = ListEvents::read(&plaintext).map_err(Error::class)?.events;
    let sealed = engine.adopt_person(host.log, events, unlock_key).await?;
    device.keep_sealed_keys(&host.log, &sealed).await?;
    // Each Welcome, then its space's events, until the host finishes.
    let mut spaces = Vec::new();
    let mut named = BTreeSet::new();
    let mut member = None;
    while let Some(frame) = incoming.next_or_end().await? {
        if read_message(&frame.message).is_ok_and(|read| read.kind != MessageType::Welcome) {
            continue;
        }
        let welcome = joiner.on_welcome(&frame.message).map_err(Error::class)?;
        if !named.insert(welcome.space) {
            continue;
        }
        if member.is_none() {
            member = frame
                .ticket
                .as_deref()
                .and_then(|text| Ticket::read(text).ok())
                .filter(|ticket| ticket.kind == TicketKind::Member);
        }
        spaces.push(welcomed(engine, connection, &welcome).await?);
    }
    connection.close(Close::Done);
    Ok((spaces, member))
}

/// Step 3 of a Welcome's checks: the space's events from its object
/// stream, and this device's own resolution, which must find the delivery
/// valid and the person's grant reaching this device.
async fn welcomed(engine: &Engine, connection: &Connection, welcome: &Welcome) -> Result<EventId> {
    let space = engine.begin_welcomed(welcome).await?;
    let received = receive_snapshot(connection, space).await?;
    if let Some(snapshot) = &received.snapshot {
        engine
            .adopt_snapshot(space, snapshot, received.parts.clone())
            .await?;
    }
    engine.ingest(space, received.events).await?;
    let me = engine.device_id();
    let (status, level) = engine
        .read(&space, |replica| {
            (
                replica.status(&welcome.event).copied(),
                replica.level_of(&me),
            )
        })
        .await?;
    match status {
        Some(Status::Valid(_)) if level.is_some() => {
            let _ = engine.keep_peer_hints(&space, &welcome.peers).await;
            Ok(space)
        }
        Some(Status::Valid(_)) => Err(Error::Class("WrongMember")),
        Some(Status::Void { class, .. }) => Err(Error::Class(class.name())),
        None => Err(Error::Class("Pending")),
    }
}
