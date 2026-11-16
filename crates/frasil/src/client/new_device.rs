//! A person's new device, admitted by code through an exchange mailbox at a
//! peer (admission.md, "A person's new device", "Exchange mailboxes"), for
//! a device that cannot take part in nearby pairing, such as a browser.
//!
//! The new device runs the joiner with ctx `0x01`:
//! [`Device::join_person_via_peer`] deposits its Request in the exchange
//! mailbox at a peer and shows a QR code naming that peer. A device of the
//! person runs the approver: [`Device::admit_device`] takes the QR code's
//! text, and both compare the same six-digit code. On a match the approver
//! signs an `add` of the new device in the person's list, publishes the list
//! in each space it writes in that grants the person, delivers each such
//! space's current state to the new device, and waits for the peer to hold
//! what it published. It deposits a sealed welcome per space the peer keeps
//! in the new
//! device's own device mailbox at the peer, then sends the Result: the
//! list's events. The new device checks the list, takes the person, keeps
//! its keys sealed again under its unlock key, collects its welcomes and
//! fetches each space from the peer. Either side stops at the other's
//! Cancel.

use super::exchange::{
    ANSWER_DEADLINE, POLL_EVERY, PUBLISH_DEADLINE, REQUEST_DEADLINE, SPACE_DEADLINE, collect,
    collect_own, peer_at, put,
};
use super::{Device, Peer, Space, SpaceId};
use crate::error::{Error, Result};
use frasil_admission::approver::{ApproverSide, ResponseDraw};
use frasil_admission::bodies::{ListEvents, RequestBody, ResponseBody, RevealBody};
use frasil_admission::joiner::{JoinerKeys, JoinerStart, expires_at};
use frasil_admission::message::read_message;
use frasil_admission::new_device::check_list_result;
use frasil_admission::qr::AdmitQr;
use frasil_admission::welcome::Welcome;
use frasil_admission::{Approver, Ctx, Joiner, MessageType};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_identity::PublicKeys;
use frasil_space::Status;
use frasil_store::store::MaybeSend;
use frasil_transport::mailbox::{Kind, address};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use tokio::sync::oneshot;

/// A new device's admission to its person through an exchange mailbox,
/// waiting for a device of the person to enter its code.
#[derive(Debug)]
pub struct JoiningPerson {
    text: String,
    done: oneshot::Receiver<Result<Vec<Space>>>,
}

impl JoiningPerson {
    /// The text a device of the person enters in [`Device::admit_device`]:
    /// show it as a QR code. It names the peer and the exchange, and admits
    /// no one by itself.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Waits until a device of the person has added this device to the
    /// person's list, and the spaces that grant the person have arrived
    /// from the peer. Returns them; [`Device::person`] is the person from
    /// then on.
    ///
    /// # Errors
    ///
    /// `WrongPerson` when a device of another person than the expected one
    /// answered, which added this device to no list; `Mismatch` when this
    /// device's person did not confirm the code;
    /// `Cancelled` when the other device cancelled; `Expired` once the
    /// code's lifetime passed; the list's classes (`WrongPerson`,
    /// `WrongMember`, `WrongApprover`, `NotFollowing`, `NotInList`);
    /// [`Error::Timeout`] when a space does not arrive;
    /// [`Error::Connection`] when the device closed first.
    pub async fn joined(self) -> Result<Vec<Space>> {
        self.done
            .await
            .map_err(|_| Error::Connection("the device closed before the admission".into()))?
    }
}

impl Device {
    /// Joins `person` as its new device through an exchange mailbox at the
    /// peer at `url` (admission.md, "A person's new device"), where this
    /// device cannot take part in nearby pairing, such as in a browser.
    /// Show the returned [`JoiningPerson::text`] as a QR code; a device of
    /// the person enters it in [`Device::admit_device`]. A device of
    /// another person that enters it adds this device to no list: this
    /// device refuses its answer before it reveals anything, and the
    /// exchange ends with `WrongPerson` (admission.md, 3.1 The joiner, step
    /// 5). `person` is the ID of the person the device is meant to join,
    /// such as the one an account names. Both screens then
    /// show the same six-digit admission code: `confirm` is given the code
    /// and the other device's name, and its future says whether this
    /// device's person saw that code on both. `name` is what the other
    /// screen shows for this device. `unlock_key` is the key this device
    /// was opened with: once admitted, its keys are sealed again under it
    /// to name the person, and kept as [`Device::make_person`] keeps them.
    /// [`JoiningPerson::joined`] waits for the person's spaces.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of a person already, or a URL that
    /// is not HTTPS; `BadSeal` when `unlock_key` does not open this
    /// device's keys; [`Error::Connection`] when the peer does not answer;
    /// `Expired` without a wall clock.
    pub async fn join_person_via_peer<F>(
        &self,
        url: &str,
        person: super::PersonId,
        name: &str,
        unlock_key: &[u8; 32],
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<JoiningPerson>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        if self.engine().person().await.is_some() {
            return Err(Error::NotAllowed("the device is already a person's"));
        }
        self.check_unlock_key(unlock_key)?;
        let peer = peer_at(self, url).await?;
        let (shown, text) = oneshot::channel();
        let (finished, done) = oneshot::channel();
        let task_device = self.clone();
        let location = url.trim_end_matches('/').to_owned();
        let name = name.to_owned();
        let unlock_key = zeroize::Zeroizing::new(*unlock_key);
        self.spawn(Box::pin(async move {
            let result = run_joiner(
                &task_device,
                &peer,
                location,
                *person.as_bytes(),
                name,
                &unlock_key,
                confirm,
                shown,
            )
            .await;
            let _ = finished.send(result);
        }));
        let text = text
            .await
            .map_err(|_| Error::Connection("the exchange did not start".into()))??;
        Ok(JoiningPerson { text, done })
    }

    /// Adds the device whose [`JoiningPerson::text`] a new device shows to
    /// this device's person, through the exchange mailbox at the peer that
    /// text names (admission.md, "A person's new device"). `confirm` is
    /// given the six-digit code both screens show and the new device's
    /// name, and its future says whether this device's person saw it on
    /// both. `name` is what the new device's screen shows for this device.
    /// The new device then reaches every space this device writes in that
    /// grants the person, as the person's grant there says; it is welcomed
    /// to those the peer keeps, and fetches them there.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; `Malformed` for a
    /// text that is no person's new device's; `CommitmentMismatch`;
    /// `Mismatch` when this device's person did not confirm the code;
    /// `Cancelled`; `Expired`; [`Error::Timeout`] when no Request arrives;
    /// [`Error::Connection`] when the peer does not answer.
    pub async fn admit_device<F>(
        &self,
        text: &str,
        name: &str,
        confirm: impl FnOnce(String, String) -> F,
    ) -> Result<()>
    where
        F: Future<Output = bool>,
    {
        admit(self, text, name, confirm).await
    }
}

/// The joiner, ctx `0x01`, through the mailbox.
#[allow(clippy::too_many_arguments)]
async fn run_joiner<F>(
    device: &Device,
    peer: &Peer,
    location: String,
    person: [u8; 32],
    name: String,
    unlock_key: &[u8; 32],
    confirm: impl FnOnce(String, String) -> F,
    shown: oneshot::Sender<Result<String>>,
) -> Result<Vec<Space>>
where
    F: Future<Output = bool>,
{
    let engine = device.engine().clone();
    let platform = engine.platform().clone();
    let wall = || platform.clock.wall();
    let started = (|| -> Result<_> {
        let now = wall().ok_or(Error::Class("Expired"))?;
        Ok((
            platform.nonce::<16>()?,
            expires_at(now),
            platform.draw()?,
            platform.draw()?,
        ))
    })();
    let (request, expires, nonce, eph_seed) = match started {
        Ok(drawn) => drawn,
        Err(error) => {
            let _ = shown.send(Err(error.clone()));
            return Err(error);
        }
    };
    let me = engine.device_id();
    let start = Joiner::start_with(
        JoinerStart {
            ctx: Ctx::DeviceList,
            request,
            expires_at: expires,
            nonce,
            eph_seed,
            display: name,
            channel: Vec::new(),
        },
        JoinerKeys::Device {
            signer: engine.signer(),
        },
    );
    let (mut joiner, request_message) = match start {
        Ok(started) => started,
        Err(class) => {
            let _ = shown.send(Err(Error::class(class)));
            return Err(Error::class(class));
        }
    };
    joiner.expect_person(person);
    let mailbox = address(Kind::Exchange, &request);
    if let Err(error) = put(device, peer, mailbox, request_message).await {
        let _ = shown.send(Err(error.clone()));
        return Err(error);
    }
    let qr = AdmitQr {
        ctx: Ctx::DeviceList,
        request,
        commitment: joiner.commitment(),
        location,
    };
    let _ = shown.send(Ok(qr.text()));
    let mut confirm = Some(confirm);
    let mut after = None;
    loop {
        if wall().is_none_or(|now| now > expires) {
            return Err(Error::Class("Expired"));
        }
        for item in collect(device, peer, mailbox, &mut after).await? {
            let Ok(message) = read_message(&item) else {
                continue;
            };
            match message.kind {
                MessageType::Response if joiner.response().is_none() => {
                    let now = wall().ok_or(Error::Class("Expired"))?;
                    let revealed =
                        match joiner.accept_response_with(&item, now, &*platform.draw::<64>()?) {
                            Ok(Some(revealed)) => revealed,
                            Ok(None) => continue,
                            Err(class) => {
                                put(device, peer, mailbox, joiner.cancel()).await?;
                                return Err(Error::class(class));
                            }
                        };
                    put(device, peer, mailbox, revealed.message.clone()).await?;
                    let other = joiner.response().map(|r| r.display.clone());
                    let agreed = match confirm.take() {
                        Some(confirm) => {
                            confirm(revealed.code.to_string(), other.unwrap_or_default()).await
                        }
                        None => false,
                    };
                    if !agreed {
                        put(device, peer, mailbox, joiner.cancel()).await?;
                        return Err(Error::Class("Mismatch"));
                    }
                }
                MessageType::Result => {
                    let Some(host) = joiner.response().cloned() else {
                        continue;
                    };
                    let plaintext = joiner.open_result(&item).map_err(Error::class)?;
                    check_list_result(&plaintext, &host.log, &host.approver, &host.heads, &me)
                        .map_err(Error::class)?;
                    let events = ListEvents::read(&plaintext).map_err(Error::class)?.events;
                    let sealed = engine.adopt_person(host.log, events, unlock_key).await?;
                    device.keep_sealed_keys(&host.log, &sealed).await?;
                    return welcomed(device, peer, &host).await;
                }
                MessageType::Cancel => return Err(Error::Class("Cancelled")),
                _ => {}
            }
        }
        device.sleep(POLL_EVERY).await;
    }
}

/// The welcomes the approver deposited in this device's own device mailbox
/// at the peer: each opens, and names the approver.
async fn collect_welcomes(
    device: &Device,
    peer: &Peer,
    approver: &DeviceId,
) -> Result<Vec<Welcome>> {
    let engine = device.engine();
    let me = engine.device_id();
    let mut welcomes = Vec::new();
    let mut after = None;
    loop {
        let items = collect_own(device, peer, after).await?;
        let Some((last, _)) = items.last() else {
            return Ok(welcomes);
        };
        after = Some(*last);
        for (_, item) in items {
            let Ok(welcome) = Welcome::open(&item, &me, engine.xwing_seed()) else {
                continue;
            };
            if welcome.approver == *approver {
                welcomes.push(welcome);
            }
        }
    }
}

/// Collects the welcomes, follows each space they name, and waits until
/// each has arrived from the peer and admits this device: the delivery is
/// valid there, and the person's grant reaches the device.
async fn welcomed(device: &Device, peer: &Peer, host: &ResponseBody) -> Result<Vec<Space>> {
    let engine = device.engine();
    let me = engine.device_id();
    // The approver deposits every welcome before it sends the Result; a
    // peer that has not yet made them readable gets a little time.
    let mut waited = Duration::ZERO;
    let welcomes = loop {
        let welcomes = collect_welcomes(device, peer, &host.approver).await?;
        if !welcomes.is_empty() || waited >= ANSWER_DEADLINE {
            break welcomes;
        }
        device.sleep(POLL_EVERY).await;
        waited += POLL_EVERY;
    };
    let mut awaited: BTreeMap<EventId, EventId> = BTreeMap::new();
    // Each welcome's peer hints, kept once its space admits the device.
    let mut hints: Vec<(EventId, Vec<String>)> = Vec::new();
    for welcome in &welcomes {
        if awaited.contains_key(&EventId(welcome.space)) {
            continue;
        }
        let space = engine.begin_welcomed(welcome).await?;
        device.present(space);
        awaited.insert(space, welcome.event);
        hints.push((space, welcome.peers.clone()));
    }
    let mut arrived = Vec::new();
    let tick = Duration::from_millis(250);
    let mut waited = Duration::ZERO;
    while !awaited.is_empty() {
        let mut still = BTreeMap::new();
        for (space, event) in awaited {
            let admitted = engine
                .read(&space, |replica| {
                    matches!(replica.status(&event), Some(Status::Valid(_)))
                        && replica.level_of(&me).is_some()
                })
                .await
                .unwrap_or(false);
            if admitted {
                if let Some((_, peers)) = hints.iter().find(|(of, _)| *of == space) {
                    let _ = engine.keep_peer_hints(&space, peers).await;
                }
                arrived.push(Space::new(device.clone(), SpaceId::of(space)));
            } else {
                still.insert(space, event);
            }
        }
        awaited = still;
        if awaited.is_empty() {
            break;
        }
        if waited >= SPACE_DEADLINE {
            return Err(Error::Timeout);
        }
        device.sleep(tick).await;
        waited += tick;
    }
    Ok(arrived)
}

/// [`Device::admit_device`]: the approver, ctx `0x01`, through the mailbox
/// the QR code names.
async fn admit<F>(
    device: &Device,
    code: &str,
    name: &str,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<()>
where
    F: Future<Output = bool>,
{
    let engine = device.engine();
    let me = engine.device_id();
    let person = engine
        .person()
        .await
        .ok_or(Error::NotAllowed("the device is no person's"))?;
    let qr = AdmitQr::read(code.trim()).map_err(Error::class)?;
    if qr.ctx != Ctx::DeviceList {
        return Err(Error::Class("Malformed"));
    }
    let peer = peer_at(device, &qr.location).await?;
    let mut heads = engine.list_heads(&person).await;
    heads.sort_unstable();
    heads.truncate(256);
    let mut approver = Approver::new(ApproverSide {
        approver: me,
        ctx: Ctx::DeviceList,
        log: person,
        heads,
        offer: Vec::new(),
        display: name.to_owned(),
        channel: Vec::new(),
    })
    .map_err(Error::class)?;
    let platform = engine.platform().clone();
    let wall = || platform.clock.wall();
    let mailbox = address(Kind::Exchange, &qr.request);
    let mut after = None;
    let mut expires: Option<u64> = None;
    let mut waited = Duration::ZERO;
    let mut confirm = Some(confirm);
    loop {
        for item in collect(device, &peer, mailbox, &mut after).await? {
            let Ok(message) = read_message(&item) else {
                continue;
            };
            if message.request != qr.request {
                continue;
            }
            match message.kind {
                MessageType::Request if expires.is_none() => {
                    let body = RequestBody::read(message.body).map_err(Error::class)?;
                    if body.commitment != qr.commitment {
                        return Err(Error::Class("CommitmentMismatch"));
                    }
                    let response = approver
                        .on_request_with(
                            &item,
                            wall(),
                            ResponseDraw {
                                nonce: platform.draw()?,
                                eph_seed: platform.draw()?,
                                encapsulation: platform.draw()?,
                            },
                        )
                        .map_err(Error::class)?;
                    expires = Some(body.expires_at);
                    put(device, &peer, mailbox, response).await?;
                }
                MessageType::Reveal => {
                    let Some(approved) = approver.on_reveal(&item, wall()).map_err(Error::class)?
                    else {
                        continue;
                    };
                    let agreed = match confirm.take() {
                        Some(confirm) => {
                            confirm(
                                approved.code.to_string(),
                                approved.reveal.display().to_owned(),
                            )
                            .await
                        }
                        None => false,
                    };
                    if !agreed {
                        let cancel = approver.cancel(&approved.request);
                        put(device, &peer, mailbox, cancel).await?;
                        return Err(Error::Class("Mismatch"));
                    }
                    // Once the person approved, the new device waits for
                    // the Result: a failure on the way to it ends the
                    // exchange with a Cancel.
                    let added: Result<Vec<u8>> = async {
                        let RevealBody::Device {
                            keys, possession, ..
                        } = &approved.reveal
                        else {
                            return Err(Error::Class("Malformed"));
                        };
                        // The keys the code authenticated by their device
                        // ID, and the device's possession proof for the
                        // list `add` (identity.md, "The possession
                        // statement").
                        let device_keys = keys.checked().map_err(Error::class)?;
                        let possession = possession.clone().ok_or(Error::Class("Malformed"))?;
                        let new = device_keys.device_id();
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
                        // Each space's delivery at the peer before the
                        // welcome that names it. Only a space the peer keeps
                        // is welcomed, as the new device fetches it there;
                        // one the peer does not take in time is not.
                        let kept = peer.status().spaces;
                        let tick = Duration::from_millis(50);
                        let mut waited = Duration::ZERO;
                        let mut pending: Vec<_> = reached
                            .into_iter()
                            .filter(|(space, ..)| kept.contains(&SpaceId::of(*space)))
                            .collect();
                        let mut ready = Vec::new();
                        loop {
                            let mut still = Vec::new();
                            for entry in pending {
                                if engine.outbox(&entry.0).await.contains(&entry.1) {
                                    still.push(entry);
                                } else {
                                    ready.push(entry);
                                }
                            }
                            pending = still;
                            if pending.is_empty() || waited >= PUBLISH_DEADLINE {
                                break;
                            }
                            device.sleep(tick).await;
                            waited += tick;
                        }
                        let own = address(Kind::Device, &new.0);
                        for (space, delivery, wrap) in ready {
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
                                approver: me,
                                peers: engine
                                    .welcome_hints(&space, std::slice::from_ref(&qr.location))
                                    .await,
                                snapshot: None,
                            };
                            let sealed = welcome
                                .seal_with(&device_keys, &*platform.draw::<64>()?)
                                .map_err(Error::class)?;
                            // A welcome the peer does not take now is kept
                            // and goes again; one refused for good fails.
                            if let super::deposits::Delivery::Refused(code) =
                                device.deposit(peer.url(), own, sealed, true).await
                            {
                                return Err(Error::Connection(format!("refused: {code}")));
                            }
                        }
                        let list = ListEvents {
                            events: engine.list_events(&person).await,
                        };
                        approver
                            .result_with(
                                &approved.request,
                                &list.encode(),
                                wall(),
                                &*platform.draw::<64>()?,
                            )
                            .map_err(Error::class)
                    }
                    .await;
                    match added {
                        Ok(result) => {
                            put(device, &peer, mailbox, result).await?;
                            return Ok(());
                        }
                        Err(error) => {
                            let cancel = approver.cancel(&approved.request);
                            let _ = put(device, &peer, mailbox, cancel).await;
                            return Err(error);
                        }
                    }
                }
                MessageType::Cancel => return Err(Error::Class("Cancelled")),
                _ => {}
            }
        }
        let now = wall().ok_or(Error::Class("Expired"))?;
        match expires {
            Some(expires) if now > expires => return Err(Error::Class("Expired")),
            None if waited >= REQUEST_DEADLINE => return Err(Error::Timeout),
            _ => {}
        }
        device.sleep(POLL_EVERY).await;
        waited += POLL_EVERY;
    }
}
