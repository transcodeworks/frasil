//! Admission by code through an exchange mailbox at a peer (admission.md,
//! "Exchange mailboxes", "Without a nearby connection"), for a device that
//! cannot take part in nearby pairing, such as a browser.
//!
//! The newcomer runs the joiner: [`Device::join_via_peer`] deposits its
//! Request in the exchange mailbox named by the request ID at a peer, and
//! shows a QR code whose `location` is that peer's origin. The
//! administrator's device runs the approver: [`Space::admit`] takes the QR
//! code's text, fetches the Request, requires its commitment to be the QR
//! code's, and answers. Both read every message of the mailbox, polling at
//! most once a second until the exchange ends or `expires_at` passes, and
//! both compare the same six-digit code. `channel` is empty: the code binds
//! no connection, and the commitment in the QR code is what keeps a party
//! in the middle out. The newcomer is admitted "from now on", unless the
//! administrator chooses "with history". From now on, the administrator
//! publishes the newcomer's snapshot at the peer and names it in the
//! welcome, and the newcomer fetches it, then the space, with the state its
//! welcome hands it (admission.md, "The newcomer's snapshot"). Either side
//! stops at the other's Cancel.

use super::{Device, Peer, Space, SpaceId};
use crate::error::{Error, Result};
use crate::peer::MailboxAsk;
use frasil_admission::approver::{ApproverSide, ResponseDraw};
use frasil_admission::bodies::{RequestBody, ResponseBody};
use frasil_admission::grant::grant_change_ranked;
use frasil_admission::joiner::{JoinerKeys, JoinerStart, expires_at};
use frasil_admission::message::read_message;
use frasil_admission::qr::AdmitQr;
use frasil_admission::welcome::Welcome;
use frasil_admission::{Approver, Ctx, Joiner, MessageType, Offer};
use frasil_space::HistoryMode;
use frasil_store::store::MaybeSend;
use frasil_transport::mailbox::{Kind, address};
use std::future::Future;
use std::time::Duration;
use tokio::sync::oneshot;

/// How often, at most, a party polls the exchange mailbox.
pub(super) const POLL_EVERY: Duration = Duration::from_secs(1);

/// How long a party waits for one answer of the peer.
pub(super) const ANSWER_DEADLINE: Duration = Duration::from_secs(10);

/// How long a newcomer waits for the space to arrive once welcomed.
pub(super) const SPACE_DEADLINE: Duration = Duration::from_secs(60);

/// How long an administrator waits for a peer to hold what it published.
pub(super) const PUBLISH_DEADLINE: Duration = Duration::from_secs(60);

/// How long an approver waits for a Request that is not in the mailbox
/// yet: the code's lifetime.
pub(super) const REQUEST_DEADLINE: Duration =
    Duration::from_secs(frasil_admission::params::ADMISSION_CODE_LIFETIME);

/// A newcomer's admission through an exchange mailbox, waiting for an
/// administrator to enter its code.
#[derive(Debug)]
pub struct Joining {
    text: String,
    done: oneshot::Receiver<Result<Space>>,
}

impl Joining {
    /// The text an administrator enters in [`Space::admit`]: show it as a
    /// QR code. It names the peer and the exchange, and admits no one by
    /// itself.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Waits until the administrator has admitted this device and the
    /// space has arrived from the peer.
    ///
    /// # Errors
    ///
    /// `Mismatch` when this device's person did not confirm the code;
    /// `Cancelled` when the administrator cancelled; `Expired` once the
    /// code's lifetime passed; the grant's classes; [`Error::Timeout`]
    /// when the space does not arrive; [`Error::Connection`] when the
    /// device closed first.
    pub async fn joined(self) -> Result<Space> {
        self.done
            .await
            .map_err(|_| Error::Connection("the device closed before the admission".into()))?
    }
}

/// The open connection to the peer at `url`, or a new one.
pub(super) async fn peer_at(device: &Device, url: &str) -> Result<Peer> {
    let url = url.trim_end_matches('/');
    let open = device
        .peers()
        .into_iter()
        .find(|peer| peer.url().trim_end_matches('/') == url && peer.status().connected);
    match open {
        Some(peer) => Ok(peer),
        None => device.connect(url).await,
    }
}

/// Sends a mailbox message within [`ANSWER_DEADLINE`].
pub(super) async fn ask(
    device: &Device,
    peer: &Peer,
    message: MailboxAsk,
) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    let answer = peer.handle().mailbox(message);
    let deadline = device.sleep(ANSWER_DEADLINE);
    tokio::select! {
        answer = answer => answer.map_err(Error::Connection),
        () = deadline => Err(Error::Timeout),
    }
}

/// Collects this device's own device mailbox at `peer` after the item
/// `after`, within [`ANSWER_DEADLINE`], on the peer's collecting
/// connection: never on `peer`'s own, which presents the device's spaces
/// (transport.md, 3.12 What a peer learns of a device).
pub(super) async fn collect_own(
    device: &Device,
    peer: &Peer,
    after: Option<[u8; 16]>,
) -> Result<Vec<([u8; 16], Vec<u8>)>> {
    let answer = device.collect_own(peer.url(), after);
    let deadline = device.sleep(ANSWER_DEADLINE);
    tokio::select! {
        answer = answer => answer,
        () = deadline => Err(Error::Timeout),
    }
}

/// Deposits an admission message in the exchange mailbox.
pub(super) async fn put(
    device: &Device,
    peer: &Peer,
    mailbox: [u8; 32],
    item: Vec<u8>,
) -> Result<()> {
    ask(
        device,
        peer,
        MailboxAsk::Exchange {
            address: mailbox,
            item,
        },
    )
    .await
    .map(drop)
}

/// The mailbox's messages after the last one collected, which moves on.
pub(super) async fn collect(
    device: &Device,
    peer: &Peer,
    mailbox: [u8; 32],
    after: &mut Option<[u8; 16]>,
) -> Result<Vec<Vec<u8>>> {
    let items = ask(
        device,
        peer,
        MailboxAsk::Collect {
            address: mailbox,
            after: *after,
        },
    )
    .await?;
    if let Some((id, _)) = items.last() {
        *after = Some(*id);
    }
    Ok(items.into_iter().map(|(_, item)| item).collect())
}

/// [`Device::join_via_peer`].
pub(super) async fn join_via_peer<F>(
    device: &Device,
    url: &str,
    name: &str,
    confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
) -> Result<Joining>
where
    F: Future<Output = bool> + MaybeSend + 'static,
{
    let peer = peer_at(device, url).await?;
    let (shown, text) = oneshot::channel();
    let (finished, done) = oneshot::channel();
    let task_device = device.clone();
    let location = url.trim_end_matches('/').to_owned();
    let name = name.to_owned();
    device.spawn(Box::pin(async move {
        let result = run_joiner(&task_device, &peer, location, name, confirm, shown).await;
        let _ = finished.send(result);
    }));
    let text = text
        .await
        .map_err(|_| Error::Connection("the exchange did not start".into()))??;
    Ok(Joining { text, done })
}

/// The joiner (admission.md, "The joiner"), through the mailbox.
async fn run_joiner<F>(
    device: &Device,
    peer: &Peer,
    location: String,
    name: String,
    confirm: impl FnOnce(String, String) -> F,
    shown: oneshot::Sender<Result<String>>,
) -> Result<Space>
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
    let start = Joiner::start_with(
        JoinerStart {
            ctx: Ctx::Space,
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
    let mailbox = address(Kind::Exchange, &request);
    if let Err(error) = put(device, peer, mailbox, request_message).await {
        let _ = shown.send(Err(error.clone()));
        return Err(error);
    }
    let qr = AdmitQr {
        ctx: Ctx::Space,
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
                    let Some(revealed) =
                        joiner.on_response_with(&item, now, &*platform.draw::<64>()?)
                    else {
                        continue;
                    };
                    put(device, peer, mailbox, revealed.message.clone()).await?;
                    let host = joiner.response().map(|r| r.display.clone());
                    let agreed = match confirm.take() {
                        Some(confirm) => {
                            confirm(revealed.code.to_string(), host.unwrap_or_default()).await
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
                    let welcome = Welcome::read(&plaintext).map_err(Error::class)?;
                    if welcome.space != host.log {
                        return Err(Error::Class("WrongSpace"));
                    }
                    return welcomed(device, &welcome, &host).await;
                }
                MessageType::Cancel => return Err(Error::Class("Cancelled")),
                _ => {}
            }
        }
        device.sleep(POLL_EVERY).await;
    }
}

/// Waits until no event of `space` in this device's outbox is `unit`: a
/// peer holds it, and the objects it names, which go before it.
pub(super) async fn published(
    device: &Device,
    space: frasil_events::EventId,
    unit: frasil_events::EventId,
) -> Result<()> {
    let tick = Duration::from_millis(50);
    let mut waited = Duration::ZERO;
    while device.engine().outbox(&space).await.contains(&unit) {
        if waited >= PUBLISH_DEADLINE {
            return Err(Error::Connection(
                "the admission event did not become durable at a peer".into(),
            ));
        }
        device.sleep(tick).await;
        waited += tick;
    }
    Ok(())
}

/// Fetches the space a welcome admits this device to from the peer, and
/// checks the grant once it arrives (admission.md, "Accepting a grant"). A
/// newcomer admitted "from now on" fetches its snapshot first.
async fn welcomed(device: &Device, welcome: &Welcome, host: &ResponseBody) -> Result<Space> {
    let engine = device.engine();
    crate::admitting::keep_as_offered(engine, frasil_events::EventId(welcome.space), &host.offer)
        .await?;
    let space = engine.begin_welcomed(welcome).await?;
    device.present(space);
    let mut waited = Duration::ZERO;
    let tick = Duration::from_millis(250);
    loop {
        device.fetch_snapshot(space).await;
        match crate::admitting::accept_grant(engine, welcome, host).await {
            Ok(()) => return Ok(Space::new(device.clone(), SpaceId::of(space))),
            Err(Error::Class("Pending" | "Sealed")) => {}
            Err(error) => return Err(error),
        }
        if waited >= SPACE_DEADLINE {
            return Err(Error::Timeout);
        }
        device.sleep(tick).await;
        waited += tick;
    }
}

/// [`Space::admit`]: the approver (admission.md, "The approver"), through
/// the mailbox the QR code names.
pub(super) async fn admit<F>(
    space: &Space,
    code: &str,
    offer: Offer,
    rank: Option<u8>,
    name: &str,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<()>
where
    F: Future<Output = bool>,
{
    // An administrator is admitted at the rank the caller names, at most
    // this device's own (roster.md, 2.3 Changes, "Ranks"), checked before
    // any code is exchanged; no other level carries one.
    match (offer.level == frasil_space::Level::Administer, rank) {
        (true, None) => {
            return Err(Error::Invalid(
                "an administrator is admitted at a rank: Space::admit_administrator",
            ));
        }
        (false, Some(_)) => return Err(Error::Invalid("only an administrator has a rank")),
        (true, Some(rank)) => {
            let mine = space.device.engine().my_rank(&space.id().event()).await;
            if rank > mine.unwrap_or(0) {
                return Err(Error::Class("HigherRank"));
            }
        }
        (false, None) => {}
    }
    let history = offer.history;
    // A guest that keeps nothing at rest takes its snapshot on a
    // connection to the device that admits it, never from a peer
    // (ext-guests.md, "Admitting a guest"); through a mailbox there is
    // none.
    if history == HistoryMode::FromNowOn && crate::admitting::keeps_nothing_at_rest(&offer) {
        return Err(Error::Unsupported(
            "a guest that keeps nothing at rest is admitted nearby, where its snapshot travels on the connection",
        ));
    }
    let device = space.device();
    let engine = device.engine();
    let me = engine.device_id();
    let administers = space
        .read(|replica| replica.roster().is_administrator(&me.0))
        .await?;
    if !administers {
        return Err(Error::NotAllowed("admitting needs administer"));
    }
    let qr = AdmitQr::read(code.trim()).map_err(Error::class)?;
    if qr.ctx != Ctx::Space {
        return Err(Error::Class("Malformed"));
    }
    let peer = peer_at(device, &qr.location).await?;
    let id = space.id().event();
    let heads = space
        .read(|replica| {
            let mut heads = replica.citable_heads();
            heads.sort_unstable();
            heads.truncate(256);
            heads
        })
        .await?;
    let mut approver = Approver::new(ApproverSide {
        approver: me,
        ctx: Ctx::Space,
        log: id.0,
        heads,
        offer: offer.encode(),
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
                    // Once the person approved, the newcomer waits for the
                    // Result: a failure on the way to it ends the exchange
                    // with a Cancel, so the newcomer stops at once.
                    let granted: Result<Vec<u8>> = async {
                        let change = grant_change_ranked(
                            &offer,
                            &approved.reveal,
                            rank.unwrap_or(frasil_space::change::MAX_RANK),
                        )
                        .map_err(Error::class)?;
                        let Some(joiner) = change.member.and_then(|m| m.device_id()) else {
                            return Err(Error::Class("Malformed"));
                        };
                        // The revealed keys, which the code authenticated
                        // by their device ID (crypto.md, "Keys by their
                        // hash").
                        if let Some(keys) = change.keys.as_deref() {
                            engine.learn_keys(keys.clone()).await?;
                        }
                        if !engine.reaches_parent_of(&id, &joiner).await {
                            return Err(Error::NotAllowed(
                                "the newcomer does not reach the restricted space's parent",
                            ));
                        }
                        let (admitting, wraps) = engine.sign_roster_with(id, vec![change]).await?;
                        let wrap = wraps.get(&joiner).ok_or(Error::NotAllowed(
                            "the grant delivered nothing to the newcomer",
                        ))?;
                        // From now on: the snapshot, at the peer before the
                        // welcome that names it.
                        let snapshot = if history == HistoryMode::FromNowOn {
                            let made = engine.newcomer_snapshot(&id, admitting).await?;
                            let (locator, unit) = engine
                                .publish_newcomer_snapshot(&id, admitting, &made)
                                .await?;
                            published(device, id, unit).await?;
                            Some(locator)
                        } else {
                            None
                        };
                        let welcome = Welcome {
                            space: id.0,
                            event: admitting,
                            key_name: wrap.key_name.encode(),
                            grant_name: wrap
                                .grant_name
                                .as_ref()
                                .map(|n| n.encode())
                                .unwrap_or_default(),
                            wrap: wrap.wrap.clone(),
                            approver: me,
                            peers: engine
                                .welcome_hints(&id, std::slice::from_ref(&qr.location))
                                .await,
                            snapshot,
                        };
                        let result = approver
                            .result_with(
                                &approved.request,
                                &welcome.encode(),
                                wall(),
                                &*platform.draw::<64>()?,
                            )
                            .map_err(Error::class)?;
                        Ok(result)
                    }
                    .await;
                    match granted {
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
