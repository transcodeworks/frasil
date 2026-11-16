//! Welcomes deposited in device mailboxes at peers (admission.md, 3.10
//! Welcomes): the signer of a person grant, or of a delivery to a device
//! added to a granted person's list, deposits each device's welcome at the
//! peers it is connected to; a device collects its own mailbox there and
//! keeps a space only once the space's own roster admits it.

use super::batch_admission::SpaceAdmission;
use super::exchange::{POLL_EVERY, SPACE_DEADLINE, collect_own, peer_at};
use super::{Device, SpaceId};
use crate::{Error, Result};
use frasil_admission::welcome::Welcome;
use frasil_base::errors::Class;
use frasil_events::EventId;
use frasil_space::{MemberRef, Status};
use frasil_transport::mailbox::{Kind, address};
use std::collections::BTreeMap;
use std::time::Duration;

/// Deposits each waiting welcome in its recipient's device mailbox at
/// every peer this device is connected to that does not hold it yet, once
/// the event it names is no longer waiting for a peer's acknowledgement,
/// so that the recipient finds the event there (admission.md, 3.10
/// Welcomes).
pub(super) async fn deposit_welcomes(device: &Device) {
    let engine = device.engine();
    for peer in device.peers() {
        if !peer.status().connected {
            continue;
        }
        let url = peer.url().to_owned();
        let waiting = engine.links().to_deposit(&url);
        for welcome in waiting {
            if engine.outbox(&welcome.space).await.contains(&welcome.event) {
                continue;
            }
            // Once taken, the deposit is the device's to deliver: it keeps
            // it, and deposits it again until the peer accepts it.
            let _ = device
                .deposit(
                    &url,
                    address(Kind::Device, &welcome.recipient.0),
                    welcome.sealed.clone(),
                    true,
                )
                .await;
            engine
                .links()
                .deposited(&welcome.recipient, &welcome.space, &url);
        }
    }
}

impl Device {
    /// Refreshes the space credentials without replaying the device mailbox.
    async fn reconnect_for_welcome(&self, url: &str) -> Result<()> {
        let spaces = self.engine().presentable_spaces().await;
        let fresh = self.open_connection(url, spaces).await?;
        let mut peers = self
            .inner
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cursor) = peers
            .iter()
            .filter(|peer| crate::hints::same_peer(peer.url(), url))
            .filter_map(super::Peer::collected)
            .max()
        {
            fresh.set_collected(cursor);
        }
        peers.retain(|peer| {
            if crate::hints::same_peer(peer.url(), url) {
                peer.close();
                false
            } else {
                true
            }
        });
        peers.push(fresh);
        Ok(())
    }

    /// Answers a verified current member's request with a delivery and snapshot.
    pub(super) async fn answer_welcome_request(&self, url: &str, item: &[u8]) -> Result<bool> {
        use frasil_transport::mailbox;
        let engine = self.engine();
        let opened =
            match mailbox::open_item(item, &engine.device_id(), engine.xwing_seed(), |name| {
                name == mailbox::content::WELCOME_REQUEST
            }) {
                Ok(opened) => opened,
                Err(_) => return Ok(false),
            };
        let request = frasil_admission::welcome_request::WelcomeRequest::read(&opened.body)
            .map_err(Error::class)?;
        if engine
            .lock()
            .await
            .welcomed_requests
            .contains(&(request.device, request.request))
        {
            return Ok(true);
        }
        let (space, keys) = engine.welcome_request_member(&opened.body).await?;
        let (event, wraps) = engine.deliver_returning_member(space, &keys).await?;
        let wrap = wraps
            .get(&keys.device_id())
            .ok_or(Error::Class("NoHybridKey"))?;
        let under = wrap.key_name.as_set().ok_or(Error::Class("Malformed"))?;
        let made = engine
            .returning_member_snapshot(&space, event, under)
            .await?;
        let (snapshot, published) = engine
            .publish_returning_snapshot(&space, event, &made, keys.device_id(), under)
            .await?;
        let welcome = Welcome {
            space: space.0,
            event,
            key_name: wrap.key_name.encode(),
            grant_name: wrap
                .grant_name
                .as_ref()
                .map(|name| name.encode())
                .unwrap_or_default(),
            wrap: wrap.wrap.clone(),
            approver: engine.device_id(),
            peers: engine.welcome_hints(&space, &[url.to_owned()]).await,
            snapshot: Some(snapshot),
        };
        let sealed = welcome
            .seal_with(&keys, &*engine.platform().draw::<64>()?)
            .map_err(Error::class)?;
        // The existing welcome outbox waits for the snapshot unit, which
        // is acknowledged only after the peer has its objects.
        engine.links().wait(crate::links::Waiting {
            recipient: keys.device_id(),
            space,
            event: published,
            sealed,
            deposited: Vec::new(),
        });
        self.present(space);
        engine
            .lock()
            .await
            .welcomed_requests
            .insert((request.device, request.request));
        Ok(true)
    }

    /// Collects the welcomes in this device's own device mailbox at the
    /// peer at `url`, on the device's collecting connection there, which
    /// presents none of its spaces (transport.md, 3.12 What a peer learns
    /// of a device), connecting to the peer when it is not, and keeps
    /// each space a welcome names once the space's roster admits this
    /// device: a grant of its person by [`Space::grant_person`], or a
    /// delivery to it after it joined its person's list. The device
    /// fetches each space from that peer, and keeps one only when, by its
    /// own resolution, the welcome's event is valid, authored by the
    /// welcome's approver as an administrator, holds the welcome's wrap,
    /// and the roster grants this device directly or through its person
    /// (admission.md, 3.10 Welcomes). It forgets a space that fails those
    /// checks, or whose event does not arrive within 60 seconds.
    ///
    /// The device's upkeep runs this by itself for each connected peer
    /// whose mailbox holds a welcome. The mailbox is collected from its
    /// start each time, so a call after a restart or a dropped connection
    /// finds what an earlier one did not finish. Spaces this device
    /// already follows are left out of the report.
    ///
    /// [`Space::grant_person`]: super::Space::grant_person
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the peer does not answer before
    /// collection begins; per-space failures are in the report.
    pub async fn receive_welcomes_via_peer(
        &self,
        url: &str,
        mut progress: impl FnMut(&SpaceAdmission),
    ) -> Result<Vec<SpaceAdmission>> {
        let peer = peer_at(self, url).await?;
        let engine = self.engine();
        let me = engine.device_id();
        // Every page first, so that the latest welcome of each space is the
        // one taken.
        let mut latest: BTreeMap<EventId, Welcome> = BTreeMap::new();
        let mut after = None;
        loop {
            let items = collect_own(self, &peer, after).await?;
            let Some((last, _)) = items.last() else {
                break;
            };
            if after == Some(*last) {
                break;
            }
            after = Some(*last);
            for (_, item) in items {
                if let Ok(welcome) = Welcome::open(&item, &me, engine.xwing_seed()) {
                    latest.insert(EventId(welcome.space), welcome);
                }
            }
        }
        let mut pending = Vec::new();
        let mut reports = Vec::new();
        for (space, welcome) in latest {
            // A space the device follows already is fetched, and judged,
            // as any other.
            if engine.read(&space, |_| ()).await.is_ok() && !engine.erasing().await.contains(&space)
            {
                continue;
            }
            let restoring = engine.erasing().await.contains(&space);
            let ignored = engine
                .lock()
                .await
                .ignored_erasure_welcomes
                .contains(&space);
            if ignored || (restoring && !engine.erasure_awaiting_welcome(&space).await) {
                continue;
            }
            match engine.begin_welcomed(&welcome).await {
                Ok(space) => {
                    if restoring {
                        self.reconnect_for_welcome(url).await?;
                    } else {
                        self.present(space);
                    }
                    pending.push(welcome);
                }
                Err(error) => {
                    let report = SpaceAdmission {
                        space: SpaceId::of(space),
                        granted: false,
                        result: Err(error),
                    };
                    progress(&report);
                    reports.push(report);
                }
            }
        }
        let mut waited = Duration::ZERO;
        while !pending.is_empty() {
            let mut still = Vec::new();
            for welcome in pending {
                let space = EventId(welcome.space);
                let result = match check_welcome(self, &welcome).await {
                    Err(Error::Class("Pending" | "Sealed")) if waited < SPACE_DEADLINE => {
                        still.push(welcome);
                        continue;
                    }
                    Err(Error::Class("Pending" | "Sealed")) => Err(Error::Timeout),
                    result => result,
                };
                match &result {
                    Ok(()) => {
                        if engine.erasing().await.contains(&space) {
                            engine.refetch_erased(&space).await?;
                            self.settle_refetched(space).await;
                        }
                        let _ = engine.keep_peer_hints(&space, &welcome.peers).await;
                    }
                    Err(_)
                        if !admitted(self, &space).await
                            && !engine.erasing().await.contains(&space) =>
                    {
                        let _ = engine.forget_space(&space).await;
                    }
                    Err(_) => {}
                }
                let report = SpaceAdmission {
                    space: SpaceId::of(space),
                    granted: result.is_ok(),
                    result,
                };
                progress(&report);
                reports.push(report);
            }
            pending = still;
            if pending.is_empty() {
                break;
            }
            self.sleep(POLL_EVERY).await;
            waited += POLL_EVERY;
        }
        Ok(reports)
    }
}

/// Whether this device holds `space` and its roster reaches the device.
async fn admitted(device: &Device, space: &EventId) -> bool {
    let me = device.engine().device_id();
    device
        .engine()
        .read(space, |replica| {
            replica.log().is_some() && replica.level_of(&me).is_some()
        })
        .await
        .unwrap_or(false)
}

/// admission.md, 3.10 Welcomes, a welcome collected at a peer: the checks,
/// in order, by this device's own resolution of the space. `Pending` until
/// the event has arrived and resolved.
async fn check_welcome(device: &Device, welcome: &Welcome) -> Result<()> {
    let engine = device.engine();
    let me = engine.device_id();
    let person = engine.person().await;
    engine
        .read(&EventId(welcome.space), |replica| {
            let event = replica
                .event(welcome.event)
                .ok_or(Error::Class("Pending"))?;
            if event.kind() != frasil_events::kind::SPACE || event.is_genesis() {
                return Err(Error::Class("Malformed"));
            }
            match replica.status(&welcome.event) {
                Some(Status::Valid(_)) => {}
                Some(Status::Void { class, .. }) => return Err(Error::Class(class.name())),
                None => return Err(Error::Class("Pending")),
            }
            if *event.author() != welcome.approver
                || !replica.authored_as_administrator(&welcome.event)
            {
                return Err(Error::Class("WrongApprover"));
            }
            // A valid event's signature verified in full.
            let verified = replica
                .verified_event(&welcome.event)
                .ok_or(Error::Class("Pending"))?;
            let visible =
                frasil_keys::body::VisiblePart::read(verified.body(), event.author(), event.seq())
                    .map_err(Error::class)?;
            let holds = visible.deliveries.iter().any(|delivery| {
                delivery
                    .key_name
                    .as_ref()
                    .is_some_and(|name| name.encode() == welcome.key_name)
                    && delivery
                        .grant_name
                        .as_ref()
                        .map(|name| name.encode())
                        .unwrap_or_default()
                        == welcome.grant_name
                    && delivery.wraps.contains(&welcome.wrap)
            });
            if !holds {
                return Err(Error::Class("Malformed"));
            }
            let direct = replica.roster().state(&MemberRef::device(me)).is_some();
            let through_person =
                person.is_some_and(|p| replica.roster().state(&MemberRef::person(p)).is_some());
            if !(direct || through_person) || replica.level_of(&me).is_none() {
                return Err(Error::Class("WrongMember"));
            }
            Ok(())
        })
        .await?
}
