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
/// every peer this device is connected to where it is due, once the event
/// the entry waits on is no longer waiting for a peer's acknowledgement, so that the
/// recipient finds the event there (admission.md, 3.10 Welcomes, "A
/// welcome that waits"). A welcome is due at a peer it was never deposited
/// at, while it names fewer than 64 peers, and again `welcome_redeposit`
/// after its latest deposit there, since a peer keeps an item for a while
/// only, four deposits there in all. The peer, the `T` of the deposit and
/// the count there are named in the welcome's record in the commit that
/// keeps the deposit, so a restart neither deposits it there again sooner
/// nor counts again; a deposit the peer refused for good counts too.
/// While a deposit of the welcome at the peer waits to go again, no other
/// is made there. A welcome is deposited at a peer only while it is due
/// there at the `T` this pass read before the kept deposits, so that of
/// passes that run at once, only one deposits it. A welcome kept
/// `welcome_retention` ago, of a space whose roster no longer reaches its
/// recipient, or whose recipient signed an event in the space after the
/// event the entry waits on, waits no longer, and goes nowhere, with the
/// deposits of it the device keeps. The welcomes due at a peer are checked
/// at once, so that those that end take their deposits in one commit.
pub(super) async fn deposit_welcomes(device: &Device) {
    let engine = device.engine();
    engine.expire_welcomes().await;
    device.forget_unkept_of(&engine.end_acted_welcomes().await);
    let now = engine.welcome_time().await;
    let mut kept = None;
    let mut outboxes: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    for peer in device.peers() {
        if !peer.status().connected {
            continue;
        }
        let url = peer.url().to_owned();
        // A `deposit` record names its peer by an origin of 1 to 512
        // bytes, so a deposit at a peer with a longer one is never kept.
        if !(1..=frasil_store::tables::MAX_PEER_URL).contains(&crate::links::origin(&url).len()) {
            continue;
        }
        let due = engine.links().to_deposit(&url, now);
        if due.is_empty() {
            continue;
        }
        let waiting = still_waiting(device, due).await;
        // The deposits kept to go again at this peer, read once a pass, by
        // address and item, so that each welcome is looked up in them.
        if kept.is_none() {
            kept = Some(device.kept_deposits().await);
        }
        let Some(kept) = &kept else {
            continue;
        };
        let held: std::collections::BTreeSet<(&[u8; 32], &[u8])> = kept
            .iter()
            .filter(|(_, record, _)| record.peer == crate::links::origin(&url))
            .map(|(_, record, _)| (&record.address, record.item.as_slice()))
            .collect();
        for welcome in waiting {
            if let std::collections::btree_map::Entry::Vacant(entry) = outboxes.entry(welcome.space)
            {
                entry.insert(engine.outbox(&welcome.space).await);
            }
            if outboxes
                .get(&welcome.space)
                .is_some_and(|outbox| outbox.contains(&welcome.event))
            {
                continue;
            }
            let address = address(Kind::Device, &welcome.recipient.0);
            if held.contains(&(&address, welcome.sealed.as_slice())) {
                continue;
            }
            // Once taken, the deposit is the device's to deliver: it keeps
            // it, and deposits it again until the peer accepts it.
            if device
                .deposit_welcome(&url, address, &welcome, now)
                .await
                .is_none()
            {
                continue;
            }
            device
                .inner
                .welcome_deposits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Those of `welcomes` that still wait: each is among the waiting
/// welcomes, the space's roster, in this device's view, still reaches its
/// recipient, and the recipient has signed no event in the space after
/// the event the entry waits on. Those that do not wait end, and the
/// deposits of them the device keeps go, those at rest in the commit that
/// deletes their records (admission.md, 3.10 Welcomes, "A welcome that
/// waits"), and those in memory here, with those of welcomes a member
/// connection ended.
pub(super) async fn still_waiting(
    device: &Device,
    welcomes: Vec<crate::links::Waiting>,
) -> Vec<crate::links::Waiting> {
    if welcomes.is_empty() {
        return welcomes;
    }
    let checked = device.engine().check_waiting(welcomes).await;
    device.forget_unkept_of(&checked.ended);
    checked.waits
}

impl Device {
    /// The welcomes this device keeps waiting, oldest first: each one's
    /// recipient, space and the peers, by origin, that hold it. For tests
    /// (admission.md, 3.10 Welcomes, "A welcome that waits").
    #[doc(hidden)]
    pub fn waiting_welcomes(&self) -> Vec<(super::MemberId, SpaceId, Vec<String>)> {
        self.engine()
            .links()
            .waiting_welcomes()
            .into_iter()
            .map(|welcome| {
                (
                    super::MemberId::device(welcome.recipient),
                    SpaceId::of(welcome.space),
                    welcome
                        .deposited
                        .into_iter()
                        .map(|(peer, _, _)| peer)
                        .collect(),
                )
            })
            .collect()
    }

    /// How many deposits each welcome this device keeps waiting, oldest
    /// first, counts at the peer at `url`: 0 where it was never deposited
    /// there. For tests (admission.md, 3.10 Welcomes, "A welcome that
    /// waits").
    #[doc(hidden)]
    pub fn welcome_deposit_counts(&self, url: &str) -> Vec<u8> {
        let url = crate::links::origin(url);
        self.engine()
            .links()
            .waiting_welcomes()
            .iter()
            .map(|welcome| {
                welcome
                    .deposited
                    .iter()
                    .find(|(peer, _, _)| peer == url)
                    .map_or(0, |(_, _, count)| *count)
            })
            .collect()
    }

    /// How many welcomes this device has deposited at peers since it
    /// opened. For tests.
    #[doc(hidden)]
    pub fn welcome_deposits(&self) -> u64 {
        self.inner
            .welcome_deposits
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Runs what the device's upkeep runs for the welcomes it keeps waiting
    /// at once: their deposits at each connected peer. For tests.
    #[doc(hidden)]
    pub async fn welcome_upkeep(&self) {
        deposit_welcomes(self).await;
    }

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
        // The welcome waits for the snapshot unit, which is acknowledged
        // only after the peer has its objects.
        let since = engine.welcome_time().await;
        engine
            .keep_welcomes(
                space,
                vec![crate::links::Waiting {
                    recipient: keys.device_id(),
                    space,
                    event: published,
                    sealed,
                    since,
                    deposited: Vec::new(),
                    looked: None,
                }],
            )
            .await?;
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

#[cfg(all(test, feature = "iroh"))]
mod tests {
    //! A welcome's deposit kept to go again, once the roster no longer
    //! reaches its recipient (admission.md, 3.10 Welcomes, "A welcome that
    //! waits").

    use crate::platform::{Clock, ManualClock};
    use crate::{Device, Level, Options, Storage};
    use frasil_space::{HistoryMode, MemberRef, Via};
    use frasil_transport::mailbox::{Kind, address};
    use std::sync::Arc;

    /// A deposit of a waiting welcome that no peer has taken yet goes no
    /// further once the space's roster no longer reaches the recipient:
    /// the next attempt drops it, and the welcome with it.
    #[tokio::test]
    async fn a_kept_deposit_of_a_welcome_goes_no_further_once_the_roster_drops_its_recipient() {
        let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
        let granter = Device::open_with(
            Storage::Memory,
            &[1; 32],
            Options::new()
                .loopback()
                .never_restored()
                .clock(clock.clone() as Arc<dyn Clock>),
        )
        .await
        .unwrap();
        let member = Device::open_with(Storage::Memory, &[2; 32], Options::new().loopback())
            .await
            .unwrap();
        let engine = granter.engine();
        let id = member.engine().device_id();
        let known = engine.create_space().await.unwrap();
        engine
            .grant_device(
                known,
                member.engine().public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let space = engine.create_space().await.unwrap();
        engine
            .admit_member(space, known, id, Level::Write, None)
            .await
            .unwrap();
        let welcome = engine.links().waiting(&id, &space).unwrap();

        // No peer answers there: the deposit is kept to go again.
        let delivery = granter
            .deposit(
                "http://127.0.0.1:9",
                address(Kind::Device, &id.0),
                welcome.sealed.clone(),
                true,
            )
            .await;
        assert!(
            matches!(delivery, super::super::deposits::Delivery::Delayed(_)),
            "{delivery:?}"
        );
        assert_eq!(granter.waiting_deposits().await, 1);

        engine.remove(space, MemberRef::device(id)).await.unwrap();
        clock.advance(super::super::deposits::retry_bound(1) + 1);
        granter.deposit_upkeep().await;
        assert_eq!(granter.waiting_deposits().await, 0);
        assert!(engine.links().waiting(&id, &space).is_none());

        for device in [granter, member] {
            device.close().await.unwrap();
        }
    }

    /// `granter` grants `member` directly in a new space, then admits it to
    /// another by that one: the other space, with the welcome waiting.
    async fn admitted(granter: &Device, member: &Device) -> frasil_events::EventId {
        let engine = granter.engine();
        let id = member.engine().device_id();
        let known = engine.create_space().await.unwrap();
        engine
            .grant_device(
                known,
                member.engine().public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let space = engine.create_space().await.unwrap();
        engine
            .admit_member(space, known, id, Level::Write, None)
            .await
            .unwrap();
        assert!(engine.links().waiting(&id, &space).is_some());
        space
    }

    /// Carries `space`'s events from `from` to `to`, by hand.
    async fn carry(from: &Device, to: &Device, space: frasil_events::EventId) {
        to.engine().follow(space).await;
        to.engine()
            .ingest(space, from.engine().events(&space).await)
            .await
            .unwrap();
    }

    /// A note `device` writes in `space`.
    async fn note(device: &Device, space: frasil_events::EventId, text: &str) {
        let held = device.space(crate::SpaceId::of(space)).await.unwrap();
        let note = held.create_document().unwrap();
        note.edit(|doc| doc.get_text("body").insert(0, text))
            .await
            .unwrap();
    }

    /// A look at the recipient of the welcome for `id` in `space` with
    /// `walks` walks of the log left: what it found, and the walks left.
    async fn look(
        engine: &crate::device::Engine,
        id: frasil_crypto::device::DeviceId,
        space: frasil_events::EventId,
        mut walks: usize,
    ) -> (Option<bool>, usize) {
        let state = engine.lock().await;
        let mut links = engine.links();
        let welcome = links.waiting(&id, &space).unwrap();
        let waiting = links.same_mut(&welcome).unwrap();
        let replica = state.replicas.get(&space).unwrap();
        let before = frasil_events::log::precedes_walks();
        let found = crate::welcomes::look(replica, waiting, &mut walks);
        LAST_WALKS.set(frasil_events::log::precedes_walks() - before);
        (found, walks)
    }

    std::thread_local! {
        /// The walks of the log [`look`] made last on this thread, counted
        /// around the look alone.
        static LAST_WALKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// The walks of the log the last [`look`] on this thread made.
    fn walks_of_last_look() -> u64 {
        LAST_WALKS.get()
    }

    /// A look that found the newcomer had not acted is remembered: a second
    /// look at the same event walks the log no more, and a newer event the
    /// newcomer signs is walked again, and ends the welcome once it has the
    /// grant in its past (admission.md, 3.10 Welcomes, "A welcome that
    /// waits").
    #[tokio::test]
    async fn a_look_walks_the_log_again_only_for_a_newer_event() {
        let options = || Options::new().loopback().never_restored();
        let granter = Device::open_with(Storage::Memory, &[7; 32], options())
            .await
            .unwrap();
        let member = Device::open_with(Storage::Memory, &[8; 32], options())
            .await
            .unwrap();
        let (engine, id) = (granter.engine(), member.engine().device_id());
        let known = engine.create_space().await.unwrap();
        let space = engine.create_space().await.unwrap();
        for held in [known, space] {
            engine
                .grant_device(
                    held,
                    member.engine().public_keys().clone(),
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap();
        }
        // A writer under an earlier grant, which a removal ends, writes
        // before the new grant and concurrently with it.
        carry(&granter, &member, space).await;
        note(&member, space, "before").await;
        carry(&member, &granter, space).await;
        engine.remove(space, MemberRef::device(id)).await.unwrap();
        engine
            .admit_member(space, known, id, Level::Write, None)
            .await
            .unwrap();
        note(&member, space, "concurrently").await;
        carry(&member, &granter, space).await;

        assert_eq!(look(engine, id, space, 1).await, (Some(false), 0));
        // The event judged stands no higher than the grant: its height
        // answers, with no walk of the log.
        assert_eq!(walks_of_last_look(), 0);
        assert_eq!(
            look(engine, id, space, 0).await,
            (Some(false), 0),
            "the same event, judged without a walk"
        );
        assert_eq!(walks_of_last_look(), 0);
        carry(&granter, &member, space).await;
        note(&member, space, "after").await;
        carry(&member, &granter, space).await;
        assert_eq!(
            look(engine, id, space, 0).await,
            (None, 0),
            "a newer event needs a walk"
        );
        assert_eq!(walks_of_last_look(), 0);
        assert_eq!(look(engine, id, space, 1).await, (Some(true), 0));
        assert_eq!(walks_of_last_look(), 1);

        for device in [granter, member] {
            device.close().await.unwrap();
        }
    }

    /// The newcomer's latest event in the space that the granter has not
    /// accepted in full does not hide an earlier one it signed after the
    /// grant: the look steps back along its chain by `prev` to the newest
    /// event accepted in full, which has the grant in its past, and the
    /// welcome ends (admission.md, 3.10 Welcomes, "A welcome that waits").
    #[tokio::test]
    async fn an_unaccepted_latest_event_does_not_hide_an_earlier_one_after_the_grant() {
        let options = || Options::new().loopback().never_restored();
        let granter = Device::open_with(Storage::Memory, &[3; 32], options())
            .await
            .unwrap();
        let member = Device::open_with(Storage::Memory, &[4; 32], options())
            .await
            .unwrap();
        let space = admitted(&granter, &member).await;
        let (engine, id) = (granter.engine(), member.engine().device_id());
        member.engine().follow(space).await;
        member
            .engine()
            .ingest(space, engine.events(&space).await)
            .await
            .unwrap();
        let held = member.space(crate::SpaceId::of(space)).await.unwrap();
        for text in ["one", "two"] {
            let note = held.create_document().unwrap();
            note.edit(|doc| doc.get_text("body").insert(0, text))
                .await
                .unwrap();
        }
        engine
            .ingest(space, member.engine().events(&space).await)
            .await
            .unwrap();
        {
            let mut state = engine.lock().await;
            let replica = state.replicas.get_mut(&space).unwrap();
            let latest = replica.log().unwrap().latest(&id).unwrap();
            replica.hold_status(&latest);
            assert!(!replica.accepted(&latest));
        }
        granter.welcome_upkeep().await;
        assert!(engine.links().waiting(&id, &space).is_none());

        drop(held);
        for device in [granter, member] {
            device.close().await.unwrap();
        }
    }

    /// A deposit of a waiting welcome kept to go again is counted once in
    /// the welcome's record, across a restart and a further attempt. Once
    /// the roster no longer reaches the recipient it is dropped with the
    /// welcome, even while an attempt of it is under way: that attempt,
    /// unanswered, keeps it no more, and a restart brings it back nowhere.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_kept_deposit_of_a_welcome_under_way_when_it_ends_goes_no_further() {
        use super::super::deposits::{Delivery, retry_bound};
        let dir = std::env::temp_dir().join(format!(
            "frasil-welcome-deposit-under-way-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
        let open = || async {
            Device::open_with(
                Storage::Directory(dir.clone()),
                &[5; 32],
                Options::new()
                    .loopback()
                    .never_restored()
                    .clock(clock.clone() as Arc<dyn Clock>),
            )
            .await
            .unwrap()
        };
        let granter = open().await;
        let member = Device::open_with(Storage::Memory, &[6; 32], Options::new().loopback())
            .await
            .unwrap();
        let space = admitted(&granter, &member).await;
        let id = member.engine().device_id();
        let welcome = granter.engine().links().waiting(&id, &space).unwrap();
        let now = granter.engine().welcome_time().await;
        let delivery = granter
            .deposit_welcome(
                "http://127.0.0.1:9",
                address(Kind::Device, &id.0),
                &welcome,
                now,
            )
            .await;
        assert!(
            matches!(delivery, Some(Delivery::Delayed(_))),
            "{delivery:?}"
        );
        assert_eq!(granter.waiting_deposits().await, 1);

        granter.close().await.unwrap();
        let granter = open().await;
        clock.advance(retry_bound(1) + 1);
        granter.deposit_upkeep().await;
        assert_eq!(granter.waiting_deposits().await, 1, "kept to go again");
        let waiting = granter.engine().links().waiting(&id, &space).unwrap();
        assert_eq!(waiting.deposited.len(), 1);
        assert_eq!(waiting.deposited[0].2, 1, "counted once");

        // An attempt holds the deposit when the roster drops the recipient.
        let (deposit, record, at_rest) = granter.kept_deposits().await.remove(0);
        assert!(at_rest);
        assert!(granter.claim_deposit(deposit));
        granter
            .engine()
            .remove(space, MemberRef::device(id))
            .await
            .unwrap();
        clock.advance(retry_bound(2) + 1);
        granter.deposit_upkeep().await;
        assert!(granter.engine().links().waiting(&id, &space).is_none());
        assert_eq!(granter.waiting_deposits().await, 0, "dropped with it");
        let delivery = granter.attempt_deposit(deposit, record, true).await;
        granter.release_deposit(deposit);
        assert!(matches!(delivery, Delivery::Delayed(_)), "{delivery:?}");
        assert_eq!(granter.waiting_deposits().await, 0, "not kept again");

        granter.close().await.unwrap();
        let granter = open().await;
        assert_eq!(granter.waiting_deposits().await, 0);
        assert!(granter.engine().links().waiting(&id, &space).is_none());
        for device in [granter, member] {
            device.close().await.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connector that opens no connection to a peer: a deposit is
    /// unanswered, or, with `unsupported`, refused for good.
    struct NoPeer {
        unsupported: bool,
    }

    impl crate::advanced::Connect for NoPeer {
        fn connect(
            &self,
            _: crate::device::Engine,
            _: String,
            _: Vec<frasil_events::EventId>,
        ) -> frasil_store::BoxFuture<'static, crate::Result<crate::peer::PeerHandle>> {
            Box::pin(async { Err(crate::Error::Connection("no peer".into())) })
        }

        fn bare(
            &self,
            _: crate::device::Engine,
            _: String,
        ) -> frasil_store::BoxFuture<'static, crate::Result<crate::peer::Bare>> {
            let unsupported = self.unsupported;
            Box::pin(async move {
                Err(if unsupported {
                    crate::Error::Unsupported("no connection of the device's own")
                } else {
                    crate::Error::Connection("no peer".into())
                })
            })
        }
    }

    /// A deposit at "https://peer.example" kept at rest, never attempted.
    async fn kept_deposit(device: &Device) -> ([u8; 16], frasil_store::DepositRecord) {
        let first = device.engine().reading().await.unwrap();
        let record = frasil_store::DepositRecord {
            peer: "https://peer.example".into(),
            address: [9; 32],
            item: b"a sealed item".to_vec(),
            first,
            attempts: 0,
            next: first.timeline,
            token: None,
        };
        let id = [7; 16];
        device.keep_deposit(&id, &record, true).await.unwrap();
        (id, record)
    }

    /// The first event `wanted` picks from `events` within `wait`.
    async fn reported(
        events: &mut crate::Events,
        wait: std::time::Duration,
        wanted: impl Fn(&crate::Event) -> bool,
    ) -> Option<crate::Event> {
        tokio::time::timeout(wait, async {
            loop {
                match events.next().await {
                    Some(event) if wanted(&event) => return Some(event),
                    Some(_) => {}
                    None => return None,
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// An attempt whose store fails to keep the deposit again reports it
    /// delayed all the same: the deposit stands at rest as it was, and
    /// was not dropped (transport.md, "A sender keeps what was refused").
    #[tokio::test]
    async fn a_store_that_fails_to_keep_a_deposit_again_leaves_it_delayed() {
        use crate::advanced::{AdapterRegistry, Platform};
        use crate::welcomes::tests::Refusing;
        use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, Store};
        let store = Arc::new(Refusing {
            inner: MemoryStore::new(),
            refuse: std::sync::atomic::AtomicBool::new(false),
        });
        let platform = Platform::new(
            Arc::clone(&store) as Arc<dyn Store>,
            Arc::new(MemorySlot::new()) as Arc<dyn DeviceBoundSlot>,
        );
        let (engine, _) =
            crate::device::Engine::create(platform, &[4; 32], AdapterRegistry::with_builtins())
                .await
                .unwrap();
        let device = Device::from_engine(
            engine,
            Options::new()
                .never_restored()
                .connect_with(Arc::new(NoPeer { unsupported: false })),
        )
        .unwrap();
        let mut events = device.events();
        let (id, record) = kept_deposit(&device).await;
        store
            .refuse
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let delivery = device.attempt_deposit(id, record, true).await;
        assert!(
            matches!(delivery, super::super::deposits::Delivery::Delayed(_)),
            "{delivery:?}"
        );
        let delayed = reported(&mut events, std::time::Duration::from_secs(5), |e| {
            matches!(e, crate::Event::Delayed { .. })
        })
        .await;
        assert!(delayed.is_some(), "reported delayed");
        assert_eq!(device.waiting_deposits().await, 1, "kept as it was");
    }

    /// A deposit refused for good is reported undelivered only while its
    /// record stood: one dropped while the attempt was under way, as that
    /// of a welcome that ended, is not (admission.md, 3.10 Welcomes, "A
    /// welcome that waits").
    #[tokio::test]
    async fn a_dropped_deposit_refused_for_good_is_not_reported_undelivered() {
        let device = Device::open_with(
            Storage::Memory,
            &[5; 32],
            Options::new()
                .never_restored()
                .connect_with(Arc::new(NoPeer { unsupported: true })),
        )
        .await
        .unwrap();
        let mut events = device.events();
        let undelivered = |e: &crate::Event| matches!(e, crate::Event::Undelivered { .. });

        let (id, record) = kept_deposit(&device).await;
        let delivery = device.attempt_deposit(id, record, true).await;
        assert_eq!(
            delivery,
            super::super::deposits::Delivery::Refused("unsupported".into())
        );
        assert!(
            reported(&mut events, std::time::Duration::from_secs(5), undelivered)
                .await
                .is_some(),
            "a deposit that stood is reported"
        );

        let (id, record) = kept_deposit(&device).await;
        assert!(device.engine().forget_deposit(&id).await.unwrap());
        let delivery = device.attempt_deposit(id, record, true).await;
        assert_eq!(
            delivery,
            super::super::deposits::Delivery::Refused("unsupported".into())
        );
        assert!(
            reported(&mut events, std::time::Duration::from_secs(1), undelivered)
                .await
                .is_none(),
            "a dropped deposit is not reported"
        );
        device.close().await.unwrap();
    }

    /// In a space kept in memory only, a welcome a member connection ends,
    /// as when its recipient attaches the space, takes the deposits of it
    /// the device keeps in memory: the next upkeep drops them, and they go
    /// no further (admission.md, 3.10 Welcomes, "A welcome that waits").
    #[cfg(feature = "ext-guests")]
    #[tokio::test]
    async fn a_welcome_a_member_connection_ends_takes_its_deposits_kept_in_memory() {
        let options = || {
            Options::new()
                .loopback()
                .never_restored()
                .connect_with(Arc::new(NoPeer { unsupported: false }))
        };
        let granter = Device::open_with(Storage::Memory, &[9; 32], options())
            .await
            .unwrap();
        let member = Device::open_with(Storage::Memory, &[10; 32], options())
            .await
            .unwrap();
        let space = admitted(&granter, &member).await;
        let (engine, id) = (granter.engine(), member.engine().device_id());
        engine.keep_in_memory(&space).await.unwrap();
        let welcome = engine.links().waiting(&id, &space).unwrap();
        let now = engine.welcome_time().await;
        let delivery = granter
            .deposit_welcome(
                "https://peer.example",
                address(Kind::Device, &id.0),
                &welcome,
                now,
            )
            .await;
        assert!(
            matches!(delivery, Some(super::super::deposits::Delivery::Delayed(_))),
            "{delivery:?}"
        );
        assert_eq!(granter.waiting_deposits().await, 1, "kept in memory");
        assert!(
            engine
                .device_records(frasil_store::Table::Deposit)
                .await
                .unwrap()
                .is_empty()
        );

        // What a member connection does once the recipient attaches.
        assert_eq!(engine.end_welcomes(id, &[space]).await.len(), 1);
        granter.deposit_upkeep().await;
        assert_eq!(granter.waiting_deposits().await, 0);

        for device in [granter, member] {
            device.close().await.unwrap();
        }
    }
}
