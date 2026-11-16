//! Admission of an already known device, using ordinary grants and sealed
//! welcomes (roster.md, "A device's keys"; admission.md, "Welcomes";
//! rationale.md, "Reusing an authenticated device for independent
//! grants"). No exchange mailbox or new wire format is needed.

use super::exchange::{POLL_EVERY, PUBLISH_DEADLINE, SPACE_DEADLINE, collect_own, peer_at};
use super::{Device, MemberId, Peer, SpaceId};
use crate::{Error, Result};

use frasil_admission::welcome::Welcome;
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Status};
use frasil_transport::mailbox::{Kind, address};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

// Leave room under the peer's default 64 presentations per connection
// per minute for read/store credentials and their initial retries.
const SPACES_PER_CONNECTION: usize = 8;

/// Connections owned by this call close even when its future is dropped.
#[derive(Debug, Default)]
struct BatchConnections(Vec<Peer>);

impl Drop for BatchConnections {
    fn drop(&mut self) {
        for peer in &self.0 {
            peer.close();
        }
    }
}

/// Progress of one space's admission, independent of the other spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceAdmission {
    /// The space.
    pub space: SpaceId,
    /// Whether the grant was committed (sender) or verified (receiver).
    /// A sender's delivery can fail after its atomic grant committed.
    pub granted: bool,
    /// Whether delivery (sender) or verification (receiver) succeeded. A
    /// sender's welcome that the peer did not take yet is
    /// [`Error::Delayed`](crate::Error::Delayed): the device keeps it and
    /// sends it again by itself.
    pub result: Result<()>,
}

impl Device {
    /// Admits a device already authenticated in `known_space` to each of
    /// `spaces` at `Administer` through its mailbox at `url`. New members
    /// receive history; existing members retain their history boundary.
    /// Select `member` by its previously authenticated device ID, never by a
    /// display name. Its keys are read once from that space's direct grant,
    /// which names them by that device ID: every new grant carries the same
    /// keys, which each replica checks by their hash. What authenticates the
    /// device is the roster this device trusts, where it learned the ID.
    /// With no direct grant yet, use one ordinary code admission into the
    /// first target, then batch the remaining targets using that space.
    /// The member administers each space at `rank`, at most this device's
    /// own rank there (roster.md, 2.3 Changes, "Ranks").
    /// No further code exchange is needed. The recipient calls
    /// [`Device::receive_spaces_via_peer`] with this device's authenticated
    /// device ID and the expected spaces.
    ///
    /// Authority is checked independently in each space at signing time.
    /// Each grant is atomic. `progress` runs after each attempt, including
    /// failures; later spaces are still attempted. Duplicate spaces are
    /// attempted once. On interrupted delivery, retry failed or unfinished
    /// spaces: an existing member is promoted, or simply receives another
    /// delivery when it already administers. An existing member retains
    /// its history boundary; a new member is granted with history.
    /// Success means the peer holds the grant
    /// and its sealed welcome, not that the recipient has collected it.
    ///
    /// # Errors
    ///
    /// A missing source space or directly granted device, or a connection
    /// failure before the batch starts. Per-space errors are in the report.
    pub async fn admit_spaces_via_peer(
        &self,
        url: &str,
        known_space: SpaceId,
        member: MemberId,
        rank: u8,
        spaces: &[SpaceId],
        mut progress: impl FnMut(&SpaceAdmission),
    ) -> Result<Vec<SpaceAdmission>> {
        let identity = DeviceId(*member.as_bytes());
        // The new grants rest on the grant in the known space: its keys,
        // and its `via`, so that a device admitted by lookup or by no step
        // is not shown as admitted by a compared code (admission.md, 2.1
        // The admission event).
        let (keys, via) = self
            .engine()
            .read(&known_space.event(), |replica| {
                replica
                    .roster()
                    .state(&MemberRef::device(identity))
                    .and_then(|state| Some((state.keys.clone()?, state.via)))
            })
            .await?
            .ok_or(Error::NotAllowed(
                "authenticate a directly granted device first",
            ))?;
        let peer = peer_at(self, url).await?;
        let mut reports = Vec::new();
        let mut ready = Vec::new();
        let mut seen = BTreeSet::new();
        for space in spaces.iter().copied().filter(|id| seen.insert(*id)) {
            let mut report = SpaceAdmission {
                space,
                granted: false,
                result: Ok(()),
            };
            let prepared: Result<_> = async {
                let id = space.event();
                if !self.engine().reaches_parent_of(&id, &identity).await {
                    return Err(Error::NotAllowed(
                        "the device does not reach the restricted space's parent",
                    ));
                }
                let existing = self
                    .engine()
                    .read(&id, |replica| {
                        if replica.level_of(&self.engine().device_id()) != Some(Level::Administer) {
                            return Err(Error::NotAllowed("admitting needs administer"));
                        }
                        // A member of the same device ID holds the same keys,
                        // which its ID commits to.
                        let member = replica.roster().state(&MemberRef::device(identity));
                        if let Some(member) = member
                            && member.session.is_some()
                        {
                            return Err(Error::NotAllowed("the existing member is a guest"));
                        }
                        Ok(member.map(|member| member.level))
                    })
                    .await??;
                let granted = if existing != Some(Level::Administer) {
                    let change = if existing.is_some() {
                        Change::raise(MemberRef::device(identity), rank)
                    } else {
                        Change::grant_administrator(
                            (*keys).clone(),
                            rank,
                            HistoryMode::WithHistory,
                            via,
                        )
                    };
                    Some(self.engine().sign_roster_with(id, vec![change]).await?)
                } else {
                    None
                };
                report.granted = true;
                // A new grant (or a promotion from read) already delivers
                // keys. Other promotions and retries need a key delivery.
                let (event, wraps) = match granted {
                    Some((event, wraps)) if wraps.contains_key(&identity) => (event, wraps),
                    _ => self.engine().deliver_administrator(id, &keys).await?,
                };
                let wrap = wraps
                    .get(&identity)
                    .ok_or(Error::NotAllowed("the grant delivered no keys"))?;
                let welcome = Welcome {
                    space: id.0,
                    event,
                    key_name: wrap.key_name.encode(),
                    grant_name: wrap
                        .grant_name
                        .as_ref()
                        .map(|name| name.encode())
                        .unwrap_or_default(),
                    wrap: wrap.wrap.clone(),
                    approver: self.engine().device_id(),
                    peers: self
                        .engine()
                        .welcome_hints(&id, &[url.trim_end_matches('/').to_owned()])
                        .await,
                    snapshot: None,
                };
                self.present(id);
                let sealed = welcome
                    .seal_with(&keys, &*self.engine().platform().draw::<64>()?)
                    .map_err(Error::class)?;
                Ok((id, event, sealed))
            }
            .await;
            let delivery = match prepared {
                Ok(delivery) => Some(delivery),
                Err(error) => {
                    report.result = Err(error);
                    None
                }
            };
            ready.push((report, delivery));
        }
        let mut connections = BatchConnections::default();
        let mut failures = BTreeMap::new();
        let prepared: Vec<_> = ready
            .iter()
            .filter_map(|(report, delivery)| delivery.as_ref().map(|_| report.space))
            .collect();
        for group in prepared.chunks(SPACES_PER_CONNECTION) {
            match self
                .open_connection(url, group.iter().map(|space| space.event()).collect())
                .await
            {
                Ok(peer) => connections.0.push(peer),
                Err(error) => {
                    for space in group {
                        failures.insert(*space, error.clone());
                    }
                }
            }
        }
        // Let every prepared space sync while earlier ones await their
        // acknowledgement, instead of serializing a round trip per grant.
        for (mut report, delivery) in ready {
            if let Some((id, event, sealed)) = delivery {
                report.result = async {
                    if let Some(error) = failures.remove(&report.space) {
                        return Err(error);
                    }
                    self.publish_on(&connections, id, event).await?;
                    // A welcome the peer does not take now is kept and goes
                    // again: `Error::Delayed`, with `granted` set.
                    self.deposit(peer.url(), address(Kind::Device, &identity.0), sealed, true)
                        .await
                        .into_result()
                }
                .await;
            }
            progress(&report);
            reports.push(report);
        }
        Ok(reports)
    }

    /// Stores a space's admission event and the twin it cites, and waits
    /// until a peer holds the event. A peer holds a grant back until its
    /// twin arrives, which may be on an administration connection the
    /// device opens later by itself: the event is offered again on the
    /// batch's sync connections every second until it is acknowledged.
    async fn publish_on(
        &self,
        connections: &BatchConnections,
        space: EventId,
        event: EventId,
    ) -> Result<()> {
        const TICK: Duration = Duration::from_millis(50);
        const REOFFER_EVERY: Duration = Duration::from_secs(1);
        let mut waited = Duration::ZERO;
        let mut since = REOFFER_EVERY;
        while self.engine().outbox(&space).await.contains(&event) {
            if waited >= PUBLISH_DEADLINE {
                return Err(Error::Connection(
                    "the admission event did not become durable at a peer".into(),
                ));
            }
            if since >= REOFFER_EVERY {
                self.administer(space).await;
                for connection in &connections.0 {
                    connection.handle().reoffer(space);
                }
                since = Duration::ZERO;
            }
            self.sleep(TICK).await;
            waited += TICK;
            since += TICK;
        }
        Ok(())
    }

    /// Collects ordinary sealed welcomes from the already authenticated
    /// `approver`, for exactly `spaces`, and verifies each grant at
    /// `Administer` against the fetched roster and this
    /// device's keys. No field in a welcome is trusted on its own.
    ///
    /// Each space is reported independently through `progress` and the
    /// returned vector. Missing welcomes time out after 60 seconds. Retry
    /// failed spaces after reconnecting; the mailbox is collected from its
    /// beginning, so earlier deliveries are not lost when a call drops.
    /// The expected identities and spaces come from the application's
    /// authenticated context, not from unsolicited mailbox contents.
    ///
    /// # Errors
    ///
    /// Connection failures before collection begins. Per-space failures
    /// and missing welcomes are in the report.
    pub async fn receive_spaces_via_peer(
        &self,
        url: &str,
        approver: MemberId,
        spaces: &[SpaceId],
        mut progress: impl FnMut(&SpaceAdmission),
    ) -> Result<Vec<SpaceAdmission>> {
        let peer = self.open_connection(url, Vec::new()).await?;
        let mut connections = BatchConnections(vec![peer.clone()]);
        let mut remaining: BTreeSet<_> = spaces.iter().copied().collect();
        let mut pending: BTreeMap<SpaceId, (Welcome, Duration)> = BTreeMap::new();
        let mut reports = Vec::new();
        let mut after = None;
        let mut waited = Duration::ZERO;
        while !remaining.is_empty() {
            let latest = match collect_latest_welcomes(
                self, &peer, approver, &remaining, &mut after,
            )
            .await
            {
                Ok(latest) => latest,
                Err(error) => {
                    for space in remaining {
                        let report = SpaceAdmission {
                            space,
                            granted: false,
                            result: Err(error.clone()),
                        };
                        progress(&report);
                        reports.push(report);
                    }
                    return Ok(reports);
                }
            };
            let mut fetching = Vec::new();
            for (space, welcome) in latest {
                if pending.get(&space).is_some_and(|(held, _)| {
                    held.event == welcome.event && held.wrap == welcome.wrap
                }) {
                    continue;
                }
                let started = pending.get(&space).map_or(waited, |(_, started)| *started);
                match self.engine().begin_welcomed(&welcome).await {
                    Ok(id) => {
                        fetching.push(id);
                        pending.insert(space, (welcome, started));
                    }
                    Err(error) => {
                        remaining.remove(&space);
                        let report = SpaceAdmission {
                            space,
                            granted: false,
                            result: Err(error),
                        };
                        progress(&report);
                        reports.push(report);
                    }
                }
            }
            for group in fetching.chunks(SPACES_PER_CONNECTION) {
                match self.open_connection(url, group.to_vec()).await {
                    Ok(peer) => connections.0.push(peer),
                    Err(error) => {
                        for id in group {
                            let space = SpaceId::of(*id);
                            pending.remove(&space);
                            remaining.remove(&space);
                            let report = SpaceAdmission {
                                space,
                                granted: false,
                                result: Err(error.clone()),
                            };
                            progress(&report);
                            reports.push(report);
                        }
                    }
                }
            }
            // Every welcome starts fetching before any one of them is
            // awaited. Each space still has an independent verification.
            let mut still = BTreeMap::new();
            for (space, (welcome, started)) in pending {
                let result = match verify_welcome(self, &welcome, approver).await {
                    Err(Error::Class("Pending" | "Sealed"))
                        if waited - started < SPACE_DEADLINE =>
                    {
                        still.insert(space, (welcome, started));
                        continue;
                    }
                    Err(Error::Class("Pending" | "Sealed")) => Err(Error::Timeout),
                    result => result,
                };
                if result.is_ok() {
                    let _ = self
                        .engine()
                        .keep_peer_hints(&space.event(), &welcome.peers)
                        .await;
                }
                remaining.remove(&space);
                let report = SpaceAdmission {
                    space,
                    granted: result.is_ok(),
                    result,
                };
                progress(&report);
                reports.push(report);
            }
            pending = still;
            if waited >= SPACE_DEADLINE {
                let missing: Vec<_> = remaining
                    .iter()
                    .filter(|space| !pending.contains_key(space))
                    .copied()
                    .collect();
                for space in missing {
                    remaining.remove(&space);
                    let report = SpaceAdmission {
                        space,
                        granted: false,
                        result: Err(Error::Timeout),
                    };
                    progress(&report);
                    reports.push(report);
                }
            }
            if remaining.is_empty() {
                break;
            }
            self.sleep(POLL_EVERY).await;
            waited += POLL_EVERY;
        }
        Ok(reports)
    }
}

/// All currently readable pages precede candidate selection, so a stale
/// delivery cannot mask a fresh one when an interrupted batch is retried.
async fn collect_latest_welcomes(
    device: &Device,
    peer: &Peer,
    approver: MemberId,
    expected: &BTreeSet<SpaceId>,
    after: &mut Option<[u8; 16]>,
) -> Result<BTreeMap<SpaceId, Welcome>> {
    let mut latest = BTreeMap::new();
    loop {
        let items = collect_own(device, peer, *after).await?;
        let Some((last, _)) = items.last() else {
            return Ok(latest);
        };
        if *after == Some(*last) {
            return Err(Error::Connection(
                "the mailbox cursor did not advance; retry collection".into(),
            ));
        }
        *after = Some(*last);
        latest.extend(latest_welcomes(
            device,
            approver,
            expected,
            items.into_iter().map(|(_, item)| item),
        ));
    }
}

/// These are untrusted candidates until `verify_welcome` accepts one.
fn latest_welcomes(
    device: &Device,
    approver: MemberId,
    expected: &BTreeSet<SpaceId>,
    items: impl IntoIterator<Item = Vec<u8>>,
) -> BTreeMap<SpaceId, Welcome> {
    let mut latest = BTreeMap::new();
    for item in items {
        let Ok(welcome) = Welcome::open(
            &item,
            &device.engine().device_id(),
            device.engine().xwing_seed(),
        ) else {
            continue;
        };
        let space = SpaceId::of(EventId(welcome.space));
        if welcome.approver.0 == *approver.as_bytes() && expected.contains(&space) {
            latest.insert(space, welcome);
        }
    }
    latest
}

/// admission.md, "Welcomes": the valid event must hold exactly this wrap.
async fn verify_welcome(device: &Device, welcome: &Welcome, approver: MemberId) -> Result<()> {
    let identity = device.engine().device_id();
    let own = device.engine().public_keys().clone();
    device
        .engine()
        .read(&EventId(welcome.space), |replica| {
            let event = replica
                .event(welcome.event)
                .ok_or(Error::Class("Pending"))?;
            if event.kind() != frasil_events::kind::SPACE || event.is_genesis() {
                return Err(Error::Class("Malformed"));
            }
            if event.author().0 != *approver.as_bytes() {
                return Err(Error::Class("WrongApprover"));
            }
            match replica.status(&welcome.event) {
                Some(Status::Valid(_)) => {}
                Some(Status::Void { class, .. }) => return Err(Error::Class(class.name())),
                None => return Err(Error::Class("Pending")),
            }
            if !replica.authored_as_administrator(&welcome.event) {
                return Err(Error::NotAllowed(
                    "the welcome's author did not administer at its place",
                ));
            }
            // A valid event's signature verified in full.
            let verified = replica
                .verified_event(&welcome.event)
                .ok_or(Error::Class("Pending"))?;
            let visible =
                frasil_keys::body::VisiblePart::read(verified.body(), event.author(), event.seq())
                    .map_err(Error::class)?;
            let matches = visible.deliveries.iter().any(|delivery| {
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
            if !matches {
                return Err(Error::Class("Malformed"));
            }
            let member = replica
                .roster()
                .state(&MemberRef::device(identity))
                .ok_or(Error::Class("Pending"))?;
            if member.level != Level::Administer
                || member.session.is_some()
                || member.keys.as_deref().is_none_or(|held| *held != own)
            {
                return Err(Error::Class("OfferMismatch"));
            }
            Ok(())
        })
        .await?
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use frasil_space::Via;

    #[tokio::test]
    async fn a_welcome_needs_its_exact_wrap_a_valid_delivery_and_an_administrator() {
        let alice = Device::open(super::super::Storage::Memory, &[31; 32])
            .await
            .unwrap();
        let bob = Device::open(super::super::Storage::Memory, &[32; 32])
            .await
            .unwrap();
        let space = alice.create_space().await.unwrap();
        let id = space.id().event();
        let identity = bob.engine().device_id();
        alice
            .engine()
            .grant_administrator(
                id,
                bob.engine().public_keys().clone(),
                255,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let (event, wraps) = alice
            .engine()
            .deliver_with(
                id,
                vec![crate::writer::Recipient {
                    keys: bob.engine().public_keys().clone(),
                    writes: true,
                    propagates: true,
                }],
            )
            .await
            .unwrap();
        let wrap = &wraps[&identity];
        let welcome = Welcome {
            space: id.0,
            event,
            key_name: wrap.key_name.encode(),
            grant_name: wrap
                .grant_name
                .as_ref()
                .map(|name| name.encode())
                .unwrap_or_default(),
            wrap: wrap.wrap.clone(),
            approver: alice.engine().device_id(),
            peers: Vec::new(),
            snapshot: None,
        };
        bob.engine().begin_welcomed(&welcome).await.unwrap();
        bob.engine()
            .ingest(id, alice.engine().events(&id).await)
            .await
            .unwrap();
        verify_welcome(&bob, &welcome, alice.id()).await.unwrap();
        assert_eq!(
            verify_welcome(&bob, &welcome, bob.id()).await,
            Err(Error::Class("WrongApprover"))
        );
        let mut changed = welcome.clone();
        changed.wrap[0] ^= 1;
        assert_eq!(
            verify_welcome(&bob, &changed, alice.id()).await,
            Err(Error::Class("Malformed"))
        );
        alice
            .engine()
            .sign_roster(
                id,
                vec![Change::set_level(MemberRef::device(identity), Level::Write)],
            )
            .await
            .unwrap();
        bob.engine()
            .ingest(id, alice.engine().events(&id).await)
            .await
            .unwrap();
        assert_eq!(
            verify_welcome(&bob, &welcome, alice.id()).await,
            Err(Error::Class("OfferMismatch"))
        );
        assert!(matches!(
            alice
                .engine()
                .deliver_administrator(id, bob.engine().public_keys())
                .await,
            Err(Error::NotAllowed(_))
        ));
        // A writer may legitimately deliver keys, but cannot act as the
        // administrator for this batch, even for an existing administrator.
        let (event, wraps) = bob
            .engine()
            .deliver_with(
                id,
                vec![crate::writer::Recipient {
                    keys: alice.engine().public_keys().clone(),
                    writes: true,
                    propagates: true,
                }],
            )
            .await
            .unwrap();
        let wrap = &wraps[&alice.engine().device_id()];
        let from_writer = Welcome {
            event,
            key_name: wrap.key_name.encode(),
            grant_name: wrap
                .grant_name
                .as_ref()
                .map(|name| name.encode())
                .unwrap_or_default(),
            wrap: wrap.wrap.clone(),
            approver: bob.engine().device_id(),
            ..welcome
        };
        alice
            .engine()
            .ingest(id, bob.engine().events(&id).await)
            .await
            .unwrap();
        assert!(
            alice
                .engine()
                .read(&id, |replica| matches!(
                    replica.status(&event),
                    Some(Status::Valid(_))
                ))
                .await
                .unwrap()
        );
        assert!(matches!(
            verify_welcome(&alice, &from_writer, bob.id()).await,
            Err(Error::NotAllowed(_))
        ));
        // A later administrator delivery supersedes that old writer's
        // welcome when both remain in the mailbox during a retry.
        alice
            .engine()
            .sign_roster(id, vec![Change::raise(MemberRef::device(identity), 255)])
            .await
            .unwrap();
        bob.engine()
            .ingest(id, alice.engine().events(&id).await)
            .await
            .unwrap();
        let (event, wraps) = bob
            .engine()
            .deliver_administrator(id, alice.engine().public_keys())
            .await
            .unwrap();
        let wrap = &wraps[&alice.engine().device_id()];
        let fresh = Welcome {
            event,
            key_name: wrap.key_name.encode(),
            grant_name: wrap
                .grant_name
                .as_ref()
                .map(|name| name.encode())
                .unwrap_or_default(),
            wrap: wrap.wrap.clone(),
            ..from_writer.clone()
        };
        alice
            .engine()
            .ingest(id, bob.engine().events(&id).await)
            .await
            .unwrap();
        let items = [
            from_writer
                .seal_with(alice.engine().public_keys(), &[41; 64])
                .unwrap(),
            fresh
                .seal_with(alice.engine().public_keys(), &[42; 64])
                .unwrap(),
        ];
        let latest = latest_welcomes(&alice, bob.id(), &BTreeSet::from([space.id()]), items);
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[&space.id()].event, fresh.event);
        verify_welcome(&alice, &latest[&space.id()], bob.id())
            .await
            .unwrap();
        alice.close().await.unwrap();
        bob.close().await.unwrap();
    }
}
