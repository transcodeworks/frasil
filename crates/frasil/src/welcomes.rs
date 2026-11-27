//! The welcomes this device signed that wait for their newcomer
//! (admission.md, 3.10 Welcomes, "A welcome that waits"): sealed to the
//! newcomer's keys, kept at rest as `welcome` records in the space's log
//! (at-rest.md, "Tables") and in memory in [`Links`](crate::links::Links),
//! loaded when the device opens, and ended by an admitted attach, a roster
//! that no longer reaches the newcomer, the bound of 256 or
//! `welcome_retention`.

use crate::at_rest::Batch;
use crate::deposits::DevicePut;
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::links::{WAITING, Waiting, origin};
use crate::writer::WrapOf;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_store::tables::{
    LogKind, MAX_PEER_URL, MAX_WELCOME_PEERS, Table, TableValue, WelcomeRecord,
};
use std::collections::BTreeMap;

/// A record to put in a space's log: its table, item and value.
pub(crate) type LogRecord = (Table, Vec<u8>, TableValue);

/// The `welcome` record of a waiting welcome, its item the newcomer's
/// device ID. A record names at most 64 peers, each by an origin of 1 to
/// 512 bytes: a peer past them, or with a longer origin, is known in
/// memory only, and deposited at again after a restart.
pub(crate) fn welcome_record(welcome: &Waiting) -> LogRecord {
    (
        Table::Welcome,
        welcome.recipient.0.to_vec(),
        TableValue::Welcome(WelcomeRecord {
            event: welcome.event.0,
            sealed: welcome.sealed.clone(),
            since: welcome.since,
            deposited: welcome
                .deposited
                .iter()
                .filter(|(peer, _)| (1..=MAX_PEER_URL).contains(&peer.len()))
                .take(MAX_WELCOME_PEERS)
                .cloned()
                .collect(),
        }),
    )
}

impl Engine {
    /// `T` on the device's timeline now, at which a welcome kept now is
    /// kept.
    pub(crate) async fn welcome_time(&self) -> u64 {
        let mut state = self.lock().await;
        self.timeline_now(&mut state)
    }

    /// The welcome naming `event`, which holds `wraps`, for each device
    /// of `recipients` the delivery wraps for, this one aside, sealed to
    /// its keys (admission.md, "The welcome"), with `hints` as its peer
    /// hints and kept at `since`.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; a welcome that does not seal.
    pub(crate) fn seal_welcomes(
        &self,
        space: EventId,
        event: EventId,
        wraps: &BTreeMap<DeviceId, WrapOf>,
        recipients: &[DeviceKeys],
        hints: &[String],
        since: u64,
    ) -> Result<Vec<Waiting>> {
        let me = self.device_id();
        let mut sealed = Vec::new();
        for keys in recipients {
            let device = keys.device_id();
            let Some(wrap) = wraps.get(&device).filter(|_| device != me) else {
                continue;
            };
            let welcome = frasil_admission::welcome::Welcome {
                space: space.0,
                event,
                key_name: wrap.key_name.encode(),
                grant_name: wrap
                    .grant_name
                    .as_ref()
                    .map(frasil_keys::KeyName::encode)
                    .unwrap_or_default(),
                wrap: wrap.wrap.clone(),
                approver: me,
                peers: hints.to_vec(),
                snapshot: None,
            };
            sealed.push(Waiting {
                recipient: device,
                space,
                event,
                sealed: welcome
                    .seal_with(keys, &*self.platform().draw::<64>()?)
                    .map_err(Error::class)?,
                since,
                deposited: Vec::new(),
                refused: Vec::new(),
            });
        }
        Ok(sealed)
    }

    /// Welcomes whose records a commit has kept: they wait, and the
    /// records of those the bound passes go. The record of one that takes
    /// the place of another welcome for the same recipient and space is
    /// written again, so that a deposit of the other one, committed since,
    /// does not stand at rest in its place.
    pub(crate) async fn waiting_kept(&self, welcomes: Vec<Waiting>) {
        let mut state = self.lock().await;
        let mut batch = Batch::default();
        {
            let mut links = self.links();
            let mut replacing = Vec::new();
            let mut passed = Vec::new();
            for welcome in welcomes {
                if links
                    .waiting(&welcome.recipient, &welcome.space)
                    .is_some_and(|w| !w.same(&welcome))
                {
                    replacing.push((welcome.recipient, welcome.space));
                }
                passed.extend(links.wait(welcome));
            }
            for (recipient, space) in replacing {
                if let Some(welcome) = links.waiting(&recipient, &space) {
                    let (table, item, value) = welcome_record(&welcome);
                    let _ = state.vault.put(&mut batch, &space.0, table, &item, &value);
                }
            }
            for welcome in &passed {
                state.vault.delete(
                    &mut batch,
                    &welcome.space.0,
                    Table::Welcome,
                    &welcome.recipient.0,
                );
            }
        }
        if !batch.is_empty() {
            let _ = state.vault.commit(batch).await;
        }
    }

    /// Keeps welcomes of `space` at rest in one commit, then waiting.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn keep_welcomes(&self, space: EventId, welcomes: Vec<Waiting>) -> Result<()> {
        if welcomes.is_empty() {
            return Ok(());
        }
        {
            let mut state = self.lock().await;
            let mut batch = Batch::default();
            for (table, item, value) in welcomes.iter().map(welcome_record) {
                state
                    .vault
                    .put(&mut batch, &space.0, table, &item, &value)?;
            }
            state.vault.commit(batch).await?;
        }
        self.waiting_kept(welcomes).await;
        Ok(())
    }

    /// Keeps a deposit of `welcome` at the peer at `url`: `deposit`, its
    /// `deposit` record, and the welcome's `welcome` record naming the
    /// peer with the timeline's `T` now, in one commit (at-rest.md,
    /// "Tables", `welcome`). Both are built under the device's lock from
    /// the welcome as it waits then, so that two deposits at once each
    /// keep the other's peer, and the waiting welcome in memory names the
    /// peer only once the commit is made. In a space kept in memory only,
    /// nothing is committed, and the deposit is the caller's to keep in
    /// memory.
    ///
    /// Returns `None`, keeping nothing, when `welcome` no longer waits;
    /// otherwise whether the deposit is kept at rest.
    ///
    /// # Errors
    ///
    /// The store's: then nothing is kept, and the welcome in memory does
    /// not name the peer.
    pub(crate) async fn keep_welcome_deposit(
        &self,
        welcome: &Waiting,
        url: &str,
        (table, item, value): DevicePut,
    ) -> Result<Option<bool>> {
        let mut state = self.lock().await;
        let now = self.timeline_now(&mut state);
        let url = origin(url);
        let Some(mut kept) = self
            .links()
            .waiting(&welcome.recipient, &welcome.space)
            .filter(|w| w.same(welcome))
        else {
            return Ok(None);
        };
        kept.deposit_at(url, now);
        let at_rest = !state.vault.is_memory_only(&welcome.space.0);
        if at_rest {
            let mut batch = Batch::default();
            state.vault.put_device(&mut batch, table, &item, &value)?;
            let (table, item, value) = welcome_record(&kept);
            state
                .vault
                .put(&mut batch, &welcome.space.0, table, &item, &value)?;
            state.vault.commit(batch).await?;
        }
        if let Some(waiting) = self.links().same_mut(welcome) {
            waiting.deposit_at(url, now);
        }
        Ok(Some(at_rest))
    }

    /// The peer at `url` refused the deposit of `welcome` for good: the
    /// welcome's record names it no longer, and it is deposited there
    /// again after `welcome_redeposit`, or after a restart (admission.md,
    /// 3.10 Welcomes, "A welcome that waits").
    pub(crate) async fn welcome_deposit_refused(&self, welcome: &Waiting, url: &str) {
        let mut state = self.lock().await;
        let now = self.timeline_now(&mut state);
        let url = origin(url);
        let Some(mut kept) = self
            .links()
            .waiting(&welcome.recipient, &welcome.space)
            .filter(|w| w.same(welcome))
        else {
            return;
        };
        let named = kept.deposited.iter().any(|(peer, _)| peer == url);
        kept.refused_at(url, now);
        if named {
            let mut batch = Batch::default();
            let (table, item, value) = welcome_record(&kept);
            let written = state
                .vault
                .put(&mut batch, &welcome.space.0, table, &item, &value)
                .is_ok()
                && state.vault.commit(batch).await.is_ok();
            if !written {
                return;
            }
        }
        if let Some(waiting) = self.links().same_mut(welcome) {
            waiting.refused_at(url, now);
        }
    }

    /// The welcome for `recipient` and `space` waits no longer: the
    /// recipient attached the space, or the roster no longer reaches it.
    pub(crate) async fn end_welcome(&self, recipient: DeviceId, space: EventId) {
        let ended = self.links().delivered(&recipient, &space);
        if ended {
            self.drop_welcome_records(&[(recipient, space)]).await;
        }
    }

    /// Ends the welcomes kept `welcome_retention` or longer ago, on the
    /// device's timeline (admission.md, 3.10 Welcomes, "A welcome that
    /// waits").
    pub(crate) async fn expire_welcomes(&self) {
        let now = self.welcome_time().await;
        let old = self.links().expire_welcomes(now);
        self.drop_welcome_records(&old).await;
    }

    /// Deletes the records of welcomes that wait no longer. A record left
    /// by a failed commit goes when the device next opens, past its age,
    /// or when the welcome ends again.
    async fn drop_welcome_records<W: Ended>(&self, ended: &[W]) {
        if ended.is_empty() {
            return;
        }
        let mut state = self.lock().await;
        let mut batch = Batch::default();
        for welcome in ended {
            let (recipient, space) = welcome.ended();
            state
                .vault
                .delete(&mut batch, &space.0, Table::Welcome, &recipient.0);
        }
        let _ = state.vault.commit(batch).await;
    }

    /// Loads the waiting welcomes from the `welcome` records of every space
    /// this device keeps, as the device opens: those kept
    /// `welcome_retention` or longer ago, and the oldest past 256, go.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn load_welcomes(&self) -> Result<()> {
        let mut state = self.lock().await;
        let now = self.timeline_now(&mut state);
        let spaces: Vec<[u8; 32]> = state
            .vault
            .logs()
            .filter(|(_, kind)| *kind == LogKind::Space)
            .map(|(log, _)| *log)
            .collect();
        let mut kept = Vec::new();
        for log in spaces {
            for (item, value) in state.vault.scan(&log, Table::Welcome).await? {
                let (TableValue::Welcome(record), Ok(recipient)) =
                    (value, <[u8; 32]>::try_from(&item[..]))
                else {
                    continue;
                };
                kept.push(Waiting {
                    recipient: DeviceId(recipient),
                    space: EventId(log),
                    event: EventId(record.event),
                    sealed: record.sealed,
                    since: record.since,
                    deposited: record.deposited,
                    refused: Vec::new(),
                });
            }
        }
        kept.sort_by_key(|welcome| welcome.since);
        let over = kept.len().saturating_sub(WAITING);
        let mut gone: Vec<Waiting> = kept.drain(..over).collect();
        let (old, young): (Vec<Waiting>, Vec<Waiting>) = kept
            .into_iter()
            .partition(|w| now.saturating_sub(w.since) >= crate::links::WELCOME_RETENTION);
        gone.extend(old);
        if !gone.is_empty() {
            let mut batch = Batch::default();
            for welcome in &gone {
                state.vault.delete(
                    &mut batch,
                    &welcome.space.0,
                    Table::Welcome,
                    &welcome.recipient.0,
                );
            }
            state.vault.commit(batch).await?;
        }
        drop(state);
        let mut links = self.links();
        for welcome in young {
            links.wait(welcome);
        }
        Ok(())
    }
}

/// A welcome that waits no longer, by its recipient and space.
trait Ended {
    fn ended(&self) -> (DeviceId, EventId);
}

impl Ended for Waiting {
    fn ended(&self) -> (DeviceId, EventId) {
        (self.recipient, self.space)
    }
}

impl Ended for (DeviceId, EventId) {
    fn ended(&self) -> (DeviceId, EventId) {
        *self
    }
}

#[cfg(all(test, feature = "iroh"))]
mod tests {
    //! The waiting welcomes at rest (admission.md, 3.10 Welcomes, "A
    //! welcome that waits"; at-rest.md, "Tables", `welcome`), on engines
    //! over one store that they open again.

    use super::*;
    use crate::advanced::{AdapterRegistry, Platform};
    use crate::platform::{Clock, ManualClock};
    use frasil_space::{HistoryMode, Level, Via};
    use frasil_store::{DeviceBoundSlot, MemorySlot, MemoryStore, Store};
    use std::sync::Arc;

    /// A store, a slot and a clock that outlive the engines opened on them.
    struct Medium {
        store: Arc<MemoryStore>,
        slot: Arc<MemorySlot>,
        clock: Arc<ManualClock>,
    }

    impl Medium {
        fn new() -> Self {
            Self {
                store: Arc::new(MemoryStore::new()),
                slot: Arc::new(MemorySlot::new()),
                clock: Arc::new(ManualClock::new(100, Some(1_800_000_000))),
            }
        }

        fn platform(&self) -> Platform {
            Platform::new(
                Arc::clone(&self.store) as Arc<dyn Store>,
                Arc::clone(&self.slot) as Arc<dyn DeviceBoundSlot>,
            )
            .with_clock(Arc::clone(&self.clock) as Arc<dyn Clock>)
        }

        async fn device(&self) -> (Engine, Vec<u8>) {
            let (engine, sealed) =
                Engine::create(self.platform(), &[4; 32], AdapterRegistry::with_builtins())
                    .await
                    .unwrap();
            (engine, sealed.to_vec())
        }

        async fn reopen(&self, engine: Engine, sealed: &[u8]) -> Engine {
            engine.keep_reading().await.unwrap();
            drop(engine);
            Engine::open(
                self.platform(),
                sealed,
                &[4; 32],
                AdapterRegistry::with_builtins(),
            )
            .await
            .unwrap()
        }
    }

    async fn other() -> Engine {
        Engine::create(
            Platform::memory(),
            &[7; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap()
        .0
    }

    /// `granter` admits `device`, which a space of its own grants directly,
    /// to a new space: that space.
    async fn admitted(granter: &Engine, device: &Engine) -> EventId {
        let known = granter.create_space().await.unwrap();
        granter
            .grant_device(
                known,
                device.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let space = granter.create_space().await.unwrap();
        granter
            .admit_member(space, known, device.device_id(), Level::Write, None)
            .await
            .unwrap();
        space
    }

    /// The `welcome` records of `space` in `engine`'s store.
    async fn records(engine: &Engine, space: EventId) -> Vec<(DeviceId, WelcomeRecord)> {
        let state = engine.lock().await;
        state
            .vault
            .scan(&space.0, Table::Welcome)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|(item, value)| match value {
                TableValue::Welcome(record) => Some((DeviceId(item.try_into().unwrap()), record)),
                _ => None,
            })
            .collect()
    }

    /// A grant's welcome is at rest once the grant returns, and waits
    /// again, the same welcome, when the device opens again.
    #[tokio::test]
    async fn a_grants_welcome_is_kept_at_rest_and_waits_after_a_restart() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let waiting = granter.links().waiting(&id, &space).unwrap();
        let kept = records(&granter, space).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, id);
        assert_eq!(kept[0].1.sealed, waiting.sealed);
        assert_eq!(EventId(kept[0].1.event), waiting.event);

        let granter = medium.reopen(granter, &sealed).await;
        let loaded = granter.links().waiting(&id, &space).unwrap();
        assert_eq!(loaded.sealed, waiting.sealed);
        assert_eq!(loaded.since, waiting.since);
        assert_eq!(granter.links().welcomes_for(&id).len(), 1);
    }

    /// A welcome waits `welcome_retention` at most, on the device's
    /// timeline, which a restart does not reset: past it, it ends and its
    /// record goes, when the device looks and when it opens.
    #[tokio::test]
    async fn a_welcome_ends_at_its_age_with_its_record() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();

        medium.clock.advance(crate::links::WELCOME_RETENTION - 1);
        granter.expire_welcomes().await;
        assert!(granter.links().waiting(&id, &space).is_some());
        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().waiting(&id, &space).is_some(), "not yet");

        medium.clock.advance(1);
        granter.expire_welcomes().await;
        assert!(granter.links().waiting(&id, &space).is_none());
        assert!(records(&granter, space).await.is_empty());

        // Past its age while the device was closed: it goes as it opens.
        let second = other_with(9).await;
        let later = admitted(&granter, &second).await;
        let granter = medium.reopen(granter, &sealed).await;
        assert!(
            granter
                .links()
                .waiting(&second.device_id(), &later)
                .is_some()
        );
        medium.clock.advance(crate::links::WELCOME_RETENTION);
        let granter = medium.reopen(granter, &sealed).await;
        assert!(
            granter
                .links()
                .waiting(&second.device_id(), &later)
                .is_none()
        );
        assert!(records(&granter, later).await.is_empty());
    }

    async fn other_with(key: u8) -> Engine {
        Engine::create(
            Platform::memory(),
            &[key; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap()
        .0
    }

    /// At most 256 welcomes wait: the 257th passes the oldest, whose record
    /// goes, and the device opens again with the newest 256.
    #[tokio::test]
    async fn the_bound_passes_the_oldest_welcome_and_its_record() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let space = granter.create_space().await.unwrap();
        let since = granter.welcome_time().await;
        let welcomes: Vec<Waiting> = (0..=WAITING as u64)
            .map(|n| {
                let mut recipient = [0; 32];
                recipient[..8].copy_from_slice(&n.to_be_bytes());
                Waiting {
                    recipient: DeviceId(recipient),
                    space,
                    event: space,
                    sealed: vec![1],
                    since: since + n,
                    deposited: Vec::new(),
                    refused: Vec::new(),
                }
            })
            .collect();
        let first = welcomes[0].recipient;
        let second = welcomes[1].recipient;
        granter.keep_welcomes(space, welcomes).await.unwrap();
        assert!(granter.links().waiting(&first, &space).is_none());
        assert!(granter.links().waiting(&second, &space).is_some());
        let kept = records(&granter, space).await;
        assert_eq!(kept.len(), WAITING);
        assert!(kept.iter().all(|(recipient, _)| *recipient != first));

        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().waiting(&first, &space).is_none());
        assert!(granter.links().waiting(&second, &space).is_some());
        assert_eq!(records(&granter, space).await.len(), WAITING);
    }

    /// A space the device forgets takes its waiting welcomes with it.
    #[tokio::test]
    async fn a_forgotten_space_takes_its_waiting_welcomes() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        granter.forget_space(&space).await.unwrap();
        assert!(granter.links().welcomes_for(&id).is_empty());
        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().welcomes_for(&id).is_empty());
    }

    /// A `deposit` record of `welcome` at `url`, as a deposit keeps it.
    fn deposit_put(welcome: &Waiting, url: &str) -> DevicePut {
        let now = frasil_base::time::Reading {
            timeline: 0,
            wall: None,
            run: 1,
        };
        (
            Table::Deposit,
            welcome.recipient.0[..16].to_vec(),
            TableValue::Deposit(frasil_store::DepositRecord {
                peer: origin(url).to_owned(),
                address: [1; 32],
                item: welcome.sealed.clone(),
                first: now,
                attempts: 0,
                next: 0,
                token: None,
            }),
        )
    }

    /// Keeps a deposit of the welcome waiting for `recipient` in `space`
    /// at `url`, as the device's upkeep does.
    async fn deposit(
        engine: &Engine,
        recipient: &DeviceId,
        space: EventId,
        url: &str,
    ) -> Result<Option<bool>> {
        let welcome = engine.links().waiting(recipient, &space).unwrap();
        let put = deposit_put(&welcome, url);
        engine.keep_welcome_deposit(&welcome, url, put).await
    }

    fn peers(record: &WelcomeRecord) -> Vec<&str> {
        record
            .deposited
            .iter()
            .map(|(peer, _)| peer.as_str())
            .collect()
    }

    /// The peers a welcome was deposited at are kept with it, by origin,
    /// each with the `T` of its deposit, so that a device that opens again
    /// deposits it only where it is due.
    #[tokio::test]
    async fn the_peers_that_hold_a_welcome_are_kept_with_it() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let at = granter.welcome_time().await;
        assert_eq!(
            deposit(&granter, &id, space, "https://peer.example/")
                .await
                .unwrap(),
            Some(true)
        );
        let kept = records(&granter, space).await;
        assert_eq!(
            kept[0].1.deposited,
            [("https://peer.example".to_owned(), at)]
        );

        let granter = medium.reopen(granter, &sealed).await;
        let now = granter.welcome_time().await;
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example", now)
                .is_empty()
        );
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example/", now)
                .is_empty()
        );
        assert_eq!(
            granter
                .links()
                .to_deposit("https://other.example", now)
                .len(),
            1
        );
    }

    /// A deposit at a peer lasts there only a while: the welcome is due at
    /// that peer again once `welcome_redeposit` has passed since its
    /// latest deposit there, after a restart too, and the new deposit's
    /// `T` takes the old one's place in the record.
    #[tokio::test]
    async fn a_welcome_is_due_again_at_a_peer_after_welcome_redeposit() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let url = "https://peer.example";
        deposit(&granter, &id, space, url).await.unwrap();

        medium.clock.advance(crate::links::WELCOME_REDEPOSIT - 1);
        let now = granter.welcome_time().await;
        assert!(granter.links().to_deposit(url, now).is_empty());
        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().to_deposit(url, now).is_empty(), "not yet");

        medium.clock.advance(1);
        let now = granter.welcome_time().await;
        assert_eq!(granter.links().to_deposit(url, now).len(), 1);
        let granter = medium.reopen(granter, &sealed).await;
        assert_eq!(granter.links().to_deposit(url, now).len(), 1);

        deposit(&granter, &id, space, url).await.unwrap();
        assert!(granter.links().to_deposit(url, now).is_empty());
        let kept = records(&granter, space).await;
        assert_eq!(kept[0].1.deposited, [(url.to_owned(), now)]);
    }

    /// A `T` in a record past the timeline's own, as after a timeline that
    /// started again, does not make the welcome due at every look.
    #[test]
    fn a_deposit_ahead_of_the_timeline_is_not_due() {
        let mut links = crate::links::Links::default();
        links.wait(Waiting {
            recipient: DeviceId([1; 32]),
            space: EventId([2; 32]),
            event: EventId([3; 32]),
            sealed: vec![1],
            since: 0,
            deposited: vec![("https://peer.example".to_owned(), 1_000_000)],
            refused: Vec::new(),
        });
        assert!(links.to_deposit("https://peer.example", 0).is_empty());
        assert!(
            links
                .to_deposit("https://peer.example", 1_000_000)
                .is_empty()
        );
        assert_eq!(
            links
                .to_deposit(
                    "https://peer.example",
                    1_000_000 + crate::links::WELCOME_REDEPOSIT
                )
                .len(),
            1
        );
    }

    /// A peer that refused the deposit for good is taken out of the
    /// record, and is due again after `welcome_redeposit`, or at once after
    /// a restart; never at the next look.
    #[tokio::test]
    async fn a_peer_that_refused_for_good_is_not_recorded_and_is_due_later() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let url = "https://peer.example";
        deposit(&granter, &id, space, "https://other.example")
            .await
            .unwrap();
        deposit(&granter, &id, space, url).await.unwrap();
        let welcome = granter.links().waiting(&id, &space).unwrap();
        granter.welcome_deposit_refused(&welcome, url).await;
        assert_eq!(
            peers(&records(&granter, space).await[0].1),
            ["https://other.example"]
        );
        let now = granter.welcome_time().await;
        assert!(granter.links().to_deposit(url, now).is_empty());

        medium.clock.advance(crate::links::WELCOME_REDEPOSIT);
        let now = granter.welcome_time().await;
        assert_eq!(granter.links().to_deposit(url, now).len(), 1);

        let granter = medium.reopen(granter, &sealed).await;
        let now = granter.welcome_time().await;
        assert_eq!(granter.links().to_deposit(url, now).len(), 1);
    }

    /// A peer whose origin is longer than a record can name is left out of
    /// the record, which a store takes only when it would open: the
    /// welcome's record is still written, and the welcome waits after a
    /// restart, due at that peer again.
    #[tokio::test]
    async fn a_peer_with_a_long_origin_is_left_out_of_the_record() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let long = format!("https://{}.example", "a".repeat(600));
        let mut welcome = granter.links().waiting(&id, &space).unwrap();
        welcome.sealed = vec![9];
        welcome.deposited = vec![(long.clone(), 0)];
        granter.keep_welcomes(space, vec![welcome]).await.unwrap();
        deposit(&granter, &id, space, "https://peer.example")
            .await
            .unwrap();
        assert_eq!(
            peers(&records(&granter, space).await[0].1),
            ["https://peer.example"]
        );

        let granter = medium.reopen(granter, &sealed).await;
        let now = granter.welcome_time().await;
        assert_eq!(granter.links().waiting(&id, &space).unwrap().sealed, [9]);
        assert_eq!(granter.links().to_deposit(&long, now).len(), 1);
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example", now)
                .is_empty()
        );
    }

    /// A welcome that ended after the upkeep read it keeps no deposit:
    /// nothing is committed, so no record of it comes back at a restart.
    #[tokio::test]
    async fn a_welcome_that_ended_keeps_no_deposit() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let now = granter.welcome_time().await;
        let read = granter.links().to_deposit("https://peer.example", now);
        granter.end_welcome(id, space).await;
        let put = deposit_put(&read[0], "https://peer.example");
        assert_eq!(
            granter
                .keep_welcome_deposit(&read[0], "https://peer.example", put)
                .await
                .unwrap(),
            None
        );
        assert!(records(&granter, space).await.is_empty());
        assert!(
            granter
                .device_records(Table::Deposit)
                .await
                .unwrap()
                .is_empty()
        );
        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().waiting(&id, &space).is_none());
    }

    /// A welcome that another for the same recipient and space replaced
    /// after the upkeep read it keeps no deposit either.
    #[tokio::test]
    async fn a_replaced_welcome_keeps_no_deposit() {
        let medium = Medium::new();
        let (granter, _) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let now = granter.welcome_time().await;
        let read = granter.links().to_deposit("https://peer.example", now);
        let mut newer = read[0].clone();
        newer.sealed = vec![9];
        granter.keep_welcomes(space, vec![newer]).await.unwrap();
        let put = deposit_put(&read[0], "https://peer.example");
        assert_eq!(
            granter
                .keep_welcome_deposit(&read[0], "https://peer.example", put)
                .await
                .unwrap(),
            None
        );
        let kept = records(&granter, space).await;
        assert_eq!(kept[0].1.sealed, [9]);
        assert!(kept[0].1.deposited.is_empty());
        assert_eq!(granter.links().waiting(&id, &space).unwrap().sealed, [9]);
    }

    /// A deposit of a welcome committed between the commit of the welcome
    /// that replaces it and that welcome's wait does not stand at rest in
    /// the newer one's place.
    #[tokio::test]
    async fn a_replacing_welcome_is_written_again_over_a_deposit_of_the_older() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let older = granter.links().waiting(&id, &space).unwrap();
        let mut newer = older.clone();
        newer.sealed = vec![9];
        {
            let mut state = granter.lock().await;
            let mut batch = Batch::default();
            let (table, item, value) = welcome_record(&newer);
            state
                .vault
                .put(&mut batch, &space.0, table, &item, &value)
                .unwrap();
            state.vault.commit(batch).await.unwrap();
        }
        deposit(&granter, &id, space, "https://peer.example")
            .await
            .unwrap();
        granter.waiting_kept(vec![newer]).await;
        let kept = records(&granter, space).await;
        assert_eq!(kept[0].1.sealed, [9]);
        assert!(kept[0].1.deposited.is_empty());
        let granter = medium.reopen(granter, &sealed).await;
        assert_eq!(granter.links().waiting(&id, &space).unwrap().sealed, [9]);
    }

    /// Two deposits of one welcome at two peers at once each keep the
    /// other's peer, at rest and in memory.
    #[tokio::test]
    async fn deposits_at_two_peers_at_once_keep_both() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let now = granter.welcome_time().await;
        let a = granter.links().to_deposit("https://a.example", now);
        let b = granter.links().to_deposit("https://b.example", now);
        let (put_a, put_b) = (
            deposit_put(&a[0], "https://a.example"),
            deposit_put(&b[0], "https://b.example"),
        );
        let (kept_a, kept_b) = tokio::join!(
            granter.keep_welcome_deposit(&a[0], "https://a.example", put_a),
            granter.keep_welcome_deposit(&b[0], "https://b.example", put_b),
        );
        assert_eq!((kept_a.unwrap(), kept_b.unwrap()), (Some(true), Some(true)));
        let both = ["https://a.example", "https://b.example"];
        assert_eq!(peers(&records(&granter, space).await[0].1), both);
        let granter = medium.reopen(granter, &sealed).await;
        let waiting = granter.links().waiting(&id, &space).unwrap();
        let named: Vec<&str> = waiting.deposited.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(named, both);
    }

    /// A store that refuses every commit once told to.
    struct Refusing {
        inner: MemoryStore,
        refuse: std::sync::atomic::AtomicBool,
    }

    impl Store for Refusing {
        fn get<'a>(
            &'a self,
            address: &'a [u8],
        ) -> frasil_store::BoxFuture<
            'a,
            std::result::Result<Option<Vec<u8>>, frasil_store::StoreError>,
        > {
            self.inner.get(address)
        }

        fn scan<'a>(
            &'a self,
            prefix: &'a [u8],
        ) -> frasil_store::BoxFuture<
            'a,
            std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, frasil_store::StoreError>,
        > {
            self.inner.scan(prefix)
        }

        fn commit<'a>(
            &'a self,
            commit: &'a frasil_store::Commit,
        ) -> frasil_store::BoxFuture<'a, std::result::Result<bool, frasil_store::StoreError>>
        {
            if self.refuse.load(std::sync::atomic::Ordering::Relaxed) {
                return Box::pin(async { Err(frasil_store::StoreError::new("refused")) });
            }
            self.inner.commit(commit)
        }
    }

    /// A deposit whose commit fails leaves the welcome in memory as it
    /// was: due at that peer still.
    #[tokio::test]
    async fn a_failed_commit_leaves_the_welcome_due() {
        let store = Arc::new(Refusing {
            inner: MemoryStore::new(),
            refuse: std::sync::atomic::AtomicBool::new(false),
        });
        let platform = Platform::new(
            Arc::clone(&store) as Arc<dyn Store>,
            Arc::new(MemorySlot::new()) as Arc<dyn DeviceBoundSlot>,
        );
        let (granter, _) = Engine::create(platform, &[4; 32], AdapterRegistry::with_builtins())
            .await
            .unwrap();
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        store
            .refuse
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            deposit(&granter, &id, space, "https://peer.example")
                .await
                .is_err()
        );
        let now = granter.welcome_time().await;
        assert_eq!(
            granter
                .links()
                .to_deposit("https://peer.example", now)
                .len(),
            1
        );
        assert!(
            granter
                .links()
                .waiting(&id, &space)
                .unwrap()
                .deposited
                .is_empty()
        );
    }

    /// A deposit of a welcome of a space kept in memory only leaves
    /// nothing at rest.
    #[cfg(feature = "ext-guests")]
    #[tokio::test]
    async fn a_memory_only_spaces_welcome_deposit_is_not_kept_at_rest() {
        let medium = Medium::new();
        let (granter, _) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        granter.keep_in_memory(&space).await.unwrap();
        assert_eq!(
            deposit(&granter, &id, space, "https://peer.example")
                .await
                .unwrap(),
            Some(false)
        );
        assert!(
            granter
                .device_records(Table::Deposit)
                .await
                .unwrap()
                .is_empty()
        );
        let now = granter.welcome_time().await;
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example", now)
                .is_empty()
        );
    }

    /// A space dropped for this device's own erasure takes its waiting
    /// welcomes with it, in memory as at rest.
    #[tokio::test]
    async fn a_space_dropped_for_its_erasure_takes_its_waiting_welcomes() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        granter
            .sign_skeleton(space, &frasil_peers::body::StorageBody::Erase)
            .await
            .unwrap();
        granter.drop_for_erasure(&space).await.unwrap();
        assert!(granter.links().welcomes_for(&id).is_empty());
        let granter = medium.reopen(granter, &sealed).await;
        assert!(granter.links().welcomes_for(&id).is_empty());
    }
}
