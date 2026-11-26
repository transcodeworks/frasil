//! The welcomes this device signed that wait for their newcomer
//! (admission.md, 3.10 Welcomes, "A welcome that waits"): sealed to the
//! newcomer's keys, kept at rest as `welcome` records in the space's log
//! (at-rest.md, "Tables") and in memory in [`Links`](crate::links::Links),
//! loaded when the device opens, and ended by an admitted attach, a roster
//! that no longer reaches the newcomer, the bound of 256 or
//! `welcome_retention`.

use crate::device::Engine;
use crate::error::{Error, Result};
use crate::links::{WAITING, Waiting, origin};
use crate::writer::WrapOf;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_store::tables::{LogKind, MAX_WELCOME_PEERS, Table, TableValue, WelcomeRecord};
use std::collections::BTreeMap;

/// A record to put in a space's log: its table, item and value.
pub(crate) type LogRecord = (Table, Vec<u8>, TableValue);

/// The `welcome` record of a waiting welcome, its item the newcomer's
/// device ID. A record names at most 64 peers: past them, a peer that
/// holds the welcome is known in memory only.
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
            });
        }
        Ok(sealed)
    }

    /// Welcomes whose records a commit has kept: they wait, and the
    /// records of those the bound passes go.
    pub(crate) async fn waiting_kept(&self, welcomes: Vec<Waiting>) {
        let mut passed = Vec::new();
        {
            let mut links = self.links();
            for welcome in welcomes {
                passed.extend(links.wait(welcome));
            }
        }
        self.drop_welcome_records(&passed).await;
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
            let mut batch = crate::at_rest::Batch::default();
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

    /// The `welcome` record of the welcome for `recipient` and `space`
    /// once the peer at `url` holds it too, for the commit that keeps that
    /// deposit (at-rest.md, "Tables", `welcome`); none when no welcome
    /// waits for them.
    pub(crate) fn welcome_deposited_record(
        &self,
        recipient: &DeviceId,
        space: &EventId,
        url: &str,
    ) -> Option<(EventId, LogRecord)> {
        let mut welcome = self.links().waiting(recipient, space)?;
        let url = origin(url);
        if let Err(at) = welcome
            .deposited
            .binary_search_by(|peer| peer.as_str().cmp(url))
        {
            welcome.deposited.insert(at, url.to_owned());
        }
        Some((*space, welcome_record(&welcome)))
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
        let mut batch = crate::at_rest::Batch::default();
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
            let mut batch = crate::at_rest::Batch::default();
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

    /// The peers that hold a welcome are kept with it, by origin, so that a
    /// device that opens again deposits it only where it is not yet.
    #[tokio::test]
    async fn the_peers_that_hold_a_welcome_are_kept_with_it() {
        let medium = Medium::new();
        let (granter, sealed) = medium.device().await;
        let device = other().await;
        let space = admitted(&granter, &device).await;
        let id = device.device_id();
        let record = granter
            .welcome_deposited_record(&id, &space, "https://peer.example/")
            .unwrap();
        granter
            .commit_device_with(Vec::new(), record)
            .await
            .unwrap();
        granter
            .links()
            .deposited(&id, &space, "https://peer.example/");
        assert_eq!(
            records(&granter, space).await[0].1.deposited,
            ["https://peer.example"]
        );

        let granter = medium.reopen(granter, &sealed).await;
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example")
                .is_empty()
        );
        assert!(
            granter
                .links()
                .to_deposit("https://peer.example/")
                .is_empty()
        );
        assert_eq!(granter.links().to_deposit("https://other.example").len(), 1);
    }
}
