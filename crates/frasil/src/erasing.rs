//! A device's own erasure of a space (peers.md, 3.16, "A device's own
//! erasure"; at-rest.md, 3.4): once it drops the space, it keeps only the
//! space's `log` record, its `pseudonym` records, its tips and the
//! erasure's own `event` record, its `peers` record and the administering
//! devices in `state` key 9, enough to present the erasure again, until
//! each peer answers `erased` or the application gives the space up.
//!
//! An erasure is a promise to the user, so the device never drops this
//! residue, nor leaves the erasure undone, without telling the application:
//! past the bound, `erasure_timeout` at its default counted on the device's
//! timeline from the erasure's first sight, it names the peers that have
//! not answered and keeps asking; when a peer serves a checkpoint that
//! makes the erasure late, it says so at once, and fetches the space again
//! from a member's space snapshot, to erase it again after the checkpoint
//! if the device still administers it, or to report the erasure void.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::Replica;
use frasil_base::time::{Reading, Timer, lower};
use frasil_crypto::device::DeviceId;
use frasil_crypto::schemes::Signer;
use frasil_events::{Event, EventId, kind};
use frasil_peers::body::{SlotId, StorageBody};
use frasil_space::Level;
use frasil_store::tables::Table;
use std::collections::BTreeSet;

/// What a device keeps of a space it dropped for its own erasure.
#[derive(Debug, Clone)]
pub(crate) struct Residue {
    /// The erasure it keeps, the newest it signed, and its signed bytes.
    pub erasure: Option<(EventId, Vec<u8>)>,
    /// The erasure's first sight: where the bound starts.
    pub since: Reading,
    /// The peers, by address, that answered `erased` for the space.
    pub answered: BTreeSet<String>,
    /// Whether the application was told which peers have not answered past
    /// the bound, since the device opened.
    pub told: bool,
    /// The peers that served a checkpoint that makes the erasure late.
    pub late_at: BTreeSet<String>,
    /// Whether the device is fetching the space again after a checkpoint
    /// made the erasure late.
    pub refetching: bool,
    /// The last welcome request; until re-entry, a welcome is expected.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub welcome_requested: Option<Reading>,
    /// The checked answer awaiting the client driver.
    #[allow(dead_code)]
    pub answer: Option<frasil_transport::messages::ErasureLate>,
    /// A contradictory answer to report without trusting it.
    #[allow(dead_code)]
    pub peer_error: Option<Vec<u8>>,
}

/// Whether an event is an erasure, by its body.
fn is_erasure(event: &Event) -> bool {
    event.kind() == kind::STORAGE
        && matches!(
            StorageBody::read(event.unverified_body()),
            Ok(StorageBody::Erase)
        )
}

impl Residue {
    /// The residue a log loaded at open is, if it is one: only erasures of
    /// the device's own pseudonyms among its events, and pseudonyms of its
    /// own. The bound starts at the newest erasure's first sight.
    pub(crate) fn found(
        events: &[Event],
        pseudonyms: &[(SlotId, Signer)],
        replica: &Replica,
    ) -> Option<Self> {
        if pseudonyms.is_empty() || events.is_empty() {
            return None;
        }
        let mine: BTreeSet<DeviceId> = pseudonyms.iter().map(|(_, p)| *p.device_id()).collect();
        if !events
            .iter()
            .all(|event| is_erasure(event) && mine.contains(event.author()))
        {
            return None;
        }
        let newest = events.iter().max_by_key(|event| {
            (
                replica.first_sight(&event.id()).map(|r| r.timeline),
                event.id(),
            )
        })?;
        let since = replica.first_sight(&newest.id()).copied()?;
        Some(Self {
            erasure: Some((newest.id(), newest.signed())),
            since,
            answered: BTreeSet::new(),
            told: false,
            late_at: BTreeSet::new(),
            refetching: false,
            welcome_requested: None,
            answer: None,
            peer_error: None,
        })
    }
}

/// Where a residue stands once a peer's answer is noted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErasureProgress {
    /// Every peer answered `erased`: the device forgot the space.
    Forgotten,
    /// Some peer has not answered yet; past the bound, the first time the
    /// device notices since it opened, those peers, which the application
    /// is told of.
    Waiting {
        /// The peers that have not answered, once the bound has passed and
        /// the application was not told yet.
        unanswered: Option<Vec<String>>,
    },
    /// The space is not one this device dropped for its own erasure.
    NotErasing,
}

/// What became of an erasure after the space was fetched again past a
/// checkpoint that made it late.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refetched {
    /// The device still administers the space there: it signed the erasure
    /// again after the checkpoint, and drops the space again once that one
    /// is acknowledged.
    SignedAgain(EventId),
    /// Another pseudonym holds the slot; the erasure stays pending.
    SlotHeld {
        /// The holding root or enrolment.
        holding: EventId,
        /// Whether its binding names this device.
        same_device: bool,
    },
    /// The device no longer administers the space there: the erasure is
    /// void, and the space lives on.
    Void,
}

impl Engine {
    /// Signs an erasure of the entire space for administration connections.
    /// The caller waits for acknowledgement before dropping the space.
    ///
    /// # Errors
    /// `NotAllowed` unless this device administers; signing and storage errors.
    pub async fn request_erasure(&self, space: EventId) -> Result<EventId> {
        if self
            .read(&space, |replica| replica.level_of(&self.device_id()))
            .await?
            != Some(Level::Administer)
        {
            return Err(Error::NotAllowed("erasing a space needs administer"));
        }
        self.sign_skeleton(space, &StorageBody::Erase).await
    }

    /// The newest erasure of this device's own pseudonyms that a space's
    /// replica holds, and its first sight.
    pub(crate) fn own_erasure(
        state: &State,
        space: &EventId,
    ) -> Option<(EventId, Vec<u8>, Option<Reading>)> {
        let replica = state.replicas.get(space)?;
        let log = replica.log()?;
        let mine: BTreeSet<DeviceId> = state.pseudonym_ids(space).into_iter().collect();
        log.frame_events()
            .filter(|event| is_erasure(event) && mine.contains(event.author()))
            .max_by_key(|event| {
                (
                    replica.first_sight(&event.id()).map(|r| r.timeline),
                    event.id(),
                )
            })
            .map(|event| {
                (
                    event.id(),
                    event.signed(),
                    replica.first_sight(&event.id()).copied(),
                )
            })
    }

    /// Drops a space for this device's own erasure of it (peers.md, 3.16,
    /// "A device's own erasure"; at-rest.md, 3.4): in one commit every
    /// record of the space goes but its `pseudonym` records and its
    /// erasure's own `event` record, beside its `log` record and its tips,
    /// and nothing of its content stays readable. Until each always-on peer
    /// it reaches answers `erased` ([`Self::erasure_answered`]), or the
    /// application gives the space up ([`Self::give_up_erasure`]), the
    /// device presents its erasure there.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn drop_for_erasure(&self, space: &EventId) -> Result<()> {
        let held = {
            let mut state = self.lock().await;
            self.take_held(&mut state, space)
        };
        if let Some((provider, tokens)) = held {
            for token in tokens {
                provider.forget(&token).await?;
            }
        }
        let mut state = self.lock().await;
        if state.erasing.contains_key(space) && !state.replicas.contains_key(space) {
            return Ok(());
        }
        let erasure = Self::own_erasure(&state, space);
        let Some((id, signed, first_sight)) =
            erasure.filter(|_| state.pseudonyms.contains_key(space))
        else {
            drop(state);
            return self.forget_space(space).await;
        };
        let since = match first_sight {
            Some(reading) => reading,
            None => self.read_timeline(&mut state).await?,
        };
        let administrators = state
            .replicas
            .get(space)
            .ok_or(Error::UnknownSpace)?
            .roster()
            .members_in()
            .filter(|(_, member)| member.level == Level::Administer)
            .filter_map(|(member, entry)| {
                let keys = entry.keys.as_ref()?;
                Some((member.id, keys.keys.xwing()?.to_vec()))
            })
            .collect();
        let residue_state = frasil_store::tables::LogState {
            erasing: Some(administrators),
            ..Default::default()
        };
        state
            .vault
            .forget_all_but(
                &space.0,
                &[Table::Pseudonym, Table::Peers, Table::State],
                &[(Table::Event, id.0.to_vec())],
                &residue_state,
            )
            .await?;
        state.replicas.remove(space);
        state.outboxes.remove(space);
        // Its waiting welcomes went with its log (at-rest.md, "Tables",
        // `welcome`).
        self.links().forget_welcomes(space);
        #[cfg(feature = "ephemeral")]
        if let Some(ephemeral) = state.ephemeral.as_mut() {
            ephemeral.forget_space(space);
        }
        #[cfg(feature = "ext-invite-links")]
        state.invites.claimed.retain(|_, kept| kept.space != *space);
        state.erasing.insert(
            *space,
            Residue {
                erasure: Some((id, signed)),
                since,
                answered: BTreeSet::new(),
                told: false,
                late_at: BTreeSet::new(),
                refetching: false,
                welcome_requested: None,
                answer: None,
                peer_error: None,
            },
        );
        Ok(())
    }

    /// The spaces this device dropped for its own erasure and still keeps
    /// for the peers' answers.
    pub async fn erasing(&self) -> Vec<EventId> {
        self.lock()
            .await
            .erasing
            .iter()
            .filter(|(_, residue)| !residue.refetching)
            .map(|(space, _)| *space)
            .collect()
    }

    /// Notes that `peer` answered `erased` for a space this device dropped
    /// for its own erasure, and forgets the space once every one of `peers`
    /// has. Past the bound, `erasure_timeout` at its default on the
    /// device's timeline from the erasure's first sight, it returns the
    /// peers that have not answered, once per opening, for the application
    /// to be told, and keeps the space.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn erasure_answered(
        &self,
        space: &EventId,
        peer: Option<&str>,
        peers: &[String],
    ) -> Result<ErasureProgress> {
        let progress = {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let Some(residue) = state.erasing.get_mut(space) else {
                return Ok(ErasureProgress::NotErasing);
            };
            if let Some(peer) = peer {
                residue.answered.insert(peer.to_owned());
            }
            let unanswered: Vec<String> = peers
                .iter()
                .filter(|peer| !residue.answered.contains(*peer))
                .cloned()
                .collect();
            if unanswered.is_empty() {
                ErasureProgress::Forgotten
            } else {
                let bound = Timer::ErasureTimeout.spec().default.unwrap_or(u64::MAX);
                let past = lower(&residue.since, &now) >= bound;
                let tell = past && !residue.told;
                residue.told |= tell;
                ErasureProgress::Waiting {
                    unanswered: tell.then_some(unanswered),
                }
            }
        };
        if progress == ErasureProgress::Forgotten {
            self.lock().await.ignored_erasure_welcomes.insert(*space);
            self.forget_space(space).await?;
        }
        Ok(progress)
    }

    /// Gives up a space this device dropped for its own erasure: the
    /// application no longer waits for the peers' answers, and the device
    /// forgets the space (at-rest.md, 3.4).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a space not dropped so; the store's.
    pub async fn give_up_erasure(&self, space: &EventId) -> Result<()> {
        if !self.lock().await.erasing.contains_key(space) {
            return Err(Error::UnknownSpace);
        }
        self.lock().await.ignored_erasure_welcomes.insert(*space);
        self.forget_space(space).await
    }

    /// Notes that `peer` served a checkpoint that makes this device's
    /// erasure of a space it dropped late. Returns whether it is new, for
    /// the application to be told at once.
    pub async fn erasure_late_at(&self, space: &EventId, peer: &str) -> bool {
        let mut state = self.lock().await;
        state
            .erasing
            .get_mut(space)
            .is_some_and(|residue| residue.late_at.insert(peer.to_owned()))
    }

    /// Checks and queues an administration answer using only the residue's records.
    /// A connector calls this before completing its administration exchange;
    /// the device driver reports checked evidence or a contradictory answer.
    ///
    /// # Errors
    /// `UnknownSpace` for no residue or pseudonym; `Malformed` for another
    /// space or erasure; `PeerError` for contradictory signed evidence.
    pub async fn receive_erasure_late(
        &self,
        expected_space: EventId,
        answer: frasil_transport::messages::ErasureLate,
    ) -> Result<()> {
        let mut state = self.lock().await;
        let space = expected_space;
        let residue = state.erasing.get(&space).ok_or(Error::UnknownSpace)?;
        let (erasure, signed) = residue.erasure.as_ref().ok_or(Error::UnknownSpace)?;
        let erasure = *erasure;
        let author = *frasil_events::decode(signed)
            .map_err(Error::class)?
            .author();
        let slot = state
            .pseudonyms
            .get(&space)
            .and_then(|held| {
                held.iter()
                    .find(|(_, signer)| *signer.device_id() == author)
            })
            .ok_or(Error::UnknownSpace)?
            .0;
        let checked = frasil_peers::erasure::check_late(
            space,
            erasure,
            slot,
            frasil_peers::erasure::LateErasure {
                space: EventId(answer.space),
                erasure: EventId(answer.erasure),
                cut: &answer.cut,
                checkpoint: EventId(answer.checkpoint),
                standing: answer.standing,
            },
        )
        .map_err(Error::class);
        if let Err(error) = checked {
            if error.class_name() == Some("PeerError") {
                state
                    .erasing
                    .get_mut(&space)
                    .ok_or(Error::UnknownSpace)?
                    .peer_error = Some(answer.encode());
            }
            return Err(error);
        }
        state
            .erasing
            .get_mut(&space)
            .ok_or(Error::UnknownSpace)?
            .answer = Some(answer);
        Ok(())
    }

    /// Whether the space has only its keyless residue, with no replica to sync.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn residue_only(&self, space: &EventId) -> bool {
        let state = self.lock().await;
        state.erasing.contains_key(space) && !state.replicas.contains_key(space)
    }

    /// The addresses retained by an erasure, also in builds without a transport.
    pub(crate) async fn erasure_peers(&self, space: &EventId) -> Result<Vec<String>> {
        let state = self.lock().await;
        let mut peers = Vec::new();
        for (_, value) in state.vault.scan(&space.0, Table::Peers).await? {
            if let frasil_store::tables::TableValue::Peers(saved) = value {
                peers.extend(saved.home);
                peers.extend(saved.hints);
            }
        }
        peers.sort();
        peers.dedup();
        Ok(peers)
    }

    /// Daily retries renew requests without filling mailboxes between polls.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn erasure_welcome_due(&self, space: &EventId) -> Result<bool> {
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        Ok(state.erasing.get(space).is_some_and(|residue| {
            residue
                .welcome_requested
                .is_none_or(|sent| lower(&sent, &now) >= 24 * 60 * 60)
        }))
    }

    /// An unsolicited or older welcome cannot restart a fresh residue.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn erasure_awaiting_welcome(&self, space: &EventId) -> bool {
        self.lock()
            .await
            .erasing
            .get(space)
            .is_some_and(|residue| !residue.refetching && residue.welcome_requested.is_some())
    }

    /// Makes sealed requests using only the administering keys kept at drop.
    pub(crate) async fn erasure_welcome_requests(
        &self,
        space: &EventId,
    ) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        use frasil_transport::mailbox::{Kind, address, item_info, item_plaintext};
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        state
            .erasing
            .get_mut(space)
            .ok_or(Error::UnknownSpace)?
            .welcome_requested = Some(now);
        let saved = crate::device::log_state(&state.vault, &space.0).await?;
        let request = frasil_admission::welcome_request::WelcomeRequest {
            space: space.0,
            device: self.device_id(),
            request: *self.platform().draw::<16>()?,
        }
        .sign(self.signer());
        saved
            .erasing
            .unwrap_or_default()
            .into_iter()
            .map(|(id, xwing)| {
                let sealed = frasil_crypto::wrap::seal_wrap_with(
                    &xwing,
                    &item_info(&DeviceId(id)),
                    &item_plaintext("frasil/welcome-request", &request),
                    &*self.platform().draw::<64>()?,
                )
                .map_err(Error::class)?;
                Ok((address(Kind::Device, &id), sealed))
            })
            .collect()
    }

    /// Verifies the requesting member's signature before preparing a delivery.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn welcome_request_member(
        &self,
        signed: &[u8],
    ) -> Result<(EventId, frasil_space::DeviceKeys)> {
        use frasil_crypto::device::KeySource;
        let state = self.lock().await;
        let asked = frasil_admission::welcome_request::WelcomeRequest::read(signed)
            .map_err(Error::class)?;
        let space = EventId(asked.space);
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let keys = replica
            .roster()
            .state(&frasil_space::MemberRef::device(asked.device))
            .and_then(|member| member.keys.as_deref())
            .cloned()
            .or_else(|| state.keys().device_keys(&asked.device))
            .filter(|keys| keys.check(&asked.device).is_ok())
            .ok_or(Error::Class("NoHybridKey"))?;
        let mut held = frasil_crypto::device::KeyRing::new();
        held.add_device(keys.clone());
        let request = frasil_admission::welcome_request::WelcomeRequest::verify(signed, &held)
            .map_err(Error::class)?;
        if state.erasing.contains_key(&space)
            || replica.level_of(&self.device_id()) != Some(Level::Administer)
            || replica.level_of(&request.device).is_none()
        {
            return Err(Error::NotAllowed(
                "welcome requests require a current member and administrator",
            ));
        }
        Ok((space, keys))
    }

    /// Takes contradictory evidence for the application.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn take_erasure_peer_error(&self, space: &EventId) -> Option<Vec<u8>> {
        self.lock().await.erasing.get_mut(space)?.peer_error.take()
    }

    /// Takes the checked answer from the last administration connection.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn take_erasure_late(
        &self,
        space: &EventId,
    ) -> Option<frasil_transport::messages::ErasureLate> {
        self.lock().await.erasing.get_mut(space)?.answer.take()
    }

    /// Starts fetching again a space this device dropped for its own
    /// erasure, after a checkpoint made the erasure late: as a replica that
    /// lost its store, from a member's space snapshot
    /// ([`Self::adopt_snapshot`]), then the events after it. A private
    /// pseudonym still enrolled in the restored world stays; an empty slot
    /// is enrolled again, and a slot held by another pseudonym is reported.
    /// The residue stays until
    /// [`Self::settle_refetched`] decides.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a space not dropped so; the store's.
    pub async fn refetch_erased(&self, space: &EventId) -> Result<()> {
        let _one = self.lock_erasure().await;
        let own_chain = {
            let mut state = self.lock().await;
            let residue = state.erasing.get_mut(space).ok_or(Error::UnknownSpace)?;
            residue.refetching = true;
            let erasure = residue.erasure.as_ref().map(|(_, signed)| signed.clone());
            // An enrolled slot keeps the private pseudonym: its own can
            // sign again, and a late one still presents the residue when
            // another pseudonym holds the slot. An empty slot needs a new
            // pseudonym for its enrolment.
            let kept: BTreeSet<_> = state
                .pseudonyms
                .get(space)
                .into_iter()
                .flatten()
                .map(|(slot, signer)| (*slot, signer))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .filter(|(slot, _)| {
                    state
                        .replicas
                        .get(space)
                        .and_then(|replica| replica.enrolled(slot))
                        .is_some()
                })
                .map(|(slot, signer)| (slot.to_value().encode(), *signer.device_id()))
                .collect();
            let own_chain = erasure.filter(|signed| {
                frasil_events::decode(signed)
                    .is_ok_and(|event| kept.iter().any(|(_, id)| id == event.author()))
            });
            let mut batch = crate::at_rest::Batch::default();
            for (item, value) in state.vault.scan(&space.0, Table::Pseudonym).await? {
                if !kept.iter().any(|(saved, _)| *saved == item) {
                    if let frasil_store::tables::TableValue::Pseudonym(mut pseudonym) = value
                        && pseudonym.token.is_some()
                    {
                        pseudonym.seeds = None;
                        state.vault.put(
                            &mut batch,
                            &space.0,
                            Table::Pseudonym,
                            &item,
                            &frasil_store::tables::TableValue::Pseudonym(pseudonym),
                        )?;
                    } else {
                        state
                            .vault
                            .delete(&mut batch, &space.0, Table::Pseudonym, &item);
                    }
                }
            }
            state.vault.commit(batch).await?;
            if let Some(held) = state.pseudonyms.get_mut(space) {
                held.retain(|(_, signer)| kept.iter().any(|(_, id)| id == signer.device_id()));
            }
            own_chain
        };
        self.follow(*space).await;
        if let Some(signed) = own_chain {
            self.ingest(*space, vec![signed]).await?;
        }
        // The fetched world can hold later events of the same pseudonym
        // from a restored installation. Advance the durable tips before
        // signing, just as after restoring a device's store.
        self.synced(space).await?;
        Ok(())
    }

    pub(crate) async fn held_slot(&self, space: &EventId) -> Option<(EventId, bool)> {
        let state = self.lock().await;
        let replica = state.replicas.get(space)?;
        let slot = &replica.slot_of(&self.device_id())?.slot;
        let enrolled = replica.enrolled(slot)?;
        if state
            .pseudonym(space, slot)
            .is_some_and(|signer| *signer.device_id() == enrolled)
        {
            return None;
        }
        let (holding, device) = replica.slot_holder(&enrolled)?;
        Some((holding, device == Some(self.device_id())))
    }

    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn residue_slot_held(&self, space: &EventId, cut: &[u8]) -> Option<EventId> {
        let state = self.lock().await;
        let residue = state.erasing.get(space)?;
        let (_, signed) = residue.erasure.as_ref()?;
        let author = *frasil_events::decode(signed).ok()?.author();
        let slot = state
            .pseudonyms
            .get(space)?
            .iter()
            .find(|(_, signer)| *signer.device_id() == author)?
            .0;
        let cut = frasil_events::decode(cut).ok()?;
        let StorageBody::Cut(body) = StorageBody::read(cut.unverified_body()).ok()? else {
            return None;
        };
        body.slots
            .iter()
            .find(|entry| entry.slot == slot)?
            .pseudonym
    }

    /// Decides, once a space fetched again holds the checkpoint that made
    /// this device's erasure late in effect, what becomes of the erasure: if
    /// the device still administers the space there, it signs the erasure
    /// again after the checkpoint, enrolling its slot again first when the
    /// checkpoint's cut asks it to; a held slot retains the erasure and
    /// reports its holder; if the device no longer administers, the erasure
    /// is void. `None`
    /// while the space is not yet held so.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn settle_refetched(&self, space: &EventId) -> Result<Option<Refetched>> {
        let _one = self.lock_erasure().await;
        let me = self.device_id();
        {
            let state = self.lock().await;
            if !state
                .erasing
                .get(space)
                .is_some_and(|residue| residue.refetching)
            {
                return Ok(None);
            }
            let Some(replica) = state.replicas.get(space) else {
                return Ok(None);
            };
            if replica.checkpoint_facts().last().is_none() || replica.log().is_none() {
                return Ok(None);
            }
            if replica.level_of(&me) != Some(Level::Administer) {
                drop(state);
                self.lock().await.erasing.remove(space);
                return Ok(Some(Refetched::Void));
            }
        }
        if let Some((holding, same_device)) = self.held_slot(space).await {
            if let Some(residue) = self.lock().await.erasing.get_mut(space) {
                residue.refetching = false;
                residue.welcome_requested = None;
            }
            return Ok(Some(Refetched::SlotHeld {
                holding,
                same_device,
            }));
        }
        // Its slot enrolled again after the checkpoint, if the cut left it
        // so, and the erasure signed again after it.
        self.enrol(space).await?;
        {
            let state = self.lock().await;
            let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
            let ready = replica.slot_of(&me).is_some_and(|info| {
                state.pseudonym(space, &info.slot).is_some_and(|pseudonym| {
                    replica.enrolled(&info.slot) == Some(*pseudonym.device_id())
                })
            });
            if !ready {
                return Ok(None);
            }
        }
        match self.sign_skeleton(*space, &StorageBody::Erase).await {
            Ok(erasure) => {
                let mut state = self.lock().await;
                if !state
                    .replicas
                    .get(space)
                    .and_then(|replica| replica.status(&erasure))
                    .is_some_and(|status| status.is_valid())
                {
                    return Ok(None);
                }
                state.erasing.remove(space);
                Ok(Some(Refetched::SignedAgain(erasure)))
            }
            Err(Error::NotAllowed(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
