//! The ephemeral channel at a device (ext-ephemeral.md), behind the
//! `ephemeral` feature.
//!
//! - **Sending.** A frame is signed by the device's Ed25519 key, carrying
//!   its `ed || kc`, whose device ID names the sender, and sealed
//!   under `ek(S)` of its current content state, numbered by the run's
//!   epoch and a counter per space. The epoch is kept in the `epoch` table:
//!   the next start uses the stored epoch plus one, and a start after a
//!   restore, or with no record, jumps by 2^32 and a random offset, so that
//!   no counter is reused (ext-ephemeral.md, "Epoch, counter and replay").
//!   The device keeps its live ephemeral slots per space.
//! - **Receiving** runs the receiver's checks in order against the current
//!   view: the space followed, the state held, the seal, the signature,
//!   membership, targets, freshness and replay. What is accepted goes to
//!   the application ([`Engine::subscribe_ephemeral`]).
//! - **Connections** carry each frame in an `Ephemeral` message, lossy, on
//!   every admitted member attach of its space.

use crate::at_rest::Batch;
use crate::device::{Engine, State};
use crate::error::{Error, Result};
use frasil_crypto::device::DeviceId;
use frasil_ephemeral::counters::Counters;
use frasil_ephemeral::inner::{Inner, Kind};
use frasil_ephemeral::limits::ORIGIN_BYTES;
use frasil_ephemeral::limits::RECEIVER_NONCE_BYTES;
use frasil_ephemeral::membership::Membership;
use frasil_ephemeral::receive::{
    AdapterCheck, CheckContext, Delivered, Extension, SpaceKind, View,
};
use frasil_ephemeral::replay::{Delivery, ReplayState, SlotKey};
use frasil_ephemeral::sending::LiveSlots;
use frasil_events::EventId;
use frasil_store::{Continuity, Table, TableValue};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use zeroize::Zeroizing;

/// The next number of a connection that delivers ephemeral frames.
static CONNECTIONS: AtomicU64 = AtomicU64::new(1);

/// A number for a connection that delivers ephemeral frames to this
/// process, unique while it runs: what a held ephemeral slot value names as
/// the connection that delivered it (ext-ephemeral.md, "Relaying").
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) fn ephemeral_connection() -> u64 {
    CONNECTIONS.fetch_add(1, Ordering::Relaxed)
}

/// What the application receives of an accepted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralReceived {
    /// The space.
    pub space: EventId,
    /// The sender's device ID.
    pub sender: DeviceId,
    /// The frame's name.
    pub name: String,
    /// The document it narrows to, if any.
    pub stream: Option<[u8; 16]>,
    /// Its data; empty clears an ephemeral slot.
    pub data: Vec<u8>,
    /// Whether it is an ephemeral slot value rather than a message.
    pub slot: bool,
    /// Whether it was a `frasil/leave`.
    pub leave: bool,
}

/// The device's ephemeral state while it runs.
pub(crate) struct EphemeralState {
    counters: Counters,
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    replay: ReplayState,
    slots: BTreeMap<EventId, LiveSlots>,
    outgoing: broadcast::Sender<(EventId, Vec<u8>)>,
    received: broadcast::Sender<EphemeralReceived>,
    /// This device's receiver nonces of this run, its last 4 per space
    /// (ext-ephemeral.md, "Freshness across restarts").
    nonces: BTreeMap<EventId, std::collections::VecDeque<[u8; RECEIVER_NONCE_BYTES]>>,
    /// Each sender's latest receiver nonce, from its `frasil/nonce` slot.
    their_nonces: BTreeMap<(EventId, DeviceId), [u8; RECEIVER_NONCE_BYTES]>,
    /// The key reference this device's live slots were last sealed under,
    /// by space: they are published again once the state changes.
    slots_sealed_under: BTreeMap<EventId, Vec<u8>>,
}

impl EphemeralState {
    /// A space this device no longer follows: its replay state and the
    /// receiver nonces its senders published go (ext-ephemeral.md, "Epoch,
    /// counter and replay").
    pub(crate) fn forget_space(&mut self, space: &EventId) {
        self.replay.drop_space(&space.0);
        self.their_nonces.retain(|(of, _), _| of != space);
    }
}

/// The receiver's view of its own state, for the checks.
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
struct Viewing<'a> {
    state: &'a State,
    own: DeviceId,
    registry: &'a crate::adapters::AdapterRegistry,
    fresh_only: &'a std::collections::BTreeSet<String>,
}

impl View for Viewing<'_> {
    fn own(&self) -> DeviceId {
        self.own
    }

    fn follows(&self, space: &[u8; 32]) -> Option<SpaceKind> {
        let replica = self.state.replicas.get(&EventId(*space))?;
        #[cfg(feature = "ext-restricted-spaces")]
        if replica.restricted_parent().is_some() {
            return Some(SpaceKind::Restricted);
        }
        let _ = replica;
        Some(SpaceKind::Plain)
    }

    fn holds_rotation(&self, space: &[u8; 32], id: &frasil_keys::names::RotationId) -> bool {
        self.state
            .replicas
            .get(&EventId(*space))
            .is_some_and(|replica| replica.secrets_held(id))
    }

    fn content_key(&self, space: &[u8; 32], reference: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        let replica = self.state.replicas.get(&EventId(*space))?;
        replica.object_key(reference).map(|(key, _)| key)
    }

    fn implements(&self, extension: Extension) -> bool {
        #[cfg(feature = "ext-guests")]
        return extension == Extension::Guests;
        #[cfg(not(feature = "ext-guests"))]
        {
            let _ = extension;
            false
        }
    }

    fn member(&self, space: &[u8; 32], sender: &DeviceId) -> Membership {
        let Some(replica) = self.state.replicas.get(&EventId(*space)) else {
            return Membership::Unjudgeable;
        };
        if replica.forked(sender) {
            return Membership::Forked;
        }
        if replica.level_of(sender).is_none() {
            // No path holds: if the space's roster still names the sender,
            // its membership ended, as through a parent it no longer
            // reaches (ext-ephemeral.md, 3.6, step 3).
            let named = replica
                .roster()
                .state(&frasil_space::MemberRef::device(*sender))
                .is_some();
            return if named {
                Membership::MembershipEnded
            } else {
                Membership::NotAMember
            };
        }
        // A restricted space counts only if the sender also reaches its
        // parent, in the parent's merged roster as this device holds it;
        // without the parent's log the path cannot be judged
        // (ext-ephemeral.md, 3.6 "Membership against the current view";
        // ext-restricted-spaces.md, 3.3 "Membership of a restricted
        // space"). The space's own roster named the sender, so a parent it
        // no longer reaches ends its membership.
        #[cfg(feature = "ext-restricted-spaces")]
        if replica.is_restricted() {
            let Some(parent) = replica
                .restricted_parent()
                .and_then(|parent| self.state.replicas.get(&parent))
            else {
                return Membership::Unjudgeable;
            };
            if parent.forked(sender) || parent.level_of(sender).is_none() {
                return Membership::MembershipEnded;
            }
        }
        Membership::In
    }

    fn holds_nonce(&self, space: &[u8; 32], nonce: &[u8; RECEIVER_NONCE_BYTES]) -> bool {
        self.state
            .ephemeral
            .as_ref()
            .and_then(|e| e.nonces.get(&EventId(*space)))
            .is_some_and(|held| held.contains(nonce))
    }

    fn fresh_only(&self, name: &str) -> bool {
        self.fresh_only.contains(name)
    }

    /// The named adapter's checks, with the sender's level and
    /// capabilities in this device's current view, those of its strongest
    /// path (ext-ephemeral.md, 3.5 "Capability checks").
    fn check_capabilities(
        &self,
        adapter: &str,
        context: &CheckContext<'_>,
        data: &[u8],
    ) -> AdapterCheck {
        let replica = self.state.replicas.get(&EventId(*context.space));
        let level = replica.and_then(|r| r.level_of(context.sender)).map_or(
            frasil_adapter::Level::Read,
            |level| match level {
                frasil_space::Level::Read => frasil_adapter::Level::Read,
                frasil_space::Level::Write => frasil_adapter::Level::Write,
                frasil_space::Level::Administer => frasil_adapter::Level::Administer,
            },
        );
        // A sender in the view whose capabilities are not found has its
        // frame refused, never checked as an unnarrowed writer's (units.md,
        // 3.17 "Capability checks").
        let found = replica.and_then(|r| r.frame_capabilities(context.sender));
        let capabilities = found.clone().unwrap_or_default();
        let frame = frasil_adapter::EphemeralContext {
            space: *context.space,
            kind: match context.kind {
                Kind::Message => frasil_adapter::EphemeralKind::Message,
                Kind::Slot => frasil_adapter::EphemeralKind::Slot,
            },
            name: context.name.to_owned(),
            stream: context.stream.copied(),
            targets: context
                .targets
                .map(|targets| targets.iter().map(|target| target.0).collect()),
            sender: context.sender.0,
            level,
            capabilities,
        };
        match self.registry.check_ephemeral(adapter, &frame, data) {
            None => AdapterCheck::Unknown,
            Some(_) if found.is_none() => AdapterCheck::Refuse,
            Some(true) => AdapterCheck::Accept,
            Some(false) => AdapterCheck::Refuse,
        }
    }
}

impl Engine {
    /// Starts the ephemeral state on first use: the epoch from the `epoch`
    /// table, committed for this run.
    async fn ephemeral_state<'a>(&self, state: &'a mut State) -> Result<&'a mut EphemeralState> {
        if state.ephemeral.is_none() {
            let stored = match state.vault.get_device(Table::Epoch).await? {
                Some(TableValue::Epoch(epoch)) => Some(epoch),
                _ => None,
            };
            let counters = match (stored, state.vault.continuity()) {
                (Some(epoch), Continuity::Current) => Counters::start(epoch),
                _ => Counters::restore_with(
                    stored,
                    u32::from_be_bytes(self.platform().nonce::<4>()?),
                ),
            }
            .ok_or(Error::Class("TooLarge"))?;
            let value = TableValue::Epoch(counters.epoch()).encode();
            let (address, record) = state.vault.seal(None, Table::Epoch, &[], &value)?;
            let mut batch = Batch::default();
            batch.puts.push((address, record));
            state.vault.commit(batch).await?;
            state.ephemeral = Some(EphemeralState {
                counters,
                replay: ReplayState::new(),
                slots: BTreeMap::new(),
                outgoing: broadcast::channel(256).0,
                received: broadcast::channel(256).0,
                nonces: BTreeMap::new(),
                their_nonces: BTreeMap::new(),
                slots_sealed_under: BTreeMap::new(),
            });
        }
        state.ephemeral.as_mut().ok_or(Error::Class("Missing"))
    }

    /// Accepted ephemeral frames, as they arrive.
    ///
    /// # Errors
    ///
    /// The store's, on the first use.
    pub async fn subscribe_ephemeral(&self) -> Result<broadcast::Receiver<EphemeralReceived>> {
        let mut state = self.lock().await;
        Ok(self.ephemeral_state(&mut state).await?.received.subscribe())
    }

    /// Outer frames this device sends, by space, for its connections.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn ephemeral_outgoing(
        &self,
    ) -> Result<broadcast::Receiver<(EventId, Vec<u8>)>> {
        let mut state = self.lock().await;
        Ok(self.ephemeral_state(&mut state).await?.outgoing.subscribe())
    }

    /// Sends an ephemeral message, or an ephemeral slot value when `slot`,
    /// to every member connected in the space (ext-ephemeral.md,
    /// "Sending"). Empty data clears a slot.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] while the device holds
    /// no current state; `TooLarge` past 32 live slots or the frame's
    /// limits; `Malformed` for a name the channel refuses.
    pub async fn send_ephemeral(
        &self,
        space: EventId,
        name: &str,
        stream: Option<[u8; 16]>,
        data: &[u8],
        slot: bool,
    ) -> Result<()> {
        self.send_frame(space, name, stream, None, data, slot).await
    }

    /// Sends an ephemeral message targeted at these devices: with a fresh
    /// entry for each one whose receiver nonce this device holds, so that
    /// a replay after the target's restart is `Stale` there
    /// (ext-ephemeral.md, "Freshness across restarts").
    ///
    /// # Errors
    ///
    /// As [`Engine::send_ephemeral`].
    pub async fn send_ephemeral_to(
        &self,
        space: EventId,
        name: &str,
        targets: &[DeviceId],
        data: &[u8],
    ) -> Result<()> {
        self.send_targeted(space, name, targets, data).await
    }

    /// Marks names fresh-only at this device (ext-ephemeral.md, "Freshness
    /// across restarts"): an ephemeral message under one of them is
    /// refused (`Stale`) unless it carries a fresh entry for this device
    /// with one of its receiver nonces, so that a command never runs twice.
    pub fn set_fresh_only(&self, names: impl IntoIterator<Item = String>) {
        let mut held = self
            .shared_fresh_only()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.extend(names);
    }

    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    fn fresh_only_names(&self) -> std::collections::BTreeSet<String> {
        self.shared_fresh_only()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Starts receiving a space's channel (ext-ephemeral.md, "Freshness
    /// across restarts"): draws a receiver nonce, holds its last 4, and
    /// publishes the newest as its `frasil/nonce` ephemeral slot. Once per
    /// space and run; a connection that admits the space calls it.
    ///
    /// # Errors
    ///
    /// As [`Engine::send_ephemeral`].
    pub async fn start_receiving(&self, space: EventId) -> Result<()> {
        let nonce = {
            let mut state = self.lock().await;
            let ephemeral = self.ephemeral_state(&mut state).await?;
            if ephemeral.nonces.contains_key(&space) {
                return Ok(());
            }
            let nonce = self.platform().nonce::<RECEIVER_NONCE_BYTES>()?;
            let held = ephemeral.nonces.entry(space).or_default();
            held.push_back(nonce);
            while held.len() > frasil_ephemeral::limits::RECEIVER_NONCES {
                held.pop_front();
            }
            nonce
        };
        self.send_frame(
            space,
            frasil_ephemeral::names::NONCE,
            None,
            None,
            &nonce,
            true,
        )
        .await
    }

    /// Publishes this device's live ephemeral slots of a space again
    /// (ext-ephemeral.md, "Sending"): when its current state has changed
    /// since it sealed them, for members who hold only the new state, or
    /// with `always`, for a connection that newly admits the space.
    ///
    /// # Errors
    ///
    /// As [`Engine::send_ephemeral`].
    pub async fn republish_slots(&self, space: EventId, always: bool) -> Result<()> {
        let live: Vec<(String, Option<[u8; 16]>, Vec<u8>)> = {
            let mut state = self.lock().await;
            let Ok((reference, _)) = self.sealing(&state, &space) else {
                return Ok(());
            };
            let ephemeral = self.ephemeral_state(&mut state).await?;
            let current = ephemeral.slots_sealed_under.get(&space) == Some(&reference);
            if current && !always {
                return Ok(());
            }
            ephemeral
                .slots
                .get(&space)
                .map(|slots| {
                    slots
                        .iter()
                        .map(|(name, stream, data)| {
                            (name.to_owned(), stream.copied(), data.to_vec())
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        for (name, stream, data) in live {
            self.send_frame(space, &name, stream, None, &data, true)
                .await?;
        }
        Ok(())
    }

    /// Sends an ephemeral message of one of Frasil's names targeted at
    /// these devices (ext-ephemeral.md, "Frasil's names"), such as a leave
    /// request.
    ///
    /// # Errors
    ///
    /// As [`Engine::send_ephemeral`].
    #[cfg_attr(not(feature = "ext-guests"), allow(dead_code))]
    pub(crate) async fn send_targeted(
        &self,
        space: EventId,
        name: &str,
        targets: &[DeviceId],
        data: &[u8],
    ) -> Result<()> {
        let mut targets = targets.to_vec();
        targets.sort_unstable();
        targets.dedup();
        self.send_frame(space, name, None, Some(targets), data, false)
            .await
    }

    async fn send_frame(
        &self,
        space: EventId,
        name: &str,
        stream: Option<[u8; 16]>,
        targets: Option<Vec<DeviceId>>,
        data: &[u8],
        slot: bool,
    ) -> Result<()> {
        let seed = self.keys().identity_seed_bytes();
        // The 64-byte `ed || kc` whose device ID names the sender
        // (ext-ephemeral.md, "The inner map").
        let sender = self.signer().signatory();
        let nonce = self.platform().nonce::<24>()?;
        let mut state = self.lock().await;
        // A device that may not write seals no ephemeral message
        // (ext-guests.md, "The writer's decision").
        #[cfg(feature = "ext-guests")]
        if name != frasil_ephemeral::names::LEAVE_REQUEST {
            self.writer_check(&mut state, &space).await?;
        }
        // In a restricted space, k_F and the restricted key reference
        // (ext-ephemeral.md, "The ephemeral key").
        let (reference, key) = self.sealing(&state, &space)?;
        let ephemeral = self.ephemeral_state(&mut state).await?;
        if slot {
            ephemeral
                .slots
                .entry(space)
                .or_default()
                .set(name, stream, data)
                .map_err(Error::class)?;
            ephemeral
                .slots_sealed_under
                .insert(space, reference.clone());
        }
        let (epoch, counter) = ephemeral
            .counters
            .next(&space.0)
            .ok_or(Error::Class("TooLarge"))?;
        let inner = Inner {
            kind: if slot { Kind::Slot } else { Kind::Message },
            sender,
            epoch,
            counter,
            name: name.to_owned(),
            stream,
            fresh: targets.as_ref().and_then(|targets| {
                // A fresh entry for each target whose nonce this device
                // holds (ext-ephemeral.md, "Freshness across restarts").
                let entries: Vec<_> = targets
                    .iter()
                    .filter_map(|target| {
                        ephemeral
                            .their_nonces
                            .get(&(space, *target))
                            .map(|nonce| (*target, *nonce))
                    })
                    .take(frasil_ephemeral::limits::MAX_TARGETS)
                    .collect();
                (!entries.is_empty()).then_some(entries)
            }),
            targets,
            adapter: None,
            data: data.to_vec(),
        };
        let sealed = frasil_ephemeral::seal_with(&inner, &space.0, &reference, &key, &seed, &nonce)
            .map_err(Error::class)?;
        let _ = ephemeral.outgoing.send((space, sealed.outer));
        Ok(())
    }

    /// A connection that delivered ephemeral frames closed: the ephemeral
    /// slot values it delivered are dropped, their marks kept
    /// (ext-ephemeral.md, "Relaying").
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn ephemeral_closed(&self, connection: u64) {
        let mut state = self.lock().await;
        if let Some(ephemeral) = state.ephemeral.as_mut() {
            ephemeral.replay.drop_connection(connection);
        }
    }

    /// A relaying peer's `Gone` on a connection names an origin: the
    /// ephemeral slot values that connection delivered with it in the
    /// space are dropped, their marks kept (ext-ephemeral.md, "Relaying").
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn ephemeral_gone(
        &self,
        space: EventId,
        connection: u64,
        origin: [u8; ORIGIN_BYTES],
    ) {
        let mut state = self.lock().await;
        if let Some(ephemeral) = state.ephemeral.as_mut() {
            ephemeral.replay.drop_gone(&space.0, connection, origin);
        }
    }

    /// Takes an outer frame a connection carried for a space: the
    /// receiver's checks, in order, and, when accepted, delivery to the
    /// application. `delivery` names the connection, and the origin a
    /// relaying peer added, so that an ephemeral slot value goes when they
    /// do. A refused frame is dropped, and nothing is answered.
    ///
    /// # Errors
    ///
    /// The refusal's class.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn receive_ephemeral(
        &self,
        space: EventId,
        outer: &[u8],
        delivery: Delivery,
    ) -> Result<()> {
        let own = self.device_id();
        let registry = self.registry().clone();
        let fresh_only = self.fresh_only_names();
        let mut state = self.lock().await;
        self.ephemeral_state(&mut state).await?;
        let mut replay = std::mem::take(
            &mut state
                .ephemeral
                .as_mut()
                .ok_or(Error::Class("Missing"))?
                .replay,
        );
        let accepted = {
            let view = Viewing {
                state: &state,
                own,
                registry: &registry,
                fresh_only: &fresh_only,
            };
            frasil_ephemeral::receive(outer, &space.0, &view, &mut replay)
        };
        let ephemeral = state.ephemeral.as_mut().ok_or(Error::Class("Missing"))?;
        ephemeral.replay = replay;
        let accepted = accepted.map_err(|refusal| Error::class(refusal.class))?;
        if accepted.delivered == Delivered::SlotValue {
            let key = SlotKey {
                space: space.0,
                sender: accepted.inner.sender.device_id(),
                name: accepted.inner.name.clone(),
                stream: accepted.inner.stream,
            };
            ephemeral.replay.set_delivery(&key, delivery);
        }
        // A sender's receiver nonce, for the fresh entries this device
        // adds when it targets the sender: Frasil's own, not the
        // application's.
        if accepted.inner.name == frasil_ephemeral::names::NONCE {
            if let Ok(nonce) =
                <[u8; RECEIVER_NONCE_BYTES]>::try_from(accepted.inner.data.as_slice())
            {
                ephemeral
                    .their_nonces
                    .insert((space, accepted.inner.sender.device_id()), nonce);
            }
            return Ok(());
        }
        // A leave request, at an administering device it targets
        // (ext-guests.md, "A leave request").
        #[cfg(feature = "ext-guests")]
        if accepted.inner.name == frasil_ephemeral::names::LEAVE_REQUEST {
            drop(state);
            return self.take_leave_request(space, &accepted.inner.data).await;
        }
        let _ = ephemeral.received.send(EphemeralReceived {
            space,
            sender: accepted.inner.sender.device_id(),
            name: accepted.inner.name,
            stream: accepted.inner.stream,
            data: accepted.inner.data,
            slot: accepted.inner.kind == Kind::Slot,
            leave: accepted.delivered == Delivered::Leave,
        });
        Ok(())
    }
}

/// A restricted space's sender judged against its parent (ext-ephemeral.md,
/// 3.6 "Membership against the current view").
#[cfg(all(test, feature = "ext-restricted-spaces"))]
mod tests {
    use super::*;
    use crate::advanced::{AdapterRegistry, Platform};
    use frasil_space::{HistoryMode, MemberRef, Via};

    async fn device(key: u8) -> Engine {
        Engine::create(
            Platform::memory(),
            &[key; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a device")
        .0
    }

    async fn grant(by: &Engine, space: EventId, to: &Engine) {
        by.grant_device(
            space,
            to.public_keys().clone(),
            frasil_space::Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    }

    /// Step 12's standing of a sender at this device, as a frame of it
    /// would meet it.
    async fn standing(at: &Engine, space: EventId, sender: &DeviceId) -> Membership {
        let registry = at.registry().clone();
        let fresh_only = std::collections::BTreeSet::new();
        let state = at.lock().await;
        let view = Viewing {
            state: &state,
            own: at.device_id(),
            registry: &registry,
            fresh_only: &fresh_only,
        };
        view.member(&space.0, sender)
    }

    #[tokio::test]
    async fn a_restricted_spaces_sender_must_reach_its_parent() {
        let alice = device(1).await;
        let bob = device(2).await;
        let p = alice.create_space().await.unwrap();
        grant(&alice, p, &bob).await;
        let f = alice.create_restricted(p).await.unwrap();
        grant(&alice, f, &bob).await;
        assert_eq!(standing(&alice, f, &bob.device_id()).await, Membership::In);
        // Bob is removed from the parent; F's roster, not yet mirrored,
        // still grants him. His frames in F are refused at once.
        alice
            .remove(p, MemberRef::device(bob.device_id()))
            .await
            .unwrap();
        assert_eq!(
            standing(&alice, f, &bob.device_id()).await,
            Membership::MembershipEnded
        );
        // In the parent itself, the removal has ended his membership too.
        assert_ne!(standing(&alice, p, &bob.device_id()).await, Membership::In);
    }
}
