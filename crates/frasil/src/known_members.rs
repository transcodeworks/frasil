//! A member of another space (admission.md, 3.16): an administrator grants
//! a device that a space it holds grants directly, by the device ID and
//! keys that roster names, with no code and no peer; and the welcomes that
//! wait for a member connection, made again from the log after a restart
//! (admission.md, 3.10 Welcomes, "A welcome that waits for a member
//! connection").

use crate::device::Engine;
use crate::error::{Error, Result};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use crate::writer::Recipient;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Via};

impl Engine {
    /// Grants `device`, which `known` grants directly, in `space`
    /// (admission.md, 3.16 A member of another space): at `level`, with
    /// `rank` exactly when `level` is `administer`, with history, `via` =
    /// `none`, carrying the keys `known`'s grant names. The grant commits
    /// at once; the device's welcome waits for a member connection with it
    /// and goes to the mailbox at peers as a person grant's does
    /// (admission.md, 3.10 Welcomes). Returns the admitting event.
    ///
    /// # Errors
    ///
    /// In the order admission.md, 3.16 checks them, each
    /// [`Error::NotAllowed`]: this device does not administer `space`;
    /// `known` does not grant the device directly; the device is a guest
    /// there; `space` reaches the device already; a restricted space's
    /// parent does not reach it. [`Error::Invalid`] for `administer`
    /// without a rank or a rank at another level; [`Error::UnknownSpace`];
    /// then as [`Engine::sign_roster`], `HigherRank` among them.
    pub async fn admit_member(
        &self,
        space: EventId,
        known: EventId,
        device: DeviceId,
        level: Level,
        rank: Option<u8>,
    ) -> Result<EventId> {
        let change = |keys: DeviceKeys| match (level, rank) {
            (Level::Administer, Some(rank)) => Ok(Change::grant_administrator(
                keys,
                rank,
                HistoryMode::WithHistory,
                Via::None,
            )),
            (Level::Administer, None) => {
                Err(Error::Invalid("an administrator is admitted at a rank"))
            }
            (_, Some(_)) => Err(Error::Invalid("only an administrator has a rank")),
            (level, None) => Ok(Change::grant_device(
                keys,
                level,
                HistoryMode::WithHistory,
                Via::None,
            )),
        };
        let me = self.device_id();
        let (keys, already) = {
            let state = self.lock().await;
            let target = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let source = state.replicas.get(&known).ok_or(Error::UnknownSpace)?;
            if target.level_of(&me) != Some(Level::Administer) {
                return Err(Error::NotAllowed("admitting needs administer"));
            }
            let member =
                source
                    .roster()
                    .state(&MemberRef::device(device))
                    .ok_or(Error::NotAllowed(
                        "the known space does not grant the device directly",
                    ))?;
            if member.session.is_some() {
                return Err(Error::NotAllowed(
                    "the device is a guest in the known space",
                ));
            }
            let keys = member.keys.as_deref().cloned().ok_or(Error::NotAllowed(
                "the known space does not grant the device directly",
            ))?;
            (keys, target.level_of(&device).is_some())
        };
        if already {
            return Err(Error::NotAllowed(
                "the device is a member of the space already",
            ));
        }
        if !self.reaches_parent_of(&space, &device).await {
            return Err(Error::NotAllowed(
                "the device does not reach the restricted space's parent",
            ));
        }
        let (event, wraps) = self
            .sign_roster_with(space, vec![change(keys.clone())?])
            .await?;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            // A grant with history delivers to the device it grants; should
            // its event not hold the device's wrap, a delivery does.
            let (delivered, wrap) = match wraps.get(&device) {
                Some(wrap) => (event, wrap.clone()),
                None => {
                    let (delivered, mut wraps) = self
                        .deliver_with(
                            space,
                            vec![Recipient {
                                keys: keys.clone(),
                                writes: level >= Level::Write,
                                propagates: true,
                            }],
                        )
                        .await?;
                    let wrap = wraps
                        .remove(&device)
                        .ok_or(Error::NotAllowed("the grant delivered no keys"))?;
                    (delivered, wrap)
                }
            };
            self.wait_welcome(space, &keys, delivered, &wrap).await?;
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = wraps;
        Ok(event)
    }

    /// Keeps a welcome for the device of `keys` naming `event`, whose
    /// delivery holds `wrap`, until a member connection with the device
    /// hands it over and the device attaches the space, and deposits it in
    /// the device's mailbox at the peers this device is connected to
    /// (admission.md, 3.10 Welcomes).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn wait_welcome(
        &self,
        space: EventId,
        keys: &DeviceKeys,
        event: EventId,
        wrap: &crate::writer::WrapOf,
    ) -> Result<()> {
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
            approver: self.device_id(),
            peers: self.welcome_hints(&space, &[]).await,
            snapshot: None,
        };
        let sealed = welcome
            .seal_with(keys, &*self.platform().draw::<64>()?)
            .map_err(Error::class)?;
        self.links().wait(crate::links::Waiting {
            recipient: keys.device_id(),
            space,
            event,
            sealed,
            deposited: Vec::new(),
        });
        Ok(())
    }

    /// Makes again the welcome of a device that refused an attach of
    /// `space` on a member connection (admission.md, 3.10 Welcomes, "A
    /// welcome that waits for a member connection"): when this device
    /// administers the space, the roster grants the device directly with
    /// no session or through a person whose list vouches for it, no member
    /// connection has admitted its attach of the space, which the member
    /// tickets kept for the space record, and no welcome of it waits. It
    /// then signs a delivery of the current state to the device and keeps
    /// a welcome naming it. Whether a welcome waits for the device now.
    ///
    /// # Errors
    ///
    /// As [`Engine::deliver`]; the store's.
    #[cfg(feature = "iroh")]
    pub(crate) async fn welcome_again(&self, space: EventId, device: DeviceId) -> Result<bool> {
        if self.links().waits(&device, &space) {
            return Ok(true);
        }
        if self.links().attaches_with(&space, &device) > 0
            || self
                .kept_endpoints(&space)
                .await?
                .iter()
                .any(|(member, _)| *member == device)
        {
            return Ok(false);
        }
        let me = self.device_id();
        let recipient = {
            let state = self.lock().await;
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(false);
            };
            if replica.level_of(&me) != Some(Level::Administer) {
                return Ok(false);
            }
            let Some(level) = replica.level_of(&device) else {
                return Ok(false);
            };
            let roster = replica.roster();
            match roster.state(&MemberRef::device(device)) {
                Some(member) if member.session.is_some() => None,
                Some(member) => member
                    .keys
                    .as_deref()
                    .filter(|keys| keys.keys.xwing().is_some())
                    .map(|keys| Recipient {
                        keys: keys.clone(),
                        writes: level >= Level::Write,
                        propagates: true,
                    }),
                None => roster
                    .members_in()
                    .filter(|(member, _)| member.kind == frasil_space::MemberType::Person)
                    .find_map(|(person, member)| {
                        crate::device::person_recipients(
                            &person.id,
                            member.level,
                            &state.lists,
                            Some(replica),
                        )
                        .into_iter()
                        .find(|recipient| recipient.keys.device_id() == device)
                    }),
            }
        };
        let Some(recipient) = recipient else {
            return Ok(false);
        };
        let keys = recipient.keys.clone();
        let (event, mut wraps) = self.deliver_with(space, vec![recipient]).await?;
        let Some(wrap) = wraps.remove(&device) else {
            return Ok(false);
        };
        self.wait_welcome(space, &keys, event, &wrap).await?;
        Ok(true)
    }
}
