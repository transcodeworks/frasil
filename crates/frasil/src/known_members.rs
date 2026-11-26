//! A member of another space (admission.md, 3.16): an administrator grants
//! a device that a space it holds grants directly, by the device ID and
//! keys that roster names, with no code and no peer, and keeps its welcome
//! waiting at rest in the grant's commit (admission.md, 3.10 Welcomes, "A
//! welcome that waits").

use crate::device::Engine;
use crate::error::{Error, Result};
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Via};

impl Engine {
    /// Grants `device`, which `known` grants directly, in `space`
    /// (admission.md, 3.16 A member of another space): at `level`, with
    /// `rank` exactly when `level` is `administer`, with history, `via` =
    /// `none`, carrying the keys `known`'s grant names. The grant commits
    /// at once, with the device's welcome kept at rest in its commit; the
    /// welcome waits for a member connection with the device and goes to
    /// the mailbox at peers as a person grant's does (admission.md, 3.10
    /// Welcomes). Returns the admitting event.
    ///
    /// # Errors
    ///
    /// In the order admission.md, 3.16 checks them, each
    /// [`Error::NotAllowed`]: this device does not administer `space`;
    /// `known` does not reach this device; `known` does not grant the
    /// device directly; the device is a guest there; `known` does not
    /// reach the device, or the device forked there; `space` reaches the
    /// device already; a restricted space's parent does not reach it. [`Error::Invalid`] for `administer`
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
            if source.level_of(&me).is_none() {
                return Err(Error::NotAllowed(
                    "the known space does not reach this device",
                ));
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
            if source.level_of(&device).is_none() || source.forked(&device) {
                return Err(Error::NotAllowed(
                    "the known space's grant of the device is not in effect",
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
        let change = change(keys.clone())?;
        // The welcome is kept at rest in the grant's own commit, so that
        // no crash between the two loses it (admission.md, 3.10 Welcomes,
        // "A welcome that waits").
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            let hints = self.welcome_hints(&space, &[]).await;
            let since = self.welcome_time().await;
            let mut waiting = Vec::new();
            let (event, _) = self
                .sign_roster_keeping(space, vec![change], |event, wraps| {
                    waiting = self.seal_welcomes(
                        space,
                        event,
                        wraps,
                        std::slice::from_ref(&keys),
                        &hints,
                        since,
                    )?;
                    Ok(waiting
                        .iter()
                        .map(crate::welcomes::welcome_record)
                        .collect())
                })
                .await?;
            self.waiting_kept(waiting).await;
            Ok(event)
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        self.sign_roster(space, vec![change]).await
    }
}
