//! Guests, as an application sees them (ext-guests.md): a guest is a
//! device admitted for a session, which reaches one space and nothing
//! else, reads what is shared from now on, and leaves when its session
//! ends.

use super::{Device, Space};
use crate::error::{Error, Result};
use frasil_space::Level;
use frasil_space::ext_guests::{Preset, SESSION_BYTES};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use frasil_store::store::MaybeSend;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use std::future::Future;
use std::time::Duration;

/// The terms on which a guest is admitted: its level, its session, how
/// long the session lasts, and whether its device keeps anything at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guest {
    level: Level,
    session: [u8; SESSION_BYTES],
    lifetime: Option<Duration>,
    nothing_at_rest: bool,
}

impl Guest {
    /// A guest at `level` (`read` or `write`) of `session`: 16 random
    /// bytes the application draws once per session, and names again to
    /// end it with [`Space::end_session`].
    pub fn new(level: Level, session: [u8; SESSION_BYTES]) -> Self {
        Self {
            level,
            session,
            lifetime: None,
            nothing_at_rest: false,
        }
    }

    /// Ends the session `lifetime` after the admission, at most 30 days:
    /// the guest's own device stops writing then, and an administering
    /// device removes it.
    #[must_use]
    pub fn lasting(mut self, lifetime: Duration) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Asks the guest's device to keep the space in memory only, never at
    /// rest. It binds honest clients only.
    #[must_use]
    pub fn nothing_at_rest(mut self) -> Self {
        self.nothing_at_rest = true;
        self
    }

    /// The session.
    pub fn session(&self) -> [u8; SESSION_BYTES] {
        self.session
    }

    /// The guest preset, its `expires_at` from this device's wall clock.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    fn preset(&self, device: &Device) -> Result<Preset> {
        if self.level == Level::Administer {
            return Err(Error::Invalid(
                "a guest reads or writes, and never administers",
            ));
        }
        let mut preset = Preset::new(self.level, self.session);
        preset.nothing_at_rest = self.nothing_at_rest;
        if let Some(lifetime) = self.lifetime {
            if lifetime.as_secs() > frasil_space::ext_guests::SESSION_LIFETIME_MAX {
                return Err(Error::Invalid("a session lasts at most 30 days"));
            }
            let wall = device
                .engine()
                .platform()
                .clock
                .wall()
                .ok_or(Error::NotAllowed("a session's end needs a wall clock"))?;
            preset.expires_at = Some(wall.saturating_add(lifetime.as_secs()));
        }
        Ok(preset)
    }
}

impl Space {
    /// Invites a guest on these terms: as [`Space::invite`], and the
    /// device admitted is a guest of the session.
    ///
    /// # Errors
    ///
    /// As [`Space::invite`]; [`Error::Invalid`] for terms that do not
    /// read.
    #[cfg(feature = "iroh")]
    pub async fn invite_guest<F>(
        &self,
        guest: &Guest,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<super::Invitation>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        let offer = frasil_admission::ext_guests::guest_offer(&guest.preset(self.device())?);
        super::invite::invite_with(self, offer, name, confirm).await
    }

    /// Admits a guest on these terms, through the exchange mailbox its
    /// [`Joining::text`](super::Joining::text) names: as [`Space::admit`],
    /// and the device admitted is a guest of the session.
    ///
    /// # Errors
    ///
    /// As [`Space::admit`]; [`Error::Invalid`] for terms that do not read.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn admit_guest<F>(
        &self,
        code: &str,
        guest: &Guest,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<()>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        let offer = frasil_admission::ext_guests::guest_offer(&guest.preset(self.device())?);
        super::exchange::admit(self, code, offer, None, name, confirm).await
    }

    /// Ends a session: every guest of it is removed in one change of the
    /// membership, and reads nothing written after.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when no guest of the session is in;
    /// [`Error::NotAllowed`] unless this device administers the space.
    pub async fn end_session(&self, session: [u8; SESSION_BYTES]) -> Result<()> {
        self.device
            .engine()
            .end_session(self.id().event(), &session)
            .await
            .map(drop)
    }

    /// Asks the space's administering devices to remove this device, and
    /// from now on writes nothing there (ext-guests.md, "The leave
    /// request"). A space kept in memory only is forgotten at once.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that administers the space, which
    /// steps down instead.
    pub(super) async fn request_leave(&self) -> Result<()> {
        let leaving = self.device.engine().leave(self.id().event()).await?;
        // The request, sealed to each administering device, in its device
        // mailbox at every peer the device is connected to.
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            // A space kept in memory only keeps its deposits in memory too.
            let at_rest = !self
                .device
                .engine()
                .is_memory_only(&self.id().event())
                .await;
            for peer in self.device.peers() {
                if !peer.status().connected {
                    continue;
                }
                for (address, item) in &leaving.deposits {
                    let _ = self
                        .device
                        .deposit(peer.url(), *address, item.clone(), at_rest)
                        .await;
                }
            }
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = leaving;
        Ok(())
    }
}
