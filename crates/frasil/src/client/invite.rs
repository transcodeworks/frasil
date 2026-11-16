//! Admitting a device: by its person's comparison of a code (admission.md,
//! "Nearby pairing"), where the host shows an invitation, the newcomer
//! enters it, and both screens show one six-digit admission code; or by an
//! invite link (ext-invite-links.md), which `super::link` follows.

use super::Device;
#[cfg(feature = "iroh")]
use super::{Space, SpaceId};
use crate::error::{Error, Result};
#[cfg(feature = "iroh")]
use frasil_events::EventId;
#[cfg(feature = "iroh")]
use frasil_space::Level;
#[cfg(feature = "iroh")]
use frasil_store::store::MaybeSend;
#[cfg(feature = "iroh")]
use frasil_transport::ticket::{Ticket, TicketKind};
use std::future::Future;
#[cfg(feature = "iroh")]
use tokio::sync::oneshot;

/// An invitation into a space, waiting for its newcomer.
#[cfg(feature = "iroh")]
#[derive(Debug)]
pub struct Invitation {
    text: String,
    space: SpaceId,
    done: oneshot::Receiver<Result<EventId>>,
}

#[cfg(feature = "iroh")]
impl Invitation {
    /// The text the newcomer enters in [`Device::join`]: show it, or a QR
    /// code of it, or send it by any channel to the person invited, such
    /// as a message, when the two devices are on different networks.
    ///
    /// It is a nearby ticket, short enough for a QR code: this device's
    /// member endpoint key, the addresses it listens on, and its relays.
    /// It names nothing of the space and admits no one by itself: the
    /// newcomer still has to show the same admission code, which both
    /// people compare. It serves while this invitation is hosted, until a
    /// newcomer is admitted or another invitation replaces it, and stops
    /// reaching this device once its member endpoint key rotates. Whoever
    /// reads it learns those addresses and relays, so send it only to the
    /// person invited.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The space it invites into.
    pub fn space(&self) -> SpaceId {
        self.space
    }

    /// Waits until the newcomer is admitted.
    ///
    /// # Errors
    ///
    /// `Mismatch` when either person did not confirm the code; the
    /// connection's failure; [`Error::Connection`] when the device closed
    /// before a newcomer came.
    pub async fn admitted(self) -> Result<()> {
        self.done
            .await
            .map_err(|_| Error::Connection("the device closed before a newcomer came".into()))?
            .map(drop)
    }
}

/// What an invitation's text names: a host's nearby endpoint, or an
/// invite link (ext-invite-links.md).
enum Invited {
    /// A host's nearby endpoint.
    #[cfg(feature = "iroh")]
    Nearby(Ticket),
    /// An invite link: the URL before `#`, if any, and the fragment.
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    Link {
        base: Option<String>,
        fragment: String,
    },
}

impl Invited {
    fn read(text: &str) -> Result<Self> {
        #[cfg(feature = "iroh")]
        if let Ok(ticket) = Ticket::read(text.trim())
            && ticket.kind == TicketKind::Nearby
        {
            return Ok(Self::Nearby(ticket));
        }
        #[cfg(all(
            feature = "ext-invite-links",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        ))]
        if let Some((base, fragment)) = super::link::split(text) {
            return Ok(Self::Link {
                base: base.map(str::to_owned),
                fragment: fragment.to_owned(),
            });
        }
        Err(Error::Invalid(
            "an invitation is the text that another device's Space::invite or \
             Space::invite_link shows",
        ))
    }
}

#[cfg(feature = "iroh")]
pub(super) async fn invite<F>(
    space: &Space,
    level: Level,
    name: &str,
    confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
) -> Result<Invitation>
where
    F: Future<Output = bool> + MaybeSend + 'static,
{
    invite_with(space, crate::pairing::default_offer(level), name, confirm).await
}

/// [`invite`], with the offer the newcomer is admitted on.
#[cfg(feature = "iroh")]
pub(super) async fn invite_with<F>(
    space: &Space,
    offer: frasil_admission::Offer,
    name: &str,
    confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
) -> Result<Invitation>
where
    F: Future<Output = bool> + MaybeSend + 'static,
{
    // Nearby admission carries no rank: it admits at most `write`, and an
    // explicit raise at a rank follows (roster.md, 2.3 Changes, "Ranks").
    if offer.level == Level::Administer {
        return Err(Error::Invalid(
            "nearby admission grants at most write; raise the member at a rank after",
        ));
    }
    let me = space.device.engine().device_id();
    let administers = space
        .read(|replica| replica.roster().is_administrator(&me.0))
        .await?;
    if !administers {
        return Err(Error::NotAllowed("inviting needs administer"));
    }
    let node = space.device.node().await?;
    let text = node
        .ticket(TicketKind::Nearby)
        .encode()
        .map_err(Error::class)?;
    let done = node.host_pairing(space.id().event(), offer, name, confirm);
    Ok(Invitation {
        text,
        space: space.id(),
        done,
    })
}

pub(super) async fn join<F>(
    device: &Device,
    invitation: &str,
    name: &str,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<super::Space>
where
    F: Future<Output = bool>,
{
    match Invited::read(invitation)? {
        #[cfg(feature = "iroh")]
        Invited::Nearby(ticket) => {
            let node = device.node().await?;
            let joined = node.join(&ticket, name, confirm).await?;
            device.present(joined.space);
            Ok(Space::new(device.clone(), SpaceId::of(joined.space)))
        }
        #[cfg(all(
            feature = "ext-invite-links",
            any(feature = "server", feature = "iroh", feature = "server-socket")
        ))]
        Invited::Link { base, fragment } => {
            let _ = name;
            super::link::join_link(device, base.as_deref(), &fragment, confirm).await
        }
    }
}
