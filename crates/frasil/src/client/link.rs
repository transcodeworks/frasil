//! Invite links (ext-invite-links.md): a link that admits a device with no
//! administrator online.
//!
//! - [`Space::invite_link`] grants an invite key, publishes the snapshot
//!   of an invite "from now on" at the peers the device is connected to,
//!   places the drop that holds its wrap and names that snapshot at every
//!   one of them, and returns the link: the first such peer's URL, `#`,
//!   and the fragment.
//! - [`Device::join`] takes a link: it fetches the drop from the link's
//!   peer, or any peer the device is connected to, fetches the snapshot the
//!   drop names, if any, then the space, from there with the state the drop
//!   hands it, checks the invite, and signs the successor once its person
//!   consents.
//! - The device's upkeep closes and revokes invites
//!   ([`Engine::maintain_invites`](crate::advanced::Engine::maintain_invites))
//!   and deletes the drops of its own once their key is removed.

use super::{Device, Peer, Space, SpaceId};
use crate::error::{Error, Result};
use crate::peer::{CONNECTION_ENDED, MailboxAsk};
use frasil_admission::ext_invite_links::{drop_address, read_fragment};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level};
use std::time::Duration;

/// How long a device waits for one answer of a peer about a drop.
const DROP_DEADLINE: Duration = Duration::from_secs(10);

/// How long a claimant waits for the invite entry and the space's events.
const CLAIM_DEADLINE: Duration = Duration::from_secs(60);

/// How many times a device asks one peer to keep an invite's drop.
const DROP_TRIES: u32 = 4;

/// The wait before the second try, doubled before each later one.
const DROP_RETRY: Duration = Duration::from_millis(250);

/// A link's parts: the URL before `#`, if any, and the fragment.
pub(super) fn split(text: &str) -> Option<(Option<&str>, &str)> {
    let text = text.trim();
    let (base, fragment) = match text.rsplit_once('#') {
        Some((base, fragment)) => (Some(base).filter(|b| !b.is_empty()), fragment),
        None => (None, text),
    };
    read_fragment(fragment).ok()?;
    Some((base, fragment))
}

impl Peer {
    /// Sends a drop message, within [`DROP_DEADLINE`]: the drop, for a
    /// fetch.
    async fn drop_message(&self, device: &Device, ask: MailboxAsk) -> Result<Option<Vec<u8>>> {
        let answer = async {
            self.handle()
                .mailbox(ask)
                .await
                .map(|items| items.into_iter().next().map(|(_, drop)| drop))
        };
        let deadline = device.sleep(DROP_DEADLINE);
        tokio::select! {
            answer = answer => answer.map_err(Error::Connection),
            () = deadline => Err(Error::Timeout),
        }
    }

    /// Fetches an invite's drop: `None` when the peer answers that it
    /// keeps none. A peer that is busy or that does not answer in time is
    /// asked again, a few times, as [`place_drop`](Self::place_drop) asks.
    ///
    /// # Errors
    ///
    /// The last try's, when none was answered.
    async fn get_drop(&self, device: &Device, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let mut wait = DROP_RETRY;
        let mut last = Error::Timeout;
        for _ in 0..DROP_TRIES {
            match self
                .drop_message(device, MailboxAsk::DropGet { address })
                .await
            {
                Err(Error::Connection(code)) if code == "not_found" => return Ok(None),
                Err(Error::Connection(code)) if code == "busy" => {
                    last = Error::Connection(code);
                }
                Err(Error::Timeout) => last = Error::Timeout,
                answer => return answer,
            }
            device.sleep(wait).await;
            wait = wait.saturating_mul(2);
        }
        Err(last)
    }

    /// Places an invite's drop: whether the peer keeps it. A peer that is
    /// busy, that refuses the store right the connection held a moment
    /// before (a rotation, a heal after a claim among them, retires the
    /// upload entry the connection proved, and it proves the next one
    /// soon after), or that does not answer in time is asked again, a few
    /// times. A conflict after a try that was not answered is that try's
    /// drop: the address is the invite's own.
    async fn place_drop(&self, device: &Device, ask: &MailboxAsk) -> bool {
        let conflict = frasil_peers::Code::Conflict.name();
        let credential = frasil_peers::Code::CredentialRefused.name();
        let mut unanswered = false;
        let mut wait = DROP_RETRY;
        for _ in 0..DROP_TRIES {
            match self.drop_message(device, ask.clone()).await {
                Ok(_) => return true,
                Err(Error::Connection(code)) if unanswered && code == conflict => return true,
                Err(Error::Connection(code)) if code == "busy" || code == credential => {}
                Err(Error::Timeout) => unanswered = true,
                Err(_) => return false,
            }
            device.sleep(wait).await;
            wait = wait.saturating_mul(2);
        }
        false
    }
}

/// [`Space::invite_link`].
pub(super) async fn invite_link(
    space: &Space,
    level: Level,
    history: HistoryMode,
    claimant: crate::Claimant,
    lifetime: Duration,
) -> Result<String> {
    let device = space.device();
    let peers: Vec<Peer> = device
        .peers()
        .into_iter()
        .filter(|peer| peer.status().connected)
        .collect();
    if peers.is_empty() {
        return Err(Error::NotAllowed(
            "an invite link needs a connected peer to keep its drop",
        ));
    }
    let hints = peers.iter().map(|peer| peer.url().to_owned()).collect();
    let made = device
        .engine()
        .make_invite(
            space.id().event(),
            level,
            history,
            claimant,
            lifetime.as_secs(),
            hints,
        )
        .await?;
    // The snapshot for K is at a peer before the drop that names it.
    if let Some(unit) = made.snapshot_unit {
        super::exchange::published(device, made.space, unit).await?;
    }
    let mut base = None;
    let mut kept_at = Vec::new();
    let ask = MailboxAsk::DropPut {
        space: made.space,
        address: made.address,
        drop: made.drop.clone(),
        lifetime: made.lifetime,
    };
    for peer in &peers {
        if peer.place_drop(device, &ask).await {
            kept_at.push(peer.url().to_owned());
            if base.is_none() {
                base = Some(peer.url().trim_end_matches('/').to_owned());
            }
        }
    }
    device.engine().drops_kept_at(made.entry, kept_at).await;
    let base = base.ok_or(Error::Connection(
        "no peer kept the invite's drop; the invite expires unclaimed".into(),
    ))?;
    Ok(format!("{base}#{}", made.fragment))
}

/// [`Space::revoke_invite_link`].
pub(super) async fn revoke_invite_link(space: &Space, link: &str) -> Result<()> {
    let (_, fragment) = split(link).ok_or(Error::Invalid("not an invite link"))?;
    let parts = read_fragment(fragment).map_err(Error::class)?;
    if parts.space != space.id().event() {
        return Err(Error::Invalid("the link is into another space"));
    }
    if space.level().await != Some(Level::Administer) {
        return Err(Error::NotAllowed(
            "revoking an invite link needs administer",
        ));
    }
    let device = space.device();
    // The drops go first: a peer deletes one only on a connection that
    // proved the upload entry it was placed under, and the revocation
    // rotates to a new one. A drop placed by another device stays until
    // it expires; a claim of it is refused as revoked.
    let address = drop_address(&parts.secret);
    let kept_at = device.engine().drops_of(&parts.entry).await;
    let under = device.engine().drop_state(&parts.entry).await;
    for peer in device.peers() {
        if peer.status().connected && keeps_drop(kept_at.as_deref(), &peer) {
            let _ = peer
                .drop_message(
                    device,
                    MailboxAsk::DropDelete {
                        space: parts.space,
                        address,
                        under: under.clone(),
                    },
                )
                .await;
        }
    }
    device
        .engine()
        .revoke_invite(space.id().event(), fragment)
        .await?;
    // The revocation goes out on every connection; this device then lets
    // go of the invite.
    device.present(space.id().event());
    delete_spent_drops(device).await;
    Ok(())
}

/// Joins by an invite link (ext-invite-links.md, "Claiming").
pub(super) async fn join_link<F>(
    device: &Device,
    base: Option<&str>,
    fragment: &str,
    confirm: impl FnOnce(String, String) -> F,
) -> Result<Space>
where
    F: std::future::Future<Output = bool>,
{
    let link = read_fragment(fragment).map_err(Error::class)?;
    let address = drop_address(&link.secret);
    // 2. The drop: from the link's peer, then any the device is connected
    // to.
    let mut peers = Vec::new();
    if let Some(base) = base {
        let known = device
            .peers()
            .into_iter()
            .find(|peer| peer.url().trim_end_matches('/') == base && peer.status().connected);
        peers.push(match known {
            Some(peer) => peer,
            None => device.connect(base).await?,
        });
    }
    for peer in device.peers() {
        if peer.status().connected && !peers.iter().any(|p: &Peer| p.url() == peer.url()) {
            peers.push(peer);
        }
    }
    // A link no peer holds a drop for is `NotFound`; when a peer could not
    // say, its failure is the answer, not that the link is gone.
    let mut drop = None;
    let mut failed = None;
    for peer in &peers {
        match peer.get_drop(device, address).await {
            Ok(Some(found)) => {
                drop = Some(found);
                break;
            }
            Ok(None) => {}
            Err(error) => failed = Some(error),
        }
    }
    let drop = match (drop, failed) {
        (Some(drop), _) => drop,
        (None, Some(error)) => return Err(error),
        (None, None) => return Err(Error::Class("NotFound")),
    };
    // 3 and 4: open it, and fetch the space with the state it hands over.
    let engine = device.engine();
    let space = engine.begin_claim(fragment, &drop).await?;
    device.present(space);
    // 5 to 10, once the invite entry and the events before it arrive.
    let offer = match wait_for_offer(device, space).await {
        Ok(offer) => offer,
        Err(error) => {
            engine.abandon_claim(&space).await?;
            return Err(error);
        }
    };
    let offer = match offer {
        Some(offer) => offer,
        None => return Ok(Space::new(device.clone(), SpaceId::of(space))),
    };
    let inviter = super::MemberId::device(offer.inviter).to_string();
    if !confirm(String::new(), inviter).await {
        engine.abandon_claim(&space).await?;
        return Err(Error::Class("Declined"));
    }
    engine.claim(space).await?;
    // 11. The successor goes out on every connection, then the claimant's
    // list: published if it writes, otherwise in the device mailbox of each
    // writer device, and again from the device's upkeep until it lands.
    device.present(space);
    hand_over_list(device, space, 0).await;
    Ok(Space::new(device.clone(), SpaceId::of(space)))
}

/// The first wait, in seconds, before a claimant hands its list to the
/// space again.
const LIST_AGAIN_FIRST: u64 = 30;

/// How long after its claim a claimant hands its list again, in seconds:
/// 7 days, the most an invite stays open.
const LIST_AGAIN_FOR: u64 = 7 * 24 * 3_600;

/// The slot of the schedule on which a claimant hands its list again that
/// `elapsed` seconds after its claim fall in: slot `k` begins
/// [`LIST_AGAIN_FIRST`] × (2^`k` − 1) seconds after it, so the waits double
/// from 30 seconds, and slot 0 is the claim's own hand-over.
pub(super) fn list_slot(elapsed: u64) -> u32 {
    let points = elapsed / LIST_AGAIN_FIRST + 1;
    63 - points.leading_zeros()
}

/// Hands this device's person's list to `space` ("Claiming", step 11):
/// each item [`Engine::hand_over_list`](crate::advanced::Engine) seals
/// goes to every connected peer, as a deposit kept until a peer takes it.
/// Records `slot` as handed once a peer was reached, or once nothing is
/// left to hand.
async fn hand_over_list(device: &Device, space: EventId, slot: u32) {
    let Ok(items) = device.engine().hand_over_list(space).await else {
        return;
    };
    let mut reached = items.is_empty();
    for peer in device.peers() {
        if !peer.status().connected {
            continue;
        }
        reached = true;
        for (address, item) in &items {
            let _ = device
                .deposit(peer.url(), *address, item.clone(), true)
                .await;
        }
    }
    if reached {
        device
            .inner
            .handed_lists
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(space, slot);
    }
}

/// Hands each claim's list to its space again, from the device's upkeep
/// (units.md, "A read-only person's list events"). A writer that does not
/// hold the successor yet drops the list, since its roster does not name
/// the claimant's person; the claimant keeps sending until each event
/// appears in the space's system stream, which is when
/// [`Engine::hand_over_list`](crate::advanced::Engine) seals nothing more.
/// It hands it again on a schedule that begins at the claim, its first
/// sight of the successor, which is kept at rest, so a restart neither
/// forgets it nor starts it over: after 30 seconds, then with the wait
/// doubling, for [`LIST_AGAIN_FOR`]. A restart hands it once more at once.
pub(super) async fn hand_over_lists_again(device: &Device) {
    let engine = device.engine();
    let Ok(now) = engine.reading().await else {
        return;
    };
    for (space, first) in engine.claims_signed().await {
        if frasil_base::time::upper(&first, &now).at_least(LIST_AGAIN_FOR) {
            continue;
        }
        let slot = list_slot(frasil_base::time::lower(&first, &now));
        let handed = device
            .inner
            .handed_lists
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&space)
            .copied();
        if handed.is_some_and(|handed| handed >= slot) {
            continue;
        }
        hand_over_list(device, space, slot).await;
    }
}

/// Waits until the claim is ready, within [`CLAIM_DEADLINE`]; `None` when
/// this device signed its successor already.
async fn wait_for_offer(
    device: &Device,
    space: EventId,
) -> Result<Option<crate::invite_links::ClaimOffer>> {
    use crate::invite_links::ClaimStatus;
    let engine = device.engine();
    let mut notices = engine.subscribe();
    let tick = Duration::from_millis(250);
    let mut waited = Duration::ZERO;
    loop {
        device.fetch_snapshot(space).await;
        match engine.claim_status(&space).await? {
            ClaimStatus::Ready(offer) => return Ok(Some(offer)),
            ClaimStatus::Claimed(_) => return Ok(None),
            ClaimStatus::Waiting => {}
        }
        if waited >= CLAIM_DEADLINE {
            return Err(Error::Timeout);
        }
        let sleep = device.sleep(tick);
        tokio::select! {
            _ = notices.recv() => {}
            () = sleep => waited += tick,
        }
    }
}

/// Whether `peer` may keep a drop placed at `kept_at`: any peer when where
/// it was placed is not known.
fn keeps_drop(kept_at: Option<&[String]>, peer: &Peer) -> bool {
    kept_at.is_none_or(|urls| urls.iter().any(|url| url == peer.url()))
}

/// Deletes the drops of the invites this device made whose key is
/// removed, at every connected peer, and lets go of each invite whose
/// drops are gone or expired (ext-invite-links.md, "Administering
/// devices").
pub(super) async fn delete_spent_drops(device: &Device) {
    let engine = device.engine();
    for spent in engine.spent_invites().await {
        let mut gone = spent.expired;
        if !gone {
            let kept_at = spent.kept_at.as_deref();
            // An invite in a space file placed no drop: nothing to delete.
            let placed_none = kept_at.is_some_and(<[String]>::is_empty);
            let peers: Vec<Peer> = device
                .peers()
                .into_iter()
                .filter(|peer| peer.status().connected && keeps_drop(kept_at, peer))
                .collect();
            let mut all = placed_none || !peers.is_empty();
            for peer in &peers {
                let answer = peer
                    .drop_message(
                        device,
                        MailboxAsk::DropDelete {
                            space: spent.space,
                            address: spent.address,
                            under: spent.under.clone(),
                        },
                    )
                    .await;
                all &= match answer {
                    Ok(_) => true,
                    // No drop there; or, for an invite made before the
                    // device opened, a peer without ext-invite-links, which
                    // closes the connection on `MailboxDelete` and keeps no
                    // drop. A drop left anywhere expires, and its claims are
                    // refused as revoked.
                    Err(Error::Connection(code)) => {
                        code == "not_found" || (kept_at.is_none() && code == CONNECTION_ENDED)
                    }
                    Err(_) => false,
                };
            }
            gone = all;
        }
        if gone {
            let _ = engine.forget_invite(&spent.space, &spent.entry).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::list_slot;

    /// A claimant hands its list again 30 seconds after its claim, then
    /// with the wait doubling: at 30, 90, 210 and 450 seconds, and so on.
    #[test]
    fn the_list_goes_again_with_a_doubling_wait() {
        let slots: Vec<u32> = [0, 29, 30, 89, 90, 209, 210, 449, 450]
            .into_iter()
            .map(list_slot)
            .collect();
        assert_eq!(slots, [0, 0, 1, 1, 2, 2, 3, 3, 4]);
        // Within 7 days, at most 15 times after the claim's own.
        assert_eq!(list_slot(7 * 24 * 3_600), 14);
        assert_eq!(list_slot(u64::MAX), 59);
    }
}
