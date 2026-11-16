//! The grant the approver signs, and the joiner's checks of it
//! (admission.md, "The admission event", "Accepting a grant").
//!
//! The joiner opens its wrap as the welcome says, derives the body key,
//! opens the admitting event ([`open_admitting_event`]), and checks, in
//! order ([`check_grant`]):
//!
//! ```text
//! 1. Its author is the Response's approver.                             else WrongApprover
//! 2. Its log is the Response's log.                                     else WrongSpace
//! 3. Every head of the Response is in its past.                         else NotFollowing
//! 4. It holds exactly one grant of the joiner: the person ID, or the
//!    device's device ID.                                                else WrongMember
//! 5. That grant's level, capabilities, label, history, session,
//!    replaces and expires_at are the offer's, and via is code.          else OfferMismatch
//! 6. A replaces grant comes with the removal of that person, and an
//!    offer from now on comes in a rotation that breaks.                 else OfferMismatch
//! 7. Its own resolution of the space finds the event valid.             else the event's verdict
//! ```
//!
//! Step 7 is the caller's: it resolves the space with `frasil-space` and
//! the keys the grant gave it. Until step 7 can run, the grant is held,
//! never relied on. A device grant whose keys do not give its member ID
//! is `NotCommitted` there.

use crate::bodies::RevealBody;
use crate::offer::Offer;
use crate::welcome::Welcome;
use crate::{AdmissionClass, malformed};
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId};
use frasil_keys::KeyName;
use frasil_keys::body::{Inner, VisiblePart};
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::body_key;
use frasil_keys::wraps::open_bundle_wrap;
use frasil_space::part::{PartContext, RosterPart};
use frasil_space::{Change, HistoryMode, Level, Limits, MemberRef, Op, Via};
use std::collections::BTreeSet;

/// The grant change an approver signs after a matched code (ctx `0x02`):
/// the offer's fields for the revealed joiner, `via` = `code`. A device
/// grant names the device ID of the revealed keys, and carries the keys.
/// A device granted `administer` takes the top rank, 255; an approver of
/// a lower rank names one at most its own with [`grant_change_ranked`]
/// (roster.md, 2.3 Changes, "Ranks").
///
/// # Errors
///
/// `InvalidKey` for revealed keys crypto.md's checks refuse.
pub fn grant_change(offer: &Offer, reveal: &RevealBody) -> Result<Change, AdmissionClass> {
    grant_change_ranked(offer, reveal, frasil_space::change::MAX_RANK)
}

/// [`grant_change`], with `rank` the rank a device granted `administer`
/// takes (change key 15). The rank is left out at any other level.
///
/// # Errors
///
/// `InvalidKey` for revealed keys crypto.md's checks refuse.
pub fn grant_change_ranked(
    offer: &Offer,
    reveal: &RevealBody,
    rank: u8,
) -> Result<Change, AdmissionClass> {
    let mut change = match reveal {
        RevealBody::Device { keys, .. } => {
            Change::grant_device(keys.checked()?, offer.level, offer.history, Via::Code)
        }
        RevealBody::Person { person, .. } => Change::grant(
            MemberRef::person(*person),
            offer.level,
            offer.history,
            Via::Code,
        ),
    };
    change.capabilities = offer.capabilities.clone();
    change.label = offer.label.clone();
    change.session = offer.session;
    change.replaces = offer.replaces;
    change.expires_at = offer.expires_at();
    if change.grants_device() && change.level == Some(Level::Administer) && change.session.is_none()
    {
        change.rank = Some(rank);
    }
    Ok(change)
}

/// The joiner the code authenticated, as a grant must name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedJoiner<'a> {
    /// A device: the device ID of the keys it revealed, which the code
    /// authenticated.
    Device(DeviceId),
    /// A person.
    Person(&'a [u8; 32]),
}

impl<'a> ExpectedJoiner<'a> {
    /// The joiner a Reveal names.
    pub fn of(reveal: &'a RevealBody) -> Self {
        match reveal {
            RevealBody::Device { keys, .. } => Self::Device(keys.device_id()),
            RevealBody::Person { person, .. } => Self::Person(person),
        }
    }

    fn member(&self) -> MemberRef {
        match self {
            Self::Device(device) => MemberRef::device(*device),
            Self::Person(person) => MemberRef::person(**person),
        }
    }
}

/// What the code authenticated of the approver's side: the Response's (or
/// the setup flow's Offer's) approver, log, heads and offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authenticated<'a> {
    /// The approver's device ID.
    pub approver: &'a DeviceId,
    /// The space ID.
    pub log: &'a [u8; 32],
    /// The heads of the space's log at the approver.
    pub heads: &'a [EventId],
    /// The offer.
    pub offer: &'a Offer,
}

/// An admitting event, opened with the joiner's own wrap.
#[derive(Debug, Clone)]
pub struct OpenedGrant {
    /// The body's visible part.
    pub visible: VisiblePart,
    /// The sealed part.
    pub inner: Inner,
    /// The roster changes it makes.
    pub changes: Vec<Change>,
    /// The bundle the wrap carried.
    pub bundle: Bundle,
    /// The event's body key.
    pub body_key: [u8; 32],
}

/// Opens an admitting event (admission.md, "Accepting a grant", and
/// "Welcomes"): finds the delivery that holds exactly the welcome's wrap
/// under the welcome's key names, opens the wrap with the joiner's device
/// ID and X-Wing seed, derives the body key from the bundle's content key,
/// opens the sealed part and reads the roster part.
///
/// # Errors
///
/// `Malformed` for a welcome of another event or space, a delivery that does
/// not hold the wrap, a bundle without a content key or an event that
/// carries no roster part; the classes of keys.md's and roster.md's checks
/// as their shared class.
pub fn open_admitting_event(
    event: &Event,
    welcome: &Welcome,
    device: &DeviceId,
    xwing_seed: &[u8; 32],
) -> Result<OpenedGrant, AdmissionClass> {
    if event.is_genesis() || event.id() != welcome.event || event.log_id().0 != welcome.space {
        return Err(malformed());
    }
    let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq())
        .map_err(AdmissionClass::of)?;
    let name = |bytes: &[u8]| -> Result<Option<KeyName>, AdmissionClass> {
        if bytes.is_empty() {
            Ok(None)
        } else {
            KeyName::decode(bytes, true)
                .map(Some)
                .map_err(AdmissionClass::of)
        }
    };
    let key_name = name(&welcome.key_name)?;
    let grant_name = name(&welcome.grant_name)?;
    let holds = visible.deliveries.iter().any(|delivery| {
        delivery.key_name == key_name
            && delivery.grant_name == grant_name
            && delivery.wraps.contains(&welcome.wrap)
    });
    if !holds {
        return Err(malformed());
    }
    let log = welcome.space;
    let bundle = open_bundle_wrap(
        &welcome.wrap,
        &log,
        key_name.as_ref(),
        grant_name.as_ref(),
        device,
        xwing_seed,
    )
    .map_err(AdmissionClass::of)?;
    let content = *bundle.content().ok_or_else(malformed)?;
    let key = body_key(&content, &log, event.author(), event.seq());
    let inner = visible
        .open(&key, &log, event.author(), event.seq())
        .map_err(AdmissionClass::of)?;
    let roster = inner.roster.as_ref().ok_or_else(malformed)?;
    let part = RosterPart::read(
        roster,
        &PartContext {
            author: event.author(),
            space: Some(&log),
            rotates: visible.rotates(),
            limits: &Limits::PROTOCOL,
        },
    )
    .map_err(AdmissionClass::of)?;
    Ok(OpenedGrant {
        changes: part.changes().to_vec(),
        visible,
        inner,
        bundle,
        body_key: *key,
    })
}

/// Steps 1 to 6 of "Accepting a grant", in order. `past` is the event's
/// past in the log the joiner fetched; `via` is what the admission rests on,
/// `code` after a code or setup exchange. Returns the grant.
///
/// # Errors
///
/// `WrongApprover`, `WrongSpace`, `NotFollowing`, `WrongMember`,
/// `OfferMismatch`.
pub fn check_grant<'g>(
    event: &Event,
    opened: &'g OpenedGrant,
    past: &BTreeSet<EventId>,
    authenticated: &Authenticated<'_>,
    joiner: &ExpectedJoiner<'_>,
    via: Via,
) -> Result<&'g Change, AdmissionClass> {
    // 1.
    if event.author() != authenticated.approver {
        return Err(AdmissionClass::WrongApprover);
    }
    // 2.
    if event.is_genesis() || event.log_id().0 != *authenticated.log {
        return Err(AdmissionClass::WrongSpace);
    }
    // 3.
    if !authenticated.heads.iter().all(|head| past.contains(head)) {
        return Err(AdmissionClass::NotFollowing);
    }
    // 4.
    let member = joiner.member();
    let grants: Vec<&Change> = opened
        .changes
        .iter()
        .filter(|c| c.op == Op::Grant && c.member == Some(member))
        .collect();
    let [grant] = grants[..] else {
        return Err(AdmissionClass::WrongMember);
    };
    // 5.
    let offer = authenticated.offer;
    if grant.level != Some(offer.level)
        || grant.capabilities != offer.capabilities
        || grant.label != offer.label
        || grant.history != Some(offer.history)
        || grant.session != offer.session
        || grant.replaces != offer.replaces
        || grant.expires_at != offer.expires_at()
        || grant.via != Some(via)
    {
        return Err(AdmissionClass::OfferMismatch);
    }
    // 6.
    if let Some(replaced) = grant.replaces {
        let removes = opened
            .changes
            .iter()
            .any(|c| c.op == Op::Remove && c.member == Some(MemberRef::person(replaced)));
        if !removes {
            return Err(AdmissionClass::OfferMismatch);
        }
    }
    if offer.history == HistoryMode::FromNowOn
        && !(opened.visible.rotates() && opened.inner.is_break)
    {
        return Err(AdmissionClass::OfferMismatch);
    }
    Ok(grant)
}
