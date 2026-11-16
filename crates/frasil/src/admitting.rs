//! A newcomer's side of an admission by code (admission.md, "Accepting a
//! grant"), whichever route the exchange took: a nearby connection, or an
//! exchange mailbox at a peer ("Exchange mailboxes").
//!
//! Through a mailbox, nothing hands the newcomer the space's events: it
//! opens its welcome's wrap, presents the state the wrap holds to the peer
//! the welcome names, fetches the space from there, and then checks the
//! admitting event as a nearby newcomer does. A newcomer admitted "from now
//! on" first fetches the snapshot its welcome names, and starts from it
//! ("The newcomer's snapshot").

use crate::device::Engine;
use crate::error::{Error, Result};
use frasil_admission::bodies::ResponseBody;
use frasil_admission::grant::{Authenticated, ExpectedJoiner, check_grant, open_admitting_event};
use frasil_admission::welcome::Welcome;
use frasil_admission::{JoinerType, Offer};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::{KeyName, RotationSet};
use frasil_space::{Status, Via};
use zeroize::Zeroizing;

impl Engine {
    /// Follows the space a welcome admits this device to, and keeps the
    /// state its wrap holds, which the device presents to peers until the
    /// space's log arrives, and the snapshot it names, which the device
    /// fetches and uses before the space's events. Returns the space.
    ///
    /// # Errors
    ///
    /// `Malformed` for key names that do not read; the wrap's class.
    pub async fn begin_welcomed(&self, welcome: &Welcome) -> Result<EventId> {
        let whole = |bytes: &[u8]| match KeyName::read(bytes, true) {
            Ok((name, [])) => Ok(name),
            _ => Err(Error::Class("Malformed")),
        };
        let key = whole(&welcome.key_name)?;
        let grant = if welcome.grant_name.is_empty() {
            None
        } else {
            Some(whole(&welcome.grant_name)?)
        };
        let bundle = frasil_keys::wraps::open_bundle_wrap(
            &welcome.wrap,
            &welcome.space,
            Some(&key),
            grant.as_ref(),
            &self.device_id(),
            self.xwing_seed(),
        )
        .map_err(Error::class)?;
        let content = *bundle.content().ok_or(Error::Class("Malformed"))?;
        let state = match key {
            KeyName::Set(set) => set,
            KeyName::SelfRef(_) => RotationSet::single(welcome.event),
        };
        let space = EventId(welcome.space);
        self.follow(space).await;
        let mut held = self.lock().await;
        held.ignored_erasure_welcomes.remove(&space);
        if let Some(replica) = held.replicas.get_mut(&space) {
            replica.keep_bootstrap_state(state, Zeroizing::new(content));
            // Admitted "from now on": the snapshot comes first
            // (admission.md, "The newcomer's snapshot").
            if let Some(snapshot) = welcome.snapshot {
                replica.await_snapshot(snapshot);
            }
        }
        Ok(space)
    }
}

/// An event's past, with the stubbed parents a newcomer's base holds in
/// place of events: a head the approver named may be one of them. The walk
/// goes through witnessed events, the units of streams a partial replica has
/// not opened (units.md, "Partial replicas").
///
/// The past is complete only once every event in it has arrived. `None` while
/// one has not: the walk would stop at the gap, and a Response head beyond it
/// would read as not followed, refusing a grant that is only still arriving.
fn past_with_stubs(
    log: &frasil_events::Log,
    id: EventId,
) -> Option<std::collections::BTreeSet<EventId>> {
    let mut past = std::collections::BTreeSet::new();
    let mut stack = vec![id];
    while let Some(current) = stack.pop() {
        let Some(event) = log.event(current).or_else(|| log.witnessed(current)) else {
            // A stub a newcomer's base holds is a parent with no event, by
            // design, and so is a parent the replica dropped, or keeps as an
            // envelope alone, before the checkpoint it started from or
            // forgot under (roster.md, 3.15.6); anything else missing is
            // still on its way.
            let boundary = log.stub(current).is_some()
                || log.is_dropped(current)
                || log.kept_envelope_of(current).is_some();
            if current == id || !boundary {
                return None;
            }
            continue;
        };
        for parent in event.parents() {
            if past.insert(*parent) {
                stack.push(*parent);
            }
        }
    }
    // The walk cannot go through a stub, so a stub of the base behind another
    // one is not reached. An author's chain is in the past all the same:
    // `prev` is always a parent (events.md, section 2.2), so an event or stub
    // of an author at `seq` s follows that author's every event before it.
    // A stub of the base is such an event when its author's chain in the past
    // reaches its `seq`. A fork that makes two events of one `seq` voids the
    // author's events from there on (events.md, section 3.5), which step 7's
    // resolution of the space applies.
    let mut reached: std::collections::BTreeMap<DeviceId, u64> = std::collections::BTreeMap::new();
    let mut reach = |author: DeviceId, seq: u64| {
        let at = reached.entry(author).or_insert(0);
        *at = (*at).max(seq);
    };
    if let Some(own) = log.event(id).or_else(|| log.witnessed(id)) {
        // The event itself follows its author's events before it.
        reach(*own.author(), own.seq().saturating_sub(1));
    }
    for member in &past {
        if let Some(event) = log.event(*member).or_else(|| log.witnessed(*member)) {
            reach(*event.author(), event.seq());
        } else if let Some(stub) = log.stub(*member) {
            reach(stub.author, stub.seq);
        }
    }
    let implied: Vec<EventId> = log
        .stubs()
        .filter(|stub| {
            reached
                .get(&stub.author)
                .is_some_and(|seq| *seq >= stub.seq)
        })
        .map(|stub| stub.id)
        .collect();
    past.extend(implied);
    Some(past)
}

/// admission.md, "Accepting a grant", in order.
pub(crate) async fn accept_grant(
    device: &Engine,
    welcome: &Welcome,
    host: &ResponseBody,
) -> Result<()> {
    let space = EventId(welcome.space);
    let me = device.device_id();
    let offer = Offer::read(&host.offer, JoinerType::Device).map_err(Error::class)?;
    let (event, past) = device
        .read(&space, |replica| {
            let event = replica.event(welcome.event).cloned();
            let past = replica
                .log()
                .and_then(|log| past_with_stubs(log, welcome.event));
            (event, past)
        })
        .await?;
    let event = event.ok_or(Error::Class("Pending"))?;
    let past = past.ok_or(Error::Class("Pending"))?;
    let opened =
        open_admitting_event(&event, welcome, &me, device.xwing_seed()).map_err(Error::class)?;
    check_grant(
        &event,
        &opened,
        &past,
        &Authenticated {
            approver: &host.approver,
            log: &host.log,
            heads: &host.heads,
            offer: &offer,
        },
        &ExpectedJoiner::Device(me),
        Via::Code,
    )
    .map_err(Error::class)?;
    // 7. Its own resolution of the space finds the event valid.
    match device
        .read(&space, |r| r.status(&welcome.event).copied())
        .await?
    {
        Some(Status::Valid(_)) => {
            // The welcome's peer hints, for when a peer answers `moved`
            // (admission.md, "The welcome").
            let _ = device.keep_peer_hints(&space, &welcome.peers).await;
            Ok(())
        }
        Some(Status::Void { class, .. }) => Err(Error::Class(class.name())),
        None => Err(Error::Class("Pending")),
    }
}

/// Keeps the space a welcome admits this device to in memory only when the
/// offer, as the host's Response carries it, says its grant carries
/// `frasil.nothing-at-rest`: before the snapshot is adopted or any event
/// placed, so that nothing of it reaches the store (ext-guests.md,
/// "Nothing at rest"). The roster, once resolved, can only add to this:
/// a space kept in memory only stays so.
///
/// # Errors
///
/// The offer's class; the store's.
pub(crate) async fn keep_as_offered(device: &Engine, space: EventId, offer: &[u8]) -> Result<()> {
    let offer = Offer::read(offer, JoinerType::Device).map_err(Error::class)?;
    #[cfg(feature = "ext-guests")]
    if keeps_nothing_at_rest(&offer) {
        device.keep_in_memory(&space).await?;
    }
    #[cfg(not(feature = "ext-guests"))]
    let _ = (device, space, offer);
    Ok(())
}

/// Whether an offer's grant carries `frasil.nothing-at-rest`
/// (ext-guests.md, "Nothing at rest").
pub(crate) fn keeps_nothing_at_rest(offer: &frasil_admission::Offer) -> bool {
    #[cfg(feature = "ext-guests")]
    {
        offer.capabilities.as_ref().is_some_and(|capabilities| {
            capabilities.contains(&frasil_space::ext_guests::nothing_at_rest_capability())
        })
    }
    #[cfg(not(feature = "ext-guests"))]
    {
        let _ = offer;
        false
    }
}
