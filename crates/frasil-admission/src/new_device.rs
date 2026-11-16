//! A person's new device, and a person that joins a space (admission.md,
//! "A person's new device", "A person that joins a space").
//!
//! For ctx `0x01`, after the comparison, the approver signs an `add` of a
//! device naming the joiner's device ID and three public keys with its
//! possession proof
//! ([`add_body`]), and sends the Result: every event of the list it holds,
//! the new `add` included. The new device checks it, in order
//! ([`check_list_result`]):
//!
//! ```text
//! 1. The Result reads.                                                  else Malformed
//! 2. Exactly one event is the list's first, and its ID is the log.      else WrongPerson
//! 3. The events place.                                                  else Malformed
//! 4. Exactly one add names J's device ID.                               else WrongMember
//! 5. Its author is the approver.                                        else WrongApprover
//! 6. Every head of the Response is in its past.                         else NotFollowing
//! 7. The merged list holds it valid.                                    else NotInList
//! ```
//!
//! An `add` that names J's device ID with other keys fails identity.md's
//! check alone (`NotCommitted`), so step 7 refuses it.
//!
//! A person joiner's List, after its own person's confirmation, is checked
//! by the approver, in order ([`check_list`]):
//!
//! ```text
//! 1. The List reads.                                                    else Malformed
//! 2. The first event's ID is the person ID, and every event passes
//!    identity.md's checks.                                              else BadList
//! 3. The heads of the events received equal the committed list heads.  else ListMismatch
//! 4. The merged list holds at least one active device or passkey
//!    member.                                                            else BadList
//! ```

use crate::bodies::{ListEvents, RevealBody};
use crate::{AdmissionClass, malformed, sorted_heads};
use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_events::{Event, EventId, Log, Placement, decode};
use frasil_identity::body::{Action, ListBody};
use frasil_identity::{DeviceList, Kind, MergedList, PublicKeys};

/// The `add` an approver signs for a person's new device after a matched
/// code: a device naming the device ID of the revealed keys and the keys,
/// with the possession proof over the person ID that the Reveal carried.
///
/// # Errors
///
/// `Malformed` for a person's Reveal, which never comes in ctx `0x01`, or
/// a device's without its possession proof.
pub fn add_body(reveal: &RevealBody) -> Result<ListBody, AdmissionClass> {
    let RevealBody::Device {
        keys, possession, ..
    } = reveal
    else {
        return Err(malformed());
    };
    Ok(ListBody::add(
        Kind::Device,
        &PublicKeys {
            identity: IdentityKey(keys.identity),
            xwing: Some(keys.xwing.clone()),
            mldsa: keys.mldsa.clone(),
        },
        possession.clone().ok_or_else(malformed)?,
    ))
}

/// The checks of a ctx `0x01` Result at the new device, in order. `log`,
/// `approver` and `heads` are the accepted Response's, and `device` the
/// new device's own device ID. Returns the `add`'s event ID and the merged
/// list.
///
/// # Errors
///
/// `Malformed`, `WrongPerson`, `Malformed`, `WrongMember`, `WrongApprover`,
/// `NotFollowing`, `NotInList`.
pub fn check_list_result(
    plaintext: &[u8],
    log: &[u8; 32],
    approver: &DeviceId,
    heads: &[EventId],
    device: &DeviceId,
) -> Result<(EventId, MergedList), AdmissionClass> {
    // 1.
    let body = ListEvents::read(plaintext)?;
    let events = body
        .events
        .iter()
        .map(|signed| decode(signed).map_err(|_| malformed()))
        .collect::<Result<Vec<Event>, AdmissionClass>>()?;
    // 2.
    let firsts: Vec<&Event> = events.iter().filter(|e| e.is_genesis()).collect();
    let [first] = firsts[..] else {
        return Err(AdmissionClass::WrongPerson);
    };
    if first.kind() != frasil_events::kind::DEVICE_LIST || first.id().0 != *log {
        return Err(AdmissionClass::WrongPerson);
    }
    // 3.
    let rest: Vec<&Event> = events.iter().filter(|e| !e.is_genesis()).collect();
    let placed = place(first, &rest)?;
    // 4. The add's body, read as the list's checks of an event alone read
    // it; step 7 counts it only if the merge holds it valid, its signature
    // verified among the rest.
    let adds: Vec<(&Event, ListBody)> = rest
        .iter()
        .filter_map(|e| {
            ListBody::decode(e.unverified_body())
                .ok()
                .filter(|b| b.action == Action::Add && b.device == *device)
                .map(|b| (*e, b))
        })
        .collect();
    let [(add, body)] = &adds[..] else {
        return Err(AdmissionClass::WrongMember);
    };
    if body.kind != Kind::Device {
        return Err(AdmissionClass::WrongMember);
    }
    // 5.
    if add.author() != approver {
        return Err(AdmissionClass::WrongApprover);
    }
    // 6.
    let past = placed.past(add.id());
    if !heads.iter().all(|head| past.contains(head)) {
        return Err(AdmissionClass::NotFollowing);
    }
    // 7. An add whose keys do not give its device ID is NotCommitted by
    //    identity.md's check alone, and so not valid here.
    let mut list = DeviceList::from_first(first.clone()).map_err(|_| AdmissionClass::NotInList)?;
    for event in &rest {
        list.insert_event((*event).clone())
            .map_err(|_| AdmissionClass::NotInList)?;
    }
    let merged = list.merge();
    if !merged.is_valid(add.id()) {
        return Err(AdmissionClass::NotInList);
    }
    Ok((add.id(), merged))
}

/// Places every event after the first, in any order: each of the first's
/// log, and every one placed in the end.
fn place(first: &Event, rest: &[&Event]) -> Result<Log, AdmissionClass> {
    let mut log = Log::new(first.clone()).map_err(|_| malformed())?;
    for event in rest {
        match log.place((*event).clone()) {
            Ok(Placement::Placed(_) | Placement::Pending(_)) => {}
            Ok(Placement::Known) | Err(_) => return Err(malformed()),
        }
    }
    if log.pending().next().is_some() {
        return Err(malformed());
    }
    Ok(log)
}

/// The approver's checks of a person joiner's List, or of a Join's list
/// (section 3.9, which runs steps 1, 2 and 4 with no committed heads).
/// Returns the list.
///
/// # Errors
///
/// `Malformed`, `BadList`, `ListMismatch`, `BadList`.
pub fn check_list(
    plaintext: &[u8],
    person: &[u8; 32],
    committed_heads: Option<&[EventId]>,
) -> Result<DeviceList, AdmissionClass> {
    // 1.
    let body = ListEvents::read(plaintext)?;
    check_list_events(&body.events, person, committed_heads)
}

/// [`check_list`] from step 2, on events already read.
///
/// # Errors
///
/// `BadList`, `ListMismatch`, `BadList`.
pub fn check_list_events(
    events: &[Vec<u8>],
    person: &[u8; 32],
    committed_heads: Option<&[EventId]>,
) -> Result<DeviceList, AdmissionClass> {
    // 2.
    let decoded = events
        .iter()
        .map(|signed| decode(signed).map_err(|_| AdmissionClass::BadList))
        .collect::<Result<Vec<Event>, AdmissionClass>>()?;
    let first = decoded
        .iter()
        .find(|e| e.id().0 == *person)
        .ok_or(AdmissionClass::BadList)?;
    let mut list = DeviceList::from_first(first.clone()).map_err(|_| AdmissionClass::BadList)?;
    for event in decoded.iter().filter(|e| e.id().0 != *person) {
        match list.insert_event(event.clone()) {
            Ok(Placement::Placed(_) | Placement::Pending(_)) => {}
            Ok(Placement::Known) | Err(_) => return Err(AdmissionClass::BadList),
        }
    }
    if list.log().pending().next().is_some() {
        return Err(AdmissionClass::BadList);
    }
    if list
        .log()
        .canonical()
        .into_iter()
        .any(|id| list.check_alone(id).is_some())
    {
        return Err(AdmissionClass::BadList);
    }
    // 3.
    if let Some(committed) = committed_heads
        && sorted_heads(&list.log().heads()) != sorted_heads(committed)
    {
        return Err(AdmissionClass::ListMismatch);
    }
    // 4.
    let merged = list.merge();
    let holds = merged
        .active_members()
        .any(|member| matches!(member.kind, Kind::Device | Kind::PasskeyMember));
    if !holds {
        return Err(AdmissionClass::BadList);
    }
    Ok(list)
}
