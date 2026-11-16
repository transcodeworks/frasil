//! Checkpoints (roster.md, 3.15 Checkpoints; identity.md, 3.16 List
//! checkpoints), as JavaScript objects: a space's checkpoint status, its
//! late changes, a device list's checkpoint status, and the device's
//! checkpoint policy. Every ID crosses as hexadecimal text, every count as a
//! `number`.

use crate::convert::{Obj, array, field, unsigned_in};
use crate::error::invalid;
use frasil::{
    BackdatedCheckpoint, CheckpointId, CheckpointPolicy, CheckpointStatus, LateChange,
    LateChangeKind, ListCheckpointStatus, PendingCheckpoint, PendingListCheckpoint,
};
use wasm_bindgen::JsValue;

/// An ID as its text, or `null`.
fn id_or_null(id: Option<CheckpointId>) -> JsValue {
    id.map_or(JsValue::NULL, |id| JsValue::from(id.to_string()))
}

/// IDs as an array of their text.
fn ids<T: ToString>(ids: &[T]) -> JsValue {
    array(ids, |id| JsValue::from(id.to_string()))
}

/// A count as a `number`: every one this binding hands out is far below
/// 2^53.
fn count(value: u64) -> JsValue {
    JsValue::from_f64(value as f64)
}

fn pending_out(pending: &PendingCheckpoint) -> JsValue {
    Obj::new()
        .set("id", pending.id.to_string())
        .set("epoch", count(pending.epoch))
        .set("proposedBy", pending.proposed_by.to_string())
        .set("waitingFor", ids(&pending.waiting_for))
        .build()
}

fn backdated_out(backdated: &BackdatedCheckpoint) -> JsValue {
    Obj::new()
        .set("checkpoint", backdated.checkpoint.to_string())
        .set("proposedBy", backdated.proposed_by.to_string())
        .set("removal", backdated.removal.to_string())
        .build()
}

/// A space's checkpoints, as `Space.checkpoints` resolves to them.
pub(crate) fn status_out(status: &CheckpointStatus) -> JsValue {
    Obj::new()
        .set("inEffect", id_or_null(status.in_effect))
        .set("epoch", count(status.epoch))
        .set("pending", array(&status.pending, pending_out))
        .set("following", id_or_null(status.following))
        .set("bad", ids(&status.bad))
        .set("late", ids(&status.late))
        .set("mixed", ids(&status.mixed))
        .set("rosterEventsSince", count(status.roster_events_since))
        .set("frameBytesSince", count(status.frame_bytes_since))
        .set("forgot", status.forgot)
        .set("refused", ids(&status.refused))
        .set("checking", ids(&status.checking))
        .set("withheld", ids(&status.withheld))
        .set("rivals", ids(&status.rivals))
        .set("backdated", array(&status.backdated, backdated_out))
        .build()
}

fn late_kind(kind: LateChangeKind) -> &'static str {
    match kind {
        LateChangeKind::Grant => "grant",
        LateChangeKind::Change => "change",
        LateChangeKind::Remove => "remove",
        _ => "other",
    }
}

/// A late membership change: `{ event, member, kind, level }`, `member`
/// and `level` `null` when the change names none.
pub(crate) fn late_change_out(change: &LateChange) -> JsValue {
    Obj::new()
        .set("event", change.event.to_string())
        .set(
            "member",
            change
                .member
                .map_or(JsValue::NULL, |member| JsValue::from(member.to_string())),
        )
        .set("kind", late_kind(change.kind))
        .set(
            "level",
            change
                .level
                .map_or(JsValue::NULL, |level| JsValue::from_str(level.name())),
        )
        .build()
}

/// Late membership changes, as an array.
pub(crate) fn late_changes_out(changes: &[LateChange]) -> JsValue {
    array(changes, late_change_out)
}

fn pending_list_out(pending: &PendingListCheckpoint) -> JsValue {
    Obj::new()
        .set("id", pending.id.to_string())
        .set("waitingFor", ids(&pending.waiting_for))
        .build()
}

/// A device list's checkpoints, as `Device.listCheckpoints` resolves to
/// them.
pub(crate) fn list_status_out(status: &ListCheckpointStatus) -> JsValue {
    Obj::new()
        .set("inEffect", id_or_null(status.in_effect))
        .set("pending", array(&status.pending, pending_list_out))
        .set("forgot", status.forgot)
        .set("rivals", ids(&status.rivals))
        .build()
}

/// The device's checkpoint policy: `{ propose, forget, rosterEvents,
/// frameBytes }`.
pub(crate) fn policy_out(policy: &CheckpointPolicy) -> JsValue {
    Obj::new()
        .set("propose", policy.propose)
        .set("forget", policy.forget)
        .set("rosterEvents", count(policy.roster_events))
        .set("frameBytes", count(policy.frame_bytes))
        .build()
}

/// A checkpoint policy from `{ propose, forget, rosterEvents, frameBytes }`:
/// each field left out takes the default's value; a threshold of 0 counts
/// as 1.
pub(crate) fn policy_in(value: &JsValue) -> Result<CheckpointPolicy, JsValue> {
    if !value.is_object() {
        return Err(invalid(
            "the checkpoint policy is an object: { propose, forget, rosterEvents, frameBytes }.",
        ));
    }
    let defaults = CheckpointPolicy::default();
    let flag = |key: &str, default: bool| -> Result<bool, JsValue> {
        let item = field(value, key)?;
        if item.is_undefined() {
            return Ok(default);
        }
        item.as_bool()
            .ok_or_else(|| invalid(&format!("the checkpoint policy's {key} is a boolean.")))
    };
    let threshold = |key: &str, default: u64| -> Result<u64, JsValue> {
        let item = field(value, key)?;
        if item.is_undefined() {
            return Ok(default);
        }
        unsigned_in(&item).ok_or_else(|| {
            invalid(&format!(
                "the checkpoint policy's {key} is a non-negative integer."
            ))
        })
    };
    Ok(CheckpointPolicy::default()
        .proposing(flag("propose", defaults.propose)?)
        .forgetting(flag("forget", defaults.forget)?)
        .proposing_at(
            threshold("rosterEvents", defaults.roster_events)?,
            threshold("frameBytes", defaults.frame_bytes)?,
        ))
}
