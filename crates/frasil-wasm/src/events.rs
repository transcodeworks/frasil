//! A device's events, as a JavaScript class.

use crate::convert::{Obj, array};
use crate::error::invalid;
use crate::promise;
use frasil::Event;
use js_sys::Promise;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A device's events, from the moment they were asked for.
#[wasm_bindgen]
pub struct Events {
    /// Lent to the one `next()` in flight, and given back when it settles.
    inner: Rc<RefCell<Option<frasil::Events>>>,
}

impl From<frasil::Events> for Events {
    fn from(inner: frasil::Events) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Some(inner))),
        }
    }
}

fn event_out(event: &Event) -> JsValue {
    match event {
        Event::Changed {
            space,
            streams,
            members,
        } => Obj::new()
            .set("kind", "changed")
            .set("space", space.to_string())
            .set(
                "streams",
                array(streams, |stream| JsValue::from(stream.to_string())),
            )
            .set("members", *members)
            .build(),
        Event::PendingChanges { space, count } => Obj::new()
            .set("kind", "pendingChanges")
            .set("space", space.to_string())
            .set("count", JsValue::from(*count))
            .build(),
        Event::Moved { space } => Obj::new()
            .set("kind", "moved")
            .set("space", space.to_string())
            .build(),
        Event::WriteReady { space } => Obj::new()
            .set("kind", "writeReady")
            .set("space", space.to_string())
            .build(),
        Event::Removed { space } => Obj::new()
            .set("kind", "removed")
            .set("space", space.to_string())
            .build(),
        Event::Delayed { peer, reason } => Obj::new()
            .set("kind", "delayed")
            .set("peer", peer.as_str())
            .set("reason", reason.as_str())
            .build(),
        Event::Delivered { peer } => Obj::new()
            .set("kind", "delivered")
            .set("peer", peer.as_str())
            .build(),
        Event::Undelivered { peer, reason } => Obj::new()
            .set("kind", "undelivered")
            .set("peer", peer.as_str())
            .set("reason", reason.as_str())
            .build(),
        Event::DepositPeerDistrusted { peer, reason } => Obj::new()
            .set("kind", "depositPeerDistrusted")
            .set("peer", peer.as_str())
            .set("reason", reason.as_str())
            .build(),
        Event::Withheld { space } => Obj::new()
            .set("kind", "withheld")
            .set("space", space.to_string())
            .build(),
        Event::RolledBack { space, member } => Obj::new()
            .set("kind", "rolledBack")
            .set("space", space.to_string())
            .set(
                "member",
                member.map_or(JsValue::NULL, |member| JsValue::from(member.to_string())),
            )
            .build(),
        Event::BadStatement { space, member } => Obj::new()
            .set("kind", "badStatement")
            .set("space", space.to_string())
            .set("member", member.to_string())
            .build(),
        Event::CheckpointPending {
            space,
            checkpoint,
            waiting_for,
        } => Obj::new()
            .set("kind", "checkpointPending")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .set(
                "waitingFor",
                array(waiting_for, |member| JsValue::from(member.to_string())),
            )
            .build(),
        Event::CheckpointInEffect { space, checkpoint } => Obj::new()
            .set("kind", "checkpointInEffect")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .build(),
        Event::BadCheckpoint { space, checkpoint } => Obj::new()
            .set("kind", "badCheckpoint")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .build(),
        Event::Late { space, changes } => Obj::new()
            .set("kind", "late")
            .set("space", space.to_string())
            .set("changes", crate::checkpoints::late_changes_out(changes))
            .build(),
        Event::MixedCut { space, event } => Obj::new()
            .set("kind", "mixedCut")
            .set("space", space.to_string())
            .set("event", event.to_string())
            .build(),
        Event::NeedsLaterVersion { space } => Obj::new()
            .set("kind", "needsLaterVersion")
            .set("space", space.to_string())
            .build(),
        Event::RequestSignedAgain { space, request } => Obj::new()
            .set("kind", "requestSignedAgain")
            .set("space", space.to_string())
            .set("request", request.to_string())
            .build(),
        Event::ErasedWhileLate { space, by } => Obj::new()
            .set("kind", "erasedWhileLate")
            .set("space", space.to_string())
            .set(
                "by",
                by.map_or(JsValue::NULL, |by| JsValue::from(by.to_string())),
            )
            .build(),
        Event::ErasureUnanswered { space, peers } => Obj::new()
            .set("kind", "erasureUnanswered")
            .set("space", space.to_string())
            .set("peers", array(peers, |peer| JsValue::from(peer.as_str())))
            .build(),
        Event::ErasureLateAtPeer { space, peer } => Obj::new()
            .set("kind", "erasureLateAtPeer")
            .set("space", space.to_string())
            .set("peer", peer.as_str())
            .build(),
        Event::PeerNeedsVersion { space, peer } => Obj::new()
            .set("kind", "peerNeedsVersion")
            .set("space", space.to_string())
            .set("peer", peer)
            .build(),
        Event::PeerError {
            space,
            peer,
            answer,
        } => Obj::new()
            .set("kind", "peerError")
            .set("space", space.to_string())
            .set("peer", peer.as_str())
            .set("answer", js_sys::Uint8Array::from(answer.as_slice()))
            .build(),
        Event::ErasureCheckpoint {
            space,
            peer,
            checkpoint,
            standing,
        } => Obj::new()
            .set("kind", "erasureCheckpoint")
            .set("space", space.to_string())
            .set("peer", peer.as_str())
            .set("checkpoint", checkpoint.to_string())
            .set("standing", u32::from(*standing))
            .build(),
        Event::ErasureAwaitingWelcome { space } => Obj::new()
            .set("kind", "erasureAwaitingWelcome")
            .set("space", space.to_string())
            .build(),
        Event::ErasureCannotErase { space, peer } => Obj::new()
            .set("kind", "erasureCannotErase")
            .set("space", space.to_string())
            .set("peer", peer.as_str())
            .build(),
        Event::SlotHeld {
            space,
            holding,
            holder,
            erasure_waiting,
            peer,
        } => Obj::new()
            .set("kind", "slotHeld")
            .set("space", space.to_string())
            .set("holding", holding.to_string())
            .set("holder", holder.as_str())
            .set("erasureWaiting", *erasure_waiting)
            .set(
                "peer",
                peer.as_deref().map(JsValue::from).unwrap_or(JsValue::NULL),
            )
            .build(),
        Event::ErasureVoid { space } => Obj::new()
            .set("kind", "erasureVoid")
            .set("space", space.to_string())
            .build(),
        Event::CheckpointRival { space, checkpoint } => Obj::new()
            .set("kind", "checkpointRival")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .build(),
        Event::CheckpointWithheld {
            space,
            checkpoint,
            proposed_by,
            theirs,
            ours,
        } => Obj::new()
            .set("kind", "checkpointWithheld")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .set("proposedBy", proposed_by.to_string())
            .set("theirs", array(theirs, |e| JsValue::from(e.to_string())))
            .set("ours", array(ours, |e| JsValue::from(e.to_string())))
            .build(),
        Event::RankAttemptRefused {
            space,
            event,
            author,
        } => Obj::new()
            .set("kind", "rankAttemptRefused")
            .set("space", space.to_string())
            .set("event", event.to_string())
            .set("author", author.to_string())
            .build(),
        Event::BackdatedCheckpoint {
            space,
            checkpoint,
            removal,
        } => Obj::new()
            .set("kind", "backdatedCheckpoint")
            .set("space", space.to_string())
            .set("checkpoint", checkpoint.to_string())
            .set("removal", removal.to_string())
            .build(),
        Event::ListCheckpointPending {
            checkpoint,
            waiting_for,
        } => Obj::new()
            .set("kind", "listCheckpointPending")
            .set("checkpoint", checkpoint.to_string())
            .set(
                "waitingFor",
                array(waiting_for, |member| JsValue::from(member.to_string())),
            )
            .build(),
        Event::ListCheckpointRival { checkpoint } => Obj::new()
            .set("kind", "listCheckpointRival")
            .set("checkpoint", checkpoint.to_string())
            .build(),
        _ => Obj::new().set("kind", "other").build(),
    }
}

#[wasm_bindgen]
impl Events {
    /// The next event; `undefined` once the device is gone. One call at a
    /// time: another while one waits is refused.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut events = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("Events.next is already waiting."))?;
        Ok(promise(async move {
            let event = events.next().await;
            if let Ok(mut held) = slot.try_borrow_mut() {
                *held = Some(events);
            }
            Ok(event.as_ref().map_or(JsValue::UNDEFINED, event_out))
        }))
    }
}
