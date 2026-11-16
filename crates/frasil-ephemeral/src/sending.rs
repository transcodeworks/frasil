//! Sending (ext-ephemeral.md, "Sending").
//!
//! - A sender keeps at most 32 live ephemeral slots per space. Empty data
//!   clears one. `frasil/leave`, broadcast when the sender closes the space,
//!   clears all of them. When its content state changes, it publishes each
//!   live ephemeral slot again under the new state ([`LiveSlots`]).
//! - **Queues.** Ephemeral frames queue apart and go first, at most 64 per
//!   connection. A new value of an ephemeral slot replaces its unsent value;
//!   when the queue is full, the oldest ephemeral message is dropped, or,
//!   with no ephemeral message queued, the oldest ephemeral slot value; a
//!   frame not sent within `ephemeral_send_deadline` (2 seconds, monotonic)
//!   is dropped ([`SendQueue`]).

use crate::EphemeralClass;
use crate::frame::Outer;
use crate::inner::Kind;
use crate::limits::{EPHEMERAL_SEND_DEADLINE, HANDLE_BYTES, LIVE_SLOTS_PER_SENDER, SEND_QUEUE};
use frasil_base::ErrorClass;
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

/// A sender's live ephemeral slots in one space, by name and stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveSlots {
    live: BTreeMap<(String, Option<[u8; 16]>), Vec<u8>>,
}

impl LiveSlots {
    /// None.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a value the sender sends; empty data clears the slot.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a new live slot past 32.
    pub fn set(
        &mut self,
        name: &str,
        stream: Option<[u8; 16]>,
        data: &[u8],
    ) -> Result<(), EphemeralClass> {
        let key = (name.to_owned(), stream);
        if data.is_empty() {
            self.live.remove(&key);
            return Ok(());
        }
        if !self.live.contains_key(&key) && self.live.len() >= LIVE_SLOTS_PER_SENDER {
            return Err(ErrorClass::TooLarge.into());
        }
        self.live.insert(key, data.to_vec());
        Ok(())
    }

    /// `frasil/leave`: clears every live slot.
    pub fn leave(&mut self) {
        self.live.clear();
    }

    /// The live slots, to publish again under a new state, or to a member
    /// connection once both sides have sent `Admit`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&[u8; 16]>, &[u8])> {
        self.live
            .iter()
            .map(|((name, stream), data)| (name.as_str(), stream.as_ref(), data.as_slice()))
    }

    /// How many slots are live.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether none is live.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// A frame waiting in a sender's queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    /// The frame's kind.
    pub kind: Kind,
    /// Its handle, for an ephemeral slot.
    pub handle: Option<[u8; HANDLE_BYTES]>,
    /// The outer frame.
    pub outer: Vec<u8>,
    /// When it was queued, on the monotonic clock.
    pub queued: Duration,
}

/// A sender's queue of ephemeral frames for one connection. Instants are
/// readings of the monotonic clock the caller passes in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendQueue {
    frames: VecDeque<Queued>,
}

impl SendQueue {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// The frames waiting, oldest first.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether none waits.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Queues a frame at `now`. A new value of an ephemeral slot replaces
    /// its unsent value, in its place. When the queue is full, the oldest
    /// ephemeral message is dropped; with none, the oldest frame. Returns
    /// the frame dropped, if any.
    pub fn push(&mut self, frame: &Outer, outer: Vec<u8>, now: Duration) -> Option<Queued> {
        let queued = Queued {
            kind: frame.kind,
            handle: frame.handle,
            outer,
            queued: now,
        };
        if let Some(handle) = frame.handle
            && let Some(unsent) = self.frames.iter_mut().find(|q| q.handle == Some(handle))
        {
            return Some(std::mem::replace(unsent, queued));
        }
        let dropped = if self.frames.len() >= SEND_QUEUE {
            let oldest = self
                .frames
                .iter()
                .position(|q| q.kind == Kind::Message)
                .unwrap_or(0);
            self.frames.remove(oldest)
        } else {
            None
        };
        self.frames.push_back(queued);
        dropped
    }

    /// The next frame to send at `now`. Frames queued more than
    /// `ephemeral_send_deadline` ago are dropped first.
    pub fn pop(&mut self, now: Duration) -> Option<Queued> {
        let deadline = Duration::from_secs(EPHEMERAL_SEND_DEADLINE);
        self.frames
            .retain(|q| now.saturating_sub(q.queued) <= deadline);
        self.frames.pop_front()
    }
}
