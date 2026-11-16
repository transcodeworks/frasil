//! A space's ephemeral channel at the root (ext-ephemeral.md): messages
//! that are never stored, such as cursors and presence, to the members
//! connected now, directly or through a peer.

use super::{MemberId, Space};
use crate::device::Engine;
use crate::ephemeral::EphemeralReceived;
use crate::error::Result;
use frasil_events::EventId;
use tokio::sync::broadcast::{self, error::RecvError};

/// The name the root API's messages carry.
const NAME: &str = "app";

/// A space's ephemeral channel.
#[derive(Clone)]
pub struct Ephemeral {
    engine: Engine,
    space: EventId,
}

impl core::fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ephemeral")
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl Space {
    /// The space's ephemeral channel: messages to the members connected
    /// now, over member connections and through peers, sealed to the
    /// space and never stored.
    pub fn ephemeral(&self) -> Ephemeral {
        Ephemeral {
            engine: self.device.engine().clone(),
            space: self.id().event(),
        }
    }
}

impl Ephemeral {
    /// Sends a message to every member connected in the space. It may be
    /// lost; nothing is answered.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`](crate::Error::NotAllowed) while the device
    /// holds no current state of the space; `TooLarge` past the frame's
    /// limits.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.engine
            .send_ephemeral(self.space, NAME, None, data, false)
            .await
    }

    /// The messages other members send in the space, from the first
    /// [`EphemeralStream::next`] on.
    pub fn subscribe(&self) -> EphemeralStream {
        EphemeralStream {
            engine: self.engine.clone(),
            space: self.space,
            receiver: None,
        }
    }
}

/// The messages members send in a space, each with its sender's device.
pub struct EphemeralStream {
    engine: Engine,
    space: EventId,
    receiver: Option<broadcast::Receiver<EphemeralReceived>>,
}

impl core::fmt::Debug for EphemeralStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralStream")
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl EphemeralStream {
    /// The next message and the device that sent it; `None` once the
    /// device is gone. A reader that falls behind skips what it missed.
    pub async fn next(&mut self) -> Option<(MemberId, Vec<u8>)> {
        if self.receiver.is_none() {
            self.receiver = Some(self.engine.subscribe_ephemeral().await.ok()?);
        }
        let receiver = self.receiver.as_mut()?;
        loop {
            match receiver.recv().await {
                Ok(frame) if frame.space == self.space && frame.name == NAME && !frame.slot => {
                    return Some((MemberId::device(frame.sender), frame.data));
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            }
        }
    }
}
