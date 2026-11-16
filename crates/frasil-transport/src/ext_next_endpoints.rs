//! Announced next endpoints (ext-next-endpoints.md, feature
//! `ext-next-endpoints`): the `NextEndpoint` message, which tells a member
//! the member endpoint key the sender takes at its next rotation, its
//! receiver's steps, and the announced ticket a device dials when it
//! reconnects.
//!
//! ```text
//! NextEndpoint = {0: 96, 1: attach, 2: next endpoint key (32)}
//! ```
//!
//! Type 96 is in the ignorable range: a receiver that does not implement
//! the extension drops it (transport.md, section 2.4), and with it
//! [`crate::frame::Extensions::next_endpoints`] reads it.

use crate::TransportClass;
use crate::frame::{ConnectionKind, Message, MessageType};
use crate::messages::{array, encode, exactly, malformed, uint};
use crate::ticket::Ticket;
use frasil_base::cbor::Value;
use frasil_crypto::keys::ed25519_valid;

/// `NextEndpoint`: the sender's next member endpoint key, on an attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextEndpoint {
    /// The attach.
    pub attach: u64,
    /// The member endpoint key the sender takes at its next rotation.
    pub key: [u8; 32],
}

impl NextEndpoint {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::NextEndpoint,
            [
                (1, Value::Unsigned(self.attach)),
                (2, Value::from(self.key)),
            ],
        )
    }

    /// Reads a `NextEndpoint`, the receiver's steps 1 and 2 (section 3.3).
    ///
    /// # Errors
    ///
    /// `Malformed` off a member connection, for other keys than 0 to 2, an
    /// attach that is not unsigned or a key that is not 32 bytes;
    /// `InvalidKey` for a key crypto.md refuses.
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        // 1. On a member connection; exactly keys 0 to 2; an unsigned
        //    attach; a 32-byte key.
        if connection != ConnectionKind::Member {
            return Err(malformed());
        }
        exactly(message, MessageType::NextEndpoint, &[0, 1, 2])?;
        let attach = uint(&message.map, 1)?;
        let key: [u8; 32] = array(&message.map, 2)?;
        // 2. An endpoint key crypto.md accepts.
        ed25519_valid(&key)?;
        Ok(Self { attach, key })
    }
}

/// What a receiver does with a `NextEndpoint` that reads (section 3.3,
/// steps 3 to 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Dropped at step 3 or 4.
    Dropped(u8),
    /// Kept as the sender's announced key in the attach's space.
    Kept,
}

/// Steps 3 to 5: `admitted` when both sides have sent `Admit` for the
/// attach; `sender_endpoint` the sender's member endpoint key on this
/// connection.
pub fn judge(message: &NextEndpoint, admitted: bool, sender_endpoint: &[u8; 32]) -> Outcome {
    if !admitted {
        return Outcome::Dropped(3);
    }
    if message.key == *sender_endpoint {
        return Outcome::Dropped(4);
    }
    Outcome::Kept
}

/// The announced ticket (section 3.4): the kept ticket under the announced
/// key, with the same relay URLs and direct addresses. `None` when the key
/// is the ticket's own, and the kept ticket alone is dialed.
pub fn announced_ticket(kept: &Ticket, announced: &[u8; 32]) -> Option<Ticket> {
    (kept.endpoint != *announced).then(|| Ticket {
        endpoint: *announced,
        ..kept.clone()
    })
}
