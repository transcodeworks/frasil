//! The invite drop's messages (ext-invite-links.md, "The drop and its
//! messages", feature `ext-invite-links`).
//!
//! ```text
//! address       = SHA-256("frasil/mailbox/v1" || u8(4) || field(locator))
//! MailboxPut, kind 4 = {0: 24, 1: request, 2: address (32), 3: drop,
//!                       4: space ID (32), 5: lifetime (seconds, 1 to 604,800), 6: 4}
//! MailboxDelete      = {0: 28, 1: request, 2: address (32), 3: space ID (32), 6: 4}
//! ```
//!
//! `MailboxDelete` travels on the control stream; both messages are
//! answered by `Accepted` or `Refused`. `MailboxGet` of kind 4 has no keys
//! 4 and 5 ([`crate::mailbox::MailboxGet`]), and `MailboxItems` carries the
//! drop as its one item. A peer's checks of the two messages, beyond their
//! shape, are `frasil-peers`' (`DropStore`).
//!
//! On the server binding, `GET /frasil/p1/mailbox/4/{address}` serves a drop
//! to anyone, and a `POST` to kind 4 is 403 `credential_refused`: a drop is
//! placed and deleted only over the WebSocket.

use crate::frame::{Extensions, Message, MessageType};
use crate::mailbox::{Kind, address};
use crate::messages::{self, malformed, of_type, uint};
use crate::{TransportClass, exact_keys};
use frasil_base::ErrorClass;
use frasil_base::cbor::Value;
use frasil_peers::ext_invite_links::PlacedDrop;

pub use frasil_peers::ext_invite_links::{DROP_LIFETIME_MAX, DROP_MAX_BYTES};

/// The fewest bytes of a drop: its nonce and the AEAD's tag.
pub const DROP_MIN_BYTES: usize = 40;

/// What the server binding answers a `POST` to mailbox kind 4 with: a drop
/// is placed only over the WebSocket.
pub const POST_REFUSED: (&str, u16) = ("credential_refused", 403);

/// A receiver's extensions with this one: it knows message type 28,
/// `MailboxDelete`, and reads mailbox kind 4 itself.
pub const fn with_invite_links(extensions: Extensions) -> Extensions {
    Extensions {
        invite_links: true,
        ..extensions
    }
}

/// A drop's address: `SHA-256("frasil/mailbox/v1" || u8(4) ||
/// field(locator))`.
pub fn drop_address(locator: &[u8; 32]) -> [u8; 32] {
    address(Kind::Drop, locator)
}

/// `MailboxPut` of kind 4: a drop placed at a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropPut {
    /// Key 1.
    pub request: u64,
    /// Key 2: the drop's address.
    pub address: [u8; 32],
    /// Key 3: the drop.
    pub drop: Vec<u8>,
    /// Key 4: the space ID.
    pub space: [u8; 32],
    /// Key 5: the lifetime, in seconds, 1 to 604,800.
    pub lifetime: u64,
}

impl DropPut {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        messages::encode(
            MessageType::MailboxPut,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.address)),
                (3, Value::from(self.drop.as_slice())),
                (4, Value::from(self.space)),
                (5, Value::Unsigned(self.lifetime)),
                (6, Value::Unsigned(Kind::Drop.code().into())),
            ],
        )
    }

    /// A peer's steps 1 and 2 on a `MailboxPut` of kind 4: keys 0 to 6;
    /// keys 2 and 4 are 32 bytes and key 5 is 1 to 604,800 (`Malformed`);
    /// the drop is at most 65,536 bytes (`TooLarge`).
    ///
    /// # Errors
    ///
    /// `Malformed` or `TooLarge`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::MailboxPut)?;
        let map = &message.map;
        if !exact_keys(map, &[0, 1, 2, 3, 4, 5, 6]) || uint(map, 6)? != u64::from(Kind::Drop.code())
        {
            return Err(malformed());
        }
        let request = uint(map, 1)?;
        let drop = messages::bytes(map, 3)?;
        // 1.
        let address = messages::array(map, 2)?;
        let space = messages::array(map, 4)?;
        let lifetime = uint(map, 5)?;
        if !(1..=DROP_LIFETIME_MAX).contains(&lifetime) {
            return Err(malformed());
        }
        // 2.
        if drop.len() > DROP_MAX_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        Ok(Self {
            request,
            address,
            drop: drop.to_vec(),
            space,
            lifetime,
        })
    }

    /// What a peer's drop store places.
    pub fn placed(&self) -> PlacedDrop<'_> {
        PlacedDrop {
            address: self.address,
            space: self.space,
            drop: &self.drop,
            lifetime: self.lifetime,
        }
    }
}

/// `MailboxDelete`: the placer removes its drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxDelete {
    /// Key 1.
    pub request: u64,
    /// Key 2: the drop's address.
    pub address: [u8; 32],
    /// Key 3: the space ID.
    pub space: [u8; 32],
}

impl MailboxDelete {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        messages::encode(
            MessageType::MailboxDelete,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.address)),
                (3, Value::from(self.space)),
                (6, Value::Unsigned(Kind::Drop.code().into())),
            ],
        )
    }

    /// Reads a `MailboxDelete`: keys 0 to 3 and 6, a 32-byte address and
    /// space ID, kind 4.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::MailboxDelete)?;
        let map = &message.map;
        if !exact_keys(map, &[0, 1, 2, 3, 6]) || uint(map, 6)? != u64::from(Kind::Drop.code()) {
            return Err(malformed());
        }
        Ok(Self {
            request: uint(map, 1)?,
            address: messages::array(map, 2)?,
            space: messages::array(map, 3)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{ConnectionKind, StreamClass, read_message};

    fn control(payload: &[u8]) -> Message {
        let extensions = with_invite_links(Extensions::NONE);
        read_message(
            payload,
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            extensions,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn the_messages_round_trip() {
        let put = DropPut {
            request: 2,
            address: [1; 32],
            drop: vec![7; 40],
            space: [2; 32],
            lifetime: 86_400,
        };
        assert_eq!(DropPut::read(&control(&put.encode())), Ok(put));
        let delete = MailboxDelete {
            request: 3,
            address: [1; 32],
            space: [2; 32],
        };
        assert_eq!(MailboxDelete::read(&control(&delete.encode())), Ok(delete));
    }
}
