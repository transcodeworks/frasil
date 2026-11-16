//! Member addresses (transport.md, "The iroh binding", member addresses):
//! the members of a space tell each other, on an attach both ends
//! admitted, the member tickets of the space's other members, so that a
//! device without local-network packets still reaches every member.
//!
//! ```text
//! Addresses = {0: 8, 1: attach, 2: [[device ID (32), ticket], ...]}
//! ```
//!
//! [`Addresses::read`] runs the receiver's steps 1 and 2, and [`judge`]
//! steps 4 to 7 for one entry. Step 3, whether both sides have sent `Admit`
//! for the attach, is the caller's. [`for_guest`] narrows a ticket the
//! sender lists to a guest.

use crate::TransportClass;
use crate::frame::{Message, MessageType};
use crate::messages::{encode, exactly, field, malformed, uint};
use crate::ticket::{Address, Ticket, TicketKind};
use frasil_base::cbor::Value;
use frasil_crypto::device::DeviceId;

/// The most entries an `Addresses` lists.
pub const MAX_ENTRIES: usize = 64;
/// The most learned tickets a receiver holds, as for local-network
/// candidates.
pub const LEARNED_TICKETS: usize = 128;
/// How long a receiver holds a learned ticket, in seconds, and so how
/// often at most it dials one endpoint key it learned.
pub const LEARNED_SECONDS: u64 = 10;
/// How long the member with the greater endpoint key waits before it dials
/// a member that learned of it at once, in seconds.
pub const CROSS_DIAL_WAIT_SECONDS: u64 = 1;

/// `Addresses`: member tickets of members of the attach's space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    /// The attach.
    pub attach: u64,
    /// Each member's device ID and member ticket, in the sender's order.
    pub entries: Vec<(DeviceId, Ticket)>,
}

/// The CBOR of one entry.
fn entry(device: &DeviceId, ticket: &Ticket) -> Value {
    Value::Array(vec![Value::from(device.0), Value::from(ticket.cbor())])
}

impl Addresses {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Addresses,
            [
                (1, Value::Unsigned(self.attach)),
                (
                    2,
                    Value::Array(self.entries.iter().map(|(k, t)| entry(k, t)).collect()),
                ),
            ],
        )
    }

    /// The `Addresses` a sender sends for an attach: `listed` in its order,
    /// each device ID once, at most [`MAX_ENTRIES`], stopping before the
    /// message would pass its cap. `None` when nothing is listed, since a
    /// sender never sends an empty list.
    pub fn fitting(
        attach: u64,
        listed: impl IntoIterator<Item = (DeviceId, Ticket)>,
    ) -> Option<Self> {
        let mut out = Self {
            attach,
            entries: Vec::new(),
        };
        // The map's head, keys 0 to 2, the type and the attach; then key 2's
        // array head, of 1 byte below 24 entries and 2 up to 64.
        let head = 1 + 1 + 1 + 1 + Value::Unsigned(attach).encode().len() + 1;
        let mut size = 0;
        for (identity, ticket) in listed {
            if out.entries.len() == MAX_ENTRIES {
                break;
            }
            if ticket.kind != TicketKind::Member || out.entries.iter().any(|(k, _)| *k == identity)
            {
                continue;
            }
            let more = entry(&identity, &ticket).encode().len();
            let array_head = if out.entries.len() < 23 { 1 } else { 2 };
            if head + array_head + size + more > MessageType::Addresses.cap() {
                break;
            }
            size += more;
            out.entries.push((identity, ticket));
        }
        (!out.entries.is_empty()).then_some(out)
    }

    /// Reads an `Addresses`, the receiver's steps 1 and 2.
    ///
    /// # Errors
    ///
    /// `Malformed` for other keys than 0 to 2, an attach that is not
    /// unsigned, more than 64 entries, an entry that is not a 32-byte
    /// device ID and a byte string, a device ID twice, or a ticket
    /// that does not read or is not a member ticket; `InvalidKey` for a
    /// ticket's endpoint key that crypto.md refuses.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        // 1. Exactly keys 0 to 2, an unsigned attach, at most 64 entries of
        //    a 32-byte device ID and a byte string, no device ID twice.
        exactly(message, MessageType::Addresses, &[0, 1, 2])?;
        let attach = uint(&message.map, 1)?;
        let items = field(&message.map, 2)?.as_array()?;
        if items.len() > MAX_ENTRIES {
            return Err(malformed());
        }
        let mut raw: Vec<(DeviceId, &[u8])> = Vec::with_capacity(items.len());
        for item in items {
            let [identity, ticket] = item.as_array()? else {
                return Err(malformed());
            };
            let identity = DeviceId(identity.as_byte_array()?);
            if raw.iter().any(|(k, _)| *k == identity) {
                return Err(malformed());
            }
            raw.push((identity, ticket.as_bytes()?));
        }
        // 2. Each byte string reads as a member ticket.
        let mut entries = Vec::with_capacity(raw.len());
        for (identity, bytes) in raw {
            let ticket = Ticket::read_cbor(bytes)?;
            if ticket.kind != TicketKind::Member {
                return Err(malformed());
            }
            entries.push((identity, ticket));
        }
        Ok(Self { attach, entries })
    }
}

/// Whether a direct address is a local-network address: IPv4 in
/// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` or
/// `127.0.0.0/8`; IPv6 in `fc00::/7`, `fe80::/10` or `::1/128`. An
/// IPv4-mapped IPv6 address is in none of them.
pub fn local_network(address: &Address) -> bool {
    match address {
        Address::V4(ip, _) => matches!(
            ip,
            [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [169, 254, ..] | [127, ..]
        ),
        Address::V6(ip, _) => {
            ip[0] & 0xfe == 0xfc
                || (ip[0] == 0xfe && ip[1] & 0xc0 == 0x80)
                || u128::from_be_bytes(*ip) == 1
        }
    }
}

/// A ticket as a sender lists it to a guest ("Sending to a guest"): its
/// local-network addresses alone, in order, and no relay URLs. `None` when
/// no address is left, and the entry is left out.
pub fn for_guest(ticket: &Ticket) -> Option<Ticket> {
    let addresses: Vec<Address> = ticket
        .addresses
        .iter()
        .copied()
        .filter(local_network)
        .collect();
    (!addresses.is_empty()).then(|| Ticket {
        kind: ticket.kind,
        endpoint: ticket.endpoint,
        relays: Vec::new(),
        addresses,
    })
}

/// The receiver of an `Addresses`, for [`judge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receiver {
    /// The receiver's device ID.
    pub device: DeviceId,
    /// The sender's device ID, attach 0's.
    pub sender: DeviceId,
    /// The receiver's own member endpoint key.
    pub endpoint: [u8; 32],
}

/// What the receiver knows of one listed member. Whether it keeps a ticket
/// of the member plays no part: a learned ticket is never written to the
/// `endpoint` table ("Keeping").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {
    /// The member reaches the space in the receiver's current view.
    pub reaches: bool,
    /// The receiver holds an admitted attach of the space with the member.
    pub attached: bool,
}

/// What a receiver does with one entry: steps 4 to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Skipped at this step, 4, 5 or 6.
    Skipped(u8),
    /// Step 7: it holds the ticket among its learned tickets and dials it.
    Dial,
}

/// Steps 4 to 7 for one entry of an `Addresses`.
pub fn judge(receiver: &Receiver, member: &DeviceId, ticket: &Ticket, known: Known) -> Outcome {
    // 4. Neither end, and a device that reaches the space.
    if *member == receiver.device || *member == receiver.sender || !known.reaches {
        return Outcome::Skipped(4);
    }
    // 5. Not the receiver's own endpoint.
    if ticket.endpoint == receiver.endpoint {
        return Outcome::Skipped(5);
    }
    // 6. No admitted attach with the member already.
    if known.attached {
        return Outcome::Skipped(6);
    }
    // 7.
    Outcome::Dial
}
