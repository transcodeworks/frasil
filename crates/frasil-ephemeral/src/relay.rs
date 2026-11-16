//! Relaying (ext-ephemeral.md, "Relaying").
//!
//! An always-on peer relays a space's channel among the connections that
//! hold the `live` right for it. A connection joins the channel with its
//! first `Subscribe` (units.md) or `Ephemeral` for the space. The peer holds
//! no key and checks only steps 1 and 2 of "Receiving". It:
//!
//! 1. draws, per connection and space, an origin of 8 random bytes, never
//!    derived from the connection's credentials;
//! 2. forwards each frame a device sent it, with no origin, to every other
//!    connection on the channel, with the sender's origin at key 3 of
//!    `Ephemeral`; it drops an `Ephemeral` that carries an origin, and
//!    relays to no other peer, so a frame crosses at most one peer and
//!    cannot loop;
//! 3. holds, per connection and handle, the latest ephemeral slot frame that
//!    connection sent, at most 64 per connection per space, dropping the
//!    oldest first, and sends all it holds, with their origins, to a
//!    connection that joins; it never sends an ephemeral message twice;
//! 4. when a connection closes or loses its `live` right, drops its frames
//!    and sends `Gone` with its origin to the channel's other connections;
//! 5. holds nothing at rest, and nothing for a channel no connection is on.
//!
//! [`Relay`] is one space's channel at the peer. The peer keeps which
//! connections hold the `live` right, drops a frame that carries an origin,
//! applies its own rate limits per connection, and queues at most a
//! sender's queue ([`SEND_QUEUE`](crate::limits::SEND_QUEUE)) of ephemeral
//! frames per connection, dropping them first.

use crate::EphemeralClass;
use crate::frame::Outer;
use crate::inner::Kind;
use crate::limits::{HANDLE_BYTES, ORIGIN_BYTES, RELAY_SLOTS_PER_CONNECTION};
use frasil_transport::messages::{Ephemeral, Gone, Scope};

/// Something the relay sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relayed<C> {
    /// A frame, forwarded or held, with its sender's origin.
    Frame {
        /// The connection it goes to.
        to: C,
        /// The sending connection's origin.
        origin: [u8; ORIGIN_BYTES],
        /// The frame's kind.
        kind: Kind,
        /// Its handle, for an ephemeral slot.
        handle: Option<[u8; HANDLE_BYTES]>,
        /// The outer frame.
        outer: Vec<u8>,
    },
    /// `Gone`, naming the origin of a connection that left the channel.
    Gone {
        /// The connection it goes to.
        to: C,
        /// The origin gone.
        origin: [u8; ORIGIN_BYTES],
    },
}

impl<C> Relayed<C> {
    /// The connection it goes to.
    pub fn to(&self) -> &C {
        match self {
            Self::Frame { to, .. } | Self::Gone { to, .. } => to,
        }
    }

    /// transport.md's message for it, scoped by the space ID on a
    /// device-to-peer connection: `Ephemeral` with the origin at key 3, or
    /// `Gone`.
    pub fn message(&self, space: &[u8; 32]) -> Vec<u8> {
        let scope = Scope::Space(*space);
        match self {
            Self::Frame { origin, outer, .. } => Ephemeral {
                scope,
                frame: outer.clone(),
                origin: Some(*origin),
            }
            .encode(),
            Self::Gone { origin, .. } => Gone {
                scope,
                origin: *origin,
            }
            .encode(),
        }
    }
}

struct Joined<C> {
    connection: C,
    origin: [u8; ORIGIN_BYTES],
    /// The latest ephemeral slot frame per handle, oldest first.
    held: Vec<([u8; HANDLE_BYTES], Vec<u8>)>,
    /// When the connection first had a frame held, for the order a joiner
    /// receives them in.
    first_held: Option<u64>,
}

/// One space's channel at an always-on peer.
pub struct Relay<C> {
    space: [u8; 32],
    joined: Vec<Joined<C>>,
    holds: u64,
}

impl<C: Clone + Eq> Relay<C> {
    /// The channel of a space, with no connection on it.
    pub fn new(space: [u8; 32]) -> Self {
        Self {
            space,
            joined: Vec::new(),
            holds: 0,
        }
    }

    /// The space.
    pub fn space(&self) -> &[u8; 32] {
        &self.space
    }

    /// Whether no connection is on the channel; the peer then drops it.
    pub fn is_empty(&self) -> bool {
        self.joined.is_empty()
    }

    /// The origin of a connection on the channel.
    pub fn origin(&self, connection: &C) -> Option<[u8; ORIGIN_BYTES]> {
        self.position(connection).map(|i| self.joined[i].origin)
    }

    fn position(&self, connection: &C) -> Option<usize> {
        self.joined.iter().position(|j| j.connection == *connection)
    }

    /// A connection joins, with its first `Subscribe` or `Ephemeral` for the
    /// space. `origin` is 8 random bytes the peer draws for it, never
    /// derived from its credentials; it is ignored for a connection already
    /// on the channel. Returns the held ephemeral slot frames it is sent,
    /// with their origins.
    pub fn join_with(&mut self, connection: C, origin: [u8; ORIGIN_BYTES]) -> Vec<Relayed<C>> {
        if self.position(&connection).is_some() {
            return Vec::new();
        }
        let mut senders: Vec<&Joined<C>> = self
            .joined
            .iter()
            .filter(|j| j.first_held.is_some())
            .collect();
        senders.sort_by_key(|j| j.first_held);
        let out = senders
            .into_iter()
            .flat_map(|j| {
                j.held.iter().map(|(handle, outer)| Relayed::Frame {
                    to: connection.clone(),
                    origin: j.origin,
                    kind: Kind::Slot,
                    handle: Some(*handle),
                    outer: outer.clone(),
                })
            })
            .collect();
        self.joined.push(Joined {
            connection,
            origin,
            held: Vec::new(),
            first_held: None,
        });
        out
    }

    /// A connection sends a frame. The relay checks steps 1 and 2 of
    /// "Receiving"; the connection joins if it is not on the channel yet,
    /// with `origin`. An ephemeral slot frame replaces the one held for its
    /// handle. Returns what is sent: to a new connection, the held frames;
    /// then the frame, to every other connection.
    ///
    /// # Errors
    ///
    /// Steps 1 and 2's: `TooLarge`, `Malformed` or `UnsupportedVersion`. The
    /// frame is dropped, and the connection does not join.
    pub fn frame_with(
        &mut self,
        connection: C,
        outer: &[u8],
        origin: [u8; ORIGIN_BYTES],
    ) -> Result<Vec<Relayed<C>>, EphemeralClass> {
        let frame = Outer::read(outer, &self.space)?;
        let mut out = self.join_with(connection.clone(), origin);
        let index = self.position(&connection).expect("the connection joined");
        if let Some(handle) = frame.handle {
            let holds = &mut self.holds;
            let sender = &mut self.joined[index];
            sender.held.retain(|(held, _)| *held != handle);
            sender.held.push((handle, outer.to_vec()));
            if sender.held.len() > RELAY_SLOTS_PER_CONNECTION {
                sender.held.remove(0);
            }
            if sender.first_held.is_none() {
                *holds += 1;
                sender.first_held = Some(*holds);
            }
        }
        let origin = self.joined[index].origin;
        out.extend(
            self.joined
                .iter()
                .filter(|j| j.connection != connection)
                .map(|j| Relayed::Frame {
                    to: j.connection.clone(),
                    origin,
                    kind: frame.kind,
                    handle: frame.handle,
                    outer: outer.to_vec(),
                }),
        );
        Ok(out)
    }

    /// A connection closes, or loses its `live` right: its frames are
    /// dropped, and `Gone` with its origin goes to every other connection.
    pub fn leave(&mut self, connection: &C) -> Vec<Relayed<C>> {
        let Some(index) = self.position(connection) else {
            return Vec::new();
        };
        let gone = self.joined.remove(index);
        self.joined
            .iter()
            .map(|j| Relayed::Gone {
                to: j.connection.clone(),
                origin: gone.origin,
            })
            .collect()
    }
}
