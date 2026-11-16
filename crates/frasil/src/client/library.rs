//! Library tickets (ext-libraries.md): a space attached to a library, the
//! billing pool a peer charges its storage to.
//!
//! The device carries tickets as opaque bytes from the issuer and sends
//! each in a `LibraryAttach` to a peer that lists service 5: before the
//! genesis of a space the peer does not host yet (a create or an import),
//! or for a space it hosts (a move). Refusals arrive as their codes, such
//! as `quota_exceeded` or `no_library`, for the application to show.

#![cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]

use super::{Device, Space};
use crate::error::{Error, Result};
use crate::peer::library;
use frasil_base::errors::Class as _;
use frasil_libraries::LibraryClass;
use std::time::Duration;

/// How long [`Space::attach_library`] waits for a peer's answer before it
/// leaves the ticket to the connection.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// How often [`Space::attach_library`] looks for its ticket handed back by
/// a connection that closed before the peer answered.
const AGAIN_EVERY: Duration = Duration::from_millis(250);

/// A refusal code as the client's error: the library class it names, or
/// a connection error with the code.
fn refused(code: &str) -> Error {
    match LibraryClass::from_wire_name(code) {
        Some(class) => Error::Class(class.name()),
        None => Error::Connection(format!("the peer refused: {code}")),
    }
}

impl Device {
    /// Keeps a library ticket for the next space this device creates at a
    /// peer that requires one: `Options::library_ticket`, at run time. A
    /// ticket attaches one space.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for bytes that are no create ticket.
    pub fn set_library_ticket(&self, ticket: Vec<u8>) -> Result<()> {
        if library::purpose_of(&ticket) != Some(frasil_libraries::Purpose::Create) {
            return Err(Error::Invalid("not a library ticket to create a space"));
        }
        library::set_default(self.engine().device_id(), ticket);
        Ok(())
    }
}

impl Space {
    /// Attaches the space to a library with a ticket from its issuer
    /// (ext-libraries.md, 3.3 Attaching): a create or an import ticket
    /// before a peer hosts the space, a move ticket after. The device sends
    /// it to the first connected peer that keeps libraries, and returns
    /// once that peer accepts it; with no peer connected, the next
    /// connection sends it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for bytes that are no ticket; the peer's
    /// refusal, as a class such as `QuotaExceeded`, `TicketExpired` or
    /// `SpaceExists`; [`Error::Timeout`] when no peer has answered in time.
    /// The ticket stays with the device, and a connection sends it again
    /// when the transport it went on ended first. A connection closed
    /// with [`Peer::close`](super::Peer::close) while it attaches a space
    /// stays open, for 5 seconds at most, until the peer has answered and
    /// stored the genesis of a create: a create that lapses leaves its
    /// ticket used. A ticket still unanswered then goes to the device's
    /// other connections.
    pub async fn attach_library(&self, ticket: &[u8]) -> Result<()> {
        if library::purpose_of(ticket).is_none() {
            return Err(Error::Invalid("not a library ticket"));
        }
        let space = self.id().event();
        let answer = library::hold(self.device.engine().device_id(), space, ticket.to_vec());
        if !self.device.send_ticket(space) {
            return Ok(());
        }
        let wait = self.device.sleep(ANSWER_WAIT);
        // A connection that closes with the ticket in flight hands it
        // back: it then goes to the connections open by then.
        let again = async {
            loop {
                self.device.sleep(AGAIN_EVERY).await;
                self.device.send_held_ticket(space);
            }
        };
        tokio::select! {
            answer = answer => match answer {
                Ok(Ok(())) => Ok(()),
                Ok(Err(code)) => Err(refused(&code)),
                Err(_) => Err(Error::Connection("no peer answered the ticket".into())),
            },
            () = again => unreachable!("the loop does not end"),
            () = wait => Err(Error::Timeout),
        }
    }
}

impl Device {
    /// Asks each open connection that may carry `space` to send the
    /// space's ticket; whether there is any.
    fn send_ticket(&self, space: frasil_events::EventId) -> bool {
        let peers: Vec<_> = self
            .peers_of(&space)
            .into_iter()
            .filter(|peer| !peer.handle().is_closed())
            .collect();
        for peer in &peers {
            peer.handle().library(space);
        }
        !peers.is_empty()
    }

    /// Sends the ticket of `space` that a connection handed back when it
    /// closed before the peer answered its `LibraryAttach`, when there is
    /// one, on the connections open now (ext-libraries.md, 3.3 Attaching).
    pub(super) fn send_held_ticket(&self, space: frasil_events::EventId) {
        if library::handed_back(self.engine().device_id(), space) {
            self.send_ticket(space);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::refused;
    use crate::error::Error;

    #[test]
    fn refusals_read_as_classes() {
        assert!(matches!(
            refused("quota_exceeded"),
            Error::Class("QuotaExceeded")
        ));
        assert!(matches!(refused("busy"), Error::Connection(_)));
    }
}
